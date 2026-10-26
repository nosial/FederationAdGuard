<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Classes\Configuration\DatabaseConfiguration;
    use FederationAdGuard\Classes\Configuration\ScanningConfiguration;
    use FederationAdGuard\Objects\RuleMatch;
    use FederationLib\Classes\Configuration as FederationConfiguration;
    use FederationLib\Classes\DatabaseConnection;
    use FederationLib\Classes\Managers\AuditLogManager;
    use FederationLib\Classes\Managers\BlacklistManager;
    use FederationLib\Classes\Managers\EntitiesManager;
    use FederationLib\Classes\Managers\EvidenceManager;
    use FederationLib\Classes\Utilities;
    use FederationLib\Enums\AuditLogType;
    use FederationLib\Enums\ContentType;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Objects\EntityRecord;
    use FederationLib\Objects\Plugin\ContentScan;
    use Throwable;

    class AuthorRecorder
    {
        /**
         * The concern authors are recorded for
         */
        public const IncidentType CONCERN = IncidentType::SPAM;

        /**
         * The tag of the evidence the plugin creates for authors, earlier offences are found by it
         */
        public const string EVIDENCE_TAG = 'adguard_author';

        /**
         * The content types that have an author whose message can be recorded
         */
        public const array CONTENT_TYPES = [ContentType::TEXT, ContentType::EMAIL, ContentType::SMS];

        /**
         * The note of the evidence the plugin creates
         */
        private const string EVIDENCE_NOTE = 'The message mostly links to hosts covered by configured filter rules. This records filter analysis of the message, it was recorded automatically.';

        /**
         * Checks if a message is little more than listed links: it links to at least ScanningConfiguration::SPAM_MIN_HOSTS
         * distinct listed hosts, and at least ScanningConfiguration::SPAM_MIN_SHARE of the distinct hosts it links to are
         * listed
         *
         * @param int $listed The number of distinct listed hosts the message links to
         * @param int $hosts The number of distinct hosts the message links to, listed or not
         * @return bool True if the message counts as spam
         */
        public static function isSpam(int $listed, int $hosts): bool
        {
            return $hosts > 0 && $listed >= ScanningConfiguration::SPAM_MIN_HOSTS && $listed / $hosts >= ScanningConfiguration::SPAM_MIN_SHARE;
        }

        /**
         * Records the author of an evidence item of a scan, if the item is a message that counts as spam
         *
         * @param ContentScan $contentScan The content scan
         * @param int $evidenceIndex The index of the evidence item
         * @param array<string, RuleMatch> $listed The strongest full match of each distinct listed host the item links to
         * @param int $hosts The number of distinct hosts the item links to, listed or not
         * @return string|null The UUID of the blacklist record, or of the evidence if the author isn't blacklisted, null
         *                     if nothing was recorded
         * @throws Throwable If the author cannot be recorded
         */
        public static function record(ContentScan $contentScan, int $evidenceIndex, array $listed, int $hosts): ?string
        {
            if(!Configuration::getDatabaseConfiguration()->isEnabled() || !self::isSpam(count($listed), $hosts))
            {
                return null;
            }

            $item = $contentScan->getEvidence()[$evidenceIndex] ?? null;
            if($item === null || !in_array($item->getContentType(), self::CONTENT_TYPES, true))
            {
                return null;
            }

            if(!($contentScan->getAuthenticatedOperator()?->hasClientPermissions() ?? false))
            {
                Logger::log()->debug('Not recording the author of an anonymous scan');
                return null;
            }

            // A scan without an author (e.g., a DNS lookup) has nobody to record
            $author = self::getAuthor($contentScan);
            if($author === null)
            {
                return null;
            }

            $lock = DatabaseLock::getFindingLock('author:' . $author->getUuid());
            if(!DatabaseLock::acquire($lock))
            {
                Logger::log()->debug(sprintf('The author %s is already being recorded', $author->getLoggableAddress()));
                return null;
            }

            try
            {
                // Read after acquiring the lock, an operator may have whitelisted the author since content resolution
                $author = EntitiesManager::getEntityByUuid($author->getUuid());
                if($author === null || $author->isWhitelisted())
                {
                    return null;
                }

                // An author already blacklisted for spamming, by anyone, is punished once for it
                foreach(BlacklistManager::getActiveEntriesByEntities([$author->getUuid()]) as $blacklistRecord)
                {
                    if($blacklistRecord->getEntityUuid() === $author->getUuid() && $blacklistRecord->getType() === self::CONCERN)
                    {
                        return null;
                    }
                }

                $operatorUuid = PluginOperator::get()->getUuid();
                $repeat = self::hasRecentOffence($author, $operatorUuid);
                $duration = $repeat ? Configuration::getDatabaseConfiguration()->getAuthorBlacklist() : null;
                $summary = sprintf('it linked to %d listed host(s) of %d (%s)', count($listed), $hosts, mb_strcut(implode(', ', array_keys($listed)), 0, 256));

                $evidenceUuid = null;
                $blacklistUuid = null;
                $connection = DatabaseConnection::getConnection();
                $connection->beginTransaction();
                try
                {
                    $evidenceUuid = EvidenceManager::addEvidence(
                        entity: $author->getUuid(), operator: $operatorUuid, textContent: $item->getTextContent(), note: self::EVIDENCE_NOTE,
                        tag: self::EVIDENCE_TAG, confidential: true, metadata: self::getMetadata($listed, $hosts, $repeat),
                        contentType: $item->getContentType(), automated: true
                    );
                    AuditLogManager::createEntry(AuditLogType::EVIDENCE_SUBMITTED, sprintf('Automated evidence submitted by FederationAdGuard for %s, %s',
                        $author->getLoggableAddress(), $summary), operatorUuid: $operatorUuid, entityUuid: $author->getUuid(), evidenceUuid: $evidenceUuid);

                    if($duration !== null)
                    {
                        $duration = max($duration, FederationConfiguration::getServerConfiguration()->getMinBlacklistTime());
                        $blacklistUuid = BlacklistManager::blacklistEntity($author->getUuid(), $operatorUuid, self::CONCERN, time() + $duration);
                        AuditLogManager::createEntry(AuditLogType::ENTITY_BLACKLISTED, sprintf('Entity %s blacklisted by FederationAdGuard with type %s for %d second(s), %s again',
                            $author->getLoggableAddress(), self::CONCERN->name, $duration, $summary), $operatorUuid, $author->getUuid(), $blacklistUuid, $evidenceUuid);
                    }

                    $connection->commit();
                }
                catch(Throwable $e)
                {
                    if($connection->inTransaction())
                    {
                        $connection->rollBack();
                    }

                    throw $e;
                }

                Logger::log()->info(sprintf('Recorded the author %s for %s (%s), %s', $author->getLoggableAddress(), self::CONCERN->value,
                    $blacklistUuid !== null ? 'repeat offence, blacklisted' : ($repeat ? 'repeat offence' : 'first offence'), $summary));
                return $blacklistUuid ?? $evidenceUuid;
            }
            finally
            {
                DatabaseLock::releaseQuietly($lock);
            }
        }

        /**
         * Checks if the plugin recorded an earlier offence of an author within DatabaseConfiguration::AUTHOR_REPEAT_WINDOW
         *
         * @param EntityRecord $author The author
         * @param string $operatorUuid The UUID of the plugin operator
         * @return bool True if this is a repeat offence
         * @throws Throwable If the evidence cannot be read
         */
        private static function hasRecentOffence(EntityRecord $author, string $operatorUuid): bool
        {
            $since = time() - DatabaseConfiguration::AUTHOR_REPEAT_WINDOW;
            // The newest evidence comes first, the plugin's evidence of a recent offence is among it
            foreach(EvidenceManager::getEvidenceByEntity($author->getUuid(), 100, 1, true) as $evidence)
            {
                if($evidence->getCreated() < $since)
                {
                    break;
                }

                if($evidence->getTag() === self::EVIDENCE_TAG && $evidence->getOperatorUuid() === $operatorUuid)
                {
                    return true;
                }
            }

            return false;
        }

        /**
         * Returns the author of a scan, registering an author given as an entity address that isn't known yet. Only
         * authors with an ID (e.g., an account or a telephone number) are returned, a bare host is not an author the
         * plugin records.
         *
         * @param ContentScan $contentScan The content scan
         * @return EntityRecord|null The author, null if the scan has none
         * @throws Throwable If the author cannot be resolved
         */
        private static function getAuthor(ContentScan $contentScan): ?EntityRecord
        {
            $author = $contentScan->getAuthorEntity()?->getEntity();
            if($author === null)
            {
                $address = $contentScan->getAuthorIdentifier() !== null ? Utilities::parseEntityAddress($contentScan->getAuthorIdentifier()) : null;
                if($address === null)
                {
                    return null;
                }

                $author = EntitiesManager::getEntity($address['host'], $address['id'])
                    ?? EntitiesManager::getEntityByUuid(EntitiesManager::registerEntity($address['host'], $address['id']));
            }

            return $author !== null && $author->getId() !== null ? $author : null;
        }

        /**
         * Builds the scalar OFD metadata of the evidence, documenting the analysis, never arbitrary client context
         *
         * @param array<string, RuleMatch> $listed The strongest match of each listed host
         * @param int $hosts The number of distinct hosts the message links to
         * @param bool $repeat Whether it's a repeat offence
         * @return array The metadata
         */
        private static function getMetadata(array $listed, int $hosts, bool $repeat): array
        {
            $lists = [];
            $concerns = [];
            foreach($listed as $match)
            {
                $lists[] = BlacklistRecorder::getListName($match->getRule()->getSubscriptionId());
                $concerns[] = $match->getRule()->getConcern()?->value;
            }

            return [
                'adguard_source' => 'FederationAdGuard',
                'adguard_concern' => self::CONCERN->value,
                'adguard_hosts' => $hosts,
                'adguard_listed_hosts' => count($listed),
                'adguard_listed' => mb_strcut(implode(', ', array_keys($listed)), 0, 1000),
                'adguard_listed_concerns' => implode(',', array_values(array_unique(array_filter($concerns)))),
                'adguard_lists' => mb_strcut(implode(', ', array_values(array_unique($lists))), 0, 1000),
                'adguard_repeat' => $repeat,
            ];
        }
    }
