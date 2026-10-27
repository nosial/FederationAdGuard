<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Classes\Managers\FindingManager;
    use FederationAdGuard\Exceptions\RecordingException;
    use FederationAdGuard\Objects\MatchResult;
    use FederationAdGuard\Objects\RuleMatch;
    use FederationLib\Classes\DatabaseConnection;
    use FederationLib\Classes\Managers\AuditLogManager;
    use FederationLib\Classes\Managers\EntitiesManager;
    use FederationLib\Classes\Managers\EvidenceManager;
    use FederationLib\Enums\AuditLogType;
    use FederationLib\Enums\ContentType;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use FederationLib\Objects\EntityRecord;
    use InvalidArgumentException;
    use PDOException;

    class FindingRecorder
    {
        /**
         * The note of the evidence the plugin creates
         */
        private const string EVIDENCE_NOTE = 'The host is covered by a configured filter rule. This records filter analysis, not observed network activity.';

        /** @var array<string, bool> Hosts currently being recorded by this process */
        private static array $recording = [];

        /**
         * Records the findings of a match result against the hosts its rules name, e.g., doubleclick.net for a match of
         * ad.doubleclick.net by ||doubleclick.net^, the listed host is the offending entity
         *
         * @param MatchResult $result The result of a match
         * @return array<string, array<string, string|null>> The UUID of the blacklist record that applies for each
         *                                                   concern, by host
         * @throws DatabaseOperationException If there is an error with the database
         * @throws CacheOperationException If there is an error during a cache operation
         * @throws InvalidArgumentException If a record is invalid
         * @throws RecordingException If the plugin operator is unavailable
         */
        public static function recordResult(MatchResult $result): array
        {
            $hosts = [];
            foreach($result->getHostBlocks() as $match)
            {
                $hosts[(string)$match->getRule()->getHost()][] = $match;
            }

            $blacklists = [];
            foreach($hosts as $host => $matches)
            {
                $blacklists[$host] = self::record((string)$host, $matches);
            }

            return $blacklists;
        }

        /**
         * Records the findings of a host, one per concern. A finding recorded before keeps its evidence and blacklist
         * record. Nothing is recorded while another process records the same host, or while building the database is
         * disabled.
         *
         * @param string $host The host the rules name, e.g., doubleclick.net for ||doubleclick.net^
         * @param RuleMatch[] $matches The rules that block the host entirely (see MatchResult::getHostBlocks()), the
         *                             first rule of each concern is recorded
         * @return array<string, string|null> The UUID of the blacklist record that applies for each concern, null if none
         * @throws DatabaseOperationException If there is an error with the database
         * @throws CacheOperationException If there is an error during a cache operation
         * @throws InvalidArgumentException If a record is invalid
         * @throws RecordingException If the plugin operator is unavailable
         */
        public static function record(string $host, array $matches): array
        {
            $matches = self::getRecordableMatches($matches);
            if(!Configuration::getDatabaseConfiguration()->isEnabled() || count($matches) === 0 || !BlacklistRecorder::isRecordable($host))
            {
                return [];
            }

            $lock = DatabaseLock::getFindingLock($host);
            if(isset(self::$recording[$host]) || !DatabaseLock::acquire($lock))
            {
                Logger::log()->debug(sprintf('The findings of %s are already being recorded', $host));
                return [];
            }

            self::$recording[$host] = true;
            try
            {
                // Read after acquiring the lock, including whitelist changes made since content resolution.
                $entity = EntitiesManager::getEntity($host) ?? EntitiesManager::getEntityByUuid(EntitiesManager::registerEntity($host));
                if($entity === null || $entity->isWhitelisted() || $entity->getId() !== null)
                {
                    return [];
                }

                $evidence = [];
                $blacklists = [];
                foreach($matches as $concern => $match)
                {
                    $rule = $match->getRule();
                    $previous = FindingManager::getFinding($entity->getUuid(), $rule->getConcern());
                    FindingManager::saveFinding($entity->getUuid(), $rule->getConcern(), $host, $rule->getRule(), $rule->getSubscriptionId());

                    $evidence[$concern] = $previous?->getEvidenceUuid() ?? self::recordEvidence($entity, $match);
                    $blacklists[$concern] = BlacklistRecorder::blacklist($entity, $match);
                }

                // This describes an observation, not current blacklist state. Metadata is never trusted as a decision.
                EntitiesManager::updateEntityMetadata($entity->getUuid(), self::getEntityMetadata($matches, $evidence));
                return $blacklists;
            }
            finally
            {
                unset(self::$recording[$host]);
                DatabaseLock::releaseQuietly($lock);
            }
        }

        /**
         * Builds the scalar OFD metadata of a finding's evidence, documenting the analysis, never arbitrary client
         * context
         *
         * @param RuleMatch $match The rule that blocks the host entirely
         * @return array The metadata
         */
        private static function getMetadata(RuleMatch $match): array
        {
            $rule = $match->getRule();
            return [
                'adguard_source' => 'FederationAdGuard',
                'adguard_concern' => $rule->getConcern()?->value,
                'adguard_rule' => mb_strcut($rule->getRule(), 0, 1000),
                'adguard_list' => mb_strcut(BlacklistRecorder::getListName($rule->getSubscriptionId()), 0, 1000),
                'adguard_host_block' => true,
            ];
        }

        /**
         * Builds the scalar OFD metadata of an entity, summarizing its findings. It only depends on the rules, so
         * recording the same findings again doesn't change the entity.
         *
         * @param array<string, RuleMatch> $matches The recordable matches by concern (see getRecordableMatches())
         * @param array<string, string|null> $evidence The UUID of the evidence of each concern
         * @return array The metadata
         */
        private static function getEntityMetadata(array $matches, array $evidence): array
        {
            $lists = array_unique(array_map(fn(RuleMatch $match) => BlacklistRecorder::getListName($match->getRule()->getSubscriptionId()), $matches));
            $first = $matches[array_key_first($matches)] ?? null;

            $metadata = [
                'adguard_source' => 'FederationAdGuard',
                'adguard_concerns' => implode(',', array_keys($matches)),
                'adguard_lists' => mb_strcut(implode(', ', $lists), 0, 1000),
                'adguard_rule' => $first !== null ? mb_strcut($first->getRule()->getRule(), 0, 1000) : null,
                'adguard_host_block' => true,
            ];

            $evidence = array_filter($evidence);
            if(count($evidence) > 0)
            {
                ksort($evidence);
                $metadata['adguard_evidence'] = implode(',', $evidence);
            }

            return $metadata;
        }

        /**
         * Returns the matches that may be recorded, the first one of each concern, in the order of their concerns
         *
         * @param RuleMatch[] $matches The matches
         * @return array<string, RuleMatch> The matches by concern
         */
        private static function getRecordableMatches(array $matches): array
        {
            $recordable = [];
            foreach($matches as $match)
            {
                $rule = $match->getRule();
                if($rule->isHostBlock() && !$match->isAssertion() && $rule->getConcern() !== null)
                {
                    $recordable[$rule->getConcern()->value] ??= $match;
                }
            }

            ksort($recordable);
            return $recordable;
        }

        /**
         * Creates the evidence of a finding. The evidence and its link to the finding are committed together, so
         * retries cannot leave duplicate evidence.
         *
         * @param EntityRecord $entity The listed host entity
         * @param RuleMatch $match The rule that blocks the host entirely
         * @return string The UUID of the evidence
         * @throws DatabaseOperationException If there is an error with the database
         * @throws CacheOperationException If there is an error during a cache operation
         * @throws InvalidArgumentException If the evidence is invalid
         * @throws RecordingException If the plugin operator is unavailable
         */
        private static function recordEvidence(EntityRecord $entity, RuleMatch $match): string
        {
            $rule = $match->getRule();
            $operatorUuid = PluginOperator::get()->getUuid();
            $connection = DatabaseConnection::getConnection();
            try
            {
                $connection->beginTransaction();
                $uuid = EvidenceManager::addEvidence(
                    entity: $entity->getUuid(), operator: $operatorUuid, textContent: $entity->getHost(), note: self::EVIDENCE_NOTE,
                    tag: 'adguard_finding', confidential: true, metadata: self::getMetadata($match), contentType: ContentType::HOSTNAME,
                    automated: true
                );
                FindingManager::setEvidence($entity->getUuid(), $rule->getConcern() ?? IncidentType::OTHER, $uuid);
                AuditLogManager::createEntry(AuditLogType::EVIDENCE_SUBMITTED, sprintf('Automated evidence submitted by FederationAdGuard for %s, it is listed as %s by %s (%s)',
                    $entity->getLoggableAddress(), $rule->getConcern()?->value, BlacklistRecorder::getListName($rule->getSubscriptionId()), mb_strcut($rule->getRule(), 0, 256)),
                    operatorUuid: $operatorUuid, entityUuid: $entity->getUuid(), evidenceUuid: $uuid);
                $connection->commit();
            }
            catch(PDOException $e)
            {
                throw new DatabaseOperationException('Failed to record the evidence of a finding: ' . $e->getMessage(), (int)$e->getCode(), $e);
            }
            finally
            {
                // Only still open if the evidence wasn't recorded
                if($connection->inTransaction())
                {
                    $connection->rollBack();
                }
            }

            return $uuid;
        }
    }
