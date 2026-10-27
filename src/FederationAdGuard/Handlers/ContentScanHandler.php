<?php

    namespace FederationAdGuard\Handlers;

    use FederationAdGuard\Classes\AuthorRecorder;
    use FederationAdGuard\Classes\Configuration;
    use FederationAdGuard\Classes\Configuration\ScanningConfiguration;
    use FederationAdGuard\Classes\FindingRecorder;
    use FederationAdGuard\Classes\Logger;
    use FederationAdGuard\Classes\Matcher;
    use FederationAdGuard\Classes\PluginOperator;
    use FederationAdGuard\Classes\TargetExtractor;
    use FederationAdGuard\Enums\TargetRole;
    use FederationAdGuard\Exceptions\RecordingException;
    use FederationAdGuard\Exceptions\RuleException;
    use FederationAdGuard\FederationAdGuard;
    use FederationAdGuard\Objects\MatchResult;
    use FederationAdGuard\Objects\MatchTarget;
    use FederationAdGuard\Objects\RuleMatch;
    use FederationLib\Classes\Configuration as FederationConfiguration;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use FederationLib\Interfaces\ContentScanEventHandlerInterface;
    use FederationLib\Objects\Plugin\ContentScan;
    use FederationLib\Objects\ScannedContent\ResolvedEntity;
    use InvalidArgumentException;

    class ContentScanHandler implements ContentScanEventHandlerInterface
    {
        /**
         * @inheritDoc
         */
        public static function handleContentScan(ContentScan $contentScan): void
        {
            if(!Configuration::isEnabled() || !PluginOperator::isActive())
            {
                return;
            }

            try
            {
                self::scan($contentScan);
            }
            catch(RuleException|DatabaseOperationException|InvalidArgumentException $e)
            {
                Logger::log()->warning('Unable to match the content scan against the lists, it continues without FederationAdGuard: ' . $e->getMessage(), $e);
            }
        }

        /**
         * Matches the targets of a scan and adds the plugin's detections and scanning rules
         *
         * @param ContentScan $contentScan The content scan
         * @return void
         * @throws DatabaseOperationException If the rules cannot be read
         * @throws CacheOperationException If a cache operation fails
         * @throws RuleException If a target matches too many rules to decide
         * @throws InvalidArgumentException If FederationLib rejects a detection or scanning rule
         */
        private static function scan(ContentScan $contentScan): void
        {
            $resolved = self::getResolvedHostEntities($contentScan);
            $listNames = null;

            /** @var array<int, array<string, float>> $points The points of each evidence item and concern */
            $points = [];
            /** @var array<int, array<string, RuleMatch|null>> $links The distinct hosts each item links to, with their strongest full listing */
            $links = [];
            $listed = 0;
            $checkedSubjects = 0;
            $checkedLinks = 0;
            foreach(TargetExtractor::extract($contentScan, ScanningConfiguration::MAX_LINKS) as $target)
            {
                $index = $target->getEvidenceIndex() ?? 0;
                $isLink = $target->getRole() === TargetRole::LINK && $target->getHost() !== null;
                if($isLink)
                {
                    $links[$index][$target->getHost()] ??= null;
                }

                $entity = self::getTargetEntity($target, $resolved);
                if($entity?->getEntity()->isWhitelisted())
                {
                    // FederationLib already lowers the risk of a whitelisted entity
                    continue;
                }

                $result = FederationAdGuard::match($target);
                $blocking = self::getEffectiveBlocking($target, $result);
                if(!$result->isBlocked())
                {
                    if($target->isVerified())
                    {
                        $isLink ? $checkedLinks++ : $checkedSubjects++;
                    }

                    continue;
                }

                // The findings only depend on the lists, never on the request (e.g., its concerns)
                self::record($result);
                if(count($blocking) === 0)
                {
                    // Only rules a hostname can't be checked against (e.g., $third-party) matched
                    continue;
                }

                $listed++;
                if($isLink)
                {
                    $links[$index][$target->getHost()] ??= self::getFullMatch($blocking);
                }

                $listNames ??= FederationAdGuard::getRuleSource()->getListNames();
                self::addDetections($contentScan, $target, $blocking, $entity, $listNames, $points);
            }

            foreach($points as $concerns)
            {
                foreach($concerns as $concern => $value)
                {
                    if($value < 0)
                    {
                        $contentScan->addScanResult('ADGUARD_' . $concern, $value, IncidentType::from($concern));
                    }
                }
            }

            if($listed === 0)
            {
                self::addUnlisted($contentScan, $checkedSubjects, $checkedLinks);
            }

            foreach($links as $index => $hosts)
            {
                self::addLinkSpam($contentScan, $index, $hosts);
            }

            Logger::log()->debug(sprintf('Content scan: %d listed target(s), %d unlisted host(s) or URL(s) and %d unlisted link(s) checked', $listed, $checkedSubjects, $checkedLinks));
        }

        /**
         * Returns the blocking rules that count for a target: rules restricted to some requests (e.g., $third-party)
         * only count for URLs, a hostname (e.g., a DNS lookup) can't be checked against them, as DNS blockers do
         *
         * @param MatchTarget $target The target
         * @param MatchResult $result The result of the target
         * @return RuleMatch[] The blocking rules, the strongest first
         */
        private static function getEffectiveBlocking(MatchTarget $target, MatchResult $result): array
        {
            if($target->getUrl() !== null)
            {
                return $result->getBlocking();
            }

            return array_values(array_filter($result->getBlocking(), fn(RuleMatch $match) => !$match->getRule()->isPartial()));
        }

        /**
         * Returns the strongest match that is neither partial nor depends on a client assertion, only those count
         * against the author of a message
         *
         * @param RuleMatch[] $blocking The blocking rules, the strongest first
         * @return RuleMatch|null The match, null if none counts
         */
        private static function getFullMatch(array $blocking): ?RuleMatch
        {
            return array_find($blocking, fn(RuleMatch $match) => !$match->getRule()->isPartial() && !$match->isAssertion());
        }

        /**
         * Adds the detections of a listed target, and keeps the strongest points of each concern of its evidence item
         *
         * @param ContentScan $contentScan The content scan
         * @param MatchTarget $target The target
         * @param RuleMatch[] $blocking The blocking rules that count for the target, the strongest first
         * @param ResolvedEntity|null $entity The resolved entity of the target, if FederationLib resolved one
         * @param array<int, string> $listNames The names of the lists by subscription ID
         * @param array<int, array<string, float>> $points The points of each evidence item and concern
         * @return void
         * @throws InvalidArgumentException If FederationLib rejects a detection
         */
        private static function addDetections(ContentScan $contentScan, MatchTarget $target, array $blocking, ?ResolvedEntity $entity, array $listNames, array &$points): void
        {
            $index = $target->getEvidenceIndex() ?? 0;
            $configuration = Configuration::getScanningConfiguration();
            $seen = [];
            foreach($blocking as $match)
            {
                $rule = $match->getRule();
                $concern = $rule->getConcern();
                if($concern === null || isset($seen[$concern->value]))
                {
                    continue;
                }

                $seen[$concern->value] = true;
                $confidence = $rule->isPartial() ? ScanningConfiguration::PARTIAL_CONFIDENCE : 1.0;
                $contentScan->addDetection(
                    $concern,
                    $index,
                    $rule->getSubscriptionId() !== null ? ($listNames[$rule->getSubscriptionId()] ?? 'FederationAdGuard') : 'FederationAdGuard',
                    $entity?->getEntity()->getUuid(),
                    $confidence,
                    $target->isVerified() && !$match->isAssertion()
                );

                // Topped up to the plugin's points, what FederationLib already adds for the entity's blacklists counts
                $desired = ($target->getRole() === TargetRole::SUBJECT ? $configuration->getPoints() : $configuration->getLinkPoints()) * $confidence;
                $value = min(0.0, $desired - self::getNativePoints($contentScan, $entity));
                if($value < ($points[$index][$concern->value] ?? 0.0))
                {
                    $points[$index][$concern->value] = $value;
                }
            }
        }

        /**
         * Returns the points FederationLib adds for the relevant blacklists of an entity and its parent (see
         * ScannedContent::getScanResults()), negative points
         *
         * @param ContentScan $contentScan The content scan
         * @param ResolvedEntity|null $entity The resolved entity
         * @return float The points
         */
        private static function getNativePoints(ContentScan $contentScan, ?ResolvedEntity $entity): float
        {
            if($entity === null)
            {
                return 0.0;
            }

            $modifiers = FederationConfiguration::getScanningConfiguration();
            $points = 0.0;
            foreach([[$entity, false], [$entity->getParentEntity(), true]] as [$resolvedEntity, $parent])
            {
                if($resolvedEntity === null || $resolvedEntity->getEntity()->isWhitelisted())
                {
                    continue;
                }

                foreach($resolvedEntity->getActiveBlacklists() as $blacklist)
                {
                    if(!$contentScan->isConcernEffective($blacklist->getType()))
                    {
                        continue;
                    }

                    $permanent = $blacklist->getExpires() === null;
                    $points += match(true)
                    {
                        $parent && $permanent => $modifiers->getModifierNamedEntityParentPermanentlyBlacklisted(),
                        $parent => $modifiers->getModifierNamedEntityParentBlacklisted(),
                        $permanent => $modifiers->getModifierNamedEntityPermanentlyBlacklisted(),
                        default => $modifiers->getModifierNamedEntityBlacklisted(),
                    };
                }
            }

            return min(0.0, $points);
        }

        /**
         * Lowers the risk of a scan whose hosts and URLs were checked and none of them is listed. Only verified
         * targets count, and only when rules for an effective concern are loaded: nothing can be said about a concern
         * without rules (e.g., before the lists were downloaded).
         *
         * @param ContentScan $contentScan The content scan
         * @param int $subjects The verified hostnames and URLs submitted themselves that were checked
         * @param int $links The verified links in messages that were checked
         * @return void
         * @throws DatabaseOperationException If the concerns of the rules cannot be read
         * @throws CacheOperationException If a cache operation fails
         * @throws InvalidArgumentException If FederationLib rejects the scanning rule
         */
        private static function addUnlisted(ContentScan $contentScan, int $subjects, int $links): void
        {
            $points = Configuration::getScanningConfiguration()->getUnlistedPoints();
            if($points <= 0 || ($subjects === 0 && $links === 0))
            {
                return;
            }

            $concern = array_find(FederationAdGuard::getRuleSource()->getConcerns(), fn(IncidentType $concern) => $contentScan->isConcernEffective($concern));
            if($concern === null)
            {
                return;
            }

            $contentScan->addScanResult('ADGUARD_UNLISTED', $subjects > 0 ? $points : $points * ScanningConfiguration::UNLISTED_LINK_SHARE, $concern);
        }

        /**
         * Adds ADGUARD_LINK_SPAM to a scan and records the author when an evidence item is a message that is little
         * more than listed links
         *
         * @param ContentScan $contentScan The content scan
         * @param int $index The index of the evidence item
         * @param array<string, RuleMatch|null> $hosts The distinct hosts the item links to, with their strongest full
         *                                            listing
         * @return void
         * @throws InvalidArgumentException If FederationLib rejects the scanning rule
         */
        private static function addLinkSpam(ContentScan $contentScan, int $index, array $hosts): void
        {
            $listed = array_filter($hosts);
            $item = $contentScan->getEvidence()[$index] ?? null;
            if($item === null || !in_array($item->getContentType(), AuthorRecorder::CONTENT_TYPES, true) || !AuthorRecorder::isSpam(count($listed), count($hosts)))
            {
                return;
            }

            $points = Configuration::getScanningConfiguration()->getSpamPoints();
            if($points < 0)
            {
                $contentScan->addScanResult('ADGUARD_LINK_SPAM', $points, AuthorRecorder::CONCERN);
            }

            try
            {
                AuthorRecorder::record($contentScan, $index, $listed, count($hosts));
            }
            catch(RecordingException|DatabaseOperationException|InvalidArgumentException $e)
            {
                Logger::log()->warning(sprintf('Unable to record the author of evidence %d: %s', $index, $e->getMessage()), $e);
            }
        }

        /**
         * Records the findings of a listed target, a failure is logged and the scan continues
         *
         * @param MatchResult $result The result of the target
         * @return void
         */
        private static function record(MatchResult $result): void
        {
            try
            {
                FindingRecorder::recordResult($result);
            }
            catch(RecordingException|DatabaseOperationException|InvalidArgumentException $e)
            {
                Logger::log()->warning(sprintf('Unable to record the findings of %s: %s', $result->getTarget()->getHost() ?? $result->getTarget()->getUrl(), $e->getMessage()), $e);
            }
        }

        /**
         * Returns the resolved entity of a target: the host entity FederationLib resolved for the target's host, or
         * for the registrable domain it belongs to
         *
         * @param MatchTarget $target The target
         * @param array<string, ResolvedEntity> $resolved The resolved host entities by host
         * @return ResolvedEntity|null The resolved entity, null if FederationLib resolved none
         */
        private static function getTargetEntity(MatchTarget $target, array $resolved): ?ResolvedEntity
        {
            $host = $target->getHost();
            if($host === null)
            {
                return null;
            }

            if(isset($resolved[$host]))
            {
                return $resolved[$host];
            }

            $best = null;
            foreach($resolved as $entityHost => $resolvedEntity)
            {
                if(Matcher::isWithin($host, (string)$entityHost) && ($best === null || strlen((string)$entityHost) > strlen($best->getEntity()->getHost())))
                {
                    $best = $resolvedEntity;
                }
            }

            return $best;
        }

        /**
         * Returns the host entities FederationLib resolved from the content, by host
         *
         * @param ContentScan $contentScan The content scan
         * @return array<string, ResolvedEntity> The resolved entities
         */
        private static function getResolvedHostEntities(ContentScan $contentScan): array
        {
            $entities = [];
            foreach($contentScan->getResolvedEntities() as $resolvedEntity)
            {
                $entity = $resolvedEntity->getEntity();
                if($entity->getId() === null)
                {
                    $entities[$entity->getHost()] ??= $resolvedEntity;
                }
            }

            return $entities;
        }
    }
