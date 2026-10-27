<?php

    namespace FederationAdGuard\Handlers;

    use FederationAdGuard\Classes\Configuration;
    use FederationAdGuard\Classes\Logger;
    use FederationAdGuard\Classes\PluginOperator;
    use FederationAdGuard\Classes\Matcher;
    use FederationAdGuard\Classes\FindingRecorder;
    use FederationAdGuard\Classes\Managers\FindingManager;
    use FederationAdGuard\Enums\FindingState;
    use FederationAdGuard\Exceptions\RecordingException;
    use FederationAdGuard\Exceptions\RuleException;
    use FederationAdGuard\FederationAdGuard;
    use FederationAdGuard\Objects\MatchResult;
    use FederationAdGuard\Objects\MatchTarget;
    use FederationAdGuard\Objects\RuleMatch;
    use FederationLib\Classes\Managers\BlacklistManager;
    use FederationLib\Classes\Managers\EntitiesManager;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Enums\SuggestedActionType;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use FederationLib\Interfaces\QueryEntityEventHandlerInterface;
    use FederationLib\Objects\Plugin\EntityQuery;
    use InvalidArgumentException;

    class QueryEntityHandler implements QueryEntityEventHandlerInterface
    {
        /**
         * @inheritDoc
         */
        public static function handleQueryEntity(EntityQuery $entityQuery): void
        {
            if(!Configuration::isEnabled() || !PluginOperator::isActive())
            {
                return;
            }

            try
            {
                self::query($entityQuery);
            }
            catch(RuleException|DatabaseOperationException|InvalidArgumentException $e)
            {
                Logger::log()->warning('Unable to match the queried entity against the lists, the response is left without FederationAdGuard: ' . $e->getMessage(), $e);
            }
        }

        /**
         * Matches the queried entity and changes the response accordingly
         *
         * @param EntityQuery $entityQuery The entity query
         * @return void
         * @throws DatabaseOperationException If the rules cannot be read
         * @throws CacheOperationException If a cache operation fails
         * @throws RuleException If the host matches too many rules to decide
         * @throws InvalidArgumentException If FederationLib rejects a change of the response
         */
        private static function query(EntityQuery $entityQuery): void
        {
            $entity = $entityQuery->getEntityRecord();
            if($entity->getId() !== null || $entity->isTelephone())
            {
                return;
            }

            $target = MatchTarget::fromHost($entity->getHost());
            if($target === null)
            {
                return;
            }

            $result = FederationAdGuard::match($target);
            // A host can't be checked against rules restricted to some requests (e.g., $third-party), as DNS blockers do
            $blocking = array_values(array_filter($result->getBlocking(), fn($match) => !$match->getRule()->isPartial()));
            self::removeUnrelatedRecords($entityQuery, $result);
            Logger::log()->debug(sprintf('Query entity %s: %s', $entity->getHost(), count($blocking) > 0
                ? 'listed for ' . implode(', ', array_unique(array_map(fn($match) => $match->getRule()->getConcern()?->value, $blocking)))
                : ($result->isExcepted() ? 'excepted by the lists' : 'not listed')));

            if($entity->isWhitelisted())
            {
                return;
            }

            if(count($blocking) > 0)
            {
                $entityQuery->addEntityMetadata(self::getMetadata($result, $blocking));
                self::addBlacklists($entityQuery, $result);
            }
            elseif($result->isExcepted())
            {
                $entityQuery->addEntityMetadata(['adguard_listed' => false, 'adguard_excepted' => true]);
            }
        }

        /**
         * Records the findings of a queried host a list blocks entirely and adds their blacklist records to the response.
         * A finding without a blacklist record (e.g., building the database is disabled) still suggests blocking the
         * entity for a requested concern, unless an operator lifted or deleted the plugin's record of it.
         *
         * @param EntityQuery $entityQuery The entity query
         * @param MatchResult $result The result of the queried host
         * @return void
         * @throws InvalidArgumentException If FederationLib rejects a change of the response
         */
        private static function addBlacklists(EntityQuery $entityQuery, MatchResult $result): void
        {
            $entity = $entityQuery->getEntityRecord();
            $hostBlocks = $result->getHostBlocks();
            if(count($hostBlocks) === 0)
            {
                return;
            }

            $blacklists = [];
            try
            {
                $blacklists = FindingRecorder::recordResult($result);
            }
            catch(RecordingException|DatabaseOperationException|InvalidArgumentException $e)
            {
                Logger::log()->warning(sprintf('Unable to record the findings of %s: %s', $entity->getHost(), $e->getMessage()));
            }

            // The listed host may be the queried entity or a related one, e.g., the registrable domain of a subdomain
            $entities = [$entity->getUuid() => true];
            foreach($entityQuery->getRelatedEntities() as $relatedEntity)
            {
                $entities[$relatedEntity->getUuid()] = true;
            }

            $active = array_map(fn($blacklist) => $blacklist->getUuid(), $entityQuery->getActiveBlacklists());
            $suggest = false;
            foreach($hostBlocks as $match)
            {
                $concern = $match->getRule()->getConcern();
                $host = (string)$match->getRule()->getHost();
                $blacklistUuid = $blacklists[$host][$concern->value] ?? null;
                if($blacklistUuid === null)
                {
                    $suggest = $suggest || (self::isConcernEffective($entityQuery, $concern) && !self::isSuppressed($host, $concern));
                    continue;
                }

                if(in_array($blacklistUuid, $active, true))
                {
                    continue;
                }

                try
                {
                    $blacklist = BlacklistManager::getBlacklistEntry($blacklistUuid);
                }
                catch(DatabaseOperationException|InvalidArgumentException $e)
                {
                    Logger::log()->warning(sprintf('Unable to retrieve the blacklist record %s: %s', $blacklistUuid, $e->getMessage()));
                    $suggest = $suggest || self::isConcernEffective($entityQuery, $concern);
                    continue;
                }

                if($blacklist !== null && !$blacklist->isLifted() && isset($entities[$blacklist->getEntityUuid()]))
                {
                    $entityQuery->addBlacklist($blacklist);
                    $active[] = $blacklistUuid;
                }
                elseif($blacklist !== null && !$blacklist->isLifted())
                {
                    $suggest = $suggest || self::isConcernEffective($entityQuery, $concern);
                }
            }

            if($suggest && !$entityQuery->isSuggestedActionOverridden())
            {
                $entityQuery->setSuggestedAction(SuggestedActionType::PERMANENTLY_BLOCK_ENTITY);
            }
        }

        /**
         * Checks if an operator lifted or deleted the plugin's blacklist record of a listed host for a concern
         *
         * @param string $host The listed host
         * @param IncidentType $concern The concern
         * @return bool True if the finding is suppressed
         */
        private static function isSuppressed(string $host, IncidentType $concern): bool
        {
            // Operators' decisions are only kept while the plugin builds the database
            if(!Configuration::getDatabaseConfiguration()->isEnabled())
            {
                return false;
            }

            try
            {
                $listedEntity = EntitiesManager::getEntity($host);
                return $listedEntity !== null && FindingManager::getFinding($listedEntity->getUuid(), $concern)?->getState() === FindingState::SUPPRESSED;
            }
            catch(DatabaseOperationException $e)
            {
                // An operator's decision can't be ruled out, the plugin doesn't suggest anything rather than overrule it
                Logger::log()->warning(sprintf('Unable to retrieve the finding of %s (%s): %s', $host, $concern->value, $e->getMessage()));
                return true;
            }
        }

        /**
         * Leaves out the plugin's blacklist records that don't apply to the queried host: records of related entities
         * the host is not within, and records whose concern no list blocks the host for anymore (e.g., an exception)
         *
         * @param EntityQuery $entityQuery The query
         * @param MatchResult $result The rules that apply to the host
         * @return void
         */
        private static function removeUnrelatedRecords(EntityQuery $entityQuery, MatchResult $result): void
        {
            try
            {
                $findings = FindingManager::getFindingsByBlacklists(array_map(fn($blacklist) => $blacklist->getUuid(), $entityQuery->getActiveBlacklists()));
            }
            catch(DatabaseOperationException $e)
            {
                Logger::log()->warning('Unable to retrieve the findings of the queried entity, its blacklist records are left as they are: ' . $e->getMessage());
                return;
            }

            $host = $entityQuery->getEntityRecord()->getHost();
            foreach($entityQuery->getActiveBlacklists() as $blacklist)
            {
                $finding = $findings[$blacklist->getUuid()] ?? null;
                if($finding === null || $finding->getState() !== FindingState::ACTIVE)
                {
                    continue;
                }

                // The finding follows the current lists, an exception unblocks the host
                $covers = Matcher::isWithin($host, $finding->getHost()) && $result->isBlocked($finding->getConcern());
                if(!$covers)
                {
                    $entityQuery->removeBlacklist($blacklist->getUuid());
                }
            }
        }

        /**
         * Returns the metadata describing why a host is listed
         *
         * @param MatchResult $result The rules that apply to the host
         * @param RuleMatch[] $blocking The blocking rules that count for a host, the strongest first
         * @return array The metadata
         */
        private static function getMetadata(MatchResult $result, array $blocking): array
        {
            $names = [];
            try
            {
                $names = FederationAdGuard::getRuleSource()->getListNames();
            }
            catch(DatabaseOperationException)
            {
                // The lists are named by their ID
            }

            $lists = [];
            foreach($blocking as $match)
            {
                $id = $match->getRule()->getSubscriptionId();
                $lists[$id] = $names[$id] ?? sprintf('subscription %d', $id);
            }

            $strongest = $blocking[0];
            return [
                'adguard_listed' => true,
                'adguard_concerns' => implode(',', array_values(array_unique(array_map(fn($match) => $match->getRule()->getConcern()?->value, $blocking)))),
                'adguard_lists' => mb_strcut(implode(', ', $lists), 0, 1000),
                'adguard_rule' => mb_strcut($strongest->getRule()->getRule(), 0, 1000),
                'adguard_host_block' => count($result->getHostBlocks()) > 0,
            ];
        }

        /**
         * Returns True if a concern determines the suggested action of the query
         *
         * @param EntityQuery $entityQuery The query
         * @param IncidentType|null $concern The concern
         * @return bool True if effective
         */
        private static function isConcernEffective(EntityQuery $entityQuery, ?IncidentType $concern): bool
        {
            return $concern !== null && ($entityQuery->getConcerns() === null || in_array($concern, $entityQuery->getConcerns(), true));
        }
    }
