<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Classes\Managers\FindingManager;
    use FederationAdGuard\Enums\FindingState;
    use FederationAdGuard\Enums\MetadataKey;
    use FederationAdGuard\Exceptions\RecordingException;
    use FederationAdGuard\Exceptions\RuleException;
    use FederationAdGuard\FederationAdGuard;
    use FederationAdGuard\Objects\FindingRecord;
    use FederationAdGuard\Objects\MatchResult;
    use FederationAdGuard\Objects\MatchTarget;
    use FederationLib\Classes\DatabaseConnection;
    use FederationLib\Classes\Managers\BlacklistManager;
    use FederationLib\Classes\Managers\EntitiesManager;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use FederationLib\Objects\EntityRecord;
    use InvalidArgumentException;
    use PDO;
    use PDOException;

    class EntityVerifier
    {
        /**
         * Checks a host entity against the lists and records its findings for every concern a list blocks it entirely
         * for (see FindingRecorder)
         *
         * @param EntityRecord $entity The entity
         * @return MatchResult|null The result, null if the entity is not a host entity
         * @throws DatabaseOperationException If there is an error with the database
         * @throws CacheOperationException If there is an error during a cache operation
         * @throws InvalidArgumentException If a record is invalid
         * @throws RecordingException If the plugin operator is unavailable
         * @throws RuleException If the host matches too many rules to decide
         */
        public static function verifyEntity(EntityRecord $entity): ?MatchResult
        {
            if($entity->getId() !== null || $entity->isTelephone() || $entity->isWhitelisted())
            {
                return null;
            }

            $target = MatchTarget::fromHost($entity->getHost());
            if($target === null)
            {
                return null;
            }

            $result = FederationAdGuard::match($target);
            FindingRecorder::recordResult($result);

            return $result;
        }

        /**
         * Checks the next batch of host entities, continuing where the previous run stopped and starting over once
         * every entity was checked
         *
         * @param int $limit The number of entities
         * @return array{checked: int, listed: int, completed: bool} What was done
         * @throws DatabaseOperationException If there is an error with the database
         */
        public static function verifyEntities(int $limit): array
        {
            $stats = ['checked' => 0, 'listed' => 0, 'completed' => false];
            if($limit < 1)
            {
                return $stats;
            }

            $cursor = DatabaseConnection::getMetadata(MetadataKey::ENTITY_CURSOR->value) ?? '';

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("SELECT * FROM entities WHERE id IS NULL AND whitelisted = 0 AND uuid > :cursor ORDER BY uuid LIMIT :limit");
                $stmt->bindParam(':cursor', $cursor);
                $stmt->bindParam(':limit', $limit, PDO::PARAM_INT);
                $stmt->execute();

                $entities = array_map(fn($data) => new EntityRecord($data), $stmt->fetchAll(PDO::FETCH_ASSOC));
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to retrieve host entities: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            foreach($entities as $entity)
            {
                $cursor = $entity->getUuid();
                $stats['checked']++;

                try
                {
                    $result = self::verifyEntity($entity);
                    if($result !== null && count($result->getHostBlocks()) > 0)
                    {
                        $stats['listed']++;
                    }
                }
                catch(RuleException|RecordingException|DatabaseOperationException|CacheOperationException|InvalidArgumentException $e)
                {
                    Logger::log()->warning(sprintf('Unable to check the entity %s: %s', $entity->getUuid(), $e->getMessage()), $e);
                }
            }

            if(count($entities) < $limit)
            {
                $stats['completed'] = true;
                $cursor = '';
            }

            DatabaseConnection::setMetadata(MetadataKey::ENTITY_CURSOR->value, $cursor);
            return $stats;
        }

        /**
         * Checks the next batch of the hosts the plugin blacklisted, continuing where the previous run stopped: a host
         * whose entity was deleted is forgotten, a blacklist record an operator lifted or deleted (without the plugin
         * noticing) is suppressed, and the record of an entity that was whitelisted or is no longer listed is lifted
         *
         * @param int $limit The number of findings
         * @return array{checked: int, lifted: int, suppressed: int, forgotten: int, repaired: int} What was done
         * @throws DatabaseOperationException If there is an error with the database
         * @throws CacheOperationException If there is an error during a cache operation
         * @throws InvalidArgumentException If FederationLib rejects the UUID of a blacklist record
         */
        public static function verifyFindings(int $limit): array
        {
            $stats = ['checked' => 0, 'lifted' => 0, 'suppressed' => 0, 'forgotten' => 0, 'repaired' => 0];
            if($limit < 1)
            {
                return $stats;
            }

            $stats['repaired'] = BlacklistRecorder::repairAbandoned();
            [$afterEntity, $afterConcern] = array_pad(explode('|', DatabaseConnection::getMetadata(MetadataKey::FINDING_CURSOR->value) ?? '', 2), 2, '');
            $findings = FindingManager::getFindings($afterEntity, $afterConcern, $limit);

            foreach($findings as $finding)
            {
                $afterEntity = $finding->getEntityUuid();
                $afterConcern = $finding->getConcern()->value;
                if($finding->getState() !== FindingState::ACTIVE)
                {
                    continue;
                }

                $stats['checked']++;
                try
                {
                    self::verifyFinding($finding, $stats);
                }
                catch(RuleException|RecordingException|DatabaseOperationException|CacheOperationException|InvalidArgumentException $e)
                {
                    Logger::log()->warning(sprintf('Unable to check the finding of %s: %s', $finding->getHost(), $e->getMessage()), $e);
                }
            }

            DatabaseConnection::setMetadata(MetadataKey::FINDING_CURSOR->value, count($findings) < $limit ? '' : $afterEntity . '|' . $afterConcern);
            return $stats;
        }

        /**
         * Checks one of the hosts the plugin blacklisted
         *
         * @param FindingRecord $finding The finding, which is active
         * @param array $stats The statistics to update
         * @return void
         * @throws CacheOperationException If there is an error during a cache operation
         * @throws DatabaseOperationException If there is an error with the database
         * @throws RuleException Thrown if there was a rule error
         * @throws InvalidArgumentException If FederationLib rejects the UUID of the entity or the blacklist record
         * @throws RecordingException If the plugin operator is unavailable
         */
        private static function verifyFinding(FindingRecord $finding, array &$stats): void
        {
            $concern = $finding->getConcern();
            $entity = EntitiesManager::getEntityByUuid($finding->getEntityUuid());
            if($entity === null)
            {
                FindingManager::deleteFindings($finding->getEntityUuid());
                $stats['forgotten']++;
                return;
            }

            $blacklistRecord = $finding->getBlacklistUuid() !== null ? BlacklistManager::getBlacklistEntry($finding->getBlacklistUuid()) : null;
            if($blacklistRecord === null || ($blacklistRecord->isLifted() && !PluginOperator::isAutomaticLift($blacklistRecord)))
            {
                FindingManager::updateState($finding->getEntityUuid(), $concern, FindingState::SUPPRESSED, [FindingState::ACTIVE]);
                $stats['suppressed']++;
                return;
            }

            if($blacklistRecord->isLifted())
            {
                // Lifted on the plugin's behalf by a process that stopped before it recorded it
                BlacklistRecorder::lift($entity->getUuid(), $concern, 'the blacklist record was already lifted');
                $stats['lifted']++;
                return;
            }

            if($entity->isWhitelisted())
            {
                BlacklistRecorder::lift($entity->getUuid(), $concern, 'the entity is whitelisted');
                $stats['lifted']++;
                return;
            }

            $target = MatchTarget::fromHost($entity->getHost());
            $listed = $target !== null && array_any(FederationAdGuard::match($target)->getHostBlocks(), fn($match) => $match->getRule()->getConcern() === $concern);

            if(!$listed)
            {
                BlacklistRecorder::lift($entity->getUuid(), $concern, sprintf('%s is no longer listed as %s', $entity->getLoggableAddress(), $concern->name));
                $stats['lifted']++;
            }
        }
    }
