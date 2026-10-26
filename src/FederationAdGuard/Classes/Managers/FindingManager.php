<?php

    namespace FederationAdGuard\Classes\Managers;

    use FederationLib\Classes\Configuration;
    use FederationLib\Classes\DatabaseConnection;
    use FederationAdGuard\Enums\FindingState;
    use FederationAdGuard\Objects\FindingRecord;
    use FederationLib\Classes\RedisConnection;
    use FederationLib\Classes\Utilities;
    use FederationLib\Classes\Validate;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use InvalidArgumentException;
    use PDO;
    use PDOException;

    class FindingManager
    {
        public const string CACHE_PREFIX = 'adguard_finding:';
        private const int CACHE_LIMIT = 5000;
        private const int CACHE_TTL = 600;

        /**
         * Records a finding, the rule that blocks a host entirely for a concern. A new finding has no blacklist record
         * yet (LIFTED), an existing one keeps its state, evidence and blacklist record and is given the current rule.
         *
         * @param string $entityUuid The UUID of the entity.
         * @param IncidentType $concern The concern of the rule.
         * @param string $host The host of the entity.
         * @param string $rule The rule as it is written in the list.
         * @param int|null $subscriptionId The subscription of the rule, null for the inline rules.
         * @throws InvalidArgumentException If the entity UUID is invalid.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function saveFinding(string $entityUuid, IncidentType $concern, string $host, string $rule, ?int $subscriptionId): void
        {
            if(!Validate::uuid($entityUuid))
            {
                throw new InvalidArgumentException('Invalid entity UUID');
            }

            $concernValue = $concern->value;
            $lifted = FindingState::LIFTED->value;
            $rule = mb_strcut($rule, 0, 1024);

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare(
                    "INSERT INTO adguard_findings (entity, concern, host, rule, subscription, state) VALUES (:entity, :concern, :host, :rule, :subscription, :state)
                     ON DUPLICATE KEY UPDATE host = VALUES(host), rule = VALUES(rule), subscription = VALUES(subscription)"
                );
                $stmt->bindParam(':entity', $entityUuid);
                $stmt->bindParam(':concern', $concernValue);
                $stmt->bindParam(':host', $host);
                $stmt->bindParam(':rule', $rule);
                $stmt->bindValue(':subscription', $subscriptionId, $subscriptionId === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
                $stmt->bindParam(':state', $lifted);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to save finding: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearCache($entityUuid, $concern);
        }

        /**
         * Claims the creation of a blacklist record for a finding, so that concurrent requests that find the same host
         * don't both blacklist it. Only a finding without a blacklist record (LIFTED) can be claimed.
         *
         * @param string $entityUuid The UUID of the entity.
         * @param IncidentType $concern The concern.
         * @return bool True if this process claimed it, false if another process did or it is active or suppressed.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function claimFinding(string $entityUuid, IncidentType $concern): bool
        {
            $concernValue = $concern->value;
            $pending = FindingState::PENDING->value;
            $lifted = FindingState::LIFTED->value;

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("UPDATE adguard_findings SET state = :pending, blacklist = NULL WHERE entity = :entity AND concern = :concern AND state = :lifted");
                $stmt->bindParam(':pending', $pending);
                $stmt->bindParam(':entity', $entityUuid);
                $stmt->bindParam(':concern', $concernValue);
                $stmt->bindParam(':lifted', $lifted);
                $stmt->execute();
                $claimed = $stmt->rowCount() > 0;
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to claim finding: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearCache($entityUuid, $concern);
            return $claimed;
        }

        /**
         * Records the evidence record created for a finding.
         *
         * @param string $entityUuid The UUID of the entity.
         * @param IncidentType $concern The concern.
         * @param string $evidenceUuid The UUID of the evidence record.
         * @throws InvalidArgumentException If a UUID is invalid.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function setEvidence(string $entityUuid, IncidentType $concern, string $evidenceUuid): void
        {
            if(!Validate::uuid($entityUuid) || !Validate::uuid($evidenceUuid))
            {
                throw new InvalidArgumentException('Invalid entity or evidence UUID');
            }

            $concernValue = $concern->value;

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("UPDATE adguard_findings SET evidence = :evidence WHERE entity = :entity AND concern = :concern");
                $stmt->bindParam(':evidence', $evidenceUuid);
                $stmt->bindParam(':entity', $entityUuid);
                $stmt->bindParam(':concern', $concernValue);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to record the evidence of the finding: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearCache($entityUuid, $concern);
        }

        /**
         * Records the blacklist record created for a claimed finding.
         *
         * @param string $entityUuid The UUID of the entity.
         * @param IncidentType $concern The concern.
         * @param string $blacklistUuid The UUID of the blacklist record.
         * @return void
         * @throws InvalidArgumentException If a UUID is invalid.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function activateFinding(string $entityUuid, IncidentType $concern, string $blacklistUuid): void
        {
            if(!Validate::uuid($entityUuid) || !Validate::uuid($blacklistUuid))
            {
                throw new InvalidArgumentException('Invalid entity or blacklist UUID');
            }

            $concernValue = $concern->value;
            $state = FindingState::ACTIVE->value;

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("UPDATE adguard_findings SET state = :state, blacklist = :blacklist WHERE entity = :entity AND concern = :concern");
                $stmt->bindParam(':state', $state);
                $stmt->bindParam(':blacklist', $blacklistUuid);
                $stmt->bindParam(':entity', $entityUuid);
                $stmt->bindParam(':concern', $concernValue);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to activate finding: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearCache($entityUuid, $concern);
        }

        /**
         * Changes the state of a finding, only if it is in one of the given states.
         *
         * @param string $entityUuid The UUID of the entity.
         * @param IncidentType $concern The concern.
         * @param FindingState $state The new state.
         * @param FindingState[] $from The states the finding may be in.
         * @return bool True if the state was changed.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function updateState(string $entityUuid, IncidentType $concern, FindingState $state, array $from): bool
        {
            if(count($from) === 0)
            {
                return false;
            }

            try
            {
                [$placeholders, $parameters] = Utilities::getInPlaceholders(array_map(fn(FindingState $item) => $item->value, $from), 'from');
                $parameters[':state'] = $state->value;
                $parameters[':entity'] = $entityUuid;
                $parameters[':concern'] = $concern->value;

                $stmt = DatabaseConnection::getConnection()->prepare("UPDATE adguard_findings SET state = :state WHERE entity = :entity AND concern = :concern AND state IN ($placeholders)");
                $stmt->execute($parameters);
                $updated = $stmt->rowCount() > 0;
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to update the state of the finding: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearCache($entityUuid, $concern);
            return $updated;
        }

        /**
         * Retrieves the finding of an entity and concern.
         *
         * @param string $entityUuid The UUID of the entity.
         * @param IncidentType $concern The concern.
         * @return FindingRecord|null The finding if found, null otherwise.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function getFinding(string $entityUuid, IncidentType $concern): ?FindingRecord
        {
            if(self::isCachingEnabled())
            {
                $cached = RedisConnection::getRecord(self::getCacheKey($entityUuid, $concern));
                if($cached !== null)
                {
                    return new FindingRecord($cached);
                }
            }

            $concernValue = $concern->value;

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("SELECT * FROM adguard_findings WHERE entity = :entity AND concern = :concern");
                $stmt->bindParam(':entity', $entityUuid);
                $stmt->bindParam(':concern', $concernValue);
                $stmt->execute();

                $data = $stmt->fetch(PDO::FETCH_ASSOC);
                if($data === false)
                {
                    return null;
                }

                $data = new FindingRecord($data);
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to retrieve finding: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            if(self::isCachingEnabled() && !RedisConnection::limitReached(self::CACHE_PREFIX, self::CACHE_LIMIT))
            {
                RedisConnection::setRecord(
                    record: $data, cacheKey: self::getCacheKey($data->getEntityUuid(), $data->getConcern()),
                    ttl: self::CACHE_TTL
                );
            }

            return $data;
        }

        /**
         * Retrieves the findings of an entity, one per concern.
         *
         * @param string $entityUuid The UUID of the entity.
         * @return FindingRecord[] The findings.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         */
        public static function getFindingsByEntity(string $entityUuid): array
        {
            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("SELECT * FROM adguard_findings WHERE entity = :entity");
                $stmt->bindParam(':entity', $entityUuid);
                $stmt->execute();

                return array_map(fn($data) => new FindingRecord($data), $stmt->fetchAll(PDO::FETCH_ASSOC));
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to retrieve the findings of the entity: " . $e->getMessage(), (int)$e->getCode(), $e);
            }
        }

        /**
         * Retrieves the findings whose blacklist record is one of the given records.
         *
         * @param string[] $blacklistUuids The UUIDs of the blacklist records.
         * @return array<string, FindingRecord> The findings by the UUID of their blacklist record.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         */
        public static function getFindingsByBlacklists(array $blacklistUuids): array
        {
            $blacklistUuids = array_values(array_unique(array_filter($blacklistUuids, fn($uuid) => is_string($uuid) && Validate::uuid($uuid))));
            if(count($blacklistUuids) === 0)
            {
                return [];
            }

            try
            {
                [$placeholders, $parameters] = Utilities::getInPlaceholders($blacklistUuids);
                $stmt = DatabaseConnection::getConnection()->prepare("SELECT * FROM adguard_findings WHERE blacklist IN ($placeholders)");
                $stmt->execute($parameters);

                $results = [];
                foreach($stmt->fetchAll(PDO::FETCH_ASSOC) as $data)
                {
                    $record = new FindingRecord($data);
                    $results[$record->getBlacklistUuid()] = $record;
                }

                return $results;
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to retrieve the findings of the blacklist records: " . $e->getMessage(), (int)$e->getCode(), $e);
            }
        }

        /**
         * Retrieves the findings in the order of their entity and concern, after a cursor.
         *
         * @param string $afterEntity The entity UUID to continue after, an empty string to start at the beginning.
         * @param string $afterConcern The concern to continue after.
         * @param int $limit The maximum number of findings.
         * @return FindingRecord[] The findings.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         */
        public static function getFindings(string $afterEntity, string $afterConcern, int $limit): array
        {
            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare(
                    "SELECT * FROM adguard_findings WHERE entity > :entity OR (entity = :same_entity AND concern > :concern) ORDER BY entity, CAST(concern AS CHAR) LIMIT :limit"
                );
                $stmt->bindParam(':entity', $afterEntity);
                $stmt->bindParam(':same_entity', $afterEntity);
                $stmt->bindParam(':concern', $afterConcern);
                $stmt->bindParam(':limit', $limit, PDO::PARAM_INT);
                $stmt->execute();

                return array_map(fn($data) => new FindingRecord($data), $stmt->fetchAll(PDO::FETCH_ASSOC));
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to retrieve findings: " . $e->getMessage(), (int)$e->getCode(), $e);
            }
        }

        /**
         * Retrieves the findings left pending since before the given time, by a process that stopped while
         * creating their blacklist record.
         *
         * @param int $before The Unix timestamp.
         * @return FindingRecord[] The findings.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         */
        public static function getAbandonedFindings(int $before): array
        {
            $pending = FindingState::PENDING->value;
            $before = date('Y-m-d H:i:s', $before);

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("SELECT * FROM adguard_findings WHERE state = :state AND updated < :before");
                $stmt->bindParam(':state', $pending);
                $stmt->bindParam(':before', $before);
                $stmt->execute();

                return array_map(fn($data) => new FindingRecord($data), $stmt->fetchAll(PDO::FETCH_ASSOC));
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to retrieve abandoned findings: " . $e->getMessage(), (int)$e->getCode(), $e);
            }
        }

        /**
         * Deletes the findings of an entity, e.g., after the entity was deleted.
         *
         * @param string $entityUuid The UUID of the entity.
         * @return void
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function deleteFindings(string $entityUuid): void
        {
            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("DELETE FROM adguard_findings WHERE entity = :entity");
                $stmt->bindParam(':entity', $entityUuid);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to delete the findings of the entity: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            foreach(IncidentType::cases() as $concern)
            {
                self::clearCache($entityUuid, $concern);
            }
        }

        /**
         * Returns the cache key of a finding.
         *
         * @param string $entityUuid The UUID of the entity.
         * @param IncidentType $concern The concern.
         * @return string The cache key.
         */
        private static function getCacheKey(string $entityUuid, IncidentType $concern): string
        {
            return sprintf("%s%s:%s", self::CACHE_PREFIX, $entityUuid, $concern->value);
        }

        /**
         * Removes a finding from the cache.
         *
         * @param string $entityUuid The UUID of the entity.
         * @param IncidentType $concern The concern.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        private static function clearCache(string $entityUuid, IncidentType $concern): void
        {
            if(self::isCachingEnabled() && RedisConnection::recordExists(self::getCacheKey($entityUuid, $concern)))
            {
                RedisConnection::getConnection()->del(self::getCacheKey($entityUuid, $concern));
            }
        }

        /**
         * Checks if caching is enabled for findings, they are cached when FederationLib's Redis is enabled.
         *
         * @return bool True if caching is enabled, false otherwise.
         */
        private static function isCachingEnabled(): bool
        {
            return Configuration::getRedisConfiguration()->isEnabled();
        }
    }
