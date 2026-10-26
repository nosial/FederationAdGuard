<?php

    namespace FederationAdGuard\Classes\Managers;

    use FederationAdGuard\Classes\Configuration;
    use FederationLib\Classes\DatabaseConnection;
    use FederationAdGuard\Enums\RuleType;
    use FederationAdGuard\Objects\FilterRule;
    use FederationLib\Classes\RedisConnection;
    use FederationLib\Classes\Utilities;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use PDO;
    use PDOException;

    class RuleManager
    {
        public const string CACHE_PREFIX = 'adguard_rule:';

        /**
         * The number of rules inserted by one statement
         */
        private const int BATCH_SIZE = 500;
        private const int CACHE_TTL = 600;

        /**
         * The maximum number of hosts or tokens looked up at once
         */
        private const int MAX_KEYS = 200;

        /**
         * The columns of adguard_rules written by replaceRules(), in the order of their values
         */
        private const array COLUMNS = [
            'subscription_id', 'bucket', 'rule', 'action', 'type', 'host', 'subdomains', 'token', 'regex', 'regex_subject',
            'partial', 'important', 'badfilter', 'dns_types', 'deny_allow', 'fingerprint', 'concern'
        ];

        /**
         * Replaces the rules of a subscription in a single transaction, requests keep matching the previous rules until
         * it's committed and the previous rules are kept if it fails.
         *
         * @param int $subscriptionId The ID of the subscription.
         * @param FilterRule[] $rules The rules.
         * @param IncidentType|null $concern The concern of every rule, null to keep the concern of each rule (custom rules).
         * @return void
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function replaceRules(int $subscriptionId, array $rules, ?IncidentType $concern): void
        {
            $connection = DatabaseConnection::getConnection();

            try
            {
                $connection->beginTransaction();

                $stmt = $connection->prepare("DELETE FROM adguard_rules WHERE subscription_id = :subscription_id");
                $stmt->bindParam(':subscription_id', $subscriptionId, PDO::PARAM_INT);
                $stmt->execute();

                foreach(array_chunk($rules, self::BATCH_SIZE) as $batch)
                {
                    self::insertRules($connection, $subscriptionId, $batch, $concern);
                }

                $connection->commit();
            }
            catch (PDOException $e)
            {
                if($connection->inTransaction())
                {
                    $connection->rollBack();
                }

                throw new DatabaseOperationException("Failed to replace the rules of the subscription: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearRuleCache();
        }

        /**
         * Changes the concern of every rule of a subscription.
         *
         * @param int $subscriptionId The ID of the subscription.
         * @param IncidentType $concern The concern.
         * @return void
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function updateConcern(int $subscriptionId, IncidentType $concern): void
        {
            $concernValue = $concern->value;

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("UPDATE adguard_rules SET concern = :concern WHERE subscription_id = :subscription_id");
                $stmt->bindParam(':concern', $concernValue);
                $stmt->bindParam(':subscription_id', $subscriptionId, PDO::PARAM_INT);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to update the concern of the rules: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearRuleCache();
        }

        /**
         * Retrieves the HOST, IP and URL rules of the subscriptions whose rules apply indexed by one of the given hosts.
         *
         * @param string[] $hosts The DNS names (a name and its parent domains) and IP addresses.
         * @return FilterRule[] The rules.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function getRulesByHosts(array $hosts): array
        {
            return self::getIndexedRules('HOST', 'host', $hosts);
        }

        /**
         * Retrieves the URL rules of the subscriptions whose rules apply indexed by one of the given tokens.
         *
         * @param string[] $tokens The tokens of a URL.
         * @return FilterRule[] The rules.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function getRulesByTokens(array $tokens): array
        {
            return self::getIndexedRules('TOKEN', 'token', $tokens);
        }

        /**
         * Retrieves the rules of the subscriptions whose rules apply that are not indexed: REGEX rules and URL rules without a
         * host or token, which are evaluated for every target.
         *
         * @return FilterRule[] The rules.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function getUnindexedRules(): array
        {
            $cacheKey = null;
            if(self::isCachingEnabled())
            {
                $cacheKey = RedisConnection::getSearchCacheKey(self::CACHE_PREFIX, ['NONE', Configuration::getFilterListsConfiguration()->isEnabled()]);
                $cached = RedisConnection::getCachedSearchResults($cacheKey);
                if($cached !== null)
                {
                    return array_map(fn($data) => new FilterRule($data), $cached);
                }
            }

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare(
                    "SELECT r.* FROM adguard_rules r INNER JOIN adguard_subscriptions s ON s.id = r.subscription_id WHERE r.bucket = 'NONE'" . self::getSourceCondition()
                );
                $stmt->execute();

                $results = array_map(fn($data) => new FilterRule($data), $stmt->fetchAll(PDO::FETCH_ASSOC));
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to retrieve the rules that are not indexed: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            if($cacheKey !== null)
            {
                RedisConnection::cacheSearchResults($cacheKey, array_map(fn(FilterRule $rule) => $rule->toArray(), $results), self::CACHE_TTL);
            }

            return $results;
        }

        /**
         * Returns the concerns there are blocking rules for, of the subscriptions whose rules apply.
         *
         * @return IncidentType[] The concerns.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function getConcerns(): array
        {
            $cacheKey = null;
            if(self::isCachingEnabled())
            {
                $cacheKey = RedisConnection::getSearchCacheKey(self::CACHE_PREFIX, ['CONCERNS', Configuration::getFilterListsConfiguration()->isEnabled()]);
                $cached = RedisConnection::getCachedSearchResults($cacheKey);
                if($cached !== null)
                {
                    return array_values(array_filter(array_map(fn($data) => IncidentType::tryFrom((string)($data['concern'] ?? '')), $cached)));
                }
            }

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare(
                    "SELECT DISTINCT r.concern FROM adguard_rules r INNER JOIN adguard_subscriptions s ON s.id = r.subscription_id WHERE r.action = 'BLOCK'" . self::getSourceCondition()
                );
                $stmt->execute();
                $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to retrieve the concerns of the rules: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            if($cacheKey !== null)
            {
                RedisConnection::cacheSearchResults($cacheKey, $rows, self::CACHE_TTL);
            }

            return array_values(array_filter(array_map(fn($data) => IncidentType::tryFrom((string)($data['concern'] ?? '')), $rows)));
        }

        /**
         * Returns how a rule is indexed in adguard_rules.
         *
         * @param FilterRule $rule The rule.
         * @return string HOST, TOKEN or NONE.
         */
        public static function getBucket(FilterRule $rule): string
        {
            if($rule->getHost() !== null && $rule->getType() !== RuleType::REGEX)
            {
                return 'HOST';
            }

            return $rule->getToken() !== null ? 'TOKEN' : 'NONE';
        }

        /**
         * Invalidates every cached rule lookup, after the rules that apply changed (rules were replaced, a list was
         * deleted, or its concern changed).
         *
         * @return void
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function clearRuleCache(): void
        {
            if(self::isCachingEnabled())
            {
                RedisConnection::clearSearchCache(self::CACHE_PREFIX);
            }
        }

        /**
         * Retrieves the rules of the subscriptions whose rules apply indexed by one of the given keys, the result of every lookup
         * (including lookups that find nothing, the most common) is cached until the rules change.
         *
         * @param string $bucket The index, HOST or TOKEN.
         * @param string $column The indexed column.
         * @param string[] $keys The keys.
         * @return FilterRule[] The rules.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        private static function getIndexedRules(string $bucket, string $column, array $keys): array
        {
            $keys = array_values(array_unique(array_filter($keys, fn($key) => is_string($key) && $key !== '' && strlen($key) <= 255)));
            if(count($keys) > self::MAX_KEYS)
            {
                $results = [];
                foreach(array_chunk($keys, self::MAX_KEYS) as $batch)
                {
                    array_push($results, ...self::getIndexedRules($bucket, $column, $batch));
                }

                return $results;
            }
            if(count($keys) === 0)
            {
                return [];
            }

            sort($keys);
            $cacheKey = null;
            if(self::isCachingEnabled())
            {
                $cacheKey = RedisConnection::getSearchCacheKey(self::CACHE_PREFIX, [$bucket, $keys, Configuration::getFilterListsConfiguration()->isEnabled()]);
                $cached = RedisConnection::getCachedSearchResults($cacheKey);
                if($cached !== null)
                {
                    return array_map(fn($data) => new FilterRule($data), $cached);
                }
            }

            try
            {
                [$placeholders, $parameters] = Utilities::getInPlaceholders($keys, 'key');
                $parameters[':bucket'] = $bucket;

                $stmt = DatabaseConnection::getConnection()->prepare(
                    "SELECT r.* FROM adguard_rules r INNER JOIN adguard_subscriptions s ON s.id = r.subscription_id WHERE r.bucket = :bucket AND r.$column IN ($placeholders)" . self::getSourceCondition()
                );
                $stmt->execute($parameters);

                $results = array_map(fn($data) => new FilterRule($data), $stmt->fetchAll(PDO::FETCH_ASSOC));
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to retrieve the rules: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            if($cacheKey !== null)
            {
                RedisConnection::cacheSearchResults($cacheKey, array_map(fn(FilterRule $rule) => $rule->toArray(), $results), self::CACHE_TTL);
            }

            return $results;
        }

        /**
         * Inserts a batch of rules.
         *
         * @param PDO $connection The connection.
         * @param int $subscriptionId The ID of the subscription.
         * @param FilterRule[] $rules The rules.
         * @param IncidentType|null $concern The concern of every rule, null to keep the concern of each rule.
         * @return void
         * @throws PDOException If the statement fails.
         */
        private static function insertRules(PDO $connection, int $subscriptionId, array $rules, ?IncidentType $concern): void
        {
            $placeholders = [];
            $values = [];
            foreach($rules as $rule)
            {
                $data = $rule->toArray();
                $data['subscription_id'] = $subscriptionId;
                $data['bucket'] = self::getBucket($rule);
                $data['concern'] = ($concern ?? $rule->getConcern() ?? IncidentType::ADVERTISING)->value;
                foreach(['subdomains', 'partial', 'important', 'badfilter'] as $flag)
                {
                    $data[$flag] = $data[$flag] ? 1 : 0;
                }

                $placeholders[] = '(' . implode(', ', array_fill(0, count(self::COLUMNS), '?')) . ')';
                foreach(self::COLUMNS as $column)
                {
                    $values[] = $data[$column];
                }
            }

            $stmt = $connection->prepare(sprintf("INSERT INTO adguard_rules (%s) VALUES %s", implode(', ', self::COLUMNS), implode(', ', $placeholders)));
            $stmt->execute($values);
        }

        /**
         * Returns the condition that leaves out the FilterLists subscriptions while the FilterLists feature is disabled
         *
         * @return string The SQL condition, empty while the feature is enabled
         */
        private static function getSourceCondition(): string
        {
            return Configuration::getFilterListsConfiguration()->isEnabled() ? '' : " AND s.source <> 'FILTERLISTS'";
        }

        /**
         * Checks if rule lookups are cached, they are cached when FederationLib's Redis is enabled.
         *
         * @return bool True if caching is enabled, false otherwise.
         */
        private static function isCachingEnabled(): bool
        {
            return \FederationLib\Classes\Configuration::getRedisConfiguration()->isEnabled();
        }
    }
