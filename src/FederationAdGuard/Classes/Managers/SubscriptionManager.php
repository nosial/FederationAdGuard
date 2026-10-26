<?php

    namespace FederationAdGuard\Classes\Managers;

    use FederationAdGuard\Classes\Logger;
    use FederationLib\Classes\Configuration;
    use FederationLib\Classes\DatabaseConnection;
    use FederationAdGuard\Enums\ListSource;
    use FederationAdGuard\Objects\SubscriptionRecord;
    use FederationLib\Classes\RedisConnection;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use InvalidArgumentException;
    use PDO;
    use PDOException;

    class SubscriptionManager
    {
        public const string CACHE_PREFIX = 'adguard_subscription:';
        private const int CACHE_LIMIT = 500;
        private const int CACHE_TTL = 600;

        /**
         * Creates a new subscription to a filter list.
         *
         * @param ListSource $source Where the rules come from, FILTERLISTS, URL or FILE.
         * @param int|null $filterListsId The FilterLists ID of the list, required for a FILTERLISTS subscription.
         * @param string|null $location The URL or local path of the list, required for a URL or FILE subscription.
         * @param string $name The name of the list.
         * @param IncidentType|null $concern Optional. The concern the rules detect, null to derive it from the list's tags.
         * @param bool $allowlist Whether every rule of the list is an exception.
         * @return int The ID of the created subscription.
         * @throws InvalidArgumentException If the subscription is invalid or the server already subscribes to the list.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         */
        public static function createSubscription(ListSource $source, ?int $filterListsId, ?string $location, string $name, ?IncidentType $concern=null, bool $allowlist=false): int
        {
            if($source === ListSource::CUSTOM)
            {
                throw new InvalidArgumentException('There is only one subscription of custom rules');
            }

            if($source === ListSource::FILTERLISTS && ($filterListsId === null || $filterListsId < 1))
            {
                throw new InvalidArgumentException('A FilterLists subscription requires the ID of the list');
            }

            if($source === ListSource::URL && ($location === null || !preg_match('/^https?:\/\/\S+$/i', $location) || strlen($location) > 2048))
            {
                throw new InvalidArgumentException('A URL subscription requires an HTTP or HTTPS URL of at most 2048 characters');
            }

            if($source === ListSource::FILE && ($location === null || $location === '' || str_contains($location, '://')))
            {
                throw new InvalidArgumentException('A file subscription requires a local path');
            }

            $name = trim($name);
            if(strlen($name) < 1 || mb_strlen($name) > 255)
            {
                throw new InvalidArgumentException('The name must be 1 to 255 characters long');
            }

            if($source === ListSource::FILTERLISTS && self::getSubscriptionByFilterListsId($filterListsId) !== null)
            {
                throw new InvalidArgumentException(sprintf('The server already subscribes to the FilterLists list %d', $filterListsId));
            }

            $sourceValue = $source->value;
            $filterListsId = $source === ListSource::FILTERLISTS ? $filterListsId : null;
            $location = $source !== ListSource::FILTERLISTS ? $location : null;
            $concernValue = $concern?->value;

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare(
                    "INSERT INTO adguard_subscriptions (source, filterlists_id, location, name, concern, allowlist)
                     VALUES (:source, :filterlists_id, :location, :name, :concern, :allowlist)"
                );
                $stmt->bindParam(':source', $sourceValue);
                $stmt->bindParam(':filterlists_id', $filterListsId, $filterListsId === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
                $stmt->bindParam(':location', $location);
                $stmt->bindParam(':name', $name);
                $stmt->bindParam(':concern', $concernValue);
                $stmt->bindParam(':allowlist', $allowlist, PDO::PARAM_BOOL);
                $stmt->execute();

                $id = (int)DatabaseConnection::getConnection()->lastInsertId();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to create subscription: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            if(self::isCachingEnabled())
            {
                RedisConnection::clearSearchCache(self::CACHE_PREFIX);
            }

            Logger::log()->info(sprintf('Subscribed to %s as subscription %d (%s)', $source === ListSource::FILTERLISTS ? sprintf('the FilterLists list %d', $filterListsId) : $location,
                $id, $name));
            return $id;
        }

        /**
         * Retrieves a subscription by its ID.
         *
         * @param int $id The ID of the subscription.
         * @return SubscriptionRecord|null The subscription if found, null otherwise.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function getSubscription(int $id): ?SubscriptionRecord
        {
            if(self::isCachingEnabled())
            {
                $cached = RedisConnection::getRecord(sprintf("%s%d", self::CACHE_PREFIX, $id));
                if($cached !== null)
                {
                    return new SubscriptionRecord($cached);
                }
            }

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("SELECT * FROM adguard_subscriptions WHERE id = :id");
                $stmt->bindParam(':id', $id, PDO::PARAM_INT);
                $stmt->execute();

                $data = $stmt->fetch(PDO::FETCH_ASSOC);
                if($data === false)
                {
                    return null;
                }

                $data = new SubscriptionRecord($data);
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to retrieve subscription: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            if(self::isCachingEnabled() && !RedisConnection::limitReached(self::CACHE_PREFIX, self::CACHE_LIMIT))
            {
                RedisConnection::setRecord(
                    record: $data, cacheKey: sprintf("%s%d", self::CACHE_PREFIX, $data->getId()),
                    ttl: self::CACHE_TTL
                );
            }

            return $data;
        }

        /**
         * Retrieves the subscription to a list of the FilterLists directory.
         *
         * @param int $filterListsId The FilterLists ID of the list.
         * @return SubscriptionRecord|null The subscription if the server subscribes to the list, null otherwise.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function getSubscriptionByFilterListsId(int $filterListsId): ?SubscriptionRecord
        {
            return array_find(self::getSubscriptions(), fn(SubscriptionRecord $subscription) => $subscription->getFilterListsId() === $filterListsId);
        }

        /**
         * Retrieves every subscription, the custom rules first.
         *
         * @return SubscriptionRecord[] The subscriptions.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function getSubscriptions(): array
        {
            $cacheKey = null;
            if(self::isCachingEnabled())
            {
                $cacheKey = RedisConnection::getSearchCacheKey(self::CACHE_PREFIX, ['all']);
                $cached = RedisConnection::getCachedSearchResults($cacheKey);
                if($cached !== null)
                {
                    return array_map(fn($data) => new SubscriptionRecord($data), $cached);
                }
            }

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("SELECT * FROM adguard_subscriptions ORDER BY source = 'CUSTOM' DESC, id");
                $stmt->execute();

                $results = array_map(fn($data) => new SubscriptionRecord($data), $stmt->fetchAll(PDO::FETCH_ASSOC));
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to retrieve subscriptions: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            if($cacheKey !== null)
            {
                RedisConnection::cacheSearchResults($cacheKey, array_map(fn(SubscriptionRecord $record) => $record->toArray(), $results),
                    self::CACHE_TTL
                );
            }

            return $results;
        }

        /**
         * Retrieves the subscription of the custom rules, creating it if it doesn't exist yet.
         *
         * @return SubscriptionRecord The subscription of the custom rules.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function getCustomSubscription(): SubscriptionRecord
        {
            foreach(self::getSubscriptions() as $subscription)
            {
                if($subscription->getSource() === ListSource::CUSTOM)
                {
                    return $subscription;
                }
            }

            $source = ListSource::CUSTOM->value;
            $name = 'Custom rules';

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("INSERT INTO adguard_subscriptions (source, name) VALUES (:source, :name)");
                $stmt->bindParam(':source', $source);
                $stmt->bindParam(':name', $name);
                $stmt->execute();

                $id = (int)DatabaseConnection::getConnection()->lastInsertId();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to create the subscription of the custom rules: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            if(self::isCachingEnabled())
            {
                RedisConnection::clearSearchCache(self::CACHE_PREFIX);
            }

            return self::getSubscription($id);
        }

        /**
         * Returns the names of the subscriptions by their ID, the sources of the detections their rules make.
         *
         * @return array<int, string> The names.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function getNames(): array
        {
            $names = [];
            foreach(self::getSubscriptions() as $subscription)
            {
                $names[$subscription->getId()] = $subscription->getName();
            }

            return $names;
        }

        /**
         * Updates the settings of a subscription, only the given settings are changed. Changing its concern changes
         * the concern of its rules, changing whether it's an allowlist downloads it again.
         *
         * @param int $id The ID of the subscription.
         * @param array{name?: string, concern?: IncidentType|null, allowlist?: bool} $settings The settings.
         * @return void
         * @throws InvalidArgumentException If a setting can't be changed.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function updateSettings(int $id, array $settings): void
        {
            $subscription = self::getSubscription($id);
            if($subscription === null)
            {
                throw new InvalidArgumentException(sprintf('The subscription %d does not exist', $id));
            }

            $columns = [];
            $values = [];
            foreach($settings as $name => $value)
            {
                $values[':' . $name] = match($name)
                {
                    'name' => trim((string)$value),
                    'concern' => $value instanceof IncidentType ? $value->value : null,
                    'allowlist' => $value ? 1 : 0,
                    default => throw new InvalidArgumentException(sprintf('The setting "%s" cannot be changed', $name)),
                };

                $columns[] = sprintf('%s = :%s', $name, $name);
            }

            if(count($columns) === 0)
            {
                return;
            }

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare(sprintf("UPDATE adguard_subscriptions SET %s WHERE id = :id", implode(', ', $columns)));
                foreach($values as $placeholder => $value)
                {
                    $stmt->bindValue($placeholder, $value, $value === null ? PDO::PARAM_NULL : (is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR));
                }
                $stmt->bindValue(':id', $id, PDO::PARAM_INT);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to update subscription: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearCache($id);
            Logger::log()->info(sprintf('Updated the settings of subscription %d (%s): %s', $id, $subscription->getName(), implode(', ', array_map(
                fn(string $name, $value) => sprintf('%s=%s', $name, match(true)
                {
                    $value instanceof IncidentType => $value->value,
                    is_bool($value) => $value ? 'true' : 'false',
                    $value === null => 'default',
                    default => (string)$value,
                }),
                array_keys($settings), $settings
            ))));

            // The custom rules keep the concern each of them was added with
            if(array_key_exists('concern', $settings) && $subscription->getSource() !== ListSource::CUSTOM)
            {
                RuleManager::updateConcern($id, self::getSubscription($id)->getEffectiveConcern());
            }

            if(array_key_exists('allowlist', $settings))
            {
                self::markForUpdate($id);
            }
        }

        /**
         * Updates what the FilterLists directory says about a list.
         *
         * @param int $id The ID of the subscription.
         * @param string $name The name of the list.
         * @param IncidentType|null $tagConcern The concern derived from the list's tags.
         * @return void
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function updateDetails(int $id, string $name, ?IncidentType $tagConcern): void
        {
            $name = mb_substr(trim($name), 0, 255);
            if(strlen($name) < 1)
            {
                $name = sprintf('FilterLists list %d', $id);
            }

            $tagConcernValue = $tagConcern?->value;

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("UPDATE adguard_subscriptions SET name = :name, tag_concern = :tag_concern WHERE id = :id");
                $stmt->bindParam(':name', $name);
                $stmt->bindParam(':tag_concern', $tagConcernValue);
                $stmt->bindParam(':id', $id, PDO::PARAM_INT);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to update the details of the subscription: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearCache($id);
        }

        /**
         * Records a successful update of a list.
         *
         * @param int $id The ID of the subscription.
         * @param string|null $checksum The SHA-256 checksum of the list, null for the custom rules.
         * @param array $validators The ETag and Last-Modified of each URL of the list.
         * @return void
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function recordUpdate(int $id, ?string $checksum, array $validators): void
        {
            $validators = json_encode($validators, JSON_UNESCAPED_SLASHES);

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare(
                    "UPDATE adguard_subscriptions SET checksum = :checksum, validators = :validators,
                     last_checked = CURRENT_TIMESTAMP WHERE id = :id"
                );
                $stmt->bindParam(':checksum', $checksum);
                $stmt->bindParam(':validators', $validators);
                $stmt->bindParam(':id', $id, PDO::PARAM_INT);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to record the update of the subscription: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearCache($id);
        }

        /**
         * Records that a list was found unchanged.
         *
         * @param int $id The ID of the subscription.
         * @param array $validators The ETag and Last-Modified of each URL of the list.
         * @return void
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function recordUnchanged(int $id, array $validators): void
        {
            $validators = json_encode($validators, JSON_UNESCAPED_SLASHES);

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("UPDATE adguard_subscriptions SET validators = :validators, last_checked = CURRENT_TIMESTAMP WHERE id = :id");
                $stmt->bindParam(':validators', $validators);
                $stmt->bindParam(':id', $id, PDO::PARAM_INT);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to record the subscription as unchanged: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearCache($id);
        }

        /**
         * Records a failed update of a list, its rules are kept and it is tried again after its update interval.
         *
         * @param int $id The ID of the subscription.
         * @return void
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function recordError(int $id): void
        {
            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("UPDATE adguard_subscriptions SET last_checked = CURRENT_TIMESTAMP WHERE id = :id");
                $stmt->bindParam(':id', $id, PDO::PARAM_INT);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to record the error of the subscription: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearCache($id);
        }

        /**
         * Makes a list due for an update that downloads it entirely, e.g., after it became an allowlist.
         *
         * @param int $id The ID of the subscription.
         * @return void
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function markForUpdate(int $id): void
        {
            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("UPDATE adguard_subscriptions SET last_checked = NULL, checksum = NULL, validators = NULL WHERE id = :id");
                $stmt->bindParam(':id', $id, PDO::PARAM_INT);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to mark the subscription for an update: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearCache($id);
        }

        /**
         * Deletes a subscription and its rules, the subscription of the custom rules can't be deleted.
         *
         * @param int $id The ID of the subscription.
         * @return void
         * @throws InvalidArgumentException If the subscription is the subscription of the custom rules.
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function deleteSubscription(int $id): void
        {
            $subscription = self::getSubscription($id);
            if($subscription === null)
            {
                return;
            }

            if($subscription->getSource() === ListSource::CUSTOM)
            {
                throw new InvalidArgumentException('The subscription of the custom rules cannot be deleted');
            }

            try
            {
                // The rules of the subscription are deleted with it (adguard_rules_adguard_subscriptions_id_fk)
                $stmt = DatabaseConnection::getConnection()->prepare("DELETE FROM adguard_subscriptions WHERE id = :id");
                $stmt->bindParam(':id', $id, PDO::PARAM_INT);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to delete subscription: " . $e->getMessage(), (int)$e->getCode(), $e);
            }

            self::clearCache($id);
            RuleManager::clearRuleCache();
            Logger::log()->info(sprintf('Deleted subscription %d (%s) and its rules', $id, $subscription->getName()));
        }

        /**
         * Removes a subscription from the cache, and the cached lists of subscriptions.
         *
         * @param int $id The ID of the subscription.
         * @return void
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        private static function clearCache(int $id): void
        {
            if(!self::isCachingEnabled())
            {
                return;
            }

            if(RedisConnection::recordExists(sprintf("%s%d", self::CACHE_PREFIX, $id)))
            {
                RedisConnection::getConnection()->del(sprintf("%s%d", self::CACHE_PREFIX, $id));
            }

            RedisConnection::clearSearchCache(self::CACHE_PREFIX);
        }

        /**
         * Checks if caching is enabled for subscriptions, they are cached when FederationLib's Redis is enabled.
         *
         * @return bool True if caching is enabled, false otherwise.
         */
        private static function isCachingEnabled(): bool
        {
            return Configuration::getRedisConfiguration()->isEnabled();
        }
    }
