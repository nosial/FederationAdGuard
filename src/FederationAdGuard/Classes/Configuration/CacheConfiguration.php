<?php

    namespace FederationAdGuard\Classes\Configuration;

    use FederationLib\Classes\Configuration\ConfigurationValues;

    class CacheConfiguration
    {
        public const array DEFAULT_RECORD_CACHE = [
            'SUBSCRIPTION' => ['limit' => 500, 'ttl' => 600],
            'LISTED_HOST' => ['limit' => 5000, 'ttl' => 600],
        ];

        private bool $enabled;
        /**
         * @var array<string, array{limit: int, ttl: int}>
         */
        private array $recordCache;
        private int $ruleCacheTtl;

        /**
         * CacheConfiguration constructor.
         *
         * @param array $configuration The cache configuration values
         */
        public function __construct(array $configuration)
        {
            $this->enabled = ConfigurationValues::parseBool($configuration['enabled'] ?? null, true);
            $this->ruleCacheTtl = ConfigurationValues::parseDuration($configuration['rule_cache_ttl'] ?? '10m', 600) ?? 0;
            $configured = ConfigurationValues::parseMap($configuration['record_cache'] ?? []);
            $this->recordCache = [];
            foreach(self::DEFAULT_RECORD_CACHE as $type => $default)
            {
                $value = $configured[$type] ?? null;
                if(is_string($value))
                {
                    $parts = explode('/', $value, 2);
                    $value = ['limit' => $parts[0], 'ttl' => $parts[1] ?? $default['ttl']];
                }

                $value = is_array($value) ? $value : [];
                $this->recordCache[$type] = [
                    'limit' => max(0, (int)($value['limit'] ?? $default['limit'])),
                    'ttl' => ConfigurationValues::parseDuration($value['ttl'] ?? $default['ttl'], $default['ttl']) ?? 0,
                ];
            }
        }

        /**
         * Checks if the plugin caches in FederationLib's Redis, which also requires FederationLib's Redis to be enabled
         *
         * @return bool True if enabled
         */
        public function isEnabled(): bool
        {
            return $this->enabled;
        }

        /**
         * Returns the maximum number of cached records of a record type, 0 when its cache is disabled
         *
         * @param string $type The record type, one of the keys of DEFAULT_RECORD_CACHE
         * @return int The maximum number of cached records
         */
        public function getRecordCacheLimit(string $type): int
        {
            return $this->recordCache[$type]['limit'] ?? 0;
        }

        /**
         * Returns the TTL of cached records of a record type in seconds, 0 for no expiry
         *
         * @param string $type The record type, one of the keys of DEFAULT_RECORD_CACHE
         * @return int The TTL in seconds
         */
        public function getRecordCacheTtl(string $type): int
        {
            return $this->recordCache[$type]['ttl'] ?? 0;
        }

        /**
         * Checks if records of a record type are cached
         *
         * @param string $type The record type, one of the keys of DEFAULT_RECORD_CACHE
         * @return bool True if the cache of the record type is enabled
         */
        public function isRecordCacheEnabled(string $type): bool
        {
            return $this->getRecordCacheLimit($type) > 0;
        }

        /**
         * Returns how long the rules found for a host or a token, and the rules that are not indexed, are cached
         *
         * @return int The TTL in seconds, 0 disables the rule cache
         */
        public function getRuleCacheTtl(): int
        {
            return $this->ruleCacheTtl;
        }

        /**
         * Checks if the rules found for a host or a token are cached
         *
         * @return bool True if rule lookups are cached
         */
        public function isRuleCacheEnabled(): bool
        {
            return $this->ruleCacheTtl > 0;
        }
    }
