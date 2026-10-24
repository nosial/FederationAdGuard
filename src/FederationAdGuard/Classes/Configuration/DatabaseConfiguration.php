<?php

    namespace FederationAdGuard\Classes\Configuration;

    use FederationLib\Classes\Configuration\ConfigurationValues;

    class DatabaseConfiguration
    {
        /**
         * The number of findings and of host entities each maintenance run checks
         */
        public const int MAINTENANCE_BATCH = 2000;

        /**
         * The age, in seconds, at which a blacklist record left unfinished by a stopped process is repaired
         */
        public const int PENDING_TIMEOUT = 900;

        /**
         * How far back, in seconds, an earlier offence of an author makes a new one a repeat offence (7 days)
         */
        public const int AUTHOR_REPEAT_WINDOW = 604800;

        private bool $enabled;
        private ?int $authorBlacklist;

        /**
         * DatabaseConfiguration constructor.
         *
         * @param array $configuration The values of the `database` section
         */
        public function __construct(array $configuration)
        {
            $this->enabled = ConfigurationValues::parseBool($configuration['enabled'] ?? null, true);

            // Always temporary, an author is never blacklisted permanently by the plugin
            $authorBlacklist = ConfigurationValues::parseDuration($configuration['author_blacklist'] ?? '1d', 86400);
            $this->authorBlacklist = $authorBlacklist !== null && $authorBlacklist > 0 ? max(60, $authorBlacklist) : null;
        }

        /**
         * Checks if the plugin builds the database: findings of the listed hosts and records of the authors that send
         * them
         *
         * @return bool True if enabled
         */
        public function isEnabled(): bool
        {
            return $this->enabled;
        }

        /**
         * Returns how long an author who repeatedly sends messages of listed links is blacklisted for, the server's
         * minimum blacklist time still applies
         *
         * @return int|null The duration in seconds, null if authors are only given evidence
         */
        public function getAuthorBlacklist(): ?int
        {
            return $this->enabled ? $this->authorBlacklist : null;
        }
    }
