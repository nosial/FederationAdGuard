<?php

    namespace FederationAdGuard\Classes\Configuration;

    use FederationAdGuard\Classes\Logger;
    use FederationAdGuard\Objects\CustomRuleDefinition;
    use FederationAdGuard\Objects\SubscriptionDefinition;
    use FederationLib\Classes\Configuration\ConfigurationValues;
    use FederationLib\Enums\IncidentType;
    use FederationAdGuard\Exceptions\ConfigurationException;

    class ListsConfiguration
    {
        /**
         * The shortest interval lists are updated in, in seconds
         */
        public const int MINIMUM_UPDATE_INTERVAL = 3600;

        /**
         * The seconds a list download may take
         */
        public const int DOWNLOAD_TIMEOUT = 120;

        /**
         * The seconds to wait for a connection when downloading a list
         */
        public const int CONNECT_TIMEOUT = 10;

        /**
         * The maximum size of a list in bytes (50 MB)
         */
        public const int MAX_SIZE = 52428800;

        /**
         * The maximum number of rules kept of a list
         */
        public const int MAX_RULES = 1000000;

        /**
         * The concern of an inline rule that doesn't name one
         */
        public const IncidentType DEFAULT_RULE_CONCERN = IncidentType::ADVERTISING;

        /** @var SubscriptionDefinition[] */
        private array $subscriptions;
        private bool $complete = true;
        /** @var array<string, CustomRuleDefinition> */
        private array $rules;
        private bool $rulesComplete = true;
        private int $updateInterval;
        private bool $allowPrivate;

        /**
         * ListsConfiguration constructor.
         *
         * @param array $configuration The plugin's configuration values, `lists`, `rules`, `update_interval` and
         *                             `allow_private`
         */
        public function __construct(array $configuration)
        {
            $this->subscriptions = [];
            foreach(self::splitEntries($configuration['lists'] ?? [], '/\s*[,\r\n]+\s*/', 'lists', $this->complete) as $entry)
            {
                try
                {
                    $definition = SubscriptionDefinition::parse(is_int($entry) ? (string)$entry : $entry);
                    $this->subscriptions[$definition->getKey()] = $definition;
                }
                catch(ConfigurationException $e)
                {
                    $this->complete = false;
                    Logger::log()->warning(sprintf('Ignoring the entry %s of lists: %s', is_string($entry) ? '"' . $entry . '"' : json_encode($entry), $e->getMessage()));
                }
            }

            $this->subscriptions = array_values($this->subscriptions);

            // Rules contain commas (e.g., $third-party,domain=example.com), they're only separated by lines
            $this->rules = [];
            foreach(self::splitEntries($configuration['rules'] ?? [], '/\r\n|\r|\n/', 'rules', $this->rulesComplete) as $entry)
            {
                try
                {
                    $definition = is_string($entry) ? CustomRuleDefinition::parse($entry, self::DEFAULT_RULE_CONCERN) : throw new ConfigurationException('A rule must be a string');
                }
                catch(ConfigurationException $e)
                {
                    $this->rulesComplete = false;
                    Logger::log()->warning(sprintf('Ignoring the rule %s of rules: %s', is_string($entry) ? '"' . $entry . '"' : json_encode($entry), $e->getMessage()));
                    continue;
                }

                if($definition !== null)
                {
                    $this->rules[$definition->getKey()] ??= $definition;
                }
            }

            $this->updateInterval = max(self::MINIMUM_UPDATE_INTERVAL, ConfigurationValues::parseDuration($configuration['update_interval'] ?? null, 86400) ?? 86400);
            $this->allowPrivate = ConfigurationValues::parseBool($configuration['allow_private'] ?? null, false);
        }

        /**
         * Splits a configured list of entries, a string (e.g., from an environment variable) or an array
         *
         * @param mixed $value The configured value
         * @param string $separator The regular expression that separates the entries of a string
         * @param string $setting The name of the setting, for the log
         * @param bool $complete Set to false if the value isn't a string or an array
         * @return array The entries, without the empty ones
         */
        private static function splitEntries(mixed $value, string $separator, string $setting, bool &$complete): array
        {
            if(is_string($value))
            {
                $value = preg_split($separator, trim($value));
            }

            if(!is_array($value))
            {
                Logger::log()->warning(sprintf('%s must be a string or a list', $setting));
                $complete = false;
                return [];
            }

            return array_values(array_filter($value, fn($entry) => !is_string($entry) || trim($entry) !== ''));
        }

        /**
         * Returns the lists declared in `lists`
         *
         * @return SubscriptionDefinition[] The definitions
         */
        public function getSubscriptions(): array
        {
            return $this->subscriptions;
        }

        /**
         * Checks if every entry of `lists` is valid, subscriptions are only removed when it is
         *
         * @return bool True if every entry is valid
         */
        public function isComplete(): bool
        {
            return $this->complete;
        }

        /**
         * Returns the inline rules declared in `rules`
         *
         * @param bool $complete Set to false if a rule is invalid, the previous rules are then kept
         * @return array<string, CustomRuleDefinition> The definitions by key
         */
        public function getRules(bool &$complete=true): array
        {
            $complete = $this->rulesComplete;
            return $this->rules;
        }

        /**
         * Returns how often the lists are updated
         *
         * @return int The interval in seconds, at least one hour
         */
        public function getUpdateInterval(): int
        {
            return $this->updateInterval;
        }

        /**
         * Checks if lists may be downloaded from private, loopback or otherwise non-public addresses
         *
         * @return bool True if private addresses are allowed
         */
        public function isPrivateAllowed(): bool
        {
            return $this->allowPrivate;
        }
    }
