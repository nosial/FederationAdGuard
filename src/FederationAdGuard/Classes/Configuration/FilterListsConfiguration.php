<?php

    namespace FederationAdGuard\Classes\Configuration;

    use FederationAdGuard\Classes\Logger;
    use FederationLib\Classes\Configuration\ConfigurationValues;
    use FederationLib\Enums\IncidentType;

    class FilterListsConfiguration
    {
        public const string DEFAULT_ENDPOINT = 'https://api.filterlists.com';

        /**
         * The concerns lists are discovered for by default
         */
        public const array DEFAULT_CONCERNS = ['ADVERTISING', 'TRACKING'];

        /**
         * The concern of a list by its directory tags, the first tag of a list found here decides. Tag names are
         * policy, their IDs and which lists have them are always read from the API.
         */
        public const array TAG_CONCERNS = [
            'malware' => IncidentType::MALWARE, 'crypto' => IncidentType::MALWARE, 'phishing' => IncidentType::PHISHING,
            'ads' => IncidentType::ADVERTISING, 'privacy' => IncidentType::TRACKING,
        ];

        /**
         * Lists with one of these tags are never discovered
         */
        public const array EXCLUDED_TAGS = ['allowlist', 'site-specific', 'beta', 'nsfw', 'research'];

        /**
         * The syntaxes discovered lists are preferred in, the parser handles these best
         */
        public const array SYNTAX_PREFERENCE = ['adblock plus', 'ublock origin static', 'adguard', 'adblocker-syntax domains', 'domains'];

        /**
         * The well-known lists that are discovered first when they are eligible
         */
        public const array PREFERRED_LISTS = ['easylist', 'easyprivacy', 'adguard base filter', 'adguard tracking protection filter'];

        /**
         * How long the directory's responses are cached on disk, in seconds
         */
        public const int CACHE_TTL = 86400;

        /**
         * How long to wait before contacting the directory again after it failed, in seconds
         */
        public const int RETRY_INTERVAL = 300;

        private bool $enabled;
        /** @var IncidentType[] */
        private array $concerns;
        /** @var string[] */
        private array $languages;
        private int $max;
        /** @var int[] */
        private array $exclude;
        private string $endpoint;

        /**
         * FilterListsConfiguration constructor.
         *
         * @param array $configuration The values of the `filterlists` section
         */
        public function __construct(array $configuration)
        {
            $this->enabled = ConfigurationValues::parseBool($configuration['enabled'] ?? null, true);
            $this->concerns = array_map(fn(string $concern) => IncidentType::from($concern), self::parseValidated('filterlists.concerns',
                $configuration['concerns'] ?? self::DEFAULT_CONCERNS, self::DEFAULT_CONCERNS,
                fn(string $value) => IncidentType::tryFromCaseInsensitive($value)?->value
            ));
            $this->languages = self::parseValidated('filterlists.languages', $configuration['languages'] ?? ['en'], ['en'],
                fn(string $value) => preg_match('/^[a-z]{2}$/i', $value) === 1 ? strtolower($value) : null
            );
            $this->max = max(0, min(500, (int)($configuration['max'] ?? 4)));
            $this->exclude = array_map('intval', self::parseValidated('filterlists.exclude', $configuration['exclude'] ?? [], [],
                fn(string $value) => filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) !== false ? $value : null
            ));

            $endpoint = is_string($configuration['endpoint'] ?? self::DEFAULT_ENDPOINT) ? trim($configuration['endpoint'] ?? self::DEFAULT_ENDPOINT) : '';
            if(filter_var($endpoint, FILTER_VALIDATE_URL) !== false && preg_match('/^https?:\/\//i', $endpoint) === 1)
            {
                $this->endpoint = rtrim($endpoint, '/');
            }
            else
            {
                Logger::log()->warning(sprintf('filterlists.endpoint "%s" is not an HTTP or HTTPS URL, using %s', $endpoint, self::DEFAULT_ENDPOINT));
                $this->endpoint = self::DEFAULT_ENDPOINT;
            }
        }

        /**
         * Checks if the FilterLists directory is used: lists are discovered in it and FilterLists IDs in `lists` are
         * subscribed to. While disabled the directory is never contacted.
         *
         * @return bool True if enabled
         */
        public function isEnabled(): bool
        {
            return $this->enabled;
        }

        /**
         * Returns the concerns lists are discovered for
         *
         * @return IncidentType[] The concerns
         */
        public function getConcerns(): array
        {
            return $this->concerns;
        }

        /**
         * Returns the preferred languages of discovered lists, lists without a language are always eligible
         *
         * @return string[] The ISO 639-1 codes, empty for every language
         */
        public function getLanguages(): array
        {
            return $this->languages;
        }

        /**
         * Returns the maximum number of discovered lists
         *
         * @return int The number of lists, 0 to only subscribe to the FilterLists IDs in `lists`
         */
        public function getMax(): int
        {
            return $this->max;
        }

        /**
         * Returns the FilterLists IDs that are never discovered
         *
         * @return int[] The IDs
         */
        public function getExclude(): array
        {
            return $this->exclude;
        }

        /**
         * Returns the FilterLists API endpoint
         *
         * @return string The endpoint, without a trailing slash
         */
        public function getEndpoint(): string
        {
            return $this->endpoint;
        }

        /**
         * Returns the directory the directory's responses are cached in
         *
         * @return string The path
         */
        public static function getCachePath(): string
        {
            return sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'federation-adguard' . DIRECTORY_SEPARATOR . 'filterlists';
        }

        /**
         * Parses a list of values, a string of comma-separated values or an array, validating each value
         *
         * @param string $setting The name of the setting, for the log
         * @param mixed $value The configured value
         * @param array $default The values when nothing is configured
         * @param callable $validate Returns the normalized value, or null if it's invalid
         * @return array The normalized values, without duplicates
         */
        private static function parseValidated(string $setting, mixed $value, array $default, callable $validate): array
        {
            if($value === null)
            {
                return $default;
            }

            $values = is_string($value) ? explode(',', $value) : (is_array($value) ? $value : [$value]);
            $result = [];
            foreach($values as $item)
            {
                if(!is_string($item) && !is_int($item))
                {
                    Logger::log()->warning(sprintf('Ignoring a non-scalar value of %s', $setting));
                    continue;
                }

                $item = trim((string)$item);
                if($item === '')
                {
                    continue;
                }

                $normalized = $validate($item);
                if($normalized === null)
                {
                    Logger::log()->warning(sprintf('Ignoring "%s" of %s, it is not a valid value', $item, $setting));
                    continue;
                }

                $result[$normalized] = $normalized;
            }

            return array_values($result);
        }
    }
