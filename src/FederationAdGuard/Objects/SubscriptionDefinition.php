<?php

    namespace FederationAdGuard\Objects;

    use FederationAdGuard\Enums\ListSource;
    use FederationLib\Classes\Configuration\ConfigurationValues;
    use FederationLib\Enums\IncidentType;
    use InvalidArgumentException;

    /**
     * A list the configuration declares, listed in `lists` or discovered in the FilterLists directory. The provisioner
     * creates a subscription for it, or makes the existing subscription to the same list match it.
     */
    class SubscriptionDefinition
    {
        private const array OPTIONS = ['list', 'name', 'concern', 'allowlist'];

        private ListSource $source;
        private ?int $filterListsId;
        private ?string $location;
        private ?string $name;
        private ?IncidentType $concern;
        private bool $allowlist;

        /**
         * SubscriptionDefinition constructor.
         *
         * @param int|string $list The FilterLists ID of the list, the HTTP(S) URL it is downloaded from, or the
         *                         absolute path of a local file or directory
         * @param string|null $name Optional. The name of the list, its host or file name by default (FilterLists lists
         *                          are named after the directory)
         * @param IncidentType|null $concern Optional. The concern the rules detect, null to derive it from the list's
         *                                   FilterLists tags (ADVERTISING for other lists)
         * @param bool $allowlist Whether every rule of the list is an exception
         * @throws InvalidArgumentException If the list is neither a FilterLists ID, an HTTP(S) URL nor an absolute path
         */
        public function __construct(int|string $list, ?string $name=null, ?IncidentType $concern=null, bool $allowlist=false)
        {
            $list = is_string($list) ? trim($list) : $list;
            if(is_int($list) || preg_match('/^\d+$/', $list) === 1)
            {
                if((int)$list < 1)
                {
                    throw new InvalidArgumentException(sprintf('"%s" is not a FilterLists ID', $list));
                }

                $this->source = ListSource::FILTERLISTS;
                $this->filterListsId = (int)$list;
                $this->location = null;
            }
            elseif(preg_match('/^https?:\/\/\S+$/i', $list) === 1 && strlen($list) <= 2048)
            {
                $this->source = ListSource::URL;
                $this->filterListsId = null;
                $this->location = $list;
            }
            elseif(str_starts_with($list, DIRECTORY_SEPARATOR) && !str_contains($list, "\0"))
            {
                $this->source = ListSource::FILE;
                $this->filterListsId = null;
                $this->location = realpath($list) ?: $list;
            }
            else
            {
                throw new InvalidArgumentException(sprintf('"%s" is not a FilterLists ID, an HTTP(S) URL or an absolute path', $list));
            }

            $name = $name !== null ? trim($name) : null;
            $this->name = $name !== null && $name !== '' ? mb_substr($name, 0, 255) : null;
            $this->concern = $concern;
            $this->allowlist = $allowlist;
        }

        /**
         * Parses an entry of `lists`: a FilterLists ID, URL or absolute path followed by its options, separated by
         * semicolons (e.g., "https://example.com/list.txt;name=Example;concern=TRACKING"), or a map of the same keys
         * with the list as "list"
         *
         * @param string|array $definition The definition
         * @return SubscriptionDefinition The definition
         * @throws InvalidArgumentException If the definition or one of its options is invalid
         */
        public static function parse(string|array $definition): SubscriptionDefinition
        {
            if(is_string($definition))
            {
                $parts = array_map('trim', explode(';', $definition));
                $options = ['list' => array_shift($parts)];
                foreach($parts as $part)
                {
                    if($part === '')
                    {
                        continue;
                    }

                    if(!str_contains($part, '='))
                    {
                        throw new InvalidArgumentException(sprintf('The option "%s" is not a key=value pair', $part));
                    }

                    [$key, $value] = array_map('trim', explode('=', $part, 2));
                    $options[strtolower($key)] = $value;
                }
            }
            else
            {
                $options = array_change_key_case($definition);
            }

            $list = $options['list'] ?? null;
            if(!is_int($list) && !is_string($list))
            {
                throw new InvalidArgumentException('The entry names no list, a FilterLists ID, URL or path is required');
            }

            foreach(array_keys($options) as $key)
            {
                if(!in_array($key, self::OPTIONS, true))
                {
                    throw new InvalidArgumentException(sprintf('The option "%s" is not supported, only name, concern and allowlist are', $key));
                }
            }

            $concern = null;
            if(isset($options['concern']) && trim((string)$options['concern']) !== '')
            {
                $concern = IncidentType::tryFromCaseInsensitive(trim((string)$options['concern']))
                    ?? throw new InvalidArgumentException(sprintf('The concern "%s" is not an incident type', $options['concern']));
            }

            return new self(
                $list,
                isset($options['name']) ? (string)$options['name'] : null,
                $concern,
                ConfigurationValues::parseBool($options['allowlist'] ?? null, false),
            );
        }

        /**
         * Creates a definition for a file in a configured directory, preserving the directory's settings.
         *
         * @param string $path The file path
         * @return SubscriptionDefinition The file's definition
         */
        public function withFile(string $path): SubscriptionDefinition
        {
            return new self($path, $this->name !== null ? $this->name . ': ' . basename($path) : null, $this->concern, $this->allowlist);
        }

        /**
         * Returns where the rules of the list come from, FILTERLISTS, URL or FILE
         *
         * @return ListSource The source
         */
        public function getSource(): ListSource
        {
            return $this->source;
        }

        /**
         * Returns the FilterLists ID of the list
         *
         * @return int|null The ID, null if the list isn't a FilterLists list
         */
        public function getFilterListsId(): ?int
        {
            return $this->filterListsId;
        }

        /**
         * Returns the URL or local path of the list
         *
         * @return string|null The location, null for a FilterLists list
         */
        public function getLocation(): ?string
        {
            return $this->location;
        }

        /**
         * Returns the name of the list, the configured name or its host or file name
         *
         * @return string The name
         */
        public function getName(): string
        {
            if($this->name !== null)
            {
                return $this->name;
            }

            return $this->source === ListSource::FILTERLISTS
                ? sprintf('FilterLists list %d', $this->filterListsId)
                : ($this->source === ListSource::FILE ? basename($this->location) : (parse_url($this->location, PHP_URL_HOST) ?: $this->location));
        }

        /**
         * Returns the configured concern of the list
         *
         * @return IncidentType|null The concern, null to derive it from the list's tags
         */
        public function getConcern(): ?IncidentType
        {
            return $this->concern;
        }

        /**
         * Checks if every rule of the list is an exception
         *
         * @return bool True if the list is an allowlist
         */
        public function isAllowlist(): bool
        {
            return $this->allowlist;
        }

        /**
         * Returns the key that identifies the list, a subscription and a definition with the same key are the same list
         *
         * @return string The key
         */
        public function getKey(): string
        {
            return self::getRecordKey($this->source, $this->filterListsId, $this->location);
        }

        /**
         * Returns the key that identifies the list of a subscription
         *
         * @param ListSource $source The source of the list
         * @param int|null $filterListsId The FilterLists ID of the list
         * @param string|null $location The URL or path of the list
         * @return string The key
         */
        public static function getRecordKey(ListSource $source, ?int $filterListsId, ?string $location): string
        {
            return $source === ListSource::FILTERLISTS ? 'filterlists:' . $filterListsId : strtolower($source->value) . ':' . $location;
        }

        /**
         * Returns the settings of a subscription that differ from the definition
         *
         * @param SubscriptionRecord $subscription The subscription to the same list
         * @return array{name?: string, concern?: IncidentType|null, allowlist?: bool} The settings to change
         */
        public function getChangedSettings(SubscriptionRecord $subscription): array
        {
            $settings = [];
            if($this->concern !== $subscription->getConcern())
            {
                $settings['concern'] = $this->concern;
            }

            if($this->allowlist !== $subscription->isAllowlist())
            {
                $settings['allowlist'] = $this->allowlist;
            }

            // FilterLists lists are named after the directory by every update
            if($this->source !== ListSource::FILTERLISTS && $this->getName() !== $subscription->getName())
            {
                $settings['name'] = $this->getName();
            }

            return $settings;
        }
    }
