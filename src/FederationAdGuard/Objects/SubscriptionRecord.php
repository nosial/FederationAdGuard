<?php

    namespace FederationAdGuard\Objects;

    use DateTime;
    use FederationAdGuard\Classes\Configuration;
    use FederationAdGuard\Enums\ListSource;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Interfaces\StandardObjectInterface;

    class SubscriptionRecord implements StandardObjectInterface
    {
        private int $id;
        private ListSource $source;
        private ?int $filterListsId;
        private ?string $location;
        private string $name;
        private ?IncidentType $concern;
        private ?IncidentType $tagConcern;
        private bool $allowlist;
        private ?string $checksum;
        private array $validators;
        private ?int $lastChecked;

        /**
         * SubscriptionRecord constructor.
         *
         * @param array $data Associative array of subscription data, a row of adguard_subscriptions or a cached record.
         */
        public function __construct(array $data)
        {
            $this->id = (int)($data['id'] ?? 0);
            $this->source = $data['source'] instanceof ListSource ? $data['source'] : ListSource::from((string)$data['source']);
            $this->filterListsId = isset($data['filterlists_id']) && $data['filterlists_id'] !== '' ? (int)$data['filterlists_id'] : null;
            $this->location = isset($data['location']) && $data['location'] !== '' ? (string)$data['location'] : null;
            $this->name = (string)($data['name'] ?? '');
            $this->concern = self::parseConcern($data['concern'] ?? null);
            $this->tagConcern = self::parseConcern($data['tag_concern'] ?? null);
            $this->allowlist = (bool)($data['allowlist'] ?? false);
            $this->checksum = isset($data['checksum']) && $data['checksum'] !== '' ? (string)$data['checksum'] : null;
            $this->validators = self::parseJson($data['validators'] ?? null) ?? [];
            $this->lastChecked = self::parseTimestamp($data['last_checked'] ?? null);
        }

        /**
         * Returns the ID of the subscription
         *
         * @return int The ID
         */
        public function getId(): int
        {
            return $this->id;
        }

        /**
         * Returns where the rules of the list come from
         *
         * @return ListSource The source
         */
        public function getSource(): ListSource
        {
            return $this->source;
        }

        /**
         * Returns the ID of the list in the FilterLists directory
         *
         * @return int|null The ID, null if the subscription is not of the FilterLists directory
         */
        public function getFilterListsId(): ?int
        {
            return $this->filterListsId;
        }

        /**
         * Returns the URL or local path the list is read from
         *
         * @return string|null The location, null for a FilterLists or custom rules subscription
         */
        public function getLocation(): ?string
        {
            return $this->location;
        }

        /**
         * Returns the name of the list, the source of the detections its rules make
         *
         * @return string The name
         */
        public function getName(): string
        {
            return $this->name;
        }

        /**
         * Returns the concern configured for the list
         *
         * @return IncidentType|null The concern, null to derive it from the list's tags
         */
        public function getConcern(): ?IncidentType
        {
            return $this->concern;
        }

        /**
         * Returns the concern derived from the FilterLists tags of the list
         *
         * @return IncidentType|null The concern, null if the list has no tags
         */
        public function getTagConcern(): ?IncidentType
        {
            return $this->tagConcern;
        }

        /**
         * Returns the concern the rules of the list detect: the configured concern, otherwise the concern derived from
         * the list's tags, otherwise OTHER for directory lists and ADVERTISING for other sources
         *
         * @return IncidentType The concern
         */
        public function getEffectiveConcern(): IncidentType
        {
            return $this->concern ?? $this->tagConcern ?? ($this->source === ListSource::FILTERLISTS ? IncidentType::OTHER : IncidentType::ADVERTISING);
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
         * Checks if the list should be downloaded: a list that was never downloaded, or was last checked longer ago
         * than the update interval. Local files are read every time, the custom rules are never downloaded.
         *
         * @param int $now The current Unix timestamp
         * @return bool True if the list is due
         */
        public function isDue(int $now): bool
        {
            if($this->source === ListSource::CUSTOM)
            {
                return false;
            }

            return $this->source === ListSource::FILE || $this->lastChecked === null || $now - $this->lastChecked >= Configuration::getListsConfiguration()->getUpdateInterval();
        }

        /**
         * Returns the SHA-256 checksum of the list as it was last parsed
         *
         * @return string|null The checksum, null if the list was never parsed
         */
        public function getChecksum(): ?string
        {
            return $this->checksum;
        }

        /**
         * Returns the validators of each URL of the list, for conditional downloads
         *
         * @return array<string, array{etag?: string, last_modified?: string}> The validators by URL
         */
        public function getValidators(): array
        {
            return $this->validators;
        }

        /**
         * Returns the timestamp of when the list was last downloaded or found unchanged
         *
         * @return int|null The timestamp, null if the list was never downloaded
         */
        public function getLastChecked(): ?int
        {
            return $this->lastChecked;
        }

        /**
         * @inheritDoc
         */
        public function toArray(): array
        {
            return [
                'id' => $this->id,
                'source' => $this->source->value,
                'filterlists_id' => $this->filterListsId,
                'location' => $this->location,
                'name' => $this->name,
                'concern' => $this->concern?->value,
                'tag_concern' => $this->tagConcern?->value,
                'allowlist' => $this->allowlist,
                'checksum' => $this->checksum,
                'validators' => $this->validators,
                'last_checked' => $this->lastChecked,
            ];
        }

        /**
         * @inheritDoc
         */
        public function toStandardArray(): array
        {
            return $this->toArray();
        }

        /**
         * @inheritDoc
         */
        public static function fromArray(array $array): SubscriptionRecord
        {
            return new self($array);
        }

        /**
         * Parses a concern column, null if it's not set
         *
         * @param mixed $value The value
         * @return IncidentType|null The concern
         */
        private static function parseConcern(mixed $value): ?IncidentType
        {
            if($value instanceof IncidentType)
            {
                return $value;
            }

            return is_string($value) && $value !== '' ? IncidentType::tryFrom($value) : null;
        }

        /**
         * Parses a JSON column, arrays are kept as they are (e.g., a record that wasn't stored yet)
         *
         * @param mixed $value The value
         * @return array|null The decoded value, null if it's not set or not JSON
         */
        private static function parseJson(mixed $value): ?array
        {
            if(is_array($value))
            {
                return $value;
            }

            if(!is_string($value) || $value === '')
            {
                return null;
            }

            $decoded = json_decode($value, true);
            return is_array($decoded) ? $decoded : null;
        }

        /**
         * Parses a timestamp column, SQL datetime strings and numeric strings (from the cache) alike
         *
         * @param mixed $value The value
         * @return int|null The Unix timestamp, null if it's not set
         */
        private static function parseTimestamp(mixed $value): ?int
        {
            if($value === null || $value === '')
            {
                return null;
            }

            if($value instanceof DateTime)
            {
                return $value->getTimestamp();
            }

            if(is_int($value) || is_numeric($value))
            {
                return (int)$value;
            }

            $timestamp = strtotime((string)$value);
            return $timestamp === false ? null : $timestamp;
        }
    }
