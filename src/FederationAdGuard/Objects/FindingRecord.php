<?php

    namespace FederationAdGuard\Objects;

    use DateTime;
    use FederationAdGuard\Enums\FindingState;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Interfaces\StandardObjectInterface;

    class FindingRecord implements StandardObjectInterface
    {
        private string $entityUuid;
        private IncidentType $concern;
        private string $host;
        private string $rule;
        private ?int $subscriptionId;
        private ?string $evidenceUuid;
        private ?string $blacklistUuid;
        private FindingState $state;
        private int $updated;

        /**
         * FindingRecord constructor.
         *
         * @param array $data Associative array of finding data, a row of adguard_findings or a cached record.
         */
        public function __construct(array $data)
        {
            $this->entityUuid = (string)($data['entity'] ?? '');
            $this->concern = $data['concern'] instanceof IncidentType ? $data['concern'] : IncidentType::fromResponse((string)($data['concern'] ?? ''));
            $this->host = (string)($data['host'] ?? '');
            $this->rule = (string)($data['rule'] ?? '');
            $this->subscriptionId = isset($data['subscription']) && $data['subscription'] !== '' ? (int)$data['subscription'] : null;
            $this->evidenceUuid = isset($data['evidence']) && $data['evidence'] !== '' ? (string)$data['evidence'] : null;
            $this->blacklistUuid = isset($data['blacklist']) && $data['blacklist'] !== '' ? (string)$data['blacklist'] : null;
            $this->state = $data['state'] instanceof FindingState ? $data['state'] : (FindingState::tryFrom((string)($data['state'] ?? '')) ?? FindingState::PENDING);
            $this->updated = self::parseTimestamp($data['updated'] ?? null);
        }

        /**
         * Returns the UUID of the listed host entity
         *
         * @return string The entity UUID
         */
        public function getEntityUuid(): string
        {
            return $this->entityUuid;
        }

        /**
         * Returns the concern, the type of the blacklist record
         *
         * @return IncidentType The concern
         */
        public function getConcern(): IncidentType
        {
            return $this->concern;
        }

        /**
         * Returns the host of the entity
         *
         * @return string The host
         */
        public function getHost(): string
        {
            return $this->host;
        }

        /**
         * Returns the rule that blocks the host entirely, as it is written in the list
         *
         * @return string The rule
         */
        public function getRule(): string
        {
            return $this->rule;
        }

        /**
         * Returns the subscription of the rule
         *
         * @return int|null The subscription ID, null for the inline rules
         */
        public function getSubscriptionId(): ?int
        {
            return $this->subscriptionId;
        }

        /**
         * Returns the UUID of the evidence record created for the finding
         *
         * @return string|null The evidence UUID, null if none was created or it was deleted
         */
        public function getEvidenceUuid(): ?string
        {
            return $this->evidenceUuid;
        }

        /**
         * Returns the UUID of the blacklist record the plugin created
         *
         * @return string|null The blacklist UUID, null while it is being created or if none was
         */
        public function getBlacklistUuid(): ?string
        {
            return $this->blacklistUuid;
        }

        /**
         * Returns the state of the blacklist record
         *
         * @return FindingState The state
         */
        public function getState(): FindingState
        {
            return $this->state;
        }

        /**
         * Returns the timestamp of when the record last changed
         *
         * @return int The timestamp
         */
        public function getUpdated(): int
        {
            return $this->updated;
        }

        /**
         * @inheritDoc
         */
        public function toArray(): array
        {
            return [
                'entity' => $this->entityUuid,
                'concern' => $this->concern->value,
                'host' => $this->host,
                'rule' => $this->rule,
                'subscription' => $this->subscriptionId,
                'evidence' => $this->evidenceUuid,
                'blacklist' => $this->blacklistUuid,
                'state' => $this->state->value,
                'updated' => $this->updated,
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
        public static function fromArray(array $array): FindingRecord
        {
            return new self($array);
        }

        /**
         * Parses a timestamp column, SQL datetime strings and numeric strings (from the cache) alike
         *
         * @param mixed $value The value
         * @return int The Unix timestamp, the current time if it's not set
         */
        private static function parseTimestamp(mixed $value): int
        {
            if($value instanceof DateTime)
            {
                return $value->getTimestamp();
            }

            if(is_int($value) || is_numeric($value))
            {
                return (int)$value;
            }

            return is_string($value) && ($timestamp = strtotime($value)) !== false ? $timestamp : time();
        }
    }
