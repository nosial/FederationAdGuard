<?php

    namespace FederationAdGuard\Objects;

    use FederationAdGuard\Enums\RegexSubject;
    use FederationAdGuard\Enums\RuleAction;
    use FederationAdGuard\Enums\RuleType;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Interfaces\SerializableInterface;

    class FilterRule implements SerializableInterface
    {
        /**
         * The maximum length of the original rule that is kept
         */
        public const int MAX_RULE_LENGTH = 1024;

        private ?int $id;
        private ?int $subscriptionId;
        private string $rule;
        private RuleAction $action;
        private RuleType $type;
        private ?string $host;
        private bool $subdomains;
        private ?string $token;
        private ?string $regex;
        private ?RegexSubject $regexSubject;
        private bool $partial;
        private bool $important;
        private bool $badfilter;
        /** @var string[]|null */
        private ?array $dnsTypes;
        /** @var string[]|null */
        private ?array $denyAllow;
        private string $fingerprint;
        private ?IncidentType $concern;

        /**
         * FilterRule constructor
         *
         * @param array $data The rule's data, the keys of toArray()
         */
        public function __construct(array $data)
        {
            $this->id = isset($data['id']) ? (int)$data['id'] : null;
            $this->subscriptionId = isset($data['subscription_id']) ? (int)$data['subscription_id'] : null;
            $this->rule = mb_strcut((string)($data['rule'] ?? ''), 0, self::MAX_RULE_LENGTH);
            $this->action = $data['action'] instanceof RuleAction ? $data['action'] : RuleAction::from((string)$data['action']);
            $this->type = $data['type'] instanceof RuleType ? $data['type'] : RuleType::from((string)$data['type']);
            $this->host = isset($data['host']) && $data['host'] !== '' ? (string)$data['host'] : null;
            $this->subdomains = (bool)($data['subdomains'] ?? false);
            $this->token = isset($data['token']) && $data['token'] !== '' ? (string)$data['token'] : null;
            $this->regex = isset($data['regex']) && $data['regex'] !== '' ? (string)$data['regex'] : null;

            $regexSubject = $data['regex_subject'] ?? null;
            $this->regexSubject = $regexSubject instanceof RegexSubject ? $regexSubject : (is_string($regexSubject) ? RegexSubject::tryFrom($regexSubject) : null);

            $this->partial = (bool)($data['partial'] ?? false);
            $this->important = (bool)($data['important'] ?? false);
            $this->badfilter = (bool)($data['badfilter'] ?? false);
            $this->dnsTypes = self::parseList($data['dns_types'] ?? null);
            $this->denyAllow = self::parseList($data['deny_allow'] ?? null);
            $this->fingerprint = (string)($data['fingerprint'] ?? sha1($this->rule));

            $concern = $data['concern'] ?? null;
            $this->concern = $concern instanceof IncidentType ? $concern : (is_string($concern) ? IncidentType::tryFrom($concern) : null);
        }

        /**
         * Returns the ID of the stored rule
         *
         * @return int|null The ID, null if the rule is not stored
         */
        public function getId(): ?int
        {
            return $this->id;
        }

        /**
         * Returns the ID of the subscription the rule belongs to
         *
         * @return int|null The subscription ID, null if the rule is not stored
         */
        public function getSubscriptionId(): ?int
        {
            return $this->subscriptionId;
        }

        /**
         * Returns the original rule, as written in the list (truncated to MAX_RULE_LENGTH bytes)
         *
         * @return string The original rule
         */
        public function getRule(): string
        {
            return $this->rule;
        }

        /**
         * Returns whether the rule blocks or unblocks what it matches
         *
         * @return RuleAction The action
         */
        public function getAction(): RuleAction
        {
            return $this->action;
        }

        /**
         * Returns how the rule matches
         *
         * @return RuleType The type
         */
        public function getType(): RuleType
        {
            return $this->type;
        }

        /**
         * Returns the DNS name of a HOST rule, the address of an IP rule, or the host a URL rule's pattern starts with
         *
         * @return string|null The host, null if the rule is not indexed by a host
         */
        public function getHost(): ?string
        {
            return $this->host;
        }

        /**
         * Returns True if a HOST rule also matches the subdomains of its host
         *
         * @return bool True if subdomains are matched
         */
        public function isSubdomains(): bool
        {
            return $this->subdomains;
        }

        /**
         * Returns the token a URL rule that doesn't start with a host is indexed by, a URL can only match the rule if
         * it contains the token
         *
         * @return string|null The token, null if the rule is not indexed by a token
         */
        public function getToken(): ?string
        {
            return $this->token;
        }

        /**
         * Returns the PCRE regular expression of a URL or REGEX rule, including its delimiters and flags
         *
         * @return string|null The regular expression, null for HOST and IP rules
         */
        public function getRegex(): ?string
        {
            return $this->regex;
        }

        /**
         * Returns what the regular expression of a REGEX rule is evaluated against
         *
         * @return RegexSubject|null The subject, null for other rules
         */
        public function getRegexSubject(): ?RegexSubject
        {
            return $this->regexSubject;
        }

        /**
         * Returns True if the rule only applies to some requests to what it matches, e.g., ||example.com^$third-party
         * or $script. A browser blocks such requests, but the host itself is not blocked entirely.
         *
         * @return bool True if the rule is partial
         */
        public function isPartial(): bool
        {
            return $this->partial;
        }

        /**
         * Returns True if the rule has the $important modifier: a blocking rule then wins over exceptions that are not
         * important themselves
         *
         * @return bool True if important
         */
        public function isImportant(): bool
        {
            return $this->important;
        }

        /**
         * Returns True if the rule has the $badfilter modifier: it disables the rule it's written as, in every list
         *
         * @return bool True if a badfilter rule
         */
        public function isBadfilter(): bool
        {
            return $this->badfilter;
        }

        /**
         * Returns the DNS record types the rule is restricted to ($dnstype), a type prefixed with "~" is excluded
         *
         * @return string[]|null The record types, null if the rule is not restricted
         */
        public function getDnsTypes(): ?array
        {
            return $this->dnsTypes;
        }

        /**
         * Returns the domains a rule doesn't apply to ($denyallow), including their subdomains
         *
         * @return string[]|null The domains, null if there are none
         */
        public function getDenyAllow(): ?array
        {
            return $this->denyAllow;
        }

        /**
         * Returns the fingerprint of the rule, the same for the rule and the $badfilter rule that disables it
         *
         * @return string The fingerprint (SHA-1, hex)
         */
        public function getFingerprint(): string
        {
            return $this->fingerprint;
        }

        /**
         * Returns the concern the rule detects, the concern of its subscription or of the custom rule
         *
         * @return IncidentType|null The concern, null if the rule is not stored
         */
        public function getConcern(): ?IncidentType
        {
            return $this->concern;
        }

        /**
         * Returns True if the rule blocks a host and every request to it: a HOST or IP rule that is not partial and not
         * restricted to some DNS record types or some subdomains. Only these rules create blacklist records.
         *
         * @return bool True if the rule blocks the host entirely
         */
        public function isHostBlock(): bool
        {
            return $this->action === RuleAction::BLOCK
                && in_array($this->type, [RuleType::HOST, RuleType::IP], true)
                && !$this->partial
                && !$this->badfilter
                && $this->dnsTypes === null
                && $this->denyAllow === null;
        }

        /**
         * Returns a copy of the rule that belongs to a subscription and detects a concern
         *
         * @param int|null $subscriptionId The subscription ID
         * @param IncidentType|null $concern The concern
         * @return FilterRule The copy
         */
        public function withSubscription(?int $subscriptionId, ?IncidentType $concern): FilterRule
        {
            return new FilterRule(array_merge($this->toArray(), ['subscription_id' => $subscriptionId, 'concern' => $concern]));
        }

        /**
         * @inheritDoc
         */
        public function toArray(): array
        {
            return [
                'id' => $this->id,
                'subscription_id' => $this->subscriptionId,
                'rule' => $this->rule,
                'action' => $this->action->value,
                'type' => $this->type->value,
                'host' => $this->host,
                'subdomains' => $this->subdomains,
                'token' => $this->token,
                'regex' => $this->regex,
                'regex_subject' => $this->regexSubject?->value,
                'partial' => $this->partial,
                'important' => $this->important,
                'badfilter' => $this->badfilter,
                'dns_types' => $this->dnsTypes !== null ? implode(',', $this->dnsTypes) : null,
                'deny_allow' => $this->denyAllow !== null ? implode(',', $this->denyAllow) : null,
                'fingerprint' => $this->fingerprint,
                'concern' => $this->concern?->value,
            ];
        }

        /**
         * @inheritDoc
         */
        public static function fromArray(array $array): FilterRule
        {
            return new self($array);
        }

        /**
         * Parses a list stored as an array or as a comma-separated string
         *
         * @param mixed $value The list
         * @return string[]|null The values, null if there are none
         */
        private static function parseList(mixed $value): ?array
        {
            if(is_string($value))
            {
                $value = explode(',', $value);
            }

            if(!is_array($value))
            {
                return null;
            }

            $value = array_values(array_filter(array_map(fn($item) => trim((string)$item), $value), fn(string $item) => $item !== ''));
            return count($value) > 0 ? $value : null;
        }
    }
