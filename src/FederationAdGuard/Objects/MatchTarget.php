<?php

    namespace FederationAdGuard\Objects;

    use FederationAdGuard\Classes\FilterParser;
    use FederationAdGuard\Enums\TargetRole;

    class MatchTarget
    {
        private ?string $host;
        private ?string $url;
        private ?string $queryType;
        /** @var string[] */
        private array $addresses;
        private TargetRole $role;
        private bool $verified;
        private ?int $evidenceIndex;

        /**
         * MatchTarget constructor
         *
         * @param string|null $host The DNS name or IP address, normalized
         * @param string|null $url The absolute URL, null if only a host is matched
         * @param string|null $queryType The DNS record type of a lookup as the client asserted it, e.g., AAAA
         * @param string[] $addresses The addresses FederationLib resolved itself for the host
         * @param TargetRole $role How the target relates to the content it was found in
         * @param bool $verified False if the target is only known from an assertion of the client (the context)
         * @param int|null $evidenceIndex The index of the evidence item the target was found in
         */
        public function __construct(?string $host, ?string $url=null, ?string $queryType=null, array $addresses=[], TargetRole $role=TargetRole::SUBJECT, bool $verified=true, ?int $evidenceIndex=null)
        {
            $this->host = $host;
            $this->url = $url;
            $this->queryType = $queryType !== null && $queryType !== '' ? strtoupper($queryType) : null;
            $this->addresses = array_values(array_unique(array_filter(array_map(fn(string $address) => FilterParser::normalizeAddress($address), $addresses))));
            $this->role = $role;
            $this->verified = $verified;
            $this->evidenceIndex = $evidenceIndex;
        }

        /**
         * Creates a target from a DNS name or IP address
         *
         * @param string $host The DNS name or IP address
         * @param string|null $queryType The DNS record type of a lookup, e.g., AAAA
         * @param string[] $addresses The addresses FederationLib resolved itself
         * @param TargetRole $role How the target relates to the content it was found in
         * @param bool $verified False if the target is only known from an assertion of the client
         * @param int|null $evidenceIndex The index of the evidence item
         * @return MatchTarget|null The target, null if the value is neither a DNS name nor an IP address
         */
        public static function fromHost(string $host, ?string $queryType=null, array $addresses=[], TargetRole $role=TargetRole::SUBJECT, bool $verified=true, ?int $evidenceIndex=null): ?MatchTarget
        {
            $normalized = self::normalizeHost($host);
            if($normalized === null)
            {
                return null;
            }

            return new MatchTarget($normalized, null, $queryType, $addresses, $role, $verified, $evidenceIndex);
        }

        /**
         * Creates a target from an absolute HTTP or HTTPS URL (a URL without a scheme is taken as HTTP)
         *
         * @param string $url The URL
         * @param string[] $addresses The addresses FederationLib resolved itself for its host
         * @param TargetRole $role How the target relates to the content it was found in
         * @param bool $verified False if the target is only known from an assertion of the client
         * @param int|null $evidenceIndex The index of the evidence item
         * @return MatchTarget|null The target, null if the value is not a URL with a host
         */
        public static function fromUrl(string $url, array $addresses=[], TargetRole $role=TargetRole::SUBJECT, bool $verified=true, ?int $evidenceIndex=null): ?MatchTarget
        {
            $url = trim($url);
            if(preg_match('#^[a-z][a-z0-9+.-]*://#i', $url) !== 1)
            {
                $url = 'http://' . $url;
            }

            $host = parse_url($url, PHP_URL_HOST);
            if(!is_string($host) || $host === '')
            {
                return null;
            }

            $normalized = self::normalizeHost($host);
            if($normalized === null)
            {
                return null;
            }

            return new MatchTarget($normalized, $url, null, $addresses, $role, $verified, $evidenceIndex);
        }

        /**
         * Normalizes a DNS name or IP address
         *
         * @param string $host The DNS name or IP address
         * @return string|null The normalized value, null if it's neither
         */
        public static function normalizeHost(string $host): ?string
        {
            $host = trim($host, " \t[]");
            return FilterParser::normalizeAddress($host) ?? FilterParser::normalizeHost($host);
        }

        /**
         * @return string|null The DNS name or IP address
         */
        public function getHost(): ?string
        {
            return $this->host;
        }

        /**
         * @return bool True if the host is an IP address
         */
        public function isAddress(): bool
        {
            return $this->host !== null && filter_var($this->host, FILTER_VALIDATE_IP) !== false;
        }

        /**
         * @return string|null The URL, null if only a host is matched
         */
        public function getUrl(): ?string
        {
            return $this->url;
        }

        /**
         * @return string|null The DNS record type of the lookup as the client asserted it
         */
        public function getQueryType(): ?string
        {
            return $this->queryType;
        }

        /**
         * @return string[] The addresses FederationLib resolved itself for the host
         */
        public function getAddresses(): array
        {
            return $this->addresses;
        }

        /**
         * @return TargetRole How the target relates to the content it was found in
         */
        public function getRole(): TargetRole
        {
            return $this->role;
        }

        /**
         * @return bool False if the target is only known from an assertion of the client
         */
        public function isVerified(): bool
        {
            return $this->verified;
        }

        /**
         * @return int|null The index of the evidence item the target was found in
         */
        public function getEvidenceIndex(): ?int
        {
            return $this->evidenceIndex;
        }
    }
