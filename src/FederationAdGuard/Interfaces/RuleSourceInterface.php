<?php

    namespace FederationAdGuard\Interfaces;

    use FederationLib\Enums\IncidentType;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use FederationAdGuard\Objects\FilterRule;

    interface RuleSourceInterface
    {
        /**
         * Returns the HOST, IP, and URL rules indexed by one of the given hosts
         *
         * @param string[] $hosts The DNS names (the name and its parent domains) and IP addresses
         * @return FilterRule[] The rules
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         */
        public function getRulesByHosts(array $hosts): array;

        /**
         * Returns the URL rules indexed by one of the given tokens
         *
         * @param string[] $tokens The tokens of a URL
         * @return FilterRule[] The rules
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         */
        public function getRulesByTokens(array $tokens): array;

        /**
         * Returns the rules that are not indexed: REGEX rules and URL rules without a host or token
         *
         * @return FilterRule[] The rules
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         */
        public function getUnindexedRules(): array;

        /**
         * Returns the names of the lists the rules belong to, by subscription ID, the sources of the detections
         * their rules make
         *
         * @return array<int, string> The names
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         */
        public function getListNames(): array;

        /**
         * Returns the concerns there are blocking rules for, nothing can be said about any other concern
         *
         * @return IncidentType[] The concerns
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         */
        public function getConcerns(): array;
    }
