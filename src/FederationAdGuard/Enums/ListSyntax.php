<?php

    namespace FederationAdGuard\Enums;

    use FederationLib\Interfaces\CaseSensitiveInterface;

    enum ListSyntax : string implements CaseSensitiveInterface
    {
        /**
         * Every line is recognized on its own: Adblock Plus, uBlock Origin and AdGuard network rules, hosts file
         * entries, domains, dnsmasq, Unbound, RPZ and BIND entries, IP addresses and URLs. Suits nearly every list.
         */
        case AUTO = 'AUTO';

        /**
         * Every line that isn't a comment is a regular expression matched against DNS names, e.g., Pi-hole's regex lists
         * (including their ;querytype= option)
         */
        case REGEX = 'REGEX';

        /** Parser capabilities, matched against names returned by GET /syntaxes, never directory IDs. */
        private const array AUTO_SYNTAXES = [
            'hosts (localhost ipv4)', 'domains', 'adblock plus', 'ublock origin static', 'adguard',
            'urls', 'ips (ipv4)', 'non-localhost hosts (ipv4)', 'domains with wildcards',
            'dnsmasq domains list', 'unbound', 'response policy zones (rpz)', 'bind',
            'adblocker-syntax domains', 'hosts (localhost ipv6)', 'non-localhost hosts (ipv6)',
            'adblock plus advanced', 'ips (ipv6)', "''\$important''/''\$empty'' only",
            'adblocker-syntax domains w/o abp tag', 'domains with abp tag', 'domains for whitelisting', 'hosts (0)',
        ];

        private const array REGEX_SYNTAXES = ['pi-hole regex'];
        private const array ALLOWLIST_SYNTAXES = ['domains for whitelisting', 'personaldnsfilter whitelisting'];

        /**
         * @inheritDoc
         */
        public static function tryFromCaseInsensitive(string $value): ?ListSyntax
        {
            return self::tryFrom(strtoupper(trim($value)));
        }

        /**
         * Returns the syntax a list of the FilterLists directory is interpreted with
         *
         * @param int[] $syntaxIds The FilterLists syntax IDs of the list
         * @param array<int, array{name: string}> $syntaxes The API syntax metadata by ID
         * @return ListSyntax|null The syntax, null if none of the syntaxes of the list is supported
         */
        public static function fromFilterListsSyntaxes(array $syntaxIds, array $syntaxes): ?ListSyntax
        {
            if(array_any($syntaxIds, fn($id) => in_array(strtolower($syntaxes[$id]['name'] ?? ''), self::AUTO_SYNTAXES, true)))
            {
                return self::AUTO;
            }

            if(array_any($syntaxIds, fn($id) => in_array(strtolower($syntaxes[$id]['name'] ?? ''), self::REGEX_SYNTAXES, true)))
            {
                return self::REGEX;
            }

            return null;
        }

        /**
         * Returns True if a FilterLists syntax only contains exceptions
         *
         * @param int[] $syntaxIds The FilterLists syntax IDs of the list
         * @param array<int, array{name: string}> $syntaxes The API syntax metadata by ID
         * @return bool True if the list is an allowlist
         */
        public static function isAllowlistSyntax(array $syntaxIds, array $syntaxes): bool
        {
            return array_any($syntaxIds, fn($id) => in_array(strtolower($syntaxes[$id]['name'] ?? ''), self::ALLOWLIST_SYNTAXES, true));
        }
    }
