<?php

    namespace FederationAdGuard\Enums;

    enum RuleType : string
    {
        /**
         * Matches a DNS name, and its subdomains unless the rule is exact (e.g., ||ads.example.com^, a hosts file entry or
         * a line of a domain list). Indexed by the name.
         */
        case HOST = 'HOST';

        /**
         * Matches the full URL with an Adblock Plus pattern (e.g., ||example.com/ads/* or /banner/ad-), never a bare DNS
         * name. Indexed by the host of the pattern when it starts with one, otherwise by a token of the pattern.
         */
        case URL = 'URL';

        /**
         * Matches with a regular expression, either the URL (Adblock Plus /regex/ rules) or the DNS name (regex lists
         * such as Pi-hole's). Never indexed, every regular expression is evaluated.
         */
        case REGEX = 'REGEX';

        /**
         * Matches an IP address exactly, e.g., a line of an IP list. Compared with the address of an IP address literal
         * and with the addresses FederationLib resolved itself.
         */
        case IP = 'IP';
    }
