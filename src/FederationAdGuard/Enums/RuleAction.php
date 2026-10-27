<?php

    namespace FederationAdGuard\Enums;

    enum RuleAction : string
    {
        /**
         * Blocks what the rule matches, e.g., ||ads.example.com^
         */
        case BLOCK = 'BLOCK';

        /**
         * Unblocks what the rule matches (an exception), e.g., @@||ads.example.com^
         */
        case ALLOW = 'ALLOW';
    }
