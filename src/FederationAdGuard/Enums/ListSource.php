<?php

    namespace FederationAdGuard\Enums;

    enum ListSource : string
    {
        /**
         * A list of the FilterLists directory (https://filterlists.com), its download URLs are retrieved from the
         * FilterLists API on every update
         */
        case FILTERLISTS = 'FILTERLISTS';

        /**
         * A list downloaded from a URL
         */
        case URL = 'URL';

        /**
         * A local filter list file
         */
        case FILE = 'FILE';

        /**
         * The inline rules declared in the configuration
         */
        case CUSTOM = 'CUSTOM';
    }
