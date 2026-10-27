<?php

    namespace FederationAdGuard\Enums;

    enum MetadataKey : string
    {
        /**
         * The UUID of the dedicated FederationAdGuard operator
         */
        case OPERATOR_UUID = 'adguard_operator_uuid';

        /**
         * The UUID of the last host entity the maintenance checked, the next run continues after it
         */
        case ENTITY_CURSOR = 'adguard_entity_cursor';

        /**
         * The entity and concern of the last finding the maintenance checked, the next run continues after it
         */
        case FINDING_CURSOR = 'adguard_finding_cursor';
    }
