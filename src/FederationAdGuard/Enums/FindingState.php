<?php

    namespace FederationAdGuard\Enums;

    use FederationLib\Interfaces\CaseSensitiveInterface;

    enum FindingState : string implements CaseSensitiveInterface
    {
        /**
         * The blacklist record is being created
         */
        case PENDING = 'PENDING';

        /**
         * The blacklist record is active
         */
        case ACTIVE = 'ACTIVE';

        /**
         * The plugin doesn't blacklist the host (anymore), e.g., the host is no longer listed, the entity was
         * whitelisted or another blacklist record of the concern already applies. The host is blacklisted again when
         * it's found again.
         */
        case LIFTED = 'LIFTED';

        /**
         * An operator lifted or deleted the blacklist record, the plugin never blacklists the entity for this concern
         * again (an operator's decision wins over a filter list)
         */
        case SUPPRESSED = 'SUPPRESSED';

        /**
         * @inheritDoc
         */
        public static function tryFromCaseInsensitive(string $value): ?FindingState
        {
            return self::tryFrom(strtoupper($value));
        }
    }
