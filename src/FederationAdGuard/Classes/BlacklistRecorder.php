<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Classes\Configuration\DatabaseConfiguration;
    use FederationAdGuard\Classes\Managers\FindingManager;
    use FederationAdGuard\Classes\Managers\SubscriptionManager;
    use FederationAdGuard\Enums\FindingState;
    use FederationAdGuard\Exceptions\RecordingException;
    use FederationAdGuard\Objects\RuleMatch;
    use FederationLib\Classes\Managers\AuditLogManager;
    use FederationLib\Classes\Managers\BlacklistManager;
    use FederationLib\Classes\Utilities;
    use FederationLib\Classes\Validate;
    use FederationLib\Enums\AuditLogType;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use FederationLib\Objects\BlacklistRecord;
    use FederationLib\Objects\EntityRecord;
    use InvalidArgumentException;

    class BlacklistRecorder
    {
        /**
         * Checks if a host can be recorded: a public IP address, or a canonical DNS name with a registrable domain
         *
         * @param string $host The host
         * @return bool True if the host can be recorded
         */
        public static function isRecordable(string $host): bool
        {
            if(filter_var($host, FILTER_VALIDATE_IP) !== false)
            {
                return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) !== false;
            }

            return Validate::host($host)
                && !Utilities::isTelephoneHost($host)
                && Utilities::getRegistrableDomain($host) !== null
                && Utilities::canonicalizeHost($host) === $host;
        }

        /**
         * Blacklists the entity of a finding for its concern, unless an operator decided otherwise or a blacklist
         * record of the concern already applies. Permanent, the plugin lifts it when the host is no longer listed.
         *
         * @param EntityRecord $entity The listed host entity, its finding was saved
         * @param RuleMatch $match The rule that blocks the host entirely
         * @return string|null The UUID of the blacklist record that applies, null if none does
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         * @throws InvalidArgumentException If the blacklist record or the finding is invalid.
         * @throws RecordingException If the plugin operator is unavailable.
         */
        public static function blacklist(EntityRecord $entity, RuleMatch $match): ?string
        {
            $rule = $match->getRule();
            $concern = $rule->getConcern();
            if($concern === null || !$rule->isHostBlock() || $match->isAssertion() || $entity->isWhitelisted() || $entity->getId() !== null)
            {
                return null;
            }

            $finding = FindingManager::getFinding($entity->getUuid(), $concern);
            if($finding === null || $finding->getState() === FindingState::SUPPRESSED)
            {
                return null;
            }

            if($finding->getState() !== FindingState::LIFTED)
            {
                return $finding->getBlacklistUuid();
            }

            // A blacklist record of the concern created by anyone already says what the list says, it isn't the
            // plugin's to lift
            foreach(BlacklistManager::getActiveEntriesByEntities([$entity->getUuid()]) as $blacklistRecord)
            {
                if($blacklistRecord->getEntityUuid() === $entity->getUuid() && $blacklistRecord->getType() === $concern)
                {
                    return $blacklistRecord->getUuid();
                }
            }

            if(!FindingManager::claimFinding($entity->getUuid(), $concern))
            {
                return FindingManager::getFinding($entity->getUuid(), $concern)?->getBlacklistUuid();
            }

            $activated = false;
            try
            {
                $operatorUuid = PluginOperator::get()->getUuid();
                $blacklistUuid = BlacklistManager::blacklistEntity($entity->getUuid(), $operatorUuid, $concern);
                FindingManager::activateFinding($entity->getUuid(), $concern, $blacklistUuid);
                $activated = true;

                AuditLogManager::createEntry(AuditLogType::ENTITY_BLACKLISTED, sprintf(
                    'Entity %s blacklisted by FederationAdGuard with type %s, it is listed by %s (%s)',
                    $entity->getLoggableAddress(), $concern->name, self::getListName($rule->getSubscriptionId()), mb_strcut($rule->getRule(), 0, 256)
                ), $operatorUuid, $entity->getUuid(), $blacklistUuid);
            }
            finally
            {
                if(!$activated)
                {
                    FindingManager::updateState($entity->getUuid(), $concern, FindingState::LIFTED, [FindingState::PENDING]);
                }
            }

            return $blacklistUuid;
        }

        /**
         * Lifts the blacklist record the plugin created for an entity and concern
         *
         * @param string $entityUuid The UUID of the entity
         * @param IncidentType $concern The concern
         * @param string $reason Why it's lifted, for the audit log
         * @return bool True if the plugin's blacklist record was lifted
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         * @throws InvalidArgumentException If FederationLib rejects the UUID of the blacklist record.
         * @throws RecordingException If the plugin operator is unavailable.
         */
        public static function lift(string $entityUuid, IncidentType $concern, string $reason): bool
        {
            $finding = FindingManager::getFinding($entityUuid, $concern);
            if($finding === null || $finding->getState() !== FindingState::ACTIVE)
            {
                return false;
            }

            // RecordChangeHandler recognizes lifts by the FederationAdGuard operator. Keep the finding ACTIVE until the
            // blacklist update succeeds, so maintenance can retry a failed lift.
            $blacklistRecord = $finding->getBlacklistUuid() !== null ? BlacklistManager::getBlacklistEntry($finding->getBlacklistUuid()) : null;
            if($blacklistRecord === null || $blacklistRecord->isLifted())
            {
                return FindingManager::updateState($entityUuid, $concern, FindingState::LIFTED, [FindingState::ACTIVE]);
            }

            $operatorUuid = PluginOperator::get()->getUuid();
            BlacklistManager::liftBlacklistRecord($finding->getBlacklistUuid(), $operatorUuid);
            FindingManager::updateState($entityUuid, $concern, FindingState::LIFTED, [FindingState::ACTIVE]);
            AuditLogManager::createEntry(AuditLogType::BLACKLIST_LIFTED, sprintf('Blacklist record lifted by FederationAdGuard: %s', $reason), $operatorUuid, $entityUuid, $finding->getBlacklistUuid());

            return true;
        }

        /**
         * Lifts every blacklist record the plugin created for an entity, e.g., after it was whitelisted
         *
         * @param string $entityUuid The UUID of the entity
         * @param string $reason Why they're lifted, for the audit log
         * @return int The number of lifted blacklist records
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         * @throws InvalidArgumentException If FederationLib rejects the UUID of a blacklist record.
         * @throws RecordingException If the plugin operator is unavailable.
         */
        public static function liftEntity(string $entityUuid, string $reason): int
        {
            $lifted = 0;
            foreach(FindingManager::getFindingsByEntity($entityUuid) as $finding)
            {
                if(self::lift($entityUuid, $finding->getConcern(), $reason))
                {
                    $lifted++;
                }
            }

            return $lifted;
        }

        /**
         * Records that an operator lifted or deleted one of the plugin's blacklist records, the plugin never blacklists
         * the entity for that concern again
         *
         * @param BlacklistRecord|string $blacklist The lifted blacklist record, or the UUID of the deleted one
         * @return bool True if the blacklist record was the plugin's
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         */
        public static function suppress(BlacklistRecord|string $blacklist): bool
        {
            $blacklistUuid = $blacklist instanceof BlacklistRecord ? $blacklist->getUuid() : $blacklist;
            $finding = FindingManager::getFindingsByBlacklists([$blacklistUuid])[$blacklistUuid] ?? null;
            if($finding === null)
            {
                return false;
            }

            $suppressed = FindingManager::updateState($finding->getEntityUuid(), $finding->getConcern(), FindingState::SUPPRESSED,
                [FindingState::ACTIVE, FindingState::PENDING]
            );

            if($suppressed)
            {
                Logger::log()->info(sprintf('An operator %s the blacklist record %s of %s (%s), FederationAdGuard never blacklists it for this concern again',
                    $blacklist instanceof BlacklistRecord ? 'lifted' : 'deleted', $blacklistUuid, $finding->getHost(), $finding->getConcern()->value));
            }

            return $suppressed;
        }

        /**
         * Repairs the findings left pending by a process that stopped while it blacklisted them
         *
         * @return int The number of repaired findings
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement.
         * @throws CacheOperationException If there is an error during a cache operation.
         * @throws InvalidArgumentException If FederationLib rejects the UUID of a blacklist record.
         */
        public static function repairAbandoned(): int
        {
            $repaired = 0;
            foreach(FindingManager::getAbandonedFindings(time() - DatabaseConfiguration::PENDING_TIMEOUT) as $finding)
            {
                $active = false;
                if($finding->getBlacklistUuid() !== null)
                {
                    $blacklistRecord = BlacklistManager::getBlacklistEntry($finding->getBlacklistUuid());
                    $active = $blacklistRecord !== null && !$blacklistRecord->isLifted();
                }

                if(FindingManager::updateState($finding->getEntityUuid(), $finding->getConcern(), $active ? FindingState::ACTIVE : FindingState::LIFTED, [FindingState::PENDING]))
                {
                    $repaired++;
                }
            }

            if($repaired > 0)
            {
                Logger::log()->info(sprintf('Repaired %d finding(s) left pending by a process that stopped while blacklisting them', $repaired));
            }

            return $repaired;
        }

        /**
         * Returns the name of the list of a rule
         *
         * @param int|null $subscriptionId The subscription of the rule, null for the inline rules
         * @return string The name of the list
         */
        public static function getListName(?int $subscriptionId): string
        {
            if($subscriptionId === null)
            {
                return 'inline filter rules';
            }

            try
            {
                return SubscriptionManager::getNames()[$subscriptionId] ?? sprintf('subscription %d', $subscriptionId);
            }
            catch(DatabaseOperationException|CacheOperationException)
            {
                return sprintf('subscription %d', $subscriptionId);
            }
        }
    }
