<?php

    namespace FederationAdGuard\Handlers;

    use FederationAdGuard\Classes\Configuration;
    use FederationAdGuard\Classes\Logger;
    use FederationAdGuard\Classes\EntityVerifier;
    use FederationAdGuard\Classes\BlacklistRecorder;
    use FederationAdGuard\Classes\Managers\FindingManager;
    use FederationAdGuard\Classes\PluginOperator;
    use FederationAdGuard\Exceptions\RecordingException;
    use FederationAdGuard\Exceptions\RuleException;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use FederationLib\Enums\RecordChangeType;
    use FederationLib\Interfaces\RecordChangeEventHandlerInterface;
    use FederationLib\Objects\BlacklistRecord;
    use FederationLib\Objects\EntityRecord;
    use FederationLib\Objects\Plugin\RecordChange;
    use InvalidArgumentException;

    class RecordChangeHandler implements RecordChangeEventHandlerInterface
    {
        /**
         * @inheritDoc
         */
        public static function handleRecordChange(RecordChange $change): void
        {
            if(!Configuration::isEnabled() || !Configuration::getDatabaseConfiguration()->isEnabled() || !PluginOperator::isActive())
            {
                return;
            }

            try
            {
                self::handle($change);
            }
            catch(RuleException|RecordingException|DatabaseOperationException|CacheOperationException|InvalidArgumentException $e)
            {
                Logger::log()->warning(sprintf('Unable to handle the %s change of %s: %s', $change->getType()->value, $change->getUuid(), $e->getMessage()), $e);
            }
        }

        /**
         * Handles a record change
         *
         * @param RecordChange $change The change
         * @return void
         * @throws DatabaseOperationException If there is an error with the database
         * @throws CacheOperationException If there is an error during a cache operation
         * @throws InvalidArgumentException If a record is invalid
         * @throws RecordingException If the plugin operator is unavailable
         * @throws RuleException If a host matches too many rules to decide
         */
        private static function handle(RecordChange $change): void
        {
            Logger::log()->debug(sprintf('Handling the %s change of %s', $change->getType()->value, $change->getUuid()));
            switch($change->getType())
            {
                case RecordChangeType::ENTITY_CREATED:
                    $entity = $change->getRecord();
                    if($entity instanceof EntityRecord)
                    {
                        EntityVerifier::verifyEntity($entity);
                    }
                    break;

                case RecordChangeType::ENTITY_UPDATED:
                    $entity = $change->getRecord();
                    if(!$entity instanceof EntityRecord)
                    {
                        break;
                    }

                    if($entity->isWhitelisted())
                    {
                        $lifted = BlacklistRecorder::liftEntity($entity->getUuid(), 'the entity is whitelisted');
                        if($lifted > 0)
                        {
                            Logger::log()->info(sprintf('Lifted %d blacklist record(s) of %s, the entity was whitelisted', $lifted, $entity->getHost()));
                        }
                    }
                    else
                    {
                        EntityVerifier::verifyEntity($entity);
                    }
                    break;

                case RecordChangeType::ENTITY_DELETED:
                    // Usually already removed with the entity (adguard_findings_entities_uuid_fk), but not from the cache
                    FindingManager::deleteFindings($change->getUuid());
                    break;

                case RecordChangeType::BLACKLIST_LIFTED:
                    $blacklist = $change->getRecord();
                    if($blacklist instanceof BlacklistRecord && !PluginOperator::isAutomaticLift($blacklist))
                    {
                        BlacklistRecorder::suppress($blacklist);
                    }
                    break;

                case RecordChangeType::BLACKLIST_DELETED:
                    BlacklistRecorder::suppress($change->getUuid());
                    break;

                default:
                    break;
            }
        }
    }
