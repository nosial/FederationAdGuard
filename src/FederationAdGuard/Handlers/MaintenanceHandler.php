<?php

    namespace FederationAdGuard\Handlers;

    use FederationAdGuard\Classes\Configuration;
    use FederationAdGuard\Classes\Configuration\DatabaseConfiguration;
    use FederationAdGuard\Classes\EntityVerifier;
    use FederationAdGuard\Classes\Logger;
    use FederationAdGuard\Classes\PluginOperator;
    use FederationAdGuard\Classes\Provisioner;
    use FederationAdGuard\Classes\Synchronizer;
    use FederationAdGuard\Exceptions\RecordingException;
    use InvalidArgumentException;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use FederationLib\Interfaces\MaintenanceEventHandlerInterface;
    use FederationLib\Objects\Plugin\Maintenance;

    class MaintenanceHandler implements MaintenanceEventHandlerInterface
    {
        /**
         * @inheritDoc
         */
        public static function handleMaintenance(Maintenance $maintenance): void
        {
            if(!Configuration::isEnabled())
            {
                Logger::log()->debug('FederationAdGuard is disabled, skipping its maintenance');
                return;
            }

            try
            {
                // The operator may have been deleted or changed since the server started, a disabled operator stays
                // disabled
                PluginOperator::provision();
            }
            catch(RecordingException|DatabaseOperationException|InvalidArgumentException $e)
            {
                Logger::log()->error('Unable to repair the FederationAdGuard operator, the plugin is inactive until it is: ' . $e->getMessage(), $e);
                return;
            }

            if(!PluginOperator::isActive())
            {
                Logger::log()->info('The FederationAdGuard operator is disabled, skipping the maintenance until it is enabled again');
                return;
            }

            try
            {
                self::maintain();
            }
            catch(InvalidArgumentException|DatabaseOperationException|CacheOperationException $e)
            {
                Logger::log()->error('The FederationAdGuard maintenance failed, the next run tries again: ' . $e->getMessage(), $e);
            }
        }

        /**
         * Provisions and updates the lists and checks a batch of findings and host entities
         *
         * @return void
         * @throws DatabaseOperationException If there is an error with the database
         * @throws CacheOperationException If there is an error during a cache operation
         * @throws InvalidArgumentException If a subscription cannot be created, changed or deleted, or FederationLib
         *                                  rejects the UUID of a blacklist record
         */
        private static function maintain(): void
        {
            Provisioner::provision();

            $synchronized = Synchronizer::syncDue();
            $failed = count(array_filter($synchronized, fn(array $result) => $result['status'] === 'FAILED'));
            $updated = count(array_filter($synchronized, fn(array $result) => $result['status'] === 'UPDATED'));

            $findings = EntityVerifier::verifyFindings(DatabaseConfiguration::MAINTENANCE_BATCH);
            // The records the plugin already created keep following the lists, new ones are only made while it builds the database
            $entities = Configuration::getDatabaseConfiguration()->isEnabled()
                ? EntityVerifier::verifyEntities(DatabaseConfiguration::MAINTENANCE_BATCH)
                : ['checked' => 0, 'listed' => 0, 'completed' => false];

            Logger::log()->info(sprintf(
                'Maintenance: %d list(s) updated, %d failed; %d finding(s) checked, %d lifted, %d suppressed, %d forgotten, %d repaired; %d host entities checked, %d listed%s',
                $updated, $failed, $findings['checked'], $findings['lifted'], $findings['suppressed'], $findings['forgotten'], $findings['repaired'],
                $entities['checked'], $entities['listed'],
                $entities['completed'] ? ', every host entity was checked' : ''
            ));
        }
    }
