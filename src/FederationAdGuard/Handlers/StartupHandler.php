<?php

    namespace FederationAdGuard\Handlers;

    use FederationAdGuard\Classes\Configuration;
    use FederationAdGuard\Classes\Logger;
    use FederationAdGuard\Classes\Provisioner;
    use FederationAdGuard\Classes\PluginOperator;
    use FederationAdGuard\Classes\Synchronizer;
    use FederationAdGuard\Enums\DatabaseTables;
    use FederationAdGuard\Exceptions\RecordingException;
    use InvalidArgumentException;
    use FederationLib\Classes\DatabaseConnection;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use FederationLib\Interfaces\StartupEventHandlerInterface;
    use FederationLib\Objects\Plugin\Startup;
    use PDOException;

    class StartupHandler implements StartupEventHandlerInterface
    {
        /**
         * @inheritDoc
         * @throws DatabaseOperationException If the plugin's tables cannot be created
         */
        public static function handleStartup(Startup $startup): void
        {
            if(!Configuration::isEnabled())
            {
                Logger::log()->info('FederationAdGuard is disabled (FEDERATION_ADGUARD_ENABLED), it does nothing');
                return;
            }

            // The plugin can't work without its tables, a failure here fails `federationlib init`
            self::initializeTables();

            try
            {
                PluginOperator::provision();
            }
            catch(RecordingException|DatabaseOperationException|InvalidArgumentException $e)
            {
                Logger::log()->error('Unable to provision the FederationAdGuard operator, the plugin is inactive until the next maintenance run repairs it: ' . $e->getMessage(), $e);
                return;
            }

            if(!PluginOperator::isActive())
            {
                Logger::log()->info('The FederationAdGuard operator is disabled, the plugin does nothing until it is enabled again');
                return;
            }

            try
            {
                Provisioner::provision();
                $results = Synchronizer::syncDue(newOnly: true);
                foreach($results as $id => $result)
                {
                    if($result['status'] === 'FAILED')
                    {
                        Logger::log()->warning(sprintf('The list %d could not be downloaded on startup, it is tried again by the next maintenance run: %s', $id, $result['error'] ?? 'unknown error'));
                    }
                }

                Logger::log()->info(sprintf('Synchronized %d list(s) on startup, %d failed', count($results), count(array_filter($results, fn(array $result) => $result['status'] === 'FAILED'))));
            }
            catch(InvalidArgumentException|DatabaseOperationException|CacheOperationException $e)
            {
                Logger::log()->error('Unable to provision or download the lists on startup, the next maintenance run tries again: ' . $e->getMessage(), $e);
            }
        }

        /**
         * Creates the plugin's tables that don't exist yet, in the order of DatabaseTables::getOrderedTables()
         *
         * @return void
         * @throws DatabaseOperationException Thrown if a table could not be created or the SQL file of a table could not
         *                                    be read
         */
        public static function initializeTables(): void
        {
            foreach(DatabaseTables::getOrderedTables() as $sql)
            {
                if(self::tableExists($sql->getTableName()))
                {
                    continue;
                }

                Logger::log()->info("Creating table {$sql->getTableName()}");
                $sqlContent = @file_get_contents($sql->getPath());
                if ($sqlContent === false)
                {
                    throw new DatabaseOperationException("Failed to read SQL file for table $sql->name at path: {$sql->getPath()}");
                }

                try
                {
                    DatabaseConnection::getConnection()->exec($sqlContent);
                    if(!self::tableExists($sql->getTableName()))
                    {
                        throw new DatabaseOperationException("Failed to create table {$sql->getTableName()} verify if the SQL in {$sql->getPath()} is valid");
                    }

                    Logger::log()->info("Database table {$sql->getTableName()} initialized successfully.");
                }
                catch (PDOException $e)
                {
                    throw new DatabaseOperationException("Failed to execute SQL for table $sql->name: " . $e->getMessage(), 0, $e);
                }
            }
        }

        /**
         * Checks if the given table exists in the database
         *
         * @param string $table The table to check its existence
         * @return bool Returns True if the table exists, False otherwise.
         * @throws DatabaseOperationException Thrown if the tables could not be listed
         */
        private static function tableExists(string $table): bool
        {
            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare('SHOW TABLES LIKE :table');
                $stmt->bindValue(':table', $table);
                $stmt->execute();

                return $stmt->rowCount() > 0;
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException("Failed to check if the table $table exists: " . $e->getMessage(), (int)$e->getCode(), $e);
            }
        }
    }
