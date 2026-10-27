<?php

    namespace FederationAdGuard\Tests\Helpers;

    use FederationAdGuard\Classes\PluginOperator;
    use FederationAdGuard\FederationAdGuard;
    use FederationLib\Classes\DatabaseConnection;
    use PDO;
    use ReflectionProperty;

    trait IsolatedDatabase
    {
        private ?PDO $connection = null;
        private ?PDO $previousConnection = null;
        private string $database;

        /**
         * Creates the database with FederationLib's tables and builds the database with the plugin
         *
         * @param array $options The plugin's configuration options (see PluginConfiguration)
         * @return void
         */
        private function createDatabase(array $options=[]): void
        {
            if(!getenv('ADGUARD_TEST_DATABASE_DSN'))
            {
                self::markTestSkipped('Set ADGUARD_TEST_DATABASE_DSN, ADGUARD_TEST_DATABASE_USER and ADGUARD_TEST_DATABASE_PASSWORD for isolated database tests');
            }

            $this->connection = new PDO(getenv('ADGUARD_TEST_DATABASE_DSN'), getenv('ADGUARD_TEST_DATABASE_USER'), getenv('ADGUARD_TEST_DATABASE_PASSWORD'),
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
            $this->database = 'adguard_test_' . bin2hex(random_bytes(6));
            $this->connection->exec('CREATE DATABASE `' . $this->database . '`');
            $this->connection->exec('USE `' . $this->database . '`');
            $property = new ReflectionProperty(DatabaseConnection::class, 'pdo');
            $this->previousConnection = $property->getValue();
            $property->setValue(null, $this->connection);
            DatabaseConnection::initializeDatabase();
            PluginOperator::setActive(null);
            PluginConfiguration::apply(array_merge(['database_enabled' => 'true'], $options));
        }

        /**
         * Drops the database
         *
         * @return void
         */
        private function dropDatabase(): void
        {
            if($this->connection !== null)
            {
                $this->connection->exec('DROP DATABASE `' . $this->database . '`');
                (new ReflectionProperty(DatabaseConnection::class, 'pdo'))->setValue(null, $this->previousConnection);
                $this->connection = null;
            }

            FederationAdGuard::setRuleSource(null);
            PluginOperator::setActive(null);
            PluginConfiguration::reset();
        }
    }
