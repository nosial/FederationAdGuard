<?php

    namespace FederationAdGuard\Classes;

    use FederationLib\Classes\DatabaseConnection;
    use FederationLib\Exceptions\DatabaseOperationException;
    use InvalidArgumentException;
    use PDO;
    use PDOException;

    class DatabaseLock
    {
        /**
         * Held while the subscriptions are provisioned or the lists are synchronized
         */
        public const string SYNCHRONIZATION = 'adguard_sync';

        /**
         * Held while the FederationAdGuard operator is created or repaired
         */
        public const string OPERATOR = 'adguard_operator';

        /**
         * The prefix of the locks held while the findings of a host are recorded
         */
        public const string FINDING = 'adguard_finding:';

        /**
         * The longest name MariaDB accepts is 64 characters, 13 of them are taken by the database scope
         */
        private const int MAX_NAME_LENGTH = 51;

        /**
         * Acquires a lock
         *
         * @param string $name The name of the lock, at most 51 characters
         * @param int $timeout The number of seconds to wait for the lock, 0 to give up right away
         * @return bool True if the lock was acquired, false if another connection holds it
         * @throws InvalidArgumentException If the name is too long
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement
         */
        public static function acquire(string $name, int $timeout=0): bool
        {
            self::validateName($name);

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("SELECT GET_LOCK(CONCAT(:name, ':', LEFT(SHA2(COALESCE(DATABASE(), ''), 256), 12)), :timeout)");
                $stmt->bindParam(':name', $name);
                $stmt->bindParam(':timeout', $timeout, PDO::PARAM_INT);
                $stmt->execute();

                return (int)$stmt->fetchColumn() === 1;
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException(sprintf("Failed to acquire the database lock %s: %s", $name, $e->getMessage()), (int)$e->getCode(), $e);
            }
        }

        /**
         * Releases a lock acquired by this connection
         *
         * @param string $name The name of the lock
         * @return void
         * @throws InvalidArgumentException If the name is too long
         * @throws DatabaseOperationException If there is an error preparing or executing the SQL statement
         */
        public static function release(string $name): void
        {
            self::validateName($name);

            try
            {
                $stmt = DatabaseConnection::getConnection()->prepare("SELECT RELEASE_LOCK(CONCAT(:name, ':', LEFT(SHA2(COALESCE(DATABASE(), ''), 256), 12)))");
                $stmt->bindParam(':name', $name);
                $stmt->execute();
            }
            catch (PDOException $e)
            {
                throw new DatabaseOperationException(sprintf("Failed to release the database lock %s: %s", $name, $e->getMessage()), (int)$e->getCode(), $e);
            }
        }

        /**
         * Releases a lock, logging a failure instead of throwing it, for the finally blocks of the lock's holders: the
         * lock is released with the connection anyway
         *
         * @param string $name The name of the lock
         * @return void
         */
        public static function releaseQuietly(string $name): void
        {
            try
            {
                self::release($name);
            }
            catch(DatabaseOperationException|InvalidArgumentException $e)
            {
                Logger::log()->warning($e->getMessage());
            }
        }

        /**
         * Returns the name of the lock held while the findings of a host are recorded
         *
         * @param string $host The host
         * @return string The name of the lock
         */
        public static function getFindingLock(string $host): string
        {
            return self::FINDING . substr(hash('sha256', $host), 0, self::MAX_NAME_LENGTH - strlen(self::FINDING));
        }

        /**
         * Validates the name of a lock
         *
         * @param string $name The name of the lock
         * @return void
         * @throws InvalidArgumentException If the name is empty or too long
         */
        private static function validateName(string $name): void
        {
            if($name === '' || strlen($name) > self::MAX_NAME_LENGTH)
            {
                throw new InvalidArgumentException(sprintf('The name of a database lock must be 1 to %d characters long', self::MAX_NAME_LENGTH));
            }
        }
    }
