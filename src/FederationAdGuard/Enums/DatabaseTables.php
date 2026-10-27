<?php

    namespace FederationAdGuard\Enums;

    enum DatabaseTables : string
    {
        case SUBSCRIPTIONS = 'adguard_subscriptions.sql';
        case RULES = 'adguard_rules.sql';
        case FINDINGS = 'adguard_findings.sql';

        /**
         * Returns the full path to the SQL file for the database table.
         *
         * @return string The full path to the SQL file.
         */
        public function getPath(): string
        {
            return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'Classes' . DIRECTORY_SEPARATOR . 'Resources' . DIRECTORY_SEPARATOR . $this->value;
        }

        /**
         * Returns the name of the database table.
         *
         * @return string The name of the database table.
         */
        public function getTableName(): string
        {
            return match($this)
            {
                self::SUBSCRIPTIONS => 'adguard_subscriptions',
                self::RULES => 'adguard_rules',
                self::FINDINGS => 'adguard_findings'
            };
        }

        /**
         * Returns an array of DatabaseTables in the order they should be processed or created.
         *
         * @return DatabaseTables[]
         */
        public static function getOrderedTables(): array
        {
            return [
                self::SUBSCRIPTIONS,
                self::RULES,
                self::FINDINGS
            ];
        }
    }
