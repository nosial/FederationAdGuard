<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Classes\Configuration\DatabaseConfiguration;
    use FederationAdGuard\Classes\Configuration\FilterListsConfiguration;
    use FederationAdGuard\Classes\Configuration\ListsConfiguration;
    use FederationAdGuard\Classes\Configuration\ScanningConfiguration;
    use FederationLib\Classes\Configuration\ConfigurationValues;

    class Configuration
    {
        private static ?\ConfigLib\Configuration $configuration = null;
        private static ?ListsConfiguration $listsConfiguration = null;
        private static ?FilterListsConfiguration $filterListsConfiguration = null;
        private static ?ScanningConfiguration $scanningConfiguration = null;
        private static ?DatabaseConfiguration $databaseConfiguration = null;
        private static bool $enabled = true;

        /**
         * Initializes the configuration with its default values, every value can also be set with its environment
         * variable
         *
         * @return void
         */
        public static function initialize(): void
        {
            self::$configuration = new \ConfigLib\Configuration('federation_adguard');

            // The hard switch: while disabled the plugin does nothing at all. Disabling the FederationAdGuard operator
            // is the soft switch, see PluginOperator::isActive()
            self::$configuration->setDefault('enabled', true, 'FEDERATION_ADGUARD_ENABLED');

            // Your own lists (URLs, absolute paths of files or directories, FilterLists IDs) and inline rules, used with
            // or without the FilterLists directory
            self::$configuration->setDefault('lists', '', 'FEDERATION_ADGUARD_LISTS');
            self::$configuration->setDefault('rules', '', 'FEDERATION_ADGUARD_RULES');
            self::$configuration->setDefault('update_interval', '1d', 'FEDERATION_ADGUARD_UPDATE_INTERVAL');
            self::$configuration->setDefault('allow_private', false, 'FEDERATION_ADGUARD_ALLOW_PRIVATE');

            // The FilterLists directory (https://filterlists.com), which lists are discovered in it
            self::$configuration->setDefault('filterlists.enabled', true, 'FEDERATION_ADGUARD_FILTERLISTS_ENABLED');
            self::$configuration->setDefault('filterlists.concerns', implode(',', FilterListsConfiguration::DEFAULT_CONCERNS), 'FEDERATION_ADGUARD_FILTERLISTS_CONCERNS');
            self::$configuration->setDefault('filterlists.languages', 'en', 'FEDERATION_ADGUARD_FILTERLISTS_LANGUAGES');
            self::$configuration->setDefault('filterlists.max', 4, 'FEDERATION_ADGUARD_FILTERLISTS_MAX');
            self::$configuration->setDefault('filterlists.exclude', '', 'FEDERATION_ADGUARD_FILTERLISTS_EXCLUDE');
            self::$configuration->setDefault('filterlists.endpoint', FilterListsConfiguration::DEFAULT_ENDPOINT, 'FEDERATION_ADGUARD_FILTERLISTS_ENDPOINT');

            // The ADGUARD_* scanning rules, -15 reaches the default block threshold on its own
            self::$configuration->setDefault('scanning.points', -15.0, 'FEDERATION_ADGUARD_SCANNING_POINTS');
            self::$configuration->setDefault('scanning.link_points', -5.0, 'FEDERATION_ADGUARD_SCANNING_LINK_POINTS');
            self::$configuration->setDefault('scanning.unlisted_points', 2.0, 'FEDERATION_ADGUARD_SCANNING_UNLISTED_POINTS');
            self::$configuration->setDefault('scanning.spam_points', -10.0, 'FEDERATION_ADGUARD_SCANNING_SPAM_POINTS');

            // Building the database: findings of the listed hosts, and the authors of messages of listed links
            self::$configuration->setDefault('database.enabled', true, 'FEDERATION_ADGUARD_DATABASE_ENABLED');
            self::$configuration->setDefault('database.author_blacklist', '1d', 'FEDERATION_ADGUARD_DATABASE_AUTHOR_BLACKLIST');

            // Only save if the configuration file does not exist or we're in CLI mode
            if(!file_exists(self::$configuration->getPath()) || php_sapi_name() === 'cli')
            {
                self::$configuration->save();
            }

            self::$enabled = ConfigurationValues::parseBool(self::$configuration->get('enabled'), true);
            self::$listsConfiguration = new ListsConfiguration([
                'lists' => self::$configuration->get('lists'),
                'rules' => self::$configuration->get('rules'),
                'update_interval' => self::$configuration->get('update_interval'),
                'allow_private' => self::$configuration->get('allow_private'),
            ]);
            self::$filterListsConfiguration = new FilterListsConfiguration(self::$configuration->get('filterlists') ?? []);
            self::$scanningConfiguration = new ScanningConfiguration(self::$configuration->get('scanning') ?? []);
            self::$databaseConfiguration = new DatabaseConfiguration(self::$configuration->get('database') ?? []);
        }

        /**
         * Returns True if the plugin is enabled, while disabled (the hard switch) it does nothing at all
         *
         * @return bool True if enabled
         */
        public static function isEnabled(): bool
        {
            if(self::$configuration === null)
            {
                self::initialize();
            }

            return self::$enabled;
        }

        /**
         * Get the lists configuration: your own lists, the inline rules and how they're updated.
         *
         * @return ListsConfiguration
         */
        public static function getListsConfiguration(): ListsConfiguration
        {
            if(self::$listsConfiguration === null)
            {
                self::initialize();
            }

            return self::$listsConfiguration;
        }

        /**
         * Get the FilterLists configuration.
         *
         * @return FilterListsConfiguration
         */
        public static function getFilterListsConfiguration(): FilterListsConfiguration
        {
            if(self::$filterListsConfiguration === null)
            {
                self::initialize();
            }

            return self::$filterListsConfiguration;
        }

        /**
         * Get the scanning configuration.
         *
         * @return ScanningConfiguration
         */
        public static function getScanningConfiguration(): ScanningConfiguration
        {
            if(self::$scanningConfiguration === null)
            {
                self::initialize();
            }

            return self::$scanningConfiguration;
        }

        /**
         * Get the database configuration.
         *
         * @return DatabaseConfiguration
         */
        public static function getDatabaseConfiguration(): DatabaseConfiguration
        {
            if(self::$databaseConfiguration === null)
            {
                self::initialize();
            }

            return self::$databaseConfiguration;
        }
    }
