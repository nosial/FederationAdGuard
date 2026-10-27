<?php

    namespace FederationAdGuard\Tests\Helpers;

    use FederationAdGuard\Classes\Configuration;

    class PluginConfiguration
    {
        private const array DEFAULTS = [
            'enabled' => 'true',
            'lists' => '',
            'rules' => '',
            'update_interval' => '1d',
            'allow_private' => 'false',
            // The unit tests never contact a directory, FilterListsTest enables it against the real directory
            'filterlists_enabled' => 'false',
            'filterlists_concerns' => 'ADVERTISING,TRACKING',
            'filterlists_languages' => 'en',
            'filterlists_max' => '4',
            'filterlists_exclude' => '',
            'filterlists_preferred' => '301,242,2214,157',
            // Nothing listens on port 1, the unit tests can never reach the real FilterLists API
            'filterlists_endpoint' => 'http://127.0.0.1:1',
            'scanning_points' => '-15',
            'scanning_link_points' => '-5',
            'scanning_unlisted_points' => '2',
            'scanning_spam_points' => '-10',
            // The unit tests never write to a database
            'database_enabled' => 'false',
            'database_author_blacklist' => '1d',
        ];

        public static function apply(array $options=[]): void
        {
            foreach(array_merge(self::DEFAULTS, $options) as $option => $value)
            {
                putenv(sprintf('FEDERATION_ADGUARD_%s=%s', strtoupper($option), $value));
            }

            Configuration::initialize();
        }

        public static function reset(): void
        {
            self::apply();
        }
    }
