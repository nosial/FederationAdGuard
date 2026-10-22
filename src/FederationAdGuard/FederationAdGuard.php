<?php

    namespace FederationAdGuard;

    use FederationAdGuard\Classes\DatabaseRuleSource;
    use FederationAdGuard\Classes\FilterListsClient;
    use FederationAdGuard\Classes\ListDownloader;
    use FederationAdGuard\Classes\Matcher;
    use FederationAdGuard\Interfaces\FilterListsClientInterface;
    use FederationAdGuard\Interfaces\ListDownloaderInterface;
    use FederationAdGuard\Interfaces\RuleSourceInterface;
    use FederationAdGuard\Objects\MatchResult;
    use FederationAdGuard\Objects\MatchTarget;

    class FederationAdGuard
    {
        private static ?RuleSourceInterface $ruleSource = null;
        private static ?ListDownloaderInterface $downloader = null;
        private static ?FilterListsClientInterface $filterListsClient = null;

        /**
         * Returns the rules of the enabled subscriptions
         *
         * @return RuleSourceInterface The rules
         */
        public static function getRuleSource(): RuleSourceInterface
        {
            if(self::$ruleSource === null)
            {
                self::$ruleSource = new DatabaseRuleSource();
            }

            return self::$ruleSource;
        }

        /**
         * Replaces the rules, null resets them to the rules of the enabled subscriptions
         *
         * @param RuleSourceInterface|null $ruleSource The rules
         * @return void
         */
        public static function setRuleSource(?RuleSourceInterface $ruleSource): void
        {
            self::$ruleSource = $ruleSource;
        }

        /**
         * Returns the downloader lists are downloaded with
         *
         * @return ListDownloaderInterface The downloader
         */
        public static function getDownloader(): ListDownloaderInterface
        {
            if(self::$downloader === null)
            {
                self::$downloader = new ListDownloader();
            }

            return self::$downloader;
        }

        /**
         * Replaces the downloader, null resets it to the downloader created from the plugin's configuration
         *
         * @param ListDownloaderInterface|null $downloader The downloader
         * @return void
         */
        public static function setDownloader(?ListDownloaderInterface $downloader): void
        {
            self::$downloader = $downloader;
            self::$filterListsClient = null;
        }

        /**
         * Returns the client of the FilterLists API
         *
         * @return FilterListsClientInterface The client
         */
        public static function getFilterListsClient(): FilterListsClientInterface
        {
            if(self::$filterListsClient === null)
            {
                self::$filterListsClient = new FilterListsClient(null, self::getDownloader());
            }

            return self::$filterListsClient;
        }

        /**
         * Replaces the client of the FilterLists API, null resets it to the client created from the plugin's
         * configuration
         *
         * @param FilterListsClientInterface|null $client The client
         * @return void
         */
        public static function setFilterListsClient(?FilterListsClientInterface $client): void
        {
            self::$filterListsClient = $client;
        }

        /**
         * Matches a target against the rules of the enabled subscriptions
         *
         * @param MatchTarget $target The target
         * @return MatchResult The rules that apply
         */
        public static function match(MatchTarget $target): MatchResult
        {
            return Matcher::match($target, self::getRuleSource());
        }
    }
