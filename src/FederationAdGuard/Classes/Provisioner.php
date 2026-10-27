<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Classes\Configuration\ListsConfiguration;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationAdGuard\Classes\Managers\RuleManager;
    use FederationAdGuard\Classes\Managers\SubscriptionManager;
    use FederationAdGuard\Enums\ListSource;
    use FederationAdGuard\Exceptions\ListException;
    use FederationAdGuard\Exceptions\RuleException;
    use InvalidArgumentException;
    use FederationAdGuard\FederationAdGuard;
    use FederationAdGuard\Objects\SubscriptionDefinition;
    use FederationLib\Exceptions\DatabaseOperationException;

    class Provisioner
    {
        /**
         * Applies the configured lists and rules while holding the same lock as the synchronizer.
         *
         * @return void
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         * @throws InvalidArgumentException If a subscription cannot be created, changed or deleted
         */
        public static function provision(): void
        {
            if(!DatabaseLock::acquire(DatabaseLock::SYNCHRONIZATION))
            {
                Logger::log()->info('The lists are already being updated by another process');
                return;
            }

            try
            {
                self::provisionSubscriptions();
                self::provisionCustomRules();
            }
            finally
            {
                DatabaseLock::releaseQuietly(DatabaseLock::SYNCHRONIZATION);
            }
        }

        /**
         * Returns the subscriptions the configuration declares
         *
         * @param bool $complete Set to false if part of the declared subscriptions could not be determined
         * @return SubscriptionDefinition[] The definitions by their key, `lists` overrides the lists
         *                                  selected automatically
         */
        public static function getDeclaredSubscriptions(bool &$complete=true): array
        {
            $configuration = Configuration::getListsConfiguration();
            $complete = $configuration->isComplete();
            $declared = [];

            $filterLists = Configuration::getFilterListsConfiguration();
            if($filterLists->isEnabled() && $filterLists->getMax() > 0)
            {
                try
                {
                    $declared = ListCatalog::discover(FederationAdGuard::getFilterListsClient(), $filterLists->getConcerns(),
                        $filterLists->getLanguages(), $filterLists->getExclude(), $filterLists->getMax(), $filterLists->getPreferred());
                    Logger::log()->debug(sprintf('Selected %d list(s) from the FilterLists directory', count($declared)));
                }
                catch(ListException $e)
                {
                    Logger::log()->warning('Unable to select lists from FilterLists, keeping previous subscriptions: ' . $e->getMessage());
                    $complete = false;
                }
            }

            foreach($configuration->getSubscriptions() as $definition)
            {
                if($definition->getSource() === ListSource::FILTERLISTS && !$filterLists->isEnabled())
                {
                    Logger::log()->warning(sprintf('Ignoring the FilterLists list %d of lists, filterlists.enabled is off', $definition->getFilterListsId()));
                    continue;
                }

                try
                {
                    $files = $definition->getSource() === ListSource::FILE ? LocalLists::expand($definition) : [$definition];
                    foreach($files as $file)
                    {
                        $declared[$file->getKey()] = $file;
                    }
                }
                catch(ListException $e)
                {
                    Logger::log()->warning($e->getMessage());
                    $complete = false;
                }
            }

            return $declared;
        }

        /**
         * Creates, updates and removes subscriptions to match the configuration.
         *
         * @return void
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         * @throws InvalidArgumentException If a subscription cannot be created, changed or deleted
         */
        private static function provisionSubscriptions(): void
        {
            $complete = true;
            $declared = self::getDeclaredSubscriptions($complete);
            $existing = [];
            foreach(SubscriptionManager::getSubscriptions() as $subscription)
            {
                if($subscription->getSource() !== ListSource::CUSTOM)
                {
                    $key = SubscriptionDefinition::getRecordKey($subscription->getSource(), $subscription->getFilterListsId(), $subscription->getLocation());
                    $existing[$key][] = $subscription;
                }
            }

            foreach($declared as $key => $definition)
            {
                $subscription = $existing[$key][0] ?? null;
                if($subscription === null)
                {
                    SubscriptionManager::createSubscription($definition->getSource(), $definition->getFilterListsId(), $definition->getLocation(), $definition->getName(),
                        $definition->getConcern(), $definition->isAllowlist());
                }
                else
                {
                    SubscriptionManager::updateSettings($subscription->getId(), $definition->getChangedSettings($subscription));
                }
            }

            if(!$complete)
            {
                Logger::log()->warning('The configured lists could not all be read, keeping previous subscriptions');
                return;
            }

            foreach($existing as $key => $subscriptions)
            {
                foreach($subscriptions as $index => $subscription)
                {
                    if(!isset($declared[$key]) || $index > 0)
                    {
                        SubscriptionManager::deleteSubscription($subscription->getId());
                    }
                }
            }
        }

        /**
         * Compiles inline rules directly into the rule table. No second copy of the configuration is stored.
         *
         * @return void
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         */
        private static function provisionCustomRules(): void
        {
            $complete = true;
            $definitions = Configuration::getListsConfiguration()->getRules($complete);
            if(!$complete)
            {
                Logger::log()->warning('The inline rules are invalid, keeping the previous rules');
                return;
            }

            $rules = [];
            try
            {
                foreach($definitions as $definition)
                {
                    foreach(FilterParser::parseLine($definition->getRule()) ?? [] as $rule)
                    {
                        $rules[] = $rule->withSubscription(null, $definition->getConcern());
                        if(count($rules) > ListsConfiguration::MAX_RULES)
                        {
                            throw new RuleException(sprintf('The inline rules exceed %d rules', ListsConfiguration::MAX_RULES));
                        }
                    }
                }
            }
            catch(RuleException $e)
            {
                Logger::log()->warning('Unable to compile the inline rules, keeping the previous rules: ' . $e->getMessage());
                return;
            }

            $subscription = SubscriptionManager::getCustomSubscription();
            $checksum = hash('sha256', serialize(array_map(fn($rule) => $rule->toArray(), $rules)));
            if($checksum === $subscription->getChecksum())
            {
                return;
            }

            RuleManager::replaceRules($subscription->getId(), $rules, null);
            SubscriptionManager::recordUpdate($subscription->getId(), $checksum, []);
            Logger::log()->info(sprintf('Compiled %d inline rules', count($rules)));
        }
    }
