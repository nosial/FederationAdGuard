<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Classes\Managers\RuleManager;
    use FederationAdGuard\Classes\Managers\SubscriptionManager;
    use FederationAdGuard\Interfaces\RuleSourceInterface;

    class DatabaseRuleSource implements RuleSourceInterface
    {
        /**
         * @inheritDoc
         */
        public function getRulesByHosts(array $hosts): array
        {
            return RuleManager::getRulesByHosts($hosts);
        }

        /**
         * @inheritDoc
         */
        public function getRulesByTokens(array $tokens): array
        {
            return RuleManager::getRulesByTokens($tokens);
        }

        /**
         * @inheritDoc
         */
        public function getUnindexedRules(): array
        {
            return RuleManager::getUnindexedRules();
        }

        /**
         * @inheritDoc
         */
        public function getListNames(): array
        {
            return SubscriptionManager::getNames();
        }

        /**
         * @inheritDoc
         */
        public function getConcerns(): array
        {
            return RuleManager::getConcerns();
        }
    }
