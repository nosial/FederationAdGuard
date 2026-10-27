<?php

    namespace FederationAdGuard\Tests\Helpers;

    use FederationAdGuard\Classes\FilterParser;
    use FederationAdGuard\Classes\MemoryRuleSource;
    use FederationAdGuard\Enums\ListSyntax;
    use FederationLib\Enums\IncidentType;

    class TestRules
    {
        /**
         * Creates a source from lists, each list belongs to a subscription with the given concern
         *
         * @param array<int, array{0: string, 1: IncidentType}> $lists The contents and concern of each list, by subscription ID
         * @return MemoryRuleSource The rules
         */
        public static function source(array $lists): MemoryRuleSource
        {
            $source = new MemoryRuleSource();
            foreach($lists as $subscriptionId => [$contents, $concern])
            {
                foreach(FilterParser::parse($contents, ListSyntax::AUTO)->getRules() as $rule)
                {
                    $source->add($rule->withSubscription($subscriptionId, $concern));
                }
            }

            return $source;
        }
    }
