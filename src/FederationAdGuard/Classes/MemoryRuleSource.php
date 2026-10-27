<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Enums\RuleAction;
    use FederationAdGuard\Enums\RuleType;
    use FederationAdGuard\Interfaces\RuleSourceInterface;
    use FederationAdGuard\Objects\FilterRule;

    class MemoryRuleSource implements RuleSourceInterface
    {
        /**
         * @var array<string, FilterRule[]>
         */
        private array $byHost;
        /**
         * @var array<string, FilterRule[]>
         */
        private array $byToken;
        /**
         * @var FilterRule[]
         */
        private array $unindexed;
        /**
         * @var array<int, string>
         */
        private array $listNames;
        /**
         * @var array<string, \FederationLib\Enums\IncidentType>
         */
        private array $concerns = [];

        /**
         * MemoryRuleSource constructor
         *
         * @param FilterRule[] $rules The rules
         * @param array<int, string> $listNames The names of the lists the rules belong to, by subscription ID
         */
        public function __construct(array $rules=[], array $listNames=[])
        {
            $this->listNames = $listNames;
            $this->byHost = [];
            $this->byToken = [];
            $this->unindexed = [];
            foreach($rules as $rule)
            {
                $this->add($rule);
            }
        }

        /**
         * Adds a rule
         *
         * @param FilterRule $rule The rule
         * @return void
         */
        public function add(FilterRule $rule): void
        {
            if($rule->getAction() === RuleAction::BLOCK && $rule->getConcern() !== null)
            {
                $this->concerns[$rule->getConcern()->value] = $rule->getConcern();
            }

            if($rule->getHost() !== null && $rule->getType() !== RuleType::REGEX)
            {
                $this->byHost[$rule->getHost()][] = $rule;
            }
            elseif($rule->getToken() !== null)
            {
                $this->byToken[$rule->getToken()][] = $rule;
            }
            else
            {
                $this->unindexed[] = $rule;
            }
        }

        /**
         * @inheritDoc
         */
        public function getRulesByHosts(array $hosts): array
        {
            return self::getIndexedRules($this->byHost, $hosts);
        }

        /**
         * @inheritDoc
         */
        public function getRulesByTokens(array $tokens): array
        {
            return self::getIndexedRules($this->byToken, $tokens);
        }

        /**
         * Reads each distinct index key once, matching the database source's lookup semantics
         *
         * @param array<string, FilterRule[]> $index The rules by key
         * @param string[] $keys The keys
         * @return FilterRule[] The indexed rules
         */
        private static function getIndexedRules(array $index, array $keys): array
        {
            $rules = [];
            foreach(array_unique($keys) as $key)
            {
                foreach($index[$key] ?? [] as $rule)
                {
                    $rules[] = $rule;
                }
            }

            return $rules;
        }

        /**
         * @inheritDoc
         */
        public function getUnindexedRules(): array
        {
            return $this->unindexed;
        }

        /**
         * @inheritDoc
         */
        public function getListNames(): array
        {
            return $this->listNames;
        }

        /**
         * @inheritDoc
         */
        public function getConcerns(): array
        {
            return array_values($this->concerns);
        }
    }
