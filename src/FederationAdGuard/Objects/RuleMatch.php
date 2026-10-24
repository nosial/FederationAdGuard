<?php

    namespace FederationAdGuard\Objects;

    class RuleMatch
    {
        private FilterRule $rule;
        private bool $assertion;

        /**
         * RuleMatch constructor
         *
         * @param FilterRule $rule The rule
         * @param bool $assertion True if the rule only applies because of something the client asserted, e.g., the
         *                        DNS record type of a $dnstype rule
         */
        public function __construct(FilterRule $rule, bool $assertion=false)
        {
            $this->rule = $rule;
            $this->assertion = $assertion;
        }

        /**
         * @return FilterRule The rule
         */
        public function getRule(): FilterRule
        {
            return $this->rule;
        }

        /**
         * @return bool True if the rule only applies because of something the client asserted
         */
        public function isAssertion(): bool
        {
            return $this->assertion;
        }

        /**
         * Returns how strongly the match blocks: a host block that relies on nothing the client asserted is the
         * strongest, a partial rule the weakest
         *
         * @return int The strength, higher is stronger
         */
        public function getStrength(): int
        {
            return ($this->rule->isHostBlock() ? 4 : 0) + ($this->rule->isPartial() ? 0 : 2) + ($this->assertion ? 0 : 1);
        }
    }
