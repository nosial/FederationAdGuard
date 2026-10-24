<?php

    namespace FederationAdGuard\Objects;

    use FederationLib\Enums\IncidentType;

    class MatchResult
    {
        private MatchTarget $target;
        /** @var RuleMatch[] */
        private array $blocking;
        /** @var RuleMatch[] */
        private array $cancelled;
        /** @var RuleMatch[] */
        private array $exceptions;

        /**
         * MatchResult constructor
         *
         * @param MatchTarget $target The target
         * @param RuleMatch[] $blocking The blocking rules that apply
         * @param RuleMatch[] $cancelled The blocking rules that apply but were cancelled by an exception
         * @param RuleMatch[] $exceptions The exceptions that apply
         */
        public function __construct(MatchTarget $target, array $blocking, array $cancelled=[], array $exceptions=[])
        {
            $this->target = $target;
            $this->blocking = array_values($blocking);
            $this->cancelled = array_values($cancelled);
            $this->exceptions = array_values($exceptions);
        }

        /**
         * @return MatchTarget The target
         */
        public function getTarget(): MatchTarget
        {
            return $this->target;
        }

        /**
         * Returns True if a blocking rule applies (for the concern, if given)
         *
         * @param IncidentType|null $concern The concern, null for any concern
         * @return bool True if blocked
         */
        public function isBlocked(?IncidentType $concern=null): bool
        {
            return count($this->getBlocking($concern)) > 0;
        }

        /**
         * Returns True if an exception applies to the target, ie; it is explicitly allowed
         *
         * @return bool True if allowed by an exception
         */
        public function isExcepted(): bool
        {
            return count($this->exceptions) > 0;
        }

        /**
         * Returns the blocking rules that apply, strongest first
         *
         * @param IncidentType|null $concern Only the rules of this concern, null for every concern
         * @return RuleMatch[] The blocking rules
         */
        public function getBlocking(?IncidentType $concern=null): array
        {
            $blocking = $concern === null ? $this->blocking : array_values(array_filter($this->blocking, fn(RuleMatch $match) => $match->getRule()->getConcern() === $concern));
            usort($blocking, fn(RuleMatch $a, RuleMatch $b) => $b->getStrength() <=> $a->getStrength());
            return $blocking;
        }

        /**
         * Returns the concerns of the blocking rules that apply
         *
         * @return IncidentType[] The concerns
         */
        public function getConcerns(): array
        {
            $concerns = [];
            foreach($this->blocking as $match)
            {
                $concern = $match->getRule()->getConcern() ?? IncidentType::OTHER;
                $concerns[$concern->value] = $concern;
            }

            return array_values($concerns);
        }

        /**
         * Returns the blocking rules that block a host entirely and rely on nothing the client asserted, one per
         * concern and host: the rules a blacklist record may be created for
         *
         * @return RuleMatch[] The host blocks
         */
        public function getHostBlocks(): array
        {
            $blocks = [];
            foreach($this->getBlocking() as $match)
            {
                $rule = $match->getRule();
                if(!$rule->isHostBlock() || $match->isAssertion() || $rule->getConcern() === null)
                {
                    continue;
                }

                $key = $rule->getConcern()->value . ':' . $rule->getHost();
                $blocks[$key] ??= $match;
            }

            return array_values($blocks);
        }

        /**
         * @return RuleMatch[] The blocking rules that apply but were cancelled by an exception
         */
        public function getCancelled(): array
        {
            return $this->cancelled;
        }
    }
