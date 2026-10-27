<?php

    namespace FederationAdGuard\Classes;

    use FederationLib\Exceptions\CacheOperationException;
    use FederationLib\Exceptions\DatabaseOperationException;
    use Generator;
    use FederationAdGuard\Exceptions\RuleException;
    use FederationAdGuard\Enums\RegexSubject;
    use FederationAdGuard\Enums\RuleAction;
    use FederationAdGuard\Enums\RuleType;
    use FederationAdGuard\Interfaces\RuleSourceInterface;
    use FederationAdGuard\Objects\FilterRule;
    use FederationAdGuard\Objects\MatchResult;
    use FederationAdGuard\Objects\MatchTarget;
    use FederationAdGuard\Objects\RuleMatch;

    class Matcher
    {
        /**
         * The maximum number of distinct rules evaluated for one target, an incomplete match never becomes a decision
         */
        public const int MAX_CANDIDATES = 50000;

        /**
         * Matches a target against the rules of a source
         *
         * @param MatchTarget $target The target
         * @param RuleSourceInterface $source The rules
         * @return MatchResult The rules that apply
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         * @throws RuleException If the distinct candidate limit is exceeded
         */
        public static function match(MatchTarget $target, RuleSourceInterface $source): MatchResult
        {
            $candidates = self::getCandidates($target, $source);

            // $badfilter rules disable the rules they are written as, whether those apply or not
            $disabled = [];
            foreach($candidates as $rule)
            {
                if($rule->isBadfilter())
                {
                    $disabled[$rule->getFingerprint()] = true;
                }
            }

            $blocking = [];
            $exceptions = [];
            foreach($candidates as $rule)
            {
                if($rule->isBadfilter() || isset($disabled[$rule->getFingerprint()]))
                {
                    continue;
                }

                $assertion = false;
                if(!self::applies($rule, $target, $assertion))
                {
                    continue;
                }

                if($rule->getAction() === RuleAction::ALLOW)
                {
                    $exceptions[] = new RuleMatch($rule, $assertion);
                }
                else
                {
                    $blocking[] = new RuleMatch($rule, $assertion);
                }
            }

            $fullException = array_any($exceptions, fn(RuleMatch $match) => !$match->getRule()->isPartial());
            $importantException = array_any($exceptions, fn(RuleMatch $match) => !$match->getRule()->isPartial() && $match->getRule()->isImportant());
            $anyException = count($exceptions) > 0;

            $effective = [];
            $cancelled = [];
            foreach($blocking as $match)
            {
                $rule = $match->getRule();
                $isCancelled = $rule->isImportant()
                    ? $importantException
                    : ($rule->isPartial() ? $anyException : $fullException);

                if($isCancelled)
                {
                    $cancelled[] = $match;
                }
                else
                {
                    $effective[] = $match;
                }
            }

            return new MatchResult($target, $effective, $cancelled, $exceptions);
        }

        /**
         * Returns the DNS name and the parent domains a HOST rule may be indexed by, e.g., a.b.example.com,
         * b.example.com, example.com and com
         *
         * @param string $host The DNS name
         * @return string[] The names
         */
        public static function getHostSuffixes(string $host): array
        {
            $suffixes = [$host];
            while(($position = strpos($host, '.')) !== false)
            {
                $host = substr($host, $position + 1);
                $suffixes[] = $host;
            }

            return $suffixes;
        }

        /**
         * Returns True if a host is the given domain or one of its subdomains
         *
         * @param string $host The host
         * @param string $domain The domain
         * @return bool True if the host is within the domain
         */
        public static function isWithin(string $host, string $domain): bool
        {
            return $host === $domain || str_ends_with($host, '.' . $domain);
        }

        /**
         * Returns the rules that may apply to a target
         *
         * @param MatchTarget $target The target
         * @param RuleSourceInterface $source The rules
         * @return FilterRule[] The candidate rules, without duplicates
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         * @throws RuleException If the distinct candidate limit is exceeded
         */
        private static function getCandidates(MatchTarget $target, RuleSourceInterface $source): array
        {
            $hosts = $target->getAddresses();
            if($target->getHost() !== null)
            {
                $hosts = array_merge($hosts, $target->isAddress() ? [$target->getHost()] : self::getHostSuffixes($target->getHost()));
            }

            $candidates = [];
            $limit = self::MAX_CANDIDATES;
            foreach(self::getCandidateRules($target, $source, array_values(array_unique($hosts))) as $rule)
            {
                $key = $rule->getId() !== null ? 'id:' . $rule->getId() : 'fp:' . $rule->getSubscriptionId() . ':' . $rule->getFingerprint() . ':' . $rule->getConcern()?->value . ':' . $rule->getRule();
                $candidates[$key] ??= $rule;
                if(count($candidates) > $limit)
                {
                    throw new RuleException(sprintf('The target exceeds the maximum of %d candidate rules; an incomplete match cannot establish a filter decision', $limit));
                }
            }

            return array_values($candidates);
        }

        /**
         * Reads each candidate group in lookup order without copying the groups into a combined array.
         * One extra distinct candidate detects overflow; incomplete matches never become filter decisions.
         *
         * @param MatchTarget $target The target
         * @param RuleSourceInterface $source The rules
         * @param string[] $hosts The host names and addresses
         * @return Generator<FilterRule> The candidate rules, including duplicates
         * @throws CacheOperationException If a cache operation fails
         * @throws DatabaseOperationException If a database operation fails
         */
        private static function getCandidateRules(MatchTarget $target, RuleSourceInterface $source, array $hosts): Generator
        {
            yield from $source->getRulesByHosts($hosts);
            if($target->getUrl() !== null)
            {
                yield from $source->getRulesByTokens(FilterParser::getUrlTokens($target->getUrl()));
            }

            yield from $source->getUnindexedRules();
        }

        /**
         * Returns True if a rule applies to a target
         *
         * @param FilterRule $rule The rule
         * @param MatchTarget $target The target
         * @param bool $assertion Set to True if the rule only applies because of something the client asserted
         * @return bool True if the rule applies
         */
        private static function applies(FilterRule $rule, MatchTarget $target, bool &$assertion): bool
        {
            $host = $target->getHost();
            $name = $host !== null && !$target->isAddress() ? $host : null;

            $matches = match($rule->getType())
            {
                RuleType::HOST => $name !== null && $rule->getHost() !== null
                    && ($name === $rule->getHost() || ($rule->isSubdomains() && str_ends_with($name, '.' . $rule->getHost()))),
                RuleType::IP => $rule->getHost() !== null
                    && (($target->isAddress() && $host === $rule->getHost()) || in_array($rule->getHost(), $target->getAddresses(), true)),
                RuleType::URL => $target->getUrl() !== null && self::matchesRegex($rule->getRegex(), $target->getUrl()),
                RuleType::REGEX => $rule->getRegexSubject() === RegexSubject::HOST
                    ? $name !== null && self::matchesRegex($rule->getRegex(), $name)
                    : $target->getUrl() !== null && self::matchesRegex($rule->getRegex(), $target->getUrl()),
            };

            if(!$matches)
            {
                return false;
            }

            if($rule->getDenyAllow() !== null && $name !== null && array_any($rule->getDenyAllow(), fn(string $domain) => self::isWithin($name, $domain)))
            {
                return false;
            }

            if($rule->getDnsTypes() !== null)
            {
                // Only the client knows the record type of a lookup, a rule restricted to some types never applies
                // to anything else
                if($target->getQueryType() === null)
                {
                    return false;
                }

                $included = array_values(array_filter($rule->getDnsTypes(), fn(string $type) => !str_starts_with($type, '~')));
                $excluded = array_map(fn(string $type) => substr($type, 1), array_filter($rule->getDnsTypes(), fn(string $type) => str_starts_with($type, '~')));
                if((count($included) > 0 && !in_array($target->getQueryType(), $included, true)) || in_array($target->getQueryType(), $excluded, true))
                {
                    return false;
                }

                $assertion = true;
            }

            return true;
        }

        /**
         * Evaluates a regular expression from a list, a regular expression that fails (e.g., exceeds the backtracking
         * limit) doesn't match
         *
         * @param string|null $regex The regular expression
         * @param string $subject The subject
         * @return bool True if it matches
         */
        private static function matchesRegex(?string $regex, string $subject): bool
        {
            return $regex !== null && @preg_match($regex, $subject) === 1;
        }
    }
