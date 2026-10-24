<?php

    namespace FederationAdGuard\Objects;

    use FederationLib\Enums\IncidentType;
    use InvalidArgumentException;

    class CustomRuleDefinition
    {
        private string $rule;
        private IncidentType $concern;

        /**
         * CustomRuleDefinition constructor.
         *
         * @param string $rule The rule, in any syntax a filter list may use
         * @param IncidentType $concern The concern the rule detects
         */
        public function __construct(string $rule, IncidentType $concern)
        {
            $this->rule = trim($rule);
            $this->concern = $concern;
        }

        /**
         * Parses a line of `rules`. A line may start with the concern of its rule in brackets
         * (e.g., "[MALWARE] ||malware.example.com^"), otherwise the rule detects the default concern. Empty lines and
         * comments (lines starting with ! or #) declare nothing.
         *
         * @param string $line The line
         * @param IncidentType $defaultConcern The concern of a rule that names none
         * @return CustomRuleDefinition|null The definition, null if the line declares nothing
         * @throws InvalidArgumentException If the concern in brackets is not an incident type
         */
        public static function parse(string $line, IncidentType $defaultConcern): ?CustomRuleDefinition
        {
            $line = trim($line);
            if($line === '' || str_starts_with($line, '!') || (str_starts_with($line, '#') && !str_starts_with($line, '##') && !str_starts_with($line, '#@#')))
            {
                return null;
            }

            $concern = $defaultConcern;
            if(preg_match('/^\[([A-Za-z_]+)]\s*(.+)$/', $line, $matches) === 1)
            {
                $concern = IncidentType::tryFromCaseInsensitive($matches[1])
                    ?? throw new InvalidArgumentException(sprintf('The concern "%s" is not an incident type', $matches[1]));
                $line = trim($matches[2]);
            }
            elseif(preg_match('/^\[(?:Adblock|AdGuard|uBlock)\b[^\]]*\]$/i', $line) === 1)
            {
                // A list header, e.g., [Adblock Plus 2.0]
                return null;
            }

            return new self($line, $concern);
        }

        /**
         * Returns the rule
         *
         * @return string The rule
         */
        public function getRule(): string
        {
            return $this->rule;
        }

        /**
         * Returns the concern the rule detects
         *
         * @return IncidentType The concern
         */
        public function getConcern(): IncidentType
        {
            return $this->concern;
        }

        /**
         * Returns the key that identifies the rule, two definitions with the same key declare the same rule
         *
         * @return string The key
         */
        public function getKey(): string
        {
            return $this->concern->value . ':' . $this->rule;
        }
    }
