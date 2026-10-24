<?php

    namespace FederationAdGuard\Objects;

    class ParseResult
    {
        /**
         * The number of examples of unsupported lines that are kept
         */
        private const int MAX_EXAMPLES = 10;

        /** @var FilterRule[] */
        private array $rules;
        private int $comments;
        private int $cosmetic;
        private int $unsupported;
        /** @var array<int, array{line: string, reason: string}> */
        private array $examples;

        /**
         * ParseResult constructor
         */
        public function __construct()
        {
            $this->rules = [];
            $this->comments = 0;
            $this->cosmetic = 0;
            $this->unsupported = 0;
            $this->examples = [];
        }

        /**
         * Adds the rules parsed from a line
         *
         * @param FilterRule[] $rules The rules
         * @return void
         */
        public function addRules(array $rules): void
        {
            foreach($rules as $rule)
            {
                $this->rules[] = $rule;
            }
        }

        /**
         * Counts a comment or an empty line
         *
         * @return void
         */
        public function addComment(): void
        {
            $this->comments++;
        }

        /**
         * Counts a cosmetic rule (element hiding, scriptlets), which can't apply to a host or URL
         *
         * @return void
         */
        public function addCosmetic(): void
        {
            $this->cosmetic++;
        }

        /**
         * Counts a line that is not supported, keeping a few examples
         *
         * @param string $line The line
         * @param string $reason Why the line is not supported
         * @return void
         */
        public function addUnsupported(string $line, string $reason): void
        {
            $this->unsupported++;
            if(count($this->examples) < self::MAX_EXAMPLES)
            {
                $this->examples[] = ['line' => mb_strcut($line, 0, 200), 'reason' => $reason];
            }
        }

        /**
         * Returns the parsed rules
         *
         * @return FilterRule[] The rules
         */
        public function getRules(): array
        {
            return $this->rules;
        }

        /**
         * Returns the number of comments and empty lines
         *
         * @return int The number of comments
         */
        public function getComments(): int
        {
            return $this->comments;
        }

        /**
         * Returns the number of cosmetic rules
         *
         * @return int The number of cosmetic rules
         */
        public function getCosmetic(): int
        {
            return $this->cosmetic;
        }

        /**
         * Returns the number of unsupported lines
         *
         * @return int The number of unsupported lines
         */
        public function getUnsupported(): int
        {
            return $this->unsupported;
        }

        /**
         * Returns examples of unsupported lines with the reason they are not supported
         *
         * @return array<int, array{line: string, reason: string}> The examples
         */
        public function getUnsupportedExamples(): array
        {
            return $this->examples;
        }
    }
