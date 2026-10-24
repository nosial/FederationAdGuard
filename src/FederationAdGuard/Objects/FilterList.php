<?php

    namespace FederationAdGuard\Objects;

    class FilterList
    {
        private int $id;
        private string $name;
        /** @var int[] */
        private array $syntaxIds;
        /** @var int[] */
        private array $languageIds;
        /** @var int[] */
        private array $tagIds;
        /** @var array<int, array{segment: int, primariness: int, url: string}> */
        private array $viewUrls;

        /**
         * FilterList constructor
         *
         * @param array $data The list as returned by the API
         */
        public function __construct(array $data)
        {
            $this->id = (int)($data['id'] ?? 0);
            $this->name = trim((string)($data['name'] ?? ''));
            $this->syntaxIds = self::parseIds($data['syntaxIds'] ?? []);
            $this->languageIds = self::parseIds($data['languageIds'] ?? []);
            $this->tagIds = self::parseIds($data['tagIds'] ?? []);

            $this->viewUrls = [];
            foreach(is_array($data['viewUrls'] ?? null) ? $data['viewUrls'] : [] as $viewUrl)
            {
                if(!is_array($viewUrl) || !isset($viewUrl['url']) || !is_string($viewUrl['url']))
                {
                    continue;
                }

                $this->viewUrls[] = [
                    'segment' => (int)($viewUrl['segmentNumber'] ?? 1),
                    'primariness' => (int)($viewUrl['primariness'] ?? 1),
                    'url' => $viewUrl['url'],
                ];
            }
        }

        /**
         * @return int The ID of the list
         */
        public function getId(): int
        {
            return $this->id;
        }

        /**
         * @return string The name of the list
         */
        public function getName(): string
        {
            return $this->name;
        }

        /**
         * @return int[] The syntaxes of the list
         */
        public function getSyntaxIds(): array
        {
            return $this->syntaxIds;
        }

        /**
         * @return int[] The languages of the list
         */
        public function getLanguageIds(): array
        {
            return $this->languageIds;
        }

        /**
         * @return int[] The tags of the list
         */
        public function getTagIds(): array
        {
            return $this->tagIds;
        }

        /**
         * Returns the URLs of the list's segments, a list may be split into segments and each segment may have mirrors
         * (only returned by GET /lists/{id})
         *
         * @return array<int, string[]> The URLs of each segment, by segment number, the most primary URL first
         */
        public function getSegments(): array
        {
            $segments = [];
            $viewUrls = $this->viewUrls;
            usort($viewUrls, fn(array $a, array $b) => [$a['segment'], $a['primariness']] <=> [$b['segment'], $b['primariness']]);
            foreach($viewUrls as $viewUrl)
            {
                $segments[$viewUrl['segment']][] = $viewUrl['url'];
            }

            ksort($segments);
            return $segments;
        }

        /**
         * Parses a list of IDs
         *
         * @param mixed $value The value
         * @return int[] The IDs
         */
        private static function parseIds(mixed $value): array
        {
            return is_array($value) ? array_values(array_map('intval', array_filter($value, 'is_numeric'))) : [];
        }
    }
