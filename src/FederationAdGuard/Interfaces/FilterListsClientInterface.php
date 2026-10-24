<?php

    namespace FederationAdGuard\Interfaces;

    use FederationAdGuard\Exceptions\FilterListsException;
    use FederationAdGuard\Objects\FilterList;

    interface FilterListsClientInterface
    {
        /**
         * Returns every list of the directory, without their URLs (GET /lists)
         *
         * @return FilterList[] The lists
         * @throws FilterListsException If the API could not be used
         */
        public function getLists(): array;

        /**
         * Returns a list with its URLs (GET /lists/{id})
         *
         * @param int $id The ID of the list
         * @return FilterList|null The list, null if it doesn't exist
         * @throws FilterListsException If the API could not be used
         */
        public function getList(int $id): ?FilterList;

        /**
         * Returns the tags lists are categorized with (GET /tags)
         *
         * @return array<int, array{id: int, name: string}> The tags by ID
         * @throws FilterListsException If the API could not be used
         */
        public function getTags(): array;

        /**
         * Returns the syntaxes lists are written in (GET /syntaxes)
         *
         * @return array<int, array{id: int, name: string}> The syntaxes by ID
         * @throws FilterListsException If the API could not be used
         */
        public function getSyntaxes(): array;

        /**
         * Returns the languages lists are written for (GET /languages)
         *
         * @return array<int, string> The ISO 639-1 codes of the languages by ID, e.g., [37 => 'en']
         * @throws FilterListsException If the API could not be used
         */
        public function getLanguages(): array;
    }
