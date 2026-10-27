<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Classes\Configuration\FilterListsConfiguration;
    use FederationAdGuard\Exceptions\ListException;
    use FederationAdGuard\Interfaces\FilterListsClientInterface;
    use FederationAdGuard\Interfaces\ListDownloaderInterface;
    use FederationAdGuard\Objects\FilterList;

    class FilterListsClient implements FilterListsClientInterface
    {
        private string $endpoint;
        private ListDownloaderInterface $downloader;

        /**
         * FilterListsClient constructor
         *
         * @param string|null $endpoint The endpoint of the API, defaults to the plugin's configuration
         * @param ListDownloaderInterface|null $downloader The downloader the API is requested with
         * @param string|null $cachePath The directory the responses are cached in, defaults to the plugin's
         */
        public function __construct(?string $endpoint=null, ?ListDownloaderInterface $downloader=null, ?string $cachePath=null)
        {
            $this->endpoint = rtrim($endpoint ?? Configuration::getFilterListsConfiguration()->getEndpoint(), '/');
            $this->downloader = new CachedDownloader($downloader ?? new ListDownloader(), $cachePath ?? FilterListsConfiguration::getCachePath(),
                FilterListsConfiguration::CACHE_TTL, FilterListsConfiguration::RETRY_INTERVAL);
        }

        /**
         * @inheritDoc
         */
        public function getLists(): array
        {
            $lists = [];
            foreach($this->request('/lists') as $data)
            {
                if(is_array($data) && isset($data['id']))
                {
                    $lists[] = new FilterList($data);
                }
            }

            return $lists;
        }

        /**
         * @inheritDoc
         */
        public function getList(int $id): ?FilterList
        {
            try
            {
                $data = $this->request('/lists/' . $id);
            }
            catch(ListException $e)
            {
                if($e->getCode() === 404)
                {
                    return null;
                }

                throw $e;
            }

            return isset($data['id']) ? new FilterList($data) : null;
        }

        /**
         * @inheritDoc
         */
        public function getTags(): array
        {
            return $this->getNamedItems('/tags');
        }

        /**
         * @inheritDoc
         */
        public function getLanguages(): array
        {
            $languages = [];
            foreach($this->request('/languages') as $language)
            {
                if(is_array($language) && isset($language['id'], $language['iso6391']) && is_string($language['iso6391']))
                {
                    $languages[(int)$language['id']] = strtolower($language['iso6391']);
                }
            }

            return $languages;
        }

        /**
         * @inheritDoc
         */
        public function getSyntaxes(): array
        {
            return $this->getNamedItems('/syntaxes');
        }

        /**
         * Returns the items of an endpoint that lists named items (tags, syntaxes), by ID
         *
         * @param string $path The path
         * @return array<int, array{id: int, name: string}> The items
         * @throws ListException If the API could not be used
         */
        private function getNamedItems(string $path): array
        {
            $items = [];
            foreach($this->request($path) as $item)
            {
                if(is_array($item) && isset($item['id'], $item['name']))
                {
                    $items[(int)$item['id']] = ['id' => (int)$item['id'], 'name' => (string)$item['name']];
                }
            }

            return $items;
        }

        /**
         * Requests an endpoint of the API
         *
         * @param string $path The path
         * @return array The decoded response
         * @throws ListException If the API could not be used, with the code 404 if the resource doesn't exist
         */
        private function request(string $path): array
        {
            if(!Configuration::getFilterListsConfiguration()->isEnabled())
            {
                throw new ListException('The FilterLists feature is disabled');
            }

            Logger::log()->debug(sprintf('Requesting %s from the FilterLists API (%s)', $path, $this->endpoint));
            try
            {
                $contents = $this->downloader->download($this->endpoint . $path, [], 'application/json')->getContents();
            }
            catch(ListException $e)
            {
                throw new ListException(sprintf('The FilterLists API could not be used: %s', $e->getMessage()), $e->getCode() === 404 ? 404 : 0, $e);
            }

            $data = json_decode((string)$contents, true);
            if(!is_array($data))
            {
                throw new ListException(sprintf('The FilterLists API responded to %s with something that is not JSON', $path));
            }

            return $data;
        }
    }
