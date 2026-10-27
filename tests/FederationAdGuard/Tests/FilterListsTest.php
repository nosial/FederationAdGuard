<?php

    /** @noinspection PhpUnhandledExceptionInspection */

    namespace FederationAdGuard\Tests;

    use FederationAdGuard\Classes\Configuration\FilterListsConfiguration;
    use FederationAdGuard\Classes\FilterListsClient;
    use FederationAdGuard\Classes\FilterParser;
    use FederationAdGuard\Classes\ListCatalog;
    use FederationAdGuard\Classes\ListDownloader;
    use FederationAdGuard\Classes\Matcher;
    use FederationAdGuard\Classes\MemoryRuleSource;
    use FederationAdGuard\Classes\Provisioner;
    use FederationAdGuard\Classes\Synchronizer;
    use FederationAdGuard\Enums\ListSource;
    use FederationAdGuard\Enums\ListSyntax;
    use FederationAdGuard\Exceptions\ListException;
    use FederationAdGuard\FederationAdGuard;
    use FederationAdGuard\Interfaces\ListDownloaderInterface;
    use FederationAdGuard\Objects\DownloadResult;
    use FederationAdGuard\Objects\FilterList;
    use FederationAdGuard\Objects\MatchTarget;
    use FederationAdGuard\Objects\SubscriptionDefinition;
    use FederationAdGuard\Tests\Helpers\PluginConfiguration;
    use FederationLib\Enums\IncidentType;
    use PHPUnit\Framework\Attributes\Group;
    use PHPUnit\Framework\TestCase;

    /**
     * The FilterLists feature against the real directory (https://api.filterlists.com) and the real lists. The lists
     * are identified by the IDs the directory gives them, the hosts are ones the lists are known to block.
     */
    #[Group('integration')]
    class FilterListsTest extends TestCase
    {
        private const string ENDPOINT = FilterListsConfiguration::DEFAULT_ENDPOINT;
        private const array CONCERNS = [IncidentType::ADVERTISING, IncidentType::TRACKING];

        private const int EASYLIST = 301;
        private const int EASYPRIVACY = 242;
        private const int ADGUARD_BASE = 2214;
        private const int ADGUARD_TRACKING = 157;
        private const int EASYLIST_GERMANY = 293;
        private const array PREFERRED = FilterListsConfiguration::DEFAULT_PREFERRED;

        /** @var string The directory's responses are cached here for the whole class, the directory is large */
        private static string $cachePath;
        /** @var string[] The URLs requested from the directory, rather than the cache */
        private array $requests = [];

        public static function setUpBeforeClass(): void
        {
            self::$cachePath = sys_get_temp_dir() . '/adguard-filterlists-' . bin2hex(random_bytes(8));
        }

        public static function tearDownAfterClass(): void
        {
            self::removeDirectory(self::$cachePath);
        }

        protected function setUp(): void
        {
            PluginConfiguration::apply(['filterlists_enabled' => 'true', 'filterlists_endpoint' => self::ENDPOINT]);
            FederationAdGuard::setFilterListsClient($this->client());
        }

        protected function tearDown(): void
        {
            FederationAdGuard::setFilterListsClient(null);
            PluginConfiguration::reset();
        }

        private static function removeDirectory(string $path): void
        {
            foreach(glob($path . '/*') ?: [] as $file)
            {
                unlink($file);
            }

            if(is_dir($path))
            {
                rmdir($path);
            }
        }

        private function client(?string $cachePath=null): FilterListsClient
        {
            $requests = &$this->requests;
            $downloader = new class($requests) implements ListDownloaderInterface
            {
                private array $requests;
                private ListDownloader $downloader;

                public function __construct(array &$requests)
                {
                    $this->requests = &$requests;
                    $this->downloader = new ListDownloader();
                }

                public function download(string $url, array $validators=[], string $accept='text/plain, */*'): DownloadResult
                {
                    $this->requests[] = $url;
                    return $this->downloader->download($url, $validators, $accept);
                }
            };

            return new FilterListsClient(self::ENDPOINT, $downloader, $cachePath ?? self::$cachePath);
        }

        private static function ids(array $definitions): array
        {
            return array_values(array_map(fn(SubscriptionDefinition $definition) => $definition->getFilterListsId(), $definitions));
        }

        /**
         * Downloads a list from its primary URL and returns its rules
         */
        private function rules(FilterList $list, FilterListsClient $client): MemoryRuleSource
        {
            $concern = Synchronizer::getConcernFromTags($list->getTagIds(), $client->getTags());
            $syntax = ListSyntax::fromFilterListsSyntaxes($list->getSyntaxIds(), $client->getSyntaxes());
            $this->assertNotNull($syntax, sprintf('%s is in a syntax the parser does not support', $list->getName()));

            $rules = [];
            foreach($list->getSegments() as $urls)
            {
                $contents = (new ListDownloader())->download($urls[0])->getContents();
                $rules = array_merge($rules, FilterParser::parse($contents, $syntax)->getRules());
            }

            return new MemoryRuleSource(array_map(fn($rule) => $rule->withSubscription($list->getId(), $concern), $rules));
        }

        /**
         * Checks if a rule of the list blocks the host entirely, the rules a hostname is detected and blacklisted by
         */
        private static function blocksHost(MemoryRuleSource $source, string $host): bool
        {
            return Matcher::match(MatchTarget::fromHost($host), $source)->getHostBlocks() !== [];
        }

        public function testDefaultsDiscoverTheBestListsForAdsAndTrackers(): void
        {
            // The plugin's default configuration selects EasyList, EasyPrivacy and AdGuard's base and tracking filters
            $configuration = new FilterListsConfiguration([]);
            $definitions = ListCatalog::discover($this->client(), $configuration->getConcerns(), $configuration->getLanguages(), $configuration->getExclude(), $configuration->getMax(), $configuration->getPreferred());
            $this->assertSame([self::EASYLIST, self::EASYPRIVACY, self::ADGUARD_BASE, self::ADGUARD_TRACKING], self::ids($definitions));
            foreach($definitions as $definition)
            {
                $this->assertSame(ListSource::FILTERLISTS, $definition->getSource());
                // The concern of a discovered list follows its tags
                $this->assertNull($definition->getConcern());
            }

            // Each preferred list is still the list it was chosen as
            $client = $this->client();
            $names = [
                self::EASYLIST => 'EasyList', self::EASYPRIVACY => 'EasyPrivacy',
                self::ADGUARD_BASE => 'AdGuard Base Filter without EasyList (uBlock Origin)',
                self::ADGUARD_TRACKING => 'AdGuard Tracking Protection Filter (AdGuard for Chromium)',
            ];
            foreach(self::PREFERRED as $id)
            {
                $this->assertSame($names[$id], $client->getList($id)?->getName(), sprintf('The preferred list %d changed in the directory', $id));
            }

            // Without preferences the other qualifying lists are discovered by syntax and name alone
            $this->assertNotSame(self::ids($definitions), self::ids(ListCatalog::discover($client, self::CONCERNS, ['en'], [], 4)));
            // The preferred order is the operator's
            $this->assertSame([self::ADGUARD_TRACKING, self::EASYLIST], self::ids(ListCatalog::discover($client, self::CONCERNS, ['en'], [], 2, [self::ADGUARD_TRACKING, self::EASYLIST])));
        }

        public function testDiscoveredListsAreEligible(): void
        {
            $client = $this->client();
            $tags = $client->getTags();
            $languages = $client->getLanguages();
            $syntaxes = $client->getSyntaxes();
            $lists = [];
            foreach($client->getLists() as $list)
            {
                $lists[$list->getId()] = $list;
            }

            foreach([[self::CONCERNS, ['en']], [[IncidentType::MALWARE], ['en']], [self::CONCERNS, ['de']]] as [$concerns, $wanted])
            {
                $ids = self::ids(ListCatalog::discover($client, $concerns, $wanted, [], 50));
                $this->assertNotEmpty($ids);
                foreach($ids as $id)
                {
                    $list = $lists[$id];
                    $this->assertContains(Synchronizer::getConcernFromTags($list->getTagIds(), $tags), $concerns, $list->getName());
                    $listTags = array_map(fn(int $tag) => strtolower($tags[$tag]['name']), $list->getTagIds());
                    $this->assertSame([], array_intersect(FilterListsConfiguration::EXCLUDED_TAGS, $listTags), $list->getName());
                    $this->assertNotNull(ListSyntax::fromFilterListsSyntaxes($list->getSyntaxIds(), $syntaxes), $list->getName());
                    $this->assertFalse(ListSyntax::isAllowlistSyntax($list->getSyntaxIds(), $syntaxes), $list->getName());
                    $listLanguages = array_map(fn(int $language) => $languages[$language], $list->getLanguageIds());
                    $this->assertTrue($listLanguages === [] || array_intersect($wanted, $listLanguages) !== [], $list->getName());
                }
            }

            // A list in another language is only discovered for that language
            $this->assertNotContains(self::EASYLIST_GERMANY, self::ids(ListCatalog::discover($client, self::CONCERNS, ['en'], [], 500)));
            $this->assertContains(self::EASYLIST_GERMANY, self::ids(ListCatalog::discover($client, self::CONCERNS, ['de'], [], 500)));
            $this->assertNotContains(self::EASYLIST, self::ids(ListCatalog::discover($client, [IncidentType::MALWARE], ['en'], [], 50)));
        }

        public function testExclusionsAndLimits(): void
        {
            $this->assertSame([self::EASYLIST], self::ids(ListCatalog::discover($this->client(), self::CONCERNS, ['en'], [], 1, self::PREFERRED)));
            $this->assertSame([self::EASYPRIVACY], self::ids(ListCatalog::discover($this->client(), self::CONCERNS, ['en'], [self::EASYLIST], 1, self::PREFERRED)));
            $this->assertSame([self::EASYPRIVACY, self::ADGUARD_TRACKING], self::ids(ListCatalog::discover($this->client(), [IncidentType::TRACKING], ['en'], [], 2, self::PREFERRED)));
            $this->assertSame([], ListCatalog::discover($this->client(), [], ['en'], [], 10));
            $this->assertSame([], ListCatalog::discover($this->client(), self::CONCERNS, ['en'], [], 0));
        }

        public function testDeclaredSubscriptions(): void
        {
            PluginConfiguration::apply(['filterlists_enabled' => 'true', 'filterlists_endpoint' => self::ENDPOINT, 'filterlists_max' => '2', 'lists' => (string)self::EASYLIST_GERMANY]);
            $complete = true;
            $declared = Provisioner::getDeclaredSubscriptions($complete);
            $this->assertTrue($complete);
            // The discovered lists and the explicit FilterLists ID
            $this->assertSame([self::EASYLIST, self::EASYPRIVACY, self::EASYLIST_GERMANY], self::ids($declared));

            // filterlists.max 0 only subscribes to the explicit IDs
            PluginConfiguration::apply(['filterlists_enabled' => 'true', 'filterlists_endpoint' => self::ENDPOINT, 'filterlists_max' => '0', 'lists' => (string)self::EASYLIST_GERMANY]);
            $this->assertSame([self::EASYLIST_GERMANY], self::ids(Provisioner::getDeclaredSubscriptions($complete)));
        }

        public function testListsAndTheirRules(): void
        {
            $client = $this->client();
            $easyList = $client->getList(self::EASYLIST);
            $this->assertSame('EasyList', $easyList->getName());
            $this->assertContains('https://easylist.to/easylist/easylist.txt', $easyList->getSegments()[1]);
            $this->assertSame(IncidentType::ADVERTISING, Synchronizer::getConcernFromTags($easyList->getTagIds(), $client->getTags()));
            $this->assertSame(IncidentType::TRACKING, Synchronizer::getConcernFromTags($client->getList(self::EASYPRIVACY)->getTagIds(), $client->getTags()));
            $this->assertNull($client->getList(999999999));

            $source = $this->rules($easyList, $client);
            foreach(['ad.doubleclick.net', 'pagead2.googlesyndication.com', 'adnxs.com'] as $host)
            {
                $this->assertTrue(self::blocksHost($source, $host), sprintf('EasyList does not block %s', $host));
            }
            foreach(['example.com', 'wikipedia.org'] as $host)
            {
                $this->assertFalse(Matcher::match(MatchTarget::fromHost($host), $source)->isBlocked(), sprintf('EasyList blocks %s', $host));
            }
        }

        public function testEveryDefaultListIsUsable(): void
        {
            $client = $this->client();
            $known = [
                self::EASYPRIVACY => ['mc.yandex.ru', 'bat.bing.com'],
                self::ADGUARD_BASE => ['syndication.exoclick.com', 'fastlane.rubiconproject.com'],
                self::ADGUARD_TRACKING => ['google-analytics.com', 'mc.appmetrica.yandex.net'],
            ];

            foreach($known as $id => $hosts)
            {
                $list = $client->getList($id);
                $source = $this->rules($list, $client);
                foreach($hosts as $host)
                {
                    $this->assertTrue(self::blocksHost($source, $host), sprintf('%s does not block %s', $list->getName(), $host));
                }
                $this->assertFalse(Matcher::match(MatchTarget::fromHost('wikipedia.org'), $source)->isBlocked(), sprintf('%s blocks wikipedia.org', $list->getName()));
            }
        }

        public function testResponsesAreCached(): void
        {
            $cachePath = sys_get_temp_dir() . '/adguard-filterlists-' . bin2hex(random_bytes(8));
            try
            {
                $this->client($cachePath)->getLists();
                $this->assertSame([self::ENDPOINT . '/lists'], $this->requests);
                // A new client reuses the responses cached on disk
                $this->client($cachePath)->getLists();
                $this->assertCount(1, $this->requests);
            }
            finally
            {
                self::removeDirectory($cachePath);
            }
        }

        public function testDisabledDirectoryIsNeverContacted(): void
        {
            PluginConfiguration::apply(['filterlists_enabled' => 'false', 'filterlists_endpoint' => self::ENDPOINT, 'lists' => '301,https://example.com/rules.txt']);

            // Your own lists keep working, the FilterLists IDs are left out without making the configuration invalid
            $complete = true;
            $declared = array_values(Provisioner::getDeclaredSubscriptions($complete));
            $this->assertTrue($complete);
            $this->assertCount(1, $declared);
            $this->assertSame(ListSource::URL, $declared[0]->getSource());
            $this->assertSame('https://example.com/rules.txt', $declared[0]->getLocation());

            try
            {
                $this->client()->getLists();
                $this->fail('The directory must not be used while the feature is disabled');
            }
            catch(ListException)
            {
                $this->assertSame([], $this->requests);
            }
        }
    }
