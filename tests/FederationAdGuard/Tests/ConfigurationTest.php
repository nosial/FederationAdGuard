<?php

    namespace FederationAdGuard\Tests;

    use FederationAdGuard\Classes\Configuration;
    use FederationAdGuard\Classes\Configuration\DatabaseConfiguration;
    use FederationAdGuard\Classes\Configuration\FilterListsConfiguration;
    use FederationAdGuard\Classes\Configuration\ListsConfiguration;
    use FederationAdGuard\Classes\Configuration\ScanningConfiguration;
    use FederationAdGuard\Enums\ListSource;
    use FederationAdGuard\Tests\Helpers\PluginConfiguration;
    use FederationLib\Enums\IncidentType;
    use PHPUnit\Framework\TestCase;

    class ConfigurationTest extends TestCase
    {
        protected function tearDown(): void
        {
            PluginConfiguration::reset();
        }

        public function testDefaults(): void
        {
            // The defaults of each section, the unit tests' own configuration aside
            $filterLists = new FilterListsConfiguration([]);
            $this->assertTrue($filterLists->isEnabled());
            $this->assertSame([IncidentType::ADVERTISING, IncidentType::TRACKING], $filterLists->getConcerns());
            $this->assertSame(['en'], $filterLists->getLanguages());
            $this->assertSame(4, $filterLists->getMax());
            $this->assertSame([], $filterLists->getExclude());
            $this->assertSame([301, 242, 2214, 157], $filterLists->getPreferred());
            $this->assertSame('https://api.filterlists.com', $filterLists->getEndpoint());

            $lists = new ListsConfiguration([]);
            $this->assertSame([], $lists->getSubscriptions());
            $this->assertSame([], $lists->getRules());
            $this->assertSame(86400, $lists->getUpdateInterval());
            $this->assertFalse($lists->isPrivateAllowed());

            $scanning = new ScanningConfiguration([]);
            $this->assertSame(-15.0, $scanning->getPoints());
            $this->assertSame(-5.0, $scanning->getLinkPoints());
            $this->assertSame(2.0, $scanning->getUnlistedPoints());
            $this->assertSame(-10.0, $scanning->getSpamPoints());

            $database = new DatabaseConfiguration([]);
            $this->assertTrue($database->isEnabled());
            $this->assertSame(86400, $database->getAuthorBlacklist());

            PluginConfiguration::reset();
            $this->assertTrue(Configuration::isEnabled());
        }

        public function testInvalidValuesFallBack(): void
        {
            PluginConfiguration::apply([
                'filterlists_endpoint' => 'not a url',
                'filterlists_concerns' => 'advertising, x, SPAM, malware',
                'filterlists_languages' => 'de, german, FR',
                'filterlists_exclude' => '1, x, -3, 2',
                'filterlists_preferred' => '242, EasyList, 0, 301',
                'filterlists_max' => '-1',
                'update_interval' => '5m',
                'scanning_points' => 'many',
                // A listing never lowers the risk score, an unlisted host never raises it
                'scanning_link_points' => '5',
                'scanning_unlisted_points' => '-2',
                'database_author_blacklist' => '10s',
            ]);

            $this->assertSame(FilterListsConfiguration::DEFAULT_ENDPOINT, Configuration::getFilterListsConfiguration()->getEndpoint());
            $this->assertSame([IncidentType::ADVERTISING, IncidentType::SPAM, IncidentType::MALWARE], Configuration::getFilterListsConfiguration()->getConcerns());
            $this->assertSame(['de', 'fr'], Configuration::getFilterListsConfiguration()->getLanguages());
            $this->assertSame([1, 2], Configuration::getFilterListsConfiguration()->getExclude());
            // The order is kept, it is the order the lists are discovered in
            $this->assertSame([242, 301], Configuration::getFilterListsConfiguration()->getPreferred());
            $this->assertSame(0, Configuration::getFilterListsConfiguration()->getMax());
            // A list is never downloaded more than once an hour
            $this->assertSame(3600, Configuration::getListsConfiguration()->getUpdateInterval());
            $this->assertSame(-15.0, Configuration::getScanningConfiguration()->getPoints());
            $this->assertSame(0.0, Configuration::getScanningConfiguration()->getLinkPoints());
            $this->assertSame(0.0, Configuration::getScanningConfiguration()->getUnlistedPoints());
            $this->assertSame(60, (new DatabaseConfiguration(['author_blacklist' => '10s']))->getAuthorBlacklist());
        }

        public function testAuthorBlacklist(): void
        {
            // An author is only ever blacklisted temporarily, or not at all
            $this->assertNull((new DatabaseConfiguration(['author_blacklist' => 'off']))->getAuthorBlacklist());
            $this->assertNull((new DatabaseConfiguration(['author_blacklist' => '0']))->getAuthorBlacklist());
            $this->assertSame(43200, (new DatabaseConfiguration(['author_blacklist' => '12h']))->getAuthorBlacklist());
            // Nothing is recorded while building the database is disabled
            $this->assertNull((new DatabaseConfiguration(['enabled' => 'false', 'author_blacklist' => '1d']))->getAuthorBlacklist());
        }

        public function testLists(): void
        {
            PluginConfiguration::apply([
                'lists' => "301;concern=TRACKING, https://lists.example.com/ads.txt;name=Example Ads;allowlist=true\n/opt/filters/malware.txt;concern=malware",
            ]);

            [$filterList, $url, $file] = Configuration::getListsConfiguration()->getSubscriptions();
            $this->assertTrue(Configuration::getListsConfiguration()->isComplete());
            $this->assertSame(ListSource::FILTERLISTS, $filterList->getSource());
            $this->assertSame(301, $filterList->getFilterListsId());
            $this->assertSame(IncidentType::TRACKING, $filterList->getConcern());
            $this->assertSame('FilterLists list 301', $filterList->getName());

            $this->assertSame(ListSource::URL, $url->getSource());
            $this->assertSame('https://lists.example.com/ads.txt', $url->getLocation());
            $this->assertSame('Example Ads', $url->getName());
            $this->assertTrue($url->isAllowlist());
            // The concern of a list without one follows its FilterLists tags, ADVERTISING for other lists
            $this->assertNull($url->getConcern());

            $this->assertSame(ListSource::FILE, $file->getSource());
            $this->assertSame('/opt/filters/malware.txt', $file->getLocation());
            $this->assertSame('malware.txt', $file->getName());
            $this->assertSame(IncidentType::MALWARE, $file->getConcern());
        }

        public function testInvalidListsAreLeftOut(): void
        {
            PluginConfiguration::apply([
                // An unsupported scheme, an unknown concern, a removed option and a relative path
                'lists' => 'ftp://example.com/list.txt, 2;concern=nothing, 3;interval=12h, filters/ads.txt, 4',
            ]);

            $this->assertSame([4], array_map(fn($definition) => $definition->getFilterListsId(), Configuration::getListsConfiguration()->getSubscriptions()));
            // The previous subscriptions are kept while the configuration is invalid
            $this->assertFalse(Configuration::getListsConfiguration()->isComplete());
        }

        public function testInvalidShapesAreNotEmptyConfigurations(): void
        {
            foreach([false, 1.5] as $value)
            {
                $configuration = new ListsConfiguration(['lists' => $value, 'rules' => $value]);
                $this->assertFalse($configuration->isComplete());
                $complete = true;
                $configuration->getRules($complete);
                $this->assertFalse($complete);
            }
        }

        public function testRules(): void
        {
            PluginConfiguration::apply([
                'rules' => "||tracker.example.com^\n[MALWARE] ||malware.example.com^\n! A comment\n\n||tracker.example.com^\n[NOTHING] ||invalid.example.com^\n||ads.example.com^\$third-party,domain=example.org",
            ]);

            $complete = true;
            $rules = array_values(Configuration::getListsConfiguration()->getRules($complete));
            // Duplicates are declared once, and a line naming an unknown concern is left out
            $this->assertFalse($complete);
            $this->assertCount(3, $rules);
            $this->assertSame('||tracker.example.com^', $rules[0]->getRule());
            $this->assertSame(IncidentType::ADVERTISING, $rules[0]->getConcern());
            $this->assertSame('||malware.example.com^', $rules[1]->getRule());
            $this->assertSame(IncidentType::MALWARE, $rules[1]->getConcern());
            // Rules may contain commas, `rules` is only separated by lines
            $this->assertSame('||ads.example.com^$third-party,domain=example.org', $rules[2]->getRule());
        }
    }
