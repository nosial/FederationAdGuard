<?php

    /** @noinspection PhpUnhandledExceptionInspection */

    namespace FederationAdGuard\Tests;

    use FederationAdGuard\Classes\PluginOperator;
    use FederationAdGuard\FederationAdGuard;
    use FederationAdGuard\Handlers\ContentScanHandler;
    use FederationAdGuard\Interfaces\RuleSourceInterface;
    use FederationAdGuard\Tests\Helpers\PluginConfiguration;
    use FederationAdGuard\Tests\Helpers\TestRules;
    use FederationLib\Enums\ContentType;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Exceptions\DatabaseOperationException;
    use FederationLib\Objects\BlacklistRecord;
    use FederationLib\Objects\ContentInput;
    use FederationLib\Objects\EntityRecord;
    use FederationLib\Objects\Plugin\ContentScan;
    use FederationLib\Objects\ScannedContent\Detection;
    use FederationLib\Objects\ScannedContent\ResolvedEntity;
    use PHPUnit\Framework\TestCase;

    /**
     * Calls the CONTENT_SCAN handler directly with rules kept in memory, nothing is recorded (building the database is
     * off in the unit tests, there is no database)
     */
    class ContentScanHandlerTest extends TestCase
    {
        private const array CONCERNS = [IncidentType::ADVERTISING, IncidentType::TRACKING];

        protected function setUp(): void
        {
            PluginConfiguration::reset();
            PluginOperator::setActive(true);
            FederationAdGuard::setRuleSource(TestRules::source([
                1 => ["||ads.example.com^\n||banner.example.com^\n||cdn.example.org/ads/*\n||thirdparty.example^\$third-party\n||ipv6only.example^\$dnstype=AAAA", IncidentType::ADVERTISING],
                2 => ['||tracker.example^', IncidentType::TRACKING],
            ]));
        }

        protected function tearDown(): void
        {
            FederationAdGuard::setRuleSource(null);
            PluginOperator::setActive(null);
            PluginConfiguration::reset();
        }

        private static function scan(array $evidence, array $concerns=self::CONCERNS, array $resolvedEntities=[]): ContentScan
        {
            $contentScan = new ContentScan($evidence, null, null, $resolvedEntities, concerns: $concerns);
            ContentScanHandler::handleContentScan($contentScan);
            return $contentScan;
        }

        private static function detections(ContentScan $contentScan): array
        {
            return array_map(fn(Detection $detection) => [$detection->getConcern(), $detection->getContentIndex(), $detection->getConfidence(), $detection->isVerified()], $contentScan->getDetections());
        }

        private static function entity(string $host, bool $whitelisted=false): EntityRecord
        {
            return new EntityRecord(['uuid' => '01900000-0000-7000-8000-' . substr(hash('sha256', $host), 0, 12), 'hash' => hash('sha256', $host), 'host' => $host, 'id' => null,
                'reputation' => 0, 'whitelisted' => $whitelisted, 'created' => time()]);
        }

        private static function blacklist(EntityRecord $entity, IncidentType $type, ?int $expires=null): BlacklistRecord
        {
            return new BlacklistRecord(['uuid' => '01900000-0000-7000-9000-000000000001', 'entity' => $entity->getUuid(), 'operator' => '01900000-0000-7000-9000-000000000002',
                'type' => $type->value, 'expires' => $expires, 'lifted' => false, 'created' => time()]);
        }

        public function testHostnames(): void
        {
            $contentScan = self::scan([
                new ContentInput('x.ads.example.com', contentType: ContentType::HOSTNAME),
                new ContentInput('pixel.tracker.example', contentType: ContentType::HOSTNAME),
                new ContentInput('example.net', contentType: ContentType::HOSTNAME),
            ]);

            $this->assertSame([
                [IncidentType::ADVERTISING, 0, 1.0, true],
                [IncidentType::TRACKING, 1, 1.0, true],
            ], self::detections($contentScan));
            // Something is listed, the unlisted example.net doesn't lower the risk
            $this->assertSame(['ADGUARD_ADVERTISING' => -15.0, 'ADGUARD_TRACKING' => -15.0], $contentScan->getScanResults());
        }

        public function testPartialRulesOnlyCountForUrls(): void
        {
            $contentScan = self::scan([
                new ContentInput('https://cdn.example.org/ads/banner.gif', contentType: ContentType::URL),
                new ContentInput('https://cdn.thirdparty.example/script.js', contentType: ContentType::URL),
            ]);

            $this->assertSame([
                [IncidentType::ADVERTISING, 0, 1.0, true],
                // A rule restricted to some requests detects with a lower confidence, and scores half
                [IncidentType::ADVERTISING, 1, 0.5, true],
            ], self::detections($contentScan));
            $this->assertSame(['ADGUARD_ADVERTISING' => -22.5], $contentScan->getScanResults());

            // A hostname can't be checked against such a rule, as DNS blockers do, nothing is said about it at all
            $contentScan = self::scan([new ContentInput('cdn.thirdparty.example', contentType: ContentType::HOSTNAME)]);
            $this->assertSame([], $contentScan->getDetections());
            $this->assertSame([], $contentScan->getScanResults());
        }

        public function testClientAssertionsAreNotVerified(): void
        {
            $contentScan = self::scan([
                // The page is what the client says it visited
                new ContentInput('Some page', contentType: ContentType::WEB_PAGE, context: ['url' => 'https://www.tracker.example/page']),
                // Only the client knows the record type of a lookup
                new ContentInput('ipv6only.example', contentType: ContentType::HOSTNAME, context: ['query_type' => 'AAAA']),
            ]);

            $this->assertSame([
                [IncidentType::TRACKING, 0, 1.0, false],
                [IncidentType::ADVERTISING, 1, 1.0, false],
            ], self::detections($contentScan));
        }

        public function testOnlyTheConcernsOfTheRequest(): void
        {
            $contentScan = self::scan([new ContentInput('ads.example.com', contentType: ContentType::HOSTNAME)], [IncidentType::SPAM]);

            // The detection is discarded by FederationLib, and no points are added
            $this->assertSame([], $contentScan->getDetections());
            $this->assertSame([], $contentScan->getScanResults());
        }

        public function testResolvedEntities(): void
        {
            $entity = self::entity('ads.example.com');
            $contentScan = self::scan([new ContentInput('ads.example.com', contentType: ContentType::HOSTNAME)], resolvedEntities: [new ResolvedEntity($entity)]);
            $this->assertSame($entity->getUuid(), $contentScan->getDetections()[0]->getEntity());

            // The registrable domain FederationLib resolved for a subdomain without an entity of its own
            $contentScan = self::scan([new ContentInput('x.ads.example.com', contentType: ContentType::HOSTNAME)], resolvedEntities: [new ResolvedEntity(self::entity('example.com'))]);
            $this->assertSame(self::entity('example.com')->getUuid(), $contentScan->getDetections()[0]->getEntity());

            // A whitelisted entity is never detected, FederationLib already lowers its risk
            $contentScan = self::scan([new ContentInput('ads.example.com', contentType: ContentType::HOSTNAME)], resolvedEntities: [new ResolvedEntity(self::entity('ads.example.com', true))]);
            $this->assertSame([], $contentScan->getDetections());
            $this->assertSame([], $contentScan->getScanResults());
        }

        public function testRecordedHostsScoreTheSame(): void
        {
            // FederationLib adds NAMED_ENTITY_PERMANENTLY_BLACKLISTED (-13) for the host's blacklist record, the plugin
            // tops it up to its own points, so the host scores -15 before and after it was recorded
            $entity = self::entity('ads.example.com');
            $resolved = new ResolvedEntity($entity, [self::blacklist($entity, IncidentType::ADVERTISING)]);
            $contentScan = self::scan([new ContentInput('ads.example.com', contentType: ContentType::HOSTNAME)], resolvedEntities: [$resolved]);
            $this->assertCount(1, $contentScan->getDetections());
            $this->assertEqualsWithDelta(-2.0, $contentScan->getScanResults()['ADGUARD_ADVERTISING'], 0.0001);

            // A link FederationLib already scores more for gets nothing on top
            $contentScan = self::scan([new ContentInput('See ads.example.com', contentType: ContentType::TEXT)], resolvedEntities: [$resolved]);
            $this->assertCount(1, $contentScan->getDetections());
            $this->assertArrayNotHasKey('ADGUARD_ADVERTISING', $contentScan->getScanResults());

            // A blacklist record of a concern that isn't requested isn't scored by FederationLib either
            $resolved = new ResolvedEntity($entity, [self::blacklist($entity, IncidentType::MALWARE)]);
            $contentScan = self::scan([new ContentInput('ads.example.com', contentType: ContentType::HOSTNAME)], resolvedEntities: [$resolved]);
            $this->assertSame(['ADGUARD_ADVERTISING' => -15.0], $contentScan->getScanResults());
        }

        public function testUnlistedHostsLowerTheRisk(): void
        {
            $contentScan = self::scan([new ContentInput('example.net', contentType: ContentType::HOSTNAME)]);
            $this->assertSame([], $contentScan->getDetections());
            $this->assertSame(['ADGUARD_UNLISTED' => 2.0], $contentScan->getScanResults());

            // A message whose links are all unlisted, a third of it
            $contentScan = self::scan([new ContentInput('Have a look at https://example.net/page', contentType: ContentType::TEXT)]);
            $this->assertEqualsWithDelta(2 / 3, $contentScan->getScanResults()['ADGUARD_UNLISTED'], 0.0001);
        }

        public function testNothingToCheckAddsNothing(): void
        {
            // A text without links, there is nothing for the lists to say
            $this->assertSame([], self::scan([new ContentInput('Hello, how are you?', contentType: ContentType::TEXT)])->getScanResults());

            // The page a client says it visited is never verified
            $this->assertSame([], self::scan([new ContentInput('Some page', contentType: ContentType::WEB_PAGE, context: ['url' => 'https://example.net/'])])->getScanResults());

            // There are no rules for the requested concern, nothing can be said about it
            $this->assertSame([], self::scan([new ContentInput('example.net', contentType: ContentType::HOSTNAME)], [IncidentType::SPAM])->getScanResults());

            // Before any rule is loaded (e.g., a fresh installation)
            FederationAdGuard::setRuleSource(TestRules::source([]));
            $this->assertSame([], self::scan([new ContentInput('example.net', contentType: ContentType::HOSTNAME)])->getScanResults());

            PluginConfiguration::apply(['scanning_unlisted_points' => '0']);
            FederationAdGuard::setRuleSource(TestRules::source([1 => ['||ads.example.com^', IncidentType::ADVERTISING]]));
            $this->assertSame([], self::scan([new ContentInput('example.net', contentType: ContentType::HOSTNAME)])->getScanResults());
        }

        public function testMessagesOfListedLinksAreSpam(): void
        {
            // Two distinct listed hosts and nothing else, the message is spam whatever ads and trackers the request asks about
            $contentScan = self::scan([new ContentInput('Deals! https://ads.example.com/a https://banner.example.com/b', contentType: ContentType::TEXT)], [IncidentType::SPAM]);
            $this->assertSame(['ADGUARD_LINK_SPAM' => -10.0], $contentScan->getScanResults());

            $contentScan = self::scan([new ContentInput('Deals! https://ads.example.com/a https://banner.example.com/b', contentType: ContentType::TEXT)], [IncidentType::SPAM, IncidentType::ADVERTISING]);
            $this->assertSame(['ADGUARD_ADVERTISING' => -5.0, 'ADGUARD_LINK_SPAM' => -10.0], $contentScan->getScanResults());

            // The same link twice is one listed host, sharing one ad isn't spam
            $this->assertSame([], self::scan([new ContentInput('https://ads.example.com/a https://ads.example.com/b', contentType: ContentType::TEXT)], [IncidentType::SPAM])->getScanResults());

            // Two listed hosts among an ordinary one is less than 80%
            $this->assertSame([], self::scan([new ContentInput('https://ads.example.com/a https://banner.example.com/b https://example.net/', contentType: ContentType::TEXT)], [IncidentType::SPAM])->getScanResults());

            // Only messages have an author whose spam it is
            $this->assertSame([], self::scan([new ContentInput('Page https://ads.example.com/a https://banner.example.com/b', contentType: ContentType::WEB_PAGE)], [IncidentType::SPAM])->getScanResults());
        }

        public function testDisabled(): void
        {
            // The hard switch
            PluginConfiguration::apply(['enabled' => 'false']);
            $contentScan = self::scan([new ContentInput('ads.example.com', contentType: ContentType::HOSTNAME)]);
            $this->assertSame([], $contentScan->getDetections());
            $this->assertSame([], $contentScan->getScanResults());

            // The soft switch, the FederationAdGuard operator is disabled
            PluginConfiguration::reset();
            PluginOperator::setActive(false);
            $contentScan = self::scan([new ContentInput('ads.example.com', contentType: ContentType::HOSTNAME)]);
            $this->assertSame([], $contentScan->getDetections());
            $this->assertSame([], $contentScan->getScanResults());
        }

        public function testFailuresNeverFailTheScan(): void
        {
            $source = $this->createMock(RuleSourceInterface::class);
            $source->method('getRulesByHosts')->willThrowException(new DatabaseOperationException('The database is unavailable'));
            FederationAdGuard::setRuleSource($source);

            $contentScan = self::scan([new ContentInput('ads.example.com', contentType: ContentType::HOSTNAME)]);
            $this->assertSame([], $contentScan->getDetections());
            $this->assertSame([], $contentScan->getScanResults());
        }
    }
