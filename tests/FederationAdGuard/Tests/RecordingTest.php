<?php

    /** @noinspection PhpUnhandledExceptionInspection */

    namespace FederationAdGuard\Tests;

    use FederationAdGuard\Classes\AuthorRecorder;
    use FederationAdGuard\Classes\BlacklistRecorder;
    use FederationAdGuard\Classes\EntityVerifier;
    use FederationAdGuard\Classes\FindingRecorder;
    use FederationAdGuard\Classes\Managers\FindingManager;
    use FederationAdGuard\Classes\PluginOperator;
    use FederationAdGuard\Enums\FindingState;
    use FederationAdGuard\FederationAdGuard;
    use FederationAdGuard\Handlers\StartupHandler;
    use FederationAdGuard\Objects\MatchTarget;
    use FederationAdGuard\Tests\Helpers\IsolatedDatabase;
    use FederationAdGuard\Tests\Helpers\TestRules;
    use FederationLib\Classes\Managers\BlacklistManager;
    use FederationLib\Classes\Managers\EntitiesManager;
    use FederationLib\Classes\Managers\OperatorManager;
    use FederationLib\Enums\ContentType;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Objects\ContentInput;
    use FederationLib\Objects\EntityRecord;
    use FederationLib\Objects\OperatorRecord;
    use FederationLib\Objects\Plugin\ContentScan;
    use FederationLib\Objects\ScannedContent\ResolvedEntity;
    use PHPUnit\Framework\Attributes\Group;
    use PHPUnit\Framework\TestCase;

    /**
     * Building the database: the findings of listed hosts and the records of the authors of messages of listed links.
     * Uses a disposable database (see IsolatedDatabase).
     */
    #[Group('integration')]
    class RecordingTest extends TestCase
    {
        use IsolatedDatabase;

        protected function setUp(): void
        {
            $this->createDatabase();
            StartupHandler::handleStartup(new \FederationLib\Objects\Plugin\Startup(time(), true, null));
            FederationAdGuard::setRuleSource(TestRules::source([
                1 => ["||ads.example.com^\n||banner.example.com^", IncidentType::ADVERTISING],
                2 => ['||ads.example.com^', IncidentType::TRACKING],
            ]));
        }

        protected function tearDown(): void
        {
            $this->dropDatabase();
        }

        private static function record(string $host): array
        {
            return FindingRecorder::recordResult(FederationAdGuard::match(MatchTarget::fromHost($host)));
        }

        private function countRows(string $sql): int
        {
            return (int)$this->connection->query($sql)->fetchColumn();
        }

        public function testFindingsAreRecordedOnce(): void
        {
            // The listed host is recorded, for every concern a list blocks it entirely for
            $blacklists = self::record('x.ads.example.com');
            self::assertSame(['ads.example.com'], array_keys($blacklists));
            self::assertNotNull($blacklists['ads.example.com']['ADVERTISING']);
            self::assertNotNull($blacklists['ads.example.com']['TRACKING']);
            self::assertSame(2, $this->countRows('SELECT COUNT(*) FROM adguard_findings'));
            self::assertSame(2, $this->countRows("SELECT COUNT(*) FROM evidence WHERE tag = 'adguard_finding'"));
            self::assertSame(2, $this->countRows('SELECT COUNT(*) FROM blacklist'));

            // Finding the host again records nothing new
            self::assertSame($blacklists, self::record('ads.example.com'));
            self::assertSame(2, $this->countRows("SELECT COUNT(*) FROM evidence WHERE tag = 'adguard_finding'"));
            self::assertSame(2, $this->countRows('SELECT COUNT(*) FROM blacklist'));
        }

        public function testWhitelistedHostsAreNotRecorded(): void
        {
            $uuid = EntitiesManager::registerEntity('banner.example.com');
            EntitiesManager::setEntityWhitelist($uuid, true);
            self::assertSame(['banner.example.com' => []], self::record('banner.example.com'));
            self::assertSame(0, $this->countRows('SELECT COUNT(*) FROM blacklist'));
        }

        public function testRevalidationFollowsTheLists(): void
        {
            $blacklistUuid = self::record('banner.example.com')['banner.example.com']['ADVERTISING'];
            $entity = EntitiesManager::getEntity('banner.example.com');

            // The list no longer blocks the host, maintenance lifts the plugin's blacklist record
            FederationAdGuard::setRuleSource(TestRules::source([1 => ['||ads.example.com^', IncidentType::ADVERTISING]]));
            $stats = EntityVerifier::verifyFindings(100);
            self::assertSame(1, $stats['lifted']);
            self::assertTrue(BlacklistManager::getBlacklistEntry($blacklistUuid)->isLifted());
            self::assertSame(FindingState::LIFTED, FindingManager::getFinding($entity->getUuid(), IncidentType::ADVERTISING)->getState());

            // Listed again, it's blacklisted again
            FederationAdGuard::setRuleSource(TestRules::source([1 => ['||banner.example.com^', IncidentType::ADVERTISING]]));
            $again = self::record('banner.example.com')['banner.example.com']['ADVERTISING'];
            self::assertNotNull($again);
            self::assertNotSame($blacklistUuid, $again);
        }

        public function testOperatorDecisionsWin(): void
        {
            $blacklistUuid = self::record('banner.example.com')['banner.example.com']['ADVERTISING'];
            $operator = OperatorManager::createOperator('Human operator')->getUuid();

            // An operator lifts the plugin's record (RECORD_CHANGE BLACKLIST_LIFTED), it's never created again
            BlacklistManager::liftBlacklistRecord($blacklistUuid, $operator);
            $record = BlacklistManager::getBlacklistEntry($blacklistUuid);
            self::assertFalse(PluginOperator::isAutomaticLift($record));
            self::assertTrue(BlacklistRecorder::suppress($record));
            self::assertSame(['banner.example.com' => ['ADVERTISING' => null]], self::record('banner.example.com'));
            self::assertSame(1, $this->countRows('SELECT COUNT(*) FROM blacklist'));
        }

        public function testAnotherOperatorsBlacklistIsNeverLifted(): void
        {
            $uuid = EntitiesManager::registerEntity('banner.example.com');
            $operator = OperatorManager::createOperator('Human operator')->getUuid();
            $blacklistUuid = BlacklistManager::blacklistEntity($uuid, $operator, IncidentType::ADVERTISING);

            // The existing record already says what the list says, it isn't the plugin's
            self::assertSame($blacklistUuid, self::record('banner.example.com')['banner.example.com']['ADVERTISING']);
            FederationAdGuard::setRuleSource(TestRules::source([]));
            EntityVerifier::verifyFindings(100);
            self::assertFalse(BlacklistManager::getBlacklistEntry($blacklistUuid)->isLifted());
        }

        /**
         * Returns the operator of a client that scans messages, e.g., a moderation bot
         *
         * @return OperatorRecord The operator
         */
        private static function client(): OperatorRecord
        {
            $uuid = OperatorManager::createOperator('Moderation bot')->getUuid();
            OperatorManager::updatePermissions($uuid, client: true);
            return OperatorManager::getOperator($uuid);
        }

        /**
         * Returns the author of a message, an account
         *
         * @param string $id The ID of the account
         * @return EntityRecord The author
         */
        private static function author(string $id): EntityRecord
        {
            return EntitiesManager::getEntityByUuid(EntitiesManager::registerEntity('chat.invalid', $id));
        }

        /**
         * Scans a message of two listed links and records its author
         *
         * @param EntityRecord|null $author The author, null for a scan without one
         * @param OperatorRecord|null $client The client that scans it, null for an anonymous scan
         * @return string|null What AuthorRecorder::record() returned
         */
        private static function recordAuthor(?EntityRecord $author, ?OperatorRecord $client): ?string
        {
            $listed = [];
            foreach(['ads.example.com', 'banner.example.com'] as $host)
            {
                $listed[$host] = FederationAdGuard::match(MatchTarget::fromHost($host))->getBlocking()[0];
            }

            $contentScan = new ContentScan([new ContentInput('Deals! https://ads.example.com/a https://banner.example.com/b', contentType: ContentType::TEXT)],
                $author?->getAddress(), $author !== null ? new ResolvedEntity($author) : null, [], $client, concerns: [IncidentType::SPAM]);
            return AuthorRecorder::record($contentScan, 0, $listed, 2);
        }

        public function testAuthorsAreRecordedLeniently(): void
        {
            $client = self::client();
            $author = self::author('spammer');

            // A first offence only gives the author evidence
            $evidenceUuid = self::recordAuthor($author, $client);
            self::assertNotNull($evidenceUuid);
            self::assertSame(1, $this->countRows("SELECT COUNT(*) FROM evidence WHERE tag = 'adguard_author'"));
            self::assertSame(0, $this->countRows("SELECT COUNT(*) FROM blacklist WHERE type = 'SPAM'"));

            // A repeat offence blacklists the author temporarily
            $blacklistUuid = self::recordAuthor($author, $client);
            $blacklist = BlacklistManager::getBlacklistEntry($blacklistUuid);
            self::assertNotNull($blacklist);
            self::assertSame(IncidentType::SPAM, $blacklist->getType());
            self::assertSame($author->getUuid(), $blacklist->getEntityUuid());
            self::assertNotNull($blacklist->getExpires());
            self::assertEqualsWithDelta(time() + 86400, $blacklist->getExpires(), 60);

            // An author blacklisted for spamming is punished once for it
            self::assertNull(self::recordAuthor($author, $client));
            self::assertSame(2, $this->countRows("SELECT COUNT(*) FROM evidence WHERE tag = 'adguard_author'"));
            self::assertSame(1, $this->countRows("SELECT COUNT(*) FROM blacklist WHERE type = 'SPAM'"));
        }

        public function testAuthorsAreOnlyRecordedWhenTrustworthy(): void
        {
            $client = self::client();

            // An anonymous scan could name anyone as the author
            self::assertNull(self::recordAuthor(self::author('framed'), null));
            // A scan without an author has nobody to record (e.g., a DNS lookup)
            self::assertNull(self::recordAuthor(null, $client));
            // A bare host is not an author the plugin records
            self::assertNull(self::recordAuthor(EntitiesManager::getEntityByUuid(EntitiesManager::registerEntity('chat.invalid')), $client));

            $whitelisted = self::author('trusted');
            EntitiesManager::setEntityWhitelist($whitelisted->getUuid(), true);
            self::assertNull(self::recordAuthor($whitelisted, $client));

            self::assertSame(0, $this->countRows("SELECT COUNT(*) FROM evidence WHERE tag = 'adguard_author'"));
        }

        public function testAuthorBlacklistCanBeTurnedOff(): void
        {
            $this->dropDatabase();
            $this->createDatabase(['database_author_blacklist' => 'off']);
            StartupHandler::handleStartup(new \FederationLib\Objects\Plugin\Startup(time(), true, null));
            FederationAdGuard::setRuleSource(TestRules::source([1 => ["||ads.example.com^\n||banner.example.com^", IncidentType::ADVERTISING]]));

            $client = self::client();
            $author = self::author('spammer');
            self::recordAuthor($author, $client);
            self::recordAuthor($author, $client);
            self::assertSame(2, $this->countRows("SELECT COUNT(*) FROM evidence WHERE tag = 'adguard_author'"));
            self::assertSame(0, $this->countRows("SELECT COUNT(*) FROM blacklist WHERE type = 'SPAM'"));
        }
    }
