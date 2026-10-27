<?php

    /** @noinspection PhpUnhandledExceptionInspection */

    namespace FederationAdGuard\Tests;

    use FederationAdGuard\Classes\PluginOperator;
    use FederationAdGuard\FederationAdGuard;
    use FederationAdGuard\Handlers\QueryEntityHandler;
    use FederationAdGuard\Tests\Helpers\PluginConfiguration;
    use FederationAdGuard\Tests\Helpers\TestRules;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Enums\SuggestedActionType;
    use FederationLib\Objects\EntityRecord;
    use FederationLib\Objects\Plugin\EntityQuery;
    use PHPUnit\Framework\TestCase;

    /**
     * Calls the QUERY_ENTITY handler directly with rules kept in memory. With building the database off (the unit tests
     * never write to a database), a listed host is suggested to be blocked instead of being blacklisted.
     */
    class QueryEntityHandlerTest extends TestCase
    {
        protected function setUp(): void
        {
            PluginConfiguration::reset();
            PluginOperator::setActive(true);
            FederationAdGuard::setRuleSource(TestRules::source([
                1 => ["||ads.example.com^\n||partial.example^\$script\n@@||good.ads.example.com^", IncidentType::ADVERTISING],
            ]));
        }

        protected function tearDown(): void
        {
            FederationAdGuard::setRuleSource(null);
            PluginOperator::setActive(null);
            PluginConfiguration::reset();
        }

        private static function entity(string $host, ?string $id=null): EntityRecord
        {
            return new EntityRecord(['uuid' => '01900000-0000-7000-8000-000000000002', 'hash' => hash('sha256', $host), 'host' => $host, 'id' => $id,
                'reputation' => 0, 'whitelisted' => false, 'created' => time()]);
        }

        public function testListedHost(): void
        {
            $query = new EntityQuery('ads.example.com', self::entity('ads.example.com'), [], [], null, [IncidentType::ADVERTISING]);
            QueryEntityHandler::handleQueryEntity($query);

            $this->assertTrue($query->getAddedEntityMetadata()['adguard_listed']);
            $this->assertSame('ADVERTISING', $query->getAddedEntityMetadata()['adguard_concerns']);
            $this->assertSame('||ads.example.com^', $query->getAddedEntityMetadata()['adguard_rule']);
            $this->assertSame(SuggestedActionType::PERMANENTLY_BLOCK_ENTITY, $query->getResult()->getSuggestedAction());
        }

        public function testOtherConcernsAreNotSuggested(): void
        {
            $query = new EntityQuery('ads.example.com', self::entity('ads.example.com'), [], [], null, [IncidentType::SPAM]);
            QueryEntityHandler::handleQueryEntity($query);

            $this->assertTrue($query->getAddedEntityMetadata()['adguard_listed']);
            $this->assertFalse($query->isSuggestedActionOverridden());
        }

        public function testPartialRulesDontListAHost(): void
        {
            // A host can't be checked against a rule restricted to some requests, as DNS blockers do
            $query = new EntityQuery('partial.example', self::entity('partial.example'), [], [], null, [IncidentType::ADVERTISING]);
            QueryEntityHandler::handleQueryEntity($query);

            $this->assertSame([], $query->getAddedEntityMetadata());
            $this->assertFalse($query->isSuggestedActionOverridden());
        }

        public function testExceptions(): void
        {
            $query = new EntityQuery('good.ads.example.com', self::entity('good.ads.example.com'), [], [], null, [IncidentType::ADVERTISING]);
            QueryEntityHandler::handleQueryEntity($query);

            $this->assertSame(['adguard_listed' => false, 'adguard_excepted' => true], $query->getAddedEntityMetadata());
            $this->assertFalse($query->isSuggestedActionOverridden());
        }

        public function testNamedEntitiesAreIgnored(): void
        {
            $query = new EntityQuery('john@ads.example.com', self::entity('ads.example.com', 'john'), [], [], null, [IncidentType::ADVERTISING]);
            QueryEntityHandler::handleQueryEntity($query);

            $this->assertSame([], $query->getAddedEntityMetadata());
            $this->assertFalse($query->isSuggestedActionOverridden());
        }

        public function testDisabled(): void
        {
            // The hard switch
            PluginConfiguration::apply(['enabled' => 'false']);
            $query = new EntityQuery('ads.example.com', self::entity('ads.example.com'), [], [], null, [IncidentType::ADVERTISING]);
            QueryEntityHandler::handleQueryEntity($query);
            $this->assertSame([], $query->getAddedEntityMetadata());
            $this->assertFalse($query->isSuggestedActionOverridden());

            // The soft switch, the FederationAdGuard operator is disabled
            PluginConfiguration::reset();
            PluginOperator::setActive(false);
            $query = new EntityQuery('ads.example.com', self::entity('ads.example.com'), [], [], null, [IncidentType::ADVERTISING]);
            QueryEntityHandler::handleQueryEntity($query);
            $this->assertSame([], $query->getAddedEntityMetadata());
            $this->assertFalse($query->isSuggestedActionOverridden());
        }
    }
