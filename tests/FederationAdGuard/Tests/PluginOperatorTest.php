<?php

    /** @noinspection PhpUnhandledExceptionInspection */

    namespace FederationAdGuard\Tests;

    use FederationAdGuard\Classes\BlacklistRecorder;
    use FederationAdGuard\Classes\FindingRecorder;
    use FederationAdGuard\Classes\PluginOperator;
    use FederationAdGuard\Enums\MetadataKey;
    use FederationAdGuard\FederationAdGuard;
    use FederationAdGuard\Handlers\ContentScanHandler;
    use FederationAdGuard\Handlers\MaintenanceHandler;
    use FederationAdGuard\Handlers\StartupHandler;
    use FederationAdGuard\Objects\MatchTarget;
    use FederationAdGuard\Tests\Helpers\IsolatedDatabase;
    use FederationAdGuard\Tests\Helpers\PluginConfiguration;
    use FederationAdGuard\Tests\Helpers\TestRules;
    use FederationLib\Classes\DatabaseConnection;
    use FederationLib\Classes\Managers\BlacklistManager;
    use FederationLib\Classes\Managers\OperatorManager;
    use FederationLib\Enums\ContentType;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Objects\BlacklistRecord;
    use FederationLib\Objects\ContentInput;
    use FederationLib\Objects\Plugin\ContentScan;
    use FederationLib\Objects\Plugin\Maintenance;
    use FederationLib\Objects\Plugin\Startup;
    use PDO;
    use PHPUnit\Framework\Attributes\Group;
    use PHPUnit\Framework\TestCase;

    /**
     * The FederationAdGuard operator, the plugin's identity and its soft switch. Uses a disposable database (see
     * IsolatedDatabase).
     */
    #[Group('integration')]
    class PluginOperatorTest extends TestCase
    {
        use IsolatedDatabase;

        protected function setUp(): void
        {
            $this->createDatabase();
        }

        protected function tearDown(): void
        {
            $this->dropDatabase();
        }

        public function testStartupCreatesAndRepairsIdentity(): void
        {
            StartupHandler::handleStartup(new Startup(time(), true, null));
            $operator = PluginOperator::get();
            self::assertSame('FederationAdGuard', $operator->getName());
            self::assertTrue($operator->hasClientPermissions());
            self::assertTrue($operator->hasManagementPermissions());
            self::assertFalse($operator->hasOperatorPermissions());
            self::assertSame($operator->getUuid(), DatabaseConnection::getMetadata(MetadataKey::OPERATOR_UUID->value));
            $row = $this->connection->query('SELECT * FROM operators')->fetch();
            self::assertSame(1, (int)$row['is_bot']);
            self::assertSame(0, (int)$row['auto_assign_reports']);
            self::assertSame(0, (int)$row['auto_assign_automated_reports']);

            OperatorManager::updatePermissions($operator->getUuid(), client: false, management: false, operator: true);
            OperatorManager::updateOperatorName($operator->getUuid(), 'Renamed plugin');
            StartupHandler::handleStartup(new Startup(time(), false, null));
            self::assertSame($operator->getUuid(), PluginOperator::get()->getUuid());
            self::assertTrue(PluginOperator::get()->hasManagementPermissions());
            self::assertFalse(PluginOperator::get()->hasOperatorPermissions());
            self::assertSame('FederationAdGuard', PluginOperator::get()->getName());
            self::assertSame(1, (int)$this->connection->query('SELECT COUNT(*) FROM operators')->fetchColumn());
        }

        public function testDisabledOperatorDisablesThePlugin(): void
        {
            StartupHandler::handleStartup(new Startup(time(), true, null));
            $uuid = PluginOperator::get()->getUuid();
            FederationAdGuard::setRuleSource(TestRules::source([1 => ['||ads.example.com^', IncidentType::ADVERTISING]]));
            self::assertTrue(PluginOperator::isActive());

            // An administrator disables the operator through the federation interface, the soft switch
            OperatorManager::disableOperator($uuid);
            self::assertFalse(PluginOperator::isActive());

            // Startup and maintenance repair the operator but never enable it again, and FederationLib keeps working
            StartupHandler::handleStartup(new Startup(time(), false, null));
            MaintenanceHandler::handleMaintenance(new Maintenance(time(), false, null, []));
            self::assertTrue(OperatorManager::getOperator($uuid)->isDisabled());
            self::assertFalse(PluginOperator::isActive());

            $contentScan = new ContentScan([new ContentInput('ads.example.com', contentType: ContentType::HOSTNAME)], null, null, [], concerns: [IncidentType::ADVERTISING]);
            ContentScanHandler::handleContentScan($contentScan);
            self::assertSame([], $contentScan->getDetections());
            self::assertSame([], $contentScan->getScanResults());
            self::assertSame(0, (int)$this->connection->query('SELECT COUNT(*) FROM adguard_findings')->fetchColumn());

            // Enabling the operator again resumes the plugin
            OperatorManager::enableOperator($uuid);
            self::assertTrue(PluginOperator::isActive());
            $contentScan = new ContentScan([new ContentInput('ads.example.com', contentType: ContentType::HOSTNAME)], null, null, [], concerns: [IncidentType::ADVERTISING]);
            ContentScanHandler::handleContentScan($contentScan);
            self::assertCount(1, $contentScan->getDetections());
            self::assertSame(1, (int)$this->connection->query('SELECT COUNT(*) FROM adguard_findings')->fetchColumn());
        }

        public function testFindingsAndLiftsUsePluginIdentity(): void
        {
            StartupHandler::handleStartup(new Startup(time(), true, null));
            $operatorUuid = PluginOperator::get()->getUuid();
            FederationAdGuard::setRuleSource(TestRules::source([1 => ['||ads.example.com^', IncidentType::ADVERTISING]]));
            $uuid = FindingRecorder::recordResult(FederationAdGuard::match(MatchTarget::fromHost('ads.example.com')))['ads.example.com'][IncidentType::ADVERTISING->value] ?? null;
            self::assertNotNull($uuid);
            $record = BlacklistManager::getBlacklistEntry($uuid);
            self::assertSame($operatorUuid, $record->getOperatorUuid());
            self::assertNull($record->getExpires());
            self::assertSame([$operatorUuid], $this->connection->query('SELECT DISTINCT operator FROM evidence')->fetchAll(PDO::FETCH_COLUMN));
            self::assertSame([$operatorUuid], $this->connection->query('SELECT DISTINCT operator FROM audit_log')->fetchAll(PDO::FETCH_COLUMN));

            self::assertTrue(BlacklistRecorder::lift($record->getEntityUuid(), IncidentType::ADVERTISING, 'test revalidation'));
            $record = BlacklistManager::getBlacklistEntry($uuid);
            self::assertSame($operatorUuid, $record->getLiftedBy());
            self::assertTrue(PluginOperator::isAutomaticLift($record));
            self::assertSame([$operatorUuid], $this->connection->query('SELECT DISTINCT operator FROM audit_log')->fetchAll(PDO::FETCH_COLUMN));
        }

        public function testManualLiftsAreOperatorDecisions(): void
        {
            StartupHandler::handleStartup(new Startup(time(), true, null));
            $manual = OperatorManager::createOperator('Human operator')->getUuid();
            self::assertFalse(PluginOperator::isAutomaticLift(new BlacklistRecord([
                'operator' => PluginOperator::get()->getUuid(), 'lifted' => true, 'lifted_by' => $manual,
            ])));
            self::assertTrue(PluginOperator::isAutomaticLift(new BlacklistRecord([
                'operator' => PluginOperator::get()->getUuid(), 'lifted' => true, 'lifted_by' => PluginOperator::get()->getUuid(),
            ])));
        }

        public function testMissingIdentityDoesNotAdoptAnExistingAccountByName(): void
        {
            $uuid = OperatorManager::createOperator('FederationAdGuard')->getUuid();
            try
            {
                PluginOperator::provision();
                self::fail('An existing account must not be adopted by its display name');
            }
            catch(\FederationLib\Exceptions\DatabaseOperationException)
            {
                self::assertNull(DatabaseConnection::getMetadata(MetadataKey::OPERATOR_UUID->value));
                self::assertFalse(OperatorManager::getOperator($uuid)->hasManagementPermissions());
            }
        }

        public function testDisabledPluginDoesNothing(): void
        {
            // The hard switch, not even the plugin's tables are created
            PluginConfiguration::apply(['database_enabled' => 'true', 'enabled' => 'false']);
            StartupHandler::handleStartup(new Startup(time(), true, null));
            MaintenanceHandler::handleMaintenance(new Maintenance(time(), false, null, []));
            self::assertNull(DatabaseConnection::getMetadata(MetadataKey::OPERATOR_UUID->value));
            self::assertSame(0, (int)$this->connection->query('SELECT COUNT(*) FROM operators')->fetchColumn());
            self::assertSame([], $this->connection->query("SHOW TABLES LIKE 'adguard_%'")->fetchAll(PDO::FETCH_COLUMN));
        }

        public function testDeletedOperatorIsRecreatedAtStartup(): void
        {
            StartupHandler::handleStartup(new Startup(time(), true, null));
            $uuid = PluginOperator::get()->getUuid();
            OperatorManager::deleteOperator($uuid);
            PluginOperator::setActive(null);
            StartupHandler::handleStartup(new Startup(time(), false, null));
            self::assertNotSame($uuid, PluginOperator::get()->getUuid());
            self::assertSame('FederationAdGuard', PluginOperator::get()->getName());
            self::assertTrue(PluginOperator::get()->hasManagementPermissions());
        }
    }
