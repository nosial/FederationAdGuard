<?php

    /** @noinspection PhpUnhandledExceptionInspection */

    namespace FederationAdGuard\Tests;

    use FederationAdGuard\Handlers\ContentScanHandler;
    use FederationAdGuard\Handlers\MaintenanceHandler;
    use FederationAdGuard\Handlers\QueryEntityHandler;
    use FederationAdGuard\Handlers\RecordChangeHandler;
    use FederationAdGuard\Handlers\StartupHandler;
    use FederationAdGuard\Enums\DatabaseTables;
    use FederationLib\Classes\PluginManager;
    use FederationLib\Enums\EventType;
    use FederationLib\Objects\Plugin;
    use LogLib2\Logger;
    use PHPUnit\Framework\TestCase;

    /**
     * Tests the plugin through FederationLib's plugin system
     */
    class PluginTest extends TestCase
    {
        private const string PACKAGE = 'net.nosial.federation_adguard';

        protected function tearDown(): void
        {
            PluginManager::setPlugins([]);
            Logger::unregisterHandlers();
        }

        public function testPluginIsValid(): void
        {
            $plugin = Plugin::load(self::PACKAGE);

            // Hosts found in scanned content are blacklisted, the server must disclose it
            $this->assertTrue($plugin->collectsScanContent());

            $this->assertSame([], $plugin->getRequestHandlers());

            $this->assertSame(StartupHandler::class, $plugin->getEventHandlers(EventType::STARTUP)[0]->getClass());
            $this->assertSame(MaintenanceHandler::class, $plugin->getEventHandlers(EventType::MAINTENANCE)[0]->getClass());
            $this->assertSame(ContentScanHandler::class, $plugin->getEventHandlers(EventType::CONTENT_SCAN)[0]->getClass());
            $this->assertSame(QueryEntityHandler::class, $plugin->getEventHandlers(EventType::QUERY_ENTITY)[0]->getClass());
            $this->assertSame(RecordChangeHandler::class, $plugin->getEventHandlers(EventType::RECORD_CHANGE)[0]->getClass());
            $this->assertEqualsCanonicalizing(['ENTITY_CREATED', 'ENTITY_UPDATED', 'ENTITY_DELETED', 'BLACKLIST_LIFTED', 'BLACKLIST_DELETED'],
                $plugin->getEventHandlers(EventType::RECORD_CHANGE)[0]->getFilter());
            $this->assertSame([], $plugin->getEventHandlers(EventType::AUDIT_LOG));

            $result = PluginManager::validateRoutes([$plugin]);
            $this->assertSame([], $result['errors']);
        }

        public function testSchemaFilesAreBundled(): void
        {
            foreach(DatabaseTables::getOrderedTables() as $table)
            {
                $this->assertFileExists($table->getPath());
                $this->assertStringContainsString('create table ' . $table->getTableName(), file_get_contents($table->getPath()));
            }
        }
    }
