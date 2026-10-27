<?php

    namespace FederationAdGuard\Tests;

    use FederationAdGuard\Classes\FilterParser;
    use FederationAdGuard\Classes\LocalLists;
    use FederationAdGuard\Classes\Matcher;
    use FederationAdGuard\Classes\MemoryRuleSource;
    use FederationAdGuard\Classes\Provisioner;
    use FederationAdGuard\Enums\ListSource;
    use InvalidArgumentException;
    use FederationAdGuard\Exceptions\ListException;
    use FederationAdGuard\Objects\MatchTarget;
    use FederationAdGuard\Objects\SubscriptionDefinition;
    use FederationAdGuard\Tests\Helpers\PluginConfiguration;
    use FederationLib\Enums\IncidentType;
    use PHPUnit\Framework\TestCase;

    class LocalListsTest extends TestCase
    {
        private string $directory;

        protected function setUp(): void
        {
            $this->directory = sys_get_temp_dir() . '/adguard-' . bin2hex(random_bytes(8));
            mkdir($this->directory);
            PluginConfiguration::reset();
        }

        protected function tearDown(): void
        {
            foreach(scandir($this->directory) as $name)
            {
                if($name !== '.' && $name !== '..')
                {
                    $path = $this->directory . '/' . $name;
                    is_dir($path) ? rmdir($path) : unlink($path);
                }
            }
            rmdir($this->directory);
            PluginConfiguration::reset();
        }

        public function testDirectoryExpandsInOrderAndKeepsSettings(): void
        {
            file_put_contents($this->directory . '/b.txt', 'b.example');
            file_put_contents($this->directory . '/a.txt', 'a.example');
            file_put_contents($this->directory . '/.hidden', 'hidden.example');
            mkdir($this->directory . '/nested');
            $definition = SubscriptionDefinition::parse(['list' => $this->directory, 'concern' => 'MALWARE', 'allowlist' => true]);
            $files = LocalLists::expand($definition);

            $this->assertSame(['a.txt', 'b.txt'], array_map(fn($file) => $file->getName(), $files));
            foreach($files as $file)
            {
                $this->assertSame(ListSource::FILE, $file->getSource());
                $this->assertSame(IncidentType::MALWARE, $file->getConcern());
                $this->assertTrue($file->isAllowlist());
            }
        }

        public function testExplicitFileOverridesDirectoryAndRemovalIsObserved(): void
        {
            $path = $this->directory . '/a.txt';
            file_put_contents($path, 'a.example');
            PluginConfiguration::apply(['lists' => $this->directory . ';concern=ADVERTISING' . "\n" . $path . ';concern=MALWARE']);
            $complete = true;
            $declared = Provisioner::getDeclaredSubscriptions($complete);
            $this->assertTrue($complete);
            $this->assertCount(1, $declared);
            $this->assertSame(IncidentType::MALWARE, array_values($declared)[0]->getConcern());

            PluginConfiguration::apply(['lists' => $this->directory]);
            unlink($path);
            $this->assertSame([], Provisioner::getDeclaredSubscriptions($complete));
            $this->assertTrue($complete);
        }

        public function testMissingPathPreventsPruning(): void
        {
            PluginConfiguration::apply(['lists' => $this->directory . '/missing']);
            $complete = true;
            $this->assertSame([], Provisioner::getDeclaredSubscriptions($complete));
            $this->assertFalse($complete);
        }

        public function testInvalidDefinitionPreventsPruning(): void
        {
            PluginConfiguration::apply(['lists' => '301;concern=INVALID']);
            $complete = true;
            $this->assertSame([], Provisioner::getDeclaredSubscriptions($complete));
            $this->assertFalse($complete);
        }

        public function testLocalListUsesWholeListSyntax(): void
        {
            $path = $this->directory . '/ads.txt';
            file_put_contents($path, "\xEF\xBB\xBF[Adblock Plus 2.0]\nads.example\n");
            $rules = FilterParser::parse(LocalLists::read($path, 1024))->getRules();
            $source = new MemoryRuleSource($rules);
            $this->assertTrue(Matcher::match(MatchTarget::fromUrl('https://other.example/ads.example/pixel'), $source)->isBlocked());
            $this->assertFalse(Matcher::match(MatchTarget::fromHost('ads.example'), $source)->isBlocked());
        }

        public function testOversizedFileIsRejected(): void
        {
            $path = $this->directory . '/large.txt';
            file_put_contents($path, str_repeat('a', 1025));
            $this->expectException(ListException::class);
            LocalLists::read($path, 1024);
        }

        public function testLocalStreamsAreRejected(): void
        {
            $this->expectException(InvalidArgumentException::class);
            SubscriptionDefinition::parse('php://filter/resource=/etc/passwd');
        }

        public function testRelativePathsAreRejected(): void
        {
            // A relative path would depend on the working directory of the process
            $this->expectException(InvalidArgumentException::class);
            SubscriptionDefinition::parse('filters/ads.txt');
        }
    }
