<?php

    namespace FederationAdGuard\Tests;

    use FederationAdGuard\Exceptions\RuleException;
    use FederationAdGuard\Classes\Matcher;
    use FederationAdGuard\Classes\FilterParser;
    use FederationAdGuard\Classes\MemoryRuleSource;
    use FederationAdGuard\Objects\FilterRule;
    use FederationAdGuard\Objects\MatchTarget;
    use FederationAdGuard\Tests\Helpers\TestRules;
    use FederationAdGuard\Tests\Helpers\PluginConfiguration;
    use FederationAdGuard\Interfaces\RuleSourceInterface;
    use FederationLib\Enums\IncidentType;
    use PHPUnit\Framework\TestCase;

    class MatcherTest extends TestCase
    {
        protected function setUp(): void
        {
            PluginConfiguration::apply();
        }

        protected function tearDown(): void
        {
            PluginConfiguration::reset();
        }

        /**
         * Returns distinct rules for the same host, as many as given
         *
         * @param int $count The number of rules
         * @return FilterRule[] The rules
         */
        private static function distinctRules(int $count): array
        {
            $rules = [];
            for($id = 1; $id <= $count; $id++)
            {
                $rules[] = new FilterRule(['id' => $id, 'rule' => '||ads.example.com^', 'action' => 'BLOCK', 'type' => 'HOST', 'host' => 'ads.example.com', 'subdomains' => true, 'concern' => 'ADVERTISING']);
            }

            return $rules;
        }

        public function testExactCandidateLimitStillChecksLaterGroups(): void
        {
            $source = $this->createMock(RuleSourceInterface::class);
            $source->expects($this->once())->method('getRulesByHosts')->willReturn(self::distinctRules(Matcher::MAX_CANDIDATES));
            $source->expects($this->once())->method('getRulesByTokens')->willReturn([]);
            $source->expects($this->once())->method('getUnindexedRules')->willReturn([]);

            $this->assertTrue(Matcher::match(MatchTarget::fromUrl('https://ads.example.com/path'), $source)->isBlocked());
        }

        public function testOverflowCannotDiscardAnException(): void
        {
            $source = $this->createMock(RuleSourceInterface::class);
            $source->method('getRulesByHosts')->willReturn(self::distinctRules(Matcher::MAX_CANDIDATES));
            $source->method('getRulesByTokens')->willReturn([]);
            // The exception comes after the limit, an incomplete match must not become a decision
            $source->method('getUnindexedRules')->willReturn(FilterParser::parseLine('@@||ads.example.com^'));
            $this->expectException(RuleException::class);
            Matcher::match(MatchTarget::fromUrl('https://ads.example.com/path'), $source);
        }

        public function testDuplicateCandidatesDoNotConsumeLimit(): void
        {
            $rules = self::distinctRules(Matcher::MAX_CANDIDATES - 1);
            $exception = FilterParser::parseLine('@@||ads.example.com^')[0];
            $source = $this->createMock(RuleSourceInterface::class);
            $source->expects($this->once())->method('getRulesByHosts')->willReturn([...$rules, ...$rules]);
            $source->expects($this->once())->method('getRulesByTokens')->willReturn([$exception]);
            $source->expects($this->once())->method('getUnindexedRules')->willReturn([]);

            $result = Matcher::match(MatchTarget::fromUrl('https://ads.example.com/path'), $source);
            $this->assertFalse($result->isBlocked());
            $this->assertCount(Matcher::MAX_CANDIDATES - 1, $result->getCancelled());
        }

        public function testMemoryLookupReadsDistinctKeys(): void
        {
            $rule = FilterParser::parseLine('||ads.example.com^')[0];
            $source = new MemoryRuleSource([$rule]);
            $this->assertSame([$rule], $source->getRulesByHosts(['ads.example.com', 'ads.example.com']));
            $this->assertSame([], $source->getRulesByHosts([]));
            $this->assertSame([], $source->getRulesByTokens([]));
            $this->assertSame(['a.b.example.com', 'b.example.com', 'example.com', 'com'], Matcher::getHostSuffixes('a.b.example.com'));
        }

        public function testHostsAndSubdomains(): void
        {
            $source = TestRules::source([1 => ["||ads.example.com^\n|exact.example.org^", IncidentType::ADVERTISING]]);

            $this->assertTrue(Matcher::match(MatchTarget::fromHost('ads.example.com'), $source)->isBlocked());
            $this->assertTrue(Matcher::match(MatchTarget::fromHost('x.ads.example.com'), $source)->isBlocked());
            $this->assertFalse(Matcher::match(MatchTarget::fromHost('example.com'), $source)->isBlocked());
            $this->assertFalse(Matcher::match(MatchTarget::fromHost('notads.example.com'), $source)->isBlocked());

            $this->assertTrue(Matcher::match(MatchTarget::fromHost('exact.example.org'), $source)->isBlocked());
            $this->assertFalse(Matcher::match(MatchTarget::fromHost('sub.exact.example.org'), $source)->isBlocked());

            // A URL on a blocked host is blocked
            $this->assertTrue(Matcher::match(MatchTarget::fromUrl('https://x.ads.example.com/path'), $source)->isBlocked());
        }

        public function testIdenticalCustomRulesKeepBothConcerns(): void
        {
            $rule = FilterParser::parseLine('||ads.example.com^')[0];
            $source = new MemoryRuleSource([
                $rule->withSubscription(null, IncidentType::ADVERTISING),
                $rule->withSubscription(null, IncidentType::TRACKING),
            ]);

            $result = Matcher::match(MatchTarget::fromHost('ads.example.com'), $source);
            $this->assertEqualsCanonicalizing([IncidentType::ADVERTISING, IncidentType::TRACKING], $result->getConcerns());
        }

        public function testConcerns(): void
        {
            $source = TestRules::source([
                1 => ['||ads.example.com^', IncidentType::ADVERTISING],
                2 => ['||ads.example.com^', IncidentType::TRACKING],
            ]);

            $result = Matcher::match(MatchTarget::fromHost('ads.example.com'), $source);
            $this->assertEqualsCanonicalizing([IncidentType::ADVERTISING, IncidentType::TRACKING], $result->getConcerns());
            $this->assertTrue($result->isBlocked(IncidentType::TRACKING));
            $this->assertFalse($result->isBlocked(IncidentType::MALWARE));
            $this->assertCount(2, $result->getHostBlocks());
        }

        public function testExceptions(): void
        {
            $source = TestRules::source([
                1 => ["||example.com^\n||evil.example^\$important\n||partial.example^\$script", IncidentType::ADVERTISING],
                2 => ["@@||good.example.com^\n@@||evil.example^\n@@||partial.example^\$script", IncidentType::ADVERTISING],
            ]);

            // An exception of another list unblocks the host
            $result = Matcher::match(MatchTarget::fromHost('good.example.com'), $source);
            $this->assertFalse($result->isBlocked());
            $this->assertTrue($result->isExcepted());
            $this->assertCount(1, $result->getCancelled());

            $this->assertTrue(Matcher::match(MatchTarget::fromHost('other.example.com'), $source)->isBlocked());

            // $important wins over an exception that isn't important
            $this->assertTrue(Matcher::match(MatchTarget::fromHost('evil.example'), $source)->isBlocked());

            // A partial exception cancels a partial rule
            $this->assertFalse(Matcher::match(MatchTarget::fromHost('partial.example'), $source)->isBlocked());
        }

        public function testPartialExceptionsDontUnblockHosts(): void
        {
            $source = TestRules::source([
                1 => ['||ads.example.com^', IncidentType::ADVERTISING],
                2 => ['@@||ads.example.com^$script', IncidentType::ADVERTISING],
            ]);

            $this->assertTrue(Matcher::match(MatchTarget::fromHost('ads.example.com'), $source)->isBlocked());
        }

        public function testBadfilter(): void
        {
            $source = TestRules::source([
                1 => ["0.0.0.0 ads.example.com\n||tracker.example^", IncidentType::ADVERTISING],
                2 => ['||ads.example.com^$badfilter', IncidentType::ADVERTISING],
            ]);

            $this->assertFalse(Matcher::match(MatchTarget::fromHost('ads.example.com'), $source)->isBlocked());
            $this->assertTrue(Matcher::match(MatchTarget::fromHost('tracker.example'), $source)->isBlocked());
        }

        public function testDnsTypesAreAssertions(): void
        {
            $source = TestRules::source([1 => ['||ipv6.example^$dnstype=AAAA', IncidentType::ADVERTISING]]);

            $this->assertFalse(Matcher::match(MatchTarget::fromHost('ipv6.example'), $source)->isBlocked());
            $this->assertFalse(Matcher::match(MatchTarget::fromHost('ipv6.example', 'A'), $source)->isBlocked());

            $result = Matcher::match(MatchTarget::fromHost('ipv6.example', 'aaaa'), $source);
            $this->assertTrue($result->isBlocked());
            $this->assertTrue($result->getBlocking()[0]->isAssertion());
            // A rule that relies on the client's assertion never creates a blacklist record
            $this->assertCount(0, $result->getHostBlocks());
        }

        public function testDenyAllow(): void
        {
            $source = TestRules::source([1 => ['||example.com^$denyallow=cdn.example.com', IncidentType::ADVERTISING]]);

            $this->assertTrue(Matcher::match(MatchTarget::fromHost('ads.example.com'), $source)->isBlocked());
            $this->assertFalse(Matcher::match(MatchTarget::fromHost('img.cdn.example.com'), $source)->isBlocked());
        }

        public function testUrlRulesOnlyMatchUrls(): void
        {
            $source = TestRules::source([1 => ["||cdn.example.com/ads/*\n/banner/ad-\n/^https?:\\/\\/[a-z]{8}\\.top\\//", IncidentType::ADVERTISING]]);

            $this->assertTrue(Matcher::match(MatchTarget::fromUrl('https://cdn.example.com/ads/1.gif'), $source)->isBlocked());
            $this->assertFalse(Matcher::match(MatchTarget::fromUrl('https://cdn.example.com/img/1.gif'), $source)->isBlocked());
            $this->assertFalse(Matcher::match(MatchTarget::fromHost('cdn.example.com'), $source)->isBlocked());

            $this->assertTrue(Matcher::match(MatchTarget::fromUrl('https://site.example/banner/ad-1.png'), $source)->isBlocked());
            $this->assertFalse(Matcher::match(MatchTarget::fromUrl('https://site.example/xbanner/ad-1.png'), $source)->isBlocked());

            $this->assertTrue(Matcher::match(MatchTarget::fromUrl('https://abcdefgh.top/x'), $source)->isBlocked());
            $this->assertFalse(Matcher::match(MatchTarget::fromHost('abcdefgh.top'), $source)->isBlocked());
        }

        public function testUnanchoredUrlsMatchInsideOtherUrls(): void
        {
            $target = MatchTarget::fromUrl('https://site.example/redirect?url=https://tracker.example/pixel');
            $source = TestRules::source([1 => ['https://tracker.example/pixel', IncidentType::TRACKING]]);
            $this->assertTrue(Matcher::match($target, $source)->isBlocked());

            $source = TestRules::source([1 => ['|https://tracker.example/pixel', IncidentType::TRACKING]]);
            $this->assertFalse(Matcher::match($target, $source)->isBlocked());
            $this->assertTrue(Matcher::match(MatchTarget::fromUrl('https://tracker.example/pixel'), $source)->isBlocked());
        }

        public function testResolvedIpv6AddressesUseCanonicalForm(): void
        {
            $source = TestRules::source([1 => ['2001:db8::1', IncidentType::MALWARE]]);
            $target = MatchTarget::fromHost('c2.example', addresses: ['2001:DB8:0:0:0:0:0:1', '2001:db8::1']);

            $this->assertSame(['2001:db8::1'], $target->getAddresses());
            $this->assertTrue(Matcher::match($target, $source)->isBlocked(IncidentType::MALWARE));
            $this->assertFalse(Matcher::match(MatchTarget::fromHost('c2.example', addresses: ['invalid']), $source)->isBlocked());
        }

        public function testHostRegexes(): void
        {
            $source = new \FederationAdGuard\Classes\MemoryRuleSource(array_map(
                fn($rule) => $rule->withSubscription(1, IncidentType::TRACKING),
                \FederationAdGuard\Classes\FilterParser::parse("(^|\\.)metrics\\.example\$", \FederationAdGuard\Enums\ListSyntax::REGEX)->getRules()
            ));

            $this->assertTrue(Matcher::match(MatchTarget::fromHost('a.metrics.example'), $source)->isBlocked());
            $this->assertTrue(Matcher::match(MatchTarget::fromUrl('https://metrics.example/collect'), $source)->isBlocked());
            $this->assertFalse(Matcher::match(MatchTarget::fromHost('metrics.example.org'), $source)->isBlocked());
        }

        public function testResolvedAddresses(): void
        {
            $source = TestRules::source([1 => ['203.0.113.7', IncidentType::MALWARE]]);

            $this->assertTrue(Matcher::match(MatchTarget::fromHost('203.0.113.7'), $source)->isBlocked());
            $this->assertTrue(Matcher::match(MatchTarget::fromHost('c2.example', null, ['203.0.113.7']), $source)->isBlocked(IncidentType::MALWARE));
            $this->assertFalse(Matcher::match(MatchTarget::fromHost('c2.example'), $source)->isBlocked());
        }

        public function testTargets(): void
        {
            $this->assertNull(MatchTarget::fromHost('not a host'));
            $this->assertNull(MatchTarget::fromUrl('https://'));
            $this->assertSame('example.com', MatchTarget::fromHost('Example.COM.')->getHost());
            $this->assertSame('2001:db8::1', MatchTarget::fromHost('[2001:DB8:0::1]')->getHost());
            $this->assertSame('http://example.com/x', MatchTarget::fromUrl('example.com/x')->getUrl());
        }
    }
