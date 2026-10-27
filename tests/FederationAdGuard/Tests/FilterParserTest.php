<?php

    /** @noinspection PhpUnhandledExceptionInspection */

    namespace FederationAdGuard\Tests;

    use FederationAdGuard\Classes\FilterParser;
    use FederationAdGuard\Enums\ListSyntax;
    use FederationAdGuard\Enums\RegexSubject;
    use FederationAdGuard\Enums\RuleAction;
    use FederationAdGuard\Enums\RuleType;
    use FederationAdGuard\Exceptions\RuleException;
    use PHPUnit\Framework\TestCase;

    class FilterParserTest extends TestCase
    {
        public function testCommentsAndHeaders(): void
        {
            $result = FilterParser::parse("[Adblock Plus 2.0]\n! Title: Test\n# A comment\n\n;RPZ comment\n!#if env_mobile\n!#endif\n");
            $this->assertCount(0, $result->getRules());
            $this->assertSame(7, $result->getComments());
            $this->assertSame(0, $result->getUnsupported());
        }

        public function testBracketedRulesAreNotHeaders(): void
        {
            $rules = FilterParser::parse('[a-z]+\\.example$', ListSyntax::REGEX)->getRules();
            $this->assertCount(1, $rules);
            $this->assertSame(RegexSubject::HOST, $rules[0]->getRegexSubject());
            $this->assertSame(1, preg_match($rules[0]->getRegex(), 'ads.example'));

            $rules = FilterParser::parse('[2001:DB8:0::1]')->getRules();
            $this->assertCount(1, $rules);
            $this->assertSame(RuleType::IP, $rules[0]->getType());
            $this->assertSame('2001:db8::1', $rules[0]->getHost());
        }

        public function testInvalidDenyAllowDoesNotBroadenRule(): void
        {
            foreach(['invalid/domain', 'cdn.example|invalid/domain'] as $domains)
            {
                $result = FilterParser::parse('||example.com^$denyallow=' . $domains);
                $this->assertCount(0, $result->getRules());
                $this->assertSame(1, $result->getUnsupported());
            }
        }

        public function testHostAnchors(): void
        {
            $rules = FilterParser::parseLine('||ads.example.com^');
            $this->assertCount(1, $rules);
            $this->assertSame(RuleType::HOST, $rules[0]->getType());
            $this->assertSame(RuleAction::BLOCK, $rules[0]->getAction());
            $this->assertSame('ads.example.com', $rules[0]->getHost());
            $this->assertTrue($rules[0]->isSubdomains());
            $this->assertTrue($rules[0]->isHostBlock());

            // AdGuard's exact host syntax
            $rules = FilterParser::parseLine('|ads.example.com^');
            $this->assertSame(RuleType::HOST, $rules[0]->getType());
            $this->assertFalse($rules[0]->isSubdomains());

            // An IP address
            $rules = FilterParser::parseLine('||203.0.113.7^');
            $this->assertSame(RuleType::IP, $rules[0]->getType());
            $this->assertSame('203.0.113.7', $rules[0]->getHost());
        }

        public function testMultiHostLineCannotExceedRuleLimit(): void
        {
            $result = FilterParser::parse("0.0.0.0 one.example two.example\nthree.example", maxRules: 1);

            $this->assertCount(1, $result->getRules());
            $this->assertSame('three.example', $result->getRules()[0]->getHost());
            $this->assertSame(1, $result->getUnsupported());
        }

        public function testHostsFiles(): void
        {
            $result = FilterParser::parse("127.0.0.1 localhost\n::1 localhost ip6-localhost\n0.0.0.0 ads.example.com tracker.example.com # inline\n127.0.0.1 AD.Example.ORG.\n");
            $hosts = array_map(fn($rule) => $rule->getHost(), $result->getRules());

            $this->assertSame(['ads.example.com', 'tracker.example.com', 'ad.example.org'], $hosts);
            $this->assertSame(0, $result->getUnsupported());
            // A hosts file entry is the same rule as ||host^
            $this->assertSame(FilterParser::parseLine('||ads.example.com^')[0]->getFingerprint(), $result->getRules()[0]->getFingerprint());
        }

        public function testDnsServerSyntaxes(): void
        {
            $result = FilterParser::parse(implode("\n", [
                'address=/dnsmasq.example/0.0.0.0',
                'server=/forward.example/1.1.1.1',
                'local-zone: "unbound.example" always_nxdomain',
                'local-zone: "pass.example" transparent',
                'zone "bind.example" { type master; file "null.zone.file"; };',
                '*.rpz.example CNAME .',
                'exact.rpz.example CNAME .',
                'allowed.rpz.example CNAME rpz-passthru.',
            ]));

            $rules = [];
            foreach($result->getRules() as $rule)
            {
                $rules[$rule->getHost()] = $rule;
            }

            $this->assertSame(['dnsmasq.example', 'unbound.example', 'bind.example', 'rpz.example', 'exact.rpz.example', 'allowed.rpz.example'], array_keys($rules));
            $this->assertFalse($rules['exact.rpz.example']->isSubdomains());
            $this->assertSame(RuleAction::ALLOW, $rules['allowed.rpz.example']->getAction());
            // The forward and the transparent zone block nothing
            $this->assertSame(2, $result->getUnsupported());
        }

        public function testDomainsAndAddresses(): void
        {
            $result = FilterParser::parse("ads.example.com\n*.wild.example\n.dot.example\n198.51.100.1\n2001:db8::1\n10.0.0.0/8\n");
            $types = array_map(fn($rule) => [$rule->getType(), $rule->getHost()], $result->getRules());

            $this->assertSame([
                [RuleType::HOST, 'ads.example.com'],
                [RuleType::HOST, 'wild.example'],
                [RuleType::HOST, 'dot.example'],
                [RuleType::IP, '198.51.100.1'],
                [RuleType::IP, '2001:db8::1'],
            ], $types);
            $this->assertSame(1, $result->getUnsupported());
        }

        public function testBarePatternsOfAdblockLists(): void
        {
            // In an Adblock Plus list a bare pattern is a substring of URLs, not a domain
            $result = FilterParser::parse("[Adblock Plus 2.0]\nads.example.com\n");
            $this->assertSame(RuleType::URL, $result->getRules()[0]->getType());

            $result = FilterParser::parse("ads.example.com\n");
            $this->assertSame(RuleType::HOST, $result->getRules()[0]->getType());
        }

        public function testUrlRules(): void
        {
            // Indexed by the host the pattern starts with
            $rule = FilterParser::parseLine('||cdn.example.com/ads/*')[0];
            $this->assertSame(RuleType::URL, $rule->getType());
            $this->assertSame('cdn.example.com', $rule->getHost());
            $this->assertNull($rule->getToken());
            $this->assertFalse($rule->isHostBlock());

            // Indexed by a token that is bounded on both sides
            $rule = FilterParser::parseLine('/banner/ad-')[0];
            $this->assertSame(RuleType::URL, $rule->getType());
            $this->assertNull($rule->getHost());
            $this->assertSame('banner', $rule->getToken());

            // A wildcard extends the token next to it, the rule is not indexed
            $rule = FilterParser::parseLine('ad*banner')[0];
            $this->assertNull($rule->getToken());

            $rule = FilterParser::parseLine('|https://tracker.example/pixel')[0];
            $this->assertSame('tracker.example', $rule->getHost());
        }

        public function testRegexRules(): void
        {
            $rule = FilterParser::parseLine('/^https?:\/\/[a-z]{8}\.top\//$script')[0];
            $this->assertSame(RuleType::REGEX, $rule->getType());
            $this->assertSame(RegexSubject::URL, $rule->getRegexSubject());
            $this->assertTrue($rule->isPartial());

            $result = FilterParser::parse("(^|\\.)regex\\.example\$\nad[0-9]+\\.;querytype=!A\ninvalid(\n", ListSyntax::REGEX);
            $this->assertCount(2, $result->getRules());
            $this->assertSame(RegexSubject::HOST, $result->getRules()[0]->getRegexSubject());
            $this->assertSame(['~A'], $result->getRules()[1]->getDnsTypes());
            $this->assertSame(1, $result->getUnsupported());
        }

        public function testModifiers(): void
        {
            $rule = FilterParser::parseLine('||ads.example.com^$third-party,script')[0];
            $this->assertTrue($rule->isPartial());
            $this->assertFalse($rule->isHostBlock());

            $rule = FilterParser::parseLine('||ads.example.com^$important')[0];
            $this->assertTrue($rule->isImportant());
            $this->assertTrue($rule->isHostBlock());

            $rule = FilterParser::parseLine('||ads.example.com^$domain=~good.example')[0];
            $this->assertTrue($rule->isPartial());

            $rule = FilterParser::parseLine('||example.com^$denyallow=cdn.example.com|img.example.com')[0];
            $this->assertSame(['cdn.example.com', 'img.example.com'], $rule->getDenyAllow());
            $this->assertFalse($rule->isHostBlock());

            $rule = FilterParser::parseLine('||example.com^$dnstype=AAAA|~A')[0];
            $this->assertSame(['AAAA', '~A'], $rule->getDnsTypes());

            $rule = FilterParser::parseLine('@@||example.com^$document')[0];
            $this->assertSame(RuleAction::ALLOW, $rule->getAction());
            $this->assertFalse($rule->isPartial());
        }

        public function testBadfilterSharesTheFingerprint(): void
        {
            $rule = FilterParser::parseLine('||ads.example.com^$third-party')[0];
            $badfilter = FilterParser::parseLine('||ads.example.com^$badfilter,third-party')[0];

            $this->assertTrue($badfilter->isBadfilter());
            $this->assertSame($rule->getFingerprint(), $badfilter->getFingerprint());
            $this->assertNotSame($rule->getFingerprint(), FilterParser::parseLine('||ads.example.com^')[0]->getFingerprint());
        }

        public function testUnsupportedRules(): void
        {
            $cases = [
                '||example.com^$domain=site.example' => 'some sites',
                '||example.com^$removeparam=utm_source' => 'do not block',
                '||example.com^$popup' => 'do not block',
                '||example.com^$nonsense' => 'not supported',
                '*$third-party' => 'every request',
                'address=/#/0.0.0.0' => 'every name',
            ];

            foreach($cases as $line => $reason)
            {
                try
                {
                    FilterParser::parseLine($line);
                    $this->fail('Expected the rule to be unsupported: ' . $line);
                }
                catch(RuleException $e)
                {
                    $this->assertStringContainsString($reason, $e->getMessage(), $line);
                }
            }
        }

        public function testCosmeticRules(): void
        {
            $result = FilterParser::parse("##.ad-box\nexample.com##.banner\nexample.com#@#.banner\nexample.com##+js(nobab)\nexample.com\$\$script[tag-content=\"ad\"]\n");
            $this->assertSame(5, $result->getCosmetic());
            $this->assertCount(0, $result->getRules());
        }

        public function testAllowlists(): void
        {
            $rules = FilterParser::parse("good.example\n0.0.0.0 fine.example\n", ListSyntax::AUTO, true)->getRules();
            $this->assertCount(2, $rules);
            $this->assertTrue(array_all($rules, fn($rule) => $rule->getAction() === RuleAction::ALLOW));
        }

        public function testMaximumRules(): void
        {
            $result = FilterParser::parse("a.example\nb.example\nc.example\n", ListSyntax::AUTO, false, 2);
            $this->assertCount(2, $result->getRules());
            $this->assertSame(1, $result->getUnsupported());
        }

        public function testUrlTokens(): void
        {
            $this->assertSame(['https', 'cdn', 'example', 'com', 'banner', 'ad', 'gif'], FilterParser::getUrlTokens('https://cdn.example.com/banner/ad-1.gif'));
        }
    }
