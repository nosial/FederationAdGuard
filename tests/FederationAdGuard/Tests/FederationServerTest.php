<?php

    /** @noinspection PhpUnhandledExceptionInspection */

    namespace FederationAdGuard\Tests;

    use FederationLib\Enums\ContentType;
    use FederationLib\Enums\IncidentType;
    use FederationLib\Exceptions\RequestException;
    use FederationLib\FederationClient;
    use PHPUnit\Framework\Attributes\DataProvider;
    use PHPUnit\Framework\Attributes\Group;
    use PHPUnit\Framework\TestCase;

    /**
     * Tests the plugin in the running FederationLib server (make test-env), only through FederationLib's public API.
     * The server's and the plugin's configurations are their defaults, the plugin discovers its lists in the real
     * FilterLists directory (EasyList, EasyPrivacy and AdGuard's base and tracking filters) and downloads the real lists.
     * The hosts are ones the lists are known to block, update them when a list changes upstream.
     */
    #[Group('integration')]
    class FederationServerTest extends TestCase
    {
        private FederationClient $client;

        protected function setUp(): void
        {
            $endpoint = getenv('SERVER_ENDPOINT') ?: 'http://172.17.0.1:7000';
            $this->client = new FederationClient($endpoint, getenv('SERVER_ACCESS_TOKEN') ?: null);
            try
            {
                $this->client->getServerInformation();
            }
            catch(RequestException $e)
            {
                $this->fail(sprintf('FederationLib is not reachable at %s (set SERVER_ENDPOINT), start the test environment with "make test-env": %s', $endpoint, $e->getMessage()));
            }
        }

        /**
         * Hosts the default lists block entirely
         *
         * @return array<string, array{string, IncidentType}>
         */
        public static function listedHosts(): array
        {
            return [
                // ||pagead2.googlesyndication.com^ in EasyList
                'advertising' => ['pagead2.googlesyndication.com', IncidentType::ADVERTISING],
                // ||adnxs.com^ in EasyList and AdGuard's base filter
                'advertising in two lists' => ['adnxs.com', IncidentType::ADVERTISING],
                // ||mc.yandex.ru^ in EasyPrivacy
                'tracking' => ['mc.yandex.ru', IncidentType::TRACKING],
                // ||google-analytics.com^ in AdGuard's tracking filter
                'tracking in AdGuard' => ['www.google-analytics.com', IncidentType::TRACKING],
            ];
        }

        /**
         * Reads the actual API response, including recommendations which the PHP client otherwise recomputes
         *
         * @param string $method The HTTP method
         * @param string $path The API path, including query parameters
         * @param array|null $data The JSON request body
         * @return array The response
         */
        private function request(string $method, string $path, ?array $data=null): array
        {
            $ch = curl_init(rtrim($this->client->getEndpoint(), '/') . '/' . ltrim($path, '/'));
            $headers = ['Accept: application/json', 'Authorization: Bearer ' . $this->client->getAccessToken()];
            if($data !== null)
            {
                $headers[] = 'Content-Type: application/json';
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data, JSON_THROW_ON_ERROR));
            }
            curl_setopt_array($ch, [
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 120,
            ]);
            $body = curl_exec($ch);
            $this->assertNotFalse($body, curl_error($ch));
            $this->assertSame(200, (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE), (string)$body);
            $response = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
            $this->assertIsArray($response);
            return $response;
        }

        private function scan(string $text, ContentType $contentType, array $concerns, ?string $author=null): array
        {
            $data = ['evidence' => ['text_content' => $text, 'content_type' => $contentType->value], 'concerns' => array_map(fn(IncidentType $concern) => $concern->value, $concerns)];
            if($author !== null)
            {
                $data['author'] = $author;
            }

            return $this->request('POST', 'scan', $data);
        }

        private static function detections(array $result, IncidentType $concern): array
        {
            return array_values(array_filter($result['detections'], fn(array $detection) => $detection['concern'] === $concern->value));
        }

        #[DataProvider('listedHosts')]
        public function testListedHostnamesAreBlocked(string $host, IncidentType $concern): void
        {
            // The first scan records the host, the second uses its blacklist record: both block the same way
            for($i = 0; $i < 2; $i++)
            {
                $result = $this->scan($host, ContentType::HOSTNAME, [$concern]);
                $this->assertNotEmpty(self::detections($result, $concern), sprintf('%s was not detected as %s', $host, $concern->value));
                $this->assertSame('BLOCK_CONTENT', $result['suggested_action']);
                // At least the plugin's points, FederationLib also lowers the reputation of a blacklisted entity
                $this->assertGreaterThanOrEqual(84.5, $result['risk_score']);
            }

            $query = $this->request('GET', 'entities/' . rawurlencode($host) . '/query?concerns=' . $concern->value);
            $this->assertSame('PERMANENTLY_BLOCK_ENTITY', $query['suggested_action']);
            $records = array_values(array_filter($query['active_blacklists'], fn(array $record) => $record['type'] === $concern->value));
            $this->assertNotEmpty($records, sprintf('%s was not blacklisted for %s', $host, $concern->value));
            foreach($records as $record)
            {
                $this->assertSame($query['entity_record']['uuid'], $record['entity']);
                $this->assertFalse($record['lifted']);
                $this->assertNull($record['expires']);
            }

            // Nothing about another concern from the plugin, FederationLib's own lowered reputation may still caution
            $excluded = $this->scan($host, ContentType::HOSTNAME, [IncidentType::MALWARE]);
            $this->assertSame([], $excluded['detections']);
            $this->assertEmpty(array_filter(array_keys($excluded['scan_results']), fn(string $rule) => str_starts_with($rule, 'ADGUARD_')));
        }

        #[DataProvider('listedHosts')]
        public function testListedUrlsAreDetected(string $host, IncidentType $concern): void
        {
            $result = $this->scan('https://' . $host . '/', ContentType::URL, [$concern]);
            $this->assertNotEmpty(self::detections($result, $concern));
        }

        public function testPartialRulesOnlyCountForUrls(): void
        {
            // EasyPrivacy restricts the rule to third-party requests (|https://a.pr-cy.ru^$third-party), a DNS lookup
            // can't be checked against it
            $result = $this->scan('a.pr-cy.ru', ContentType::HOSTNAME, [IncidentType::TRACKING]);
            $this->assertSame([], self::detections($result, IncidentType::TRACKING));

            $result = $this->scan('https://a.pr-cy.ru/collect.js', ContentType::URL, [IncidentType::TRACKING]);
            $detections = self::detections($result, IncidentType::TRACKING);
            $this->assertNotEmpty($detections);
            foreach($detections as $detection)
            {
                $this->assertSame(0.5, $detection['confidence']);
            }
        }

        public function testExceptionsUnblock(): void
        {
            // AdGuard's tracking filter blocks the domain and unblocks the subdomain, @@||redirect.appmetrica.yandex.net^
            $this->assertNotEmpty(self::detections($this->scan('mc.appmetrica.yandex.net', ContentType::HOSTNAME, [IncidentType::TRACKING]), IncidentType::TRACKING));
            $result = $this->scan('redirect.appmetrica.yandex.net', ContentType::HOSTNAME, [IncidentType::TRACKING]);
            $this->assertSame([], self::detections($result, IncidentType::TRACKING));
        }

        public function testUnlistedHostsLowerTheRisk(): void
        {
            $host = 'adguard-' . bin2hex(random_bytes(8)) . '.invalid';
            $result = $this->scan($host, ContentType::HOSTNAME, [IncidentType::ADVERTISING, IncidentType::TRACKING]);
            $this->assertSame([], $result['detections']);
            $this->assertNull($result['suggested_action']);
            $this->assertEquals(2.0, $result['scan_results']['ADGUARD_UNLISTED']);
            $this->assertEqualsWithDelta(45.4, $result['risk_score'], 0.01);

            // A message without links gives the plugin nothing to say
            $result = $this->scan('Hello, how are you?', ContentType::TEXT, [IncidentType::ADVERTISING, IncidentType::TRACKING]);
            $this->assertArrayNotHasKey('ADGUARD_UNLISTED', $result['scan_results']);
        }

        public function testCombinedRequestIdentifiesEachRequestedConcern(): void
        {
            $information = $this->request('GET', 'info');
            $this->assertContains('ADVERTISING', $information['concerns']);
            $this->assertContains('TRACKING', $information['concerns']);
            $result = $this->request('POST', 'scan', [
                'evidence' => [
                    ['text_content' => 'pagead2.googlesyndication.com', 'content_type' => 'HOSTNAME'],
                    ['text_content' => 'mc.yandex.ru', 'content_type' => 'HOSTNAME'],
                ],
                'concerns' => ['ADVERTISING', 'TRACKING'],
            ]);
            foreach([0 => 'ADVERTISING', 1 => 'TRACKING'] as $index => $concern)
            {
                $this->assertNotEmpty(array_filter($result['detections'],
                    fn(array $detection) => $detection['concern'] === $concern && $detection['content_index'] === $index));
            }
            $this->assertSame('BLOCK_CONTENT', $result['suggested_action']);
        }

        public function testAuthorsOfAdSpamAreRecorded(): void
        {
            $author = 'spammer-' . bin2hex(random_bytes(6)) . '@chat.invalid';
            $message = 'Deals! https://pagead2.googlesyndication.com/offer https://adnxs.com/now';

            // The message is spam for a client that only asks about spam, a first offence only gives the author evidence
            $first = $this->scan($message, ContentType::TEXT, [IncidentType::SPAM], $author);
            $this->assertEquals(-10.0, $first['scan_results']['ADGUARD_LINK_SPAM']);
            // At least a caution, the reputation FederationLib lowers for the blacklisted hosts adds to it
            $this->assertContains($first['suggested_action'], ['CAUTION', 'BLOCK_CONTENT']);

            // A repeat offence blacklists the author temporarily, their next message suggests blocking them for a while
            $this->scan($message, ContentType::TEXT, [IncidentType::SPAM], $author);
            $third = $this->scan('Hello again', ContentType::TEXT, [IncidentType::SPAM], $author);
            $this->assertSame('TEMPORARILY_BLOCK_ENTITY', $third['suggested_action']);
            $this->assertNotNull($third['suggested_lift_timestamp']);

            // Sharing one listed link is no offence
            $other = 'member-' . bin2hex(random_bytes(6)) . '@chat.invalid';
            for($i = 0; $i < 2; $i++)
            {
                $result = $this->scan('Look at https://pagead2.googlesyndication.com/offer', ContentType::TEXT, [IncidentType::SPAM], $other);
                $this->assertArrayNotHasKey('ADGUARD_LINK_SPAM', $result['scan_results']);
            }
            $this->assertNull($this->scan('Hello', ContentType::TEXT, [IncidentType::SPAM], $other)['suggested_action']);
        }

        public function testDisabledOperatorDisablesThePlugin(): void
        {
            $operators = array_values(array_filter($this->client->listOperators(limit: 100), fn($operator) => $operator->getName() === 'FederationAdGuard'));
            $this->assertCount(1, $operators, 'The FederationAdGuard operator was not provisioned');
            $operator = $operators[0];
            // A subdomain no earlier run recorded, ||g.doubleclick.net^ in EasyList blocks it. No other test blacklists
            // its parent, FederationLib would otherwise detect it through the parent's blacklist record
            $host = 'x' . bin2hex(random_bytes(6)) . '.g.doubleclick.net';

            // The soft switch, an administrator disables the operator through the federation interface
            $this->client->disableOperator($operator->getUuid());
            try
            {
                $result = $this->scan($host, ContentType::HOSTNAME, [IncidentType::ADVERTISING]);
                $this->assertSame([], $result['detections']);
                $this->assertEmpty(array_filter(array_keys($result['scan_results']), fn(string $rule) => str_starts_with($rule, 'ADGUARD_')));
                // FederationLib itself keeps working
                $this->assertArrayHasKey('risk_score', $result);
            }
            finally
            {
                $this->client->enableOperator($operator->getUuid());
            }

            // Enabled again, the plugin resumes
            $this->assertNotEmpty(self::detections($this->scan($host, ContentType::HOSTNAME, [IncidentType::ADVERTISING]), IncidentType::ADVERTISING));
        }
    }
