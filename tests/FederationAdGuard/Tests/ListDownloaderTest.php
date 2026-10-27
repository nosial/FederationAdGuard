<?php

    namespace FederationAdGuard\Tests;

    use FederationAdGuard\Classes\ListDownloader;
    use FederationAdGuard\Exceptions\ListException;
    use PHPUnit\Framework\TestCase;

    /**
     * Only the validation of URLs is tested, nothing is downloaded
     */
    class ListDownloaderTest extends TestCase
    {
        public function testRejectsUrls(): void
        {
            $cases = [
                'ftp://203.0.113.1/list.txt' => 'Only HTTP and HTTPS',
                'https://user:pass@203.0.113.1/list.txt' => 'credentials',
                'not a url' => 'valid URL',
                // Addresses that are not publicly routable are refused unless lists.allow_private
                'http://127.0.0.1/list.txt' => 'not publicly routable',
                'http://[::1]/list.txt' => 'not publicly routable',
                'http://10.0.0.1/list.txt' => 'not publicly routable',
            ];

            foreach($cases as $url => $reason)
            {
                try
                {
                    ListDownloader::resolveTarget($url, false);
                    $this->fail('Expected the URL to be rejected: ' . $url);
                }
                catch(ListException $e)
                {
                    $this->assertStringContainsString($reason, $e->getMessage(), $url);
                }
            }
        }

        public function testNormalizesUrls(): void
        {
            $target = ListDownloader::resolveTarget('http://127.0.0.1:8080/lists/1?x=1', true);
            $this->assertSame('http://127.0.0.1:8080/lists/1?x=1', $target['url']);
            $this->assertSame(8080, $target['port']);
            $this->assertNull($target['address']);

            // Some of the directory's list URLs contain spaces, what is already encoded stays as it is
            $target = ListDownloader::resolveTarget('http://127.0.0.1/Ancient Library/Filter JP?a=b c&d=%20', true);
            $this->assertSame('http://127.0.0.1/Ancient%20Library/Filter%20JP?a=b%20c&d=%20', $target['url']);
            $this->assertSame('http://127.0.0.1/100%25/l%C3%BCste.txt', ListDownloader::resolveTarget('http://127.0.0.1/100%/lüste.txt', true)['url']);

            $this->assertSame('https://example.com/a/b.txt', ListDownloader::resolveRedirect('https://example.com/a/list.txt', 'b.txt'));
            $this->assertSame('https://example.com/b.txt', ListDownloader::resolveRedirect('https://example.com/a/list.txt', '/b.txt'));
            $this->assertSame('https://cdn.example.com/b.txt', ListDownloader::resolveRedirect('https://example.com/a/list.txt', '//cdn.example.com/b.txt'));
        }
    }
