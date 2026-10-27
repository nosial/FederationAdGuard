<?php

    namespace FederationAdGuard\Tests;

    use FederationAdGuard\Classes\CachedDownloader;
    use FederationAdGuard\Exceptions\ListException;
    use FederationAdGuard\Interfaces\ListDownloaderInterface;
    use FederationAdGuard\Objects\DownloadResult;
    use PHPUnit\Framework\TestCase;

    /** Cache mechanics are independent of directory or publisher response formats. */
    class CachedDownloaderTest extends TestCase
    {
        private string $directory;

        protected function setUp(): void
        {
            $this->directory = sys_get_temp_dir() . '/adguard-cache-' . bin2hex(random_bytes(8));
        }

        protected function tearDown(): void
        {
            foreach(glob($this->directory . '/*') as $file)
            {
                unlink($file);
            }
            if(is_dir($this->directory))
            {
                rmdir($this->directory);
            }
        }

        public function testNewClientsReuseResponseAndRespectValidators(): void
        {
            $transport = $this->createMock(ListDownloaderInterface::class);
            $transport->expects($this->once())->method('download')->willReturn(new DownloadResult('contents', 'version-1'));
            $first = new CachedDownloader($transport, $this->directory);
            self::assertSame('contents', $first->download('https://example.com/list')->getContents());
            $second = new CachedDownloader($transport, $this->directory);
            self::assertSame('contents', $second->download('https://example.com/list')->getContents());
            self::assertTrue($second->download('https://example.com/list', ['etag' => 'version-1'])->isNotModified());
            self::assertSame('contents', $second->download('https://example.com/list', ['etag' => 'older'])->getContents());
        }

        public function testFailedRequestsAreThrottledAcrossClients(): void
        {
            $transport = $this->createMock(ListDownloaderInterface::class);
            $transport->expects($this->once())->method('download')->willThrowException(new ListException('unavailable', 503));
            for($i = 0; $i < 2; $i++)
            {
                try
                {
                    (new CachedDownloader($transport, $this->directory))->download('https://example.com/list');
                    self::fail('A failed refresh must not be reported as a successful test');
                }
                catch(ListException $e)
                {
                    self::assertSame(503, $e->getCode());
                    self::assertStringContainsString('unavailable', $e->getMessage());
                }
            }
        }

        public function testCorruptResponseIsRefetchedWithoutValidators(): void
        {
            $transport = $this->createMock(ListDownloaderInterface::class);
            $transport->expects($this->exactly(2))->method('download')
                ->with('https://example.com/list', [], 'text/plain, */*')
                ->willReturn(new DownloadResult('contents', 'version-1'));
            $cache = new CachedDownloader($transport, $this->directory);
            $cache->download('https://example.com/list');
            $path = glob($this->directory . '/*.json')[0];
            $data = json_decode(file_get_contents($path), true);
            $data['contents'] = ['invalid'];
            file_put_contents($path, json_encode($data));
            self::assertSame('contents', $cache->download('https://example.com/list')->getContents());
        }

        public function testInvalidValidatorEncodingIsADownloadFailure(): void
        {
            $transport = $this->createMock(ListDownloaderInterface::class);
            $transport->expects($this->once())->method('download')->willReturn(new DownloadResult('contents', "\xFF"));
            $this->expectException(ListException::class);
            $this->expectExceptionMessage('Unable to encode the download cache');
            (new CachedDownloader($transport, $this->directory))->download('https://example.com/list');
        }

        public function testExpiredResponseIsConditionallyRefreshed(): void
        {
            $transport = $this->createMock(ListDownloaderInterface::class);
            $transport->expects($this->exactly(2))->method('download')->willReturnCallback(
                function(string $url, array $validators): DownloadResult
                {
                    return $validators === [] ? new DownloadResult('contents', 'version-1') : new DownloadResult(null, 'version-1');
                }
            );
            $cache = new CachedDownloader($transport, $this->directory);
            $cache->download('https://example.com/list');
            $path = glob($this->directory . '/*.json')[0];
            $data = json_decode(file_get_contents($path), true);
            $data['expires'] = 0;
            file_put_contents($path, json_encode($data));
            self::assertSame('contents', $cache->download('https://example.com/list')->getContents());
            self::assertGreaterThan(time(), json_decode(file_get_contents($path), true)['expires']);
        }
    }
