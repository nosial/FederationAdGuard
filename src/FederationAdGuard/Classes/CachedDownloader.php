<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Exceptions\DownloadException;
    use FederationAdGuard\Interfaces\ListDownloaderInterface;
    use FederationAdGuard\Objects\DownloadResult;
    use JsonException;

    class CachedDownloader implements ListDownloaderInterface
    {
        private ListDownloaderInterface $downloader;
        private string $directory;
        private int $ttl;
        private int $retryInterval;

        /**
         * CachedDownloader constructor.
         *
         * @param ListDownloaderInterface $downloader The real transport used when a response expires
         * @param string $directory The shared cache directory
         * @param int $ttl The lifetime of successful responses in seconds
         * @param int $retryInterval The backoff after failed requests in seconds
         */
        public function __construct(ListDownloaderInterface $downloader, string $directory, int $ttl=86400, int $retryInterval=300)
        {
            $this->downloader = $downloader;
            $this->directory = $directory;
            $this->ttl = max(1, $ttl);
            $this->retryInterval = max(1, $retryInterval);
        }

        /**
         * @inheritDoc
         */
        public function download(string $url, array $validators=[], string $accept='text/plain, */*'): DownloadResult
        {
            if(!is_dir($this->directory) && !@mkdir($this->directory, 0700, true) && !is_dir($this->directory))
            {
                throw new DownloadException('Unable to create the download cache directory');
            }

            $key = hash('sha256', $url . "\n" . $accept);
            $path = $this->directory . DIRECTORY_SEPARATOR . $key . '.json';
            $lock = @fopen($path . '.lock', 'c');
            if($lock === false)
            {
                throw new DownloadException('Unable to open the download cache lock');
            }

            try
            {
                if(!flock($lock, LOCK_EX))
                {
                    throw new DownloadException('Unable to lock the download cache');
                }

                $cached = is_file($path) ? json_decode((string)file_get_contents($path), true) : null;
                $cached = is_array($cached) ? $cached : [];
                if((isset($cached['contents']) && (!is_string($cached['contents']) || base64_decode($cached['contents'], true) === false))
                    || !is_array($cached['validators'] ?? [])
                    || array_filter($cached['validators'] ?? [], static fn($value) => !is_string($value)) !== []
                    || !is_int($cached['expires'] ?? 0)
                    || !is_int($cached['retry_after'] ?? 0)
                    || !is_string($cached['error'] ?? '')
                    || !is_int($cached['code'] ?? 0))
                {
                    $cached = [];
                }
                if(($cached['retry_after'] ?? 0) > time())
                {
                    throw new DownloadException('Cached download failure: ' . ($cached['error'] ?? 'unknown error'), (int)($cached['code'] ?? 0));
                }

                if(!isset($cached['contents']) || ($cached['expires'] ?? 0) <= time())
                {
                    try
                    {
                        $result = $this->downloader->download($url, isset($cached['contents']) ? ($cached['validators'] ?? []) : [], $accept);
                        if($result->isNotModified() && !isset($cached['contents']))
                        {
                            throw new DownloadException('Received HTTP 304 without cached contents');
                        }
                        $cached = [
                            'contents' => $result->isNotModified() ? $cached['contents'] : base64_encode($result->getContents()),
                            'validators' => array_merge($result->isNotModified() ? ($cached['validators'] ?? []) : [], $result->getValidators()),
                            'expires' => time() + max(1, $this->ttl),
                        ];
                    }
                    catch(DownloadException $e)
                    {
                        $cached['retry_after'] = time() + max(1, $this->retryInterval);
                        $cached['error'] = $e->getMessage();
                        $cached['code'] = $e->getCode();
                        self::write($path, $cached);
                        throw $e;
                    }

                    self::write($path, $cached);
                }

                $stored = $cached['validators'] ?? [];
                $unchanged = isset($validators['etag'], $stored['etag'])
                    ? $validators['etag'] === $stored['etag']
                    : !isset($validators['etag']) && isset($validators['last_modified'], $stored['last_modified']) && $validators['last_modified'] === $stored['last_modified'];
                $contents = base64_decode($cached['contents'], true);
                if($contents === false)
                {
                    throw new DownloadException('The cached response is corrupt');
                }

                return new DownloadResult($unchanged ? null : $contents, $stored['etag'] ?? null, $stored['last_modified'] ?? null);
            }
            finally
            {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        }

        /**
         * Replaces a cache entry while its request lock is held.
         *
         * @param string $path The cache file
         * @param array $data The response or retry state
         * @throws DownloadException If the cache cannot be encoded or saved
         * @return void
         */
        private static function write(string $path, array $data): void
        {
            try
            {
                $encoded = json_encode($data, JSON_THROW_ON_ERROR);
            }
            catch(JsonException $e)
            {
                throw new DownloadException('Unable to encode the download cache', 0, $e);
            }

            $temporary = $path . '.tmp';
            if(file_put_contents($temporary, $encoded) === false || !rename($temporary, $path))
            {
                throw new DownloadException('Unable to save the download cache');
            }
        }
    }
