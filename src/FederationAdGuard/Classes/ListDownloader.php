<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Classes\Configuration\ListsConfiguration;
    use FederationAdGuard\Exceptions\ListException;
    use FederationAdGuard\Interfaces\ListDownloaderInterface;
    use FederationAdGuard\Objects\DownloadResult;

    class ListDownloader implements ListDownloaderInterface
    {
        private const int URL_MAX_LENGTH = 2048;
        private const int MAX_REDIRECTS = 5;
        private const string USER_AGENT = 'FederationAdGuard/1.0 (FederationLib)';

        private int $maxSize;
        private int $timeout;
        private int $connectTimeout;
        private bool $allowPrivate;

        /**
         * ListDownloader constructor, the limits default to the plugin's configuration
         *
         * @param int|null $maxSize The maximum size of the contents in bytes
         * @param int|null $timeout The maximum number of seconds a download may take, including redirects
         * @param int|null $connectTimeout The maximum number of seconds to wait for a connection
         * @param bool|null $allowPrivate True to allow URLs that resolve to non-public addresses
         */
        public function __construct(?int $maxSize=null, ?int $timeout=null, ?int $connectTimeout=null, ?bool $allowPrivate=null)
        {
            $this->maxSize = $maxSize ?? ListsConfiguration::MAX_SIZE;
            $this->timeout = $timeout ?? ListsConfiguration::DOWNLOAD_TIMEOUT;
            $this->connectTimeout = $connectTimeout ?? ListsConfiguration::CONNECT_TIMEOUT;
            $this->allowPrivate = $allowPrivate ?? Configuration::getListsConfiguration()->isPrivateAllowed();
        }

        /**
         * @inheritDoc
         */
        public function download(string $url, array $validators=[], string $accept='text/plain, */*'): DownloadResult
        {
            $deadline = time() + max(1, $this->timeout);

            for($redirects = 0; ; $redirects++)
            {
                $target = self::resolveTarget($url, $this->allowPrivate);
                $url = $target['url'];

                $remaining = $deadline - time();
                if($remaining <= 0)
                {
                    throw new ListException('Timed out while downloading the list');
                }

                $headers = [];
                $contents = '';
                $exceeded = false;
                $maxSize = $this->maxSize;

                $requestHeaders = ['Accept: ' . $accept];
                if(isset($validators['etag']))
                {
                    $requestHeaders[] = 'If-None-Match: ' . $validators['etag'];
                }
                if(isset($validators['last_modified']))
                {
                    $requestHeaders[] = 'If-Modified-Since: ' . $validators['last_modified'];
                }

                Logger::log()->debug(sprintf('Downloading %s%s', $url, count($requestHeaders) > 1 ? ' (conditional)' : ''));
                $ch = curl_init($url);
                if($ch === false)
                {
                    throw new ListException('Unable to download the list');
                }

                curl_setopt_array($ch, [
                    CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_NOPROXY => '*',
                    CURLOPT_CONNECTTIMEOUT => min($this->connectTimeout, $remaining),
                    CURLOPT_TIMEOUT => $remaining,
                    // Accept every encoding curl supports, the size limit applies to the decoded contents
                    CURLOPT_ENCODING => '',
                    CURLOPT_USERAGENT => self::USER_AGENT,
                    CURLOPT_HTTPHEADER => $requestHeaders,
                    CURLOPT_HEADERFUNCTION => function($ch, string $line) use (&$headers): int
                    {
                        if(str_starts_with($line, 'HTTP/'))
                        {
                            $headers = [];
                        }
                        elseif(str_contains($line, ':'))
                        {
                            [$name, $value] = explode(':', $line, 2);
                            $headers[strtolower(trim($name))] = trim($value);
                        }

                        return strlen($line);
                    },
                    CURLOPT_WRITEFUNCTION => function($ch, string $data) use (&$contents, &$exceeded, $maxSize): int
                    {
                        if(strlen($contents) + strlen($data) > $maxSize)
                        {
                            $exceeded = true;
                            return 0;
                        }

                        $contents .= $data;
                        return strlen($data);
                    },
                ]);

                // Pin the connection to the validated address, so the host isn't resolved a second time
                if($target['address'] !== null)
                {
                    $address = str_contains($target['address'], ':') ? '[' . $target['address'] . ']' : $target['address'];
                    curl_setopt($ch, CURLOPT_RESOLVE, [sprintf('%s:%d:%s', $target['host'], $target['port'], $address)]);
                }

                curl_exec($ch);
                $errorCode = curl_errno($ch);
                $error = curl_error($ch);
                $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

                if($exceeded)
                {
                    throw new ListException(sprintf('The list exceeds the maximum size of %d bytes', $this->maxSize));
                }

                if($errorCode !== 0)
                {
                    throw new ListException(sprintf('Unable to download %s: %s', $url, $error));
                }

                if(in_array($status, [301, 302, 303, 307, 308], true) && !empty($headers['location']))
                {
                    if($redirects >= self::MAX_REDIRECTS)
                    {
                        throw new ListException('The URL redirected too many times');
                    }

                    $url = self::resolveRedirect($url, $headers['location']);
                    Logger::log()->debug(sprintf('Following the HTTP %d redirect to %s', $status, $url));
                    continue;
                }

                if($status === 304)
                {
                    Logger::log()->debug(sprintf('%s was not modified (HTTP 304)', $url));
                    return new DownloadResult(null, $headers['etag'] ?? $validators['etag'] ?? null, $headers['last-modified'] ?? $validators['last_modified'] ?? null);
                }

                if($status < 200 || $status >= 300)
                {
                    // The status is the code of the exception, e.g., 404 for a list that no longer exists
                    throw new ListException(sprintf('%s responded with HTTP status %d', $url, $status), $status);
                }

                Logger::log()->debug(sprintf('Downloaded %s: HTTP %d, %d bytes', $url, $status, strlen($contents)));
                return new DownloadResult($contents, $headers['etag'] ?? null, $headers['last-modified'] ?? null);
            }
        }

        /**
         * Validates a URL and resolves its host, rejecting URLs that aren't HTTP or HTTPS, carry credentials, or
         * resolve to an address that isn't publicly routable (unless permitted)
         *
         * @param string $url The URL
         * @param bool $allowPrivate True to allow non-public addresses
         * @return array{url: string, host: string, port: int, address: string|null} The normalized URL, its host and
         *         port, and the address to connect to (null when the host is an IP address literal)
         * @throws ListException If the URL is not valid or not permitted
         */
        public static function resolveTarget(string $url, bool $allowPrivate): array
        {
            if(strlen($url) > self::URL_MAX_LENGTH)
            {
                throw new ListException(sprintf('The URL exceeds the maximum length of %d characters', self::URL_MAX_LENGTH));
            }

            $parts = parse_url($url);
            if($parts === false || !isset($parts['scheme'], $parts['host']))
            {
                throw new ListException('A valid URL is required');
            }

            $scheme = strtolower($parts['scheme']);
            if(!in_array($scheme, ['http', 'https'], true))
            {
                throw new ListException('Only HTTP and HTTPS URLs are supported');
            }

            if(isset($parts['user']) || isset($parts['pass']))
            {
                throw new ListException('URLs containing credentials are not supported');
            }

            $host = strtolower(trim($parts['host'], '[]'));
            $isAddress = filter_var($host, FILTER_VALIDATE_IP) !== false;
            if(!$isAddress && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false)
            {
                throw new ListException('A valid URL is required');
            }

            $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
            if($isAddress)
            {
                $addresses = [$host];
            }
            else
            {
                $addresses = gethostbynamel($host) ?: [];
                foreach(@dns_get_record($host, DNS_AAAA) ?: [] as $record)
                {
                    if(isset($record['ipv6']))
                    {
                        $addresses[] = $record['ipv6'];
                    }
                }
            }

            if(empty($addresses))
            {
                throw new ListException(sprintf('The host %s could not be resolved', $host));
            }

            if(!$allowPrivate)
            {
                foreach($addresses as $address)
                {
                    if(filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) === false)
                    {
                        throw new ListException(sprintf('The host %s resolves to an address that is not publicly routable', $host));
                    }
                }
            }

            // Rebuild the URL from the validated components, so the request can't target a different host than the
            // one that was validated due to URL parsing differences
            $authority = str_contains($host, ':') ? '[' . $host . ']' : $host;
            if(isset($parts['port']))
            {
                $authority .= ':' . $parts['port'];
            }

            $normalized = $scheme . '://' . $authority . self::encodeUnsafe($parts['path'] ?? '/');
            if(isset($parts['query']))
            {
                $normalized .= '?' . self::encodeUnsafe($parts['query']);
            }

            return [
                'url' => $normalized,
                'host' => $host,
                'port' => (int)$port,
                'address' => $isAddress ? null : $addresses[0],
            ];
        }

        /**
         * Percent-encodes the characters a URL can't contain as they are, e.g., the spaces in some of the directory's
         * list URLs, without encoding what is already encoded
         *
         * @param string $value The path or query of a URL
         * @return string The encoded path or query
         */
        private static function encodeUnsafe(string $value): string
        {
            return preg_replace_callback('#[^A-Za-z0-9\-._~!$&\'()*+,;=:@/?%]|%(?![0-9A-Fa-f]{2})#',
                fn(array $matches) => rawurlencode($matches[0]), $value);
        }

        /**
         * Resolves the Location header of a redirect against the URL that was requested
         *
         * @param string $baseUrl The normalized URL that was requested
         * @param string $location The value of the Location header
         * @return string The absolute URL to redirect to
         */
        public static function resolveRedirect(string $baseUrl, string $location): string
        {
            $location = trim($location);
            if(preg_match('#^[a-z][a-z0-9+.-]*:#i', $location))
            {
                return $location;
            }

            $base = parse_url($baseUrl);
            if(str_starts_with($location, '//'))
            {
                return $base['scheme'] . ':' . $location;
            }

            $origin = $base['scheme'] . '://' . $base['host'] . (isset($base['port']) ? ':' . $base['port'] : '');
            $path = $base['path'] ?? '/';
            if(str_starts_with($location, '/'))
            {
                return $origin . $location;
            }

            if(str_starts_with($location, '?'))
            {
                return $origin . $path . $location;
            }

            return $origin . preg_replace('#/[^/]*$#', '/', $path) . $location;
        }
    }
