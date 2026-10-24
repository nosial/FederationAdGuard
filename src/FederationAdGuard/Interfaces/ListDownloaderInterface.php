<?php

    namespace FederationAdGuard\Interfaces;

    use FederationAdGuard\Exceptions\DownloadException;
    use FederationAdGuard\Objects\DownloadResult;

    interface ListDownloaderInterface
    {
        /**
         * Downloads a URL
         *
         * @param string $url The HTTP or HTTPS URL
         * @param array{etag?: string, last_modified?: string} $validators The validators of the previous download, to
         *        download the contents only if they changed
         * @param string $accept The media types accepted
         * @return DownloadResult The result
         * @throws DownloadException If the URL could not be downloaded
         */
        public function download(string $url, array $validators=[], string $accept='text/plain, */*'): DownloadResult;
    }
