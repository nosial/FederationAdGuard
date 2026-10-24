<?php

    namespace FederationAdGuard\Objects;

    class DownloadResult
    {
        private ?string $contents;
        private ?string $etag;
        private ?string $lastModified;

        /**
         * DownloadResult constructor
         *
         * @param string|null $contents The contents, null if the server said they're unchanged (HTTP 304)
         * @param string|null $etag The ETag of the response
         * @param string|null $lastModified The Last-Modified of the response
         */
        public function __construct(?string $contents, ?string $etag=null, ?string $lastModified=null)
        {
            $this->contents = $contents;
            $this->etag = $etag;
            $this->lastModified = $lastModified;
        }

        /**
         * @return string|null The contents, null if unchanged
         */
        public function getContents(): ?string
        {
            return $this->contents;
        }

        /**
         * @return bool True if the server said the contents are unchanged
         */
        public function isNotModified(): bool
        {
            return $this->contents === null;
        }

        /**
         * @return array{etag?: string, last_modified?: string} The validators of a later conditional download
         */
        public function getValidators(): array
        {
            return array_filter(['etag' => $this->etag, 'last_modified' => $this->lastModified], fn($value) => $value !== null && $value !== '');
        }
    }
