<?php

    namespace FederationAdGuard\Classes\Configuration;

    class ScanningConfiguration
    {
        /**
         * The maximum number of links matched of each evidence item
         */
        public const int MAX_LINKS = 25;

        /**
         * The confidence of a detection made by a rule restricted to some requests (e.g., $third-party), its points are
         * weighted by it too
         */
        public const float PARTIAL_CONFIDENCE = 0.5;

        /**
         * The share of unlisted_points a message whose links are all unlisted contributes, links count a third of the
         * hosts and URLs that were submitted themselves, like link_points and points
         */
        public const float UNLISTED_LINK_SHARE = 1 / 3;

        /**
         * The distinct listed hosts a message has to link to before it counts as spam
         */
        public const int SPAM_MIN_HOSTS = 2;

        /**
         * The share of the distinct hosts a message links to that have to be listed before it counts as spam
         */
        public const float SPAM_MIN_SHARE = 0.8;

        private float $points;
        private float $linkPoints;
        private float $unlistedPoints;
        private float $spamPoints;

        /**
         * ScanningConfiguration constructor.
         *
         * @param array $configuration The values of the `scanning` section
         */
        public function __construct(array $configuration)
        {
            // Listings only ever raise the risk score and an unlisted host only ever lowers it
            $this->points = min(0.0, self::parseFloat($configuration['points'] ?? null, -15.0));
            $this->linkPoints = min(0.0, self::parseFloat($configuration['link_points'] ?? null, -5.0));
            $this->unlistedPoints = max(0.0, self::parseFloat($configuration['unlisted_points'] ?? null, 2.0));
            $this->spamPoints = min(0.0, self::parseFloat($configuration['spam_points'] ?? null, -10.0));
        }

        /**
         * Returns the points of a listed host, URL or page that was submitted itself
         *
         * @return float The points, 0 or negative
         */
        public function getPoints(): float
        {
            return $this->points;
        }

        /**
         * Returns the points of a listed link mentioned in a message
         *
         * @return float The points, 0 or negative
         */
        public function getLinkPoints(): float
        {
            return $this->linkPoints;
        }

        /**
         * Returns the points of a scan whose hosts and URLs were checked and none of them is listed
         *
         * @return float The points, 0 or positive
         */
        public function getUnlistedPoints(): float
        {
            return $this->unlistedPoints;
        }

        /**
         * Returns the points of a message that is mostly listed links, they count as SPAM
         *
         * @return float The points, 0 or negative
         */
        public function getSpamPoints(): float
        {
            return $this->spamPoints;
        }

        /**
         * Parses a number, values set by environment variables are strings
         *
         * @param mixed $value The configured value
         * @param float $default The value when nothing valid is configured
         * @return float The number
         */
        private static function parseFloat(mixed $value, float $default): float
        {
            return is_numeric($value) && is_finite((float)$value) ? (float)$value : $default;
        }
    }
