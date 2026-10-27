<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Enums\TargetRole;
    use FederationAdGuard\Objects\MatchTarget;
    use FederationLib\Enums\ContentType;
    use FederationLib\Enums\NamedEntityType;
    use FederationLib\Objects\Plugin\ContentScan;

    class TargetExtractor
    {
        /**
         * Returns the targets of every evidence item of a scan
         *
         * @param ContentScan $contentScan The scan
         * @param int $maxLinks The maximum number of links per evidence item
         * @return MatchTarget[] The targets
         */
        public static function extract(ContentScan $contentScan, int $maxLinks): array
        {
            $targets = [];
            foreach($contentScan->getEvidence() as $index => $contentInput)
            {
                $textContent = $contentInput->getTextContent();
                $context = $contentInput->getContext() ?? [];
                $addresses = $contentScan->getResolvedAddresses($index);

                switch($contentInput->getContentType())
                {
                    case ContentType::HOSTNAME:
                        if($textContent !== null)
                        {
                            $targets[] = MatchTarget::fromHost($textContent, $context['query_type'] ?? null, $addresses, TargetRole::SUBJECT, true, $index);
                        }
                        continue 2;

                    case ContentType::URL:
                        if($textContent !== null)
                        {
                            $targets[] = MatchTarget::fromUrl($textContent, $addresses, TargetRole::SUBJECT, true, $index);
                        }
                        continue 2;

                    case ContentType::WEB_PAGE:
                        // The page is what the client says it visited, FederationLib resolved the addresses of its host
                        if(isset($context['url']))
                        {
                            $targets[] = MatchTarget::fromUrl($context['url'], $addresses, TargetRole::SUBJECT, false, $index);
                        }

                        if(isset($context['final_url']) && $context['final_url'] !== ($context['url'] ?? null))
                        {
                            $targets[] = MatchTarget::fromUrl($context['final_url'], [], TargetRole::SUBJECT, false, $index);
                        }
                        break;

                    default:
                        break;
                }

                if($textContent !== null && $textContent !== '')
                {
                    $region = $contentInput->getContentType() === ContentType::SMS ? ($context['region'] ?? null) : null;
                    array_push($targets, ...self::extractLinks($textContent, $index, $maxLinks, $region));
                }
            }

            return array_values(array_filter($targets));
        }

        /**
         * Returns the links, domains and IP addresses mentioned in a text
         *
         * @param string $text The text
         * @param int $index The index of the evidence item
         * @param int $maxLinks The maximum number of targets
         * @param string|null $region The region an SMS was received in
         * @return MatchTarget[] The targets
         */
        private static function extractLinks(string $text, int $index, int $maxLinks, ?string $region=null): array
        {
            if($maxLinks < 1)
            {
                return [];
            }

            $targets = [];
            foreach(NamedEntityType::extract($text, $region) as $identifier => $position)
            {
                $identifier = (string)$identifier;
                $target = match($position->getType())
                {
                    NamedEntityType::URL => MatchTarget::fromUrl($identifier, [], TargetRole::LINK, true, $index),
                    NamedEntityType::DOMAIN, NamedEntityType::IPv4, NamedEntityType::IPv6 => MatchTarget::fromHost($identifier, null, [], TargetRole::LINK, true, $index),
                    default => null,
                };

                if($target === null)
                {
                    continue;
                }

                $targets[$target->getUrl() ?? $target->getHost()] = $target;
                if(count($targets) >= $maxLinks)
                {
                    break;
                }
            }

            return array_values($targets);
        }
    }
