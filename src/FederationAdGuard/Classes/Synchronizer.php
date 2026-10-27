<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Classes\Configuration\FilterListsConfiguration;
    use FederationAdGuard\Classes\Configuration\ListsConfiguration;
    use FederationAdGuard\Exceptions\ListException;
    use FederationAdGuard\Exceptions\RuleException;
    use FederationLib\Exceptions\CacheOperationException;
    use FederationAdGuard\Classes\Managers\RuleManager;
    use FederationAdGuard\Classes\Managers\SubscriptionManager;
    use FederationAdGuard\Enums\ListSource;
    use FederationAdGuard\Enums\ListSyntax;
    use FederationAdGuard\FederationAdGuard;
    use FederationAdGuard\Objects\DownloadResult;
    use FederationAdGuard\Objects\SubscriptionRecord;
    use FederationLib\Exceptions\DatabaseOperationException;
    use FederationLib\Enums\IncidentType;

    class Synchronizer
    {
        /**
         * Synchronizes the lists that are due
         *
         * @param bool $newOnly True to only download the lists that were never downloaded
         * @return array<int, array> The result of each list that was synchronized, by subscription ID
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         */
        public static function syncDue(bool $newOnly=false): array
        {
            // Shared with the provisioner, a maintenance run and a startup never update the same lists at the same time
            if(!DatabaseLock::acquire(DatabaseLock::SYNCHRONIZATION))
            {
                Logger::log()->info('The lists are already being synchronized by another process');
                return [];
            }

            try
            {
                $results = [];
                $now = time();
                foreach(SubscriptionManager::getSubscriptions() as $subscription)
                {
                    if($subscription->getSource() === ListSource::CUSTOM || !$subscription->isDue($now))
                    {
                        continue;
                    }

                    if($subscription->getSource() === ListSource::FILTERLISTS && !Configuration::getFilterListsConfiguration()->isEnabled())
                    {
                        continue;
                    }

                    if($newOnly && $subscription->getLastChecked() !== null && $subscription->getSource() !== ListSource::FILE)
                    {
                        continue;
                    }

                    $results[$subscription->getId()] = self::syncSubscription($subscription);
                }

                Logger::log()->debug(sprintf('Synchronized %d list(s)%s: %d updated, %d unchanged, %d failed', count($results), $newOnly ? ', new lists only' : '',
                    count(array_filter($results, fn(array $result) => $result['status'] === 'UPDATED')),
                    count(array_filter($results, fn(array $result) => $result['status'] === 'UNCHANGED')),
                    count(array_filter($results, fn(array $result) => $result['status'] === 'FAILED'))
                ));
                return $results;
            }
            finally
            {
                DatabaseLock::releaseQuietly(DatabaseLock::SYNCHRONIZATION);
            }
        }

        /**
         * Synchronizes a subscription while the caller holds the synchronization lock.
         *
         * @param SubscriptionRecord $subscription The subscription
         * @return array The synchronization result
         */
        private static function syncSubscription(SubscriptionRecord $subscription): array
        {
            Logger::log()->debug(sprintf('Synchronizing the list %s (%d) from %s', $subscription->getName(), $subscription->getId(),
                $subscription->getSource() === ListSource::FILTERLISTS ? sprintf('the FilterLists list %d', $subscription->getFilterListsId()) : $subscription->getLocation()));

            try
            {
                return match($subscription->getSource())
                {
                    ListSource::FILTERLISTS => self::syncFilterList($subscription),
                    ListSource::FILE => self::syncFile($subscription),
                    default => self::syncUrl($subscription),
                };
            }
            catch(ListException|RuleException|DatabaseOperationException|CacheOperationException $e)
            {
                Logger::log()->warning(sprintf('Unable to update the list %s (%d): %s', $subscription->getName(), $subscription->getId(), $e->getMessage()));

                try
                {
                    SubscriptionManager::recordError($subscription->getId());
                }
                catch(DatabaseOperationException $recordError)
                {
                    Logger::log()->error(sprintf('Unable to record the error of the list %d: %s', $subscription->getId(), $recordError->getMessage()), $recordError);
                }

                return ['status' => 'FAILED', 'error' => $e->getMessage()];
            }
        }

        /**
         * Returns the concern of a list of the FilterLists directory by its tags
         *
         * @param int[] $tagIds The IDs of the list's tags
         * @param array<int, array{id: int, name: string}> $tags Every tag by ID
         * @return IncidentType|null The concern, OTHER for a list of another kind (e.g., gambling), null if the list
         *                           has no tags
         */
        public static function getConcernFromTags(array $tagIds, array $tags): ?IncidentType
        {
            $names = array_map(fn(int $id) => strtolower($tags[$id]['name'] ?? ''), $tagIds);
            foreach(FilterListsConfiguration::TAG_CONCERNS as $name => $concern)
            {
                if(in_array($name, $names, true))
                {
                    return $concern;
                }
            }

            return count(array_filter($names, fn(string $name) => $name !== '' && $name !== 'allowlist')) > 0 ? IncidentType::OTHER : null;
        }

        /**
         * Synchronizes a list of the FilterLists directory, its details and URLs are retrieved from the directory
         *
         * @param SubscriptionRecord $subscription The subscription
         * @return array The result
         * @throws ListException If the list could not be retrieved
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         */
        private static function syncFilterList(SubscriptionRecord $subscription): array
        {
            $client = FederationAdGuard::getFilterListsClient();
            $list = $client->getList($subscription->getFilterListsId());
            if($list === null)
            {
                throw new ListException(sprintf('The list %d no longer exists in the FilterLists directory', $subscription->getFilterListsId()));
            }

            $tags = $client->getTags();
            $syntaxes = $client->getSyntaxes();

            if(array_any($list->getTagIds(), fn(int $id) => !isset($tags[$id]))
                || array_any($list->getSyntaxIds(), fn(int $id) => !isset($syntaxes[$id])))
            {
                throw new ListException('The list references unresolved directory metadata');
            }

            // A list without tags detects OTHER until the directory categorizes it
            $tagConcern = self::getConcernFromTags($list->getTagIds(), $tags) ?? IncidentType::OTHER;
            SubscriptionManager::updateDetails($subscription->getId(), $list->getName(), $tagConcern);

            // A list whose concern follows its tags changes concern with them
            if($subscription->getConcern() === null && $tagConcern !== $subscription->getTagConcern())
            {
                Logger::log()->info(sprintf('The concern of the list %s (%d) follows its FilterLists tags, it changed from %s to %s', $list->getName(), $subscription->getId(),
                    $subscription->getTagConcern()?->value ?? 'none', $tagConcern->value));
                RuleManager::updateConcern($subscription->getId(), $tagConcern);
            }

            $syntax = ListSyntax::fromFilterListsSyntaxes($list->getSyntaxIds(), $syntaxes);
            if($syntax === null)
            {
                throw new ListException('The syntax of the list is not supported, only lists of network rules, hosts, domains, IP addresses and regular expressions are');
            }

            $allowlist = $subscription->isAllowlist()
                || ListSyntax::isAllowlistSyntax($list->getSyntaxIds(), $syntaxes)
                || in_array('allowlist', array_map(fn(int $id) => strtolower($tags[$id]['name'] ?? ''), $list->getTagIds()), true);

            $segments = $list->getSegments();
            if(count($segments) === 0)
            {
                throw new ListException('The FilterLists directory has no URL for the list');
            }

            $subscription = SubscriptionManager::getSubscription($subscription->getId()) ?? $subscription;
            return self::update($subscription, array_values($segments), $syntax, $allowlist);
        }

        /**
         * Reads a local filter list and replaces its rules only when its contents or parsing settings changed.
         *
         * @param SubscriptionRecord $subscription The local file subscription
         * @return array The result
         * @throws CacheOperationException If a cache operation fails
         * @throws DatabaseOperationException If a database operation fails
         * @throws ListException If the local file cannot be read
         */
        private static function syncFile(SubscriptionRecord $subscription): array
        {
            $contents = LocalLists::read($subscription->getLocation(), ListsConfiguration::MAX_SIZE);
            return self::storeContents($subscription, $contents, ListSyntax::AUTO, $subscription->isAllowlist(), []);
        }

        /**
         * Synchronizes a list downloaded from a URL
         *
         * @param SubscriptionRecord $subscription The subscription
         * @return array The result
         * @throws ListException If the list could not be downloaded
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         */
        private static function syncUrl(SubscriptionRecord $subscription): array
        {
            if($subscription->getLocation() === null)
            {
                throw new ListException('The subscription has no URL');
            }

            return self::update($subscription, [[$subscription->getLocation()]], ListSyntax::AUTO, $subscription->isAllowlist());
        }

        /**
         * Downloads the segments of a list, and stores its rules if it changed
         *
         * @param SubscriptionRecord $subscription The subscription
         * @param array<int, string[]> $segments The URLs of each segment, mirrors after the primary URL
         * @param ListSyntax $syntax How the lines are interpreted
         * @param bool $allowlist True if every rule is an exception
         * @return array The result
         * @throws ListException If a segment could not be downloaded from any of its URLs
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         */
        private static function update(SubscriptionRecord $subscription, array $segments, ListSyntax $syntax, bool $allowlist): array
        {
            $previous = $subscription->getChecksum() !== null ? $subscription->getValidators() : [];

            // Every segment is downloaded conditionally first, a list is unchanged only if every segment is
            $downloads = [];
            $validators = [];
            $unchanged = true;
            foreach($segments as $index => $urls)
            {
                [$url, $result] = self::downloadSegment($urls, $previous);
                $downloads[$index] = [$url, $result];
                $validators[$url] = $result->getValidators();
                $unchanged = $unchanged && $result->isNotModified();
            }

            if($unchanged)
            {
                Logger::log()->debug(sprintf('The list %s (%d) was not modified since its last download', $subscription->getName(), $subscription->getId()));
                SubscriptionManager::recordUnchanged($subscription->getId(), $validators);
                return ['status' => 'UNCHANGED'];
            }

            // A segment that didn't change has to be downloaded again, only the whole list can be parsed
            $contents = [];
            foreach($downloads as $index => [$url, $result])
            {
                if($result->isNotModified())
                {
                    [$url, $result] = self::downloadSegment($segments[$index], []);
                    $validators[$url] = $result->getValidators();
                }

                $contents[] = $result->getContents();
            }

            $contents = implode("\n", $contents);
            return self::storeContents($subscription, $contents, $syntax, $allowlist, $validators);
        }

        /**
         * Parses and stores the contents of a local or downloaded list.
         *
         * @param SubscriptionRecord $subscription The subscription
         * @param string $contents The complete list
         * @param ListSyntax $syntax The parser syntax
         * @param bool $allowlist Whether every rule is an exception
         * @param array $validators The remote download validators
         * @return array The update result
         * @throws DatabaseOperationException If a database operation fails
         * @throws CacheOperationException If a cache operation fails
         */
        private static function storeContents(SubscriptionRecord $subscription, string $contents, ListSyntax $syntax, bool $allowlist, array $validators): array
        {
            $checksum = hash('sha256', $syntax->value . ($allowlist ? ':allow:' : ':block:') . $contents);
            if($checksum === $subscription->getChecksum())
            {
                Logger::log()->debug(sprintf('The list %s (%d) was downloaded again but its contents are unchanged', $subscription->getName(), $subscription->getId()));
                SubscriptionManager::recordUnchanged($subscription->getId(), $validators);
                return ['status' => 'UNCHANGED'];
            }

            $result = FilterParser::parse($contents, $syntax, $allowlist, ListsConfiguration::MAX_RULES);
            unset($contents);

            RuleManager::replaceRules($subscription->getId(), $result->getRules(), $subscription->getEffectiveConcern());
            SubscriptionManager::recordUpdate($subscription->getId(), $checksum, $validators);

            Logger::log()->info(sprintf('Updated the list %s (%d): %d rules, %d unsupported lines', $subscription->getName(), $subscription->getId(), count($result->getRules()), $result->getUnsupported()));
            foreach($result->getUnsupportedExamples() as $example)
            {
                Logger::log()->debug(sprintf('Unsupported line of the list %s (%d): %s (%s)', $subscription->getName(), $subscription->getId(), $example['line'], $example['reason']));
            }
            return ['status' => 'UPDATED', 'rules' => count($result->getRules())];
        }

        /**
         * Downloads a segment from the first of its URLs that works
         *
         * @param string[] $urls The URLs, the primary URL first
         * @param array $validators The validators of the previous downloads by URL
         * @return array{0: string, 1: DownloadResult} The URL and the result
         * @throws ListException If the segment could not be downloaded from any URL
         */
        private static function downloadSegment(array $urls, array $validators): array
        {
            $errors = [];
            foreach($urls as $url)
            {
                try
                {
                    $previous = $validators[$url] ?? [];
                    $result = FederationAdGuard::getDownloader()->download($url, $previous);
                    if($result->isNotModified() && empty($previous))
                    {
                        throw new ListException('The list returned HTTP 304 without a previous download');
                    }

                    return [$url, $result];
                }
                catch(ListException $e)
                {
                    Logger::log()->debug(sprintf('Unable to download %s, trying its next mirror: %s', $url, $e->getMessage()));
                    $errors[] = $e->getMessage();
                }
            }

            throw new ListException(implode('; ', $errors) ?: 'The list has no URL');
        }
    }
