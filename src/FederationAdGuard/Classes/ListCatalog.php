<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Classes\Configuration\FilterListsConfiguration;
    use FederationAdGuard\Enums\ListSyntax;
    use FederationAdGuard\Exceptions\ListException;
    use FederationAdGuard\Interfaces\FilterListsClientInterface;
    use FederationAdGuard\Objects\FilterList;
    use FederationAdGuard\Objects\SubscriptionDefinition;
    use FederationLib\Enums\IncidentType;

    class ListCatalog
    {
        /**
         * Selects supported lists by their API tags and languages. No list identity, maintainer trust,
         * age, variant relationship or availability is inferred from an ID or name.
         *
         * @param FilterListsClientInterface $client The directory
         * @param IncidentType[] $concerns The concerns to detect
         * @param string[] $languages Language codes; empty accepts all languages
         * @param int[] $excluded Operator-excluded directory IDs
         * @param int $limit Maximum automatic subscriptions
         * @return SubscriptionDefinition[] Definitions by subscription key
         * @throws ListException If directory metadata cannot be read
         */
        public static function discover(FilterListsClientInterface $client, array $concerns, array $languages, array $excluded, int $limit): array
        {
            if($limit < 1 || $concerns === [])
            {
                return [];
            }

            $tags = $client->getTags();
            $syntaxes = $client->getSyntaxes();
            $languageCodes = $client->getLanguages();
            $candidates = [];
            foreach($client->getLists() as $list)
            {
                if($list->getId() < 1 || in_array($list->getId(), $excluded, true)
                    || array_any($list->getTagIds(), fn(int $id) => !isset($tags[$id]))
                    || array_any($list->getSyntaxIds(), fn(int $id) => !isset($syntaxes[$id]))
                    || array_any($list->getLanguageIds(), fn(int $id) => !isset($languageCodes[$id])))
                {
                    continue;
                }

                $concern = Synchronizer::getConcernFromTags($list->getTagIds(), $tags);
                $listTags = array_map(fn(int $id) => strtolower($tags[$id]['name']), $list->getTagIds());
                $listLanguages = array_map(fn(int $id) => $languageCodes[$id], $list->getLanguageIds());
                if(!in_array($concern, $concerns, true)
                    || count(array_intersect(FilterListsConfiguration::EXCLUDED_TAGS, $listTags)) > 0
                    || ListSyntax::fromFilterListsSyntaxes($list->getSyntaxIds(), $syntaxes) === null
                    || ListSyntax::isAllowlistSyntax($list->getSyntaxIds(), $syntaxes)
                    || ($languages !== [] && $listLanguages !== [] && array_intersect($languages, $listLanguages) === []))
                {
                    continue;
                }

                $candidates[$list->getId()] = $list;
            }

            $preferredLists = array_flip(FilterListsConfiguration::PREFERRED_LISTS);
            $priority = fn(FilterList $list) => $preferredLists[strtolower($list->getName())] ?? count($preferredLists);
            $preferences = array_flip(FilterListsConfiguration::SYNTAX_PREFERENCE);
            $rank = fn(FilterList $list) => min([count($preferences), ...array_map(fn(int $id) => $preferences[strtolower($syntaxes[$id]['name'])] ?? count($preferences), $list->getSyntaxIds())]);
            // Prefer configured parser formats; alphabetic ties imply no quality or trust ranking.
            usort($candidates, fn(FilterList $a, FilterList $b) => [$priority($a), $rank($a), strtolower($a->getName()), $a->getId()] <=> [$priority($b), $rank($b), strtolower($b->getName()), $b->getId()]);
            $definitions = [];
            foreach(array_slice($candidates, 0, $limit) as $list)
            {
                // Leave concern unset so synchronization continues following current API tags.
                $definition = new SubscriptionDefinition($list->getId());
                $definitions[$definition->getKey()] = $definition;
            }

            return $definitions;
        }
    }
