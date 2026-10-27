<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Enums\ListSyntax;
    use FederationAdGuard\Enums\RegexSubject;
    use FederationAdGuard\Enums\RuleAction;
    use FederationAdGuard\Enums\RuleType;
    use FederationAdGuard\Exceptions\RuleException;
    use FederationAdGuard\Objects\FilterRule;
    use FederationAdGuard\Objects\ParseResult;

    class FilterParser
    {
        /**
         * The delimiter of the regular expressions the plugin compiles, a control character that never appears in a
         * rule so that patterns and regular expressions from lists never have to be escaped for it
         */
        public const string DELIMITER = "\x01";

        /**
         * The code of a RuleException thrown for a cosmetic rule
         */
        public const int COSMETIC = 1;

        /**
         * The names hosts files map to themselves, they are never blocked
         */
        private const array LOCAL_HOSTS = [
            'localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'localhost4', 'localhost6', 'ip6-localhost',
            'ip6-loopback', 'ip6-localnet', 'ip6-mcastprefix', 'ip6-allnodes', 'ip6-allrouters', 'ip6-allhosts', '0.0.0.0'
        ];

        /**
         * The addresses a hosts file entry blocks a name with
         */
        private const string HOSTS_ENTRY = '/^(?:0\.0\.0\.0|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0|::|::0|::1|0:0:0:0:0:0:0:[01]|255\.255\.255\.255|fe80::1%lo0|ff0\d::\S*)\s+(.+)$/i';

        /**
         * Modifiers that restrict a rule to some requests (by type or party), the rule is partial
         */
        private const array PARTIAL_MODIFIERS = [
            'third-party', '3p', 'first-party', '1p', 'strict1p', 'strict3p', 'strict-first-party', 'strict-third-party',
            'script', 'image', 'stylesheet', 'css', 'object', 'object-subrequest', 'xmlhttprequest', 'xhr', 'subdocument',
            'frame', 'ping', 'beacon', 'media', 'font', 'other', 'websocket', 'webrtc', 'redirect', 'empty', 'mp4',
            'header', 'method', 'webtransport', 'webbundle',
        ];

        /**
         * Modifiers that don't restrict which requests a rule applies to
         */
        private const array FULL_MODIFIERS = ['document', 'doc', 'all'];


        /**
         * Modifiers of rules that don't block or unblock requests to what they match, or only apply to some clients
         */
        private const array IGNORED_MODIFIERS = [
            'redirect-rule', 'removeparam', 'queryprune', 'csp', 'replace', 'cookie', 'removeheader', 'permissions',
            'hls', 'jsonprune', 'xmlprune', 'urltransform', 'uritransform', 'inline-script', 'inline-font', 'generichide',
            'ghide', 'elemhide', 'ehide', 'specifichide', 'shide', 'genericblock', 'content', 'extension', 'jsinject',
            'stealth', 'urlblock', 'network', 'app', 'referrerpolicy', 'sitekey', 'popup', 'popunder', 'client', 'ctag',
            'dnsrewrite', 'to', 'cname', 'reason', 'ipaddress', 'rewrite',
        ];

        /**
         * Tokens that appear in nearly every URL, a rule is only indexed by one of them if it has no other token
         */
        private const array COMMON_TOKENS = ['http', 'https', 'www', 'com', 'net', 'org', 'html', 'php', 'js'];

        /**
         * Parses a filter list
         *
         * @param string $contents The contents of the list
         * @param ListSyntax $syntax How the lines are interpreted
         * @param bool $allowlist True if every rule of the list is an exception
         * @param int $maxRules The maximum number of rules, the remaining lines are counted as unsupported
         * @return ParseResult The rules and the statistics of the list
         */
        public static function parse(string $contents, ListSyntax $syntax=ListSyntax::AUTO, bool $allowlist=false, int $maxRules=PHP_INT_MAX): ParseResult
        {
            $result = new ParseResult();

            // A UTF-8 byte order mark would be part of the first rule
            if(str_starts_with($contents, "\xEF\xBB\xBF"))
            {
                $contents = substr($contents, 3);
            }

            // An Adblock Plus list is recognized by its header, its bare patterns (e.g., ad.example.) are then substring
            // patterns rather than domains
            $adblock = preg_match('/^\s*\[(?:Adblock|AdGuard|uBlock)/i', $contents) === 1;

            $count = 0;
            // The newline that ends the last line doesn't start another one
            $lines = preg_split('/\r\n|\r|\n/', $contents);
            if(count($lines) > 1 && end($lines) === '')
            {
                array_pop($lines);
            }

            foreach($lines as $line)
            {
                if($count >= $maxRules)
                {
                    if(trim($line) !== '')
                    {
                        $result->addUnsupported($line, sprintf('The list exceeds the maximum of %d rules', $maxRules));
                    }

                    continue;
                }

                try
                {
                    $rules = self::parseLine($line, $syntax, $allowlist, $adblock);
                }
                catch(RuleException $e)
                {
                    if($e->getCode() === self::COSMETIC)
                    {
                        $result->addCosmetic();
                    }
                    else
                    {
                        $result->addUnsupported($line, $e->getMessage());
                    }

                    continue;
                }

                // Lines without rules of their own, e.g., Unbound's server: or an RPZ SOA record
                if($rules === null || count($rules) === 0)
                {
                    $result->addComment();
                    continue;
                }

                if(count($rules) > $maxRules - $count)
                {
                    $result->addUnsupported($line, sprintf('The list exceeds the maximum of %d rules', $maxRules));
                    continue;
                }

                $result->addRules($rules);
                $count += count($rules);
            }

            return $result;
        }

        /**
         * Parses a single line of a filter list, e.g., a custom rule
         *
         * @param string $line The line
         * @param ListSyntax $syntax How the line is interpreted
         * @param bool $allowlist True if the line is an exception whatever it's written as
         * @param bool $adblock True if the line belongs to an Adblock Plus list, a bare pattern (e.g., ad.example.) is
         *                      then a substring pattern rather than a domain
         * @return FilterRule[]|null The rules, null (or an empty array for lines such as Unbound's server:) if the line
         *                           is a comment or empty
         * @throws RuleException If the line is not supported (with the code COSMETIC for a cosmetic rule)
         */
        public static function parseLine(string $line, ListSyntax $syntax=ListSyntax::AUTO, bool $allowlist=false, bool $adblock=false): ?array
        {
            $line = trim($line);
            if($line === '' || self::isComment($line))
            {
                return null;
            }

            if(strlen($line) > FilterRule::MAX_RULE_LENGTH)
            {
                throw new RuleException(sprintf('The rule exceeds the maximum length of %d bytes', FilterRule::MAX_RULE_LENGTH));
            }

            if($syntax === ListSyntax::REGEX)
            {
                return [self::parseRegexLine($line, $allowlist)];
            }

            // Element hiding (##, #@#, #?#, #$#, #%#), scriptlets (##+js) and HTML filtering ($$)
            if(preg_match('/^[^\/\s|]*(?:#@?(?:[?$%]|\$\?)?#|\$@?\$)/', $line) === 1)
            {
                throw new RuleException('Cosmetic rules do not apply to hosts or URLs', self::COSMETIC);
            }

            $action = $allowlist ? RuleAction::ALLOW : RuleAction::BLOCK;
            return self::parseHostsEntry($line, $action)
                ?? self::parseDnsmasqEntry($line, $action)
                ?? self::parseUnboundEntry($line, $action)
                ?? self::parseBindEntry($line, $action)
                ?? self::parseRpzEntry($line, $action)
                ?? self::parseAddress($line, $action)
                ?? self::parseDomain($line, $action, $adblock)
                ?? self::parseNetworkRule($line, $allowlist);
        }

        /**
         * Returns the tokens of a URL, a URL rule indexed by a token can only match URLs that contain it
         *
         * @param string $url The URL
         * @return string[] The tokens
         */
        public static function getUrlTokens(string $url): array
        {
            preg_match_all('/[a-z0-9%]{2,}/', strtolower($url), $matches);
            return array_values(array_unique($matches[0]));
        }

        /**
         * Normalizes a DNS name of a rule: lowercase, internationalized names in their ASCII form, without a trailing dot
         *
         * @param string $name The name
         * @return string|null The normalized name, null if it is not a DNS name
         */
        public static function normalizeHost(string $name): ?string
        {
            $name = rtrim(strtolower(trim($name)), '.');
            if($name === '' || strlen($name) > 253)
            {
                return null;
            }

            if(preg_match('/[^\x20-\x7e]/', $name) === 1)
            {
                if(!function_exists('idn_to_ascii'))
                {
                    return null;
                }

                $name = idn_to_ascii($name);
                if($name === false)
                {
                    return null;
                }
            }

            if(preg_match('/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/', $name) !== 1)
            {
                return null;
            }

            return $name;
        }

        /**
         * Returns True if the line is a comment, a list header or a preprocessor directive (!#if, !#include)
         *
         * @param string $line The trimmed line
         * @return bool True if it's a comment
         */
        private static function isComment(string $line): bool
        {
            if(str_starts_with($line, '!') || str_starts_with($line, ';') || preg_match('/^\[(?:Adblock|AdGuard|uBlock)\b[^\]]*\]$/i', $line) === 1 || str_starts_with($line, '$TTL'))
            {
                return true;
            }

            // A line starting with # is a comment, unless it's a generic cosmetic rule (##.ad)
            return str_starts_with($line, '#') && preg_match('/^#@?(?:[?$%]|\$\?)?#/', $line) !== 1;
        }

        /**
         * Removes a trailing comment from an entry of a hosts file or domain list
         *
         * @param string $line The line
         * @return string The line without the comment
         */
        private static function stripInlineComment(string $line): string
        {
            return trim(preg_replace('/\s+#.*$/', '', $line));
        }

        /**
         * Parses a hosts file entry, e.g., 0.0.0.0 ads.example.com tracker.example.com
         *
         * @param string $line The line
         * @param RuleAction $action The action of the rules
         * @return FilterRule[]|null The rules, null if the line is not a hosts file entry
         * @throws RuleException If the entry names no DNS name that can be blocked
         */
        private static function parseHostsEntry(string $line, RuleAction $action): ?array
        {
            if(preg_match(self::HOSTS_ENTRY, $line, $matches) !== 1)
            {
                return null;
            }

            $rules = [];
            $local = false;
            foreach(preg_split('/\s+/', self::stripInlineComment($matches[1])) as $name)
            {
                $host = self::normalizeHost($name);
                if($host !== null && in_array($host, self::LOCAL_HOSTS, true))
                {
                    $local = true;
                    continue;
                }

                if($host !== null)
                {
                    $rules[] = self::hostRule($line, $action, $host, true);
                }
            }

            // Hosts files start with the entries of the local host (127.0.0.1 localhost), which block nothing
            if(count($rules) === 0 && !$local)
            {
                throw new RuleException('The hosts file entry names no DNS name that can be blocked');
            }

            return $rules;
        }

        /**
         * Parses a dnsmasq entry, e.g., address=/ads.example.com/0.0.0.0 or server=/ads.example.com/
         *
         * @param string $line The line
         * @param RuleAction $action The action of the rules
         * @return FilterRule[]|null The rules, null if the line is not a dnsmasq entry
         * @throws RuleException If the entry doesn't block its names
         */
        private static function parseDnsmasqEntry(string $line, RuleAction $action): ?array
        {
            if(preg_match('/^(address|server|local)=\/(.+)\/([^\/]*)$/i', self::stripInlineComment($line), $matches) !== 1)
            {
                return null;
            }

            // An address other than these answers the names with another address, a server forwards them elsewhere
            $target = strtolower(trim($matches[3]));
            $blocking = strtolower($matches[1]) === 'address'
                ? in_array($target, ['', '#', '0.0.0.0', '127.0.0.1', '::', '::1'], true)
                : $target === '';
            if(!$blocking)
            {
                throw new RuleException('The dnsmasq entry answers or forwards its names rather than blocking them');
            }

            $rules = [];
            foreach(explode('/', $matches[2]) as $name)
            {
                if($name === '#')
                {
                    throw new RuleException('The dnsmasq entry matches every name');
                }

                $host = self::normalizeHost($name);
                if($host !== null)
                {
                    $rules[] = self::hostRule($line, $action, $host, true);
                }
            }

            if(count($rules) === 0)
            {
                throw new RuleException('The dnsmasq entry names no DNS name');
            }

            return $rules;
        }

        /**
         * Parses an Unbound entry, e.g., local-zone: "ads.example.com" always_nxdomain or local-data: "ads.example.com A 0.0.0.0"
         *
         * @param string $line The line
         * @param RuleAction $action The action of the rule
         * @return FilterRule[]|null The rules, null if the line is not an Unbound entry
         * @throws RuleException If the entry doesn't block its name
         */
        private static function parseUnboundEntry(string $line, RuleAction $action): ?array
        {
            $line = self::stripInlineComment($line);
            if(preg_match('/^server:\s*$/i', $line) === 1)
            {
                return [];
            }

            if(preg_match('/^local-zone:\s*"?([^"\s]+)"?\s+(\S+)/i', $line, $matches) === 1)
            {
                $zoneType = strtolower($matches[2]);
                if(in_array($zoneType, ['transparent', 'typetransparent', 'always_transparent', 'nodefault'], true))
                {
                    throw new RuleException('The Unbound zone does not block its name');
                }

                $host = self::normalizeHost($matches[1]);
                if($host === null)
                {
                    throw new RuleException('The Unbound zone is not a DNS name');
                }

                return [self::hostRule($line, $action, $host, true)];
            }

            if(preg_match('/^local-data:\s*"([^"\s]+)\s/i', $line, $matches) === 1)
            {
                $host = self::normalizeHost($matches[1]);
                if($host === null)
                {
                    throw new RuleException('The Unbound record is not for a DNS name');
                }

                return [self::hostRule($line, $action, $host, false)];
            }

            return null;
        }

        /**
         * Parses a BIND zone, e.g., zone "ads.example.com" { type master; file "null.zone.file"; };
         *
         * @param string $line The line
         * @param RuleAction $action The action of the rule
         * @return FilterRule[]|null The rules, null if the line is not a BIND zone
         * @throws RuleException If the zone is not a DNS name
         */
        private static function parseBindEntry(string $line, RuleAction $action): ?array
        {
            if(preg_match('/^zone\s+"([^"]+)"/i', $line, $matches) !== 1)
            {
                return null;
            }

            $host = self::normalizeHost($matches[1]);
            if($host === null)
            {
                throw new RuleException('The BIND zone is not a DNS name');
            }

            return [self::hostRule($line, $action, $host, true)];
        }

        /**
         * Parses a Response Policy Zone entry, e.g., ads.example.com CNAME . or *.ads.example.com CNAME .
         *
         * @param string $line The line
         * @param RuleAction $action The action of the rule
         * @return FilterRule[]|null The rules, null if the line is not an RPZ entry
         * @throws RuleException If the entry rewrites its name rather than blocking it
         */
        private static function parseRpzEntry(string $line, RuleAction $action): ?array
        {
            $line = trim(preg_replace('/\s*;.*$/', '', $line));
            if(preg_match('/^(?:@|\S+)\s+(?:\d+\s+)?(?:IN\s+)?(?:SOA|NS)\s/i', $line) === 1)
            {
                return [];
            }

            if(preg_match('/^(\*\.)?(\S+?)\.?\s+(?:\d+\s+)?(?:IN\s+)?CNAME\s+(\S+)$/i', $line, $matches) !== 1)
            {
                return null;
            }

            $target = strtolower($matches[3]);
            if($target === 'rpz-passthru.')
            {
                $action = RuleAction::ALLOW;
            }
            elseif(!in_array($target, ['.', '*.', 'rpz-drop.'], true))
            {
                throw new RuleException('The RPZ entry rewrites its name rather than blocking it');
            }

            $host = self::normalizeHost($matches[2]);
            if($host === null)
            {
                throw new RuleException('The RPZ entry is not for a DNS name');
            }

            return [self::hostRule($line, $action, $host, $matches[1] !== '')];
        }

        /**
         * Parses an IP address, e.g., a line of an IP list
         *
         * @param string $line The line
         * @param RuleAction $action The action of the rule
         * @return FilterRule[]|null The rules, null if the line is not an IP address
         * @throws RuleException If the line is a range of addresses
         */
        private static function parseAddress(string $line, RuleAction $action): ?array
        {
            $line = self::stripInlineComment($line);
            if(preg_match('/^[0-9a-f.:]+\/\d{1,3}$/i', $line) === 1 || preg_match('/^[0-9.]+\s*-\s*[0-9.]+$/', $line) === 1 || preg_match('/^[0-9.]+\s+[0-9.]+\s+\d+/', $line) === 1)
            {
                throw new RuleException('Ranges of IP addresses are not supported');
            }

            $address = self::normalizeAddress($line);
            if($address === null)
            {
                return null;
            }

            return [new FilterRule([
                'rule' => $line,
                'action' => $action,
                'type' => RuleType::IP,
                'host' => $address,
                'fingerprint' => self::fingerprint($action, '|' . $address . '^', []),
            ])];
        }

        /**
         * Parses a line of a domain list, e.g., ads.example.com, *.ads.example.com or .ads.example.com. In an Adblock
         * Plus list (and for anything that looks like a pattern) the line is left to parseNetworkRule().
         *
         * @param string $line The line
         * @param RuleAction $action The action of the rule
         * @param bool $adblock True if the line belongs to an Adblock Plus list
         * @return FilterRule[]|null The rules, null if the line is not a domain
         */
        private static function parseDomain(string $line, RuleAction $action, bool $adblock): ?array
        {
            if($adblock || str_starts_with($line, '@@') || str_contains($line, '$'))
            {
                return null;
            }

            $line = self::stripInlineComment($line);
            if(preg_match('/^(\*\.|\.)?([^\s*\/|^]+?)\^?$/', $line, $matches) !== 1 || !str_contains($matches[2], '.'))
            {
                return null;
            }

            $host = self::normalizeHost($matches[2]);

            // The last label of a name is never numeric, e.g., ad.300 is a pattern
            if($host === null || preg_match('/\.[0-9]+$/', $host) === 1)
            {
                return null;
            }

            return [self::hostRule($line, $action, $host, true)];
        }

        /**
         * Parses a line of a regex list (e.g., Pi-hole's), a regular expression matched against DNS names with the
         * optional ;querytype= option
         *
         * @param string $line The line
         * @param bool $allowlist True if the rule is an exception
         * @return FilterRule The rule
         * @throws RuleException If the regular expression is invalid or uses an option that is not supported
         */
        private static function parseRegexLine(string $line, bool $allowlist): FilterRule
        {
            $dnsTypes = null;
            while(preg_match('/^(.*);(querytype=([^;]+)|invert|reply=[^;]*)$/i', $line, $matches) === 1)
            {
                if(strtolower($matches[2]) === 'invert')
                {
                    throw new RuleException('Inverted regular expressions are not supported');
                }

                if(isset($matches[3]) && $matches[3] !== '')
                {
                    $dnsTypes = array_map(fn(string $type) => str_starts_with($type, '!') ? '~' . strtoupper(substr($type, 1)) : strtoupper($type),
                        array_filter(array_map('trim', explode(',', $matches[3])))
                    );
                }

                $line = $matches[1];
            }

            $regex = self::DELIMITER . $line . self::DELIMITER . 'i';
            self::validateRegex($regex);
            $action = $allowlist ? RuleAction::ALLOW : RuleAction::BLOCK;

            return new FilterRule([
                'rule' => $line,
                'action' => $action,
                'type' => RuleType::REGEX,
                'regex' => $regex,
                'regex_subject' => RegexSubject::HOST,
                'dns_types' => $dnsTypes,
                'fingerprint' => self::fingerprint($action, '/' . $line . '/', $dnsTypes !== null ? ['dnstype=' . implode('|', $dnsTypes)] : []),
            ]);
        }

        /**
         * Parses an Adblock Plus, uBlock Origin or AdGuard network rule
         *
         * @param string $line The line
         * @param bool $allowlist True if the rule is an exception whatever it's written as
         * @return FilterRule[] The rules
         * @throws RuleException If the rule is not supported
         */
        private static function parseNetworkRule(string $line, bool $allowlist): array
        {
            $exception = $allowlist;
            if(str_starts_with($line, '@@'))
            {
                $exception = true;
                $line = substr($line, 2);
            }

            $action = $exception ? RuleAction::ALLOW : RuleAction::BLOCK;
            [$pattern, $modifierText] = self::splitModifiers($line);
            $modifiers = self::parseModifiers($modifierText);
            $original = ($exception ? '@@' : '') . $line;

            if($pattern === '' || trim($pattern, '*|^') === '')
            {
                throw new RuleException('The rule matches every request');
            }

            $base = [
                'rule' => $original,
                'action' => $action,
                'partial' => $modifiers['partial'],
                'important' => $modifiers['important'],
                'badfilter' => $modifiers['badfilter'],
                'dns_types' => $modifiers['dns_types'],
                'deny_allow' => $modifiers['deny_allow'],
            ];

            // A regular expression, /ad[0-9]+\./
            if(strlen($pattern) > 2 && str_starts_with($pattern, '/') && str_ends_with($pattern, '/'))
            {
                $regex = self::DELIMITER . substr($pattern, 1, -1) . self::DELIMITER . ($modifiers['match_case'] ? '' : 'i');
                self::validateRegex($regex);

                return [new FilterRule(array_merge($base, [
                    'type' => RuleType::REGEX,
                    'regex' => $regex,
                    'regex_subject' => RegexSubject::URL,
                    'fingerprint' => self::fingerprint($action, $pattern, $modifiers['canonical']),
                ]))];
            }

            $lowerPattern = $modifiers['match_case'] ? $pattern : strtolower($pattern);

            // A host anchor, ||ads.example.com^ or ||example.com/ads/
            if(str_starts_with($lowerPattern, '||') && preg_match('/^\|\|([a-z0-9._-]+)(.*)$/i', $lowerPattern, $matches) === 1)
            {
                $hostPart = strtolower($matches[1]);
                $tail = $matches[2];
                $address = self::normalizeAddress($hostPart);
                $host = $address ?? self::normalizeHost($hostPart);

                if($host !== null && in_array($tail, ['', '^', '^|', '|'], true))
                {
                    if($address !== null)
                    {
                        return [new FilterRule(array_merge($base, [
                            'type' => RuleType::IP,
                            'host' => $address,
                            'fingerprint' => self::fingerprint($action, '|' . $address . '^', $modifiers['canonical']),
                        ]))];
                    }

                    return [self::hostRule($original, $action, $host, true, $base, $modifiers['canonical'])];
                }

                // The host is followed by a path, a port or a query (never a *, which may extend the host)
                if($host !== null && $address === null && $tail !== '' && !str_starts_with($tail, '*'))
                {
                    return [new FilterRule(array_merge($base, [
                        'type' => RuleType::URL,
                        'host' => $host,
                        'regex' => self::compilePattern($pattern, $modifiers['match_case']),
                        'fingerprint' => self::fingerprint($action, $lowerPattern, $modifiers['canonical']),
                    ]))];
                }
            }

            // An exact host (AdGuard's DNS syntax), |ads.example.com^
            if(str_starts_with($lowerPattern, '|') && !str_starts_with($lowerPattern, '||') && preg_match('/^\|([a-z0-9._-]+)(\^|\^\||\|)$/i', $lowerPattern, $matches) === 1)
            {
                $host = self::normalizeHost($matches[1]);
                if($host !== null && str_contains($host, '.'))
                {
                    return [self::hostRule($original, $action, $host, false, $base, $modifiers['canonical'])];
                }
            }

            // Only a start-anchored URL requires its host; an unanchored URL can also occur in a path or query
            $host = null;
            if(preg_match('#^\|[a-z][a-z0-9+.-]*://([a-z0-9._-]+)(?:[/:?^|]|$)#i', $lowerPattern, $matches) === 1)
            {
                $host = self::normalizeHost($matches[1]);
            }

            return [new FilterRule(array_merge($base, [
                'type' => RuleType::URL,
                'host' => $host,
                'token' => $host === null ? self::selectToken($pattern) : null,
                'regex' => self::compilePattern($pattern, $modifiers['match_case']),
                'fingerprint' => self::fingerprint($action, $lowerPattern, $modifiers['canonical']),
            ]))];
        }

        /**
         * Creates a HOST rule
         *
         * @param string $rule The original rule
         * @param RuleAction $action The action of the rule
         * @param string $host The normalized DNS name
         * @param bool $subdomains True if the subdomains of the name are matched too
         * @param array $base The modifiers of the rule, see parseNetworkRule()
         * @param string[] $canonicalModifiers The canonical modifiers, for the fingerprint
         * @return FilterRule The rule
         */
        private static function hostRule(string $rule, RuleAction $action, string $host, bool $subdomains, array $base=[], array $canonicalModifiers=[]): FilterRule
        {
            // A hosts file entry is the same rule as ||host^, a $badfilter written either way disables it
            return new FilterRule(array_merge($base, [
                'rule' => $rule,
                'action' => $action,
                'type' => RuleType::HOST,
                'host' => $host,
                'subdomains' => $subdomains,
                'fingerprint' => self::fingerprint($action, ($subdomains ? '||' : '|') . $host . '^', $canonicalModifiers),
            ]));
        }

        /**
         * Splits a network rule into its pattern and its modifiers
         *
         * @param string $rule The rule without its exception marker
         * @return array{0: string, 1: string|null} The pattern and the modifiers, null if there are none
         */
        private static function splitModifiers(string $rule): array
        {
            // The modifiers of a regular expression rule follow its closing slash, /regex/$script
            if(str_starts_with($rule, '/'))
            {
                $end = strrpos($rule, '/$');
                if($end !== false && $end > 0 && preg_match('/^[~\w-]+(?:=|,|$)/', substr($rule, $end + 2)) === 1)
                {
                    return [substr($rule, 0, $end + 1), substr($rule, $end + 2)];
                }

                return [$rule, null];
            }

            $position = strrpos($rule, '$');
            if($position === false || preg_match('/^[~\w-]+(?:=|,|$)/', substr($rule, $position + 1)) !== 1)
            {
                return [$rule, null];
            }

            return [substr($rule, 0, $position), substr($rule, $position + 1)];
        }

        /**
         * Parses the modifiers of a network rule
         *
         * @param string|null $text The modifiers, e.g., third-party,script
         * @return array{partial: bool, important: bool, badfilter: bool, match_case: bool, dns_types: string[]|null, deny_allow: string[]|null, canonical: string[]}
         * @throws RuleException If a modifier makes the rule inapplicable or is not supported
         */
        private static function parseModifiers(?string $text): array
        {
            $result = ['partial' => false, 'important' => false, 'badfilter' => false, 'match_case' => false, 'dns_types' => null, 'deny_allow' => null, 'canonical' => []];
            if($text === null || $text === '')
            {
                return $result;
            }

            // AdGuard escapes the commas of a value as \,
            foreach(preg_split('/(?<!\\\\),/', $text) as $modifier)
            {
                $modifier = trim($modifier);
                if($modifier === '')
                {
                    continue;
                }

                [$name, $value] = array_pad(explode('=', $modifier, 2), 2, null);
                $name = strtolower($name);
                $negated = str_starts_with($name, '~');
                $bareName = ltrim($name, '~');

                if($bareName !== 'badfilter')
                {
                    $result['canonical'][] = $value !== null ? $name . '=' . strtolower($value) : $name;
                }

                switch(true)
                {
                    case $bareName === 'important':
                        $result['important'] = true;
                        break;

                    case $bareName === 'badfilter':
                        $result['badfilter'] = true;
                        break;

                    case $bareName === 'match-case':
                        $result['match_case'] = true;
                        break;

                    case $bareName === 'dnstype':
                        $result['dns_types'] = self::parseValues($value, true);
                        if($result['dns_types'] === null)
                        {
                            throw new RuleException('The $dnstype modifier requires record types');
                        }
                        break;

                    case $bareName === 'denyallow':
                        $domains = self::parseValues($value, false);
                        if($domains === null || array_any($domains, fn(string $domain) => str_starts_with($domain, '~')))
                        {
                            throw new RuleException('The $denyallow modifier requires domains, which cannot be negated');
                        }
                        $domains = array_map(fn(string $domain) => self::normalizeHost($domain), $domains);
                        if(in_array(null, $domains, true))
                        {
                            throw new RuleException('The $denyallow modifier requires valid domains');
                        }

                        $result['deny_allow'] = array_values(array_unique($domains));
                        break;

                    case in_array($bareName, ['domain', 'from'], true):
                        // A rule restricted to requests made by some sites can't apply to a host or URL on its own,
                        // excluding sites only makes it partial
                        $domains = self::parseValues($value, false);
                        if($domains === null || !array_all($domains, fn(string $domain) => str_starts_with($domain, '~')))
                        {
                            throw new RuleException('Rules that only apply on some sites ($domain) are not supported');
                        }
                        $result['partial'] = true;
                        break;

                    case in_array($bareName, self::PARTIAL_MODIFIERS, true):
                        $result['partial'] = true;
                        break;

                    case in_array($bareName, self::FULL_MODIFIERS, true) && !$negated:
                        break;

                    case in_array($bareName, self::IGNORED_MODIFIERS, true):
                        throw new RuleException(sprintf('Rules with the $%s modifier do not block or unblock requests to what they match', $bareName));

                    default:
                        throw new RuleException(sprintf('The $%s modifier is not supported', $bareName));
                }
            }

            sort($result['canonical']);
            return $result;
        }

        /**
         * Parses the |-separated values of a modifier
         *
         * @param string|null $value The value
         * @param bool $uppercase True to convert the values to uppercase (record types), otherwise lowercase
         * @return string[]|null The values, null if there are none
         */
        private static function parseValues(?string $value, bool $uppercase): ?array
        {
            if($value === null)
            {
                return null;
            }

            $values = array_values(array_filter(array_map(fn(string $item) => $uppercase ? strtoupper(trim($item)) : strtolower(trim($item)), explode('|', $value)), fn(string $item) => $item !== '' && $item !== '~'));
            return count($values) > 0 ? $values : null;
        }

        /**
         * Compiles an Adblock Plus pattern to a regular expression matched against URLs
         *
         * @param string $pattern The pattern, e.g., ||example.com/ads/*.gif|
         * @param bool $matchCase True if the pattern is case-sensitive
         * @return string The regular expression, including its delimiters and flags
         */
        private static function compilePattern(string $pattern, bool $matchCase): string
        {
            $prefix = '';
            $start = 0;
            if(str_starts_with($pattern, '||'))
            {
                // The scheme, then the host or one of its subdomains
                $prefix = '^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]*@)?(?:[^\/?#]*\.)?';
                $start = 2;
            }
            elseif(str_starts_with($pattern, '|'))
            {
                $prefix = '^';
                $start = 1;
            }

            $suffix = '';
            $end = strlen($pattern);
            if($end > $start && str_ends_with($pattern, '|'))
            {
                $suffix = '$';
                $end--;
            }

            $body = '';
            for($i = $start; $i < $end; $i++)
            {
                $character = $pattern[$i];
                $body .= match($character)
                {
                    '*' => '.*',
                    // A separator: anything but a letter, a digit or one of _-.%, or the end of the URL
                    '^' => '(?:[^a-zA-Z0-9_.%-]|$)',
                    default => preg_quote($character, self::DELIMITER),
                };
            }

            return self::DELIMITER . $prefix . $body . $suffix . self::DELIMITER . ($matchCase ? '' : 'i');
        }

        /**
         * Selects the token a URL pattern is indexed by: the longest run of letters, digits and % that is bounded on
         * both sides in the pattern, so that a URL can only match the pattern if it contains the token as a token of
         * its own (see getUrlTokens())
         *
         * @param string $pattern The pattern
         * @return string|null The token, null if the pattern has no bounded token
         */
        private static function selectToken(string $pattern): ?string
        {
            $pattern = strtolower($pattern);
            $anchoredStart = str_starts_with($pattern, '|');
            $anchoredEnd = strlen($pattern) > 1 && str_ends_with($pattern, '|');
            $body = trim($pattern, '|');

            preg_match_all('/[a-z0-9%]+/', $body, $matches, PREG_OFFSET_CAPTURE);

            $best = null;
            $bestCommon = null;
            foreach($matches[0] as [$token, $offset])
            {
                $length = strlen($token);
                if($length < 2)
                {
                    continue;
                }

                $before = $offset > 0 ? $body[$offset - 1] : null;
                $after = $offset + $length < strlen($body) ? $body[$offset + $length] : null;
                $leftBounded = $before === null ? $anchoredStart : $before !== '*';
                $rightBounded = $after === null ? $anchoredEnd : $after !== '*';
                if(!$leftBounded || !$rightBounded)
                {
                    continue;
                }

                if(in_array($token, self::COMMON_TOKENS, true))
                {
                    if($bestCommon === null || $length > strlen($bestCommon))
                    {
                        $bestCommon = $token;
                    }

                    continue;
                }

                if($best === null || $length > strlen($best))
                {
                    $best = $token;
                }
            }

            return $best ?? $bestCommon;
        }

        /**
         * Normalizes an IP address
         *
         * @param string $value The value
         * @return string|null The address in its canonical form (IPv6 compressed and lowercase), null if it's not one
         */
        public static function normalizeAddress(string $value): ?string
        {
            $value = trim($value, " \t[]");
            if(filter_var($value, FILTER_VALIDATE_IP) === false)
            {
                return null;
            }

            $packed = @inet_pton($value);
            return $packed !== false ? inet_ntop($packed) : null;
        }

        /**
         * Validates a regular expression from a list
         *
         * @param string $regex The regular expression, including its delimiters and flags
         * @return void
         * @throws RuleException If the regular expression is invalid
         */
        private static function validateRegex(string $regex): void
        {
            if(@preg_match($regex, '') === false)
            {
                throw new RuleException('The regular expression is invalid: ' . preg_last_error_msg());
            }
        }

        /**
         * Calculates the fingerprint of a rule, the same for a rule and the $badfilter rule that disables it
         *
         * @param RuleAction $action The action of the rule
         * @param string $pattern The canonical pattern of the rule
         * @param string[] $canonicalModifiers The sorted modifiers other than $badfilter
         * @return string The fingerprint (SHA-1, hex)
         */
        private static function fingerprint(RuleAction $action, string $pattern, array $canonicalModifiers): string
        {
            return sha1(($action === RuleAction::ALLOW ? '@@' : '') . $pattern . '$' . implode(',', $canonicalModifiers));
        }
    }
