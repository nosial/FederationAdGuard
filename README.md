# FederationAdGuard

A [FederationLib](https://git.n64.cc/nosial/federationlib) plugin that checks the hosts and URLs FederationLib sees
against advertising, tracking and other filter lists, the same lists content blockers such as uBlock Origin and AdGuard
use. It does two things:

 - **It answers scans and queries.** A listed host or URL is a detection of a content scan and adds to its risk score,
   an unlisted one lowers it slightly, and an entity query describes why a host is listed, so clients can decide
   whether to block a request or content.
 - **It builds the database.** Every host a list blocks entirely that the plugin comes across is recorded with
   evidence, metadata and a blacklist record, and the author of a message that is little more than listed links is
   recorded for spamming, so FederationLib's database grows its information on known advertising and tracking hosts
   as it's used.

The plugin doesn't block anything by itself, it tells clients what the lists say. Clients (eg; a DNS resolver like
FederationShield, or a chat bot like SpamProtectionBot) act on the suggested action FederationLib returns.

## Table of contents

<!-- TOC -->
* [FederationAdGuard](#federationadguard)
  * [Table of contents](#table-of-contents)
  * [What it does](#what-it-does)
    * [Where the rules come from](#where-the-rules-come-from)
    * [Content scans](#content-scans)
    * [Entity queries](#entity-queries)
    * [Supported rules](#supported-rules)
    * [What it doesn't do](#what-it-doesnt-do)
  * [Building the database](#building-the-database)
    * [Listed hosts](#listed-hosts)
    * [Authors](#authors)
  * [Scoring and suggested actions](#scoring-and-suggested-actions)
  * [Disabling the plugin](#disabling-the-plugin)
  * [Configuration](#configuration)
    * [Lists](#lists)
    * [FilterLists](#filterlists)
    * [Scanning](#scanning)
    * [Database](#database)
  * [Installation](#installation)
    * [Docker](#docker)
  * [Building and testing](#building-and-testing)
    * [Test environment](#test-environment)
    * [Running the tests](#running-the-tests)
* [License](#license)
<!-- TOC -->

## What it does

The plugin hooks into five FederationLib events:

| Event           | Handler               | What the plugin does                                                                                          |
|-----------------|-----------------------|---------------------------------------------------------------------------------------------------------------|
| `STARTUP`       | `StartupHandler`      | Creates its tables and operator, provisions the configured lists and rules and downloads new lists            |
| `MAINTENANCE`   | `MaintenanceHandler`  | Provisions the lists and rules again, updates the lists that are due, checks a batch of findings and entities |
| `CONTENT_SCAN`  | `ContentScanHandler`  | Matches the hosts and URLs of every scan against the lists, adding detections and points to the result        |
| `QUERY_ENTITY`  | `QueryEntityHandler`  | Matches a queried host entity against the lists, adding its findings, metadata and blacklist records          |
| `RECORD_CHANGE` | `RecordChangeHandler` | Checks new and updated host entities, and follows whitelists, deleted entities, lifts and deletions           |

In short, the lists are downloaded and compiled into FederationLib's database by startup and maintenance, every scan
and query is matched against the compiled rules, and what the lists say is recorded in the database, see
[Building the database](#building-the-database).

A failure of the plugin never fails a FederationLib request, startup or maintenance run, the request continues without
the plugin's contribution and the failure is logged.

### Where the rules come from

The rules come from three places, any of them can be used without the others:

 - **FilterLists.** By default the plugin discovers up to 4 lists for `ADVERTISING` and `TRACKING` in the
   [FilterLists](https://filterlists.com/) directory, preferring EasyList, EasyPrivacy, AdGuard Base filter and AdGuard
   Tracking Protection filter (the actual selection depends on the directory's current contents). A list's concern
   follows its tags in the directory, eg; `ads` is `ADVERTISING` and `privacy` is `TRACKING`. See
   [FilterLists](#filterlists).
 - **Your own lists.** URLs, local files and directories, and FilterLists IDs, see [Lists](#lists).
 - **Inline rules.** Rules written directly in the configuration, see [Lists](#lists).

With FilterLists disabled the plugin never contacts the directory and works entirely on your own lists and rules.

The configuration is the only source of subscriptions, startup and every maintenance run make the database match it:
new lists are added, changed ones are updated and lists that are no longer configured are removed with their rules.

Remote lists are downloaded the first time on startup and updated by maintenance once `update_interval` (`1d`) has
passed, local files are read on every run. A list is only parsed again when it changed, the server is asked with the
`ETag` and `Last-Modified` of the previous download. A list that fails to download keeps its previous rules and is
tried again by the next maintenance run. On a fresh installation a list says nothing until it was downloaded once.

### Content scans

When content is scanned with `POST /scan`, the content type of each evidence item decides what is matched:

| Content type           | What is matched                                                                           |
|------------------------|-------------------------------------------------------------------------------------------|
| `HOSTNAME`             | The hostname or IP address, and the addresses FederationLib resolved                      |
| `URL`                  | The URL, and the addresses FederationLib resolved                                         |
| `WEB_PAGE`             | The page's `context.url`, its `context.final_url` if different, and the links in its text |
| `TEXT`, `EMAIL`, `SMS` | The links and domains mentioned in the text, up to 25 of each item                        |

For instance, a DNS client submits a `HOSTNAME` before answering a lookup, or an application submits a `URL` before
requesting it. Scanning a page's text only checks the links found in that text, it doesn't see the requests a browser
makes while loading the page.

A listed host or URL is a detection of the scan (eg; `ADVERTISING` or `TRACKING`), with the name of the list as its
source, and adds points as the `ADGUARD_<CONCERN>` scanning rule, see
[Scoring and suggested actions](#scoring-and-suggested-actions). Some detections are weaker than others:

 - **Partial matches.** Rules restricted to certain requests, eg; `$script` or `$third-party`, can't be fully checked
   because a scan doesn't have the information a browser has. A URL matched by one is detected with a confidence of
   `0.5` and half the points. A hostname is never matched against them, as DNS blockers do, so a DNS client never
   blocks a host for a rule DNS can't evaluate.
 - **Unverified detections.** The page URLs of a `WEB_PAGE` and matches that depend on a record type the client
   asserted (`$dnstype`) are marked unverified, the server can't confirm what the client claims.

Whitelisted entities are never matched, FederationLib already lowers their risk.

> Note: FederationLib does not assess `ADVERTISING` or `TRACKING` by default. Clients have to include them in the
> request's `concerns`, or the server's `scanning.default_concerns` has to be changed. Only the detections and points
> of the request's effective concerns count towards the result, except `ADGUARD_LINK_SPAM`, which is `SPAM`.

### Entity queries

`GET /entities/{identifier}/query` of a host entity is matched against the lists the same way as a hostname. A listed
host is given `adguard_*` metadata in the response (`adguard_listed`, `adguard_concerns`, `adguard_lists`,
`adguard_rule` and `adguard_host_block`), its blacklist records are included, and if a list blocks the entire host for
one of the requested concerns the suggested action is `PERMANENTLY_BLOCK_ENTITY`. A host that a list explicitly
allows is given `adguard_excepted: true` instead.

### Supported rules

The parser understands the network rules of Adblock Plus, uBlock Origin and AdGuard lists, hosts files, plain domain
lists, IP addresses, URLs and the common DNS blocking formats (dnsmasq, Unbound, RPZ and BIND), eg;

```text
||ads.example.com^
||example.com/advertising/*
@@||allowed.ads.example.com^
0.0.0.0 tracker.example.com
```

The first rule blocks a domain and its subdomains (a host-wide finding), the second only matches URLs below that path,
the third is an exception and the fourth is a hosts file entry. Exceptions (`@@`) apply across every list, `$important`
rules take precedence over exceptions and `$badfilter` disables the rule it's written as in every list.

### What it doesn't do

 - It doesn't block requests, clients act on the scan or query result.
 - It doesn't retrieve the URLs it's given, only the lists themselves are downloaded.
 - Cosmetic rules, element hiding, scriptlets and HTML filtering are ignored, as are site-specific rules and rules that
   modify a request rather than block it, eg; `$removeparam`. The plugin implements network matching, not a browser
   content blocker.

## Building the database

Besides answering scans and queries, the plugin manages records of its own in FederationLib's database. Two kinds of
entity are recorded, separately:

 - **The listed host**, eg; `example.com` when a list blocks `||example.com^`. The host is the offending entity, it's
   recorded for the concern of its list, see [Listed hosts](#listed-hosts).
 - **The author of a message** that is little more than listed links, eg; a Telegram user whose message
   SpamProtectionBot scans. The author is recorded for spamming, see [Authors](#authors).

What is recorded is decided only by the lists, the content and the server's own records, never by the request: a
caller can make the plugin look at a host, but whether and how it's recorded is the same whoever asks and whatever
concerns they ask about. Nothing the client asserts (eg; the page of a `WEB_PAGE` or the record type of a `HOSTNAME`)
can become a finding.

Everything is attributed to a bot operator named `FederationAdGuard` the plugin creates on its first start, with
management and client permissions but not operator permissions. These are ordinary FederationLib records that every
client, search and entity query sees, and FederationLib treats them like any other, eg; a blacklisted entity's
reputation is lowered.

### Listed hosts

A rule that blocks an entire host without conditions, eg; `||ads.example.com^`, establishes a fact about that host, so
whenever the plugin comes across such a host it records a finding:

| Where          | What is recorded                                                                     |
|----------------|--------------------------------------------------------------------------------------|
| Content scans  | The hosts of submitted hostnames, URLs and pages, and of the links mentioned in text |
| Entity queries | The queried host                                                                     |
| Record changes | Host entities when they are created or updated                                       |
| Maintenance    | 2000 of the existing host entities every run, until every one was checked            |

The host recorded is the one the rule names, eg; `doubleclick.net` for a scan of `ad.doubleclick.net` matched by
`||doubleclick.net^`, and its entity is registered if FederationLib didn't know it yet. A finding consists of:

 - **Evidence**, confidential and automated, for each concern, tagged `adguard_finding`.
 - **A permanent blacklist record** for each concern, eg; one for `ADVERTISING` and one for `TRACKING`. When another
   operator already blacklisted the host for that concern, their record stands for it and the plugin creates none.
 - **Entity metadata** summarizing the finding: `adguard_concerns`, `adguard_lists`, `adguard_rule`,
   `adguard_host_block` and `adguard_evidence`.

A finding is recorded once, finding the same host again doesn't create new records. Rules for a single URL path,
partial rules and matches that depend on what a client asserted never become findings.

The findings follow the current lists: maintenance checks 2000 of them every run and lifts the plugin's blacklist
record of a host the lists no longer block entirely, eg; after a list fixed a false positive or a list was removed
from the configuration. The plugin also respects the decisions of operators:

 - Whitelisting an entity lifts the plugin's blacklist records of that entity.
 - Lifting or deleting a plugin blacklist record stops the plugin from ever recreating it for that concern.
 - Deleting an entity makes the plugin forget its findings of that entity.
 - The plugin never lifts a blacklist record another operator created.

### Authors

When a scanned `TEXT`, `EMAIL` or `SMS` names its `author`, eg; the account that sent the message, and the message is
little more than listed links, the author is recorded for `SPAM` in addition to the hosts themselves. The plugin is
deliberately lenient so that an accident isn't punished:

 - The message has to link to at least 2 distinct listed hosts, and at least 80% of the distinct hosts it links to have
   to be listed. Sharing a listed link, or a few listed links among ordinary ones, records nothing. Only full rules
   count, partial rules and matches that depend on what the client asserted don't.
 - **A first offence** only gives the author evidence of the message, confidential and automated, tagged
   `adguard_author`, with the listed hosts, their lists and concerns in its metadata.
 - **A repeat offence** within a week also blacklists the author for `SPAM` temporarily, for `database.author_blacklist`
   (`1d`, never shorter than the server's `server.min_blacklist_time`). The author is never blacklisted permanently.
 - An author that already has an active `SPAM` blacklist record, by anyone, isn't recorded again until it expired.
   Whitelisted authors are never recorded.
 - Only authors with an ID are recorded, eg; `12345@telegram.org` or a telephone number. A bare host given as the
   author isn't, and an author given as an entity address that FederationLib doesn't know yet is registered.
 - Only scans of authenticated clients are recorded. The author of a scan is whoever the client says it is, an
   anonymous scan could otherwise name anyone. This is the same rule FederationLib follows for reputation.

A scan without an author, eg; a DNS lookup submitted as a `HOSTNAME`, records nothing about anyone but the listed
hosts. FederationLib then takes it from there: while the author is blacklisted, their next messages suggest
`TEMPORARILY_BLOCK_ENTITY`, and their reputation doesn't grow.

## Scoring and suggested actions

FederationLib's risk score starts at a neutral `50`, the points of every scanning rule tip it: with its defaults the
risk score is `50 - (total points * 2.3)` limited to 0-100, a score of 60 suggests `CAUTION` and 80 suggests
`BLOCK_CONTENT`. The plugin adds four scanning rules:

| Rule                | Concern                | When                                                                  | Default points |
|---------------------|------------------------|-----------------------------------------------------------------------|----------------|
| `ADGUARD_<CONCERN>` | The list's concern     | A submitted host, URL or page is listed                               | `-15`          |
| `ADGUARD_<CONCERN>` | The list's concern     | A link mentioned in a message is listed                               | `-5`           |
| `ADGUARD_UNLISTED`  | A concern of the lists | Something was checked and nothing is listed (a third of it for links) | `+2`           |
| `ADGUARD_LINK_SPAM` | `SPAM`                 | A message is little more than listed links (see [Authors](#authors))  | `-10`          |

Within an evidence item only the strongest points of each concern count, so several lists matching the same thing
don't score it repeatedly. With no other points contributing:

| Scan                                              | Risk score | Suggested action |
|---------------------------------------------------|------------|------------------|
| A listed hostname (eg; a DNS lookup) or URL       | `84.5`     | `BLOCK_CONTENT`  |
| A partially matched URL                           | `67.25`    | `CAUTION`        |
| An unlisted hostname or URL                       | `45.4`     | None             |
| A message with a listed link, ads requested       | `61.5`     | `CAUTION`        |
| A message of listed links, only spam requested    | `73`       | `CAUTION`        |
| A message of listed links, spam and ads requested | `84.5`     | `BLOCK_CONTENT`  |
| A message without links                           | `50`       | None             |

**Unlisted hosts.** The unlisted bonus is small on purpose: a filter list is a blocklist, not an allowlist, so a host
missing from it isn't known to be good. It's only given when the plugin checked a verified host or URL, nothing it
checked is listed, and rules for one of the request's concerns are loaded. Nothing is given for content the plugin had
nothing to check in (eg; a text without links), for the page a client says it visited, or before any list was loaded.

**Recorded hosts.** Once a host is recorded, FederationLib's own `NAMED_ENTITY_PERMANENTLY_BLACKLISTED` rule (`-13`)
scores its blacklist record. The plugin only tops that up to its own points rather than adding them again, so a listed
host gets the same verdict before and after it's recorded. FederationLib also lowers the reputation of a blacklisted
entity, which adds its own `NAMED_ENTITY_BAD_REPUTATION` points to any scan mentioning the host.

**Tuning.** Both the plugin's points and FederationLib's thresholds are configurable, eg; to give a link mentioned in a
message the same weight as a URL submitted directly:

```yaml
environment:
  - FEDERATION_ADGUARD_SCANNING_LINK_POINTS=-15
```

FederationLib's `FEDERATION_SCANNING_ACTION_BLOCK_THRESHOLD` and `FEDERATION_SCANNING_ACTION_CAUTION_THRESHOLD`
apply to every scan, not just the plugin's. If a result is `CAUTION` where blocking was expected, check its
`scan_results`, the confidence of its detections and its content type, a URL submitted as `TEXT` is a mentioned link
and not the subject of the scan.

## Disabling the plugin

There are two ways to disable the plugin, neither of them affects the rest of FederationLib:

 - **The soft switch.** Disable the `FederationAdGuard` operator through the federation interface (eg;
   `PATCH /operators/{uuid}/disable`). The plugin then does nothing: no detections, points, records or list updates.
   Startup and maintenance keep repairing the operator's name and permissions but never enable it again, so it stays
   off until an administrator enables the operator again, which resumes the plugin without a restart. What operators
   lifted, deleted or whitelisted meanwhile is noticed by the next maintenance run.
 - **The hard switch.** `enabled: false` (`FEDERATION_ADGUARD_ENABLED=false`) makes the plugin do nothing at all, not
   even create its tables or operator. Removing the plugin from `FEDERATION_PLUGINS` does the same.

The records the plugin already created stay either way, they are ordinary FederationLib records until they are lifted
or deleted.

## Configuration

The plugin has its own [ConfigLib](https://github.com/nosial/ConfigLib) configuration named `federation_adguard`,
every value can also be set with its environment variable. Durations are seconds or a number with a unit, eg; `30m`,
`12h` or `1d`, lists are YAML lists or comma-separated values.

| Name      | Environment Variable         | Type    | Default Value | Description                                                    |
|-----------|------------------------------|---------|---------------|----------------------------------------------------------------|
| `enabled` | `FEDERATION_ADGUARD_ENABLED` | boolean | `true`        | The hard switch, while disabled the plugin does nothing at all |

### Lists

Your own lists and inline rules, used with or without FilterLists.

| Name              | Environment Variable                 | Type     | Default Value | Description                                                                      |
|-------------------|--------------------------------------|----------|---------------|----------------------------------------------------------------------------------|
| `lists`           | `FEDERATION_ADGUARD_LISTS`           | list     | Empty         | Your own lists: URLs, absolute paths of files or directories, FilterLists IDs    |
| `rules`           | `FEDERATION_ADGUARD_RULES`           | string   | Empty         | Inline rules, one per line                                                       |
| `update_interval` | `FEDERATION_ADGUARD_UPDATE_INTERVAL` | duration | `1d`          | How often lists are updated, at least one hour                                   |
| `allow_private`   | `FEDERATION_ADGUARD_ALLOW_PRIVATE`   | boolean  | `false`       | Allow downloading lists from private, loopback or otherwise non-public addresses |

Each entry of `lists` is an HTTP(S) URL, the absolute path of a local file or directory (its non-hidden regular
files, not its subdirectories) or a FilterLists ID, followed by options separated with semicolons. Entries are
separated with newlines or commas.

| Option      | Default                                         | Description                                               |
|-------------|-------------------------------------------------|-----------------------------------------------------------|
| `name`      | The list's name, host or file name              | The name shown as the source of the detections            |
| `concern`   | The list's FilterLists tags, else `ADVERTISING` | The concern the list detects, eg; `TRACKING` or `MALWARE` |
| `allowlist` | `false`                                         | Treat every rule of the list as an exception              |

For example, to use only local lists:

```yaml
environment:
  FEDERATION_ADGUARD_FILTERLISTS_ENABLED: "false"
  FEDERATION_ADGUARD_LISTS: |
    /opt/filters/advertising.txt;name=Local advertising;concern=ADVERTISING
    /opt/filters/tracking.txt;name=Local tracking;concern=TRACKING
    /opt/filters/allowed.txt;name=Local exceptions;allowlist=true
```

Or the same in the ConfigLib configuration:

```yaml
filterlists:
  enabled: false
lists:
  - list: /opt/filters/advertising.txt
    name: Local advertising
    concern: ADVERTISING
  - list: /opt/filters/tracking.txt
    name: Local tracking
    concern: TRACKING
  - list: /opt/filters/allowed.txt
    name: Local exceptions
    allowlist: true
```

A line of `rules` can start with its concern in brackets, otherwise it detects `ADVERTISING`. Inline rules use the same
parser and exceptions as the lists:

```yaml
environment:
  FEDERATION_ADGUARD_RULES: |
    ||ads.example.com^
    [TRACKING] ||tracker.example.com^
    [MALWARE] ||malware.example.com^
    @@||allowed.ads.example.com^
```

An invalid entry or rule is left out with a warning, and while one is invalid the plugin keeps the lists and rules it
had rather than removing anything.

### FilterLists

The [FilterLists](https://filterlists.com/) directory, an optional feature that is on by default. It discovers lists
for the configured concerns and languages, and makes FilterLists IDs usable in `lists`.

| Name                    | Environment Variable                       | Type    | Default Value                 | Description                                                              |
|-------------------------|--------------------------------------------|---------|-------------------------------|--------------------------------------------------------------------------|
| `filterlists.enabled`   | `FEDERATION_ADGUARD_FILTERLISTS_ENABLED`   | boolean | `true`                        | Use the directory, while disabled it's never contacted                   |
| `filterlists.concerns`  | `FEDERATION_ADGUARD_FILTERLISTS_CONCERNS`  | list    | `ADVERTISING,TRACKING`        | The concerns lists are discovered for                                    |
| `filterlists.languages` | `FEDERATION_ADGUARD_FILTERLISTS_LANGUAGES` | list    | `en`                          | The languages of discovered lists, lists without one always qualify      |
| `filterlists.max`       | `FEDERATION_ADGUARD_FILTERLISTS_MAX`       | integer | `4`                           | The maximum number of discovered lists, `0` only uses the IDs in `lists` |
| `filterlists.exclude`   | `FEDERATION_ADGUARD_FILTERLISTS_EXCLUDE`   | list    | Empty                         | FilterLists IDs that are never discovered                                |
| `filterlists.preferred` | `FEDERATION_ADGUARD_FILTERLISTS_PREFERRED` | list    | `301,242,2214,157`            | FilterLists IDs discovered first, in this order, when they qualify       |
| `filterlists.endpoint`  | `FEDERATION_ADGUARD_FILTERLISTS_ENDPOINT`  | string  | `https://api.filterlists.com` | The directory's API                                                      |

A list's concern follows its tags: `ads` is `ADVERTISING`, `privacy` is `TRACKING`, `malware` and `crypto` are
`MALWARE` and `phishing` is `PHISHING`. Lists in a syntax the plugin doesn't support, allowlists and lists tagged
`site-specific`, `beta`, `nsfw` or `research` are never discovered. The preferred lists are discovered first when they
qualify, by default [EasyList](https://filterlists.com/lists/easylist) (301) and
[EasyPrivacy](https://filterlists.com/lists/easyprivacy) (242) with AdGuard's Base filter without EasyList (2214) and
Tracking Protection filter (157): one list per concern from each, without overlap. The other qualifying lists follow,
in the syntax the plugin parses best first, then by name. eg; to also discover malware and phishing lists:

```yaml
environment:
  - FEDERATION_ADGUARD_FILTERLISTS_CONCERNS=ADVERTISING,TRACKING,MALWARE,PHISHING
  - FEDERATION_ADGUARD_FILTERLISTS_MAX=8
```

The directory's responses are cached on disk for a day. With `filterlists.enabled: false`, FilterLists IDs in `lists`
are left out with a warning and the lists the directory provided are removed.

### Scanning

The points of the plugin's scanning rules, see [Scoring and suggested actions](#scoring-and-suggested-actions).
Negative points raise the risk score, positive points lower it.

| Name                       | Environment Variable                          | Type  | Default Value | Description                                                     |
|----------------------------|-----------------------------------------------|-------|---------------|-----------------------------------------------------------------|
| `scanning.points`          | `FEDERATION_ADGUARD_SCANNING_POINTS`          | float | `-15`         | A listed host, URL or page that was submitted itself, 0 or less |
| `scanning.link_points`     | `FEDERATION_ADGUARD_SCANNING_LINK_POINTS`     | float | `-5`          | A listed link mentioned in a message, 0 or less                 |
| `scanning.unlisted_points` | `FEDERATION_ADGUARD_SCANNING_UNLISTED_POINTS` | float | `2`           | Something was checked and nothing is listed, 0 or more          |
| `scanning.spam_points`     | `FEDERATION_ADGUARD_SCANNING_SPAM_POINTS`     | float | `-10`         | A message that is little more than listed links, 0 or less      |

`0` turns a rule off.

### Database

What the plugin records, see [Building the database](#building-the-database).

| Name                        | Environment Variable                           | Type     | Default Value | Description                                                                     |
|-----------------------------|------------------------------------------------|----------|---------------|---------------------------------------------------------------------------------|
| `database.enabled`          | `FEDERATION_ADGUARD_DATABASE_ENABLED`          | boolean  | `true`        | Build the database: record listed hosts and authors                             |
| `database.author_blacklist` | `FEDERATION_ADGUARD_DATABASE_AUTHOR_BLACKLIST` | duration | `1d`          | How long a repeat offender is blacklisted for, `off` to only give them evidence |

With `database.enabled: false` the plugin only answers scans and queries, an entity query still suggests blocking a
host a list blocks entirely. The records it already created keep following the lists.

## Installation

The plugin is loaded by FederationLib through the `plugins` configuration (`FEDERATION_PLUGINS`) using its package
name, `net.nosial.federation_adguard`. FederationLib (and ConfigLib and LogLib2) are provided by FederationLib at
runtime.

```shell
make target/release/net.nosial.federation_adguard.ncc
ncc install --package="$PWD/target/release/net.nosial.federation_adguard.ncc" --yes --reinstall
```

`federationlib init` with the plugin enabled creates its tables and operator and downloads the initial lists before
serving requests. Lists are only kept up to date while `federationlib maintenance` runs, the FederationLib docker image
runs it every hour, other deployments have to schedule it themselves.

### Docker

The FederationLib docker image installs plugins listed in `REQUIRE_PLUGINS` before it initializes:

```yaml
volumes:
  - ./target/release/net.nosial.federation_adguard.ncc:/opt/plugins/net.nosial.federation_adguard.ncc:ro
environment:
  - REQUIRE_PLUGINS=/opt/plugins/net.nosial.federation_adguard.ncc   # Anything `ncc install` accepts
  - FEDERATION_PLUGINS=net.nosial.federation_adguard
```

Keep the other plugins you use in both lists. After changing the plugin's environment variables, recreate the
container so that startup and maintenance use the new values.

The plugin doesn't conflict with BayesianPlugin, ArachnidFederationPlugin or TelegramFederationPlugin.

## Building and testing

```shell
ncc project install   # Installs the dependencies
make                  # Builds target/release and target/debug
make test-unit        # Runs the tests that need neither the test environment nor a database
make test-env         # Starts the test environment (FederationLib with the plugin installed, see below)
make test             # Runs every test (phpunit) against the test environment, requires the release build
make test-env-down    # Removes the test environment, keeping its database volume
```

### Test environment

The integration tests run against a live FederationLib server with the plugin installed, started with Docker Compose
([docker-compose.yml](docker-compose.yml)). The server's and the plugin's configurations are their defaults, the plugin
discovers its lists in the real FilterLists directory and downloads the real lists:

| Service   | Description                                                   | Port                       |
|-----------|---------------------------------------------------------------|----------------------------|
| `app`     | FederationLib's `dev` image with the plugin built from source | `7000` (`FEDERATION_PORT`) |
| `mariadb` | FederationLib's database                                      | -                          |
| `redis`   | FederationLib's cache                                         | -                          |

The integration tests (`--group integration`), including `FilterListsTest`, need internet access: they check the
real directory and hosts the real lists are known to block. When a list changes upstream the expected hosts are
updated in the tests. The unit tests (`make test-unit`) never contact a directory. Run `make test-env` again after
changing the plugin, the container uses the plugin built with its image.

### Running the tests

The tests import FederationLib from the installed `net.nosial.federation` package, or a locally built sibling
FederationLib package when available (`FEDERATIONLIB_BUILD_OUTPUT_PATH` points to another build), and the plugin from
`target/release` (or `NCC_BUILD_OUTPUT_PATH`). The tests that use the server read `SERVER_ENDPOINT` (default
`http://172.17.0.1:7000`) and `SERVER_ACCESS_TOKEN` (the root operator's access token, default
`abcdefghijklmnopqrstuvwxyz123456`).

The tests of the operator and of building the database (`PluginOperatorTest`, `RecordingTest`) create a disposable
database for each test, with `ADGUARD_TEST_DATABASE_DSN`, `ADGUARD_TEST_DATABASE_USER` and
`ADGUARD_TEST_DATABASE_PASSWORD`, a MariaDB account that may create and drop databases. Run them with
`FEDERATION_REDIS_ENABLED=false`, without a DSN they are skipped.

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
