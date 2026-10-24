create table adguard_rules
(
    id              bigint auto_increment                            not null comment 'The unique ID of the rule' primary key,
    subscription_id int                                              not null comment 'The subscription the rule belongs to',
    bucket          enum ('HOST', 'TOKEN', 'NONE')                   not null comment 'How the rule is indexed, by its host, by a token of its pattern or not at all',
    rule            varchar(1024)                                    not null comment 'The rule as it is written in the list',
    action          enum ('BLOCK', 'ALLOW')                          not null comment 'Whether the rule blocks or unblocks what it matches',
    type            enum ('HOST', 'URL', 'REGEX', 'IP')              not null comment 'How the rule matches',
    host            varchar(253) character set ascii                 null comment 'Optional. The DNS name or IP address the rule is indexed by',
    subdomains      tinyint(1)                     default 0         not null comment 'Default: 0, 1=The HOST rule also matches the subdomains of its name',
    token           varchar(255) character set ascii                 null comment 'Optional. The token the URL rule is indexed by',
    regex           text                                             null comment 'Optional. The regular expression of a URL or REGEX rule',
    regex_subject   enum ('URL', 'HOST')                             null comment 'Optional. What the regular expression of a REGEX rule is matched against',
    partial         tinyint(1)                     default 0         not null comment 'Default: 0, 1=The rule only applies to some requests (eg; $third-party)',
    important       tinyint(1)                     default 0         not null comment 'Default: 0, 1=The rule has the $important modifier',
    badfilter       tinyint(1)                     default 0         not null comment 'Default: 0, 1=The rule has the $badfilter modifier and disables the rule it is written as',
    dns_types       varchar(255)                                     null comment 'Optional. The DNS record types the rule is restricted to ($dnstype)',
    deny_allow      text                                             null comment 'Optional. The domains the rule does not apply to ($denyallow)',
    fingerprint     char(40) character set ascii                     not null comment 'The fingerprint the rule shares with the $badfilter rule that disables it',
    concern         enum ('SPAM', 'SCAM', 'SERVICE_ABUSE', 'ILLEGAL_CONTENT', 'MALWARE', 'PHISHING', 'ADVERTISING', 'TRACKING', 'OTHER')               not null comment 'The concern the rule detects',
    constraint adguard_rules_adguard_subscriptions_id_fk
        foreign key (subscription_id) references adguard_subscriptions (id)
            on update cascade on delete cascade
)
    comment 'FederationAdGuard: the network rules of the subscribed filter lists and of the custom rules';

create index adguard_rules_host_index
    on adguard_rules (host);

create index adguard_rules_token_index
    on adguard_rules (token);

create index adguard_rules_bucket_index
    on adguard_rules (bucket);
