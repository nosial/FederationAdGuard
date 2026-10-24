create table adguard_subscriptions
(
    id              int auto_increment                                     not null comment 'The unique ID of the subscription' primary key,
    source          enum ('FILTERLISTS', 'URL', 'FILE', 'CUSTOM')          not null comment 'Where the rules of the list come from',
    filterlists_id  int                                                    null comment 'Optional. The ID of the list in the FilterLists directory, for FILTERLISTS subscriptions',
    location        text                                                   null comment 'Optional. The URL or local file path of the list',
    name            varchar(255)                                           not null comment 'The name of the list, the source of the detections its rules make',
    concern         enum ('SPAM', 'SCAM', 'SERVICE_ABUSE', 'ILLEGAL_CONTENT', 'MALWARE', 'PHISHING', 'ADVERTISING', 'TRACKING', 'OTHER') null comment 'Optional. The concern the rules detect, null to derive it from the tags of the list',
    tag_concern     enum ('SPAM', 'SCAM', 'SERVICE_ABUSE', 'ILLEGAL_CONTENT', 'MALWARE', 'PHISHING', 'ADVERTISING', 'TRACKING', 'OTHER') null comment 'Optional. The concern derived from the FilterLists tags of the list',
    allowlist       tinyint(1)                 default 0                   not null comment 'Default: 0, 1=Every rule of the list is an exception',
    checksum        char(64)                                               null comment 'Optional. The SHA-256 checksum of the list as it was last parsed',
    validators      text                                                   null comment 'Optional. The ETag and Last-Modified of each URL of the list (JSON)',
    last_checked    timestamp                                              null comment 'Optional. The Timestamp for when the list was last downloaded or found unchanged',
    constraint adguard_subscriptions_filterlists_id_uindex
        unique (filterlists_id)
)
    comment 'FederationAdGuard: the filter lists the server subscribes to';

create index adguard_subscriptions_source_index
    on adguard_subscriptions (source);
