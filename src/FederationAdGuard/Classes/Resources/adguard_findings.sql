create table adguard_findings
(
    entity          varchar(36)                                          not null comment 'The UUID of the listed host entity',
    concern         enum ('SPAM', 'SCAM', 'SERVICE_ABUSE', 'ILLEGAL_CONTENT', 'MALWARE', 'PHISHING', 'ADVERTISING', 'TRACKING', 'OTHER') not null comment 'The concern of the rule, the type of the blacklist record',
    host            varchar(255)                                         not null comment 'The host of the entity',
    rule            varchar(1024)                                        not null comment 'The rule that blocks the host entirely, as it is written in the list',
    subscription    int                                                  null comment 'Optional. The subscription of the rule, null for the inline rules',
    evidence        varchar(36)                                          null comment 'Optional. The UUID of the evidence record created for the finding, null if none was created or it was deleted',
    blacklist       varchar(36)                                          null comment 'Optional. The UUID of the blacklist record the plugin created, null while it is being created or if none was',
    state           enum ('PENDING', 'ACTIVE', 'LIFTED', 'SUPPRESSED')   not null comment 'PENDING=Being blacklisted, ACTIVE=Blacklisted, LIFTED=Not blacklisted by the plugin (eg; no longer listed), SUPPRESSED=Lifted or deleted by an operator',
    updated         timestamp default current_timestamp()                not null on update current_timestamp() comment 'The Timestamp for when the record last changed',
    primary key (entity, concern),
    constraint adguard_findings_entities_uuid_fk
        foreign key (entity) references entities (uuid)
            on update cascade on delete cascade,
    constraint adguard_findings_evidence_uuid_fk
        foreign key (evidence) references evidence (uuid)
            on update cascade on delete set null
)
    comment 'FederationAdGuard: the hosts a list blocks entirely, with the evidence and blacklist record the plugin created for each concern';

create index adguard_findings_blacklist_index
    on adguard_findings (blacklist);

create index adguard_findings_state_updated_index
    on adguard_findings (state, updated);
