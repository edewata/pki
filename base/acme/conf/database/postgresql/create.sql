create table "nonces" (
    "value"   varchar primary key,
    "expires" timestamp not null
);

create table "accounts" (
    "id"     varchar primary key,
    "status" varchar not null,
    "orders" varchar not null,
    "jwk" varchar not null
);

create table "account_contacts" (
    "account_id" varchar not null,
    "contact"    varchar not null
);

create table "orders" (
    "id"          varchar primary key,
    "account_id"  varchar not null,
    "status"      varchar not null,
    "expires"     timestamp not null,
    "not_before"  timestamp,
    "not_after"   timestamp,
    "finalize"    varchar,
    "csr"         varchar,
    "certificate" varchar,
    "resource"    varchar
);

create table "order_identifiers" (
    "order_id" varchar not null,
    "type"     varchar not null,
    "value"    varchar not null
);

create table "order_authorizations" (
    "order_id" varchar not null,
    "url"    varchar not null
);

create table "authorizations" (
    "id"               varchar primary key,
    "account_id"       varchar not null,
    "status"           varchar not null,
    "expires"          timestamp not null,
    "identifier_type"  varchar,
    "identifier_value" varchar,
    "wildcard"         boolean
);

create table "authorization_challenges" (
    "id"         varchar not null,
    "authz_id"   varchar not null,
    "type"       varchar not null,
    "url"        varchar not null,
    "token"      varchar not null,
    "status"     varchar not null,
    "validated"  timestamp
);
