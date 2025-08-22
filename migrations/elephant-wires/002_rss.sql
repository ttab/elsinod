CREATE TABLE IF NOT EXISTS rss_feed (
    uuid uuid primary key,
    title text not null,
    url text not null,
    type text not null,
    type_exceptions jsonb null,
    section_code text not null,
    refresh_interval bigint not null,
    language text not null,
    last_checked timestamptz,
    last_publication timestamptz
);

---- create above / drop below ----

DROP TABLE IF EXISTS rss_feed;