CREATE TABLE IF NOT EXISTS email(
    id text primary key,
    doc_uuid uuid null,
    tries bigint null,
    err_message text null,
    created timestamptz not null,
    updated timestamptz not null
);

---- create above / drop below ----

DROP TABLE IF EXISTS email;