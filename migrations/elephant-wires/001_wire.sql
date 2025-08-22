CREATE TABLE IF NOT EXISTS import_state(
       provider text primary key,
       updated timestamptz not null default NOW(),
       data jsonb not null
);

---- create above / drop below ----

DROP TABLE IF EXISTS import_state;
