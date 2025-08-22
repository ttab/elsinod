CREATE TABLE IF NOT EXISTS signing_key(
       id text PRIMARY KEY,
       data jsonb NOT NULL
);

---- create above / drop below ----

DROP TABLE IF EXISTS signing_key;
