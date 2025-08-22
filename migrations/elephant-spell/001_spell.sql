CREATE TABLE IF NOT EXISTS entry(
       language text not null,
       entry text not null,
       status text not null,
       description text not null,
       common_mistakes text[],
       primary key(language, entry)
);

CREATE INDEX idx_entry_pattern_ops ON entry (entry varchar_pattern_ops);

---- create above / drop below ----

DROP TABLE IF EXISTS entry;
