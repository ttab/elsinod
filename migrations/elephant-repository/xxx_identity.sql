create table caller_identity(
        sub text primary key not null,
        created timestamptz not null,
        updated timestamptz not null,
        name text not null,
        email text,
        data jsonb not null
);

---- create above / drop below ----

drop table caller_identity;
