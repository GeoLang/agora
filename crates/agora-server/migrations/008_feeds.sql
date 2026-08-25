create table feeds (
    id uuid primary key,
    doc_id uuid not null references documents (id) on delete cascade,
    name text not null,
    interval_seconds integer not null check (interval_seconds > 0),
    created_by text not null,
    created_at timestamptz not null default now()
);

create index feeds_doc_id_index on feeds (doc_id);

create table readings (
    feed_id uuid not null references feeds (id) on delete cascade,
    asset_id text not null,
    kind text not null,
    at timestamptz not null,
    value double precision not null,
    primary key (feed_id, asset_id, kind, at)
);

create index readings_at_index on readings (at);
