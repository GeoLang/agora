create table watches (
    id uuid primary key,
    doc_id uuid not null references documents (id) on delete cascade,
    name text not null,
    layer text not null,
    region jsonb not null,
    reducer text not null check (reducer in ('mean', 'min', 'max', 'sum', 'count')),
    interval_seconds integer not null check (interval_seconds >= 60),
    threshold_op text check (threshold_op in ('gt', 'lt')),
    threshold_value double precision,
    webhook_url text,
    webhook_secret text,
    created_by text not null,
    created_at timestamptz not null default now(),
    last_run_at timestamptz,
    last_error text,
    check ((threshold_op is null) = (threshold_value is null))
);

create index watches_doc_id_index on watches (doc_id);

create index watches_last_run_at_index on watches (last_run_at);

create table watch_readings (
    watch_id uuid not null references watches (id) on delete cascade,
    at timestamptz not null,
    value double precision not null,
    count bigint not null,
    primary key (watch_id, at)
);

create index watch_readings_at_index on watch_readings (at);
