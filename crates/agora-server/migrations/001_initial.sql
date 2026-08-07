create table documents (
    id uuid primary key,
    name text not null,
    created_by text not null,
    created_at timestamptz not null default now(),
    checkpoint jsonb not null,
    checkpoint_seq bigint not null default 0
);

create table ops (
    doc_id uuid not null references documents (id) on delete cascade,
    seq bigint not null,
    actor text not null,
    key text not null,
    value jsonb,
    client_seq bigint not null,
    created_at timestamptz not null default now(),
    primary key (doc_id, seq)
);

create table members (
    doc_id uuid not null references documents (id) on delete cascade,
    user_id text not null,
    role text not null check (role in ('view', 'edit')),
    primary key (doc_id, user_id)
);

create table share_links (
    token text primary key,
    doc_id uuid not null references documents (id) on delete cascade,
    role text not null check (role in ('view', 'edit')),
    created_by text not null,
    revoked boolean not null default false,
    created_at timestamptz not null default now()
);

create index members_user_id_index on members (user_id);

create index share_links_doc_id_index on share_links (doc_id);
