create table attachments (
    token_hash text primary key,
    doc_id uuid not null references documents (id) on delete cascade,
    content_type text not null,
    bytes bytea not null,
    created_by text not null,
    created_at timestamptz not null default now()
);

create index attachments_doc_id_index on attachments (doc_id);
