create table notifications (
    id uuid primary key,
    user_id text not null,
    doc_id uuid not null references documents (id) on delete cascade,
    comment_id text not null,
    author_name text not null,
    excerpt text not null,
    created_at timestamptz not null default now(),
    read_at timestamptz
);

create index notifications_user_id_index on notifications (user_id, created_at desc);

create index notifications_comment_index on notifications (doc_id, comment_id);
