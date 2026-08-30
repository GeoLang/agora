alter table notifications alter column comment_id drop not null;

alter table notifications
    add column watch_id uuid references watches (id) on delete cascade;

alter table notifications
    add constraint notifications_name_one_target
    check ((comment_id is null) <> (watch_id is null));

create index notifications_watch_index on notifications (watch_id);
