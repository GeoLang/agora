-- when the sweep last found the document pointing at this attachment. rows
-- written before this column existed start their grace period here, so nothing
-- already uploaded is swept before a document has been looked at.
alter table attachments add column last_referenced_at timestamptz not null default now();

create index attachments_last_referenced_index on attachments (last_referenced_at);
