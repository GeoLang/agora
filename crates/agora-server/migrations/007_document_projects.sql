-- The ptolemy project a document belongs to. Null means agora's own members
-- table is the only thing that grants access to it.
--
-- No foreign key and no project table: agora has no project of its own, and the
-- id is only ever handed to ptolemy to ask what the caller may do.
alter table documents add column project_id uuid;
