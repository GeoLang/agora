-- the seq of the first op of the frame this op was applied with, so a replay
-- can rebuild the frames instead of one op each. rows written before this
-- column existed become frames of one, which is how they were replayed anyway.
alter table ops add column batch_seq bigint;

update ops set batch_seq = seq where batch_seq is null;

alter table ops alter column batch_seq set not null;
