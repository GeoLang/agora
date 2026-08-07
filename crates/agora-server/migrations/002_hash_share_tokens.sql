-- existing rows hold raw tokens and cannot be rehashed without pgcrypto, so
-- they go: every share link minted before this migration stops working
delete from share_links;

alter table share_links rename column token to token_hash;
