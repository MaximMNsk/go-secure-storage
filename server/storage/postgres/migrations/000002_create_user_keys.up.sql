BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS public.user_keys
(
    id serial PRIMARY KEY,
    user_id int,
    user_key bytea NOT NULL,
    is_active boolean default true,
    created_at timestamp default CURRENT_TIMESTAMP
);

COMMIT ;