BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS public.user_data
(
    id serial PRIMARY KEY,
    user_id int NOT NULL ,
    data_type text NOT NULL ,
    user_data bytea ,
    created_at timestamp default CURRENT_TIMESTAMP
);

COMMIT ;