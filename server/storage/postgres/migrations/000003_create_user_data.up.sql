BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS public.user_data
(
    id serial PRIMARY KEY,
    user_id int NOT NULL ,
    user_data jsonb
);

COMMIT ;