BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS public.users
(
    id serial PRIMARY KEY,
    user_name  TEXT  NOT NULL,
    user_second_name  TEXT  NOT NULL,
    user_login  TEXT  NOT NULL,
    user_pwd_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true
);

CREATE UNIQUE INDEX IF NOT EXISTS user_login
    ON public.users(user_login);

INSERT INTO public.users (user_name, user_second_name, user_login, user_pwd_hash)
    VALUES ('USER', 'PRIMARY', 'MASTER', '');

COMMIT ;