create extension IF NOT EXISTS pgcrypto;
create extension IF NOT EXISTS citext;
create extension IF NOT EXISTS pgtap;

DROP SCHEMA IF EXISTS api cascade;
DROP SCHEMA IF EXISTS auth CASCADE;

DROP ROLE IF EXISTS authenticator;
create role authenticator noinherit login with password 'input_your_password';

DROP ROLE IF EXISTS anonymous;
create role anonymous nologin noinherit;

DROP ROLE IF EXISTS webuser;
create role webuser nologin noinherit;

grant anonymous, webuser to authenticator;

--REASSIGN OWNED BY auth TO xiuli; 
--DROP OWNED BY auth;
--DROP USER auth;
drop role if exists auth;
create role auth nologin;


--REASSIGN OWNED BY api TO xiuli; 
--DROP OWNED BY api;
--DROP USER api;
drop role if exists api;
create role api nologin;

alter default privileges revoke execute on functions from public;

alter default privileges for role auth, api revoke execute on functions from public;

------------------------
create schema authorization api;

set role api;

DROP TABLE IF EXISTS api.users;
create table api.users
    ( user_id     bigserial primary key
    , email       citext not null
    , name        text not null
    , password    text not null

    , unique (email)
    );



create or replace function api.cryptpassword()
    returns trigger
    language plpgsql
    as $$
        begin
            if tg_op = 'INSERT' or new.password <> old.password then
                new.password = crypt(new.password, gen_salt('bf'));
            end if;
            return new;
        end
    $$;

create trigger cryptpassword
    before insert or update
    on api.users
    for each row
    execute procedure api.cryptpassword();

grant references, select(user_id, email, password) on table api.users to auth;

grant
        select(user_id, name, email),
        insert(name, email, password),
        update(name, email, password)
    on table api.users
    to api;


grant all on api.users_user_id_seq to api;

create function api.current_user_id()
    returns integer
    language sql
    as $$
        select nullif(current_setting('auth.user_id', true), '')::integer
    $$;


grant usage on schema api to auth, api;

reset role;
------------------------------------------------


create schema authorization auth;


set role auth;


create table auth.sessions
    ( token      text not null primary key
                 default encode(gen_random_bytes(32), 'base64')
    , user_id    integer not null references api.users
    , created    timestamptz not null default clock_timestamp()
    , expires    timestamptz not null
                 default clock_timestamp() + '15min'::interval

    , check (expires > created)
    );


create view auth.active_sessions as
    select
            token,
            user_id,
            created,
            expires
        from auth.sessions
        where expires > clock_timestamp()
        with local check option;


create index on auth.sessions(expires);

create or replace function auth.clean_sessions()
    returns void
    language sql
    security definer
    as $$
        delete from auth.sessions
            where expires < clock_timestamp() - '1day'::interval;
    $$;


create or replace function auth.login(email text, password text)
    returns text
    language sql
    security definer
    as $$
        insert into auth.active_sessions(user_id)
            select user_id
            from api.users
            where
                email = login.email
                and password = crypt(login.password, password)
            returning token;
    $$;


grant execute on function auth.login to anonymous, api;

create or replace function auth.refresh_session(session_token text)
    returns void
    language sql
    security definer
    as $$
        update auth.sessions
            set expires = default
            where token = session_token and expires > clock_timestamp()
    $$;


grant execute on function auth.refresh_session to webuser;

create or replace function auth.logout(token text)
    returns void
    language sql
    security definer
    as $$
        update auth.sessions
            set expires = clock_timestamp()
            where token = logout.token
    $$;


grant execute on function auth.logout to webuser;

create or replace function auth.session_user_id(session_token text)
    returns integer
    language sql
    security definer
    as $$
        select user_id
            from auth.active_sessions
            where token = session_token;
    $$;


grant execute on function auth.session_user_id to anonymous;

create or replace function auth.authenticate()
    returns void
    language plpgsql
    as $$
        declare
            session_token text;
            session_user_id int;
        begin
            select current_setting('request.cookie.session_token', true)
                into session_token;

            select auth.session_user_id(session_token)
                into session_user_id;

            if session_user_id is not null then
                set local role to webuser;
                perform set_config('auth.user_id', session_user_id::text, true);
            else
                set local role to anonymous;
                perform set_config('auth.user_id', '', true);
            end if;
        end;
    $$;

grant execute on function auth.authenticate to anonymous;


grant usage on schema auth to api, anonymous, webuser;


reset role;



----------------------


set role api;


grant select, update(name) on api.users to webuser;

create type api.user as (
    user_id bigint,
    name text,
    email citext
);

create or replace function api.current_user()
    returns api.user
    language sql
    security definer
    as $$
        select user_id, name, email
            from api.users
            where user_id = api.current_user_id();
    $$;


grant execute on function api.current_user to webuser;


create or replace function api.login(email text, password text)
    returns void
    language plpgsql
    as $$
        declare
            session_token text;
        begin
            select auth.login(email, password) into session_token;

            if session_token is null then
                raise insufficient_privilege
                    using detail = 'invalid credentials';
            end if;

            perform set_config(
                'response.headers',
                '[{"Set-Cookie": "session_token='
                    || session_token
                    || '; Path=/; Max-Age=600; HttpOnly"}]',
                true
            );
        end;
    $$;


grant execute on function api.login to anonymous;


create or replace function api.refresh_session()
    returns void
    language plpgsql
    as $$
        declare
            session_token text;
        begin
            select current_setting('request.cookie.session_token', false)
                into strict session_token;

            perform auth.refresh_session(session_token);

            perform set_config(
                'response.headers',
                '[{"Set-Cookie": "session_token='
                    || session_token
                    || '; Path=/; Max-Age=600; HttpOnly"}]',
                true
            );
        end;
    $$;



grant execute on function api.refresh_session to webuser;


create or replace function api.logout()
    returns void
    language plpgsql
    as $$
        begin
            perform auth.logout(
                current_setting('request.cookie.session_token', true)
            );

            perform set_config(
                'response.headers',
                '[{"Set-Cookie": "session_token=; Path=/"}]',
                true
            );
        end;
    $$;



grant execute on function api.logout to webuser;


create or replace function api.register(email text, name text, password text)
    returns void
    security definer
    language plpgsql
    as $$
        begin
            insert into api.users(email, name, password)
                values(register.email, register.name, register.password);

            perform api.login(email, password);
        end;
    $$;


grant execute on function api.register to anonymous;


grant usage on schema api to anonymous, webuser;


reset role;


revoke select on table api.users from webuser;
