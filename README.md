# postgrest
REST API for PostGREST



      - Docker-compose.yml
        en
      ```
        postgrest:
          image: postgrest/postgrest:latest
          volumes:
            - /opt/anaconda:/opt/anaconda
        environment:
            PGRST_DB_URI: postgres://authenticator:mypwd:5432/mydb
            PGRST_DB_SCHEMA: api 
            PGRST_DB_ANON_ROLE: anonymous
            PGRST_PRE_REQUEST: auth.authenticate
            PGRST_JWT_SECRET: "fdafgagdfdfaqr2rr@d/JQPi&c99!!8(#!!="  
          networks:
            nifinet:
      ```

- When add a view to schema **api**, the following permission should be granted:

  ```
  GRANT SELECT ON TABLE api.v_myview TO webuser
  ```

- The example of client python can be found [here ](<https://github.com/monacoremo/postgrest-sessions-example/blob/master/tests.py)

