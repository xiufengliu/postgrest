# postgrest
REST API for PostGREST



      - Docker-compose.yml
        en
      ```yaml
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

        ```sql
        GRANT SELECT ON TABLE api.v_myview TO webuser
        ```

        

   - The example of client python can be found [here ](https://github.com/monacoremo/postgrest-sessions-example/blob/master/tests.py)

- ```python
  BASE_URL = 'https://pg.myserver.site/'
  QUERY = "bronderslev_readings?id=eq.1:HM_SP18@Global?SETPOINT/EngineeringUnits&select=reading,timestamp&order=timestamp.desc"
  
  def get_session(email, password):
      session = requests.Session()
      resp = session.post(f'{BASE_URL}rpc/login', json={
          'email': email,
          'password': password
      })
      print( resp.cookies.get('session_token'))
      return session
  
  alice_session = get_session('youremailaddr', 'yourpassword')
  resp = alice_session.get(f'{BASE_URL}{QUERY}')
  
  print(resp.json())
  ```

  