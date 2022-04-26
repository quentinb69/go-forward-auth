Lightweight GO server acting as a "forward-auth" middleware (in Traefik for instance).

Inspired by https://github.com/sohamkamani/go-session-auth-example many thanks to him.

Use at your own risk, not yet secured. Feel free to PR/Issue if you detect security issues :)

Endpoints :
- / for html rendering and forward-auth url 
  - return 401 and a "Login page" if no valid JWT and invalid credentials supplied
  - return 300 if no valid JWT and valid credentials supplied (means you logged-in succesfully)
  - return 200 and a "Welcome <user> page" if valid JWT
- /logout to logout
  - return 401 if invalid JWT
  - return 200 if valid JWT
- /login to login without using "/"
  - return 401 if invalid credentials supplied
  - return 200 if valid credentials supplied (means you logged-in succesfully)

To log-in, credentials are supplied via Header "Auth-Form" (POST is not forwarded to middlewares by Traefik)

WIP
- ~~jwt instead of cookie and session~~
- ~~password saved as hash using bcrypt~~
- ~~ssl with selfsigned cert~~
- ~~choose config file from flag~~
- ~~automatic image push on docker hub (quentinb69/go-forward-auth)~~
- use actions and CSRF ? (not sure if needed)
- help tool for bcrypt
- pass header value such as username when valid JWT
- automatic test
- real documentation
- reacto for clean code
