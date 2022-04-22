Lightweight GO server acting as a forward auth (for Traefik for example)

Greatly inspired by https://github.com/sohamkamani/go-session-auth-example many thanks to him

Use at your own risk, not yet secured

Endpoints :
- / is the default 
  - return 401 and a "Login page" if not signed-in and no or bad credentials supplied
  - return 300 if not signed-in and good credentials supplied
  - return 200 if signed-in and a "Welcome page"
- /logout to logout
  - return 401 if not logged
  - return 200 if logged-out
- /login to login
  - return 401 if no or bad credentials supplied
  - return if logged-in

To log in, credentials are passed via header (because POST is not forwarded to middleware by traefik)

WIP
- ~~jwt instead of cookie and session~~
- password saved as hash using bcrypt
- ssl with selfgenerating cert
- ~~choose config file from flag~~
- automatic test
- automatic image push on docker hub
- real documentation
