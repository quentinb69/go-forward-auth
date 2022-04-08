home
  cookie ? 200 + refresh cookie
    => show logout form
  no cookie ? 401
    => show login form





login
  => check header & check form
    => KO => 401 + login form
    => OK => 302 + redirect home
    
logout
  => check cookie
    => KO => 401 + login form
    => OK => 302 + redirect home


template 401 = login form
template 200 = logout form

