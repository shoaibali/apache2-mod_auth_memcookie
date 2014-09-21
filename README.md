apache2-mod_auth_memcookie
==========================

Fork to support SimpleSAMLphp and Apache 2.4

Takes a session cookie, looks this up in Memcache.  Sets REMOTE_User to UserName value in session. Optionally  Takes all the other session values and sticks them in X_* env vars and HTTP headers.

Configure Apache:

# Configuration example for using auth_memcookie module
LoadModule auth_memcookie_module /usr/lib/apache2/modules/mod_auth_memcookie.so

<IfModule auth_memcookie.c>
  <Location /some_service>
    Auth_memCookie_CookieName AuthMemCookie
    Auth_memCookie_Memcached_AddrPort 127.0.0.1:11211
    Auth_memCookie_Add_Remote_User_Header on
    Auth_memCookie_SessionHeaders on
    Auth_memCookie_SetSessionHTTPHeader on

    # to redirect unauthorized user to the login page
    ErrorDocument 401 "/simplesaml/authmemcookie.php"

    Auth_memCookie_Authoritative on
    AuthType Cookie
    AuthName "Login To Thing"
    Require valid-user
  </Location>

ProxyPass /some_service http://localhost:8787
ProxyPassReverse /some_service http://localhost:8787

</IfModule>

