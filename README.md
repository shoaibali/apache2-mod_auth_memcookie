apache2-mod_auth_memcookie
==========================

Fork to support SimpleSAMLphp and Apache 2.4

Takes a session cookie, looks this up in Memcache.  Sets REMOTE_USER to UserName value in session. Optionally  Takes all the other session values and sticks them in X_* env vars and HTTP headers.

## Configure Apache:

    # Configuration example for using auth_memcookie module
    LoadModule mod_auth_memcookie_module /usr/lib/apache2/modules/mod_auth_memcookie.so

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


## Configuration options:

* Auth_memCookie_Memcached_AddrPort: ip or host address(es) and port (':' separated) of memcache daemon(s) to be used, comma separated list
* Auth_memCookie_SessionTableSize: Max number of elements in session information table. 25 by default
* Auth_memCookie_SetSessionHTTPHeader: Set to 'yes' to set session information in http headers of the authenticated users, no by default
* Auth_memCookie_CookieName: Name of cookie to get session ID from
* Auth_memCookie_MatchIP_Mode: Set to '1' to use 'X-Forwarded-For' http header, and to '2' to use 'Via' http header, otherwise use apache remote_ip. set to '0' by default
* Auth_memCookie_Authoritative: Set to 'yes' to allow access control to be passed along to lower modules, set to 'no' by default
* Auth_memCookie_SilmulateAuthBasic: Set to 'no' to fix http header and auth_type for simulating auth basic for scripting languages like php auth framework work, set to 'no' by default
* Auth_memCookie_SessionHeaders: Comma seperated list of headers that define a session - these get unset
* Auth_memCookie_Add_Remote_User_Header: Set to 'yes' to pass username in te header X-Remote-User, set to 'no' by default

## Dependencies

* apache2-dev 
* libmemcache-dev

## Build

See build.sh for an example of how to build a debian package

