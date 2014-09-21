/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * mod_auth_memcookie_module: memcached cookies authentication
 *
 * Autor: Mathieu CARBONNEAUX
 *
 */

/* changed by mls in 2011-04:
 *
 * - ported the code to libmemcached.
 * - made sure that the session data contains no \r or \n.
 * - made sure that the cookie is a valid md5sum.
 * - added Auth_memCookie_SessionHeaders option to specify which
 *   headers should be cleared from the input headers and taken from
 *   the session data.
 * - added szAuth_memCookie_AuthentificationURI to configure that
 *   the session is created by doing a subrequest to the specfied
 *   URI and using the returned headers (uses the configured
 *   SessionHeaders).
 * - added Auth_memCookie_AuthentificationHeader option to tell the
 *   module that it can take the user name from the specified header
 *   when it creates the session.
 * - added Auth_memCookie_AuthentificationURIOnlyAuth to make it
 *   just run the authentification steps for the subrequest
 *   (data is taken from the input headers in that case).
 * - added Auth_memCookie_CookieDomain to specify a domain for the
 *   session cookie.
 * - added Auth_memCookie_AllowAnonymous to specify that no session
 *   is required for the request.
 * - added Auth_memCookie_CommandHeader to specify a way to issue
 *   commands for session managemant: "login" makes it ignore the
 *   AllowAnonymous flag, "logout" deletes the session.
 */

#include <stdio.h>
#include <string.h>
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_uuid.h"
#include "apr_md5.h"            /* for apr_password_validate */
#include "apr_tables.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/
#include "http_vhost.h"
#include "apr_base64.h"

#include "memcached.h"



#define ERRTAG "Auth_memCookie: "
#define VERSION "1.1.0"


/* apache module name */
module AP_MODULE_DECLARE_DATA auth_memcookie_module;

/* config structure */
typedef struct {
    char *	szAuth_memCookie_memCached_addr;
    int 	nAuth_memCookie_SetSessionHTTPHeader;
    int 	nAuth_memCookie_SessionTableSize;
    char *	szAuth_memCookie_CookieName;
    int 	nAuth_memCookie_Authoritative;
    int 	nAuth_memCookie_MatchIP_Mode;
    int 	nAuth_memCookie_authbasicfix;
    char *	szAuth_memCookie_SessionHeaders;
    int     nAuth_memCookie_Add_Remote_User_Header;
} strAuth_memCookie_config_rec;


extern ap_conf_vector_t * ap_create_request_config(apr_pool_t *p);


/* Look through 'Cookie' header for indicated cookie; extract it
 * and URL-unescape it. Return the cookie on success, NULL on failure. */
static char * extract_cookie(request_rec *r, const char *szCookie_name)
{
    const char *szRaw_cookie, *szRaw_cookie_start = NULL, *szRaw_cookie_end;
    char *szCookie;
    int i;

    /* get cookie string */
    szRaw_cookie = apr_table_get(r->headers_in, "Cookie");
    if (!szRaw_cookie)
    	return 0;

    /* loop to search cookie name in cookie header */
    do {
    	/* search cookie name in cookie string */
    	if ((szRaw_cookie = strstr(szRaw_cookie, szCookie_name)) == 0)
    	    return 0;
        szRaw_cookie_start = szRaw_cookie;
    	/* search '=' */
    	if ((szRaw_cookie = strchr(szRaw_cookie, '=')) == 0)
    	    return 0;
    } while (strncmp(szCookie_name, szRaw_cookie_start, szRaw_cookie - szRaw_cookie_start) != 0);

    /* skip '=' */
    szRaw_cookie++;

    /* search end of cookie name value: ';' or end of cookie strings */
    if ((szRaw_cookie_end = strchr(szRaw_cookie, ';')) == 0 && (szRaw_cookie_end = strchr(szRaw_cookie, '\0')) == 0)
	   return 0;

    /* dup the value string found in apache pool and set the result pool ptr to szCookie ptr */
    if ((szCookie = apr_pstrndup(r->pool, szRaw_cookie, szRaw_cookie_end-szRaw_cookie)) == 0)
	   return 0;
    /* unescape the value string */
    if (ap_unescape_url(szCookie) != 0)
	   return 0;

    /* be extra paranoid about the cookie value, reject if no md5sum */
    if (!(strlen(szCookie) == 32 || strlen(szCookie)== 43))
	   return 0;
    for (i = 0; i < 32; i++) {
        if (szCookie[i] == '_')
            continue;
    	if (szCookie[i] >= '0' && szCookie[i] <= '9')
    	    continue;
    	if (szCookie[i] >= 'a' && szCookie[i] <= 'f')
    	    continue;
    	return 0;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, ERRTAG "Cleaned Cookie: %s ", szCookie);
    return szCookie;
}

/* function to fix any headers in the input request that may be relied on by an
   application. e.g. php uses the Authorization header when logging the request
   in apache and not r->user (like it ought to). It is applied after the request
   has been authenticated. */
static void fix_headers_in(request_rec *r, const char *szPassword)
{

    strAuth_memCookie_config_rec *conf = NULL;
    const char *szUser = NULL;

    /* Set an Authorization header in the input request table for php and
       other applications that use it to obtain the username (mainly to fix
       apache logging of php scripts). We only set this if there is no header
       already present. */

    if (apr_table_get(r->headers_in, "Authorization") == NULL) {

    	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "fixing apache Authorization header for this request using user:%s",r->user);

    	/* concat username and ':' */
    	if (szPassword != NULL)
    	    szUser = apr_pstrcat(r->pool, r->user, ":", szPassword, NULL);
    	else
    	    szUser = apr_pstrcat(r->pool, r->user, ":", NULL);

    	/* alloc memory for the estimated encode size of the username */
    	char *szB64_enc_user = apr_palloc(r->pool, apr_base64_encode_len(strlen(szUser)) + 1);
    	if (!szB64_enc_user) {
    	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memory alloc failed!");
    	    return;
    	}

    	/* encode username in base64 format */
    	apr_base64_encode(szB64_enc_user, szUser, strlen(szUser));

    	/* set authorization header */
    	apr_table_set(r->headers_in, "Authorization", apr_pstrcat(r->pool, "Basic ", szB64_enc_user, NULL));

    	/* force auth type to basic */
    	r->ap_auth_type = apr_pstrdup(r->pool, "Basic");
    }

    return;
}

/* get session with szCookieValue key from memcached server */
static apr_table_t *Auth_memCookie_get_session(request_rec *r, strAuth_memCookie_config_rec *conf, char *szCookieValue)
{
    char *szMemcached_addr = conf->szAuth_memCookie_memCached_addr;

    memcached_st *mc_session = NULL;
    memcached_server_st *servers = NULL;
    memcached_return mc_err = 0;

    apr_table_t *pMySession = NULL;
    size_t nGetKeyLen = strlen(szCookieValue);
    uint32_t nGetFlags = 0;
    size_t nGetLen = 0;
    char *szTokenPos;
    char *szFieldTokenPos;
    char *szField;
    char *szValue;
    char *szFieldName;
    char *szFieldValue;
    char *szMyValue;
    const char *UserName;
    int nbInfo = 0;

    if ((pMySession = apr_table_make(r->pool, conf->nAuth_memCookie_SessionTableSize)) == 0) {
    	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG "apr_tablemake failed");
    	return NULL;
    }

    /* init memcache lib */
    if ((mc_session = memcached_create(NULL)) == 0) {
	 ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memcache lib init failed");
	 return NULL;
    }
    servers = memcached_servers_parse(szMemcached_addr);
    memcached_server_push(mc_session, servers);

    if ((szValue = memcached_get(mc_session, szCookieValue, nGetKeyLen, &nGetLen, &nGetFlags, &mc_err)) == 0) {
    	ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "memcached_get failed to find key '%s'",szCookieValue);
    	memcached_free(mc_session);
    	return NULL;
    }

    /* dup szValue in pool */
    szMyValue = apr_pstrdup(r->pool, szValue);

    /* split szValue into struct strAuthSession */
    /* szValue is formated multi line (\r\n) with name=value on each line */
    /* must containe UserName,Groups,RemoteIP fieldname */
    szTokenPos = NULL;
    for (szField = strtok_r(szMyValue, "\r\n", &szTokenPos); szField; szField=strtok_r(NULL, "\r\n", &szTokenPos)) {
	szFieldTokenPos = NULL;
	ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "session field:%s",szField);
	szFieldName = strtok_r(szField, "=", &szFieldTokenPos);
	szFieldValue = strtok_r(NULL, "=", &szFieldTokenPos);
	if (szFieldName != NULL && szFieldValue != NULL) {
	    /* add key and value in pMySession table */
	    apr_table_set(pMySession, szFieldName, szFieldValue);
	    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "session information %s=%s",szFieldName,szFieldValue);

	    /* count the number of element added to table to check table size not reached */
	    nbInfo++;
	    if (nbInfo > conf->nAuth_memCookie_SessionTableSize) {
    		ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "maximum session information reached!");
    		if (szValue)
    		    free(szValue);
    		memcached_free(mc_session);
    		return NULL;
	    }
	}
    }

    if (!apr_table_get(pMySession, "UserName")) {
    	ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "Username not found in Session value(key:%s) found = %s",szCookieValue,szValue);
    	pMySession = NULL;
    } else if (conf->nAuth_memCookie_MatchIP_Mode != 0 && !apr_table_get(pMySession, "RemoteIP")) {
    	ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "MatchIP_Mode activated and RemoteIP not found in Session value(key:%s) found = %s",szCookieValue,szValue);
    	pMySession = NULL;
    } else {
    	ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "Value for Session (key:%s) found => Username=%s Groups=%s RemoteIp=%s",
    				 szCookieValue,
    				 apr_table_get(pMySession,"UserName"),
    				 apr_table_get(pMySession,"Groups"),
    				 apr_table_get(pMySession,"RemoteIP"));
    }

    /* free returned value */
    if (szValue)
	   free(szValue);

    /* free the mc session */
    memcached_free(mc_session);

    /* set the good username found in request structure */
    UserName = 0;
    if (pMySession != NULL)
	   UserName = apr_table_get(pMySession, "UserName");
    if (UserName)
	   r->user = (char *)UserName;

    return pMySession;
}

/* user apr_table_do to set session information in child environment variable */
static int Auth_memCookie_DoSetEnv(void *rec, const char *szKey, const char *szValue)
{
    request_rec *r = (request_rec*)rec;
    char *szEnvName = apr_pstrcat(r->pool,"X_",szKey,NULL);
    /* set env var X_USER to the user session value */
    apr_table_setn(r->subprocess_env, szEnvName, szValue);
    return 1;
}

/* user apr_table_do to set session information in header http */
static int Auth_memCookie_DoSetHeader(void *rec, const char *szKey, const char *szValue)
{
    // strAuth_memCookie_config_rec *conf = NULL;
    request_rec *r = (request_rec*)rec;
    const char *szHeaderName = szKey;

    /* if key does not start with X-, preprent X-MCAC_ */
    if (strncasecmp(szHeaderName, "x-", 2) != 0)
        szHeaderName = apr_pstrcat(r->pool, "X-", szHeaderName, NULL);

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG, 0,r,ERRTAG  "adding header: %s ", szHeaderName);

	/* set string header */
    if (apr_table_get(r->headers_in, szHeaderName) == NULL) {
        apr_table_addn(r->headers_in, szHeaderName, szValue);
    }
    else {
        apr_table_set(r->headers_in, szHeaderName, szValue);
    }
    return 1;
}

/**************************************************
 * authentification phase:
 * verify if cookie is set and if it is known in memcache server
 **************************************************/
static int Auth_memCookie_check_cookie(request_rec *r)
{
    strAuth_memCookie_config_rec *conf = NULL;
    char *szCookieValue = NULL;
    apr_table_t *pAuthSession = NULL;
    apr_status_t tRetStatus;
    char *szRemoteIP = NULL;
    const char *command = NULL;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "ap_hook_check_user_id in");

    /* get apache config */
    conf = ap_get_module_config(r->per_dir_config, &auth_memcookie_module);

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "check MatchIP_Mode:%d",conf->nAuth_memCookie_MatchIP_Mode);
    /* set remote ip in case of conf->nAuth_memCookie_MatchIP_Mode value */
    if (conf->nAuth_memCookie_MatchIP_Mode == 2 && apr_table_get(r->headers_in, "Via") != NULL)
	   szRemoteIP = apr_pstrdup(r->pool, apr_table_get(r->headers_in, "Via"));
    else if (conf->nAuth_memCookie_MatchIP_Mode == 1 && apr_table_get(r->headers_in, "X-Forwarded-For") != NULL)
	   szRemoteIP = apr_pstrdup(r->pool, apr_table_get(r->headers_in, "X-Forwarded-For"));
    else
	   szRemoteIP = apr_pstrdup(r->pool, r->connection->client_ip);

    if (!conf->nAuth_memCookie_Authoritative)
	   return DECLINED;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "AuthType is '%s'", ap_auth_type(r));

    if (strncmp("Cookie", ap_auth_type(r), 6) != 0) {
    	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Auth type not specified as 'Cookie'");
    	return HTTP_UNAUTHORIZED;
    }

    if (!conf->szAuth_memCookie_CookieName) {
    	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "No Auth_memCookie_CookieName specified");
    	return HTTP_UNAUTHORIZED;
    }

    if (!conf->szAuth_memCookie_memCached_addr) {
    	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "No Auth_memCookie_Memcached_AddrPort specified");
    	return HTTP_UNAUTHORIZED;
    }
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "Memcached server(s) adresse(s) are %s",conf->szAuth_memCookie_memCached_addr);

    pAuthSession = NULL;

    /* extract session cookie from headers */
    szCookieValue = extract_cookie(r, conf->szAuth_memCookie_CookieName);

    /* if we have a cookie, get session from memcache */
    if (szCookieValue) {
    	ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "got cookie; value is %s", szCookieValue);
    	if((pAuthSession = Auth_memCookie_get_session(r, conf, szCookieValue)) == NULL) {
    	    ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "AuthSession %s not found: %s", szCookieValue, r->filename);
    	}
    } else {
	   ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "cookie not found! not authorized! RemoteIP:%s", szRemoteIP);
    }

    /* unset headers sent by the client that are supposed to be set by us */
    if (conf->szAuth_memCookie_SessionHeaders) {
    	char *headers = apr_pstrdup(r->pool, conf->szAuth_memCookie_SessionHeaders);
    	char *key, *keypos = 0;
    	for(key = strtok_r(headers, ", ", &keypos); key; key = strtok_r(NULL, ", ", &keypos))
    	    apr_table_unset(r->headers_in, key);
    }

    /* still no session? goodbye */
    if (!pAuthSession)
	   return HTTP_UNAUTHORIZED;

    /* check remote ip if option is enabled */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "check ip: remote_ip=%s cookie_ip=%s", szRemoteIP ,apr_table_get(pAuthSession,"RemoteIP"));
    if (conf->nAuth_memCookie_MatchIP_Mode != 0) {
    	if (strcmp(szRemoteIP, apr_table_get(pAuthSession,"RemoteIP"))) {
    	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "unauthorized, by ip. user:%s remote_ip:%s != cookie_ip:%s", apr_table_get(pAuthSession,"UserName"),szRemoteIP ,apr_table_get(pAuthSession,"RemoteIP"));
    	    return HTTP_UNAUTHORIZED;
       }
    }

    /* set env var X_ to the information session value */
    apr_table_do(Auth_memCookie_DoSetEnv, r, pAuthSession, NULL);

    /* set REMOTE_USER var for scripts language */
    apr_table_setn(r->subprocess_env, "REMOTE_USER", apr_table_get(pAuthSession,"UserName"));

    /* set in http header the session value */
    if (conf->nAuth_memCookie_SetSessionHTTPHeader)
	   apr_table_do(Auth_memCookie_DoSetHeader, r, pAuthSession, NULL);

    /* log authorisation ok */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "authentication ok");

    /* fix http header for php */
    if (conf->nAuth_memCookie_authbasicfix)
	   fix_headers_in(r, apr_table_get(pAuthSession, "Password"));

    // do we add the X-Remote-User header?
    if (conf->nAuth_memCookie_Add_Remote_User_Header) {
        if (apr_table_get(r->headers_in, "X-Remote-User") == NULL) {
            apr_table_addn(r->headers_in, "X-Remote-User", r->user);
        }
        else {
            apr_table_set(r->headers_in, "X-Remote-User", r->user);
        }
    }

    /* if all is ok return auth ok */
    return OK;
}

static int memcookie_sink_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    return APR_SUCCESS;
}

/**************************************************
 * register module hook
 **************************************************/
static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter("MEMCOOKIE_SINK", memcookie_sink_filter, NULL, AP_FTYPE_CONTENT_SET + 1);
    ap_hook_check_user_id(Auth_memCookie_check_cookie, NULL, NULL, APR_HOOK_FIRST);
}

/************************************************************************************
 *  Apache CONFIG Phase:
 ************************************************************************************/
static void *create_Auth_memCookie_dir_config(apr_pool_t *p, char *d)
{
    strAuth_memCookie_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->szAuth_memCookie_memCached_addr = apr_pstrdup(p,"127.0.0.1:11211");
    conf->szAuth_memCookie_CookieName = apr_pstrdup(p,"AuthMemCookie");
    conf->nAuth_memCookie_MatchIP_Mode = 0;  /* method used in matchip, use (0) remote ip by default, if set to 1 for use ip from x_forwarded_for http header and 2 for use Via http header */
    conf->nAuth_memCookie_Authoritative = 0;  /* not by default */
    conf->nAuth_memCookie_authbasicfix = 0;  /* fix header for php auth by default */
    conf->nAuth_memCookie_SetSessionHTTPHeader = 0; /* set session information in http header of authenticated user */
    conf->nAuth_memCookie_SessionTableSize=25; /* Max number of element in session information table, 25 by default */
    conf->szAuth_memCookie_SessionHeaders = 0;
    conf->nAuth_memCookie_Add_Remote_User_Header = 0;
    return conf;
}

static const char *cmd_MatchIP_Mode(cmd_parms *cmd, void *InDirConf, const char *p1) {
    strAuth_memCookie_config_rec *conf = (strAuth_memCookie_config_rec*)InDirConf;

    if ((strcasecmp("1", p1) == 0) || (strcasecmp("X-Forwarded-For", p1) == 0)) {
	   conf->nAuth_memCookie_MatchIP_Mode = 1;
    } else if ((strcasecmp("2", p1) == 0) || (strcasecmp("Via", p1) == 0)) {
	   conf->nAuth_memCookie_MatchIP_Mode = 2;
    } else if ((strcasecmp("3", p1) == 0) || (strcasecmp("RemoteIP", p1) == 0)) {
	   conf->nAuth_memCookie_MatchIP_Mode = 3;
    } else {
	   conf->nAuth_memCookie_MatchIP_Mode = 0;
    }
    return NULL;
}

/* apache config fonction of the module */
static const command_rec Auth_memCookie_cmds[] =
{
    AP_INIT_TAKE1("Auth_memCookie_Memcached_AddrPort", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, szAuth_memCookie_memCached_addr),
     OR_AUTHCFG, "ip or host adressei(s) and port (':' separated) of memcache(s) daemon to be used, coma separated"),
    AP_INIT_TAKE1("Auth_memCookie_SessionTableSize", ap_set_int_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_SessionTableSize),
     OR_AUTHCFG, "Max number of element in session information table. 10 by default"),
    AP_INIT_FLAG ("Auth_memCookie_SetSessionHTTPHeader", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_SetSessionHTTPHeader),
     OR_AUTHCFG, "Set to 'yes' to set session information to http header of the authenticated users, no by default"),
    AP_INIT_TAKE1("Auth_memCookie_CookieName", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, szAuth_memCookie_CookieName),
     OR_AUTHCFG, "Name of cookie to set"),
    AP_INIT_TAKE1 ( "Auth_memCookie_MatchIP_Mode", cmd_MatchIP_Mode,
     NULL,
     OR_AUTHCFG, "To check cookie ip adresse, Set to '1' to use 'X-Forwarded-For' http header, to '2' to use 'Via' http header, and to '3' to use apache remote_ip. set to '0' by default to desactivate the ip check."),
    AP_INIT_FLAG ("Auth_memCookie_Authoritative", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_Authoritative),
     OR_AUTHCFG, "Set to 'yes' to allow access control to be passed along to lower modules, set to 'no' by default"),
    AP_INIT_FLAG ("Auth_memCookie_SilmulateAuthBasic", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_authbasicfix),
     OR_AUTHCFG, "Set to 'no' to fix http header and auth_type for simulating auth basic for scripting language like php auth framework work, set to 'no' by default"),
    AP_INIT_TAKE1("Auth_memCookie_SessionHeaders", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, szAuth_memCookie_SessionHeaders),
     OR_AUTHCFG, "Comma seperated list of headers that define a session - these get unset"),
    AP_INIT_FLAG ("Auth_memCookie_Add_Remote_User_Header", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_Add_Remote_User_Header),
     OR_AUTHCFG, "Set to 'yes' to pass username in te header X-Remote-User, set to 'no' by default"),

    {NULL}
};

/* apache module structure */
module AP_MODULE_DECLARE_DATA auth_memcookie_module =
{
    STANDARD20_MODULE_STUFF,
    create_Auth_memCookie_dir_config, /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    Auth_memCookie_cmds,              /* command apr_table_t */
    register_hooks              /* register hooks */
};
