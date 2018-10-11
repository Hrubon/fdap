#include "fdap.h"
#include "log.h"
#include <grp.h>
#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>

typedef enum nss_status	nss_status_t;

static fdap_t fdap_enum;

/*
 * FDAP resp_enumonse, global for the module. Used to hold the state between
 * multiple NSS enumerator-like queries. We assume, that that the NSS
 * enumerator-like queries cannot overlay each other.
 */
static struct fdap_resp *resp_enum;

static bool nss_fdap_init(fdap_t *fdap)
{
	*fdap = fdap_open_default();
	return (*fdap != NULL);
}

static void nss_fdap_close(fdap_t fdap)
{
	fdap_close(fdap);
}

/*
 * Copies string `str` into `buffer` of length `buflen`. If there is not enough
 * space in the `buffer`, NSS_STATUS_TRYAGAIN will be returned.  Otherwise,
 * `buffer` will be modified to point right after just copied string; `buflen`
 * will be decreased about copied string length. Pointer to the start of
 * coppied string will be stored into `dst` parameter, and NSS_STATUS_SUCCESS
 * will be returned.
 */
static nss_status_t strcpy_to_buffer(char **dst, char *str, char **buffer, size_t *buflen)
{
	size_t len = strlen(str) + 1;
	if (*buflen < len)
		return NSS_STATUS_TRYAGAIN;
	char *pstr = *buffer;
	strcpy(pstr, str);
	*buffer += len;
	*buflen -= len;
	*dst = pstr;
	return NSS_STATUS_SUCCESS;
}

/*
 * Attempts to extract attribute named `dotname` from record `rec` as string.
 * On fail, NSS_STATUS_NOTFOUND will be returned.  On success, it will call
 * `strcpy_to_buffer`.
 */
static nss_status_t rec_to_str(char **dst, char *dotname, struct record *rec, char **buffer, size_t *buflen)
{
	char *str;
	if (!record_get_string(rec, dotname, &str)) 
		return NSS_STATUS_NOTFOUND;
	return strcpy_to_buffer(dst, str, buffer, buflen);
}

/*
 * Initialize passwd (user) entry `result` from record `rec`, using auxiliary
 * string `buffer` of length `buflen`.
 */
static nss_status_t init_passwd(struct passwd *result, struct record *rec, char *buffer, size_t buflen)
{
	memset(buffer, '\0', buflen);
	char *bptr = buffer;
	nss_status_t ret;
	if ((ret = rec_to_str(&result->pw_name, "read-only.username", rec, &bptr, &buflen))
		!= NSS_STATUS_SUCCESS) return ret;
	LOG(LOG_DEBUG, "username OK");
	if ((ret = strcpy_to_buffer(&result->pw_passwd, "x", &bptr, &buflen))
		!= NSS_STATUS_SUCCESS) return ret;
	LOG(LOG_DEBUG, "passwd OK");
	if (!record_get_int(rec, "read-only.uid", (int *)&result->pw_uid))
		return NSS_STATUS_NOTFOUND;
	LOG(LOG_DEBUG, "uid OK");
	if (!record_get_int(rec, "read-only.gid", (int *)&result->pw_gid))
		return NSS_STATUS_NOTFOUND;
	LOG(LOG_DEBUG, "gid OK");
	if ((ret = rec_to_str(&result->pw_gecos, "name", rec, &bptr, &buflen))
		!= NSS_STATUS_SUCCESS) return ret;
	LOG(LOG_DEBUG, "gecos OK");
	if ((ret = rec_to_str(&result->pw_dir, "read-only.home", rec, &bptr, &buflen))
		!= NSS_STATUS_SUCCESS) return ret;
	LOG(LOG_DEBUG, "home OK");
	if ((ret = rec_to_str(&result->pw_shell, "shell", rec, &bptr, &buflen))
		!= NSS_STATUS_SUCCESS) return ret;
	LOG(LOG_DEBUG, "shell OK");
	return NSS_STATUS_SUCCESS;
}

/*
 * Initialize shadow (password) entry `result` from record `rec`, using auxiliary
 * string `buffer` of length `buflen`.
 */

static nss_status_t init_shadow(struct spwd *result, struct record *rec, char *buffer, size_t buflen)
{
	memset(buffer, '\0', buflen);
	char *bptr = buffer;
	nss_status_t ret;
	if ((ret = rec_to_str(&result->sp_namp, "read-only.username", rec, &bptr, &buflen))
		!= NSS_STATUS_SUCCESS) return ret;

	LOG(LOG_INFO, "username OK");
	if ((ret = rec_to_str(&result->sp_pwdp, "password", rec, &bptr, &buflen))
		!= NSS_STATUS_SUCCESS) return ret;
	LOG(LOG_INFO, "passwd OK");
	result->sp_lstchg = 17476 ;
	result->sp_min = 0;
	result->sp_max = 99999;
	result->sp_warn = 7;
	result->sp_inact = 500000;
	result->sp_expire = 500000;
	result->sp_flag = 0;
	return NSS_STATUS_SUCCESS;
}

/* Initialize group entry. */
static void init_gr(struct group *result, char *buffer, size_t buflen)
{
	LOGF(LOG_NOTICE, "%s", __func__);
	memset(buffer, 0, buflen);
	char **members = (char **)buffer;
	result->gr_mem = members;

	//char *bptr = (char *)(members + 3);
	//result->gr_name = strcpy_to_buffer(&bptr, USERNAME, &buflen);
	//result->gr_gid = UID;
	//members[0] = strcpy_to_buffer(&bptr, USERNAME, &buflen);
	//members[1] = strcpy_to_buffer(&bptr, "foo", &buflen);
	members[2] = NULL;
	//result->gr_passwd = strcpy_to_buffer(&bptr, "debile", &buflen);
}


/******************************** passwd database ********************************/

nss_status_t _nss_fdap_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
	LOGF(LOG_NOTICE, "%s", __func__);
	fdap_t conn;
	if (!nss_fdap_init(&conn))
		return NSS_STATUS_UNAVAIL;
	struct fdap_resp *resp = fdap_search(conn, "read-only.username = %s", name);
	if (!resp)
		return NSS_STATUS_UNAVAIL;
	struct record *rec = iter_next(resp->results);
	nss_status_t ret;
	if (rec) {
		ret = init_passwd(result, rec, buffer, buflen);
	} else {
		if (fdap_err != FDAP_OK)
			*errnop = ENOENT;
		ret = NSS_STATUS_NOTFOUND;
	}
	fdap_response_destroy(resp);
	nss_fdap_close(conn);
	return ret;
}

nss_status_t _nss_fdap_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
	LOGF(LOG_NOTICE, "%s", __func__);
	fdap_t conn;
	if (!nss_fdap_init(&conn))
		return NSS_STATUS_UNAVAIL;
	struct fdap_resp *resp = fdap_search(conn, "read-only.uid = %i", (int)uid);
	if (!resp)
		return NSS_STATUS_UNAVAIL;
	struct record *rec = iter_next(resp->results);
	nss_status_t ret;
	if (rec) {
		ret = init_passwd(result, rec, buffer, buflen);
	} else {
		if (fdap_err != FDAP_OK)
			*errnop = ENOENT;
		ret = NSS_STATUS_NOTFOUND;
	}
	fdap_response_destroy(resp);
	nss_fdap_close(conn);
	return ret;
}

nss_status_t _nss_fdap_setpwent(void)
{
	LOGF(LOG_NOTICE, "%s", __func__);
	if (!nss_fdap_init(&fdap_enum))
		return NSS_STATUS_UNAVAIL;
	resp_enum = fdap_search(fdap_enum, "read-only.username > ''");
	if (!resp_enum)
		return NSS_STATUS_UNAVAIL;
	return NSS_STATUS_SUCCESS;
}

nss_status_t _nss_fdap_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
	LOGF(LOG_NOTICE, "%s", __func__);
	struct record *rec = iter_next(resp_enum->results);
	if (rec) {
		return init_passwd(result, rec, buffer, buflen);
	} else {
		if (fdap_err != FDAP_OK)
			*errnop = ENOENT;
		return NSS_STATUS_NOTFOUND;
	}
}

nss_status_t _nss_fdap_endpwent(void)
{
	LOGF(LOG_NOTICE, "%s", __func__);
	nss_fdap_close(fdap_enum);
	fdap_response_destroy(resp_enum);
	return NSS_STATUS_SUCCESS;
}

/******************************** shadow database ********************************/

nss_status_t _nss_fdap_getspnam_r(const char *name, struct spwd *result, char *buffer, size_t buflen, int *errnop)
{
	LOGF(LOG_NOTICE, "%s", __func__);
	fdap_t conn;
	if (!nss_fdap_init(&conn))
		return NSS_STATUS_UNAVAIL;
	struct fdap_resp *resp = fdap_search(conn, "read-only.username = %s", name);
	if (!resp)
		return NSS_STATUS_UNAVAIL;
	struct record *rec = iter_next(resp->results);
	nss_status_t ret;
	if (rec) {
		ret = init_shadow(result, rec, buffer, buflen);
	} else {
		if (fdap_err != FDAP_OK)
			*errnop = ENOENT;
		ret = NSS_STATUS_NOTFOUND;
	}
	fdap_response_destroy(resp);
	nss_fdap_close(conn);
	return ret;
}

nss_status_t _nss_fdap_setspent(void)
{
	LOGF(LOG_NOTICE, "%s", __func__);
	if (!nss_fdap_init(&fdap_enum))
		return NSS_STATUS_UNAVAIL;
	resp_enum = fdap_search(fdap_enum, "password >= ''");
	if (!resp_enum)
		return NSS_STATUS_UNAVAIL;
	return NSS_STATUS_SUCCESS;
}

nss_status_t _nss_fdap_getspent_r(struct spwd *result, char *buffer, size_t buflen, int *errnop)
{
	LOGF(LOG_NOTICE, "%s", __func__);
	struct record *rec = iter_next(resp_enum->results);
	if (rec) {
		return init_shadow(result, rec, buffer, buflen);
	} else {
		if (fdap_err != FDAP_OK)
			*errnop = ENOENT;
		return NSS_STATUS_NOTFOUND;
	}
}

nss_status_t _nss_fdap_endspent(void)
{
	LOGF(LOG_NOTICE, "%s", __func__);
	nss_fdap_close(fdap_enum);
	fdap_response_destroy(resp_enum);
	return NSS_STATUS_SUCCESS;
}

/******************************** group database ********************************/

nss_status_t _nss_fdap_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
	(void) name;
	(void) result;
	(void) buffer;
	(void) buflen;
	(void) errnop;
	return NSS_STATUS_NOTFOUND;
}

nss_status_t _nss_fdap_getgrgid_r(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
	(void) gid;
	(void) result;
	(void) buffer;
	(void) buflen;
	(void) errnop;
	return NSS_STATUS_NOTFOUND;
}

nss_status_t _nss_fdap_setgrent(void)
{
	return NSS_STATUS_SUCCESS;
}

nss_status_t _nss_fdap_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop)
{
	(void) result;
	(void) buffer;
	(void) buflen;
	(void) errnop;
	return NSS_STATUS_NOTFOUND;
}

nss_status_t _nss_fdap_endgrent(void)
{
	return NSS_STATUS_SUCCESS;
}

