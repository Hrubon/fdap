#include "fdap.h"
#include "log.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void) pamh;
	(void) flags;
	(void) argc;
	(void) argv;
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void) flags;
	(void) argc;
	(void) argv;

	LOG(LOG_INFO, "PAM-FDAP module has started-up");
	int ret;
	char* username;
	if ((ret = pam_get_user(pamh, (const char **)&username, "Username: ")) != PAM_SUCCESS)
		return ret;
	char *pwd;
	if ((ret = pam_get_authtok(pamh, PAM_AUTHTOK, (const char **)&pwd , NULL)) != PAM_SUCCESS)
		return ret;

	// TODO: Hash the password with SHA-512
	char *hash = pwd;

	fdap_t fdap = fdap_open_default();
	struct fdap_resp *resp = fdap_auth(fdap, username, hash);
	if (resp == NULL)
		return PAM_SERVICE_ERR;
	if (resp->result == FDAP_OK)
		ret = PAM_SUCCESS;
	else if (resp->result == FDAP_NOT_FOUND)
		ret = PAM_USER_UNKNOWN;
	else if (resp->result == FDAP_ERR_NOT_AUTH)
		ret = PAM_AUTH_ERR;
	else
		ret = PAM_SERVICE_ERR;
	fdap_close(fdap);
	fdap_response_destroy(resp);
	return ret;
}
