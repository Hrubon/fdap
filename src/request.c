#include "filter.h"
#include "log.h"
#include "request.h"

const char *fdap_stroper(enum fdap_oper oper)
{
	switch (oper) {
	case FDAP_AUTH:
		return "authenticate";
	case FDAP_SEARCH:
		return "search";
	case FDAP_GET:
		return "get";
	case FDAP_CREATE:
		return "create";
	case FDAP_UPDATE:
		return "update";
	case FDAP_DELETE:
		return "delete";
	default:
		return "unknown";
	}
}

const char *fdap_strerr(enum fdap_res res)
{
	switch (res) {
	case FDAP_OK:
		return "Success";
	case FDAP_NOT_FOUND:
		return "Not found";
	case FDAP_ERR_INTERNAL:
		return "Internal Server Error";
	case FDAP_ERR_NOT_IMPL:
		return "Not Implemented";
	case FDAP_ERR_STR_TOO_LONG:
		return "String is too long";
	case FDAP_ERR_INVALID_FILTER:
		return "FDAP filter is invalid";
	case FDAP_ERR_INVALID_ENTRY:
		return "FDAP entry is invalid";
	case FDAP_ERR_NOT_MAP:
		return "An entry must be a CBOR map";
	case FDAP_ERR_INVALID_REF:
		return "Operation would break referential integrity";
	case FDAP_ERR_NOT_AUTH:
		return "Not atuhenticated";
	case FDAP_ERR_FORBIDDEN:
		return "Forbidden";
	default:
		assert(0);
	}
}

void fdap_request_free(struct fdap_req *r)
{
	switch (r->oper) {
	case FDAP_AUTH:
		free(r->auth.username);
		free(r->auth.pwd);
		break;
	case FDAP_SEARCH:
		filter_free(&r->filter);
		break;
	case FDAP_CREATE:
		cbor_item_free(&r->entry);
		break;
	case FDAP_UPDATE:
		cbor_item_free(&r->entry);
		break;
	default:
		break;
	}
}

void fdap_response_destroy(struct fdap_resp *r)
{
	iter_destroy(r->results);
	free(r);
}
