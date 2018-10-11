%option noinput
%option nounput
%option noyywrap
%option prefix="fdapc_cfg_yy"

%{
	#include <errno.h>
	#include <string.h>
	#include <stdbool.h>
	#include "array.h"
	#include "cfg.h"
	#include "fdapc_cfg_parser.h"
	#include "log.h"
	#include "token_table.h"
	
	int status;

	static char *strip_quotes(char *str)
	{
		str[strlen(str) - 1] = '\0';
		return (str + 1);
	}
%}

STRVAL		\".*\"
PNUM		[0-9]{1,5}
COMMENT		#.*$

%%

"{"		|
"}"		|
":"		|
";"		{ return yytext[0]; }

upstream	{ return UPSTREAM; }
tls		{ return TLS; }
tcp		{ return TCP; }
unix		{ return UNIX; }
host		{ return HOST; }
port		{ return PORT; }
ca-certs	{ return CA_CERTS; }
skip-verify	{ return SKIP_VERIFY; }
skip-cn-verify	{ return SKIP_CN_VERIFY; }
path		{ return PATH; }

{STRVAL}	{ fdapc_cfg_yylval.STRVAL = mempool_strdup(&c->strpool, strip_quotes(yytext));	return STRVAL; }
{PNUM}		{ fdapc_cfg_yylval.PORTNUM = mempool_strdup(&c->strpool, yytext);		return PORTNUM; }
yes		{ fdapc_cfg_yylval.BOOL = true;							return BOOL; }
no		{ fdapc_cfg_yylval.BOOL = false;						return BOOL; }

{COMMENT}	{ /* ignore comments   */ }
[ \t\r\n]+ 	{ /* ignore whitespace */ }
. 		{
			LOGF(LOG_ERR, "configuration parsing failed: invalid character '%c'", *yytext);
			status = 1;
			yyterminate();
		}
%%


int fdapc_cfg_parse_file(struct fdapc_cfg *cfg, const char *filename)
{
	FILE *stream = fopen(filename, "r");
	if (stream == NULL) {
		LOGF(LOG_ERR, "could not open the config file, error: %s", strerror(errno));
		return -1;
	}
	YY_BUFFER_STATE bf = yy_create_buffer(stream, YY_BUF_SIZE);
	yy_switch_to_buffer(bf);

	c = cfg;
	fdapc_cfg_init(c);
	fdapc_cfg_init_tt();
	status = 0;
	int result = fdapc_cfg_yyparse();

	if (!result && !status && ARRAY_SIZE(c->socks) == 0) {
		LOG(LOG_ERR, "At least one 'upstream' block is required");
		status = -1;
	}

	for (size_t i = 0; i < ARRAY_SIZE(c->socks); i++) {
		if (c->socks[i].cacert_path == NULL) {
			char *capath = autodetect_cacert_path();
			if (capath == NULL) {
				status = -1;
				LOG(LOG_ERR, "Could not determine CA certificates file location, please provide it manually.");
			}
			else
				c->socks[i].cacert_path = mempool_strdup(&c->strpool, capath);
		}
	}

	yy_delete_buffer(bf);
	fclose(stream);

	if (!result && !status)
		LOG(LOG_DEBUG, "Configuration successfully parsed");
	return (status == 0) ? result : status;
}


int fdapc_cfg_yyerror(const char *msg)
{
	LOGF(LOG_ERR, "configuration parsing failed: %s", msg);
	return 1;
}
