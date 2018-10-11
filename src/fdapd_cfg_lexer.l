%option noinput
%option nounput
%option noyywrap
%option prefix="fdapd_cfg_yy"

%{
	#include <errno.h>
	#include <string.h>
	#include <stdbool.h>
	#include "array.h"
	#include "cfg.h"
	#include "fdapd_cfg_parser.h"
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
INTVAL		[0-9]+
PNUM		[0-9]{1,5}
COMMENT		#.*$

%x PORTX

%%

"{"		|
"}"		|
":"		|
<PORTX>":"	|
";"		{ return yytext[0]; }

storage		{ return STORAGE; }
file		{ return FILETOK; }
listen		{ return LISTEN; }
tls		{ return TLS; }
tcp		{ return TCP; }
unix		{ return UNIX; }
mode		{ return MODE; }
host		{ return HOST; }
port		{ BEGIN(PORTX); return PORT; }
path		{ return PATH; }
limit		{ return LIMIT; }
ca-certs	{ return CA_CERTS; }
cert		{ return CERT; }
pk		{ return PK; }
pk-pwd		{ return PK_PWD; }

{STRVAL}	{ fdapd_cfg_yylval.STRVAL = mempool_strdup(&c->strpool, strip_quotes(yytext));		return STRVAL; }
<PORTX>{PNUM}	{ BEGIN(INITIAL); fdapd_cfg_yylval.PORTNUM = mempool_strdup(&c->strpool, yytext);	return PORTNUM; }
{INTVAL}	{ fdapd_cfg_yylval.INTVAL = strtol(yytext, NULL, 10);					return INTVAL; }
client		{ fdapd_cfg_yylval.SOCKMODE = SM_FDAPC;							return SOCKMODE; }
downstream	{ fdapd_cfg_yylval.SOCKMODE = SM_DSTREAM;						return SOCKMODE; }
yes		{ fdapd_cfg_yylval.BOOL = true;								return BOOL; }
no		{ fdapd_cfg_yylval.BOOL = false;							return BOOL; }

{COMMENT}	{ /* ignore comments   */ }
[ \t\r\n]+ 	{ /* ignore whitespace */ }
. 		{
			LOGF(LOG_ERR, "configuration parsing failed: invalid character '%c'", *yytext);
			status = 1;
			yyterminate();
		}
%%


int fdapd_cfg_parse_file(struct fdapd_cfg *cfg, const char *filename)
{
	FILE *stream = fopen(filename, "r");
	if (stream == NULL) {
		LOGF(LOG_ERR, "could not open the config file, error: %s", strerror(errno));
		return -1;
	}
	YY_BUFFER_STATE bf = yy_create_buffer(stream, YY_BUF_SIZE);
	yy_switch_to_buffer(bf);

	c = cfg;
	fdapd_cfg_init(c);
	fdapd_cfg_init_tt();
	has_tls_lsock = false;
	has_tls_block = false;
	has_stor_block = false;
	status = 0;
	int result = fdapd_cfg_yyparse();


	if (!result && !status) {
		if (ARRAY_SIZE(c->socks) == 0) {
			LOG(LOG_ERR, "At least one 'listen' block is required");
			status = -1;
		}
		if (has_tls_lsock && !has_tls_block) {
			LOG(LOG_ERR, "configuration parsing failed: 'tls' block is required when 'listen tls' is present");
			status = -1;
		}
		if (!has_tls_lsock && has_tls_block)
			LOG(LOG_NOTICE, "'tls' block is present even if it is not necessary (TLS module will be initialized)");
		if (!has_stor_block) {
			LOG(LOG_ERR, "configuration parsing failed: 'storage' block is required");
			status = -1;
		}
	}
	c->init_tls = has_tls_block;

	if (c->init_tls && c->cacert_path == NULL) {
		char *capath = autodetect_cacert_path();
		if (capath == NULL) {
			status = -1;
			LOG(LOG_ERR, "Could not determine CA certificates file location, please provide it manually.");
		}
		else
			c->cacert_path = mempool_strdup(&c->strpool, capath);
	}

	yy_delete_buffer(bf);
	fclose(stream);

	if (!result && !status)
		LOG(LOG_DEBUG, "Configuration successfully parsed");
	return (status == 0) ? result : status;
}


int fdapd_cfg_yyerror(const char *msg)
{
	LOGF(LOG_ERR, "configuration parsing failed: %s", msg);
	return 1;
}
