%code requires
{
	#include <string.h>
	#include "cfg.h"
	#include "log.h"
	#include "token_table.h"

	struct fdapc_cfg *c;
	struct token_table t;
}

%code provides
{
	void fdapc_cfg_init_tt(void);
	int fdapc_cfg_yylex(void);

	/* See lexer for definitions. */
	int fdapc_cfg_yyerror(const char *msg);
}

%define parse.error verbose
%define api.prefix {fdapc_cfg_yy}
%define api.value.type union
%token-table

%token <char *> STRVAL PORTNUM
%token <bool> BOOL

%token UPSTREAM "upstream"
%token TLS "tls"
%token TCP "tcp"
%token UNIX "unix"
%token HOST "host"
%token PORT "port"
%token CA_CERTS "ca-certs"
%token SKIP_VERIFY "skip-verify"
%token SKIP_CN_VERIFY "skip-cn-verify"
%token PATH "path"

%type <struct csock_cfg *> btls btcp bunix

%%

config:	%empty
	| config block
;

block: "upstream" btype;

btype:	"tls" '{' btls '}' ';'			{ tt_set_token_required(&t, HOST);
						  tt_set_token_required(&t, PORT);
						  if (!tt_check_required_tokens(&t)) YYABORT;
						  tt_reset_tokens(&t);
						  $3->trans = ST_TCP;
						  $3->use_tls = true; }

	| "tcp" '{' btcp '}' ';'		{ tt_set_token_required(&t, HOST);
						  tt_set_token_required(&t, PORT);
						  if (!tt_check_required_tokens(&t)) YYABORT;
						  tt_reset_tokens(&t);
						  $3->trans = ST_TCP;
						  $3->use_tls = false; }

	| "unix" '{' bunix '}' ';'		{ tt_set_token_required(&t, PATH);
						  if (!tt_check_required_tokens(&t)) YYABORT;
						  tt_reset_tokens(&t);
						  $3->trans = ST_UNIX;
						  $3->use_tls = false; }
; 
btls:	btls "host" ':' STRVAL ';'		{ if (tt_set_token(&t, HOST)) YYABORT;
						  $1->host = $4; }

	| btls "port" ':' PORTNUM ';'		{ if (tt_set_token(&t, PORT)) YYABORT;
						  $1->port = $4; }

	| btls "ca-certs" ':' STRVAL ';'	{ if (tt_set_token(&t, CA_CERTS)) YYABORT;
						  $1->cacert_path = $4; }
						  
	| btls "skip-verify" ':' BOOL ';'	{ if (tt_set_token(&t, SKIP_VERIFY)) YYABORT;
						  $1->tls_skip_vrf = $4; }

	| btls "skip-cn-verify" ':' BOOL ';'	{ if (tt_set_token(&t, SKIP_CN_VERIFY)) YYABORT;
						  $1->tls_skip_cn_vrf = $4; }


	| %empty				{ $$ = fdapc_cfg_new_csock(c); }
;

btcp:	btcp "host" ':' STRVAL ';'		{ if (tt_set_token(&t, HOST)) YYABORT;
						  $1->host = $4; }

	| btcp "port" ':' PORTNUM ';'		{ if (tt_set_token(&t, PORT)) YYABORT;
						  $1->port = $4; }

	| %empty				{ $$ = fdapc_cfg_new_csock(c); }
;

bunix:	bunix "path" ':' STRVAL ';'		{ if (tt_set_token(&t, PATH)) YYABORT;
						  $1->path = $4; }

	| %empty				{ $$ = fdapc_cfg_new_csock(c); }
;

%%

void fdapc_cfg_init_tt(void)
{
	tt_init(&t, &yytname);
}
