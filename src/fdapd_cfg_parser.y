%code requires
{
	#include <stdbool.h>
	#include <string.h>
	#include "cfg.h"
	#include "log.h"
	#include "token_table.h"

	struct fdapd_cfg *c;
	struct token_table t;
}

%code provides
{
	bool has_tls_lsock;
	bool has_tls_block;
	bool has_stor_block;

	void fdapd_cfg_init_tt(void);
	int fdapd_cfg_yylex(void);

	/* See lexer for definitions. */
	int fdapd_cfg_yyerror(const char *msg);
}

%define parse.error verbose
%define api.prefix {fdapd_cfg_yy}
%define api.value.type union
%token-table

%token <char *> STRVAL PORTNUM
%token <int> INTVAL
%token <bool> BOOL
%token <enum sockmode> SOCKMODE

%token STORAGE "storage"
%token FILETOK "file"
%token LISTEN "listen"
%token TLS "tls"
%token TCP "tcp"
%token UNIX "unix"
%token MODE "mode"
%token HOST "host"
%token PORT "port"
%token PATH "path"
%token LIMIT "limit"
%token CA_CERTS "ca-certs"
%token CERT "cert"
%token PK "pk"
%token PK_PWD "pk-pwd"

%type <struct lsock_cfg *> btls btcp bunix

%%

config:	%empty
	| config block
;

block: "storage" storblock
	| "tls" tlsblock
	| "listen" lblock
;

storblock: '{' fileopt '}' ';'
;

fileopt: "file" ':' STRVAL ';'			{ has_stor_block = true;
						  c->stor_path = $3; }
;

tlsblock: '{' tlsopt '}' ';'			{ tt_set_token_required(&t, CERT);
						  tt_set_token_required(&t, PK);
						  if (!tt_check_required_tokens(&t)) YYABORT;
						  tt_reset_tokens(&t);
						  has_tls_block = true; }
;

tlsopt:	tlsopt "ca-certs" ':' STRVAL ';'	{ if (tt_set_token(&t, CA_CERTS)) YYABORT;
						  c->cacert_path = $4; }

	| tlsopt "cert" ':' STRVAL ';'		{ if (tt_set_token(&t, CERT)) YYABORT;
						  c->srvcert_path = $4; }

	| tlsopt "pk" ':' STRVAL ';'		{ if (tt_set_token(&t, PK)) YYABORT;
						  c->pk_path = $4; }

	| tlsopt "pk-pwd" ':' STRVAL ';'	{ if (tt_set_token(&t, PK_PWD)) YYABORT;
						  c->pk_pwd = $4; }
	| %empty
;


lblock:	"tls" '{' btls '}' ';'			{ tt_set_token_required(&t, MODE);
						  tt_set_token_required(&t, HOST);
						  tt_set_token_required(&t, PORT);
						  if (!tt_check_required_tokens(&t)) YYABORT;
						  tt_reset_tokens(&t);
						  has_tls_lsock = true;
						  $3->trans = ST_TCP;
						  $3->use_tls = true; }

	| "tcp" '{' btcp '}' ';'		{ tt_set_token_required(&t, MODE);
						  tt_set_token_required(&t, HOST);
						  tt_set_token_required(&t, PORT);
						  if (!tt_check_required_tokens(&t)) YYABORT;
						  tt_reset_tokens(&t);
						  $3->trans = ST_TCP;
						  $3->use_tls = false; }

	| "unix" '{' bunix '}' ';'		{ tt_set_token_required(&t, MODE);
						  tt_set_token_required(&t, PATH);
						  if (!tt_check_required_tokens(&t)) YYABORT;
						  tt_reset_tokens(&t);
						  $3->trans = ST_UNIX; }
;

btls:	btls "mode" ':' SOCKMODE ';'		{ if (tt_set_token(&t, MODE)) YYABORT;
						  $1->mode = $4; }

	| btls "host" ':' STRVAL ';'		{ if (tt_set_token(&t, HOST)) YYABORT;
						  $1->host = $4; }

	| btls "port" ':' PORTNUM ';'		{ if (tt_set_token(&t, PORT)) YYABORT;
						  $1->port = $4; }

	| btls "limit" ':' INTVAL ';'		{ if (tt_set_token(&t, LIMIT)) YYABORT;
						  $1->limit = $4; }

	| %empty				{ $$ = fdapd_cfg_new_lsock(c); }
;

btcp:	btcp "mode" ':' SOCKMODE ';'		{ if (tt_set_token(&t, MODE)) YYABORT;
						  $1->mode = $4; }

	| btcp "host" ':' STRVAL ';'		{ if (tt_set_token(&t, HOST)) YYABORT;
						  $1->host = $4; }

	| btcp "port" ':' PORTNUM ';'		{ if (tt_set_token(&t, PORT)) YYABORT;
						  $1->port = $4; }

	| btcp "limit" ':' INTVAL ';'		{ if (tt_set_token(&t, LIMIT)) YYABORT;
						  $1->limit = $4; }

	| %empty				{ $$ = fdapd_cfg_new_lsock(c); }
;

bunix:	bunix "mode" ':' SOCKMODE ';'		{ if (tt_set_token(&t, MODE)) YYABORT;
	     					  $1->mode = $4; }

	| bunix "path" ':' STRVAL ';'		{ if (tt_set_token(&t, PATH)) YYABORT;
						  $1->path = $4; }

	| bunix "limit" ':' INTVAL ';'		{ if (tt_set_token(&t, LIMIT)) YYABORT;
						  $1->limit = $4; }

	| %empty				{ $$ = fdapd_cfg_new_lsock(c); }
;

%%

void fdapd_cfg_init_tt(void)
{
	tt_init(&t, &yytname);
}

