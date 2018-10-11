%code requires
{
	#include "cbor.h"
	#include "filter.h"
	
	struct filter *f;
}

%code provides
{
	int filter_yylex(void);
	
	/* See lexer for definitions. */
	int filter_yyerror(const char *msg);
}

%define parse.error verbose
%define api.prefix {filter_yy}
%define api.value.type union

%token EOL
%token IF_HAS_THEN
%token <struct aname *> ANAME
%token <enum filter_oper> OPER
%token <struct cbor_item> VALUE 

%type <struct filter_node *> filter and or expr cond;

%%

start: %empty
	| start filter		{ f->tree = $2; }
	| start filter EOL	{ f->tree = $2; }
;

filter: expr			/* Default action: { $$ = $1; } */
	| and
	| or
;

and: and '&' expr		{ $$ = filter_new_binary(f, FILTER_OPB_AND, $1, $3); }
	| expr '&' expr		{ $$ = filter_new_binary(f, FILTER_OPB_AND, $1, $3); } 
;

or: or '|' expr			{ $$ = filter_new_binary(f, FILTER_OPB_OR, $1, $3); }
	| expr '|' expr		{ $$ = filter_new_binary(f, FILTER_OPB_OR, $1, $3); }
;

expr: cond					
	| '!' expr		{ $$ = filter_new_unary(f, FILTER_OPU_NOT, $2); }
	| '(' filter ')'	{ $$ = $2; }
;

cond: ANAME OPER VALUE			{ $$ = filter_new_cond(f, $1, $2, $3, false); }
    	| ANAME IF_HAS_THEN OPER VALUE	{ $$ = filter_new_cond(f, $1, $3, $4, true); }


%%

