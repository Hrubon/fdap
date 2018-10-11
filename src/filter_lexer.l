%option noinput
%option nounput
%option noyywrap
%option prefix="filter_yy"

%{
	#include <string.h>
	#include "cbor.h"
	#include "filter.h"
	#include "filter_parser.h"
	#include "fdap.h"
	#include "log.h"
	
	struct cbor_item v;
	int status;
%}

ID		[a-zA-Z_@][a-zA-Z0-9_\-@]*
STRVAL		'(\\\\|\\'|[^\\'])*'
INTVAL		(\+|-)?[0-9]+

%x SVALX

%%
"\&"		|
"|"		|
"!"		|
"("		|
")"		{ return yytext[0]; }

"<"		{ filter_yylval.OPER = FILTER_OPER_LT;		return OPER; }
"<="		{ filter_yylval.OPER = FILTER_OPER_LE;		return OPER; }
"="		{ filter_yylval.OPER = FILTER_OPER_EQ;		return OPER; }
"!="		{ filter_yylval.OPER = FILTER_OPER_NE;		return OPER; }
">="		{ filter_yylval.OPER = FILTER_OPER_GE;		return OPER; }
">"		{ filter_yylval.OPER = FILTER_OPER_GT;		return OPER; }
"?"		{ return IF_HAS_THEN; }

{STRVAL}	{ cbor_item_set_escaped_text_pool(&v, yytext, &f->pool);	filter_yylval.VALUE = v;	return VALUE; }
{INTVAL}	{ cbor_item_set_int(&v, strtol(yytext, NULL, 10));		filter_yylval.VALUE = v;	return VALUE; }
false		{ cbor_item_set_sval(&v, CBOR_SVAL_FALSE);			filter_yylval.VALUE = v;	return VALUE; }
true		{ cbor_item_set_sval(&v, CBOR_SVAL_TRUE);			filter_yylval.VALUE = v;	return VALUE; }
null		{ cbor_item_set_sval(&v, CBOR_SVAL_NULL);			filter_yylval.VALUE = v;	return VALUE; }
undef		{ cbor_item_set_sval(&v, CBOR_SVAL_UNDEF);			filter_yylval.VALUE = v;	return VALUE; }
 
simple\(	{ BEGIN(SVALX); }
<SVALX>{INTVAL}	{ cbor_item_set_sval(&v, (uint8_t)strtol(yytext, NULL, 10));		filter_yylval.VALUE = v;	return VALUE; }
<SVALX>\)	{ BEGIN(INITIAL); }

{ID}(\.{ID})*	{ filter_yylval.ANAME = aname_new(yytext, &f->pool);  return ANAME; }

"\n" 		{ return EOL; }
[ \t\r]+ 	{ /* ignore whitespace */ }
. 		{
			LOGF(LOG_ERR, "Filter parsing failed: invalid character '%c'", *yytext);
			status = 1;
			yyterminate();
		}
%%


static int filter_parse(struct filter *filter, YY_BUFFER_STATE bf)
{
	f = filter;
	filter_init(f);
	yy_switch_to_buffer(bf);
	status = 0;
	int result = filter_yyparse();
	yy_delete_buffer(bf);
	if (!result && !status)
		LOG(LOG_DEBUG, "Filter parsing completed successfully");
	return (status == 0) ? result : status;
}


int filter_parse_string(struct filter *filter, const char *str)
{
	YY_BUFFER_STATE bf = yy_scan_string(str);
	return filter_parse(filter, bf);
}


int filter_parse_file(struct filter *filter, FILE *stream)
{
	YY_BUFFER_STATE bf = yy_create_buffer(stream, YY_BUF_SIZE);
	return filter_parse(filter, bf);
}


int filter_yyerror(const char *msg)
{
	LOGF(LOG_ERR, "Filter parsing failed: %s", msg);
	return 1;
}
