%{

#ifndef __G_LIB_H__
#include <glib.h>
#endif

#include "rt-compile.h"
#include "rt-global.h"
#include "ct-compile.h"

GList* (*mk_bytecmp) (int ftype, int rel_opcode, guint8 *bytes);
void (*mk_optimize) (GList *L);

/* The encapsulation type for which we are compiling the filter */
int comp_encap_type;
int filter_parsed = 0;

bytecmp_info *bytecmp;
eitherof_info *either;
GList *L1, *L2;

/* ct-compile: bytecmp_table */
/*bytecmp_info bytecmp_table[] = {
	{ ETH_TYPE, 12, 2 },
	{ TR_DST, 2, 6 },
	{ TR_SRC, 8, 6 },
	{ ETH_DSTVENDOR, 0, 3 },
	{ 0, 0, 0 }
};*/

/* ct-compile: eitherof_table */
/*eitherof_table[] = {
	{ TR_VENDOR, CTYPE_BYTECMP, TR_SRCVENDOR, TR_DSTVENDOR },
	{ TR_ADDR, CTYPE_BYTECMP, TR_SRCADDR, TR_DSTADDR }
};
*/
%}

%union {
	gint	d;
	guint8	*b;
	GString	*s;
	GList	*L;
}

%type <d>	bytecmp_lval
%type <L>	sentence bytecmp_relation
%type <d>	bytecmp_test;

%token <b>	BYTES
%token <s>	QUOTED TEXT
%token <d>	NUMBER
%token <d>	EQ NE

/* ct-compile: yacc tokens */

%%

paragraph: /* EMPTY */
		| paragraph sentence { mk_optimize($2); filter_parsed = 1; }
		;

sentence:	bytecmp_relation { $$ = $1 }
		;
	

bytecmp_relation:	bytecmp_lval bytecmp_test BYTES
{
	bytecmp = lookup_bytecmp($1);
	if (bytecmp->ctype == CTYPE_EITHEROF) {
		either = lookup_eitherof($1);
		L1 = mk_bytecmp(either->field1, $2, $3);
		L2 = mk_bytecmp(either->field2, $2, $3);
		$$ = g_list_concat(L1, L2);
	}
	else {
		$$ = mk_bytecmp($1, $2, $3);
	}
}
		;

/* ct-compile: bytecmp_lval */
/*bytecmp_lval:	TR_DST { $$ = TR_DST; }
	|	TR_SRC { $$ = TR_SRC; }
	|	TR_SRCVENDOR { $$ = TR_SRCVENDOR; }
	|	TR_DSTVENDOR { $$ = TR_DSTVENDOR; }
	;*/

bytecmp_test:	EQ { $$ = EQ; }
	|	NE { $$ = NE; }
	;

%%

bytecmp_info*
lookup_bytecmp(int ftype)
{
	bytecmp_info *b = &bytecmp_table[0];
	bytecmp_info *ret_val = NULL;

	/* find the field in the table */
	while (b->ftype != 0) {
		if (b->ftype == ftype) {
			ret_val = b;
			break;
		}
		else {
			b++;
		}
	}

	return ret_val;
}


eitherof_info*
lookup_eitherof(int ftype)
{
	eitherof_info *e = &eitherof_table[0];
	eitherof_info *ret_val = NULL;

	/* find the field in the table */
	while (e->ftype != 0) {
		if (e->ftype == ftype) {
			ret_val = e;
			break;
		}
		else {
			e++;
		}
	}

	return ret_val;
}
