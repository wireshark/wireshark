/* ct-compile.h
   ------------
   Compile-time filter-compiler for Wiretap

*/

#ifndef __G_LIB_H__
#include <glib.h>
#endif

/* field type IDs */
#define FTYPE_BOOLEAN	1
#define FTYPE_ETHER	2
#define FTYPE_IPv4ADDR	3
#define FTYPE_UINT8	4
#define FTYPE_UINT16	5
#define FTYPE_UINT32	6
#define FTYPE_BYTE	7

/* field lengths */
#define FLEN_BOOLEAN	1
#define FLEN_ETHER	6
#define FLEN_IPv4ADDR	4
#define FLEN_UINT8	1
#define FLEN_UINT16	2
#define FLEN_UINT32	4
/*      FLEN_BYTE doesn't get a fixed length, of course */

/* computation types */
#define CTYPE_NONE	0
#define CTYPE_ANDMASK	1
#define CTYPE_BYTECMP	2
#define CTYPE_EITHEROF	3

/* Protocol-layer information */
struct protocol_layer {
	char	*name;
	char	*description;
	GSList	*parents;
};

/* Fields */
struct field_info {
	char	*name;
	char	*short_name;
	char	*description;
	int	field_type;
	int	computation_type;
	int	offset;
	int	value;
	int	length;

	GSList	*aliases;
	GSList	*many_list;

	struct protocol_layer *parent;
};

/* Add a field-info struct to the compiler's list of fields */
void field_info_add(struct field_info *fi, char *protocol);

/* Initialize values in a field_info struct. This can only be run once per
 * structure, as it would cause a memory leak if used multiple times. */
void field_info_init(struct field_info *fi);

/* Zero-out the values in a field_info struct. This can be used more than once
 * per structure, as it avoids a memory leak. But call field_info_init the
 * first time, and field_info_zero for all other times */
void field_info_zero(struct field_info *fi);

/* add alias(es) to this field */
void field_info_add_alias(char *field_name, GSList *aliases);

/* add a protocol to the hash */
void protocol_layer_add(char *name, char *description);

/* Given a list of GStrings of field names, returns a list of pointers
 * to field_info structs */
GSList* field_info_list(GSList *field_names, char *protocol);

/* used by field_info_list() */
void field_info_list_func1(gpointer node, gpointer protocol);
void field_info_list_func2(gpointer node, gpointer new_list);

void compiler_init(void);
void write_rt_lex(void);
void write_rt_lex_tokens(FILE *out);
void rt_lex_tokens(gpointer key, gpointer value, gpointer out);
void rt_lex_tokens_aliases(gpointer node, gpointer out);
char* rt_lex_token_upcase(char *text);

void write_rt_yacc(void);
void write_rt_bytecmp_table(FILE *out);
void rt_bytecmp_table(gpointer key, gpointer value, gpointer out);
void write_rt_eitherof_table(FILE *out);
void rt_eitherof_table(gpointer key, gpointer value, gpointer out);
void write_rt_yacc_tokens(FILE *out);
void rt_yacc_tokens(gpointer key, gpointer value, gpointer out);
void write_rt_bytecmp_lval(FILE *out);
void rt_bytecmp_lval(gpointer key, gpointer value, gpointer out);

int yylex(void);
int yyparse(void);
void yyerror(char *string);
