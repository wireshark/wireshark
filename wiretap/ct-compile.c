/* ct-compile.c
   ------------
   Compile-time filter-compiler for Wiretap

*/

#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "ct-compile.h"

#ifdef HAVE_GLIB10
#include "glib-new.h"
#endif

#define LINE_SIZE 1024

GHashTable *field_hash;
GHashTable *protocol_hash;
char *protocol_name = NULL;
int rt_iteration;

extern struct field_info working_field; /* in ct-grammar.y */

char *ftype_text[] = {
	"NONE",
	"BOOLEAN",
	"ETHER",
	"IPv4ADDR",
	"UINT8",
	"UINT16",
	"UINT32",
	"BYTE"
};

char *ctype_text[] = {
	"NONE",
	"ANDMASK",
	"BYTECMP",
	"EITHEROF"
};

static
int many_list_subtype(struct field_info *val);

/* Called by main() to initialize the global variables that ct-compile.c
 * worries about. */
void compiler_init(void)
{
	field_hash = g_hash_table_new(g_str_hash, g_str_equal);
	protocol_hash = g_hash_table_new(g_str_hash, g_str_equal);
	field_info_init(&working_field);
}

/* takes a pointer to a field_info struct that the parser built,
 * makes a copy of the struct, and adds it to our list of fields */
void field_info_add(struct field_info *fi, char *protocol)
{
	struct field_info *new_fi;

	/* Make a duplicate of the field_info struct, destroying
	 * the pointers of the old struct in the process. */
	new_fi = g_memdup(fi, sizeof(struct field_info));
	new_fi->name = fi->name;
	new_fi->short_name = fi->short_name;
	new_fi->description = fi->description;
	new_fi->many_list = fi->many_list;
	new_fi->aliases = fi->aliases;
	fi->name = NULL;
	fi->short_name = NULL;
	fi->description = NULL;
	fi->many_list = NULL;
	fi->aliases = NULL;

	/* Find the parent */
	new_fi->parent = g_hash_table_lookup(protocol_hash, protocol);
	if (!new_fi)
		g_print("Cannot find parent protocol %s for field %s\n",
				protocol, new_fi->name);

	g_hash_table_insert(field_hash, new_fi->name, new_fi);

	g_print("field_info_add added %s (%s) \n\t"
			"ftype=%s, off=%d, len=%d, val=%d, ctype=%s\n",
			new_fi->name,
			new_fi->description,
			ftype_text[new_fi->field_type], new_fi->offset,
			new_fi->length, new_fi->value,
			ctype_text[new_fi->computation_type]);
}

/* initialize a field_info struct */
void field_info_init(struct field_info *fi)
{
	/* put NULLs in the fields that field_info_zero assumes
	 * that a non-NULL value corresponds to allocated memory. */
	fi->name = NULL;
	fi->description = NULL;
	fi->aliases = NULL;
	fi->many_list = NULL;

	field_info_zero(fi);
}

/* zero out the values of an existing field_info struct */
void field_info_zero(struct field_info *fi)
{
	if (fi->name)
		free(fi->name);
	if (fi->short_name)
		free(fi->short_name);
	if (fi->description)
		free(fi->description);

	fi->field_type = 0;
	fi->computation_type = CTYPE_NONE;
	fi->offset = 0;
	fi->length = 0;
	fi->value = 0;
	fi->parent = NULL;

	if (fi->aliases)
		g_slist_free(fi->aliases);
	if (fi->many_list)
		g_slist_free(fi->many_list);

	fi->aliases = g_slist_alloc();
	fi->many_list = g_slist_alloc();	
}

void show_aliases(gpointer alias, gpointer field)
{
	if (alias) 
		g_print("%s ", ((GString*)alias)->str);

}
/* add alias(es) to this field */
void field_info_add_alias(char *field_name, GSList *aliases)
{
	struct field_info *fi;

	fi = g_hash_table_lookup(field_hash, field_name);

	if (!fi) {
		g_print("Could not find field %s to alias.\n", field_name);
		return;
	}

	g_slist_concat(fi->aliases, aliases);
	g_print("(%s) added aliases: ", fi->name);
	g_slist_foreach(fi->aliases, show_aliases, NULL);
	g_print("\n");
}

/* Given a list of GStrings of field_names, return a list of field_info
 * pointers */
GSList* field_info_list(GSList *field_names, char *protocol)
{	
	GSList *new_list;
	char	*protocol_dot;

	protocol_dot = g_strjoin("", protocol, ".", NULL);
	g_slist_foreach(field_names, field_info_list_func1, protocol_dot);

	new_list = g_slist_alloc();
	g_slist_foreach(field_names, field_info_list_func2, new_list);

	return new_list;
}

void field_info_list_func1(gpointer node, gpointer protocol)
{
	if(node)
		g_string_prepend((GString*)node, (char*)protocol);
}
	

void field_info_list_func2(gpointer node, gpointer new_list)
{
	if (node)
		g_slist_append(new_list, 
				g_hash_table_lookup(field_hash,
						((GString*)node)->str));
/*	if (node)
		g_print("info_list added %s\n", ((GString*)node)->str);*/
}


/* add a protocol to the hash */
void protocol_layer_add(char *name, char *description)
{
	struct protocol_layer *new_pr;

	new_pr = g_malloc(sizeof(struct protocol_layer));

	new_pr->name = g_strdup(name);
	new_pr->description = g_strdup(description);

	g_hash_table_insert(protocol_hash, new_pr->name, new_pr);

	g_print("protocol_layer_add added %s (%s)\n",
			new_pr->name,
			new_pr->description);
}

/* Creates rt-scanner.l from rt-scanner-skel.l */
void write_rt_lex(void)
{
	char	buf[LINE_SIZE];
	FILE	*in, *out;

	if (!(in = fopen("rt-scanner-skel.l", "r"))) {
		g_error("Could not open rt-scanner-skel.l for reading.");
		exit(1);
	}

	if (!(out = fopen("rt-scanner.l", "w"))) {
		g_error("Could not open rt-scanner.l for writing.");
		exit(1);
	}

	while(fgets(buf, LINE_SIZE, in)) {
		if (strcmp(buf, "/* ct-compile: lex tokens */\n") == 0) {
			write_rt_lex_tokens(out);
			continue;
		}
		else {
			fprintf(out, "%s", buf);
		}
	}
	fclose(in);
	fclose(out);
}


void write_rt_lex_tokens(FILE *out)
{
	g_hash_table_foreach(field_hash, rt_lex_tokens, out);
}

void rt_lex_tokens(gpointer key, gpointer value, gpointer out)
{
	char *upcase;

	if (!value) {
		g_print("key %s has no value.\n", (char*)key);
		return;
	}

	protocol_name = ((struct field_info*) value)->parent->name;
	if (((struct field_info*) value)->aliases) {
		g_slist_foreach(((struct field_info*) value)->aliases,
				rt_lex_tokens_aliases, out);
	}
	upcase = rt_lex_token_upcase(((struct field_info*)value)->name);
	fprintf((FILE*)out, "%s\\.%s\t return %s;\n", protocol_name,
			((struct field_info*) value)->short_name,
			upcase);

	free(upcase);
}

char* rt_lex_token_upcase(char *text)
{
	char *new_text;
	char *p;
	new_text = g_strdup(text);
	g_strup(new_text);

	/* s/\./_/g */
	for (p = new_text; *p; p++) {
		if (*p == '.') {
			*p = '_';
		}
	}
	return new_text;
}


void rt_lex_tokens_aliases(gpointer node, gpointer out)
{
	if (node) {
		fprintf((FILE*)out, "%s\\.%s\t|\n",
				protocol_name,
				((GString*) node)->str);
	}
}

/* Creates rt-grammar.y from rt-grammar-skel.y */
void write_rt_yacc(void)
{
	char	buf[LINE_SIZE];
	FILE	*in, *out;

	if (!(in = fopen("rt-grammar-skel.y", "r"))) {
		g_error("Could not open rt-grammar-skel.y for reading.");
		exit(1);
	}

	if (!(out = fopen("rt-grammar.y", "w"))) {
		g_error("Could not open rt-scanner.l for writing.");
		exit(1);
	}

	while(fgets(buf, LINE_SIZE, in)) {
		if (strcmp(buf, "/* ct-compile: bytecmp_table */\n") == 0) {
			write_rt_bytecmp_table(out);
			continue;
		}
		else if (strcmp(buf, "/* ct-compile: eitherof_table */\n") == 0) {
			write_rt_eitherof_table(out);
			continue;
		}
		else if (strcmp(buf, "/* ct-compile: yacc tokens */\n") == 0) {
			write_rt_yacc_tokens(out);
			continue;
		}
		else if (strcmp(buf, "/* ct-compile: bytecmp_lval */\n") == 0) {
			write_rt_bytecmp_lval(out);
			continue;
		}
		else {
			fprintf(out, "%s", buf);
		}
	}
	fclose(in);
	fclose(out);
}

/* ------------------------- BYTECMP_TABLE -------------------- */
void write_rt_bytecmp_table(FILE *out)
{
	fprintf(out, "bytecmp_info bytecmp_table[] = {\n");
	g_hash_table_foreach(field_hash, rt_bytecmp_table, out);
	fprintf(out, "\t{ 0, 0, 0, 0 }\n};\n");
}

void rt_bytecmp_table(gpointer key, gpointer value, gpointer out)
{
	char *upcase;
	struct field_info *val = (struct field_info*) value;

	if (!val) {
		g_print("key %s has no value.\n", (char*)key);
		return;
	}

	/* return now if we're not dealing with a bytecmp field */
	if (val->computation_type == CTYPE_EITHEROF) {
		if (many_list_subtype(val) != CTYPE_BYTECMP)
			return;
	}
	else if (val->computation_type != CTYPE_BYTECMP) {
		return;
	}

	upcase = rt_lex_token_upcase(((struct field_info*)value)->name);
	fprintf((FILE*)out, "\t{ %s, %d, %d, %d },\n",
		upcase, val->computation_type, val->offset, val->length);
	free(upcase);
}

static
int many_list_subtype(struct field_info *val)
{
	struct field_info *fi;
	gchar *field1;

	if (!val->many_list)
		return 0;

	field1 = ((GString*)g_slist_nth_data(val->many_list, 1))->str;
	fi = g_hash_table_lookup(field_hash, field1);

	if (!fi)
		return 0;

	return fi->computation_type;;
}	

/* ------------------- EITHEROF_TABLE ------------------------ */
void write_rt_eitherof_table(FILE *out)
{
	fprintf(out, "eitherof_info eitherof_table[] = {\n");
	g_hash_table_foreach(field_hash, rt_eitherof_table, out);
	fprintf(out, "\t{ 0, 0, 0, 0 }\n};\n");
}

void rt_eitherof_table(gpointer key, gpointer value, gpointer out)
{
	char *upcase_field, *upcase_field1, *upcase_field2;
	struct field_info *val = (struct field_info*) value;

	if (!val) {
		g_print("key %s has no value.\n", (char*)key);
		return;
	}

	if (val->computation_type != CTYPE_EITHEROF) {
		return;
	}

	upcase_field = rt_lex_token_upcase(((struct field_info*)value)->name);
	g_print("EITHEROF checking %s\n", upcase_field);
	if (val->many_list) {
		g_print("getting fields\n");
		upcase_field1 = ((GString*)g_slist_nth_data(val->many_list, 1))->str;
		g_print("got field1 %s\n", upcase_field1);
		upcase_field2 = ((GString*)g_slist_nth_data(val->many_list, 2))->str;
		g_print("got field2 %s\n", upcase_field2);
		upcase_field1 = rt_lex_token_upcase(upcase_field1);
		g_print("got field1 %s\n", upcase_field1);
		upcase_field2 = rt_lex_token_upcase(upcase_field2);
		g_print("got field2 %s\n", upcase_field2);
	}
	else
		return;

	fprintf((FILE*)out, "\t{ %s, %d, %s, %s },\n",
			upcase_field, val->computation_type,
			upcase_field1, upcase_field2);
	free(upcase_field);
	free(upcase_field1);
	free(upcase_field2);
}

/* ---------------------- YACC_TOKENS ---------------------------- */
void write_rt_yacc_tokens(FILE *out)
{
	g_hash_table_foreach(field_hash, rt_yacc_tokens, out);
}

void rt_yacc_tokens(gpointer key, gpointer value, gpointer out)
{
	char *upcase;
	struct field_info *val = (struct field_info*) value;

	if (!val) {
		g_print("key %s has no value.\n", (char*)key);
		return;
	}

	upcase = rt_lex_token_upcase(((struct field_info*)value)->name);
	fprintf((FILE*)out, "%%token <d>\t%s\n", upcase);
	free(upcase);
}

/* ------------------------ BYTECMP_LVAL -------------------------- */
void write_rt_bytecmp_lval(FILE *out)
{
	rt_iteration = 0;
	g_hash_table_foreach(field_hash, rt_bytecmp_lval, out);
	fprintf(out, "\t;\n");
}

void rt_bytecmp_lval(gpointer key, gpointer value, gpointer out)
{
	char *upcase;
	struct field_info *val = (struct field_info*) value;

	if (!val) {
		g_print("key %s has no value.\n", (char*)key);
		return;
	}

	if (val->computation_type == CTYPE_EITHEROF) {
		if (many_list_subtype(val) != CTYPE_BYTECMP)
			return;
	}
	else if (val->computation_type != CTYPE_BYTECMP) {
		return;
	}

	if (rt_iteration == 0) {
		fprintf(out, "bytecmp_lval:\t");
	}
	else {
		fprintf(out,"\t|\t");
	}

	upcase = rt_lex_token_upcase(((struct field_info*)value)->name);
	fprintf((FILE*)out, "\t%s { $$ = %s; }\n",
			upcase, upcase);
	free(upcase);
	rt_iteration++;
}
