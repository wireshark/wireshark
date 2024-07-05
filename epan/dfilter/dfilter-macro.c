/* dfilter-macro.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_DFILTER
#include "dfilter-macro.h"
#include "dfilter-macro-uat.h"

#ifdef DUMP_DFILTER_MACRO
#include <stdio.h>
#endif
#include <string.h>

#include "dfilter-int.h"
#include <ftypes/ftypes.h>
#include <epan/proto.h>
#include <wsutil/glib-compat.h>
#include <wsutil/filter_files.h>

static GHashTable *macros_table;

/* #define DUMP_DFILTER_MACRO */
#ifdef DUMP_DFILTER_MACRO
void dump_dfilter_macro_t(const dfilter_macro_t *m, const char *function, const char *file, int line);
#define DUMP_MACRO(m) dump_dfilter_macro_t(m, G_STRFUNC, __FILE__, __LINE__)
#else
#define DUMP_MACRO(m)
#endif

static char* dfilter_macro_resolve(char* name, char** args, df_error_t** error) {
	GString* text;
	int argc = 0;
	dfilter_macro_t* m = NULL;
	int* arg_pos_p;
	char** parts;
	char* ret;

	m = g_hash_table_lookup(macros_table, name);
	if (!m || !m->usable) {
		if (error != NULL)
			*error = df_error_new_printf(DF_ERROR_GENERIC, NULL, "macro '%s' does not exist", name);
		return NULL;
	}

	DUMP_MACRO(m);

	if (args) {
		while(args[argc]) argc++;
	}

	if (argc != m->argc) {
		if (error != NULL) {
			*error = df_error_new_printf(DF_ERROR_GENERIC, NULL,
							"wrong number of arguments for macro '%s', expecting %d instead of %d",
							name, m->argc, argc);
		}
		return NULL;
	}

	arg_pos_p = m->args_pos;
	parts = m->parts;

	text = g_string_new(*(parts++));

	if (args) {
		while (*parts) {
			g_string_append_printf(text,"%s%s",
					       args[*(arg_pos_p++)],
					       *(parts++));
		}
	}

	ret = wmem_strdup(NULL, text->str);

	g_string_free(text,TRUE);

	return ret;
}

/* Start points to the first character after "${" */
static bool start_is_field_reference(const char *start)
{
	const char *end;
	char saved_c;
	const header_field_info *hfinfo;

	end = strpbrk(start, "#}:;");
	if (end == NULL)
		return false;

	saved_c = *end;
	if (saved_c == ';' || saved_c == ':') {
		/* Cannot be a field, looks like macro. */
		return false;
	}

	/* This violates constness but we will restore the original string. */
	*(char *)end = '\0';
	/* Search for name in registered fields. */

	if (start[0] == '@')
		start++;

	hfinfo = dfilter_resolve_unparsed(start, NULL);
	/* Restore mangled string. */
	*(char *)end = saved_c;

	if (hfinfo == NULL)
		return false;

	if (hfinfo->type == FT_PROTOCOL || hfinfo->type == FT_NONE) {
		/* Ignore these? */
		return false;
	}

	/* It's a field reference so ignore it as a macro. */
	ws_noisy("Ignore field reference ${%s}", start);
	return true;
}

static inline char
close_char(int c)
{
	switch (c) {
		case '(': return ')';
		case '{': return '}';
		default: break;
	}
	ws_assert_not_reached();
}

static char* dfilter_macro_apply_recurse(const char* text, unsigned depth, df_error_t** error) {
	enum { OUTSIDE, STARTING, NAME, NAME_PARENS, ARGS } state = OUTSIDE;
	GString* out;
	GString* name = NULL;
	GString* arg = NULL;
	GPtrArray* args = NULL;
	char c;
	char open_c = 0; // parenthesis or curly brace
	const char* r = text;
	bool changed = false;
	char* resolved;

	if ( depth > 31) {
		if (error != NULL)
			*error = df_error_new_msg("too much nesting in macros");
		return NULL;
	}

#define FGS(n) if (n) g_string_free(n,TRUE); n = NULL

#define FREE_ALL() \
	do { \
		FGS(name); \
		FGS(arg); \
		if (args) { \
			while(args->len) { void* p = g_ptr_array_remove_index_fast(args,0); g_free(p); } \
			g_ptr_array_free(args,true); \
			args = NULL; \
		} \
		open_c = 0; \
	} while(0)

#define MACRO_NAME_CHAR(c) (g_ascii_isalnum(c) || (c) == '_')

	if (error != NULL)
		*error = NULL;
	out = g_string_sized_new(64);

	while(1) {
		c = *r++;

		switch(state) {
			case OUTSIDE:
			{
				switch(c) {
					case '\0':
						goto finish;
					case '$':
						state = STARTING;
						break;
					default:
						g_string_append_c(out,c);
						break;
				}
				break;
			}
			case STARTING:
			{
				switch (c) {
					case '{':
						if (start_is_field_reference(r)) {
							/* We have a field reference, preserve the name with ${} and bail. */
							g_string_append(out,"${");
							state = OUTSIDE;
							break;
						}

						/* We have a macro, continue. */
						args = g_ptr_array_new();
						arg = g_string_sized_new(32);
						name = g_string_sized_new(32);

						state = NAME;
						open_c = c;

						break;
					case '\0':
						g_string_append_c(out,'$');

						goto finish;
					default:
						if (MACRO_NAME_CHAR(c)) {
							/* Possible macro of the form $macro_name() */
							args = g_ptr_array_new();
							arg = g_string_sized_new(32);
							name = g_string_sized_new(32);
							g_string_append_c(name,c);
							state = NAME_PARENS;
						}
						else {
							/* Not a macro. */
							g_string_append_c(out,'$');
							g_string_append_c(out,c);
							state = OUTSIDE;
						}

						break;
				}
				break;
			}
			case NAME:
			{
				if (MACRO_NAME_CHAR(c)) {
					g_string_append_c(name,c);
				} else if ( c == ':' || c == ';' ) {
					/* XXX - The traditional form with ':' makes for a more
					 * complicated grammar because ':' is found inside
					 * literals and args can be literals. (See #19499)
					 */
					state = ARGS;
				} else if ( c == '}') {
					g_ptr_array_add(args,NULL);

					resolved = dfilter_macro_resolve(name->str, (char**)args->pdata, error);
					if (resolved == NULL)
						goto on_error;

					changed = true;

					g_string_append(out,resolved);
					wmem_free(NULL, resolved);

					FREE_ALL();

					state = OUTSIDE;
				} else if ( c == '\0') {
					if (error != NULL)
						*error = df_error_new_msg("end of filter in the middle of a macro expression");
					goto on_error;
				} else {
					/* XXX - Spaces or other whitespace after the macro name but
					 * before the ':' or ';' are not allowed. Should it be?
					 */
					if (error != NULL)
						*error = df_error_new_msg("invalid character in macro name");
					goto on_error;
				}
				break;
			}
			case NAME_PARENS:
			{
				if (MACRO_NAME_CHAR(c)) {
					g_string_append_c(name,c);
				} else if ( c == '(' || c == '{') {
					state = ARGS;
					open_c = c;
				} else {
					/* Not a macro, walk back */
					g_string_append_c(out,'$');
					g_string_append(out,name->str);
					g_string_append_c(out,c);
					FREE_ALL();
					if (c == '\0')
						goto finish;
					state = OUTSIDE;
				}
				break;
			}
			case ARGS:
			{
				switch(c) {
					case '\0':
						if (error != NULL)
							*error = df_error_new_msg("end of filter in the middle of a macro expression");
						goto on_error;
					case ';':
					case ',':
						if (arg->len == 0) {
							/* Null arguments aren't accepted */
							if (error != NULL)
								*error = df_error_new_msg("null argument in macro expression");
							goto on_error;
						}
						g_ptr_array_add(args,g_string_free(arg,FALSE));

						arg = g_string_sized_new(32);
						break;
					case '\\':
						c = *r++;
						if (c) {
							g_string_append_c(arg,c);
							break;
						} else {
							if (error != NULL)
								*error = df_error_new_msg("end of filter in the middle of a macro expression");
							goto on_error;
						}
					case '}':
					case ')':
						if (c != close_char(open_c)) {
							/* Accept character and continue parsing args. */
							g_string_append_c(arg,c);
							break;
						}

						if (arg->len == 0) {
							/* Null arguments aren't accepted... */
							if (args->len != 0) {
								/* Except $macro() or ${macro:} means zero args, not one null arg */
								if (error != NULL)
									*error = df_error_new_msg("null argument in macro expression");
								goto on_error;
							}
						} else {
							g_ptr_array_add(args,g_string_free(arg,FALSE));
							g_ptr_array_add(args,NULL);
							arg = NULL;
						}

						resolved = dfilter_macro_resolve(name->str, (char**)args->pdata, error);
						if (resolved == NULL)
							goto on_error;

						changed = true;

						g_string_append(out,resolved);
						wmem_free(NULL, resolved);

						FREE_ALL();

						state = OUTSIDE;
						break;
					default:
						/* XXX - Spaces and other whitespace are passed through
						 * whether interior or exterior to the rest of the
						 * argument, which is powerful but confusing.
						 */
						g_string_append_c(arg,c);
						break;
				}
				break;
			}
		}
	}

finish:
	{
		FREE_ALL();

		if (changed) {
			resolved = dfilter_macro_apply_recurse(out->str, depth + 1, error);
			g_string_free(out,TRUE);
			return resolved;
		} else {
			char* out_str = wmem_strdup(NULL, out->str);
			g_string_free(out,TRUE);
			return out_str;
		}
	}
on_error:
	{
		FREE_ALL();
		if (error != NULL) {
			if (*error == NULL)
				*error = df_error_new_msg("unknown error in macro expression");
		}
		g_string_free(out,TRUE);
		return NULL;
	}
}

char* dfilter_macro_apply(const char* text, df_error_t** error) {
	return dfilter_macro_apply_recurse(text, 0, error);
}

/* Parses the text into its parts and arguments. Needs to
 * be called before a macro can be used. */
void macro_parse(dfilter_macro_t* m) {
	GPtrArray* parts;
	GArray* args_pos;
	const char* r;
	char* w;
	char* part;
	int argc = 0;

	DUMP_MACRO(m);

	parts = g_ptr_array_new();
	args_pos = g_array_new(false,false,sizeof(int));

	m->priv = part = w = g_strdup(m->text);
	r = m->text;
	g_ptr_array_add(parts,part);

	while (r && *r) {

		switch (*r) {
			default:
				*(w++) = *(r++);
				break;
			case '\0':
				*w = *r;
				goto done;
			case '\\':
				*(w++) = *(r++);
				if(*r)
					*(w++) = *(r++);
				break;
			case '$':
			{
				int cnt = 0;
				int arg_pos = 0;
				do {
					char c = *(r+1);
					if (c >= '0' && c <= '9') {
						cnt++;
						r++;
						*(w++) = '\0';
						arg_pos *= 10;
						arg_pos += c - '0';
					} else {
						break;
					}
				} while(*r);

				if (cnt) {
					*(w++) = '\0';
					r++;
					argc = argc < arg_pos ? arg_pos : argc;
					arg_pos--;
					g_array_append_val(args_pos,arg_pos);
					g_ptr_array_add(parts,w);
				} else {
					*(w++) = *(r++);
				}
				break;
			}
		}

	}

done:
	g_ptr_array_add(parts,NULL);

	g_free(m->parts);
	m->parts = (char **)g_ptr_array_free(parts, false);

	g_free(m->args_pos);
	m->args_pos = (int*)(void *)g_array_free(args_pos, false);

	m->argc = argc;

	m->usable = true;

	DUMP_MACRO(m);
}

static void macro_free(dfilter_macro_t* m) {
	DUMP_MACRO(r);

	g_free(m->name);
	g_free(m->text);
	g_free(m->priv);
	g_free(m->parts);
	g_free(m->args_pos);
	g_free(m);
}

dfilter_macro_t *macro_new(const char *name, const char *text) {
	dfilter_macro_t *m = g_new0(dfilter_macro_t, 1);
	m->name = g_strdup(name);
	m->text = g_strdup(text);
	macro_parse(m);
	return m;
}

void dfilter_macro_init(void) {
	macros_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)macro_free);
	dfilter_macro_reload();
}

static bool check_macro(const char *name, const char *text, const char **errp)
{
	if (*name == '\0') {
		*errp = "empty name";
		return false;
	}
	if (*text == '\0') {
		*errp = "empty text";
		return false;
	}
	for (const char *s = name; *s != '\0'; s++) {
		if (!(g_ascii_isalnum(*s) || *s == '_')) {
			*errp = "invalid char in name";
			return false;
		}
	}
	if (g_hash_table_contains(macros_table, name)) {
		*errp = "name already exists";
		return false;
	}
	return true;
}

void dfilter_macro_reload(void) {

	/* Check if we need to convert an old dfilter_macro configuration file.
	 * We do so only if a new one doesn't exist. We need to do this check
	 * for every reload because the configuration profile might have changed. */
	convert_old_uat_file();

	g_hash_table_remove_all(macros_table);

	filter_list_t *list = ws_filter_list_read(DMACROS_LIST);
	const char *err;

	for (GList *l = list->list; l != NULL; l = l->next) {
		filter_def *def = l->data;
		if (!check_macro(def->name, def->strval, &err)) {
			ws_warning("Invalid macro '%s': %s",def->name, err);
			continue;
		}
		dfilter_macro_t *m = macro_new(def->name, def->strval);
		if (m != NULL) {
			g_hash_table_insert(macros_table, g_strdup(def->name), m);
		}
	}

	ws_filter_list_free(list);
}

#ifdef DUMP_DFILTER_MACRO
/*
 * The dfilter_macro_t has several characteristics that are
 * not immediately obvious. The dump_dfilter_filter_macro_t()
 * function can be used to help "visualize" the contents of
 * a dfilter_macro_t.
 *
 * Some non-obvious components of this struct include:
 *
 *    m->parts is an argv style array of pointers into the
 *    m->priv string.
 *
 *    The last pointer of an m->parts array should contain
 *    NULL to indicate the end of the parts pointer array.
 *
 *    m->priv is a "cooked" copy of the m->text string.
 *    Any variable substitution indicators within m->text
 *    ("$1", "$2", ...) will have been replaced with ASCII
 *    NUL characters within m->priv.
 *
 *    The first element of m->parts array (m-parts[0]) will
 *    usually have the same pointer value as m->priv (unless
 *    the dfilter-macro starts off with a variable
 *    substitution indicator (e.g. "$1").
 */

void dump_dfilter_macro_t(const dfilter_macro_t *m, const char *function, const char *file, int line)
{
	printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

	if(m == NULL) {
		printf("  dfilter_macro_t * == NULL! (via: %s(): %s:%d)\n", function, file, line);
		printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
		return;
	}

	printf("DUMP of dfilter_macro_t: %p (via: %s(): %s:%d)\n", m, function, file, line);

	printf("  &dfilter_macro->name     == %p\n", &m->name);
	if(m->name == NULL) {
		printf("                ->name     == NULL\n");
	} else {
		printf("                ->name     == %p\n", m->name);
		printf("                ->name     == <%s>\n", m->name);
	}

	printf("  &dfilter_macro->text     == %p\n", &m->text);
	if(m->text == NULL) {
		printf("                ->text     == NULL\n");
	} else {
		printf("                ->text     == %p\n", m->text);
		printf("                ->text     == <%s>\n", m->text);
	}

	printf("  &dfilter_macro->usable   == %p\n", &m->usable);
	printf("                ->usable   == %u\n", m->usable);

	printf("  &dfilter_macro->parts    == %p\n", &m->parts);

	if(m->parts == NULL) {
		printf("                ->parts    == NULL\n");
	} else {
		int i = 0;

		while (m->parts[i]) {
			printf("                ->parts[%d] == %p\n", i, m->parts[i]);
			printf("                ->parts[%d] == <%s>\n", i, m->parts[i]);
			i++;
		}
		printf("                ->parts[%d] == NULL\n", i);
	}

	printf("  &dfilter_macro->args_pos == %p\n", &m->args_pos);
	if(m->args_pos == NULL) {
		printf("                ->args_pos == NULL\n");
	} else {
		printf("                ->args_pos == %p\n", m->args_pos);
		/*printf("                ->args_pos == <%?>\n", m->args_pos);*/
	}

	printf("  &dfilter_macro->argc     == %p\n", &m->argc);
	printf("                ->argc     == %d\n", m->argc);

	printf("  &dfilter_macro->priv     == %p\n", &m->priv);
	if(m->priv == NULL) {
		printf("                ->priv     == NULL\n");
	} else {
		printf("                ->priv     == %p\n", m->priv);
		printf("                ->priv     == <%s>\n", (char *)m->priv);
	}

	printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
}
#endif

void dfilter_macro_cleanup(void)
{
	g_hash_table_destroy(macros_table);
	macros_table = NULL;
}

size_t
dfilter_macro_table_count(void)
{
	return g_hash_table_size(macros_table);
}

void
dfilter_macro_table_iter_init(struct dfilter_macro_table_iter *iter)
{
	g_hash_table_iter_init(&iter->iter, macros_table);
}

bool
dfilter_macro_table_iter_next(struct dfilter_macro_table_iter *iter,
				const char **name_ptr, const char **text_ptr)
{
	const char *key;
	dfilter_macro_t *m;

	if (!g_hash_table_iter_next(&iter->iter, (gpointer *)&key, (gpointer *)&m))
		return false;
	if (name_ptr)
		*name_ptr = key;
	if (text_ptr)
		*text_ptr = m->text;
	return true;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
