/* dfilter-macro.c
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>

#include "dfilter-int.h"
#include "dfilter.h"
#include "dfilter-macro.h"
#include <epan/emem.h>
#include <epan/uat-int.h>
#include <epan/report_err.h>
#include <epan/proto.h>
#include <wsutil/file_util.h>

typedef struct {
	const char* name;
	gboolean usable;
	char* repr;
} fvt_cache_entry_t;

static uat_t* dfilter_macro_uat = NULL;
static dfilter_macro_t* macros = NULL;
static guint num_macros;
static GHashTable* fvt_cache = NULL;

/* #define DUMP_DFILTER_MACRO */
#ifdef DUMP_DFILTER_MACRO
void dump_dfilter_macro_t(const dfilter_macro_t *m, const char *function, const char *file, int line);
#define DUMP_MACRO(m) dump_dfilter_macro_t(m, __func__, __FILE__, __LINE__)
#else
#define DUMP_MACRO(m)
#endif

static gboolean free_value(gpointer k _U_, gpointer v, gpointer u _U_) {
	fvt_cache_entry_t* e = v;
	g_free(e->repr);
	g_free(e);
	return TRUE;
}

static gboolean fvt_cache_cb(proto_node * node, gpointer data _U_) {
	field_info* finfo = PNODE_FINFO(node);
	fvt_cache_entry_t* e;

	if (!finfo) return FALSE;

	if ((e = g_hash_table_lookup(fvt_cache,finfo->hfinfo->abbrev))) {
		e->usable = FALSE;
	} else if (finfo->value.ftype->val_to_string_repr) {
		switch (finfo->hfinfo->type) {
			case FT_NONE:
			case FT_PROTOCOL:
				return FALSE;
			default:
				break;
		}
		e = g_malloc(sizeof(fvt_cache_entry_t));
		e->name = finfo->hfinfo->abbrev,
		e->repr = fvalue_to_string_repr(&(finfo->value), FTREPR_DFILTER, NULL);
		e->usable = TRUE;
		g_hash_table_insert(fvt_cache,(void*)finfo->hfinfo->abbrev,e);
	}
	return FALSE;
}

void dfilter_macro_build_ftv_cache(void* tree_root) {
	g_hash_table_foreach_remove(fvt_cache,free_value,NULL);
	proto_tree_traverse_post_order(tree_root, fvt_cache_cb, NULL);
}

void dfilter_macro_foreach(dfilter_macro_cb_t cb, void* data) {
	guint i;

	for (i = 0; i < num_macros; i++) {
		cb(&(macros[i]),data);
	}
	return;
}

static void macro_fprint(dfilter_macro_t* m, void* ud) {
	FILE* f = ud;

	fprintf(f,"%s\t%s\n",m->name,m->text);
}

void dfilter_macro_save(const gchar* filename, gchar** error) {
	FILE* f = ws_fopen(filename,"w");

	if (!f) {
		*error = ep_strdup_printf("Could not open file: '%s', error: %s\n", filename, g_strerror(errno) );
		return;
	}

	dfilter_macro_foreach(macro_fprint, f);

	fclose(f);

	return;
}

#ifdef DUMP_MACROS
static void macro_dump(dfilter_macro_t* m _U_, void* ud _U_) {
	gchar** part = m->parts;
	int* args_pos = m->args_pos;

	printf("\n->%s\t%s\t%d [%d]\n\t'%s'\n",
		   m->name, m->text, m->argc, m->usable, *(part++));

	while (*part) {
		printf("\t$%d '%s'\n",*args_pos,*part);

		args_pos++;
		part++;
	}
}
#else
#define macro_dump(a,b)
#endif

void dfilter_macro_dump(void) {
#ifdef DUMP_MACROS
	dfilter_macro_foreach(macro_dump, NULL);
#endif
}

static gchar* dfilter_macro_resolve(gchar* name, gchar** args, const gchar** error) {
	GString* text;
	int argc = 0;
	dfilter_macro_t* m = NULL;
	fvt_cache_entry_t* e;
	int* arg_pos_p;
	gchar** parts;
	gchar* ret;
	guint i;

	for (i = 0; i < num_macros; i++) {
		dfilter_macro_t* c = &(macros[i]);
		if ( c->usable && g_str_equal(c->name,name) ) {
			m = c;
			break;
		}
	}

	if (!m) {
		if (fvt_cache &&
		    (e = g_hash_table_lookup(fvt_cache,name)) != NULL) {
			if(e->usable) {
				return e->repr;
			} else {
				*error = ep_strdup_printf("macro '%s' is unusable", name);
				return NULL;
			}
		} else {
			*error = ep_strdup_printf("macro '%s' does not exist", name);
			return NULL;
		}
	}

	DUMP_MACRO(m);

	if (args) {
		while(args[argc]) argc++;
	}

	if (argc != m->argc) {
		*error = ep_strdup_printf("wrong number of arguments for macro '%s', expecting %d instead of %d",
								  name, m->argc, argc);
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

	ret = ep_strdup(text->str);

	g_string_free(text,TRUE);

	return ret;
}


static gchar* dfilter_macro_apply_recurse(const gchar* text, guint depth, const gchar** error) {
	enum { OUTSIDE, STARTING, NAME, ARGS } state = OUTSIDE;
	GString* out;
	GString* name = NULL;
	GString* arg = NULL;
	GPtrArray* args = NULL;
	gchar c;
	const gchar* r = text;
	gboolean changed = FALSE;

	if ( depth > 31) {
		*error = "too much nesting in macros";
		return NULL;
	}

#define FGS(n) if (n) g_string_free(n,TRUE); n = NULL

#define FREE_ALL() \
	do { \
		FGS(name); \
		FGS(arg); \
		if (args) { \
			while(args->len) { void* p = g_ptr_array_remove_index_fast(args,0); if (p) g_free(p); } \
			g_ptr_array_free(args,TRUE); \
			args = NULL; \
		} \
	} while(0)

	*error = NULL;
	out = g_string_sized_new(64);

	while(1) {
		c = *r++;

		switch(state) {
			case OUTSIDE: {
				switch(c) {
					case '\0': {
						goto finish;
					} case '$': {
						state = STARTING;
						break;
					} default: {
						g_string_append_c(out,c);
						break;
					}
				}
				break;
			} case STARTING: {
				switch (c) {
					case '{': {
						args = g_ptr_array_new();
						arg = g_string_sized_new(32);
						name = g_string_sized_new(32);

						state = NAME;

						break;
					} case '\0': {
						g_string_append_c(out,'$');

						goto finish;
					} default: {
						g_string_append_c(out,'$');
						g_string_append_c(out,c);

						state = OUTSIDE;

						break;
					}
				}
				break;
			} case NAME: {
				if ( isalnum((int)c) || c == '_' || c == '-' || c == '.' ) {
					g_string_append_c(name,c);
				} else if ( c == ':') {
					state = ARGS;
				} else if ( c == '}') {
					gchar* resolved;

					g_ptr_array_add(args,NULL);

					resolved = dfilter_macro_resolve(name->str, (gchar**)args->pdata, error);
					if (*error) goto on_error;

					changed = TRUE;

					g_string_append(out,resolved);

					FREE_ALL();

					state = OUTSIDE;
				} else if ( c == '\0') {
					*error = "end of filter in the middle of a macro expression";
					goto on_error;
				} else {
					*error = "invalid char in macro name";
					goto on_error;
				}
				break;
			} case ARGS: {
				switch(c) {
					case '\0': {
						*error = "end of filter in the middle of a macro expression";
						goto on_error;
					} case ';': {
						g_ptr_array_add(args,arg->str);
						g_string_free(arg,FALSE);

						arg = g_string_sized_new(32);
						break;
					} case '\\': {
						c = *r++;
						if (c) {
							g_string_append_c(arg,c);
							break;
						} else {
							*error = "end of filter in the middle of a macro expression";
							goto on_error;
						}
					} default: {
						g_string_append_c(arg,c);
						break;
					} case '}': {
						gchar* resolved;
						g_ptr_array_add(args,arg->str);
						g_ptr_array_add(args,NULL);

						g_string_free(arg,FALSE);
						arg = NULL;

						resolved = dfilter_macro_resolve(name->str, (gchar**)args->pdata, error);
						if (*error) goto on_error;

						changed = TRUE;

						g_string_append(out,resolved);

						FREE_ALL();

						state = OUTSIDE;
						break;
					}
				}
				break;
			}
		}
	}

finish:
	{
		FREE_ALL();

		if (changed) {
			gchar* resolved = dfilter_macro_apply_recurse(out->str, depth + 1, error);
			g_string_free(out,TRUE);
			return (*error) ? NULL : resolved;
		} else {
			gchar* out_str = ep_strdup(out->str);
			g_string_free(out,TRUE);
			return out_str;
		}
	}
on_error:
	{
		FREE_ALL();
		if (! *error) *error = "unknown error in macro expression";
		g_string_free(out,TRUE);
		return NULL;
	}
}

gchar* dfilter_macro_apply(const gchar* text, const gchar** error) {
	return dfilter_macro_apply_recurse(text, 0, error);
}

static void macro_update(void* mp, const gchar** error) {
	dfilter_macro_t* m = mp;
	GPtrArray* parts;
	GArray* args_pos;
	const gchar* r;
	gchar* w;
	gchar* part;
	int argc = 0;
	guint i;

	DUMP_MACRO(m);

	*error = NULL;

	for (i = 0; i < num_macros; i++) {
		if (m == &(macros[i])) continue;

		if ( g_str_equal(m->name,macros[i].name) ) {
			*error = ep_strdup_printf("macro '%s' exists already", m->name);
			m->usable = FALSE;
			return;
		}
	}

	/* Invalidate the display filter in case it's in use */
	if (dfilter_macro_uat && dfilter_macro_uat->post_update_cb)
	  dfilter_macro_uat->post_update_cb();

	parts = g_ptr_array_new();
	args_pos = g_array_new(FALSE,FALSE,sizeof(int));

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
				*(w++) = *(++r);
				r++;
				break;
			case '$': {
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
	m->parts = (gchar**)parts->pdata;

	g_free(m->args_pos);
	m->args_pos = (int*)(void *)args_pos->data;

	g_ptr_array_free(parts,FALSE);
	g_array_free(args_pos,FALSE);

	m->argc = argc;

	m->usable = TRUE;

	macro_dump(m,NULL);

	DUMP_MACRO(m);

	return;
}

static void macro_free(void* r) {
	dfilter_macro_t* m = r;

	DUMP_MACRO(r);

	g_free(m->name);
	g_free(m->text);
	g_free(m->priv);
	g_free(m->parts);
	g_free(m->args_pos);
}

static void* macro_copy(void* dest, const void* orig, size_t len _U_) {
	dfilter_macro_t* d = dest;
	const dfilter_macro_t* m = orig;

	DUMP_MACRO(m);

	d->name = g_strdup(m->name);
	d->text = g_strdup(m->text);
	d->usable = m->usable;

	if (m->parts) {
		guint nparts = 0;

		/*
		 * Copy the contents of m->priv (a "cooked" version
		 * of m->text) into d->priv.
		 *
		 * First we clone m->text into d->priv, this gets
		 * us a NUL terminated string of the proper length.
		 *
		 * Then we loop copying bytes from m->priv into
		 * d-priv.  Since m->priv contains internal ACSII NULs
		 * we use the length of m->text to stop the copy.
                 */

		d->priv = g_strdup(m->text);
		{
			const gchar* oldText = m->text;
			const gchar* oldPriv = m->priv;
			gchar* newPriv = d->priv;
			while(oldText && *oldText) {
				*(newPriv++) = *(oldPriv++);
				oldText++;
			}
		}

		/*
		 * The contents of the m->parts array contains pointers
		 * into various sections of m->priv.  Since it's
		 * an argv style array of ponters, this array is
		 * actually one larger than the number of parts
		 * to hold the final NULL terminator.
		 *
		 * The following copy clones the original m->parts
		 * array into d->parts but then fixes-up the pointers
		 * so that they point into the appropriate sections
		 * of the d->priv.
                 */

		do nparts++; while (m->parts[nparts]);
		d->parts = g_memdup(m->parts,(nparts+1)*(guint)sizeof(void*));
		nparts = 0;
		while(m->parts[nparts]) {
			if(nparts) {
				d->parts[nparts] = d->parts[nparts - 1] + (m->parts[nparts] - m->parts[nparts - 1]);
			} else {
				d->parts[nparts] = d->priv;
			}
			nparts++;
		}

		/*
		 * Clone the contents of m->args_pos into d->args_pos.
		 */

		d->args_pos = g_memdup(m->args_pos,(--nparts)*(guint)sizeof(int));
	}

	DUMP_MACRO(d);

	return d;
}

static gboolean macro_name_chk(void* r _U_, const char* in_name, unsigned name_len, const void* u1 _U_, const void* u2 _U_, const char** error) {
	guint i;

	if (name_len == 0) {
		*error = "invalid name";
		return FALSE;
	}

	for (i=0; i < name_len; i++) {
		if (!(in_name[i] == '_' || isalnum((guchar)in_name[i]) ) ) {
			*error = "invalid char in name";
			return FALSE;
		}
	}

	return TRUE;
}

UAT_CSTRING_CB_DEF(macro,name,dfilter_macro_t)
UAT_CSTRING_CB_DEF(macro,text,dfilter_macro_t)

void dfilter_macro_init(void) {
	static uat_field_t uat_fields[] =  {
		UAT_FLD_CSTRING_OTHER(macro,name,"Name",macro_name_chk,"The name of the macro."),
		UAT_FLD_CSTRING_ISPRINT(macro,text,"Text","The text this macro resolves to."),
		UAT_END_FIELDS
	};

	dfilter_macro_uat = uat_new("Display Filter Macros",
				    sizeof(dfilter_macro_t),
				    DFILTER_MACRO_FILENAME,
				    TRUE,
				    (void*) &macros,
				    &num_macros,
				    NULL,
				    "ChDisplayFilterMacrosSection",
				    macro_copy,
				    macro_update,
				    macro_free,
				    NULL, /* Note: This is set in macros_init () */
				    uat_fields);

	fvt_cache = g_hash_table_new(g_str_hash,g_str_equal);
}

void dfilter_macro_get_uat(void** p) {
	*p = dfilter_macro_uat;
}

#ifdef DUMP_DFILTER_MACRO
/*
 * The dfilter_macro_t has several characteristics that are
 * not immediattly obvious. The dump_dfilter_filter_macro_t()
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

