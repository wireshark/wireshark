/* dfilter-macro.c
 *
 * $Id: dfilter_macro_expand.l 18197 2006-05-21 05:12:17Z sahlberg $
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

dfilter_macro_t* macros = NULL;

void dfilter_macro_foreach(dfilter_macro_cb_t cb, void* data) {
	dfilter_macro_t* c;

	for (c = macros; c; c = c->next) {
		cb(c,data);
	}
	return;
}

static void macro_fprint(dfilter_macro_t* m, void* ud) {
	FILE* f = ud;
	
	fprintf(f,"%s\t%s\n",m->name,m->text);
}

void dfilter_macro_save(const gchar* filename, gchar** error) {
	FILE* f = fopen(filename,"w");
	
	if (!f) {
		*error = ep_strdup_printf("Could not open file: '%s', error: %s\n", filename, strerror(errno) );
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

	printf("\n->%s\t%s\t%d\n\t'%s'\n",
		   m->name, m->text, m->argc, *(part++));
	
	while (*part) {
		printf("\t$%d '%s'\n",*args_pos,*part);
		
		args_pos++;
		part++;
	}
}
#endif

void dfilter_macro_dump(void) {
#ifdef DUMP_MACROS
	dfilter_macro_foreach(macro_dump, NULL);
#endif
}

gchar* dfilter_macro_resolve(gchar* name, gchar** args, gchar** error) {
	GString* text;
	int argc = 0;
	dfilter_macro_t* m;
	int* arg_pos_p;
	gchar** parts;
	gchar* ret;
		
	for (m = macros; m; m = m->next) {
		if ( g_str_equal(m->name,name) ) break;
	}

	if (!m) {
		*error = ep_strdup_printf("macro '%s' does not exist", name);
		return NULL;
	}

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
	
	while (*parts) {
		g_string_sprintfa(text,"%s%s",
						  args[*(arg_pos_p++)],
						  *(parts++));
	}
	
	ret = ep_strdup(text->str);

	g_string_free(text,TRUE);
		
	return ret;
}

void dfilter_macro_add(const gchar* name, const gchar* text, gchar** error) {
	dfilter_macro_t* m;
	GPtrArray* parts;
	GArray* args_pos;
	const gchar* r;
	gchar* w;
	gchar* part;
	int argc = 0;

	*error = NULL;
	
	for (m = macros; m; m = m->next) {
		if ( g_str_equal(m->name,name) ) {
			*error = ep_strdup_printf("macro '%s' exists already", name);
			return;
		}
	}
	
	m = g_malloc(sizeof(dfilter_macro_t));
	m->name = g_strdup(name);
	m->text = g_strdup(text);
	
	parts = g_ptr_array_new();
	args_pos = g_array_new(FALSE,FALSE,sizeof(int));

	m->priv = part =  w = g_strdup(text);
	r = text;
	g_ptr_array_add(parts,part);
	
	do {
		
		switch (*r) { 
			default:
				*(w++) = *(r++);
				break;
			case '\0':
				*(w++) = *(r++);
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
						arg_pos *= 10;
						arg_pos += c - '0';
					} else {
						break;
					}
				} while(1);
				
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
				
	} while(1);

done:
	g_ptr_array_add(parts,NULL);
	m->parts = (gchar**)parts->pdata;
	
	m->args_pos = (int*)args_pos->data;

	g_ptr_array_free(parts,FALSE);
	g_array_free(args_pos,FALSE);
	
	m->argc = argc;
	m->next = macros;
	macros = m;
	
	return;
}

void dfilter_macro_remove(const gchar* name, gchar** error) {
	dfilter_macro_t* m;
	dfilter_macro_t* p = NULL;
	
	for (m = macros; m; m = m->next) {
		if ( g_str_equal(m->name,name) ) {
			p = m;
			break;
		}
	}
	
	if (!m) {
		*error = ep_strdup_printf("macro '%s' does not exist", name);
		return;
	}
	
	if (p) {
		p->next = m->next;
	} else {
		macros = m->next;
	}
	
	g_free(m->name);
	g_free(m->text);
	g_free(m->priv);
	g_free(m->parts);
	g_free(m->args_pos);
	g_free(m);
}



gchar* dfilter_macro_apply(const gchar* text, guint depth, gchar** error) {
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
	
#define FREE_ALL() do { \
	FGS(name); \
	FGS(arg); \
	if (args) { \
		while(args->len) { void* p = g_ptr_array_remove_index_fast(args,0); if (p) g_free(p); } \
		g_ptr_array_free(args,TRUE); \
		args = NULL; } } while(0)
		
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
					if ( isalnum(c) || c == '_' ) {
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
				gchar* resolved = dfilter_macro_apply(out->str, depth++, error);
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

