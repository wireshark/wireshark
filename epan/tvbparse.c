/* tvbparse.c
*
* Copyright 2005, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
*
* $Id$
*
* Ethereal - Network traffic analyzer
* By Gerald Combs <gerald@ethereal.com>
* Copyright 1998 Gerald Combs
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
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <epan/emem.h>
#include <epan/proto.h>
#include <epan/tvbparse.h>

typedef enum _tvbparse_wanted_type_t {
	TVBPARSE_WANTED_NONE, /* currently unused */
	
	/* simple tokens */
	TVBPARSE_WANTED_SIMPLE_CHAR, /* just one matching char */
	TVBPARSE_WANTED_SIMPLE_CHARS, /* a sequence of matching chars */
	TVBPARSE_WANTED_SIMPLE_NOT_CHAR, /* one non matching char */ 
	TVBPARSE_WANTED_SIMPLE_NOT_CHARS, /* a sequence of non matching chars */
	TVBPARSE_WANTED_SIMPLE_STRING, /* a string */
	TVBPARSE_WANTED_SIMPLE_CASESTRING, /* a caseless string */
	TVBPARSE_WANTED_UNTIL, /* all the characters until the first matching token */
	
	/* composed tokens */
	TVBPARSE_WANTED_SET_ONEOF, /* one of the given types */
	TVBPARSE_WANTED_SET_SEQ, /* an exact sequence of tokens of the given types */
	TVBPARSE_WANTED_CARDINALITY, /* one or more tokens of the given type */ 
    TVBPARSE_WANTED_HANDLE,  /* a handle to another one */
    
} tvbparse_type_t;

struct _tvbparse_t {
	tvbuff_t* tvb;
	int offset;
	int max_len;
	void* data;
	const tvbparse_wanted_t* ignore;
	guint depth;
};

struct _tvbparse_wanted_t {
	int id;
	tvbparse_type_t type;
	
	union {
        const gchar* str;
        guint val;
        struct _tvbparse_wanted_t** handle;
    } control;
    
	int len;
	
	guint min;
	guint max;
	
	const void* data;
	tvbparse_action_t before;
	tvbparse_action_t after;
	
	GPtrArray* elems;
};


tvbparse_wanted_t* tvbparse_char(int id,
						  const gchar* chr,
						  const void* data,
						  tvbparse_action_t before_cb,
						  tvbparse_action_t after_cb) {
	tvbparse_wanted_t* w = g_malloc(sizeof(tvbparse_wanted_t));
	
	w->id = id;
	w->type = TVBPARSE_WANTED_SIMPLE_CHAR;
	w->control.str = chr;
	w->len = 1;
	w->min = 0;
	w->max = 0;
	w->data = data;
	w->before = before_cb;
	w->after = after_cb;
	w->elems = g_ptr_array_new();
	
	return w;
}

tvbparse_wanted_t* tvbparse_chars(int id,
								  guint min_len,
								  guint max_len,
								  const gchar* chr,
								  const void* data,
								  tvbparse_action_t before_cb,
								  tvbparse_action_t after_cb) {
	tvbparse_wanted_t* w = g_malloc(sizeof(tvbparse_wanted_t));
	
	w->id = id;
	w->type = TVBPARSE_WANTED_SIMPLE_CHARS;
	w->control.str = chr;
	w->len = 0;
	w->min = min_len ? min_len : 1;
	w->max = max_len ? max_len : G_MAXINT;
	w->data = data;
	w->before = before_cb;
	w->after = after_cb;
	w->elems = g_ptr_array_new();
	
	return w;
}

tvbparse_wanted_t* tvbparse_not_char(int id,
							  const gchar* chr,
							  const void* data,
							  tvbparse_action_t before_cb,
							  tvbparse_action_t after_cb) {
	tvbparse_wanted_t* w = g_malloc(sizeof(tvbparse_wanted_t));
	
	w->id = id;
	w->type = TVBPARSE_WANTED_SIMPLE_NOT_CHAR;
	w->control.str = chr;
	w->len = 0;
	w->min = 0;
	w->max = 0;
	w->data = data;
	w->before = before_cb;
	w->after = after_cb;
	w->elems = g_ptr_array_new();
	
	return w;
}

tvbparse_wanted_t* tvbparse_not_chars(int id,
									  guint min_len,
									  guint max_len,
									  const gchar* chr,
									  const void* data,
									  tvbparse_action_t before_cb,
									  tvbparse_action_t after_cb){
	tvbparse_wanted_t* w = g_malloc(sizeof(tvbparse_wanted_t));
	
	w->id = id;
	w->type = TVBPARSE_WANTED_SIMPLE_NOT_CHARS;
	w->control.str = chr;
	w->len = 0;
	w->min = min_len ? min_len : 1;
	w->max = max_len ? max_len : G_MAXINT;
	w->data = data;
	w->before = before_cb;
	w->after = after_cb;
	w->elems = g_ptr_array_new();
	
	return w;
}


tvbparse_wanted_t* tvbparse_string(int id,
								   const gchar* str,
								   const void* data,
								   tvbparse_action_t before_cb,
								   tvbparse_action_t after_cb) {
	tvbparse_wanted_t* w = g_malloc(sizeof(tvbparse_wanted_t));
	
	w->id = id;
	w->type = TVBPARSE_WANTED_SIMPLE_STRING;
	w->control.str = str;
	w->len = strlen(str);
	w->min = 0;
	w->max = 0;
	w->data = data;
	w->before = before_cb;
	w->after = after_cb;
	w->elems = g_ptr_array_new();
	
	return w;
}

tvbparse_wanted_t* tvbparse_casestring(int id,
								   const gchar* str,
								   const void* data,
								   tvbparse_action_t before_cb,
								   tvbparse_action_t after_cb) {
	tvbparse_wanted_t* w = g_malloc(sizeof(tvbparse_wanted_t));
	
	w->id = id;
	w->type = TVBPARSE_WANTED_SIMPLE_CASESTRING;
	w->control.str = str;
	w->len = strlen(str);
	w->min = 0;
	w->max = 0;
	w->data = data;
	w->before = before_cb;
	w->after = after_cb;
	w->elems = g_ptr_array_new();
	
	return w;
}


tvbparse_wanted_t* tvbparse_set_oneof(int id,
							   const void* data, 
							   tvbparse_action_t before_cb,
							   tvbparse_action_t after_cb,
							   ...) {
	tvbparse_wanted_t* w = g_malloc(sizeof(tvbparse_wanted_t));
	tvbparse_t* el;
	va_list ap;
	
	w->id = id;
	w->type = TVBPARSE_WANTED_SET_ONEOF;
	w->control.val = 0;
	w->len = 0;
	w->min = 0;
	w->max = 0;
	w->data = data;
	w->before = before_cb;
	w->after = after_cb;
	w->elems = g_ptr_array_new();
	
	va_start(ap,after_cb);
	
	while(( el = va_arg(ap,tvbparse_t*) )) {
		g_ptr_array_add(w->elems,el);
	};
	
	va_end(ap);
	
	return w;
}

tvbparse_wanted_t* tvbparse_set_seq(int id,
							 const void* data,
							 tvbparse_action_t before_cb,
							 tvbparse_action_t after_cb,
							 ...) {
	tvbparse_wanted_t* w = g_malloc(sizeof(tvbparse_wanted_t));
	tvbparse_wanted_t*  el = NULL;
	va_list ap;
	
	w->id = id;
	w->type = TVBPARSE_WANTED_SET_SEQ;
	w->control.val = 0;
	w->len = 0;
	w->min = 0;
	w->max = 0;
	w->data = data;
	w->before = before_cb;
	w->after = after_cb;
	w->elems = g_ptr_array_new();
	
	va_start(ap,after_cb);
	
	while(( el = va_arg(ap,tvbparse_wanted_t*) )) {
		g_ptr_array_add(w->elems,el);
	};
	
	va_end(ap);
	return w;
}


tvbparse_wanted_t* tvbparse_some(int id,
								 guint from,
								 guint to,
								 const void* data,
								 tvbparse_action_t before_cb,
								 tvbparse_action_t after_cb,
								 const tvbparse_wanted_t* el) {
	
	tvbparse_wanted_t* w = g_malloc(sizeof(tvbparse_wanted_t));
	
	g_assert(from <= to);
	
	w->id = id;
	w->type = TVBPARSE_WANTED_CARDINALITY;
	w->control.val = 0;
	w->len = 0;
	w->min = from;
	w->max = to;
	w->data = data;
	w->before = before_cb;
	w->after = after_cb;
	w->elems = g_ptr_array_new();
	
	g_ptr_array_add(w->elems,(gpointer)el);
	
	return w;
}

tvbparse_wanted_t* tvbparse_until(int id,
						   const void* data,
						   tvbparse_action_t before_cb,
						   tvbparse_action_t after_cb,
						   const tvbparse_wanted_t* el,
						   int op_mode) {
	tvbparse_wanted_t* w = g_malloc(sizeof(tvbparse_wanted_t));
	
	w->id = id;
	w->type = TVBPARSE_WANTED_UNTIL;
	
	w->control.val = op_mode;
	
	w->len = 0;
	w->min = 0;
	w->max = 0;
	w->data = data;
	w->before = before_cb;
	w->after = after_cb;
	w->elems = g_ptr_array_new();
	
	g_ptr_array_add(w->elems,(gpointer)el);
	
	return w;
}

tvbparse_wanted_t* tvbparse_handle(tvbparse_wanted_t** handle) {
	tvbparse_wanted_t* w = g_malloc(sizeof(tvbparse_wanted_t));
	
	w->id = 0;
	w->type = TVBPARSE_WANTED_HANDLE;
	
	w->control.handle = handle;
	
	w->len = 0;
	w->min = 0;
	w->max = 0;
	w->data = NULL;
	w->before = NULL;
	w->after = NULL;
	w->elems = NULL;
	
	return w;
}


tvbparse_wanted_t* tvbparse_quoted(int id,
								   const void* data,
								   tvbparse_action_t before_cb,
								   tvbparse_action_t after_cb,
								   char quote,
								   char esc) {
	
	gchar* esc_quot = g_strdup_printf("%c%c",esc,quote);
	gchar* quot = g_strdup_printf("%c",quote);
	tvbparse_wanted_t* want_quot = tvbparse_char(-1,quot,NULL,NULL,NULL);
	
	return tvbparse_set_oneof(id, data, before_cb, after_cb,
							  tvbparse_set_seq(-1, NULL, NULL, NULL,
											   want_quot,
											   tvbparse_set_seq(-1,NULL,NULL,NULL,
																tvbparse_set_oneof(-1, NULL, NULL, NULL,
																				   tvbparse_string(-1,esc_quot,NULL,NULL,NULL),
																				   tvbparse_not_chars(-1,0,0,quot,NULL,NULL,NULL),
																				   NULL),
																NULL),
											   want_quot,
											   NULL),
							  tvbparse_set_seq(-1, NULL, NULL, NULL,
											   want_quot,
											   want_quot,
											   NULL),														
							  NULL);
	
}

void tvbparse_shrink_token_cb(void* tvbparse_data _U_,
							  const void* wanted_data _U_,
							  tvbparse_elem_t* tok) {
	tok->offset += 1;
	tok->len -= 2;
}

tvbparse_t* tvbparse_init(tvbuff_t* tvb,
						  int offset,
						  int len,
						  void* data,
						  const tvbparse_wanted_t* ignore) {
	tvbparse_t* tt = ep_alloc(sizeof(tvbparse_t));
	
	tt->tvb = tvb;
	tt->offset = offset;
	tt->max_len = (len == -1) ? (int) tvb_length(tvb) : len;
	tt->data = data;
	tt->ignore = ignore;
	tt->depth = 0;
	return tt;
}

gboolean tvbparse_reset(tvbparse_t* tt,
						int offset,
						int len) {
	
	len = (len == -1) ? (int) tvb_length(tt->tvb) : len;
	
	if( tvb_length_remaining(tt->tvb, offset) >= len) {
		tt->offset = offset;
		tt->max_len = len;
		tt->depth = 0;
		return TRUE;
	} else {
		tt->depth = 0;
		return FALSE;
	}
}

static tvbparse_elem_t* new_tok(tvbparse_t* tt,
							   int id,
							   int offset,
							   int len,
							   const tvbparse_wanted_t* wanted) {
	tvbparse_elem_t* tok = ep_alloc(sizeof(tvbparse_elem_t));
	
	tok->tvb = tt->tvb;
	tok->id = id;
	tok->offset = offset;
	tok->len = len;
	tok->data = NULL;
	tok->sub = NULL;
	tok->next = NULL;
	tok->wanted = wanted;
	tok->last = tok;
	
	return tok;
}

guint tvbparse_curr_offset(tvbparse_t* tt) {
    return tt->offset;
}
guint tvbparse_len_left(tvbparse_t* tt) {
    return tt->max_len;
}

tvbparse_elem_t* tvbparse_get(tvbparse_t* tt,
								  const tvbparse_wanted_t* wanted) {
	tvbparse_elem_t* tok = NULL;
	int save_offset = tt->offset;
	int save_len = tt->max_len;
	
	tt->depth++;
	
	if (tt->ignore && tt->ignore != wanted) {
		tvbparse_wanted_t* save = (void*)tt->ignore;
		tt->ignore = NULL;
		while ( tvbparse_get(tt,save) )  {
			;
		}
		tt->ignore = save;
	}
	
	switch(wanted->type) {
		case TVBPARSE_WANTED_NONE:
			goto reject;
		case TVBPARSE_WANTED_SIMPLE_NOT_CHAR:
		{
			gchar c, t;
			guint i;
			gboolean not_matched = FALSE;
			
			if (! tt->max_len )
				goto reject;
			
			t = (gchar) tvb_get_guint8(tt->tvb,tt->offset);
			
			for(i = 0; (c = wanted->control.str[i]) && tt->max_len; i++) {
				if ( c == t ) {
					not_matched = TRUE;
				}
			}
			
			if (not_matched) {
				goto reject;
			} else {
				tt->offset++;
				tt->max_len--;
				tok =  new_tok(tt,wanted->id,tt->offset-1,1,wanted);
				goto accept;
			}
		}
		case TVBPARSE_WANTED_SIMPLE_CHAR:
		{
			gchar c,t;
			guint i;
			
			if (! tt->max_len )
				goto reject;
			
			t = (gchar) tvb_get_guint8(tt->tvb,tt->offset);
			
			for(i = 0; (c = wanted->control.str[i]) && tt->max_len; i++) {
				if ( c == t ) {
					tt->offset++;
					tt->max_len--;
					tok =  new_tok(tt,wanted->id,tt->offset-1,1,wanted);
					goto accept;
				}
			}
			goto reject;
		}
		case TVBPARSE_WANTED_SIMPLE_NOT_CHARS:
		{
			gchar c, t;
			guint i;
			guint offset = tt->offset;
			guint length = 0;
			
			while( tt->max_len && length < wanted->max) {
				gboolean not_matched = FALSE;
				t = (gchar) tvb_get_guint8(tt->tvb,tt->offset);
				i = 0;
				
				while ( (c = wanted->control.str[i]) && tt->max_len ) {
					
					if (c == t) {
						not_matched = TRUE;
					}
					
					i++;
				}
				
				if ( not_matched )
					break;

				length++;
				tt->offset++;
				tt->max_len--;
			};
			
			if ( length < wanted->min ) {
				goto reject;
			} else {
				tok = new_tok(tt,wanted->id,offset,length,wanted);
				goto accept;			
			}
		}
		case TVBPARSE_WANTED_SIMPLE_CHARS:
		{
			gchar c, t;
			guint i;
			guint offset = tt->offset;
			guint length = 0;
			
			while( tt->max_len && length < wanted->max) {
				gboolean matched = FALSE;
				t = (gchar) tvb_get_guint8(tt->tvb,tt->offset);
				i = 0;
				
				while ( (c = wanted->control.str[i]) && tt->max_len ) {
					
					if (c == t) {
						matched = TRUE;
						break;
					}
					
					i++;
				}
				
				if (! matched )
					break;
				
				length++;
				tt->offset++;
				tt->max_len--;
			};
			
			if (length < wanted->min) {
				goto reject;
			} else {
				tok = new_tok(tt,wanted->id,offset,length,wanted);
				goto accept;			
			}
		}
		case TVBPARSE_WANTED_SIMPLE_STRING:
		{
			if ( tvb_strneql(tt->tvb, tt->offset, wanted->control.str, wanted->len) == 0 ) {
				int offset = tt->offset;
				tt->offset += wanted->len;
				tt->max_len -= wanted->len;
				tok = new_tok(tt,wanted->id,offset,wanted->len,wanted);
				goto accept;
			} else {
				goto reject;
			}
		}
		case TVBPARSE_WANTED_SIMPLE_CASESTRING:
		{
			if ( tvb_strncaseeql(tt->tvb, tt->offset, wanted->control.str, wanted->len) == 0 ) {
				int offset = tt->offset;
				tt->offset += wanted->len;
				tt->max_len -= wanted->len;
				tok = new_tok(tt,wanted->id,offset,wanted->len,wanted);
				goto accept;
			} else {
				goto reject;
			}
		}
		case TVBPARSE_WANTED_SET_ONEOF:
		{
			guint i;
			
			for(i=0; i < wanted->elems->len; i++) {
				tvbparse_wanted_t* w = g_ptr_array_index(wanted->elems,i);
				tvbparse_elem_t* new = tvbparse_get(tt, w);
				
				if (new) {
					tok = new_tok(tt, wanted->id, new->offset, new->len, wanted);
					tok->sub = new;
					goto accept;			
				}
			}
			goto reject;
		}
		case TVBPARSE_WANTED_SET_SEQ:
		{
			guint i;
			
			for(i=0; i < wanted->elems->len; i++) {
				tvbparse_wanted_t* w = g_ptr_array_index(wanted->elems,i);
				tvbparse_elem_t* new = tvbparse_get(tt, w);
				
				if (new) {
					if (tok) {
						tok->len = (new->offset - tok->offset) + new->len;
						tok->sub->last->next = new;
						tok->sub->last = new;
					} else {
						tok = new_tok(tt, wanted->id, new->offset, new->len, wanted);
						tok->sub = new;
					}
				} else {
					goto reject;
				}
				
			}
			
			goto accept;			
		}
		case TVBPARSE_WANTED_CARDINALITY:
		{
			guint got_so_far = 0;
			tvbparse_wanted_t* w = g_ptr_array_index(wanted->elems,0);
			
            if ( wanted->min == 0 ) {
                new_tok(tt,wanted->id,tt->offset,0,wanted);
            }
            
			while (got_so_far < wanted->max) {
				tvbparse_elem_t* new = tvbparse_get(tt, w);
				
				if(new) {
					if (tok) {
						tok->len = (new->offset - tok->offset) + new->len;
						tok->sub->last->next = new;
						tok->sub->last = new;
					} else {
						tok = new_tok(tt, wanted->id, new->offset, new->len, wanted);
						tok->sub = new;
					}
				} else {
					break;
				}
				
				got_so_far++;
			}
			
			if(got_so_far < wanted->min) {
				goto reject;
			}
			
			goto accept;			
		}
		case TVBPARSE_WANTED_UNTIL:
		{
			int offset = tt->offset;
			tvbparse_wanted_t* w = g_ptr_array_index(wanted->elems,0);
			tvbparse_elem_t* new = tvbparse_find(tt, w);
			
			if (new) {
				tok = new;
				
				switch (wanted->control.val) {
                    case TP_UNTIL_INCLUDE:
                        tok->len = (tok->offset - offset) + tok->len;
                        break;
                    case TP_UNTIL_LEAVE:
                        tt->offset -= tok->len;
                        tt->max_len += tok->len;
                        /* fall through */
                    case TP_UNTIL_SPEND:
                        tok->len = (tok->offset - offset);
                        break;
                    default:
                        DISSECTOR_ASSERT_NOT_REACHED();
				}
				
				tok->offset = offset;
				tok->id = wanted->id;
				tok->next = NULL;
				tok->last = tok;
				tok->wanted = wanted;
				
				goto accept;
			} else {
				goto reject;
			}
		}
        case TVBPARSE_WANTED_HANDLE:
        {
            tok = tvbparse_get(tt, *(wanted->control.handle));
            if (tok) {
                goto accept;
            } else {
                goto reject;
            }
        }
	}
	
	DISSECTOR_ASSERT_NOT_REACHED();
	return NULL;
	
accept:
		if (tok) {
			if( tt->depth == 1 ) {
				GPtrArray* stack = g_ptr_array_new();
				tvbparse_elem_t* curr = tok;
				
				while (curr) {
					
					if(curr->wanted->before) {
						curr->wanted->before(tt->data, curr->wanted->data, curr);
					}
					
					if(curr->sub) {
						g_ptr_array_add(stack,curr);
						curr = curr->sub;
						continue;
					} else {
						if(curr->wanted->after) curr->wanted->after(tt->data, curr->wanted->data, curr);
					}
					
					curr = curr->next;
					
					while( !curr && stack->len ) {
						curr = g_ptr_array_remove_index_fast(stack,stack->len - 1);
						if( curr->wanted->after ) curr->wanted->after(tt->data, curr->wanted->data, curr);
						curr = curr->next;
					}
					
				}
				
				g_ptr_array_free(stack,TRUE);
			}
			
			tt->depth--;
			return tok; 
		}
	
reject:
		tt->offset = save_offset;
	tt->max_len = save_len;
	tt->depth--;
	return NULL;
				
}


tvbparse_elem_t* tvbparse_find(tvbparse_t* tt, const tvbparse_wanted_t* wanted) {
	int save_offset = tt->offset;
	int save_len = tt->max_len;
	tvbparse_elem_t* tok = NULL;
	
	while ( tvb_length_remaining(tt->tvb,tt->offset) >= wanted->len ) {
		if (( tok = tvbparse_get(tt, wanted) )) {
			return tok;
		}
		tt->offset++;
		tt->max_len--;
	}
	
	tt->offset = save_offset;
	tt->max_len = save_len;
	
	return NULL;
}


static void tvbparse_tree_add_elem(proto_tree* tree, tvbparse_elem_t* curr) {
    GPtrArray* stack = g_ptr_array_new();
    struct _elem_tree_stack_frame* frame = ep_alloc(sizeof(struct _elem_tree_stack_frame));
    proto_item* pi;
    frame->tree = tree;
    frame->elem = curr;
    
    while (curr) {
        pi = proto_tree_add_text(frame->tree,curr->tvb,curr->offset,curr->len,"%s",tvb_format_text(curr->tvb,curr->offset,curr->len));
        
        if(curr->sub) {
            frame->elem = curr;
            g_ptr_array_add(stack,frame);
            frame = ep_alloc(sizeof(struct _elem_tree_stack_frame));
            frame->tree = proto_item_add_subtree(pi,0);
            curr = curr->sub;
            continue;
        }
        
        curr = curr->next;
        
        while( !curr && stack->len ) {
            frame = g_ptr_array_remove_index_fast(stack,stack->len - 1);
            curr = frame->elem->next;
        }
        
    }
    
    g_ptr_array_free(stack,TRUE);
}

