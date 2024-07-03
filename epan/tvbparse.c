/* tvbparse.c
 *
 * Copyright 2005, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <epan/wmem_scopes.h>
#include <epan/proto.h>
#include <epan/packet_info.h>
#include <epan/tvbparse.h>
#include <wsutil/ws_assert.h>


#define TVBPARSE_DEBUG_ALL 0xffffffff

#if 0
#define TVBPARSE_DEBUG_ 0x80000000
#define TVBPARSE_DEBUG_ 0x40000000
#define TVBPARSE_DEBUG_ 0x20000000
#define TVBPARSE_DEBUG_ 0x10000000
#endif

#define TVBPARSE_DEBUG_CHAR 0x08000000
#define TVBPARSE_DEBUG_CHARS 0x04000000
#define TVBPARSE_DEBUG_NOT_CHAR 0x02000000
#define TVBPARSE_DEBUG_NOT_CHARS 0x01000000
#define TVBPARSE_DEBUG_STRING 0x00800000
#define TVBPARSE_DEBUG_CASESTRING 0x00400000
#define TVBPARSE_DEBUG_ONEOF 0x00200000
#define TVBPARSE_DEBUG_HASH 0x00100000
#define TVBPARSE_DEBUG_SEQ 0x00080000
#define TVBPARSE_DEBUG_SOME 0x00040000
#define TVBPARSE_DEBUG_UNTIL 0x00020000
#if 0
#define TVBPARSE_DEBUG_ 0x00010000
#define TVBPARSE_DEBUG_ 0x00008000
#define TVBPARSE_DEBUG_ 0x00004000
#define TVBPARSE_DEBUG_ 0x00002000
#define TVBPARSE_DEBUG_ 0x00001000
#endif
#define TVBPARSE_DEBUG_TT 0x00000800
#define TVBPARSE_DEBUG_CB 0x00000400
#define TVBPARSE_DEBUG_GET 0x00000200
#define TVBPARSE_DEBUG_FIND 0x00000100
#define TVBPARSE_DEBUG_NEWTOK 0x00000080
#define TVBPARSE_DEBUG_IGNORE 0x00000040
#define TVBPARSE_DEBUG_PEEK 0x00000020
#if 0
#define TVBPARSE_DEBUG_ 0x00000010
#define TVBPARSE_DEBUG_ 0x00000008
#define TVBPARSE_DEBUG_ 0x00000004
#define TVBPARSE_DEBUG_ 0x00000002
#define TVBPARSE_DEBUG_ 0x00000001
#endif

/*
#define TVBPARSE_DEBUG (TVBPARSE_DEBUG_SOME)
*/

#define TVBPARSE_MAX_RECURSION_DEPTH 100 // Arbitrary. Matches DAAP and PNIO.

static tvbparse_elem_t* new_tok(tvbparse_t* tt,
                                int id,
                                int offset,
                                int len,
                                const tvbparse_wanted_t* wanted) {
    tvbparse_elem_t* tok;

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_NEWTOK) ws_warning("new_tok: id=%i offset=%u len=%u",id,offset,len);
#endif

    tok = wmem_new(tt->scope, tvbparse_elem_t);

    tok->parser = tt;
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

static int ignore_fcn(tvbparse_t* tt, int offset) {
    int len = 0;
    int consumed;
    tvbparse_elem_t* ignored = NULL;

    if (!tt->ignore) return 0;

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_IGNORE) ws_warning("ignore: enter");
#endif

    while ((consumed = tt->ignore->condition(tt,offset,tt->ignore,&ignored)) > 0) {
        len += consumed;
        offset += consumed;
#ifdef TVBPARSE_DEBUG
        if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_IGNORE) ws_warning("ignore: consumed=%i",consumed);
#endif

    }

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_IGNORE) ws_warning("ignore: len=%i",len);
#endif

    return len;
}


static int cond_char (tvbparse_t* tt, const int offset, const tvbparse_wanted_t * wanted, tvbparse_elem_t** tok) {
    char c,t;
    unsigned i;

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_CHAR) ws_warning("cond_char: control='%s'",wanted->control.str);
#endif

    if ( offset + 1 > tt->end_offset )
        return -1;

    t = (char) tvb_get_guint8(tt->tvb,offset);

    for(i = 0; (c = wanted->control.str[i]) && offset <= tt->end_offset; i++) {
        if ( c == t ) {
            *tok =  new_tok(tt,wanted->id,offset,1,wanted);
#ifdef TVBPARSE_DEBUG
            if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_CHAR) ws_warning("cond_char: GOT: '%c'",c);
#endif
            return 1;
        }
    }

    return -1;
}

tvbparse_wanted_t* tvbparse_char(const int id,
                                 const char* chr,
                                 const void* data,
                                 tvbparse_action_t before_cb,
                                 tvbparse_action_t after_cb) {
    tvbparse_wanted_t* w = wmem_new0(wmem_epan_scope(), tvbparse_wanted_t);

    w->condition = cond_char;
    w->id = id;
    w->control.str = chr;
    w->len = 1;
    w->data = data;
    w->before = before_cb;
    w->after = after_cb;

    return w;
}

static int cond_chars_common(tvbparse_t* tt, int offset, const tvbparse_wanted_t * wanted, tvbparse_elem_t** tok) {
    unsigned length = 0;
    int start = offset;
    int left = tt->end_offset - offset;

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_CHARS) ws_warning("cond_chars_common: control='%s'",wanted->control.str);
#endif

    if ( offset + (int)wanted->min > tt->end_offset )
        return -1;

    left = left < (int) wanted->max ? left :  (int) wanted->max;

    while( left > 0 ) {
        uint8_t t = tvb_get_guint8(tt->tvb,offset++);

        if (!wanted->control.str[t])
            break;

        length++;
        left--;
    };

    if (length < wanted->min) {
        return  -1;
    } else {
        *tok = new_tok(tt,wanted->id,start,length,wanted);
#ifdef TVBPARSE_DEBUG
        if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_CHARS) ws_warning("cond_chars_common: GOT len=%i",length);
#endif
        return length;
    }
}

tvbparse_wanted_t* tvbparse_chars(const int id,
                                  const unsigned min_len,
                                  const unsigned max_len,
                                  const char* chr,
                                  const void* data,
                                  tvbparse_action_t before_cb,
                                  tvbparse_action_t after_cb)
{
    tvbparse_wanted_t* w = wmem_new0(wmem_epan_scope(), tvbparse_wanted_t);
    char *accept_str;
    size_t i;

    accept_str = (char *)wmem_alloc(wmem_epan_scope(), 256);
    memset(accept_str, 0x00, 256);
    for (i = 0; chr[i]; i++)
        accept_str[(unsigned)chr[i]] = (char)0xFF;

    w->condition = cond_chars_common;
    w->id = id;
    w->control.str = accept_str;
    w->min = min_len ? min_len : 1;
    w->max = max_len ? max_len : INT_MAX/2;
    w->data = data;
    w->before = before_cb;
    w->after = after_cb;

    return w;
}


static int cond_not_char(tvbparse_t* tt, const int offset, const tvbparse_wanted_t * wanted, tvbparse_elem_t** tok) {
    char c, t;
    unsigned i;
    bool not_matched = false;

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_NOT_CHAR) ws_warning("cond_not_char: control='%s'",wanted->control.str);
#endif

    if ( offset >= tt->end_offset ) {
        return -1;
    }

    t = (char) tvb_get_guint8(tt->tvb,offset);

    for(i = 0; (c = wanted->control.str[i]); i++) {
        if ( c == t ) {
            not_matched = true;
        }
    }

    if (not_matched) {
        return -1;
    } else {
        *tok =  new_tok(tt,wanted->id,offset,1,wanted);
#ifdef TVBPARSE_DEBUG
        if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_NOT_CHAR) ws_warning("cond_not_char: GOT='%c'",t);
#endif
        return 1;
    }
}

tvbparse_wanted_t* tvbparse_not_char(const int id,
                                     const char* chr,
                                     const void* data,
                                     tvbparse_action_t before_cb,
                                     tvbparse_action_t after_cb) {
    tvbparse_wanted_t* w = wmem_new0(wmem_epan_scope(), tvbparse_wanted_t);

    w->condition = cond_not_char;
    w->id = id;
    w->control.str = chr;
    w->data = data;
    w->before = before_cb;
    w->after = after_cb;

    return w;
}

tvbparse_wanted_t* tvbparse_not_chars(const int id,
                                      const unsigned min_len,
                                      const unsigned max_len,
                                      const char* chr,
                                      const void* data,
                                      tvbparse_action_t before_cb,
                                      tvbparse_action_t after_cb)
{
    tvbparse_wanted_t* w = wmem_new0(wmem_epan_scope(), tvbparse_wanted_t);
    char *accept_str;
    size_t i;

    /* cond_chars_common() use accept string, so mark all elements with, and later unset from reject */
    accept_str = (char *)wmem_alloc(wmem_epan_scope(), 256);
    memset(accept_str, 0xFF, 256);
    for (i = 0; chr[i]; i++)
        accept_str[(unsigned) chr[i]] = '\0';

    w->condition = cond_chars_common;
    w->id = id;
    w->control.str = accept_str;
    w->len = 0;
    w->min = min_len ? min_len : 1;
    w->max = max_len ? max_len : INT_MAX/2;
    w->data = data;
    w->before = before_cb;
    w->after = after_cb;

    return w;
}


static int cond_string(tvbparse_t* tt, const int offset, const tvbparse_wanted_t * wanted, tvbparse_elem_t** tok) {
    int len = wanted->len;
#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_STRING) ws_warning("cond_string: control='%s'",wanted->control.str);
#endif

    if ( offset + wanted->len > tt->end_offset )
        return -1;

    if ( tvb_strneql(tt->tvb, offset, wanted->control.str, len) == 0 ) {
        *tok = new_tok(tt,wanted->id,offset,len,wanted);
#ifdef TVBPARSE_DEBUG
        if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_STRING) ws_warning("cond_string: GOT len=%i",len);
#endif
        return len;
    } else {
        return -1;
    }
}

tvbparse_wanted_t* tvbparse_string(const int id,
                                   const char* str,
                                   const void* data,
                                   tvbparse_action_t before_cb,
                                   tvbparse_action_t after_cb) {
    tvbparse_wanted_t* w = wmem_new0(wmem_epan_scope(), tvbparse_wanted_t);

    w->condition = cond_string;
    w->id = id;
    w->control.str = str;
    w->len = (int) strlen(str);
    w->data = data;
    w->before = before_cb;
    w->after = after_cb;

    return w;
}

static int cond_casestring(tvbparse_t* tt, const int offset, const tvbparse_wanted_t * wanted, tvbparse_elem_t** tok) {
    int len = wanted->len;
#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_CASESTRING) ws_warning("cond_casestring: control='%s'",wanted->control.str);
#endif

    if ( offset + len > tt->end_offset )
        return -1;

    if ( tvb_strncaseeql(tt->tvb, offset, wanted->control.str, len) == 0 ) {
        *tok = new_tok(tt,wanted->id,offset,len,wanted);
#ifdef TVBPARSE_DEBUG
        if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_CASESTRING) ws_warning("cond_casestring: GOT len=%i",len);
#endif
        return len;
    } else {
        *tok = NULL;
        return -1;
    }
}

tvbparse_wanted_t* tvbparse_casestring(const int id,
                                       const char* str,
                                       const void* data,
                                       tvbparse_action_t before_cb,
                                       tvbparse_action_t after_cb) {
    tvbparse_wanted_t* w = wmem_new0(wmem_epan_scope(), tvbparse_wanted_t);

    w->condition = cond_casestring;
    w->id = id;
    w->control.str = str;
    w->len = (int) strlen(str);
    w->data = data;
    w->before = before_cb;
    w->after = after_cb;

    return w;
}

static int cond_one_of(tvbparse_t* tt, const int offset, const tvbparse_wanted_t * wanted, tvbparse_elem_t** tok) {
    unsigned i;
#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_ONEOF) ws_warning("cond_one_of: START");
#endif

    if ( offset > tt->end_offset )
        return -1;

    if (++tt->recursion_depth > TVBPARSE_MAX_RECURSION_DEPTH)
        return -1;

    for(i=0; i < wanted->control.elems->len; i++) {
        tvbparse_wanted_t* w = (tvbparse_wanted_t *)g_ptr_array_index(wanted->control.elems,i);
        tvbparse_elem_t* new_elem = NULL;
        int curr_len;

        if ( offset + w->len > tt->end_offset )
            continue;

        curr_len = w->condition(tt, offset, w,  &new_elem);

        if (curr_len >= 0) {
            *tok = new_tok(tt, wanted->id, new_elem->offset, new_elem->len, wanted);
            (*tok)->sub = new_elem;
#ifdef TVBPARSE_DEBUG
            if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_ONEOF) ws_warning("cond_one_of: GOT len=%i",curr_len);
#endif
            tt->recursion_depth--;
            return curr_len;
        }
    }

    tt->recursion_depth--;
    return -1;
}

static bool
tvbparse_wanted_cleanup_cb(wmem_allocator_t* allocator _U_, wmem_cb_event_t event _U_, void *user_data)
{
    tvbparse_wanted_t* w = (tvbparse_wanted_t *)user_data;
    g_ptr_array_free(w->control.elems, true);
    return false;
}

tvbparse_wanted_t* tvbparse_set_oneof(const int id,
                                      const void* data,
                                      tvbparse_action_t before_cb,
                                      tvbparse_action_t after_cb,
                                      ...) {
    tvbparse_wanted_t* w = wmem_new0(wmem_epan_scope(), tvbparse_wanted_t);
    tvbparse_t* el;
    va_list ap;

    w->condition = cond_one_of;
    w->id = id;
    w->data = data;
    w->before = before_cb;
    w->after = after_cb;
    w->control.elems = g_ptr_array_new();
    wmem_register_callback(wmem_epan_scope(), tvbparse_wanted_cleanup_cb, w);

    va_start(ap,after_cb);

    while(( el = va_arg(ap,tvbparse_t*) )) {
        g_ptr_array_add(w->control.elems,el);
    };

    va_end(ap);

    return w;
}

static int cond_hash(tvbparse_t* tt, const int offset, const tvbparse_wanted_t* wanted, tvbparse_elem_t** tok) {
    int key_len;
    char* key = NULL;
    tvbparse_elem_t* key_elem = NULL;
    tvbparse_wanted_t* value_wanted = NULL;
    int value_len;
    tvbparse_elem_t* value_elem = NULL;
    int tot_len;
    tvbparse_elem_t* ret_tok;

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_HASH) ws_warning("cond_hash: START");
#endif

    if ( offset > tt->end_offset )
        return -1;

    if (++tt->recursion_depth > TVBPARSE_MAX_RECURSION_DEPTH)
        return -1;

    key_len = wanted->control.hash.key->condition(tt, offset, wanted->control.hash.key,  &key_elem);

    if (key_len < 0) {
        tt->recursion_depth--;
        return -1;
    }

    key = tvb_get_string_enc(tt->scope,key_elem->parser->tvb,key_elem->offset,key_elem->len, ENC_ASCII);
#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_HASH) ws_warning("cond_hash: got key='%s'",key);
#endif

    if ((value_wanted = (tvbparse_wanted_t *)wmem_map_lookup(wanted->control.hash.table,key))) {
        value_len = value_wanted->condition(tt, offset + key_len, value_wanted,  &value_elem);
    } else if (wanted->control.hash.other) {
        value_len = wanted->control.hash.other->condition(tt, offset+key_len, wanted->control.hash.other,  &value_elem);
        if (value_len < 0) {
            tt->recursion_depth--;
            return -1;
        }
    } else {
        tt->recursion_depth--;
        return -1;
    }

    tt->recursion_depth--;

    tot_len = key_len + value_len;

    ret_tok = new_tok(tt, value_elem->id, offset, tot_len, wanted);
    ret_tok->sub = key_elem;
    ret_tok->sub->last->next = value_elem;

    *tok = ret_tok;
#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_HASH) ws_warning("cond_hash: GOT len=%i",tot_len);
#endif

    return tot_len;
}

tvbparse_wanted_t* tvbparse_hashed(const int id,
                                   const void* data,
                                   tvbparse_action_t before_cb,
                                   tvbparse_action_t after_cb,
                                   tvbparse_wanted_t* key,
                                   tvbparse_wanted_t* other,
                                   ...) {
    tvbparse_wanted_t* w = wmem_new0(wmem_epan_scope(), tvbparse_wanted_t);
    char* name;
    tvbparse_wanted_t* el;
    va_list ap;

    w->condition = cond_hash;
    w->id = id;
    w->data = data;
    w->before = before_cb;
    w->after = after_cb;
    w->control.hash.table = wmem_map_new(wmem_epan_scope(), g_str_hash,g_str_equal);
    w->control.hash.key = key;
    w->control.hash.other = other;

    va_start(ap,other);

    while(( name = va_arg(ap,char*) )) {
        el = va_arg(ap,tvbparse_wanted_t*);
        wmem_map_insert(w->control.hash.table,name,el);
    }

    va_end(ap);

    return w;
}

void tvbparse_hashed_add(tvbparse_wanted_t* w, ...) {
    tvbparse_wanted_t* el;
    va_list ap;
    char* name;

    va_start(ap,w);

    while (( name = va_arg(ap,char*) )) {
        el = va_arg(ap,tvbparse_wanted_t*);
        wmem_map_insert(w->control.hash.table,name,el);
    }

    va_end(ap);
}

static int cond_seq(tvbparse_t* tt, int offset, const tvbparse_wanted_t * wanted, tvbparse_elem_t** tok) {
    unsigned i;
    int len = 0;
    int start = offset;
    tvbparse_elem_t* ret_tok = NULL;

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_SEQ) ws_warning("cond_seq: START");
#endif

    if ( offset > tt->end_offset )
        return -1;

    if (++tt->recursion_depth > TVBPARSE_MAX_RECURSION_DEPTH)
        return -1;

    for(i=0; i < wanted->control.elems->len; i++) {
        tvbparse_wanted_t* w = (tvbparse_wanted_t *)g_ptr_array_index(wanted->control.elems,i);
        tvbparse_elem_t* new_elem = NULL;

        if ( offset + w->len > tt->end_offset ) {
            tt->recursion_depth--;
            return -1;
        }

        len = w->condition(tt, offset, w, &new_elem);

        if (len >= 0) {
            if (ret_tok) {
                if (new_elem->len)
                    ret_tok->len = (new_elem->offset - ret_tok->offset) + new_elem->len;
                ret_tok->sub->last->next = new_elem;
                ret_tok->sub->last = new_elem;
            } else {
                ret_tok = new_tok(tt, wanted->id, new_elem->offset, new_elem->len, wanted);
                ret_tok->sub = new_elem;
                new_elem->last = new_elem;
            }
        } else {
            tt->recursion_depth--;
            return -1;
        }

        offset += len;
        offset += ignore_fcn(tt,offset);
    }

    tt->recursion_depth--;

    *tok = ret_tok;

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_SEQ) ws_warning("cond_seq: GOT len=%i",offset - start);
#endif

    return offset - start;
}


tvbparse_wanted_t* tvbparse_set_seq(const int id,
                                    const void* data,
                                    tvbparse_action_t before_cb,
                                    tvbparse_action_t after_cb,
                                    ...) {
    tvbparse_wanted_t* w = wmem_new0(wmem_epan_scope(), tvbparse_wanted_t);
    tvbparse_wanted_t*  el = NULL;
    va_list ap;

    w->condition = cond_seq;
    w->id = id;
    w->data = data;
    w->before = before_cb;
    w->after = after_cb;
    w->control.elems = g_ptr_array_new();
    wmem_register_callback(wmem_epan_scope(), tvbparse_wanted_cleanup_cb, w);

    va_start(ap,after_cb);

    while(( el = va_arg(ap,tvbparse_wanted_t*) )) {
        g_ptr_array_add(w->control.elems,el);
    };

    va_end(ap);
    return w;
}

static int cond_some(tvbparse_t* tt, int offset, const tvbparse_wanted_t * wanted, tvbparse_elem_t** tok) {
    unsigned got_so_far = 0;
    int start = offset;
    tvbparse_elem_t* ret_tok = NULL;
#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_SOME) ws_warning("cond_some: START");
#endif

    if ( offset > tt->end_offset )
        return -1;

    if (++tt->recursion_depth > TVBPARSE_MAX_RECURSION_DEPTH)
        return -1;

    if ( wanted->min == 0 ) {
        ret_tok = new_tok(tt,wanted->id,offset,0,wanted);
    }

    while (got_so_far < wanted->max) {
        tvbparse_elem_t* new_elem = NULL;
        int consumed;

        if ( offset > tt->end_offset ) {
            tt->recursion_depth--;
            return -1;
        }

        consumed = wanted->control.subelem->condition(tt, offset, wanted->control.subelem, &new_elem);

        if(consumed >= 0) {
            if (ret_tok) {
                if (new_elem->len)
                    ret_tok->len = (new_elem->offset - ret_tok->offset) + new_elem->len;

                if (ret_tok->sub) {
                    ret_tok->sub->last->next = new_elem;
                    ret_tok->sub->last = new_elem;
                } else {
                    ret_tok->sub = new_elem;
                }
            } else {
                ret_tok = new_tok(tt, wanted->id, new_elem->offset, new_elem->len, wanted);
                ret_tok->sub = new_elem;
            }
        } else {
            break;
        }

        offset += consumed;
        got_so_far++;
    }

    tt->recursion_depth--;

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_SOME) ws_warning("cond_some: got num=%u",got_so_far);
#endif

    if(got_so_far < wanted->min) {
        return -1;
    }

    *tok = ret_tok;
#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_SOME) ws_warning("cond_some: GOT len=%i",offset - start);
#endif
    return offset - start;
}

tvbparse_wanted_t* tvbparse_some(const int id,
                                 const unsigned from,
                                 const unsigned to,
                                 const void* data,
                                 tvbparse_action_t before_cb,
                                 tvbparse_action_t after_cb,
                                 const tvbparse_wanted_t* el) {

    tvbparse_wanted_t* w = wmem_new0(wmem_epan_scope(), tvbparse_wanted_t);

    ws_assert(from <= to);

    w->condition = cond_some;
    w->id = id;
    w->min = from;
    w->max = to;
    w->data = data;
    w->before = before_cb;
    w->after = after_cb;
    w->control.subelem = el;

    return w;
}


static int cond_until(tvbparse_t* tt, const int offset, const tvbparse_wanted_t * wanted, tvbparse_elem_t** tok) {
    tvbparse_elem_t* new_elem = NULL;
    int len = 0;
    int target_offset = offset;
#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_UNTIL) ws_warning("cond_until: START");
#endif

    if ( offset + wanted->control.until.subelem->len > tt->end_offset )
        return -1;

    if (++tt->recursion_depth > TVBPARSE_MAX_RECURSION_DEPTH)
        return -1;

    do {
        len = wanted->control.until.subelem->condition(tt, target_offset++, wanted->control.until.subelem,  &new_elem);
    } while(len < 0  && target_offset+1 < tt->end_offset);

    tt->recursion_depth--;

    if (len >= 0) {

        new_elem->id = wanted->id;
        new_elem->next = NULL;
        new_elem->last = NULL;
        new_elem->wanted = wanted;
        new_elem->offset = offset;

        (*tok) = new_elem;

        switch (wanted->control.until.mode) {
            case TP_UNTIL_INCLUDE:
                new_elem->len = target_offset - offset - 1 + len;
#ifdef TVBPARSE_DEBUG
                if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_UNTIL) ws_warning("cond_until: GOT len=%i",target_offset - offset -1 + len);
#endif
                return target_offset - offset -1 + len;
            case TP_UNTIL_SPEND:
                new_elem->len = target_offset - offset - 1;
#ifdef TVBPARSE_DEBUG
                if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_UNTIL) ws_warning("cond_until: GOT len=%i",target_offset - offset -1 + len);
#endif
                return target_offset - offset - 1 + len;
            case TP_UNTIL_LEAVE:
                new_elem->len = target_offset - offset - 1;
#ifdef TVBPARSE_DEBUG
                if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_UNTIL) ws_warning("cond_until: GOT len=%i",target_offset - offset -1);
#endif
                return target_offset - offset -1;
            default:
                DISSECTOR_ASSERT_NOT_REACHED();
                return -1;
        }

    } else {
        return -1;
    }
}

tvbparse_wanted_t* tvbparse_until(const int id,
                                  const void* data,
                                  tvbparse_action_t before_cb,
                                  tvbparse_action_t after_cb,
                                  const tvbparse_wanted_t* el,
                                  until_mode_t until_mode) {
    tvbparse_wanted_t* w = wmem_new0(wmem_epan_scope(), tvbparse_wanted_t);

    w->condition = cond_until;
    w->control.until.mode = until_mode;
    w->control.until.subelem = el;
    w->id = id;
    w->data = data;
    w->before = before_cb;
    w->after = after_cb;

    return w;
}

tvbparse_wanted_t* tvbparse_quoted(const int id,
                                   const void* data,
                                   tvbparse_action_t before_cb,
                                   tvbparse_action_t after_cb,
                                   const char quote,
                                   const char esc) {

    char* esc_quot = wmem_strdup_printf(wmem_epan_scope(), "%c%c",esc,quote);
    char* quot = wmem_strdup_printf(wmem_epan_scope(), "%c",quote);
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

tvbparse_t* tvbparse_init(wmem_allocator_t *scope,
                          tvbuff_t* tvb,
                          const int offset,
                          int len,
                          void* data,
                          const tvbparse_wanted_t* ignore) {
    tvbparse_t* tt = wmem_new(scope, tvbparse_t);

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_TT) ws_warning("tvbparse_init: offset=%i len=%i",offset,len);
#endif

    tt->scope = scope;
    tt->tvb = tvb;
    tt->offset = offset;
    len = (len == -1) ? (int) tvb_captured_length(tvb) : len;
    tt->end_offset = offset + len;
    tt->data = data;
    tt->ignore = ignore;
    tt->recursion_depth = 0;
    return tt;
}

bool tvbparse_reset(tvbparse_t* tt,
                        const int offset,
                        int len) {

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_TT) ws_warning("tvbparse_init: offset=%i len=%i",offset,len);
#endif

    len = (len == -1) ? (int) tvb_captured_length(tt->tvb) : len;

    if( tvb_captured_length_remaining(tt->tvb, offset) >= len) {
        tt->offset = offset;
        tt->end_offset = offset + len;
        return true;
    } else {
        return false;
    }
}

unsigned tvbparse_curr_offset(tvbparse_t* tt) {
    return tt->offset;
}

static void execute_callbacks(tvbparse_t* tt, tvbparse_elem_t* curr) {
    wmem_stack_t *stack = wmem_stack_new(tt->scope);

    while (curr) {
        if(curr->wanted->before) {
#ifdef TVBPARSE_DEBUG
            if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_CB) ws_warning("execute_callbacks: BEFORE: id=%i offset=%i len=%i",curr->id,curr->offset,curr->len);
#endif
            curr->wanted->before(tt->data, curr->wanted->data, curr);
        }

        if(curr->sub) {
            wmem_stack_push(stack, curr);
            curr = curr->sub;
            continue;
        } else {
#ifdef TVBPARSE_DEBUG
            if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_CB) ws_warning("execute_callbacks: AFTER: id=%i offset=%i len=%i",curr->id,curr->offset,curr->len);
#endif
            if(curr->wanted->after) curr->wanted->after(tt->data, curr->wanted->data, curr);
        }

        curr = curr->next;

        while( !curr && wmem_stack_count(stack) > 0 ) {
            curr = (tvbparse_elem_t *)wmem_stack_pop(stack);
#ifdef TVBPARSE_DEBUG
            if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_CB) ws_warning("execute_callbacks: AFTER: id=%i offset=%i len=%i",curr->id,curr->offset,curr->len);
#endif
            if( curr->wanted->after ) curr->wanted->after(tt->data, curr->wanted->data, curr);
            curr = curr->next;
        }
    }

}

bool tvbparse_peek(tvbparse_t* tt,
                       const tvbparse_wanted_t* wanted) {
    tvbparse_elem_t* tok = NULL;
    int consumed;
    int offset = tt->offset;

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_PEEK) ws_warning("tvbparse_peek: ENTER offset=%i",offset);
#endif

    offset += ignore_fcn(tt,offset);

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_PEEK) ws_warning("tvbparse_peek: after ignore offset=%i",offset);
#endif

    consumed = wanted->condition(tt,offset,wanted,&tok);

    if (consumed >= 0) {
#ifdef TVBPARSE_DEBUG
        if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_PEEK) ws_warning("tvbparse_peek: GOT len=%i",consumed);
#endif
        return true;
    } else {
#ifdef TVBPARSE_DEBUG
        if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_PEEK) ws_warning("tvbparse_peek: NOT GOT");
#endif
        return false;
    }

}

tvbparse_elem_t* tvbparse_get(tvbparse_t* tt,
                              const tvbparse_wanted_t* wanted) {
    tvbparse_elem_t* tok = NULL;
    int consumed;
    int offset = tt->offset;

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_GET) ws_warning("tvbparse_get: ENTER offset=%i",offset);
#endif

    offset += ignore_fcn(tt,offset);

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_GET) ws_warning("tvbparse_get: after ignore offset=%i",offset);
#endif

    consumed = wanted->condition(tt,offset,wanted,&tok);

    if (consumed >= 0) {
#ifdef TVBPARSE_DEBUG
        if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_GET) ws_warning("tvbparse_get: GOT len=%i",consumed);
#endif
        execute_callbacks(tt,tok);
        tt->offset = offset + consumed;
#ifdef TVBPARSE_DEBUG
        if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_GET) ws_warning("tvbparse_get: DONE offset=%i", tt->offset);
#endif
        return tok;
    } else {
        return NULL;
    }

}


tvbparse_elem_t* tvbparse_find(tvbparse_t* tt, const tvbparse_wanted_t* wanted) {
    tvbparse_elem_t* tok = NULL;
    int len = 0;
    int offset = tt->offset;
    int target_offset = offset -1;

#ifdef TVBPARSE_DEBUG
    if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_FIND) ws_warning("tvbparse_get: ENTER offset=%i", tt->offset);
#endif

    do {
        len = wanted->condition(tt, target_offset+1, wanted,  &tok);
    } while(len < 0  && ++target_offset < tt->end_offset);

    if (len >= 0) {
#ifdef TVBPARSE_DEBUG
        if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_FIND) ws_warning("tvbparse_get: FOUND offset=%i len=%i", target_offset,len);
#endif
        execute_callbacks(tt,tok);
        tt->offset = target_offset + len;

#ifdef TVBPARSE_DEBUG
        if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_FIND) ws_warning("tvbparse_get: DONE offset=%i", tt->offset);
#endif
        return tok;
    } else {
#ifdef TVBPARSE_DEBUG
        if (TVBPARSE_DEBUG & TVBPARSE_DEBUG_FIND) ws_warning("tvbparse_get: NOT FOUND");
#endif
        return NULL;
    }
}

struct _elem_tree_stack_frame {
    proto_tree* tree;
    tvbparse_elem_t* elem;
};

void tvbparse_tree_add_elem(proto_tree* tree, tvbparse_elem_t* curr) {
    wmem_stack_t *stack = wmem_stack_new(curr->parser->scope);
    struct _elem_tree_stack_frame* frame = wmem_new(curr->parser->scope, struct _elem_tree_stack_frame);
    proto_item* pi;
    frame->tree = tree;
    frame->elem = curr;

    while (curr) {
        pi = proto_tree_add_format_text(frame->tree,curr->parser->tvb,curr->offset,curr->len);

        if(curr->sub) {
            frame->elem = curr;
            wmem_stack_push(stack, frame);
            frame = wmem_new(curr->parser->scope, struct _elem_tree_stack_frame);
            frame->tree = proto_item_add_subtree(pi,0);
            curr = curr->sub;
            continue;
        }

        curr = curr->next;

        while( !curr && wmem_stack_count(stack) > 0 ) {
            frame = (struct _elem_tree_stack_frame *)wmem_stack_pop(stack);
            curr = frame->elem->next;
        }

    }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
