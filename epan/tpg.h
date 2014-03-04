/* tpg.h
 * Definitions of helper functions for TPG
 *
 *  (c) 2005, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _TPG_H_
#define _TPG_H_

#include <glib.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/tvbparse.h>
#include <epan/wmem/wmem.h>
#include "ws_symbol_export.h"

typedef struct _tpg_parser_data_t {
    wmem_stack_t *stack;
    tvbparse_t* tt;
    void* private_data;
} tpg_parser_data_t;

extern tpg_parser_data_t* tpg_start(proto_tree* root_tree,
                                    tvbuff_t* tvb,
                                    int offset,
                                    int len,
                                    tvbparse_wanted_t* ignore,
                                    void* private_data);

#define TPG_START(tree,tvb,offset,len,data) tpg_start((tree),(tvb),(offset),(len),(data))

#define TPG_GET(tpg, wanted)  tvbparse_get((tpg)->tt,(wanted))
#define TPG_FIND(tpg, wanted)  tvbparse_find((tpg)->tt,(wanted))

#define TPG_TREE(vp) (((tpg_parser_data_t*)(vp))->tree)
#define TPG_DATA(vp,type) (((type*)(((tpg_parser_data_t*)(vp))->private_data)))

#define TPG_STRING(i) tvb_get_string(wmem_packet_scope(), (i)->tvb,(i)->offset,(i)->len)
#define TPG_INT(i) strtol(tvb_get_string(wmem_packet_scope(), (i)->tvb,(i)->offset,(i)->len),NULL,10)
#define TPG_UINT(i) strtoul(tvb_get_string(wmem_packet_scope(), (i)->tvb,(i)->offset,(i)->len),NULL,10)
#define TPG_UINT_HEX(i) strtoul(tvb_get_string(wmem_packet_scope(), (i)->tvb,(i)->offset,(i)->len),NULL,16)
#define TPG_TVB(i) tvb_new_subset((i)->tvb,(i)->offset,(i)->len,(i)->len)

WS_DLL_PUBLIC guint32 tpg_ipv4(tvbparse_elem_t*);
#define TPG_IPV4(i) tpg_ipv4((i))

WS_DLL_PUBLIC guint8* tpg_ipv6(tvbparse_elem_t*);
#define TPG_IPV6(i) tpg_ipv6((i))

#define TPG_PUSH(tpg,pi,ett) wmem_stack_push(((tpg_parser_data_t*)(tpg))->stack,proto_item_add_subtree((pi),(ett)))
#define TPG_POP(tpg) wmem_stack_pop(((tpg_parser_data_t*)(tpg))->stack) ;

#define TPG_ADD_STRING(tpg,  hfid, elem) proto_tree_add_item(ep_stack_peek(((tpg_parser_data_t*)tpg)->stack), hfid, (elem)->tvb, (elem)->offset, (elem)->len, FALSE)
#define TPG_ADD_BOOLEAN(tpg,  hfid, elem) proto_tree_add_boolean(ep_stack_peek(((tpg_parser_data_t*)tpg)->stack), hfid, (elem)->tvb, (elem)->offset, (elem)->len, TRUE)
#define TPG_ADD_INT(tpg,  hfid, elem, value) proto_tree_add_int(ep_stack_peek(((tpg_parser_data_t*)tpg)->stack), hfid, (elem)->tvb, (elem)->offset, (elem)->len, value)
#define TPG_ADD_UINT(tpg,  hfid, elem, value) proto_tree_add_uint(ep_stack_peek(((tpg_parser_data_t*)tpg)->stack), hfid, (elem)->tvb, (elem)->offset, (elem)->len, value)
#define TPG_ADD_IPV4(tpg,  hfid, elem, value) proto_tree_add_ipv4(ep_stack_peek(((tpg_parser_data_t*)tpg)->stack), hfid, (elem)->tvb, (elem)->offset, (elem)->len, value)
#define TPG_ADD_IPV6(tpg,  hfid, elem, value) proto_tree_add_ipv6(ep_stack_peek(((tpg_parser_data_t*)tpg)->stack), hfid, (elem)->tvb, (elem)->offset, (elem)->len, value)
#define TPG_ADD_TEXT(tpg, elem) proto_tree_add_text(ep_stack_peek(((tpg_parser_data_t*)tpg)->stack), (elem)->tvb, (elem)->offset, (elem)->len, \
                                                             "%s",tvb_format_text((elem)->tvb, (elem)->offset, (elem)->len))

#define TPG_SET_TEXT(pi, elem) proto_item_set_text((pi), "%s",tvb_format_text((elem)->tvb, (elem)->offset, (elem)->len))

#endif /* _TPG_H_ */
