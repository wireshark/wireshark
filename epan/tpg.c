/* tpg.c
 * helper functions for TPG
 *
 *  (c) 2005, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 * 
 * $Id:$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "tpg.h"
#include <epan/emem.h>
#include <epan/packet.h>

void
http_dissector_add(guint32 port, dissector_handle_t handle)
{
}


extern guint32 tpg_ipv4(tvbparse_elem_t* e _U_) {    
    /* XXX TO DO */
    return 0;
}

extern guint8* tpg_ipv6(tvbparse_elem_t* e _U_) {
    /* XXX TO DO */
    return NULL;
}

extern tpg_parser_data_t* tpg_start(proto_tree* root_tree,
                                    tvbuff_t* tvb,
                                    int offset,
                                    int len,
                                    void* private_data) {
    tpg_parser_data_t* tpg = ep_alloc(sizeof(tpg_parser_data_t));
    tpg->private_data = private_data;
    tpg->tt = tvbparse_init(tvb,offset,len,tpg,NULL);

    tpg->stack = ep_alloc(sizeof(tpg_stack_frame_t));
    tpg->stack->tree = root_tree;
    tpg->stack->down = NULL;
    
    return tpg;
}


extern void tpg_push(tpg_parser_data_t* tpg, proto_item* item, gint ett) {
    tpg_stack_frame_t* frame = ep_alloc(sizeof(tpg_stack_frame_t));
    
    frame->tree = proto_item_add_subtree(item,ett);
    frame->down = tpg->stack;
    tpg->stack = frame;
    
}


tpg_stack_frame_t* tpg_pop(tpg_parser_data_t* tpg) {
    tpg_stack_frame_t* frame = tpg->stack;
    
    if (tpg->stack->down) {
        tpg->stack = tpg->stack->down;
    } else {
        DISSECTOR_ASSERT( FALSE && "Error in the TPG infrastructure: trying to pop the end of the stack");
    }
    
    return frame;
}
