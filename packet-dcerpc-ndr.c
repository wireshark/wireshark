/* packet-dcerpc-ndr.c
 * Routines for DCERPC NDR dissection
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * $Id: packet-dcerpc-ndr.c,v 1.5 2002/01/29 09:13:28 guy Exp $
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
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"


/*
 * The NDR routines are for use by dcerpc subdissetors.  They're
 * primarily for making sure things are aligned properly according
 * to the rules of NDR.
 */

int
dissect_ndr_uint8 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                   proto_tree *tree, char *drep, 
                   int hfindex, guint8 *pdata)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
      /* just a run to handle conformant arrays, no scalars to dissect */
      return offset;
    }

    /* no alignment needed */
    return dissect_dcerpc_uint8 (tvb, offset, pinfo, 
                                 tree, drep, hfindex, pdata);
}

int
dissect_ndr_uint16 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                    proto_tree *tree, char *drep, 
                    int hfindex, guint16 *pdata)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
      /* just a run to handle conformant arrays, no scalars to dissect */
      return offset;
    }


    if (offset % 2) {
        offset++;
    }
    return dissect_dcerpc_uint16 (tvb, offset, pinfo, 
                                  tree, drep, hfindex, pdata);
}

int
dissect_ndr_uint32 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                    proto_tree *tree, char *drep, 
                    int hfindex, guint32 *pdata)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
      /* just a run to handle conformant arrays, no scalars to dissect */
      return offset;
    }


    if (offset % 4) {
        offset += 4 - (offset % 4);
    }
    return dissect_dcerpc_uint32 (tvb, offset, pinfo, 
                                  tree, drep, hfindex, pdata);
}

int
dissect_ndr_uint64 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                    proto_tree *tree, char *drep, 
                    int hfindex, unsigned char *pdata)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
      /* just a run to handle conformant arrays, no scalars to dissect */
      return offset;
    }

    if (offset % 4) {
        offset += 4 - (offset % 4);
    }
    return dissect_dcerpc_uint64 (tvb, offset, pinfo, 
                                  tree, drep, hfindex, pdata);
}

int
dissect_ndr_uuid_t (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                    proto_tree *tree, char *drep, 
                    int hfindex, e_uuid_t *pdata)
{
    e_uuid_t uuid;
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
      /* just a run to handle conformant arrays, no scalars to dissect */
      return offset;
    }

    /* uuid's are aligned to 4 bytes, due to initial uint32 in struct */
    if (offset % 4) {
        offset += 4 - (offset % 4);
    }
    dcerpc_tvb_get_uuid (tvb, offset, drep, &uuid);
    if (tree) {
        proto_tree_add_string_format (tree, hfindex, tvb, offset, 16, "",
                                      "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      uuid.Data1, uuid.Data2, uuid.Data3,
                                      uuid.Data4[0], uuid.Data4[1],
                                      uuid.Data4[2], uuid.Data4[3],
                                      uuid.Data4[4], uuid.Data4[5],
                                      uuid.Data4[6], uuid.Data4[7]);
    }
    if (pdata) {
        *pdata = uuid;
    }
    return offset + 16;
}


int
dissect_ndr_ctx_hnd (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                     proto_tree *tree, char *drep, 
                     int hfindex, e_ctx_hnd *pdata)
{
    e_ctx_hnd ctx_hnd;
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
      /* just a run to handle conformant arrays, no scalars to dissect */
      return offset;
    }

    if (offset % 4) {
        offset += 4 - (offset % 4);
    }
    ctx_hnd.Data1 = dcerpc_tvb_get_ntohl (tvb, offset, drep);
    dcerpc_tvb_get_uuid (tvb, offset+4, drep, &ctx_hnd.uuid);
    if (tree) {
        proto_tree_add_bytes (tree, hfindex, tvb, offset, 20,
                              tvb_get_ptr (tvb, offset, 20));
    }
    if (pdata) {
        *pdata = ctx_hnd;
    }
    return offset + 20;
}
