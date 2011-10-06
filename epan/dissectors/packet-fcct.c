/* packet-fcct.c
 * Routines for FC Common Transport Protocol (used by GS3 services)
 * Copyright 2001, Dinesh G Dutt <ddutt@andiamo.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/conversation.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-fcct.h"

/* Initialize the protocol and registered fields */
static int proto_fcct           = -1;
static int hf_fcct_revision     = -1;
static int hf_fcct_inid         = -1;
static int hf_fcct_gstype       = -1;
static int hf_fcct_gssubtype    = -1;
static int hf_fcct_options      = -1;
static int hf_fcct_server       = -1; /* derived field */

/* Extended preamble fields */
static int hf_fcct_ext_said     = -1;
static int hf_fcct_ext_tid      = -1;
static int hf_fcct_ext_reqname  = -1;
static int hf_fcct_ext_tstamp   = -1;
static int hf_fcct_ext_authblk  = -1;

/* Initialize the subtree pointers */
static gint ett_fcct = -1;
static gint ett_fcct_ext = -1;  /* for the extended header */

const value_string fc_ct_rjt_code_vals [] = {
    {FCCT_RJT_INVCMDCODE, "Invalid Cmd Code"},
    {FCCT_RJT_INVVERSION, "Invalid Version Level"},
    {FCCT_RJT_LOGICALERR, "Logical Error"},
    {FCCT_RJT_INVSIZE,    "Invalid CT_IU Size"},
    {FCCT_RJT_LOGICALBSY, "Logical Busy"},
    {FCCT_RJT_PROTOERR,   "Protocol Error"},
    {FCCT_RJT_GENFAIL,    "Unable to Perform Cmd"},
    {FCCT_RJT_CMDNOTSUPP, "Cmd Not Supported"},
    {0, NULL},
};

const value_string fc_ct_gstype_vals[] = {
    {FCCT_GSTYPE_KEYSVC, "Key Service"},
    {FCCT_GSTYPE_ALIASSVC, "Alias Service"},
    {FCCT_GSTYPE_MGMTSVC, "Management Service"},
    {FCCT_GSTYPE_TIMESVC, "Time Service"},
    {FCCT_GSTYPE_DIRSVC, "Directory Service"},
    {FCCT_GSTYPE_FCTLR, "Fabric Controller"},
    {FCCT_GSTYPE_VENDOR, "Vendor-Specific"},
    {0, NULL},
};

const value_string fc_ct_gsserver_vals[] = {
    {FCCT_GSRVR_DNS, "dNS"},
    {FCCT_GSRVR_IP,  "IP"},
    {FCCT_GSRVR_FCS, "Fabric Config Server"},
    {FCCT_GSRVR_UNS, "Unzoned Name Server"},
    {FCCT_GSRVR_FZS, "Fabric Zone Server"},
    {FCCT_GSRVR_TS,  "Time Server"},
    {FCCT_GSRVR_KS,  "Key Server"},
    {FCCT_GSRVR_AS,  "Alias Server"},
    {FCCT_GSRVR_FCTLR, "Fabric Controller"},
    {0, NULL},
};

static dissector_table_t fcct_gserver_table;
static dissector_handle_t data_handle;

guint8
get_gs_server (guint8 gstype, guint8 gssubtype)
{
    switch (gstype) {
    case FCCT_GSTYPE_KEYSVC:
        return FCCT_GSRVR_KS;
    case FCCT_GSTYPE_ALIASSVC:
        if (gssubtype == FCCT_GSSUBTYPE_AS)
            return FCCT_GSRVR_AS;
        return FCCT_GSRVR_UNKNOWN;
    case FCCT_GSTYPE_MGMTSVC:
        if (gssubtype == FCCT_GSSUBTYPE_FCS)
            return FCCT_GSRVR_FCS;
        else if (gssubtype == FCCT_GSSUBTYPE_UNS)
            return FCCT_GSRVR_UNS;
        else if (gssubtype == FCCT_GSSUBTYPE_FZS)
            return FCCT_GSRVR_FZS;
        else return FCCT_GSRVR_UNKNOWN;
    case FCCT_GSTYPE_TIMESVC:
        if (gssubtype == FCCT_GSSUBTYPE_TS)
            return FCCT_GSRVR_TS;
        return FCCT_GSRVR_UNKNOWN;
    case FCCT_GSTYPE_DIRSVC:
        if (gssubtype == FCCT_GSSUBTYPE_DNS)
            return FCCT_GSRVR_DNS;
        else if (gssubtype == FCCT_GSSUBTYPE_IP)
            return FCCT_GSRVR_IP;
        return FCCT_GSRVR_UNKNOWN;
    case FCCT_GSRVR_FCTLR:
         if (gssubtype == FCCT_GSSUBTYPE_FCTLR)
              return (FCCT_GSRVR_FCTLR);
         else return (FCCT_GSRVR_UNKNOWN);
    default:
        return FCCT_GSRVR_UNKNOWN;
    }
}

/* Code to actually dissect the packets */
static void
dissect_fcct (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *fcct_tree;
    tvbuff_t *next_tvb;
    int in_id,
        offset = 0;
    guint8 server;
    fc_ct_preamble cthdr;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FC_CT");

    /*
      cthdr.revision = tvb_get_guint8 (tvb, offset++);
      cthdr.in_id = tvb_get_ntoh24 (tvb, offset);
      offset += 3;

      cthdr.gstype = tvb_get_guint8 (tvb, offset++);
      cthdr.options = tvb_get_guint8 (tvb, offset++);
    */
    tvb_memcpy (tvb, (guint8 *)&cthdr, offset, FCCT_PRMBL_SIZE);
    cthdr.revision = tvb_get_guint8 (tvb, offset++);
    cthdr.in_id = tvb_get_ntoh24 (tvb, offset);
    cthdr.opcode = g_ntohs (cthdr.opcode);
    cthdr.maxres_size = g_ntohs (cthdr.maxres_size);

    if (check_col (pinfo->cinfo, COL_INFO)) {
        if (cthdr.opcode < FCCT_MSG_REQ_MAX) {
            col_append_str (pinfo->cinfo, COL_INFO, " Request");
        }
        else if (cthdr.opcode == FCCT_MSG_ACC) {
            col_append_str (pinfo->cinfo, COL_INFO, " Accept");
        }
        else if (cthdr.opcode == FCCT_MSG_RJT) {
            col_append_fstr (pinfo->cinfo, COL_INFO, " Reject (%s)",
                             val_to_str (cthdr.rjt_code, fc_ct_rjt_code_vals, "0x%x"));
        }
        else {
            col_append_str (pinfo->cinfo, COL_INFO, " Reserved");
        }
    }

    in_id = cthdr.in_id;
    in_id = g_htonl (in_id) >> 8;

    /* Determine server */
    server = get_gs_server (cthdr.gstype, cthdr.gssubtype);

    if (tree) {
        offset = 0;
        ti = proto_tree_add_protocol_format (tree, proto_fcct, tvb, 0, FCCT_PRMBL_SIZE,
                                             "FC_CT");
        fcct_tree = proto_item_add_subtree (ti, ett_fcct);

        proto_tree_add_item (fcct_tree, hf_fcct_revision, tvb, offset++,
                             sizeof (guint8), ENC_BIG_ENDIAN);
        proto_tree_add_string (fcct_tree, hf_fcct_inid, tvb, offset, 3,
                               fc_to_str ((guint8 *)&in_id));
        offset += 3; /* sizeof FC address */

        proto_tree_add_item (fcct_tree, hf_fcct_gstype, tvb, offset++,
                             sizeof (guint8), ENC_BIG_ENDIAN);
        proto_tree_add_item (fcct_tree, hf_fcct_gssubtype, tvb, offset,
                             sizeof (guint8), ENC_BIG_ENDIAN);
        proto_tree_add_uint (fcct_tree, hf_fcct_server, tvb, offset++, 1,
                             server);
        proto_tree_add_item (fcct_tree, hf_fcct_options, tvb, offset++,
                             sizeof (guint8), ENC_BIG_ENDIAN);

    }
    /* We do not change the starting offset for the next protocol in the
     * chain since the fc_ct header is common to the sub-protocols.
     */
    next_tvb = tvb_new_subset_remaining (tvb, 0);
    if (!dissector_try_uint (fcct_gserver_table, server, next_tvb, pinfo,
                             tree)) {
        call_dissector (data_handle, next_tvb, pinfo, tree);
    }
}

/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_fcct(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_fcct_revision,
          {"Revision", "fcct.revision", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_fcct_inid,
          {"IN_ID", "fcct.in_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_fcct_gstype,
          {"GS Type", "fcct.gstype", FT_UINT8, BASE_HEX, VALS(fc_ct_gstype_vals),
           0x0, NULL, HFILL}},
        { &hf_fcct_gssubtype,
          {"GS Subtype", "fcct.gssubtype", FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcct_server,
          {"Server", "fcct.server", FT_UINT8, BASE_HEX,
           VALS (fc_ct_gsserver_vals), 0x0,
           "Derived from GS Type & Subtype fields", HFILL}},
        { &hf_fcct_options,
          {"Options", "fcct.options", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcct_ext_said,
          {"Auth SAID", "fcct.ext_said", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcct_ext_tid,
          {"Transaction ID", "fcct.ext_tid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcct_ext_reqname,
          {"Requestor Port Name", "fcct.ext_reqnm", FT_BYTES, BASE_NONE, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcct_ext_tstamp,
          {"Timestamp", "fcct.ext_tstamp", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcct_ext_authblk,
          {"Auth Hash Blk", "fcct.ext_authblk", FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_fcct,
        &ett_fcct_ext,
    };

    /* Register the protocol name and description */
    proto_fcct = proto_register_protocol("Fibre Channel Common Transport", "FC_CT", "fcct");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_fcct, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    fcct_gserver_table = register_dissector_table ("fcct.server",
                                                   "Server",
                                                   FT_UINT8, BASE_HEX);
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_fcct (void)
{
    dissector_handle_t fcct_handle;

    fcct_handle = create_dissector_handle (dissect_fcct, proto_fcct);
    dissector_add_uint("fc.ftype", FC_FTYPE_FCCT, fcct_handle);

    data_handle = find_dissector ("data");
}


