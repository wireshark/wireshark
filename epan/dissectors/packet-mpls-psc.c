/* packet-mpls-psc.c
 *
 * Routines for MPLS[-TP] Protection State Coordination (PSC) Protocol: it 
 * should conform to RFC 6378.
 *
 * Copyright 2012 _FF_
 *
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
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
#include <stdio.h>
#include <glib.h>

#include <epan/packet.h>
#include <packet-ip.h>

static gint proto_mpls_psc = -1;

static gint ett_mpls_psc = -1;

static int hf_mpls_psc_ver = -1;
static int hf_mpls_psc_req = -1;
static int hf_mpls_psc_pt = -1;
static int hf_mpls_psc_rev = -1;
static int hf_mpls_psc_fpath = -1;
static int hf_mpls_psc_dpath = -1;
static int hf_mpls_psc_tlvlen = -1;

static dissector_handle_t mpls_psc_handle;

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/mpls-oam-parameters/mpls-oam-parameters.xml
 * Registry Name: 'MPLS PSC Request'
 */
const range_string mpls_psc_req_rvals[] = {
    {  0,  0, "No Request"            },
    {  1,  1, "Do Not Revert"         },
    {  2,  3, "Unassigned"            },
    {  4,  4, "Wait to Restore"       },
    {  5,  5, "Manual Switch"         },
    {  6,  6, "Unassigned"            },
    {  7,  7, "Signal Degrade"        },
    {  8,  9, "Unassigned"            },
    { 10, 10, "Signal Fail"           },
    { 11, 11, "Unassigned"            },
    { 12, 12, "Forced Switch"         },
    { 13, 13, "Unassigned"            },
    { 14, 14, "Lockout of protection" },
    { 15, 15, "Unassigned"            },
    { 0,   0, NULL                    }
};

const value_string mpls_psc_req_short_vals[] = {
    {  0, "NR"  },
    {  1, "DNR" },
    {  4, "WTR" },
    {  5, "MS"  },
    {  7, "SD"  },
    { 10, "SF"  },
    { 12, "FS"  },
    { 14, "LO"  },
    {  0, NULL  }
};

const range_string mpls_psc_pt_rvals[] = {
    { 0, 0, "for future extensions"                             },
    { 1, 1, "unidirectional switching using a permanent bridge" },
    { 2, 2, "bidirectional switching using a selector bridge"   },
    { 3, 3, "bidirectional switching using a permanent bridge"  },
    { 0, 0, NULL                                                }
};

const range_string mpls_psc_rev_rvals[] = {
    { 0, 0, "non-revertive mode" },
    { 1, 1, "revertive mode"     },
    { 0, 0, NULL                 }
};

const range_string mpls_psc_fpath_rvals[] = {
    { 0,   0, "protection"            },
    { 1,   1, "working"               },
    { 2, 255, "for future extensions" },
    { 0,   0, NULL                    }
};

const range_string mpls_psc_dpath_rvals[] = {
    { 0,   0, "protection is not in use" },
    { 1,   1, "protection is in use"     },
    { 2, 255, "for future extensions"    },
    { 0,   0, NULL                       }
};

static void
dissect_mpls_psc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *psc_tree = NULL;
    guint32 offset = 0;
    guint8 req = 0;
    guint8 fpath = 0;
    guint8 path = 0;

    /* build cinfo */
    req = (tvb_get_guint8(tvb, offset) & 0x3C) >> 2;
    fpath = tvb_get_guint8(tvb, offset + 2);
    path = tvb_get_guint8(tvb, offset + 3);

    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_clear(pinfo->cinfo, COL_INFO);

    col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "PSC");

    col_add_fstr(pinfo->cinfo, COL_INFO,
                 "%s(%u,%u)",
                 val_to_str(req, mpls_psc_req_short_vals, "Unknown-Request"),
                 fpath, path);

    if (!tree) {
        return;
    }
    
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_mpls_psc, tvb, 0, -1, ENC_NA);
    psc_tree = proto_item_add_subtree(ti, ett_mpls_psc);
    /* version */
    proto_tree_add_item(psc_tree, hf_mpls_psc_ver, tvb, offset, 1, ENC_NA);
    /* request */
    proto_tree_add_item(psc_tree, hf_mpls_psc_req, tvb, offset, 1, ENC_NA);
    /* prot type */
    proto_tree_add_item(psc_tree, hf_mpls_psc_pt, tvb, offset, 1, ENC_NA);
    offset += 1;
    /* prot type */
    proto_tree_add_item(psc_tree, hf_mpls_psc_rev, tvb, offset, 1, ENC_NA);
    /* skip reserved1 */
    offset += 1;
    /* fpath */
    proto_tree_add_item(psc_tree, hf_mpls_psc_fpath, tvb, offset, 1, ENC_NA);
    offset += 1;
    /* path */
    proto_tree_add_item(psc_tree, hf_mpls_psc_dpath, tvb, offset, 1, ENC_NA);
    offset += 1;
    /* tlv len */
    proto_tree_add_item(psc_tree, hf_mpls_psc_tlvlen, tvb, offset, 1, 
                        ENC_BIG_ENDIAN);
}

void
proto_register_mpls_psc(void)
{
    static hf_register_info hf[] = {
        {
            &hf_mpls_psc_ver,
            {
                "Version", "mpls.psc.ver", FT_UINT8, BASE_DEC, NULL,
                0xC0, NULL, HFILL
            }
        },
        {
            &hf_mpls_psc_req,
            {
                "Request", "mpls.psc.req", FT_UINT8, 
                BASE_RANGE_STRING | BASE_DEC,
                RVALS(&mpls_psc_req_rvals), 
                0x3C, NULL, HFILL
            }
        },
        {
            &hf_mpls_psc_pt,
            {
                "Protection Type", "mpls.psc.pt", FT_UINT8,
                BASE_RANGE_STRING | BASE_DEC,
                RVALS(&mpls_psc_pt_rvals),  
                0x03, NULL, HFILL
            }
        },
        {
            &hf_mpls_psc_rev,
            {
                "R", "mpls.psc.rev", FT_UINT8,
                BASE_RANGE_STRING | BASE_DEC,
                RVALS(&mpls_psc_rev_rvals), 
                0x80, NULL, HFILL
            }
        },
        {
            &hf_mpls_psc_fpath,
            {
                "Fault Path", "mpls.psc.fpath", FT_UINT8,
                BASE_RANGE_STRING | BASE_DEC,
                RVALS(&mpls_psc_fpath_rvals), 
                0x0, NULL, HFILL
            }
        },
        {
            &hf_mpls_psc_dpath,
            {
                "Data Path", "mpls.psc.dpath", FT_UINT8,
                BASE_RANGE_STRING | BASE_DEC,
                RVALS(&mpls_psc_dpath_rvals),
                0x0, NULL, HFILL
            }
        },
        {
            &hf_mpls_psc_tlvlen,
            {
                "TLV Length", "mpls.psc.tlvlen", FT_UINT16, BASE_DEC, NULL, 
                0x0, NULL, HFILL
            }
        },
    };

    static gint *ett[] = {
        &ett_mpls_psc,
    };

    proto_mpls_psc =
        proto_register_protocol("PSC", "MPLS[-TP] Protection State "
                                "Coordination (PSC) Protocol",
                                "mplspsc");

    proto_register_field_array(proto_mpls_psc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("mpls_psc", dissect_mpls_psc, proto_mpls_psc);
}

void
proto_reg_handoff_mpls_psc(void)
{
    mpls_psc_handle =
        create_dissector_handle(dissect_mpls_psc, proto_mpls_psc);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
