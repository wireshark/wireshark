/* packet-tte-pcf.c
 * Routines for Time Triggered Ethernet Protocol Control Frame dissection
 *
 * Author: Valentin Ecker
 * Author: Benjamin Roch, benjamin.roch (AT) tttech.com
 *
 * TTTech Computertechnik AG, Austria.
 * http://www.tttech.com/solutions/ttethernet/
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/etypes.h>

#include "packet-tte.h"

/* Initialize the protocol and registered fields */
static int proto_tte_pcf = -1;

static int hf_tte_pcf = -1;
static int hf_tte_pcf_ic = -1;
static int hf_tte_pcf_mn = -1;
static int hf_tte_pcf_res0 = -1;
static int hf_tte_pcf_sp = -1;
static int hf_tte_pcf_sd = -1;
static int hf_tte_pcf_type = -1;
static int hf_tte_pcf_res1 = -1;
static int hf_tte_pcf_tc = -1;

/* Initialize the subtree pointers */
static gint ett_tte_pcf = -1;

static const value_string pcf_type_str_vals[] =
    { {2, "integration frame"}
    , {4, "coldstart frame"}
    , {8, "coldstart ack frame"}
    , {0, NULL}
    };


/* Code to actually dissect the packets */
static void
dissect_tte_pcf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *tte_pcf_root_item;
    proto_tree *tte_pcf_tree;

    /* variables used to store the fields displayed in the info_column */
    guint8 sync_priority = 0;
    guint8 sync_domain   = 0;

    /* Check that there's enough data */
    if (tvb_length(tvb) < TTE_PCF_LENGTH )
    {
        return;
    }

    /* get sync_priority and sync_domain */
    sync_priority = tvb_get_guint8(tvb, TTE_PCF_IC_LENGTH+TTE_PCF_MN_LENGTH+
        TTE_PCF_RES0_LENGTH);
    sync_domain = tvb_get_guint8(tvb, TTE_PCF_IC_LENGTH+TTE_PCF_MN_LENGTH+
        TTE_PCF_RES0_LENGTH+TTE_PCF_SP_LENGTH);

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCF");

    col_add_fstr(pinfo->cinfo, COL_INFO,
            "Sync Domain: 0x%02X  Sync Priority: 0x%02X",
            sync_domain, sync_priority);

    if (tree) {

        /* create display subtree for the protocol */
        tte_pcf_root_item = proto_tree_add_item(tree, proto_tte_pcf, tvb, 0,
            TTE_PCF_LENGTH, ENC_NA);

        tte_pcf_tree = proto_item_add_subtree(tte_pcf_root_item, ett_tte_pcf);

        proto_tree_add_item(tte_pcf_tree,
            hf_tte_pcf_ic, tvb, 0, TTE_PCF_IC_LENGTH, ENC_BIG_ENDIAN);

        proto_tree_add_item(tte_pcf_tree,
            hf_tte_pcf_mn, tvb, TTE_PCF_IC_LENGTH, TTE_PCF_MN_LENGTH, ENC_BIG_ENDIAN);

     /* RESERVED FIELD --- will not be displayed */
     /* proto_tree_add_item(tte_pcf_tree,
            hf_tte_pcf_res0, tvb, TTE_PCF_IC_LENGTH+TTE_PCF_MN_LENGTH,
            TTE_PCF_RES0_LENGTH, ENC_BIG_ENDIAN); */

        proto_tree_add_item(tte_pcf_tree,
            hf_tte_pcf_sp, tvb, TTE_PCF_IC_LENGTH+TTE_PCF_MN_LENGTH+
            TTE_PCF_RES0_LENGTH, TTE_PCF_SP_LENGTH, ENC_BIG_ENDIAN);

        proto_tree_add_item(tte_pcf_tree,
            hf_tte_pcf_sd, tvb, TTE_PCF_IC_LENGTH+TTE_PCF_MN_LENGTH+
            TTE_PCF_RES0_LENGTH+TTE_PCF_SP_LENGTH, TTE_PCF_SD_LENGTH, ENC_BIG_ENDIAN);

        proto_tree_add_item(tte_pcf_tree,
            hf_tte_pcf_type, tvb, TTE_PCF_IC_LENGTH+TTE_PCF_MN_LENGTH+
            TTE_PCF_RES0_LENGTH+TTE_PCF_SP_LENGTH+TTE_PCF_SD_LENGTH,
            TTE_PCF_TYPE_LENGTH, ENC_BIG_ENDIAN);

     /* RESERVED FIELD --- will not be displayed */
     /* proto_tree_add_item(tte_pcf_tree,
            hf_tte_pcf_res1, tvb, TTE_PCF_IC_LENGTH+TTE_PCF_MN_LENGTH+
            TTE_PCF_RES0_LENGTH+TTE_PCF_SP_LENGTH+TTE_PCF_SD_LENGTH+
            TTE_PCF_TYPE_LENGTH, TTE_PCF_RES1_LENGTH, ENC_NA); */

        proto_tree_add_item(tte_pcf_tree,
            hf_tte_pcf_tc, tvb, TTE_PCF_IC_LENGTH+TTE_PCF_MN_LENGTH+
            TTE_PCF_RES0_LENGTH+TTE_PCF_SP_LENGTH+TTE_PCF_SD_LENGTH+
            TTE_PCF_TYPE_LENGTH+TTE_PCF_RES1_LENGTH, TTE_PCF_TC_LENGTH, ENC_BIG_ENDIAN);
    }

}


void
proto_register_tte_pcf(void)
{
    static hf_register_info hf[] = {

        { &hf_tte_pcf,
            { "Protocol Control Frame", "tte.pcf",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tte_pcf_ic,
            { "Integration Cycle", "tte.pcf.ic",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
            { &hf_tte_pcf_mn,
            { "Membership New", "tte.pcf.mn",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
            { &hf_tte_pcf_res0,
            { "Reserved 0", "tte.pcf.res0",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tte_pcf_sp,
            { "Sync Priority", "tte.pcf.sp",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tte_pcf_sd,
            { "Sync Domain", "tte.pcf.sd",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tte_pcf_type,
            { "Type", "tte.pcf.type",
            FT_UINT8, BASE_HEX, VALS(pcf_type_str_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_tte_pcf_res1,
            { "Reserved 1", "tte.pcf.res1",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tte_pcf_tc,
            { "Transparent Clock", "tte.pcf.tc",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_tte_pcf
    };

    /* Register the protocol name and description */
    proto_tte_pcf = proto_register_protocol("TTEthernet Protocol Control Frame",
        "TTE PCF", "tte_pcf");

    /* Required function calls to register header fields and subtrees used */
    proto_register_field_array(proto_tte_pcf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("tte_pcf", dissect_tte_pcf, proto_tte_pcf);

}


void
proto_reg_handoff_tte_pcf(void)
{
    dissector_handle_t tte_pcf_handle;

    /* initialize the pcf handle */
    tte_pcf_handle = find_dissector("tte_pcf");

    dissector_add_uint("ethertype", ETHERTYPE_TTE_PCF, tte_pcf_handle);

}

