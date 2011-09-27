/* packet-uaudp.c
* Routines for UA/UDP (Universal Alcatel UDP) packet dissection.
* Copyright 2011
*
* $Id$
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
* is a dissector file; if you just copied this from README.developer,
* don't bother with the "Copied from" - you don't even need to put
* in a "Copied from" if you copied an existing dissector, especially
* if the bulk of the code in the new dissector is your code)
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <epan/packet.h>
#include <epan/prefs.h>

/*
* Here are the global variables associated with
* the various user definable characteristics of the dissection
*/

static range_t *global_uaudp_port_range;
static dissector_handle_t uaudp_handle;

#define UAUDP_PORT_RANGE "5001, 32512"


/* Define the UAUDP proto */
static int proto_uaudp = -1;
static dissector_table_t uaudp_dissector_table;

/* Define many header fields for UAUDP */
static int hf_uaudp_opcode = -1;
static int hf_uaudp_expected = -1;
static int hf_uaudp_send = -1;

/*
* Define the trees for UAUDP
* We need one tree for UAUDP itself and one for the pn-rt data status subtree
*/
static int ett_uaudp_header = -1;

/**
* Opcode
*/
static const value_string szUaOpcode[] =
{
    { 0, "Connect" },
    { 1, "Connect ACK" },
    { 2, "Release" },
    { 3, "Release ACK" },
    { 4, "Keepalive" },
    { 5, "Keepalive ACK" },
    { 6, "NACK" },
    { 7, "Data" },
    { 0, NULL }
};

/*
* dissect_uaudp - The dissector for the UA/UDP protocol
*/
static int dissect_uaudp(tvbuff_t *pTvb, packet_info *pInfo, proto_tree *pTree)
{
    gint nLen;
    guint8 u8Opcode;
    proto_item *pUAUDP, *pHeaderSubTree;

    /* PROTOCOL column */
    if(check_col(pInfo->cinfo, COL_PROTOCOL))
        col_set_str(pInfo->cinfo, COL_PROTOCOL, "UAUDP");

    nLen = tvb_length(pTvb);
    u8Opcode = tvb_get_guint8(pTvb, 0);

    /* INFO column */
    if(check_col(pInfo->cinfo, COL_INFO))
        col_set_str(pInfo->cinfo, COL_INFO, val_to_str(u8Opcode, szUaOpcode, "Unknown"));

    if(pTree)
    {
        /* opcode "UA/UDP Protocol, ..." */
        pUAUDP = proto_tree_add_item(pTree, proto_uaudp, pTvb, 0, -1, ENC_BIG_ENDIAN);
        proto_item_append_text(pUAUDP, ", %s (%d)", val_to_str(u8Opcode, szUaOpcode, "Unknown"), u8Opcode);

        pHeaderSubTree = proto_item_add_subtree(pUAUDP, ett_uaudp_header);
        proto_tree_add_item(pHeaderSubTree, hf_uaudp_opcode, pTvb, 0, 1, ENC_BIG_ENDIAN);

        if(u8Opcode == 7)
        {
            int iOffs = 1;

            /* Sequence Number (expected) */
            proto_tree_add_item(pHeaderSubTree, hf_uaudp_expected, pTvb, iOffs, 2, ENC_BIG_ENDIAN);
            iOffs += 2;

            /* Sequence Number (sent) */
            proto_tree_add_item(pHeaderSubTree, hf_uaudp_send, pTvb, iOffs, 2, ENC_BIG_ENDIAN);
            iOffs += 2;

            /* Create the tvbuffer for the next dissector */
            if(nLen > iOffs)
            {
                tvbuff_t *pTvbNext = tvb_new_subset(pTvb, iOffs, -1, -1);
                if(dissector_try_uint(uaudp_dissector_table, 7, pTvbNext, pInfo, pTree))
                    iOffs = nLen;
                return iOffs;
            }
            else
            {
                if(check_col(pInfo->cinfo, COL_INFO))
                    col_append_str(pInfo->cinfo, COL_INFO, " ACK");
            }
        }
    }
    return nLen;
}

/* The registration hand-off routine is called at startup */
static void range_delete_callback(guint32 port)
{
    dissector_delete_uint("udp.port", port, uaudp_handle);
}

static void range_add_callback (guint32 port)
{
    dissector_add_uint("udp.port", port, uaudp_handle);
}

void proto_reg_handoff_uaudp(void)
{
    static range_t *uaudp_port_range;
    static gboolean uaudp_initialized = FALSE;

    if (!uaudp_initialized)
    {
        uaudp_handle = find_dissector("uaudp");
        uaudp_initialized = TRUE;
    }
    else
    {
        range_foreach(uaudp_port_range, range_delete_callback);
        g_free(uaudp_port_range);
    }

    uaudp_port_range = range_copy(global_uaudp_port_range);
    range_foreach(uaudp_port_range, range_add_callback);
}

/* Register all the bits needed by the filtering engine */
void proto_register_uaudp(void)
{
    static hf_register_info hf[] =
    {
        { &hf_uaudp_opcode,
            { "Opcode", "uaudp.opcode",
                FT_UINT8, BASE_DEC, VALS(szUaOpcode), 0x0,
                "UA/UDP Opcode", HFILL }
        },
        { &hf_uaudp_expected,
            { "Sequence Number (expected)", "uaudp.expected",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uaudp_send,
            { "Sequence Number (sent)", "uaudp.sent",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        }
    };
    static gint *ett[] =
    {
        &ett_uaudp_header,
    };

    module_t* uaudp_module;

    proto_uaudp = proto_register_protocol("Universal Alcatel UDP Protocol", "UAUDP", "uaudp");

    proto_register_field_array(proto_uaudp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    new_register_dissector("uaudp", dissect_uaudp, proto_uaudp);

    /* Register our configuration options */
    range_convert_str(&global_uaudp_port_range, UAUDP_PORT_RANGE, MAX_UDP_PORT);

    uaudp_module = prefs_register_protocol(proto_uaudp, proto_reg_handoff_uaudp);
    prefs_register_range_preference(uaudp_module, "udp_ports",
        "UAUDP port numbers",
        "Port numbers used for UAUDP traffic "
        "(default " UAUDP_PORT_RANGE ")",
        &global_uaudp_port_range, MAX_UDP_PORT);

    uaudp_dissector_table = register_dissector_table("uaudp.opcode", "UA/UDP Opcode", FT_UINT8, BASE_DEC);
}
/*
* Editor modelines - http://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
