/* packet-uaudp.c
 * Routines for UA/UDP (Universal Alcatel UDP) packet dissection.
 * Copyright 2011, Marek Tews <marek@trx.com.pl>
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

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-ua.h"

static gboolean use_heuristic_dissector = TRUE;
static range_t *global_uaudp_port_range = NULL;

/* Define the UAUDP proto */
static int proto_uaudp = -1;
static dissector_handle_t uaudp_handle;
static dissector_table_t uaudp_dissector_table;

/* Define many header fields for UAUDP */
static int hf_uaudp_opcode = -1;
static int hf_uaudp_expected = -1;
static int hf_uaudp_send = -1;

/*
* Define the trees for UAUDP
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
static int
dissect_uaudp(tvbuff_t *pTvb, packet_info *pInfo, proto_tree *pTree)
{
    gint   nLen;
    guint8 u8Opcode;
    proto_item *pUAUDP, *pHeaderSubTree;

    /* PROTOCOL column */
    col_set_str(pInfo->cinfo, COL_PROTOCOL, "UAUDP");

    nLen = tvb_reported_length(pTvb);
    u8Opcode = tvb_get_guint8(pTvb, 0);

    /* INFO column */
    col_set_str(pInfo->cinfo, COL_INFO, val_to_str_const(u8Opcode, szUaOpcode, "Unknown"));

    /* opcode "UA/UDP Protocol, ..." */
    pUAUDP = proto_tree_add_item(pTree, proto_uaudp, pTvb, 0, -1, ENC_NA);
    proto_item_append_text(pUAUDP, ", %s (%d)", val_to_str_const(u8Opcode, szUaOpcode, "Unknown"), u8Opcode);

    pHeaderSubTree = proto_item_add_subtree(pUAUDP, ett_uaudp_header);
    proto_tree_add_item(pHeaderSubTree, hf_uaudp_opcode, pTvb, 0, 1, ENC_BIG_ENDIAN);

    switch(u8Opcode)
    {
    case 6:
        {
            /* Sequence Number (expected) */
            proto_tree_add_item(pHeaderSubTree, hf_uaudp_expected, pTvb, 1, 2, ENC_BIG_ENDIAN);
            break;
        }
    case 7:
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
                if(dissector_try_uint(uaudp_dissector_table, 7, tvb_new_subset_remaining(pTvb, iOffs), pInfo, pTree))
                    iOffs = nLen;
                return iOffs;
            }
            else
            {
                col_append_str(pInfo->cinfo, COL_INFO, " ACK");
            }
            break;
        }
    }
    return nLen;
}

/*
 * UAUDP-over-UDP
 */
static gboolean
dissect_uaudp_heur(tvbuff_t *pTvb, packet_info *pInfo, proto_tree *pTree)
{
    guint8 u8Opcode;

    if(!use_heuristic_dissector)
        return FALSE;

    /* The opcode must be in range */
    u8Opcode = tvb_get_guint8(pTvb, 0);
    if(u8Opcode > 7)
        return FALSE;

    /* The minimum length of a UAUDP message */
    switch(u8Opcode)
    {
    case 4:
    case 5:
        {
            if(tvb_reported_length(pTvb) != 1)
                return FALSE;
            break;
        }
    case 6:
        {
            if(tvb_reported_length(pTvb) != 3)
                return FALSE;
            break;
        }
    case 7:
        {
            guint nLen = tvb_reported_length(pTvb);
            if(nLen < 5)
                return FALSE;

            if(nLen > 5 && !is_ua(tvb_new_subset_remaining(pTvb, 5)))
                return FALSE;

            break;
        }
    /*
     * There I met with other opcodes
     * and do not know how much data is transmitted.
     */
    default: return FALSE;
    }

    dissect_uaudp(pTvb, pInfo, pTree);
    return TRUE;
}

/* Register all the bits needed by the filtering engine */
void proto_reg_handoff_uaudp(void);

void
proto_register_uaudp(void)
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
    uaudp_module = prefs_register_protocol(proto_uaudp, proto_reg_handoff_uaudp);
    prefs_register_bool_preference(uaudp_module, "use_heuristic_dissector",
        "Use heuristic dissector",
        "Use to decode a packet a heuristic dissector. "
        "Otherwise, they are decoded only those packets that will come from the specified ports.",
        &use_heuristic_dissector);
    prefs_register_range_preference(uaudp_module, "udp_ports",
        "UAUDP port numbers",
        "Port numbers used for UAUDP traffic (examples: 5001, 32512)",
        &global_uaudp_port_range, MAX_UDP_PORT);

    uaudp_dissector_table = register_dissector_table("uaudp.opcode", "UA/UDP Opcode", FT_UINT8, BASE_DEC);
}

/* The registration hand-off routine is called at startup */
static void
range_delete_callback(guint32 port)
{
    dissector_delete_uint("udp.port", port, uaudp_handle);
}

static void
range_add_callback (guint32 port)
{
    dissector_add_uint("udp.port", port, uaudp_handle);
}

void
proto_reg_handoff_uaudp(void)
{
    static range_t *uaudp_port_range  = NULL;
    static gboolean uaudp_initialized = FALSE;

    if (!uaudp_initialized)
    {
        /*
         * For UAUDP-over-UDP.
         */
        heur_dissector_add("udp", dissect_uaudp_heur, proto_uaudp);

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
