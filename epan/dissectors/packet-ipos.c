/* packet-ipos.c
 * Routines for IPOS dissection
 * Copyright 2015, Chuan He <chuan.he@ericsson.com>
 *                 Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This is a dissector for Ericsson IPOS Linux kernel packets' header
 * exchanged between kernel and linecard. All fields are in network byte order.
 * This header follow the Linux cooked-mode capture(SLL) and will call REDBACK
 * dissector.
 *
 * IPOS is the network operating system running on a few Ericsson platforms
 * including SSR 8000 routers, Router 6000 series, and SP routers.
 *
 * Product details for Ericsson's IP Metro and Backhaul routers using IPOS:
 * http://www.ericsson.com/ourportfolio/products/ip-metro-and-backhaul
 *
 */
#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>

void proto_reg_handoff_ipos(void);
void proto_register_ipos(void);

static dissector_handle_t ipos_handle;
static dissector_handle_t redback_handle;

static int proto_ipos = -1;
static int hf_ipos_protocol = -1;
static int hf_ipos_priority = -1;
static int hf_ipos_ppe = -1;
static int hf_ipos_slot = -1;
static gint ett_ipos = -1;

/* static expert_field ei_ipos_protocol = EI_INIT; */

#define LINUX_SLL_P_IPOS_NETIPC	 0x0030	/* IPOS IPC frames to/from AF_IPC module */
#define LINUX_SLL_P_IPOS_RBN     0x0031  /* IPOS IP frames to/from CTX module */
#define LINUX_SLL_P_IPOS_NETLINK 0x0032 /* IPOS data frames to/from AF_RBN_NETLINK module */
#define LINUX_SLL_P_IPOS_XCRP    0x0033 /* IPOS data frames to/from XCRP driver */
#define LINUX_SLL_P_IPOS_ISIS    0x0034 /* IPOS data frames to/from ISIS module */
#define LINUX_SLL_P_IPOS_PAKIO   0x0035 /* IPOS data frames to/from AF_RBN_PAKIO module */

static const value_string prototypenames[] = {
    { 0, "L2 Protocol" },
    { 1, "L3 Protocol" },
    { 2, "Control (IPC) message" },
    { 3, "ISIS packet" },
    { 4, "PAKIO packet" },
    { 0,  NULL }
};

static const value_string ppetypenames[] = {
    { 4,  "Output PPA" },
    { 6,  "Input PPA" },
    { 10, "SPPA" },
    { 0,   NULL }
};

/**
 *   Dissect a buffer containing IPOS kernel packet bit string.
 *
 *   @param tvb   The buffer to dissect.
 *   @param pinfo Packet Info.
 *   @param tree  The protocol tree.
 **/
static int
dissect_ipos(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item	*ti = NULL;
    proto_tree	*ipos_tree = NULL;
    tvbuff_t	*next_tvb;
    int         offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPOS");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        ti = proto_tree_add_item(tree, proto_ipos, tvb, 0, -1, ENC_NA);
        ipos_tree = proto_item_add_subtree(ti, ett_ipos);
        proto_tree_add_item(ipos_tree, hf_ipos_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ipos_tree, hf_ipos_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(ipos_tree, hf_ipos_ppe, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(ipos_tree, hf_ipos_slot, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    if (redback_handle) {
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(redback_handle, next_tvb, pinfo, tree);
    }

    return tvb_reported_length(tvb);
}

void
proto_register_ipos(void)
{
    static hf_register_info hf[] = {
        { &hf_ipos_protocol,
        { "Protocol", "ipos.proto", FT_UINT8, BASE_DEC, VALS(prototypenames), 0xF0,
        NULL, HFILL }},

        { &hf_ipos_priority,
        { "Priority", "ipos.priority", FT_UINT8, BASE_DEC, NULL, 0x0F,
        NULL, HFILL }},

        { &hf_ipos_ppe,
        { "Packet Processing Engine", "ipos.ppe", FT_UINT8, BASE_HEX, VALS(ppetypenames), 0x0,
        NULL, HFILL }},

        { &hf_ipos_slot,
        { "Destination (source) Slot", "ipos.slot", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_ipos
    };

#if 0
    static ei_register_info ei[] = {
        { &ei_ipos_protocol,
        { "ipos.protocol.unknown", PI_PROTOCOL, PI_WARN,
        "Unknown Protocol Data", EXPFILL }}
    };

    expert_module_t* expert_ipos;
#endif

    proto_ipos = proto_register_protocol("IPOS Kernel Packet Protocol", "IPOS", "ipos");
    proto_register_field_array(proto_ipos, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
#if 0
    expert_ipos = expert_register_protocol(proto_ipos);
    expert_register_field_array(expert_ipos, ei, array_length(ei));
#endif
    register_dissector("ipos", dissect_ipos, proto_ipos);
}

void
proto_reg_handoff_ipos(void)
{
    ipos_handle = find_dissector("ipos");
    redback_handle = find_dissector_add_dependency("redback", proto_ipos);

    /*dissector_add_uint("wtap_encap", WTAP_ENCAP_IPOS, ipos_handle); */
    dissector_add_uint("sll.ltype", LINUX_SLL_P_IPOS_NETIPC, ipos_handle);
    dissector_add_uint("sll.ltype", LINUX_SLL_P_IPOS_RBN, ipos_handle);
    dissector_add_uint("sll.ltype", LINUX_SLL_P_IPOS_NETLINK, ipos_handle);
    dissector_add_uint("sll.ltype", LINUX_SLL_P_IPOS_XCRP, ipos_handle);
    dissector_add_uint("sll.ltype", LINUX_SLL_P_IPOS_ISIS, ipos_handle);
    dissector_add_uint("sll.ltype", LINUX_SLL_P_IPOS_PAKIO, ipos_handle);
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
