/* packet-rfid-mifare.c
 * Dissector for the NXP MiFare Protocol
 *
 * References:
 * http://code.google.com/p/nfc-tools/source/browse/trunk/libfreefare/libfreefare/mifare_classic.c
 * http://www.nxp.com/documents/data_sheet/MF1S703x.pdf
 * http://www.nxp.com/documents/application_note/AN1304.pdf
 *
 * Copyright 2011, Tyson Key <tyson.key@gmail.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

static int proto_mifare = -1;

static int hf_mifare_command = -1;
static int hf_mifare_block_address = -1;
static int hf_mifare_key_a = -1;
static int hf_mifare_key_b = -1;
static int hf_mifare_uid = -1;
static int hf_mifare_operand = -1;

#define AUTH_A    0x60
#define AUTH_B    0x61
#define READ      0x30
#define WRITE     0xA0
#define TRANSFER  0xB0
#define DECREMENT 0xC0
#define INCREMENT 0xC1
#define RESTORE   0xC2

static const value_string hf_mifare_commands[] = {
    {AUTH_A,    "AUTH_A"},
    {AUTH_B,    "AUTH_B"},
    {READ,      "READ"},
    {WRITE,     "WRITE"},
    {TRANSFER,  "TRANSFER"},
    {DECREMENT, "DECREMENT"},
    {INCREMENT, "INCREMENT"},
    {RESTORE,   "RESTORE"},

    /* End of commands */
    {0x00, NULL}
};

static dissector_handle_t data_handle;
static dissector_table_t  mifare_dissector_table;

/* Subtree handles: set by register_subtree_array */
static gint ett_mifare = -1;

static void
dissect_mifare(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item;
    proto_tree *mifare_tree;
    guint8      cmd;
    tvbuff_t   *next_tvb = NULL;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MiFare");
    col_set_str(pinfo->cinfo, COL_INFO, "MiFare Packet");

    if (tree) {
        /* Start with a top-level item to add everything else to */

        item = proto_tree_add_item(tree, proto_mifare, tvb, 0, -1, ENC_NA);
        mifare_tree = proto_item_add_subtree(item, ett_mifare);

        proto_tree_add_item(mifare_tree, hf_mifare_command, tvb, 0, 1, ENC_NA);
        cmd = tvb_get_guint8(tvb, 0);

        switch (cmd) {

        case AUTH_A:
            proto_tree_add_item(mifare_tree, hf_mifare_block_address, tvb, 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mifare_tree, hf_mifare_key_a, tvb, 2, 6, ENC_BIG_ENDIAN);
            proto_tree_add_item(mifare_tree, hf_mifare_uid, tvb, 8, 4, ENC_BIG_ENDIAN);

            col_set_str(pinfo->cinfo, COL_INFO, "Authenticate with Key A");

            break;

        case AUTH_B:
            proto_tree_add_item(mifare_tree, hf_mifare_block_address, tvb, 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mifare_tree, hf_mifare_key_b, tvb, 2, 6, ENC_BIG_ENDIAN);
            proto_tree_add_item(mifare_tree, hf_mifare_uid, tvb, 8, 4, ENC_BIG_ENDIAN);

            col_set_str(pinfo->cinfo, COL_INFO, "Authenticate with Key B");

            break;

        case READ:
            proto_tree_add_item(mifare_tree, hf_mifare_block_address, tvb, 1, 1, ENC_BIG_ENDIAN);

            col_set_str(pinfo->cinfo, COL_INFO, "Read");

            break;

        case WRITE:
            col_set_str(pinfo->cinfo, COL_INFO, "Write");

            /* LibNFC and the TouchATag-branded reader don't expose the 2-byte CRC
               or 4-bit NAK, as per MF1S703x, so we pretend that they don't exist.

               I've never seen traces with those data structures before, either... */

            proto_tree_add_item(mifare_tree, hf_mifare_block_address, tvb, 1, 1, ENC_BIG_ENDIAN);

            /* Because we don't know what the user will write, just let Data have away
               with the rest of the packet's contents for now. */

            next_tvb = tvb_new_subset_remaining(tvb, 2);

            call_dissector(data_handle, next_tvb, pinfo, tree);

            break;

        case TRANSFER:
            proto_tree_add_item(mifare_tree, hf_mifare_block_address, tvb, 1, 1, ENC_BIG_ENDIAN);

            col_set_str(pinfo->cinfo, COL_INFO, "Transfer");

            break;

        case DECREMENT:
            proto_tree_add_item(mifare_tree, hf_mifare_block_address, tvb, 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mifare_tree, hf_mifare_operand, tvb, 2, 4, ENC_BIG_ENDIAN);

            col_set_str(pinfo->cinfo, COL_INFO, "Decrement");

            break;

        case INCREMENT:
            proto_tree_add_item(mifare_tree, hf_mifare_block_address, tvb, 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mifare_tree, hf_mifare_operand, tvb, 2, 4, ENC_BIG_ENDIAN);

            col_set_str(pinfo->cinfo, COL_INFO, "Increment");

            break;

        case RESTORE:
            proto_tree_add_item(mifare_tree, hf_mifare_block_address, tvb, 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mifare_tree, hf_mifare_operand, tvb, 2, 4, ENC_BIG_ENDIAN);

            col_set_str(pinfo->cinfo, COL_INFO, "Restore");

            break;

        default:
            col_set_str(pinfo->cinfo, COL_INFO, "Unknown");

            break;
        }
    }
}

void
proto_register_mifare(void)
{
    static hf_register_info hf[] = {

        {&hf_mifare_command,
         { "Command", "mifare.cmd", FT_UINT8, BASE_HEX,
           VALS(hf_mifare_commands), 0x0, NULL, HFILL }},
        {&hf_mifare_block_address,
         { "Block Address", "mifare.block.addr", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_mifare_key_a,
         { "Key A", "mifare.key.a", FT_UINT64, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_mifare_key_b,
         { "Key B", "mifare.key.b", FT_UINT64, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_mifare_uid,
         { "UID", "mifare.uid", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_mifare_operand,
         { "Operand", "mifare.operand", FT_INT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_mifare
    };

    proto_mifare = proto_register_protocol("NXP MiFare", "MiFare", "mifare");
    proto_register_field_array(proto_mifare, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    mifare_dissector_table = register_dissector_table("mifare.payload",
                                                      "MiFare Payload", FT_UINT8, BASE_DEC);

    register_dissector("mifare", dissect_mifare, proto_mifare);
}

/* Handler registration */
void
proto_reg_handoff_mifare(void)
{
    data_handle = find_dissector("data");
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
