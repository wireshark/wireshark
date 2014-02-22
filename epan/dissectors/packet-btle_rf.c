/* packet-btle_rf.c
 * http://www.whiterocker.com/bt/LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR.html
 *
 * Copyright 2014, Christopher D. Kilgour, techie at whiterocker dot com
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

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>

#include "packet-btle.h"

#define LE_DEWHITENED        0x0001
#define LE_SIGPOWER_VALID    0x0002
#define LE_NOISEPOWER_VALID  0x0004
#define LE_PACKET_DECRYPTED  0x0008
#define LE_REF_AA_VALID      0x0010
#define LE_AA_OFFENSES_VALID 0x0020
#define LE_CHANNEL_ALIASED   0x0040
#define LE_CRC_CHECKED       0x0400
#define LE_CRC_VALID         0x0800
#define LE_MIC_CHECKED       0x1000
#define LE_MIC_VALID         0x2000

#define BTLE_RF_OCTETS 10

static int proto_btle_rf = -1;

static int hf_btle_rf_signed_byte_unused = -1;
static int hf_btle_rf_unsigned_byte_unused = -1;
static int hf_btle_rf_word_unused = -1;
static int hf_btle_rf_channel = -1;
static int hf_btle_rf_signal_dbm = -1;
static int hf_btle_rf_noise_dbm = -1;
static int hf_btle_rf_access_address_offenses = -1;
static int hf_btle_rf_reference_access_address = -1;
static int hf_btle_rf_flags = -1;
static int hf_btle_rf_dewhitened_flag = -1;
static int hf_btle_rf_sigpower_valid_flag = -1;
static int hf_btle_rf_noisepower_valid_flag = -1;
static int hf_btle_rf_packet_decrypted_flag = -1;
static int hf_btle_rf_ref_aa_valid_flag = -1;
static int hf_btle_rf_aa_offenses_valid_flag = -1;
static int hf_btle_rf_channel_aliased_flag = -1;
static int hf_btle_rf_flags_rfu_1 = -1;
static int hf_btle_rf_crc_checked_flag = -1;
static int hf_btle_rf_crc_valid_flag = -1;
static int hf_btle_rf_mic_checked_flag = -1;
static int hf_btle_rf_mic_valid_flag = -1;
static int hf_btle_rf_flags_rfu_2 = -1;

static int ett_btle_rf = -1;
static int ett_btle_rf_flags = -1;

static dissector_handle_t btle_rf_handle;
static dissector_handle_t btle_handle;

void proto_register_btle_rf(void);
void proto_reg_handoff_btle_rf(void);

static const char *
btle_rf_channel_type(guint8 rf_channel)
{
    if (rf_channel <= 39) {
        switch(rf_channel) {
        case 0:
        case 12:
        case 39:
            return "Advertising channel";
        default:
            return "Data channel";
        }
    }
    return "Illegal channel";
}

static guint8
btle_rf_channel_index(guint8 rf_channel)
{
    if (rf_channel <= 39) {
        if (rf_channel == 39) {
            return 39;
        }
        else if (rf_channel >= 13) {
            return rf_channel - 2;
        }
        else if (rf_channel == 12) {
            return 38;
        }
        else if (rf_channel >= 1) {
            return rf_channel - 1;
        }
        else {
            return 37;
        }
    }
    return (guint8) -1;
}

static gint
dissect_btle_rf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BTLE RF");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree && (tvb_captured_length(tvb) >= BTLE_RF_OCTETS)) {
        proto_item *ti = NULL;
        proto_tree *btle_rf_tree = NULL;
        proto_tree *btle_rf_flags_tree = NULL;
        tvbuff_t *btle_tvb;
        btle_context_t context;
        guint8 rf_channel  = tvb_get_guint8(tvb, 0);
        guint8 aa_offenses = tvb_get_guint8(tvb, 3);
        guint16 flags      = tvb_get_letohs(tvb, 8);

        context.aa_category            = E_AA_NO_COMMENT;
        context.connection_info_valid  = 0; /* TODO */
        context.crc_checked_at_capture = !!(flags & LE_CRC_CHECKED);
        context.crc_valid_at_capture   = !!(flags & LE_CRC_VALID);
        context.mic_checked_at_capture = !!(flags & LE_MIC_CHECKED);
        context.mic_valid_at_capture   = !!(flags & LE_MIC_VALID);

        ti = proto_tree_add_item(tree, proto_btle_rf, tvb, 0, tvb_captured_length(tvb), ENC_NA);
        btle_rf_tree = proto_item_add_subtree(ti, ett_btle_rf);
        ti = proto_tree_add_item(btle_rf_tree, hf_btle_rf_channel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
        proto_item_append_text(ti, ", %d MHz, %s %d", 2402+2*rf_channel,
                               btle_rf_channel_type(rf_channel),
                               btle_rf_channel_index(rf_channel));
        if (flags & LE_CHANNEL_ALIASED) {
            proto_item_append_text(ti, " [aliased]");
        }
        if (flags & LE_SIGPOWER_VALID) {
            proto_tree_add_item(btle_rf_tree, hf_btle_rf_signal_dbm, tvb, 1, 1, ENC_LITTLE_ENDIAN);
        }
        else {
            proto_tree_add_item(btle_rf_tree, hf_btle_rf_signed_byte_unused, tvb, 1, 1, ENC_LITTLE_ENDIAN);
        }
        if (flags & LE_NOISEPOWER_VALID) {
            proto_tree_add_item(btle_rf_tree, hf_btle_rf_noise_dbm, tvb, 2, 1, ENC_LITTLE_ENDIAN);
        }
        else {
            proto_tree_add_item(btle_rf_tree, hf_btle_rf_signed_byte_unused, tvb, 2, 1, ENC_LITTLE_ENDIAN);
        }
        if (flags & LE_REF_AA_VALID) {
            proto_tree_add_item(btle_rf_tree, hf_btle_rf_reference_access_address, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        }
        else {
            proto_tree_add_item(btle_rf_tree, hf_btle_rf_word_unused, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        }
        if (flags & LE_AA_OFFENSES_VALID) {
            proto_tree_add_item(btle_rf_tree, hf_btle_rf_access_address_offenses, tvb, 3, 1, ENC_LITTLE_ENDIAN);
            if (aa_offenses > 0) {
                if (flags & LE_REF_AA_VALID) {
                    context.aa_category = E_AA_BIT_ERRORS;
                }
                else {
                    context.aa_category = E_AA_ILLEGAL;
                }
            }
            else if (flags & LE_REF_AA_VALID) {
                context.aa_category = E_AA_MATCHED;
            }
        }
        else {
            proto_tree_add_item(btle_rf_tree, hf_btle_rf_unsigned_byte_unused, tvb, 3, 1, ENC_LITTLE_ENDIAN);
        }
        ti = proto_tree_add_item(btle_rf_tree, hf_btle_rf_flags, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        btle_rf_flags_tree = proto_item_add_subtree(ti, ett_btle_rf_flags);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_dewhitened_flag, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_sigpower_valid_flag, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_noisepower_valid_flag, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_packet_decrypted_flag, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_ref_aa_valid_flag, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_aa_offenses_valid_flag, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_channel_aliased_flag, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_flags_rfu_1, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_crc_checked_flag, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_crc_valid_flag, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_mic_checked_flag, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_mic_valid_flag, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btle_rf_flags_tree, hf_btle_rf_flags_rfu_2, tvb, 8, 2, ENC_LITTLE_ENDIAN);

        btle_tvb = tvb_new_subset_remaining(tvb, BTLE_RF_OCTETS);
        return BTLE_RF_OCTETS+call_dissector_with_data(btle_handle, btle_tvb, pinfo, tree, &context);
    }
    return 0;
}

void
proto_register_btle_rf(void)
{
    static hf_register_info hf[] = {
        { &hf_btle_rf_signed_byte_unused,
          { "Unused signed byte", "btle_rf.signed_byte_unused",
            FT_INT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_rf_unsigned_byte_unused,
          { "Unused unsigned byte", "btle_rf.unsigned_byte_unused",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_rf_word_unused,
          { "Unused word", "btle_rf.word_unused",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_rf_channel,
          { "RF Channel", "btle_rf.channel",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_rf_signal_dbm,
          { "Signal dBm", "btle_rf.signal_dbm",
            FT_INT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_rf_noise_dbm,
          { "Noise dBm", "btle_rf.noise_dbm",
            FT_INT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_rf_access_address_offenses,
          { "Access Address Offenses", "btle_rf.access_address_offenses",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_rf_reference_access_address,
          { "Reference Access Address", "btle_rf.reference_access_address",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_rf_flags,
          { "Flags", "btle_rf.flags",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_rf_dewhitened_flag,
          { "Dewhitened", "btle_rf.flags.dewhitened",
            FT_BOOLEAN, 16,
            NULL, LE_DEWHITENED,
            NULL, HFILL }
        },
        { &hf_btle_rf_sigpower_valid_flag,
          { "Signal Power Valid", "btle_rf.flags.signal_dbm_valid",
            FT_BOOLEAN, 16,
            NULL, LE_SIGPOWER_VALID,
            NULL, HFILL }
        },
        { &hf_btle_rf_noisepower_valid_flag,
          { "Noise Power Valid", "btle_rf.flags.noise_dbm_valid",
            FT_BOOLEAN, 16,
            NULL, LE_NOISEPOWER_VALID,
            NULL, HFILL }
        },
        { &hf_btle_rf_packet_decrypted_flag,
          { "Decrypted", "btle_rf.flags.decrypted",
            FT_BOOLEAN, 16,
            NULL, LE_PACKET_DECRYPTED,
            NULL, HFILL }
        },
        { &hf_btle_rf_ref_aa_valid_flag,
          { "Reference Access Address Valid",
            "btle_rf.flags.reference_access_address_valid",
            FT_BOOLEAN, 16,
            NULL, LE_REF_AA_VALID,
            NULL, HFILL }
        },
        { &hf_btle_rf_aa_offenses_valid_flag,
          { "Access Address Offenses Valid",
            "btle_rf.flags.access_address_offenses_valid",
            FT_BOOLEAN, 16,
            NULL, LE_AA_OFFENSES_VALID,
            NULL, HFILL }
        },
        { &hf_btle_rf_channel_aliased_flag,
          { "Channel Aliased", "btle_rf.flags.channel_aliased",
            FT_BOOLEAN, 16,
            NULL, LE_CHANNEL_ALIASED,
            NULL, HFILL }
        },
        { &hf_btle_rf_flags_rfu_1,
          { "RFU", "btle_rf.flags.rfu.1",
            FT_UINT16, BASE_DEC, NULL, 0x380,
            NULL, HFILL }
        },
        { &hf_btle_rf_crc_checked_flag,
          { "CRC Checked", "btle_rf.flags.crc_checked",
            FT_BOOLEAN, 16,
            NULL, LE_CRC_CHECKED,
            NULL, HFILL }
        },
        { &hf_btle_rf_crc_valid_flag,
          { "CRC Valid", "btle_rf.flags.crc_valid",
            FT_BOOLEAN, 16,
            NULL, LE_CRC_VALID,
            NULL, HFILL }
        },
        { &hf_btle_rf_mic_checked_flag,
          { "MIC Checked", "btle_rf.flags.mic_checked",
            FT_BOOLEAN, 16,
            NULL, LE_MIC_CHECKED,
            NULL, HFILL }
        },
        { &hf_btle_rf_mic_valid_flag,
          { "MIC Valid", "btle_rf.flags.mic_valid",
            FT_BOOLEAN, 16,
            NULL, LE_MIC_VALID,
            NULL, HFILL }
        },
        { &hf_btle_rf_flags_rfu_2,
          { "RFU", "btle_rf.flags.rfu.2",
            FT_UINT16, BASE_DEC, NULL, 0xc000,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_btle_rf,
        &ett_btle_rf_flags,
    };

    proto_btle_rf = proto_register_protocol("Bluetooth Low Energy RF Info",
                                            "BTLE RF", "btle_rf");
    proto_register_field_array(proto_btle_rf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    btle_rf_handle = new_register_dissector("btle_rf", dissect_btle_rf, proto_btle_rf);
}

void
proto_reg_handoff_btle_rf(void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR, btle_rf_handle);
    btle_handle = find_dissector("btle");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
