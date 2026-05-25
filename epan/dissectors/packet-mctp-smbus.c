/* packet-mctp-smbus.c
 * Routines for MCTP over SMBus/I2C transport binding dissection
 * Based on DMTF DSP0237 MCTP SMBus/I2C Transport Binding Specification
 *
 * Copyright 2025, Brandon Chiu
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * MCTP over SMBus/I2C uses SMBus Block Write transactions.  The frame
 * structure (DSP0237 §6.3) as seen by the i2c.message subdissector is:
 *
 *   tvb[0]  Destination Slave Address  [7:1]=addr, [0]=R/W#=0
 *   tvb[1]  Command Code               0x0F (MCTP-assigned)
 *   tvb[2]  Byte Count                 counts tvb[3]..last data byte, excl. PEC
 *   tvb[3]  Source Slave Address       [7:1]=addr, [0]=MCTP flag (must be 1)
 *   tvb[4]  MCTP Header Version        [7:4]=rsvd, [3:0]=0x01  <- MCTP base hdr
 *   tvb[5]  Destination EID
 *   tvb[6]  Source EID
 *   tvb[7]  Message Flags              SOM/EOM/Seq#/TO/Tag
 *   tvb[8]  IC + Message Type
 *   tvb[9+] MCTP message payload
 *   tvb[byte_count+3]  PEC (CRC-8, present when capture tool includes it)
 *
 * The source address LSB=1 is the key differentiator from IPMI/IPMB, which
 * uses LSB=0 on the same command code (DSP0237 §6.21).
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tfs.h>
#include <wsutil/array.h>

void proto_register_mctp_smbus(void);
void proto_reg_handoff_mctp_smbus(void);

static int proto_mctp_smbus;

static int hf_mctp_smbus_dst_addr;
static int hf_mctp_smbus_rw;
static int hf_mctp_smbus_command_code;
static int hf_mctp_smbus_byte_count;
static int hf_mctp_smbus_src_addr;
static int hf_mctp_smbus_src_mctp_flag;
static int hf_mctp_smbus_pec;

static int ett_mctp_smbus;

static expert_field ei_mctp_smbus_malformed;
static expert_field ei_mctp_smbus_length_mismatch;

static dissector_handle_t mctp_smbus_handle;
static dissector_handle_t mctp_handle;

#define MCTP_SMBUS_COMMAND_CODE   0x0F
/* Minimum: dest_addr(1) + cmd(1) + byte_count(1) + src_addr(1) + MCTP hdr(4) + msg_type(1) */
#define MCTP_SMBUS_MIN_LENGTH     9
/*
 * Minimum byte_count per DSP0237 §6.3 Table 1:
 *   src_addr (Data Byte 1) + MCTP base header (4 bytes) + msg type (1 byte) = 6.
 * MCTP base dissector enforces MCTP_MIN_LENGTH=5 on the inner TVB.
 */
#define MCTP_SMBUS_MIN_BYTE_COUNT 6

/* R/W# bit: 1 = Read, 0 = Write (MCTP always uses Write) */
static const true_false_string tfs_smbus_rw = { "Read", "Write" };

/* Returns true only if tvb passes all structural checks for an MCTP SMBus frame.
   Dual maintenance with dissect_mctp_smbus() since this is just for heuristic validation.*/
static bool
mctp_smbus_frame_is_valid(tvbuff_t *tvb)
{
    unsigned len = tvb_reported_length(tvb);
    uint8_t  byte_count;

    /*
     * Gate on the *captured* length, not just the reported length: a
     * snaplen-truncated frame can report a large length while only a few
     * bytes were actually captured, in which case the tvb_get_uint8() reads
     * below would throw a bounds exception out of the heuristic.
     */
    if (tvb_captured_length(tvb) < MCTP_SMBUS_MIN_LENGTH)
        return false;
    /* R/W# bit must be 0 — MCTP only uses SMBus Block Write */
    if (tvb_get_uint8(tvb, 0) & 0x01)
        return false;
    if (tvb_get_uint8(tvb, 1) != MCTP_SMBUS_COMMAND_CODE)
        return false;
    byte_count = tvb_get_uint8(tvb, 2);
    if (byte_count < MCTP_SMBUS_MIN_BYTE_COUNT)
        return false;
    /* TVB must contain all declared payload bytes (PEC may or may not follow) */
    if (len < (unsigned)(byte_count + 3))
        return false;
    /* Source address LSB=1 identifies MCTP; LSB=0 identifies IPMI/IPMB */
    if (!(tvb_get_uint8(tvb, 3) & 0x01))
        return false;
    /* MCTP header version must be 1 */
    if ((tvb_get_uint8(tvb, 4) & 0x0F) != 0x01)
        return false;
    return true;
}

static int
dissect_mctp_smbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti, *bc_ti;
    proto_tree *smbus_tree;
    uint8_t     dst_addr;
    bool        rw;
    uint8_t     command_code;
    uint8_t     byte_count;
    uint8_t     src_addr;
    bool        src_mctp_flag;
    unsigned    len;
    unsigned    frame_min;
    unsigned    frame_pec;
    tvbuff_t   *next_tvb;

    len = tvb_reported_length(tvb);

    if (len < MCTP_SMBUS_MIN_LENGTH)
        return 0;

    ti = proto_tree_add_item(tree, proto_mctp_smbus, tvb, 0, -1, ENC_NA);
    smbus_tree = proto_item_add_subtree(ti, ett_mctp_smbus);

    proto_tree_add_item_ret_uint8(smbus_tree, hf_mctp_smbus_dst_addr,           tvb, 0, 1, ENC_NA, &dst_addr);
    proto_tree_add_item_ret_boolean(smbus_tree, hf_mctp_smbus_rw,               tvb, 0, 1, ENC_NA, &rw);
    proto_tree_add_item_ret_uint8(smbus_tree, hf_mctp_smbus_command_code,       tvb, 1, 1, ENC_NA, &command_code);
    bc_ti = proto_tree_add_item_ret_uint8(smbus_tree, hf_mctp_smbus_byte_count, tvb, 2, 1, ENC_NA, &byte_count);
    proto_tree_add_item_ret_uint8(smbus_tree, hf_mctp_smbus_src_addr,           tvb, 3, 1, ENC_NA, &src_addr);
    proto_tree_add_item_ret_boolean(smbus_tree, hf_mctp_smbus_src_mctp_flag,    tvb, 3, 1, ENC_NA, &src_mctp_flag);

    /* Validate protocol-identifying fields; flag violations and bail
       Dual maintenance with mctp_smbus_frame_is_valid() since this adds expert info. */
    if (rw || (command_code != MCTP_SMBUS_COMMAND_CODE) || !src_mctp_flag) {
        expert_add_info(pinfo, ti, &ei_mctp_smbus_malformed);
        return tvb_captured_length(tvb);
    }

    if (byte_count < MCTP_SMBUS_MIN_BYTE_COUNT) {
        expert_add_info_format(pinfo, bc_ti, &ei_mctp_smbus_malformed,
                "Byte count %u is below minimum %u (DSP0237 §6.3)",
                byte_count, MCTP_SMBUS_MIN_BYTE_COUNT);
        return tvb_captured_length(tvb);
    }

    frame_min = byte_count + 3U;   /* excl. PEC */
    if (len < frame_min) {
        expert_add_info_format(pinfo, bc_ti, &ei_mctp_smbus_length_mismatch,
                "Byte count %u implies frame length >= %u, but captured length is %u (frame truncated)",
                byte_count, frame_min, len);
        return tvb_captured_length(tvb);
    }

    /* MCTP header version (low nibble of first MCTP header byte) */
    if ((tvb_get_uint8(tvb, 4) & 0x0F) != 0x01) {
        expert_add_info(pinfo, ti, &ei_mctp_smbus_malformed);
        return tvb_captured_length(tvb);
    }

    /*
     * Valid frame tail layouts (DSP0237 §6.3):
     *   len == byte_count + 3  -> PEC stripped by capture
     *   len == byte_count + 4  -> PEC present (one byte)
     *   len  > byte_count + 4  -> unexpected trailing bytes; warn the user
     */
    frame_pec = byte_count + 4U;
    if (len >= frame_pec) {
        /* PEC is always the last byte of the SMBus transaction if it is present */
        proto_tree_add_item(smbus_tree, hf_mctp_smbus_pec, tvb, len - 1, 1, ENC_NA);
    }
    if (len > frame_pec) {
        /* Extra bytes between MCTP payload and PEC */
        tvbuff_t *extra_tvb = tvb_new_subset_length(tvb, frame_min, len - frame_pec);
        call_data_dissector(extra_tvb, pinfo, smbus_tree);
        expert_add_info_format(pinfo, bc_ti, &ei_mctp_smbus_length_mismatch,
                "Byte count %u implies frame length %u (or %u with PEC), but captured length is %u (%u extra trailing bytes)",
                byte_count, frame_min, frame_pec, len,
                len - frame_pec);

    }

    col_set_writable(pinfo->cinfo, -1, true);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMBus/I2C / ");
    col_set_fence(pinfo->cinfo, COL_PROTOCOL);

    /*
     * Hand the MCTP base header + payload to the MCTP dissector.
     * MCTP data starts at offset 4 (first byte after source slave address).
     * Length is byte_count - 1 (byte_count counts src_addr + MCTP data;
     * subtract 1 to exclude the src_addr byte already parsed above).
     */
    next_tvb = tvb_new_subset_length(tvb, 4, byte_count - 1);
    if (mctp_handle) {
        call_dissector(mctp_handle, next_tvb, pinfo, tree);
    } else {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    /* Prepend SMBus addressing after MCTP has written its COL_INFO */
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "[0x%02x->0x%02x] ", src_addr, dst_addr);

    return tvb_captured_length(tvb);
}

/* Heuristic wrapper for registration with the i2c.message heuristic table */
static bool
dissect_mctp_smbus_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data)
{
    if (!mctp_smbus_frame_is_valid(tvb))
        return false;
    return dissect_mctp_smbus(tvb, pinfo, tree, data) > 0;
}

void
proto_register_mctp_smbus(void)
{
    static hf_register_info hf[] = {
        { &hf_mctp_smbus_dst_addr,
          { "Destination Slave Address", "mctp.smbus.dst_addr",
            FT_UINT8, BASE_HEX, NULL, 0xFE,
            "7-bit SMBus destination slave address", HFILL }},
        { &hf_mctp_smbus_rw,
          { "R/W#", "mctp.smbus.rw",
            FT_BOOLEAN, 8, TFS(&tfs_smbus_rw), 0x01,
            "Read/Write direction bit (must be 0=Write for MCTP Block Write)", HFILL }},
        { &hf_mctp_smbus_command_code,
          { "Command Code", "mctp.smbus.command_code",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            "SMBus Block Write command code (0x0F for MCTP, per DSP0237)", HFILL }},
        { &hf_mctp_smbus_byte_count,
          { "Byte Count", "mctp.smbus.byte_count",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Count of bytes from source slave address through last data byte, excluding PEC", HFILL }},
        { &hf_mctp_smbus_src_addr,
          { "Source Slave Address", "mctp.smbus.src_addr",
            FT_UINT8, BASE_HEX, NULL, 0xFE,
            "7-bit SMBus source slave address", HFILL }},
        { &hf_mctp_smbus_src_mctp_flag,
          { "MCTP Indicator", "mctp.smbus.src_mctp_flag",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
            "LSB=1 indicates MCTP transport (LSB=0 indicates IPMI/IPMB)", HFILL }},
        { &hf_mctp_smbus_pec,
          { "PEC", "mctp.smbus.pec",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            "SMBus Packet Error Code (CRC-8)", HFILL }},
    };

    static int *ett[] = {
        &ett_mctp_smbus,
    };

    static ei_register_info ei[] = {
        { &ei_mctp_smbus_malformed,
          { "mctp.smbus.malformed", PI_MALFORMED, PI_ERROR,
            "Malformed MCTP SMBus frame", EXPFILL }},
        { &ei_mctp_smbus_length_mismatch,
          { "mctp.smbus.length_mismatch", PI_PROTOCOL, PI_WARN,
            "Byte count does not match captured frame length", EXPFILL }},
    };

    expert_module_t *expert_mctp_smbus;

    proto_mctp_smbus = proto_register_protocol(
            "MCTP over SMBus/I2C", "MCTP-SMBus", "mctp.smbus");
    proto_register_field_array(proto_mctp_smbus, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_mctp_smbus = expert_register_protocol(proto_mctp_smbus);
    expert_register_field_array(expert_mctp_smbus, ei, array_length(ei));

    mctp_smbus_handle = register_dissector("mctp.smbus",
            dissect_mctp_smbus, proto_mctp_smbus);
}

void
proto_reg_handoff_mctp_smbus(void)
{
    mctp_handle = find_dissector_add_dependency("mctp", proto_mctp_smbus);

    /* Automatic detection of MCTP frames inside i2c.message via heuristics */
    heur_dissector_add("i2c.message", dissect_mctp_smbus_heur,
            "MCTP over SMBus/I2C", "mctp_smbus_i2c",
            proto_mctp_smbus, HEURISTIC_ENABLE);

    /* Also expose via Decode As so users can force this dissector manually */
    dissector_add_for_decode_as("i2c.message", mctp_smbus_handle);
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
