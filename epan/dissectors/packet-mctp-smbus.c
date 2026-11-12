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

#include <epan/address_types.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-i2c.h"
#include "packet-mctp.h"

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
static int hf_mctp_smbus_pec_status;

static int ett_mctp_smbus;

static expert_field ei_mctp_smbus_malformed;
static expert_field ei_mctp_smbus_length_mismatch;
static expert_field ei_mctp_smbus_pec_bad;

static dissector_handle_t mctp_smbus_handle;
static dissector_handle_t mctp_handle;
static bool mctp_smbus_drop_bad_pec = true;

static int mctp_smbus_address_type = -1;

/* 7-bit SMBus slave address, as 0x-prefixed hex (DSP0237 Table 1). */
#define MCTP_SMBUS_ADDR_STR_LEN 5   /* "0x" + 2 hex digits + NUL */

static int
mctp_smbus_addr_str_len(const address *addr _U_)
{
    return MCTP_SMBUS_ADDR_STR_LEN;
}

static int
mctp_smbus_addr_to_str(const address *addr, char *buf, int buf_len)
{
    if (!buf || buf_len <= 0)
        return MCTP_SMBUS_ADDR_STR_LEN;
    if (addr->len != 1 || !addr->data) {
        buf[0] = '\0';
        return MCTP_SMBUS_ADDR_STR_LEN;
    }
    /* Bounded: truncates and NUL-terminates when buf_len < 5. */
    snprintf(buf, (size_t)buf_len, "0x%02x", *(const uint8_t *)addr->data);
    return MCTP_SMBUS_ADDR_STR_LEN;
}

static const char *
mctp_smbus_addr_col_filter_str(const address *addr _U_, bool is_src)
{
    return is_src ? "mctp.smbus.src_addr" : "mctp.smbus.dst_addr";
}

static int
mctp_smbus_addr_len(void)
{
    return 1;
}

bool
mctp_smbus_slave_addr(const address *addr, uint8_t *slave)
{
    if (mctp_smbus_address_type < 0 || addr->type != mctp_smbus_address_type ||
        addr->len != 1 || !addr->data)
        return false;
    *slave = *(const uint8_t *)addr->data;
    return true;
}

#define MCTP_SMBUS_COMMAND_CODE   0x0F
/* Minimum: dest_addr(1) + cmd(1) + byte_count(1) + src_addr(1) + MCTP hdr(4) */
#define MCTP_SMBUS_MIN_LENGTH     8
/* Minimum byte_count (DSP0237 6.3 Table 1): source address plus the
 * MCTP header.  A continuation packet may carry no payload byte. */
#define MCTP_SMBUS_MIN_BYTE_COUNT 5

/* SMBus 3.3 6.4.1.3 PEC: CRC-8 poly 0x07, MSB first, seed 0 (no in-tree helper). */
static uint8_t
mctp_smbus_pec(tvbuff_t *tvb, unsigned offset, unsigned len)
{
    uint8_t crc = 0;

    while (len--) {
        crc ^= tvb_get_uint8(tvb, offset++);
        for (int bit = 0; bit < 8; bit++)
            crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x07)
                               : (uint8_t)(crc << 1);
    }

    return crc;
}

/* Returns true only if tvb passes all structural checks for an MCTP SMBus frame.
   Dual maintenance with dissect_mctp_smbus() since this is just for heuristic validation.*/
static bool
mctp_smbus_frame_is_valid(tvbuff_t *tvb, packet_info *pinfo _U_)
{
    uint8_t  byte_count;

    /*
     * Gate on the *captured* length, not just the reported length: a
     * snaplen-truncated frame can report a large length while only a few
     * bytes were actually captured, in which case the tvb_get_uint8() reads
     * below would throw a bounds exception out of the heuristic.
     */
    if (tvb_captured_length(tvb) < MCTP_SMBUS_MIN_LENGTH)
        return false;
    /* R/W# must be 0: MCTP uses Block Write only (DSP0237 Table 1).  The
     * capture's direction flag describes the capturing host, so it is unused. */
    if (tvb_get_uint8(tvb, 0) & 0x01)
        return false;
    if (tvb_get_uint8(tvb, 1) != MCTP_SMBUS_COMMAND_CODE)
        return false;
    byte_count = tvb_get_uint8(tvb, 2);
    if (byte_count < MCTP_SMBUS_MIN_BYTE_COUNT)
        return false;
    /* The record must carry all of its declared payload: a complete packet
     * is byte_count + 3 octets (DSP0237 6.3 Table 1); the PEC is optional. */
    if (tvb_captured_length(tvb) < (unsigned)(byte_count + 3))
        return false;
    /* Source address LSB=1 identifies MCTP; LSB=0 identifies IPMI/IPMB */
    if (!(tvb_get_uint8(tvb, 3) & 0x01))
        return false;
    /* MCTP header version must be 1.  A recognition signal only: the forced
     * decode path leaves this to packet-mctp.c (see dissect_mctp_smbus()). */
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
    unsigned    captured;
    unsigned    frame_min;
    unsigned    frame_pec;
    bool        pec_bad = false;
    bool        drop_from_assembly = false;
    proto_item *pec_ti;
    tvbuff_t   *next_tvb;
    const i2c_message_data *message_data;

    len = tvb_reported_length(tvb);
    captured = tvb_captured_length(tvb);

    /*
     * Gate on captured length too: when invoked directly via "Decode As" a
     * snaplen-truncated frame can report a large length while only a few bytes
     * were captured, and the fixed-header reads below would otherwise throw a
     * bounds exception mid-dissection.  The heuristic path applies the same
     * guard in mctp_smbus_frame_is_valid().  A frame that is itself shorter
     * than the minimum is malformed (DSP0237 6.3 Table 1: byte count >= 5);
     * only "Decode As" reaches here with one.
     */
    if (captured < MCTP_SMBUS_MIN_LENGTH && len >= MCTP_SMBUS_MIN_LENGTH)
        return 0;

    ti = proto_tree_add_item(tree, proto_mctp_smbus, tvb, 0, -1, ENC_NA);
    smbus_tree = proto_item_add_subtree(ti, ett_mctp_smbus);

    if (len < MCTP_SMBUS_MIN_LENGTH) {
        if (tvb_bytes_exist(tvb, 0, 1)) {
            proto_tree_add_item(smbus_tree, hf_mctp_smbus_dst_addr, tvb, 0, 1, ENC_NA);
            proto_tree_add_item(smbus_tree, hf_mctp_smbus_rw, tvb, 0, 1, ENC_BIG_ENDIAN);
        }
        if (tvb_bytes_exist(tvb, 1, 1))
            proto_tree_add_item(smbus_tree, hf_mctp_smbus_command_code, tvb, 1, 1, ENC_NA);
        if (tvb_bytes_exist(tvb, 2, 1)) {
            bc_ti = proto_tree_add_item_ret_uint8(smbus_tree, hf_mctp_smbus_byte_count,
                                                  tvb, 2, 1, ENC_NA, &byte_count);
            if (byte_count < MCTP_SMBUS_MIN_BYTE_COUNT)
                expert_add_info_format(pinfo, bc_ti, &ei_mctp_smbus_malformed,
                        "Byte count %u is below minimum %u (DSP0237 §6.3)",
                        byte_count, MCTP_SMBUS_MIN_BYTE_COUNT);
        }
        if (tvb_bytes_exist(tvb, 3, 1)) {
            proto_tree_add_item(smbus_tree, hf_mctp_smbus_src_addr, tvb, 3, 1, ENC_NA);
            proto_tree_add_item(smbus_tree, hf_mctp_smbus_src_mctp_flag, tvb, 3, 1, ENC_BIG_ENDIAN);
        }
        expert_add_info_format(pinfo, ti, &ei_mctp_smbus_malformed,
                "Frame length %u is below the minimum %u (DSP0237 §6.3)",
                len, MCTP_SMBUS_MIN_LENGTH);
        return captured;
    }

    proto_tree_add_item_ret_uint8(smbus_tree, hf_mctp_smbus_dst_addr,           tvb, 0, 1, ENC_NA, &dst_addr);
    proto_tree_add_item_ret_boolean(smbus_tree, hf_mctp_smbus_rw,               tvb, 0, 1, ENC_BIG_ENDIAN, &rw);
    proto_tree_add_item_ret_uint8(smbus_tree, hf_mctp_smbus_command_code,       tvb, 1, 1, ENC_NA, &command_code);
    bc_ti = proto_tree_add_item_ret_uint8(smbus_tree, hf_mctp_smbus_byte_count, tvb, 2, 1, ENC_NA, &byte_count);
    proto_tree_add_item_ret_uint8(smbus_tree, hf_mctp_smbus_src_addr,           tvb, 3, 1, ENC_NA, &src_addr);
    proto_tree_add_item_ret_boolean(smbus_tree, hf_mctp_smbus_src_mctp_flag,    tvb, 3, 1, ENC_BIG_ENDIAN, &src_mctp_flag);
    proto_item_append_text(ti, ", Src: 0x%02x, Dst: 0x%02x (7-bit physical addresses)",
                           src_addr, dst_addr);

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
                "Byte count %u implies frame length >= %u, but frame length is %u (frame truncated)",
                byte_count, frame_min, len);
        return tvb_captured_length(tvb);
    }

    /* Version unchecked: MCTP reports a bad one (DSP0236 8.7); the heuristic declines it. */

    /* Tail layouts (DSP0237 6.3 Table 1):
     *   len == byte_count + 3  no PEC in the record
     *   len == byte_count + 4  a PEC, possibly cut by the snaplen
     *   len  > byte_count + 4  trailing bytes */
    frame_pec = byte_count + 4U;
    if (len == frame_min) {
        /* No PEC in the record: a status only, since a producer may strip it
         * and a PEC item would make mctp.smbus.pec match. */
        pec_ti = proto_tree_add_uint(smbus_tree, hf_mctp_smbus_pec_status,
                                     tvb, frame_min, 0,
                                     PROTO_CHECKSUM_E_NOT_PRESENT);
        proto_item_set_generated(pec_ti);
    } else if (tvb_bytes_exist(tvb, frame_min, 1)) {
        /* The PEC follows the last data byte, at byte_count + 3, and covers
         * tvb[0 .. frame_min - 1] (SMBus 3.3 6.4.1.3). */
        pec_bad = tvb_get_uint8(tvb, frame_min) !=
                  mctp_smbus_pec(tvb, 0, frame_min);
        proto_tree_add_checksum(smbus_tree, tvb, frame_min,
                                hf_mctp_smbus_pec, hf_mctp_smbus_pec_status,
                                &ei_mctp_smbus_pec_bad, pinfo,
                                mctp_smbus_pec(tvb, 0, frame_min),
                                ENC_NA, PROTO_CHECKSUM_VERIFY);
        drop_from_assembly = pec_bad && mctp_smbus_drop_bad_pec;
    } else {
        /* Reported but not captured: not verified. */
        pec_ti = proto_tree_add_uint(smbus_tree, hf_mctp_smbus_pec_status,
                                     tvb, frame_min, 0,
                                     PROTO_CHECKSUM_E_UNVERIFIED);
        proto_item_set_generated(pec_ti);
    }
    if (len > frame_pec) {
        drop_from_assembly = true;
        /* Extra bytes after the PEC; only dissect them if the snaplen
           actually captured that far, otherwise skip so dissection can still
           reach the MCTP subdissector below. */
        if (tvb_bytes_exist(tvb, frame_pec, len - frame_pec)) {
            tvbuff_t *extra_tvb = tvb_new_subset_length(tvb, frame_pec, len - frame_pec);
            call_data_dissector(extra_tvb, pinfo, smbus_tree);
        }
        expert_add_info_format(pinfo, bc_ti, &ei_mctp_smbus_length_mismatch,
                "Byte count %u implies frame length %u (or %u with PEC), but frame length is %u (%u extra trailing bytes)",
                byte_count, frame_min, frame_pec, len,
                len - frame_pec);

    }

    col_set_writable(pinfo->cinfo, -1, true);

    /* 7-bit slave addresses (not EIDs), the physical keys for MCTP assembly,
     * control pairing and NVMe-MI conversations. */
    alloc_address_wmem(pinfo->pool, &pinfo->net_src, mctp_smbus_address_type,
                       sizeof(src_addr), &src_addr);
    alloc_address_wmem(pinfo->pool, &pinfo->net_dst, mctp_smbus_address_type,
                       sizeof(dst_addr), &dst_addr);

    /* Fenced, so the address prefix survives an exception below. */
    col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[0x%02x->0x%02x] ",
                           src_addr, dst_addr);

    /*
     * Hand the MCTP base header + payload to the MCTP dissector.
     * MCTP data starts at offset 4 (first byte after source slave address).
     * Length is byte_count - 1 (byte_count counts src_addr + MCTP data;
     * subtract 1 to exclude the src_addr byte already parsed above).
     */
    next_tvb = tvb_new_subset_length(tvb, 4, byte_count - 1);
    if (mctp_handle) {
        message_data = i2c_message_data_get(pinfo);
        mctp_dissector_data mctp_data = {
            .has_ingress_scope = message_data != NULL,
            .ingress_scope_kind = MCTP_SCOPE_I2C_BUS,
            .ingress_scope_value = message_data ? message_data->bus : 0,
            .drop_from_assembly = drop_from_assembly,
        };

        /*
         * Set the protocol column to "SMBus/I2C / " with a fence only when the
         * MCTP subdissector will run and append its own protocol name after
         * it; otherwise the trailing separator would be left dangling.
         */
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMBus/I2C / ");
        col_set_fence(pinfo->cinfo, COL_PROTOCOL);
        call_dissector_with_data(mctp_handle, next_tvb, pinfo, tree,
                                 &mctp_data);
    } else {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMBus/I2C");
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

/* Heuristic wrapper for registration with the i2c.message heuristic table */
static bool
dissect_mctp_smbus_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data)
{
    if (!mctp_smbus_frame_is_valid(tvb, pinfo))
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
            FT_BOOLEAN, 8, TFS(&tfs_read_write), 0x01,
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
        { &hf_mctp_smbus_pec_status,
          { "PEC Status", "mctp.smbus.pec.status",
            FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x00,
            NULL, HFILL }},
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
            "Byte count does not match reported frame length", EXPFILL }},
        { &ei_mctp_smbus_pec_bad,
          { "mctp.smbus.pec_bad", PI_CHECKSUM, PI_WARN,
            "Packet Error Code does not match the computed CRC-8", EXPFILL }},
    };

    expert_module_t *expert_mctp_smbus;
    module_t *mctp_smbus_module;

    proto_mctp_smbus = proto_register_protocol(
            "MCTP over SMBus/I2C", "MCTP-SMBus", "mctp.smbus");
    proto_register_field_array(proto_mctp_smbus, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_mctp_smbus = expert_register_protocol(proto_mctp_smbus);
    expert_register_field_array(expert_mctp_smbus, ei, array_length(ei));

    mctp_smbus_address_type = address_type_dissector_register("AT_MCTP_SMBUS",
            "MCTP SMBus/I2C slave address", mctp_smbus_addr_to_str,
            mctp_smbus_addr_str_len, NULL, mctp_smbus_addr_col_filter_str,
            mctp_smbus_addr_len, NULL, NULL);

    mctp_smbus_module = prefs_register_protocol(proto_mctp_smbus, NULL);
    prefs_register_bool_preference(mctp_smbus_module, "drop_bad_pec",
            "Drop packets with a bad PEC before MCTP reassembly",
            "Do not let packets with a definitively invalid PEC alter MCTP "
            "message assembly state (DSP0236 8.7).",
            &mctp_smbus_drop_bad_pec);

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
