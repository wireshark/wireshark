/* packet-opa.c
 * Routines for Omni-Path 9B L2, L4, and extended L4 header dissection
 * Copyright (c) 2016, Intel Corporation.
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

#include "config.h"

#include <epan/packet.h>
#include <wiretap/erf.h>

void proto_reg_handoff_opa_9b(void);
void proto_register_opa_9b(void);

/* OpCodeValues
 * Code Bits [7-5] Connection Type
 *           [4-0] Message Type
 * Reliable Connection (RC) [7-5] = 000 */
#define RC_SEND_FIRST                    0 /*0x00000000 */
#define RC_SEND_MIDDLE                   1 /*0x00000001 */
#define RC_SEND_LAST                     2 /*0x00000010 */
#define RC_SEND_LAST_IMM                 3 /*0x00000011 */
#define RC_SEND_ONLY                     4 /*0x00000100 */
#define RC_SEND_ONLY_IMM                 5 /*0x00000101 */
#define RC_RDMA_WRITE_FIRST              6 /*0x00000110 */
#define RC_RDMA_WRITE_MIDDLE             7 /*0x00000111 */
#define RC_RDMA_WRITE_LAST               8 /*0x00001000 */
#define RC_RDMA_WRITE_LAST_IMM           9 /*0x00001001 */
#define RC_RDMA_WRITE_ONLY              10 /*0x00001010 */
#define RC_RDMA_WRITE_ONLY_IMM          11 /*0x00001011 */
#define RC_RDMA_READ_REQUEST            12 /*0x00001100 */
#define RC_RDMA_READ_RESPONSE_FIRST     13 /*0x00001101 */
#define RC_RDMA_READ_RESPONSE_MIDDLE    14 /*0x00001110 */
#define RC_RDMA_READ_RESPONSE_LAST      15 /*0x00001111 */
#define RC_RDMA_READ_RESPONSE_ONLY      16 /*0x00010000 */
#define RC_ACKNOWLEDGE                  17 /*0x00010001 */
#define RC_ATOMIC_ACKNOWLEDGE           18 /*0x00010010 */
#define RC_CMP_SWAP                     19 /*0x00010011 */
#define RC_FETCH_ADD                    20 /*0x00010100 */
#define RC_SEND_LAST_INVAL              22 /*0x00010110 */
#define RC_SEND_ONLY_INVAL              23 /*0x00010111 */
/* Reliable Datagram (RD) [7-5] = 010 */
#define RD_SEND_FIRST                   64 /*0x01000000 */
#define RD_SEND_MIDDLE                  65 /*0x01000001 */
#define RD_SEND_LAST                    66 /*0x01000010 */
#define RD_SEND_LAST_IMM                67 /*0x01000011 */
#define RD_SEND_ONLY                    68 /*0x01000100 */
#define RD_SEND_ONLY_IMM                69 /*0x01000101 */
#define RD_RDMA_WRITE_FIRST             70 /*0x01000110 */
#define RD_RDMA_WRITE_MIDDLE            71 /*0x01000111 */
#define RD_RDMA_WRITE_LAST              72 /*0x01001000 */
#define RD_RDMA_WRITE_LAST_IMM          73 /*0x01001001 */
#define RD_RDMA_WRITE_ONLY              74 /*0x01001010 */
#define RD_RDMA_WRITE_ONLY_IMM          75 /*0x01001011 */
#define RD_RDMA_READ_REQUEST            76 /*0x01001100 */
#define RD_RDMA_READ_RESPONSE_FIRST     77 /*0x01001101 */
#define RD_RDMA_READ_RESPONSE_MIDDLE    78 /*0x01001110 */
#define RD_RDMA_READ_RESPONSE_LAST      79 /*0x01001111 */
#define RD_RDMA_READ_RESPONSE_ONLY      80 /*0x01010000 */
#define RD_ACKNOWLEDGE                  81 /*0x01010001 */
#define RD_ATOMIC_ACKNOWLEDGE           82 /*0x01010010 */
#define RD_CMP_SWAP                     83 /*0x01010011 */
#define RD_FETCH_ADD                    84 /*0x01010100 */
#define RD_RESYNC                       85 /*0x01010101 */
/* Unreliable Datagram (UD) [7-5] = 011 */
#define UD_SEND_ONLY                   100 /*0x01100100 */
#define UD_SEND_ONLY_IMM               101 /*0x01100101 */
/* Unreliable Connection (UC) [7-5] = 001 */
#define UC_SEND_FIRST                   32 /*0x00100000 */
#define UC_SEND_MIDDLE                  33 /*0x00100001 */
#define UC_SEND_LAST                    34 /*0x00100010 */
#define UC_SEND_LAST_IMM                35 /*0x00100011 */
#define UC_SEND_ONLY                    36 /*0x00100100 */
#define UC_SEND_ONLY_IMM                37 /*0x00100101 */
#define UC_RDMA_WRITE_FIRST             38 /*0x00100110 */
#define UC_RDMA_WRITE_MIDDLE            39 /*0x00100111 */
#define UC_RDMA_WRITE_LAST              40 /*0x00101000 */
#define UC_RDMA_WRITE_LAST_IMM          41 /*0x00101001 */
#define UC_RDMA_WRITE_ONLY              42 /*0x00101010 */
#define UC_RDMA_WRITE_ONLY_IMM          43 /*0x00101011 */

/* Header Ordering Based on OPCODES */
#define RDETH_DETH_PAYLD            0
#define RDETH_DETH_RETH_PAYLD       1
#define RDETH_DETH_IMMDT_PAYLD      2
#define RDETH_DETH_RETH_IMMDT_PAYLD 3
#define RDETH_DETH_RETH             4
#define RDETH_AETH_PAYLD            5
#define RDETH_PAYLD                 6
#define RDETH_AETH                  7
#define RDETH_AETH_ATOMICACKETH     8
#define RDETH_DETH_ATOMICETH        9
#define RDETH_DETH                  10
#define DETH_PAYLD                  11
#define DETH_IMMDT_PAYLD            12
#define PAYLD                       13
#define IMMDT_PAYLD                 14
#define RETH_PAYLD                  15
#define RETH_IMMDT_PAYLD            16
#define RETH                        17
#define AETH_PAYLD                  18
#define AETH                        19
#define AETH_ATOMICACKETH           20
#define ATOMICETH                   21
#define IETH_PAYLD                  22
#define KDETH_PSM                   23

/* PSM */
#define PSM_RESERVED                    0xC0
#define PSM_TINY                        0xC1
#define PSM_SHORT                       0xC2
#define PSM_MEDIUM                      0xC3
#define PSM_MEDIUM_DATA                 0xC4
#define PSM_LONG_RTS                    0xC5
#define PSM_LONG_CTS                    0xC6
#define PSM_LONG_DATA                   0xC7
#define PSM_TIDS_GRANT                  0xC8
#define PSM_TIDS_GRANT_ACK              0xC9
#define PSM_TIDS_RELEASE                0xCA
#define PSM_TIDS_RELEASE_CONFIRM        0xCB
#define PSM_EXPTID_UNALIGNED            0xCC
#define PSM_EXPTID                      0xCD
#define PSM_ACK                         0xCE
#define PSM_NAK                         0xCF
#define PSM_ERR_CHK                     0xD0
#define PSM_ERR_CHK_BAD                 0xD1
#define PSM_ERR_CHK_GEN                 0xD2
#define PSM_FLOW_CCA_BECN               0xD3
#define PSM_CONNECT_REQUEST             0xD4
#define PSM_CONNECT_REPLY               0xD5
#define PSM_DISCONNECT_REQUEST          0xD6
#define PSM_DISCONNECT_REPLY            0xD7
#define PSM_AM_REQUEST_NOREPLY          0xD8
#define PSM_AM_REQUEST                  0xD9
#define PSM_AM_REPLY                    0xDA

/* Array of all availavle OpCodes to make matching a bit easier. The OpCodes
 * dictate the header sequence following in the packet. These arrays tell the
 * dissector which headers must be decoded for the given OpCode.
 */
static guint32 opCode_RDETH_DETH_ATOMICETH[] = {
    RD_CMP_SWAP,
    RD_FETCH_ADD
};
static guint32 opCode_IETH_PAYLD[] = {
    RC_SEND_LAST_INVAL,
    RC_SEND_ONLY_INVAL
};
static guint32 opCode_ATOMICETH[] = {
    RC_CMP_SWAP,
    RC_FETCH_ADD
};
static guint32 opCode_RDETH_DETH_RETH_PAYLD[] = {
    RD_RDMA_WRITE_FIRST,
    RD_RDMA_WRITE_ONLY
};
static guint32 opCode_RETH_IMMDT_PAYLD[] = {
    RC_RDMA_WRITE_ONLY_IMM,
    UC_RDMA_WRITE_ONLY_IMM
};
static guint32 opCode_RDETH_DETH_IMMDT_PAYLD[] = {
    RD_SEND_LAST_IMM,
    RD_SEND_ONLY_IMM,
    RD_RDMA_WRITE_LAST_IMM
};
static guint32 opCode_RDETH_AETH_PAYLD[] = {
    RD_RDMA_READ_RESPONSE_FIRST,
    RD_RDMA_READ_RESPONSE_LAST,
    RD_RDMA_READ_RESPONSE_ONLY
};
static guint32 opCode_AETH_PAYLD[] = {
    RC_RDMA_READ_RESPONSE_FIRST,
    RC_RDMA_READ_RESPONSE_LAST,
    RC_RDMA_READ_RESPONSE_ONLY
};
static guint32 opCode_RETH_PAYLD[] = {
    RC_RDMA_WRITE_FIRST,
    RC_RDMA_WRITE_ONLY,
    UC_RDMA_WRITE_FIRST,
    UC_RDMA_WRITE_ONLY
};
static guint32 opCode_RDETH_DETH_PAYLD[] = {
    RD_SEND_FIRST,
    RD_SEND_MIDDLE,
    RD_SEND_LAST,
    RD_SEND_ONLY,
    RD_RDMA_WRITE_MIDDLE,
    RD_RDMA_WRITE_LAST
};
static guint32 opCode_IMMDT_PAYLD[] = {
    RC_SEND_LAST_IMM,
    RC_SEND_ONLY_IMM,
    RC_RDMA_WRITE_LAST_IMM,
    UC_SEND_LAST_IMM,
    UC_SEND_ONLY_IMM,
    UC_RDMA_WRITE_LAST_IMM
};
static guint32 opCode_PAYLD[] = {
    RC_SEND_FIRST,
    RC_SEND_MIDDLE,
    RC_SEND_LAST,
    RC_SEND_ONLY,
    RC_RDMA_WRITE_MIDDLE,
    RC_RDMA_WRITE_LAST,
    RC_RDMA_READ_RESPONSE_MIDDLE,
    UC_SEND_FIRST,
    UC_SEND_MIDDLE,
    UC_SEND_LAST,
    UC_SEND_ONLY,
    UC_RDMA_WRITE_MIDDLE,
    UC_RDMA_WRITE_LAST
};
static guint32 opCode_PSM[] = {
    PSM_RESERVED,
    PSM_TINY,
    PSM_SHORT,
    PSM_MEDIUM,
    PSM_MEDIUM_DATA,
    PSM_LONG_RTS,
    PSM_LONG_CTS,
    PSM_LONG_DATA,
    PSM_TIDS_GRANT,
    PSM_TIDS_GRANT_ACK,
    PSM_TIDS_RELEASE,
    PSM_TIDS_RELEASE_CONFIRM,
    PSM_EXPTID_UNALIGNED,
    PSM_EXPTID,
    PSM_ACK,
    PSM_NAK,
    PSM_ERR_CHK,
    PSM_ERR_CHK_BAD,
    PSM_ERR_CHK_GEN,
    PSM_FLOW_CCA_BECN,
    PSM_CONNECT_REQUEST,
    PSM_CONNECT_REPLY,
    PSM_DISCONNECT_REQUEST,
    PSM_DISCONNECT_REPLY,
    PSM_AM_REQUEST_NOREPLY,
    PSM_AM_REQUEST,
    PSM_AM_REPLY,
};

/* OP Codes */
static const value_string vals_opa_bth_opcode[] = {
    { RC_SEND_FIRST,                "RC Send First " },
    { RC_SEND_MIDDLE,               "RC Send Middle " },
    { RC_SEND_LAST,                 "RC Send Last " },
    { RC_SEND_LAST_IMM,             "RC Send Last Immediate " },
    { RC_SEND_ONLY,                 "RC Send Only " },
    { RC_SEND_ONLY_IMM,             "RC Send Only Immediate " },
    { RC_RDMA_WRITE_FIRST,          "RC RDMA Write First " },
    { RC_RDMA_WRITE_MIDDLE,         "RC RDMA Write Middle " },
    { RC_RDMA_WRITE_LAST,           "RC RDMA Write Last " },
    { RC_RDMA_WRITE_LAST_IMM,       "RC RDMA Write Last Immediate " },
    { RC_RDMA_WRITE_ONLY,           "RC RDMA Write Only " },
    { RC_RDMA_WRITE_ONLY_IMM,       "RC RDMA Write Only Immediate " },
    { RC_RDMA_READ_REQUEST,         "RC RDMA Read Request " },
    { RC_RDMA_READ_RESPONSE_FIRST,  "RC RDMA Read Response First " },
    { RC_RDMA_READ_RESPONSE_MIDDLE, "RC RDMA Read Response Middle " },
    { RC_RDMA_READ_RESPONSE_LAST,   "RC RDMA Read Response Last " },
    { RC_RDMA_READ_RESPONSE_ONLY,   "RC RDMA Read Response Only " },
    { RC_ACKNOWLEDGE,               "RC Acknowledge " },
    { RC_ATOMIC_ACKNOWLEDGE,        "RC Atomic Acknowledge " },
    { RC_CMP_SWAP,                  "RC Compare Swap " },
    { RC_FETCH_ADD,                 "RC Fetch Add " },
    { RC_SEND_LAST_INVAL,           "RC Send Last Invalidate " },
    { RC_SEND_ONLY_INVAL,           "RC Send Only Invalidate " },
    { RD_SEND_FIRST,                "RD Send First " },
    { RD_SEND_MIDDLE,               "RD Send Middle " },
    { RD_SEND_LAST,                 "RD Send Last " },
    { RD_SEND_LAST_IMM,             "RD Last Immediate " },
    { RD_SEND_ONLY,                 "RD Send Only " },
    { RD_SEND_ONLY_IMM,             "RD Send Only Immediate " },
    { RD_RDMA_WRITE_FIRST,          "RD RDMA Write First " },
    { RD_RDMA_WRITE_MIDDLE,         "RD RDMA Write Middle " },
    { RD_RDMA_WRITE_LAST,           "RD RDMA Write Last " },
    { RD_RDMA_WRITE_LAST_IMM,       "RD RDMA Write Last Immediate " },
    { RD_RDMA_WRITE_ONLY,           "RD RDMA Write Only " },
    { RD_RDMA_WRITE_ONLY_IMM,       "RD RDMA Write Only Immediate " },
    { RD_RDMA_READ_REQUEST,         "RD RDMA Read Request " },
    { RD_RDMA_READ_RESPONSE_FIRST,  "RD RDMA Read Response First " },
    { RD_RDMA_READ_RESPONSE_MIDDLE, "RD RDMA Read Response Middle " },
    { RD_RDMA_READ_RESPONSE_LAST,   "RD RDMA Read Response Last " },
    { RD_RDMA_READ_RESPONSE_ONLY,   "RD RDMA Read Response Only " },
    { RD_ACKNOWLEDGE,               "RD Acknowledge " },
    { RD_ATOMIC_ACKNOWLEDGE,        "RD Atomic Acknowledge " },
    { RD_CMP_SWAP,                  "RD Compare Swap " },
    { RD_FETCH_ADD,                 "RD Fetch Add " },
    { RD_RESYNC,                    "RD RESYNC " },
    { UD_SEND_ONLY,                 "UD Send Only " },
    { UD_SEND_ONLY_IMM,             "UD Send Only Immediate " },
    { UC_SEND_FIRST,                "UC Send First " },
    { UC_SEND_MIDDLE,               "UC Send Middle " },
    { UC_SEND_LAST,                 "UC Send Last " },
    { UC_SEND_LAST_IMM,             "UC Send Last Immediate " },
    { UC_SEND_ONLY,                 "UC Send Only " },
    { UC_SEND_ONLY_IMM,             "UC Send Only Immediate " },
    { UC_RDMA_WRITE_FIRST,          "UC RDMA Write First" },
    { UC_RDMA_WRITE_MIDDLE,         "Unreliable Connection RDMA Write Middle " },
    { UC_RDMA_WRITE_LAST,           "UC RDMA Write Last " },
    { UC_RDMA_WRITE_LAST_IMM,       "UC RDMA Write Last Immediate " },
    { UC_RDMA_WRITE_ONLY,           "UC RDMA Write Only " },
    { UC_RDMA_WRITE_ONLY_IMM,       "UC RDMA Write Only Immediate " },
    { 0, NULL }
};
static const value_string vals_opa_9b_lnh[] = {
    { 0, "RAW" },
    { 3, "GRH" },
    { 2, "BTH" },
    { 1, "Ipv6" },
    { 0, NULL }
};
static const value_string vals_opa_9b_grh_ipver[] = {
    { 4, "IPv4" },
    { 6, "IPv6" },
    { 0, NULL },
};
static const value_string vals_opa_9b_grh_next_hdr[] = {
    { 0x1B, "BTH Follows" },
    { 0, NULL }
};
static const true_false_string tfs_opa_bth_migrated_notmigrated = {
    "Migrated",
    "Not Migrated"
};
static const true_false_string tfs_opa_kdeth_offset_32_64 = {
    "32 Byte Words",
    "64 Byte Words"
};
/* Wireshark ID */
static gint proto_opa_9b = -1;

/* Variables to hold expansion values between packets */
static gint ett_all_headers = -1;
static gint ett_9b = -1;
static gint ett_grh = -1;
static gint ett_bth = -1;
static gint ett_rdeth = -1;
static gint ett_deth = -1;
static gint ett_reth = -1;
static gint ett_atomiceth = -1;
static gint ett_aeth = -1;
static gint ett_atomicacketh = -1;
static gint ett_immdt = -1;
static gint ett_ieth = -1;
static gint ett_kdeth = -1;
static gint ett_psm = -1;

/* 9B Header Fields */
static gint hf_opa_9B = -1;
static gint hf_opa_9B_service_channel = -1;
static gint hf_opa_9B_link_version = -1;
static gint hf_opa_9B_service_level = -1;
static gint hf_opa_9B_reserved2 = -1;
static gint hf_opa_9B_lnh = -1;
static gint hf_opa_9B_dlid = -1;
static gint hf_opa_9B_reserved3 = -1;
static gint hf_opa_9B_packet_length = -1;
static gint hf_opa_9B_slid = -1;
/* ICRC */
static gint hf_opa_9b_ICRC = -1;

/* GRH */
static gint hf_opa_grh = -1;
static gint hf_opa_grh_ip_version = -1;
static gint hf_opa_grh_traffic_class = -1;
static gint hf_opa_grh_flow_label = -1;
static gint hf_opa_grh_payload_length = -1;
static gint hf_opa_grh_next_header = -1;
static gint hf_opa_grh_hop_limit = -1;
static gint hf_opa_grh_source_gid = -1;
static gint hf_opa_grh_destination_gid = -1;

/* BTH */
static gint hf_opa_bth = -1;
static gint hf_opa_bth_opcode = -1;
static gint hf_opa_bth_solicited_event = -1;
static gint hf_opa_bth_migreq = -1;
static gint hf_opa_bth_pad_count = -1;
static gint hf_opa_bth_transport_header_version = -1;
static gint hf_opa_bth_partition_key = -1;
static gint hf_opa_bth_fcn = -1;
static gint hf_opa_bth_bcn = -1;
static gint hf_opa_bth_Reserved8a = -1;
static gint hf_opa_bth_destination_qp = -1;
static gint hf_opa_bth_acknowledge_request = -1;
static gint hf_opa_bth_packet_sequence_number = -1;

/* XXETH */
static gint hf_opa_RDETH = -1;
static gint hf_opa_RDETH_reserved8 = -1;
static gint hf_opa_RDETH_ee_context = -1;
static gint hf_opa_DETH = -1;
static gint hf_opa_DETH_queue_key = -1;
static gint hf_opa_DETH_reserved8 = -1;
static gint hf_opa_DETH_source_qp = -1;
static gint hf_opa_RETH = -1;
static gint hf_opa_RETH_virtual_address = -1;
static gint hf_opa_RETH_remote_key = -1;
static gint hf_opa_RETH_dma_length = -1;
static gint hf_opa_AtomicETH = -1;
static gint hf_opa_AtomicETH_virtual_address = -1;
static gint hf_opa_AtomicETH_remote_key = -1;
static gint hf_opa_AtomicETH_swap_or_add_data = -1;
static gint hf_opa_AtomicETH_compare_data = -1;
static gint hf_opa_AETH = -1;
static gint hf_opa_AETH_syndrome = -1;
static gint hf_opa_AETH_message_sequence_number = -1;
static gint hf_opa_AtomicAckETH = -1;
static gint hf_opa_AtomicAckETH_original_remote_data = -1;
static gint hf_opa_IMMDT = -1;
static gint hf_opa_IMMDT_data = -1;
static gint hf_opa_IETH = -1;
static gint hf_opa_IETH_r_key = -1;
static gint hf_opa_KDETH = -1;
static gint hf_opa_KDETH_kver = -1;
static gint hf_opa_KDETH_sh = -1;
static gint hf_opa_KDETH_intr = -1;
static gint hf_opa_KDETH_tidctrl = -1;
static gint hf_opa_KDETH_tid = -1;
static gint hf_opa_KDETH_offset_mode = -1;
static gint hf_opa_KDETH_offset = -1;
static const gint *_opa_KDETH_word1[] = {
    &hf_opa_KDETH_kver,
    &hf_opa_KDETH_sh,
    &hf_opa_KDETH_intr,
    &hf_opa_KDETH_tidctrl,
    &hf_opa_KDETH_tid,
    &hf_opa_KDETH_offset_mode,
    &hf_opa_KDETH_offset,
    NULL
};
static gint hf_opa_KDETH_hcrc = -1;
static gint hf_opa_KDETH_j_key = -1;
static const gint *_opa_KDETH_word2[] = {
    &hf_opa_KDETH_hcrc,
    &hf_opa_KDETH_j_key,
    NULL
};
/* PSM */
static gint hf_opa_psm = -1;
static gint hf_opa_psm_a = -1;
static gint hf_opa_psm_ackpsn = -1;
static gint hf_opa_psm_flags = -1;
static gint hf_opa_psm_commidx = -1;
static gint hf_opa_psm_flowid = -1;
static gint hf_opa_psm_msglen = -1;
static gint hf_opa_psm_msgseq = -1;
static gint hf_opa_psm_tag = -1;
static gint hf_opa_psm_msgdata = -1;
static gint hf_opa_psm_short_msglen = -1;
static gint hf_opa_psm_paylen = -1;
static gint hf_opa_psm_offset = -1;
static gint hf_opa_psm_sreqidx = -1;
static gint hf_opa_psm_rreqidx = -1;
static gint hf_opa_psm_rdescid = -1;
static gint hf_opa_psm_sdescid = -1;
static gint hf_opa_psm_psn = -1;
static gint hf_opa_psm_hostipv4 = -1;
static gint hf_opa_psm_hostpid = -1;
static gint hf_opa_psm_dlen = -1;
static gint hf_opa_psm_nargs = -1;
static gint hf_opa_psm_hidx = -1;
static gint hf_opa_psm_arg = -1;
static gint hf_opa_psm_payload = -1;

/* Custom Functions */
static void cf_opa_dw_to_b(gchar *buf, guint32 value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH, "%u DWORDS (%u Bytes)", value, value * 4);
}

/* Dissector Declarations */
static dissector_handle_t opa_9b_handle;
static dissector_handle_t opa_mad_handle;
static dissector_handle_t infiniband_handle;
static dissector_handle_t ipv6_handle;

static void parse_opa_9B_Header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset, guint8 *lnh_val)
{
    /* 16B - L2 Header */
    proto_item *L2_9B_header_item;
    proto_tree *L2_9B_header_tree;
    void *src_addr, *dst_addr;

    gint local_offset = *offset;

    col_prepend_fstr(pinfo->cinfo, COL_INFO, "9B: ");
    L2_9B_header_item = proto_tree_add_item(tree, hf_opa_9B, tvb, local_offset, 8, ENC_NA);
    L2_9B_header_tree = proto_item_add_subtree(L2_9B_header_item, ett_9b);

    proto_tree_add_item(L2_9B_header_tree, hf_opa_9B_service_channel, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(L2_9B_header_tree, hf_opa_9B_link_version, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(L2_9B_header_tree, hf_opa_9B_service_level, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(L2_9B_header_tree, hf_opa_9B_reserved2, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(L2_9B_header_tree, hf_opa_9B_lnh, tvb, local_offset, 1, ENC_BIG_ENDIAN);

    /* Save Link Next Header... This tells us what the next header is. */
    *lnh_val = tvb_get_guint8(tvb, local_offset);
    *lnh_val &= 0x03;
    local_offset += 1;

    proto_tree_add_item(L2_9B_header_tree, hf_opa_9B_dlid, tvb, local_offset, 2, ENC_BIG_ENDIAN);

    /* Set destination in packet view. */
    dst_addr = wmem_alloc(pinfo->pool, sizeof(guint16));
    *((guint16 *)dst_addr) = tvb_get_ntohs(tvb, local_offset);
    set_address(&pinfo->dst, AT_IB, sizeof(guint16), dst_addr);
    local_offset += 2;

    proto_tree_add_item(L2_9B_header_tree, hf_opa_9B_reserved3, tvb, local_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(L2_9B_header_tree, hf_opa_9B_packet_length, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(L2_9B_header_tree, hf_opa_9B_slid, tvb, local_offset, 2, ENC_BIG_ENDIAN);

    /* Set Source in packet view. */
    src_addr = wmem_alloc(pinfo->pool, sizeof(guint16));
    *((guint16 *)src_addr) = tvb_get_ntohs(tvb, local_offset);
    set_address(&pinfo->src, AT_IB, sizeof(guint16), src_addr);
    local_offset += 2;

    *offset = local_offset;
}

static void parse_opa_grh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset, guint8 *nextHdr)
{
    proto_item *global_route_header_item;
    proto_tree *global_route_header_tree;

    gint local_offset = *offset;

    col_append_fstr(pinfo->cinfo, COL_INFO, "GRH: ");
    global_route_header_item = proto_tree_add_item(tree, hf_opa_grh, tvb, local_offset, 40, ENC_NA);
    global_route_header_tree = proto_item_add_subtree(global_route_header_item, ett_grh);

    proto_tree_add_item(global_route_header_tree, hf_opa_grh_ip_version, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(global_route_header_tree, hf_opa_grh_traffic_class, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(global_route_header_tree, hf_opa_grh_flow_label, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(global_route_header_tree, hf_opa_grh_payload_length, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    *nextHdr = tvb_get_guint8(tvb, local_offset);

    proto_tree_add_item(global_route_header_tree, hf_opa_grh_next_header, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(global_route_header_tree, hf_opa_grh_hop_limit, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(global_route_header_tree, hf_opa_grh_source_gid, tvb, local_offset, 16, ENC_NA);

    /* set source GID in packet view*/
    set_address_tvb(&pinfo->src, AT_IB, 16, tvb, local_offset);
    local_offset += 16;

    proto_tree_add_item(global_route_header_tree, hf_opa_grh_destination_gid, tvb, local_offset, 16, ENC_NA);

    /* set destination GID in packet view*/
    set_address_tvb(&pinfo->dst, AT_IB, 16, tvb, local_offset);
    local_offset += 16;

    *offset = local_offset;
}

static void parse_opa_bth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset, guint8 *opCode)
{
    proto_item *base_transport_header_item;
    proto_tree *base_transport_header_tree;

    gint local_offset = *offset;

    col_append_fstr(pinfo->cinfo, COL_INFO, "BTH: ");
    base_transport_header_item = proto_tree_add_item(tree, hf_opa_bth, tvb, local_offset, 12, ENC_NA);
    base_transport_header_tree = proto_item_add_subtree(base_transport_header_item, ett_bth);

    proto_tree_add_item(base_transport_header_tree, hf_opa_bth_opcode, tvb, local_offset, 1, ENC_LITTLE_ENDIAN);
    *opCode = tvb_get_guint8(tvb, local_offset);
    col_append_str(pinfo->cinfo, COL_INFO, val_to_str((guint32)(*opCode), vals_opa_bth_opcode, "Unknown OpCode (0x%0x)"));
    local_offset += 1;

    proto_tree_add_item(base_transport_header_tree, hf_opa_bth_solicited_event, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(base_transport_header_tree, hf_opa_bth_migreq, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(base_transport_header_tree, hf_opa_bth_pad_count, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(base_transport_header_tree, hf_opa_bth_transport_header_version, tvb, local_offset, 1, ENC_BIG_ENDIAN);

    local_offset += 1;
    proto_tree_add_item(base_transport_header_tree, hf_opa_bth_partition_key, tvb, local_offset, 2, ENC_BIG_ENDIAN);

    local_offset += 2;
    proto_tree_add_item(base_transport_header_tree, hf_opa_bth_fcn, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(base_transport_header_tree, hf_opa_bth_bcn, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(base_transport_header_tree, hf_opa_bth_Reserved8a, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(base_transport_header_tree, hf_opa_bth_destination_qp, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    pinfo->destport = tvb_get_ntoh24(tvb, local_offset); local_offset += 3;
    proto_tree_add_item(base_transport_header_tree, hf_opa_bth_acknowledge_request, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(base_transport_header_tree, hf_opa_bth_packet_sequence_number, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    *offset = local_offset;
}
static gboolean contains(guint32 OpCode, guint32 *Codes, gint32 length)
{
    gint32 i;
    for (i = 0; i < length; i++) {
        if ((OpCode ^ Codes[i]) == 0)
            return TRUE;
    }
    return FALSE;
}
static gint32 find_next_header_sequence(guint32 OpCode)
{
    if (contains(OpCode, &opCode_PAYLD[0], (gint32)array_length(opCode_PAYLD)))
        return PAYLD;

    if (contains(OpCode, &opCode_IMMDT_PAYLD[0], (gint32)array_length(opCode_IMMDT_PAYLD)))
        return IMMDT_PAYLD;

    if (contains(OpCode, &opCode_RDETH_DETH_PAYLD[0], (gint32)array_length(opCode_RDETH_DETH_PAYLD)))
        return RDETH_DETH_PAYLD;

    if (contains(OpCode, &opCode_RETH_PAYLD[0], (gint32)array_length(opCode_RETH_PAYLD)))
        return RETH_PAYLD;

    if (contains(OpCode, &opCode_RDETH_AETH_PAYLD[0], (gint32)array_length(opCode_RDETH_AETH_PAYLD)))
        return RDETH_AETH_PAYLD;

    if (contains(OpCode, &opCode_AETH_PAYLD[0], (gint32)array_length(opCode_AETH_PAYLD)))
        return AETH_PAYLD;

    if (contains(OpCode, &opCode_RDETH_DETH_IMMDT_PAYLD[0], (gint32)array_length(opCode_RDETH_DETH_IMMDT_PAYLD)))
        return RDETH_DETH_IMMDT_PAYLD;

    if (contains(OpCode, &opCode_RETH_IMMDT_PAYLD[0], (gint32)array_length(opCode_RETH_IMMDT_PAYLD)))
        return RETH_IMMDT_PAYLD;

    if (contains(OpCode, &opCode_RDETH_DETH_RETH_PAYLD[0], (gint32)array_length(opCode_RDETH_DETH_RETH_PAYLD)))
        return RDETH_DETH_RETH_PAYLD;

    if (contains(OpCode, &opCode_ATOMICETH[0], (gint32)array_length(opCode_ATOMICETH)))
        return ATOMICETH;

    if (contains(OpCode, &opCode_IETH_PAYLD[0], (gint32)array_length(opCode_IETH_PAYLD)))
        return IETH_PAYLD;

    if (contains(OpCode, &opCode_RDETH_DETH_ATOMICETH[0], (gint32)array_length(opCode_RDETH_DETH_ATOMICETH)))
        return RDETH_DETH_ATOMICETH;

    if (contains(OpCode, &opCode_PSM[0], (gint32)array_length(opCode_PSM)))
        return KDETH_PSM;

    if ((OpCode ^ RC_ACKNOWLEDGE) == 0)
        return AETH;

    if ((OpCode ^ RC_RDMA_READ_REQUEST) == 0)
        return RETH;

    if ((OpCode ^ RC_ATOMIC_ACKNOWLEDGE) == 0)
        return AETH_ATOMICACKETH;

    if ((OpCode ^ RD_RDMA_READ_RESPONSE_MIDDLE) == 0)
        return RDETH_PAYLD;

    if ((OpCode ^ RD_ACKNOWLEDGE) == 0)
        return RDETH_AETH;

    if ((OpCode ^ RD_ATOMIC_ACKNOWLEDGE) == 0)
        return RDETH_AETH_ATOMICACKETH;

    if ((OpCode ^ RD_RDMA_WRITE_ONLY_IMM) == 0)
        return RDETH_DETH_RETH_IMMDT_PAYLD;

    if ((OpCode ^ RD_RDMA_READ_REQUEST) == 0)
        return RDETH_DETH_RETH;

    if ((OpCode ^ RD_RESYNC) == 0)
        return RDETH_DETH;

    if ((OpCode ^ UD_SEND_ONLY) == 0)
        return DETH_PAYLD;

    if ((OpCode ^ UD_SEND_ONLY_IMM) == 0)
        return DETH_IMMDT_PAYLD;

    return -1;
}

/* Parse RDETH - Reliable Datagram Extended Transport Header */
static void parse_RDETH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    gint local_offset = *offset;
    /* RDETH - Reliable Datagram Extended Transport Header */
    proto_item *RDETH_header_item;
    proto_tree *RDETH_header_tree;

    col_append_fstr(pinfo->cinfo, COL_INFO, "RDETH: ");
    RDETH_header_item = proto_tree_add_item(tree, hf_opa_RDETH, tvb, local_offset, 4, ENC_NA);
    RDETH_header_tree = proto_item_add_subtree(RDETH_header_item, ett_rdeth);

    proto_tree_add_item(RDETH_header_tree, hf_opa_RDETH_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(RDETH_header_tree, hf_opa_RDETH_ee_context, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;
    *offset = local_offset;
}
/* Parse DETH - Datagram Extended Transport Header */
static void parse_DETH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    gint local_offset = *offset;
    /* DETH - Datagram Extended Transport Header */
    proto_item *DETH_header_item;
    proto_tree *DETH_header_tree;

    col_append_fstr(pinfo->cinfo, COL_INFO, "DETH: ");
    DETH_header_item = proto_tree_add_item(tree, hf_opa_DETH, tvb, local_offset, 8, ENC_NA);
    DETH_header_tree = proto_item_add_subtree(DETH_header_item, ett_deth);

    proto_tree_add_item(DETH_header_tree, hf_opa_DETH_queue_key, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(DETH_header_tree, hf_opa_DETH_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(DETH_header_tree, hf_opa_DETH_source_qp, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    pinfo->srcport = tvb_get_ntoh24(tvb, local_offset); local_offset += 3;

    *offset = local_offset;
}
/* Parse RETH - RDMA Extended Transport Header */
static void parse_RETH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    gint local_offset = *offset;
    /* RETH - RDMA Extended Transport Header */
    proto_item *RETH_header_item;
    proto_tree *RETH_header_tree;

    col_append_fstr(pinfo->cinfo, COL_INFO, "RETH: ");
    RETH_header_item = proto_tree_add_item(tree, hf_opa_RETH, tvb, local_offset, 16, ENC_NA);
    RETH_header_tree = proto_item_add_subtree(RETH_header_item, ett_reth);

    proto_tree_add_item(RETH_header_tree, hf_opa_RETH_virtual_address, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(RETH_header_tree, hf_opa_RETH_remote_key, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(RETH_header_tree, hf_opa_RETH_dma_length, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    *offset = local_offset;
}
/* Parse AtomicETH - Atomic Extended Transport Header */
static void parse_ATOMICETH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    gint local_offset = *offset;
    /* AtomicETH - Atomic Extended Transport Header */
    proto_item *ATOMICETH_header_item;
    proto_tree *ATOMICETH_header_tree;

    col_append_fstr(pinfo->cinfo, COL_INFO, "AtomicETH: ");
    ATOMICETH_header_item = proto_tree_add_item(tree, hf_opa_AtomicETH, tvb, local_offset, 28, ENC_NA);
    ATOMICETH_header_tree = proto_item_add_subtree(ATOMICETH_header_item, ett_atomiceth);

    proto_tree_add_item(ATOMICETH_header_tree, hf_opa_AtomicETH_virtual_address, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(ATOMICETH_header_tree, hf_opa_AtomicETH_remote_key, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(ATOMICETH_header_tree, hf_opa_AtomicETH_swap_or_add_data, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(ATOMICETH_header_tree, hf_opa_AtomicETH_compare_data, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    *offset = local_offset;
}
/* Parse AETH - ACK Extended Transport Header */
static void parse_AETH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    gint local_offset = *offset;
    /* AETH - ACK Extended Transport Header */
    proto_item *AETH_header_item;
    proto_tree *AETH_header_tree;

    col_append_fstr(pinfo->cinfo, COL_INFO, "AETH: ");
    AETH_header_item = proto_tree_add_item(tree, hf_opa_AETH, tvb, local_offset, 4, ENC_NA);
    AETH_header_tree = proto_item_add_subtree(AETH_header_item, ett_aeth);

    proto_tree_add_item(AETH_header_tree, hf_opa_AETH_syndrome, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(AETH_header_tree, hf_opa_AETH_message_sequence_number, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;

    *offset = local_offset;
}
/* Parse AtomicAckEth - Atomic ACK Extended Transport Header */
static void parse_ATOMICACKETH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    gint local_offset = *offset;
    /* AtomicAckEth - Atomic ACK Extended Transport Header */
    proto_item *ATOMICACKETH_header_item;
    proto_tree *ATOMICACKETH_header_tree;

    col_append_fstr(pinfo->cinfo, COL_INFO, "AtomicACKETH: ");
    ATOMICACKETH_header_item = proto_tree_add_item(tree, hf_opa_AtomicAckETH, tvb, local_offset, 8, ENC_NA);
    ATOMICACKETH_header_tree = proto_item_add_subtree(ATOMICACKETH_header_item, ett_atomicacketh);
    proto_tree_add_item(ATOMICACKETH_header_tree, hf_opa_AtomicAckETH_original_remote_data, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    *offset = local_offset;
}
/* Parse IMMDT - Immediate Data Extended Transport Header */
static void parse_IMMDT(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    gint local_offset = *offset;
    /* IMMDT - Immediate Data Extended Transport Header */
    proto_item *IMMDT_header_item;
    proto_tree *IMMDT_header_tree;

    col_append_fstr(pinfo->cinfo, COL_INFO, "IMMDT: ");
    IMMDT_header_item = proto_tree_add_item(tree, hf_opa_IMMDT, tvb, local_offset, 4, ENC_NA);
    IMMDT_header_tree = proto_item_add_subtree(IMMDT_header_item, ett_immdt);
    proto_tree_add_item(IMMDT_header_tree, hf_opa_IMMDT_data, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    *offset = local_offset;
}
/* Parse IETH - Invalidate Extended Transport Header */
static void parse_IETH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    gint local_offset = *offset;
    /* IETH - Invalidate Extended Transport Header */
    proto_item *IETH_header_item;
    proto_tree *IETH_header_tree;

    col_append_fstr(pinfo->cinfo, COL_INFO, "IETH: ");
    IETH_header_item = proto_tree_add_item(tree, hf_opa_IETH, tvb, local_offset, 4, ENC_NA);
    IETH_header_tree = proto_item_add_subtree(IETH_header_item, ett_ieth);

    proto_tree_add_item(IETH_header_tree, hf_opa_IETH_r_key,  tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    *offset = local_offset;
}
/* Parse KDETH - Key Datagram Extended Transport Header */
static void parse_KDETH(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    gint local_offset = *offset;
    /* KDETH - Key Datagram Extended Transport Header */
    proto_item *KDETH_header_item;
    proto_tree *KDETH_header_tree;

    col_append_fstr(pinfo->cinfo, COL_INFO, "KDETH: ");
    KDETH_header_item = proto_tree_add_item(tree, hf_opa_KDETH, tvb, local_offset, 8, ENC_NA);
    KDETH_header_tree = proto_item_add_subtree(KDETH_header_item, ett_kdeth);

    proto_tree_add_bitmask_list(KDETH_header_tree, tvb, local_offset, 4, _opa_KDETH_word1, ENC_LITTLE_ENDIAN);
    local_offset += 4;
    proto_tree_add_bitmask_list(KDETH_header_tree, tvb, local_offset, 4, _opa_KDETH_word2, ENC_LITTLE_ENDIAN);
    local_offset += 4;

    *offset = local_offset;
}

/* Parse PSM header */
static void parse_PSM(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset, gint opCode)
{
    gint local_offset = *offset;
    /* PSM Header */
    proto_item *PSM_header_item;
    proto_tree *PSM_header_tree;
    guint32 payLength;

    col_append_fstr(pinfo->cinfo, COL_INFO, "PSM: ");
    PSM_header_item = proto_tree_add_item(tree, hf_opa_psm, tvb, local_offset, 28, ENC_NA);
    PSM_header_tree = proto_item_add_subtree(PSM_header_item, ett_psm);

    proto_tree_add_item(PSM_header_tree, hf_opa_psm_a, tvb, local_offset + 3, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(PSM_header_tree, hf_opa_psm_ackpsn, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PSM_header_tree, hf_opa_psm_flags, tvb, local_offset + 3, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(PSM_header_tree, hf_opa_psm_commidx, tvb, local_offset, 3, ENC_LITTLE_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PSM_header_tree, hf_opa_psm_flowid, tvb, local_offset + 3, 1, ENC_LITTLE_ENDIAN);

    switch (opCode) {
    case PSM_TINY:
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_msglen, tvb, local_offset + 2, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_msgseq, tvb, local_offset, 2, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_tag, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_msgdata, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        break;
    case PSM_SHORT:
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_msgseq, tvb, local_offset, 2, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_tag, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_msglen, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        payLength = tvb_get_letohl(tvb, local_offset);
        local_offset += 8;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_payload, tvb, local_offset, payLength, ENC_NA);
        local_offset += payLength;
        break;
    case PSM_MEDIUM:
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_msgseq, tvb, local_offset, 2, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_tag, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_msglen, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_paylen, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        break;
    case PSM_MEDIUM_DATA:
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_msgseq, tvb, local_offset, 2, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        local_offset += 8;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_offset, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_paylen, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        break;
    case PSM_LONG_RTS:
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_msgseq, tvb, local_offset, 2, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_tag, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_msglen, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_sreqidx, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        break;
    case PSM_LONG_CTS:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_sreqidx, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_rreqidx, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_msglen, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        break;
    case PSM_LONG_DATA:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_rreqidx, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_offset, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_paylen, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        break;
    case PSM_TIDS_GRANT:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_sreqidx, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_short_msglen, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_paylen, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        break;
    case PSM_TIDS_GRANT_ACK:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_rdescid, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        local_offset += 8;
        break;
    case PSM_TIDS_RELEASE:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_rdescid, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_sdescid, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        break;
    case PSM_TIDS_RELEASE_CONFIRM:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_sdescid, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        local_offset += 8;
        break;
    case PSM_EXPTID_UNALIGNED:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_rdescid, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        local_offset += 8;
        break;
    case PSM_EXPTID:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_rdescid, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_sdescid, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        break;
    case PSM_ACK:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_sdescid, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        local_offset += 8;
        break;
    case PSM_NAK:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_sdescid, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_psn, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        break;
    case PSM_ERR_CHK:
    case PSM_ERR_CHK_BAD:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_hostipv4, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_hostpid, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 12;
        break;
    case PSM_ERR_CHK_GEN:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_rdescid, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_sdescid, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        break;
    case PSM_FLOW_CCA_BECN:
        break;
    case PSM_CONNECT_REQUEST:
    case PSM_CONNECT_REPLY:
    case PSM_DISCONNECT_REQUEST:
    case PSM_DISCONNECT_REPLY:
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_paylen, tvb, local_offset, 4, ENC_LITTLE_ENDIAN);
        local_offset += 16;
        break;
    case PSM_AM_REQUEST_NOREPLY:
    case PSM_AM_REQUEST:
    case PSM_AM_REPLY:
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_dlen, tvb, local_offset + 3, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_nargs, tvb, local_offset + 3, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_hidx, tvb, local_offset + 2, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_msgseq, tvb, local_offset, 2, ENC_LITTLE_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_arg, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(PSM_header_tree, hf_opa_psm_arg, tvb, local_offset, 8, ENC_LITTLE_ENDIAN);
        local_offset += 8;
        break;
    }
    *offset = local_offset;
}

static void parse_IPvSix(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    call_dissector(ipv6_handle, tvb_new_subset_remaining(tvb, *offset), pinfo, tree);
    *offset = tvb_reported_length(tvb);
}

static int dissect_opa_9b(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *opa_packet;

    /* TVB to pass to opa header */
    tvbuff_t *opa_tvb;
    /* TVB to pass to infiniband header */
    tvbuff_t *infiniband_tvb;

    gint offset = 0;    /* Current Offset */
    gint ib_offset = 0; /* Offset to track if IB packet */
    gint captured_length, reported_length;
    guint8 lnh_val = 0;
    gboolean bthFollows = FALSE;
    gboolean parsePayload = FALSE;
    gint32 nextHeaderSequence = -1;
    guint8 nextHdr = 0, opCode = 0;
    guint8 baseVersion = 0;

    /* Infiniband Check */
    lnh_val = tvb_get_guint8(tvb, ib_offset + 1) & 0x3;
    if (lnh_val == 3) {
        nextHdr = tvb_get_guint8(tvb, ib_offset + 6);
        ib_offset += 40;
    }
    if (lnh_val == 2 || nextHdr == 0x1B) {
        opCode = tvb_get_guint8(tvb, ib_offset + 8);
        if (opCode == 0x64) {
            baseVersion = tvb_get_guint8(tvb, ib_offset + 28);
            if (baseVersion == 0x01) {
                infiniband_tvb = tvb_new_subset_remaining(tvb, offset);
                call_dissector(infiniband_handle, infiniband_tvb, pinfo, tree);
                return tvb_captured_length(tvb);
            }
        }
    }

    tree = proto_tree_get_parent_tree(tree);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Omni-Path");
    col_clear(pinfo->cinfo, COL_INFO);

    pinfo->srcport = pinfo->destport = 0xffffffff;

    opa_packet = proto_tree_add_item(tree, proto_opa_9b, tvb, offset, -1, ENC_NA);

    /* Headers Level Tree */
    tree = proto_item_add_subtree(opa_packet, ett_all_headers);
    parse_opa_9B_Header(tvb, pinfo, tree, &offset, &lnh_val);

    switch (lnh_val) {
    case 3: /* GLOBAL - GRH - Global Route Header */
        parse_opa_grh(tvb, pinfo, tree, &offset, &nextHdr);
        if (nextHdr != 0x1B) {   /* no BTH following. */
            break;
        }
    case 2: /* LOCAL - BTH - Base Transport Header */
        parse_opa_bth(tvb, pinfo, tree, &offset, &opCode);
        bthFollows = TRUE;
        break;
    case 1: /* NON OPA - IPv6 Packet */
        set_address(&pinfo->dst, AT_STRINGZ, (int)strlen("IPv6 over OPA Packet") + 1,
            wmem_strdup(pinfo->pool, "IPv6 over OPA Packet"));

        parse_IPvSix(tvb, pinfo, tree, &offset);

        break;
    case 0: /* RAW */

        break;
    default:
        break;
    }

    if (bthFollows) {
        /* Save transport type for identifying EoOPA payloads later */
        nextHeaderSequence = find_next_header_sequence((guint32)opCode);
        switch (nextHeaderSequence) {
        case RDETH_DETH_PAYLD:
            parse_RDETH(tvb, pinfo, tree, &offset);
            parse_DETH(tvb, pinfo, tree, &offset);

            parsePayload = TRUE;
            break;
        case RDETH_DETH_RETH_PAYLD:
            parse_RDETH(tvb, pinfo, tree, &offset);
            parse_DETH(tvb, pinfo, tree, &offset);
            parse_RETH(tvb, pinfo, tree, &offset);

            parsePayload = TRUE;
            break;
        case RDETH_DETH_IMMDT_PAYLD:
            parse_RDETH(tvb, pinfo, tree, &offset);
            parse_DETH(tvb, pinfo, tree, &offset);
            parse_IMMDT(tvb, pinfo, tree, &offset);

            parsePayload = TRUE;
            break;
        case RDETH_DETH_RETH_IMMDT_PAYLD:
            parse_RDETH(tvb, pinfo, tree, &offset);
            parse_DETH(tvb, pinfo, tree, &offset);
            parse_RETH(tvb, pinfo, tree, &offset);
            parse_IMMDT(tvb, pinfo, tree, &offset);

            parsePayload = TRUE;
            break;
        case RDETH_DETH_RETH:
            parse_RDETH(tvb, pinfo, tree, &offset);
            parse_DETH(tvb, pinfo, tree, &offset);
            parse_RETH(tvb, pinfo, tree, &offset);

            break;
        case RDETH_AETH_PAYLD:
            parse_RDETH(tvb, pinfo, tree, &offset);
            parse_AETH(tvb, pinfo, tree, &offset);

            parsePayload = TRUE;
            break;
        case RDETH_PAYLD:
            parse_RDETH(tvb, pinfo, tree, &offset);

            parsePayload = TRUE;
            break;
        case RDETH_AETH:
            parse_AETH(tvb, pinfo, tree, &offset);

            break;
        case RDETH_AETH_ATOMICACKETH:
            parse_RDETH(tvb, pinfo, tree, &offset);
            parse_AETH(tvb, pinfo, tree, &offset);
            parse_ATOMICACKETH(tvb, pinfo, tree, &offset);

            break;
        case RDETH_DETH_ATOMICETH:
            parse_RDETH(tvb, pinfo, tree, &offset);
            parse_DETH(tvb, pinfo, tree, &offset);
            parse_ATOMICETH(tvb, pinfo, tree, &offset);

            break;
        case RDETH_DETH:
            parse_RDETH(tvb, pinfo, tree, &offset);
            parse_DETH(tvb, pinfo, tree, &offset);

            break;
        case DETH_PAYLD:
            parse_DETH(tvb, pinfo, tree, &offset);

            parsePayload = TRUE;
            break;
        case PAYLD:

            parsePayload = TRUE;
            break;
        case IMMDT_PAYLD:
            parse_IMMDT(tvb, pinfo, tree, &offset);

            parsePayload = TRUE;
            break;
        case RETH_PAYLD:
            parse_RETH(tvb, pinfo, tree, &offset);

            parsePayload = TRUE;
            break;
        case RETH:
            parse_RETH(tvb, pinfo, tree, &offset);

            break;
        case AETH_PAYLD:
            parse_AETH(tvb, pinfo, tree, &offset);

            parsePayload = TRUE;
            break;
        case AETH:
            parse_AETH(tvb, pinfo, tree, &offset);

            break;
        case AETH_ATOMICACKETH:
            parse_AETH(tvb, pinfo, tree, &offset);
            parse_ATOMICACKETH(tvb, pinfo, tree, &offset);

            break;
        case ATOMICETH:
            parse_ATOMICETH(tvb, pinfo, tree, &offset);

            break;
        case IETH_PAYLD:
            parse_IETH(tvb, pinfo, tree, &offset);

            parsePayload = TRUE;
            break;
        case DETH_IMMDT_PAYLD:
            parse_DETH(tvb, pinfo, tree, &offset);
            parse_IMMDT(tvb, pinfo, tree, &offset);

            parsePayload = TRUE;
            break;
        case KDETH_PSM:
            parse_KDETH(tvb, pinfo, tree, &offset);
            parse_PSM(tvb, pinfo, tree, &offset, opCode);

            break;
        default:
            break;

        } /* END: switch (nextHeaderSequence) */

        if (parsePayload) {
            /* Pass to OPA MAD dissector */
            captured_length = tvb_captured_length_remaining(tvb, offset);
            reported_length = tvb_reported_length_remaining(tvb, offset);

            if (reported_length >= 4)
                reported_length -= 4;
            if (captured_length > reported_length)
                captured_length = reported_length;

            if (captured_length > 0) {
                opa_tvb = tvb_new_subset(tvb, offset, captured_length, reported_length);
                call_dissector(opa_mad_handle, opa_tvb, pinfo, tree);
                offset += captured_length;
            }
        }
    } /* END: if(bthFollows) */

    /* Display the ICRC */
    reported_length = tvb_reported_length_remaining(tvb, offset);
    if (reported_length != 4) {
        offset += reported_length - 4;
    }
    proto_tree_add_item(tree, hf_opa_9b_ICRC, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    return offset;
}
void proto_register_opa_9b(void)
{
    static hf_register_info hf[] = {
        /* L2Header(9B) */
        { &hf_opa_9B, {
                "Omni-Path 9B Header", "opa.9b",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_9B_service_channel, {
                "Service Channel", "opa.9b.sc",
                FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_opa_9B_link_version, {
                "Link Version", "opa.9b.linkversion",
                FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_opa_9B_service_level, {
                "Service Level", "opa.9b.sl",
                FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_opa_9B_reserved2, {
                "Reserved (2 bits)", "opa.9b.reserved2",
                FT_UINT8, BASE_HEX, NULL, 0x0C, NULL, HFILL }
        },
        { &hf_opa_9B_lnh, {
                "Link Next Header", "opa.9b.lnh",
                FT_UINT8, BASE_DEC, VALS(vals_opa_9b_lnh), 0x03, NULL, HFILL }
        },
        { &hf_opa_9B_dlid, {
                "Dest LID", "opa.9b.dlid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_9B_reserved3, {
                "Reserved (4 bits)", "opa.9b.reserved3",
                FT_UINT16, BASE_HEX, NULL, 0xF000, NULL, HFILL }
        },
        { &hf_opa_9B_packet_length, {
                "Packet Length", "opa.length",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_dw_to_b), 0x0FFF, NULL, HFILL }
        },
        { &hf_opa_9B_slid, {
                "Source LID", "opa.9b.slid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_9b_ICRC, {
                "Invariant CRC", "opa.9b.icrc",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* Global Route Header */
        { &hf_opa_grh, {
                "GRH - Global Route Header", "opa.grh",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_grh_ip_version, {
                "IP Version", "opa.grh.ipver",
                FT_UINT8, BASE_DEC, VALS(vals_opa_9b_grh_ipver), 0xF0, NULL, HFILL }
        },
        { &hf_opa_grh_traffic_class, {
                "Traffic Class", "opa.grh.tclass",
                FT_UINT16, BASE_DEC, NULL, 0x0FF0, NULL, HFILL }
        },
        { &hf_opa_grh_flow_label, {
                "Flow Label", "opa.grh.flowlabel",
                FT_UINT32, BASE_DEC, NULL, 0x000FFFFF, NULL, HFILL }
        },
        { &hf_opa_grh_payload_length, {
                "Payload Length", "opa.grh.paylen",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_grh_next_header, {
                "Next Header", "opa.grh.nxthdr",
                FT_UINT8, BASE_DEC, VALS(vals_opa_9b_grh_next_hdr), 0x0, NULL, HFILL }
        },
        { &hf_opa_grh_hop_limit, {
                "Hop Limit", "opa.grh.hoplmt",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_grh_source_gid, {
                "Source GID", "opa.grh.sgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_grh_destination_gid, {
                "Destination GID", "opa.grh.dgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* Base Transport Header */
        { &hf_opa_bth, {
                "BTH - Base Transport Header", "opa.bth",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_bth_opcode, {
                "Opcode", "opa.bth.opcode",
                FT_UINT8, BASE_HEX, VALS(vals_opa_bth_opcode), 0x0, NULL, HFILL }
        },
        { &hf_opa_bth_solicited_event, {
                "Solicited Event", "opa.bth.se",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80, NULL, HFILL }
        },
        { &hf_opa_bth_migreq, {
                "MigReq", "opa.bth.m",
                FT_BOOLEAN, 8, TFS(&tfs_opa_bth_migrated_notmigrated), 0x40, NULL, HFILL }
        },
        { &hf_opa_bth_pad_count, {
                "Pad Count", "opa.bth.padcnt",
                FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL }
        },
        { &hf_opa_bth_transport_header_version, {
                "Header Version", "opa.bth.tver",
                FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_opa_bth_partition_key, {
                "Partition Key", "opa.bth.p_key",
                FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_bth_fcn, {
                "FCN", "opa.bth.fcn",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80, NULL, HFILL }
        },
        { &hf_opa_bth_bcn, {
                "BCN", "opa.bth.bcn",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40, NULL, HFILL }
        },
        { &hf_opa_bth_Reserved8a, {
                "Reserved (6 bits)", "opa.bth.reserved8a",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_opa_bth_destination_qp, {
                "Destination Queue Pair", "opa.bth.destqp",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_bth_acknowledge_request, {
                "Acknowledge Request", "opa.bth.a",
                FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80, NULL, HFILL }
        },
        { &hf_opa_bth_packet_sequence_number, {
                "Packet Sequence Number", "opa.bth.psn",
                FT_UINT32, BASE_DEC, NULL, 0x7FFFFFFF, NULL, HFILL }
        },

        /* Reliable Datagram Extended Transport Header (RDETH) */
        { &hf_opa_RDETH, {
                "RDETH - Reliable Datagram Extended Transport Header", "opa.rdeth",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_RDETH_reserved8, {
                "Reserved (8 bits)", "opa.rdeth.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_RDETH_ee_context, {
                "EE Context", "opa.rdeth.eecnxt",
                FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        /* Datagram Extended Transport Header (DETH) */
        { &hf_opa_DETH, {
                "DETH - Datagram Extended Transport Header", "opa.deth",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DETH_queue_key, {
                "Queue Key", "opa.deth.q_key",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DETH_reserved8, {
                "Reserved (8 bits)", "opa.deth.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DETH_source_qp, {
                "Source Queue Pair", "opa.deth.srcqp",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* RDMA Extended Transport Header (RETH) */
        { &hf_opa_RETH, {
                "RETH - RDMA Extended Transport Header", "opa.reth",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_RETH_virtual_address, {
                "Virtual Address", "opa.reth.va",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_RETH_remote_key, {
                "Remote Key", "opa.reth.r_key",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_RETH_dma_length, {
                "DMA Length", "opa.reth.dmalen",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        /* Atomic Extended Transport Header (AtomicETH) */
        { &hf_opa_AtomicETH, {
                "AtomicETH - Atomic Extended Transport Header", "opa.atomiceth",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_AtomicETH_virtual_address, {
                "Virtual Address", "opa.atomiceth.va",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_AtomicETH_remote_key, {
                "Remote Key", "opa.atomiceth.r_key",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_AtomicETH_swap_or_add_data, {
                "Swap (Or Add) Data", "opa.atomiceth.swapdt",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_AtomicETH_compare_data, {
                "Compare Data", "opa.atomiceth.cmpdt",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        /* ACK Extended Transport Header (AETH) */
        { &hf_opa_AETH, {
                "AETH - ACK Extended Transport Header", "opa.aeth",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_AETH_syndrome, {
                "Syndrome", "opa.aeth.syndrome",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_AETH_message_sequence_number, {
                "Message Sequence Number", "opa.aeth.msn",
                FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        /* Atomic ACK Extended Transport Header (AtomicAckETH) */
        { &hf_opa_AtomicAckETH, {
                "AtomicAckETH - Atomic ACK Extended Transport Header", "opa.atomicacketh",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_AtomicAckETH_original_remote_data, {
                "Original Remote Data", "opa.atomicacketh.origremdt",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        /* Immediate Extended Transport Header (ImmDT) */
        { &hf_opa_IMMDT, {
                "IMMDT - Immediate Extended Transport Header", "opa.immdt",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_IMMDT_data, {
                "Immediate Data", "opa.immdt.data",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* Invalidate Extended Transport Header (IETH) */
        { &hf_opa_IETH, {
                "IETH - Invalidate Extended Transport Header", "opa.ieth",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_IETH_r_key, {
                "RKey", "opa.ieth.r_key",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* Key Datagram Extended Transport Header (KDETH) */
        { &hf_opa_KDETH, {
                "KDETH - Key Datagram Extended Transport Header", "opa.kdeth",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_KDETH_kver, {
                "KDETH Version Field", "opa.kdeth.kver",
                FT_UINT32, BASE_HEX, NULL, 0xC0000000, NULL, HFILL }
        },
        { &hf_opa_KDETH_sh, {
                "SuppressHeader", "opa.kdeth.sh",
                FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL }
        },
        { &hf_opa_KDETH_intr, {
                "InterruptBit", "opa.kdeth.intr",
                FT_BOOLEAN, 32, NULL, 0x10000000, NULL, HFILL }
        },
        { &hf_opa_KDETH_tidctrl, {
                "TokenIDCtrl", "opa.kdeth.tidctrl",
                FT_UINT32, BASE_HEX, NULL, 0x0C000000, NULL, HFILL }
        },
        { &hf_opa_KDETH_tid, {
                "TokenID", "opa.kdeth.tid",
                FT_UINT32, BASE_HEX, NULL, 0x03FF0000, NULL, HFILL }
        },
        { &hf_opa_KDETH_offset_mode, {
                "Offset Mode", "opa.kdeth.offsetmode",
                FT_BOOLEAN, 32, TFS(&tfs_opa_kdeth_offset_32_64), 0x00008000, NULL, HFILL }
        },
        { &hf_opa_KDETH_offset, {
                "Offset", "opa.kdeth.offset",
                FT_UINT32, BASE_HEX, NULL, 0x00007FFF, NULL, HFILL }
        },
        { &hf_opa_KDETH_hcrc, {
                "HCRC", "opa.kdeth.hcrc",
                FT_UINT32, BASE_HEX, NULL, 0xFFFF0000, NULL, HFILL }
        },
        { &hf_opa_KDETH_j_key, {
                "J_Key", "opa.kdeth.j_key",
                FT_UINT32, BASE_HEX, NULL, 0x0000FFFF, NULL, HFILL }
        },

        /* PSM */
        { &hf_opa_psm, {
                "PSM Header", "opa.psm",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_a, {
                "ACKFlag", "opa.psm.a",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_psm_ackpsn, {
                "ACKPSN", "opa.psm.ackpsn",
                FT_UINT32, BASE_DEC, NULL, 0x7FFF, NULL, HFILL }
        },
        { &hf_opa_psm_flags, {
                "Flags", "opa.psm.flags",
                FT_UINT8, BASE_DEC, NULL, 0xFC, NULL, HFILL }
        },
        { &hf_opa_psm_commidx, {
                "CommIdx", "opa.psm.commidx",
                FT_UINT32, BASE_HEX, NULL, 0x3FFF, NULL, HFILL }
        },
        { &hf_opa_psm_flowid, {
                "FlowId", "opa.psm.flowid",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        /* PSM opcode specific */
        { &hf_opa_psm_msglen, {
                "MsgLen", "opa.psm.msglen",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_msgseq, {
                "MsqSeq", "opa.psm.msgseq",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_tag, {
                "Tag", "opa.psm.tag",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_msgdata, {
                "MsqData", "opa.psm.msgdata",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_short_msglen, {
                "MsgLen", "opa.psm.short.msglen",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_paylen, {
                "PayLen", "opa.psm.paylen",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_offset, {
                "Offset", "opa.psm.offset",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_sreqidx, {
                "SreqIdx", "opa.psm.sreqidx",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_rreqidx, {
                "RreqIdx", "opa.psm.rreqidx",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_rdescid, {
                "RdescId", "opa.psm.rdescid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_sdescid, {
                "SdescId", "opa.psm.sdescid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_psn, {
                "PSN", "opa.psm.psn",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_hostipv4, {
                "HostIPv4Addr", "opa.psm.hostipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_hostpid, {
                "HostPid", "opa.psm.hostpid",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_dlen, {
                "Datalength", "opa.psm.dlen",
                FT_UINT8, BASE_DEC, NULL, 0x38, NULL, HFILL }
        },
        { &hf_opa_psm_nargs, {
                "NumberArgs", "opa.psm.nargs",
                FT_UINT32, BASE_DEC, NULL, 0x07, NULL, HFILL }
        },
        { &hf_opa_psm_hidx, {
                "HandlerIndex", "opa.psm.hidx",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_arg, {
                "Argument", "opa.psm.arg",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_psm_payload, {
                "Payload", "opa.psm.payload",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_all_headers,
        &ett_9b,
        &ett_grh,
        &ett_bth,
        &ett_rdeth,
        &ett_deth,
        &ett_reth,
        &ett_atomiceth,
        &ett_aeth,
        &ett_atomicacketh,
        &ett_immdt,
        &ett_ieth,
        &ett_kdeth,
        &ett_psm
    };

    proto_opa_9b = proto_register_protocol("Intel Omni-Path", "OPA", "opa");
    opa_9b_handle = register_dissector("opa", dissect_opa_9b, proto_opa_9b);

    proto_register_field_array(proto_opa_9b, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_opa_9b(void)
{
    ipv6_handle             = find_dissector("ipv6");
    opa_mad_handle          = find_dissector("opa.mad");
    infiniband_handle       = find_dissector("infiniband");

    /* announce an anonymous Omni-Path 9B dissector */
    dissector_add_uint("erf.types.type", ERF_TYPE_OPA_9B, opa_9b_handle);

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
