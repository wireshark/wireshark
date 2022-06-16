/* packet-opensafety.c
 *
 *   openSAFETY is a machine-safety protocol, encapsulated in modern fieldbus
 *   and industrial ethernet solutions.
 *
 *   For more information see http://www.open-safety.org
 *
 *   This dissector currently supports the following transport protocols
 *
 *   - openSAFETY using POWERLINK
 *   - openSAFETY using SercosIII
 *   - openSAFETY using Generic UDP
 *   - openSAFETY using Modbus/TCP
 *   - openSAFETY using (openSAFETY over UDP) transport
 *   - openSAFETY using ProfiNet IO
 *
 * By Roland Knall <roland.knall@br-automation.com>
 * Copyright 2011-2012 Bernecker + Rainer Industrie-Elektronik Ges.m.b.H.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/strutil.h>
#include <epan/tap.h>
#include <epan/conversation_table.h>

#include <wsutil/crc8.h>
#include <wsutil/crc16.h>

#include "packet-frame.h"
#include "packet-opensafety.h"

/* General definitions */

/* Used to clasify incoming traffic and presort the heuristic */
#define OPENSAFETY_ANY_TRANSPORT 0x00
#define OPENSAFETY_CYCLIC_DATA   0x01
#define OPENSAFETY_ACYCLIC_DATA  0x02

#ifndef OPENSAFETY_PINFO_CONST_DATA
#define OPENSAFETY_PINFO_CONST_DATA 0xAABBCCDD
#endif

#define OPENSAFETY_REQUEST  TRUE
#define OPENSAFETY_RESPONSE FALSE

/* SPDO Feature Flags
 * Because featureflags are part of the TR field (which is only 6 bit), the field get's shifted */
#define OPENSAFETY_SPDO_FEAT_40BIT_AVAIL   0x20
#define OPENSAFETY_SPDO_FEAT_40BIT_USED    0x10
#define OPENSAFETY_SPDO_FEATURE_FLAGS      (OPENSAFETY_SPDO_FEAT_40BIT_USED | OPENSAFETY_SPDO_FEAT_40BIT_AVAIL)

#define OSS_FRAME_POS_ADDR   0
#define OSS_FRAME_POS_ID     1
#define OSS_FRAME_POS_LEN    2
#define OSS_FRAME_POS_CT     3
#define OSS_FRAME_POS_DATA   4

#define OSS_PAYLOAD_MAXSIZE_FOR_CRC8        0x08
#define OSS_SLIM_FRAME_WITH_CRC8_MAXSIZE    0x13   /* 19 */
#define OSS_SLIM_FRAME2_WITH_CRC8           0x06   /*  6 */
#define OSS_SLIM_FRAME2_WITH_CRC16          0x07   /*  7 */
#define OSS_MINIMUM_LENGTH                  0x0b   /* 11 */

#define OPENSAFETY_SPDO_CONNECTION_VALID  0x04

#define OPENSAFETY_SOD_DVI   0x1018
#define OPENSAFETY_SOD_RXMAP 0x1800
#define OPENSAFETY_SOD_TXMAP 0xC000

#define OSS_FRAME_ADDR(f, offset)        (f[OSS_FRAME_POS_ADDR + offset] + ((guint8)((f[OSS_FRAME_POS_ADDR + offset + 1]) << 6) << 2))
#define OSS_FRAME_ID(f, offset)          (f[OSS_FRAME_POS_ID + offset] & 0xFC )
#define OSS_FRAME_LENGTH(f, offset)      (f[OSS_FRAME_POS_LEN + offset])
#define OSS_FRAME_FIELD(f, position)     (f[position])

#define OSS_FRAME_ADDR_T(f, offset)        (tvb_get_guint8(f, OSS_FRAME_POS_ADDR + offset) + ((guint8)((tvb_get_guint8( f, OSS_FRAME_POS_ADDR + offset + 1)) << 6) << 2))
#define OSS_FRAME_ADDR_T2(f, offset, su1, su2)        (( tvb_get_guint8(f, OSS_FRAME_POS_ADDR + offset) ^ su1) + ((guint8)(((tvb_get_guint8( f, OSS_FRAME_POS_ADDR + offset + 1) ^ su2)) << 6) << 2))
#define OSS_FRAME_ID_T(f, offset)          (tvb_get_guint8(f, OSS_FRAME_POS_ID + offset) & 0xFC)
#define OSS_FRAME_LENGTH_T(f, offset)      (tvb_get_guint8(f, OSS_FRAME_POS_LEN + offset))

static int proto_opensafety = -1;

static gint ett_opensafety = -1;
static gint ett_opensafety_checksum = -1;
static gint ett_opensafety_snmt = -1;
static gint ett_opensafety_ssdo = -1;
static gint ett_opensafety_spdo = -1;
static gint ett_opensafety_spdo_flags = -1;
static gint ett_opensafety_ssdo_sacmd = -1;
static gint ett_opensafety_ssdo_payload = -1;
static gint ett_opensafety_ssdo_sodentry = -1;
static gint ett_opensafety_ssdo_extpar = -1;
static gint ett_opensafety_sod_mapping = -1;
static gint ett_opensafety_node = -1;

static expert_field ei_payload_length_not_positive = EI_INIT;
static expert_field ei_payload_unknown_format = EI_INIT;
static expert_field ei_crc_slimssdo_instead_of_spdo = EI_INIT;
static expert_field ei_crc_frame_1_invalid = EI_INIT;
static expert_field ei_crc_frame_1_valid_frame2_invalid = EI_INIT;
static expert_field ei_crc_frame_2_invalid = EI_INIT;
static expert_field ei_crc_frame_2_unknown_scm_udid = EI_INIT;
static expert_field ei_crc_frame_2_scm_udid_encoded = EI_INIT;
static expert_field ei_message_unknown_type = EI_INIT;
static expert_field ei_message_reassembly_size_differs_from_header = EI_INIT;
static expert_field ei_message_spdo_address_invalid = EI_INIT;
static expert_field ei_message_id_field_mismatch = EI_INIT;
static expert_field ei_scmudid_autodetected = EI_INIT;
static expert_field ei_scmudid_invalid_preference = EI_INIT;
static expert_field ei_scmudid_unknown = EI_INIT;
static expert_field ei_40bit_default_domain = EI_INIT;

static int hf_oss_msg = -1;
static int hf_oss_msg_direction = -1;
static int hf_oss_msg_category = -1;
static int hf_oss_msg_node = -1;
static int hf_oss_msg_network = -1;
static int hf_oss_msg_sender = -1;
static int hf_oss_msg_receiver = -1;
static int hf_oss_length= -1;
static int hf_oss_crc = -1;
static int hf_oss_byte_offset = -1;

static int hf_oss_crc_valid = -1;
static int hf_oss_crc2_valid = -1;
static int hf_oss_crc_type  = -1;

static int hf_oss_snmt_slave = -1;
static int hf_oss_snmt_master = -1;
static int hf_oss_snmt_udid = -1;
static int hf_oss_snmt_scm = -1;
static int hf_oss_snmt_tool = -1;
static int hf_oss_snmt_service_id = -1;
static int hf_oss_snmt_error_group = -1;
static int hf_oss_snmt_error_code = -1;
static int hf_oss_snmt_param_type = -1;
static int hf_oss_snmt_ext_addsaddr = -1;
static int hf_oss_snmt_ext_addtxspdo = -1;
static int hf_oss_snmt_ext_initct = -1;

static int hf_oss_ssdo_server = -1;
static int hf_oss_ssdo_client = -1;
static int hf_oss_ssdo_sano = -1;
static int hf_oss_ssdo_sacmd = -1;
static int hf_oss_ssdo_sod_index = -1;
static int hf_oss_ssdo_sod_subindex = -1;
static int hf_oss_ssdo_payload = -1;
static int hf_oss_ssdo_payload_size = -1;
static int hf_oss_ssdo_sodentry_size = -1;
static int hf_oss_ssdo_sodentry_data = -1;
static int hf_oss_ssdo_abort_code = -1;
static int hf_oss_ssdo_preload_queue = -1;
static int hf_oss_ssdo_preload_error = -1;

static int hf_oss_sod_par_timestamp = -1;
static int hf_oss_sod_par_checksum = -1;
static int hf_oss_ssdo_sodmapping = -1;
static int hf_oss_ssdo_sodmapping_bits = -1;

static int hf_oss_ssdo_sacmd_access_type = -1;
static int hf_oss_ssdo_sacmd_preload = -1;
static int hf_oss_ssdo_sacmd_abort_transfer = -1;
static int hf_oss_ssdo_sacmd_segmentation = -1;
static int hf_oss_ssdo_sacmd_toggle = -1;
static int hf_oss_ssdo_sacmd_initiate = -1;
static int hf_oss_ssdo_sacmd_end_segment = -1;
#if 0
static int hf_oss_ssdo_sacmd_reserved = -1;
#endif

static int hf_oss_ssdo_extpar_parset = -1;
static int hf_oss_ssdo_extpar_version = -1;
static int hf_oss_ssdo_extpar_saddr = -1;
static int hf_oss_ssdo_extpar_length = -1;
static int hf_oss_ssdo_extpar_crc = -1;
static int hf_oss_ssdo_extpar_tstamp = -1;
static int hf_oss_ssdo_extpar_data = -1;
static int hf_oss_ssdo_extpar = -1;

static int hf_oss_scm_udid = -1;
static int hf_oss_scm_udid_auto = -1;
static int hf_oss_scm_udid_valid = -1;

static int hf_oss_spdo_direction = -1;
static int hf_oss_spdo_connection_valid = -1;
static int hf_oss_spdo_ct = -1;
static int hf_oss_spdo_ct_40bit = -1;
static int hf_oss_spdo_time_request = -1;
static int hf_oss_spdo_time_request_to = -1;
static int hf_oss_spdo_time_request_from = -1;
static int hf_oss_spdo_feature_flags = -1;
static int hf_oss_spdo_feature_flag_40bit_available = -1;
static int hf_oss_spdo_feature_flag_40bit_used = -1;

static int hf_oss_fragments = -1;
static int hf_oss_fragment = -1;
static int hf_oss_fragment_overlap = -1;
static int hf_oss_fragment_overlap_conflicts = -1;
static int hf_oss_fragment_multiple_tails = -1;
static int hf_oss_fragment_too_long_fragment = -1;
static int hf_oss_fragment_error = -1;
static int hf_oss_fragment_count = -1;
static int hf_oss_reassembled_in = -1;
static int hf_oss_reassembled_length = -1;
static int hf_oss_reassembled_data = -1;

static gint ett_opensafety_ssdo_fragment = -1;
static gint ett_opensafety_ssdo_fragments = -1;

/* Definitions for the openSAFETY ov. UDP transport protocol */
static dissector_handle_t opensafety_udptransport_handle = NULL;

static int proto_oss_udp_transport = -1;

static int hf_oss_udp_transport_version = -1;
static int hf_oss_udp_transport_flags_type = -1;
static int hf_oss_udp_transport_counter = -1;
static int hf_oss_udp_transport_sender = -1;
static int hf_oss_udp_transport_datapoint = -1;
static int hf_oss_udp_transport_length= -1;

static gint ett_oss_udp_transport = -1;

static const true_false_string tfs_udp_transport_cyclic_acyclic = { "Cyclic", "ACyclic" };
static guint global_network_oss_udp_port = OPENSAFETY_UDP_PORT;

static int opensafety_tap = -1;

static const fragment_items oss_frag_items = {
    /* Fragment subtrees */
    &ett_opensafety_ssdo_fragment,
    &ett_opensafety_ssdo_fragments,
    /* Fragment fields */
    &hf_oss_fragments,
    &hf_oss_fragment,
    &hf_oss_fragment_overlap,
    &hf_oss_fragment_overlap_conflicts,
    &hf_oss_fragment_multiple_tails,
    &hf_oss_fragment_too_long_fragment,
    &hf_oss_fragment_error,
    &hf_oss_fragment_count,
    /* Reassembled in field */
    &hf_oss_reassembled_in,
    /* Reassembled length field */
    &hf_oss_reassembled_length,
    /* Reassembled data */
    &hf_oss_reassembled_data,
    /* Tag */
    "Message fragments"
};

static const char *global_scm_udid = "00:00:00:00:00:00";

static dissector_handle_t data_dissector = NULL;
static dissector_handle_t opensafety_udpdata_handle = NULL;
static dissector_handle_t opensafety_mbtcp_handle = NULL;
static dissector_handle_t opensafety_pnio_handle = NULL;

static gboolean global_display_intergap_data   = FALSE;
static gboolean global_scm_udid_autoset        = TRUE;
static gboolean global_udp_frame2_first        = FALSE;
static gboolean global_siii_udp_frame2_first   = FALSE;
static gboolean global_mbtcp_big_endian        = FALSE;
static guint global_network_udp_port           = OPENSAFETY_UDP_PORT;
static guint global_network_udp_port_sercosiii = OPENSAFETY_UDP_PORT_SIII;
static gboolean global_classify_transport      = TRUE;

static gboolean global_enable_udp    = TRUE;
static gboolean global_enable_mbtcp  = TRUE;

static gboolean global_opensafety_debug_verbose = FALSE;

static const char * global_filter_nodes = "";
static gboolean global_show_only_node_in_filter = TRUE;
static wmem_list_t * global_filter_list = NULL;

static gboolean heuristic_siii_dissection_enabled = TRUE;

static heur_dissector_list_t heur_opensafety_spdo_subdissector_list;

static gboolean bDissector_Called_Once_Before = FALSE;
/* Using local_scm_udid as read variable for global_scm_udid, to
 * enable automatic detection of scm udid */
static char *local_scm_udid = NULL;

static reassembly_table os_reassembly_table;

/* Resets the dissector in case the dissection is malformed and the dissector crashes */
static void
reset_dissector(void)
{
    bDissector_Called_Once_Before = FALSE;
}

static void
setup_dissector(void)
{
    heur_dtbl_entry_t * heur_entry = NULL;

    /* create list if it does not exist, but clean existing elements anyway,
     * as options might have changed */
    global_filter_list = wmem_list_new(wmem_file_scope());

    gchar ** vector = wmem_strsplit(wmem_file_scope(), global_filter_nodes, ",", -1);
    for (; NULL != *vector; vector++ )
    {
        if ( *vector && g_ascii_strtoll(*vector, NULL, 10) > 0 )
            wmem_list_append(global_filter_list, GINT_TO_POINTER(g_ascii_strtoll(*vector, NULL, 10)));
    }

    heur_entry = find_heur_dissector_by_unique_short_name("opensafety_sercosiii");
    if ( heur_entry != NULL )
        heuristic_siii_dissection_enabled = heur_entry->enabled;
}

static void
cleanup_dissector(void)
{
    local_scm_udid = NULL;

    if ( global_filter_list )
    {
        wmem_destroy_list(global_filter_list);
        global_filter_list = NULL;
    }
}

void proto_register_opensafety(void);
void proto_reg_handoff_opensafety(void);

/* Conversation functions */

/* This is defined by the specification. The Address field is 10 bits long, and the node with the number
 *  1 is always the SCM, therefore ( 2 ^ 10 ) - 1 nodes can be addressed. We use 2 ^ 10 here, because the
 *  SCM can talk to himself (Assign SADR for instance ) */
/* #define MAX_NUMBER_OF_SAFETY_NODES      ( 1 << 10 ) */

/* Tracks the information that the packet pinfo has been received by receiver, and adds that information to the tree, using pos, as
 * byte position in the PDU */
static void
opensafety_packet_node(tvbuff_t * message_tvb, packet_info *pinfo, proto_tree *tree,
        gint hf_field, guint16 saddr, guint16 posInFrame, guint16 posSdnInFrame, guint16 sdn )
{
    proto_item *psf_item = NULL;
    proto_tree *psf_tree  = NULL;

    psf_item = proto_tree_add_uint(tree, hf_field, message_tvb, posInFrame, 2, saddr);
    psf_tree = proto_item_add_subtree(psf_item, ett_opensafety_node);
    psf_item = proto_tree_add_uint(psf_tree, hf_oss_msg_node, message_tvb, posInFrame, 2, saddr);
    proto_item_set_generated(psf_item);

    if ( sdn > 0 )
    {
        psf_item = proto_tree_add_uint(psf_tree, hf_oss_msg_network, message_tvb,
                posSdnInFrame, 2, sdn);
    } else if ( sdn <= 0 ) {
        psf_item = proto_tree_add_uint(psf_tree, hf_oss_msg_network, message_tvb,
                posSdnInFrame, 2, sdn * -1);
        expert_add_info(pinfo, psf_item, &ei_scmudid_unknown );
    }
    proto_item_set_generated(psf_item);
}

static void
opensafety_packet_receiver(tvbuff_t * message_tvb, packet_info *pinfo, proto_tree *tree, proto_item *opensafety_item,
        opensafety_packet_info *packet, guint16 recv,
        guint16 posInFrame, guint16 posSdnInFrame, guint16 sdn )
{
    packet->receiver = recv;
    if ( sdn > 0 )
        packet->sdn = sdn;

    opensafety_packet_node (message_tvb, pinfo, tree, hf_oss_msg_receiver, recv, posInFrame, posSdnInFrame, sdn );
    proto_item_append_text(opensafety_item, ", Dst: 0x%03X (%d)", recv, recv);
}

/* Tracks the information that the packet pinfo has been sent by sender, and received by everyone else, and adds that information to
 * the tree, using pos, as byte position in the PDU */
static void
opensafety_packet_sender(tvbuff_t * message_tvb, packet_info *pinfo, proto_tree *tree, proto_item *opensafety_item,
        opensafety_packet_info *packet, guint16 sender,
        guint16 posInFrame, guint16 posSdnInFrame, guint16 sdn )
{
    packet->sender = sender;
    if ( sdn > 0 )
        packet->sdn = sdn;

    opensafety_packet_node (message_tvb, pinfo, tree, hf_oss_msg_sender, sender, posInFrame, posSdnInFrame, sdn );
    proto_item_append_text(opensafety_item, ", Src: 0x%03X (%d)", sender, sender);
}

/* Tracks the information that the packet pinfo has been sent by sender, and received by receiver, and adds that information to
 * the tree, using pos for the sender and pos2 for the receiver, as byte position in the PDU */
static void
opensafety_packet_sendreceiv(tvbuff_t * message_tvb, packet_info *pinfo, proto_tree *tree, proto_item *opensafety_item,
        opensafety_packet_info *packet, guint16 send, guint16 pos,
        guint16 recv, guint16 pos2, guint16 posnet, guint16 sdn)
{
        opensafety_packet_receiver(message_tvb, pinfo, tree, opensafety_item, packet, recv, pos2, posnet, sdn);
        opensafety_packet_sender(message_tvb, pinfo, tree, opensafety_item, packet, send, pos, posnet, sdn);
}

static proto_item *
opensafety_packet_response(tvbuff_t *message_tvb, proto_tree *sub_tree, opensafety_packet_info *packet, gboolean isResponse)
{
    proto_item *item = NULL;
    guint8 b_id = 0;

    if ( packet->msg_type != OPENSAFETY_SPDO_MESSAGE_TYPE )
    {
        proto_tree_add_item(sub_tree, hf_oss_msg, message_tvb,
            OSS_FRAME_POS_ID + packet->frame.subframe1, 1, ENC_NA );
    }
    else
    {
        /* SPDOs code the connection valid bit on offset 0x04. SSDO and SNMT frames use this
         * bit for messages. Therefore setting a bitmask on the hf-field would not work. */
        b_id = OSS_FRAME_ID_T(message_tvb, packet->frame.subframe1) & 0xF8;
        proto_tree_add_uint(sub_tree, hf_oss_msg, message_tvb, OSS_FRAME_POS_ID + packet->frame.subframe1, 1, b_id);
    }

    item = proto_tree_add_item(sub_tree, packet->msg_type != OPENSAFETY_SPDO_MESSAGE_TYPE ? hf_oss_msg_direction : hf_oss_spdo_direction,
            message_tvb, OSS_FRAME_POS_ID + packet->frame.subframe1, 1, ENC_NA);
    if ( ! isResponse )
        packet->is_request = TRUE;

    return item;
}

static proto_tree *
opensafety_packet_payloadtree(packet_info *pinfo, tvbuff_t *message_tvb, proto_tree *opensafety_tree,
        opensafety_packet_info *packet, gint ett_tree)
{
    proto_item *item = NULL;

    item = proto_tree_add_item(opensafety_tree, hf_oss_msg_category, message_tvb, OSS_FRAME_POS_ID + packet->frame.subframe1, 1, ENC_NA );
    proto_item_set_generated(item);

    if ( packet->msg_type == OPENSAFETY_SNMT_MESSAGE_TYPE)
        packet->payload.snmt = wmem_new0(pinfo->pool, opensafety_packet_snmt);
    else if ( packet->msg_type == OPENSAFETY_SSDO_MESSAGE_TYPE || packet->msg_type == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
    {
        packet->payload.ssdo = wmem_new0(pinfo->pool, opensafety_packet_ssdo);
        if ( packet->msg_type == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
            packet->payload.ssdo->is_slim = TRUE;
    }
    else if ( packet->msg_type == OPENSAFETY_SPDO_MESSAGE_TYPE )
        packet->payload.spdo = wmem_new0(pinfo->pool, opensafety_packet_spdo);

    return proto_item_add_subtree(item, ett_tree);
}

static guint16
findFrame1Position ( packet_info *pinfo, tvbuff_t *message_tvb, guint16 byte_offset, guint8 dataLength, gboolean checkIfSlimMistake )
{
    guint16  i_wFrame1Position                   = 0;
    guint16  i_payloadLength, i_calculatedLength = 0;
    guint16  i_offset                            = 0, calcCRC = 0, frameCRC = 0;
    guint8   b_tempByte                          = 0;
    guint8  *bytes = NULL;

    /*
     * First, a normal package is assumed. Calculation of frame 1 position is
     * pretty easy, because, the length of the whole package is 11 + 2*n + 2*o, which
     * results in frame 1 start at (6 + n + o), which is length / 2 + 1
     */
    i_wFrame1Position = dataLength / 2 + 1;
    i_payloadLength = tvb_get_guint8(message_tvb, byte_offset + i_wFrame1Position + 2 );
    /* Calculating the assumed frame length, taking CRC8/CRC16 into account */
    i_calculatedLength = i_payloadLength * 2 + 11 + 2 * (i_payloadLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 ? 1 : 0);

    /* To prevent miscalculations, where by chance the byte at [length / 2] + 3 is a value matching a possible payload length,
     * but in reality the frame is a slim ssdo, the CRC of frame 1 gets checked additionally. This check
     * is somewhat time consuming, so it will only run if the normal check led to a mistake detected along the line */
    if ( checkIfSlimMistake && i_calculatedLength == dataLength )
    {
        if (dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8)
            frameCRC = tvb_get_letohs(message_tvb,  byte_offset + i_wFrame1Position + dataLength + OSS_FRAME_POS_DATA);
        else
            frameCRC = tvb_get_guint8(message_tvb,  byte_offset + i_wFrame1Position + dataLength + OSS_FRAME_POS_DATA);

        bytes = (guint8*)tvb_memdup(pinfo->pool, message_tvb, byte_offset + i_wFrame1Position, dataLength + 4);
        if ( dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 )
        {
            calcCRC = crc16_0x755B(bytes, dataLength + 4, 0);
            if ( frameCRC != calcCRC )
                calcCRC = crc16_0x5935(bytes, dataLength + 4, 0);
        }
        else
            calcCRC = crc8_0x2F(bytes, dataLength + 4, 0);

        /* if the calculated crc does not match the detected, the package is not a normal openSAFETY package */
        if ( frameCRC != calcCRC )
            dataLength = 0;
    }

    /* If the calculated length differs from the given length, a slim package is assumed. */
    if ( i_calculatedLength != dataLength )
    {
        /* possible slim package */
        i_wFrame1Position = 0;
        /*
         * Slim packages have a fixed sublength of either 6 bytes for frame 2 in
         * case of crc8 and 7 bytes in case of crc16
         */
        i_offset = OSS_SLIM_FRAME2_WITH_CRC8 + ( dataLength < (OSS_SLIM_FRAME_WITH_CRC8_MAXSIZE + 1) ? 0 : 1 );
        /* Last 2 digits belong to addr, therefore have to be cleared */
        b_tempByte = ( tvb_get_guint8 ( message_tvb, byte_offset + i_offset + 1 ) ) & 0xFC;

        /* If the id byte xor 0xE8 is 0, we have a slim package */
        if ( ( ( b_tempByte ^ OPENSAFETY_MSG_SSDO_SLIM_SERVICE_REQUEST ) == 0 ) ||
             ( ( b_tempByte ^ OPENSAFETY_MSG_SSDO_SLIM_SERVICE_RESPONSE ) == 0 ) )
        {
            /* Slim package found */
            i_wFrame1Position = i_offset;
        }
    }

    return i_wFrame1Position;
}

static gboolean findSafetyFrame ( packet_info *pinfo, tvbuff_t *message_tvb, guint u_Offset, gboolean b_frame2first,
        guint *u_frameOffset, guint *u_frameLength, opensafety_packet_info *packet )
{
    guint     ctr, rem_length;
    guint16   crc, f2crc, calcCrc = 0;
    guint8    b_Length = 0, b_CTl = 0, crcOffset = 0, crc1Type = 0;
    guint8   *bytes;
    guint     b_ID = 0;
    gboolean  found;

    found = FALSE;
    ctr = u_Offset;
    rem_length = tvb_reported_length_remaining (message_tvb, ctr);

    /* Search will allways start at the second byte of the frame ( cause it determines )
     * the type of package and therefore everything else. Therefore the mininmum length - 1
     * is the correct minimum length */
    while ( rem_length >= ( OSS_MINIMUM_LENGTH - 1 ) )
    {
        /* The ID byte must ALWAYS be the second byte, therefore 0 is invalid,
         * also, the byte we want to access, must at least exist, otherwise,
         * the frame is not detectable as an openSAFETY frame.
         * We check for ID and length */
        if ( ctr != 0 && tvb_bytes_exist(message_tvb, ctr, 2) )
        {
            *u_frameLength = 0;
            *u_frameOffset = 0;

            crcOffset = 0;
            b_ID = tvb_get_guint8(message_tvb, ctr );

            if ( b_ID != 0x0 )
            {
                b_Length = tvb_get_guint8(message_tvb, ctr + 1 );

                /* 0xFF is often used, but always false, otherwise start detection, if the highest
                 *  bit is set */
                if ( ( b_ID != 0xFF ) && ( b_ID & 0x80 ) )
                {
                    /* The rem_length value might be poluted, due to the else statement of
                     * above if-decision (frame at end position detection). Therefore we
                     * calculate it here again, to have a sane value */
                    rem_length = tvb_reported_length_remaining(message_tvb, ctr);

                    /* Plausability check on length */
                    if ( (guint)( b_Length * 2 ) < ( rem_length + OSS_MINIMUM_LENGTH ) )
                    {

                        /* The calculated length must fit, but for the CRC16 check, also the calculated length
                         * plus the CRC16 end position must fit in the remaining length */
                        if ( ( b_Length <= (guint) 8 && ( b_Length <= rem_length ) ) ||
                            ( b_Length > (guint) 8 && ( ( b_Length + (guint) 5 ) <= rem_length ) ) )
                        {
                            /* Ensure, that the correct length for CRC calculation
                             * still exists in byte stream, so that we can calculate the crc */
                            if ( tvb_bytes_exist(message_tvb, ctr - 1, b_Length + 5) )
                            {
                                /* An openSAFETY command has to have a high-byte range between 0x0A and 0x0E
                                 *  b_ID & 0x80 took care of everything underneath, we check for 0x09 and 0x0F,
                                 *  as they remain the only values left, which are not valid */
                                if ( ( ( b_ID >> 4 ) != 0x09 ) && ( ( b_ID >> 4 ) != 0x0F ) )
                                {
                                    /* Read CRC from position */
                                    crc = tvb_get_guint8(message_tvb, ctr + 3 + b_Length );

                                    /* There exists some false positives, where the only possible
                                     * data information in the frame is the ID and the ADDR fields.
                                     * The rest of the fields in frame 1 are zeroed out. The packet
                                     * must be filtered out and may not be used. To detect it, we
                                     * check for the CT value, which, if zero indicates strongly
                                     * that this is false-positive. */
                                    b_CTl = tvb_get_guint8(message_tvb, ctr + 2 );

                                    /* If either length, crc or CTl is not zero, this may be a
                                     * correct package. If all three are 0, this is most certainly
                                     * an incorrect package, because the possibility of a valid
                                     * package with all three values being zero is next to impossible */
                                    if ( b_Length != 0x00 || crc != 0x00 || b_CTl != 0x00 )
                                    {
                                        /* calculate checksum */
                                        bytes = (guint8 *)tvb_memdup(pinfo->pool, message_tvb, ctr - 1, b_Length + 5 );
                                        if ( b_Length > 8 )
                                        {
                                            crc = tvb_get_letohs ( message_tvb, ctr + 3 + b_Length );
                                            crcOffset = 1;

                                            crc1Type = OPENSAFETY_CHECKSUM_CRC16;
                                            calcCrc = crc16_0x755B( bytes, b_Length + 4, 0 );
                                            if ( ( crc ^ calcCrc ) != 0 )
                                            {
                                                calcCrc = crc16_0x5935( bytes, b_Length + 4, 0 );
                                                if ( ( crc ^ calcCrc ) == 0 )
                                                    crc1Type = OPENSAFETY_CHECKSUM_CRC16SLIM;
                                                else
                                                    crc1Type = OPENSAFETY_CHECKSUM_INVALID;
                                            }
                                        } else {
                                            crc1Type = OPENSAFETY_CHECKSUM_CRC8;
                                            calcCrc = crc8_0x2F ( bytes, b_Length + 4, 0 );
                                        }

                                        if ( ( crc ^ calcCrc ) == 0 )
                                        {
                                            /* Check if this is a Slim SSDO message */
                                            if ( ( b_ID >> 3 ) == ( OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE >> 3 ) )
                                            {
                                                /* Slim SSDO messages must have a length != 0, as the first byte
                                                 * in the payload contains the SOD access command */
                                                if ( b_Length > 0 )
                                                {
                                                    *u_frameOffset = ( ctr - 1 );
                                                    *u_frameLength = b_Length + 2 * crcOffset + 11;

                                                    /* It is highly unlikely, that both frame 1 and frame 2 generate
                                                     * a crc == 0 or equal crc's. Therefore we check, if both crc's are
                                                     * equal. If so, it is a falsely detected frame. */
                                                    f2crc = tvb_get_guint8 ( message_tvb, ctr + 3 + 5 + b_Length );
                                                    if ( b_Length > 8 )
                                                        f2crc = tvb_get_letohs ( message_tvb, ctr + 3 + 5 + b_Length );
                                                    if ( crc != f2crc )
                                                    {
                                                        found = TRUE;
                                                        break;
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                *u_frameLength = 2 * b_Length + 2 * crcOffset + 11;
                                                *u_frameOffset = ( ctr - 1 );

                                                /* If the first crc is zero, the second one must not be 0. The header
                                                 * for each subfields differ, therefore it is impossible, that both
                                                 * crcs are zero */
                                                if ( crc == 0 )
                                                {
                                                    f2crc = tvb_get_guint8 ( message_tvb, ( ctr - 1 ) + 10 + ( 2 * b_Length ) );
                                                    if ( b_Length > 8 )
                                                        f2crc = tvb_get_letohs ( message_tvb, ( ctr - 1 ) + 11 + ( 2 * b_Length ) );

                                                    /* The crc's differ, everything is ok */
                                                    if ( crc != f2crc )
                                                    {
                                                        found = TRUE;
                                                        break;
                                                    }
                                                }
                                                else
                                                {
                                                    /* At this point frames had been checked for SoC and SoA types of
                                                     * EPL. This is no longer necessary and leads to false-negatives.
                                                     * SoC and SoA frames get filtered out at the EPL entry point, cause
                                                     * EPL only provides payload, no longer complete frames. */
                                                    found = TRUE;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    /* There exist frames, where the last openSAFETY frame is sitting in the
                     * very last bytes of the frame, and the complete frame itself contains
                     * more than one openSAFETY frame. It so happens that in such a case, the
                     * last openSAFETY frame will miss detection.
                     *
                     * If so we look at the transported length, calculate the frame length,
                     * and take a look if the calculated frame length, might be a fit for the
                     * remaining length. If such is the case, we increment ctr and increment
                     * rem_length (to hit the while loop one more time) and the frame will be
                     * detected correctly. */
                    if ( rem_length == OSS_MINIMUM_LENGTH )
                    {
                        b_ID = tvb_get_guint8(message_tvb, ctr );
                        b_Length = tvb_get_guint8(message_tvb, ctr + 2 );
                        if ( ( b_ID >> 3 ) == ( OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE >> 3 ) )
                            b_Length = ( 11 + ( b_Length > 8 ? 2 : 0 ) + b_Length );
                        else
                            b_Length = ( 11 + ( b_Length > 8 ? 2 : 0 ) + 2 * b_Length );

                        if ( rem_length == b_Length )
                        {
                            ctr++;
                            rem_length++;
                            continue;
                        }
                    }
                }
            }
        }

        ctr++;
        rem_length = tvb_reported_length_remaining(message_tvb, ctr);

    }

    /* Store packet information in packet_info */
    if ( found && packet )
    {
        packet->msg_id = b_ID;
        packet->msg_len = b_Length;
        packet->frame_len = *u_frameLength;

        /* Should be the calculated crc, which is the same as the frame crc */
        packet->crc.frame1 = calcCrc;
        packet->crc.type = crc1Type;
        if ( packet->crc.type != OPENSAFETY_CHECKSUM_INVALID )
            packet->crc.valid1 = TRUE;
        else
            packet->crc.valid1 = FALSE;
    }

    /* Seem redundant if b_frame2First is false. But in this case, the function is needed for the
     * simple detection of a possible openSAFETY frame.  */
    if ( b_frame2first && found )
        *u_frameOffset = u_Offset;

    return found;
}

static gint
dissect_data_payload ( proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, gint len, guint8 msgType )
{
        gint off = 0;
        tvbuff_t * payload_tvb = NULL;
        heur_dtbl_entry_t *hdtbl_entry = NULL;

        off = offset;

        if (len > 0)
        {
                payload_tvb = tvb_new_subset_length_caplen(tvb, off, len, tvb_reported_length_remaining(tvb, offset) );
                if ( ! dissector_try_heuristic(heur_opensafety_spdo_subdissector_list, payload_tvb, pinfo, epl_tree, &hdtbl_entry, &msgType))
                        call_dissector(data_dissector, payload_tvb, pinfo, epl_tree);

                off += len;
        }

        return off;
}

static void
dissect_opensafety_spdo_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *opensafety_tree,
        opensafety_packet_info * packet, proto_item * opensafety_item )
{
    proto_item *item, *diritem;
    proto_tree *spdo_tree, *spdo_flags_tree;
    guint16     ct, addr;
    guint64     ct40bit;
    gint16      taddr, sdn;
    guint       dataLength;
    guint8      tr, b_ID, spdoFlags;

    dataLength = tvb_get_guint8(message_tvb, OSS_FRAME_POS_LEN + packet->frame.subframe1);
    b_ID = tvb_get_guint8(message_tvb, packet->frame.subframe1 + 1) & 0xF8;

    /* Network address is xor'ed into the start of the second frame, but only legible, if the scm given is valid */
    sdn = ( ( OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1) ) ^
            ( OSS_FRAME_ADDR_T2(message_tvb, packet->frame.subframe2, packet->scm_udid[0], packet->scm_udid[1]) ) );
    if ( ! packet->scm_udid_valid )
        sdn = ( -1 * sdn );

    /* taddr is the 4th octet in the second frame */
    tr = ( tvb_get_guint8(message_tvb, packet->frame.subframe2 + 4)  ^ packet->scm_udid[4] ) & 0xFC;

    /* allow only valid SPDO flags */
    spdoFlags = ( ( tr >> 2 ) & OPENSAFETY_SPDO_FEATURE_FLAGS );

    /* An SPDO is always sent by the producer, to everybody else .
     * For a 40bit connection OPENSAFETY_DEFAULT_DOMAIN is assumed as sdn value for now */
    if ( (OPENSAFETY_SPDO_FEAT_40BIT_USED & spdoFlags ) == OPENSAFETY_SPDO_FEAT_40BIT_USED )
        sdn = OPENSAFETY_DEFAULT_DOMAIN;

    /* Determine the producer and set it, as opensafety_packet_node does not */
    addr = OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1);
    packet->sender = addr;

    opensafety_packet_node ( message_tvb, pinfo, opensafety_tree, hf_oss_msg_sender,
            addr, OSS_FRAME_POS_ADDR + packet->frame.subframe1, packet->frame.subframe2, sdn );
    proto_item_append_text(opensafety_item, "; Producer: 0x%03X (%d)", addr, addr);

    spdo_tree = opensafety_packet_payloadtree ( pinfo, message_tvb, opensafety_tree, packet, ett_opensafety_spdo );

    /* Determine SPDO Flags. Attention packet->payload.spdo exists ONLY AFTER opensafety_packet_payloadtree */
    packet->payload.spdo->flags.enabled40bit = FALSE;
    packet->payload.spdo->flags.requested40bit = FALSE;

    if ( (OPENSAFETY_SPDO_FEAT_40BIT_AVAIL & spdoFlags ) == OPENSAFETY_SPDO_FEAT_40BIT_AVAIL )
        packet->payload.spdo->flags.requested40bit = TRUE;
    if ( packet->payload.spdo->flags.requested40bit && ( (OPENSAFETY_SPDO_FEAT_40BIT_USED & spdoFlags ) == OPENSAFETY_SPDO_FEAT_40BIT_USED ) )
        packet->payload.spdo->flags.enabled40bit = TRUE;

    diritem = opensafety_packet_response(message_tvb, spdo_tree, packet, b_ID == OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_RESPONSE );
    proto_tree_add_item(spdo_tree, hf_oss_spdo_connection_valid, message_tvb, OSS_FRAME_POS_ID + packet->frame.subframe1, 1, ENC_NA);

    packet->payload.spdo->conn_valid = (tvb_get_guint8(message_tvb, OSS_FRAME_POS_ID + packet->frame.subframe1) & 0x04) == 0x04;

    /* taddr is the 4th octet in the second frame */
    taddr = OSS_FRAME_ADDR_T2(message_tvb, packet->frame.subframe2 + 3, packet->scm_udid[3], packet->scm_udid[4]);
    tr = ( tvb_get_guint8(message_tvb, packet->frame.subframe2 + 4)  ^ packet->scm_udid[4] ) & 0xFC;

    /* determine the ct value. if complete it can be used for analysis of the package */
    ct = tvb_get_guint8(message_tvb, packet->frame.subframe1 + 3);
    if ( packet->scm_udid_valid )
    {
        ct = (guint16)((tvb_get_guint8(message_tvb, packet->frame.subframe2 + 2) ^ packet->scm_udid[2]) << 8) +
            (tvb_get_guint8(message_tvb, packet->frame.subframe1 + 3));
    }

    if ( b_ID == OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_REQUEST )
    {
        proto_item_append_text(diritem, " (Safety Node: %03d)", taddr);
        item = proto_tree_add_uint_format_value(spdo_tree, hf_oss_spdo_ct, message_tvb, 0, 0, ct,
                                                "0x%04X [%d] (%s)", ct, ct,
                                                (packet->scm_udid_valid ? "Complete" : "Low byte only"));
        proto_item_set_generated(item);
        packet->payload.spdo->counter.b16 = ct;

        packet->payload.spdo->timerequest = taddr;
        proto_tree_add_uint(spdo_tree, hf_oss_spdo_time_request, message_tvb,
                            OSS_FRAME_POS_ADDR + packet->frame.subframe2 + 4, 1, tr);
        opensafety_packet_node ( message_tvb, pinfo, spdo_tree, hf_oss_spdo_time_request_from, taddr,
                OSS_FRAME_POS_ADDR + packet->frame.subframe2 + 3, packet->frame.subframe2, sdn );
    }
    else
    {
        if ( ! (b_ID == OPENSAFETY_MSG_SPDO_DATA_ONLY) || !(packet->payload.spdo->flags.enabled40bit) )
        {
            item = proto_tree_add_uint_format_value(spdo_tree, hf_oss_spdo_ct, message_tvb, 0, 0, ct,
                    "0x%04X [%d] (%s)", ct, ct, (packet->scm_udid_valid ? "Complete" : "Low byte only"));
            proto_item_set_generated(item);
            packet->payload.spdo->counter.b16 = ct;
        }
        else
        {
            /* 40bit counter is calculated from various fields. Therefore it cannot be read
             * directly from the frame. All fields starting after or with packet->frame.subframe2 have to
             * be decoded using the scm udid */
            ct40bit = (tvb_get_guint8(message_tvb, packet->frame.subframe2 + 3) ^ packet->scm_udid[3]);
            ct40bit <<= 8;
            ct40bit += ((guint64)(tvb_get_guint8(message_tvb, packet->frame.subframe2 + 1) ^ packet->scm_udid[1]) ^ tvb_get_guint8(message_tvb, packet->frame.subframe1 + 1));
            ct40bit <<= 8;
            ct40bit += (tvb_get_guint8(message_tvb, packet->frame.subframe2 + 0) ^ packet->scm_udid[0]) ^ OPENSAFETY_DEFAULT_DOMAIN ^ tvb_get_guint8(message_tvb, packet->frame.subframe1 + 0);
            ct40bit <<= 8;
            ct40bit += (tvb_get_guint8(message_tvb, packet->frame.subframe2 + 2) ^ packet->scm_udid[2]);
            ct40bit <<= 8;
            ct40bit += tvb_get_guint8(message_tvb, packet->frame.subframe1 + 3);

            item = proto_tree_add_uint64(spdo_tree, hf_oss_spdo_ct_40bit, message_tvb, 0, 0, ct40bit);
            proto_item_set_generated(item);

            packet->payload.spdo->counter.b40 = ct40bit;
            if ( global_opensafety_debug_verbose )
                expert_add_info ( pinfo, item, &ei_40bit_default_domain );
        }
        proto_item_set_generated(item);

        if ( b_ID == OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_RESPONSE )
        {
            proto_item_append_text(diritem, " (Safety Node: %03d)", taddr);
            proto_tree_add_uint(spdo_tree, hf_oss_spdo_time_request, message_tvb,
                    OSS_FRAME_POS_ADDR + packet->frame.subframe2 + 4, 1, tr);
            packet->payload.spdo->timerequest = taddr;

            opensafety_packet_node ( message_tvb, pinfo, spdo_tree, hf_oss_spdo_time_request_to, taddr,
                    OSS_FRAME_POS_ADDR + packet->frame.subframe2 + 3, packet->frame.subframe2, sdn );
        }
        else
        {
            item = proto_tree_add_uint(spdo_tree, hf_oss_spdo_feature_flags,
                    message_tvb, OSS_FRAME_POS_ADDR + packet->frame.subframe2 + 4, 1, spdoFlags << 2);

            spdo_flags_tree = proto_item_add_subtree(item, ett_opensafety_spdo_flags);

            proto_tree_add_boolean(spdo_flags_tree, hf_oss_spdo_feature_flag_40bit_available, message_tvb,
                    OSS_FRAME_POS_ADDR + packet->frame.subframe2 + 4, 1,
                    packet->payload.spdo->flags.requested40bit ? OPENSAFETY_SPDO_FEAT_40BIT_AVAIL << 2 : 0 );
            proto_tree_add_boolean(spdo_flags_tree, hf_oss_spdo_feature_flag_40bit_used, message_tvb,
                    OSS_FRAME_POS_ADDR + packet->frame.subframe2 + 4, 1,
                    packet->payload.spdo->flags.enabled40bit ? OPENSAFETY_SPDO_FEAT_40BIT_USED << 2 : 0 );
        }
    }

    if ( dataLength > 0 )
    {
        dissect_data_payload(spdo_tree, message_tvb, pinfo, OSS_FRAME_POS_ID + 3, dataLength, OPENSAFETY_SPDO_MESSAGE_TYPE);
    }
}

static void dissect_opensafety_ssdo_payload ( packet_info *pinfo, tvbuff_t *new_tvb, proto_tree *ssdo_payload, guint8 sacmd )
{
    guint       dataLength   = 0, ctr = 0, n = 0, nCRCs = 0;
    guint8      ssdoSubIndex = 0;
    guint16     ssdoIndex    = 0, dispSSDOIndex = 0;
    guint32     sodLength    = 0, entry = 0;
    proto_item *item;
    proto_tree *sod_tree, *ext_tree;

    dataLength = tvb_captured_length(new_tvb);

    ssdoIndex = tvb_get_letohs(new_tvb, 0);

    sodLength = tvb_get_letohl(new_tvb, 4);

    /* first check for extended parameter */
    if ( dataLength == 16 || sodLength == ( dataLength - 16 ) || ssdoIndex == 0x0101 )
    {
        /* extended parameter header & data */
        item = proto_tree_add_string_format(ssdo_payload, hf_oss_ssdo_extpar,
                                            new_tvb, 0, dataLength, "", "Extended Parameter Set: %s",
                                            (dataLength == 16 ? "Header only" : "Header & Data") );
        ext_tree = proto_item_add_subtree(item, ett_opensafety_ssdo_extpar);

        proto_tree_add_item(ext_tree, hf_oss_ssdo_extpar_parset,  new_tvb, 0, 1, ENC_BIG_ENDIAN );
        proto_tree_add_item(ext_tree, hf_oss_ssdo_extpar_version, new_tvb, 1, 1, ENC_BIG_ENDIAN );
        proto_tree_add_item(ext_tree, hf_oss_ssdo_extpar_saddr,   new_tvb, 2, 2, ENC_LITTLE_ENDIAN );

        proto_tree_add_uint_format_value(ext_tree, hf_oss_ssdo_extpar_length,
                                         new_tvb, 4, 4, sodLength, "0x%04X (%d octets)",
                                         sodLength, sodLength );

        proto_tree_add_item(ext_tree, hf_oss_ssdo_extpar_crc,    new_tvb,  8, 4, ENC_LITTLE_ENDIAN );
        proto_tree_add_item(ext_tree, hf_oss_ssdo_extpar_tstamp, new_tvb, 12, 4, ENC_LITTLE_ENDIAN );

        if ( dataLength != 16 )
        {
            item = proto_tree_add_item(ext_tree, hf_oss_ssdo_extpar_data, new_tvb, 16, dataLength - 16, ENC_NA );

            if ( ( dataLength - sodLength ) != 16 )
                expert_add_info ( pinfo, item, &ei_message_reassembly_size_differs_from_header );
        }
    }
    else
    {
        /* If == upload, it is most likely a par upload */
        if ( sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_END && ( dataLength % 4 == 0 ) )
        {

            item = proto_tree_add_uint_format_value(ssdo_payload, hf_oss_ssdo_sod_index, new_tvb,
                                                    0, 0,  0x1018, "0x%04X (%s)", 0x1018,
                                                    val_to_str_ext_const( ((guint32) (0x1018 << 16) ),
                                                                          &opensafety_sod_idx_names_ext, "Unknown") );
            sod_tree = proto_item_add_subtree(item, ett_opensafety_ssdo_sodentry);
            proto_item_set_generated(item);

            item = proto_tree_add_uint_format_value(sod_tree, hf_oss_ssdo_sod_subindex, new_tvb, 0, 0,
                                                    0x06, "0x%02X (%s)", 0x06,
                                                    val_to_str_ext_const(((guint32) (0x1018 << 16) +  0x06),
                                                                         &opensafety_sod_idx_names_ext, "Unknown") );
            proto_item_set_generated(item);

            proto_tree_add_item( sod_tree, hf_oss_sod_par_timestamp, new_tvb, 0, 4, ENC_LITTLE_ENDIAN );

            /* This is to avoid a compiler loop optimization warning */
            nCRCs = dataLength / 4;
            for ( ctr = 1; ctr < nCRCs; ctr++ )
            {
                entry = tvb_get_letohl ( new_tvb, ctr * 4 );
                proto_tree_add_uint_format_value ( sod_tree, hf_oss_sod_par_checksum, new_tvb, ctr * 4,
                        4, entry, "[#%d] 0x%08X", ctr, entry );
            }
        }
        /* If != upload, it is most likely a 101A download */
        else
        {

            /* normal parameter set */
            for ( ctr = 0; ctr < dataLength; ctr++ )
            {
                ssdoIndex = tvb_get_letohs(new_tvb, ctr);
                ssdoSubIndex = tvb_get_guint8(new_tvb, ctr + 2);
                dispSSDOIndex = ssdoIndex;

                if ( ssdoIndex >= 0x1400 && ssdoIndex <= 0x17FE )
                    dispSSDOIndex = 0x1400;
                else if ( ssdoIndex >= 0x1800 && ssdoIndex <= 0x1BFE )
                    dispSSDOIndex = 0x1800;
                else if ( ssdoIndex >= 0x1C00 && ssdoIndex <= 0x1FFE )
                    dispSSDOIndex = 0x1C00;
                else if ( ssdoIndex >= 0xC000 && ssdoIndex <= 0xC3FE )
                    dispSSDOIndex = 0xC000;

                item = proto_tree_add_uint_format_value(ssdo_payload, hf_oss_ssdo_sod_index, new_tvb,
                                                        ctr, 2,  ssdoIndex, "0x%04X (%s)", ssdoIndex,
                                                        val_to_str_ext_const( ((guint32) (dispSSDOIndex << 16) ),
                                                                              &opensafety_sod_idx_names_ext, "Unknown") );
                if ( ssdoIndex != dispSSDOIndex )
                    proto_item_set_generated ( item );

                if ( ssdoIndex < 0x1000 || ssdoIndex > 0xE7FF )
                    expert_add_info ( pinfo, item, &ei_payload_unknown_format );

                sod_tree = proto_item_add_subtree(item, ett_opensafety_ssdo_sodentry);

                if ( ssdoSubIndex != 0 )
                {
                    proto_tree_add_uint_format_value(sod_tree, hf_oss_ssdo_sod_subindex, new_tvb, ctr + 2, 1,
                                                     ssdoSubIndex, "0x%02X (%s)", ssdoSubIndex,
                                                     val_to_str_ext_const(((guint32) (ssdoIndex << 16) + ssdoSubIndex),
                                                                          &opensafety_sod_idx_names_ext, "Unknown") );
                }
                else
                    proto_tree_add_uint_format_value(sod_tree, hf_oss_ssdo_sod_subindex, new_tvb, ctr + 2, 1,
                                                 ssdoSubIndex, "0x%02X", ssdoSubIndex );
                ctr += 2;

                /* reading real size */
                sodLength = tvb_get_letohl ( new_tvb, ctr + 1 );
                if ( sodLength > (dataLength - ctr) )
                    sodLength = 0;

                if ( ( sodLength + 4 + ctr ) > dataLength )
                    break;

                if ( ssdoIndex == OPENSAFETY_SOD_DVI && ssdoSubIndex == 0x06 )
                {
                    proto_tree_add_item( sod_tree, hf_oss_sod_par_timestamp, new_tvb, ctr + 5, 4, ENC_LITTLE_ENDIAN );

                    /* This is to avoid a compiler loop optimization warning */
                    nCRCs = sodLength / 4;
                    for ( n = 1; n < nCRCs; n++ )
                    {
                        entry = tvb_get_letohl ( new_tvb, ctr + 5 + ( n * 4 ) );
                        proto_tree_add_uint_format_value ( sod_tree, hf_oss_sod_par_checksum, new_tvb,
                                (ctr + 5 + ( n * 4 ) ), 4, entry, "[#%d] 0x%08X", n, entry );
                    }
                } else if ( ssdoIndex == OPENSAFETY_SOD_DVI && ssdoSubIndex == 0x07 ) {
                    proto_tree_add_item( sod_tree, hf_oss_sod_par_timestamp, new_tvb, ctr + 5, 4, ENC_LITTLE_ENDIAN );
                } else if ( ( dispSSDOIndex == OPENSAFETY_SOD_RXMAP || dispSSDOIndex == OPENSAFETY_SOD_TXMAP ) && ssdoSubIndex != 0x0 ) {
                    proto_tree_add_uint(sod_tree, hf_oss_ssdo_sodentry_size, new_tvb, ctr + 1, 4, sodLength );
                    item = proto_tree_add_item(sod_tree, hf_oss_ssdo_sodmapping, new_tvb, ctr + 5, sodLength, ENC_NA );
                    ext_tree = proto_item_add_subtree(item, ett_opensafety_sod_mapping);

                    proto_tree_add_item(ext_tree, hf_oss_ssdo_sodmapping_bits, new_tvb, ctr + 5, 1, ENC_NA);

                    proto_tree_add_item(ext_tree, hf_oss_ssdo_sod_index, new_tvb, ctr + 7, 2, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(ext_tree, hf_oss_ssdo_sod_subindex, new_tvb, ctr + 6, 1, ENC_NA);

                } else {
                    proto_tree_add_uint(sod_tree, hf_oss_ssdo_sodentry_size, new_tvb, ctr + 1, 4, sodLength );
                    if ( sodLength > 0 )
                        proto_tree_add_item(sod_tree, hf_oss_ssdo_sodentry_data, new_tvb, ctr + 5, sodLength, ENC_NA );
                }
                ctr += sodLength + 4;
        }
        }
    }


}

static void
dissect_opensafety_ssdo_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *opensafety_tree,
        opensafety_packet_info * packet, proto_item * opensafety_item )
{
    proto_item    *item;
    proto_tree    *ssdo_tree, *ssdo_payload;
    guint16        taddr                = 0, sdn = 0, server = 0, client = 0, n = 0, ct = 0;
    guint32        abortcode, ssdoIndex = 0, ssdoSubIndex = 0, payloadSize, fragmentId = 0, entry = 0;
    guint8         db0Offset, db0, payloadOffset, preload;
    guint          dataLength;
    gint           calcDataLength;
    gboolean       isResponse, saveFragmented;
    tvbuff_t      *new_tvb              = NULL;
    fragment_head *frag_msg             = NULL;

    static int * const ssdo_sacmd_flags[] = {
            &hf_oss_ssdo_sacmd_end_segment,
            &hf_oss_ssdo_sacmd_initiate,
            &hf_oss_ssdo_sacmd_toggle,
            &hf_oss_ssdo_sacmd_segmentation,
            &hf_oss_ssdo_sacmd_abort_transfer,
            &hf_oss_ssdo_sacmd_preload,
            &hf_oss_ssdo_sacmd_access_type,
            NULL
    };

    dataLength = tvb_get_guint8(message_tvb, OSS_FRAME_POS_LEN + packet->frame.subframe1);

    db0Offset = packet->frame.subframe1 + OSS_FRAME_POS_DATA;
    db0 = tvb_get_guint8(message_tvb, db0Offset);
    ssdoIndex = 0;
    ssdoSubIndex = 0;

    /* Response is determined by the openSAFETY message field */
    isResponse = ( ( OSS_FRAME_ID_T(message_tvb, packet->frame.subframe1) & 0x04 ) == 0x04 );

    if ( packet->scm_udid_valid )
    {
        /* taddr is the 4th octet in the second frame */
        taddr = OSS_FRAME_ADDR_T2(message_tvb, packet->frame.subframe2 + 3, packet->scm_udid[3], packet->scm_udid[4]);
        sdn =  ( OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1) ^
                        ( OSS_FRAME_ADDR_T2(message_tvb, packet->frame.subframe2, packet->scm_udid[0], packet->scm_udid[1]) ) );

        opensafety_packet_sendreceiv ( message_tvb, pinfo, opensafety_tree, opensafety_item, packet, taddr,
                packet->frame.subframe2 + 3, OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1),
                packet->frame.subframe1, packet->frame.subframe2, sdn );
    }
    else if ( ! isResponse )
    {
        opensafety_packet_sender ( message_tvb, pinfo, opensafety_tree, opensafety_item, packet,
                OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1), packet->frame.subframe1,
                packet->frame.subframe2, -1 * ( ( OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1) ) ^
                        ( OSS_FRAME_ADDR_T2(message_tvb, packet->frame.subframe2, packet->scm_udid[0], packet->scm_udid[1]) ) ) );
    }
    else if ( isResponse )
    {
        opensafety_packet_receiver ( message_tvb, pinfo, opensafety_tree, opensafety_item, packet,
                OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1), packet->frame.subframe1,
                packet->frame.subframe2, -1 * ( ( OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1) ) ^
                        ( OSS_FRAME_ADDR_T2(message_tvb, packet->frame.subframe2, packet->scm_udid[0], packet->scm_udid[1]) ) ) );
    }

    ssdo_tree = opensafety_packet_payloadtree ( pinfo, message_tvb, opensafety_tree, packet, ett_opensafety_ssdo );

    opensafety_packet_response ( message_tvb, ssdo_tree, packet, isResponse );

    packet->payload.ssdo->sacmd.toggle = ( db0 & OPENSAFETY_SSDO_SACMD_TGL ) == OPENSAFETY_SSDO_SACMD_TGL;
    packet->payload.ssdo->sacmd.abort_transfer = ( db0 & OPENSAFETY_SSDO_SACMD_ABRT ) == OPENSAFETY_SSDO_SACMD_ABRT;
    packet->payload.ssdo->sacmd.preload = ( db0 & OPENSAFETY_SSDO_SACMD_PRLD ) == OPENSAFETY_SSDO_SACMD_PRLD;
    packet->payload.ssdo->sacmd.read_access = ( db0 & OPENSAFETY_SSDO_DOWNLOAD ) == OPENSAFETY_SSDO_DOWNLOAD;
    packet->payload.ssdo->sacmd.initiate = ( db0 & OPENSAFETY_SSDO_SACMD_INI ) == OPENSAFETY_SSDO_SACMD_INI;
    packet->payload.ssdo->sacmd.segmented = ( db0 & OPENSAFETY_SSDO_SACMD_SEG ) == OPENSAFETY_SSDO_SACMD_SEG;
    packet->payload.ssdo->sacmd.end_segment = ( db0 & OPENSAFETY_SSDO_SACMD_ENSG ) == OPENSAFETY_SSDO_SACMD_ENSG;

    if ( isResponse )
    {
        opensafety_packet_node ( message_tvb, pinfo, ssdo_tree, hf_oss_ssdo_client,
                OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1),
                packet->frame.subframe1, packet->frame.subframe2, sdn );
        client = OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1);

        if ( packet->scm_udid_valid )
        {
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_server, message_tvb, packet->frame.subframe2 + 3, 2, taddr);
            server = taddr;
        }
    }
    else if ( ! isResponse )
    {
        proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_server, message_tvb, packet->frame.subframe1, 2, OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1));
        server = OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1);
        if ( packet->scm_udid_valid )
        {
            opensafety_packet_node ( message_tvb, pinfo, ssdo_tree, hf_oss_ssdo_client,
                    taddr, packet->frame.subframe2 + 3, packet->frame.subframe2, sdn );
            client = taddr;
        }
    }

    /* Toggle bit must be removed, otherwise the values cannot be displayed correctly */
    if ( packet->payload.ssdo->sacmd.toggle )
        db0 &= (~OPENSAFETY_SSDO_SACMD_TGL);
    proto_tree_add_bitmask(ssdo_tree, message_tvb, db0Offset, hf_oss_ssdo_sacmd,
            ett_opensafety_ssdo_sacmd, ssdo_sacmd_flags, ENC_NA);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", SACMD: %s", val_to_str_const(db0, opensafety_ssdo_sacmd_values, " "));

    payloadOffset = db0Offset + 1;

    ct = tvb_get_guint8(message_tvb, packet->frame.subframe1 + 3);
    if ( packet->scm_udid_valid )
    {
        ct = (guint16)((tvb_get_guint8(message_tvb, packet->frame.subframe2 + 2) ^ packet->scm_udid[2]) << 8);
        ct += (tvb_get_guint8(message_tvb, packet->frame.subframe1 + 3));
    }

    proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_sano, message_tvb, packet->frame.subframe1 + 3, 1, ct );

    /* Evaluate preload field [field TR] */
    if ( packet->scm_udid_valid && packet->payload.ssdo->sacmd.preload && isResponse )
    {
        /* Preload info are the higher 6 bit of the TR field */
        preload = ( (tvb_get_guint8(message_tvb, packet->frame.subframe2 + 4) ^ packet->scm_udid[4]) & 0xFC ) >> 2;

        if ( packet->payload.ssdo->sacmd.initiate )
        {
            /* Use the lower 4 bits from the preload as size */
            proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_preload_queue, message_tvb, packet->frame.subframe2 + 4, 1,
                    preload & 0x0F, "%d", preload & 0x0F );
        }
        else
        {
            /* The highest 2 bits of information contain an error flag */
            item = proto_tree_add_item(ssdo_tree, hf_oss_ssdo_preload_error, message_tvb, packet->frame.subframe2 + 4, 1, ENC_NA );
            if ( (preload & 0x30) == 0x30 )
                proto_item_append_text(item, " (SOD Access Request Number is last successful)" );
        }
    }

    /* When the following clause is met, DB1,2 contain the SOD index, and DB3 the SOD subindex */
    if ( packet->payload.ssdo->sacmd.initiate && !packet->payload.ssdo->sacmd.abort_transfer )
    {
        ssdoIndex = tvb_get_letohs(message_tvb, db0Offset + 1);
        ssdoSubIndex = tvb_get_guint8(message_tvb, db0Offset + 3);

        proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_sod_index, message_tvb, db0Offset + 1, 2,
                ssdoIndex, "0x%04X (%s)", ssdoIndex,
                val_to_str_ext_const(((guint32) (ssdoIndex << 16)), &opensafety_sod_idx_names_ext, "Unknown") );
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s", val_to_str_ext_const(((guint32) (ssdoIndex << 16)), &opensafety_sod_idx_names_ext, "Unknown"));

        /* Some SOD downloads (0x101A for instance) don't have sub-indeces */
        if ( ssdoSubIndex != 0x0 )
        {
            proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_sod_subindex, message_tvb, db0Offset + 3, 1,
                ssdoSubIndex, "0x%02X (%s)", ssdoSubIndex,
                val_to_str_ext_const(((guint32) (ssdoIndex << 16) + ssdoSubIndex), &opensafety_sod_idx_names_ext, "Unknown") );
            col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                    val_to_str_ext_const(((guint32) (ssdoIndex << 16) + ssdoSubIndex), &opensafety_sod_idx_names_ext, "Unknown"));
        }
        col_append_str(pinfo->cinfo, COL_INFO, "]");
        payloadOffset += 3;
    }

    if ( packet->payload.ssdo->sacmd.abort_transfer )
    {
        abortcode = tvb_get_letohl(message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA + 4);

        proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_abort_code, message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA + 4, 4, abortcode,
                "0x%04X %04X - %s", (guint16)(abortcode >> 16), (guint16)(abortcode),
                val_to_str_ext_const(abortcode, &opensafety_abort_codes_ext, "Unknown"));
        col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(abortcode, &opensafety_abort_codes_ext, "Unknown"));


    } else {
        /* Either the SSDO msg is a response, then data is sent by the server and only in uploads,
         * or the message is a request, then data is coming from the client and payload data is
         * sent in downloads. Data is only sent in initiate, segmented or end-segment messages */
        if ( ( packet->payload.ssdo->sacmd.initiate || packet->payload.ssdo->sacmd.segmented || packet->payload.ssdo->sacmd.end_segment ) &&
             ( ( isResponse && !packet->payload.ssdo->sacmd.read_access ) ||
                     ( !isResponse && packet->payload.ssdo->sacmd.read_access ) ) )
        {
            saveFragmented = pinfo->fragmented;
            if ( server != 0 && client != 0 )
                fragmentId = (guint32)((((guint32)client) << 16 ) + server );

            /* If payload data has to be calculated, either a total size is given, or not */
            if ( packet->payload.ssdo->sacmd.segmented && packet->payload.ssdo->sacmd.initiate )
            {

                payloadOffset += 4;

                /* reading real size */
                payloadSize = tvb_get_letohl(message_tvb, payloadOffset - 4);

                calcDataLength = dataLength - (payloadOffset - db0Offset);

                item = proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_payload_size, message_tvb, payloadOffset - 4, 4,
                        payloadSize, "%d octets total (%d octets in this frame)", payloadSize, calcDataLength);

                if ( calcDataLength >= 0 )
                {
                    if ( fragmentId != 0 && packet->payload.ssdo->sacmd.segmented )
                    {
                        pinfo->fragmented = TRUE;
                        frag_msg = fragment_add_seq_check(&os_reassembly_table, message_tvb, payloadOffset, pinfo,
                                                          fragmentId, NULL, 0, calcDataLength, TRUE );
                        fragment_add_seq_offset ( &os_reassembly_table, pinfo, fragmentId, NULL, ct );

                        if ( frag_msg != NULL )
                        {
                            item = proto_tree_add_bytes_format_value(ssdo_tree, hf_oss_ssdo_payload, message_tvb, 0, 0, NULL, "Reassembled" );
                            proto_item_set_generated(item);

                            ssdo_payload = proto_item_add_subtree(item, ett_opensafety_ssdo_payload);
                            process_reassembled_data(message_tvb, 0, pinfo, "Reassembled Message", frag_msg, &oss_frag_items, NULL, ssdo_payload );
                        }
                    }

                    proto_tree_add_item(ssdo_tree, hf_oss_ssdo_payload, message_tvb, payloadOffset, calcDataLength, ENC_NA );
                } else {
                    if ( global_opensafety_debug_verbose )
                        expert_add_info_format(pinfo, item, &ei_payload_length_not_positive,
                                                    "Calculation for payload length yielded non-positive result [%d]", (guint) calcDataLength );
                }
            }
            else
            {
                payloadSize = dataLength - (payloadOffset - db0Offset);
                if ((gint)dataLength < (payloadOffset - db0Offset))
                {
                    if ( global_opensafety_debug_verbose )
                        expert_add_info_format(pinfo, opensafety_item, &ei_payload_length_not_positive,
                                                    "Calculation for payload length yielded non-positive result [%d]", (gint)payloadSize );
                    return;
                }

                if ( fragmentId != 0 && packet->payload.ssdo->sacmd.segmented )
                {
                    pinfo->fragmented = TRUE;

                    frag_msg = fragment_add_seq_check(&os_reassembly_table, message_tvb, payloadOffset, pinfo,
                                                      fragmentId, NULL, ct, payloadSize,
                                                      packet->payload.ssdo->sacmd.end_segment ? FALSE : TRUE );
                }

                if ( frag_msg )
                {
                    item = proto_tree_add_bytes_format_value(ssdo_tree, hf_oss_ssdo_payload, message_tvb,
                                                             0, 0, NULL, "Reassembled" );
                    proto_item_set_generated(item);
                    ssdo_payload = proto_item_add_subtree(item, ett_opensafety_ssdo_payload);

                    new_tvb = process_reassembled_data(message_tvb, 0, pinfo, "Reassembled Message", frag_msg,
                                                       &oss_frag_items, NULL, ssdo_payload );
                    if ( packet->payload.ssdo->sacmd.end_segment && new_tvb )
                    {
                        item = proto_tree_add_uint_format_value(ssdo_payload, hf_oss_ssdo_payload_size, message_tvb, 0, 0,
                                                                payloadSize, "%d octets (over all fragments)", frag_msg->len);
                        proto_item_set_generated(item);

                        col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)" );
                        dissect_opensafety_ssdo_payload ( pinfo, new_tvb, ssdo_payload, db0 );
                    }
                }
                else
                {
                    item = proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_payload_size, message_tvb, 0, 0, payloadSize,
                            "%d octets", payloadSize);
                    proto_item_set_generated(item);

                    if ( ssdoIndex == OPENSAFETY_SOD_DVI && ssdoSubIndex == 0x06 )
                    {
                        proto_tree_add_item( ssdo_tree, hf_oss_sod_par_timestamp, message_tvb, payloadOffset, 4, ENC_LITTLE_ENDIAN );
                        for ( n = 4; n < payloadSize; n+=4 )
                        {
                            entry = tvb_get_letohl ( message_tvb, payloadOffset + n );
                            proto_tree_add_uint_format_value ( ssdo_tree, hf_oss_sod_par_checksum, message_tvb, (payloadOffset + n ),
                                    4, entry, "[#%d] 0x%08X", ( n / 4 ), entry );
                        }
                    } else if ( ssdoIndex == OPENSAFETY_SOD_DVI && ssdoSubIndex == 0x07 ) {
                        proto_tree_add_item ( ssdo_tree, hf_oss_sod_par_timestamp, message_tvb, payloadOffset, 4, ENC_LITTLE_ENDIAN );
                    } else
                        proto_tree_add_item(ssdo_tree, hf_oss_ssdo_payload, message_tvb, payloadOffset, payloadSize, ENC_NA );
                }
            }

            pinfo->fragmented = saveFragmented;
        }
    }
}

static void
opensafety_parse_scm_udid ( tvbuff_t* tvb, packet_info *pinfo, proto_tree *tree,
        opensafety_packet_info *packet, guint offset )
{
    proto_item * item = NULL;
    gchar      *scm_udid_test = NULL;

    item = proto_tree_add_item(tree, hf_oss_snmt_udid, tvb, offset, 6, ENC_NA);

    scm_udid_test = tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, 6, ':' );

    if ( scm_udid_test != NULL && strlen( scm_udid_test ) == 17 )
    {
        if ( g_strcmp0("00:00:00:00:00:00", scm_udid_test ) != 0 )
        {
            packet->payload.snmt->scm_udid = scm_udid_test;

            if ( ( global_scm_udid_autoset == TRUE ) &&  ( memcmp ( global_scm_udid, scm_udid_test, 17 ) != 0 ) )
            {
                if ( local_scm_udid == NULL || memcmp ( local_scm_udid, scm_udid_test, 17 ) != 0 )
                {
                    local_scm_udid = wmem_strdup(wmem_file_scope(), scm_udid_test );
                    if ( global_opensafety_debug_verbose )
                        expert_add_info_format(pinfo, item, &ei_scmudid_autodetected,
                                "Auto detected payload as SCM UDID [%s].", local_scm_udid);
                }
            }
        }
    }
}

static void
dissect_opensafety_snmt_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *opensafety_tree,
        opensafety_packet_info *packet, proto_item * opensafety_item )
{
    proto_tree *snmt_tree;
    guint16     addr, taddr, sdn;
    guint8      db0, byte, errcode;
    guint       dataLength;

    dataLength = OSS_FRAME_LENGTH_T(message_tvb, packet->frame.subframe1);

    /* addr is the first field, as well as the recipient of the message */
    addr = packet->saddr;

    /* taddr is the 4th octet in the second frame */
    taddr = OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe2 + 3);
    /* domain is xor'ed on the first field in the second frame. As this is also addr, it is easy to obtain */
    sdn = OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe2) ^ addr;
    packet->sdn = sdn;

    db0 = -1;
    if (dataLength > 0)
        db0 = tvb_get_guint8(message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA);

    packet->msg_id = OSS_FRAME_ID_T(message_tvb, packet->frame.subframe1);

    if ( ( packet->msg_id == OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE ) &&
         ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_STOP) == 0 ||
           (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_OP) == 0 ) )
    {
        opensafety_packet_receiver( message_tvb, pinfo, opensafety_tree, opensafety_item, packet, addr,
                OSS_FRAME_POS_ADDR + packet->frame.subframe1, packet->frame.subframe2, sdn );
    }
    else
    {
        opensafety_packet_sendreceiv ( message_tvb, pinfo, opensafety_tree, opensafety_item, packet, taddr,
                packet->frame.subframe2 + 3, addr, OSS_FRAME_POS_ADDR + packet->frame.subframe1,
                packet->frame.subframe2, sdn );
    }

    snmt_tree = opensafety_packet_payloadtree ( pinfo, message_tvb, opensafety_tree, packet, ett_opensafety_snmt );
    /* Just a precaution, cause payloadtree actually sets the snmt pointer */
    if ( packet->payload.snmt == NULL )
        return;

    if ( ( packet->msg_id == OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE ) ||
         ( packet->msg_id == OPENSAFETY_MSG_SNMT_SERVICE_REQUEST ) )
        packet->payload.snmt->ext_msg_id = db0;

    opensafety_packet_response(message_tvb, snmt_tree, packet, ( packet->msg_id & 0x04 ) == 0x04 );

    if ( packet->is_request )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, packet->frame.subframe2 + 3, 2, taddr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, OSS_FRAME_POS_ADDR + packet->frame.subframe1, 2, addr);
    }
    else
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + packet->frame.subframe1, 2, addr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, packet->frame.subframe2 + 3, 2, taddr);
    }

    /* Handle Acknowledge and Fail specifically */
    if ( ( ( db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ACKNOWLEDGE) == 0 ) || ( db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_FAIL) == 0 )
    {
        byte = tvb_get_guint8(message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1 + 1);

        /* Handle a normal SN Fail */
        if ( byte != OPENSAFETY_ERROR_GROUP_ADD_PARAMETER )
        {
            if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_FAIL) == 0 )
            {
                proto_tree_add_uint(snmt_tree, hf_oss_snmt_service_id, message_tvb,
                        OSS_FRAME_POS_DATA + packet->frame.subframe1, 1, packet->payload.snmt->ext_msg_id);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                        val_to_str_const(packet->payload.snmt->ext_msg_id, opensafety_message_service_type, "Unknown"));
            }
            else if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ACKNOWLEDGE) == 0 )
            {
                proto_tree_add_uint(snmt_tree, hf_oss_snmt_service_id, message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1, 1, db0);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(db0, opensafety_message_service_type, "Unknown"));
            }

            proto_tree_add_uint_format_value(snmt_tree, hf_oss_snmt_error_group, message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1 + 1, 1,
                    byte, "%s", ( byte == 0 ? "Device" : val_to_str(byte, opensafety_sn_fail_error_group, "Reserved [%d]" ) ) );

            errcode = tvb_get_guint8(message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1 + 2);
            proto_tree_add_uint_format_value(snmt_tree, hf_oss_snmt_error_code, message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1 + 2, 1,
                    errcode, "%s [%d]", ( errcode == 0 ? "Default" : "Vendor Specific" ), errcode );

            col_append_fstr(pinfo->cinfo, COL_INFO, " - Group: %s; Code: %s",
                ( byte == 0 ? "Device" : val_to_str(byte, opensafety_sn_fail_error_group, "Reserved [%d]" ) ),
                ( errcode == 0 ? "Default" : "Vendor Specific" )
            );

            packet->payload.snmt->add_param.exists = FALSE;
            packet->payload.snmt->error_code = errcode;
        }
        else
        {
            if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_FAIL) == 0 )
            {
                proto_tree_add_uint_format_value(snmt_tree, hf_oss_snmt_service_id, message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1, 1,
                        packet->payload.snmt->ext_msg_id, "%s [Request via SN Fail] (0x%02X)",
                        val_to_str_const(byte, opensafety_sn_fail_error_group, "Unknown"), packet->payload.snmt->ext_msg_id);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(byte, opensafety_sn_fail_error_group, "Unknown"));
            } else if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ACKNOWLEDGE) == 0 )
            {
                proto_tree_add_uint_format_value(snmt_tree, hf_oss_snmt_service_id, message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1, 1,
                        packet->payload.snmt->ext_msg_id, "Additional parameter missing [Response via SN Acknowledge] (0x%02X)", packet->payload.snmt->ext_msg_id);
                col_append_str(pinfo->cinfo, COL_INFO, ", Additional parameter missing");
            }

            errcode = tvb_get_guint8(message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1 + 2);
            packet->payload.snmt->add_param.exists = TRUE;
            packet->payload.snmt->add_param.id = errcode;
            packet->payload.snmt->add_param.set = ( errcode & 0x0F ) + 1;
            packet->payload.snmt->add_param.full = ( ( errcode & 0xF0 ) == 0xF0 );

            /* Handle an additional parameter request */
            proto_tree_add_uint(snmt_tree, hf_oss_ssdo_extpar_parset, message_tvb,
                    OSS_FRAME_POS_DATA + packet->frame.subframe1 + 2, 1, ( errcode & 0x0F ) + 1 );

            proto_tree_add_boolean(snmt_tree, hf_oss_snmt_param_type, message_tvb,
                    OSS_FRAME_POS_DATA + packet->frame.subframe1 + 2, 1, ( ( errcode & 0xF0 ) != 0xF0 ) );
        }
    }
    else if ( (OSS_FRAME_ID_T(message_tvb, packet->frame.subframe1) ^ OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_service_id, message_tvb,
                OSS_FRAME_POS_DATA + packet->frame.subframe1, 1, packet->payload.snmt->ext_msg_id);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                val_to_str_const(packet->payload.snmt->ext_msg_id, opensafety_message_service_type, "Unknown"));

        if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_UDID_SCM) == 0 )
        {
            opensafety_parse_scm_udid ( message_tvb, pinfo, snmt_tree, packet, OSS_FRAME_POS_DATA + packet->frame.subframe1 + 1 );
        }
        else if ( ( db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_ADDITIONAL_SADR) == 0 )
        {
            packet->payload.snmt->add_saddr.actual = OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA + 1);
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_ext_addsaddr, message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1 + 1, 2,
                    packet->payload.snmt->add_saddr.actual );

            packet->payload.snmt->add_saddr.additional = OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA + 3);
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_ext_addtxspdo, message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1 + 3, 2,
                    packet->payload.snmt->add_saddr.additional);

            col_append_fstr(pinfo->cinfo, COL_INFO, " [0x%04X => 0x%04X]",
                    OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA + 1),
                    OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA + 3));
        }
        else if ( ( db0 ^ OPENSAFETY_MSG_SNMT_EXT_ASSIGNED_INIT_CT) == 0 )
        {
            packet->payload.snmt->init_ct =
                    tvb_get_guint40(message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA + 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(snmt_tree, hf_oss_snmt_ext_initct, message_tvb,
                    packet->frame.subframe1 + OSS_FRAME_POS_DATA + 1, 5, ENC_BIG_ENDIAN );
        }
    }
    else if ( (OSS_FRAME_ID_T(message_tvb, packet->frame.subframe1) ^ OPENSAFETY_MSG_SNMT_SERVICE_REQUEST) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_service_id, message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1, 1, db0);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(db0, opensafety_message_service_type, "Unknown"));

        if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_STOP) == 0 || (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_OP) == 0 )
        {
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_scm, message_tvb, OSS_FRAME_POS_ADDR + packet->frame.subframe1, 2, addr);
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_tool, message_tvb, packet->frame.subframe2 + 3, 2, taddr);
        }
        else if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGN_UDID_SCM) == 0 )
        {
            opensafety_parse_scm_udid ( message_tvb, pinfo, snmt_tree, packet, OSS_FRAME_POS_DATA + packet->frame.subframe1 + 1 );
        }
        else if ( ( db0 ^ OPENSAFETY_MSG_SNMT_EXT_ASSIGN_INIT_CT) == 0 )
        {
            packet->payload.snmt->init_ct =
                    tvb_get_guint40(message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA + 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(snmt_tree, hf_oss_snmt_ext_initct, message_tvb,
                    packet->frame.subframe1 + OSS_FRAME_POS_DATA + 1, 5, ENC_BIG_ENDIAN );
        }
        else
        {
            if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_SET_TO_OP) == 0 )
            {
                proto_tree_add_item ( snmt_tree, hf_oss_sod_par_timestamp, message_tvb,
                        OSS_FRAME_POS_DATA + packet->frame.subframe1 + 1, 4, ENC_LITTLE_ENDIAN );
            }
            else if ( ( db0 ^ OPENSAFETY_MSG_SNMT_EXT_ASSIGN_ADDITIONAL_SADR) == 0 )
            {
                packet->payload.snmt->add_saddr.actual = OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA + 1);
                proto_tree_add_uint(snmt_tree, hf_oss_snmt_ext_addsaddr, message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1 + 1, 2,
                        packet->payload.snmt->add_saddr.actual );

                packet->payload.snmt->add_saddr.additional = OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA + 3);
                proto_tree_add_uint(snmt_tree, hf_oss_snmt_ext_addtxspdo, message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1 + 3, 2,
                        packet->payload.snmt->add_saddr.additional);

                col_append_fstr(pinfo->cinfo, COL_INFO, " [0x%04X => 0x%04X]",
                        OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA + 1),
                        OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1 + OSS_FRAME_POS_DATA + 3));
            }

        }
    }
    else if ( (OSS_FRAME_ID_T(message_tvb, packet->frame.subframe1) ^ OPENSAFETY_MSG_SNMT_SADR_ASSIGNED) == 0 ||
            (OSS_FRAME_ID_T(message_tvb, packet->frame.subframe1) ^ OPENSAFETY_MSG_SNMT_ASSIGN_SADR) == 0 ||
            (OSS_FRAME_ID_T(message_tvb, packet->frame.subframe1) ^ OPENSAFETY_MSG_SNMT_RESPONSE_UDID) == 0 )
    {
        if (dataLength > 0)
        {
            packet->payload.snmt->sn_udid = wmem_strdup(pinfo->pool,
                    tvb_bytes_to_str_punct(pinfo->pool, message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1 + 1, 6, ':' ) );
            proto_tree_add_item(snmt_tree, hf_oss_snmt_udid, message_tvb, OSS_FRAME_POS_DATA + packet->frame.subframe1, 6, ENC_NA);
        }
    }
}

static gboolean
dissect_opensafety_checksum(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *opensafety_tree,
                            opensafety_packet_info *packet )
{
    guint16     frame1_crc, frame2_crc;
    guint16     calc1_crc, calc2_crc;
    guint       dataLength, frame2Length;
    guint8     *bytesf2, *bytesf1, ctr = 0, crcType = OPENSAFETY_CHECKSUM_CRC8;
    proto_item *item;
    proto_tree *checksum_tree;
    gint        start;
    gint        length;
    gboolean    isSlim = FALSE;
    gboolean    isSNMT = FALSE;
    gboolean    isSPDO = FALSE;
    GByteArray *scmUDID = NULL;

    dataLength = OSS_FRAME_LENGTH_T(message_tvb, packet->frame.subframe1);
    start = OSS_FRAME_POS_DATA + dataLength + packet->frame.subframe1;

    if (OSS_FRAME_LENGTH_T(message_tvb, packet->frame.subframe1) > OSS_PAYLOAD_MAXSIZE_FOR_CRC8)
        frame1_crc = tvb_get_letohs(message_tvb, start);
    else
        frame1_crc = tvb_get_guint8(message_tvb, start);

    if ( packet->msg_type == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
        isSlim = TRUE;
    if ( packet->msg_type == OPENSAFETY_SNMT_MESSAGE_TYPE )
        isSNMT = TRUE;
    if ( packet->msg_type == OPENSAFETY_SPDO_MESSAGE_TYPE )
        isSPDO = TRUE;

    frame2Length = (isSlim ? 0 : dataLength) + 5;

    length = (dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 ? OPENSAFETY_CHECKSUM_CRC16 : OPENSAFETY_CHECKSUM_CRC8);
    item = proto_tree_add_uint_format(opensafety_tree, hf_oss_crc, message_tvb, start, length, frame1_crc,
                                      "CRC for subframe #1: 0x%04X", frame1_crc);

    checksum_tree = proto_item_add_subtree(item, ett_opensafety_checksum);

    bytesf1 = (guint8*)tvb_memdup(pinfo->pool, message_tvb, packet->frame.subframe1, dataLength + 4);

    crcType = packet->crc.type;
    calc1_crc = packet->crc.frame1;

    if ( ! isSlim && crcType == OPENSAFETY_CHECKSUM_CRC16SLIM )
        expert_add_info(pinfo, item, &ei_crc_slimssdo_instead_of_spdo );

    item = proto_tree_add_boolean(checksum_tree, hf_oss_crc_valid, message_tvb,
            packet->frame.subframe1, dataLength + 4, (frame1_crc == calc1_crc));
    proto_item_set_generated(item);
    if ( crcType == OPENSAFETY_CHECKSUM_INVALID || frame1_crc != calc1_crc )
        expert_add_info(pinfo, item, &ei_crc_frame_1_invalid );

    /* using the defines, as the values can change */
    proto_tree_add_uint(checksum_tree, hf_oss_crc_type, message_tvb, start, length, crcType );

    start = packet->frame.subframe2 + (isSlim ? 5 : dataLength + OSS_FRAME_POS_DATA + 1 );
    if (OSS_FRAME_LENGTH_T(message_tvb, packet->frame.subframe1) > OSS_PAYLOAD_MAXSIZE_FOR_CRC8)
        frame2_crc = tvb_get_letohs(message_tvb, start);
    else
        frame2_crc = tvb_get_guint8(message_tvb, start);

    /* 0xFFFF is an invalid CRC16 value, therefore valid for initialization. Needed, because
     * otherwise this function may return without setting calc2_crc, and this does not go well
     * with the compiler */
    calc2_crc = 0xFFFF;

    /* Currently SPDO 40 Bit CRC2 support is broken. Will be implemented at a later state, after
     * the first generation of openSAFETY devices using 40 bit counter are available */
    if ( isSPDO && packet->payload.spdo->flags.enabled40bit == TRUE )
        packet->scm_udid_valid = FALSE;

    /* This used to be an option. But only, because otherwise there would be three different
     * crc calculations taking place within dissection. As we could reduce this by one, the
     * global option has been changed to the simple validity question, if we have enough information
     * to calculate the second crc, meaning, if the SCM udid is known, or if we have an SNMT msg */
    if ( isSNMT || packet->scm_udid_valid )
    {
        bytesf2 = (guint8*)tvb_memdup(pinfo->pool, message_tvb, packet->frame.subframe2, frame2Length + length);

        /* SLIM SSDO messages, do not contain a payload in frame2 */
        if ( isSlim == TRUE )
            dataLength = 0;

        scmUDID = g_byte_array_new();
        packet->crc.valid2 = FALSE;
        if ( isSNMT || ( hex_str_to_bytes((local_scm_udid != NULL ? local_scm_udid : global_scm_udid), scmUDID, TRUE) && scmUDID->len == 6 ) )
        {
            if ( !isSNMT )
            {
                for ( ctr = 0; ctr < 6; ctr++ )
                    bytesf2[ctr] = bytesf2[ctr] ^ (guint8)(scmUDID->data[ctr]);
                if ( isSPDO )
                {

                    /* allow only valid SPDO flags */
                    if ( packet->msg_id == OPENSAFETY_MSG_SPDO_DATA_ONLY )
                    {
                        if ( packet->payload.spdo->flags.enabled40bit == TRUE )
                        {
                            /* we assume the OPENSAFETY_DEFAULT_DOMAIN (0x01) for 40 bit for now */
                            bytesf2[0] = bytesf2[0] ^ (bytesf2[0] ^ OPENSAFETY_DEFAULT_DOMAIN ^ bytesf1[0]);
                            bytesf2[1] = bytesf2[1] ^ (bytesf2[1] ^ bytesf1[1]);
                            bytesf2[3] = 0;
                        }
                    }
                }

                if ( isSlim || packet->frame.length == 11 )
                    frame2_crc ^= ((guint8)scmUDID->data[5]);

                /*
                 * If the second frame is 6 or 7 (slim) bytes in length, we have to decode the found
                 * frame crc again. This must be done using the byte array, as the unxor operation
                 * had to take place.
                 */
                if ( dataLength == 0 )
                {
                    if ( isSlim && length == 2 )
                        frame2_crc = ( bytesf2[6] << 8 ) + bytesf2[5];
                }

            }

            item = proto_tree_add_uint_format(opensafety_tree, hf_oss_crc, message_tvb, start, length, frame2_crc,
                    "CRC for subframe #2: 0x%04X", frame2_crc);

            checksum_tree = proto_item_add_subtree(item, ett_opensafety_checksum);

            if ( OSS_FRAME_LENGTH_T(message_tvb, packet->frame.subframe1) > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 )
            {
                calc2_crc = crc16_0x755B(bytesf2, frame2Length, 0);
                if ( frame2_crc != calc2_crc )
                    calc2_crc = crc16_0x5935(bytesf2, frame2Length, 0);
            }
            else
                calc2_crc = crc8_0x2F(bytesf2, frame2Length, 0);

            item = proto_tree_add_boolean(checksum_tree, hf_oss_crc2_valid, message_tvb,
                    packet->frame.subframe2, frame2Length, (frame2_crc == calc2_crc));
            proto_item_set_generated(item);

            if ( frame2_crc != calc2_crc )
            {
                item = proto_tree_add_uint_format(checksum_tree, hf_oss_crc, message_tvb,
                        packet->frame.subframe2, frame2Length, calc2_crc, "Calculated CRC: 0x%04X", calc2_crc);
                proto_item_set_generated(item);
                expert_add_info(pinfo, item, &ei_crc_frame_2_invalid );
            }
            else
            {
                if ( global_opensafety_debug_verbose && ( isSlim || ( !isSNMT && packet->frame.length == 11 ) ) )
                    expert_add_info(pinfo, item, &ei_crc_frame_2_scm_udid_encoded );

                packet->crc.valid2 = TRUE;
            }
        }
        else
            expert_add_info(pinfo, item, &ei_crc_frame_2_unknown_scm_udid );

        g_byte_array_free(scmUDID, TRUE);
    }

    /* For a correct calculation of the second crc we need to know the scm udid.
     * If the dissection of the second frame has been triggered, we integrate the
     * crc for frame2 into the result */
    return (gboolean) (frame1_crc == calc1_crc) &&
            ( ( isSNMT || packet->scm_udid_valid ) == TRUE ? (frame2_crc == calc2_crc) : TRUE);
}

static gint
check_scmudid_validity(opensafety_packet_info *packet, tvbuff_t *message_tvb)
{
    guint8      b_ID, spdoFlags, udidLen;
    GByteArray *scmUDID = NULL;

    packet->scm_udid_valid = FALSE;
    scmUDID = g_byte_array_new();

    if ( hex_str_to_bytes((local_scm_udid != NULL ? local_scm_udid : global_scm_udid), scmUDID, TRUE) && scmUDID->len == 6 )
    {
        packet->scm_udid_valid = TRUE;

        /* Now confirm, that the xor operation was successful. The ID fields of both frames have to be the same */
        b_ID = tvb_get_guint8(message_tvb, packet->frame.subframe2 + 1) ^ (guint8)(scmUDID->data[OSS_FRAME_POS_ID]);;
        if ( ( OSS_FRAME_ID_T(message_tvb, packet->frame.subframe1) ^ b_ID ) != 0 )
            packet->scm_udid_valid = FALSE;

        /* The IDs do not match, but the SCM UDID could still be ok. This happens, if this packet
         * utilizes the 40 bit counter. Therefore we reduce the check here only to the feature
         * flags, but only if the package is a SPDO Data Only (because everything else uses 16 bit. */
        if ( packet->msg_id == OPENSAFETY_MSG_SPDO_DATA_ONLY )
        {
            spdoFlags = ( tvb_get_guint8(message_tvb, packet->frame.subframe2 + 4 ) ^ scmUDID->data[4] ) ;
            spdoFlags = ( spdoFlags >> 2 ) & OPENSAFETY_SPDO_FEATURE_FLAGS;
            if ( ( spdoFlags & OPENSAFETY_SPDO_FEAT_40BIT_USED ) == OPENSAFETY_SPDO_FEAT_40BIT_USED )
                packet->scm_udid_valid = TRUE;
        }

        if ( packet->scm_udid_valid == TRUE )
            memcpy(packet->scm_udid, scmUDID->data, 6);
    }

    udidLen = scmUDID->len;

    g_byte_array_free( scmUDID, TRUE);

    return udidLen;
}

static gboolean
dissect_opensafety_message(opensafety_packet_info *packet,
                           tvbuff_t *message_tvb, packet_info *pinfo,
                           proto_item *opensafety_item, proto_tree *opensafety_tree,
                           guint8 u_nrInPackage, guint8 previous_msg_id)
{
    guint8      ctr, udidLen;
    proto_item *item;
    gboolean    messageTypeUnknown, crcValid;

    messageTypeUnknown = FALSE;

    for ( ctr = 0; ctr < 6; ctr++ )
        packet->scm_udid[ctr] = 0;

    packet->saddr = OSS_FRAME_ADDR_T(message_tvb, packet->frame.subframe1);
    /* Sender / Receiver is determined by message type */
    packet->sender = 0;
    packet->receiver = 0;

    /* SPDO is handled below */
    if ( packet->msg_type != OPENSAFETY_SPDO_MESSAGE_TYPE )
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, (u_nrInPackage > 1 ? " | %s" : "%s" ),
            val_to_str(packet->msg_id, opensafety_message_type_values, "Unknown Message (0x%02X) "));
    }

    item = proto_tree_add_uint(opensafety_tree, hf_oss_byte_offset, packet->frame.frame_tvb, 0, 1, packet->frame.byte_offset);
    proto_item_set_generated(item);

    if ( packet->msg_type == OPENSAFETY_SNMT_MESSAGE_TYPE )
    {
        proto_item_append_text(opensafety_item, ", SNMT");
        dissect_opensafety_snmt_message ( message_tvb, pinfo, opensafety_tree, packet, opensafety_item );
    }
    else
    {
        udidLen = check_scmudid_validity(packet, message_tvb);

        if ( strlen( (local_scm_udid != NULL ? local_scm_udid : global_scm_udid) ) > 0  && udidLen == 6 )
        {
            if ( local_scm_udid != NULL )
            {
                item = proto_tree_add_string(opensafety_tree, hf_oss_scm_udid_auto, message_tvb, 0, 0, local_scm_udid);
                if ( ! packet->scm_udid_valid )
                    expert_add_info(pinfo, item, &ei_message_id_field_mismatch );
            }
            else
                item = proto_tree_add_string(opensafety_tree, hf_oss_scm_udid, message_tvb, 0, 0, global_scm_udid);
            proto_item_set_generated(item);
        }

        item = proto_tree_add_boolean(opensafety_tree, hf_oss_scm_udid_valid, message_tvb, 0, 0, packet->scm_udid_valid);
        if ( udidLen != 6 )
            expert_add_info(pinfo, item, &ei_scmudid_invalid_preference );
        proto_item_set_generated(item);

        if ( packet->msg_type == OPENSAFETY_SSDO_MESSAGE_TYPE || packet->msg_type == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
        {
            proto_item_append_text(opensafety_item,
                    (packet->msg_type == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE) ? ", Slim SSDO" : ", SSDO");
            dissect_opensafety_ssdo_message ( message_tvb, pinfo, opensafety_tree, packet, opensafety_item );
        }
        else if ( packet->msg_type == OPENSAFETY_SPDO_MESSAGE_TYPE )
        {
            proto_item_append_text(opensafety_item, ", SPDO" );
            dissect_opensafety_spdo_message ( message_tvb, pinfo, opensafety_tree, packet, opensafety_item );

            /* Now we know packet->sender, therefore we can add the info text */
            if ( previous_msg_id != packet->msg_id )
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, (u_nrInPackage > 1 ? " | %s - 0x%03X" : "%s - 0x%03X" ),
                            val_to_str(packet->msg_id, opensafety_message_type_values, "Unknown Message (0x%02X) "),
                            packet->sender );
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", 0x%03X", packet->sender );
            }
        }
        else
        {
            messageTypeUnknown = TRUE;
            proto_item_append_text(opensafety_item, ", Unknown" );
        }
    }

    crcValid = FALSE;
    item = proto_tree_add_uint(opensafety_tree, hf_oss_length,
                               message_tvb, OSS_FRAME_POS_LEN + packet->frame.subframe1, 1,
                               OSS_FRAME_LENGTH_T(message_tvb, packet->frame.subframe1));
    if ( messageTypeUnknown )
    {
        expert_add_info(pinfo, item, &ei_message_unknown_type );
    }
    else
    {
        crcValid = dissect_opensafety_checksum ( message_tvb, pinfo, opensafety_tree, packet );
    }

    /* with SNMT's we can check if the ID's for the frames match. Rare randomized packages do have
     * an issue, where an frame 1 can be valid. The id's for both frames must differ, as well as
     * the addresses, but addresses won't be checked yet, as there are issues with SDN xored on it. */
    if ( crcValid && packet->msg_type == OPENSAFETY_SNMT_MESSAGE_TYPE )
    {
        if ( OSS_FRAME_ID_T(message_tvb, packet->frame.subframe1) != OSS_FRAME_ID_T(message_tvb, packet->frame.subframe2) )
            expert_add_info(pinfo, opensafety_item, &ei_crc_frame_1_valid_frame2_invalid );
    }

    return TRUE;
}

static const char* opensafety_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if (filter == CONV_FT_SRC_ADDRESS) {
        if (conv->src_address.type == AT_NUMERIC)
            return "opensafety.msg.sender";
    }

    if (filter == CONV_FT_DST_ADDRESS) {
        if (conv->dst_address.type == AT_NUMERIC)
            return "opensafety.msg.receiver";
    }

    if (filter == CONV_FT_ANY_ADDRESS) {
        if (conv->src_address.type == AT_NUMERIC && conv->dst_address.type == AT_NUMERIC)
            return "opensafety.msg.node";
    }

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t opensafety_ct_dissector_info = {&opensafety_conv_get_filter_type};

static const char* opensafety_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter)
{
    if (host->myaddress.type == AT_NUMERIC) {
        if (filter == CONV_FT_ANY_ADDRESS)
            return "opensafety.msg.node";
        else if (filter == CONV_FT_SRC_ADDRESS)
            return "opensafety.msg.sender";
        else if (filter == CONV_FT_DST_ADDRESS)
            return "opensafety.msg.receiver";
    }

    return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t  opensafety_dissector_info = {&opensafety_get_filter_type};

static tap_packet_status
opensafety_conversation_packet(void *pct, packet_info *pinfo,
        epan_dissect_t *edt _U_, const void *vip _U_, tap_flags_t flags)
{
    address *src = (address *)wmem_alloc0(pinfo->pool, sizeof(address));
    address *dst = (address *)wmem_alloc0(pinfo->pool, sizeof(address));
    conv_hash_t *hash = (conv_hash_t*) pct;
    opensafety_packet_info * osinfo = (opensafety_packet_info *)vip;
    guint16 receiver = osinfo->receiver;
    if (osinfo->msg_type == OPENSAFETY_SPDO_MESSAGE_TYPE)
        receiver = 0x3FF;

    hash->flags = flags;

    alloc_address_wmem(pinfo->pool, src, AT_NUMERIC, (int) sizeof(guint16), &osinfo->sender);
    alloc_address_wmem(pinfo->pool, dst, AT_NUMERIC, (int) sizeof(guint16), &receiver);

    add_conversation_table_data(hash, src, dst, 0, 0, 1, osinfo->msg_len, &pinfo->rel_ts, &pinfo->abs_ts,
            &opensafety_ct_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}

static tap_packet_status
opensafety_hostlist_packet(void *pit, packet_info *pinfo,
        epan_dissect_t *edt _U_, const void *vip _U_, tap_flags_t flags)
{
    address *src = (address *)wmem_alloc0(pinfo->pool, sizeof(address));
    address *dst = (address *)wmem_alloc0(pinfo->pool, sizeof(address));
    conv_hash_t *hash = (conv_hash_t*) pit;
    opensafety_packet_info * osinfo = (opensafety_packet_info *)vip;
    guint16 receiver = osinfo->receiver;
    if (osinfo->msg_type == OPENSAFETY_SPDO_MESSAGE_TYPE)
        receiver = 0x3FF;

    hash->flags = flags;

    alloc_address_wmem(pinfo->pool, src, AT_NUMERIC, (int) sizeof(guint16), &osinfo->sender);
    alloc_address_wmem(pinfo->pool, dst, AT_NUMERIC, (int) sizeof(guint16), &receiver);

    add_hostlist_table_data(hash, src, 0, TRUE,  1, osinfo->msg_len, &opensafety_dissector_info, ENDPOINT_NONE);
    add_hostlist_table_data(hash, dst, 0, FALSE, 1, osinfo->msg_len, &opensafety_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}

static gboolean
opensafety_package_dissector(const gchar *protocolName, const gchar *sub_diss_handle,
                             gboolean b_frame2First, gboolean do_byte_swap, guint8 force_nr_in_package,
                             tvbuff_t *given_tvb, packet_info *pinfo, proto_tree *tree, guint8 transporttype )
{
    tvbuff_t           *next_tvb = NULL, *gap_tvb = NULL, *message_tvb = NULL;
    guint               length, len, frameOffset, frameLength, nodeAddress, gapStart;
    guint8             *swbytes;
    gboolean            handled, dissectorCalled, call_sub_dissector, markAsMalformed;
    guint8              type, found, i, tempByte, previous_msg_id;
    guint16             frameStart1, frameStart2, byte_offset;
    gint                reported_len;
    dissector_handle_t  protocol_dissector = NULL;
    proto_item         *opensafety_item;
    proto_tree         *opensafety_tree;

    opensafety_packet_info *packet = NULL;

    handled            = FALSE;
    dissectorCalled    = FALSE;
    call_sub_dissector = FALSE;
    markAsMalformed    = FALSE;
    previous_msg_id    = 0;

    /* registering frame end routine, to prevent a malformed dissection preventing
     * further dissector calls (see bug #6950) */
    register_frame_end_routine(pinfo, reset_dissector);

    length = tvb_reported_length(given_tvb);
    /* Minimum package length is 11 */
    if ( length < OSS_MINIMUM_LENGTH )
        return FALSE;

    /* Determine dissector handle for sub-dissection */
    if ( strlen( sub_diss_handle ) > 0 )
    {
        call_sub_dissector = TRUE;
        protocol_dissector = find_dissector ( sub_diss_handle );
        if ( protocol_dissector == NULL )
            protocol_dissector = data_dissector;
    }

    reported_len = tvb_reported_length_remaining(given_tvb, 0);

    /* This will swap the bytes according to MBTCP encoding */
    if ( do_byte_swap == TRUE && global_mbtcp_big_endian == TRUE )
    {
        /* Because of padding bytes at the end of the frame, tvb_memdup could lead
         * to a "openSAFETY truncated" message. By ensuring, that we have enough
         * bytes to copy, this will be prevented. */
        if ( ! tvb_bytes_exist ( given_tvb, 0, length ) )
            return FALSE;

        swbytes = (guint8 *) tvb_memdup( pinfo->pool, given_tvb, 0, length);

        /* Wordswapping for modbus detection */
        /* Only a even number of bytes can be swapped */
        len = (length / 2);
        for ( i = 0; i < len; i++ )
        {
            tempByte = swbytes [ 2 * i ]; swbytes [ 2 * i ] = swbytes [ 2 * i + 1 ]; swbytes [ 2 * i + 1 ] = tempByte;
        }

        message_tvb = tvb_new_real_data(swbytes, length, reported_len);
    } else {
        message_tvb = given_tvb;
    }

    frameOffset = 0;
    frameLength = 0;
    found = 0;

    /* Counter to determine gaps between openSAFETY packages */
    gapStart = 0;

    while ( frameOffset < length )
    {
        /* Reset the next_tvb buffer */
        next_tvb = NULL;

        /* Smallest possible frame size is 11, but this check must ensure, that even the last frame
         * will get considered, which leads us with 10, as the first byte checked is the second one */
        if ( tvb_captured_length_remaining(message_tvb, frameOffset ) < ( OSS_MINIMUM_LENGTH - 1 ) )
            break;

        /* Resetting packet, to ensure, that findSafetyFrame starts with a fresh frame.
         * As only packet_scope is used, this will not polute memory too much and get's
         * cleared with the next packet anyway  */
        packet = wmem_new0(pinfo->pool, opensafety_packet_info);

        /* Finding the start of the first possible safety frame */
        if ( findSafetyFrame(pinfo, message_tvb, frameOffset, b_frame2First, &frameOffset, &frameLength, packet) )
        {
            /* if packet msg_id is not null, it still might be an incorrect frame, as there is no validity
             * check in findSafetyFrame for the msg id (this happens later in this routine)
             * frameLength is calculated/read directly from the dissected data. If frameLength and frameOffset together
             * are bigger than the reported length, the package is not really an openSAFETY package */
            if ( packet->msg_id == 0 || ( frameOffset + frameLength ) > (guint)reported_len )
                break;

            found++;

            byte_offset = ( b_frame2First ? 0 : frameOffset );
            /* We determine a possible position for frame 1 and frame 2 */
            if ( b_frame2First )
            {
                frameStart1 = findFrame1Position (pinfo, message_tvb, byte_offset, frameLength, FALSE );
                frameStart2 = 0;
            }
            else
            {
                frameStart1 = 0;
                frameStart2 = ((OSS_FRAME_LENGTH_T(message_tvb, byte_offset + frameStart1) - 1) +
                        (OSS_FRAME_LENGTH_T(message_tvb, byte_offset + frameStart1) > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 ? OSS_SLIM_FRAME2_WITH_CRC16 : OSS_SLIM_FRAME2_WITH_CRC8));
            }

            /* If both frame starts are equal, something went wrong. In which case, we retract the found entry, and
             * also increase the search offset, just doing a continue will result in an infinite loop. */
            if (frameStart1 == frameStart2)
            {
                found--;
                frameOffset += frameLength;
                continue;
            }

            /* We determine the possible type, and return false, if there could not be one */
            packet->msg_id = OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1);
            if ( ( packet->msg_id & OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
                type = OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE;
            else if ( ( packet->msg_id & OPENSAFETY_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SSDO_MESSAGE_TYPE )
                type = OPENSAFETY_SSDO_MESSAGE_TYPE;
            else if ( ( packet->msg_id & OPENSAFETY_SPDO_MESSAGE_TYPE ) == OPENSAFETY_SPDO_MESSAGE_TYPE )
                type = OPENSAFETY_SPDO_MESSAGE_TYPE;
            else if ( ( packet->msg_id & OPENSAFETY_SNMT_MESSAGE_TYPE ) == OPENSAFETY_SNMT_MESSAGE_TYPE )
                type = OPENSAFETY_SNMT_MESSAGE_TYPE;
            else
            {
                /* This is an invalid openSAFETY package, but it could be an undetected slim ssdo message. This specific error
                 * will only occur, if findFrame1Position is in play. So we search once more, but this time calculating the CRC.
                 * The reason for the second run is, that calculating the CRC is time consuming.  */
                if ( b_frame2First )
                {
                    /* Now let's check again, but this time calculate the CRC */
                    frameStart1 = findFrame1Position(pinfo, message_tvb, ( b_frame2First ? 0 : frameOffset ), frameLength, TRUE );
                    frameStart2 = 0;

                    packet->msg_id = OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1);
                    if ( ( packet->msg_id & OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
                        type = OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE;
                    else if ( ( packet->msg_id & OPENSAFETY_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SSDO_MESSAGE_TYPE )
                        type = OPENSAFETY_SSDO_MESSAGE_TYPE;
                    else if ( ( packet->msg_id & OPENSAFETY_SPDO_MESSAGE_TYPE ) == OPENSAFETY_SPDO_MESSAGE_TYPE )
                        type = OPENSAFETY_SPDO_MESSAGE_TYPE;
                    else if ( ( packet->msg_id & OPENSAFETY_SNMT_MESSAGE_TYPE ) == OPENSAFETY_SNMT_MESSAGE_TYPE )
                        type = OPENSAFETY_SNMT_MESSAGE_TYPE;
                    else {
                        /* Skip this frame.  We cannot continue without
                           advancing frameOffset - just doing a continue
                           will result in an infinite loop. Advancing with 1 will
                           lead to infinite loop, advancing with frameLength might miss
                           some packages*/
                        frameOffset += 2;
                        found--;
                        continue;
                    }
                } else {
                    /* As stated above, you cannot just continue
                       without advancing frameOffset. Advancing with 1 will
                       lead to infinite loop, advancing with frameLength might miss
                       some packages*/
                    frameOffset += 2;
                    found--;
                    continue;
                }
            }

            /* Sorting messages for transporttype */
            if ( global_classify_transport && transporttype != OPENSAFETY_ANY_TRANSPORT )
            {
                /* Cyclic data is transported via SPDOs and acyclic is transported via SNMT, SSDO. Everything
                 * else is misclassification */
                if ( ( transporttype == OPENSAFETY_ACYCLIC_DATA && type == OPENSAFETY_SPDO_MESSAGE_TYPE ) ||
                        ( transporttype == OPENSAFETY_CYCLIC_DATA && type != OPENSAFETY_SPDO_MESSAGE_TYPE ) )
                {
                    frameOffset += 2;
                    found--;
                    continue;
                }
            }

            /* Some faulty packages do indeed have a valid first frame, but the second is
             * invalid. These checks should prevent most faulty detections */
            if ( type != OPENSAFETY_SPDO_MESSAGE_TYPE )
            {
                /* Is the given type at least known? */
                gint idx = -1;
                try_val_to_str_idx(OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1), opensafety_message_type_values, &idx );
                /* Unknown Frame Type */
                if ( idx < 0 )
                {
                    frameOffset += 2;
                    found--;
                    continue;
                }
                /* Frame IDs do not match */
                else if ( type == OPENSAFETY_SNMT_MESSAGE_TYPE &&
                        (OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1) != OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart2)) )
                {
                    frameOffset += 2;
                    found--;
                    continue;
                }
            }

            /* If this package is not valid, the next step, which normally occurs in unxorFrame will lead to a
             * frameLength bigger than the maximum data size. This is an indicator, that the package in general
             * is fault, and therefore we return false. Increasing the frameOffset will lead to out-of-bounds
             * for tvb_* functions. And frameLength errors are misidentified packages most of the times anyway */
            if ( ( (gint)frameLength - (gint)( frameStart2 > frameStart1 ? frameStart2 : frameLength - frameStart1 ) ) < 0 )
                return FALSE;

            /* Some SPDO based sanity checks, still a lot of faulty SPDOs remain, because they
             * cannot be filtered, without throwing out too many positives. */
            if ( type == OPENSAFETY_SPDO_MESSAGE_TYPE )
            {
                /* Checking if there is a node address set, or the package is invalid. Some PRes
                 * messages in EPL may double as valid subframes 1. If the nodeAddress is out of
                 * range, the package is marked as malformed */
                nodeAddress = OSS_FRAME_ADDR_T(message_tvb, byte_offset + frameStart1);
                if ( nodeAddress == 0 || nodeAddress > 1024 ) {
                    markAsMalformed = TRUE;
                }

                /* SPDO Reserved is invalid, therefore all packages using this ID can be discarded */
                if ( OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1) == OPENSAFETY_MSG_SPDO_RESERVED )
                {
                    frameOffset += 2;
                    found--;
                    continue;
                }
            }

            /* Filter node list */
            gint addr = OSS_FRAME_ADDR_T(message_tvb, byte_offset + frameStart1);
            if ( global_filter_list && wmem_list_count ( global_filter_list ) > 0 )
            {
                gboolean found_in_list = wmem_list_find(global_filter_list, GINT_TO_POINTER( addr )) ? TRUE : FALSE;

                if ( ( ! global_show_only_node_in_filter && found_in_list ) ||
                        ( global_show_only_node_in_filter && ! found_in_list ) )
                {
                    opensafety_item = proto_tree_add_item(tree, proto_opensafety, message_tvb, frameOffset, frameLength, ENC_NA);
                    proto_item_append_text(opensafety_item, ", Filtered Node: 0x%03X (%d)", addr, addr);
                    frameOffset += 2;
                    found--;
                    continue;
                }
            }

            /* From here on, the package should be correct. Even if it is not correct, it will be dissected
             * anyway and marked as malformed. Therefore it can be assumed, that a gap will end here.
             */
            if ( global_display_intergap_data == TRUE && gapStart != frameOffset )
            {
                /* Storing the gap data in subset, and calling the data dissector to display it */
                gap_tvb = tvb_new_subset_length_caplen(message_tvb, gapStart, (frameOffset - gapStart), reported_len);
                call_dissector(data_dissector, gap_tvb, pinfo, tree);
            }
            /* Setting the gap to the next offset */
            gapStart = frameOffset + frameLength;

            /* Adding second data source */
            next_tvb = tvb_new_subset_length_caplen ( message_tvb, frameOffset, frameLength, reported_len );

            /* Adding a visual aid to the dissector tree */
            add_new_data_source(pinfo, next_tvb, "openSAFETY Frame");

            /* A new subtype for package dissection will need to set the actual nr. for the whole dissected package */
            if ( force_nr_in_package > 0 )
            {
                found = force_nr_in_package + 1;
                dissectorCalled = TRUE;
                col_set_str(pinfo->cinfo, COL_PROTOCOL, protocolName);
            }

            if ( ! dissectorCalled )
            {
                if ( call_sub_dissector )
                    call_dissector(protocol_dissector, message_tvb, pinfo, tree);
                dissectorCalled = TRUE;

                col_set_str(pinfo->cinfo, COL_PROTOCOL, protocolName);
                col_clear(pinfo->cinfo, COL_INFO);
            }

            /* if the tree is NULL, we are called for the overview, otherwise for the
               more detailed view of the package */
            if ( tree )
            {
                /* create the opensafety protocol tree */
                opensafety_item = proto_tree_add_item(tree, proto_opensafety, message_tvb, frameOffset, frameLength, ENC_NA);
                opensafety_tree = proto_item_add_subtree(opensafety_item, ett_opensafety);
            } else {
                opensafety_item = NULL;
                opensafety_tree = NULL;
            }

            /* Setting type to packet_info */
            packet->msg_type = type;

            packet->frame.frame_tvb = next_tvb;
            packet->frame.byte_offset = frameOffset + tvb_raw_offset(message_tvb);
            packet->frame.subframe1 = frameStart1;
            packet->frame.subframe2 = frameStart2;
            packet->frame.length = frameLength;
            packet->frame.malformed = FALSE;

            /* Clearing connection valid bit */
            if ( packet->msg_type == OPENSAFETY_SPDO_MESSAGE_TYPE )
                packet->msg_id = packet->msg_id & 0xF8;

            if ( dissect_opensafety_message(packet, next_tvb, pinfo, opensafety_item, opensafety_tree, found, previous_msg_id) != TRUE )
                markAsMalformed = TRUE;

            previous_msg_id = packet->msg_id;

            if ( markAsMalformed )
            {
                packet->frame.malformed = TRUE;
                if ( OSS_FRAME_ADDR_T(message_tvb, byte_offset + frameStart1) > 1024 )
                    expert_add_info(pinfo, opensafety_item, &ei_message_spdo_address_invalid );
            }

            tap_queue_packet(opensafety_tap, pinfo, packet);

            /* Something is being displayed, therefore this dissector returns true */
            handled = TRUE;
        }
        else
            break;

        /* findSafetyFrame starts at frameOffset with the search for the next position. But the
         * offset is assumed to be the ID, which can lead to scenarios, where the CRC of a previous
         * detected frame is assumed to be the addr of the next one. +1 prevents such a scenario.
         * It must be checked, if the resulting frameOffset does not scratch the max length. It
         * cannot exceed by adding just frameLength, as this value is a result of the heuristic, and
         * therefore must be within the correct length, but it can exceed if +1 is added unchecked. */
        frameOffset += frameLength;
        if ( tvb_captured_length_remaining(message_tvb, frameOffset) > 0 )
            frameOffset += 1;
    }

    if ( handled == TRUE )
    {
        /* There might be some undissected data at the end of the frame (e.g. SercosIII) */
        if ( frameOffset < length && global_display_intergap_data == TRUE && gapStart != frameOffset )
        {
            /* Storing the gap data in subset, and calling the data dissector to display it */
            gap_tvb = tvb_new_subset_length_caplen(message_tvb, gapStart, (length - gapStart), reported_len);
            call_dissector(data_dissector, gap_tvb, pinfo, tree);
        }
    }

    return ( handled ? TRUE : FALSE );
}

static gboolean
dissect_opensafety_epl(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data )
{
    gboolean        result     = FALSE;
    proto_tree      *epl_tree = NULL;
    guint8  epl_msgtype = 0;

    /* We will call the epl dissector by using call_dissector(). The epl dissector will then call
     * the heuristic openSAFETY dissector again. By setting this information, we prevent a dissector
     * loop */
    if ( bDissector_Called_Once_Before == FALSE )
    {
        bDissector_Called_Once_Before = TRUE;

        /* Set the tree up, until it is par with the top-level */
        epl_tree = tree;
        while ( epl_tree != NULL && epl_tree->parent != NULL )
            epl_tree = epl_tree->parent;

        /* Ordering message type to traffic types */
        if ( *((guint8*)data) == 0x03 || *((guint8*)data) == 0x04 )
            epl_msgtype = OPENSAFETY_CYCLIC_DATA;
        else
            epl_msgtype = OPENSAFETY_ACYCLIC_DATA;

        /* We check if we have a asynchronous message, or a synchronous message. In case of
         * asynchronous messages, SPDO packages are not valid. */

        result = opensafety_package_dissector("openSAFETY/Powerlink", "",
                FALSE, FALSE, 0, message_tvb, pinfo, epl_tree, epl_msgtype );

        bDissector_Called_Once_Before = FALSE;
    }

    return result;
}

static gboolean
dissect_opensafety_siii(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    gboolean        result     = FALSE;
    gboolean        udp        = FALSE;
    guint8          firstByte;

    /* The UDP dissection is not done by a heuristic, but rather by a normal dissector. But
     * the customer may not expect, that if (s)he disables the SercosIII dissector, that the
     * SercosIII UDP packages get still dissected. This will disable them as well. */
    if ( ! heuristic_siii_dissection_enabled )
        return FALSE;

    /* We will call the SercosIII dissector by using call_dissector(). The SercosIII dissector will
     * then call the heuristic openSAFETY dissector again. By setting this information, we prevent
     * a dissector loop. */
    if ( bDissector_Called_Once_Before == FALSE )
    {
        udp = pinfo->destport == OPENSAFETY_UDP_PORT_SIII;

        bDissector_Called_Once_Before = TRUE;
        /* No frames can be sent in AT messages, therefore those get filtered right away */
        firstByte = ( tvb_get_guint8(message_tvb, 0) << 1 );
        if ( udp || ( firstByte & 0x40 ) == 0x40 )
        {
            result = opensafety_package_dissector( "openSAFETY/SercosIII",
                    udp ? "" : "sercosiii",
                    FALSE, FALSE, 0, message_tvb, pinfo, tree,
                    udp ? OPENSAFETY_ACYCLIC_DATA : OPENSAFETY_CYCLIC_DATA );
        }
        bDissector_Called_Once_Before = FALSE;
    }

    return result;
}

static gboolean
dissect_opensafety_pn_io(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    gboolean        result     = FALSE;

    /* We will call the pn_io dissector by using call_dissector(). The epl dissector will then call
     * the heuristic openSAFETY dissector again. By setting this information, we prevent a dissector
     * loop */
    if ( bDissector_Called_Once_Before == FALSE )
    {
        bDissector_Called_Once_Before = TRUE;
        result = opensafety_package_dissector("openSAFETY/Profinet IO", "pn_io",
                                              FALSE, FALSE, 0, message_tvb, pinfo, tree, OPENSAFETY_ANY_TRANSPORT);
        bDissector_Called_Once_Before = FALSE;
    }

    return result;
}

static gboolean
dissect_opensafety_mbtcp(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    if ( ! global_enable_mbtcp )
        return FALSE;

    /* When Modbus/TCP gets dissected, openSAFETY would be sorted as a child protocol. Although,
     * this behaviour is technically correct, it differs from other implemented IEM protocol handlers.
     * Therefore, the openSAFETY frame gets put one up, if the parent is not NULL */
    return opensafety_package_dissector("openSAFETY/Modbus TCP", "", FALSE, TRUE, 0,
                                        message_tvb, pinfo, ( ((tree != NULL) && (tree->parent != NULL)) ? tree->parent : tree ),
                                        OPENSAFETY_ANY_TRANSPORT);
}

static gboolean
opensafety_udp_transport_dissector(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item      *ti = NULL;
    proto_tree      *transport_tree = NULL;
    gint            offset = 0;
    tvbuff_t        *os_tvb = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "openSAFETY over UDP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_oss_udp_transport, message_tvb, 0, -1, ENC_NA);
    transport_tree = proto_item_add_subtree(ti, ett_opensafety);

    proto_tree_add_item(transport_tree, hf_oss_udp_transport_version, message_tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(transport_tree, hf_oss_udp_transport_flags_type, message_tvb, 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(transport_tree, hf_oss_udp_transport_counter, message_tvb, 2, 2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(transport_tree, hf_oss_udp_transport_sender, message_tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(transport_tree, hf_oss_udp_transport_datapoint, message_tvb, 8, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(transport_tree, hf_oss_udp_transport_length, message_tvb, 10, 2, ENC_LITTLE_ENDIAN);
    offset += 12;

    os_tvb = tvb_new_subset_remaining(message_tvb, offset);

    if ( ! opensafety_package_dissector("openSAFETY/UDP", "", FALSE,
            FALSE, 0, os_tvb, pinfo, tree, OPENSAFETY_ANY_TRANSPORT ) )
        call_dissector(find_dissector("data"), os_tvb, pinfo, transport_tree);

    return TRUE;
}

static gboolean
dissect_opensafety_udpdata(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    gboolean       result   = FALSE;
    static guint32 frameNum = 0;
    static guint32 frameIdx = 0;

    gboolean frameFound = FALSE;
    guint    frameOffset = 0;
    guint    frameLength = 0;

    if ( pinfo->destport == OPENSAFETY_UDP_PORT_SIII )
        return dissect_opensafety_siii(message_tvb, pinfo, tree, data);

    if ( ! global_enable_udp )
        return result;

    /* An openSAFETY frame has at least OSS_MINIMUM_LENGTH bytes */
    if ( tvb_captured_length ( message_tvb ) < OSS_MINIMUM_LENGTH )
        return result;

    /* More than one openSAFETY package could be transported in the same frame,
     * in such a case, we need to establish the number of packages inside the frame */
    if ( pinfo->num != frameNum )
    {
        frameIdx = 0;
        frameNum = pinfo->num;
    }

    /* check for openSAFETY frame at beginning of data */

    frameFound = findSafetyFrame(pinfo, message_tvb, 0, global_udp_frame2_first, &frameOffset, &frameLength, NULL );
    if ( ! frameFound || ( frameOffset >= 11 ) )
    {
        dissector_handle_t udp_transport = find_dissector ( "opensafety_udp_transport" );
        if ( udp_transport != NULL )
            call_dissector(udp_transport, message_tvb, pinfo, tree);
        result = opensafety_udp_transport_dissector(message_tvb, pinfo, tree);
    }
    else
        result = opensafety_package_dissector("openSAFETY/UDP", "", global_udp_frame2_first,
                                          FALSE, frameIdx, message_tvb, pinfo, tree, OPENSAFETY_ACYCLIC_DATA );

    if ( result )
        frameIdx++;

    return result;
}

static void
apply_prefs ( void )
{
    static guint    opensafety_udp_port_number;
    static guint    opensafety_udp_siii_port_number;
    static gboolean opensafety_init = FALSE;

    /* It only should delete dissectors, if run for any time except the first */
    if ( opensafety_init )
    {
        /* Delete dissectors in preparation of a changed config setting */
        dissector_delete_uint ("udp.port", opensafety_udp_port_number, opensafety_udptransport_handle);
        dissector_delete_uint ("udp.port", opensafety_udp_siii_port_number, opensafety_udpdata_handle);
    }
    opensafety_init = TRUE;

    /* Storing the port numbers locally, to being able to delete the old associations */
    opensafety_udp_port_number = global_network_udp_port;
    opensafety_udp_siii_port_number = global_network_udp_port_sercosiii;

    /* Default UDP only based dissector, will hand traffic to SIII dissector if needed */
    /* Preference names to specific to use "auto" preference */
    dissector_add_uint("udp.port", opensafety_udp_port_number, opensafety_udptransport_handle);
    dissector_add_uint("udp.port", opensafety_udp_siii_port_number, opensafety_udpdata_handle);
}

void
proto_register_opensafety(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_oss_scm_udid,
          { "SCM UDID Configured",    "opensafety.scm_udid",
            FT_STRING,   BASE_NONE, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_scm_udid_auto,
          { "SCM UDID Auto Detect",    "opensafety.scm_udid.auto",
            FT_STRING,   BASE_NONE, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_scm_udid_valid,
          { "SCM UDID Valid",    "opensafety.scm_udid.valid",
            FT_BOOLEAN,   BASE_NONE, NULL,   0x0, NULL, HFILL } },

        { &hf_oss_byte_offset,
          { "Byte Offset",    "opensafety.msg.byte_offset",
            FT_UINT16,  BASE_HEX, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_msg,
          { "Message",    "opensafety.msg.id",
            FT_UINT8,   BASE_HEX, VALS(opensafety_message_type_values),   0x0, NULL, HFILL } },
        { &hf_oss_msg_category,
          { "Type",  "opensafety.msg.type",
            FT_UINT8,   BASE_HEX, VALS(opensafety_msg_id_values),   0xE0, NULL, HFILL } },
        { &hf_oss_msg_direction,
          { "Direction",  "opensafety.msg.direction",
            FT_BOOLEAN,   8, TFS(&opensafety_message_direction),   0x04, NULL, HFILL } },
        { &hf_oss_msg_node,
          { "Safety Node",  "opensafety.msg.node",
            FT_UINT16,   BASE_HEX, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_msg_network,
          { "Safety Domain",  "opensafety.msg.network",
            FT_UINT16,   BASE_HEX, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_msg_sender,
          { "SN send from",  "opensafety.msg.sender",
            FT_UINT16,   BASE_HEX, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_msg_receiver,
          { "SN send to",  "opensafety.msg.receiver",
            FT_UINT16,   BASE_HEX, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_length,
          { "Length",    "opensafety.length",
            FT_UINT8,   BASE_DEC, NULL,     0x0, NULL, HFILL } },
        { &hf_oss_crc,
          { "CRC",       "opensafety.crc.data",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },

        { &hf_oss_crc_valid,
          { "Is Valid", "opensafety.crc.valid",
            FT_BOOLEAN, BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_crc_type,
          { "CRC Type",  "opensafety.crc.type",
            FT_UINT8,   BASE_DEC, VALS(opensafety_frame_crc_type),    0x0, NULL, HFILL } },
        { &hf_oss_crc2_valid,
          { "Is Valid", "opensafety.crc2.valid",
            FT_BOOLEAN, BASE_NONE, NULL,    0x0, NULL, HFILL } },

        /* SNMT Specific fields */
        { &hf_oss_snmt_slave,
          { "SNMT Slave",    "opensafety.snmt.slave",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_master,
          { "SNMT Master",   "opensafety.snmt.master",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_scm,
          { "SCM",    "opensafety.snmt.scm",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_tool,
          { "Tool ID",   "opensafety.snmt.tool_id",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_udid,
          { "UDID for SN",   "opensafety.snmt.udid",
            FT_ETHER,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_service_id,
          { "Extended Service ID",   "opensafety.snmt.service_id",
            FT_UINT8,  BASE_HEX, VALS(opensafety_message_service_type),    0x0, NULL, HFILL } },
        { &hf_oss_snmt_error_group,
          { "Error Group",   "opensafety.snmt.error_group",
            FT_UINT8,  BASE_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_error_code,
          { "Error Code",   "opensafety.snmt.error_code",
            FT_UINT8,  BASE_DEC, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_snmt_param_type,
          { "Parameter Request Type",   "opensafety.snmt.parameter_type",
            FT_BOOLEAN,  BASE_NONE, TFS(&opensafety_addparam_request),   0x0, NULL, HFILL } },
        { &hf_oss_snmt_ext_addsaddr,
          { "Additional SADDR",    "opensafety.snmt.additional.saddr",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_ext_addtxspdo,
          { "Additional TxSPDO",    "opensafety.snmt.additional.txspdo",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_ext_initct,
          { "Initial CT", "opensafety.snmt.initct",
            FT_UINT40,  BASE_HEX, NULL,    0x0, NULL, HFILL } },

        /* SSDO Specific fields */
        { &hf_oss_ssdo_server,
          { "SSDO Server", "opensafety.ssdo.master",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_client,
          { "SSDO Client", "opensafety.ssdo.client",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sano,
          { "SOD Access Request Number", "opensafety.ssdo.sano",
            FT_UINT16,  BASE_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd,
          { "SOD Access Command", "opensafety.ssdo.sacmd",
            FT_UINT8,  BASE_HEX, VALS(opensafety_ssdo_sacmd_values),    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sod_index,
          { "SOD Index", "opensafety.ssdo.sodentry.index",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sod_subindex,
          { "SOD Sub Index", "opensafety.ssdo.sodentry.subindex",
            FT_UINT8,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_payload,
          { "SOD Payload", "opensafety.ssdo.payload",
            FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_payload_size,
          { "SOD Payload Size", "opensafety.ssdo.payloadsize",
            FT_UINT32,  BASE_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sodentry_size,
          { "SOD Entry Size", "opensafety.ssdo.sodentry.size",
            FT_UINT32,  BASE_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sodentry_data,
          { "SOD Data", "opensafety.ssdo.sodentry.data",
            FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_sod_par_timestamp,
          { "Parameter Timestamp", "opensafety.sod.parameter.timestamp",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_sod_par_checksum,
          { "Parameter Checksum", "opensafety.sod.parameter.checksum",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_oss_ssdo_sodmapping,
          { "Mapping entry", "opensafety.sod.mapping",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sodmapping_bits,
          { "Mapping size", "opensafety.sod.mapping.bits",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_oss_ssdo_extpar_parset,
          { "Additional Parameter Set", "opensafety.ssdo.extpar.setnr",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar_version,
          { "Parameter Set Version", "opensafety.ssdo.extpar.version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar_saddr,
          { "Parameter Set for SADDR", "opensafety.ssdo.extpar.saddr",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar_length,
          { "Parameter Set Length", "opensafety.ssdo.extpar.length",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar_crc,
          { "Parameter Set CRC", "opensafety.ssdo.extpar.crc",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar_tstamp,
          { "Timestamp", "opensafety.ssdo.extpar.timestamp",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar_data,
          { "Ext. Parameter Data", "opensafety.ssdo.extpar.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar,
          { "Ext. Parameter", "opensafety.ssdo.extpar",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        {&hf_oss_fragments,
         {"Message fragments", "opensafety.ssdo.fragments",
          FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment,
         {"Message fragment", "opensafety.ssdo.fragment",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment_overlap,
         {"Message fragment overlap", "opensafety.ssdo.fragment.overlap",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment_overlap_conflicts,
         {"Message fragment overlapping with conflicting data",
          "opensafety.ssdo.fragment.overlap.conflicts",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment_multiple_tails,
         {"Message has multiple tail fragments", "opensafety.ssdo.fragment.multiple_tails",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment_too_long_fragment,
         {"Message fragment too long", "opensafety.ssdo.fragment.too_long_fragment",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment_error,
         {"Message defragmentation error", "opensafety.ssdo.fragment.error",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment_count,
         {"Message fragment count", "opensafety.ssdo.fragment.count",
          FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_reassembled_in,
         {"Reassembled in", "opensafety.ssdo.reassembled.in",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_reassembled_length,
         {"Reassembled length", "opensafety.ssdo.reassembled.length",
          FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_reassembled_data,
         {"Reassembled Data", "opensafety.ssdo.reassembled.data",
          FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        { &hf_oss_ssdo_abort_code,
          { "Abort Code", "opensafety.ssdo.abortcode",
            FT_UINT32,  BASE_HEX, NULL,    0x0, NULL, HFILL } },

        { &hf_oss_ssdo_preload_error,
          { "Wrong/missing segment", "opensafety.ssdo.preload.error",
            FT_BOOLEAN, 8, NULL,    0x30, NULL, HFILL } },
        { &hf_oss_ssdo_preload_queue,
          { "Preload Queue Size", "opensafety.ssdo.preload.queuesize",
            FT_UINT8,  BASE_DEC, NULL,    0x0, NULL, HFILL } },

        /* SSDO SACmd specific fields */
        { &hf_oss_ssdo_sacmd_access_type,
          { "Access Direction", "opensafety.ssdo.sacmd.access",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_acc), OPENSAFETY_SSDO_SACMD_ACC, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_preload,
          { "Preload Transfer", "opensafety.ssdo.sacmd.preload",
            FT_BOOLEAN,  8, TFS(&tfs_enabled_disabled), OPENSAFETY_SSDO_SACMD_PRLD, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_abort_transfer,
          { "Abort Transfer", "opensafety.ssdo.sacmd.abort_transfer",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_abrt), OPENSAFETY_SSDO_SACMD_ABRT, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_segmentation,
          { "Segmentation", "opensafety.ssdo.sacmd.segmentation",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_seg), OPENSAFETY_SSDO_SACMD_SEG, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_toggle,
          { "Toggle Bit", "opensafety.ssdo.sacmd.toggle",
            FT_BOOLEAN,  8, TFS(&tfs_on_off), OPENSAFETY_SSDO_SACMD_TGL, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_initiate,
          { "Initiate Transfer", "opensafety.ssdo.sacmd.initiate",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_ini), OPENSAFETY_SSDO_SACMD_INI, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_end_segment,
          { "End Segment", "opensafety.ssdo.sacmd.end_segment",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_ensg), OPENSAFETY_SSDO_SACMD_ENSG, NULL, HFILL } },
#if 0
        { &hf_oss_ssdo_sacmd_reserved,
          { "Reserved", "opensafety.ssdo.sacmd.reserved",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_res), OPENSAFETY_SSDO_SACMD_RES, NULL, HFILL } },
#endif

        /* SPDO Specific fields */
        { &hf_oss_spdo_connection_valid,
          { "Connection Valid Bit", "opensafety.spdo.connection_valid",
            FT_BOOLEAN,  8, TFS(&tfs_set_notset),  0x04, NULL, HFILL } },
        { &hf_oss_spdo_direction,
          { "Send to",  "opensafety.spdo.direction",
            FT_BOOLEAN,   8, TFS(&opensafety_spdo_direction),   0x08, NULL, HFILL } },
        { &hf_oss_spdo_ct,
          { "Consecutive Time", "opensafety.spdo.ct",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_spdo_ct_40bit,
          { "Consecutive Time 40bit", "opensafety.spdo.ct40bit",
            FT_UINT40,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_spdo_time_request,
          { "Time Request Counter", "opensafety.spdo.time.request_counter",
            FT_UINT8,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_spdo_time_request_to,
          { "Time Request from", "opensafety.spdo.time.request_from",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_spdo_time_request_from,
          { "Time Request by", "opensafety.spdo.time.request_to",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_spdo_feature_flags,
          { "SPDO Feature Flags", "opensafety.spdo.featureflags",
            FT_UINT8,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_spdo_feature_flag_40bit_available,
          { "40Bit Request", "opensafety.spdo.features.40bitrequest",
            FT_BOOLEAN,  8, TFS(&tfs_requested_not_requested), (OPENSAFETY_SPDO_FEAT_40BIT_AVAIL << 2), NULL, HFILL } },
        { &hf_oss_spdo_feature_flag_40bit_used,
          { "40Bit Counter", "opensafety.spdo.features.40bitactive",
            FT_BOOLEAN,  8, TFS(&tfs_enabled_disabled), (OPENSAFETY_SPDO_FEAT_40BIT_USED << 2), NULL, HFILL } },
    };

    /* Setup list of header fields */
    static hf_register_info hf_oss_udp_transport[] = {
        /* UDP transport specific fields */
        { &hf_oss_udp_transport_version,
          { "Transport Version", "opensafety.udp_transport.version",
            FT_UINT8,  BASE_DEC, NULL,  0x0, NULL, HFILL } },
        { &hf_oss_udp_transport_flags_type,
          { "Data Type", "opensafety.udp_transport.flags.type",
            FT_BOOLEAN, 8, TFS(&tfs_udp_transport_cyclic_acyclic),  0x01, NULL, HFILL } },
        { &hf_oss_udp_transport_counter,
          { "Counter", "opensafety.udp_transport.counter",
            FT_UINT16,  BASE_HEX_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_udp_transport_sender,
          { "Sender ID", "opensafety.udp_transport.sender",
            FT_UINT32,  BASE_HEX_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_udp_transport_datapoint,
          { "Datapoint ID", "opensafety.udp_transport.datapoint",
            FT_UINT16,  BASE_HEX_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_udp_transport_length,
          { "Length", "opensafety.udp_transport.length",
            FT_UINT16,  BASE_DEC, NULL,    0x0, NULL, HFILL } },

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_opensafety,
        &ett_opensafety_node,
        &ett_opensafety_checksum,
        &ett_opensafety_snmt,
        &ett_opensafety_ssdo,
        &ett_opensafety_ssdo_sacmd,
        &ett_opensafety_ssdo_fragment,
        &ett_opensafety_ssdo_fragments,
        &ett_opensafety_ssdo_payload,
        &ett_opensafety_ssdo_sodentry,
        &ett_opensafety_sod_mapping,
        &ett_opensafety_ssdo_extpar,
        &ett_opensafety_spdo,
        &ett_opensafety_spdo_flags,
    };

    static gint *ett_oss_udp[] = {
        &ett_oss_udp_transport,
    };

    static ei_register_info ei[] = {
        { &ei_crc_frame_1_invalid,
          { "opensafety.crc.error.frame1_invalid", PI_PROTOCOL, PI_ERROR,
            "Frame 1 CRC invalid, Possible error in package", EXPFILL } },
        { &ei_crc_frame_1_valid_frame2_invalid,
          { "opensafety.crc.error.frame1_valid_frame2_invalid", PI_PROTOCOL, PI_ERROR,
            "Frame 1 is valid, frame 2 id is invalid", EXPFILL } },
        { &ei_crc_slimssdo_instead_of_spdo,
          { "opensafety.crc.warning.wrong_crc_for_spdo", PI_PROTOCOL, PI_WARN,
            "Frame 1 SPDO CRC is Slim SSDO CRC16 0x5935", EXPFILL } },
        { &ei_crc_frame_2_invalid,
          { "opensafety.crc.error.frame2_invalid", PI_PROTOCOL, PI_ERROR,
            "Frame 2 CRC invalid, Possible error in package or crc calculation", EXPFILL } },
        { &ei_crc_frame_2_unknown_scm_udid,
          { "opensafety.crc.error.frame2_unknown_scmudid", PI_PROTOCOL, PI_WARN,
            "Frame 2 CRC invalid, SCM UDID was not auto-detected", EXPFILL } },
        { &ei_crc_frame_2_scm_udid_encoded,
          { "opensafety.crc.error.crc2_scm_udid_encoded", PI_PROTOCOL, PI_NOTE,
            "Frame 2 CRC is encoded with byte 6 of SCM UDID due to payload length of 0 in frame 2 or SLIM SSDO", EXPFILL } },

        { &ei_message_reassembly_size_differs_from_header,
          { "opensafety.msg.warning.reassembly_size_fail", PI_PROTOCOL, PI_WARN,
            "Reassembled message size differs from size in header", EXPFILL } },
        { &ei_message_unknown_type,
          { "opensafety.msg.error.unknown_type", PI_MALFORMED, PI_ERROR,
            "Unknown openSAFETY message type", EXPFILL } },
        { &ei_message_spdo_address_invalid,
          { "opensafety.msg.error.spdo_address_invalid", PI_MALFORMED, PI_ERROR,
            "SPDO address is invalid", EXPFILL } },
        { &ei_message_id_field_mismatch,
          { "opensafety.msg.error.id.mismatch", PI_PROTOCOL, PI_ERROR,
            "ID for frame 2 is not the same as for frame 1", EXPFILL } },

        { &ei_scmudid_autodetected,
          { "opensafety.scm_udid.note.autodetected", PI_PROTOCOL, PI_NOTE,
            "Auto detected payload as SCM UDID", EXPFILL } },
        { &ei_scmudid_invalid_preference,
          { "opensafety.scm_udid.note.invalid_preference", PI_PROTOCOL, PI_WARN,
            "openSAFETY protocol settings are invalid! SCM UDID first octet will be assumed to be 00", EXPFILL } },
        { &ei_scmudid_unknown,
          { "opensafety.scm_udid.warning.assuming_first_octet", PI_PROTOCOL, PI_WARN,
            "SCM UDID unknown, assuming 00 as first UDID octet", EXPFILL } },

        { &ei_payload_unknown_format,
          { "opensafety.msg.warning.unknown_format", PI_PROTOCOL, PI_WARN,
            "Unknown payload format detected", EXPFILL } },
        { &ei_payload_length_not_positive,
          { "opensafety.msg.warning.reassembly_length_not_positive", PI_PROTOCOL, PI_NOTE,
            "Calculation for payload length yielded non-positive result", EXPFILL } },

        { &ei_40bit_default_domain,
          { "opensafety.msg.warning.default_domain_40bit", PI_PROTOCOL, PI_NOTE,
            "SDN is assumed with 1 to allow 40bit dissection", EXPFILL } },

    };

    module_t *opensafety_module, *oss_udp_module;
    expert_module_t *expert_opensafety;

    /* Register the protocol name and description */
    proto_opensafety = proto_register_protocol("openSAFETY", "openSAFETY",  "opensafety");
    opensafety_module = prefs_register_protocol(proto_opensafety, apply_prefs);
    proto_oss_udp_transport = proto_register_protocol("openSAFETY over UDP", "openSAFETY ov. UDP", "opensafety_udp");
    oss_udp_module = prefs_register_protocol(proto_oss_udp_transport, apply_prefs);

    /* Register data dissector */
    heur_opensafety_spdo_subdissector_list = register_heur_dissector_list("opensafety.spdo", proto_opensafety);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_opensafety, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_oss_udp_transport, hf_oss_udp_transport, array_length(hf_oss_udp_transport));
    proto_register_subtree_array(ett_oss_udp, array_length(ett_oss_udp));

    /* Register tap */
    opensafety_tap = register_tap("opensafety");

    expert_opensafety = expert_register_protocol ( proto_opensafety );
    expert_register_field_array ( expert_opensafety, ei, array_length (ei ) );

    /* register user preferences */
    prefs_register_string_preference(opensafety_module, "scm_udid",
                 "SCM UDID (xx:xx:xx:xx:xx:xx)",
                 "To be able to fully dissect SSDO and SPDO packages, a valid UDID for the SCM has to be provided",
                 &global_scm_udid);
    prefs_register_bool_preference(opensafety_module, "scm_udid_autoset",
                 "Set SCM UDID if detected in stream",
                 "Automatically assign a detected SCM UDID (by reading SNMT->SNTM_assign_UDID_SCM) and set it for the file",
                 &global_scm_udid_autoset);

    prefs_register_string_preference(opensafety_module, "filter_nodes",
                 "Filter openSAFETY Nodes",
                 "A comma-separated list of nodes to be filtered during dissection",
                 &global_filter_nodes);
    prefs_register_bool_preference(opensafety_module, "filter_show_nodes_in_filterlist",
                 "Show nodes in filter, hide otherwise",
                 "If set to true, only nodes in the list will be shown, otherwise they will be hidden",
                 &global_show_only_node_in_filter);

    prefs_register_uint_preference(opensafety_module, "network_udp_port",
                "Port used for Generic UDP",
                "Port used by any UDP demo implementation to transport data", 10,
                &global_network_udp_port);
    prefs_register_uint_preference(opensafety_module, "network_udp_port_sercosiii",
                "Port used for SercosIII/UDP",
                "UDP port used by SercosIII to transport data", 10,
                &global_network_udp_port_sercosiii);
    prefs_register_bool_preference(opensafety_module, "network_udp_frame_first_sercosiii",
                "openSAFETY frame 2 before frame 1 (SercosIII/UDP only)",
                "In an SercosIII/UDP transport stream, openSAFETY frame 2 will be expected before frame 1",
                &global_siii_udp_frame2_first );

    prefs_register_bool_preference(opensafety_module, "network_udp_frame_first",
                "openSAFETY frame 2 before frame 1 (UDP only)",
                "In the transport stream, openSAFETY frame 2 will be expected before frame 1",
                &global_udp_frame2_first );
    prefs_register_bool_preference(opensafety_module, "mbtcp_big_endian",
                "Big Endian Word Coding (Modbus/TCP only)",
                "Modbus/TCP words can be transcoded either big- or little endian. Default will be little endian",
                &global_mbtcp_big_endian);
    prefs_register_bool_preference(opensafety_module, "debug_verbose",
                "openSAFETY print all dissection information",
                "Enables additional information in the dissection for better debugging an openSAFETY trace",
                &global_opensafety_debug_verbose );

    prefs_register_obsolete_preference(opensafety_module, "enable_plk");
    prefs_register_obsolete_preference(opensafety_module, "enable_siii");
    prefs_register_obsolete_preference(opensafety_module, "enable_pnio");

    prefs_register_bool_preference(opensafety_module, "enable_udp",
                "Enable heuristic dissection for openSAFETY over UDP encoded traffic", "Enable heuristic dissection for openSAFETY over UDP encoded traffic",
                &global_enable_udp);
    prefs_register_bool_preference(opensafety_module, "enable_mbtcp",
                "Enable heuristic dissection for Modbus/TCP", "Enable heuristic dissection for Modbus/TCP",
                &global_enable_mbtcp);

    prefs_register_bool_preference(opensafety_module, "display_intergap_data",
                "Display the data between openSAFETY packets", "Display the data between openSAFETY packets",
                &global_display_intergap_data);
    prefs_register_bool_preference(opensafety_module, "classify_transport",
                "Dissect packet based on transport method (EPL + SercosIII only)",
                "SPDOs may only be found in cyclic data, SSDOs/SNMTS only in acyclic data",
                &global_classify_transport);

    prefs_register_uint_preference(oss_udp_module, "network_udp_port",
                "Port used for UDP Transport",
                "Port used by the openSAFETY over UDP data transport", 10,
                &global_network_oss_udp_port);

    /* Registering default and ModBus/TCP dissector */
    opensafety_udpdata_handle = register_dissector("opensafety_udp", dissect_opensafety_udpdata, proto_opensafety );
    opensafety_udptransport_handle =
            register_dissector("opensafety_udptransport", dissect_opensafety_udpdata, proto_oss_udp_transport );
    opensafety_mbtcp_handle = register_dissector("opensafety_mbtcp", dissect_opensafety_mbtcp, proto_opensafety );
    opensafety_pnio_handle = register_dissector("opensafety_pnio", dissect_opensafety_pn_io, proto_opensafety);

    register_conversation_table(proto_opensafety, TRUE, opensafety_conversation_packet, opensafety_hostlist_packet);
}

void
proto_reg_handoff_opensafety(void)
{
    /* Storing global data_dissector */
    data_dissector = find_dissector ( "data" );

    /* EPL & SercosIII dissector registration */
    heur_dissector_add("epl_data",  dissect_opensafety_epl, "openSAFETY over EPL", "opensafety_epl_data", proto_opensafety, HEURISTIC_ENABLE);
    heur_dissector_add("sercosiii", dissect_opensafety_siii, "openSAFETY over SercosIII", "opensafety_sercosiii", proto_opensafety, HEURISTIC_ENABLE);

    /* Modbus TCP dissector registration */
    dissector_add_string("modbus.data", "data", opensafety_mbtcp_handle);

    /* For Profinet we have to register as a heuristic dissector, as Profinet
     *  is implemented as a plugin, and therefore the heuristic dissector is not
     *  added by the time this method is being called
     */
    if ( find_dissector("pn_io") != NULL )
    {
        heur_dissector_add("pn_io", dissect_opensafety_pn_io, "openSAFETY over Profinet", "opensafety_pn_io", proto_opensafety, HEURISTIC_DISABLE);
    }
    else
    {
        /* The native dissector cannot be loaded. so we add our protocol directly to
         * the ethernet subdissector list. No PNIO specific data will be dissected
         * and a warning will be displayed, recognizing the missing dissector plugin.
         */
        dissector_add_uint("ethertype", ETHERTYPE_PROFINET, opensafety_pnio_handle);
    }

    apply_prefs();

    register_init_routine ( setup_dissector );
    register_cleanup_routine ( cleanup_dissector );

    reassembly_table_register(&os_reassembly_table, &addresses_reassembly_table_functions);

    /* registering frame end routine, to prevent a malformed dissection preventing
     * further dissector calls (see bug #6950) */
    /* register_frame_end_routine(reset_dissector); */
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
