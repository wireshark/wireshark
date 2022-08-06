/* packet-rtps-virtual-transport.c
 * Dissector for the Real-Time Publish-Subscribe (RTPS) Virtual Transport
 * Protocol.
 *
 * (c) 2020 Copyright, Real-Time Innovations, Inc.
 * Real-Time Innovations, Inc.
 * 232 East Java Drive
 * Sunnyvale, CA 94089
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * -----------------------------------------------------------------------------
 * RTI Connext DDS can capture RTPS-related traffic by using the Network Capture
 * Utility. The generated .pcap capture files will follow the RTPS-VT protocol,
 * which establishes a format for how information must be saved, and then
 * parsed.
 *
 * The protocol is divided into two layers: transport
 * (packet-rtps-virtual-transport.c) and advanced (packet-rtps-processed.c).
 * This file is about the transport dissector. For more information about the
 * advanced dissector, read the documentation at the beginning of
 * packet-rtps-processed.c.
 *
 * Every packet saved in the capture file follows the PCAP file format.
 * As a consequence, there are two headers: a global one (unique per file) and
 * a per-packet header. These headers have the typical content described in the
 * PCAP format: a magic number, version number, some timestamps, information
 * describing the length of the packet and the data link layer (0x000000fc, i.e.
 * custom protocol), etc. Then, we have a header that indicates Wireshark the
 * name of the protocol: "rtpsvt". The transport dissector is called when
 * Wireshark finds "rtpsvt" as the protocol name.
 *
 * After the RTPS-VT header, we have the frame type. The frame type determines
 * what kind of information has the dumped packet. RTPS-VT data comes as a
 * series of [parameter identifier, content length, content]. Depending on the
 * type of frame (RTPS or lossInfo), the dissector will expect some parameters
 * or others.
 *
 * If the frame type is RTPS, we will continue parsing transport-layer data.
 * The transport layer contains all information about the source and destination
 * of a packet. This corresponds to data typically found on Network or Transport
 * protocols. However, because RTI Connext DDS generates the capture file
 * directly at application-level, this information is added at the moment of
 * writing the capture file.
 * After the transport-layer information, we will call the advanced dissector.
 *
 * If the frame type is lossInfo, the dissector will generate a packet
 * indicating that there were missing frames (and the range of sequence
 * numbers).
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/wmem_scopes.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-rtps.h>


#define CONTENT_KIND_RTPS                        0x01
#define CONTENT_KIND_LOSS_INFO                   0x02

#define PARAM_ID_TRANSPORT_CLASS                 0x0001
#define PARAM_ID_MONITORING_GUID                 0x0002
#define PARAM_ID_MONITORING_SN                   0x0003
#define PARAM_ID_SOURCE_IP_ADDRESS               0x0004
#define PARAM_ID_SOURCE_PORT                     0x0005
#define PARAM_ID_DESTINATION_IP_ADDRESS          0x0006
#define PARAM_ID_DESTINATION_RTPS_PORT           0x0007
#define PARAM_ID_DESTINATION_PORT                0x0008
#define PARAM_ID_DIRECTION                       0x0009
#define FIRST_PARAM_ID_RTPS  PARAM_ID_TRANSPORT_CLASS
#define LAST_PARAM_ID_RTPS   PARAM_ID_DIRECTION

/* First parameter Identifier that the "rtpsproc" protocol accepts */
#define PARAM_ID_MAIN_FRAME                      0x00C0

#define PARAM_ID_LOST_MESSAGES                   0x0001

void proto_register_rtps_virtual_transport(void);
static gint dissect_rtps_virtual_transport(
        tvbuff_t *tvb,
        packet_info *pinfo,
        proto_tree *tree,
        void *data _U_);
static gint dissect_rtps_virtual_transport_rtps_type(
        tvbuff_t *tvb,
        packet_info *pinfo,
        proto_tree *tree,
        proto_tree *tree_transport,
        gint offset,
        struct rtpsvt_data *transport_data);
static gint dissect_parameter_transport_rtps_type(
        tvbuff_t *tvb,
        proto_tree *rtpsvt_tree_general,
        proto_tree *rtpsvt_tree_identifier,
        proto_tree *rtpsvt_tree_information,
        gint offset,
        packet_info *pinfo,
        struct rtpsvt_data *transport_data);
static gint dissect_rtps_virtual_transport_loss_info_type(
        tvbuff_t *tvb,
        packet_info *pinfo,
        proto_tree *tree_transport,
        gint offset);

/* Subtree pointers */
static gint proto_rtpsvt = -1;
static gint rtpsvt_ett = -1;
static gint rtpsvt_ett_version = -1;
static gint rtpsvt_ett_identifier = -1;
static gint rtpsvt_ett_information = -1;
static gint rtpsvt_ett_information_class = -1;
static gint rtpsvt_ett_information_src_port = -1;
static gint rtpsvt_ett_information_dst_port = -1;
static gint rtpsvt_ett_information_src_addr = -1;
static gint rtpsvt_ett_information_dst_addr = -1;
static gint rtpsvt_ett_information_direction = -1;
static gint rtpsvt_ett_monitoring_sn = -1;
static gint rtpsvt_ett_frame = -1;

/* Initialize the protocol and registered fields */
static header_field_info *rtpsvt_hf = NULL;
static gint rtpsvt_hf_version = -1;
static gint rtpsvt_hf_version_major = -1;
static gint rtpsvt_hf_version_minor = -1;
static gint rtpsvt_hf_content_kind = -1;
static gint rtpsvt_hf_param_id = -1;
static gint rtpsvt_hf_param_length = -1;
static gint rtpsvt_hf_packet_identifier = -1;
static gint rtpsvt_hf_monitoring_guid = -1;
static gint rtpsvt_hf_monitoring_seqNr = -1;
static gint rtpsvt_hf_information = -1;
static gint rtpsvt_hf_class = -1;
static gint rtpsvt_hf_source_port = -1;
static gint rtpsvt_hf_source_address = -1;
static gint rtpsvt_hf_source_pid = -1;
static gint rtpsvt_hf_destination_port = -1;
static gint rtpsvt_hf_destination_rtps_port = -1;
static gint rtpsvt_hf_destination_address = -1;
static gint rtpsvt_hf_direction = -1;
static gint rtpsvt_hf_destination_pid = -1;
static gint rtpsvt_hf_missing_messages = -1;

/* expert info fields */
static expert_field ei_missing_msg = EI_INIT;

/* Vendor specific: RTI */
static const value_string ndds_transport_class_id_vals[] = {
    { NDDS_TRANSPORT_CLASSID_ANY,           "ANY" },
    { NDDS_TRANSPORT_CLASSID_UDPv4,         "UDPv4" },
    { NDDS_TRANSPORT_CLASSID_UDPv4_WAN,     "UDPv4_WAN"},
    { NDDS_TRANSPORT_CLASSID_SHMEM,         "SHMEM" },
    { NDDS_TRANSPORT_CLASSID_INTRA,         "INTRA" },
    { NDDS_TRANSPORT_CLASSID_UDPv6,         "UDPv6" },
    { NDDS_TRANSPORT_CLASSID_DTLS,          "DTLS" },
    { NDDS_TRANSPORT_CLASSID_WAN,           "WAN" },
    { NDDS_TRANSPORT_CLASSID_TCPV4_LAN,     "TCPv4_LAN" },
    { NDDS_TRANSPORT_CLASSID_TCPV4_WAN,     "TCPv4_WAN" },
    { NDDS_TRANSPORT_CLASSID_TLSV4_LAN,     "TLSv4_LAN" },
    { NDDS_TRANSPORT_CLASSID_TLSV4_WAN,     "TLSv4_WAN" },
    { NDDS_TRANSPORT_CLASSID_PCIE,          "PCIE" },
    { NDDS_TRANSPORT_CLASSID_ITP,           "ITP" },
    { 0, NULL }
};

static gint dissect_rtps_virtual_transport(
        tvbuff_t *tvb,
        packet_info *pinfo,
        proto_tree *tree,
        void *data _U_)
{
    proto_tree *rtpsvt_tree_transport;
    proto_item *rtpsvt_ti_transport;
    proto_item *rtpsvt_ti_version;
    proto_tree *rtpsvt_tree_version;
    proto_item *rtpsvt_ti_content_kind;
    struct rtpsvt_data transport_data;
    guint16 version;
    guint8 content_type;
    const gchar *content_type_label;
    gint offset = 0;
    gint output = 0;

    /* Add transport tree, used for the fields of our proto_rtpsvt */
    rtpsvt_ti_transport = proto_tree_add_item(
            tree,
            proto_rtpsvt,
            tvb,
            offset,
            -1,
            ENC_BIG_ENDIAN);
    rtpsvt_tree_transport = proto_item_add_subtree(rtpsvt_ti_transport, rtpsvt_ett);

    /* Add the version to the transport protocol */
    version = tvb_get_ntohs(tvb, offset);
    transport_data.version_major = version >> 8;
    transport_data.version_minor = version & 0xff;
    rtpsvt_ti_version = proto_tree_add_uint_format(
            rtpsvt_tree_transport,
            rtpsvt_hf_version,
            tvb,
            offset,
            2, /* 2B: sizeof(guint16) */
            version,
            "Version: %d.%d",
            transport_data.version_major,
            transport_data.version_minor);
    rtpsvt_tree_version = proto_item_add_subtree(
            rtpsvt_ti_version,
            rtpsvt_ett_version);

    proto_tree_add_item(
            rtpsvt_tree_version,
            rtpsvt_hf_version_major,
            tvb,
            offset,
            1, /* length: sizeof(guint8) */
            ENC_NA);
    proto_tree_add_item(
            rtpsvt_tree_version,
            rtpsvt_hf_version_minor,
            tvb,
            offset + 1,
            1, /* length: sizeof(guint8) */
            ENC_NA);
    offset += 2;

    /* Add the content kind. */
    content_type = tvb_get_guint8(tvb, offset);
    rtpsvt_ti_content_kind = proto_tree_add_item(
            rtpsvt_ti_transport,
            rtpsvt_hf_content_kind,
            tvb,
            offset,
            1, /* length: sizeof(guint8) */
            ENC_NA);
    if (content_type == CONTENT_KIND_RTPS) {
        content_type_label = "RTPS";
    } else {
        content_type_label = "LOST_INFO";
    }
    proto_item_append_text(rtpsvt_ti_content_kind, " (%s)", content_type_label);
    offset += 1;

    switch(content_type) {
        case CONTENT_KIND_RTPS:
            output = dissect_rtps_virtual_transport_rtps_type(
                    tvb,
                    pinfo,
                    tree,
                    rtpsvt_tree_transport,
                    offset,
                    &transport_data);
            break;

        case CONTENT_KIND_LOSS_INFO:
            output = dissect_rtps_virtual_transport_loss_info_type(
                    tvb,
                    pinfo,
                    rtpsvt_tree_transport,
                    offset);
            break;
    }
    return output;
}

static gint dissect_rtps_virtual_transport_rtps_type(
        tvbuff_t *tvb,
        packet_info *pinfo,
        proto_tree *tree,
        proto_tree *tree_transport,
        gint offset,
        struct rtpsvt_data *transport_data)
{
    proto_item *rtpsvt_ti_identifier;
    proto_tree *rtpsvt_tree_identifier;
    proto_item *rtpsvt_ti_information;
    proto_tree *rtpsvt_tree_information;
    tvbuff_t *advanced_payload;
    static dissector_handle_t advanced_handle = NULL;
    unsigned int idx = FIRST_PARAM_ID_RTPS;
    guint16 param_id;
    guint16 param_length;

    /*
     * Add the tree for the packet identifier, which will be populated in
     * dissect_parameter_transport_rtps_type.
     */
    rtpsvt_ti_identifier = proto_tree_add_item(
            tree_transport,
            rtpsvt_hf_packet_identifier,
            tvb,
            offset,
            -1,
            ENC_NA);
    rtpsvt_tree_identifier = proto_item_add_subtree(
            rtpsvt_ti_identifier,
            rtpsvt_ett_identifier);

    /*
     * Add the tree for the transport information, which will be populated in
     * dissect_parameter_transport_rtps_type.
     */
    rtpsvt_ti_information = proto_tree_add_item(
            tree_transport,
            rtpsvt_hf_information,
            tvb,
            offset,
            -1,
            ENC_NA);
    rtpsvt_tree_information = proto_item_add_subtree(
            rtpsvt_ti_information,
            rtpsvt_ett_information);

    /*
     * Each parameter has an id, a length and a value.
     */
    for (idx = FIRST_PARAM_ID_RTPS; idx <= LAST_PARAM_ID_RTPS; idx++) {
        offset = dissect_parameter_transport_rtps_type(
                tvb,
                tree_transport,
                rtpsvt_tree_identifier,
                rtpsvt_tree_information,
                offset,
                pinfo,
                transport_data);
    }

    /*
     * In the future we may have more transport parameters.
     * These parameters will have an identifier less than PARAM_ID_MAIN_FRAME
     * (which is parsed by the rtpsproc dissector).
     * If we open a "future" capture file with this dissector, we will skip all
     * of those parameters and parse only the ones we know about.
     */
    do {
        param_id = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
        offset += 2;
        param_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
        offset += 2;
        if (param_id == PARAM_ID_MAIN_FRAME) {
            proto_tree *rtpsvt_tree_frame;
            transport_data->rtps_length = param_length;
            rtpsvt_tree_frame = proto_tree_add_subtree_format(
                    tree_transport,
                    tvb,
                    offset,
                    0,
                    rtpsvt_ett_frame,
                    NULL,
                    "Real-Time Publish-Subscribe Wire Protocol (content)");

            proto_tree_add_uint(
                    rtpsvt_tree_frame,
                    rtpsvt_hf_param_id,
                    tvb,
                    offset,
                    2, /* 2B: sizeof(guint16) */
                    param_id);
            proto_tree_add_uint(
                    rtpsvt_tree_frame,
                    rtpsvt_hf_param_length,
                    tvb,
                    offset + 2,
                    2,
                    param_length);
            break;
        }
        offset += param_length;
    } while (tvb_reported_length_remaining(tvb, offset) > 0);

    if (param_id != PARAM_ID_MAIN_FRAME || param_length <= 0) {
        /*
         * Reject the packet if we don't have an RTPS frame.
         * The rtpsproc dissector assumes that the contents start with the
         * RTPS frame (parameter value; the length is obtained from
         * transport_data).
         */
        return 0;
    }

    advanced_payload = tvb_new_subset_length(tvb, offset, -1);
    advanced_handle = find_dissector("rtpsproc");
    call_dissector_with_data(
            advanced_handle,
            advanced_payload,
            pinfo,
            tree,
            (void *) transport_data);

    return tvb_captured_length(tvb);
}

static gint dissect_parameter_transport_rtps_type(
        tvbuff_t *tvb,
        proto_tree *rtpsvt_tree_general,
        proto_tree *rtpsvt_tree_identifier,
        proto_tree *rtpsvt_tree_information,
        gint offset,
        packet_info *pinfo,
        struct rtpsvt_data *transport_data)
{
    /*
     * We will add the parameter id and length later, as part of a subtree
     * dependent of the parameter.
     * That is why value of the parameter is now at offset + 4
     * (i.e. offset + sizeof(param_id) + sizeof(param_length))
     */
    guint16 param_id = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    guint16 param_length = tvb_get_guint16(tvb, offset + 2, ENC_BIG_ENDIAN);
    const gint OFFSET_TO_VAL = offset + 4;
    if (param_length <=0) {
        /* Length not valid: skip parameter (id + length) */
        return OFFSET_TO_VAL;
    }

    switch(param_id) {
        case PARAM_ID_TRANSPORT_CLASS:
            {
                proto_tree *rtpsvt_tree_information_class;
                gint32 classId = tvb_get_gint32(tvb, OFFSET_TO_VAL, ENC_BIG_ENDIAN);
                const gchar *className = val_to_str(
                        classId,
                        ndds_transport_class_id_vals,
                        "%d");

                rtpsvt_tree_information_class = proto_tree_add_subtree_format(
                        rtpsvt_tree_information,
                        tvb,
                        offset,
                        0,
                        rtpsvt_ett_information_class,
                        NULL,
                        "Class: %s",
                        className);

                /* Add parameter identifier and length */
                proto_tree_add_uint(
                        rtpsvt_tree_information_class,
                        rtpsvt_hf_param_id,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_id);
                offset += 2;
                proto_tree_add_uint(
                        rtpsvt_tree_information_class,
                        rtpsvt_hf_param_length,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_length);
                offset += 2;

                /*
                 * Add transport class as item to the tree.
                 * This is useful to apply as column or filter.
                 */
                proto_tree_add_string(
                        rtpsvt_tree_information_class,
                        rtpsvt_hf_class,
                        tvb,
                        offset,
                        param_length,
                        className);
                offset += param_length;

                /* Add summary to protocol header */
                proto_item_append_text(rtpsvt_tree_general, ", %s", className);

                /* Add summary to the transport information header */
                proto_item_append_text(
                        rtpsvt_tree_information,
                        ", %s",
                        className);
            }
            break;

        case PARAM_ID_MONITORING_GUID:
            {
                proto_tree *rtpsvt_tree_monitoring_guid;
                const guint8 *guid_bytes = tvb_get_ptr(
                        tvb,
                        OFFSET_TO_VAL,
                        param_length);
                const gchar *guid_string = bytes_to_str_punct(
                        pinfo->pool,
                        guid_bytes,
                        MIN(param_length, 12),
                        0);

                rtpsvt_tree_monitoring_guid = proto_tree_add_subtree_format(
                        rtpsvt_tree_identifier,
                        tvb,
                        offset,
                        0,
                        rtpsvt_ett_information_src_addr,
                        NULL,
                        "Monitoring GUID Prefix: %s",
                        guid_string);

                /* Add parameter identifier and length */
                proto_tree_add_uint(
                        rtpsvt_tree_monitoring_guid,
                        rtpsvt_hf_param_id,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_id);
                offset += 2;
                proto_tree_add_uint(
                        rtpsvt_tree_monitoring_guid,
                        rtpsvt_hf_param_length,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_length);
                offset += 2;

                proto_tree_add_item(
                        rtpsvt_tree_monitoring_guid,
                        rtpsvt_hf_monitoring_guid,
                        tvb,
                        offset,
                        param_length,
                        ENC_NA);
                offset += param_length;

                /* Add summary to packet identifier header */
                proto_item_append_text(
                        rtpsvt_tree_identifier,
                       ", GUID: %s",
                       guid_string);
            }
            break;
        case PARAM_ID_MONITORING_SN:
            {
                proto_tree *rtpsvt_tree_seqNr;
                guint64 seqNr = tvb_get_guint64(tvb, OFFSET_TO_VAL, ENC_BIG_ENDIAN);

                rtpsvt_tree_seqNr = proto_tree_add_subtree_format(
                        rtpsvt_tree_identifier,
                        tvb,
                        offset,
                        0,
                        rtpsvt_ett_monitoring_sn,
                        NULL,
                        "Monitoring Sequence Number: %" PRIu64,
                        seqNr);

                /* Add parameter identifier and length */
                proto_tree_add_uint(
                        rtpsvt_tree_seqNr,
                        rtpsvt_hf_param_id,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_id);
                offset += 2;
                proto_tree_add_uint(
                        rtpsvt_tree_seqNr,
                        rtpsvt_hf_param_length,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_length);
                offset += 2;

                proto_tree_add_uint64(
                        rtpsvt_tree_seqNr,
                        rtpsvt_hf_monitoring_seqNr,
                        tvb,
                        offset,
                        param_length,
                        seqNr);
                offset += param_length;

                /* Add summary to packet identifier header */
                proto_item_append_text(
                        rtpsvt_tree_identifier,
                        ", SeqNum: %" PRIu64,
                        seqNr);
            }
            break;
        case PARAM_ID_SOURCE_IP_ADDRESS:
            {
                proto_tree *rtpsvt_tree_information_address;
                gint temporary_hf = rtpsvt_hf_source_address;
                const gchar *prefix = "shmem_prefix";
                const gchar *title_tree = "Source address";
                gchar addr[COL_MAX_LEN];
                ws_in6_addr addr_raw;
                const guint8 bytes_zeroed[12] = {0};
                tvb_get_ipv6(tvb, OFFSET_TO_VAL, &addr_raw);

                /* shared memory pid or address? */
                if (memcmp(&addr_raw.bytes, prefix, strlen(prefix)) == 0) {
                    temporary_hf = rtpsvt_hf_source_pid;
                    title_tree = "Source process ID";
                    guint32 pid = tvb_get_guint32(
                            tvb,
                            OFFSET_TO_VAL + (gint) (strlen(prefix)),
                            ENC_BIG_ENDIAN);
                    snprintf(addr, sizeof(addr), "%u", pid);
                } else if (memcmp(
                        &addr_raw.bytes,
                        bytes_zeroed,
                        sizeof(bytes_zeroed)) == 0){
                    snprintf(
                            addr,
                            sizeof(addr),
                            "%s",
                            tvb_ip_to_str(pinfo->pool, tvb, OFFSET_TO_VAL + sizeof(bytes_zeroed)));
                } else {
                    snprintf(
                            addr,
                            sizeof(addr),
                            "%s",
                            tvb_ip6_to_str(pinfo->pool, tvb, OFFSET_TO_VAL));
                }

                /* Add source to destination column field */
                if (pinfo->cinfo) {
                    col_append_str(pinfo->cinfo, COL_DEF_SRC, addr);
                }

                rtpsvt_tree_information_address = proto_tree_add_subtree_format(
                        rtpsvt_tree_information,
                        tvb,
                        offset,
                        0,
                        rtpsvt_ett_information_src_addr,
                        NULL,
                        "%s: %s",
                        title_tree,
                        addr);

                /* Add parameter identifier and length */
                proto_tree_add_uint(
                        rtpsvt_tree_information_address,
                        rtpsvt_hf_param_id,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_id);
                offset += 2;
                proto_tree_add_uint(
                        rtpsvt_tree_information_address,
                        rtpsvt_hf_param_length,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_length);
                offset += 2;

                /* Add source to the transport information tree */
                proto_tree_add_string(
                        rtpsvt_tree_information_address,
                        temporary_hf,
                        tvb,
                        offset,
                        param_length,
                        addr);
                offset += param_length;

                /* Add summary to protocol header */
                proto_item_append_text(rtpsvt_tree_general, ", Src: (%s", addr);

                /* Add summary to transport information header */
                proto_item_append_text(
                        rtpsvt_tree_information,
                        ", Src: (%s",
                        addr);
            }
            break;
        case PARAM_ID_SOURCE_PORT:
            {
                proto_tree *rtpsvt_tree_information_port;
                guint32 port = tvb_get_guint32(
                        tvb,
                        OFFSET_TO_VAL,
                        ENC_BIG_ENDIAN);

                rtpsvt_tree_information_port = proto_tree_add_subtree_format(
                        rtpsvt_tree_information,
                        tvb,
                        offset,
                        0,
                        rtpsvt_ett_information_src_port,
                        NULL,
                        "Source port: %d",
                        port);

                /* Add parameter identifier and length */
                proto_tree_add_uint(
                        rtpsvt_tree_information_port,
                        rtpsvt_hf_param_id,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_id);
                offset += 2;
                proto_tree_add_uint(
                        rtpsvt_tree_information_port,
                        rtpsvt_hf_param_length,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_length);
                offset += 2;

                proto_tree_add_uint(
                        rtpsvt_tree_information_port,
                        rtpsvt_hf_source_port,
                        tvb,
                        offset,
                        param_length,
                        port);
                offset += param_length;

                /* Add summary to protocol header */
                proto_item_append_text(rtpsvt_tree_general, ":%d)", port);

                /* Add summary to transport information header */
                proto_item_append_text(
                        rtpsvt_tree_information,
                        ":%d)",
                        port);

                /*
                 * Add the source port to pinfo.
                 * This is used by the RTPS dissector to get the domainId and
                 * participantIdx information displayed in discovery packets.
                 */
                pinfo->srcport = port;
            }
            break;
        case PARAM_ID_DESTINATION_IP_ADDRESS:
            {
                proto_tree *rtpsvt_tree_information_address;
                gint temporary_hf= rtpsvt_hf_destination_address;
                const gchar *prefix = "shmem_prefix";
                const gchar *title_tree = "Destination address";
                gchar addr[COL_MAX_LEN];
                ws_in6_addr addr_raw;
                const guint8 bytes_zeroed[12] = {0};
                tvb_get_ipv6(tvb, OFFSET_TO_VAL, &addr_raw);

                /* shared memory pid or address? */
                if (memcmp(&addr_raw.bytes, prefix, strlen(prefix)) == 0) {
                    temporary_hf = rtpsvt_hf_destination_pid;
                    title_tree = "Destination process ID";
                    guint32 pid = tvb_get_guint32(
                            tvb,
                            OFFSET_TO_VAL + (gint) (strlen(prefix)),
                            ENC_BIG_ENDIAN);
                    snprintf(addr, sizeof(addr), "%u", pid);
                } else if (memcmp(
                        &addr_raw.bytes,
                        bytes_zeroed,
                        sizeof(bytes_zeroed)) == 0){
                    snprintf(
                            addr,
                            sizeof(addr),
                            "%s",
                            tvb_ip_to_str(pinfo->pool, tvb, OFFSET_TO_VAL + sizeof(bytes_zeroed)));
                } else {
                    snprintf(
                            addr,
                            sizeof(addr),
                            "%s",
                            tvb_ip6_to_str(pinfo->pool, tvb, OFFSET_TO_VAL));
                }

                /* Add address to destination column field */
                if (pinfo->cinfo) {
                    col_append_str(pinfo->cinfo, COL_DEF_DST, addr);
                }

                rtpsvt_tree_information_address = proto_tree_add_subtree_format(
                        rtpsvt_tree_information,
                        tvb,
                        offset,
                        0,
                        rtpsvt_ett_information_dst_addr,
                        NULL,
                        "%s: %s",
                        title_tree,
                        addr);

                /* Add parameter identifier and length */
                proto_tree_add_uint(
                        rtpsvt_tree_information_address,
                        rtpsvt_hf_param_id,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_id);
                offset += 2;
                proto_tree_add_uint(
                        rtpsvt_tree_information_address,
                        rtpsvt_hf_param_length,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_length);
                offset += 2;

                /* Add destination to the transport information tree */
                proto_tree_add_string(
                        rtpsvt_tree_information_address,
                        temporary_hf,
                        tvb,
                        offset,
                        param_length,
                        addr);
                offset += param_length;

                /* Add summary to protocol header */
                proto_item_append_text(rtpsvt_tree_general, ", Dst: (%s", addr);

                /* Add summary to transport information header */
                proto_item_append_text(
                        rtpsvt_tree_information,
                        ", Dst: (%s",
                        addr);
            }
            break;
        case PARAM_ID_DESTINATION_RTPS_PORT:
            {
                guint32 port = tvb_get_guint32(tvb, OFFSET_TO_VAL, ENC_BIG_ENDIAN);

                proto_tree_add_uint(
                        rtpsvt_tree_information,
                        rtpsvt_hf_destination_rtps_port,
                        tvb,
                        OFFSET_TO_VAL,
                        param_length,
                        port);

                offset = OFFSET_TO_VAL + param_length;
            }
            break;
        case PARAM_ID_DESTINATION_PORT:
            {
                proto_tree *rtpsvt_tree_information_port;
                guint32 port = tvb_get_guint32(tvb, OFFSET_TO_VAL, ENC_BIG_ENDIAN);

                rtpsvt_tree_information_port = proto_tree_add_subtree_format(
                        rtpsvt_tree_information,
                        tvb,
                        offset,
                        0,
                        rtpsvt_ett_information_dst_port,
                        NULL,
                        "Destination port: %d",
                        port);

                /* Add parameter identifier and length */
                proto_tree_add_uint(
                        rtpsvt_tree_information_port,
                        rtpsvt_hf_param_id,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_id);
                offset += 2;
                proto_tree_add_uint(
                        rtpsvt_tree_information_port,
                        rtpsvt_hf_param_length,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_length);
                offset += 2;

                proto_tree_add_uint(
                        rtpsvt_tree_information_port,
                        rtpsvt_hf_destination_port,
                        tvb,
                        offset,
                        param_length,
                        port);
                offset += param_length;

                /* Add summary to protocol header */
                proto_item_append_text(rtpsvt_tree_general, ":%d)", port);

                /* Add summary to transport information header */
                proto_item_append_text(
                        rtpsvt_tree_information,
                        ":%d)",
                        port);

                /*
                 * Add the destination port to pinfo.
                 * This is used by the RTPS dissector to get the domainId and
                 * participantIdx information displayed in discovery packets.
                 */
                pinfo->destport = port;
            }
            break;
        case PARAM_ID_DIRECTION:
            {
                proto_tree *rtpsvt_tree_direction;
                guint8 value = tvb_get_guint8(tvb, OFFSET_TO_VAL);
                const gchar *direction = value ? "INBOUND" : "OUTBOUND";

                rtpsvt_tree_direction = proto_tree_add_subtree_format(
                        rtpsvt_tree_general,
                        tvb,
                        offset,
                        0,
                        rtpsvt_ett_information_src_addr,
                        NULL,
                        "Traffic Direction: %s",
                        direction);

                /* Add parameter identifier and length */
                proto_tree_add_uint(
                        rtpsvt_tree_direction,
                        rtpsvt_hf_param_id,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_id);
                offset += 2;
                proto_tree_add_uint(
                        rtpsvt_tree_direction,
                        rtpsvt_hf_param_length,
                        tvb,
                        offset,
                        2, /* length: sizeof(guint16) */
                        param_length);

                proto_tree_add_string(
                        rtpsvt_tree_direction,
                        rtpsvt_hf_direction,
                        tvb,
                        OFFSET_TO_VAL,
                        param_length,
                        direction);
                offset = OFFSET_TO_VAL + param_length;

                /* Save transport direction for the RTPS-PROC protocol */
                transport_data->direction = value;
            }
            break;
    }
    return offset;
}

static gint dissect_rtps_virtual_transport_loss_info_type(
        tvbuff_t *tvb,
        packet_info *pinfo,
        proto_tree *tree_transport,
        gint offset)
{

    guint16 param_id;

    param_id = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    offset += 2;
    offset += 2; /* parameter length */
    if (param_id == PARAM_ID_LOST_MESSAGES) {
        guint64 first_lost = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
        guint64 last_lost = tvb_get_guint64(tvb, offset+8, ENC_BIG_ENDIAN);

        if (pinfo->cinfo) {
            char info[COL_MAX_INFO_LEN] = {'\0'};
            snprintf(
                    info,
                    sizeof(info),
                    "Missing RTPS messages [%" PRIu64 "-%" PRIu64 "]",
                    first_lost,
                    last_lost);
            col_append_str(pinfo->cinfo, COL_INFO, info);
        }
        expert_add_info(NULL, tree_transport, &ei_missing_msg);
    }

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_rtps_virtual_transport(void)
{
    expert_module_t* expert_info;

    static hf_register_info hf[] = {
        {
            &rtpsvt_hf_version,
            {
                "Version", "rtpsvt.version",
                FT_UINT16, BASE_HEX, NULL, 0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_version_major,
            {
                "Major", "rtpsvt.version.major",
                FT_INT8, BASE_DEC, NULL, 0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_version_minor,
            {
                "Minor", "rtpsvt.version.minor",
                FT_INT8, BASE_DEC, NULL, 0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_content_kind,
            {
                "Content kind", "rtpsvt.content.kind",
                FT_INT8, BASE_DEC, NULL, 0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_param_id,
            {
                "Parameter Identifier", "rtpsvt.param.id",
                FT_UINT16, BASE_DEC, NULL, 0, 0, HFILL
            },
        },
        {
            &rtpsvt_hf_param_length,
            {
                "Parameter Length", "rtpsvt.param.length",
                FT_UINT16, BASE_DEC, NULL, 0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_direction,
            {
                "Traffic Direction", "rtpsvt.direction",
                FT_STRING, BASE_NONE, NULL, 0x0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_packet_identifier,
            {
                "Packet identifier", "rtpsvt.identifier",
                FT_NONE, BASE_NONE, NULL, 0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_monitoring_guid,
            {
                "GUID", "rtpsvt.monitoring_guid",
                FT_BYTES, BASE_NONE, NULL, 0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_monitoring_seqNr,
            {
                "SeqNum", "rtpsvt.seqNr",
                FT_UINT64, BASE_DEC, NULL, 0x0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_information,
            {
                "Transport Information", "rtpsvt.information",
                FT_NONE, BASE_NONE, NULL, 0x0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_source_port,
            {
                "Source Port", "rtpsvt.source_port",
                FT_UINT32, BASE_DEC, NULL, 0x0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_source_address,
            {
                "Source address", "rtpsvt.source_address",
                FT_STRING, BASE_NONE, NULL, 0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_source_pid,
            {
                "Source process ID", "rtpsvt.source_pid",
                FT_STRING, BASE_NONE, NULL, 0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_destination_port,
            {
                "Destination Port", "rtpsvt.port",
                FT_UINT32, BASE_DEC, NULL, 0x0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_destination_rtps_port,
            {
                "Destination RTPS Port", "rtpsvt.rtps_port",
                FT_UINT32, BASE_DEC, NULL, 0x0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_destination_address,
            {
                "Destination address", "rtpsvt.destination_address",
                FT_STRING, BASE_NONE, NULL, 0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_destination_pid,
            {
                "Destination process ID", "rtpsvt.destination_pid",
                FT_STRING, BASE_NONE, NULL, 0, 0, HFILL
            }
        },
        {
            &rtpsvt_hf_class,
            {
                "Transport class", "rtpsvt.class",
                FT_STRING, BASE_NONE, NULL, 0, 0, HFILL
            }
        },
        {
            /* Information related to the 'lost' content type */
            &rtpsvt_hf_missing_messages,
            {
                "Packets lost", "rtpsvt.missing_messages",
                FT_UINT64, BASE_DEC, NULL, 0x0, 0, HFILL
            }
        }
    };

    static gint *ett[] = {
        &rtpsvt_ett,
        &rtpsvt_ett_version,
        &rtpsvt_ett_identifier,
        &rtpsvt_ett_information,
        &rtpsvt_ett_information_class,
        &rtpsvt_ett_information_src_port,
        &rtpsvt_ett_information_dst_port,
        &rtpsvt_ett_information_src_addr,
        &rtpsvt_ett_information_dst_addr,
        &rtpsvt_ett_information_direction,
        &rtpsvt_ett_monitoring_sn,
        &rtpsvt_ett_frame
    };

    static ei_register_info ei[] = {
        {
        &ei_missing_msg,
        {
            "rtpsvt.expert.missing_messages",
            PI_PROTOCOL,
            PI_NOTE,
            "Missing RTPS Messages because of full buffer pool",
            EXPFILL
        }
    },
    };

    /* Register the protocol name and description */
    proto_rtpsvt = proto_register_protocol(
            "Real-Time Publish-Subscribe Virtual Transport",
            "RTPS-VT",
            "rtpsvt");

    /* Required function calls to register the header fields and subtrees */
    rtpsvt_hf = proto_registrar_get_nth(proto_rtpsvt);
    proto_register_field_array(proto_rtpsvt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register expert information */
    expert_info = expert_register_protocol(proto_rtpsvt);
    expert_register_field_array(expert_info, ei, array_length(ei));

    register_dissector("rtpsvt", dissect_rtps_virtual_transport, proto_rtpsvt);
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
