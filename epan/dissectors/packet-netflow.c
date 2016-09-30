/*
 ** packet-netflow.c
 **
 ** (c) 2002 bill fumerola <fumerola@yahoo-inc.com>
 ** (C) 2005-06 Luca Deri <deri@ntop.org>
 **
 ** All rights reserved.
 **
 ** Wireshark - Network traffic analyzer
 ** By Gerald Combs <gerald@wireshark.org>
 ** Copyright 1998 Gerald Combs
 **
 ** This program is free software; you can redistribute it and/or
 ** modify it under the terms of the GNU General Public License
 ** as published by the Free Software Foundation; either version 2
 ** of the License, or (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *****************************************************************************
 **
 ** Previous NetFlow dissector written by Matthew Smart <smart@monkey.org>
 ** NetFlow v9 support added by same.
 **
 ** NetFlow v9 patches by Luca Deri <deri@ntop.org>
 **
 ** See
 **
 ** http://www.cisco.com/warp/public/cc/pd/iosw/prodlit/tflow_wp.htm
 ** http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
 **
 ** Cisco ASA5500 Series
 ** http://www.cisco.com/en/US/docs/security/asa/asa83/netflow/netflow.html
 **
 ** ( http://www.ietf.org/rfc/rfc3954.txt ? for NetFlow v9 information)
 **
 ** IPFIX
 ** http://tools/ietf.org/html/rfc5103 Bidirectional Flow Export Using IP Flow Information Export (IPFIX)
 ** http://tools.ietf.org/html/rfc5610 Exporting Type Information for
 **                                     IP Flow Information Export (IPFIX) Information Elements
 ** http://tools.ietf.org/html/rfc7011 Specification of the IP Flow Information Export (IPFIX) Protocol
 **                                     for the Exchange of Flow Information
 ** http://tools.ietf.org/html/rfc7012 Information Model for IP Flow Information Export (IPFIX)
 ** http://tools.ietf.org/html/rfc7013 Guidelines for Authors and Reviewers of
 **                                     IP Flow Information Export (IPFIX) Information Elements
 **
 ** http://www.iana.org/assignments/ipfix/ipfix.xml     [version dated: 2014-08-13]
 ** http://www.iana.org/assignments/psamp-parameters/psamp-parameters.xml
 ** for IPFIX
 **
 *****************************************************************************
 **
 ** this code was written from the following documentation:
 **
 ** http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_6/iug/format.pdf
 ** http://www.caida.org/tools/measurement/cflowd/configuration/configuration-9.html
 **
 ** some documentation is more accurate then others. in some cases, live data and
 ** information contained in responses from vendors were also used. some fields
 ** are dissected as vendor specific fields.
 **
 ** See also
 **
 ** http://www.cisco.com/en/US/docs/ios/solutions_docs/netflow/nfwhite.html
 **
 *****************************************************************************
 ** NetFlow forwarding status and template fixes
 ** by Aamer Akhter <aakhter@cisco.com>
 ** Copyright 2010, cisco Systems, Inc.
 **
 ** $Yahoo: //depot/fumerola/packet-netflow/packet-netflow.c#14 $
 **
 *****************************************************************************
 **
 **
 */

/*
 * ToDo: [11/23/2011: WMeier]
 *
 *  1. (See the various XXX comments)
 *  2. Template processing:
 *     a. Verify that template with same src_addr, ... ,ID is actually identical to that previously seen ?
 *        Handle changes ? Don't use template to dissect data packets previous to the packet with the templates.
 *        Essentially; need to keep the packet number containing the first copy of the template.
 *
 */

/*
 * November 2010: acferen:  Add ntop nProbe and Plixer Mailinizer extensions
 *
 * nProbe changes are for nprobe >= 5.5.6.  Earlier nprobe versions
 * "supported" some of the same fields, but they used element IDs that
 * collide with standard IDs.  Because of this versions prior to 5.5.6
 * using IDs above 80 (nprobe extensions) cannot be decoded correctly.
 *
 * nprobe supports extensions in v9 and IPFIX.  IPFIX is done in the
 * standard way.  See the NTOP_BASE for handling v9 with no collisions
 * (maybe).
 *
 * Plixer changes are just new field definitions.  (IPFIX only)
 *
 * extended core code to allow naming vendor extensions.
 *
 * Put the length for variable length strings in a tree under the
 * decoded string.  Wonder if this might be overkill.  Could probably
 * just format the "(Variable length)" string to include the actual
 * length.
 *
 * Did some minor cleanup.
 *
 * Note for WMeier...  Added YYY comments with some XXX comments.
 */

/*
 * March 2015: uhei:  Add Citrix Netscaler AppFlow extensions
 * used documentation found at:
 * https://raw.githubusercontent.com/splunk/ipfix/master/app/Splunk_TA_IPFIX/bin/IPFIX/information-elements/5951.xml
 */

/*
 * December 2015: uhei:  Add Barracuda NGFirewall extensions
 * used documentation found at:
 * https://techlib.barracuda.com/NG61/ConfigAuditReportingIPFIX
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/ipproto.h>
#include <wiretap/wtap.h>
#include <epan/sminmpec.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include <wsutil/str_util.h>
#include "packet-tcp.h"
#include "packet-udp.h"
#include "packet-ntp.h"

void proto_register_netflow(void);
void proto_reg_handoff_netflow(void);

#if 0
#define ipfix_debug(...) g_warning(__VA_ARGS__)
#else
#define ipfix_debug(...)
#endif


/* 4739 is IPFIX.
   2055 and 9996 are common defaults for Netflow
 */
#define NETFLOW_UDP_PORTS "2055,9996"
#define IPFIX_UDP_PORTS   "4739"
#define REVPEN            29305
static dissector_handle_t netflow_handle;

/* If you want sort of safely to send enterprise specific element IDs
   using v9 you need to stake a claim in the wilds with the high bit
   set.  Still no naming authority, but at least it will never collide
   with valid IPFIX */
#define NTOP_BASE 57472u                /* nprobe >= 5.5.6 */

/*
 *  global_netflow_ports : holds the configured range of ports for netflow
 */
static range_t *global_netflow_ports = NULL;
/*
 *  global_ipfix_ports : holds the configured range of ports for IPFIX
 */
static range_t *global_ipfix_ports = NULL;

/*
 * Flowset (template) ID's
 */
#define FLOWSET_ID_V9_DATA_TEMPLATE         0
#define FLOWSET_ID_V9_OPTIONS_TEMPLATE      1
#define FLOWSET_ID_V10_DATA_TEMPLATE        2
#define FLOWSET_ID_V10_OPTIONS_TEMPLATE     3
#define FLOWSET_ID_RESERVED_MIN             4
#define FLOWSET_ID_RESERVED_MAX           255
#define FLOWSET_ID_DATA_MIN               256
#define FLOWSET_ID_DATA_MAX             65535

static const range_string rs_flowset_ids[] = {
    { FLOWSET_ID_V9_DATA_TEMPLATE    , FLOWSET_ID_V9_DATA_TEMPLATE    , "Data Template (V9)"             },
    { FLOWSET_ID_V9_OPTIONS_TEMPLATE , FLOWSET_ID_V9_OPTIONS_TEMPLATE , "Options Template(V9)"           },
    { FLOWSET_ID_V10_DATA_TEMPLATE   , FLOWSET_ID_V10_DATA_TEMPLATE   , "Data Template (V10 [IPFIX])"    },
    { FLOWSET_ID_V10_OPTIONS_TEMPLATE, FLOWSET_ID_V10_OPTIONS_TEMPLATE, "Options Template (V10 [IPFIX])" },
    { FLOWSET_ID_RESERVED_MIN        , FLOWSET_ID_RESERVED_MAX        , "(Reserved)"                     },
    { FLOWSET_ID_DATA_MIN            , FLOWSET_ID_DATA_MAX            , "(Data)"                         },
    { 0,           0,          NULL                   }
};

/*
 * pdu identifiers & sizes
 */

#define V1PDU_SIZE                 (4 * 12)
#define V5PDU_SIZE                 (4 * 12)
#define V7PDU_SIZE                 (4 * 13)
#define V8PDU_AS_SIZE              (4 *  7)
#define V8PDU_PROTO_SIZE           (4 *  7)
#define V8PDU_SPREFIX_SIZE         (4 *  8)
#define V8PDU_DPREFIX_SIZE         (4 *  8)
#define V8PDU_MATRIX_SIZE          (4 * 10)
#define V8PDU_DESTONLY_SIZE        (4 * 8)
#define V8PDU_SRCDEST_SIZE         (4 * 10)
#define V8PDU_FULL_SIZE            (4 * 11)
#define V8PDU_TOSAS_SIZE           (V8PDU_AS_SIZE + 4)
#define V8PDU_TOSPROTOPORT_SIZE    (V8PDU_PROTO_SIZE + 4)
#define V8PDU_TOSSRCPREFIX_SIZE    (V8PDU_SPREFIX_SIZE)
#define V8PDU_TOSDSTPREFIX_SIZE    (V8PDU_DPREFIX_SIZE)
#define V8PDU_TOSMATRIX_SIZE       (V8PDU_MATRIX_SIZE)
#define V8PDU_PREPORTPROTOCOL_SIZE (4 * 10)

#define VARIABLE_LENGTH 65535

static const value_string v5_sampling_mode[] = {
    {0, "No sampling mode configured"},
    {1, "Packet Interval sampling mode configured"},
    {2, "Random sampling mode configured"},
    {0, NULL}
};

static const value_string ipfix_sampling_mode[] = {
    {0, "No sampling mode configured"},
    {1, "Deterministic sampling"},
    {2, "Random sampling"},
    {0, NULL}
};

enum {
    V8PDU_NO_METHOD = 0,
    V8PDU_AS_METHOD,
    V8PDU_PROTO_METHOD,
    V8PDU_SPREFIX_METHOD,
    V8PDU_DPREFIX_METHOD,
    V8PDU_MATRIX_METHOD,
    V8PDU_DESTONLY_METHOD,
    V8PDU_SRCDEST_METHOD,
    V8PDU_FULL_METHOD,
    V8PDU_TOSAS_METHOD,
    V8PDU_TOSPROTOPORT_METHOD,
    V8PDU_TOSSRCPREFIX_METHOD,
    V8PDU_TOSDSTPREFIX_METHOD,
    V8PDU_TOSMATRIX_METHOD,
    V8PDU_PREPORTPROTOCOL_METHOD
};

static const value_string v8_agg[] = {
    {V8PDU_AS_METHOD,               "V8 AS aggregation"},
    {V8PDU_PROTO_METHOD,            "V8 Proto/Port aggregation"},
    {V8PDU_SPREFIX_METHOD,          "V8 Source Prefix aggregation"},
    {V8PDU_DPREFIX_METHOD,          "V8 Destination Prefix aggregation"},
    {V8PDU_MATRIX_METHOD,           "V8 Network Matrix aggregation"},
    {V8PDU_DESTONLY_METHOD,         "V8 Destination aggregation (Cisco Catalyst)"},
    {V8PDU_SRCDEST_METHOD,          "V8 Src/Dest aggregation (Cisco Catalyst)"},
    {V8PDU_FULL_METHOD,             "V8 Full aggregation (Cisco Catalyst)"},
    {V8PDU_TOSAS_METHOD,            "V8 TOS+AS aggregation"},
    {V8PDU_TOSPROTOPORT_METHOD,     "V8 TOS+Protocol aggregation"},
    {V8PDU_TOSSRCPREFIX_METHOD,     "V8 TOS+Source Prefix aggregation"},
    {V8PDU_TOSDSTPREFIX_METHOD,     "V8 TOS+Destination Prefix aggregation"},
    {V8PDU_TOSMATRIX_METHOD,        "V8 TOS+Prefix Matrix aggregation"},
    {V8PDU_PREPORTPROTOCOL_METHOD,  "V8 Port+Protocol aggregation"},
    {0, NULL}
};
static value_string_ext v8_agg_ext = VALUE_STRING_EXT_INIT(v8_agg);


/* Max number of entries/scopes per template */
/* Space is allocated dynamically so there isn't really a need to
   bound this except to cap possible memory use.  Unfortunately if
   this value is too low we can't decode any template with more than
   v9_tmplt_max_fields fields in it.  The best compromise seems
   to be to make v9_tmplt_max_fields a user preference.
   A value of 0 will be unlimited.
*/
#define V9_TMPLT_MAX_FIELDS_DEF   60
static guint v9_tmplt_max_fields = V9_TMPLT_MAX_FIELDS_DEF;

typedef struct _v9_v10_tmplt_entry {
    guint16      type;
    guint16      length;
    guint32      pen;
    const gchar *pen_str;
} v9_v10_tmplt_entry_t;

typedef enum {
    TF_SCOPES=0,
    TF_ENTRIES,
    /* START IPFIX VENDOR FIELDS */
    TF_PLIXER,
    TF_NTOP,
    TF_IXIA,
    TF_NETSCALER,
    TF_BARRACUDA,
    TF_NO_VENDOR_INFO
} v9_v10_tmplt_fields_type_t;
#define TF_NUM 2
#define TF_NUM_EXT 8   /* includes vendor fields */

typedef struct _v9_v10_tmplt {
    /* For linking back to show where fields were defined */
    guint32  template_frame_number;
    address  src_addr;
    guint32  src_port;
    address  dst_addr;
    guint32  dst_port;
    guint32  src_id;   /* SourceID in NetFlow V9, Observation Domain ID in IPFIX */
    guint16  tmplt_id;
    guint    length;
    guint16  field_count[TF_NUM];                /* 0:scopes; 1:entries  */
    v9_v10_tmplt_entry_t *fields_p[TF_NUM_EXT];  /* 0:scopes; 1:entries; n:vendor_entries  */
} v9_v10_tmplt_t;


/* Map from (converstion+obs-domain-id+flowset-id) -> v9_v10_tmplt_entry_t*    */
/* Confusingly, for key, fill in only relevant parts of v9_v10_tmplt_entry_t... */
GHashTable *v9_v10_tmplt_table = NULL;


static const value_string v9_v10_template_types[] = {
    {   1, "BYTES" },
    {   2, "PKTS" },
    {   3, "FLOWS" },
    {   4, "PROTOCOL" },
    {   5, "IP_TOS" },
    {   6, "TCP_FLAGS" },
    {   7, "L4_SRC_PORT" },
    {   8, "IP_SRC_ADDR" },
    {   9, "SRC_MASK" },
    {  10, "INPUT_SNMP" },
    {  11, "L4_DST_PORT" },
    {  12, "IP_DST_ADDR" },
    {  13, "DST_MASK" },
    {  14, "OUTPUT_SNMP" },
    {  15, "IP_NEXT_HOP" },
    {  16, "SRC_AS" },
    {  17, "DST_AS" },
    {  18, "BGP_NEXT_HOP" },
    {  19, "MUL_DPKTS" },
    {  20, "MUL_DOCTETS" },
    {  21, "LAST_SWITCHED" },
    {  22, "FIRST_SWITCHED" },
    {  23, "OUT_BYTES" },
    {  24, "OUT_PKTS" },
    {  25, "IP LENGTH MINIMUM" },
    {  26, "IP LENGTH MAXIMUM" },
    {  27, "IPV6_SRC_ADDR" },
    {  28, "IPV6_DST_ADDR" },
    {  29, "IPV6_SRC_MASK" },
    {  30, "IPV6_DST_MASK" },
    {  31, "FLOW_LABEL" },
    {  32, "ICMP_TYPE" },
    {  33, "IGMP_TYPE" },
    {  34, "SAMPLING_INTERVAL" },
    {  35, "SAMPLING_ALGORITHM" },
    {  36, "FLOW_ACTIVE_TIMEOUT" },
    {  37, "FLOW_INACTIVE_TIMEOUT" },
    {  38, "ENGINE_TYPE" },
    {  39, "ENGINE_ID" },
    {  40, "TOTAL_BYTES_EXP" },
    {  41, "TOTAL_PKTS_EXP" },
    {  42, "TOTAL_FLOWS_EXP" },
    {  43, "IPV4_ROUTER_SC" },
    {  44, "IP_SRC_PREFIX" },
    {  45, "IP_DST_PREFIX" },
    {  46, "MPLS_TOP_LABEL_TYPE" },
    {  47, "MPLS_TOP_LABEL_ADDR" },
    {  48, "FLOW_SAMPLER_ID" },
    {  49, "FLOW_SAMPLER_MODE" },
    {  50, "FLOW_SAMPLER_RANDOM_INTERVAL" },
    {  51, "FLOW_CLASS" },
    {  52, "IP TTL MINIMUM" },
    {  53, "IP TTL MAXIMUM" },
    {  54, "IPv4 ID" },
    {  55, "DST_TOS" },
    {  56, "SRC_MAC" },
    {  57, "DST_MAC" },
    {  58, "SRC_VLAN" },
    {  59, "DST_VLAN" },
    {  60, "IP_PROTOCOL_VERSION" },
    {  61, "DIRECTION" },
    {  62, "IPV6_NEXT_HOP" },
    {  63, "BGP_IPV6_NEXT_HOP" },
    {  64, "IPV6_OPTION_HEADERS" },
    {  70, "MPLS_LABEL_1" },
    {  71, "MPLS_LABEL_2" },
    {  72, "MPLS_LABEL_3" },
    {  73, "MPLS_LABEL_4" },
    {  74, "MPLS_LABEL_5" },
    {  75, "MPLS_LABEL_6" },
    {  76, "MPLS_LABEL_7" },
    {  77, "MPLS_LABEL_8" },
    {  78, "MPLS_LABEL_9" },
    {  79, "MPLS_LABEL_10" },
    {  80, "DESTINATION_MAC" },
    {  81, "SOURCE_MAC" },
    {  82, "IF_NAME" },
    {  83, "IF_DESC" },
    {  84, "SAMPLER_NAME" },
    {  85, "BYTES_TOTAL" },
    {  86, "PACKETS_TOTAL" },
    {  88, "FRAGMENT_OFFSET" },
    {  89, "FORWARDING_STATUS" },
    {  90, "VPN_ROUTE_DISTINGUISHER" },
    {  91, "mplsTopLabelPrefixLength" },
    {  92, "SRC_TRAFFIC_INDEX" },
    {  93, "DST_TRAFFIC_INDEX" },
    {  94, "APPLICATION_DESC" },
    {  95, "APPLICATION_ID" },
    {  96, "APPLICATION_NAME" },
    {  98, "postIpDiffServCodePoint" },
    {  99, "multicastReplicationFactor" },
    { 101, "classificationEngineId" },
    { 128, "DST_AS_PEER" },
    { 129, "SRC_AS_PEER" },
    { 130, "exporterIPv4Address" },
    { 131, "exporterIPv6Address" },
    { 132, "DROPPED_BYTES" },
    { 133, "DROPPED_PACKETS" },
    { 134, "DROPPED_BYTES_TOTAL" },
    { 135, "DROPPED_PACKETS_TOTAL" },
    { 136, "flowEndReason" },
    { 137, "commonPropertiesId" },
    { 138, "observationPointId" },
    { 139, "icmpTypeCodeIPv6" },
    { 140, "MPLS_TOP_LABEL_IPv6_ADDRESS" },
    { 141, "lineCardId" },
    { 142, "portId" },
    { 143, "meteringProcessId" },
    { 144, "FLOW_EXPORTER" },
    { 145, "templateId" },
    { 146, "wlanChannelId" },
    { 147, "wlanSSID" },
    { 148, "flowId" },
    { 149, "observationDomainId" },
    { 150, "flowStartSeconds" },
    { 151, "flowEndSeconds" },
    { 152, "flowStartMilliseconds" },
    { 153, "flowEndMilliseconds" },
    { 154, "flowStartMicroseconds" },
    { 155, "flowEndMicroseconds" },
    { 156, "flowStartNanoseconds" },
    { 157, "flowEndNanoseconds" },
    { 158, "flowStartDeltaMicroseconds" },
    { 159, "flowEndDeltaMicroseconds" },
    { 160, "systemInitTimeMilliseconds" },
    { 161, "flowDurationMilliseconds" },
    { 162, "flowDurationMicroseconds" },
    { 163, "observedFlowTotalCount" },
    { 164, "ignoredPacketTotalCount" },
    { 165, "ignoredOctetTotalCount" },
    { 166, "notSentFlowTotalCount" },
    { 167, "notSentPacketTotalCount" },
    { 168, "notSentOctetTotalCount" },
    { 169, "destinationIPv6Prefix" },
    { 170, "sourceIPv6Prefix" },
    { 171, "postOctetTotalCount" },
    { 172, "postPacketTotalCount" },
    { 173, "flowKeyIndicator" },
    { 174, "postMCastPacketTotalCount" },
    { 175, "postMCastOctetTotalCount" },
    { 176, "ICMP_IPv4_TYPE" },
    { 177, "ICMP_IPv4_CODE" },
    { 178, "ICMP_IPv6_TYPE" },
    { 179, "ICMP_IPv6_CODE" },
    { 180, "UDP_SRC_PORT" },
    { 181, "UDP_DST_PORT" },
    { 182, "TCP_SRC_PORT" },
    { 183, "TCP_DST_PORT" },
    { 184, "TCP_SEQ_NUM" },
    { 185, "TCP_ACK_NUM" },
    { 186, "TCP_WINDOW_SIZE" },
    { 187, "TCP_URGENT_PTR" },
    { 188, "TCP_HEADER_LEN" },
    { 189, "IP_HEADER_LEN" },
    { 190, "IP_TOTAL_LEN" },
    { 191, "payloadLengthIPv6" },
    { 192, "IP_TTL" },
    { 193, "nextHeaderIPv6" },
    { 194, "mplsPayloadLength" },
    { 195, "IP_DSCP" },
    { 196, "IP_PRECEDENCE" },
    { 197, "IP_FRAGMENT_FLAGS" },
    { 198, "DELTA_BYTES_SQUARED" },
    { 199, "TOTAL_BYTES_SQUARED" },
    { 200, "MPLS_TOP_LABEL_TTL" },
    { 201, "MPLS_LABEL_STACK_OCTETS" },
    { 202, "MPLS_LABEL_STACK_DEPTH" },
    { 203, "MPLS_TOP_LABEL_EXP" },
    { 204, "IP_PAYLOAD_LENGTH" },
    { 205, "UDP_LENGTH" },
    { 206, "IS_MULTICAST" },
    { 207, "IP_HEADER_WORDS" },
    { 208, "IP_OPTION_MAP" },
    { 209, "TCP_OPTION_MAP" },
    { 210, "paddingOctets" },
    { 211, "collectorIPv4Address" },
    { 212, "collectorIPv6Address" },
    { 213, "collectorInterface" },
    { 214, "collectorProtocolVersion" },
    { 215, "collectorTransportProtocol" },
    { 216, "collectorTransportPort" },
    { 217, "exporterTransportPort" },
    { 218, "tcpSynTotalCount" },
    { 219, "tcpFinTotalCount" },
    { 220, "tcpRstTotalCount" },
    { 221, "tcpPshTotalCount" },
    { 222, "tcpAckTotalCount" },
    { 223, "tcpUrgTotalCount" },
    { 224, "ipTotalLength" },
    { 225, "postNATSourceIPv4Address" },
    { 226, "postNATDestinationIPv4Address" },
    { 227, "postNAPTSourceTransportPort" },
    { 228, "postNAPTDestinationTransportPort" },
    { 229, "natOriginatingAddressRealm" },
    { 230, "natEvent" },
    { 231, "initiatorOctets" },
    { 232, "responderOctets" },
    { 233, "firewallEvent" },
    { 234, "ingressVRFID" },
    { 235, "egressVRFID" },
    { 236, "VRFname" },
    { 237, "postMplsTopLabelExp" },
    { 238, "tcpWindowScale" },
    { 239, "biflowDirection" },
    { 240, "ethernetHeaderLength" },
    { 241, "ethernetPayloadLength" },
    { 242, "ethernetTotalLength" },
    { 243, "dot1qVlanId" },
    { 244, "dot1qPriority" },
    { 245, "dot1qCustomerVlanId" },
    { 246, "dot1qCustomerPriority" },
    { 247, "metroEvcId" },
    { 248, "metroEvcType" },
    { 249, "pseudoWireId" },
    { 250, "pseudoWireType" },
    { 251, "pseudoWireControlWord" },
    { 252, "ingressPhysicalInterface" },
    { 253, "egressPhysicalInterface" },
    { 254, "postDot1qVlanId" },
    { 255, "postDot1qCustomerVlanId" },
    { 256, "ethernetType" },
    { 257, "postIpPrecedence" },
    { 258, "collectionTimeMilliseconds" },
    { 259, "exportSctpStreamId" },
    { 260, "maxExportSeconds" },
    { 261, "maxFlowEndSeconds" },
    { 262, "messageMD5Checksum" },
    { 263, "messageScope" },
    { 264, "minExportSeconds" },
    { 265, "minFlowStartSeconds" },
    { 266, "opaqueOctets" },
    { 267, "sessionScope" },
    { 268, "maxFlowEndMicroseconds" },
    { 269, "maxFlowEndMilliseconds" },
    { 270, "maxFlowEndNanoseconds" },
    { 271, "minFlowStartMicroseconds" },
    { 272, "minFlowStartMilliseconds" },
    { 273, "minFlowStartNanoseconds" },
    { 274, "collectorCertificate" },
    { 275, "exporterCertificate" },
    { 276, "dataRecordsReliability" },
    { 277, "observationPointType" },
    { 278, "newConnectionDeltaCount" },
    { 279, "connectionSumDurationSeconds" },
    { 280, "connectionTransactionId" },
    { 281, "postNATSourceIPv6Address" },
    { 282, "postNATDestinationIPv6Address" },
    { 283, "natPoolId" },
    { 284, "natPoolName" },
    { 285, "anonymizationFlags" },
    { 286, "anonymizationTechnique" },
    { 287, "informationElementIndex" },
    { 288, "p2pTechnology" },
    { 289, "tunnelTechnology" },
    { 290, "encryptedTechnology" },
    { 291, "basicList" },
    { 292, "subTemplateList" },
    { 293, "subTemplateMultiList" },
    { 294, "bgpValidityState" },
    { 295, "IPSecSPI" },
    { 296, "greKey" },
    { 297, "natType" },
    { 298, "initiatorPackets" },
    { 299, "responderPackets" },
    { 300, "observationDomainName" },
    { 301, "selectionSequenceId" },
    { 302, "selectorId" },
    { 303, "informationElementId" },
    { 304, "selectorAlgorithm" },
    { 305, "samplingPacketInterval" },
    { 306, "samplingPacketSpace" },
    { 307, "samplingTimeInterval" },
    { 308, "samplingTimeSpace" },
    { 309, "samplingSize" },
    { 310, "samplingPopulation" },
    { 311, "samplingProbability" },
    { 312, "dataLinkFrameSize" },
    { 313, "IP_SECTION HEADER" },
    { 314, "IP_SECTION PAYLOAD" },
    { 315, "dataLinkFrameSection" },
    { 316, "mplsLabelStackSection" },
    { 317, "mplsPayloadPacketSection" },
    { 318, "selectorIdTotalPktsObserved" },
    { 319, "selectorIdTotalPktsSelected" },
    { 320, "absoluteError" },
    { 321, "relativeError" },
    { 322, "observationTimeSeconds" },
    { 323, "observationTimeMilliseconds" },
    { 324, "observationTimeMicroseconds" },
    { 325, "observationTimeNanoseconds" },
    { 326, "digestHashValue" },
    { 327, "hashIPPayloadOffset" },
    { 328, "hashIPPayloadSize" },
    { 329, "hashOutputRangeMin" },
    { 330, "hashOutputRangeMax" },
    { 331, "hashSelectedRangeMin" },
    { 332, "hashSelectedRangeMax" },
    { 333, "hashDigestOutput" },
    { 334, "hashInitialiserValue" },
    { 335, "selectorName" },
    { 336, "upperCILimit" },
    { 337, "lowerCILimit" },
    { 338, "confidenceLevel" },
    { 339, "informationElementDataType" },
    { 340, "informationElementDescription" },
    { 341, "informationElementName" },
    { 342, "informationElementRangeBegin" },
    { 343, "informationElementRangeEnd" },
    { 344, "informationElementSemantics" },
    { 345, "informationElementUnits" },
    { 346, "privateEnterpriseNumber" },
    { 347, "virtualStationInterfaceId" },
    { 348, "virtualStationInterfaceName" },
    { 349, "virtualStationUUID" },
    { 350, "virtualStationName" },
    { 351, "layer2SegmentId" },
    { 352, "layer2OctetDeltaCount" },
    { 353, "layer2OctetTotalCount" },
    { 354, "ingressUnicastPacketTotalCount" },
    { 355, "ingressMulticastPacketTotalCount" },
    { 356, "ingressBroadcastPacketTotalCount" },
    { 357, "egressUnicastPacketTotalCount" },
    { 358, "egressBroadcastPacketTotalCount" },
    { 359, "monitoringIntervalStartMilliSeconds" },
    { 360, "monitoringIntervalEndMilliSeconds" },
    { 361, "portRangeStart" },
    { 362, "portRangeEnd" },
    { 363, "portRangeStepSize" },
    { 364, "portRangeNumPorts" },
    { 365, "staMacAddress" },
    { 366, "staIPv4Address" },
    { 367, "wtpMacAddress" },
    { 368, "ingressInterfaceType" },
    { 369, "egressInterfaceType" },
    { 370, "rtpSequenceNumber" },
    { 371, "userName" },
    { 372, "applicationCategoryName" },
    { 373, "applicationSubCategoryName" },
    { 374, "applicationGroupName" },
    { 375, "originalFlowsPresent" },
    { 376, "originalFlowsInitiated" },
    { 377, "originalFlowsCompleted" },
    { 378, "distinctCountOfSourceIPAddress" },
    { 379, "distinctCountOfDestinationIPAddress" },
    { 380, "distinctCountOfSourceIPv4Address" },
    { 381, "distinctCountOfDestinationIPv4Address" },
    { 382, "distinctCountOfSourceIPv6Address" },
    { 383, "distinctCountOfDestinationIPv6Address" },
    { 384, "valueDistributionMethod" },
    { 385, "rfc3550JitterMilliseconds" },
    { 386, "rfc3550JitterMicroseconds" },
    { 387, "rfc3550JitterNanoseconds" },
    { 388, "dot1qDEI" },
    { 389, "dot1qCustomerDEI" },
    { 390, "flowSelectorAlgorithm" },
    { 391, "flowSelectedOctetDeltaCount" },
    { 392, "flowSelectedPacketDeltaCount" },
    { 393, "flowSelectedFlowDeltaCount" },
    { 394, "selectorIDTotalFlowsObserved" },
    { 395, "selectorIDTotalFlowsSelected" },
    { 396, "samplingFlowInterval" },
    { 397, "samplingFlowSpacing" },
    { 398, "flowSamplingTimeInterval" },
    { 399, "flowSamplingTimeSpacing" },
    { 400, "hashFlowDomain" },
    { 401, "transportOctetDeltaCount" },
    { 402, "transportPacketDeltaCount" },
    { 403, "originalExporterIPv4Address" },
    { 404, "originalExporterIPv6Address" },
    { 405, "originalObservationDomainId" },
    { 406, "intermediateProcessId" },
    { 407, "ignoredDataRecordTotalCount" },
    { 408, "dataLinkFrameType" },
    { 409, "sectionOffset" },
    { 410, "sectionExportedOctets" },
    { 411, "dot1qServiceInstanceTag" },
    { 412, "dot1qServiceInstanceId" },
    { 413, "dot1qServiceInstancePriority" },
    { 414, "dot1qCustomerSourceMacAddress" },
    { 415, "dot1qCustomerDestinationMacAddress" },
    { 416, "deprecated [dup of layer2OctetDeltaCount]" },
    { 417, "postLayer2OctetDeltaCount" },
    { 418, "postMCastLayer2OctetDeltaCount" },
    { 419, "deprecated [dup of layer2OctetTotalCount" },
    { 420, "postLayer2OctetTotalCount" },
    { 421, "postMCastLayer2OctetTotalCount" },
    { 422, "minimumLayer2TotalLength" },
    { 423, "maximumLayer2TotalLength" },
    { 424, "droppedLayer2OctetDeltaCount" },
    { 425, "droppedLayer2OctetTotalCount" },
    { 426, "ignoredLayer2OctetTotalCount" },
    { 427, "notSentLayer2OctetTotalCount" },
    { 428, "layer2OctetDeltaSumOfSquares" },
    { 429, "layer2OctetTotalSumOfSquares" },
    { 430, "layer2FrameDeltaCount" },
    { 431, "layer2FrameTotalCount" },
    { 432, "pseudoWireDestinationIPv4Address" },
    { 433, "ignoredLayer2FrameTotalCount" },

    /* Ericsson NAT Logging */
    { 24628, "NAT_LOG_FIELD_IDX_CONTEXT_ID" },
    { 24629, "NAT_LOG_FIELD_IDX_CONTEXT_NAME" },
    { 24630, "NAT_LOG_FIELD_IDX_ASSIGN_TS_SEC" },
    { 24631, "NAT_LOG_FIELD_IDX_UNASSIGN_TS_SEC" },
    { 24632, "NAT_LOG_FIELD_IDX_IPV4_INT_ADDR" },
    { 24633, "NAT_LOG_FIELD_IDX_IPV4_EXT_ADDR" },
    { 24634, "NAT_LOG_FIELD_IDX_EXT_PORT_FIRST" },
    { 24635, "NAT_LOG_FIELD_IDX_EXT_PORT_LAST" },
    /* Cisco ASA5500 Series NetFlow */
    { 33000, "INGRESS_ACL_ID" },
    { 33001, "EGRESS_ACL_ID" },
    { 33002, "FW_EXT_EVENT" },
    /* Cisco TrustSec */
    { 34000, "SGT_SOURCE_TAG" },
    { 34001, "SGT_DESTINATION_TAG" },
    { 34002, "SGT_SOURCE_NAME" },
    { 34003, "SGT_DESTINATION_NAME" },
    /* medianet performance monitor */
    { 37000, "PACKETS_DROPPED" },
    { 37003, "BYTE_RATE" },
    { 37004, "APPLICATION_MEDIA_BYTES" },
    { 37006, "APPLICATION_MEDIA_BYTE_RATE" },
    { 37007, "APPLICATION_MEDIA_PACKETS" },
    { 37009, "APPLICATION_MEDIA_PACKET_RATE" },
    { 37011, "APPLICATION_MEDIA_EVENT" },
    { 37012, "MONITOR_EVENT" },
    { 37013, "TIMESTAMP_INTERVAL" },
    { 37014, "TRANSPORT_PACKETS_EXPECTED" },
    { 37016, "TRANSPORT_ROUND_TRIP_TIME" },
    { 37017, "TRANSPORT_EVENT_PACKET_LOSS" },
    { 37019, "TRANSPORT_PACKETS_LOST" },
    { 37021, "TRANSPORT_PACKETS_LOST_RATE" },
    { 37022, "TRANSPORT_RTP_SSRC" },
    { 37023, "TRANSPORT_RTP_JITTER_MEAN" },
    { 37024, "TRANSPORT_RTP_JITTER_MIN" },
    { 37025, "TRANSPORT_RTP_JITTER_MAX" },
    { 37041, "TRANSPORT_RTP_PAYLOAD_TYPE" },
    { 37071, "TRANSPORT_BYTES_OUT_OF_ORDER" },
    { 37074, "TRANSPORT_PACKETS_OUT_OF_ORDER" },
    { 37083, "TRANSPORT_TCP_WINDOWS_SIZE_MIN" },
    { 37084, "TRANSPORT_TCP_WINDOWS_SIZE_MAX" },
    { 37085, "TRANSPORT_TCP_WINDOWS_SIZE_MEAN" },
    { 37086, "TRANSPORT_TCP_MAXIMUM_SEGMENT_SIZE" },
    /* Cisco ASA 5500 */
    { 40000, "AAA_USERNAME" },
    { 40001, "XLATE_SRC_ADDR_IPV4" },
    { 40002, "XLATE_DST_ADDR_IPV4" },
    { 40003, "XLATE_SRC_PORT" },
    { 40004, "XLATE_DST_PORT" },
    { 40005, "FW_EVENT" },
    /* v9 nTop extensions. */
    {  80 + NTOP_BASE, "FRAGMENTS" },
    {  82 + NTOP_BASE, "CLIENT_NW_DELAY_SEC" },
    {  83 + NTOP_BASE, "CLIENT_NW_DELAY_USEC" },
    {  84 + NTOP_BASE, "SERVER_NW_DELAY_SEC" },
    {  85 + NTOP_BASE, "SERVER_NW_DELAY_USEC" },
    {  86 + NTOP_BASE, "APPL_LATENCY_SEC" },
    {  87 + NTOP_BASE, "APPL_LATENCY_USEC" },
    {  98 + NTOP_BASE, "ICMP_FLAGS" },
    { 101 + NTOP_BASE, "SRC_IP_COUNTRY" },
    { 102 + NTOP_BASE, "SRC_IP_CITY" },
    { 103 + NTOP_BASE, "DST_IP_COUNTRY" },
    { 104 + NTOP_BASE, "DST_IP_CITY" },
    { 105 + NTOP_BASE, "FLOW_PROTO_PORT" },
    { 106 + NTOP_BASE, "TUNNEL_ID" },
    { 107 + NTOP_BASE, "LONGEST_FLOW_PKT" },
    { 108 + NTOP_BASE, "SHORTEST_FLOW_PKT" },
    { 109 + NTOP_BASE, "RETRANSMITTED_IN_PKTS" },
    { 110 + NTOP_BASE, "RETRANSMITTED_OUT_PKTS" },
    { 111 + NTOP_BASE, "OOORDER_IN_PKTS" },
    { 112 + NTOP_BASE, "OOORDER_OUT_PKTS" },
    { 113 + NTOP_BASE, "UNTUNNELED_PROTOCOL" },
    { 114 + NTOP_BASE, "UNTUNNELED_IPV4_SRC_ADDR" },
    { 115 + NTOP_BASE, "UNTUNNELED_L4_SRC_PORT" },
    { 116 + NTOP_BASE, "UNTUNNELED_IPV4_DST_ADDR" },
    { 117 + NTOP_BASE, "UNTUNNELED_L4_DST_PORT" },
    { 120 + NTOP_BASE, "DUMP_PATH" },
    { 130 + NTOP_BASE, "SIP_CALL_ID" },
    { 131 + NTOP_BASE, "SIP_CALLING_PARTY" },
    { 132 + NTOP_BASE, "SIP_CALLED_PARTY" },
    { 133 + NTOP_BASE, "SIP_RTP_CODECS" },
    { 134 + NTOP_BASE, "SIP_INVITE_TIME" },
    { 135 + NTOP_BASE, "SIP_TRYING_TIME" },
    { 136 + NTOP_BASE, "SIP_RINGING_TIME" },
    { 137 + NTOP_BASE, "SIP_OK_TIME" },
    { 138 + NTOP_BASE, "SIP_BYE_TIME" },
    { 139 + NTOP_BASE, "SIP_RTP_SRC_IP" },
    { 140 + NTOP_BASE, "SIP_RTP_SRC_PORT" },
    { 141 + NTOP_BASE, "SIP_RTP_DST_IP" },
    { 142 + NTOP_BASE, "SIP_RTP_DST_PORT" },
    { 150 + NTOP_BASE, "RTP_FIRST_SSRC" },
    { 151 + NTOP_BASE, "RTP_FIRST_TS" },
    { 152 + NTOP_BASE, "RTP_LAST_SSRC" },
    { 153 + NTOP_BASE, "RTP_LAST_TS" },
    { 154 + NTOP_BASE, "RTP_IN_JITTER" },
    { 155 + NTOP_BASE, "RTP_OUT_JITTER" },
    { 156 + NTOP_BASE, "RTP_IN_PKT_LOST" },
    { 157 + NTOP_BASE, "RTP_OUT_PKT_LOST" },
    { 158 + NTOP_BASE, "RTP_OUT_PAYLOAD_TYPE" },
    { 159 + NTOP_BASE, "RTP_IN_MAX_DELTA" },
    { 160 + NTOP_BASE, "RTP_OUT_MAX_DELTA" },
    { 165 + NTOP_BASE, "L7_PROTO" },
    { 180 + NTOP_BASE, "HTTP_URL" },
    { 181 + NTOP_BASE, "HTTP_RET_CODE" },
    { 182 + NTOP_BASE, "HTTP_REFERER" },
    { 183 + NTOP_BASE, "HTTP_UA" },
    { 184 + NTOP_BASE, "HTTP_MIME" },
    { 185 + NTOP_BASE, "SMTP_MAIL_FROM" },
    { 186 + NTOP_BASE, "SMTP_RCPT_TO" },
    { 195 + NTOP_BASE, "MYSQL_SERVER_VERSION" },
    { 196 + NTOP_BASE, "MYSQL_USERNAME" },
    { 197 + NTOP_BASE, "MYSQL_DB" },
    { 198 + NTOP_BASE, "MYSQL_QUERY" },
    { 199 + NTOP_BASE, "MYSQL_RESPONSE" },
    { 0, NULL }
};
static value_string_ext v9_v10_template_types_ext = VALUE_STRING_EXT_INIT(v9_v10_template_types);

static const value_string v10_template_types_plixer[] = {
    { 100, "client_ip_v4" },
    { 101, "client_hostname" },
    { 102, "partner_name" },
    { 103, "server_hostname" },
    { 104, "server_ip_v4" },
    { 105, "recipient_address" },
    { 106, "event_id" },
    { 107, "msgid" },
    { 108, "priority" },
    { 109, "recipient_report_status" },
    { 110, "number_recipients" },
    { 111, "origination_time" },
    { 112, "encryption" },
    { 113, "service_version" },
    { 114, "linked_msgid" },
    { 115, "message_subject" },
    { 116, "sender_address" },
    { 117, "date_time" },
    { 118, "client_ip_v6" },
    { 119, "server_ip_v6" },
    { 120, "source_context" },
    { 121, "connector_id" },
    { 122, "source_component" },
    { 124, "related_recipient_address" },
    { 125, "reference" },
    { 126, "return_path" },
    { 127, "message_info" },
    { 128, "directionality" },
    { 129, "tenant_id" },
    { 130, "original_client_ip_v4" },
    { 131, "original_server_ip_v4" },
    { 132, "custom_data" },
    { 133, "internal_message_id" },
    { 0, NULL }
};
static value_string_ext v10_template_types_plixer_ext = VALUE_STRING_EXT_INIT(v10_template_types_plixer);

static const value_string v10_template_types_ntop[] = {
    {  80, "FRAGMENTS" },
    {  82, "CLIENT_NW_DELAY_SEC" },
    {  83, "CLIENT_NW_DELAY_USEC" },
    {  84, "SERVER_NW_DELAY_SEC" },
    {  85, "SERVER_NW_DELAY_USEC" },
    {  86, "APPL_LATENCY_SEC" },
    {  87, "APPL_LATENCY_USEC" },
    {  98, "ICMP_FLAGS" },
    { 101, "SRC_IP_COUNTRY" },
    { 102, "SRC_IP_CITY" },
    { 103, "DST_IP_COUNTRY" },
    { 104, "DST_IP_CITY" },
    { 105, "FLOW_PROTO_PORT" },
    { 106, "TUNNEL_ID" },
    { 107, "LONGEST_FLOW_PKT" },
    { 108, "SHORTEST_FLOW_PKT" },
    { 109, "RETRANSMITTED_IN_PKTS" },
    { 110, "RETRANSMITTED_OUT_PKTS" },
    { 111, "OOORDER_IN_PKTS" },
    { 112, "OOORDER_OUT_PKTS" },
    { 113, "UNTUNNELED_PROTOCOL" },
    { 114, "UNTUNNELED_IPV4_SRC_ADDR" },
    { 115, "UNTUNNELED_L4_SRC_PORT" },
    { 116, "UNTUNNELED_IPV4_DST_ADDR" },
    { 117, "UNTUNNELED_L4_DST_PORT" },
    { 120, "DUMP_PATH" },
    { 130, "SIP_CALL_ID" },
    { 131, "SIP_CALLING_PARTY" },
    { 132, "SIP_CALLED_PARTY" },
    { 133, "SIP_RTP_CODECS" },
    { 134, "SIP_INVITE_TIME" },
    { 135, "SIP_TRYING_TIME" },
    { 136, "SIP_RINGING_TIME" },
    { 137, "SIP_OK_TIME" },
    { 138, "SIP_BYE_TIME" },
    { 139, "SIP_RTP_SRC_IP" },
    { 140, "SIP_RTP_SRC_PORT" },
    { 141, "SIP_RTP_DST_IP" },
    { 142, "SIP_RTP_DST_PORT" },
    { 150, "RTP_FIRST_SSRC" },
    { 151, "RTP_FIRST_TS" },
    { 152, "RTP_LAST_SSRC" },
    { 153, "RTP_LAST_TS" },
    { 154, "RTP_IN_JITTER" },
    { 155, "RTP_OUT_JITTER" },
    { 156, "RTP_IN_PKT_LOST" },
    { 157, "RTP_OUT_PKT_LOST" },
    { 158, "RTP_OUT_PAYLOAD_TYPE" },
    { 159, "RTP_IN_MAX_DELTA" },
    { 160, "RTP_OUT_MAX_DELTA" },
    { 165, "L7_PROTO" },
    { 180, "HTTP_URL" },
    { 181, "HTTP_RET_CODE" },
    { 182, "HTTP_REFERER" },
    { 183, "HTTP_UA" },
    { 184, "HTTP_MIME" },
    { 185, "SMTP_MAIL_FROM" },
    { 186, "SMTP_RCPT_TO" },
    { 195, "MYSQL_SERVER_VERSION" },
    { 196, "MYSQL_USERNAME" },
    { 197, "MYSQL_DB" },
    { 198, "MYSQL_QUERY" },
    { 199, "MYSQL_RESPONSE" },
    { 0, NULL }
};
static value_string_ext v10_template_types_ntop_ext = VALUE_STRING_EXT_INIT(v10_template_types_ntop);

/* Ixia IxFlow */
static const value_string v10_template_types_ixia[] = {
    {  110, "L7 Application ID" },
    {  111, "L7 Application Name" },
    {  120, "Source IP Country Code" },
    {  121, "Source IP Country Name" },
    {  122, "Source IP Region Code" },
    {  123, "Source IP Region Name" },
    {  125, "Source IP City Name" },
    {  126, "Source IP Latitude" },
    {  127, "Source IP Longitude" },
    {  140, "Destination IP Country Code" },
    {  141, "Destination IP Country Name" },
    {  142, "Destination IP Region Code" },
    {  143, "Destination IP Region Node" },
    {  145, "Destination IP City Name" },
    {  146, "Destination IP Latitude" },
    {  147, "Destination IP Longitude" },
    {  160, "OS Device ID" },
    {  161, "OS Device Name" },
    {  162, "Browser ID" },
    {  163, "Browser Name" },
    {  176, "Reverse Octet Delta Count" },
    {  177, "Reverse Packet Delta Count" },
    {  178, "Connection encryption type" },
    {  179, "Encryption Cipher Suite" },
    {  180, "Encryption Key Length" },
    {  181, "IMSI for 3/4G subscriber" },
    {  182, "HTTP Request User-Agent" },
    {  183, "Host Name" },
    {  184, "HTTP URI" },
    {  185, "DNS record TXT" },
    { 0, NULL }
};
static value_string_ext v10_template_types_ixia_ext = VALUE_STRING_EXT_INIT(v10_template_types_ixia);

/* Netscaler AppFlow */
static const value_string v10_template_types_netscaler[] = {
    {  128, "Round Trip Time" },
    {  129, "Transaction Id" },
    {  130, "HTTP Request URL" },
    {  131, "HTTP Request Cookie" },
    {  132, "Flow Flags" },
    {  133, "Connection Id" },
    {  134, "Syslog Priority" },
    {  135, "Syslog Message" },
    {  136, "Syslog Timestamp" },
    {  140, "HTTP Request Referer" },
    {  141, "HTTP Request Method" },
    {  142, "HTTP Request Host" },
    {  143, "HTTP Request UserAgent" },
    {  144, "HTTP Response Status" },
    {  145, "HTTP Response Length" },
    {  146, "Server TTFB" },
    {  147, "Server TTLB" },
    {  150, "AppName Incarnation Number" },
    {  151, "AppName App Id" },
    {  152, "AppName" },
    {  153, "HTTP Request Received FB" },
    {  156, "HTTP Request Forwarded FB" },
    {  157, "HTTP Response Received FB" },
    {  158, "HTTP Response Forwarded FB" },
    {  159, "HTTP Request Received LB" },
    {  160, "HTTP Request Forwarded LB" },
    {  161, "Main Page Id" },
    {  162, "Main Page Core Id" },
    {  163, "HTTP Client Interaction Start Time" },
    {  164, "HTTP Client Render End Time" },
    {  165, "HTTP Client Render Start Time" },
    {  167, "App Template Name" },
    {  168, "HTTP Client Interaction End Time" },
    {  169, "HTTP Response Received LB" },
    {  170, "HTTP Response Forwarded LB" },
    {  171, "App Unit Name App Id" },
    {  172, "DB Login Flags" },
    {  173, "DB Request Type" },
    {  174, "DB Protocol Name" },
    {  175, "DB User Name" },
    {  176, "DB Database Name" },
    {  177, "DB Client Host Name" },
    {  178, "DB Request String" },
    {  179, "DB Response Status String" },
    {  180, "DB Response Status" },
    {  181, "DB Response Length" },
    {  182, "Client RTT" },
    {  183, "HTTP Content Type" },
    {  185, "HTTP Request Authorization" },
    {  186, "HTTP Request Via" },
    {  187, "HTTP Response Location" },
    {  188, "HTTP Response Set-Cookie" },
    {  189, "HTTP Response Set-Cookie2" },
    {  190, "HTTP Request X-Forwarded-For" },
    {  192, "Connection Chain ID" },
    {  193, "Connection Chain Hop Count" },
    {  200, "ICA Session Guid" },
    {  201, "ICA Client Version" },
    {  202, "ICA Client Type" },
    {  203, "ICA Client IP" },
    {  204, "ICA Client Host Name" },
    {  205, "AAA Username" },
    {  207, "ICA Domain Name" },
    {  208, "ICA Client Launcher" },
    {  209, "ICA Session Setup Time" },
    {  210, "ICA Server Name" },
    {  214, "ICA Session Reconnects" },
    {  215, "ICA RTT" },
    {  216, "ICA Clientside RX Bytes" },
    {  217, "ICA Clientside TX Bytes" },
    {  219, "ICA Clientside Packets Retransmit" },
    {  220, "ICA Serverside Packets Retransmit" },
    {  221, "ICA Clientside RTT" },
    {  222, "ICA Serverside RTT" },
    {  223, "ICA Session Update Begin Sec" },
    {  224, "ICA Session Update End Sec" },
    {  225, "ICA Channel Id1" },
    {  226, "ICA Channel Id1 Bytes" },
    {  227, "ICA Channel Id2" },
    {  228, "ICA Channel Id2 Bytes" },
    {  229, "ICA Channel Id3" },
    {  230, "ICA Channel Id3 Bytes" },
    {  231, "ICA Channel Id4" },
    {  232, "ICA Channel Id4 Bytes" },
    {  233, "ICA Channel Id5" },
    {  234, "ICA Channel Id5 Bytes" },
    {  235, "ICA Connection Priority" },
    {  236, "Application Startup Duration" },
    {  237, "ICA Launch Mechanism" },
    {  238, "ICA Application Name" },
    {  239, "Application Startup Time" },
    {  240, "ICA Application Termination Type" },
    {  241, "ICA Application Termination Time" },
    {  242, "ICA Session End Time" },
    {  243, "ICA Clientside Jitter" },
    {  244, "ICA Serverside Jitter" },
    {  245, "ICA App Process ID" },
    {  246, "ICA App Module Path" },
    {  247, "ICA Device Serial No" },
    {  248, "Msi Client Cookie" },
    {  249, "ICA Flags" },
    {  250, "ICA Username" },
    {  251, "License Type" },
    {  252, "Max License Count" },
    {  253, "Current License Consumed" },
    {  254, "ICA Network Update Start Time" },
    {  255, "ICA Network Update End Time" },
    {  256, "ICA Clientside SRTT" },
    {  257, "ICA Serverside SRTT" },
    {  258, "ICA Clientside Delay" },
    {  259, "ICA Serverside Delay" },
    {  260, "ICA Host Delay" },
    {  261, "ICA ClientSide WindowSize" },
    {  262, "ICA ServerSide WindowSize" },
    {  263, "ICA ClientSide RTO Count" },
    {  264, "ICA ServerSide RTO Count" },
    {  265, "ICA L7 Client Latency" },
    {  266, "ICA L7 Server Latency" },
    {  267, "HTTP Domain Name" },
    {  268, "CacheRedir Client Connection Core ID" },
    {  269, "CacheRedir Client Connection Transaction ID" },
    { 0, NULL }
};
static value_string_ext v10_template_types_netscaler_ext = VALUE_STRING_EXT_INIT(v10_template_types_netscaler);

/* Barracuda NGFirewall IPFIX */
static const value_string v10_template_types_barracuda[] = {
    {  1, "Timestamp" },
    {  2, "LogOp" },
    {  3, "TrafficType" },
    {  4, "FW Rule" },
    {  5, "ServiceName" },
    {  6, "Reason" },
    {  7, "ReasonText" },
    {  8, "BindIPv4Address" },
    {  9, "BindTransportPort" },
    {  10, "ConnIPv4Address" },
    {  11, "ConnTransportPort" },
    {  12, "AuditCounter" },
    { 0, NULL }
};
static value_string_ext v10_template_types_barracuda_ext = VALUE_STRING_EXT_INIT(v10_template_types_barracuda);

static const value_string v10_barracuda_logop[] = {
    { 0, "Unknown" },
    { 1, "Allow" },
    { 2, "LocalAllow" },
    { 3, "Block" },
    { 4, "LocalBlock" },
    { 5, "Remove" },
    { 6, "LocalRemove" },
    { 7, "Drop" },
    { 8, "Terminate" },
    { 9, "LocalTerminate" },
    { 10, "Change" },
    { 11, "Operation" },
    { 12, "Startup" },
    { 13, "Configuration" },
    { 14, "Rule" },
    { 15, "State" },
    { 16, "LocalState" },
    { 17, "Process" },
    { 18, "AdminAction" },
    { 19, "Deny" },
    { 20, "LocalDeny" },
    { 21, "SecurityEvent" },
    { 22, "Sync" },
    { 23, "Fail" },
    { 24, "LocalFail" },
    { 25, "ARP" },
    { 26, "Detect" },
    { 27, "LocalDetect" },
    { 28, "IntermediateReport" },
    { 0, NULL }
};

static const value_string v10_barracuda_traffictype[] = {
    { 0, "Forwarding" },
    { 1, "Local In" },
    { 2, "Local Out" },
    { 3, "Loopback" },
    { 0, NULL }
};

static const value_string v9_scope_field_types[] = {
    { 1, "System" },
    { 2, "Interface" },
    { 3, "Line Card" },
    { 4, "NetFlow Cache" },
    { 5, "Template" },
    { 0, NULL }
};
static value_string_ext v9_scope_field_types_ext = VALUE_STRING_EXT_INIT(v9_scope_field_types);

static const value_string v9_sampler_mode[] = {
    { 0, "Deterministic" },
    { 1, "Unknown" },  /* "Time-Based" ?? */
    { 2, "Random" },
    { 0, NULL }
};

static const value_string v9_direction[] = {
    { 0, "Ingress" },
    { 1, "Egress" },
    { 0, NULL }
};

#define FORWARDING_STATUS_UNKNOWN 0
#define FORWARDING_STATUS_FORWARD 1
#define FORWARDING_STATUS_DROP    2
#define FORWARDING_STATUS_CONSUME 3

static const value_string v9_forwarding_status[] = {
    { FORWARDING_STATUS_UNKNOWN, "Unknown"},  /* Observed on IOS-XR 3.2 */
    { FORWARDING_STATUS_FORWARD, "Forward"},  /* Observed on 7200 12.4(9)T */
    { FORWARDING_STATUS_DROP,    "Drop"},     /* Observed on 7200 12.4(9)T */
    { FORWARDING_STATUS_CONSUME, "Consume"},  /* Observed on 7200 12.4(9)T */
    { 0, NULL }
};

static const value_string v9_forwarding_status_unknown_code[] = {
    {   0, NULL }
};

static const value_string v9_forwarding_status_forward_code[] = {
    {   0, "Forwarded (Unknown)" },
    {   1, "Forwarded Fragmented" },
    {   2, "Forwarded not Fragmented" },
    {   0, NULL }
};

static const value_string v9_forwarding_status_drop_code[] = {
    {   0, "Dropped (Unknown)" },
    {   1, "Drop ACL Deny" },
    {   2, "Drop ACL drop" },
    {   3, "Drop Unroutable" },
    {   4, "Drop Adjacency" },
    {   5, "Drop Fragmentation & DF set" },
    {   6, "Drop Bad header checksum" },
    {   7, "Drop Bad total Length" },
    {   8, "Drop Bad Header Length" },
    {   9, "Drop bad TTL" },
    {  10, "Drop Policer" },
    {  11, "Drop WRED" },
    {  12, "Drop RPF" },
    {  13, "Drop For us" },
    {  14, "Drop Bad output interface" },
    {  15, "Drop Hardware" },
    {   0, NULL }
};

static const value_string v9_forwarding_status_consume_code[] = {
    {   0, "Consumed (Unknown)" },
    {   1, "Terminate Punt Adjacency" },
    {   2, "Terminate Incomplete Adjacency" },
    {   3, "Terminate For us" },
    {   0, NULL }
};

static const value_string v9_firewall_event[] = {
    { 0, "Default (ignore)"},
    { 1, "Flow created"},
    { 2, "Flow deleted"},
    { 3, "Flow denied"},
    { 4, "Flow alert"},
    { 0, NULL }
};

static const value_string v9_extended_firewall_event[] = {
    {    0, "ignore"},
    { 1001, "Flow denied by an ingress ACL"},
    { 1002, "Flow denied by an egress ACL"},
    { 1003, "Flow denied by security appliance"},
    { 1004, "Flow denied (TCP flow beginning with not TCP SYN)"},
    { 0, NULL }
};

static const value_string engine_type[] = {
    { 0, "RP"},
    { 1, "VIP/Linecard"},
    { 2, "PFC/DFC" },
    { 0, NULL }
};

static const value_string v9_flow_end_reason[] = {
    { 0, "Unknown"},
    { 1, "Idle timeout"},
    { 2, "Active timeout" },
    { 3, "End of Flow detected" },
    { 4, "Forced end" },
    { 5, "Lack of resources" },
    { 0, NULL }
};

static const value_string v9_biflow_direction[] = {
    { 0, "Arbitrary"},
    { 1, "Initiator"},
    { 2, "ReverseInitiator" },
    { 3, "Perimeter" },
    { 0, NULL }
};

static const value_string selector_algorithm[] = {
    { 0, "Reserved"},
    { 1, "Systematic count-based Sampling"},
    { 2, "Systematic time-based Sampling"},
    { 3, "Random n-out-of-N Sampling"},
    { 4, "Uniform probabilistic Sampling"},
    { 5, "Property match Filtering"},
    { 6, "Hash based Filtering using BOB"},
    { 7, "Hash based Filtering using IPSX"},
    { 8, "Hash based Filtering using CRC"},
    { 0, NULL }
};
static value_string_ext selector_algorithm_ext = VALUE_STRING_EXT_INIT(selector_algorithm);

static const value_string performance_monitor_specials[] = {
    { 0xFFFFFFFF, "Not Measured"},
    { 0xFFFF, "Not Measured"},
    { 0xFF, "Not Measured"},
    { 0, NULL }
};

static const true_false_string mpls_bos_tfs = {
    "Bottom-of-Stack",
    ""
};


/*
 * wireshark tree identifiers
 */

static int      proto_netflow           = -1;

static int      ett_netflow             = -1;
static int      ett_unixtime            = -1;
static int      ett_flow                = -1;
static int      ett_flowtime            = -1;
static int      ett_str_len             = -1;
static int      ett_template            = -1;
static int      ett_field               = -1;
static int      ett_dataflowset         = -1;
static int      ett_fwdstat             = -1;
static int      ett_mpls_label          = -1;
static int      ett_tcpflags            = -1;
/*
 * cflow header
 */

static int      hf_cflow_version        = -1;
static int      hf_cflow_count          = -1;
static int      hf_cflow_len            = -1;
static int      hf_cflow_sysuptime      = -1;
static int      hf_cflow_exporttime     = -1;
static int      hf_cflow_unix_secs      = -1;
static int      hf_cflow_unix_nsecs     = -1;
static int      hf_cflow_timestamp      = -1;
static int      hf_cflow_samplingmode   = -1;
static int      hf_cflow_samplerate     = -1;

static int      hf_cflow_unknown_field_type        = -1;
static int      hf_cflow_padding        = -1;
static int      hf_cflow_reserved       = -1;
static int      hf_cflow_extra_packets  = -1;

/*
 * cflow version specific info
 */
static int      hf_cflow_sequence       = -1;
static int      hf_cflow_engine_type    = -1;
static int      hf_cflow_engine_id      = -1;
static int      hf_cflow_source_id      = -1;

static int      hf_cflow_aggmethod      = -1;
static int      hf_cflow_aggversion     = -1;

/* Version 9 */

static int      hf_cflow_flowset_id                = -1;
static int      hf_cflow_flowset_length            = -1;
static int      hf_cflow_template_id               = -1;
static int      hf_cflow_template_field_count      = -1;
static int      hf_cflow_template_field_type       = -1;
static int      hf_cflow_template_field_length     = -1;
static int      hf_cflow_option_scope_length       = -1;
static int      hf_cflow_option_length             = -1;
static int      hf_cflow_template_scope_field_type = -1;

static int      hf_cflow_scope_system              = -1;
static int      hf_cflow_scope_interface           = -1;
static int      hf_cflow_scope_linecard            = -1;
static int      hf_cflow_scope_cache               = -1;
static int      hf_cflow_scope_template            = -1;

/* IPFIX */
static int      hf_cflow_template_ipfix_total_field_count           = -1;
static int      hf_cflow_template_ipfix_scope_field_count           = -1;
static int      hf_cflow_template_ipfix_pen_provided                = -1;
static int      hf_cflow_template_ipfix_field_type                  = -1;
static int      hf_cflow_template_ipfix_field_type_enterprise       = -1;
static int      hf_cflow_template_ipfix_field_pen                   = -1;

/* IPFIX / vendor */
static int      hf_cflow_template_plixer_field_type                 = -1;
static int      hf_cflow_template_ntop_field_type                   = -1;
static int      hf_cflow_template_ixia_field_type                   = -1;
static int      hf_cflow_template_netscaler_field_type              = -1;
static int      hf_cflow_template_barracuda_field_type              = -1;


/*
 * pdu storage
 */
static int      hf_cflow_srcaddr                                    = -1;
static int      hf_cflow_srcaddr_v6                                 = -1;
static int      hf_cflow_srcnet                                     = -1;
static int      hf_cflow_dstaddr                                    = -1;
static int      hf_cflow_dstaddr_v6                                 = -1;
static int      hf_cflow_dstnet                                     = -1;
static int      hf_cflow_nexthop                                    = -1;
static int      hf_cflow_nexthop_v6                                 = -1;
static int      hf_cflow_bgpnexthop                                 = -1;
static int      hf_cflow_bgpnexthop_v6                              = -1;
static int      hf_cflow_inputint                                   = -1;
static int      hf_cflow_outputint                                  = -1;
static int      hf_cflow_flows                                      = -1;
static int      hf_cflow_packets                                    = -1;
static int      hf_cflow_octets                                     = -1;
static int      hf_cflow_length_min                                 = -1;
static int      hf_cflow_length_max                                 = -1;
static int      hf_cflow_timedelta                                  = -1;
static int      hf_cflow_sys_init_time                              = -1;
static int      hf_cflow_timestart                                  = -1;
static int      hf_cflow_timeend                                    = -1;
static int      hf_cflow_srcport                                    = -1;
static int      hf_cflow_dstport                                    = -1;
static int      hf_cflow_prot                                       = -1;
static int      hf_cflow_tos                                        = -1;
static int      hf_cflow_marked_tos                                 = -1;
static int      hf_cflow_flags                                      = -1;
static int      hf_cflow_tcpflags                                   = -1;
static int      hf_cflow_tcpflags16                                 = -1;
static int      hf_cflow_tcpflags_fin                               = -1;
static int      hf_cflow_tcpflags_syn                               = -1;
static int      hf_cflow_tcpflags_rst                               = -1;
static int      hf_cflow_tcpflags_psh                               = -1;
static int      hf_cflow_tcpflags_ack                               = -1;
static int      hf_cflow_tcpflags_urg                               = -1;
static int      hf_cflow_tcpflags16_fin                             = -1;
static int      hf_cflow_tcpflags16_syn                             = -1;
static int      hf_cflow_tcpflags16_rst                             = -1;
static int      hf_cflow_tcpflags16_psh                             = -1;
static int      hf_cflow_tcpflags16_ack                             = -1;
static int      hf_cflow_tcpflags16_urg                             = -1;
static int      hf_cflow_tcpflags16_ece                             = -1;
static int      hf_cflow_tcpflags16_cwr                             = -1;
static int      hf_cflow_tcpflags16_ns                              = -1;
static int      hf_cflow_tcpflags_reserved                          = -1;
static int      hf_cflow_tcpflags16_reserved                        = -1;
static int      hf_cflow_tcpflags16_zero                            = -1;
static int      hf_cflow_dstas                                      = -1;
static int      hf_cflow_srcas                                      = -1;
static int      hf_cflow_dstmask                                    = -1;
static int      hf_cflow_dstmask_v6                                 = -1;
static int      hf_cflow_srcmask                                    = -1;
static int      hf_cflow_srcmask_v6                                 = -1;
static int      hf_cflow_routersc                                   = -1;
static int      hf_cflow_mulpackets                                 = -1;
static int      hf_cflow_muloctets                                  = -1;
static int      hf_cflow_octets_exp                                 = -1;
static int      hf_cflow_packets_exp                                = -1;
static int      hf_cflow_flows_exp                                  = -1;
static int      hf_cflow_ipv4_router_sc                             = -1;
static int      hf_cflow_srcprefix                                  = -1;
static int      hf_cflow_dstprefix                                  = -1;
static int      hf_cflow_flow_class                                 = -1;
static int      hf_cflow_ttl_minimum                                = -1;
static int      hf_cflow_ttl_maximum                                = -1;
static int      hf_cflow_frag_id                                    = -1;
static int      hf_cflow_ip_version                                 = -1;
static int      hf_cflow_icmp_type_code_ipv4                        = -1;
static int      hf_cflow_igmp_type                                  = -1;
static int      hf_cflow_sampling_interval                          = -1;
static int      hf_cflow_sampling_algorithm                         = -1;
static int      hf_cflow_flow_active_timeout                        = -1;
static int      hf_cflow_flow_inactive_timeout                      = -1;
static int      hf_cflow_mpls_top_label_type                        = -1;
static int      hf_cflow_mpls_pe_addr                               = -1;
static int      hf_cflow_sampler_id                                 = -1;
static int      hf_cflow_sampler_mode                               = -1;
static int      hf_cflow_sampler_random_interval                    = -1;
static int      hf_cflow_direction                                  = -1;
static int      hf_cflow_if_name                                    = -1;
static int      hf_cflow_if_descr                                   = -1;
static int      hf_cflow_sampler_name                               = -1;
static int      hf_cflow_forwarding_status                          = -1;
static int      hf_cflow_forwarding_status_unknown_code             = -1;
static int      hf_cflow_forwarding_status_forward_code             = -1;
static int      hf_cflow_forwarding_status_consume_code             = -1;
static int      hf_cflow_forwarding_status_drop_code                = -1;
static int      hf_cflow_nbar_appl_desc                             = -1;
static int      hf_cflow_nbar_appl_id                               = -1;
static int      hf_cflow_nbar_appl_name                             = -1;
static int      hf_cflow_peer_srcas                                 = -1;
static int      hf_cflow_peer_dstas                                 = -1;
static int      hf_cflow_flow_exporter                              = -1;
static int      hf_cflow_icmp_ipv4_type                             = -1;
static int      hf_cflow_icmp_ipv4_code                             = -1;
static int      hf_cflow_icmp_ipv6_type                             = -1;
static int      hf_cflow_icmp_ipv6_code                             = -1;
static int      hf_cflow_tcp_window_size                            = -1;
static int      hf_cflow_ipv4_total_length                          = -1;
static int      hf_cflow_ip_ttl                                     = -1;
static int      hf_cflow_mpls_payload_length                        = -1;
static int      hf_cflow_ip_dscp                                    = -1;
static int      hf_cflow_delta_octets_squared                       = -1;
static int      hf_cflow_total_octets_squared                       = -1;
static int      hf_cflow_udp_length                                 = -1;
static int      hf_cflow_is_multicast                               = -1;
static int      hf_cflow_ip_header_words                            = -1;
static int      hf_cflow_option_map                                 = -1;
static int      hf_cflow_section_header                             = -1;
static int      hf_cflow_section_payload                            = -1;
/* IPFIX (version 10) Information Elements */
static int      hf_cflow_post_octets                                = -1;
static int      hf_cflow_post_packets                               = -1;
static int      hf_cflow_ipv6_flowlabel                             = -1;
static int      hf_cflow_post_tos                                   = -1;
static int      hf_cflow_srcmac                                     = -1;
static int      hf_cflow_post_dstmac                                = -1;
static int      hf_cflow_vlanid                                     = -1;
static int      hf_cflow_post_vlanid                                = -1;
static int      hf_cflow_ipv6_exthdr                                = -1;
static int      hf_cflow_dstmac                                     = -1;
static int      hf_cflow_post_srcmac                                = -1;
static int      hf_cflow_permanent_packets                          = -1;
static int      hf_cflow_permanent_octets                           = -1;
static int      hf_cflow_fragment_offset                            = -1;
static int      hf_cflow_mpls_vpn_rd                                = -1;
static int      hf_cflow_mpls_top_label_prefix_length               = -1; /* ID:  91 */
static int      hf_cflow_src_traffic_index                          = -1; /* ID:  92 */
static int      hf_cflow_dst_traffic_index                          = -1; /* ID:  93 */
static int      hf_cflow_post_ip_diff_serv_code_point               = -1; /* ID:  98 */
static int      hf_cflow_multicast_replication_factor               = -1; /* ID:  99 */
static int      hf_cflow_classification_engine_id                   = -1; /* ID: 101 */
static int      hf_cflow_exporter_addr                              = -1;
static int      hf_cflow_exporter_addr_v6                           = -1;
static int      hf_cflow_drop_octets                                = -1;
static int      hf_cflow_drop_packets                               = -1;
static int      hf_cflow_drop_total_octets                          = -1;
static int      hf_cflow_drop_total_packets                         = -1;
static int      hf_cflow_flow_end_reason                            = -1;
static int      hf_cflow_common_properties_id                       = -1;
static int      hf_cflow_observation_point_id                       = -1;
static int      hf_cflow_mpls_pe_addr_v6                            = -1;
static int      hf_cflow_port_id                                    = -1;
static int      hf_cflow_mp_id                                      = -1;
static int      hf_cflow_wlan_channel_id                            = -1;
static int      hf_cflow_wlan_ssid                                  = -1;
static int      hf_cflow_flow_id                                    = -1;
static int      hf_cflow_od_id                                      = -1;
static int      hf_cflow_abstimestart                               = -1;
static int      hf_cflow_abstimeend                                 = -1;
static int      hf_cflow_dstnet_v6                                  = -1;
static int      hf_cflow_srcnet_v6                                  = -1;
static int      hf_cflow_ignore_packets                             = -1;
static int      hf_cflow_ignore_octets                              = -1;
static int      hf_cflow_notsent_flows                              = -1;
static int      hf_cflow_notsent_packets                            = -1;
static int      hf_cflow_notsent_octets                             = -1;
static int      hf_cflow_post_total_octets                          = -1;
static int      hf_cflow_post_total_packets                         = -1;
static int      hf_cflow_key                                        = -1;
static int      hf_cflow_post_total_mulpackets                      = -1;
static int      hf_cflow_post_total_muloctets                       = -1;
static int      hf_cflow_tcp_seq_num                                = -1;
static int      hf_cflow_tcp_ack_num                                = -1;
static int      hf_cflow_tcp_urg_ptr                                = -1;
static int      hf_cflow_tcp_header_length                          = -1;
static int      hf_cflow_ip_header_length                           = -1;
static int      hf_cflow_ipv6_payload_length                        = -1;
static int      hf_cflow_ipv6_next_hdr                              = -1;
static int      hf_cflow_ip_precedence                              = -1;
static int      hf_cflow_ip_fragment_flags                          = -1;
static int      hf_cflow_mpls_top_label_ttl                         = -1;
static int      hf_cflow_mpls_label_length                          = -1;
static int      hf_cflow_mpls_label_depth                           = -1;
static int      hf_cflow_mpls_top_label_exp                         = -1;
static int      hf_cflow_ip_payload_length                          = -1;
static int      hf_cflow_tcp_option_map                             = -1;
static int      hf_cflow_collector_addr                             = -1;
static int      hf_cflow_collector_addr_v6                          = -1;
static int      hf_cflow_export_interface                           = -1;
static int      hf_cflow_export_protocol_version                    = -1;
static int      hf_cflow_export_prot                                = -1;
static int      hf_cflow_collector_port                             = -1;
static int      hf_cflow_exporter_port                              = -1;
static int      hf_cflow_total_tcp_syn                              = -1;
static int      hf_cflow_total_tcp_fin                              = -1;
static int      hf_cflow_total_tcp_rst                              = -1;
static int      hf_cflow_total_tcp_psh                              = -1;
static int      hf_cflow_total_tcp_ack                              = -1;
static int      hf_cflow_total_tcp_urg                              = -1;
static int      hf_cflow_ip_total_length                            = -1;
static int      hf_cflow_post_natsource_ipv4_address                = -1;      /* ID: 225 */
static int      hf_cflow_post_natdestination_ipv4_address           = -1;      /* ID: 226 */
static int      hf_cflow_post_naptsource_transport_port             = -1;      /* ID: 227 */
static int      hf_cflow_post_naptdestination_transport_port        = -1;      /* ID: 228 */
static int      hf_cflow_nat_originating_address_realm              = -1;      /* ID: 229 */
static int      hf_cflow_nat_event                                  = -1;      /* ID: 230 */
static int      hf_cflow_initiator_octets                           = -1;      /* ID: 231 */
static int      hf_cflow_responder_octets                           = -1;      /* ID: 232 */
static int      hf_cflow_firewall_event                             = -1;      /* ID: 233 */
static int      hf_cflow_ingress_vrfid                              = -1;      /* ID: 234 */
static int      hf_cflow_egress_vrfid                               = -1;      /* ID: 235 */
static int      hf_cflow_vrfname                                    = -1;      /* ID: 236 */
static int      hf_cflow_post_mpls_top_label_exp                    = -1;      /* ID: 237 */
static int      hf_cflow_tcp_window_scale                           = -1;      /* ID: 238 */
static int      hf_cflow_biflow_direction                           = -1;
static int      hf_cflow_ethernet_header_length                     = -1;      /* ID: 240 */
static int      hf_cflow_ethernet_payload_length                    = -1;      /* ID: 241 */
static int      hf_cflow_ethernet_total_length                      = -1;      /* ID: 242 */
static int      hf_cflow_dot1q_vlan_id                              = -1;      /* ID: 243 */
static int      hf_cflow_dot1q_priority                             = -1;      /* ID: 244 */
static int      hf_cflow_dot1q_customer_vlan_id                     = -1;      /* ID: 245 */
static int      hf_cflow_dot1q_customer_priority                    = -1;      /* ID: 246 */
static int      hf_cflow_metro_evc_id                               = -1;      /* ID: 247 */
static int      hf_cflow_metro_evc_type                             = -1;      /* ID: 248 */
static int      hf_cflow_pseudo_wire_id                             = -1;      /* ID: 249 */
static int      hf_cflow_pseudo_wire_type                           = -1;      /* ID: 250 */
static int      hf_cflow_pseudo_wire_control_word                   = -1;      /* ID: 251 */
static int      hf_cflow_ingress_physical_interface                 = -1;      /* ID: 252 */
static int      hf_cflow_egress_physical_interface                  = -1;      /* ID: 253 */
static int      hf_cflow_post_dot1q_vlan_id                         = -1;      /* ID: 254 */
static int      hf_cflow_post_dot1q_customer_vlan_id                = -1;      /* ID: 255 */
static int      hf_cflow_ethernet_type                              = -1;      /* ID: 256 */
static int      hf_cflow_post_ip_precedence                         = -1;      /* ID: 257 */
static int      hf_cflow_collection_time_milliseconds               = -1;      /* ID: 258 */
static int      hf_cflow_export_sctp_stream_id                      = -1;      /* ID: 259 */
static int      hf_cflow_max_export_seconds                         = -1;      /* ID: 260 */
static int      hf_cflow_max_flow_end_seconds                       = -1;      /* ID: 261 */
static int      hf_cflow_message_md5_checksum                       = -1;      /* ID: 262 */
static int      hf_cflow_message_scope                              = -1;      /* ID: 263 */
static int      hf_cflow_min_export_seconds                         = -1;      /* ID: 264 */
static int      hf_cflow_min_flow_start_seconds                     = -1;      /* ID: 265 */
static int      hf_cflow_opaque_octets                              = -1;      /* ID: 266 */
static int      hf_cflow_session_scope                              = -1;      /* ID: 267 */
static int      hf_cflow_max_flow_end_microseconds                  = -1;      /* ID: 268 */
static int      hf_cflow_max_flow_end_milliseconds                  = -1;      /* ID: 269 */
static int      hf_cflow_max_flow_end_nanoseconds                   = -1;      /* ID: 270 */
static int      hf_cflow_min_flow_start_microseconds                = -1;      /* ID: 271 */
static int      hf_cflow_min_flow_start_milliseconds                = -1;      /* ID: 272 */
static int      hf_cflow_min_flow_start_nanoseconds                 = -1;      /* ID: 273 */
static int      hf_cflow_collector_certificate                      = -1;      /* ID: 274 */
static int      hf_cflow_exporter_certificate                       = -1;      /* ID: 275 */
static int      hf_cflow_data_records_reliability                   = -1;      /* ID: 276 */
static int      hf_cflow_observation_point_type                     = -1;      /* ID: 277 */
static int      hf_cflow_new_connection_delta_count                 = -1;      /* ID: 278 */
static int      hf_cflow_connection_sum_duration_seconds            = -1;      /* ID: 279 */
static int      hf_cflow_connection_transaction_id                  = -1;      /* ID: 280 */
static int      hf_cflow_post_nat_source_ipv6_address               = -1;      /* ID: 281 */
static int      hf_cflow_post_nat_destination_ipv6_address          = -1;      /* ID: 282 */
static int      hf_cflow_nat_pool_id                                = -1;      /* ID: 283 */
static int      hf_cflow_nat_pool_name                              = -1;      /* ID: 284 */
static int      hf_cflow_anonymization_flags                        = -1;      /* ID: 285 */
static int      hf_cflow_anonymization_technique                    = -1;      /* ID: 286 */
static int      hf_cflow_information_element_index                  = -1;      /* ID: 287 */
static int      hf_cflow_p2p_technology                             = -1;      /* ID: 288 */
static int      hf_cflow_tunnel_technology                          = -1;      /* ID: 289 */
static int      hf_cflow_encrypted_technology                       = -1;      /* ID: 290 */
static int      hf_cflow_bgp_validity_state                         = -1;      /* ID: 294 */
static int      hf_cflow_ipsec_spi                                  = -1;      /* ID: 295 */
static int      hf_cflow_gre_key                                    = -1;      /* ID: 296 */
static int      hf_cflow_nat_type                                   = -1;      /* ID: 297 */
static int      hf_cflow_initiator_packets                          = -1;      /* ID: 298 */
static int      hf_cflow_responder_packets                          = -1;      /* ID: 299 */
static int      hf_cflow_observation_domain_name                    = -1;      /* ID: 300 */
static int      hf_cflow_selection_sequence_id                      = -1;      /* ID: 301 */
static int      hf_cflow_selector_id                                = -1;      /* ID: 302 */
static int      hf_cflow_information_element_id                     = -1;      /* ID: 303 */
static int      hf_cflow_selector_algorithm                         = -1;      /* ID: 304 */
static int      hf_cflow_sampling_packet_interval                   = -1;      /* ID: 305 */
static int      hf_cflow_sampling_packet_space                      = -1;      /* ID: 306 */
static int      hf_cflow_sampling_time_interval                     = -1;      /* ID: 307 */
static int      hf_cflow_sampling_time_space                        = -1;      /* ID: 308 */
static int      hf_cflow_sampling_size                              = -1;      /* ID: 309 */
static int      hf_cflow_sampling_population                        = -1;      /* ID: 310 */
static int      hf_cflow_sampling_probability_float64               = -1;      /* ID: 311 */
static int      hf_cflow_sampling_probability_float32               = -1;      /* ID: 311 */
static int      hf_cflow_data_link_frame_size                       = -1;      /* ID: 312 */
static int      hf_cflow_data_link_frame_section                    = -1;      /* ID: 315 */
static int      hf_cflow_mpls_label_stack_section                   = -1;      /* ID: 316 */
static int      hf_cflow_mpls_payload_packet_section                = -1;      /* ID: 317 */
static int      hf_cflow_selector_id_total_pkts_observed            = -1;      /* ID: 318 */
static int      hf_cflow_selector_id_total_pkts_selected            = -1;      /* ID: 319 */
static int      hf_cflow_absolute_error_float32                     = -1;      /* ID: 320 */
static int      hf_cflow_absolute_error_float64                     = -1;      /* ID: 320 */
static int      hf_cflow_relative_error_float32                     = -1;      /* ID: 321 */
static int      hf_cflow_relative_error_float64                     = -1;      /* ID: 321 */
static int      hf_cflow_observation_time_seconds                   = -1;      /* ID: 322 */
static int      hf_cflow_observation_time_milliseconds              = -1;      /* ID: 323 */
static int      hf_cflow_observation_time_microseconds              = -1;      /* ID: 324 */
static int      hf_cflow_observation_time_nanoseconds               = -1;      /* ID: 325 */
static int      hf_cflow_digest_hash_value                          = -1;      /* ID: 326 */
static int      hf_cflow_hash_ippayload_offset                      = -1;      /* ID: 327 */
static int      hf_cflow_hash_ippayload_size                        = -1;      /* ID: 328 */
static int      hf_cflow_hash_output_range_min                      = -1;      /* ID: 329 */
static int      hf_cflow_hash_output_range_max                      = -1;      /* ID: 330 */
static int      hf_cflow_hash_selected_range_min                    = -1;      /* ID: 331 */
static int      hf_cflow_hash_selected_range_max                    = -1;      /* ID: 332 */
static int      hf_cflow_hash_digest_output                         = -1;      /* ID: 333 */
static int      hf_cflow_hash_initialiser_value                     = -1;      /* ID: 334 */
static int      hf_cflow_selector_name                              = -1;      /* ID: 335 */
static int      hf_cflow_upper_cilimit_float32                      = -1;      /* ID: 336 */
static int      hf_cflow_upper_cilimit_float64                      = -1;      /* ID: 336 */
static int      hf_cflow_lower_cilimit_float32                      = -1;      /* ID: 337 */
static int      hf_cflow_lower_cilimit_float64                      = -1;      /* ID: 337 */
static int      hf_cflow_confidence_level_float32                   = -1;      /* ID: 338 */
static int      hf_cflow_confidence_level_float64                   = -1;      /* ID: 338 */
static int      hf_cflow_information_element_data_type              = -1;      /* ID: 339 */
static int      hf_cflow_information_element_description            = -1;      /* ID: 340 */
static int      hf_cflow_information_element_name                   = -1;      /* ID: 341 */
static int      hf_cflow_information_element_range_begin            = -1;      /* ID: 342 */
static int      hf_cflow_information_element_range_end              = -1;      /* ID: 343 */
static int      hf_cflow_information_element_semantics              = -1;      /* ID: 344 */
static int      hf_cflow_information_element_units                  = -1;      /* ID: 345 */
static int      hf_cflow_private_enterprise_number                  = -1;      /* ID: 346 */

static int      hf_cflow_virtual_station_interface_id               = -1;      /* ID: 347 */
static int      hf_cflow_virtual_station_interface_name             = -1;      /* ID: 348 */
static int      hf_cflow_virtual_station_uuid                       = -1;      /* ID: 349 */
static int      hf_cflow_virtual_station_name                       = -1;      /* ID: 350 */
static int      hf_cflow_layer2_segment_id                          = -1;      /* ID: 351 */
static int      hf_cflow_layer2_octet_delta_count                   = -1;      /* ID: 352 */
static int      hf_cflow_layer2_octet_total_count                   = -1;      /* ID: 353 */
static int      hf_cflow_ingress_unicast_packet_total_count         = -1;      /* ID: 354 */
static int      hf_cflow_ingress_multicast_packet_total_count       = -1;      /* ID: 355 */
static int      hf_cflow_ingress_broadcast_packet_total_count       = -1;      /* ID: 356 */
static int      hf_cflow_egress_unicast_packet_total_count          = -1;      /* ID: 357 */
static int      hf_cflow_egress_broadcast_packet_total_count        = -1;      /* ID: 358 */
static int      hf_cflow_monitoring_interval_start_milliseconds     = -1;      /* ID: 359 */
static int      hf_cflow_monitoring_interval_end_milliseconds       = -1;      /* ID: 360 */
static int      hf_cflow_port_range_start                           = -1;      /* ID: 361 */
static int      hf_cflow_port_range_end                             = -1;      /* ID: 362 */
static int      hf_cflow_port_range_step_size                       = -1;      /* ID: 363 */
static int      hf_cflow_port_range_num_ports                       = -1;      /* ID: 364 */
static int      hf_cflow_sta_mac_address                            = -1;      /* ID: 365 */
static int      hf_cflow_sta_ipv4_address                           = -1;      /* ID: 366 */
static int      hf_cflow_wtp_mac_address                            = -1;      /* ID: 367 */
static int      hf_cflow_ingress_interface_type                     = -1;      /* ID: 368 */
static int      hf_cflow_egress_interface_type                      = -1;      /* ID: 369 */
static int      hf_cflow_rtp_sequence_number                        = -1;      /* ID: 370 */
static int      hf_cflow_user_name                                  = -1;      /* ID: 371 */
static int      hf_cflow_application_category_name                  = -1;      /* ID: 372 */
static int      hf_cflow_application_sub_category_name              = -1;      /* ID: 373 */
static int      hf_cflow_application_group_name                     = -1;      /* ID: 374 */
static int      hf_cflow_original_flows_present                     = -1;      /* ID: 375 */
static int      hf_cflow_original_flows_initiated                   = -1;      /* ID: 376 */
static int      hf_cflow_original_flows_completed                   = -1;      /* ID: 377 */
static int      hf_cflow_distinct_count_of_source_ip_address        = -1;      /* ID: 378 */
static int      hf_cflow_distinct_count_of_destinationip_address    = -1;      /* ID: 379 */
static int      hf_cflow_distinct_count_of_source_ipv4_address      = -1;      /* ID: 380 */
static int      hf_cflow_distinct_count_of_destination_ipv4_address = -1;      /* ID: 381 */
static int      hf_cflow_distinct_count_of_source_ipv6_address      = -1;      /* ID: 382 */
static int      hf_cflow_distinct_count_of_destination_ipv6_address = -1;      /* ID: 383 */
static int      hf_cflow_value_distribution_method                  = -1;      /* ID: 384 */
static int      hf_cflow_rfc3550_jitter_milliseconds                = -1;      /* ID: 385 */
static int      hf_cflow_rfc3550_jitter_microseconds                = -1;      /* ID: 386 */
static int      hf_cflow_rfc3550_jitter_nanoseconds                 = -1;      /* ID: 387 */
static int      hf_cflow_dot1q_dei                                  = -1;      /* ID: 388 */
static int      hf_cflow_dot1q_customer_dei                         = -1;      /* ID: 389 */
static int      hf_cflow_flow_selector_algorithm                    = -1;      /* ID: 390 */
static int      hf_cflow_flow_selected_octet_delta_count            = -1;      /* ID: 391 */
static int      hf_cflow_flow_selected_packet_delta_count           = -1;      /* ID: 392 */
static int      hf_cflow_flow_selected_flow_delta_count             = -1;      /* ID: 393 */
static int      hf_cflow_selectorid_total_flows_observed            = -1;      /* ID: 394 */
static int      hf_cflow_selectorid_total_flows_selected            = -1;      /* ID: 395 */
static int      hf_cflow_sampling_flow_interval                     = -1;      /* ID: 396 */
static int      hf_cflow_sampling_flow_spacing                      = -1;      /* ID: 397 */
static int      hf_cflow_flow_sampling_time_interval                = -1;      /* ID: 398 */
static int      hf_cflow_flow_sampling_time_spacing                 = -1;      /* ID: 399 */
static int      hf_cflow_hash_flow_domain                           = -1;      /* ID: 400 */
static int      hf_cflow_transport_octet_delta_count                = -1;      /* ID: 401 */
static int      hf_cflow_transport_packet_delta_count               = -1;      /* ID: 402 */
static int      hf_cflow_original_exporter_ipv4_address             = -1;      /* ID: 403 */
static int      hf_cflow_original_exporter_ipv6_address             = -1;      /* ID: 404 */
static int      hf_cflow_original_observation_domain_id             = -1;      /* ID: 405 */
static int      hf_cflow_intermediate_process_id                    = -1;      /* ID: 406 */
static int      hf_cflow_ignored_data_record_total_count            = -1;      /* ID: 407 */
static int      hf_cflow_data_link_frame_type                       = -1;      /* ID: 408 */
static int      hf_cflow_section_offset                             = -1;      /* ID: 409 */
static int      hf_cflow_section_exported_octets                    = -1;      /* ID: 410 */
static int      hf_cflow_dot1q_service_instance_tag                 = -1;      /* ID: 411 */
static int      hf_cflow_dot1q_service_instance_id                  = -1;      /* ID: 412 */
static int      hf_cflow_dot1q_service_instance_priority            = -1;      /* ID: 413 */
static int      hf_cflow_dot1q_customer_source_mac_address          = -1;      /* ID: 414 */
static int      hf_cflow_dot1q_customer_destination_mac_address     = -1;      /* ID: 415 */
static int      hf_cflow_post_layer2_octet_delta_count              = -1;      /* ID: 417 */
static int      hf_cflow_postm_cast_layer2_octet_delta_count        = -1;      /* ID: 418 */
static int      hf_cflow_post_layer2_octet_total_count              = -1;      /* ID: 420 */
static int      hf_cflow_postm_cast_layer2_octet_total_count        = -1;      /* ID: 421 */
static int      hf_cflow_minimum_layer2_total_length                = -1;      /* ID: 422 */
static int      hf_cflow_maximum_layer2_total_length                = -1;      /* ID: 423 */
static int      hf_cflow_dropped_layer2_octet_delta_count           = -1;      /* ID: 424 */
static int      hf_cflow_dropped_layer2_octet_total_count           = -1;      /* ID: 425 */
static int      hf_cflow_ignored_layer2_octet_total_count           = -1;      /* ID: 426 */
static int      hf_cflow_not_sent_layer2_octet_total_count          = -1;      /* ID: 427 */
static int      hf_cflow_layer2_octet_delta_sum_of_squares          = -1;      /* ID: 428 */
static int      hf_cflow_layer2_octet_total_sum_of_squares          = -1;      /* ID: 429 */
static int      hf_cflow_layer2_frame_delta_count                   = -1;      /* ID: 430 */
static int      hf_cflow_layer2_frame_total_count                   = -1;      /* ID: 431 */
static int      hf_cflow_pseudo_wire_destination_ipv4_address       = -1;      /* ID: 432 */
static int      hf_cflow_ignored_layer2_frame_total_count           = -1;      /* ID: 433 */

static int      hf_cflow_mpls_label                                 = -1;
static int      hf_cflow_mpls_exp                                   = -1;
static int      hf_cflow_mpls_bos                                   = -1;

static int      hf_cflow_cts_sgt_source_tag                         = -1;      /* ID: 34000 */
static int      hf_cflow_cts_sgt_destination_tag                    = -1;      /* ID: 34001 */
static int      hf_cflow_cts_sgt_source_name                        = -1;      /* ID: 34002 */
static int      hf_cflow_cts_sgt_destination_name                   = -1;      /* ID: 34003 */
static int      hf_cflow_packets_dropped                            = -1;      /* ID: 37000 */
static int      hf_cflow_byte_rate                                  = -1;      /* ID: 37003 */
static int      hf_cflow_application_media_bytes                    = -1;      /* ID: 37004 */
static int      hf_cflow_application_media_byte_rate                = -1;      /* ID: 37006 */
static int      hf_cflow_application_media_packets                  = -1;      /* ID: 37007 */
static int      hf_cflow_application_media_packet_rate              = -1;      /* ID: 37009 */
static int      hf_cflow_application_media_event                    = -1;      /* ID: 37011 */
static int      hf_cflow_monitor_event                              = -1;      /* ID: 37012 */
static int      hf_cflow_timestamp_interval                         = -1;      /* ID: 37013 */
static int      hf_cflow_transport_packets_expected                 = -1;      /* ID: 37014 */
static int      hf_cflow_transport_round_trip_time                  = -1;      /* ID: 37016 */
static int      hf_cflow_transport_round_trip_time_string           = -1;      /* ID: 37016 */
static int      hf_cflow_transport_event_packet_loss                = -1;      /* ID: 37017 */
static int      hf_cflow_transport_packets_lost                     = -1;      /* ID: 37019 */
static int      hf_cflow_transport_packets_lost_string              = -1;      /* ID: 37019 */
static int      hf_cflow_transport_packets_lost_rate                = -1;      /* ID: 37021 */
static int      hf_cflow_transport_packets_lost_rate_string         = -1;      /* ID: 37021 */
static int      hf_cflow_transport_rtp_ssrc                         = -1;      /* ID: 37022 */
static int      hf_cflow_transport_rtp_jitter_mean                  = -1;      /* ID: 37023 */
static int      hf_cflow_transport_rtp_jitter_mean_string           = -1;      /* ID: 37023 */
static int      hf_cflow_transport_rtp_jitter_min                   = -1;      /* ID: 37024 */
static int      hf_cflow_transport_rtp_jitter_min_string            = -1;      /* ID: 37024 */
static int      hf_cflow_transport_rtp_jitter_max                   = -1;      /* ID: 37025 */
static int      hf_cflow_transport_rtp_jitter_max_string            = -1;      /* ID: 37025 */

static int      hf_cflow_transport_rtp_payload_type                 = -1;      /* ID: 37041 */
static int      hf_cflow_transport_rtp_payload_type_string          = -1;      /* ID: 37041 */
static int      hf_cflow_transport_bytes_out_of_order               = -1;      /* ID: 37071 */
/* static int      hf_cflow_transport_packets_out_of_order          = -1; */      /* ID: 37074 */
static int      hf_cflow_transport_packets_out_of_order_string      = -1;      /* ID: 37074 */
static int      hf_cflow_transport_tcp_window_size_min              = -1;      /* ID: 37083 */
static int      hf_cflow_transport_tcp_window_size_min_string       = -1;      /* ID: 37083 */
static int      hf_cflow_transport_tcp_window_size_max              = -1;      /* ID: 37084  */
static int      hf_cflow_transport_tcp_window_size_max_string       = -1;      /* ID: 37084 */
static int      hf_cflow_transport_tcp_window_size_mean             = -1;      /* ID: 37085  */
static int      hf_cflow_transport_tcp_window_size_mean_string      = -1;      /* ID: 37085  */
static int      hf_cflow_transport_tcp_maximum_segment_size         = -1;      /* ID: 37086  */
static int      hf_cflow_transport_tcp_maximum_segment_size_string  = -1;      /* ID: 37086 */

/* Sequence analysis fields */
static int      hf_cflow_sequence_analysis_expected_sn            = -1;
static int      hf_cflow_sequence_analysis_previous_frame         = -1;

/* Ericsson SE NAT Logging */
static int      hf_cflow_nat_context_id         = -1;   /* ID: 24628 */
static int      hf_cflow_nat_context_name       = -1;   /* ID: 24629 */
static int      hf_cflow_nat_assign_time        = -1;   /* ID: 24630 */
static int      hf_cflow_nat_unassign_time      = -1;   /* ID: 24631 */
static int      hf_cflow_nat_int_addr           = -1;   /* ID: 24632 */
static int      hf_cflow_nat_ext_addr           = -1;   /* ID: 24633 */
static int      hf_cflow_nat_ext_port_first     = -1;   /* ID: 24634 */
static int      hf_cflow_nat_ext_port_last      = -1;   /* ID: 24635 */


/* Cisco ASA 5500 Series */
static int      hf_cflow_ingress_acl_id = -1; /* NF_F_INGRESS_ACL_ID (33000) */
static int      hf_cflow_egress_acl_id  = -1; /* NF_F_EGRESS_ACL_ID  (33001) */
static int      hf_cflow_fw_ext_event   = -1; /* NF_F_FW_EXT_EVENT   (33002) */
static int      hf_cflow_aaa_username   = -1; /* NF_F_USERNAME[_MAX] (40000) */

static int      hf_ipfix_enterprise_private_entry = -1;

/* pie = private information element */

static int      hf_pie_cace                       = -1;
static int      hf_pie_cace_local_ipv4_address   = -1;
static int      hf_pie_cace_remote_ipv4_address  = -1;
static int      hf_pie_cace_local_ipv6_address   = -1;
static int      hf_pie_cace_remote_ipv6_address  = -1;
static int      hf_pie_cace_local_port           = -1;
static int      hf_pie_cace_remote_port          = -1;
static int      hf_pie_cace_local_ipv4_id        = -1;
static int      hf_pie_cace_local_icmp_id        = -1;
static int      hf_pie_cace_local_uid            = -1;
static int      hf_pie_cace_local_pid            = -1;
static int      hf_pie_cace_local_username_len   = -1;
static int      hf_pie_cace_local_username       = -1;
static int      hf_pie_cace_local_cmd_len        = -1;
static int      hf_pie_cace_local_cmd            = -1;

static int      hf_pie_ntop                      = -1;
static int      hf_pie_ntop_fragmented           = -1;
static int      hf_pie_ntop_fingerprint          = -1;
static int      hf_pie_ntop_client_nw_delay_sec  = -1;
static int      hf_pie_ntop_client_nw_delay_usec = -1;
static int      hf_pie_ntop_server_nw_delay_sec  = -1;
static int      hf_pie_ntop_server_nw_delay_usec = -1;
static int      hf_pie_ntop_appl_latency_sec     = -1;
static int      hf_pie_ntop_icmp_flags           = -1;
static int      hf_pie_ntop_src_ip_country       = -1;
static int      hf_pie_ntop_src_ip_city          = -1;
static int      hf_pie_ntop_dst_ip_country       = -1;
static int      hf_pie_ntop_dst_ip_city          = -1;
static int      hf_pie_ntop_flow_proto_port      = -1;

static int      hf_pie_ntop_longest_flow_pkt         = -1;
static int      hf_pie_ntop_ooorder_in_pkts          = -1;
static int      hf_pie_ntop_ooorder_out_pkts         = -1;
static int      hf_pie_ntop_retransmitted_in_pkts    = -1;
static int      hf_pie_ntop_retransmitted_out_pkts   = -1;
static int      hf_pie_ntop_shortest_flow_pkt        = -1;
static int      hf_pie_ntop_tunnel_id                = -1;
static int      hf_pie_ntop_untunneled_ipv4_dst_addr = -1;
static int      hf_pie_ntop_untunneled_ipv4_src_addr = -1;
static int      hf_pie_ntop_untunneled_l4_dst_port   = -1;
static int      hf_pie_ntop_untunneled_l4_src_port   = -1;
static int      hf_pie_ntop_untunneled_protocol      = -1;

static int      hf_pie_ntop_dump_path            = -1;
static int      hf_pie_ntop_sip_call_id          = -1;
static int      hf_pie_ntop_sip_calling_party    = -1;
static int      hf_pie_ntop_sip_called_party     = -1;
static int      hf_pie_ntop_sip_rtp_codecs       = -1;
static int      hf_pie_ntop_sip_invite_time      = -1;
static int      hf_pie_ntop_sip_trying_time      = -1;
static int      hf_pie_ntop_sip_ringing_time     = -1;
static int      hf_pie_ntop_sip_ok_time          = -1;
static int      hf_pie_ntop_sip_bye_time         = -1;
static int      hf_pie_ntop_sip_rtp_src_ip       = -1;
static int      hf_pie_ntop_sip_rtp_src_port     = -1;
static int      hf_pie_ntop_sip_rtp_dst_ip       = -1;
static int      hf_pie_ntop_sip_rtp_dst_port     = -1;
static int      hf_pie_ntop_rtp_first_ssrc       = -1;
static int      hf_pie_ntop_rtp_first_ts         = -1;
static int      hf_pie_ntop_rtp_last_ssrc        = -1;
static int      hf_pie_ntop_rtp_last_ts          = -1;
static int      hf_pie_ntop_rtp_in_jitter        = -1;
static int      hf_pie_ntop_rtp_out_jitter       = -1;
static int      hf_pie_ntop_rtp_in_pkt_lost      = -1;
static int      hf_pie_ntop_rtp_out_pkt_lost     = -1;
static int      hf_pie_ntop_rtp_out_payload_type = -1;
static int      hf_pie_ntop_rtp_in_max_delta     = -1;
static int      hf_pie_ntop_rtp_out_max_delta    = -1;
static int      hf_pie_ntop_proc_id              = -1;
static int      hf_pie_ntop_proc_name            = -1;
static int      hf_pie_ntop_http_url             = -1;
static int      hf_pie_ntop_http_ret_code        = -1;
static int      hf_pie_ntop_smtp_mail_from       = -1;
static int      hf_pie_ntop_smtp_rcpt_to         = -1;

static int      hf_pie_ntop_mysql_server_version = -1;
static int      hf_pie_ntop_mysql_username       = -1;
static int      hf_pie_ntop_mysql_db             = -1;
static int      hf_pie_ntop_mysql_query          = -1;
static int      hf_pie_ntop_mysql_response       = -1;

static int      hf_pie_plixer                         = -1;
static int      hf_pie_plixer_client_ip_v4            = -1;
static int      hf_pie_plixer_client_hostname         = -1;     /* string */
static int      hf_pie_plixer_partner_name            = -1;     /* string */
static int      hf_pie_plixer_server_hostname         = -1;     /* string */
static int      hf_pie_plixer_server_ip_v4            = -1;
static int      hf_pie_plixer_recipient_address       = -1;     /* string */
static int      hf_pie_plixer_event_id                = -1;
static int      hf_pie_plixer_msgid                   = -1;     /* string */

static int      hf_pie_plixer_priority                = -1;
static int      hf_pie_plixer_recipient_report_status = -1;
static int      hf_pie_plixer_number_recipients       = -1;
static int      hf_pie_plixer_origination_time        = -1;
static int      hf_pie_plixer_encryption              = -1;     /* string */
static int      hf_pie_plixer_service_version         = -1;     /* string */
static int      hf_pie_plixer_linked_msgid            = -1;     /* string */
static int      hf_pie_plixer_message_subject         = -1;     /* string */
static int      hf_pie_plixer_sender_address          = -1;     /* string */
static int      hf_pie_plixer_date_time               = -1;

static int      hf_pie_ixia                             = -1;
static int      hf_pie_ixia_l7_application_id           = -1;
static int      hf_pie_ixia_l7_application_name         = -1;
static int      hf_pie_ixia_source_ip_country_code      = -1;
static int      hf_pie_ixia_source_ip_country_name      = -1;
static int      hf_pie_ixia_source_ip_region_code       = -1;
static int      hf_pie_ixia_source_ip_region_name       = -1;
static int      hf_pie_ixia_source_ip_city_name         = -1;
static int      hf_pie_ixia_source_ip_latitude          = -1;
static int      hf_pie_ixia_source_ip_longitude         = -1;
static int      hf_pie_ixia_destination_ip_country_code = -1;
static int      hf_pie_ixia_destination_ip_country_name = -1;
static int      hf_pie_ixia_destination_ip_region_code  = -1;
static int      hf_pie_ixia_destination_ip_region_name  = -1;
static int      hf_pie_ixia_destination_ip_city_name    = -1;
static int      hf_pie_ixia_destination_ip_latitude     = -1;
static int      hf_pie_ixia_destination_ip_longitude    = -1;
static int      hf_pie_ixia_os_device_id                = -1;
static int      hf_pie_ixia_os_device_name              = -1;
static int      hf_pie_ixia_browser_id                  = -1;
static int      hf_pie_ixia_browser_name                = -1;
static int      hf_pie_ixia_reverse_octet_delta_count   = -1;
static int      hf_pie_ixia_reverse_packet_delta_count  = -1;
static int      hf_pie_ixia_conn_encryption_type        = -1;
static int      hf_pie_ixia_encryption_cipher           = -1;
static int      hf_pie_ixia_encryption_keylen           = -1;
static int      hf_pie_ixia_imsi                        = -1;
static int      hf_pie_ixia_user_agent                  = -1;
static int      hf_pie_ixia_host_name                   = -1;
static int      hf_pie_ixia_uri                         = -1;
static int      hf_pie_ixia_dns_txt                     = -1;

static int      hf_pie_netscaler                                         = -1;
static int      hf_pie_netscaler_roundtriptime                           = -1;
static int      hf_pie_netscaler_transactionid                           = -1;
static int      hf_pie_netscaler_httprequrl                              = -1;
static int      hf_pie_netscaler_httpreqcookie                           = -1;
static int      hf_pie_netscaler_flowflags                               = -1;
static int      hf_pie_netscaler_connectionid                            = -1;
static int      hf_pie_netscaler_syslogpriority                          = -1;
static int      hf_pie_netscaler_syslogmessage                           = -1;
static int      hf_pie_netscaler_syslogtimestamp                         = -1;
static int      hf_pie_netscaler_httpreqreferer                          = -1;
static int      hf_pie_netscaler_httpreqmethod                           = -1;
static int      hf_pie_netscaler_httpreqhost                             = -1;
static int      hf_pie_netscaler_httprequseragent                        = -1;
static int      hf_pie_netscaler_httprspstatus                           = -1;
static int      hf_pie_netscaler_httprsplen                              = -1;
static int      hf_pie_netscaler_serverttfb                              = -1;
static int      hf_pie_netscaler_serverttlb                              = -1;
static int      hf_pie_netscaler_appnameincarnationnumber                = -1;
static int      hf_pie_netscaler_appnameappid                            = -1;
static int      hf_pie_netscaler_appname                                 = -1;
static int      hf_pie_netscaler_httpreqrcvfb                            = -1;
static int      hf_pie_netscaler_httpreqforwfb                           = -1;
static int      hf_pie_netscaler_httpresrcvfb                            = -1;
static int      hf_pie_netscaler_httpresforwfb                           = -1;
static int      hf_pie_netscaler_httpreqrcvlb                            = -1;
static int      hf_pie_netscaler_httpreqforwlb                           = -1;
static int      hf_pie_netscaler_mainpageid                              = -1;
static int      hf_pie_netscaler_mainpagecoreid                          = -1;
static int      hf_pie_netscaler_httpclientinteractionstarttime          = -1;
static int      hf_pie_netscaler_httpclientrenderendtime                 = -1;
static int      hf_pie_netscaler_httpclientrenderstarttime               = -1;
static int      hf_pie_netscaler_apptemplatename                         = -1;
static int      hf_pie_netscaler_httpclientinteractionendtime            = -1;
static int      hf_pie_netscaler_httpresrcvlb                            = -1;
static int      hf_pie_netscaler_httpresforwlb                           = -1;
static int      hf_pie_netscaler_appunitnameappid                        = -1;
static int      hf_pie_netscaler_dbloginflags                            = -1;
static int      hf_pie_netscaler_dbreqtype                               = -1;
static int      hf_pie_netscaler_dbprotocolname                          = -1;
static int      hf_pie_netscaler_dbusername                              = -1;
static int      hf_pie_netscaler_dbdatabasename                          = -1;
static int      hf_pie_netscaler_dbclthostname                           = -1;
static int      hf_pie_netscaler_dbreqstring                             = -1;
static int      hf_pie_netscaler_dbrespstatusstring                      = -1;
static int      hf_pie_netscaler_dbrespstatus                            = -1;
static int      hf_pie_netscaler_dbresplength                            = -1;
static int      hf_pie_netscaler_clientrtt                               = -1;
static int      hf_pie_netscaler_httpcontenttype                         = -1;
static int      hf_pie_netscaler_httpreqauthorization                    = -1;
static int      hf_pie_netscaler_httpreqvia                              = -1;
static int      hf_pie_netscaler_httpreslocation                         = -1;
static int      hf_pie_netscaler_httpressetcookie                        = -1;
static int      hf_pie_netscaler_httpressetcookie2                       = -1;
static int      hf_pie_netscaler_httpreqxforwardedfor                    = -1;
static int      hf_pie_netscaler_connectionchainid                       = -1;
static int      hf_pie_netscaler_connectionchainhopcount                 = -1;
static int      hf_pie_netscaler_icasessionguid                          = -1;
static int      hf_pie_netscaler_icaclientversion                        = -1;
static int      hf_pie_netscaler_icaclienttype                           = -1;
static int      hf_pie_netscaler_icaclientip                             = -1;
static int      hf_pie_netscaler_icaclienthostname                       = -1;
static int      hf_pie_netscaler_aaausername                             = -1;
static int      hf_pie_netscaler_icadomainname                           = -1;
static int      hf_pie_netscaler_icaclientlauncher                       = -1;
static int      hf_pie_netscaler_icasessionsetuptime                     = -1;
static int      hf_pie_netscaler_icaservername                           = -1;
static int      hf_pie_netscaler_icasessionreconnects                    = -1;
static int      hf_pie_netscaler_icartt                                  = -1;
static int      hf_pie_netscaler_icaclientsiderxbytes                    = -1;
static int      hf_pie_netscaler_icaclientsidetxbytes                    = -1;
static int      hf_pie_netscaler_icaclientsidepacketsretransmit          = -1;
static int      hf_pie_netscaler_icaserversidepacketsretransmit          = -1;
static int      hf_pie_netscaler_icaclientsidertt                        = -1;
static int      hf_pie_netscaler_icaserversidertt                        = -1;
static int      hf_pie_netscaler_icasessionupdatebeginsec                = -1;
static int      hf_pie_netscaler_icasessionupdateendsec                  = -1;
static int      hf_pie_netscaler_icachannelid1                           = -1;
static int      hf_pie_netscaler_icachannelid1bytes                      = -1;
static int      hf_pie_netscaler_icachannelid2                           = -1;
static int      hf_pie_netscaler_icachannelid2bytes                      = -1;
static int      hf_pie_netscaler_icachannelid3                           = -1;
static int      hf_pie_netscaler_icachannelid3bytes                      = -1;
static int      hf_pie_netscaler_icachannelid4                           = -1;
static int      hf_pie_netscaler_icachannelid4bytes                      = -1;
static int      hf_pie_netscaler_icachannelid5                           = -1;
static int      hf_pie_netscaler_icachannelid5bytes                      = -1;
static int      hf_pie_netscaler_icaconnectionpriority                   = -1;
static int      hf_pie_netscaler_applicationstartupduration              = -1;
static int      hf_pie_netscaler_icalaunchmechanism                      = -1;
static int      hf_pie_netscaler_icaapplicationname                      = -1;
static int      hf_pie_netscaler_applicationstartuptime                  = -1;
static int      hf_pie_netscaler_icaapplicationterminationtype           = -1;
static int      hf_pie_netscaler_icaapplicationterminationtime           = -1;
static int      hf_pie_netscaler_icasessionendtime                       = -1;
static int      hf_pie_netscaler_icaclientsidejitter                     = -1;
static int      hf_pie_netscaler_icaserversidejitter                     = -1;
static int      hf_pie_netscaler_icaappprocessid                         = -1;
static int      hf_pie_netscaler_icaappmodulepath                        = -1;
static int      hf_pie_netscaler_icadeviceserialno                       = -1;
static int      hf_pie_netscaler_msiclientcookie                         = -1;
static int      hf_pie_netscaler_icaflags                                = -1;
static int      hf_pie_netscaler_icausername                             = -1;
static int      hf_pie_netscaler_licensetype                             = -1;
static int      hf_pie_netscaler_maxlicensecount                         = -1;
static int      hf_pie_netscaler_currentlicenseconsumed                  = -1;
static int      hf_pie_netscaler_icanetworkupdatestarttime               = -1;
static int      hf_pie_netscaler_icanetworkupdateendtime                 = -1;
static int      hf_pie_netscaler_icaclientsidesrtt                       = -1;
static int      hf_pie_netscaler_icaserversidesrtt                       = -1;
static int      hf_pie_netscaler_icaclientsidedelay                      = -1;
static int      hf_pie_netscaler_icaserversidedelay                      = -1;
static int      hf_pie_netscaler_icahostdelay                            = -1;
static int      hf_pie_netscaler_icaclientsidewindowsize                 = -1;
static int      hf_pie_netscaler_icaserversidewindowsize                 = -1;
static int      hf_pie_netscaler_icaclientsidertocount                   = -1;
static int      hf_pie_netscaler_icaserversidertocount                   = -1;
static int      hf_pie_netscaler_ical7clientlatency                      = -1;
static int      hf_pie_netscaler_ical7serverlatency                      = -1;
static int      hf_pie_netscaler_httpdomainname                          = -1;
static int      hf_pie_netscaler_cacheredirclientconnectioncoreid        = -1;
static int      hf_pie_netscaler_cacheredirclientconnectiontransactionid = -1;


static int      hf_pie_barracuda                                         = -1;
static int      hf_pie_barracuda_timestamp                               = -1;
static int      hf_pie_barracuda_logop                                   = -1;
static int      hf_pie_barracuda_traffictype                             = -1;
static int      hf_pie_barracuda_fwrule                                  = -1;
static int      hf_pie_barracuda_servicename                             = -1;
static int      hf_pie_barracuda_reason                                  = -1;
static int      hf_pie_barracuda_reasontext                              = -1;
static int      hf_pie_barracuda_bindipv4address                         = -1;
static int      hf_pie_barracuda_bindtransportport                       = -1;
static int      hf_pie_barracuda_connipv4address                         = -1;
static int      hf_pie_barracuda_conntransportport                       = -1;
static int      hf_pie_barracuda_auditcounter                            = -1;

static int      hf_string_len_short = -1;
static int      hf_string_len_long  = -1;

static int      hf_template_frame = -1;

static expert_field ei_cflow_entries                                   = EI_INIT;
static expert_field ei_cflow_options                                   = EI_INIT;
static expert_field ei_cflow_flowset_length                            = EI_INIT;
static expert_field ei_cflow_scopes                                    = EI_INIT;
static expert_field ei_cflow_template_ipfix_scope_field_count_too_many = EI_INIT;
static expert_field ei_cflow_template_ipfix_scope_field_count          = EI_INIT;
static expert_field ei_cflow_no_flow_information                       = EI_INIT;
static expert_field ei_cflow_mpls_label_bad_length                     = EI_INIT;
static expert_field ei_cflow_flowsets_impossible                       = EI_INIT;
static expert_field ei_cflow_no_template_found                         = EI_INIT;
static expert_field ei_transport_bytes_out_of_order                    = EI_INIT;
static expert_field ei_unexpected_sequence_number                      = EI_INIT;

static const value_string special_mpls_top_label_type[] = {
    {0, "Unknown"},
    {1, "TE-MIDPT"},
    {2, "ATOM"},
    {3, "VPN"},
    {4, "BGP"},
    {5, "LDP"},
    {0, NULL }
};

static const int * tcp_flags[] = {
    &hf_cflow_tcpflags_reserved,
    &hf_cflow_tcpflags_urg,
    &hf_cflow_tcpflags_ack,
    &hf_cflow_tcpflags_psh,
    &hf_cflow_tcpflags_rst,
    &hf_cflow_tcpflags_syn,
    &hf_cflow_tcpflags_fin,
    NULL
};

static const int * tcp_flags16[] = {
    &hf_cflow_tcpflags16_zero,
    &hf_cflow_tcpflags16_reserved,
    &hf_cflow_tcpflags16_ns,
    &hf_cflow_tcpflags16_cwr,
    &hf_cflow_tcpflags16_ece,
    &hf_cflow_tcpflags16_urg,
    &hf_cflow_tcpflags16_ack,
    &hf_cflow_tcpflags16_psh,
    &hf_cflow_tcpflags16_rst,
    &hf_cflow_tcpflags16_syn,
    &hf_cflow_tcpflags16_fin,
    NULL
};

static proto_item *
proto_tree_add_mpls_label(proto_tree *pdutree, tvbuff_t *tvb, int offset, int length, int level)
{
    proto_tree *mpls_tree;
    proto_item *ti;
    if( length == 3) {
        guint8 b0 = tvb_get_guint8(tvb, offset);
        guint8 b1 = tvb_get_guint8(tvb, offset + 1);
        guint8 b2 = tvb_get_guint8(tvb, offset + 2);

        guint32  label = (b0<<12) + (b1<<4) + (b2>>4);
        guint8   exp   = (b2>>1) & 0x7;
        guint8   bos   =  b2     & 0x1;

        mpls_tree = proto_tree_add_subtree_format(pdutree, tvb, offset, length, ett_mpls_label, &ti,
                                                  "MPLS-Label%d: %u exp-bits: %u %s",
                                                  level, label, exp, bos ? "bottom-of-stack" : "");
        proto_tree_add_item(mpls_tree, hf_cflow_mpls_label, tvb, offset,   3, ENC_BIG_ENDIAN);
        proto_tree_add_item(mpls_tree, hf_cflow_mpls_exp,   tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mpls_tree, hf_cflow_mpls_bos,   tvb, offset+2, 1, ENC_NA);

    } else {
        ti = proto_tree_add_expert_format(pdutree, NULL, &ei_cflow_mpls_label_bad_length,
                                          tvb, offset, length,
                                          "MPLS-Label%d: bad length %d", level, length);
    }
    return ti;
}


static void
nbar_fmt_id(gchar *result, guint32 nbar_id)
{
    guint32 nbar_id_type = (nbar_id>>24)&0xFF;
    nbar_id &= 0xFFFFFF;

    g_snprintf(result, ITEM_LABEL_LENGTH,
               "NBAR Application ID: %d:%d (type:id)", nbar_id_type, nbar_id);
}


typedef struct _hdrinfo_t {
    guint8  vspec;
    guint32 src_id;            /* SourceID in NetFlow V9, Observation Domain ID in IPFIX */
    time_t  export_time_secs;  /* secs since epoch */
} hdrinfo_t;

typedef int     dissect_pdu_t(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                              hdrinfo_t *hdrinfo_p, guint32 *flows_seen);

static int      dissect_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                            hdrinfo_t *hdrinfo_p, guint32 *flows_seen);
static int      dissect_v8_aggpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree,
                                  int offset, hdrinfo_t *hdrinfo_p, guint32 *flows_seen);
static int      dissect_v8_flowpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree,
                                   int offset, hdrinfo_t *hdrinfo_p, guint32 *flows_seen);
static int      dissect_v9_v10_flowset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree,
                                   int offset, hdrinfo_t *hdrinfo_p, guint32 *flows_seen);
static int      dissect_v9_v10_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree,
                                int offset, guint16 id, guint length, hdrinfo_t *hdrinfo_p,
                                guint32 *flows_seen);
static guint    dissect_v9_v10_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree,
                               int offset, v9_v10_tmplt_t *tmplt_p, hdrinfo_t *hdrinfo_p,
                               guint32 *flows_seen);
static guint    dissect_v9_pdu_scope(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree,
                               int offset, v9_v10_tmplt_t *tmplt_p);
static guint    dissect_v9_v10_pdu_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree,
                                        int offset, v9_v10_tmplt_t *tmplt_p, hdrinfo_t *hdrinfo_p,
                                        v9_v10_tmplt_fields_type_t fields_type);
static int      dissect_v9_v10_options_template(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree,
                                                int offset, int len, hdrinfo_t *hdrinfo_p, guint16 flowset_id);
static int      dissect_v9_v10_data_template(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree,
                                    int offset, int len, hdrinfo_t *hdrinfo_p, guint16 flowset_id);

static const gchar *getprefix(const guint32 *address, int prefix);

static int      flow_process_ints(proto_tree *pdutree, tvbuff_t *tvb,
                                  int offset);
static int      flow_process_ports(proto_tree *pdutree, tvbuff_t *tvb,
                                   int offset);
static int      flow_process_timeperiod(proto_tree *pdutree, tvbuff_t *tvb,
                                        int offset);
static int      flow_process_aspair(proto_tree *pdutree, tvbuff_t *tvb,
                                    int offset);
static int      flow_process_sizecount(proto_tree *pdutree, tvbuff_t *tvb,
                                       int offset);

static v9_v10_tmplt_t *v9_v10_tmplt_build_key(v9_v10_tmplt_t *tmplt_p, packet_info *pinfo, guint32 src_id, guint16 tmplt_id);


static int
flow_process_textfield(proto_tree *pdutree, tvbuff_t *tvb, int offset, int bytes, int hf)
{
    proto_tree_add_item(pdutree, hf, tvb, offset, bytes, ENC_NA);
    offset += bytes;

    return offset;
}


static int
pen_to_type_hf_list(guint32 pen) {
    switch (pen) {
    case VENDOR_PLIXER:
        return TF_PLIXER;
    case VENDOR_NTOP:
        return TF_NTOP;
    case VENDOR_IXIA:
        return TF_IXIA;
    case VENDOR_NETSCALER:
        return TF_NETSCALER;
    case VENDOR_BARRACUDA:
        return TF_BARRACUDA;
    default:
        return TF_NO_VENDOR_INFO;
    }
}


/****************************************/
/* Sequence analysis                    */
/****************************************/

/* Observation domain -> domain state.  For now, just looking up by observation domain ID.
   TODO: consider also including transport info in key?  May be better to store separate
   map for each template/set ID inside the domain state? */

typedef struct netflow_domain_state_t {
    gboolean sequence_number_set;
    guint32 current_sequence_number;
    guint32 current_frame_number;
} netflow_domain_state_t;

static GHashTable *netflow_sequence_analysis_domain_hash = NULL;

/* Frame number -> domain state */
static GHashTable *netflow_sequence_analysis_result_hash = NULL;

/* On first pass, check ongoing sequence of observation domain, and only store a result
   if the sequence number is not as expected */
static void store_sequence_analysis_info(guint32 domain_id, guint32 seqnum, unsigned int version, guint32 new_flows,
                                         packet_info *pinfo)
{
    /* Find current domain info */
    netflow_domain_state_t *domain_state = (netflow_domain_state_t *)g_hash_table_lookup(netflow_sequence_analysis_domain_hash,
                                                                                         GUINT_TO_POINTER(domain_id));
    if (domain_state == NULL) {
        /* Give up if we haven't seen a template for this domain id yet */
        return;
    }

    /* Store result if not expected sequence.
       SequenceNumber represents SN of first flow in current packet, i.e. flows/data-records for previous
       frame have now been added (apart from V9, which just counts netflow frames). */
    if (domain_state->sequence_number_set &&
        (seqnum != domain_state->current_sequence_number)) {

        /* Allocate state to remember - a deep copy of current domain */
        netflow_domain_state_t *result_state = wmem_new0(wmem_file_scope(), netflow_domain_state_t);
        *result_state = *domain_state;

        /* Add into result table for current frame number */
        g_hash_table_insert(netflow_sequence_analysis_result_hash, GUINT_TO_POINTER(pinfo->num), result_state);
    }

    /* Update domain info for the next frame to consult.
       Add flows(data records) for all protocol versions except for 9, which just counts exported frames */
    domain_state->current_sequence_number = seqnum + ((version == 9) ? 1 : new_flows);
    domain_state->sequence_number_set = TRUE;
    domain_state->current_frame_number = pinfo->num;
}

/* Check for result stored indicating that sequence number wasn't as expected, and show in tree */
static void show_sequence_analysis_info(guint32 domain_id, guint32 seqnum,
                                        packet_info *pinfo, tvbuff_t *tvb,
                                        proto_item *flow_sequence_ti, proto_tree *tree)
{
    /* Look for info stored for this frame */
    netflow_domain_state_t *state = (netflow_domain_state_t *)g_hash_table_lookup(netflow_sequence_analysis_result_hash,
                                                                                  GUINT_TO_POINTER(pinfo->num));
    if (state != NULL) {
        proto_item *ti;

        /* Expected sequence number, i.e. what we stored in state when checking previous frame */
        ti = proto_tree_add_uint(tree, hf_cflow_sequence_analysis_expected_sn, tvb,
                                 0, 0, state->current_sequence_number);
        PROTO_ITEM_SET_GENERATED(ti);
        expert_add_info_format(pinfo, flow_sequence_ti, &ei_unexpected_sequence_number,
                               "Unexpected flow sequence for domain ID %u (expected %u, got %u)",
                               domain_id, state->current_sequence_number, seqnum);

        /* Avoid needing to open item to see what expected sequence number was... */
        proto_item_append_text(flow_sequence_ti, " (expected %u)", state->current_sequence_number);

        /* Previous frame for this observation domain ID */
        ti = proto_tree_add_uint(tree, hf_cflow_sequence_analysis_previous_frame, tvb,
                                 0, 0, state->current_frame_number);
        PROTO_ITEM_SET_GENERATED(ti);
    }
}

/* Try to look up the transport name given the pen_type, ip_protocol and port_number.
   If found, append to port number item */
static void netflow_add_transport_info(guint64 pen_type, guint8 ip_protocol,
                                       guint16 port_number, proto_item *ti)
{
    const char *port_str = "";

    /* UDP */
    if ((ip_protocol == IP_PROTO_UDP) || (pen_type == 180) || (pen_type == 181)) {
        port_str = udp_port_to_display(wmem_packet_scope(), port_number);
    }
    /* TCP */
    else if ((ip_protocol == IP_PROTO_TCP) || (pen_type == 182) || (pen_type == 183)) {
        port_str = tcp_port_to_display(wmem_packet_scope(), port_number);
    }
    /* SCTP */
    else if (ip_protocol == IP_PROTO_SCTP) {
        port_str = sctp_port_to_display(wmem_packet_scope(), port_number);
    }
    else {
        /* Didn't match any of these transports, so do nothing */
        return;
    }

    proto_item_append_text(ti, " (%s)", port_str);
}


/* Main dissector function */
static int
dissect_netflow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree     *netflow_tree = NULL;
    proto_tree     *ti;
    proto_item     *timeitem;
    proto_tree     *timetree, *pdutree;
    unsigned int    pduret, ver, pdus, x;
    hdrinfo_t       hdrinfo;
    guint32         flow_sequence = 0; /* TODO: could be part of hdrinfo struct? */
    proto_item      *flow_sequence_ti = NULL;
    gint            flow_len = -1;
    guint           available, pdusize, offset = 0;
    nstime_t        ts;
    dissect_pdu_t  *pduptr;
    guint32         flows_seen = 0;

    ipfix_debug("dissect_netflow: start");

    ver = tvb_get_ntohs(tvb, offset);

    ipfix_debug("dissect_netflow: found version %d", ver);

    switch (ver) {
    case 1:
        pdusize = V1PDU_SIZE;
        pduptr = &dissect_pdu;
        break;
    case 5:
        pdusize = V5PDU_SIZE;
        pduptr = &dissect_pdu;
        break;
    case 7:
        pdusize = V7PDU_SIZE;
        pduptr = &dissect_pdu;
        break;
    case 8:
        pdusize = -1;   /* deferred */
        pduptr = &dissect_v8_aggpdu;
        break;
    case 9:
    case 10: /* IPFIX */
        pdusize = -1;   /* deferred */
        pduptr = &dissect_v9_v10_flowset;
        break;
    default:
        /*  This does not appear to be a valid netflow packet;
         *  return 0 to let another dissector have a chance at
         *  dissecting it.
         */
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CFLOW");
    col_clear(pinfo->cinfo, COL_INFO);
    ipfix_debug("dissect_netflow: column cleared");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_netflow, tvb, offset, -1, ENC_NA);
        netflow_tree = proto_item_add_subtree(ti, ett_netflow);
    }
    ipfix_debug("dissect_netflow: tree added");

    hdrinfo.vspec = ver;
    hdrinfo.src_id = 0;

    if (tree)
        proto_tree_add_uint(netflow_tree, hf_cflow_version, tvb, offset, 2, ver);
    offset += 2;

    pdus = tvb_get_ntohs(tvb, offset);
    if(ver == 10) {
        proto_tree_add_uint(netflow_tree, hf_cflow_len, tvb, offset, 2, pdus);
        flow_len = pdus;
    } else {
        proto_tree_add_uint(netflow_tree, hf_cflow_count, tvb, offset, 2, pdus);
        flow_len = -1;
    }
    offset += 2;

    /*
     * set something interesting in the display now that we have info
     */
    if (ver == 9) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                        "total: %u (v%u) record%s", pdus, ver,
                        plurality(pdus, "", "s"));
    } else if (ver == 10) {
        gint remaining = tvb_reported_length_remaining(tvb, offset) + 4;

        if(remaining == flow_len)
            col_add_fstr(pinfo->cinfo, COL_INFO, "IPFIX flow (%4d bytes)",
                         flow_len);
        else
            col_add_fstr(pinfo->cinfo, COL_INFO,
                            "IPFIX partial flow (%u/%u bytes)",
                            remaining, flow_len);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                        "total: %u (v%u) flow%s", pdus, ver,
                        plurality(pdus, "", "s"));
    }

    /*
     * The rest is only interesting if we're displaying/searching the
     * packet or if V9/V10 so we need to keep going to find any templates
     */
    if ( (ver != 9) && (ver != 10) && !tree )
        return tvb_reported_length(tvb);

    if(ver != 10) {
        guint32 sysuptime = tvb_get_ntohl(tvb, offset);
        nstime_t nsuptime;

        nsuptime.secs = sysuptime / 1000;
        nsuptime.nsecs = (sysuptime % 1000) * 1000000;
        proto_tree_add_time(netflow_tree, hf_cflow_sysuptime, tvb,
                            offset, 4, &nsuptime);
        offset += 4;
    }

    ts.secs = tvb_get_ntohl(tvb, offset);
    hdrinfo.export_time_secs = ts.secs;

    if ((ver != 9) && (ver != 10)) {
        ts.nsecs = tvb_get_ntohl(tvb, offset + 4);
        timeitem = proto_tree_add_time(netflow_tree,
                                       hf_cflow_timestamp, tvb, offset,
                                       8, &ts);
    } else {
        ts.nsecs = 0;
        timeitem = proto_tree_add_time(netflow_tree,
                                       hf_cflow_timestamp, tvb, offset,
                                       4, &ts);
    }

    timetree = proto_item_add_subtree(timeitem, ett_unixtime);

    proto_tree_add_item(timetree,
                        (ver == 10) ? hf_cflow_exporttime : hf_cflow_unix_secs,
                        tvb, offset, 4, ENC_BIG_ENDIAN);

    offset += 4;

    if ((ver != 9) && (ver != 10)) {
        proto_tree_add_item(timetree, hf_cflow_unix_nsecs, tvb,
                            offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /*
     * version specific header
     */
    if (ver == 5 || ver == 7 || ver == 8 || ver == 9 || ver == 10) {
        flow_sequence = tvb_get_ntohl(tvb, offset);
        flow_sequence_ti = proto_tree_add_item(netflow_tree, hf_cflow_sequence,
                                               tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    if (ver == 5 || ver == 8) {
        proto_tree_add_item(netflow_tree, hf_cflow_engine_type,
                            tvb, offset++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(netflow_tree, hf_cflow_engine_id,
                            tvb, offset++, 1, ENC_BIG_ENDIAN);
    } else if ((ver == 9) || (ver == 10)) {
        proto_tree_add_item(netflow_tree,
                            (ver == 9) ? hf_cflow_source_id : hf_cflow_od_id,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        hdrinfo.src_id = tvb_get_ntohl(tvb, offset);
        col_append_fstr(pinfo->cinfo, COL_INFO, " Obs-Domain-ID=%5u",
                        hdrinfo.src_id);
        offset += 4;
    }
    if (ver == 8) {
        hdrinfo.vspec = tvb_get_guint8(tvb, offset);
        switch (hdrinfo.vspec) {
        case V8PDU_AS_METHOD:
            pdusize = V8PDU_AS_SIZE;
            break;
        case V8PDU_PROTO_METHOD:
            pdusize = V8PDU_PROTO_SIZE;
            break;
        case V8PDU_SPREFIX_METHOD:
            pdusize = V8PDU_SPREFIX_SIZE;
            break;
        case V8PDU_DPREFIX_METHOD:
            pdusize = V8PDU_DPREFIX_SIZE;
            break;
        case V8PDU_MATRIX_METHOD:
            pdusize = V8PDU_MATRIX_SIZE;
            break;
        case V8PDU_DESTONLY_METHOD:
            pdusize = V8PDU_DESTONLY_SIZE;
            pduptr = &dissect_v8_flowpdu;
            break;
        case V8PDU_SRCDEST_METHOD:
            pdusize = V8PDU_SRCDEST_SIZE;
            pduptr = &dissect_v8_flowpdu;
            break;
        case V8PDU_FULL_METHOD:
            pdusize = V8PDU_FULL_SIZE;
            pduptr = &dissect_v8_flowpdu;
            break;
        case V8PDU_TOSAS_METHOD:
            pdusize = V8PDU_TOSAS_SIZE;
            break;
        case V8PDU_TOSPROTOPORT_METHOD:
            pdusize = V8PDU_TOSPROTOPORT_SIZE;
            break;
        case V8PDU_TOSSRCPREFIX_METHOD:
            pdusize = V8PDU_TOSSRCPREFIX_SIZE;
            break;
        case V8PDU_TOSDSTPREFIX_METHOD:
            pdusize = V8PDU_TOSDSTPREFIX_SIZE;
            break;
        case V8PDU_TOSMATRIX_METHOD:
            pdusize = V8PDU_TOSMATRIX_SIZE;
            break;
        case V8PDU_PREPORTPROTOCOL_METHOD:
            pdusize = V8PDU_PREPORTPROTOCOL_SIZE;
            break;
        default:
            pdusize = -1;
            hdrinfo.vspec = 0;
            break;
        }
        proto_tree_add_uint(netflow_tree, hf_cflow_aggmethod,
                            tvb, offset++, 1, hdrinfo.vspec);
        proto_tree_add_item(netflow_tree, hf_cflow_aggversion,
                            tvb, offset++, 1, ENC_BIG_ENDIAN);
    }
    if (ver == 7 || ver == 8)
        offset = flow_process_textfield(netflow_tree, tvb, offset, 4, hf_cflow_reserved);
    else if (ver == 5) {
        proto_tree_add_item(netflow_tree, hf_cflow_samplingmode,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(netflow_tree, hf_cflow_samplerate,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    if (pdus == 0) { /* no payload to decode - in theory */
        /* This is absurd, but does happen in practice.  */
        proto_tree_add_expert_format(netflow_tree, NULL, &ei_cflow_flowsets_impossible,
                                     tvb, offset, tvb_reported_length_remaining(tvb, offset),
                                     "FlowSets impossible - PDU Count is %d", pdus);
        return tvb_reported_length(tvb);
    }
    /*
     * everything below here should be payload
     */
    available = tvb_reported_length_remaining(tvb, offset);
    for (x = 1; ((ver != 10) && (x < pdus + 1)) || ((ver == 10) && ((available - pdusize) > 0)); x++) {
        /*
         * make sure we have a pdu's worth of data
         */
        available = tvb_reported_length_remaining(tvb, offset);
        if(((ver == 9) || (ver == 10)) && available >= 4) {
            /* pdusize can be different for each v9/v10 flowset */
            pdusize = tvb_get_ntohs(tvb, offset + 2);
        }

        if (available < pdusize)
            break;

        if ((ver == 9) || (ver == 10)) {
            pdutree = proto_tree_add_subtree_format(netflow_tree, tvb, offset, pdusize, ett_flow, NULL,
                                                    (ver == 9) ? "FlowSet %u" : "Set %u", x);
        } else {
            pdutree = proto_tree_add_subtree_format(netflow_tree, tvb, offset, pdusize, ett_flow, NULL,
                                                    "pdu %u/%u", x, pdus);
        }

        /* Call callback function depending upon protocol version/spec */
        pduret = pduptr(tvb, pinfo, pdutree, offset, &hdrinfo, &flows_seen);

        if (pduret < pdusize) pduret = pdusize; /* padding */

        /*
         * if we came up short, stop processing
         */
        if ((pduret == pdusize) && (pduret != 0))
            offset += pduret;
        else
            break;
    }

    /* Can only check sequence analysis once have seen how many flows were reported across
       all data sets (flows are not dissected if no template for set is present).
       N.B. will currently only work for v9 and v10 as earlier versions don't fill in src_id from
       observation domain id. */
    if ((ver == 5) || (ver == 7) || (ver == 8)  || (ver == 9) || (ver == 10)) {
        /* On first pass check sequence analysis */
        if (!pinfo->fd->flags.visited) {
            if (ver != 10) {
                flows_seen = pdus;  /* i.e. use value from header rather than counted value */
            }
            store_sequence_analysis_info(hdrinfo.src_id, flow_sequence, ver, flows_seen, pinfo);
        }
        /* Show any stored sequence analysis results */
        show_sequence_analysis_info(hdrinfo.src_id, flow_sequence, pinfo, tvb, flow_sequence_ti, netflow_tree);
    }

    return tvb_reported_length(tvb);
}

/*
 * flow_process_* == common groups of fields, probably could be inline
 */

static int
flow_process_ints(proto_tree *pdutree, tvbuff_t *tvb, int offset)
{
    proto_tree_add_item(pdutree, hf_cflow_inputint, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(pdutree, hf_cflow_outputint, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static int
flow_process_ports(proto_tree *pdutree, tvbuff_t *tvb, int offset)
{
    proto_tree_add_item(pdutree, hf_cflow_srcport, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(pdutree, hf_cflow_dstport, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static int
flow_process_timeperiod(proto_tree *pdutree, tvbuff_t *tvb, int offset)
{
    nstime_t    ts_start, ts_end;
    int         offset_s, offset_e;
    nstime_t    ts_delta;
    guint32     msec_start, msec_end;
    guint32     msec_delta;
    proto_tree *timetree;
    proto_item *timeitem;


    msec_start = tvb_get_ntohl(tvb, offset);
    ts_start.secs = msec_start / 1000;
    ts_start.nsecs = (msec_start % 1000) * 1000000;
    offset_s = offset;
    offset += 4;

    msec_end = tvb_get_ntohl(tvb, offset);
    ts_end.secs = msec_end / 1000;
    ts_end.nsecs = (msec_end % 1000) * 1000000;
    offset_e = offset;
    offset += 4;

    msec_delta = msec_end - msec_start;
    ts_delta.secs = msec_delta / 1000;
    ts_delta.nsecs = (msec_delta % 1000) * 1000000;


    timeitem = proto_tree_add_time(pdutree, hf_cflow_timedelta, tvb,
                                   offset_s, 8, &ts_delta);
    PROTO_ITEM_SET_GENERATED(timeitem);
    timetree = proto_item_add_subtree(timeitem, ett_flowtime);

    proto_tree_add_time(timetree, hf_cflow_timestart, tvb, offset_s, 4,
                        &ts_start);
    proto_tree_add_time(timetree, hf_cflow_timeend, tvb, offset_e, 4,
                        &ts_end);

    return offset;
}


static int
flow_process_aspair(proto_tree *pdutree, tvbuff_t *tvb, int offset)
{
    proto_tree_add_item(pdutree, hf_cflow_srcas, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(pdutree, hf_cflow_dstas, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static int
flow_process_sizecount(proto_tree *pdutree, tvbuff_t *tvb, int offset)
{
    proto_tree_add_item(pdutree, hf_cflow_packets, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(pdutree, hf_cflow_octets, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_v8_flowpdu(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *pdutree, int offset,
                   hdrinfo_t *hdrinfo_p, guint32 *flows_seen _U_)
{
    int      startoffset = offset;
    guint8   verspec;

    proto_tree_add_item(pdutree, hf_cflow_dstaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    verspec = hdrinfo_p->vspec;

    if (verspec != V8PDU_DESTONLY_METHOD) {
        proto_tree_add_item(pdutree, hf_cflow_srcaddr, tvb, offset, 4,
                            ENC_BIG_ENDIAN);
        offset += 4;
    }
    if (verspec == V8PDU_FULL_METHOD) {
        proto_tree_add_item(pdutree, hf_cflow_dstport, tvb, offset, 2,
                            ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(pdutree, hf_cflow_srcport, tvb, offset, 2,
                            ENC_BIG_ENDIAN);
        offset += 2;
    }

    offset = flow_process_sizecount(pdutree, tvb, offset);
    offset = flow_process_timeperiod(pdutree, tvb, offset);

    proto_tree_add_item(pdutree, hf_cflow_outputint, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    offset += 2;

    if (verspec != V8PDU_DESTONLY_METHOD) {
        proto_tree_add_item(pdutree, hf_cflow_inputint, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    proto_tree_add_item(pdutree, hf_cflow_tos, tvb, offset++, 1, ENC_BIG_ENDIAN);
    if (verspec == V8PDU_FULL_METHOD)
        proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1, ENC_BIG_ENDIAN);
    offset = flow_process_textfield(pdutree, tvb, offset, 1, hf_cflow_marked_tos);

    if (verspec == V8PDU_SRCDEST_METHOD)
        offset = flow_process_textfield(pdutree, tvb, offset, 2, hf_cflow_reserved);
    else if (verspec == V8PDU_FULL_METHOD)
        offset = flow_process_textfield(pdutree, tvb, offset, 1, hf_cflow_padding);

    offset = flow_process_textfield(pdutree, tvb, offset, 4, hf_cflow_extra_packets);

    proto_tree_add_item(pdutree, hf_cflow_routersc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return (offset - startoffset);
}

/*
 * dissect a version 8 pdu, returning the length of the pdu processed
 */

static int
dissect_v8_aggpdu(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *pdutree, int offset,
                  hdrinfo_t *hdrinfo_p, guint32 *flows_seen _U_)
{
    int      startoffset = offset;
    guint8   verspec;
    int      local_cflow_as;   /* hf_cflow_srcas     || hf_cflow_dstas    */
    int      local_cflow_net;  /* hf_cflow_srcnet    || hf_cflow_dstnet   */
    int      local_cflow_int;  /* hf_cflow_outputint || hf_cflow_inputint */
    int      local_cflow_mask; /* hf_cflow_srcmask   || hf_cflow_dstmask  */

    proto_tree_add_item(pdutree, hf_cflow_flows, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = flow_process_sizecount(pdutree, tvb, offset);
    offset = flow_process_timeperiod(pdutree, tvb, offset);

    verspec = hdrinfo_p->vspec;

    switch (verspec) {

    case V8PDU_AS_METHOD:
    case V8PDU_TOSAS_METHOD:
        offset = flow_process_aspair(pdutree, tvb, offset);

        if (verspec == V8PDU_TOSAS_METHOD) {
            proto_tree_add_item(pdutree, hf_cflow_tos, tvb,
                                offset++, 1, ENC_BIG_ENDIAN);
            offset = flow_process_textfield(pdutree, tvb, offset, 1, hf_cflow_padding);
            offset = flow_process_textfield(pdutree, tvb, offset, 2, hf_cflow_reserved);
        }
        /* ACF - Seen in the wild and documented here...
           http://www.caida.org/tools/measurement/cflowd/configuration/configuration-9.html#ss9.1
        */
        offset = flow_process_ints(pdutree, tvb, offset);
        break;

    case V8PDU_PROTO_METHOD:
    case V8PDU_TOSPROTOPORT_METHOD:
        proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1, ENC_BIG_ENDIAN);

        if (verspec == V8PDU_PROTO_METHOD)
            offset = flow_process_textfield(pdutree, tvb, offset, 1, hf_cflow_padding);
        else if (verspec == V8PDU_TOSPROTOPORT_METHOD)
            proto_tree_add_item(pdutree, hf_cflow_tos, tvb, offset++, 1, ENC_BIG_ENDIAN);

        offset = flow_process_textfield(pdutree, tvb, offset, 2, hf_cflow_reserved);
        offset = flow_process_ports(pdutree, tvb, offset);

        if (verspec == V8PDU_TOSPROTOPORT_METHOD)
            offset = flow_process_ints(pdutree, tvb, offset);
        break;

    case V8PDU_SPREFIX_METHOD:
    case V8PDU_DPREFIX_METHOD:
    case V8PDU_TOSSRCPREFIX_METHOD:
    case V8PDU_TOSDSTPREFIX_METHOD:
        switch (verspec) {
        case V8PDU_SPREFIX_METHOD:
        case V8PDU_TOSSRCPREFIX_METHOD:
            local_cflow_net  = hf_cflow_srcnet;
            local_cflow_mask = hf_cflow_srcmask;
            local_cflow_as   = hf_cflow_srcas;
            local_cflow_int  = hf_cflow_inputint;
            break;
        case V8PDU_DPREFIX_METHOD:
        case V8PDU_TOSDSTPREFIX_METHOD:
        default:        /* stop warning that :
                           'local_cflow_*' may be used
                           uninitialized in this function */
            local_cflow_net  = hf_cflow_dstnet;
            local_cflow_mask = hf_cflow_dstmask;
            local_cflow_as   = hf_cflow_dstas;
            local_cflow_int  = hf_cflow_outputint;
            break;
        }

        proto_tree_add_item(pdutree, local_cflow_net, tvb, offset, 4, ENC_NA);
        offset += 4;

        proto_tree_add_item(pdutree, local_cflow_mask, tvb, offset++, 1, ENC_NA);

        if ((verspec == V8PDU_SPREFIX_METHOD) || (verspec == V8PDU_DPREFIX_METHOD))
            offset = flow_process_textfield(pdutree, tvb, offset, 1, hf_cflow_padding);

        else if ((verspec == V8PDU_TOSSRCPREFIX_METHOD) || (verspec == V8PDU_TOSDSTPREFIX_METHOD))
            proto_tree_add_item(pdutree, hf_cflow_tos, tvb, offset++, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(pdutree, local_cflow_as, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(pdutree, local_cflow_int, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        offset = flow_process_textfield(pdutree, tvb, offset, 2, hf_cflow_reserved);
        break;

    case V8PDU_MATRIX_METHOD:
    case V8PDU_TOSMATRIX_METHOD:
    case V8PDU_PREPORTPROTOCOL_METHOD:
        proto_tree_add_item(pdutree, hf_cflow_srcnet, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(pdutree, hf_cflow_dstnet, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(pdutree, hf_cflow_srcmask, tvb, offset++, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(pdutree, hf_cflow_dstmask, tvb, offset++, 1, ENC_BIG_ENDIAN);

        if ((verspec == V8PDU_TOSMATRIX_METHOD) ||
            (verspec == V8PDU_PREPORTPROTOCOL_METHOD)) {
            proto_tree_add_item(pdutree, hf_cflow_tos, tvb, offset++, 1, ENC_BIG_ENDIAN);
            if (verspec == V8PDU_TOSMATRIX_METHOD) {
                offset = flow_process_textfield(pdutree, tvb, offset, 1, hf_cflow_padding);
            } else if (verspec == V8PDU_PREPORTPROTOCOL_METHOD) {
                proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1, ENC_BIG_ENDIAN);
            }
        } else {
            offset = flow_process_textfield(pdutree, tvb, offset, 2, hf_cflow_reserved);
        }

        if ((verspec == V8PDU_MATRIX_METHOD)
            || (verspec == V8PDU_TOSMATRIX_METHOD)) {
            offset = flow_process_aspair(pdutree, tvb, offset);
        } else if (verspec == V8PDU_PREPORTPROTOCOL_METHOD) {
            offset = flow_process_ports(pdutree, tvb, offset);
        }

        offset = flow_process_ints(pdutree, tvb, offset);
        break;
    }

    return (offset - startoffset);
}

/* Dissect a version 9 FlowSet and return the length we processed. */

static int
dissect_v9_v10_flowset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree, int offset,
                       hdrinfo_t *hdrinfo_p, guint32 *flows_seen)
{
    proto_item *pi;
    int     length;
    guint16 flowset_id;
    guint8  ver;

    ver = hdrinfo_p->vspec;

    if ((ver != 9) && (ver != 10))
        return (0);

    flowset_id = tvb_get_ntohs(tvb, offset);
    length = tvb_get_ntohs(tvb, offset + 2);

    proto_tree_add_item(pdutree, hf_cflow_flowset_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_item_append_text(pdutree, " [id=%u]", flowset_id);

    pi = proto_tree_add_item(pdutree, hf_cflow_flowset_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (length < 4) {
        expert_add_info_format(pinfo, pi, &ei_cflow_flowset_length,
                               "Flowset Length (%u) too short", length);
        return tvb_reported_length_remaining(tvb, offset-4);
    }

    switch (flowset_id) {
    case FLOWSET_ID_V9_DATA_TEMPLATE:
    case FLOWSET_ID_V10_DATA_TEMPLATE:
        dissect_v9_v10_data_template(tvb, pinfo, pdutree, offset, length - 4, hdrinfo_p, flowset_id);
        break;
    case FLOWSET_ID_V9_OPTIONS_TEMPLATE:
    case FLOWSET_ID_V10_OPTIONS_TEMPLATE:
        dissect_v9_v10_options_template(tvb, pinfo, pdutree, offset, length - 4, hdrinfo_p, flowset_id);
        break;
    default:
        if (flowset_id >= FLOWSET_ID_DATA_MIN) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " [Data:%u]", flowset_id);
            dissect_v9_v10_data(tvb, pinfo, pdutree, offset, flowset_id, (guint)length - 4, hdrinfo_p, flows_seen);
        }
        break;
    }

    return (length);
}

static int
dissect_v9_v10_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree, int offset,
                    guint16 id, guint length, hdrinfo_t *hdrinfo_p, guint32 *flows_seen)
{
    v9_v10_tmplt_t *tmplt_p;
    v9_v10_tmplt_t  tmplt_key;
    proto_tree     *data_tree;
    guint           pdu_len;

    if (length == 0) {
        expert_add_info(pinfo, proto_tree_get_parent(pdutree), &ei_cflow_no_flow_information);
    }

    /* Look up template */
    v9_v10_tmplt_build_key(&tmplt_key, pinfo, hdrinfo_p->src_id, id);
    tmplt_p = (v9_v10_tmplt_t *)g_hash_table_lookup(v9_v10_tmplt_table, &tmplt_key);
    if ((tmplt_p != NULL)  && (tmplt_p->length != 0)) {
        int count = 1;
        proto_item *ti;

        /* Provide a link back to template frame */
        ti = proto_tree_add_uint(pdutree, hf_template_frame, tvb,
                                 0, 0, tmplt_p->template_frame_number);
        if (tmplt_p->template_frame_number > pinfo->num) {
            proto_item_append_text(ti, " (received after this frame)");
        }
        PROTO_ITEM_SET_GENERATED(ti);

        /* Note: If the flow contains variable length fields then          */
        /*       tmplt_p->length will be less then actual length of the flow. */
        while (length >= tmplt_p->length) {
            data_tree = proto_tree_add_subtree_format(pdutree, tvb, offset, tmplt_p->length,
                                            ett_dataflowset, NULL, "Flow %d", count++);

            pdu_len = dissect_v9_v10_pdu(tvb, pinfo, data_tree, offset, tmplt_p, hdrinfo_p, flows_seen);

            offset += pdu_len;
            /* XXX - Throw an exception */
            length -= (pdu_len < length) ? pdu_len : length;
        }
        proto_item_append_text(pdutree, " (%u flows)", count-1);
        if (length != 0) {
            proto_tree_add_item(pdutree, hf_cflow_padding, tvb, offset, length, ENC_NA);
        }
    } else {
        proto_tree_add_expert_format(pdutree, NULL, &ei_cflow_no_template_found,
                                     tvb, offset, length,
                                     "Data (%u byte%s), no template found",
                                     length, plurality(length, "", "s"));
    }

    return (0);
}

#define GOT_LOCAL_ADDR  (1 << 0)
#define GOT_REMOTE_ADDR (1 << 1)
#define GOT_LOCAL_PORT  (1 << 2)
#define GOT_REMOTE_PORT (1 << 3)
#define GOT_IPv4_ID     (1 << 4)
#define GOT_ICMP_ID     (1 << 5)
#define GOT_UID         (1 << 6)
#define GOT_PID         (1 << 7)
#define GOT_USERNAME    (1 << 8)
#define GOT_COMMAND     (1 << 9)

#define GOT_BASE ( \
        GOT_LOCAL_ADDR | \
        GOT_REMOTE_ADDR | \
        GOT_UID | \
        GOT_PID | \
        GOT_USERNAME | \
        GOT_COMMAND \
        )

#define GOT_TCP_UDP (GOT_BASE | GOT_LOCAL_PORT | GOT_REMOTE_PORT)
#define GOT_ICMP    (GOT_BASE | GOT_IPv4_ID    | GOT_ICMP_ID)

static guint
dissect_v9_v10_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree, int offset,
                   v9_v10_tmplt_t *tmplt_p, hdrinfo_t *hdrinfo_p, guint32 *flows_seen)
{
    int orig_offset = offset;

    if ((tmplt_p->fields_p[TF_SCOPES] != NULL)
        && (tmplt_p->field_count[TF_SCOPES] > 0)) {
        if (hdrinfo_p->vspec == 9) {
            offset += dissect_v9_pdu_scope(tvb, pinfo, pdutree, offset, tmplt_p);
        } else if (hdrinfo_p->vspec == 10) {
            offset += dissect_v9_v10_pdu_data(tvb, pinfo, pdutree, offset, tmplt_p, hdrinfo_p, TF_SCOPES);
        }
    }
    offset += dissect_v9_v10_pdu_data(tvb, pinfo, pdutree, offset, tmplt_p, hdrinfo_p, TF_ENTRIES);

    /* Inc number of flows seen in this overall PDU */
    (*flows_seen)++;
    return (guint) (offset - orig_offset);
}

static guint
dissect_v9_pdu_scope(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *pdutree, int offset,
                     v9_v10_tmplt_t *tmplt_p)
{
    int   orig_offset;
    int   i;

    DISSECTOR_ASSERT(tmplt_p->fields_p[TF_SCOPES] != NULL);

    orig_offset = offset;

    for(i = 0; i < tmplt_p->field_count[TF_SCOPES]; i++) {
        guint16 type   = tmplt_p->fields_p[TF_SCOPES][i].type;
        guint16 length = tmplt_p->fields_p[TF_SCOPES][i].length;
        if (length == 0) { /* XXX: Zero length fields probably shouldn't be included in the cached template */
            /* YYY: Maybe.  If you don't cache the zero length fields can you still compare that you actually  */
            /*      have the same template with the same ID. */
            continue;
        }
        switch (type) {
            /* XXX: template length fields should be validated during template processing ... */
        case 1: /* system */
            proto_tree_add_item(pdutree, hf_cflow_scope_system,
                                tvb, offset, length, ENC_NA);
            break;
        case 2: /* interface */
            proto_tree_add_item(pdutree, hf_cflow_scope_interface,
                                tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 3: /* linecard */
            proto_tree_add_item(pdutree, hf_cflow_scope_linecard,
                                tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 4: /* netflow cache */
            proto_tree_add_item(pdutree, hf_cflow_scope_cache,
                                tvb, offset, length, ENC_NA);
            break;
        case 5: /* tmplt */
            proto_tree_add_item(pdutree, hf_cflow_scope_template,
                                tvb, offset, length, ENC_NA);
            break;
        default: /* unknown */
            proto_tree_add_item(pdutree, hf_cflow_unknown_field_type,
                                tvb, offset, length, ENC_NA);
            break;
        }
        offset += length;
    }
    return (guint) (offset - orig_offset);
}

/* Type of duration being calculated for a flow. */
enum duration_type_e {
    duration_type_switched,
    duration_type_seconds,
    duration_type_milliseconds,
    duration_type_microseconds,
    duration_type_nanoseconds,
    duration_type_delta_milliseconds,
    duration_type_max    /* not used - for sizing only */
};

static guint
dissect_v9_v10_pdu_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree, int offset,
                        v9_v10_tmplt_t *tmplt_p, hdrinfo_t *hdrinfo_p, v9_v10_tmplt_fields_type_t fields_type)
{
    int                   orig_offset;
    int                   rev;
    nstime_t              ts_start[2][duration_type_max], ts_end[2][duration_type_max];
    int                   offset_s[2][duration_type_max], offset_e[2][duration_type_max];
    nstime_t              ts;
    guint32               msec_start[2][duration_type_max], msec_end[2][duration_type_max];
    gint                  duration_type;
    guint32               msec_delta;
    nstime_t              ts_delta;
    guint32               usec;
    int                   i, j;

    address               local_addr, remote_addr;
    guint16               local_port = 0, remote_port = 0/*, ipv4_id = 0, icmp_id = 0*/;
    guint32               uid = 0, pid = 0;
    int                   uname_len;
    gchar                *uname_str = NULL;
    int                   cmd_len;
    gchar                *cmd_str = NULL;
    guint16               got_flags = 0;

    int                   string_len_short = 0;
    int                   string_len_long = 0;

    proto_tree           *string_tree;

    gchar                *gen_str = NULL;
    int                   gen_str_offset = 0;

    proto_item           *ti;
    guint16               count;
    v9_v10_tmplt_entry_t *entries_p;
    proto_tree           *fwdstattree;

    gboolean             cace_pie_seen = FALSE,
                         plixer_pie_seen = FALSE,
                         ntop_pie_seen = FALSE,
                         ixia_pie_seen = FALSE,
                         netscaler_pie_seen = FALSE,
                         barracuda_pie_seen = FALSE;


    guint8       ip_protocol = 0;
    guint16      port_number;

    entries_p = tmplt_p->fields_p[fields_type];
    if (entries_p == NULL) {
        /* I don't think we can actually hit this condition.
           If we can, what would cause it?  Does this need a
           warn?  If so, what?
        */
        return 0;
    }
    orig_offset   = offset;
    count         = tmplt_p->field_count[fields_type];

    for (i=0; i < (int)duration_type_max; i++) {
        offset_s[0][i]   = offset_s[1][i] = offset_e[0][i] = offset_e[1][i] = 0;
        msec_start[0][i] = msec_start[1][i] = msec_end[0][i] = msec_end[1][i] = 0;
    }

    for (i = 0; i < count; i++) {
        guint64      pen_type;
        guint16      type;
        guint16      masked_type;
        guint16      length;
        guint32      pen;
        const gchar *pen_str;
        int          vstr_len;

        type    = entries_p[i].type;
        length  = entries_p[i].length;
        pen     = entries_p[i].pen;
        pen_str = entries_p[i].pen_str;

        if (length == 0) { /* XXX: Zero length fields probably shouldn't be included in the cached template */
            /* YYY: Maybe.  If you don't cache the zero length fields can you still compare that you actually */
            /* have the same template with the same ID. */
            /* XXX: One capture has been seen wherein the "length" field in the template is 0 even though
                    the field is actually present in the dataflow.
                    See: https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=10432#c1
            */
            continue;
        }
        /* See if variable length field */
        vstr_len = 0;
        if (length == VARIABLE_LENGTH) {
            vstr_len = 1;
            string_len_short = length = tvb_get_guint8(tvb, offset);
            if (length == 255) {
                vstr_len = 3;
                string_len_long = length = tvb_get_ntohs(tvb, offset+1);
            }
            offset += vstr_len;
            gen_str_offset = offset;
        }

        /*  v9 types
         *    0x 0000 0000 0000 to
         *    0x 0000 0000 ffff
         *  v10 global types (presumably consistent with v9 types 0x0000 - 0x7fff)
         *    0x 0000 0000 0000 to
         *    0x 0000 0000 7fff
         *  V10 Enterprise types
         *    0x 0000 0001 0000 to
         *    0x ffff ffff 7fff
         */
        pen_type = masked_type = type;
        rev      = 0;

        if ((hdrinfo_p->vspec == 10) && (type & 0x8000)) {
            pen_type = masked_type = type & 0x7fff;
            if (pen == REVPEN) { /* reverse PEN */
                rev = 1;
            } else if (pen == 0) {
                pen_type = (G_GUINT64_CONSTANT(0xffff) << 16) | pen_type;  /* hack to force "unknown" */
            } else {
                pen_type = (((guint64)pen) << 16) | pen_type;
            }
        }

        /* Provide a convenient (hidden) filter for any items belonging to a known PIE,
           but take care not to add > once. */
        switch (pen) {
            case VENDOR_CACE:
                if (!cace_pie_seen) {
                    proto_item *pie_cace_ti = proto_tree_add_item(pdutree, hf_pie_cace, tvb, 0, 0, ENC_NA);
                    PROTO_ITEM_SET_HIDDEN(pie_cace_ti);
                    cace_pie_seen = TRUE;
                }
                break;
            case VENDOR_PLIXER:
                if (!plixer_pie_seen) {
                    proto_item *pie_plixer_ti = proto_tree_add_item(pdutree, hf_pie_plixer, tvb, 0, 0, ENC_NA);
                    PROTO_ITEM_SET_HIDDEN(pie_plixer_ti);
                    plixer_pie_seen = TRUE;
                }
                break;
            case VENDOR_NTOP:
                if (!ntop_pie_seen) {
                    proto_item *pie_ntop_ti = proto_tree_add_item(pdutree, hf_pie_ntop, tvb, 0, 0, ENC_NA);
                    PROTO_ITEM_SET_HIDDEN(pie_ntop_ti);
                    ntop_pie_seen = TRUE;
                }
                break;
            case VENDOR_IXIA:
                if (!ixia_pie_seen) {
                    proto_item *pie_ixia_ti = proto_tree_add_item(pdutree, hf_pie_ixia, tvb, 0, 0, ENC_NA);
                    PROTO_ITEM_SET_HIDDEN(pie_ixia_ti);
                    ixia_pie_seen = TRUE;
                }
                break;
            case VENDOR_NETSCALER:
                if (!netscaler_pie_seen) {
                    proto_item *pie_netscaler_ti = proto_tree_add_item(pdutree, hf_pie_netscaler, tvb, 0, 0, ENC_NA);
                    PROTO_ITEM_SET_HIDDEN(pie_netscaler_ti);
                    netscaler_pie_seen = TRUE;
                }
                break;
            case VENDOR_BARRACUDA:
                if (!barracuda_pie_seen) {
                    proto_item *pie_barracuda_ti = proto_tree_add_item(pdutree, hf_pie_barracuda, tvb, 0, 0, ENC_NA);
                    PROTO_ITEM_SET_HIDDEN(pie_barracuda_ti);
                    barracuda_pie_seen = TRUE;
                }
                break;

            default:
                break;
        }

        ti = NULL;
        switch (pen_type) {

        case 1: /* bytes */
            ti = proto_tree_add_item(pdutree, hf_cflow_octets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 2: /* packets */
            ti = proto_tree_add_item(pdutree, hf_cflow_packets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 163: /*  observedFlowTotalCount */
        case 3: /* flows */
            ti = proto_tree_add_item(pdutree, hf_cflow_flows,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 4: /* proto */
            /* Store this to help with possible port transport lookup */
            ip_protocol = tvb_get_guint8(tvb, offset);
            ti = proto_tree_add_item(pdutree, hf_cflow_prot,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 5: /* TOS */
            ti = proto_tree_add_item(pdutree, hf_cflow_tos,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 6: /* TCP flags */
            if (length == 1) {
                ti = proto_tree_add_bitmask(pdutree, tvb, offset, hf_cflow_tcpflags, ett_tcpflags, tcp_flags, ENC_NA);
            } else {
                ti = proto_tree_add_bitmask(pdutree, tvb, offset, hf_cflow_tcpflags16, ett_tcpflags, tcp_flags16, ENC_NA);
            }
            break;

        case 7: /* source port */
        case 180: /*  udpSourcePort */
        case 182: /*  tcpSourcePort */
            ti = proto_tree_add_item(pdutree, hf_cflow_srcport,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            port_number = tvb_get_ntohs(tvb, offset);
            netflow_add_transport_info(pen_type, ip_protocol, port_number, ti);
            break;

        case 8: /* source IP */
            /* IANA indicates this can only be an IPv4 Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_srcaddr,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 9: /* source mask */
            ti = proto_tree_add_item(pdutree, hf_cflow_srcmask,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 10: /* input SNMP */
            ti = proto_tree_add_item(pdutree, hf_cflow_inputint,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 11: /* dest port */
        case 181: /*  udpDestinationPort */
        case 183: /*  tcpDestinationPort */
            ti = proto_tree_add_item(pdutree, hf_cflow_dstport,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            port_number = tvb_get_ntohs(tvb, offset);
            netflow_add_transport_info(pen_type, ip_protocol, port_number, ti);
            break;

        case 12: /* dest IP */
            /* IANA indicates this can only be an IPv4 Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_dstaddr,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 13: /* dest mask */
            ti = proto_tree_add_item(pdutree, hf_cflow_dstmask,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 14: /* output SNMP */
            ti = proto_tree_add_item(pdutree, hf_cflow_outputint,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 15: /* nexthop IP */
            ti = proto_tree_add_item(pdutree, hf_cflow_nexthop,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 16: /* source AS */
            ti = proto_tree_add_item(pdutree, hf_cflow_srcas,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 17: /* dest AS */
            ti = proto_tree_add_item(pdutree, hf_cflow_dstas,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 18: /* BGP nexthop IP */
            /* IANA indicates this can only be an IPv4 Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_bgpnexthop,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 19: /* multicast packets */
            ti = proto_tree_add_item(pdutree, hf_cflow_mulpackets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 20: /* multicast octets */
            ti = proto_tree_add_item(pdutree, hf_cflow_muloctets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 21: /* last switched */
            duration_type = (gint)duration_type_switched;
            offset_e[rev][duration_type] = offset;
            msec_end[rev][duration_type] = tvb_get_ntohl(tvb, offset);
            ts_end[rev][duration_type].secs = msec_end[rev][duration_type] / 1000;
            ts_end[rev][duration_type].nsecs = (msec_end[rev][duration_type] % 1000) * 1000000;
            goto timestamp_common;
            break;
        case 22: /* first switched */
            duration_type = (gint)duration_type_switched;
            offset_s[rev][duration_type] = offset;
            msec_start[rev][duration_type] = tvb_get_ntohl(tvb, offset);
            ts_start[rev][duration_type].secs = msec_start[rev][duration_type] / 1000;
            ts_start[rev][duration_type].nsecs = (msec_start[rev][duration_type] % 1000) * 1000000;
            goto timestamp_common;
            break;

        case 150: /*  flowStartSeconds */
            duration_type = (gint)duration_type_seconds;
            offset_s[rev][duration_type] = offset;
            ts_start[rev][duration_type].secs = tvb_get_ntohl(tvb, offset);
            ts_start[rev][duration_type].nsecs = 0;
            goto timestamp_common;
            break;

        case 151: /*  flowEndSeconds */
            duration_type = (gint)duration_type_seconds;
            offset_e[rev][duration_type] = offset;
            ts_end[rev][duration_type].secs = tvb_get_ntohl(tvb, offset);
            ts_end[rev][duration_type].nsecs = 0;
            goto timestamp_common;
            break;

        case 152: /*  flowStartMilliseconds: 64-bit integer */
            duration_type = (gint)duration_type_milliseconds;
            offset_s[rev][duration_type] = offset;
            ts_start[rev][duration_type].secs = (time_t)(tvb_get_ntoh64(tvb, offset)/1000);
            ts_start[rev][duration_type].nsecs = (int)(tvb_get_ntoh64(tvb, offset)%1000) * 1000000;
            goto timestamp_common;
            break;

        case 153: /*  flowEndMilliseconds; 64-bit integer */
            duration_type = (gint)duration_type_milliseconds;
            offset_e[rev][duration_type] = offset;
            ts_end[rev][duration_type].secs  = (time_t)(tvb_get_ntoh64(tvb, offset)/1000);
            ts_end[rev][duration_type].nsecs = (int)(tvb_get_ntoh64(tvb, offset)%1000) * 1000000;
            goto timestamp_common;
            break;

        case 154: /*  flowStartMicroseconds: 64-bit NTP format */
            duration_type = (gint)duration_type_microseconds;
            offset_s[rev][duration_type] = offset;
            ntp_to_nstime(tvb, offset, &ts_start[rev][duration_type]);
            goto timestamp_common;
            break;

        case 155: /*  flowEndMicroseconds: 64-bit NTP format */
            /*  XXX: Not tested ...                    */
            duration_type = (gint)duration_type_microseconds;
            offset_e[rev][duration_type] = offset;
            ntp_to_nstime(tvb, offset, &ts_end[rev][duration_type]);
            goto timestamp_common;
            break;

        case 156: /*  flowStartNanoseconds: 64-bit NTP format */
            /*  XXX: Not tested ...                     */
            duration_type = (gint)duration_type_nanoseconds;
            offset_s[rev][duration_type] = offset;
            ntp_to_nstime(tvb, offset, &ts_start[rev][duration_type]);
            goto timestamp_common;
            break;

        case 157: /*  flowEndNanoseconds: 64-bit NTP format */
            /*  XXX: Not tested ...                   */
            duration_type = (gint)duration_type_nanoseconds;
            offset_e[rev][duration_type] = offset;
            ntp_to_nstime(tvb, offset, &ts_end[rev][duration_type]);
            goto timestamp_common;
            break;

        case 158: /*  flowStartDeltaMicroseconds: 32-bit integer; negative time offset   */
            /*   relative to the export time specified in the IPFIX Message Header */
            /*  XXX: Not tested ...                                                */
            duration_type = (gint)duration_type_delta_milliseconds;
            offset_s[rev][duration_type]       = offset;
            usec                = tvb_get_ntohl(tvb, offset);
            ts_start[rev][duration_type].secs  = (time_t)(((guint64)(hdrinfo_p->export_time_secs)*1000000 - usec) / 1000000);
            ts_start[rev][duration_type].nsecs = (int)(((guint64)(hdrinfo_p->export_time_secs)*1000000 - usec) % 1000000) * 1000;
            goto timestamp_common;
            break;

        case 159: /*  flowEndDeltaMicroseconds: 32-bit integer; negative time offset     */
            /*   relative to the export time specified in the IPFIX Message Header */
            /*  XXX: Not tested ...                                                */
            duration_type = (gint)duration_type_delta_milliseconds;
            offset_e[rev][duration_type] = offset;
            usec          = tvb_get_ntohl(tvb, offset);
            ts_end[rev][duration_type].secs  = (time_t)(((guint64)(hdrinfo_p->export_time_secs)*1000000 - usec) / 1000000);
            ts_end[rev][duration_type].nsecs = (int)(((guint64)(hdrinfo_p->export_time_secs)*1000000 - usec) % 1000000) * 1000;

            /* This code executed for all timestamp fields above  */
            /* Since bug 11295, cope with multiple durations in one flow - not really sure if it makes sense... */
        timestamp_common:
            if(offset_s[rev][duration_type] && offset_e[rev][duration_type]) {
                proto_tree *timetree;
                proto_item *timeitem;

                nstime_delta(&ts_delta, &ts_end[rev][duration_type], &ts_start[rev][duration_type]);
                timeitem =
                    proto_tree_add_time(pdutree, hf_cflow_timedelta, tvb,
                                        offset_s[rev][duration_type], 0, &ts_delta);
                PROTO_ITEM_SET_GENERATED(timeitem);
                timetree = proto_item_add_subtree(timeitem, ett_flowtime);

                /* Show the type/units used to calculate the duration */
                switch (duration_type) {
                    case duration_type_switched:
                        proto_item_append_text(timeitem, " (switched)");
                        break;
                    case duration_type_seconds:
                        proto_item_append_text(timeitem, " (seconds)");
                        break;
                    case duration_type_milliseconds:
                        proto_item_append_text(timeitem, " (milliseconds)");
                        break;
                    case duration_type_microseconds:
                        proto_item_append_text(timeitem, " (microseconds)");
                        break;
                    case duration_type_nanoseconds:
                        proto_item_append_text(timeitem, " (nanoseconds)");
                        break;
                    case duration_type_delta_milliseconds:
                        proto_item_append_text(timeitem, " (delta milliseconds)");
                        break;
                    default:
                        break;
                }

                /* Note: length of "start" is assumed to match that of "end" */
                if (msec_start[rev][duration_type]) {
                    proto_tree_add_time(timetree, hf_cflow_timestart, tvb,
                                        offset_s[rev][duration_type], length, &ts_start[rev][duration_type]);
                } else {
                    proto_tree_add_time(timetree, hf_cflow_abstimestart, tvb,
                                        offset_s[rev][duration_type], length, &ts_start[rev][duration_type]);
                }
                if (msec_end[rev][duration_type]) {
                    proto_tree_add_time(timetree, hf_cflow_timeend, tvb,
                                        offset_e[rev][duration_type], length, &ts_end[rev][duration_type]);
                } else {
                    proto_tree_add_time(timetree, hf_cflow_abstimeend, tvb,
                                        offset_e[rev][duration_type], length, &ts_end[rev][duration_type]);
                }
            }
            break;

        case 23: /* postOctetDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_octets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 24: /* postPacketDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_packets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 25: /* length_min */
            ti = proto_tree_add_item(pdutree, hf_cflow_length_min,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 26: /* length_max */
            ti = proto_tree_add_item(pdutree, hf_cflow_length_max,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 27: /* IPv6 src addr */
            ti = proto_tree_add_item(pdutree, hf_cflow_srcaddr_v6,
                                     tvb, offset, length, ENC_NA);
            break;

        case 28: /* IPv6 dst addr */
            ti = proto_tree_add_item(pdutree, hf_cflow_dstaddr_v6,
                                     tvb, offset, length, ENC_NA);
            break;

        case 29: /* IPv6 src addr mask */
            ti = proto_tree_add_item(pdutree, hf_cflow_srcmask_v6,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 30: /* IPv6 dst addr mask */
            ti = proto_tree_add_item(pdutree, hf_cflow_dstmask_v6,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 31: /* flowLabelIPv6 */
            /* RFC5102 defines that Abstract Data Type of this
                Information Element is unsigned32 */
            /* RFC3954 defines that length of this field is 3
                Bytes */
            ti = proto_tree_add_item(pdutree, hf_cflow_ipv6_flowlabel,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 32: /* ICMP_TYPE/ICMP_CODE IPv4 */
            ti = proto_tree_add_item(pdutree, hf_cflow_icmp_type_code_ipv4,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 33: /* IGMP_TYPE */
            ti = proto_tree_add_item(pdutree, hf_cflow_igmp_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 34: /* sampling interval */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampling_interval,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 35: /* sampling algorithm */
                 /* "Deprecated in favor of 304 selectorAlgorithm" */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampling_algorithm,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 36: /* flow active timeout */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_active_timeout,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 37: /* flow inactive timeout */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_inactive_timeout,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 38: /* engine type */
            ti = proto_tree_add_item(pdutree, hf_cflow_engine_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 39: /* engine id*/
            ti = proto_tree_add_item(pdutree, hf_cflow_engine_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 40: /* bytes exported */
            ti = proto_tree_add_item(pdutree, hf_cflow_octets_exp,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 41: /* packets exported */
            ti = proto_tree_add_item(pdutree, hf_cflow_packets_exp,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 42: /* flows exported */
            ti = proto_tree_add_item(pdutree, hf_cflow_flows_exp,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 43: /* ipv4RouterSc */
                 /* platform-specific field for the Catalyst 5000/Catalyst 6000 family */
            ti = proto_tree_add_item(pdutree, hf_cflow_ipv4_router_sc,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 44: /* IP source prefix */
            ti = proto_tree_add_item(pdutree, hf_cflow_srcprefix,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 45: /* IP destination prefix */
            ti = proto_tree_add_item(pdutree, hf_cflow_dstprefix,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 46: /* top MPLS label type*/
            ti = proto_tree_add_item(pdutree, hf_cflow_mpls_top_label_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 47: /* top MPLS label PE address*/
            ti = proto_tree_add_item(pdutree, hf_cflow_mpls_pe_addr,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 48: /* Flow Sampler ID */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampler_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 49: /* FLOW_SAMPLER_MODE  */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampler_mode,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 50: /* FLOW_SAMPLER_RANDOM_INTERVAL  */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampler_random_interval,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 51: /*  FLOW_CLASS */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_class,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 52: /*  TTL_MINIMUM */
            ti = proto_tree_add_item(pdutree, hf_cflow_ttl_minimum,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 53: /*  TTL_MAXIMUM */
            ti = proto_tree_add_item(pdutree, hf_cflow_ttl_maximum,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 54: /* FRAG ID  */
            ti = proto_tree_add_item(pdutree, hf_cflow_frag_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 55: /* postIpClassOfService */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_tos,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 56: /* sourceMacAddress */
            ti = proto_tree_add_item(pdutree, hf_cflow_srcmac,
                                     tvb, offset, length, ENC_NA);
            break;

        case 57: /* postDestinationMacAddress */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_dstmac,
                                     tvb, offset, length, ENC_NA);
            break;

        case 58: /* vlanId */
            ti = proto_tree_add_item(pdutree, hf_cflow_vlanid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 59: /* postVlanId */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_vlanid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 60: /* IP_VERSION */
            ti = proto_tree_add_item(pdutree, hf_cflow_ip_version,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 61: /* DIRECTION   */
            ti = proto_tree_add_item(pdutree, hf_cflow_direction,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 62: /* IPV6_NEXT_HOP */
            ti = proto_tree_add_item(pdutree, hf_cflow_nexthop_v6,
                                     tvb, offset, length, ENC_NA);
            break;

        case 63: /* BGP_IPV6_NEXT_HOP */
            ti = proto_tree_add_item(pdutree, hf_cflow_bgpnexthop_v6,
                                     tvb, offset, length, ENC_NA);
            break;

        case 64: /* ipv6ExtensionHeaders */
            ti = proto_tree_add_item(pdutree, hf_cflow_ipv6_exthdr,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 70: /* MPLS label1*/
            ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 1);
            break;

        case 71: /* MPLS label2*/
            ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 2);
            break;

        case 72: /* MPLS label3*/
            ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 3);
            break;

        case 73: /* MPLS label4*/
            ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 4);
            break;

        case 74: /* MPLS label5*/
            ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 5);
            break;

        case 75: /* MPLS label6*/
            ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 6);
            break;

        case 76: /* MPLS label7*/
            ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 7);
            break;

        case 77: /* MPLS label8*/
            ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 8);
            break;

        case 78: /* MPLS label9*/
            ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 9);
            break;

        case 79: /* MPLS label10*/
            ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 10);
            break;

        case 80: /* destinationMacAddress */
            ti = proto_tree_add_item(pdutree, hf_cflow_dstmac,
                                     tvb, offset, length, ENC_NA);
            break;

        case 81: /* postSourceMacAddress */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_srcmac,
                                     tvb, offset, length, ENC_NA);
            break;

        case 82: /* IF_NAME  */
            ti = proto_tree_add_item(pdutree, hf_cflow_if_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 83: /* IF_DESCR  */
            ti = proto_tree_add_item(pdutree, hf_cflow_if_descr,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 84: /* SAMPLER_NAME  */
                 /* "Deprecated in favor of 335 selectorName" */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampler_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 85: /* BYTES_PERMANENT */
            ti = proto_tree_add_item(pdutree, hf_cflow_permanent_octets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 86: /* PACKETS_PERMANENT */
            ti = proto_tree_add_item(pdutree, hf_cflow_permanent_packets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 88: /* fragmentOffset */
            ti = proto_tree_add_item(pdutree, hf_cflow_fragment_offset,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 89: {
            /* FORWARDING_STATUS */
            /* Forwarding status is encoded on 1 byte with
             * the 2 left bits giving the status and the 6
             * remaining bits giving the reason code. */

            guint8              forwarding_status;
            const value_string *x_vs;
            int                 x_hf;

            fwdstattree = proto_tree_add_subtree(pdutree, tvb, offset, length, ett_fwdstat, NULL, "Forwarding Status");

            forwarding_status = tvb_get_guint8(tvb, offset)>>6;
            switch(forwarding_status) {
            default:
            case FORWARDING_STATUS_UNKNOWN:
                x_vs = v9_forwarding_status_unknown_code;
                x_hf = hf_cflow_forwarding_status_unknown_code;
                break;
            case FORWARDING_STATUS_FORWARD:
                x_vs = v9_forwarding_status_forward_code;
                x_hf = hf_cflow_forwarding_status_forward_code;
                break;
            case FORWARDING_STATUS_DROP:
                x_vs = v9_forwarding_status_drop_code;
                x_hf = hf_cflow_forwarding_status_drop_code;
                break;
            case FORWARDING_STATUS_CONSUME:
                x_vs = v9_forwarding_status_consume_code;
                x_hf = hf_cflow_forwarding_status_consume_code;
                break;
            }

            proto_tree_add_item(fwdstattree, hf_cflow_forwarding_status,
                                tvb, offset, length, ENC_BIG_ENDIAN);

            proto_tree_add_item(fwdstattree, x_hf,
                                tvb, offset, length, ENC_NA);

            /* add status code to tree summary */
            if (length == 1) {
                proto_item_append_text(ti, ": %s", val_to_str_const(forwarding_status,
                                                                    v9_forwarding_status, "(Unknown)"));
                proto_item_append_text(ti, ": %s", val_to_str_const((tvb_get_guint8(tvb, offset)&0x3F),
                                                                    x_vs, "(Unknown)"));
            };
        }
            break;

        case 90: /* mplsVpnRouteDistinguisher */
            ti = proto_tree_add_item(pdutree, hf_cflow_mpls_vpn_rd,
                                     tvb, offset, length, ENC_NA);
            break;

        case 91: /* mplsTopLabelPrefixLength */
            ti = proto_tree_add_item(pdutree, hf_cflow_mpls_top_label_prefix_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 92:
            ti = proto_tree_add_item(pdutree, hf_cflow_src_traffic_index,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 93:
            ti = proto_tree_add_item(pdutree, hf_cflow_dst_traffic_index,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 94: /* NBAR applicationDesc */
            ti = proto_tree_add_item(pdutree, hf_cflow_nbar_appl_desc,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 95: /* NBAR applicationId */
            ti = proto_tree_add_item(pdutree, hf_cflow_nbar_appl_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 96: /* NBAR applicationName */
            ti = proto_tree_add_item(pdutree, hf_cflow_nbar_appl_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 98: /* postIpDiffServCodePoint */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_ip_diff_serv_code_point,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 99: /* multicastReplicationFactor */
            ti = proto_tree_add_item(pdutree, hf_cflow_multicast_replication_factor,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 101:
            ti = proto_tree_add_item(pdutree, hf_cflow_classification_engine_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 128: /* dest AS Peer */
            ti = proto_tree_add_item(pdutree, hf_cflow_peer_dstas,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 129: /* source AS Peer*/
            ti = proto_tree_add_item(pdutree, hf_cflow_peer_srcas,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 130: /*  exporterIPv4Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_exporter_addr,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 131: /*  exporterIPv6Address */
            ti = proto_tree_add_item(pdutree,
                                     hf_cflow_exporter_addr_v6,
                                     tvb, offset, length, ENC_NA);
            break;

        case 132: /*  droppedOctetDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_drop_octets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 133: /*  droppedPacketDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_drop_packets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 134: /*  droppedOctetTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_drop_total_octets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 135: /*  droppedPacketTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_drop_total_packets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 136: /*  flowEndReason */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_end_reason,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 137: /*  commonPropertiesId */
            ti = proto_tree_add_item(pdutree, hf_cflow_common_properties_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 138: /*  observationPointId */
            ti = proto_tree_add_item(pdutree, hf_cflow_observation_point_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 139: /* icmpTypeCodeIPv6 */
            proto_tree_add_item(pdutree, hf_cflow_icmp_ipv6_type,
                                     tvb, offset, 1, ENC_BIG_ENDIAN);
            ti = proto_tree_add_item(pdutree, hf_cflow_icmp_ipv6_code,
                                     tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            break;

        case 140: /*  mplsTopLabelIPv6Address */
            ti = proto_tree_add_item(pdutree,
                                     hf_cflow_mpls_pe_addr_v6,
                                     tvb, offset, length, ENC_NA);
            break;

        case 141: /*  lineCardId */
            ti = proto_tree_add_item(pdutree, hf_cflow_scope_linecard,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 142: /*  portId */
            ti = proto_tree_add_item(pdutree, hf_cflow_port_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 143: /*  meteringProcessId */
            ti = proto_tree_add_item(pdutree, hf_cflow_mp_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 144: /* FLOW EXPORTER */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_exporter,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 145: /*  templateId */
            ti = proto_tree_add_item(pdutree, hf_cflow_template_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 146: /*  wlanChannelId */
            ti = proto_tree_add_item(pdutree, hf_cflow_wlan_channel_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 147: /*  wlanSSID */
            ti = proto_tree_add_item(pdutree, hf_cflow_wlan_ssid,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 148: /*  flowId */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 149: /*  observationDomainId */
            ti = proto_tree_add_item(pdutree, hf_cflow_od_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 160: /*  systemInitTimeMilliseconds */
            ts.secs  = (time_t)(tvb_get_ntoh64(tvb, offset)/1000);
            ts.nsecs = (int)(tvb_get_ntoh64(tvb, offset)%1000) *1000000;
            ti = proto_tree_add_time(pdutree,
                                     hf_cflow_sys_init_time,
                                     tvb, offset, length, &ts);
            break;

        case 161: /*  flowDurationMilliseconds */
            msec_delta = tvb_get_ntohl(tvb, offset);
            ts_delta.secs = msec_delta / 1000;
            ts_delta.nsecs = (msec_delta % 1000) * 1000000;
            ti = proto_tree_add_time(pdutree, hf_cflow_timedelta, tvb,
                                     offset, length, &ts_delta);
            break;

        case 162: /*  flowDurationMicroseconds */
            msec_delta = tvb_get_ntohl(tvb, offset);
            ts_delta.secs = msec_delta / 1000000;
            ts_delta.nsecs = (msec_delta % 1000000) * 1000;
            ti = proto_tree_add_time(pdutree, hf_cflow_timedelta, tvb,
                                     offset, length, &ts_delta);
            break;

        case 164: /*  ignoredPacketTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_ignore_packets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 165: /*  ignoredOctetTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_ignore_octets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 166: /*  notSentFlowTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_notsent_flows,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 167: /*  notSentPacketTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_notsent_packets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 168: /*  notSentOctetTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_notsent_octets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 169: /* destinationIPv6Prefix */
            ti = proto_tree_add_item(pdutree, hf_cflow_dstnet_v6,
                                     tvb, offset, length, ENC_NA);
            break;

        case 170: /* sourceIPv6Prefix */
            ti = proto_tree_add_item(pdutree, hf_cflow_srcnet_v6,
                                     tvb, offset, length, ENC_NA);
            break;

        case 171: /* postOctetTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_total_octets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 172: /* postPacketTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_total_packets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 173: /* flowKeyIndicator */
            ti = proto_tree_add_item(pdutree, hf_cflow_key,
                                     tvb, offset, length, ENC_NA);
            break;

        case 174: /* postMCastPacketTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_total_mulpackets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 175: /* postMCastOctetTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_total_muloctets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 176: /* ICMP_IPv4_TYPE */
            ti = proto_tree_add_item(pdutree, hf_cflow_icmp_ipv4_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 177: /* ICMP_IPv4_CODE */
            ti = proto_tree_add_item(pdutree, hf_cflow_icmp_ipv4_code,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 178: /* ICMP_IPv6_TYPE */
            ti = proto_tree_add_item(pdutree, hf_cflow_icmp_ipv6_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 179: /* ICMP_IPv6_CODE */
            ti = proto_tree_add_item(pdutree, hf_cflow_icmp_ipv6_code,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 184: /* tcpSequenceNumber */
            ti = proto_tree_add_item(pdutree, hf_cflow_tcp_seq_num,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 185: /* tcpAcknowledgementNumber */
            ti = proto_tree_add_item(pdutree, hf_cflow_tcp_ack_num,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 186: /* TCP_WINDOWS_SIZE */
            ti = proto_tree_add_item(pdutree, hf_cflow_tcp_window_size,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 187: /* tcpUrgentPointer */
            ti = proto_tree_add_item(pdutree, hf_cflow_tcp_urg_ptr,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 188: /* tcpHeaderLength */
            ti = proto_tree_add_item(pdutree, hf_cflow_tcp_header_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 189: /* ipHeaderLength */
            ti = proto_tree_add_item(pdutree, hf_cflow_ip_header_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 190: /* IPV4_TOTAL_LENGTH */
            ti = proto_tree_add_item(pdutree, hf_cflow_ipv4_total_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 191: /* payloadLengthIPv6 */
            ti = proto_tree_add_item(pdutree, hf_cflow_ipv6_payload_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 192: /* IP_TTL */
            ti = proto_tree_add_item(pdutree, hf_cflow_ip_ttl,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 193: /* nextHeaderIPv6 */
            ti = proto_tree_add_item(pdutree, hf_cflow_ipv6_next_hdr,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 194: /* mplsPayloadLength */
            ti = proto_tree_add_item(pdutree, hf_cflow_mpls_payload_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 195: /* IP_DSCP */
            ti = proto_tree_add_item(pdutree, hf_cflow_ip_dscp,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 196: /* ipPrecedence */
            ti = proto_tree_add_item(pdutree, hf_cflow_ip_precedence,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 197: /* fragmentFlags */
            ti = proto_tree_add_item(pdutree, hf_cflow_ip_fragment_flags,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 198: /* DELTA_BYTES_SQUARED */
            ti = proto_tree_add_item(pdutree, hf_cflow_delta_octets_squared,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 199: /* TOTAL_BYTES_SQUARED */
            ti = proto_tree_add_item(pdutree, hf_cflow_total_octets_squared,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 200: /* mplsTopLabelTTL */
            ti = proto_tree_add_item(pdutree, hf_cflow_mpls_top_label_ttl,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 201: /* mplsLabelStackLength */
            ti = proto_tree_add_item(pdutree, hf_cflow_mpls_label_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 202: /* mplsLabelStackDepth */
            ti = proto_tree_add_item(pdutree, hf_cflow_mpls_label_depth,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 203: /* mplsTopLabelExp */
            ti = proto_tree_add_item(pdutree, hf_cflow_mpls_top_label_exp,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 204: /* ipPayloadLength */
            ti = proto_tree_add_item(pdutree, hf_cflow_ip_payload_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 205: /* UDP_LENGTH */
            ti = proto_tree_add_item(pdutree, hf_cflow_udp_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 206: /* IS_MULTICAST */
            ti = proto_tree_add_item(pdutree, hf_cflow_is_multicast,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 207: /* IP_HEADER_WORDS */
            ti = proto_tree_add_item(pdutree, hf_cflow_ip_header_words,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 208: /* OPTION_MAP */
            ti = proto_tree_add_item(pdutree, hf_cflow_option_map,
                                     tvb, offset, length, ENC_NA);
            break;

        case 209: /* tcpOptions */
            ti = proto_tree_add_item(pdutree, hf_cflow_tcp_option_map,
                                     tvb, offset, length, ENC_NA);
            break;

        case 210: /* paddingOctets */
            ti = proto_tree_add_item(pdutree, hf_cflow_padding, tvb, offset, length, ENC_NA);
            break;

        case 211: /* collectorIPv4Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_collector_addr,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 212: /* collectorIPv6Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_collector_addr_v6,
                                     tvb, offset, length, ENC_NA);
            break;

        case 213: /* exportInterface */
            ti = proto_tree_add_item(pdutree, hf_cflow_export_interface,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 214: /* exportProtocolVersion */
            ti = proto_tree_add_item(pdutree, hf_cflow_export_protocol_version,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 215: /* exportTransportProtocol */
            ti = proto_tree_add_item(pdutree, hf_cflow_export_prot,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 216: /* collectorTransportPort */
            ti = proto_tree_add_item(pdutree, hf_cflow_collector_port,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 217: /* exporterTransportPort */
            ti = proto_tree_add_item(pdutree, hf_cflow_exporter_port,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 218: /* tcpSynTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_total_tcp_syn,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 219: /* tcpFinTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_total_tcp_fin,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 220: /* tcpRstTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_total_tcp_rst,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 221: /* tcpPshTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_total_tcp_psh,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 222: /* tcpAckTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_total_tcp_ack,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 223: /* tcpUrgTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_total_tcp_urg,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 224: /* IP_TOTAL_LENGTH */
            ti = proto_tree_add_item(pdutree, hf_cflow_ip_total_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 225: /* postNATSourceIPv4Address */
        case 40001: /* NF_F_XLATE_SRC_ADDR_IPV4 (Cisco ASA 5500 Series) */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_natsource_ipv4_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 226: /* postNATDestinationIPv4Address */
        case 40002: /* NF_F_XLATE_DST_ADDR_IPV4 (Cisco ASA 5500 Series) */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_natdestination_ipv4_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 227: /* postNAPTSourceTransportPort */
        case 40003: /* NF_F_XLATE_SRC_PORT (Cisco ASA 5500 Series) */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_naptsource_transport_port,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 228: /* postNAPTDestinationTransportPort */
        case 40004: /* NF_F_XLATE_DST_PORT (Cisco ASA 5500 Series) */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_naptdestination_transport_port,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 229: /* natOriginatingAddressRealm */
            ti = proto_tree_add_item(pdutree, hf_cflow_nat_originating_address_realm,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 230: /* natEvent */
            ti = proto_tree_add_item(pdutree, hf_cflow_nat_event,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 231: /* initiatorOctets */
            ti = proto_tree_add_item(pdutree, hf_cflow_initiator_octets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 232: /* responderOctets */
            ti = proto_tree_add_item(pdutree, hf_cflow_responder_octets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 233: /* firewallEvent */
        case 40005: /* NF_F_FW_EVENT (Cisco ASA 5500 Series) */
            ti = proto_tree_add_item(pdutree, hf_cflow_firewall_event,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 234: /* ingressVRFID */
            ti = proto_tree_add_item(pdutree, hf_cflow_ingress_vrfid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 235: /* egressVRFID */
            ti = proto_tree_add_item(pdutree, hf_cflow_egress_vrfid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 236: /* VRFname */
            ti = proto_tree_add_item(pdutree, hf_cflow_vrfname,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 237: /* postMplsTopLabelExp */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_mpls_top_label_exp,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 238: /* tcpWindowScale */
            ti = proto_tree_add_item(pdutree, hf_cflow_tcp_window_scale,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 239: /*  biflowDirection */
            ti = proto_tree_add_item(pdutree, hf_cflow_biflow_direction,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 240: /* ethernetHeaderLength */
            ti = proto_tree_add_item(pdutree, hf_cflow_ethernet_header_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 241: /* ethernetPayloadLength */
            ti = proto_tree_add_item(pdutree, hf_cflow_ethernet_payload_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 242: /* ethernetTotalLength */
            ti = proto_tree_add_item(pdutree, hf_cflow_ethernet_total_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 243: /* dot1qVlanId */
            ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_vlan_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 244: /* dot1qPriority */
            ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_priority,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 245: /* dot1qCustomerVlanId */
            ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_customer_vlan_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 246: /* dot1qCustomerPriority */
            ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_customer_priority,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 247: /* metroEvcId */
            ti = proto_tree_add_item(pdutree, hf_cflow_metro_evc_id,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 248: /* metroEvcType */
            ti = proto_tree_add_item(pdutree, hf_cflow_metro_evc_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 249: /* pseudoWireId */
            ti = proto_tree_add_item(pdutree, hf_cflow_pseudo_wire_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 250: /* pseudoWireType */
            ti = proto_tree_add_item(pdutree, hf_cflow_pseudo_wire_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 251: /* pseudoWireControlWord */
            ti = proto_tree_add_item(pdutree, hf_cflow_pseudo_wire_control_word,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 252: /* ingressPhysicalInterface */
            ti = proto_tree_add_item(pdutree, hf_cflow_ingress_physical_interface,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 253: /* egressPhysicalInterface */
            ti = proto_tree_add_item(pdutree, hf_cflow_egress_physical_interface,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 254: /* postDot1qVlanId */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_dot1q_vlan_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 255: /* postDot1qCustomerVlanId */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_dot1q_customer_vlan_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 256: /* ethernetType */
            ti = proto_tree_add_item(pdutree, hf_cflow_ethernet_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 257: /* postIpPrecedence */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_ip_precedence,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 258: /* collectionTimeMilliseconds */
            ts.secs  = (time_t)(tvb_get_ntoh64(tvb, offset)/1000);
            ts.nsecs = (int)(tvb_get_ntoh64(tvb, offset)%1000) *1000000;
            ti = proto_tree_add_time(pdutree,
                                     hf_cflow_collection_time_milliseconds,
                                     tvb, offset, length, &ts);
            break;

        case 259: /* exportSctpStreamId */
            ti = proto_tree_add_item(pdutree, hf_cflow_export_sctp_stream_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 260: /* maxExportSeconds */
            ts.secs = tvb_get_ntohl(tvb, offset);
            ts.nsecs = 0;
            ti = proto_tree_add_time(pdutree, hf_cflow_max_export_seconds,
                                     tvb, offset, length, &ts);
            break;

        case 261: /* maxFlowEndSeconds */
            ts.secs = tvb_get_ntohl(tvb, offset);
            ts.nsecs = 0;
            ti = proto_tree_add_time(pdutree, hf_cflow_max_flow_end_seconds,
                                     tvb, offset, length, &ts);
            break;

        case 262: /* messageMD5Checksum */
            ti = proto_tree_add_item(pdutree, hf_cflow_message_md5_checksum,
                                     tvb, offset, length, ENC_NA);
            break;

        case 263: /* messageScope */
            ti = proto_tree_add_item(pdutree, hf_cflow_message_scope,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 264: /* minExportSeconds */
            ts.secs = tvb_get_ntohl(tvb, offset);
            ts.nsecs = 0;
            ti = proto_tree_add_time(pdutree, hf_cflow_min_export_seconds,
                                     tvb, offset, length, &ts);
            break;

        case 265: /* minFlowStartSeconds */
            ts.secs = tvb_get_ntohl(tvb, offset);
            ts.nsecs = 0;
            ti = proto_tree_add_time(pdutree, hf_cflow_min_flow_start_seconds,
                                     tvb, offset, length, &ts);
            break;

        case 266: /* opaqueOctets */
            ti = proto_tree_add_item(pdutree, hf_cflow_opaque_octets,
                                     tvb, offset, length, ENC_NA);
            break;

        case 267: /* sessionScope */
            ti = proto_tree_add_item(pdutree, hf_cflow_session_scope,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 268: /* maxFlowEndMicroseconds */
            ti = proto_tree_add_item(pdutree, hf_cflow_max_flow_end_microseconds,
                                     tvb, offset, length, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            break;

        case 269: /* maxFlowEndMilliseconds */
            ts.secs =  (time_t)(tvb_get_ntoh64(tvb, offset)/1000);
            ts.nsecs = (int)(tvb_get_ntoh64(tvb, offset)%1000) * 1000000;
            ti = proto_tree_add_time(pdutree, hf_cflow_max_flow_end_milliseconds,
                                     tvb, offset, length, &ts);
            break;

        case 270: /* maxFlowEndNanoseconds */
            ti = proto_tree_add_item(pdutree, hf_cflow_max_flow_end_nanoseconds,
                                     tvb, offset, length, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            break;

        case 271: /* minFlowStartMicroseconds */
            ti = proto_tree_add_item(pdutree, hf_cflow_min_flow_start_microseconds,
                                     tvb, offset, length, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            break;

        case 272: /* minFlowStartMilliseconds */
            ts.secs  = (tvb_get_ntohl(tvb, offset)/1000);
            ts.nsecs = (tvb_get_ntohl(tvb, offset)%1000) * 1000000;
            ti = proto_tree_add_time(pdutree, hf_cflow_min_flow_start_milliseconds,
                                     tvb, offset, length, &ts);
            break;

        case 273: /* minFlowStartNanoseconds */
            ti = proto_tree_add_item(pdutree, hf_cflow_min_flow_start_nanoseconds,
                                     tvb, offset, length, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            break;

        case 274: /* collectorCertificate */
            ti = proto_tree_add_item(pdutree, hf_cflow_collector_certificate,
                                     tvb, offset, length, ENC_NA);
            break;

        case 275: /* exporterCertificate */
            ti = proto_tree_add_item(pdutree, hf_cflow_exporter_certificate,
                                     tvb, offset, length, ENC_NA);
            break;

        case 276:
            ti = proto_tree_add_item(pdutree, hf_cflow_data_records_reliability,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 277:
            ti = proto_tree_add_item(pdutree, hf_cflow_observation_point_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 278:
            ti = proto_tree_add_item(pdutree, hf_cflow_new_connection_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 279:
            ti = proto_tree_add_item(pdutree, hf_cflow_connection_sum_duration_seconds,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 280:
            ti = proto_tree_add_item(pdutree, hf_cflow_connection_transaction_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 281:
            ti = proto_tree_add_item(pdutree, hf_cflow_post_nat_source_ipv6_address,
                                     tvb, offset, length, ENC_NA);
            break;

        case 282:
            ti = proto_tree_add_item(pdutree, hf_cflow_post_nat_destination_ipv6_address,
                                     tvb, offset, length, ENC_NA);
            break;

        case 283:
            ti = proto_tree_add_item(pdutree, hf_cflow_nat_pool_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 284:
            ti = proto_tree_add_item(pdutree, hf_cflow_nat_pool_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 285:
            ti = proto_tree_add_item(pdutree, hf_cflow_anonymization_flags,
                                     tvb, offset, length, ENC_NA);
            break;

        case 286:
            ti = proto_tree_add_item(pdutree, hf_cflow_anonymization_technique,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 287:
            ti = proto_tree_add_item(pdutree, hf_cflow_information_element_index,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 288:
            ti = proto_tree_add_item(pdutree, hf_cflow_p2p_technology,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 289:
            ti = proto_tree_add_item(pdutree, hf_cflow_tunnel_technology,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 290:
            ti = proto_tree_add_item(pdutree, hf_cflow_encrypted_technology,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 294:
            ti = proto_tree_add_item(pdutree, hf_cflow_bgp_validity_state,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 295:
            ti = proto_tree_add_item(pdutree, hf_cflow_ipsec_spi,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 296:
            ti = proto_tree_add_item(pdutree, hf_cflow_gre_key,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 297:
            ti = proto_tree_add_item(pdutree, hf_cflow_nat_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 298:
            ti = proto_tree_add_item(pdutree, hf_cflow_initiator_packets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 299:
            ti = proto_tree_add_item(pdutree, hf_cflow_responder_packets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 300:
            ti = proto_tree_add_item(pdutree, hf_cflow_observation_domain_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 301: /* selectionSequenceId */
            ti = proto_tree_add_item(pdutree, hf_cflow_selection_sequence_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 302: /* selectorId */
            ti = proto_tree_add_item(pdutree, hf_cflow_selector_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 303: /* informationElementId */
            ti = proto_tree_add_item(pdutree, hf_cflow_information_element_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 304: /* selectorAlgorithm */
            ti = proto_tree_add_item(pdutree, hf_cflow_selector_algorithm,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 305: /* samplingPacketInterval */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampling_packet_interval,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 306: /* samplingPacketSpace */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampling_packet_space,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 307: /* samplingTimeInterval */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampling_time_interval,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 308: /* samplingTimeSpace */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampling_time_space,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 309: /* samplingSize */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampling_size,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 310: /* samplingPopulation */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampling_population,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 311: /* samplingProbability */
            if (length == 4) {
                ti = proto_tree_add_item(pdutree, hf_cflow_sampling_probability_float32,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_sampling_probability_float64,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;

        case 312:
            ti = proto_tree_add_item(pdutree, hf_cflow_data_link_frame_size,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 313: /* SECTION_HEADER */
            ti = proto_tree_add_item(pdutree, hf_cflow_section_header,
                                     tvb, offset, length, ENC_NA);
            break;

        case 314: /* SECTION_PAYLOAD */
            ti = proto_tree_add_item(pdutree, hf_cflow_section_payload,
                                     tvb, offset, length, ENC_NA);
            break;

        case 315:
            ti = proto_tree_add_item(pdutree, hf_cflow_data_link_frame_section,
                                     tvb, offset, length, ENC_NA);
            break;

        case 316: /* mplsLabelStackSection */
            ti = proto_tree_add_item(pdutree, hf_cflow_mpls_label_stack_section,
                                     tvb, offset, length, ENC_NA);
            break;

        case 317: /* mplsPayloadPacketSection */
            ti = proto_tree_add_item(pdutree, hf_cflow_mpls_payload_packet_section,
                                     tvb, offset, length, ENC_NA);
            break;

        case 318: /* selectorIdTotalPktsObserved */
            ti = proto_tree_add_item(pdutree, hf_cflow_selector_id_total_pkts_observed,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 319: /* selectorIdTotalPktsSelected */
            ti = proto_tree_add_item(pdutree, hf_cflow_selector_id_total_pkts_selected,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 320: /* absoluteError */
            if (length == 4) {
                ti = proto_tree_add_item(pdutree, hf_cflow_absolute_error_float32,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_absolute_error_float64,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;

        case 321: /* relativeError */
            if (length == 4) {
                ti = proto_tree_add_item(pdutree, hf_cflow_relative_error_float32,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_relative_error_float64,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;

        case 322: /* observationTimeSeconds */
            ts.secs = tvb_get_ntohl(tvb, offset);
            ts.nsecs = 0;
            ti = proto_tree_add_time(pdutree, hf_cflow_observation_time_seconds,
                                     tvb, offset, length, &ts);
            break;

        case 323: /* observationTimeMilliseconds */
            ts.secs  = (time_t)(tvb_get_ntoh64(tvb, offset)/1000);
            ts.nsecs = (int)(tvb_get_ntoh64(tvb, offset)%1000) * 1000000;
            ti = proto_tree_add_time(pdutree, hf_cflow_observation_time_milliseconds,
                                     tvb, offset, length, &ts);
            break;

        case 324: /* observationTimeMicroseconds */
            ti = proto_tree_add_item(pdutree, hf_cflow_observation_time_microseconds,
                                     tvb, offset, length, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            break;

        case 325: /* observationTimeNanoseconds */
            ti = proto_tree_add_item(pdutree, hf_cflow_observation_time_nanoseconds,
                                     tvb, offset, length, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            break;

        case 326: /* digestHashValue */
            ti = proto_tree_add_item(pdutree, hf_cflow_digest_hash_value,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 327: /* hashIPPayloadOffset */
            ti = proto_tree_add_item(pdutree, hf_cflow_hash_ippayload_offset,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 328: /* hashIPPayloadSize */
            ti = proto_tree_add_item(pdutree, hf_cflow_hash_ippayload_size,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 329: /* hashOutputRangeMin */
            ti = proto_tree_add_item(pdutree, hf_cflow_hash_output_range_min,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 330: /* hashOutputRangeMax */
            ti = proto_tree_add_item(pdutree, hf_cflow_hash_output_range_max,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 331: /* hashSelectedRangeMin */
            ti = proto_tree_add_item(pdutree, hf_cflow_hash_selected_range_min,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 332: /* hashSelectedRangeMax */
            ti = proto_tree_add_item(pdutree, hf_cflow_hash_selected_range_max,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 333: /* hashDigestOutput */
            ti = proto_tree_add_item(pdutree, hf_cflow_hash_digest_output,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 334: /* hashInitialiserValue */
            ti = proto_tree_add_item(pdutree, hf_cflow_hash_initialiser_value,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 335: /* selectorName */
            ti = proto_tree_add_item(pdutree, hf_cflow_selector_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 336: /* upperCILimit */
            if (length == 4) {
                ti = proto_tree_add_item(pdutree, hf_cflow_upper_cilimit_float32,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_upper_cilimit_float64,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;

        case 337: /* lowerCILimit */
            if (length == 4) {
                ti = proto_tree_add_item(pdutree, hf_cflow_lower_cilimit_float32,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_lower_cilimit_float64,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;

        case 338: /* confidenceLevel */
            if (length == 4) {
                ti = proto_tree_add_item(pdutree, hf_cflow_confidence_level_float32,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_confidence_level_float64,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;

        case 339: /* informationElementDataType */
            ti = proto_tree_add_item(pdutree, hf_cflow_information_element_data_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 340: /* informationElementDescription */
            ti = proto_tree_add_item(pdutree, hf_cflow_information_element_description,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 341: /* informationElementName */
            {
                const guint8 *string;
                ti = proto_tree_add_item_ret_string(pdutree, hf_cflow_information_element_name,
                                         tvb, offset, length, ENC_UTF_8|ENC_NA, wmem_packet_scope(), &string);
                /* Add name of element to root for this flow */
                proto_item_append_text(pdutree, " [%s]", string);
            }
            break;

        case 342: /* informationElementRangeBegin */
            ti = proto_tree_add_item(pdutree, hf_cflow_information_element_range_begin,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 343: /* informationElementRangeEnd */
            ti = proto_tree_add_item(pdutree, hf_cflow_information_element_range_end,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 344: /* informationElementSemantics */
            ti = proto_tree_add_item(pdutree, hf_cflow_information_element_semantics,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 345: /* informationElementUnits */
            ti = proto_tree_add_item(pdutree, hf_cflow_information_element_units,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 346: /* privateEnterpriseNumber */
            ti = proto_tree_add_item(pdutree, hf_cflow_private_enterprise_number,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 347: /* virtualStationInterfaceId */
            ti = proto_tree_add_item(pdutree, hf_cflow_virtual_station_interface_id,
                                     tvb, offset, length, ENC_NA);
            break;

        case 348: /* virtualStationInterfaceName */
            ti = proto_tree_add_item(pdutree, hf_cflow_virtual_station_interface_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 349: /* virtualStationUUID */
            ti = proto_tree_add_item(pdutree, hf_cflow_virtual_station_uuid,
                                     tvb, offset, length, ENC_NA);
            break;

        case 350: /* virtualStationName */
            ti = proto_tree_add_item(pdutree, hf_cflow_virtual_station_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 351: /* layer2SegmentId */
            ti = proto_tree_add_item(pdutree, hf_cflow_layer2_segment_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 416:
        case 352: /* layer2OctetDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_layer2_octet_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 419:
        case 353: /* layer2OctetTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_layer2_octet_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 354: /* ingressUnicastPacketTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_ingress_unicast_packet_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 355: /* ingressMulticastPacketTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_ingress_multicast_packet_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 356: /* ingressBroadcastPacketTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_ingress_broadcast_packet_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 357: /* egressUnicastPacketTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_egress_unicast_packet_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 358: /* egressBroadcastPacketTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_egress_broadcast_packet_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 359: /* monitoringIntervalStartMilliSeconds */
            ts.secs  = (time_t)(tvb_get_ntoh64(tvb, offset)/1000);
            ts.nsecs = (int)(tvb_get_ntoh64(tvb, offset)%1000) * 1000000;
            ti = proto_tree_add_time(pdutree, hf_cflow_monitoring_interval_start_milliseconds,
                                     tvb, offset, length, &ts);
            break;

        case 360: /* monitoringIntervalEndMilliSeconds */
            ts.secs  = (time_t)(tvb_get_ntoh64(tvb, offset)/1000);
            ts.nsecs = (int)(tvb_get_ntoh64(tvb, offset)%1000) * 1000000;
            ti = proto_tree_add_time(pdutree, hf_cflow_monitoring_interval_end_milliseconds,
                                     tvb, offset, length, &ts);
            break;

        case 361: /* portRangeStart */
            ti = proto_tree_add_item(pdutree, hf_cflow_port_range_start,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 362: /* portRangeEnd */
            ti = proto_tree_add_item(pdutree, hf_cflow_port_range_end,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 363: /* portRangeStepSize */
            ti = proto_tree_add_item(pdutree, hf_cflow_port_range_step_size,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 364: /* portRangeNumPorts */
            ti = proto_tree_add_item(pdutree, hf_cflow_port_range_num_ports,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 365: /* staMacAddress */
            ti = proto_tree_add_item(pdutree, hf_cflow_sta_mac_address,
                                     tvb, offset, length, ENC_NA);
            break;

        case 366: /* staIPv4Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_sta_ipv4_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 367: /* wtpMacAddress */
            ti = proto_tree_add_item(pdutree, hf_cflow_wtp_mac_address,
                                     tvb, offset, length, ENC_NA);
            break;

        case 368: /* ingressInterfaceType */
            ti = proto_tree_add_item(pdutree, hf_cflow_ingress_interface_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 369: /* egressInterfaceType */
            ti = proto_tree_add_item(pdutree, hf_cflow_egress_interface_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 370: /* rtpSequenceNumber */
            ti = proto_tree_add_item(pdutree, hf_cflow_rtp_sequence_number,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 371: /* userName */
            ti = proto_tree_add_item(pdutree, hf_cflow_user_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 372: /* applicationCategoryName */
            ti = proto_tree_add_item(pdutree, hf_cflow_application_category_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 373: /* applicationSubCategoryName */
            ti = proto_tree_add_item(pdutree, hf_cflow_application_sub_category_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 374: /* applicationGroupName */
            ti = proto_tree_add_item(pdutree, hf_cflow_application_group_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;

        case 375: /* originalFlowsPresent */
            ti = proto_tree_add_item(pdutree, hf_cflow_original_flows_present,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 376: /* originalFlowsInitiated */
            ti = proto_tree_add_item(pdutree, hf_cflow_original_flows_initiated,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 377: /* originalFlowsCompleted */
            ti = proto_tree_add_item(pdutree, hf_cflow_original_flows_completed,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 378: /* distinctCountOfSourceIPAddress */
            ti = proto_tree_add_item(pdutree, hf_cflow_distinct_count_of_source_ip_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 379: /* distinctCountOfDestinationIPAddress */
            ti = proto_tree_add_item(pdutree, hf_cflow_distinct_count_of_destinationip_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 380: /* distinctCountOfSourceIPv4Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_distinct_count_of_source_ipv4_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 381: /* distinctCountOfDestinationIPv4Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_distinct_count_of_destination_ipv4_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 382: /* distinctCountOfSourceIPv6Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_distinct_count_of_source_ipv6_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 383: /* distinctCountOfDestinationIPv6Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_distinct_count_of_destination_ipv6_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 384: /* valueDistributionMethod */
            ti = proto_tree_add_item(pdutree, hf_cflow_value_distribution_method,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 385: /* rfc3550JitterMilliseconds */
            ti = proto_tree_add_item(pdutree, hf_cflow_rfc3550_jitter_milliseconds,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 386: /* rfc3550JitterMicroseconds */
            ti = proto_tree_add_item(pdutree, hf_cflow_rfc3550_jitter_microseconds,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 387: /* rfc3550JitterNanoseconds */
            ti = proto_tree_add_item(pdutree, hf_cflow_rfc3550_jitter_nanoseconds,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 388: /* dot1qDEI */
            ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_dei,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 389: /* dot1qCustomerDEI */
            ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_customer_dei,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 390: /* flowSelectorAlgorithm */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_selector_algorithm,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 391: /* flowSelectedOctetDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_selected_octet_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 392: /* flowSelectedPacketDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_selected_packet_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 393: /* flowSelectedFlowDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_selected_flow_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 394: /* selectorIDTotalFlowsObserved */
            ti = proto_tree_add_item(pdutree, hf_cflow_selectorid_total_flows_observed,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 395: /* selectorIDTotalFlowsSelected */
            ti = proto_tree_add_item(pdutree, hf_cflow_selectorid_total_flows_selected,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 396: /* samplingFlowInterval */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampling_flow_interval,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 397: /* samplingFlowSpacing */
            ti = proto_tree_add_item(pdutree, hf_cflow_sampling_flow_spacing,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 398: /* flowSamplingTimeInterval */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_sampling_time_interval,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 399: /* flowSamplingTimeSpacing */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_sampling_time_spacing,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 400: /* hashFlowDomain */
            ti = proto_tree_add_item(pdutree, hf_cflow_hash_flow_domain,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 401: /* transportOctetDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_transport_octet_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 402: /* transportPacketDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_transport_packet_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 403: /* originalExporterIPv4Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_original_exporter_ipv4_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 404: /* originalExporterIPv6Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_original_exporter_ipv6_address,
                                     tvb, offset, length, ENC_NA);
            break;

        case 405: /* originalObservationDomainId */
            ti = proto_tree_add_item(pdutree, hf_cflow_original_observation_domain_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 406: /* intermediateProcessId */
            ti = proto_tree_add_item(pdutree, hf_cflow_intermediate_process_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 407: /* ignoredDataRecordTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_ignored_data_record_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 408: /* dataLinkFrameType */
            ti = proto_tree_add_item(pdutree, hf_cflow_data_link_frame_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 409: /* sectionOffset */
            ti = proto_tree_add_item(pdutree, hf_cflow_section_offset,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 410: /* sectionExportedOctets */
            ti = proto_tree_add_item(pdutree, hf_cflow_section_exported_octets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 411: /* dot1qServiceInstanceTag */
            ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_service_instance_tag,
                                     tvb, offset, length, ENC_NA);
            break;

        case 412: /* dot1qServiceInstanceId */
            ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_service_instance_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 413: /* dot1qServiceInstancePriority */
            ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_service_instance_priority,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 414: /* dot1qCustomerSourceMacAddress */
            ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_customer_source_mac_address,
                                     tvb, offset, length, ENC_NA);
            break;

        case 415: /* dot1qCustomerDestinationMacAddress */
            ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_customer_destination_mac_address,
                                     tvb, offset, length, ENC_NA);
            break;

        case 417: /* postLayer2OctetDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_layer2_octet_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 418: /* postMCastLayer2OctetDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_postm_cast_layer2_octet_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 420: /* postLayer2OctetTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_post_layer2_octet_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 421: /* postMCastLayer2OctetTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_postm_cast_layer2_octet_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 422: /* minimumLayer2TotalLength */
            ti = proto_tree_add_item(pdutree, hf_cflow_minimum_layer2_total_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 423: /* maximumLayer2TotalLength */
            ti = proto_tree_add_item(pdutree, hf_cflow_maximum_layer2_total_length,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 424: /* droppedLayer2OctetDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_dropped_layer2_octet_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 425: /* droppedLayer2OctetTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_dropped_layer2_octet_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 426: /* ignoredLayer2OctetTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_ignored_layer2_octet_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 427: /* notSentLayer2OctetTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_not_sent_layer2_octet_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 428: /* layer2OctetDeltaSumOfSquares */
            ti = proto_tree_add_item(pdutree, hf_cflow_layer2_octet_delta_sum_of_squares,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 429: /* layer2OctetTotalSumOfSquares */
            ti = proto_tree_add_item(pdutree, hf_cflow_layer2_octet_total_sum_of_squares,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 430: /* layer2FrameDeltaCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_layer2_frame_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 431: /* layer2FrameTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_layer2_frame_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 432: /* pseudoWireDestinationIPv4Address */
            ti = proto_tree_add_item(pdutree, hf_cflow_pseudo_wire_destination_ipv4_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 433: /* ignoredLayer2FrameTotalCount */
            ti = proto_tree_add_item(pdutree, hf_cflow_ignored_layer2_frame_total_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;


        case 34000: /* cts_sgt_source_tag */
            ti = proto_tree_add_item(pdutree, hf_cflow_cts_sgt_source_tag,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 34001: /* cts_sgt_destination_tag */
            ti = proto_tree_add_item(pdutree, hf_cflow_cts_sgt_destination_tag,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 34002: /* cts_sgt_source_name */
            ti = proto_tree_add_item(pdutree, hf_cflow_cts_sgt_source_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;

        case 34003: /* cts_sgt_destination_name */
            ti = proto_tree_add_item(pdutree, hf_cflow_cts_sgt_destination_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;

        case 37000: /* packets_dropped */
            ti = proto_tree_add_item(pdutree, hf_cflow_packets_dropped,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 37003: /* byte_rate */
            ti = proto_tree_add_item(pdutree, hf_cflow_byte_rate,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 37004: /* application_media_bytes */
            ti = proto_tree_add_item(pdutree, hf_cflow_application_media_bytes,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 37006: /* application_media_byte_rate */
            ti = proto_tree_add_item(pdutree, hf_cflow_application_media_byte_rate,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 37007: /* application_media_packets */
            ti = proto_tree_add_item(pdutree, hf_cflow_application_media_packets,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 37009: /* application_media_packet_rate */
            ti = proto_tree_add_item(pdutree, hf_cflow_application_media_packet_rate,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 37011: /* application_media_event */
            ti = proto_tree_add_item(pdutree, hf_cflow_application_media_event,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 37012: /* monitor_event */
            ti = proto_tree_add_item(pdutree, hf_cflow_monitor_event,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case 37013: /* timestamp_interval */
            ti = proto_tree_add_item(pdutree, hf_cflow_timestamp_interval,
                                     tvb, offset, length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
            break;
        case 37014: /* transport_packets_expected */
            ti = proto_tree_add_item(pdutree, hf_cflow_transport_packets_expected,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 37016: /* transport_round_trip_time */
            if (tvb_get_ntohl(tvb, offset) == 0xFFFFFFFF ) {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_round_trip_time_string,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                /* value is in microseconds, adjust to nanoseconds*/
                ts.secs =0;
                ts.nsecs= tvb_get_ntohl(tvb, offset) * 1000;
                ti = proto_tree_add_time(pdutree, hf_cflow_transport_round_trip_time,
                                         tvb, offset, length, &ts);
            }
            break;
        case 37017: /* transport_event_packet_loss */
            ti = proto_tree_add_item(pdutree, hf_cflow_transport_event_packet_loss,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 37019: /* transport_packets_lost */
            if (tvb_get_ntohl(tvb, offset) == 0xFFFFFFFF ) {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_packets_lost_string,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_packets_lost,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;
        case 37021: /* transport_packets_lost_rate */
            if (tvb_get_ntohl(tvb, offset) == 0xFFFF ) {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_packets_lost_rate_string,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_packets_lost_rate,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;
        case 37022: /* transport_rtp_ssrc */
            ti = proto_tree_add_item(pdutree, hf_cflow_transport_rtp_ssrc,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 37023: /* transport_rtp_jitter_mean */
            if (tvb_get_ntohl(tvb, offset) == 0xFFFFFFFF ) {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_rtp_jitter_mean_string,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                /* value is in microseconds, adjust to nanoseconds*/
                ts.secs =0;
                ts.nsecs= tvb_get_ntohl(tvb, offset) * 1000;

                ti = proto_tree_add_time(pdutree, hf_cflow_transport_rtp_jitter_mean,
                                         tvb, offset, length, &ts);
            }
            break;
        case 37024: /* transport_rtp_jitter_min */
            if (tvb_get_ntohl(tvb, offset) == 0xFFFFFFFF ) {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_rtp_jitter_min_string,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                /* value is in microseconds, adjust to nanoseconds*/
                ts.secs =0;
                ts.nsecs= tvb_get_ntohl(tvb, offset) * 1000;
                ti = proto_tree_add_time(pdutree, hf_cflow_transport_rtp_jitter_min,
                                         tvb, offset, length, &ts);
            }
            break;
        case 37025: /* transport_rtp_jitter_max */
            if (tvb_get_ntohl(tvb, offset) == 0xFFFFFFFF ) {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_rtp_jitter_max_string,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                /* value is in microseconds, adjust to nanoseconds*/
                ts.secs =0;
                ts.nsecs= tvb_get_ntohl(tvb, offset) * 1000;
                ti = proto_tree_add_time(pdutree, hf_cflow_transport_rtp_jitter_max,
                                         tvb, offset, length, &ts);
            }
            break;
        case 37041: /* transport_payload_type */
            if (tvb_get_guint8(tvb, offset) == 0xFF) {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_rtp_payload_type_string,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_rtp_payload_type,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;
        case 37071: /* bytes_out_of_order */
            if (tvb_get_ntoh64(tvb, offset) == G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
                /* need to add custom code to show "Not Measured"  */
                proto_tree_add_expert_format(pdutree, NULL, &ei_transport_bytes_out_of_order,
                                             tvb, offset, 8,
                                             "Transport Bytes Out of Order: Not Measured (0x%"G_GINT64_MODIFIER"x)",
                                             tvb_get_ntoh64(tvb, offset));
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_bytes_out_of_order,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_bytes_out_of_order,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;
        case 37074: /* packets_out_of_order */
            if (tvb_get_ntohl(tvb, offset) == 0xFFFFFFFF) {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_packets_out_of_order_string,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_bytes_out_of_order,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;
        case 37083: /* tcp_window_size_min */
            if (tvb_get_ntohl(tvb, offset) == 0xFFFFFFFF) {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_tcp_window_size_min_string,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_tcp_window_size_min,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;

        case 37084: /* tcp_window_size_max */
            if (tvb_get_ntohl(tvb, offset) == 0xFFFFFFFF) {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_tcp_window_size_max_string,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_tcp_window_size_max,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;

        case 37085: /* tcp_window_size_mean */
            if (tvb_get_ntohl(tvb, offset) == 0xFFFFFFFF) {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_tcp_window_size_mean_string,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_tcp_window_size_mean,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;
        case 37086: /* tcp_maximum_segment_size */
            if (tvb_get_ntohs(tvb, offset) == 0xFFFF) {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_tcp_maximum_segment_size_string,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            } else {
                ti = proto_tree_add_item(pdutree, hf_cflow_transport_tcp_maximum_segment_size,
                                         tvb, offset, length, ENC_BIG_ENDIAN);
            }
            break;
            /* Ericsson SE NAT Logging */
        case 24628: /* natContextId */
            ti = proto_tree_add_item(pdutree, hf_cflow_nat_context_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 24629: /* natContextName */
            ti = proto_tree_add_item(pdutree, hf_cflow_nat_context_name,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case 24630: /* natAssignTime */
            ts.secs = tvb_get_ntohl(tvb, offset);
            ts.nsecs = 0;
            ti = proto_tree_add_time(pdutree, hf_cflow_nat_assign_time,
                                     tvb, offset, length, &ts);
            break;
        case 24631: /* natUnAssignTime */
            ts.secs = tvb_get_ntohl(tvb, offset);
            ts.nsecs = 0;
            ti = proto_tree_add_time(pdutree, hf_cflow_nat_unassign_time,
                                     tvb, offset, length, &ts);
            break;
        case 24632: /* natInternalAddr */
            ti = proto_tree_add_item(pdutree, hf_cflow_nat_int_addr,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 24633: /* natExternalAddr */
            ti = proto_tree_add_item(pdutree, hf_cflow_nat_ext_addr,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 24634: /* natExternalPortFirst */
            ti = proto_tree_add_item(pdutree, hf_cflow_nat_ext_port_first,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 24635: /* natExternalPortLast */
            ti = proto_tree_add_item(pdutree, hf_cflow_nat_ext_port_last,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

            /* Cisco ASA 5500 Series */
        case 33000: /* NF_F_INGRESS_ACL_ID */
            proto_tree_add_item(pdutree, hf_cflow_ingress_acl_id,
                                tvb, offset, length, ENC_NA);
            break;
        case 33001: /* NF_F_EGRESS_ACL_ID */
            proto_tree_add_item(pdutree, hf_cflow_egress_acl_id,
                                tvb, offset, length, ENC_NA);
            break;
        case 33002: /* NF_F_FW_EXT_EVENT */
            proto_tree_add_item(pdutree, hf_cflow_fw_ext_event,
                                tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case 40000: /* NF_F_USERNAME[_MAX] */
            proto_tree_add_item(pdutree, hf_cflow_aaa_username,
                                tvb, offset, length, ENC_ASCII|ENC_NA);
            break;

            /* CACE Technologies */
        case VENDOR_CACE << 16 | 0: /* caceLocalIPv4Address */
            ti = proto_tree_add_item(pdutree, hf_pie_cace_local_ipv4_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            set_address_tvb(&local_addr, AT_IPv4, 4, tvb, offset);
            got_flags |= GOT_LOCAL_ADDR;
            break;

        case VENDOR_CACE << 16 | 1: /* caceRemoteIPv4Address */
            ti = proto_tree_add_item(pdutree, hf_pie_cace_remote_ipv4_address,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            set_address_tvb(&remote_addr, AT_IPv4, 4, tvb, offset);
            got_flags |= GOT_REMOTE_ADDR;
            break;

        case VENDOR_CACE << 16 | 2: /* caceLocalIPv6Address */
            ti = proto_tree_add_item(pdutree, hf_pie_cace_local_ipv6_address,
                                     tvb, offset, length, ENC_NA);
            set_address_tvb(&local_addr, AT_IPv6, 16, tvb, offset);
            got_flags |= GOT_LOCAL_ADDR;
            break;

        case VENDOR_CACE << 16 | 3: /* caceRemoteIPv6Address */
            ti = proto_tree_add_item(pdutree, hf_pie_cace_remote_ipv6_address,
                                     tvb, offset, length, ENC_NA);
            set_address_tvb(&remote_addr, AT_IPv6, 16, tvb, offset);
            got_flags |= GOT_REMOTE_ADDR;
            break;

        case VENDOR_CACE << 16 | 4: /* caceLocalTransportPort */
            ti = proto_tree_add_item(pdutree, hf_pie_cace_local_port,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            local_port = tvb_get_ntohs(tvb, offset);
            got_flags |= GOT_LOCAL_PORT;
            break;

        case VENDOR_CACE << 16 | 5: /* caceRemoteTransportPort */
            ti = proto_tree_add_item(pdutree, hf_pie_cace_remote_port,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            remote_port = tvb_get_ntohs(tvb, offset);
            got_flags |= GOT_REMOTE_PORT;
            break;

        case VENDOR_CACE << 16 | 6: /* caceLocalIPv4id */
            ti = proto_tree_add_item(pdutree, hf_pie_cace_local_ipv4_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            /*ipv4_id = tvb_get_ntohs(tvb, offset);*/
            /*got_flags |= GOT_IPv4_ID;*/
            break;

        case VENDOR_CACE << 16 | 7: /* caceLocalICMPid */
            ti = proto_tree_add_item(pdutree, hf_pie_cace_local_icmp_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            /*icmp_id = tvb_get_ntohs(tvb, offset);*/
            /*got_flags |= GOT_ICMP_ID;*/
            break;

        case VENDOR_CACE << 16 | 8: /* caceLocalProcessUserId */
            ti = proto_tree_add_item(pdutree, hf_pie_cace_local_uid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            uid = tvb_get_ntohl(tvb, offset);
            got_flags |= GOT_UID;
            break;

        case VENDOR_CACE << 16 | 9: /* caceLocalProcessId */
            ti = proto_tree_add_item(pdutree, hf_pie_cace_local_pid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            pid = tvb_get_ntohl(tvb, offset);
            got_flags |= GOT_PID;
            break;

        case VENDOR_CACE << 16 | 10: /* caceLocalProcessUserName */
            uname_len = tvb_get_guint8(tvb, offset);
            uname_str = tvb_format_text(tvb, offset+1, uname_len);
            proto_tree_add_item(pdutree, hf_pie_cace_local_username_len,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            ti = proto_tree_add_string(pdutree, hf_pie_cace_local_username,
                                       tvb, offset+1, uname_len, uname_str);
            length = uname_len + 1;
            got_flags |= GOT_USERNAME;
            break;

        case VENDOR_CACE << 16 | 11: /* caceLocalProcessCommand */
            cmd_len = tvb_get_guint8(tvb, offset);
            cmd_str = tvb_format_text(tvb, offset+1, cmd_len);
            proto_tree_add_item(pdutree, hf_pie_cace_local_cmd_len,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            ti = proto_tree_add_string(pdutree, hf_pie_cace_local_cmd,
                                       tvb, offset+1, cmd_len, cmd_str);
            length = cmd_len + 1;
            got_flags |= GOT_COMMAND;
            break;

            /* START NTOP */
        case (NTOP_BASE + 80):           /* FRAGMENTED */
        case ((VENDOR_NTOP << 16) | 80): /* FRAGMENTED */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_fragmented,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 81):           /* FINGERPRINT */
        case ((VENDOR_NTOP << 16) | 81): /* FINGERPRINT */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_fingerprint,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 82):           /* CLIENT_NW_DELAY_SEC */
        case ((VENDOR_NTOP << 16) | 82): /* CLIENT_NW_DELAY_SEC */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_client_nw_delay_sec,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 83): /*           /\* CLIENT_NW_DELAY_USEC *\/ */
        case ((VENDOR_NTOP << 16) | 83): /* CLIENT_NW_DELAY_USEC */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_client_nw_delay_usec,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 84):           /* SERVER_NW_DELAY_SEC */
        case ((VENDOR_NTOP << 16) | 84): /* SERVER_NW_DELAY_SEC */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_server_nw_delay_sec,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 85):           /* SERVER_NW_DELAY_USEC */
        case ((VENDOR_NTOP << 16) | 85): /* SERVER_NW_DELAY_USEC */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_server_nw_delay_usec,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 86):           /* APPL_LATENCY_SEC */
        case ((VENDOR_NTOP << 16) | 86): /* APPL_LATENCY_SEC */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_appl_latency_sec,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 87):           /* APPL_LATENCY_USEC */
        case ((VENDOR_NTOP << 16) | 87): /* APPL_LATENCY_USEC */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_appl_latency_sec,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 98):           /* ICMP_FLAGS */
        case ((VENDOR_NTOP << 16) | 98): /* ICMP_FLAGS */
            /* Cumulative of all flow ICMP types */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_icmp_flags,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 101):           /* SRC_IP_COUNTRY */
        case ((VENDOR_NTOP << 16) | 101): /* SRC_IP_COUNTRY */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_src_ip_country,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case (NTOP_BASE + 102):           /* SRC_IP_CITY */
        case ((VENDOR_NTOP << 16) | 102): /* SRC_IP_CITY */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_src_ip_city,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case (NTOP_BASE + 103):           /* DST_IP_COUNTRY */
        case ((VENDOR_NTOP << 16) | 103): /* DST_IP_COUNTRY */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_dst_ip_country,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case (NTOP_BASE + 104):           /* DST_IP_CITY */
        case ((VENDOR_NTOP << 16) | 104): /* DST_IP_CITY */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_dst_ip_city,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case (NTOP_BASE + 105):           /* FLOW_PROTO_PORT */
        case ((VENDOR_NTOP << 16) | 105): /* FLOW_PROTO_PORT */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_flow_proto_port,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case (NTOP_BASE + 106):           /* TUNNEL_ID */
        case ((VENDOR_NTOP << 16) | 106): /* TUNNEL_ID */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_tunnel_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 107):           /* LONGEST_FLOW_PKT */
        case ((VENDOR_NTOP << 16) | 107): /* LONGEST_FLOW_PKT */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_longest_flow_pkt,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 108):           /* SHORTEST_FLOW_PKT */
        case ((VENDOR_NTOP << 16) | 108): /* SHORTEST_FLOW_PKT */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_shortest_flow_pkt,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 109):           /* RETRANSMITTED_IN_PKTS */
        case ((VENDOR_NTOP << 16) | 109): /* RETRANSMITTED_IN_PKTS */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_retransmitted_in_pkts,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 110):           /* RETRANSMITTED_OUT_PKTS */
        case ((VENDOR_NTOP << 16) | 110): /* RETRANSMITTED_OUT_PKTS */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_retransmitted_out_pkts,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 111):           /* OOORDER_IN_PKTS */
        case ((VENDOR_NTOP << 16) | 111): /* OOORDER_IN_PKTS */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_ooorder_in_pkts,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 112):           /* OOORDER_OUT_PKTS */
        case ((VENDOR_NTOP << 16) | 112): /* OOORDER_OUT_PKTS */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_ooorder_out_pkts,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 113):           /* UNTUNNELED_PROTOCOL */
        case ((VENDOR_NTOP << 16) | 113): /* UNTUNNELED_PROTOCOL */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_untunneled_protocol,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 114):           /* UNTUNNELED_IPV4_SRC_ADDR */
        case ((VENDOR_NTOP << 16) | 114): /* UNTUNNELED_IPV4_SRC_ADDR */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_untunneled_ipv4_src_addr,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 115):           /* UNTUNNELED_L4_SRC_PORT */
        case ((VENDOR_NTOP << 16) | 115): /* UNTUNNELED_L4_SRC_PORT */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_untunneled_l4_src_port,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 116):           /* UNTUNNELED_IPV4_DST_ADDR */
        case ((VENDOR_NTOP << 16) | 116): /* UNTUNNELED_IPV4_DST_ADDR */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_untunneled_ipv4_dst_addr,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 117):           /* UNTUNNELED_L4_DST_PORT */
        case ((VENDOR_NTOP << 16) | 117): /* UNTUNNELED_L4_DST_PORT */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_untunneled_l4_dst_port,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case (NTOP_BASE + 120):           /* DUMP_PATH */
        case ((VENDOR_NTOP << 16) | 120): /* DUMP_PATH */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_dump_path,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;

        case (NTOP_BASE + 130):           /* SIP_CALL_ID */
        case ((VENDOR_NTOP << 16) | 130): /* SIP_CALL_ID */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_ntop_sip_call_id,
                                       tvb, offset, length, gen_str);
            break;
        case (NTOP_BASE + 131):           /* SIP_CALLING_PARTY */
        case ((VENDOR_NTOP << 16) | 131): /* SIP_CALLING_PARTY */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_ntop_sip_calling_party,
                                       tvb, offset, length, gen_str);
            break;
        case (NTOP_BASE + 132):           /* SIP_CALLED_PARTY */
        case ((VENDOR_NTOP << 16) | 132): /* SIP_CALLED_PARTY */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_ntop_sip_called_party,
                                       tvb, offset, length, gen_str);
            break;
        case (NTOP_BASE + 133):           /* SIP_RTP_CODECS */
        case ((VENDOR_NTOP << 16) | 133): /* SIP_RTP_CODECS */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_ntop_sip_rtp_codecs,
                                       tvb, offset, length, gen_str);
            break;
        case (NTOP_BASE + 134):           /* SIP_INVITE_TIME */
        case ((VENDOR_NTOP << 16) | 134): /* SIP_INVITE_TIME */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_sip_invite_time,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 135):           /* SIP_TRYING_TIME */
        case ((VENDOR_NTOP << 16) | 135): /* SIP_TRYING_TIME */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_sip_trying_time,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 136):           /* SIP_RINGING_TIME */
        case ((VENDOR_NTOP << 16) | 136): /* SIP_RINGING_TIME */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_sip_ringing_time,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 137):           /* SIP_OK_TIME */
        case ((VENDOR_NTOP << 16) | 137): /* SIP_OK_TIME */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_sip_ok_time,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 138):           /* SIP_BYE_TIME */
        case ((VENDOR_NTOP << 16) | 138): /* SIP_BYE_TIME */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_sip_bye_time,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 139):           /* SIP_RTP_SRC_IP */
        case ((VENDOR_NTOP << 16) | 139): /* SIP_RTP_SRC_IP */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_sip_rtp_src_ip,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 140):           /* SIP_RTP_SRC_PORT */
        case ((VENDOR_NTOP << 16) | 140): /* SIP_RTP_SRC_PORT */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_sip_rtp_src_port,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 141):           /* SIP_RTP_DST_IP */
        case ((VENDOR_NTOP << 16) | 141): /* SIP_RTP_DST_IP */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_sip_rtp_dst_ip,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 142):           /* SIP_RTP_DST_PORT */
        case ((VENDOR_NTOP << 16) | 142): /* SIP_RTP_DST_PORT */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_sip_rtp_dst_port,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 150):           /* RTP_FIRST_SSRC */
        case ((VENDOR_NTOP << 16) | 150): /* RTP_FIRST_SSRC */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_rtp_first_ssrc,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 151):           /* RTP_FIRST_TS */
        case ((VENDOR_NTOP << 16) | 151): /* RTP_FIRST_TS */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_rtp_first_ts,
                                     tvb, offset, length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 152):           /* RTP_LAST_SSRC */
        case ((VENDOR_NTOP << 16) | 152): /* RTP_LAST_SSRC */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_rtp_last_ssrc,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 153):           /* RTP_LAST_TS */
        case ((VENDOR_NTOP << 16) | 153): /* RTP_LAST_TS */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_rtp_last_ts,
                                     tvb, offset, length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 154):           /* RTP_IN_JITTER */
        case ((VENDOR_NTOP << 16) | 154): /* RTP_IN_JITTER */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_rtp_in_jitter,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 155):           /* RTP_OUT_JITTER */
        case ((VENDOR_NTOP << 16) | 155): /* RTP_OUT_JITTER */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_rtp_out_jitter,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 156):           /* RTP_IN_PKT_LOST */
        case ((VENDOR_NTOP << 16) | 156): /* RTP_IN_PKT_LOST */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_rtp_in_pkt_lost,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 157):           /* RTP_OUT_PKT_LOST */
        case ((VENDOR_NTOP << 16) | 157): /* RTP_OUT_PKT_LOST */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_rtp_out_pkt_lost,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 158):           /* RTP_OUT_PAYLOAD_TYPE */
        case ((VENDOR_NTOP << 16) | 158): /* RTP_OUT_PAYLOAD_TYPE */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_rtp_out_payload_type,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 159):           /* RTP_IN_MAX_DELTA */
        case ((VENDOR_NTOP << 16) | 159): /* RTP_IN_MAX_DELTA */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_rtp_in_max_delta,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 160):           /* RTP_OUT_MAX_DELTA */
        case ((VENDOR_NTOP << 16) | 160): /* RTP_OUT_MAX_DELTA */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_rtp_out_max_delta,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 168):           /* PROC_ID */
        case ((VENDOR_NTOP << 16) | 168): /* PROC_ID */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_proc_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case (NTOP_BASE + 169):           /* PROC_NAME */
        case ((VENDOR_NTOP << 16) | 169): /* PROC_NAME */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_proc_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case (NTOP_BASE + 180):           /* HTTP_URL */
        case ((VENDOR_NTOP << 16) | 180): /* HTTP_URL */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_ntop_http_url,
                                       tvb, offset, length, gen_str);
            break;
        case (NTOP_BASE + 181):           /* HTTP_RET_CODE */
        case ((VENDOR_NTOP << 16) | 181): /* HTTP_RET_CODE */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_http_ret_code,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;


        case (NTOP_BASE + 182):           /* HTTP_REFERER */
        case ((VENDOR_NTOP << 16) | 182): /* HTTP_REFERER */
            break;
        case (NTOP_BASE + 183):           /* HTTP_UA */
        case ((VENDOR_NTOP << 16) | 183): /* HTTP_UA */
            break;
        case (NTOP_BASE + 184):           /* HTTP_MIME */
        case ((VENDOR_NTOP << 16) | 184): /* HTTP_MIME */
            break;

        case (NTOP_BASE + 185):           /* SMTP_MAIL_FROM */
        case ((VENDOR_NTOP << 16) | 185): /* SMTP_MAIL_FROM */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_ntop_smtp_mail_from,
                                       tvb, offset, length, gen_str);
            break;
        case (NTOP_BASE + 186):           /* SMTP_RCPT_TO */
        case ((VENDOR_NTOP << 16) | 186): /* SMTP_RCPT_TO */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_ntop_smtp_rcpt_to,
                                       tvb, offset, length, gen_str);
            break;

        case (NTOP_BASE + 190):           /* FLOW_ID */
        case ((VENDOR_NTOP << 16) | 190): /* FLOW_ID */
            ti = proto_tree_add_item(pdutree, hf_cflow_flow_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case (NTOP_BASE + 195):           /* MYSQL_SERVER_VERSION */
        case ((VENDOR_NTOP << 16) | 195): /* MYSQL_SERVER_VERSION */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_ntop_mysql_server_version,
                                       tvb, offset, length, gen_str);
            break;
        case (NTOP_BASE + 196):           /* MYSQL_USERNAME */
        case ((VENDOR_NTOP << 16) | 196): /* MYSQL_USERNAME */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_ntop_mysql_username,
                                       tvb, offset, length, gen_str);
            break;
        case (NTOP_BASE + 197):           /* MYSQL_DB */
        case ((VENDOR_NTOP << 16) | 197): /* MYSQL_DB */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_ntop_mysql_db,
                                       tvb, offset, length, gen_str);
            break;
        case (NTOP_BASE + 198):           /* MYSQL_QUERY */
        case ((VENDOR_NTOP << 16) | 198): /* MYSQL_QUERY */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_ntop_mysql_query,
                                       tvb, offset, length, gen_str);
            break;
        case (NTOP_BASE + 199):           /* MYSQL_RESPONSE */
        case ((VENDOR_NTOP << 16) | 199): /* MYSQL_RESPONSE */
            ti = proto_tree_add_item(pdutree, hf_pie_ntop_mysql_response,
                                     tvb, offset, length, ENC_BIG_ENDIAN);

            break;

            /* END NTOP */

            /* START Plixer International */
        case ((VENDOR_PLIXER << 16) | 100):    /* client_ip_v4 */
            ti = proto_tree_add_item(pdutree, hf_pie_plixer_client_ip_v4,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_PLIXER << 16) | 101):    /* client_hostname */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_plixer_client_hostname,
                                       tvb, offset, length, gen_str);
            break;
        case ((VENDOR_PLIXER << 16) | 102):    /* partner_name */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_plixer_partner_name,
                                       tvb, offset, length, gen_str);
            break;
        case ((VENDOR_PLIXER << 16) | 103):    /* server_hostname */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_plixer_server_hostname,
                                       tvb, offset, length, gen_str);
            break;
        case ((VENDOR_PLIXER << 16) | 104):    /* server_ip_v4 */
            ti = proto_tree_add_item(pdutree, hf_pie_plixer_server_ip_v4,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_PLIXER << 16) | 105):    /* recipient_address */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_plixer_recipient_address,
                                       tvb, offset, length, gen_str);
            break;
        case ((VENDOR_PLIXER << 16) | 106):    /* event_id */
            ti = proto_tree_add_item(pdutree, hf_pie_plixer_event_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_PLIXER << 16) | 107):    /* msgid */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_plixer_msgid,
                                       tvb, offset, length, gen_str);
            break;
        case ((VENDOR_PLIXER << 16) | 108):    /* priority */
            ti = proto_tree_add_item(pdutree, hf_pie_plixer_priority,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_PLIXER << 16) | 109):    /* recipient_report_status */
            ti = proto_tree_add_item(pdutree, hf_pie_plixer_recipient_report_status,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_PLIXER << 16) | 110):    /* number_recipients */
            ti = proto_tree_add_item(pdutree, hf_pie_plixer_number_recipients,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_PLIXER << 16) | 111):    /* origination_time */
            ti = proto_tree_add_item(pdutree, hf_pie_plixer_origination_time,
                                     tvb, offset, length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_PLIXER << 16) | 112):    /* encryption */
            ti = proto_tree_add_item(pdutree, hf_pie_plixer_encryption,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_PLIXER << 16) | 113):    /* service_version */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_plixer_service_version,
                                       tvb, offset, length, gen_str);
            break;
        case ((VENDOR_PLIXER << 16) | 114):    /* linked_msgid */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_plixer_linked_msgid,
                                       tvb, offset, length, gen_str);
            break;
        case ((VENDOR_PLIXER << 16) | 115):    /* message_subject */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_plixer_message_subject,
                                       tvb, offset, length, gen_str);
            break;
        case ((VENDOR_PLIXER << 16) | 116):    /* sender_address */
            gen_str = tvb_format_text(tvb, offset, length);
            ti = proto_tree_add_string(pdutree, hf_pie_plixer_sender_address,
                                       tvb, offset, length, gen_str);
            break;
        case ((VENDOR_PLIXER << 16) | 117):    /* date_time */
            ti = proto_tree_add_item(pdutree, hf_pie_plixer_date_time,
                                     tvb, offset, length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
            break;
            /* END Plixer International */

            /* START Ixia Communications */
        case ((VENDOR_IXIA << 16) | 110):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_l7_application_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_IXIA << 16) | 111):
            {
            const guint8 *string;
            ti = proto_tree_add_item_ret_string(pdutree, hf_pie_ixia_l7_application_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA, wmem_packet_scope(), &string);
            proto_item_append_text(pdutree, " (%s)", string);
            }

            break;

        case ((VENDOR_IXIA << 16) | 120):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_source_ip_country_code,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 121):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_source_ip_country_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 122):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_source_ip_region_code,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 123):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_source_ip_region_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 125):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_source_ip_city_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 126):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_source_ip_latitude,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_IXIA << 16) | 127):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_source_ip_longitude,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;

        case ((VENDOR_IXIA << 16) | 140):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_destination_ip_country_code,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 141):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_destination_ip_country_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 142):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_destination_ip_region_code,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 143):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_destination_ip_region_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 145):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_destination_ip_city_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 146):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_destination_ip_latitude,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_IXIA << 16) | 147):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_destination_ip_longitude,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_IXIA << 16) | 160):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_os_device_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_IXIA << 16) | 161):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_os_device_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 162):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_browser_id,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_IXIA << 16) | 163):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_browser_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 176):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_reverse_octet_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_IXIA << 16) | 177):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_reverse_packet_delta_count,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_IXIA << 16) | 178):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_conn_encryption_type,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 179):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_encryption_cipher,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 180):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_encryption_keylen,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_IXIA << 16) | 181):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_imsi,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 182):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_user_agent,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 183):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_host_name,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 184):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_uri,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
        case ((VENDOR_IXIA << 16) | 185):
            ti = proto_tree_add_item(pdutree, hf_pie_ixia_dns_txt,
                                     tvb, offset, length, ENC_ASCII|ENC_NA);
            break;
            /* END Ixia Communications */

            /* START Netscaler Communications */
        case ((VENDOR_NETSCALER << 16) | 128):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_roundtriptime,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 129):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_transactionid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 130):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httprequrl,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 131):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpreqcookie,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 132):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_flowflags,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 133):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_connectionid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 134):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_syslogpriority,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 135):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_syslogmessage,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 136):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_syslogtimestamp,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 140):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpreqreferer,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 141):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpreqmethod,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 142):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpreqhost,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 143):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httprequseragent,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 144):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httprspstatus,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 145):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httprsplen,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 146):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_serverttfb,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 147):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_serverttlb,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 150):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_appnameincarnationnumber,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 151):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_appnameappid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 152):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_appname,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 153):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpreqrcvfb,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 156):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpreqforwfb,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 157):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpresrcvfb,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 158):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpresforwfb,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 159):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpreqrcvlb,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 160):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpreqforwlb,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 161):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_mainpageid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 162):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_mainpagecoreid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 163):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpclientinteractionstarttime,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 164):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpclientrenderendtime,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 165):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpclientrenderstarttime,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 167):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_apptemplatename,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 168):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpclientinteractionendtime,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 169):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpresrcvlb,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 170):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpresforwlb,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 171):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_appunitnameappid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 172):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_dbloginflags,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 173):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_dbreqtype,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 174):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_dbprotocolname,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 175):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_dbusername,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 176):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_dbdatabasename,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 177):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_dbclthostname,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 178):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_dbreqstring,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 179):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_dbrespstatusstring,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 180):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_dbrespstatus,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 181):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_dbresplength,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 182):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_clientrtt,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 183):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpcontenttype,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 185):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpreqauthorization,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 186):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpreqvia,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 187):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpreslocation,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 188):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpressetcookie,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 189):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpressetcookie2,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 190):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpreqxforwardedfor,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 192):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_connectionchainid,
                                     tvb, offset, length, ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 193):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_connectionchainhopcount,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 200):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icasessionguid,
                                     tvb, offset, length, ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 201):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclientversion,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 202):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclienttype,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 203):
            ti = proto_tree_add_ipv4(pdutree, hf_pie_netscaler_icaclientip,
                                     tvb, offset, 4, tvb_get_ipv4(tvb, offset));
            break;
        case ((VENDOR_NETSCALER << 16) | 204):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclienthostname,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 205):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_aaausername,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 207):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icadomainname,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 208):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclientlauncher,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 209):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icasessionsetuptime,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 210):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaservername,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 214):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icasessionreconnects,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 215):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icartt,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 216):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclientsiderxbytes,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 217):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclientsidetxbytes,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 219):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclientsidepacketsretransmit,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 220):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaserversidepacketsretransmit,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 221):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclientsidertt,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 222):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaserversidertt,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 223):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icasessionupdatebeginsec,
                                     tvb, offset, length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 224):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icasessionupdateendsec,
                                     tvb, offset, length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 225):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icachannelid1,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 226):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icachannelid1bytes,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 227):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icachannelid2,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 228):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icachannelid2bytes,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 229):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icachannelid3,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 230):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icachannelid3bytes,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 231):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icachannelid4,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 232):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icachannelid4bytes,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 233):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icachannelid5,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 234):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icachannelid5bytes,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 235):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaconnectionpriority,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 236):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_applicationstartupduration,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 237):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icalaunchmechanism,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 238):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaapplicationname,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 239):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_applicationstartuptime,
                                     tvb, offset, length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 240):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaapplicationterminationtype,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 241):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaapplicationterminationtime,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 242):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icasessionendtime,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 243):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclientsidejitter,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 244):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaserversidejitter,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 245):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaappprocessid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 246):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaappmodulepath,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 247):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icadeviceserialno,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 248):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_msiclientcookie,
                                     tvb, offset, length, ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 249):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaflags,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 250):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icausername,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 251):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_licensetype,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 252):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_maxlicensecount,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 253):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_currentlicenseconsumed,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 254):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icanetworkupdatestarttime,
                                     tvb, offset, length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 255):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icanetworkupdateendtime,
                                     tvb, offset, length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 256):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclientsidesrtt,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 257):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaserversidesrtt,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 258):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclientsidedelay,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 259):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaserversidedelay,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 260):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icahostdelay,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 261):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclientsidewindowsize,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 262):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaserversidewindowsize,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 263):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaclientsidertocount,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 264):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_icaserversidertocount,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 265):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_ical7clientlatency,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 266):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_ical7serverlatency,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 267):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_httpdomainname,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_NETSCALER << 16) | 268):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_cacheredirclientconnectioncoreid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_NETSCALER << 16) | 269):
            ti = proto_tree_add_item(pdutree, hf_pie_netscaler_cacheredirclientconnectiontransactionid,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
            /* END Netscaler Communications */

            /* START Barracuda Communications */
        case ((VENDOR_BARRACUDA << 16) | 1):
            ti = proto_tree_add_item(pdutree, hf_pie_barracuda_timestamp,
                                     tvb, offset, length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_BARRACUDA << 16) | 2):
            ti = proto_tree_add_item(pdutree, hf_pie_barracuda_logop,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_BARRACUDA << 16) | 3):
            ti = proto_tree_add_item(pdutree, hf_pie_barracuda_traffictype,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_BARRACUDA << 16) | 4):
            ti = proto_tree_add_item(pdutree, hf_pie_barracuda_fwrule,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_BARRACUDA << 16) | 5):
            ti = proto_tree_add_item(pdutree, hf_pie_barracuda_servicename,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_BARRACUDA << 16) | 6):
            ti = proto_tree_add_item(pdutree, hf_pie_barracuda_reason,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_BARRACUDA << 16) | 7):
            ti = proto_tree_add_item(pdutree, hf_pie_barracuda_reasontext,
                                     tvb, offset, length, ENC_UTF_8|ENC_NA);
            break;
        case ((VENDOR_BARRACUDA << 16) | 8):
            ti = proto_tree_add_ipv4(pdutree, hf_pie_barracuda_bindipv4address,
                                     tvb, offset, 4, tvb_get_ipv4(tvb, offset));
            break;
        case ((VENDOR_BARRACUDA << 16) | 9):
            ti = proto_tree_add_item(pdutree, hf_pie_barracuda_bindtransportport,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_BARRACUDA << 16) | 10):
            ti = proto_tree_add_ipv4(pdutree, hf_pie_barracuda_connipv4address,
                                     tvb, offset, 4, tvb_get_ipv4(tvb, offset));
            break;
        case ((VENDOR_BARRACUDA << 16) | 11):
            ti = proto_tree_add_item(pdutree, hf_pie_barracuda_conntransportport,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case ((VENDOR_BARRACUDA << 16) | 12):
            ti = proto_tree_add_item(pdutree, hf_pie_barracuda_auditcounter,
                                     tvb, offset, length, ENC_BIG_ENDIAN);
            break;
            /* END Barracuda Communications */

        default:  /* Unknown Field ID */
            if ((hdrinfo_p->vspec == 9) || (pen == REVPEN)) {
                ti = proto_tree_add_bytes_format_value(pdutree, hf_cflow_unknown_field_type,
                                                       tvb, offset, length, NULL,
                                                       "Type %u: Value (hex bytes): %s",
                                                       masked_type,
                                                       tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, offset, length, ' '));
            } else { /* v10 PEN */
                ti = proto_tree_add_bytes_format_value(pdutree, hf_ipfix_enterprise_private_entry,
                                                       tvb, offset, length, NULL,
                                                       "(%s) Type %u: Value (hex bytes): %s",
                                                       pen_str ? pen_str : "(null)",
                                                       masked_type,
                                                       tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, offset, length, ' '));
            }
            break;

        } /* switch (pen_type) */

        if (ti && (vstr_len != 0)) {
            string_tree = proto_item_add_subtree(ti, ett_str_len);
            proto_tree_add_uint(string_tree, hf_string_len_short, tvb,
                                gen_str_offset-vstr_len, 1, string_len_short);
            if (vstr_len == 3) {
                proto_tree_add_uint(string_tree, hf_string_len_long, tvb,
                                    gen_str_offset-2, 2, string_len_long);
            }
        }

        if (ti && (pen == REVPEN)) {
            /* XXX: why showing type ? type not shown if not reverse */
            proto_item_append_text(ti, " (Reverse Type %u %s)",
                                   masked_type,
                                   val_to_str_ext_const(masked_type, &v9_v10_template_types_ext, "Unknown"));
        }

        offset += length;
    } /* for (i=0; i < count; i++) */

    /* If only "start" or "end" time, show it here */
    /* XXX: length is actually 8 if millisec, microsec, nanosec time */
    for (i = 0; i < 2; i++) {
        for (j=0; j < (gint)duration_type_max; j++) {
            if (!(offset_s[i][j] && offset_e[i][j])) {
                if (offset_s[i][j]) {
                    if (msec_start[i][j]) {
                        proto_tree_add_time(pdutree, hf_cflow_timestart, tvb,
                                            offset_s[i][j], 4, &ts_start[i][j]);
                    } else {
                        proto_tree_add_time(pdutree, hf_cflow_abstimestart, tvb,
                                            offset_s[i][j], 4, &ts_start[i][j]);
                    }
                }
                if (offset_e[i][j]) {
                    if (msec_end[i][j]) {
                        proto_tree_add_time(pdutree, hf_cflow_timeend, tvb,
                                            offset_e[i][j], 4, &ts_end[i][j]);
                    } else {
                        proto_tree_add_time(pdutree, hf_cflow_abstimeend, tvb,
                                            offset_e[i][j], 4, &ts_end[i][j]);
                    }
                }
            }
        }
    }

    /* XXX - These IDs are currently hard-coded in procflow.py. */
    if (got_flags == GOT_TCP_UDP && (tmplt_p->tmplt_id == 256 || tmplt_p->tmplt_id == 258)) {
        add_tcp_process_info(pinfo->num, &local_addr, &remote_addr, local_port, remote_port, uid, pid, uname_str, cmd_str);
    }
    if (got_flags == GOT_TCP_UDP && (tmplt_p->tmplt_id == 257 || tmplt_p->tmplt_id == 259)) {
        add_udp_process_info(pinfo->num, &local_addr, &remote_addr, local_port, remote_port, uid, pid, uname_str, cmd_str);
    }

    return (guint) (offset - orig_offset);

}

/* --- Dissect Template ---*/
/* Template Fields Dissection */
static const int *v9_template_type_hf_list[TF_NUM] = {
    &hf_cflow_template_scope_field_type,            /* scope */
    &hf_cflow_template_field_type};                 /* entry */
static const int *v10_template_type_hf_list[TF_NUM_EXT] = {
    &hf_cflow_template_ipfix_field_type,            /* scope */
    &hf_cflow_template_ipfix_field_type,
    &hf_cflow_template_plixer_field_type,
    &hf_cflow_template_ntop_field_type,
    &hf_cflow_template_ixia_field_type,
    &hf_cflow_template_netscaler_field_type,
    &hf_cflow_template_barracuda_field_type,
    NULL};

static value_string_ext *v9_template_type_vse_list[TF_NUM] = {
    &v9_scope_field_types_ext,                      /* scope */
    &v9_v10_template_types_ext };                   /* entry */
static value_string_ext *v10_template_type_vse_list[TF_NUM_EXT] = {
    &v9_v10_template_types_ext,                     /* scope */
    &v9_v10_template_types_ext,                     /* entry */
    &v10_template_types_plixer_ext,
    &v10_template_types_ntop_ext,
    &v10_template_types_ixia_ext,
    &v10_template_types_netscaler_ext,
    &v10_template_types_barracuda_ext,
    NULL};

static int
dissect_v9_v10_template_fields(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tmplt_tree, int offset,
                               hdrinfo_t *hdrinfo_p,
                               v9_v10_tmplt_t *tmplt_p,
                               v9_v10_tmplt_fields_type_t fields_type)
{
    int ver;
    int count;
    int i;

    DISSECTOR_ASSERT((fields_type == TF_SCOPES) || (fields_type == TF_ENTRIES));

    ver = hdrinfo_p->vspec;
    DISSECTOR_ASSERT((ver == 9) || (ver == 10));

    count = tmplt_p->field_count[fields_type];
    for(i=0; i<count; i++) {
        guint16      type;
        guint16      length;
        guint32      pen;
        const gchar *pen_str;
        proto_tree  *field_tree;
        proto_item  *field_item;
        proto_item  *ti;

        pen     = 0;
        pen_str = NULL;
        type    = tvb_get_ntohs(tvb, offset);
        length  = tvb_get_ntohs(tvb, offset+2); /* XXX: 0 length should not be allowed ? exception: "ScopeSystem" */
        if ((ver == 10) && (type & 0x8000)) {   /* IPFIX only */
            pen = tvb_get_ntohl(tvb, offset+4);
            pen_str = val_to_str_ext_const(pen, &sminmpec_values_ext, "(Unknown)");
        }

        if (tmplt_p->fields_p[fields_type] != NULL) {
            DISSECTOR_ASSERT (i < count);
            tmplt_p->fields_p[fields_type][i].type    = type;
            tmplt_p->fields_p[fields_type][i].length  = length;
            tmplt_p->fields_p[fields_type][i].pen     = pen;
            tmplt_p->fields_p[fields_type][i].pen_str = pen_str;
            if (length != VARIABLE_LENGTH) { /* Don't include "variable length" in the total */
                tmplt_p->length    += length;
            }
        }

        field_tree = proto_tree_add_subtree_format(tmplt_tree, tvb, offset, 4+((pen_str!=NULL)?4:0),
                                                   ett_field, &field_item, "Field (%u/%u)", i+1, count);
        if (fields_type == TF_SCOPES) {
            proto_item_append_text(field_item, " [Scope]");
        }

        if (ver == 9) { /* v9 */
            proto_tree_add_item(field_tree, *v9_template_type_hf_list[fields_type],
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_append_text(field_item, ": %s",
                                   val_to_str_ext(type, v9_template_type_vse_list[fields_type], "Unknown(%d)"));
        } else { /* v10 */
            proto_tree_add_item(field_tree, hf_cflow_template_ipfix_pen_provided,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            if ( !(type & 0x8000) || (pen == REVPEN)) {
                proto_item *rp_ti;
                rp_ti = proto_tree_add_item(field_tree, *v10_template_type_hf_list[fields_type],
                                            tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_item_append_text(field_item, ": %s",
                                       val_to_str_ext(type&0x7fff, v10_template_type_vse_list[fields_type], "Unknown(%d)"));
                if (pen == REVPEN) {
                    proto_item_append_text(rp_ti, " [Reverse]");
                    proto_item_append_text(field_item, " [Reverse]");
                }
            } else {
                int fields_type_pen = pen_to_type_hf_list(pen);
                if (fields_type_pen != TF_NO_VENDOR_INFO) {
                    proto_tree_add_item(field_tree, *v10_template_type_hf_list[fields_type_pen],
                                        tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_item_append_text(field_item, ": %s",
                                           val_to_str_ext(type&0x7fff, v10_template_type_vse_list[fields_type_pen], "Unknown(%d)"));
                } else { /* Private Enterprise */
                    proto_item *pen_ti;
                    pen_ti = proto_tree_add_item(field_tree, hf_cflow_template_ipfix_field_type_enterprise,
                                                 tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_item_append_text(pen_ti, " [pen: %s]", pen_str);
                    proto_item_append_text(field_item, ": %3u [pen: %s]", type&0x7fff, pen_str);
                }
            }
        }

        offset += 2;

        ti = proto_tree_add_item(field_tree, hf_cflow_template_field_length, tvb,
                                 offset, 2, ENC_BIG_ENDIAN);
        if (length == VARIABLE_LENGTH) {
            proto_item_append_text(ti, " [i.e.: \"Variable Length\"]");
        }
        offset += 2;

        /* Private Enterprise Number (IPFIX only) */
        if ((ver == 10) && (type & 0x8000)) {
            proto_tree_add_uint_format_value(field_tree, hf_cflow_template_ipfix_field_pen, tvb, offset, 4,
                                             pen, "%s (%u)", pen_str, pen);
            offset += 4;
        }
    }
    return offset;
}

/* Options Template Dissection */
static int
dissect_v9_v10_options_template(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree, int offset, int length,
                                hdrinfo_t *hdrinfo_p, guint16 flowset_id)
{
    int remaining;
    proto_item_append_text(pdutree, " (Options Template): ");
    col_append_fstr(pinfo->cinfo, COL_INFO, " [Options-Template:");

    remaining = length;
    while (remaining > 3) { /* allow for padding */
        v9_v10_tmplt_t *tmplt_p;
        v9_v10_tmplt_t  tmplt;
        proto_tree     *tmplt_tree;
        proto_item     *tmplt_item;
        proto_item     *ti;
        guint16         id;
        guint16         option_scope_field_count;
        guint16         option_field_count;
        int             orig_offset;

        orig_offset = offset;

        id = tvb_get_ntohs(tvb, offset);
        /* Show set flow-id in set root and Info column */
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        "%s%u", (remaining<length) ? "," : "", id);
        proto_item_append_text(pdutree, "%s%u", (remaining<length) ? "," : "", id);

        tmplt_tree = proto_tree_add_subtree_format(pdutree, tvb, offset, -1, ett_template, &tmplt_item, "Options Template (Id = %u)", id);

        proto_tree_add_item(tmplt_tree, hf_cflow_template_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (flowset_id == FLOWSET_ID_V9_OPTIONS_TEMPLATE) { /* V9 */
            /* Note: v9: field_count = fields_byte_length/4 since each entry is 4 bytes */
            /* XXX: validate byte_length is a multiple of 4 ? */
            option_scope_field_count = tvb_get_ntohs(tvb, offset)/4;
            proto_tree_add_item(tmplt_tree,
                                hf_cflow_option_scope_length,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            option_field_count = tvb_get_ntohs(tvb, offset)/4;
            ti = proto_tree_add_item(tmplt_tree,
                                     hf_cflow_option_length,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        } else { /* IPFIX (V10) */
            guint16 option_total_field_count;

            option_total_field_count = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tmplt_tree,
                                hf_cflow_template_ipfix_total_field_count,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            option_scope_field_count = tvb_get_ntohs(tvb, offset);
            ti = proto_tree_add_item(tmplt_tree,
                                     hf_cflow_template_ipfix_scope_field_count,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            option_field_count = option_total_field_count - option_scope_field_count;

            if (option_scope_field_count == 0) {
                expert_add_info(pinfo, ti, &ei_cflow_template_ipfix_scope_field_count);
                return 0;
            }
            if (option_scope_field_count > option_total_field_count) {
                expert_add_info_format(pinfo, ti, &ei_cflow_template_ipfix_scope_field_count_too_many,
                                       "More scope fields (%u) than fields (%u)",
                                       option_scope_field_count, option_total_field_count);
                return 0;
            }
        }

        proto_item_append_text(tmplt_item,
                               " (Scope Count = %u; Data Count = %u)",
                               option_scope_field_count, option_field_count);
        proto_item_set_len(tmplt_item, 6 +4*(option_scope_field_count+option_field_count));

        if (v9_tmplt_max_fields &&
            (option_field_count > v9_tmplt_max_fields)) {
            expert_add_info_format(pinfo, ti, &ei_cflow_options,
                                   "More options (%u) than we can handle."
                                   " Maximum value can be adjusted in the protocol preferences.",
                                   option_field_count);
        }

        if (v9_tmplt_max_fields &&
            (option_scope_field_count > v9_tmplt_max_fields)) {
            expert_add_info_format(pinfo, ti, &ei_cflow_scopes,
                                   "More scopes (%u) than we can handle [template won't be used]."
                                   " Maximum value can be adjusted in the protocol preferences.",
                                   option_scope_field_count);
        }

        memset(&tmplt, 0, sizeof(tmplt));

        v9_v10_tmplt_build_key(&tmplt, pinfo, hdrinfo_p->src_id, id);

        tmplt.field_count[TF_SCOPES]  = option_scope_field_count;
        tmplt.field_count[TF_ENTRIES] = option_field_count;

        /* If an entry for this template already exists in the template table then after the     */
        /* 'do {} while' tmplt.fields_p[TF_SCOPES] and tmplt.fields_p[TF_ENTRIES] will be NULL   */
        /* (no memory will have been allocated) and thus this template will not be cached after  */
        /* dissection.                                                                           */
        /*  ToDo: expert warning if replacement (changed) and new template ignored.              */
        /*  XXX: Is an Options template with only scope fields allowed for V9 ??                 */

        tmplt_p = (v9_v10_tmplt_t *)g_hash_table_lookup(v9_v10_tmplt_table, &tmplt);
        if (!pinfo->fd->flags.visited) { /* cache template info only during first pass */
            do {
                if (v9_tmplt_max_fields &&
                     ((option_scope_field_count > v9_tmplt_max_fields)
                      || (option_field_count > v9_tmplt_max_fields)))  {
                    break; /* Don't cache this template */
                }
                if (tmplt_p != NULL) {
                    /* Entry for this template already exists; Can be dup or changed */
                    /* ToDo: Test for changed template ? If so: expert ?             */
                    break; /* Don't cache this template */
                }
                tmplt.fields_p[TF_SCOPES]  = (v9_v10_tmplt_entry_t *)wmem_alloc0(wmem_file_scope(), option_scope_field_count *sizeof(v9_v10_tmplt_entry_t));
                tmplt.fields_p[TF_ENTRIES] = (v9_v10_tmplt_entry_t *)wmem_alloc0(wmem_file_scope(), option_field_count       *sizeof(v9_v10_tmplt_entry_t));
                break;
            } while (FALSE);
        }

        offset = dissect_v9_v10_template_fields(tvb, pinfo, tmplt_tree, offset,
                                                hdrinfo_p, &tmplt, TF_SCOPES);

        offset = dissect_v9_v10_template_fields(tvb, pinfo, tmplt_tree, offset,
                                                hdrinfo_p, &tmplt, TF_ENTRIES);

        if ((tmplt_p == NULL) && (tmplt.fields_p[TF_SCOPES] || tmplt.fields_p[TF_ENTRIES])) {
            /* create permanent template copy for storage in template table */
            tmplt_p = (v9_v10_tmplt_t *)wmem_memdup(wmem_file_scope(), &tmplt, sizeof(tmplt));
            copy_address_wmem(wmem_file_scope(), &tmplt_p->src_addr, &pinfo->net_src);
            copy_address_wmem(wmem_file_scope(), &tmplt_p->dst_addr, &pinfo->net_dst);
            /* Remember when we saw this template */
            tmplt_p->template_frame_number = pinfo->num;
            /* Add completed entry into table */
            g_hash_table_insert(v9_v10_tmplt_table, tmplt_p, tmplt_p);
        }

        remaining -= offset - orig_offset;
    }
    if (remaining > 0)
        flow_process_textfield(pdutree, tvb, offset, remaining, hf_cflow_padding);

    col_append_fstr(pinfo->cinfo, COL_INFO, "]");

    return length;
}

/* Data Template Dissection */
static int
dissect_v9_v10_data_template(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree, int offset, int length,
                             hdrinfo_t *hdrinfo_p, guint16 flowset_id _U_)
{
    int remaining;
    proto_item_append_text(pdutree, " (Data Template): ");
    col_append_fstr(pinfo->cinfo, COL_INFO, " [Data-Template:");

    remaining = length;
    while (remaining > 3) { /* allow for padding */
        v9_v10_tmplt_t *tmplt_p;
        v9_v10_tmplt_t  tmplt;
        proto_tree     *tmplt_tree;
        proto_item     *ti;
        guint16         id;
        guint16         count;
        int             orig_offset;

        orig_offset = offset;
        id = tvb_get_ntohs(tvb, offset);
        /* Show set flow-id in set root and Info column */
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        "%s%u", (remaining<length) ? "," : "", id);
        proto_item_append_text(pdutree, "%s%u", (remaining<length) ? "," : "", id);

        count = tvb_get_ntohs(tvb, offset + 2);

        tmplt_tree = proto_tree_add_subtree_format(pdutree, tvb, offset,
                                         4 + 4 * count /* hdrsiz + count*2*(sizeof guint16)*/,
                                         ett_template, NULL, "Template (Id = %u, Count = %u)", id, count);

        proto_tree_add_item(tmplt_tree, hf_cflow_template_id, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        ti = proto_tree_add_item(tmplt_tree, hf_cflow_template_field_count,
                                 tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (v9_tmplt_max_fields && (count > v9_tmplt_max_fields)) {
            expert_add_info_format(pinfo, ti, &ei_cflow_entries,
                                   "More entries (%u) than we can handle [template won't be used]."
                                   " Maximum value can be adjusted in the protocol preferences.",
                                   count);
        }

        memset(&tmplt, 0, sizeof(tmplt));

        v9_v10_tmplt_build_key(&tmplt, pinfo, hdrinfo_p->src_id, id); /* lookup only ! */

        tmplt.field_count[TF_ENTRIES]  = count;

        /* If an entry for this hash already exists in the template table then after the           */
        /* 'do {} while' tmplt.fields_p[TF_ENTRIES] will be NULL (no memory will have been         */
        /*  been allocated) and thus this template will not be cached after dissection.            */
        /*  ToDo: expert warning if replacement (changed) and new template ignored.                */

        tmplt_p = (v9_v10_tmplt_t *)g_hash_table_lookup(v9_v10_tmplt_table, &tmplt);
        if (!pinfo->fd->flags.visited) { /* cache template info only during first pass */
            do {
                if ((count == 0) ||
                    (v9_tmplt_max_fields && (count > v9_tmplt_max_fields))) {
                    break; /* Don't cache this template */
                }
                if (tmplt_p != NULL) {
                    /* Entry for this template already exists; Can be dup or changed */
                    /* ToDo: Test for changed template ? If so: expert ?             */
                    break; /* Don't cache this template */
                }
                tmplt.fields_p[TF_ENTRIES] = (v9_v10_tmplt_entry_t *)wmem_alloc0(wmem_file_scope(), count * sizeof(v9_v10_tmplt_entry_t));
                break;
            } while (FALSE);
        }
        offset = dissect_v9_v10_template_fields(tvb, pinfo, tmplt_tree, offset,
                                                hdrinfo_p, &tmplt, TF_ENTRIES);

        if ((tmplt_p == NULL) && tmplt.fields_p[TF_ENTRIES]) {
            netflow_domain_state_t *domain_state;

            /* create permanent template copy for storage in template table */
            tmplt_p = (v9_v10_tmplt_t *)wmem_memdup(wmem_file_scope(), &tmplt, sizeof(tmplt));
            copy_address_wmem(wmem_file_scope(), &tmplt_p->src_addr, &pinfo->net_src);
            copy_address_wmem(wmem_file_scope(), &tmplt_p->dst_addr, &pinfo->net_dst);
            /* Remember when we saw this template */
            tmplt_p->template_frame_number = pinfo->num;
            g_hash_table_insert(v9_v10_tmplt_table, tmplt_p, tmplt_p);

            /* Create if necessary observation domain entry (for use with sequence analysis) */
            domain_state = (netflow_domain_state_t *)g_hash_table_lookup(netflow_sequence_analysis_domain_hash,
                                                                         GUINT_TO_POINTER(hdrinfo_p->src_id));
            if (domain_state == NULL) {
                domain_state = wmem_new0(wmem_file_scope(), netflow_domain_state_t);
                /* Store new domain in table */
                g_hash_table_insert(netflow_sequence_analysis_domain_hash, GUINT_TO_POINTER(hdrinfo_p->src_id), domain_state);
            }
        }
        remaining -= offset - orig_offset;
    }
    if (remaining > 0)
        flow_process_textfield(pdutree, tvb, offset, remaining, hf_cflow_padding);

    col_append_fstr(pinfo->cinfo, COL_INFO, "]");

    return length;
}

/* build temporary key */
/* Note: address at *(pinfo->net_???.data) is *not* copied */
static v9_v10_tmplt_t *v9_v10_tmplt_build_key(v9_v10_tmplt_t *tmplt_p, packet_info *pinfo, guint32 src_id, guint16 tmplt_id)
{
    set_address(&tmplt_p->src_addr, pinfo->net_src.type, pinfo->net_src.len, pinfo->net_src.data); /* lookup only! */
    tmplt_p->src_port  = pinfo->srcport;
    set_address(&tmplt_p->dst_addr, pinfo->net_dst.type, pinfo->net_dst.len, pinfo->net_dst.data); /* lookup only! */
    tmplt_p->dst_port  = pinfo->destport;
    tmplt_p->src_id    = src_id;
    tmplt_p->tmplt_id  = tmplt_id;
    return tmplt_p;
}

static gboolean
v9_v10_tmplt_table_equal(gconstpointer k1, gconstpointer k2)
{
    const v9_v10_tmplt_t *ta = (const v9_v10_tmplt_t *)k1;
    const v9_v10_tmplt_t *tb = (const v9_v10_tmplt_t *)k2;

    return (
        (cmp_address(&ta->src_addr, &tb->src_addr) == 0) &&
        (ta->src_port == tb->src_port)                   &&
        (cmp_address(&ta->dst_addr, &tb->dst_addr) == 0) &&
        (ta->dst_port == tb->dst_port)                   &&
        (ta->src_id   == tb->src_id)                     &&
        (ta->tmplt_id == tb->tmplt_id)
        );
}

static guint
v9_v10_tmplt_table_hash(gconstpointer k)
{
    const v9_v10_tmplt_t *tmplt_p = (const v9_v10_tmplt_t *)k;
    guint32               val;

    val = tmplt_p->src_id + (tmplt_p->tmplt_id << 9) + tmplt_p->src_port + tmplt_p->dst_port;

    val = add_address_to_hash(val, &tmplt_p->src_addr);
    val = add_address_to_hash(val, &tmplt_p->dst_addr);

    return val;
}

/*
 * dissect a version 1, 5, or 7 pdu and return the length of the pdu we
 * processed
 */

static int
dissect_pdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *pdutree, int offset, hdrinfo_t *hdrinfo_p, guint32 *flows_seen _U_)
{
    int             startoffset = offset;
    guint32         srcaddr, dstaddr;
    guint8          mask;
    nstime_t        ts;
    guint8          ver;

    memset(&ts, 0, sizeof(ts));

    /*
     * memcpy so we can use the values later to calculate a prefix
     */
    srcaddr = tvb_get_ipv4(tvb, offset);
    proto_tree_add_ipv4(pdutree, hf_cflow_srcaddr, tvb, offset, 4, srcaddr);
    offset += 4;

    dstaddr = tvb_get_ipv4(tvb, offset);
    proto_tree_add_ipv4(pdutree, hf_cflow_dstaddr, tvb, offset, 4, dstaddr);
    offset += 4;

    proto_tree_add_item(pdutree, hf_cflow_nexthop, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = flow_process_ints(pdutree, tvb, offset);
    offset = flow_process_sizecount(pdutree, tvb, offset);
    offset = flow_process_timeperiod(pdutree, tvb, offset);
    offset = flow_process_ports(pdutree, tvb, offset);

    /*
     * and the similarities end here
     */

    ver = hdrinfo_p->vspec;

    if (ver == 1) {
        offset = flow_process_textfield(pdutree, tvb, offset, 2, hf_cflow_padding);

        proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(pdutree, hf_cflow_tos, tvb, offset++, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(pdutree, hf_cflow_tcpflags, tvb, offset++, 1, ENC_BIG_ENDIAN);

        offset = flow_process_textfield(pdutree, tvb, offset, 3, hf_cflow_padding);

        offset = flow_process_textfield(pdutree, tvb, offset, 4, hf_cflow_reserved);
    } else {
        if (ver == 5)
            offset = flow_process_textfield(pdutree, tvb, offset, 1, hf_cflow_padding);
        else {
            proto_tree_add_item(pdutree, hf_cflow_flags, tvb, offset++, 1, ENC_BIG_ENDIAN);
        }

        proto_tree_add_item(pdutree, hf_cflow_tcpflags, tvb, offset++, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(pdutree, hf_cflow_tos, tvb, offset++, 1, ENC_BIG_ENDIAN);

        offset = flow_process_aspair(pdutree, tvb, offset);

        mask = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format_value(pdutree, hf_cflow_srcmask, tvb, offset++, 1,
                                         mask,
                                         "%u (prefix: %s/%u)",
                                         mask, getprefix(&srcaddr, mask),
                                         mask != 0 ? mask : 32);

        mask = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format_value(pdutree, hf_cflow_dstmask, tvb, offset++, 1,
                                         mask,
                                         "%u (prefix: %s/%u)",
                                         mask, getprefix(&dstaddr, mask),
                                         mask != 0 ? mask : 32);

        offset = flow_process_textfield(pdutree, tvb, offset, 2, hf_cflow_padding);

        if (ver == 7) {
            proto_tree_add_item(pdutree, hf_cflow_routersc, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
    }

    return (offset - startoffset);
}

static const gchar   *
getprefix(const guint32 *addr, int prefix)
{
    guint32 gprefix;
    address prefix_addr;

    gprefix = *addr & g_htonl((0xffffffff << (32 - prefix)));

    set_address(&prefix_addr, AT_IPv4, 4, &gprefix);
    return address_to_str(wmem_packet_scope(), &prefix_addr);
}

/* Called whenever a new capture is loaded, a complete redissection is done, a pref is changed, & etc */
static void
netflow_init(void)
{
    v9_v10_tmplt_table = g_hash_table_new(v9_v10_tmplt_table_hash, v9_v10_tmplt_table_equal);
    netflow_sequence_analysis_domain_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    netflow_sequence_analysis_result_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void
netflow_cleanup(void)
{
    g_hash_table_destroy(v9_v10_tmplt_table);
    g_hash_table_destroy(netflow_sequence_analysis_domain_hash);
    g_hash_table_destroy(netflow_sequence_analysis_result_hash);
}

void
proto_register_netflow(void)
{
    static hf_register_info hf[] = {
        /*
         * flow header
         */
        {&hf_cflow_version,
         {"Version", "cflow.version",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "NetFlow Version", HFILL}
        },
        {&hf_cflow_len,
         {"Length", "cflow.len",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Length of PDUs", HFILL}
        },
        {&hf_cflow_count,
         {"Count", "cflow.count",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Count of PDUs", HFILL}
        },
        {&hf_cflow_sysuptime,
         {"SysUptime", "cflow.sysuptime",
          FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
          "Time since router booted (in seconds)", HFILL}
        },
        {&hf_cflow_exporttime,
         {"ExportTime", "cflow.exporttime",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Time when the flow has been exported", HFILL}
        },
        {&hf_cflow_timestamp,
         {"Timestamp", "cflow.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          "Current seconds since epoch", HFILL}
        },
        {&hf_cflow_unix_secs,
         {"CurrentSecs", "cflow.unix_secs",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Current seconds since epoch", HFILL}
        },
        {&hf_cflow_unix_nsecs,
         {"CurrentNSecs", "cflow.unix_nsecs",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Residual nanoseconds since epoch", HFILL}
        },
        {&hf_cflow_samplingmode,
         {"SamplingMode", "cflow.samplingmode",
          FT_UINT16, BASE_DEC, VALS(v5_sampling_mode), 0xC000,
          "Sampling Mode of exporter", HFILL}
        },
        {&hf_cflow_samplerate,
         {"SampleRate", "cflow.samplerate",
          FT_UINT16, BASE_DEC, NULL, 0x3FFF,
          "Sample Frequency of exporter", HFILL}
        },

        /*
         * end version-agnostic header
         * version-specific flow header
         */
        {&hf_cflow_sequence,
         {"FlowSequence", "cflow.sequence",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Sequence number of flows seen", HFILL}
        },
        {&hf_cflow_engine_type,
         {"EngineType", "cflow.engine_type",
          FT_UINT8, BASE_DEC, VALS(engine_type), 0x0,
          "Flow switching engine type", HFILL}
        },
        {&hf_cflow_engine_id,
         {"EngineId", "cflow.engine_id",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Slot number of switching engine", HFILL}
        },
        {&hf_cflow_source_id,
         {"SourceId", "cflow.source_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Identifier for export device", HFILL}
        },
        {&hf_cflow_aggmethod,
         {"AggMethod", "cflow.aggmethod",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &v8_agg_ext, 0x0,
          "CFlow V8 Aggregation Method", HFILL}
        },
        {&hf_cflow_aggversion,
         {"AggVersion", "cflow.aggversion",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "CFlow V8 Aggregation Version", HFILL}
        },
        /*
         * end version specific header storage
         */
        /*
         * Version 9
         */
        {&hf_cflow_flowset_id,
         {"FlowSet Id", "cflow.flowset_id",
          FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(rs_flowset_ids), 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_flowset_length,
         {"FlowSet Length", "cflow.flowset_length",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "FlowSet Length in bytes", HFILL}
        },
        {&hf_cflow_template_id,
         {"Template Id", "cflow.template_id",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_template_field_count,
         {"Field Count", "cflow.template_field_count",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Template field count", HFILL}
        },
        {&hf_cflow_template_field_type,
         {"Type", "cflow.template_field_type",
          FT_UINT16, BASE_DEC|BASE_EXT_STRING, &v9_v10_template_types_ext, 0x0,
          "Template field type", HFILL}
        },
        {&hf_cflow_template_field_length,
         {"Length", "cflow.template_field_length",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Template field length", HFILL}
        },

        /* options */
        {&hf_cflow_option_scope_length,
         {"Option Scope Length", "cflow.option_scope_length",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_option_length,
         {"Option Length", "cflow.option_length",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_template_scope_field_type,
         {"Scope Type", "cflow.scope_field_type",
          FT_UINT16, BASE_DEC|BASE_EXT_STRING, &v9_scope_field_types_ext, 0x0,
          "Scope field type", HFILL}
        },
        {&hf_cflow_icmp_type_code_ipv4,
         {"ICMP Type", "cflow.icmp_type_code_ipv4",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_igmp_type,
         {"IGMP Type", "cflow.igmp_type",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_sampling_interval,
         {"Sampling interval", "cflow.sampling_interval",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_sampling_algorithm,
         {"Sampling algorithm", "cflow.sampling_algorithm",
          FT_UINT8, BASE_DEC, VALS(ipfix_sampling_mode), 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_flow_active_timeout,
         {"Flow active timeout", "cflow.flow_active_timeout",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_flow_inactive_timeout,
         {"Flow inactive timeout", "cflow.flow_inactive_timeout",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },

        /*
         * begin pdu content storage
         */
        {&hf_cflow_srcaddr,
         {"SrcAddr", "cflow.srcaddr",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Flow Source Address (IPv4)", HFILL}
        },
        {&hf_cflow_srcaddr_v6,
         {"SrcAddr", "cflow.srcaddrv6",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          "Flow Source Address (IPv6)", HFILL}
        },
        {&hf_cflow_srcnet,
         {"SrcNet", "cflow.srcnet",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Flow Source Network", HFILL}
        },
        {&hf_cflow_dstaddr,
         {"DstAddr", "cflow.dstaddr",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Flow Destination Address (IPv4)", HFILL}
        },
        {&hf_cflow_dstaddr_v6,
         {"DstAddr", "cflow.dstaddrv6",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          "Flow Destination Address (IPv6)", HFILL}
        },
        {&hf_cflow_dstnet,
         {"DstNet", "cflow.dstnet",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Flow Destination Network", HFILL}
        },
        {&hf_cflow_nexthop,
         {"NextHop", "cflow.nexthop",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Router nexthop (IPv4)", HFILL}
        },
        {&hf_cflow_nexthop_v6,
         {"NextHop", "cflow.nexthopv6",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          "Router nexthop (IPv6)", HFILL}
        },
        {&hf_cflow_bgpnexthop,
         {"BGPNextHop", "cflow.bgpnexthop",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "BGP Router Nexthop (IPv4)", HFILL}
        },
        {&hf_cflow_bgpnexthop_v6,
         {"BGPNextHop", "cflow.bgpnexthopv6",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          "BGP Router Nexthop (IPv6)", HFILL}
        },
        {&hf_cflow_inputint,
         {"InputInt", "cflow.inputint",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Flow Input Interface", HFILL}
        },
        {&hf_cflow_outputint,
         {"OutputInt", "cflow.outputint",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Flow Output Interface", HFILL}
        },
        {&hf_cflow_flows,
         {"Flows", "cflow.flows",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Flows Aggregated in PDU", HFILL}
        },
        {&hf_cflow_packets,
         {"Packets", "cflow.packets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of packets in flow", HFILL}
        },
        {&hf_cflow_octets,
         {"Octets", "cflow.octets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of bytes in flow", HFILL}
        },
        {&hf_cflow_length_min,
         {"MinLength", "cflow.length_min",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Packet Length Min", HFILL}
        },
        {&hf_cflow_length_max,
         {"MaxLength", "cflow.length_max",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Packet Length Max", HFILL}
        },
        {&hf_cflow_timedelta,
         {"Duration", "cflow.timedelta",
          FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
          "Duration of flow sample (end - start) in seconds", HFILL}
        },
        {&hf_cflow_timestart,
         {"StartTime", "cflow.timestart",
          FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
          "Uptime at start of flow", HFILL}
        },
        {&hf_cflow_timeend,
         {"EndTime", "cflow.timeend",
          FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
          "Uptime at end of flow", HFILL}
        },
        /* TODO: allow transport lookup on these ports, assuming have already read protocol? */
        {&hf_cflow_srcport,
         {"SrcPort", "cflow.srcport",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Flow Source Port", HFILL}
        },
        {&hf_cflow_dstport,
         {"DstPort", "cflow.dstport",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Flow Destination Port", HFILL}
        },
        {&hf_cflow_prot,
         {"Protocol", "cflow.protocol",
          FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
          "IP Protocol", HFILL}
        },
        {&hf_cflow_tos,
         {"IP ToS", "cflow.tos",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          "IP Type of Service", HFILL}
        },
        {&hf_cflow_marked_tos,
         {"Marked ToS", "cflow.marked_tos",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_flags,
         {"Export Flags", "cflow.flags",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          "CFlow Flags", HFILL}
        },
        {&hf_cflow_tcpflags,
         {"TCP Flags", "cflow.tcpflags",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags16,
         {"TCP Flags", "cflow.tcpflags",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags_fin,
         {"FIN", "cflow.tcpflags.fin",
          FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x01,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags_syn,
         {"SYN", "cflow.tcpflags.syn",
          FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x02,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags_rst,
         {"RST", "cflow.tcpflags.rst",
          FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x04,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags_psh,
         {"PSH", "cflow.tcpflags.psh",
          FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x08,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags_ack,
         {"ACK", "cflow.tcpflags.ack",
          FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x10,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags_urg,
         {"URG", "cflow.tcpflags.urg",
          FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x20,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags16_fin,
         {"FIN", "cflow.tcpflags.fin",
          FT_BOOLEAN, 16, TFS(&tfs_used_notused), 0x0001,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags16_syn,
         {"SYN", "cflow.tcpflags.syn",
          FT_BOOLEAN, 16, TFS(&tfs_used_notused), 0x0002,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags16_rst,
         {"RST", "cflow.tcpflags.rst",
          FT_BOOLEAN, 16, TFS(&tfs_used_notused), 0x0004,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags16_psh,
         {"PSH", "cflow.tcpflags.psh",
          FT_BOOLEAN, 16, TFS(&tfs_used_notused), 0x0008,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags16_ack,
         {"ACK", "cflow.tcpflags.ack",
          FT_BOOLEAN, 16, TFS(&tfs_used_notused), 0x0010,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags16_urg,
         {"URG", "cflow.tcpflags.urg",
          FT_BOOLEAN, 16, TFS(&tfs_used_notused), 0x0020,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags16_ece,
         {"ECN Echo", "cflow.tcpflags.ece",
          FT_BOOLEAN, 16, TFS(&tfs_used_notused), 0x0040,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags16_cwr,
         {"CWR", "cflow.tcpflags.cwr",
          FT_BOOLEAN, 16, TFS(&tfs_used_notused), 0x0080,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags16_ns,
         {"ECN Nonce Sum", "cflow.tcpflags.ns",
          FT_BOOLEAN, 16, TFS(&tfs_used_notused), 0x0100,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags_reserved,
         {"Reserved", "cflow.tcpflags.reserved",
          FT_UINT8, BASE_HEX, NULL, 0xc0,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags16_reserved,
         {"Reserved", "cflow.tcpflags.reserved",
          FT_UINT16, BASE_HEX, NULL, 0x0e00,
          NULL, HFILL}
        },
        {&hf_cflow_tcpflags16_zero,
         {"Zero (Header Length)", "cflow.tcpflags.zero",
          FT_UINT16, BASE_HEX, NULL, 0xf000,
          NULL, HFILL}
        },
        {&hf_cflow_srcas,
         {"SrcAS", "cflow.srcas",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Source AS", HFILL}
        },
        {&hf_cflow_dstas,
         {"DstAS", "cflow.dstas",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Destination AS", HFILL}
        },
        {&hf_cflow_srcmask,
         {"SrcMask", "cflow.srcmask",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Source Prefix Mask", HFILL}
        },
        {&hf_cflow_srcmask_v6,
         {"SrcMask", "cflow.srcmaskv6",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "IPv6 Source Prefix Mask", HFILL}
        },
        {&hf_cflow_dstmask,
         {"DstMask", "cflow.dstmask",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Destination Prefix Mask", HFILL}
        },
        {&hf_cflow_dstmask_v6,
         {"DstMask", "cflow.dstmaskv6",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "IPv6 Destination Prefix Mask", HFILL}
        },
        {&hf_cflow_routersc,
         {"Router Shortcut", "cflow.routersc",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Router shortcut by switch", HFILL}
        },
        {&hf_cflow_mulpackets,
         {"MulticastPackets", "cflow.mulpackets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of multicast packets", HFILL}
        },
        {&hf_cflow_muloctets,
         {"MulticastOctets", "cflow.muloctets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of multicast octets", HFILL}
        },
        {&hf_cflow_octets_exp,
         {"OctetsExp", "cflow.octetsexp",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Octets exported", HFILL}
        },
        {&hf_cflow_packets_exp,
         {"PacketsExp", "cflow.packetsexp",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Packets exported", HFILL}
        },
        {&hf_cflow_flows_exp,
         {"FlowsExp", "cflow.flowsexp",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Flows exported", HFILL}
        },
        {&hf_cflow_ipv4_router_sc,
         {"ipv4RouterSc", "cflow.ipv4_router_sc",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "ipv4 Router Shortcur", HFILL}
        },
        {&hf_cflow_srcprefix,
         {"SrcPrefix", "cflow.srcprefix",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Flow Source Prefix", HFILL}
        },
        {&hf_cflow_dstprefix,
         {"DstPrefix", "cflow.dstprefix",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Flow Destination Prefix", HFILL}
        },
        {&hf_cflow_mpls_top_label_type,
         {"TopLabelType", "cflow.toplabeltype",
          FT_UINT8, BASE_DEC, VALS(special_mpls_top_label_type), 0x0,
          "Top MPLS label Type", HFILL}
        },
        {&hf_cflow_mpls_pe_addr,
         {"TopLabelAddr", "cflow.toplabeladdr",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Top MPLS label PE address", HFILL}
        },
        {&hf_cflow_sampler_id,
         {"SamplerID", "cflow.sampler_id",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Flow Sampler ID", HFILL}
        },
        {&hf_cflow_sampler_mode,
         {"SamplerMode", "cflow.sampler_mode",
          FT_UINT8, BASE_DEC, VALS(v9_sampler_mode), 0x0,
          "Flow Sampler Mode", HFILL}
        },
        {&hf_cflow_sampler_random_interval,
         {"SamplerRandomInterval", "cflow.sampler_random_interval",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Flow Sampler Random Interval", HFILL}
        },
        {&hf_cflow_flow_class,
         {"FlowClass", "cflow.flow_class",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Flow Class", HFILL}
        },
        {&hf_cflow_ttl_minimum,
         {"MinTTL", "cflow.ttl_min",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "TTL minimum", HFILL}
        },
        {&hf_cflow_ttl_maximum,
         {"MaxTTL", "cflow.ttl_max",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "TTL maximum", HFILL}
        },
        {&hf_cflow_frag_id,
         {"fragIdent", "cflow.frag_ident",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Fragment Identifier", HFILL}
        },
        {&hf_cflow_ip_version,
         {"IPVersion", "cflow.ip_version",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "IP Version", HFILL}
        },
        {&hf_cflow_direction,
         {"Direction", "cflow.direction",
          FT_UINT8, BASE_DEC, VALS(v9_direction), 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_if_name,
         {"IfName", "cflow.if_name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "SNMP Interface Name", HFILL}
        },
        {&hf_cflow_if_descr,
         {"IfDescr", "cflow.if_descr",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "SNMP Interface Description", HFILL}
        },
        {&hf_cflow_sampler_name,
         {"SamplerName", "cflow.sampler_name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "Sampler Name", HFILL}
        },
        {&hf_cflow_forwarding_status,
         {"ForwardingStatus", "cflow.forwarding_status",
          FT_UINT8, BASE_DEC, VALS(v9_forwarding_status), 0xC0,
          "Forwarding Status", HFILL}
        },
        {&hf_cflow_forwarding_status_unknown_code,
         {"ForwardingStatusUnknown", "cflow.forwarding_status_unknown_code",
          FT_UINT8, BASE_DEC, VALS(v9_forwarding_status_unknown_code), 0x3F,
          NULL, HFILL}
        },
        {&hf_cflow_forwarding_status_forward_code,
         {"ForwardingStatusForwardCode", "cflow.forwarding_status_forward_code",
          FT_UINT8, BASE_DEC, VALS(v9_forwarding_status_forward_code), 0x3F,
          NULL, HFILL}
        },
        {&hf_cflow_forwarding_status_drop_code,
         {"ForwardingStatusDropCode", "cflow.forwarding_status_drop_code",
          FT_UINT8, BASE_DEC, VALS(v9_forwarding_status_drop_code), 0x3F,
          NULL, HFILL}
        },
        {&hf_cflow_forwarding_status_consume_code,
         {"ForwardingStatusConsumeCode", "cflow.forwarding_status_consume_code",
          FT_UINT8, BASE_DEC, VALS(v9_forwarding_status_consume_code), 0x3F,
          NULL, HFILL}
        },
        {&hf_cflow_nbar_appl_desc,
         {"ApplicationDesc", "cflow.appl_desc",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "Application Desc (NBAR)", HFILL}
        },
        {&hf_cflow_nbar_appl_id,
         {"ApplicationID", "cflow.appl_id",
          FT_UINT32, BASE_CUSTOM, CF_FUNC(nbar_fmt_id), 0x0,
          "Application ID (NBAR)", HFILL}
        },
        {&hf_cflow_nbar_appl_name,
         {"ApplicationName", "cflow.appl_name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "Application Name (NBAR)", HFILL}
        },
        {&hf_cflow_peer_srcas,
         {"PeerSrcAS", "cflow.peer_srcas",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Peer Source AS", HFILL}
        },
        {&hf_cflow_peer_dstas,
         {"PeerDstAS", "cflow.peer_dstas",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Peer Destination AS", HFILL}
        },
        {&hf_cflow_flow_exporter,
         {"FlowExporter", "cflow.flow_exporter",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_icmp_ipv4_type,
         {"IPv4 ICMP Type", "cflow.icmp_ipv4_type",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_icmp_ipv4_code,
         {"IPv4 ICMP Code", "cflow.icmp_ipv4_code",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_icmp_ipv6_type,
         {"IPv6 ICMP Type", "cflow.icmp_ipv6_type",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_icmp_ipv6_code,
         {"IPv6 ICMP Code", "cflow.icmp_ipv6_code",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_tcp_window_size,
         {"TCP Windows Size", "cflow.tcp_windows_size",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ipv4_total_length,
         {"IPV4 Total Length", "cflow.ipv4_total_length",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ip_ttl,
         {"IP TTL", "cflow.ip_ttl",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "IP time to live", HFILL}
        },
        {&hf_cflow_mpls_payload_length,
         {"mplsPayloadLength", "cflow.mpls_payload_length",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ip_dscp,
         {"DSCP", "cflow.ip_dscp",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_delta_octets_squared,
         {"DeltaOctetsSquared", "cflow.delta_octets_squared",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_total_octets_squared,
         {"TotalOctetsSquared", "cflow.total_octets_squared",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_udp_length,
         {"UDP Length", "cflow.udp_length",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_is_multicast,
         {"IsMulticast", "cflow.is_multicast",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ip_header_words,
         {"IPHeaderLen", "cflow.ip_header_words",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_option_map,
         {"OptionMap", "cflow.option_map",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_section_header,
         {"SectionHeader", "cflow.section_header",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          "Header of Packet", HFILL}
        },
        {&hf_cflow_section_payload,
         {"SectionPayload", "cflow.section_payload",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          "Payload of Packet", HFILL}
        },
        /* IPFIX Information Elements */
        {&hf_cflow_post_octets,
         {"Post Octets", "cflow.post_octets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of post bytes", HFILL}
        },
        {&hf_cflow_post_packets,
         {"Post Packets", "cflow.post_packets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of post packets", HFILL}
        },
        {&hf_cflow_ipv6_flowlabel,
         {"ipv6FlowLabel", "cflow.ipv6flowlabel",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "IPv6 Flow Label", HFILL}
        },
        {&hf_cflow_post_tos,
         {"Post IP ToS", "cflow.post_tos",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          "Post IP Type of Service", HFILL}
        },
        {&hf_cflow_srcmac,
         {"Source Mac Address", "cflow.srcmac",
          FT_ETHER, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_dstmac,
         {"Post Destination Mac Address", "cflow.post_dstmac",
          FT_ETHER, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_vlanid,
         {"Vlan Id", "cflow.vlanid",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_vlanid,
         {"Post Vlan Id", "cflow.post_vlanid",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ipv6_exthdr,
         {"IPv6 Extension Headers", "cflow.ipv6_exthdr",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_dstmac,
         {"Destination Mac Address", "cflow.dstmac",
          FT_ETHER, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_srcmac,
         {"Post Source Mac Address", "cflow.post_srcmac",
          FT_ETHER, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_permanent_packets,
         {"Permanent Packets", "cflow.permanent_packets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Running Count of packets for permanent flows", HFILL}
        },
        {&hf_cflow_permanent_octets,
         {"Permanent Octets", "cflow.permanent_octets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Running Count of bytes for permanent flows", HFILL}
        },
        {&hf_cflow_fragment_offset,
         {"Fragment Offset", "cflow.fragment_offset",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_mpls_vpn_rd,
         {"MPLS VPN RD", "cflow.mpls_vpn_rd",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          "MPLS VPN Route Distinguisher", HFILL}
        },
        {&hf_cflow_mpls_top_label_prefix_length,
         {"MPLS Top Label Prefix Length", "cflow.mpls_top_label_prefix_length",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_src_traffic_index,
         {"Src Traffic Index", "cflow.src_traffic_index",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_dst_traffic_index,
         {"Dst Traffic Index", "cflow.dst_traffic_index",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_ip_diff_serv_code_point,
         {"Post Ip Diff Serv Code Point", "cflow.post_ip_diff_serv_code_point",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_multicast_replication_factor,
         {"Multicast Replication Factor", "cflow.multicast_replication_factor",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_classification_engine_id,
         {"Classification Engine Id", "cflow.classification_engine_id",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_exporter_addr,
         {"ExporterAddr", "cflow.exporter_addr",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Flow Exporter Address", HFILL}
        },
        {&hf_cflow_exporter_addr_v6,
         {"ExporterAddr", "cflow.exporter_addr_v6",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          "Flow Exporter Address", HFILL}
        },
        {&hf_cflow_drop_octets,
         {"Dropped Octets", "cflow.drop_octets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of dropped bytes", HFILL}
        },
        {&hf_cflow_drop_packets,
         {"Dropped Packets", "cflow.drop_packets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of dropped packets", HFILL}
        },
        {&hf_cflow_drop_total_octets,
         {"Dropped Total Octets", "cflow.drop_total_octets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of total dropped bytes", HFILL}
        },
        {&hf_cflow_drop_total_packets,
         {"Dropped Total Packets", "cflow.drop_total_packets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of total dropped packets", HFILL}
        },
        {&hf_cflow_flow_end_reason,
         {"Flow End Reason", "cflow.flow_end_reason",
          FT_UINT8, BASE_DEC, VALS(v9_flow_end_reason), 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_common_properties_id,
         {"Common Properties Id", "cflow.common_properties_id",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_observation_point_id,
         {"Observation Point Id", "cflow.observation_point_id",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_mpls_pe_addr_v6,
         {"TopLabelAddr V6", "cflow.toplabeladdr_v6",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          "Top MPLS label PE address IPv6", HFILL}
        },
        {&hf_cflow_port_id,
         {"Port Id", "cflow.port_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_mp_id,
         {"Metering Process Id", "cflow.mp_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_wlan_channel_id,
         {"Wireless LAN Channel Id", "cflow.wlan_channel_id",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_wlan_ssid,
         {"Wireless LAN SSId", "cflow.wlan_ssid",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_flow_id,
         {"Flow Id", "cflow.flow_id",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_od_id,
         {"Observation Domain Id", "cflow.od_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Identifier of an Observation Domain that is locally unique to an Exporting Process", HFILL}
        },
        {&hf_cflow_sys_init_time,
         {"System Init Time", "cflow.sys_init_time",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_abstimestart,
         {"StartTime", "cflow.abstimestart",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          "Uptime at start of flow", HFILL}
        },
        {&hf_cflow_abstimeend,
         {"EndTime", "cflow.abstimeend",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          "Uptime at end of flow", HFILL}
        },
        {&hf_cflow_dstnet_v6,
         {"DstNet", "cflow.dstnetv6",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          "Flow Destination Network (IPv6)", HFILL}
        },
        {&hf_cflow_srcnet_v6,
         {"SrcNet", "cflow.srcnetv6",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          "Flow Source Network (IPv6)", HFILL}
        },
        {&hf_cflow_ignore_packets,
         {"Ignored Packets", "cflow.ignore_packets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of ignored packets", HFILL}
        },
        {&hf_cflow_ignore_octets,
         {"Ignored Octets", "cflow.ignore_octets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of ignored octets", HFILL}
        },
        {&hf_cflow_notsent_flows,
         {"Not Sent Flows", "cflow.notsent_flows",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of not sent flows", HFILL}
        },
        {&hf_cflow_notsent_packets,
         {"Not Sent Packets", "cflow.notsent_packets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of not sent packets", HFILL}
        },
        {&hf_cflow_notsent_octets,
         {"Not Sent Octets", "cflow.notsent_octets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of not sent octets", HFILL}
        },
        {&hf_cflow_post_total_octets,
         {"Post Total Octets", "cflow.post_total_octets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of post total octets", HFILL}
        },
        {&hf_cflow_post_total_packets,
         {"Post Total Packets", "cflow.post_total_packets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of post total packets", HFILL}
        },
        {&hf_cflow_key,
         {"floKeyIndicator", "cflow.post_key",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          "Flow Key Indicator", HFILL}
        },
        {&hf_cflow_post_total_mulpackets,
         {"Post Total Multicast Packets", "cflow.post_total_mulpackets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of post total multicast packets", HFILL}
        },
        {&hf_cflow_post_total_muloctets,
         {"Post Total Multicast Octets", "cflow.post_total_muloctets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of post total multicast octets", HFILL}
        },
        {&hf_cflow_tcp_seq_num,
         {"TCP Sequence Number", "cflow.tcp_seq_num",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_tcp_ack_num,
         {"TCP Acknowledgement Number", "cflow.tcp_ack_num",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_tcp_urg_ptr,
         {"TCP Urgent Pointer", "cflow.tcp_urg_ptr",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_tcp_header_length,
         {"TCP Header Length", "cflow.tcp_header_length",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ip_header_length,
         {"IP Header Length", "cflow.ip_header_length",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ipv6_payload_length,
         {"IPv6 Payload Length", "cflow.ipv6_payload_length",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ipv6_next_hdr,
         {"IPv6 Next Header", "cflow.ipv6_next_hdr",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ip_precedence,
         {"IP Precedence", "cflow.ip_precedence",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ip_fragment_flags,
         {"IP Fragment Flags", "cflow.ip_fragment_flags",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_mpls_top_label_ttl,
         {"MPLS Top Label TTL", "cflow.mpls_top_label_ttl",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "MPLS top label time to live", HFILL}
        },
        {&hf_cflow_mpls_label_length,
         {"MPLS Label Stack Length", "cflow.mpls_label_length",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "The length of the MPLS label stac", HFILL}
        },
        {&hf_cflow_mpls_label_depth,
         {"MPLS Label Stack Depth", "cflow.mpls_label_depth",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "The number of labels in the MPLS label stack", HFILL}
        },
        {&hf_cflow_ip_payload_length,
         {"IP Payload Length", "cflow.ip_payload_length",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_mpls_top_label_exp,
         {"MPLS Top Label Exp", "cflow.mpls_top_label_exp",
          FT_UINT8, BASE_OCT, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_tcp_option_map,
         {"TCP OptionMap", "cflow.tcp_option_map",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          "TCP Option Map", HFILL}
        },
        {&hf_cflow_collector_addr,
         {"CollectorAddr", "cflow.collector_addr",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Flow Collector Address (IPv4)", HFILL}
        },
        {&hf_cflow_collector_addr_v6,
         {"CollectorAddr", "cflow.collector_addr_v6",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          "Flow Collector Address (IPv6)", HFILL}
        },
        {&hf_cflow_export_interface,
         {"ExportInterface", "cflow.export_interface",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_export_protocol_version,
         {"ExportProtocolVersion", "cflow.export_protocol_version",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_export_prot,
         {"ExportTransportProtocol", "cflow.exporter_protocol",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Transport Protocol used by the Exporting Process", HFILL}
        },
        {&hf_cflow_collector_port,
         {"CollectorPort", "cflow.collector_port",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Flow Collector Port", HFILL}
        },
        {&hf_cflow_exporter_port,
         {"ExporterPort", "cflow.exporter_port",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Flow Exporter Port", HFILL}
        },
        {&hf_cflow_total_tcp_syn,
         {"Total TCP syn", "cflow.total_tcp_syn",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of total TCP syn", HFILL}
        },
        {&hf_cflow_total_tcp_fin,
         {"Total TCP fin", "cflow.total_tcp_fin",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of total TCP fin", HFILL}
        },
        {&hf_cflow_total_tcp_rst,
         {"Total TCP rst", "cflow.total_tcp_rst",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of total TCP rst", HFILL}
        },
        {&hf_cflow_total_tcp_psh,
         {"Total TCP psh", "cflow.total_tcp_psh",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of total TCP psh", HFILL}
        },
        {&hf_cflow_total_tcp_ack,
         {"Total TCP ack", "cflow.total_tcp_ack",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of total TCP ack", HFILL}
        },
        {&hf_cflow_total_tcp_urg,
         {"Total TCP urg", "cflow.total_tcp_urg",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Count of total TCP urg", HFILL}
        },
        {&hf_cflow_ip_total_length,
         {"IP Total Length", "cflow.ip_total_length",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_natsource_ipv4_address,
         {"Post NAT Source IPv4 Address", "cflow.post_natsource_ipv4_address",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_natdestination_ipv4_address,
         {"Post NAT Destination IPv4 Address", "cflow.post_natdestination_ipv4_address",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_naptsource_transport_port,
         {"Post NAPT Source Transport Port", "cflow.post_naptsource_transport_port",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_naptdestination_transport_port,
         {"Post NAPT Destination Transport Port", "cflow.post_naptdestination_transport_port",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_nat_originating_address_realm,
         {"Nat Originating Address Realm", "cflow.nat_originating_address_realm",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_nat_event,
         {"Nat Event", "cflow.nat_event",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_initiator_octets,
         {"Initiator Octets", "cflow.initiator_octets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_responder_octets,
         {"Responder Octets", "cflow.responder_octets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_firewall_event,
         {"Firewall Event", "cflow.firewall_event",
          FT_UINT8, BASE_DEC, VALS(v9_firewall_event), 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ingress_vrfid,
         {"Ingress VRFID", "cflow.ingress_vrfid",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_egress_vrfid,
         {"Egress VRFID", "cflow.egress_vrfid",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_vrfname,
         {"VRFname", "cflow.vrfname",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_mpls_top_label_exp,
         {"Post MPLS Top Label Exp", "cflow.post_mpls_top_label_exp",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_tcp_window_scale,
         {"Tcp Window Scale", "cflow.tcp_window_scale",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_biflow_direction,
         {"Biflow Direction", "cflow.biflow_direction",
          FT_UINT8, BASE_DEC, VALS(v9_biflow_direction), 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ethernet_header_length,
         {"Ethernet Header Length", "cflow.ethernet_header_length",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ethernet_payload_length,
         {"Ethernet Payload Length", "cflow.ethernet_payload_length",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ethernet_total_length,
         {"Ethernet Total Length", "cflow.ethernet_total_length",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_dot1q_vlan_id,
         {"Dot1q Vlan Id", "cflow.dot1q_vlan_id",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_dot1q_priority,
         {"Dot1q Priority", "cflow.dot1q_priority",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_dot1q_customer_vlan_id,
         {"Dot1q Customer Vlan Id", "cflow.dot1q_customer_vlan_id",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_dot1q_customer_priority,
         {"Dot1q Customer Priority", "cflow.dot1q_customer_priority",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_metro_evc_id,
         {"Metro Evc Id", "cflow.metro_evc_id",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_metro_evc_type,
         {"Metro Evc Type", "cflow.metro_evc_type",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_pseudo_wire_id,
         {"Pseudo Wire Id", "cflow.pseudo_wire_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_pseudo_wire_type,
         {"Pseudo Wire Type", "cflow.pseudo_wire_type",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_pseudo_wire_control_word,
         {"Pseudo Wire Control Word", "cflow.pseudo_wire_control_word",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ingress_physical_interface,
         {"Ingress Physical Interface", "cflow.ingress_physical_interface",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_egress_physical_interface,
         {"Egress Physical Interface", "cflow.egress_physical_interface",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_dot1q_vlan_id,
         {"Post Dot1q Vlan Id", "cflow.post_dot1q_vlan_id",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_dot1q_customer_vlan_id,
         {"Post Dot1q Customer Vlan Id", "cflow.post_dot1q_customer_vlan_id",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ethernet_type,
         {"Ethernet Type", "cflow.ethernet_type",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_ip_precedence,
         {"Post Ip Precedence", "cflow.post_ip_precedence",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_collection_time_milliseconds,
         {"Collection Time Milliseconds", "cflow.collection_time_milliseconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_export_sctp_stream_id,
         {"Export Sctp Stream Id", "cflow.export_sctp_stream_id",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_max_export_seconds,
         {"Max Export Seconds", "cflow.max_export_seconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_max_flow_end_seconds,
         {"Max Flow End Seconds", "cflow.max_flow_end_seconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_message_md5_checksum,
         {"Message MD5 Checksum", "cflow.message_md5_checksum",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_message_scope,
         {"Message Scope", "cflow.message_scope",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_min_export_seconds,
         {"Min Export Seconds", "cflow.min_export_seconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_min_flow_start_seconds,
         {"Min Flow Start Seconds", "cflow.min_flow_start_seconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_opaque_octets,
         {"Opaque Octets", "cflow.opaque_octets",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_session_scope,
         {"Session Scope", "cflow.session_scope",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_max_flow_end_microseconds,
         {"Max Flow End Microseconds", "cflow.max_flow_end_microseconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_max_flow_end_milliseconds,
         {"Max Flow End Milliseconds", "cflow.max_flow_end_milliseconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_max_flow_end_nanoseconds,
         {"Max Flow End Nanoseconds", "cflow.max_flow_end_nanoseconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_min_flow_start_microseconds,
         {"Min Flow Start Microseconds", "cflow.min_flow_start_microseconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_min_flow_start_milliseconds,
         {"Min Flow Start Milliseconds", "cflow.min_flow_start_milliseconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_min_flow_start_nanoseconds,
         {"Min Flow Start Nanoseconds", "cflow.min_flow_start_nanoseconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_collector_certificate,
         {"Collector Certificate", "cflow.collector_certificate",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_exporter_certificate,
         {"Exporter Certificate", "cflow.exporter_certificate",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_data_records_reliability,
         {"Data Records Reliability", "cflow.data_records_reliability",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_observation_point_type,
         {"Observation Point Type", "cflow.observation_point_type",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_new_connection_delta_count,
         {"New Connection Delta Count", "cflow.new_connection_delta_count",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_connection_sum_duration_seconds,
         {"Connection Sum Duration Seconds", "cflow.connection_sum_duration_seconds",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_connection_transaction_id,
         {"Connection Transaction Id", "cflow.connection_transaction_id",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_nat_source_ipv6_address,
         {"Post NAT Source IPv6 Address", "cflow.post_nat_source_ipv6_address",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_post_nat_destination_ipv6_address,
         {"Post NAT Destination IPv6 Address", "cflow.post_nat_destination_ipv6_address",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_nat_pool_id,
         {"Nat Pool Id", "cflow.nat_pool_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_nat_pool_name,
         {"Nat Pool Name", "cflow.nat_pool_name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_anonymization_flags,
         {"Anonymization Flags", "cflow.anonymization_flags",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_anonymization_technique,
         {"Anonymization Technique", "cflow.anonymization_technique",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_information_element_index,
         {"Information Element Index", "cflow.information_element_index",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_p2p_technology,
         {"P2p Technology", "cflow.p2p_technology",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_tunnel_technology,
         {"Tunnel Technology", "cflow.tunnel_technology",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_encrypted_technology,
         {"Encrypted Technology", "cflow.encrypted_technology",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_bgp_validity_state,
         {"Bgp Validity State", "cflow.bgp_validity_state",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_ipsec_spi,
         {"IPSec SPI", "cflow.ipsec_spi",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_gre_key,
         {"Gre Key", "cflow.gre_key",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_nat_type,
         {"Nat Type", "cflow.nat_type",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_initiator_packets,
         {"Initiator Packets", "cflow.initiator_packets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_responder_packets,
         {"Responder Packets", "cflow.responder_packets",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_observation_domain_name,
         {"Observation Domain Name", "cflow.observation_domain_name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_selection_sequence_id,
         {"Selection Sequence Id", "cflow.selection_sequence_id",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_selector_id,
         {"Selector Id", "cflow.selector_id",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_information_element_id,
         {"Information Element Id", "cflow.information_element_id",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_selector_algorithm,
         {"Selector Algorithm", "cflow.selector_algorithm",
          FT_UINT16, BASE_DEC|BASE_EXT_STRING, &selector_algorithm_ext, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_sampling_packet_interval,
         {"Sampling Packet Interval", "cflow.sampling_packet_interval",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_sampling_packet_space,
         {"Sampling Packet Space", "cflow.sampling_packet_space",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_sampling_time_interval,
         {"Sampling Time Interval", "cflow.sampling_time_interval",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_sampling_time_space,
         {"Sampling Time Space", "cflow.sampling_time_space",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_sampling_size,
         {"Sampling Size", "cflow.sampling_size",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_sampling_population,
         {"Sampling Population", "cflow.sampling_population",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_sampling_probability_float32,
         {"Sampling Probability", "cflow.sampling_probability",
          FT_FLOAT, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_sampling_probability_float64,
         {"Sampling Probability", "cflow.sampling_probability",
          FT_DOUBLE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_data_link_frame_size,
         {"Data Link Frame Size", "cflow.data_link_frame_size",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_data_link_frame_section,
         {"Data Link Frame Section", "cflow.data_link_frame_section",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_mpls_label_stack_section,
         {"MPLS Label Stack Section", "cflow.mpls_label_stack_section",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_mpls_payload_packet_section,
         {"MPLS Payload Packet Section", "cflow.mpls_payload_packet_section",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_selector_id_total_pkts_observed,
         {"Selector Id Total Pkts Observed", "cflow.selector_id_total_pkts_observed",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_selector_id_total_pkts_selected,
         {"Selector Id Total Pkts Selected", "cflow.selector_id_total_pkts_selected",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_absolute_error_float32,
         {"Absolute Error", "cflow.absolute_error",
          FT_FLOAT, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_absolute_error_float64,
         {"Absolute Error", "cflow.absolute_error",
          FT_DOUBLE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_relative_error_float32,
         {"Relative Error", "cflow.relative_error",
          FT_FLOAT, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_relative_error_float64,
         {"Relative Error", "cflow.relative_error",
          FT_DOUBLE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_observation_time_seconds,
         {"Observation Time Seconds", "cflow.observation_time_seconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_observation_time_milliseconds,
         {"Observation Time Milliseconds", "cflow.observation_time_milliseconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_observation_time_microseconds,
         {"Observation Time Microseconds", "cflow.observation_time_microseconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_observation_time_nanoseconds,
         {"Observation Time Nanoseconds", "cflow.observation_time_nanoseconds",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_digest_hash_value,
         {"Digest Hash Value", "cflow.digest_hash_value",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_hash_ippayload_offset,
         {"Hash IPPayload Offset", "cflow.hash_ippayload_offset",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_hash_ippayload_size,
         {"Hash IPPayload Size", "cflow.hash_ippayload_size",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_hash_output_range_min,
         {"Hash Output Range Min", "cflow.hash_output_range_min",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_hash_output_range_max,
         {"Hash Output Range Max", "cflow.hash_output_range_max",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_hash_selected_range_min,
         {"Hash Selected Range Min", "cflow.hash_selected_range_min",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_hash_selected_range_max,
         {"Hash Selected Range Max", "cflow.hash_selected_range_max",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_hash_digest_output,
         {"Hash Digest Output", "cflow.hash_digest_output",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_hash_initialiser_value,
         {"Hash Initialiser Value", "cflow.hash_initialiser_value",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_selector_name,
         {"Selector Name", "cflow.selector_name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_upper_cilimit_float32,
         {"Upper CILimit", "cflow.upper_cilimit",
          FT_FLOAT, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_upper_cilimit_float64,
         {"Upper CILimit", "cflow.upper_cilimit",
          FT_DOUBLE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_lower_cilimit_float32,
         {"Lower CILimit", "cflow.lower_cilimit",
          FT_FLOAT, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_lower_cilimit_float64,
         {"Lower CILimit", "cflow.lower_cilimit",
          FT_DOUBLE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_confidence_level_float32,
         {"Confidence Level", "cflow.confidence_level",
          FT_FLOAT, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_confidence_level_float64,
         {"Confidence Level", "cflow.confidence_level",
          FT_DOUBLE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* TODO: want to add a value_string, but where defined in RFCs? */
        {&hf_cflow_information_element_data_type,
         {"Information Element Data Type", "cflow.information_element_data_type",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_information_element_description,
         {"Information Element Description", "cflow.information_element_description",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_information_element_name,
         {"Information Element Name", "cflow.information_element_name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_information_element_range_begin,
         {"Information Element Range Begin", "cflow.information_element_range_begin",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_information_element_range_end,
         {"Information Element Range End", "cflow.information_element_range_end",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_information_element_semantics,
         {"Information Element Semantics", "cflow.information_element_semantics",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_information_element_units,
         {"Information Element Units", "cflow.information_element_units",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_private_enterprise_number,
         {"Private Enterprise Number", "cflow.private_enterprise_number",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },

        {&hf_cflow_virtual_station_interface_id,
         {"Virtual Station Interface Id", "cflow.virtual_station_interface_id",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_virtual_station_interface_name,
          {"Virtual Station Interface Name", "cflow.virtual_station_interface_name",
           FT_STRING, STR_UNICODE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_virtual_station_uuid,
          {"Virtual Station Uuid", "cflow.virtual_station_uuid",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_virtual_station_name,
          {"Virtual Station Name", "cflow.virtual_station_name",
           FT_STRING, STR_UNICODE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_layer2_segment_id,
          {"Layer2 Segment Id", "cflow.layer2_segment_id",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_layer2_octet_delta_count,
          {"Layer2 Octet Delta Count", "cflow.layer2_octet_delta_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_layer2_octet_total_count,
          {"Layer2 Octet Total Count", "cflow.layer2_octet_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_ingress_unicast_packet_total_count,
          {"Ingress Unicast Packet Total Count", "cflow.ingress_unicast_packet_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_ingress_multicast_packet_total_count,
          {"Ingress Multicast Packet Total Count", "cflow.ingress_multicast_packet_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_ingress_broadcast_packet_total_count,
          {"Ingress Broadcast Packet Total Count", "cflow.ingress_broadcast_packet_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_egress_unicast_packet_total_count,
          {"Egress Unicast Packet Total Count", "cflow.egress_unicast_packet_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_egress_broadcast_packet_total_count,
          {"Egress Broadcast Packet Total Count", "cflow.egress_broadcast_packet_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_monitoring_interval_start_milliseconds,
          {"Monitoring Interval Start MilliSeconds", "cflow.monitoring_interval_start_milliseconds",
           FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_monitoring_interval_end_milliseconds,
          {"Monitoring Interval End MilliSeconds", "cflow.monitoring_interval_end_milliseconds",
           FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_port_range_start,
          {"Port Range Start", "cflow.port_range_start",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_port_range_end,
          {"Port Range End", "cflow.port_range_end",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_port_range_step_size,
          {"Port Range Step Size", "cflow.port_range_step_size",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_port_range_num_ports,
          {"Port Range Num Ports", "cflow.port_range_num_ports",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_sta_mac_address,
          {"Sta Mac Address", "cflow.sta_mac_address",
           FT_ETHER, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_sta_ipv4_address,
          {"Sta Ipv4 Address", "cflow.sta_ipv4_address",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_wtp_mac_address,
          {"Wtp Mac Address", "cflow.wtp_mac_address",
           FT_ETHER, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_ingress_interface_type,
          {"Ingress Interface Type", "cflow.ingress_interface_type",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_egress_interface_type,
          {"Egress Interface Type", "cflow.egress_interface_type",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_rtp_sequence_number,
          {"Rtp Sequence Number", "cflow.rtp_sequence_number",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_user_name,
          {"User Name", "cflow.user_name",
           FT_STRING, STR_UNICODE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_application_category_name,
          {"Application Category Name", "cflow.application_category_name",
           FT_STRING, STR_UNICODE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_application_sub_category_name,
          {"Application Sub Category Name", "cflow.application_sub_category_name",
           FT_STRING, STR_UNICODE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_application_group_name,
          {"Application Group Name", "cflow.application_group_name",
           FT_STRING, STR_UNICODE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_original_flows_present,
          {"Original Flows Present", "cflow.original_flows_present",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_original_flows_initiated,
          {"Original Flows Initiated", "cflow.original_flows_initiated",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_original_flows_completed,
          {"Original Flows Completed", "cflow.original_flows_completed",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_distinct_count_of_source_ip_address,
          {"Distinct Count Of Source Ip Address", "cflow.distinct_count_of_source_ip_address",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_distinct_count_of_destinationip_address,
          {"Distinct Count Of Destinationip Address", "cflow.distinct_count_of_destinationip_address",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_distinct_count_of_source_ipv4_address,
          {"Distinct Count Of Source Ipv4 Address", "cflow.distinct_count_of_source_ipv4_address",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_distinct_count_of_destination_ipv4_address,
          {"Distinct Count Of Destination Ipv4 Address", "cflow.distinct_count_of_destination_ipv4_address",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_distinct_count_of_source_ipv6_address,
          {"Distinct Count Of Source Ipv6 Address", "cflow.distinct_count_of_source_ipv6_address",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_distinct_count_of_destination_ipv6_address,
          {"Distinct Count Of Destination Ipv6 Address", "cflow.distinct_count_of_destination_ipv6_address",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_value_distribution_method,
          {"Value Distribution Method", "cflow.value_distribution_method",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_rfc3550_jitter_milliseconds,
          {"Rfc3550 Jitter Milliseconds", "cflow.rfc3550_jitter_milliseconds",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_rfc3550_jitter_microseconds,
          {"Rfc3550 Jitter Microseconds", "cflow.rfc3550_jitter_microseconds",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_rfc3550_jitter_nanoseconds,
          {"Rfc3550 Jitter Nanoseconds", "cflow.rfc3550_jitter_nanoseconds",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_dot1q_dei,
          {"Dot1q DEI", "cflow.dot1q_dei",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_dot1q_customer_dei,
          {"Dot1q Customer DEI", "cflow.dot1q_customer_dei",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_flow_selector_algorithm,
          {"Flow_Selector_Algorithm", "cflow.flow_selector_algorithm",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_flow_selected_octet_delta_count,
          {"Flow_Selected_Octet_Delta_Count", "cflow.flow_selected_octet_delta_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_flow_selected_packet_delta_count,
          {"Flow_Selected_Packet_Delta_Count", "cflow.flow_selected_packet_delta_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_flow_selected_flow_delta_count,
          {"Flow_Selected_Flow_Delta_Count", "cflow.flow_selected_flow_delta_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_selectorid_total_flows_observed,
          {"Selectorid_Total_Flows_Observed", "cflow.selectorid_total_flows_observed",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_selectorid_total_flows_selected,
          {"Selectorid_Total_Flows_Selected", "cflow.selectorid_total_flows_selected",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_sampling_flow_interval,
          {"Sampling_Flow_Interval", "cflow.sampling_flow_interval",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_sampling_flow_spacing,
          {"Sampling_Flow_Spacing", "cflow.sampling_flow_spacing",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_flow_sampling_time_interval,
          {"Flow_Sampling_Time_Interval", "cflow.flow_sampling_time_interval",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_flow_sampling_time_spacing,
          {"Flow_Sampling_Time_Spacing", "cflow.flow_sampling_time_spacing",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_hash_flow_domain,
          {"Hash_Flow_Domain", "cflow.hash_flow_domain",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_transport_octet_delta_count,
          {"Transport_Octet_Delta_Count", "cflow.transport_octet_delta_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_transport_packet_delta_count,
          {"Transport_Packet_Delta_Count", "cflow.transport_packet_delta_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_original_exporter_ipv4_address,
          {"Original_Exporter_Ipv4_Address", "cflow.original_exporter_ipv4_address",
          FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_original_exporter_ipv6_address,
          {"Original_Exporter_Ipv6_Address", "cflow.original_exporter_ipv6_address",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_original_observation_domain_id,
          {"Original_Observation_Domain_Id", "cflow.original_observation_domain_id",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_intermediate_process_id,
          {"Intermediate_Process_Id", "cflow.intermediate_process_id",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_ignored_data_record_total_count,
          {"Ignored_Data_Record_Total_Count", "cflow.ignored_data_record_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_data_link_frame_type,
          {"Data_Link_Frame_Type", "cflow.data_link_frame_type",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_section_offset,
          {"Section_Offset", "cflow.section_offset",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_section_exported_octets,
          {"Section_Exported_Octets", "cflow.section_exported_octets",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_dot1q_service_instance_tag,
          {"Dot1q_Service_Instance_Tag", "cflow.dot1q_service_instance_tag",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_dot1q_service_instance_id,
          {"Dot1q_Service_Instance_Id", "cflow.dot1q_service_instance_id",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_dot1q_service_instance_priority,
          {"Dot1q_Service_Instance_Priority", "cflow.dot1q_service_instance_priority",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_dot1q_customer_source_mac_address,
          {"Dot1q_Customer_Source_Mac_Address", "cflow.dot1q_customer_source_mac_address",
           FT_ETHER, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_dot1q_customer_destination_mac_address,
          {"Dot1q_Customer_Destination_Mac_Address", "cflow.dot1q_customer_destination_mac_address",
           FT_ETHER, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_post_layer2_octet_delta_count,
          {"Post_Layer2_Octet_Delta_Count", "cflow.post_layer2_octet_delta_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_postm_cast_layer2_octet_delta_count,
          {"Postm_Cast_Layer2_Octet_Delta_Count", "cflow.postm_cast_layer2_octet_delta_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_post_layer2_octet_total_count,
          {"Post_Layer2_Octet_Total_Count", "cflow.post_layer2_octet_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_postm_cast_layer2_octet_total_count,
          {"Postm_Cast_Layer2_Octet_Total_Count", "cflow.postm_cast_layer2_octet_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_minimum_layer2_total_length,
          {"Minimum_Layer2_Total_Length", "cflow.minimum_layer2_total_length",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_maximum_layer2_total_length,
          {"Maximum_Layer2_Total_Length", "cflow.maximum_layer2_total_length",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_dropped_layer2_octet_delta_count,
          {"Dropped_Layer2_Octet_Delta_Count", "cflow.dropped_layer2_octet_delta_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_dropped_layer2_octet_total_count,
          {"Dropped_Layer2_Octet_Total_Count", "cflow.dropped_layer2_octet_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_ignored_layer2_octet_total_count,
          {"Ignored_Layer2_Octet_Total_Count", "cflow.ignored_layer2_octet_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_not_sent_layer2_octet_total_count,
          {"Not_Sent_Layer2_Octet_Total_Count", "cflow.not_sent_layer2_octet_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_layer2_octet_delta_sum_of_squares,
          {"Layer2_Octet_Delta_Sum_Of_Squares", "cflow.layer2_octet_delta_sum_of_squares",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_layer2_octet_total_sum_of_squares,
          {"Layer2_Octet_Total_Sum_Of_Squares", "cflow.layer2_octet_total_sum_of_squares",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_layer2_frame_delta_count,
          {"Layer2_Frame_Delta_Count", "cflow.layer2_frame_delta_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_layer2_frame_total_count,
          {"Layer2_Frame_Total_Count", "cflow.layer2_frame_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_pseudo_wire_destination_ipv4_address,
          {"Pseudo_Wire_Destination_Ipv4_Address", "cflow.pseudo_wire_destination_ipv4_address",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_cflow_ignored_layer2_frame_total_count,
          {"Ignored_Layer2_Frame_Total_Count", "cflow.ignored_layer2_frame_total_count",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },

        /*
         * end pdu content storage
         */
        {&hf_cflow_scope_system,
         {"ScopeSystem", "cflow.scope_system",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          "Option Scope System", HFILL}
        },
        {&hf_cflow_scope_interface,
         {"ScopeInterface", "cflow.scope_interface",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Option Scope Interface", HFILL}
        },
        {&hf_cflow_scope_linecard,
         {"ScopeLinecard", "cflow.scope_linecard",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Option Scope Linecard", HFILL}
        },
        {&hf_cflow_scope_cache,
         {"ScopeCache", "cflow.scope_cache",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          "Option Scope Cache", HFILL}
        },
        {&hf_cflow_scope_template,
         {"ScopeTemplate", "cflow.scope_template",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          "Option Scope Template", HFILL}
        },

        {&hf_cflow_padding,
         {"Padding", "cflow.padding",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },

        {&hf_cflow_reserved,
         {"Reserved", "cflow.reserved",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },

        {&hf_cflow_extra_packets,
         {"Extra packets", "cflow.extra_packets",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },

        /* IPFIX */
        {&hf_cflow_unknown_field_type,
         {"Unknown Field Type", "cflow.unknown_field_type",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_template_ipfix_total_field_count,
         {"Total Field Count", "cflow.template_ipfix_total_field_count",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "IPFIX Options Template Total Field Count", HFILL}
        },
        {&hf_cflow_template_ipfix_scope_field_count,
         {"Scope Field Count", "cflow.template_ipfix_scope_field_count",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "IPFIX Options Template Scope Field Count", HFILL}
        },
        {&hf_cflow_template_ipfix_pen_provided,
         {"Pen provided", "cflow.template_ipfix_pen_provided",
          FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
          "Is Template Enterprise Specific", HFILL}
        },
        {&hf_cflow_template_ipfix_field_type,
         {"Type", "cflow.template_ipfix_field_type",
          FT_UINT16, BASE_DEC|BASE_EXT_STRING, &v9_v10_template_types_ext, 0x7FFF,
          "Template field type", HFILL}
        },
        {&hf_cflow_template_plixer_field_type,
         {"Type", "cflow.template_plixer_field_type",
          FT_UINT16, BASE_DEC|BASE_EXT_STRING, &v10_template_types_plixer_ext, 0x7FFF,
          "Template field type", HFILL}
        },
        {&hf_cflow_template_ntop_field_type,
         {"Type", "cflow.template_ntop_field_type",
          FT_UINT16, BASE_DEC|BASE_EXT_STRING, &v10_template_types_ntop_ext, 0x7FFF,
          "Template field type", HFILL}
        },
        {&hf_cflow_template_ixia_field_type,
         {"Type", "cflow.template_ixia_field_type",
          FT_UINT16, BASE_DEC|BASE_EXT_STRING, &v10_template_types_ixia_ext, 0x7FFF,
          "Template field type", HFILL}
        },
        {&hf_cflow_template_netscaler_field_type,
         {"Type", "cflow.template_netscaler_field_type",
          FT_UINT16, BASE_DEC|BASE_EXT_STRING, &v10_template_types_netscaler_ext, 0x7FFF,
          "Template field type", HFILL}
        },
        {&hf_cflow_template_barracuda_field_type,
         {"Type", "cflow.template_barracuda_field_type",
          FT_UINT16, BASE_DEC|BASE_EXT_STRING, &v10_template_types_barracuda_ext, 0x7FFF,
          "Template field type", HFILL}
        },
        {&hf_cflow_template_ipfix_field_type_enterprise,
         {"Type", "cflow.template_ipfix_field_type_enterprise",
          FT_UINT16, BASE_DEC, NULL, 0x7FFF,
          "Template field type", HFILL}
        },
        {&hf_cflow_template_ipfix_field_pen,
         {"PEN",
          "cflow.template_ipfix_field_pen",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "IPFIX Private Enterprise Number", HFILL}
        },
        {&hf_cflow_cts_sgt_source_tag,
         {"Source SGT",
          "cflow.source_sgt_tag",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_cts_sgt_destination_tag,
         {"Destination SGT",
          "cflow.destination_sgt_tag",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_cts_sgt_source_name,
         {"Source SGT Name",
          "cflow.source_sgt_name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_cts_sgt_destination_name,
         {"Destination SGT Name",
          "cflow.destination_sgt_name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_packets_dropped,
         {"Packets Dropped",
          "cflow.packets_dropped",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_byte_rate,
         {"Byte Rate",
          "cflow.byte_rate",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_application_media_bytes,
         {"Media Bytes",
          "cflow.application_media_bytes",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_application_media_byte_rate,
         {"Media Byte Rate",
          "cflow.media_byte_rate",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_application_media_packets,
         {"Media Packets",
          "cflow.application_media_packets",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_application_media_packet_rate,
         {"Media Packet Rate",
          "cflow.media_packet_rate",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_application_media_event,
         {"Media Event",
          "cflow.application_media_event",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_monitor_event,
         {"Monitor Event",
          "cflow.monitor_event",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_timestamp_interval,
         {"Timestamp Interval",
          "cflow.timestamp_interval",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_packets_expected,
         {"Transport Packets Expected",
          "cflow.transport_packets_expected",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_round_trip_time_string,
         {"Transport Round-Trip-Time",
          "cflow.transport_rtt",
          FT_UINT32, BASE_HEX, VALS(performance_monitor_specials), 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_round_trip_time,
         {"Transport Round-Trip-Time",
          "cflow.transport_rtt",
          FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_event_packet_loss,
         {"Transport Packet Loss Events",
          "cflow.transport_packet_loss_event",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_packets_lost,
         {"Transport Packets Lost",
          "cflow.transport_packets_lost",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_packets_lost_string,
         {"Transport Packets Lost",
          "cflow.transport_packets_lost",
          FT_UINT32, BASE_HEX, VALS(performance_monitor_specials), 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_packets_lost_rate,
         {"Transport Packet Loss Rate",
          "cflow.transport_packet_loss_rate",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_packets_lost_rate_string,
         {"Transport Packet Loss Rate",
          "cflow.transport_packet_loss_rate",
          FT_UINT32, BASE_HEX, VALS(performance_monitor_specials) , 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_rtp_ssrc,
         {"RTP SSRC",
          "cflow.transport_rtp_ssrc",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_rtp_jitter_mean,
         {"RTP Mean Jitter",
          "cflow.transport_jitter_mean",
          FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_rtp_jitter_mean_string,
         {"RTP Mean Jitter",
          "cflow.transport_jitter_mean",
          FT_UINT32, BASE_HEX, VALS(performance_monitor_specials), 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_rtp_jitter_min,
         {"RTP Min Jitter",
          "cflow.transport_jitter_min",
          FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_rtp_jitter_min_string,
         {"RTP Min Jitter",
          "cflow.transport_jitter_min",
          FT_UINT32, BASE_HEX, VALS(performance_monitor_specials), 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_rtp_jitter_max,
         {"RTP Max Jitter",
          "cflow.transport_jitter_max",
          FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_rtp_jitter_max_string,
         {"RTP Max Jitter",
          "cflow.transport_jitter_max",
          FT_UINT32, BASE_HEX, VALS(performance_monitor_specials), 0x0,
          NULL, HFILL}
        },

        {&hf_cflow_transport_rtp_payload_type,
         {"RTP Payload Type",
          "cflow.rtp_payload_type",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_rtp_payload_type_string,
         {"RTP Payload Type",
          "cflow.rtp_payload_type",
          FT_UINT8, BASE_HEX, VALS(performance_monitor_specials), 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_transport_bytes_out_of_order,
         {"Transport Bytes Out of Order",
          "cflow.transport_bytes_out_of_ordera",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
#if 0
        {&hf_cflow_transport_packets_out_of_order,
         {"Transport Packets Out of Order",
          "cflow.transport_packets_out_of_order",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
#endif
        {&hf_cflow_transport_packets_out_of_order_string,
         {"Transport Packets Out of Order",
          "cflow.transport_packets_out_of_order",
          FT_UINT32, BASE_HEX, VALS(performance_monitor_specials), 0x0,
          NULL, HFILL}
        },
       {&hf_cflow_transport_tcp_window_size_min,
         {"Transport TCP Window Size Min",
          "cflow.transport_tcp_window_size_min",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
       {&hf_cflow_transport_tcp_window_size_min_string,
         {"Transport TCP Window Size Min",
          "cflow.transport_tcp_window_size_min",
          FT_UINT32, BASE_HEX, VALS(performance_monitor_specials), 0x0,
          NULL, HFILL}
        },
       {&hf_cflow_transport_tcp_window_size_max,
         {"Transport TCP Window Size Max",
          "cflow.transport_tcp_window_size_max",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
       {&hf_cflow_transport_tcp_window_size_max_string,
         {"Transport TCP Window Size Max",
          "cflow.transport_tcp_window_size_max",
          FT_UINT32, BASE_HEX, VALS(performance_monitor_specials), 0x0,
          NULL, HFILL}
        },
       {&hf_cflow_transport_tcp_window_size_mean,
         {"Transport TCP Window Size Mean",
          "cflow.transport_tcp_window_size_mean",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
       {&hf_cflow_transport_tcp_window_size_mean_string,
         {"Transport TCP Window Size Mean",
          "cflow.transport_tcp_window_size_mean",
          FT_UINT32, BASE_HEX, VALS(performance_monitor_specials), 0x0,
          NULL, HFILL}
        },
       {&hf_cflow_transport_tcp_maximum_segment_size,
         {"Transport TCP Maximum Segment Size",
          "cflow.transport_tcp_maximum_segment_size",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
       {&hf_cflow_transport_tcp_maximum_segment_size_string,
         {"Transport TCP Maximum Segment Size",
          "cflow.transport_tcp_maximum_segment_size",
          FT_UINT16, BASE_HEX, VALS(performance_monitor_specials), 0x0,
          NULL, HFILL}
        },
        /* Sequence analysis fields */
       {&hf_cflow_sequence_analysis_expected_sn,
         {"Expected Sequence Number",
          "cflow.sequence_analysis.expected_sn",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
       {&hf_cflow_sequence_analysis_previous_frame,
         {"Previous Frame in Sequence",
          "cflow.sequence_analysis.previous_frame",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },

        /* Ericsson SE NAT Logging */
        {&hf_cflow_nat_context_id,
         {"NAT Context ID", "cflow.nat_context_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Internal context ID", HFILL}
        },
        {&hf_cflow_nat_context_name,
         {"NAT Context Name", "cflow.nat_context_name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "Zero terminated context Name", HFILL}
        },
        {&hf_cflow_nat_assign_time,
         {"NAT Assign Time", "cflow.nat_assign_time",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          "Seconds of UNIX timestamp for assign", HFILL}
        },
        {&hf_cflow_nat_unassign_time,
         {"NAT Unassign Time", "cflow.nat_unassign_time",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          "Seconds of UNIX timestamp for unassign", HFILL}
        },
        {&hf_cflow_nat_int_addr,
         {"Internal IPv4 address", "cflow.nat_int_addr",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_nat_ext_addr,
         {"External IPv4 address", "cflow.nat_ext_addr",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_nat_ext_port_first,
         {"NAT port start", "cflow.nat_ext_port_first",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "External L4 port start", HFILL}
        },
        {&hf_cflow_nat_ext_port_last,
         {"NAT port end", "cflow.nat_ext_port_last",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "External L4 port end", HFILL}
        },
        /* Cisco ASA 5500 Series */
        {&hf_cflow_ingress_acl_id,
         {"Ingress ACL ID", "cflow.ingress_acl_id",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_egress_acl_id,
         {"Egress ACL ID", "cflow.egress_acl_id",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_fw_ext_event,
         {"Extended firewall event code", "cflow.fw_ext_event",
          FT_UINT16, BASE_DEC, VALS(v9_extended_firewall_event), 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_aaa_username,
         {"AAA username", "cflow.aaa_username",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },

        {&hf_ipfix_enterprise_private_entry,
         {"Enterprise Private entry", "cflow.enterprise_private_entry",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* Private Information Elements */

        /* CACE root (a hidden item to allow filtering) */
        {&hf_pie_cace,
         {"CACE", "cflow.pie.cace",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* CACE Technologies, 32622 / 0 */
        {&hf_pie_cace_local_ipv4_address,
         {"Local IPv4 Address", "cflow.pie.cace.localaddr4",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Local IPv4 Address (caceLocalIPv4Address)", HFILL}
        },
        /* CACE Technologies, 32622 / 1 */
        {&hf_pie_cace_remote_ipv4_address,
         {"Remote IPv4 Address", "cflow.pie.cace.remoteaddr4",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          "Remote IPv4 Address (caceRemoteIPv4Address)", HFILL}
        },
        /* CACE Technologies, 32622 / 2 */
        {&hf_pie_cace_local_ipv6_address,
         {"Local IPv6 Address", "cflow.pie.cace.localaddr6",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          "Local IPv6 Address (caceLocalIPv6Address)", HFILL}
        },
        /* CACE Technologies, 32622 / 3 */
        {&hf_pie_cace_remote_ipv6_address,
         {"Remote IPv6 Address", "cflow.pie.cace.remoteaddr6",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          "Remote IPv6 Address (caceRemoteIPv6Address)", HFILL}
        },
        /* CACE Technologies, 32622 / 4 */
        {&hf_pie_cace_local_port,
         {"Local Port", "cflow.pie.cace.localport",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Local Transport Port (caceLocalTransportPort)", HFILL}
        },
        /* CACE Technologies, 32622 / 5 */
        {&hf_pie_cace_remote_port,
         {"Remote Port", "cflow.pie.cace.remoteport",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Remote Transport Port (caceRemoteTransportPort)", HFILL}
        },
        /* CACE Technologies, 32622 / 6 */
        {&hf_pie_cace_local_ipv4_id,
         {"Local IPv4 ID", "cflow.pie.cace.localip4id",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "The IPv4 identification header field from a locally-originated packet (caceLocalIPv4id)", HFILL}
        },
        /* CACE Technologies, 32622 / 7 */
        {&hf_pie_cace_local_icmp_id,
         {"Local ICMP ID", "cflow.pie.cace.localicmpid",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "The ICMP identification header field from a locally-originated ICMPv4 or ICMPv6 echo request (caceLocalICMPid)", HFILL}
        },
        /* CACE Technologies, 32622 / 8 */
        {&hf_pie_cace_local_uid,
         {"Local User ID", "cflow.pie.cace.localuid",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Local User ID (caceLocalProcessUserId)", HFILL}
        },
        /* CACE Technologies, 32622 / 9 */
        {&hf_pie_cace_local_pid,
         {"Local Process ID", "cflow.pie.cace.localpid",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Local Process ID (caceLocalProcessId)", HFILL}
        },
        /* CACE Technologies, 32622 / 10 */
        {&hf_pie_cace_local_username_len,
         {"Local Username Length", "cflow.pie.cace.localusernamelen",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Local User Name Length (caceLocalProcessUserName)", HFILL}
        },
        /* CACE Technologies, 32622 / 10 */
        {&hf_pie_cace_local_username,
         {"Local User Name", "cflow.pie.cace.localusername",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "Local User Name (caceLocalProcessUserName)", HFILL}
        },
        /* CACE Technologies, 32622 / 11 */
        {&hf_pie_cace_local_cmd_len,
         {"Local Command Length", "cflow.pie.cace.localcmdlen",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Local Command Length (caceLocalProcessCommand)", HFILL}
        },
        /* CACE Technologies, 32622 / 11 */
        {&hf_pie_cace_local_cmd,
         {"Local Command", "cflow.pie.cace.localcmd",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "Local Command (caceLocalProcessCommand)", HFILL}
        },

        /* ntop root (a hidden item to allow filtering) */
        {&hf_pie_ntop,
         {"Ntop", "cflow.pie.ntop",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 80 */
        {&hf_pie_ntop_fragmented,
         {"Fragmented", "cflow.pie.ntop.fragmented",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 81 */
        {&hf_pie_ntop_fingerprint,
         {"Fingerprint", "cflow.pie.ntop.fingerprint",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 82 */
        {&hf_pie_ntop_client_nw_delay_sec,
         {"Client_nw_delay_sec", "cflow.pie.ntop.client_nw_delay_sec",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 83 */
        {&hf_pie_ntop_client_nw_delay_usec,
         {"Client_nw_delay_usec", "cflow.pie.ntop.client_nw_delay_usec",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 84 */
        {&hf_pie_ntop_server_nw_delay_sec,
         {"Server_nw_delay_sec", "cflow.pie.ntop.server_nw_delay_sec",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 85 */
        {&hf_pie_ntop_server_nw_delay_usec,
         {"Server_nw_delay_usec", "cflow.pie.ntop.server_nw_delay_usec",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 86 */
        {&hf_pie_ntop_appl_latency_sec,
         {"Appl_latency_sec", "cflow.pie.ntop.appl_latency_sec",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 98 */
        {&hf_pie_ntop_icmp_flags,
         {"Icmp_flags", "cflow.pie.ntop.icmp_flags",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 101 */
        {&hf_pie_ntop_src_ip_country,
         {"Src_ip_country", "cflow.pie.ntop.src_ip_country",
          FT_STRINGZ, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 102 */
        {&hf_pie_ntop_src_ip_city,
         {"Src_ip_city", "cflow.pie.ntop.src_ip_city",
          FT_STRINGZ, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 103 */
        {&hf_pie_ntop_dst_ip_country,
         {"Dst_ip_country", "cflow.pie.ntop.dst_ip_country",
          FT_STRINGZ, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 104 */
        {&hf_pie_ntop_dst_ip_city,
         {"Dst_ip_city", "cflow.pie.ntop.dst_ip_city",
          FT_STRINGZ, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 105 */
        {&hf_pie_ntop_flow_proto_port,
         {"Flow_proto_port", "cflow.pie.ntop.flow_proto_port",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 106 */
        {&hf_pie_ntop_tunnel_id,
         {"Tunnel_id", "cflow.pie.ntop.tunnel_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 107 */
        {&hf_pie_ntop_longest_flow_pkt,
         {"Longest_flow_pkt", "cflow.pie.ntop.longest_flow_pkt",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 108 */
        {&hf_pie_ntop_shortest_flow_pkt,
         {"Shortest_flow_pkt", "cflow.pie.ntop.shortest_flow_pkt",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 109 */
        {&hf_pie_ntop_retransmitted_in_pkts,
         {"Retransmitted_in_pkts", "cflow.pie.ntop.retransmitted_in_pkts",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 110 */
        {&hf_pie_ntop_retransmitted_out_pkts,
         {"Retransmitted_out_pkts", "cflow.pie.ntop.retransmitted_out_pkts",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 111 */
        {&hf_pie_ntop_ooorder_in_pkts,
         {"Ooorder_in_pkts", "cflow.pie.ntop.ooorder_in_pkts",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 112 */
        {&hf_pie_ntop_ooorder_out_pkts,
         {"Ooorder_out_pkts", "cflow.pie.ntop.ooorder_out_pkts",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 113 */
        {&hf_pie_ntop_untunneled_protocol,
         {"Untunneled_protocol", "cflow.pie.ntop.untunneled_protocol",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 114 */
        {&hf_pie_ntop_untunneled_ipv4_src_addr,
         {"Untunneled_ipv4_src_addr", "cflow.pie.ntop.untunneled_ipv4_src_addr",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 115 */
        {&hf_pie_ntop_untunneled_l4_src_port,
         {"Untunneled_l4_src_port", "cflow.pie.ntop.untunneled_l4_src_port",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 116 */
        {&hf_pie_ntop_untunneled_ipv4_dst_addr,
         {"Untunneled_ipv4_dst_addr", "cflow.pie.ntop.untunneled_ipv4_dst_addr",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 117 */
        {&hf_pie_ntop_untunneled_l4_dst_port,
         {"Untunneled_l4_dst_port", "cflow.pie.ntop.untunneled_l4_dst_port",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },

        /* ntop, 35632 / 110 */
        {&hf_pie_ntop_dump_path,
         {"Dump_path", "cflow.pie.ntop.dump_path",
          FT_STRINGZ, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 130 */
        {&hf_pie_ntop_sip_call_id,
         {"Sip_call_id", "cflow.pie.ntop.sip_call_id",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 131 */
        {&hf_pie_ntop_sip_calling_party,
         {"Sip_calling_party", "cflow.pie.ntop.sip_calling_party",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 132 */
        {&hf_pie_ntop_sip_called_party,
         {"Sip_called_party", "cflow.pie.ntop.sip_called_party",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 133 */
        {&hf_pie_ntop_sip_rtp_codecs,
         {"Sip_rtp_codecs", "cflow.pie.ntop.sip_rtp_codecs",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 134 */
        {&hf_pie_ntop_sip_invite_time,
         {"Sip_invite_time", "cflow.pie.ntop.sip_invite_time",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 135 */
        {&hf_pie_ntop_sip_trying_time,
         {"Sip_trying_time", "cflow.pie.ntop.sip_trying_time",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 136 */
        {&hf_pie_ntop_sip_ringing_time,
         {"Sip_ringing_time", "cflow.pie.ntop.sip_ringing_time",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 137 */
        {&hf_pie_ntop_sip_ok_time,
         {"Sip_ok_time", "cflow.pie.ntop.sip_ok_time",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 138 */
        {&hf_pie_ntop_sip_bye_time,
         {"Sip_bye_time", "cflow.pie.ntop.sip_bye_time",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 139 */
        {&hf_pie_ntop_sip_rtp_src_ip,
         {"Sip_rtp_src_ip", "cflow.pie.ntop.sip_rtp_src_ip",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 140 */
        {&hf_pie_ntop_sip_rtp_src_port,
         {"Sip_rtp_src_port", "cflow.pie.ntop.sip_rtp_src_port",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 141 */
        {&hf_pie_ntop_sip_rtp_dst_ip,
         {"Sip_rtp_dst_ip", "cflow.pie.ntop.sip_rtp_dst_ip",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 142 */
        {&hf_pie_ntop_sip_rtp_dst_port,
         {"Sip_rtp_dst_port", "cflow.pie.ntop.sip_rtp_dst_port",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 150 */
        {&hf_pie_ntop_rtp_first_ssrc,
         {"Rtp_first_ssrc", "cflow.pie.ntop.rtp_first_ssrc",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 151 */
        {&hf_pie_ntop_rtp_first_ts,
         {"Rtp_first_ts", "cflow.pie.ntop.rtp_first_ts",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 152 */
        {&hf_pie_ntop_rtp_last_ssrc,
         {"Rtp_last_ssrc", "cflow.pie.ntop.rtp_last_ssrc",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 153 */
        {&hf_pie_ntop_rtp_last_ts,
         {"Rtp_last_ts", "cflow.pie.ntop.rtp_last_ts",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 154 */
        {&hf_pie_ntop_rtp_in_jitter,
         {"Rtp_in_jitter", "cflow.pie.ntop.rtp_in_jitter",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 155 */
        {&hf_pie_ntop_rtp_out_jitter,
         {"Rtp_out_jitter", "cflow.pie.ntop.rtp_out_jitter",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 156 */
        {&hf_pie_ntop_rtp_in_pkt_lost,
         {"Rtp_in_pkt_lost", "cflow.pie.ntop.rtp_in_pkt_lost",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 157 */
        {&hf_pie_ntop_rtp_out_pkt_lost,
         {"Rtp_out_pkt_lost", "cflow.pie.ntop.rtp_out_pkt_lost",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 158 */
        {&hf_pie_ntop_rtp_out_payload_type,
         {"Rtp_out_payload_type", "cflow.pie.ntop.rtp_out_payload_type",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 159 */
        {&hf_pie_ntop_rtp_in_max_delta,
         {"Rtp_in_max_delta", "cflow.pie.ntop.rtp_in_max_delta",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 160 */
        {&hf_pie_ntop_rtp_out_max_delta,
         {"Rtp_out_max_delta", "cflow.pie.ntop.rtp_out_max_delta",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 168 */
        {&hf_pie_ntop_proc_id,
         {"Proc_id", "cflow.pie.ntop.proc_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 169 */
        {&hf_pie_ntop_proc_name,
         {"Proc_name", "cflow.pie.ntop.proc_name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 180 */
        {&hf_pie_ntop_http_url,
         {"Http_url", "cflow.pie.ntop.http_url",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 181 */
        {&hf_pie_ntop_http_ret_code,
         {"Http_ret_code", "cflow.pie.ntop.http_ret_code",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 185 */
        {&hf_pie_ntop_smtp_mail_from,
         {"Smtp_mail_from", "cflow.pie.ntop.smtp_mail_from",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 186 */
        {&hf_pie_ntop_smtp_rcpt_to,
         {"Smtp_rcpt_to", "cflow.pie.ntop.smtp_rcpt_to",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 195 */
        {&hf_pie_ntop_mysql_server_version,
         {"Mysql_server_version", "cflow.pie.ntop.mysql_server_version",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 196 */
        {&hf_pie_ntop_mysql_username,
         {"Mysql_username", "cflow.pie.ntop.mysql_username",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 197 */
        {&hf_pie_ntop_mysql_db,
         {"Mysql_db", "cflow.pie.ntop.mysql_db",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 198 */
        {&hf_pie_ntop_mysql_query,
         {"Mysql_query", "cflow.pie.ntop.mysql_query",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* ntop, 35632 / 199 */
        {&hf_pie_ntop_mysql_response,
         {"Mysql_response", "cflow.pie.ntop.mysql_response",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },

        /* Plixer root (a hidden item to allow filtering) */
        {&hf_pie_plixer,
         {"Plixer", "cflow.pie.plixer",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 100 */
        {&hf_pie_plixer_client_ip_v4,
         {"client_ip_v4", "cflow.pie.plixer.client.ip_v4",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_pie_plixer_client_hostname,
         /* plixer, 13745 / 101 */
         {"client_hostname", "cflow.pie.plixer.client_hostname",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 102 */
        {&hf_pie_plixer_partner_name,
         {"Partner_name", "cflow.pie.plixer.partner_name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 103 */
        {&hf_pie_plixer_server_hostname,
         {"Server_hostname", "cflow.pie.plixer.server_hostname",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 104 */
        {&hf_pie_plixer_server_ip_v4,
         {"Server_ip_v4", "cflow.pie.plixer.server_ip_v4",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 105 */
        {&hf_pie_plixer_recipient_address,
         {"Recipient_address", "cflow.pie.plixer.recipient_address",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 106 */
        {&hf_pie_plixer_event_id,
         {"Event_id", "cflow.pie.plixer.event_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 107 */
        {&hf_pie_plixer_msgid,
         {"Msgid", "cflow.pie.plixer.msgid",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 108 */
        {&hf_pie_plixer_priority,
         {"Priority", "cflow.pie.plixer_priority",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 109 */
        {&hf_pie_plixer_recipient_report_status,
         {"Recipient_report_status", "cflow.pie.plixer.recipient_report_status",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 110 */
        {&hf_pie_plixer_number_recipients,
         {"Number_recipients", "cflow.pie.plixer.number_recipients",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 111 */
        {&hf_pie_plixer_origination_time,
         {"Origination_time", "cflow.pie.plixer.origination_time",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 112 */
        {&hf_pie_plixer_encryption,
         {"Cncryption", "cflow.pie.plixer.encryption",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 113 */
        {&hf_pie_plixer_service_version,
         {"Service_version", "cflow.pie.plixer.service_version",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 114 */
        {&hf_pie_plixer_linked_msgid,
         {"Linked_msgid", "cflow.pie.plixer.linked_msgid",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 115 */
        {&hf_pie_plixer_message_subject,
         {"Message_subject", "cflow.pie.plixer.message_subject",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 116 */
        {&hf_pie_plixer_sender_address,
         {"Sender_address", "cflow.pie.plixer.sender_address",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },
        /* plixer, 13745 / 117 */
        {&hf_pie_plixer_date_time,
         {"Date_time", "cflow.pie.plixer.date_time",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL}
        },

        /* Ixia root (a hidden item to allow filtering) */
        {&hf_pie_ixia,
         {"Ixia", "cflow.pie.ixia",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* ixia, 3054 / 110 */
        {&hf_pie_ixia_l7_application_id,
         {"L7 Application ID", "cflow.pie.ixia.l7-application-id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Application Identication number. Dynamically detected, so unique to each exporter", HFILL}
        },
        /* ixia, 3054 / 111 */
        {&hf_pie_ixia_l7_application_name,
         {"L7 Application Name", "cflow.pie.ixia.l7-application-name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          NULL, HFILL}
        },

        /* ixia, 3054 / 120 */
        {&hf_pie_ixia_source_ip_country_code,
         {"Source IP Country Code", "cflow.pie.ixia.source-ip-country-code",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "2 letter country code for the source IP address", HFILL}
        },
        /* ixia, 3054 / 121 */
        {&hf_pie_ixia_source_ip_country_name,
         {"Source IP Country Name", "cflow.pie.ixia.source-ip-country-name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "Country name for the source IP address", HFILL}
        },
        /* ixia, 3054 / 122 */
        {&hf_pie_ixia_source_ip_region_code,
         {"Source IP Region Code", "cflow.pie.ixia.source-ip-region-code",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "2 letter region code for the source IP address", HFILL}
        },
        /* ixia, 3054 / 123 */
        {&hf_pie_ixia_source_ip_region_name,
         {"Source IP Region Name", "cflow.pie.ixia.source-ip-region-name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "Region name for the source IP address", HFILL}
        },
        /* ixia, 3054 / 125 */
        {&hf_pie_ixia_source_ip_city_name,
         {"Source IP City Name", "cflow.pie.ixia.source-ip-city-name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "City name for the source IP address", HFILL}
        },
        /* ixia, 3054 / 126 */
        {&hf_pie_ixia_source_ip_latitude,
         {"Source IP Latitude", "cflow.pie.ixia.source-ip-latitude",
          FT_FLOAT, BASE_NONE, NULL, 0x0,
          "Latitude for the source IP address", HFILL}
        },
        /* ixia, 3054 / 127 */
        {&hf_pie_ixia_source_ip_longitude,
         {"Source IP Longitude", "cflow.pie.ixia.source-ip-longitude",
          FT_FLOAT, BASE_NONE, NULL, 0x0,
          "Longitude for the source IP address", HFILL}
        },

        /* ixia, 3054 / 140 */
        {&hf_pie_ixia_destination_ip_country_code,
         {"Destination IP Country Code", "cflow.pie.ixia.destination-ip-country-code",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "2 letter region code for the destination IP address", HFILL}
        },
        /* ixia, 3054 / 141 */
        {&hf_pie_ixia_destination_ip_country_name,
         {"Destination IP Country Name", "cflow.pie.ixia.destination-ip-country-name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "Country name for the destination IP address", HFILL}
        },
        /* ixia, 3054 / 142 */
        {&hf_pie_ixia_destination_ip_region_code,
         {"Destination IP Region Code", "cflow.pie.ixia.destination-ip-region-code",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "2 letter region code for the destination IP address", HFILL}
        },
        /* ixia, 3054 / 143 */
        {&hf_pie_ixia_destination_ip_region_name,
         {"Destination IP Region Name", "cflow.pie.ixia.destination-ip-region-name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "Region name for the destination IP address", HFILL}
        },
        /* ixia, 3054 / 145 */
        {&hf_pie_ixia_destination_ip_city_name,
         {"Destination IP City Name", "cflow.pie.ixia.destination-ip-city-name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "City name for the destination IP address", HFILL}
        },
        /* ixia, 3054 / 146 */
        {&hf_pie_ixia_destination_ip_latitude,
         {"Destination IP Latitude", "cflow.pie.ixia.destination-ip-latitude",
          FT_FLOAT, BASE_NONE, NULL, 0x0,
          "Latitude for the destination IP address", HFILL}
        },
        /* ixia, 3054 / 147 */
        {&hf_pie_ixia_destination_ip_longitude,
         {"Destination IP Longitude", "cflow.pie.ixia.destination-ip-longitude",
          FT_FLOAT, BASE_NONE, NULL, 0x0,
          "Longitude for the destination IP address", HFILL}
        },

        /* ixia, 3054 / 160 */
        {&hf_pie_ixia_os_device_id,
         {"OS Device ID", "cflow.pie.ixia.os-device-id",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Unique ID for each OS", HFILL}
        },
        /* ixia, 3054 / 161 */
        {&hf_pie_ixia_os_device_name,
         {"OS Device Name", "cflow.pie.ixia.os-device-name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "String containing OS name", HFILL}
        },
        /* ixia, 3054 / 162 */
        {&hf_pie_ixia_browser_id,
         {"Browser ID", "cflow.pie.ixia.browser-id",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Unique ID for each browser type", HFILL}
        },
        /* ixia, 3054 / 163 */
        {&hf_pie_ixia_browser_name,
         {"Browser Name", "cflow.pie.ixia.browser-name",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "Unique Name for each browser type", HFILL}
        },

        /* ixia, 3054 / 176 */
        {&hf_pie_ixia_reverse_octet_delta_count,
         {"Reverse octet octet count", "cflow.pie.ixia.reverse-octet-delta-count",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "In bi-directional flows, byte count for the server back to client", HFILL}
        },
        /* ixia, 3054 / 177 */
        {&hf_pie_ixia_reverse_packet_delta_count,
         {"Reverse octet packet count", "cflow.pie.ixia.reverse-packet-delta-count",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "In bi-directional flows, packet count for the server back to client", HFILL}
        },

        /* ixia, 3054 / 178 */
        {&hf_pie_ixia_conn_encryption_type,
         {"Connection Encryption Type", "cflow.pie.ixia.conn-encryption-type",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "Whether the connection is encrypted", HFILL}
        },

        /* ixia, 3054 / 179 */
        {&hf_pie_ixia_encryption_cipher,
         {"Encryption Cipher", "cflow.pie.ixia.encryption-cipher",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "Cipher used in the encryption", HFILL}
        },

        /* ixia, 3054 / 180 */
        {&hf_pie_ixia_encryption_keylen,
         {"Encryption Key Length", "cflow.pie.ixia.encryption-keylen",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Length of the encryption key in bytes", HFILL}
        },

        /* ixia, 3054 / 181 */
        {&hf_pie_ixia_imsi,
         {"IMSI", "cflow.pie.ixia.imsi",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "IMSI associated with a GTP tunneled flow", HFILL}
        },

        /* ixia, 3054 / 182 */
        {&hf_pie_ixia_user_agent,
         {"HTTP User Agent", "cflow.pie.ixia.http-user-agent",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "User-Agent string in HTTP requests", HFILL}
        },

        /* ixia, 3054 / 183 */
        {&hf_pie_ixia_host_name,
         {"Host Name", "cflow.pie.ixia.hostname",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "HTTP Hostname", HFILL}
        },

        /* ixia, 3054 / 184 */
        {&hf_pie_ixia_uri,
         {"HTTP URI", "cflow.pie.ixia.http-uri",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "URI in HTTP requests", HFILL}
        },

        /* ixia, 3054 / 185 */
        {&hf_pie_ixia_dns_txt,
         {"DNS TXT", "cflow.pie.ixia.dns-txt",
          FT_STRING, STR_ASCII, NULL, 0x0,
          "TXT record in DNS query", HFILL}
        },

        /* Netscaler root (a hidden item to allow filtering) */
        {&hf_pie_netscaler,
         {"Netscaler", "cflow.pie.netscaler",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 128 */
        {&hf_pie_netscaler_roundtriptime,
         {"Round Trip Time", "cflow.pie.netscaler.round-trip-time",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "TCP RTT of the flow in milliseconds", HFILL}
        },
        /* netscaler, 5951 / 129 */
        {&hf_pie_netscaler_transactionid,
         {"Transaction ID", "cflow.pie.netscaler.transaction-id",
          FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
          "Four flows of a transaction between client and server (client-to-NS, NS-to-Server, Server-to-NS, NS-to-Client)", HFILL}
        },
        /* netscaler, 5951 / 130 */
        {&hf_pie_netscaler_httprequrl,
         {"HTTP Request Url", "cflow.pie.netscaler.http-req-url",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 131 */
        {&hf_pie_netscaler_httpreqcookie,
         {"HTTP Request Cookie", "cflow.pie.netscaler.http-req-cookie",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 132 */
        {&hf_pie_netscaler_flowflags,
         {"Flow Flags", "cflow.pie.netscaler.flow-flags",
          FT_UINT64, BASE_HEX, NULL, 0x0,
          "Application Layer Flags", HFILL}
        },
        /* netscaler, 5951 / 133 */
        {&hf_pie_netscaler_connectionid,
         {"Connection ID", "cflow.pie.netscaler.connection-id",
          FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
          "Two flows of a TCP connection", HFILL}
        },
        /* netscaler, 5951 / 134 */
        {&hf_pie_netscaler_syslogpriority,
         {"Syslog Priority", "cflow.pie.netscaler.syslog-priority",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Priority of the syslog message", HFILL}
        },
        /* netscaler, 5951 / 135 */
        {&hf_pie_netscaler_syslogmessage,
         {"Syslog Message", "cflow.pie.netscaler.syslog-message",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 136 */
        {&hf_pie_netscaler_syslogtimestamp,
         {"Syslog Timestamp", "cflow.pie.netscaler.syslog-timestamp",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Timestamp of syslog message (ms)", HFILL}
        },
        /* netscaler, 5951 / 140 */
        {&hf_pie_netscaler_httpreqreferer,
         {"HTTP Request Referer", "cflow.pie.netscaler.http-req-referer",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 141 */
        {&hf_pie_netscaler_httpreqmethod,
         {"HTTP Request Method", "cflow.pie.netscaler.http-req-method",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 142 */
        {&hf_pie_netscaler_httpreqhost,
         {"HTTP Request Host", "cflow.pie.netscaler.http-req-host",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 143 */
        {&hf_pie_netscaler_httprequseragent,
         {"HTTP Request UserAgent", "cflow.pie.netscaler.http-req-useragent",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 144 */
        {&hf_pie_netscaler_httprspstatus,
         {"HTTP Response Status", "cflow.pie.netscaler.http-rsp-status",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 145 */
        {&hf_pie_netscaler_httprsplen,
         {"HTTP Response Length", "cflow.pie.netscaler.http-rsp-len",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 146 */
        {&hf_pie_netscaler_serverttfb,
         {"Server TTFB", "cflow.pie.netscaler.server-ttfb",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Time till First Byte (microseconds)", HFILL}
        },
        /* netscaler, 5951 / 147 */
        {&hf_pie_netscaler_serverttlb,
         {"Server TTLB", "cflow.pie.netscaler.server-ttlb",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Time till Last Byte (microseconds)", HFILL}
        },
        /* netscaler, 5951 / 150 */
        {&hf_pie_netscaler_appnameincarnationnumber,
         {"AppName Incarnation Number", "cflow.pie.netscaler.appname-incarnation-number",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 151 */
        {&hf_pie_netscaler_appnameappid,
         {"AppName App ID", "cflow.pie.netscaler.appname-app-id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 152 */
        {&hf_pie_netscaler_appname,
         {"AppName", "cflow.pie.netscaler.appname",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 153 */
        {&hf_pie_netscaler_httpreqrcvfb,
         {"HTTP Request Received FB", "cflow.pie.netscaler.http-req-rcv-fb",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Timestamp of first byte received from client (microseconds)", HFILL}
        },
        /* netscaler, 5951 / 156 */
        {&hf_pie_netscaler_httpreqforwfb,
         {"HTTP Request Forwarded FB", "cflow.pie.netscaler.http-req-forw-fb",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Timestamp of first byte forwarded to server (microseconds)", HFILL}
        },
        /* netscaler, 5951 / 157 */
        {&hf_pie_netscaler_httpresrcvfb,
         {"HTTP Response Received FB", "cflow.pie.netscaler.http-res-rcv-fb",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Timestamp of first byte received from server (microseconds)", HFILL}
        },
        /* netscaler, 5951 / 158 */
        {&hf_pie_netscaler_httpresforwfb,
         {"HTTP Response Forwarded FB", "cflow.pie.netscaler.http-res-forw-fb",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Timestamp of first byte forwarded to client (microseconds)", HFILL}
        },
        /* netscaler, 5951 / 159 */
        {&hf_pie_netscaler_httpreqrcvlb,
         {"HTTP Request Received LB", "cflow.pie.netscaler.http-req-rcv-lb",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Timestamp of last byte received from client (microseconds)", HFILL}
        },
        /* netscaler, 5951 / 160 */
        {&hf_pie_netscaler_httpreqforwlb,
         {"HTTP Request Forwarded LB", "cflow.pie.netscaler.http-req-forw-lb",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Timestamp of last byte forwarded to server (microseconds)", HFILL}
        },
        /* netscaler, 5951 / 161 */
        {&hf_pie_netscaler_mainpageid,
         {"Main Page Id", "cflow.pie.netscaler.mainpage-id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 162 */
        {&hf_pie_netscaler_mainpagecoreid,
         {"Main Page Core Id", "cflow.pie.netscaler.mainpage-core-id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 163 */
        {&hf_pie_netscaler_httpclientinteractionstarttime,
         {"HTTP Client Interaction Start Time", "cflow.pie.netscaler.http-client-interaction-starttime",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "Timestamp when the page starts loading", HFILL}
        },
        /* netscaler, 5951 / 164 */
        {&hf_pie_netscaler_httpclientrenderendtime,
         {"HTTP Client Render End Time", "cflow.pie.netscaler.http-client-render-endtime",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "Timestamp when the page completely renders", HFILL}
        },
        /* netscaler, 5951 / 165 */
        {&hf_pie_netscaler_httpclientrenderstarttime,
         {"HTTP Client Render Start Time", "cflow.pie.netscaler.http-client-render-starttime",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "Timestamp when page rendering begins", HFILL}
        },
        /* netscaler, 5951 / 167 */
        {&hf_pie_netscaler_apptemplatename,
         {"App Template Name", "cflow.pie.netscaler.app-template-name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 168 */
        {&hf_pie_netscaler_httpclientinteractionendtime,
         {"HTTP Client Interaction End Time", "cflow.pie.netscaler.http-client-interaction-endtime",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 169 */
        {&hf_pie_netscaler_httpresrcvlb,
         {"HTTP Response Received LB", "cflow.pie.netscaler.http-res-rcv-lb",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Timestamp of last byte received from server (microseconds)", HFILL}
        },
        /* netscaler, 5951 / 170 */
        {&hf_pie_netscaler_httpresforwlb,
         {"HTTP Response Forwarded LB", "cflow.pie.netscaler.http-res-forw-lb",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Timestamp of last byte of forwarded to client (microseconds)", HFILL}
        },
        /* netscaler, 5951 / 171 */
        {&hf_pie_netscaler_appunitnameappid,
         {"AppUnit Name App Id", "cflow.pie.netscaler.app-unit-name-appid",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 172 */
        {&hf_pie_netscaler_dbloginflags,
         {"DB Login Flags", "cflow.pie.netscaler.db-login-flags",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 173 */
        {&hf_pie_netscaler_dbreqtype,
         {"DB Request Type", "cflow.pie.netscaler.db-req-type",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Type of database request", HFILL}
        },
        /* netscaler, 5951 / 174 */
        {&hf_pie_netscaler_dbprotocolname,
         {"DB Protocol Name", "cflow.pie.netscaler.db-protocol-name",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Database protocol", HFILL}
        },
        /* netscaler, 5951 / 175 */
        {&hf_pie_netscaler_dbusername,
         {"DB User Name", "cflow.pie.netscaler.db-user-name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "Database username", HFILL}
        },
        /* netscaler, 5951 / 176 */
        {&hf_pie_netscaler_dbdatabasename,
         {"DB Database Name", "cflow.pie.netscaler.db-database-name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 177 */
        {&hf_pie_netscaler_dbclthostname,
         {"DB Client Host Name", "cflow.pie.netscaler.db-clt-hostname",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 178 */
        {&hf_pie_netscaler_dbreqstring,
         {"DB Request String", "cflow.pie.netscaler.db-req-string",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 179 */
        {&hf_pie_netscaler_dbrespstatusstring,
         {"DB Response Status String", "cflow.pie.netscaler.db-resp-status-string",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "Database response status", HFILL}
        },
        /* netscaler, 5951 / 180 */
        {&hf_pie_netscaler_dbrespstatus,
         {"DB Response Status", "cflow.pie.netscaler.db-resp-status",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 181 */
        {&hf_pie_netscaler_dbresplength,
         {"DB Response Length", "cflow.pie.netscaler.db-resp-length",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 182 */
        {&hf_pie_netscaler_clientrtt,
         {"Client RTT", "cflow.pie.netscaler.client-rtt",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "RTT of the client", HFILL}
        },
        /* netscaler, 5951 / 183 */
        {&hf_pie_netscaler_httpcontenttype,
         {"HTTP Content-Type", "cflow.pie.netscaler.http-contenttype",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 185 */
        {&hf_pie_netscaler_httpreqauthorization,
         {"HTTP Request Authorization", "cflow.pie.netscaler.http-req-authorization",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 186 */
        {&hf_pie_netscaler_httpreqvia,
         {"HTTP Request Via", "cflow.pie.netscaler.http-req-via",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 187 */
        {&hf_pie_netscaler_httpreslocation,
         {"HTTP Response Location", "cflow.pie.netscaler.http-res-location",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 188 */
        {&hf_pie_netscaler_httpressetcookie,
         {"HTTP Response Set-Cookie", "cflow.pie.netscaler.http-res-setcookie",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 189 */
        {&hf_pie_netscaler_httpressetcookie2,
         {"HTTP Response Set-Cookie2", "cflow.pie.netscaler.http-res-setcookie2",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 190 */
        {&hf_pie_netscaler_httpreqxforwardedfor,
         {"HTTP Request X-Forwarded-For", "cflow.pie.netscaler.http-reqx-forwardedfor",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 192 */
        {&hf_pie_netscaler_connectionchainid,
         {"Connection Chain ID", "cflow.pie.netscaler.connection-chain-id",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 193 */
        {&hf_pie_netscaler_connectionchainhopcount,
         {"Connection Chain Hop Count", "cflow.pie.netscaler.connection-chain-hop-count",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 200 */
        {&hf_pie_netscaler_icasessionguid,
         {"ICA Session GUID", "cflow.pie.netscaler.ica-session-guid",
          FT_GUID, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 201 */
        {&hf_pie_netscaler_icaclientversion,
         {"ICA Client Version", "cflow.pie.netscaler.ica-client-version",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "Version of the ICA client", HFILL}
        },
        /* netscaler, 5951 / 202 */
        {&hf_pie_netscaler_icaclienttype,
         {"ICA Client Type", "cflow.pie.netscaler.ica-client-type",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 203 */
        {&hf_pie_netscaler_icaclientip,
         {"ICA Client IP", "cflow.pie.netscaler.ica-client-ip",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 204 */
        {&hf_pie_netscaler_icaclienthostname,
         {"ICA Client Host Name", "cflow.pie.netscaler.ica-client-hostname",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 205 */
        {&hf_pie_netscaler_aaausername,
         {"AAA Username", "cflow.pie.netscaler.aaa-username",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 207 */
        {&hf_pie_netscaler_icadomainname,
         {"ICA Domain Name", "cflow.pie.netscaler.ica-domain-name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 208 */
        {&hf_pie_netscaler_icaclientlauncher,
         {"ICA Client Launcher", "cflow.pie.netscaler.ica-client-launcher",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 209 */
        {&hf_pie_netscaler_icasessionsetuptime,
         {"ICA Session Setup Time", "cflow.pie.netscaler.ica-session-setuptime",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "ICA Session Setup Time (s)", HFILL}
        },
        /* netscaler, 5951 / 210 */
        {&hf_pie_netscaler_icaservername,
         {"ICA Server Name", "cflow.pie.netscaler.ica-servername",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 214 */
        {&hf_pie_netscaler_icasessionreconnects,
         {"ICA Session Reconnects", "cflow.pie.netscaler.ica-session-reconnects",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 215 */
        {&hf_pie_netscaler_icartt,
         {"ICA RTT", "cflow.pie.netscaler.ica-rtt",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 216 */
        {&hf_pie_netscaler_icaclientsiderxbytes,
         {"ICA Clientside RX Bytes", "cflow.pie.netscaler.ica-client-side-rxbytes",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 217 */
        {&hf_pie_netscaler_icaclientsidetxbytes,
         {"ICA Clientside TX Bytes", "cflow.pie.netscaler.ica-client-side-txbytes",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 219 */
        {&hf_pie_netscaler_icaclientsidepacketsretransmit,
         {"ICA Clientside Packets Retransmit", "cflow.pie.netscaler.ica-clientside-packets-retransmit",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 220 */
        {&hf_pie_netscaler_icaserversidepacketsretransmit,
         {"ICA Serverside Packets Retransmit", "cflow.pie.netscaler.ica-serverside-packets-retransmit",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 221 */
        {&hf_pie_netscaler_icaclientsidertt,
         {"ICA Clientside RTT", "cflow.pie.netscaler.ica-clientside-rtt",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 222 */
        {&hf_pie_netscaler_icaserversidertt,
         {"ICA Serverside RTT", "cflow.pie.netscaler.ica-serverside-rtt",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 223 */
        {&hf_pie_netscaler_icasessionupdatebeginsec,
         {"ICA Session Update Begin Sec", "cflow.pie.netscaler.ica-session-update-begin-sec",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 224 */
        {&hf_pie_netscaler_icasessionupdateendsec,
         {"ICA Session Update End Sec", "cflow.pie.netscaler.ica-session-update-end-sec",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 225 */
        {&hf_pie_netscaler_icachannelid1,
         {"ICA Channel Id1", "cflow.pie.netscaler.ica-channel-id1",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 226 */
        {&hf_pie_netscaler_icachannelid1bytes,
         {"ICA Channel Id1 Bytes", "cflow.pie.netscaler.ica-channel-id1-bytes",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 227 */
        {&hf_pie_netscaler_icachannelid2,
         {"ICA Channel Id2", "cflow.pie.netscaler.ica-channel-id2",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 228 */
        {&hf_pie_netscaler_icachannelid2bytes,
         {"ICA Channel Id2 Bytes", "cflow.pie.netscaler.ica-channel-id2-bytes",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 229 */
        {&hf_pie_netscaler_icachannelid3,
         {"ICA Channel Id3", "cflow.pie.netscaler.ica-channel-id3",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 230 */
        {&hf_pie_netscaler_icachannelid3bytes,
         {"ICA Channel Id3 Bytes", "cflow.pie.netscaler.ica-channel-id3-bytes",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 231 */
        {&hf_pie_netscaler_icachannelid4,
         {"ICA Channel Id4", "cflow.pie.netscaler.ica-channel-id4",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 232 */
        {&hf_pie_netscaler_icachannelid4bytes,
         {"ICA Channel Id4 Bytes", "cflow.pie.netscaler.ica-channel-id4-bytes",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 233 */
        {&hf_pie_netscaler_icachannelid5,
         {"ICA Channel Id5", "cflow.pie.netscaler.ica-channel-id5",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 234 */
        {&hf_pie_netscaler_icachannelid5bytes,
         {"ICA Channel Id5 Bytes", "cflow.pie.netscaler.ica-channel-id5-bytes",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 235 */
        {&hf_pie_netscaler_icaconnectionpriority,
         {"ICA Connection Priority", "cflow.pie.netscaler.ica-connection-priority",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 236 */
        {&hf_pie_netscaler_applicationstartupduration,
         {"Application Startup Duration", "cflow.pie.netscaler.application-startup-duration",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 237 */
        {&hf_pie_netscaler_icalaunchmechanism,
         {"ICA Launch Mechanism", "cflow.pie.netscaler.ica-launch-mechanism",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 238 */
        {&hf_pie_netscaler_icaapplicationname,
         {"ICA Application Name", "cflow.pie.netscaler.ica-application-name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 239 */
        {&hf_pie_netscaler_applicationstartuptime,
         {"Application Startup Time", "cflow.pie.netscaler.application-startup-time",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 240 */
        {&hf_pie_netscaler_icaapplicationterminationtype,
         {"ICA Application Termination Type", "cflow.pie.netscaler.ica-application-termination-type",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 241 */
        {&hf_pie_netscaler_icaapplicationterminationtime,
         {"ICA Application Termination Time", "cflow.pie.netscaler.ica-application-termination-time",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "ICA Application Termination Time (s)", HFILL}
        },
        /* netscaler, 5951 / 242 */
        {&hf_pie_netscaler_icasessionendtime,
         {"ICA Session End Time", "cflow.pie.netscaler.ica-session-end-time",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "ICA Session End Time (s)", HFILL}
        },
        /* netscaler, 5951 / 243 */
        {&hf_pie_netscaler_icaclientsidejitter,
         {"ICA Clientside Jitter", "cflow.pie.netscaler.ica-clientside-jitter",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 244 */
        {&hf_pie_netscaler_icaserversidejitter,
         {"ICA Serverside Jitter", "cflow.pie.netscaler.ica-serverside-jitter",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 245 */
        {&hf_pie_netscaler_icaappprocessid,
         {"ICA App Process ID", "cflow.pie.netscaler.ica-app-processid",
          FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 246 */
        {&hf_pie_netscaler_icaappmodulepath,
         {"ICA AppModule Path", "cflow.pie.netscaler.ica-appmodule-path",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 247 */
        {&hf_pie_netscaler_icadeviceserialno,
         {"ICA Device Serial No", "cflow.pie.netscaler.ica-device-serial-no",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 248 */
        {&hf_pie_netscaler_msiclientcookie,
         {"Msi Client Cookie", "cflow.pie.netscaler.msi-client-cookie",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 249 */
        {&hf_pie_netscaler_icaflags,
         {"ICA Flags", "cflow.pie.netscaler.ica-flags",
          FT_UINT64, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 250 */
        {&hf_pie_netscaler_icausername,
         {"ICA Username", "cflow.pie.netscaler.icau-sername",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 251 */
        {&hf_pie_netscaler_licensetype,
         {"License Type", "cflow.pie.netscaler.license-type",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 252 */
        {&hf_pie_netscaler_maxlicensecount,
         {"Max License Count", "cflow.pie.netscaler.max-license-count",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 253 */
        {&hf_pie_netscaler_currentlicenseconsumed,
         {"Current License Consumed", "cflow.pie.netscaler.current-license-consumed",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 254 */
        {&hf_pie_netscaler_icanetworkupdatestarttime,
         {"ICA Network Update Start Time", "cflow.pie.netscaler.ica-network-update-start-time",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 255 */
        {&hf_pie_netscaler_icanetworkupdateendtime,
         {"ICA Network Update End Time", "cflow.pie.netscaler.ica-network-update-end-time",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 256 */
        {&hf_pie_netscaler_icaclientsidesrtt,
         {"ICA Clientside SRTT", "cflow.pie.netscaler.ica-clientside-srtt",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "ICA Clientside smooothed RTT", HFILL}
        },
        /* netscaler, 5951 / 257 */
        {&hf_pie_netscaler_icaserversidesrtt,
         {"ICA Serverside SRTT", "cflow.pie.netscaler.ica-serverside-srtt",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "ICA Serverside smoothed RTT", HFILL}
        },
        /* netscaler, 5951 / 258 */
        {&hf_pie_netscaler_icaclientsidedelay,
         {"ICA Clientside Delay", "cflow.pie.netscaler.ica-clientsi-dedelay",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 259 */
        {&hf_pie_netscaler_icaserversidedelay,
         {"ICA Serverside Delay", "cflow.pie.netscaler.ica-serversi-dedelay",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 260 */
        {&hf_pie_netscaler_icahostdelay,
         {"ICA Host Delay", "cflow.pie.netscaler.ica-host-delay",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 261 */
        {&hf_pie_netscaler_icaclientsidewindowsize,
         {"ICA Clientside WindowSize", "cflow.pie.netscaler.ica-clientside-windowsize",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 262 */
        {&hf_pie_netscaler_icaserversidewindowsize,
         {"ICA Serverside WindowSize", "cflow.pie.netscaler.ica-serverside-windowsize",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 263 */
        {&hf_pie_netscaler_icaclientsidertocount,
         {"ICA Clientside RTO Count", "cflow.pie.netscaler.ica-clientside-rto-count",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "ICA Clientside retrans timeout occured Count", HFILL}
        },
        /* netscaler, 5951 / 264 */
        {&hf_pie_netscaler_icaserversidertocount,
         {"ICA Serverside RTO Count", "cflow.pie.netscaler.ica-serverside-rto-count",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "ICA Serverside retrans timeout occured Count", HFILL}
        },
        /* netscaler, 5951 / 265 */
        {&hf_pie_netscaler_ical7clientlatency,
         {"ICA L7 Client Latency", "cflow.pie.netscaler.ica-l7-client-latency",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 266 */
        {&hf_pie_netscaler_ical7serverlatency,
         {"ICA L7 Server Latency", "cflow.pie.netscaler.ica-l7-server-latency",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 267 */
        {&hf_pie_netscaler_httpdomainname,
         {"HTTP Domain Name", "cflow.pie.netscaler.http-domain-name",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 268 */
        {&hf_pie_netscaler_cacheredirclientconnectioncoreid,
         {"CacheRedir Client Connection Core ID", "cflow.pie.netscaler.cacheredir-client-connection-coreid",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        /* netscaler, 5951 / 269 */
        {&hf_pie_netscaler_cacheredirclientconnectiontransactionid,
         {"CacheRedir Client Connection Transaction ID", "cflow.pie.netscaler.cacheredir-client-connectiontransactionid",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },

        /* Barracuda root (a hidden item to allow filtering) */
        {&hf_pie_barracuda,
         {"Barracuda", "cflow.pie.barracuda",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* Barracuda, 10704 / 1 */
        {&hf_pie_barracuda_timestamp,
         {"Timestamp", "cflow.pie.barracuda.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          "Seconds since epoch", HFILL}
        },
        /* Barracuda, 10704 / 2 */
        {&hf_pie_barracuda_logop,
         {"LogOp", "cflow.pie.barracuda.logop",
          FT_UINT8, BASE_DEC, VALS(v10_barracuda_logop), 0x0,
          NULL, HFILL}
        },
        /* Barracuda, 10704 / 3 */
        {&hf_pie_barracuda_traffictype,
         {"Traffic Type", "cflow.pie.barracuda.traffictype",
          FT_UINT8, BASE_DEC, VALS(v10_barracuda_traffictype), 0x0,
          NULL, HFILL}
        },
        /* Barracuda, 10704 / 4 */
        {&hf_pie_barracuda_fwrule,
         {"FW Rule", "cflow.pie.barracuda.fwrule",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "Name of FW Rule", HFILL}
        },
        /* Barracuda, 10704 / 5 */
        {&hf_pie_barracuda_servicename,
         {"Service Name", "cflow.pie.barracuda.servicename",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          "Name of Service", HFILL}
        },
        /* Barracuda, 10704 / 6 */
        {&hf_pie_barracuda_reason,
         {"Reason", "cflow.pie.barracuda.reason",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* Barracuda, 10704 / 7 */
        {&hf_pie_barracuda_reasontext,
         {"Reason Text", "cflow.pie.barracuda.reasontext",
          FT_STRING, STR_UNICODE, NULL, 0x0,
          NULL, HFILL}
        },
        /* Barracuda, 10704 / 8 */
        {&hf_pie_barracuda_bindipv4address,
         {"Bind IPv4 Address", "cflow.pie.barracuda.bindipv4address",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* Barracuda, 10704 / 9 */
        {&hf_pie_barracuda_bindtransportport,
         {"Bind Transport Port", "cflow.pie.barracuda.bindtransportport",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* Barracuda, 10704 / 10 */
        {&hf_pie_barracuda_connipv4address,
         {"Conn IPv4 Address", "cflow.pie.barracuda.connipv4address",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /* Barracuda, 10704 / 11 */
        {&hf_pie_barracuda_conntransportport,
         {"Conn Transport Port", "cflow.pie.barracuda.conntransportport",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* Barracuda, 10704 / 12 */
        {&hf_pie_barracuda_auditcounter,
         {"Audit Counter", "cflow.pie.barracuda.auditcounter",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Internal Data Counter", HFILL}
        },

        {&hf_string_len_short,
         {"String_len_short", "cflow.string_len_short",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_string_len_long,
         {"String_len_short", "cflow.string_len_long",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_cflow_mpls_label,
         {"MPLS label", "cflow.mpls_label",
          FT_UINT24, BASE_DEC, NULL, 0xFFFFF0,
          NULL, HFILL}
        },
        {&hf_cflow_mpls_exp,
         {"MPLS experimental bits", "cflow.mpls_exp",
          FT_UINT8, BASE_DEC, NULL, 0x0E,
          NULL, HFILL}
        },
        {&hf_cflow_mpls_bos,
         {"MPLS Bottom of Stack", "cflow.mpls_bos",
          FT_BOOLEAN, 8, TFS(&mpls_bos_tfs), 0x01,
          NULL, HFILL}
        },

        { &hf_template_frame,
         { "Template Frame", "cflow.template_frame",
          FT_FRAMENUM, BASE_NONE, 0, 0x0,
          NULL, HFILL}
        },
    };

    static gint    *ett[] = {
        &ett_netflow,
        &ett_unixtime,
        &ett_flow,
        &ett_flowtime,
        &ett_str_len,
        &ett_template,
        &ett_field,
        &ett_dataflowset,
        &ett_fwdstat,
        &ett_mpls_label,
        &ett_tcpflags
    };

    static ei_register_info ei[] = {
        { &ei_cflow_flowset_length,
          { "cflow.flowset_length.invalid", PI_MALFORMED, PI_WARN,
            NULL, EXPFILL }},
        { &ei_cflow_no_flow_information,
          { "cflow.no_flow_information", PI_MALFORMED, PI_WARN,
            "No flow information", EXPFILL }},
        { &ei_cflow_template_ipfix_scope_field_count,
          { "cflow.template_ipfix_scope_field_count.none", PI_MALFORMED, PI_WARN,
            "No scope fields", EXPFILL }},
        { &ei_cflow_template_ipfix_scope_field_count_too_many,
          { "cflow.template_ipfix_scope_field_count.too_many", PI_MALFORMED, PI_WARN,
            NULL, EXPFILL }},
        { &ei_cflow_options,
          { "cflow.options.too_many", PI_UNDECODED, PI_WARN,
            NULL, EXPFILL }},
        { &ei_cflow_scopes,
          { "cflow.scopes.too_many", PI_UNDECODED, PI_WARN,
            NULL, EXPFILL }},
        { &ei_cflow_entries,
          { "cflow.entries.too_many", PI_UNDECODED, PI_WARN,
            NULL, EXPFILL }},
        { &ei_cflow_mpls_label_bad_length,
          { "cflow.mpls_label.bad_length", PI_UNDECODED, PI_WARN,
            NULL, EXPFILL }},
        { &ei_cflow_flowsets_impossible,
          { "cflow.flowsets.impossible", PI_MALFORMED, PI_WARN,
            NULL, EXPFILL }},
        { &ei_cflow_no_template_found,
          { "cflow.no_template_found", PI_MALFORMED, PI_WARN,
            NULL, EXPFILL }},
        { &ei_transport_bytes_out_of_order,
          { "cflow.transport_bytes.out-of-order", PI_MALFORMED, PI_WARN,
            NULL, EXPFILL}},
        { &ei_unexpected_sequence_number,
          { "cflow.unexpected_sequence_number", PI_SEQUENCE, PI_WARN,
            NULL, EXPFILL}},
    };

    module_t *netflow_module;
    expert_module_t* expert_netflow;

    proto_netflow = proto_register_protocol("Cisco NetFlow/IPFIX", "CFLOW", "cflow");

    proto_register_field_array(proto_netflow, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_netflow = expert_register_protocol(proto_netflow);
    expert_register_field_array(expert_netflow, ei, array_length(ei));

    /* Register our configuration options for NetFlow */
    netflow_module = prefs_register_protocol(proto_netflow, proto_reg_handoff_netflow);

    /* Set default Netflow port(s) */
    range_convert_str(&global_netflow_ports, NETFLOW_UDP_PORTS, MAX_UDP_PORT);
    range_convert_str(&global_ipfix_ports,  IPFIX_UDP_PORTS,   MAX_UDP_PORT);

    prefs_register_obsolete_preference(netflow_module, "udp.port");

    prefs_register_range_preference(netflow_module, "netflow.ports",
                                    "NetFlow UDP Port(s)",
                                    "Set the port(s) for NetFlow messages"
                                    " (default: " NETFLOW_UDP_PORTS ")",
                                    &global_netflow_ports, MAX_UDP_PORT);

    prefs_register_range_preference(netflow_module, "ipfix.ports",
                                    "IPFIX UDP/TCP/SCTP Port(s)",
                                    "Set the port(s) for IPFIX messages"
                                    " (default: " IPFIX_UDP_PORTS ")",
                                    &global_ipfix_ports, MAX_UDP_PORT);

    prefs_register_uint_preference(netflow_module, "max_template_fields",
                                   "Maximum number of fields allowed in a template",
                                   "Set the number of fields allowed in a template.  "
                                   "Use 0 (zero) for unlimited.  "
                                   " (default: " G_STRINGIFY(V9_TMPLT_MAX_FIELDS_DEF) ")",
                                   10, &v9_tmplt_max_fields);

    register_init_routine(&netflow_init);
    register_cleanup_routine(&netflow_cleanup);
}


/*
 * protocol/port association
 */
static void
ipfix_delete_callback(guint32 port)
{
    if ( port ) {
        dissector_delete_uint("udp.port",  port, netflow_handle);
        dissector_delete_uint("tcp.port",  port, netflow_handle);
        dissector_delete_uint("sctp.port", port, netflow_handle);
    }
}

static void
ipfix_add_callback(guint32 port)
{
    if ( port ) {
        dissector_add_uint("udp.port",  port, netflow_handle);
        dissector_add_uint("tcp.port",  port, netflow_handle);
        dissector_add_uint("sctp.port", port, netflow_handle);
    }
}

void
proto_reg_handoff_netflow(void)
{
    static gboolean  netflow_prefs_initialized = FALSE;
    static range_t  *netflow_ports;
    static range_t  *ipfix_ports;

    if (!netflow_prefs_initialized) {
        netflow_handle = create_dissector_handle(dissect_netflow, proto_netflow);
        netflow_prefs_initialized = TRUE;
        dissector_add_uint("wtap_encap", WTAP_ENCAP_RAW_IPFIX, netflow_handle);
    } else {
        dissector_delete_uint_range("udp.port", netflow_ports, netflow_handle);
        g_free(netflow_ports);
        range_foreach(ipfix_ports, ipfix_delete_callback);
        g_free(ipfix_ports);
    }

    netflow_ports = range_copy(global_netflow_ports);
    ipfix_ports = range_copy(global_ipfix_ports);

    dissector_add_uint_range("udp.port", netflow_ports, netflow_handle);
    range_foreach(ipfix_ports, ipfix_add_callback);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
