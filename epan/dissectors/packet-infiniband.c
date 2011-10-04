/* packet-infiniband.c
 * Routines for Infiniband/ERF Dissection
 * Copyright 2008 Endace Technology Limited
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Modified 2010 by Mellanox Technologies Ltd.
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/dissectors/packet-frame.h>
#include "packet-infiniband.h"

#define PROTO_TAG_INFINIBAND    "Infiniband"

/* Wireshark ID */
static int proto_infiniband = -1;
static int proto_infiniband_link = -1;

/* Variables to hold expansion values between packets */
/* static gint ett_infiniband = -1;                */
static gint ett_all_headers = -1;
static gint ett_lrh = -1;
static gint ett_grh = -1;
static gint ett_bth = -1;
static gint ett_rwh = -1;
static gint ett_rdeth = -1;
static gint ett_deth = -1;
static gint ett_reth = -1;
static gint ett_atomiceth = -1;
static gint ett_aeth = -1;
static gint ett_atomicacketh = -1;
static gint ett_immdt = -1;
static gint ett_ieth = -1;
static gint ett_payload = -1;
static gint ett_vendor = -1;
static gint ett_subn_lid_routed = -1;
static gint ett_subn_directed_route = -1;
static gint ett_subnadmin = -1;
static gint ett_mad = -1;
static gint ett_cm = -1;
static gint ett_rmpp = -1;
static gint ett_subm_attribute = -1;
static gint ett_suba_attribute = -1;
static gint ett_datadetails = -1;
static gint ett_noticestraps = -1;
/* static gint ett_nodedesc = -1;                  */
/* static gint ett_nodeinfo = -1;                  */
/* static gint ett_switchinfo = -1;                */
/* static gint ett_guidinfo = -1;                  */
/* static gint ett_portinfo = -1;                  */
static gint ett_portinfo_capmask = -1;
static gint ett_pkeytable = -1;
static gint ett_sltovlmapping = -1;
static gint ett_vlarbitrationtable = -1;
static gint ett_linearforwardingtable = -1;
static gint ett_randomforwardingtable = -1;
static gint ett_multicastforwardingtable = -1;
static gint ett_sminfo = -1;
static gint ett_vendordiag = -1;
static gint ett_ledinfo = -1;
static gint ett_linkspeedwidthpairs = -1;
static gint ett_informinfo = -1;
static gint ett_linkrecord = -1;
static gint ett_servicerecord = -1;
static gint ett_pathrecord = -1;
static gint ett_mcmemberrecord = -1;
static gint ett_tracerecord = -1;
static gint ett_multipathrecord = -1;
static gint ett_serviceassocrecord = -1;
static gint ett_perfclass = -1;
static gint ett_eoib = -1;
static gint ett_link = -1;

/* Global ref to highest level tree should we find other protocols encapsulated in IB */
static proto_tree *top_tree = NULL;

/* Dissector Declarations */
static dissector_handle_t ipv6_handle;
static dissector_handle_t data_handle;
static dissector_handle_t eth_handle;
static dissector_table_t ethertype_dissector_table;

/* MAD_Data
* Structure to hold information from the common MAD header.
* This is necessary because the MAD header contains information which significantly changes the dissection algorithm. */
typedef struct {
    guint8 managementClass;
    guint8 classVersion;
    guint8 method;
    guint8 status;
    guint16 classSpecific;
    guint64 transactionID;
    guint16 attributeID;
    guint32 attributeModifier;
    char data[232];
} MAD_Data;

/* Forward-declarations */

static void dissect_roce(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_infiniband(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_infiniband_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean starts_with_grh);
static void dissect_infiniband_link(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gint32 find_next_header_sequence(guint32 OpCode);
static gboolean contains(guint32 value, guint32* arr, int length);
static void dissect_general_info(tvbuff_t *tvb, gint offset, packet_info *pinfo, gboolean starts_with_grh);

/* Parsing Methods for specific IB headers. */

static void parse_VENDOR(proto_tree *, tvbuff_t *, gint *);
static void parse_PAYLOAD(proto_tree *, packet_info *, tvbuff_t *, gint *, gint length);
static void parse_IETH(proto_tree *, tvbuff_t *, gint *);
static void parse_IMMDT(proto_tree *, tvbuff_t *, gint *offset);
static void parse_ATOMICACKETH(proto_tree *, tvbuff_t *, gint *offset);
static void parse_AETH(proto_tree *, tvbuff_t *, gint *offset);
static void parse_ATOMICETH(proto_tree *, tvbuff_t *, gint *offset);
static void parse_RETH(proto_tree *, tvbuff_t *, gint *offset);
static void parse_DETH(proto_tree *, packet_info *, tvbuff_t *, gint *offset);
static void parse_RDETH(proto_tree *, tvbuff_t *, gint *offset);
static void parse_IPvSix(proto_tree *, tvbuff_t *, gint *offset, packet_info *);
static void parse_RWH(proto_tree *, tvbuff_t *, gint *offset, packet_info *);
static gboolean parse_EoIB(proto_tree *, tvbuff_t *, gint offset, packet_info *);

static void parse_SUBN_LID_ROUTED(proto_tree *, packet_info *, tvbuff_t *, gint *offset);
static void parse_SUBN_DIRECTED_ROUTE(proto_tree *, packet_info *, tvbuff_t *, gint *offset);
static void parse_SUBNADMN(proto_tree *, packet_info *, tvbuff_t *, gint *offset);
static void parse_PERF(proto_tree *, tvbuff_t *, packet_info *, gint *offset);
static void parse_BM(proto_tree *, tvbuff_t *, gint *offset);
static void parse_DEV_MGT(proto_tree *, tvbuff_t *, gint *offset);
static void parse_COM_MGT(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, gint *offset);
static void parse_SNMP(proto_tree *, tvbuff_t *, gint *offset);
static void parse_VENDOR_MANAGEMENT(proto_tree *, tvbuff_t *, gint *offset);
static void parse_APPLICATION_MANAGEMENT(proto_tree *, tvbuff_t *, gint *offset);
static void parse_RESERVED_MANAGEMENT(proto_tree *, tvbuff_t *, gint *offset);

static gboolean parse_MAD_Common(proto_tree*, tvbuff_t*, gint *offset, MAD_Data*);
static gboolean parse_RMPP(proto_tree* , tvbuff_t* , gint *offset);
static void label_SUBM_Method(proto_item*, MAD_Data*, packet_info*);
static void label_SUBM_Attribute(proto_item*, MAD_Data*, packet_info*);
static void label_SUBA_Method(proto_item*, MAD_Data*, packet_info*);
static void label_SUBA_Attribute(proto_item*, MAD_Data*, packet_info*);

/* Class Attribute Parsing Routines */
static gboolean parse_SUBM_Attribute(proto_tree*, tvbuff_t*, gint *offset, MAD_Data*);
static gboolean parse_SUBA_Attribute(proto_tree*, tvbuff_t*, gint *offset, MAD_Data*);

/* These methods parse individual attributes
* Naming convention FunctionHandle = "parse_" + [Attribute Name];
* Where [Attribute Name] is the attribute identifier from chapter 14 of the IB Specification
* Subnet Management */
static void parse_NoticesAndTraps(proto_tree*, tvbuff_t*, gint *offset);
static void parse_NodeDescription(proto_tree*, tvbuff_t*, gint *offset);
static void parse_NodeInfo(proto_tree*, tvbuff_t*, gint *offset);
static void parse_SwitchInfo(proto_tree*, tvbuff_t*, gint *offset);
static void parse_GUIDInfo(proto_tree*, tvbuff_t*, gint *offset);
static void parse_PortInfo(proto_tree*, tvbuff_t*, gint *offset);
static void parse_P_KeyTable(proto_tree*, tvbuff_t*, gint *offset);
static void parse_SLtoVLMappingTable(proto_tree*, tvbuff_t*, gint *offset);
static void parse_VLArbitrationTable(proto_tree*, tvbuff_t*, gint *offset);
static void parse_LinearForwardingTable(proto_tree*, tvbuff_t*, gint *offset);
static void parse_RandomForwardingTable(proto_tree*, tvbuff_t*, gint *offset);
static void parse_MulticastForwardingTable(proto_tree*, tvbuff_t*, gint *offset);
static void parse_SMInfo(proto_tree*, tvbuff_t*, gint *offset);
static void parse_VendorDiag(proto_tree*, tvbuff_t*, gint *offset);
static void parse_LedInfo(proto_tree*, tvbuff_t*, gint *offset);
static void parse_LinkSpeedWidthPairsTable(proto_tree*, tvbuff_t*, gint *offset);

/* These methods parse individual attributes for specific MAD management classes.
* Naming convention FunctionHandle = "parse_" + [Management Class] + "_" + [Attribute Name];
* Where [Management Class] is the shorthand name for the management class as defined
* in the MAD Management Classes section below in this file, and [Attribute Name] is the
* attribute identifier from the corresponding chapter of the IB Specification */
static void parse_PERF_PortCounters(proto_tree* parentTree, tvbuff_t* tvb, packet_info *pinfo, gint *offset);
static void parse_PERF_PortCountersExtended(proto_tree* parentTree, tvbuff_t* tvb, packet_info *pinfo, gint *offset);

/* Subnet Administration */
static void parse_InformInfo(proto_tree*, tvbuff_t*, gint *offset);
static void parse_LinkRecord(proto_tree*, tvbuff_t*, gint *offset);
static void parse_ServiceRecord(proto_tree*, tvbuff_t*, gint *offset);
static void parse_PathRecord(proto_tree*, tvbuff_t*, gint *offset);
static void parse_MCMemberRecord(proto_tree*, tvbuff_t*, gint *offset);
static void parse_TraceRecord(proto_tree*, tvbuff_t*, gint *offset);
static void parse_MultiPathRecord(proto_tree*, tvbuff_t*, gint *offset);
static void parse_ServiceAssociationRecord(proto_tree*, tvbuff_t*, gint *offset);

/* Subnet Administration */
static void parse_RID(proto_tree*, tvbuff_t*, gint *offset, MAD_Data*);

/* SM Methods */
static const value_string SUBM_Methods[] = {
    { 0x01, "SubnGet("},
    { 0x02, "SubnSet("},
    { 0x81, "SubnGetResp("},
    { 0x05, "SubnTrap("},
    { 0x07, "SubnTrapResp("},
    { 0, NULL}
};
/* SM Attributes */
static const value_string SUBM_Attributes[] = {
    { 0x0001, "Attribute (ClassPortInfo)"},
    { 0x0002, "Attribute (Notice)"},
    { 0x0003, "Attribute (InformInfo)"},
    { 0x0010, "Attribute (NodeDescription)"},
    { 0x0011, "Attribute (NodeInfo)"},
    { 0x0012, "Attribute (SwitchInfo)"},
    { 0x0014, "Attribute (GUIDInfo)"},
    { 0x0015, "Attribute (PortInfo)"},
    { 0x0016, "Attribute (P_KeyTable)"},
    { 0x0017, "Attribute (SLtoVLMapptingTable)"},
    { 0x0018, "Attribute (VLArbitrationTable)"},
    { 0x0019, "Attribute (LinearForwardingTable)"},
    { 0x001A, "Attribute (RandomForwardingTable)"},
    { 0x001B, "Attribute (MulticastForwardingTable)"},
    { 0x001C, "Attribute (LinkSpeedWidthPairsTable)"},
    { 0x0020, "Attribute (SMInfo)"},
    { 0x0030, "Attribute (VendorDiag)"},
    { 0x0031, "Attribute (LedInfo)"},
    { 0, NULL}
};

/* SA Methods */
static const value_string SUBA_Methods[] = {
    { 0x01, "SubnAdmGet("},
    { 0x81, "SubnAdmGetResp("},
    { 0x02, "SubnAdmSet("},
    { 0x06, "SubnAdmReport("},
    { 0x86, "SubnAdmReportResp("},
    { 0x12, "SubnAdmGetTable("},
    { 0x92, "SubnAdmGetTableResp("},
    { 0x13, "SubnAdmGetTraceTable("},
    { 0x14, "SubnAdmGetMulti("},
    { 0x94, "SubnAdmGetMultiResp("},
    { 0x15, "SubnAdmDelete("},
    { 0x95, "SubnAdmDeleteResp("},
    { 0, NULL}
};
/* SA Attributes */
static const value_string SUBA_Attributes[] = {
    { 0x0001, "Attribute (ClassPortInfo)"},
    { 0x0002, "Attribute (Notice)"},
    { 0x0003, "Attribute (InformInfo)"},
    { 0x0011, "Attribute (NodeRecord)"},
    { 0x0012, "Attribute (PortInfoRecord)"},
    { 0x0013, "Attribute (SLtoVLMappingTableRecord)"},
    { 0x0014, "Attribute (SwitchInfoRecord)"},
    { 0x0015, "Attribute (LinearForwardingTableRecord)"},
    { 0x0016, "Attribute (RandomForwardingTableRecord)"},
    { 0x0017, "Attribute (MulticastForwardingTableRecord)"},
    { 0x0018, "Attribute (SMInfoRecord)"},
    { 0x0019, "Attribute (LinkSpeedWidthPairsTableRecord)"},
    { 0x00F3, "Attribute (InformInfoRecord)"},
    { 0x0020, "Attribute (LinkRecord)"},
    { 0x0030, "Attribute (GuidInfoRecord)"},
    { 0x0031, "Attribute (ServiceRecord)"},
    { 0x0033, "Attribute (P_KeyTableRecord)"},
    { 0x0035, "Attribute (PathRecord)"},
    { 0x0036, "Attribute (VLArbitrationTableRecord)"},
    { 0x0038, "Attribute (MCMembersRecord)"},
    { 0x0039, "Attribute (TraceRecord)"},
    { 0x003A, "Attribute (MultiPathRecord)"},
    { 0x003B, "Attribute (ServiceAssociationRecord)"},
    { 0, NULL}
};

/* CM Attributes */
static const value_string CM_Attributes[] = {
    { 0x0001, "ClassPortInfo"},
    { 0x0010, "ConnectRequest"},
    { 0x0011, "MsgRcptAck"},
    { 0x0012, "ConnectReject"},
    { 0x0013, "ConnectReply"},
    { 0x0014, "ReadyToUse"},
    { 0x0015, "DisconnectRequest"},
    { 0x0016, "DisconnectReply"},
    { 0x0017, "ServiceIDResReq"},
    { 0x0018, "ServiceIDResReqResp"},
    { 0x0019, "LoadAlternatePath"},
    { 0x001A, "AlternatePathResponse"},
    { 0, NULL}
};


/* RMPP Types */
#define RMPP_ILLEGAL 0
#define RMPP_DATA   1
#define RMPP_ACK    2
#define RMPP_STOP   3
#define RMPP_ABORT  4

static const value_string RMPP_Packet_Types[] = {
    { RMPP_ILLEGAL, " Illegal RMPP Type (0)! " },
    { RMPP_DATA, "RMPP (DATA)" },
    { RMPP_ACK, "RMPP (ACK)" },
    { RMPP_STOP, "RMPP (STOP)" },
    { RMPP_ABORT, "RMPP (ABORT)" },
    { 0, NULL}
};

static const value_string RMPP_Flags[] = {
    { 3, " (Transmission Sequence - First Packet)"},
    { 5, " (Transmission Sequence - Last Packet)"},
    { 1, " (Transmission Sequence) " },
    { 0, NULL}
};

static const value_string RMPP_Status[]= {
    { 0, " (Normal)"},
    { 1, " (Resources Exhausted)"},
    { 118, " (Total Time Too Long)"},
    { 119, " (Inconsistent Last and PayloadLength)"},
    { 120, " (Inconsistent First and Segment Number)"},
    { 121, " (Bad RMPPType)"},
    { 122, " (NewWindowLast Too Small)"},
    { 123, " (SegmentNumber Too Big)"},
    { 124, " (Illegal Status)"},
    { 125, " (Unsupported Version)"},
    { 126, " (Too Many Retries)"},
    { 127, " (Unspecified - Unknown Error Code on ABORT)"},
    { 0, NULL}
};

static const value_string DiagCode[]= {
    {0x0000, "Function Ready"},
    {0x0001, "Performing Self Test"},
    {0x0002, "Initializing"},
    {0x0003, "Soft Error - Function has non-fatal error"},
    {0x0004, "Hard Error - Function has fatal error"},
    { 0, NULL}
};
static const value_string LinkWidthEnabled[]= {
    {0x0000, "No State Change"},
    {0x0001, "1x"},
    {0x0002, "4x"},
    {0x0003, "1x or 4x"},
    {0x0004, "8x"},
    {0x0005, "1x or 8x"},
    {0x0006, "4x or 8x"},
    {0x0007, "1x or 4x or 8x"},
    {0x0008, "12x"},
    {0x0009, "1x or 12x"},
    {0x000A, "4x or 12x"},
    {0x000B, "1x or 4x or 12x"},
    {0x000C, "8x or 12x"},
    {0x000D, "1x or 8x or 12x"},
    {0x000E, "4x or 8x or 12x"},
    {0x000E, "1x or 4x or 8x or 12x"},
    {0x00FF, "Set to LinkWidthSupported Value - Response contains actual LinkWidthSupported"},
    { 0, NULL}
};

static const value_string LinkWidthSupported[]= {
    {0x0001, "1x"},
    {0x0003, "1x or 4x"},
    {0x0007, "1x or 4x or 8x"},
    {0x000B, "1x or 4x or 12x"},
    {0x000F, "1x or 4x or 8x or 12x"},
    { 0, NULL}
};
static const value_string LinkWidthActive[]= {
    {0x0001, "1x"},
    {0x0002, "4x"},
    {0x0004, "8x"},
    {0x0008, "12x"},
    { 0, NULL}
};
static const value_string LinkSpeedSupported[]= {
    {0x0001, "2.5 Gbps"},
    {0x0003, "2.5 or 5.0 Gbps"},
    {0x0005, "2.5 or 10.0 Gbps"},
    {0x0007, "2.5 or 5.0 or 10.0 Gbps"},
    { 0, NULL}
};
static const value_string PortState[]= {
    {0x0000, "No State Change"},
    {0x0001, "Down (includes failed links)"},
    {0x0002, "Initialized"},
    {0x0003, "Armed"},
    {0x0004, "Active"},
    { 0, NULL}
};
static const value_string PortPhysicalState[]= {
    {0x0000, "No State Change"},
    {0x0001, "Sleep"},
    {0x0002, "Polling"},
    {0x0003, "Disabled"},
    {0x0004, "PortConfigurationTraining"},
    {0x0005, "LinkUp"},
    {0x0006, "LinkErrorRecovery"},
    {0x0007, "Phy Test"},
    { 0, NULL}
};
static const value_string LinkDownDefaultState[]= {
    {0x0000, "No State Change"},
    {0x0001, "Sleep"},
    {0x0002, "Polling"},
    { 0, NULL}
};
static const value_string LinkSpeedActive[]= {
    {0x0001, "2.5 Gbps"},
    {0x0002, "5.0 Gbps"},
    {0x0004, "10.0 Gbps"},
    { 0, NULL}
};
static const value_string LinkSpeedEnabled[]= {
    {0x0000, "No State Change"},
    {0x0001, "2.5 Gbps"},
    {0x0003, "2.5 or 5.0 Gbps"},
    {0x0005, "2.5 or 10.0 Gbps"},
    {0x0007, "2.5 or 5.0 or 10.0 Gbps"},
    {0x000F, "Set to LinkSpeedSupported value - response contains actual LinkSpeedSupported"},
    { 0, NULL}
};
static const value_string NeighborMTU[]= {
    {0x0001, "256"},
    {0x0002, "512"},
    {0x0003, "1024"},
    {0x0004, "2048"},
    {0x0005, "4096"},
    { 0, NULL}
};
static const value_string VLCap[]= {
    {0x0001, "VL0"},
    {0x0002, "VL0, VL1"},
    {0x0003, "VL0 - VL3"},
    {0x0004, "VL0 - VL7"},
    {0x0005, "VL0 - VL14"},
    { 0, NULL}
};
static const value_string MTUCap[]= {
    {0x0001, "256"},
    {0x0002, "512"},
    {0x0003, "1024"},
    {0x0004, "2048"},
    {0x0005, "4096"},
    { 0, NULL}
};
static const value_string OperationalVLs[]= {
    {0x0000, "No State Change"},
    {0x0001, "VL0"},
    {0x0002, "VL0, VL1"},
    {0x0003, "VL0 - VL3"},
    {0x0004, "VL0 - VL7"},
    {0x0005, "VL0 - VL14"},
    { 0, NULL}
};

/* Local Route Header (LRH) */
static int hf_infiniband_LRH = -1;
static int hf_infiniband_virtual_lane = -1;
static int hf_infiniband_link_version = -1;
static int hf_infiniband_service_level = -1;
static int hf_infiniband_reserved2 = -1;
static int hf_infiniband_link_next_header = -1;
static int hf_infiniband_destination_local_id = -1;
static int hf_infiniband_reserved5 = -1;
static int hf_infiniband_packet_length = -1;
static int hf_infiniband_source_local_id = -1;
/* Global Route Header (GRH) */
static int hf_infiniband_GRH = -1;
static int hf_infiniband_ip_version = -1;
static int hf_infiniband_traffic_class = -1;
static int hf_infiniband_flow_label = -1;
static int hf_infiniband_payload_length = -1;
static int hf_infiniband_next_header = -1;
static int hf_infiniband_hop_limit = -1;
static int hf_infiniband_source_gid = -1;
static int hf_infiniband_destination_gid = -1;
/* Base Transport Header (BTH) */
static int hf_infiniband_BTH = -1;
static int hf_infiniband_opcode = -1;
static int hf_infiniband_solicited_event = -1;
static int hf_infiniband_migreq = -1;
static int hf_infiniband_pad_count = -1;
static int hf_infiniband_transport_header_version = -1;
static int hf_infiniband_partition_key = -1;
static int hf_infiniband_reserved8 = -1;
static int hf_infiniband_destination_qp = -1;
static int hf_infiniband_acknowledge_request = -1;
static int hf_infiniband_reserved7 = -1;
static int hf_infiniband_packet_sequence_number = -1;
/* Raw Header (RWH) */
static int hf_infiniband_RWH = -1;
static int hf_infiniband_reserved16_RWH = -1;
static int hf_infiniband_etype = -1;
/* Reliable Datagram Extended Transport Header (RDETH) */
static int hf_infiniband_RDETH = -1;
static int hf_infiniband_reserved8_RDETH = -1;
static int hf_infiniband_ee_context = -1;
/* Datagram Extended Transport Header (DETH) */
static int hf_infiniband_DETH = -1;
static int hf_infiniband_queue_key = -1;
static int hf_infiniband_reserved8_DETH = -1;
static int hf_infiniband_source_qp = -1;
/* RDMA Extended Transport Header (RETH) */
static int hf_infiniband_RETH = -1;
static int hf_infiniband_virtual_address = -1;
static int hf_infiniband_remote_key = -1;
static int hf_infiniband_dma_length = -1;
/* Atomic Extended Transport Header (AtomicETH) */
static int hf_infiniband_AtomicETH = -1;
/* static int hf_infiniband_virtual_address_AtomicETH = -1;                  */
/* static int hf_infiniband_remote_key_AtomicETH = -1;                       */
static int hf_infiniband_swap_or_add_data = -1;
static int hf_infiniband_compare_data = -1;
/* ACK Extended Transport Header (AETH) */
static int hf_infiniband_AETH = -1;
static int hf_infiniband_syndrome = -1;
static int hf_infiniband_message_sequence_number = -1;
/* Atomic ACK Extended Transport Header (AtomicAckETH) */
static int hf_infiniband_AtomicAckETH = -1;
static int hf_infiniband_original_remote_data = -1;
/* Immediate Extended Transport Header (ImmDt) */
static int hf_infiniband_IMMDT = -1;
/* Invalidate Extended Transport Header (IETH) */
static int hf_infiniband_IETH = -1;
/* Payload */
static int hf_infiniband_payload = -1;
static int hf_infiniband_invariant_crc = -1;
static int hf_infiniband_variant_crc = -1;
/* Unknown or Vendor Specific */
static int hf_infiniband_raw_data = -1;
static int hf_infiniband_vendor = -1;
/* CM REQ Header */
static int hf_cm_req_local_comm_id = -1;
static int hf_cm_req_service_id = -1;
static int hf_cm_req_local_ca_guid = -1;
static int hf_cm_req_local_qkey = -1;
static int hf_cm_req_local_qpn = -1;
static int hf_cm_req_respo_res = -1;
static int hf_cm_req_local_eecn = -1;
static int hf_cm_req_init_depth = -1;
static int hf_cm_req_remote_eecn = -1;
static int hf_cm_req_remote_cm_resp_to = -1;
static int hf_cm_req_transp_serv_type = -1;
static int hf_cm_req_e2e_flow_ctrl = -1;
static int hf_cm_req_start_psn = -1;
static int hf_cm_req_local_cm_resp_to = -1;
static int hf_cm_req_retry_count = -1;
static int hf_cm_req_pkey = -1;
static int hf_cm_req_path_pp_mtu = -1;
static int hf_cm_req_rdc_exists = -1;
static int hf_cm_req_rnr_retry_count = -1;
static int hf_cm_req_max_cm_retries = -1;
static int hf_cm_req_srq = -1;
static int hf_cm_req_primary_local_lid = -1;
static int hf_cm_req_primary_remote_lid = -1;
static int hf_cm_req_primary_local_gid = -1;
static int hf_cm_req_primary_remote_gid = -1;
static int hf_cm_req_primary_flow_label = -1;
static int hf_cm_req_primary_packet_rate = -1;
static int hf_cm_req_primary_traffic_class = -1;
static int hf_cm_req_primary_hop_limit = -1;
static int hf_cm_req_primary_sl = -1;
static int hf_cm_req_primary_subnet_local = -1;
static int hf_cm_req_primary_local_ack_to = -1;
static int hf_cm_req_alt_local_lid = -1;
static int hf_cm_req_alt_remote_lid = -1;
static int hf_cm_req_alt_local_gid = -1;
static int hf_cm_req_alt_remote_gid = -1;
static int hf_cm_req_flow_label = -1;
static int hf_cm_req_packet_rate = -1;
static int hf_cm_req_alt_traffic_class = -1;
static int hf_cm_req_alt_hop_limit = -1;
static int hf_cm_req_SL = -1;
static int hf_cm_req_subnet_local = -1;
static int hf_cm_req_local_ACK_timeout = -1;
static int hf_cm_req_private_data = -1;
/* CM REP Header */
static int hf_cm_rep_localcommid = -1;
static int hf_cm_rep_remotecommid = -1;
static int hf_cm_rep_localqkey = -1;
static int hf_cm_rep_localqpn = -1;
static int hf_cm_rep_localeecontnum = -1;
static int hf_cm_rep_startingpsn = -1;
static int hf_cm_rep_responderres = -1;
static int hf_cm_rep_initiatordepth = -1;
static int hf_cm_rep_tgtackdelay = -1;
static int hf_cm_rep_failoveracc = -1;
static int hf_cm_rep_e2eflowctl = -1;
static int hf_cm_rep_rnrretrycount = -1;
static int hf_cm_rep_srq = -1;
static int hf_cm_rep_localcaguid = -1;
static int hf_cm_rep_privatedata = -1;
/* CM RTU Header */
static int hf_cm_rtu_localcommid = -1;
static int hf_cm_rtu_remotecommid = -1;
static int hf_cm_rtu_privatedata = -1;
/* CM REJ Header */
static int hf_cm_rej_local_commid = -1;
static int hf_cm_rej_remote_commid = -1;
static int hf_cm_rej_msg_rej = -1;
static int hf_cm_rej_rej_info_len = -1;
static int hf_cm_rej_reason = -1;
static int hf_cm_rej_add_rej_info = -1;
static int hf_cm_rej_private_data = -1;
/* MAD Base Header */
static int hf_infiniband_MAD = -1;
static int hf_infiniband_base_version = -1;
static int hf_infiniband_mgmt_class = -1;
static int hf_infiniband_class_version = -1;
/* static int hf_infiniband_reserved1 = -1;                                  */
static int hf_infiniband_method = -1;
static int hf_infiniband_status = -1;
static int hf_infiniband_class_specific = -1;
static int hf_infiniband_transaction_id = -1;
static int hf_infiniband_attribute_id = -1;
static int hf_infiniband_reserved16 = -1;
static int hf_infiniband_attribute_modifier = -1;
static int hf_infiniband_data = -1;
/* RMPP Header */
static int hf_infiniband_RMPP = -1;
static int hf_infiniband_rmpp_version = -1;
static int hf_infiniband_rmpp_type = -1;
static int hf_infiniband_r_resp_time = -1;
static int hf_infiniband_rmpp_flags = -1;
static int hf_infiniband_rmpp_status = -1;
static int hf_infiniband_rmpp_data1 = -1;
static int hf_infiniband_rmpp_data2 = -1;
/* RMPP Data */
/* static int hf_infiniband_RMPP_DATA = -1;                                  */
static int hf_infiniband_segment_number = -1;
static int hf_infiniband_payload_length32 = -1;
static int hf_infiniband_transferred_data = -1;
/* RMPP ACK */
static int hf_infiniband_new_window_last = -1;
static int hf_infiniband_reserved220 = -1;
/* RMPP ABORT and STOP */
static int hf_infiniband_reserved32 = -1;
static int hf_infiniband_optional_extended_error_data = -1;
/* SMP Data LID Routed */
static int hf_infiniband_SMP_LID = -1;
static int hf_infiniband_m_key = -1;
static int hf_infiniband_smp_data = -1;
static int hf_infiniband_reserved1024 = -1;
static int hf_infiniband_reserved256 = -1;
/* SMP Data Directed Route */
static int hf_infiniband_SMP_DIRECTED = -1;
static int hf_infiniband_smp_status = -1;
static int hf_infiniband_hop_pointer = -1;
static int hf_infiniband_hop_count = -1;
static int hf_infiniband_dr_slid = -1;
static int hf_infiniband_dr_dlid = -1;
static int hf_infiniband_reserved28 = -1;
static int hf_infiniband_d = -1;
static int hf_infiniband_initial_path = -1;
static int hf_infiniband_return_path = -1;
/* SA MAD Header */
static int hf_infiniband_SA = -1;
static int hf_infiniband_sm_key = -1;
static int hf_infiniband_attribute_offset = -1;
static int hf_infiniband_component_mask = -1;
static int hf_infiniband_subnet_admin_data = -1;
/* Mellanox EoIB encapsulation header */
static int hf_infiniband_EOIB = -1;
static int hf_infiniband_ver = -1;
static int hf_infiniband_tcp_chk = -1;
static int hf_infiniband_ip_chk = -1;
static int hf_infiniband_fcs = -1;
static int hf_infiniband_ms = -1;
static int hf_infiniband_seg_off = -1;
static int hf_infiniband_seg_id = -1;

/* Attributes
* Additional Structures for individuala attribute decoding.
* Since they are not headers the naming convention is slightly modified
* Convention: hf_infiniband_[attribute name]_[field]
* This was not entirely necessary but I felt the previous convention
* did not provide adequate readability for the granularity of attribute/attribute fields. */

/* NodeDescription */
static int hf_infiniband_NodeDescription_NodeString = -1;
/* NodeInfo */
static int hf_infiniband_NodeInfo_BaseVersion = -1;
static int hf_infiniband_NodeInfo_ClassVersion = -1;
static int hf_infiniband_NodeInfo_NodeType = -1;
static int hf_infiniband_NodeInfo_NumPorts = -1;
static int hf_infiniband_NodeInfo_SystemImageGUID = -1;
static int hf_infiniband_NodeInfo_NodeGUID = -1;
static int hf_infiniband_NodeInfo_PortGUID = -1;
static int hf_infiniband_NodeInfo_PartitionCap = -1;
static int hf_infiniband_NodeInfo_DeviceID = -1;
static int hf_infiniband_NodeInfo_Revision = -1;
static int hf_infiniband_NodeInfo_LocalPortNum = -1;
static int hf_infiniband_NodeInfo_VendorID = -1;
/* SwitchInfo */
static int hf_infiniband_SwitchInfo_LinearFDBCap = -1;
static int hf_infiniband_SwitchInfo_RandomFDBCap = -1;
static int hf_infiniband_SwitchInfo_MulticastFDBCap = -1;
static int hf_infiniband_SwitchInfo_LinearFDBTop = -1;
static int hf_infiniband_SwitchInfo_DefaultPort = -1;
static int hf_infiniband_SwitchInfo_DefaultMulticastPrimaryPort = -1;
static int hf_infiniband_SwitchInfo_DefaultMulticastNotPrimaryPort = -1;
static int hf_infiniband_SwitchInfo_LifeTimeValue = -1;
static int hf_infiniband_SwitchInfo_PortStateChange = -1;
static int hf_infiniband_SwitchInfo_OptimizedSLtoVLMappingProgramming = -1;
static int hf_infiniband_SwitchInfo_LIDsPerPort = -1;
static int hf_infiniband_SwitchInfo_PartitionEnforcementCap = -1;
static int hf_infiniband_SwitchInfo_InboundEnforcementCap = -1;
static int hf_infiniband_SwitchInfo_OutboundEnforcementCap = -1;
static int hf_infiniband_SwitchInfo_FilterRawInboundCap = -1;
static int hf_infiniband_SwitchInfo_FilterRawOutboundCap = -1;
static int hf_infiniband_SwitchInfo_EnhancedPortZero = -1;
/* GUIDInfo */
/* static int hf_infiniband_GUIDInfo_GUIDBlock = -1;                         */
static int hf_infiniband_GUIDInfo_GUID = -1;
/* PortInfo */
static int hf_infiniband_PortInfo_GidPrefix = -1;
static int hf_infiniband_PortInfo_LID = -1;
static int hf_infiniband_PortInfo_MasterSMLID = -1;
static int hf_infiniband_PortInfo_CapabilityMask = -1;

/* Capability Mask Flags */
static int hf_infiniband_PortInfo_CapabilityMask_SM = -1;
static int hf_infiniband_PortInfo_CapabilityMask_NoticeSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_TrapSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_OptionalPDSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_AutomaticMigrationSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_SLMappingSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_MKeyNVRAM = -1;
static int hf_infiniband_PortInfo_CapabilityMask_PKeyNVRAM = -1;
static int hf_infiniband_PortInfo_CapabilityMask_LEDInfoSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_SMdisabled = -1;
static int hf_infiniband_PortInfo_CapabilityMask_SystemImageGUIDSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_PKeySwitchExternalPortTrapSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_CommunicationsManagementSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_SNMPTunnelingSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_ReinitSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_DeviceManagementSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_VendorClassSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_DRNoticeSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_CapabilityMaskNoticeSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_BootManagementSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_LinkRoundTripLatencySupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_ClientRegistrationSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_OtherLocalChangesNoticeSupported = -1;
static int hf_infiniband_PortInfo_CapabilityMask_LinkSpeedWIdthPairsTableSupported = -1;
/* End Capability Mask Flags */


static int hf_infiniband_PortInfo_DiagCode = -1;
static int hf_infiniband_PortInfo_M_KeyLeasePeriod = -1;
static int hf_infiniband_PortInfo_LocalPortNum = -1;
static int hf_infiniband_PortInfo_LinkWidthEnabled = -1;
static int hf_infiniband_PortInfo_LinkWidthSupported = -1;
static int hf_infiniband_PortInfo_LinkWidthActive = -1;
static int hf_infiniband_PortInfo_LinkSpeedSupported = -1;
static int hf_infiniband_PortInfo_PortState = -1;
static int hf_infiniband_PortInfo_PortPhysicalState = -1;
static int hf_infiniband_PortInfo_LinkDownDefaultState = -1;
static int hf_infiniband_PortInfo_M_KeyProtectBits = -1;
static int hf_infiniband_PortInfo_LMC = -1;
static int hf_infiniband_PortInfo_LinkSpeedActive = -1;
static int hf_infiniband_PortInfo_LinkSpeedEnabled = -1;
static int hf_infiniband_PortInfo_NeighborMTU = -1;
static int hf_infiniband_PortInfo_MasterSMSL = -1;
static int hf_infiniband_PortInfo_VLCap = -1;
static int hf_infiniband_PortInfo_M_Key = -1;
static int hf_infiniband_PortInfo_InitType = -1;
static int hf_infiniband_PortInfo_VLHighLimit = -1;
static int hf_infiniband_PortInfo_VLArbitrationHighCap = -1;
static int hf_infiniband_PortInfo_VLArbitrationLowCap = -1;
static int hf_infiniband_PortInfo_InitTypeReply = -1;
static int hf_infiniband_PortInfo_MTUCap = -1;
static int hf_infiniband_PortInfo_VLStallCount = -1;
static int hf_infiniband_PortInfo_HOQLife = -1;
static int hf_infiniband_PortInfo_OperationalVLs = -1;
static int hf_infiniband_PortInfo_PartitionEnforcementInbound = -1;
static int hf_infiniband_PortInfo_PartitionEnforcementOutbound = -1;
static int hf_infiniband_PortInfo_FilterRawInbound = -1;
static int hf_infiniband_PortInfo_FilterRawOutbound = -1;
static int hf_infiniband_PortInfo_M_KeyViolations = -1;
static int hf_infiniband_PortInfo_P_KeyViolations = -1;
static int hf_infiniband_PortInfo_Q_KeyViolations = -1;
static int hf_infiniband_PortInfo_GUIDCap = -1;
static int hf_infiniband_PortInfo_ClientReregister = -1;
static int hf_infiniband_PortInfo_SubnetTimeOut = -1;
static int hf_infiniband_PortInfo_RespTimeValue = -1;
static int hf_infiniband_PortInfo_LocalPhyErrors = -1;
static int hf_infiniband_PortInfo_OverrunErrors = -1;
static int hf_infiniband_PortInfo_MaxCreditHint = -1;
static int hf_infiniband_PortInfo_LinkRoundTripLatency = -1;

/* P_KeyTable */
static int hf_infiniband_P_KeyTable_P_KeyTableBlock = -1;
static int hf_infiniband_P_KeyTable_MembershipType = -1;
static int hf_infiniband_P_KeyTable_P_KeyBase = -1;

/* SLtoVLMappingTable */
static int hf_infiniband_SLtoVLMappingTable_SLtoVL_HighBits = -1;
static int hf_infiniband_SLtoVLMappingTable_SLtoVL_LowBits = -1;

/* VLArbitrationTable */
/* static int hf_infiniband_VLArbitrationTable_VLWeightPairs = -1;           */
static int hf_infiniband_VLArbitrationTable_VL = -1;
static int hf_infiniband_VLArbitrationTable_Weight = -1;

/* LinearForwardingTable */
/* static int hf_infiniband_LinearForwardingTable_LinearForwardingTableBlock = -1;  */
static int hf_infiniband_LinearForwardingTable_Port = -1;

/* RandomForwardingTable */
/* static int hf_infiniband_RandomForwardingTable_RandomForwardingTableBlock = -1;  */
static int hf_infiniband_RandomForwardingTable_LID = -1;
static int hf_infiniband_RandomForwardingTable_Valid = -1;
static int hf_infiniband_RandomForwardingTable_LMC = -1;
static int hf_infiniband_RandomForwardingTable_Port = -1;

/* MulticastForwardingTable */
/* static int hf_infiniband_MulticastForwardingTable_MulticastForwardingTableBlock = -1;    */
static int hf_infiniband_MulticastForwardingTable_PortMask = -1;

/* SMInfo */
static int hf_infiniband_SMInfo_GUID = -1;
static int hf_infiniband_SMInfo_SM_Key = -1;
static int hf_infiniband_SMInfo_ActCount = -1;
static int hf_infiniband_SMInfo_Priority = -1;
static int hf_infiniband_SMInfo_SMState = -1;

/* VendorDiag */
static int hf_infiniband_VendorDiag_NextIndex = -1;
static int hf_infiniband_VendorDiag_DiagData = -1;

/* LedInfo */
static int hf_infiniband_LedInfo_LedMask = -1;

/* LinkSpeedWidthPairsTable */
static int hf_infiniband_LinkSpeedWidthPairsTable_NumTables = -1;
static int hf_infiniband_LinkSpeedWidthPairsTable_PortMask = -1;
static int hf_infiniband_LinkSpeedWidthPairsTable_SpeedTwoFive = -1;
static int hf_infiniband_LinkSpeedWidthPairsTable_SpeedFive = -1;
static int hf_infiniband_LinkSpeedWidthPairsTable_SpeedTen = -1;

/* Attributes for Subnet Administration.
* Mostly we have "Records" here which are just structures of SM attributes.
* There are some unique attributes though that we will want to have a structure for. */

/* NodeRecord */
/* PortInfoRecord */
/* SLtoVLMappingTableRecord */
/* SwitchInfoRecord */
/* LinearForwardingTableRecord */
/* RandomForwardingTableRecord */
/* MulticastForwardingTableRecord */
/* VLArbitrationTableRecord */

static int hf_infiniband_SA_LID = -1;
static int hf_infiniband_SA_EndportLID = -1;
static int hf_infiniband_SA_PortNum = -1;
static int hf_infiniband_SA_InputPortNum = -1;
static int hf_infiniband_SA_OutputPortNum = -1;
static int hf_infiniband_SA_BlockNum_EightBit = -1;
static int hf_infiniband_SA_BlockNum_NineBit = -1;
static int hf_infiniband_SA_BlockNum_SixteenBit = -1;
static int hf_infiniband_SA_Position = -1;
/* static int hf_infiniband_SA_Index = -1;                                   */

/* InformInfoRecord */
static int hf_infiniband_InformInfoRecord_SubscriberGID = -1;
static int hf_infiniband_InformInfoRecord_Enum = -1;

/* InformInfo */
static int hf_infiniband_InformInfo_GID = -1;
static int hf_infiniband_InformInfo_LIDRangeBegin = -1;
static int hf_infiniband_InformInfo_LIDRangeEnd = -1;
static int hf_infiniband_InformInfo_IsGeneric = -1;
static int hf_infiniband_InformInfo_Subscribe = -1;
static int hf_infiniband_InformInfo_Type = -1;
static int hf_infiniband_InformInfo_TrapNumberDeviceID = -1;
static int hf_infiniband_InformInfo_QPN = -1;
static int hf_infiniband_InformInfo_RespTimeValue = -1;
static int hf_infiniband_InformInfo_ProducerTypeVendorID = -1;

/* LinkRecord */
static int hf_infiniband_LinkRecord_FromLID = -1;
static int hf_infiniband_LinkRecord_FromPort = -1;
static int hf_infiniband_LinkRecord_ToPort = -1;
static int hf_infiniband_LinkRecord_ToLID = -1;

/* ServiceRecord */
static int hf_infiniband_ServiceRecord_ServiceID = -1;
static int hf_infiniband_ServiceRecord_ServiceGID = -1;
static int hf_infiniband_ServiceRecord_ServiceP_Key = -1;
static int hf_infiniband_ServiceRecord_ServiceLease = -1;
static int hf_infiniband_ServiceRecord_ServiceKey = -1;
static int hf_infiniband_ServiceRecord_ServiceName = -1;
static int hf_infiniband_ServiceRecord_ServiceData = -1;

/* ServiceAssociationRecord */
static int hf_infiniband_ServiceAssociationRecord_ServiceKey = -1;
static int hf_infiniband_ServiceAssociationRecord_ServiceName = -1;

/* PathRecord */
static int hf_infiniband_PathRecord_DGID = -1;
static int hf_infiniband_PathRecord_SGID = -1;
static int hf_infiniband_PathRecord_DLID = -1;
static int hf_infiniband_PathRecord_SLID = -1;
static int hf_infiniband_PathRecord_RawTraffic = -1;
static int hf_infiniband_PathRecord_FlowLabel = -1;
static int hf_infiniband_PathRecord_HopLimit = -1;
static int hf_infiniband_PathRecord_TClass = -1;
static int hf_infiniband_PathRecord_Reversible = -1;
static int hf_infiniband_PathRecord_NumbPath = -1;
static int hf_infiniband_PathRecord_P_Key = -1;
static int hf_infiniband_PathRecord_SL = -1;
static int hf_infiniband_PathRecord_MTUSelector = -1;
static int hf_infiniband_PathRecord_MTU = -1;
static int hf_infiniband_PathRecord_RateSelector = -1;
static int hf_infiniband_PathRecord_Rate = -1;
static int hf_infiniband_PathRecord_PacketLifeTimeSelector = -1;
static int hf_infiniband_PathRecord_PacketLifeTime = -1;
static int hf_infiniband_PathRecord_Preference = -1;

/* MCMemberRecord */
static int hf_infiniband_MCMemberRecord_MGID = -1;
static int hf_infiniband_MCMemberRecord_PortGID = -1;
static int hf_infiniband_MCMemberRecord_Q_Key = -1;
static int hf_infiniband_MCMemberRecord_MLID = -1;
static int hf_infiniband_MCMemberRecord_MTUSelector = -1;
static int hf_infiniband_MCMemberRecord_MTU = -1;
static int hf_infiniband_MCMemberRecord_TClass = -1;
static int hf_infiniband_MCMemberRecord_P_Key = -1;
static int hf_infiniband_MCMemberRecord_RateSelector = -1;
static int hf_infiniband_MCMemberRecord_Rate = -1;
static int hf_infiniband_MCMemberRecord_PacketLifeTimeSelector = -1;
static int hf_infiniband_MCMemberRecord_PacketLifeTime = -1;
static int hf_infiniband_MCMemberRecord_SL = -1;
static int hf_infiniband_MCMemberRecord_FlowLabel = -1;
static int hf_infiniband_MCMemberRecord_HopLimit = -1;
static int hf_infiniband_MCMemberRecord_Scope = -1;
static int hf_infiniband_MCMemberRecord_JoinState = -1;
static int hf_infiniband_MCMemberRecord_ProxyJoin = -1;

/* TraceRecord */
static int hf_infiniband_TraceRecord_GIDPrefix = -1;
static int hf_infiniband_TraceRecord_IDGeneration = -1;
static int hf_infiniband_TraceRecord_NodeType = -1;
static int hf_infiniband_TraceRecord_NodeID = -1;
static int hf_infiniband_TraceRecord_ChassisID = -1;
static int hf_infiniband_TraceRecord_EntryPortID = -1;
static int hf_infiniband_TraceRecord_ExitPortID = -1;
static int hf_infiniband_TraceRecord_EntryPort = -1;
static int hf_infiniband_TraceRecord_ExitPort = -1;

/* MultiPathRecord */
static int hf_infiniband_MultiPathRecord_RawTraffic = -1;
static int hf_infiniband_MultiPathRecord_FlowLabel = -1;
static int hf_infiniband_MultiPathRecord_HopLimit = -1;
static int hf_infiniband_MultiPathRecord_TClass = -1;
static int hf_infiniband_MultiPathRecord_Reversible = -1;
static int hf_infiniband_MultiPathRecord_NumbPath = -1;
static int hf_infiniband_MultiPathRecord_P_Key = -1;
static int hf_infiniband_MultiPathRecord_SL = -1;
static int hf_infiniband_MultiPathRecord_MTUSelector = -1;
static int hf_infiniband_MultiPathRecord_MTU = -1;
static int hf_infiniband_MultiPathRecord_RateSelector = -1;
static int hf_infiniband_MultiPathRecord_Rate = -1;
static int hf_infiniband_MultiPathRecord_PacketLifeTimeSelector = -1;
static int hf_infiniband_MultiPathRecord_PacketLifeTime = -1;
static int hf_infiniband_MultiPathRecord_IndependenceSelector = -1;
static int hf_infiniband_MultiPathRecord_GIDScope = -1;
static int hf_infiniband_MultiPathRecord_SGIDCount = -1;
static int hf_infiniband_MultiPathRecord_DGIDCount = -1;
static int hf_infiniband_MultiPathRecord_SDGID = -1;

/* Notice */
static int hf_infiniband_Notice_IsGeneric = -1;
static int hf_infiniband_Notice_Type = -1;
static int hf_infiniband_Notice_ProducerTypeVendorID = -1;
static int hf_infiniband_Notice_TrapNumberDeviceID = -1;
static int hf_infiniband_Notice_IssuerLID = -1;
static int hf_infiniband_Notice_NoticeToggle = -1;
static int hf_infiniband_Notice_NoticeCount = -1;
static int hf_infiniband_Notice_DataDetails = -1;
/* static int hf_infiniband_Notice_IssuerGID = -1;             */
/* static int hf_infiniband_Notice_ClassTrapSpecificData = -1; */

/* PortCounters attribute in Performance class */
static int hf_infiniband_PortCounters = -1;
static int hf_infiniband_PortCounters_PortSelect = -1;
static int hf_infiniband_PortCounters_CounterSelect = -1;
static int hf_infiniband_PortCounters_SymbolErrorCounter = -1;
static int hf_infiniband_PortCounters_LinkErrorRecoveryCounter = -1;
static int hf_infiniband_PortCounters_LinkDownedCounter = -1;
static int hf_infiniband_PortCounters_PortRcvErrors = -1;
static int hf_infiniband_PortCounters_PortRcvRemotePhysicalErrors = -1;
static int hf_infiniband_PortCounters_PortRcvSwitchRelayErrors = -1;
static int hf_infiniband_PortCounters_PortXmitDiscards = -1;
static int hf_infiniband_PortCounters_PortXmitConstraintErrors = -1;
static int hf_infiniband_PortCounters_PortRcvConstraintErrors = -1;
static int hf_infiniband_PortCounters_LocalLinkIntegrityErrors = -1;
static int hf_infiniband_PortCounters_ExcessiveBufferOverrunErrors = -1;
static int hf_infiniband_PortCounters_VL15Dropped = -1;
static int hf_infiniband_PortCounters_PortXmitData = -1;
static int hf_infiniband_PortCounters_PortRcvData = -1;
static int hf_infiniband_PortCounters_PortXmitPkts = -1;
static int hf_infiniband_PortCounters_PortRcvPkts = -1;

/* Extended PortCounters attribute in Performance class */
static int hf_infiniband_PortCountersExt = -1;
static int hf_infiniband_PortCountersExt_PortSelect = -1;
static int hf_infiniband_PortCountersExt_CounterSelect = -1;
static int hf_infiniband_PortCountersExt_PortXmitData = -1;
static int hf_infiniband_PortCountersExt_PortRcvData = -1;
static int hf_infiniband_PortCountersExt_PortXmitPkts = -1;
static int hf_infiniband_PortCountersExt_PortRcvPkts = -1;
static int hf_infiniband_PortCountersExt_PortUnicastXmitPkts = -1;
static int hf_infiniband_PortCountersExt_PortUnicastRcvPkts = -1;
static int hf_infiniband_PortCountersExt_PortMulticastXmitPkts = -1;
static int hf_infiniband_PortCountersExt_PortMulticastRcvPkts = -1;

/* Notice DataDetails and ClassTrapSpecific Data for certain traps
* Note that traps reuse many fields, so they are only declared once under the first trap that they appear.
* There is no need to redeclare them for specific Traps (as with other SA Attributes) because they are uniform between Traps. */

/* Parse DataDetails for a given Trap */
static void parse_NoticeDataDetails(proto_tree*, tvbuff_t*, gint *offset, guint16 trapNumber);

/* Traps 64,65,66,67 */
static int hf_infiniband_Trap_GIDADDR = -1;

/* Traps 68,69 */
/* DataDetails */
static int hf_infiniband_Trap_COMP_MASK = -1;
static int hf_infiniband_Trap_WAIT_FOR_REPATH = -1;
/* ClassTrapSpecificData */
/* static int hf_infiniband_Trap_PATH_REC = -1;                              */

/* Trap 128 */
static int hf_infiniband_Trap_LIDADDR = -1;

/* Trap 129, 130, 131 */
static int hf_infiniband_Trap_PORTNO = -1;

/* Trap 144 */
static int hf_infiniband_Trap_OtherLocalChanges = -1;
static int hf_infiniband_Trap_CAPABILITYMASK = -1;
static int hf_infiniband_Trap_LinkSpeecEnabledChange = -1;
static int hf_infiniband_Trap_LinkWidthEnabledChange = -1;
static int hf_infiniband_Trap_NodeDescriptionChange = -1;

/* Trap 145 */
static int hf_infiniband_Trap_SYSTEMIMAGEGUID = -1;

/* Trap 256 */
static int hf_infiniband_Trap_DRSLID = -1;
static int hf_infiniband_Trap_METHOD = -1;
static int hf_infiniband_Trap_ATTRIBUTEID = -1;
static int hf_infiniband_Trap_ATTRIBUTEMODIFIER = -1;
static int hf_infiniband_Trap_MKEY = -1;
static int hf_infiniband_Trap_DRNotice = -1;
static int hf_infiniband_Trap_DRPathTruncated = -1;
static int hf_infiniband_Trap_DRHopCount = -1;
static int hf_infiniband_Trap_DRNoticeReturnPath = -1;

/* Trap 257, 258 */
static int hf_infiniband_Trap_LIDADDR1 = -1;
static int hf_infiniband_Trap_LIDADDR2 = -1;
static int hf_infiniband_Trap_KEY = -1;
static int hf_infiniband_Trap_SL = -1;
static int hf_infiniband_Trap_QP1 = -1;
static int hf_infiniband_Trap_QP2 = -1;
static int hf_infiniband_Trap_GIDADDR1 = -1;
static int hf_infiniband_Trap_GIDADDR2 = -1;

/* Trap 259 */
static int hf_infiniband_Trap_DataValid = -1;
static int hf_infiniband_Trap_PKEY = -1;
static int hf_infiniband_Trap_SWLIDADDR = -1;

/* Infiniband Link */
static int hf_infiniband_link_op = -1;
static int hf_infiniband_link_fctbs = -1;
static int hf_infiniband_link_vl = -1;
static int hf_infiniband_link_fccl = -1;
static int hf_infiniband_link_lpcrc = -1;

/* Trap Type/Descriptions for dissection */
static const value_string Operand_Description[]= {
    { 0, " Normal Flow Control"},
    { 1, " Flow Control Init"},
    { 0, NULL}
};

/* Trap Type/Descriptions for dissection */
static const value_string Trap_Description[]= {
    { 64, " (Informational) <GIDADDR> is now in service"},
    { 65, " (Informational) <GIDADDR> is out of service"},
    { 66, " (Informational) New Multicast Group with multicast address <GIDADDR> is now created"},
    { 67, " (Informational) Multicast Group with multicast address <GIDADDR> is now deleted"},
    { 68, " (Informational) Paths indicated by <PATH_REC> and <COMP_MASK> are no longer valid"},
    { 69, " (Informational) Paths indicated by <PATH_REC> and <COMP_MASK> have been recomputed"},
    { 128, " (Urgent) Link State of at least one port of switch at <LIDADDR> has changed"},
    { 129, " (Urgent) Local Link Integrity threshold reached at <LIDADDR><PORTNO>"},
    { 130, " (Urgent) Excessive Buffer OVerrun threshold reached at <LIDADDR><PORTNO>"},
    { 131, " (Urgent) Flow Control Update watchdog timer expired at <LIDADDR><PORTNO>"},
    { 144, " (Informational) CapMask, NodeDesc, LinkWidthEnabled or LinkSpeedEnabled at <LIDADDR> has been modified"},
    { 145, " (Informational) SystemImageGUID at <LIDADDR> has been modified.  New value is <SYSTEMIMAGEGUID>"},
    { 256, " (Security) Bad M_Key, <M_KEY> from <LIDADDR> attempted <METHOD> with <ATTRIBUTEID> and <ATTRIBUTEMODIFIER>"},
    { 257, " (Security) Bad P_Key, <KEY> from <LIDADDR1><GIDADDR1><QP1> to <LIDADDR2><GIDADDR2><QP2> on <SL>"},
    { 258, " (Security) Bad Q_Key, <KEY> from <LIDADDR1><GIDADDR1><QP1> to <LIDADDR2><GIDADDR2><QP2> on <SL>"},
    { 259, " (Security) Bad P_Key, <KEY> from <LIDADDR1><GIDADDR1><QP1> to <LIDADDR2><GIDADDR2><QP2> on <SL> at switch <LIDADDR><PORTNO>"},
    { 0, NULL}
};




/* MAD Management Classes
* Classes from the Common MAD Header
*
*      Management Class Name        Class Description
* ------------------------------------------------------------------------------------------------------------ */
#define SUBN_LID_ROUTED 0x01        /* Subnet Management LID Route */
#define SUBN_DIRECTED_ROUTE 0x81    /* Subnet Management Directed Route */
#define SUBNADMN 0x03               /* Subnet Administration */
#define PERF 0x04                   /* Performance Management */
#define BM 0x05                     /* Baseboard Management (Tunneling of IB-ML commands through the IBA subnet) */
#define DEV_MGT 0x06                /* Device Management */
#define COM_MGT 0x07                /* Communications Management */
#define SNMP 0x08                   /* SNMP Tunneling (tunneling of the SNMP protocol through the IBA fabric) */
#define VENDOR_1_START 0x09         /* Start of first Vendor Specific Range */
#define VENDOR_1_END 0x0F           /* End of first Vendor Specific Range */
#define VENDOR_2_START 0x30         /* Start of second Vendor Specific Range */
#define VENDOR_2_END 0x4F           /* End of the second Vendor Specific Range */
#define APPLICATION_START 0x10      /* Start of Application Specific Range */
#define APPLICATION_END 0x2F        /* End of Application Specific Range */

/* Performance class Attributes */
#define ATTR_PORT_COUNTERS      0x0012
#define ATTR_PORT_COUNTERS_EXT  0x001D

/* ComMgt class Attributes*/
#define ATTR_CM_REQ             0x0010
#define ATTR_CM_REP             0x0013
#define ATTR_CM_RTU             0x0014
#define ATTR_CM_REJ             0x0012

/* Link Next Header Values */
#define IBA_GLOBAL 3
#define IBA_LOCAL  2
#define IP_NON_IBA 1
#define RAW        0

/* OpCodeValues
* Code Bits [7-5] Connection Type
*           [4-0] Message Type

* Reliable Connection (RC)
* [7-5] = 000 */
#define RC_SEND_FIRST                   0 /*0x00000000 */
#define RC_SEND_MIDDLE                  1 /*0x00000001 */
#define RC_SEND_LAST                    2 /*0x00000010 */
#define RC_SEND_LAST_IMM                3 /*0x00000011 */
#define RC_SEND_ONLY                    4 /*0x00000100 */
#define RC_SEND_ONLY_IMM                5 /*0x00000101 */
#define RC_RDMA_WRITE_FIRST             6 /*0x00000110 */
#define RC_RDMA_WRITE_MIDDLE            7 /*0x00000111 */
#define RC_RDMA_WRITE_LAST              8 /*0x00001000 */
#define RC_RDMA_WRITE_LAST_IMM          9 /*0x00001001 */
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

/* Reliable Datagram (RD)
* [7-5] = 010 */
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

/* Unreliable Datagram (UD)
* [7-5] = 011 */
#define UD_SEND_ONLY                    100 /*0x01100100 */
#define UD_SEND_ONLY_IMM                101 /*0x01100101 */

/* Unreliable Connection (UC)
* [7-5] = 001 */
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

static const value_string OpCodeMap[] =
{
    { RC_SEND_FIRST, "RC Send First " },
    { RC_SEND_MIDDLE, "RC Send Middle "},
    { RC_SEND_LAST, "RC Send Last " },
    { RC_SEND_LAST_IMM, "RC Send Last Immediate "},
    { RC_SEND_ONLY, "RC Send Only "},
    { RC_SEND_ONLY_IMM, "RC Send Only Immediate "},
    { RC_RDMA_WRITE_FIRST, "RC RDMA Write First " },
    { RC_RDMA_WRITE_MIDDLE, "RC RDMA Write Middle "},
    { RC_RDMA_WRITE_LAST, "RC RDMA Write Last "},
    { RC_RDMA_WRITE_LAST_IMM, "RC RDMA Write Last Immediate " },
    { RC_RDMA_WRITE_ONLY, "RC RDMA Write Only " },
    { RC_RDMA_WRITE_ONLY_IMM, "RC RDMA Write Only Immediate "},
    { RC_RDMA_READ_REQUEST,  "RC RDMA Read Request " },
    { RC_RDMA_READ_RESPONSE_FIRST, "RC RDMA Read Response First " },
    { RC_RDMA_READ_RESPONSE_MIDDLE, "RC RDMA Read Response Middle "},
    { RC_RDMA_READ_RESPONSE_LAST, "RC RDMA Read Response Last " },
    { RC_RDMA_READ_RESPONSE_ONLY, "RC RDMA Read Response Only "},
    { RC_ACKNOWLEDGE, "RC Acknowledge " },
    { RC_ATOMIC_ACKNOWLEDGE, "RC Atomic Acknowledge " },
    { RC_CMP_SWAP, "RC Compare Swap " },
    { RC_FETCH_ADD, "RC Fetch Add "},
    { RC_SEND_LAST_INVAL, "RC Send Last Invalidate "},
    { RC_SEND_ONLY_INVAL, "RC Send Only Invalidate " },


    { RD_SEND_FIRST, "RD Send First "},
    { RD_SEND_MIDDLE,"RD Send Middle " },
    { RD_SEND_LAST, "RD Send Last "},
    { RD_SEND_LAST_IMM, "RD Last Immediate " },
    { RD_SEND_ONLY,"RD Send Only "},
    { RD_SEND_ONLY_IMM,"RD Send Only Immediate "},
    { RD_RDMA_WRITE_FIRST,"RD RDMA Write First "},
    { RD_RDMA_WRITE_MIDDLE, "RD RDMA Write Middle "},
    { RD_RDMA_WRITE_LAST,"RD RDMA Write Last "},
    { RD_RDMA_WRITE_LAST_IMM,"RD RDMA Write Last Immediate "},
    { RD_RDMA_WRITE_ONLY,"RD RDMA Write Only "},
    { RD_RDMA_WRITE_ONLY_IMM,"RD RDMA Write Only Immediate "},
    { RD_RDMA_READ_REQUEST,"RD RDMA Read Request "},
    { RD_RDMA_READ_RESPONSE_FIRST,"RD RDMA Read Response First "},
    { RD_RDMA_READ_RESPONSE_MIDDLE,"RD RDMA Read Response Middle "},
    { RD_RDMA_READ_RESPONSE_LAST,"RD RDMA Read Response Last "},
    { RD_RDMA_READ_RESPONSE_ONLY,"RD RDMA Read Response Only "},
    { RD_ACKNOWLEDGE,"RD Acknowledge "},
    { RD_ATOMIC_ACKNOWLEDGE,"RD Atomic Acknowledge "},
    { RD_CMP_SWAP,"RD Compare Swap "},
    { RD_FETCH_ADD, "RD Fetch Add "},
    { RD_RESYNC,"RD RESYNC "},


    { UD_SEND_ONLY, "UD Send Only "},
    { UD_SEND_ONLY_IMM, "UD Send Only Immediate "},


    { UC_SEND_FIRST,"UC Send First "},
    { UC_SEND_MIDDLE,"UC Send Middle "},
    { UC_SEND_LAST,"UC Send Last "},
    { UC_SEND_LAST_IMM,"UC Send Last Immediate "},
    { UC_SEND_ONLY,"UC Send Only "},
    { UC_SEND_ONLY_IMM,"UC Send Only Immediate "},
    { UC_RDMA_WRITE_FIRST,"UC RDMA Write First"},
    { UC_RDMA_WRITE_MIDDLE,"Unreliable Connection RDMA Write Middle "},
    { UC_RDMA_WRITE_LAST,"UC RDMA Write Last "},
    { UC_RDMA_WRITE_LAST_IMM,"UC RDMA Write Last Immediate "},
    { UC_RDMA_WRITE_ONLY,"UC RDMA Write Only "},
    { UC_RDMA_WRITE_ONLY_IMM,"UC RDMA Write Only Immediate "},
    { 0, NULL}

};



/* Header Ordering Based on OPCODES
* These are simply an enumeration of the possible header combinations defined by the IB Spec.
* These enumerations
* #DEFINE [HEADER_ORDER]         [ENUM]
* __________________________________ */
#define RDETH_DETH_PAYLD            0
/* __________________________________ */
#define RDETH_DETH_RETH_PAYLD       1
/* __________________________________ */
#define RDETH_DETH_IMMDT_PAYLD      2
/* __________________________________ */
#define RDETH_DETH_RETH_IMMDT_PAYLD 3
/* __________________________________ */
#define RDETH_DETH_RETH             4
/* __________________________________ */
#define RDETH_AETH_PAYLD            5
/* __________________________________ */
#define RDETH_PAYLD                 6
/* __________________________________ */
#define RDETH_AETH                  7
/* __________________________________ */
#define RDETH_AETH_ATOMICACKETH     8
/* __________________________________ */
#define RDETH_DETH_ATOMICETH        9
/* ___________________________________ */
#define RDETH_DETH                  10
/* ___________________________________ */
#define DETH_PAYLD                  11
/* ___________________________________ */
#define DETH_IMMDT_PAYLD            12
/* ___________________________________ */
#define PAYLD                       13
/* ___________________________________ */
#define IMMDT_PAYLD                 14
/* ___________________________________ */
#define RETH_PAYLD                  15
/* ___________________________________ */
#define RETH_IMMDT_PAYLD            16
/* ___________________________________ */
#define RETH                        17
/* ___________________________________ */
#define AETH_PAYLD                  18
/* ___________________________________ */
#define AETH                        19
/* ___________________________________ */
#define AETH_ATOMICACKETH           20
/* ___________________________________ */
#define ATOMICETH                   21
/* ___________________________________ */
#define IETH_PAYLD                  22
/* ___________________________________ */


/* Infiniband transport services
   These are an enumeration of the transport services over which an IB packet
   might be sent. The values match the corresponding 3 bits of the opCode field
   in the BTH  */
#define TRANSPORT_RC    0
#define TRANSPORT_UC    1
#define TRANSPORT_RD    2
#define TRANSPORT_UD    3


/* Array of all availavle OpCodes to make matching a bit easier.
* The OpCodes dictate the header sequence following in the packet.
* These arrays tell the dissector which headers must be decoded for the given OpCode. */
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

/* It is not necessary to create arrays for these OpCodes since they indicate only one further header.
*  We can just decode it directly

* static guint32 opCode_DETH_IMMDT_PAYLD[] = {
* UD_SEND_ONLY_IMM
* };
* static guint32 opCode_DETH_PAYLD[] = {
* UD_SEND_ONLY
* };
* static guint32 opCode_RDETH_DETH[] = {
* RD_RESYNC
* };
* static guint32 opCode_RDETH_DETH_RETH[] = {
* RD_RDMA_READ_REQUEST
* };
* static guint32 opCode_RDETH_DETH_RETH_IMMDT_PAYLD[] = {
* RD_RDMA_WRITE_ONLY_IMM
* };
* static guint32 opCode_RDETH_AETH_ATOMICACKETH[] = {
* RD_ATOMIC_ACKNOWLEDGE
* };
* static guint32 opCode_RDETH_AETH[] = {
* RD_ACKNOWLEDGE
* };
* static guint32 opCode_RDETH_PAYLD[] = {
* RD_RDMA_READ_RESPONSE_MIDDLE
* };
* static guint32 opCode_AETH_ATOMICACKETH[] = {
* RC_ATOMIC_ACKNOWLEDGE
* };
* static guint32 opCode_RETH[] = {
* RC_RDMA_READ_REQUEST
* };
* static guint32 opCode_AETH[] = {
* RC_ACKNOWLEDGE
* }; */

static void *src_addr = NULL,     /* the address to be displayed in the source/destination columns */
            *dst_addr = NULL;     /* (lid/gid number) will be stored here */

#define ADDR_MAX_LEN  sizeof("IPv6 over IB Packet")      /* maximum length of src_addr and dst_addr is for IPoIB
                                                            where we print an explanation string */

static gint8 transport_type = -1;      /* reflects the transport type of the packet being parsed.
                                          only use one of the TRANSPORT_* values for this field */

/* settings to be set by the user via the preferences dialog */
static gboolean pref_dissect_eoib = TRUE;
static gboolean pref_identify_iba_payload = TRUE;

/* saves information about connections that have been/are in the process of being
   negotiated via ConnectionManagement packets */
typedef struct {
    guint8 req_gid[GID_SIZE],
           resp_gid[GID_SIZE];  /* GID of requester/responder, respectively */
    guint16 req_lid,
            resp_lid;   /* LID of requester/responder, respectively */
    guint32 req_qp,
            resp_qp;            /* QP number of requester/responder, respectively */
    guint64 service_id;         /* service id for this connection */
} connection_context;

/* holds a table of connection contexts being negotiated by CM. the key is a obtained
   using ADD_ADDRESS_TO_HASH(initiator address, TransactionID) [remember that the 1st
   argument to ADD_ADDRESS_TO_HASH must be an lvalue. */
static GHashTable *CM_context_table = NULL;

/* heuristics sub-dissectors list for dissecting the data payload of IB packets */
static heur_dissector_list_t heur_dissectors_payload;
/* heuristics sub-dissectors list for dissecting the PrivateData of CM packets */
static heur_dissector_list_t heur_dissectors_cm_private;

/* ----- This sections contains various utility functions indirectly related to Infiniband dissection ---- */

/* g_int64_hash, g_int64_equal are defined starting glib 2.22 - otherwise, we'll have to
   provide them ourselves! */
#if !GLIB_CHECK_VERSION(2,22,0)
guint
g_int64_hash (gconstpointer v)
{
  return (guint) *(const gint64*) v;
}

gboolean
g_int64_equal (gconstpointer v1,
               gconstpointer v2)
{
  return *((const gint64*) v1) == *((const gint64*) v2);
}
#endif

void table_destroy_notify(gpointer data) {
    g_free(data);
}

/* --------------------------------------------------------------------------------------------------------*/

/* Helper dissector for correctly dissecting RoCE packets (encapsulated within an Ethernet */
/* frame). The only difference from regular IB packets is that RoCE packets do not contain */
/* a LRH, and always start with a GRH.                                                      */
static void
dissect_roce(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* this is a RoCE packet, so signal the IB dissector not to look for LRH */
    dissect_infiniband_common(tvb, pinfo, tree, TRUE);
}

static void
dissect_infiniband(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_infiniband_common(tvb, pinfo, tree, FALSE);
}

/* Common Dissector for both InfiniBand and RoCE packets
 * IN:
 *       tvb - The tvbbuff of packet data
 *       pinfo - The packet info structure with column information
 *       tree - The tree structure under which field nodes are to be added
 *       starts_with_grh - If true this packets start with a GRH header (RoCE), otherwise with LRH as usual
 * Notes:
 * 1.) Floating "offset+=" statements should probably be "functionized" but they are inline
 * Offset is only passed by reference in specific places, so do not be confused when following code
 * In any code path, adding up "offset+=" statements will tell you what byte you are at */
static void
dissect_infiniband_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean starts_with_grh)
{
    /* Top Level Item */
    proto_item *infiniband_packet = NULL;

    /* The Headers Subtree */
    proto_tree *all_headers_tree = NULL;

    /* LRH - Local Route Header */
    proto_tree *local_route_header_tree = NULL;
    proto_item *local_route_header_item = NULL;

    /* GRH - Global Route Header */
    proto_tree *global_route_header_tree = NULL;
    proto_item *global_route_header_item = NULL;

    /* BTH - Base Transport header */
    proto_tree *base_transport_header_tree = NULL;
    proto_item *base_transport_header_item = NULL;

    /* Raw Data */
    proto_item *RAWDATA_header_item;
    guint8 lnh_val = 0;             /* Link Next Header Value */
    gint offset = 0;                /* Current Offset */

    /* General Variables */
    gboolean bthFollows = FALSE;    /* Tracks if we are parsing a BTH.  This is a significant decision point */
    guint8 virtualLane = 0;         /* IB VirtualLane.  Keyed off of for detecting subnet admin/management */
    guint8 opCode = 0;              /* OpCode from BTH header. */
    gint32 nextHeaderSequence = -1; /* defined by this dissector. #define which indicates the upcoming header sequence from OpCode */
    guint8 nxtHdr = 0;              /* Keyed off for header dissection order */
    guint16 packetLength = 0;       /* Packet Length.  We track this as tvb_length - offset.   */
                                    /*  It provides the parsing methods a known size            */
                                    /*   that must be available for that header.                */
    struct e_in6_addr SRCgid;       /* Structures to hold GIDs should we need them */
    struct e_in6_addr DSTgid;
    gint crc_length = 0;

    /* allocate space for source/destination addresses. we will fill them in later */
    src_addr = ep_alloc(ADDR_MAX_LEN);
    dst_addr = ep_alloc(ADDR_MAX_LEN);

    pinfo->srcport = pinfo->destport = 0xffffffff;  /* set the src/dest QPN to something impossible instead of the default 0,
                                                       so we don't mistake it for a MAD. (QP is only 24bit, so can't be 0xffffffff)*/

    /* add any code that should only run the first time the packet is dissected here: */
    if (!pinfo->fd->flags.visited)
    {
        pinfo->ptype = PT_IBQP;     /* set the port-type for this packet to be Infiniband QP number */
    }

    /* Mark the Packet type as Infiniband in the wireshark UI */
    /* Clear other columns */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "InfiniBand");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Get the parent tree from the ERF dissector.  We don't want to nest under ERF */
    if(tree && tree->parent)
    {
        /* Set the normal tree outside of ERF */
        tree = tree->parent;
        /* Set a global reference for nested protocols */
        top_tree = tree;
    }

    /* The "quick-dissection" code in dissect_general_info skips lots of the recently-added code
       for saving context etc. It is no longer viable to maintain two code branches, so we have
       (temporarily?) disabled the second one. All dissection now goes through the full branch,
       using a NULL tree pointer if this is not a full dissection call. Take care not to dereference
       the tree pointer or any subtree pointers you create using it and you'll be fine. */
    if(0 && !tree)
    {
        /* If no packet details are being dissected, extract some high level info for the packet view */
        /* Assigns column values rather than full tree population */
        dissect_general_info(tvb, offset, pinfo, starts_with_grh);
        return;
    }

    /* Top Level Packet */
    infiniband_packet = proto_tree_add_item(tree, proto_infiniband, tvb, offset, -1, FALSE);

    /* Headers Level Tree */
    all_headers_tree = proto_item_add_subtree(infiniband_packet, ett_all_headers);

    if (starts_with_grh) {
        /* this is a RoCE packet, skip LRH parsing */
        lnh_val = IBA_GLOBAL;
        packetLength = tvb_get_ntohs(tvb, 4);   /* since we have no LRH to get PktLen from, use that of the GRH */
        goto skip_lrh;
    }

    /* Local Route Header Subtree */
    local_route_header_item = proto_tree_add_item(all_headers_tree, hf_infiniband_LRH, tvb, offset, 8, ENC_NA);
    proto_item_set_text(local_route_header_item, "%s", "Local Route Header");
    local_route_header_tree = proto_item_add_subtree(local_route_header_item, ett_lrh);

    proto_tree_add_item(local_route_header_tree, hf_infiniband_virtual_lane,            tvb, offset, 1, FALSE);


    /* Get the Virtual Lane.  We'll use this to identify Subnet Management and Subnet Administration Packets. */
    virtualLane =  tvb_get_guint8(tvb, offset);
    virtualLane = virtualLane & 0xF0;


    proto_tree_add_item(local_route_header_tree, hf_infiniband_link_version,            tvb, offset, 1, FALSE); offset+=1;
    proto_tree_add_item(local_route_header_tree, hf_infiniband_service_level,           tvb, offset, 1, FALSE);

    proto_tree_add_item(local_route_header_tree, hf_infiniband_reserved2,               tvb, offset, 1, FALSE);
    proto_tree_add_item(local_route_header_tree, hf_infiniband_link_next_header,        tvb, offset, 1, FALSE);


    /* Save Link Next Header... This tells us what the next header is. */
    lnh_val =  tvb_get_guint8(tvb, offset);
    lnh_val = lnh_val & 0x03;
    offset+=1;


    proto_tree_add_item(local_route_header_tree, hf_infiniband_destination_local_id,    tvb, offset, 2, FALSE);


    /* Set destination in packet view. */
    *((guint16*) dst_addr) = tvb_get_ntohs(tvb, offset);
    SET_ADDRESS(&pinfo->dst, AT_IB, sizeof(guint16), dst_addr);

    offset+=2;

    proto_tree_add_item(local_route_header_tree, hf_infiniband_reserved5,               tvb, offset, 2, FALSE);

    packetLength = tvb_get_ntohs(tvb, offset); /* Get the Packet Length. This will determine payload size later on. */
    packetLength = packetLength & 0x07FF;      /* Mask off top 5 bits, they are reserved */
    packetLength = packetLength * 4;           /* Multiply by 4 to get true byte length. This is by specification.  */
                                               /*   PktLen is size in 4 byte words (byteSize /4). */

    proto_tree_add_item(local_route_header_tree, hf_infiniband_packet_length,           tvb, offset, 2, FALSE); offset+=2;
    proto_tree_add_item(local_route_header_tree, hf_infiniband_source_local_id,         tvb, offset, 2, FALSE);

    /* Set Source in packet view. */
    *((guint16*) src_addr) = tvb_get_ntohs(tvb, offset);
    SET_ADDRESS(&pinfo->src, AT_IB, sizeof(guint16), src_addr);

    offset+=2;
    packetLength -= 8; /* Shave 8 bytes for the LRH. */

skip_lrh:

    /* Key off Link Next Header.  This tells us what High Level Data Format we have */
    switch(lnh_val)
    {
        case IBA_GLOBAL:
            global_route_header_item = proto_tree_add_item(all_headers_tree, hf_infiniband_GRH, tvb, offset, 40, ENC_NA);
            proto_item_set_text(global_route_header_item, "%s", "Global Route Header");
            global_route_header_tree = proto_item_add_subtree(global_route_header_item, ett_grh);

            proto_tree_add_item(global_route_header_tree, hf_infiniband_ip_version,         tvb, offset, 1, FALSE);
            proto_tree_add_item(global_route_header_tree, hf_infiniband_traffic_class,      tvb, offset, 2, FALSE);
            proto_tree_add_item(global_route_header_tree, hf_infiniband_flow_label,         tvb, offset, 4, FALSE); offset += 4;

            proto_tree_add_item(global_route_header_tree, hf_infiniband_payload_length,     tvb, offset, 2, FALSE); offset += 2;

            nxtHdr = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(global_route_header_tree, hf_infiniband_next_header,        tvb, offset, 1, FALSE); offset +=1;
            proto_tree_add_item(global_route_header_tree, hf_infiniband_hop_limit,          tvb, offset, 1, FALSE); offset +=1;
            proto_tree_add_item(global_route_header_tree, hf_infiniband_source_gid,         tvb, offset, 16, FALSE);

            tvb_get_ipv6(tvb, offset, &SRCgid);

            /* set source GID in packet view*/
            memcpy(src_addr, &SRCgid, GID_SIZE);
            SET_ADDRESS(&pinfo->src, AT_IB, GID_SIZE, src_addr);

            offset += 16;

            proto_tree_add_item(global_route_header_tree, hf_infiniband_destination_gid,    tvb, offset, 16, FALSE);

            tvb_get_ipv6(tvb, offset, &DSTgid);

            /* set destination GID in packet view*/
            memcpy(dst_addr, &DSTgid, GID_SIZE);
            SET_ADDRESS(&pinfo->dst, AT_IB, GID_SIZE, dst_addr);

            offset += 16;
            packetLength -= 40; /* Shave 40 bytes for GRH */

            if(nxtHdr != 0x1B)
            {
                /* Some kind of packet being transported globally with IBA, but locally it is not IBA - no BTH following. */
                break;
            }
            /* otherwise fall through and start parsing BTH */
        case IBA_LOCAL:
            bthFollows = TRUE;
            base_transport_header_item = proto_tree_add_item(all_headers_tree, hf_infiniband_BTH, tvb, offset, 12, ENC_NA);
            proto_item_set_text(base_transport_header_item, "%s", "Base Transport Header");
            base_transport_header_tree = proto_item_add_subtree(base_transport_header_item, ett_bth);
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_opcode,                       tvb, offset, 1, FALSE);

            /* Get the OpCode - this tells us what headers are following */
            opCode = tvb_get_guint8(tvb, offset);
            col_append_str(pinfo->cinfo, COL_INFO, val_to_str((guint32)opCode, OpCodeMap, "Unknown OpCode"));
            offset +=1;

            proto_tree_add_item(base_transport_header_tree, hf_infiniband_solicited_event,              tvb, offset, 1, FALSE);
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_migreq,                       tvb, offset, 1, FALSE);
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_pad_count,                    tvb, offset, 1, FALSE);
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_transport_header_version,     tvb, offset, 1, FALSE); offset +=1;
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_partition_key,                tvb, offset, 2, FALSE); offset +=2;
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_reserved8,                    tvb, offset, 1, FALSE); offset +=1;
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_destination_qp,               tvb, offset, 3, FALSE);
            pinfo->destport = tvb_get_ntoh24(tvb, offset); offset +=3;
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_acknowledge_request,          tvb, offset, 1, FALSE);
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_reserved7,                    tvb, offset, 1, FALSE); offset +=1;
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_packet_sequence_number,       tvb, offset, 3, FALSE); offset +=3;


            packetLength -= 12; /* Shave 12 for Base Transport Header */

        break;
        case IP_NON_IBA:
            /* Raw IPv6 Packet */
            g_snprintf(dst_addr,  ADDR_MAX_LEN, "IPv6 over IB Packet");
            SET_ADDRESS(&pinfo->dst,  AT_STRINGZ, (int)strlen(dst_addr)+1, dst_addr);

            parse_IPvSix(all_headers_tree, tvb, &offset, pinfo);
            break;
        case RAW:
            parse_RWH(all_headers_tree, tvb, &offset, pinfo);
            break;
        default:
            /* Unknown Packet */
            RAWDATA_header_item = proto_tree_add_item(all_headers_tree, hf_infiniband_raw_data, tvb, offset, -1, ENC_NA);
            proto_item_set_text(RAWDATA_header_item, "%s", "Unknown Raw Data - IB Encapsulated");
            break;
    }

    /* Base Transport header is hit quite often, however it is alone since it is the exception not the rule */
    /* Only IBA Local packets use it */
    if(bthFollows)
    {
        /* Find our next header sequence based on the Opcode
        * Each case decrements the packetLength by the amount of bytes consumed by each header.
        * The find_next_header_sequence method could be used to automate this.
        * We need to keep track of this so we know much data to mark as payload/ICRC/VCRC values. */

        transport_type = (opCode & 0xE0) >> 5;   /* save transport type for identifying EoIB payloads later... */
        nextHeaderSequence = find_next_header_sequence((guint32) opCode);

        /* find_next_header_sequence gives us the DEFINE value corresponding to the header order following */
        /* Enumerations are named intuitively, e.g. RDETH DETH PAYLOAD means there is an RDETH Header, DETH Header, and a packet payload */
        switch(nextHeaderSequence)
        {
            case RDETH_DETH_PAYLD:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RDETH_DETH_RETH_PAYLD:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);
                parse_RETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */
                packetLength -= 16; /* RETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RDETH_DETH_IMMDT_PAYLD:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);
                parse_IMMDT(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */
                packetLength -= 4; /* IMMDT */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RDETH_DETH_RETH_IMMDT_PAYLD:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);
                parse_RETH(all_headers_tree, tvb, &offset);
                parse_IMMDT(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */
                packetLength -= 16; /* RETH */
                packetLength -= 4; /* IMMDT */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RDETH_DETH_RETH:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);
                parse_RETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */
                packetLength -= 16; /* RETH */

                break;
            case RDETH_AETH_PAYLD:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_AETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 4; /* AETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RDETH_PAYLD:
                parse_RDETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RDETH_AETH:
                parse_AETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 4; /* AETH */


                break;
            case RDETH_AETH_ATOMICACKETH:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_AETH(all_headers_tree, tvb, &offset);
                parse_ATOMICACKETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 4; /* AETH */
                packetLength -= 8; /* AtomicAckETH */


                break;
            case RDETH_DETH_ATOMICETH:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);
                parse_ATOMICETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */
                packetLength -= 28; /* AtomicETH */

                break;
            case RDETH_DETH:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */

                break;
            case DETH_PAYLD:
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);

                packetLength -= 8; /* DETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case PAYLD:

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case IMMDT_PAYLD:
                parse_IMMDT(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* IMMDT */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RETH_PAYLD:
                parse_RETH(all_headers_tree, tvb, &offset);

                packetLength -= 16; /* RETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RETH:
                parse_RETH(all_headers_tree, tvb, &offset);

                packetLength -= 16; /* RETH */

                break;
            case AETH_PAYLD:
                parse_AETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* AETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case AETH:
                parse_AETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* AETH */

                break;
            case AETH_ATOMICACKETH:
                parse_AETH(all_headers_tree, tvb, &offset);
                parse_ATOMICACKETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* AETH */
                packetLength -= 8; /* AtomicAckETH */

                break;
            case ATOMICETH:
                parse_ATOMICETH(all_headers_tree, tvb, &offset);

                packetLength -= 28; /* AtomicETH */

                break;
            case IETH_PAYLD:
                parse_IETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* IETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case DETH_IMMDT_PAYLD:
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);
                parse_IMMDT(all_headers_tree, tvb, &offset);

                packetLength -= 8; /* DETH */
                packetLength -= 4; /* IMMDT */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            default:
                parse_VENDOR(all_headers_tree, tvb, &offset);
                break;

        }

    }
    /* Display the ICRC/VCRC */
    /* Doing it this way rather than in a variety of places according to the specific packet */
    /* If we've already displayed it crc_length comes out 0 */
    crc_length = tvb_reported_length_remaining(tvb, offset);
    if(crc_length == 6)
    {
        proto_tree_add_item(all_headers_tree, hf_infiniband_invariant_crc, tvb, offset, 4, FALSE); offset +=4;
        proto_tree_add_item(all_headers_tree, hf_infiniband_variant_crc,   tvb, offset, 2, FALSE); offset+=2;
    }
    else if(crc_length == 4)
    {
        proto_tree_add_item(all_headers_tree, hf_infiniband_invariant_crc, tvb, offset, 4, FALSE); offset +=4;
    }
    else if(crc_length == 2)
    {
        proto_tree_add_item(all_headers_tree, hf_infiniband_variant_crc,   tvb, offset, 2, FALSE); offset+=2;
    }

}

static void
dissect_infiniband_link(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Top Level Item */
    proto_item *infiniband_link_packet = NULL;

    /* The Link Subtree */
    proto_tree *link_tree = NULL;

    proto_item *operand_item = NULL;
    gint offset = 0;                /* Current Offset */
    guint8 operand;                 /* Link packet Operand */

    operand =  tvb_get_guint8(tvb, offset);
    operand = (operand & 0xF0) >> 4;

    /* Mark the Packet type as Infiniband in the wireshark UI */
    /* Clear other columns */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "InfiniBand Link");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
             val_to_str(operand, Operand_Description, "Unknown (0x%1x)"));

    /* Get the parent tree from the ERF dissector.  We don't want to nest under ERF */
    if(tree && tree->parent)
    {
        /* Set the normal tree outside of ERF */
        tree = tree->parent;
        /* Set a global reference for nested protocols */
        top_tree = tree;
    }

    if(!tree)
    {
        /* If no packet details are being dissected, extract some high level info for the packet view */
        /* Assigns column values rather than full tree population */
        dissect_general_info(tvb, offset, pinfo, FALSE);
        return;
    }

    /* Top Level Packet */
    infiniband_link_packet = proto_tree_add_item(tree, proto_infiniband_link, tvb, offset, -1, FALSE);

    /* Headers Level Tree */
    link_tree = proto_item_add_subtree(infiniband_link_packet, ett_link);

    operand_item = proto_tree_add_item(link_tree, hf_infiniband_link_op, tvb, offset, 2, FALSE);

    if (operand > 1) {
        proto_item_set_text(operand_item, "%s", "Reserved");
        call_dissector(data_handle, tvb, pinfo, link_tree);
    } else {
        proto_tree_add_item(link_tree, hf_infiniband_link_fctbs, tvb, offset, 2, FALSE);
        offset += 2;

        proto_tree_add_item(link_tree, hf_infiniband_link_vl, tvb, offset, 2, FALSE);
        proto_tree_add_item(link_tree, hf_infiniband_link_fccl, tvb, offset, 2, FALSE);
        offset += 2;

        proto_tree_add_item(link_tree, hf_infiniband_link_lpcrc, tvb, offset, 2, FALSE);
        offset += 2;
    }

}


/* Description: Finds the header sequence that follows the Base Transport Header.
* Somwhat inefficient (should be using a single key,value pair data structure)
* But uses pure probablity to take a stab at better efficiency.
* Searches largest header sequence groups first, and then finally resorts to single matches for unique header sequences
* IN: OpCode: The OpCode from the Base Transport Header.
* OUT: The Header Sequence enumeration.  See Declarations for #defines from (0-22) */
static gint32
find_next_header_sequence(guint32 OpCode)
{
    if(contains(OpCode, &opCode_PAYLD[0], (gint32)sizeof(opCode_PAYLD)))
        return PAYLD;

    if(contains(OpCode, &opCode_IMMDT_PAYLD[0], (gint32)sizeof(opCode_IMMDT_PAYLD)))
        return IMMDT_PAYLD;

    if(contains(OpCode, &opCode_RDETH_DETH_PAYLD[0], (gint32)sizeof(opCode_RDETH_DETH_PAYLD)))
        return RDETH_DETH_PAYLD;

    if(contains(OpCode, &opCode_RETH_PAYLD[0], (gint32)sizeof(opCode_RETH_PAYLD)))
        return RETH_PAYLD;

    if(contains(OpCode, &opCode_RDETH_AETH_PAYLD[0], (gint32)sizeof(opCode_RDETH_AETH_PAYLD)))
        return RDETH_AETH_PAYLD;

    if(contains(OpCode, &opCode_AETH_PAYLD[0], (gint32)sizeof(opCode_AETH_PAYLD)))
        return AETH_PAYLD;

    if(contains(OpCode, &opCode_RDETH_DETH_IMMDT_PAYLD[0], (gint32)sizeof(opCode_RDETH_DETH_IMMDT_PAYLD)))
        return RDETH_DETH_IMMDT_PAYLD;

    if(contains(OpCode, &opCode_RETH_IMMDT_PAYLD[0], (gint32)sizeof(opCode_RETH_IMMDT_PAYLD)))
        return RETH_IMMDT_PAYLD;

    if(contains(OpCode, &opCode_RDETH_DETH_RETH_PAYLD[0], (gint32)sizeof(opCode_RDETH_DETH_RETH_PAYLD)))
        return RDETH_DETH_RETH_PAYLD;

    if(contains(OpCode, &opCode_ATOMICETH[0], (gint32)sizeof(opCode_ATOMICETH)))
        return ATOMICETH;

    if(contains(OpCode, &opCode_IETH_PAYLD[0], (gint32)sizeof(opCode_IETH_PAYLD)))
        return IETH_PAYLD;

    if(contains(OpCode, &opCode_RDETH_DETH_ATOMICETH[0], (gint32)sizeof(opCode_RDETH_DETH_ATOMICETH)))
        return RDETH_DETH_ATOMICETH;

    if((OpCode ^ RC_ACKNOWLEDGE) == 0)
        return AETH;

    if((OpCode ^ RC_RDMA_READ_REQUEST) == 0)
        return RETH;

    if((OpCode ^ RC_ATOMIC_ACKNOWLEDGE) == 0)
        return AETH_ATOMICACKETH;

    if((OpCode ^ RD_RDMA_READ_RESPONSE_MIDDLE) == 0)
        return RDETH_PAYLD;

    if((OpCode ^ RD_ACKNOWLEDGE) == 0)
        return RDETH_AETH;

    if((OpCode ^ RD_ATOMIC_ACKNOWLEDGE) == 0)
        return RDETH_AETH_ATOMICACKETH;

    if((OpCode ^ RD_RDMA_WRITE_ONLY_IMM) == 0)
        return RDETH_DETH_RETH_IMMDT_PAYLD;

    if((OpCode ^ RD_RDMA_READ_REQUEST) == 0)
        return RDETH_DETH_RETH;

    if((OpCode ^ RD_RESYNC) == 0)
        return RDETH_DETH;

    if((OpCode ^ UD_SEND_ONLY) == 0)
        return DETH_PAYLD;

    if((OpCode ^ UD_SEND_ONLY_IMM) == 0)
        return DETH_IMMDT_PAYLD;

    return -1;
}

/* Description: Finds if a given value is present in an array. This is probably in a standard library somewhere,
* But I'd rather define my own.
* IN: OpCode: The OpCode you are looking for
* IN: Codes: The organized array of OpCodes to look through
* IN: Array length, because we're in C++...
* OUT: Boolean indicating if that OpCode was found in OpCodes */
static gboolean
contains(guint32 OpCode, guint32* Codes, gint32 length)
{
    gint32 i;
    for(i = 0; i < length; i++)
    {
        if((OpCode ^ Codes[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

/* Parse RDETH - Reliable Datagram Extended Transport Header
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void
parse_RDETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
    gint local_offset = *offset;
    /* RDETH - Reliable Datagram Extended Transport Header */
    proto_tree *RDETH_header_tree = NULL;
    proto_item *RDETH_header_item = NULL;

    RDETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_RDETH, tvb, local_offset, 4, ENC_NA);
    proto_item_set_text(RDETH_header_item, "%s", "RDETH - Reliable Datagram Extended Transport Header");
    RDETH_header_tree = proto_item_add_subtree(RDETH_header_item, ett_rdeth);

    proto_tree_add_item(RDETH_header_tree, hf_infiniband_reserved8_RDETH,   tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(RDETH_header_tree, hf_infiniband_ee_context,        tvb, local_offset, 3, FALSE); local_offset+=3;
    *offset = local_offset;
}

/* Parse DETH - Datagram Extended Transport Header
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset  */
static void
parse_DETH(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, gint *offset)
{
    gint local_offset = *offset;
    /* DETH - Datagram Extended Transport Header */
    proto_tree *DETH_header_tree = NULL;
    proto_item *DETH_header_item = NULL;

    DETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_DETH, tvb, local_offset, 8, ENC_NA);
    proto_item_set_text(DETH_header_item, "%s", "DETH - Datagram Extended Transport Header");
    DETH_header_tree = proto_item_add_subtree(DETH_header_item, ett_deth);

    proto_tree_add_item(DETH_header_tree, hf_infiniband_queue_key,                  tvb, local_offset, 4, FALSE); local_offset+=4;
    proto_tree_add_item(DETH_header_tree, hf_infiniband_reserved8_DETH,             tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(DETH_header_tree, hf_infiniband_source_qp,                  tvb, local_offset, 3, FALSE);
    pinfo->srcport = tvb_get_ntoh24(tvb, local_offset); local_offset+=3;

    *offset = local_offset;
}

/* Parse RETH - RDMA Extended Transport Header
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void
parse_RETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
    gint local_offset = *offset;
    /* RETH - RDMA Extended Transport Header */
    proto_tree *RETH_header_tree = NULL;
    proto_item *RETH_header_item = NULL;

    RETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_RETH, tvb, local_offset, 16, ENC_NA);
    proto_item_set_text(RETH_header_item, "%s", "RETH - RDMA Extended Transport Header");
    RETH_header_tree = proto_item_add_subtree(RETH_header_item, ett_reth);

    proto_tree_add_item(RETH_header_tree, hf_infiniband_virtual_address,                tvb, local_offset, 8, FALSE); local_offset+=8;
    proto_tree_add_item(RETH_header_tree, hf_infiniband_remote_key,                     tvb, local_offset, 4, FALSE); local_offset+=4;
    proto_tree_add_item(RETH_header_tree, hf_infiniband_dma_length,                     tvb, local_offset, 4, FALSE); local_offset+=4;

    *offset = local_offset;
}

/* Parse AtomicETH - Atomic Extended Transport Header
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void
parse_ATOMICETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
    gint local_offset = *offset;
    /* AtomicETH - Atomic Extended Transport Header */
    proto_tree *ATOMICETH_header_tree = NULL;
    proto_item *ATOMICETH_header_item = NULL;

    ATOMICETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_AtomicETH, tvb, local_offset, 28, ENC_NA);
    proto_item_set_text(ATOMICETH_header_item, "%s", "AtomicETH - Atomic Extended Transport Header");
    ATOMICETH_header_tree = proto_item_add_subtree(ATOMICETH_header_item, ett_atomiceth);

    proto_tree_add_item(ATOMICETH_header_tree, hf_infiniband_virtual_address,               tvb, local_offset, 8, FALSE); local_offset+=8;
    proto_tree_add_item(ATOMICETH_header_tree, hf_infiniband_remote_key,                    tvb, local_offset, 4, FALSE); local_offset+=4;
    proto_tree_add_item(ATOMICETH_header_tree, hf_infiniband_swap_or_add_data,              tvb, local_offset, 8, FALSE); local_offset+=8;
    proto_tree_add_item(ATOMICETH_header_tree, hf_infiniband_compare_data,                  tvb, local_offset, 8, FALSE); local_offset+=8;
    *offset = local_offset;
}

/* Parse AETH - ACK Extended Transport Header
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void
parse_AETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
    gint local_offset = *offset;
    /* AETH - ACK Extended Transport Header */
    proto_tree *AETH_header_tree = NULL;
    proto_item *AETH_header_item = NULL;

    AETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_AETH, tvb, local_offset, 4, ENC_NA);
    proto_item_set_text(AETH_header_item, "%s", "AETH - ACK Extended Transport Header");
    AETH_header_tree = proto_item_add_subtree(AETH_header_item, ett_aeth);

    proto_tree_add_item(AETH_header_tree, hf_infiniband_syndrome,                       tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(AETH_header_tree, hf_infiniband_message_sequence_number,        tvb, local_offset, 3, FALSE); local_offset+=3;

    *offset = local_offset;
}

/* Parse AtomicAckEth - Atomic ACK Extended Transport Header
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void
parse_ATOMICACKETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
    gint local_offset = *offset;
    /* AtomicAckEth - Atomic ACK Extended Transport Header */
    proto_tree *ATOMICACKETH_header_tree = NULL;
    proto_item *ATOMICACKETH_header_item = NULL;

    ATOMICACKETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_AtomicAckETH, tvb, local_offset, 8, ENC_NA);
    proto_item_set_text(ATOMICACKETH_header_item, "%s", "ATOMICACKETH - Atomic ACK Extended Transport Header");
    ATOMICACKETH_header_tree = proto_item_add_subtree(ATOMICACKETH_header_item, ett_atomicacketh);
    proto_tree_add_item(ATOMICACKETH_header_tree, hf_infiniband_original_remote_data,   tvb, local_offset, 8, FALSE); local_offset+=8;
    *offset = local_offset;
}

/* Parse IMMDT - Immediate Data Extended Transport Header
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void
parse_IMMDT(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
    gint local_offset = *offset;
    /* IMMDT - Immediate Data Extended Transport Header */
    proto_tree *IMMDT_header_tree = NULL;
    proto_item *IMMDT_header_item = NULL;

    IMMDT_header_item = proto_tree_add_item(parentTree, hf_infiniband_IMMDT, tvb, local_offset, 4, ENC_NA);
    proto_item_set_text(IMMDT_header_item, "%s", "IMMDT - Immediate Data Extended Transport Header");
    IMMDT_header_tree = proto_item_add_subtree(IMMDT_header_item, ett_immdt);
    proto_tree_add_item(IMMDT_header_tree, hf_infiniband_IMMDT, tvb, local_offset, 4, ENC_NA); local_offset+=4;
    *offset = local_offset;
}

/* Parse IETH - Invalidate Extended Transport Header
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void
parse_IETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
    gint local_offset = *offset;
    /* IETH - Invalidate Extended Transport Header */
    proto_tree *IETH_header_tree = NULL;
    proto_item *IETH_header_item = NULL;

    IETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_IETH, tvb, local_offset, 4, ENC_NA);
    proto_item_set_text(IETH_header_item, "%s", "IETH - Invalidate Extended Transport Header");
    IETH_header_tree = proto_item_add_subtree(IETH_header_item, ett_ieth);

    proto_tree_add_item(IETH_header_tree, hf_infiniband_IETH,   tvb, local_offset, 4, ENC_NA); local_offset+=4;

    *offset = local_offset;
}

/* Parse Payload - Packet Payload / Invariant CRC / Variant CRC
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: pinfo - packet info from wireshark
* IN: tvb - the data buffer from wireshark
* IN/OUT: offset - The current and updated offset
* IN: length - Length of Payload */
static void parse_PAYLOAD(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, gint *offset, gint length)
{
    gint local_offset = *offset;
    /* Payload - Packet Payload */
    proto_tree *PAYLOAD_header_tree = NULL;
    proto_item *PAYLOAD_header_item = NULL;
    guint8 management_class;
    tvbuff_t *volatile next_tvb;
    gint            captured_length, reported_length;
    guint16 etype, reserved;
    const char      *saved_proto;
    volatile gboolean   dissector_found = FALSE;

    if(!tvb_bytes_exist(tvb, *offset, length)) /* previously consumed bytes + offset was all the data - none or corrupt payload */
    {
        col_set_str(pinfo->cinfo, COL_INFO, "Invalid Packet Length from LRH! [Malformed Packet]");
        col_set_fence(pinfo->cinfo, COL_INFO);
        return;
    }

    /* management datagrams are determined by the source/destination QPs */
    if (pinfo->srcport == 0 || pinfo->srcport == 1 || pinfo->destport == 0 || pinfo->destport == 1)    /* management datagram */
    {
        management_class =  tvb_get_guint8(tvb, (*offset) + 1);

        if(((management_class >= (guint8)VENDOR_1_START) && (management_class <= (guint8)VENDOR_1_END))
            || ((management_class >= (guint8)VENDOR_2_START) && (management_class <= (guint8)VENDOR_2_END)))
        {
            /* parse vendor specific */
            parse_VENDOR_MANAGEMENT(parentTree, tvb, offset);
        }
        else if((management_class >= (guint8)APPLICATION_START) && (management_class <= (guint8)APPLICATION_END))
        {
            /* parse application specific */
            parse_APPLICATION_MANAGEMENT(parentTree, tvb, offset);
        }
        else if(((management_class == (guint8)0x00) || (management_class == (guint8)0x02))
            || ((management_class >= (guint8)0x50) && (management_class <= (guint8)0x80))
            || ((management_class >= (guint8)0x82)))
        {
            /* parse reserved classes */
            parse_RESERVED_MANAGEMENT(parentTree, tvb, offset);
        }
        else /* we have a normal management_class */
        {
            switch(management_class)
            {
                case SUBN_LID_ROUTED:
                    /* parse subn man lid routed */
                    parse_SUBN_LID_ROUTED(parentTree, pinfo, tvb, &local_offset);
                break;
                case SUBN_DIRECTED_ROUTE:
                    /* parse subn directed route */
                    parse_SUBN_DIRECTED_ROUTE(parentTree, pinfo, tvb, &local_offset);
                break;
                case SUBNADMN:
                    /* parse sub admin */
                    parse_SUBNADMN(parentTree, pinfo, tvb, &local_offset);
                break;
                case PERF:
                    /* parse performance */
                    parse_PERF(parentTree, tvb, pinfo, &local_offset);
                break;
                case BM:
                    /* parse baseboard mgmt */
                    parse_BM(parentTree, tvb, &local_offset);
                break;
                case DEV_MGT:
                    /* parse device management */
                    parse_DEV_MGT(parentTree, tvb, &local_offset);
                break;
                case COM_MGT:
                    /* parse communication management */
                    parse_COM_MGT(parentTree, pinfo, tvb, &local_offset);
                break;
                case SNMP:
                    /* parse snmp tunneling */
                    parse_SNMP(parentTree, tvb, &local_offset);
                break;
                default:
                    break;
            }
        }
    }
    else /* Normal Data Packet - Parse as such */
    {

        /* Calculation for Payload:
        * (tvb_length) Length of entire packet - (local_offset) Starting byte of Payload Data
        * offset addition is more complex for the payload.
        * We need the total length of the packet, - length of previous headers, + offset where payload started.
        * We also need  to reserve 6 bytes for the CRCs which are not actually part of the payload.  */

        etype = tvb_get_ntohs(tvb, local_offset);
        reserved =  tvb_get_ntohs(tvb, local_offset + 2);

        /* try to recognize whether or not this is a Mellanox EoIB packet by the
           transport type and the 4 first bits of the payload */
        if      (pref_dissect_eoib &&
                 transport_type == TRANSPORT_UD &&
                 tvb_get_bits8(tvb, local_offset*8, 4) == 0xC) {
            dissector_found = parse_EoIB(parentTree, tvb, local_offset, pinfo);
        }

        /* IBA packet data could be anything in principle, however it is common
         * practice to carry non-IBA data encapsulated with an EtherType header,
         * similar to the RWH header. There is no way to identify these frames
         * positively.
         *
         * If the appropriate option is set in protocol preferences,
         * We see if the first few bytes look like an EtherType header, and if so
         * call the appropriate dissector. If not we call the "data" dissector.
         */
        if (!dissector_found && pref_identify_iba_payload && reserved == 0) {
            void *pd_save;

            /* Get the captured length and reported length of the data
               after the Ethernet type. */
            captured_length = tvb_length_remaining(tvb, local_offset+4);
            reported_length = tvb_reported_length_remaining(tvb,
                                    local_offset+4);

            next_tvb = tvb_new_subset(tvb, local_offset+4, captured_length,
                          reported_length);

            pinfo->ethertype = etype;

            /* Look for sub-dissector, and call it if found.
               Catch exceptions, so that if the reported length of "next_tvb"
               was reduced by some dissector before an exception was thrown,
               we can still put in an item for the trailer. */
            saved_proto = pinfo->current_proto;
            pd_save = pinfo->private_data;

            TRY {
                dissector_found = dissector_try_uint(ethertype_dissector_table,
                                     etype, next_tvb, pinfo, top_tree);
            }
            CATCH(BoundsError) {
                /* Somebody threw BoundsError, which means that:

                1) a dissector was found, so we don't need to
                dissect the payload as data or update the
                protocol or info columns;

                2) dissecting the payload found that the packet was
                cut off by a snapshot length before the end of
                the payload.  The trailer comes after the payload,
                so *all* of the trailer is cut off, and we'll
                just get another BoundsError if we add the trailer.

                Therefore, we just rethrow the exception so it gets
                reported; we don't dissect the trailer or do anything
                else. */
                RETHROW;
            }
            CATCH(OutOfMemoryError) {
                RETHROW;
            }
            CATCH_ALL {
                /* Somebody threw an exception other than BoundsError, which
                   means that a dissector was found, so we don't need to
                   dissect the payload as data or update the protocol or info
                   columns.  We just show the exception and then drive on
                   to show the trailer, after noting that a dissector was
                   found and restoring the protocol value that was in effect
                   before we called the subdissector. */

                /*  Restore the private_data structure in case one of the
                 *  called dissectors modified it (and, due to the exception,
                 *  was unable to restore it).
                 */
                pinfo->private_data = pd_save;

                show_exception(next_tvb, pinfo, top_tree, EXCEPT_CODE, GET_MESSAGE);
                dissector_found = TRUE;
                pinfo->current_proto = saved_proto;
            }
            ENDTRY;

            if (dissector_found) {
                /* now create payload entry to show Ethertype */
                PAYLOAD_header_item = proto_tree_add_item(parentTree, hf_infiniband_payload, tvb, local_offset, tvb_reported_length_remaining(tvb, local_offset)-6, ENC_NA);
                proto_item_set_text(PAYLOAD_header_item, "%s", "IBA Payload - appears to be EtherType encapsulated");
                PAYLOAD_header_tree = proto_item_add_subtree(PAYLOAD_header_item, ett_payload);
                proto_tree_add_uint(PAYLOAD_header_tree, hf_infiniband_etype, tvb,
                            local_offset, 2,  tvb_get_ntohs(tvb, local_offset));

                local_offset += 2;

                proto_tree_add_uint(PAYLOAD_header_tree, hf_infiniband_reserved16_RWH, tvb,
                            local_offset, 2, tvb_get_ntohs(tvb, local_offset));

            }

        }

        captured_length = tvb_length_remaining(tvb, local_offset);
        reported_length = tvb_reported_length_remaining(tvb,
                                local_offset);

        if (reported_length >= 6)
            reported_length -= 6;
        if (captured_length > reported_length)
            captured_length = reported_length;

        next_tvb = tvb_new_subset(tvb, local_offset,
                      captured_length,
                      reported_length);

        /* Try any heuristic dissectors that requested a chance to try and dissect IB payloads */
        if (!dissector_found) {
            dissector_found = dissector_try_heuristic(heur_dissectors_payload, next_tvb, pinfo, parentTree);
        }

        if (!dissector_found) {
            /* No sub-dissector found.
               Label rest of packet as "Data" */
            call_dissector(data_handle, next_tvb, pinfo, top_tree);

        }


        /*parse_RWH(parentTree, tvb, &local_offset, pinfo);*/

        /* Will contain ICRC and VCRC = 4+2 */
        local_offset = tvb_reported_length(tvb) - 6;
    }

    *offset = local_offset;
}

/* Parse VENDOR - Parse a vendor specific or unknown header sequence
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void parse_VENDOR(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *VENDOR_header_tree = NULL;
    proto_item *VENDOR_header_item = NULL;

    VENDOR_header_item = proto_tree_add_item(parentTree, hf_infiniband_vendor, tvb, local_offset, 4, ENC_NA);
    proto_item_set_text(VENDOR_header_item, "%s", "Vendor Specific or Unknown Header Sequence");
    VENDOR_header_tree = proto_item_add_subtree(VENDOR_header_item, ett_vendor);
    proto_tree_add_item(VENDOR_header_tree, hf_infiniband_vendor,   tvb, local_offset, -1, ENC_NA);
    *offset = local_offset;
}

/* Parse IPv6 - Parse an IPv6 Packet
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset
* IN: pinfo - packet info from wireshark */
static void parse_IPvSix(proto_tree *parentTree, tvbuff_t *tvb, gint *offset, packet_info *pinfo)
{
    tvbuff_t *ipv6_tvb;

    /* (- 2) for VCRC which lives at the end of the packet   */
    ipv6_tvb = tvb_new_subset(tvb, *offset,
                  tvb_length_remaining(tvb, *offset) - 2,
                  tvb_reported_length_remaining(tvb, *offset) - 2);
    call_dissector(ipv6_handle, ipv6_tvb, pinfo, parentTree);
    *offset = tvb_reported_length(tvb) - 2;

    /* Display the VCRC */
    proto_tree_add_item(parentTree, hf_infiniband_variant_crc,  tvb, *offset, 2, FALSE);
}

/* Parse EtherType - Parse a generic IP packaet with an EtherType of IP or ARP
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset
* IN: pinfo - packet info from wireshark */
static void parse_RWH(proto_tree *ah_tree, tvbuff_t *tvb, gint *offset, packet_info *pinfo)
{
    guint16 ether_type;
    tvbuff_t *next_tvb;

    /* RWH - Raw Header */
    proto_tree *RWH_header_tree = NULL;
    proto_item *RWH_header_item = NULL;

    gint captured_length, reported_length;

    RWH_header_item = proto_tree_add_item(ah_tree, hf_infiniband_RWH, tvb, *offset, 4, ENC_NA);
    proto_item_set_text(RWH_header_item, "%s", "RWH - Raw Header");
    RWH_header_tree = proto_item_add_subtree(RWH_header_item, ett_rwh);

    proto_tree_add_item(RWH_header_tree, hf_infiniband_reserved16_RWH, tvb,
            *offset, 2, FALSE);

    *offset += 2;

    ether_type = tvb_get_ntohs(tvb, *offset);
    proto_tree_add_uint(RWH_header_tree, hf_infiniband_etype, tvb, *offset, 2,
                        ether_type);
    *offset += 2;

    /* Get the captured length and reported length of the data
     * after the Ethernet type. */
    captured_length = tvb_length_remaining(tvb, *offset);
    reported_length = tvb_reported_length_remaining(tvb, *offset);

    /* Construct a tvbuff for the payload after the Ethernet type,
     * not including the FCS. */
    if (captured_length >= 0 && reported_length >= 0) {
        if (reported_length >= 2)
            reported_length -= 2;
        if (captured_length > reported_length)
            captured_length = reported_length;
    }

    next_tvb = tvb_new_subset(tvb, *offset, captured_length, reported_length);
    if (!dissector_try_uint(ethertype_dissector_table, ether_type,
            next_tvb, pinfo, top_tree))
       call_dissector(data_handle, next_tvb, pinfo, top_tree);

    *offset = tvb_reported_length(tvb) - 2;
    /* Display the VCRC */
    proto_tree_add_item(ah_tree, hf_infiniband_variant_crc, tvb, *offset, 2, FALSE);
}


/* Parse a Mellanox EoIB Encapsulation Header and the associated Ethernet frame
* IN: parentTree to add the dissection to - in this code the all_headers_tree
* IN: tvb - the data buffer from wireshark
* IN: The current offset
* IN: pinfo - packet info from wireshark */
static gboolean parse_EoIB(proto_tree *tree, tvbuff_t *tvb, gint offset, packet_info *pinfo)
{
    proto_item *header_item;
    proto_tree *header_subtree;
    gboolean ms;
    gint8 seg_offset;
    tvbuff_t *encap_tvb;
    /* the encapsulated eoib size (including the header!) is remaining length-6 bytes of CRC */
    int encap_size = tvb_reported_length_remaining(tvb, offset) - 6;

    if (encap_size < 4) {
        /* not even large enough to contain the eoib encap header. error! */
        return FALSE;
    }

    encap_tvb = tvb_new_subset(tvb, offset + 4, tvb_length_remaining(tvb, offset + 4), encap_size - 4);

    header_item = proto_tree_add_item(tree, hf_infiniband_EOIB, tvb, offset, 4, ENC_NA);
    header_subtree = proto_item_add_subtree(header_item, ett_eoib);

    proto_tree_add_item(header_subtree, hf_infiniband_ver, tvb, offset, 2, FALSE);
    proto_tree_add_item(header_subtree, hf_infiniband_tcp_chk, tvb, offset, 2, FALSE);
    proto_tree_add_item(header_subtree, hf_infiniband_ip_chk, tvb, offset, 2, FALSE);
    proto_tree_add_item(header_subtree, hf_infiniband_fcs, tvb, offset, 2, FALSE);

    ms = tvb_get_bits8(tvb, (offset + 1)*8 + 2, 1);
    seg_offset = tvb_get_bits8(tvb, (offset + 1)*8 + 3, 5);

    proto_tree_add_item(header_subtree, hf_infiniband_ms, tvb, offset, 2, FALSE);
    proto_tree_add_item(header_subtree, hf_infiniband_seg_off, tvb, offset, 2, FALSE); offset += 2;
    proto_tree_add_item(header_subtree, hf_infiniband_seg_id, tvb, offset, 2, FALSE); offset += 2;

    if (seg_offset || ms) {
        /* this is a fragment of an encapsulated Ethernet jumbo frame, parse as data */
        call_dissector(data_handle, encap_tvb, pinfo, top_tree);
    } else {
        /* non-fragmented frames can be fully parsed */
        call_dissector(eth_handle, encap_tvb, pinfo, top_tree);
    }

    return TRUE;
}


/* Parse Subnet Management (LID Routed)
* IN: parentTree to add the dissection to
* IN: pinfo - packet info from wireshark
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void parse_SUBN_LID_ROUTED(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, gint *offset)
{
    /* Parse the Common MAD Header */
    MAD_Data MadData;
    gint local_offset;
    proto_tree *SUBN_LID_ROUTED_header_tree = NULL;
    proto_item *SUBN_LID_ROUTED_header_item = NULL;

    if(!parse_MAD_Common(parentTree, tvb, offset, &MadData))
    {
        /* TODO: Mark Corrupt Packet - Not enough bytes exist for at least the Common MAD header which is present in all MAD packets */
        return;
    }

    local_offset = *offset;

    /* local_offset - 24 here because when we come out of parse_MAD_Common, the offset it sitting at the data section. */
    SUBN_LID_ROUTED_header_item = proto_tree_add_item(parentTree, hf_infiniband_SMP_LID, tvb, local_offset - 24, 256, ENC_NA);
    proto_item_set_text(SUBN_LID_ROUTED_header_item, "%s", "SMP (LID Routed) ");
    SUBN_LID_ROUTED_header_tree = proto_item_add_subtree(SUBN_LID_ROUTED_header_item, ett_subn_lid_routed);
    proto_tree_add_item(SUBN_LID_ROUTED_header_tree, hf_infiniband_m_key,           tvb, local_offset, 8, FALSE); local_offset +=8;
    proto_tree_add_item(SUBN_LID_ROUTED_header_tree, hf_infiniband_reserved256,     tvb, local_offset, 32, ENC_NA); local_offset +=32;

    label_SUBM_Method(SUBN_LID_ROUTED_header_item, &MadData, pinfo);
    label_SUBM_Attribute(SUBN_LID_ROUTED_header_item, &MadData, pinfo);

    /* Try to do the detail parse of the attribute.  If there is an error, or the attribute is unknown, we'll just highlight the generic data. */
    if(!parse_SUBM_Attribute(SUBN_LID_ROUTED_header_tree, tvb, &local_offset, &MadData))
    {
        proto_tree_add_item(SUBN_LID_ROUTED_header_tree, hf_infiniband_smp_data,    tvb, local_offset, 64, ENC_NA); local_offset +=64;
    }

    proto_tree_add_item(SUBN_LID_ROUTED_header_tree, hf_infiniband_reserved1024,    tvb, local_offset, 128, ENC_NA); local_offset +=128;
    *offset = local_offset;
}

/* Parse Subnet Management (Directed Route)
* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void parse_SUBN_DIRECTED_ROUTE(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, gint *offset)
{
    /* Parse the Common MAD Header */
    MAD_Data MadData;
    gint local_offset;
    proto_tree *SUBN_DIRECTED_ROUTE_header_tree = NULL;
    proto_item *SUBN_DIRECTED_ROUTE_header_item = NULL;

    if(!parse_MAD_Common(parentTree, tvb, offset, &MadData))
    {
        /* TODO: Mark Corrupt Packet - Not enough bytes exist for at least the Common MAD header which is present in all MAD packets */
        return;
    }

    local_offset = *offset;

    /* local_offset - 24 here because when we come out of parse_MAD_Common, the offset it sitting at the data section.
    * We need to go backwards because this particular SMP uses the class specific portion of the Common MAD Header */
    SUBN_DIRECTED_ROUTE_header_item = proto_tree_add_item(parentTree, hf_infiniband_SMP_DIRECTED, tvb, local_offset - 24, 256, ENC_NA);
    proto_item_set_text(SUBN_DIRECTED_ROUTE_header_item, "%s", "SMP (Directed Route) ");
    SUBN_DIRECTED_ROUTE_header_tree = proto_item_add_subtree(SUBN_DIRECTED_ROUTE_header_item, ett_subn_directed_route);

    label_SUBM_Method(SUBN_DIRECTED_ROUTE_header_item, &MadData, pinfo);
    label_SUBM_Attribute(SUBN_DIRECTED_ROUTE_header_item, &MadData, pinfo);

    /* Place us at offset 4, the "D" Bit (Direction bit for Directed Route SMPs) */
    local_offset -= 20;
    proto_tree_add_item(SUBN_DIRECTED_ROUTE_header_tree, hf_infiniband_d,               tvb, local_offset, 1, FALSE);
    proto_tree_add_item(SUBN_DIRECTED_ROUTE_header_tree, hf_infiniband_smp_status,      tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(SUBN_DIRECTED_ROUTE_header_tree, hf_infiniband_hop_pointer,     tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(SUBN_DIRECTED_ROUTE_header_tree, hf_infiniband_hop_count,       tvb, local_offset, 1, FALSE); local_offset +=1;
    local_offset += 16; /* Skip over the rest of the Common MAD Header... It's already dissected by parse_MAD_Common */
    proto_tree_add_item(SUBN_DIRECTED_ROUTE_header_tree, hf_infiniband_m_key,           tvb, local_offset, 8, FALSE); local_offset +=8;
    proto_tree_add_item(SUBN_DIRECTED_ROUTE_header_tree, hf_infiniband_dr_slid,         tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(SUBN_DIRECTED_ROUTE_header_tree, hf_infiniband_dr_dlid,         tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(SUBN_DIRECTED_ROUTE_header_tree, hf_infiniband_reserved28,      tvb, local_offset, 28, ENC_NA); local_offset +=28;

    /* Try to do the detail parse of the attribute.  If there is an error, or the attribute is unknown, we'll just highlight the generic data. */
    if(!parse_SUBM_Attribute(SUBN_DIRECTED_ROUTE_header_tree, tvb, &local_offset, &MadData))
    {
        proto_tree_add_item(SUBN_DIRECTED_ROUTE_header_tree, hf_infiniband_smp_data,    tvb, local_offset, 64, ENC_NA); local_offset +=64;
    }

    proto_tree_add_item(SUBN_DIRECTED_ROUTE_header_tree, hf_infiniband_initial_path,        tvb, local_offset, 64, ENC_NA); local_offset +=64;
    proto_tree_add_item(SUBN_DIRECTED_ROUTE_header_tree, hf_infiniband_return_path,     tvb, local_offset, 64, ENC_NA); local_offset +=64;
    *offset = local_offset;
}

/* Parse Subnet Administration
* IN: parentTree to add the dissection to
* IN: pinfo - packet info from wireshark
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void parse_SUBNADMN(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, gint *offset)
{
    /* Parse the Common MAD Header */
    MAD_Data MadData;
    gint local_offset;
    proto_tree *SUBNADMN_header_tree = NULL;
    proto_item *SUBNADMN_header_item = NULL;

    if(!parse_MAD_Common(parentTree, tvb, offset, &MadData))
    {
        /* TODO: Mark Corrupt Packet - Not enough bytes exist for at least the Common MAD header which is present in all MAD packets */
        return;
    }
    if(!parse_RMPP(parentTree, tvb, offset))
    {
        /* TODO: Mark Corrupt Packet */
        return;
    }
    local_offset = *offset;

    SUBNADMN_header_item = proto_tree_add_item(parentTree, hf_infiniband_SA, tvb, local_offset - 36, 256, ENC_NA);
    proto_item_set_text(SUBNADMN_header_item, "%s", "SMA");
    SUBNADMN_header_tree = proto_item_add_subtree(SUBNADMN_header_item, ett_subnadmin);

    proto_tree_add_item(SUBNADMN_header_tree, hf_infiniband_sm_key,             tvb, local_offset, 8, FALSE); local_offset+=8;
    proto_tree_add_item(SUBNADMN_header_tree, hf_infiniband_attribute_offset,   tvb, local_offset, 2, FALSE); local_offset+=4;
    proto_tree_add_item(SUBNADMN_header_tree, hf_infiniband_reserved16,         tvb, local_offset, 2, FALSE); local_offset+=4;
    proto_tree_add_item(SUBNADMN_header_tree, hf_infiniband_component_mask,     tvb, local_offset, 8, FALSE); local_offset+=8;

    label_SUBA_Method(SUBNADMN_header_item, &MadData, pinfo);
    label_SUBA_Attribute(SUBNADMN_header_item, &MadData, pinfo);

    if(!parse_SUBA_Attribute(SUBNADMN_header_tree, tvb, &local_offset, &MadData))
    {
        proto_tree_add_item(SUBNADMN_header_tree, hf_infiniband_subnet_admin_data,  tvb, local_offset, 200, ENC_NA); local_offset+=200;
    }
    *offset = local_offset;
}

/* Parse Performance Management
* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN: pinfo - the pinfo struct from wireshark
* IN/OUT: The current and updated offset */
static void parse_PERF(proto_tree *parentTree, tvbuff_t *tvb, packet_info *pinfo, gint *offset)
{
    /* Parse the Common MAD Header */
    MAD_Data MadData;
    gint local_offset;
    proto_item *PERF_header_item = NULL;

    if(!parse_MAD_Common(parentTree, tvb, offset, &MadData))
    {
        /* TODO: Mark Corrupt Packet - Not enough bytes exist for at least the Common MAD header which is present in all MAD packets */
        return;
    }

    local_offset = *offset; /* offset now points to the start of the MAD data field */

    switch (MadData.attributeID) {
        case ATTR_PORT_COUNTERS:
            parse_PERF_PortCounters(parentTree, tvb, pinfo, &local_offset);
            break;
        case ATTR_PORT_COUNTERS_EXT:
            parse_PERF_PortCountersExtended(parentTree, tvb, pinfo, &local_offset);
            break;
        default:
            PERF_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, MAD_DATA_SIZE, ENC_NA); local_offset += MAD_DATA_SIZE;
            proto_item_set_text(PERF_header_item, "%s", "PERF - Performance Management MAD (Dissector Not Implemented)");
            break;
    }

    *offset = local_offset;
}

/* Parse Baseboard Management
* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void parse_BM(proto_tree *parentTree, tvbuff_t *tvb, gint *offset)
{
    /* Parse the Common MAD Header */
    MAD_Data MadData;
    gint local_offset;
    proto_item *PERF_header_item = NULL;

    if(!parse_MAD_Common(parentTree, tvb, offset, &MadData))
    {
        /* TODO: Mark Corrupt Packet - Not enough bytes exist for at least the Common MAD header which is present in all MAD packets */
        return;
    }
    local_offset = *offset;

    PERF_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, MAD_DATA_SIZE, ENC_NA); local_offset += MAD_DATA_SIZE;
    proto_item_set_text(PERF_header_item, "%s", "BM - Baseboard Management MAD (Dissector Not Implemented)");
    *offset = local_offset;
}

/* Parse Device Management
* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void parse_DEV_MGT(proto_tree *parentTree, tvbuff_t *tvb, gint *offset)
{
    /* Parse the Common MAD Header */
    MAD_Data MadData;
    gint local_offset;
    proto_item *PERF_header_item = NULL;

    if(!parse_MAD_Common(parentTree, tvb, offset, &MadData))
    {
        /* TODO: Mark Corrupt Packet - Not enough bytes exist for at least the Common MAD header which is present in all MAD packets */
        return;
    }
    local_offset = *offset;
    PERF_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, MAD_DATA_SIZE, ENC_NA); local_offset += MAD_DATA_SIZE;
    proto_item_set_text(PERF_header_item, "%s", "DEV_MGT - Device Management MAD (Dissector Not Implemented)");
    *offset = local_offset;
}

/* Parse Communications Management
* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void parse_COM_MGT(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, gint *offset)
{
    MAD_Data MadData;
    gint local_offset;
    guint32 local_qpn = 0, remote_qpn = 0;
    guint8 *local_gid, *remote_gid;
    guint32 local_lid, remote_lid;
    guint64 serviceid;
    const char *label = NULL;
    proto_item *CM_header_item = NULL;
    proto_tree *CM_header_tree = NULL;
    connection_context *connection = NULL; /* we'll use this to store new connections this CM packet is establishing*/
    tvbuff_t *next_tvb;

    local_gid = ep_alloc(GID_SIZE);
    remote_gid = ep_alloc(GID_SIZE);

    if(!parse_MAD_Common(parentTree, tvb, offset, &MadData))
    {
        /* TODO: Mark Corrupt Packet - Not enough bytes exist for at least the Common MAD header which is present in all MAD packets */
        return;
    }
    local_offset = *offset;

    CM_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 140, ENC_NA);

    label = val_to_str(MadData.attributeID, CM_Attributes, "(Unknown CM Attribute)");

    proto_item_set_text(CM_header_item, "CM %s", label);
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "CM: %s", label);

    CM_header_tree = proto_item_add_subtree(CM_header_item, ett_cm);

    switch (MadData.attributeID) {
        case ATTR_CM_REQ:
            proto_tree_add_item(CM_header_tree, hf_cm_req_local_comm_id, tvb, local_offset, 4, FALSE); local_offset += 4;
            local_offset += 4;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_req_service_id, tvb, local_offset, 8, FALSE);
            serviceid = tvb_get_ntoh64(tvb, local_offset); local_offset += 8;
            proto_tree_add_item(CM_header_tree, hf_cm_req_local_ca_guid, tvb, local_offset, 8, FALSE); local_offset += 8;
            local_offset += 4;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_req_local_qkey, tvb, local_offset, 4, FALSE); local_offset += 4;
            proto_tree_add_item(CM_header_tree, hf_cm_req_local_qpn, tvb, local_offset, 3, FALSE);
            local_qpn = tvb_get_ntoh24(tvb, local_offset); local_offset += 3;
            proto_tree_add_item(CM_header_tree, hf_cm_req_respo_res, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_req_local_eecn, tvb, local_offset, 3, FALSE); local_offset += 3;
            proto_tree_add_item(CM_header_tree, hf_cm_req_init_depth, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_req_remote_eecn, tvb, local_offset, 3, FALSE); local_offset += 3;
            proto_tree_add_item(CM_header_tree, hf_cm_req_remote_cm_resp_to, tvb, local_offset, 1, FALSE);
            proto_tree_add_item(CM_header_tree, hf_cm_req_transp_serv_type, tvb, local_offset, 1, FALSE);
            proto_tree_add_item(CM_header_tree, hf_cm_req_e2e_flow_ctrl, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_req_start_psn, tvb, local_offset, 3, FALSE); local_offset += 3;
            proto_tree_add_item(CM_header_tree, hf_cm_req_local_cm_resp_to, tvb, local_offset, 1, FALSE);
            proto_tree_add_item(CM_header_tree, hf_cm_req_retry_count, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_req_pkey, tvb, local_offset, 2, FALSE); local_offset += 2;
            proto_tree_add_item(CM_header_tree, hf_cm_req_path_pp_mtu, tvb, local_offset, 1, FALSE);
            proto_tree_add_item(CM_header_tree, hf_cm_req_rdc_exists, tvb, local_offset, 1, FALSE);
            proto_tree_add_item(CM_header_tree, hf_cm_req_rnr_retry_count, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_req_max_cm_retries, tvb, local_offset, 1, FALSE);
            proto_tree_add_item(CM_header_tree, hf_cm_req_srq, tvb, local_offset, 1, FALSE);
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_req_primary_local_lid, tvb, local_offset, 2, FALSE);
            local_lid = tvb_get_ntohs(tvb, local_offset); local_offset += 2;
            proto_tree_add_item(CM_header_tree, hf_cm_req_primary_remote_lid, tvb, local_offset, 2, FALSE);
            remote_lid = tvb_get_ntohs(tvb, local_offset); local_offset += 2;
            proto_tree_add_item(CM_header_tree, hf_cm_req_primary_local_gid, tvb, local_offset, 16, FALSE);
            tvb_get_ipv6(tvb, local_offset, (struct e_in6_addr*)local_gid); local_offset += 16;
            proto_tree_add_item(CM_header_tree, hf_cm_req_primary_remote_gid, tvb, local_offset, 16, FALSE);
            tvb_get_ipv6(tvb, local_offset, (struct e_in6_addr*)remote_gid); local_offset += 16;
            proto_tree_add_item(CM_header_tree, hf_cm_req_primary_flow_label, tvb, local_offset, 2, FALSE); local_offset += 2;
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_req_primary_packet_rate, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_req_primary_traffic_class, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_req_primary_hop_limit, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_req_primary_sl, tvb, local_offset, 1, FALSE);
            proto_tree_add_item(CM_header_tree, hf_cm_req_primary_subnet_local, tvb, local_offset, 1, FALSE);
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_req_primary_local_ack_to, tvb, local_offset, 1, FALSE);
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_req_alt_local_lid, tvb, local_offset, 2, FALSE); local_offset += 2;
            proto_tree_add_item(CM_header_tree, hf_cm_req_alt_remote_lid, tvb, local_offset, 2, FALSE); local_offset += 2;
            proto_tree_add_item(CM_header_tree, hf_cm_req_alt_local_gid, tvb, local_offset, 16, ENC_NA); local_offset += 16;
            proto_tree_add_item(CM_header_tree, hf_cm_req_alt_remote_gid, tvb, local_offset, 16, ENC_NA); local_offset += 16;
            proto_tree_add_item(CM_header_tree, hf_cm_req_flow_label, tvb, local_offset, 2, FALSE); local_offset += 2;
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_req_packet_rate, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_req_alt_traffic_class, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_req_alt_hop_limit, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_req_SL, tvb, local_offset, 1, FALSE);
            proto_tree_add_item(CM_header_tree, hf_cm_req_subnet_local, tvb, local_offset, 1, FALSE);
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_req_local_ACK_timeout, tvb, local_offset, 1, FALSE);
            local_offset += 1;  /* skip reserved */

            /* the following saves information about the conversation this packet defines,
               so there's no point in doing it more than once per packet */
            if(!pinfo->fd->flags.visited)
            {
                conversation_t *conv;
                conversation_infiniband_data *proto_data = NULL;
                guint64 *hash_key = g_malloc(sizeof(guint64));

                /* create a new connection context and store it in the hash table */
                connection = g_malloc(sizeof(connection_context));
                memcpy(&(connection->req_gid), local_gid, GID_SIZE);
                memcpy(&(connection->resp_gid), remote_gid, GID_SIZE);
                connection->req_lid = local_lid;
                connection->resp_lid = remote_lid;
                connection->req_qp = local_qpn;
                connection->resp_qp = 0;   /* not currently known. we'll fill this in later */
                connection->service_id = serviceid;

                /* save the context to the context hash table, for retrieval when the corresponding
                   CM REP message arrives*/
                *hash_key = MadData.transactionID;
                ADD_ADDRESS_TO_HASH(*hash_key, &pinfo->src);
                g_hash_table_replace(CM_context_table, hash_key, connection);

                /* Now we create a conversation for the CM exchange. This uses both
                   sides of the conversation since CM packets also include the source
                   QPN */
                proto_data = se_alloc(sizeof(conversation_infiniband_data));
                proto_data->service_id = connection->service_id;

                conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                        PT_IBQP, pinfo->srcport, pinfo->destport, 0);
                conversation_add_proto_data(conv, proto_infiniband, proto_data);
            }

            /* give a chance for subdissectors to analyze the private data */
            next_tvb = tvb_new_subset(tvb, local_offset, 92, -1);
            if (! dissector_try_heuristic(heur_dissectors_cm_private, next_tvb, pinfo, parentTree) )
                /* if none reported success, add this as raw "data" */
                proto_tree_add_item(CM_header_tree, hf_cm_req_private_data, tvb, local_offset, 92, ENC_NA);

            local_offset += 92;
            break;
        case ATTR_CM_REP:
            proto_tree_add_item(CM_header_tree, hf_cm_rep_localcommid, tvb, local_offset, 4, FALSE); local_offset += 4;
            proto_tree_add_item(CM_header_tree, hf_cm_rep_remotecommid, tvb, local_offset, 4, FALSE); local_offset += 4;
            proto_tree_add_item(CM_header_tree, hf_cm_rep_localqkey, tvb, local_offset, 4, FALSE); local_offset += 4;
            proto_tree_add_item(CM_header_tree, hf_cm_rep_localqpn, tvb, local_offset, 3, FALSE);
            remote_qpn = tvb_get_ntoh24(tvb, local_offset); local_offset += 3;
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_rep_localeecontnum, tvb, local_offset, 3, FALSE); local_offset += 3;
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_rep_startingpsn, tvb, local_offset, 3, FALSE); local_offset += 3;
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_rep_responderres, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_rep_initiatordepth, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_rep_tgtackdelay, tvb, local_offset, 1, FALSE);
            proto_tree_add_item(CM_header_tree, hf_cm_rep_failoveracc, tvb, local_offset, 1, FALSE);
            proto_tree_add_item(CM_header_tree, hf_cm_rep_e2eflowctl, tvb, local_offset, 1, FALSE); local_offset += 1;
            proto_tree_add_item(CM_header_tree, hf_cm_rep_rnrretrycount, tvb, local_offset, 1, FALSE);
            proto_tree_add_item(CM_header_tree, hf_cm_rep_srq, tvb, local_offset, 1, FALSE);
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_rep_localcaguid, tvb, local_offset, 8, FALSE); local_offset += 8;

            /* the following saves information about the conversation this packet defines,
               so there's no point in doing it more than once per packet */
            if(!pinfo->fd->flags.visited)
            {
                /* get the previously saved context for this connection */
                guint64 hash_key;
                hash_key = MadData.transactionID;
                ADD_ADDRESS_TO_HASH(hash_key, &pinfo->dst);
                connection = g_hash_table_lookup(CM_context_table, &hash_key);

                /* if an appropriate connection was not found there's something wrong, but nothing we can
                   do about it here - so just skip saving the context */
                if(connection)
                {
                    address req_addr,
                            resp_addr;  /* we'll fill these in and pass them to conversation_new */
                    conversation_t *conv;
                    conversation_infiniband_data *proto_data = NULL;

                    connection->resp_qp = remote_qpn;

                    proto_data = se_alloc(sizeof(conversation_infiniband_data));
                    proto_data->service_id = connection->service_id;

                    /* RC traffic never(?) includes a field indicating the source QPN, so
                       the destination host knows it only from previous context (a single
                       QPN on the host that is part of an RC can only receive traffic from
                       that RC). For this reason we do not register conversations with both
                       sides, but rather we register the same conversation twice - once for
                       each side of the Reliable Connection. */

                    /* first register the conversation using the GIDs */
                    SET_ADDRESS(&req_addr, AT_IB, GID_SIZE, connection->req_gid);
                    SET_ADDRESS(&resp_addr, AT_IB, GID_SIZE, connection->resp_gid);

                    conv = conversation_new(pinfo->fd->num, &req_addr, &req_addr,
                                            PT_IBQP, connection->req_qp, connection->req_qp, NO_ADDR2|NO_PORT2);
                    conversation_add_proto_data(conv, proto_infiniband, proto_data);
                    conv = conversation_new(pinfo->fd->num, &resp_addr, &resp_addr,
                                            PT_IBQP, connection->resp_qp, connection->resp_qp, NO_ADDR2|NO_PORT2);
                    conversation_add_proto_data(conv, proto_infiniband, proto_data);

                    /* next, register the conversation using the LIDs */
                    SET_ADDRESS(&req_addr, AT_IB, sizeof(guint16), &(connection->req_lid));
                    SET_ADDRESS(&resp_addr, AT_IB, sizeof(guint16), &(connection->resp_lid));

                    conv = conversation_new(pinfo->fd->num, &req_addr, &req_addr,
                                            PT_IBQP, connection->req_qp, connection->req_qp, NO_ADDR2|NO_PORT2);
                    conversation_add_proto_data(conv, proto_infiniband, proto_data);
                    conv = conversation_new(pinfo->fd->num, &resp_addr, &resp_addr,
                                            PT_IBQP, connection->resp_qp, connection->resp_qp, NO_ADDR2|NO_PORT2);
                    conversation_add_proto_data(conv, proto_infiniband, proto_data);

                    g_hash_table_remove(CM_context_table, &hash_key);
                }
            }

            /* give a chance for subdissectors to get the private data */
            next_tvb = tvb_new_subset(tvb, local_offset, 196, -1);
            if (! dissector_try_heuristic(heur_dissectors_cm_private, next_tvb, pinfo, parentTree) )
                /* if none reported success, add this as raw "data" */
                proto_tree_add_item(CM_header_tree, hf_cm_rep_privatedata, tvb, local_offset, 196, ENC_NA);

            local_offset += 196;
            break;
        case ATTR_CM_RTU:
            proto_tree_add_item(CM_header_tree, hf_cm_rtu_localcommid, tvb, local_offset, 4, FALSE); local_offset += 4;
            proto_tree_add_item(CM_header_tree, hf_cm_rtu_remotecommid, tvb, local_offset, 4, FALSE); local_offset += 4;
            /* currently only REQ/REP call subdissectors for the private data */
            proto_tree_add_item(CM_header_tree, hf_cm_rtu_privatedata, tvb, local_offset, 224, ENC_NA); local_offset += 224;
            break;
        case ATTR_CM_REJ:
            proto_tree_add_item(CM_header_tree, hf_cm_rej_local_commid, tvb, local_offset, 4, FALSE); local_offset += 4;
            proto_tree_add_item(CM_header_tree, hf_cm_rej_remote_commid, tvb, local_offset, 4, FALSE); local_offset += 4;
            proto_tree_add_item(CM_header_tree, hf_cm_rej_msg_rej, tvb, local_offset, 1, FALSE);
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_rej_rej_info_len, tvb, local_offset, 1, FALSE);
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(CM_header_tree, hf_cm_rej_reason, tvb, local_offset, 2, FALSE); local_offset += 2;
            proto_tree_add_item(CM_header_tree, hf_cm_rej_add_rej_info, tvb, local_offset, 72, ENC_NA); local_offset += 72;
            /* currently only REQ/REP call subdissectors for the private data */
            proto_tree_add_item(CM_header_tree, hf_cm_rej_private_data, tvb, local_offset, 148, ENC_NA); local_offset += 148;
            break;
        default:
            proto_item_append_text(CM_header_item, " (Dissector Not Implemented)"); local_offset += MAD_DATA_SIZE;
            break;
    }

    *offset = local_offset;
}

/* Parse SNMP Tunneling
* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void parse_SNMP(proto_tree *parentTree, tvbuff_t *tvb, gint *offset)
{
    /* Parse the Common MAD Header */
    MAD_Data MadData;
    gint local_offset;
    proto_item *PERF_header_item = NULL;

    if(!parse_MAD_Common(parentTree, tvb, offset, &MadData))
    {
        /* TODO: Mark Corrupt Packet - Not enough bytes exist for at least the Common MAD header which is present in all MAD packets */
        return;
    }
    local_offset = *offset;

    PERF_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, MAD_DATA_SIZE, ENC_NA); local_offset += MAD_DATA_SIZE;
    proto_item_set_text(PERF_header_item, "%s", "SNMP - SNMP Tunneling MAD (Dissector Not Implemented)");
    *offset = local_offset;
}

/* Parse Vendor Specific Management Packets
* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void parse_VENDOR_MANAGEMENT(proto_tree *parentTree, tvbuff_t *tvb, gint *offset)
{
    /* Parse the Common MAD Header */
    MAD_Data MadData;
    gint local_offset;
    proto_item *PERF_header_item = NULL;

    if(!parse_MAD_Common(parentTree, tvb, offset, &MadData))
    {
        /* TODO: Mark Corrupt Packet - Not enough bytes exist for at least the Common MAD header which is present in all MAD packets */
        return;
    }
    local_offset = *offset;

    PERF_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, MAD_DATA_SIZE, ENC_NA); local_offset += MAD_DATA_SIZE;
    proto_item_set_text(PERF_header_item, "%s", "VENDOR - Vendor Specific Management MAD (Dissector Not Implemented)");
    *offset = local_offset;
}

/* Parse Application Specific Management Packets
* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void parse_APPLICATION_MANAGEMENT(proto_tree *parentTree, tvbuff_t *tvb, gint *offset)
{
    /* Parse the Common MAD Header */
    MAD_Data MadData;
    gint local_offset;
    proto_item *PERF_header_item = NULL;

    if(!parse_MAD_Common(parentTree, tvb, offset, &MadData))
    {
        /* TODO: Mark Corrupt Packet - Not enough bytes exist for at least the Common MAD header which is present in all MAD packets */
        return;
    }
    local_offset = *offset;
    PERF_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, MAD_DATA_SIZE, ENC_NA); local_offset += MAD_DATA_SIZE;
    proto_item_set_text(PERF_header_item, "%s", "APP - Application Specific MAD (Dissector Not Implemented)");
    *offset = local_offset;
}

/* Parse Reserved Management Packets.

* This is an !ERROR CONDITION!
* It means that the Management Class value used was defined as a reserved value for furture use.
* This method is here since we will want to report this information directly to the UI without blowing up Wireshark.

* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static void parse_RESERVED_MANAGEMENT(proto_tree *parentTree, tvbuff_t *tvb, gint *offset)
{
    /* Parse the Common MAD Header */
    MAD_Data MadData;
    gint local_offset;
    proto_item *PERF_header_item = NULL;

    if(!parse_MAD_Common(parentTree, tvb, offset, &MadData))
    {
        /* TODO: Mark Corrupt Packet - Not enough bytes exist for at least the Common MAD header which is present in all MAD packets */
        return;
    }
    local_offset = *offset;
    PERF_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 256, ENC_NA); local_offset += 256;
    proto_item_set_text(PERF_header_item, "%s", "RESERVED - Reserved MAD Type (Possible Device Error)");
    *offset = local_offset;
}

/* Parse the common MAD Header
* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset
* IN/OUT: MadData - the data from the MAD header */
static gboolean parse_MAD_Common(proto_tree *parentTree, tvbuff_t *tvb, gint *offset, MAD_Data* MadData)
{
    gint local_offset = *offset;
    proto_tree *MAD_header_tree = NULL;
    proto_item *MAD_header_item = NULL;

    if(MadData == NULL)
        return FALSE;
    if(!tvb_bytes_exist(tvb, *offset, 256))
        return FALSE;

    /* Get the Management Class to decide between LID Routed and Direct Route */
    MadData->managementClass =      tvb_get_guint8(tvb, local_offset + 1);
    MadData->classVersion =         tvb_get_guint8(tvb, local_offset + 2);
    MadData->method =               tvb_get_guint8(tvb, local_offset + 3);
    MadData->status =               tvb_get_guint8(tvb, local_offset + 4);
    MadData->classSpecific =        tvb_get_ntohs(tvb, local_offset + 6);
    MadData->transactionID =        tvb_get_ntoh64(tvb, local_offset + 8);
    MadData->attributeID =          tvb_get_ntohs(tvb, local_offset + 16);
    MadData->attributeModifier =    tvb_get_ntohl(tvb, local_offset + 20);
    tvb_memcpy(tvb, MadData->data, local_offset + 24, MAD_DATA_SIZE);

    /* Populate the Dissector Tree */

    MAD_header_item = proto_tree_add_item(parentTree, hf_infiniband_MAD, tvb, local_offset, 256, ENC_NA);
    proto_item_set_text(MAD_header_item, "%s", "MAD Header - Common Management Datagram");
    MAD_header_tree = proto_item_add_subtree(MAD_header_item, ett_mad);

    proto_tree_add_item(MAD_header_tree, hf_infiniband_base_version,        tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MAD_header_tree, hf_infiniband_mgmt_class,          tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MAD_header_tree, hf_infiniband_class_version,       tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MAD_header_tree, hf_infiniband_method,              tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MAD_header_tree, hf_infiniband_status,              tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(MAD_header_tree, hf_infiniband_class_specific,      tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(MAD_header_tree, hf_infiniband_transaction_id,      tvb, local_offset, 8, FALSE); local_offset+=8;
    proto_tree_add_item(MAD_header_tree, hf_infiniband_attribute_id,        tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(MAD_header_tree, hf_infiniband_reserved16,          tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(MAD_header_tree, hf_infiniband_attribute_modifier,  tvb, local_offset, 4, FALSE); local_offset+=4;
    proto_tree_add_item(MAD_header_tree, hf_infiniband_data,                tvb, local_offset, MAD_DATA_SIZE, ENC_NA);
    *offset = local_offset; /* Move the offset to the start of the Data field - this will be where the other parsers start. */

    return TRUE;
}

/* Parse the RMPP (Reliable Multi-Packet Transaction Protocol
* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static gboolean parse_RMPP(proto_tree *parentTree, tvbuff_t *tvb, gint *offset)
{
    gint local_offset = *offset;
    guint8 RMPP_Type = tvb_get_guint8(tvb, local_offset + 1);
    proto_tree *RMPP_header_tree = NULL;
    proto_item *RMPP_header_item = NULL;

    RMPP_header_item = proto_tree_add_item(parentTree, hf_infiniband_RMPP, tvb, local_offset, 12, ENC_NA);
    proto_item_set_text(RMPP_header_item, "%s", val_to_str(RMPP_Type, RMPP_Packet_Types, "Reserved RMPP Type! (0x%02x)"));
    RMPP_header_tree = proto_item_add_subtree(RMPP_header_item, ett_rmpp);

    proto_tree_add_item(RMPP_header_tree, hf_infiniband_rmpp_version,   tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(RMPP_header_tree, hf_infiniband_rmpp_type,      tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(RMPP_header_tree, hf_infiniband_r_resp_time,    tvb, local_offset, 1, FALSE);
    proto_tree_add_item(RMPP_header_tree, hf_infiniband_rmpp_flags,     tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(RMPP_header_tree, hf_infiniband_rmpp_status,    tvb, local_offset, 1, FALSE); local_offset+=1;
    switch(RMPP_Type)
    {
        case RMPP_ILLEGAL:
            proto_tree_add_item(RMPP_header_tree, hf_infiniband_rmpp_data1,     tvb, local_offset, 4, FALSE); local_offset+=4;
            proto_tree_add_item(RMPP_header_tree, hf_infiniband_rmpp_data2,     tvb, local_offset, 4, FALSE); local_offset+=4;
            break;
        case RMPP_DATA:
            proto_tree_add_item(RMPP_header_tree, hf_infiniband_segment_number,     tvb, local_offset, 4, FALSE); local_offset+=4;
            proto_tree_add_item(RMPP_header_tree, hf_infiniband_payload_length32,   tvb, local_offset, 4, FALSE); local_offset+=4;
            proto_tree_add_item(RMPP_header_tree, hf_infiniband_transferred_data,   tvb, local_offset, 220, ENC_NA);
            break;
        case RMPP_ACK:
            proto_tree_add_item(RMPP_header_tree, hf_infiniband_segment_number,     tvb, local_offset, 4, FALSE); local_offset+=4;
            proto_tree_add_item(RMPP_header_tree, hf_infiniband_new_window_last,    tvb, local_offset, 4, FALSE); local_offset+=4;
            proto_tree_add_item(RMPP_header_tree, hf_infiniband_reserved220,        tvb, local_offset, 220, ENC_NA);
            break;
        case RMPP_STOP:
        case RMPP_ABORT:
            proto_tree_add_item(RMPP_header_tree, hf_infiniband_reserved32,                     tvb, local_offset, 4, FALSE); local_offset+=4;
            proto_tree_add_item(RMPP_header_tree, hf_infiniband_reserved32,                     tvb, local_offset, 4, FALSE); local_offset+=4;
            proto_tree_add_item(RMPP_header_tree, hf_infiniband_optional_extended_error_data,   tvb, local_offset, 220, ENC_NA);
            break;
        default:
            break;
    }
    *offset = local_offset;
    return TRUE;
}

/* Parse the Method from the MAD Common Header.
* Simply used to generate the identifier.
* IN: SubMItem - the item to append the method label to.
* IN: MadHeader - the MadData structure that contains the information from the Common MAD header.
* IN: pinfo - packet info from wireshark. */
static void label_SUBM_Method(proto_item *SubMItem, MAD_Data *MadHeader, packet_info *pinfo)
{
    const char *label = val_to_str(MadHeader->method, SUBM_Methods, "(Unknown SubManagement Method!)");

    proto_item_append_text(SubMItem, "%s", label);
    col_append_str(pinfo->cinfo, COL_INFO, label);
}

/* Parse the SA Method from the MAD Common Header.
* Simply used to generate the identifier.
* IN: SubAItem - the item to append the method label to.
* IN: MadHeader - the MadData structure that contains the information from the Common MAD header.
* IN: pinfo - packet info from wireshark. */
static void label_SUBA_Method(proto_item *SubAItem, MAD_Data *MadHeader, packet_info *pinfo)
{
    const char *label = val_to_str(MadHeader->method, SUBA_Methods, "(Unknown SubAdministration Method!)");

    proto_item_append_text(SubAItem, "%s", label);
    col_append_str(pinfo->cinfo, COL_INFO, label);
}

/* Parse the Attribute from the MAD Common Header
* Simply used to generate the identifier.
* IN: SubMItem - the item to append the Attribute label to.
* IN: MadHeader - the MadData structure that contains the information from the Common MAD header.
* IN: pinfo - packet info from wireshark. */
static void label_SUBM_Attribute(proto_item *SubMItem, MAD_Data *MadHeader, packet_info *pinfo)
{
    const char *label = val_to_str(MadHeader->attributeID, SUBM_Attributes, "(Unknown SubManagement Attribute!)");

    proto_item_append_text(SubMItem, "%s", &label[11]);
    col_append_str(pinfo->cinfo, COL_INFO, &label[11]);
}

/* Parse the SA Attribute from the MAD Common Header
* Simply used to generate the identifier.
* IN: SubAItem - the item to append the Attribute label to.
* IN: MadHeader - the MadData structure that contains the information from the Common MAD header.
* IN: pinfo - packet info from wireshark. */
static void label_SUBA_Attribute(proto_item *SubAItem, MAD_Data *MadHeader, packet_info *pinfo)
{
    const char *label = val_to_str(MadHeader->attributeID, SUBA_Attributes, "(Unknown SubAdministration Attribute!)");

    proto_item_append_text(SubAItem, "%s", &label[11]);
    col_append_str(pinfo->cinfo, COL_INFO, &label[11]);
}

/* Parse the attribute from a Subnet Management Packet.
* IN: Parent Tree to add the item to in the dissection tree
* IN: tvbuff, offset - the data and where it is.
* IN: MAD_Data the data from the Common MAD Header that provides the information we need */
static gboolean parse_SUBM_Attribute(proto_tree *parentTree, tvbuff_t *tvb, gint *offset, MAD_Data *MadHeader)
{
    guint16 attributeID = MadHeader->attributeID;
    proto_tree *SUBM_Attribute_header_tree = NULL;
    proto_item *SUBM_Attribute_header_item = NULL;

    SUBM_Attribute_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, *offset, 64, ENC_NA);
    proto_item_set_text(SUBM_Attribute_header_item, "%s", val_to_str(attributeID, SUBM_Attributes, "Unknown Attribute Type! (0x%02x)"));
    SUBM_Attribute_header_tree = proto_item_add_subtree(SUBM_Attribute_header_item, ett_subm_attribute);


    switch(attributeID)
    {
        case 0x0002:
            parse_NoticesAndTraps(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x0010:
             parse_NodeDescription(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x0011:
            parse_NodeInfo(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x0012:
            parse_SwitchInfo(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x0014:
            parse_GUIDInfo(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x0015:
            parse_PortInfo(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x0016:
            parse_P_KeyTable(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x0017:
            parse_SLtoVLMappingTable(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x0018:
            parse_VLArbitrationTable(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x0019:
            parse_LinearForwardingTable(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x001A:
            parse_RandomForwardingTable(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x001B:
            parse_MulticastForwardingTable(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x001C:
            parse_SMInfo(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x0020:
            parse_VendorDiag(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x0030:
            parse_LedInfo(SUBM_Attribute_header_tree , tvb, offset);
            break;
        case 0x0031:
            parse_LinkSpeedWidthPairsTable(SUBM_Attribute_header_tree , tvb, offset);
            break;
        default:
            break;
    }


    *offset += 64;
    return TRUE;

}
/* Parse the attribute from a Subnet Administration Packet.
* IN: Parent Tree to add the item to in the dissection tree
* IN: tvbuff, offset - the data and where it is.
* IN: MAD_Data the data from the Common MAD Header that provides the information we need */
static gboolean parse_SUBA_Attribute(proto_tree *parentTree, tvbuff_t *tvb, gint *offset, MAD_Data *MadHeader)
{
    guint16 attributeID = MadHeader->attributeID;
    proto_tree *SUBA_Attribute_header_tree = NULL;
    proto_item *SUBA_Attribute_header_item = NULL;

    SUBA_Attribute_header_item = proto_tree_add_item(parentTree, hf_infiniband_SA, tvb, *offset, 200, ENC_NA);
    proto_item_set_text(SUBA_Attribute_header_item, "%s", val_to_str(attributeID, SUBA_Attributes, "Unknown Attribute Type! (0x%02x)"));
    SUBA_Attribute_header_tree = proto_item_add_subtree(SUBA_Attribute_header_item, ett_suba_attribute);

    /* Skim off the RID fields should they be present */
    parse_RID(SUBA_Attribute_header_tree, tvb, offset, MadHeader);

    /* Parse the rest of the attributes */
    switch(MadHeader->attributeID)
    {
        case 0x0001: /* (ClassPortInfo) */
            parse_PortInfo(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0002: /* (Notice) */
            parse_NoticesAndTraps(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0003: /* (InformInfo) */
            parse_InformInfo(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0011: /* (NodeRecord) */
            parse_NodeInfo(SUBA_Attribute_header_tree, tvb, offset);
            *offset += 40;
            parse_NodeDescription(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0012: /* (PortInfoRecord) */
            parse_PortInfo(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0013: /* (SLtoVLMappingTableRecord) */
            parse_SLtoVLMappingTable(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0014: /* (SwitchInfoRecord) */
            parse_SwitchInfo(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0015: /*(LinearForwardingTableRecord) */
            parse_LinearForwardingTable(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0016: /* (RandomForwardingTableRecord) */
            parse_RandomForwardingTable(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0017: /* (MulticastForwardingTableRecord) */
            parse_MulticastForwardingTable(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0018: /* (SMInfoRecord) */
            parse_SMInfo(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0019: /* (LinkSpeedWidthPairsTableRecord) */
            parse_LinkSpeedWidthPairsTable(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x00F3: /*(InformInfoRecord) */
            parse_InformInfo(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0020: /* (LinkRecord) */
            parse_LinkRecord(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0030: /* (GuidInforecord) */
            parse_GUIDInfo(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0031: /*(ServiceRecord) */
            parse_ServiceRecord(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0033: /* (P_KeyTableRecord) */
            parse_P_KeyTable(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0035: /* (PathRecord) */
            parse_PathRecord(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0036: /* (VLArbitrationTableRecord) */
            parse_VLArbitrationTable(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0038: /* (MCMemberRecord) */
            parse_MCMemberRecord(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x0039: /* (TraceRecord) */
            parse_TraceRecord(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x003A: /* (MultiPathRecord) */
            parse_MultiPathRecord(SUBA_Attribute_header_tree, tvb, offset);
            break;
        case 0x003B: /* (ServiceAssociationRecord) */
            parse_ServiceAssociationRecord(SUBA_Attribute_header_tree, tvb, offset);
            break;
        default: /* (Unknown SubAdministration Attribute!) */
            /* We've already labeled as unknown in item construction */
            break;
    }

    *offset += 200;
    return TRUE;
}

/* Subnet Management Attribute Parsing Methods.
*  Also Parsing for Attributes common to both SM/SA.
* The Subnet Admin Parsing methods will call some of these methods when an attribute is present within an SA MAD
*/


/* Parse NoticeDataDetails Attribute Field
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       trapNumber - The Trap ID of the Trap Data being Dissected  */

static void parse_NoticeDataDetails(proto_tree* parentTree, tvbuff_t* tvb, gint *offset, guint16 trapNumber)
{
    gint local_offset = *offset;
    proto_tree *DataDetails_header_tree = NULL;
    proto_item *DataDetails_header_item = NULL;

    if(!parentTree)
        return;

    DataDetails_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 54, ENC_NA);
    DataDetails_header_tree = proto_item_add_subtree(DataDetails_header_item, ett_datadetails);


    switch(trapNumber)
    {
        case 64:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 64 DataDetails");
            local_offset +=6;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_GIDADDR,    tvb, local_offset, 16, FALSE);  local_offset+=16;
        break;
        case 65:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 65 DataDetails");
            local_offset +=6;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_GIDADDR,    tvb, local_offset, 16, FALSE);  local_offset+=16;
        break;
        case 66:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 66 DataDetails");
            local_offset +=6;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_GIDADDR,    tvb, local_offset, 16, FALSE);  local_offset+=16;
        break;
        case 67:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 67 DataDetails");
            local_offset +=6;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_GIDADDR,    tvb, local_offset, 16, FALSE);  local_offset+=16;
        break;
        case 68:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 68 DataDetails");
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_COMP_MASK,          tvb, local_offset, 8, FALSE);  local_offset+=8;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_WAIT_FOR_REPATH,    tvb, local_offset, 1, FALSE);
        break;
        case 69:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 69 DataDetails");
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_COMP_MASK,          tvb, local_offset, 8, FALSE);  local_offset+=8;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_WAIT_FOR_REPATH,    tvb, local_offset, 1, FALSE);
        break;
        case 128:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 128 DataDetails");
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR,        tvb, local_offset, 2, FALSE);  local_offset+=2;
        break;
        case 129:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 129 DataDetails");
            local_offset += 2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR,        tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_PORTNO,         tvb, local_offset, 1, FALSE);  local_offset+=1;
        break;
        case 130:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 130 DataDetails");
            local_offset += 2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR,        tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_PORTNO,         tvb, local_offset, 1, FALSE);  local_offset+=1;
        break;
        case 131:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 131 DataDetails");
            local_offset += 2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR,        tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_PORTNO,         tvb, local_offset, 1, FALSE);  local_offset+=1;
        break;
        case 144:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 144 DataDetails");
            local_offset +=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR,        tvb, local_offset, 2, FALSE);  local_offset+=2;
            local_offset +=1;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_OtherLocalChanges,      tvb, local_offset, 1, FALSE);  local_offset+=1;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_CAPABILITYMASK,     tvb, local_offset, 4, FALSE);  local_offset+=4;
            local_offset +=1;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LinkSpeecEnabledChange,     tvb, local_offset, 1, FALSE);
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LinkWidthEnabledChange,     tvb, local_offset, 1, FALSE);
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_NodeDescriptionChange,      tvb, local_offset, 1, FALSE);
        break;
        case 145:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 145 DataDetails");
            local_offset +=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR,        tvb, local_offset, 2, FALSE);  local_offset+=2;
            local_offset +=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_SYSTEMIMAGEGUID,        tvb, local_offset, 8, FALSE);  local_offset+=8;
        break;
        case 256:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 256 DataDetails");
            local_offset +=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR,            tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_DRSLID,             tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_METHOD,             tvb, local_offset, 1, FALSE);  local_offset+=1;
            local_offset +=1;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_ATTRIBUTEID,        tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_ATTRIBUTEMODIFIER,  tvb, local_offset, 4, FALSE);  local_offset+=4;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_MKEY,               tvb, local_offset, 8, FALSE);  local_offset+=8;
            local_offset +=1;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_DRNotice,           tvb, local_offset, 1, FALSE);
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_DRPathTruncated,    tvb, local_offset, 1, FALSE);
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_DRHopCount,         tvb, local_offset, 1, FALSE);  local_offset+=1;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_DRNoticeReturnPath, tvb, local_offset, 30, ENC_NA);  local_offset+=30;
        break;
        case 257:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 257 DataDetails");
            local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR1,   tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR2,   tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_KEY,        tvb, local_offset, 4, FALSE);  local_offset+=4;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_SL,         tvb, local_offset, 1, FALSE);  local_offset+=1;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_QP1,        tvb, local_offset, 3, FALSE);  local_offset+=3;
            local_offset +=1;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_QP2,        tvb, local_offset, 3, FALSE);  local_offset+=3;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_GIDADDR1,   tvb, local_offset, 16, FALSE);  local_offset+=16;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_GIDADDR2,   tvb, local_offset, 16, FALSE);  local_offset+=16;
        break;
        case 258:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 258 DataDetails");
            local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR1,   tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR2,   tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_KEY,        tvb, local_offset, 4, FALSE);  local_offset+=4;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_SL,         tvb, local_offset, 1, FALSE);  local_offset +=1;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_QP1,        tvb, local_offset, 3, FALSE);  local_offset+=3;
            local_offset +=1;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_QP2,        tvb, local_offset, 3, FALSE);  local_offset+=3;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_GIDADDR1,   tvb, local_offset, 16, FALSE);  local_offset+=16;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_GIDADDR2,   tvb, local_offset, 16, FALSE);  local_offset+=16;
        break;
        case 259:
            proto_item_set_text(DataDetails_header_item, "%s", "Trap 259 DataDetails");
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_DataValid,  tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR1,   tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_LIDADDR2,   tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_PKEY,       tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_SL,         tvb, local_offset, 1, FALSE);  local_offset+=1;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_QP1,        tvb, local_offset, 3, FALSE);  local_offset+=3;
            local_offset +=1;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_QP2,        tvb, local_offset, 3, FALSE);  local_offset+=3;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_GIDADDR1,   tvb, local_offset, 16, FALSE);  local_offset+=16;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_GIDADDR2,   tvb, local_offset, 16, FALSE);  local_offset+=16;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_SWLIDADDR,  tvb, local_offset, 2, FALSE);  local_offset+=2;
            proto_tree_add_item(DataDetails_header_tree, hf_infiniband_Trap_PORTNO,     tvb, local_offset, 1, FALSE);  local_offset+=1;
        break;
        default:
            proto_item_set_text(DataDetails_header_item, "%s", "Vendor Specific Subnet Management Trap"); local_offset +=54;
            break;
    }

}

/* Parse NoticesAndTraps Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_NoticesAndTraps(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *NoticesAndTraps_header_tree = NULL;
    proto_item *NoticesAndTraps_header_item = NULL;
    guint16 trapNumber = tvb_get_ntohs(tvb, local_offset + 4);

    if(!parentTree)
        return;

    NoticesAndTraps_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(NoticesAndTraps_header_item, "%s", val_to_str(trapNumber, Trap_Description, "Unknown or Vendor Specific Trap Number! (0x%02x)"));
    NoticesAndTraps_header_tree = proto_item_add_subtree(NoticesAndTraps_header_item, ett_noticestraps);

    proto_tree_add_item(NoticesAndTraps_header_tree, hf_infiniband_Notice_IsGeneric,                tvb, local_offset, 1, FALSE);
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_infiniband_Notice_Type,                     tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_infiniband_Notice_ProducerTypeVendorID,     tvb, local_offset, 3, FALSE); local_offset+=3;
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_infiniband_Notice_TrapNumberDeviceID,       tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_infiniband_Notice_IssuerLID,                tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_infiniband_Notice_NoticeToggle,             tvb, local_offset, 1, FALSE);
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_infiniband_Notice_NoticeCount,              tvb, local_offset, 2, FALSE); local_offset+=2;

    parse_NoticeDataDetails(NoticesAndTraps_header_tree, tvb, &local_offset, trapNumber);
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_infiniband_Notice_DataDetails,              tvb, local_offset, 54, ENC_NA); local_offset+=54;

    /* Only Defined For GMPs not SMPs which is not part of this dissector phase
    *proto_tree_add_item(NoticesAndTraps_header_tree, hf_infiniband_Notice_IssuerGID,               tvb, local_offset, 16, FALSE); local_offset+=16;
    *proto_tree_add_item(NoticesAndTraps_header_tree, hf_infiniband_Notice_ClassTrapSpecificData,   tvb, local_offset, 1, ENC_NA); local_offset+=1; */

}

/* Parse NodeDescription Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_NodeDescription(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *NodeDescription_header_tree = NULL;

    if(!parentTree)
        return;

    NodeDescription_header_tree = parentTree;
    proto_tree_add_item(NodeDescription_header_tree, hf_infiniband_NodeDescription_NodeString,  tvb, local_offset, 64, FALSE);
}

/* Parse NodeInfo Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_NodeInfo(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *NodeInfo_header_tree = NULL;

    if(!parentTree)
        return;

    NodeInfo_header_tree = parentTree;

    proto_tree_add_item(NodeInfo_header_tree, hf_infiniband_NodeInfo_BaseVersion,       tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(NodeInfo_header_tree, hf_infiniband_NodeInfo_ClassVersion,      tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(NodeInfo_header_tree, hf_infiniband_NodeInfo_NodeType,          tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(NodeInfo_header_tree, hf_infiniband_NodeInfo_NumPorts,          tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(NodeInfo_header_tree, hf_infiniband_NodeInfo_SystemImageGUID,   tvb, local_offset, 8, FALSE); local_offset +=8;
    proto_tree_add_item(NodeInfo_header_tree, hf_infiniband_NodeInfo_NodeGUID,          tvb, local_offset, 8, FALSE); local_offset +=8;
    proto_tree_add_item(NodeInfo_header_tree, hf_infiniband_NodeInfo_PortGUID,          tvb, local_offset, 8, FALSE); local_offset +=8;
    proto_tree_add_item(NodeInfo_header_tree, hf_infiniband_NodeInfo_PartitionCap,      tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(NodeInfo_header_tree, hf_infiniband_NodeInfo_DeviceID,          tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(NodeInfo_header_tree, hf_infiniband_NodeInfo_Revision,          tvb, local_offset, 4, FALSE); local_offset +=4;
    proto_tree_add_item(NodeInfo_header_tree, hf_infiniband_NodeInfo_LocalPortNum,      tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(NodeInfo_header_tree, hf_infiniband_NodeInfo_VendorID,          tvb, local_offset, 3, FALSE); local_offset +=3;

}

/* Parse SwitchInfo Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_SwitchInfo(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *SwitchInfo_header_tree = NULL;

    if(!parentTree)
        return;

    SwitchInfo_header_tree = parentTree;

    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_LinearFDBCap,                      tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_RandomFDBCap,                      tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_MulticastFDBCap,                   tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_LinearFDBTop,                      tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_DefaultPort,                       tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_DefaultMulticastPrimaryPort,       tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_DefaultMulticastNotPrimaryPort,    tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_LifeTimeValue,                     tvb, local_offset, 1, FALSE);
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_PortStateChange,                   tvb, local_offset, 1, FALSE);
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_OptimizedSLtoVLMappingProgramming, tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_LIDsPerPort,                       tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_PartitionEnforcementCap,           tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_InboundEnforcementCap,             tvb, local_offset, 1, FALSE);
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_OutboundEnforcementCap,            tvb, local_offset, 1, FALSE);
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_FilterRawInboundCap,               tvb, local_offset, 1, FALSE);
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_FilterRawOutboundCap,              tvb, local_offset, 1, FALSE);
    proto_tree_add_item(SwitchInfo_header_tree, hf_infiniband_SwitchInfo_EnhancedPortZero,                  tvb, local_offset, 1, FALSE); local_offset +=1;
}

/* Parse GUIDInfo Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_GUIDInfo(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *GUIDInfo_header_tree = NULL;
    proto_item *tempItemLow = NULL;
    gint i = 0;

    if(!parentTree)
        return;

    GUIDInfo_header_tree = parentTree;

    for(i = 0; i < 8; i++)
    {
        proto_tree_add_item(GUIDInfo_header_tree, hf_infiniband_GUIDInfo_GUID, tvb, local_offset, 8, FALSE); local_offset +=8;
        proto_item_append_text(tempItemLow, "(%u)", i);
    }

}

/* Parse PortInfo Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_PortInfo(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *PortInfo_header_tree = NULL;
    proto_tree *PortInfo_CapabilityMask_tree = NULL;
    proto_item *PortInfo_CapabilityMask_item = NULL;
    proto_item *temp_item = NULL;
    guint16 temp_val = 0;

    if(!parentTree)
        return;

    PortInfo_header_tree = parentTree;

    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_M_Key,                 tvb, local_offset, 8, FALSE); local_offset +=8;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_GidPrefix,             tvb, local_offset, 8, FALSE); local_offset +=8;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_LID,                   tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_MasterSMLID,           tvb, local_offset, 2, FALSE); local_offset +=2;

    /* Capability Mask Flags */
    PortInfo_CapabilityMask_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_CapabilityMask,     tvb, local_offset, 4, FALSE);
    PortInfo_CapabilityMask_tree = proto_item_add_subtree(PortInfo_CapabilityMask_item, ett_portinfo_capmask);

    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_SM,                             tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_NoticeSupported,                tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_TrapSupported,                  tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_OptionalPDSupported,            tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_AutomaticMigrationSupported,    tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_SLMappingSupported,             tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_MKeyNVRAM,                      tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_PKeyNVRAM,                      tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_LEDInfoSupported,               tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_SMdisabled,                     tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_SystemImageGUIDSupported,       tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_PKeySwitchExternalPortTrapSupported,    tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_CommunicationsManagementSupported,      tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_SNMPTunnelingSupported,                 tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_ReinitSupported,                tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_DeviceManagementSupported,      tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_VendorClassSupported,           tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_DRNoticeSupported,              tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_CapabilityMaskNoticeSupported,  tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_BootManagementSupported,        tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_LinkRoundTripLatencySupported,  tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_ClientRegistrationSupported,    tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_OtherLocalChangesNoticeSupported,   tvb, local_offset, 4, FALSE);
    proto_tree_add_item(PortInfo_CapabilityMask_tree, hf_infiniband_PortInfo_CapabilityMask_LinkSpeedWIdthPairsTableSupported,  tvb, local_offset, 4, FALSE);
    local_offset+=4;
    /* End Capability Mask Flags */

    /* Diag Code */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_DiagCode,              tvb, local_offset, 2, FALSE);
    temp_val = tvb_get_ntohs(tvb, local_offset);

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, DiagCode, "Reserved DiagCode! Possible Error"));
    local_offset +=2;
    /* End Diag Code */

    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_M_KeyLeasePeriod,      tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_LocalPortNum,          tvb, local_offset, 1, FALSE); local_offset +=1;

    /* LinkWidthEnabled */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_LinkWidthEnabled,      tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, LinkWidthEnabled, "Reserved LinkWidthEnabled Value! Possible Error"));
    local_offset +=1;
    /* End LinkWidthEnabled */

    /* LinkWidthSupported */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_LinkWidthSupported,    tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, LinkWidthSupported, "Reserved LinkWidthSupported Value! Possible Error"));
    local_offset +=1;
    /* End LinkWidthSupported */

    /* LinkWidthActive */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_LinkWidthActive,       tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, LinkWidthActive, "Reserved LinkWidthActive Value! Possible Error"));
    local_offset +=1;
    /* End LinkWidthActive */

    /* LinkSpeedSupported */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_LinkSpeedSupported,    tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    /* 4 bit values = mask and shift */
    temp_val = temp_val & 0x00F0;
    temp_val = temp_val >> 4;

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, LinkSpeedSupported, "Reserved LinkWidthSupported Value! Possible Error"));
    /* End LinkSpeedSupported */

    /* PortState */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_PortState,             tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    /* 4 bit values = mask and shift */
    temp_val = temp_val & 0x000F;
    /*temp_val = temp_val >> 4 */

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, PortState, "Reserved PortState Value! Possible Error"));
    local_offset +=1;
    /* End PortState */

    /* PortPhysicalState */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_PortPhysicalState,     tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    /* 4 bit values = mask and shift */
    temp_val = temp_val & 0x00F0;
    temp_val = temp_val >> 4;

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, PortPhysicalState, "Reserved PortPhysicalState Value! Possible Error"));
    /* End PortPhysicalState */

    /* LinkDownDefaultState */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_LinkDownDefaultState,  tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    /* 4 bit values = mask and shift */
    temp_val = temp_val & 0x000F;
    /*temp_val = temp_val >> 4 */

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, LinkDownDefaultState, "Reserved LinkDownDefaultState Value! Possible Error"));
    local_offset +=1;
    /* End LinkDownDefaultState */

    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_M_KeyProtectBits,      tvb, local_offset, 1, FALSE);
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_LMC,                   tvb, local_offset, 1, FALSE); local_offset +=1;

    /* LinkSpeedActive */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_LinkSpeedActive,       tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    /* 4 bit values = mask and shift */
    temp_val = temp_val & 0x00F0;
    temp_val = temp_val >> 4;

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, LinkSpeedActive, "Reserved LinkSpeedActive Value! Possible Error"));
    /* End LinkSpeedActive */

    /* LinkSpeedEnabled */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_LinkSpeedEnabled,      tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    /* 4 bit values = mask and shift */
    temp_val = temp_val & 0x000F;
    /*temp_val = temp_val >> 4 */

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, LinkSpeedEnabled, "Reserved LinkSpeedEnabled Value! Possible Error"));
    local_offset +=1;
    /* End LinkSpeedEnabled */

    /* NeighborMTU */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_NeighborMTU,           tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    /* 4 bit values = mask and shift */
    temp_val = temp_val & 0x00F0;
    temp_val = temp_val >> 4;

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, NeighborMTU, "Reserved NeighborMTU Value! Possible Error"));

    /* End NeighborMTU */

    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_MasterSMSL,            tvb, local_offset, 1, FALSE); local_offset +=1;

    /* VLCap */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_VLCap,                 tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    /* 4 bit values = mask and shift */
    temp_val = temp_val & 0x00F0;
    temp_val = temp_val >> 4;

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, VLCap, "Reserved VLCap Value! Possible Error"));

    /* End VLCap */

    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_InitType,              tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_VLHighLimit,           tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_VLArbitrationHighCap,  tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_VLArbitrationLowCap,   tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_InitTypeReply,         tvb, local_offset, 1, FALSE);

    /* MTUCap */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_MTUCap,                tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    /* 4 bit values = mask and shift */
    temp_val = temp_val & 0x000F;
    /*temp_val = temp_val >> 4 */

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, MTUCap, "Reserved MTUCap Value! Possible Error"));
    local_offset +=1;
    /* End MTUCap */

    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_VLStallCount,          tvb, local_offset, 1, FALSE);
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_HOQLife,               tvb, local_offset, 1, FALSE); local_offset +=1;

    /* OperationalVLs */
    temp_item = proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_OperationalVLs,        tvb, local_offset, 1, FALSE);
    temp_val = (guint16)tvb_get_guint8(tvb, local_offset);

    /* 4 bit values = mask and shift */
    temp_val = temp_val & 0x00F0;
    temp_val = temp_val >> 4;

    proto_item_append_text(temp_item, ", %s", val_to_str(temp_val, OperationalVLs, "Reserved OperationalVLs Value! Possible Error"));
    /* End OperationalVLs */

    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_PartitionEnforcementInbound,       tvb, local_offset, 1, FALSE);
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_PartitionEnforcementOutbound,      tvb, local_offset, 1, FALSE);
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_FilterRawInbound,      tvb, local_offset, 1, FALSE);
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_FilterRawOutbound,     tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_M_KeyViolations,       tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_P_KeyViolations,       tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_Q_KeyViolations,       tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_GUIDCap,               tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_ClientReregister,      tvb, local_offset, 1, FALSE);
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_SubnetTimeOut,         tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_RespTimeValue,         tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_LocalPhyErrors,        tvb, local_offset, 1, FALSE);
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_OverrunErrors,         tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_MaxCreditHint,         tvb, local_offset, 2, FALSE); local_offset +=3; /* 2 + 1 Reserved */
    proto_tree_add_item(PortInfo_header_tree, hf_infiniband_PortInfo_LinkRoundTripLatency,  tvb, local_offset, 3, FALSE); local_offset +=3;
}

/* Parse P_KeyTable Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_P_KeyTable(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    gint i = 0;
    proto_tree *P_KeyTable_header_tree = NULL;
    proto_item *P_KeyTable_header_item = NULL;
    proto_item *tempItemLow = NULL;
    proto_item *tempItemHigh = NULL;

    if(!parentTree)
        return;

    P_KeyTable_header_item = proto_tree_add_item(parentTree, hf_infiniband_P_KeyTable_P_KeyTableBlock, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(P_KeyTable_header_item, "%s", "P_KeyTable");
    P_KeyTable_header_tree = proto_item_add_subtree(P_KeyTable_header_item, ett_pkeytable);

    for(i = 0; i < 32; i++)
    {
        tempItemLow = proto_tree_add_item(P_KeyTable_header_tree, hf_infiniband_P_KeyTable_MembershipType,  tvb, local_offset, 1, FALSE);
        tempItemHigh = proto_tree_add_item(P_KeyTable_header_tree, hf_infiniband_P_KeyTable_P_KeyBase,          tvb, local_offset, 2, FALSE); local_offset +=2;
        proto_item_append_text(tempItemLow, "(%u)", i);
        proto_item_append_text(tempItemHigh,"(%u)", i+1);
    }
}

/* Parse SLtoVLMappingTable Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_SLtoVLMappingTable(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *SLtoVLMappingTable_header_tree = NULL;
    proto_item *SLtoVLMappingTable_header_item = NULL;
    proto_item *tempItemLow = NULL;
    proto_item *tempItemHigh = NULL;
    gint i = 0;

    if(!parentTree)
        return;

    SLtoVLMappingTable_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(SLtoVLMappingTable_header_item, "%s", "SLtoVLMappingTable");
    SLtoVLMappingTable_header_tree = proto_item_add_subtree(SLtoVLMappingTable_header_item, ett_sltovlmapping);

    for(i = 0; i < 8; i++)
    {
        tempItemLow = proto_tree_add_item(SLtoVLMappingTable_header_tree, hf_infiniband_SLtoVLMappingTable_SLtoVL_HighBits,  tvb, local_offset, 1, FALSE);
        tempItemHigh = proto_tree_add_item(SLtoVLMappingTable_header_tree, hf_infiniband_SLtoVLMappingTable_SLtoVL_LowBits,  tvb, local_offset, 1, FALSE); local_offset +=1;
        proto_item_append_text(tempItemLow, "(%u)", i);
        proto_item_append_text(tempItemHigh,"(%u)", i+1);
    }
}

/* Parse VLArbitrationTable Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_VLArbitrationTable(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    gint i = 0;
    proto_tree *VLArbitrationTable_header_tree = NULL;
    proto_item *VLArbitrationTable_header_item = NULL;
    proto_item *tempItemLow = NULL;
    proto_item *tempItemHigh = NULL;

    if(!parentTree)
        return;

    VLArbitrationTable_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(VLArbitrationTable_header_item, "%s", "VLArbitrationTable");
    VLArbitrationTable_header_tree = proto_item_add_subtree(VLArbitrationTable_header_item, ett_vlarbitrationtable);

    for(i = 0; i < 32; i++)
    {
        tempItemLow = proto_tree_add_item(VLArbitrationTable_header_tree, hf_infiniband_VLArbitrationTable_VL,      tvb, local_offset, 1, FALSE); local_offset +=1;
        tempItemHigh = proto_tree_add_item(VLArbitrationTable_header_tree, hf_infiniband_VLArbitrationTable_Weight, tvb, local_offset, 1, FALSE); local_offset +=1;
        proto_item_append_text(tempItemLow, "(%u)", i);
        proto_item_append_text(tempItemHigh,"(%u)", i);
    }
}

/* Parse LinearForwardingTable Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_LinearForwardingTable(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint i = 0;
    gint local_offset = *offset;
    proto_tree *LinearForwardingTable_header_tree = NULL;
    proto_item *LinearForwardingTable_header_item = NULL;
    proto_item *tempItemLow = NULL;

    if(!parentTree)
        return;

    LinearForwardingTable_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(LinearForwardingTable_header_item, "%s", "LinearForwardingTable");
    LinearForwardingTable_header_tree = proto_item_add_subtree(LinearForwardingTable_header_item, ett_linearforwardingtable);

    for(i = 0; i < 64; i++)
    {
        tempItemLow = proto_tree_add_item(LinearForwardingTable_header_tree, hf_infiniband_LinearForwardingTable_Port, tvb, local_offset, 1, FALSE); local_offset +=1;
        proto_item_append_text(tempItemLow, "(%u)", i);
    }
}

/* Parse RandomForwardingTable Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_RandomForwardingTable(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint i = 0;
    gint local_offset = *offset;
    proto_tree *RandomForwardingTable_header_tree = NULL;
    proto_item *RandomForwardingTable_header_item = NULL;
    proto_item *tempItemLow = NULL;

    if(!parentTree)
        return;

    RandomForwardingTable_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(RandomForwardingTable_header_item, "%s", "RandomForwardingTable");
    RandomForwardingTable_header_tree = proto_item_add_subtree(RandomForwardingTable_header_item, ett_randomforwardingtable);

    for(i = 0; i < 16; i++)
    {
        tempItemLow = proto_tree_add_item(RandomForwardingTable_header_tree, hf_infiniband_RandomForwardingTable_LID,   tvb, local_offset, 2, FALSE); local_offset +=2;
        proto_item_append_text(tempItemLow, "(%u)", i);
        tempItemLow = proto_tree_add_item(RandomForwardingTable_header_tree, hf_infiniband_RandomForwardingTable_Valid, tvb, local_offset, 1, FALSE);
        proto_item_append_text(tempItemLow, "(%u)", i);
        tempItemLow = proto_tree_add_item(RandomForwardingTable_header_tree, hf_infiniband_RandomForwardingTable_LMC,   tvb, local_offset, 1, FALSE); local_offset +=1;
        proto_item_append_text(tempItemLow, "(%u)", i);
        tempItemLow = proto_tree_add_item(RandomForwardingTable_header_tree, hf_infiniband_RandomForwardingTable_Port,  tvb, local_offset, 1, FALSE); local_offset +=1;
        proto_item_append_text(tempItemLow, "(%u)", i);
    }
}

/* Parse NoticesAndTraps Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_MulticastForwardingTable(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint i = 0;
    gint local_offset = *offset;
    proto_tree *MulticastForwardingTable_header_tree = NULL;
    proto_item *MulticastForwardingTable_header_item = NULL;
    proto_item *tempItemLow = NULL;

    if(!parentTree)
        return;

    MulticastForwardingTable_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(MulticastForwardingTable_header_item, "%s", "MulticastForwardingTable");
    MulticastForwardingTable_header_tree = proto_item_add_subtree(MulticastForwardingTable_header_item, ett_multicastforwardingtable);

    for(i = 0; i < 16; i++)
    {
        tempItemLow = proto_tree_add_item(MulticastForwardingTable_header_tree, hf_infiniband_MulticastForwardingTable_PortMask, tvb, local_offset, 2, FALSE); local_offset +=2;
        proto_item_append_text(tempItemLow, "(%u)", i);
    }

}

/* Parse SMInfo Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_SMInfo(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *SMInfo_header_tree = NULL;
    proto_item *SMInfo_header_item = NULL;

    if(!parentTree)
        return;

    SMInfo_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(SMInfo_header_item, "%s", "SMInfo");
    SMInfo_header_tree = proto_item_add_subtree(SMInfo_header_item, ett_sminfo);

    proto_tree_add_item(SMInfo_header_tree, hf_infiniband_SMInfo_GUID,      tvb, local_offset, 8, FALSE); local_offset +=8;
    proto_tree_add_item(SMInfo_header_tree, hf_infiniband_SMInfo_SM_Key,    tvb, local_offset, 8, FALSE); local_offset +=8;
    proto_tree_add_item(SMInfo_header_tree, hf_infiniband_SMInfo_ActCount,  tvb, local_offset, 4, FALSE); local_offset +=4;
    proto_tree_add_item(SMInfo_header_tree, hf_infiniband_SMInfo_Priority,  tvb, local_offset, 1, FALSE);
    proto_tree_add_item(SMInfo_header_tree, hf_infiniband_SMInfo_SMState,   tvb, local_offset, 1, FALSE); local_offset +=1;
}

/* Parse VendorDiag Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_VendorDiag(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *VendorDiag_header_tree = NULL;
    proto_item *VendorDiag_header_item = NULL;

    if(!parentTree)
        return;

    VendorDiag_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(VendorDiag_header_item, "%s", "VendorDiag");
    VendorDiag_header_tree = proto_item_add_subtree(VendorDiag_header_item, ett_vendordiag);

    proto_tree_add_item(VendorDiag_header_tree, hf_infiniband_VendorDiag_NextIndex,     tvb, local_offset, 2, FALSE); local_offset +=2;
    proto_tree_add_item(VendorDiag_header_tree, hf_infiniband_VendorDiag_DiagData,      tvb, local_offset, 62, ENC_NA); local_offset +=62;
}

/* Parse LedInfo Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_LedInfo(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *LedInfo_header_tree = NULL;
    proto_item *LedInfo_header_item = NULL;

    if(!parentTree)
        return;

    LedInfo_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(LedInfo_header_item, "%s", "LedInfo");
    LedInfo_header_tree = proto_item_add_subtree(LedInfo_header_item, ett_ledinfo);

    proto_tree_add_item(LedInfo_header_tree, hf_infiniband_LedInfo_LedMask,     tvb, local_offset, 1, FALSE);
}

/* Parse LinkSpeedWidthPairsTable Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_LinkSpeedWidthPairsTable(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *LinkSpeedWidthPairsTable_header_tree = NULL;
    proto_item *LinkSpeedWidthPairsTable_header_item = NULL;

    if(!parentTree)
        return;

    LinkSpeedWidthPairsTable_header_item = proto_tree_add_item(parentTree, hf_infiniband_smp_data, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(LinkSpeedWidthPairsTable_header_item, "%s", "LinkSpeedWidthPairsTable");
    LinkSpeedWidthPairsTable_header_tree = proto_item_add_subtree(LinkSpeedWidthPairsTable_header_item, ett_linkspeedwidthpairs);

    proto_tree_add_item(LinkSpeedWidthPairsTable_header_tree, hf_infiniband_LinkSpeedWidthPairsTable_NumTables,     tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(LinkSpeedWidthPairsTable_header_tree, hf_infiniband_LinkSpeedWidthPairsTable_PortMask,      tvb, local_offset, 32, ENC_NA); local_offset +=32;
    proto_tree_add_item(LinkSpeedWidthPairsTable_header_tree, hf_infiniband_LinkSpeedWidthPairsTable_SpeedTwoFive,  tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(LinkSpeedWidthPairsTable_header_tree, hf_infiniband_LinkSpeedWidthPairsTable_SpeedFive,     tvb, local_offset, 1, FALSE); local_offset +=1;
    proto_tree_add_item(LinkSpeedWidthPairsTable_header_tree, hf_infiniband_LinkSpeedWidthPairsTable_SpeedTen,      tvb, local_offset, 1, FALSE); local_offset +=1;
}

/* Parse RID Field from Subnet Administraiton Packets.
* IN: SA_header_tree - the dissection tree of the subnet admin attribute.
*     tvb - the packet buffer
*      MadHeader - the Common MAD header from this packet.
* IN/OUT:  offset - the current and updated offset in the packet buffer */
static void parse_RID(proto_tree* SA_header_tree, tvbuff_t* tvb, gint *offset, MAD_Data* MadHeader)
{
    gint local_offset = *offset;
    if(!SA_header_tree)
    {
        return;
    }
        switch(MadHeader->attributeID)
        {
            case 0x0011:
                /* NodeRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_LID,   tvb, local_offset, 2, FALSE); local_offset+=2;
                local_offset+=2; /* Reserved bits */
                break;
            case 0x0012:
                /* PortInfoRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_EndportLID,    tvb, local_offset, 2, FALSE); local_offset+=2;
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_PortNum,       tvb, local_offset, 1, FALSE); local_offset+=1;
                local_offset+=1; /* Reserved bits */
                break;
            case 0x0013:
                /* SLtoVLMappingTableRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_LID,           tvb, local_offset, 2, FALSE); local_offset+=2;
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_InputPortNum,  tvb, local_offset, 1, FALSE); local_offset+=1;
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_OutputPortNum, tvb, local_offset, 1, FALSE); local_offset+=1;
                local_offset+=4; /* Reserved bits */
                break;
            case 0x0014:
                /* SwitchInfoRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_LID,           tvb, local_offset, 2, FALSE); local_offset+=2;
                local_offset+=2; /* Reserved bits */
                break;
            case 0x0015:
                /* LinearForwardingTableRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_LID,                   tvb, local_offset, 2, FALSE); local_offset+=2;
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_BlockNum_SixteenBit,   tvb, local_offset, 2, FALSE); local_offset+=2;
                local_offset+=4; /* Reserved bits */
                break;
            case 0x0016:
                /* RandomForwardingTableRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_LID,                   tvb, local_offset, 2, FALSE); local_offset+=2;
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_BlockNum_SixteenBit,   tvb, local_offset, 2, FALSE); local_offset+=2;
                local_offset+=4; /* Reserved bits */
                break;
            case 0x0017:
                /* MulticastForwardingTableRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_LID,               tvb, local_offset, 2, FALSE); local_offset+=2;
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_Position,          tvb, local_offset, 1, FALSE);
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_BlockNum_NineBit,  tvb, local_offset, 2, FALSE); local_offset+=2;
                local_offset+=4; /* Reserved bits */
                break;
            case 0x0036:
                /*VLArbitrationTableRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_LID,           tvb, local_offset, 2, FALSE); local_offset+=2;
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_OutputPortNum, tvb, local_offset, 1, FALSE); local_offset+=1;
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_BlockNum_EightBit,     tvb, local_offset, 1, FALSE); local_offset+=1;
                local_offset+=4; /* Reserved bits */
                break;
            case 0x0018:
                /* SMInfoRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_LID,               tvb, local_offset, 2, FALSE); local_offset+=2;
                local_offset+=2; /* Reserved bits */
                break;
            case 0x0033:
                /* P_KeyTableRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_LID,                   tvb, local_offset, 2, FALSE); local_offset+=2;
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_BlockNum_SixteenBit,   tvb, local_offset, 2, FALSE); local_offset+=2;
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_PortNum,               tvb, local_offset, 1, FALSE); local_offset+=1;
                local_offset+=3; /* Reserved bits */
                break;
            case 0x00F3:
                /* InformInfoRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_InformInfoRecord_SubscriberGID,   tvb, local_offset, 16, FALSE); local_offset+=16;
                proto_tree_add_item(SA_header_tree, hf_infiniband_InformInfoRecord_Enum,            tvb, local_offset, 2, FALSE); local_offset+=2;
                local_offset+=6; /* Reserved bits */
                break;
            case 0x0020:
                /* LinkRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_LinkRecord_FromLID,   tvb, local_offset, 2, FALSE); local_offset+=2;
                proto_tree_add_item(SA_header_tree, hf_infiniband_LinkRecord_FromPort,  tvb, local_offset, 1, FALSE); local_offset+=1;
                break;
            case 0x0031:
                /* ServiceRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_ServiceRecord_ServiceID,      tvb, local_offset, 8, FALSE); local_offset+=8;
                proto_tree_add_item(SA_header_tree, hf_infiniband_ServiceRecord_ServiceGID,     tvb, local_offset, 16, FALSE); local_offset+=16;
                proto_tree_add_item(SA_header_tree, hf_infiniband_ServiceRecord_ServiceP_Key,   tvb, local_offset, 2, FALSE); local_offset+=2;
                local_offset+=2;
                break;
            case 0x0038:
                /* MCMemberRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_MCMemberRecord_MGID,      tvb, local_offset, 16, FALSE); local_offset+=16;
                proto_tree_add_item(SA_header_tree, hf_infiniband_MCMemberRecord_PortGID,   tvb, local_offset, 16, FALSE); local_offset+=16;
                break;
            case 0x0030:
                /* GuidInfoRecord */
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_LID,               tvb, local_offset, 2, FALSE); local_offset+=2;
                proto_tree_add_item(SA_header_tree, hf_infiniband_SA_BlockNum_EightBit, tvb, local_offset, 1, FALSE); local_offset+=2;
                local_offset+=4;
                break;
            default:
                break;
        }

    *offset = local_offset;
}

/* Parse InformInfo Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_InformInfo(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *InformInfo_header_tree = NULL;
    proto_item *InformInfo_header_item = NULL;
    if(!parentTree)
    {
        return;
    }
    InformInfo_header_item = proto_tree_add_item(parentTree, hf_infiniband_SA, tvb, local_offset, 36, ENC_NA);
    proto_item_set_text(InformInfo_header_item, "%s", "InformInfo");
    InformInfo_header_tree = proto_item_add_subtree(InformInfo_header_item, ett_informinfo);

    proto_tree_add_item(InformInfo_header_tree, hf_infiniband_InformInfo_GID,                   tvb, local_offset, 16, FALSE); local_offset+=16;
    proto_tree_add_item(InformInfo_header_tree, hf_infiniband_InformInfo_LIDRangeBegin,         tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(InformInfo_header_tree, hf_infiniband_InformInfo_LIDRangeEnd,           tvb, local_offset, 2, FALSE); local_offset+=2;
    local_offset+=2; /* Reserved Bits */
    proto_tree_add_item(InformInfo_header_tree, hf_infiniband_InformInfo_IsGeneric,             tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(InformInfo_header_tree, hf_infiniband_InformInfo_Subscribe,             tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(InformInfo_header_tree, hf_infiniband_InformInfo_Type,                  tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(InformInfo_header_tree, hf_infiniband_InformInfo_TrapNumberDeviceID,    tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(InformInfo_header_tree, hf_infiniband_InformInfo_QPN,                   tvb, local_offset, 3, FALSE); local_offset+=3;
    proto_tree_add_item(InformInfo_header_tree, hf_infiniband_InformInfo_RespTimeValue,         tvb, local_offset, 1, FALSE); local_offset+=1;
    local_offset+=1;
    proto_tree_add_item(InformInfo_header_tree, hf_infiniband_InformInfo_ProducerTypeVendorID,  tvb, local_offset, 3, FALSE); local_offset+=3;

}
/* Parse LinkRecord Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_LinkRecord(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *LinkRecord_header_tree = NULL;
    proto_item *LinkRecord_header_item = NULL;

    if(!parentTree)
    {
        return;
    }

    LinkRecord_header_item = proto_tree_add_item(parentTree, hf_infiniband_SA, tvb, local_offset, 3, ENC_NA);
    proto_item_set_text(LinkRecord_header_item, "%s", "LinkRecord");
    LinkRecord_header_tree = proto_item_add_subtree(LinkRecord_header_item, ett_linkrecord);

    proto_tree_add_item(LinkRecord_header_tree, hf_infiniband_LinkRecord_ToPort,    tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(LinkRecord_header_tree, hf_infiniband_LinkRecord_ToLID,     tvb, local_offset, 2, FALSE); local_offset +=2;

}
/* Parse ServiceRecord Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_ServiceRecord(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *ServiceRecord_header_tree = NULL;
    proto_item *ServiceRecord_header_item = NULL;
    proto_item *tempData = NULL;

    if(!parentTree)
    {
        return;
    }

    ServiceRecord_header_item = proto_tree_add_item(parentTree, hf_infiniband_SA, tvb, local_offset, 176, ENC_NA);
    proto_item_set_text(ServiceRecord_header_item, "%s", "ServiceRecord");
    ServiceRecord_header_tree = proto_item_add_subtree(ServiceRecord_header_item, ett_servicerecord);

    proto_tree_add_item(ServiceRecord_header_tree, hf_infiniband_ServiceRecord_ServiceLease,    tvb, local_offset, 4, FALSE); local_offset+=4;
    proto_tree_add_item(ServiceRecord_header_tree, hf_infiniband_ServiceRecord_ServiceKey,      tvb, local_offset, 16, ENC_NA); local_offset+=16;
    proto_tree_add_item(ServiceRecord_header_tree, hf_infiniband_ServiceRecord_ServiceName,     tvb, local_offset, 64, ENC_NA); local_offset+=64;

    tempData = proto_tree_add_item(ServiceRecord_header_tree, hf_infiniband_ServiceRecord_ServiceData,      tvb, local_offset, 16, ENC_NA); local_offset+=16;
    proto_item_append_text(tempData, "%s", "(ServiceData 8.1, 8.16)");
    tempData = proto_tree_add_item(ServiceRecord_header_tree, hf_infiniband_ServiceRecord_ServiceData,      tvb, local_offset, 16, ENC_NA); local_offset+=16;
    proto_item_append_text(tempData, "%s", "(ServiceData 16.1, 16.8)");
    tempData = proto_tree_add_item(ServiceRecord_header_tree, hf_infiniband_ServiceRecord_ServiceData,      tvb, local_offset, 16, ENC_NA); local_offset+=16;
    proto_item_append_text(tempData, "%s", "(ServiceData 32.1, 32.4)");
    tempData = proto_tree_add_item(ServiceRecord_header_tree, hf_infiniband_ServiceRecord_ServiceData,      tvb, local_offset, 16, ENC_NA); local_offset+=16;
    proto_item_append_text(tempData, "%s", "(ServiceData 64.1, 64.2)");

}
/* Parse PathRecord Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_PathRecord(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *PathRecord_header_tree = NULL;
    proto_item *PathRecord_header_item = NULL;

    if(!parentTree)
    {
        return;
    }

    PathRecord_header_item = proto_tree_add_item(parentTree, hf_infiniband_SA, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(PathRecord_header_item, "%s", "PathRecord");
    PathRecord_header_tree = proto_item_add_subtree(PathRecord_header_item, ett_pathrecord);
    local_offset += 8; /* Reserved Bits */

    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_DGID,          tvb, local_offset, 16, FALSE); local_offset+=16;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_SGID,          tvb, local_offset, 16, FALSE); local_offset+=16;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_DLID,          tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_SLID,          tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_RawTraffic,    tvb, local_offset, 1, FALSE);
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_FlowLabel,     tvb, local_offset, 3, FALSE); local_offset+=3;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_HopLimit,      tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_TClass,        tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_Reversible,    tvb, local_offset, 1, FALSE);
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_NumbPath,      tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_P_Key,         tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_SL,            tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_MTUSelector,   tvb, local_offset, 1, FALSE);
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_MTU,           tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_RateSelector,  tvb, local_offset, 1, FALSE);
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_Rate,          tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_PacketLifeTimeSelector,    tvb, local_offset, 1, FALSE);
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_PacketLifeTime,            tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(PathRecord_header_tree, hf_infiniband_PathRecord_Preference,                tvb, local_offset, 1, FALSE); local_offset+=1;
}
/* Parse MCMemberRecord Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_MCMemberRecord(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *MCMemberRecord_header_tree = NULL;
    proto_item *MCMemberRecord_header_item = NULL;

    if(!parentTree)
    {
        return;
    }

    MCMemberRecord_header_item = proto_tree_add_item(parentTree, hf_infiniband_SA, tvb, local_offset, 64, ENC_NA);
    proto_item_set_text(MCMemberRecord_header_item, "%s", "MCMemberRecord");
    MCMemberRecord_header_tree = proto_item_add_subtree(MCMemberRecord_header_item, ett_mcmemberrecord);

    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_Q_Key,         tvb, local_offset, 4, FALSE); local_offset+=4;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_MLID,          tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_MTUSelector,   tvb, local_offset, 1, FALSE);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_MTU,           tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_TClass,        tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_P_Key,         tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_RateSelector,  tvb, local_offset, 1, FALSE);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_Rate,          tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_PacketLifeTimeSelector,    tvb, local_offset, 1, FALSE);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_PacketLifeTime,            tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_SL,            tvb, local_offset, 1, FALSE);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_FlowLabel,     tvb, local_offset, 3, FALSE); local_offset+=3;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_HopLimit,      tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_Scope,         tvb, local_offset, 1, FALSE);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_JoinState,     tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_infiniband_MCMemberRecord_ProxyJoin,     tvb, local_offset, 1, FALSE); local_offset+=3;

}
/* Parse TraceRecord Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_TraceRecord(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *TraceRecord_header_tree = NULL;
    proto_item *TraceRecord_header_item = NULL;

    if(!parentTree)
    {
        return;
    }

    TraceRecord_header_item = proto_tree_add_item(parentTree, hf_infiniband_SA, tvb, local_offset, 46, ENC_NA);
    proto_item_set_text(TraceRecord_header_item, "%s", "TraceRecord");
    TraceRecord_header_tree = proto_item_add_subtree(TraceRecord_header_item, ett_tracerecord);

    proto_tree_add_item(TraceRecord_header_tree, hf_infiniband_TraceRecord_GIDPrefix,       tvb, local_offset, 8, FALSE); local_offset+=8;
    proto_tree_add_item(TraceRecord_header_tree, hf_infiniband_TraceRecord_IDGeneration,    tvb, local_offset, 2, FALSE); local_offset+=2;
    local_offset+=1; /* Reserved Bits */
    proto_tree_add_item(TraceRecord_header_tree, hf_infiniband_TraceRecord_NodeType,        tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(TraceRecord_header_tree, hf_infiniband_TraceRecord_NodeID,          tvb, local_offset, 8, FALSE); local_offset+=8;
    proto_tree_add_item(TraceRecord_header_tree, hf_infiniband_TraceRecord_ChassisID,       tvb, local_offset, 8, FALSE); local_offset+=8;
    proto_tree_add_item(TraceRecord_header_tree, hf_infiniband_TraceRecord_EntryPortID,     tvb, local_offset, 8, FALSE); local_offset+=8;
    proto_tree_add_item(TraceRecord_header_tree, hf_infiniband_TraceRecord_ExitPortID,      tvb, local_offset, 8, FALSE); local_offset+=8;
    proto_tree_add_item(TraceRecord_header_tree, hf_infiniband_TraceRecord_EntryPort,       tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(TraceRecord_header_tree, hf_infiniband_TraceRecord_ExitPort,        tvb, local_offset, 1, FALSE); local_offset+=1;
}
/* Parse MultiPathRecord Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_MultiPathRecord(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *MultiPathRecord_header_tree = NULL;
    proto_item *MultiPathRecord_header_item = NULL;
    proto_item *SDGID = NULL;
    guint8 SDGIDCount = 0;
    guint8 DGIDCount = 0;
    guint32 i = 0;

    if(!parentTree)
    {
        return;
    }

    MultiPathRecord_header_item = proto_tree_add_item(parentTree, hf_infiniband_SA, tvb, local_offset, 200, ENC_NA);
    proto_item_set_text(MultiPathRecord_header_item, "%s", "MultiPathRecord");
    MultiPathRecord_header_tree = proto_item_add_subtree(MultiPathRecord_header_item, ett_multipathrecord);

    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_RawTraffic,      tvb, local_offset, 1, FALSE);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_FlowLabel,       tvb, local_offset, 3, FALSE); local_offset+=3;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_HopLimit,        tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_TClass,          tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_Reversible,      tvb, local_offset, 1, FALSE);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_NumbPath,        tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_P_Key,           tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_SL,              tvb, local_offset, 2, FALSE); local_offset+=2;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_MTUSelector,     tvb, local_offset, 1, FALSE);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_MTU,             tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_RateSelector,    tvb, local_offset, 1, FALSE);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_Rate,            tvb, local_offset, 1, FALSE); local_offset+=1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_PacketLifeTimeSelector,  tvb, local_offset, 1, FALSE);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_PacketLifeTime,          tvb, local_offset, 1, FALSE); local_offset+=1;
    local_offset+=1; /* Reserved Bits */
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_IndependenceSelector,    tvb, local_offset, 1, FALSE);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_GIDScope,                tvb, local_offset, 1, FALSE); local_offset+=1;

    SDGIDCount = tvb_get_guint8(tvb, local_offset);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_SGIDCount,       tvb, local_offset, 1, FALSE); local_offset+=1;
    DGIDCount = tvb_get_guint8(tvb, local_offset);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_DGIDCount,       tvb, local_offset, 1, FALSE); local_offset+=1;
    local_offset+=7; /*Reserved Bits */

    for(i = 0; i < SDGIDCount; i++)
    {
        SDGID = proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_SDGID,       tvb, local_offset, 16, FALSE); local_offset+=16;
        proto_item_set_text(SDGID, "(%s%u)","SGID", i);
    }
    for(i = 0; i < DGIDCount; i++)
    {
        SDGID = proto_tree_add_item(MultiPathRecord_header_tree, hf_infiniband_MultiPathRecord_SDGID,       tvb, local_offset, 16, FALSE); local_offset+=16;
        proto_item_set_text(SDGID, "(%s%u)","DGID", i);
    }
}
/* Parse ServiceAssociationRecord Attribute
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       MadHeader - The common MAD header of the current SMP/SMA  */
static void parse_ServiceAssociationRecord(proto_tree* parentTree, tvbuff_t* tvb, gint *offset)
{
    gint local_offset = *offset;
    proto_tree *ServiceAssociationRecord_header_tree = NULL;
    proto_item *ServiceAssociationRecord_header_item = NULL;

    if(!parentTree)
    {
        return;
    }

    ServiceAssociationRecord_header_item = proto_tree_add_item(parentTree, hf_infiniband_SA, tvb, local_offset, 80, ENC_NA);
    proto_item_set_text(ServiceAssociationRecord_header_item, "%s", "ServiceAssociationRecord");
    ServiceAssociationRecord_header_tree = proto_item_add_subtree(ServiceAssociationRecord_header_item, ett_serviceassocrecord);

    proto_tree_add_item(ServiceAssociationRecord_header_tree, hf_infiniband_ServiceAssociationRecord_ServiceKey,        tvb, local_offset, 16, ENC_NA); local_offset +=16;
    proto_tree_add_item(ServiceAssociationRecord_header_tree, hf_infiniband_ServiceAssociationRecord_ServiceName,       tvb, local_offset, 64, FALSE); local_offset +=64;
}

/* Parse PortCounters MAD from the Performance management class.
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       pinfo - The packet info structure with column information  */
static void parse_PERF_PortCounters(proto_tree* parentTree, tvbuff_t* tvb, packet_info *pinfo, gint *offset)
{
    proto_item *perf_item = NULL;
    proto_tree *perf_tree = NULL;
    gint local_offset = *offset;

    col_set_str(pinfo->cinfo, COL_INFO, "PERF (PortCounters)");

    perf_item = proto_tree_add_item(parentTree, hf_infiniband_PortCounters, tvb, local_offset, 40, ENC_NA);
    perf_tree = proto_item_add_subtree(perf_item, ett_perfclass);

    local_offset += 40; /* skip reserved field */
    local_offset += 1;  /* skip reserved field */
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_PortSelect,  tvb, local_offset, 1, FALSE); local_offset += 1;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_CounterSelect, tvb, local_offset, 2, FALSE); local_offset += 2;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_SymbolErrorCounter, tvb, local_offset, 2, FALSE); local_offset += 2;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_LinkErrorRecoveryCounter, tvb, local_offset, 1, FALSE); local_offset += 1;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_LinkDownedCounter, tvb, local_offset, 1, FALSE); local_offset += 1;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_PortRcvErrors, tvb, local_offset, 2, FALSE); local_offset += 2;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_PortRcvRemotePhysicalErrors, tvb, local_offset, 2, FALSE); local_offset += 2;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_PortRcvSwitchRelayErrors, tvb, local_offset, 2, FALSE); local_offset += 2;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_PortXmitDiscards, tvb, local_offset, 2, FALSE); local_offset += 2;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_PortXmitConstraintErrors, tvb, local_offset, 1, FALSE); local_offset += 1;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_PortRcvConstraintErrors, tvb, local_offset, 1, FALSE); local_offset += 1;
    local_offset += 1;  /* skip reserved field */
    proto_tree_add_bits_item(perf_tree, hf_infiniband_PortCounters_LocalLinkIntegrityErrors, tvb, local_offset*8, 4, FALSE);
    proto_tree_add_bits_item(perf_tree, hf_infiniband_PortCounters_ExcessiveBufferOverrunErrors, tvb, local_offset*8 + 4, 4, FALSE); local_offset += 1;
    local_offset += 2;  /* skip reserved field */
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_VL15Dropped, tvb, local_offset, 2, FALSE); local_offset += 2;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_PortXmitData, tvb, local_offset, 4, FALSE); local_offset += 4;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_PortRcvData, tvb, local_offset, 4, FALSE); local_offset += 4;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_PortXmitPkts, tvb, local_offset, 4, FALSE); local_offset += 4;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCounters_PortRcvPkts, tvb, local_offset, 4, FALSE); local_offset += 4;

    *offset = local_offset; /* update caller's offset to point to end of the PortCounters payload */
    return;
}

/* Parse PortCountersExtended MAD from the Performance management class.
* IN:   parentTree - The tree to add the dissection to
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       pinfo - The packet info structure with column information  */
static void parse_PERF_PortCountersExtended(proto_tree* parentTree, tvbuff_t* tvb, packet_info *pinfo, gint *offset)
{
    proto_item *perf_item = NULL;
    proto_tree *perf_tree = NULL;
    gint local_offset = *offset;

    col_set_str(pinfo->cinfo, COL_INFO, "PERF (PortCountersExtended)");

    perf_item = proto_tree_add_item(parentTree, hf_infiniband_PortCountersExt, tvb, local_offset, 72, ENC_NA);
    perf_tree = proto_item_add_subtree(perf_item, ett_perfclass);

    local_offset += 40; /* skip reserved field */
    local_offset += 1;  /* skip reserved field */
    proto_tree_add_item(perf_tree, hf_infiniband_PortCountersExt_PortSelect,  tvb, local_offset, 1, FALSE); local_offset += 1;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCountersExt_CounterSelect, tvb, local_offset, 2, FALSE); local_offset += 2;
    local_offset += 4;  /* skip reserved field */
    proto_tree_add_item(perf_tree, hf_infiniband_PortCountersExt_PortXmitData, tvb, local_offset, 8, FALSE); local_offset += 8;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCountersExt_PortRcvData, tvb, local_offset, 8, FALSE); local_offset += 8;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCountersExt_PortXmitPkts, tvb, local_offset, 8, FALSE); local_offset += 8;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCountersExt_PortRcvPkts, tvb, local_offset, 8, FALSE); local_offset += 8;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCountersExt_PortUnicastXmitPkts, tvb, local_offset, 8, FALSE); local_offset += 8;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCountersExt_PortUnicastRcvPkts, tvb, local_offset, 8, FALSE); local_offset += 8;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCountersExt_PortMulticastXmitPkts, tvb, local_offset, 8, FALSE); local_offset += 8;
    proto_tree_add_item(perf_tree, hf_infiniband_PortCountersExt_PortMulticastRcvPkts, tvb, local_offset, 8, FALSE); local_offset += 8;

    *offset = local_offset; /* update caller's offset to point to end of the PortCountersExt payload */
    return;
}

/* dissect_general_info
* Used to extract very few values from the packet in the case that full dissection is disabled by the user.
* IN:
*       tvb - The tvbbuff of packet data
*       offset - The offset in TVB where the attribute begins
*       pinfo - The packet info structure with column information
*       starts_with_grh - If true this packets start with a GRH header, otherwise with LRH  */
static void dissect_general_info(tvbuff_t *tvb, gint offset, packet_info *pinfo, gboolean starts_with_grh)
{
    guint8 lnh_val = 0;             /* The Link Next Header Value.  Tells us which headers are coming */
    gboolean bthFollows = FALSE;    /* Tracks if we are parsing a BTH.  This is a significant decision point */
    guint8 virtualLane = 0;         /* The Virtual Lane of the current Packet */
    guint8 opCode = 0;              /* OpCode from BTH header. */
    gint32 nextHeaderSequence = -1; /* defined by this dissector. #define which indicates the upcoming header sequence from OpCode */
    guint8 nxtHdr = 0;              /* that must be available for that header. */
    struct e_in6_addr SRCgid;       /* Struct to display ipv6 Address */
    struct e_in6_addr DSTgid;       /* Struct to display ipv6 Address */
    guint8 management_class = 0;
    MAD_Data MadData;

    if (starts_with_grh) {
        /* this is a RoCE packet, skip LRH parsing */
        lnh_val = IBA_GLOBAL;
        goto skip_lrh;
    }

    virtualLane =  tvb_get_guint8(tvb, offset);
    virtualLane = virtualLane & 0xF0;
    offset+=1;

    /* Save Link Next Header... This tells us what the next header is. */
    lnh_val =  tvb_get_guint8(tvb, offset);
    lnh_val = lnh_val & 0x03;
    offset+=1;

    /* Set destination in packet view. */
    *((guint16*) dst_addr) = tvb_get_ntohs(tvb, offset);
    SET_ADDRESS(&pinfo->dst, AT_IB, sizeof(guint16), dst_addr);

    offset+=4;

    /* Set Source in packet view. */
    *((guint16*) src_addr) = tvb_get_ntohs(tvb, offset);
    SET_ADDRESS(&pinfo->src, AT_IB, sizeof(guint16), src_addr);

    offset+=2;

skip_lrh:

    switch(lnh_val)
    {
        case IBA_GLOBAL:
            offset +=6;
            nxtHdr = tvb_get_guint8(tvb, offset);
            offset += 2;

            tvb_get_ipv6(tvb, offset, &SRCgid);

            /* Set source GID in packet view. */
            memcpy(src_addr, &SRCgid, GID_SIZE);
            SET_ADDRESS(&pinfo->src, AT_IB, GID_SIZE, src_addr);

            offset += 16;

            tvb_get_ipv6(tvb, offset, &DSTgid);

            /* Set destination GID in packet view. */
            memcpy(dst_addr, &DSTgid, GID_SIZE);
            SET_ADDRESS(&pinfo->dst, AT_IB, GID_SIZE, dst_addr);

            offset += 16;

            if(nxtHdr != 0x1B)
            {
                /* Some kind of packet being transported globally with IBA, but locally it is not IBA - no BTH following. */
                break;
            }
            /* else
             * {
             *      Fall through switch and start parsing Local Headers and BTH
             * }
             */
        case IBA_LOCAL:
            bthFollows = TRUE;

            /* Get the OpCode - this tells us what headers are following */
            opCode = tvb_get_guint8(tvb, offset);
            col_append_str(pinfo->cinfo, COL_INFO, val_to_str((guint32)opCode, OpCodeMap, "Unknown OpCode"));
            offset +=12;
            break;
        case IP_NON_IBA:
            /* Raw IPv6 Packet */
            g_snprintf(dst_addr,  ADDR_MAX_LEN, "IPv6 over IB Packet");
            SET_ADDRESS(&pinfo->dst,  AT_STRINGZ, (int)strlen(dst_addr)+1, dst_addr);
            break;
        case RAW:
            break;
        default:
            break;
    }

    if(bthFollows)
    {
        /* Find our next header sequence based on the Opcode
         * Since we're not doing dissection here, we just need the proper offsets to get our labels in packet view */

        nextHeaderSequence = find_next_header_sequence((guint32) opCode);
        switch(nextHeaderSequence)
        {
            case RDETH_DETH_PAYLD:
                offset += 4; /* RDETH */
                offset += 8; /* DETH */
                break;
            case RDETH_DETH_RETH_PAYLD:
                offset += 4; /* RDETH */
                offset += 8; /* DETH */
                offset += 16; /* RETH */
                break;
            case RDETH_DETH_IMMDT_PAYLD:
                offset += 4; /* RDETH */
                offset += 8; /* DETH */
                offset += 4; /* IMMDT */
                break;
            case RDETH_DETH_RETH_IMMDT_PAYLD:
                offset += 4; /* RDETH */
                offset += 8; /* DETH */
                offset += 16; /* RETH */
                offset += 4; /* IMMDT */
                break;
            case RDETH_DETH_RETH:
                offset += 4; /* RDETH */
                offset += 8; /* DETH */
                offset += 16; /* RETH */
                break;
            case RDETH_AETH_PAYLD:
                offset += 4; /* RDETH */
                offset += 4; /* AETH */
                break;
            case RDETH_PAYLD:
                offset += 4; /* RDETH */
                break;
            case RDETH_AETH:
                offset += 4; /* RDETH */
                offset += 4; /* AETH */
                break;
            case RDETH_AETH_ATOMICACKETH:
                offset += 4; /* RDETH */
                offset += 4; /* AETH */
                offset += 8; /* AtomicAckETH */
                break;
            case RDETH_DETH_ATOMICETH:
                offset += 4; /* RDETH */
                offset += 8; /* DETH */
                offset += 28; /* AtomicETH */
                break;
            case RDETH_DETH:
                offset += 4; /* RDETH */
                offset += 8; /* DETH */
                break;
            case DETH_PAYLD:
                offset += 8; /* DETH */
                break;
            case PAYLD:
                break;
            case IMMDT_PAYLD:
                offset += 4; /* IMMDT */
                break;
            case RETH_PAYLD:
                offset += 16; /* RETH */
                break;
            case RETH:
                offset += 16; /* RETH */
                break;
            case AETH_PAYLD:
                offset += 4; /* AETH */
                break;
            case AETH:
                offset += 4; /* AETH */
                break;
            case AETH_ATOMICACKETH:
                offset += 4; /* AETH */
                offset += 8; /* AtomicAckETH */
                break;
            case ATOMICETH:
                offset += 28; /* AtomicETH */
                break;
            case IETH_PAYLD:
                offset += 4; /* IETH */
                break;
            case DETH_IMMDT_PAYLD:
                offset += 8; /* DETH */
                offset += 4; /* IMMDT */
                break;
            default:
                break;
        }
    }
    if(virtualLane == 0xF0)
    {
        management_class =  tvb_get_guint8(tvb, offset + 1);
        if(((management_class >= (guint8)VENDOR_1_START) && (management_class <= (guint8)VENDOR_1_END))
        || ((management_class >= (guint8)VENDOR_2_START) && (management_class <= (guint8)VENDOR_2_END)))
        {
            return;
        }
        else if((management_class >= (guint8)APPLICATION_START) && (management_class <= (guint8)APPLICATION_END))
        {
            return;
        }
        else if(((management_class == (guint8)0x00) || (management_class == (guint8)0x02))
            || ((management_class >= (guint8)0x50) && (management_class <= (guint8)0x80))
            || ((management_class >= (guint8)0x82)))
        {
            return;
        }
        else /* we have a normal management_class */
        {
            parse_MAD_Common(NULL, tvb, &offset, &MadData);
            label_SUBM_Method(NULL, &MadData, pinfo);
            label_SUBM_Attribute(NULL, &MadData, pinfo);
        }
    }

    return;
}

/* Protocol Registration */
void proto_register_infiniband(void)
{
    module_t *infiniband_module;

    /* Field dissector structures.
    * For reserved fields, reservedX denotes the reserved field is X bits in length.
    * e.g. reserved2 is a reserved field 2 bits in length.
    * The third parameter is a filter string associated for this field.
    * So for instance, to filter packets for a given virtual lane,
    * The filter (infiniband.LRH.vl == 3) or something similar would be used. */

    /* XXX: ToDo: Verify against Infiniband 1.2.1 Specification                           */
    /*            Fields verified/corrected: Those after comment "XX: All following ..."  */

    /* meanings for MAD method field */
    static const value_string mad_method_str[] = {
        { 0x01, "Get()" },
        { 0x02, "Set()" },
        { 0x81, "GetResp()" },
        { 0x03, "Send()" },
        { 0x05, "Trap()" },
        { 0x06, "Report()" },
        { 0x86, "ReportResp()" },
        { 0x07, "TrapRepress()" },
        { 0,    NULL }
    };

    static hf_register_info hf[] = {
        /* Local Route Header (LRH) */
        { &hf_infiniband_LRH, {
                "Local Route Header", "infiniband.lrh",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_virtual_lane, {
                "Virtual Lane", "infiniband.lrh.vl",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_link_version, {
                "Link Version", "infiniband.lrh.lver",
                FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}
        },
        { &hf_infiniband_service_level, {
                "Service Level", "infiniband.lrh.sl",
                FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_reserved2, {
                "Reserved (2 bits)", "infiniband.lrh.reserved2",
                FT_UINT8, BASE_DEC, NULL, 0x0C, NULL, HFILL}
        },
        { &hf_infiniband_link_next_header, {
                "Link Next Header", "infiniband.lrh.lnh",
                FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL}
        },
        { &hf_infiniband_destination_local_id, {
                "Destination Local ID", "infiniband.lrh.dlid",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_reserved5, {
                "Reserved (5 bits)", "infiniband.lrh.reserved5",
                FT_UINT16, BASE_DEC, NULL, 0xF800, NULL, HFILL}
        },
        { &hf_infiniband_packet_length, {
                "Packet Length", "infiniband.lrh.pktlen",
                FT_UINT16, BASE_DEC, NULL, 0x07FF, NULL, HFILL}
        },
        { &hf_infiniband_source_local_id, {
                "Source Local ID", "infiniband.lrh.slid",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },

        /* Global Route Header (GRH) */
        { &hf_infiniband_GRH, {
                "Global Route Header", "infiniband.grh",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_ip_version, {
                "IP Version", "infiniband.grh.ipver",
                FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_traffic_class, {
                "Traffic Class", "infiniband.grh.tclass",
                FT_UINT16, BASE_DEC, NULL, 0x0FF0, NULL, HFILL}
        },
        { &hf_infiniband_flow_label, {
                "Flow Label", "infiniband.grh.flowlabel",
                FT_UINT32, BASE_DEC, NULL, 0x000FFFFF, NULL, HFILL}
        },
        { &hf_infiniband_payload_length, {
                "Payload Length", "infiniband.grh.paylen",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_next_header, {
                "Next Header", "infiniband.grh.nxthdr",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_hop_limit, {
                "Hop Limit", "infiniband.grh.hoplmt",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_source_gid, {
                "Source GID", "infiniband.grh.sgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_destination_gid, {
                "Destination GID", "infiniband.grh.dgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* Base Transport Header (BTH) */
        { &hf_infiniband_BTH, {
                "Base Transport Header", "infiniband.bth",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_opcode, {
                "Opcode", "infiniband.bth.opcode",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_solicited_event, {
                "Solicited Event", "infiniband.bth.se",
                FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_migreq, {
                "MigReq", "infiniband.bth.m",
                FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        { &hf_infiniband_pad_count, {
                "Pad Count", "infiniband.bth.padcnt",
                FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL}
        },
        { &hf_infiniband_transport_header_version, {
                "Header Version", "infiniband.bth.tver",
                FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}
        },
        { &hf_infiniband_partition_key, {
                "Partition Key", "infiniband.bth.p_key",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_reserved8, {
                "Reserved (8 bits)", "infiniband.bth.reserved8",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_destination_qp, {
                "Destination Queue Pair", "infiniband.bth.destqp",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_acknowledge_request, {
                "Acknowledge Request", "infiniband.bth.a",
                FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_reserved7, {
                "Reserved (7 bits)", "infiniband.bth.reserved7",
                FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL}
        },
        { &hf_infiniband_packet_sequence_number, {
                "Packet Sequence Number", "infiniband.bth.psn",
                FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },

        /* Raw Header (RWH) */
        { &hf_infiniband_RWH, {
                "Raw Header", "infiniband.rwh",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_reserved16_RWH, {
                "Reserved (16 bits)", "infiniband.rwh.reserved",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_etype, {
                "Ethertype", "infiniband.rwh.etype",
                FT_UINT16, BASE_HEX, NULL /*VALS(etype_vals)*/, 0x0, "Type", HFILL }
        },

        /* Reliable Datagram Extended Transport Header (RDETH) */
        { &hf_infiniband_RDETH, {
                "Reliable Datagram Extended Transport Header", "infiniband.rdeth",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_reserved8_RDETH, {
                "Reserved (8 bits)", "infiniband.rdeth.reserved8",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_ee_context, {
                "E2E Context", "infiniband.rdeth.eecnxt",
                FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },

        /* Datagram Extended Transport Header (DETH) */
        { &hf_infiniband_DETH, {
                "Datagram Extended Transport Header", "infiniband.deth",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_queue_key, {
                "Queue Key", "infiniband.deth.q_key",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_reserved8_DETH, {
                "Reserved (8 bits)", "infiniband.deth.reserved8",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_source_qp, {
                "Source Queue Pair", "infiniband.deth.srcqp",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* RDMA Extended Transport Header (RETH) */
        { &hf_infiniband_RETH, {
                "RDMA Extended Transport Header", "infiniband.reth",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_virtual_address, {
                "Virtual Address", "infiniband.reth.va",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_remote_key, {
                "Remote Key", "infiniband.reth.r_key",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_dma_length, {
                "DMA Length", "infiniband.reth.dmalen",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },

        /* Atomic Extended Transport Header (AtomicETH) */
        { &hf_infiniband_AtomicETH, {
                "Atomic Extended Transport Header", "infiniband.atomiceth",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
#if 0
        { &hf_infiniband_virtual_address_AtomicETH, {
                "Virtual Address", "infiniband.atomiceth.va",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_remote_key_AtomicETH, {
                "Remote Key", "infiniband.atomiceth.r_key",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
#endif
        { &hf_infiniband_swap_or_add_data, {
                "Swap (Or Add) Data", "infiniband.atomiceth.swapdt",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_compare_data, {
                "Compare Data", "infiniband.atomiceth.cmpdt",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },

        /* ACK Extended Transport Header (AETH) */
        { &hf_infiniband_AETH, {
                "ACK Extended Transport Header", "infiniband.aeth",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_syndrome, {
                "Syndrome", "infiniband.aeth.syndrome",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_message_sequence_number, {
                "Message Sequence Number", "infiniband.aeth.msn",
                FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },

        /* Atomic ACK Extended Transport Header (AtomicAckETH) */
        { &hf_infiniband_AtomicAckETH, {
                "Atomic ACK Extended Transport Header", "infiniband.atomicacketh",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_original_remote_data, {
                "Original Remote Data", "infiniband.atomicacketh.origremdt",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },

        /* Immediate Extended Transport Header (ImmDT) */
        { &hf_infiniband_IMMDT, {
                "Immediate Data", "infiniband.immdt",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* Invalidate Extended Transport Header (IETH) */
        { &hf_infiniband_IETH, {
                "RKey", "infiniband.ieth",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* Payload */
        { &hf_infiniband_payload, {
                "Payload", "infiniband.payload",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_invariant_crc, {
                "Invariant CRC", "infiniband.invariant.crc",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_variant_crc, {
                "Variant CRC", "infiniband.variant.crc",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_raw_data, {
                "Raw Data", "infiniband.rawdata",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Unknown or Vendor Specific */
        { &hf_infiniband_vendor, {
                "Unknown/Vendor Specific Data", "infiniband.vendor",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* CM REQ Header */
        {&hf_cm_req_local_comm_id, {
                "Local Communication ID", "infiniband.cm.req",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_service_id, {
                "ServiceID", "infiniband.cm.req.serviceid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_local_ca_guid, {
                "Local CA GUID", "infiniband.cm.req.localcaguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_local_qkey, {
                "Local Q_Key", "infiniband.cm.req.localqkey",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_local_qpn, {
                "Local QPN", "infiniband.cm.req.localqpn",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_respo_res, {
                "Responder Resources", "infiniband.cm.req.responderres",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_local_eecn, {
                "Local EECN", "infiniband.cm.req.localeecn",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_init_depth, {
                "Initiator Depth", "infiniband.cm.req.initdepth",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_remote_eecn, {
                "Remote EECN", "infiniband.cm.req.remoteeecn",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_remote_cm_resp_to, {
                "Remote CM Response Timeout", "infiniband.cm.req.remoteresptout",
                FT_UINT8, BASE_HEX, NULL, 0x1f, NULL, HFILL}
        },
        {&hf_cm_req_transp_serv_type, {
                "Transport Service Type", "infiniband.cm.req.transpsvctype",
                FT_UINT8, BASE_HEX, NULL, 0x60, NULL, HFILL}
        },
        {&hf_cm_req_e2e_flow_ctrl, {
                "End-to-End Flow Control", "infiniband.cm.req.e2eflowctrl",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        {&hf_cm_req_start_psn, {
                "Starting PSN", "infiniband.cm.req.startpsn",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_local_cm_resp_to, {
                "Local CM Response Timeout", "infiniband.cm.req.localresptout",
                FT_UINT8, BASE_HEX, NULL, 0x1f, NULL, HFILL}
        },
        {&hf_cm_req_retry_count, {
                "Retry Count", "infiniband.cm.req.retrcount",
                FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        {&hf_cm_req_pkey, {
                "Partition Key", "infiniband.cm.req.pkey",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_path_pp_mtu, {
                "Path Packet Payload MTU", "infiniband.cm.req.pppmtu",
                FT_UINT8, BASE_HEX, NULL, 0xf, NULL, HFILL}
        },
        {&hf_cm_req_rdc_exists, {
                "RDC Exists", "infiniband.cm.req.rdcexist",
                FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL}
        },
        {&hf_cm_req_rnr_retry_count, {
                "RNR Retry Count", "infiniband.cm.req.rnrretrcount",
                FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        {&hf_cm_req_max_cm_retries, {
                "Max CM Retries", "infiniband.cm.req.maxcmretr",
                FT_UINT8, BASE_HEX, NULL, 0xf, NULL, HFILL}
        },
        {&hf_cm_req_srq, {
                "SRQ", "infiniband.cm.req.srq",
                FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL}
        },
        {&hf_cm_req_primary_local_lid, {
                "Primary Local Port LID", "infiniband.cm.req.prim_locallid",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_primary_remote_lid, {
                "Primary Remote Port LID", "infiniband.cm.req.prim_remotelid",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_primary_local_gid, {
                "Primary Local Port GID", "infiniband.cm.req.prim_localgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_primary_remote_gid, {
                "Primary Remote Port GID", "infiniband.cm.req.prim_remotegid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_primary_flow_label, {
                "Primary Flow Label", "infiniband.cm.req.prim_flowlabel",
                FT_UINT24, BASE_HEX, NULL, 0xfffff, NULL, HFILL}
        },
        {&hf_cm_req_primary_packet_rate, {
                "Primary Packet Rate", "infiniband.cm.req.prim_pktrate",
                FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        {&hf_cm_req_primary_traffic_class, {
                "Primary Traffic Class", "infiniband.cm.req.prim_tfcclass",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_primary_hop_limit, {
                "Primary Hop Limit", "infiniband.cm.req.prim_hoplim",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_primary_sl, {
                "Primary SL", "infiniband.cm.req.prim_sl",
                FT_UINT8, BASE_HEX, NULL, 0xf, NULL, HFILL}
        },
        {&hf_cm_req_primary_subnet_local, {
                "Primary Subnet Local", "infiniband.cm.req.prim_subnetlocal",
                FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL}
        },
        {&hf_cm_req_primary_local_ack_to, {
                "Primary Local ACK Timeout", "infiniband.cm.req.prim_localacktout",
                FT_UINT8, BASE_HEX, NULL, 0x1f, NULL, HFILL}
        },
        {&hf_cm_req_alt_local_lid, {
                "Alternate Local Port LID", "infiniband.cm.req.alt_locallid",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_alt_remote_lid, {
                "Alternate Remote Port LID", "infiniband.cm.req.alt_remotelid",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_alt_local_gid, {
                "Alternate Local Port GID", "infiniband.cm.req.alt_localgid",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_alt_remote_gid, {
                "Alternate Remote Port GID", "infiniband.cm.req.alt_remotegid",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_flow_label, {
                "Alternate Flow Label", "infiniband.cm.req.alt_flowlabel",
                FT_UINT24, BASE_HEX, NULL, 0xfffff, NULL, HFILL}
        },
        {&hf_cm_req_packet_rate, {
                "Alternate Packet Rate", "infiniband.cm.req.alt_pktrate",
                FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        {&hf_cm_req_alt_traffic_class, {
                "Alternate Traffic Class", "infiniband.cm.req.alt_tfcclass",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_alt_hop_limit, {
                "Alternate Hop Limit", "infiniband.cm.req.alt_hoplim",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_req_SL, {
                "Alternate SL", "infiniband.cm.req.alt_sl",
                FT_UINT8, BASE_HEX, NULL, 0xf, NULL, HFILL}
        },
        {&hf_cm_req_subnet_local, {
                "Alternate Subnet Local", "infiniband.cm.req.alt_subnetlocal",
                FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL}
        },
        {&hf_cm_req_local_ACK_timeout, {
                "Alternate Local ACK Timeout", "infiniband.cm.req.alt_localacktout",
                FT_UINT8, BASE_HEX, NULL, 0x1f, NULL, HFILL}
        },
        {&hf_cm_req_private_data, {
                "PrivateData", "infiniband.cm.req.private",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* CM REP Header */
        {&hf_cm_rep_localcommid, {
                "Local Communication ID", "infiniband.cm.rep",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rep_remotecommid, {
                "Remote Communication ID", "infiniband.cm.rep.remotecommid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rep_localqkey, {
                "Local Q_Key", "infiniband.cm.rep.localqkey",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rep_localqpn, {
                "Local QPN", "infiniband.cm.rep.localqpn",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rep_localeecontnum, {
                "Local EE Context Number", "infiniband.cm.rep.localeecn",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rep_startingpsn, {
                "Starting PSN", "infiniband.cm.rep.startpsn",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rep_responderres, {
                "Responder Resources", "infiniband.cm.rep.respres",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rep_initiatordepth, {
                "Initiator Depth", "infiniband.cm.rep.initdepth",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rep_tgtackdelay, {
                "Target ACK Delay", "infiniband.cm.rep.tgtackdelay",
                FT_UINT8, BASE_HEX, NULL, 0x1f, NULL, HFILL}
        },
        {&hf_cm_rep_failoveracc, {
                "Failover Accepted", "infiniband.cm.rep.failoveracc",
                FT_UINT8, BASE_HEX, NULL, 0x60, NULL, HFILL}
        },
        {&hf_cm_rep_e2eflowctl, {
                "End-To-End Flow Control", "infiniband.cm.rep.e2eflowctrl",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        {&hf_cm_rep_rnrretrycount, {
                "RNR Retry Count", "infiniband.cm.rep.rnrretrcount",
                FT_UINT8, BASE_HEX, NULL, 0x7, NULL, HFILL}
        },
        {&hf_cm_rep_srq, {
                "SRQ", "infiniband.cm.rep.srq",
                FT_UINT8, BASE_HEX, NULL, 0x8, NULL, HFILL}
        },
        {&hf_cm_rep_localcaguid, {
                "Local CA GUID", "infiniband.cm.rep.localcaguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rep_privatedata, {
                "PrivateData", "infiniband.cm.rep.private",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* IB CM RTU Header */
        {&hf_cm_rtu_localcommid, {
                "Local Communication ID", "infiniband.cm.rtu.localcommid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rtu_remotecommid, {
                "Remote Communication ID", "infiniband.cm.rtu.remotecommid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rtu_privatedata, {
                "PrivateData", "infiniband.cm.rtu.private",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* CM REJ Header */
        {&hf_cm_rej_local_commid, {
                "Local Communication ID", "infiniband.cm.rej.localcommid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rej_remote_commid, {
                "Remote Communication ID", "infiniband.cm.rej.remotecommid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rej_msg_rej, {
                "Message REJected", "infiniband.cm.rej.msgrej",
                FT_UINT8, BASE_HEX, NULL, 0x3, NULL, HFILL}
        },
        {&hf_cm_rej_rej_info_len, {
                "Reject Info Length", "infiniband.cm.rej.rejinfolen",
                FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL}
        },
        {&hf_cm_rej_reason, {
                "Reason", "infiniband.cm.rej.reason",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rej_add_rej_info, {
                "Additional Reject Information (ARI)", "infiniband.cm.rej.ari",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_cm_rej_private_data, {
                "PrivateData", "infiniband.cm.rej.private",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* MAD Base Header */
        { &hf_infiniband_MAD, {
                "MAD (Management Datagram) Common Header", "infiniband.mad",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_base_version, {
                "Base Version", "infiniband.mad.baseversion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_mgmt_class, {
                "Management Class", "infiniband.mad.mgmtclass",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_class_version, {
                "Class Version", "infiniband.mad.classversion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
#if 0
        { &hf_infiniband_reserved1, {
                "Reserved", "infiniband.mad.reserved1",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
#endif
        { &hf_infiniband_method, {
                "Method", "infiniband.mad.method",
                FT_UINT8, BASE_HEX, VALS(mad_method_str), 0x0, NULL, HFILL}
        },
        { &hf_infiniband_status, {
                "Status", "infiniband.mad.status",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_class_specific, {
                "Class Specific", "infiniband.mad.classspecific",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_transaction_id, {
                "Transaction ID", "infiniband.mad.transactionid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_attribute_id, {
                "Attribute ID", "infiniband.mad.attributeid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_reserved16, {
                "Reserved", "infiniband.mad.reserved16",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_attribute_modifier, {
                "Attribute Modifier", "infiniband.mad.attributemodifier",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_data, {
                "MAD Data Payload", "infiniband.mad.data",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* RMPP Header */
        { &hf_infiniband_RMPP, {
                "RMPP (Reliable Multi-Packet Transaction Protocol)", "infiniband.rmpp",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_rmpp_version, {
                "RMPP Type", "infiniband.rmpp.rmppversion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_rmpp_type, {
                "RMPP Type", "infiniband.rmpp.rmpptype",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_r_resp_time, {
                "R Resp Time", "infiniband.rmpp.rresptime",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_rmpp_flags, {
                "RMPP Flags", "infiniband.rmpp.rmppflags",
                FT_UINT8, BASE_HEX, VALS(RMPP_Flags), 0x0F, NULL, HFILL}
        },
        { &hf_infiniband_rmpp_status, {
                "RMPP Status", "infiniband.rmpp.rmppstatus",
                FT_UINT8, BASE_HEX, VALS(RMPP_Status), 0x0, NULL, HFILL}
        },
        { &hf_infiniband_rmpp_data1, {
                "RMPP Data 1", "infiniband.rmpp.data1",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_rmpp_data2, {
                "RMPP Data 2", "infiniband.rmpp.data2",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

    /* RMPP Data */
#if 0
        { &hf_infiniband_RMPP_DATA, {
                "RMPP Data (Reliable Multi-Packet Transaction Protocol)", "infiniband.rmpp.data",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
#endif
        { &hf_infiniband_segment_number, {
                "Segment Number", "infiniband.rmpp.segmentnumber",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_payload_length32, {
                "Payload Length", "infiniband.rmpp.payloadlength",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_transferred_data, {
                "Transferred Data", "infiniband.rmpp.transferreddata",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* RMPP ACK */
        { &hf_infiniband_new_window_last, {
                "New Window Last", "infiniband.rmpp.newwindowlast",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_reserved220, {
                "Segment Number", "infiniband.rmpp.reserved220",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* RMPP ABORT/STOP */
        { &hf_infiniband_optional_extended_error_data, {
                "Optional Extended Error Data", "infiniband.rmpp.extendederrordata",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* SMP Data (LID Routed) */
        { &hf_infiniband_SMP_LID, {
                "Subnet Management Packet (LID Routed)", "infiniband.smplid",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_m_key, {
                "M_Key", "infiniband.smplid.mkey",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_smp_data, {
                "SMP Data", "infiniband.smplid.smpdata",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_reserved1024, {
                "Reserved (1024 bits)", "infiniband.smplid.reserved1024",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_reserved256, {
                "Reserved (256 bits)", "infiniband.smplid.reserved256",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

    /* XX: All following verified/corrected against Infiniband 1.2.1 Specification */
        /* SMP Data Directed Route */
        { &hf_infiniband_SMP_DIRECTED, {
                "Subnet Management Packet (Directed Route)", "infiniband.smpdirected",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_smp_status, {
                "Status", "infiniband.smpdirected.smpstatus",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_hop_pointer, {
                "Hop Pointer", "infiniband.smpdirected.hoppointer",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_hop_count, {
                "Hop Count", "infiniband.smpdirected.hopcount",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_dr_slid, {
                "DrSLID", "infiniband.smpdirected.drslid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_dr_dlid, {
                "DrDLID", "infiniband.smpdirected.drdlid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_reserved28, {
                "Reserved (224 bits)", "infiniband.smpdirected.reserved28",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_d, {
                "D (Direction Bit)", "infiniband.smpdirected.d",
                FT_UINT64, BASE_HEX, NULL, 0x8000, NULL, HFILL}
        },
        { &hf_infiniband_initial_path, {
                "Initial Path", "infiniband.smpdirected.initialpath",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_return_path, {
                "Return Path", "infiniband.smpdirected.returnpath",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* SA MAD Header */
        { &hf_infiniband_SA, {
                "SA Packet (Subnet Administration)", "infiniband.sa.drdlid",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_sm_key, {
                "SM_Key (Verification Key)", "infiniband.sa.smkey",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_attribute_offset, {
                "Attribute Offset", "infiniband.sa.attributeoffset",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_component_mask, {
                "Component Mask", "infiniband.sa.componentmask",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_subnet_admin_data, {
                "Subnet Admin Data", "infiniband.sa.subnetadmindata",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* Mellanox EoIB encapsulation header */
        { &hf_infiniband_EOIB, {
                "Mellanox EoIB Encapsulation Header", "infiniband.eoib",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_ver, {
                "Version", "infiniband.eoib.version",
                FT_UINT16, BASE_HEX, NULL, 0x3000, NULL, HFILL}
        },
        { &hf_infiniband_tcp_chk, {
                "TCP Checksum", "infiniband.eoib.tcp_chk",
                FT_UINT16, BASE_HEX, NULL, 0x0c00, NULL, HFILL}
        },
        { &hf_infiniband_ip_chk, {
                "IP Checksum", "infiniband.eoib.ip_chk",
                FT_UINT16, BASE_HEX, NULL, 0x0300, NULL, HFILL}
        },
        { &hf_infiniband_fcs, {
                "FCS Field Present", "infiniband.eoib.fcs",
                FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL}
        },
        { &hf_infiniband_ms, {
                "More Segments to Follow", "infiniband.eoib.ms",
                FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL}
        },
        { &hf_infiniband_seg_off, {
                "Segment Offset", "infiniband.eoib.ip_seg_offset",
                FT_UINT16, BASE_DEC, NULL, 0x001f, NULL, HFILL}
        },
        { &hf_infiniband_seg_id, {
                "Segment ID", "infiniband.eoib.ip_seg_id",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },

        /* NodeDescription */
        { &hf_infiniband_NodeDescription_NodeString, {
                "NodeString", "infiniband.nodedescription.nodestring",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* NodeInfo */
        { &hf_infiniband_NodeInfo_BaseVersion, {
                "BaseVersion", "infiniband.nodeinfo.baseversion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_NodeInfo_ClassVersion, {
                "ClassVersion", "infiniband.nodeinfo.classversion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_NodeInfo_NodeType, {
                "NodeType", "infiniband.nodeinfo.nodetype",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_NodeInfo_NumPorts, {
                "NumPorts", "infiniband.nodeinfo.numports",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_NodeInfo_SystemImageGUID, {
                "SystemImageGUID", "infiniband.nodeinfo.systemimageguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_NodeInfo_NodeGUID, {
                "NodeGUID", "infiniband.nodeinfo.nodeguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_NodeInfo_PortGUID, {
                "PortGUID", "infiniband.nodeinfo.portguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_NodeInfo_PartitionCap, {
                "PartitionCap", "infiniband.nodeinfo.partitioncap",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_NodeInfo_DeviceID, {
                "DeviceID", "infiniband.nodeinfo.deviceid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_NodeInfo_Revision, {
                "Revision", "infiniband.nodeinfo.revision",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_NodeInfo_LocalPortNum, {
                "LocalPortNum", "infiniband.nodeinfo.localportnum",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_NodeInfo_VendorID, {
                "VendorID", "infiniband.nodeinfo.vendorid",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* SwitchInfo */
        { &hf_infiniband_SwitchInfo_LinearFDBCap, {
                "LinearFDBCap", "infiniband.switchinfo.linearfdbcap",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_RandomFDBCap, {
                "RandomFDBCap", "infiniband.switchinfo.randomfdbcap",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_MulticastFDBCap, {
                "MulticastFDBCap", "infiniband.switchinfo.multicastfdbcap",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_LinearFDBTop, {
                "LinearFDBTop", "infiniband.switchinfo.linearfdbtop",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_DefaultPort, {
                "DefaultPort", "infiniband.switchinfo.defaultport",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_DefaultMulticastPrimaryPort, {
                "DefaultMulticastPrimaryPort", "infiniband.switchinfo.defaultmulticastprimaryport",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_DefaultMulticastNotPrimaryPort, {
                "DefaultMulticastNotPrimaryPort", "infiniband.switchinfo.defaultmulticastnotprimaryport",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_LifeTimeValue, {
                "LifeTimeValue", "infiniband.switchinfo.lifetimevalue",
                FT_UINT8, BASE_HEX, NULL, 0xF8, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_PortStateChange, {
                "PortStateChange", "infiniband.switchinfo.portstatechange",
                FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_OptimizedSLtoVLMappingProgramming, {
                "OptimizedSLtoVLMappingProgramming", "infiniband.switchinfo.optimizedsltovlmappingprogramming",
                FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_LIDsPerPort, {
                "LIDsPerPort", "infiniband.switchinfo.lidsperport",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_PartitionEnforcementCap, {
                "PartitionEnforcementCap", "infiniband.switchinfo.partitionenforcementcap",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_InboundEnforcementCap, {
                "InboundEnforcementCap", "infiniband.switchinfo.inboundenforcementcap",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_OutboundEnforcementCap, {
                "OutboundEnforcementCap", "infiniband.switchinfo.outboundenforcementcap",
                FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_FilterRawInboundCap, {
                "FilterRawInboundCap", "infiniband.switchinfo.filterrawinboundcap",
                FT_UINT8, BASE_HEX, NULL, 0x20, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_FilterRawOutboundCap, {
                "FilterRawOutboundCap", "infiniband.switchinfo.filterrawoutboundcap",
                FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL}
        },
        { &hf_infiniband_SwitchInfo_EnhancedPortZero, {
                "EnhancedPortZero", "infiniband.switchinfo.enhancedportzero",
                FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL}
        },

        /* GUIDInfo */
#if 0
        { &hf_infiniband_GUIDInfo_GUIDBlock, {
                "GUIDBlock", "infiniband.switchinfo.guidblock",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
#endif
        { &hf_infiniband_GUIDInfo_GUID, {
                "GUID", "infiniband.switchinfo.guid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* PortInfo */
        { &hf_infiniband_PortInfo_M_Key, {
                "M_Key", "infiniband.portinfo.m_key",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_GidPrefix, {
                "GidPrefix", "infiniband.portinfo.guid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_LID, {
                "LID", "infiniband.portinfo.lid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_MasterSMLID, {
                "MasterSMLID", "infiniband.portinfo.mastersmlid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask, {
                "CapabilityMask", "infiniband.portinfo.capabilitymask",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* Capability Mask Flags */
        { &hf_infiniband_PortInfo_CapabilityMask_SM, {
                "SM", "infiniband.portinfo.capabilitymask.issm",
                FT_UINT32, BASE_HEX, NULL, 0x00000002, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_NoticeSupported, {
                "NoticeSupported", "infiniband.portinfo.capabilitymask.noticesupported",
                FT_UINT32, BASE_HEX, NULL, 0x00000004, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_TrapSupported, {
                "TrapSupported", "infiniband.portinfo.capabilitymask.trapsupported",
                FT_UINT32, BASE_HEX, NULL, 0x00000008, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_OptionalPDSupported, {
                "OptionalPDSupported", "infiniband.portinfo.capabilitymask.optionalpdsupported",
                FT_UINT32, BASE_HEX, NULL, 0x00000010, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_AutomaticMigrationSupported, {
                "AutomaticMigrationSupported", "infiniband.portinfo.capabilitymask.automaticmigrationsupported",
                FT_UINT32, BASE_HEX, NULL, 0x00000020, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_SLMappingSupported, {
                "SLMappingSupported", "infiniband.portinfo.capabilitymask.slmappingsupported",
                FT_UINT32, BASE_HEX, NULL, 0x00000040, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_MKeyNVRAM, {
                "MKeyNVRAM", "infiniband.portinfo.capabilitymask.mkeynvram",
                FT_UINT32, BASE_HEX, NULL, 0x00000080, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_PKeyNVRAM, {
                "PKeyNVRAM", "infiniband.portinfo.capabilitymask.pkeynvram",
                FT_UINT32, BASE_HEX, NULL, 0x00000100, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_LEDInfoSupported, {
                "LEDInfoSupported", "infiniband.portinfo.capabilitymask.ledinfosupported",
                FT_UINT32, BASE_HEX, NULL, 0x00000200, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_SMdisabled, {
                "SMdisabled", "infiniband.portinfo.capabilitymask.smdisabled",
                FT_UINT32, BASE_HEX, NULL, 0x00000400, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_SystemImageGUIDSupported, {
                "SystemImageGUIDSupported", "infiniband.portinfo.capabilitymask.systemimageguidsupported",
                FT_UINT32, BASE_HEX, NULL, 0x00000800, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_PKeySwitchExternalPortTrapSupported, {
                "PKeySwitchExternalPortTrapSupported", "infiniband.portinfo.capabilitymask.pkeyswitchexternalporttrapsupported",
                FT_UINT32, BASE_HEX, NULL, 0x00001000, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_CommunicationsManagementSupported, {
                "CommunicationsManagementSupported", "infiniband.portinfo.capabilitymask.communicationsmanagementsupported",
                FT_UINT32, BASE_HEX, NULL, 0x00010000, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_SNMPTunnelingSupported, {
                "SNMPTunnelingSupported", "infiniband.portinfo.capabilitymask.snmptunnelingsupported",
                FT_UINT32, BASE_HEX, NULL, 0x00020000, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_ReinitSupported, {
                "ReinitSupported", "infiniband.portinfo.capabilitymask.reinitsupported",
                FT_UINT32, BASE_HEX, NULL, 0x00040000, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_DeviceManagementSupported, {
                "DeviceManagementSupported", "infiniband.portinfo.capabilitymask.devicemanagementsupported",
                FT_UINT32, BASE_HEX, NULL, 0x00080000, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_VendorClassSupported, {
                "VendorClassSupported", "infiniband.portinfo.capabilitymask.vendorclasssupported",
                FT_UINT32, BASE_HEX, NULL, 0x00100000, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_DRNoticeSupported, {
                "DRNoticeSupported", "infiniband.portinfo.capabilitymask.drnoticesupported",
                FT_UINT32, BASE_HEX, NULL, 0x00200000, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_CapabilityMaskNoticeSupported, {
                "CapabilityMaskNoticeSupported", "infiniband.portinfo.capabilitymask.capabilitymasknoticesupported",
                FT_UINT32, BASE_HEX, NULL, 0x00400000, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_BootManagementSupported, {
                "BootManagementSupported", "infiniband.portinfo.capabilitymask.bootmanagementsupported",
                FT_UINT32, BASE_HEX, NULL, 0x00800000, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_LinkRoundTripLatencySupported, {
                "LinkRoundTripLatencySupported", "infiniband.portinfo.capabilitymask.linkroundtriplatencysupported",
                FT_UINT32, BASE_HEX, NULL, 0x01000000, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_ClientRegistrationSupported, {
                "ClientRegistrationSupported", "infiniband.portinfo.capabilitymask.clientregistrationsupported",
                FT_UINT32, BASE_HEX, NULL, 0x02000000, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_OtherLocalChangesNoticeSupported, {
                "OtherLocalChangesNoticeSupported", "infiniband.portinfo.capabilitymask.otherlocalchangesnoticesupported",
                FT_UINT32, BASE_HEX, NULL, 0x04000000, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_CapabilityMask_LinkSpeedWIdthPairsTableSupported, {
                "LinkSpeedWIdthPairsTableSupported", "infiniband.portinfo.capabilitymask.linkspeedwidthpairstablesupported",
                FT_UINT32, BASE_HEX, NULL, 0x08000000, NULL, HFILL}
        },
        /* End Capability Mask Flags */

        /* PortInfo */
        { &hf_infiniband_PortInfo_DiagCode, {
                "DiagCode", "infiniband.portinfo.diagcode",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_M_KeyLeasePeriod, {
                "M_KeyLeasePeriod", "infiniband.portinfo.m_keyleaseperiod",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_LocalPortNum, {
                "LocalPortNum", "infiniband.portinfo.localportnum",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_LinkWidthEnabled, {
                "LinkWidthEnabled", "infiniband.portinfo.linkwidthenabled",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_LinkWidthSupported, {
                "LinkWidthSupported", "infiniband.portinfo.linkwidthsupported",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_LinkWidthActive, {
                "LinkWidthActive", "infiniband.portinfo.linkwidthactive",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_LinkSpeedSupported, {
                "LinkSpeedSupported", "infiniband.portinfo.linkspeedsupported",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_PortState, {
                "PortState", "infiniband.portinfo.portstate",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_PortPhysicalState, {
                "PortPhysicalState", "infiniband.portinfo.portphysicalstate",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_LinkDownDefaultState, {
                "LinkDownDefaultState", "infiniband.portinfo.linkdowndefaultstate",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_M_KeyProtectBits, {
                "M_KeyProtectBits", "infiniband.portinfo.m_keyprotectbits",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_LMC, {
                "LMC", "infiniband.portinfo.lmc",
                FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_LinkSpeedActive, {
                "LinkSpeedActive", "infiniband.portinfo.linkspeedactive",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_LinkSpeedEnabled, {
                "LinkSpeedEnabled", "infiniband.portinfo.linkspeedenabled",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_NeighborMTU, {
                "NeighborMTU", "infiniband.portinfo.neighbormtu",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_MasterSMSL, {
                "MasterSMSL", "infiniband.portinfo.mastersmsl",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_VLCap, {
                "VLCap", "infiniband.portinfo.vlcap",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_InitType, {
                "InitType", "infiniband.portinfo.inittype",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_VLHighLimit, {
                "VLHighLimit", "infiniband.portinfo.vlhighlimit",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_VLArbitrationHighCap, {
                "VLArbitrationHighCap", "infiniband.portinfo.vlarbitrationhighcap",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_VLArbitrationLowCap, {
                "VLArbitrationLowCap", "infiniband.portinfo.vlarbitrationlowcap",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_InitTypeReply, {
                "InitTypeReply", "infiniband.portinfo.inittypereply",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_MTUCap, {
                "MTUCap", "infiniband.portinfo.mtucap",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_VLStallCount, {
                "VLStallCount", "infiniband.portinfo.vlstallcount",
                FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_HOQLife, {
                "HOQLife", "infiniband.portinfo.hoqlife",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_OperationalVLs, {
                "OperationalVLs", "infiniband.portinfo.operationalvls",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_PartitionEnforcementInbound, {
                "PartitionEnforcementInbound", "infiniband.portinfo.partitionenforcementinbound",
                FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_PartitionEnforcementOutbound, {
                "PartitionEnforcementOutbound", "infiniband.portinfo.partitionenforcementoutbound",
                FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_FilterRawInbound, {
                "FilterRawInbound", "infiniband.portinfo.filterrawinbound",
                FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_FilterRawOutbound, {
                "FilterRawOutbound", "infiniband.portinfo.filterrawoutbound",
                FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_M_KeyViolations, {
                "M_KeyViolations", "infiniband.portinfo.m_keyviolations",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_P_KeyViolations, {
                "P_KeyViolations", "infiniband.portinfo.p_keyviolations",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_Q_KeyViolations, {
                "Q_KeyViolations", "infiniband.portinfo.q_keyviolations",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_GUIDCap, {
                "GUIDCap", "infiniband.portinfo.guidcap",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_ClientReregister, {
                "ClientReregister", "infiniband.portinfo.clientreregister",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_SubnetTimeOut, {
                "SubnetTimeOut", "infiniband.portinfo.subnettimeout",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_RespTimeValue, {
                "RespTimeValue", "infiniband.portinfo.resptimevalue",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_LocalPhyErrors, {
                "LocalPhyErrors", "infiniband.portinfo.localphyerrors",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_OverrunErrors, {
                "OverrunErrors", "infiniband.portinfo.overrunerrors",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_MaxCreditHint, {
                "MaxCreditHint", "infiniband.portinfo.maxcredithint",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PortInfo_LinkRoundTripLatency, {
                "LinkRoundTripLatency", "infiniband.portinfo.linkroundtriplatency",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* P_KeyTable */
        { &hf_infiniband_P_KeyTable_P_KeyTableBlock, {
                "P_KeyTableBlock", "infiniband.p_keytable.p_keytableblock",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_P_KeyTable_MembershipType, {
                "MembershipType", "infiniband.p_keytable.membershiptype",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_P_KeyTable_P_KeyBase, {
                "P_KeyBase", "infiniband.p_keytable.p_keybase",
                FT_UINT16, BASE_HEX, NULL, 0x7FFF, NULL, HFILL}
        },

        /* SLtoVLMappingTable */
        { &hf_infiniband_SLtoVLMappingTable_SLtoVL_HighBits, {
                "SL(x)toVL", "infiniband.sltovlmappingtable.sltovlhighbits",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_SLtoVLMappingTable_SLtoVL_LowBits, {
                "SL(x)toVL", "infiniband.sltovlmappingtable.sltovllowbits",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}
        },

        /* VLArbitrationTable */
#if 0
        { &hf_infiniband_VLArbitrationTable_VLWeightPairs, {
                "VLWeightPairs", "infiniband.vlarbitrationtable.vlweightpairs",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
#endif
        { &hf_infiniband_VLArbitrationTable_VL, {
                "VL", "infiniband.vlarbitrationtable.vl",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}
        },
        { &hf_infiniband_VLArbitrationTable_Weight, {
                "Weight", "infiniband.vlarbitrationtable.weight",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* LinearForwardingTable */
#if 0
        { &hf_infiniband_LinearForwardingTable_LinearForwardingTableBlock, {
                "LinearForwardingTableBlock", "infiniband.linearforwardingtable.linearforwardingtableblock",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
#endif
        { &hf_infiniband_LinearForwardingTable_Port, {
                "Port", "infiniband.linearforwardingtable.port",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* RandomForwardingTable */
#if 0
        { &hf_infiniband_RandomForwardingTable_RandomForwardingTableBlock, {
                "RandomForwardingTableBlock", "infiniband.randomforwardingtable.randomforwardingtableblock",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
#endif
        { &hf_infiniband_RandomForwardingTable_LID, {
                "LID", "infiniband.randomforwardingtable.lid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_RandomForwardingTable_Valid, {
                "Valid", "infiniband.randomforwardingtable.valid",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_RandomForwardingTable_LMC, {
                "LMC", "infiniband.randomforwardingtable.lmc",
                FT_UINT8, BASE_HEX, NULL, 0x70, NULL, HFILL}
        },
        { &hf_infiniband_RandomForwardingTable_Port, {
                "Port", "infiniband.randomforwardingtable.port",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* MulticastForwardingTable */
#if 0
        { &hf_infiniband_MulticastForwardingTable_MulticastForwardingTableBlock , {
                "MulticastForwardingTableBlock", "infiniband.multicastforwardingtable.multicastforwardingtableblock",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
#endif
        { &hf_infiniband_MulticastForwardingTable_PortMask, {
                "PortMask", "infiniband.multicastforwardingtable.portmask",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* SMInfo */
        { &hf_infiniband_SMInfo_GUID, {
                "GUID", "infiniband.sminfo.guid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SMInfo_SM_Key, {
                "SM_Key", "infiniband.sminfo.sm_key",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SMInfo_ActCount, {
                "ActCount", "infiniband.sminfo.actcount",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SMInfo_Priority, {
                "Priority", "infiniband.sminfo.priority",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_SMInfo_SMState, {
                "SMState", "infiniband.sminfo.smstate",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}
        },

        /* VendorDiag */
        { &hf_infiniband_VendorDiag_NextIndex, {
                "NextIndex", "infiniband.vendordiag.nextindex",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_VendorDiag_DiagData, {
                "DiagData", "infiniband.vendordiag.diagdata",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* LedInfo */
        { &hf_infiniband_LedInfo_LedMask, {
                "LedMask", "infiniband.ledinfo.ledmask",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },

        /* LinkSpeedWidthPairsTable */
        { &hf_infiniband_LinkSpeedWidthPairsTable_NumTables, {
                "NumTables", "infiniband.linkspeedwidthpairstable.numtables",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_LinkSpeedWidthPairsTable_PortMask, {
                "PortMask", "infiniband.linkspeedwidthpairstable.portmask",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_LinkSpeedWidthPairsTable_SpeedTwoFive, {
                "Speed 2.5 Gbps", "infiniband.linkspeedwidthpairstable.speedtwofive",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_LinkSpeedWidthPairsTable_SpeedFive, {
                "Speed 5 Gbps", "infiniband.linkspeedwidthpairstable.speedfive",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_LinkSpeedWidthPairsTable_SpeedTen, {
                "Speed 10 Gbps", "infiniband.linkspeedwidthpairstable.speedten",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },

        /* NodeRecord */
        /* PortInfoRecord */
        /* SLtoVLMappingTableRecord */
        /* SwitchInfoRecord */
        /* LinearForwardingTableRecord */
        /* RandomForwardingTableRecord */
        /* MulticastForwardingTableRecord */
        /* VLArbitrationTableRecord */
        { &hf_infiniband_SA_LID, {
                "LID", "infiniband.sa.lid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SA_EndportLID, {
                "EndportLID", "infiniband.sa.endportlid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SA_PortNum, {
                "PortNum", "infiniband.sa.portnum",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SA_InputPortNum , {
                "InputPortNum", "infiniband.sa.inputportnum",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SA_OutputPortNum, {
                "OutputPortNum", "infiniband.sa.outputportnum",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SA_BlockNum_EightBit, {
                "BlockNum_EightBit", "infiniband.sa.blocknum_eightbit",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SA_BlockNum_NineBit, {
                "BlockNum_NineBit", "infiniband.sa.blocknum_ninebit",
                FT_UINT16, BASE_HEX, NULL, 0x01FF, NULL, HFILL}
        },
        { &hf_infiniband_SA_BlockNum_SixteenBit, {
                "BlockNum_SixteenBit", "infiniband.sa.blocknum_sixteenbit",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_SA_Position, {
                "Position", "infiniband.sa.position",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
#if 0
        { &hf_infiniband_SA_Index, {
                "Index", "infiniband.sa.index",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
#endif

        /* InformInfoRecord */
        { &hf_infiniband_InformInfoRecord_SubscriberGID, {
                "SubscriberGID", "infiniband.informinforecord.subscribergid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_InformInfoRecord_Enum, {
                "Enum", "infiniband.informinforecord.enum",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* InformInfo */
        { &hf_infiniband_InformInfo_GID, {
                "GID", "infiniband.informinfo.gid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_InformInfo_LIDRangeBegin, {
                "LIDRangeBegin", "infiniband.informinfo.lidrangebegin",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_InformInfo_LIDRangeEnd, {
                "LIDRangeEnd", "infiniband.informinfo.lidrangeend",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_InformInfo_IsGeneric, {
                "IsGeneric", "infiniband.informinfo.isgeneric",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_InformInfo_Subscribe, {
                "Subscribe", "infiniband.informinfo.subscribe",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_InformInfo_Type, {
                "Type", "infiniband.informinfo.type",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_InformInfo_TrapNumberDeviceID, {
                "TrapNumberDeviceID", "infiniband.informinfo.trapnumberdeviceid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_InformInfo_QPN, {
                "QPN", "infiniband.informinfo.qpn",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_InformInfo_RespTimeValue, {
                "RespTimeValue", "infiniband.informinfo.resptimevalue",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL}
        },
        { &hf_infiniband_InformInfo_ProducerTypeVendorID, {
                "ProducerTypeVendorID", "infiniband.informinfo.producertypevendorid",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* LinkRecord */
        { &hf_infiniband_LinkRecord_FromLID, {
                "FromLID", "infiniband.linkrecord.fromlid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_LinkRecord_FromPort, {
                "FromPort", "infiniband.linkrecord.fromport",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_LinkRecord_ToPort, {
                "ToPort", "infiniband.linkrecord.toport",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_LinkRecord_ToLID, {
                "ToLID", "infiniband.linkrecord.tolid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* ServiceRecord */
        { &hf_infiniband_ServiceRecord_ServiceID, {
                "ServiceID", "infiniband.linkrecord.serviceid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_ServiceRecord_ServiceGID, {
                "ServiceGID", "infiniband.linkrecord.servicegid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_ServiceRecord_ServiceP_Key, {
                "ServiceP_Key", "infiniband.linkrecord.servicep_key",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_ServiceRecord_ServiceLease, {
                "ServiceLease", "infiniband.linkrecord.servicelease",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_ServiceRecord_ServiceKey, {
                "ServiceKey", "infiniband.linkrecord.servicekey",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_ServiceRecord_ServiceName, {
                "ServiceName", "infiniband.linkrecord.servicename",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_ServiceRecord_ServiceData, {
                "ServiceData", "infiniband.linkrecord.servicedata",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* ServiceAssociationRecord */
        { &hf_infiniband_ServiceAssociationRecord_ServiceKey, {
                "ServiceKey", "infiniband.serviceassociationrecord.servicekey",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_ServiceAssociationRecord_ServiceName, {
                "ServiceName", "infiniband.serviceassociationrecord.servicename",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* PathRecord */
        { &hf_infiniband_PathRecord_DGID, {
                "DGID", "infiniband.pathrecord.dgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_SGID, {
                "SGID", "infiniband.pathrecord.sgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_DLID, {
                "DLID", "infiniband.pathrecord.dlid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_SLID, {
                "SLID", "infiniband.pathrecord.slid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_RawTraffic, {
                "RawTraffic", "infiniband.pathrecord.rawtraffic",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_FlowLabel, {
                "FlowLabel", "infiniband.pathrecord.flowlabel",
                FT_UINT24, BASE_HEX, NULL, 0x0FFFFF, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_HopLimit, {
                "HopLimit", "infiniband.pathrecord.hoplimit",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_TClass, {
                "TClass", "infiniband.pathrecord.tclass",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_Reversible, {
                "Reversible", "infiniband.pathrecord.reversible",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_NumbPath, {
                "NumbPath", "infiniband.pathrecord.numbpath",
                FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_P_Key, {
                "P_Key", "infiniband.pathrecord.p_key",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_SL, {
                "SL", "infiniband.pathrecord.sl",
                FT_UINT16, BASE_HEX, NULL, 0x000F, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_MTUSelector, {
                "MTUSelector", "infiniband.pathrecord.mtuselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_MTU, {
                "MTU", "infiniband.pathrecord.mtu",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_RateSelector, {
                "RateSelector", "infiniband.pathrecord.rateselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_Rate, {
                "Rate", "infiniband.pathrecord.rate",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_PacketLifeTimeSelector, {
                "PacketLifeTimeSelector", "infiniband.pathrecord.packetlifetimeselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_PacketLifeTime, {
                "PacketLifeTime", "infiniband.pathrecord.packetlifetime",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL}
        },
        { &hf_infiniband_PathRecord_Preference, {
                "Preference", "infiniband.pathrecord.preference",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* MCMemberRecord */
        { &hf_infiniband_MCMemberRecord_MGID, {
                "MGID", "infiniband.mcmemberrecord.mgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_PortGID, {
                "PortGID", "infiniband.mcmemberrecord.portgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_Q_Key, {
                "Q_Key", "infiniband.mcmemberrecord.q_key",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_MLID, {
                "MLID", "infiniband.mcmemberrecord.mlid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_MTUSelector, {
                "MTUSelector", "infiniband.mcmemberrecord.mtuselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_MTU, {
                "MTU", "infiniband.mcmemberrecord.mtu",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_TClass, {
                "TClass", "infiniband.mcmemberrecord.tclass",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_P_Key, {
                "P_Key", "infiniband.mcmemberrecord.p_key",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_RateSelector, {
                "RateSelector", "infiniband.mcmemberrecord.rateselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_Rate, {
                "Rate", "infiniband.mcmemberrecord.rate",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_PacketLifeTimeSelector, {
                "PacketLifeTimeSelector", "infiniband.mcmemberrecord.packetlifetimeselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_PacketLifeTime, {
                "PacketLifeTime", "infiniband.mcmemberrecord.packetlifetime",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_SL, {
                "SL", "infiniband.mcmemberrecord.sl",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_FlowLabel, {
                "FlowLabel", "infiniband.mcmemberrecord.flowlabel",
                FT_UINT24, BASE_HEX, NULL, 0x0FFFFF, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_HopLimit, {
                "HopLimit", "infiniband.mcmemberrecord.hoplimit",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_Scope, {
                "Scope", "infiniband.mcmemberrecord.scope",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_JoinState, {
                "JoinState", "infiniband.mcmemberrecord.joinstate",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_MCMemberRecord_ProxyJoin, {
                "ProxyJoin", "infiniband.mcmemberrecord.proxyjoin",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },

        /* MultiPathRecord */
        { &hf_infiniband_MultiPathRecord_RawTraffic, {
                "RawTraffic", "infiniband.multipathrecord.rawtraffic",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_FlowLabel, {
                "FlowLabel", "infiniband.multipathrecord.flowlabel",
                FT_UINT24, BASE_HEX, NULL, 0x0FFFFF, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_HopLimit, {
                "HopLimit", "infiniband.multipathrecord.hoplimit",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_TClass, {
                "TClass", "infiniband.multipathrecord.tclass",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_Reversible, {
                "Reversible", "infiniband.multipathrecord.reversible",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_NumbPath, {
                "NumbPath", "infiniband.multipathrecord.numbpath",
                FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_P_Key, {
                "P_Key", "infiniband.multipathrecord.p_key",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_SL, {
                "SL", "infiniband.multipathrecord.sl",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_MTUSelector, {
                "MTUSelector", "infiniband.multipathrecord.mtuselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_MTU, {
                "MTU", "infiniband.multipathrecord.mtu",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_RateSelector, {
                "RateSelector", "infiniband.multipathrecord.rateselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_Rate, {
                "Rate", "infiniband.multipathrecord.rate",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_PacketLifeTimeSelector, {
                "PacketLifeTimeSelector", "infiniband.multipathrecord.packetlifetimeselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_PacketLifeTime, {
                "PacketLifeTime", "infiniband.multipathrecord.packetlifetime",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_IndependenceSelector, {
                "IndependenceSelector", "infiniband.multipathrecord.independenceselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_GIDScope, {
                "GIDScope", "infiniband.multipathrecord.gidscope",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_SGIDCount, {
                "SGIDCount", "infiniband.multipathrecord.sgidcount",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_DGIDCount, {
                "DGIDCount", "infiniband.multipathrecord.dgidcount",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_MultiPathRecord_SDGID, {
                "SDGID", "infiniband.multipathrecord.sdgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* Notice */
        { &hf_infiniband_Notice_IsGeneric, {
                "IsGeneric", "infiniband.notice.isgeneric",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_Notice_Type, {
                "Type", "infiniband.notice.type",
                FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL}
        },
        { &hf_infiniband_Notice_ProducerTypeVendorID, {
                "ProducerTypeVendorID", "infiniband.notice.producertypevendorid",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Notice_TrapNumberDeviceID, {
                "TrapNumberDeviceID", "infiniband.notice.trapnumberdeviceid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Notice_IssuerLID, {
                "IssuerLID", "infiniband.notice.issuerlid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Notice_NoticeToggle, {
                "NoticeToggle", "infiniband.notice.noticetoggle",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_Notice_NoticeCount, {
                "NoticeCount", "infiniband.notice.noticecount",
                FT_UINT16, BASE_HEX, NULL, 0x7FFF, NULL, HFILL}
        },
        { &hf_infiniband_Notice_DataDetails, {
                "DataDetails", "infiniband.notice.datadetails",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
#if 0
        { &hf_infiniband_Notice_IssuerGID, {
                "IssuerGID", "infiniband.notice.issuergid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Notice_ClassTrapSpecificData, {
                "ClassTrapSpecificData", "infiniband.notice.classtrapspecificdata",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
#endif

        /* Traps 64,65,66,67 */
        { &hf_infiniband_Trap_GIDADDR, {
                "GIDADDR", "infiniband.trap.gidaddr",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Traps 68,69 */
        { &hf_infiniband_Trap_COMP_MASK, {
                "COMP_MASK", "infiniband.trap.comp_mask",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_WAIT_FOR_REPATH, {
                "WAIT_FOR_REPATH", "infiniband.trap.wait_for_repath",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
#if 0
        { &hf_infiniband_Trap_PATH_REC, {
                "PATH_REC", "infiniband.trap.path_rec",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
#endif

        /* Trap 128 */
        { &hf_infiniband_Trap_LIDADDR, {
                "LIDADDR", "infiniband.trap.lidaddr",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* Trap 129, 130, 131 */
        { &hf_infiniband_Trap_PORTNO, {
                "PORTNO", "infiniband.trap.portno",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* Trap 144 */
        { &hf_infiniband_Trap_OtherLocalChanges, {
                "OtherLocalChanges", "infiniband.trap.otherlocalchanges",
                FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL}
        },
        { &hf_infiniband_Trap_CAPABILITYMASK, {
                "CAPABILITYMASK", "infiniband.trap.capabilitymask",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_LinkSpeecEnabledChange, {
                "LinkSpeecEnabledChange", "infiniband.trap.linkspeecenabledchange",
                FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL}
        },
        { &hf_infiniband_Trap_LinkWidthEnabledChange, {
                "LinkWidthEnabledChange", "infiniband.trap.linkwidthenabledchange",
                FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL}
        },
        { &hf_infiniband_Trap_NodeDescriptionChange, {
                "NodeDescriptionChange", "infiniband.trap.nodedescriptionchange",
                FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL}
        },

        /* Trap 145 */
        { &hf_infiniband_Trap_SYSTEMIMAGEGUID, {
                "SYSTEMIMAGEGUID", "infiniband.trap.systemimageguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* Trap 256 */
        { &hf_infiniband_Trap_DRSLID, {
                "DRSLID", "infiniband.trap.drslid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_METHOD, {
                "METHOD", "infiniband.trap.method",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_ATTRIBUTEID, {
                "ATTRIBUTEID", "infiniband.trap.attributeid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_ATTRIBUTEMODIFIER, {
                "ATTRIBUTEMODIFIER", "infiniband.trap.attributemodifier",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_MKEY, {
                "MKEY", "infiniband.trap.mkey",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_DRNotice, {
                "DRNotice", "infiniband.trap.drnotice",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_infiniband_Trap_DRPathTruncated, {
                "DRPathTruncated", "infiniband.trap.drpathtruncated",
                FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL}
        },
        { &hf_infiniband_Trap_DRHopCount, {
                "DRHopCount", "infiniband.trap.drhopcount",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL}
        },
        { &hf_infiniband_Trap_DRNoticeReturnPath, {
                "DRNoticeReturnPath", "infiniband.trap.drnoticereturnpath",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* Trap 257, 258 */
        { &hf_infiniband_Trap_LIDADDR1, {
                "LIDADDR1", "infiniband.trap.lidaddr1",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_LIDADDR2, {
                "LIDADDR2", "infiniband.trap.lidaddr2",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_KEY, {
                "KEY", "infiniband.trap.key",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_SL, {
                "SL", "infiniband.trap.sl",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_QP1, {
                "QP1", "infiniband.trap.qp1",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_QP2, {
                "QP2", "infiniband.trap.qp2",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_GIDADDR1, {
                "GIDADDR1", "infiniband.trap.gidaddr1",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_GIDADDR2, {
                "GIDADDR2", "infiniband.trap.gidaddr2",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* Trap 259 */
        { &hf_infiniband_Trap_DataValid, {
                "DataValid", "infiniband.trap.datavalid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_PKEY, {
                "PKEY", "infiniband.trap.pkey",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_infiniband_Trap_SWLIDADDR, {
                "SWLIDADDR", "infiniband.trap.swlidaddr",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* PortCounters in Performance class */
        { &hf_infiniband_PortCounters, {
                "Port Counters (Performance Management MAD)", "infiniband.portcounters",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Performance class PortCounters packet", HFILL}
        },
        { &hf_infiniband_PortCounters_PortSelect, {
                "PortSelect", "infiniband.portcounters.portselect",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "Selects the port that will be accessed", HFILL}
        },
        { &hf_infiniband_PortCounters_CounterSelect, {
                "CounterSelect", "infiniband.portcounters.counterselect",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "When writing, selects which counters are affected by the operation", HFILL}
        },
        { &hf_infiniband_PortCounters_SymbolErrorCounter, {
                "SymbolErrorCounter", "infiniband.portcounters.symbolerrorcounter",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Total number of minor link errors", HFILL}
        },
        { &hf_infiniband_PortCounters_LinkErrorRecoveryCounter, {
                "LinkErrorRecoveryCounter", "infiniband.portcounters.linkerrorrecoverycounter",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Total number of times successfully completed link error recovery process", HFILL}
        },
        { &hf_infiniband_PortCounters_LinkDownedCounter, {
                "LinkDownedCounter", "infiniband.portcounters.linkdownedcounter",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Total number of times failed link error recovery process", HFILL}
        },
        { &hf_infiniband_PortCounters_PortRcvErrors, {
                "PortRcvErrors", "infiniband.portcounters.portrcverrors",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Total number of packets containing an error received", HFILL}
        },
        { &hf_infiniband_PortCounters_PortRcvRemotePhysicalErrors, {
                "PortRcvRemotePhysicalErrors", "infiniband.portcounters.portrcvremotephysicalerrors",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Total number of packets marked with EBP delimiter received", HFILL}
        },
        { &hf_infiniband_PortCounters_PortRcvSwitchRelayErrors, {
                "PortRcvSwitchRelayErrors", "infiniband.portcounters.portrcvswitchrelayerrors",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Total number of packets discarded because they could not be forwarded by switch relay",
                HFILL}
        },
        { &hf_infiniband_PortCounters_PortXmitDiscards, {
                "PortXmitDiscards", "infiniband.portcounters.portxmitdiscards",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Total number of outbound packets discarded", HFILL}
        },
        { &hf_infiniband_PortCounters_PortXmitConstraintErrors, {
                "PortXmitConstraintErrors", "infiniband.portcounters.portxmitconstrainterrors",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Total number of packets not transmitted from the switch physical port", HFILL}
        },
        { &hf_infiniband_PortCounters_PortRcvConstraintErrors, {
                "PortRcvConstraintErrors", "infiniband.portcounters.portrcvconstrainterrors",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Total number of packets received on the switch physical port that are discarded", HFILL}
        },
        { &hf_infiniband_PortCounters_LocalLinkIntegrityErrors, {
                "LocalLinkIntegrityErrors", "infiniband.portcounters.locallinkintegrityerrors",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "The number of times the count of local physical errors exceeded the threshold specified by LocalPhyErrors",
                HFILL}
        },
        { &hf_infiniband_PortCounters_ExcessiveBufferOverrunErrors, {
                "ExcessiveBufferOverrunErrors", "infiniband.portcounters.excessivebufferoverrunerrors",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "The number of times that OverrunErrors consecutive flow control update periods occured",
                HFILL}
        },
        { &hf_infiniband_PortCounters_VL15Dropped, {
                "VL15Dropped", "infiniband.portcounters.vl15dropped",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Number of incoming VL15 packets dropped", HFILL}
        },
        { &hf_infiniband_PortCounters_PortXmitData, {
                "PortXmitData", "infiniband.portcounters.portxmitdata",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Total number of data octets, divided by 4, transmitted on all VLs from the port", HFILL}
        },
        { &hf_infiniband_PortCounters_PortRcvData, {
                "PortRcvData", "infiniband.portcounters.portrcvdata",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Total number of data octets, divided by 4, received on all VLs at the port", HFILL}
        },
        { &hf_infiniband_PortCounters_PortXmitPkts, {
                "PortXmitPkts", "infiniband.portcounters.portxmitpkts",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Total number of packets transmitted on all VLs from the port", HFILL}
        },
        { &hf_infiniband_PortCounters_PortRcvPkts, {
                "PortRcvPkts", "infiniband.portcounters.portrcvpkts",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Total number of packets received from all VLs on the port", HFILL}
        },
        /* PortCountersExtended in Performance class */
        { &hf_infiniband_PortCountersExt, {
                "Port Counters Extended (Performance Management MAD)", "infiniband.portcounters_ext",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Performance class PortCountersExtended packet", HFILL}
        },
        { &hf_infiniband_PortCountersExt_PortSelect, {
                "PortSelect", "infiniband.portcounters_ext.portselect",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "Selects the port that will be accessed", HFILL}
        },
        { &hf_infiniband_PortCountersExt_CounterSelect, {
                "CounterSelect", "infiniband.portcounters_ext.counterselect",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "When writing, selects which counters are affected by the operation", HFILL}
        },
        { &hf_infiniband_PortCountersExt_PortXmitData, {
                "PortXmitData", "infiniband.portcounters_ext.portxmitdata",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "Total number of data octets, divided by 4, transmitted on all VLs from the port", HFILL}
        },
        { &hf_infiniband_PortCountersExt_PortRcvData, {
                "PortRcvData", "infiniband.portcounters_ext.portrcvdata",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "Total number of data octets, divided by 4, received on all VLs at the port", HFILL}
        },
        { &hf_infiniband_PortCountersExt_PortXmitPkts, {
                "PortXmitPkts", "infiniband.portcounters_ext.portxmitpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "Total number of packets transmitted on all VLs from the port", HFILL}
        },
        { &hf_infiniband_PortCountersExt_PortRcvPkts, {
                "PortRcvPkts", "infiniband.portcounters_ext.portrcvpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "Total number of packets received from all VLs on the port", HFILL}
        },
        { &hf_infiniband_PortCountersExt_PortUnicastXmitPkts, {
                "PortUnicastXmitPkts", "infiniband.portcounters_ext.portunicastxmitpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "Total number of unicast packets transmitted on all VLs from the port", HFILL}
        },
        { &hf_infiniband_PortCountersExt_PortUnicastRcvPkts, {
                "PortUnicastRcvPkts", "infiniband.portcounters_ext.portunicastrcvpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "Total number of unicast packets received from all VLs on the port", HFILL}
        },
        { &hf_infiniband_PortCountersExt_PortMulticastXmitPkts, {
                "PortMulticastXmitPkts", "infiniband.portcounters_ext.portmulticastxmitpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "Total number of multicast packets transmitted on all VLs from the port", HFILL}
        },
        { &hf_infiniband_PortCountersExt_PortMulticastRcvPkts, {
                "PortMulticastRcvPkts", "infiniband.portcounters_ext.portmulticastrcvpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "Total number of multicast packets received from all VLs on the port", HFILL}
        }
    };

    /* Array to hold expansion options between dissections */
    static gint *ett[] = {
    /*  &ett_infiniband,       */
        &ett_all_headers,
        &ett_lrh,
        &ett_grh,
        &ett_bth,
        &ett_rwh,
        &ett_rdeth,
        &ett_deth,
        &ett_reth,
        &ett_atomiceth,
        &ett_aeth,
        &ett_atomicacketh,
        &ett_immdt,
        &ett_ieth,
        &ett_payload,
        &ett_vendor,
        &ett_subn_lid_routed,
        &ett_subn_directed_route,
        &ett_subnadmin,
        &ett_cm,
        &ett_mad,
        &ett_rmpp,
        &ett_subm_attribute,
        &ett_suba_attribute,
        &ett_datadetails,
        &ett_noticestraps,
    /*  &ett_nodedesc,         */
    /*  &ett_nodeinfo,         */
    /*  &ett_switchinfo,       */
    /*  &ett_guidinfo,         */
    /*  &ett_portinfo,         */
        &ett_portinfo_capmask,
        &ett_pkeytable,
        &ett_sltovlmapping,
        &ett_vlarbitrationtable,
        &ett_linearforwardingtable,
        &ett_randomforwardingtable,
        &ett_multicastforwardingtable,
        &ett_sminfo,
        &ett_vendordiag,
        &ett_ledinfo,
        &ett_linkspeedwidthpairs,
        &ett_informinfo,
        &ett_linkrecord,
        &ett_servicerecord,
        &ett_pathrecord,
        &ett_mcmemberrecord,
        &ett_tracerecord,
        &ett_multipathrecord,
        &ett_serviceassocrecord,
        &ett_perfclass,
        &ett_eoib
    };

    static hf_register_info hf_link[] = {
        { &hf_infiniband_link_op, {
                "Operand", "infiniband_link.op",
                FT_UINT16, BASE_DEC, VALS(Operand_Description), 0xF000, NULL, HFILL}
        },
        { &hf_infiniband_link_fctbs, {
                "Flow Control Total Blocks Sent", "infiniband_link.fctbs",
                FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL}
        },
        { &hf_infiniband_link_vl, {
                "Virtual Lane", "infiniband_link.vl",
                FT_UINT16, BASE_DEC, NULL, 0xF000, NULL, HFILL}
        },
        { &hf_infiniband_link_fccl, {
                "Flow Control Credit Limit", "infiniband_link.fccl",
                FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL}
        },
        { &hf_infiniband_link_lpcrc, {
                "Link Packet CRC", "infiniband_link.lpcrc",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
        }
    };


    static gint *ett_link_array[] = {
        &ett_link
    };

    proto_infiniband = proto_register_protocol("InfiniBand", "InfiniBand", "infiniband");
    register_dissector("infiniband", dissect_infiniband, proto_infiniband);

    proto_register_field_array(proto_infiniband, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* register the subdissector tables */
    register_heur_dissector_list("infiniband.payload", &heur_dissectors_payload);
    register_heur_dissector_list("infiniband.mad.cm.private", &heur_dissectors_cm_private);

    /* register dissection preferences */
    infiniband_module = prefs_register_protocol(proto_infiniband, NULL);

    prefs_register_bool_preference(infiniband_module, "identify_payload",
                                   "Attempt to identify and parse encapsulated IBA payloads",
                                   "When set, dissector will attempt to identify unknown IBA payloads "
                                   "as containing an encapsulated ethertype, and parse them accordingly",
                                   &pref_identify_iba_payload);
    prefs_register_bool_preference(infiniband_module, "dissect_eoib",
                                   "Attempt to identify and parse Mellanox EoIB packets",
                                   "When set, dissector will attempt to identify and parse "
                                   "Mellanox Ethernet-over-InfiniBand packets",
                                   &pref_dissect_eoib);

    proto_infiniband_link = proto_register_protocol("InfiniBand Link", "InfiniBand Link", "infiniband_link");
    register_dissector("infiniband_link", dissect_infiniband_link, proto_infiniband_link);

    proto_register_field_array(proto_infiniband_link, hf_link, array_length(hf_link));
    proto_register_subtree_array(ett_link_array, array_length(ett_link_array));

    /* initialize the hash table */
    CM_context_table = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                             table_destroy_notify, table_destroy_notify);
}

/* Reg Handoff.  Register dissectors we'll need for IPoIB and RoCE */
void proto_reg_handoff_infiniband(void)
{
    dissector_handle_t roce_handle;

    ipv6_handle = find_dissector("ipv6");
    data_handle = find_dissector("data");
    eth_handle = find_dissector("eth");
    ethertype_dissector_table = find_dissector_table("ethertype");

    /* create and announce an anonymous RoCE dissector */
    roce_handle = create_dissector_handle(dissect_roce, proto_infiniband);
    dissector_add_uint("ethertype", ETHERTYPE_ROCE, roce_handle);
}
