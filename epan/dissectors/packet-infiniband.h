/* packet-infiniband.h
 * Routines for Infiniband/ERF Dissection
 * Copyright 2008 Endace Technology Limited
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __PACKET_INFINIBAND_H_
#define __PACKET_INFINIBAND_H_

#define PROTO_TAG_INFINIBAND    "Infiniband"

#include <epan/etypes.h>

/* Wireshark ID */
static int proto_infiniband = -1;

/* Variables to hold expansion values between packets */
/* static gint ett_infiniband = -1;                */
static gint ett_all_headers = -1;
static gint ett_lrh = -1;
static gint ett_grh = -1;
static gint ett_bth = -1;
static gint ett_rwh = -1;
static gint ett_rawdata = -1;
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

/* Global ref to highest level tree should we find other protocols encapsulated in IB */
static proto_tree *top_tree = NULL;
 
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

/* Dissector Declarations */
static dissector_handle_t ipv6_handle;
static dissector_handle_t data_handle;
static dissector_table_t ethertype_dissector_table;

static void dissect_infiniband(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gint32 find_next_header_sequence(guint32 OpCode);
static gboolean contains(guint32 value, guint32* arr, int length);
static void dissect_general_info(tvbuff_t *tvb, gint offset, packet_info *pinfo);

/* Parsing Methods for specific IB headers. */

static void parse_VENDOR(proto_tree *, tvbuff_t *, gint *);
static void parse_PAYLOAD(proto_tree *, packet_info *, tvbuff_t *, gint *, gint length, guint8 virtualLane);
static void parse_IETH(proto_tree *, tvbuff_t *, gint *);
static void parse_IMMDT(proto_tree *, tvbuff_t *, gint *offset);
static void parse_ATOMICACKETH(proto_tree *, tvbuff_t *, gint *offset);
static void parse_AETH(proto_tree *, tvbuff_t *, gint *offset);
static void parse_ATOMICETH(proto_tree *, tvbuff_t *, gint *offset);
static void parse_RETH(proto_tree *, tvbuff_t *, gint *offset);
static void parse_DETH(proto_tree *, tvbuff_t *, gint *offset);
static void parse_RDETH(proto_tree *, tvbuff_t *, gint *offset);
static void parse_IPvSix(proto_tree *, tvbuff_t *, gint *offset, packet_info *);
static void parse_RWH(proto_tree *, tvbuff_t *, gint *offset, packet_info *);

static void parse_SUBN_LID_ROUTED(proto_tree *, packet_info *, tvbuff_t *, gint *offset);
static void parse_SUBN_DIRECTED_ROUTE(proto_tree *, packet_info *, tvbuff_t *, gint *offset);
static void parse_SUBNADMN(proto_tree *, packet_info *, tvbuff_t *, gint *offset);
static void parse_PERF(proto_tree *, tvbuff_t *, gint *offset);
static void parse_BM(proto_tree *, tvbuff_t *, gint *offset);
static void parse_DEV_MGT(proto_tree *, tvbuff_t *, gint *offset);
static void parse_COM_MGT(proto_tree *, tvbuff_t *, gint *offset);
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

#endif
