/* packet-opa-mad.c
 * Routines for Omni-Path MAD header and payload dissection
 * Copyright (c) 2016, Intel Corporation.
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

void proto_reg_handoff_opa_mad(void);
void proto_register_opa_mad(void);

/* MAD Management Classes  */
#define SUBN_LID_ROUTED       0x01
#define SUBN_DIRECTED_ROUTE   0x81
#define SUBNADMN              0x03
#define PERF                  0x04
#define PERFADMN              0x32

/* Depreciated Management Classes */
#define BM                    0x05
#define DEV_MGT               0x06
#define COM_MGT               0x07
#define SNMP                  0x08

/* Default Range Strings */
#define OPA_MGMTCLASS_RANGE_STR   "0x01,0x03-0x04,0x32,0x81"
#define OPA_VENDOR_RANGE_STR      "0x09-0x0F"
#define OPA_VENDOR_RMPP_RANGE_STR "0x30-0x31,0x33-0x4F"
#define OPA_APPLICATION_RANGE_STR "0x10-0x2F"
#define OPA_RESERVED_RANGE_STR    "0x00,0x02,0x50-0x80,0x82-0xFF"

static const value_string MAD_mgmt_names[] = {
    { SUBN_LID_ROUTED,     "Subnet Management (LID Routed)" },
    { SUBNADMN,            "Subnet Administration" },
    { PERF,                "Performance Management" },
    { BM,                  "Baseboard Management" },
    { DEV_MGT,             "Device Management" },
    { COM_MGT,             "Communication Management" },
    { SNMP,                "SNMP" },
    { 0x09,                "VENDOR 0x09" },
    { 0x0A,                "VENDOR 0x0A" },
    { 0x0B,                "VENDOR 0x0B" },
    { 0x0C,                "VENDOR 0x0C" },
    { 0x0D,                "VENDOR 0x0D" },
    { 0x0E,                "VENDOR 0x0E" },
    { 0x0F,                "VENDOR 0x0F" },
    { 0x10,                "APPLICATION 0x10" },
    { 0x11,                "APPLICATION 0x11" },
    { 0x12,                "APPLICATION 0x12" },
    { 0x13,                "APPLICATION 0x13" },
    { 0x14,                "APPLICATION 0x14" },
    { 0x15,                "APPLICATION 0x15" },
    { 0x16,                "APPLICATION 0x16" },
    { 0x17,                "APPLICATION 0x17" },
    { 0x18,                "APPLICATION 0x18" },
    { 0x19,                "APPLICATION 0x19" },
    { 0x1A,                "APPLICATION 0x1A" },
    { 0x1B,                "APPLICATION 0x1B" },
    { 0x1C,                "APPLICATION 0x1C" },
    { 0x1D,                "APPLICATION 0x1D" },
    { 0x1E,                "APPLICATION 0x1E" },
    { 0x1F,                "APPLICATION 0x1F" },
    { 0X20,                "APPLICATION 0X20" },
    { 0x21,                "APPLICATION 0x21" },
    { 0x22,                "APPLICATION 0x22" },
    { 0x23,                "APPLICATION 0x23" },
    { 0x24,                "APPLICATION 0x24" },
    { 0x25,                "APPLICATION 0x25" },
    { 0x26,                "APPLICATION 0x26" },
    { 0x27,                "APPLICATION 0x27" },
    { 0x28,                "APPLICATION 0x28" },
    { 0x29,                "APPLICATION 0x29" },
    { 0x2A,                "APPLICATION 0x2A" },
    { 0x2B,                "APPLICATION 0x2B" },
    { 0x2C,                "APPLICATION 0x2C" },
    { 0x2D,                "APPLICATION 0x2D" },
    { 0x2E,                "APPLICATION 0x2E" },
    { 0x2F,                "APPLICATION 0x2F" },
    { 0x30,                "VENDOR 0x30" },
    { 0x31,                "VENDOR 0x31" },
    { PERFADMN,            "Performance Administration" },
    { 0x33,                "VENDOR 0x33" },
    { 0x34,                "VENDOR 0x34" },
    { 0x35,                "VENDOR 0x35" },
    { 0x36,                "VENDOR 0x36" },
    { 0x37,                "VENDOR 0x37" },
    { 0x38,                "VENDOR 0x38" },
    { 0x39,                "VENDOR 0x39" },
    { 0x3A,                "VENDOR 0x3A" },
    { 0x3B,                "VENDOR 0x3B" },
    { 0x3C,                "VENDOR 0x3C" },
    { 0x3D,                "VENDOR 0x3D" },
    { 0x3E,                "VENDOR 0x3E" },
    { 0x3F,                "VENDOR 0x3F" },
    { 0x40,                "VENDOR 0x40" },
    { 0x41,                "VENDOR 0x41" },
    { 0x42,                "VENDOR 0x42" },
    { 0x43,                "VENDOR 0x43" },
    { 0x44,                "VENDOR 0x44" },
    { 0x45,                "VENDOR 0x45" },
    { 0x46,                "VENDOR 0x46" },
    { 0x47,                "VENDOR 0x47" },
    { 0x48,                "VENDOR 0x48" },
    { 0x49,                "VENDOR 0x49" },
    { 0x4A,                "VENDOR 0x4A" },
    { 0x4B,                "VENDOR 0x4B" },
    { 0x4C,                "VENDOR 0x4C" },
    { 0x4D,                "VENDOR 0x4D" },
    { 0x4E,                "VENDOR 0x4E" },
    { 0x4F,                "VENDOR 0x4F" },
    { SUBN_DIRECTED_ROUTE, "Subnet Management (Direct Routed)" },
    { 0, NULL }
};
static value_string_ext MAD_mgmt_names_ext = VALUE_STRING_EXT_INIT(MAD_mgmt_names);

/* SM Attributes */
#define SM_ATTR_ID_CLASS_PORT_INFO                 0x0001
#define SM_ATTR_ID_NOTICE                          0x0002
#define SM_ATTR_ID_INFORM_INFO                     0x0003
#define SM_ATTR_ID_NODE_DESCRIPTION                0x0010
#define SM_ATTR_ID_NODE_INFO                       0x0011
#define SM_ATTR_ID_SWITCH_INFO                     0x0012
#define SM_ATTR_ID_PORT_INFO                       0x0015
#define SM_ATTR_ID_PART_TABLE                      0x0016
#define SM_ATTR_ID_SL_SC_MAPPING_TABLE             0x0017
#define SM_ATTR_ID_VL_ARBITRATION                  0x0018
#define SM_ATTR_ID_LINEAR_FWD_TABLE                0x0019
#define SM_ATTR_ID_MCAST_FWD_TABLE                 0x001B
#define SM_ATTR_ID_SM_INFO                         0x0020
#define SM_ATTR_ID_LED_INFO                        0x0031
#define SM_ATTR_ID_CABLE_INFO                      0x0032
#define SM_ATTR_ID_AGGREGATE                       0x0080
#define SM_ATTR_ID_SC_SC_MAPPING_TABLE             0x0081
#define SM_ATTR_ID_SC_SL_MAPPING_TABLE             0x0082
#define SM_ATTR_ID_SC_VLR_MAPPING_TABLE            0x0083
#define SM_ATTR_ID_SC_VLT_MAPPING_TABLE            0x0084
#define SM_ATTR_ID_SC_VLNT_MAPPING_TABLE           0x0085
#define SM_ATTR_ID_PORT_STATE_INFO                 0x0087
#define SM_ATTR_ID_PORT_GROUP_FWD_TABLE            0x0088
#define SM_ATTR_ID_PORT_GROUP_TABLE                0x0089
#define SM_ATTR_ID_BUFFER_CONTROL_TABLE            0x008A
#define SM_ATTR_ID_CONGESTION_INFO                 0x008B
#define SM_ATTR_ID_SWITCH_CONGESTION_LOG           0x008C
#define SM_ATTR_ID_SWITCH_CONGESTION_SETTING       0x008D
#define SM_ATTR_ID_SWITCH_PORT_CONGESTION_SETTING  0x008E
#define SM_ATTR_ID_HFI_CONGESTION_LOG              0x008F
#define SM_ATTR_ID_HFI_CONGESTION_SETTING          0x0090
#define SM_ATTR_ID_HFI_CONGESTION_CONTROL_TABLE    0x0091

/* SA Attributes */
#define SA_ATTR_ID_CLASS_PORT_INFO                 0x0001
#define SA_ATTR_ID_NOTICE                          0x0002
#define SA_ATTR_ID_INFORM_INFO                     0x0003
#define SA_ATTR_ID_NODE_RECORD                     0x0011
#define SA_ATTR_ID_PORTINFO_RECORD                 0x0012
#define SA_ATTR_ID_SC_MAPTBL_RECORD                0x0013
#define SA_ATTR_ID_SWITCHINFO_RECORD               0x0014
#define SA_ATTR_ID_LINEAR_FWDTBL_RECORD            0x0015
#define SA_ATTR_ID_MCAST_FWDTBL_RECORD             0x0017
#define SA_ATTR_ID_SMINFO_RECORD                   0x0018
#define SA_ATTR_ID_LINK_SPD_WDTH_PAIRS_RECORD      0x0019
#define SA_ATTR_ID_LINK_RECORD                     0x0020
#define SA_ATTR_ID_SERVICE_RECORD                  0x0031
#define SA_ATTR_ID_P_KEY_TABLE_RECORD              0x0033
#define SA_ATTR_ID_PATH_RECORD                     0x0035
#define SA_ATTR_ID_VLARBTABLE_RECORD               0x0036
#define SA_ATTR_ID_MCMEMBER_RECORD                 0x0038
#define SA_ATTR_ID_TRACE_RECORD                    0x0039
#define SA_ATTR_ID_MULTIPATH_GID_RECORD            0x003A
#define SA_ATTR_ID_SERVICEASSOCIATION_RECORD       0x003B
#define SA_ATTR_ID_SL2SC_MAPTBL_RECORD             0x0080
#define SA_ATTR_ID_SC2SL_MAPTBL_RECORD             0x0081
#define SA_ATTR_ID_SC_VLNT_MAPTBL_RECORD           0x0082
#define SA_ATTR_ID_SC_VLT_MAPTBL_RECORD            0x0083
#define SA_ATTR_ID_SC_VLR_MAPTBL_RECORD            0x0084
#define SA_ATTR_ID_PGROUP_FWDTBL_RECORD            0x0085
#define SA_ATTR_ID_MULTIPATH_GUID_RECORD           0x0086
#define SA_ATTR_ID_MULTIPATH_LID_RECORD            0x0087
#define SA_ATTR_ID_CABLE_INFO_RECORD               0x0088
#define SA_ATTR_ID_VF_INFO_RECORD                  0x0089
#define SA_ATTR_ID_PORTGROUP_TABLE_RECORD          0x008B
#define SA_ATTR_ID_BUFF_CTRL_TAB_RECORD            0x008C
#define SA_ATTR_ID_FABRICINFO_RECORD               0x008D
#define SA_ATTR_ID_QUARANTINED_NODE_RECORD         0x0090
#define SA_ATTR_ID_CONGESTION_INFO_RECORD          0x0091
#define SA_ATTR_ID_SWITCH_CONG_RECORD              0x0092
#define SA_ATTR_ID_SWITCH_PORT_CONG_RECORD         0x0093
#define SA_ATTR_ID_HFI_CONG_RECORD                 0x0094
#define SA_ATTR_ID_HFI_CONG_CTRL_RECORD            0x0095
#define SA_ATTR_ID_INFORM_INFO_RECORD              0x00F3

/* Performance Management class Attributes */
#define PM_ATTR_ID_CLASS_PORTINFO                  0x0001
#define PM_ATTR_ID_PORT_STATUS                     0x0040
#define PM_ATTR_ID_CLEAR_PORT_STATUS               0x0041
#define PM_ATTR_ID_DATA_PORT_COUNTERS              0x0042
#define PM_ATTR_ID_ERROR_PORT_COUNTERS             0x0043
#define PM_ATTR_ID_ERROR_INFO                      0x0044
/* Performance Administration class Attributes */
#define PA_ATTR_ID_CLASS_PORTINFO                  0x0001
#define PA_ATTR_ID_GET_GRP_LIST                    0x00A0
#define PA_ATTR_ID_GET_GRP_INFO                    0x00A1
#define PA_ATTR_ID_GET_GRP_CFG                     0x00A2
#define PA_ATTR_ID_GET_PORT_CTRS                   0x00A3
#define PA_ATTR_ID_CLR_PORT_CTRS                   0x00A4
#define PA_ATTR_ID_CLR_ALL_PORT_CTRS               0x00A5
#define PA_ATTR_ID_GET_PM_CFG                      0x00A6
#define PA_ATTR_ID_FREEZE_IMAGE                    0x00A7
#define PA_ATTR_ID_RELEASE_IMAGE                   0x00A8
#define PA_ATTR_ID_RENEW_IMAGE                     0x00A9
#define PA_ATTR_ID_GET_FOCUS_PORTS                 0x00AA
#define PA_ATTR_ID_GET_IMAGE_INFO                  0x00AB
#define PA_ATTR_ID_MOVE_FREEZE_FRAME               0x00AC
#define PA_ATTR_ID_GET_VF_LIST                     0x00AD
#define PA_ATTR_ID_GET_VF_INFO                     0x00AE
#define PA_ATTR_ID_GET_VF_CONFIG                   0x00AF
#define PA_ATTR_ID_GET_VF_PORT_CTRS                0x00B0
#define PA_ATTR_ID_CLR_VF_PORT_CTRS                0x00B1
#define PA_ATTR_ID_GET_VF_FOCUS_PORTS              0x00B2

/* Attributes */
static const value_string SUBM_Attributes[] = {
    { SM_ATTR_ID_CLASS_PORT_INFO,                "Attribute (ClassPortInfo)" },
    { SM_ATTR_ID_NOTICE,                         "Attribute (Notice)" },
    { SM_ATTR_ID_INFORM_INFO,                    "Attribute (InformInfo)" },
    { SM_ATTR_ID_NODE_DESCRIPTION,               "Attribute (NodeDescription)" },
    { SM_ATTR_ID_NODE_INFO,                      "Attribute (NodeInfo)" },
    { SM_ATTR_ID_SWITCH_INFO,                    "Attribute (SwitchInfo)" },
    { SM_ATTR_ID_PORT_INFO,                      "Attribute (PortInfo)" },
    { SM_ATTR_ID_PART_TABLE,                     "Attribute (PKeyTable)" },
    { SM_ATTR_ID_SL_SC_MAPPING_TABLE,            "Attribute (SLSCMappingTable)" },
    { SM_ATTR_ID_VL_ARBITRATION,                 "Attribute (VLArbitrationTable)" },
    { SM_ATTR_ID_LINEAR_FWD_TABLE,               "Attribute (LinearForwardingTable)" },
    { SM_ATTR_ID_MCAST_FWD_TABLE,                "Attribute (MulticastForwardingTable)" },
    { SM_ATTR_ID_SM_INFO,                        "Attribute (SMInfo)" },
    { SM_ATTR_ID_LED_INFO,                       "Attribute (LedInfo)" },
    { SM_ATTR_ID_CABLE_INFO,                     "Attribute (CableInfo)" },
    { SM_ATTR_ID_AGGREGATE,                      "Attribute (Aggregate)" },
    { SM_ATTR_ID_SC_SC_MAPPING_TABLE,            "Attribute (SCSCMappingTable)" },
    { SM_ATTR_ID_SC_SL_MAPPING_TABLE,            "Attribute (SCSLMappingTable)" },
    { SM_ATTR_ID_SC_VLR_MAPPING_TABLE,           "Attribute (SCVLRMappingTable)" },
    { SM_ATTR_ID_SC_VLT_MAPPING_TABLE,           "Attribute (SCVLTMappingTable)" },
    { SM_ATTR_ID_SC_VLNT_MAPPING_TABLE,          "Attribute (SCVLNTMappingTable)" },
    { SM_ATTR_ID_PORT_STATE_INFO,                "Attribute (PortStateInfo)" },
    { SM_ATTR_ID_PORT_GROUP_FWD_TABLE,           "Attribute (PortGroupForwardingTable)" },
    { SM_ATTR_ID_PORT_GROUP_TABLE,               "Attribute (PortGroupTable)" },
    { SM_ATTR_ID_BUFFER_CONTROL_TABLE,           "Attribute (BufferControlTable)" },
    { SM_ATTR_ID_CONGESTION_INFO,                "Attribute (CongestionInfo)" },
    { SM_ATTR_ID_SWITCH_CONGESTION_LOG,          "Attribute (SwitchCongestionLog)" },
    { SM_ATTR_ID_SWITCH_CONGESTION_SETTING,      "Attribute (SwitchCongestionSetting)" },
    { SM_ATTR_ID_SWITCH_PORT_CONGESTION_SETTING, "Attribute (SwitchPortCongestionSetting)" },
    { SM_ATTR_ID_HFI_CONGESTION_LOG,             "Attribute (HFICongestionLog)" },
    { SM_ATTR_ID_HFI_CONGESTION_SETTING,         "Attribute (HFICongestionSetting)" },
    { SM_ATTR_ID_HFI_CONGESTION_CONTROL_TABLE,   "Attribute (HFICongestionControlTable)" },
    { 0, NULL }
};
static const value_string SUBA_Attributes[] = {
    { SA_ATTR_ID_CLASS_PORT_INFO,                 "Attribute (ClassPortInfo)" },
    { SA_ATTR_ID_NOTICE,                          "Attribute (Notice)" },
    { SA_ATTR_ID_INFORM_INFO,                     "Attribute (InformInfo)" },
    { SA_ATTR_ID_NODE_RECORD,                     "Attribute (NodeRecord)" },
    { SA_ATTR_ID_PORTINFO_RECORD,                 "Attribute (PortInfoRecord)" },
    { SA_ATTR_ID_SC_MAPTBL_RECORD,                "Attribute (SCMappingTableRecord)" },
    { SA_ATTR_ID_SWITCHINFO_RECORD,               "Attribute (SwitchInfoRecord)" },
    { SA_ATTR_ID_LINEAR_FWDTBL_RECORD,            "Attribute (LinearForwardingTableRecord)" },
    { SA_ATTR_ID_MCAST_FWDTBL_RECORD,             "Attribute (MulticastForwardingTableRecord)" },
    { SA_ATTR_ID_SMINFO_RECORD,                   "Attribute (SMInfoRecord)" },
    { SA_ATTR_ID_LINK_SPD_WDTH_PAIRS_RECORD,      "Attribute (LinkSpeedWidthPairsTableRecord)" },
    { SA_ATTR_ID_LINK_RECORD,                     "Attribute (LinkRecord)" },
    { SA_ATTR_ID_SERVICE_RECORD,                  "Attribute (ServiceRecord)" },
    { SA_ATTR_ID_P_KEY_TABLE_RECORD,              "Attribute (P_KeyTableRecord)" },
    { SA_ATTR_ID_PATH_RECORD,                     "Attribute (PathRecord)" },
    { SA_ATTR_ID_VLARBTABLE_RECORD,               "Attribute (VLArbitrationTableRecord)" },
    { SA_ATTR_ID_MCMEMBER_RECORD,                 "Attribute (MulticastMemberRecord)" },
    { SA_ATTR_ID_TRACE_RECORD,                    "Attribute (TraceRecord)" },
    { SA_ATTR_ID_MULTIPATH_GID_RECORD,            "Attribute (MultiPathRecord)" },
    { SA_ATTR_ID_SERVICEASSOCIATION_RECORD,       "Attribute (ServiceAssociationRecord)" },
    { SA_ATTR_ID_SL2SC_MAPTBL_RECORD,             "Attribute (SLtoSCMappingTableRecord)" },
    { SA_ATTR_ID_SC2SL_MAPTBL_RECORD,             "Attribute (SCtoSLMappingTableRecord)" },
    { SA_ATTR_ID_SC_VLNT_MAPTBL_RECORD,           "Attribute (SCtoVLNTMappingTableRecord)" },
    { SA_ATTR_ID_SC_VLT_MAPTBL_RECORD,            "Attribute (SCtoVLTMappingTableRecord)" },
    { SA_ATTR_ID_SC_VLR_MAPTBL_RECORD,            "Attribute (SCtoVLRMappingTableRecord)" },
    { SA_ATTR_ID_PGROUP_FWDTBL_RECORD,            "Attribute (PortGroupForwardTableRecord)" },
    { SA_ATTR_ID_MULTIPATH_GUID_RECORD,           "Attribute (MultipathGUIDRecord)" },
    { SA_ATTR_ID_MULTIPATH_LID_RECORD,            "Attribute (MultipathLIDRecord)" },
    { SA_ATTR_ID_CABLE_INFO_RECORD,               "Attribute (CableInfoRecord)" },
    { SA_ATTR_ID_VF_INFO_RECORD,                  "Attribute (VFInfoRecord)" },
    { SA_ATTR_ID_PORTGROUP_TABLE_RECORD,          "Attribute (PortGroupTableRecord)" },
    { SA_ATTR_ID_BUFF_CTRL_TAB_RECORD,            "Attribute (BufferControlTableRecord)" },
    { SA_ATTR_ID_FABRICINFO_RECORD,               "Attribute (FabricInfoRecord)" },
    { SA_ATTR_ID_QUARANTINED_NODE_RECORD,         "Attribute (QuarantinedNodeRecord)" },
    { SA_ATTR_ID_CONGESTION_INFO_RECORD,          "Attribute (CongestionInfoRecord)" },
    { SA_ATTR_ID_SWITCH_CONG_RECORD,              "Attribute (SwitchCongestionRecord)" },
    { SA_ATTR_ID_SWITCH_PORT_CONG_RECORD,         "Attribute (SwitchPortCongestionRecord)" },
    { SA_ATTR_ID_HFI_CONG_RECORD,                 "Attribute (HFICongestionRecord)" },
    { SA_ATTR_ID_HFI_CONG_CTRL_RECORD,            "Attribute (HFICongestionControlRecord)" },
    { SA_ATTR_ID_INFORM_INFO_RECORD,              "Attribute (InformInfoRecord)" },
    { 0, NULL }
};
static const value_string PM_Attributes[] = {
    { PM_ATTR_ID_CLASS_PORTINFO,               "Attribute (ClassPortInfo)" },
    { PM_ATTR_ID_PORT_STATUS,                  "Attribute (PortStatus)" },
    { PM_ATTR_ID_CLEAR_PORT_STATUS,            "Attribute (ClearPortStatus)" },
    { PM_ATTR_ID_DATA_PORT_COUNTERS,           "Attribute (DataPortCounters)" },
    { PM_ATTR_ID_ERROR_PORT_COUNTERS,          "Attribute (ErrorPortCounters)" },
    { PM_ATTR_ID_ERROR_INFO,                   "Attribute (ErrorInfo)" },
    { 0, NULL }
};
static const value_string PA_Attributes[] = {
    { PA_ATTR_ID_CLASS_PORTINFO,               "Attribute (ClassPortInfo)" },
    { PA_ATTR_ID_GET_GRP_LIST,                 "Attribute (GetGroupList)" },
    { PA_ATTR_ID_GET_GRP_INFO,                 "Attribute (GetGroupInfo)" },
    { PA_ATTR_ID_GET_GRP_CFG,                  "Attribute (GetGroupConfig)" },
    { PA_ATTR_ID_GET_PORT_CTRS,                "Attribute (GetPortCounters)" },
    { PA_ATTR_ID_CLR_PORT_CTRS,                "Attribute (ClearPortCounters)" },
    { PA_ATTR_ID_CLR_ALL_PORT_CTRS,            "Attribute (ClearAllPortCounters)" },
    { PA_ATTR_ID_GET_PM_CFG,                   "Attribute (GetPerfMgmtConfig)" },
    { PA_ATTR_ID_FREEZE_IMAGE,                 "Attribute (FreezeImage)" },
    { PA_ATTR_ID_RELEASE_IMAGE,                "Attribute (ReleaseImage)" },
    { PA_ATTR_ID_RENEW_IMAGE,                  "Attribute (RenewImage)" },
    { PA_ATTR_ID_GET_FOCUS_PORTS,              "Attribute (GetFocusPorts)" },
    { PA_ATTR_ID_GET_IMAGE_INFO,               "Attribute (GetImageInfo)" },
    { PA_ATTR_ID_MOVE_FREEZE_FRAME,            "Attribute (MoveFreezeFrame)" },
    { PA_ATTR_ID_GET_VF_LIST,                  "Attribute (GetVFList)" },
    { PA_ATTR_ID_GET_VF_INFO,                  "Attribute (GetVFInfo)" },
    { PA_ATTR_ID_GET_VF_CONFIG,                "Attribute (GetVFConfig)" },
    { PA_ATTR_ID_GET_VF_PORT_CTRS,             "Attribute (GetVFPortCounters)" },
    { PA_ATTR_ID_CLR_VF_PORT_CTRS,             "Attribute (ClearVFPortCounters)" },
    { PA_ATTR_ID_GET_VF_FOCUS_PORTS,           "Attribute (GetVFFocusPorts)" },
    { 0, NULL }
};

/* Methods */
#define METHOD_GET                   0x01
#define METHOD_SET                   0x02
#define METHOD_SEND                  0x03
#define METHOD_TRAP                  0x05
#define METHOD_REPORT                0x06
#define METHOD_TRAPREPRESS           0x07
#define METHOD_GETTABLE              0x12
#define METHOD_GETTRACETABLE         0x13
#define METHOD_GETMULTI              0x14
#define METHOD_DELETE                0x15

#define METHOD_GET_RESP              0x81
#define METHOD_REPORT_RESP           0x86
#define METHOD_GETTABLE_RESP         0x92
#define METHOD_GETTRACETABLE_RESP    0x93
#define METHOD_GETMULTI_RESP         0x94
#define METHOD_DELETE_RESP           0x95
static const value_string Methods[] = {
    { METHOD_GET,                "Get()" },
    { METHOD_GET_RESP,           "GetResp()" },
    { METHOD_SET,                "Set()" },
    { METHOD_SEND,               "Send()" },
    { METHOD_TRAP,               "Trap()" },
    { METHOD_REPORT,             "Report()" },
    { METHOD_REPORT_RESP,        "ReportResp()" },
    { METHOD_TRAPREPRESS,        "TrapRepress()" },
    { METHOD_GETTABLE,           "GetTable()" },
    { METHOD_GETTABLE_RESP,      "GetTableResp()" },
    { METHOD_GETTRACETABLE,      "GetTraceTable()" },
    { METHOD_GETTRACETABLE_RESP, "GetTraceTableResp()" },
    { METHOD_GETMULTI,           "GetMulti()" },
    { METHOD_GETMULTI_RESP,      "GetMultiResp()" },
    { METHOD_DELETE,             "Delete()" },
    { METHOD_DELETE_RESP,        "DeleteResp()" },
    { 0, NULL }
};
static const value_string SUBM_Methods[] = {
    { METHOD_GET,                "SubnGet(" },
    { METHOD_SET,                "SubnSet(" },
    { METHOD_GET_RESP,           "SubnGetResp(" },
    { METHOD_TRAP,               "SubnTrap(" },
    { METHOD_TRAPREPRESS,        "SubnTrapRepress(" },
    { 0, NULL }
};
static const value_string SUBA_Methods[] = {
    { METHOD_GET,                "SubnAdmGet(" },
    { METHOD_GET_RESP,           "SubnAdmGetResp(" },
    { METHOD_SET,                "SubnAdmSet(" },
    { METHOD_REPORT,             "SubnAdmReport(" },
    { METHOD_REPORT_RESP,        "SubnAdmReportResp(" },
    { METHOD_GETTABLE,           "SubnAdmGetTable(" },
    { METHOD_GETTABLE_RESP,      "SubnAdmGetTableResp(" },
    { METHOD_GETTRACETABLE,      "SubnAdmGetTraceTable(" },
    { METHOD_GETMULTI,           "SubnAdmGetMulti(" },
    { METHOD_GETMULTI_RESP,      "SubnAdmGetMultiResp(" },
    { METHOD_DELETE,             "SubnAdmDelete(" },
    { METHOD_DELETE_RESP,        "SubnAdmDeleteResp(" },
    { 0, NULL }
};
static const value_string PM_Methods[] = {
    { METHOD_GET,                "PerfGet(" },
    { METHOD_SET,                "PerfSet(" },
    { METHOD_GET_RESP,           "PerfGetResp(" },
    { 0, NULL }
};
static const value_string PA_Methods[] = {
    { METHOD_GET,                "PerfAdmGet(" },
    { METHOD_SET,                "PerfAdmSet(" },
    { METHOD_GET_RESP,           "PerfAdmGetResp(" },
    { METHOD_GETTABLE,           "PerfAdmGetTable(" },
    { METHOD_GETTABLE_RESP,      "PerfAdmGetTableResp(" },
    { 0, NULL }
};

/* RMPP Types */
#define RMPP_ILLEGAL        0
#define RMPP_DATA           1
#define RMPP_ACK            2
#define RMPP_STOP           3
#define RMPP_ABORT          4
static const value_string RMPP_Packet_Types[] = {
    { RMPP_ILLEGAL, "Illegal RMPP Type (0)! " },
    { RMPP_DATA,    "RMPP (DATA)" },
    { RMPP_ACK,     "RMPP (ACK)" },
    { RMPP_STOP,    "RMPP (STOP)" },
    { RMPP_ABORT,   "RMPP (ABORT)" },
    { 0, NULL }
};
static const value_string RMPP_Status[] = {
    {   0, " (Normal)" },
    {   1, " (Resources Exhausted)" },
    { 118, " (Total Time Too Long)" },
    { 119, " (Inconsistent Last and PayloadLength)" },
    { 120, " (Inconsistent First and Segment Number)" },
    { 121, " (Bad RMPPType)" },
    { 122, " (NewWindowLast Too Small)" },
    { 123, " (SegmentNumber Too Big)" },
    { 124, " (Illegal Status)" },
    { 125, " (Unsupported Version)" },
    { 126, " (Too Many Retries)" },
    { 127, " (Unspecified - Unknown Error Code on ABORT)" },
    { 0, NULL }
};

/* MAD_t
* Structure to hold information from the common MAD header.
* This is necessary because the MAD header contains information which significantly changes the dissection algorithm. */
#define STL_MAX_MAD_PAYLOAD 2048
typedef struct _MAD {
    uint8_t BaseVersion;
    uint8_t MgmtClass;
    uint8_t ClassVersion;
    uint8_t Method;
    uint16_t Status; /* D = bit 15 when DR */
    uint8_t HopPointer; /* Reserved in DR MADs */
    uint8_t HopCount; /* Reserved in DR MADs */
    uint64_t TransactionID;
    uint16_t AttributeID;
    uint16_t Reserved2;
    uint32_t AttributeModifier;
} MAD_t;
#define STL_MAX_RMPP_PAYLOAD 2036
#define RMPP_FLAG_LAST_MASK 0x04
#define RMPP_FLAG_LAST_SHIFT 2
#define RMPP_FLAG_FIRST_MASK 0x02
#define RMPP_FLAG_FIRST_SHIFT 1
#define RMPP_FLAG_ACTIVE_MASK 0x01
#define RMPP_FLAG_ACTIVE_SHIFT 0
typedef struct _RMPP {
    uint8_t Version;
    uint8_t Type;
    uint8_t resptime_flags;
    uint8_t Status;
    uint32_t SegmentNumber;
    uint32_t PayloadLength;
} RMPP_t;

#define STL_MAX_SA_PA_PAYLOAD 1992
typedef struct _SA_HEADER {
    uint64_t SM_Key;
    uint16_t AttributeOffset;
    uint16_t Reserved;
    uint64_t ComponentMask;
} SA_HEADER_t, PA_HEADER_t;

/* Trap Type/Descriptions for dissection */
static const value_string NoticeType[] = {
    { 0, "Fatal" },
    { 1, "Urgent" },
    { 2, "Security" },
    { 3, "SM" },
    { 4, "Info" },
    { 0, NULL }
};
static const value_string Trap_Description[] = {
    { 64, " (Informational) <GIDADDR> is now in service" },
    { 65, " (Informational) <GIDADDR> is out of service" },
    { 66, " (Informational) New Multicast Group with multicast address <GIDADDR> is now created" },
    { 67, " (Informational) Multicast Group with multicast address <GIDADDR> is now deleted" },
    { 68, " (Informational) Paths indicated by <PATH_REC> and <COMP_MASK> are no longer valid" },
    { 69, " (Informational) Paths indicated by <PATH_REC> and <COMP_MASK> have been recomputed" },
    { 128, " (Urgent) Link State of at least one port of switch at <LIDADDR> has changed" },
    { 129, " (Urgent) Local Link Integrity threshold reached at <LIDADDR><PORTNO>" },
    { 130, " (Urgent) Excessive Buffer OVerrun threshold reached at <LIDADDR><PORTNO>" },
    { 131, " (Urgent) Flow Control Update watchdog timer expired at <LIDADDR><PORTNO>" },
    { 144, " (Informational) CapMask, NodeDesc, LinkWidthEnabled or LinkSpeedEnabled at <LIDADDR> has been modified" },
    { 145, " (Informational) SystemImageGUID at <LIDADDR> has been modified.  New value is <SYSTEMIMAGEGUID>" },
    { 256, " (Security) Bad M_Key, <M_KEY> from <LIDADDR> attempted <METHOD> with <ATTRIBUTEID> and <ATTRIBUTEMODIFIER>" },
    { 257, " (Security) Bad P_Key, <KEY> from <LIDADDR1><GIDADDR1><QP1> to <LIDADDR2><GIDADDR2><QP2> on <SL>" },
    { 258, " (Security) Bad Q_Key, <KEY> from <LIDADDR1><GIDADDR1><QP1> to <LIDADDR2><GIDADDR2><QP2> on <SL>" },
    { 259, " (Security) Bad P_Key, <KEY> from <LIDADDR1><GIDADDR1><QP1> to <LIDADDR2><GIDADDR2><QP2> on <SL> at switch <LIDADDR><PORTNO>" },
    { 2048, " (Informational) LinkWidth.Active, LinkWidthDowngrade.TxActive or LinkWidthDowngrade.RxActive of at least one port of switch at <REPORTINGLID> has changed" },
    { 0, NULL }
};
static const value_string RoutingMode[] = {
    { 0x00, "No change" },
    { 0x01, "Linear routing algorithm" },
    { 0x02, "Hierarchical routing algorithm" },
    { 0, NULL }
};
static const value_string AdaptiveRoutingAlgorithm[] = {
    { 0x0, "Random" },
    { 0x1, "Greedy" },
    { 0x2, "Random Greedy" },
    { 0, NULL }
};
static const value_string PortType[] = {
    { 0, "Unknown" },
    { 1, "Disconnected" },
    { 2, "Fixed" },
    { 3, "Variable" },
    { 4, "QSFP" },
    { 5, "SiPh_x16" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 8, "Reserved" },
    { 9, "Reserved" },
    { 10, "Reserved" },
    { 11, "Reserved" },
    { 12, "Reserved" },
    { 13, "Reserved" },
    { 14, "Reserved" },
    { 15, "Reserved" },
    { 0, NULL }
};
static const value_string NodeType[] = {
    { 1, "FI" },
    { 2, "Switch" },
    { 0, NULL }
};
static const value_string LinkDownReason[] = {
    {  0, "No specified reason" },
    {  1, "Receive Error 0" },
    {  2, "Bad packet length" },
    {  3, "Packet too long" },
    {  4, "Packet too short" },
    {  5, "Bad SLID" },
    {  6, "Bad DLID" },
    {  7, "Bad L2" },
    {  8, "Bad SC" },
    {  9, "Receive Error 8" },
    { 10, "Bad mid tail" },
    { 11, "Receive Error 10" },
    { 12, "Preempt error" },
    { 13, "Preempt VL15" },
    { 14, "Bad VL marker" },
    { 15, "Receive Error 14" },
    { 16, "Receive Error 15" },
    { 17, "Bad head dist" },
    { 18, "Bad tail dist" },
    { 19, "Bad ctrl dist" },
    { 20, "Bad credit ack" },
    { 21, "Unsupported VL marker" },
    { 22, "Bad preempt" },
    { 23, "Bad control flit" },
    { 24, "Exceed multicast limit" },
    { 25, "Receive Error 24" },
    { 26, "Receive Error 25" },
    { 27, "Receive Error 26" },
    { 28, "Receive Error 27" },
    { 29, "Receive Error 28" },
    { 30, "Receive Error 29" },
    { 31, "Receive Error 30" },
    { 32, "Excessive buffer overrun" },
    { 33, "Unknown (locally initiated)" },
    { 35, "Reboot" },
    { 36, "Neighbor Unknown (not locally initiated)" },
    { 39, "FM initiated bounce" },
    { 40, "Link outside speed policy" },
    { 41, "Link downgrade outside" },
    { 49, "Disconnected" },
    { 50, "Local media not installed" },
    { 51, "Not installed" },
    { 52, "Chassis config" },
    { 54, "End to end not installed" },
    { 56, "Power policy" },
    { 57, "Linkspeed policy" },
    { 58, "Linkwidth policy" },
    { 60, "Switch management" },
    { 61, "Sma disabled" },
    { 63, "Transient" },
    { 0, NULL }
};
static const value_string LinkInitReason[] = {
    {  0, "No Error" },
    {  1, "Link just came up" },
    {  2, "FM ignoring flapping port" },
    {  8, "FM ignoring, width or speed, outside FM configured policy" },
    {  9, "FM ignoring, quarantined for security" },
    { 10, "FM ignoring, link has insufficient capabilities for FM configuration" },
    { 0, NULL },
};
static const value_string DiagCode[] = {
    { 0x0000, "Function Ready" },
    { 0x0001, "Performing Self Test" },
    { 0x0002, "Initializing" },
    { 0x0003, "Soft Error - Function has non-fatal error" },
    { 0x0004, "Hard Error - Function has fatal error" },
    { 0, NULL }
};
static const value_string PortFlitDistanceMode[] = {
    { 0x0000, "No State Change" },
    { 0x0001, "STL1 Mode" },
    { 0x0002, "STL2 Mode" },
    { 0, NULL }
};
static const value_string PortState[] = {
    { 0x0000, "No State Change" },
    { 0x0001, "Down (includes failed links)" },
    { 0x0002, "Initialized" },
    { 0x0003, "Armed" },
    { 0x0004, "Active" },
    { 0, NULL }
};
static const value_string PortPhysicalState[] = {
    { 0x0000, "No State Change" },
    { 0x0002, "Polling" },
    { 0x0003, "Disabled" },
    { 0x0004, "PortConfigurationTraining" },
    { 0x0005, "LinkUp" },
    { 0x0006, "LinkErrorRecovery" },
    { 0x0009, "Offline" },
    { 0x000B, "Test" },
    { 0, NULL }
};
static const value_string OfflineDisabledReason[] = {
    { 0x0000, "No reason available" },
    { 0x0001, "Disconnected" },
    { 0x0002, "Local Media not Installed" },
    { 0x0003, "Not Installed" },
    { 0x0004, "Chassis Config" },
    { 0x0005, "Reserved" },
    { 0x0006, "End-to-end not Installed" },
    { 0x0007, "Reserved" },
    { 0x0008, "Power Policy" },
    { 0x0009, "Link Speed Policy" },
    { 0x000A, "Link Width Policy" },
    { 0x000B, "Reserved" },
    { 0x000C, "Switch Mgmt" },
    { 0x000D, "SMA Disabled" },
    { 0x000E, "Reserved" },
    { 0x000F, "Transient" },
    { 0, NULL }
};
static const value_string MTU[] = {
    { 0x0001, "256" },   /* IB_MTU_256 */
    { 0x0002, "512" },   /* IB_MTU_512 */
    { 0x0003, "1024" },  /* IB_MTU_1024 */
    { 0x0004, "2048" },  /* IB_MTU_2048 */
    { 0x0005, "4096" },  /* IB_MTU_4096 */
    { 0x0006, "8192" },  /* STL_MTU_8192 */
    { 0x0007, "10240" }, /* STL_MTU_10240 */
    { 0, NULL }
};
static const value_string Rate[] = {
    { 11, "12.5 Gbps" }, /* IB_STATIC_RATE_14G */
    { 15, "25 Gbps" },   /* IB_STATIC_RATE_25G */
    { 7,  "37.5 Gbps" }, /* IB_STATIC_RATE_40G */
    { 12, "50 Gbps" },   /* IB_STATIC_RATE_56G */
    { 9,  "75 Gbps" },   /* IB_STATIC_RATE_80G */
    { 16, "100 Gbps" },  /* IB_STATIC_RATE_100G */
    { 17, "200 Gbps" },  /* IB_STATIC_RATE_200G */
    { 0, NULL }
};
static const true_false_string tfs_PKeyMembershipType = {
    "Full",
    "Limited"
};
static const value_string MADAttrModSectionVLarb[] = {
    { 0, "Arbitration Low Weight Elements" },
    { 1, "Arbitration High Weight Elements" },
    { 2, "Preemption Weight Elements" },
    { 3, "Preemption Matrix" },
    { 0, NULL }
};
static const value_string MADAttrModSectionVLarb_short[] = {
    { 0, "Low Weight" },
    { 1, "High Weight" },
    { 2, "Preemption Weight" },
    { 3, "Preemption Matrix" },
    { 0, NULL }
};
static const value_string SA_SC_VLx[] = {
    { SA_ATTR_ID_SC_VLNT_MAPTBL_RECORD, "nt" },
    { SA_ATTR_ID_SC_VLT_MAPTBL_RECORD, "t" },
    { SA_ATTR_ID_SC_VLR_MAPTBL_RECORD, "r" },
    { 0, NULL }
};
static const value_string SM_SC_VLx[] = {
    { SM_ATTR_ID_SC_VLNT_MAPPING_TABLE, "nt" },
    { SM_ATTR_ID_SC_VLT_MAPPING_TABLE, "t" },
    { SM_ATTR_ID_SC_VLR_MAPPING_TABLE, "r" },
    { 0, NULL }
};
static const value_string GroupTablePosition[] = {
    { 0, "1-64" },
    { 1, "65-128" },
    { 2, "129-192" },
    { 3, "193-256" },
    { 0, NULL },
};
static const value_string AdaptiveRoutingThreshold[] = {
    { 0, "Default tuning" },
    { 1, "Consumed nearly all of the buffering(or Tags) for a VL (~100%)" },
    { 2, "90%" },
    { 3, "80%" },
    { 4, "70%" },
    { 5, "65%" },
    { 6, "60%" },
    { 7, "55%" },
    { 0, NULL }
};
static const value_string LinkQualityIndicator[] = {
    { 0, "Down" },
    { 1, "Bad" },
    { 2, "Poor" },
    { 3, "Good" },
    { 4, "Very Good" },
    { 5, "Excellent" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL },
};
/*static const value_string LinkQualityIndicatorLong[] = {
    { 0, "link down" },
    { 1, "working far below acceptable link quality, recommend immediate corrective action" },
    { 2, "working below acceptable link quality, recommend consider timely corrective action" },
    { 3, "working on low end of acceptable link quality, recommended to consider corrective action on next maintenance window" },
    { 4, "working slightly below preferred link quality, but no action required" },
    { 5, "working at or above preferred link quality, no action needed" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL },
};*/
static const true_false_string tfs_NeighborFWAuthenBypass = {
    "Not Authenticated",
    "Authenticated"
};
static const true_false_string tfs_SwPortCongSetting_CtrlType = {
    "Credit Starvation",
    "Packet Marketing"
};
static const true_false_string tfs_clear_dont_clear = {
    "Clear",
    "Don't Clear"
};
static const value_string MAD_Status_InvalidField[] = {
    { 0, "No Invalid Fields" },
    { 1, "Bad Version" },
    { 2, "Method not supported" },
    { 3, "The method/attribute combination is not supported" },
    { 4, "Reserved" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "One or more fields in the attribute or attribute modifier contain an invalid value" },
    { 0, NULL }
};
static const true_false_string tfs_busy_not_busy = {
    "Busy",
    "Not Busy"
};
static const true_false_string tfs_redirect_no_redirect = {
    "Redirect",
    "No Redirect"
};
static const value_string FocusPortFlags[] = {
    { 0, "OK" },
    { 1, "PMA Ignore" },
    { 2, "PMA Failure" },
    { 3, "Topo Failure" },
    { 0, NULL  },
};

#define PM_UTIL_BUCKETS 10
#define PM_ERR_BUCKETS 5

/* Wireshark ID */
static int proto_opa_mad;

/* Variables to hold expansion values between packets */
static int ett_payload;
static int ett_sm_lid;
static int ett_sm_dr;
static int ett_sa;
static int ett_pm;
static int ett_pa;
static int ett_mad;
static int ett_mad_status;
static int ett_mad_attributemod;
static int ett_rmpp;
static int ett_rmpp_fragment;
static int ett_rmpp_fragments;
static int ett_rmpp_sa_record;
/* Common */
static int ett_noticestraps;
static int ett_datadetails;
static int ett_datadetails_trap259datavalid;
static int ett_informinfo;
static int ett_classportinfo;
static int ett_classportinfo_redirect;
static int ett_classportinfo_trap;
/* SM */
static int ett_nodedescription;
static int ett_nodeinfo;
static int ett_switchinfo;
static int ett_switchinfo_switchcapabilitymask;
static int ett_portinfo;
static int ett_portinfo_vl;
static int ett_portinfo_link;
static int ett_portinfo_portmode;
static int ett_portinfo_flitcontrol;
static int ett_portinfo_porterroraction;
static int ett_portinfo_neighbormtu;
static int ett_portinfo_xmitq;
static int ett_portinfo_capmask;
static int ett_portinfo_capmask3;
static int ett_portstates;
static int ett_pkeytable;
static int ett_pkeytable_block;
static int ett_sltoscmapping;
static int ett_sltoscmapping_block;
static int ett_sctoscmapping;
static int ett_sctoscmapping_block;
static int ett_sctoslmapping;
static int ett_sctoslmapping_block;
static int ett_sctovlxmappingtable;
static int ett_sctovlxmappingtable_block;
static int ett_vlarbitrationtable;
static int ett_vlarbitrationtable_port;
static int ett_linearforwardingtable;
static int ett_linearforwardingtable_block;
static int ett_multicastforwardingtable;
static int ett_multicastforwardingtable_block;
static int ett_portgroupforwardingtable;
static int ett_portgroupforwardingtable_block;
static int ett_portgrouptable;
static int ett_portgrouptable_block;
static int ett_sminfo;
static int ett_ledinfo;
static int ett_cableinfo;
static int ett_aggregate;
static int ett_buffercontroltable;
static int ett_congestioninfo;
static int ett_switchcongestionlog;
static int ett_switchcongestionlog_entry;
static int ett_switchcongestionsetting;
static int ett_switchportcongestionsetting;
static int ett_switchportcongestionsetting_port;
static int ett_hficongestionlog;
static int ett_hficongestionlog_entry;
static int ett_hficongestionsetting;
static int ett_hficongestioncontroltable;
static int ett_hficongestioncontroltable_block;
/* SA */
static int ett_portinforecord_linkdownreason;
static int ett_portinforecord_linkdownreason_entry;
static int ett_scmappingrecord;
static int ett_lftrecord;
static int ett_linkrecord;
static int ett_servicerecord;
static int ett_pathrecord;
static int ett_pathrecord_dgid;
static int ett_pathrecord_sgid;
static int ett_mcmemberrecord;
static int ett_tracerecord;
static int ett_multipathrecord_gid;
static int ett_multipathrecord_guid;
static int ett_multipathrecord_lid;
static int ett_cableinforecord;
static int ett_serviceassocrecord;
static int ett_sctoslmappingtablerecord;
static int ett_portgroupforwardingtablerecord;
static int ett_vfinforecord;
static int ett_quarantinednoderecord;
static int ett_fabricinforecord;
/* PM */
static int ett_portstatus;
static int ett_portstatus_vl;
static int ett_clearportstatus;
static int ett_clearportstatus_counterselectmask;
static int ett_dataportcounters;
static int ett_dataportcounters_port;
static int ett_dataportcounters_vl;
static int ett_errorportcounters;
static int ett_errorportcounters_port;
static int ett_errorportinfo;
static int ett_errorportinfoport;
static int ett_errorportinfo_portrcverrorinfo;
static int ett_errorportinfo_excessivebufferoverruninfo;
static int ett_errorportinfo_portxmitconstrainterrorinfo;
static int ett_errorportinfo_portrcvconstrainterrorinfo;
static int ett_errorportinfo_portrcvswitchrelayerrorinfo;
static int ett_errorportinfo_uncorrectableerrorinfo;
static int ett_errorportinfo_fmconfigerrorinfo;
/* PA */
static int ett_getgrouplist;
static int ett_getgroupinfo;
static int ett_getgroupinfoutilstats;
static int ett_getgroupinfoutilbuckets;
static int ett_getgroupinfoerrorsummary;
static int ett_getgroupinfoerrintegritybucket;
static int ett_getgroupinfoerrcongestionbucket;
static int ett_getgroupinfoerrsmacongestionbucket;
static int ett_getgroupinfoerrbubblebucket;
static int ett_getgroupinfoerrsecuritybucket;
static int ett_getgroupinfoerrroutingbucket;
static int ett_getportcounters;
static int ett_clearportcounters;
static int ett_clearportcounters_counterselectmask;
static int ett_clearallportcounters;
static int ett_clearallportcounters_counterselectmask;
static int ett_pmconfig;
static int ett_getgroupconfig;
static int ett_getgroupconfigport;
static int ett_movefreezeframeold;
static int ett_movefreezeframenew;
static int ett_getfocusports;
static int ett_getfocusportsport;
static int ett_getimageinfo;
static int ett_getimageinfosm;
static int ett_getvflist;
static int ett_getvfinfo;
static int ett_getvfinfoutilstats;
static int ett_getvfinfoutilbuckets;
static int ett_getvfinfoerrorsummary;
static int ett_getvfinfoerrintegritybucket;
static int ett_getvfinfoerrcongestionbucket;
static int ett_getvfinfoerrsmacongestionbucket;
static int ett_getvfinfoerrbubblebucket;
static int ett_getvfinfoerrsecuritybucket;
static int ett_getvfinfoerrroutingbucket;
static int ett_getvfconfig;
static int ett_getvfconfigport;
static int ett_getvffocusports;
static int ett_getvffocusportsport;
static int ett_getvfportcounters;
static int ett_clearvfportcounters;
static int ett_clearvfportcounters_counterselectmask;

/* Reserved Fields */
static int hf_opa_reserved8;
static int hf_opa_reserved16;
static int hf_opa_reserved24;
static int hf_opa_reserved32;
static int hf_opa_reserved64;
/* opa_MAD Dissector */
static int hf_opa_etype;
static int hf_opa_etype_reserved16;
/* SM Header - Lid Routed*/
static int hf_opa_sm_lid;
static int hf_opa_sm_m_key;
/* SM Header - Directed Route */
static int hf_opa_sm_dr;
static int hf_opa_sm_dr_slid;
static int hf_opa_sm_dr_dlid;
static int hf_opa_sm_dr_initial_path;
static int hf_opa_sm_dr_return_path;
static int hf_opa_sm_dr_reserved64;
/* SA Header */
static int hf_opa_sa;
static int hf_opa_sa_sm_key;
static int hf_opa_sa_attribute_offset;
static int hf_opa_sa_component_mask;
/* PM Header / PA Header */
static int hf_opa_pm;
static int hf_opa_pa;
static int hf_opa_pa_sm_key;
static int hf_opa_pa_attribute_offset;
static int hf_opa_pa_component_mask;
/* Other Vendor Header */
static int hf_opa_vendor;
static int hf_opa_application;
static int hf_opa_reservedmclass;
static int hf_opa_unknown;

/* MAD Header */
static int hf_opa_mad;
static int hf_opa_mad_base_version;
static int hf_opa_mad_mgmt_class;
static int hf_opa_mad_class_version;
static int hf_opa_mad_method;
static int hf_opa_mad_status;
static int hf_opa_mad_status_DR_D;
static int hf_opa_mad_status_DR_status;
static int hf_opa_mad_status_DR_Hop_Pointer;
static int hf_opa_mad_status_DR_Hop_Count;
static int hf_opa_mad_status_NM_ClassSpecific;
static int hf_opa_mad_status_NM_reserved1;
static int hf_opa_mad_status_NM_InvalidField;
static int hf_opa_mad_status_NM_RedirectRqrd;
static int hf_opa_mad_status_NM_Busy;
static int * const _mad_status[] = {
    &hf_opa_mad_status_NM_ClassSpecific,
    &hf_opa_mad_status_NM_reserved1,
    &hf_opa_mad_status_NM_InvalidField,
    &hf_opa_mad_status_NM_RedirectRqrd,
    &hf_opa_mad_status_NM_Busy,
    NULL
};
static int hf_opa_mad_transaction_id;
static int hf_opa_mad_attribute_id;
static int hf_opa_attribute_modifier;
static int hf_opa_attribute_modifier_A;
static int hf_opa_attribute_modifier_A2;
static int hf_opa_attribute_modifier_A3;
static int hf_opa_attribute_modifier_A4;
static int hf_opa_attribute_modifier_A5;
static int hf_opa_attribute_modifier_A6;
static int hf_opa_attribute_modifier_B;
static int hf_opa_attribute_modifier_B2;
static int hf_opa_attribute_modifier_B3;
static int hf_opa_attribute_modifier_B4;
static int hf_opa_attribute_modifier_B5;
static int hf_opa_attribute_modifier_E;
static int hf_opa_attribute_modifier_I;
static int hf_opa_attribute_modifier_L;
static int hf_opa_attribute_modifier_NP;
static int hf_opa_attribute_modifier_NB;
static int hf_opa_attribute_modifier_N2;
static int hf_opa_attribute_modifier_P;
static int hf_opa_attribute_modifier_P2;
static int hf_opa_attribute_modifier_P3;
static int hf_opa_attribute_modifier_S;
static int hf_opa_attribute_modifier_S2;
static int hf_opa_attribute_modifier_Y;
static int * const _attribute_modifier_Nps2AP[] = {
    &hf_opa_attribute_modifier_NP,
    &hf_opa_attribute_modifier_S2,
    &hf_opa_attribute_modifier_A,
    &hf_opa_attribute_modifier_P,
    NULL
};
static int * const _attribute_modifier_NpS2P[] = {
    &hf_opa_attribute_modifier_NP,
    &hf_opa_attribute_modifier_S2,
    &hf_opa_attribute_modifier_P,
    NULL
};
static int * const _attribute_modifier_NpAP[] = {
    &hf_opa_attribute_modifier_NP,
    &hf_opa_attribute_modifier_A,
    &hf_opa_attribute_modifier_P,
    NULL
};
static int * const _attribute_modifier_NbP2B[] = {
    &hf_opa_attribute_modifier_NB,
    &hf_opa_attribute_modifier_P2,
    &hf_opa_attribute_modifier_B,
    NULL
};
static int * const _attribute_modifier_NbA2B2IE[] = {
    &hf_opa_attribute_modifier_NB,
    &hf_opa_attribute_modifier_A2,
    &hf_opa_attribute_modifier_B2,
    &hf_opa_attribute_modifier_I,
    &hf_opa_attribute_modifier_E,
    NULL
};
static int * const _attribute_modifier_NpSAP[] = {
    &hf_opa_attribute_modifier_NP,
    &hf_opa_attribute_modifier_S,
    &hf_opa_attribute_modifier_A,
    &hf_opa_attribute_modifier_P,
    NULL
};
static int * const _attribute_modifier_NbA3B3[] = {
    &hf_opa_attribute_modifier_NB,
    &hf_opa_attribute_modifier_A3,
    &hf_opa_attribute_modifier_B3,
    NULL
};
static int * const _attribute_modifier_NbP3A4B4[] = {
    &hf_opa_attribute_modifier_NB,
    &hf_opa_attribute_modifier_P3,
    &hf_opa_attribute_modifier_A4,
    &hf_opa_attribute_modifier_B4,
    NULL
};
static int * const _attribute_modifier_A5LP[] = {
    &hf_opa_attribute_modifier_A5,
    &hf_opa_attribute_modifier_L,
    &hf_opa_attribute_modifier_P,
    NULL
};
static int * const _attribute_modifier_NbYAP[] = {
    &hf_opa_attribute_modifier_NB,
    &hf_opa_attribute_modifier_Y,
    &hf_opa_attribute_modifier_A,
    &hf_opa_attribute_modifier_P,
    NULL
};
static int * const _attribute_modifier_NpP[] = {
    &hf_opa_attribute_modifier_NP,
    &hf_opa_attribute_modifier_P,
    NULL
};
static int * const _attribute_modifier_NbP[] = {
    &hf_opa_attribute_modifier_NB,
    &hf_opa_attribute_modifier_P,
    NULL
};
static int * const _attribute_modifier_NbP3A6B5[] = {
    &hf_opa_attribute_modifier_NB,
    &hf_opa_attribute_modifier_P3,
    &hf_opa_attribute_modifier_A6,
    &hf_opa_attribute_modifier_B5,
    NULL
};
/* RMPP Header */
static int hf_opa_rmpp;
static int hf_opa_rmpp_version;
static int hf_opa_rmpp_type;
static int hf_opa_rmpp_r_resp_time;
static int hf_opa_rmpp_flags_last;
static int hf_opa_rmpp_flags_first;
static int hf_opa_rmpp_flags_active;
static int hf_opa_rmpp_status;
static int hf_opa_rmpp_data1;
static int hf_opa_rmpp_data2;
static int hf_opa_rmpp_segment_number;
static int hf_opa_rmpp_payload_length32;
static int hf_opa_rmpp_new_window_last;
/* SA Packets */
/* SA RID */
static int hf_opa_sa_Lid;
static int hf_opa_sa_EndportLID;
static int hf_opa_sa_PortNum;
static int hf_opa_sa_InputPortNum;
static int hf_opa_sa_OutputPortNum;
static int hf_opa_sa_Port;
static int hf_opa_sa_reserved14;
static int hf_opa_sa_BlockNum_18b;
static int hf_opa_sa_Position;
static int hf_opa_sa_Position_16b;
static int hf_opa_sa_reserved9;
static int hf_opa_sa_reserved9_16b;
static int hf_opa_sa_BlockNum_21b;
static int hf_opa_sa_BlockNum_8b;
static int hf_opa_sa_BlockNum_16b;
static int hf_opa_sa_BlockNum_5b;
static int hf_opa_sa_SubscriberLID;
static int hf_opa_sa_Enum;
static int hf_opa_sa_FromLID;
static int hf_opa_sa_FromPort;
static int hf_opa_sa_ServiceID;
static int hf_opa_sa_ServiceLID;
static int hf_opa_sa_ServiceP_Key;
static int hf_opa_sa_ServiceGID;
static int hf_opa_sa_MGID;
static int hf_opa_sa_PortGID;

/* Attribute Specific Fields */
static int hf_opa_Notice;
static int hf_opa_Notice_IsGeneric;
static int hf_opa_Notice_Type;
static int hf_opa_Notice_ProducerType;
static int hf_opa_Notice_TrapNumber;
static int hf_opa_Notice_VendorID;
static int hf_opa_Notice_DeviceID;
static int hf_opa_Notice_IssuerLID;
static int hf_opa_Notice_IssuerGID;
static int hf_opa_Notice_Toggle;
static int hf_opa_Notice_Count;
static int hf_opa_Notice_ClassDataDetails;
static int hf_opa_Trap;
static int hf_opa_Trap_GID;
static int hf_opa_Trap_LID;
static int hf_opa_Trap_PORTNO;
static int hf_opa_Trap_CAPABILITYMASK;
static int hf_opa_Trap_CAPABILITYMASK3;
static int hf_opa_Trap_144_reserved;
static int hf_opa_Trap_LinkWidthDowngradeEnabledChange;
static int hf_opa_Trap_LinkSpeecEnabledChange;
static int hf_opa_Trap_LinkWidthEnabledChange;
static int hf_opa_Trap_NodeDescriptionChange;
static int hf_opa_Trap_SystemImageGUID;
static int hf_opa_Trap_DRSLID;
static int hf_opa_Trap_Method;
static int hf_opa_Trap_AttributeID;
static int hf_opa_Trap_AttributeModifier;
static int hf_opa_Trap_MKey;
static int hf_opa_Trap_DRNotice;
static int hf_opa_Trap_DRPathTruncated;
static int hf_opa_Trap_DRHopCount;
static int hf_opa_Trap_DRNoticeReturnPath;
static int hf_opa_Trap_Key;
static int hf_opa_Trap_SL;
static int hf_opa_Trap_SL_reserved;
static int hf_opa_Trap_QP;
static int hf_opa_Trap_DataValid;
static int hf_opa_Trap_DataValid_Lid1;
static int hf_opa_Trap_DataValid_Lid2;
static int hf_opa_Trap_DataValid_PKey;
static int hf_opa_Trap_DataValid_SL;
static int hf_opa_Trap_DataValid_QP1;
static int hf_opa_Trap_DataValid_QP2;
static int hf_opa_Trap_DataValid_Gid1;
static int hf_opa_Trap_DataValid_Gid2;
static int hf_opa_Trap_DataValid_Reserved;
static int * const _Trap_DataValid[] = {
    &hf_opa_Trap_DataValid_Lid1,
    &hf_opa_Trap_DataValid_Lid2,
    &hf_opa_Trap_DataValid_PKey,
    &hf_opa_Trap_DataValid_SL,
    &hf_opa_Trap_DataValid_QP1,
    &hf_opa_Trap_DataValid_QP2,
    &hf_opa_Trap_DataValid_Gid1,
    &hf_opa_Trap_DataValid_Gid2,
    &hf_opa_Trap_DataValid_Reserved,
    NULL
};
static int hf_opa_Trap_PKey;
static int hf_opa_ClassPortInfo;
static int hf_opa_ClassPortInfo_BaseVersion;
static int hf_opa_ClassPortInfo_ClassVersion;
static int hf_opa_ClassPortInfo_CapMask;
static int hf_opa_ClassPortInfo_CapMask2;
static int hf_opa_ClassPortInfo_RespTimeValue;
static int hf_opa_ClassPortInfo_Redirect_GID;
static int hf_opa_ClassPortInfo_Redirect_TClass;
static int hf_opa_ClassPortInfo_Redirect_SL;
static int hf_opa_ClassPortInfo_Redirect_reserved;
static int hf_opa_ClassPortInfo_Redirect_FlowLabel;
static int hf_opa_ClassPortInfo_Redirect_LID;
static int hf_opa_ClassPortInfo_Redirect_reserved2;
static int hf_opa_ClassPortInfo_Redirect_QP;
static int hf_opa_ClassPortInfo_Redirect_Q_Key;
static int hf_opa_ClassPortInfo_Trap_GID;
static int hf_opa_ClassPortInfo_Trap_TClass;
static int hf_opa_ClassPortInfo_Trap_reserved;
static int hf_opa_ClassPortInfo_Trap_FlowLabel;
static int hf_opa_ClassPortInfo_Trap_LID;
static int hf_opa_ClassPortInfo_Trap_HopLimit;
static int hf_opa_ClassPortInfo_Trap_QP;
static int hf_opa_ClassPortInfo_Trap_Q_Key;
static int hf_opa_ClassPortInfo_Trap_P_Key;
static int hf_opa_ClassPortInfo_Redirect_P_Key;
static int hf_opa_ClassPortInfo_Trap_SL;
static int hf_opa_ClassPortInfo_Trap_reserved2;
static int hf_opa_InformInfo;
static int hf_opa_InformInfo_GID;
static int hf_opa_InformInfo_LIDRangeBegin;
static int hf_opa_InformInfo_LIDRangeEnd;
static int hf_opa_InformInfo_IsGeneric;
static int hf_opa_InformInfo_Subscribe;
static int hf_opa_InformInfo_Type;
static int hf_opa_InformInfo_TrapNumber;
static int hf_opa_InformInfo_DeviceID;
static int hf_opa_InformInfo_QPN;
static int hf_opa_InformInfo_reserved;
static int hf_opa_InformInfo_RespTimeValue;
static int hf_opa_InformInfo_ProducerType;
static int hf_opa_InformInfo_VendorID;
/* SM */
static int hf_opa_NodeDescription;
static int hf_opa_NodeDescription_NodeString;
static int hf_opa_NodeInfo;
static int hf_opa_NodeInfo_BaseVersion;
static int hf_opa_NodeInfo_ClassVersion;
static int hf_opa_NodeInfo_NodeType;
static int hf_opa_NodeInfo_NumPorts;
static int hf_opa_NodeInfo_SystemImageGUID;
static int hf_opa_NodeInfo_NodeGUID;
static int hf_opa_NodeInfo_PortGUID;
static int hf_opa_NodeInfo_PartitionCap;
static int hf_opa_NodeInfo_DeviceID;
static int hf_opa_NodeInfo_Revision;
static int hf_opa_NodeInfo_LocalPortNum;
static int hf_opa_NodeInfo_VendorID;
static int hf_opa_SwitchInfo;
static int hf_opa_SwitchInfo_LinearFDBCap;
static int hf_opa_SwitchInfo_MulticastFDBCap;
static int hf_opa_SwitchInfo_LinearFDBTop;
static int hf_opa_SwitchInfo_MulticastFDBTop;
static int hf_opa_SwitchInfo_CollectiveCap;
static int hf_opa_SwitchInfo_CollectiveTop;
static int hf_opa_SwitchInfo_IPAddrIPv6;
static int hf_opa_SwitchInfo_IPAddrIPv4;
static int hf_opa_SwitchInfo_LifeTimeValue;
static int hf_opa_SwitchInfo_PortStateChange;
static int hf_opa_SwitchInfo_reserved2;
static int hf_opa_SwitchInfo_PartitionEnforcementCap;
static int hf_opa_SwitchInfo_PortGroupCap;
static int hf_opa_SwitchInfo_PortGroupTop;
static int hf_opa_SwitchInfo_SupportedRoutingMode;
static int hf_opa_SwitchInfo_EnabledRoutingMode;
static int hf_opa_SwitchInfo_reserved3;
static int hf_opa_SwitchInfo_EnhancedPortZero;
static int hf_opa_SwitchInfo_reserved4;
static int hf_opa_SwitchInfo_reserved5;
static int hf_opa_SwitchInfo_CollectiveMask;
static int hf_opa_SwitchInfo_MulticastMask;
static int hf_opa_SwitchInfo_AdaptiveRoutingEnable;
static int hf_opa_SwitchInfo_AdaptiveRoutingPause;
static int hf_opa_SwitchInfo_AdaptiveRoutingAlgorithm;
static int hf_opa_SwitchInfo_AdaptiveRoutingFrequency;
static int hf_opa_SwitchInfo_AdaptiveRoutingLostRoutesOnly;
static int hf_opa_SwitchInfo_AdaptiveRoutingThreshold;
static int hf_opa_SwitchInfo_reserved6;
static int * const _SwitchInfo_AdaptiveRouting[] = {
    &hf_opa_SwitchInfo_AdaptiveRoutingEnable,
    &hf_opa_SwitchInfo_AdaptiveRoutingPause,
    &hf_opa_SwitchInfo_AdaptiveRoutingAlgorithm,
    &hf_opa_SwitchInfo_AdaptiveRoutingFrequency,
    &hf_opa_SwitchInfo_AdaptiveRoutingLostRoutesOnly,
    &hf_opa_SwitchInfo_AdaptiveRoutingThreshold,
    &hf_opa_SwitchInfo_reserved6,
    NULL
};
static int hf_opa_SwitchInfo_SwitchCapabilityMask;
static int hf_opa_SwitchInfo_SwitchCapabilityMask_reserved;
static int hf_opa_SwitchInfo_SwitchCapabilityMask_IsAddrRangeConfigSupported;
static int hf_opa_SwitchInfo_SwitchCapabilityMask_reserved2;
static int hf_opa_SwitchInfo_SwitchCapabilityMask_IsAdaptiveRoutingSupported;
static int * const _SwitchInfo_SwitchCapabilityMask[] = {
    &hf_opa_SwitchInfo_SwitchCapabilityMask_reserved,
    &hf_opa_SwitchInfo_SwitchCapabilityMask_IsAddrRangeConfigSupported,
    &hf_opa_SwitchInfo_SwitchCapabilityMask_reserved2,
    &hf_opa_SwitchInfo_SwitchCapabilityMask_IsAdaptiveRoutingSupported,
    NULL
};
static int hf_opa_SwitchInfo_CapabilityMaskCollectives;
static int hf_opa_PortInfo;
static int hf_opa_PortInfo_LID;
static int hf_opa_PortInfo_FlowControlMask;
static int hf_opa_PortInfo_VL_PreemptCap;
static int hf_opa_PortInfo_VL_reserved;
static int hf_opa_PortInfo_VL_Cap;
static int hf_opa_PortInfo_VL_HighLimit;
static int hf_opa_PortInfo_VL_PreemptingLimit;
static int hf_opa_PortInfo_VL_ArbitrationHighCap;
static int hf_opa_PortInfo_VL_ArbitrationLowCap;
static int hf_opa_PortInfo_PortPhysConfig_reserved;
static int hf_opa_PortInfo_PortPhysConfig_PortType;
static int hf_opa_PortInfo_MultiCollectMask_reserved;
static int hf_opa_PortInfo_MultiCollectMask_CollectiveMask;
static int hf_opa_PortInfo_MultiCollectMask_MulticastMask;
static int hf_opa_PortInfo_M_KeyProtectBits;
static int hf_opa_PortInfo_S1_reserved;
static int hf_opa_PortInfo_LMC;
static int hf_opa_PortInfo_S2_reserved;
static int hf_opa_PortInfo_MasterSMSL;
static int hf_opa_PortInfo_LinkInitReason;
static int hf_opa_PortInfo_PartitionEnforcementInbound;
static int hf_opa_PortInfo_PartitionEnforcementOutbound;
static int hf_opa_PortInfo_S3_reserved2;
static int hf_opa_PortInfo_S4_reserved;
static int hf_opa_PortInfo_OperationalVL;
static int hf_opa_PortInfo_P_Keys_P_Key_8B;
static int hf_opa_PortInfo_P_Keys_P_Key_10B;
static int hf_opa_PortInfo_M_KeyViolations;
static int hf_opa_PortInfo_P_KeyViolations;
static int hf_opa_PortInfo_Q_KeyViolations;
static int hf_opa_PortInfo_TrapQueuePair_reserved;
static int hf_opa_PortInfo_TrapQueuePair;
static int hf_opa_PortInfo_SAQueuePair_reserved;
static int hf_opa_PortInfo_SAQueuePair;
static int hf_opa_PortInfo_NeighborPortNum;
static int hf_opa_PortInfo_LinkDownReason;
static int hf_opa_PortInfo_NeighborLinkDownReason;
static int hf_opa_PortInfo_ClientReregister;
static int hf_opa_PortInfo_MulticastPKeyTrapSuppressEnabled;
static int hf_opa_PortInfo_Timeout;
static int hf_opa_PortInfo_LinkSpeedSupported;
static int hf_opa_PortInfo_LinkSpeedEnabled;
static int hf_opa_PortInfo_LinkSpeedActive;
static int hf_opa_PortInfo_LinkWidthSupported;
static int hf_opa_PortInfo_LinkWidthEnabled;
static int hf_opa_PortInfo_LinkWidthActive;
static int hf_opa_PortInfo_LinkWidthDowngrade_Supported;
static int hf_opa_PortInfo_LinkWidthDowngrade_Enabled;
static int hf_opa_PortInfo_LinkWidthDowngrade_TxActive;
static int hf_opa_PortInfo_LinkWidthDowngrade_RxActive;
static int hf_opa_PortInfo_PortLinkMode_reserved;
static int hf_opa_PortInfo_PortLinkMode_Supported;
static int hf_opa_PortInfo_PortLinkMode_Enabled;
static int hf_opa_PortInfo_PortLinkMode_Active;
static int hf_opa_PortInfo_PortLTPCRCMode_reserved;
static int hf_opa_PortInfo_PortLTPCRCMode_Supported;
static int hf_opa_PortInfo_PortLTPCRCMode_Enabled;
static int hf_opa_PortInfo_PortLTPCRCMode_Active;
static int hf_opa_PortInfo_PortMode;
static int hf_opa_PortInfo_PortMode_reserved;
static int hf_opa_PortInfo_PortMode_IsActiveOptimizeEnabled;
static int hf_opa_PortInfo_PortMode_IsPassThroughEnabled;
static int hf_opa_PortInfo_PortMode_IsVLMarkerEnabled;
static int hf_opa_PortInfo_PortMode_reserved2;
static int hf_opa_PortInfo_PortMode_Is16BTrapQueryEnabled;
static int hf_opa_PortInfo_PortMode_reserved3;
static int * const _PortInfo_PortMode[] = {
    &hf_opa_PortInfo_PortMode_reserved,
    &hf_opa_PortInfo_PortMode_IsActiveOptimizeEnabled,
    &hf_opa_PortInfo_PortMode_IsPassThroughEnabled,
    &hf_opa_PortInfo_PortMode_IsVLMarkerEnabled,
    &hf_opa_PortInfo_PortMode_reserved2,
    &hf_opa_PortInfo_PortMode_Is16BTrapQueryEnabled,
    &hf_opa_PortInfo_PortMode_reserved3,
    NULL
};
static int hf_opa_PortInfo_PortPacketFormats_Supported;
static int hf_opa_PortInfo_PortPacketFormats_Enabled;
static int hf_opa_PortInfo_FlitControl_Interleave_reserved;
static int hf_opa_PortInfo_FlitControl_Interleave_DistanceSupported;
static int hf_opa_PortInfo_FlitControl_Interleave_DistanceEnabled;
static int hf_opa_PortInfo_FlitControl_Interleave_MaxNestLevelTxEnabled;
static int hf_opa_PortInfo_FlitControl_Interleave_MaxNestLevelRxSupported;
static int hf_opa_PortInfo_FlitControl_Preemption_MinInitial;
static int hf_opa_PortInfo_FlitControl_Preemption_MinTail;
static int hf_opa_PortInfo_FlitControl_Preemption_LargePacketLimit;
static int hf_opa_PortInfo_FlitControl_Preemption_SmallPacketLimit;
static int hf_opa_PortInfo_FlitControl_Preemption_MaxSmallPacketLimit;
static int hf_opa_PortInfo_FlitControl_Preemption_PreemptionLimit;
static int hf_opa_PortInfo_PortErrorAction;
static int hf_opa_PortInfo_PortErrorAction_ExcessiveBufferOverrun;
static int hf_opa_PortInfo_PortErrorAction_reserved;
static int hf_opa_PortInfo_PortErrorAction_FmConfigErrorExceedMulticastLimit;
static int hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadControlFlit;
static int hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadPreempt;
static int hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadVLMarker;
static int hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadCrdtAck;
static int hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadCtrlDist;
static int hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadTailDist;
static int hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadHeadDist;
static int hf_opa_PortInfo_PortErrorAction_reserved2;
static int hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadVLMarker;
static int hf_opa_PortInfo_PortErrorAction_PortRcvErrorPreemptVL15;
static int hf_opa_PortInfo_PortErrorAction_PortRcvErrorPreemptError;
static int hf_opa_PortInfo_PortErrorAction_reserved3;
static int hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadMidTail;
static int hf_opa_PortInfo_PortErrorAction_PortRcvErrorReserved;
static int hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadSC;
static int hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadL2;
static int hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadDLID;
static int hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadSLID;
static int hf_opa_PortInfo_PortErrorAction_PortRcvErrorPktLenTooShort;
static int hf_opa_PortInfo_PortErrorAction_PortRcvErrorPktLenTooLong;
static int hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadPktLen;
static int hf_opa_PortInfo_PortErrorAction_reserved4;
static int * const _PortInfo_PortErrorAction[] = {
    &hf_opa_PortInfo_PortErrorAction_ExcessiveBufferOverrun,
    &hf_opa_PortInfo_PortErrorAction_reserved,
    &hf_opa_PortInfo_PortErrorAction_FmConfigErrorExceedMulticastLimit,
    &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadControlFlit,
    &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadPreempt,
    &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadVLMarker,
    &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadCrdtAck,
    &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadCtrlDist,
    &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadTailDist,
    &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadHeadDist,
    &hf_opa_PortInfo_PortErrorAction_reserved2,
    &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadVLMarker,
    &hf_opa_PortInfo_PortErrorAction_PortRcvErrorPreemptVL15,
    &hf_opa_PortInfo_PortErrorAction_PortRcvErrorPreemptError,
    &hf_opa_PortInfo_PortErrorAction_reserved3,
    &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadMidTail,
    &hf_opa_PortInfo_PortErrorAction_PortRcvErrorReserved,
    &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadSC,
    &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadL2,
    &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadDLID,
    &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadSLID,
    &hf_opa_PortInfo_PortErrorAction_PortRcvErrorPktLenTooShort,
    &hf_opa_PortInfo_PortErrorAction_PortRcvErrorPktLenTooLong,
    &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadPktLen,
    &hf_opa_PortInfo_PortErrorAction_reserved4,
    NULL
};
static int hf_opa_PortInfo_PassThroughControl_EgressPort;
static int hf_opa_PortInfo_PassThroughControl_reserved;
static int hf_opa_PortInfo_PassThroughControl_DRControl;
static int hf_opa_PortInfo_M_KeyLeasePeriod;
static int hf_opa_PortInfo_BufferUnits_reserved;
static int hf_opa_PortInfo_BufferUnits_VL15Init;
static int hf_opa_PortInfo_BufferUnits_VL15CreditRate;
static int hf_opa_PortInfo_BufferUnits_CreditAck;
static int hf_opa_PortInfo_BufferUnits_BufferAlloc;
static int hf_opa_PortInfo_MasterSMLID;
static int hf_opa_PortInfo_M_Key;
static int hf_opa_PortInfo_SubnetPrefix;
static int hf_opa_PortInfo_VL1;
static int hf_opa_PortInfo_VL2;
static int hf_opa_PortInfo_XmitQ_VLStallCount;
static int hf_opa_PortInfo_XmitQ_HOQLife;
static int hf_opa_PortInfo_IPAddrIPv6;
static int hf_opa_PortInfo_IPAddrIPv4;
static int hf_opa_PortInfo_NeighborNodeGUID;
static int hf_opa_PortInfo_CapabilityMask;
static int hf_opa_PortInfo_CapabilityMask_reserved;
static int hf_opa_PortInfo_CapabilityMask_IsCapabilityMaskNoticeSupported;
static int hf_opa_PortInfo_CapabilityMask_reserved2;
static int hf_opa_PortInfo_CapabilityMask_IsVendorClassSupported;
static int hf_opa_PortInfo_CapabilityMask_IsDeviceManagementSupported;
static int hf_opa_PortInfo_CapabilityMask_reserved3;
static int hf_opa_PortInfo_CapabilityMask_IsConnectionManagementSupported;
static int hf_opa_PortInfo_CapabilityMask_reserved4;
static int hf_opa_PortInfo_CapabilityMask_IsAutomaticMigrationSupported;
static int hf_opa_PortInfo_CapabilityMask_reserved5;
static int hf_opa_PortInfo_CapabilityMask_IsSM;
static int hf_opa_PortInfo_CapabilityMask_reserved6;
static int * const _PortInfo_CapabilityMask[] = {
    &hf_opa_PortInfo_CapabilityMask_reserved,
    &hf_opa_PortInfo_CapabilityMask_IsCapabilityMaskNoticeSupported,
    &hf_opa_PortInfo_CapabilityMask_reserved2,
    &hf_opa_PortInfo_CapabilityMask_IsVendorClassSupported,
    &hf_opa_PortInfo_CapabilityMask_IsDeviceManagementSupported,
    &hf_opa_PortInfo_CapabilityMask_reserved3,
    &hf_opa_PortInfo_CapabilityMask_IsConnectionManagementSupported,
    &hf_opa_PortInfo_CapabilityMask_reserved4,
    &hf_opa_PortInfo_CapabilityMask_IsAutomaticMigrationSupported,
    &hf_opa_PortInfo_CapabilityMask_reserved5,
    &hf_opa_PortInfo_CapabilityMask_IsSM,
    &hf_opa_PortInfo_CapabilityMask_reserved6,
    NULL
};
static int hf_opa_PortInfo_CapabilityMask3;
static int hf_opa_PortInfo_CapabilityMask3_reserved;
static int hf_opa_PortInfo_CapabilityMask3_IsSnoopSupported;
static int hf_opa_PortInfo_CapabilityMask3_IsAsyncSCtoVLSupported;
static int hf_opa_PortInfo_CapabilityMask3_IsAddrRangeConfigSupported;
static int hf_opa_PortInfo_CapabilityMask3_IsPassThroughSupported;
static int hf_opa_PortInfo_CapabilityMask3_IsSharedSpaceSupported;
static int hf_opa_PortInfo_CapabilityMask3_reserved2;
static int hf_opa_PortInfo_CapabilityMask3_IsVLMarkerSupported;
static int hf_opa_PortInfo_CapabilityMask3_IsVLrSupported;
static int * const _PortInfo_CapabilityMask3[] = {
    &hf_opa_PortInfo_CapabilityMask3_reserved,
    &hf_opa_PortInfo_CapabilityMask3_IsSnoopSupported,
    &hf_opa_PortInfo_CapabilityMask3_IsAsyncSCtoVLSupported,
    &hf_opa_PortInfo_CapabilityMask3_IsAddrRangeConfigSupported,
    &hf_opa_PortInfo_CapabilityMask3_IsPassThroughSupported,
    &hf_opa_PortInfo_CapabilityMask3_IsSharedSpaceSupported,
    &hf_opa_PortInfo_CapabilityMask3_reserved2,
    &hf_opa_PortInfo_CapabilityMask3_IsVLMarkerSupported,
    &hf_opa_PortInfo_CapabilityMask3_IsVLrSupported,
    NULL
};
static int hf_opa_PortInfo_OverallBufferSpace;
static int hf_opa_PortInfo_DiagCode;
static int hf_opa_PortInfo_ReplayDepth_BufferDepth;
static int hf_opa_PortInfo_ReplayDepth_WireDepth;
static int hf_opa_PortInfo_PortNeighborMode_reserved;
static int hf_opa_PortInfo_PortNeighborMode_MgmtAllowed;
static int hf_opa_PortInfo_PortNeighborMode_NeighborFWAuthenBypass;
static int hf_opa_PortInfo_PortNeighborMode_NeighborNodeType;
static int hf_opa_PortInfo_MTU_reserved;
static int hf_opa_PortInfo_MTU_Cap;
static int hf_opa_PortInfo_Resp_reserved;
static int hf_opa_PortInfo_Resp_TimeValue;
static int hf_opa_PortInfo_LocalPortNum;
static int hf_opa_PortStates;
static int hf_opa_PortStates_reserved;
static int hf_opa_PortStates_LEDEnabled;
static int hf_opa_PortStates_IsSMConfigurationStarted;
static int hf_opa_PortStates_NeighborNormal;
static int hf_opa_PortStates_OfflineDisabledReason;
static int hf_opa_PortStates_PortUnsleepState;
static int hf_opa_PortStates_DownDefaultState;
static int hf_opa_PortStates_PortPhysicalState;
static int hf_opa_PortStates_PortState;
static int * const _PortStates[] = {
    &hf_opa_PortStates_reserved,
    &hf_opa_PortStates_LEDEnabled,
    &hf_opa_PortStates_IsSMConfigurationStarted,
    &hf_opa_PortStates_NeighborNormal,
    &hf_opa_PortStates_OfflineDisabledReason,
    &hf_opa_PortStates_PortUnsleepState,
    &hf_opa_PortStates_DownDefaultState,
    &hf_opa_PortStates_PortPhysicalState,
    &hf_opa_PortStates_PortState,
    NULL
};
static int hf_opa_PortStates_LinkWidthDowngradeTxActive;
static int hf_opa_PortStates_LinkWidthDowngradeRxActive;
static int hf_opa_P_KeyTable;
static int hf_opa_P_KeyTable_MembershipType;
static int hf_opa_P_KeyTable_P_KeyBase;
static int hf_opa_SLtoSCMappingTable;
static int hf_opa_SLtoSCMappingTable_SLtoSC_HighBits;
static int hf_opa_SLtoSCMappingTable_SLtoSC_LowBits;
static int hf_opa_SCtoSCMappingTable;
static int hf_opa_SCtoSCMappingTable_SCtoSC_HighBits;
static int hf_opa_SCtoSCMappingTable_SCtoSC_LowBits;
static int hf_opa_SCtoSLMappingTable;
static int hf_opa_SCtoSLMappingTable_SCtoSL_HighBits;
static int hf_opa_SCtoSLMappingTable_SCtoSL_LowBits;
static int hf_opa_SCtoVLxMappingTable;
static int hf_opa_SCtoVLxMappingTable_SCtoVLx_HighBits;
static int hf_opa_SCtoVLxMappingTable_SCtoVLx_LowBits;
static int hf_opa_VLArbitrationTable;
static int hf_opa_VLArbitrationTable_reserved;
static int hf_opa_VLArbitrationTable_VL;
static int hf_opa_VLArbitrationTable_Weight;
static int hf_opa_VLArbitrationTable_Matrix;
static int hf_opa_LinearForwardingTable;
static int hf_opa_LinearForwardingTable_Port;
static int hf_opa_MulticastForwardingTable;
static int hf_opa_MulticastForwardingTable_PortMask;
static int hf_opa_PortGroupForwardingTable;
static int hf_opa_PortGroupForwardingTable_Port;
static int hf_opa_PortGroupTable;
static int hf_opa_PortGroupTable_PortMask;
static int hf_opa_SMInfo;
static int hf_opa_SMInfo_GUID;
static int hf_opa_SMInfo_SM_Key;
static int hf_opa_SMInfo_ActCount;
static int hf_opa_SMInfo_ElapsedTime;
static int hf_opa_SMInfo_Priority;
static int hf_opa_SMInfo_ElevatedPriority;
static int hf_opa_SMInfo_InitialPriority;
static int hf_opa_SMInfo_SMState;
static int hf_opa_LedInfo;
static int hf_opa_LedInfo_LedMask;
static int hf_opa_LedInfo_reserved;
static int hf_opa_CableInfo;
static int hf_opa_CableInfo_Data;
static int hf_opa_CableInfo_DataStream;
static int hf_opa_Aggregate;
static int hf_opa_Aggregate_AttributeID;
static int hf_opa_Aggregate_Error;
static int hf_opa_Aggregate_RequestLength;
static int hf_opa_BufferControlTable;
static int hf_opa_BufferControlTable_TxOverallSharedLimit;
static int hf_opa_BufferControlTable_TxDedicatedLimit;
static int hf_opa_BufferControlTable_TxSharedLimit;
static int hf_opa_CongestionInfo;
static int hf_opa_CongestionInfo_CongestionInfo;
static int hf_opa_CongestionInfo_ControlTableCap;
static int hf_opa_CongestionInfo_CongestionLogLength;
static int hf_opa_SwitchCongestionLog;
static int hf_opa_SwitchCongestionLog_LogType;
static int hf_opa_SwitchCongestionLog_CongestionFlags;
static int hf_opa_SwitchCongestionLog_LogEventsCounter;
static int hf_opa_SwitchCongestionLog_CurrentTimeStamp;
static int hf_opa_SwitchCongestionLog_PortMap;
static int hf_opa_SwitchCongestionLog_SLID;
static int hf_opa_SwitchCongestionLog_DLID;
static int hf_opa_SwitchCongestionLog_SC;
static int hf_opa_SwitchCongestionLog_reserved;
static int hf_opa_SwitchCongestionLog_TimeStamp;
static int hf_opa_SwitchCongestionSetting;
static int hf_opa_SwitchCongestionSetting_Control_Map;
static int hf_opa_SwitchCongestionSetting_Victim_Mask;
static int hf_opa_SwitchCongestionSetting_Credit_Mask;
static int hf_opa_SwitchCongestionSetting_Threshold;
static int hf_opa_SwitchCongestionSetting_reserved1;
static int hf_opa_SwitchCongestionSetting_Packet_Size;
static int hf_opa_SwitchCongestionSetting_CS_Threshold;
static int hf_opa_SwitchCongestionSetting_reserved2;
static int hf_opa_SwitchCongestionSetting_CS_ReturnDelay;
static int hf_opa_SwitchCongestionSetting_Marking_Rate;
static int hf_opa_SwitchPortCongestionSetting;
static int hf_opa_SwitchPortCongestionSetting_Valid;
static int hf_opa_SwitchPortCongestionSetting_Control_Type;
static int hf_opa_SwitchPortCongestionSetting_reserved;
static int hf_opa_SwitchPortCongestionSetting_Threshold;
static int hf_opa_SwitchPortCongestionSetting_Packet_Size;
static int hf_opa_SwitchPortCongestionSetting_Marking_Rate;
static int hf_opa_HFICongestionLog;
static int hf_opa_HFICongestionLog_LogType;
static int hf_opa_HFICongestionLog_CongestionFlags;
static int hf_opa_HFICongestionLog_ThresholdEventCounter;
static int hf_opa_HFICongestionLog_CurrentTimeStamp;
static int hf_opa_HFICongestionLog_ThresholdCongestionEventMap;
static int hf_opa_HFICongestionLog_Local_QP_CN_Entry;
static int hf_opa_HFICongestionLog_Remote_QP_Number_CN_Entry;
static int hf_opa_HFICongestionLog_SL_CN_Entry;
static int hf_opa_HFICongestionLog_Service_Type_CN_Entry;
static int hf_opa_HFICongestionLog_Remote_LID_CN_Entry;
static int hf_opa_HFICongestionLog_TimeStamp_CN_Entry;
static int hf_opa_HFICongestionSetting;
static int hf_opa_HFICongestionSetting_Control_Map;
static int hf_opa_HFICongestionSetting_Port_Control;
static int hf_opa_HFICongestionSetting_CCTI_Increase;
static int hf_opa_HFICongestionSetting_CCTI_Timer;
static int hf_opa_HFICongestionSetting_TriggerThreshold;
static int hf_opa_HFICongestionSetting_CCTI_Min;
static int hf_opa_HFICongestionControlTable;
static int hf_opa_HFICongestionControlTable_CCTI_Limit;
static int hf_opa_HFICongestionControlTable_CCT_Shift;
static int hf_opa_HFICongestionControlTable_CCT_Multiplier;
/* SA */
static int hf_opa_PortInfoRecord_LinkDownReason_NeighborLinkDownReason;
static int hf_opa_PortInfoRecord_LinkDownReason_LinkDownReason;
static int hf_opa_PortInfoRecord_LinkDownReason_Timestamp;
static int hf_opa_LinkRecord;
static int hf_opa_LinkRecord_ToPort;
static int hf_opa_LinkRecord_ToLID;
static int hf_opa_ServiceRecord;
static int hf_opa_ServiceRecord_ServiceLease;
static int hf_opa_ServiceRecord_ServiceKey;
static int hf_opa_ServiceRecord_ServiceName;
static int hf_opa_ServiceRecord_ServiceData;
static int hf_opa_ServiceAssociationRecord_ServiceKey;
static int hf_opa_ServiceAssociationRecord_ServiceName;
static int hf_opa_PathRecord;
static int hf_opa_PathRecord_DGID;
static int hf_opa_PathRecord_SGID;
static int hf_opa_PathRecord_DLID;
static int hf_opa_PathRecord_SLID;
static int hf_opa_PathRecord_RawTraffic;
static int hf_opa_PathRecord_reserved;
static int hf_opa_PathRecord_FlowLabel;
static int hf_opa_PathRecord_HopLimit;
static int hf_opa_PathRecord_TClass;
static int hf_opa_PathRecord_Reversible;
static int hf_opa_PathRecord_NumbPath;
static int hf_opa_PathRecord_P_Key;
static int hf_opa_PathRecord_QosType;
static int hf_opa_PathRecord_reserved2;
static int hf_opa_PathRecord_QosPriority;
static int hf_opa_PathRecord_SL;
static int hf_opa_PathRecord_MTUSelector;
static int hf_opa_PathRecord_MTU;
static int hf_opa_PathRecord_RateSelector;
static int hf_opa_PathRecord_Rate;
static int hf_opa_PathRecord_PacketLifeTimeSelector;
static int hf_opa_PathRecord_PacketLifeTime;
static int hf_opa_PathRecord_Preference;
static int hf_opa_MCMemberRecord;
static int hf_opa_MCMemberRecord_Q_Key;
static int hf_opa_MCMemberRecord_MLID;
static int hf_opa_MCMemberRecord_MTUSelector;
static int hf_opa_MCMemberRecord_MTU;
static int hf_opa_MCMemberRecord_TClass;
static int hf_opa_MCMemberRecord_P_Key;
static int hf_opa_MCMemberRecord_RateSelector;
static int hf_opa_MCMemberRecord_Rate;
static int hf_opa_MCMemberRecord_PacketLifeTimeSelector;
static int hf_opa_MCMemberRecord_PacketLifeTime;
static int hf_opa_MCMemberRecord_SL;
static int hf_opa_MCMemberRecord_reserved;
static int hf_opa_MCMemberRecord_HopLimit;
static int hf_opa_MCMemberRecord_Scope;
static int hf_opa_MCMemberRecord_reserved2;
static int hf_opa_MCMemberRecord_JoinSendOnlyMember;
static int hf_opa_MCMemberRecord_JoinNonMember;
static int hf_opa_MCMemberRecord_JoinFullMember;
static int hf_opa_MCMemberRecord_ProxyJoin;
static int hf_opa_MCMemberRecord_reserved3;
static int hf_opa_TraceRecord;
static int hf_opa_TraceRecord_IDGeneration;
static int hf_opa_TraceRecord_NodeType;
static int hf_opa_TraceRecord_NodeID;
static int hf_opa_TraceRecord_ChassisID;
static int hf_opa_TraceRecord_EntryPortID;
static int hf_opa_TraceRecord_ExitPortID;
static int hf_opa_TraceRecord_EntryPort;
static int hf_opa_TraceRecord_ExitPort;
static int hf_opa_MultiPathRecord;
static int hf_opa_MultiPathRecord_reserved;
static int hf_opa_MultiPathRecord_FlowLabel;
static int hf_opa_MultiPathRecord_HopLimit;
static int hf_opa_MultiPathRecord_TClass;
static int hf_opa_MultiPathRecord_Reversible;
static int hf_opa_MultiPathRecord_NumbPath;
static int hf_opa_MultiPathRecord_P_Key;
static int hf_opa_MultiPathRecord_QoSType;
static int hf_opa_MultiPathRecord_QoSPriority;
static int hf_opa_MultiPathRecord_reserved2;
static int hf_opa_MultiPathRecord_SL;
static int hf_opa_MultiPathRecord_MTUSelector;
static int hf_opa_MultiPathRecord_MTU;
static int hf_opa_MultiPathRecord_RateSelector;
static int hf_opa_MultiPathRecord_Rate;
static int hf_opa_MultiPathRecord_PacketLifeTimeSelector;
static int hf_opa_MultiPathRecord_PacketLifeTime;
static int hf_opa_MultiPathRecord_IndependenceSelector;
static int hf_opa_MultiPathRecord_SGIDScope;
static int hf_opa_MultiPathRecord_DGIDScope;
static int hf_opa_MultiPathRecord_SGIDCount;
static int hf_opa_MultiPathRecord_DGIDCount;
static int hf_opa_MultiPathRecord_SGID;
static int hf_opa_MultiPathRecord_DGID;
static int hf_opa_MultiPathRecord_L2_8B;
static int hf_opa_MultiPathRecord_L2_10B;
static int hf_opa_MultiPathRecord_L2_9B;
static int hf_opa_MultiPathRecord_L2_16B;
static int hf_opa_MultiPathRecord_reserved3;
static int hf_opa_MultiPathRecord_SGUIDScope;
static int hf_opa_MultiPathRecord_DGUIDScope;
static int hf_opa_MultiPathRecord_SGUIDCount;
static int hf_opa_MultiPathRecord_DGUIDCount;
static int hf_opa_MultiPathRecord_SGUID;
static int hf_opa_MultiPathRecord_DGUID;
static int hf_opa_MultiPathRecord_ServiceID;
static int hf_opa_MultiPathRecord_SubnetPrefix;
static int hf_opa_MultiPathRecord_SLIDCount;
static int hf_opa_MultiPathRecord_DLIDCount;
static int hf_opa_MultiPathRecord_SLID;
static int hf_opa_MultiPathRecord_DLID;
static int hf_opa_CableInfoRecord;
static int hf_opa_CableInfoRecord_Lid;
static int hf_opa_CableInfoRecord_Port;
static int hf_opa_CableInfoRecord_Length;
static int hf_opa_CableInfoRecord_reserved;
static int hf_opa_CableInfoRecord_Address;
static int hf_opa_CableInfoRecord_PortType;
static int hf_opa_CableInfoRecord_Data;
static int hf_opa_VFInfoRecord;
static int hf_opa_VFInfoRecord_vfIndex;
static int hf_opa_VFInfoRecord_pKey;
static int hf_opa_VFInfoRecord_vfName;
static int hf_opa_VFInfoRecord_MGID;
static int hf_opa_VFInfoRecord_SelectFlags;
static int hf_opa_VFInfoRecord_reserved;
static int hf_opa_VFInfoRecord_SL;
static int hf_opa_VFInfoRecord_MTUSpecified;
static int hf_opa_VFInfoRecord_reserved2;
static int hf_opa_VFInfoRecord_MTU;
static int hf_opa_VFInfoRecord_RateSpecified;
static int hf_opa_VFInfoRecord_reserved4;
static int hf_opa_VFInfoRecord_Rate;
static int hf_opa_VFInfoRecord_PktLifeSpecified;
static int hf_opa_VFInfoRecord_reserved5;
static int hf_opa_VFInfoRecord_PktLifeTimeInc;
static int hf_opa_VFInfoRecord_OptionFlags;
static int hf_opa_VFInfoRecord_BandwidthPercent;
static int hf_opa_VFInfoRecord_reserved6;
static int hf_opa_VFInfoRecord_Priority;
static int hf_opa_VFInfoRecord_RoutingSLs;
static int hf_opa_VFInfoRecord_reserved7;
static int hf_opa_QuarantinedNodeRecord;
static int hf_opa_QuarantinedNodeRecord_TrustedLid;
static int hf_opa_QuarantinedNodeRecord_TrustedNodeGUID;
static int hf_opa_QuarantinedNodeRecord_TrustedPortNum;
static int hf_opa_QuarantinedNodeRecord_TrustedNeighborNodeGUID;
static int hf_opa_QuarantinedNodeRecord_QuarantineReasons;
static int hf_opa_QuarantinedNodeRecord_ExpectedNodeDesc;
static int hf_opa_QuarantinedNodeRecord_ExpectedNodeGUID;
static int hf_opa_QuarantinedNodeRecord_ExpectedPortGUID;
static int hf_opa_FabricInfoRecord;
static int hf_opa_FabricInfoRecord_NumHFIs;
static int hf_opa_FabricInfoRecord_NumSwitches;
static int hf_opa_FabricInfoRecord_NumInternalHFILinks;
static int hf_opa_FabricInfoRecord_NumExternalHFILinks;
static int hf_opa_FabricInfoRecord_NumInternalISLs;
static int hf_opa_FabricInfoRecord_NumExternalISLs;
static int hf_opa_FabricInfoRecord_NumDegradedHFILinks;
static int hf_opa_FabricInfoRecord_NumDegradedISLs;
static int hf_opa_FabricInfoRecord_NumOmittedHFILinks;
static int hf_opa_FabricInfoRecord_NumOmittedISLs;
static int hf_opa_FabricInfoRecord_Reserved;
/* PM */
static int hf_opa_PortStatus;
static int hf_opa_PortStatus_PortNumber;
static int hf_opa_PortStatus_VLSelectMask;
static int hf_opa_PortStatus_PortXmitData;
static int hf_opa_PortStatus_PortRcvData;
static int hf_opa_PortStatus_PortXmitPkts;
static int hf_opa_PortStatus_PortRcvPkts;
static int hf_opa_PortStatus_PortMulticastXmitPkts;
static int hf_opa_PortStatus_PortMulticastRcvPkts;
static int hf_opa_PortStatus_PortXmitWait;
static int hf_opa_PortStatus_SwPortCongestion;
static int hf_opa_PortStatus_PortRcvFECN;
static int hf_opa_PortStatus_PortRcvBECN;
static int hf_opa_PortStatus_PortXmitTimeCong;
static int hf_opa_PortStatus_PortXmitWastedBW;
static int hf_opa_PortStatus_PortXmitWaitData;
static int hf_opa_PortStatus_PortRcvBubble;
static int hf_opa_PortStatus_PortMarkFECN;
static int hf_opa_PortStatus_PortRcvConstraintErrors;
static int hf_opa_PortStatus_PortRcvSwitchRelayErrors;
static int hf_opa_PortStatus_PortXmitDiscards;
static int hf_opa_PortStatus_PortXmitConstraintErrors;
static int hf_opa_PortStatus_PortRcvRemotePhysicalErrors;
static int hf_opa_PortStatus_LocalLinkIntegrityErrors;
static int hf_opa_PortStatus_PortRcvErrors;
static int hf_opa_PortStatus_ExcessiveBufferOverruns;
static int hf_opa_PortStatus_FMConfigErrors;
static int hf_opa_PortStatus_LinkErrorRecovery;
static int hf_opa_PortStatus_LinkDowned;
static int hf_opa_PortStatus_UncorrectableErrors;
static int hf_opa_PortStatus_reserved;
static int hf_opa_PortStatus_LinkQualityIndicator;
static int hf_opa_PortStatus_PortVLXmitData;
static int hf_opa_PortStatus_PortVLRcvData;
static int hf_opa_PortStatus_PortVLXmitPkts;
static int hf_opa_PortStatus_PortVLRcvPkts;
static int hf_opa_PortStatus_PortVLXmitWait;
static int hf_opa_PortStatus_SwPortVLCongestion;
static int hf_opa_PortStatus_PortVLRcvFECN;
static int hf_opa_PortStatus_PortVLRcvBECN;
static int hf_opa_PortStatus_PortVLXmitTimeCong;
static int hf_opa_PortStatus_PortVLXmitWastedBW;
static int hf_opa_PortStatus_PortVLXmitWaitData;
static int hf_opa_PortStatus_PortVLRcvBubble;
static int hf_opa_PortStatus_PortVLMarkFECN;
static int hf_opa_PortStatus_PortVLXmitDiscards;
static int hf_opa_ClearPortStatus;
static int hf_opa_ClearPortStatus_PortSelectMask;
static int hf_opa_ClearPortStatus_PortXmitData;
static int hf_opa_ClearPortStatus_PortRcvData;
static int hf_opa_ClearPortStatus_PortXmitPkts;
static int hf_opa_ClearPortStatus_PortRcvPkts;
static int hf_opa_ClearPortStatus_PortMulticastXmitPkts;
static int hf_opa_ClearPortStatus_PortMulticastRcvPkts;
static int hf_opa_ClearPortStatus_PortXmitWait;
static int hf_opa_ClearPortStatus_SwPortCongestion;
static int hf_opa_ClearPortStatus_PortRcvFECN;
static int hf_opa_ClearPortStatus_PortRcvBECN;
static int hf_opa_ClearPortStatus_PortXmitTimeCong;
static int hf_opa_ClearPortStatus_PortXmitWastedBW;
static int hf_opa_ClearPortStatus_PortXmitWaitData;
static int hf_opa_ClearPortStatus_PortRcvBubble;
static int hf_opa_ClearPortStatus_PortMarkFECN;
static int hf_opa_ClearPortStatus_PortRcvConstraintErrors;
static int hf_opa_ClearPortStatus_PortRcvSwitchRelayErrors;
static int hf_opa_ClearPortStatus_PortXmitDiscards;
static int hf_opa_ClearPortStatus_PortXmitConstraintErrors;
static int hf_opa_ClearPortStatus_PortRcvRemotePhysicalErrors;
static int hf_opa_ClearPortStatus_LocalLinkIntegrityErrors;
static int hf_opa_ClearPortStatus_PortRcvErrors;
static int hf_opa_ClearPortStatus_ExcessiveBufferOverruns;
static int hf_opa_ClearPortStatus_FMConfigErrors;
static int hf_opa_ClearPortStatus_LinkErrorRecovery;
static int hf_opa_ClearPortStatus_LinkDowned;
static int hf_opa_ClearPortStatus_UncorrectableErrors;
static int hf_opa_ClearPortStatus_reserved;
static int hf_opa_ClearPortStatus_CounterSelectMask;
static int * const _ClearPortStatus_CounterSelectMask[] = {
    &hf_opa_ClearPortStatus_PortXmitData,
    &hf_opa_ClearPortStatus_PortRcvData,
    &hf_opa_ClearPortStatus_PortXmitPkts,
    &hf_opa_ClearPortStatus_PortRcvPkts,
    &hf_opa_ClearPortStatus_PortMulticastXmitPkts,
    &hf_opa_ClearPortStatus_PortMulticastRcvPkts,
    &hf_opa_ClearPortStatus_PortXmitWait,
    &hf_opa_ClearPortStatus_SwPortCongestion,
    &hf_opa_ClearPortStatus_PortRcvFECN,
    &hf_opa_ClearPortStatus_PortRcvBECN,
    &hf_opa_ClearPortStatus_PortXmitTimeCong,
    &hf_opa_ClearPortStatus_PortXmitWastedBW,
    &hf_opa_ClearPortStatus_PortXmitWaitData,
    &hf_opa_ClearPortStatus_PortRcvBubble,
    &hf_opa_ClearPortStatus_PortMarkFECN,
    &hf_opa_ClearPortStatus_PortRcvConstraintErrors,
    &hf_opa_ClearPortStatus_PortRcvSwitchRelayErrors,
    &hf_opa_ClearPortStatus_PortXmitDiscards,
    &hf_opa_ClearPortStatus_PortXmitConstraintErrors,
    &hf_opa_ClearPortStatus_PortRcvRemotePhysicalErrors,
    &hf_opa_ClearPortStatus_LocalLinkIntegrityErrors,
    &hf_opa_ClearPortStatus_PortRcvErrors,
    &hf_opa_ClearPortStatus_ExcessiveBufferOverruns,
    &hf_opa_ClearPortStatus_FMConfigErrors,
    &hf_opa_ClearPortStatus_LinkErrorRecovery,
    &hf_opa_ClearPortStatus_LinkDowned,
    &hf_opa_ClearPortStatus_UncorrectableErrors,
    &hf_opa_ClearPortStatus_reserved,
    NULL
};
static int hf_opa_DataPortCounters;
static int hf_opa_DataPortCounters_PortSelectMask;
static int hf_opa_DataPortCounters_VLSelectMask;
static int hf_opa_DataPortCounters_resolution_reserved;
static int hf_opa_DataPortCounters_LocalLinkIntegrityResolution;
static int hf_opa_DataPortCounters_LinkErrorRecoveryResolution;
static int hf_opa_DataPortCounters_PortNumber;
static int hf_opa_DataPortCounters_lqi_reserved;
static int hf_opa_DataPortCounters_LinkQualityIndicator;
static int hf_opa_DataPortCounters_PortXmitData;
static int hf_opa_DataPortCounters_PortRcvData;
static int hf_opa_DataPortCounters_PortXmitPkts;
static int hf_opa_DataPortCounters_PortRcvPkts;
static int hf_opa_DataPortCounters_PortMulticastXmitPkts;
static int hf_opa_DataPortCounters_PortMulticastRcvPkts;
static int hf_opa_DataPortCounters_PortXmitWait;
static int hf_opa_DataPortCounters_SwPortCongestion;
static int hf_opa_DataPortCounters_PortRcvFECN;
static int hf_opa_DataPortCounters_PortRcvBECN;
static int hf_opa_DataPortCounters_PortXmitTimeCong;
static int hf_opa_DataPortCounters_PortXmitWastedBW;
static int hf_opa_DataPortCounters_PortXmitWaitData;
static int hf_opa_DataPortCounters_PortRcvBubble;
static int hf_opa_DataPortCounters_PortMarkFECN;
static int hf_opa_DataPortCounters_PortErrorCounterSummary;
static int hf_opa_DataPortCounters_PortVLXmitData;
static int hf_opa_DataPortCounters_PortVLRcvData;
static int hf_opa_DataPortCounters_PortVLXmitPkts;
static int hf_opa_DataPortCounters_PortVLRcvPkts;
static int hf_opa_DataPortCounters_PortVLXmitWait;
static int hf_opa_DataPortCounters_SwPortVLCongestion;
static int hf_opa_DataPortCounters_PortVLRcvFECN;
static int hf_opa_DataPortCounters_PortVLRcvBECN;
static int hf_opa_DataPortCounters_PortVLXmitTimeCong;
static int hf_opa_DataPortCounters_PortVLXmitWastedBW;
static int hf_opa_DataPortCounters_PortVLXmitWaitData;
static int hf_opa_DataPortCounters_PortVLRcvBubble;
static int hf_opa_DataPortCounters_PortVLMarkFECN;
static int hf_opa_ErrorPortCounters;
static int hf_opa_ErrorPortCounters_PortSelectMask;
static int hf_opa_ErrorPortCounters_VLSelectMask;
static int hf_opa_ErrorPortCounters_PortNumber;
static int hf_opa_ErrorPortCounters_PortRcvConstraintErrors;
static int hf_opa_ErrorPortCounters_PortRcvSwitchRelayErrors;
static int hf_opa_ErrorPortCounters_PortXmitDiscards;
static int hf_opa_ErrorPortCounters_PortXmitConstraintErrors;
static int hf_opa_ErrorPortCounters_PortRcvRemotePhysicalErrors;
static int hf_opa_ErrorPortCounters_LocalLinkIntegrityErrors;
static int hf_opa_ErrorPortCounters_PortRcvErrors;
static int hf_opa_ErrorPortCounters_ExcessiveBufferOverruns;
static int hf_opa_ErrorPortCounters_FMConfigErrors;
static int hf_opa_ErrorPortCounters_LinkErrorRecovery;
static int hf_opa_ErrorPortCounters_LinkDowned;
static int hf_opa_ErrorPortCounters_UncorrectableErrors;
static int hf_opa_ErrorPortCounters_PortVLXmitDiscards;
static int hf_opa_ErrorPortInfo;
static int hf_opa_ErrorPortInfo_PortSelectMask;
static int hf_opa_ErrorPortInfo_ErrorInfoSelectMask_PortRcvErrorInfo;
static int hf_opa_ErrorPortInfo_ErrorInfoSelectMask_ExcessiveBufferOverrunInfo;
static int hf_opa_ErrorPortInfo_ErrorInfoSelectMask_PortXmitConstraintErrorInfo;
static int hf_opa_ErrorPortInfo_ErrorInfoSelectMask_PortRcvConstraintErrorInfo;
static int hf_opa_ErrorPortInfo_ErrorInfoSelectMask_PortRcvSwitchRelayErrorInfo;
static int hf_opa_ErrorPortInfo_ErrorInfoSelectMask_UncorrectableErrorInfo;
static int hf_opa_ErrorPortInfo_ErrorInfoSelectMask_FMConfigErrorInfo;
static int hf_opa_ErrorPortInfo_ErrorInfoSelectMask_reserved;
static int * const _ErrorPortInfo_ErrorInfoSelectMask[] = {
    &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_PortRcvErrorInfo,
    &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_ExcessiveBufferOverrunInfo,
    &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_PortXmitConstraintErrorInfo,
    &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_PortRcvConstraintErrorInfo,
    &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_PortRcvSwitchRelayErrorInfo,
    &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_UncorrectableErrorInfo,
    &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_FMConfigErrorInfo,
    &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_reserved,
    NULL
};
static int hf_opa_ErrorPortInfo_PortNumber;
static int hf_opa_ErrorPortInfo_PortRcvErrorInfo_Status;
static int hf_opa_ErrorPortInfo_PortRcvErrorInfo_reserved;
static int hf_opa_ErrorPortInfo_PortRcvErrorInfo_ErrorCode;
static int hf_opa_ErrorPortInfo_PortRcvErrorInfo_PacketFlit1;
static int hf_opa_ErrorPortInfo_PortRcvErrorInfo_PacketFlit2;
static int hf_opa_ErrorPortInfo_PortRcvErrorInfo_Flit1Bits;
static int hf_opa_ErrorPortInfo_PortRcvErrorInfo_Flit2Bits;
static int hf_opa_ErrorPortInfo_PortRcvErrorInfo_reserved2;
static int hf_opa_ErrorPortInfo_PortRcvErrorInfo_PacketBytes;
static int hf_opa_ErrorPortInfo_PortRcvErrorInfo_FlitBits;
static int hf_opa_ErrorPortInfo_PortRcvErrorInfo_reserved3;
static int hf_opa_ErrorPortInfo_PortRcvErrorInfo_reserved4;
static int hf_opa_ErrorPortInfo_ExcessiveBufferOverrunErrorInfo_Status;
static int hf_opa_ErrorPortInfo_ExcessiveBufferOverrunErrorInfo_SC;
static int hf_opa_ErrorPortInfo_ExcessiveBufferOverrunErrorInfo_reserved;
static int hf_opa_ErrorPortInfo_PortXmitConstraintErrorInfo_Status;
static int hf_opa_ErrorPortInfo_PortXmitConstraintErrorInfo_reserved;
static int hf_opa_ErrorPortInfo_PortXmitConstraintErrorInfo_P_Key;
static int hf_opa_ErrorPortInfo_PortXmitConstraintErrorInfo_SLID;
static int hf_opa_ErrorPortInfo_PortRcvConstraintErrorInfo_Status;
static int hf_opa_ErrorPortInfo_PortRcvConstraintErrorInfo_reserved;
static int hf_opa_ErrorPortInfo_PortRcvConstraintErrorInfo_P_Key;
static int hf_opa_ErrorPortInfo_PortRcvConstraintErrorInfo_SLID;
static int hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_Status;
static int hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_reserved;
static int hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_ErrorCode;
static int hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_DLID;
static int hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_EgressPortNum;
static int hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_SC;
static int hf_opa_ErrorPortInfo_UncorrectableErrorInfo_Status;
static int hf_opa_ErrorPortInfo_UncorrectableErrorInfo_reserved;
static int hf_opa_ErrorPortInfo_UncorrectableErrorInfo_ErrorCode;
static int hf_opa_ErrorPortInfo_FMConfigErrorInfo_Status;
static int hf_opa_ErrorPortInfo_FMConfigErrorInfo_reserved;
static int hf_opa_ErrorPortInfo_FMConfigErrorInfo_ErrorCode;
static int hf_opa_ErrorPortInfo_FMConfigErrorInfo_VL;
static int hf_opa_ErrorPortInfo_FMConfigErrorInfo_Distance;
static int hf_opa_ErrorPortInfo_FMConfigErrorInfo_BadFlitBits;
static int hf_opa_ErrorPortInfo_FMConfigErrorInfo_SC;
/* PA */
static int hf_opa_ImageID_imageNumber;
static int hf_opa_ImageID_imageOffset;
static int hf_opa_GetGroupList;
static int hf_opa_GetGroupList_groupName;
static int hf_opa_GetGroupInfo;
static int hf_opa_GetGroupInfo_groupName;
static int hf_opa_GetGroupInfo_numInternalPorts;
static int hf_opa_GetGroupInfo_numExternalPorts;
static int hf_opa_GetGroupInfo_totalMBps;
static int hf_opa_GetGroupInfo_totalKPps;
static int hf_opa_GetGroupInfo_avgMBps;
static int hf_opa_GetGroupInfo_minMBps;
static int hf_opa_GetGroupInfo_maxMBps;
static int hf_opa_GetGroupInfo_numBWBuckets;
static int hf_opa_GetGroupInfo_BWBuckets;
static int hf_opa_GetGroupInfo_avgKPps;
static int hf_opa_GetGroupInfo_minKPps;
static int hf_opa_GetGroupInfo_maxKPps;
static int hf_opa_GetGroupInfo_pmaFailedPorts;
static int hf_opa_GetGroupInfo_topoFailedPorts;
static int hf_opa_GetGroupInfo_integrityErrors;
static int hf_opa_GetGroupInfo_congestionErrors;
static int hf_opa_GetGroupInfo_smaCongestionErrors;
static int hf_opa_GetGroupInfo_bubbleErrors;
static int hf_opa_GetGroupInfo_securityErrors;
static int hf_opa_GetGroupInfo_routingErrors;
static int hf_opa_GetGroupInfo_utilizationPct10;
static int hf_opa_GetGroupInfo_discardsPct10;
static int hf_opa_GetGroupInfo_maxInternalRate;
static int hf_opa_GetGroupInfo_minInternalRate;
static int hf_opa_GetGroupInfo_maxExternalRate;
static int hf_opa_GetGroupInfo_minExternalRate;
static int hf_opa_GetGroupInfo_maxInternalMBps;
static int hf_opa_GetGroupInfo_maxExternalMBps;
static int hf_opa_GetGroupConfig;
static int hf_opa_GetGroupConfig_groupName;
static int hf_opa_GetGroupConfig_Port_NodeGUID;
static int hf_opa_GetGroupConfig_Port_nodeDesc;
static int hf_opa_GetGroupConfig_Port_NodeLID;
static int hf_opa_GetGroupConfig_Port_PortNumber;
static int hf_opa_GetPortCounters;
static int hf_opa_GetPortCounters_nodeLID;
static int hf_opa_GetPortCounters_PortNumber;
static int hf_opa_GetPortCounters_flags;
static int hf_opa_GetPortCounters_PortXmitData;
static int hf_opa_GetPortCounters_PortRcvData;
static int hf_opa_GetPortCounters_PortXmitPkts;
static int hf_opa_GetPortCounters_PortRcvPkts;
static int hf_opa_GetPortCounters_PortMulticastXmitPkts;
static int hf_opa_GetPortCounters_PortMulticastRcvPkts;
static int hf_opa_GetPortCounters_LocalLinkIntegrityErrors;
static int hf_opa_GetPortCounters_FMConfigErrors;
static int hf_opa_GetPortCounters_PortRcvErrors;
static int hf_opa_GetPortCounters_ExcessiveBufferOverruns;
static int hf_opa_GetPortCounters_PortRcvConstraintErrors;
static int hf_opa_GetPortCounters_PortRcvSwitchRelayErrors;
static int hf_opa_GetPortCounters_PortXmitDiscards;
static int hf_opa_GetPortCounters_PortXmitConstraintErrors;
static int hf_opa_GetPortCounters_PortRcvRemotePhysicalErrors;
static int hf_opa_GetPortCounters_SwPortCongestion;
static int hf_opa_GetPortCounters_PortXmitWait;
static int hf_opa_GetPortCounters_PortRcvFECN;
static int hf_opa_GetPortCounters_PortRcvBECN;
static int hf_opa_GetPortCounters_PortXmitTimeCong;
static int hf_opa_GetPortCounters_PortXmitWastedBW;
static int hf_opa_GetPortCounters_PortXmitWaitData;
static int hf_opa_GetPortCounters_PortRcvBubble;
static int hf_opa_GetPortCounters_PortMarkFECN;
static int hf_opa_GetPortCounters_LinkErrorRecovery;
static int hf_opa_GetPortCounters_LinkDowned;
static int hf_opa_GetPortCounters_UncorrectableErrors;
static int hf_opa_GetPortCounters_NumLanesDown;
static int hf_opa_GetPortCounters_reserved;
static int hf_opa_GetPortCounters_LinkQualityIndicator;
static int hf_opa_ClearPortCounters;
static int hf_opa_ClearPortCounters_nodeLID;
static int hf_opa_ClearPortCounters_PortNumber;
static int hf_opa_ClearPortCounters_PortXmitData;
static int hf_opa_ClearPortCounters_PortRcvData;
static int hf_opa_ClearPortCounters_PortXmitPkts;
static int hf_opa_ClearPortCounters_PortRcvPkts;
static int hf_opa_ClearPortCounters_PortMulticastXmitPkts;
static int hf_opa_ClearPortCounters_PortMulticastRcvPkts;
static int hf_opa_ClearPortCounters_LocalLinkIntegrityErrors;
static int hf_opa_ClearPortCounters_FMConfigErrors;
static int hf_opa_ClearPortCounters_PortRcvErrors;
static int hf_opa_ClearPortCounters_ExcessiveBufferOverruns;
static int hf_opa_ClearPortCounters_PortRcvConstraintErrors;
static int hf_opa_ClearPortCounters_PortRcvSwitchRelayErrors;
static int hf_opa_ClearPortCounters_PortXmitDiscards;
static int hf_opa_ClearPortCounters_PortXmitConstraintErrors;
static int hf_opa_ClearPortCounters_PortRcvRemotePhysicalErrors;
static int hf_opa_ClearPortCounters_SwPortCongestion;
static int hf_opa_ClearPortCounters_PortXmitWait;
static int hf_opa_ClearPortCounters_PortRcvFECN;
static int hf_opa_ClearPortCounters_PortRcvBECN;
static int hf_opa_ClearPortCounters_PortXmitTimeCong;
static int hf_opa_ClearPortCounters_PortXmitWastedBW;
static int hf_opa_ClearPortCounters_PortXmitWaitData;
static int hf_opa_ClearPortCounters_PortRcvBubble;
static int hf_opa_ClearPortCounters_PortMarkFECN;
static int hf_opa_ClearPortCounters_LinkErrorRecovery;
static int hf_opa_ClearPortCounters_LinkDowned;
static int hf_opa_ClearPortCounters_UncorrectableErrors;
static int hf_opa_ClearPortCounters_reserved;
static int hf_opa_ClearPortCounters_CounterSelectMask;
static int * const _ClearPortCounters_CounterSelectMask[] = {
    &hf_opa_ClearPortCounters_PortXmitData,
    &hf_opa_ClearPortCounters_PortRcvData,
    &hf_opa_ClearPortCounters_PortXmitPkts,
    &hf_opa_ClearPortCounters_PortRcvPkts,
    &hf_opa_ClearPortCounters_PortMulticastXmitPkts,
    &hf_opa_ClearPortCounters_PortMulticastRcvPkts,
    &hf_opa_ClearPortCounters_LocalLinkIntegrityErrors,
    &hf_opa_ClearPortCounters_FMConfigErrors,
    &hf_opa_ClearPortCounters_PortRcvErrors,
    &hf_opa_ClearPortCounters_ExcessiveBufferOverruns,
    &hf_opa_ClearPortCounters_PortRcvConstraintErrors,
    &hf_opa_ClearPortCounters_PortRcvSwitchRelayErrors,
    &hf_opa_ClearPortCounters_PortXmitDiscards,
    &hf_opa_ClearPortCounters_PortXmitConstraintErrors,
    &hf_opa_ClearPortCounters_PortRcvRemotePhysicalErrors,
    &hf_opa_ClearPortCounters_SwPortCongestion,
    &hf_opa_ClearPortCounters_PortXmitWait,
    &hf_opa_ClearPortCounters_PortRcvFECN,
    &hf_opa_ClearPortCounters_PortRcvBECN,
    &hf_opa_ClearPortCounters_PortXmitTimeCong,
    &hf_opa_ClearPortCounters_PortXmitWastedBW,
    &hf_opa_ClearPortCounters_PortXmitWaitData,
    &hf_opa_ClearPortCounters_PortRcvBubble,
    &hf_opa_ClearPortCounters_PortMarkFECN,
    &hf_opa_ClearPortCounters_LinkErrorRecovery,
    &hf_opa_ClearPortCounters_LinkDowned,
    &hf_opa_ClearPortCounters_UncorrectableErrors,
    &hf_opa_ClearPortCounters_reserved,
    NULL
};
static int hf_opa_ClearAllPortCounters;
static int hf_opa_ClearAllPortCounters_PortXmitData;
static int hf_opa_ClearAllPortCounters_PortRcvData;
static int hf_opa_ClearAllPortCounters_PortXmitPkts;
static int hf_opa_ClearAllPortCounters_PortRcvPkts;
static int hf_opa_ClearAllPortCounters_PortMulticastXmitPkts;
static int hf_opa_ClearAllPortCounters_PortMulticastRcvPkts;
static int hf_opa_ClearAllPortCounters_LocalLinkIntegrityErrors;
static int hf_opa_ClearAllPortCounters_FMConfigErrors;
static int hf_opa_ClearAllPortCounters_PortRcvErrors;
static int hf_opa_ClearAllPortCounters_ExcessiveBufferOverruns;
static int hf_opa_ClearAllPortCounters_PortRcvConstraintErrors;
static int hf_opa_ClearAllPortCounters_PortRcvSwitchRelayErrors;
static int hf_opa_ClearAllPortCounters_PortXmitDiscards;
static int hf_opa_ClearAllPortCounters_PortXmitConstraintErrors;
static int hf_opa_ClearAllPortCounters_PortRcvRemotePhysicalErrors;
static int hf_opa_ClearAllPortCounters_SwPortCongestion;
static int hf_opa_ClearAllPortCounters_PortXmitWait;
static int hf_opa_ClearAllPortCounters_PortRcvFECN;
static int hf_opa_ClearAllPortCounters_PortRcvBECN;
static int hf_opa_ClearAllPortCounters_PortXmitTimeCong;
static int hf_opa_ClearAllPortCounters_PortXmitWastedBW;
static int hf_opa_ClearAllPortCounters_PortXmitWaitData;
static int hf_opa_ClearAllPortCounters_PortRcvBubble;
static int hf_opa_ClearAllPortCounters_PortMarkFECN;
static int hf_opa_ClearAllPortCounters_LinkErrorRecovery;
static int hf_opa_ClearAllPortCounters_LinkDowned;
static int hf_opa_ClearAllPortCounters_UncorrectableErrors;
static int hf_opa_ClearAllPortCounters_reserved;
static int hf_opa_ClearAllPortCounters_CounterSelectMask;
static int * const _ClearAllPortCounters_CounterSelectMask[] = {
    &hf_opa_ClearAllPortCounters_PortXmitData,
    &hf_opa_ClearAllPortCounters_PortRcvData,
    &hf_opa_ClearAllPortCounters_PortXmitPkts,
    &hf_opa_ClearAllPortCounters_PortRcvPkts,
    &hf_opa_ClearAllPortCounters_PortMulticastXmitPkts,
    &hf_opa_ClearAllPortCounters_PortMulticastRcvPkts,
    &hf_opa_ClearAllPortCounters_LocalLinkIntegrityErrors,
    &hf_opa_ClearAllPortCounters_FMConfigErrors,
    &hf_opa_ClearAllPortCounters_PortRcvErrors,
    &hf_opa_ClearAllPortCounters_ExcessiveBufferOverruns,
    &hf_opa_ClearAllPortCounters_PortRcvConstraintErrors,
    &hf_opa_ClearAllPortCounters_PortRcvSwitchRelayErrors,
    &hf_opa_ClearAllPortCounters_PortXmitDiscards,
    &hf_opa_ClearAllPortCounters_PortXmitConstraintErrors,
    &hf_opa_ClearAllPortCounters_PortRcvRemotePhysicalErrors,
    &hf_opa_ClearAllPortCounters_SwPortCongestion,
    &hf_opa_ClearAllPortCounters_PortXmitWait,
    &hf_opa_ClearAllPortCounters_PortRcvFECN,
    &hf_opa_ClearAllPortCounters_PortRcvBECN,
    &hf_opa_ClearAllPortCounters_PortXmitTimeCong,
    &hf_opa_ClearAllPortCounters_PortXmitWastedBW,
    &hf_opa_ClearAllPortCounters_PortXmitWaitData,
    &hf_opa_ClearAllPortCounters_PortRcvBubble,
    &hf_opa_ClearAllPortCounters_PortMarkFECN,
    &hf_opa_ClearAllPortCounters_LinkErrorRecovery,
    &hf_opa_ClearAllPortCounters_LinkDowned,
    &hf_opa_ClearAllPortCounters_UncorrectableErrors,
    &hf_opa_ClearAllPortCounters_reserved,
    NULL
};
static int hf_opa_PMConfig;
static int hf_opa_PMConfig_sweepInterval;
static int hf_opa_PMConfig_maxClients;
static int hf_opa_PMConfig_sizeHistory;
static int hf_opa_PMConfig_sizeFreeze;
static int hf_opa_PMConfig_lease;
static int hf_opa_PMConfig_pmFlags;
static int hf_opa_PMConfig_PortXmitWait;
static int hf_opa_PMConfig_SwPortCongestion;
static int hf_opa_PMConfig_PortRcvFECN;
static int hf_opa_PMConfig_PortRcvBECN;
static int hf_opa_PMConfig_PortXmitTimeCong;
static int hf_opa_PMConfig_PortMarkFECN;
static int hf_opa_PMConfig_integrityErrors;
static int hf_opa_PMConfig_congestionErrors;
static int hf_opa_PMConfig_smaCongestionErrors;
static int hf_opa_PMConfig_bubbleErrors;
static int hf_opa_PMConfig_securityErrors;
static int hf_opa_PMConfig_routingErrors;
static int hf_opa_PMConfig_LocalLinkIntegrityErrors;
static int hf_opa_PMConfig_PortRcvErrors;
static int hf_opa_PMConfig_ExcessiveBufferOverrunErrors;
static int hf_opa_PMConfig_LinkErrorRecovery;
static int hf_opa_PMConfig_LinkDowned;
static int hf_opa_PMConfig_UncorrectableErrors;
static int hf_opa_PMConfig_FMConfigErrors;
static int hf_opa_PMConfig_LinkQualityIndicator;
static int hf_opa_PMConfig_LinkWidthDowngrade;
static int hf_opa_PMConfig_memoryFootprint;
static int hf_opa_PMConfig_maxAttempts;
static int hf_opa_PMConfig_respTimeout;
static int hf_opa_PMConfig_minRespTimeout;
static int hf_opa_PMConfig_maxParallelNodes;
static int hf_opa_PMConfig_pmaBatchSize;
static int hf_opa_PMConfig_errorClear;
static int hf_opa_MoveFreezeFrame_old;
static int hf_opa_MoveFreezeFrame_new;
static int hf_opa_GetFocusPorts;
static int hf_opa_GetFocusPorts_groupName;
static int hf_opa_GetFocusPorts_select;
static int hf_opa_GetFocusPorts_start;
static int hf_opa_GetFocusPorts_range;
static int hf_opa_GetFocusPorts_nodeLID;
static int hf_opa_GetFocusPorts_portNumber;
static int hf_opa_GetFocusPorts_rate;
static int hf_opa_GetFocusPorts_mtu;
static int hf_opa_GetFocusPorts_localFlags;
static int hf_opa_GetFocusPorts_neighborFlags;
static int hf_opa_GetFocusPorts_value;
static int hf_opa_GetFocusPorts_nodeGUID;
static int hf_opa_GetFocusPorts_nodeDesc;
static int hf_opa_GetFocusPorts_neighborLid;
static int hf_opa_GetFocusPorts_neighborPortNumber;
static int hf_opa_GetFocusPorts_neighborValue;
static int hf_opa_GetFocusPorts_neighborGuid;
static int hf_opa_GetFocusPorts_neighborNodeDesc;
static int hf_opa_GetImageInfo;
static int hf_opa_GetImageInfo_sweepStart;
static int hf_opa_GetImageInfo_sweepDuration;
static int hf_opa_GetImageInfo_numHFIPorts;
static int hf_opa_GetImageInfo_numSwitchNodes;
static int hf_opa_GetImageInfo_numSwitchPorts;
static int hf_opa_GetImageInfo_numLinks;
static int hf_opa_GetImageInfo_numSMs;
static int hf_opa_GetImageInfo_numFailedNodes;
static int hf_opa_GetImageInfo_numFailedPorts;
static int hf_opa_GetImageInfo_numSkippedNodes;
static int hf_opa_GetImageInfo_numSkippedPorts;
static int hf_opa_GetImageInfo_numUnexpectedClearPorts;
static int hf_opa_GetImageInfo_imageInterval;
static int hf_opa_GetImageInfo_smPortGuid;
static int hf_opa_GetImageInfo_smNodeDesc;
static int hf_opa_GetImageInfo_lid;
static int hf_opa_GetImageInfo_state;
static int hf_opa_GetImageInfo_priority;
static int hf_opa_GetImageInfo_portNumber;
static int hf_opa_GetVFList;
static int hf_opa_GetVFList_vfName;

static int hf_opa_GetVFInfo;
static int hf_opa_GetVFInfo_vfName;
static int hf_opa_GetVFInfo_numPorts;
static int hf_opa_GetVFInfo_totalMBps;
static int hf_opa_GetVFInfo_totalKPps;
static int hf_opa_GetVFInfo_avgMBps;
static int hf_opa_GetVFInfo_minMBps;
static int hf_opa_GetVFInfo_maxMBps;
static int hf_opa_GetVFInfo_numBWBuckets;
static int hf_opa_GetVFInfo_BWBuckets;
static int hf_opa_GetVFInfo_avgKPps;
static int hf_opa_GetVFInfo_minKPps;
static int hf_opa_GetVFInfo_maxKPps;
static int hf_opa_GetVFInfo_pmaFailedPorts;
static int hf_opa_GetVFInfo_topoFailedPorts;
static int hf_opa_GetVFInfo_integrityErrors;
static int hf_opa_GetVFInfo_congestionErrors;
static int hf_opa_GetVFInfo_smaCongestionErrors;
static int hf_opa_GetVFInfo_bubbleErrors;
static int hf_opa_GetVFInfo_securityErrors;
static int hf_opa_GetVFInfo_routingErrors;
static int hf_opa_GetVFInfo_utilizationPct10;
static int hf_opa_GetVFInfo_discardsPct10;
static int hf_opa_GetVFInfo_maxInternalRate;
static int hf_opa_GetVFInfo_minInternalRate;
static int hf_opa_GetVFInfo_maxInternalMBps;

static int hf_opa_GetVFConfig;
static int hf_opa_GetVFConfig_vfName;
static int hf_opa_GetVFConfig_Port_NodeGUID;
static int hf_opa_GetVFConfig_Port_nodeDesc;
static int hf_opa_GetVFConfig_Port_NodeLID;
static int hf_opa_GetVFConfig_Port_PortNumber;

static int hf_opa_GetVFPortCounters;
static int hf_opa_GetVFPortCounters_vfName;
static int hf_opa_GetVFPortCounters_nodeLID;
static int hf_opa_GetVFPortCounters_PortNumber;
static int hf_opa_GetVFPortCounters_flags;
static int hf_opa_GetVFPortCounters_PortVFXmitData;
static int hf_opa_GetVFPortCounters_PortVFRcvData;
static int hf_opa_GetVFPortCounters_PortVFXmitPkts;
static int hf_opa_GetVFPortCounters_PortVFRcvPkts;
static int hf_opa_GetVFPortCounters_PortVFXmitDiscards;
static int hf_opa_GetVFPortCounters_SwPortVFCongestion;
static int hf_opa_GetVFPortCounters_PortVFXmitWait;
static int hf_opa_GetVFPortCounters_PortVFRcvFECN;
static int hf_opa_GetVFPortCounters_PortVFRcvBECN;
static int hf_opa_GetVFPortCounters_PortVFXmitTimeCong;
static int hf_opa_GetVFPortCounters_PortVFXmitWastedBW;
static int hf_opa_GetVFPortCounters_PortVFXmitWaitData;
static int hf_opa_GetVFPortCounters_PortVFRcvBubble;
static int hf_opa_GetVFPortCounters_PortVFMarkFECN;

static int hf_opa_ClearVFPortCounters;
static int hf_opa_ClearVFPortCounters_vfName;
static int hf_opa_ClearVFPortCounters_nodeLID;
static int hf_opa_ClearVFPortCounters_PortNumber;
static int hf_opa_ClearVFPortCounters_PortVFXmitData;
static int hf_opa_ClearVFPortCounters_PortVFRcvData;
static int hf_opa_ClearVFPortCounters_PortVFXmitPkts;
static int hf_opa_ClearVFPortCounters_PortVFRcvPkts;
static int hf_opa_ClearVFPortCounters_PortVFXmitDiscards;
static int hf_opa_ClearVFPortCounters_SwPortVFCongestion;
static int hf_opa_ClearVFPortCounters_PortVFXmitWait;
static int hf_opa_ClearVFPortCounters_PortVFRcvFECN;
static int hf_opa_ClearVFPortCounters_PortVFRcvBECN;
static int hf_opa_ClearVFPortCounters_PortVFXmitTimeCong;
static int hf_opa_ClearVFPortCounters_PortVFXmitWastedBW;
static int hf_opa_ClearVFPortCounters_PortVFXmitWaitData;
static int hf_opa_ClearVFPortCounters_PortVFRcvBubble;
static int hf_opa_ClearVFPortCounters_PortVFMarkFECN;
static int hf_opa_ClearVFPortCounters_reserved;
static int hf_opa_ClearVFPortCounters_CounterSelectMask;
static int * const _ClearVFPortCounters_CounterSelectMask[] = {
    &hf_opa_ClearVFPortCounters_PortVFXmitData,
    &hf_opa_ClearVFPortCounters_PortVFRcvData,
    &hf_opa_ClearVFPortCounters_PortVFXmitPkts,
    &hf_opa_ClearVFPortCounters_PortVFRcvPkts,
    &hf_opa_ClearVFPortCounters_PortVFXmitDiscards,
    &hf_opa_ClearVFPortCounters_SwPortVFCongestion,
    &hf_opa_ClearVFPortCounters_PortVFXmitWait,
    &hf_opa_ClearVFPortCounters_PortVFRcvFECN,
    &hf_opa_ClearVFPortCounters_PortVFRcvBECN,
    &hf_opa_ClearVFPortCounters_PortVFXmitTimeCong,
    &hf_opa_ClearVFPortCounters_PortVFXmitWastedBW,
    &hf_opa_ClearVFPortCounters_PortVFXmitWaitData,
    &hf_opa_ClearVFPortCounters_PortVFRcvBubble,
    &hf_opa_ClearVFPortCounters_PortVFMarkFECN,
    &hf_opa_ClearVFPortCounters_reserved,
    NULL
};

static int hf_opa_GetVFFocusPorts;
static int hf_opa_GetVFFocusPorts_vfName;
static int hf_opa_GetVFFocusPorts_select;
static int hf_opa_GetVFFocusPorts_start;
static int hf_opa_GetVFFocusPorts_range;
static int hf_opa_GetVFFocusPorts_nodeLID;
static int hf_opa_GetVFFocusPorts_portNumber;
static int hf_opa_GetVFFocusPorts_rate;
static int hf_opa_GetVFFocusPorts_mtu;
static int hf_opa_GetVFFocusPorts_localFlags;
static int hf_opa_GetVFFocusPorts_neighborFlags;
static int hf_opa_GetVFFocusPorts_value;
static int hf_opa_GetVFFocusPorts_nodeGUID;
static int hf_opa_GetVFFocusPorts_nodeDesc;
static int hf_opa_GetVFFocusPorts_neighborLid;
static int hf_opa_GetVFFocusPorts_neighborPortNumber;
static int hf_opa_GetVFFocusPorts_neighborValue;
static int hf_opa_GetVFFocusPorts_neighborGuid;
static int hf_opa_GetVFFocusPorts_neighborNodeDesc;

/* Expert Info */
static expert_field ei_opa_mad_error;
static expert_field ei_opa_mad_no_attribute_dissector;
static expert_field ei_opa_mad_attribute_modifier_error_nonzero;
static expert_field ei_opa_rmpp_undecoded;
static expert_field ei_opa_aggregate_error;

/* Fragments */
static int hf_opa_rmpp_fragments;
static int hf_opa_rmpp_fragment;
static int hf_opa_rmpp_fragment_overlap;
static int hf_opa_rmpp_fragment_overlap_conflicts;
static int hf_opa_rmpp_fragment_multiple_tails;
static int hf_opa_rmpp_fragment_too_long_fragment;
static int hf_opa_rmpp_fragment_error;
static int hf_opa_rmpp_fragment_count;
static int hf_opa_rmpp_reassembled_in;
static int hf_opa_rmpp_reassembled_length;

static const fragment_items opa_rmpp_frag_items = {
    &ett_rmpp_fragment,
    &ett_rmpp_fragments,
    &hf_opa_rmpp_fragments,
    &hf_opa_rmpp_fragment,
    &hf_opa_rmpp_fragment_overlap,
    &hf_opa_rmpp_fragment_overlap_conflicts,
    &hf_opa_rmpp_fragment_multiple_tails,
    &hf_opa_rmpp_fragment_too_long_fragment,
    &hf_opa_rmpp_fragment_error,
    &hf_opa_rmpp_fragment_count,
    &hf_opa_rmpp_reassembled_in,
    &hf_opa_rmpp_reassembled_length,
    NULL,
    "RMPP Fragments"
};

/**
 * Builds a range string from a PortSelectMask
 *
 * @param[in] tvb pointer to packet buffer
 * @param[in] offset offset into packet buffer where port select mask begins
 * @param[out] port_list optional: pointer to an arrray of ports, allocated by
 *                                 wmem_alloc(wmem_packet_scope(), 256)
 * @param[out] num_ports optional: pointer to a number of ports in set in port
 *                                 select mask and portlist if provided.
 * @return char* pointer to range string allocated using
 *                wmem_strbuf_new_sized(wmem_packet_scope(),...)
 */
static char *opa_format_port_select_mask(tvbuff_t *tvb, int offset, uint8_t **port_list, uint8_t *num_ports)
{
    int i, j, port, last = -1, first = 0, ports = 0;
    uint64_t mask, psm[4];
    wmem_strbuf_t *buf = NULL;
    uint8_t *portlist = NULL;

    if (!tvb_bytes_exist(tvb, offset, 32)) {
        return (char *)"Invalid Length: Requires 32 bytes";
    }
    psm[0] = tvb_get_ntoh64(tvb, offset);
    psm[1] = tvb_get_ntoh64(tvb, offset + 8);
    psm[2] = tvb_get_ntoh64(tvb, offset + 16);
    psm[3] = tvb_get_ntoh64(tvb, offset + 24);

    buf = wmem_strbuf_create(wmem_packet_scope());

    if (port_list) {
        /* Allocate list of ports; max = 256 = 64 * 4 */
        portlist = (uint8_t *)wmem_alloc(wmem_packet_scope(), 256);
        memset(portlist, 0xFF, 256);
    }
    for (i = 0; i < 4; i++) {
        mask = psm[3 - i];
        for (j = 0; mask && j < 64; j++, mask >>= 1) {
            if ((mask & (uint64_t)0x1) == 0) continue;
            port = (i * 64) + j;
            if (portlist) portlist[ports] = port;

            if (last == -1) {
                wmem_strbuf_append_printf(buf, "%d", port);
                last = first = port;
            } else if ((port - last) > 1) {
                if (first == last)
                    wmem_strbuf_append_printf(buf, ",%d", port);
                else
                    wmem_strbuf_append_printf(buf, "-%d,%d", last, port);
                last = first = port;
            } else {
                last = port;
            }
            ports++;
        }
    }
    if (first != last && last != -1) {
        wmem_strbuf_append_printf(buf, "-%d", last);
    }
    if (wmem_strbuf_get_len(buf) == 0) {
        wmem_strbuf_append(buf, "<Empty>");
    }
    if (num_ports) *num_ports = ports;
    if (port_list) *port_list = portlist;
    return (char *)wmem_strbuf_finalize(buf);
}
/* Custom Functions */
static void cf_opa_mad_swinfo_ar_frequency(char *buf, uint16_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%u ms", 2 ^ (value)*64);
}
static void cf_opa_mad_linkspeed(char *buf, uint16_t value)
{
    int len = 0;
    if (value & 0x1) /* 12.5 Gbps */
        len = snprintf(buf, ITEM_LABEL_LENGTH, "12.5");
    if (value & 0x2) /* 25.78125 Gbps */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%s25.78125", (len ? ", " : ""));
    if (len)
        snprintf(&buf[len], ITEM_LABEL_LENGTH - len, " Gbps");
    else
        snprintf(buf, ITEM_LABEL_LENGTH, "No State Change");
}
static void cf_opa_mad_linkwidth(char *buf, uint16_t value)
{
    int len = 0;
    if (value & 0x1) /* 1x */
        len = snprintf(buf, ITEM_LABEL_LENGTH, "1X");
    if (value & 0x2) /* 2x */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%s2X", (len ? ", " : ""));
    if (value & 0x4) /* 3x */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%s3X", (len ? ", " : ""));
    if (value & 0x8) /* 4x */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%s4X", (len ? ", " : ""));
    if (!len)
        snprintf(buf, ITEM_LABEL_LENGTH, "No State Change");
}
static void cf_opa_mad_portlinkmode(char *buf, uint16_t value)
{
    int len = 0;
    if (value & 0x1) /* Reserved */
        len = snprintf(buf, ITEM_LABEL_LENGTH, "Reserved");
    if (value & 0x2) /* Ethernet */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%sEthernet", (len ? ", " : ""));
    if (value & 0x4) /* STL */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%sSTL", (len ? ", " : ""));
    if (!len)
        snprintf(buf, ITEM_LABEL_LENGTH, "No State Change");
}
static void cf_opa_mad_portltpcrcmode(char *buf, uint16_t value)
{
    int len = 0;
    if (value & 0x1) /* 14-bit */
        len = snprintf(buf, ITEM_LABEL_LENGTH, "14-bit");
    if (value & 0x2) /* 16-bit */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%s16-bit", (len ? ", " : ""));
    if (value & 0x4) /* 48-bit */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%s48-bit overlapping", (len ? ", " : ""));
    if (value & 0x8) /* 12 to 16 bit per lane */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%s[12,16]-bit per lane", (len ? ", " : ""));
    if (len)
        snprintf(&buf[len], ITEM_LABEL_LENGTH - len, " LTP CRC Mode");
    else
        snprintf(buf, ITEM_LABEL_LENGTH, "No State Change");
}
static void cf_opa_mad_packetformat(char *buf, uint16_t value)
{
    int len = 0;
    if (value & 0x1) /* 8B */
        len = snprintf(buf, ITEM_LABEL_LENGTH, "8B");
    if (value & 0x2) /* 9B */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%s9B", (len ? ", " : ""));
    if (value & 0x4) /* 10B */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%s10B", (len ? ", " : ""));
    if (value & 0x8) /* 16B */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%s16B", (len ? ", " : ""));
    if (len)
        snprintf(&buf[len], ITEM_LABEL_LENGTH - len, " Format%s", (len > 4 ? "s" : ""));
    else
        snprintf(buf, ITEM_LABEL_LENGTH, "No State Change");
}
static void cf_opa_mad_swcongestionsetting_controlmap(char *buf, uint32_t value)
{
    int len = 0;
    if (value & 0x1) /* Victim */
        len = snprintf(buf, ITEM_LABEL_LENGTH, "Victim");
    if (value & 0x2) /* Credit */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%sCredit", (len ? ", " : ""));
    if (value & 0x4) /* Threshold & PacketSize */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%sThreshold & PacketSize", (len ? ", " : ""));
    if (value & 0x8) /* CS_threshold & CS_ReturnDelay */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%sCS_threshold & CS_ReturnDelay", (len ? ", " : ""));
    if (value & 0x10) /* Marking Rate */
        len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%sMarking Rate", (len ? ", " : ""));
    if (!len)
        snprintf(buf, ITEM_LABEL_LENGTH, "No Valid Fields");
}
static void cf_opa_mad_32b_mask(char *buf, uint32_t value)
{
    int len = 0;
    uint32_t i, mask;
    for (i = 0, mask = value; mask && i < 32 && len < ITEM_LABEL_LENGTH; i++, mask >>= 1) {
        if (mask & 1) {
            len += snprintf(&buf[len], ITEM_LABEL_LENGTH - len, "%s%u", (len ? ", " : ""), i);
        }
    }
    if (!len) {
        snprintf(buf, ITEM_LABEL_LENGTH, " ");
    }
}
static void cf_opa_mad_computed_pct10(char *buf, uint16_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%u.%01u", value / 10, value % 10);
}

/* Dissector Declarations */
static dissector_handle_t opa_mad_handle;
static dissector_table_t ethertype_dissector_table;

static reassembly_table opa_mad_rmpp_reassembly_table;

static bool pref_parse_on_mad_status_error;
static bool pref_attempt_rmpp_defragment = true;

static range_t *global_mad_vendor_class;
static range_t *global_mad_vendor_rmpp_class;
static range_t *global_mad_application_class;
static range_t *global_mad_reserved_class;
static range_t *global_mad_opa_class;

static int parse_MAD_AttributeModifier(proto_tree *MAD_tree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    proto_tree *AttributeModifier_tree;
    proto_item *AttributeModifier_item;
    int local_offset = *offset;

    AttributeModifier_item = proto_tree_add_item(MAD_tree, hf_opa_attribute_modifier, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    AttributeModifier_tree = proto_item_add_subtree(AttributeModifier_item, ett_mad_attributemod);

    switch (MAD->MgmtClass) {
    case SUBN_LID_ROUTED:
    case SUBN_DIRECTED_ROUTE:
        switch (MAD->AttributeID) {
        case SM_ATTR_ID_CLASS_PORT_INFO:            /* Shall be 0 */
        case SM_ATTR_ID_NOTICE:
        case SM_ATTR_ID_NODE_DESCRIPTION:
        case SM_ATTR_ID_NODE_INFO:
        case SM_ATTR_ID_SWITCH_INFO:
        case SM_ATTR_ID_SL_SC_MAPPING_TABLE:
        case SM_ATTR_ID_SC_SL_MAPPING_TABLE:
        case SM_ATTR_ID_SM_INFO:
        case SM_ATTR_ID_CONGESTION_INFO:
        case SM_ATTR_ID_SWITCH_CONGESTION_LOG:
        case SM_ATTR_ID_SWITCH_CONGESTION_SETTING:
        case SM_ATTR_ID_HFI_CONGESTION_LOG:
        case SM_ATTR_ID_HFI_CONGESTION_SETTING:
            if (MAD->AttributeModifier)
                expert_add_info(NULL, AttributeModifier_item, &ei_opa_mad_attribute_modifier_error_nonzero);
            break;
        case SM_ATTR_ID_PORT_INFO:                  /* NNNN NNNN 0000 0000 0000 00SA PPPP PPPP */
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_Nps2AP, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_PORT_STATE_INFO:            /* NNNN NNNN 0000 0000 0000 00S0 PPPP PPPP */
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_NpS2P, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_LED_INFO:                   /* NNNN NNNN 0000 0000 0000 000A PPPP PPPP */
        case SM_ATTR_ID_BUFFER_CONTROL_TABLE:
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_NpAP, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_PART_TABLE:                 /* NNNN NNNN PPPP PPPP 0000 0BBB BBBB BBBB */
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_NbP2B, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_SC_SC_MAPPING_TABLE:        /* NNNN NNNN 0000 00AB IIII IIII EEEE EEEE */
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_NbA2B2IE, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_VL_ARBITRATION:             /* NNNN NNNN SSSS SSSS 0000 000A PPPP PPPP */
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_NpSAP, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_LINEAR_FWD_TABLE:           /* NNNN NNNN 0000 0ABB BBBB BBBB BBBB BBBB */
        case SM_ATTR_ID_PORT_GROUP_FWD_TABLE:
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_NbA3B3, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_MCAST_FWD_TABLE:            /* NNNN NNNN PP0A BBBB BBBB BBBB BBBB BBBB */
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_NbP3A4B4, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_CABLE_INFO:                 /* 0AAA AAAA AAAA ALLL LLL0 0000 PPPP PPPP */
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_A5LP, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_AGGREGATE:                  /* 0000 0000 0000 0000 0000 0000 NNNN NNNN */
            proto_tree_add_item(AttributeModifier_tree, hf_opa_attribute_modifier_N2, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_SC_VLR_MAPPING_TABLE:       /* NNNN NNNN 0000 0000 000Y 000A PPPP PPPP */
        case SM_ATTR_ID_SC_VLT_MAPPING_TABLE:
        case SM_ATTR_ID_SC_VLNT_MAPPING_TABLE:
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_NbYAP, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_SWITCH_PORT_CONGESTION_SETTING: /* NNNN NNNN 0000 0000 0000 0000 PPPP PPPP */
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_NpP, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_HFI_CONGESTION_CONTROL_TABLE: /* NNNN NNNN 0000 0000 0000 0000 PPPP PPPP */
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_NbP, ENC_BIG_ENDIAN);
            break;
        case SM_ATTR_ID_PORT_GROUP_TABLE:           /* NNNN NNNN PP00 0000 0000 0000 00AB BBBB */
            proto_tree_add_bitmask_list(AttributeModifier_tree, tvb, local_offset, 4, _attribute_modifier_NbP3A6B5, ENC_BIG_ENDIAN);
            break;
        default:
            if (MAD->AttributeModifier)
                expert_add_info(NULL, AttributeModifier_item, &ei_opa_mad_attribute_modifier_error_nonzero);
            break;
        }
        break;
    case PERF:
        switch (MAD->AttributeID) {
        case PM_ATTR_ID_CLASS_PORTINFO:         /* 0 */
            if (MAD->AttributeModifier)
                expert_add_info(NULL, AttributeModifier_item, &ei_opa_mad_attribute_modifier_error_nonzero);
            break;
        case PM_ATTR_ID_PORT_STATUS:            /* PPPP PPPP 0000 0000 0000 0000 0000 0000 */
        case PM_ATTR_ID_CLEAR_PORT_STATUS:
        case PM_ATTR_ID_DATA_PORT_COUNTERS:
        case PM_ATTR_ID_ERROR_PORT_COUNTERS:
            proto_tree_add_item(AttributeModifier_tree, hf_opa_attribute_modifier_NP, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            break;
        case PM_ATTR_ID_ERROR_INFO:
        default:
            if (MAD->AttributeModifier)
                expert_add_info(NULL, AttributeModifier_item, &ei_opa_mad_attribute_modifier_error_nonzero);
            break;
        }
        break;
    case PERFADMN:
    case SUBNADMN:
        if (MAD->AttributeModifier)
            expert_add_info(NULL, AttributeModifier_item, &ei_opa_mad_attribute_modifier_error_nonzero);
        break;
    default:
        break;
    }
    local_offset += 4;
    return local_offset;
}
/* Parse the common MAD Header */
static bool parse_MAD_Common(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *MAD_header_item;
    proto_tree *MAD_header_tree;
    proto_item *MAD_Status_item;

    if (MAD == NULL) {
        return false;
    }

    /* Get the Management Class to decide between LID Routed and Direct Route */

    /* Populate the Dissector Tree */
    MAD_header_item = proto_tree_add_item(parentTree, hf_opa_mad, tvb, local_offset, 24, ENC_NA);
    MAD_header_tree = proto_item_add_subtree(MAD_header_item, ett_mad);

    proto_tree_add_item(MAD_header_tree, hf_opa_mad_base_version, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    MAD->BaseVersion = tvb_get_uint8(tvb, local_offset);
    local_offset += 1;
    proto_tree_add_item(MAD_header_tree, hf_opa_mad_mgmt_class, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    MAD->MgmtClass = tvb_get_uint8(tvb, local_offset);
    local_offset += 1;
    proto_tree_add_item(MAD_header_tree, hf_opa_mad_class_version, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    MAD->ClassVersion = tvb_get_uint8(tvb, local_offset);
    local_offset += 1;
    proto_tree_add_item(MAD_header_tree, hf_opa_mad_method, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    MAD->Method = tvb_get_uint8(tvb, local_offset);
    local_offset += 1;
    if (MAD->MgmtClass == SUBN_DIRECTED_ROUTE) {
        proto_tree_add_item(MAD_header_tree, hf_opa_mad_status_DR_D, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        MAD_Status_item = proto_tree_add_item(MAD_header_tree, hf_opa_mad_status_DR_status, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        MAD->Status = tvb_get_ntohs(tvb, local_offset);
        local_offset += 2;
        if (MAD->Status & 0x7FFF) {
            proto_item_append_text(MAD_header_item, " Error: 0x%04x", MAD->Status & 0x7FFF);
            expert_add_info_format(pinfo, MAD_Status_item, &ei_opa_mad_error,
                "Mad Status Error (0x%04x)", MAD->Status & 0x7FFF);
        }
        proto_tree_add_item(MAD_header_tree, hf_opa_mad_status_DR_Hop_Pointer, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        MAD->HopPointer = tvb_get_uint8(tvb, local_offset);
        local_offset += 1;
        proto_tree_add_item(MAD_header_tree, hf_opa_mad_status_DR_Hop_Count, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        MAD->HopCount = tvb_get_uint8(tvb, local_offset);
        local_offset += 1;
    } else {
        MAD_Status_item = proto_tree_add_bitmask(MAD_header_tree, tvb, local_offset,
            hf_opa_mad_status, ett_mad_status, _mad_status, ENC_BIG_ENDIAN);
        MAD->Status = tvb_get_ntohs(tvb, local_offset);
        local_offset += 2;
        if (MAD->Status) {
            proto_item_append_text(MAD_header_item, " Error: 0x%04x", MAD->Status);
            expert_add_info_format(pinfo, MAD_Status_item, &ei_opa_mad_error,
                "Mad Status Error (0x%04x)", MAD->Status);
        }
        proto_tree_add_item(MAD_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
    }
    proto_tree_add_item(MAD_header_tree, hf_opa_mad_transaction_id, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    MAD->TransactionID = tvb_get_ntoh64(tvb, local_offset);
    local_offset += 8;
    proto_tree_add_item(MAD_header_tree, hf_opa_mad_attribute_id, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    MAD->AttributeID = tvb_get_ntohs(tvb, local_offset);
    local_offset += 2;
    proto_tree_add_item(MAD_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    MAD->AttributeModifier = tvb_get_ntohl(tvb, local_offset);
    *offset = parse_MAD_AttributeModifier(MAD_header_tree, tvb, &local_offset, MAD);

    return true;
}
/* Parse the RMPP (Reliable Multi-Packet Transaction Protocol) */
static bool parse_RMPP(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset, RMPP_t *RMPP)
{
    int local_offset = *offset;
    proto_item *RMPP_header_item;
    proto_item *RMPP_type_item;
    proto_item *RMPP_segment_number_item;
    proto_tree *RMPP_header_tree;
    uint32_t val;

    RMPP_header_item = proto_tree_add_item(parentTree, hf_opa_rmpp, tvb, local_offset, 12, ENC_NA);
    RMPP_header_tree = proto_item_add_subtree(RMPP_header_item, ett_rmpp);

    proto_tree_add_item(RMPP_header_tree, hf_opa_rmpp_version, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    RMPP->Version = tvb_get_uint8(tvb, local_offset);
    local_offset += 1;

    RMPP_type_item = proto_tree_add_item_ret_uint(RMPP_header_tree, hf_opa_rmpp_type, tvb,
                                                  local_offset, 1, ENC_BIG_ENDIAN, &val);
    RMPP->Type = val;
    local_offset += 1;
    proto_tree_add_item(RMPP_header_tree, hf_opa_rmpp_r_resp_time, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(RMPP_header_tree, hf_opa_rmpp_flags_last, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(RMPP_header_tree, hf_opa_rmpp_flags_first, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(RMPP_header_tree, hf_opa_rmpp_flags_active, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    RMPP->resptime_flags = tvb_get_uint8(tvb, local_offset);
    local_offset += 1;

    proto_tree_add_item_ret_uint(RMPP_header_tree, hf_opa_rmpp_status, tvb,
                                 local_offset, 1, ENC_BIG_ENDIAN, &val);
    RMPP->Status = val;
    local_offset += 1;

    if (!(RMPP->resptime_flags & RMPP_FLAG_ACTIVE_MASK) && RMPP->Type == RMPP_ILLEGAL) {
        proto_item_set_text(RMPP_header_item, "%s%s", "RMPP (Empty)", " - Reliable Multi-Packet Transaction Protocol");
        proto_item_append_text(RMPP_type_item, " %s", "RMPP (Empty)");
    } else {
        proto_item_set_text(RMPP_header_item, "%s%s", val_to_str(RMPP->Type, RMPP_Packet_Types, "RMPP (Reserved 0x%02x)"), " - Reliable Multi-Packet Transaction Protocol");
        proto_item_append_text(RMPP_type_item, " %s", val_to_str(RMPP->Type, RMPP_Packet_Types, "RMPP (Reserved 0x%02x)"));
    }

    RMPP->PayloadLength = 0;

    switch (RMPP->Type) {
    case RMPP_ILLEGAL:
        proto_tree_add_item(RMPP_header_tree, hf_opa_rmpp_data1, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(RMPP_header_tree, hf_opa_rmpp_data2, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        break;
    case RMPP_DATA:
        RMPP_segment_number_item = proto_tree_add_item(RMPP_header_tree, hf_opa_rmpp_segment_number, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        RMPP->SegmentNumber = tvb_get_ntohl(tvb, local_offset);
        if (!pref_attempt_rmpp_defragment && RMPP->SegmentNumber > 1) {
            expert_add_info_format(pinfo, RMPP_segment_number_item, &ei_opa_rmpp_undecoded,
                "Parsing Disabled for RMPP Data Segments greater than 1 (%u)", RMPP->SegmentNumber);
        }
        local_offset += 4;
        proto_tree_add_item(RMPP_header_tree, hf_opa_rmpp_payload_length32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        RMPP->PayloadLength = tvb_get_ntohl(tvb, local_offset);
        local_offset += 4;
        break;
    case RMPP_ACK:
        proto_tree_add_item(RMPP_header_tree, hf_opa_rmpp_segment_number, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(RMPP_header_tree, hf_opa_rmpp_new_window_last, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        break;
    case RMPP_STOP:
    case RMPP_ABORT:
        proto_tree_add_item(RMPP_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_NA);
        local_offset += 4;
        proto_tree_add_item(RMPP_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_NA);
        local_offset += 4;
        break;
    default:
        return false;
    }
    *offset = local_offset;
    return true;
}
/* Parse NoticeDataDetails Attribute Field */
static int parse_NoticeDataDetails(proto_tree *parentTree, tvbuff_t *tvb, int *offset, uint16_t trapNumber)
{
    int local_offset = *offset;
    proto_item *DataDetails_header_item;
    proto_tree *DataDetails_header_tree;

    if (!parentTree)
        return 0;

    DataDetails_header_item = proto_tree_add_item(parentTree, hf_opa_Trap, tvb, local_offset, 64, ENC_NA);
    DataDetails_header_tree = proto_item_add_subtree(DataDetails_header_item, ett_datadetails);
    proto_item_append_text(DataDetails_header_item, " %u DataDetails", trapNumber);

    switch (trapNumber) {
    case 64:
    case 65:
    case 66:
    case 67:
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_GID, tvb, local_offset, 16, ENC_NA);
        local_offset += 16;
        break;
    case 128:
    case 2048:
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_LID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        break;
    case 129:
    case 130:
    case 131:
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_LID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_PORTNO, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        break;
    case 144:
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_LID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_CAPABILITYMASK, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_CAPABILITYMASK3, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_144_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_LinkWidthDowngradeEnabledChange, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_LinkSpeecEnabledChange, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_LinkWidthEnabledChange, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_NodeDescriptionChange, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        break;
    case 145:
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_SystemImageGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_LID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        break;
    case 256:
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_LID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_DRSLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_Method, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_DRNotice, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_DRPathTruncated, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_DRHopCount, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_AttributeID, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_AttributeModifier, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_MKey, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_DRNoticeReturnPath, tvb, local_offset, 30, ENC_NA);
        local_offset += 30;
        break;
    case 257:
    case 258:
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_LID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_LID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_Key, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_SL, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_SL_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_GID, tvb, local_offset, 16, ENC_NA);
        local_offset += 16;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_GID, tvb, local_offset, 16, ENC_NA);
        local_offset += 16;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_QP, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_QP, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        break;
    case 259:
        proto_tree_add_bitmask(DataDetails_header_tree, tvb, local_offset, hf_opa_Trap_DataValid,
            ett_datadetails_trap259datavalid, _Trap_DataValid, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_PKey, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_LID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_LID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_SL, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_SL_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_GID, tvb, local_offset, 16, ENC_NA);
        local_offset += 16;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_GID, tvb, local_offset, 16, ENC_NA);
        local_offset += 16;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_QP, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_Trap_QP, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(DataDetails_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        break;
    default:
        break;
    }

    return local_offset;
}

/* Parse NoticesAndTraps Attribute  */
static int parse_NoticesAndTraps(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    int local_offset = *offset;
    proto_item *NoticesAndTraps_header_item;
    proto_tree *NoticesAndTraps_header_tree;
    bool isGeneric = tvb_get_bits8(tvb, local_offset * 8, 1);
    uint16_t trapNumber = tvb_get_ntohs(tvb, local_offset + 4);

    if (!parentTree)
        return *offset;

    NoticesAndTraps_header_item = proto_tree_add_item(parentTree, hf_opa_Notice, tvb, local_offset, 96, ENC_NA);
    proto_item_set_text(NoticesAndTraps_header_item, "%s", val_to_str(trapNumber, Trap_Description, "Unknown or Vendor Specific Trap Number! (0x%02x)"));
    NoticesAndTraps_header_tree = proto_item_add_subtree(NoticesAndTraps_header_item, ett_noticestraps);

    proto_tree_add_item(NoticesAndTraps_header_tree, hf_opa_Notice_IsGeneric, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_opa_Notice_Type, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    if (isGeneric) {
        proto_tree_add_item(NoticesAndTraps_header_tree, hf_opa_Notice_ProducerType, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(NoticesAndTraps_header_tree, hf_opa_Notice_TrapNumber, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
    } else {
        proto_tree_add_item(NoticesAndTraps_header_tree, hf_opa_Notice_VendorID, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(NoticesAndTraps_header_tree, hf_opa_Notice_DeviceID, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
    }
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_opa_Notice_Toggle, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_opa_Notice_Count, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_opa_Notice_IssuerLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(NoticesAndTraps_header_tree, hf_opa_Notice_IssuerGID, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;

    if (isGeneric) {
        parse_NoticeDataDetails(NoticesAndTraps_header_tree, tvb, &local_offset, trapNumber);
        local_offset += 64;
        if (tvb_bytes_exist(tvb, local_offset, 8)) {
            proto_tree_add_item(NoticesAndTraps_header_tree, hf_opa_Notice_ClassDataDetails, tvb, local_offset, -1, ENC_NA);
        }
    } else {
        local_offset += 64;
    }
    return local_offset;
}

/* Parse InformInfo Attribute*/
static int parse_InformInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *InformInfo_header_item;
    proto_tree *InformInfo_header_tree;
    bool         isGeneric;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    InformInfo_header_item = proto_tree_add_item(parentTree, hf_opa_InformInfo, tvb, local_offset, 40, ENC_NA);
    InformInfo_header_tree = proto_item_add_subtree(InformInfo_header_item, ett_informinfo);

    proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_GID, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;
    proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_LIDRangeBegin, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_LIDRangeEnd, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    isGeneric = (bool)tvb_get_bits8(tvb, local_offset * 8 + 7, 1);
    proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_IsGeneric, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_Subscribe, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_Type, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(InformInfo_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    if (isGeneric) {
        proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_TrapNumber, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
    } else {
        proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_DeviceID, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
    }
    proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_QPN, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;
    proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_RespTimeValue, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(InformInfo_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    if (isGeneric) {
        proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_ProducerType, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
    } else {
        proto_tree_add_item(InformInfo_header_tree, hf_opa_InformInfo_VendorID, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
    }

    return local_offset;
}

/* Parse ClassPortInfo MAD from the ALL classes. */
static int parse_ClassPortInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    proto_item *ClassPortInfo_item;
    proto_tree *ClassPortInfo_tree;
    proto_tree *ClassPortInfo_Redirect_tree;
    proto_tree *ClassPortInfo_Trap_tree;
    int local_offset = *offset;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    ClassPortInfo_item = proto_tree_add_item(parentTree, hf_opa_ClassPortInfo, tvb, local_offset, 80, ENC_NA);
    ClassPortInfo_tree = proto_item_add_subtree(ClassPortInfo_item, ett_classportinfo);

    proto_tree_add_item(ClassPortInfo_tree, hf_opa_ClassPortInfo_BaseVersion, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(ClassPortInfo_tree, hf_opa_ClassPortInfo_ClassVersion, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(ClassPortInfo_tree, hf_opa_ClassPortInfo_CapMask, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(ClassPortInfo_tree, hf_opa_ClassPortInfo_CapMask2, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(ClassPortInfo_tree, hf_opa_ClassPortInfo_RespTimeValue, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    ClassPortInfo_Redirect_tree = proto_tree_add_subtree(ClassPortInfo_tree, tvb, local_offset, 32,
        ett_classportinfo_redirect, NULL, "Redirect");

    proto_tree_add_item(ClassPortInfo_Redirect_tree, hf_opa_ClassPortInfo_Redirect_GID, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;
    proto_tree_add_item(ClassPortInfo_Redirect_tree, hf_opa_ClassPortInfo_Redirect_TClass, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(ClassPortInfo_Redirect_tree, hf_opa_ClassPortInfo_Redirect_reserved, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(ClassPortInfo_Redirect_tree, hf_opa_ClassPortInfo_Redirect_FlowLabel, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;
    proto_tree_add_item(ClassPortInfo_Redirect_tree, hf_opa_ClassPortInfo_Redirect_LID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(ClassPortInfo_Redirect_tree, hf_opa_ClassPortInfo_Redirect_SL, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ClassPortInfo_Redirect_tree, hf_opa_ClassPortInfo_Redirect_reserved2, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(ClassPortInfo_Redirect_tree, hf_opa_ClassPortInfo_Redirect_QP, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;
    proto_tree_add_item(ClassPortInfo_Redirect_tree, hf_opa_ClassPortInfo_Redirect_Q_Key, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    ClassPortInfo_Trap_tree = proto_tree_add_subtree(ClassPortInfo_tree, tvb, local_offset, 32,
        ett_classportinfo_trap, NULL, "Trap");

    proto_tree_add_item(ClassPortInfo_Trap_tree, hf_opa_ClassPortInfo_Trap_GID, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;
    proto_tree_add_item(ClassPortInfo_Trap_tree, hf_opa_ClassPortInfo_Trap_TClass, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(ClassPortInfo_Trap_tree, hf_opa_ClassPortInfo_Trap_reserved, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(ClassPortInfo_Trap_tree, hf_opa_ClassPortInfo_Trap_FlowLabel, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;
    proto_tree_add_item(ClassPortInfo_Trap_tree, hf_opa_ClassPortInfo_Trap_LID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(ClassPortInfo_Trap_tree, hf_opa_ClassPortInfo_Trap_HopLimit, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(ClassPortInfo_Trap_tree, hf_opa_ClassPortInfo_Trap_QP, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;
    proto_tree_add_item(ClassPortInfo_Trap_tree, hf_opa_ClassPortInfo_Trap_Q_Key, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(ClassPortInfo_Trap_tree, hf_opa_ClassPortInfo_Trap_P_Key, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(ClassPortInfo_Redirect_tree, hf_opa_ClassPortInfo_Redirect_P_Key, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(ClassPortInfo_Trap_tree, hf_opa_ClassPortInfo_Trap_SL, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ClassPortInfo_Trap_tree, hf_opa_ClassPortInfo_Trap_reserved2, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(ClassPortInfo_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;

    return local_offset;
}

/* Parse NodeDescription Attribute  */
static int parse_NodeDescription(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_tree *NodeDescription_header_tree = parentTree;
    proto_item *NodeDescription_header_item;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    NodeDescription_header_item = proto_tree_add_item(NodeDescription_header_tree, hf_opa_NodeDescription, tvb, local_offset, 64, ENC_NA);
    NodeDescription_header_tree = proto_item_add_subtree(NodeDescription_header_item, ett_nodedescription);

    proto_tree_add_item(NodeDescription_header_tree, hf_opa_NodeDescription_NodeString, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
    local_offset += 64;
    return local_offset;
}

/* Parse NodeInfo Attribute */
static int parse_NodeInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_tree *NodeInfo_header_tree = parentTree;
    proto_item *NodeInfo_header_item;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    NodeInfo_header_item = proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo, tvb, local_offset, 44, ENC_NA);
    NodeInfo_header_tree = proto_item_add_subtree(NodeInfo_header_item, ett_nodeinfo);

    proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo_BaseVersion, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo_ClassVersion, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo_NodeType, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo_NumPorts, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(NodeInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo_SystemImageGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo_NodeGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo_PortGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo_PartitionCap, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo_DeviceID, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo_Revision, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo_LocalPortNum, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(NodeInfo_header_tree, hf_opa_NodeInfo_VendorID, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;

    return local_offset;

}

/* Parse SwitchInfo Attribute  */
static int parse_SwitchInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_tree *SwitchInfo_header_tree = parentTree;
    proto_item *SwitchInfo_header_item;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    SwitchInfo_header_item = proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo, tvb, local_offset, 84, ENC_NA);
    SwitchInfo_header_tree = proto_item_add_subtree(SwitchInfo_header_item, ett_switchinfo);

    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_LinearFDBCap, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_MulticastFDBCap, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_LinearFDBTop, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_MulticastFDBTop, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_CollectiveCap, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_CollectiveTop, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_IPAddrIPv6, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_IPAddrIPv4, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_LifeTimeValue, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_PortStateChange, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_reserved2, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_PartitionEnforcementCap, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_PortGroupCap, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_PortGroupTop, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_SupportedRoutingMode, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_EnabledRoutingMode, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_reserved3, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_EnhancedPortZero, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_reserved4, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_reserved5, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_CollectiveMask, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_MulticastMask, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_bitmask_list(SwitchInfo_header_tree, tvb, local_offset, 2,
        _SwitchInfo_AdaptiveRouting, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_bitmask(SwitchInfo_header_tree, tvb, local_offset, hf_opa_SwitchInfo_SwitchCapabilityMask,
        ett_switchinfo_switchcapabilitymask, _SwitchInfo_SwitchCapabilityMask, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(SwitchInfo_header_tree, hf_opa_SwitchInfo_CapabilityMaskCollectives, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    return local_offset;
}

/* Parse PortInfo Attribute  */
static int parse_PortInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_tree *PortInfo_header_tree = parentTree,
        *PortInfo_VL_tree,
        *PortInfo_Link_tree,
        *PortInfo_FlitControl_tree,
        *PortInfo_NeighborMTU_tree,
        *PortInfo_XmitQ_tree;
    proto_item * PortInfo_header_item,
        *PortInfo_PortWdthSpeedActive_item;
    proto_item *temp_item;
    unsigned p, i, Num_ports, Port_num;
    uint16_t active;
    int block_length = 242;
    int block_pad_len = 8 - (block_length & 7); /* Padding to add */

    if (MAD->MgmtClass == SUBNADMN) {
        Num_ports = 1;
        Port_num = tvb_get_uint8(tvb, local_offset - 4);
    } else {
        Num_ports = (MAD->AttributeModifier & 0xFF000000) >> 24;
        Port_num = (MAD->AttributeModifier & 0x000000FF);
    }

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    for (p = Port_num; p < (Port_num + Num_ports);) {
        PortInfo_header_item = proto_tree_add_item(parentTree, hf_opa_PortInfo, tvb, local_offset, block_length, ENC_NA);
        proto_item_set_text(PortInfo_header_item, "PortInfo on Port %d", p);
        PortInfo_header_tree = proto_item_add_subtree(PortInfo_header_item, ett_portinfo);

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_LID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_FlowControlMask, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        /* VL */
        PortInfo_VL_tree = proto_tree_add_subtree(PortInfo_header_tree, tvb, local_offset, 8,
            ett_portinfo_vl, NULL, "VL Info");
        proto_tree_add_item(PortInfo_VL_tree, hf_opa_PortInfo_VL_PreemptCap, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(PortInfo_VL_tree, hf_opa_PortInfo_VL_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_VL_tree, hf_opa_PortInfo_VL_Cap, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(PortInfo_VL_tree, hf_opa_PortInfo_VL_HighLimit, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortInfo_VL_tree, hf_opa_PortInfo_VL_PreemptingLimit, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortInfo_VL_tree, hf_opa_PortInfo_VL_ArbitrationHighCap, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(PortInfo_VL_tree, hf_opa_PortInfo_VL_ArbitrationLowCap, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        /* Port States */
        proto_tree_add_bitmask_list(PortInfo_header_tree, tvb, local_offset, 4, _PortStates, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PortPhysConfig_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PortPhysConfig_PortType, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        /* MultiCollectMask */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_MultiCollectMask_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_MultiCollectMask_CollectiveMask, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_MultiCollectMask_MulticastMask, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_M_KeyProtectBits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_S1_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_LMC, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_S2_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_MasterSMSL, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_LinkInitReason, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PartitionEnforcementInbound, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PartitionEnforcementOutbound, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_S3_reserved2, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_S4_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_OperationalVL, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        /* P_Keys */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_P_Keys_P_Key_8B, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_P_Keys_P_Key_10B, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        /* Violations */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_M_KeyViolations, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_P_KeyViolations, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_Q_KeyViolations, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_TrapQueuePair_reserved, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_TrapQueuePair, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_SAQueuePair_reserved, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_SAQueuePair, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_NeighborPortNum, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        /*STL Linkdown reason */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_LinkDownReason, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        /*STL NeighborLinkdown reason */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_NeighborLinkDownReason, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        /* Subnet */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_ClientReregister, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_MulticastPKeyTrapSuppressEnabled, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_Timeout, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        PortInfo_Link_tree = proto_tree_add_subtree(PortInfo_header_tree, tvb, local_offset, 22,
            ett_portinfo_link, NULL, "Link Info");
        /* LinkSpeed */
        proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_LinkSpeedSupported, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_LinkSpeedEnabled, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        active = tvb_get_ntohs(tvb, local_offset);
        PortInfo_PortWdthSpeedActive_item = proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_LinkSpeedActive, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        if (!active && (MAD->Method == METHOD_GET_RESP || MAD->Method == METHOD_GETTABLE_RESP))
            proto_item_set_text(PortInfo_PortWdthSpeedActive_item, "None");
        /* LinkWidth */
        proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_LinkWidthSupported, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_LinkWidthEnabled, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        active = tvb_get_ntohs(tvb, local_offset);
        PortInfo_PortWdthSpeedActive_item = proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_LinkWidthActive, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        if (!active && (MAD->Method == METHOD_GET_RESP || MAD->Method == METHOD_GETTABLE_RESP))
            proto_item_set_text(PortInfo_PortWdthSpeedActive_item, "None");

        /* LinkWidthDowngrade */
        proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_LinkWidthDowngrade_Supported, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_LinkWidthDowngrade_Enabled, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        active = tvb_get_ntohs(tvb, local_offset);
        PortInfo_PortWdthSpeedActive_item = proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_LinkWidthDowngrade_TxActive, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        if (!active && (MAD->Method == METHOD_GET_RESP || MAD->Method == METHOD_GETTABLE_RESP))
            proto_item_set_text(PortInfo_PortWdthSpeedActive_item, "None");
        active = tvb_get_ntohs(tvb, local_offset);
        PortInfo_PortWdthSpeedActive_item = proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_LinkWidthDowngrade_RxActive, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        if (!active && (MAD->Method == METHOD_GET_RESP || MAD->Method == METHOD_GETTABLE_RESP))
            proto_item_set_text(PortInfo_PortWdthSpeedActive_item, "None");

        /*PortLinkMode */
        proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_PortLinkMode_reserved, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_PortLinkMode_Supported, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_PortLinkMode_Enabled, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_Link_tree, hf_opa_PortInfo_PortLinkMode_Active, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        /*PortLTPCRCMode */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PortLTPCRCMode_reserved, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PortLTPCRCMode_Supported, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PortLTPCRCMode_Enabled, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PortLTPCRCMode_Active, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        /*PortMode*/
        proto_tree_add_bitmask(PortInfo_header_tree, tvb, local_offset, hf_opa_PortInfo_PortMode,
            ett_portinfo_portmode, _PortInfo_PortMode, ENC_BIG_ENDIAN);
        local_offset += 2;

        /* PortPacketFormats */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PortPacketFormats_Supported, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PortPacketFormats_Enabled, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        /* Flit Control */
        PortInfo_FlitControl_tree = proto_tree_add_subtree(PortInfo_header_tree, tvb, local_offset, 10,
            ett_portinfo_flitcontrol, NULL, "Flit Control");
        proto_tree_add_item(PortInfo_FlitControl_tree, hf_opa_PortInfo_FlitControl_Interleave_reserved, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_FlitControl_tree, hf_opa_PortInfo_FlitControl_Interleave_DistanceSupported, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_FlitControl_tree, hf_opa_PortInfo_FlitControl_Interleave_DistanceEnabled, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_FlitControl_tree, hf_opa_PortInfo_FlitControl_Interleave_MaxNestLevelTxEnabled, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_FlitControl_tree, hf_opa_PortInfo_FlitControl_Interleave_MaxNestLevelRxSupported, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        proto_tree_add_item(PortInfo_FlitControl_tree, hf_opa_PortInfo_FlitControl_Preemption_MinInitial, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortInfo_FlitControl_tree, hf_opa_PortInfo_FlitControl_Preemption_MinTail, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortInfo_FlitControl_tree, hf_opa_PortInfo_FlitControl_Preemption_LargePacketLimit, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(PortInfo_FlitControl_tree, hf_opa_PortInfo_FlitControl_Preemption_SmallPacketLimit, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(PortInfo_FlitControl_tree, hf_opa_PortInfo_FlitControl_Preemption_MaxSmallPacketLimit, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(PortInfo_FlitControl_tree, hf_opa_PortInfo_FlitControl_Preemption_PreemptionLimit, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        /*PortErrorAction*/
        proto_tree_add_bitmask(PortInfo_header_tree, tvb, local_offset, hf_opa_PortInfo_PortErrorAction,
            ett_portinfo_porterroraction, _PortInfo_PortErrorAction, ENC_BIG_ENDIAN);
        local_offset += 4;

        /* PassThroughControl */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PassThroughControl_EgressPort, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PassThroughControl_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PassThroughControl_DRControl, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_M_KeyLeasePeriod, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        /* BufferUnits */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_BufferUnits_reserved, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_BufferUnits_VL15Init, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_BufferUnits_VL15CreditRate, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_BufferUnits_CreditAck, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_BufferUnits_BufferAlloc, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_MasterSMLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_M_Key, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_SubnetPrefix, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        /*NeighborMTU */
        PortInfo_NeighborMTU_tree = proto_tree_add_subtree(PortInfo_header_tree, tvb, local_offset, 32 / 2,
            ett_portinfo_neighbormtu, NULL, "NeighborMTU");
        for (i = 0; i < (32 / 2); i++) {
            temp_item = proto_tree_add_item(PortInfo_NeighborMTU_tree, hf_opa_PortInfo_VL1, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_item_prepend_text(temp_item, "%3u: ", 2 * i);
            temp_item = proto_tree_add_item(PortInfo_NeighborMTU_tree, hf_opa_PortInfo_VL2, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_item_prepend_text(temp_item, "%3u: ", 2 * i + 1);
        }

        /*XmitQ*/
        PortInfo_XmitQ_tree = proto_tree_add_subtree(PortInfo_header_tree, tvb, local_offset, 32,
            ett_portinfo_xmitq, NULL, "XmitQ");
        for (i = 0; i < 32; i++) {
            temp_item = proto_tree_add_item(PortInfo_XmitQ_tree, hf_opa_PortInfo_XmitQ_VLStallCount, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_item_prepend_text(temp_item, "%3u: ", i);
            temp_item = proto_tree_add_item(PortInfo_XmitQ_tree, hf_opa_PortInfo_XmitQ_HOQLife, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_item_prepend_text(temp_item, "     ");
        }

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_IPAddrIPv6, tvb, local_offset, 16, ENC_NA);
        local_offset += 16;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_IPAddrIPv4, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_NeighborNodeGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        /* Capability Mask Flags */
        proto_tree_add_bitmask(PortInfo_header_tree, tvb, local_offset, hf_opa_PortInfo_CapabilityMask,
            ett_portinfo_capmask, _PortInfo_CapabilityMask, ENC_BIG_ENDIAN);
        local_offset += 4;
        /* End Capability Mask Flags */

        proto_tree_add_item(PortInfo_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        /* CapabilityMask3 */
        proto_tree_add_bitmask(PortInfo_header_tree, tvb, local_offset, hf_opa_PortInfo_CapabilityMask3,
            ett_portinfo_capmask3, _PortInfo_CapabilityMask3, ENC_BIG_ENDIAN);
        local_offset += 2;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_OverallBufferSpace, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        /* Diag Code */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_DiagCode, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        /* End Diag Code */

        /* Replay Depth */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_ReplayDepth_BufferDepth, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_ReplayDepth_WireDepth, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        /* PortNeighborMode */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PortNeighborMode_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PortNeighborMode_MgmtAllowed, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PortNeighborMode_NeighborFWAuthenBypass, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_PortNeighborMode_NeighborNodeType, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        /* MTU */
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_MTU_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_MTU_Cap, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_Resp_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_Resp_TimeValue, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_PortInfo_LocalPortNum, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        proto_tree_add_item(PortInfo_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        /* If Not last block add byte padding */
        if ((++p) < (Port_num + Num_ports)) {
            local_offset += block_pad_len;
        }
    }

    return local_offset;
}

/* Parse PortStateInfo Attribute */
static int parse_PortStateInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *PortStates_header_item;
    proto_tree *PortStates_header_tree;
    unsigned i, Num_ports, Port_num;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    Num_ports = (MAD->AttributeModifier & 0xFF000000) >> 24;
    Port_num = (MAD->AttributeModifier & 0x000000FF);

    for (i = Port_num; i < Port_num + Num_ports; i++) {
        PortStates_header_item = proto_tree_add_item(parentTree, hf_opa_PortStates, tvb, local_offset, 4, ENC_NA);
        proto_item_set_text(PortStates_header_item, "Port Sate Info on Port %d", i);
        PortStates_header_tree = proto_item_add_subtree(PortStates_header_item, ett_portstates);

        proto_tree_add_bitmask_list(PortStates_header_tree, tvb, local_offset, 4,
            _PortStates, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(PortStates_header_tree, hf_opa_PortStates_LinkWidthDowngradeTxActive, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortStates_header_tree, hf_opa_PortStates_LinkWidthDowngradeRxActive, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
    }

    return local_offset;
}

/* Parse P_KeyTable Attribute  */
static int parse_P_KeyTable(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *P_KeyTable_header_item;
    proto_tree *P_KeyTable_header_tree;
    proto_tree *tempBlock_tree;
    proto_item *tempItemLow;
    proto_item *tempItemHigh;
    unsigned i, b, Num_blocks, Block_num/*, Port_num*/;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    if (MAD->MgmtClass == SUBNADMN) {
        Num_blocks = 1;
        Block_num = tvb_get_ntohs(tvb, local_offset - 4);
        /*Port_num = tvb_get_uint8(tvb, local_offset - 2);*/
    } else {
        Num_blocks = (MAD->AttributeModifier & 0xFF000000) >> 24;
        Block_num = (MAD->AttributeModifier & 0x000007FF);
        /*Port_num = (MAD->AttributeModifier & 0x00FF0000) >> 16;*/
    }

    P_KeyTable_header_item = proto_tree_add_item(parentTree, hf_opa_P_KeyTable, tvb, local_offset, 64 * Num_blocks, ENC_NA);
    P_KeyTable_header_tree = proto_item_add_subtree(P_KeyTable_header_item, ett_pkeytable);

    for (b = Block_num; b < Block_num + Num_blocks; b++) {
        tempBlock_tree = proto_tree_add_subtree_format(P_KeyTable_header_tree, tvb, local_offset, 64,
            ett_pkeytable_block, NULL, "PKey Table Block %u", b);

        for (i = 0; i < 32; i++) {
            tempItemHigh = proto_tree_add_item(tempBlock_tree, hf_opa_P_KeyTable_MembershipType, tvb, local_offset, 2, ENC_BIG_ENDIAN);
            tempItemLow = proto_tree_add_item(tempBlock_tree, hf_opa_P_KeyTable_P_KeyBase, tvb, local_offset, 2, ENC_BIG_ENDIAN);
            local_offset += 2;
            proto_item_prepend_text(tempItemHigh, "%3u: ", i);
            proto_item_prepend_text(tempItemLow, "     ");
        }
    }
    return local_offset;
}

/* Parse SLtoSC Mapping Table Attribute */
static int parse_SLtoSCMappingTable(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *SLtoSCMappingTable_header_item;
    proto_tree *SLtoSCMappingTable_header_tree;
    proto_item *tempItemHigh;
    proto_item *tempItemLow;
    unsigned i;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    SLtoSCMappingTable_header_item = proto_tree_add_item(parentTree, hf_opa_SLtoSCMappingTable, tvb, local_offset, 32, ENC_NA);
    SLtoSCMappingTable_header_tree = proto_item_add_subtree(SLtoSCMappingTable_header_item, ett_sltoscmapping);

    for (i = 0; i < 32; i++) {
        tempItemHigh = proto_tree_add_item(SLtoSCMappingTable_header_tree, hf_opa_SLtoSCMappingTable_SLtoSC_HighBits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_item_prepend_text(tempItemHigh, "%3u: ", i);
        tempItemLow = proto_tree_add_item(SLtoSCMappingTable_header_tree, hf_opa_SLtoSCMappingTable_SLtoSC_LowBits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_item_prepend_text(tempItemLow, "     ");
        local_offset += 1;
    }

    return local_offset;
}

/* Parse SCtoSC Mapping Table Attribute  */
static int parse_SCtoSCMappingTable(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int         local_offset = *offset;
    proto_item *SCtoSCMappingTable_header_item;
    proto_tree *SCtoSCMappingTable_header_tree;
    proto_item *tempItemHigh;
    proto_item *tempItemLow;
    proto_tree *tempBlock_tree;
    unsigned    i, b, i_block, e_block, Num_blocks, Block_num;
    bool        B;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    if (MAD->MgmtClass == SUBNADMN) {
        Num_blocks = 1;
        B = false;
        i_block = tvb_get_uint8(tvb, local_offset - 4);
        e_block = tvb_get_uint8(tvb, local_offset - 3);
        Block_num = e_block;
    } else {
        Num_blocks = (MAD->AttributeModifier & 0xFF000000) >> 24;
        B = (bool)((MAD->AttributeModifier & 0x00010000) >> 16);
        i_block = (MAD->AttributeModifier & 0x0000FF00) >> 8;
        e_block = (MAD->AttributeModifier & 0x000000FF);
        Block_num = (B ? i_block : e_block);
    }

    SCtoSCMappingTable_header_item = proto_tree_add_item(parentTree, hf_opa_SCtoSCMappingTable, tvb, local_offset, 32 * Num_blocks, ENC_NA);
    SCtoSCMappingTable_header_tree = proto_item_add_subtree(SCtoSCMappingTable_header_item, ett_sctoscmapping);

    for (b = Block_num; b < (Block_num + Num_blocks); b++) {
        tempBlock_tree = proto_tree_add_subtree_format(SCtoSCMappingTable_header_tree, tvb, local_offset, 32,
            ett_sctoscmapping_block, NULL, "SC to SC Mapping Table for InPort %u, OutPort %u", (B ? b : i_block), (B ? e_block : b));

        for (i = 0; i < 32; i++) {
            tempItemHigh = proto_tree_add_item(tempBlock_tree, hf_opa_SCtoSCMappingTable_SCtoSC_HighBits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_item_prepend_text(tempItemHigh, "%3u: ", i);
            tempItemLow = proto_tree_add_item(tempBlock_tree, hf_opa_SCtoSCMappingTable_SCtoSC_LowBits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_item_prepend_text(tempItemLow, "     ");
            local_offset += 1;
        }
    }

    return local_offset;
}

/* Parse SCtoSL Mapping Table Attribute  */
static int parse_SCtoSLMappingTable(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int         local_offset = *offset;
    proto_item *SCtoSLMappingTable_header_item;
    proto_tree *SCtoSLMappingTable_header_tree;
    proto_item *tempItemHigh;
    proto_item *tempItemLow;
    unsigned    i;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    SCtoSLMappingTable_header_item = proto_tree_add_item(parentTree, hf_opa_SCtoSLMappingTable, tvb, local_offset, 32, ENC_NA);
    SCtoSLMappingTable_header_tree = proto_item_add_subtree(SCtoSLMappingTable_header_item, ett_sctoslmapping);

    for (i = 0; i < 32; i++) {
        tempItemHigh = proto_tree_add_item(SCtoSLMappingTable_header_tree, hf_opa_SCtoSLMappingTable_SCtoSL_HighBits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_item_prepend_text(tempItemHigh, "%3u: ", i);
        tempItemLow = proto_tree_add_item(SCtoSLMappingTable_header_tree, hf_opa_SCtoSLMappingTable_SCtoSL_LowBits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_item_prepend_text(tempItemLow, "     ");
        local_offset += 1;
    }
    return local_offset;
}

/* Parse SCtoVLx Mapping Table Attribute  */
static int parse_SCtoVLxMappingTable(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int         local_offset = *offset;
    proto_item *SCtoVLxMappingTable_header_item;
    proto_tree *SCtoVLxMappingTable_header_tree;
    proto_item *tempItemLow;
    proto_item *tempItemHigh;
    proto_tree *tempBlock_tree;
    unsigned    p, v, Port_num, Num_ports;
    const char *VLx;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    if (MAD->MgmtClass == SUBNADMN) {
        Num_ports = 1;
        Port_num = tvb_get_uint8(tvb, local_offset - 4);
        VLx = val_to_str_const(MAD->AttributeID, SA_SC_VLx, "x");
    } else {
        Num_ports = (MAD->AttributeModifier & 0xFF000000) >> 24;
        Port_num = (MAD->AttributeModifier & 0x000000FF);
        VLx = val_to_str_const(MAD->AttributeID, SM_SC_VLx, "x");
    }

    SCtoVLxMappingTable_header_item = proto_tree_add_item(parentTree, hf_opa_SCtoVLxMappingTable, tvb, local_offset, 32 * Num_ports, ENC_NA);
    proto_item_set_text(SCtoVLxMappingTable_header_item, "SC to VL%s Mapping Table", VLx);
    SCtoVLxMappingTable_header_tree = proto_item_add_subtree(SCtoVLxMappingTable_header_item, ett_sctovlxmappingtable);

    for (p = Port_num; p < (Port_num + Num_ports); p++) {
        tempBlock_tree = proto_tree_add_subtree_format(SCtoVLxMappingTable_header_tree, tvb, local_offset, 32,
            ett_sctovlxmappingtable_block, NULL, "SC to VL%s Mapping Table for Port %u", VLx, p);

        for (v = 0; v < 32; v++) {
            tempItemHigh = proto_tree_add_item(tempBlock_tree, hf_opa_SCtoVLxMappingTable_SCtoVLx_HighBits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_item_prepend_text(tempItemHigh, "%3u: ", v);
            tempItemLow = proto_tree_add_item(tempBlock_tree, hf_opa_SCtoVLxMappingTable_SCtoVLx_LowBits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_item_prepend_text(tempItemLow, "     ");
            local_offset += 1;
        }
    }
    return local_offset;
}

/* Parse VLArbitrationTable Attribute  */
static int parse_VLArbitrationTable(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int         local_offset = *offset;
    proto_item *VLArbitrationTable_header_item;
    proto_tree * VLArbitrationTable_header_tree,*VLArbitrationTable_port_tree;
    proto_item *tempItemHigh;
    proto_item *tempItemLow;
    proto_item *tempItem;
    unsigned    i, p, Section, Num_ports, Port_num;
    const char *TableType;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    if (MAD->MgmtClass == SUBNADMN) {
        Num_ports = 1;
        Section = tvb_get_uint8(tvb, local_offset - 3);
        Port_num = tvb_get_uint8(tvb, local_offset - 4);
    } else {
        Num_ports = (MAD->AttributeModifier & 0xFF000000) >> 24;
        Section = (MAD->AttributeModifier & 0x00FF0000) >> 16;
        Port_num = (MAD->AttributeModifier & 0x000000FF);
    }
    TableType = val_to_str_const(Section, MADAttrModSectionVLarb_short, "Reserved");

    VLArbitrationTable_header_item = proto_tree_add_item(parentTree, hf_opa_VLArbitrationTable, tvb, local_offset, 256 * Num_ports, ENC_NA);
    VLArbitrationTable_header_tree = proto_item_add_subtree(VLArbitrationTable_header_item, ett_vlarbitrationtable);

    for (p = Port_num; p < (Port_num + Num_ports); p++) {
        VLArbitrationTable_port_tree = proto_tree_add_subtree_format(VLArbitrationTable_header_tree, tvb, local_offset, 256,
            ett_vlarbitrationtable_port, NULL, "%s VL Arbitration Table on Port %u", TableType, p);

        if (Section < 3) {
            for (i = 0; i < 128; i++) {
                tempItemHigh = proto_tree_add_item(VLArbitrationTable_port_tree, hf_opa_VLArbitrationTable_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
                proto_item_prepend_text(tempItemHigh, "%3u: ", i);
                tempItemLow = proto_tree_add_item(VLArbitrationTable_port_tree, hf_opa_VLArbitrationTable_VL, tvb, local_offset, 1, ENC_BIG_ENDIAN);
                proto_item_prepend_text(tempItemLow, "     ");
                local_offset += 1;

                tempItem = proto_tree_add_item(VLArbitrationTable_port_tree, hf_opa_VLArbitrationTable_Weight, tvb, local_offset, 1, ENC_BIG_ENDIAN);
                local_offset += 1;
                proto_item_prepend_text(tempItem, "     ");
            }
        } else if (Section == 3) {
            for (i = 0; i < 32; i++) {
                tempItemLow = proto_tree_add_item(VLArbitrationTable_port_tree, hf_opa_VLArbitrationTable_Matrix, tvb, local_offset, 4, ENC_BIG_ENDIAN);
                local_offset += 4;
                proto_item_prepend_text(tempItemLow, "%3u: ", i);
            }
            local_offset += 128;
        } else {
            local_offset += 256;
        }
    }
    return local_offset;
}

/* Parse LinearForwardingTable Attribute  */
static int parse_LinearForwardingTable(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int         local_offset = *offset;
    proto_item *LinearForwardingTable_header_item;
    proto_tree *LinearForwardingTable_header_tree;
    proto_item *tempItemLow;
    proto_tree *tempBlock_tree;
    unsigned    b, i, Block_num, Num_blocks;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    if (MAD->MgmtClass == SUBNADMN) {
        Num_blocks = 1;
        Block_num = tvb_get_ntohl(tvb, local_offset - 4) & 0x0003FFFF;
    } else {
        Num_blocks = (MAD->AttributeModifier & 0xFF000000) >> 24;
        Block_num = (MAD->AttributeModifier & 0x0003FFFF);
    }

    LinearForwardingTable_header_item = proto_tree_add_item(parentTree, hf_opa_LinearForwardingTable, tvb, local_offset, 64 * Num_blocks, ENC_NA);
    LinearForwardingTable_header_tree = proto_item_add_subtree(LinearForwardingTable_header_item, ett_linearforwardingtable);
    for (b = Block_num; b < (Block_num + Num_blocks); b++) {
        tempBlock_tree = proto_tree_add_subtree_format(LinearForwardingTable_header_tree, tvb, local_offset, 64,
            ett_linearforwardingtable_block, NULL, "Linear Forwarding Table Block %u",  b);

        for (i = 0; i < 64; i++) {
            tempItemLow = proto_tree_add_item(tempBlock_tree, hf_opa_LinearForwardingTable_Port, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_item_prepend_text(tempItemLow, "%3u: ", i);
        }
    }
    return local_offset;
}

/* Parse MulticastForwardingTable Attribute  */
static int parse_MulticastForwardingTable(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int         local_offset = *offset;
    proto_item *MulticastForwardingTable_header_item;
    proto_tree *MulticastForwardingTable_header_tree;
    proto_item *tempItem;
    proto_tree *tempBlock_tree;
    unsigned    b, i, Block_num, Num_blocks, Pos;
    const char *Position;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    if (MAD->MgmtClass == SUBNADMN) {
        Num_blocks = 1;
        Pos = 0;
        Block_num = tvb_get_ntohl(tvb, local_offset - 4) & 0x001FFFFF;
    } else {
        Num_blocks = (MAD->AttributeModifier & 0xFF000000) >> 24;
        Pos = (MAD->AttributeModifier & 0x00C00000) >> 22;
        Block_num = (MAD->AttributeModifier & 0x000FFFFF);
    }
    Position = val_to_str_const(Pos, GroupTablePosition, "Unknown");

    MulticastForwardingTable_header_item = proto_tree_add_item(parentTree, hf_opa_MulticastForwardingTable, tvb, local_offset, 64 * Num_blocks, ENC_NA);
    MulticastForwardingTable_header_tree = proto_item_add_subtree(MulticastForwardingTable_header_item, ett_multicastforwardingtable);
    for (b = Block_num; b < (Block_num + Num_blocks); b++) {
        tempBlock_tree = proto_tree_add_subtree_format(MulticastForwardingTable_header_tree, tvb, local_offset, 64,
            ett_multicastforwardingtable_block, NULL, "Multicast Forwarding Table Block %u, Ports %s", b, Position);

        for (i = 0; i < 8; i++) {
            tempItem = proto_tree_add_item(tempBlock_tree, hf_opa_MulticastForwardingTable_PortMask, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_item_prepend_text(tempItem, "%3u: ", i);
        }
    }
    return local_offset;
}

/* Parse PortGroupForwardingTable Attribute  */
static int parse_PortGroupForwardingTable(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int         local_offset = *offset;
    proto_item *PortGroupForwardingTable_header_item;
    proto_tree *PortGroupForwardingTable_header_tree;
    proto_item *tempItemLow;
    proto_tree *tempBlock_tree;
    unsigned    b, i, Block_num, Num_blocks;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    if (MAD->MgmtClass == SUBNADMN) {
        Num_blocks = 1;
        Block_num = tvb_get_ntohl(tvb, local_offset - 4) & 0x0003FFFF;
    } else {
        Num_blocks = (MAD->AttributeModifier & 0xFF000000) >> 24;
        Block_num = (MAD->AttributeModifier & 0x0003FFFF);
    }

    PortGroupForwardingTable_header_item = proto_tree_add_item(parentTree, hf_opa_PortGroupForwardingTable, tvb, local_offset, 64 * Num_blocks, ENC_NA);
    PortGroupForwardingTable_header_tree = proto_item_add_subtree(PortGroupForwardingTable_header_item, ett_portgroupforwardingtable);

    for (b = Block_num; b < (Block_num + Num_blocks); b++) {
        tempBlock_tree = proto_tree_add_subtree_format(PortGroupForwardingTable_header_tree, tvb, local_offset, 64,
            ett_portgroupforwardingtable_block, NULL, "Port Group Forwarding Table Block %u", b);

        for (i = 0; i < 64; i++) {
            tempItemLow = proto_tree_add_item(tempBlock_tree, hf_opa_PortGroupForwardingTable_Port, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_item_prepend_text(tempItemLow, "%3u: ", i);
        }
    }
    return local_offset;
}

/* Parse PortGroupTable Attribute */
static int parse_PortGroupTable(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int         local_offset = *offset;
    proto_item *PortGroupTable_header_item;
    proto_tree *PortGroupTable_header_tree;
    proto_item *tempItemLow;
    proto_tree *tempBlock_tree;
    unsigned    b, i, Block_num, Num_blocks, Pos;
    const char *Position;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    if (MAD->MgmtClass == SUBNADMN) {
        Num_blocks = 1;
        Pos = 0;
        Block_num = tvb_get_uint8(tvb, local_offset - 3) & 0x1F;
    } else {
        Num_blocks = (MAD->AttributeModifier & 0xFF000000) >> 24;
        Pos = (MAD->AttributeModifier & 0x00C00000) >> 22;
        Block_num = (MAD->AttributeModifier & 0x0000001F);
    }
    Position = val_to_str_const(Pos, GroupTablePosition, "Unknown");

    PortGroupTable_header_item = proto_tree_add_item(parentTree, hf_opa_PortGroupTable, tvb, local_offset, 64 * Num_blocks, ENC_NA);
    PortGroupTable_header_tree = proto_item_add_subtree(PortGroupTable_header_item, ett_portgrouptable);

    for (b = Block_num; b < (Block_num + Num_blocks); b++) {
        tempBlock_tree = proto_tree_add_subtree_format(PortGroupTable_header_tree, tvb, local_offset, 64,
            ett_portgrouptable_block, NULL, "Port Group Table Block %u, Ports %s", b, Position);

        for (i = 0; i < 8; i++) {
            tempItemLow = proto_tree_add_item(tempBlock_tree, hf_opa_PortGroupTable_PortMask, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_item_prepend_text(tempItemLow, "%3u: ", i);
        }
    }
    return local_offset;
}

/* Parse SMInfo Attribute */
static int parse_SMInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *SMInfo_header_item;
    proto_tree *SMInfo_header_tree;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    SMInfo_header_item = proto_tree_add_item(parentTree, hf_opa_SMInfo, tvb, local_offset, 26, ENC_NA);
    SMInfo_header_tree = proto_item_add_subtree(SMInfo_header_item, ett_sminfo);

    proto_tree_add_item(SMInfo_header_tree, hf_opa_SMInfo_GUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(SMInfo_header_tree, hf_opa_SMInfo_SM_Key, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(SMInfo_header_tree, hf_opa_SMInfo_ActCount, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SMInfo_header_tree, hf_opa_SMInfo_ElapsedTime, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SMInfo_header_tree, hf_opa_SMInfo_Priority, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(SMInfo_header_tree, hf_opa_SMInfo_ElevatedPriority, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(SMInfo_header_tree, hf_opa_SMInfo_InitialPriority, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(SMInfo_header_tree, hf_opa_SMInfo_SMState, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    return local_offset;
}

/* Parse LedInfo Attribute */
static int parse_LedInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int         local_offset = *offset;
    proto_item *LedInfo_header_item;
    proto_tree *LedInfo_header_tree;
    proto_item *tempItemHigh;
    proto_item *tempItemLow;
    unsigned    p, Port_num, Num_ports;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    Num_ports = (MAD->AttributeModifier & 0xFF000000) >> 24;
    Port_num = (MAD->AttributeModifier & 0x000000FF);

    LedInfo_header_item = proto_tree_add_item(parentTree, hf_opa_LedInfo, tvb, local_offset, 8 * Num_ports, ENC_NA);
    LedInfo_header_tree = proto_item_add_subtree(LedInfo_header_item, ett_ledinfo);

    for (p = Port_num; p < (Port_num + Num_ports); p++) {
        tempItemHigh = proto_tree_add_item(LedInfo_header_tree, hf_opa_LedInfo_LedMask, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        proto_item_prepend_text(tempItemHigh, "Port %3u: ", p);
        tempItemLow = proto_tree_add_item(LedInfo_header_tree, hf_opa_LedInfo_reserved, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        proto_item_prepend_text(tempItemLow, "          ");
        local_offset += 4;
        proto_tree_add_item(LedInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
    }
    return local_offset;
}

/* Parse CableInfo Attribute */
static int parse_CableInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *CableInfo_header_item;
    proto_tree *CableInfo_header_tree;
    proto_item *tempItemLow;
    unsigned i, Port_num, Data_Len, start_addr;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    start_addr = (MAD->AttributeModifier & 0x7FF80000) >> 19;
    Port_num = (MAD->AttributeModifier & 0x000000FF);
    Data_Len = ((MAD->AttributeModifier & 0x0007E000) >> 13) + 1;

    CableInfo_header_item = proto_tree_add_item(parentTree, hf_opa_CableInfo, tvb, local_offset, Data_Len, ENC_NA);
    proto_item_set_text(CableInfo_header_item, "Cable Info on Port %u", Port_num);
    CableInfo_header_tree = proto_item_add_subtree(CableInfo_header_item, ett_cableinfo);

    proto_tree_add_item(CableInfo_header_tree, hf_opa_CableInfo_DataStream, tvb, local_offset, Data_Len, ENC_ASCII | ENC_NA);
    for (i = 0; i < Data_Len; i++) {
        tempItemLow = proto_tree_add_item(CableInfo_header_tree, hf_opa_CableInfo_Data, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_item_prepend_text(tempItemLow, "0x%04X: ", i + start_addr);
        local_offset += 1;
    }
    return local_offset;
}
/* Parse BufferControlTable Attribute */
static int parse_BufferControlTable(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *BCT_header_item;
    proto_tree *BCT_header_tree;
    proto_item *tempItemLow;
    proto_item *tempItemHigh;
    unsigned p, i, Port_num, Num_ports;
    int block_length = 4 + (32 * 4);
    int block_pad_len = 8 - (block_length & 7); /* Padding to add */

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    if (MAD->MgmtClass == SUBNADMN) {
        Num_ports = 1;
        Port_num = tvb_get_uint8(tvb, local_offset - 4);
    } else {
        Num_ports = (MAD->AttributeModifier & 0xFF000000) >> 24;
        Port_num = (MAD->AttributeModifier & 0x000000FF);
    }

    for (p = Port_num; p < (Port_num + Num_ports);) {
        BCT_header_item = proto_tree_add_item(parentTree, hf_opa_BufferControlTable, tvb, local_offset, block_length, ENC_NA);
        proto_item_append_text(BCT_header_item, " Port %u", p);
        BCT_header_tree = proto_item_add_subtree(BCT_header_item, ett_buffercontroltable);

        proto_tree_add_item(BCT_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(BCT_header_tree, hf_opa_BufferControlTable_TxOverallSharedLimit, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        for (i = 0; i < 32; i++) {
            tempItemHigh = proto_tree_add_item(BCT_header_tree, hf_opa_BufferControlTable_TxSharedLimit, tvb, local_offset, 2, ENC_BIG_ENDIAN);
            local_offset += 2;
            tempItemLow = proto_tree_add_item(BCT_header_tree, hf_opa_BufferControlTable_TxDedicatedLimit, tvb, local_offset, 2, ENC_BIG_ENDIAN);
            local_offset += 2;
            proto_item_prepend_text(tempItemHigh, "VL %2u: ", i);
            proto_item_prepend_text(tempItemLow, "       ");
        }

        /* If Not last block add byte padding */
        if ((++p) < (Port_num + Num_ports)) {
            local_offset += block_pad_len;
        }
    }
    return local_offset;
}

/* Parse CongestionInfo Attribute */
static int parse_CongestionInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *CongestionInfo_header_item;
    proto_tree *CongestionInfo_header_tree;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    CongestionInfo_header_item = proto_tree_add_item(parentTree, hf_opa_CongestionInfo, tvb, local_offset, 4, ENC_NA);
    CongestionInfo_header_tree = proto_item_add_subtree(CongestionInfo_header_item, ett_congestioninfo);

    proto_tree_add_item(CongestionInfo_header_tree, hf_opa_CongestionInfo_CongestionInfo, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(CongestionInfo_header_tree, hf_opa_CongestionInfo_ControlTableCap, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(CongestionInfo_header_tree, hf_opa_CongestionInfo_CongestionLogLength, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    return local_offset;
}

/* Parse SwitchCongestionLog Attribute */
static int parse_SwitchCongestionLog(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *SwitchCongestionLog_header_item;
    proto_tree *SwitchCongestionLog_header_tree;
    proto_tree *SwitchCongestionLog_Entry_tree;
    unsigned i;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    SwitchCongestionLog_header_item = proto_tree_add_item(parentTree, hf_opa_SwitchCongestionLog, tvb, local_offset, 40 + (96 * 16), ENC_NA);
    SwitchCongestionLog_header_tree = proto_item_add_subtree(SwitchCongestionLog_header_item, ett_switchcongestionlog);

    proto_tree_add_item(SwitchCongestionLog_header_tree, hf_opa_SwitchCongestionLog_LogType, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(SwitchCongestionLog_header_tree, hf_opa_SwitchCongestionLog_CongestionFlags, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(SwitchCongestionLog_header_tree, hf_opa_SwitchCongestionLog_LogEventsCounter, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(SwitchCongestionLog_header_tree, hf_opa_SwitchCongestionLog_CurrentTimeStamp, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchCongestionLog_header_tree, hf_opa_SwitchCongestionLog_PortMap, tvb, local_offset, 32, ENC_NA);
    local_offset += 32;

    for (i = 0; i < 96; i++) {
        SwitchCongestionLog_Entry_tree = proto_tree_add_subtree_format(SwitchCongestionLog_header_tree, tvb, local_offset, 16,
            ett_switchcongestionlog_entry, NULL, "Switch Congestion Log Entry %u", i);

        proto_tree_add_item(SwitchCongestionLog_Entry_tree, hf_opa_SwitchCongestionLog_SLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SwitchCongestionLog_Entry_tree, hf_opa_SwitchCongestionLog_DLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SwitchCongestionLog_Entry_tree, hf_opa_SwitchCongestionLog_SC, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(SwitchCongestionLog_Entry_tree, hf_opa_SwitchCongestionLog_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(SwitchCongestionLog_Entry_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(SwitchCongestionLog_Entry_tree, hf_opa_SwitchCongestionLog_TimeStamp, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
    }
    return local_offset;
}

/* Parse SwitchCongestionSetting Attribute */
static int parse_SwitchCongestionSetting(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *SwitchCongestionSetting_header_item;
    proto_tree *SwitchCongestionSetting_header_tree;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    SwitchCongestionSetting_header_item = proto_tree_add_item(parentTree, hf_opa_SwitchCongestionSetting, tvb, local_offset, 64, ENC_NA);
    SwitchCongestionSetting_header_tree = proto_item_add_subtree(SwitchCongestionSetting_header_item, ett_switchcongestionsetting);

    proto_tree_add_item(SwitchCongestionSetting_header_tree, hf_opa_SwitchCongestionSetting_Control_Map, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SwitchCongestionSetting_header_tree, hf_opa_SwitchCongestionSetting_Victim_Mask, tvb, local_offset, 32, ENC_NA);
    local_offset += 32;
    proto_tree_add_item(SwitchCongestionSetting_header_tree, hf_opa_SwitchCongestionSetting_Credit_Mask, tvb, local_offset, 32, ENC_NA);
    local_offset += 32;
    proto_tree_add_item(SwitchCongestionSetting_header_tree, hf_opa_SwitchCongestionSetting_Threshold, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(SwitchCongestionSetting_header_tree, hf_opa_SwitchCongestionSetting_reserved1, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(SwitchCongestionSetting_header_tree, hf_opa_SwitchCongestionSetting_Packet_Size, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(SwitchCongestionSetting_header_tree, hf_opa_SwitchCongestionSetting_CS_Threshold, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(SwitchCongestionSetting_header_tree, hf_opa_SwitchCongestionSetting_reserved2, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(SwitchCongestionSetting_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(SwitchCongestionSetting_header_tree, hf_opa_SwitchCongestionSetting_CS_ReturnDelay, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(SwitchCongestionSetting_header_tree, hf_opa_SwitchCongestionSetting_Marking_Rate, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    return local_offset;
}

/* Parse SwitchPortCongestionSetting Attribute */
static int parse_SwitchPortCongestionSetting(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *SwitchPortCongestionSetting_header_item;
    proto_tree *SwitchPortCongestionSetting_header_tree;
    proto_tree *SwitchPortCongestionSetting_Port_tree;
    unsigned p, Num_ports, Port_num;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    if (MAD->MgmtClass == SUBNADMN) {
        Num_ports = 1;
        Port_num = tvb_get_uint8(tvb, local_offset - 4);
    } else {
        Num_ports = (MAD->AttributeModifier & 0xFF000000) >> 24;
        Port_num = (MAD->AttributeModifier & 0x000000FF);
    }

    SwitchPortCongestionSetting_header_item = proto_tree_add_item(parentTree, hf_opa_SwitchPortCongestionSetting, tvb, local_offset, 4 * Num_ports, ENC_NA);
    SwitchPortCongestionSetting_header_tree = proto_item_add_subtree(SwitchPortCongestionSetting_header_item, ett_switchportcongestionsetting);

    for (p = Port_num; p < Port_num + Num_ports; p++) {
        SwitchPortCongestionSetting_Port_tree = proto_tree_add_subtree_format(SwitchPortCongestionSetting_header_tree, tvb, local_offset, 4,
            ett_switchportcongestionsetting_port, NULL, "Switch Port Congestion Setting on Port %u", p);

        proto_tree_add_item(SwitchPortCongestionSetting_Port_tree, hf_opa_SwitchPortCongestionSetting_Valid, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(SwitchPortCongestionSetting_Port_tree, hf_opa_SwitchPortCongestionSetting_Control_Type, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(SwitchPortCongestionSetting_Port_tree, hf_opa_SwitchPortCongestionSetting_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(SwitchPortCongestionSetting_Port_tree, hf_opa_SwitchPortCongestionSetting_Threshold, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(SwitchPortCongestionSetting_Port_tree, hf_opa_SwitchPortCongestionSetting_Packet_Size, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(SwitchPortCongestionSetting_Port_tree, hf_opa_SwitchPortCongestionSetting_Marking_Rate, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
    }

    return local_offset;
}

/* Parse HFICongestionLog Attribute */
static int parse_HFICongestionLog(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *HFICongestionLog_header_item;
    proto_tree *HFICongestionLog_header_tree;
    proto_tree *HFICongestionLog_Entry_tree;
    unsigned i;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    HFICongestionLog_header_item = proto_tree_add_item(parentTree, hf_opa_HFICongestionLog, tvb, local_offset, 12 + (96 * 16), ENC_NA);
    HFICongestionLog_header_tree = proto_item_add_subtree(HFICongestionLog_header_item, ett_hficongestionlog);

    proto_tree_add_item(HFICongestionLog_header_tree, hf_opa_HFICongestionLog_LogType, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(HFICongestionLog_header_tree, hf_opa_HFICongestionLog_CongestionFlags, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(HFICongestionLog_header_tree, hf_opa_HFICongestionLog_ThresholdEventCounter, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(HFICongestionLog_header_tree, hf_opa_HFICongestionLog_CurrentTimeStamp, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(HFICongestionLog_header_tree, hf_opa_HFICongestionLog_ThresholdCongestionEventMap, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    for (i = 0; i < 96; i++) {
        HFICongestionLog_Entry_tree = proto_tree_add_subtree_format(HFICongestionLog_header_tree, tvb, local_offset, 16,
            ett_hficongestionlog_entry, NULL, "HFI Congestion Log Entry %u", i);

        proto_tree_add_item(HFICongestionLog_Entry_tree, hf_opa_HFICongestionLog_Local_QP_CN_Entry, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(HFICongestionLog_Entry_tree, hf_opa_HFICongestionLog_Remote_QP_Number_CN_Entry, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(HFICongestionLog_Entry_tree, hf_opa_HFICongestionLog_SL_CN_Entry, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(HFICongestionLog_Entry_tree, hf_opa_HFICongestionLog_Service_Type_CN_Entry, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(HFICongestionLog_Entry_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        proto_tree_add_item(HFICongestionLog_Entry_tree, hf_opa_HFICongestionLog_Remote_LID_CN_Entry, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(HFICongestionLog_Entry_tree, hf_opa_HFICongestionLog_TimeStamp_CN_Entry, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
    }
    return local_offset;
}

/* Parse HFICongestionSetting Attribute*/
static int parse_HFICongestionSetting(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int i;
    int local_offset = *offset;
    proto_item *HFICongestionSetting_header_item;
    proto_tree *HFICongestionSetting_header_tree;
    proto_item *tempItem;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    HFICongestionSetting_header_item = proto_tree_add_item(parentTree, hf_opa_HFICongestionSetting, tvb, local_offset, 6 + 32 * 6, ENC_NA);
    HFICongestionSetting_header_tree = proto_item_add_subtree(HFICongestionSetting_header_item, ett_hficongestionsetting);

    proto_tree_add_item(HFICongestionSetting_header_tree, hf_opa_HFICongestionSetting_Control_Map, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(HFICongestionSetting_header_tree, hf_opa_HFICongestionSetting_Port_Control, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    for (i = 0; i < 32; i++) {
        tempItem = proto_tree_add_item(HFICongestionSetting_header_tree, hf_opa_HFICongestionSetting_CCTI_Increase, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_item_prepend_text(tempItem, "%3u: ", i);
        local_offset += 1;

        tempItem = proto_tree_add_item(HFICongestionSetting_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_item_prepend_text(tempItem, "     ");
        local_offset += 1;

        tempItem = proto_tree_add_item(HFICongestionSetting_header_tree, hf_opa_HFICongestionSetting_CCTI_Timer, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_item_prepend_text(tempItem, "     ");
        local_offset += 2;

        tempItem = proto_tree_add_item(HFICongestionSetting_header_tree, hf_opa_HFICongestionSetting_TriggerThreshold, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_item_prepend_text(tempItem, "     ");
        local_offset += 1;

        tempItem = proto_tree_add_item(HFICongestionSetting_header_tree, hf_opa_HFICongestionSetting_CCTI_Min, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_item_prepend_text(tempItem, "     ");
        local_offset += 1;
    }

    return local_offset;
}

/* Parse HFICongestionControlTable Attribute*/
static int parse_HFICongestionControlTable(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *HFICongestionControlTable_header_item;
    proto_tree *HFICongestionControlTable_header_tree;
    proto_item *tempItem;
    proto_tree *tempBlock_tree;
    unsigned b, i, Num_blocks, Block_Num;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    if (MAD->MgmtClass == SUBNADMN) {
        Num_blocks = 1;
        Block_Num = tvb_get_ntohs(tvb, local_offset - 4);
    } else { /* SM LID and SM DR */
        Num_blocks = (MAD->AttributeModifier & 0xFF000000) >> 24;
        Block_Num = (MAD->AttributeModifier & 0x000000FF);
    }

    HFICongestionControlTable_header_item = proto_tree_add_item(parentTree, hf_opa_HFICongestionControlTable, tvb, local_offset, 2 + ((64 * 2) * Num_blocks), ENC_NA);
    HFICongestionControlTable_header_tree = proto_item_add_subtree(HFICongestionControlTable_header_item, ett_hficongestioncontroltable);

    proto_tree_add_item(HFICongestionControlTable_header_tree, hf_opa_HFICongestionControlTable_CCTI_Limit, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    for (b = Block_Num; b < Block_Num + Num_blocks; b++) {
        tempBlock_tree = proto_tree_add_subtree_format(HFICongestionControlTable_header_tree, tvb, local_offset, 128,
            ett_hficongestioncontroltable_block, NULL, "HFI Congestion Control Table Block %u", b);

        for (i = 0; i < 64; i++) {
            tempItem = proto_tree_add_item(tempBlock_tree, hf_opa_HFICongestionControlTable_CCT_Shift, tvb, local_offset, 2, ENC_BIG_ENDIAN);
            proto_item_prepend_text(tempItem, "%3u: ", i);
            tempItem = proto_tree_add_item(tempBlock_tree, hf_opa_HFICongestionControlTable_CCT_Multiplier, tvb, local_offset, 2, ENC_BIG_ENDIAN);
            local_offset += 2;
            proto_item_prepend_text(tempItem, "     ");

        }
    }
    return local_offset;
}
/* Call appropriate parsing function */
static bool call_SUBM_Parser(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD, uint16_t AttributeID)
{
    proto_tree *SUBM_Attribute_header_tree = parentTree;
    int local_offset = *offset;

    if (!tvb_bytes_exist(tvb, local_offset, 8))
        return true;

    switch (AttributeID) {
    case SM_ATTR_ID_CLASS_PORT_INFO:
        local_offset = parse_ClassPortInfo(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_NOTICE:
        local_offset = parse_NoticesAndTraps(SUBM_Attribute_header_tree, tvb, offset);
        break;
    case SM_ATTR_ID_NODE_DESCRIPTION:
        local_offset = parse_NodeDescription(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_NODE_INFO:
        local_offset = parse_NodeInfo(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_SWITCH_INFO:
        local_offset = parse_SwitchInfo(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_PORT_INFO:
        local_offset = parse_PortInfo(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_PART_TABLE:
        local_offset = parse_P_KeyTable(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_SL_SC_MAPPING_TABLE:
        local_offset = parse_SLtoSCMappingTable(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_VL_ARBITRATION:
        local_offset = parse_VLArbitrationTable(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_LINEAR_FWD_TABLE:
        local_offset = parse_LinearForwardingTable(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_MCAST_FWD_TABLE:
        local_offset = parse_MulticastForwardingTable(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_SM_INFO:
        local_offset = parse_SMInfo(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_LED_INFO:
        local_offset = parse_LedInfo(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_CABLE_INFO:
        local_offset = parse_CableInfo(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_SC_SC_MAPPING_TABLE:
        local_offset = parse_SCtoSCMappingTable(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_SC_SL_MAPPING_TABLE:
        local_offset = parse_SCtoSLMappingTable(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_SC_VLR_MAPPING_TABLE:
    case SM_ATTR_ID_SC_VLT_MAPPING_TABLE:
    case SM_ATTR_ID_SC_VLNT_MAPPING_TABLE:
        local_offset = parse_SCtoVLxMappingTable(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_PORT_STATE_INFO:
        local_offset = parse_PortStateInfo(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_PORT_GROUP_FWD_TABLE:
        local_offset = parse_PortGroupForwardingTable(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_PORT_GROUP_TABLE:
        local_offset = parse_PortGroupTable(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_BUFFER_CONTROL_TABLE:
        local_offset = parse_BufferControlTable(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_CONGESTION_INFO:
        local_offset = parse_CongestionInfo(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_SWITCH_CONGESTION_LOG:
        local_offset = parse_SwitchCongestionLog(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_SWITCH_CONGESTION_SETTING:
        local_offset = parse_SwitchCongestionSetting(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_SWITCH_PORT_CONGESTION_SETTING:
        local_offset = parse_SwitchPortCongestionSetting(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_HFI_CONGESTION_LOG:
        local_offset = parse_HFICongestionLog(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_HFI_CONGESTION_SETTING:
        local_offset = parse_HFICongestionSetting(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    case SM_ATTR_ID_HFI_CONGESTION_CONTROL_TABLE:
        local_offset = parse_HFICongestionControlTable(SUBM_Attribute_header_tree, tvb, offset, MAD);
        break;
    default:
        return false;
    }
    *offset = local_offset;
    return true;
}

/* Parse Aggregate Attribute */
static int parse_Aggregate(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int i;
    unsigned requestLength;
    int numAttributes;
    int local_offset = *offset;
    int saved_offset;
    uint16_t LocalAttributeID = 0;
    bool AggregatError = false;
    proto_item *Aggregate_header_item;
    proto_item *Aggregate_Length_item;
    proto_item *Aggregate_Error_item;
    proto_tree *Aggregate_header_tree;

    if (!parentTree)
        return *offset;

    numAttributes = MAD->AttributeModifier & 0x000000FF;

    for (i = 0; i < numAttributes; i++) {
        requestLength = (tvb_get_uint8(tvb, local_offset + 3) & 0x7F) * 8;
        if (i == numAttributes - 1 && MAD->Method == METHOD_GET) {
            Aggregate_header_item = proto_tree_add_item(parentTree, hf_opa_Aggregate, tvb, local_offset, 8, ENC_NA);
        } else {
            Aggregate_header_item = proto_tree_add_item(parentTree, hf_opa_Aggregate, tvb, local_offset, requestLength + 8, ENC_NA);
        }
        Aggregate_header_tree = proto_item_add_subtree(Aggregate_header_item, ett_aggregate);

        proto_tree_add_item(Aggregate_header_tree, hf_opa_Aggregate_AttributeID, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        LocalAttributeID = tvb_get_ntohs(tvb, local_offset);
        local_offset += 2;
        proto_item_set_text(Aggregate_header_item, "Aggregate %u: %s", i + 1, val_to_str(LocalAttributeID, SUBM_Attributes, "Unknown Attribute Type! (0x%02x)"));

        AggregatError = (bool)tvb_get_bits(tvb, local_offset * 8, 1, ENC_BIG_ENDIAN);
        Aggregate_Error_item = proto_tree_add_item(Aggregate_header_tree, hf_opa_Aggregate_Error, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        if (AggregatError)
            expert_add_info(NULL, Aggregate_Error_item, &ei_opa_aggregate_error);

        Aggregate_Length_item = proto_tree_add_item(Aggregate_header_tree, hf_opa_Aggregate_RequestLength, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(Aggregate_Length_item, " (%u Bytes)", requestLength);
        local_offset += 2;

        MAD->AttributeModifier = tvb_get_ntohl(tvb, local_offset);
        MAD->AttributeID = LocalAttributeID;
        local_offset = parse_MAD_AttributeModifier(Aggregate_header_tree, tvb, &local_offset, MAD);
        if (i == numAttributes - 1 && MAD->Method == METHOD_GET) {
            /* Do Nothing */
        } else {
            saved_offset = local_offset;
            call_SUBM_Parser(Aggregate_header_tree, tvb, &local_offset, MAD, LocalAttributeID);
            if (local_offset != (saved_offset + (int)requestLength)) {
                local_offset = saved_offset + (int)requestLength;
            }
        }
    }
    return local_offset;
}
/* Parse the attribute from a Subnet Management Packet. */
static bool parse_SUBM_Attribute(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    if (MAD->AttributeID == SM_ATTR_ID_AGGREGATE) {
        *offset = parse_Aggregate(parentTree, tvb, &local_offset, MAD);
        return true;
    } else
        return call_SUBM_Parser(parentTree, tvb, offset, MAD, MAD->AttributeID);
}
/* Parse the Method from the MAD Common Header. */
static void label_SUBM_Method(proto_item *SubMItem, MAD_t *MAD, packet_info *pinfo)
{
    const char *label = val_to_str_const(MAD->Method, SUBM_Methods, "(Unknown SM Method!)");
    proto_item_append_text(SubMItem, " %s", label);
    col_append_str(pinfo->cinfo, COL_INFO, label);
}
/* Parse the Attribute from the MAD Common Header */
static void label_SUBM_Attribute(proto_item *SubMItem, MAD_t *MAD, packet_info *pinfo)
{
    const char *label = val_to_str_const(MAD->AttributeID, SUBM_Attributes, "Attribute (Unknown SM Attribute!)");
    proto_item_append_text(SubMItem, "%s", &label[11]);
    col_append_str(pinfo->cinfo, COL_INFO, &label[11]);
}
/* Parse Subnet Management (LID Routed) */
static void parse_SUBN_LID_ROUTED(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset)
{
    MAD_t       MAD;
    int         local_offset;
    proto_item *SM_LID_header_item;
    proto_tree *SM_LID_header_tree;

    if (!parse_MAD_Common(parentTree, pinfo, tvb, offset, &MAD)) {
        return;
    }
    local_offset = *offset;

    SM_LID_header_item = proto_tree_add_item(parentTree, hf_opa_sm_lid, tvb, local_offset, -1, ENC_NA);
    SM_LID_header_tree = proto_item_add_subtree(SM_LID_header_item, ett_sm_lid);

    proto_tree_add_item(SM_LID_header_tree, hf_opa_sm_m_key, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    label_SUBM_Method(SM_LID_header_item, &MAD, pinfo);
    label_SUBM_Attribute(SM_LID_header_item, &MAD, pinfo);

    *offset = local_offset;
    if (!pref_parse_on_mad_status_error && MAD.Status) {
        local_offset += tvb_captured_length_remaining(tvb, *offset);
    } else if (!parse_SUBM_Attribute(SM_LID_header_tree, tvb, &local_offset, &MAD)) {
        expert_add_info_format(pinfo, NULL, &ei_opa_mad_no_attribute_dissector,
            "Attribute Dissector Not Implemented (0x%x)", MAD.AttributeID);
        local_offset += tvb_captured_length_remaining(tvb, *offset);
    }
    *offset = local_offset;
}

/* Parse Subnet Management (Directed Route) */
static void parse_SUBN_DIRECTED_ROUTE(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset)
{
    MAD_t        MAD;
    int local_offset;
    proto_item *SM_DR_header_item;
    proto_tree *SM_DR_header_tree;

    if (!parse_MAD_Common(parentTree, pinfo, tvb, offset, &MAD)) {
        return;
    }
    local_offset = *offset;

    SM_DR_header_item = proto_tree_add_item(parentTree, hf_opa_sm_dr, tvb, local_offset, -1, ENC_NA);
    SM_DR_header_tree = proto_item_add_subtree(SM_DR_header_item, ett_sm_dr);

    proto_tree_add_item(SM_DR_header_item, hf_opa_sm_m_key, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    label_SUBM_Method(SM_DR_header_item, &MAD, pinfo);
    label_SUBM_Attribute(SM_DR_header_item, &MAD, pinfo);

    proto_tree_add_item(SM_DR_header_tree, hf_opa_sm_dr_slid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SM_DR_header_tree, hf_opa_sm_dr_dlid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(SM_DR_header_tree, hf_opa_sm_dr_initial_path, tvb, local_offset, 64, ENC_NA);
    local_offset += 64;
    proto_tree_add_item(SM_DR_header_tree, hf_opa_sm_dr_return_path, tvb, local_offset, 64, ENC_NA);
    local_offset += 64;
    proto_tree_add_item(SM_DR_header_tree, hf_opa_sm_dr_reserved64, tvb, local_offset, 8, ENC_NA);
    local_offset += 8;
    *offset = local_offset;
    if (!pref_parse_on_mad_status_error && (MAD.Status & 0x7FFF)) {
        local_offset += tvb_captured_length_remaining(tvb, *offset);
    } else if (!parse_SUBM_Attribute(SM_DR_header_tree, tvb, &local_offset, &MAD)) {
        expert_add_info_format(pinfo, NULL, &ei_opa_mad_no_attribute_dissector,
            "Attribute Dissector Not Implemented (0x%x)", MAD.AttributeID);
        local_offset += tvb_captured_length_remaining(tvb, *offset);
        return;
    }
    *offset = local_offset;
}

static int parse_PortInfoRecord(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_tree * PortInfoRecord_LinkDownReason_tree,
        *PortInfoRecord_LinkDownReason_Entry_tree;
    int i;
    local_offset = parse_PortInfo(parentTree, tvb, &local_offset, MAD);

    PortInfoRecord_LinkDownReason_tree = proto_tree_add_subtree(parentTree, tvb, local_offset, 8 * 16,
        ett_portinforecord_linkdownreason, NULL, "Port Info Record LinkDown Reason");
    for (i = 0; i < 8; i++) {
        PortInfoRecord_LinkDownReason_Entry_tree = proto_tree_add_subtree_format(PortInfoRecord_LinkDownReason_tree, tvb, local_offset, 16,
            ett_portinforecord_linkdownreason_entry, NULL, "Link Down Reason Entry %u", i);

        proto_tree_add_item(PortInfoRecord_LinkDownReason_Entry_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_NA);
        local_offset += 4;
        proto_tree_add_item(PortInfoRecord_LinkDownReason_Entry_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_NA);
        local_offset += 2;
        proto_tree_add_item(PortInfoRecord_LinkDownReason_Entry_tree, hf_opa_PortInfoRecord_LinkDownReason_NeighborLinkDownReason, tvb, local_offset, 1, ENC_NA);
        local_offset += 1;
        proto_tree_add_item(PortInfoRecord_LinkDownReason_Entry_tree, hf_opa_PortInfoRecord_LinkDownReason_LinkDownReason, tvb, local_offset, 1, ENC_NA);
        local_offset += 1;
        proto_tree_add_item(PortInfoRecord_LinkDownReason_Entry_tree, hf_opa_PortInfoRecord_LinkDownReason_Timestamp, tvb, local_offset, 8, ENC_NA);
        local_offset += 8;

    }
    return local_offset;
}

/* Parse LinkRecord Attribute*/
static int parse_LinkRecord(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    int local_offset = *offset;
    proto_item *LinkRecord_header_item;
    proto_tree *LinkRecord_header_tree;

    if (!parentTree) {
        return *offset;
    }

    LinkRecord_header_item = proto_tree_add_item(parentTree, hf_opa_LinkRecord, tvb, local_offset, 7, ENC_NA);
    LinkRecord_header_tree = proto_item_add_subtree(LinkRecord_header_item, ett_linkrecord);

    proto_tree_add_item(LinkRecord_header_tree, hf_opa_LinkRecord_ToPort, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(LinkRecord_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(LinkRecord_header_tree, hf_opa_LinkRecord_ToLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    return local_offset;

}

/* Parse ServiceRecord Attribute*/
static int parse_ServiceRecord(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    int local_offset = *offset;
    proto_item *ServiceRecord_header_item;
    proto_tree *ServiceRecord_header_tree;
    proto_item *tempData;

    if (!parentTree) {
        return *offset;
    }

    ServiceRecord_header_item = proto_tree_add_item(parentTree, hf_opa_ServiceRecord, tvb, local_offset, 152, ENC_NA);
    ServiceRecord_header_tree = proto_item_add_subtree(ServiceRecord_header_item, ett_servicerecord);

    proto_tree_add_item(ServiceRecord_header_tree, hf_opa_ServiceRecord_ServiceLease, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(ServiceRecord_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(ServiceRecord_header_tree, hf_opa_ServiceRecord_ServiceKey, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;
    proto_tree_add_item(ServiceRecord_header_tree, hf_opa_ServiceRecord_ServiceName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
    local_offset += 64;

    tempData = proto_tree_add_item(ServiceRecord_header_tree, hf_opa_ServiceRecord_ServiceData, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;
    proto_item_append_text(tempData, "(ServiceData 8.1, 8.16)");
    tempData = proto_tree_add_item(ServiceRecord_header_tree, hf_opa_ServiceRecord_ServiceData, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;
    proto_item_append_text(tempData, "(ServiceData 16.1, 16.8)");
    tempData = proto_tree_add_item(ServiceRecord_header_tree, hf_opa_ServiceRecord_ServiceData, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;
    proto_item_append_text(tempData, "(ServiceData 32.1, 32.4)");
    tempData = proto_tree_add_item(ServiceRecord_header_tree, hf_opa_ServiceRecord_ServiceData, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;
    proto_item_append_text(tempData, "(ServiceData 64.1, 64.2)");

    return local_offset;

}

/* Parse PathRecord Attribute*/
static int parse_PathRecord(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    int local_offset = *offset;
    proto_item * PathRecord_header_item;
    proto_tree * PathRecord_header_tree;

    if (!parentTree) {
        return *offset;
    }

    PathRecord_header_item = proto_tree_add_item(parentTree, hf_opa_PathRecord, tvb, local_offset, 64, ENC_NA);
    PathRecord_header_tree = proto_item_add_subtree(PathRecord_header_item, ett_pathrecord);

    proto_tree_add_item(PathRecord_header_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_NA);
    local_offset += 8;
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_DGID, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_SGID, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_DLID, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_SLID, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_RawTraffic, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_reserved, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_FlowLabel, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_HopLimit, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_TClass, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_Reversible, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_NumbPath, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_P_Key, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_QosType, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_reserved2, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_QosPriority, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_SL, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_MTUSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_MTU, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_RateSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_Rate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_PacketLifeTimeSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_PacketLifeTime, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PathRecord_header_tree, hf_opa_PathRecord_Preference, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PathRecord_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(PathRecord_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    return local_offset;
}

/* Parse MCMemberRecord Attribute*/
static int parse_MCMemberRecord(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    int local_offset = *offset;
    proto_item *MCMemberRecord_header_item;
    proto_tree *MCMemberRecord_header_tree;

    if (!parentTree) {
        return *offset;
    }

    MCMemberRecord_header_item = proto_tree_add_item(parentTree, hf_opa_MCMemberRecord, tvb, local_offset, 24, ENC_NA);
    MCMemberRecord_header_tree = proto_item_add_subtree(MCMemberRecord_header_item, ett_mcmemberrecord);

    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_Q_Key, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_MTUSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_MTU, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_TClass, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_P_Key, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_RateSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_Rate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_PacketLifeTimeSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_PacketLifeTime, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_SL, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_reserved, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_HopLimit, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_Scope, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_reserved2, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_JoinSendOnlyMember, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_JoinNonMember, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_JoinFullMember, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_ProxyJoin, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_reserved3, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(MCMemberRecord_header_tree, hf_opa_MCMemberRecord_MLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    return local_offset;

}

/* Parse TraceRecord Attribute*/
static int parse_TraceRecord(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    int local_offset = *offset;
    proto_item *TraceRecord_header_item;
    proto_tree *TraceRecord_header_tree;

    if (!parentTree) {
        return *offset;
    }

    TraceRecord_header_item = proto_tree_add_item(parentTree, hf_opa_TraceRecord, tvb, local_offset, 40, ENC_NA);
    TraceRecord_header_tree = proto_item_add_subtree(TraceRecord_header_item, ett_tracerecord);

    proto_tree_add_item(TraceRecord_header_tree, hf_opa_TraceRecord_IDGeneration, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(TraceRecord_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(TraceRecord_header_tree, hf_opa_TraceRecord_NodeType, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(TraceRecord_header_tree, hf_opa_TraceRecord_EntryPort, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(TraceRecord_header_tree, hf_opa_TraceRecord_ExitPort, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(TraceRecord_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(TraceRecord_header_tree, hf_opa_TraceRecord_NodeID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(TraceRecord_header_tree, hf_opa_TraceRecord_ChassisID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(TraceRecord_header_tree, hf_opa_TraceRecord_EntryPortID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(TraceRecord_header_tree, hf_opa_TraceRecord_ExitPortID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    return local_offset;
}

/* Parse MultiPathRecord Attribute*/
static int parse_MultiPathRecord_GID(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    int local_offset = *offset;
    proto_item *MultiPathRecord_header_item;
    proto_tree *MultiPathRecord_header_tree;
    proto_item *SDGID;
    uint8_t SGIDCount;
    uint8_t DGIDCount;
    uint32_t i;

    if (!parentTree)
        return *offset;

    SGIDCount = tvb_get_uint8(tvb, local_offset + 14);
    DGIDCount = tvb_get_uint8(tvb, local_offset + 15);
    MultiPathRecord_header_item = proto_tree_add_item(parentTree, hf_opa_MultiPathRecord, tvb, local_offset, 32 + (SGIDCount + DGIDCount) * 16, ENC_NA);
    proto_item_append_text(MultiPathRecord_header_item, " (GID)");
    MultiPathRecord_header_tree = proto_item_add_subtree(MultiPathRecord_header_item, ett_multipathrecord_gid);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_reserved, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_FlowLabel, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_HopLimit, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_TClass, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_Reversible, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_NumbPath, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_P_Key, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_QoSType, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_QoSPriority, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_reserved2, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SL, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_MTUSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_MTU, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_RateSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_Rate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_PacketLifeTimeSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_PacketLifeTime, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_IndependenceSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SGIDScope, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_DGIDScope, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SGIDCount, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_DGIDCount, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_sa_ServiceID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_L2_8B, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_L2_10B, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_L2_9B, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_L2_16B, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_reserved3, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    for (i = 0; i < SGIDCount; i++) {
        SDGID = proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SGID, tvb, local_offset, 16, ENC_NA);
        local_offset += 16;
        proto_item_prepend_text(SDGID, "%u: ", i);
    }
    for (i = 0; i < DGIDCount; i++) {
        SDGID = proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_DGID, tvb, local_offset, 16, ENC_NA);
        local_offset += 16;
        proto_item_prepend_text(SDGID, "%u: ", i);
    }

    return local_offset;
}

/* Parse MultiPathRecord Attribute*/
static int parse_MultiPathRecord_GUID(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    int local_offset = *offset;
    proto_item *MultiPathRecord_header_item;
    proto_tree *MultiPathRecord_header_tree;
    proto_item *SDGUID;
    uint16_t SGUIDCount;
    uint16_t DGUIDCount;
    uint32_t i;

    if (!parentTree)
        return *offset;

    SGUIDCount = tvb_get_ntohs(tvb, local_offset + 14);
    DGUIDCount = tvb_get_ntohs(tvb, local_offset + 16);
    MultiPathRecord_header_item = proto_tree_add_item(parentTree, hf_opa_MultiPathRecord, tvb, local_offset, 40 + (SGUIDCount + DGUIDCount) * 8, ENC_NA);
    proto_item_append_text(MultiPathRecord_header_item, " (GUID)");
    MultiPathRecord_header_tree = proto_item_add_subtree(MultiPathRecord_header_item, ett_multipathrecord_guid);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_reserved, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_FlowLabel, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_HopLimit, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_TClass, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_Reversible, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_NumbPath, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_P_Key, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_QoSType, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_QoSPriority, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_reserved2, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SL, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_MTUSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_MTU, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_RateSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_Rate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_PacketLifeTimeSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_PacketLifeTime, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_IndependenceSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SGUIDScope, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_DGUIDScope, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SGUIDCount, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_DGUIDCount, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_L2_8B, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_L2_10B, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_L2_9B, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_L2_16B, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_reserved3, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_ServiceID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SubnetPrefix, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    for (i = 0; i < SGUIDCount; i++) {
        SDGUID = proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SGUID, tvb, local_offset, 8, ENC_NA);
        local_offset += 8;
        proto_item_prepend_text(SDGUID, "%u: ", i);
    }
    for (i = 0; i < DGUIDCount; i++) {
        SDGUID = proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_DGUID, tvb, local_offset, 8, ENC_NA);
        local_offset += 8;
        proto_item_prepend_text(SDGUID, "%u: ", i);
    }
    return local_offset;
}

/* Parse MultiPathRecord Attribute*/
static int parse_MultiPathRecord_lid(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    int local_offset = *offset;
    proto_item *MultiPathRecord_header_item;
    proto_tree *MultiPathRecord_header_tree;
    proto_item *SDLID;
    uint16_t SLIDCount;
    uint16_t DLIDCount;
    uint32_t i;

    if (!parentTree)
        return *offset;

    SLIDCount = tvb_get_ntohs(tvb, local_offset + 14);
    DLIDCount = tvb_get_ntohs(tvb, local_offset + 16);
    MultiPathRecord_header_item = proto_tree_add_item(parentTree, hf_opa_MultiPathRecord, tvb, local_offset, 40 + (SLIDCount + DLIDCount) * 4, ENC_NA);
    MultiPathRecord_header_tree = proto_item_add_subtree(MultiPathRecord_header_item, ett_multipathrecord_lid);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_reserved, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_FlowLabel, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_HopLimit, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_TClass, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_Reversible, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_NumbPath, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_P_Key, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_QoSType, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_QoSPriority, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_reserved2, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SL, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_MTUSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_MTU, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_RateSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_Rate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_PacketLifeTimeSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_PacketLifeTime, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_IndependenceSelector, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SGUIDScope, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_DGUIDScope, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SLIDCount, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_DLIDCount, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_L2_8B, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_L2_10B, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_L2_9B, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_L2_16B, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_reserved3, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_ServiceID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SubnetPrefix, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    for (i = 0; i < SLIDCount; i++) {
        SDLID = proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_SLID, tvb, local_offset, 4, ENC_NA);
        local_offset += 4;
        proto_item_prepend_text(SDLID, "%u: ", i);
    }
    for (i = 0; i < DLIDCount; i++) {
        SDLID = proto_tree_add_item(MultiPathRecord_header_tree, hf_opa_MultiPathRecord_DLID, tvb, local_offset, 4, ENC_NA);
        local_offset += 4;
        proto_item_prepend_text(SDLID, "%u: ", i);
    }
    return local_offset;
}

/* Parse CableInfoRecord Attribute*/
static int parse_CableInfoRecord(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    int local_offset = *offset;
    proto_item *CableInfoRecord_header_item;
    proto_tree *CableInfoRecord_header_tree;

    if (!parentTree)
        return *offset;

    CableInfoRecord_header_item = proto_tree_add_item(parentTree, hf_opa_CableInfoRecord, tvb, local_offset, 72, ENC_NA);
    CableInfoRecord_header_tree = proto_item_add_subtree(CableInfoRecord_header_item, ett_cableinforecord);

    proto_tree_add_item(CableInfoRecord_header_tree, hf_opa_CableInfoRecord_Lid, tvb, local_offset, 4, ENC_NA);
    local_offset += 4;
    proto_tree_add_item(CableInfoRecord_header_tree, hf_opa_CableInfoRecord_Port, tvb, local_offset, 1, ENC_NA);
    local_offset += 1;
    proto_tree_add_item(CableInfoRecord_header_tree, hf_opa_CableInfoRecord_Length, tvb, local_offset, 1, ENC_NA);
    proto_tree_add_item(CableInfoRecord_header_tree, hf_opa_CableInfoRecord_reserved, tvb, local_offset, 1, ENC_NA);
    local_offset += 1;
    proto_tree_add_item(CableInfoRecord_header_tree, hf_opa_CableInfoRecord_Address, tvb, local_offset, 2, ENC_NA);
    proto_tree_add_item(CableInfoRecord_header_tree, hf_opa_CableInfoRecord_PortType, tvb, local_offset, 2, ENC_NA);
    local_offset += 2;
    proto_tree_add_item(CableInfoRecord_header_tree, hf_opa_CableInfoRecord_Data, tvb, local_offset, 64, ENC_NA);
    local_offset += 64;

    return local_offset;
}

/* Parse ServiceAssociationRecord Attribute*/
static int parse_ServiceAssociationRecord(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    int local_offset = *offset;
    /* proto_item *ServiceAssociationRecord_header_item; */
    proto_tree *ServiceAssociationRecord_header_tree;

    if (!parentTree) {
        return *offset;
    }

    /* ServiceAssociationRecord_header_item = proto_tree_add_item(parentTree, hf_opa_sapa, tvb, local_offset, 80, ENC_NA); */
    /* proto_item_set_text(ServiceAssociationRecord_header_item, "%s", "ServiceAssociationRecord"); */
    ServiceAssociationRecord_header_tree = parentTree; /* proto_item_add_subtree(ServiceAssociationRecord_header_item, ett_serviceassocrecord); */

    proto_tree_add_item(ServiceAssociationRecord_header_tree, hf_opa_ServiceAssociationRecord_ServiceKey, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;
    proto_tree_add_item(ServiceAssociationRecord_header_tree, hf_opa_ServiceAssociationRecord_ServiceName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
    local_offset += 64;

    return local_offset;
}

static int parse_VFInfoRecord(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    int local_offset = *offset;
    proto_item *VFInfoRecord_header_item;
    proto_tree *VFInfoRecord_header_tree;

    if (!parentTree)
        return *offset;

    VFInfoRecord_header_item = proto_tree_add_item(parentTree, hf_opa_VFInfoRecord, tvb, local_offset, 128, ENC_NA);
    VFInfoRecord_header_tree = proto_item_add_subtree(VFInfoRecord_header_item, ett_vfinforecord);

    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_vfIndex, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_pKey, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_vfName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
    local_offset += 64;
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_sa_ServiceID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_MGID, tvb, local_offset, 16, ENC_NA);
    local_offset += 16;

    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_SelectFlags, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_SL, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_MTUSpecified, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_reserved2, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_MTU, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_RateSpecified, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_reserved4, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_Rate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_PktLifeSpecified, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_reserved5, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_PktLifeTimeInc, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_OptionFlags, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_BandwidthPercent, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_reserved6, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_Priority, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_RoutingSLs, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(VFInfoRecord_header_tree, hf_opa_VFInfoRecord_reserved7, tvb, local_offset, 24, ENC_NA);
    local_offset += 24;

    return local_offset;
}
static int parse_QuarantinedNodeRecord(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *QuarantinedNodeRecord_header_item;
    proto_tree *QuarantinedNodeRecord_header_tree;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    QuarantinedNodeRecord_header_item = proto_tree_add_item(parentTree, hf_opa_QuarantinedNodeRecord, tvb, local_offset, 213, ENC_NA);
    QuarantinedNodeRecord_header_tree = proto_item_add_subtree(QuarantinedNodeRecord_header_item, ett_quarantinednoderecord);

    proto_tree_add_item(QuarantinedNodeRecord_header_tree, hf_opa_QuarantinedNodeRecord_TrustedLid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(QuarantinedNodeRecord_header_tree, hf_opa_QuarantinedNodeRecord_TrustedPortNum, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(QuarantinedNodeRecord_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;
    proto_tree_add_item(QuarantinedNodeRecord_header_tree, hf_opa_QuarantinedNodeRecord_TrustedNodeGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(QuarantinedNodeRecord_header_tree, hf_opa_QuarantinedNodeRecord_TrustedNeighborNodeGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    local_offset = parse_NodeDescription(QuarantinedNodeRecord_header_tree, tvb, &local_offset, MAD);
    local_offset = parse_NodeInfo(QuarantinedNodeRecord_header_tree, tvb, &local_offset, MAD);

    proto_tree_add_item(QuarantinedNodeRecord_header_tree, hf_opa_QuarantinedNodeRecord_QuarantineReasons, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(QuarantinedNodeRecord_header_tree, hf_opa_QuarantinedNodeRecord_ExpectedNodeDesc, tvb, local_offset, 64, ENC_NA);
    local_offset += 64;
    proto_tree_add_item(QuarantinedNodeRecord_header_tree, hf_opa_QuarantinedNodeRecord_ExpectedNodeGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(QuarantinedNodeRecord_header_tree, hf_opa_QuarantinedNodeRecord_ExpectedPortGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    return local_offset;
}
static int parse_FabricInfoRecord(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;
    proto_item *FabricInfoRecord_header_item;
    proto_tree *FabricInfoRecord_header_tree;

    if (!parentTree || MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE)
        return *offset;

    FabricInfoRecord_header_item = proto_tree_add_item(parentTree, hf_opa_FabricInfoRecord, tvb, local_offset, 132, ENC_NA);
    FabricInfoRecord_header_tree = proto_item_add_subtree(FabricInfoRecord_header_item, ett_fabricinforecord);

    proto_tree_add_item(FabricInfoRecord_header_tree, hf_opa_FabricInfoRecord_NumHFIs, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(FabricInfoRecord_header_tree, hf_opa_FabricInfoRecord_NumSwitches, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(FabricInfoRecord_header_tree, hf_opa_FabricInfoRecord_NumInternalHFILinks, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(FabricInfoRecord_header_tree, hf_opa_FabricInfoRecord_NumExternalHFILinks, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(FabricInfoRecord_header_tree, hf_opa_FabricInfoRecord_NumInternalISLs, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(FabricInfoRecord_header_tree, hf_opa_FabricInfoRecord_NumExternalISLs, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(FabricInfoRecord_header_tree, hf_opa_FabricInfoRecord_NumDegradedHFILinks, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(FabricInfoRecord_header_tree, hf_opa_FabricInfoRecord_NumDegradedISLs, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(FabricInfoRecord_header_tree, hf_opa_FabricInfoRecord_NumOmittedHFILinks, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(FabricInfoRecord_header_tree, hf_opa_FabricInfoRecord_NumOmittedISLs, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(FabricInfoRecord_header_tree, hf_opa_FabricInfoRecord_Reserved, tvb, local_offset, 92, ENC_NA);
    local_offset += 92;

    return local_offset;
}
/* Parse RID Field from Subnet Administration Packets. */
static void parse_RID(proto_tree *SA_header_tree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;

    if (!SA_header_tree)
        return;

    switch (MAD->AttributeID) {
    case SA_ATTR_ID_CLASS_PORT_INFO:
        break;
    case SA_ATTR_ID_NOTICE:
        break;
    case SA_ATTR_ID_NODE_RECORD: /* NodeRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        break;
    case SA_ATTR_ID_PORTINFO_RECORD: /* PortInfoRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_EndportLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_PortNum, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(SA_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        break;
    case SA_ATTR_ID_SC_MAPTBL_RECORD: /* SCMappingTableRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_InputPortNum, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_OutputPortNum, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        break;
    case SA_ATTR_ID_SL2SC_MAPTBL_RECORD:
    case SA_ATTR_ID_SC2SL_MAPTBL_RECORD:
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        break;
    case SA_ATTR_ID_SC_VLNT_MAPTBL_RECORD:
    case SA_ATTR_ID_SC_VLT_MAPTBL_RECORD:
    case SA_ATTR_ID_SC_VLR_MAPTBL_RECORD:
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Port, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        break;
    case SA_ATTR_ID_SWITCHINFO_RECORD: /* SwitchInfoRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        break;
    case SA_ATTR_ID_LINEAR_FWDTBL_RECORD: /* LinearForwardingTableRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_reserved14, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(SA_header_tree, hf_opa_sa_BlockNum_18b, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        break;
    case SA_ATTR_ID_MCAST_FWDTBL_RECORD: /* MulticastForwardingTableRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Position, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(SA_header_tree, hf_opa_sa_reserved9, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(SA_header_tree, hf_opa_sa_BlockNum_21b, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        break;
    case SA_ATTR_ID_VLARBTABLE_RECORD: /*VLArbitrationTableRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_OutputPortNum, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_BlockNum_8b, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        break;
    case SA_ATTR_ID_SMINFO_RECORD: /* SMInfoRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        break;
    case SA_ATTR_ID_P_KEY_TABLE_RECORD: /* P_KeyTableRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_BlockNum_16b, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_PortNum, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        break;
    case SA_ATTR_ID_INFORM_INFO_RECORD: /* InformInfoRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_SubscriberLID, tvb, local_offset, 4, ENC_NA);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Enum, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        break;
    case SA_ATTR_ID_LINK_RECORD: /* LinkRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_FromLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_FromPort, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        break;
    case SA_ATTR_ID_SERVICE_RECORD: /* ServiceRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_ServiceID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_ServiceLID, tvb, local_offset, 4, ENC_NA);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_ServiceP_Key, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(SA_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_ServiceGID, tvb, local_offset, 16, ENC_NA);
        local_offset += 16;
        break;
    case SA_ATTR_ID_PATH_RECORD: /* PathRecord */
        break;
    case SA_ATTR_ID_MCMEMBER_RECORD: /* MCMemberRecord */
        proto_tree_add_item(SA_header_tree, hf_opa_sa_MGID, tvb, local_offset, 16, ENC_NA);
        local_offset += 16;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_PortGID, tvb, local_offset, 16, ENC_NA);
        local_offset += 16;
        break;
    case SA_ATTR_ID_TRACE_RECORD:
        break;
    case SA_ATTR_ID_MULTIPATH_GID_RECORD:
        break;
    case SA_ATTR_ID_MULTIPATH_GUID_RECORD:
        break;
    case SA_ATTR_ID_MULTIPATH_LID_RECORD:
        break;
    case SA_ATTR_ID_CABLE_INFO_RECORD:
        break;
    case SA_ATTR_ID_VF_INFO_RECORD:
        break;
    case SA_ATTR_ID_PORTGROUP_TABLE_RECORD:
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Position_16b, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(SA_header_tree, hf_opa_sa_reserved9_16b, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(SA_header_tree, hf_opa_sa_BlockNum_5b, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        break;
    case SA_ATTR_ID_QUARANTINED_NODE_RECORD:
        break;
    case SA_ATTR_ID_CONGESTION_INFO_RECORD:
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        break;
    case SA_ATTR_ID_SWITCH_CONG_RECORD:
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        break;
    case SA_ATTR_ID_SWITCH_PORT_CONG_RECORD:
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Port, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        break;
    case SA_ATTR_ID_HFI_CONG_RECORD:
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        break;
    case SA_ATTR_ID_HFI_CONG_CTRL_RECORD:
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_BlockNum_16b, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        break;
    case SA_ATTR_ID_BUFF_CTRL_TAB_RECORD:
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(SA_header_tree, hf_opa_sa_Port, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        break;
    case SA_ATTR_ID_FABRICINFO_RECORD:
        break;
    default:
        break;
    }
    *offset = local_offset;
}
/* Parse the attribute from a Subnet Administration Packet. */
static bool parse_SUBA_Attribute(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD, RMPP_t *RMPP, SA_HEADER_t *SA_HEADER)
{
    proto_tree *SUBA_Attribute_header_tree = parentTree;
    int local_offset = *offset;

    if (RMPP->Type == RMPP_ACK || SA_HEADER->AttributeOffset == 0 || (RMPP->PayloadLength <= 20 && RMPP->Type == RMPP_DATA) ||
        (!pref_attempt_rmpp_defragment && RMPP->Type == RMPP_DATA && RMPP->SegmentNumber != 1))
        return true;

    /* Skim off the RID fields should they be present */
    parse_RID(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);

    /* Parse the rest of the attributes */
    switch (MAD->AttributeID) {
    case SA_ATTR_ID_CLASS_PORT_INFO: /* (ClassPortInfo) */
        local_offset = parse_ClassPortInfo(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_NOTICE: /* (Notice) */
        local_offset = parse_NoticesAndTraps(SUBA_Attribute_header_tree, tvb, &local_offset);
        break;
    case SA_ATTR_ID_INFORM_INFO: /* (InformInfo) */
        local_offset = parse_InformInfo(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_NODE_RECORD: /* (NodeRecord) */
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        local_offset = parse_NodeInfo(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        local_offset = parse_NodeDescription(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_PORTINFO_RECORD: /* (PortInfoRecord) */
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        local_offset = parse_PortInfoRecord(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_SL2SC_MAPTBL_RECORD:
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        local_offset = parse_SLtoSCMappingTable(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_SC_MAPTBL_RECORD:
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        local_offset = parse_SCtoSCMappingTable(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_SC2SL_MAPTBL_RECORD:
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        local_offset = parse_SCtoSLMappingTable(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_SC_VLNT_MAPTBL_RECORD:
    case SA_ATTR_ID_SC_VLT_MAPTBL_RECORD:
    case SA_ATTR_ID_SC_VLR_MAPTBL_RECORD:
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        local_offset = parse_SCtoVLxMappingTable(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_SWITCHINFO_RECORD: /* (SwitchInfoRecord) */
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        local_offset = parse_SwitchInfo(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_LINEAR_FWDTBL_RECORD: /*(LinearForwardingTableRecord) */
        local_offset = parse_LinearForwardingTable(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_MCAST_FWDTBL_RECORD: /* (MulticastForwardingTableRecord) */
        local_offset = parse_MulticastForwardingTable(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_VLARBTABLE_RECORD: /* (VLArbitrationTableRecord) */
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        local_offset = parse_VLArbitrationTable(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_SMINFO_RECORD: /* (SMInfoRecord) */
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        local_offset = parse_SMInfo(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_P_KEY_TABLE_RECORD: /* (P_KeyTableRecord) */
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        local_offset = parse_P_KeyTable(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_INFORM_INFO_RECORD: /*(InformInfoRecord) */
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        local_offset = parse_InformInfo(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_LINK_RECORD: /* (LinkRecord) */
        local_offset = parse_LinkRecord(SUBA_Attribute_header_tree, tvb, &local_offset);
        break;
    case SA_ATTR_ID_SERVICE_RECORD: /*(ServiceRecord) */
        local_offset = parse_ServiceRecord(SUBA_Attribute_header_tree, tvb, &local_offset);
        break;
    case SA_ATTR_ID_PATH_RECORD: /* (PathRecord) */
        local_offset = parse_PathRecord(SUBA_Attribute_header_tree, tvb, &local_offset);
        break;
    case SA_ATTR_ID_MCMEMBER_RECORD: /* (MCMemberRecord) */
        local_offset = parse_MCMemberRecord(SUBA_Attribute_header_tree, tvb, &local_offset);
        break;
    case SA_ATTR_ID_TRACE_RECORD: /* (TraceRecord) */
        local_offset = parse_TraceRecord(SUBA_Attribute_header_tree, tvb, &local_offset);
        break;
    case SA_ATTR_ID_MULTIPATH_GID_RECORD: /* (MultiPathRecord) */
        local_offset = parse_MultiPathRecord_GID(SUBA_Attribute_header_tree, tvb, &local_offset);
        break;
    case SA_ATTR_ID_MULTIPATH_GUID_RECORD:
        local_offset = parse_MultiPathRecord_GUID(SUBA_Attribute_header_tree, tvb, &local_offset);
        break;
    case SA_ATTR_ID_MULTIPATH_LID_RECORD:
        local_offset = parse_MultiPathRecord_lid(SUBA_Attribute_header_tree, tvb, &local_offset);
        break;
    case SA_ATTR_ID_SERVICEASSOCIATION_RECORD: /* (ServiceAssociationRecord) */
        local_offset = parse_ServiceAssociationRecord(SUBA_Attribute_header_tree, tvb, &local_offset);
        break;
    case SA_ATTR_ID_PGROUP_FWDTBL_RECORD:
        local_offset = parse_PortGroupForwardingTable(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_CABLE_INFO_RECORD: /* (CableInfoRecord) */
        local_offset = parse_CableInfoRecord(SUBA_Attribute_header_tree, tvb, &local_offset);
        break;
    case SA_ATTR_ID_VF_INFO_RECORD:
        local_offset = parse_VFInfoRecord(SUBA_Attribute_header_tree, tvb, &local_offset);
        break;
    case SA_ATTR_ID_PORTGROUP_TABLE_RECORD:
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        local_offset = parse_PortGroupTable(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_QUARANTINED_NODE_RECORD:
        local_offset = parse_QuarantinedNodeRecord(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_CONGESTION_INFO_RECORD:
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        local_offset = parse_CongestionInfo(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_SWITCH_CONG_RECORD:
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        local_offset = parse_SwitchCongestionSetting(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_SWITCH_PORT_CONG_RECORD:
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        local_offset = parse_SwitchPortCongestionSetting(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_HFI_CONG_RECORD:
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        local_offset = parse_HFICongestionSetting(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_HFI_CONG_CTRL_RECORD:
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        local_offset = parse_HFICongestionControlTable(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_BUFF_CTRL_TAB_RECORD:
        proto_tree_add_item(SUBA_Attribute_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        local_offset = parse_BufferControlTable(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    case SA_ATTR_ID_FABRICINFO_RECORD:
        local_offset = parse_FabricInfoRecord(SUBA_Attribute_header_tree, tvb, &local_offset, MAD);
        break;
    default:
        return false;
    }

    *offset = local_offset;
    return true;
}
/* Parse the SA Method from the MAD Common Header. */
static void label_SUBA_Method(proto_item *SubAItem, MAD_t *MAD, packet_info *pinfo)
{
    const char *label = val_to_str_const(MAD->Method, SUBA_Methods, "(Unknown SA Method!)");
    proto_item_append_text(SubAItem, " %s", label);
    col_append_str(pinfo->cinfo, COL_INFO, label);
}
/* Parse the SA Attribute from the MAD Common Header */
static void label_SUBA_Attribute(proto_item *SubAItem, MAD_t *MAD, packet_info *pinfo)
{
    const char *label = val_to_str_const(MAD->AttributeID, SUBA_Attributes, "Attribute (Unknown SA Attribute!)");
    proto_item_append_text(SubAItem, "%s", &label[11]);
    col_append_str(pinfo->cinfo, COL_INFO, &label[11]);
}
/* Parse the SA_HEADER
* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static bool parse_SA_HEADER(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset, MAD_t *MAD, SA_HEADER_t *SA_HEADER)
{
    int local_offset = *offset;
    proto_item *SA_HEADER_header_item;
    proto_tree *SA_HEADER_header_tree;

    SA_HEADER_header_item = proto_tree_add_item(parentTree, hf_opa_sa, tvb, local_offset, 20, ENC_NA);
    SA_HEADER_header_tree = proto_item_add_subtree(SA_HEADER_header_item, ett_sa);

    SA_HEADER->SM_Key = tvb_get_ntoh64(tvb, local_offset);
    proto_tree_add_item(SA_HEADER_header_tree, hf_opa_sa_sm_key, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    SA_HEADER->AttributeOffset = tvb_get_ntohs(tvb, local_offset);
    proto_tree_add_item(SA_HEADER_header_tree, hf_opa_sa_attribute_offset, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    SA_HEADER->Reserved = tvb_get_ntohs(tvb, local_offset);
    proto_tree_add_item(SA_HEADER_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    SA_HEADER->ComponentMask = tvb_get_ntoh64(tvb, local_offset);
    proto_tree_add_item(SA_HEADER_header_tree, hf_opa_sa_component_mask, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    label_SUBA_Method(SA_HEADER_header_item, MAD, pinfo);
    label_SUBA_Attribute(SA_HEADER_header_item, MAD, pinfo);

    *offset = local_offset;
    return true;
}
/* Parse Subnet Administration */
static void parse_SUBNADMN(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset)
{
    MAD_t       MAD;
    RMPP_t      RMPP;
    SA_HEADER_t SA_HEADER;
    fragment_head *frag_head = NULL;
    tvbuff_t *old_tvb = NULL;
    int old_offset;
    unsigned r, records, length;
    proto_tree *SA_record_tree;
    const char *label;
    bool parent_was_opa_fe = proto_is_frame_protocol(pinfo->layers, "opa.fe");

    if (!parse_MAD_Common(parentTree, pinfo, tvb, offset, &MAD)) {
        return;
    }
    if (!parse_RMPP(parentTree, pinfo, tvb, offset, &RMPP)) {
        return;
    }
    if (!parse_SA_HEADER(parentTree, pinfo, tvb, offset, &MAD, &SA_HEADER)) {
        return;
    }
    if ((!pref_parse_on_mad_status_error && MAD.Status) ||
        RMPP.Type == RMPP_ACK) {
        *offset += tvb_captured_length_remaining(tvb, *offset);
        return;
    }

    if (!parent_was_opa_fe && pref_attempt_rmpp_defragment
        && (RMPP.resptime_flags & RMPP_FLAG_ACTIVE_MASK) && (RMPP.Type == RMPP_DATA)
        && !((RMPP.resptime_flags & RMPP_FLAG_FIRST_MASK)
            && (RMPP.resptime_flags & RMPP_FLAG_LAST_MASK))) {

        frag_head = fragment_add_seq_check(&opa_mad_rmpp_reassembly_table,
            tvb, *offset, pinfo, (uint32_t)MAD.TransactionID, NULL, RMPP.SegmentNumber - 1,
            ((RMPP.resptime_flags & RMPP_FLAG_LAST_MASK) ?
                RMPP.PayloadLength - 20 : (uint32_t)tvb_captured_length_remaining(tvb, *offset)),
            (bool)!(RMPP.resptime_flags & RMPP_FLAG_LAST_MASK));
        /* Back up tvb & offset */
        old_tvb = tvb;
        old_offset = *offset;
        /* Create new tvb from reassembled data */
        tvb = process_reassembled_data(old_tvb, old_offset, pinfo, "Reassembled RMPP Packet",
            frag_head, &opa_rmpp_frag_items, NULL, parentTree);
        if (tvb == NULL) {
            return;
        }
        *offset = 0;
    }

    length = tvb_captured_length_remaining(tvb, *offset);
    records = (SA_HEADER.AttributeOffset ? length / (SA_HEADER.AttributeOffset * 8) : 0);
    for (r = 0; r < records; r++) {
        old_offset = *offset;
        label = val_to_str_const(MAD.AttributeID, SUBA_Attributes, "Attribute (Unknown SA Attribute!)");
        SA_record_tree = proto_tree_add_subtree_format(parentTree, tvb, old_offset,
            (SA_HEADER.AttributeOffset * 8), ett_rmpp_sa_record, NULL, "%s Record %u: ", label, r);

        if (!parse_SUBA_Attribute(SA_record_tree, tvb, offset, &MAD, &RMPP, &SA_HEADER)) {
            expert_add_info_format(pinfo, NULL, &ei_opa_mad_no_attribute_dissector,
                "Attribute Dissector Not Implemented (0x%x)", MAD.AttributeID);
            *offset += tvb_captured_length_remaining(tvb, *offset);
            return;
        }
        *offset = old_offset + (SA_HEADER.AttributeOffset * 8);
    }
    return;
}

/* Parse PortStatus MAD from the Performance management class. */
static int parse_PortStatus(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    proto_item *PortStatus_header_item;
    proto_tree *PortStatus_header_tree;
    proto_tree *PortStatus_VL_tree;
    int local_offset = *offset;
    uint32_t VLSelectMask;
    unsigned i, VLs;
    uint32_t vlSelMskTmp;

    if (!parentTree)
        return *offset;

    VLSelectMask = tvb_get_ntohl(tvb, local_offset + 4);
    for (i = 0, VLs = 0, vlSelMskTmp = VLSelectMask; vlSelMskTmp && i < 32; i++, vlSelMskTmp >>= 1) {
        VLs = VLs + (vlSelMskTmp & 0x1);
    }

    if (MAD->Method == METHOD_GET) { /* Get() */
        PortStatus_header_item = proto_tree_add_item(parentTree, hf_opa_PortStatus, tvb, local_offset, 8, ENC_NA);
    } else if (MAD->Method == METHOD_GET_RESP) {  /* GetResp(): */
        PortStatus_header_item = proto_tree_add_item(parentTree, hf_opa_PortStatus, tvb, local_offset, 208 + VLs * 112, ENC_NA);
    } else {
        return *offset;
    }
    PortStatus_header_tree = proto_item_add_subtree(PortStatus_header_item, ett_portstatus);

    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;

    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_VLSelectMask, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    if (MAD->Method == METHOD_GET)
        return local_offset;

    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortXmitData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortRcvData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortXmitPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortRcvPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortMulticastXmitPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortMulticastRcvPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortXmitWait, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_SwPortCongestion, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortRcvFECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortRcvBECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortXmitTimeCong, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortXmitWastedBW, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortXmitWaitData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortRcvBubble, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortMarkFECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortRcvConstraintErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortRcvSwitchRelayErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortXmitDiscards, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortXmitConstraintErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortRcvRemotePhysicalErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_LocalLinkIntegrityErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_PortRcvErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_ExcessiveBufferOverruns, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_FMConfigErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_LinkErrorRecovery, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_LinkDowned, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_UncorrectableErrors, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(PortStatus_header_tree, hf_opa_PortStatus_LinkQualityIndicator, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;

    proto_tree_add_item(PortStatus_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(PortStatus_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    for (i = 0, vlSelMskTmp = VLSelectMask; vlSelMskTmp && i < 32; i++, vlSelMskTmp >>= 1) {
        if (vlSelMskTmp & 0x1) {
            PortStatus_VL_tree = proto_tree_add_subtree_format(PortStatus_header_tree, tvb, local_offset, 112,
                ett_portstatus_vl, NULL, "VL %u", i);

            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLXmitData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLRcvData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLXmitPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLRcvPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLXmitWait, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;

            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_SwPortVLCongestion, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLRcvFECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLRcvBECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLXmitTimeCong, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLXmitWastedBW, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;

            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLXmitWaitData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLRcvBubble, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLMarkFECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortStatus_VL_tree, hf_opa_PortStatus_PortVLXmitDiscards, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
        }
    }
    return local_offset;
}

/* Parse ClearPortStatus MAD from the Performance management class.*/
static int parse_ClearPortStatus(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    proto_item *ClearPortStatus_header_item;
    proto_tree *ClearPortStatus_header_tree;
    proto_item *ClearPortStatus_PortSelectMask_item;
    int local_offset = *offset;

    if (!parentTree)
        return *offset;

    if (MAD->Method == METHOD_SET || MAD->Method == METHOD_GET_RESP) { /* Only Set()/GetResp() is supported. */
        ClearPortStatus_header_item = proto_tree_add_item(parentTree, hf_opa_ClearPortStatus, tvb, local_offset, 36, ENC_NA);
    } else
        return *offset;

    ClearPortStatus_header_tree = proto_item_add_subtree(ClearPortStatus_header_item, ett_clearportstatus);

    ClearPortStatus_PortSelectMask_item = proto_tree_add_item(ClearPortStatus_header_tree, hf_opa_ClearPortStatus_PortSelectMask, tvb, local_offset, 32, ENC_NA);
    proto_item_append_text(ClearPortStatus_PortSelectMask_item, ": %s",
        opa_format_port_select_mask(tvb, local_offset, NULL, NULL));
    local_offset += 32;

    proto_tree_add_bitmask(ClearPortStatus_header_tree, tvb, local_offset,
        hf_opa_ClearPortStatus_CounterSelectMask, ett_clearportstatus_counterselectmask,
        _ClearPortStatus_CounterSelectMask, ENC_BIG_ENDIAN);
    local_offset += 4;

    return local_offset;
}

/* Parse DataPortCounters MAD from the Performance management class.*/
static int parse_DataPortCounters(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    proto_item *DataPortCounters_header_item;
    proto_item *DataPortCounters_PortSelectMask_item;
    proto_tree *DataPortCounters_header_tree;
    proto_tree *DataPortCounters_Port_tree;
    proto_tree *DataPortCounters_VL_tree;

    int local_offset = *offset;
    uint32_t VLSelectMask, vlSelMskTmp;
    unsigned VLs, i, p;
    unsigned Num_Ports = (MAD->AttributeModifier >> 24) & 0xFF;

    if (!parentTree)
        return *offset;

    VLSelectMask = tvb_get_ntohl(tvb, local_offset + 32);
    for (i = 0, VLs = 0, vlSelMskTmp = VLSelectMask; vlSelMskTmp && i < 32; i++, vlSelMskTmp >>= 1) {
        VLs += (vlSelMskTmp & 0x1);
    }

    if (MAD->Method == METHOD_GET) {  /* Get() */
        DataPortCounters_header_item = proto_tree_add_item(parentTree, hf_opa_DataPortCounters, tvb, local_offset, 40, ENC_NA);
    } else if (MAD->Method == METHOD_GET_RESP) { /* GetResp(): */
        DataPortCounters_header_item = proto_tree_add_item(parentTree, hf_opa_DataPortCounters, tvb, local_offset, 40 + Num_Ports * (136 + VLs * 104), ENC_NA);
    } else { /* Set() */
        return *offset;
    }
    DataPortCounters_header_tree = proto_item_add_subtree(DataPortCounters_header_item, ett_dataportcounters);

    DataPortCounters_PortSelectMask_item = proto_tree_add_item(DataPortCounters_header_tree, hf_opa_DataPortCounters_PortSelectMask, tvb, local_offset, 32, ENC_NA);
    proto_item_append_text(DataPortCounters_PortSelectMask_item, ": %s",
        opa_format_port_select_mask(tvb, local_offset, NULL, NULL));
    local_offset += 32;

    proto_tree_add_item(DataPortCounters_header_tree, hf_opa_DataPortCounters_VLSelectMask, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(DataPortCounters_header_tree, hf_opa_DataPortCounters_resolution_reserved, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(DataPortCounters_header_tree, hf_opa_DataPortCounters_LocalLinkIntegrityResolution, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(DataPortCounters_header_tree, hf_opa_DataPortCounters_LinkErrorRecoveryResolution, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    if (MAD->Method == METHOD_GET)
        return local_offset;

    for (p = 0; p < Num_Ports; p++) {
        DataPortCounters_Port_tree = proto_tree_add_subtree_format(DataPortCounters_header_tree, tvb, local_offset, (1 + 3 + 4 + (8 * 16) + VLs * (8 * 13)),
            ett_dataportcounters_port, NULL, "Port %u", tvb_get_uint8(tvb, local_offset));

        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_lqi_reserved, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_LinkQualityIndicator, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortXmitData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortRcvData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortXmitPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortRcvPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortMulticastXmitPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortMulticastRcvPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortXmitWait, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_SwPortCongestion, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortRcvFECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortRcvBECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortXmitTimeCong, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortXmitWastedBW, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortXmitWaitData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortRcvBubble, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortMarkFECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(DataPortCounters_Port_tree, hf_opa_DataPortCounters_PortErrorCounterSummary, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        for (i = 0, vlSelMskTmp = VLSelectMask; vlSelMskTmp && i < 32; i++, vlSelMskTmp >>= 1) {
            if (vlSelMskTmp & 0x1) {
                DataPortCounters_VL_tree = proto_tree_add_subtree_format(DataPortCounters_Port_tree, tvb, local_offset, 8 * 13,
                    ett_dataportcounters_vl, NULL, "VL %u", i);

                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_PortVLXmitData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;
                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_PortVLRcvData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;
                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_PortVLXmitPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;
                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_PortVLRcvPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;
                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_PortVLXmitWait, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;

                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_SwPortVLCongestion, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;
                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_PortVLRcvFECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;
                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_PortVLRcvBECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;
                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_PortVLXmitTimeCong, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;
                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_PortVLXmitWastedBW, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;

                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_PortVLXmitWaitData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;
                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_PortVLRcvBubble, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;
                proto_tree_add_item(DataPortCounters_VL_tree, hf_opa_DataPortCounters_PortVLMarkFECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;
            }
        }
    }
    return local_offset;
}

/* Parse ErrorPortCounters MAD from the Performance management class.*/
static int parse_ErrorPortCounters(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    proto_item *ErrorPortCounters_header_item;
    proto_item *ErrorPortCounters_PortSelectMask_item;
    proto_item *ErrorPortCounters_VL_item;
    proto_tree *ErrorPortCounters_header_tree;
    proto_tree *ErrorPortCounters_Port_tree;

    int local_offset = *offset;
    uint32_t VLSelectMask, vlSelMskTmp;
    unsigned VLs, i, p;
    unsigned Num_Ports = (MAD->AttributeModifier & 0xFF000000) >> 24;

    if (!parentTree)
        return *offset;

    VLSelectMask = tvb_get_ntohl(tvb, local_offset + 32);
    for (i = 0, VLs = 0, vlSelMskTmp = VLSelectMask; vlSelMskTmp && i < 32; i++, vlSelMskTmp >>= 1) {
        VLs += (vlSelMskTmp & 0x1);
    }

    if (MAD->Method == METHOD_GET) { /* Get() */
        ErrorPortCounters_header_item = proto_tree_add_item(parentTree, hf_opa_ErrorPortCounters, tvb, local_offset, 40, ENC_NA);
    } else if (MAD->Method == METHOD_GET_RESP) { /* GetResp(): */
        ErrorPortCounters_header_item = proto_tree_add_item(parentTree, hf_opa_ErrorPortCounters, tvb, local_offset, 40 + Num_Ports * (96 + VLs * 8), ENC_NA);
    } else { /* Set() */
        return *offset;
    }
    ErrorPortCounters_header_tree = proto_item_add_subtree(ErrorPortCounters_header_item, ett_errorportcounters);

    ErrorPortCounters_PortSelectMask_item = proto_tree_add_item(ErrorPortCounters_header_tree, hf_opa_ErrorPortCounters_PortSelectMask, tvb, local_offset, 32, ENC_NA);
    proto_item_append_text(ErrorPortCounters_PortSelectMask_item, ": %s",
        opa_format_port_select_mask(tvb, local_offset, NULL, NULL));
    local_offset += 32;

    proto_tree_add_item(ErrorPortCounters_header_tree, hf_opa_ErrorPortCounters_VLSelectMask, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(ErrorPortCounters_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    if (MAD->Method == METHOD_GET)
        return local_offset;

    for (p = 0; p < Num_Ports; p++) {
        ErrorPortCounters_Port_tree = proto_tree_add_subtree_format(ErrorPortCounters_header_tree, tvb, local_offset, (96 + VLs * 8),
            ett_errorportcounters_port, NULL, "Port %u", tvb_get_uint8(tvb, local_offset));

        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_PortNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_PortRcvConstraintErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_PortRcvSwitchRelayErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_PortXmitDiscards, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_PortXmitConstraintErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_PortRcvRemotePhysicalErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_LocalLinkIntegrityErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_PortRcvErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_ExcessiveBufferOverruns, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_FMConfigErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_LinkErrorRecovery, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_LinkDowned, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_UncorrectableErrors, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        for (i = 0, vlSelMskTmp = VLSelectMask; vlSelMskTmp && i < 32; i++, vlSelMskTmp >>= 1) {
            if (vlSelMskTmp & 0x1) {
                ErrorPortCounters_VL_item = proto_tree_add_item(ErrorPortCounters_Port_tree, hf_opa_ErrorPortCounters_PortVLXmitDiscards, tvb, local_offset, 8, ENC_BIG_ENDIAN);
                local_offset += 8;
                proto_item_prepend_text(ErrorPortCounters_VL_item, "%3u: ", i);
            }
        }
    }
    return local_offset;
}

/* Parse ErrorPortInfo MAD from the Performance management class.*/
static int parse_ErrorPortInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    proto_item *ErrorPortInfo_header_item;
    proto_item *ErrorPortInfo_PortSelectMask_item;

    proto_tree *ErrorPortInfo_header_tree;
    proto_tree *ErrorPortInfo_Port_tree;
    proto_tree * PortRcvErrorInfo_tree,
        *ExcessiveBufferOverrunInfo_tree,
        *PortXmitConstraintErrorInfo_tree,
        *PortRcvConstraintErrorInfo_tree,
        *PortRcvSwitchRelayErrorInfo_tree,
        *UncorrectableErrorInfo_tree,
        *FMConfigErrorInfo_tree;

    int local_offset = *offset;
    unsigned p, ErrorCode;
    unsigned Num_Ports = (MAD->AttributeModifier & 0xFF000000) >> 24;

    if (!parentTree)
        return *offset;

    if (MAD->Method == METHOD_GET_RESP) {
        ErrorPortInfo_header_item = proto_tree_add_item(parentTree, hf_opa_ErrorPortInfo, tvb, local_offset, -1, ENC_NA);
    } else if (MAD->Method == METHOD_SET) {
        ErrorPortInfo_header_item = proto_tree_add_item(parentTree, hf_opa_ErrorPortInfo, tvb, local_offset, 40, ENC_NA);
    } else { /* GET */
        ErrorPortInfo_header_item = proto_tree_add_item(parentTree, hf_opa_ErrorPortInfo, tvb, local_offset, 32, ENC_NA);
    }
    ErrorPortInfo_header_tree = proto_item_add_subtree(ErrorPortInfo_header_item, ett_errorportinfo);

    ErrorPortInfo_PortSelectMask_item = proto_tree_add_item(ErrorPortInfo_header_tree, hf_opa_ErrorPortInfo_PortSelectMask, tvb, local_offset, 32, ENC_NA);
    proto_item_append_text(ErrorPortInfo_PortSelectMask_item, ": %s",
        opa_format_port_select_mask(tvb, local_offset, NULL, NULL));
    local_offset += 32;

    if (MAD->Method == METHOD_GET)
        return local_offset;
    /* ErrorInfoSelectMask */
    proto_tree_add_bitmask_list(ErrorPortInfo_header_tree, tvb, local_offset, 4, _ErrorPortInfo_ErrorInfoSelectMask, ENC_BIG_ENDIAN);
    local_offset += 4;

    if (MAD->Method == METHOD_SET
        /* GetResp packet from a Set operation will contain 1 zeroed port struct */
        || (MAD->Method == METHOD_GET_RESP && Num_Ports > 1
            && tvb_reported_length_remaining(tvb, local_offset) < (72 * 2)))
        return local_offset;

    proto_tree_add_item(ErrorPortInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    for (p = 0; p < Num_Ports; p++) {
        ErrorPortInfo_Port_tree = proto_tree_add_subtree_format(ErrorPortInfo_header_tree, tvb, local_offset, 72,
            ett_errorportinfoport, NULL, "Port %u", tvb_get_uint8(tvb, local_offset));

        proto_tree_add_item(ErrorPortInfo_Port_tree, hf_opa_ErrorPortInfo_PortNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(ErrorPortInfo_Port_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(ErrorPortInfo_Port_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        /* PortRcvErrorInfo */
        PortRcvErrorInfo_tree = proto_tree_add_subtree(ErrorPortInfo_Port_tree, tvb, local_offset, 24,
            ett_errorportinfo_portrcverrorinfo, NULL, "PortRcv Error Info");

        proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvErrorInfo_Status, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvErrorInfo_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvErrorInfo_ErrorCode, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        ErrorCode = tvb_get_uint8(tvb, local_offset) & 0x0F;
        local_offset += 1;
        if (ErrorCode >= 1 && ErrorCode <= 12) {
            proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvErrorInfo_PacketFlit1, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvErrorInfo_PacketFlit2, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvErrorInfo_Flit1Bits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvErrorInfo_Flit2Bits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvErrorInfo_reserved2, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
        } else if (ErrorCode == 13) {
            proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvErrorInfo_PacketBytes, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvErrorInfo_FlitBits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvErrorInfo_reserved3, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
        } else {
            proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvErrorInfo_reserved4, tvb, local_offset, 17, ENC_NA);
            local_offset += 17;
        }
        proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortRcvErrorInfo_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        /* ExcessiveBufferOverrunErrorInfo */
        ExcessiveBufferOverrunInfo_tree = proto_tree_add_subtree(ErrorPortInfo_Port_tree, tvb, local_offset, 8,
            ett_errorportinfo_excessivebufferoverruninfo, NULL, "ExcessiveBufferOverrun Error Info");

        proto_tree_add_item(ExcessiveBufferOverrunInfo_tree, hf_opa_ErrorPortInfo_ExcessiveBufferOverrunErrorInfo_Status, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ExcessiveBufferOverrunInfo_tree, hf_opa_ErrorPortInfo_ExcessiveBufferOverrunErrorInfo_SC, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ExcessiveBufferOverrunInfo_tree, hf_opa_ErrorPortInfo_ExcessiveBufferOverrunErrorInfo_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(ExcessiveBufferOverrunInfo_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        proto_tree_add_item(ExcessiveBufferOverrunInfo_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        /* PortXmitConstraintErrorInfo */
        PortXmitConstraintErrorInfo_tree = proto_tree_add_subtree(ErrorPortInfo_Port_tree, tvb, local_offset, 8,
            ett_errorportinfo_portxmitconstrainterrorinfo, NULL, "PortXmitConstraint Error Info");

        proto_tree_add_item(PortXmitConstraintErrorInfo_tree, hf_opa_ErrorPortInfo_PortXmitConstraintErrorInfo_Status, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortXmitConstraintErrorInfo_tree, hf_opa_ErrorPortInfo_PortXmitConstraintErrorInfo_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(PortXmitConstraintErrorInfo_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(PortXmitConstraintErrorInfo_tree, hf_opa_ErrorPortInfo_PortXmitConstraintErrorInfo_P_Key, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortXmitConstraintErrorInfo_tree, hf_opa_ErrorPortInfo_PortXmitConstraintErrorInfo_SLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        /* PortRcvConstraintErrorInfo */
        PortRcvConstraintErrorInfo_tree = proto_tree_add_subtree(ErrorPortInfo_Port_tree, tvb, local_offset, 8,
            ett_errorportinfo_portrcvconstrainterrorinfo, NULL, "PortRcvConstraint Error Info");

        proto_tree_add_item(PortRcvConstraintErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvConstraintErrorInfo_Status, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortRcvConstraintErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvConstraintErrorInfo_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(PortRcvConstraintErrorInfo_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(PortRcvConstraintErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvConstraintErrorInfo_P_Key, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(PortRcvConstraintErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvConstraintErrorInfo_SLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        /* PortRcvSwitchRelayErrorInfo */
        PortRcvSwitchRelayErrorInfo_tree = proto_tree_add_subtree(ErrorPortInfo_Port_tree, tvb, local_offset, 8,
            ett_errorportinfo_portrcvswitchrelayerrorinfo, NULL, "PortRcvSwitchRelay Error Info");

        proto_tree_add_item(PortRcvSwitchRelayErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_Status, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortRcvSwitchRelayErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(PortRcvSwitchRelayErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_ErrorCode, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        ErrorCode = tvb_get_uint8(tvb, local_offset) & 0x0F;
        local_offset += 1;
        proto_tree_add_item(PortRcvSwitchRelayErrorInfo_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
        local_offset += 3;
        switch (ErrorCode) {
        case 0:
            proto_tree_add_item(PortRcvSwitchRelayErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_DLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            local_offset += 4;
            break;
        case 2:
            proto_tree_add_item(PortRcvSwitchRelayErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_EgressPortNum, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(PortRcvSwitchRelayErrorInfo_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
            local_offset += 3;
            break;
        case 3:
            proto_tree_add_item(PortRcvSwitchRelayErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_EgressPortNum, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(PortRcvSwitchRelayErrorInfo_tree, hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_SC, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(PortRcvSwitchRelayErrorInfo_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
            local_offset += 2;
            break;
        default:
            proto_tree_add_item(PortRcvSwitchRelayErrorInfo_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            local_offset += 4;
            break;
        }

        /* UncorrectableErrorInfo */
        UncorrectableErrorInfo_tree = proto_tree_add_subtree(ErrorPortInfo_Port_tree, tvb, local_offset, 2,
            ett_errorportinfo_uncorrectableerrorinfo, NULL, "Uncorrectable Error Info");

        proto_tree_add_item(UncorrectableErrorInfo_tree, hf_opa_ErrorPortInfo_UncorrectableErrorInfo_Status, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(UncorrectableErrorInfo_tree, hf_opa_ErrorPortInfo_UncorrectableErrorInfo_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(UncorrectableErrorInfo_tree, hf_opa_ErrorPortInfo_UncorrectableErrorInfo_ErrorCode, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(UncorrectableErrorInfo_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        /* FMConfigErrorInfo */
        FMConfigErrorInfo_tree = proto_tree_add_subtree(ErrorPortInfo_Port_tree, tvb, local_offset, 6,
            ett_errorportinfo_fmconfigerrorinfo, NULL, "FMConfig Error Info");

        proto_tree_add_item(FMConfigErrorInfo_tree, hf_opa_ErrorPortInfo_FMConfigErrorInfo_Status, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(FMConfigErrorInfo_tree, hf_opa_ErrorPortInfo_FMConfigErrorInfo_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(FMConfigErrorInfo_tree, hf_opa_ErrorPortInfo_FMConfigErrorInfo_ErrorCode, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        ErrorCode = tvb_get_uint8(tvb, local_offset) & 0x0F;
        local_offset += 1;
        switch (ErrorCode) {
        case 0:
        case 1:
        case 2:
            proto_tree_add_item(FMConfigErrorInfo_tree, hf_opa_ErrorPortInfo_FMConfigErrorInfo_Distance, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            break;
        case 3:
        case 4:
        case 5:
            proto_tree_add_item(FMConfigErrorInfo_tree, hf_opa_ErrorPortInfo_FMConfigErrorInfo_VL, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            break;
        case 6:
            proto_tree_add_item(FMConfigErrorInfo_tree, hf_opa_ErrorPortInfo_FMConfigErrorInfo_BadFlitBits, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            break;
        case 7:
            proto_tree_add_item(FMConfigErrorInfo_tree, hf_opa_ErrorPortInfo_FMConfigErrorInfo_SC, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            break;
        default:
            proto_tree_add_item(FMConfigErrorInfo_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            break;
        }

        proto_tree_add_item(FMConfigErrorInfo_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
    }
    return local_offset;
}
static bool parse_PM_Attribute(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    int local_offset = *offset;

    switch (MAD->AttributeID) {
        /* Mgmt */
    case PA_ATTR_ID_CLASS_PORTINFO:
        local_offset = parse_ClassPortInfo(parentTree, tvb, &local_offset, MAD);
        break;
    case PM_ATTR_ID_PORT_STATUS:
        local_offset = parse_PortStatus(parentTree, tvb, &local_offset, MAD);
        break;
    case PM_ATTR_ID_CLEAR_PORT_STATUS:
        local_offset = parse_ClearPortStatus(parentTree, tvb, &local_offset, MAD);
        break;
    case PM_ATTR_ID_DATA_PORT_COUNTERS:
        local_offset = parse_DataPortCounters(parentTree, tvb, &local_offset, MAD);
        break;
    case PM_ATTR_ID_ERROR_PORT_COUNTERS:
        local_offset = parse_ErrorPortCounters(parentTree, tvb, &local_offset, MAD);
        break;
    case PM_ATTR_ID_ERROR_INFO:
        local_offset = parse_ErrorPortInfo(parentTree, tvb, &local_offset, MAD);
        break;
    default:
        return false;
    }

    *offset = local_offset;
    return true;
}

/* Parse the Method from the MAD Common Header. */
static void label_PM_Method(proto_item *PMItem, MAD_t *MAD, packet_info *pinfo)
{
    const char *label = val_to_str_const(MAD->Method, PM_Methods, "(Unknown Perf Method!)");
    proto_item_append_text(PMItem, " %s", label);
    col_append_str(pinfo->cinfo, COL_INFO, label);
}

/* Parse the Attribute from the MAD Common Header */
static void label_PM_Attribute(proto_item *PMItem, MAD_t *MAD, packet_info *pinfo)
{
    const char *label = val_to_str_const(MAD->AttributeID, PM_Attributes, "Attribute (Unknown Perf Attribute!)");
    proto_item_append_text(PMItem, "%s", &label[11]);
    col_append_str(pinfo->cinfo, COL_INFO, &label[11]);
}
/* Parse Performance Management */
static void parse_PERF(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset)
{
    MAD_t        MAD;
    proto_item *PM_header_item;
    proto_tree *PM_header_tree;

    if (!parse_MAD_Common(parentTree, pinfo, tvb, offset, &MAD)) {
        return;
    }

    PM_header_item = proto_tree_add_item(parentTree, hf_opa_pm, tvb, *offset, -1, ENC_NA);
    PM_header_tree = proto_item_add_subtree(PM_header_item, ett_pm);

    label_PM_Method(PM_header_item, &MAD, pinfo);
    label_PM_Attribute(PM_header_item, &MAD, pinfo);

    if (!pref_parse_on_mad_status_error && MAD.Status) {
        *offset += tvb_captured_length_remaining(tvb, *offset);
        return;
    }
    if (!parse_PM_Attribute(PM_header_tree, tvb, offset, &MAD)) {
        expert_add_info_format(pinfo, NULL, &ei_opa_mad_no_attribute_dissector,
            "Attribute Dissector Not Implemented (0x%x)", MAD.AttributeID);
        *offset += tvb_captured_length_remaining(tvb, *offset);
        return;
    }
}

/* Parse Image MAD from the Performance Admin class. */
static int parse_Image(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    proto_tree *Image_header_tree = parentTree;

    int local_offset = *offset;

    if (!parentTree)
        return *offset;

    /* ImageID */
    proto_tree_add_item(Image_header_tree, hf_opa_ImageID_imageNumber, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(Image_header_tree, hf_opa_ImageID_imageOffset, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(Image_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    /* End ImageID */

    return local_offset;
}
/* Parse GetGroupList MAD from the Performance Admin class.*/
static int parse_GetGroupList(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD, RMPP_t *RMPP, PA_HEADER_t *PA_HEADER)
{
    proto_item *GetGroupList_GroupName_item;
    proto_tree *GetGroupList_header_tree;
    proto_item *GetGroupList_header_item;
    int local_offset = *offset;
    unsigned i;

    unsigned length = tvb_captured_length_remaining(tvb, local_offset);
    unsigned records = (PA_HEADER->AttributeOffset ? length / (PA_HEADER->AttributeOffset * 8) : 0);

    if (!parentTree || RMPP->Type != RMPP_DATA ||
        (MAD->Method != METHOD_GET_RESP && MAD->Method != METHOD_GETTABLE_RESP)) {
        return *offset;
    }

    GetGroupList_header_item = proto_tree_add_item(parentTree, hf_opa_GetGroupList, tvb, local_offset, length, ENC_NA);
    GetGroupList_header_tree = proto_item_add_subtree(GetGroupList_header_item, ett_getgrouplist);
    proto_tree_add_none_format(GetGroupList_header_tree, hf_opa_GetGroupList, tvb, local_offset, length, "Number of Groups: %u", records);

    for (i = 0; i < records; i++) {
        GetGroupList_GroupName_item = proto_tree_add_item(GetGroupList_header_tree, hf_opa_GetGroupList_groupName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
        local_offset += 64;
        proto_item_prepend_text(GetGroupList_GroupName_item, "%3u: ", i + 1);
    }
    return local_offset;
}

/* Parse GetGroupInfo MAD from the Performance Admin class.*/
static int parse_GetGroupInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD, RMPP_t *RMPP, PA_HEADER_t *PA_HEADER)
{
    proto_tree *GetGroupInfo_header_tree;
    proto_tree *GetGroupInfo_header_item;

    proto_tree *GetGroupInfo_Util_Stats_tree;
    proto_item *GetGroupInfo_Util_Stats_Buckets_item;
    proto_tree *GetGroupInfo_Util_Stats_Buckets_tree;
    proto_item *GetGroupInfo_Util_Stats_Bucket_item;

    proto_tree *GetGroupInfo_Error_Summary_tree;
    proto_tree *GetGroupInfo_Error_Integrity_Buckets_tree;
    proto_tree *GetGroupInfo_Error_Congestion_Buckets_tree;
    proto_tree *GetGroupInfo_Error_SmaCongestion_Buckets_tree;
    proto_tree *GetGroupInfo_Error_Bubble_Buckets_tree;
    proto_tree *GetGroupInfo_Error_Security_Buckets_tree;
    proto_tree *GetGroupInfo_Error_Routing_Buckets_tree;
    proto_item *GetGroupInfo_Error_Stats_Integrity_Buckets_item;
    proto_item *GetGroupInfo_Error_Stats_Congestion_Buckets_item;
    proto_item *GetGroupInfo_Error_Stats_SmaCongestion_Buckets_item;
    proto_item *GetGroupInfo_Error_Stats_Bubble_Buckets_item;
    proto_item *GetGroupInfo_Error_Stats_Security_Buckets_item;
    proto_item *GetGroupInfo_Error_Stats_Routing_Buckets_item;
    proto_item *GetGroupInfo_Error_Stats_Bucket_item;

    int local_offset = *offset;
    unsigned i, r;

    unsigned length = tvb_captured_length_remaining(tvb, local_offset);
    unsigned records = (PA_HEADER->AttributeOffset ? length / (PA_HEADER->AttributeOffset * 8) : 0);

    unsigned util = 100 / PM_UTIL_BUCKETS;     /* 0%+ 10%+ 20%+ ... 80%+ 90%+ */
    unsigned err = 100 / (PM_ERR_BUCKETS - 1); /* 0%+ 25%+ 50%+ 75%+ 100%+ */

    if (!parentTree || (!pref_attempt_rmpp_defragment && RMPP->Type == RMPP_DATA && RMPP->SegmentNumber != 1))
        return *offset;

    if (MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE) {
        GetGroupInfo_header_item = proto_tree_add_item(parentTree, hf_opa_GetGroupInfo, tvb, local_offset, 64 + 16, ENC_NA);
        proto_item_set_text(GetGroupInfo_header_item, "GroupInfo for %s", tvb_get_string_enc(wmem_file_scope(), tvb, local_offset, 64, ENC_ASCII));
        GetGroupInfo_header_tree = proto_item_add_subtree(GetGroupInfo_header_item, ett_getgroupinfo);
        proto_tree_add_item(GetGroupInfo_header_tree, hf_opa_GetGroupInfo_groupName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
        local_offset += 64;
        /* ImageID */
        local_offset = parse_Image(GetGroupInfo_header_tree, tvb, &local_offset);
        return local_offset;
    }

    for (r = 0; r < records; r++) {
        GetGroupInfo_header_item = proto_tree_add_item(parentTree, hf_opa_GetGroupInfo, tvb, local_offset, 64 + 16, ENC_NA);
        proto_item_set_text(GetGroupInfo_header_item, "GroupInfo for %s", tvb_get_string_enc(wmem_file_scope(), tvb, local_offset, 64, ENC_ASCII));
        GetGroupInfo_header_tree = proto_item_add_subtree(GetGroupInfo_header_item, ett_getgroupinfo);
        proto_tree_add_item(GetGroupInfo_header_tree, hf_opa_GetGroupInfo_groupName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
        local_offset += 64;

        /* ImageID */
        local_offset = parse_Image(GetGroupInfo_header_tree, tvb, &local_offset);

        proto_tree_add_item(GetGroupInfo_header_tree, hf_opa_GetGroupInfo_numInternalPorts, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_header_tree, hf_opa_GetGroupInfo_numExternalPorts, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        /* internalUtilStats */
        GetGroupInfo_Util_Stats_tree = proto_tree_add_subtree(GetGroupInfo_header_tree, tvb, local_offset, 48 + PM_UTIL_BUCKETS * 4,
            ett_getgroupinfoutilstats, NULL, "Internal Utilization Statistics");

        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_totalMBps, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_totalKPps, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_avgMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_minMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_maxMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Util_Stats_Buckets_item = proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_numBWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Util_Stats_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Util_Stats_Buckets_item, ett_getgroupinfoutilbuckets);
        for (i = 0; i < PM_UTIL_BUCKETS; i++) {
            GetGroupInfo_Util_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Util_Stats_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Util_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * util, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
        }
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_avgKPps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_minKPps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_maxKPps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_pmaFailedPorts, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_topoFailedPorts, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        /* sendUtilStats */
        GetGroupInfo_Util_Stats_tree = proto_tree_add_subtree(GetGroupInfo_header_tree, tvb, local_offset, 48 + PM_UTIL_BUCKETS * 4,
            ett_getgroupinfoutilstats, NULL, "External Send Utilization Statistics");

        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_totalMBps, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_totalKPps, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_avgMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_minMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_maxMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Util_Stats_Buckets_item = proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_numBWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Util_Stats_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Util_Stats_Buckets_item, ett_getgroupinfoutilbuckets);
        for (i = 0; i < PM_UTIL_BUCKETS; i++) {
            GetGroupInfo_Util_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Util_Stats_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Util_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * util, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
        }
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_avgKPps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_minKPps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_maxKPps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_pmaFailedPorts, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_topoFailedPorts, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        /* recvUtilStats */
        GetGroupInfo_Util_Stats_tree = proto_tree_add_subtree(GetGroupInfo_header_tree, tvb, local_offset, 48 + PM_UTIL_BUCKETS * 4,
            ett_getgroupinfoutilstats, NULL, "External Receive Utilization Statistics");

        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_totalMBps, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_totalKPps, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_avgMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_minMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_maxMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Util_Stats_Buckets_item = proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_numBWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Util_Stats_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Util_Stats_Buckets_item, ett_getgroupinfoutilbuckets);
        for (i = 0; i < PM_UTIL_BUCKETS; i++) {
            GetGroupInfo_Util_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Util_Stats_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Util_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * util, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
        }
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_avgKPps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_minKPps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_maxKPps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_pmaFailedPorts, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(GetGroupInfo_Util_Stats_tree, hf_opa_GetGroupInfo_topoFailedPorts, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        /* internalErrors */
        GetGroupInfo_Error_Summary_tree = proto_tree_add_subtree(GetGroupInfo_header_tree, tvb, local_offset, 40 + PM_ERR_BUCKETS * 24,
            ett_getgroupinfoerrorsummary, NULL, "Internal Error Statistics");

        GetGroupInfo_Error_Stats_Integrity_Buckets_item = proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_integrityErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Error_Stats_Congestion_Buckets_item = proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_congestionErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Error_Stats_SmaCongestion_Buckets_item = proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_smaCongestionErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Error_Stats_Bubble_Buckets_item = proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_bubbleErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Error_Stats_Security_Buckets_item = proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_securityErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Error_Stats_Routing_Buckets_item = proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_routingErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_utilizationPct10, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_discardsPct10, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        GetGroupInfo_Error_Integrity_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Error_Stats_Integrity_Buckets_item, ett_getgroupinfoerrintegritybucket);
        GetGroupInfo_Error_Congestion_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Error_Stats_Congestion_Buckets_item, ett_getgroupinfoerrcongestionbucket);
        GetGroupInfo_Error_SmaCongestion_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Error_Stats_SmaCongestion_Buckets_item, ett_getgroupinfoerrsmacongestionbucket);
        GetGroupInfo_Error_Bubble_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Error_Stats_Bubble_Buckets_item, ett_getgroupinfoerrbubblebucket);
        GetGroupInfo_Error_Security_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Error_Stats_Security_Buckets_item, ett_getgroupinfoerrsecuritybucket);
        GetGroupInfo_Error_Routing_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Error_Stats_Routing_Buckets_item, ett_getgroupinfoerrroutingbucket);

        for (i = 0; i < PM_ERR_BUCKETS; i++) {
            GetGroupInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Error_Integrity_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetGroupInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Error_Congestion_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetGroupInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Error_SmaCongestion_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetGroupInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Error_Bubble_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetGroupInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Error_Security_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetGroupInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Error_Routing_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
        }

        /* externalErrors */
        GetGroupInfo_Error_Summary_tree = proto_tree_add_subtree(GetGroupInfo_header_tree, tvb, local_offset, 40 + PM_ERR_BUCKETS * 24,
            ett_getgroupinfoerrorsummary, NULL, "External Error Statistics");

        GetGroupInfo_Error_Stats_Integrity_Buckets_item = proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_integrityErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Error_Stats_Congestion_Buckets_item = proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_congestionErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Error_Stats_SmaCongestion_Buckets_item = proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_smaCongestionErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Error_Stats_Bubble_Buckets_item = proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_bubbleErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Error_Stats_Security_Buckets_item = proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_securityErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetGroupInfo_Error_Stats_Routing_Buckets_item = proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_routingErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_utilizationPct10, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_GetGroupInfo_discardsPct10, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_Error_Summary_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        GetGroupInfo_Error_Integrity_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Error_Stats_Integrity_Buckets_item, ett_getgroupinfoerrintegritybucket);
        GetGroupInfo_Error_Congestion_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Error_Stats_Congestion_Buckets_item, ett_getgroupinfoerrcongestionbucket);
        GetGroupInfo_Error_SmaCongestion_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Error_Stats_SmaCongestion_Buckets_item, ett_getgroupinfoerrsmacongestionbucket);
        GetGroupInfo_Error_Bubble_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Error_Stats_Bubble_Buckets_item, ett_getgroupinfoerrbubblebucket);
        GetGroupInfo_Error_Security_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Error_Stats_Security_Buckets_item, ett_getgroupinfoerrsecuritybucket);
        GetGroupInfo_Error_Routing_Buckets_tree = proto_item_add_subtree(GetGroupInfo_Error_Stats_Routing_Buckets_item, ett_getgroupinfoerrroutingbucket);

        for (i = 0; i < PM_ERR_BUCKETS; i++) {
            GetGroupInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Error_Integrity_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetGroupInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Error_Congestion_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetGroupInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Error_SmaCongestion_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetGroupInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Error_Bubble_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetGroupInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Error_Security_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetGroupInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetGroupInfo_Error_Routing_Buckets_tree, hf_opa_GetGroupInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetGroupInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
        }

        proto_tree_add_item(GetGroupInfo_header_tree, hf_opa_GetGroupInfo_maxInternalRate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(GetGroupInfo_header_tree, hf_opa_GetGroupInfo_minInternalRate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(GetGroupInfo_header_tree, hf_opa_GetGroupInfo_maxExternalRate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(GetGroupInfo_header_tree, hf_opa_GetGroupInfo_minExternalRate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(GetGroupInfo_header_tree, hf_opa_GetGroupInfo_maxInternalMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetGroupInfo_header_tree, hf_opa_GetGroupInfo_maxExternalMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
    }
    return local_offset;
}

/* Parse GetGroupConfig MAD from the Performance Admin class.*/
static int parse_GetGroupConfig(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD, RMPP_t *RMPP, PA_HEADER_t *PA_HEADER)
{
    proto_item *GetGroupConfig_header_item;
    proto_tree *GetGroupConfig_header_tree = parentTree;

    proto_item *GetGroupConfig_Port_item;
    proto_tree *GetGroupConfig_Port_tree;

    int local_offset = *offset;
    unsigned i;

    unsigned length = tvb_captured_length_remaining(tvb, local_offset);
    unsigned records = (PA_HEADER->AttributeOffset ? length / (PA_HEADER->AttributeOffset * 8) : 0);

    if (!parentTree || (!pref_attempt_rmpp_defragment && RMPP->Type == RMPP_DATA && RMPP->SegmentNumber != 1))
        return *offset;

    if (MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE) {
        GetGroupConfig_header_item = proto_tree_add_item(parentTree, hf_opa_GetGroupConfig, tvb, local_offset, 64 + 16, ENC_NA);
        proto_item_set_text(GetGroupConfig_header_item, "GroupConfig for %s", tvb_get_string_enc(wmem_file_scope(), tvb, local_offset, 64, ENC_ASCII));
        GetGroupConfig_header_tree = proto_item_add_subtree(GetGroupConfig_header_item, ett_getgroupconfig);

        proto_tree_add_item(GetGroupConfig_header_tree, hf_opa_GetGroupConfig_groupName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
        local_offset += 64;
        local_offset = parse_Image(GetGroupConfig_header_tree, tvb, &local_offset);
    } else if (MAD->Method == METHOD_GET_RESP || MAD->Method == METHOD_GETTABLE_RESP) {
        GetGroupConfig_header_item = proto_tree_add_item(parentTree, hf_opa_GetGroupConfig, tvb, local_offset, records * PA_HEADER->AttributeOffset * 8, ENC_NA);
        GetGroupConfig_header_tree = proto_item_add_subtree(GetGroupConfig_header_item, ett_getgroupconfig);
        for (i = 0; i < records; i++) {
            GetGroupConfig_Port_tree = proto_tree_add_subtree_format(GetGroupConfig_header_tree, tvb, local_offset,
                PA_HEADER->AttributeOffset * 8, ett_getgroupconfigport, &GetGroupConfig_Port_item, "%3u: ", i);
            local_offset = parse_Image(GetGroupConfig_Port_tree, tvb, &local_offset);
            proto_tree_add_item(GetGroupConfig_Port_tree, hf_opa_GetGroupConfig_Port_NodeGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(GetGroupConfig_Port_tree, hf_opa_GetGroupConfig_Port_nodeDesc, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
            local_offset += 64;
            proto_item_append_text(GetGroupConfig_Port_item, "LID: 0x%04x, Port: %u", tvb_get_ntohl(tvb, local_offset), tvb_get_uint8(tvb, local_offset + 4));
            proto_tree_add_item(GetGroupConfig_Port_tree, hf_opa_GetGroupConfig_Port_NodeLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            local_offset += 4;
            proto_tree_add_item(GetGroupConfig_Port_tree, hf_opa_GetGroupConfig_Port_PortNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(GetGroupConfig_Port_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
            local_offset += 3;
        }
    }

    return local_offset;
}

/* Parse GetPortCounters MAD from the Performance Admin class.*/
static int parse_GetPortCounters(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    proto_tree *GetPortCounters_header_tree;
    proto_item *GetPortCounters_header_item;

    int local_offset = *offset;

    if (!parentTree)
        return *offset;

    GetPortCounters_header_item = proto_tree_add_item(parentTree, hf_opa_GetPortCounters, tvb, local_offset, 232 + 16, ENC_NA);
    proto_item_set_text(GetPortCounters_header_item, "Port Counters for LID: 0x%x Port: %u", tvb_get_ntohl(tvb, local_offset), tvb_get_uint8(tvb, local_offset + 4));
    GetPortCounters_header_tree = proto_item_add_subtree(GetPortCounters_header_item, ett_getportcounters);

    proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_nodeLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(GetPortCounters_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;

    proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_flags, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetPortCounters_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetPortCounters_header_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    /* ImageID */
    local_offset = parse_Image(GetPortCounters_header_tree, tvb, &local_offset);
    if (MAD->Method == METHOD_GET_RESP || MAD->Method == METHOD_GETTABLE_RESP) {
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortXmitData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortRcvData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortXmitPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortRcvPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortMulticastXmitPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortMulticastRcvPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_LocalLinkIntegrityErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_FMConfigErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortRcvErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_ExcessiveBufferOverruns, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortRcvConstraintErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortRcvSwitchRelayErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortXmitDiscards, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortXmitConstraintErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortRcvRemotePhysicalErrors, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_SwPortCongestion, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortXmitWait, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortRcvFECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortRcvBECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortXmitTimeCong, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortXmitWastedBW, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortXmitWaitData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortRcvBubble, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_PortMarkFECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_LinkErrorRecovery, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_LinkDowned, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_UncorrectableErrors, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_NumLanesDown, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_reserved, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_GetPortCounters_LinkQualityIndicator, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;

        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(GetPortCounters_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
    } else {
        local_offset += 208;
    }

    return local_offset;
}

static int parse_ClearPortCounters(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    proto_tree *ClearPortCounters_header_tree;
    proto_item *ClearPortCounters_header_item;

    int local_offset = *offset;

    if (!parentTree)
        return *offset;

    ClearPortCounters_header_item = proto_tree_add_item(parentTree, hf_opa_ClearPortCounters, tvb, local_offset, 20, ENC_NA);
    proto_item_set_text(ClearPortCounters_header_item, "Clear User Port Counters for LID: 0x%x Port: %u", tvb_get_ntohl(tvb, local_offset), tvb_get_uint8(tvb, local_offset + 4));
    ClearPortCounters_header_tree = proto_item_add_subtree(ClearPortCounters_header_item, ett_clearportcounters);

    proto_tree_add_item(ClearPortCounters_header_tree, hf_opa_ClearPortCounters_nodeLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(ClearPortCounters_header_tree, hf_opa_ClearPortCounters_PortNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(ClearPortCounters_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;
    proto_tree_add_item(ClearPortCounters_header_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    proto_tree_add_bitmask(ClearPortCounters_header_tree, tvb, local_offset,
        hf_opa_ClearPortCounters_CounterSelectMask, ett_clearportcounters_counterselectmask,
        _ClearPortCounters_CounterSelectMask, ENC_BIG_ENDIAN);
    local_offset += 4;

    return local_offset;
}

static int parse_ClearAllPortCounters(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{

    proto_tree *ClearAllPortCounters_header_tree;
    proto_item *ClearAllPortCounters_header_item;

    int local_offset = *offset;

    if (!parentTree)
        return *offset;

    ClearAllPortCounters_header_item = proto_tree_add_item(parentTree, hf_opa_ClearAllPortCounters, tvb, local_offset, 4, ENC_NA);
    proto_item_set_text(ClearAllPortCounters_header_item, "Clear All User Port Counters");
    ClearAllPortCounters_header_tree = proto_item_add_subtree(ClearAllPortCounters_header_item, ett_clearallportcounters);

    proto_tree_add_bitmask(ClearAllPortCounters_header_tree, tvb, local_offset,
        hf_opa_ClearAllPortCounters_CounterSelectMask, ett_clearallportcounters_counterselectmask,
        _ClearAllPortCounters_CounterSelectMask, ENC_BIG_ENDIAN);
    local_offset += 4;

    return local_offset;
}

static int parse_PMConfig(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    proto_tree *PMConfig_header_tree;
    proto_item *PMConfig_header_item;

    int local_offset = *offset;

    if (!parentTree)
        return *offset;

    PMConfig_header_item = proto_tree_add_item(parentTree, hf_opa_PMConfig, tvb, local_offset, 104, ENC_NA);
    PMConfig_header_tree = proto_item_add_subtree(PMConfig_header_item, ett_pmconfig);

    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_sweepInterval, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_maxClients, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_sizeHistory, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_sizeFreeze, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_lease, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_pmFlags, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_PortXmitWait, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_SwPortCongestion, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_PortRcvFECN, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_PortRcvBECN, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_PortXmitTimeCong, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_PortMarkFECN, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;

    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_integrityErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_congestionErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_smaCongestionErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_bubbleErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_securityErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_routingErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_LocalLinkIntegrityErrors, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_PortRcvErrors, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_ExcessiveBufferOverrunErrors, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_LinkErrorRecovery, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_LinkDowned, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_UncorrectableErrors, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_FMConfigErrors, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_LinkQualityIndicator, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_LinkWidthDowngrade, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_reserved8, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_memoryFootprint, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_maxAttempts, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_respTimeout, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_minRespTimeout, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_maxParallelNodes, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_pmaBatchSize, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_PMConfig_errorClear, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(PMConfig_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;

    return local_offset;
}

/* Parse MoveFreezeFrame MAD from the Performance Admin class. */
static int parse_MoveFreezeFrame(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    proto_tree *MoveFreezeFrame_header_tree = parentTree;
    proto_item *MoveFreezeFrame_old_item;
    proto_tree *MoveFreezeFrame_old_tree;
    proto_item *MoveFreezeFrame_new_item;
    proto_tree *MoveFreezeFrame_new_tree;

    int local_offset = *offset;

    if (!parentTree)
        return *offset;

    MoveFreezeFrame_old_item = proto_tree_add_item(MoveFreezeFrame_header_tree, hf_opa_MoveFreezeFrame_old, tvb, local_offset, 16, ENC_NA);
    MoveFreezeFrame_old_tree = proto_item_add_subtree(MoveFreezeFrame_old_item, ett_movefreezeframeold);
    local_offset = parse_Image(MoveFreezeFrame_old_tree, tvb, &local_offset);

    MoveFreezeFrame_new_item = proto_tree_add_item(MoveFreezeFrame_header_tree, hf_opa_MoveFreezeFrame_new, tvb, local_offset, 16, ENC_NA);
    MoveFreezeFrame_new_tree = proto_item_add_subtree(MoveFreezeFrame_new_item, ett_movefreezeframenew);
    local_offset = parse_Image(MoveFreezeFrame_new_tree, tvb, &local_offset);

    return local_offset;
}

/* Parse GetFocusPorts MAD from the Performance Admin class. */
static int parse_GetFocusPorts(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD, RMPP_t *RMPP, PA_HEADER_t *PA_HEADER)
{
    proto_tree *GetFocusPorts_header_tree;
    proto_item *GetFocusPorts_header_item;

    proto_tree *GetFocusPorts_Port_tree;
    proto_item *GetFocusPorts_Port_item;

    int local_offset = *offset;
    unsigned i = 0;

    unsigned length = tvb_captured_length_remaining(tvb, local_offset);
    unsigned records = (PA_HEADER->AttributeOffset ? length / (PA_HEADER->AttributeOffset * 8) : 0);

    if (!parentTree || (!pref_attempt_rmpp_defragment && RMPP->Type == RMPP_DATA && RMPP->SegmentNumber != 1))
        return *offset;

    if (MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE) {
        GetFocusPorts_header_item = proto_tree_add_item(parentTree, hf_opa_GetFocusPorts, tvb, local_offset, 64 + 28, ENC_NA);
        proto_item_set_text(GetFocusPorts_header_item, "Focus Ports for %s", tvb_get_string_enc(wmem_file_scope(), tvb, local_offset, 64, ENC_ASCII));
        GetFocusPorts_header_tree = proto_item_add_subtree(GetFocusPorts_header_item, ett_getfocusports);

        proto_tree_add_item(GetFocusPorts_header_tree, hf_opa_GetFocusPorts_groupName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
        local_offset += 64;
        local_offset = parse_Image(GetFocusPorts_header_tree, tvb, &local_offset);
        proto_tree_add_item(GetFocusPorts_header_tree, hf_opa_GetFocusPorts_select, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetFocusPorts_header_tree, hf_opa_GetFocusPorts_start, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetFocusPorts_header_tree, hf_opa_GetFocusPorts_range, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

    } else if (MAD->Method == METHOD_GET_RESP || MAD->Method == METHOD_GETTABLE_RESP) {
        GetFocusPorts_header_item = proto_tree_add_item(parentTree, hf_opa_GetFocusPorts, tvb, local_offset, records * PA_HEADER->AttributeOffset * 8, ENC_NA);
        GetFocusPorts_header_tree = proto_item_add_subtree(GetFocusPorts_header_item, ett_getfocusports);
        for (i = 0; i < records; i++) {
            GetFocusPorts_Port_tree = proto_tree_add_subtree_format(GetFocusPorts_header_tree, tvb, local_offset,
                PA_HEADER->AttributeOffset * 8, ett_getfocusportsport, &GetFocusPorts_Port_item, "%3u: ", i);
            local_offset = parse_Image(GetFocusPorts_Port_tree, tvb, &local_offset);

            proto_item_append_text(GetFocusPorts_Port_item, "LID: %04x, Port %u",
                tvb_get_ntohl(tvb, local_offset), tvb_get_uint8(tvb, local_offset + 4));
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_nodeLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            local_offset += 4;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_portNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_rate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_mtu, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_localFlags, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_neighborFlags, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_value, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_nodeGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_nodeDesc, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
            local_offset += 64;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_neighborLid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            local_offset += 4;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_neighborPortNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
            local_offset += 3;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_neighborValue, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_neighborGuid, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(GetFocusPorts_Port_tree, hf_opa_GetFocusPorts_neighborNodeDesc, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
            local_offset += 64;
        }
    }

    return local_offset;
}

/* Parse GetImageInfo MAD from the Performance Admin class. */
static int parse_GetImageInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    proto_tree *GetImageInfo_header_tree = parentTree;
    proto_item *GetImageInfo_header_item;
    proto_tree *GetImageInfo_SM_tree;
    uint32_t numSMs;

    int local_offset = *offset;

    if (!parentTree)
        return *offset;

    GetImageInfo_header_item = proto_tree_add_item(parentTree, hf_opa_GetImageInfo, tvb, local_offset, 216, ENC_NA);
    GetImageInfo_header_tree = proto_item_add_subtree(GetImageInfo_header_item, ett_getimageinfo);

    local_offset = parse_Image(GetImageInfo_header_tree, tvb, &local_offset);

    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_sweepStart,
            tvb, local_offset, 8, ENC_TIME_SECS|ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_sweepDuration, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_numHFIPorts, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_numSwitchNodes, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_numSwitchPorts, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_numLinks, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    numSMs = tvb_get_ntohl(tvb, local_offset);
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_numSMs, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_numFailedNodes, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_numFailedPorts, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_numSkippedNodes, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_numSkippedPorts, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_numUnexpectedClearPorts, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetImageInfo_header_tree, hf_opa_GetImageInfo_imageInterval, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    GetImageInfo_SM_tree = proto_tree_add_subtree(GetImageInfo_header_tree, tvb, local_offset, 16 + 64,
        ett_getimageinfosm, NULL, "Primary SM Info");
    proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_GetImageInfo_lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_GetImageInfo_state, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_GetImageInfo_priority, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_GetImageInfo_portNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_GetImageInfo_smPortGuid, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_GetImageInfo_smNodeDesc, tvb, local_offset, 64, ENC_NA | ENC_ASCII);
    local_offset += 64;

    if (!numSMs || numSMs > 1) {
        GetImageInfo_SM_tree = proto_tree_add_subtree(GetImageInfo_header_tree, tvb, local_offset, 16 + 64,
            ett_getimageinfosm, NULL, "Secondary SM Info");
        proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_GetImageInfo_lid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_GetImageInfo_state, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_GetImageInfo_priority, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_GetImageInfo_portNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_GetImageInfo_smPortGuid, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetImageInfo_SM_tree, hf_opa_GetImageInfo_smNodeDesc, tvb, local_offset, 64, ENC_NA | ENC_ASCII);
        local_offset += 64;
    } else {
        proto_tree_add_subtree(GetImageInfo_header_tree, tvb, local_offset, 16 + 64,
            ett_getimageinfosm, NULL, "No Secondary SM Info");
        local_offset += (16 + 64);
    }
    return local_offset;
}

/* Parse GetVFList MAD from the Performance Admin class. */
static int parse_GetVFList(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD, RMPP_t *RMPP, PA_HEADER_t *PA_HEADER)
{
    proto_item *GetVFList_GroupName_item;
    proto_tree *GetVFList_header_tree;
    proto_item *GetVFList_header_item;

    int local_offset = *offset;
    unsigned i;

    unsigned length = tvb_captured_length_remaining(tvb, local_offset);
    unsigned records = (PA_HEADER->AttributeOffset ? length / (PA_HEADER->AttributeOffset * 8) : 0);

    if (!parentTree || RMPP->Type != RMPP_DATA ||
        (MAD->Method != METHOD_GET_RESP && MAD->Method != METHOD_GETTABLE_RESP)) {
        return *offset;
    }

    GetVFList_header_item = proto_tree_add_item(parentTree, hf_opa_GetVFList, tvb, local_offset, length, ENC_NA);
    GetVFList_header_tree = proto_item_add_subtree(GetVFList_header_item, ett_getvflist);
    proto_tree_add_none_format(GetVFList_header_tree, hf_opa_GetVFList, tvb, local_offset, length, "Number of VFs: %u", records);

    for (i = 0; i < records; i++) {
        GetVFList_GroupName_item = proto_tree_add_item(GetVFList_header_tree, hf_opa_GetVFList_vfName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
        local_offset += 64;
        proto_item_prepend_text(GetVFList_GroupName_item, "%3u: ", i + 1);
    }

    return local_offset;
}

/* Parse GetVFInfo MAD from the Performance Admin class. */
static int parse_GetVFInfo(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD, RMPP_t *RMPP, PA_HEADER_t *PA_HEADER)
{
    proto_tree *GetVFInfo_header_tree = parentTree;
    proto_tree *GetVFInfo_header_item = parentTree;

    proto_tree *GetVFInfo_Util_Stats_tree;
    proto_item *GetVFInfo_Util_Stats_Buckets_item;
    proto_tree *GetVFInfo_Util_Stats_Buckets_tree;
    proto_item *GetVFInfo_Util_Stats_Bucket_item;

    proto_tree *GetVFInfo_Error_Summary_tree;
    proto_tree *GetVFInfo_Error_Integrity_Buckets_tree;
    proto_tree *GetVFInfo_Error_Congestion_Buckets_tree;
    proto_tree *GetVFInfo_Error_SmaCongestion_Buckets_tree;
    proto_tree *GetVFInfo_Error_Bubble_Buckets_tree;
    proto_tree *GetVFInfo_Error_Security_Buckets_tree;
    proto_tree *GetVFInfo_Error_Routing_Buckets_tree;
    proto_item *GetVFInfo_Error_Stats_Integrity_Buckets_item;
    proto_item *GetVFInfo_Error_Stats_Congestion_Buckets_item;
    proto_item *GetVFInfo_Error_Stats_SmaCongestion_Buckets_item;
    proto_item *GetVFInfo_Error_Stats_Bubble_Buckets_item;
    proto_item *GetVFInfo_Error_Stats_Security_Buckets_item;
    proto_item *GetVFInfo_Error_Stats_Routing_Buckets_item;
    proto_item *GetVFInfo_Error_Stats_Bucket_item;

    int local_offset = *offset;
    unsigned i;

    unsigned length = tvb_captured_length_remaining(tvb, local_offset);
    unsigned records = (PA_HEADER->AttributeOffset ? length / (PA_HEADER->AttributeOffset * 8) : 0);

    unsigned util = 100 / PM_UTIL_BUCKETS;     /* 0%+ 10%+ 20%+ ... 80%+ 90%+ */
    unsigned err = 100 / (PM_ERR_BUCKETS - 1); /* 0%+ 25%+ 50%+ 75%+ 100%+ */

    if (!parentTree || (!pref_attempt_rmpp_defragment && RMPP->Type == RMPP_DATA && RMPP->SegmentNumber != 1)) {
        return *offset;
    }

    if (MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE) {
        GetVFInfo_header_item = proto_tree_add_item(parentTree, hf_opa_GetVFInfo, tvb, local_offset, 64 + 24, ENC_NA);
        proto_item_set_text(GetVFInfo_header_item, "VFInfo for %s", tvb_get_string_enc(wmem_file_scope(), tvb, local_offset, 64, ENC_ASCII));
        GetVFInfo_header_tree = proto_item_add_subtree(GetVFInfo_header_item, ett_getvfinfo);
        proto_tree_add_item(GetVFInfo_header_tree, hf_opa_GetVFInfo_vfName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
        local_offset += 64;
        proto_tree_add_item(GetVFInfo_header_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        /* ImageID */
        local_offset = parse_Image(GetVFInfo_header_tree, tvb, &local_offset);
        return local_offset;
    }

    for (i = 0; i < records; i++) {
        GetVFInfo_header_item = proto_tree_add_item(parentTree, hf_opa_GetVFInfo, tvb, local_offset, PA_HEADER->AttributeOffset * 8, ENC_NA);
        proto_item_set_text(GetVFInfo_header_item, "VFInfo for %s", tvb_get_string_enc(wmem_file_scope(), tvb, local_offset, 64, ENC_ASCII));
        GetVFInfo_header_tree = proto_item_add_subtree(GetVFInfo_header_item, ett_getvfinfo);

        proto_tree_add_item(GetVFInfo_header_tree, hf_opa_GetVFInfo_vfName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
        local_offset += 64;
        proto_tree_add_item(GetVFInfo_header_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        local_offset = parse_Image(GetVFInfo_header_tree, tvb, &local_offset);

        proto_tree_add_item(GetVFInfo_header_tree, hf_opa_GetVFInfo_numPorts, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        /* UtilStats */
        GetVFInfo_Util_Stats_tree = proto_tree_add_subtree(GetVFInfo_header_tree, tvb, local_offset, 40 + PM_UTIL_BUCKETS * 4,
            ett_getvfinfoutilstats, NULL, "Internal Utilization Statistics");

        proto_tree_add_item(GetVFInfo_Util_Stats_tree, hf_opa_GetVFInfo_totalMBps, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFInfo_Util_Stats_tree, hf_opa_GetVFInfo_totalKPps, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFInfo_Util_Stats_tree, hf_opa_GetVFInfo_avgMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetVFInfo_Util_Stats_tree, hf_opa_GetVFInfo_minMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetVFInfo_Util_Stats_tree, hf_opa_GetVFInfo_maxMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetVFInfo_Util_Stats_Buckets_item = proto_tree_add_item(GetVFInfo_Util_Stats_tree, hf_opa_GetVFInfo_numBWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetVFInfo_Util_Stats_Buckets_tree = proto_item_add_subtree(GetVFInfo_Util_Stats_Buckets_item, ett_getvfinfoutilbuckets);
        for (i = 0; i < PM_UTIL_BUCKETS; i++) {
            GetVFInfo_Util_Stats_Bucket_item = proto_tree_add_item(GetVFInfo_Util_Stats_Buckets_tree, hf_opa_GetVFInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetVFInfo_Util_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * util, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;

        }
        proto_tree_add_item(GetVFInfo_Util_Stats_tree, hf_opa_GetVFInfo_avgKPps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetVFInfo_Util_Stats_tree, hf_opa_GetVFInfo_minKPps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetVFInfo_Util_Stats_tree, hf_opa_GetVFInfo_maxKPps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetVFInfo_Util_Stats_tree, hf_opa_GetVFInfo_pmaFailedPorts, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(GetVFInfo_Util_Stats_tree, hf_opa_GetVFInfo_topoFailedPorts, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;

        /* ErrorStats  */
        GetVFInfo_Error_Summary_tree = proto_tree_add_subtree(GetVFInfo_header_tree, tvb, local_offset, 40 + PM_ERR_BUCKETS * 24,
            ett_getvfinfoerrorsummary, NULL, "Internal Error Statistics");

        GetVFInfo_Error_Stats_Integrity_Buckets_item = proto_tree_add_item(GetVFInfo_Error_Summary_tree, hf_opa_GetVFInfo_integrityErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetVFInfo_Error_Stats_Congestion_Buckets_item = proto_tree_add_item(GetVFInfo_Error_Summary_tree, hf_opa_GetVFInfo_congestionErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetVFInfo_Error_Stats_SmaCongestion_Buckets_item = proto_tree_add_item(GetVFInfo_Error_Summary_tree, hf_opa_GetVFInfo_smaCongestionErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetVFInfo_Error_Stats_Bubble_Buckets_item = proto_tree_add_item(GetVFInfo_Error_Summary_tree, hf_opa_GetVFInfo_bubbleErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetVFInfo_Error_Stats_Security_Buckets_item = proto_tree_add_item(GetVFInfo_Error_Summary_tree, hf_opa_GetVFInfo_securityErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        GetVFInfo_Error_Stats_Routing_Buckets_item = proto_tree_add_item(GetVFInfo_Error_Summary_tree, hf_opa_GetVFInfo_routingErrors, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;

        proto_tree_add_item(GetVFInfo_Error_Summary_tree, hf_opa_GetVFInfo_utilizationPct10, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(GetVFInfo_Error_Summary_tree, hf_opa_GetVFInfo_discardsPct10, tvb, local_offset, 2, ENC_BIG_ENDIAN);
        local_offset += 2;
        proto_tree_add_item(GetVFInfo_Error_Summary_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetVFInfo_Error_Summary_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;

        GetVFInfo_Error_Integrity_Buckets_tree = proto_item_add_subtree(GetVFInfo_Error_Stats_Integrity_Buckets_item, ett_getvfinfoerrintegritybucket);
        GetVFInfo_Error_Congestion_Buckets_tree = proto_item_add_subtree(GetVFInfo_Error_Stats_Congestion_Buckets_item, ett_getvfinfoerrcongestionbucket);
        GetVFInfo_Error_SmaCongestion_Buckets_tree = proto_item_add_subtree(GetVFInfo_Error_Stats_SmaCongestion_Buckets_item, ett_getvfinfoerrsmacongestionbucket);
        GetVFInfo_Error_Bubble_Buckets_tree = proto_item_add_subtree(GetVFInfo_Error_Stats_Bubble_Buckets_item, ett_getvfinfoerrbubblebucket);
        GetVFInfo_Error_Security_Buckets_tree = proto_item_add_subtree(GetVFInfo_Error_Stats_Security_Buckets_item, ett_getvfinfoerrsecuritybucket);
        GetVFInfo_Error_Routing_Buckets_tree = proto_item_add_subtree(GetVFInfo_Error_Stats_Routing_Buckets_item, ett_getvfinfoerrroutingbucket);

        for (i = 0; i < PM_ERR_BUCKETS; i++) {
            GetVFInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetVFInfo_Error_Integrity_Buckets_tree, hf_opa_GetVFInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetVFInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetVFInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetVFInfo_Error_Congestion_Buckets_tree, hf_opa_GetVFInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetVFInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetVFInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetVFInfo_Error_SmaCongestion_Buckets_tree, hf_opa_GetVFInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetVFInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetVFInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetVFInfo_Error_Bubble_Buckets_tree, hf_opa_GetVFInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetVFInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetVFInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetVFInfo_Error_Security_Buckets_tree, hf_opa_GetVFInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetVFInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
            GetVFInfo_Error_Stats_Bucket_item = proto_tree_add_item(GetVFInfo_Error_Routing_Buckets_tree, hf_opa_GetVFInfo_BWBuckets, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            proto_item_set_text(GetVFInfo_Error_Stats_Bucket_item, "Bucket %u: %3u%%+: %u", i, i * err, tvb_get_ntohl(tvb, local_offset));
            local_offset += 4;
        }
        /* End internalErrors */
        proto_tree_add_item(GetVFInfo_header_tree, hf_opa_GetVFInfo_maxInternalRate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(GetVFInfo_header_tree, hf_opa_GetVFInfo_minInternalRate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
        local_offset += 1;
        proto_tree_add_item(GetVFInfo_header_tree, hf_opa_GetVFInfo_maxInternalMBps, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
    }

    return local_offset;
}

/* Parse GetVFConfig MAD from the Performance Admin class. */
static int parse_GetVFConfig(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD, RMPP_t *RMPP, PA_HEADER_t *PA_HEADER)
{
    proto_tree *GetVFConfig_header_tree;
    proto_item *GetVFConfig_header_item;
    proto_item *GetVFConfig_Port_item;
    proto_tree *GetVFConfig_Port_tree;

    int local_offset = *offset;
    unsigned i;

    unsigned length = tvb_captured_length_remaining(tvb, local_offset);
    unsigned records = (PA_HEADER->AttributeOffset ? length / (PA_HEADER->AttributeOffset * 8) : 0);

    if (!parentTree || (!pref_attempt_rmpp_defragment && RMPP->Type == RMPP_DATA && RMPP->SegmentNumber != 1))
        return *offset;

    if (MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE) {
        GetVFConfig_header_item = proto_tree_add_item(parentTree, hf_opa_GetVFConfig, tvb, local_offset, 64 + 24, ENC_NA);
        proto_item_set_text(GetVFConfig_header_item, "VF Config");
        GetVFConfig_header_tree = proto_item_add_subtree(GetVFConfig_header_item, ett_getvfconfig);
        proto_tree_add_item(GetVFConfig_header_tree, hf_opa_GetVFConfig_vfName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
        local_offset += 64;
        proto_tree_add_item(GetVFConfig_header_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        local_offset = parse_Image(GetVFConfig_header_tree, tvb, &local_offset);
    } else if (MAD->Method == METHOD_GETTABLE_RESP || MAD->Method == METHOD_GET_RESP) {
        GetVFConfig_header_item = proto_tree_add_item(parentTree, hf_opa_GetVFConfig, tvb, local_offset, records * PA_HEADER->AttributeOffset * 8, ENC_NA);
        proto_item_set_text(GetVFConfig_header_item, "VF Config");
        GetVFConfig_header_tree = proto_item_add_subtree(GetVFConfig_header_item, ett_getvfconfig);
        for (i = 0; i < records; i++) {
            GetVFConfig_Port_tree = proto_tree_add_subtree_format(GetVFConfig_header_tree, tvb, local_offset,
                PA_HEADER->AttributeOffset * 8, ett_getvfconfigport, &GetVFConfig_Port_item, "%3u: ", i);
            local_offset = parse_Image(GetVFConfig_Port_tree, tvb, &local_offset);
            proto_tree_add_item(GetVFConfig_Port_tree, hf_opa_GetVFConfig_Port_NodeGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(GetVFConfig_Port_tree, hf_opa_GetVFConfig_Port_nodeDesc, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
            local_offset += 64;
            proto_item_append_text(GetVFConfig_Port_item, "LID: 0x%04x, Port: %u", tvb_get_ntohl(tvb, local_offset), tvb_get_uint8(tvb, local_offset + 4));
            proto_tree_add_item(GetVFConfig_Port_tree, hf_opa_GetVFConfig_Port_NodeLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            local_offset += 4;
            proto_tree_add_item(GetVFConfig_Port_tree, hf_opa_GetVFConfig_Port_PortNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(GetVFConfig_Port_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
            local_offset += 3;
        }
    }

    return local_offset;
}

/* Parse GetVFPortCounters MAD from the Performance Admin class. */
static int parse_GetVFPortCounters(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD)
{
    proto_tree *GetVFPortCounters_header_tree;
    proto_item *GetVFPortCounters_header_item;

    int local_offset = *offset;

    if (!parentTree)
        return *offset;

    GetVFPortCounters_header_item = proto_tree_add_item(parentTree, hf_opa_GetVFPortCounters, tvb, local_offset, 224, ENC_NA);
    GetVFPortCounters_header_tree = proto_item_add_subtree(GetVFPortCounters_header_item, ett_getvfportcounters);

    proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_nodeLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;

    proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_flags, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_reserved32, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_vfName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
    local_offset += 64;
    proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    local_offset = parse_Image(GetVFPortCounters_header_tree, tvb, &local_offset);

    if (MAD->Method == METHOD_GET_RESP || MAD->Method == METHOD_GETTABLE_RESP) {
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFXmitData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFRcvData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFXmitPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFRcvPkts, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFXmitDiscards, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_SwPortVFCongestion, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFXmitWait, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFRcvFECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFRcvBECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFXmitTimeCong, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFXmitWastedBW, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFXmitWaitData, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFRcvBubble, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        proto_tree_add_item(GetVFPortCounters_header_tree, hf_opa_GetVFPortCounters_PortVFMarkFECN, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
    } else {
        local_offset += 112;
    }

    return local_offset;
}

/* Parse ClearVFPortCounters MAD from the Performance Admin class. */
static int parse_ClearVFPortCounters(proto_tree *parentTree, tvbuff_t *tvb, int *offset)
{
    proto_tree *ClearVFPortCounters_header_tree;
    proto_item *ClearVFPortCounters_header_item;

    int local_offset = *offset;

    if (!parentTree)
        return *offset;

    ClearVFPortCounters_header_item = proto_tree_add_item(parentTree, hf_opa_ClearVFPortCounters, tvb, local_offset, 92, ENC_NA);
    ClearVFPortCounters_header_tree = proto_item_add_subtree(ClearVFPortCounters_header_item, ett_clearvfportcounters);

    proto_tree_add_item(ClearVFPortCounters_header_tree, hf_opa_ClearVFPortCounters_nodeLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    proto_tree_add_item(ClearVFPortCounters_header_tree, hf_opa_ClearVFPortCounters_PortNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(ClearVFPortCounters_header_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
    local_offset += 3;
    proto_tree_add_item(ClearVFPortCounters_header_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    proto_tree_add_item(ClearVFPortCounters_header_tree, hf_opa_ClearVFPortCounters_vfName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
    local_offset += 64;
    proto_tree_add_item(ClearVFPortCounters_header_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    proto_tree_add_bitmask(ClearVFPortCounters_header_tree, tvb, local_offset,
        hf_opa_ClearVFPortCounters_CounterSelectMask, ett_clearvfportcounters_counterselectmask,
        _ClearVFPortCounters_CounterSelectMask, ENC_BIG_ENDIAN);
    local_offset += 4;

    return local_offset;
}

/* Parse GetVFFocusPorts MAD from the Performance Admin class. */
static int parse_GetVFFocusPorts(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD, RMPP_t *RMPP, PA_HEADER_t *PA_HEADER)
{
    proto_tree *GetVFFocusPorts_header_tree;
    proto_item *GetVFFocusPorts_header_item;

    proto_tree *GetVFFocusPorts_Port_tree;

    int local_offset = *offset;
    unsigned i;

    unsigned length = tvb_captured_length_remaining(tvb, local_offset);
    unsigned records = (PA_HEADER->AttributeOffset ? length / (PA_HEADER->AttributeOffset * 8) : 0);

    if (!parentTree || (!pref_attempt_rmpp_defragment && RMPP->Type == RMPP_DATA && RMPP->SegmentNumber != 1))
        return *offset;

    if (MAD->Method == METHOD_GET || MAD->Method == METHOD_GETTABLE) {
        GetVFFocusPorts_header_item = proto_tree_add_item(parentTree, hf_opa_GetVFFocusPorts, tvb, local_offset, 130, ENC_NA);
        GetVFFocusPorts_header_tree = proto_item_add_subtree(GetVFFocusPorts_header_item, ett_getvffocusports);

        proto_tree_add_item(GetVFFocusPorts_header_tree, hf_opa_GetVFFocusPorts_vfName, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
        local_offset += 64;
        proto_tree_add_item(GetVFFocusPorts_header_tree, hf_opa_reserved64, tvb, local_offset, 8, ENC_BIG_ENDIAN);
        local_offset += 8;
        local_offset = parse_Image(GetVFFocusPorts_header_tree, tvb, &local_offset);
        proto_tree_add_item(GetVFFocusPorts_header_tree, hf_opa_GetVFFocusPorts_select, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetVFFocusPorts_header_tree, hf_opa_GetVFFocusPorts_start, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
        proto_tree_add_item(GetVFFocusPorts_header_tree, hf_opa_GetVFFocusPorts_range, tvb, local_offset, 4, ENC_BIG_ENDIAN);
        local_offset += 4;
    } else if (MAD->Method == METHOD_GET_RESP || MAD->Method == METHOD_GETTABLE_RESP) {
        GetVFFocusPorts_header_item = proto_tree_add_item(parentTree, hf_opa_GetVFFocusPorts, tvb, local_offset, records * PA_HEADER->AttributeOffset * 8, ENC_NA);
        GetVFFocusPorts_header_tree = proto_item_add_subtree(GetVFFocusPorts_header_item, ett_getvffocusports);
        for (i = 0; i < records; i++) {
            GetVFFocusPorts_Port_tree = proto_tree_add_subtree_format(GetVFFocusPorts_header_tree,
                tvb, local_offset, PA_HEADER->AttributeOffset * 8, ett_getvffocusportsport, NULL,
                "%3u: LID: 0x%04x, Port: %u",
                i, tvb_get_ntohl(tvb, local_offset), tvb_get_uint8(tvb, local_offset + 4));
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_nodeLID, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            local_offset += 4;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_portNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_rate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_mtu, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_localFlags, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_neighborFlags, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_value, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_nodeGUID, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_nodeDesc, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
            local_offset += 64;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_neighborLid, tvb, local_offset, 4, ENC_BIG_ENDIAN);
            local_offset += 4;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_neighborPortNumber, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_reserved24, tvb, local_offset, 3, ENC_BIG_ENDIAN);
            local_offset += 3;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_neighborValue, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_neighborGuid, tvb, local_offset, 8, ENC_BIG_ENDIAN);
            local_offset += 8;
            proto_tree_add_item(GetVFFocusPorts_Port_tree, hf_opa_GetVFFocusPorts_neighborNodeDesc, tvb, local_offset, 64, ENC_ASCII | ENC_NA);
            local_offset += 64;
        }
    }

    return local_offset;
}
static bool parse_PA_Attribute(proto_tree *parentTree, tvbuff_t *tvb, int *offset, MAD_t *MAD, RMPP_t *RMPP, PA_HEADER_t *PA_HEADER)
{
    int local_offset = *offset;

    switch (MAD->AttributeID) {
    case PA_ATTR_ID_CLASS_PORTINFO:
        local_offset = parse_ClassPortInfo(parentTree, tvb, &local_offset, MAD);
        break;
    case PA_ATTR_ID_GET_GRP_LIST:
        local_offset = parse_GetGroupList(parentTree, tvb, &local_offset, MAD, RMPP, PA_HEADER);
        break;
    case PA_ATTR_ID_GET_GRP_INFO:
        local_offset = parse_GetGroupInfo(parentTree, tvb, &local_offset, MAD, RMPP, PA_HEADER);
        break;
    case PA_ATTR_ID_GET_GRP_CFG:
        local_offset = parse_GetGroupConfig(parentTree, tvb, &local_offset, MAD, RMPP, PA_HEADER);
        break;
    case PA_ATTR_ID_GET_PORT_CTRS:
        local_offset = parse_GetPortCounters(parentTree, tvb, &local_offset, MAD);
        break;
    case PA_ATTR_ID_CLR_PORT_CTRS:
        local_offset = parse_ClearPortCounters(parentTree, tvb, &local_offset);
        break;
    case PA_ATTR_ID_CLR_ALL_PORT_CTRS:
        local_offset = parse_ClearAllPortCounters(parentTree, tvb, &local_offset);
        break;
    case PA_ATTR_ID_GET_PM_CFG:
        local_offset = parse_PMConfig(parentTree, tvb, &local_offset);
        break;
    case PA_ATTR_ID_FREEZE_IMAGE:
        local_offset = parse_Image(parentTree, tvb, &local_offset);
        break;
    case PA_ATTR_ID_RELEASE_IMAGE:
        local_offset = parse_Image(parentTree, tvb, &local_offset);
        break;
    case PA_ATTR_ID_RENEW_IMAGE:
        local_offset = parse_Image(parentTree, tvb, &local_offset);
        break;
    case PA_ATTR_ID_GET_FOCUS_PORTS:
        local_offset = parse_GetFocusPorts(parentTree, tvb, &local_offset, MAD, RMPP, PA_HEADER);
        break;
    case PA_ATTR_ID_GET_IMAGE_INFO:
        local_offset = parse_GetImageInfo(parentTree, tvb, &local_offset);
        break;
    case PA_ATTR_ID_MOVE_FREEZE_FRAME:
        local_offset = parse_MoveFreezeFrame(parentTree, tvb, &local_offset);
        break;
    case PA_ATTR_ID_GET_VF_LIST:
        local_offset = parse_GetVFList(parentTree, tvb, &local_offset, MAD, RMPP, PA_HEADER);
        break;
    case PA_ATTR_ID_GET_VF_INFO:
        local_offset = parse_GetVFInfo(parentTree, tvb, &local_offset, MAD, RMPP, PA_HEADER);
        break;
    case PA_ATTR_ID_GET_VF_CONFIG:
        local_offset = parse_GetVFConfig(parentTree, tvb, &local_offset, MAD, RMPP, PA_HEADER);
        break;
    case PA_ATTR_ID_GET_VF_PORT_CTRS:
        local_offset = parse_GetVFPortCounters(parentTree, tvb, &local_offset, MAD);
        break;
    case PA_ATTR_ID_CLR_VF_PORT_CTRS:
        local_offset = parse_ClearVFPortCounters(parentTree, tvb, &local_offset);
        break;
    case PA_ATTR_ID_GET_VF_FOCUS_PORTS:
        local_offset = parse_GetVFFocusPorts(parentTree, tvb, &local_offset, MAD, RMPP, PA_HEADER);
        break;
    default:
        return false;
    }

    *offset = local_offset;
    return true;
}

/* Parse the Method from the MAD Common Header. */
static void label_PA_Method(proto_item *PAItem, MAD_t *MAD, packet_info *pinfo)
{
    const char *label = val_to_str_const(MAD->Method, PA_Methods, "(Unknown Perf Method!)");
    proto_item_append_text(PAItem, " %s", label);
    col_append_str(pinfo->cinfo, COL_INFO, label);
}

/* Parse the Attribute from the MAD Common Header */
static void label_PA_Attribute(proto_item *PAItem, MAD_t *MAD, packet_info *pinfo)
{
    const char *label = val_to_str_const(MAD->AttributeID, PA_Attributes, "Attribute (Unknown Perf Attribute!)");
    proto_item_append_text(PAItem, "%s", &label[11]);
    col_append_str(pinfo->cinfo, COL_INFO, &label[11]);
}
/* Parse the PA_HEADER
* IN: parentTree to add the dissection to
* IN: tvb - the data buffer from wireshark
* IN/OUT: The current and updated offset */
static bool parse_PA_HEADER(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset, MAD_t *MAD, PA_HEADER_t *PA_HEADER)
{
    int local_offset = *offset;
    proto_item *PA_HEADER_header_item;
    proto_tree *PA_HEADER_header_tree;

    PA_HEADER_header_item = proto_tree_add_item(parentTree, hf_opa_pa, tvb, local_offset, 20, ENC_NA);
    PA_HEADER_header_tree = proto_item_add_subtree(PA_HEADER_header_item, ett_pa);

    PA_HEADER->SM_Key = tvb_get_ntoh64(tvb, local_offset);
    proto_tree_add_item(PA_HEADER_header_tree, hf_opa_pa_sm_key, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;
    PA_HEADER->AttributeOffset = tvb_get_ntohs(tvb, local_offset);
    proto_tree_add_item(PA_HEADER_header_tree, hf_opa_pa_attribute_offset, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    PA_HEADER->Reserved = tvb_get_ntohs(tvb, local_offset);
    proto_tree_add_item(PA_HEADER_header_tree, hf_opa_reserved16, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    local_offset += 2;
    PA_HEADER->ComponentMask = tvb_get_ntoh64(tvb, local_offset);
    proto_tree_add_item(PA_HEADER_header_tree, hf_opa_pa_component_mask, tvb, local_offset, 8, ENC_BIG_ENDIAN);
    local_offset += 8;

    label_PA_Method(PA_HEADER_header_item, MAD, pinfo);
    label_PA_Attribute(PA_HEADER_header_item, MAD, pinfo);

    *offset = local_offset;
    return true;
}
/* Parse Performance Administration */
static void parse_PERFADMN(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset)
{
    MAD_t       MAD;
    RMPP_t      RMPP;
    PA_HEADER_t PA_HEADER;
    fragment_head *frag_head = NULL;
    tvbuff_t *old_tvb = NULL;
    int old_offset;
    bool parent_was_opa_fe = proto_is_frame_protocol(pinfo->layers, "opa.fe");

    if (!parse_MAD_Common(parentTree, pinfo, tvb, offset, &MAD)) {
        return;
    }
    if (!parse_RMPP(parentTree, pinfo, tvb, offset, &RMPP)) {
        return;
    }
    if (!parse_PA_HEADER(parentTree, pinfo, tvb, offset, &MAD, &PA_HEADER)) {
        return;
    }
    if ((!pref_parse_on_mad_status_error && MAD.Status) ||
        RMPP.Type == RMPP_ACK) {
        *offset += tvb_captured_length_remaining(tvb, *offset);
        return;
    }

    if (!parent_was_opa_fe && pref_attempt_rmpp_defragment
        && (RMPP.resptime_flags & RMPP_FLAG_ACTIVE_MASK) && (RMPP.Type == RMPP_DATA)
        && !((RMPP.resptime_flags & RMPP_FLAG_FIRST_MASK)
            && (RMPP.resptime_flags & RMPP_FLAG_LAST_MASK))) {

        frag_head = fragment_add_seq_check(&opa_mad_rmpp_reassembly_table,
            tvb, *offset, pinfo, (uint32_t)MAD.TransactionID, NULL, RMPP.SegmentNumber - 1,
            ((RMPP.resptime_flags & RMPP_FLAG_LAST_MASK) ?
                RMPP.PayloadLength - 20 : (uint32_t)tvb_captured_length_remaining(tvb, *offset)),
            (bool)!(RMPP.resptime_flags & RMPP_FLAG_LAST_MASK));
        /* Back up tvb & offset */
        old_tvb = tvb;
        old_offset = *offset;
        /* Create new tvb from reassembled data */
        tvb = process_reassembled_data(old_tvb, old_offset, pinfo, "Reassembled RMPP Packet",
            frag_head, &opa_rmpp_frag_items, NULL, parentTree);
        if (tvb == NULL) {
            return;
        }
        *offset = 0;
    }
    if (!parse_PA_Attribute(parentTree, tvb, offset, &MAD, &RMPP, &PA_HEADER)) {
        expert_add_info_format(pinfo, NULL, &ei_opa_mad_no_attribute_dissector,
            "Attribute Dissector Not Implemented (0x%x)", MAD.AttributeID);
        *offset += tvb_captured_length_remaining(tvb, *offset);
        return;
    }
}
/* Parse Vendor Specific Management Packets */
/* TBD: Replace with dissector table to call other possible dissectors */
static void parse_VENDOR_MANAGEMENT(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset)
{
    MAD_t  MAD;
    RMPP_t RMPP;

    if (!parse_MAD_Common(parentTree, pinfo, tvb, offset, &MAD)) {
        return;
    }
    if (value_is_in_range(global_mad_vendor_class, MAD.MgmtClass)) {
        /* Vendor MAD 0x09 to 0x0F does NOT have an RMPP header */

    } else if (value_is_in_range(global_mad_vendor_rmpp_class, MAD.MgmtClass)) {
        /* Vendor MAD 0x30 to 0x4F has an RMPP header */
        if (!parse_RMPP(parentTree, pinfo, tvb, offset, &RMPP)) {
            return;
        }
    }
    if (!pref_parse_on_mad_status_error && MAD.Status) {
        *offset += tvb_captured_length_remaining(tvb, *offset);
        return;
    }
    proto_tree_add_item(parentTree, hf_opa_vendor, tvb, *offset, -1, ENC_NA);

    col_append_str(pinfo->cinfo, COL_INFO, "Vendor: (Dissector Not Implemented)");

    expert_add_info_format(pinfo, NULL, &ei_opa_mad_no_attribute_dissector,
        "Attribute Dissector Not Implemented (0x%x)", MAD.AttributeID);

    *offset += tvb_captured_length_remaining(tvb, *offset);
    return;
}

/* Parse Application Specific Management Packets */
/* TBD: Replace with dissector table to call other possible dissectors */
static void parse_APPLICATION_MANAGEMENT(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset)
{
    MAD_t  MAD;

    if (!parse_MAD_Common(parentTree, pinfo, tvb, offset, &MAD)) {
        return;
    }
    if (!pref_parse_on_mad_status_error && MAD.Status) {
        *offset += tvb_captured_length_remaining(tvb, *offset);
        return;
    }
    proto_tree_add_item(parentTree, hf_opa_application, tvb, *offset, -1, ENC_NA);

    col_append_str(pinfo->cinfo, COL_INFO, "Application: (Dissector Not Implemented)");

    expert_add_info_format(pinfo, NULL, &ei_opa_mad_no_attribute_dissector,
        "Attribute Dissector Not Implemented (0x%x)", MAD.AttributeID);

    *offset += tvb_captured_length_remaining(tvb, *offset);
    return;
}

/* Parse Reserved Management Packets --- ERROR */
static void parse_RESERVED_MANAGEMENT(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset)
{
    MAD_t  MAD;

    if (!parse_MAD_Common(parentTree, pinfo, tvb, offset, &MAD)) {
        return;
    }
    if (!pref_parse_on_mad_status_error && MAD.Status) {
        *offset += tvb_captured_length_remaining(tvb, *offset);
        return;
    }
    proto_tree_add_item(parentTree, hf_opa_reservedmclass, tvb, *offset, -1, ENC_NA);

    col_append_str(pinfo->cinfo, COL_INFO, "Reserved: (Dissector Not Implemented)");

    expert_add_info_format(pinfo, NULL, &ei_opa_mad_no_attribute_dissector,
        "Attribute Dissector Not Implemented (0x%x)", MAD.AttributeID);

    *offset += tvb_captured_length_remaining(tvb, *offset);
    return;
}

/* Parse Unknown Management Packets --- WARNING */
/* TBD: Replace with dissector table to call other possible dissectors */
static void parse_UNKNOWN_MANAGEMENT(proto_tree *parentTree, packet_info *pinfo, tvbuff_t *tvb, int *offset)
{
    MAD_t  MAD;

    if (!parse_MAD_Common(parentTree, pinfo, tvb, offset, &MAD)) {
        return;
    }
    if (!pref_parse_on_mad_status_error && MAD.Status) {
        *offset += tvb_captured_length_remaining(tvb, *offset);
        return;
    }
    proto_tree_add_item(parentTree, hf_opa_unknown, tvb, *offset, -1, ENC_NA);

    col_append_str(pinfo->cinfo, COL_INFO, "Unknown: (Dissector Not Implemented)");

    expert_add_info_format(pinfo, NULL, &ei_opa_mad_no_attribute_dissector,
        "Attribute Dissector Not Implemented (0x%x)", MAD.AttributeID);

    *offset += tvb_captured_length_remaining(tvb, *offset);
    return;
}

/* Main OPA MAD dissector */
static int dissect_opa_mad(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;                /* Current Offset */
    uint8_t management_class;
    uint16_t etype, reserved;
    dissector_handle_t dissector_found = NULL;
    bool parent_was_opa_fe = proto_is_frame_protocol(pinfo->layers, "opa.fe");

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Omni-Path");
    col_clear_fence(pinfo->cinfo, COL_INFO);

    /* management datagrams are determined by the source/destination QPs */
    if (pinfo->srcport == 0 || pinfo->srcport == 1 || pinfo->destport == 0
        || pinfo->destport == 1 || parent_was_opa_fe) {
        management_class = tvb_get_uint8(tvb, offset + 1);
        if (value_is_in_range(global_mad_vendor_class, management_class) ||
            value_is_in_range(global_mad_vendor_rmpp_class, management_class)) {
            /* parse vendor specific */
            parse_VENDOR_MANAGEMENT(tree, pinfo, tvb, &offset);
        } else if (value_is_in_range(global_mad_application_class, management_class)) {
            /* parse application specific */
            parse_APPLICATION_MANAGEMENT(tree, pinfo, tvb, &offset);
        } else if (value_is_in_range(global_mad_reserved_class, management_class)) {
            /* parse reserved classes */
            parse_RESERVED_MANAGEMENT(tree, pinfo, tvb, &offset);
        } else if (value_is_in_range(global_mad_opa_class, management_class)) {
            switch (management_class) {
            case SUBN_LID_ROUTED: /* parse subn man lid routed */
                parse_SUBN_LID_ROUTED(tree, pinfo, tvb, &offset);
                break;
            case SUBN_DIRECTED_ROUTE: /* parse subn directed route */
                parse_SUBN_DIRECTED_ROUTE(tree, pinfo, tvb, &offset);
                break;
            case SUBNADMN: /* parse sub admin */
                parse_SUBNADMN(tree, pinfo, tvb, &offset);
                break;
            case PERFADMN:
                parse_PERFADMN(tree, pinfo, tvb, &offset);
                break;
            case PERF: /* parse performance */
                parse_PERF(tree, pinfo, tvb, &offset);
                break;
            default:
                parse_UNKNOWN_MANAGEMENT(tree, pinfo, tvb, &offset);
                break;
            }
        } else {
            /* parse Unknown classes */
            parse_UNKNOWN_MANAGEMENT(tree, pinfo, tvb, &offset);
        }
    } else { /* Normal Data Packet - Parse as such */
        etype    = tvb_get_ntohs(tvb, offset);
        reserved = tvb_get_ntohs(tvb, offset + 2);
        dissector_found = dissector_get_uint_handle(ethertype_dissector_table, etype);
        if (dissector_found != NULL && (reserved == 0)) {
            proto_tree_add_item(tree, hf_opa_etype, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_opa_etype_reserved16, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            call_dissector(dissector_found, tvb_new_subset_remaining(tvb, offset), pinfo, tree);
        }
    }
    return tvb_captured_length(tvb);
}

static void opa_mad_init(void)
{
    reassembly_table_init(&opa_mad_rmpp_reassembly_table,
        &addresses_ports_reassembly_table_functions);
}
static void opa_mad_cleanup(void)
{
    reassembly_table_destroy(&opa_mad_rmpp_reassembly_table);
}
void proto_register_opa_mad(void)
{
    module_t *opa_mad_module;
    expert_module_t *expert_opa_mad;

    static hf_register_info hf[] = {
        { &hf_opa_reserved64, {
                "Reserved (64 bits)", "opa.reserved64",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_reserved32, {
                "Reserved (32 bits)", "opa.reserved",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_reserved24, {
                "Reserved (24 bits)", "opa.reserved",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_reserved16, {
                "Reserved (16 bits)", "opa.reserved",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_reserved8, {
                "Reserved (8 bits)", "opa.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        /* Omni-Path*/
        { &hf_opa_etype, {
                "Ethertype", "opa.etype",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_etype_reserved16, {
                "Reserved (16 bits)", "opa.etype.reserved",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        /* SM - Lid Routed*/
        { &hf_opa_sm_lid, {
                "Subnet Management (LID Routed)", "opa.sm.lid",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sm_m_key, {
                "M_Key", "opa.sm.lid.mkey",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* SM - Directed Route */
        { &hf_opa_sm_dr, {
                "Subnet Management (Directed Route)", "opa.sm.dr",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sm_dr_slid, {
                "DrSLID", "opa.sm.dr.slid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sm_dr_dlid, {
                "DrDLID", "opa.sm.dr.dlid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sm_dr_initial_path, {
                "Initial Path", "opa.sm.dr.initialpath",
                FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sm_dr_return_path, {
                "Return Path", "opa.sm.dr.returnpath",
                FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sm_dr_reserved64, {
                "Reserved (64 bits)", "opa.sm.dr.reserved",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* SA MAD Header */
        { &hf_opa_sa, {
                "Subnet Administration Header", "opa.sa",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_sm_key, {
                "SM_Key (Verification Key)", "opa.sa.smkey",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_attribute_offset, {
                "Attribute Offset", "opa.sa.attributeoffset",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_component_mask, {
                "Component Mask", "opa.sa.componentmask",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* PM MAD Header */
        { &hf_opa_pm, {
                "Performance Management", "opa.pm",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* PA MAD Header */
        { &hf_opa_pa, {
                "Performance Administration Header", "opa.pa",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_pa_sm_key, {
                "SM_Key (Verification Key)", "opa.pa.smkey",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_pa_attribute_offset, {
                "Attribute Offset", "opa.pa.attributeoffset",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_pa_component_mask, {
                "Component Mask", "opa.pa.componentmask",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* Other MAD Headers */
        { &hf_opa_vendor, {
                "Vendor MAD Header", "opa.vendor",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_application, {
                "Application MAD Header", "opa.application",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_reservedmclass, {
                "Reserved MAD Header", "opa.reservedmclass",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_unknown, {
                "Unknown MAD Header", "opa.unknown",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* MAD Header */
        { &hf_opa_mad, {
                "MAD Header - Common Management Datagram", "opa.mad.header",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_mad_base_version, {
                "Base Version", "opa.mad.baseversion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_mad_mgmt_class, {
                "Management Class", "opa.mad.mgmtclass",
                FT_UINT8, BASE_HEX | BASE_EXT_STRING, &MAD_mgmt_names_ext, 0x0, NULL, HFILL }
        },
        { &hf_opa_mad_class_version, {
                "Class Version", "opa.mad.classversion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_mad_method, {
                "Method", "opa.mad.method",
                FT_UINT8, BASE_HEX, VALS(Methods), 0x0, NULL, HFILL }
        },
        { &hf_opa_mad_status, {
                "Status", "opa.mad.status",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_mad_status_DR_D, {
                "Direction", "opa.mad.dr.direction",
                FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL }
        },
        { &hf_opa_mad_status_DR_status, {
                "Status", "opa.mad.status",
                FT_UINT16, BASE_HEX, NULL, 0x7FFF, NULL, HFILL }
        },
        { &hf_opa_mad_status_DR_Hop_Pointer, {
                "Hop Pointer", "opa.mad.dr.hoppointer",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_mad_status_DR_Hop_Count, {
                "Hop Counter", "opa.mad.dr.hopcounter",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_mad_status_NM_ClassSpecific, {
                "Class Specific", "opa.mad.status.classspecific",
                FT_UINT16, BASE_HEX, NULL, 0xFF00, NULL, HFILL }
        },
        { &hf_opa_mad_status_NM_reserved1, {
                "Reserved (3 Bits)", "opa.mad.status.reserved",
                FT_UINT16, BASE_HEX, NULL, 0x00E0, NULL, HFILL }
        },
        { &hf_opa_mad_status_NM_InvalidField, {
                "Invalid Field", "opa.mad.status.invalidfield",
                FT_UINT16, BASE_HEX, VALS(MAD_Status_InvalidField), 0x001C, NULL, HFILL }
        },
        { &hf_opa_mad_status_NM_RedirectRqrd, {
                "Redirect Required", "opa.mad.status.redirectrqrd",
                FT_BOOLEAN, 16, TFS(&tfs_redirect_no_redirect), 0x0002, NULL, HFILL }
        },
        { &hf_opa_mad_status_NM_Busy, {
                "Busy", "opa.mad.status.busy",
                FT_BOOLEAN, 16, TFS(&tfs_busy_not_busy), 0x0001, NULL, HFILL }
        },
        { &hf_opa_mad_transaction_id, {
                "Transaction ID", "opa.mad.transactionid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_mad_attribute_id, {
                "Attribute ID", "opa.mad.attributeid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        /* MAD Header - Attribute Modifier */
        { &hf_opa_attribute_modifier, {
                "Attribute Modifier", "opa.mad.attributemodifier",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_A, {
                "All", "opa.mad.attributemodifier.a",
                FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_A2, {
                "All Ingress Ports", "opa.mad.attributemodifier.a2",
                FT_BOOLEAN, 32, NULL, 0x00020000, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_A3, {
                "All", "opa.mad.attributemodifier.a3",
                FT_BOOLEAN, 32, NULL, 0x00040000, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_A4, {
                "All", "opa.mad.attributemodifier.a4",
                FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_A5, {
                "Starting Address", "opa.mad.attributemodifier.a5",
                FT_UINT32, BASE_HEX, NULL, 0x7FF80000, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_A6, {
                "All", "opa.mad.attributemodifier.a6",
                FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_B, {
                "Block Number", "opa.mad.attributemodifier.b",
                FT_UINT32, BASE_DEC, NULL, 0x000007FF, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_B2, {
                "All Egress Ports", "opa.mad.attributemodifier.b2",
                FT_BOOLEAN, 32, NULL, 0x00010000, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_B3, {
                "Block Number", "opa.mad.attributemodifier.b3",
                FT_UINT32, BASE_DEC, NULL, 0x0003FFFF, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_B4, {
                "Block Number", "opa.mad.attributemodifier.b4",
                FT_UINT32, BASE_DEC, NULL, 0x000FFFFF, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_B5, {
                "Block Number", "opa.mad.attributemodifier.b5",
                FT_UINT32, BASE_DEC, NULL, 0x0000001F, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_E, {
                "Egress Ports", "opa.mad.attributemodifier.e",
                FT_UINT32, BASE_DEC, NULL, 0x000000FF, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_I, {
                "Ingress Ports", "opa.mad.attributemodifier.i",
                FT_UINT32, BASE_DEC, NULL, 0x0000FF00, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_L, {
                "Length", "opa.mad.attributemodifier.l",
                FT_UINT32, BASE_DEC, NULL, 0x0007E000, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_NP, {
                "Number of Ports", "opa.mad.attributemodifier.n",
                FT_UINT32, BASE_DEC, NULL, 0xFF000000, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_NB, {
                "Number of Blocks", "opa.mad.attributemodifier.n",
                FT_UINT32, BASE_DEC, NULL, 0xFF000000, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_N2, {
                "Number of aggregated Attributes", "opa.mad.attributemodifier.n",
                FT_UINT32, BASE_DEC, NULL, 0x000000FF, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_P, {
                "Port Number", "opa.mad.attributemodifier.p",
                FT_UINT32, BASE_DEC, NULL, 0x000000FF, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_P2, {
                "Port Number", "opa.mad.attributemodifier.p",
                FT_UINT32, BASE_DEC, NULL, 0x00FF0000, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_P3, {
                "Position", "opa.mad.attributemodifier.p",
                FT_UINT32, BASE_DEC, NULL, 0x00C00000, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_S, {
                "Section of Table", "opa.mad.attributemodifier.s",
                FT_UINT32, BASE_DEC, VALS(MADAttrModSectionVLarb), 0x00FF0000, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_S2, {
                "Start of SM Configuration", "opa.mad.attributemodifier.s2",
                FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL }
        },
        { &hf_opa_attribute_modifier_Y, {
                "Asynchronous update", "opa.mad.attributemodifier.y",
                FT_BOOLEAN, 32, NULL, 0x00001000, NULL, HFILL }
        },

        /* RMPP Header */
        { &hf_opa_rmpp, {
                "RMPP - Reliable Multi-Packet Transaction Protocol", "opa.rmpp",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_rmpp_version, {
                "RMPP Version", "opa.rmpp.rmppversion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_rmpp_type, {
                "RMPP Type", "opa.rmpp.rmpptype",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_rmpp_r_resp_time, {
                "R Resp Time", "opa.rmpp.rresptime",
                FT_UINT8, BASE_HEX, NULL, 0xF8, NULL, HFILL }
        },
        { &hf_opa_rmpp_flags_last, {
                "Last", "opa.rmpp.flags.last",
                FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }
        },
        { &hf_opa_rmpp_flags_first, {
                "First", "opa.rmpp.flags.first",
                FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }
        },
        { &hf_opa_rmpp_flags_active, {
                "Active", "opa.rmpp.flags.active",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }
        },
        { &hf_opa_rmpp_status, {
                "RMPP Status", "opa.rmpp.rmppstatus",
                FT_UINT8, BASE_HEX, VALS(RMPP_Status), 0x0, NULL, HFILL }
        },
        { &hf_opa_rmpp_data1, {
                "RMPP Data 1", "opa.rmpp.data1",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_rmpp_data2, {
                "RMPP Data 2", "opa.rmpp.data2",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        /* RMPP Data */
        { &hf_opa_rmpp_segment_number, {
                "Segment Number", "opa.rmpp.segmentnumber",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_rmpp_payload_length32, {
                "Payload Length", "opa.rmpp.payloadlength",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        /* RMPP ACK */
        { &hf_opa_rmpp_new_window_last, {
                "New Window Last", "opa.rmpp.newwindowlast",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        /* Fragments */
        { &hf_opa_rmpp_fragments, {
                "Message fragments", "opa.fragments",
                FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_opa_rmpp_fragment, {
                "Message fragment", "opa.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_opa_rmpp_fragment_overlap, {
                "Message fragment overlap", "opa.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_opa_rmpp_fragment_overlap_conflicts, {
                "Message fragment overlapping with conflicting data", "opa.fragment.overlap.conflicts",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_opa_rmpp_fragment_multiple_tails, {
                "Message has multiple tail fragments", "opa.fragment.multiple_tails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_opa_rmpp_fragment_too_long_fragment, {
                "Message fragment too long", "opa.fragment.too_long_fragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_opa_rmpp_fragment_error, {
                "Message defragmentation error", "opa.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_opa_rmpp_fragment_count, {
                "Message fragment count", "opa.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_opa_rmpp_reassembled_in, {
                "Reassembled in", "opa.reassembled.in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_opa_rmpp_reassembled_length, {
                "Reassembled length", "opa.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },

        /* SA Packet */
        /* SA RID */
        { &hf_opa_sa_Lid, {
                "LID", "opa.sa.lid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_Port, {
                "Port", "opa.sa.port",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_EndportLID, {
                "EndportLID", "opa.sa.endportlid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_PortNum, {
                "PortNum", "opa.sa.portnum",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_InputPortNum, {
                "InputPortNum", "opa.sa.inputportnum",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_OutputPortNum, {
                "OutputPortNum", "opa.sa.outputportnum",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_reserved14, {
                "Reserved (14 bits)", "opa.sa.reserved",
                FT_UINT32, BASE_HEX, NULL, 0xFFFC0000, NULL, HFILL }
        },
        { &hf_opa_sa_BlockNum_18b, {
                "BlockNum", "opa.sa.blocknum",
                FT_UINT32, BASE_HEX, NULL, 0x0003FFFF, NULL, HFILL }
        },
        { &hf_opa_sa_Position, {
                "Position", "opa.sa.position",
                FT_UINT32, BASE_HEX, NULL, 0xC0000000, NULL, HFILL }
        },
        { &hf_opa_sa_Position_16b, {
                "Position", "opa.sa.position",
                FT_UINT16, BASE_HEX, NULL, 0xC000, NULL, HFILL }
        },
        { &hf_opa_sa_reserved9, {
                "Reserved (9 bits)", "opa.sa.reserved",
                FT_UINT32, BASE_HEX, NULL, 0x3FE00000, NULL, HFILL }
        },
        { &hf_opa_sa_reserved9_16b, {
                "Reserved (9 bits)", "opa.sa.reserved",
                FT_UINT16, BASE_HEX, NULL, 0x3FE0, NULL, HFILL }
        },
        { &hf_opa_sa_BlockNum_21b, {
                "BlockNum", "opa.sa.blocknum",
                FT_UINT32, BASE_HEX, NULL, 0x001FFFFF, NULL, HFILL }
        },
        { &hf_opa_sa_BlockNum_8b, {
                "BlockNum", "opa.sa.blocknum",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_BlockNum_16b, {
                "BlockNum", "opa.sa.blocknum",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_BlockNum_5b, {
                "BlockNum", "opa.sa.blocknum",
                FT_UINT16, BASE_HEX, NULL, 0x001F, NULL, HFILL }
        },
        { &hf_opa_sa_SubscriberLID, {
                "SubscriberGID", "opa.sa.subscribergid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_Enum, {
                "Enum", "opa.sa.enum",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_FromLID, {
                "FromLID", "opa.sa.fromlid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_FromPort, {
                "FromPort", "opa.sa.fromport",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_ServiceID, {
                "ServiceID", "opa.sa.serviceid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_ServiceLID, {
                "ServiceLID", "opa.sa.servicelid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_ServiceP_Key, {
                "ServiceP_Key", "opa.sa.servicep_key",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_ServiceGID, {
                "ServiceGID", "opa.sa.servicegid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_MGID, {
                "MGID", "opa.sa.mgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_sa_PortGID, {
                "PortGID", "opa.sa.portgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* Notice */
        { &hf_opa_Notice, {
                "Notice", "opa.notice",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Notice_IsGeneric, {
                "IsGeneric", "opa.notice.isgeneric",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_Notice_Type, {
                "Type", "opa.notice.type",
                FT_UINT8, BASE_HEX, VALS(NoticeType), 0x7F, NULL, HFILL }
        },
        { &hf_opa_Notice_ProducerType, {
                "ProducerType", "opa.notice.producertype",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Notice_TrapNumber, {
                "TrapNumber", "opa.notice.trapnumber",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Notice_VendorID, {
                "VendorID", "opa.notice.vendorid",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Notice_DeviceID, {
                "DeviceID", "opa.notice.deviceid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Notice_Toggle, {
                "Toggle", "opa.notice.toggle",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_Notice_Count, {
                "Count", "opa.notice.count",
                FT_UINT16, BASE_HEX, NULL, 0x7FFF, NULL, HFILL }
        },
        { &hf_opa_Notice_IssuerLID, {
                "IssuerLID", "opa.notice.issuerlid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Notice_IssuerGID, {
                "IssuerGID", "opa.notice.issuergid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Notice_ClassDataDetails, {
                "ClassDataDetails", "opa.notice.classdatadetails",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* Trap */
        { &hf_opa_Trap, {
                "Trap", "opa.trap",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* Traps 64,65,66,67 */
        { &hf_opa_Trap_GID, {
                "GID", "opa.trap.gid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        /* Traps 68,69 */

        /* Trap 128 */
        { &hf_opa_Trap_LID, {
                "LIDADDR", "opa.trap.lidaddr",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* Trap 129, 130, 131 */
        { &hf_opa_Trap_PORTNO, {
                "PORTNO", "opa.trap.portno",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* Trap 144 */
        { &hf_opa_Trap_CAPABILITYMASK, {
                "CapabilityMask", "opa.trap.capabilitymask",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Trap_CAPABILITYMASK3, {
                "CapabilityMask3", "opa.trap.capabilitymask3",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Trap_144_reserved, {
                "Reserved (4 bits)", "opa.trap.144.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_opa_Trap_LinkWidthDowngradeEnabledChange, {
                "LinkWidthDowngradeEnabledChange", "opa.trap.linkwidthdowngradeenabledchange",
                FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
        },
        { &hf_opa_Trap_LinkSpeecEnabledChange, {
                "LinkSpeecEnabledChange", "opa.trap.linkspeecenabledchange",
                FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }
        },
        { &hf_opa_Trap_LinkWidthEnabledChange, {
                "LinkWidthEnabledChange", "opa.trap.linkwidthenabledchange",
                FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }
        },
        { &hf_opa_Trap_NodeDescriptionChange, {
                "NodeDescriptionChange", "opa.trap.nodedescriptionchange",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }
        },

        /* Trap 145 */
        { &hf_opa_Trap_SystemImageGUID, {
                "SystemImageGUID", "opa.trap.systemimageguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* Trap 256 */
        { &hf_opa_Trap_DRSLID, {
                "DR SLID", "opa.trap.drslid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Trap_Method, {
                "Method", "opa.trap.method",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Trap_AttributeID, {
                "AttributeID", "opa.trap.attributeid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Trap_AttributeModifier, {
                "AttributeModifier", "opa.trap.attributemodifier",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Trap_MKey, {
                "MKey", "opa.trap.mkey",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Trap_DRNotice, {
                "DRNotice", "opa.trap.drnotice",
                FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_Trap_DRPathTruncated, {
                "DRPathTruncated", "opa.trap.drpathtruncated",
                FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }
        },
        { &hf_opa_Trap_DRHopCount, {
                "DRHopCount", "opa.trap.drhopcount",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_opa_Trap_DRNoticeReturnPath, {
                "DRNoticeReturnPath", "opa.trap.drnoticereturnpath",
                FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },

        /* Trap 257, 258 */
        { &hf_opa_Trap_Key, {
                "Key", "opa.trap.key",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Trap_SL, {
                "SL", "opa.trap.sl",
                FT_UINT8, BASE_HEX, NULL, 0xF8, NULL, HFILL }
        },
        { &hf_opa_Trap_SL_reserved, {
                "Reserved (3 bits)", "opa.trap.sl.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
        },
        { &hf_opa_Trap_QP, {
                "QP", "opa.trap.qp",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* Trap 259 */
        { &hf_opa_Trap_DataValid, {
                "DataValid", "opa.trap.datavalid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Trap_DataValid_Lid1, {
                "Lid1", "opa.trap.datavalid.lid1",
                FT_BOOLEAN, 16, TFS(&tfs_valid_invalid), 0x8000, NULL, HFILL }
        },
        { &hf_opa_Trap_DataValid_Lid2, {
                "Lid2", "opa.trap.datavalid.lid2",
                FT_BOOLEAN, 16, TFS(&tfs_valid_invalid), 0x4000, NULL, HFILL }
        },
        { &hf_opa_Trap_DataValid_PKey, {
                "PKey", "opa.trap.datavalid.pkey",
                FT_BOOLEAN, 16, TFS(&tfs_valid_invalid), 0x2000, NULL, HFILL }
        },
        { &hf_opa_Trap_DataValid_SL, {
                "SL", "opa.trap.datavalid.sl",
                FT_BOOLEAN, 16, TFS(&tfs_valid_invalid), 0x1000, NULL, HFILL }
        },
        { &hf_opa_Trap_DataValid_QP1, {
                "QP1", "opa.trap.datavalid.qp1",
                FT_BOOLEAN, 16, TFS(&tfs_valid_invalid), 0x0800, NULL, HFILL }
        },
        { &hf_opa_Trap_DataValid_QP2, {
                "QP2", "opa.trap.datavalid.qp2",
                FT_BOOLEAN, 16, TFS(&tfs_valid_invalid), 0x0400, NULL, HFILL }
        },
        { &hf_opa_Trap_DataValid_Gid1, {
                "Gid1", "opa.trap.datavalid.gid1",
                FT_BOOLEAN, 16, TFS(&tfs_valid_invalid), 0x0200, NULL, HFILL }
        },
        { &hf_opa_Trap_DataValid_Gid2, {
                "Gid2", "opa.trap.datavalid.gid2",
                FT_BOOLEAN, 16, TFS(&tfs_valid_invalid), 0x0100, NULL, HFILL }
        },
        { &hf_opa_Trap_DataValid_Reserved, {
                "DataValid", "opa.trap.datavalid.reserved",
                FT_UINT16, BASE_HEX, NULL, 0x00FF, NULL, HFILL }
        },

        { &hf_opa_Trap_PKey, {
                "PKey", "opa.trap.pkey",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* ClassPortInfo in Performance class */
        { &hf_opa_ClassPortInfo, {
                "ClassPortInfo", "opa.classportinfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_BaseVersion, {
                "BaseVersion", "opa.clasportinfo.baseversion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_ClassVersion, {
                "ClassVersion", "opa.clasportinfo.classversion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_CapMask, {
                "CapMask", "opa.clasportinfo.capmask",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_CapMask2, {
                "CapMask2", "opa.clasportinfo.capmask2",
                FT_UINT32, BASE_HEX, NULL, 0xFFFFFFE0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_RespTimeValue, {
                "RespTimeValue", "opa.clasportinfo.resptimevalue",
                FT_UINT32, BASE_HEX, NULL, 0x0000001F, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Redirect_GID, {
                "GID", "opa.clasportinfo.redirect.gid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Redirect_TClass, {
                "TClass", "opa.clasportinfo.redirect.tclass",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Redirect_reserved, {
                "Reserved (4 bits)", "opa.clasportinfo.redirect.reserved",
                FT_UINT24, BASE_HEX, NULL, 0xF00000, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Redirect_FlowLabel, {
                "FlowLabel", "opa.clasportinfo.redirect.flowlabel",
                FT_UINT24, BASE_HEX, NULL, 0x0FFFFF, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Redirect_LID, {
                "LID", "opa.clasportinfo.redirect.lid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Redirect_SL, {
                "SL", "opa.clasportinfo.redirect.sl",
                FT_UINT8, BASE_HEX, NULL, 0xF8, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Redirect_reserved2, {
                "Reserved (3 bits)", "opa.clasportinfo.redirect.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Redirect_QP, {
                "QP", "opa.clasportinfo.redirect.qp",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Redirect_Q_Key, {
                "Q_Key", "opa.clasportinfo.redirect.q_key",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Trap_GID, {
                "GID", "opa.clasportinfo.trap.gid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Trap_TClass, {
                "TClass", "opa.clasportinfo.trap.tclass",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Trap_reserved, {
                "Reserved (4 bits)", "opa.clasportinfo.trap.reserved",
                FT_UINT24, BASE_HEX, NULL, 0xF00000, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Trap_FlowLabel, {
                "FlowLabel", "opa.clasportinfo.trap.flowlabel",
                FT_UINT24, BASE_HEX, NULL, 0x0FFFFF, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Trap_LID, {
                "LID", "opa.clasportinfo.trap.lid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Trap_HopLimit, {
                "HopLimit", "opa.clasportinfo.trap.hoplimit",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Trap_QP, {
                "QP", "opa.clasportinfo.trap.qp",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Trap_Q_Key, {
                "Q_Key", "opa.clasportinfo.trap.q_key",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Trap_P_Key, {
                "P_Key", "opa.clasportinfo.trap.p_key",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Redirect_P_Key, {
                "P_Key", "opa.clasportinfo.redirect.p_key",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Trap_SL, {
                "SL", "opa.clasportinfo.trap.sl",
                FT_UINT8, BASE_HEX, NULL, 0xF8, NULL, HFILL }
        },
        { &hf_opa_ClassPortInfo_Trap_reserved2, {
                "Reserved (3 bits)", "opa.clasportinfo.trap.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
        },
/*******************
* NodeDescription *
*******************/

        { &hf_opa_NodeDescription, {
                "NodeDescription", "opa.nodedescription",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeDescription_NodeString, {
                "NodeString", "opa.nodedescription.nodestring",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

/************
* NodeInfo *
************/
        { &hf_opa_NodeInfo, {
                "Node Info", "opa.nodeinfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeInfo_BaseVersion, {
                "Base Version", "opa.nodeinfo.baseversion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeInfo_ClassVersion, {
                "Class Version", "opa.nodeinfo.classversion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeInfo_NodeType, {
                "Node Type", "opa.nodeinfo.nodetype",
                FT_UINT8, BASE_HEX, VALS(NodeType), 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeInfo_NumPorts, {
                "Num Ports", "opa.nodeinfo.numports",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeInfo_SystemImageGUID, {
                "System Image GUID", "opa.nodeinfo.systemimageguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeInfo_NodeGUID, {
                "Node GUID", "opa.nodeinfo.nodeguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeInfo_PortGUID, {
                "Port GUID", "opa.nodeinfo.portguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeInfo_PartitionCap, {
                "Partition Cap", "opa.nodeinfo.partitioncap",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeInfo_DeviceID, {
                "Device ID", "opa.nodeinfo.deviceid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeInfo_Revision, {
                "Revision", "opa.nodeinfo.revision",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeInfo_LocalPortNum, {
                "Local Port Num", "opa.nodeinfo.localportnum",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_NodeInfo_VendorID, {
                "Vendor ID", "opa.nodeinfo.vendorid",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/**************
* SwitchInfo *
**************/

        { &hf_opa_SwitchInfo, {
                "Switch Info", "opa.switchinfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_LinearFDBCap, {
                "Linear FDB Cap", "opa.switchinfo.linearfdbcap",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_MulticastFDBCap, {
                "Multicast FDB Cap", "opa.switchinfo.multicastfdbcap",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_LinearFDBTop, {
                "Linear FDB Top", "opa.switchinfo.linearfdbtop",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_MulticastFDBTop, {
                "Multicast FDB Top", "opa.switchinfo.multicastfdbtop",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_CollectiveCap, {
                "Collective Cap", "opa.switchinfo.collectivecap",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_CollectiveTop, {
                "Collective Top", "opa.switchinfo.collectivetop",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_IPAddrIPv6, {
                "IP Addr IPv6", "opa.switchinfo.ipaddripv6",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_IPAddrIPv4, {
                "IP Addr IPv4", "opa.switchinfo.ipaddripv4",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_LifeTimeValue, {
                "Life Time Value", "opa.switchinfo.lifetimevalue",
                FT_UINT8, BASE_HEX, NULL, 0xF8, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_PortStateChange, {
                "Port State Change", "opa.switchinfo.portstatechange",
                FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_reserved2, {
                "Reserved (2 bits)", "opa.switchinfo.reserved2",
                FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_PartitionEnforcementCap, {
                "Partition Enforcement Cap", "opa.switchinfo.partitionenforcementcap",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_PortGroupCap, {
                "Port Group Cap", "opa.switchinfo.portgroupcap",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_PortGroupTop, {
                "Port Group Top", "opa.switchinfo.portgrouptop",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_SupportedRoutingMode, {
                "Supported Routing Mode", "opa.switchinfo.supportedroutingmode",
                FT_UINT8, BASE_HEX, VALS(RoutingMode), 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_EnabledRoutingMode, {
                "Enabled Routing Mode", "opa.switchinfo.enabledroutingmode",
                FT_UINT8, BASE_HEX, VALS(RoutingMode), 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_reserved3, {
                "Reserved (4 bits)", "opa.switchinfo.reserved3",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_EnhancedPortZero, {
                "Enhanced Port Zero", "opa.switchinfo.enhancedportzero",
                FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_reserved4, {
                "Reserved (3 bits)", "opa.switchinfo.reserved4",
                FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_reserved5, {
                "Reserved (2 bits)", "opa.switchinfo.reserved5",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_CollectiveMask, {
                "Collective Mask", "opa.switchinfo.collectivemask",
                FT_UINT8, BASE_HEX, NULL, 0x38, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_MulticastMask, {
                "Multicast Mask", "opa.switchinfo.multicastmask",
                FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_AdaptiveRoutingEnable, {
                "Adaptive Routing Enable", "opa.switchinfo.adaptiveroutingenable",
                FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_AdaptiveRoutingPause, {
                "Adaptive Routing Pause", "opa.switchinfo.adaptiveroutingpause",
                FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_AdaptiveRoutingAlgorithm, {
                "Adaptive Routing  Algorithm", "opa.switchinfo.adaptiveroutingalgorithm",
                FT_UINT16, BASE_HEX, VALS(AdaptiveRoutingAlgorithm), 0x3800, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_AdaptiveRoutingFrequency, {
                "Adaptive Routing  Frequency", "opa.switchinfo.adaptiveroutingfrequency",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_swinfo_ar_frequency), 0x0700, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_AdaptiveRoutingLostRoutesOnly, {
                "Adaptive Routing  Lost Routes Only", "opa.switchinfo.adaptiveroutinglostroutesonly",
                FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_AdaptiveRoutingThreshold, {
                "Adaptive Routing  Threshold", "opa.switchinfo.adaptiveroutingthreshold",
                FT_UINT16, BASE_HEX, VALS(AdaptiveRoutingThreshold), 0x0070, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_reserved6, {
                "Reserved (4 bits)", "opa.switchinfo.reserved6",
                FT_UINT16, BASE_HEX, NULL, 0x000F, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_SwitchCapabilityMask, {
                "Switch Capability Mask", "opa.switchinfo.switchcapabilitymask",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_SwitchCapabilityMask_reserved, {
                "Reserved (13 bits)", "opa.switchinfo.switchcapabilitymask.reserved",
                FT_UINT16, BASE_HEX, NULL, 0xFFF8, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_SwitchCapabilityMask_IsAddrRangeConfigSupported, {
                "IsAddrRangeConfigSupported", "opa.switchinfo.switchcapabilitymask.isaddrrangeconfigsupported",
                FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_SwitchCapabilityMask_reserved2, {
                "Reserved (1 bit)", "opa.switchinfo.switchcapabilitymask.reserved",
                FT_UINT16, BASE_HEX, NULL, 0x0002, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_SwitchCapabilityMask_IsAdaptiveRoutingSupported, {
                "IsAdaptiveRoutingSupported", "opa.switchinfo.switchcapabilitymask.isadaptiveroutingsupported",
                FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }
        },
        { &hf_opa_SwitchInfo_CapabilityMaskCollectives, {
                "Capability Mask Collectives", "opa.switchinfo.capabilitymaskcollectives",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/************
* PortInfo *
************/
        { &hf_opa_PortInfo, {
                "Port Info", "opa.portinfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LID, {
                "LID", "opa.portinfo.lid",
                FT_UINT32, BASE_HEX, NULL, 0x0, "Base LID of this node", HFILL }
        },
        { &hf_opa_PortInfo_FlowControlMask, {
                "Flow Control Mask", "opa.portinfo.flowcontrolmask",
                FT_UINT32, BASE_CUSTOM, CF_FUNC(cf_opa_mad_32b_mask), 0x0, "Flow control enabled on all VLs except VL15", HFILL }
        },
        { &hf_opa_PortInfo_VL_PreemptCap, {
                "PreemptCap", "opa.portinfo.vl.preemptcap",
                FT_UINT8, BASE_DEC, NULL, 0x0, "Size of Preempting VL Arbitration table", HFILL }
        },
        { &hf_opa_PortInfo_VL_reserved, {
                "Reserved (3 bits)", "opa.portinfo.vl.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_VL_Cap, {
                "VL Cap", "opa.portinfo.vl.cap",
                FT_UINT8, BASE_DEC, NULL, 0x1F, "Virtual Lanes supported on this port", HFILL }
        },
        { &hf_opa_PortInfo_VL_HighLimit, {
                "HighLimit", "opa.portinfo.vl.highlimit",
                FT_UINT16, BASE_DEC, NULL, 0x0, "Limit of high priority component of VL Arbitration table", HFILL }
        },
        { &hf_opa_PortInfo_VL_PreemptingLimit, {
                "PreemptingLimit", "opa.portinfo.vl.preemptinglimit",
                FT_UINT16, BASE_DEC, NULL, 0x0, "Limit of preempt component of VL Arbitration table", HFILL }
        },
        { &hf_opa_PortInfo_VL_ArbitrationHighCap, {
                "ArbitrationHighCap", "opa.portinfo.vl.arbitrationhighcap",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_VL_ArbitrationLowCap, {
                "ArbitrationLowCap", "opa.portinfo.vl.arbitrationlowcap",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        { &hf_opa_PortInfo_PortPhysConfig_reserved, {
                "Reserved (4 bits)", "opa.portinfo.portphysconfig.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortPhysConfig_PortType, {
                "PortPhysConfig PortType", "opa.portinfo.portphysconfig.porttype",
                FT_UINT8, BASE_HEX, VALS(PortType), 0x0F, NULL, HFILL }
        },
        { &hf_opa_PortInfo_MultiCollectMask_reserved, {
                "Reserved (2 bits)", "opa.portinfo.multicollectmask.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_MultiCollectMask_CollectiveMask, {
                "MultiCollectMask CollectiveMask", "opa.portinfo.multicollectmask.collectivemask",
                FT_UINT8, BASE_HEX, NULL, 0x38, NULL, HFILL }
        },
        { &hf_opa_PortInfo_MultiCollectMask_MulticastMask, {
                "MultiCollectMask MulticastMask", "opa.portinfo.multicollectmask.multicastmask",
                FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
        },
        { &hf_opa_PortInfo_M_KeyProtectBits, {
                "M_KeyProtectBits", "opa.portinfo.mkeyprotectbits",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_S1_reserved, {
                "Reserved (2 bits)", "opa.portinfo.s1.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x30, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LMC, {
                "LMC", "opa.portinfo.lmc",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_opa_PortInfo_S2_reserved, {
                "Reserved (3 bits)", "opa.portinfo.s2.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_MasterSMSL, {
                "MasterSMSL", "opa.portinfo.mastersml",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LinkInitReason, {
                "LinkInitReason", "opa.portinfo.linkinitreason",
                FT_UINT8, BASE_HEX, VALS(LinkInitReason), 0xF0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PartitionEnforcementInbound, {
                "PartitionEnforcementInbound", "opa.portinfo.partitionenforcementinbound",
                FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PartitionEnforcementOutbound, {
                "PartitionEnforcementOutbound", "opa.portinfo.partitionenforcementoutbound",
                FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL }
        },
        { &hf_opa_PortInfo_S3_reserved2, {
                "Reserved (2 bits)", "opa.portinfo.s3.reserved2",
                FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }
        },
        { &hf_opa_PortInfo_S4_reserved, {
                "Reserved (3 bits)", "opa.portinfo.s4.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_OperationalVL, {
                "OperationalVL", "opa.portinfo.operationalvl",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },
        /* P_Keys */
        { &hf_opa_PortInfo_P_Keys_P_Key_8B, {
                "P_Keys P_Key_8B", "opa.portinfo.pkey8",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_P_Keys_P_Key_10B, {
                "P_Keys P_Key_10B", "opa.portinfo.pkey10",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        { &hf_opa_PortInfo_M_KeyViolations, {
                "M_KeyViolations", "opa.portinfo.m_keyviolations",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_P_KeyViolations, {
                "P_KeyViolations", "opa.portinfo.p_keyviolations",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_Q_KeyViolations, {
                "Q_KeyViolations", "opa.portinfo.q_keyviolations",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        { &hf_opa_PortInfo_TrapQueuePair_reserved, {
                "TrapQueuePair Reserved (8 bits)", "opa.portinfo.trapqpair.reserved",
                FT_UINT32, BASE_HEX, NULL, 0xFF000000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_TrapQueuePair, {
                "TrapQueuePair", "opa.portinfo.trapqpair",
                FT_UINT32, BASE_HEX, NULL, 0x00FFFFFF, NULL, HFILL }
        },
        { &hf_opa_PortInfo_SAQueuePair_reserved, {
                "SAQueuePair Reserved (8 bits)", "opa.portinfo.saqpair.reserved",
                FT_UINT32, BASE_HEX, NULL, 0xFF000000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_SAQueuePair, {
                "SAQueuePair", "opa.portinfo.saqpair",
                FT_UINT32, BASE_HEX, NULL, 0x00FFFFFF, NULL, HFILL }
        },
        { &hf_opa_PortInfo_NeighborPortNum, {
                "NeighborPortNum", "opa.portinfo.neighborportnum",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LinkDownReason, {
                "LinkDownReason", "opa.portinfo.linkdownreason",
                FT_UINT8, BASE_HEX, VALS(LinkDownReason), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_NeighborLinkDownReason, {
                "NeighborLinkDownReason", "opa.portinfo.neighborlinkdownreason",
                FT_UINT8, BASE_HEX, VALS(LinkDownReason), 0x0, NULL, HFILL }
        },

        { &hf_opa_PortInfo_ClientReregister, {
                "Subnet ClientReregister", "opa.portinfo.clientreregister",
                FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_PortInfo_MulticastPKeyTrapSuppressEnabled, {
                "Subnet Multicast PKey Trap Enabled", "opa.portinfo.multicastpkeytrapenabled",
                FT_UINT8, BASE_HEX, NULL, 0x60, NULL, HFILL }
        },
        { &hf_opa_PortInfo_Timeout, {
                "Subnet Timeout", "opa.portinfo.timeout",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LinkSpeedSupported, {
                "LinkSpeedSupported", "opa.portinfo.linkspeedsupported",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_linkspeed), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LinkSpeedEnabled, {
                "LinkSpeedEnabled", "opa.portinfo.linkspeedenabled",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_linkspeed), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LinkSpeedActive, {
                "LinkSpeedActive", "opa.portinfo.linkspeedactive",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_linkspeed), 0x0, NULL, HFILL }
        },

        { &hf_opa_PortInfo_LinkWidthSupported, {
                "LinkWidthSupported", "opa.portinfo.linkwidthsupported",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_linkwidth), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LinkWidthEnabled, {
                "LinkWidthEnabled", "opa.portinfo.linkwidthenabled",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_linkwidth), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LinkWidthActive, {
                "LinkWidthActive", "opa.portinfo.linkwidthactive",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_linkwidth), 0x0, NULL, HFILL }
        },

        { &hf_opa_PortInfo_LinkWidthDowngrade_Supported, {
                "LinkWidthDowngrade Supported", "opa.portinfo.linkwidthdowngradesupported",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_linkwidth), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LinkWidthDowngrade_Enabled, {
                "LinkWidthDowngrade Enabled", "opa.portinfo.linkwidthdowngradeenabled",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_linkwidth), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LinkWidthDowngrade_TxActive, {
                "LinkWidthDowngrade TxActive", "opa.portinfo.linkwidthdowngradetxactive",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_linkwidth), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LinkWidthDowngrade_RxActive, {
                "LinkWidthDowngrade RxActive", "opa.portinfo.linkwidthdowngraderxactive",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_linkwidth), 0x0, NULL, HFILL }
        },
        /* PortLinkMode */
        { &hf_opa_PortInfo_PortLinkMode_reserved, {
                "PortLinkMode Reserved (1 bit)", "opa.portinfo.portlinkmode.reserved",
                FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortLinkMode_Supported, {
                "PortLinkMode Supported", "opa.portinfo.portlinkmode.supported",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_portlinkmode), 0x7C00, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortLinkMode_Enabled, {
                "PortLinkMode Enabled", "opa.portinfo.portlinkmode.enabled",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_portlinkmode), 0x03E0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortLinkMode_Active, {
                "PortLinkMode Active", "opa.portinfo.portlinkmode.active",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_portlinkmode), 0x001F, NULL, HFILL }
        },

        /* PortLTPCRCMode */
        { &hf_opa_PortInfo_PortLTPCRCMode_reserved, {
                "PortLTPCRCMode Reserved (4 bits)", "opa.portinfo.portltpcrc.reserved",
                FT_UINT16, BASE_HEX, NULL, 0xF000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortLTPCRCMode_Supported, {
                "PortLTPCRCMode Supported", "opa.portinfo.portltpcrc.supported",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_portltpcrcmode), 0x0F00, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortLTPCRCMode_Enabled, {
                "PortLTPCRCMode Enabled", "opa.portinfo.portltpcrc.enabled",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_portltpcrcmode), 0x00F0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortLTPCRCMode_Active, {
                "PortLTPCRCMode Active", "opa.portinfo.portltpcrc.active",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_portltpcrcmode), 0x000F, NULL, HFILL }
        },

        /* PortMode */
        { &hf_opa_PortInfo_PortMode, {
                "PortMode", "opa.portinfo.portmode",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortMode_reserved, {
                "Reserved (9 bits)", "opa.portinfo.portmode.reserved",
                FT_UINT16, BASE_HEX, NULL, 0xFF80, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortMode_IsActiveOptimizeEnabled, {
                "IsActiveOptimizeEnabled", "opa.portinfo.portmode.isactiveoptimizeenabled",
                FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortMode_IsPassThroughEnabled, {
                "IsPassThroughEnabled", "opa.portinfo.portmode.ispassthroughenabled",
                FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortMode_IsVLMarkerEnabled, {
                "IsVLMarkerEnabled", "opa.portinfo.portmode.isvlmarkerenabled",
                FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortMode_reserved2, {
                "Reserved (2 bits)", "opa.portinfo.portmode.reserved2",
                FT_UINT16, BASE_HEX, NULL, 0x000C, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortMode_Is16BTrapQueryEnabled, {
                "Is16BTrapQueryEnabled", "opa.portinfo.portmode.is16btrapqueryenabled",
                FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortMode_reserved3, {
                "Reserved (1 bit)", "opa.portinfo.portmode.reserved3",
                FT_UINT16, BASE_HEX, NULL, 0x0001, NULL, HFILL }
        },

        /*PortPacketFormats*/
        { &hf_opa_PortInfo_PortPacketFormats_Supported, {
                "PortPacketFormats Supported", "opa.portinfo.portpacketformats.supported",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_packetformat), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortPacketFormats_Enabled, {
                "PortPacketFormats Enabled", "opa.portinfo.portpacketformats.enabled",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_packetformat), 0x0, NULL, HFILL }
        },
        /* Flit Control*/
        { &hf_opa_PortInfo_FlitControl_Interleave_reserved, {
                "Interleave Reserved (2 bits)", "opa.portinfo.flitcontrol.interleave.reserved",
                FT_UINT16, BASE_HEX, NULL, 0xC000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_FlitControl_Interleave_DistanceSupported, {
                "Interleave DistanceSupported", "opa.portinfo.flitcontrol.interleave.distancesupported",
                FT_UINT16, BASE_HEX, VALS(PortFlitDistanceMode), 0x3000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_FlitControl_Interleave_DistanceEnabled, {
                "Interleave DistanceEnabled", "opa.portinfo.flitcontrol.interleave.distanceenabled",
                FT_UINT16, BASE_HEX, VALS(PortFlitDistanceMode), 0x0C00, NULL, HFILL }
        },
        { &hf_opa_PortInfo_FlitControl_Interleave_MaxNestLevelTxEnabled, {
                "Interleave MaxNestLevelTxEnabled", "opa.portinfo.flitcontrol.interleave.maxnestleveltxenabled",
                FT_UINT16, BASE_HEX, NULL, 0x03E0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_FlitControl_Interleave_MaxNestLevelRxSupported, {
                "Interleave MaxNestLevelRxEnabled", "opa.portinfo.flitcontrol.interleave.maxnestlevelrxenabled",
                FT_UINT16, BASE_HEX, NULL, 0x001F, NULL, HFILL }
        },
        { &hf_opa_PortInfo_FlitControl_Preemption_MinInitial, {
                "Preemption MinInitial", "opa.portinfo.flitcontrol.preemption.mininitial",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_FlitControl_Preemption_MinTail, {
                "Preemption Mintail", "opa.portinfo.flitcontrol.preemption.mintail",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_FlitControl_Preemption_LargePacketLimit, {
                "Preemption LargePacketLimit", "opa.portinfo.flitcontrol.preemption.largepacketlimit",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_FlitControl_Preemption_SmallPacketLimit, {
                "Preemption SmallPacketLimit", "opa.portinfo.flitcontrol.preemption.smallpacketlimit",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_FlitControl_Preemption_MaxSmallPacketLimit, {
                "Preemption MaxSmallPacketLimit", "opa.portinfo.flitcontrol.preemption.maxsmallpacketlimit",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_FlitControl_Preemption_PreemptionLimit, {
                "Preemption PreemptionLimit", "opa.portinfo.flitcontrol.preemption.preemptionlimit",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* PortErrorAction */
        { &hf_opa_PortInfo_PortErrorAction, {
                "PortErrorAction", "opa.portinfo.porterroraction",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_ExcessiveBufferOverrun, {
                "ExcessiveBufferOverrun", "opa.portinfo.porterroraction.excessivebufferoverrun",
                FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_reserved, {
                "Reserved (7 bits)", "opa.portinfo.porterroraction.reserved",
                FT_UINT32, BASE_HEX, NULL, 0x7F000000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_FmConfigErrorExceedMulticastLimit, {
                "FMConfigErrorExceedMulticastLimit", "opa.portinfo.porterroraction.fmconfigerrorexceedmulticastlimit",
                FT_BOOLEAN, 32, NULL, 0x00800000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadControlFlit, {
                "FmConfigErrorBadControlFlit", "opa.portinfo.porterroraction.fmconfigerrorbadcontrolflit",
                FT_BOOLEAN, 32, NULL, 0x00400000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadPreempt, {
                "FmConfigErrorBadPreempt", "opa.portinfo.porterroraction.fmconfigerrorbadpreempt",
                FT_BOOLEAN, 32, NULL, 0x00200000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadVLMarker, {
                "FmConfigErrorBadVLMarker", "opa.portinfo.porterroraction.fmconfigerrorbadvlmarker",
                FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadCrdtAck, {
                "FmConfigErrorBadCrdtAck", "opa.portinfo.porterroraction.fmconfigerrorbadcrdtack",
                FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadCtrlDist, {
                "FmConfigErrorBadCtrlDist", "opa.portinfo.porterroraction.fmconfigerrorbadctrldist",
                FT_BOOLEAN, 32, NULL, 0x00040000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadTailDist, {
                "FmConfigErrorBadTailDist", "opa.portinfo.porterroraction.fmconfigerrorbadtaildist",
                FT_BOOLEAN, 32, NULL, 0x00020000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_FmConfigErrorBadHeadDist, {
                "FmConfigErrorBadHeadDist", "opa.portinfo.porterroraction.fmconfigerrorbadheaddist",
                FT_BOOLEAN, 32, NULL, 0x00010000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_reserved2, {
                "Reserved (2 bits)", "opa.portinfo.porterroraction.reserved2",
                FT_UINT32, BASE_HEX, NULL, 0x0000C000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadVLMarker, {
                "PortRcvErrorBadVLMarker", "opa.portinfo.porterroraction.portrcverrorbadvlmarker",
                FT_BOOLEAN, 32, NULL, 0x00002000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_PortRcvErrorPreemptVL15, {
                "PortRcvErrorPreemptVL15", "opa.portinfo.porterroraction.portrcverrorpreemptvl15",
                FT_BOOLEAN, 32, NULL, 0x00001000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_PortRcvErrorPreemptError, {
                "PortRcvErrorPreemptError", "opa.portinfo.porterroraction.portrcverrorpreempterror",
                FT_BOOLEAN, 32, NULL, 0x00000800, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_reserved3, {
                "Reserved (1 bit)", "opa.portinfo.porterroraction.reserved3",
                FT_UINT32, BASE_HEX, NULL, 0x00000400, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadMidTail, {
                "PortRcvErrorBadMidTail", "opa.portinfo.porterroraction.portrcverrorbadmidtail",
                FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_PortRcvErrorReserved, {
                "PortRcvErrorReserved", "opa.portinfo.porterroraction.portrcverrorreserved",
                FT_UINT32, BASE_HEX, NULL, 0x00000100, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadSC, {
                "PortRcvErrorBadSC", "opa.portinfo.porterroraction.portrcverrorbadsc",
                FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadL2, {
                "PortRcvErrorBadL2", "opa.portinfo.porterroraction.portrcverrorbadl2",
                FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadDLID, {
                "PortRcvErrorBadDLID", "opa.portinfo.porterroraction.portrcverrorbaddlid",
                FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadSLID, {
                "PortRcvErrorBadSLID", "opa.portinfo.porterroraction.portrcverrorbadslid",
                FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_PortRcvErrorPktLenTooShort, {
                "PortRcvErrorPktLenTooShort", "opa.portinfo.porterroraction.portrcverrorpktlentooshort",
                FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_PortRcvErrorPktLenTooLong, {
                "PortRcvErrorPktLenTooLong", "opa.portinfo.porterroraction.portrcverrorpktlentoolong",
                FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_PortRcvErrorBadPktLen, {
                "PortRcvErrorBadPktLen", "opa.portinfo.porterroraction.portrcverrorbadpktlen",
                FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortErrorAction_reserved4, {
                "Reserved (1 bit)", "opa.portinfo.porterroraction.reserved4",
                FT_UINT32, BASE_HEX, NULL, 0x00000001, NULL, HFILL }
        },
        /* PassThroughControl */
        { &hf_opa_PortInfo_PassThroughControl_EgressPort, {
                "PassThroughControl EgressPort", "opa.portinfo.passthroughcontrol.egressport",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        { &hf_opa_PortInfo_PassThroughControl_reserved, {
                "Reserved (7 Bits)", "opa.portinfo.passthroughcontrol.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xFE, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PassThroughControl_DRControl, {
                "PassThroughControl DRControl", "opa.portinfo.passthroughcontrol.drcontrol",
                FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }
        },
        { &hf_opa_PortInfo_M_KeyLeasePeriod, {
                "M_KeyLeasePeriod", "opa.portinfo.m_keyleaseperiod",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_BufferUnits_reserved, {
                "BufferUnits Reserved (9 bits)", "opa.portinfo.bufferunits.reserved",
                FT_UINT32, BASE_HEX, NULL, 0xFF800000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_BufferUnits_VL15Init, {
                "BufferUnits VL15Init", "opa.portinfo.bufferunits.vl15init",
                FT_UINT32, BASE_HEX, NULL, 0x007FF800, NULL, HFILL }
        },
        { &hf_opa_PortInfo_BufferUnits_VL15CreditRate, {
                "BufferUnits VL15Credit", "opa.portinfo.bufferunits.vl15credit",
                FT_UINT32, BASE_HEX, NULL, 0x000007C0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_BufferUnits_CreditAck, {
                "BufferUnits CreditAck", "opa.portinfo.bufferunits.creditack",
                FT_UINT32, BASE_HEX, NULL, 0x00000038, NULL, HFILL }
        },
        { &hf_opa_PortInfo_BufferUnits_BufferAlloc, {
                "BufferUnits BufferAlloc", "opa.portinfo.bufferunits.bufferalloc",
                FT_UINT32, BASE_HEX, NULL, 0x00000007, NULL, HFILL }
        },

        { &hf_opa_PortInfo_MasterSMLID, {
                "MasterSMLID", "opa.portinfo.mastersmlid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_M_Key, {
                "MKey", "opa.portinfo.mkey",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_SubnetPrefix, {
                "SubnetPrefix", "opa.portinfo.subnetprefix",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_VL1, {
                "VL", "opa.portinfo.vl1",
                FT_UINT8, BASE_HEX, VALS(MTU), 0xF0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_VL2, {
                "VL", "opa.portinfo.vl2",
                FT_UINT8, BASE_HEX, VALS(MTU), 0x0F, NULL, HFILL }
        },
        /* XmitQ */
        { &hf_opa_PortInfo_XmitQ_VLStallCount, {
                "VLStallCount", "opa.portinfo.xmitq.vlstallcount",
                FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_XmitQ_HOQLife, {
                "HOQLife", "opa.portinfo.xmitq.hoqlife",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },

        { &hf_opa_PortInfo_IPAddrIPv6, {
                "IPAddr IPv6", "opa.portinfo.ipaddripv6",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_IPAddrIPv4, {
                "IPAddr IPv4", "opa.portinfo.ipaddripv4",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_NeighborNodeGUID, {
                "NeighborNodeGUID", "opa.portinfo.neighbornodeguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* Capability Mask Flags */
        { &hf_opa_PortInfo_CapabilityMask, {
                "CapabilityMask", "opa.portinfo.capabilitymask",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask_reserved, {
                "Reserved (9 bits)", "opa.portinfo.capabilitymask.reserved",
                FT_UINT32, BASE_HEX, NULL, 0xFF800000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask_IsCapabilityMaskNoticeSupported, {
                "IsCapabilityMaskNoticeSupported", "opa.portinfo.capabilitymask.iscapabilitymasknoticesupported",
                FT_BOOLEAN, 32, NULL, 0x00400000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask_reserved2, {
                "Reserved (1 bit)", "opa.portinfo.capabilitymask.reserved2",
                FT_UINT32, BASE_HEX, NULL, 0x00200000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask_IsVendorClassSupported, {
                "IsVendorClassSupported", "opa.portinfo.capabilitymask.isvendorclasssupported",
                FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask_IsDeviceManagementSupported, {
                "IsDeviceManagementSupported", "opa.portinfo.capabilitymask.isdevicemanagementsupported",
                FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask_reserved3, {
                "Reserved (2 bits)", "opa.portinfo.capabilitymask.reserved3",
                FT_UINT32, BASE_HEX, NULL, 0x00060000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask_IsConnectionManagementSupported, {
                "IsConnectionManagementSupported", "opa.portinfo.capabilitymask.isconnectionmanagementsupported",
                FT_BOOLEAN, 32, NULL, 0x00010000, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask_reserved4, {
                "Reserved (10 bits)", "opa.portinfo.capabilitymask.reserved4",
                FT_UINT32, BASE_HEX, NULL, 0x0000FFC0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask_IsAutomaticMigrationSupported, {
                "IsAutomaticMigrationSupported", "opa.portinfo.capabilitymask.isautomaticmigrationsupported",
                FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask_reserved5, {
                "Reserved (3 bits)", "opa.portinfo.capabilitymask.reserved5",
                FT_UINT32, BASE_HEX, NULL, 0x0000001C, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask_IsSM, {
                "IsSM", "opa.portinfo.capabilitymask.issm",
                FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask_reserved6, {
                "Reserved (1 bit)", "opa.portinfo.capabilitymask.reserved6",
                FT_UINT32, BASE_HEX, NULL, 0x00000001, NULL, HFILL }
        },
        /* End Capability Mask Flags */

        /* Capability Mask 3 */
        { &hf_opa_PortInfo_CapabilityMask3, {
                "CapabilityMask3", "opa.portinfo.capabilitymask3",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask3_reserved, {
                "Reserved (8 bits)", "opa.portinfo.capabilitymask3.reserved",
                FT_UINT16, BASE_HEX, NULL, 0xFF00, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask3_IsSnoopSupported, {
                "IsSnoopSupported", "opa.portinfo.capabilitymask3.issnoopsupported",
                FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask3_IsAsyncSCtoVLSupported, {
                "IsAsyncSCtoVLSupported", "opa.portinfo.capabilitymask3.isasyncsc2vlsupported",
                FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask3_IsAddrRangeConfigSupported, {
                "IsAddrRangeConfigSupported", "opa.portinfo.capabilitymask3.isaddrrangeconfigsupported",
                FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask3_IsPassThroughSupported, {
                "IsPassThroughSupported", "opa.portinfo.capabilitymask3.ispassthroughsupported",
                FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask3_IsSharedSpaceSupported, {
                "IsSharedSpaceSupported", "opa.portinfo.capabilitymask3.issharedspacesupported",
                FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask3_reserved2, {
                "IsVLMarkerSupported", "opa.portinfo.capabilitymask3.reserved2",
                FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask3_IsVLMarkerSupported, {
                "IsVLMarkerSupported", "opa.portinfo.capabilitymask3.isvlmarkersupported",
                FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }
        },
        { &hf_opa_PortInfo_CapabilityMask3_IsVLrSupported, {
                "IsVLrSupported", "opa.portinfo.capabilitymask3.isvlrsupported",
                FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }
        },
        /* End Capability Mask3 Flags */

        { &hf_opa_PortInfo_OverallBufferSpace, {
                "OverallBufferSpace", "opa.portinfo.overallbufferspace",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_DiagCode, {
                "DiagCode", "opa.portinfo.diagcode",
                FT_UINT16, BASE_HEX, VALS(DiagCode), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_ReplayDepth_BufferDepth, {
                "Replay BufferDepth", "opa.portinfo.replaydepth.bufferdepth",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_ReplayDepth_WireDepth, {
                "Replay WireDepth", "opa.portinfo.replaydepth.wiredepth",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* PortNeighborNode*/
        { &hf_opa_PortInfo_PortNeighborMode_reserved, {
                "PortNeighborMode Reserved (4 bits)", "opa.portinfo.portneighbormode.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortNeighborMode_MgmtAllowed, {
                "PortNeighborMode MgmtAllowed", "opa.portinfo.portneighbormode.mgmtallowed",
                FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortNeighborMode_NeighborFWAuthenBypass, {
                "PortNeighborMode NeighborFWAuthenBypass", "opa.portinfo.portneighbormode.neighborfwauthenbypass",
                FT_BOOLEAN, 8, TFS(&tfs_NeighborFWAuthenBypass), 0x04, NULL, HFILL }
        },
        { &hf_opa_PortInfo_PortNeighborMode_NeighborNodeType, {
                "PortNeighborMode NeighborNodeType", "opa.portinfo.portneighbormode.neighbornodetype",
                FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }
        },

        /* MTU*/
        { &hf_opa_PortInfo_MTU_reserved, {
                "MTU Reserved (4 bits)", "opa.portinfo.mtu.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_MTU_Cap, {
                "MTU Cap", "opa.portinfo.mtu.cap",
                FT_UINT8, BASE_HEX, VALS(MTU), 0x0F, NULL, HFILL }
        },
        { &hf_opa_PortInfo_Resp_reserved, {
                "Resp Reserved (3 bits)", "opa.portinfo.resp.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_opa_PortInfo_Resp_TimeValue, {
                "Resp TimeValue", "opa.portinfo.resp.timevalue",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },
        { &hf_opa_PortInfo_LocalPortNum, {
                "LocalPortNum", "opa.portinfo.localportnum",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/*******************
* Port State Info *
*******************/

        { &hf_opa_PortStates, {
                "PortStates", "opa.portstates",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStates_reserved, {
                "Reserved (10 bits)", "opa.portstates.reserved",
                FT_UINT32, BASE_HEX, NULL, 0xFF800000, NULL, HFILL }
        },
        { &hf_opa_PortStates_LEDEnabled, {
                "LEDEnabled", "opa.portstates.ledenabled",
                FT_BOOLEAN, 32, NULL, 0x00400000, NULL, HFILL }
        },
        { &hf_opa_PortStates_IsSMConfigurationStarted, {
                "IsSMConfigurationStarted", "opa.portstates.issmconfigurationstarted",
                FT_BOOLEAN, 32, NULL, 0x00200000, NULL, HFILL }
        },
        { &hf_opa_PortStates_NeighborNormal, {
                "NeighborNormal", "opa.portstates.neighbornormal",
                FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL }
        },
        { &hf_opa_PortStates_OfflineDisabledReason, {
                "OfflineDisabledReason", "opa.portstates.offlinedisabledreason",
                FT_UINT32, BASE_HEX, VALS(OfflineDisabledReason), 0x000F0000, NULL, HFILL }
        },
        { &hf_opa_PortStates_PortUnsleepState, {
                "PortUnsleepState", "opa.portstates.portunsleepstates",
                FT_UINT32, BASE_HEX, VALS(PortPhysicalState), 0x0000F000, NULL, HFILL }
        },
        { &hf_opa_PortStates_DownDefaultState, {
                "DownDefaultState", "opa.portstates.downdefaultstate",
                FT_UINT32, BASE_HEX, VALS(PortPhysicalState), 0x00000F00, NULL, HFILL }
        },
        { &hf_opa_PortStates_PortPhysicalState, {
                "PortPhysicalState", "opa.portstates.portphysicalstate",
                FT_UINT32, BASE_HEX, VALS(PortPhysicalState), 0x000000F0, NULL, HFILL }
        },
        { &hf_opa_PortStates_PortState, {
                "PortState", "opa.portstates.portstate",
                FT_UINT32, BASE_HEX, VALS(PortState), 0x0000000F, NULL, HFILL }
        },
        { &hf_opa_PortStates_LinkWidthDowngradeTxActive, {
                "LinkWidthDowngrade TxActive", "opa.portstates.linkwidthdowngradetxactive",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_linkwidth), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStates_LinkWidthDowngradeRxActive, {
                "LinkWidthDowngrade RxActive", "opa.portstates.linkwidthdowngraderxactive",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_linkwidth), 0x0, NULL, HFILL }
        },

/*****************
*  P_KeyTable   *
*****************/

        { &hf_opa_P_KeyTable, {
                "P_Key Table", "opa.p_keytable",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_P_KeyTable_MembershipType, {
                "Membership Type", "opa.p_keytable.membershiptype",
                FT_BOOLEAN, 16, TFS(&tfs_PKeyMembershipType), 0x8000, NULL, HFILL }
        },
        { &hf_opa_P_KeyTable_P_KeyBase, {
                "P_Key Base", "opa.p_keytable.p_keybase",
                FT_UINT16, BASE_HEX, NULL, 0x7FFF, NULL, HFILL }
        },

/**************************
*   SLtoSC Mapping Table   *
**************************/

        { &hf_opa_SLtoSCMappingTable, {
                "SL to SC Mapping Table", "opa.sltoscmappingtable",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SLtoSCMappingTable_SLtoSC_HighBits, {
                "Reserved (3 bits)", "opa.sltoscmappingtable.sltoschighbits",
                FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_opa_SLtoSCMappingTable_SLtoSC_LowBits, {
                "SC", "opa.sltoscmappingtable.sltosclowbits",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },

/**************************
*   SCtoSC Mapping Table   *
**************************/

        { &hf_opa_SCtoSCMappingTable, {
                "SC to SC Mapping Table", "opa.sctoscmappingtable",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SCtoSCMappingTable_SCtoSC_HighBits, {
                "Reserved (3 bits)", "opa.sctoscmappingtable.sctoschighbits",
                FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_opa_SCtoSCMappingTable_SCtoSC_LowBits, {
                "SC", "opa.sctoscmappingtable.sctosclowbits",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },

/**************************
*   SCtoSL Mapping Table   *
**************************/

        { &hf_opa_SCtoSLMappingTable, {
                "SC to SL Mapping Table", "opa.sctoslmappingtable",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SCtoSLMappingTable_SCtoSL_HighBits, {
                "Reserved (3 bits)", "opa.sctoslmappingtable.sctoslhighbits",
                FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_opa_SCtoSLMappingTable_SCtoSL_LowBits, {
                "SL", "opa.sctoslmappingtable.sctosllowbits",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },

/**************************
*   SCtoVLx Mapping Table  *
**************************/

        { &hf_opa_SCtoVLxMappingTable, {
                "SC to VLx Mapping Table", "opa.sctovlxmappingtable",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SCtoVLxMappingTable_SCtoVLx_HighBits, {
                "Reserved (3 bits)", "opa.sctovlxmappingtable.sctovlxhighbits",
                FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_opa_SCtoVLxMappingTable_SCtoVLx_LowBits, {
                "VL", "opa.sctovlxmappingtable.sctovlxlowbits",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },

/**************************
*   VLArbitrationTable   *
**************************/
        { &hf_opa_VLArbitrationTable, {
                "VL Arbitration Table", "opa.vlarbitrationtable",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_VLArbitrationTable_reserved, {
                "Reserved (3 bits)", "opa.vlarbitrationtable.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_opa_VLArbitrationTable_VL, {
                "VL", "opa.vlarbitrationtable.vl",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },
        { &hf_opa_VLArbitrationTable_Weight, {
                "Weight", "opa.vlarbitrationtable.weight",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_VLArbitrationTable_Matrix, {
                "Element", "opa.vlarbitrationtable.matrix",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/*************************
* LinearForwardingTable *
*************************/

        { &hf_opa_LinearForwardingTable, {
                "Linear Forwarding Table", "opa.linearforwardingtable",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_LinearForwardingTable_Port, {
                "Port", "opa.linearforwardingtable.port",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/****************************
* MulticastForwardingTable *
****************************/

        { &hf_opa_MulticastForwardingTable, {
                "Multicast Forwarding Table", "opa.multicastforwardingtable",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MulticastForwardingTable_PortMask, {
                "Port Mask", "opa.multicastforwardingtable.portmask",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/****************************
* PortGroupForwardingTable *
****************************/

        { &hf_opa_PortGroupForwardingTable, {
                "Port Group Forwarding Table", "opa.portgroupforwardingtable",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortGroupForwardingTable_Port, {
                "Port", "opa.portgroupforwardingtable.port",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/******************
* PortGroupTable *
******************/

        { &hf_opa_PortGroupTable, {
                "Port Group Table", "opa.portgrouptable",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortGroupTable_PortMask, {
                "Port Mask", "opa.portgrouptable.portmask",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/**********
* SMInfo *
**********/

        { &hf_opa_SMInfo, {
                "SM Info", "opa.sminfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SMInfo_GUID, {
                "GUID", "opa.sminfo.guid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SMInfo_SM_Key, {
                "SM_Key", "opa.sminfo.sm_key",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SMInfo_ActCount, {
                "ActCount", "opa.sminfo.actcount",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SMInfo_ElapsedTime, {
                "ElapsedTime", "opa.sminfo.elapsedtime",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SMInfo_Priority, {
                "Priority", "opa.sminfo.priority",
                FT_UINT16, BASE_HEX, NULL, 0xF000, NULL, HFILL }
        },
        { &hf_opa_SMInfo_ElevatedPriority, {
                "ElevatedPriority", "opa.sminfo.elevatedpriority",
                FT_UINT16, BASE_HEX, NULL, 0x0F00, NULL, HFILL }
        },
        { &hf_opa_SMInfo_InitialPriority, {
                "InitialPriority", "opa.sminfo.initialpriority",
                FT_UINT16, BASE_HEX, NULL, 0x00F0, NULL, HFILL }
        },
        { &hf_opa_SMInfo_SMState, {
                "SMState", "opa.sminfo.smstate",
                FT_UINT16, BASE_HEX, NULL, 0x000F, NULL, HFILL }
        },

/***********
* LedInfo *
***********/

        { &hf_opa_LedInfo, {
                "Led Info", "opa.ledinfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_LedInfo_LedMask, {
                "LedMask", "opa.ledinfo.ledmask",
                FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL }
        },
        { &hf_opa_LedInfo_reserved, {
                "Reserved (31 bits)", "opa.ledinfo.reserved",
                FT_UINT32, BASE_HEX, NULL, 0x7FFFFFFF, NULL, HFILL }
        },

/************
* CableInfo *
*************/

        { &hf_opa_CableInfo, {
                "Cable Info", "opa.cableinfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_CableInfo_Data, {
                "Data", "opa.cableinfo.data",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_CableInfo_DataStream, {
                "Data", "opa.cableinfo.datastream",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

/************
* Aggregate *
*************/

        { &hf_opa_Aggregate, {
                "Aggregate", "opa.aggregate",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_Aggregate_AttributeID, {
                "Attribute ID", "opa.aggregate.attrid",
                FT_UINT16, BASE_HEX, VALS(SUBM_Attributes), 0x0, NULL, HFILL }
        },
        { &hf_opa_Aggregate_Error, {
                "Error", "opa.aggregate.error",
                FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }
        },
        { &hf_opa_Aggregate_RequestLength, {
                "Request Length", "opa.aggregate.requestlength",
                FT_UINT16, BASE_DEC, NULL, 0x007F, NULL, HFILL }
        },

/*********************
* BufferControlTable *
**********************/

        { &hf_opa_BufferControlTable, {
                "Buffer Control Table", "opa.buffercontroltable",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_BufferControlTable_TxOverallSharedLimit, {
                "Tx Overall Shared Limit", "opa.buffercontroltable.txoverallsharedlimit",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_BufferControlTable_TxDedicatedLimit, {
                "Tx Dedicated Limit", "opa.buffercontroltable.txdedicatedlimit",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_BufferControlTable_TxSharedLimit, {
                "Tx Shared Limit", "opa.buffercontroltable.txsharedlimit",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
/*******************
* FabricInfoRecord *
********************/

        { &hf_opa_FabricInfoRecord, {
                "Fabric Info Record", "opa.fabricinforecord",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_FabricInfoRecord_NumHFIs, {
                "Num HFIs", "opa.fabricinforecord.numhfis",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_FabricInfoRecord_NumSwitches, {
                "Num Switches", "opa.fabricinforecord.numswitches",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_FabricInfoRecord_NumInternalHFILinks, {
                "Num Internal HFI Links", "opa.fabricinforecord.numinternalhfilinks",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_FabricInfoRecord_NumExternalHFILinks, {
                "Num External HFI Links", "opa.fabricinforecord.numexternalhfilinks",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_FabricInfoRecord_NumInternalISLs, {
                "Num Internal ISLs", "opa.fabricinforecord.numinternalisls",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_FabricInfoRecord_NumExternalISLs, {
                "Num External ISLs", "opa.fabricinforecord.numexternalisls",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_FabricInfoRecord_NumDegradedHFILinks, {
                "Num Degraded HFI Links", "opa.fabricinforecord.numdegradedhfilinks",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_FabricInfoRecord_NumDegradedISLs, {
                "Num Degraded ISLs", "opa.fabricinforecord.numdegradedisls",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_FabricInfoRecord_NumOmittedHFILinks, {
                "Num Omitted HFI Links", "opa.fabricinforecord.numomittedhfilinks",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_FabricInfoRecord_NumOmittedISLs, {
                "Num Omitted ISLs", "opa.fabricinforecord.numomittedisls",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_FabricInfoRecord_Reserved, {
                "Reserved (92 Bytes)", "opa.fabricinforecord.reserved",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

/*****************
* CongestionInfo *
******************/

        { &hf_opa_CongestionInfo, {
                "Congestion Info", "opa.congestioninfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_CongestionInfo_CongestionInfo, {
                "Congestion Info", "opa.congestioninfo.congestioninfo",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_CongestionInfo_ControlTableCap, {
                "Control Table Cap", "opa.congestioninfo.controltablecap",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_CongestionInfo_CongestionLogLength, {
                "Congestion Log Length", "opa.congestioninfo.congestionloglength",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/***********************
* SwitchCongestionLog *
***********************/

        { &hf_opa_SwitchCongestionLog, {
                "Switch Congestion Log", "opa.switchcongestionlog",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionLog_LogType, {
                "Log Type", "opa.switchcongestionlog.logtype",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionLog_CongestionFlags, {
                "Congestion Flags", "opa.switchcongestionlog.congestionflags",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionLog_LogEventsCounter, {
                "Log Events Counter", "opa.switchcongestionlog.logeventscounter",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionLog_CurrentTimeStamp, {
                "Current Time Stamp", "opa.switchcongestionlog.currenttimestamp",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionLog_PortMap, {
                "Port Map", "opa.switchcongestionlog.portmap",
                FT_BYTES, FT_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionLog_SLID, {
                "SLID", "opa.switchcongestionlog.slid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionLog_DLID, {
                "DLID", "opa.switchcongestionlog.dlid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionLog_SC, {
                "SC", "opa.switchcongestionlog.sc",
                FT_UINT8, BASE_HEX, NULL, 0xF8, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionLog_reserved, {
                "Reserved (3 bits)", "opa.switchcongestionlog.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionLog_TimeStamp, {
                "Time Stamp", "opa.switchcongestionlog.timestamp",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/***************************
* SwitchCongestionSetting *
***************************/

        { &hf_opa_SwitchCongestionSetting, {
                "Switch Congestion Setting", "opa.switchcongestionsetting",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionSetting_Control_Map, {
                "Control Map", "opa.switchcongestionsetting.controlmap",
                FT_UINT32, BASE_CUSTOM, CF_FUNC(cf_opa_mad_swcongestionsetting_controlmap), 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionSetting_Victim_Mask, {
                "Victim Mask", "opa.switchcongestionsetting.victimmask",
                FT_BYTES, FT_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionSetting_Credit_Mask, {
                "Credit Mask", "opa.switchcongestionsetting.creditmask",
                FT_BYTES, FT_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionSetting_Threshold, {
                "Threshold", "opa.switchcongestionsetting.threshold",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionSetting_reserved1, {
                "Reserved (4 bits)", "opa.switchcongestionsetting.reserved1",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionSetting_Packet_Size, {
                "Packet Size", "opa.switchcongestionsetting.packetsize",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionSetting_CS_Threshold, {
                "CS Threshold", "opa.switchcongestionsetting.csthreshold",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionSetting_reserved2, {
                "Reserved (4 bits)", "opa.switchcongestionsetting.reserved2",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionSetting_CS_ReturnDelay, {
                "CS ReturnDelay", "opa.switchcongestionsetting.csreturndelay",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchCongestionSetting_Marking_Rate, {
                "Marking Rate", "opa.switchcongestionsetting.markingrate",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/*******************************
* SwitchPortCongestionSetting *
*******************************/

        { &hf_opa_SwitchPortCongestionSetting, {
                "Switch Port Congestion Setting", "opa.switchportcongestionsetting",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchPortCongestionSetting_Valid, {
                "Valid", "opa.switchportcongestionsetting.valid",
                FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x80, NULL, HFILL }
        },
        { &hf_opa_SwitchPortCongestionSetting_Control_Type, {
                "Control Type", "opa.switchportcongestionsetting.controltype",
                FT_BOOLEAN, 8, TFS(&tfs_SwPortCongSetting_CtrlType), 0x40, NULL, HFILL }
        },
        { &hf_opa_SwitchPortCongestionSetting_reserved, {
                "Reserved (2 bits)", "opa.switchportcongestionsetting.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x30, NULL, HFILL }
        },
        { &hf_opa_SwitchPortCongestionSetting_Threshold, {
                "Threshold", "opa.switchportcongestionsetting.threshold",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_opa_SwitchPortCongestionSetting_Packet_Size, {
                "Packet Size", "opa.switchportcongestionsetting.packetsize",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_SwitchPortCongestionSetting_Marking_Rate, {
                "Marking Rate", "opa.switchportcongestionsetting.markingrate",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/********************
* HFICongestionLog *
********************/

        { &hf_opa_HFICongestionLog, {
                "HFI Congestion Log", "opa.hficongestionlog",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionLog_LogType, {
                "Log Type", "opa.hficongestionsetting.logtype",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionLog_CongestionFlags, {
                "Congestion Flags", "opa.hficongestionsetting.congestionflags",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionLog_ThresholdEventCounter, {
                "Threshold Event Counter", "opa.hficongestionsetting.thresholdeventcounter",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionLog_CurrentTimeStamp, {
                "Current Time Stamp", "opa.hficongestionsetting.currenttimestamp",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionLog_ThresholdCongestionEventMap, {
                "Threshold Congestion Event Map", "opa.hficongestionsetting.thresholdcongestioneventmap",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionLog_Local_QP_CN_Entry, {
                "Local QP CN Entry", "opa.hficongestionsetting.localqpcnentry",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionLog_Remote_QP_Number_CN_Entry, {
                "Remote QP Number CN Entry", "opa.hficongestionsetting.remoteqpnumbercnentry",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionLog_SL_CN_Entry, {
                "Threshold Congestion Event Map", "opa.hficongestionsetting.thresholdcongestioneventmap",
                FT_UINT8, BASE_HEX, NULL, 0xF8, NULL, HFILL }
        },
        { &hf_opa_HFICongestionLog_Service_Type_CN_Entry, {
                "Service Type CN Entry", "opa.hficongestionsetting.servicetypecnentry",
                FT_UINT8, BASE_HEX, NULL, 0x0E, NULL, HFILL }
        },
        { &hf_opa_HFICongestionLog_Remote_LID_CN_Entry, {
                "LID CN Entry", "opa.hficongestionsetting.lidcnentry",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionLog_TimeStamp_CN_Entry, {
                "TimeStamp CN Entry", "opa.hficongestionsetting.timestampcnentry",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/************************
* HFICongestionSetting *
************************/

        { &hf_opa_HFICongestionSetting, {
                "HFI Congestion Setting", "opa.hficongestionsetting",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionSetting_Control_Map, {
                "Control Map", "opa.hficongestionsetting.controlmap",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionSetting_Port_Control, {
                "Port Control", "opa.hficongestionsetting.portcontrol",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionSetting_CCTI_Increase, {
                "CCTI Increase", "opa.hficongestionsetting.cctiincrease",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionSetting_CCTI_Timer, {
                "CCTI Timer", "opa.hficongestionsetting.cctitimer",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionSetting_TriggerThreshold, {
                "Trigger Threshold", "opa.hficongestionsetting.triggerthreshold",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionSetting_CCTI_Min, {
                "CCTI Min", "opa.hficongestionsetting.cctimin",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/*****************************
* HFICongestionControlTable *
*****************************/

        { &hf_opa_HFICongestionControlTable, {
                "HFI Congestion Control Table", "opa.hficongestioncontroltable",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionControlTable_CCTI_Limit, {
                "CCTI Limit", "opa.hficongestioncontroltable.cctilimit",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_HFICongestionControlTable_CCT_Shift, {
                "CCT Shift", "opa.hficongestioncontroltable.cctshift",
                FT_UINT16, BASE_HEX, NULL, 0xC000, NULL, HFILL }
        },
        { &hf_opa_HFICongestionControlTable_CCT_Multiplier, {
                "CCT Multiplier", "opa.hficongestioncontroltable.cctmultiplier",
                FT_UINT16, BASE_HEX, NULL, 0x3FFF, NULL, HFILL }
        },

/* SA */
        { &hf_opa_PortInfoRecord_LinkDownReason_NeighborLinkDownReason, {
                "Neighbor Link Down Reason", "opa.portinforecord.linkdownreason.neighborlinkdownreason",
                FT_UINT8, BASE_HEX, VALS(LinkDownReason), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfoRecord_LinkDownReason_LinkDownReason, {
                "Link Down Reason", "opa.portinforecord.linkdownreason.linkdownreason",
                FT_UINT8, BASE_HEX, VALS(LinkDownReason), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortInfoRecord_LinkDownReason_Timestamp, {
                "Time Stamp", "opa.portinforecord.linkdownreason.timestamp",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* InformInfoRecord */
        /* InformInfo */
        { &hf_opa_InformInfo, {
                "Inform Info", "opa.informinfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_InformInfo_GID, {
                "GID", "opa.informinfo.gid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_InformInfo_LIDRangeBegin, {
                "LID Range Begin", "opa.informinfo.lidrangebegin",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_InformInfo_LIDRangeEnd, {
                "LID Range End", "opa.informinfo.lidrangeend",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_InformInfo_IsGeneric, {
                "Is Generic", "opa.informinfo.isgeneric",
                FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }
        },
        { &hf_opa_InformInfo_Subscribe, {
                "Subscribe", "opa.informinfo.subscribe",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_InformInfo_Type, {
                "Type", "opa.informinfo.type",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_InformInfo_TrapNumber, {
                "Trap Number", "opa.informinfo.trapnumber",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_InformInfo_DeviceID, {
                "Device ID", "opa.informinfo.deviceid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_InformInfo_QPN, {
                "QPN", "opa.informinfo.qpn",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_InformInfo_reserved, {
                "Reserved (3 bits)", "opa.informinfo.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_opa_InformInfo_RespTimeValue, {
                "Resp Time Value", "opa.informinfo.resptimevalue",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },
        { &hf_opa_InformInfo_ProducerType, {
                "Producer Type", "opa.informinfo.producertype",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_InformInfo_VendorID, {
                "Vendor ID", "opa.informinfo.vendorid",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* LinkRecord */
        { &hf_opa_LinkRecord, {
                "Link Record", "opa.linkrecord",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_LinkRecord_ToPort, {
                "To Port", "opa.linkrecord.toport",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_LinkRecord_ToLID, {
                "To LID", "opa.linkrecord.tolid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* ServiceRecord */
        { &hf_opa_ServiceRecord, {
                "Service Record", "opa.servicerecord",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ServiceRecord_ServiceLease, {
                "ServiceLease", "opa.servicerecord.servicelease",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ServiceRecord_ServiceKey, {
                "ServiceKey", "opa.servicerecord.servicekey",
                FT_BYTES, FT_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ServiceRecord_ServiceName, {
                "ServiceName", "opa.servicerecord.servicename",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ServiceRecord_ServiceData, {
                "ServiceData", "opa.servicerecord.servicedata",
                FT_BYTES, FT_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* ServiceAssociationRecord */
        { &hf_opa_ServiceAssociationRecord_ServiceKey, {
                "ServiceKey", "opa.serviceassociationrecord.servicekey",
                FT_BYTES, FT_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ServiceAssociationRecord_ServiceName, {
                "ServiceName", "opa.serviceassociationrecord.servicename",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

/**************
* PathRecord *
**************/
        { &hf_opa_PathRecord, {
                "Path Record", "opa.pathrecord",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PathRecord_DGID, {
                "DGID", "opa.pathrecord.dgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PathRecord_SGID, {
                "SGID", "opa.pathrecord.sgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PathRecord_DLID, {
                "DLID", "opa.pathrecord.dlid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PathRecord_SLID, {
                "SLID", "opa.pathrecord.slid",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PathRecord_RawTraffic, {
                "Raw Traffic", "opa.pathrecord.rawtraffic",
                FT_UINT32, BASE_HEX, NULL, 0x80000000, NULL, HFILL }
        },
        { &hf_opa_PathRecord_reserved, {
                "Reserved (3 bits)", "opa.pathrecord.reserved",
                FT_UINT32, BASE_HEX, NULL, 0x70000000, NULL, HFILL }
        },
        { &hf_opa_PathRecord_FlowLabel, {
                "Flow Label", "opa.pathrecord.flowlabel",
                FT_UINT32, BASE_HEX, NULL, 0x0FFFFF00, NULL, HFILL }
        },
        { &hf_opa_PathRecord_HopLimit, {
                "Hop Limit", "opa.pathrecord.hoplimit",
                FT_UINT32, BASE_HEX, NULL, 0x000000FF, NULL, HFILL }
        },
        { &hf_opa_PathRecord_TClass, {
                "T Class", "opa.pathrecord.tclass",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PathRecord_Reversible, {
                "Reversible", "opa.pathrecord.reversible",
                FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_PathRecord_NumbPath, {
                "Numb Path", "opa.pathrecord.numbpath",
                FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }
        },
        { &hf_opa_PathRecord_P_Key, {
                "P_Key", "opa.pathrecord.p_key",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PathRecord_QosType, {
                "Qos Type", "opa.pathrecord.qostype",
                FT_UINT16, BASE_HEX, NULL, 0xC000, NULL, HFILL }
        },
        { &hf_opa_PathRecord_reserved2, {
                "Reserved (2 bits)", "opa.pathrecord.reserved2",
                FT_UINT16, BASE_HEX, NULL, 0x3000, NULL, HFILL }
        },
        { &hf_opa_PathRecord_QosPriority, {
                "Qos Priority", "opa.pathrecord.qospriority",
                FT_UINT16, BASE_HEX, NULL, 0x0FF0, NULL, HFILL }
        },
        { &hf_opa_PathRecord_SL, {
                "SL", "opa.pathrecord.sl",
                FT_UINT16, BASE_HEX, NULL, 0x000F, NULL, HFILL }
        },
        { &hf_opa_PathRecord_MTUSelector, {
                "MTU Selector", "opa.pathrecord.mtuselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_PathRecord_MTU, {
                "MTU", "opa.pathrecord.mtu",
                FT_UINT8, BASE_HEX, VALS(MTU), 0x3F, NULL, HFILL }
        },
        { &hf_opa_PathRecord_RateSelector, {
                "Rate Selector", "opa.pathrecord.rateselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_PathRecord_Rate, {
                "Rate", "opa.pathrecord.rate",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_opa_PathRecord_PacketLifeTimeSelector, {
                "Packet Life Time Selector", "opa.pathrecord.packetlifetimeselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_PathRecord_PacketLifeTime, {
                "Packet Life Time", "opa.pathrecord.packetlifetime",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_opa_PathRecord_Preference, {
                "Preference", "opa.pathrecord.preference",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/******************
* MCMemberRecord *
******************/

        { &hf_opa_MCMemberRecord, {
                "MC Member Record", "opa.mcmemberrecord",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_Q_Key, {
                "Q_Key", "opa.mcmemberrecord.q_key",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_MLID, {
                "MLID", "opa.mcmemberrecord.mlid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_MTUSelector, {
                "MTU Selector", "opa.mcmemberrecord.mtuselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_MTU, {
                "MTU", "opa.mcmemberrecord.mtu",
                FT_UINT8, BASE_HEX, VALS(MTU), 0x3F, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_TClass, {
                "T Class", "opa.mcmemberrecord.tclass",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_P_Key, {
                "P_Key", "opa.mcmemberrecord.p_key",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_RateSelector, {
                "Rate Selector", "opa.mcmemberrecord.rateselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_Rate, {
                "Rate", "opa.mcmemberrecord.rate",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_PacketLifeTimeSelector, {
                "Packet Life Time Selector", "opa.mcmemberrecord.packetlifetimeselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_PacketLifeTime, {
                "Packet Life Time", "opa.mcmemberrecord.packetlifetime",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_SL, {
                "SL", "opa.mcmemberrecord.sl",
                FT_UINT32, BASE_HEX, NULL, 0xF8000000, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_reserved, {
                "Reserved (19 bits)", "opa.mcmemberrecord.reserved",
                FT_UINT32, BASE_HEX, NULL, 0x07FFFF00, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_HopLimit, {
                "Hop Limit", "opa.mcmemberrecord.hoplimit",
                FT_UINT32, BASE_HEX, NULL, 0x000000FF, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_Scope, {
                "Scope", "opa.mcmemberrecord.scope",
                FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_reserved2, {
                "Reserved (1 bit)", "opa.mcmemberrecord.reserved2",
                FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_JoinSendOnlyMember, {
                "Join Send Only Member", "opa.mcmemberrecord.joinsendonlymember",
                FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_JoinNonMember, {
                "Join Non Member", "opa.mcmemberrecord.joinnonmember",
                FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_JoinFullMember, {
                "Join Full Member", "opa.mcmemberrecord.joinfullmember",
                FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_ProxyJoin, {
                "Proxy Join", "opa.mcmemberrecord.proxyjoin",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_MCMemberRecord_reserved3, {
                "Reserved (7 bits)", "opa.mcmemberrecord.reserved3",
                FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }
        },

        /* TraceRecord */
        { &hf_opa_TraceRecord, {
                "Trace Record", "opa.tracerecord",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_TraceRecord_IDGeneration, {
                "ID Generation", "opa.tracerecord.idgeneration",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_TraceRecord_NodeType, {
                "Node Type", "opa.tracerecord.nodetype",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_TraceRecord_NodeID, {
                "Node ID", "opa.tracerecord.nodeid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_TraceRecord_ChassisID, {
                "Chassis ID", "opa.tracerecord.chassisid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_TraceRecord_EntryPortID, {
                "Entry Port ID", "opa.tracerecord.entryportid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_TraceRecord_ExitPortID, {
                "Exit Port ID", "opa.tracerecord.exitportid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_TraceRecord_EntryPort, {
                "Entry Port", "opa.tracerecord.entryport",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_TraceRecord_ExitPort, {
                "Exit Port", "opa.tracerecord.exitport",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/*******************
* MultiPathRecord *
*******************/

        { &hf_opa_MultiPathRecord, {
                "Multi Path Record", "opa.multipathrecord",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_reserved, {
                "Reserved (4 bits)", "opa.multipathrecord.reserved",
                FT_UINT32, BASE_HEX, NULL, 0xF0000000, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_FlowLabel, {
                "Flow Label", "opa.multipathrecord.flowlabel",
                FT_UINT32, BASE_HEX, NULL, 0x0FFFFF00, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_HopLimit, {
                "Hop Limit", "opa.multipathrecord.hoplimit",
                FT_UINT32, BASE_HEX, NULL, 0x000000FF, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_TClass, {
                "T Class", "opa.multipathrecord.tclass",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_Reversible, {
                "Reversible", "opa.multipathrecord.reversible",
                FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_NumbPath, {
                "Numb Path", "opa.multipathrecord.numbpath",
                FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_P_Key, {
                "P_Key", "opa.multipathrecord.p_key",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_QoSType, {
                "QoS Type", "opa.multipathrecord.qostype",
                FT_UINT16, BASE_HEX, NULL, 0xC000, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_QoSPriority, {
                "QoS Priority", "opa.multipathrecord.qospriority",
                FT_UINT16, BASE_HEX, NULL, 0x3FC0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_reserved2, {
                "Reserved (1 bit)", "opa.multipathrecord.reserved2",
                FT_UINT16, BASE_HEX, NULL, 0x0020, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_SL, {
                "SL", "opa.multipathrecord.sl",
                FT_UINT16, BASE_HEX, NULL, 0x001F, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_MTUSelector, {
                "MTU Selector", "opa.multipathrecord.mtuselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_MTU, {
                "MTU", "opa.multipathrecord.mtu",
                FT_UINT8, BASE_HEX, VALS(MTU), 0x3F, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_RateSelector, {
                "Rate Selector", "opa.multipathrecord.rateselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_Rate, {
                "Rate", "opa.multipathrecord.rate",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_PacketLifeTimeSelector, {
                "Packet Life Time Selector", "opa.multipathrecord.packetlifetimeselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_PacketLifeTime, {
                "Packet Life Time", "opa.multipathrecord.packetlifetime",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_IndependenceSelector, {
                "Independence Selector", "opa.multipathrecord.independenceselector",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_SGIDScope, {
                "SGID Scope", "opa.multipathrecord.sgidscope",
                FT_UINT8, BASE_HEX, NULL, 0x38, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_DGIDScope, {
                "DGID Scope", "opa.multipathrecord.dgidscope",
                FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_SGIDCount, {
                "SGID Count", "opa.multipathrecord.sgidcount",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_DGIDCount, {
                "DGID Count", "opa.multipathrecord.dgidcount",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_SGID, {
                "Source GID", "opa.multipathrecord.sgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_DGID, {
                "Dest GID", "opa.multipathrecord.dgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_L2_8B, {
                "8B Support", "opa.multipathrecord.l2_8b",
                FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_L2_10B, {
                "10B Support", "opa.multipathrecord.l2_10b",
                FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_L2_9B, {
                "9B Support", "opa.multipathrecord.l2_9b",
                FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_L2_16B, {
                "16B Support", "opa.multipathrecord.l2_16b",
                FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_reserved3, {
                "Reserved (4 bits)", "opa.multipathrecord.reserved3",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },

        /* GUID */
        { &hf_opa_MultiPathRecord_ServiceID, {
                "Service ID", "opa.multipathrecord.serviceid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_SubnetPrefix, {
                "SubnetPrefix", "opa.multipathrecord.subnetprefix",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_SGUIDScope, {
                "SGUIDScope", "opa.multipathrecord.sguidscope",
                FT_UINT8, BASE_HEX, NULL, 0x38, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_DGUIDScope, {
                "DGUIDScope", "opa.multipathrecord.dguidscope",
                FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_SGUIDCount, {
                "SGUIDCount", "opa.multipathrecord.sguidcount",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_DGUIDCount, {
                "DGUIDCount", "opa.multipathrecord.dguidcount",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_SGUID, {
                "Source GUID", "opa.multipathrecord.sguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_DGUID, {
                "Dest GUID", "opa.multipathrecord.dguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        /* LID */
        { &hf_opa_MultiPathRecord_SLIDCount, {
                "SLIDCount", "opa.multipathrecord.slidcount",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_DLIDCount, {
                "DLIDCount", "opa.multipathrecord.dlidcount",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_SLID, {
                "Source LID", "opa.multipathrecord.slid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MultiPathRecord_DLID, {
                "Dest LID", "opa.multipathrecord.dlid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

/*******************
* CableInfoRecord *
*******************/

        { &hf_opa_CableInfoRecord, {
                "Cable Info Record", "opa.cableinforecord",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_CableInfoRecord_Lid, {
                "LID", "opa.cableinforecord.lid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_CableInfoRecord_Port, {
                "Port", "opa.cableinforecord.port",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_CableInfoRecord_Length, {
                "Length", "opa.cableinforecord.length",
                FT_UINT8, BASE_DEC, NULL, 0xFE, NULL, HFILL }
        },
        { &hf_opa_CableInfoRecord_reserved, {
                "Reserved (1 bit)", "opa.cableinforecord.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }
        },
        { &hf_opa_CableInfoRecord_Address, {
                "Address", "opa.cableinforecord.address",
                FT_UINT16, BASE_HEX, NULL, 0xFFF0, NULL, HFILL }
        },
        { &hf_opa_CableInfoRecord_PortType, {
                "PortType", "opa.cableinforecord.porttype",
                FT_UINT16, BASE_HEX, VALS(PortType), 0x000F, NULL, HFILL }
        },
        { &hf_opa_CableInfoRecord_Data, {
                "Data", "opa.cableinforecord.data",
                FT_BYTES, FT_NONE, NULL, 0x0, NULL, HFILL }
        },

/**************
* PortStatus *
**************/

        { &hf_opa_PortStatus, {
                "Port Status", "opa.pm.portstatus",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortNumber, {
                "Port Number", "opa.pm.portstatus.portnumber",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_VLSelectMask, {
                "VL Select Mask", "opa.pm.portstatus.vlselectmask",
                FT_UINT32, BASE_CUSTOM, CF_FUNC(cf_opa_mad_32b_mask), 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortXmitData, {
                "PortXmitData", "opa.pm.portstatus.portxmitdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortRcvData, {
                "PortRcvData", "opa.pm.portstatus.portrcvdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortXmitPkts, {
                "PortXmitPkts", "opa.pm.portstatus.portxmitpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortRcvPkts, {
                "PortRcvPkts", "opa.pm.portstatus.portrcvpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortMulticastXmitPkts, {
                "PortMulticastXmitPkts", "opa.pm.portstatus.portmulticastxmitpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortMulticastRcvPkts, {
                "PortMulticastRcvPkts", "opa.pm.portstatus.portmulticastrcvpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortXmitWait, {
                "PortXmitWait", "opa.pm.portstatus.portxmitwait",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_SwPortCongestion, {
                "SwPortCongestion", "opa.pm.portstatus.swportcongestion",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortRcvFECN, {
                "PortRcvFECN", "opa.pm.portstatus.portrecvfecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortRcvBECN, {
                "PortRcvBECN", "opa.pm.portstatus.portrecvbecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortXmitTimeCong, {
                "PortXmitTimeCong", "opa.pm.portstatus.portxmittimecong",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortXmitWastedBW, {
                "PortXmitWastedBW", "opa.pm.portstatus.portxmitwastedbw",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortXmitWaitData, {
                "PortXmitWaitData", "opa.pm.portstatus.portxmitwaitdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortRcvBubble, {
                "PortRcvBubble", "opa.pm.portstatus.portrcvbubble",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortMarkFECN, {
                "PortMarkFECN", "opa.pm.portstatus.portmarkfecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortRcvConstraintErrors, {
                "PortRcvConstraintErrors", "opa.pm.portstatus.portrcvconstrainterrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortRcvSwitchRelayErrors, {
                "PortRcvSwitchRelayErrors", "opa.pm.portstatus.portrcvswitchrelayerrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortXmitDiscards, {
                "PortXmitDiscards", "opa.pm.portstatus.portxmitdiscards",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortXmitConstraintErrors, {
                "PortXmitConstraintErrors", "opa.pm.portstatus.portxmitconstrainterrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortRcvRemotePhysicalErrors, {
                "PortRcvRemotePhysicalErrors", "opa.pm.portstatus.portrcvremotephysicalerrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_LocalLinkIntegrityErrors, {
                "LocalLinkIntegrityErrors", "opa.pm.portstatus.locallinkintegrityerrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortRcvErrors, {
                "PortRcvErrors", "opa.pm.portstatus.portrcverrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_ExcessiveBufferOverruns, {
                "ExcessiveBufferOverruns", "opa.pm.portstatus.excessivebufferoverruns",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_FMConfigErrors, {
                "FMConfigErrors", "opa.pm.portstatus.fmconfigerrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_LinkErrorRecovery, {
                "LinkErrorRecovery", "opa.pm.portstatus.linkerrorrecovery",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_LinkDowned, {
                "LinkDowned", "opa.pm.portstatus.linkdowned",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_UncorrectableErrors, {
                "UncorrectableErrors", "opa.pm.portstatus.uncorrectableerrors",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_reserved, {
                "Reserved", "opa.pm.portstatus.reserved",
                FT_UINT8, BASE_DEC, NULL, 0xF8, NULL, HFILL }
        },
        { &hf_opa_PortStatus_LinkQualityIndicator, {
                "LinkQualityIndicator", "opa.pm.portstatus.linkqualityindicator",
                FT_UINT8, BASE_DEC, VALS(LinkQualityIndicator), 0x07, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLXmitData, {
                "PortVLXmitData", "opa.pm.portstatus.vl.xmitdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLRcvData, {
                "PortVLRcvData", "opa.pm.portstatus.vl.rcvdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLXmitPkts, {
                "PortVLXmitPkts", "opa.pm.portstatus.vl.xmitpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLRcvPkts, {
                "PortVLRcvPkts", "opa.pm.portstatus.vl.rcvpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLXmitWait, {
                "PortVLXmitWait", "opa.pm.portstatus.vl.xmitwait",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_SwPortVLCongestion, {
                "SwPortVLCongestion", "opa.pm.portstatus.vl.swcongestion",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLRcvFECN, {
                "PortVLRcvFECN", "opa.pm.portstatus.vl.rcvfecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLRcvBECN, {
                "PortVLRcvBECN", "opa.pm.portstatus.vl.rcvbecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLXmitTimeCong, {
                "PortVLXmitTimeCong", "opa.pm.portstatus.vl.xmittimecong",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLXmitWastedBW, {
                "PortVLXmitWastedBW", "opa.pm.portstatus.vl.xmitwastedbw",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLXmitWaitData, {
                "PortVLXmitWaitData", "opa.pm.portstatus.vl.xmitwaitdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLRcvBubble, {
                "PortVLRcvBubble", "opa.pm.portstatus.vl.rcvbubble",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLMarkFECN, {
                "PortVLMarkFECN", "opa.pm.portstatus.vl.markfecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PortStatus_PortVLXmitDiscards, {
                "PortVLXmitDiscards", "opa.pm.portstatus.vl.xmitdiscards",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

/*******************
* ClearPortStatus *
*******************/

        { &hf_opa_ClearPortStatus, {
                "Clear Port Status", "opa.pm.clearportstatus",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortSelectMask, {
                "Port Select Mask", "opa.pm.clearportstatus.portselectmask",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_CounterSelectMask, {
                "CounterSelectMask", "opa.pm.clearportstatus.counterselectmask",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortXmitData, {
                "PortXmitData", "opa.pm.clearportstatus.portxmitdata",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x80000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortRcvData, {
                "PortRcvData", "opa.pm.clearportstatus.portrcvdata",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x40000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortXmitPkts, {
                "PortXmitPkts", "opa.pm.clearportstatus.portxmitpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x20000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortRcvPkts, {
                "PortRcvPkts", "opa.pm.clearportstatus.portrcvpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x10000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortMulticastXmitPkts, {
                "PortMulticastXmitPkts", "opa.pm.clearportstatus.portmulticastxmitpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x08000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortMulticastRcvPkts, {
                "PortMulticastRcvPkts", "opa.pm.clearportstatus.portmulticastrcvpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x04000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortXmitWait, {
                "PortXmitWait", "opa.pm.clearportstatus.portxmitwait",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x02000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_SwPortCongestion, {
                "SwPortCongestion", "opa.pm.clearportstatus.swportcongestion",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x01000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortRcvFECN, {
                "PortRcvFECN", "opa.pm.clearportstatus.portrecvfecn",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00800000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortRcvBECN, {
                "PortRcvBECN", "opa.pm.clearportstatus.portrecvbecn",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00400000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortXmitTimeCong, {
                "PortXmitTimeCong", "opa.pm.clearportstatus.portxmittimecong",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00200000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortXmitWastedBW, {
                "PortXmitWastedBW", "opa.pm.clearportstatus.portxmitwastedbw",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00100000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortXmitWaitData, {
                "PortXmitWaitData", "opa.pm.clearportstatus.portxmitwaitdata",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00080000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortRcvBubble, {
                "PortRcvBubble", "opa.pm.clearportstatus.portrcvbubble",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00040000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortMarkFECN, {
                "PortMarkFECN", "opa.pm.clearportstatus.portmarkfecn",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00020000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortRcvConstraintErrors, {
                "PortRcvConstraintErrors", "opa.pm.clearportstatus.portrcvconstrainterrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00010000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortRcvSwitchRelayErrors, {
                "PortRcvSwitchRelayErrors", "opa.pm.clearportstatus.portrcvswitchrelayerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00008000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortXmitDiscards, {
                "PortXmitDiscards", "opa.pm.clearportstatus.portxmitdiscards",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00004000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortXmitConstraintErrors, {
                "PortXmitConstraintErrors", "opa.pm.clearportstatus.portxmitconstrainterrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00002000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortRcvRemotePhysicalErrors, {
                "PortRcvRemotePhysicalErrors", "opa.pm.clearportstatus.portrcvremotephysicalerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00001000, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_LocalLinkIntegrityErrors, {
                "LocalLinkIntegrityErrors", "opa.pm.clearportstatus.locallinkintegrityerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000800, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_PortRcvErrors, {
                "PortRcvErrors", "opa.pm.clearportstatus.portrcverrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000400, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_ExcessiveBufferOverruns, {
                "ExcessiveBufferOverruns", "opa.pm.clearportstatus.excessivebufferoverruns",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000200, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_FMConfigErrors, {
                "FMConfigErrors", "opa.pm.clearportstatus.fmconfigerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000100, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_LinkErrorRecovery, {
                "LinkErrorRecovery", "opa.pm.clearportstatus.linkerrorrecovery",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000080, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_LinkDowned, {
                "LinkDowned", "opa.pm.clearportstatus.linkdowned",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000040, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_UncorrectableErrors, {
                "UncorrectableErrors", "opa.pm.clearportstatus.uncorrectableerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000020, NULL, HFILL }
        },
        { &hf_opa_ClearPortStatus_reserved, {
                "Reserved (5 bits)", "opa.pm.clearportstatus.reserved",
                FT_UINT32, BASE_DEC, NULL, 0x0000001F, NULL, HFILL }
        },

        /* DataPortCounters */
        { &hf_opa_DataPortCounters, {
                "Data Port Counters", "opa.pm.dataportcounters",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortSelectMask, {
                "Port Select Mask", "opa.pm.dataportcounters.portselectmask",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_VLSelectMask, {
                "VL Select Mask", "opa.pm.dataportcounters.vlselectmask",
                FT_UINT32, BASE_CUSTOM, CF_FUNC(cf_opa_mad_32b_mask), 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_resolution_reserved, {
                "Reserved (24 bits)", "opa.pm.dataportcounters.reserved",
                FT_UINT32, BASE_HEX, NULL, 0xFFFFFF00, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_LocalLinkIntegrityResolution, {
                "Local Link Integrity Resolution", "opa.pm.dataportcounters.locallinkintegrityresolution",
                FT_UINT32, BASE_DEC, NULL, 0x000000F0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_LinkErrorRecoveryResolution, {
                "Link Error Recovery Resolution", "opa.pm.dataportcounters.linkerrorrecoveryresolution",
                FT_UINT32, BASE_DEC, NULL, 0x0000000F, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortNumber, {
                "PortNumber", "opa.pm.dataportcounters.portnumber",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_lqi_reserved, {
                "Reserved (29 bits)", "opa.pm.dataportcounters.reserved",
                FT_UINT32, BASE_DEC, NULL, 0xFFFFFFF8, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_LinkQualityIndicator, {
                "LinkQualityIndicator", "opa.pm.dataportcounters.linkqualityindicator",
                FT_UINT32, BASE_DEC, VALS(LinkQualityIndicator), 0x00000007, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortXmitData, {
                "PortXmitData", "opa.pm.dataportcounters.portxmitdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortRcvData, {
                "PortRcvData", "opa.pm.dataportcounters.portrcvdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortXmitPkts, {
                "PortXmitPkts", "opa.pm.dataportcounters.portxmitpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortRcvPkts, {
                "PortRcvPkts", "opa.pm.dataportcounters.portrcvpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortMulticastXmitPkts, {
                "PortMulticastXmitPkts", "opa.pm.dataportcounters.portmulticastxmitpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortMulticastRcvPkts, {
                "PortMulticastRcvPkts", "opa.pm.dataportcounters.portmulticastrcvpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortXmitWait, {
                "PortXmitWait", "opa.pm.dataportcounters.portxmitwait",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_SwPortCongestion, {
                "SwPortCongestion", "opa.pm.dataportcounters.swportcongestion",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortRcvFECN, {
                "PortRcvFECN", "opa.pm.dataportcounters.portrecvfecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortRcvBECN, {
                "PortRcvBECN", "opa.pm.dataportcounters.portrecvbecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortXmitTimeCong, {
                "PortXmitTimeCong", "opa.pm.dataportcounters.portxmittimecong",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortXmitWastedBW, {
                "PortXmitWastedBW", "opa.pm.dataportcounters.portxmitwastedbw",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortXmitWaitData, {
                "PortXmitWaitData", "opa.pm.dataportcounters.portxmitwaitdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortRcvBubble, {
                "PortRcvBubble", "opa.pm.dataportcounters.portrcvbubble",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortMarkFECN, {
                "PortMarkFECN", "opa.pm.dataportcounters.portmarkfecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortErrorCounterSummary, {
                "PortErrorCounterSummary", "opa.pm.dataportcounters.porterrorcountersummary",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortVLXmitData, {
                "PortVLXmitData", "opa.pm.dataportcounters.vl.xmitdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortVLRcvData, {
                "PortVLRcvData", "opa.pm.dataportcounters.vl.rcvdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortVLXmitPkts, {
                "PortVLXmitPkts", "opa.pm.dataportcounters.vl.xmitpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortVLRcvPkts, {
                "PortVLRcvPkts", "opa.pm.dataportcounters.vl.rcvpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortVLXmitWait, {
                "PortVLXmitWait", "opa.pm.dataportcounters.vl.xmitwait",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_SwPortVLCongestion, {
                "SwPortVLCongestion", "opa.pm.dataportcounters.vl.swcongestion",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortVLRcvFECN, {
                "PortVLRcvFECN", "opa.pm.dataportcounters.vl.rcvfecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortVLRcvBECN, {
                "PortVLRcvBECN", "opa.pm.dataportcounters.vl.rcvbecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortVLXmitTimeCong, {
                "PortVLXmitTimeCong", "opa.pm.dataportcounters.vl.xmittimecong",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortVLXmitWastedBW, {
                "PortVLXmitWastedBW", "opa.pm.dataportcounters.vl.xmitwastedbw",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortVLXmitWaitData, {
                "PortVLXmitWaitData", "opa.pm.dataportcounters.vl.xmitwaitdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortVLRcvBubble, {
                "PortVLRcvBubble", "opa.pm.dataportcounters.vl.rcvbubble",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_DataPortCounters_PortVLMarkFECN, {
                "PortVLMarkFECN", "opa.pm.dataportcounters.vl.markfecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        /* ErrorPortCounters */
        { &hf_opa_ErrorPortCounters, {
                "Error Port Counters", "opa.pm.errorportcounters",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_PortSelectMask, {
                "Port Select Mask", "opa.pm.errorportcounters.portselectmask",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_VLSelectMask, {
                "VL Select Mask", "opa.pm.errorportcounters.vlselectmask",
                FT_UINT32, BASE_CUSTOM, CF_FUNC(cf_opa_mad_32b_mask), 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_PortNumber, {
                "PortNumber", "opa.pm.errorportcounters.portnumber",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_PortRcvConstraintErrors, {
                "PortRcvConstraintErrors", "opa.pm.errorportcounters.portrcvconstrainterrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_PortRcvSwitchRelayErrors, {
                "PortRcvSwitchRelayErrors", "opa.pm.errorportcounters.portrcvswitchrelayerrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_PortXmitDiscards, {
                "PortXmitDiscards", "opa.pm.errorportcounters.portxmitdiscards",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_PortXmitConstraintErrors, {
                "PortXmitConstraintErrors", "opa.pm.errorportcounters.portxmitconstrainterrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_PortRcvRemotePhysicalErrors, {
                "PortRcvRemotePhysicalErrors", "opa.pm.errorportcounters.portrcvremotephysicalerrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_LocalLinkIntegrityErrors, {
                "LocalLinkIntegrityErrors", "opa.pm.errorportcounters.locallinkintegrityerrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_PortRcvErrors, {
                "PortRcvErrors", "opa.pm.errorportcounters.portrcverrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_ExcessiveBufferOverruns, {
                "ExcessiveBufferOverruns", "opa.pm.errorportcounters.excessivebufferoverruns",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_FMConfigErrors, {
                "FMConfigErrors", "opa.pm.errorportcounters.fmconfigerrors",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_LinkErrorRecovery, {
                "LinkErrorRecovery", "opa.pm.errorportcounters.linkerrorrecovery",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_LinkDowned, {
                "LinkDowned", "opa.pm.errorportcounters.linkdowned",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_UncorrectableErrors, {
                "UncorrectableErrors", "opa.pm.errorportcounters.uncorrectableerrors",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortCounters_PortVLXmitDiscards, {
                "PortVLXmitDiscards", "opa.pm.errorportcounters.portvlxmitdiscards",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        /* ErrorPortInfo */
        { &hf_opa_ErrorPortInfo, {
                "Error Port Info", "opa.pm.errorportinfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortSelectMask, {
                "Port Select Mask", "opa.pm.errorportinfo.portselectmask",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_PortRcvErrorInfo, {
                "Port Rcv Error Info", "opa.pm.errorportinfo.errorinfoselectmask.portrcverrorinfo",
                FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_ExcessiveBufferOverrunInfo, {
                "ExcessiveBufferOverrunInfo", "opa.pm.errorportinfo.errorinfoselectmask.excessivebufferoverruninfo",
                FT_BOOLEAN, 32, NULL, 0x40000000, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_PortXmitConstraintErrorInfo, {
                "PortXmitConstraintErrorInfo", "opa.pm.errorportinfo.errorinfoselectmask.portxmitconstrainterrorinfo",
                FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_PortRcvConstraintErrorInfo, {
                "PortRcvConstraintErrorInfo", "opa.pm.errorportinfo.errorinfoselectmask.portrcvconstrainterrorinfo",
                FT_BOOLEAN, 32, NULL, 0x10000000, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_PortRcvSwitchRelayErrorInfo, {
                "PortRcvSwitchRelayErrorInfo", "opa.pm.errorportinfo.errorinfoselectmask.portrcvswitchrelayerrorinfo",
                FT_BOOLEAN, 32, NULL, 0x08000000, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_UncorrectableErrorInfo, {
                "UncorrectableErrorInfo", "opa.pm.errorportinfo.errorinfoselectmask.uncorrectableerrorinfo",
                FT_BOOLEAN, 32, NULL, 0x04000000, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_FMConfigErrorInfo, {
                "Fmconfigerrorinfo", "opa.pm.errorportinfo.errorinfoselectmask.fmconfigerrorinfo",
                FT_BOOLEAN, 32, NULL, 0x02000000, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_ErrorInfoSelectMask_reserved, {
                "Reserved (25 bits)", "opa.pm.errorportinfo.errorinfoselectmask.reserved",
                FT_UINT32, BASE_HEX, NULL, 0x01FFFFFF, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortNumber, {
                "Port Number", "opa.pm.errorportinfo.Portnumber",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvErrorInfo_Status, {
                "Status", "opa.pm.errorportinfo.portrcverrorinfo.status",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvErrorInfo_reserved, {
                "Reserved", "opa.pm.errorportinfo.portrcverrorinfo.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x70, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvErrorInfo_ErrorCode, {
                "ErrorCode", "opa.pm.errorportinfo.portrcverrorinfo.errorcode",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvErrorInfo_PacketFlit1, {
                "PacketFlit1", "opa.pm.errorportinfo.portrcverrorinfo.packetflit1",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvErrorInfo_PacketFlit2, {
                "PacketFlit2", "opa.pm.errorportinfo.portrcverrorinfo.packetflit2",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvErrorInfo_Flit1Bits, {
                "Flit1Bits", "opa.pm.errorportinfo.portrcverrorinfo.flit1bits",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvErrorInfo_Flit2Bits, {
                "Flit2Bits", "opa.pm.errorportinfo.portrcverrorinfo.flit2bits",
                FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvErrorInfo_reserved2, {
                "Reserved (4 bits)", "opa.pm.errorportinfo.portrcverrorinfo.reserved2",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvErrorInfo_PacketBytes, {
                "PacketBytes", "opa.pm.errorportinfo.portrcverrorinfo.packetbytes",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvErrorInfo_FlitBits, {
                "FlitBits", "opa.pm.errorportinfo.portrcverrorinfo.flitbits",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvErrorInfo_reserved3, {
                "Reserved (6 bits)", "opa.pm.errorportinfo.portrcverrorinfo.reserved3",
                FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvErrorInfo_reserved4, {
                "Reserved (17 bytes)", "opa.pm.errorportinfo.portrcverrorinfo.reserved4",
                FT_BYTES, FT_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_ExcessiveBufferOverrunErrorInfo_Status, {
                "Status", "opa.pm.errorportinfo.excessivebufferoverrunerrorinfo.status",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_ExcessiveBufferOverrunErrorInfo_SC, {
                "SC", "opa.pm.errorportinfo.excessivebufferoverrunerrorinfo.sc",
                FT_UINT8, BASE_HEX, NULL, 0x7C, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_ExcessiveBufferOverrunErrorInfo_reserved, {
                "Reserved (2 bits)", "opa.pm.errorportinfo.ExcessiveBufferOverrunErrorInfo.Reserved",
                FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortXmitConstraintErrorInfo_Status, {
                "Status", "opa.pm.errorportinfo.portxmitconstrainterrorinfo.status",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortXmitConstraintErrorInfo_reserved, {
                "Reserved (7 bits)", "opa.pm.errorportinfo.portxmitconstrainterrorinfo.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortXmitConstraintErrorInfo_P_Key, {
                "P_Key", "opa.pm.errorportinfo.portxmitconstrainterrorinfo.pkey",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortXmitConstraintErrorInfo_SLID, {
                "SLID", "opa.pm.errorportinfo.portxmitconstrainterrorinfo.slid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvConstraintErrorInfo_Status, {
                "Status", "opa.pm.errorportinfo.portrcvconstrainterrorinfo.status",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvConstraintErrorInfo_reserved, {
                "Reserved (7 bits)", "opa.pm.errorportinfo.portrcvconstrainterrorinfo.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvConstraintErrorInfo_P_Key, {
                "P_Key", "opa.pm.errorportinfo.portrcvconstrainterrorinfo.pkey",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvConstraintErrorInfo_SLID, {
                "SLID", "opa.pm.errorportinfo.portrcvconstrainterrorinfo.slid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_Status, {
                "Status", "opa.pm.errorportinfo.portrcvswitchrelayerrorinfo.status",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_reserved, {
                "Reserved (3 bits)", "opa.pm.errorportinfo.portrcvswitchrelayerrorinfo.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x70, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_ErrorCode, {
                "ErrorCode", "opa.pm.errorportinfo.portrcvswitchrelayerrorinfo.errorcode",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_DLID, {
                "DLID", "opa.pm.errorportinfo.portrcvswitchrelayerrorinfo.dlid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_EgressPortNum, {
                "EgressPortNum", "opa.pm.errorportinfo.portrcvswitchrelayerrorinfo.egressportnum",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_PortRcvSwitchRelayErrorInfo_SC, {
                "SC", "opa.pm.errorportinfo.portrcvswitchrelayerrorinfo.scorsl",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_UncorrectableErrorInfo_Status, {
                "Status", "opa.pm.errorportinfo.uncorrectableerrorinfo.status",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_UncorrectableErrorInfo_reserved, {
                "Reserved (3 bits)", "opa.pm.errorportinfo.uncorrectableerrorinfo.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x70, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_UncorrectableErrorInfo_ErrorCode, {
                "ErrorCode", "opa.pm.errorportinfo.uncorrectableerrorinfo.errorcode",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_FMConfigErrorInfo_Status, {
                "Status", "opa.pm.errorportinfo.fmconfigerrorinfo.status",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_FMConfigErrorInfo_reserved, {
                "Reserved (3 bits)", "opa.pm.errorportinfo.fmconfigerrorinfo.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x70, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_FMConfigErrorInfo_ErrorCode, {
                "ErrorCode", "opa.pm.errorportinfo.fmconfigerrorinfo.errorcode",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_FMConfigErrorInfo_VL, {
                "VL", "opa.pm.errorportinfo.fmconfigerrorinfo.vl",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_FMConfigErrorInfo_Distance, {
                "Distance", "opa.pm.errorportinfo.fmconfigerrorinfo.distance",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_FMConfigErrorInfo_BadFlitBits, {
                "BadFlitBits", "opa.pm.errorportinfo.fmconfigerrorinfo.badflitbits",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ErrorPortInfo_FMConfigErrorInfo_SC, {
                "SC", "opa.pm.errorportinfo.fmconfigerrorinfo.sc",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* General PA */
        { &hf_opa_ImageID_imageNumber, {
                "imageNumber", "opa.pa.imageid.imagenumber",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ImageID_imageOffset, {
                "imageOffset", "opa.pa.imageid.imageoffset",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* GetGroupList */
        { &hf_opa_GetGroupList, {
                "Group List", "opa.pa.getgrouplist",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupList_groupName, {
                "Group Name", "opa.pa.getgrouplist.groupname",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* GetGroupInfo */
        { &hf_opa_GetGroupInfo, {
                "Group Info", "opa.pa.getgroupinfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_groupName, {
                "Group Name", "opa.pa.getgroupinfo.groupname",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_numInternalPorts, {
                "numInternalPorts", "opa.pa.getgroupinfo.numinternalports",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_numExternalPorts, {
                "numExternalPorts", "opa.pa.getgroupinfo.numexternalports",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_totalMBps, {
                "totalMBps", "opa.pa.getgroupinfo.totalmbps",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_totalKPps, {
                "totalKPps", "opa.pa.getgroupinfo.totalkpps",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_avgMBps, {
                "avgMBps", "opa.pa.getgroupinfo.avgmbps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_minMBps, {
                "minMBps", "opa.pa.getgroupinfo.minmbps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_maxMBps, {
                "maxMBps", "opa.pa.getgroupinfo.maxmbps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_numBWBuckets, {
                "numBWBuckets", "opa.pa.getgroupinfo.numbwbuckets",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_BWBuckets, {
                "BWBuckets", "opa.pa.getgroupinfo.bwbuckets",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_avgKPps, {
                "avgKPps", "opa.pa.getgroupinfo.avgkpps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_minKPps, {
                "minKPps", "opa.pa.getgroupinfo.minkpps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_maxKPps, {
                "maxKPps", "opa.pa.getgroupinfo.maxkpps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_pmaFailedPorts, {
                "pmaFailedPorts", "opa.pa.getgroupinfo.pmafailedports",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_topoFailedPorts, {
                "topoFailedPorts", "opa.pa.getgroupinfo.topofailedports",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_integrityErrors, {
                "integrityErrors", "opa.pa.getgroupinfo.integrityerrors",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_congestionErrors, {
                "congestionErrors", "opa.pa.getgroupinfo.congestionerrors",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_smaCongestionErrors, {
                "smaCongestionErrors", "opa.pa.getgroupinfo.smacongestionerrors",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_bubbleErrors, {
                "bubbleErrors", "opa.pa.getgroupinfo.bubbleerrors",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_securityErrors, {
                "securityErrors", "opa.pa.getgroupinfo.securityerrors",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_routingErrors, {
                "routingErrors", "opa.pa.getgroupinfo.routingerrors",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_utilizationPct10, {
                "utilizationPct10", "opa.pa.getgroupinfo.utilizationpct10",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_computed_pct10), 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_discardsPct10, {
                "discardsPct10", "opa.pa.getgroupinfo.discardspct10",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_computed_pct10), 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_maxInternalRate, {
                "maxInternalRate", "opa.pa.getgroupinfo.maxinternalrate",
                FT_UINT8, BASE_HEX, VALS(Rate), 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_minInternalRate, {
                "minInternalRate", "opa.pa.getgroupinfo.mininternalrate",
                FT_UINT8, BASE_HEX, VALS(Rate), 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_maxExternalRate, {
                "maxExternalRate", "opa.pa.getgroupinfo.maxexternalrate",
                FT_UINT8, BASE_HEX, VALS(Rate), 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_minExternalRate, {
                "minExternalRate", "opa.pa.getgroupinfo.minexternalrate",
                FT_UINT8, BASE_HEX, VALS(Rate), 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_maxInternalMBps, {
                "maxInternalMBps", "opa.pa.getgroupinfo.maxinternalmbps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupInfo_maxExternalMBps, {
                "maxExternalMBps", "opa.pa.getgroupinfo.maxexternalmbps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* GetGroupConfig */
        { &hf_opa_GetGroupConfig, {
                "Group Config", "opa.pa.getgroupconfig",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupConfig_groupName, {
                "Group Name", "opa.pa.getgroupconfig.groupname",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupConfig_Port_NodeGUID, {
                "NodeGUID", "opa.pa.getgroupconfig.port.nodeguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupConfig_Port_nodeDesc, {
                "nodeDesc", "opa.pa.getgroupconfig.port.nodedesc",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupConfig_Port_NodeLID, {
                "NodeLID", "opa.pa.getgroupconfig.port.nodelid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetGroupConfig_Port_PortNumber, {
                "PortNumber", "opa.pa.getgroupconfig.port.portnumber",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* GetPortCounters */
        { &hf_opa_GetPortCounters, {
                "Port Counters", "opa.pa.getportcounters",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_nodeLID, {
                "nodeLID", "opa.pa.getportcounters.nodelid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortNumber, {
                "PortNumber", "opa.pa.getportcounters.portnumber",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_flags, {
                "flags", "opa.pa.getportcounters.flags",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortXmitData, {
                "PortXmitData", "opa.pa.getportcounters.portxmitdata",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortRcvData, {
                "PortRcvData", "opa.pa.getportcounters.portrcvdata",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortXmitPkts, {
                "PortXmitPkts", "opa.pa.getportcounters.portxmitpkts",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortRcvPkts, {
                "PortRcvPkts", "opa.pa.getportcounters.portrcvpkts",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortMulticastXmitPkts, {
                "PortMulticastXmitPkts", "opa.pa.getportcounters.portmulticastxmitpkts",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortMulticastRcvPkts, {
                "PortMulticastRcvPkts", "opa.pa.getportcounters.portmulticastrcvpkts",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_LocalLinkIntegrityErrors, {
                "LocalLinkIntegrityErrors", "opa.pa.getportcounters.locallinkintegrityerrors",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_FMConfigErrors, {
                "FMConfigErrors", "opa.pa.getportcounters.fmconfigerrors",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortRcvErrors, {
                "PortRcvErrors", "opa.pa.getportcounters.portrcverrors",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_ExcessiveBufferOverruns, {
                "ExcessiveBufferOverruns", "opa.pa.getportcounters.excessivebufferoverruns",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortRcvConstraintErrors, {
                "PortRcvConstraintErrors", "opa.pa.getportcounters.portrcvconstrainterrors",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortRcvSwitchRelayErrors, {
                "PortRcvSwitchRelayErrors", "opa.pa.getportcounters.portrcvswitchrelayerrors",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortXmitDiscards, {
                "PortXmitDiscards", "opa.pa.getportcounters.portxmitdiscards",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortXmitConstraintErrors, {
                "PortXmitConstraintErrors", "opa.pa.getportcounters.portxmitconstrainterrors",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortRcvRemotePhysicalErrors, {
                "PortRcvRemotePhysicalErrors", "opa.pa.getportcounters.portrcvremotephysicalerrors",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_SwPortCongestion, {
                "SwPortCongestion", "opa.pa.getportcounters.swportcongestion",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortXmitWait, {
                "PortXmitWait", "opa.pa.getportcounters.portxmitwait",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortRcvFECN, {
                "PortRcvFECN", "opa.pa.getportcounters.portrcvfecn",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortRcvBECN, {
                "PortRcvBECN", "opa.pa.getportcounters.portrcvbecn",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortXmitTimeCong, {
                "PortXmitTimeCong", "opa.pa.getportcounters.portxmittimecong",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortXmitWastedBW, {
                "PortXmitWastedBW", "opa.pa.getportcounters.portxmitwastedbw",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortXmitWaitData, {
                "PortXmitWaitData", "opa.pa.getportcounters.portxmitwaitdata",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortRcvBubble, {
                "PortRcvBubble", "opa.pa.getportcounters.portrcvbubble",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_PortMarkFECN, {
                "PortMarkFECN", "opa.pa.getportcounters.portmarkfecn",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_LinkErrorRecovery, {
                "LinkErrorRecovery", "opa.pa.getportcounters.linkerrorrecovery",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_LinkDowned, {
                "LinkDowned", "opa.pa.getportcounters.linkdowned",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_UncorrectableErrors, {
                "UncorrectableErrors", "opa.pa.getportcounters.uncorrectableerrors",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_NumLanesDown, {
                "NumLanesDown", "opa.pa.getportcounters.numlanesdown",
                FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_reserved, {
                "Reserved", "opa.pa.getportcounters.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL }
        },
        { &hf_opa_GetPortCounters_LinkQualityIndicator, {
                "LinkQualityIndicator", "opa.pa.getportcounters.linkqualityindicator",
                FT_UINT8, BASE_DEC, VALS(LinkQualityIndicator), 0x07, NULL, HFILL }
        },

        /* ClearPortCounters */
        { &hf_opa_ClearPortCounters, {
                "Clear User Port Counters", "opa.pa.clearportcounters",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_nodeLID, {
                "nodeLID", "opa.pa.clearportcounters.nodelid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortNumber, {
                "PortNumber", "opa.pa.clearportcounters.portnumber",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_CounterSelectMask, {
                "CounterSelectMask", "opa.pa.clearportcounters.counterselectmask",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortXmitData, {
                "PortXmitData", "opa.pa.clearportcounters.portxmitdata",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x80000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortRcvData, {
                "PortRcvData", "opa.pa.clearportcounters.portrcvdata",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x40000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortXmitPkts, {
                "PortXmitPkts", "opa.pa.clearportcounters.portxmitpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x20000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortRcvPkts, {
                "PortRcvPkts", "opa.pa.clearportcounters.portrcvpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x10000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortMulticastXmitPkts, {
                "PortMulticastXmitPkts", "opa.pa.clearportcounters.portmulticastxmitpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x08000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortMulticastRcvPkts, {
                "PortMulticastRcvPkts", "opa.pa.clearportcounters.portmulticastrcvpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x04000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortXmitWait, {
                "PortXmitWait", "opa.pa.clearportcounters.portxmitwait",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x02000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_SwPortCongestion, {
                "SwPortCongestion", "opa.pa.clearportcounters.swportcongestion",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x01000000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortRcvFECN, {
                "PortRcvFECN", "opa.pa.clearportcounters.portrecvfecn",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00800000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortRcvBECN, {
                "PortRcvBECN", "opa.pa.clearportcounters.portrecvbecn",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00400000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortXmitTimeCong, {
                "PortXmitTimeCong", "opa.pa.clearportcounters.portxmittimecong",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00200000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortXmitWastedBW, {
                "PortXmitWastedBW", "opa.pa.clearportcounters.portxmitwastedbw",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00100000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortXmitWaitData, {
                "PortXmitWaitData", "opa.pa.clearportcounters.portxmitwaitdata",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00080000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortRcvBubble, {
                "PortRcvBubble", "opa.pa.clearportcounters.portrcvbubble",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00040000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortMarkFECN, {
                "PortMarkFECN", "opa.pa.clearportcounters.portmarkfecn",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00020000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortRcvConstraintErrors, {
                "PortRcvConstraintErrors", "opa.pa.clearportcounters.portrcvconstrainterrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00010000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortRcvSwitchRelayErrors, {
                "PortRcvSwitchRelayErrors", "opa.pa.clearportcounters.portrcvswitchrelayerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00008000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortXmitDiscards, {
                "PortXmitDiscards", "opa.pa.clearportcounters.portxmitdiscards",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00004000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortXmitConstraintErrors, {
                "PortXmitConstraintErrors", "opa.pa.clearportcounters.portxmitconstrainterrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00002000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortRcvRemotePhysicalErrors, {
                "PortRcvRemotePhysicalErrors", "opa.pa.clearportcounters.portrcvremotephysicalerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00001000, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_LocalLinkIntegrityErrors, {
                "LocalLinkIntegrityErrors", "opa.pa.clearportcounters.locallinkintegrityerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000800, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_PortRcvErrors, {
                "PortRcvErrors", "opa.pa.clearportcounters.portrcverrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000400, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_ExcessiveBufferOverruns, {
                "ExcessiveBufferOverruns", "opa.pa.clearportcounters.excessivebufferoverruns",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000200, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_FMConfigErrors, {
                "FMConfigErrors", "opa.pa.clearportcounters.fmconfigerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000100, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_LinkErrorRecovery, {
                "LinkErrorRecovery", "opa.pa.clearportcounters.linkerrorrecovery",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000080, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_LinkDowned, {
                "LinkDowned", "opa.pa.clearportcounters.linkdowned",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000040, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_UncorrectableErrors, {
                "UncorrectableErrors", "opa.pa.clearportcounters.uncorrectableerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000020, NULL, HFILL }
        },
        { &hf_opa_ClearPortCounters_reserved, {
                "Reserved (5 bits)", "opa.pa.clearportcounters.reserved",
                FT_UINT32, BASE_DEC, NULL, 0x0000001F, NULL, HFILL }
        },

        /* ClearAllPortCounters */
        { &hf_opa_ClearAllPortCounters, {
                "Clear All User Port Counters", "opa.pa.clearallportcounters",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_CounterSelectMask, {
                "CounterSelectMask", "opa.pa.clearallportcounters.counterselectmask",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortXmitData, {
                "PortXmitData", "opa.pa.clearallportcounters.portxmitdata",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x80000000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortRcvData, {
                "PortRcvData", "opa.pa.clearallportcounters.portrcvdata",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x40000000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortXmitPkts, {
                "PortXmitPkts", "opa.pa.clearallportcounters.portxmitpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x20000000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortRcvPkts, {
                "PortRcvPkts", "opa.pa.clearallportcounters.portrcvpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x10000000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortMulticastXmitPkts, {
                "PortMulticastXmitPkts", "opa.pa.clearallportcounters.portmulticastxmitpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x08000000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortMulticastRcvPkts, {
                "PortMulticastRcvPkts", "opa.pa.clearallportcounters.portmulticastrcvpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x04000000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortXmitWait, {
                "PortXmitWait", "opa.pa.clearallportcounters.portxmitwait",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x02000000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_SwPortCongestion, {
                "SwPortCongestion", "opa.pa.clearallportcounters.swportcongestion",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x01000000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortRcvFECN, {
                "PortRcvFECN", "opa.pa.clearallportcounters.portrecvfecn",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00800000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortRcvBECN, {
                "PortRcvBECN", "opa.pa.clearallportcounters.portrecvbecn",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00400000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortXmitTimeCong, {
                "PortXmitTimeCong", "opa.pa.clearallportcounters.portxmittimecong",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00200000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortXmitWastedBW, {
                "PortXmitWastedBW", "opa.pa.clearallportcounters.portxmitwastedbw",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00100000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortXmitWaitData, {
                "PortXmitWaitData", "opa.pa.clearallportcounters.portxmitwaitdata",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00080000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortRcvBubble, {
                "PortRcvBubble", "opa.pa.clearallportcounters.portrcvbubble",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00040000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortMarkFECN, {
                "PortMarkFECN", "opa.pa.clearallportcounters.portmarkfecn",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00020000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortRcvConstraintErrors, {
                "PortRcvConstraintErrors", "opa.pa.clearallportcounters.portrcvconstrainterrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00010000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortRcvSwitchRelayErrors, {
                "PortRcvSwitchRelayErrors", "opa.pa.clearallportcounters.portrcvswitchrelayerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00008000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortXmitDiscards, {
                "PortXmitDiscards", "opa.pa.clearallportcounters.portxmitdiscards",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00004000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortXmitConstraintErrors, {
                "PortXmitConstraintErrors", "opa.pa.clearallportcounters.portxmitconstrainterrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00002000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortRcvRemotePhysicalErrors, {
                "PortRcvRemotePhysicalErrors", "opa.pa.clearallportcounters.portrcvremotephysicalerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00001000, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_LocalLinkIntegrityErrors, {
                "LocalLinkIntegrityErrors", "opa.pa.clearallportcounters.locallinkintegrityerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000800, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_PortRcvErrors, {
                "PortRcvErrors", "opa.pa.clearallportcounters.portrcverrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000400, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_ExcessiveBufferOverruns, {
                "ExcessiveBufferOverruns", "opa.pa.clearallportcounters.excessivebufferoverruns",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000200, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_FMConfigErrors, {
                "FMConfigErrors", "opa.pa.clearallportcounters.fmconfigerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000100, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_LinkErrorRecovery, {
                "LinkErrorRecovery", "opa.pa.clearallportcounters.linkerrorrecovery",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000080, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_LinkDowned, {
                "LinkDowned", "opa.pa.clearallportcounters.linkdowned",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000040, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_UncorrectableErrors, {
                "UncorrectableErrors", "opa.pa.clearallportcounters.uncorrectableerrors",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00000020, NULL, HFILL }
        },
        { &hf_opa_ClearAllPortCounters_reserved, {
                "Reserved (5 bits)", "opa.pa.clearallportcounters.reserved",
                FT_UINT32, BASE_DEC, NULL, 0x0000001F, NULL, HFILL }
        },

        /* PMConfig */
        { &hf_opa_PMConfig, {
                "PM Config", "opa.pa.pmconfig",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_sweepInterval, {
                "sweepInterval", "opa.pa.pmconfig.sweepinterval",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_maxClients, {
                "maxClients", "opa.pa.pmconfig.maxclients",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_sizeHistory, {
                "sizeHistory", "opa.pa.pmconfig.sizehistory",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_sizeFreeze, {
                "sizeFreeze", "opa.pa.pmconfig.sizefreeze",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_lease, {
                "lease", "opa.pa.pmconfig.lease",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_pmFlags, {
                "pmFlags", "opa.pa.pmconfig.pmflags",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_PortXmitWait, {
                "PortXmitWait", "opa.pa.pmconfig.portxmitwait",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_SwPortCongestion, {
                "SwPortCongestion", "opa.pa.pmconfig.swportcongestion",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_PortRcvFECN, {
                "PortRcvFECN", "opa.pa.pmconfig.portrcvfecn",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_PortRcvBECN, {
                "PortRcvBECN", "opa.pa.pmconfig.portrcvbecn",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_PortXmitTimeCong, {
                "PortXmitTimeCong", "opa.pa.pmconfig.portxmittimecong",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_PortMarkFECN, {
                "PortMarkFECN", "opa.pa.pmconfig.portmarkfecn",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_integrityErrors, {
                "integrityErrors", "opa.pa.pmconfig.integrityerrors",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_congestionErrors, {
                "congestionErrors", "opa.pa.pmconfig.congestionerrors",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_bubbleErrors, {
                "bubbleErrors", "opa.pa.pmconfig.bubbleerrors",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_smaCongestionErrors, {
                "smaCongestionErrors", "opa.pa.pmconfig.smacongestionerrors",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_securityErrors, {
                "securityErrors", "opa.pa.pmconfig.securityerrors",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_routingErrors, {
                "routingErrors", "opa.pa.pmconfig.routingerrors",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_LocalLinkIntegrityErrors, {
                "LocalLinkIntegrityErrors", "opa.pa.pmconfig.locallinkintegrityerrors",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_PortRcvErrors, {
                "PortRcvErrors", "opa.pa.pmconfig.portrcverrors",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_ExcessiveBufferOverrunErrors, {
                "ExcessiveBufferOverrunErrors", "opa.pa.pmconfig.excessivebufferoverrunerrors",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_LinkErrorRecovery, {
                "LinkErrorRecovery", "opa.pa.pmconfig.linkerrorrecovery",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_LinkDowned, {
                "LinkDowned", "opa.pa.pmconfig.linkdowned",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_UncorrectableErrors, {
                "UncorrectableErrors", "opa.pa.pmconfig.uncorrectableerrors",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_FMConfigErrors, {
                "FMConfigErrors", "opa.pa.pmconfig.fmconfigerrors",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_LinkQualityIndicator, {
                "LinkQualityIndicator", "opa.pa.pmconfig.linkqualityindicator",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_LinkWidthDowngrade, {
                "LinkWidthDowngrade", "opa.pa.pmconfig.linkwidthdowngrade",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_memoryFootprint, {
                "memoryFootprint", "opa.pa.pmconfig.memoryfootprint",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_maxAttempts, {
                "maxAttempts", "opa.pa.pmconfig.maxattempts",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_respTimeout, {
                "respTimeout", "opa.pa.pmconfig.resptimeout",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_minRespTimeout, {
                "minRespTimeout", "opa.pa.pmconfig.minresptimeout",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_maxParallelNodes, {
                "maxParallelNodes", "opa.pa.pmconfig.maxparallelnodes",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_pmaBatchSize, {
                "pmaBatchSize", "opa.pa.pmconfig.pmabatchsize",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_PMConfig_errorClear, {
                "errorClear", "opa.pa.pmconfig.errorclear",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* MoveFreezeFrame */
        { &hf_opa_MoveFreezeFrame_old, {
                "Old Image", "opa.pa.movefreezeframe.old",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_MoveFreezeFrame_new, {
                "New Image", "opa.pa.movefreezeframe.new",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* GetFocusPorts */
        { &hf_opa_GetFocusPorts, {
                "Focus Ports", "opa.pa.getfocusports",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_groupName, {
                "Group Name", "opa.pa.getfocusports.groupname",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_select, {
                "select", "opa.pa.getfocusports.select",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_start, {
                "start", "opa.pa.getfocusports.start",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_range, {
                "range", "opa.pa.getfocusports.range",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_nodeLID, {
                "nodeLID", "opa.pa.getfocusports.nodelid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_portNumber, {
                "portNumber", "opa.pa.getfocusports.portnumber",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_rate, {
                "rate", "opa.pa.getfocusports.rate",
                FT_UINT8, BASE_HEX, VALS(Rate), 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_mtu, {
                "mtu", "opa.pa.getfocusports.mtu",
                FT_UINT8, BASE_HEX, VALS(MTU), 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_localFlags, {
                "localFlags", "opa.pa.getfocusports.localflags",
                FT_UINT8, BASE_DEC, VALS(FocusPortFlags), 0xF0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_neighborFlags, {
                "neighborFlags", "opa.pa.getfocusports.neighborflags",
                FT_UINT8, BASE_DEC, VALS(FocusPortFlags), 0x0F, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_value, {
                "value", "opa.pa.getfocusports.value",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_nodeGUID, {
                "nodeGUID", "opa.pa.getfocusports.nodeguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_nodeDesc, {
                "nodeDesc", "opa.pa.getfocusports.nodedesc",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_neighborLid, {
                "neighborLid", "opa.pa.getfocusports.neighborlid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_neighborPortNumber, {
                "neighborPortNumber", "opa.pa.getfocusports.neighborportnumber",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_neighborValue, {
                "neighborValue", "opa.pa.getfocusports.neighborvalue",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_neighborGuid, {
                "neighborGuid", "opa.pa.getfocusports.neighborguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetFocusPorts_neighborNodeDesc, {
                "neighborNodeDesc", "opa.pa.getfocusports.neighbornodedesc",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* GetImageInfo */
        { &hf_opa_GetImageInfo, {
                "Image Info", "opa.pa.getimageinfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_sweepStart, {
                "sweepStart", "opa.pa.getimageinfo.sweepstart",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_sweepDuration, {
                "sweepDuration", "opa.pa.getimageinfo.sweepduration",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_numHFIPorts, {
                "numHHIPorts", "opa.pa.getimageinfo.numhfiports",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_numSwitchNodes, {
                "numSwitchNodes", "opa.pa.getimageinfo.numswitchnodes",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_numSwitchPorts, {
                "numSwitchPorts", "opa.pa.getimageinfo.numswitchports",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_numLinks, {
                "numLinks", "opa.pa.getimageinfo.numlinks",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_numSMs, {
                "numSMs", "opa.pa.getimageinfo.numsms",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_numFailedNodes, {
                "numFailedNodes", "opa.pa.getimageinfo.numfailednodes",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_numFailedPorts, {
                "numFailedPorts", "opa.pa.getimageinfo.numfailedports",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_numSkippedNodes, {
                "numSkippedNodes", "opa.pa.getimageinfo.numskippednodes",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_numSkippedPorts, {
                "numSkippedPorts", "opa.pa.getimageinfo.numskippedports",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_numUnexpectedClearPorts, {
                "numUnexpectedClearPorts", "opa.pa.getimageinfo.numunexpectedclearports",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_imageInterval, {
                "imageInterval", "opa.pa.getimageinfo.imageinterval",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_lid, {
                "lid", "opa.pa.getimageinfo.sminfo.lid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_state, {
                "state", "opa.pa.getimageinfo.sminfo.state",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_priority, {
                "priority", "opa.pa.getimageinfo.sminfo.priority",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_portNumber, {
                "portNumber", "opa.pa.getimageinfo.sminfo.portnumber",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_smPortGuid, {
                "portGUID", "opa.pa.getimageinfo.sminfo.portguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetImageInfo_smNodeDesc, {
                "nodeDesc", "opa.pa.getimageinfo.sminfo.nodedesc",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* GetVFList */
        { &hf_opa_GetVFList, {
                "Vf List", "opa.pa.getvflist",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFList_vfName, {
                "VF Name", "opa.pa.getvflist.vfname",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* GetVFInfo */
        { &hf_opa_GetVFInfo, {
                "VF Info", "opa.pa.getvfinfo",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_vfName, {
                "VF Name", "opa.pa.getvfinfo.vfname",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_numPorts, {
                "numPorts", "opa.pa.getvfinfo.numports",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_totalMBps, {
                "totalMBps", "opa.pa.getvfinfo.totalmbps",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_totalKPps, {
                "totalKPps", "opa.pa.getvfinfo.totalkpps",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_avgMBps, {
                "avgMBps", "opa.pa.getvfinfo.avgmbps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_minMBps, {
                "minMBps", "opa.pa.getvfinfo.minmbps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_maxMBps, {
                "maxMBps", "opa.pa.getvfinfo.maxmbps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_numBWBuckets, {
                "numBWBuckets", "opa.pa.getvfinfo.numbwbuckets",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_BWBuckets, {
                "BWBuckets", "opa.pa.getvfinfo.bwbuckets",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_avgKPps, {
                "avgKPps", "opa.pa.getvfinfo.avgkpps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_minKPps, {
                "minKPps", "opa.pa.getvfinfo.minkpps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_maxKPps, {
                "maxKPps", "opa.pa.getvfinfo.maxkpps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_pmaFailedPorts, {
                "pmaFailedPorts", "opa.pa.getvfinfo.pmafailedports",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_topoFailedPorts, {
                "topoFailedPorts", "opa.pa.getvfinfo.topofailedports",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_integrityErrors, {
                "integrityErrors", "opa.pa.getvfinfo.integrityerrors",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_congestionErrors, {
                "congestionErrors", "opa.pa.getvfinfo.congestionerrors",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_smaCongestionErrors, {
                "smaCongestionErrors", "opa.pa.getvfinfo.smacongestionerrors",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_bubbleErrors, {
                "bubbleErrors", "opa.pa.getvfinfo.bubbleerrors",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_securityErrors, {
                "securityErrors", "opa.pa.getvfinfo.securityerrors",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_routingErrors, {
                "routingErrors", "opa.pa.getvfinfo.routingerrors",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_utilizationPct10, {
                "utilizationPct10", "opa.pa.getvfinfo.utilizationpct10",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_computed_pct10), 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_discardsPct10, {
                "discardsPct10", "opa.pa.getvfinfo.discardspct10",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(cf_opa_mad_computed_pct10), 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_maxInternalRate, {
                "maxInternalRate", "opa.pa.getvfinfo.maxinternalrate",
                FT_UINT8, BASE_HEX, VALS(Rate), 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_minInternalRate, {
                "minInternalRate", "opa.pa.getvfinfo.mininternalrate",
                FT_UINT8, BASE_HEX, VALS(Rate), 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFInfo_maxInternalMBps, {
                "maxInternalMBps", "opa.pa.getvfinfo.maxinternalmbps",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* GetVFConfig */
        { &hf_opa_GetVFConfig, {
                "VF Config", "opa.pa.getvfconfig",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFConfig_vfName, {
                "VF Name", "opa.pa.getvfconfig.vfname",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFConfig_Port_NodeGUID, {
                "NodeGUID", "opa.pa.getvfconfig.port.nodeguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFConfig_Port_nodeDesc, {
                "nodeDesc", "opa.pa.getvfconfig.port.nodedesc",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFConfig_Port_NodeLID, {
                "NodeLID", "opa.pa.getvfconfig.port.nodelid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFConfig_Port_PortNumber, {
                "PortNumber", "opa.pa.getvfconfig.port.portnumber",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        /* GetVFPortCounters */
        { &hf_opa_GetVFPortCounters, {
                "VF Port Counters", "opa.pa.getvfportcounters",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_vfName, {
                "VF Name", "opa.pa.getvfportcounters.vfname",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_nodeLID, {
                "nodeLID", "opa.pa.getvfportcounters.nodelid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortNumber, {
                "PortNumber", "opa.pa.getvfportcounters.portnumber",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_flags, {
                "flags", "opa.pa.getvfportcounters.flags",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFXmitData, {
                "PortVFXmitData", "opa.pa.getvfportcounters.portvfxmitdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFRcvData, {
                "PortVFRcvData", "opa.pa.getvfportcounters.portvfrcvdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFXmitPkts, {
                "PortVFXmitPkts", "opa.pa.getvfportcounters.portvfxmitpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFRcvPkts, {
                "PortVFRcvPkts", "opa.pa.getvfportcounters.portvfrcvpkts",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFXmitDiscards, {
                "PortVFXmitDiscards", "opa.pa.getvfportcounters.portvfxmitdiscards",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_SwPortVFCongestion, {
                "SwPortCongestion", "opa.pa.getvfportcounters.swportcongestion",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFXmitWait, {
                "PortVFXmitWait", "opa.pa.getvfportcounters.portvfxmitwait",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFRcvFECN, {
                "PortVFRcvFECN", "opa.pa.getvfportcounters.portvfrcvfecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFRcvBECN, {
                "PortVFRcvBECN", "opa.pa.getvfportcounters.portvfrcvbecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFXmitTimeCong, {
                "PortVFXmitTimeCong", "opa.pa.getvfportcounters.portvfxmittimecong",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFXmitWastedBW, {
                "PortVFXmitWastedBW", "opa.pa.getvfportcounters.portvfxmitwastedbw",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFXmitWaitData, {
                "PortVFXmitWaitData", "opa.pa.getvfportcounters.portvfxmitwaitdata",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFRcvBubble, {
                "PortVFRcvBubble", "opa.pa.getvfportcounters.portvfrcvbubble",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFPortCounters_PortVFMarkFECN, {
                "PortVFMarkFECN", "opa.pa.getvfportcounters.portvfmarkfecn",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        /* ClearVFPortCounters */
        { &hf_opa_ClearVFPortCounters, {
                "Clear VF Port Counters", "opa.pa.clearvfportcounters",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_vfName, {
                "VF Name", "opa.pa.clearvfportcounters.vfname",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_nodeLID, {
                "nodeLID", "opa.pa.clearvfportcounters.nodelid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortNumber, {
                "PortNumber", "opa.pa.clearvfportcounters.portnumber",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_CounterSelectMask, {
                "CounterSelectMask", "opa.pa.clearvfportcounters.counterselectmask",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFXmitData, {
                "PortVFXmitData", "opa.pa.clearvfportcounters.portvfxmitdata",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x80000000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFRcvData, {
                "PortVFRcvData", "opa.pa.clearvfportcounters.portvfrcvdata",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x40000000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFXmitPkts, {
                "PortVFXmitPkts", "opa.pa.clearvfportcounters.portvfxmitpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x20000000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFRcvPkts, {
                "PortVFRcvPkts", "opa.pa.clearvfportcounters.portvfrcvpkts",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x10000000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFXmitDiscards, {
                "PortVFXmitDiscards", "opa.pa.clearvfportcounters.portvfxmitdiscards",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x08000000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_SwPortVFCongestion, {
                "SwPortVFCongestion", "opa.pa.clearvfportcounters.swportvfcongestion",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x04000000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFXmitWait, {
                "PortVFXmitWait", "opa.pa.clearvfportcounters.portvfxmitwait",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x02000000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFRcvFECN, {
                "PortVFRcvFECN", "opa.pa.clearvfportcounters.portvfrcvfecn",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x01000000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFRcvBECN, {
                "PortVFRcvBECN", "opa.pa.clearvfportcounters.portvfrcvbecn",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00800000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFXmitTimeCong, {
                "PortVFXmitTimeCong", "opa.pa.clearvfportcounters.portvfxmittimecong",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00400000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFXmitWastedBW, {
                "PortVFXmitWastedBW", "opa.pa.clearvfportcounters.portvfxmitwastedbw",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00200000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFXmitWaitData, {
                "PortVFXmitWaitData", "opa.pa.clearvfportcounters.portvfxmitwaitdata",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00100000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFRcvBubble, {
                "PortVFRcvBubble", "opa.pa.clearvfportcounters.portvfrcvbubble",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00080000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_PortVFMarkFECN, {
                "PortVFMarkFECN", "opa.pa.clearvfportcounters.portvfmarkfecn",
                FT_BOOLEAN, 32, TFS(&tfs_clear_dont_clear), 0x00040000, NULL, HFILL }
        },
        { &hf_opa_ClearVFPortCounters_reserved, {
                "Reserved", "opa.pa.clearvfportcounters.reserved",
                FT_UINT32, BASE_HEX, NULL, 0x0003FFFF, NULL, HFILL }
        },

        /* GetVFFocusPorts */
        { &hf_opa_GetVFFocusPorts, {
                "VF Focus Ports", "opa.pa.getvffocusports",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_vfName, {
                "VF Name", "opa.pa.getvffocusports.vfname",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_select, {
                "select", "opa.pa.getvffocusports.select",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_start, {
                "start", "opa.pa.getvffocusports.start",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_range, {
                "range", "opa.pa.getvffocusports.range",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_nodeLID, {
                "nodeLID", "opa.pa.getvffocusports.nodelid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_portNumber, {
                "portNumber", "opa.pa.getvffocusports.portnumber",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_rate, {
                "rate", "opa.pa.getvffocusports.rate",
                FT_UINT8, BASE_HEX, VALS(Rate), 0xF8, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_mtu, {
                "mtu", "opa.pa.getvffocusports.mtu",
                FT_UINT8, BASE_HEX, VALS(MTU), 0x07, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_localFlags, {
                "localFlags", "opa.pa.getvffocusports.localflags",
                FT_UINT8, BASE_DEC, VALS(FocusPortFlags), 0xF0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_neighborFlags, {
                "neighborFlags", "opa.pa.getvffocusports.neighborflags",
                FT_UINT8, BASE_DEC, VALS(FocusPortFlags), 0x0F, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_value, {
                "value", "opa.pa.getvffocusports.value",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_nodeGUID, {
                "nodeGUID", "opa.pa.getvffocusports.nodeguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_nodeDesc, {
                "nodeDesc", "opa.pa.getvffocusports.nodedesc",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_neighborLid, {
                "neighborLid", "opa.pa.getvffocusports.neighborlid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_neighborPortNumber, {
                "neighborPortNumber", "opa.pa.getvffocusports.neighborportnumber",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_neighborValue, {
                "neighborValue", "opa.pa.getvffocusports.neighborvalue",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_neighborGuid, {
                "neighborGuid", "opa.pa.getvffocusports.neighborguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_GetVFFocusPorts_neighborNodeDesc, {
                "neighborNodeDesc", "opa.pa.getvffocusports.neighbornodedesc",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* VFInfoRecord */
        { &hf_opa_VFInfoRecord, {
                "VF Info Record", "opa.vfinforecorf",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_vfIndex, {
                "VF Index", "opa.vfinforecorf.vfindex",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_pKey, {
                "P Key", "opa.vfinforecord.pkey",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_vfName, {
                "VF Name", "opa.vfinforecord.vfname",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_MGID, {
                "M GID", "opa.vfinforecord.mgid",
                FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_SelectFlags, {
                "Select Flags", "opa.vfinforecord.selectflags",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_reserved, {
                "Reserved (1 bit)", "opa.vfinforecord.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x20, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_SL, {
                "SL", "opa.vfinforecord.sl",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_MTUSpecified, {
                "MTU Specified", "opa.vfinforecord.mtuspecified",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_reserved2, {
                "Reserved (1 bit)", "opa.vfinforecord.reserved2",
                FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_MTU, {
                "MTU", "opa.vfinforecord.mtu",
                FT_UINT8, BASE_HEX, VALS(MTU), 0x3F, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_RateSpecified, {
                "Rate Specified", "opa.vfinforecord.ratespecified",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_reserved4, {
                "Reserved (1 bit)", "opa.vfinforecord.reserved4",
                FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_Rate, {
                "Rate", "opa.vfinforecord.rate",
                FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_PktLifeSpecified, {
                "Packet Life Time Specified", "opa.vfinforecord.pktlifespecified",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_reserved5, {
                "Reserved (4 bits)", "opa.vfinforecord.reserved5",
                FT_UINT8, BASE_HEX, NULL, 0x78, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_PktLifeTimeInc, {
                "Packet Life Time", "opa.vfinforecord.pktlifetime",
                FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_OptionFlags, {
                "Option Flags", "opa.vfinforecord.optionflags",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_BandwidthPercent, {
                "Bandwidth Percent", "opa.vfinforecord.bandwidthpercent",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_reserved6, {
                "Reserved (7 bits)", "opa.vfinforecord.reserved6",
                FT_UINT8, BASE_HEX, NULL, 0xFE, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_Priority, {
                "Priority", "opa.vfinforecord.priority",
                FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_RoutingSLs, {
                "Routing SLs", "opa.vfinforecord.routingsls",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_VFInfoRecord_reserved7, {
                "Reserved (24 Bytes)", "opa.vfinforecord.reserved7",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        /* QuarantinedNodeRecord */
        { &hf_opa_QuarantinedNodeRecord, {
                "Quarantined Node Record", "opa.quarantinednoderecord",
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_QuarantinedNodeRecord_TrustedLid, {
                "Trusted LID", "opa.quarantinednoderecord.trustedlid",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_QuarantinedNodeRecord_TrustedNodeGUID, {
                "Trusted Node GUID", "opa.quarantinednoderecord.trustednodeguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_QuarantinedNodeRecord_TrustedPortNum, {
                "Trusted Port Num", "opa.quarantinednoderecord.trustedportnum",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_QuarantinedNodeRecord_TrustedNeighborNodeGUID, {
                "Trusted Neighbor Node GUID", "opa.quarantinednoderecord.trustedneighbornodeguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_QuarantinedNodeRecord_QuarantineReasons, {
                "Quarantine Reasons", "opa.quarantinednoderecord.quarantinereasons",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_QuarantinedNodeRecord_ExpectedNodeDesc, {
                "Expected Node Desc", "opa.quarantinednoderecord.expectednodedesc",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_QuarantinedNodeRecord_ExpectedNodeGUID, {
                "Expected Node GUID", "opa.quarantinednoderecord.expectednodeguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_QuarantinedNodeRecord_ExpectedPortGUID, {
                "Expected Port GUID", "opa.quarantinednoderecord.expectedportguid",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_payload,
        &ett_sm_lid,
        &ett_sm_dr,
        &ett_sa,
        &ett_pm,
        &ett_pa,
        &ett_mad,
        &ett_mad_status,
        &ett_mad_attributemod,
        &ett_rmpp,
        &ett_rmpp_fragment,
        &ett_rmpp_fragments,
        &ett_rmpp_sa_record,
        /* Common */
        &ett_noticestraps,
        &ett_datadetails,
        &ett_datadetails_trap259datavalid,
        &ett_informinfo,
        &ett_classportinfo,
        &ett_classportinfo_redirect,
        &ett_classportinfo_trap,
        /* SM */
        &ett_nodedescription,
        &ett_nodeinfo,
        &ett_switchinfo,
        &ett_switchinfo_switchcapabilitymask,
        &ett_portinfo,
        &ett_portinfo_vl,
        &ett_portinfo_link,
        &ett_portinfo_portmode,
        &ett_portinfo_flitcontrol,
        &ett_portinfo_porterroraction,
        &ett_portinfo_neighbormtu,
        &ett_portinfo_xmitq,
        &ett_portinfo_capmask,
        &ett_portinfo_capmask3,
        &ett_portstates,
        &ett_pkeytable,
        &ett_pkeytable_block,
        &ett_sltoscmapping,
        &ett_sltoscmapping_block,
        &ett_sctoscmapping,
        &ett_sctoscmapping_block,
        &ett_sctoslmapping,
        &ett_sctoslmapping_block,
        &ett_sctovlxmappingtable,
        &ett_sctovlxmappingtable_block,
        &ett_vlarbitrationtable,
        &ett_vlarbitrationtable_port,
        &ett_linearforwardingtable,
        &ett_linearforwardingtable_block,
        &ett_multicastforwardingtable,
        &ett_multicastforwardingtable_block,
        &ett_portgroupforwardingtable,
        &ett_portgroupforwardingtable_block,
        &ett_portgrouptable,
        &ett_portgrouptable_block,
        &ett_sminfo,
        &ett_ledinfo,
        &ett_cableinfo,
        &ett_aggregate,
        &ett_buffercontroltable,
        &ett_congestioninfo,
        &ett_switchcongestionlog,
        &ett_switchcongestionlog_entry,
        &ett_switchcongestionsetting,
        &ett_switchportcongestionsetting,
        &ett_switchportcongestionsetting_port,
        &ett_hficongestionlog,
        &ett_hficongestionlog_entry,
        &ett_hficongestionsetting,
        &ett_hficongestioncontroltable,
        &ett_hficongestioncontroltable_block,
        /* SA */
        &ett_portinforecord_linkdownreason,
        &ett_portinforecord_linkdownreason_entry,
        &ett_scmappingrecord,
        &ett_lftrecord,
        &ett_linkrecord,
        &ett_servicerecord,
        &ett_pathrecord,
        &ett_pathrecord_dgid,
        &ett_pathrecord_sgid,
        &ett_mcmemberrecord,
        &ett_tracerecord,
        &ett_multipathrecord_gid,
        &ett_multipathrecord_guid,
        &ett_multipathrecord_lid,
        &ett_cableinforecord,
        &ett_serviceassocrecord,
        &ett_sctoslmappingtablerecord,
        &ett_portgroupforwardingtablerecord,
        &ett_vfinforecord,
        &ett_quarantinednoderecord,
        &ett_fabricinforecord,
        /* PM */
        &ett_portstatus,
        &ett_portstatus_vl,
        &ett_clearportstatus,
        &ett_clearportstatus_counterselectmask,
        &ett_dataportcounters,
        &ett_dataportcounters_port,
        &ett_dataportcounters_vl,
        &ett_errorportcounters,
        &ett_errorportcounters_port,
        &ett_errorportinfo,
        &ett_errorportinfoport,
        &ett_errorportinfo_portrcverrorinfo,
        &ett_errorportinfo_excessivebufferoverruninfo,
        &ett_errorportinfo_portxmitconstrainterrorinfo,
        &ett_errorportinfo_portrcvconstrainterrorinfo,
        &ett_errorportinfo_portrcvswitchrelayerrorinfo,
        &ett_errorportinfo_uncorrectableerrorinfo,
        &ett_errorportinfo_fmconfigerrorinfo,
        /* PA */
        &ett_getgrouplist,
        &ett_getgroupinfo,
        &ett_getgroupinfoutilstats,
        &ett_getgroupinfoutilbuckets,
        &ett_getgroupinfoerrorsummary,
        &ett_getgroupinfoerrintegritybucket,
        &ett_getgroupinfoerrcongestionbucket,
        &ett_getgroupinfoerrsmacongestionbucket,
        &ett_getgroupinfoerrbubblebucket,
        &ett_getgroupinfoerrsecuritybucket,
        &ett_getgroupinfoerrroutingbucket,
        &ett_getportcounters,
        &ett_clearportcounters,
        &ett_clearportcounters_counterselectmask,
        &ett_clearallportcounters,
        &ett_clearallportcounters_counterselectmask,
        &ett_pmconfig,
        &ett_getgroupconfig,
        &ett_getgroupconfigport,
        &ett_movefreezeframeold,
        &ett_movefreezeframenew,
        &ett_getfocusports,
        &ett_getfocusportsport,
        &ett_getimageinfo,
        &ett_getimageinfosm,
        &ett_getvflist,
        &ett_getvfinfo,
        &ett_getvfinfoutilstats,
        &ett_getvfinfoutilbuckets,
        &ett_getvfinfoerrorsummary,
        &ett_getvfinfoerrintegritybucket,
        &ett_getvfinfoerrcongestionbucket,
        &ett_getvfinfoerrsmacongestionbucket,
        &ett_getvfinfoerrbubblebucket,
        &ett_getvfinfoerrsecuritybucket,
        &ett_getvfinfoerrroutingbucket,
        &ett_getvfconfig,
        &ett_getvfconfigport,
        &ett_getvffocusports,
        &ett_getvffocusportsport,
        &ett_getvfportcounters,
        &ett_clearvfportcounters,
        &ett_clearvfportcounters_counterselectmask
    };

    static ei_register_info ei[] = {
        { &ei_opa_mad_error, {
                "opa.mad.error", PI_RESPONSE_CODE, PI_WARN,
                "MAD Status Error", EXPFILL }
        },
        { &ei_opa_mad_no_attribute_dissector, {
                "opa.mad.noattributedissector", PI_UNDECODED, PI_NOTE,
                "Attribute Dissector Not Implemented", EXPFILL }
        },
        { &ei_opa_mad_attribute_modifier_error_nonzero, {
                "opa.mad.attributemodifiererrornonzero", PI_PROTOCOL, PI_WARN,
                "Attribute Modifier is unexpectedly Non-zero", EXPFILL }
        },
        { &ei_opa_rmpp_undecoded, {
                "opa.rmpp.undecoded", PI_UNDECODED, PI_NOTE,
                "RMPP Records Undecoded", EXPFILL }
        },
        { &ei_opa_aggregate_error, {
                "opa.aggregate.error.exp", PI_RESPONSE_CODE, PI_WARN,
                "Aggregate Error", EXPFILL }
        }
    };

    proto_opa_mad = proto_register_protocol("Intel Omni-Path MAD", "OPA MAD", "opa.mad");
    opa_mad_handle = register_dissector("opa.mad", dissect_opa_mad, proto_opa_mad);

    proto_register_field_array(proto_opa_mad, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_opa_mad = expert_register_protocol(proto_opa_mad);
    expert_register_field_array(expert_opa_mad, ei, array_length(ei));

    range_convert_str(wmem_epan_scope(), &global_mad_vendor_class, OPA_VENDOR_RANGE_STR, 0xFF);
    range_convert_str(wmem_epan_scope(), &global_mad_vendor_rmpp_class, OPA_VENDOR_RMPP_RANGE_STR, 0xFF);
    range_convert_str(wmem_epan_scope(), &global_mad_application_class, OPA_APPLICATION_RANGE_STR, 0xFF);
    range_convert_str(wmem_epan_scope(), &global_mad_reserved_class, OPA_RESERVED_RANGE_STR, 0xFF);
    range_convert_str(wmem_epan_scope(), &global_mad_opa_class, OPA_MGMTCLASS_RANGE_STR, 0xFF);

    opa_mad_module = prefs_register_protocol(proto_opa_mad, NULL);
    prefs_register_bool_preference(opa_mad_module, "parse_mad_error",
        "Enable Parsing of Mad Payload on Mad Status Error",
        "Attempt to parse mad payload even when MAD.Status is non-zero",
        &pref_parse_on_mad_status_error);
    prefs_register_bool_preference(opa_mad_module, "reassemble_rmpp",
        "Enable Reassembly of RMPP packets",
        "Attempt to reassemble the mad payload of RMPP segments",
        &pref_attempt_rmpp_defragment);

    register_init_routine(opa_mad_init);
    register_cleanup_routine(opa_mad_cleanup);
}

void proto_reg_handoff_opa_mad(void)
{
    ethertype_dissector_table       = find_dissector_table("ethertype");
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
