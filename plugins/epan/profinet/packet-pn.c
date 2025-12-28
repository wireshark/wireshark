/* packet-pn.c
 * Common functions for other PROFINET protocols like IO, CBA, DCP, ...
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/wmem_scopes.h>
#include <epan/dissectors/packet-dcerpc.h>

#include <wsutil/ws_padding_to.h>

#include "packet-pn.h"

static int hf_pn_padding;
static int hf_pn_undecoded_data;
static int hf_pn_user_data;
static int hf_pn_user_bytes;
static int hf_pn_frag_bytes;
static int hf_pn_malformed;

static int hf_pn_io_status;

static int hf_pn_io_error_code;
static int hf_pn_io_error_decode;
static int hf_pn_io_error_code1;
static int hf_pn_io_error_code1_pniorw;
static int hf_pn_io_error_code1_pnio;
static int hf_pn_io_error_code2;
static int hf_pn_io_error_code2_pniorw;
static int hf_pn_io_error_code2_pnio_1;
static int hf_pn_io_error_code2_pnio_2;
static int hf_pn_io_error_code2_pnio_3;
static int hf_pn_io_error_code2_pnio_4;
static int hf_pn_io_error_code2_pnio_5;
static int hf_pn_io_error_code2_pnio_6;
static int hf_pn_io_error_code2_pnio_7;
static int hf_pn_io_error_code2_pnio_8;
static int hf_pn_io_error_code2_pnio_9;
static int hf_pn_io_error_code2_pnio_10;
static int hf_pn_io_error_code2_pnio_11;
static int hf_pn_io_error_code2_pnio_12;
static int hf_pn_io_error_code2_pnio_13;
static int hf_pn_io_error_code2_pnio_14;
static int hf_pn_io_error_code2_pnio_20;
static int hf_pn_io_error_code2_pnio_21;
static int hf_pn_io_error_code2_pnio_22;
static int hf_pn_io_error_code2_pnio_23;
static int hf_pn_io_error_code2_pnio_24;
static int hf_pn_io_error_code2_pnio_25;
static int hf_pn_io_error_code2_pnio_26;
static int hf_pn_io_error_code2_pnio_27;
static int hf_pn_io_error_code2_pnio_40;
static int hf_pn_io_error_code2_pnio_60;
static int hf_pn_io_error_code2_pnio_61;
static int hf_pn_io_error_code2_pnio_62;
static int hf_pn_io_error_code2_pnio_63;
static int hf_pn_io_error_code2_pnio_64;
static int hf_pn_io_error_code2_pnio_65;
static int hf_pn_io_error_code2_pnio_66;
static int hf_pn_io_error_code2_pnio_69;
static int hf_pn_io_error_code2_pnio_70;
static int hf_pn_io_error_code2_pnio_71;
static int hf_pn_io_error_code2_pnio_72;
static int hf_pn_io_error_code2_pnio_73;
static int hf_pn_io_error_code2_pnio_74;
static int hf_pn_io_error_code2_pnio_75;
static int hf_pn_io_error_code2_pnio_76;
static int hf_pn_io_error_code2_pnio_77;
static int hf_pn_io_error_code2_pnio_79;
static int hf_pn_io_error_code2_pnio_80;
static int hf_pn_io_error_code2_pnio_100;
static int hf_pn_io_error_code2_pnio_101;
static int hf_pn_io_error_code2_pnio_102;
static int hf_pn_io_error_code2_pnio_103;
static int hf_pn_io_error_code2_pnio_104;
static int hf_pn_io_error_code2_pnio_105;
static int hf_pn_io_error_code2_pnio_106;
static int hf_pn_io_error_code2_pnio_107;
static int hf_pn_io_error_code2_pnio_108;
static int hf_pn_io_error_code2_pnio_109;
static int hf_pn_io_error_code2_pnio_110;
static int hf_pn_io_error_code2_pnio_112;
static int hf_pn_io_error_code2_pnio_114;
static int hf_pn_io_error_code2_pnio_253;
static int hf_pn_io_error_code2_pnio_255;

static int ett_pn_io_status;

static expert_field ei_pn_undecoded_data;
static expert_field ei_pn_io_error_code1;
static expert_field ei_pn_io_error_code2;

static const value_string pn_io_error_code[] = {
    { 0x00, "OK" },
    { 0x81, "PNIO" },
    { 0xCF, "RTA error" },
    { 0xDA, "AlarmAck" },
    { 0xDB, "IODConnectRes" },
    { 0xDC, "IODReleaseRes" },
    { 0xDD, "IODControlRes" },
    { 0xDE, "IODReadRes" },
    { 0xDF, "IODWriteRes" },
    { 0, NULL }
};

static const value_string pn_io_error_decode[] = {
    { 0x00, "OK" },
    { 0x80, "PNIORW" },
    { 0x81, "PNIO" },
    { 0, NULL }
};

/* dummy for unknown decode */
static const value_string pn_io_error_code1[] = {
    { 0x00, "OK" },
    { 0, NULL }
};

/* dummy for unknown decode/code1 combination */
static const value_string pn_io_error_code2[] = {
    { 0x00, "OK" },
    { 0, NULL }
};

static const value_string pn_io_error_code1_pniorw[] = {
    /* high nibble 0-9 not specified -> legacy codes */
    { 0xa0, "application: read error" },
    { 0xa1, "application: write error" },
    { 0xa2, "application: module failure" },
    { 0xa3, "application: not specified" },
    { 0xa4, "application: not specified" },
    { 0xa5, "application: not specified" },
    { 0xa6, "application: not specified" },
    { 0xa7, "application: busy" },
    { 0xa8, "application: version conflict" },
    { 0xa9, "application: feature not supported" },
    { 0xaa, "application: User specific 1" },
    { 0xab, "application: User specific 2" },
    { 0xac, "application: User specific 3" },
    { 0xad, "application: User specific 4" },
    { 0xae, "application: User specific 5" },
    { 0xaf, "application: User specific 6" },
    { 0xb0, "access: invalid index" },
    { 0xb1, "access: write length error" },
    { 0xb2, "access: invalid slot/subslot" },
    { 0xb3, "access: type conflict" },
    { 0xb4, "access: invalid area" },
    { 0xb5, "access: state conflict" },
    { 0xb6, "access: access denied" },
    { 0xb7, "access: invalid range" },
    { 0xb8, "access: invalid parameter" },
    { 0xb9, "access: invalid type" },
    { 0xba, "access: backup" },
    { 0xbb, "access: User specific 7" },
    { 0xbc, "access: User specific 8" },
    { 0xbd, "access: User specific 9" },
    { 0xbe, "access: User specific 10" },
    { 0xbf, "access: User specific 11" },
    { 0xc0, "resource: read constrain conflict" },
    { 0xc1, "resource: write constrain conflict" },
    { 0xc2, "resource: resource busy" },
    { 0xc3, "resource: resource unavailable" },
    { 0xc4, "resource: not specified" },
    { 0xc5, "resource: not specified" },
    { 0xc6, "resource: not specified" },
    { 0xc7, "resource: not specified" },
    { 0xc8, "resource: User specific 12" },
    { 0xc9, "resource: User specific 13" },
    { 0xca, "resource: User specific 14" },
    { 0xcb, "resource: User specific 15" },
    { 0xcc, "resource: User specific 16" },
    { 0xcd, "resource: User specific 17" },
    { 0xce, "resource: User specific 18" },
    { 0xcf, "resource: User specific 19" },
    /* high nibble d-f user specific */
    { 0, NULL }
};

static const value_string pn_io_error_code2_pniorw[] = {
    /* all values are user specified */
    { 0, NULL }
};

static const value_string pn_io_error_code1_pnio[] = {
    { 0x00 /*  0*/, "Reserved" },
    { 0x01 /*  1*/, "Connect: Faulty ARBlockReq" },
    { 0x02 /*  2*/, "Connect: Faulty IOCRBlockReq" },
    { 0x03 /*  3*/, "Connect: Faulty ExpectedSubmoduleBlockReq" },
    { 0x04 /*  4*/, "Connect: Faulty AlarmCRBlockReq" },
    { 0x05 /*  5*/, "Connect: Faulty PrmServerBlockReq" },
    { 0x06 /*  6*/, "Connect: Faulty MCRBlockReq" },
    { 0x07 /*  7*/, "Connect: Faulty ARRPCBlockReq" },
    { 0x08 /*  8*/, "Read/Write Record: Faulty Record" },
    { 0x09 /*  9*/, "Connect: Faulty IRInfoBlock" },
    { 0x0A /* 10*/, "Connect: Faulty SRInfoBlock" },
    { 0x0B /* 11*/, "Connect: Faulty ARFSUBlock" },
    { 0x0C /* 12*/, "Connect: Faulty ARVendorBlockReq" },
    { 0x0D /* 13*/, "Connect: Faulty RSInfoBlock" },
    { 0x0E /* 14*/, "Connect: ARAlgorithmInfoBlock"},
    { 0x14 /* 20*/, "IODControl: Faulty ControlBlockConnect" },
    { 0x15 /* 21*/, "IODControl: Faulty ControlBlockPlug" },
    { 0x16 /* 22*/, "IOXControl: Faulty ControlBlock after a connect est." },
    { 0x17 /* 23*/, "IOXControl: Faulty ControlBlock a plug alarm" },
    { 0x18 /* 24*/, "IOXControl: Faulty ControlBlockPrmBegin" },
    { 0x19 /* 25*/, "IOXControl: Faulty SubmoduleListBlock" },
    { 0x1A /* 26*/, "IOXSecure: Faulty SecurityRequestBlock"},
    { 0x1B /* 27*/, "IOXSecure: Faulty ARUUIDBlock"},

    { 0x28 /* 40*/, "Release: Faulty ReleaseBlock" },

    { 0x32 /* 50*/, "Response: Faulty ARBlockRes" },
    { 0x33 /* 51*/, "Response: Faulty IOCRBlockRes" },
    { 0x34 /* 52*/, "Response: Faulty AlarmCRBlockRes" },
    { 0x35 /* 53*/, "Response: Faulty ModuleDifflock" },
    { 0x36 /* 54*/, "Response: Faulty ARRPCBlockRes" },
    { 0x37 /* 55*/, "Response: Faulty ARServerBlockRes" },
    { 0x38 /* 56*/, "Response: Faulty ARVendorBlockRes" },

    { 0x3c /* 60*/, "AlarmAck Error Codes" },
    { 0x3d /* 61*/, "CMDEV" },
    { 0x3e /* 62*/, "CMCTL" },
    { 0x3f /* 63*/, "CTLDINA" },
    { 0x40 /* 64*/, "CMRPC" },
    { 0x41 /* 65*/, "ALPMI" },
    { 0x42 /* 66*/, "ALPMR" },
    { 0x43 /* 67*/, "LMPM" },
    { 0x44 /* 68*/, "MAC" },
    { 0x45 /* 69*/, "RPC" },
    { 0x46 /* 70*/, "APMR" },
    { 0x47 /* 71*/, "APMS" },
    { 0x48 /* 72*/, "CPM" },
    { 0x49 /* 73*/, "PPM" },
    { 0x4a /* 74*/, "DCPUCS" },
    { 0x4b /* 75*/, "DCPUCR" },
    { 0x4c /* 76*/, "DCPMCS" },
    { 0x4d /* 77*/, "DCPMCR" },
    { 0x4e /* 78*/, "FSPM" },
    { 0x4f /* 79*/, "RSI" },
    { 0x50 /* 80*/, "RSIR" },

    { 0x64 /*100*/, "CTLSM" },
    { 0x65 /*101*/, "CTLRDI" },
    { 0x66 /*102*/, "CTLRDR" },
    { 0x67 /*103*/, "CTLWRI" },
    { 0x68 /*104*/, "CTLWRR" },
    { 0x69 /*105*/, "CTLIO" },
    { 0x6a /*106*/, "CTLSU" },
    { 0x6b /*107*/, "CTLRPC" },
    { 0x6c /*108*/, "CTLBE" },
    { 0x6d /*109*/, "CTLSRL" },
    { 0x6e /*110*/, "NME" },
    { 0x6f /*111*/, "TDE" },
    { 0x70 /*112*/, "PCE" },
    { 0x71 /*113*/, "NCE" },
    { 0x72 /*114*/, "NUE" },
    { 0x73 /*115*/, "BNME" },
    { 0x74 /*116*/, "CTLSAM" },

    { 0xc8 /*200*/, "CMSM" },
    { 0xca /*202*/, "CMRDR" },
    { 0xcc /*204*/, "CMWRR" },
    { 0xcd /*205*/, "CMIO" },
    { 0xce /*206*/, "CMSU" },
    { 0xd0 /*208*/, "CMINA" },
    { 0xd1 /*209*/, "CMPBE" },
    { 0xd2 /*210*/, "CMSRL" },
    { 0xd3 /*211*/, "CMDMC" },
    { 0xd4 /*212*/, "CMSAM" },

    { 0xfd /*253*/, "RTA_ERR_CLS_PROTOCOL" },
    { 0xff /*255*/, "User specific" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_1[] = {
    /* CheckingRules for ARBlockReq */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter ARType" },
    { 5, "Error in Parameter ARUUID" },
    { 7, "Error in Parameter CMInitiatorMACAddress" },
    { 8, "Error in Parameter CMInitiatorObjectUUID" },
    { 9, "Error in Parameter ARProperties" },
    { 10, "Error in Parameter CMInitiatorActivityTimeoutFactor" },
    { 11, "Error in Parameter InitiatorUDPRTPort" },
    { 12, "Error in Parameter StationNameLength" },
    { 13, "Error in Parameter CMInitiatorStationName" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_2[] = {
    /* CheckingRules for IOCRBlockReq */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter IOCRType" },
    { 5, "Error in Parameter IOCRReference" },
    { 6, "Error in Parameter LT" },
    { 7, "Error in Parameter IOCRProperties" },
    { 8, "Error in Parameter DataLength" },
    { 9, "Error in Parameter FrameID" },
    { 10, "Error in Parameter GatingCycle" },
    { 11, "Error in Parameter ReductionRatio" },
    { 12, "Error in Parameter Phase" },
    { 14, "Error in Parameter FrameSendOffset" },
    { 15, "Error in Parameter WatchdogFactor" },
    { 16, "Error in Parameter DataHoldFactor" },
    { 17, "Error in Parameter IOCRTagHeader" },
    { 18, "Error in Parameter IOCRMulticastMacAddress" },
    { 19, "Error in Parameter NumberOfAPI" },
    { 20, "Error in Parameter API" },
    { 21, "Error in Parameter NumberOfIODataObjects" },
    { 22, "Error in Parameter SlotNumber" },
    { 23, "Error in Parameter SubslotNumber" },
    { 24, "Error in Parameter IODataObjectFrameOffset" },
    { 25, "Error in Parameter NumberOfIOCS" },
    { 26, "Error in Parameter SlotNumber" },
    { 27, "Error in Parameter SubslotNumber" },
    { 28, "Error in Parameter IOCSFrameOffset" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_3[] = {
    /* CheckingRules for ExpectedSubmoduleBlockReq */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter NumberOfAPI" },
    { 5, "Error in Parameter API" },
    { 6, "Error in Parameter SlotNumber" },
    { 7, "Error in Parameter ModuleIdentNumber" },
    { 8, "Error in Parameter ModuleProperties" },
    { 9, "Error in Parameter NumberOfSubmodules" },
    { 10, "Error in Parameter SubslotNumber" },
    { 12, "Error in Parameter SubmoduleProperties" },
    { 13, "Error in Parameter DataDescription" },
    { 14, "Error in Parameter SubmoduleDataLength" },
    { 15, "Error in Parameter LengthIOPS" },
    { 16, "Error in Parameter LengthIOCS" },
    { 0, NULL }
};


static const value_string pn_io_error_code2_pnio_4[] = {
    /* CheckingRules for AlarmCRBlockReq */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter AlarmCRType" },
    { 5, "Error in Parameter LT" },
    { 6, "Error in Parameter AlarmCRProperties" },
    { 7, "Error in Parameter RTATimeoutFactor" },
    { 8, "Error in Parameter RTARetries" },
    { 10, "Error in Parameter MaxAlarmDataLength" },
    { 11, "Error in Parameter AlarmCRTagHeaderHigh" },
    { 12, "Error in Parameter AlarmCRTagHeaderLow" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_5[] = {
    /* CheckingRules for PrmServerBlockReq */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 6, "Error in Parameter CMInitiatorActivityTimeoutFactor" },
    { 7, "Error in Parameter StationNameLength" },
    { 8, "Error in Parameter ParameterServerStationName" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_6[] = {
    /* CheckingRules for MCRBlockReq */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter IOCRReference" },
    { 5, "Error in Parameter AddressResolutionProperties" },
    { 6, "Error in Parameter MCITimeoutFactor" },
    { 7, "Error in Parameter StationNameLength" },
    { 8, "Error in Parameter ProviderStationName" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_7[] = {
    /* CheckingRules for ARRPCBlockReq */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter InitiatorRPCServerPort" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_8[] = {
    /* CheckingRules for Faulty Record */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 5, "Error in Parameter ARUUID" },
    { 6, "Error in Parameter API" },
    { 7, "Error in Parameter SlotNumber" },
    { 8, "Error in Parameter SubslotNumber" },
    { 9, "Error in Parameter Padding" },
    { 10, "Error in Parameter Index" },
    { 11, "Error in Parameter RecordDataLength" },
    { 12, "Error in Parameter TargetARUUID" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_9[] = {
    /* CheckingRules for IRInfoBlock */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter Length" },
    { 2, "Error in BlockVersionHigh" },
    { 3, "Error in BlockVersionLow" },
    { 5, "Error in IRDataUUID" },
    { 7, "Error in NumberOfIOCRs" },
    { 8, "Error in IOCRReference" },
    { 9, "Error in SubframeOffset" },
    { 10, "Error in SubframeData" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_10[] = {
    /* Checking Rules for SRInfoBlock */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter Length" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter RedundancyDataHoldFactor" },
    { 5, "Error in Parameter SRProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_11[] = {
    /* CheckingRules for ARFSUBlock */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter Length" },
    { 5, "Error in Parameter FastStartUpBlock" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_12[] = {
    /* CheckingRules for ARVendorBlockReq */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter Length" },
    { 5, "Error in Parameter API" },
    { 6, "Error in Parameter Data*" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_13[] = {
    /* CheckingRules for RSInfoBlock */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter Padding" },
    { 5, "Error in Parameter RSProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_14[] = {
    /* Checking Rules for ARAlgorithmInfoBlock */
    { 0, "Error in Parameter BlockType" },
    { 8, "SecurityCapability" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_20[] = {
    /* CheckingRules for ControlBlockConnect */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter Padding" },
    { 6, "Error in Parameter SessionKey" },
    { 7, "Error in Parameter Padding" },
    { 8, "Error in Parameter ControlCommand" },
    { 9, "Error in Parameter ControlBlockProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_21[] = {
    /* CheckingRules for ControlBlockPlug */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter Padding" },
    { 6, "Error in Parameter SessionKey" },
    { 7, "Error in Parameter AlarmSequenceNumber" },
    { 8, "Error in Parameter ControlCommand" },
    { 9, "Error in Parameter ControlBlockProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_22[] = {
    /* CheckingRule for ControlBlockConnect */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter Padding" },
    { 6, "Error in Parameter SessionKey" },
    { 7, "Error in Parameter Padding" },
    { 8, "Error in Parameter ControlCommand" },
    { 9, "Error in Parameter ControlBlockProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_23[] = {
    /* CheckingRules for ControlBlockPlug */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter Padding" },
    { 6, "Error in Parameter SessionKey" },
    { 7, "Error in Parameter AlarmSequenceNumber" },
    { 8, "Error in Parameter ControlCommand" },
    { 9, "Error in Parameter ControlBlockProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_24[] = {
    /* CheckingRules for ControlBlockPrmBegin */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter Length" },
    { 9, "Error in Parameter ControlBlockProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_25[] = {
    /* CheckingRules for SubmoduleListBlock */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter Length" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter NumberOfEntries" },
    { 5, "Error in Parameter API" },
    { 6, "Error in Parameter SlotNumber" },
    { 7, "Error in Parameter SubslotNumber" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_26[] = {
    /* CheckingRules for SecurityRequestBlock */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter Length" },
    { 4, "SecurityOperation" },
    { 5, "SAMRequestData" },
    { 16, "CredentialID" },
    { 17, "CredentialCreationProperties" },
    { 18, "PrivateKeyLength" },
    { 19, "PrivateKey" },
    { 20, "Padding" },
    { 21, "NumberOfElements" },
    { 22, "CertificateLength" },
    { 23, "Certificate" },
    { 24, "SecurityConfigurationParameters" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_27[] = {
    /* CheckingRules for ARUUIDBlock */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter Length" },
    { 6, "Error in Parameter ARUUID" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_40[] = {
    /* CheckingRules for ReleaseBlock */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter Padding" },
    { 6, "Error in Parameter SessionKey" },
    { 7, "Error in Parameter Padding" },
    { 8, "Error in Parameter ControlCommand" },
    { 9, "Error in Parameter ControlBlockProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_60[] = {
    /* AlarmAck Error Codes */
    { 0, "Alarm Type Not Supported" },
    { 1, "Wrong Submodule State" },
    { 2, "IOCARSR Backup - Alarm not executed" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_61[] = {
    /* CMDEV */
    { 0, "State Conflict" },
    { 1, "Resources" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_62[] = {
    /* CMCTL */
    { 0, "State Conflict" },
    { 1, "Timeout" },
    { 2, "No data send" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_63[] = {
    /* CTLDINA */
    { 0, "No DCP active / No Link" },
    { 1, "DNS Unknown_RealStationName" },
    { 2, "DCP No_RealStationName" },
    { 3, "DCP Multiple_RealStationName" },
    { 4, "DCP No_StationName" },
    { 5, "No_IP_Addr" },
    { 6, "DCP_Set_Error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_64[] = {
    /* CMRPC */
    { 0, "ArgsLength invalid" },
    { 1, "Unknown Blocks" },
    { 2, "IOCR Missing" },
    { 3, "Wrong AlarmCRBlock count" },
    { 4, "Out of AR Resources" },
    { 5, "AR UUID unknown" },
    { 6, "State conflict" },
    { 7, "Out of Provider, Consumer or Alarm Resources" },
    { 8, "Out of Memory" },
    { 9, "Pdev already owned" },
    { 10, "ARset State conflict during connection establishment" },
    { 11, "ARset Parameter conflict during connection establishment" },
    { 12, "Pdev, port(s) without interface" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_65[] = {
    /* ALPMI */
    { 0, "Invalid State" },
    { 1, "Wrong ACK-PDU" },
    { 2, "Invalid" },
    { 3, "Wrong state" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_66[] = {
    /* ALPMR */
    { 0, "Invalid State" },
    { 1, "Wrong Notification PDU" },
    { 2, "Invalid" },
    { 3, "Wrong state" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_69[] = {
    /* RPC */
    { 1, "CLRPC_ERR_REJECTED" },
    { 2, "CLRPC_ERR_FAULTED" },
    { 3, "CLRPC_ERR_TIMEOUT" },
    { 4, "CLRPC_ERR_IN_ARGS" },
    { 5, "CLRPC_ERR_OUT_ARGS" },
    { 6, "CLRPC_ERR_DECODE" },
    { 7, "CLRPC_ERR_PNIO_OUT_ARGS" },
    { 8, "CLRPC_ERR_PNIO_APP_TIMEOUT" },
    { 0, NULL },
};

static const value_string pn_io_error_code2_pnio_70[] = {
    /* APMR */
    { 0, "Invalid State" },
    { 1, "LMPM signaled error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_71[] = {
    /* APMS */
    { 0, "Invalid State" },
    { 1, "LMPM signaled error" },
    { 2, "Timeout" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_72[] = {
    /* CPM */
    { 1, "Invalid State" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_73[] = {
    /* PPM */
    { 1, "Invalid State" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_74[] = {
    /* DCPUCS */
    { 0, "Invalid State" },
    { 1, "LMPM signaled an error" },
    { 2, "Timeout" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_75[] = {
    /* DCPUCR */
    { 0, "Invalid State" },
    { 1, "LMPM signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_76[] = {
    /* DCPMCS */
    { 0, "Invalid State" },
    { 1, "LMPM signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_77[] = {
    /* DCPMCR */
    { 0, "Invalid State" },
    { 1, "LMPM signaled an error" },
    { 0, NULL }
};


static const value_string pn_io_error_code2_pnio_79[] = {
    /* RSI */
    { 0, "State conflict" },
    { 1, "Abort" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_80[] = {
    /* RSIR */
    { 0, "State conflict" },
    { 1, "Abort" },
    { 2, "InterfaceNotFound "},
    { 3, "OutOfResources" },
    { 4, "Rerun connect" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_100[] = {
    /* CTLSM */
    { 0, "Invalid state" },
    { 1, "CTLSM signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_101[] = {
    /* CTLRDI */
    { 0, "Invalid state" },
    { 1, "CTLRDI signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_102[] = {
    /* CTLRDR */
    { 0, "Invalid state" },
    { 1, "CTLRDR signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_103[] = {
    /* CTLRWRI */
    { 0, "Invalid state" },
    { 1, "CTLWRI signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_104[] = {
    /* CTLRWRR */
    { 0, "Invalid state" },
    { 1, "CTLWRR signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_105[] = {
    /* CTLIO */
    { 0, "Invalid state" },
    { 1, "CTLIO signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_106[] = {
    /* CTLSU */
    { 0, "Invalid state" },
    { 1, "AR add provider or consumer failed" },
    { 2, "AR alarm-open failed" },
    { 3, "AR alarm-ack-send" },
    { 4, "AR alarm-ind" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_107[] = {
    /* CTLRPC */
    { 0, "Invalid state" },
    { 1, "CTLRPC signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_108[] = {
    /* CTLPBE */
    { 0, "Invalid state" },
    { 1, "CTLPBE signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_109[] = {
    /* CTLSRL */
    { 0, "Invalid state" },
    { 1, "CTLSRL signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_110[] = {
    /* NME */
    { 0, "Invalid state" },
    { 1, "Temporarily unknown" },
    { 2, "Not best NME" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_112[] = {
    /* PCE */
    { 0, "Invalid state" },
    { 1, "No path found" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_114[] = {
    /* NUE */
    { 0, "Invalid state" },
    { 1, "Remote problem" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_253[] = {
    { 0, "reserved" },
    { 1, "Error within the coordination of sequence numbers (RTA_ERR_CODE_SEQ) error" },
    { 2, "Instance closed (RTA_ERR_ABORT)" },
    { 3, "AR out of memory (RTA_ERR_ABORT)" },
    { 4, "AR add provider or consumer failed (RTA_ERR_ABORT)" },
    { 5, "AR consumer DHT/WDT expired (RTA_ERR_ABORT)" },
    { 6, "AR cmi timeout (RTA_ERR_ABORT)" },
    { 7, "AR alarm-open failed (RTA_ERR_ABORT)" },
    { 8, "AR alarm-send.cnf(-) (RTA_ERR_ABORT)" },
    { 9, "AR alarm-ack-send.cnf(-) (RTA_ERR_ABORT)" },
    { 10, "AR alarm data too long (RTA_ERR_ABORT)" },
    { 11, "AR alarm.ind(err) (RTA_ERR_ABORT)" },
    { 12, "AR rpc-client call.cnf(-) (RTA_ERR_ABORT)" },
    { 13, "AR abort.req (RTA_ERR_ABORT)" },
    { 14, "AR re-run aborts existing (RTA_ERR_ABORT)" },
    { 15, "AR release.ind received (RTA_ERR_ABORT)" },
    { 16, "AR device deactivated (RTA_ERR_ABORT)" },
    { 17, "AR removed (RTA_ERR_ABORT)" },
    { 18, "AR protocol violation (RTA_ERR_ABORT)" },
    { 19, "AR name resolution error (RTA_ERR_ABORT)" },
    { 20, "AR RPC-Bind error (RTA_ERR_ABORT)" },
    { 21, "AR RPC-Connect error (RTA_ERR_ABORT)" },
    { 22, "AR RPC-Read error (RTA_ERR_ABORT)" },
    { 23, "AR RPC-Write error (RTA_ERR_ABORT)" },
    { 24, "AR RPC-Control error (RTA_ERR_ABORT)" },
    { 25, "AR forbidden pull or plug after check.rsp and before in-data.ind (RTA_ERR_ABORT)" },
    { 26, "AR AP removed (RTA_ERR_ABORT)" },
    { 27, "AR link down (RTA_ERR_ABORT)" },
    { 28, "AR could not register multicast-mac address (RTA_ERR_ABORT)" },
    { 29, "not synchronized (cannot start companion-ar) (RTA_ERR_ABORT)" },
    { 30, "wrong topology (cannot start companion-ar) (RTA_ERR_ABORT)" },
    { 31, "dcp, station-name changed (RTA_ERR_ABORT)" },
    { 32, "dcp, reset to factory-settings (RTA_ERR_ABORT)" },
    { 33, "cannot start companion-AR because a 0x8ipp submodule in the first AR... (RTA_ERR_ABORT)" },
    { 34, "no irdata record yet (RTA_ERR_ABORT)" },
    { 35, "PDEV (RTA_ERROR_ABORT)" },
    { 36, "PDEV, no port offers required speed/duplexity (RTA_ERROR_ABORT)" },
    { 37, "IP-Suite [of the IOC] changed by means of DCP_Set(IPParameter) or local engineering (RTA_ERROR_ABORT)" },
    { 38, "IOCARSR, RDHT expired" },
    { 39, "IOCARSR, Pdev, parameterization impossible" },
    { 40, "Remote application ready timeout expired" },
    { 41, "IOCARSR, Redundant interface list or access to the peripherals impossible" },
    { 42, "IOCARSR, MTOT expired" },
    { 43, "IOCARSR, AR protocol violation" },
    { 44, "PDEV, plug port without CombinedObjectContainer" },
    { 45, "NME, no or wrong configuration" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_255[] = {
    /* User specific */
    { 255, "User abort" },
    { 0, NULL }
};


/* Initialize PNIO RTC1 stationInfo memory */
void
init_pnio_rtc1_station(stationInfo *station_info) {
    station_info->iocs_data_in = wmem_list_new(wmem_file_scope());
    station_info->iocs_data_out = wmem_list_new(wmem_file_scope());
    station_info->ioobject_data_in = wmem_list_new(wmem_file_scope());
    station_info->ioobject_data_out = wmem_list_new(wmem_file_scope());
    station_info->diff_module = wmem_list_new(wmem_file_scope());
}

/* dissect an 8 bit unsigned integer */
unsigned
dissect_pn_uint8(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                  proto_tree *tree, int hfindex, uint8_t *pdata)
{
    uint8_t data;

    data = tvb_get_uint8 (tvb, offset);
    proto_tree_add_uint(tree, hfindex, tvb, offset, 1, data);
    if (pdata)
        *pdata = data;
    return offset + 1;
}

/* dissect a 16 bit unsigned integer; return the item through a pointer as well */
unsigned
dissect_pn_uint16_ret_item(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                       proto_tree *tree, int hfindex, uint16_t *pdata, proto_item ** new_item)
{
    uint16_t    data;
    proto_item *item = NULL;

    data = tvb_get_ntohs (tvb, offset);

    item = proto_tree_add_uint(tree, hfindex, tvb, offset, 2, data);
    if (pdata)
        *pdata = data;
    if (new_item)
        *new_item = item;
    return offset + 2;
}

/* dissect a 16 bit unsigned integer */
unsigned
dissect_pn_uint16(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                       proto_tree *tree, int hfindex, uint16_t *pdata)
{
    uint16_t data;

    data = tvb_get_ntohs (tvb, offset);

    proto_tree_add_uint(tree, hfindex, tvb, offset, 2, data);
    if (pdata)
        *pdata = data;
    return offset + 2;
}

/* dissect a 16 bit signed integer */
unsigned
dissect_pn_int16(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                       proto_tree *tree, int hfindex, int16_t *pdata)
{
    int16_t data;

    data = tvb_get_ntohs (tvb, offset);

    proto_tree_add_int(tree, hfindex, tvb, offset, 2, data);
    if (pdata)
        *pdata = data;
    return offset + 2;
}

/* dissect a 24bit OUI (IEC organizational unique id) */
unsigned
dissect_pn_oid(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, uint32_t *pdata)
{
    uint32_t data;

    data = tvb_get_ntoh24(tvb, offset);

    proto_tree_add_uint(tree, hfindex, tvb, offset, 3, data);
    if (pdata)
        *pdata = data;
    return offset + 3;
}

/* dissect a 6 byte MAC address */
unsigned
dissect_pn_mac(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, uint8_t *pdata)
{
    uint8_t data[6];

    tvb_memcpy(tvb, data, offset, 6);
    proto_tree_add_ether(tree, hfindex, tvb, offset, 6, data);

    if (pdata)
        memcpy(pdata, data, 6);

    return offset + 6;
}

/* dissect an IPv4 address */
unsigned
dissect_pn_ipv4(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, uint32_t *pdata)
{
    uint32_t data;

    data = tvb_get_ipv4(tvb, offset);
    proto_tree_add_ipv4(tree, hfindex, tvb, offset, 4, data);

    if (pdata)
        *pdata = data;

    return offset + 4;
}

/* dissect a 16 byte UUID address */
unsigned
dissect_pn_uuid(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, e_guid_t *uuid)
{
    uint8_t drep[2] = { 0,0 };

    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                    hfindex, uuid);

    return offset;
}

/* "dissect" some bytes still undecoded (with Expert warning) */
unsigned
dissect_pn_undecoded(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                    proto_tree *tree, uint32_t length)
{
    proto_item *item;


    item = proto_tree_add_string_format(tree, hf_pn_undecoded_data, tvb, offset, length, "data",
        "Undecoded Data: %d bytes", length);

    expert_add_info_format(pinfo, item, &ei_pn_undecoded_data,
                           "Undecoded Data, %u bytes", length);

    return offset + length;
}

/* "dissect" some user bytes */
unsigned
dissect_pn_user_data_bytes(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                    proto_tree *tree, uint32_t length, int iSelect)
{
    if(iSelect == FRAG_DATA)
        proto_tree_add_item(tree, hf_pn_frag_bytes, tvb, offset, length, ENC_NA);
    else
        proto_tree_add_item(tree, hf_pn_user_bytes, tvb, offset, length, ENC_NA);

    return offset + length;
}

unsigned
dissect_pn_user_data(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                    proto_tree *tree, uint32_t length, const char *text)
{
    if (length != 0) {
        proto_tree_add_string_format(tree, hf_pn_user_data, tvb, offset, length, "data",
            "%s: %d byte", text, length);
    }
    return offset + length;
}

/* packet is malformed, mark it as such */
unsigned
dissect_pn_malformed(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                    proto_tree *tree, uint32_t length)
{
    proto_tree_add_item(tree, hf_pn_malformed, tvb, 0, 10000, ENC_NA);

    return offset + length;
}


/* dissect some padding data (with the given length) */
unsigned
dissect_pn_padding(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                    proto_tree *tree, unsigned length)
{
    proto_tree_add_string_format(tree, hf_pn_padding, tvb, offset, length, "data",
        "Padding: %u byte", length);

    return offset + length;
}

/* align offset to 4 */
unsigned
dissect_pn_align4(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_, proto_tree *tree)
{
    unsigned padding;

    padding = WS_PADDING_TO_4(offset);
    if (padding != 0) {
        proto_tree_add_string_format(tree, hf_pn_padding, tvb, offset, padding, "data",
            "Padding: %u byte", padding);
    }

    return offset + padding;
}

/* dissect the four status (error) fields */
unsigned
dissect_PNIO_status(tvbuff_t *tvb, unsigned offset,
    packet_info *pinfo, proto_tree *tree, uint8_t *drep)
{
    uint8_t u8ErrorCode;
    uint8_t u8ErrorDecode;
    uint8_t u8ErrorCode1;
    uint8_t u8ErrorCode2;

    proto_item *sub_item;
    proto_tree *sub_tree;
    uint32_t    u32SubStart;
    int         bytemask = (drep[0] & DREP_LITTLE_ENDIAN) ? 3 : 0;

    const value_string *error_code1_vals;
    const value_string *error_code2_vals = pn_io_error_code2;   /* defaults */



                                                                /* status */
    sub_item = proto_tree_add_item(tree, hf_pn_io_status, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_status);
    u32SubStart = offset;

    /* the PNIOStatus field is existing in both the RPC and the application data,
    * depending on the current PDU.
    * As the byte representation of these layers are different, this has to be handled
    * in a somewhat different way than elsewhere. */

    dissect_dcerpc_uint8(tvb, offset + (0 ^ bytemask), pinfo, sub_tree, drep,
        hf_pn_io_error_code, &u8ErrorCode);
    dissect_dcerpc_uint8(tvb, offset + (1 ^ bytemask), pinfo, sub_tree, drep,
        hf_pn_io_error_decode, &u8ErrorDecode);

    switch (u8ErrorDecode) {
    case(0x80): /* PNIORW */
        dissect_dcerpc_uint8(tvb, offset + (2 ^ bytemask), pinfo, sub_tree, drep,
            hf_pn_io_error_code1_pniorw, &u8ErrorCode1);
        error_code1_vals = pn_io_error_code1_pniorw;

        /* u8ErrorCode2 for PNIORW is always user specific */
        dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
            hf_pn_io_error_code2_pniorw, &u8ErrorCode2);

        error_code2_vals = pn_io_error_code2_pniorw;

        break;
    case(0x81): /* PNIO */
        dissect_dcerpc_uint8(tvb, offset + (2 ^ bytemask), pinfo, sub_tree, drep,
            hf_pn_io_error_code1_pnio, &u8ErrorCode1);
        error_code1_vals = pn_io_error_code1_pnio;

        switch (u8ErrorCode1) {
        case(1):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_1, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_1;
            break;
        case(2):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_2, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_2;
            break;
        case(3):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_3, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_3;
            break;
        case(4):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_4, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_4;
            break;
        case(5):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_5, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_5;
            break;
        case(6):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_6, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_6;
            break;
        case(7):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_7, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_7;
            break;
        case(8):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_8, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_8;
            break;
        case(9):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_9, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_9;
            break;
        case(10):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_10, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_10;
            break;
        case(11):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_11, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_11;
            break;
        case(12):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_12, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_12;
            break;
        case(13):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_13, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_13;
            break;
        case(14):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_14, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_14;
            break;
        case(20):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_20, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_20;
            break;
        case(21):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_21, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_21;
            break;
        case(22):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_22, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_22;
            break;
        case(23):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_23, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_23;
            break;
        case(24):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_24, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_24;
            break;
        case(25):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_25, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_25;
            break;
        case(26):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_26, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_26;
            break;
        case (27):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_27, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_27;
            break;
        case(40):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_40, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_40;
            break;
        case(60):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_60, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_60;
            break;
        case(61):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_61, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_61;
            break;
        case(62):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_62, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_62;
            break;
        case(63):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_63, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_63;
            break;
        case(64):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_64, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_64;
            break;
        case(65):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_65, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_65;
            break;
        case(66):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_66, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_66;
            break;
        case(69):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_69, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_69;
            break;
        case(70):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_70, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_70;
            break;
        case(71):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_71, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_71;
            break;
        case(72):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_72, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_72;
            break;
        case(73):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_73, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_73;
            break;
        case(74):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_74, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_74;
            break;
        case(75):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_75, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_75;
            break;
        case(76):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_76, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_76;
            break;
        case(77):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_77, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_77;
            break;
        case(79):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_79, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_79;
            break;
        case(80):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_80, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_80;
            break;
        case(100):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_100, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_100;
            break;
        case(101):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_101, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_101;
            break;
        case(102):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_102, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_102;
            break;
        case(103):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_103, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_103;
            break;
        case(104):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_104, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_104;
            break;
        case(105):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_105, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_105;
            break;
        case(106):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_106, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_106;
            break;
        case(107):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_107, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_107;
            break;
        case(108):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_108, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_108;
            break;
        case(109):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_109, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_109;
            break;
        case(110):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_110, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_110;
            break;
        case(112):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_112, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_112;
            break;
        case(114):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_114, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_114;
            break;
        case(253):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_253, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_253;
            break;
        case(255):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pnio_255, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_255;
            break;
        default:
            /* don't know this u8ErrorCode1 for PNIO, use defaults */
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2, &u8ErrorCode2);
            expert_add_info_format(pinfo, sub_item, &ei_pn_io_error_code1, "Unknown ErrorCode1 0x%x (for ErrorDecode==PNIO)", u8ErrorCode1);
            break;
        }
        break;
    default:
        dissect_dcerpc_uint8(tvb, offset + (2 ^ bytemask), pinfo, sub_tree, drep,
            hf_pn_io_error_code1, &u8ErrorCode1);
        if (u8ErrorDecode != 0) {
            expert_add_info_format(pinfo, sub_item, &ei_pn_io_error_code1, "Unknown ErrorDecode 0x%x", u8ErrorDecode);
        }
        error_code1_vals = pn_io_error_code1;

        /* don't know this u8ErrorDecode, use defaults */
        dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
            hf_pn_io_error_code2, &u8ErrorCode2);
        if (u8ErrorDecode != 0) {
            expert_add_info_format(pinfo, sub_item, &ei_pn_io_error_code2, "Unknown ErrorDecode 0x%x", u8ErrorDecode);
        }
    }

    offset += 4;

    if ((u8ErrorCode == 0) && (u8ErrorDecode == 0) && (u8ErrorCode1 == 0) && (u8ErrorCode2 == 0)) {
        proto_item_append_text(sub_item, ": OK");
        col_append_str(pinfo->cinfo, COL_INFO, ", OK");
    }
    else {
        proto_item_append_text(sub_item, ": Error: \"%s\", \"%s\", \"%s\", \"%s\"",
            val_to_str(pinfo->pool, u8ErrorCode, pn_io_error_code, "(0x%x)"),
            val_to_str(pinfo->pool, u8ErrorDecode, pn_io_error_decode, "(0x%x)"),
            val_to_str(pinfo->pool, u8ErrorCode1, error_code1_vals, "(0x%x)"),
            val_to_str(pinfo->pool, u8ErrorCode2, error_code2_vals, "(0x%x)"));
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: \"%s\", \"%s\", \"%s\", \"%s\"",
            val_to_str(pinfo->pool, u8ErrorCode, pn_io_error_code, "(0x%x)"),
            val_to_str(pinfo->pool, u8ErrorDecode, pn_io_error_decode, "(0x%x)"),
            val_to_str(pinfo->pool, u8ErrorCode1, error_code1_vals, "(0x%x)"),
            val_to_str(pinfo->pool, u8ErrorCode2, error_code2_vals, "(0x%x)"));
    }
    proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}



/* append the given info text to item and column */
void
pn_append_info(packet_info *pinfo, proto_item *dcp_item, const char *text)
{
    col_append_str(pinfo->cinfo, COL_INFO, text);

    proto_item_append_text(dcp_item, "%s", text);
}

void pn_init_append_aruuid_frame_setup_list(e_guid_t aruuid, uint32_t setup) {

    ARUUIDFrame* aruuid_frame;

    aruuid_frame = wmem_new0(wmem_file_scope(), ARUUIDFrame);
    aruuid_frame->aruuid = aruuid;
    aruuid_frame->setupframe = setup;
    aruuid_frame->releaseframe = 0;
    aruuid_frame->inputframe = 0;
    aruuid_frame->outputframe = 0;

    wmem_list_append(aruuid_frame_setup_list, aruuid_frame);
}

ARUUIDFrame* pn_find_aruuid_frame_setup(packet_info* pinfo) {

    wmem_list_frame_t* aruuid_frame;
    ARUUIDFrame* current_aruuid_frame = NULL;

    if (aruuid_frame_setup_list != NULL) {
        for (aruuid_frame = wmem_list_head(aruuid_frame_setup_list); aruuid_frame != NULL; aruuid_frame = wmem_list_frame_next(aruuid_frame)) {
            current_aruuid_frame = (ARUUIDFrame*)wmem_list_frame_data(aruuid_frame);
            if (current_aruuid_frame->setupframe == pinfo->num) {
                break;
            }
        }
    }

    return current_aruuid_frame;
}

void pn_find_dcp_station_info(stationInfo* station_info, conversation_t* conversation) {
    stationInfo* dcp_station_info = NULL;
    /* search for DCP Station Info */
    dcp_station_info = (stationInfo*)conversation_get_proto_data(conversation, proto_pn_dcp);
    if (dcp_station_info != NULL) {
        if (dcp_station_info->typeofstation != NULL) {
            if (station_info->typeofstation == NULL || strcmp(dcp_station_info->typeofstation, station_info->typeofstation) != 0) {
                station_info->typeofstation = wmem_strdup(wmem_file_scope(), dcp_station_info->typeofstation);
            }
        }
        if (dcp_station_info->nameofstation != NULL) {
            if (station_info->nameofstation == NULL || strcmp(dcp_station_info->nameofstation, station_info->nameofstation) != 0) {
                station_info->nameofstation = wmem_strdup(wmem_file_scope(), dcp_station_info->nameofstation);
            }
        }
        if (dcp_station_info->u16Vendor_id != station_info->u16Vendor_id || dcp_station_info->u16Device_id != station_info->u16Device_id) {
            station_info->u16Vendor_id = dcp_station_info->u16Vendor_id;
            station_info->u16Device_id = dcp_station_info->u16Device_id;
        }
    }
}


void
init_pn (int proto)
{
    static hf_register_info hf[] = {
    { &hf_pn_padding,
      { "Padding", "pn.padding",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_undecoded_data,
      { "Undecoded Data", "pn.undecoded",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_user_data,
      { "User Data", "pn.user_data",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_user_bytes,
      { "Substitute Data", "pn.user_bytes",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_frag_bytes,
      { "Fragment Data", "pn.frag_bytes",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_malformed,
      { "Malformed", "pn_rt.malformed",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_status,
      { "Status", "pn_io.status",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code,
      { "ErrorCode", "pn_io.error_code",
        FT_UINT8, BASE_HEX, VALS(pn_io_error_code), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_decode,
      { "ErrorDecode", "pn_io.error_decode",
        FT_UINT8, BASE_HEX, VALS(pn_io_error_decode), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code1,
      { "ErrorCode1", "pn_io.error_code1",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code1), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2,
      { "ErrorCode2", "pn_io.error_code2",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code1_pniorw,
      { "ErrorCode1", "pn_io.error_code1_pniorw",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code1_pniorw), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pniorw,
      { "ErrorCode2 for PNIORW is u 0x0!", "pnio.error_code2_pniorw",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code1_pnio,
      { "ErrorCode1", "pn_io.error_code1_pnio",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code1_pnio), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_1,
      { "ErrorCode2", "pn_io.error_code2_pnio_1",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_1), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_2,
      { "ErrorCode2", "pn_io.error_code2_pnio_2",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_2), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_3,
      { "ErrorCode2", "pn_io.error_code2_pnio_3",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_3), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_4,
      { "ErrorCode2", "pn_io.error_code2_pnio_4",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_4), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_5,
      { "ErrorCode2", "pn_io.error_code2_pnio_5",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_5), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_6,
      { "ErrorCode2", "pn_io.error_code2_pnio_6",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_6), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_7,
      { "ErrorCode2", "pn_io.error_code2_pnio_7",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_7), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_8,
      { "ErrorCode2", "pn_io.error_code2_pnio_8",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_8), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_9,
      { "ErrorCode2", "pn_io.error_code2_pnio_9",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_9), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_10,
      { "ErrorCode2", "pn_io.error_code2_pnio_10",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_10), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_11,
      { "ErrorCode2", "pn_io.error_code2_pnio_11",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_11), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_12,
      { "ErrorCode2", "pn_io.error_code2_pnio_12",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_12), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_13,
      { "ErrorCode2", "pn_io.error_code2_pnio_13",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_13), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_14,
      { "ErrorCode2", "pn_io.error_code2_pnio_14",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_14), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_20,
      { "ErrorCode2", "pn_io.error_code2_pnio_20",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_20), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_21,
      { "ErrorCode2", "pn_io.error_code2_pnio_21",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_21), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_22,
      { "ErrorCode2", "pn_io.error_code2_pnio_22",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_22), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_23,
      { "ErrorCode2", "pn_io.error_code2_pnio_23",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_23), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_24,
      { "ErrorCode2", "pn_io.error_code2_pnio_24",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_24), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_25,
      { "ErrorCode2", "pn_io.error_code2_pnio_25",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_25), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_26,
      { "ErrorCode2", "pn_io.error_code2_pnio_26",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_26), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_27,
      { "ErrorCode2", "pn_io.error_code2_pnio_27",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_27), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_40,
      { "ErrorCode2", "pn_io.error_code2_pnio_40",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_40), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_60,
      { "ErrorCode2", "pn_io.error_code2_pnio_60",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_60), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_61,
      { "ErrorCode2", "pn_io.error_code2_pnio_61",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_61), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_62,
      { "ErrorCode2", "pn_io.error_code2_pnio_62",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_62), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_63,
      { "ErrorCode2", "pn_io.error_code2_pnio_63",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_63), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_64,
      { "ErrorCode2", "pn_io.error_code2_pnio_64",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_64), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_65,
      { "ErrorCode2", "pn_io.error_code2_pnio_65",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_65), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_66,
      { "ErrorCode2", "pn_io.error_code2_pnio_66",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_66), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_69,
      { "ErrorCode2", "pn_io.error_code2_pnio_69",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_69), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_70,
      { "ErrorCode2", "pn_io.error_code2_pnio_70",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_70), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_71,
      { "ErrorCode2", "pn_io.error_code2_pnio_71",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_71), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_72,
      { "ErrorCode2", "pn_io.error_code2_pnio_72",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_72), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_73,
      { "ErrorCode2", "pn_io.error_code2_pnio_73",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_73), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_74,
      { "ErrorCode2", "pn_io.error_code2_pnio_74",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_74), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_75,
      { "ErrorCode2", "pn_io.error_code2_pnio_75",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_75), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_76,
      { "ErrorCode2", "pn_io.error_code2_pnio_76",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_76), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_77,
      { "ErrorCode2", "pn_io.error_code2_pnio_77",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_77), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_79,
      { "ErrorCode2", "pn_io.error_code2_pnio_79",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_79), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_80,
      { "ErrorCode2", "pn_io.error_code2_pnio_80",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_80), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_100,
      { "ErrorCode2", "pn_io.error_code2_pnio_100",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_100), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_101,
      { "ErrorCode2", "pn_io.error_code2_pnio_101",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_101), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_102,
      { "ErrorCode2", "pn_io.error_code2_pnio_102",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_102), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_103,
      { "ErrorCode2", "pn_io.error_code2_pnio_103",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_103), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_104,
      { "ErrorCode2", "pn_io.error_code2_pnio_104",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_104), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_105,
      { "ErrorCode2", "pn_io.error_code2_pnio_105",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_105), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_106,
      { "ErrorCode2", "pn_io.error_code2_pnio_106",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_106), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_107,
      { "ErrorCode2", "pn_io.error_code2_pnio_107",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_107), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_108,
      { "ErrorCode2", "pn_io.error_code2_pnio_108",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_108), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_109,
      { "ErrorCode2", "pn_io.error_code2_pnio_109",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_109), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_110,
      { "ErrorCode2", "pn_io.error_code2_pnio_110",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_110), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_112,
      { "ErrorCode2", "pn_io.error_code2_pnio_112",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_112), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_114,
      { "ErrorCode2", "pn_io.error_code2_pnio_114",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_114), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_253,
      { "ErrorCode2", "pn_io.error_code2_pnio_253",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_253), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pnio_255,
      { "ErrorCode2", "pn_io.error_code2_pnio_255",
        FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_255), 0x0,
        NULL, HFILL }
    },

    };

    static int *ett[] = {
        &ett_pn_io_status
      };

    static ei_register_info ei[] = {
        { &ei_pn_undecoded_data, { "pn.undecoded_data", PI_UNDECODED, PI_WARN, "Undecoded Data", EXPFILL }},
        { &ei_pn_io_error_code1, { "pn_io.error_code1.expert", PI_UNDECODED, PI_WARN, "Unknown ErrorCode1", EXPFILL }},
        { &ei_pn_io_error_code2, { "pn_io.error_code2.expert", PI_UNDECODED, PI_WARN, "Unknown ErrorDecode", EXPFILL } },

    };

    expert_module_t* expert_pn;


    proto_register_field_array (proto, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    expert_pn = expert_register_protocol(proto);
    expert_register_field_array(expert_pn, ei, array_length(ei));
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
