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
static int hf_pn_io_error_code1_pniosec;
static int hf_pn_io_error_code2_pniosec_01;
static int hf_pn_io_error_code2_pniosec_02;
static int hf_pn_io_error_code2_pniosec_04;
static int hf_pn_io_error_code2_pniosec_10;
static int hf_pn_io_error_code2_pniosec_80;
static int hf_pn_io_error_code2_pniosec_f0;
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
    { 0xDB, "IODConnectRsp" },
    { 0xDC, "Obsoleted" },
    { 0xDD, "IODControlRsp, IOXControlRsp" },
    { 0xDE, "IODReadRsp" },
    { 0xDF, "IODWriteRsp" },
    { 0xE0, "SXP-SAMConnect-RSP, SXP-SAMService-RSP" },
    { 0xE1, "SCMServiceReq response" },
    { 0, NULL }
};

static const value_string pn_io_error_decode[] = {
    { 0x00, "OK" },
    { 0x80, "PNIORW" },
    { 0x81, "PNIO" },
    { 0x82, "Manufacturer specific" },
    { 0x83, "PNIOSEC" },
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

/* Table 690 – Coding of ErrorCode1 with ErrorDecode := PNIOSEC */
static const value_string pn_io_error_code1_pniosec[] = {
    { 0x00, "Reserved" },
    { 0x01, "Parameter Error Faulty SAMRequestBlock" },
    { 0x02, "Parameter Error Faulty ARAlgorithmInfoBlock" },
    { 0x04, "Parameter Error Faulty ExpectedCredentialTypeBlock" },
    { 0x10, "Parameter Error Faulty SCMRequestBlock" },
    { 0x80, "State machine CMSAM Error" },
    { 0xF0, "Security errors" },
    { 0, NULL }
};

/* Table 691 – ErrorCode2 for PNIOSEC, ErrorCode1 = 0x01 (SAMRequestBlock) */
static const value_string pn_io_error_code2_pniosec_01[] = {
    { 0x00, "Error in Parameter BlockType" },
    { 0x01, "Error in Parameter BlockLength" },
    { 0x02, "Error in Parameter BlockVersionHigh" },
    { 0x03, "Error in Parameter BlockVersionLow" },
    { 0x04, "Error in Parameter SAMOperation" },
    { 0x05, "Error in Parameter SAMRequestData" },
    { 0x10, "Error in Parameter EAPRequest_Identity" },
    { 0x11, "Error in Parameter EAPRequest_TLS" },
    { 0, NULL }
};

/* Table 691 – ErrorCode2 for PNIOSEC, ErrorCode1 = 0x02 (ARAlgorithmInfoBlock) */
static const value_string pn_io_error_code2_pniosec_02[] = {
    { 0x00, "Error in Parameter BlockType" },
    { 0x09, "Error in Parameter KeyAgreementAlgorithm" },
    { 0, NULL }
};

/* Table 691 – ErrorCode2 for PNIOSEC, ErrorCode1 = 0x04 (ExpectedCredentialTypeBlock) */
static const value_string pn_io_error_code2_pniosec_04[] = {
    { 0x00, "Error in Parameter BlockType" },
    { 0x04, "Reserved" },
    { 0x05, "ExpectedCredentialType" },
    { 0, NULL }
};

/* Table 691 – ErrorCode2 for PNIOSEC, ErrorCode1 = 0x10 (SCMRequestBlock) */
static const value_string pn_io_error_code2_pniosec_10[] = {
    { 0x00, "Error in Parameter BlockType" },
    { 0x01, "Error in Parameter BlockLength" },
    { 0x02, "Error in Parameter BlockVersionHigh" },
    { 0x03, "Error in Parameter BlockVersionLow" },
    { 0x04, "Error in Parameter SCMOperation" },
    { 0x05, "Error in Parameter SCMRequestData" },
    { 0x10, "Error in Parameter DevIDDomain" },
    { 0x11, "Error in Parameter CertificationRequestInfo" },
    { 0x12, "Error in Parameter NumberOfEntries" },
    { 0x13, "Error in Parameter CertificateLength" },
    { 0x14, "Error in Parameter Certificate" },
    { 0x15, "Error in Parameter Padding" },
    { 0x16, "Error in Parameter SecurityConfigurationParameters" },
    { 0, NULL }
};

/* Table 691 – ErrorCode2 for PNIOSEC, ErrorCode1 = 0x80 (CMSAM Error) */
static const value_string pn_io_error_code2_pniosec_80[] = {
    { 0x00, "Invalid protocol state / internal error" },
    { 0x01, "Service not allowed in this state" },
    { 0x02, "ARAlgorithmInfoBlock not allowed in this state" },
    { 0x03, "ARAlgorithmInfoBlock required in this state" },
    { 0x80, "EAP/TLS protocol failure (with AR abort)" },
    { 0x81, "EAP/TLS protocol failure (during secure AR update, without AR abort)" },
    { 0, NULL }
};

/* Table 691 – ErrorCode2 for PNIOSEC, ErrorCode1 = 0xF0 (Security errors) */
static const value_string pn_io_error_code2_pniosec_f0[] = {
    { 0x00, "Access denied / insufficient roles (ACD)" },
    { 0x10, "Expected credential not available" },
    { 0x20, "Mismatching keys" },
    { 0, NULL }
};

static const value_string pn_io_error_code1_pnio[] = {
    { 0x00 /*  0*/, "Reserved" },
    { 0x01 /*  1*/, "Obsoleted" },
    { 0x02 /*  2*/, "Connect: Faulty IOCRBlockReq" },
    { 0x03 /*  3*/, "Connect: Faulty ExpectedSubmoduleBlockReq" },
    { 0x04 /*  4*/, "Connect: Faulty AlarmCRBlockReq" },
    { 0x05 /*  5*/, "Connect: Faulty PrmServerBlockReq" },
    { 0x06 /*  6*/, "Connect: Faulty MCRBlockReq" },
    { 0x07 /*  7*/, "Obsoleted" },
    { 0x08 /*  8*/, "Read/Write Record: Faulty Record" },
    { 0x09 /*  9*/, "Connect: Faulty IRInfoBlock" },
    { 0x0A /* 10*/, "Connect: Faulty SRInfoBlock" },
    { 0x0B /* 11*/, "Connect: Faulty ARFSUBlock" },
    { 0x0C /* 12*/, "Obsoleted" },
    { 0x0D /* 13*/, "Connect: Faulty RSInfoBlock" },
    { 0x0E /* 14*/, "Connect: Faulty ARSXPBlockReq"},
    { 0x0F /* 15*/, "Reserved" },
    { 0x10 /* 16*/, "Reserved" },
    { 0x11 /* 17*/, "Reserved" },
    { 0x12 /* 18*/, "Reserved" },
    { 0x13 /* 19*/, "Reserved" },
    { 0x14 /* 20*/, "IODControl: Faulty ControlBlockConnect" },
    { 0x15 /* 21*/, "IODControl: Faulty ControlBlockPlug" },
    { 0x16 /* 22*/, "IOXControl: Faulty ControlBlock after a connect est." },
    { 0x17 /* 23*/, "IOXControl: Faulty ControlBlock a plug alarm" },
    { 0x18 /* 24*/, "IODControl: Faulty ControlBlockPrmBegin" },
    { 0x19 /* 25*/, "IODControl: Faulty SubmoduleListBlock" },
    { 0x1A /* 26*/, "Reserved" },
    { 0x1B /* 27*/, "Reserved"},
    { 0x1C /* 28*/, "Reserved"},
    { 0x1D /* 29*/, "Reserved"},
    { 0x1E /* 30*/, "Reserved"},
    { 0x1F /* 31*/, "Reserved"},
    { 0x20 /* 32*/, "Reserved" },
    { 0x21 /* 33*/, "Reserved" },
    { 0x22 /* 34*/, "Reserved" },
    { 0x23 /* 35*/, "Reserved" },
    { 0x24 /* 36*/, "Reserved" },
    { 0x25 /* 37*/, "Reserved" },
    { 0x26 /* 38*/, "Reserved" },
    { 0x27 /* 39*/, "Reserved" },
    { 0x28 /* 40*/, "Obsoleted" },
    { 0x29 /* 41*/, "Reserved" },
    { 0x2A /* 42*/, "Reserved" },
    { 0x2B /* 43*/, "Reserved" },
    { 0x2C /* 44*/, "Reserved" },
    { 0x2D /* 45*/, "Reserved" },
    { 0x2E /* 46*/, "Reserved" },
    { 0x2F /* 47*/, "Reserved" },
    { 0x30 /* 48*/, "Reserved" },
    { 0x31 /* 49*/, "Reserved" },
    { 0x32 /* 50*/, "Obsoleted" },
    { 0x33 /* 51*/, "Response: Faulty IOCRBlockRes" },
    { 0x34 /* 52*/, "Response: Faulty AlarmCRBlockRes" },
    { 0x35 /* 53*/, "Response: Faulty ModuleDifflock" },
    { 0x36 /* 54*/, "Obsoleted" },
    { 0x37 /* 55*/, "Obsoleted" },
    { 0x38 /* 56*/, "Obsoleted" },
    { 0x39 /* 57*/, "Response: Faulty ARSXPBlockRes" },
    { 0x3B /* 59*/, "Reserved" },
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
    { 0x4f /* 79*/, "Obsoleted" },
    { 0x50 /* 80*/, "Obsoleted" },
    { 0x51 /* 81*/, "Reserved" },
    { 0x52 /* 82*/, "Reserved" },
    { 0x53 /* 83*/, "Reserved" },
    { 0x54 /* 84*/, "Reserved" },
    { 0x55 /* 85*/, "Reserved" },
    { 0x56 /* 86*/, "Reserved" },
    { 0x57 /* 87*/, "Reserved" },
    { 0x58 /* 88*/, "Reserved" },
    { 0x59 /* 89*/, "Reserved" },
    { 0x5a /* 90*/, "Reserved" },
    { 0x5b /* 91*/, "Reserved" },
    { 0x5c /* 92*/, "Reserved" },
    { 0x5d /* 93*/, "Reserved" },
    { 0x5e /* 94*/, "Reserved" },
    { 0x5f /* 95*/, "Reserved" },
    { 0x60 /* 96*/, "Reserved" },
    { 0x61 /* 97*/, "Reserved" },
    { 0x62 /* 98*/, "Reserved" },
    { 0x63 /* 99*/, "Reserved" },
    { 0x64 /*100*/, "CTLSM" },
    { 0x65 /*101*/, "CTLRDI" },
    { 0x66 /*102*/, "CTLRDR" },
    { 0x67 /*103*/, "CTLWRI" },
    { 0x68 /*104*/, "CTLWRR" },
    { 0x69 /*105*/, "CTLIO" },
    { 0x6a /*106*/, "CTLSU" },
    { 0x6b /*107*/, "CTLRPC" },
    { 0x6c /*108*/, "CTLPBE" },
    { 0x6d /*109*/, "CTLSRL" },
    { 0x6e /*110*/, "Obsoleted" },
    { 0x6f /*111*/, "Obsoleted" },
    { 0x70 /*112*/, "Obsoleted" },
    { 0x71 /*113*/, "Obsoleted" },
    { 0x72 /*114*/, "Obsoleted" },
    { 0x73 /*115*/, "Obsoleted" },
    { 0x74 /*116*/, "Reserved" },
    { 0x75 /*117*/, "Reserved" },
    { 0x76 /*118*/, "Reserved" },
    { 0x77 /*119*/, "Reserved" },
    { 0x78 /*120*/, "Reserved" },
    { 0x79 /*121*/, "Reserved" },
    { 0x7a /*122*/, "Reserved" },
    { 0x7b /*123*/, "Reserved" },
    { 0x7c /*124*/, "Reserved" },
    { 0x7d /*125*/, "Reserved" },
    { 0x7e /*126*/, "Reserved" },
    { 0x7f /*127*/, "Reserved" },
    { 0x80 /*128*/, "Reserved" },
    { 0x81 /*129*/, "Reserved" },
    { 0x82 /*130*/, "Reserved" },
    { 0x83 /*131*/, "Reserved" },
    { 0x84 /*132*/, "Reserved" },
    { 0x85 /*133*/, "Reserved" },
    { 0x86 /*134*/, "Reserved" },
    { 0x87 /*135*/, "Reserved" },
    { 0x88 /*136*/, "Reserved" },
    { 0x89 /*137*/, "Reserved" },
    { 0x8a /*138*/, "Reserved" },
    { 0x8b /*139*/, "Reserved" },
    { 0x8c /*140*/, "Reserved" },
    { 0x8d /*141*/, "Reserved" },
    { 0x8e /*142*/, "Reserved" },
    { 0x8f /*143*/, "Reserved" },
    { 0x90 /*144*/, "Reserved" },
    { 0x91 /*145*/, "Reserved" },
    { 0x92 /*146*/, "Reserved" },
    { 0x93 /*147*/, "Reserved" },
    { 0x94 /*148*/, "Reserved" },
    { 0x95 /*149*/, "Reserved" },
    { 0x96 /*150*/, "Reserved" },
    { 0x97 /*151*/, "Reserved" },
    { 0x98 /*152*/, "Reserved" },
    { 0x99 /*153*/, "Reserved" },
    { 0x9a /*154*/, "Reserved" },
    { 0x9b /*155*/, "Reserved" },
    { 0x9c /*156*/, "Reserved" },
    { 0x9d /*157*/, "Reserved" },
    { 0x9e /*158*/, "Reserved" },
    { 0xa1 /*161*/, "Reserved" },
    { 0xa2 /*162*/, "Reserved" },
    { 0xa3 /*163*/, "Reserved" },
    { 0xa4 /*164*/, "Reserved" },
    { 0xa5 /*165*/, "Reserved" },
    { 0xa6 /*166*/, "Reserved" },
    { 0xa7 /*167*/, "Reserved" },
    { 0xa8 /*168*/, "Reserved" },
    { 0xa9 /*169*/, "Reserved" },
    { 0xaa /*170*/, "Reserved" },
    { 0xab /*171*/, "Reserved" },
    { 0xac /*172*/, "Reserved" },
    { 0xad /*173*/, "Reserved" },
    { 0xae /*174*/, "Reserved" },
    { 0xaf /*175*/, "Reserved" },
    { 0xb0 /*176*/, "Reserved" },
    { 0xb1 /*177*/, "Reserved" },
    { 0xb2 /*178*/, "Reserved" },
    { 0xb3 /*179*/, "Reserved" },
    { 0xb4 /*180*/, "Reserved" },
    { 0xb5 /*181*/, "Reserved" },
    { 0xb6 /*182*/, "Reserved" },
    { 0xb7 /*183*/, "Reserved" },
    { 0xb8 /*184*/, "Reserved" },
    { 0xb9 /*185*/, "Reserved" },
    { 0xba /*186*/, "Reserved" },
    { 0xbb /*187*/, "Reserved" },
    { 0xbc /*188*/, "Reserved" },
    { 0xbd /*189*/, "Reserved" },
    { 0xbe /*190*/, "Reserved" },
    { 0xbf /*191*/, "Reserved" },
    { 0xc0 /*192*/, "Reserved" },
    { 0xc1 /*193*/, "Reserved" },
    { 0xc2 /*194*/, "Reserved" },
    { 0xc3 /*195*/, "Reserved" },
    { 0xc4 /*196*/, "Reserved" },
    { 0xc5 /*197*/, "Reserved" },
    { 0xc6 /*198*/, "Reserved" },
    { 0xc7 /*199*/, "Reserved" },
    { 0xc8 /*200*/, "CMSM" },
    { 0xc9 /*201*/, "Reserved" },
    { 0xca /*202*/, "CMRDR" },
    { 0xcb /*203*/, "Reserved" },
    { 0xcc /*204*/, "CMWRR" },
    { 0xcd /*205*/, "CMIO" },
    { 0xce /*206*/, "CMSU" },
    { 0xcf /*207*/, "Reserved" },
    { 0xd0 /*208*/, "CMINA" },
    { 0xd1 /*209*/, "CMPBE" },
    { 0xd2 /*210*/, "CMSRL" },
    { 0xd3 /*211*/, "CMDMC" },
    { 0xd4 /*212*/, "Reserved" },
    { 0xd5 /*213*/, "Reserved" },
    { 0xd6 /*214*/, "Reserved" },
    { 0xd7 /*215*/, "Reserved" },
    { 0xd8 /*216*/, "Reserved" },
    { 0xd9 /*217*/, "Reserved" },
    { 0xda /*218*/, "Reserved" },
    { 0xdb /*219*/, "Reserved" },
    { 0xdc /*220*/, "Reserved" },
    { 0xdd /*221*/, "Reserved" },
    { 0xde /*222*/, "Reserved" },
    { 0xdf /*223*/, "Reserved" },
    { 0xe0 /*224*/, "SXP Protocol Error" },
    { 0xe1 /*225*/, "RTAv3 Protocol Error" },
    { 0xe2 /*226*/, "Reserved" },
    { 0xe3 /*227*/, "Reserved" },
    { 0xe4 /*228*/, "Reserved" },
    { 0xe5 /*229*/, "Reserved" },
    { 0xe6 /*230*/, "Reserved" },
    { 0xe7 /*231*/, "Reserved" },
    { 0xe8 /*232*/, "Reserved" },
    { 0xe9 /*233*/, "Reserved" },
    { 0xea /*234*/, "Reserved" },
    { 0xeb /*235*/, "Reserved" },
    { 0xec /*236*/, "Reserved" },
    { 0xed /*237*/, "Reserved" },
    { 0xee /*238*/, "Reserved" },
    { 0xef /*239*/, "Reserved" },
    { 0xf0 /*240*/, "Reserved" },
    { 0xf1 /*241*/, "Reserved" },
    { 0xf2 /*242*/, "Reserved" },
    { 0xf3 /*243*/, "Reserved" },
    { 0xf4 /*244*/, "Reserved" },
    { 0xf5 /*245*/, "Reserved" },
    { 0xf6 /*246*/, "Reserved" },
    { 0xf7 /*247*/, "Reserved" },
    { 0xf8 /*248*/, "Reserved" },
    { 0xf9 /*249*/, "Reserved" },
    { 0xfa /*250*/, "Reserved" },
    { 0xfb /*251*/, "Reserved" },
    { 0xfc /*252*/, "Reserved" },
    { 0xfd /*253*/, "RTA Protocol Error" },
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
    /* Checking Rules for ARSXPBlockReq (Table 1238) */
    {  0, "Error in Parameter BlockType" },
    {  1, "Error in Parameter BlockLength" },
    {  2, "Error in Parameter BlockVersionHigh" },
    {  3, "Error in Parameter BlockVersionLow" },
    {  4, "Error in Parameter ARType" },
    {  5, "Error in Parameter ARUUID" },
    {  7, "Error in Parameter CMInitiatorActivityTimeoutFactor" },
    {  8, "Error in Parameter ARProperties" },
    { 10, "Error in Parameter Reserved" },
    { 11, "Error in Parameter Reserved" },
    { 14, "Error in Parameter StationNameLength" },
    { 15, "Error in Parameter CMInitiatorStationName" },
    {  0, NULL }
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


    item = proto_tree_add_string_format_value(tree, hf_pn_undecoded_data, tvb, offset, length, "data",
        "%d bytes", length);

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
    proto_tree_add_string_format_value(tree, hf_pn_padding, tvb, offset, length, "data",
        "%u byte", length);

    return offset + length;
}

/* align offset to 4 */
unsigned
dissect_pn_align4(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_, proto_tree *tree)
{
    unsigned padding;

    padding = WS_PADDING_TO_4(offset);
    if (padding != 0) {
        proto_tree_add_string_format_value(tree, hf_pn_padding, tvb, offset, padding, "data",
            "%u byte", padding);
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
    case(0x83): /* PNIOSEC */
        dissect_dcerpc_uint8(tvb, offset + (2 ^ bytemask), pinfo, sub_tree, drep,
            hf_pn_io_error_code1_pniosec, &u8ErrorCode1);
        error_code1_vals = pn_io_error_code1_pniosec;

        switch (u8ErrorCode1) {
        case(0x01):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pniosec_01, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pniosec_01;
            break;
        case(0x02):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pniosec_02, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pniosec_02;
            break;
        case(0x04):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pniosec_04, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pniosec_04;
            break;
        case(0x10):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pniosec_10, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pniosec_10;
            break;
        case(0x80):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pniosec_80, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pniosec_80;
            break;
        case(0xF0):
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2_pniosec_f0, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pniosec_f0;
            break;
        default:
            dissect_dcerpc_uint8(tvb, offset + (3 ^ bytemask), pinfo, sub_tree, drep,
                hf_pn_io_error_code2, &u8ErrorCode2);
            expert_add_info_format(pinfo, sub_item, &ei_pn_io_error_code1, "Unknown ErrorCode1 0x%x (for ErrorDecode==PNIOSEC)", u8ErrorCode1);
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
    { &hf_pn_io_error_code1_pniosec,
      { "ErrorCode1", "pn_io.error_code1_pniosec",
        FT_UINT8, BASE_HEX, VALS(pn_io_error_code1_pniosec), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pniosec_01,
      { "ErrorCode2", "pn_io.error_code2_pniosec_01",
        FT_UINT8, BASE_HEX, VALS(pn_io_error_code2_pniosec_01), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pniosec_02,
      { "ErrorCode2", "pn_io.error_code2_pniosec_02",
        FT_UINT8, BASE_HEX, VALS(pn_io_error_code2_pniosec_02), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pniosec_04,
      { "ErrorCode2", "pn_io.error_code2_pniosec_04",
        FT_UINT8, BASE_HEX, VALS(pn_io_error_code2_pniosec_04), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pniosec_10,
      { "ErrorCode2", "pn_io.error_code2_pniosec_10",
        FT_UINT8, BASE_HEX, VALS(pn_io_error_code2_pniosec_10), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pniosec_80,
      { "ErrorCode2", "pn_io.error_code2_pniosec_80",
        FT_UINT8, BASE_HEX, VALS(pn_io_error_code2_pniosec_80), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_code2_pniosec_f0,
      { "ErrorCode2", "pn_io.error_code2_pniosec_f0",
        FT_UINT8, BASE_HEX, VALS(pn_io_error_code2_pniosec_f0), 0x0,
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

bool
pn_is_valid_security_metadata(tvbuff_t *tvb, unsigned security_meta_data_offset, int expected_security_data_length)
{
    uint8_t  u8SecurityInformation;
    uint8_t  u8SecurityControl;
    uint32_t u32SecurityCounter;
    uint16_t u16SecurityLengthRaw;
    uint16_t u16SecurityLength;

    /* Need at least 8 bytes for SecurityMetaData */
    if (tvb_captured_length(tvb) < security_meta_data_offset + 8)
        return false;

    /* Byte 0: SecurityInformation - bits 1-7 must be reserved (0) */
    u8SecurityInformation = tvb_get_uint8(tvb, security_meta_data_offset);
    if ((u8SecurityInformation & 0xFE) != 0)
        return false;

    /* Byte 1: SecurityControl - bits 4-7 must be reserved (0) */
    u8SecurityControl = tvb_get_uint8(tvb, security_meta_data_offset + 1);
    if ((u8SecurityControl & 0xF0) != 0)
        return false;

    /* Bytes 2-5: SecurityCounter - value 0 is reserved per spec */
    u32SecurityCounter = tvb_get_uint32(tvb, security_meta_data_offset + 2, ENC_BIG_ENDIAN);
    if (u32SecurityCounter == 0)
        return false;

    /* Bytes 6-7: SecurityLength - bits 11-15 must be reserved (0) */
    u16SecurityLengthRaw = tvb_get_uint16(tvb, security_meta_data_offset + 6, ENC_BIG_ENDIAN);
    if ((u16SecurityLengthRaw & 0xF800) != 0)
        return false;

    /* SecurityLength value 0 is reserved per spec */
    u16SecurityLength = u16SecurityLengthRaw & 0x07FF;
    if (u16SecurityLength == 0)
        return false;

    /* Validate that SecurityLength matches expected data length */
    if (u16SecurityLength != (uint16_t)expected_security_data_length)
        return false;

    /* Cross-validate: AE mode (ProtectionMode=1) requires SecurityChecksum (16 bytes) */
    if ((u8SecurityInformation & 0x01) == 0x01) {
        if (tvb_captured_length(tvb) < security_meta_data_offset + 8 + u16SecurityLength + 16)
            return false;
    }

    return true;
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
