/*
 *  packet-h248_annex_c.c
 *  H.248 annex C
 *
 *  (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-isup.h"
#include "packet-q931.h"
#include "packet-h248.h"

void proto_register_h248_annex_c(void);
void proto_reg_handoff_h248_annex_c(void);


#define PNAME  "H.248 Annex C"
#define PSNAME "H248C"
#define PFNAME "h248.annexc"

/* H.248 Annex C */
static int proto_h248_pkg_annexc = -1;

static int hf_h248_sdp_connection_info = -1;
static int hf_h248_sdp_media_port = -1;

static int hf_h248_pkg_annexc_media = -1;
static int hf_h248_pkg_annexc_ACodec = -1;
static int hf_h248_pkg_annexc_Mediatx = -1;
static int hf_h248_pkg_annexc_NSAP = -1;
static int hf_h248_pkg_annexc_BIR = -1;
static int hf_h248_pkg_annexc_transmission_mode = -1;
static int hf_h248_pkg_annexc_num_of_channels = -1;
static int hf_h248_pkg_annexc_sampling_rate = -1;
static int hf_h248_pkg_annexc_bit_rate = -1;
static int hf_h248_pkg_annexc_samplepp = -1;
static int hf_h248_pkg_annexc_silence_supp = -1;
static int hf_h248_pkg_annexc_encrypt_type = -1;
static int hf_h248_pkg_annexc_encrypt_key = -1;
static int hf_h248_pkg_annexc_gain = -1;
static int hf_h248_pkg_annexc_jitterbuf = -1;
static int hf_h248_pkg_annexc_propdelay = -1;
static int hf_h248_pkg_annexc_rtp_payload = -1;

static int hf_h248_pkg_annexc_h222 = -1;
static int hf_h248_pkg_annexc_h223 = -1;
static int hf_h248_pkg_annexc_v76 = -1;
static int hf_h248_pkg_annexc_h2250 = -1;

static int hf_h248_pkg_annexc_aesa = -1;
static int hf_h248_pkg_annexc_vp = -1;
static int hf_h248_pkg_annexc_vc = -1;
static int hf_h248_pkg_annexc_sc = -1;
static int hf_h248_pkg_annexc_bcob = -1;
static int hf_h248_pkg_annexc_bbtc = -1;
static int hf_h248_pkg_annexc_atc = -1;
static int hf_h248_pkg_annexc_stc = -1;
static int hf_h248_pkg_annexc_uppc = -1;
static int hf_h248_pkg_annexc_pcr0 = -1;
static int hf_h248_pkg_annexc_scr0 = -1;
static int hf_h248_pkg_annexc_mbs0 = -1;
static int hf_h248_pkg_annexc_pcr1 = -1;
static int hf_h248_pkg_annexc_scr1 = -1;
static int hf_h248_pkg_annexc_mbs1 = -1;
static int hf_h248_pkg_annexc_bei = -1;
static int hf_h248_pkg_annexc_ti = -1;
static int hf_h248_pkg_annexc_fd = -1;
static int hf_h248_pkg_annexc_a2pcdv = -1;
static int hf_h248_pkg_annexc_c2pcdv = -1;
static int hf_h248_pkg_annexc_appcdv = -1;
static int hf_h248_pkg_annexc_cppcdv = -1;
static int hf_h248_pkg_annexc_aclr = -1;
static int hf_h248_pkg_annexc_meetd = -1;
static int hf_h248_pkg_annexc_ceetd = -1;
static int hf_h248_pkg_annexc_QosClass = -1;
static int hf_h248_pkg_annexc_AALtype = -1;

static int hf_h248_pkg_annexc_dlci = -1;
static int hf_h248_pkg_annexc_cid = -1;
static int hf_h248_pkg_annexc_sid = -1;
static int hf_h248_pkg_annexc_ppt = -1;

static int hf_h248_pkg_annexc_ipv4 = -1;
static int hf_h248_pkg_annexc_ipv6 = -1;
static int hf_h248_pkg_annexc_port = -1;
static int hf_h248_pkg_annexc_porttype = -1;

static int hf_h248_pkg_annexc_alc = -1;
static int hf_h248_pkg_annexc_sut = -1;
static int hf_h248_pkg_annexc_tci = -1;
static int hf_h248_pkg_annexc_timer_cu = -1;
static int hf_h248_pkg_annexc_maxcpssdu = -1;

static int hf_h248_pkg_annexc_aal1st = -1;
static int hf_h248_pkg_annexc_cbrr = -1;
static int hf_h248_pkg_annexc_scri = -1;
static int hf_h248_pkg_annexc_ecm = -1;
static int hf_h248_pkg_annexc_sdbt = -1;
static int hf_h248_pkg_annexc_pfci = -1;

static int hf_h248_pkg_annexc_tmr = -1;
static int hf_h248_pkg_annexc_tmrsr = -1;
static int hf_h248_pkg_annexc_contcheck = -1;
static int hf_h248_pkg_annexc_itc = -1;
static int hf_h248_pkg_annexc_transmode = -1;
static int hf_h248_pkg_annexc_transrate = -1;
static int hf_h248_pkg_annexc_mult = -1;
static int hf_h248_pkg_annexc_syncasync = -1;
static int hf_h248_pkg_annexc_negotiation = -1;
static int hf_h248_pkg_annexc_userrate = -1;
static int hf_h248_pkg_annexc_intrate = -1;
static int hf_h248_pkg_annexc_nictx = -1;
static int hf_h248_pkg_annexc_nicrx = -1;
static int hf_h248_pkg_annexc_flowconttx = -1;
static int hf_h248_pkg_annexc_flowcontrx = -1;
static int hf_h248_pkg_annexc_rateadapthdr = -1;
static int hf_h248_pkg_annexc_multiframe = -1;
static int hf_h248_pkg_annexc_opmode = -1;
static int hf_h248_pkg_annexc_llidnegot = -1;
static int hf_h248_pkg_annexc_assign = -1;
static int hf_h248_pkg_annexc_inbandneg = -1;
static int hf_h248_pkg_annexc_stopbits = -1;
static int hf_h248_pkg_annexc_databits = -1;
static int hf_h248_pkg_annexc_parity = -1;
static int hf_h248_pkg_annexc_duplexmode = -1;
static int hf_h248_pkg_annexc_modem = -1;
static int hf_h248_pkg_annexc_layer2prot = -1;
static int hf_h248_pkg_annexc_layer3prot = -1;
static int hf_h248_pkg_annexc_addlayer3prot = -1;
static int hf_h248_pkg_annexc_dialedn = -1;
static int hf_h248_pkg_annexc_dialingn = -1;
static int hf_h248_pkg_annexc_echoci = -1;
static int hf_h248_pkg_annexc_nci = -1;
static int hf_h248_pkg_annexc_USI = -1;

static int hf_h248_pkg_annexc_fmsdu = -1;
static int hf_h248_pkg_annexc_bmsdu = -1;
static int hf_h248_pkg_annexc_sscs = -1;

static int hf_h248_pkg_annexc_sdp_v = -1;
static int hf_h248_pkg_annexc_sdp_o = -1;
static int hf_h248_pkg_annexc_sdp_s = -1;
static int hf_h248_pkg_annexc_sdp_i = -1;
static int hf_h248_pkg_annexc_sdp_u = -1;
static int hf_h248_pkg_annexc_sdp_e = -1;
static int hf_h248_pkg_annexc_sdp_p = -1;
static int hf_h248_pkg_annexc_sdp_c = -1;
static int hf_h248_pkg_annexc_sdp_b = -1;
static int hf_h248_pkg_annexc_sdp_z = -1;
static int hf_h248_pkg_annexc_sdp_k = -1;
static int hf_h248_pkg_annexc_sdp_a = -1;
static int hf_h248_pkg_annexc_sdp_t = -1;
static int hf_h248_pkg_annexc_sdp_r = -1;
static int hf_h248_pkg_annexc_sdp_m = -1;

static int hf_h248_pkg_annexc_olc = -1;
static int hf_h248_pkg_annexc_olcack = -1;
static int hf_h248_pkg_annexc_olccnf = -1;
static int hf_h248_pkg_annexc_olcrej = -1;
static int hf_h248_pkg_annexc_clc = -1;
static int hf_h248_pkg_annexc_clcack = -1;



static gint ett_annexc = -1;
static gint ett_vpvc = -1;
static gint ett_codec = -1;

static const value_string h248_annexc_package_properties_vals[] = {
	{ 0x0000, "Media stream properties H.248.1 Annex C" },
	{ 0x1001, "media" },
	{ 0x1002, "transmission mode" },
	{ 0x1003, "num_of_channels" },
	{ 0x1004, "sampling_rate" },
	{ 0x1005, "bit_rate" },
	{ 0x1006, "ACodec" },
	{ 0x1007, "samplepp" },
	{ 0x1008, "silence_supp" },
	{ 0x1009, "encrypt_type" },
	{ 0x100A, "encrypt_key" },
	{ 0x100B, "echo canceller" },
	{ 0x100C, "gain" },
	{ 0x100D, "jitterbuf" },
	{ 0x100E, "propdelay" },
	{ 0x100F, "rtp_payload" },

	{ 0x2001, "h222" },
	{ 0x2002, "h223" },
	{ 0x2003, "v76" },
	{ 0x2004, "h2250" },

	{ 0x3001, "Mediatx" },
	{ 0x3002, "BIR" },
	{ 0x3003, "NSAP" },

	{ 0x4001, "aesa" },
	{ 0x4002, "vp" },
	{ 0x4003, "sc" },
	{ 0x4004, "bcob" },
	{ 0x4005, "bbtc" },
	{ 0x4006, "atc" },
	{ 0x4007, "stc" },
	{ 0x4008, "uppc" },
	{ 0x4009, "pcr0" },
	{ 0x400a, "scr0" },
	{ 0x400b, "mbs0" },
	{ 0x400c, "pcr1" },
	{ 0x400d, "scr1" },
	{ 0x400e, "mbs1" },
	{ 0x400f, "bei" },
	{ 0x4010, "ti" },
	{ 0x4011, "fd" },
	{ 0x4012, "a2pcdv" },
	{ 0x4013, "c2pcdv" },
	{ 0x4014, "appcdv" },
	{ 0x4015, "cppcdv" },
	{ 0x4016, "aclr" },
	{ 0x4017, "meetd" },
	{ 0x4018, "ceetd" },
	{ 0x4019, "QosClass" },
	{ 0x401a, "AALtype" },

	{ 0x5001, "DLCI" },
	{ 0x5002, "CID" },
	{ 0x5003, "SID/Noiselevel" },
	{ 0x5004, "PPT" },

	{ 0x6001, "IPv4" },
	{ 0x6002, "IPv6" },
	{ 0x6003, "Port" },
	{ 0x6004, "Porttype" },

	{ 0x7001, "AESA" },
	{ 0x7002, "ALC" },
	{ 0x7003, "SSCS" },
	{ 0x7004, "SUT" },
	{ 0x7005, "TCI" },
	{ 0x7006, "Timer_CU" },
	{ 0x7007, "MaxCPSSDU" },
	{ 0x7008, "CID" },

	{ 0x8001, "AAL1ST" },
	{ 0x8002, "CBRR" },
	{ 0x8003, "SCRI" },
	{ 0x8004, "ECM" },
	{ 0x8005, "SDTB" },
	{ 0x8006, "PFCI" },

	{ 0x9001, "TMR" },
	{ 0x9008, "USI" },
	{ 0x9009, "syncasync" },
	{ 0x900a, "negotiation" },
	{ 0x900b, "userrate" },
	{ 0x900c, "intrate" },
	{ 0x900d, "nictx" },
	{ 0x900e, "nicrx" },
	{ 0x900f, "flowconttx" },
	{ 0x9010, "flowcontrx" },
	{ 0x9011, "rateadapthdr" },
	{ 0x9012, "multiframe" },
	{ 0x9013, "opmode" },
	{ 0x9014, "llnegot" },
	{ 0x9015, "assign" },
	{ 0x9016, "inbandneg" },
	{ 0x9017, "stopbits" },
	{ 0x9018, "databits" },
	{ 0x9019, "parity" },
	{ 0x901a, "duplexmode" },
	{ 0x901b, "modem" },
	{ 0x901c, "layer2prot" },
	{ 0x901d, "layer3prot" },
	{ 0x901e, "addlayer3prot" },
	{ 0x901f, "DialledN" },
	{ 0x9020, "DiallingN" },
	{ 0x9021, "ECHOCI" },
	{ 0x9022, "NCI" },
	{ 0x9023, "USI" },

	{ 0xA001, "FMSDU" },
	{ 0xA002, "BMSDU" },

	{ 0xB001, "SDP_V (Protocol Version)" },
	{ 0xB002, "SDP_O (Owner/creator)" },
	{ 0xB003, "SDP_S (Session Name)" },
	{ 0xB004, "SDP_I (Session Identifier)" },
	{ 0xB005, "SDP_U (URI)" },
	{ 0xB006, "SDP_E (email address)" },
	{ 0xB007, "SDP_P (phone number)" },
	{ 0xB008, "SDP_C (connection)" },
	{ 0xB009, "SDP_B (bandwidth info)" },
	{ 0xB00A, "SDP_Z (TZ adjustment)" },
	{ 0xB00B, "SDP_K (encryption key)" },
	{ 0xB00C, "SDP_A (Session attributes)" },
	{ 0xB00D, "SDP_T (Active Session Time)" },
	{ 0xB00E, "SDP_R (Repeat times)" },
	{ 0xB00F, "SDP_M (Media type, portm transport and format)" },

	{ 0xC001, "OLC" },
	{ 0xC002, "OLCack" },
	{ 0xC003, "OLCcnf" },
	{ 0xC004, "OLCrej" },
	{ 0xC005, "CLC" },
	{ 0xC006, "CLCack" },

	{ 0,NULL }
};



static const value_string h248_annexc_media_vals[] = {
	{   0, "Audio" },
	{   1, "Video" },
	{   2, "Data" },
	{   0,NULL }
};

static const value_string h248_pkg_annexc_Mediatx_vals[] = {
	{   0x0000, "TDM Circuit" },
	{   0x0001, "ATM" },
	{   0x0002, "FR" },
	{   0x0003, "Ipv4" },
	{   0x0004, "Ipv6" },
	{0,     NULL}
};

static const value_string h248_annexc_transmission_mode[] = {
	{0, "Send"},
	{1, "Receive"},
	{2, "Send&Receive"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_sc[] _U_ = {
	{0, "CBR"},
	{1, "nrt-VBR1"},
	{2, "nrt-VBR2"},
	{3, "nrt-VBR3"},
	{4, "rt-VBR1"},
	{5, "rt-VBR2"},
	{6, "rt-VBR3"},
	{7, "UBR1"},
	{8, "UBR2"},
	{9, "ABR"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_atc_values[] = {
	{0, "DBR"},
	{1, "SBR1"},

	{2, "SBR2"},
	{3, "SBR3"},
	{4, "ABT/IT"},
	{5, "ABT/DT"},
	{6, "ABR"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_stc_values[] = {
	{0, "Not Susceptible to clipping"},
	{1, "Susceptible to clipping"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_uppc_values[] = {
	{0, "point-to-point"},
	{1, "point-to-multipoint"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_syncasync_values[] = {
	{0, "Synchronous Data"},
	{1, "Asynchronous Data"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_negotiation_values[] = {
	{0, "In-Band negotiation possible"},
	{1, "In-Band negotiation not possible"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_userrate_values[] = {
	{0x0, "E-Bit specified I.460 or higher negotiated in-band"},
	{0x1, "0.6 kbps (X.1)"},
	{0x2, "1.2 kbps"},
	{0x3, "2.4 kbps (X.1)"},
	{0x4, "3.6 kbps"},
	{0x5, "4.8 kbps (X.1)"},
	{0x6, "7.2 kbps"},
	{0x7, "8 kbps (I.460)"},
	{0x8, "9.6 kbps (X.1)"},
	{0x9, "14.4 kbps"},
	{0xa, "16 kbps (I.460)"},
	{0xb, "19.2 kbps"},
	{0xc, "32 kbps (I.460)"},
	{0xd, "38.4 kbps (V.110)"},
	{0xe, "48 kbps (X.1)"},
	{0xf, "56 kbps"},

	{0x12, "57.6 kbps (V.14 extended)"},
	{0x13, "28.8 kbps (V.110)"},
	{0x14, "24 kbps (V.110)"},
	{0x15, "0.1345 kbps (X.1)"},
	{0x16, "0.100 kbps (X.1)"},
	{0x17, "0.075/1.2 kbps (X.1)"},
	{0x18, "1.2/0.075 kbps (X.1)"},
	{0x19, "0.050 kbps (X.1)"},
	{0x1a, "0.075 kbps (X.1)"},
	{0x1b, "0.110 kbps (X.1)"},
	{0x1c, "0.150 kbps (X.1)"},
	{0x1d, "0.200 kbps (X.1)"},
	{0x1e, "0.300 kbps (X.1)"},
	{0x1f, "12 kbps (X.1)"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_intrate_values[] = {
	{0x0, "Not Used"},
	{0x1, "8 kbps"},
	{0x2, "16 kbps"},
	{0x3, "32 kbps"},
	{0,NULL}
};


static const value_string h248_pkg_annexc_nictx_values[] = {
	{0, "Not required to transmit with NIC"},
	{1, "Required to transmit with NIC"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_nicrx_values[] = {
	{0, "Cannot accept data with NIC"},
	{1, "Can accept data with NIC"},
	{0,NULL}
};


static const value_string h248_pkg_annexc_flowconttx_values[] = {
	{0, "Not Required"},
	{1, "Required"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_flowcontrx_values[] = {
	{0, "Cannot accept data with flow control mechanism"},
	{1, "Can accept data with flow control mechanism"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_rateadapthdr_values[] = {
	{0, "not included"},
	{1, "included"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_multiframe_values[] = {
	{0, "not supported"},
	{1, "supported"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_opmode_values[] = {
	{0, "bit transparent"},
	{1, "protocol sensitive"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_llidnegot_values[] = {
	{0, "Default, LLI=256 only"},
	{1, "Full protocol negotiation"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_assign_values[] = {
	{0, "Originator is default assignee"},
	{1, "Originator is assignor only"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_inbandneg_values[] = {
	{0, "negotiation on temporary signalling connection"},
	{1, "negotiation in-band"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_stopbits_values[] = {
	{0, "none"},
	{1, "1 bit"},
	{2, "1.5 bits"},
	{3, "2 bits"},
	{0,NULL}
};


static const value_string h248_pkg_annexc_databits_values[] = {
	{0, "Not Used"},
	{1, "5 bits"},
	{2, "7 bits"},
	{3, "8 bits"},
	{0,NULL}
};


static const value_string h248_pkg_annexc_parity_values[] = {
	{0, "Odd"},
	{2, "Even"},
	{3, "None"},
	{4, "Forced to 0"},
	{5, "Forced to 1"},
	{0,NULL}
};


static const value_string h248_pkg_annexc_duplexmode_values[] = {
	{0, "Half Duplex"},
	{1, "Full Duplex"},
	{0,NULL}
};


static const value_string h248_pkg_annexc_modem_values[] = {
	{0x00, "National Use"},
	{0x01, "National Use"},
	{0x02, "National Use"},
	{0x03, "National Use"},
	{0x04, "National Use"},
	{0x05, "National Use"},

	{0x11, "V.21"},
	{0x12, "V.22"},
	{0x13, "V.22bis"},
	{0x14, "V.23"},
	{0x15, "V.26"},
	{0x16, "V.26bis"},
	{0x17, "V.26ter"},
	{0x18, "V.27"},
	{0x19, "V.27bis"},
	{0x1A, "V.27ter"},
	{0x1B, "V.29"},
	{0x1D, "V.32"},
	{0x1E, "V.34"},

	{0x20, "National Use"},
	{0x21, "National Use"},
	{0x22, "National Use"},
	{0x23, "National Use"},
	{0x24, "National Use"},
	{0x25, "National Use"},
	{0x26, "National Use"},
	{0x27, "National Use"},
	{0x28, "National Use"},
	{0x29, "National Use"},
	{0x2a, "National Use"},
	{0x2b, "National Use"},
	{0x2c, "National Use"},
	{0x2d, "National Use"},
	{0x2e, "National Use"},
	{0x2f, "National Use"},

	{0x30, "User Specified"},
	{0x31, "User Specified"},
	{0x32, "User Specified"},
	{0x33, "User Specified"},
	{0x34, "User Specified"},
	{0x35, "User Specified"},
	{0x36, "User Specified"},
	{0x37, "User Specified"},
	{0x38, "User Specified"},
	{0x39, "User Specified"},
	{0x3a, "User Specified"},
	{0x3b, "User Specified"},
	{0x3c, "User Specified"},
	{0x3d, "User Specified"},
	{0x3e, "User Specified"},
	{0x3f, "User Specified"},

	{0,NULL}
};


static const value_string h248_pkg_annexc_layer2prot_values[] = {
	{0x2, "Q.921/I.441"},
	{0x6, "X.25, link layer"},
	{0xC, "LLC (ISO/IEC 8802-2)"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_layer3prot_values[] = {
	{0x2, "Q.921/I.441"},
	{0x6, "X.25, packet layer"},
	{0xC, "IP, ISO/IEC TR 9577"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_addlayer3prot_values[] = {
	{0xCC, "IP (RFC 791)"},
	{0xCF, "PPP (RFC 1661)"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_nci_satellite_values[] _U_ = {
	{0x0, "no satellite circuit"},
	{0x1, "one satellite circuit"},
	{0x2, "two satellite circuits"},
	{0x3, "spare"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_nci_continuity_values[] _U_ = {
	{0x0, "continuity check not required"},
	{0x1, "continuity check required on this circuit"},
	{0x2, "continuity check performed on a previous circuit"},
	{0x3, "spare"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_nci_echoctl_values[] _U_ = {
	{0x0, "outgoing echo control device not included"},
	{0x1, "outgoing echo control device included"},
	{0,NULL}
};


static const value_string h248_pkg_annexc_QosClass_values[] = {
	{0x0, "Default"},
	{0x1, "Stringent"},
	{0x2, "Tolerant"},
	{0x3, "Bi-Level"},
	{0x4, "Unbounded"},
	{0x5, "Stringent Bi-level"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_AALtype_values[] = {
	{0x0, "AAL for Voice"},
	{0x1, "AAL1"},
	{0x2, "AAL2"},
	{0x3, "AAL3/4"},
	{0x5, "AAL5"},
	{0x10, "User Defined"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_porttype_values[] = {
	{0x0, "TCP"},
	{0x1, "UDP"},
	{0x2, "SCTP"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_aal1st_values[] = {
	{0x0, "null"},
	{0x1, "voiceband signal transport on 64kbps"},
	{0x2, "circuit transport"},
	{0x4, "high quality audio signal transport"},
	{0x5, "video signal transport"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_cbrr_values[] = {
	{0x01, "64 kbps"},
	{0x04, "1544 kbps"},
	{0x05, "6312 kbps"},
	{0x06, "32064 kbps"},
	{0x07, "44736 kbps"},
	{0x08, "44736 kbps"},
	{0x10, "2048 kbps"},
	{0x11, "8448 kbps"},
	{0x12, "34368 kbps"},
	{0x13, "139264 kbps"},
	{0x40, "n * 64 kbps"},
	{0x41, "n * 8 kbps"},
	{0,NULL}
};

static const value_string h248_pkg_annexc_scri_values[] = {
	{0x0, "null"},
	{0x1, "SRTS"},
	{0x2, "ACM"},
	{0,NULL}
};


static const value_string h248_pkg_annexc_ecm_values[] = {
	{0x0, "null"},
	{0x1, "FEC - Loss"},
	{0x2, "FEC - Delay"},
	{0,NULL}
};


static const value_string h248_pkg_annexc_tmrsr_values[] = {
	/* TO DO */
	{0,NULL}
};


static const value_string h248_pkg_annexc_contcheck_values[] = {
	/* TO DO */
	{0,NULL}
};

static const value_string h248_pkg_annexc_itc_values[] = {
	/* TO DO */
	{0,NULL}
};


static const value_string h248_pkg_annexc_transmode_values[] = {
	/* TO DO */
	{0,NULL}
};


static const value_string h248_pkg_annexc_transrate_values[] = {
	/* TO DO */
	{0,NULL}
};



static void dissect_h248_annexc_acodec(proto_tree* tree,
										tvbuff_t* tvb,
										packet_info* pinfo,
										int hfid,
										h248_curr_info_t* h248_info _U_,
										void* implicit_p ) {
	int len;
	tvbuff_t* new_tvb;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	dissect_ber_octet_string(implicit_p ? *((gboolean*)implicit_p) : FALSE, &asn1_ctx, tree, tvb, 0, hfid, &new_tvb);

	tree = proto_item_add_subtree(asn1_ctx.created_item,ett_codec);
	len = tvb_reported_length(new_tvb);
	dissect_codec_mode(tree,new_tvb,0,len);
}

static void dissect_h248_annexc_BIR(proto_tree* tree,
									 tvbuff_t* tvb,
									 packet_info* pinfo,
									 int hfid,
									 h248_curr_info_t* h248_info,
									 void* implicit_p ) {
	tvbuff_t* new_tvb = NULL;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	dissect_ber_octet_string(implicit_p ? *((gboolean*)implicit_p) : FALSE, &asn1_ctx, tree, tvb, 0, hfid, &new_tvb);

	if ( new_tvb && h248_info->term && ! h248_info->term->bir ) {
		h248_info->term->bir = tvb_bytes_to_str(wmem_file_scope(), new_tvb,0,tvb_reported_length(new_tvb));
	}
}

static void dissect_h248_annexc_NSAP(proto_tree* tree,
									  tvbuff_t* tvb,
									  packet_info* pinfo,
									  int hfid,
									  h248_curr_info_t* h248_info,
									  void* implicit_p ) {
	tvbuff_t* new_tvb = NULL;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	dissect_ber_octet_string(implicit_p ? *((gboolean*)implicit_p) : FALSE, &asn1_ctx, tree, tvb, 0, hfid, &new_tvb);
	if (new_tvb) {
		dissect_nsap(new_tvb, 0,tvb_reported_length(new_tvb), tree);
		if ( h248_info->term && ! h248_info->term->nsap) {
			h248_info->term->nsap = tvb_bytes_to_str(wmem_file_scope(), new_tvb,0,tvb_reported_length(new_tvb));
		}
	}
}

static void dissect_h248_annexc_vpvc(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo _U_, int hfid, h248_curr_info_t* h248_info _U_, void* unused _U_) {
	proto_item* pi = proto_tree_add_item(tree,hfid,tvb,0,2,ENC_BIG_ENDIAN);
	proto_tree* pt = proto_item_add_subtree(pi,ett_vpvc);
	proto_tree_add_item(pt,hf_h248_pkg_annexc_vp,tvb,0,2,ENC_BIG_ENDIAN);
	proto_tree_add_item(pt,hf_h248_pkg_annexc_vc,tvb,2,2,ENC_BIG_ENDIAN);
}

static void dissect_h248_annexc_USI(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* h248_info _U_, void* implicit_p) {
	tvbuff_t* new_tvb = NULL;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	dissect_ber_octet_string(implicit_p ? *((gboolean*)implicit_p) : FALSE, &asn1_ctx, tree, tvb, 0, hfid, &new_tvb);
	if (new_tvb)
		dissect_q931_bearer_capability_ie(new_tvb, 0, tvb_reported_length(new_tvb), tree);
}

static void dissect_h248_annexc_SDP(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* h248_info _U_, void* implicit_p _U_) {
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	dissect_ber_restricted_string(FALSE, BER_UNI_TAG_IA5String,
		&asn1_ctx, tree, tvb, 0, hfid,
		NULL);
}

static void dissect_h248_annexc_SDP_C(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* h248_info _U_, void* implicit_p _U_) {
	asn1_ctx_t asn1_ctx;
	tvbuff_t *param_tvb = NULL;
	proto_item *ti;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	dissect_ber_restricted_string(FALSE, BER_UNI_TAG_IA5String,
		&asn1_ctx, tree, tvb, 0, hfid,
		&param_tvb);

	if (param_tvb){
		ti = proto_tree_add_item(tree, hf_h248_sdp_connection_info, param_tvb, 0, -1, ENC_BIG_ENDIAN);
		PROTO_ITEM_SET_GENERATED(ti);
	}
}

static void dissect_h248_annexc_SDP_M(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* h248_info _U_, void* implicit_p _U_) {
	asn1_ctx_t asn1_ctx;
	tvbuff_t *param_tvb = NULL;
	proto_item *ti;
	int offset, next_offset, tokenlen;
	gchar *port_str;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	dissect_ber_restricted_string(FALSE, BER_UNI_TAG_IA5String,
		&asn1_ctx, tree, tvb, 0, hfid,
		&param_tvb);

	if (param_tvb){
		offset = tvb_find_guint8(param_tvb, 0, -1, ' ');
		if (offset != -1){
			offset++;
			next_offset = tvb_find_guint8(param_tvb, offset, -1, ' ');
			if (next_offset > 0){
				tokenlen = next_offset - offset;
				port_str = tvb_get_string_enc(wmem_packet_scope(), param_tvb, offset, tokenlen, ENC_UTF_8 | ENC_NA);
				if (g_ascii_isdigit(port_str[0])) {
					ti = proto_tree_add_uint(tree, hf_h248_sdp_media_port, param_tvb, offset, tokenlen, atoi(port_str));
					PROTO_ITEM_SET_GENERATED(ti);
				}
			}
		}
	}
}

gboolean h248_c_implicit = TRUE;

static h248_pkg_param_t h248_annexc_package_properties[] = {
	{ 0x1001, &hf_h248_pkg_annexc_media, h248_param_ber_integer, NULL },
	{ 0x1002, &hf_h248_pkg_annexc_transmission_mode, h248_param_ber_integer, NULL },
	{ 0x1003, &hf_h248_pkg_annexc_num_of_channels, h248_param_ber_integer, NULL },
	{ 0x1004, &hf_h248_pkg_annexc_sampling_rate, h248_param_ber_integer, NULL },
	{ 0x1005, &hf_h248_pkg_annexc_bit_rate, h248_param_ber_integer, NULL },
	{ 0x1006, &hf_h248_pkg_annexc_ACodec, dissect_h248_annexc_acodec, NULL },
	{ 0x1007, &hf_h248_pkg_annexc_samplepp, h248_param_ber_integer, NULL },
	{ 0x1008, &hf_h248_pkg_annexc_silence_supp, h248_param_ber_boolean, NULL },
	{ 0x1009, &hf_h248_pkg_annexc_encrypt_type, h248_param_ber_octetstring, NULL }, /* XXX Hand over to what in H.245? */
	{ 0x100A, &hf_h248_pkg_annexc_encrypt_key, h248_param_ber_integer, NULL },
	{ 0x100C, &hf_h248_pkg_annexc_gain, h248_param_ber_integer, NULL },
	{ 0x100D, &hf_h248_pkg_annexc_jitterbuf, h248_param_ber_integer, NULL },
	{ 0x100E, &hf_h248_pkg_annexc_propdelay, h248_param_ber_integer, NULL },
	{ 0x100F, &hf_h248_pkg_annexc_rtp_payload, h248_param_ber_integer, NULL },

	{ 0x2001, &hf_h248_pkg_annexc_h222, h248_param_ber_octetstring, NULL },
	{ 0x2002, &hf_h248_pkg_annexc_h223, h248_param_ber_octetstring, NULL },
	{ 0x2003, &hf_h248_pkg_annexc_v76, h248_param_ber_octetstring, NULL },
	{ 0x2004, &hf_h248_pkg_annexc_h2250, h248_param_ber_octetstring, NULL },

	{ 0x3001, &hf_h248_pkg_annexc_Mediatx, h248_param_ber_integer, NULL },
	{ 0x3002, &hf_h248_pkg_annexc_BIR, dissect_h248_annexc_BIR, NULL },
	{ 0x3003, &hf_h248_pkg_annexc_NSAP, dissect_h248_annexc_NSAP, NULL },

	{ 0x4001, &hf_h248_pkg_annexc_aesa, h248_param_ber_octetstring, NULL },
	{ 0x4002, &hf_h248_pkg_annexc_vp, dissect_h248_annexc_vpvc, NULL },
	{ 0x4003, &hf_h248_pkg_annexc_sc, h248_param_ber_integer, NULL },
	{ 0x4004, &hf_h248_pkg_annexc_bcob, h248_param_ber_integer, NULL },
	{ 0x4005, &hf_h248_pkg_annexc_bbtc, h248_param_ber_integer, NULL },
	{ 0x4006, &hf_h248_pkg_annexc_atc, h248_param_ber_integer, NULL },
	{ 0x4007, &hf_h248_pkg_annexc_stc, h248_param_ber_integer, NULL },
	{ 0x4008, &hf_h248_pkg_annexc_uppc, h248_param_ber_integer, NULL },
	{ 0x4009, &hf_h248_pkg_annexc_pcr0, h248_param_ber_octetstring, NULL },
	{ 0x400a, &hf_h248_pkg_annexc_scr0, h248_param_ber_octetstring, NULL },
	{ 0x400b, &hf_h248_pkg_annexc_mbs0, h248_param_ber_octetstring, NULL },
	{ 0x400c, &hf_h248_pkg_annexc_pcr1, h248_param_ber_octetstring, NULL },
	{ 0x400d, &hf_h248_pkg_annexc_scr1, h248_param_ber_octetstring, NULL },
	{ 0x400e, &hf_h248_pkg_annexc_mbs1, h248_param_ber_octetstring, NULL },
	{ 0x400f, &hf_h248_pkg_annexc_bei, h248_param_ber_boolean, NULL },
	{ 0x4010, &hf_h248_pkg_annexc_ti, h248_param_ber_boolean, NULL },
	{ 0x4011, &hf_h248_pkg_annexc_fd, h248_param_ber_boolean, NULL },
	{ 0x4012, &hf_h248_pkg_annexc_a2pcdv, h248_param_ber_octetstring, NULL },
	{ 0x4013, &hf_h248_pkg_annexc_c2pcdv, h248_param_ber_octetstring, NULL },
	{ 0x4014, &hf_h248_pkg_annexc_appcdv, h248_param_ber_octetstring, NULL },
	{ 0x4015, &hf_h248_pkg_annexc_cppcdv, h248_param_ber_octetstring, NULL },
	{ 0x4016, &hf_h248_pkg_annexc_aclr, h248_param_ber_integer, NULL },
	{ 0x4017, &hf_h248_pkg_annexc_meetd, h248_param_ber_octetstring,NULL },
	{ 0x4018, &hf_h248_pkg_annexc_ceetd, h248_param_ber_octetstring,NULL },
	{ 0x4019, &hf_h248_pkg_annexc_QosClass, h248_param_ber_integer, NULL },
	{ 0x401A, &hf_h248_pkg_annexc_AALtype, h248_param_ber_integer, NULL },

	{ 0x5001, &hf_h248_pkg_annexc_dlci, h248_param_ber_integer, NULL },
	{ 0x5002, &hf_h248_pkg_annexc_cid, h248_param_ber_integer, NULL },
	{ 0x5003, &hf_h248_pkg_annexc_sid, h248_param_ber_integer, NULL },
	{ 0x5004, &hf_h248_pkg_annexc_ppt, h248_param_ber_integer, NULL },

	{ 0x6001, &hf_h248_pkg_annexc_ipv4, h248_param_ber_octetstring, NULL },
	{ 0x6002, &hf_h248_pkg_annexc_ipv6, h248_param_ber_octetstring,NULL },
	{ 0x6003, &hf_h248_pkg_annexc_port, h248_param_ber_integer, NULL },
	{ 0x6004, &hf_h248_pkg_annexc_porttype, h248_param_ber_integer, NULL },

	{ 0x7001, &hf_h248_pkg_annexc_aesa, h248_param_ber_octetstring, NULL },
	{ 0x7002, &hf_h248_pkg_annexc_alc, h248_param_ber_octetstring,NULL }, /* from ALCAP */
	{ 0x7003, &hf_h248_pkg_annexc_sscs, h248_param_ber_octetstring, NULL },
	{ 0x7004, &hf_h248_pkg_annexc_sut, h248_param_ber_octetstring, NULL },
	{ 0x7005, &hf_h248_pkg_annexc_tci, h248_param_ber_boolean, NULL },
	{ 0x7006, &hf_h248_pkg_annexc_timer_cu, h248_param_ber_octetstring, NULL },
	{ 0x7007, &hf_h248_pkg_annexc_maxcpssdu, h248_param_ber_integer, NULL },
	{ 0x7008, &hf_h248_pkg_annexc_cid, h248_param_ber_integer, NULL },

	{ 0x8001, &hf_h248_pkg_annexc_aal1st, h248_param_ber_integer, NULL },
	{ 0x8002, &hf_h248_pkg_annexc_cbrr, h248_param_ber_integer, NULL },
	{ 0x8003, &hf_h248_pkg_annexc_scri, h248_param_ber_integer, NULL },
	{ 0x8004, &hf_h248_pkg_annexc_ecm, h248_param_ber_integer, NULL },
	{ 0x8005, &hf_h248_pkg_annexc_sdbt, h248_param_ber_octetstring,NULL },
	{ 0x8006, &hf_h248_pkg_annexc_pfci, h248_param_ber_integer, NULL },

	{ 0x9001, &hf_h248_pkg_annexc_tmr, h248_param_ber_octetstring, NULL },
	{ 0x9002, &hf_h248_pkg_annexc_tmrsr, h248_param_ber_integer, NULL },
	{ 0x9003, &hf_h248_pkg_annexc_contcheck, h248_param_ber_integer, NULL },
	{ 0x9004, &hf_h248_pkg_annexc_itc, h248_param_ber_integer, NULL },
	{ 0x9005, &hf_h248_pkg_annexc_transmode, h248_param_ber_integer, NULL },
	{ 0x9006, &hf_h248_pkg_annexc_transrate, h248_param_ber_integer, NULL },
	{ 0x9007, &hf_h248_pkg_annexc_mult, h248_param_ber_integer, NULL },
	{ 0x9008, &hf_h248_pkg_annexc_USI, dissect_h248_annexc_USI, NULL },
	{ 0x9009, &hf_h248_pkg_annexc_syncasync, h248_param_ber_integer, NULL },
	{ 0x900A, &hf_h248_pkg_annexc_negotiation, h248_param_ber_integer, NULL },
	{ 0x900B, &hf_h248_pkg_annexc_userrate, h248_param_ber_integer, NULL },
	{ 0x900C, &hf_h248_pkg_annexc_intrate, h248_param_ber_integer, NULL },
	{ 0x900D, &hf_h248_pkg_annexc_nictx, h248_param_ber_boolean, NULL },
	{ 0x900E, &hf_h248_pkg_annexc_nicrx, h248_param_ber_boolean, NULL },
	{ 0x900F, &hf_h248_pkg_annexc_flowconttx, h248_param_ber_boolean, NULL },
	{ 0x9010, &hf_h248_pkg_annexc_flowcontrx, h248_param_ber_boolean, NULL },
	{ 0x9011, &hf_h248_pkg_annexc_rateadapthdr, h248_param_ber_boolean, NULL },
	{ 0x9012, &hf_h248_pkg_annexc_multiframe, h248_param_ber_boolean, NULL },
	{ 0x9013, &hf_h248_pkg_annexc_opmode, h248_param_ber_boolean, NULL },
	{ 0x9014, &hf_h248_pkg_annexc_llidnegot, h248_param_ber_boolean, NULL },
	{ 0x9015, &hf_h248_pkg_annexc_assign, h248_param_ber_boolean, NULL },
	{ 0x9016, &hf_h248_pkg_annexc_inbandneg, h248_param_ber_boolean, NULL },
	{ 0x9017, &hf_h248_pkg_annexc_stopbits, h248_param_ber_integer, NULL },
	{ 0x9018, &hf_h248_pkg_annexc_databits, h248_param_ber_integer, NULL },
	{ 0x9019, &hf_h248_pkg_annexc_parity, h248_param_ber_integer, NULL },
	{ 0x901a, &hf_h248_pkg_annexc_duplexmode, h248_param_ber_integer, NULL },
	{ 0x901b, &hf_h248_pkg_annexc_modem, h248_param_ber_integer, NULL },
	{ 0x901c, &hf_h248_pkg_annexc_layer2prot, h248_param_ber_integer, NULL },
	{ 0x901d, &hf_h248_pkg_annexc_layer3prot, h248_param_ber_integer, NULL },
	{ 0x901e, &hf_h248_pkg_annexc_addlayer3prot, h248_param_ber_integer, NULL },
	{ 0x901f, &hf_h248_pkg_annexc_dialedn, h248_param_ber_octetstring, NULL },
	{ 0x9020, &hf_h248_pkg_annexc_dialingn, h248_param_ber_octetstring, NULL },
	{ 0x9021, &hf_h248_pkg_annexc_echoci, h248_param_ber_integer, NULL },
	{ 0x9022, &hf_h248_pkg_annexc_nci, h248_param_ber_integer, NULL },
	{ 0x9023, &hf_h248_pkg_annexc_USI, dissect_h248_annexc_USI, NULL },

	{ 0xA001, &hf_h248_pkg_annexc_fmsdu, h248_param_ber_octetstring, NULL },
	{ 0xA002, &hf_h248_pkg_annexc_bmsdu, h248_param_ber_octetstring, NULL },
	{ 0xA003, &hf_h248_pkg_annexc_sscs, NULL, NULL },

	{ 0xB001, &hf_h248_pkg_annexc_sdp_v, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB002, &hf_h248_pkg_annexc_sdp_o, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB003, &hf_h248_pkg_annexc_sdp_s, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB004, &hf_h248_pkg_annexc_sdp_i, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB005, &hf_h248_pkg_annexc_sdp_u, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB006, &hf_h248_pkg_annexc_sdp_e, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB007, &hf_h248_pkg_annexc_sdp_p, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB008, &hf_h248_pkg_annexc_sdp_c, dissect_h248_annexc_SDP_C, &h248_c_implicit },
	{ 0xB009, &hf_h248_pkg_annexc_sdp_b, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB00a, &hf_h248_pkg_annexc_sdp_z, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB00b, &hf_h248_pkg_annexc_sdp_k, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB00c, &hf_h248_pkg_annexc_sdp_a, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB00d, &hf_h248_pkg_annexc_sdp_t, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB00e, &hf_h248_pkg_annexc_sdp_r, dissect_h248_annexc_SDP, &h248_c_implicit },
	{ 0xB00f, &hf_h248_pkg_annexc_sdp_m, dissect_h248_annexc_SDP_M, &h248_c_implicit },

	{ 0xC001, &hf_h248_pkg_annexc_olc, h248_param_ber_octetstring,    NULL },
	{ 0xC002, &hf_h248_pkg_annexc_olcack, h248_param_ber_octetstring, NULL },
	{ 0xC003, &hf_h248_pkg_annexc_olccnf, h248_param_ber_octetstring, NULL },
	{ 0xC004, &hf_h248_pkg_annexc_olcrej, h248_param_ber_octetstring, NULL },
	{ 0xC005, &hf_h248_pkg_annexc_clc, h248_param_ber_octetstring,    NULL },
	{ 0xC006, &hf_h248_pkg_annexc_clcack, h248_param_ber_octetstring, NULL },

	{ 0, NULL, NULL, NULL }
};

static h248_package_t h248_annexc_package = {
	0x0000,
	&proto_h248_pkg_annexc,
	&ett_annexc,
	h248_annexc_package_properties_vals,
	NULL,
	NULL,
	NULL,
	h248_annexc_package_properties, /* properties */
	NULL,							/* signals */
	NULL,							/* events */
	NULL							/* statistics */
};


void proto_register_h248_annex_c(void) {
	static hf_register_info hf[] = {
		{ &hf_h248_pkg_annexc_media,
		  { "Media", "h248.annexc.media",
		    FT_UINT32, BASE_HEX, VALS(h248_annexc_media_vals), 0,
		    "Media Type", HFILL }},
		{ &hf_h248_pkg_annexc_ACodec,
		  { "ACodec", "h248.annexc.ACodec",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_Mediatx,
		  { "Mediatx", "h248.annexc.Mediatx",
		    FT_UINT32, BASE_DEC, VALS(h248_pkg_annexc_Mediatx_vals), 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_BIR,
		  { "BIR", "h248.annexc.BIR",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_NSAP,
		  { "NSAP", "h248.annexc.NSAP",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_transmission_mode,
		  { "Transmission Mode", "h248.annexc.transmission_mode",
		    FT_UINT32, BASE_DEC, VALS(h248_annexc_transmission_mode), 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_num_of_channels,
		  { "Number of Channels", "h248.annexc.num_of_channels",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_sampling_rate,
		  { "Sampling Rate", "h248.annexc.sampling_rate",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_bit_rate,
		  { "Bit Rate", "h248.annexc.bit_rate",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_samplepp,
		  { "Samplepp", "h248.annexc.samplepp",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_silence_supp,
		  { "SilenceSupp", "h248.annexc.silence_supp",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Silence Suppression", HFILL }},
		{ &hf_h248_pkg_annexc_encrypt_type,
		  { "Encrypttype", "h248.annexc.encrypt_type",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    "Encryption Type", HFILL }},
		{ &hf_h248_pkg_annexc_encrypt_key,
		  { "Encrypt Key", "h248.annexc.encrypt_key",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Encryption Key", HFILL }},
		{ &hf_h248_pkg_annexc_gain,
		  { "Gain", "h248.annexc.gain",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Gain (dB)", HFILL }},
		{ &hf_h248_pkg_annexc_jitterbuf,
		  { "JitterBuff", "h248.annexc.jitterbuf",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Jitter Buffer Size (ms)", HFILL }},
		{ &hf_h248_pkg_annexc_propdelay,
		  { "Propagation Delay", "h248.annexc.propdelay",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Propagation Delay (ms)", HFILL }},
		{ &hf_h248_pkg_annexc_rtp_payload,
		  { "RTP Payload type", "h248.annexc.rtp_payload",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Payload type in RTP Profile", HFILL }},
		{ &hf_h248_pkg_annexc_h222,
		  { "H222LogicalChannelParameters", "h248.annexc.h222",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_h223,
		  { "H223LogicalChannelParameters", "h248.annexc.h223",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_v76,
		  { "V76LogicalChannelParameters", "h248.annexc.v76",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_h2250,
		  { "H2250LogicalChannelParameters", "h248.annexc.h2250",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_aesa,
		  { "AESA", "h248.annexc.aesa",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    "ATM End System Address", HFILL }},
		{ &hf_h248_pkg_annexc_vp,
		  { "VPI", "h248.annexc.vpi",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    "Virtual Path Identifier", HFILL }},
		{ &hf_h248_pkg_annexc_vc,
		  { "VCI", "h248.annexc.vci",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    "Virtual Circuit Identifier", HFILL }},
		{ &hf_h248_pkg_annexc_sc,
		  { "Service Class", "h248.annexc.sc",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_bcob,
		  { "BCOB", "h248.annexc.bcob",
		    FT_UINT8, BASE_DEC, NULL, 0x1F,
		    "Broadband Bearer Class", HFILL }},
		{ &hf_h248_pkg_annexc_bbtc,
		  { "BBTC", "h248.annexc.bbtc",
		    FT_UINT8, BASE_DEC, NULL, 0x3F,
		    "Broadband Transfer Capability", HFILL }},
		{ &hf_h248_pkg_annexc_atc,
		  { "ATC", "h248.annexc.atc",
		    FT_UINT32, BASE_DEC, VALS(h248_pkg_annexc_atc_values), 0x0,
		    "ATM Traffic Capability", HFILL }},
		{ &hf_h248_pkg_annexc_stc,
		  { "STC", "h248.annexc.stc",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_stc_values), 0x03,
		    "Susceptibility to Clipping", HFILL }},
		{ &hf_h248_pkg_annexc_uppc,
		  { "UPPC", "h248.annexc.uppc",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_uppc_values), 0x03,
		    "User Plane Connection Configuration", HFILL }},

		{ &hf_h248_pkg_annexc_pcr0,
		  { "PCR0", "h248.annexc.pcr0",
		    FT_UINT24, BASE_DEC, NULL, 0,
		    "Peak Cell Rate for CLP=0", HFILL }},
		{ &hf_h248_pkg_annexc_scr0,
		  { "SCR0", "h248.annexc.scr0",
		    FT_UINT24, BASE_DEC, NULL, 0,
		    "Sustained Cell Rate for CLP=0", HFILL }},
		{ &hf_h248_pkg_annexc_mbs0,
		  { "MBS0", "h248.annexc.mbs0",
		    FT_UINT24, BASE_DEC, NULL, 0,
		    "Maximum Burst Size for CLP=0", HFILL }},

		{ &hf_h248_pkg_annexc_pcr1,
		  { "PCR1", "h248.annexc.pcr1",
		    FT_UINT24, BASE_DEC, NULL, 0,
		    "Peak Cell Rate for CLP=1", HFILL }},
		{ &hf_h248_pkg_annexc_scr1,
		  { "SCR1", "h248.annexc.scr1",
		    FT_UINT24, BASE_DEC, NULL, 0,
		    "Sustained Cell Rate for CLP=1", HFILL }},
		{ &hf_h248_pkg_annexc_mbs1,
		  { "MBS1", "h248.annexc.mbs1",
		    FT_UINT24, BASE_DEC, NULL, 0,
		    "Maximum Burst Size for CLP=1", HFILL }},

		{ &hf_h248_pkg_annexc_bei,
		  { "BEI", "h248.annexc.bei",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Best Effort Indicator", HFILL }},
		{ &hf_h248_pkg_annexc_ti,
		  { "TI", "h248.annexc.ti",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Tagging Indicator", HFILL }},
		{ &hf_h248_pkg_annexc_fd,
		  { "FD", "h248.annexc.fd",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Frame Discard", HFILL }},

		{ &hf_h248_pkg_annexc_a2pcdv,
		  { "A2PCDV", "h248.annexc.a2pcdv",
		    FT_UINT24, BASE_DEC, NULL, 0,
		    "Acceptable 2 point CDV", HFILL }},
		{ &hf_h248_pkg_annexc_c2pcdv,
		  { "C2PCDV", "h248.annexc.c2pcdv",
		    FT_UINT24, BASE_DEC, NULL, 0,
		    "Cumulative 2 point CDV", HFILL }},
		{ &hf_h248_pkg_annexc_appcdv,
		  { "APPCDV", "h248.annexc.appcdv",
		    FT_UINT24, BASE_DEC, NULL, 0,
		    "Acceptable Point to Point CDV", HFILL }},
		{ &hf_h248_pkg_annexc_cppcdv,
		  { "CPPCDV", "h248.annexc.cppcdv",
		    FT_UINT24, BASE_DEC, NULL, 0,
		    "Cumulative Point to Point CDV", HFILL }},
		{ &hf_h248_pkg_annexc_aclr,
		  { "ACLR", "h248.annexc.aclr",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Acceptable Cell Loss Ratio (Q.2965.2 ATMF UNI 4.0)", HFILL }},

		{ &hf_h248_pkg_annexc_meetd,
		  { "MEETD", "h248.annexc.meetd",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    "Maximum End-to-End Transit Delay (Q.2965.2 ATMF UNI 4.0)", HFILL }},
		{ &hf_h248_pkg_annexc_ceetd,
		  { "CEETD", "h248.annexc.ceetd",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    "Cumulative End-to-End Transit Delay (Q.2965.2 ATMF UNI 4.0)", HFILL }},
		{ &hf_h248_pkg_annexc_QosClass,
		  { "QosClass", "h248.annexc.qosclass",
		    FT_UINT16, BASE_DEC, VALS(h248_pkg_annexc_QosClass_values), 0,
		    "QoS Class (Q.2965.1)", HFILL }},
		{ &hf_h248_pkg_annexc_AALtype,
		  { "AALtype", "h248.annexc.aaltype",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_AALtype_values), 0,
		    "AAL Type", HFILL }},

		{ &hf_h248_pkg_annexc_dlci,
		  { "DLCI", "h248.annexc.dlci",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Data Link Connection ID (FR)", HFILL }},
		{ &hf_h248_pkg_annexc_cid,
		  { "CID", "h248.annexc.cid",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Channel-Id", HFILL }},
		{ &hf_h248_pkg_annexc_sid,
		  { "SID", "h248.annexc.sid",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Silence Insertion Descriptor", HFILL }},
		{ &hf_h248_pkg_annexc_ppt,
		  { "PPT", "h248.annexc.ppt",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Primary Payload Type", HFILL }},

		{ &hf_h248_pkg_annexc_ipv4,
		  { "IPv4", "h248.annexc.ipv4",
		    FT_IPv4, BASE_NONE, NULL, 0,
		    "IPv4 Address", HFILL }},
		{ &hf_h248_pkg_annexc_ipv6,
		  { "IPv6", "h248.annexc.ipv6",
		    FT_IPv6, BASE_NONE, NULL, 0,
		    "IPv6 Address", HFILL }},
		{ &hf_h248_pkg_annexc_port,
		  { "Port", "h248.annexc.port",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_porttype,
		  { "PortType", "h248.annexc.porttype",
		    FT_UINT32, BASE_DEC, VALS(h248_pkg_annexc_porttype_values), 0,
		    "Port Type", HFILL }},

		{ &hf_h248_pkg_annexc_alc,
		  { "ALC", "h248.annexc.alc",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    "AAL2 Link Characteristics", HFILL }},
		{ &hf_h248_pkg_annexc_sut,
		  { "SUT", "h248.annexc.sut",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    "Served User Transport", HFILL }},
		{ &hf_h248_pkg_annexc_tci,
		  { "TCI", "h248.annexc.tci",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Test Connection Indicator", HFILL }},
		{ &hf_h248_pkg_annexc_timer_cu,
		  { "Timer CU", "h248.annexc.timer_cu",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Milliseconds to hold the  partially filled cell before sending", HFILL }},
		{ &hf_h248_pkg_annexc_maxcpssdu,
		  { "Max CPS SDU", "h248.annexc.maxcpssdu",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Maximum Common Part Sublayer Service Data Unit size", HFILL }},

		{ &hf_h248_pkg_annexc_aal1st,
		  { "AAL1ST", "h248.annexc.aal1st",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_aal1st_values), 0,
		    "AAL1 subtype", HFILL }},
		{ &hf_h248_pkg_annexc_cbrr,
		  { "CBRR", "h248.annexc.cbrr",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_cbrr_values), 0,
		    "CBR rate", HFILL }},
		{ &hf_h248_pkg_annexc_scri,
		  { "SCRI", "h248.annexc.scri",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_scri_values), 0,
		    "Source Clock frequency Recovery Method", HFILL }},
		{ &hf_h248_pkg_annexc_ecm,
		  { "ECM", "h248.annexc.ecm",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_ecm_values), 0,
		    "Error Correction Method", HFILL }},
		{ &hf_h248_pkg_annexc_sdbt,
		  { "SDBT", "h248.annexc.sdbt",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    "Structured Data Transfer Blocksize", HFILL }},
		{ &hf_h248_pkg_annexc_pfci,
		  { "PFCI", "h248.annexc.pfci",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Partially Filled Cells Identifier", HFILL }},

		{ &hf_h248_pkg_annexc_tmr,
		  { "TMR", "h248.annexc.tmr",
		    FT_UINT8, BASE_HEX|BASE_EXT_STRING, &isup_transmission_medium_requirement_value_ext, 0,
		    "Transmission Medium Requirement", HFILL }},
		{ &hf_h248_pkg_annexc_tmrsr,
		  { "TMSR", "h248.annexc.tmsr",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_tmrsr_values), 0,
		    "Transmission Medium Requirement Subrate", HFILL }},
		{ &hf_h248_pkg_annexc_contcheck,
		  { "Continuity Check", "h248.annexc.tmsr",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_contcheck_values), 0x0C,
		    NULL, HFILL }},

		{ &hf_h248_pkg_annexc_itc,
		  { "ITC", "h248.annexc.itc",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_itc_values), 0x1f,
		    "Information Transfer Capability", HFILL }},
		{ &hf_h248_pkg_annexc_transmode,
		  { "TransMode", "h248.annexc.transmode",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_transmode_values), 0x60,
		    "Transfer Mode", HFILL }},
		{ &hf_h248_pkg_annexc_transrate,
		  { "TransRate", "h248.annexc.transrate",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_transrate_values), 0x1f,
		    "Transfer Rate", HFILL }},
		{ &hf_h248_pkg_annexc_mult,
		  { "Rate Multiplier", "h248.annexc.mult",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_syncasync,
		  { "SyncAsync", "h248.annexc.syncasync",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_syncasync_values), 0x80,
		    "Synchronous/Asynchronous", HFILL }},
		{ &hf_h248_pkg_annexc_negotiation,
		  { "UPPC", "h248.annexc.negotiation",
		    FT_UINT8, BASE_DEC, VALS(h248_pkg_annexc_negotiation_values), 0x40,
		    "Negotiation", HFILL }},

		{ &hf_h248_pkg_annexc_userrate,
		  { "Userrate", "h248.annexc.userrate",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_userrate_values), 0x1f,
		    "User Rate", HFILL }},
		{ &hf_h248_pkg_annexc_intrate,
		  { "UPPC", "h248.annexc.intrate",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_intrate_values), 0xc0,
		    "Intermediate Rate", HFILL }},
		{ &hf_h248_pkg_annexc_nictx,
		  { "nictx", "h248.annexc.nictx",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_nictx_values), 0xc0,
		    "Network independent clock on transmission", HFILL }},
		{ &hf_h248_pkg_annexc_nicrx,
		  { "nicrx", "h248.annexc.nicrx",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_nicrx_values), 0xc0,
		    "Network independent clock on reception", HFILL }},
		{ &hf_h248_pkg_annexc_flowconttx,
		  { "flowconttx", "h248.annexc.flowconttx",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_flowconttx_values), 0xc0,
		    "Flow Control on Transmission", HFILL }},
		{ &hf_h248_pkg_annexc_flowcontrx,
		  { "flowcontrx", "h248.annexc.flowcontrx",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_flowcontrx_values), 0xc0,
		    "Flow Control on Reception", HFILL }},
		{ &hf_h248_pkg_annexc_rateadapthdr,
		  { "rateadapthdr", "h248.annexc.rateadapthdr",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_rateadapthdr_values), 0xc0,
		    "Rate Adaptation Header/No-Header", HFILL }},
		{ &hf_h248_pkg_annexc_multiframe,
		  { "multiframe", "h248.annexc.multiframe",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_multiframe_values), 0xc0,
		    "Multiple Frame establishment support in datalink", HFILL }},
		{ &hf_h248_pkg_annexc_opmode,
		  { "OPMODE", "h248.annexc.opmode",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_opmode_values), 0xc0,
		    "Mode of operation", HFILL }},
		{ &hf_h248_pkg_annexc_llidnegot,
		  { "llidnegot", "h248.annexc.llidnegot",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_llidnegot_values), 0xc0,
		    "Logical Link Identifier negotiation", HFILL }},

		{ &hf_h248_pkg_annexc_assign,
		  { "llidnegot", "h248.annexc.assign",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_assign_values), 0xc0,
		    "Assignor/Assignee", HFILL }},
		{ &hf_h248_pkg_annexc_inbandneg,
		  { "inbandneg", "h248.annexc.inbandneg",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_inbandneg_values), 0xc0,
		    "In-band/Out-band negotiation", HFILL }},
		{ &hf_h248_pkg_annexc_stopbits,
		  { "stopbits", "h248.annexc.stopbits",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_stopbits_values), 0xc0,
		    "Number of stop bits", HFILL }},
		{ &hf_h248_pkg_annexc_databits,
		  { "databits", "h248.annexc.databits",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_databits_values), 0xc0,
		    "Number of data bits", HFILL }},
		{ &hf_h248_pkg_annexc_parity,
		  { "parity", "h248.annexc.parity",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_parity_values), 0xe0,
		    "Parity Information Bits", HFILL }},
		{ &hf_h248_pkg_annexc_duplexmode,
		  { "duplexmode", "h248.annexc.duplexmode",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_duplexmode_values), 0x80,
		    "Mode Duplex", HFILL }},

		{ &hf_h248_pkg_annexc_modem,
		  { "modem", "h248.annexc.modem",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_modem_values), 0xfc,
		    "Modem Type", HFILL }},
		{ &hf_h248_pkg_annexc_layer2prot,
		  { "layer2prot", "h248.annexc.layer2prot",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_layer2prot_values), 0x80,
		    "Layer 2 protocol", HFILL }},
		{ &hf_h248_pkg_annexc_layer3prot,
		  { "layer3prot", "h248.annexc.layer3prot",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_layer3prot_values), 0x80,
		    "Layer 3 protocol", HFILL }},
		{ &hf_h248_pkg_annexc_addlayer3prot,
		  { "addlayer3prot", "h248.annexc.addlayer3prot",
		    FT_UINT8, BASE_HEX, VALS(h248_pkg_annexc_addlayer3prot_values), 0x80,
		    "Additional User Information Layer 3 protocol", HFILL }},
		{ &hf_h248_pkg_annexc_dialedn,
		  { "Dialed Number", "h248.annexc.dialedn",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_dialingn,
		  { "Dialing Number", "h248.annexc.dialingn",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_echoci,
		  { "ECHOCI", "h248.annexc.echoci",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    "Not used", HFILL }},
		{ &hf_h248_pkg_annexc_nci,
		  { "NCI", "h248.annexc.nci",
		    FT_UINT8, BASE_HEX, NULL, 0xff,
		    "Nature of Connection Indicator", HFILL }},


		{ &hf_h248_pkg_annexc_USI,
		  { "USI", "h248.annexc.USI",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    "User Service Information", HFILL }},


		{ &hf_h248_pkg_annexc_fmsdu,
		  { "fmsdu", "h248.annexc.fmsdu",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_bmsdu,
		  { "bmsdu", "h248.annexc.bmsdu",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_h248_pkg_annexc_sscs,
		  { "sscs", "h248.annexc.sscs",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},


		{ &hf_h248_pkg_annexc_sdp_v,
		  { "sdp_v", "h248.annexc.sdp_v",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP V", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_o,
		  { "sdp_o", "h248.annexc.sdp_o",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP O", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_s,
		  { "sdp_s", "h248.annexc.sdp_s",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP S", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_i,
		  { "sdp_i", "h248.annexc.sdp_i",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP I", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_u,
		  { "sdp_u", "h248.annexc.sdp_u",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP U", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_e,
		  { "sdp_e", "h248.annexc.sdp_e",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP E", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_p,
		  { "sdp_p", "h248.annexc.sdp_p",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP P", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_c,
		  { "sdp_c", "h248.annexc.sdp_c",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP C", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_b,
		  { "sdp_b", "h248.annexc.sdp_b",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP B", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_z,
		  { "sdp_z", "h248.annexc.sdp_z",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP Z", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_k,
		  { "sdp_k", "h248.annexc.sdp_k",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP K", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_a,
		  { "sdp_a", "h248.annexc.sdp_a",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP A", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_t,
		  { "sdp_t", "h248.annexc.sdp_t",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP T", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_r,
		  { "sdp_r", "h248.annexc.sdp_r",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP R", HFILL }},
		{ &hf_h248_pkg_annexc_sdp_m,
		  { "sdp_m", "h248.annexc.sdp_m",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SDP M", HFILL }},

		{ &hf_h248_pkg_annexc_olc,
		  { "OLC", "h248.annexc.olc",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    "Open Logical Channel", HFILL }},
		{ &hf_h248_pkg_annexc_olcack,
		  { "OLCack", "h248.annexc.olcack",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    "Open Logical Channel Acknowledge", HFILL }},
		{ &hf_h248_pkg_annexc_olccnf,
		  { "OLCcnf", "h248.annexc.olccnf",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    "Open Logical Channel CNF", HFILL }},
		{ &hf_h248_pkg_annexc_olcrej,
		  { "OLCrej", "h248.annexc.olcrej",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    "Open Logical Channel Reject", HFILL }},
		{ &hf_h248_pkg_annexc_clc,
		  { "CLC", "h248.annexc.clc",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    "Close Logical Channel", HFILL }},
		{ &hf_h248_pkg_annexc_clcack,
		  { "CLCack", "h248.annexc.clcack",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_annexc,
		&ett_vpvc,
		&ett_codec
	};

	proto_h248_pkg_annexc = proto_register_protocol(PNAME, PSNAME, PFNAME);

	proto_register_field_array(proto_h248_pkg_annexc, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	h248_register_package(&h248_annexc_package,MERGE_PKG_HIGH);


}

void
proto_reg_handoff_h248_annex_c(void)
{

	hf_h248_sdp_connection_info = proto_registrar_get_id_byname("sdp.connection_info");
	hf_h248_sdp_media_port = proto_registrar_get_id_byname("sdp.media.port");

}
/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
