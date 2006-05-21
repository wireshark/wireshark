/* packet-rtp-events.h
 *
 * Defines for RFC 2833 RTP Events dissection
 * Copyright 2003, Kevin A. Noll <knoll[AT]poss.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#define RTP_DTMF_0	0
#define RTP_DTMF_1	1
#define RTP_DTMF_2	2
#define RTP_DTMF_3	3
#define RTP_DTMF_4	4
#define RTP_DTMF_5	5
#define RTP_DTMF_6	6
#define RTP_DTMF_7	7
#define RTP_DTMF_8	8
#define RTP_DTMF_9	9
#define RTP_DTMF_STAR	10
#define RTP_DTMF_POUND	11
#define RTP_DTMF_A	12
#define RTP_DTMF_B	13
#define RTP_DTMF_C	14
#define RTP_DTMF_D	15
#define RTP_DTMF_FLASH	16

#define RTP_ANS		32
#define RTP_ANSREV	33
#define RTP_ANSAM	34
#define RTP_ANSAMREV	35
#define RTP_CNG		36
#define RTP_V21C1B0	37
#define RTP_V21C1B1	38
#define RTP_V21C2B0	39
#define RTP_V21C2B1	40
#define RTP_CRDI	41
#define RTP_CRDR	42
#define RTP_CRE		43
#define RTP_ESI		44
#define RTP_ESR		45
#define RTP_MRDI	46
#define RTP_MRDR	47
#define RTP_MRE		48
#define RTP_CT		49

#define RTP_OFFHOOK	64
#define RTP_ONHOOK	65
#define RTP_DIALTONE	66
#define RTP_INTDT	67
#define RTP_SPCDT	68
#define RTP_2NDDT	69
#define RTP_RGTONE	70
#define RTP_SPRGTONE	71
#define RTP_BUSYTONE	72
#define RTP_CNGTONE	73
#define RTP_SPINFOTN	74
#define RTP_CMFTTONE	75
#define RTP_HOLDTONE	76
#define RTP_RECTONE	77
#define RTP_CLRWTTONE	78
#define RTP_CWTONE	79
#define RTP_PAYTONE	80
#define RTP_POSINDTONE	81
#define RTP_NEGINDTONE	82
#define RTP_WARNTONE	83
#define RTP_INTRTONE	84
#define RTP_CALLCDTONE	85
#define RTP_PAYPHONE	86
#define RTP_CAS		87
#define RTP_OFFHKWARN	88
#define RTP_RING	89

#define RTP_ACCPTTONE	96
#define RTP_CONFIRMTN	97
#define RTP_DLTNRECALL	98
#define RTP_END3WAYTN	99
#define RTP_FACTONE	100
#define RTP_LNLOCKTN	101
#define RTP_NUMUNOBT	102
#define RTP_OFFERGTONE	103
#define RTP_PERMSIGTN	104
#define RTP_PREEMPTTN	105
#define RTP_QUETONE	106
#define RTP_REFUSALTN	107
#define RTP_ROUTETONE	108
#define RTP_VALIDTONE	109
#define RTP_WAITGTONE	110
#define RTP_WARNEOPTN	111
#define RTP_WARNPIPTN	112

#define RTP_MF0		128
#define RTP_MF1		129
#define RTP_MF2		130
#define RTP_MF3		131
#define RTP_MF4		132
#define RTP_MF5		133
#define RTP_MF6		134
#define RTP_MF7		135
#define RTP_MF8		136
#define RTP_MF9		137
#define RTP_K0		138
#define RTP_K1		139
#define RTP_K2		140
#define RTP_S0		141
#define RTP_S1		142
#define RTP_S3		143

#define RTP_WINK	160
#define RTP_WINKOFF	161
#define RTP_INCSEIZ	162
#define RTP_SEIZURE	163
#define RTP_UNSEIZE	164
#define RTP_COT		165
#define RTP_DEFCOT	166
#define RTP_COTTONE	167
#define RTP_COTSEND	168

#define RTP_COTVERFD	170
#define RTP_LOOPBACK	171
#define RTP_MWATTTONE	172
#define RTP_NEWMWATTTN	173

static const value_string rtp_event_type_values[] =
{

	{ RTP_DTMF_0,		"DTMF Zero 0" },
	{ RTP_DTMF_1,		"DTMF One 1" },
	{ RTP_DTMF_2,		"DTMF Two 2" },
	{ RTP_DTMF_3,		"DTMF Three 3" },
	{ RTP_DTMF_4,		"DTMF Four 4" },
	{ RTP_DTMF_5,		"DTMF Five 5" },
	{ RTP_DTMF_6,		"DTMF Six 6" },
	{ RTP_DTMF_7,		"DTMF Seven 7" },
	{ RTP_DTMF_8,		"DTMF Eight 8" },
	{ RTP_DTMF_9,		"DTMF Nine 9" },
	{ RTP_DTMF_STAR,	"DTMF Star *" },
	{ RTP_DTMF_POUND,	"DTMF Pound #" },
	{ RTP_DTMF_A,		"DTMF A" },
	{ RTP_DTMF_B,		"DTMF B" },
	{ RTP_DTMF_C,		"DTMF C" },
	{ RTP_DTMF_D,		"DTMF D" },
	{ RTP_DTMF_FLASH,	"Flash" },
	{ RTP_ANS,		"Fax ANS"},
	{ RTP_ANSREV,       	"Fax /ANS"},
	{ RTP_ANSAM,		"Fax ANSam"},
	{ RTP_ANSAMREV,		"Fax /ANSam"},
	{ RTP_CNG,		"Fax CNG"},
	{ RTP_V21C1B0,		"V.21 channel 1, 0 bit"},
	{ RTP_V21C1B1,		"V.21 channel 1, 1 bit"},
	{ RTP_V21C2B0,		"V.21 channel 2, 0 bit"},
	{ RTP_V21C2B1,		"V.21 channel 2, 1 bit"},
	{ RTP_CRDI,		"Fax CRdi"},
	{ RTP_CRDR,		"Fax CRdr"},
	{ RTP_CRE,		"Fax CRe"},
	{ RTP_ESI,		"Fax ESi"},
	{ RTP_ESR,		"Fax ESr"},
	{ RTP_MRDI,		"Fax MRdi"},
	{ RTP_MRDR,		"Fax MRdr"},
	{ RTP_MRE,		"Fax MRe"},
	{ RTP_CT,		"Fax CT"},
	{ RTP_OFFHOOK,		"Off Hook"},
	{ RTP_ONHOOK,		"On Hook"},
	{ RTP_DIALTONE,		"Dial tone"},
	{ RTP_INTDT,	        "PABX internal dial tone"},
	{ RTP_SPCDT,	        "Special dial tone"},
	{ RTP_2NDDT,	        "Second dial tone"},
	{ RTP_RGTONE,	        "Ringing tone"},
	{ RTP_SPRGTONE,	        "Special ringing tone"},
	{ RTP_BUSYTONE,	        "Busy tone"},
	{ RTP_CNGTONE,	        "Congestion tone"},
	{ RTP_SPINFOTN,	        "Special information tone"},
	{ RTP_CMFTTONE,	        "Comfort tone"},
	{ RTP_HOLDTONE,	        "Hold tone"},
	{ RTP_RECTONE,	        "Record tone"},
	{ RTP_CLRWTTONE,	"Caller waiting tone"},
	{ RTP_CWTONE,	        "Call waiting tone"},
	{ RTP_PAYTONE,	        "Pay tone"},
	{ RTP_POSINDTONE,       "Positive indication tone"},
	{ RTP_NEGINDTONE,       "Negative indication tone"},
	{ RTP_WARNTONE,         "Warning tone"},
	{ RTP_INTRTONE,         "Intrusion tone"},
	{ RTP_CALLCDTONE,       "Calling card service tone"},
	{ RTP_PAYPHONE,         "Payphone recognition tone"},
	{ RTP_CAS,              "CPE alerting signal (CAS)"},
	{ RTP_OFFHKWARN,        "Off-hook warning tone"},
	{ RTP_RING,             "Ring"},
	{ RTP_ACCPTTONE,        "Acceptance tone"},
	{ RTP_CONFIRMTN,        "Confirmation tone"},
	{ RTP_DLTNRECALL,	"Dial tone, recall"},
	{ RTP_END3WAYTN,        "End of three party service tone"},
	{ RTP_FACTONE,          "Facilities tone"},
	{ RTP_LNLOCKTN,         "Line lockout tone"},
	{ RTP_NUMUNOBT,         "Number unobtainable tone"},
	{ RTP_OFFERGTONE,       "Offering tone"},
	{ RTP_PERMSIGTN,        "Permanent signal tone"},
	{ RTP_PREEMPTTN,        "Preemption tone"},
	{ RTP_QUETONE,          "Queue tone"},
	{ RTP_REFUSALTN,        "Refusal tone"},
	{ RTP_ROUTETONE,        "Route tone"},
	{ RTP_VALIDTONE,        "Valid tone"},
	{ RTP_WAITGTONE,        "Waiting tone"},
	{ RTP_WARNEOPTN,        "Warning tone (end of period)"},
	{ RTP_WARNPIPTN,        "Warning Tone (PIP tone)"},
	{ RTP_MF0,              "MF 0"},
	{ RTP_MF1,              "MF 1"},
	{ RTP_MF2,              "MF 2"},
	{ RTP_MF3,              "MF 3"},
	{ RTP_MF4,              "MF 4"},
	{ RTP_MF5,              "MF 5"},
	{ RTP_MF6,              "MF 6"},
	{ RTP_MF7,              "MF 7"},
	{ RTP_MF8,              "MF 8"},
	{ RTP_MF9,              "MF 9"},
	{ RTP_K0,               "MF K0 or KP (start-of-pulsing)"},
	{ RTP_K1,               "MF K1"},
	{ RTP_K2,               "MF K2"},
	{ RTP_S0,               "MF S0 to ST (end-of-pulsing)"},
	{ RTP_S1,               "MF S1"},
	{ RTP_S3,               "MF S3"},
	{ RTP_WINK,             "Wink"},
	{ RTP_WINKOFF,          "Wink off"},
	{ RTP_INCSEIZ,          "Incoming seizure"},
	{ RTP_SEIZURE,          "Seizure"},
	{ RTP_UNSEIZE,          "Unseize circuit"},
	{ RTP_COT,              "Continuity test"},
	{ RTP_DEFCOT,           "Default continuity tone"},
	{ RTP_COTTONE,          "Continuity tone (single tone)"},
	{ RTP_COTSEND,          "Continuity test send"},
	{ RTP_COTVERFD,         "Continuity verified"},
	{ RTP_LOOPBACK,         "Loopback"},
	{ RTP_MWATTTONE,        "Old milliwatt tone (1000 Hz)"},
	{ RTP_NEWMWATTTN,       "New milliwatt tone (1004 Hz)"},
	{ 0,               NULL },
};

struct _rtp_event_info {
	guint8      info_rtp_evt;
	guint32		info_setup_frame_num; /* the frame num of the packet that set this RTP connection */
	gboolean	info_end;
};

