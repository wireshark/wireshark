/* packet-rtp-events.c
 *
 * Routines for RFC 2833 RTP Events dissection
 * Copyright 2003, Kevin A. Noll <knoll[AT]poss.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Ref https://tools.ietf.org/html/rfc4733
 */

/*
 * This dissector tries to dissect RTP Events.
 *
 * Cisco NSE is now supported, additions by
 *                Gonzalo Salgueiro <gsalguei@cisco.com>
 *          Chidambaram Arunachalam <carunach@cisco.com>
 * Copyright 2008, Cisco Systems, Inc.
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

#include "packet-rtp-events.h"
#include "packet-rtp.h"
#include <epan/tap.h>

void proto_register_rtp_events(void);
void proto_reg_handoff_rtp_events(void);

/* 101 for RTP Event, 100 for Cisco NSE */
#define RTP_EVENT_DEFAULT_PT_RANGE "100-101"

/* RTP Event Fields */

static int proto_rtp_events = -1;
static int rtp_event_tap = -1;

static int hf_rtp_events_event = -1;	/* one byte */
static int hf_rtp_events_end = -1;	/* one bit */
static int hf_rtp_events_reserved = -1; /* one bit */
static int hf_rtp_events_volume = -1;	/* six bits */
static int hf_rtp_events_duration = -1; /* sixteen bits */


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

#define RTP_CISCO_NSE_FAX_PASSTHROUGH_IND    192
#define RTP_CISCO_NSE_MODEM_PASSTHROUGH_IND  193
#define RTP_CISCO_NSE_VOICE_MODE_IND         194
#define RTP_CISCO_NSE_MODEM_RELAY_CAP_IND    199
#define RTP_CISCO_NSE_FAX_RELAY_IND          200
#define RTP_CISCO_NSE_ACK                    201
#define RTP_CISCO_NSE_NACK                   202
#define RTP_CISCO_NSE_MODEM_RELAY_IND        203

/* https://www.iana.org/assignments/audio-telephone-event-registry/audio-telephone-event-registry.xml */
static const value_string rtp_event_type_values[] =
{
    { RTP_DTMF_0,                   "DTMF Zero 0" },
    { RTP_DTMF_1,                   "DTMF One 1" },
    { RTP_DTMF_2,                   "DTMF Two 2" },
    { RTP_DTMF_3,                   "DTMF Three 3" },
    { RTP_DTMF_4,                   "DTMF Four 4" },
    { RTP_DTMF_5,                   "DTMF Five 5" },
    { RTP_DTMF_6,                   "DTMF Six 6" },
    { RTP_DTMF_7,                   "DTMF Seven 7" },
    { RTP_DTMF_8,                   "DTMF Eight 8" },
    { RTP_DTMF_9,                   "DTMF Nine 9" },
    { RTP_DTMF_STAR,                "DTMF Star *" },
    { RTP_DTMF_POUND,               "DTMF Pound #" },
    { RTP_DTMF_A,                   "DTMF A" },
    { RTP_DTMF_B,                   "DTMF B" },
    { RTP_DTMF_C,                   "DTMF C" },
    { RTP_DTMF_D,                   "DTMF D" },
    { RTP_DTMF_FLASH,               "Flash" },
    /* 17-22    Unassigned*/
    { 23,                           "CRdSeg: second segment of V.8 bis CRd signal" }, // [RFC4734]
    { 24,                           "CReSeg : second segment of V.8 bis CRe signal" }, // [RFC4734]
    { 25,                           "MRdSeg : second segment of V.8 bis MRd signal" }, // [RFC4734]
    { 26,                           "MReSeg : second segment of V.8 bis MRe signal" }, // [RFC4734]
    { 27,                           "V32AC : A pattern of bits modulated at 4800 bits / s, emitted by a V.32 / V.32bis answering terminal upon detection of the AA pattern." }, // [RFC4734]
    { 28,                           "V8bISeg : first segment of initiating V.8 bis signal" }, // [RFC4734]
    { 29,                           "V8bRSeg : first segment of responding V.8 bis signal" }, // [RFC4734]
    { 30,                           "V21L300 : 300 bits / s low channel V.21 indication" }, // [RFC4734]
    { 31,                           "V21H300 : 300 bits / s high channel V.21 indication" }, // [RFC4734]
    { RTP_ANS,                      "Fax ANS"},
    { RTP_ANSREV,                   "Fax /ANS"},
    { RTP_ANSAM,                    "Fax ANSam"},
    { RTP_ANSAMREV,                 "Fax /ANSam"},
    { RTP_CNG,                      "Fax CNG"},
    { RTP_V21C1B0,                  "V.21 channel 1, 0 bit"},
    { RTP_V21C1B1,                  "V.21 channel 1, 1 bit"},
    { RTP_V21C2B0,                  "V.21 channel 2, 0 bit"},
    { RTP_V21C2B1,                  "V.21 channel 2, 1 bit"},
    { RTP_CRDI,                     "Fax CRdi"},
    { RTP_CRDR,                     "Fax CRdr"},
    { RTP_CRE,                      "Fax CRe"},
    { RTP_ESI,                      "Fax ESi"},
    { RTP_ESR,                      "Fax ESr"},
    { RTP_MRDI,                     "Fax MRdi"},
    { RTP_MRDR,                     "Fax MRdr"},
    { RTP_MRE,                      "Fax MRe"},
    { RTP_CT,                       "Fax CT"},
    /* 50-51    Unassigned*/
    { 52,                           "ANS2225: 2225 Hz indication for text telephony" }, // [RFC4734]
    { 53,                           "CI(V.8 Call Indicator signal preamble)" }, // [RFC4734]
    { 54,                           "V.21 preamble flag(T.30)" }, // [RFC4734]
    { 55,                           "V21L110 : 110 bits / s V.21 indication for text telephony" }, // [RFC4734]
    { 56,                           "B103L300 : Bell 103 low channel indication for text telephony" }, // [RFC4734]
    { 57,                           "V23Main : V.23 main channel indication for text telephony" }, // [RFC4734]
    { 58,                           "V23Back : V.23 back channel indication for text telephony" }, // [RFC4734]
    { 59,                           "Baud4545 : 45.45 bits / s Baudot indication for text telephony" }, // [RFC4734]
    { 60,                           "Baud50 : 50 bits / s Baudot indication for text telephony" }, // [RFC4734]
    { 61,                           "VBDGen : Tone patterns indicative of use of an unidentified modem type" }, // [RFC4734]
    { 62,                           "XCIMark : A pattern of bits modulated in the V.23 main channel, emitted by a V.18 calling terminal" }, // [RFC4734]
    { 63,                           "V32AA : A pattern of bits modulated at 4800 bits / s, emitted by a V.32 / V.23bis calling terminal" }, // [RFC4734]
    { RTP_OFFHOOK,                  "Off Hook"},
    { RTP_ONHOOK,                   "On Hook"},
    { RTP_DIALTONE,                 "Dial tone"},
    { RTP_INTDT,                    "PABX internal dial tone"},
    { RTP_SPCDT,                    "Special dial tone"},
    { RTP_2NDDT,                    "Second dial tone"},
    { RTP_RGTONE,                   "Ringing tone"},
    { RTP_SPRGTONE,                  "Special ringing tone"},
    { RTP_BUSYTONE,                  "Busy tone"},
    { RTP_CNGTONE,                   "Congestion tone"},
    { RTP_SPINFOTN,                  "Special information tone"},
    { RTP_CMFTTONE,                  "Comfort tone"},
    { RTP_HOLDTONE,                  "Hold tone"},
    { RTP_RECTONE,                   "Record tone"},
    { RTP_CLRWTTONE,                 "Caller waiting tone"},
    { RTP_CWTONE,                    "Call waiting tone"},
    { RTP_PAYTONE,                   "Pay tone"},
    { RTP_POSINDTONE,                "Positive indication tone"},
    { RTP_NEGINDTONE,                "Negative indication tone"},
    { RTP_WARNTONE,                  "Warning tone"},
    { RTP_INTRTONE,                  "Intrusion tone"},
    { RTP_CALLCDTONE,                "Calling card service tone"},
    { RTP_PAYPHONE,                  "Payphone recognition tone"},
    { RTP_CAS,                       "CPE alerting signal (CAS)"},
    { RTP_OFFHKWARN,                 "Off-hook warning tone"},
    { RTP_RING,                      "Ring"},
    { RTP_ACCPTTONE,                 "Acceptance tone"},
    { RTP_CONFIRMTN,                 "Confirmation tone"},
    { RTP_DLTNRECALL,                "Dial tone, recall"},
    { RTP_END3WAYTN,                 "End of three party service tone"},
    { RTP_FACTONE,                   "Facilities tone"},
    { RTP_LNLOCKTN,                  "Line lockout tone"},
    { RTP_NUMUNOBT,                  "Number unobtainable tone"},
    { RTP_OFFERGTONE,                "Offering tone"},
    { RTP_PERMSIGTN,                 "Permanent signal tone"},
    { RTP_PREEMPTTN,                 "Preemption tone"},
    { RTP_QUETONE,                   "Queue tone"},
    { RTP_REFUSALTN,                 "Refusal tone"},
    { RTP_ROUTETONE,                 "Route tone"},
    { RTP_VALIDTONE,                 "Valid tone"},
    { RTP_WAITGTONE,                 "Waiting tone"},
    { RTP_WARNEOPTN,                 "Warning tone (end of period)"},
    { RTP_WARNPIPTN,                 "Warning Tone (PIP tone)"},
    { 115,                           "North American SIT Segment 1 Low" }, // [GR - 674]
    { 116,                           "North American SIT Segment 1 High" }, // [GR - 674]
    { 117,                           "North American SIT Segment 2 Low" }, // [GR - 674]
    { 118,                           "North American SIT Segment 2 High" }, // [GR - 674]
    { 119,                           "North American SIT Segment 3" }, // [GR - 674]
    { 120,                           "North American Coin Deposit" }, // [GR - 506]
    { 121,                           "Continuity check - tone" }, // [RFC5244]
    { 122,                           "Continuity verify - tone" }, // [RFC5244]
    { 123,                           "MF Code 11 (SS No. 5) or KP3P / ST3P(R1) or North American Ringback" }, // [GR-506]
    { 124,                           "MF KP(SS No. 5) or KP1(R1) or North American Coin Return" }, // [GR-506]
    { 125,                           "MF KP2(SS No. 5) or KP2P / ST2P(R1)" }, // [RFC5244]
    { 126,                           "MF ST(SS No. 5 and R1) or North American Coin Collect / Operator Released" }, // [GR-506]
    { 127,                           "MF Code 12 (SS No. 5) or KP'/STP (R1)" },
    { RTP_MF0,                       "MF 0"},
    { RTP_MF1,                       "MF 1"},
    { RTP_MF2,                       "MF 2"},
    { RTP_MF3,                       "MF 3"},
    { RTP_MF4,                       "MF 4"},
    { RTP_MF5,                       "MF 5"},
    { RTP_MF6,                       "MF 6"},
    { RTP_MF7,                       "MF 7"},
    { RTP_MF8,                       "MF 8"},
    { RTP_MF9,                       "MF 9"},
    { RTP_K0,                        "MF K0 or KP (start-of-pulsing)"},
    { RTP_K1,                        "MF K1"},
    { RTP_K2,                        "MF K2"},
    { RTP_S0,                        "MF S0 to ST (end-of-pulsing)"},
    { RTP_S1,                        "MF S1"},
    { RTP_S3,                        "MF S3"},
    { 144,                           "ABCD signalling state '0000'" }, // [RFC5244]
    { 145,                           "ABCD signalling state '0001'" }, // [RFC5244]
    { 146,                           "ABCD signalling state '0010'" }, // [RFC5244]
    { 147,                           "ABCD signalling state '0011'" }, // [RFC5244]
    { 148,                           "ABCD signalling state '0100'" }, // [RFC5244]
    { 149,                           "ABCD signalling state '0101'" }, // [RFC5244]
    { 150,                           "ABCD signalling state '0110'" }, // [RFC5244]
    { 151,                           "ABCD signalling state '0111'" }, // [RFC5244]
    { 152,                           "ABCD signalling state '1000'" }, // [RFC5244]
    { 153,                           "ABCD signalling state '1001'" }, // [RFC5244]
    { 154,                           "ABCD signalling state '1010'" }, // [RFC5244]
    { 155,                           "ABCD signalling state '1011'" }, // [RFC5244]
    { 156,                           "ABCD signalling state '1100'" }, // [RFC5244]
    { 157,                           "ABCD signalling state '1101'" }, // [RFC5244]
    { 158,                           "ABCD signalling state '1110'" }, // [RFC5244]
    { 159,                           "ABCD signalling state '1111'" }, // [RFC5244]
    { RTP_WINK,                      "Wink"},
    { RTP_WINKOFF,                   "Wink off"},
    { RTP_INCSEIZ,                   "Incoming seizure"},
    { RTP_SEIZURE,                   "Seizure"},
    { RTP_UNSEIZE,                   "Unseize circuit"},
    { RTP_COT,                       "Continuity test"},
    { RTP_DEFCOT,                    "Default continuity tone"},
    { RTP_COTTONE,                   "Continuity tone (single tone)"},
    { RTP_COTSEND,                   "Continuity test send"},
    { RTP_COTVERFD,                  "Continuity verified"},
    { RTP_LOOPBACK,                  "Loopback"},
    { RTP_MWATTTONE,                 "Old milliwatt tone (1000 Hz)"},
    { RTP_NEWMWATTTN,                "New milliwatt tone (1004 Hz)"},
    { 174,                           "Metering pulse" }, // [RFC5244]
    { 175,                           "Trunk unavailable" }, // [RFC5244]
    { 176,                           "MFC forward signal 1" }, // [RFC5244]
    { 177,                           "MFC forward signal 2" }, // [RFC5244]
    { 178,                           "MFC forward signal 3" }, // [RFC5244]
    { 179,                           "MFC forward signal 4" }, // [RFC5244]
    { 180,                           "MFC forward signal 5" }, // [RFC5244]
    { 181,                           "MFC forward signal 6" }, // [RFC5244]
    { 182,                           "MFC forward signal 7" }, // [RFC5244]
    { 183,                           "MFC forward signal 8" }, // [RFC5244]
    { 184,                           "MFC forward signal 9" }, // [RFC5244]
    { 185,                           "MFC forward signal 10" }, // [RFC5244]
    { 186,                           "MFC forward signal 11" }, // [RFC5244]
    { 187,                           "MFC forward signal 12" }, // [RFC5244]
    { 188,                           "MFC forward signal 13" }, // [RFC5244]
    { 189,                           "MFC forward signal 14" }, // [RFC5244]
    { 190,                           "MFC forward signal 15" }, // [RFC5244]
    { 191,                           "MFC backward signal 1" }, // [RFC5244]
    { 192,                           "MFC backward signal 2" }, // [RFC5244]

        //193	MFC backward signal 3[RFC5244]
        //194	MFC backward signal 4[RFC5244]
        //195	MFC backward signal 5[RFC5244]
        //196	MFC backward signal 6[RFC5244]
        //197	MFC backward signal 7[RFC5244]
        //198	MFC backward signal 8[RFC5244]
        //199	MFC backward signal 9[RFC5244]
        //200	MFC backward signal 10[RFC5244]
        //201	MFC backward signal 11[RFC5244]
        //202	MFC backward signal 12[RFC5244]
        //203	MFC backward signal 13[RFC5244]
        //204	MFC backward signal 14[RFC5244]
        //205	MFC backward signal 15[RFC5244]
        //206	A bit signalling state '0'[RFC5244]
        //207	A bit signalling state '1'[RFC5244]
        //208	AB bit signalling state '00'[RFC5244]
        //209	AB bit signalling state '01'[RFC5244]
        //210	AB bit signalling state '10'[RFC5244]
        //211	AB bit signalling state '11'	[RFC5244]
    { RTP_CISCO_NSE_FAX_PASSTHROUGH_IND,   "Cisco NSE: Shift to voiceband data mode"},
    { RTP_CISCO_NSE_MODEM_PASSTHROUGH_IND, "Cisco NSE: Disable echo cancellation"},
    { RTP_CISCO_NSE_VOICE_MODE_IND,        "Cisco NSE: Shift to voice mode"},
    { RTP_CISCO_NSE_MODEM_RELAY_CAP_IND,   "Cisco NSE: Advertise Modem relay capability"},
    { RTP_CISCO_NSE_FAX_RELAY_IND,         "Cisco NSE: Shift to fax relay mode"},
    { RTP_CISCO_NSE_ACK,                   "Positive acknowledgement of Cisco NSE"},
    { RTP_CISCO_NSE_NACK,                  "Negative acknowledgement of Cisco NSE"},
    { RTP_CISCO_NSE_MODEM_RELAY_IND ,      "Cisco NSE: Shift to modem relay mode"},
    { 0,               NULL },
};
value_string_ext rtp_event_type_values_ext = VALUE_STRING_EXT_INIT(rtp_event_type_values);

/* RTP Events fields defining a subtree */

static gint ett_rtp_events           = -1;

static dissector_handle_t rtp_events_handle;

static struct _rtp_event_info rtp_event_info;

static int
dissect_rtp_events( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ )
{
	proto_item   *ti;
	proto_tree   *rtp_events_tree;
	unsigned int  offset = 0;

	struct _rtp_conversation_info *p_conv_data;

	guint8 rtp_evt;
	guint8 octet;
	static int * const events[] = {
		&hf_rtp_events_end,
		&hf_rtp_events_reserved,
		&hf_rtp_events_volume,
		NULL
	};

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP EVENT");
	col_clear(pinfo->cinfo, COL_INFO);


	/* Get event fields */

	rtp_evt = tvb_get_guint8(tvb, offset );

	/* get tap info */
	rtp_event_info.info_rtp_evt = rtp_evt;

	p_conv_data = (struct _rtp_conversation_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_get_id_by_filter_name("rtp"), 0);
	if (p_conv_data)
		rtp_event_info.info_setup_frame_num = p_conv_data->frame_number;
	else
		rtp_event_info.info_setup_frame_num = 0;


	col_add_fstr( pinfo->cinfo, COL_INFO,
		"Payload type=RTP Event, %s",
		val_to_str_ext( rtp_evt, &rtp_event_type_values_ext, "Unknown (%u)" ));

	ti = proto_tree_add_item( tree, proto_rtp_events, tvb, offset, -1, ENC_NA );
	rtp_events_tree = proto_item_add_subtree( ti, ett_rtp_events );

	proto_tree_add_uint ( rtp_events_tree, hf_rtp_events_event, tvb, offset, 1, rtp_evt);
	offset++;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_bitmask_list(rtp_events_tree, tvb, offset, 1, events, ENC_NA);
	offset++;

	/* The duration field indicates the duration of the event or segment
	 * being reported, in timestamp units.
	 */
	rtp_event_info.info_duration = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item ( rtp_events_tree, hf_rtp_events_duration, tvb, offset, 2, ENC_BIG_ENDIAN);

	/* set the end info for the tap */
	if (octet & 0x80)
	{
		rtp_event_info.info_end = TRUE;
	} else
	{
		rtp_event_info.info_end = FALSE;
	}

	/* Make end-of-event packets obvious in the info column */
	if ((octet & 0x80))
	{
		col_append_str(pinfo->cinfo, COL_INFO, " (end)");
	}

	tap_queue_packet(rtp_event_tap, pinfo, &rtp_event_info);
	return tvb_captured_length(tvb);
}


void
proto_register_rtp_events(void)
{

	module_t *rtp_events_module;

	static hf_register_info hf[] =
	{
		{
			&hf_rtp_events_event,
			{
				"Event ID",
				"rtpevent.event_id",
				FT_UINT8,
				BASE_DEC | BASE_EXT_STRING,
				&rtp_event_type_values_ext,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_events_end,
			{
				"End of Event",
				"rtpevent.end_of_event",
				FT_BOOLEAN,
				8,
				NULL,
				0x80,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_events_reserved,
			{
				"Reserved",
				"rtpevent.reserved",
				FT_BOOLEAN,
				8,
				NULL,
				0x40,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_events_volume,
			{
				"Volume",
				"rtpevent.volume",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x3F,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_events_duration,
			{
				"Event Duration",
				"rtpevent.duration",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

	};

	static gint *ett[] =
	{
		&ett_rtp_events,
	};


	proto_rtp_events = proto_register_protocol("RFC 2833 RTP Event", "RTP Event", "rtpevent");
	proto_register_field_array(proto_rtp_events, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));


	/* Register preferences */
	rtp_events_module = prefs_register_protocol (proto_rtp_events, NULL);
	prefs_register_obsolete_preference(rtp_events_module, "event_payload_type_value");
	prefs_register_obsolete_preference(rtp_events_module, "cisco_nse_payload_type_value");

	rtp_events_handle = register_dissector("rtpevent", dissect_rtp_events, proto_rtp_events);
	rtp_event_tap = register_tap("rtpevent");
}



void
proto_reg_handoff_rtp_events(void)
{
	dissector_add_string("rtp_dyn_payload_type", "telephone-event", rtp_events_handle);
	dissector_add_string("rtp_dyn_payload_type", "X-NSE", rtp_events_handle);
	dissector_add_uint_range_with_preference("rtp.pt", RTP_EVENT_DEFAULT_PT_RANGE, rtp_events_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
