/* packet-rtp-midi.c
 *
 * Routines for RFC 4695/6295 RTP-MIDI dissection
 * Copyright 2006-2012, Tobias Erichsen <t.erichsen@gmx.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>'
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * RTP-MIDI ( RFC 4695/6295 ) is a payload type for transmitting MIDI-data over
 * RTP-packets.  This payload type can be used on an RTP-conversation that has been
 * established either by means of a session establishment-protocol like SIP or
 * something more lightweight like the Apple network-midi session establishment.
 *
 * This dissector is built based on the RTP-MIDI-specification RFC 4695 from
 * August 13, 2008, the superseding version RFC 6295 and the MIDI-specification 96.1
 *
 * Here are some links:
 *
 * http://www.cs.berkeley.edu/~lazzaro/rtpmidi/
 * https://tools.ietf.org/html/rfc4695
 * https://tools.ietf.org/html/rfc6295
 * http://www.midi.org/
 *
 * 2012-02-24
 * - Initial version of dissector
 *
 * Open topics:
 * - reassembly of large sysex-fields going over multiple RTP-packets - this would be a major task, though!
 * - MIDI Show-Control
 * - MIDI Machine-Control
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include <epan/prefs.h>
#include <data-midi-sysex-id.h>
#include "packet-midi.h"

void proto_register_rtp_midi(void);

/* Definitions for protocol name during dissector-register */
#define RTP_MIDI_DISSECTOR_NAME						"RFC 4695/6295 RTP-MIDI"
#define RTP_MIDI_DISSECTOR_SHORTNAME					"RTP-MIDI"
#define RTP_MIDI_DISSECTOR_ABBREVIATION					"rtpmidi"

#define RTP_MIDI_NO_RUNNING_STATUS					0xffff

#define RTP_MIDI_TREE_NAME_COMMAND					"Command Section"
#define RTP_MIDI_TREE_NAME_JOURNAL					"Journal Section"
#define RTP_MIDI_TREE_NAME_SYSTEM_JOURNAL				"System-Journal"
#define RTP_MIDI_TREE_NAME_SYSTEM_CHAPTERS				"System-Chapters"
#define RTP_MIDI_TREE_NAME_SJ_CHAPTER_D_FIELD_J				"System Common 0xF4"
#define RTP_MIDI_TREE_NAME_SJ_CHAPTER_D_FIELD_K				"System Common 0xF5"
#define RTP_MIDI_TREE_NAME_SJ_CHAPTER_D_FIELD_Y				"System Common 0xF9"
#define RTP_MIDI_TREE_NAME_SJ_CHAPTER_D_FIELD_Z				"System Common 0xFD"
#define RTP_MIDI_TREE_NAME_SJ_CHAPTER_Q					"Sequencer State Commands"
#define RTP_MIDI_TREE_NAME_SJ_CHAPTER_F					"MIDI Time Code Tape Position"
#define RTP_MIDI_TREE_NAME_SJ_CHAPTER_X					"System Exclusive"
#define RTP_MIDI_TREE_NAME_SJ_CHAPTER_X_DATA				"Data field (sysex commands)"
#define RTP_MIDI_TREE_NAME_SJ_CHAPTER_X_INVALID_DATA			"Data field (invalid sysex commands)"
#define RTP_MIDI_TREE_NAME_CHANNEL_JOURNAL				"Channel-Journal"
#define RTP_MIDI_TREE_NAME_CHANNEL_CHAPTERS				"Channel-Chapters"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_P					"Program Change"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_C					"Control Change"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_C_LOGLIST				"Log List"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_C_LOGITEM				"Log Item"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_M					"Parameter System"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_M_LOGLIST				"Log List"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_M_LOGITEM				"Log Item"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_M_LOG_COUNT			"Count"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_W					"Pitch Wheel"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_N					"Note on/off"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_N_LOGLIST				"Log List"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_N_LOGITEM				"Note On"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_N_OCTETS				"Offbit Octets"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_E					"Note Command Extras"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_E_LOGLIST				"Log List"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_E_LOGITEM1			"Note Off"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_E_LOGITEM2			"Note On/Off"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_A					"Poly Aftertouch"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_A_LOGLIST				"Log List"
#define RTP_MIDI_TREE_NAME_CJ_CHAPTER_A_LOGITEM				"Pressure"

/* used to mask the most significant bit, which flags the start of a new midi-command! */
#define RTP_MIDI_COMMAND_STATUS_FLAG					0x80

/* used to mask the lower 7 bits of the single octets that make up the delta-time */
#define RTP_MIDI_DELTA_TIME_OCTET_MASK					0x7f
/* used to mask the most significant bit, which flags the extension of the delta-time */
#define RTP_MIDI_DELTA_TIME_EXTENSION					0x80

#define RTP_MIDI_CS_FLAG_B						0x80
#define RTP_MIDI_CS_FLAG_J						0x40
#define RTP_MIDI_CS_FLAG_Z						0x20
#define RTP_MIDI_CS_FLAG_P						0x10
#define RTP_MIDI_CS_MASK_SHORTLEN					0x0f
#define RTP_MIDI_CS_MASK_LONGLEN					0x0fff

#define RTP_MIDI_CJ_CHAPTER_M_FLAG_J					0x80
#define RTP_MIDI_CJ_CHAPTER_M_FLAG_K					0x40
#define RTP_MIDI_CJ_CHAPTER_M_FLAG_L					0x20
#define RTP_MIDI_CJ_CHAPTER_M_FLAG_M					0x10
#define RTP_MIDI_CJ_CHAPTER_M_FLAG_N					0x08
#define RTP_MIDI_CJ_CHAPTER_M_FLAG_T					0x04
#define RTP_MIDI_CJ_CHAPTER_M_FLAG_V					0x02
#define RTP_MIDI_CJ_CHAPTER_M_FLAG_R					0x01

#define RTP_MIDI_JS_FLAG_S				0x80
#define RTP_MIDI_JS_FLAG_Y				0x40
#define RTP_MIDI_JS_FLAG_A				0x20
#define RTP_MIDI_JS_FLAG_H				0x10
#define RTP_MIDI_JS_MASK_TOTALCHANNELS			0x0f

#define RTP_MIDI_SJ_FLAG_S				0x8000
#define RTP_MIDI_SJ_FLAG_D				0x4000
#define RTP_MIDI_SJ_FLAG_V				0x2000
#define RTP_MIDI_SJ_FLAG_Q				0x1000
#define RTP_MIDI_SJ_FLAG_F				0x0800
#define RTP_MIDI_SJ_FLAG_X				0x0400
#define RTP_MIDI_SJ_MASK_LENGTH				0x03ff

#define RTP_MIDI_SJ_CHAPTER_D_FLAG_S			0x80
#define RTP_MIDI_SJ_CHAPTER_D_FLAG_B			0x40
#define RTP_MIDI_SJ_CHAPTER_D_FLAG_G			0x20
#define RTP_MIDI_SJ_CHAPTER_D_FLAG_H			0x10
#define RTP_MIDI_SJ_CHAPTER_D_FLAG_J			0x08
#define RTP_MIDI_SJ_CHAPTER_D_FLAG_K			0x04
#define RTP_MIDI_SJ_CHAPTER_D_FLAG_Y			0x02
#define RTP_MIDI_SJ_CHAPTER_D_FLAG_Z			0x01

#define RTP_MIDI_SJ_CHAPTER_D_RESET_FLAG_S		0x80
#define RTP_MIDI_SJ_CHAPTER_D_RESET_COUNT		0x7f
#define RTP_MIDI_SJ_CHAPTER_D_TUNE_FLAG_S		0x80
#define RTP_MIDI_SJ_CHAPTER_D_TUNE_COUNT		0x7f
#define RTP_MIDI_SJ_CHAPTER_D_SONG_SEL_FLAG_S		0x80
#define RTP_MIDI_SJ_CHAPTER_D_SONG_SEL_VALUE		0x7f

#define RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_S		0x8000
#define RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_C		0x4000
#define RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_V		0x2000
#define RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_L		0x1000
#define RTP_MIDI_SJ_CHAPTER_D_SYSCOM_MASK_DSZ		0x0c00
#define RTP_MIDI_SJ_CHAPTER_D_SYSCOM_MASK_LENGTH	0x03ff
#define RTP_MIDI_SJ_CHAPTER_D_SYSCOM_MASK_COUNT		0xff

#define RTP_MIDI_SJ_CHAPTER_D_SYSREAL_FLAG_S		0x80
#define RTP_MIDI_SJ_CHAPTER_D_SYSREAL_FLAG_C		0x40
#define RTP_MIDI_SJ_CHAPTER_D_SYSREAL_FLAG_L		0x20
#define RTP_MIDI_SJ_CHAPTER_D_SYSREAL_MASK_LENGTH	0x1f
#define RTP_MIDI_SJ_CHAPTER_D_SYSREAL_MASK_COUNT	0xff

#define RTP_MIDI_SJ_CHAPTER_Q_FLAG_S			0x80
#define RTP_MIDI_SJ_CHAPTER_Q_FLAG_N			0x40
#define RTP_MIDI_SJ_CHAPTER_Q_FLAG_D			0x20
#define RTP_MIDI_SJ_CHAPTER_Q_FLAG_C			0x10
#define RTP_MIDI_SJ_CHAPTER_Q_FLAG_T			0x80
#define RTP_MIDI_SJ_CHAPTER_Q_MASK_TOP			0x07
#define RTP_MIDI_SJ_CHAPTER_Q_MASK_CLOCK		0x07ffff
#define RTP_MIDI_SJ_CHAPTER_Q_MASK_TIMETOOLS		0xffffff

#define RTP_MIDI_SJ_CHAPTER_F_FLAG_S			0x80
#define RTP_MIDI_SJ_CHAPTER_F_FLAG_C			0x40
#define RTP_MIDI_SJ_CHAPTER_F_FLAG_P			0x20
#define RTP_MIDI_SJ_CHAPTER_F_FLAG_Q			0x10
#define RTP_MIDI_SJ_CHAPTER_F_FLAG_D			0x08
#define RTP_MIDI_SJ_CHAPTER_F_MASK_POINT		0x07
#define RTP_MIDI_SJ_CHAPTER_F_MASK_MT0			0xf0000000
#define RTP_MIDI_SJ_CHAPTER_F_MASK_MT1			0x0f000000
#define RTP_MIDI_SJ_CHAPTER_F_MASK_MT2			0x00f00000
#define RTP_MIDI_SJ_CHAPTER_F_MASK_MT3			0x000f0000
#define RTP_MIDI_SJ_CHAPTER_F_MASK_MT4			0x0000f000
#define RTP_MIDI_SJ_CHAPTER_F_MASK_MT5			0x00000f00
#define RTP_MIDI_SJ_CHAPTER_F_MASK_MT6			0x000000f0
#define RTP_MIDI_SJ_CHAPTER_F_MASK_MT7			0x0000000f
#define RTP_MIDI_SJ_CHAPTER_F_MASK_HR			0xff000000
#define RTP_MIDI_SJ_CHAPTER_F_MASK_MN			0x00ff0000
#define RTP_MIDI_SJ_CHAPTER_F_MASK_SC			0x0000ff00
#define RTP_MIDI_SJ_CHAPTER_F_MASK_FR			0x000000ff

#define RTP_MIDI_SJ_CHAPTER_X_FLAG_S			0x80
#define RTP_MIDI_SJ_CHAPTER_X_FLAG_T			0x40
#define RTP_MIDI_SJ_CHAPTER_X_FLAG_C			0x20
#define RTP_MIDI_SJ_CHAPTER_X_FLAG_F			0x10
#define RTP_MIDI_SJ_CHAPTER_X_FLAG_D			0x08
#define RTP_MIDI_SJ_CHAPTER_X_FLAG_L			0x04
#define RTP_MIDI_SJ_CHAPTER_X_MASK_STA			0x03
#define RTP_MIDI_SJ_CHAPTER_X_MASK_TCOUNT		0x0
#define RTP_MIDI_SJ_CHAPTER_X_MASK_COUNT		0x0

#define RTP_MIDI_CJ_FLAG_S				0x800000
#define RTP_MIDI_CJ_FLAG_H				0x040000
#define RTP_MIDI_CJ_FLAG_P				0x000080
#define RTP_MIDI_CJ_FLAG_C				0x000040
#define RTP_MIDI_CJ_FLAG_M				0x000020
#define RTP_MIDI_CJ_FLAG_W				0x000010
#define RTP_MIDI_CJ_FLAG_N				0x000008
#define RTP_MIDI_CJ_FLAG_E				0x000004
#define RTP_MIDI_CJ_FLAG_T				0x000002
#define RTP_MIDI_CJ_FLAG_A				0x000001
#define RTP_MIDI_CJ_MASK_LENGTH				0x03ff00
#define RTP_MIDI_CJ_MASK_CHANNEL			0x780000
#define RTP_MIDI_CJ_CHANNEL_SHIFT			19

#define RTP_MIDI_CJ_CHAPTER_M_MASK_LENGTH		0x3f

#define RTP_MIDI_CJ_CHAPTER_N_MASK_LENGTH		0x7f00
#define RTP_MIDI_CJ_CHAPTER_N_MASK_LOW			0x00f0
#define RTP_MIDI_CJ_CHAPTER_N_MASK_HIGH			0x000f

#define RTP_MIDI_CJ_CHAPTER_E_MASK_LENGTH		0x7f
#define RTP_MIDI_CJ_CHAPTER_A_MASK_LENGTH		0x7f





static const char rtp_midi_unknown_value_dec[] =			"unknown value: %d";
static const char rtp_midi_unknown_value_hex[] =			"unknown value: 0x%x";




static const value_string rtp_midi_js_tot_channels[] = {
	{ 0,								"1 channel" },
	{ 1,								"2 channels" },
	{ 2,								"3 channels" },
	{ 3,								"4 channels" },
	{ 4,								"5 channels" },
	{ 5,								"6 channels" },
	{ 6,								"7 channels" },
	{ 7,								"8 channels" },
	{ 8,								"9 channels" },
	{ 9,								"10 channels" },
	{ 10,								"11 channels" },
	{ 11,								"12 channels" },
	{ 12,								"13 channels" },
	{ 13,								"14 channels" },
	{ 14,								"15 channels" },
	{ 15,								"16 channels" },
	{ 0,								NULL }
};



static const value_string rtp_midi_sj_chapter_d_syscom_dsz_values[] = {
	{ 0,								"Command has 0 octets" },
	{ 1,								"Command has 1 octet" },
	{ 2,								"Command has 2 octets" },
	{ 3,								"Command has 3 or more octets" },
	{ 0,								NULL }
};

static const true_false_string rtp_midi_cs_flag_b= {
	"Long Header: 2 octets",
	"Short Header: 1 octet"
};

static const true_false_string rtp_midi_cs_flag_j= {
	"Journal present",
	"No Journal present"
};

static const true_false_string rtp_midi_cs_flag_z= {
	"Delta-Time present for first MIDI-command",
	"No Delta-Time for first MIDI-command"
};

static const true_false_string rtp_midi_cs_flag_p= {
	"Status byte was NOT present in original MIDI-command",
	"Status byte was present in original MIDI-command"
};

static const true_false_string rtp_midi_js_flag_y = {
	"System-journal present",
	"System-journal NOT present"
};

static const true_false_string rtp_midi_js_flag_s = {
	"Standard journal behaviour",
	"Journal encodes data in preceding RTP-packet"
};

static const true_false_string rtp_midi_js_flag_a = {
	"Channel-journal present",
	"Channel-journal NOT present"
};

static const true_false_string rtp_midi_js_flag_h = {
	"Enhanced Encoding",
	"Standard Encoding"
};

static const true_false_string rtp_midi_sj_flag_d = {
	"Chapter D journal present",
	"Chapter D journal NOT present"
};

static const true_false_string rtp_midi_sj_flag_v = {
	"Chapter V journal present",
	"Chapter V journal NOT present"
};

static const true_false_string rtp_midi_sj_flag_q = {
	"Chapter Q journal present",
	"Chapter Q journal NOT present"
};

static const true_false_string rtp_midi_sj_flag_f = {
	"Chapter F journal present",
	"Chapter F journal NOT present"
};

static const true_false_string rtp_midi_sj_flag_x = {
	"Chapter X journal present",
	"Chapter X journal NOT present"
};

static const true_false_string rtp_midi_cj_flag_p = {
	"Chapter P journal present",
	"Chapter P journal NOT present"
};

static const true_false_string rtp_midi_cj_flag_c = {
	"Chapter C journal present",
	"Chapter C journal NOT present"
};

static const true_false_string rtp_midi_cj_flag_m = {
	"Chapter M journal present",
	"Chapter M journal NOT present"
};

static const true_false_string rtp_midi_cj_flag_w = {
	"Chapter W journal present",
	"Chapter W journal NOT present"
};

static const true_false_string rtp_midi_cj_flag_n = {
	"Chapter N journal present",
	"Chapter N journal NOT present"
};

static const true_false_string rtp_midi_cj_flag_e = {
	"Chapter E journal present",
	"Chapter E journal NOT present"
};

static const true_false_string rtp_midi_cj_flag_t = {
	"Chapter T journal present",
	"Chapter T journal NOT present"
};

static const true_false_string rtp_midi_cj_flag_a = {
	"Chapter A journal present",
	"Chapter A journal NOT present"
};

static const true_false_string rtp_midi_cj_chapter_c_flag_a = {
	"Alternative Coding",
	"Value Coding"
};

static const true_false_string rtp_midi_cj_chapter_m_flag_p = {
	"Pending field is encoded",
	"Pending field is NOT encoded"
};

static const true_false_string rtp_midi_cj_chapter_m_flag_e = {
	"Initiated transaction is in progress",
	"NO transaction in progress"
};

static const true_false_string rtp_midi_cj_chapter_m_flag_u = {
	"All parameters are RPNs",
	"Parameters may include NRPNs"
};

static const true_false_string rtp_midi_cj_chapter_m_flag_w = {
	"All parameters are NRPNs",
	"Parameters may include RPNs"
};

static const true_false_string rtp_midi_cj_chapter_m_flag_z = {
	"Only LSB parameters",
	"Parameters may have LSB & MSB"
};

static const true_false_string rtp_midi_cj_chapter_m_flag_q = {
	"Pending encodes NRPN MSB",
	"Pending encodes RPN MSB"
};

static const true_false_string rtp_midi_cj_chapter_m_log_flag_q = {
	"NRPN parameter encoded",
	"RPN parameter encoded"
};

static const true_false_string rtp_midi_cj_chapter_m_log_flag_j = {
	"ENTRY-MSB field present",
	"ENTRY-MSB field NOT present"
};

static const true_false_string rtp_midi_cj_chapter_m_log_flag_k = {
	"ENTRY-LSB field present",
	"ENTRY-LSB field NOT present"
};

static const true_false_string rtp_midi_cj_chapter_m_log_flag_l = {
	"A-Button field present",
	"A-Button field NOT present"
};

static const true_false_string rtp_midi_cj_chapter_m_log_flag_m = {
	"C-Button field present",
	"C-Button field NOT present"
};

static const true_false_string rtp_midi_cj_chapter_m_log_flag_n = {
	"Count field present",
	"Count field NOT present"
};

static const true_false_string rtp_midi_cj_chapter_m_log_flag_t = {
	"Count Tool used",
	"Count Tool NOT used"
};

static const true_false_string rtp_midi_cj_chapter_m_log_flag_v = {
	"Value Tool used",
	"Value Tool NOT used"
};

static const true_false_string rtp_midi_cj_chapter_m_log_flag_r = {
	"Reserved-Flag set",
	"Reserved-Flag NOT set"
};

static const true_false_string rtp_midi_cj_chapter_m_log_flag_x = {
	"Precedes most recent Control Change command for ctrl=121",
	"Does not precede most recent Control Change command for ctrl=121"
};

static const true_false_string rtp_midi_cj_chapter_m_log_flag_g = {
	"negative value",
	"positive value"
};

static const true_false_string rtp_midi_cj_chapter_n_log_flag_y = {
	"Execute Note-On",
	"Skip Note-On"
};

static const true_false_string rtp_midi_cj_chapter_e_log_flag_v = {
	"Encodes Note-Off velocity",
	"Encodes Note-On/Off count"
};

static const true_false_string rtp_midi_cj_chapter_a_log_flag_x = {
	"Precedes most recent Control Change command for ctrl=123-127",
	"Does not precede most recent Control Change command for ctrl=123-127"
};

static const true_false_string rtp_midi_cj_chapter_p_log_flag_x = {
	"Reset all controllers received between MSB and LSB",
	"NO Reset all controllers received between MSB and LSB"
};

static const true_false_string rtp_midi_sj_chapter_d_flag_b = {
	"Reset field present",
	"Reset field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_d_flag_g = {
	"Tune request field present",
	"Tune request field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_d_flag_h = {
	"Song select field present",
	"Song select field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_d_flag_j = {
	"Undefined system common 0xF4 field present",
	"Undefined system common 0xF4 field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_d_flag_k = {
	"Undefined system common 0xF5 field present",
	"Undefined system common 0xF5 field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_d_flag_y = {
	"Undefined system common 0xF9 field present",
	"Undefined system common 0xF9 field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_d_flag_z = {
	"Undefined system common 0xFD field present",
	"Undefined system common 0xFD field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_d_syscom_flag_c = {
	"Count field present",
	"Count field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_d_syscom_flag_v = {
	"Value field present",
	"Value field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_d_syscom_flag_l = {
	"Legal field present",
	"Legal field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_q_flag_n = {
	"Active Start / Continue",
	"NO active Start / Stop Continue"
};

static const true_false_string rtp_midi_sj_chapter_q_flag_d = {
	"Song position already reached",
	"Song position yet to be reached"
};

static const true_false_string rtp_midi_sj_chapter_q_flag_c = {
	"Clock field present",
	"Clock field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_q_flag_t = {
	"Timetools field present",
	"Timetools field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_f_flag_c = {
	"Complete field present",
	"Complete field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_f_flag_p = {
	"Partial field present",
	"Partial field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_f_flag_q = {
	"Complete field contains quarter frames",
	"Complete field contains full frame format"
};

static const true_false_string rtp_midi_sj_chapter_f_flag_d = {
	"Tape head is moving reverse",
	"Tape head is moving forward or undefined"
};

static const true_false_string rtp_midi_sj_chapter_x_flag_t = {
	"TCOUNT field present",
	"TCOUNT field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_x_flag_c = {
	"COUNT field present",
	"COUNT field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_x_flag_f = {
	"FIRST field present",
	"FIRST field NOT present"
};

static const true_false_string rtp_midi_sj_chapter_x_flag_d = {
	"DATA field present",
	"DATA field not present"
};

static const true_false_string rtp_midi_sj_chapter_x_flag_l = {
	"List Tool used",
	"Recency Tool used"
};



static int hf_rtp_midi_bflag;
static int hf_rtp_midi_jflag;
static int hf_rtp_midi_zflag;
static int hf_rtp_midi_pflag;
static int hf_rtp_midi_shortlen;
static int hf_rtp_midi_longlen;

static int hf_rtp_midi_sflag;
static int hf_rtp_midi_yflag;
static int hf_rtp_midi_aflag;
static int hf_rtp_midi_hflag;
static int hf_rtp_midi_totchan;
static int hf_rtp_midi_check_seq_num;

static int hf_rtp_midi_deltatime1;
static int hf_rtp_midi_deltatime2;
static int hf_rtp_midi_deltatime3;
static int hf_rtp_midi_deltatime4;


static int hf_rtp_midi_sysjour_toc_s;
static int hf_rtp_midi_sysjour_toc_d;
static int hf_rtp_midi_sysjour_toc_v;
static int hf_rtp_midi_sysjour_toc_q;
static int hf_rtp_midi_sysjour_toc_f;
static int hf_rtp_midi_sysjour_toc_x;
static int hf_rtp_midi_sysjour_len;

static int hf_rtp_midi_chanjour_sflag;
static int hf_rtp_midi_chanjour_chan;
static int hf_rtp_midi_chanjour_hflag;
static int hf_rtp_midi_chanjour_len;
static int hf_rtp_midi_chanjour_toc_p;
static int hf_rtp_midi_chanjour_toc_c;
static int hf_rtp_midi_chanjour_toc_m;
static int hf_rtp_midi_chanjour_toc_w;
static int hf_rtp_midi_chanjour_toc_n;
static int hf_rtp_midi_chanjour_toc_e;
static int hf_rtp_midi_chanjour_toc_t;
static int hf_rtp_midi_chanjour_toc_a;

static int hf_rtp_midi_cj_chapter_p_sflag;
static int hf_rtp_midi_cj_chapter_p_program;
static int hf_rtp_midi_cj_chapter_p_bflag;
static int hf_rtp_midi_cj_chapter_p_bank_msb;
static int hf_rtp_midi_cj_chapter_p_xflag;
static int hf_rtp_midi_cj_chapter_p_bank_lsb;

static int hf_rtp_midi_cj_chapter_c_sflag;
static int hf_rtp_midi_cj_chapter_c_length;
static int hf_rtp_midi_cj_chapter_c_number;
static int hf_rtp_midi_cj_chapter_c_aflag;
static int hf_rtp_midi_cj_chapter_c_value;
static int hf_rtp_midi_cj_chapter_c_tflag;
static int hf_rtp_midi_cj_chapter_c_alt;

static int hf_rtp_midi_cj_chapter_m_sflag;
static int hf_rtp_midi_cj_chapter_m_pflag;
static int hf_rtp_midi_cj_chapter_m_eflag;
static int hf_rtp_midi_cj_chapter_m_uflag;
static int hf_rtp_midi_cj_chapter_m_wflag;
static int hf_rtp_midi_cj_chapter_m_zflag;
static int hf_rtp_midi_cj_chapter_m_length;
static int hf_rtp_midi_cj_chapter_m_qflag;
static int hf_rtp_midi_cj_chapter_m_pending;
static int hf_rtp_midi_cj_chapter_m_log_sflag;
static int hf_rtp_midi_cj_chapter_m_log_pnum_lsb;
static int hf_rtp_midi_cj_chapter_m_log_qflag;
static int hf_rtp_midi_cj_chapter_m_log_pnum_msb;
static int hf_rtp_midi_cj_chapter_m_log_jflag;
static int hf_rtp_midi_cj_chapter_m_log_kflag;
static int hf_rtp_midi_cj_chapter_m_log_lflag;
static int hf_rtp_midi_cj_chapter_m_log_mflag;
static int hf_rtp_midi_cj_chapter_m_log_nflag;
static int hf_rtp_midi_cj_chapter_m_log_tflag;
static int hf_rtp_midi_cj_chapter_m_log_vflag;
static int hf_rtp_midi_cj_chapter_m_log_rflag;
static int hf_rtp_midi_cj_chapter_m_log_msb;
static int hf_rtp_midi_cj_chapter_m_log_msb_x;
static int hf_rtp_midi_cj_chapter_m_log_msb_entry;
static int hf_rtp_midi_cj_chapter_m_log_lsb;
static int hf_rtp_midi_cj_chapter_m_log_lsb_x;
static int hf_rtp_midi_cj_chapter_m_log_lsb_entry;
static int hf_rtp_midi_cj_chapter_m_log_a_button_g;
static int hf_rtp_midi_cj_chapter_m_log_a_button_x;
static int hf_rtp_midi_cj_chapter_m_log_a_button;
static int hf_rtp_midi_cj_chapter_m_log_a_button_full;
static int hf_rtp_midi_cj_chapter_m_log_c_button;
static int hf_rtp_midi_cj_chapter_m_log_c_button_g;
static int hf_rtp_midi_cj_chapter_m_log_c_button_r;
static int hf_rtp_midi_cj_chapter_m_log_c_button_full;
static int hf_rtp_midi_cj_chapter_m_log_count;
static int hf_rtp_midi_cj_chapter_m_log_count_x;
static int hf_rtp_midi_cj_chapter_m_log_count_full;

static int hf_rtp_midi_cj_chapter_w_sflag;
static int hf_rtp_midi_cj_chapter_w_first;
static int hf_rtp_midi_cj_chapter_w_rflag;
static int hf_rtp_midi_cj_chapter_w_second;

static int hf_rtp_midi_cj_chapter_n_bflag;
static int hf_rtp_midi_cj_chapter_n_len;
static int hf_rtp_midi_cj_chapter_n_low;
static int hf_rtp_midi_cj_chapter_n_high;
static int hf_rtp_midi_cj_chapter_n_log_sflag;
static int hf_rtp_midi_cj_chapter_n_log_notenum;
static int hf_rtp_midi_cj_chapter_n_log_yflag;
static int hf_rtp_midi_cj_chapter_n_log_velocity;
static int hf_rtp_midi_cj_chapter_n_log_octet;

static int hf_rtp_midi_cj_chapter_e_sflag;
static int hf_rtp_midi_cj_chapter_e_len;
static int hf_rtp_midi_cj_chapter_e_log_sflag;
static int hf_rtp_midi_cj_chapter_e_log_notenum;
static int hf_rtp_midi_cj_chapter_e_log_vflag;
static int hf_rtp_midi_cj_chapter_e_log_velocity;
static int hf_rtp_midi_cj_chapter_e_log_count;

static int hf_rtp_midi_cj_chapter_t_channel_aftertouch;
static int hf_rtp_midi_cj_chapter_t_sflag;
static int hf_rtp_midi_cj_chapter_t_pressure;

static int hf_rtp_midi_cj_chapter_a_sflag;
static int hf_rtp_midi_cj_chapter_a_len;
static int hf_rtp_midi_cj_chapter_a_log_sflag;
static int hf_rtp_midi_cj_chapter_a_log_notenum;
static int hf_rtp_midi_cj_chapter_a_log_xflag;
static int hf_rtp_midi_cj_chapter_a_log_pressure;

static int hf_rtp_midi_sj_chapter_v;
static int hf_rtp_midi_sj_chapter_v_sflag;
static int hf_rtp_midi_sj_chapter_v_count;

static int hf_rtp_midi_sj_chapter_d_simple_system_commands;
static int hf_rtp_midi_sj_chapter_d_sflag;
static int hf_rtp_midi_sj_chapter_d_bflag;
static int hf_rtp_midi_sj_chapter_d_gflag;
static int hf_rtp_midi_sj_chapter_d_hflag;
static int hf_rtp_midi_sj_chapter_d_jflag;
static int hf_rtp_midi_sj_chapter_d_kflag;
static int hf_rtp_midi_sj_chapter_d_yflag;
static int hf_rtp_midi_sj_chapter_d_zflag;

static int hf_rtp_midi_sj_chapter_d_reset;
static int hf_rtp_midi_sj_chapter_d_reset_sflag;
static int hf_rtp_midi_sj_chapter_d_reset_count;
static int hf_rtp_midi_sj_chapter_d_tune;
static int hf_rtp_midi_sj_chapter_d_tune_sflag;
static int hf_rtp_midi_sj_chapter_d_tune_count;
static int hf_rtp_midi_sj_chapter_d_song_sel;
static int hf_rtp_midi_sj_chapter_d_song_sel_sflag;
static int hf_rtp_midi_sj_chapter_d_song_sel_value;

static int hf_rtp_midi_sj_chapter_d_syscom_sflag;
static int hf_rtp_midi_sj_chapter_d_syscom_cflag;
static int hf_rtp_midi_sj_chapter_d_syscom_vflag;
static int hf_rtp_midi_sj_chapter_d_syscom_lflag;
static int hf_rtp_midi_sj_chapter_d_syscom_dsz;
static int hf_rtp_midi_sj_chapter_d_syscom_length;
static int hf_rtp_midi_sj_chapter_d_syscom_count;
static int hf_rtp_midi_sj_chapter_d_syscom_value;
static int hf_rtp_midi_sj_chapter_d_syscom_legal;
static int hf_rtp_midi_sj_chapter_d_syscom_data;

static int hf_rtp_midi_sj_chapter_d_sysreal_sflag;
static int hf_rtp_midi_sj_chapter_d_sysreal_cflag;
static int hf_rtp_midi_sj_chapter_d_sysreal_lflag;
static int hf_rtp_midi_sj_chapter_d_sysreal_length;
static int hf_rtp_midi_sj_chapter_d_sysreal_count;
static int hf_rtp_midi_sj_chapter_d_sysreal_legal;
static int hf_rtp_midi_sj_chapter_d_sysreal_data;

static int hf_rtp_midi_sj_chapter_q_sflag;
static int hf_rtp_midi_sj_chapter_q_nflag;
static int hf_rtp_midi_sj_chapter_q_dflag;
static int hf_rtp_midi_sj_chapter_q_cflag;
static int hf_rtp_midi_sj_chapter_q_tflag;
static int hf_rtp_midi_sj_chapter_q_top;
static int hf_rtp_midi_sj_chapter_q_clock;
static int hf_rtp_midi_sj_chapter_q_timetools;

static int hf_rtp_midi_sj_chapter_f_sflag;
static int hf_rtp_midi_sj_chapter_f_cflag;
static int hf_rtp_midi_sj_chapter_f_pflag;
static int hf_rtp_midi_sj_chapter_f_qflag;
static int hf_rtp_midi_sj_chapter_f_dflag;
static int hf_rtp_midi_sj_chapter_f_point;
static int hf_rtp_midi_sj_chapter_f_complete;
static int hf_rtp_midi_sj_chapter_f_partial;
static int hf_rtp_midi_sj_chapter_f_mt0;
static int hf_rtp_midi_sj_chapter_f_mt1;
static int hf_rtp_midi_sj_chapter_f_mt2;
static int hf_rtp_midi_sj_chapter_f_mt3;
static int hf_rtp_midi_sj_chapter_f_mt4;
static int hf_rtp_midi_sj_chapter_f_mt5;
static int hf_rtp_midi_sj_chapter_f_mt6;
static int hf_rtp_midi_sj_chapter_f_mt7;
static int hf_rtp_midi_sj_chapter_f_hr;
static int hf_rtp_midi_sj_chapter_f_mn;
static int hf_rtp_midi_sj_chapter_f_sc;
static int hf_rtp_midi_sj_chapter_f_fr;

static int hf_rtp_midi_sj_chapter_x_sflag;
static int hf_rtp_midi_sj_chapter_x_tflag;
static int hf_rtp_midi_sj_chapter_x_cflag;
static int hf_rtp_midi_sj_chapter_x_fflag;
static int hf_rtp_midi_sj_chapter_x_dflag;
static int hf_rtp_midi_sj_chapter_x_lflag;
static int hf_rtp_midi_sj_chapter_x_sta;
static int hf_rtp_midi_sj_chapter_x_tcount;
static int hf_rtp_midi_sj_chapter_x_count;
static int hf_rtp_midi_sj_chapter_x_first1;
static int hf_rtp_midi_sj_chapter_x_first2;
static int hf_rtp_midi_sj_chapter_x_first3;
static int hf_rtp_midi_sj_chapter_x_first4;
static int hf_rtp_midi_sj_chapter_x_data;
static int hf_rtp_midi_sj_chapter_x_invalid_data;


/* RTP MIDI fields defining a subtree */

static int ett_rtp_midi;
static int ett_rtp_midi_commands;
static int ett_rtp_midi_journal;
static int ett_rtp_midi_systemjournal;
static int ett_rtp_midi_channeljournals;
static int ett_rtp_midi_systemchapters;
static int ett_rtp_midi_sj_chapter_d;
static int ett_rtp_midi_sj_chapter_d_field_b;
static int ett_rtp_midi_sj_chapter_d_field_g;
static int ett_rtp_midi_sj_chapter_d_field_h;
static int ett_rtp_midi_sj_chapter_d_field_j;
static int ett_rtp_midi_sj_chapter_d_field_k;
static int ett_rtp_midi_sj_chapter_d_field_y;
static int ett_rtp_midi_sj_chapter_d_field_z;
static int ett_rtp_midi_sj_chapter_v;
static int ett_rtp_midi_sj_chapter_q;
static int ett_rtp_midi_sj_chapter_f;
static int ett_rtp_midi_sj_chapter_f_complete;
static int ett_rtp_midi_sj_chapter_f_partial;
static int ett_rtp_midi_sj_chapter_x;
static int ett_rtp_midi_sj_chapter_x_first;
static int ett_rtp_midi_sj_chapter_x_data;
static int ett_rtp_midi_channeljournal;
static int ett_rtp_midi_channelchapters;
static int ett_rtp_midi_cj_chapter_p;
static int ett_rtp_midi_cj_chapter_c;
static int ett_rtp_midi_cj_chapter_c_loglist;
static int ett_rtp_midi_cj_chapter_c_logitem;
static int ett_rtp_midi_cj_chapter_m;
static int ett_rtp_midi_cj_chapter_m_loglist;
static int ett_rtp_midi_cj_chapter_m_logitem;
static int ett_rtp_midi_cj_chapter_m_log_msb;
static int ett_rtp_midi_cj_chapter_m_log_lsb;
static int ett_rtp_midi_cj_chapter_m_log_a_button;
static int ett_rtp_midi_cj_chapter_m_log_c_button;
static int ett_rtp_midi_cj_chapter_m_log_count;
static int ett_rtp_midi_cj_chapter_w;
static int ett_rtp_midi_cj_chapter_n;
static int ett_rtp_midi_cj_chapter_n_loglist;
static int ett_rtp_midi_cj_chapter_n_logitem;
static int ett_rtp_midi_cj_chapter_n_octets;
static int ett_rtp_midi_cj_chapter_e;
static int ett_rtp_midi_cj_chapter_e_loglist;
static int ett_rtp_midi_cj_chapter_e_logitem;
static int ett_rtp_midi_cj_chapter_t;
static int ett_rtp_midi_cj_chapter_a;
static int ett_rtp_midi_cj_chapter_a_loglist;
static int ett_rtp_midi_cj_chapter_a_logitem;


static int proto_rtp_midi;


static dissector_handle_t	rtp_midi_handle;


void proto_reg_handoff_rtp_midi( void );


/*
 * This decodes the delta-time before a MIDI-command
 */
static int
decodetime(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset)
{
	uint8_t		octet;
	unsigned int	consumed;
	unsigned int    i;
	unsigned int    deltatime;

	consumed  = 0;
	deltatime = 0;


	/* RTP-MIDI deltatime is "compressed" using only the necessary amount of octets */
	for ( i=0; i < 4; i++ ) {

		octet = tvb_get_uint8( tvb, offset + consumed );
		deltatime = ( deltatime << 7 ) | ( octet & RTP_MIDI_DELTA_TIME_OCTET_MASK );
		consumed++;

		if ( ( octet & RTP_MIDI_DELTA_TIME_EXTENSION ) == 0 ) {
			break;
		}
	}

	switch (consumed) {
		case 1:
		    proto_tree_add_uint ( tree, hf_rtp_midi_deltatime1, tvb, offset, consumed, deltatime );
			break;
		case 2:
		    proto_tree_add_uint ( tree, hf_rtp_midi_deltatime2, tvb, offset, consumed, deltatime );
			break;
		case 3:
		    proto_tree_add_uint ( tree, hf_rtp_midi_deltatime3, tvb, offset, consumed, deltatime );
			break;
		case 4:
		    proto_tree_add_uint ( tree, hf_rtp_midi_deltatime4, tvb, offset, consumed, deltatime );
			break;

	}

	return consumed;
}



/*
 * Here the chapter c of the channel-journal is decoded.
 */
static int
decode_cj_chapter_c( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {
	proto_tree			*rtp_midi_cj_chapter_tree;
	proto_tree			*rtp_midi_loglist_tree;
	proto_tree			*loglist_tree;
	unsigned int start_offset = offset;
	uint8_t				 octet;
	int				 count;
	int				 i;

	octet = tvb_get_uint8( tvb, offset );
	count = octet & 0x7f;

	/* count encoded is n+1 */
	count++;

	rtp_midi_cj_chapter_tree = proto_tree_add_subtree( tree, tvb, offset, 1 + 2 * count,
				ett_rtp_midi_cj_chapter_c, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_C );

	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_c_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_c_length, tvb, offset, 1, ENC_BIG_ENDIAN );

	offset++;

	rtp_midi_loglist_tree = proto_tree_add_subtree( rtp_midi_cj_chapter_tree, tvb, offset, count * 2,
				ett_rtp_midi_cj_chapter_c_loglist, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_C_LOGLIST );

	for ( i = 0; i < count; i++ ) {

		loglist_tree = proto_tree_add_subtree(rtp_midi_loglist_tree, tvb, offset, 2,
			ett_rtp_midi_cj_chapter_c_logitem, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_C_LOGITEM );

		proto_tree_add_item(loglist_tree, hf_rtp_midi_cj_chapter_c_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item(loglist_tree, hf_rtp_midi_cj_chapter_c_number, tvb, offset, 1, ENC_BIG_ENDIAN );

		offset++;

		octet = tvb_get_uint8( tvb, offset );
		proto_tree_add_item(loglist_tree, hf_rtp_midi_cj_chapter_c_aflag, tvb, offset, 1, ENC_BIG_ENDIAN );

		/* do we have a value or alternative coding? */
		if ( octet & 0x80 ) {
			proto_tree_add_item(loglist_tree, hf_rtp_midi_cj_chapter_c_tflag, tvb, offset, 1, ENC_BIG_ENDIAN );
			proto_tree_add_item(loglist_tree, hf_rtp_midi_cj_chapter_c_alt, tvb, offset, 1, ENC_BIG_ENDIAN );
		} else {
			proto_tree_add_item(loglist_tree, hf_rtp_midi_cj_chapter_c_value, tvb, offset, 1, ENC_BIG_ENDIAN );
		}

		offset++;
	}
	return offset-start_offset;
}



/*
 * Here the chapter m of the channel-journal is decoded, possibly the most complex part of the RTP-MIDI stuff ;-)
 */
static int
decode_cj_chapter_m( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {
	proto_tree			*rtp_midi_cj_chapter_tree;
	proto_tree			*rtp_midi_loglist_tree;
	proto_tree			*rtp_midi_loglist_item_tree;
	uint16_t				header;
	uint8_t				logitemheader;
	int				length;
	int				logitemhdrlen;
	int				logitemlen;
	bool			no_pnum_msb;
	unsigned int start_offset = offset;

	/* first we need to get the flags & length of this chapter */
	header = tvb_get_ntohs( tvb, offset );
	length = header & RTP_MIDI_CJ_CHAPTER_M_MASK_LENGTH;
	/* take of length of header */
	length -= 2;

	rtp_midi_cj_chapter_tree = proto_tree_add_subtree( tree, tvb, offset, length, ett_rtp_midi_cj_chapter_m, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_M );

	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_m_sflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_m_pflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_m_eflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_m_uflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_m_wflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_m_zflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_m_length, tvb, offset, 2, ENC_BIG_ENDIAN );

	/* done with header */
	offset	 += 2;

	/* do we have the pending field? */
	if ( header & 0x4000 ) {

		proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_m_qflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_m_pending, tvb, offset, 1, ENC_BIG_ENDIAN );

		offset++;
	}

	/*
	 * lets find out if we need to decode the pnum_msb:
	 * if Z = 1 and either U = 1 or W = 1 we don't
	 */
	no_pnum_msb = ( header & 0x0400 ) && ( ( header & 0x0800 ) || ( header & 0x1000 ) );
	logitemhdrlen = no_pnum_msb ? 2 : 3;

	rtp_midi_loglist_tree = proto_tree_add_subtree( rtp_midi_cj_chapter_tree, tvb, offset, length, ett_rtp_midi_cj_chapter_m_loglist, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_M_LOGLIST );

	/* lets step through the loglist */
	while ( length > 0 ) {

		if ( no_pnum_msb ) {
			logitemheader = tvb_get_uint8( tvb, offset + 1 );
		} else {
			logitemheader = tvb_get_uint8( tvb, offset + 2 );
		}

		logitemlen = logitemhdrlen;

		/* do we have a msb field? */
		if ( logitemheader & RTP_MIDI_CJ_CHAPTER_M_FLAG_J ) {
			logitemlen++;
		}

		/* do we have a lsb field? */
		if ( logitemheader & RTP_MIDI_CJ_CHAPTER_M_FLAG_K ) {
			logitemlen++;
		}

		/* do we have an a-button field? */
		if ( logitemheader & RTP_MIDI_CJ_CHAPTER_M_FLAG_L ) {
			logitemlen +=2;
		}

		/* do we have a c-button field? */
		if ( logitemheader & RTP_MIDI_CJ_CHAPTER_M_FLAG_M ) {
			logitemlen +=2;
		}

		/* do we have a count field? */
		if ( logitemheader & RTP_MIDI_CJ_CHAPTER_M_FLAG_N ) {
			logitemlen++;
		}

		/* now that we have the length of the logitem, we can create the tree... */
		rtp_midi_loglist_item_tree = proto_tree_add_subtree( rtp_midi_loglist_tree, tvb, offset, logitemlen,
						ett_rtp_midi_cj_chapter_m_logitem, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_M_LOGITEM );

		proto_tree_add_item( rtp_midi_loglist_item_tree, hf_rtp_midi_cj_chapter_m_log_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_loglist_item_tree, hf_rtp_midi_cj_chapter_m_log_pnum_lsb, tvb, offset, 1, ENC_BIG_ENDIAN );
		offset++;
		length--;

		/* if we have the msb, we need to decode it */
		if ( !no_pnum_msb ) {
			proto_tree_add_item( rtp_midi_loglist_item_tree, hf_rtp_midi_cj_chapter_m_log_qflag, tvb, offset, 1, ENC_BIG_ENDIAN );
			proto_tree_add_item( rtp_midi_loglist_item_tree, hf_rtp_midi_cj_chapter_m_log_pnum_msb, tvb, offset, 1, ENC_BIG_ENDIAN );
			offset++;
			length--;
		}

		proto_tree_add_item( rtp_midi_loglist_item_tree, hf_rtp_midi_cj_chapter_m_log_jflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_loglist_item_tree, hf_rtp_midi_cj_chapter_m_log_kflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_loglist_item_tree, hf_rtp_midi_cj_chapter_m_log_lflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_loglist_item_tree, hf_rtp_midi_cj_chapter_m_log_mflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_loglist_item_tree, hf_rtp_midi_cj_chapter_m_log_nflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_loglist_item_tree, hf_rtp_midi_cj_chapter_m_log_tflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_loglist_item_tree, hf_rtp_midi_cj_chapter_m_log_vflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_loglist_item_tree, hf_rtp_midi_cj_chapter_m_log_rflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		offset++;
		length--;

		/* do we have a entry-msb field? */
		if ( logitemheader & RTP_MIDI_CJ_CHAPTER_M_FLAG_J ) {
			static int * const msb_flags[] = {
				&hf_rtp_midi_cj_chapter_m_log_msb_x,
				&hf_rtp_midi_cj_chapter_m_log_msb,
				NULL
				};

			proto_tree_add_bitmask(rtp_midi_loglist_tree, tvb, offset, hf_rtp_midi_cj_chapter_m_log_msb_entry, ett_rtp_midi_cj_chapter_m_log_msb, msb_flags, ENC_NA);

			offset++;
			length--;
		}

		/* do we have a entry-lsb field? */
		if ( logitemheader & RTP_MIDI_CJ_CHAPTER_M_FLAG_K ) {
			static int * const lsb_flags[] = {
				&hf_rtp_midi_cj_chapter_m_log_lsb_x,
				&hf_rtp_midi_cj_chapter_m_log_lsb,
				NULL
				};

			proto_tree_add_bitmask(rtp_midi_loglist_tree, tvb, offset, hf_rtp_midi_cj_chapter_m_log_lsb_entry, ett_rtp_midi_cj_chapter_m_log_lsb, lsb_flags, ENC_NA);
			offset++;
			length--;
		}

		/* do we have an a-button field? */
		if ( logitemheader & RTP_MIDI_CJ_CHAPTER_M_FLAG_L ) {
			static int * const button_flags[] = {
				&hf_rtp_midi_cj_chapter_m_log_a_button_g,
				&hf_rtp_midi_cj_chapter_m_log_a_button_x,
				&hf_rtp_midi_cj_chapter_m_log_a_button,
				NULL
				};

			proto_tree_add_bitmask(rtp_midi_loglist_tree, tvb, offset, hf_rtp_midi_cj_chapter_m_log_a_button_full, ett_rtp_midi_cj_chapter_m_log_a_button, button_flags, ENC_BIG_ENDIAN);

			offset	 += 2;
			length	 -= 2;
		}

		/* do we have a c-button field? */
		if ( logitemheader & RTP_MIDI_CJ_CHAPTER_M_FLAG_M ) {
			static int * const button_flags[] = {
				&hf_rtp_midi_cj_chapter_m_log_c_button_g,
				&hf_rtp_midi_cj_chapter_m_log_c_button_r,
				&hf_rtp_midi_cj_chapter_m_log_c_button,
				NULL
				};

			proto_tree_add_bitmask(rtp_midi_loglist_tree, tvb, offset, hf_rtp_midi_cj_chapter_m_log_c_button_full, ett_rtp_midi_cj_chapter_m_log_c_button, button_flags, ENC_BIG_ENDIAN);

			offset	 += 2;
			length	 -= 2;
		}

		/* do we have a count field? */
		if ( logitemheader & RTP_MIDI_CJ_CHAPTER_M_FLAG_N ) {
			static int * const log_flags[] = {
				&hf_rtp_midi_cj_chapter_m_log_count_x,
				&hf_rtp_midi_cj_chapter_m_log_count,
				NULL
				};

			proto_tree_add_bitmask(rtp_midi_loglist_tree, tvb, offset, hf_rtp_midi_cj_chapter_m_log_count_full, ett_rtp_midi_cj_chapter_m_log_count, log_flags, ENC_BIG_ENDIAN);

			offset++;
			length--;
		}

	}

	return offset-start_offset;
}


/*
 * Here the chapter n of the channel-journal is decoded.
 */
static int
decode_cj_chapter_n( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {
	proto_tree			*rtp_midi_cj_chapter_tree;
	proto_tree			*rtp_midi_loglist_tree;
	const char			*note_str;
	unsigned int start_offset = offset;
	uint16_t				 header;
	uint8_t				 note;
	uint8_t				 velocity;
	int				 log_count;
	int				 octet_count;
	int				 low;
	int				 high;
	int				 i;

	/* first we need to get the flags & length of this chapter */
	header = tvb_get_ntohs( tvb, offset );
	log_count = ( header & RTP_MIDI_CJ_CHAPTER_N_MASK_LENGTH ) >> 8;
	low = ( header & RTP_MIDI_CJ_CHAPTER_N_MASK_LOW ) >> 4;
	high = header & RTP_MIDI_CJ_CHAPTER_N_MASK_HIGH;

	/* how many offbits octets do we have? */
	if ( low <= high ) {
		octet_count = high - low + 1;
	} else if ( ( low == 15 ) && ( high == 0 ) ) {
		octet_count = 0;
	} else if ( ( low == 15 ) && ( high == 1 ) ) {
		octet_count = 0;
	} else {
		return -1;
	}

	/* special case -> no offbit octets, but 128 note-logs */
	if ( ( log_count == 127 ) && ( low == 15) && ( high == 0 ) ) {
		log_count++;
	}

	rtp_midi_cj_chapter_tree = proto_tree_add_subtree( tree, tvb, offset, 2 + ( log_count * 2 ) + octet_count,
					ett_rtp_midi_cj_chapter_n, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_N );

	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_n_bflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_n_len, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_n_low, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_n_high, tvb, offset, 2, ENC_BIG_ENDIAN );

	offset	 += 2;

	if ( log_count > 0 ) {

		rtp_midi_loglist_tree = proto_tree_add_subtree( rtp_midi_cj_chapter_tree, tvb, offset, log_count * 2,
					ett_rtp_midi_cj_chapter_n_loglist, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_N_LOGLIST );

		for ( i = 0; i < log_count; i++ ) {

			note = tvb_get_uint8( tvb, offset ) & 0x7f;
			velocity = tvb_get_uint8( tvb, offset + 1 ) & 0x7f;

			note_str = val_to_str_ext(pinfo->pool, note, &midi_note_values_ext, rtp_midi_unknown_value_dec );

			rtp_midi_loglist_tree = proto_tree_add_subtree_format(rtp_midi_loglist_tree, tvb, offset, 2,
						ett_rtp_midi_cj_chapter_n_logitem, NULL, "%s (n=%s, v=%d)", RTP_MIDI_TREE_NAME_CJ_CHAPTER_N_LOGITEM, note_str, velocity );

			proto_tree_add_item( rtp_midi_loglist_tree, hf_rtp_midi_cj_chapter_n_log_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
			proto_tree_add_item( rtp_midi_loglist_tree, hf_rtp_midi_cj_chapter_n_log_notenum, tvb, offset, 1, ENC_BIG_ENDIAN );

			offset++;

			proto_tree_add_item( rtp_midi_loglist_tree, hf_rtp_midi_cj_chapter_n_log_yflag, tvb, offset, 1, ENC_BIG_ENDIAN );
			proto_tree_add_item( rtp_midi_loglist_tree, hf_rtp_midi_cj_chapter_n_log_velocity, tvb, offset, 1, ENC_BIG_ENDIAN );

			offset++;
		}

	}

	if ( octet_count > 0 ) {

		rtp_midi_loglist_tree = proto_tree_add_subtree( rtp_midi_cj_chapter_tree, tvb, offset, log_count,
				ett_rtp_midi_cj_chapter_n_octets, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_N_OCTETS );

		for ( i = 0; i < octet_count; i++ ) {

			proto_tree_add_item(rtp_midi_loglist_tree, hf_rtp_midi_cj_chapter_n_log_octet, tvb, offset, 1, ENC_BIG_ENDIAN );

			offset++;
		}
	}

	return offset-start_offset;
}


/*
 * Here the chapter e of the channel-journal is decoded.
 */
static int
decode_cj_chapter_e( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {
	proto_tree			*rtp_midi_cj_chapter_tree;
	proto_tree			*rtp_midi_loglist_tree, *log_tree;
	const char			*note_str;
	unsigned int start_offset = offset;
	uint8_t				 header;
	uint8_t				 note;
	uint8_t				 count_vel;
	uint8_t				 octet;
	int				 log_count;
	int				 i;

	/* first we need to get the flags & length of this chapter */
	header = tvb_get_uint8( tvb, offset );
	log_count = header & RTP_MIDI_CJ_CHAPTER_E_MASK_LENGTH;

	/* count is encoded n+1 */
	log_count++;

	rtp_midi_cj_chapter_tree = proto_tree_add_subtree( tree, tvb, offset, 1 + ( log_count * 2 ),
				ett_rtp_midi_cj_chapter_e, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_E );

	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_e_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_e_len, tvb, offset, 1, ENC_BIG_ENDIAN );

	offset++;

	rtp_midi_loglist_tree = proto_tree_add_subtree( rtp_midi_cj_chapter_tree, tvb, offset, log_count * 2,
				ett_rtp_midi_cj_chapter_e_loglist, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_E_LOGLIST );

	for ( i = 0; i < log_count; i++ ) {

		note = tvb_get_uint8( tvb, offset ) & 0x7f;
		octet = tvb_get_uint8( tvb, offset + 1 );
		count_vel = octet & 0x7f;

		note_str = val_to_str_ext(pinfo->pool, note, &midi_note_values_ext, rtp_midi_unknown_value_dec );

		if ( octet & 0x80 ) {
			log_tree = proto_tree_add_subtree_format(rtp_midi_loglist_tree, tvb, offset, 2, ett_rtp_midi_cj_chapter_e_logitem, NULL,
						"%s (n=%s, v=%d)", RTP_MIDI_TREE_NAME_CJ_CHAPTER_E_LOGITEM1, note_str, count_vel );
		} else {
			log_tree = proto_tree_add_subtree_format(rtp_midi_loglist_tree, tvb, offset, 2, ett_rtp_midi_cj_chapter_e_logitem, NULL,
						"%s (n=%s, c=%d)", RTP_MIDI_TREE_NAME_CJ_CHAPTER_E_LOGITEM2, note_str, count_vel );
		}

		proto_tree_add_item( log_tree, hf_rtp_midi_cj_chapter_e_log_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( log_tree, hf_rtp_midi_cj_chapter_e_log_notenum, tvb, offset, 1, ENC_BIG_ENDIAN );

		offset++;

		proto_tree_add_item( log_tree, hf_rtp_midi_cj_chapter_e_log_vflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		if ( octet & 0x80 ) {
			proto_tree_add_item( log_tree, hf_rtp_midi_cj_chapter_e_log_velocity, tvb, offset, 1, ENC_BIG_ENDIAN );
		} else {
			proto_tree_add_item( log_tree, hf_rtp_midi_cj_chapter_e_log_count, tvb, offset, 1, ENC_BIG_ENDIAN );
		}

		offset++;
	}

	return offset-start_offset;
}








/*
 * Here the chapter a of the channel-journal is decoded.
 */
static int
decode_cj_chapter_a( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {
	proto_tree			*rtp_midi_cj_chapter_tree;
	proto_tree			*rtp_midi_loglist_tree, *log_tree;
	const char			*note_str;
	unsigned int start_offset = offset;
	uint8_t				 header;
	uint8_t				 note;
	uint8_t				 pressure;
	int				 log_count;
	int				 i;

	/* first we need to get the flags & length of this chapter */
	header = tvb_get_uint8( tvb, offset );
	log_count = header & RTP_MIDI_CJ_CHAPTER_A_MASK_LENGTH;

	/* count is encoded n+1 */
	log_count++;

	rtp_midi_cj_chapter_tree = proto_tree_add_subtree( tree, tvb, offset, 1 + ( log_count * 2 ), ett_rtp_midi_cj_chapter_a, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_A );

	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_a_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_a_len, tvb, offset, 1, ENC_BIG_ENDIAN );

	offset++;

	rtp_midi_loglist_tree = proto_tree_add_subtree( rtp_midi_cj_chapter_tree, tvb, offset, log_count * 2, ett_rtp_midi_cj_chapter_a_loglist, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_A_LOGLIST );

	for ( i = 0; i < log_count; i++ ) {

		note	 = tvb_get_uint8( tvb, offset ) & 0x7f;
		pressure = tvb_get_uint8( tvb, offset + 1 ) & 0x7f;

		note_str = val_to_str_ext(pinfo->pool, note, &midi_note_values_ext, rtp_midi_unknown_value_dec );

		log_tree = proto_tree_add_subtree_format(rtp_midi_loglist_tree, tvb, offset, 2, ett_rtp_midi_cj_chapter_a_logitem, NULL,
				"%s (n=%s, p=%d)", RTP_MIDI_TREE_NAME_CJ_CHAPTER_A_LOGITEM, note_str, pressure );

		proto_tree_add_item( log_tree, hf_rtp_midi_cj_chapter_a_log_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( log_tree, hf_rtp_midi_cj_chapter_a_log_notenum, tvb, offset, 1, ENC_BIG_ENDIAN );

		offset++;

		proto_tree_add_item( log_tree, hf_rtp_midi_cj_chapter_a_log_xflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( log_tree, hf_rtp_midi_cj_chapter_a_log_pressure, tvb, offset, 1, ENC_BIG_ENDIAN );

		offset++;
	}

	return offset-start_offset;
}





/*
 * Here a channel-journal is decoded.
 */
static int
decode_channel_journal( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {
	proto_tree			*rtp_midi_chanjournal_tree;
	proto_tree			*rtp_midi_cj_chapters_tree;
	proto_tree			*rtp_midi_cj_chapter_tree;
	uint32_t				chanflags;
	uint16_t				chanjourlen;
	int				consumed = 0;
	int				ext_consumed = 0;

	/* first we need to get the flags & length of this channel-journal */
	chanflags = tvb_get_ntoh24( tvb, offset );
	chanjourlen = ( chanflags & RTP_MIDI_CJ_MASK_LENGTH ) >> 8;

	rtp_midi_chanjournal_tree = proto_tree_add_subtree( tree, tvb, offset, chanjourlen, ett_rtp_midi_channeljournal, NULL,
			val_to_str(pinfo->pool,  ( chanflags & RTP_MIDI_CJ_MASK_CHANNEL ) >> RTP_MIDI_CJ_CHANNEL_SHIFT, midi_channels, rtp_midi_unknown_value_hex ) );

	proto_tree_add_item( rtp_midi_chanjournal_tree, hf_rtp_midi_chanjour_sflag, tvb, offset, 3, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_chanjournal_tree, hf_rtp_midi_chanjour_chan, tvb, offset, 3, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_chanjournal_tree, hf_rtp_midi_chanjour_hflag, tvb, offset, 3, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_chanjournal_tree, hf_rtp_midi_chanjour_len, tvb, offset, 3, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_chanjournal_tree, hf_rtp_midi_chanjour_toc_p, tvb, offset, 3, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_chanjournal_tree, hf_rtp_midi_chanjour_toc_c, tvb, offset, 3, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_chanjournal_tree, hf_rtp_midi_chanjour_toc_m, tvb, offset, 3, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_chanjournal_tree, hf_rtp_midi_chanjour_toc_w, tvb, offset, 3, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_chanjournal_tree, hf_rtp_midi_chanjour_toc_n, tvb, offset, 3, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_chanjournal_tree, hf_rtp_midi_chanjour_toc_e, tvb, offset, 3, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_chanjournal_tree, hf_rtp_midi_chanjour_toc_t, tvb, offset, 3, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_chanjournal_tree, hf_rtp_midi_chanjour_toc_a, tvb, offset, 3, ENC_BIG_ENDIAN );

	rtp_midi_cj_chapters_tree = proto_tree_add_subtree( rtp_midi_chanjournal_tree, tvb, offset + 3, chanjourlen - 3,
			ett_rtp_midi_channelchapters, NULL, RTP_MIDI_TREE_NAME_CHANNEL_CHAPTERS );

	/* take care of length of header */
	offset	 += 3;
	consumed += 3;

	/* Do we have a program change chapter? */
	if ( chanflags & RTP_MIDI_CJ_FLAG_P ) {

		rtp_midi_cj_chapter_tree = proto_tree_add_subtree( rtp_midi_cj_chapters_tree, tvb, offset, 3,
				ett_rtp_midi_cj_chapter_p, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_P );

		proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_p_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_p_program, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_p_bflag, tvb, offset + 1, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_p_bank_msb, tvb, offset + 1, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_p_xflag, tvb, offset + 2, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_p_bank_lsb, tvb, offset + 2, 1, ENC_BIG_ENDIAN );

		offset	 += 3;
		consumed += 3;
	}

	/* Do we have a control chapter? */
	if ( chanflags & RTP_MIDI_CJ_FLAG_C ) {
		ext_consumed = decode_cj_chapter_c( tvb, pinfo, rtp_midi_cj_chapters_tree, offset );
		if ( ext_consumed < 0 ) {
			return ext_consumed;
		}
		consumed += ext_consumed;
		offset	 += ext_consumed;

	}

	/* Do we have a parameter changes? */
	if ( chanflags & RTP_MIDI_CJ_FLAG_M ) {
		ext_consumed = decode_cj_chapter_m( tvb, pinfo, rtp_midi_cj_chapters_tree, offset );
		if ( ext_consumed < 0 ) {
			return ext_consumed;
		}
		consumed += ext_consumed;
		offset	 += ext_consumed;
	}

	/* Do we have a pitch-wheel chapter? */
	if ( chanflags & RTP_MIDI_CJ_FLAG_W ) {

		rtp_midi_cj_chapter_tree = proto_tree_add_subtree( rtp_midi_cj_chapters_tree, tvb, offset, 2,
						ett_rtp_midi_cj_chapter_w, NULL, RTP_MIDI_TREE_NAME_CJ_CHAPTER_W );

		proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_w_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_w_first, tvb, offset, 1, ENC_BIG_ENDIAN );

		offset++;
		consumed++;

		proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_w_rflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_cj_chapter_tree, hf_rtp_midi_cj_chapter_w_second, tvb, offset, 1, ENC_BIG_ENDIAN );

		offset++;
		consumed++;
	}

	/* Do we have a note on/off chapter? */
	if ( chanflags & RTP_MIDI_CJ_FLAG_N ) {
		ext_consumed = decode_cj_chapter_n( tvb, pinfo, rtp_midi_cj_chapters_tree, offset );
		if ( ext_consumed < 0 ) {
			return ext_consumed;
		}
		consumed += ext_consumed;
		offset	 += ext_consumed;
	}

	/* Do we have a note command extras chapter? */
	if ( chanflags & RTP_MIDI_CJ_FLAG_E ) {
		ext_consumed = decode_cj_chapter_e( tvb, pinfo, rtp_midi_cj_chapters_tree, offset );
		if ( ext_consumed < 0 ) {
			return ext_consumed;
		}
		consumed += ext_consumed;
		offset	 += ext_consumed;
	}

	/* Do we have channel aftertouch chapter? */
	if ( chanflags & RTP_MIDI_CJ_FLAG_T ) {
		static int * const flags_t[] = {
			&hf_rtp_midi_cj_chapter_t_sflag,
			&hf_rtp_midi_cj_chapter_t_pressure,
			NULL
		};

		proto_tree_add_bitmask(rtp_midi_cj_chapters_tree, tvb, offset, hf_rtp_midi_cj_chapter_t_channel_aftertouch, ett_rtp_midi_cj_chapter_t, flags_t, ENC_NA);

		offset++;
		consumed++;
	}

	/* Do we have a poly aftertouch chapter? */
	if ( chanflags & RTP_MIDI_CJ_FLAG_A ) {
		ext_consumed = decode_cj_chapter_a( tvb, pinfo, rtp_midi_cj_chapters_tree, offset );
		if ( ext_consumed < 0 ) {
			return ext_consumed;
		}
		consumed += ext_consumed;
	}

	/* Make sanity check for consumed data vs. stated length of this channels journal */
	if ( consumed != chanjourlen ) {
		return -1;
	}
	return consumed;
}


/*
 * Here the chapter D F4-field of the system-journal is decoded.
 */
static int
decode_sj_chapter_d_f4( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {

	proto_tree	*rtp_midi_field_tree;
	unsigned int start_offset = offset;
	uint16_t		 f4flags;
	uint16_t		 f4length;

	/* Get flags & length */
	f4flags = tvb_get_ntohs( tvb, offset );
	f4length = f4flags & RTP_MIDI_SJ_CHAPTER_D_SYSCOM_MASK_LENGTH;

	/* now we can display our tree, as we now have the full length */
	rtp_midi_field_tree = proto_tree_add_subtree( tree, tvb, offset, f4length, ett_rtp_midi_sj_chapter_d_field_j, NULL, RTP_MIDI_TREE_NAME_SJ_CHAPTER_D_FIELD_J );

	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_sflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_cflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_vflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_lflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_dsz, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_length, tvb, offset, 2, ENC_BIG_ENDIAN );

	offset	 += 2;
	f4length -= 2;

	if ( f4flags & RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_C ) {

		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_count, tvb, offset, 1, ENC_BIG_ENDIAN );

		offset++;
		f4length--;
	}

	if ( f4flags & RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_V ) {

		int valuelen = 0;
		uint8_t octet;

		/* variable length field - ends with an octet with MSB set */
		for (;;) {
			octet = tvb_get_uint8( tvb, offset+valuelen );
			valuelen++;
			if ( octet & 0x80 ) {
				break;
			}
		}
		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_value, tvb, offset, valuelen, ENC_NA );
		offset	 += valuelen;
		f4length -= valuelen;
	}

	if ( f4flags & RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_L ) {

		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_legal, tvb, offset, f4length, ENC_NA );
		offset	 += f4length;
	}

	/* if we still have data, the length-field was incorrect we dump the data here and abort! */
	if ( f4length > 0 ) {

		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_data, tvb, offset, f4length, ENC_NA );
		offset += f4length;
		/* must be a protocol error - since we have a length, we can recover...*/
	}


	return offset-start_offset;
}


/*
 * Here the chapter D F5-field of the system-journal is decoded.
 */
static int
decode_sj_chapter_d_f5( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {

	proto_tree	*rtp_midi_field_tree;
	unsigned int start_offset = offset;
	uint16_t		 f5flags;
	uint16_t		 f5length;

	/* Get flags & length */
	f5flags = tvb_get_ntohs( tvb, offset );
	f5length = f5flags & RTP_MIDI_SJ_CHAPTER_D_SYSCOM_MASK_LENGTH;

	/* now we can display our tree, as we now have the full length */
	rtp_midi_field_tree = proto_tree_add_subtree( tree, tvb, offset, f5length, ett_rtp_midi_sj_chapter_d_field_k, NULL, RTP_MIDI_TREE_NAME_SJ_CHAPTER_D_FIELD_K );

	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_sflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_cflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_vflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_lflag, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_dsz, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_length, tvb, offset, 2, ENC_BIG_ENDIAN );

	offset	 += 2;
	f5length -= 2;

	if ( f5flags & RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_C ) {

		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_count, tvb, offset, 1, ENC_BIG_ENDIAN );

		offset++;
		f5length--;
	}

	if ( f5flags & RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_V ) {

		int valuelen = 0;
		uint8_t octet;

		/* variable length field - ends with an octet with MSB set */
		for (;;) {
			octet = tvb_get_uint8( tvb, offset+valuelen );
			valuelen++;
			if ( octet & 0x80 ) {
				break;
			}
		}
		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_value, tvb, offset, valuelen, ENC_NA );
		offset	 += valuelen;
		f5length -= valuelen;
	}

	if ( f5flags & RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_L ) {

		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_legal, tvb, offset, f5length, ENC_NA );
		offset	 += f5length;
		f5length = 0;
	}

	/* if we still have data, we dump it here - see above! */
	if ( f5length > 0 ) {

		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_syscom_data, tvb, offset, f5length, ENC_NA );
		offset += f5length;
		/* must be a protocol error - since we have a length, we can recover...*/
	}

	return offset-start_offset;
}

/*
 * Here the chapter D F9-field of the system-journal is decoded.
 */
static int
decode_sj_chapter_d_f9( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {

	proto_tree	*rtp_midi_field_tree;
	unsigned int start_offset = offset;
	uint8_t		 f9flags;
	uint8_t		 f9length;

	/* Get flags & length */
	f9flags = tvb_get_uint8( tvb, offset );
	f9length = f9flags & RTP_MIDI_SJ_CHAPTER_D_SYSREAL_MASK_LENGTH;

	/* now we can display our tree, as we now have the full length */
	rtp_midi_field_tree = proto_tree_add_subtree( tree, tvb, offset, f9length, ett_rtp_midi_sj_chapter_d_field_y, NULL, RTP_MIDI_TREE_NAME_SJ_CHAPTER_D_FIELD_Y );

	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_cflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_lflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_length, tvb, offset, 1, ENC_BIG_ENDIAN );

	offset++;
	f9length--;

	if ( f9flags & RTP_MIDI_SJ_CHAPTER_D_SYSREAL_FLAG_C ) {

		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_count, tvb, offset, 1, ENC_BIG_ENDIAN );

		offset++;
		f9length--;
	}

	if ( f9flags & RTP_MIDI_SJ_CHAPTER_D_SYSREAL_FLAG_L ) {

		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_legal, tvb, offset, f9length, ENC_NA );
		offset	 += f9length;
		f9length = 0;
	}

	/* if we still have data, the length-field was incorrect we dump the data here and abort! */

	if ( f9length > 0 ) {

		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_data, tvb, offset, f9length, ENC_NA );
		offset += f9length;
		/* must be a protocol error - since we have a length, we can recover...*/
	}

	return offset-start_offset;
}


/*
 * Here the chapter D FD-field of the system-journal is decoded.
 */
static int
decode_sj_chapter_d_fd( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {

	proto_tree	*rtp_midi_field_tree;
	unsigned int start_offset = offset;
	uint8_t		 fdflags;
	uint8_t		 fdlength;

	/* Get flags & length */
	fdflags  = tvb_get_uint8( tvb, offset );
	fdlength = fdflags & RTP_MIDI_SJ_CHAPTER_D_SYSREAL_MASK_LENGTH;

	/* now we can display our tree, as we now have the full length */
	rtp_midi_field_tree = proto_tree_add_subtree( tree, tvb, offset, fdlength, ett_rtp_midi_sj_chapter_d_field_z, NULL, RTP_MIDI_TREE_NAME_SJ_CHAPTER_D_FIELD_Z );

	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_cflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_lflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_length, tvb, offset, 1, ENC_BIG_ENDIAN );

	offset++;
	fdlength--;

	if ( fdflags & RTP_MIDI_SJ_CHAPTER_D_SYSREAL_FLAG_C ) {

		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_count, tvb, offset, 1, ENC_BIG_ENDIAN );

		offset++;
		fdlength--;
	}

	if ( fdflags & RTP_MIDI_SJ_CHAPTER_D_SYSREAL_FLAG_L ) {

		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_legal, tvb, offset, fdlength, ENC_NA );
		offset	 += fdlength;
		fdlength = 0;
	}

	/* if we still have data, the length-field was incorrect we dump the data here and abort! */

	if ( fdlength > 0 ) {

		proto_tree_add_item( rtp_midi_field_tree, hf_rtp_midi_sj_chapter_d_sysreal_data, tvb, offset, fdlength, ENC_NA );

		offset += fdlength;
		/* must be a protocol error - since we have a length, we can recover...*/
	}

	return offset-start_offset;
}



/*
 * Here the chapter D of the channel-journal is decoded.
 */
static int
decode_sj_chapter_d( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {
	proto_item			*tix;
	proto_tree			*rtp_midi_sj_chapter_tree;
	uint8_t				header;
	unsigned int start_offset = offset;
	int				ext_consumed;

	static int * const chapter_d_flags[] = {
		&hf_rtp_midi_sj_chapter_d_sflag,
		&hf_rtp_midi_sj_chapter_d_bflag,
		&hf_rtp_midi_sj_chapter_d_gflag,
		&hf_rtp_midi_sj_chapter_d_hflag,
		&hf_rtp_midi_sj_chapter_d_jflag,
		&hf_rtp_midi_sj_chapter_d_kflag,
		&hf_rtp_midi_sj_chapter_d_yflag,
		&hf_rtp_midi_sj_chapter_d_zflag,
		NULL
	};

	/* first we need to get the flags of this chapter */
	header = tvb_get_uint8( tvb, offset );

	/*
	 * we don't know the complete length yet - we know that we have at least the header -> 1.
	 * At the end we set the real length...
	 */
	tix = proto_tree_add_bitmask(tree, tvb, offset, hf_rtp_midi_sj_chapter_d_simple_system_commands, ett_rtp_midi_sj_chapter_d, chapter_d_flags, ENC_NA);
	rtp_midi_sj_chapter_tree = proto_item_add_subtree( tix, ett_rtp_midi_sj_chapter_d );

	/* done with header */
	offset++;

	/* do we have Reset field? */
	if ( header & RTP_MIDI_SJ_CHAPTER_D_FLAG_B ) {

		static int * const reset_flags[] = {
			&hf_rtp_midi_sj_chapter_d_reset_sflag,
			&hf_rtp_midi_sj_chapter_d_reset_count,
			NULL
		};

		proto_tree_add_bitmask(rtp_midi_sj_chapter_tree, tvb, offset, hf_rtp_midi_sj_chapter_d_reset, ett_rtp_midi_sj_chapter_d_field_b, reset_flags, ENC_NA);
		offset++;
	}

	/* do we have Tune request field? */
	if ( header & RTP_MIDI_SJ_CHAPTER_D_FLAG_G ) {

		static int * const tune_flags[] = {
			&hf_rtp_midi_sj_chapter_d_tune_sflag,
			&hf_rtp_midi_sj_chapter_d_tune_count,
			NULL
		};

		proto_tree_add_bitmask(rtp_midi_sj_chapter_tree, tvb, offset, hf_rtp_midi_sj_chapter_d_tune, ett_rtp_midi_sj_chapter_d_field_g, tune_flags, ENC_BIG_ENDIAN);
		offset++;
	}

	/* do we have Song select field? */
	if ( header & RTP_MIDI_SJ_CHAPTER_D_FLAG_H ) {

		static int * const song_flags[] = {
			&hf_rtp_midi_sj_chapter_d_song_sel_sflag,
			&hf_rtp_midi_sj_chapter_d_song_sel_value,
			NULL
		};

		proto_tree_add_bitmask(rtp_midi_sj_chapter_tree, tvb, offset, hf_rtp_midi_sj_chapter_d_song_sel, ett_rtp_midi_sj_chapter_d_field_h, song_flags, ENC_BIG_ENDIAN);
		offset++;
	}

	/* do we have 0xF4 field? */
	if ( header & RTP_MIDI_SJ_CHAPTER_D_FLAG_J ) {
		ext_consumed = decode_sj_chapter_d_f4( tvb, pinfo, rtp_midi_sj_chapter_tree, offset );
		if ( ext_consumed < 0 ) {
			return ext_consumed;
		}
		offset	 += ext_consumed;
	}

	/* do we have 0xF5 field? */
	if ( header & RTP_MIDI_SJ_CHAPTER_D_FLAG_K ) {
		ext_consumed = decode_sj_chapter_d_f5( tvb, pinfo, rtp_midi_sj_chapter_tree, offset );
		if ( ext_consumed < 0 ) {
			return ext_consumed;
		}
		offset	 += ext_consumed;
	}

	/* do we have 0xF9 field? */
	if ( header & RTP_MIDI_SJ_CHAPTER_D_FLAG_Y ) {
		ext_consumed = decode_sj_chapter_d_f9( tvb, pinfo, rtp_midi_sj_chapter_tree, offset );
		if ( ext_consumed < 0 ) {
			return ext_consumed;
		}
		offset	 += ext_consumed;
	}

	/* do we have 0xFD field? */
	if ( header & RTP_MIDI_SJ_CHAPTER_D_FLAG_Z ) {
		ext_consumed = decode_sj_chapter_d_fd( tvb, pinfo, rtp_midi_sj_chapter_tree, offset );
		if ( ext_consumed < 0 ) {
			return ext_consumed;
		}
		offset += ext_consumed;
	}


	/* now we know the complete length and set it. */
	proto_item_set_len( tix, offset-start_offset );
	return offset-start_offset;
}

/*
 * Here the chapter Q of the channel-journal is decoded.
 */
static int
decode_sj_chapter_q( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {
	proto_tree			*rtp_midi_sj_chapter_tree;
	uint8_t				header;
	unsigned int start_offset = offset;
	int				len = 1;

	/* first we need to get the flags of this chapter */
	header = tvb_get_uint8( tvb, offset );

	if ( header & RTP_MIDI_SJ_CHAPTER_Q_FLAG_C ) {
		len += 2;
	}
	if ( header & RTP_MIDI_SJ_CHAPTER_Q_FLAG_T ) {
		len += 3;
	}

	/* now we have the length... */
	rtp_midi_sj_chapter_tree = proto_tree_add_subtree( tree, tvb, offset, len, ett_rtp_midi_sj_chapter_q, NULL, RTP_MIDI_TREE_NAME_SJ_CHAPTER_Q );

	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_q_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_q_nflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_q_dflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_q_cflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_q_tflag, tvb, offset, 1, ENC_BIG_ENDIAN );

	if ( header & RTP_MIDI_SJ_CHAPTER_Q_FLAG_C ) {

		proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_q_clock, tvb, offset, 3, ENC_BIG_ENDIAN );

		offset	 += 3;

	} else {
		proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_q_top, tvb, offset, 1, ENC_BIG_ENDIAN );

		offset++;
	}

	if ( header & RTP_MIDI_SJ_CHAPTER_Q_FLAG_T ) {

		proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_q_timetools, tvb, offset, 3, ENC_BIG_ENDIAN );

		offset += 3;
	}

	return offset-start_offset;
}

/*
 * Here the chapter F of the channel-journal is decoded.
 */
static int
decode_sj_chapter_f( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {
	proto_tree			*rtp_midi_sj_chapter_tree;
	uint8_t				header;
	unsigned int start_offset = offset;
	int				len = 1;

	/* first we need to get the flags of this chapter */
	header = tvb_get_uint8( tvb, offset );

	if ( header & RTP_MIDI_SJ_CHAPTER_F_FLAG_C ) {
		len += 4;
	}
	if ( header & RTP_MIDI_SJ_CHAPTER_F_FLAG_P ) {
		len += 4;
	}

	/* now we have the length... */
	rtp_midi_sj_chapter_tree = proto_tree_add_subtree( tree, tvb, offset, len, ett_rtp_midi_sj_chapter_f, NULL, RTP_MIDI_TREE_NAME_SJ_CHAPTER_F );

	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_f_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_f_cflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_f_pflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_f_qflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_f_dflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_f_point, tvb, offset, 1, ENC_BIG_ENDIAN );

	offset++;

	if ( header & RTP_MIDI_SJ_CHAPTER_F_FLAG_C ) {

		if ( header & RTP_MIDI_SJ_CHAPTER_F_FLAG_Q ) {
			static int * const fq_flags[] = {
				&hf_rtp_midi_sj_chapter_f_mt0,
				&hf_rtp_midi_sj_chapter_f_mt1,
				&hf_rtp_midi_sj_chapter_f_mt2,
				&hf_rtp_midi_sj_chapter_f_mt3,
				&hf_rtp_midi_sj_chapter_f_mt4,
				&hf_rtp_midi_sj_chapter_f_mt5,
				&hf_rtp_midi_sj_chapter_f_mt6,
				&hf_rtp_midi_sj_chapter_f_mt7,
				NULL
			};

			proto_tree_add_bitmask(rtp_midi_sj_chapter_tree, tvb, offset, hf_rtp_midi_sj_chapter_f_complete, ett_rtp_midi_sj_chapter_f_complete, fq_flags, ENC_BIG_ENDIAN);
		} else {
			static int * const f_flags[] = {
				&hf_rtp_midi_sj_chapter_f_hr,
				&hf_rtp_midi_sj_chapter_f_mn,
				&hf_rtp_midi_sj_chapter_f_sc,
				&hf_rtp_midi_sj_chapter_f_fr,
				NULL
			};

			proto_tree_add_bitmask(rtp_midi_sj_chapter_tree, tvb, offset, hf_rtp_midi_sj_chapter_f_complete, ett_rtp_midi_sj_chapter_f_complete, f_flags, ENC_BIG_ENDIAN);
		}

		offset	 += 4;
	}

	if ( header & RTP_MIDI_SJ_CHAPTER_F_FLAG_P ) {
		static int * const fp_flags[] = {
			&hf_rtp_midi_sj_chapter_f_mt0,
			&hf_rtp_midi_sj_chapter_f_mt1,
			&hf_rtp_midi_sj_chapter_f_mt2,
			&hf_rtp_midi_sj_chapter_f_mt3,
			&hf_rtp_midi_sj_chapter_f_mt4,
			&hf_rtp_midi_sj_chapter_f_mt5,
			&hf_rtp_midi_sj_chapter_f_mt6,
			&hf_rtp_midi_sj_chapter_f_mt7,
			NULL
		};

		proto_tree_add_bitmask(rtp_midi_sj_chapter_tree, tvb, offset, hf_rtp_midi_sj_chapter_f_partial, ett_rtp_midi_sj_chapter_f_partial, fp_flags, ENC_BIG_ENDIAN);
		offset += 4;
	}

	return offset-start_offset;
}

/*
 * Here the chapter X of the channel-journal is decoded.
 */
static int
decode_sj_chapter_x( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset, unsigned int max_length ) {
	proto_tree			*rtp_midi_sj_chapter_tree;
	proto_tree			*rtp_midi_sj_data_tree;
	uint8_t				header;
	uint8_t				octet;
	unsigned int			consumed = 0;
	unsigned int			cmdlen   = 0;
	unsigned int			i;

	/* first we need to get the flags of this chapter */
	header = tvb_get_uint8( tvb, offset );

	rtp_midi_sj_chapter_tree = proto_tree_add_subtree( tree, tvb, offset, max_length, ett_rtp_midi_sj_chapter_x, NULL, RTP_MIDI_TREE_NAME_SJ_CHAPTER_X );

	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_tflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_cflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_fflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_dflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_lflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_sta, tvb, offset, 1, ENC_BIG_ENDIAN );

	consumed++;
	offset++;

	if ( header & RTP_MIDI_SJ_CHAPTER_X_FLAG_T ) {

		proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_tcount, tvb, offset, 1, ENC_BIG_ENDIAN );

		consumed++;
		offset++;
	}

	if ( header & RTP_MIDI_SJ_CHAPTER_X_FLAG_C ) {

		proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_count, tvb, offset, 1, ENC_BIG_ENDIAN );

		consumed++;
		offset++;
	}

	if ( header & RTP_MIDI_SJ_CHAPTER_X_FLAG_F ) {
		unsigned int field    = 0;
		unsigned int fieldlen = 0;

		/* FIRST is "compressed" using only the necessary amount of octets, like delta-time */
		for ( i=0; i < 4; i++ ) {

			/* do we still fit in the dissected packet & in the length restriction of this chapter? */
			if ( ( !( consumed >= max_length ) ) || ( !tvb_bytes_exist( tvb, offset + fieldlen, 1 ) ) ) {
				return -1;
			}

			octet = tvb_get_uint8( tvb, offset + fieldlen );
			field = ( field << 7 ) | ( octet & RTP_MIDI_DELTA_TIME_OCTET_MASK );
			fieldlen++;

			if ( ( octet & RTP_MIDI_DELTA_TIME_EXTENSION ) == 0 ) {
				break;
			}
		}

		switch (fieldlen) {
			case 1:
			    proto_tree_add_uint ( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_first1, tvb, offset, fieldlen, field );
				break;
			case 2:
			    proto_tree_add_uint ( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_first2, tvb, offset, fieldlen, field );
				break;
			case 3:
			    proto_tree_add_uint ( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_first3, tvb, offset, fieldlen, field );
				break;
			case 4:
			    proto_tree_add_uint ( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_first4, tvb, offset, fieldlen, field );
				break;

		}
		consumed += fieldlen;
		offset	 += fieldlen;

	}

	if ( header & RTP_MIDI_SJ_CHAPTER_X_FLAG_D ) {
		rtp_midi_sj_data_tree = proto_tree_add_subtree( rtp_midi_sj_chapter_tree, tvb, offset,  max_length - consumed,
						ett_rtp_midi_sj_chapter_x_data, NULL, RTP_MIDI_TREE_NAME_SJ_CHAPTER_X_DATA );
		while ( consumed < max_length ) {
			octet = tvb_get_uint8( tvb, offset + cmdlen );
			if ( octet & 0x80 ) {
				proto_tree_add_item( rtp_midi_sj_data_tree, hf_rtp_midi_sj_chapter_x_data, tvb, offset, cmdlen, ENC_NA );
				offset += cmdlen;
				cmdlen	= 0;
			} else {
				cmdlen += 1;
			}
			consumed += 1;
		}
		/* unfinished command still to put into tree */
		if ( cmdlen ) {
			proto_tree_add_item( rtp_midi_sj_data_tree, hf_rtp_midi_sj_chapter_x_invalid_data, tvb, offset, cmdlen, ENC_NA );
			offset += cmdlen;
		}
	}

	/* this should not ever enter - we still have data, but flag d was apparently not set...  */
	if ( consumed < max_length ) {

		proto_tree_add_item( rtp_midi_sj_chapter_tree, hf_rtp_midi_sj_chapter_x_invalid_data, tvb, offset, max_length - consumed, ENC_NA );
		consumed = max_length;
	}

	return consumed;
}



/*
 * Here the system-journal is decoded.
 */
static int
decode_system_journal( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned int offset ) {
	proto_tree			*rtp_midi_sysjournal_tree;
	proto_tree			*rtp_midi_sj_chapters_tree;
	unsigned int start_offset = offset;
	int				ext_consumed = 0;
	uint16_t				sysjourlen;
	uint16_t				systemflags;

	systemflags = tvb_get_ntohs( tvb, offset );
	sysjourlen  = systemflags & RTP_MIDI_SJ_MASK_LENGTH;

	rtp_midi_sysjournal_tree = proto_tree_add_subtree( tree, tvb, offset, sysjourlen, ett_rtp_midi_systemjournal, NULL, RTP_MIDI_TREE_NAME_SYSTEM_JOURNAL );

	proto_tree_add_item( rtp_midi_sysjournal_tree, hf_rtp_midi_sysjour_toc_s, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sysjournal_tree, hf_rtp_midi_sysjour_toc_d, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sysjournal_tree, hf_rtp_midi_sysjour_toc_v, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sysjournal_tree, hf_rtp_midi_sysjour_toc_q, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sysjournal_tree, hf_rtp_midi_sysjour_toc_f, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sysjournal_tree, hf_rtp_midi_sysjour_toc_x, tvb, offset, 2, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_sysjournal_tree, hf_rtp_midi_sysjour_len, tvb, offset, 2, ENC_BIG_ENDIAN );

	offset	 += 2;

	rtp_midi_sj_chapters_tree = proto_tree_add_subtree( rtp_midi_sysjournal_tree, tvb, offset, sysjourlen - 2,
				ett_rtp_midi_systemchapters, NULL, RTP_MIDI_TREE_NAME_SYSTEM_CHAPTERS );

	/* Do we have a simple system commands chapter? */
	if ( systemflags & RTP_MIDI_SJ_FLAG_D ) {
		offset += decode_sj_chapter_d( tvb, pinfo, rtp_midi_sj_chapters_tree, offset );
	}

	/* Do we have a active sensing chapter? */
	if ( systemflags & RTP_MIDI_SJ_FLAG_V ) {
		static int * const v_flags[] = {
			&hf_rtp_midi_sj_chapter_v_sflag,
			&hf_rtp_midi_sj_chapter_v_count,
			NULL
		};

		proto_tree_add_bitmask(rtp_midi_sj_chapters_tree, tvb, offset, hf_rtp_midi_sj_chapter_v, ett_rtp_midi_sj_chapter_v, v_flags, ENC_BIG_ENDIAN);

		offset++;
	}

	/* Do we have a sequencer state commands chapter? */
	if ( systemflags & RTP_MIDI_SJ_FLAG_Q ) {
		offset += decode_sj_chapter_q( tvb, pinfo, rtp_midi_sj_chapters_tree, offset );
	}

	/* Do we have a MTC chapter? */
	if ( systemflags & RTP_MIDI_SJ_FLAG_F ) {
		offset += decode_sj_chapter_f( tvb, pinfo, rtp_midi_sj_chapters_tree, offset );
	}


	/* Do we have a Sysex chapter? */
	if ( systemflags & RTP_MIDI_SJ_FLAG_X ) {
		ext_consumed = decode_sj_chapter_x( tvb, pinfo, rtp_midi_sj_chapters_tree, offset, sysjourlen - (offset-start_offset) );
		if ( ext_consumed < 0 ) {
			return ext_consumed;
		}
		offset += ext_consumed;
	}


	/* Make sanity check for consumed data vs. stated length of system journal */
	if ( offset-start_offset != sysjourlen ) {
		return -1;
	}
	return offset-start_offset;
}






/*
 * This is the main dissector function for the RTP-MIDI protocol
 * It decodes the wrapper of the command-section and punts
 * decoding of delta-time and the actual MIDI-command itself to
 * external decoders.  Afterwards the journal-section is decoded.
 */

static int
dissect_rtp_midi( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_ )
{
	proto_item		*ti;
	proto_tree		*rtp_midi_tree;
	unsigned int		 offset = 0;

	uint8_t			flags;		/* used for command-section and journal-section*/
	unsigned int		cmd_len;
	unsigned int		cmd_count;
	uint8_t			runningstatus;

	int			consumed;

	uint8_t			totchan;

	unsigned int		i;

	col_set_str( pinfo->cinfo, COL_PROTOCOL, RTP_MIDI_DISSECTOR_SHORTNAME );
	col_clear( pinfo->cinfo, COL_INFO );

	/*
	 * MIDI command section
	 */

	/* RTP-MIDI starts with 4 bits of flags... */
	flags = tvb_get_uint8( tvb, offset );

	ti = proto_tree_add_item( tree, proto_rtp_midi, tvb, 0, -1, ENC_NA );
	rtp_midi_tree = proto_item_add_subtree( ti, ett_rtp_midi);

	/* Decode those four flags */
	proto_tree_add_item( rtp_midi_tree, hf_rtp_midi_bflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_tree, hf_rtp_midi_jflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_tree, hf_rtp_midi_zflag, tvb, offset, 1, ENC_BIG_ENDIAN );
	proto_tree_add_item( rtp_midi_tree, hf_rtp_midi_pflag, tvb, offset, 1, ENC_BIG_ENDIAN );

	/* ...followed by a length-field of at least 4 bits */
	cmd_len = flags & RTP_MIDI_CS_MASK_SHORTLEN;

	/* see if we have small or large len-field */
	if (flags & RTP_MIDI_CS_FLAG_B)  {
		cmd_len = tvb_get_ntohs( tvb, offset) & RTP_MIDI_CS_MASK_LONGLEN;
		proto_tree_add_item( rtp_midi_tree, hf_rtp_midi_longlen, tvb, offset, 2, ENC_BIG_ENDIAN );
		offset	+= 2;
	} else {
		proto_tree_add_item( rtp_midi_tree, hf_rtp_midi_shortlen, tvb, offset, 1, ENC_BIG_ENDIAN );
		offset++;
	}

	/* if we have a command-section -> dissect it */
	if ( cmd_len ) {
		proto_tree *rtp_midi_commands_tree;

		rtp_midi_commands_tree = proto_tree_add_subtree( rtp_midi_tree, tvb, offset, cmd_len, ett_rtp_midi_commands, NULL, RTP_MIDI_TREE_NAME_COMMAND );

		/* No commands decoded yet */
		cmd_count = 0;

		/* RTP-MIDI-pdus always start with no running status */
		runningstatus = 0;

		/* Multiple MIDI-commands might follow - the exact number can only be discovered by really decoding the commands! */
		while ( cmd_len) {

			/* for the first command we only have a delta-time if Z-Flag is set */
			if ( ( cmd_count ) || ( flags & RTP_MIDI_CS_FLAG_Z ) ) {

				/* Decode a delta-time */
				consumed = decodetime( tvb, pinfo, rtp_midi_commands_tree, offset );

				/* seek to next command and set remaining length */
				offset  += consumed;
				cmd_len -= consumed;
			}

			/* Only decode MIDI-command if there is any data left - it is valid to only have delta-time! */
			if ( cmd_len ) {

				/* Decode a MIDI-command - if 0 is returned something went wrong */
				// consumed = decodemidi( tvb, pinfo, rtp_midi_commands_tree, cmd_count, offset, cmd_len, &runningstatus, &rsoffset );
				int new_offset = dissect_midi1_message(
					tvb,
					pinfo,
					rtp_midi_commands_tree,
					offset,
					&runningstatus,
					cmd_count == 0
				);
				if (new_offset < 0) {
					return offset;
				}
				consumed = new_offset - offset;

				/* seek to next delta-time and set remaining length */
				offset  += consumed;
				cmd_len -= consumed;

				/* as we have successfully decoded another command, increment count */
				cmd_count++;
			}
		}
	}
	/*
	 * Journal section
	 */

	/* if we have a journal-section -> dissect it */
	if ( flags & RTP_MIDI_CS_FLAG_J ) {
		proto_tree *rtp_midi_journal_tree;

		rtp_midi_journal_tree = proto_tree_add_subtree( rtp_midi_tree, tvb, offset, -1, ett_rtp_midi_journal, NULL, RTP_MIDI_TREE_NAME_JOURNAL );

		/* lets get the main flags from the recovery journal header */
		flags = tvb_get_uint8(     tvb, offset );

		proto_tree_add_item( rtp_midi_journal_tree, hf_rtp_midi_sflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_journal_tree, hf_rtp_midi_yflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_journal_tree, hf_rtp_midi_aflag, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( rtp_midi_journal_tree, hf_rtp_midi_hflag, tvb, offset, 1, ENC_BIG_ENDIAN );

		/* At the same place we find the total channels encoded in the channel journal */
		totchan = flags & RTP_MIDI_JS_MASK_TOTALCHANNELS;
		proto_tree_add_item( rtp_midi_journal_tree, hf_rtp_midi_totchan, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		/* the checkpoint-sequence-number can be used to see if the recovery journal covers all lost events */
		proto_tree_add_item( rtp_midi_journal_tree, hf_rtp_midi_check_seq_num, tvb, offset, 2, ENC_BIG_ENDIAN );
		offset += 2;


		/* do we have system journal? */
		if ( flags & RTP_MIDI_JS_FLAG_Y ) {
			/* first we need to get the flags & length from the system-journal */
			consumed = decode_system_journal( tvb, pinfo, rtp_midi_journal_tree, offset );

			if ( -1 == consumed ) {
				return offset;
			}

			/* seek to optional channel-journals-section */
			offset += consumed;

		}

		/* do we have channel journal(s)? */
		if ( flags & RTP_MIDI_JS_FLAG_A ) {
			proto_tree *rtp_midi_chanjournals_tree;
			rtp_midi_chanjournals_tree = proto_tree_add_subtree( rtp_midi_journal_tree, tvb, offset, -1, ett_rtp_midi_channeljournals, NULL, RTP_MIDI_TREE_NAME_CHANNEL_JOURNAL );

			/* iterate through all the channels specified in header */
			for ( i = 0; i <= totchan; i++ ) {

				consumed = decode_channel_journal( tvb, pinfo, rtp_midi_chanjournals_tree, offset );

				if ( -1 == consumed ) {
					return offset;
				}

				/* seek to next channel-journal */
				offset += consumed;

			}
		}
	}
	return tvb_captured_length(tvb);
}




void
proto_register_rtp_midi( void )
{
	module_t *rtp_midi_module;

	static hf_register_info hf[] = {
		{
			&hf_rtp_midi_bflag,
			{
				"B-Flag",
				"rtpmidi.b_flag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cs_flag_b),
				RTP_MIDI_CS_FLAG_B,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_jflag,
			{
				"J-Flag",
				"rtpmidi.j_flag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cs_flag_j),
				RTP_MIDI_CS_FLAG_J,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_zflag,
			{
				"Z-Flag",
				"rtpmidi.z_flag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cs_flag_z),
				RTP_MIDI_CS_FLAG_Z,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_pflag,
			{
				"P-Flag",
				"rtpmidi.p_flag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cs_flag_p),
				RTP_MIDI_CS_FLAG_P,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_shortlen,
			{
				"Command length (short)",
				"rtpmidi.cmd_length_short",
				FT_UINT8,
				BASE_DEC,
				NULL,
				RTP_MIDI_CS_MASK_SHORTLEN,
				NULL, HFILL
			}
		},
			{
			&hf_rtp_midi_longlen,
			{
				"Command length (long)",
				"rtpmidi.cmd_length_long",
				FT_UINT16,
				BASE_DEC,
				NULL,
				RTP_MIDI_CS_MASK_LONGLEN,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sflag,
			{
				"S-Flag",
				"rtpmidi.s_flag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				RTP_MIDI_JS_FLAG_S,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_yflag,
			{
				"Y-Flag",
				"rtpmidi.y_flag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_y),
				RTP_MIDI_JS_FLAG_Y,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_aflag,
			{
				"A-Flag",
				"rtpmidi.a_flag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_a),
				RTP_MIDI_JS_FLAG_A,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_hflag,
			{
				"H-Flag",
				"rtpmidi.h_flag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_h),
				RTP_MIDI_JS_FLAG_H,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_totchan,
			{
				"Total channels",
				"rtpmidi.total_channels",
				FT_UINT8,
				BASE_DEC,
				VALS(rtp_midi_js_tot_channels),
				RTP_MIDI_JS_MASK_TOTALCHANNELS,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_check_seq_num,
			{
				"Checkpoint Packet Seqnum",
				"rtpmidi.check_Seq_num",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x00,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_deltatime1,
			{
				"Delta Time (one octet)",
				"rtpmidi.deltatime_1",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_deltatime2,
			{
				"Delta Time (two octets)",
				"rtpmidi.deltatime_2",
				FT_UINT16,
				BASE_HEX,
				NULL,
				0x7f7f,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_deltatime3,
			{
				"Delta Time (three octets)",
				"rtpmidi.deltatime_3",
				FT_UINT24,
				BASE_HEX,
				NULL,
				0x7f7f7f,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_deltatime4,
			{
				"Delta Time (four octets)",
				"rtpmidi.deltatime_4",
				FT_UINT32,
				BASE_HEX,
				NULL,
				0x7f7f7f7f,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sysjour_toc_s,
			{
				"System-Journal TOC-S-Flag",
				"rtpmidi.sysjour_toc_s",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_js_flag_s),
				RTP_MIDI_SJ_FLAG_S,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sysjour_toc_d,
			{
				"System-Journal TOC-D-Flag",
				"rtpmidi.sysjour_toc_d",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_sj_flag_d),
				RTP_MIDI_SJ_FLAG_D,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sysjour_toc_v,
			{
				"System-Journal TOC-V-Flag",
				"rtpmidi.sysjour_toc_v",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_sj_flag_v),
				RTP_MIDI_SJ_FLAG_V,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sysjour_toc_q,
			{
				"System-Journal TOC-Q-Flag",
				"rtpmidi.sysjour_toc_q",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_sj_flag_q),
				RTP_MIDI_SJ_FLAG_Q,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sysjour_toc_f,
			{
				"System-Journal TOC-F-Flag",
				"rtpmidi.sysjour_toc_f",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_sj_flag_f),
				RTP_MIDI_SJ_FLAG_F,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sysjour_toc_x,
			{
				"System-Journal TOC-X-Flag",
				"rtpmidi.sysjour_toc_x",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_sj_flag_x),
				RTP_MIDI_SJ_FLAG_X,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sysjour_len,
			{
				"System-Journal-Length",
				"rtpmidi.cmd_sysjour_len",
				FT_UINT16,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_MASK_LENGTH,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_chanjour_sflag,
			{
				"Channel-Journal S-Flag",
				"rtpmidi.chanjour_s",
				FT_BOOLEAN,
				24,
				TFS(&rtp_midi_js_flag_s),
				0x800000,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_chanjour_chan,
			{
				"Channel",
				"rtpmidi.chanjour_channel",
				FT_UINT24,
				BASE_HEX,
				VALS(midi_channels),
				0x780000,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_chanjour_hflag,
			{
				"Channel-Journal H-Flag",
				"rtpmidi.chanjour_h",
				FT_BOOLEAN,
				24,
				TFS(&rtp_midi_js_flag_h),
				0x040000,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_chanjour_len,
			{
				"Channel-Journal-Length",
				"rtpmidi.cmd_chanjour_len",
				FT_UINT24,
				BASE_DEC,
				NULL,
				0x03FF00,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_chanjour_toc_p,
			{
				"Channel-Journal TOC-P-Flag",
				"rtpmidi.chanjour_toc_p",
				FT_BOOLEAN,
				24,
				TFS(&rtp_midi_cj_flag_p),
				0x000080,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_chanjour_toc_c,
			{
				"Channel-Journal TOC-C-Flag",
				"rtpmidi.chanjour_toc_c",
				FT_BOOLEAN,
				24,
				TFS(&rtp_midi_cj_flag_c),
				0x000040,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_chanjour_toc_m,
			{
				"Channel-Journal TOC-M-Flag",
				"rtpmidi.chanjour_toc_m",
				FT_BOOLEAN,
				24,
				TFS(&rtp_midi_cj_flag_m),
				0x000020,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_chanjour_toc_w,
			{
				"Channel-Journal TOC-W-Flag",
				"rtpmidi.chanjour_toc_w",
				FT_BOOLEAN,
				24,
				TFS(&rtp_midi_cj_flag_w),
				0x000010,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_chanjour_toc_n,
			{
				"Channel-Journal TOC-N-Flag",
				"rtpmidi.chanjour_toc_n",
				FT_BOOLEAN,
				24,
				TFS(&rtp_midi_cj_flag_n),
				0x000008,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_chanjour_toc_e,
			{
				"Channel-Journal TOC-E-Flag",
				"rtpmidi.chanjour_toc_e",
				FT_BOOLEAN,
				24,
				TFS(&rtp_midi_cj_flag_e),
				0x000004,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_chanjour_toc_t,
			{
				"Channel-Journal TOC-T-Flag",
				"rtpmidi.chanjour_toc_t",
				FT_BOOLEAN,
				24,
				TFS(&rtp_midi_cj_flag_t),
				0x000002,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_chanjour_toc_a,
			{
				"Channel-Journal TOC-A-Flag",
				"rtpmidi.chanjour_toc_a",
				FT_BOOLEAN,
				24,
				TFS(&rtp_midi_cj_flag_a),
				0x000001,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_p_sflag,
			{
				"Chapter P S-Flag",
				"rtpmidi.cj_chapter_p_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_p_program,
			{
				"Chapter P Program",
				"rtpmidi.cj_chapter_p_program",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_p_bflag,
			{
				"Chapter P B-Flag",
				"rtpmidi.cj_chapter_p_bflag",
				FT_BOOLEAN,
				8,
				NULL,
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_p_bank_msb,
			{
				"Chapter P Bank-MSB",
				"rtpmidi.cj_chapter_p_bank_msb",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_p_xflag,
			{
				"Chapter P X-Flag",
				"rtpmidi.cj_chapter_p_xflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_p_log_flag_x),
				0x80,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_cj_chapter_p_bank_lsb,
			{
				"Chapter P Bank-LSB",
				"rtpmidi.cj_chapter_p_bank_lsb",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_c_sflag,
			{
				"Chapter C S-Flag",
				"rtpmidi.cj_chapter_c_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_c_length,
			{
				"Chapter C Length",
				"rtpmidi.cj_chapter_c_length",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_c_number,
			{
				"Chapter C Number",
				"rtpmidi.cj_chapter_c_number",
				FT_UINT8,
				BASE_DEC | BASE_EXT_STRING,
				&midi_controller_values_ext,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_c_aflag,
			{
				"Chapter C A-Flag",
				"rtpmidi.cj_chapter_c_aflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_c_flag_a),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_c_tflag,
			{
				"Chapter C T-Flag",
				"rtpmidi.cj_chapter_c_tflag",
				FT_BOOLEAN,
				8,
				NULL,
				0x40,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_c_value,
			{
				"Chapter C Value",
				"rtpmidi.cj_chapter_c_value",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_c_alt,
			{
				"Chapter C Alt",
				"rtpmidi.cj_chapter_c_alt",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x3f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_sflag,
			{
				"Chapter M S-Flag",
				"rtpmidi.cj_chapter_m_sflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_js_flag_s),
				0x8000,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_pflag,
			{
				"Chapter M P-Flag",
				"rtpmidi.cj_chapter_m_pflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_cj_chapter_m_flag_p),
				0x4000,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_eflag,
			{
				"Chapter M E-Flag",
				"rtpmidi.cj_chapter_m_eflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_cj_chapter_m_flag_e),
				0x2000,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_uflag,
			{
				"Chapter M U-Flag",
				"rtpmidi.cj_chapter_m_uflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_cj_chapter_m_flag_u),
				0x1000,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_wflag,
			{
				"Chapter M W-Flag",
				"rtpmidi.cj_chapter_m_wflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_cj_chapter_m_flag_w),
				0x0800,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_zflag,
			{
				"Chapter M Z-Flag",
				"rtpmidi.cj_chapter_m_zflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_cj_chapter_m_flag_z),
				0x0400,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_length,
			{
				"Chapter M Length",
				"rtpmidi.cj_chapter_m_length",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x03ff,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_qflag,
			{
				"Chapter M Q-Flag",
				"rtpmidi.cj_chapter_m_qflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_flag_q),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_pending,
			{
				"Chapter M Pending",
				"rtpmidi.cj_chapter_m_pending",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_sflag,
			{
				"Chapter M Log S-Flag",
				"rtpmidi.cj_chapter_m_log_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_pnum_lsb,
			{
				"Chapter M Log PNUM-LSB",
				"rtpmidi.cj_chapter_m_log_pnum_lsb",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_qflag,
			{
				"Chapter M Log Q-Flag",
				"rtpmidi.cj_chapter_m_log_qflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_q),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_pnum_msb,
			{
				"Chapter M Log PNUM-MSB",
				"rtpmidi.cj_chapter_m_log_pnum_msb",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_jflag,
			{
				"Chapter M Log J-Flag",
				"rtpmidi.cj_chapter_m_log_jflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_j),
				RTP_MIDI_CJ_CHAPTER_M_FLAG_J,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_kflag,
			{
				"Chapter M Log K-Flag",
				"rtpmidi.cj_chapter_m_log_kflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_k),
				RTP_MIDI_CJ_CHAPTER_M_FLAG_K,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_lflag,
			{
				"Chapter M Log L-Flag",
				"rtpmidi.cj_chapter_m_log_lflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_l),
				RTP_MIDI_CJ_CHAPTER_M_FLAG_L,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_mflag,
			{
				"Chapter M Log M-Flag",
				"rtpmidi.cj_chapter_m_log_mflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_m),
				RTP_MIDI_CJ_CHAPTER_M_FLAG_M,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_nflag,
			{
				"Chapter M Log N-Flag",
				"rtpmidi.cj_chapter_m_log_nflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_n),
				RTP_MIDI_CJ_CHAPTER_M_FLAG_N,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_tflag,
			{
				"Chapter M Log T-Flag",
				"rtpmidi.cj_chapter_m_log_tflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_t),
				RTP_MIDI_CJ_CHAPTER_M_FLAG_T,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_vflag,
			{
				"Chapter M Log V-Flag",
				"rtpmidi.cj_chapter_m_log_vflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_v),
				RTP_MIDI_CJ_CHAPTER_M_FLAG_V,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_rflag,
			{
				"Chapter M Log R-Flag",
				"rtpmidi.cj_chapter_m_log_rflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_r),
				RTP_MIDI_CJ_CHAPTER_M_FLAG_R,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_msb_entry,
			{
				"Entry MSB",
				"rtpmidi.cj_chapter_m_log_msb_entry",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_msb_x,
			{
				"Chapter M Log MSB X-Flag",
				"rtpmidi.cj_chapter_m_log_msb_xflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_x),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_msb,
			{
				"Chapter M Log MSB",
				"rtpmidi.cj_chapter_m_log_msb",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_lsb_entry,
			{
				"Entry LSB",
				"rtpmidi.cj_chapter_m_log_lsb_entry",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_lsb_x,
			{
				"Chapter M Log LSB X-Flag",
				"rtpmidi.cj_chapter_m_log_lsb_xflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_x),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_lsb,
			{
				"Chapter M Log LSB",
				"rtpmidi.cj_chapter_m_log_lsb",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_a_button_g,
			{
				"Chapter M Log A-Button G-Flag",
				"rtpmidi.cj_chapter_m_log_a_button_gflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_cj_chapter_m_log_flag_g),
				0x8000,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_a_button_x,
			{
				"Chapter M Log A-Button X-Flag",
				"rtpmidi.cj_chapter_m_log_a_button_xflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_cj_chapter_m_log_flag_x),
				0x4000,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_a_button,
			{
				"Chapter M Log A-Button",
				"rtpmidi.cj_chapter_m_log_a_button",
				FT_UINT16,
				BASE_HEX,
				NULL,
				0x3fff,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_a_button_full,
			{
				"A-Button",
				"rtpmidi.cj_chapter_m_log_a_button_full",
				FT_UINT16,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_c_button_g,
			{
				"Chapter M Log C-Button G-Flag",
				"rtpmidi.cj_chapter_m_log_c_button_gflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_cj_chapter_m_log_flag_g),
				0x8000,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_c_button_r,
			{
				"Chapter M Log C-Button R-Flag",
				"rtpmidi.cj_chapter_m_log_c_button_rflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_cj_chapter_m_log_flag_r),
				0x4000,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_c_button,
			{
				"Chapter M Log C-Button",
				"rtpmidi.cj_chapter_m_log_c_button",
				FT_UINT16,
				BASE_HEX,
				NULL,
				0x3fff,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_c_button_full,
			{
				"C-Button",
				"rtpmidi.cj_chapter_m_log_c_button_full",
				FT_UINT16,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_count_x,
			{
				"Chapter M Log Count X-Flag",
				"rtpmidi.cj_chapter_m_log_count_xflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_x),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_count,
			{
				"Chapter M Log Count",
				"rtpmidi.cj_chapter_m_log_count",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_m_log_count_full,
			{
				"Count",
				"rtpmidi.cj_chapter_m_log_count_full",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_w_sflag,
			{
				"Chapter W S-Flag",
				"rtpmidi.cj_chapter_w_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_w_first,
			{
				"Chapter W First",
				"rtpmidi.cj_chapter_w_first",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_w_rflag,
			{
				"Chapter W R-Flag",
				"rtpmidi.cj_chapter_w_rflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_m_log_flag_r),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_w_second,
			{
				"Chapter W Second",
				"rtpmidi.cj_chapter_w_second",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_n_bflag,
			{
				"Chapter N B-Flag",
				"rtpmidi.cj_chapter_n_bflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_js_flag_s),
				0x8000,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_n_len,
			{
				"Chapter N Length",
				"rtpmidi.cj_chapter_n_length",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x7f00,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_n_low,
			{
				"Chapter N Low",
				"rtpmidi.cj_chapter_n_low",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x00f0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_n_high,
			{
				"Chapter N High",
				"rtpmidi.cj_chapter_n_high",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x000f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_n_log_sflag,
			{
				"Chapter N Log S-Flag",
				"rtpmidi.cj_chapter_n_log_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_n_log_notenum,
			{
				"Chapter N Log Note",
				"rtpmidi.cj_chapter_n_log_note",
				FT_UINT8,
				BASE_DEC | BASE_EXT_STRING,
				&midi_note_values_ext,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_n_log_yflag,
			{
				"Chapter N Log Y-Flag",
				"rtpmidi.cj_chapter_n_log_yflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_n_log_flag_y),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_n_log_velocity,
			{
				"Chapter N Log Velocity",
				"rtpmidi.cj_chapter_n_log_velocity",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_n_log_octet,
			{
				"Chapter N Log Octet",
				"rtpmidi.cj_chapter_n_log_octet",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0xff,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_e_sflag,
			{
				"Chapter E S-Flag",
				"rtpmidi.cj_chapter_e_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_e_len,
			{
				"Chapter E Length",
				"rtpmidi.cj_chapter_e_length",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_e_log_sflag,
			{
				"Chapter E Log S-Flag",
				"rtpmidi.cj_chapter_e_log_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_e_log_notenum,
			{
				"Chapter E Log Note",
				"rtpmidi.cj_chapter_e_log_note",
				FT_UINT8,
				BASE_DEC | BASE_EXT_STRING,
				&midi_note_values_ext,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_e_log_vflag,
			{
				"Chapter N Log V-Flag",
				"rtpmidi.cj_chapter_n_log_vflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_e_log_flag_v),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_e_log_velocity,
			{
				"Chapter E Log Velocity",
				"rtpmidi.cj_chapter_e_log_velocity",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_e_log_count,
			{
				"Chapter E Log Count",
				"rtpmidi.cj_chapter_e_log_count",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_t_channel_aftertouch,
			{
				"Channel Aftertouch",
				"rtpmidi.cj_chapter_t_channel_aftertouch",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_t_sflag,
			{
				"Chapter T S-Flag",
				"rtpmidi.cj_chapter_t_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_t_pressure,
			{
				"Chapter T Pressure",
				"rtpmidi.cj_chapter_t_pressure",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_a_sflag,
			{
				"Chapter A S-Flag",
				"rtpmidi.cj_chapter_a_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_a_len,
			{
				"Chapter A Length",
				"rtpmidi.cj_chapter_a_length",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_a_log_sflag,
			{
				"Chapter A Log S-Flag",
				"rtpmidi.cj_chapter_a_log_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_a_log_notenum,
			{
				"Chapter A Log Note",
				"rtpmidi.cj_chapter_a_log_note",
				FT_UINT8,
				BASE_DEC | BASE_EXT_STRING,
				&midi_note_values_ext,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_a_log_xflag,
			{
				"Chapter A Log X-Flag",
				"rtpmidi.cj_chapter_a_log_xflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_cj_chapter_a_log_flag_x),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_cj_chapter_a_log_pressure,
			{
				"Chapter A Log Pressure",
				"rtpmidi.cj_chapter_a_log_pressure",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_v,
			{
				"Active Sensing",
				"rtpmidi.sj_chapter_v",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_v_sflag,
			{
				"Chapter V S-Flag",
				"rtpmidi.sj_chapter_v_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				0x80,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_v_count,
			{
				"Chapter V Count",
				"rtpmidi.sj_chapter_v_count",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_simple_system_commands,
			{
				"Simple System Commands",
				"rtpmidi.sj_chapter_d_simple_system_commands",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_sflag,
			{
				"Chapter D S-Flag",
				"rtpmidi.sj_chapter_d_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				RTP_MIDI_SJ_CHAPTER_D_FLAG_S,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_bflag,
			{
				"Chapter D B-Flag",
				"rtpmidi.sj_chapter_d_bflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_d_flag_b),
				RTP_MIDI_SJ_CHAPTER_D_FLAG_B,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_gflag,
			{
				"Chapter D G-Flag",
				"rtpmidi.sj_chapter_d_gflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_d_flag_g),
				RTP_MIDI_SJ_CHAPTER_D_FLAG_G,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_hflag,
			{
				"Chapter D H-Flag",
				"rtpmidi.sj_chapter_d_hflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_d_flag_h),
				RTP_MIDI_SJ_CHAPTER_D_FLAG_H,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_jflag,
			{
				"Chapter D J-Flag",
				"rtpmidi.sj_chapter_d_jflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_d_flag_j),
				RTP_MIDI_SJ_CHAPTER_D_FLAG_J,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_kflag,
			{
				"Chapter D K-Flag",
				"rtpmidi.sj_chapter_d_kflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_d_flag_k),
				RTP_MIDI_SJ_CHAPTER_D_FLAG_K,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_yflag,
			{
				"Chapter D Y-Flag",
				"rtpmidi.sj_chapter_d_yflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_d_flag_y),
				RTP_MIDI_SJ_CHAPTER_D_FLAG_Y,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_zflag,
			{
				"Chapter D Z-Flag",
				"rtpmidi.sj_chapter_d_zflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_d_flag_z),
				RTP_MIDI_SJ_CHAPTER_D_FLAG_Z,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_reset,
			{
				"Reset Field",
				"rtpmidi.cj_chapter_d_reset",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_reset_sflag,
			{
				"Chapter D Reset S-Flag",
				"rtpmidi.sj_chapter_d_reset_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				RTP_MIDI_SJ_CHAPTER_D_RESET_FLAG_S,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_reset_count,
			{
				"Chapter D Reset Count",
				"rtpmidi.cj_chapter_d_reset_count",
				FT_UINT8,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_D_RESET_COUNT,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_tune,
			{
				"Tune Request Field",
				"rtpmidi.cj_chapter_d_tune",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_tune_sflag,
			{
				"Chapter D Tune Request S-Flag",
				"rtpmidi.sj_chapter_d_tune_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				RTP_MIDI_SJ_CHAPTER_D_TUNE_FLAG_S,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_tune_count,
			{
				"Chapter D Tune Request Count",
				"rtpmidi.cj_chapter_d_tune_count",
				FT_UINT8,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_D_TUNE_COUNT,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_song_sel,
			{
				"Song Select Field",
				"rtpmidi.cj_chapter_d_song_sel",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_song_sel_sflag,
			{
				"Chapter D Song Select S-Flag",
				"rtpmidi.sj_chapter_d_song_sel_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				RTP_MIDI_SJ_CHAPTER_D_SONG_SEL_FLAG_S,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_song_sel_value,
			{
				"Chapter D Song Select Value",
				"rtpmidi.cj_chapter_d_song_sel_value",
				FT_UINT8,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_D_SONG_SEL_VALUE,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_syscom_sflag,
			{
				"Chapter D System Common (F4/F5) S-Flag",
				"rtpmidi.sj_chapter_d_syscom_sflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_js_flag_s),
				RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_S,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_d_syscom_cflag,
			{
				"Chapter D System Common (F4/F5) C-Flag",
				"rtpmidi.sj_chapter_d_syscom_cflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_sj_chapter_d_syscom_flag_c),
				RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_C,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_syscom_vflag,
			{
				"Chapter D System Common (F4/F5) V-Flag",
				"rtpmidi.sj_chapter_d_syscom_vflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_sj_chapter_d_syscom_flag_v),
				RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_V,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_syscom_lflag,
			{
				"Chapter D System Common (F4/F5) L-Flag",
				"rtpmidi.sj_chapter_d_syscom_lflag",
				FT_BOOLEAN,
				16,
				TFS(&rtp_midi_sj_chapter_d_syscom_flag_l),
				RTP_MIDI_SJ_CHAPTER_D_SYSCOM_FLAG_L,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_syscom_dsz,
			{
				"Chapter D System Common (F4/F5) DSZ",
				"rtpmidi.sj_chapter_d_syscom_dsz",
				FT_UINT16,
				BASE_DEC,
				VALS(rtp_midi_sj_chapter_d_syscom_dsz_values),
				RTP_MIDI_SJ_CHAPTER_D_SYSCOM_MASK_DSZ,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_syscom_length,
			{
				"Chapter D System Common (F4/F5) Length",
				"rtpmidi.sj_chapter_d_syscom_len",
				FT_UINT16,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_D_SYSCOM_MASK_LENGTH,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_syscom_count,
			{
				"Chapter D System Common (F4/F5) Count",
				"rtpmidi.sj_chapter_d_syscom_count",
				FT_UINT8,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_D_SYSCOM_MASK_COUNT,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_syscom_value,
			{
				"Chapter D System Common (F4/F5) Value",
				"rtpmidi.sj_chapter_d_syscom_value",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x00,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_syscom_legal,
			{
				"Chapter D System Common (F4/F5) Legal - for future extension",
				"rtpmidi.sj_chapter_d_syscom_legal",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x00,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_syscom_data,
			{
				"Chapter D System Common (F4/F5) Erroneous Data",
				"rtpmidi.sj_chapter_d_syscom_data",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x00,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_sysreal_sflag,
			{
				"Chapter D System Realtime (F9/FD) S-Flag",
				"rtpmidi.sj_chapter_d_sysreal_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				RTP_MIDI_SJ_CHAPTER_D_SYSREAL_FLAG_S,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_sysreal_cflag,
			{
				"Chapter D System Realtime (F9/FF) C-Flag",
				"rtpmidi.sj_chapter_d_sysreal_cflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_d_syscom_flag_c),
				RTP_MIDI_SJ_CHAPTER_D_SYSREAL_FLAG_C,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_sysreal_lflag,
			{
				"Chapter D System Realtime (F9/FD) L-Flag",
				"rtpmidi.sj_chapter_d_sysreal_lflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_d_syscom_flag_l),
				RTP_MIDI_SJ_CHAPTER_D_SYSREAL_FLAG_L,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_sysreal_length,
			{
				"Chapter D System Realtime (F9/FD) Length",
				"rtpmidi.sj_chapter_d_sysreal_len",
				FT_UINT8,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_D_SYSREAL_MASK_LENGTH,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_sysreal_count,
			{
				"Chapter D System Realtime (F9/FD) Count",
				"rtpmidi.sj_chapter_d_sysreal_count",
				FT_UINT8,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_D_SYSREAL_MASK_COUNT,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_sysreal_legal,
			{
				"Chapter D System Realtime (F9/FD) Legal - for future extension",
				"rtpmidi.sj_chapter_d_sysreal_legal",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x00,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_d_sysreal_data,
			{
				"Chapter D System Realtime (F9/FD) Erroneous Data",
				"rtpmidi.sj_chapter_d_sysreal_data",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x00,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_q_sflag,
			{
				"Chapter Q Sequencer State S-Flag",
				"rtpmidi.sj_chapter_q_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				RTP_MIDI_SJ_CHAPTER_Q_FLAG_S,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_q_nflag,
			{
				"Chapter Q Sequencer State N-Flag",
				"rtpmidi.sj_chapter_q_nflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_q_flag_n),
				RTP_MIDI_SJ_CHAPTER_Q_FLAG_N,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_q_dflag,
			{
				"Chapter Q Sequencer State D-Flag",
				"rtpmidi.sj_chapter_q_dflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_q_flag_d),
				RTP_MIDI_SJ_CHAPTER_Q_FLAG_D,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_q_cflag,
			{
				"Chapter Q Sequencer State C-Flag",
				"rtpmidi.sj_chapter_q_cflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_q_flag_c),
				RTP_MIDI_SJ_CHAPTER_Q_FLAG_C,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_q_tflag,
			{
				"Chapter Q Sequencer State T-Flag",
				"rtpmidi.sj_chapter_q_tflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_q_flag_t),
				RTP_MIDI_SJ_CHAPTER_Q_FLAG_T,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_q_top,
			{
				"Chapter Q Sequencer State Top",
				"rtpmidi.sj_chapter_q_top",
				FT_UINT8,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_Q_MASK_TOP,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_q_clock,
			{
				"Chapter Q Sequencer State Clock",
				"rtpmidi.sj_chapter_q_clock",
				FT_UINT24,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_Q_MASK_CLOCK,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_q_timetools,
			{
				"Chapter Q Sequencer State Timetools",
				"rtpmidi.sj_chapter_q_timetools",
				FT_UINT24,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_Q_MASK_TIMETOOLS,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_midi_sj_chapter_f_sflag,
			{
				"Chapter F MTC S-Flag",
				"rtpmidi.sj_chapter_f_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				RTP_MIDI_SJ_CHAPTER_F_FLAG_S,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_cflag,
			{
				"Chapter F MTC C-Flag",
				"rtpmidi.sj_chapter_f_cflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_f_flag_c),
				RTP_MIDI_SJ_CHAPTER_F_FLAG_C,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_pflag,
			{
				"Chapter F MTC P-Flag",
				"rtpmidi.sj_chapter_f_pflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_f_flag_p),
				RTP_MIDI_SJ_CHAPTER_F_FLAG_P,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_qflag,
			{
				"Chapter F MTC Q-Flag",
				"rtpmidi.sj_chapter_f_qflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_f_flag_q),
				RTP_MIDI_SJ_CHAPTER_F_FLAG_Q,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_dflag,
			{
				"Chapter F MTC D-Flag",
				"rtpmidi.sj_chapter_f_dflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_f_flag_d),
				RTP_MIDI_SJ_CHAPTER_F_FLAG_D,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_point,
			{
				"Chapter F MTC Point",
				"rtpmidi.sj_chapter_f_point",
				FT_UINT8,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_POINT,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_complete,
			{
				"Complete field",
				"rtpmidi.sj_chapter_f_complete",
				FT_UINT32,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_partial,
			{
				"Partial field",
				"rtpmidi.sj_chapter_f_partial",
				FT_UINT32,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_mt0,
			{
				"Chapter F MTC MT0",
				"rtpmidi.sj_chapter_f_mt0",
				FT_UINT32,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_MT0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_mt1,
			{
				"Chapter F MTC MT1",
				"rtpmidi.sj_chapter_f_mt1",
				FT_UINT32,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_MT1,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_mt2,
			{
				"Chapter F MTC MT2",
				"rtpmidi.sj_chapter_f_mt2",
				FT_UINT32,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_MT2,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_mt3,
			{
				"Chapter F MTC MT3",
				"rtpmidi.sj_chapter_f_mt3",
				FT_UINT32,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_MT3,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_mt4,
			{
				"Chapter F MTC MT4",
				"rtpmidi.sj_chapter_f_mt4",
				FT_UINT32,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_MT4,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_mt5,
			{
				"Chapter F MTC MT5",
				"rtpmidi.sj_chapter_f_mt5",
				FT_UINT32,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_MT5,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_mt6,
			{
				"Chapter F MTC MT6",
				"rtpmidi.sj_chapter_f_mt6",
				FT_UINT32,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_MT6,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_mt7,
			{
				"Chapter F MTC MT7",
				"rtpmidi.sj_chapter_f_mt7",
				FT_UINT32,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_MT7,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_hr,
			{
				"Chapter F MTC Hour",
				"rtpmidi.sj_chapter_f_hr",
				FT_UINT32,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_HR,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_mn,
			{
				"Chapter F MTC Minute",
				"rtpmidi.sj_chapter_f_mn",
				FT_UINT32,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_MN,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_sc,
			{
				"Chapter F MTC Second",
				"rtpmidi.sj_chapter_f_sc",
				FT_UINT32,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_SC,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_f_fr,
			{
				"Chapter F MTC Frame",
				"rtpmidi.sj_chapter_f_fr",
				FT_UINT32,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_F_MASK_FR,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_sflag,
			{
				"Chapter X Sysex S-Flag",
				"rtpmidi.sj_chapter_x_sflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_js_flag_s),
				RTP_MIDI_SJ_CHAPTER_X_FLAG_S,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_tflag,
			{
				"Chapter X Sysex T-Flag",
				"rtpmidi.sj_chapter_x_tflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_x_flag_t),
				RTP_MIDI_SJ_CHAPTER_X_FLAG_T,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_cflag,
			{
				"Chapter X Sysex C-Flag",
				"rtpmidi.sj_chapter_x_cflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_x_flag_c),
				RTP_MIDI_SJ_CHAPTER_X_FLAG_C,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_fflag,
			{
				"Chapter X Sysex F-Flag",
				"rtpmidi.sj_chapter_x_fflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_x_flag_f),
				RTP_MIDI_SJ_CHAPTER_X_FLAG_F,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_dflag,
			{
				"Chapter X Sysex D-Flag",
				"rtpmidi.sj_chapter_x_dflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_x_flag_d),
				RTP_MIDI_SJ_CHAPTER_X_FLAG_D,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_lflag,
			{
				"Chapter X Sysex L-Flag",
				"rtpmidi.sj_chapter_x_lflag",
				FT_BOOLEAN,
				8,
				TFS(&rtp_midi_sj_chapter_x_flag_l),
				RTP_MIDI_SJ_CHAPTER_X_FLAG_L,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_sta,
			{
				"Chapter X Sysex STA",
				"rtpmidi.sj_chapter_x_sta",
				FT_UINT8,
				BASE_HEX,
				NULL,
				RTP_MIDI_SJ_CHAPTER_X_MASK_STA,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_tcount,
			{
				"Chapter X Sysex TCOUT",
				"rtpmidi.sj_chapter_x_tcount",
				FT_UINT8,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_X_MASK_TCOUNT,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_count,
			{
				"Chapter X Sysex COUNT",
				"rtpmidi.sj_chapter_x_count",
				FT_UINT8,
				BASE_DEC,
				NULL,
				RTP_MIDI_SJ_CHAPTER_X_MASK_COUNT,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_first1,
			{
				"Chapter X Sysex FIRST (one octet)",
				"rtpmidi.sj_chapter_x_first_1",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x7f,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_first2,
			{
				"Chapter X Sysex FIRST (two octets)",
				"rtpmidi.sj_chapter_x_first_2",
				FT_UINT16,
				BASE_HEX,
				NULL,
				0x7f7f,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_first3,
			{
				"Chapter X Sysex FIRST (three octets)",
				"rtpmidi.sj_chapter_x_first_3",
				FT_UINT24,
				BASE_HEX,
				NULL,
				0x7f7f7f,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_first4,
			{
				"Chapter X Sysex FIRST (four octets)",
				"rtpmidi.sj_chapter_x_first_4",
				FT_UINT32,
				BASE_HEX,
				NULL,
				0x7f7f7f7f,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_data,
			{
				"Chapter X Sysex Data",
				"rtpmidi.sj_chapter_x_data",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x00,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_midi_sj_chapter_x_invalid_data,
			{
				"Chapter X Invalid Sysex Data",
				"rtpmidi.sj_chapter_x_invalid_data",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x00,
				NULL, HFILL
			}
		},


	};





	static int *ett[] = {
		&ett_rtp_midi,
		&ett_rtp_midi_commands,
		&ett_rtp_midi_journal,
		&ett_rtp_midi_systemjournal,
		&ett_rtp_midi_channeljournals,
		&ett_rtp_midi_channelchapters,
		&ett_rtp_midi_cj_chapter_p,
		&ett_rtp_midi_cj_chapter_c,
		&ett_rtp_midi_cj_chapter_c_loglist,
		&ett_rtp_midi_cj_chapter_c_logitem,
		&ett_rtp_midi_cj_chapter_m,
		&ett_rtp_midi_cj_chapter_m_loglist,
		&ett_rtp_midi_cj_chapter_m_logitem,
		&ett_rtp_midi_cj_chapter_m_log_msb,
		&ett_rtp_midi_cj_chapter_m_log_lsb,
		&ett_rtp_midi_cj_chapter_m_log_a_button,
		&ett_rtp_midi_cj_chapter_m_log_c_button,
		&ett_rtp_midi_cj_chapter_m_log_count,
		&ett_rtp_midi_cj_chapter_w,
		&ett_rtp_midi_cj_chapter_n,
		&ett_rtp_midi_cj_chapter_n_loglist,
		&ett_rtp_midi_cj_chapter_n_logitem,
		&ett_rtp_midi_cj_chapter_n_octets,
		&ett_rtp_midi_cj_chapter_e,
		&ett_rtp_midi_cj_chapter_e_loglist,
		&ett_rtp_midi_cj_chapter_e_logitem,
		&ett_rtp_midi_cj_chapter_t,
		&ett_rtp_midi_cj_chapter_a,
		&ett_rtp_midi_cj_chapter_a_loglist,
		&ett_rtp_midi_cj_chapter_a_logitem,
		&ett_rtp_midi_systemchapters,
		&ett_rtp_midi_sj_chapter_d,
		&ett_rtp_midi_sj_chapter_d_field_b,
		&ett_rtp_midi_sj_chapter_d_field_g,
		&ett_rtp_midi_sj_chapter_d_field_h,
		&ett_rtp_midi_sj_chapter_d_field_j,
		&ett_rtp_midi_sj_chapter_d_field_k,
		&ett_rtp_midi_sj_chapter_d_field_y,
		&ett_rtp_midi_sj_chapter_d_field_z,
		&ett_rtp_midi_sj_chapter_v,
		&ett_rtp_midi_sj_chapter_q,
		&ett_rtp_midi_sj_chapter_f,
		&ett_rtp_midi_sj_chapter_f_complete,
		&ett_rtp_midi_sj_chapter_f_partial,
		&ett_rtp_midi_sj_chapter_x,
		&ett_rtp_midi_sj_chapter_x_first,
		&ett_rtp_midi_sj_chapter_x_data,
		&ett_rtp_midi_channeljournal,
	};

	proto_rtp_midi = proto_register_protocol( RTP_MIDI_DISSECTOR_NAME, RTP_MIDI_DISSECTOR_SHORTNAME, RTP_MIDI_DISSECTOR_ABBREVIATION );
	proto_register_field_array( proto_rtp_midi, hf, array_length( hf ) );
	proto_register_subtree_array( ett, array_length( ett ) );

	rtp_midi_module = prefs_register_protocol( proto_rtp_midi, NULL );
	prefs_register_obsolete_preference( rtp_midi_module, "midi_payload_type_value");
	rtp_midi_handle = register_dissector( RTP_MIDI_DISSECTOR_ABBREVIATION, dissect_rtp_midi, proto_rtp_midi );
}



void
proto_reg_handoff_rtp_midi( void )
{
	dissector_add_string("rtp_dyn_payload_type", "rtp-midi", rtp_midi_handle);
	dissector_add_uint_range_with_preference( "rtp.pt", "", rtp_midi_handle );

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
