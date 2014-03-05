/* packet-selfm.c
 * Routines for Schweitzer Engineering Laboratories Fast Message Protocol (SEL FM) Dissection
 * By Chris Bontje (cbontje[AT]gmail.com
 * Copyright Nov/Dec 2012,
 *
 * $Id$
 *
 * Schweitzer Engineering Labs manufactures and sells digital protective relay equipment for
 * use in industrial high-voltage installations.  SEL FM protocol evolved over time as a
 * (semi)proprietary method for auto-configuration of connected SEL devices for retrieval of
 * analog and digital status data.  The protocol itself supports embedded binary messages
 * (which are what this dissector looks for) slip-streamed in the data stream with normal
 * ASCII text data.  A combination of both are used for full auto-configuration of devices,
 * but a wealth of information can be extracted from the binary messages alone.
 *
 * Documentation on Fast Meter and Fast SER messages available from www.selinc.com in
 * SEL Application Guides AG95-10_20091109.pdf and AG_200214.pdf
 ************************************************************************************************
 * Dissector Notes:
 *
 * 1) SEL Fast Message protocol over TCP is normally tunneled via a Telnet connection.  As Telnet
 * has special handling for the 0xFF character ("IAC"), normally a pair of 0xFF's are inserted
 * to represent an actual payload byte of 0xFF.  A function from the packet-telnet.c dissector has
 * been borrowed to automatically pre-process any Ethernet-based packet and remove these 'extra'
 * 0xFF bytes.  Wireshark Notes on Telnet 0xFF doubling are discussed here:
 * http://www.wireshark.org/lists/wireshark-bugs/201204/msg00198.html
 *
 * 2) As the presence of 0xFF pad bytes can render the "length" byte of a response message inaccurate
 * (as the 'length' does not compensate for these extra bytes) it can be difficult to accurately determine
 * the proper length of a message when attempting to do TCP reassembly.  The get_selfm_len function
 * does a best-guess, based on evidence observed from multiple packet captures from different devices.
 * What would be ideal would be to:
 *     a) Attempt initial PDU re-assembly based on length byte
 *     b) Detect if a 0xFF pair is found in the payload and add 1 byte to the PDU length
 *     c) Continue re-assembly based on revised length.
 *     d) Once full re-assembly of (actual length) TCP data is done, pass off full frame to selfm
 *        dissector to have 0xFF pairs stripped and the protocol dissected as per normal.
 * I'm not sure if tcp_dissect_pdus already supports this functionality, but I didn't see any examples?
 *
 * 3) Generally, the auto-configuration process itself will exchange several "configuration" messages
 * that describe various data regions (METER, DEMAND, PEAK, etc) that will later have corresponding
 * "data" messages.  This dissector code will currently save and accurately retrieve one set of these
 * exchanges (0xA5C1, 0xA5D1, "METER" region) using the GArray and conversation functions built into
 * Wireshark.  That said, a future modification would be nice to capture and retrieve multiple sets
 * of configuration messages to be able to decode all the different "data" messages encountered in
 * future exchanges.
 *
 ************************************************************************************************
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
#include "packet-tcp.h"
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/wmem/wmem.h>

/* Initialize the protocol and registered fields */
static int proto_selfm                   = -1;
static int hf_selfm_msgtype              = -1;
static int hf_selfm_relaydef_len         = -1;
static int hf_selfm_relaydef_numproto    = -1;
static int hf_selfm_relaydef_numfm       = -1;
static int hf_selfm_relaydef_numflags    = -1;
static int hf_selfm_relaydef_fmcfg_cmd   = -1;
static int hf_selfm_relaydef_fmdata_cmd  = -1;
static int hf_selfm_relaydef_statbit     = -1;
static int hf_selfm_relaydef_statbit_cmd = -1;
static int hf_selfm_relaydef_proto       = -1;
static int hf_selfm_fmconfig_len         = -1;
static int hf_selfm_fmconfig_numflags    = -1;
static int hf_selfm_fmconfig_loc_sf      = -1;
static int hf_selfm_fmconfig_num_sf      = -1;
static int hf_selfm_fmconfig_num_ai      = -1;
static int hf_selfm_fmconfig_num_samp    = -1;
static int hf_selfm_fmconfig_num_dig     = -1;
static int hf_selfm_fmconfig_num_calc    = -1;
static int hf_selfm_fmconfig_ofs_ai      = -1;
static int hf_selfm_fmconfig_ofs_ts      = -1;
static int hf_selfm_fmconfig_ofs_dig     = -1;
static int hf_selfm_fmconfig_ai_type     = -1;
static int hf_selfm_fmconfig_ai_sf_type  = -1;
static int hf_selfm_fmconfig_ai_sf_ofs   = -1;
static int hf_selfm_fmdata_len           = -1;
static int hf_selfm_fmdata_flagbyte      = -1;
static int hf_selfm_fmdata_dig_b0        = -1;
static int hf_selfm_fmdata_dig_b1        = -1;
static int hf_selfm_fmdata_dig_b2        = -1;
static int hf_selfm_fmdata_dig_b3        = -1;
static int hf_selfm_fmdata_dig_b4        = -1;
static int hf_selfm_fmdata_dig_b5        = -1;
static int hf_selfm_fmdata_dig_b6        = -1;
static int hf_selfm_fmdata_dig_b7        = -1;
static int hf_selfm_fmdata_ai_sf_fp      = -1;
static int hf_selfm_foconfig_len         = -1;
static int hf_selfm_foconfig_num_brkr    = -1;
static int hf_selfm_foconfig_num_rb      = -1;
static int hf_selfm_foconfig_prb_supp    = -1;
static int hf_selfm_foconfig_reserved    = -1;
static int hf_selfm_foconfig_brkr_open   = -1;
static int hf_selfm_foconfig_brkr_close  = -1;
static int hf_selfm_foconfig_rb_cmd      = -1;
static int hf_selfm_fastop_len           = -1;
static int hf_selfm_fastop_rb_code       = -1;
static int hf_selfm_fastop_br_code       = -1;
static int hf_selfm_fastop_valid         = -1;

static int hf_selfm_fastser_len                   = -1;
static int hf_selfm_fastser_routing_addr          = -1;
static int hf_selfm_fastser_status                = -1;
static int hf_selfm_fastser_funccode              = -1;
static int hf_selfm_fastser_seq                   = -1;
static int hf_selfm_fastser_seq_fir               = -1;
static int hf_selfm_fastser_seq_fin               = -1;
static int hf_selfm_fastser_seq_cnt               = -1;
static int hf_selfm_fastser_resp_num              = -1;
static int hf_selfm_fastser_crc16                 = -1;
static int hf_selfm_fastser_def_route_sup         = -1;
static int hf_selfm_fastser_def_rx_stat           = -1;
static int hf_selfm_fastser_def_tx_stat           = -1;
static int hf_selfm_fastser_def_rx_maxfr          = -1;
static int hf_selfm_fastser_def_tx_maxfr          = -1;
static int hf_selfm_fastser_def_rx_num_fc         = -1;
static int hf_selfm_fastser_def_rx_fc             = -1;
static int hf_selfm_fastser_def_tx_num_fc         = -1;
static int hf_selfm_fastser_def_tx_fc             = -1;
static int hf_selfm_fastser_uns_en_fc             = -1;
static int hf_selfm_fastser_uns_en_fc_data        = -1;
static int hf_selfm_fastser_uns_dis_fc            = -1;
static int hf_selfm_fastser_uns_dis_fc_data       = -1;
static int hf_selfm_fastser_read_baseaddr         = -1;
static int hf_selfm_fastser_read_numaddr          = -1;
static int hf_selfm_fastser_datafmt_resp_num_tag  = -1;
static int hf_selfm_fastser_datafmt_resp_tag_qty  = -1;
static int hf_selfm_fastser_datafmt_resp_tag_type = -1;
static int hf_selfm_fastser_devdesc_num_reg       = -1;
static int hf_selfm_fastser_unsresp_orig          = -1;
static int hf_selfm_fastser_unsresp_doy           = -1;
static int hf_selfm_fastser_unsresp_year          = -1;
static int hf_selfm_fastser_unsresp_todms         = -1;
static int hf_selfm_fastser_unsresp_num_elmt      = -1;
static int hf_selfm_fastser_unsresp_elmt_idx      = -1;
static int hf_selfm_fastser_unsresp_elmt_ts_ofs   = -1;
static int hf_selfm_fastser_unsresp_elmt_status   = -1;
static int hf_selfm_fastser_unsresp_eor           = -1;
static int hf_selfm_fastser_unsresp_elmt_statword = -1;
static int hf_selfm_fastser_unswrite_addr1        = -1;
static int hf_selfm_fastser_unswrite_addr2        = -1;
static int hf_selfm_fastser_unswrite_num_reg      = -1;
static int hf_selfm_fastser_unswrite_reg_val      = -1;

/* Initialize the subtree pointers */
static gint ett_selfm                       = -1;
static gint ett_selfm_relaydef              = -1;
static gint ett_selfm_relaydef_fm           = -1;
static gint ett_selfm_relaydef_proto        = -1;
static gint ett_selfm_relaydef_flags        = -1;
static gint ett_selfm_fmconfig              = -1;
static gint ett_selfm_fmconfig_ai           = -1;
static gint ett_selfm_foconfig              = -1;
static gint ett_selfm_foconfig_brkr         = -1;
static gint ett_selfm_foconfig_rb           = -1;
static gint ett_selfm_fastop                = -1;
static gint ett_selfm_fmdata                = -1;
static gint ett_selfm_fmdata_ai             = -1;
static gint ett_selfm_fmdata_dig            = -1;
static gint ett_selfm_fmdata_ai_ch          = -1;
static gint ett_selfm_fmdata_dig_ch         = -1;
static gint ett_selfm_fastser               = -1;
static gint ett_selfm_fastser_seq           = -1;
static gint ett_selfm_fastser_def_fc        = -1;
static gint ett_selfm_fastser_datareg       = -1;
static gint ett_selfm_fastser_tag           = -1;
static gint ett_selfm_fastser_element_list  = -1;
static gint ett_selfm_fastser_element       = -1;

#define PORT_SELFM    0

#define CMD_FAST_SER            0xA546
#define CMD_CLEAR_STATBIT       0xA5B9
#define CMD_RELAY_DEF           0xA5C0
#define CMD_FM_CONFIG           0xA5C1
#define CMD_DFM_CONFIG          0xA5C2
#define CMD_PDFM_CONFIG         0xA5C3
#define CMD_FASTOP_RESETDEF     0xA5CD
#define CMD_FASTOP_CONFIG       0xA5CE
#define CMD_FASTOP_CONFIG_ALT   0xA5CF
#define CMD_FM_DATA             0xA5D1
#define CMD_DFM_DATA            0xA5D2
#define CMD_PDFM_DATA           0xA5D3
#define CMD_FASTOP_RB_CTRL      0xA5E0
#define CMD_FASTOP_BR_CTRL      0xA5E3
#define CMD_FASTOP_RESET        0xA5ED

#define RELAYDEF_PROTO_SEL          0x0000
#define RELAYDEF_PROTO_LMD          0x0001
#define RELAYDEF_PROTO_MODBUS       0x0002
#define RELAYDEF_PROTO_SYMAX        0x0003
#define RELAYDEF_PROTO_R2R          0x0004
#define RELAYDEF_PROTO_DNP3         0x0005
#define RELAYDEF_PROTO_MB           0x0006
#define RELAYDEF_PROTO_C37_118      0x0007
#define RELAYDEF_PROTO_61850        0x0008
#define RELAYDEF_PROTO_SEL_FO       0x0100
#define RELAYDEF_PROTO_LMD_FO       0x0101
#define RELAYDEF_PROTO_SEL_FM       0x0200
#define RELAYDEF_PROTO_SEL_FO_FM    0x0300
#define RELAYDEF_PROTO_LMD_FO_FM    0x0301

#define FM_CONFIG_SF_LOC_FM             0
#define FM_CONFIG_SF_LOC_CFG            1

#define FM_CONFIG_ANA_CHNAME_LEN        6
#define FM_CONFIG_ANA_CHTYPE_INT16      0x00
#define FM_CONFIG_ANA_CHTYPE_INT16_LEN  2
#define FM_CONFIG_ANA_CHTYPE_FP         0x01
#define FM_CONFIG_ANA_CHTYPE_FP_LEN     4
#define FM_CONFIG_ANA_CHTYPE_FPD        0x02
#define FM_CONFIG_ANA_CHTYPE_FPD_LEN    8
#define FM_CONFIG_ANA_CHTYPE_TS         0x03
#define FM_CONFIG_ANA_CHTYPE_TS_LEN     8

#define FM_CONFIG_ANA_SFTYPE_INT16      0x00
#define FM_CONFIG_ANA_SFTYPE_FP         0x01
#define FM_CONFIG_ANA_SFTYPE_FPD        0x02
#define FM_CONFIG_ANA_SFTYPE_TS         0x03
#define FM_CONFIG_ANA_SFTYPE_NONE       0xFF

#define FO_CONFIG_PRB_SUPP_NO           0
#define FO_CONFIG_PRB_SUPP_YES          1

/* Fast SER Function Codes, "response" or "ACK" messages are the same as the request, but have the MSB set */
#define FAST_SER_MESSAGE_DEF            0x00
#define FAST_SER_MESSAGE_DEF_ACK        0x80
#define FAST_SER_EN_UNS_DATA            0x01
#define FAST_SER_EN_UNS_DATA_ACK        0x81
#define FAST_SER_DIS_UNS_DATA           0x02
#define FAST_SER_DIS_UNS_DATA_ACK       0x82
#define FAST_SER_PING                   0x05
#define FAST_SER_PING_ACK               0x85
#define FAST_SER_READ_REQ               0x10   /* Limited Public Documentation... */
#define FAST_SER_READ_RESP              0x90   /* Limited Public Documentation... */
#define FAST_SER_GEN_UNS_DATA           0x12   /* Limited Public Documentation... */
#define FAST_SER_SOE_STATE_REQ          0x16   /* Limited Public Documentation... */
#define FAST_SER_SOE_STATE_RESP         0x96   /* Limited Public Documentation... */
#define FAST_SER_UNS_RESP               0x18
#define FAST_SER_UNS_RESP_ACK           0x98
#define FAST_SER_UNS_WRITE              0x20
#define FAST_SER_UNS_WRITE_REQ          0x21   /* Limited Public Documentation... */
#define FAST_SER_DEVDESC_REQ            0x30   /* Limited Public Documentation... */
#define FAST_SER_DEVDESC_RESP           0xB0   /* Limited Public Documentation... */
#define FAST_SER_DATAFMT_REQ            0x31   /* Limited Public Documentation... */
#define FAST_SER_DATAFMT_RESP           0xB1   /* Limited Public Documentation... */
#define FAST_SER_UNS_DATAFMT_RESP       0x32   /* Limited Public Documentation... */
#define FAST_SER_BITLABEL_REQ           0x33   /* Limited Public Documentation... */
#define FAST_SER_BITLABEL_RESP          0xB3   /* Limited Public Documentation... */
#define FAST_SER_MGMT_REQ               0x40   /* Limited Public Documentation... */

/* Fast SER Sequence Byte Masks
   Observation suggests a similar format to the DNP3 Transport Layer byte */
#define FAST_SER_SEQ_FIR     0x80
#define FAST_SER_SEQ_FIN     0x40
#define FAST_SER_SEQ_CNT     0x3f

/* Fast SER Tag Data Types, unknown exact formatting but observation suggests the following */
/* 32-bit Float     01 00 41 */
/* 2 x 32-bit Float 02 00 41 */
/* 32-bit Integer   01 00 34 */
/* 16-bit Integer   01 00 32 */
/* 22-byte string   0B 00 12 */
/* 4-byte string    02 00 12 */
/* TARGETS          80 00 21 , address 0x3004 -> 0x3183 , 384 rows */
#define FAST_SER_TAGTYPE_FLOAT   0x41
#define FAST_SER_TAGTYPE_INT32   0x34
#define FAST_SER_TAGTYPE_INT16   0x32
#define FAST_SER_TAGTYPE_DIGWORD 0x21
#define FAST_SER_TAGTYPE_CHAR16  0x12

#define FAST_SER_UNSWRITE_COM01   0x0100
#define FAST_SER_UNSWRITE_COM02   0x0200
#define FAST_SER_UNSWRITE_COM03   0x0300
#define FAST_SER_UNSWRITE_COM04   0x0400
#define FAST_SER_UNSWRITE_COM05   0x0500
#define FAST_SER_UNSWRITE_COM06   0x0600
#define FAST_SER_UNSWRITE_COM07   0x0700
#define FAST_SER_UNSWRITE_COM08   0x0800
#define FAST_SER_UNSWRITE_COM09   0x0900
#define FAST_SER_UNSWRITE_COM10   0x0A00
#define FAST_SER_UNSWRITE_COM11   0x0B00
#define FAST_SER_UNSWRITE_COM12   0x0C00
#define FAST_SER_UNSWRITE_COM13   0x0D00
#define FAST_SER_UNSWRITE_COM14   0x0E00
#define FAST_SER_UNSWRITE_COM15   0x0F00

#define FASTOP_BR1_OPEN    0x31
#define FASTOP_BR1_CLOSE   0x11
#define FASTOP_BR2_OPEN    0x32
#define FASTOP_BR2_CLOSE   0x12
#define FASTOP_BR3_OPEN    0x33
#define FASTOP_BR3_CLOSE   0x13
#define FASTOP_BR4_OPEN    0x34
#define FASTOP_BR4_CLOSE   0x14

#define FASTOP_RB01_CLEAR  0x00
#define FASTOP_RB01_SET    0x20
#define FASTOP_RB01_PULSE  0x40
#define FASTOP_RB02_CLEAR  0x01
#define FASTOP_RB02_SET    0x21
#define FASTOP_RB02_PULSE  0x41
#define FASTOP_RB03_CLEAR  0x02
#define FASTOP_RB03_SET    0x22
#define FASTOP_RB03_PULSE  0x42
#define FASTOP_RB04_CLEAR  0x03
#define FASTOP_RB04_SET    0x23
#define FASTOP_RB04_PULSE  0x43
#define FASTOP_RB05_CLEAR  0x04
#define FASTOP_RB05_SET    0x24
#define FASTOP_RB05_PULSE  0x44
#define FASTOP_RB06_CLEAR  0x05
#define FASTOP_RB06_SET    0x25
#define FASTOP_RB06_PULSE  0x45
#define FASTOP_RB07_CLEAR  0x06
#define FASTOP_RB07_SET    0x26
#define FASTOP_RB07_PULSE  0x46
#define FASTOP_RB08_CLEAR  0x07
#define FASTOP_RB08_SET    0x27
#define FASTOP_RB08_PULSE  0x47
#define FASTOP_RB09_CLEAR  0x08
#define FASTOP_RB09_SET    0x28
#define FASTOP_RB09_PULSE  0x48
#define FASTOP_RB10_CLEAR  0x09
#define FASTOP_RB10_SET    0x29
#define FASTOP_RB10_PULSE  0x49
#define FASTOP_RB11_CLEAR  0x0A
#define FASTOP_RB11_SET    0x2A
#define FASTOP_RB11_PULSE  0x4A
#define FASTOP_RB12_CLEAR  0x0B
#define FASTOP_RB12_SET    0x2B
#define FASTOP_RB12_PULSE  0x4B
#define FASTOP_RB13_CLEAR  0x0C
#define FASTOP_RB13_SET    0x2C
#define FASTOP_RB13_PULSE  0x4C
#define FASTOP_RB14_CLEAR  0x0D
#define FASTOP_RB14_SET    0x2D
#define FASTOP_RB14_PULSE  0x4D
#define FASTOP_RB15_CLEAR  0x0E
#define FASTOP_RB15_SET    0x2E
#define FASTOP_RB15_PULSE  0x4E
#define FASTOP_RB16_CLEAR  0x0F
#define FASTOP_RB16_SET    0x2F
#define FASTOP_RB16_PULSE  0x4F
#define FASTOP_RB17_CLEAR  0x10
#define FASTOP_RB17_SET    0x30
#define FASTOP_RB17_PULSE  0x50
#define FASTOP_RB18_CLEAR  0x11
#define FASTOP_RB18_SET    0x31
#define FASTOP_RB18_PULSE  0x51
#define FASTOP_RB19_CLEAR  0x12
#define FASTOP_RB19_SET    0x32
#define FASTOP_RB19_PULSE  0x52
#define FASTOP_RB20_CLEAR  0x13
#define FASTOP_RB20_SET    0x33
#define FASTOP_RB20_PULSE  0x53
#define FASTOP_RB21_CLEAR  0x14
#define FASTOP_RB21_SET    0x34
#define FASTOP_RB21_PULSE  0x54
#define FASTOP_RB22_CLEAR  0x15
#define FASTOP_RB22_SET    0x35
#define FASTOP_RB22_PULSE  0x55
#define FASTOP_RB23_CLEAR  0x16
#define FASTOP_RB23_SET    0x36
#define FASTOP_RB23_PULSE  0x56
#define FASTOP_RB24_CLEAR  0x17
#define FASTOP_RB24_SET    0x37
#define FASTOP_RB24_PULSE  0x57
#define FASTOP_RB25_CLEAR  0x18
#define FASTOP_RB25_SET    0x38
#define FASTOP_RB25_PULSE  0x58
#define FASTOP_RB26_CLEAR  0x19
#define FASTOP_RB26_SET    0x39
#define FASTOP_RB26_PULSE  0x59
#define FASTOP_RB27_CLEAR  0x1A
#define FASTOP_RB27_SET    0x3A
#define FASTOP_RB27_PULSE  0x5A
#define FASTOP_RB28_CLEAR  0x1B
#define FASTOP_RB28_SET    0x3B
#define FASTOP_RB28_PULSE  0x5B
#define FASTOP_RB29_CLEAR  0x1C
#define FASTOP_RB29_SET    0x3C
#define FASTOP_RB29_PULSE  0x5C
#define FASTOP_RB30_CLEAR  0x1D
#define FASTOP_RB30_SET    0x3D
#define FASTOP_RB30_PULSE  0x5D
#define FASTOP_RB31_CLEAR  0x1E
#define FASTOP_RB31_SET    0x3E
#define FASTOP_RB31_PULSE  0x5E
#define FASTOP_RB32_CLEAR  0x1F
#define FASTOP_RB32_SET    0x3F
#define FASTOP_RB32_PULSE  0x5F


/* Globals for SEL Protocol Preferences */
static gboolean selfm_desegment = TRUE;
static gboolean selfm_telnet_clean = TRUE;
static guint global_selfm_tcp_port = PORT_SELFM; /* Port 0, by default */

/***************************************************************************************/
/* Fast Meter Message structs */
/***************************************************************************************/
/* Holds Configuration Information required to decode a Fast Meter analog value        */
typedef struct {
    gchar    name[FM_CONFIG_ANA_CHNAME_LEN+1];    /* Name of Analog Channel, 6 char + a null */
    guint8  type;                              /* Analog Channel Type, Int, FP, etc */
    guint8  sf_type;                           /* Analog Scale Factor Type, none, etc */
    guint16 sf_offset;                         /* Analog Scale Factor Offset */
} fm_analog_info;

/* Holds Information from a single "Fast Meter Configuration" frame.  Required to dissect subsequent "Data" frames. */
typedef struct {
    guint32  fnum;                   /* frame number */
    guint16  cfg_cmd;                /* holds ID of config command, ie: 0xa5c1 */
    guint8   num_flags;              /* Number of Flag Bytes           */
    guint8   num_ai;                 /* Number of Analog Inputs        */
    guint8   num_ai_samples;         /* Number samples per Analog Input */
    guint16  offset_ai;              /* Start Offset of Analog Inputs  */
    guint8   num_dig;                /* Number of Digital Input Blocks */
    guint16  offset_dig;             /* Start Offset of Digital Inputs */
    guint16  offset_ts;              /* Start Offset of Time Stamp     */
    guint8   num_calc;               /* Number of Calculations         */
    fm_analog_info *analogs;         /* Array of fm_analog_infos       */
} fm_config_frame;

typedef struct {
    wmem_slist_t *fm_config_frames; /* Contains a fm_config_data struct for the information in the Fast Meter configuration frame */
} fm_conversation;

/**************************************************************************************/
/* Fast SER Message structs */
/**************************************************************************************/
/* Holds Configuration Information required to decode a Fast SER Data Tag             */
/* Each data region format is returned as a sequential list of tags, w/o reference to */
/* an absolute address.  We can determine an address based on the sequence byte count */
/* when the tag was encountered and the index position within the data format message */
typedef struct {
    gchar    name[11];                          /* Name of Data Tag, 11 chars, null-terminated              */
    guint8  seq_count;                         /* Sequence count of data format message (0,1,2,3,4,etc)    */
    guint8  index_pos;                         /* Index Offset Position within data format message (1-16)  */
    guint8  quantity;                          /* Quantity of values within tag                            */
    guint8  type;                              /* Data Tag Type, Int, FP, etc                              */
} fastser_tag;

/* Holds Configuration Information required to decode a Fast SER Data Region */
typedef struct {
    gchar    name[12];                          /* Name of Data Region, 12 chars, null-terminated           */
    guint8  base_addr;                         /* Base address offset of region (0x3000, etc)              */
    guint8  qty_addr;                          /* Quantity of 16-bit addresses within region               */
    GArray     *tags;                               /* Array of fastser_tags                                    */
} fastser_region;

typedef struct {
    guint32     fnum;                     /* frame number */
    GArray    *fastser_region_blocks;  /* Contains a fastser_region struct for the information in the Fast SER configuration frame */
} fastser_config_frame;

static const value_string selfm_msgtype_vals[] = {
    { CMD_FAST_SER,              "Fast SER Block" },
    { CMD_CLEAR_STATBIT,         "Clear Status Bits Command" },
    { CMD_RELAY_DEF,             "Relay Definition Block" },
    { CMD_FM_CONFIG,             "Fast Meter Configuration Block" },
    { CMD_DFM_CONFIG,            "Demand Fast Meter Configuration Block" },
    { CMD_PDFM_CONFIG,           "Peak Demand Fast Meter Configuration Block" },
    { CMD_FASTOP_RESETDEF,       "Fast Operate Reset Definition" },
    { CMD_FASTOP_CONFIG,         "Fast Operate Configuration" },
    { CMD_FASTOP_CONFIG_ALT,     "Fast Operate Configuration (alt)" },
    { CMD_FM_DATA,               "Fast Meter Data Block" },
    { CMD_DFM_DATA,              "Demand Fast Meter Data Block" },
    { CMD_PDFM_DATA,             "Peak Demand Fast Meter Data Block" },
    { CMD_FASTOP_RB_CTRL,        "Fast Operate Remote Bit Control" },
    { CMD_FASTOP_BR_CTRL,        "Fast Operate Breaker Bit Control" },
    { CMD_FASTOP_RESET,          "Fast Operate Reset" },
    { 0,                         NULL }
};
static value_string_ext selfm_msgtype_vals_ext = VALUE_STRING_EXT_INIT(selfm_msgtype_vals);

static const value_string selfm_relaydef_proto_vals[] = {
    { RELAYDEF_PROTO_SEL,        "SEL Fast Meter" },
    { RELAYDEF_PROTO_LMD,        "SEL Limited Multidrop (LMD)" },
    { RELAYDEF_PROTO_MODBUS,     "Modbus" },
    { RELAYDEF_PROTO_SYMAX,      "SY/MAX" },
    { RELAYDEF_PROTO_R2R,        "SEL Relay-to-Relay" },
    { RELAYDEF_PROTO_DNP3,       "DNP 3.0" },
    { RELAYDEF_PROTO_MB,         "SEL Mirrored Bits" },
    { RELAYDEF_PROTO_C37_118,    "IEEE 37.118 Synchrophasors" },
    { RELAYDEF_PROTO_61850,      "IEC 61850" },
    { RELAYDEF_PROTO_SEL_FO,     "SEL Fast Meter w/ Fast Operate" },
    { RELAYDEF_PROTO_LMD_FO,     "SEL Limited Multidrop (LMD) w/ Fast Operate" },
    { RELAYDEF_PROTO_SEL_FM,     "SEL Fast Meter w/ Fast SER" },
    { RELAYDEF_PROTO_SEL_FO_FM,  "SEL Fast Meter w/ Fast Operate and Fast SER" },
    { RELAYDEF_PROTO_LMD_FO_FM,  "SEL Limited Multidrop (LMD) w/ Fast Operate and Fast SER" },
    { 0,                         NULL }
};
static value_string_ext selfm_relaydef_proto_vals_ext = VALUE_STRING_EXT_INIT(selfm_relaydef_proto_vals);

static const value_string selfm_fmconfig_ai_chtype_vals[] = {
    { FM_CONFIG_ANA_CHTYPE_INT16,  "16-Bit Integer" },
    { FM_CONFIG_ANA_CHTYPE_FP,     "IEEE Floating Point" },
    { FM_CONFIG_ANA_CHTYPE_FPD,    "IEEE Floating Point (Double)" },
    { FM_CONFIG_ANA_CHTYPE_TS,     "8-byte Time Stamp" },
    { 0,                           NULL }
};

static const value_string selfm_fmconfig_ai_sftype_vals[] = {
    { FM_CONFIG_ANA_SFTYPE_INT16,  "16-Bit Integer" },
    { FM_CONFIG_ANA_SFTYPE_FP,     "IEEE Floating Point" },
    { FM_CONFIG_ANA_SFTYPE_FPD,    "IEEE Floating Point (Double)" },
    { FM_CONFIG_ANA_SFTYPE_TS,     "8-byte Time Stamp" },
    { FM_CONFIG_ANA_SFTYPE_NONE,   "None" },
    { 0,                           NULL }
};

static const value_string selfm_fmconfig_sfloc_vals[] = {
    { FM_CONFIG_SF_LOC_FM,  "In Fast Meter Message" },
    { FM_CONFIG_SF_LOC_CFG, "In Configuration Message" },
    { 0,                           NULL }
};

/* Depending on number of analog samples present in Fast Meter Messages, identification of data will change */
static const value_string selfm_fmconfig_numsamples1_vals[] = {
    { 1,              "Magnitudes Only" },
    { 0,                           NULL }
};

static const value_string selfm_fmconfig_numsamples2_vals[] = {
    { 1,              "Imaginary Components" },
    { 2,              "Real Components" },
    { 0,                           NULL }
};

static const value_string selfm_fmconfig_numsamples4_vals[] = {
    { 1,              "1st Quarter Cycle Data" },
    { 2,              "2nd Quarter Cycle Data" },
    { 3,              "5th Quarter-Cycle Data" },
    { 4,              "6th Quarter-Cycle Data" },
    { 0,                           NULL }
};


static const value_string selfm_foconfig_prb_supp_vals[] = {
    { FO_CONFIG_PRB_SUPP_NO,  "No" },
    { FO_CONFIG_PRB_SUPP_YES, "Yes" },
    { 0,                      NULL }
};

static const value_string selfm_ser_status_vals[] = {
    { 0,  "Deasserted" },
    { 1,  "Asserted" },
    { 0,  NULL }
};


static const value_string selfm_fo_rb_vals[] = {
    { FASTOP_RB01_CLEAR,  "RB01 Clear" },
    { FASTOP_RB01_SET,    "RB01 Set" },
    { FASTOP_RB01_PULSE,  "RB01 Pulse" },
    { FASTOP_RB02_CLEAR,  "RB02 Clear" },
    { FASTOP_RB02_SET,    "RB02 Set" },
    { FASTOP_RB02_PULSE,  "RB02 Pulse" },
    { FASTOP_RB03_CLEAR,  "RB03 Clear" },
    { FASTOP_RB03_SET,    "RB03 Set" },
    { FASTOP_RB03_PULSE,  "RB03 Pulse" },
    { FASTOP_RB04_CLEAR,  "RB04 Clear" },
    { FASTOP_RB04_SET,    "RB04 Set" },
    { FASTOP_RB04_PULSE,  "RB04 Pulse" },
    { FASTOP_RB05_CLEAR,  "RB05 Clear" },
    { FASTOP_RB05_SET,    "RB05 Set" },
    { FASTOP_RB05_PULSE,  "RB05 Pulse" },
    { FASTOP_RB06_CLEAR,  "RB06 Clear" },
    { FASTOP_RB06_SET,    "RB06 Set" },
    { FASTOP_RB06_PULSE,  "RB06 Pulse" },
    { FASTOP_RB07_CLEAR,  "RB07 Clear" },
    { FASTOP_RB07_SET,    "RB07 Set" },
    { FASTOP_RB07_PULSE,  "RB07 Pulse" },
    { FASTOP_RB08_CLEAR,  "RB08 Clear" },
    { FASTOP_RB08_SET,    "RB08 Set" },
    { FASTOP_RB08_PULSE,  "RB08 Pulse" },
    { FASTOP_RB09_CLEAR,  "RB09 Clear" },
    { FASTOP_RB09_SET,    "RB09 Set" },
    { FASTOP_RB09_PULSE,  "RB09 Pulse" },
    { FASTOP_RB10_CLEAR,  "RB10 Clear" },
    { FASTOP_RB10_SET,    "RB10 Set" },
    { FASTOP_RB10_PULSE,  "RB10 Pulse" },
    { FASTOP_RB11_CLEAR,  "RB11 Clear" },
    { FASTOP_RB11_SET,    "RB11 Set" },
    { FASTOP_RB11_PULSE,  "RB11 Pulse" },
    { FASTOP_RB12_CLEAR,  "RB12 Clear" },
    { FASTOP_RB12_SET,    "RB12 Set" },
    { FASTOP_RB12_PULSE,  "RB12 Pulse" },
    { FASTOP_RB13_CLEAR,  "RB13 Clear" },
    { FASTOP_RB13_SET,    "RB13 Set" },
    { FASTOP_RB13_PULSE,  "RB13 Pulse" },
    { FASTOP_RB14_CLEAR,  "RB14 Clear" },
    { FASTOP_RB14_SET,    "RB14 Set" },
    { FASTOP_RB14_PULSE,  "RB14 Pulse" },
    { FASTOP_RB15_CLEAR,  "RB15 Clear" },
    { FASTOP_RB15_SET,    "RB15 Set" },
    { FASTOP_RB15_PULSE,  "RB15 Pulse" },
    { FASTOP_RB16_CLEAR,  "RB16 Clear" },
    { FASTOP_RB16_SET,    "RB16 Set" },
    { FASTOP_RB16_PULSE,  "RB16 Pulse" },
    { FASTOP_RB17_CLEAR,  "RB17 Clear" },
    { FASTOP_RB17_SET,    "RB17 Set" },
    { FASTOP_RB17_PULSE,  "RB17 Pulse" },
    { FASTOP_RB18_CLEAR,  "RB18 Clear" },
    { FASTOP_RB18_SET,    "RB18 Set" },
    { FASTOP_RB18_PULSE,  "RB18 Pulse" },
    { FASTOP_RB19_CLEAR,  "RB19 Clear" },
    { FASTOP_RB19_SET,    "RB19 Set" },
    { FASTOP_RB19_PULSE,  "RB19 Pulse" },
    { FASTOP_RB20_CLEAR,  "RB20 Clear" },
    { FASTOP_RB20_SET,    "RB20 Set" },
    { FASTOP_RB20_PULSE,  "RB20 Pulse" },
    { FASTOP_RB21_CLEAR,  "RB21 Clear" },
    { FASTOP_RB21_SET,    "RB21 Set" },
    { FASTOP_RB21_PULSE,  "RB21 Pulse" },
    { FASTOP_RB22_CLEAR,  "RB22 Clear" },
    { FASTOP_RB22_SET,    "RB22 Set" },
    { FASTOP_RB22_PULSE,  "RB22 Pulse" },
    { FASTOP_RB23_CLEAR,  "RB23 Clear" },
    { FASTOP_RB23_SET,    "RB23 Set" },
    { FASTOP_RB23_PULSE,  "RB23 Pulse" },
    { FASTOP_RB24_CLEAR,  "RB24 Clear" },
    { FASTOP_RB24_SET,    "RB24 Set" },
    { FASTOP_RB24_PULSE,  "RB24 Pulse" },
    { FASTOP_RB25_CLEAR,  "RB25 Clear" },
    { FASTOP_RB25_SET,    "RB25 Set" },
    { FASTOP_RB25_PULSE,  "RB25 Pulse" },
    { FASTOP_RB26_CLEAR,  "RB26 Clear" },
    { FASTOP_RB26_SET,    "RB26 Set" },
    { FASTOP_RB26_PULSE,  "RB26 Pulse" },
    { FASTOP_RB27_CLEAR,  "RB27 Clear" },
    { FASTOP_RB27_SET,    "RB27 Set" },
    { FASTOP_RB27_PULSE,  "RB27 Pulse" },
    { FASTOP_RB28_CLEAR,  "RB28 Clear" },
    { FASTOP_RB28_SET,    "RB28 Set" },
    { FASTOP_RB28_PULSE,  "RB28 Pulse" },
    { FASTOP_RB29_CLEAR,  "RB29 Clear" },
    { FASTOP_RB29_SET,    "RB29 Set" },
    { FASTOP_RB29_PULSE,  "RB29 Pulse" },
    { FASTOP_RB30_CLEAR,  "RB30 Clear" },
    { FASTOP_RB30_SET,    "RB30 Set" },
    { FASTOP_RB30_PULSE,  "RB30 Pulse" },
    { FASTOP_RB31_CLEAR,  "RB31 Clear" },
    { FASTOP_RB31_SET,    "RB31 Set" },
    { FASTOP_RB31_PULSE,  "RB31 Pulse" },
    { FASTOP_RB32_CLEAR,  "RB32 Clear" },
    { FASTOP_RB32_SET,    "RB32 Set" },
    { FASTOP_RB32_PULSE,  "RB32 Pulse" },
    { 0,                           NULL }
};

static const value_string selfm_fo_br_vals[] = {
    { FASTOP_BR1_OPEN,  "Breaker Bit 1 Open (OC/OC1)" },
    { FASTOP_BR1_CLOSE, "Breaker Bit 1 Close (CC/CC1)" },
    { FASTOP_BR2_OPEN,  "Breaker Bit 2 Open (OC2)" },
    { FASTOP_BR2_CLOSE, "Breaker Bit 2 Close (CC2)" },
    { FASTOP_BR3_OPEN,  "Breaker Bit 3 Open (OC3)" },
    { FASTOP_BR3_CLOSE, "Breaker Bit 3 Close (CC3)" },
    { FASTOP_BR4_OPEN,  "Breaker Bit 4 Open (OC4)" },
    { FASTOP_BR4_CLOSE, "Breaker Bit 4 Close (CC4)" },
    { 0,                           NULL }
};


static const value_string selfm_fastser_func_code_vals[] = {
    { FAST_SER_MESSAGE_DEF,       "Fast SER Message Definition Block" },
    { FAST_SER_MESSAGE_DEF_ACK,   "Fast SER Message Definition Block ACK" },
    { FAST_SER_EN_UNS_DATA,       "Enable Unsolicited Data" },
    { FAST_SER_EN_UNS_DATA_ACK,   "Enable Unsolicited Data ACK" },
    { FAST_SER_DIS_UNS_DATA,      "Disable Unsolicited Data" },
    { FAST_SER_DIS_UNS_DATA_ACK,  "Disable Unsolicited Data ACK" },
    { FAST_SER_PING,              "Ping Message" },
    { FAST_SER_PING_ACK,          "Ping Message ACK" },
    { FAST_SER_READ_REQ,          "Read Request" },
    { FAST_SER_READ_RESP,         "Read Response" },
    { FAST_SER_GEN_UNS_DATA,      "Generic Unsolicited Data" },
    { FAST_SER_SOE_STATE_REQ,     "SOE Present State Request" },
    { FAST_SER_SOE_STATE_RESP,    "SOE Present State Response" },
    { FAST_SER_UNS_RESP,          "Unsolicited Fast SER Data Response" },
    { FAST_SER_UNS_RESP_ACK,      "Unsolicited Fast SER Data Response ACK" },
    { FAST_SER_UNS_WRITE,         "Unsolicited Write" },
    { FAST_SER_UNS_WRITE_REQ,     "Unsolicited Write Request" },
    { FAST_SER_DEVDESC_REQ,       "Device Description Request" },
    { FAST_SER_DEVDESC_RESP,      "Device Description Response" },
    { FAST_SER_DATAFMT_REQ,       "Data Format Request" },
    { FAST_SER_DATAFMT_RESP,      "Data Format Response" },
    { FAST_SER_UNS_DATAFMT_RESP,  "Unsolicited Data Format Response" },
    { FAST_SER_BITLABEL_REQ,      "Bit Label Request" },
    { FAST_SER_BITLABEL_RESP,     "Bit Label Response" },
    { FAST_SER_MGMT_REQ,          "Management Request" },
    { 0,                           NULL }
};

static const value_string selfm_fastser_seq_vals[] = {
  { FAST_SER_SEQ_FIN,  "FIN" },
  { FAST_SER_SEQ_FIR,  "FIR" },
  { 0,  NULL }
};

static const value_string selfm_fastser_tagtype_vals[] = {
  { FAST_SER_TAGTYPE_FLOAT,   "IEEE Floating Point" },
  { FAST_SER_TAGTYPE_INT32,   "32-bit Integer" },
  { FAST_SER_TAGTYPE_INT16,   "16-bit Integer" },
  { FAST_SER_TAGTYPE_DIGWORD, "Digital Word" },
  { FAST_SER_TAGTYPE_CHAR16,  "16-bit Character Array" },
  { 0,  NULL }
};

static const value_string selfm_fastser_unswrite_com_vals[] = {
  { FAST_SER_UNSWRITE_COM01,   "COM01" },
  { FAST_SER_UNSWRITE_COM02,   "COM02" },
  { FAST_SER_UNSWRITE_COM03,   "COM03" },
  { FAST_SER_UNSWRITE_COM04,   "COM04" },
  { FAST_SER_UNSWRITE_COM05,   "COM05" },
  { FAST_SER_UNSWRITE_COM06,   "COM06" },
  { FAST_SER_UNSWRITE_COM07,   "COM07" },
  { FAST_SER_UNSWRITE_COM08,   "COM08" },
  { FAST_SER_UNSWRITE_COM09,   "COM09" },
  { FAST_SER_UNSWRITE_COM10,   "COM10" },
  { FAST_SER_UNSWRITE_COM11,   "COM11" },
  { FAST_SER_UNSWRITE_COM12,   "COM12" },
  { FAST_SER_UNSWRITE_COM13,   "COM13" },
  { FAST_SER_UNSWRITE_COM14,   "COM14" },
  { FAST_SER_UNSWRITE_COM15,   "COM15" },
  { 0,  NULL }
};

/**********************************************************************************************************/
/* Clean all instances of 0xFFFF from Telnet payload to compensate for IAC control code (replace w/ 0xFF) */
/* Function Duplicated from packet-telnet.c (unescape_and_tvbuffify_telnet_option)                        */
/**********************************************************************************************************/
static tvbuff_t *
clean_telnet_iac(packet_info *pinfo, tvbuff_t *tvb, int offset, int len)
{
  tvbuff_t     *telnet_tvb;
  guint8       *buf;
  const guint8 *spos;
  guint8       *dpos;
  int           skip, l;

  spos=tvb_get_ptr(tvb, offset, len);
  buf=(guint8 *)g_malloc(len);
  dpos=buf;
  skip=0;
  l=len;
  while(l>0){
    if((spos[0]==0xff) && (spos[1]==0xff)){
      skip++;
      l-=2;
      *(dpos++)=0xff;
      spos+=2;
      continue;
    }
    *(dpos++)=*(spos++);
    l--;
  }
  telnet_tvb = tvb_new_child_real_data(tvb, buf, len-skip, len-skip);
  tvb_set_free_cb(telnet_tvb, g_free);
  add_new_data_source(pinfo, telnet_tvb, "Processed Telnet Data");

  return telnet_tvb;
}

/******************************************************************************************************/
/* Execute dissection of Fast Meter configuration rames independent of any GUI access of said frames  */
/* Load configuration information into fm_config_frame struct */
/******************************************************************************************************/
static fm_config_frame* fmconfig_frame_fast(tvbuff_t *tvb)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    guint           count, offset = 0;
    fm_config_frame *frame;

    /* get a new frame and initialize it */
    frame = (fm_config_frame *)wmem_alloc(wmem_file_scope(), sizeof(fm_config_frame));

    /* Get data packet setup information from config message and copy into ai_info (if required) */
    frame->cfg_cmd        = tvb_get_ntohs(tvb, offset);
    /* skip length byte, position offset+2 */
    frame->num_flags      = tvb_get_guint8(tvb, offset+3);
    /* skip scale factor location, position offset+4 */
    /* skip number of scale factors, position offset+5 */
    frame->num_ai         = tvb_get_guint8(tvb, offset+6);
    frame->num_ai_samples = tvb_get_guint8(tvb, offset+7);
    frame->num_dig        = tvb_get_guint8(tvb, offset+8);
    frame->num_calc       = tvb_get_guint8(tvb, offset+9);

    /* Update offset pointer */
    offset += 10;

    /* Get data packet analog/timestamp/digital offsets and copy into ai_info */
    frame->offset_ai  = tvb_get_ntohs(tvb, offset);
    frame->offset_ts  = tvb_get_ntohs(tvb, offset+2);
    frame->offset_dig = tvb_get_ntohs(tvb, offset+4);

    /* Update offset pointer */
    offset += 6;

    frame->analogs = (fm_analog_info *)wmem_alloc(wmem_file_scope(), frame->num_ai * sizeof(fm_analog_info));

    /* Get AI Channel Details and copy into ai_info */
    for (count = 0; count < frame->num_ai; count++) {
        fm_analog_info *analog = &(frame->analogs[count]);
        tvb_memcpy(tvb, analog->name, offset, FM_CONFIG_ANA_CHNAME_LEN);
        analog->name[FM_CONFIG_ANA_CHNAME_LEN] = '\0'; /* Put a terminating null onto the end of the AI Channel name */
        analog->type = tvb_get_guint8(tvb, offset+6);
        analog->sf_type = tvb_get_guint8(tvb, offset+7);
        analog->sf_offset = tvb_get_ntohs(tvb, offset+8);

        offset += 10;
    }

    return frame;

}

/******************************************************************************************************/
/* Code to Dissect Relay Definition Frames */
/******************************************************************************************************/
static int
dissect_relaydef_frame(tvbuff_t *tvb, proto_tree *tree, int offset)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *relaydef_item, *relaydef_fm_item, *relaydef_flags_item, *relaydef_proto_item;
    proto_tree    *relaydef_tree, *relaydef_fm_tree, *relaydef_flags_tree, *relaydef_proto_tree;
    guint8        len, num_proto, num_fm, num_flags;
    int           count;

    len = tvb_get_guint8(tvb, offset);
    num_proto = tvb_get_guint8(tvb, offset+1);
    num_fm = tvb_get_guint8(tvb, offset+2);
    num_flags = tvb_get_guint8(tvb, offset+3);

    /* Add items to protocol tree specific to Relay Definition Block */
    relaydef_item = proto_tree_add_text(tree, tvb, offset, len-2, "Relay Definition Block Details");
    relaydef_tree = proto_item_add_subtree(relaydef_item, ett_selfm_relaydef);

    /* Reported length */
    proto_tree_add_item(relaydef_tree, hf_selfm_relaydef_len, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Reported Number of Protocols Supported */
    relaydef_proto_item = proto_tree_add_item(relaydef_tree, hf_selfm_relaydef_numproto, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    relaydef_proto_tree = proto_item_add_subtree(relaydef_proto_item, ett_selfm_relaydef_proto);

    /* Reported Number of Fast Meter Commands Supported */
    relaydef_fm_item = proto_tree_add_item(relaydef_tree, hf_selfm_relaydef_numfm, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    relaydef_fm_tree = proto_item_add_subtree(relaydef_fm_item, ett_selfm_relaydef_fm);

    /* Reported Number of Status Bit Flags Supported */
    relaydef_flags_item = proto_tree_add_item(relaydef_tree, hf_selfm_relaydef_numflags, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    relaydef_flags_tree = proto_item_add_subtree(relaydef_flags_item, ett_selfm_relaydef_flags);

    /* Get our offset up-to-date */
    offset += 4;

    /* Add each reported Fast Meter cfg/data message */
    for (count = 1; count <= num_fm; count++) {
        proto_tree_add_item(relaydef_fm_tree, hf_selfm_relaydef_fmcfg_cmd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(relaydef_fm_tree, hf_selfm_relaydef_fmdata_cmd, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /* Add each reported status bit flag, along with corresponding response command */
    for (count = 1; count <= num_flags; count++) {
        proto_tree_add_item(relaydef_flags_tree, hf_selfm_relaydef_statbit, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(relaydef_flags_tree, hf_selfm_relaydef_statbit_cmd, tvb, offset+2, 6, ENC_NA);
        offset += 8;
    }

    /* Add each supported protocol */
    for (count = 1; count <= num_proto; count++) {
        proto_tree_add_item(relaydef_proto_tree, hf_selfm_relaydef_proto, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    return tvb_length(tvb);

}

/******************************************************************************************************/
/* Code to dissect Fast Meter Configuration Frames */
/******************************************************************************************************/
static int
dissect_fmconfig_frame(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *fmconfig_item, *fmconfig_ai_item=NULL;
    proto_tree    *fmconfig_tree, *fmconfig_ai_tree=NULL;
    guint         count;
    guint8        len, num_ai;
    gchar         ai_name[FM_CONFIG_ANA_CHNAME_LEN+1]; /* 6 Characters + a Null */

    len = tvb_get_guint8(tvb, offset);
    /* skip num_flags, position offset+1 */
    /* skip sf_loc,    position offset+2 */
    /* skip num_sf,    position offset+3 */
    num_ai = tvb_get_guint8(tvb, offset+4);
    /* skip num_samp,  position offset+5 */
    /* skip num_dig,   position offset+6 */
    /* skip num_calc,  position offset+7 */

    fmconfig_item = proto_tree_add_text(tree, tvb, offset, len, "Fast Meter Configuration Details");
    fmconfig_tree = proto_item_add_subtree(fmconfig_item, ett_selfm_fmconfig);

    /* Add items to protocol tree specific to Fast Meter Configuration Block */

    /* Get Setup Information for FM Config Block */
    proto_tree_add_item(fmconfig_tree, hf_selfm_fmconfig_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fmconfig_tree, hf_selfm_fmconfig_numflags, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fmconfig_tree, hf_selfm_fmconfig_loc_sf, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fmconfig_tree, hf_selfm_fmconfig_num_sf, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fmconfig_tree, hf_selfm_fmconfig_num_ai, tvb, offset+4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fmconfig_tree, hf_selfm_fmconfig_num_samp, tvb, offset+5, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fmconfig_tree, hf_selfm_fmconfig_num_dig, tvb, offset+6, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fmconfig_tree, hf_selfm_fmconfig_num_calc, tvb, offset+7, 1, ENC_BIG_ENDIAN);

    /* Update offset pointer */
    offset += 8;

    /* Add data packet offsets to tree and update offset pointer */
    proto_tree_add_item(fmconfig_tree, hf_selfm_fmconfig_ofs_ai, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(fmconfig_tree, hf_selfm_fmconfig_ofs_ts, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(fmconfig_tree, hf_selfm_fmconfig_ofs_dig, tvb, offset+4, 2, ENC_BIG_ENDIAN);
    offset += 6;

    /* Get AI Channel Details */
    for (count = 0; count < num_ai; count++) {
        tvb_memcpy(tvb, &ai_name, offset, 6);
        ai_name[FM_CONFIG_ANA_CHNAME_LEN] = '\0'; /* Put a terminating null onto the end of the AI name, in case none exists */

        fmconfig_ai_item = proto_tree_add_text(fmconfig_tree, tvb, offset, 10, "Analog Channel: %s", ai_name);
        fmconfig_ai_tree = proto_item_add_subtree(fmconfig_ai_item, ett_selfm_fmconfig_ai);

        /* Add Channel Name, Channel Data Type, Scale Factor Type and Scale Factor Offset to tree */
        proto_tree_add_text(fmconfig_ai_tree, tvb, offset, 6, "Analog Channel Name: %s", ai_name);
        proto_tree_add_item(fmconfig_ai_tree, hf_selfm_fmconfig_ai_type, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_ai_tree, hf_selfm_fmconfig_ai_sf_type, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_ai_tree, hf_selfm_fmconfig_ai_sf_ofs, tvb, offset+8, 2, ENC_BIG_ENDIAN);

        /* Update Offset Pointer */
        offset += 10;
    }

    /* XXX - Need to decode any Calculation block instances here in a future version, based on num_calc */

    return tvb_length(tvb);

}

/******************************************************************************************************/
/* Code to dissect Fast Meter Data Frames */
/* Formatting depends heavily on previously-encountered Configuration Frames so search array instances for them */
/******************************************************************************************************/
static int
dissect_fmdata_frame(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset, guint16 config_cmd_match)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item       *fmdata_item, *fmdata_ai_item=NULL, *fmdata_dig_item=NULL, *fmdata_ai_ch_item=NULL, *fmdata_dig_ch_item=NULL;
    proto_tree       *fmdata_tree, *fmdata_ai_tree=NULL, *fmdata_dig_tree=NULL, *fmdata_ai_ch_tree=NULL, *fmdata_dig_ch_tree=NULL;
    guint8           len, i=0, j=0, ts_mon, ts_day, ts_year, ts_hour, ts_min, ts_sec;
    guint16          config_cmd, ts_msec;
    gint16           ai_int16val;
    gfloat           ai_fpval, ai_sf_fp;
    gdouble          ai_fpd_val;
    gboolean         config_found = FALSE;
    fm_conversation  *conv;
    fm_config_frame  *cfg_data;
    gint             cnt = 0, ch_size=0;

    len = tvb_get_guint8(tvb, offset);

    fmdata_item = proto_tree_add_text(tree, tvb, offset, len-2, "Fast Meter Data Details");
    fmdata_tree = proto_item_add_subtree(fmdata_item, ett_selfm_fmdata);

    /* Reported length */
    proto_tree_add_item(fmdata_tree, hf_selfm_fmdata_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Search for previously-encountered Configuration information to dissect the frame */
    {
        conv = (fm_conversation *)p_get_proto_data(pinfo->fd, proto_selfm, 0);

        if (conv) {
            wmem_slist_frame_t *frame = wmem_slist_front(conv->fm_config_frames);
            /* Cycle through possible instances of multiple fm_config_data_blocks, looking for match */
            while (frame && !config_found) {
                cfg_data = (fm_config_frame *)wmem_slist_frame_data(frame);
                config_cmd = cfg_data->cfg_cmd;

                /* If the stored config_cmd matches the expected one we are looking for, mark that the config data was found */
                if (config_cmd == config_cmd_match) {
                    proto_item_append_text(fmdata_item, ", using frame number %"G_GUINT32_FORMAT" as Configuration Frame",
                                   cfg_data->fnum);
                    config_found = TRUE;
                }

                frame = wmem_slist_frame_next(frame);
            }

            if (config_found) {

                /* Retrieve number of Status Flag bytes and setup tree */
                if (cfg_data->num_flags == 1){
                    proto_tree_add_item(fmdata_tree, hf_selfm_fmdata_flagbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /*offset += 1;*/
                }

                cnt = cfg_data->num_ai; /* actual number of analog values to available to dissect */

                /* Update our current tvb offset to the actual AI offset saved the Configuration message */
                offset = cfg_data->offset_ai;

                /* Check that we actually have analog data to dissect */
                if (cnt > 0) {

                    /* Include decoding for each Sample provided for the Analog Channels */
                    for (j=0; j < cfg_data->num_ai_samples; j++) {

                        /* Use different lookup strings, depending on how many samples are available per Analog Channel */
                        if (cfg_data->num_ai_samples == 1) {
                            fmdata_ai_item = proto_tree_add_text(fmdata_tree, tvb, offset, ((cfg_data->offset_ts - cfg_data->offset_ai)/cfg_data->num_ai_samples),
                                "Analog Channels (%d), Sample: %d (%s)",
                                cfg_data->num_ai, j+1, val_to_str_const(j+1, selfm_fmconfig_numsamples1_vals, "Unknown"));
                            fmdata_ai_tree = proto_item_add_subtree(fmdata_ai_item, ett_selfm_fmdata_ai);
                        }
                        else if (cfg_data->num_ai_samples == 2) {
                            fmdata_ai_item = proto_tree_add_text(fmdata_tree, tvb, offset, ((cfg_data->offset_ts - cfg_data->offset_ai)/cfg_data->num_ai_samples),
                                "Analog Channels (%d), Sample: %d (%s)",
                                cfg_data->num_ai, j+1, val_to_str_const(j+1, selfm_fmconfig_numsamples2_vals, "Unknown"));
                            fmdata_ai_tree = proto_item_add_subtree(fmdata_ai_item, ett_selfm_fmdata_ai);
                        }
                        else if (cfg_data->num_ai_samples == 4) {
                            fmdata_ai_item = proto_tree_add_text(fmdata_tree, tvb, offset, ((cfg_data->offset_ts - cfg_data->offset_ai)/cfg_data->num_ai_samples),
                                "Analog Channels (%d), Sample: %d (%s)",
                                cfg_data->num_ai, j+1, val_to_str_const(j+1, selfm_fmconfig_numsamples4_vals, "Unknown"));
                            fmdata_ai_tree = proto_item_add_subtree(fmdata_ai_item, ett_selfm_fmdata_ai);
                        }

                        /* For each analog channel we encounter... */
                        for (i = 0; i < cnt; i++) {

                            fm_analog_info *ai = &(cfg_data->analogs[i]);

                            /* Channel size (in bytes) determined by data type */
                            switch (ai->type) {
                                case FM_CONFIG_ANA_CHTYPE_INT16:
                                    ch_size = FM_CONFIG_ANA_CHTYPE_INT16_LEN; /* 2 bytes */
                                    break;
                                case FM_CONFIG_ANA_CHTYPE_FP:
                                    ch_size = FM_CONFIG_ANA_CHTYPE_FP_LEN;    /* 4 bytes */
                                    break;
                                case FM_CONFIG_ANA_CHTYPE_FPD:
                                    ch_size = FM_CONFIG_ANA_CHTYPE_FPD_LEN;   /* 8 bytes */
                                    break;
                                default:
                                    break;
                            }

                            /* Build sub-tree for each Analog Channel */
                            fmdata_ai_ch_item = proto_tree_add_text(fmdata_ai_tree, tvb, offset, ch_size, "Analog Channel %d: %s", i+1, ai->name);
                            fmdata_ai_ch_tree = proto_item_add_subtree(fmdata_ai_ch_item, ett_selfm_fmdata_ai_ch);

                            /* XXX - Need more decoding options here for different data types, but I need packet capture examples first */
                            /* Decode analog value appropriately, according to data type */
                            switch (ai->type) {
                                /* Channel type is 16-bit Integer */
                                case FM_CONFIG_ANA_CHTYPE_INT16:
                                    ai_int16val = tvb_get_ntohs(tvb, offset);

                                    /* If we've got a scale factor offset, apply it before printing the analog */
                                    if ((ai->sf_offset != 0) && (ai->sf_type == FM_CONFIG_ANA_SFTYPE_FP)){
                                        ai_sf_fp = tvb_get_ntohieee_float(tvb, ai->sf_offset);
                                        proto_tree_add_float(fmdata_ai_ch_tree, hf_selfm_fmdata_ai_sf_fp, tvb, ai->sf_offset, 4, ai_sf_fp);
                                    }
                                    else {
                                        ai_sf_fp = 1;
                                    }

                                    proto_tree_add_text(fmdata_ai_ch_tree, tvb, offset, ch_size, "Value (Raw): %d", ai_int16val);
                                    proto_tree_add_text(fmdata_ai_ch_tree, tvb, offset, ch_size, "Value (w/ Scale Factor): %f", ((gfloat)ai_int16val*ai_sf_fp));
                                    offset += ch_size;
                                    break;
                                /* Channel type is IEEE Floating point */
                                case FM_CONFIG_ANA_CHTYPE_FP:
                                    ai_fpval = tvb_get_ntohieee_float(tvb, offset);
                                    proto_tree_add_text(fmdata_ai_ch_tree, tvb, offset, ch_size, "Value: %f", ai_fpval);
                                    offset += ch_size;
                                    break;
                                /* Channel type is Double IEEE Floating point */
                                case FM_CONFIG_ANA_CHTYPE_FPD:
                                    ai_fpd_val = tvb_get_ntohieee_double(tvb, offset);
                                    proto_tree_add_text(fmdata_ai_ch_tree, tvb, offset, ch_size, "Value: %f", ai_fpd_val);
                                    offset += ch_size;
                                    break;

                            } /* channel type */

                        } /* number of analog channels */

                    } /* number of samples */

                } /* there were analogs */

                /* Check if we have a time-stamp in this message */
                if (cfg_data->offset_ts != 0xFFFF) {
                    /* Retrieve timestamp from 8-byte format                         */
                    /* Stored as: month, day, year (xx), hr, min, sec, msec (16-bit) */
                    ts_mon  = tvb_get_guint8(tvb, offset);
                    ts_day  = tvb_get_guint8(tvb, offset+1);
                    ts_year = tvb_get_guint8(tvb, offset+2);
                    ts_hour = tvb_get_guint8(tvb, offset+3);
                    ts_min  = tvb_get_guint8(tvb, offset+4);
                    ts_sec  = tvb_get_guint8(tvb, offset+5);
                    ts_msec = tvb_get_ntohs(tvb, offset+6);
                    proto_tree_add_text(fmdata_tree, tvb, offset, 8, "Timestamp: %.2d/%.2d/%.2d %.2d:%.2d:%.2d.%.3d", ts_mon, ts_day, ts_year, ts_hour, ts_min, ts_sec, ts_msec);

                    offset += 8;
                }

                /* Check that we actually have digital data */
                if (cfg_data->num_dig > 0) {

                    fmdata_dig_item = proto_tree_add_text(fmdata_tree, tvb, offset, cfg_data->num_dig, "Digital Channels (%d)", cfg_data->num_dig);
                    fmdata_dig_tree = proto_item_add_subtree(fmdata_dig_item, ett_selfm_fmdata_dig);

                    for (i=0; i < cfg_data->num_dig; i++) {

                        fmdata_dig_ch_item = proto_tree_add_text(fmdata_dig_tree, tvb, offset, 1, "Digital Word Bit Row: %d", i+1);
                        fmdata_dig_ch_tree = proto_item_add_subtree(fmdata_dig_ch_item, ett_selfm_fmdata_dig_ch);

                        proto_tree_add_item(fmdata_dig_ch_tree, hf_selfm_fmdata_dig_b0, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(fmdata_dig_ch_tree, hf_selfm_fmdata_dig_b1, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(fmdata_dig_ch_tree, hf_selfm_fmdata_dig_b2, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(fmdata_dig_ch_tree, hf_selfm_fmdata_dig_b3, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(fmdata_dig_ch_tree, hf_selfm_fmdata_dig_b4, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(fmdata_dig_ch_tree, hf_selfm_fmdata_dig_b5, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(fmdata_dig_ch_tree, hf_selfm_fmdata_dig_b6, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(fmdata_dig_ch_tree, hf_selfm_fmdata_dig_b7, tvb, offset, 1, ENC_BIG_ENDIAN);

                        offset += 1;
                    }

                } /* digital data was available */

            } /* matching config frame message was found */

        } /* config data found */

        if (!config_found) {
            proto_item_append_text(fmdata_item, ", No Fast Meter Configuration frame found");
            return 0;
        }
    }

    return tvb_length(tvb);

}

/******************************************************************************************************/
/* Code to Dissect Fast Operate Configuration Frames */
/******************************************************************************************************/
static int
dissect_foconfig_frame(tvbuff_t *tvb, proto_tree *tree, int offset)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *foconfig_item, *foconfig_brkr_item, *foconfig_rb_item;
    proto_tree    *foconfig_tree, *foconfig_brkr_tree=NULL, *foconfig_rb_tree=NULL;
    guint         count;
    guint8        len, num_brkr, prb_supp;
    guint16       num_rb;

    len = tvb_get_guint8(tvb, offset);
    num_brkr = tvb_get_guint8(tvb, offset+1);
    num_rb = tvb_get_ntohs(tvb, offset+2);
    prb_supp = tvb_get_guint8(tvb, offset+4);

    foconfig_item = proto_tree_add_text(tree, tvb, offset, len-2, "Fast Operate Configuration Details");
    foconfig_tree = proto_item_add_subtree(foconfig_item, ett_selfm_foconfig);

    /* Add items to protocol tree specific to Fast Operate Configuration Block */

    /* Reported length */
    proto_tree_add_item(foconfig_tree, hf_selfm_foconfig_len, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Supported Breaker Bits */
    foconfig_brkr_item = proto_tree_add_item(foconfig_tree, hf_selfm_foconfig_num_brkr, tvb, offset+1, 1, ENC_BIG_ENDIAN);

    /* Supported Remote Bits */
    foconfig_rb_item = proto_tree_add_item(foconfig_tree, hf_selfm_foconfig_num_rb, tvb, offset+2, 2, ENC_BIG_ENDIAN);

    /* Add "Remote Bit Pulse Supported?" and "Reserved Bit" to Tree */
    proto_tree_add_item(foconfig_tree, hf_selfm_foconfig_prb_supp, tvb, offset+4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(foconfig_tree, hf_selfm_foconfig_reserved, tvb, offset+5, 1, ENC_BIG_ENDIAN);

    /* Update offset pointer */
    offset += 6;

    /* Get Breaker Bit Command Details */
    for (count = 1; count <= num_brkr; count++) {

        foconfig_brkr_tree = proto_item_add_subtree(foconfig_brkr_item, ett_selfm_foconfig_brkr);

        /* Add Breaker Open/Close commands to tree */
        proto_tree_add_item(foconfig_brkr_tree, hf_selfm_foconfig_brkr_open, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(foconfig_brkr_tree, hf_selfm_foconfig_brkr_close, tvb, offset+1, 1, ENC_BIG_ENDIAN);

        offset += 2;
    }

    /* Get Remote Bit Command Details */
    for (count = 1; count <= num_rb; count++) {

        foconfig_rb_tree = proto_item_add_subtree(foconfig_rb_item, ett_selfm_foconfig_rb);

        /* Add "Remote Bit Set" command to tree */
        proto_tree_add_item(foconfig_rb_tree, hf_selfm_foconfig_rb_cmd, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Print "Remote Bit Clear" command to tree */
        proto_tree_add_item(foconfig_rb_tree, hf_selfm_foconfig_rb_cmd, tvb, offset+1, 1, ENC_BIG_ENDIAN);

        /* If Remote Bit "pulse" is supported, retrieve that command as well */
        if (prb_supp) {
            proto_tree_add_item(foconfig_rb_tree, hf_selfm_foconfig_rb_cmd, tvb, offset+2, 1, ENC_BIG_ENDIAN);
            offset += 3;
        }
        else{
            offset += 2;
        }
    }


    return tvb_length(tvb);

}

/******************************************************************************************************/
/* Code to Dissect Fast Operate (Remote Bit or Breaker Bit) Frames */
/******************************************************************************************************/
static int
dissect_fastop_frame(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *fastop_item;
    proto_tree    *fastop_tree;
    guint8        len, opcode;
    guint16       msg_type;

    msg_type = tvb_get_ntohs(tvb, offset-2);
    len = tvb_get_guint8(tvb, offset);

    fastop_item = proto_tree_add_text(tree, tvb, offset, len-2, "Fast Operate Details");
    fastop_tree = proto_item_add_subtree(fastop_item, ett_selfm_fastop);

    /* Add Reported length to tree*/
    proto_tree_add_item(fastop_tree, hf_selfm_fastop_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Operate Code */
    opcode = tvb_get_guint8(tvb, offset);

    /* Use different lookup table for different msg_type */
    if (msg_type == CMD_FASTOP_RB_CTRL) {
        proto_tree_add_item(fastop_tree, hf_selfm_fastop_rb_code, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Append Column Info w/ Control Code Code */
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", val_to_str_const(opcode, selfm_fo_rb_vals, "Unknown Control Code"));
        }

    }
    else if (msg_type == CMD_FASTOP_BR_CTRL) {
        proto_tree_add_item(fastop_tree, hf_selfm_fastop_br_code, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Append Column Info w/ Control Code Code */
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", val_to_str_const(opcode, selfm_fo_br_vals, "Unknown Control Code"));
        }

    }
    offset += 1;

    /* Operate Code Validation */
    proto_tree_add_item(fastop_tree, hf_selfm_fastop_valid, tvb, offset, 1, ENC_BIG_ENDIAN);

    return tvb_length(tvb);

}

/******************************************************************************************************/
/* Code to dissect Fast SER Frames       */
/* Some protocol structure is guessed at */
/******************************************************************************************************/
static int
dissect_fastser_frame(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *fastser_item, *fastser_def_fc_item=NULL, *fastser_seq_item=NULL, *fastser_elementlist_item=NULL;
    proto_item    *fastser_element_item=NULL, *fastser_datareg_item=NULL, *fastser_tag_item=NULL;
    proto_tree    *fastser_tree, *fastser_def_fc_tree=NULL, *fastser_seq_tree=NULL, *fastser_elementlist_tree=NULL;
    proto_tree    *fastser_element_tree=NULL, *fastser_datareg_tree=NULL, *fastser_tag_tree=NULL;
    gint          cnt, num_elements, elmt_status32_ofs=0, elmt_status;
    guint8        len, funccode, seq, rx_num_fc, tx_num_fc;
    guint8        seq_cnt, seq_fir, seq_fin, elmt_idx, fc_enable;
    guint8        *fid_str_ptr, *rid_str_ptr, *region_name_ptr, *tag_name_ptr;
    guint16       base_addr, num_addr, num_reg, addr1, addr2;
    guint32       tod_ms, elmt_status32, elmt_ts_offset;


    len = tvb_get_guint8(tvb, offset);

    fastser_item = proto_tree_add_text(tree, tvb, offset, len-2, "Fast SER Message Details");
    fastser_tree = proto_item_add_subtree(fastser_item, ett_selfm_fastser);

    /* Reported length */
    proto_tree_add_item(fastser_tree, hf_selfm_fastser_len, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* 5-byte Future Routing Address */
    proto_tree_add_item(fastser_tree, hf_selfm_fastser_routing_addr, tvb, offset+1, 5, ENC_NA);
    offset += 6;

    /* Add Status Byte to tree */
    proto_tree_add_item(fastser_tree, hf_selfm_fastser_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Get Function Code, add to tree */
    funccode = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(fastser_tree, hf_selfm_fastser_funccode, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Append Column Info w/ Function Code */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", val_to_str_const(funccode, selfm_fastser_func_code_vals, "Unknown Function Code"));
    }

    offset += 1;

    /* Get Sequence Byte, add to Tree */
    /* Some more decoding may be required here, format of this byte for multi-frame messages is guessed */
    /* based on observations from communications */
    /* 0x80 - First Message */
    /* 0x40 - Final Message */
    /* 0x3f - Sequence Count */
    /* Sequence Byte(s): */
    /* SEL-2411 */
    /* 0xC0 (11000000) - single frame req message m->r or r->m */
    /* 0x80 (10000000) - multi-frame message r->m */
    /* 0xC1 (11000001) - next scan after multi-frame message response m->r */
    /* 0x41 (01000001) - final response of multi-frame message r->m */
    /* SEL-735 */
    /* 0xC0 (11000000) - single frame req message m->r or r->m */
    /* 0x80 (10000000) - multi-frame message r->m */
    /* 0xC1 (11000001) - next scan after multi-frame message response m->r */
    /* 0x01 (00000001) - continued response of multi-frame message r->m */
    /* 0xC2 (11000010) - next scan after multi-frame message response m->r */
    /* 0x02 (00000010) - continued response of multi-frame message r->m */
    /* 0xC3 (11000011) - next scan after multi-frame message response m->r */
    /* 0x43 (01000011) - final response of multi-frame message r->m */
    /* SEL-421 */
    /* 0xC0 (11000000) - single frame req message m->r or r->m */
    /* 0x80 (10000000) - multi-frame message r->m */
    /* 0xC1 (11000001) - next scan after multi-frame message response m->r */
    /* 0x01 (00000001) - continued response of multi-frame message r->m */
    /* 0xC2 (11000010) - next scan after multi-frame message response m->r */
    /* 0x02 (00000010) - continued response of multi-frame message r->m */
    /* 0xC3 (11000011) - next scan after multi-frame message response m->r */
    /* 0x03 (00000011) - continued response of multi-frame message r->m */
    /* 0xC4 (11000100) - next scan after multi-frame message response m->r */
    /* 0x04 (00000100) - continued response of multi-frame message r->m */
    /* 0xC5 (11000100) - next scan after multi-frame message response m->r */
    /* 0x45 (01000101) - final response of multi-frame message r->m */

    seq = tvb_get_guint8(tvb, offset);
    seq_cnt = seq & FAST_SER_SEQ_CNT;
    seq_fir = seq & FAST_SER_SEQ_FIR;
    seq_fin = seq & FAST_SER_SEQ_FIN;

    fastser_seq_item = proto_tree_add_uint_format(fastser_tree, hf_selfm_fastser_seq, tvb, offset, 1, seq, "Sequence Byte: 0x%02x (", seq);
    if (seq_fir) proto_item_append_text(fastser_seq_item, "FIR, ");
    if (seq_fin) proto_item_append_text(fastser_seq_item, "FIN, ");
    proto_item_append_text(fastser_seq_item, "Count %u)", seq_cnt);

    fastser_seq_tree = proto_item_add_subtree(fastser_seq_item, ett_selfm_fastser_seq);
    proto_tree_add_boolean(fastser_seq_tree, hf_selfm_fastser_seq_fir, tvb, offset, 1, seq);
    proto_tree_add_boolean(fastser_seq_tree, hf_selfm_fastser_seq_fin, tvb, offset, 1, seq);
    proto_tree_add_item(fastser_seq_tree, hf_selfm_fastser_seq_cnt, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Add Response Number to tree */
    proto_tree_add_item(fastser_tree, hf_selfm_fastser_resp_num, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Depending on Function Code used, remaining section of packet will be handled differently. */
    switch (funccode) {
        case FAST_SER_MESSAGE_DEF_ACK: /* 0x80 (resp to 0x00) - Fast SER Message Definition Acknowledge */

             /* Routing Support */
             proto_tree_add_item(fastser_tree, hf_selfm_fastser_def_route_sup, tvb, offset, 1, ENC_BIG_ENDIAN);
             offset += 1;

             /* RX / TX Status */
             proto_tree_add_item(fastser_tree, hf_selfm_fastser_def_rx_stat, tvb, offset, 1, ENC_BIG_ENDIAN);
             proto_tree_add_item(fastser_tree, hf_selfm_fastser_def_tx_stat, tvb, offset+1, 1, ENC_BIG_ENDIAN);
             offset += 2;

             /* Max Frames RX/TX */
             proto_tree_add_item(fastser_tree, hf_selfm_fastser_def_rx_maxfr, tvb, offset, 1, ENC_BIG_ENDIAN);
             proto_tree_add_item(fastser_tree, hf_selfm_fastser_def_tx_maxfr, tvb, offset+1, 1, ENC_BIG_ENDIAN);
             offset += 2;

             /* 6 bytes of reserved space */
             offset += 6;

             /* Number of Supported RX Function Codes */
             rx_num_fc = tvb_get_guint8(tvb, offset);
             fastser_def_fc_item = proto_tree_add_item(fastser_tree, hf_selfm_fastser_def_rx_num_fc, tvb, offset, 1, ENC_BIG_ENDIAN);
             fastser_def_fc_tree = proto_item_add_subtree(fastser_def_fc_item, ett_selfm_fastser_def_fc);
             offset += 1;

             /* Add Supported RX Function Codes to tree */
             for (cnt=0; cnt<rx_num_fc; cnt++) {
                 proto_tree_add_item(fastser_def_fc_tree, hf_selfm_fastser_def_rx_fc, tvb, offset, 1, ENC_BIG_ENDIAN);
                 offset += 2;
             }

             /* Number of Supported TX Function Codes */
             tx_num_fc = tvb_get_guint8(tvb, offset);
             fastser_def_fc_item = proto_tree_add_item(fastser_tree, hf_selfm_fastser_def_tx_num_fc, tvb, offset, 1, ENC_BIG_ENDIAN);
             fastser_def_fc_tree = proto_item_add_subtree(fastser_def_fc_item, ett_selfm_fastser_def_fc);
             offset += 1;

             /* Add Supported TX Function Codes to tree */
             for (cnt=0; cnt<tx_num_fc; cnt++) {
                 proto_tree_add_item(fastser_def_fc_tree, hf_selfm_fastser_def_tx_fc, tvb, offset, 1, ENC_BIG_ENDIAN);
                 offset += 2;
             }

             break;

        case FAST_SER_EN_UNS_DATA:   /* 0x01 - Enabled Unsolicited Data Transfers */

             /* Function code to enable */
             fc_enable = tvb_get_guint8(tvb, offset);
             proto_tree_add_item(fastser_tree, hf_selfm_fastser_uns_en_fc, tvb, offset, 1, ENC_BIG_ENDIAN);

            /* Append Column Info w/ "Enable" Function Code */
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Function to Enable (%#x)", fc_enable);
            }

             /* 3-byte Function Code data */
             proto_tree_add_item(fastser_tree, hf_selfm_fastser_uns_en_fc_data, tvb, offset+1, 3, ENC_NA);

             offset += 4;

             break;

        case FAST_SER_DIS_UNS_DATA:   /* 0x02 - Disable Unsolicited Data Transfers */

             /* Function code to disable */
             fc_enable = tvb_get_guint8(tvb, offset);
             proto_tree_add_item(fastser_tree, hf_selfm_fastser_uns_dis_fc, tvb, offset, 1, ENC_BIG_ENDIAN);

            /* Append Column Info w/ "Disable" Function Code */
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Function to Disable (%#x)", fc_enable);
            }

             /* 1-byte Function Code data */
             proto_tree_add_item(fastser_tree, hf_selfm_fastser_uns_dis_fc_data, tvb, offset+1, 1, ENC_NA);

             offset += 2;

             break;


        case FAST_SER_READ_REQ:     /* 0x10 - Read Request - unknown full structure */

            offset += 2; /* 2 unknown bytes */

            base_addr = tvb_get_ntohs(tvb, offset); /* unknown - 16-bit field with base address to read? */

            /* Append Column Info w/ Base Address */
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x", base_addr);
            }

            proto_tree_add_item(fastser_tree, hf_selfm_fastser_read_baseaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_read_numaddr, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            offset += 4;
            break;

        case FAST_SER_READ_RESP:     /* 0x90 (resp to 0x10) - Read Response - unknown full structure */

            offset += 2; /* 2 unknown bytes */

            base_addr = tvb_get_ntohs(tvb, offset); /* unknown - 16-bit field with base address to read? */
            num_addr = tvb_get_ntohs(tvb, offset+2); /* unknown - 16-bit field with number of 16-bit addresses to read? */

            /* Append Column Info w/ Base Address */
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x", base_addr);
            }

            proto_tree_add_item(fastser_tree, hf_selfm_fastser_read_baseaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_read_numaddr, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            offset += 4;

            /* Skip over read response data, we'll be able to format and decode this later once specifications are out */
            offset += num_addr*2;

            break;

        case FAST_SER_UNS_RESP:     /* 0x18 - Unsolicited Fast SER Data Response */

            /* 4 bytes - "Origination Path" */
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_unsresp_orig, tvb, offset, 4, ENC_NA);
            offset += 4;

            /* Timestamp: 2-byte day-of-year, 2-byte year, 4-byte time-of-day in milliseconds  */
            /* XXX - We can use a built-in function to convert the tod_ms to a readable time format, is there anything for day_of_year? */
            tod_ms = tvb_get_ntohl(tvb, offset+4);

            proto_tree_add_item(fastser_tree, hf_selfm_fastser_unsresp_doy, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_unsresp_year, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_unsresp_todms, tvb, offset+4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_text(fastser_tree, tvb, offset+4, 4, "Time of Day (decoded): %s", time_msecs_to_str(tod_ms));
            offset += 8;

            /* Build element tree */
            /* Determine the number of elements returned in this unsolicited message */
            /* The general formula is: (Length - 34) / 4 */
            num_elements = (len-34) / 4;

            fastser_elementlist_item = proto_tree_add_uint(fastser_tree, hf_selfm_fastser_unsresp_num_elmt, tvb, offset, (4*num_elements), num_elements);
            fastser_elementlist_tree = proto_item_add_subtree(fastser_elementlist_item, ett_selfm_fastser_element_list);

            /* "Reported New Status" word for up to 32 index elements is following the upcoming 0xFFFFFFFE End-of-record indicator
               Search for that indicator and use the detected tvb offset+4 to retrieve the proper 32-bit status word.
               Save this word for use in the element index printing but don't print the word itself until the end of the tree dissection */
            for (cnt = offset; cnt < len; cnt++) {

                if (tvb_memeql(tvb, cnt, "\xFF\xFF\xFF\xFE", 4) == 0) {
                    elmt_status32_ofs = cnt+4;
                }
            }
            elmt_status32 = tvb_get_ntohl(tvb, elmt_status32_ofs );

            /* Cycle through each element we have detected that exists in the SER record */
            for (cnt=0; cnt<num_elements; cnt++) {

                /* Get Element Index and Timestamp Offset (in uSec) */
                elmt_idx = tvb_get_guint8(tvb, offset);
                elmt_ts_offset = (guint32)((tvb_get_guint8(tvb, offset+1) << 16) | (tvb_get_guint8(tvb, offset+2) << 8) | (tvb_get_guint8(tvb, offset+3)));

                /* Bit shift the appropriate element from the 32-bit elmt_status word to position 0 and get the bit state for use in the tree */
                elmt_status = ((elmt_status32 >> cnt) & 0x01);

                /* Build the tree */
                fastser_element_item = proto_tree_add_text(fastser_elementlist_tree, tvb, offset, 4,
                    "Reported Event %d (Index: %d, New State: %s)", cnt+1, elmt_idx, val_to_str_const(elmt_status, selfm_ser_status_vals, "Unknown"));
                fastser_element_tree = proto_item_add_subtree(fastser_element_item, ett_selfm_fastser_element);

                /* Add Index Number and Timestamp offset to tree */
                proto_tree_add_item(fastser_element_tree, hf_selfm_fastser_unsresp_elmt_idx, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(fastser_element_tree, hf_selfm_fastser_unsresp_elmt_ts_ofs, tvb, offset+1, 3, ENC_NA);
                proto_tree_add_text(fastser_element_tree, tvb, offset+1, 3,
                    "SER Element Timestamp Offset (decoded): %s", time_msecs_to_str(tod_ms + (elmt_ts_offset/1000)));
                proto_tree_add_uint(fastser_element_tree, hf_selfm_fastser_unsresp_elmt_status, tvb, elmt_status32_ofs, 4, elmt_status);

                offset += 4;

            }

            /* 4-byte End-of-Record Terminator 0xFFFFFFFE */
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_unsresp_eor, tvb, offset, 4, ENC_NA);
            offset += 4;

            /* 4-byte Element Status word */
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_unsresp_elmt_statword, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            break;


        case FAST_SER_UNS_WRITE:    /* 0x20 - Unsolicited Write */

            /* Write Address Region #1 and #2, along with number of 16-bit registers */
            addr1 =   tvb_get_ntohs(tvb, offset);
            addr2 =   tvb_get_ntohs(tvb, offset+2);
            num_reg = tvb_get_ntohs(tvb, offset+4);

            /* Append Column Info w/ Address Information */
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x, %#x", addr1, addr2);
            }

            proto_tree_add_item(fastser_tree, hf_selfm_fastser_unswrite_addr1, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_unswrite_addr2, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_unswrite_num_reg, tvb, offset+4, 2, ENC_BIG_ENDIAN);

            offset += 6;

            /* For the number of registers, step through and retrieve/print each 16-bit component */
            for (cnt=0; cnt < num_reg; cnt++) {
                proto_tree_add_item(fastser_tree, hf_selfm_fastser_unswrite_reg_val, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }

            break;

        case FAST_SER_DEVDESC_RESP: /* 0xB0 - Device Description Response - unknown full structure */

            fid_str_ptr = tvb_get_ephemeral_string(tvb, offset, 50);  /* Add FID / RID ASCII data to tree */
            rid_str_ptr = tvb_get_ephemeral_string(tvb, offset+50, 40);
            proto_tree_add_text(fastser_tree, tvb, offset, 50, "FID: %s", fid_str_ptr);
            proto_tree_add_text(fastser_tree, tvb, offset+50, 40, "RID: %s", rid_str_ptr);
            offset += 90;

            /* unknown - 16-bit field with number of data regions? */
            num_reg = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_devdesc_num_reg, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* 2 unknown bytes */
            offset += 2;

            /* exact arrangement of these regions are unknown, but I think believe we have a 12 byte region name,
               followed by 16-bit base and address count fields */
            for (cnt=0; cnt<num_reg; cnt++) {

                fastser_datareg_item = proto_tree_add_text(fastser_tree, tvb, offset, 18, "Fast SER Data Region #%d", cnt+1);
                fastser_datareg_tree = proto_item_add_subtree(fastser_datareg_item, ett_selfm_fastser_datareg);

                region_name_ptr = tvb_get_ephemeral_string(tvb, offset, 12);
                proto_tree_add_text(fastser_datareg_tree, tvb, offset, 12, "Data Region Name: %s", region_name_ptr);
                offset += 12;

                /* unknown - 16-bit field with base address of data region? */
                proto_tree_add_item(fastser_datareg_tree, hf_selfm_fastser_read_baseaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* unknown - 16-bit field with number of addresses in data region? */
                proto_tree_add_item(fastser_datareg_tree, hf_selfm_fastser_read_numaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* 2 unknown bytes */
                offset += 2;

            }

            break;
        case FAST_SER_DATAFMT_REQ: /* 0x31 - Data Format Request - unknown full structure */

            /* 2 unknown bytes */
           offset += 2;

            /* unknown - 16-bit field with base address to read? */
            base_addr = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_read_baseaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Append Column Info w/ Base Address */
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x", base_addr);
            }

            break;

        case FAST_SER_DATAFMT_RESP: /* 0xB1 - Data Format Response - unknown full structure */

            /* 2 unknown bytes */
            offset += 2;

            /* unknown - 16-bit field with base address to read? */
            base_addr = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_read_baseaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Append Column Info w/ Base Address */
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x", base_addr);
            }

            /* unknown - 16-bit field with number of tags to follow? */
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_datafmt_resp_num_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            while ((tvb_reported_length_remaining(tvb, offset)) > 2) {
                tag_name_ptr = tvb_get_ephemeral_string(tvb, offset, 11);  /* unknown field - Tag name 11 bytes? */
                fastser_tag_item = proto_tree_add_text(fastser_tree, tvb, offset, 14, "Tag Name: %s", tag_name_ptr);
                fastser_tag_tree = proto_item_add_subtree(fastser_tag_item, ett_selfm_fastser_tag);

                /* Unknown 3 bytes that follow */
                /* 01 - Quantity of Values within Tag */
                /* 02 - Unused ??? */
                /* 03 - Data Type of Tag */
                proto_tree_add_item(fastser_tag_tree, hf_selfm_fastser_datafmt_resp_tag_qty, tvb, offset+11, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(fastser_tag_tree, hf_selfm_fastser_datafmt_resp_tag_type, tvb, offset+13, 1, ENC_BIG_ENDIAN);

                offset += 14;
            }
            break;

        case FAST_SER_BITLABEL_REQ: /* 0x33 - Bit Label Request - unknown full structure */

            /* 2 unknown bytes */
            offset += 2;

            /* unknown - 16-bit field with base address to read? */
            base_addr = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(fastser_tree, hf_selfm_fastser_read_baseaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Append Column Info w/ Base Address */
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x", base_addr);
            }
            break;

        case FAST_SER_BITLABEL_RESP: /* 0xB3 - Bit Label Response - unknown full structure */

            /* Variable length string containing the names of 8 digital bits.  Each name is max 8 chars and each is null-seperated */
            proto_tree_add_text(fastser_tree, tvb, offset, (tvb_reported_length_remaining(tvb, offset)-2), "Bit Label Data %s",
               tvb_format_text(tvb, offset, (tvb_reported_length_remaining(tvb, offset)-2)));

            /* Skip over variable-length string */
            offset += (tvb_reported_length_remaining(tvb, offset)-2);

        default:
            break;
    } /* func_code */

    /* XXX - Should eventually get a function here to validate this CRC16 */
    proto_tree_add_item(fastser_tree, hf_selfm_fastser_crc16, tvb, offset, 2, ENC_BIG_ENDIAN);

    return tvb_length(tvb);

}


/******************************************************************************************************/
/* Code to dissect SEL Fast Message Protocol packets */
/* Will call other sub-dissectors, as needed         */
/******************************************************************************************************/
static void
dissect_selfm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *selfm_item=NULL;
    proto_tree    *selfm_tree=NULL;
    int           offset=0;
    guint16       msg_type, len;
    tvbuff_t      *selfm_tvb;

    /* Make entries in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SEL Fast Msg");
    col_clear(pinfo->cinfo, COL_INFO);

    len = tvb_length(tvb);

    /* If this is a Telnet-encapsulated Ethernet, let's clean out the IAC 0xFF instances */
    if ((pinfo->srcport) && selfm_telnet_clean) {
        selfm_tvb=clean_telnet_iac(pinfo, tvb, offset, len);
    }
    else {
        selfm_tvb = tvb_new_subset( tvb, offset, len, len);
    }

    msg_type = tvb_get_ntohs(selfm_tvb, offset);

    /* Configuration (0xA5C1, 0xA5C2, 0xA5C3) and corresponding data frames (0xA5D1, 0xA5D2, 0xA5D3)
    * need special treatment during the first run:
    * For Fast Meter Configuration frames (0xA5C1), a 'fm_config_frame' struct is created to hold the
    * information necessary to decode subsequent Fast Meter Data frames (0xA5D1). A pointer to this
    * struct is saved in the conversation and is copied to the per-packet information if a
    * Fast Meter Data frame is dissected.
    */
    if (!pinfo->fd->flags.visited) {
        conversation_t *conversation;
        fm_conversation *conv_data;

        /* Find a conversation, create a new if no one exists */
        conversation = find_or_create_conversation(pinfo);

        conv_data = (fm_conversation *)conversation_get_proto_data(conversation, proto_selfm);

        if (conv_data == NULL) {
            conv_data = (fm_conversation *)wmem_alloc(wmem_file_scope(), sizeof(fm_conversation));
            conv_data->fm_config_frames = wmem_slist_new(wmem_file_scope());
            conversation_add_proto_data(conversation, proto_selfm, (void *)conv_data);
        }

        p_add_proto_data(pinfo->fd, proto_selfm, 0, conv_data);

        if ((CMD_FM_CONFIG == msg_type) || (CMD_DFM_CONFIG == msg_type) || (CMD_PDFM_CONFIG == msg_type)) {
            /* Fill the fm_config_frame */
            fm_config_frame *frame_ptr = fmconfig_frame_fast(selfm_tvb);
            frame_ptr->fnum = pinfo->fd->num;
            wmem_slist_prepend(conv_data->fm_config_frames, frame_ptr);
        }

    } /* if (!visited) */

    if (tree) {

        selfm_item = proto_tree_add_protocol_format(tree, proto_selfm, selfm_tvb, 0, len, "SEL Fast Message");
        selfm_tree = proto_item_add_subtree(selfm_item, ett_selfm);

        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_clear(pinfo->cinfo, COL_INFO); /* clear out stuff in the info column */
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_const(msg_type, selfm_msgtype_vals, "Unknown Message Type"));
        }

        /* Add Message Type to Protocol Tree */
        proto_tree_add_item(selfm_tree, hf_selfm_msgtype, selfm_tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Determine correct message type and call appropriate dissector */
        if (tvb_reported_length_remaining(selfm_tvb, offset) > 0) {
                switch (msg_type) {
                    case CMD_RELAY_DEF:
                        dissect_relaydef_frame(selfm_tvb, selfm_tree, offset);
                        break;
                    case CMD_FM_CONFIG:
                    case CMD_DFM_CONFIG:
                    case CMD_PDFM_CONFIG:
                        dissect_fmconfig_frame(selfm_tvb, selfm_tree, offset);
                        break;
                    case CMD_FM_DATA:
                        dissect_fmdata_frame(selfm_tvb, selfm_tree, pinfo, offset, CMD_FM_CONFIG);
                        break;
                    case CMD_DFM_DATA:
                        dissect_fmdata_frame(selfm_tvb, selfm_tree, pinfo, offset, CMD_DFM_CONFIG);
                        break;
                    case CMD_PDFM_DATA:
                        dissect_fmdata_frame(selfm_tvb, selfm_tree, pinfo, offset, CMD_PDFM_CONFIG);
                        break;
                    case CMD_FASTOP_CONFIG:
                        dissect_foconfig_frame(selfm_tvb, selfm_tree, offset);
                        break;
                    case CMD_FAST_SER:
                        dissect_fastser_frame(selfm_tvb, selfm_tree, pinfo, offset);
                        break;
                    case CMD_FASTOP_RB_CTRL:
                    case CMD_FASTOP_BR_CTRL:
                        dissect_fastop_frame(selfm_tvb, selfm_tree, pinfo, offset);
                        break;
                    default:
                        break;
                } /* msg_type */
        } /* remaining length > 0 */
    } /* tree */

}

/******************************************************************************************************/
/* Return length of SEL Protocol over TCP message (used for re-assembly)                               */
/* SEL Protocol "Scan" messages are generally 2-bytes in length and only include a 16-bit message type */
/* SEL Protocol "Response" messages include a "length" byte in each response message but an issue      */
/* is that the "length" byte does not always line up with the actual length of the data packet due to  */
/* Telnet 0xFF pad bytes (as documented elsewhere).  Make a best-guess "total size" effort here.       */
/******************************************************************************************************/
static guint
get_selfm_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_)
{
    guint message_len=0;  /* message length, inclusive of header, data, crc */
    guint16 msg_type;

    if (tvb_length(tvb) > 2) {
        msg_type = tvb_get_ntohs(tvb, 0);

        switch (msg_type) {
            case CMD_FM_CONFIG:
                /* 0xA5C1 messages have reported lengths, but extra 0xFF pad bytes strewn about in 'Telnet' mode */
                /* Attempt to guess the length by using the num_ai (normal size 10 bytes) and num_calc (normal size 15 bytes) block fields  */
                /* If the number of scale factors is 0 (offset 5) then there will be 1 extra 0xFFs per num_ai (offset 6) */
                /* Number of calculation blocks (offset 9) will typically produce a minimum of 20 bytes including padding */
                /* 18 bytes of hardcoded data are: hdr(2), len, flag, sf_loc, sf_num, ai_num, samp_num,
                                                   dig_num, num_calc, ai_ofs(2), ts_ofs(2), dig_ofs(2), pad, crc */

                /* Only attempt to retrieve bytes that we know will exist */
                if (tvb_length(tvb) > 10) {
                    if (tvb_get_guint8(tvb, 5) != 0) {
                        message_len = ((tvb_get_guint8(tvb, 6) * 10) + (tvb_get_guint8(tvb, 9) * 20) + 18);
                    }
                    else {
                        message_len = ((tvb_get_guint8(tvb, 6) * 11) + (tvb_get_guint8(tvb, 9) * 20) + 18);
                    }
                }
                /* Otherwise we can fall back on the length byte */
                else {
                    message_len = tvb_get_guint8(tvb, 2);
                }

                /* After calculating theoretical length, check if actual length of tvb is longer.  In that case, use the tvb length */
                if (message_len < tvb_length(tvb)) {
                    message_len = tvb_length(tvb);
                }

                break;

            case CMD_DFM_CONFIG:
            case CMD_PDFM_CONFIG:
                /* 0xA5C2/C2 messages have reported lengths, but typically extra 0xFF pad bytes strewn about in Telnet mode */
                /* Attempt to guess the length by using the num_ai (normal size 11 bytes) and harcoded fields */
                /* 20 bytes of hardcoded data are: hdr(2), len, flag, sf_loc, sf_num, ai_num, samp_num,
                                                   dig_num, num_calc, ai_ofs(2), ts_ofs(2), dig_ofs(4), pad, crc */

                /* Only attempt to retrieve bytes that we know will exist */
                if (tvb_length(tvb) > 7) {
                    message_len = ((tvb_get_guint8(tvb, 6) * 11) + 20);
                }
                /* Otherwise we can fall back on the length byte */
                else {
                    message_len = tvb_get_guint8(tvb, 2);
                }

                /* After calculating theoretical length, check if actual length of tvb is longer.  In that case, use the tvb length */
                if (message_len < tvb_length(tvb)) {
                    message_len = tvb_length(tvb);
                }

                break;

            case CMD_RELAY_DEF:
            case CMD_FM_DATA:
            case CMD_DFM_DATA:
            case CMD_PDFM_DATA:
            case CMD_FAST_SER:
                /* Theses messages include length byte and don't generally contain 0xFF data */
                message_len = tvb_get_guint8(tvb, 2);

                /* After processing length byte, check if actual length of tvb is longer.  In that case, use the tvb length */
                if (message_len < tvb_length(tvb)) {
                    message_len = tvb_length(tvb);
                }

                break;

            default:
                /* For remaining packet types, fall back whatever length is greater, len byte from packet or tvb length */
                if (tvb_get_guint8(tvb, 2) > tvb_length(tvb)) {
                    message_len = tvb_get_guint8(tvb, 2);
                }
                else {
                    message_len = tvb_length(tvb);
                }
                break;
        }

    }
    /* for 2-byte poll messages, manually set the length to 2 */
    else if (tvb_length(tvb) == 2) {
        message_len = 2;
    }

    return message_len;
}

/******************************************************************************************************/
/* Dissect (and possibly Re-assemble) SEL protocol payload data */
/******************************************************************************************************/
static gboolean
dissect_selfm_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    gint length = tvb_length(tvb);

    /* Check for a SEL FM packet.  It should begin with 0xA5 */
    if(length < 2 || tvb_get_guint8(tvb, 0) != 0xA5) {
        /* Not a SEL Protocol packet, just happened to use the same port */
        return FALSE;
    }

    tcp_dissect_pdus(tvb, pinfo, tree, selfm_desegment, 2,
                   get_selfm_len, dissect_selfm);

    return TRUE;
}

/******************************************************************************************************/
/* Dissect "simple" SEL protocol payload (no TCP re-assembly) */
/******************************************************************************************************/
static gboolean
dissect_selfm_simple(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint length = tvb_length(tvb);

    /* Check for a SEL FM packet.  It should begin with 0xA5 */
    if(length < 2 || tvb_get_guint8(tvb, 0) != 0xA5) {
        /* Not a SEL Protocol packet, just happened to use the same port */
        return FALSE;
    }

    dissect_selfm(tvb, pinfo, tree);

    return TRUE;
}

/******************************************************************************************************/
/* Register the protocol with Wireshark */
/******************************************************************************************************/
void proto_reg_handoff_selfm(void);

void
proto_register_selfm(void)
{
    /* SEL Protocol header fields */
    static hf_register_info selfm_hf[] = {
        { &hf_selfm_msgtype,
        { "Message Type", "selfm.msgtype", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &selfm_msgtype_vals_ext, 0x0, NULL, HFILL }},
        /* "Relay Definition" specific fields */
        { &hf_selfm_relaydef_len,
        { "Length", "selfm.relaydef.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_relaydef_numproto,
        { "Number of Protocols", "selfm.relaydef.numproto", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_relaydef_numfm,
        { "Number of Fast Meter Messages", "selfm.relaydef.numfm", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_relaydef_numflags,
        { "Number of Status Flags", "selfm.relaydef.numflags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_relaydef_fmcfg_cmd,
        { "Fast Meter Config Command", "selfm.relaydef.fmcfg_cmd", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_relaydef_fmdata_cmd,
        { "Fast Meter Data Command", "selfm.relaydef.fmdata_cmd", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_relaydef_statbit,
        { "Status Flag Bit", "selfm.relaydef.status_bit", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_relaydef_statbit_cmd,
        { "Status Flag Bit Response Command", "selfm.relaydef.status_bit_cmd", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_relaydef_proto,
        { "Supported Protocol", "selfm.relaydef.proto", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &selfm_relaydef_proto_vals_ext, 0x0, NULL, HFILL }},
        /* "Fast Meter Configuration" specific fields */
        { &hf_selfm_fmconfig_len,
        { "Length", "selfm.fmconfig.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_numflags,
        { "Number of Status Flags", "selfm.fmconfig.numflags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_loc_sf,
        { "Location of Scale Factor", "selfm.fmconfig.loc_sf", FT_UINT8, BASE_DEC, VALS(selfm_fmconfig_sfloc_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_num_sf,
        { "Number of Scale Factors", "selfm.fmconfig.num_sf", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_num_ai,
        { "Number of Analog Input Channels", "selfm.fmconfig.num_ai", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_num_samp,
        { "Number of Samples per AI Channel", "selfm.fmconfig.num_samp", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_num_dig,
        { "Number of Digital Banks", "selfm.fmconfig.num_dig", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_num_calc,
        { "Number of Calculation Blocks", "selfm.fmconfig.num_calc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_ofs_ai,
        { "First Analog Channel Offset", "selfm.fmconfig.ofs_ai", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_ofs_ts,
        { "Timestamp Offset", "selfm.fmconfig.ofs_ts", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_ofs_dig,
        { "First Digital Bank Offset", "selfm.fmconfig.ofs_dig", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_ai_type,
        { "Analog Channel Type", "selfm.fmconfig.ai_type", FT_UINT8, BASE_DEC, VALS(selfm_fmconfig_ai_chtype_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_ai_sf_type,
        { "Analog Channel Scale Factor Type", "selfm.fmconfig.ai_sf_type", FT_UINT8, BASE_DEC, VALS(selfm_fmconfig_ai_sftype_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_ai_sf_ofs,
        { "Analog Channel Scale Factor Offset", "selfm.fmconfig.ai_sf_ofs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        /* "Fast Meter Data" specific fields */
        { &hf_selfm_fmdata_len,
        { "Length", "selfm.fmdata.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmdata_flagbyte,
        { "Status Flags Byte", "selfm.fmdata.flagbyte", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmdata_ai_sf_fp,
        { "Using IEEE FP Format Scale Factor", "selfm.fmdata.ai.sf_fp",FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmdata_dig_b0,
        { "Bit 0", "selfm.fmdata.dig_b0", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
        { &hf_selfm_fmdata_dig_b1,
        { "Bit 1", "selfm.fmdata.dig_b1", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
        { &hf_selfm_fmdata_dig_b2,
        { "Bit 2", "selfm.fmdata.dig_b2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
        { &hf_selfm_fmdata_dig_b3,
        { "Bit 3", "selfm.fmdata.dig_b3", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
        { &hf_selfm_fmdata_dig_b4,
        { "Bit 4", "selfm.fmdata.dig_b4", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
        { &hf_selfm_fmdata_dig_b5,
        { "Bit 5", "selfm.fmdata.dig_b5", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
        { &hf_selfm_fmdata_dig_b6,
        { "Bit 6", "selfm.fmdata.dig_b6", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
        { &hf_selfm_fmdata_dig_b7,
        { "Bit 7", "selfm.fmdata.dig_b7", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
        /* "Fast Operate Configuration" specific fields */
        { &hf_selfm_foconfig_len,
        { "Length", "selfm.foconfig.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_foconfig_num_brkr,
        { "Number of Breaker Bits", "selfm.foconfig.num_brkr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_foconfig_num_rb,
        { "Number of Remote Bits", "selfm.foconfig.num_rb", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_foconfig_prb_supp,
        { "Remote Bit Pulse Supported", "selfm.foconfig.prb_supp", FT_UINT8, BASE_DEC, VALS(selfm_foconfig_prb_supp_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_foconfig_reserved,
        { "Reserved Bit (Future)", "selfm.foconfig.reserved", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_foconfig_brkr_open,
        { "Breaker Bit Open Command", "selfm.foconfig.brkr_open", FT_UINT8, BASE_HEX, VALS(selfm_fo_br_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_foconfig_brkr_close,
        { "Breaker Bit Close Command", "selfm.foconfig.brkr_close", FT_UINT8, BASE_HEX, VALS(selfm_fo_br_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_foconfig_rb_cmd,
        { "Remote Bit Command", "selfm.foconfig.rb_cmd", FT_UINT8, BASE_HEX, VALS(selfm_fo_rb_vals), 0x0, NULL, HFILL }},
        /* "Fast Operate" specific fields */
        { &hf_selfm_fastop_len,
        { "Length", "selfm.fastop.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastop_rb_code,
        { "Remote Bit Operate Code", "selfm.fastop.rb_code", FT_UINT8, BASE_HEX, VALS(selfm_fo_rb_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fastop_br_code,
        { "Breaker Bit Operate Code", "selfm.fastop.br_code", FT_UINT8, BASE_HEX, VALS(selfm_fo_br_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fastop_valid,
        { "Operate Code Validation", "selfm.fastop.valid", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        /* "Fast SER Message" specific fields */
        { &hf_selfm_fastser_len,
        { "Length", "selfm.fastser.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_routing_addr,
        { "Routing Address (future)", "selfm.fastser.routing_addr", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_status,
        { "Status Byte", "selfm.fastser.status", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_funccode,
        { "Function Code", "selfm.fastser.funccode", FT_UINT8, BASE_HEX, VALS(selfm_fastser_func_code_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_seq,
        { "Sequence Byte", "selfm.fastser.seq", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_seq_fir,
        { "FIR", "selfm.fastser.seq_fir", FT_BOOLEAN, 8, NULL, FAST_SER_SEQ_FIR, NULL, HFILL }},
        { &hf_selfm_fastser_seq_fin,
        { "FIN", "selfm.fastser.seq_fin", FT_BOOLEAN, 8, NULL, FAST_SER_SEQ_FIN, NULL, HFILL }},
        { &hf_selfm_fastser_seq_cnt,
        { "Count", "selfm.fastser.seq_cnt", FT_UINT8, BASE_DEC, NULL, FAST_SER_SEQ_CNT, "Frame Count Number", HFILL }},
        { &hf_selfm_fastser_resp_num,
        { "Response Number", "selfm.fastser.resp_num", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_crc16,
        { "CRC-16", "selfm.fastser.crc16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_def_route_sup,
        { "Routing Support", "selfm.fastser.def_route_sup", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_def_rx_stat,
        { "Status RX", "selfm.fastser.def_rx_stat", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_def_tx_stat,
        { "Status TX", "selfm.fastser.def_tx_stat", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_def_rx_maxfr,
        { "Max Frames RX", "selfm.fastser.def_rx_maxfr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_def_tx_maxfr,
        { "Max Frames TX", "selfm.fastser.def_tx_maxfr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_def_rx_num_fc,
        { "Number of Supported RX Function Codes", "selfm.fastser.def_rx_num_fc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_def_rx_fc,
        { "Receive Function Code", "selfm.fastser.def_rx_fc", FT_UINT8, BASE_HEX, VALS(selfm_fastser_func_code_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_def_tx_num_fc,
        { "Number of Supported TX Function Codes", "selfm.fastser.def_tx_num_fc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_def_tx_fc,
        { "Transmit Function Code", "selfm.fastser.def_tx_fc", FT_UINT8, BASE_HEX, VALS(selfm_fastser_func_code_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_uns_en_fc,
        { "Function Code to Enable", "selfm.fastser.uns_en_fc", FT_UINT8, BASE_HEX, VALS(selfm_fastser_func_code_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_uns_en_fc_data,
        { "Function Code Data", "selfm.fastser.uns_en_fc_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_uns_dis_fc,
        { "Function Code to Disable", "selfm.fastser.uns_dis_fc", FT_UINT8, BASE_HEX, VALS(selfm_fastser_func_code_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_uns_dis_fc_data,
        { "Function Code Data", "selfm.fastser.uns_dis_fc_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unsresp_orig,
        { "Origination path", "selfm.fastser.unsresp_orig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unsresp_doy,
        { "Day of Year", "selfm.fastser.unsresp_doy", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unsresp_year,
        { "Year", "selfm.fastser.unsresp_year", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unsresp_todms,
        { "Time of Day (in ms)", "selfm.fastser.unsresp_todms", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unsresp_num_elmt,
        { "Number of SER Elements", "selfm.fastser.unsresp_num_elmt", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unsresp_elmt_idx,
        { "SER Element Index", "selfm.fastser.unsresp_elmt_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unsresp_elmt_ts_ofs,
        { "SER Element Timestamp Offset (us)", "selfm.fastser.unsresp_elmt_ts_ofs", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unsresp_elmt_status,
        { "SER Element Status", "selfm.fastser.unsresp_elmt_status", FT_UINT8, BASE_DEC, VALS(selfm_ser_status_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unsresp_eor,
        { "End of Record Indicator", "selfm.fastser.unsresp_eor", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unsresp_elmt_statword,
        { "SER Element Status Word", "selfm.fastser.unsresp_elmt_statword", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unswrite_addr1,
        { "Write Address Region #1", "selfm.fastser.unswrite_addr1", FT_UINT16, BASE_HEX, VALS(selfm_fastser_unswrite_com_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unswrite_addr2,
        { "Write Address Region #2", "selfm.fastser.unswrite_addr2", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unswrite_num_reg,
        { "Number of Registers", "selfm.fastser.unswrite_num_reg", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_unswrite_reg_val,
        { "Register Value", "selfm.fastser.unswrite_reg_val", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_read_baseaddr,
        { "Base Address", "selfm.fastser.read_baseaddr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_read_numaddr,
        { "Number of Addresses", "selfm.fastser.read_numaddr", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_datafmt_resp_num_tag,
        { "Number of Tags", "selfm.fastser.datafmt_resp_numtag", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_datafmt_resp_tag_qty,
        { "Quantity of Values within Tag", "selfm.fastser.datafmt_resp_tagqty", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_datafmt_resp_tag_type,
        { "Tag Data Type", "selfm.fastser.datafmt_resp_tagtype", FT_UINT8, BASE_HEX, VALS(selfm_fastser_tagtype_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fastser_devdesc_num_reg,
        { "Number of Data Regions", "selfm.fastser.devdesc_num_reg", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_selfm,
        &ett_selfm_relaydef,
        &ett_selfm_relaydef_fm,
        &ett_selfm_relaydef_proto,
        &ett_selfm_relaydef_flags,
        &ett_selfm_fmconfig,
        &ett_selfm_fmconfig_ai,
        &ett_selfm_foconfig,
        &ett_selfm_foconfig_brkr,
        &ett_selfm_foconfig_rb,
        &ett_selfm_fastop,
        &ett_selfm_fmdata,
        &ett_selfm_fmdata_ai,
        &ett_selfm_fmdata_dig,
        &ett_selfm_fmdata_ai_ch,
        &ett_selfm_fmdata_dig_ch,
        &ett_selfm_fastser,
        &ett_selfm_fastser_seq,
        &ett_selfm_fastser_def_fc,
        &ett_selfm_fastser_tag,
        &ett_selfm_fastser_element_list,
        &ett_selfm_fastser_element,
        &ett_selfm_fastser_datareg,
   };

    module_t *selfm_module;

    /* Register the protocol name and description */
    proto_selfm = proto_register_protocol("SEL Fast Message", "SEL Fast Message", "selfm");

    /* Registering protocol to be called by another dissector */
    new_register_dissector("selfm", dissect_selfm_simple, proto_selfm);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_selfm, selfm_hf, array_length(selfm_hf));
    proto_register_subtree_array(ett, array_length(ett));


    /* Register required preferences for SEL Protocol register decoding */
    selfm_module = prefs_register_protocol(proto_selfm, proto_reg_handoff_selfm);

    /*  SEL Protocol - Desegmentmentation; defaults to TRUE for TCP desegmentation*/
    prefs_register_bool_preference(selfm_module, "desegment",
                                  "Desegment all SEL Fast Message Protocol packets spanning multiple TCP segments",
                                  "Whether the SEL Protocol dissector should desegment all messages spanning multiple TCP segments",
                                  &selfm_desegment);

    /* SEL Protocol - Telnet protocol IAC (0xFF) processing; defaults to TRUE to allow Telnet Encapsulated Data */
    prefs_register_bool_preference(selfm_module, "telnetclean",
                                  "Enable Automatic pre-processing of Telnet-encapsulated data to remove extra 0xFF (IAC) bytes",
                                  "Whether the SEL Protocol dissector should automatically pre-process Telnet data to remove IAC bytes",
                                  &selfm_telnet_clean);

    /* SEL Protocol Preference - Default TCP Port, allows for "user" port either than 0. */
    prefs_register_uint_preference(selfm_module, "tcp.port", "SEL Protocol Port",
                       "Set the TCP port for SEL FM Protocol packets (if other"
                       " than the default of 0)",
                       10, &global_selfm_tcp_port);

}

/******************************************************************************************************/
/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
 */
/******************************************************************************************************/
void
proto_reg_handoff_selfm(void)
{
    static int selfm_prefs_initialized = FALSE;
    static dissector_handle_t selfm_handle;
    static unsigned int selfm_port;

    /* Make sure to use SEL FM Protocol Preferences field to determine default TCP port */
    if (! selfm_prefs_initialized) {
        selfm_handle = new_create_dissector_handle(dissect_selfm_tcp, proto_selfm);
        selfm_prefs_initialized = TRUE;
    }
    else {
        dissector_delete_uint("tcp.port", selfm_port, selfm_handle);
    }

    selfm_port = global_selfm_tcp_port;

    dissector_add_uint("tcp.port", selfm_port, selfm_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
