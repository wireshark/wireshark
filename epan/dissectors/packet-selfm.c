/* packet-selfm.c
 * Routines for Schweitzer Engineering Laboratories (SEL) Protocols Dissection
 * By Chris Bontje (cbontje[AT]gmail.com
 * Copyright 2012-2015,
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
 *
 ************************************************************************************************
 * Schweitzer Engineering Labs ("SEL") manufactures and sells digital protective relay equipment
 * for use in industrial high-voltage installations.  SEL Protocol evolved over time as a
 * (semi)proprietary method for auto-configuration of connected SEL devices for retrieval of
 * analog and digital status data.  The protocol itself supports embedded binary messages
 * (which are what this dissector looks for) slip-streamed in the data stream with normal
 * ASCII text data.  A combination of both are used for full auto-configuration of devices,
 * but a wealth of information can be extracted from the binary messages alone.
 *
 * 'SEL Protocol' encompasses several message types, including
 * - Fast Meter
 * - Fast Operate
 * - Fast SER
 * - Fast Message
 *
 * Documentation on Fast Meter and Fast Message standards available from www.selinc.com in
 * SEL Application Guides AG95-10_20091109.pdf and AG_200214.pdf
 ************************************************************************************************
 * Dissector Notes:
 *
 * 1) All SEL Protocol messages over TCP are normally tunneled via a Telnet connection.  As Telnet
 * has special handling for the 0xFF character ("IAC"), normally a pair of 0xFF's are inserted
 * to represent an actual payload byte of 0xFF.  A function from the packet-telnet.c dissector has
 * been borrowed to automatically pre-process any Ethernet-based packet and remove these 'extra'
 * 0xFF bytes.  Wireshark Notes on Telnet 0xFF doubling are discussed here:
 * http://www.wireshark.org/lists/wireshark-bugs/201204/msg00198.html
 *
 * 2) The auto-configuration process for Fast Meter will exchange several "configuration" messages
 * that describe various data regions (METER, DEMAND, PEAK, etc) that will later have corresponding
 * "data" messages.  This dissector code will currently save and accurately retrieve the 3 sets
 * of these exchanges:
 *             0xA5C1, 0xA5D1, "METER" region
 *             0xA5C2, 0xA5D2, "DEMAND" region
 *             0xA5C3, 0xA5D3, "PEAK" region
 * The configuration messages are stored in structs that are managed using the wmem library and
 * the Wireshark conversation functionality.
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-tcp.h"
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/crc16-tvb.h>
#include <epan/proto_data.h>

void proto_register_selfm(void);

/* Initialize the protocol and registered fields */
static int proto_selfm                        = -1;
static int hf_selfm_msgtype                   = -1;
static int hf_selfm_padbyte                   = -1;
static int hf_selfm_checksum                  = -1;
static int hf_selfm_relaydef_len              = -1;
static int hf_selfm_relaydef_numproto         = -1;
static int hf_selfm_relaydef_numfm            = -1;
static int hf_selfm_relaydef_numflags         = -1;
static int hf_selfm_relaydef_fmcfg_cmd        = -1;
static int hf_selfm_relaydef_fmdata_cmd       = -1;
static int hf_selfm_relaydef_statbit          = -1;
static int hf_selfm_relaydef_statbit_cmd      = -1;
static int hf_selfm_relaydef_proto            = -1;
static int hf_selfm_fmconfig_len              = -1;
static int hf_selfm_fmconfig_numflags         = -1;
static int hf_selfm_fmconfig_loc_sf           = -1;
static int hf_selfm_fmconfig_num_sf           = -1;
static int hf_selfm_fmconfig_num_ai           = -1;
static int hf_selfm_fmconfig_num_samp         = -1;
static int hf_selfm_fmconfig_num_dig          = -1;
static int hf_selfm_fmconfig_num_calc         = -1;
static int hf_selfm_fmconfig_ofs_ai           = -1;
static int hf_selfm_fmconfig_ofs_ts           = -1;
static int hf_selfm_fmconfig_ofs_dig          = -1;
static int hf_selfm_fmconfig_ai_type          = -1;
static int hf_selfm_fmconfig_ai_sf_type       = -1;
static int hf_selfm_fmconfig_ai_sf_ofs        = -1;
static int hf_selfm_fmconfig_cblk_rot         = -1;
static int hf_selfm_fmconfig_cblk_vconn       = -1;
static int hf_selfm_fmconfig_cblk_iconn       = -1;
static int hf_selfm_fmconfig_cblk_ctype       = -1;
static int hf_selfm_fmconfig_cblk_deskew_ofs  = -1;
static int hf_selfm_fmconfig_cblk_rs_ofs      = -1;
static int hf_selfm_fmconfig_cblk_xs_ofs      = -1;
static int hf_selfm_fmconfig_cblk_ia_idx      = -1;
static int hf_selfm_fmconfig_cblk_ib_idx      = -1;
static int hf_selfm_fmconfig_cblk_ic_idx      = -1;
static int hf_selfm_fmconfig_cblk_va_idx      = -1;
static int hf_selfm_fmconfig_cblk_vb_idx      = -1;
static int hf_selfm_fmconfig_cblk_vc_idx      = -1;
static int hf_selfm_fmconfig_ai_sf_float      = -1;
static int hf_selfm_fmdata_len                = -1;
static int hf_selfm_fmdata_flagbyte           = -1;
static int hf_selfm_fmdata_dig_b0             = -1;
static int hf_selfm_fmdata_dig_b1             = -1;
static int hf_selfm_fmdata_dig_b2             = -1;
static int hf_selfm_fmdata_dig_b3             = -1;
static int hf_selfm_fmdata_dig_b4             = -1;
static int hf_selfm_fmdata_dig_b5             = -1;
static int hf_selfm_fmdata_dig_b6             = -1;
static int hf_selfm_fmdata_dig_b7             = -1;
static int hf_selfm_fmdata_ai_sf_fp           = -1;
static int hf_selfm_foconfig_len              = -1;
static int hf_selfm_foconfig_num_brkr         = -1;
static int hf_selfm_foconfig_num_rb           = -1;
static int hf_selfm_foconfig_prb_supp         = -1;
static int hf_selfm_foconfig_reserved         = -1;
static int hf_selfm_foconfig_brkr_open        = -1;
static int hf_selfm_foconfig_brkr_close       = -1;
static int hf_selfm_foconfig_rb_cmd           = -1;
static int hf_selfm_fastop_len                = -1;
static int hf_selfm_fastop_rb_code            = -1;
static int hf_selfm_fastop_br_code            = -1;
static int hf_selfm_fastop_valid              = -1;
static int hf_selfm_alt_foconfig_len          = -1;
static int hf_selfm_alt_foconfig_num_ports    = -1;
static int hf_selfm_alt_foconfig_num_brkr     = -1;
static int hf_selfm_alt_foconfig_num_rb       = -1;
static int hf_selfm_alt_foconfig_funccode     = -1;
static int hf_selfm_alt_fastop_len            = -1;
static int hf_selfm_alt_fastop_code           = -1;
static int hf_selfm_alt_fastop_valid          = -1;

static int hf_selfm_fastmsg_len                    = -1;
static int hf_selfm_fastmsg_routing_addr           = -1;
static int hf_selfm_fastmsg_status                 = -1;
static int hf_selfm_fastmsg_funccode               = -1;
static int hf_selfm_fastmsg_seq                    = -1;
static int hf_selfm_fastmsg_seq_fir                = -1;
static int hf_selfm_fastmsg_seq_fin                = -1;
static int hf_selfm_fastmsg_seq_cnt                = -1;
static int hf_selfm_fastmsg_resp_num               = -1;
static int hf_selfm_fastmsg_crc16                  = -1;
static int hf_selfm_fastmsg_def_route_sup          = -1;
static int hf_selfm_fastmsg_def_rx_stat            = -1;
static int hf_selfm_fastmsg_def_tx_stat            = -1;
static int hf_selfm_fastmsg_def_rx_maxfr           = -1;
static int hf_selfm_fastmsg_def_tx_maxfr           = -1;
static int hf_selfm_fastmsg_def_rx_num_fc          = -1;
static int hf_selfm_fastmsg_def_rx_fc              = -1;
static int hf_selfm_fastmsg_def_tx_num_fc          = -1;
static int hf_selfm_fastmsg_def_tx_fc              = -1;
static int hf_selfm_fastmsg_uns_en_fc              = -1;
static int hf_selfm_fastmsg_uns_en_fc_data         = -1;
static int hf_selfm_fastmsg_uns_dis_fc             = -1;
static int hf_selfm_fastmsg_uns_dis_fc_data        = -1;
static int hf_selfm_fastmsg_baseaddr               = -1;
static int hf_selfm_fastmsg_numwords               = -1;
static int hf_selfm_fastmsg_flags                  = -1;
static int hf_selfm_fastmsg_datafmt_resp_numitem   = -1;
static int hf_selfm_fastmsg_dataitem_qty           = -1;
static int hf_selfm_fastmsg_dataitem_type          = -1;
static int hf_selfm_fastmsg_dataitem_uint16        = -1;
static int hf_selfm_fastmsg_dataitem_int16         = -1;
static int hf_selfm_fastmsg_dataitem_uint32        = -1;
static int hf_selfm_fastmsg_dataitem_int32         = -1;
static int hf_selfm_fastmsg_dataitem_float         = -1;
static int hf_selfm_fastmsg_devdesc_num_region     = -1;
static int hf_selfm_fastmsg_devdesc_num_ctrl       = -1;
static int hf_selfm_fastmsg_unsresp_orig           = -1;
static int hf_selfm_fastmsg_unsresp_doy            = -1;
static int hf_selfm_fastmsg_unsresp_year           = -1;
static int hf_selfm_fastmsg_unsresp_todms          = -1;
static int hf_selfm_fastmsg_unsresp_num_elmt       = -1;
static int hf_selfm_fastmsg_unsresp_elmt_idx       = -1;
static int hf_selfm_fastmsg_unsresp_elmt_ts_ofs    = -1;
static int hf_selfm_fastmsg_unsresp_elmt_status    = -1;
static int hf_selfm_fastmsg_unsresp_eor            = -1;
static int hf_selfm_fastmsg_unsresp_elmt_statword  = -1;
static int hf_selfm_fastmsg_unswrite_addr1         = -1;
static int hf_selfm_fastmsg_unswrite_addr2         = -1;
static int hf_selfm_fastmsg_unswrite_num_reg       = -1;
static int hf_selfm_fastmsg_unswrite_reg_val       = -1;
static int hf_selfm_fastmsg_soe_req_orig           = -1;
static int hf_selfm_fastmsg_soe_resp_numblks       = -1;
static int hf_selfm_fastmsg_soe_resp_orig          = -1;
static int hf_selfm_fastmsg_soe_resp_numbits       = -1;
static int hf_selfm_fastmsg_soe_resp_pad           = -1;
static int hf_selfm_fastmsg_soe_resp_doy           = -1;
static int hf_selfm_fastmsg_soe_resp_year          = -1;
static int hf_selfm_fastmsg_soe_resp_tod           = -1;
/* static int hf_selfm_fastmsg_soe_resp_data          = -1; */
/* Generated from convert_proto_tree_add_text.pl */
static int hf_selfm_fmconfig_ai_channel = -1;
static int hf_selfm_fmdata_ai_value16 = -1;
static int hf_selfm_fmdata_ai_scale_factor = -1;
static int hf_selfm_fmdata_ai_value_float = -1;
static int hf_selfm_fmdata_ai_value_double = -1;
static int hf_selfm_fmdata_data_type = -1;
static int hf_selfm_fmdata_quantity = -1;
static int hf_selfm_fmdata_ai_value_string = -1;
static int hf_selfm_fastmsg_unsresp_elmt_ts_ofs_decoded = -1;
static int hf_selfm_fid = -1;
static int hf_selfm_rid = -1;
static int hf_selfm_fastmsg_data_region_name = -1;
static int hf_selfm_fmdata_timestamp = -1;
static int hf_selfm_fmdata_frame_data_format_reference = -1;
static int hf_selfm_fastmsg_bit_label_name = -1;

/* Initialize the subtree pointers */
static gint ett_selfm                       = -1;
static gint ett_selfm_relaydef              = -1;
static gint ett_selfm_relaydef_fm           = -1;
static gint ett_selfm_relaydef_proto        = -1;
static gint ett_selfm_relaydef_flags        = -1;
static gint ett_selfm_fmconfig              = -1;
static gint ett_selfm_fmconfig_ai           = -1;
static gint ett_selfm_fmconfig_calc         = -1;
static gint ett_selfm_foconfig              = -1;
static gint ett_selfm_foconfig_brkr         = -1;
static gint ett_selfm_foconfig_rb           = -1;
static gint ett_selfm_fastop                = -1;
static gint ett_selfm_fmdata                = -1;
static gint ett_selfm_fmdata_ai             = -1;
static gint ett_selfm_fmdata_dig            = -1;
static gint ett_selfm_fmdata_ai_ch          = -1;
static gint ett_selfm_fmdata_dig_ch         = -1;
static gint ett_selfm_fastmsg               = -1;
static gint ett_selfm_fastmsg_seq           = -1;
static gint ett_selfm_fastmsg_def_fc        = -1;
static gint ett_selfm_fastmsg_datareg       = -1;
static gint ett_selfm_fastmsg_tag           = -1;
static gint ett_selfm_fastmsg_element_list  = -1;
static gint ett_selfm_fastmsg_element       = -1;

/* Expert fields */
static expert_field ei_selfm_crc16_incorrect = EI_INIT;

static dissector_handle_t selfm_handle;

#define PORT_SELFM    0

#define CMD_FAST_MSG            0xA546
#define CMD_CLEAR_STATBIT       0xA5B9
#define CMD_RELAY_DEF           0xA5C0
#define CMD_FM_CONFIG           0xA5C1
#define CMD_DFM_CONFIG          0xA5C2
#define CMD_PDFM_CONFIG         0xA5C3
#define CMD_FASTOP_RESETDEF     0xA5CD
#define CMD_FASTOP_CONFIG       0xA5CE
#define CMD_ALT_FASTOP_CONFIG   0xA5CF
#define CMD_FM_DATA             0xA5D1
#define CMD_DFM_DATA            0xA5D2
#define CMD_PDFM_DATA           0xA5D3
#define CMD_FASTOP_RB_CTRL      0xA5E0
#define CMD_FASTOP_BR_CTRL      0xA5E3
#define CMD_ALT_FASTOP_OPEN     0xA5E5
#define CMD_ALT_FASTOP_CLOSE    0xA5E6
#define CMD_ALT_FASTOP_SET      0xA5E7
#define CMD_ALT_FASTOP_CLEAR    0xA5E8
#define CMD_ALT_FASTOP_PULSE    0xA5E9
#define CMD_FASTOP_RESET        0xA5ED

#define FM_CONFIG_SF_LOC_FM             0
#define FM_CONFIG_SF_LOC_CFG            1

#define FM_CONFIG_ANA_CHNAME_LEN        6
#define FM_CONFIG_ANA_CHTYPE_INT16      0x00
#define FM_CONFIG_ANA_CHTYPE_FP         0x01
#define FM_CONFIG_ANA_CHTYPE_FPD        0x02
#define FM_CONFIG_ANA_CHTYPE_TS         0x03
#define FM_CONFIG_ANA_CHTYPE_TS_LEN     8

#define FM_CONFIG_ANA_SFTYPE_INT16      0x00
#define FM_CONFIG_ANA_SFTYPE_FP         0x01
#define FM_CONFIG_ANA_SFTYPE_FPD        0x02
#define FM_CONFIG_ANA_SFTYPE_TS         0x03
#define FM_CONFIG_ANA_SFTYPE_NONE       0xFF


/* Fast Message Function Codes, "response" or "ACK" messages are the same as the request, but have the MSB set */
#define FAST_MSG_CFG_BLOCK              0x00
#define FAST_MSG_EN_UNS_DATA            0x01
#define FAST_MSG_DIS_UNS_DATA           0x02
#define FAST_MSG_PING                   0x05
#define FAST_MSG_READ_REQ               0x10
#define FAST_MSG_GEN_UNS_DATA           0x12
#define FAST_MSG_SOE_STATE_REQ          0x16
#define FAST_MSG_UNS_RESP               0x18
#define FAST_MSG_UNS_WRITE              0x20
#define FAST_MSG_UNS_WRITE_REQ          0x21
#define FAST_MSG_DEVDESC_REQ            0x30
#define FAST_MSG_DATAFMT_REQ            0x31
#define FAST_MSG_UNS_DATAFMT_RESP       0x32
#define FAST_MSG_BITLABEL_REQ           0x33
#define FAST_MSG_MGMT_REQ               0x40
#define FAST_MSG_CFG_BLOCK_RESP         0x80
#define FAST_MSG_EN_UNS_DATA_ACK        0x81
#define FAST_MSG_DIS_UNS_DATA_ACK       0x82
#define FAST_MSG_PING_ACK               0x85
#define FAST_MSG_READ_RESP              0x90
#define FAST_MSG_SOE_STATE_RESP         0x96
#define FAST_MSG_UNS_RESP_ACK           0x98
#define FAST_MSG_DEVDESC_RESP           0xB0
#define FAST_MSG_DATAFMT_RESP           0xB1
#define FAST_MSG_BITLABEL_RESP          0xB3


/* Fast Message Sequence Byte Masks */
#define FAST_MSG_SEQ_FIR     0x80
#define FAST_MSG_SEQ_FIN     0x40
#define FAST_MSG_SEQ_CNT     0x3f

/* Fast Message Tag Data Types */
#define FAST_MSG_TAGTYPE_CHAR8        0x0011   /* 1 x 8-bit character per item */
#define FAST_MSG_TAGTYPE_CHAR16       0x0012   /* 2 x 8-bit characters per item */
#define FAST_MSG_TAGTYPE_DIGWORD8_BL  0x0021   /* 8-bit binary item, with labels */
#define FAST_MSG_TAGTYPE_DIGWORD8     0x0022   /* 8-bit binary item, without labels */
#define FAST_MSG_TAGTYPE_DIGWORD16_BL 0x0023   /* 16-bit binary item, with labels */
#define FAST_MSG_TAGTYPE_DIGWORD16    0x0024   /* 16-bit binary item, without labels */
#define FAST_MSG_TAGTYPE_INT16        0x0031   /* 16-bit signed integer */
#define FAST_MSG_TAGTYPE_UINT16       0x0032   /* 16-bit unsigned integer */
#define FAST_MSG_TAGTYPE_INT32        0x0033   /* 32-bit signed integer */
#define FAST_MSG_TAGTYPE_UINT32       0x0034   /* 32-bit unsigned integer */
#define FAST_MSG_TAGTYPE_FLOAT        0x0041   /* 32-bit floating point */


/* Globals for SEL Protocol Preferences */
static gboolean selfm_desegment = TRUE;
static gboolean selfm_telnet_clean = TRUE;
static guint global_selfm_tcp_port = PORT_SELFM; /* Port 0, by default */
static gboolean selfm_crc16 = FALSE;             /* Default CRC16 valdiation to false */
static const char *selfm_ser_list = NULL;

/***************************************************************************************/
/* Fast Meter Message structs */
/***************************************************************************************/
/* Holds Configuration Information required to decode a Fast Meter analog value        */
typedef struct {
    gchar   name[FM_CONFIG_ANA_CHNAME_LEN+1];     /* Name of Analog Channel, 6 char + a null */
    guint8  type;                                 /* Analog Channel Type, Int, FP, etc */
    guint8  sf_type;                              /* Analog Scale Factor Type, none, etc */
    guint16 sf_offset;                            /* Analog Scale Factor Offset */
    gfloat  sf_fp;                                /* Scale factor, if present in Cfg message */
} fm_analog_info;


/* Holds Information from a single "Fast Meter Configuration" frame.  Required to dissect subsequent "Data" frames. */
typedef struct {
    guint32  fnum;                   /* frame number */
    guint16  cfg_cmd;                /* holds ID of config command, ie: 0xa5c1 */
    guint8   num_flags;              /* Number of Flag Bytes           */
    guint8   sf_loc;                 /* Scale Factor Location          */
    guint8   sf_num;                 /* Number of Scale Factors        */
    guint8   num_ai;                 /* Number of Analog Inputs        */
    guint8   num_ai_samples;         /* Number samples per Analog Input */
    guint16  offset_ai;              /* Start Offset of Analog Inputs  */
    guint8   num_dig;                /* Number of Digital Input Blocks */
    guint16  offset_dig;             /* Start Offset of Digital Inputs */
    guint16  offset_ts;              /* Start Offset of Time Stamp     */
    guint8   num_calc;               /* Number of Calculations         */
    fm_analog_info *analogs;         /* Array of fm_analog_infos       */
} fm_config_frame;

/**************************************************************************************/
/* Fast Message Data Item struct */
/**************************************************************************************/
/* Holds Configuration Information required to decode a Fast Message Data Item        */
/* Each data region format is returned as a sequential list of tags, w/o reference to */
/* an absolute address.  The format information will consist of a name, a data type   */
/* and a quantity of values contained within the data item.  We will retrieve this    */
/* format information later while attempting to dissect Read Response frames          */
typedef struct {
    guint32  fnum;                              /* frame number */
    guint32  base_address;                      /* Base address of Data Item Region                         */
    guint8   index_pos;                         /* Index Offset Position within data format message (1-16)  */
    gchar    name[10+1];                        /* Name of Data Item, 10 chars, null-terminated             */
    guint16  quantity;                          /* Quantity of values within Data Item                      */
    guint16  data_type;                         /* Data Item Type, Char, Int, FP, etc                       */
} fastmsg_dataitem;

/**************************************************************************************/
/* Fast Message Data Region struct */
/**************************************************************************************/
/* Holds Configuration Information required to decode a Fast Message Data Region      */
/* Each data region format is returned as a sequential list of tags, w/o reference to */
typedef struct {
    gchar    name[10+1];                        /* Name of Data Region, 10 chars, null-terminated              */
} fastmsg_dataregion;

/**************************************************************************************/
/* Fast Unsolicited SER Index Lookup */
/**************************************************************************************/
/* Holds user-configurable naming information for Unsolicited Fast SER word bits      */
/* that will later be present in an 0xA546 msg with only an index position reference  */
typedef struct {
    gchar    *name;                     /* Name of Word Bit, 8 chars, null-terminated */
} fastser_uns_wordbit;


/**************************************************************************************/
/* Fast Message Conversation struct */
/**************************************************************************************/
typedef struct {
    wmem_list_t *fm_config_frames;      /* List contains a fm_config_data struct for each Fast Meter configuration frame */
    wmem_list_t *fastmsg_dataitems;     /* List contains a fastmsg_dataitem struct for each Fast Message Data Item */
    wmem_tree_t *fastmsg_dataregions;   /* Tree contains a fastmsg_dataregion struct for each Fast Message Data Region */
    wmem_tree_t *fastser_uns_wordbits;  /* Tree contains a fastser_uns_wordbit struct for each comma-separated entry in the 'SER List' User Preference */
} fm_conversation;


static const value_string selfm_msgtype_vals[] = {
    { CMD_FAST_MSG,              "Fast Message Block"                              },  /* 0xA546 */
    { CMD_CLEAR_STATBIT,         "Clear Status Bits Command"                       },  /* 0xA5B9 */
    { CMD_RELAY_DEF,             "Relay Definition Block"                          },  /* 0xA5C0 */
    { CMD_FM_CONFIG,             "Fast Meter Configuration Block"                  },  /* 0xA5C1 */
    { CMD_DFM_CONFIG,            "Demand Fast Meter Configuration Block"           },  /* 0xA5C2 */
    { CMD_PDFM_CONFIG,           "Peak Demand Fast Meter Configuration Block"      },  /* 0xA5C3 */
    { CMD_FASTOP_RESETDEF,       "Fast Operate Reset Definition"                   },  /* 0xA5CD */
    { CMD_FASTOP_CONFIG,         "Fast Operate Configuration"                      },  /* 0xA5CE */
    { CMD_ALT_FASTOP_CONFIG,     "Alternate Fast Operate Configuration"            },  /* 0xA5CF */
    { CMD_FM_DATA,               "Fast Meter Data Block"                           },  /* 0xA5D1 */
    { CMD_DFM_DATA,              "Demand Fast Meter Data Block"                    },  /* 0xA5D2 */
    { CMD_PDFM_DATA,             "Peak Demand Fast Meter Data Block"               },  /* 0xA5D3 */
    { CMD_FASTOP_RB_CTRL,        "Fast Operate Remote Bit Control"                 },  /* 0xA5E0 */
    { CMD_FASTOP_BR_CTRL,        "Fast Operate Breaker Bit Control"                },  /* 0xA5E3 */
    { CMD_ALT_FASTOP_OPEN,       "Alternate Fast Operate Open Breaker Control"     },  /* 0xA5E5 */
    { CMD_ALT_FASTOP_CLOSE,      "Alternate Fast Operate Close Breaker Control"    },  /* 0xA5E6 */
    { CMD_ALT_FASTOP_SET,        "Alternate Fast Operate Set Remote Bit Control"   },  /* 0xA5E7 */
    { CMD_ALT_FASTOP_CLEAR,      "Alternate Fast Operate Clear Remote Bit Control" },  /* 0xA5E8 */
    { CMD_ALT_FASTOP_PULSE,      "Alternate Fast Operate Pulse Remote Bit Control" },  /* 0xA5E9 */
    { CMD_FASTOP_RESET,          "Fast Operate Reset"                              },  /* 0xA5ED */
    { 0,                         NULL }
};
static value_string_ext selfm_msgtype_vals_ext = VALUE_STRING_EXT_INIT(selfm_msgtype_vals);

static const value_string selfm_relaydef_proto_vals[] = {
    { 0x0000,  "SEL Fast Meter" },
    { 0x0001,  "SEL Limited Multidrop (LMD)" },
    { 0x0002,  "Modbus" },
    { 0x0003,  "SY/MAX" },
    { 0x0004,  "SEL Relay-to-Relay" },
    { 0x0005,  "DNP 3.0" },
    { 0x0006,  "SEL Mirrored Bits" },
    { 0x0007,  "IEEE 37.118 Synchrophasors" },
    { 0x0008,  "IEC 61850" },
    { 0x0100,  "SEL Fast Meter w/ Fast Operate" },
    { 0x0101,  "SEL Limited Multidrop (LMD) w/ Fast Operate" },
    { 0x0200,  "SEL Fast Meter w/ Fast Message" },
    { 0x0300,  "SEL Fast Meter w/ Fast Operate and Fast Message" },
    { 0x0301,  "SEL Limited Multidrop (LMD) w/ Fast Operate and Fast Message" },
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

/* Calculation Block lookup values */
static const value_string selfm_fmconfig_cblk_rot_vals[] = {
    { 0x00,      "ABC Rotation" },
    { 0x01,      "ACB Rotation" },
    { 0,         NULL           }
};

static const value_string selfm_fmconfig_cblk_vconn_vals[] = {
    { 0x00,      "Y-Connected" },
    { 0x01,      "Delta-Connected (in seq. Vab, Vbc, Vca)" },
    { 0x02,      "Delta-Connected (in seq. Vac, Vba, Vcb)" },
    { 0,         NULL           }
};

static const value_string selfm_fmconfig_cblk_iconn_vals[] = {
    { 0x00,      "Y-Connected" },
    { 0x01,      "Delta-Connected (in seq. Iab, Ibc, Ica)" },
    { 0x02,      "Delta-Connected (in seq. Iac, Iba, Icb)" },
    { 0,         NULL           }
};

static const value_string selfm_fmconfig_cblk_ctype_vals[] = {
    { 0,      "Standard Power Calculations" },
    { 1,      "2-1/2 Element Delta Power Calculation" },
    { 2,      "Voltages-Only" },
    { 3,      "Currents-Only" },
    { 4,      "Single-Phase Ia and Va Only" },
    { 5,      "Standard Power Calcs with 2 sets of Currents" },
    { 6,      "2-1/2 Element Delta Power Calcs with 2 sets of Currents" },
    { 0,         NULL           }
};

/* Fast Operate Remote Bit 'Pulse Supported' Lookup */
static const value_string selfm_foconfig_prb_supp_vals[] = {
    { 0x00,  "No" },
    { 0x01,  "Yes" },
    { 0,                      NULL }
};

/* SER Status Value Lookup */
static const value_string selfm_ser_status_vals[] = {
    { 0x00,  "Deasserted" },
    { 0x01,  "Asserted" },
    { 0,  NULL }
};

/* Fast Operate Remote Bit Lookup */
static const value_string selfm_fo_rb_vals[] = {
    { 0x00,  "RB01 Clear" },
    { 0x01,  "RB02 Clear" },
    { 0x02,  "RB03 Clear" },
    { 0x03,  "RB04 Clear" },
    { 0x04,  "RB05 Clear" },
    { 0x05,  "RB06 Clear" },
    { 0x06,  "RB07 Clear" },
    { 0x07,  "RB08 Clear" },
    { 0x08,  "RB09 Clear" },
    { 0x09,  "RB10 Clear" },
    { 0x0A,  "RB11 Clear" },
    { 0x0B,  "RB12 Clear" },
    { 0x0C,  "RB13 Clear" },
    { 0x0D,  "RB14 Clear" },
    { 0x0E,  "RB15 Clear" },
    { 0x0F,  "RB16 Clear" },
    { 0x10,  "RB17 Clear" },
    { 0x11,  "RB18 Clear" },
    { 0x12,  "RB19 Clear" },
    { 0x13,  "RB20 Clear" },
    { 0x14,  "RB21 Clear" },
    { 0x15,  "RB22 Clear" },
    { 0x16,  "RB23 Clear" },
    { 0x17,  "RB24 Clear" },
    { 0x18,  "RB25 Clear" },
    { 0x19,  "RB26 Clear" },
    { 0x1A,  "RB27 Clear" },
    { 0x1B,  "RB28 Clear" },
    { 0x1C,  "RB29 Clear" },
    { 0x1D,  "RB30 Clear" },
    { 0x1E,  "RB31 Clear" },
    { 0x1F,  "RB32 Clear" },
    { 0x20,  "RB01 Set" },
    { 0x21,  "RB02 Set" },
    { 0x22,  "RB03 Set" },
    { 0x23,  "RB04 Set" },
    { 0x24,  "RB05 Set" },
    { 0x25,  "RB06 Set" },
    { 0x26,  "RB07 Set" },
    { 0x27,  "RB08 Set" },
    { 0x28,  "RB09 Set" },
    { 0x29,  "RB10 Set" },
    { 0x2A,  "RB11 Set" },
    { 0x2B,  "RB12 Set" },
    { 0x2C,  "RB13 Set" },
    { 0x2D,  "RB14 Set" },
    { 0x2E,  "RB15 Set" },
    { 0x2F,  "RB16 Set" },
    { 0x30,  "RB17 Set" },
    { 0x31,  "RB18 Set" },
    { 0x32,  "RB19 Set" },
    { 0x33,  "RB20 Set" },
    { 0x34,  "RB21 Set" },
    { 0x35,  "RB22 Set" },
    { 0x36,  "RB23 Set" },
    { 0x37,  "RB24 Set" },
    { 0x38,  "RB25 Set" },
    { 0x39,  "RB26 Set" },
    { 0x3A,  "RB27 Set" },
    { 0x3B,  "RB28 Set" },
    { 0x3C,  "RB29 Set" },
    { 0x3D,  "RB30 Set" },
    { 0x3E,  "RB31 Set" },
    { 0x3F,  "RB32 Set" },
    { 0x40,  "RB01 Pulse" },
    { 0x41,  "RB02 Pulse" },
    { 0x42,  "RB03 Pulse" },
    { 0x43,  "RB04 Pulse" },
    { 0x44,  "RB05 Pulse" },
    { 0x45,  "RB06 Pulse" },
    { 0x46,  "RB07 Pulse" },
    { 0x47,  "RB08 Pulse" },
    { 0x48,  "RB09 Pulse" },
    { 0x49,  "RB10 Pulse" },
    { 0x4A,  "RB11 Pulse" },
    { 0x4B,  "RB12 Pulse" },
    { 0x4C,  "RB13 Pulse" },
    { 0x4D,  "RB14 Pulse" },
    { 0x4E,  "RB15 Pulse" },
    { 0x4F,  "RB16 Pulse" },
    { 0x50,  "RB17 Pulse" },
    { 0x51,  "RB18 Pulse" },
    { 0x52,  "RB19 Pulse" },
    { 0x53,  "RB20 Pulse" },
    { 0x54,  "RB21 Pulse" },
    { 0x55,  "RB22 Pulse" },
    { 0x56,  "RB23 Pulse" },
    { 0x57,  "RB24 Pulse" },
    { 0x58,  "RB25 Pulse" },
    { 0x59,  "RB26 Pulse" },
    { 0x5A,  "RB27 Pulse" },
    { 0x5B,  "RB28 Pulse" },
    { 0x5C,  "RB29 Pulse" },
    { 0x5D,  "RB30 Pulse" },
    { 0x5E,  "RB31 Pulse" },
    { 0x5F,  "RB32 Pulse" },
    { 0,             NULL }
};
static value_string_ext selfm_fo_rb_vals_ext = VALUE_STRING_EXT_INIT(selfm_fo_rb_vals);

/* Fast Operate Breaker Bit Lookup */
static const value_string selfm_fo_br_vals[] = {
    { 0x11, "Breaker Bit 1 Close (CC/CC1)" },
    { 0x12, "Breaker Bit 2 Close (CC2)" },
    { 0x13, "Breaker Bit 3 Close (CC3)" },
    { 0x14, "Breaker Bit 4 Close (CC4)" },
    { 0x15, "Breaker Bit 5 Close (CC5)" },
    { 0x16, "Breaker Bit 6 Close (CC6)" },
    { 0x17, "Breaker Bit 7 Close (CC7)" },
    { 0x18, "Breaker Bit 8 Close (CC8)" },
    { 0x19, "Breaker Bit 9 Close (CC9)" },
    { 0x1A, "Breaker Bit 10 Close (CC10)" },
    { 0x1B, "Breaker Bit 11 Close (CC11)" },
    { 0x1C, "Breaker Bit 12 Close (CC12)" },
    { 0x1D, "Breaker Bit 13 Close (CC13)" },
    { 0x1E, "Breaker Bit 14 Close (CC14)" },
    { 0x1F, "Breaker Bit 15 Close (CC15)" },
    { 0x20, "Breaker Bit 16 Close (CC16)" },
    { 0x21, "Breaker Bit 17 Close (CC17)" },
    { 0x22, "Breaker Bit 18 Close (CC18)" },
    { 0x31, "Breaker Bit 1 Open (OC/OC1)" },
    { 0x32, "Breaker Bit 2 Open (OC2)" },
    { 0x33, "Breaker Bit 3 Open (OC3)" },
    { 0x34, "Breaker Bit 4 Open (OC4)" },
    { 0x35, "Breaker Bit 5 Open (OC5)" },
    { 0x36, "Breaker Bit 6 Open (OC6)" },
    { 0x37, "Breaker Bit 7 Open (OC7)" },
    { 0x38, "Breaker Bit 8 Open (OC8)" },
    { 0x39, "Breaker Bit 9 Open (OC9)" },
    { 0x3A, "Breaker Bit 10 Open (OC10)" },
    { 0x3B, "Breaker Bit 11 Open (OC11)" },
    { 0x3C, "Breaker Bit 12 Open (OC12)" },
    { 0x3D, "Breaker Bit 13 Open (OC13)" },
    { 0x3E, "Breaker Bit 14 Open (OC14)" },
    { 0x3F, "Breaker Bit 15 Open (OC15)" },
    { 0x40, "Breaker Bit 16 Open (OC16)" },
    { 0x41, "Breaker Bit 17 Open (OC17)" },
    { 0x42, "Breaker Bit 18 Open (OC18)" },
    { 0,                           NULL }
};
static value_string_ext selfm_fo_br_vals_ext = VALUE_STRING_EXT_INIT(selfm_fo_br_vals);

/* Alternate Fast Operate Function Code Lookup */
static const value_string selfm_foconfig_alt_funccode_vals[] = {
    { 0xE5, "Open Breaker Bit"  },
    { 0xE6, "Close Breaker Bit" },
    { 0xE7, "Set Remote Bit"    },
    { 0xE8, "Clear Remote Bit"  },
    { 0xE9, "Pulse Remote Bit"  },
    { 0x00, "Unsupported"       },
    { 0,                   NULL }
};

/* Fast Message Function Codes */
static const value_string selfm_fastmsg_func_code_vals[] = {
    { FAST_MSG_CFG_BLOCK,         "Fast Message Configuration Block Request" },
    { FAST_MSG_EN_UNS_DATA,       "Enable Unsolicited Data" },
    { FAST_MSG_DIS_UNS_DATA,      "Disable Unsolicited Data" },
    { FAST_MSG_PING,              "Ping Message" },
    { FAST_MSG_READ_REQ,          "Read Request" },
    { FAST_MSG_GEN_UNS_DATA,      "Generic Unsolicited Data" },
    { FAST_MSG_SOE_STATE_REQ,     "SOE Present State Request" },
    { FAST_MSG_UNS_RESP,          "Unsolicited Fast SER Data Response" },
    { FAST_MSG_UNS_WRITE,         "Unsolicited Write" },
    { FAST_MSG_UNS_WRITE_REQ,     "Unsolicited Write Request" },
    { FAST_MSG_DEVDESC_REQ,       "Device Description Request" },
    { FAST_MSG_DATAFMT_REQ,       "Data Format Request" },
    { FAST_MSG_UNS_DATAFMT_RESP,  "Unsolicited Data Format Response" },
    { FAST_MSG_BITLABEL_REQ,      "Bit Label Request" },
    { FAST_MSG_MGMT_REQ,          "Management Request" },
    { FAST_MSG_CFG_BLOCK_RESP,    "Fast Message Configuration Block Response" },
    { FAST_MSG_EN_UNS_DATA_ACK,   "Enable Unsolicited Data ACK" },
    { FAST_MSG_DIS_UNS_DATA_ACK,  "Disable Unsolicited Data ACK" },
    { FAST_MSG_PING_ACK,          "Ping Message ACK" },
    { FAST_MSG_READ_RESP,         "Read Response" },
    { FAST_MSG_SOE_STATE_RESP,    "SOE Present State Response" },
    { FAST_MSG_UNS_RESP_ACK,      "Unsolicited Fast SER Data Response ACK" },
    { FAST_MSG_DEVDESC_RESP,      "Device Description Response" },
    { FAST_MSG_DATAFMT_RESP,      "Data Format Response" },
    { FAST_MSG_BITLABEL_RESP,     "Bit Label Response" },
    { 0,                           NULL }
};
static value_string_ext selfm_fastmsg_func_code_vals_ext =
    VALUE_STRING_EXT_INIT(selfm_fastmsg_func_code_vals);

static const value_string selfm_fastmsg_tagtype_vals[] = {
    { FAST_MSG_TAGTYPE_CHAR8,        "1 x 8-bit character per item" },
    { FAST_MSG_TAGTYPE_CHAR16,       "2 x 8-bit characters per item" },
    { FAST_MSG_TAGTYPE_DIGWORD8_BL,  "8-bit binary item, with labels" },
    { FAST_MSG_TAGTYPE_DIGWORD8,     "8-bit binary item, without labels" },
    { FAST_MSG_TAGTYPE_DIGWORD16_BL, "16-bit binary item, with labels" },
    { FAST_MSG_TAGTYPE_DIGWORD16,    "16-bit binary item, without labels" },
    { FAST_MSG_TAGTYPE_INT16,        "16-bit Signed Integer" },
    { FAST_MSG_TAGTYPE_UINT16,       "16-bit Unsigned Integer" },
    { FAST_MSG_TAGTYPE_INT32,        "32-bit Signed Integer" },
    { FAST_MSG_TAGTYPE_UINT32,       "32-bit Unsigned Integer" },
    { FAST_MSG_TAGTYPE_FLOAT,        "IEEE Floating Point" },
    { 0,  NULL }
};


/* Fast Message Unsolicited Write COM Port Codes */
static const value_string selfm_fastmsg_unswrite_com_vals[] = {
    { 0x0100,   "COM01" },
    { 0x0200,   "COM02" },
    { 0x0300,   "COM03" },
    { 0x0400,   "COM04" },
    { 0x0500,   "COM05" },
    { 0x0600,   "COM06" },
    { 0x0700,   "COM07" },
    { 0x0800,   "COM08" },
    { 0x0900,   "COM09" },
    { 0x0A00,   "COM10" },
    { 0x0B00,   "COM11" },
    { 0x0C00,   "COM12" },
    { 0x0D00,   "COM13" },
    { 0x0E00,   "COM14" },
    { 0x0F00,   "COM15" },
    { 0,  NULL }
};
static value_string_ext selfm_fastmsg_unswrite_com_vals_ext =
    VALUE_STRING_EXT_INIT(selfm_fastmsg_unswrite_com_vals);

/* Tables for reassembly of fragments. */
static reassembly_table selfm_reassembly_table;

/* ************************************************************************* */
/*                   Header values for reassembly                            */
/* ************************************************************************* */
static int   hf_selfm_fragment  = -1;
static int   hf_selfm_fragments = -1;
static int   hf_selfm_fragment_overlap = -1;
static int   hf_selfm_fragment_overlap_conflict = -1;
static int   hf_selfm_fragment_multiple_tails = -1;
static int   hf_selfm_fragment_too_long_fragment = -1;
static int   hf_selfm_fragment_error = -1;
static int   hf_selfm_fragment_count = -1;
static int   hf_selfm_fragment_reassembled_in = -1;
static int   hf_selfm_fragment_reassembled_length = -1;
static gint ett_selfm_fragment  = -1;
static gint ett_selfm_fragments = -1;

static const fragment_items selfm_frag_items = {
    &ett_selfm_fragment,
    &ett_selfm_fragments,
    &hf_selfm_fragments,
    &hf_selfm_fragment,
    &hf_selfm_fragment_overlap,
    &hf_selfm_fragment_overlap_conflict,
    &hf_selfm_fragment_multiple_tails,
    &hf_selfm_fragment_too_long_fragment,
    &hf_selfm_fragment_error,
    &hf_selfm_fragment_count,
    &hf_selfm_fragment_reassembled_in,
    &hf_selfm_fragment_reassembled_length,
    /* Reassembled data field */
    NULL,
    "SEL Fast Message fragments"
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
    int           skip_byte, len_remaining;

    spos=tvb_get_ptr(tvb, offset, len);
    buf=(guint8 *)wmem_alloc(pinfo->pool, len);
    dpos=buf;
    skip_byte = 0;
    len_remaining = len;
    while(len_remaining > 0){

        /* Only analyze two sequential bytes of source tvb if we have at least two bytes left */
        if (len_remaining > 1) {
            /* If two sequential 0xFF's exist, increment skip_byte counter, decrement  */
            /* len_remaining by 2 and copy a single 0xFF to dest tvb. */
            if((spos[0]==0xff) && (spos[1]==0xff)){
                skip_byte++;
                len_remaining -= 2;
                *(dpos++)=0xff;
                spos+=2;
                continue;
            }
        }
        /* If we only have a single byte left, or there were no sequential 0xFF's, copy byte from src tvb to dest tvb */
        *(dpos++)=*(spos++);
        len_remaining--;
    }
    telnet_tvb = tvb_new_child_real_data(tvb, buf, len-skip_byte, len-skip_byte);
    add_new_data_source(pinfo, telnet_tvb, "Processed Telnet Data");

    return telnet_tvb;
}

/******************************************************************************************************/
/* Execute dissection of Fast Meter configuration frames independent of any GUI access of said frames */
/* Load configuration information into fm_config_frame struct */
/******************************************************************************************************/
static fm_config_frame* fmconfig_frame_fast(tvbuff_t *tvb)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    guint           count, offset = 0;
    fm_config_frame *frame;

    /* get a new frame and initialize it */
    frame = wmem_new(wmem_file_scope(), fm_config_frame);

    /* Get data packet setup information from config message and copy into ai_info (if required) */
    frame->cfg_cmd        = tvb_get_ntohs(tvb, offset);
    /* skip length byte, position offset+2 */
    frame->num_flags      = tvb_get_guint8(tvb, offset+3);
    frame->sf_loc         = tvb_get_guint8(tvb, offset+4);
    frame->sf_num         = tvb_get_guint8(tvb, offset+5);
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

        /* If Scale Factors are present in the cfg message, retrieve and store them per analog */
        /* Otherwise, default to Scale Factor of 1 for now */
        if (frame->sf_loc == FM_CONFIG_SF_LOC_CFG) {
            analog->sf_fp = tvb_get_ntohieee_float(tvb, analog->sf_offset);
        }
        else {
            analog->sf_fp = 1;
        }

        offset += 10;
    }

    return frame;

}

/******************************************************************************************************/
/* Execute dissection of Data Item definition info before loading GUI tree                            */
/* Load configuration information into fastmsg_dataitem struct                                        */
/******************************************************************************************************/
static fastmsg_dataitem* fastmsg_dataitem_save(tvbuff_t *tvb, int offset)
{
    fastmsg_dataitem *dataitem;

    /* get a new dataitem and initialize it */
    dataitem = wmem_new(wmem_file_scope(), fastmsg_dataitem);

    /* retrieve data item name and terminate with a null */
    tvb_memcpy(tvb, dataitem->name, offset, 10);
    dataitem->name[10] = '\0'; /* Put a terminating null onto the end of the string */

    /* retrieve data item quantity and type */
    dataitem->quantity = tvb_get_ntohs(tvb, offset+10);
    dataitem->data_type = tvb_get_ntohs(tvb, offset+12);

    return dataitem;

}

/******************************************************************************************************/
/* Execute dissection of Data Region definition info before loading GUI tree                          */
/* Load configuration information into fastmsg_dataregion struct                                      */
/******************************************************************************************************/
static fastmsg_dataregion* fastmsg_dataregion_save(tvbuff_t *tvb, int offset)
{
    fastmsg_dataregion *dataregion;

    /* get a new dataregion and initialize it */
    dataregion = wmem_new(wmem_file_scope(), fastmsg_dataregion);

    /* retrieve data region name and terminate with a null */
    tvb_memcpy(tvb, dataregion->name, offset, 10);
    dataregion->name[10] = '\0'; /* Put a terminating null onto the end of the string */

    return dataregion;

}

/********************************************************************************************************/
/* Lookup region name using current base address & saved conversation data.  Return ptr to gchar string */
/********************************************************************************************************/
static const gchar*
region_lookup(packet_info *pinfo, guint32 base_addr)
{
    fm_conversation    *conv;
    fastmsg_dataregion *dataregion = NULL;

    conv = (fm_conversation *)p_get_proto_data(wmem_file_scope(), pinfo, proto_selfm, 0);
    if (conv) {
        dataregion = (fastmsg_dataregion*)wmem_tree_lookup32(conv->fastmsg_dataregions, base_addr);
    }

    if (dataregion) {
        return dataregion->name;
    }

    /* If we couldn't identify the region using the current base address, return a default string */
    return "Unknown Region";
}

/***********************************************************************************************************/
/* Create Fast SER Unsolicited Word Bit item.  Return item to calling function.  'index' parameter         */
/* will be used to store 'name' parameter in lookup tree.  Index 254 and 255 are special (hardcoded) cases */
/***********************************************************************************************************/
static fastser_uns_wordbit* fastser_uns_wordbit_save(guint8 idx, const char *name)
{
    fastser_uns_wordbit *wordbit_item;

    /* get a new wordbit_item and initialize it */
    wordbit_item = wmem_new(wmem_file_scope(), fastser_uns_wordbit);

    if (idx <= 253) {
        wordbit_item->name = wmem_strdup(wmem_file_scope(), name);
    }

    if (idx == 254) {
        wordbit_item->name = wmem_strdup(wmem_file_scope(), "POWER_UP");
    }

    if (idx == 255) {
        wordbit_item->name = wmem_strdup(wmem_file_scope(), "SET_CHNG");
    }

    return wordbit_item;

}

/***************************************************************************************************************/
/* Lookup uns wordbit name using current index position & saved conversation data.  Return ptr to gchar string */
/***************************************************************************************************************/
static const gchar*
fastser_uns_wordbit_lookup(packet_info *pinfo, guint8 idx)
{
    fm_conversation    *conv;
    fastser_uns_wordbit *wordbit = NULL;

    conv = (fm_conversation *)p_get_proto_data(wmem_file_scope(), pinfo, proto_selfm, 0);

    if (conv) {
        wordbit = (fastser_uns_wordbit*)wmem_tree_lookup32(conv->fastser_uns_wordbits, idx);
    }

    if (wordbit) {
        return wordbit->name;
    }

    /* If we couldn't identify the bit using the index, return a default string */
    return "Unknown";

}

/******************************************************************************************************/
/* Code to Dissect Relay Definition Frames */
/******************************************************************************************************/
static int
dissect_relaydef_frame(tvbuff_t *tvb, proto_tree *tree, int offset)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *relaydef_fm_item, *relaydef_flags_item, *relaydef_proto_item;
    proto_tree    *relaydef_tree, *relaydef_fm_tree, *relaydef_flags_tree, *relaydef_proto_tree;
    guint8        len, num_proto, num_fm, num_flags;
    int           count;

    len = tvb_get_guint8(tvb, offset);
    num_proto = tvb_get_guint8(tvb, offset+1);
    num_fm = tvb_get_guint8(tvb, offset+2);
    num_flags = tvb_get_guint8(tvb, offset+3);

    /* Add items to protocol tree specific to Relay Definition Block */
    relaydef_tree = proto_tree_add_subtree(tree, tvb, offset, len-2, ett_selfm_relaydef, NULL, "Relay Definition Block Details");

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

    /* Add Pad byte (if present) and checksum */
    if (tvb_reported_length_remaining(tvb, offset) > 1) {
        proto_tree_add_item(relaydef_tree, hf_selfm_padbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    proto_tree_add_checksum(relaydef_tree, tvb, offset, hf_selfm_checksum, -1, NULL, NULL, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);

    return tvb_reported_length(tvb);
}

/******************************************************************************************************/
/* Code to dissect Fast Meter Configuration Frames */
/******************************************************************************************************/
static int
dissect_fmconfig_frame(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_tree    *fmconfig_tree, *fmconfig_ai_tree=NULL, *fmconfig_calc_tree=NULL;
    guint         count;
    guint8        len, sf_loc, num_sf, num_ai, num_calc;
    gchar*        ai_name;

    len = tvb_get_guint8(tvb, offset);
    /* skip num_flags, position offset+1 */
    sf_loc = tvb_get_guint8(tvb, offset+2);
    num_sf = tvb_get_guint8(tvb, offset+3);
    num_ai = tvb_get_guint8(tvb, offset+4);
    /* skip num_samp,  position offset+5 */
    /* skip num_dig,   position offset+6 */
    num_calc = tvb_get_guint8(tvb, offset+7);

    fmconfig_tree = proto_tree_add_subtree(tree, tvb, offset, len-2, ett_selfm_fmconfig, NULL, "Fast Meter Configuration Details");

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
        ai_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 6, ENC_ASCII);

        fmconfig_ai_tree = proto_tree_add_subtree_format(fmconfig_tree, tvb, offset, 10,
                    ett_selfm_fmconfig_ai, NULL, "Analog Channel: %s", ai_name);

        /* Add Channel Name, Channel Data Type, Scale Factor Type and Scale Factor Offset to tree */
        proto_tree_add_item(fmconfig_ai_tree, hf_selfm_fmconfig_ai_channel, tvb, offset, 6, ENC_ASCII|ENC_NA);
        proto_tree_add_item(fmconfig_ai_tree, hf_selfm_fmconfig_ai_type, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_ai_tree, hf_selfm_fmconfig_ai_sf_type, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_ai_tree, hf_selfm_fmconfig_ai_sf_ofs, tvb, offset+8, 2, ENC_BIG_ENDIAN);

        /* Update Offset Pointer */
        offset += 10;
    }

    /* 14-byte Calculation block instances based on num_calc */
    for (count = 0; count < num_calc; count++) {
        fmconfig_calc_tree = proto_tree_add_subtree_format(fmconfig_tree, tvb, offset, 14,
                            ett_selfm_fmconfig_calc, NULL, "Calculation Block: %d", count+1);

        /* Rotation, Voltage Connection and Current Connection are all bit-masked on the same byte */
        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_rot, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_vconn, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_iconn, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_ctype, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_deskew_ofs, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_rs_ofs, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_xs_ofs, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_ia_idx, tvb, offset+8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_ib_idx, tvb, offset+9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_ic_idx, tvb, offset+10, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_va_idx, tvb, offset+11, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_vb_idx, tvb, offset+12, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fmconfig_calc_tree, hf_selfm_fmconfig_cblk_vc_idx, tvb, offset+13, 1, ENC_BIG_ENDIAN);

        offset += 14;
    }

    /* Add Config Message Scale Factor(s) (if present) */
    if ((num_sf != 0) && (sf_loc == FM_CONFIG_SF_LOC_CFG)) {
        for (count = 0; count < num_sf; count++) {
            proto_tree_add_item(fmconfig_tree, hf_selfm_fmconfig_ai_sf_float, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
    }

    /* Add Pad byte (if present) and checksum */
    if (tvb_reported_length_remaining(tvb, offset) > 1) {
        proto_tree_add_item(fmconfig_tree, hf_selfm_padbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    proto_tree_add_checksum(fmconfig_tree, tvb, offset, hf_selfm_checksum, -1, NULL, NULL, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);

    return tvb_reported_length(tvb);

}

/******************************************************************************************************/
/* Code to dissect Fast Meter Data Frames */
/* Formatting depends heavily on previously-encountered Configuration Frames so search array instances for them */
/******************************************************************************************************/
static int
dissect_fmdata_frame(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset, guint16 config_cmd_match)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item       *fmdata_item, *fmdata_dig_ch_item;
    proto_item       *fmdata_ai_sf_item;
    proto_tree       *fmdata_tree, *fmdata_ai_tree=NULL, *fmdata_dig_tree=NULL, *fmdata_ai_ch_tree=NULL, *fmdata_dig_ch_tree=NULL;
    guint8           len, idx=0, j=0, ts_mon, ts_day, ts_year, ts_hour, ts_min, ts_sec;
    guint16          config_cmd, ts_msec;
    gint16           ai_int16val;
    gint             cnt = 0, ch_size=0;
    gfloat           ai_sf_fp;
    gboolean         config_found = FALSE;
    fm_conversation  *conv;
    fm_config_frame  *cfg_data = NULL;

    len = tvb_get_guint8(tvb, offset);

    fmdata_tree = proto_tree_add_subtree_format(tree, tvb, offset, len-2, ett_selfm_fmdata, &fmdata_item, "Fast Meter Data Details");

    /* Reported length */
    proto_tree_add_item(fmdata_tree, hf_selfm_fmdata_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Search for previously-encountered Configuration information to dissect the frame */
    {
        conv = (fm_conversation *)p_get_proto_data(wmem_file_scope(), pinfo, proto_selfm, 0);

        if (conv) {
            wmem_list_frame_t *frame = wmem_list_head(conv->fm_config_frames);
            /* Cycle through possible instances of multiple fm_config_data_blocks, looking for match */
            while (frame && !config_found) {
                cfg_data = (fm_config_frame *)wmem_list_frame_data(frame);
                config_cmd = cfg_data->cfg_cmd;

                /* If the stored config_cmd matches the expected one we are looking for, mark that the config data was found */
                if (config_cmd == config_cmd_match) {
                    proto_item_append_text(fmdata_item, ", using frame number %"G_GUINT32_FORMAT" as Configuration Frame",
                                   cfg_data->fnum);
                    config_found = TRUE;
                }

                frame = wmem_list_frame_next(frame);
            }

            if (config_found) {

                /* Retrieve number of Status Flag bytes and setup tree */
                if (cfg_data->num_flags == 1){
                    proto_tree_add_item(fmdata_tree, hf_selfm_fmdata_flagbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /*offset += 1;*/
                }

                cnt = cfg_data->num_ai; /* actual number of analog values to available to dissect */

                /* Update our current tvb offset to the actual AI offset saved from the Configuration message */
                offset = cfg_data->offset_ai;

                /* Check that we actually have analog data to dissect */
                if (cnt > 0) {

                    /* Include decoding for each Sample provided for the Analog Channels */
                    for (j=0; j < cfg_data->num_ai_samples; j++) {

                        /* Use different lookup strings, depending on how many samples are available per Analog Channel */
                        if (cfg_data->num_ai_samples == 1) {
                            fmdata_ai_tree = proto_tree_add_subtree_format(fmdata_tree, tvb, offset, ((cfg_data->offset_ts - cfg_data->offset_ai)/cfg_data->num_ai_samples),
                                ett_selfm_fmdata_ai, NULL, "Analog Channels (%d), Sample: %d (%s)",
                                cfg_data->num_ai, j+1, val_to_str_const(j+1, selfm_fmconfig_numsamples1_vals, "Unknown"));
                        }
                        else if (cfg_data->num_ai_samples == 2) {
                            fmdata_ai_tree = proto_tree_add_subtree_format(fmdata_tree, tvb, offset, ((cfg_data->offset_ts - cfg_data->offset_ai)/cfg_data->num_ai_samples),
                                ett_selfm_fmdata_ai, NULL, "Analog Channels (%d), Sample: %d (%s)",
                                cfg_data->num_ai, j+1, val_to_str_const(j+1, selfm_fmconfig_numsamples2_vals, "Unknown"));
                        }
                        else if (cfg_data->num_ai_samples == 4) {
                            fmdata_ai_tree = proto_tree_add_subtree_format(fmdata_tree, tvb, offset, ((cfg_data->offset_ts - cfg_data->offset_ai)/cfg_data->num_ai_samples),
                                ett_selfm_fmdata_ai, NULL, "Analog Channels (%d), Sample: %d (%s)",
                                cfg_data->num_ai, j+1, val_to_str_const(j+1, selfm_fmconfig_numsamples4_vals, "Unknown"));
                        }

                        /* For each analog channel we encounter... */
                        for (idx = 0; idx < cnt; idx++) {

                            fm_analog_info *ai = &(cfg_data->analogs[idx]);

                            /* Channel size (in bytes) determined by data type */
                            switch (ai->type) {
                                case FM_CONFIG_ANA_CHTYPE_INT16:
                                    ch_size = 2;    /* 2 bytes */
                                    break;
                                case FM_CONFIG_ANA_CHTYPE_FP:
                                    ch_size = 4;    /* 4 bytes */
                                    break;
                                case FM_CONFIG_ANA_CHTYPE_FPD:
                                    ch_size = 8;    /* 8 bytes */
                                    break;
                                default:
                                    break;
                            }

                            /* Build sub-tree for each Analog Channel */
                            fmdata_ai_ch_tree = proto_tree_add_subtree_format(fmdata_ai_tree, tvb, offset, ch_size,
                                            ett_selfm_fmdata_ai_ch, NULL, "Analog Channel %d: %s", idx+1, ai->name);

                            /* XXX - Need more decoding options here for different data types, but I need packet capture examples first */
                            /* Decode analog value appropriately, according to data type */
                            switch (ai->type) {
                                /* Channel type is 16-bit Integer */
                                case FM_CONFIG_ANA_CHTYPE_INT16:
                                    ai_int16val = tvb_get_ntohs(tvb, offset);

                                    /* If we've got a scale factor, apply it before printing the analog */
                                    /* For scale factors present in the Fast Meter Data message... */
                                    if ((ai->sf_offset != 0) && (ai->sf_type == FM_CONFIG_ANA_SFTYPE_FP) && (cfg_data->sf_loc == FM_CONFIG_SF_LOC_FM)) {
                                        ai_sf_fp = tvb_get_ntohieee_float(tvb, ai->sf_offset);
                                        proto_tree_add_float(fmdata_ai_ch_tree, hf_selfm_fmdata_ai_sf_fp, tvb, ai->sf_offset, 4, ai_sf_fp);
                                    }
                                    /* For scale factors present in the Fast Meter Configuration Message... */
                                    else if (cfg_data->sf_loc == FM_CONFIG_SF_LOC_CFG) {
                                        ai_sf_fp = ai->sf_fp;
                                        fmdata_ai_sf_item = proto_tree_add_float(fmdata_ai_ch_tree, hf_selfm_fmdata_ai_sf_fp, tvb, offset, ch_size, ai_sf_fp);
                                        PROTO_ITEM_SET_GENERATED(fmdata_ai_sf_item);
                                    }
                                    /* If there was no scale factor, default value to 1 */
                                    else {
                                        ai_sf_fp = 1;
                                    }

                                    proto_tree_add_uint(fmdata_ai_ch_tree, hf_selfm_fmdata_ai_value16, tvb, offset, ch_size, ai_int16val);
                                    proto_tree_add_float(fmdata_ai_ch_tree, hf_selfm_fmdata_ai_scale_factor, tvb, offset, ch_size, ((gfloat)ai_int16val*ai_sf_fp));
                                    offset += ch_size;
                                    break;
                                /* Channel type is IEEE Floating point */
                                case FM_CONFIG_ANA_CHTYPE_FP:
                                    proto_tree_add_item(fmdata_ai_ch_tree, hf_selfm_fmdata_ai_value_float, tvb, offset, ch_size, ENC_BIG_ENDIAN);
                                    offset += ch_size;
                                    break;
                                /* Channel type is Double IEEE Floating point */
                                case FM_CONFIG_ANA_CHTYPE_FPD:
                                    proto_tree_add_item(fmdata_ai_ch_tree, hf_selfm_fmdata_ai_value_double, tvb, offset, ch_size, ENC_BIG_ENDIAN);
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
                    proto_tree_add_bytes_format_value(fmdata_tree, hf_selfm_fmdata_timestamp, tvb, offset, 8, NULL,
                            "%.2d/%.2d/%.2d %.2d:%.2d:%.2d.%.3d", ts_mon, ts_day, ts_year, ts_hour, ts_min, ts_sec, ts_msec);

                    offset += 8;
                }

                /* Check that we actually have digital data */
                if (cfg_data->num_dig > 0) {

                    fmdata_dig_tree = proto_tree_add_subtree_format(fmdata_tree, tvb, offset, cfg_data->num_dig,
                                        ett_selfm_fmdata_dig, NULL, "Digital Channels (%d)", cfg_data->num_dig);

                    for (idx=0; idx < cfg_data->num_dig; idx++) {

                        fmdata_dig_ch_tree = proto_tree_add_subtree_format(fmdata_dig_tree, tvb, offset, 1, ett_selfm_fmdata_dig_ch, &fmdata_dig_ch_item, "Digital Word Bit Row: %2d", idx+1);

                        /* Display the bit pattern on the digital channel proto_item */
                        proto_item_append_text(fmdata_dig_ch_item, " [  %d %d %d %d %d %d %d %d  ]",
                        ((tvb_get_guint8(tvb, offset) & 0x80) >> 7), ((tvb_get_guint8(tvb, offset) & 0x40) >> 6),
                        ((tvb_get_guint8(tvb, offset) & 0x20) >> 5), ((tvb_get_guint8(tvb, offset) & 0x10) >> 4),
                        ((tvb_get_guint8(tvb, offset) & 0x08) >> 3), ((tvb_get_guint8(tvb, offset) & 0x04) >> 2),
                        ((tvb_get_guint8(tvb, offset) & 0x02) >> 1), (tvb_get_guint8(tvb, offset) & 0x01));

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

                /* Add Pad byte (if present) and checksum */
                if (tvb_reported_length_remaining(tvb, offset) > 1) {
                    proto_tree_add_item(fmdata_tree, hf_selfm_padbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                }

                proto_tree_add_checksum(fmdata_tree, tvb, offset, hf_selfm_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);

            } /* matching config frame message was found */

        } /* config data found */

        if (!config_found) {
            proto_item_append_text(fmdata_item, ", No Fast Meter Configuration frame found");
            return 0;
        }
    }

    return tvb_reported_length(tvb);

}

/******************************************************************************************************/
/* Code to Dissect Fast Operate Configuration Frames */
/******************************************************************************************************/
static int
dissect_foconfig_frame(tvbuff_t *tvb, proto_tree *tree, int offset)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *foconfig_brkr_item, *foconfig_rb_item;
    proto_tree    *foconfig_tree, *foconfig_brkr_tree=NULL, *foconfig_rb_tree=NULL;
    guint         count;
    guint8        len, num_brkr, prb_supp;
    guint16       num_rb;

    len = tvb_get_guint8(tvb, offset);
    num_brkr = tvb_get_guint8(tvb, offset+1);
    num_rb = tvb_get_ntohs(tvb, offset+2);
    prb_supp = tvb_get_guint8(tvb, offset+4);

    foconfig_tree = proto_tree_add_subtree(tree, tvb, offset, len-2, ett_selfm_foconfig, NULL, "Fast Operate Configuration Details");

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

    /* Add Pad byte (if present) and checksum */
    if (tvb_reported_length_remaining(tvb, offset) > 1) {
        proto_tree_add_item(foconfig_tree, hf_selfm_padbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    proto_tree_add_checksum(foconfig_tree, tvb, offset, hf_selfm_checksum, -1, NULL, NULL, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);

    return tvb_reported_length(tvb);

}

/******************************************************************************************************/
/* Code to Dissect Alternate Fast Operate (AFO) Configuration Frames */
/******************************************************************************************************/
static int
dissect_alt_fastop_config_frame(tvbuff_t *tvb, proto_tree *tree, int offset)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_tree    *foconfig_tree;
    guint8        len;

    len = tvb_get_guint8(tvb, offset);

    foconfig_tree = proto_tree_add_subtree(tree, tvb, offset, len-2,
            ett_selfm_foconfig, NULL, "Alternate Fast Operate Configuration Details");

    /* Add items to protocol tree specific to Fast Operate Configuration Block */

    /* Reported length */
    proto_tree_add_item(foconfig_tree, hf_selfm_alt_foconfig_len, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Number of Ports */
    proto_tree_add_item(foconfig_tree, hf_selfm_alt_foconfig_num_ports, tvb, offset+1, 1, ENC_BIG_ENDIAN);

    /* Number of Breaker Bits */
    proto_tree_add_item(foconfig_tree, hf_selfm_alt_foconfig_num_brkr, tvb, offset+2, 1, ENC_BIG_ENDIAN);

    /* Number of Remote Bits */
    proto_tree_add_item(foconfig_tree, hf_selfm_alt_foconfig_num_rb, tvb, offset+3, 1, ENC_BIG_ENDIAN);

    /* Function Code(s) Supported */
    proto_tree_add_item(foconfig_tree, hf_selfm_alt_foconfig_funccode, tvb, offset+4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(foconfig_tree, hf_selfm_alt_foconfig_funccode, tvb, offset+5, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(foconfig_tree, hf_selfm_alt_foconfig_funccode, tvb, offset+6, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(foconfig_tree, hf_selfm_alt_foconfig_funccode, tvb, offset+7, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(foconfig_tree, hf_selfm_alt_foconfig_funccode, tvb, offset+8, 1, ENC_BIG_ENDIAN);

    return tvb_reported_length(tvb);

}

/******************************************************************************************************/
/* Code to Dissect Fast Operate (Remote Bit or Breaker Bit) Frames */
/******************************************************************************************************/
static int
dissect_fastop_frame(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_tree    *fastop_tree;
    guint8        len, opcode;
    guint16       msg_type;

    msg_type = tvb_get_ntohs(tvb, offset-2);
    len = tvb_get_guint8(tvb, offset);

    fastop_tree = proto_tree_add_subtree(tree, tvb, offset, len-2, ett_selfm_fastop, NULL, "Fast Operate Details");

    /* Add Reported length to tree*/
    proto_tree_add_item(fastop_tree, hf_selfm_fastop_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Operate Code */
    opcode = tvb_get_guint8(tvb, offset);

    /* Use different lookup table for different msg_type */
    if (msg_type == CMD_FASTOP_RB_CTRL) {
        proto_tree_add_item(fastop_tree, hf_selfm_fastop_rb_code, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Append Column Info w/ Control Code Code */
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", val_to_str_ext_const(opcode, &selfm_fo_rb_vals_ext, "Unknown Control Code"));
    }
    else if (msg_type == CMD_FASTOP_BR_CTRL) {
        proto_tree_add_item(fastop_tree, hf_selfm_fastop_br_code, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Append Column Info w/ Control Code Code */
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", val_to_str_ext_const(opcode, &selfm_fo_br_vals_ext, "Unknown Control Code"));
    }
    offset += 1;

    /* Operate Code Validation */
    proto_tree_add_item(fastop_tree, hf_selfm_fastop_valid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Add checksum */
    proto_tree_add_checksum(fastop_tree, tvb, offset, hf_selfm_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);

    return tvb_reported_length(tvb);

}

/******************************************************************************************************/
/* Code to Dissect Alternate Fast Operate (AFO) Command Frames */
/******************************************************************************************************/
static int
dissect_alt_fastop_frame(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_tree    *fastop_tree;
    guint8        len;
    guint16       opcode;

    len = tvb_get_guint8(tvb, offset);

    fastop_tree = proto_tree_add_subtree(tree, tvb, offset, len-2, ett_selfm_fastop, NULL, "Alternate Fast Operate Details");

    /* Add Reported length to tree */
    proto_tree_add_item(fastop_tree, hf_selfm_alt_fastop_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Operate Code */
    opcode = tvb_get_ntohs(tvb, offset);

    /* Append Column Info w/ Control Code Code */
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x", opcode);

    proto_tree_add_item(fastop_tree, hf_selfm_alt_fastop_code, tvb, offset, 2, ENC_BIG_ENDIAN);

    offset += 2;

    /* Operate Code Validation */
    proto_tree_add_item(fastop_tree, hf_selfm_alt_fastop_valid, tvb, offset, 2, ENC_BIG_ENDIAN);

    return tvb_reported_length(tvb);

}

/************************************************************************************************************************/
/* Code to dissect Fast Message Read Response Messages  */
/************************************************************************************************************************/
/* Each Read Response frame can have a maximum data size of 117 x 16-bit words (or 234 bytes) -  this is due to the 20  */
/* bytes of overhead and 254 max frame size. In the event of a larger data payload than 234 bytes, the FIR and FIN      */
/* bits will be used to indicate either the first frame, last frame, or a neither/middle frame.                         */
/* We can use the FIN bit to attempt a reassembly of the data payload since all messages will arrive sequentially.      */
/************************************************************************************************************************/

static int
dissect_fastmsg_readresp_frame(tvbuff_t *tvb, proto_tree *fastmsg_tree, packet_info *pinfo, int offset, guint8 seq_byte)
{
    proto_item        *fastmsg_tag_value_item=NULL, *fmdata_dig_item=NULL;
    proto_item        *pi_baseaddr=NULL, *pi_fnum=NULL, *pi_type=NULL, *pi_qty=NULL;
    proto_tree        *fastmsg_tag_tree=NULL, *fmdata_dig_tree=NULL;
    guint32           base_addr;
    guint16           data_size, num_addr, cnt;
    guint8            seq_cnt;
    gboolean          seq_fir, seq_fin, save_fragmented;
    int               payload_offset=0;
    fm_conversation   *conv;
    fastmsg_dataitem  *dataitem;
    tvbuff_t          *data_tvb, *payload_tvb;

    /* Decode sequence byte components */
    seq_cnt = seq_byte & FAST_MSG_SEQ_CNT;
    seq_fir = ((seq_byte & FAST_MSG_SEQ_FIR) >> 7);
    seq_fin = ((seq_byte & FAST_MSG_SEQ_FIN) >> 6);

    base_addr = tvb_get_ntohl(tvb, offset);  /* 32-bit field with base address to read */
    num_addr = tvb_get_ntohs(tvb, offset+4); /* 16-bit field with number of 16-bit addresses to read */

    /* Append Column Info w/ Base Address */
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x [%s]", base_addr, region_lookup(pinfo, base_addr));

    pi_baseaddr = proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_baseaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(pi_baseaddr, " [%s]", region_lookup(pinfo, base_addr));

    proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_numwords, tvb, offset+4, 2, ENC_BIG_ENDIAN);
    offset += 6;

    /* Setup a new tvb representing just the data payload of this particular message */
    data_tvb = tvb_new_subset( tvb, offset, (tvb_reported_length_remaining(tvb, offset)-2), (tvb_reported_length_remaining(tvb, offset)-2));

    save_fragmented = pinfo->fragmented;

    /* Check for fragmented packet by looking at the FIR and FIN bits */
    if (! (seq_fir && seq_fin)) {
        fragment_head         *frag_msg;

        /* This is a fragmented packet, mark it as such */
        pinfo->fragmented = TRUE;

        frag_msg = fragment_add_seq_next(&selfm_reassembly_table,
            data_tvb, 0, pinfo, 0, NULL,
            tvb_reported_length(data_tvb),
            !seq_fin);

        payload_tvb = process_reassembled_data(data_tvb, 0, pinfo,
            "Reassembled Data Response Payload", frag_msg, &selfm_frag_items,
            NULL, fastmsg_tree);

        if (payload_tvb) { /* Reassembled */
          /* We have the complete payload */
          col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Reassembled Data Response");
        }
        else
        {
          /* We don't have the complete reassembled payload. */
          col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Response Data Fragment %u" , seq_cnt);
        }

    }

    /* No re-assembly required, setup the payload_tvb based on the single-frame data payload tvb */
    else {
        payload_tvb = data_tvb;
        add_new_data_source(pinfo, payload_tvb, "Data Response Payload");
    }

    pinfo->fragmented = save_fragmented;

    /* If we had no need to re-assemble or this is the final packet of a reassembly, let's attempt to dissect the */
    /* data payload using any previously-captured data format information */
    if (payload_tvb) {

        /* Search for previously-encountered data format reference information to dissect the frame */
        conv = (fm_conversation *)p_get_proto_data(wmem_file_scope(), pinfo, proto_selfm, 0);

        if (conv) {
            /* Start at front of list and cycle through possible instances of multiple fastmsg_dataitem frames, looking for match */
            wmem_list_frame_t *frame = wmem_list_head(conv->fastmsg_dataitems);

            while (frame && (tvb_reported_length_remaining(payload_tvb, payload_offset) > 0)) {
                dataitem = (fastmsg_dataitem *)wmem_list_frame_data(frame);

                /* If the stored base address of the current data item matches the current base address of this response frame */
                /* mark that the config data was found and attempt further dissection */
                if (dataitem->base_address == base_addr) {

                    /* Data Item size (in bytes) determined by data type and quantity within item */
                    switch (dataitem->data_type) {
                        case FAST_MSG_TAGTYPE_CHAR8:
                        case FAST_MSG_TAGTYPE_DIGWORD8_BL:
                        case FAST_MSG_TAGTYPE_DIGWORD8:
                            data_size = 1 * dataitem->quantity;    /* 1 byte per qty */
                            break;
                        case FAST_MSG_TAGTYPE_CHAR16:
                        case FAST_MSG_TAGTYPE_DIGWORD16_BL:
                        case FAST_MSG_TAGTYPE_DIGWORD16:
                        case FAST_MSG_TAGTYPE_INT16:
                        case FAST_MSG_TAGTYPE_UINT16:
                            data_size = 2 * dataitem->quantity;    /* 2 bytes per qty */
                            break;
                        case FAST_MSG_TAGTYPE_INT32:
                        case FAST_MSG_TAGTYPE_UINT32:
                        case FAST_MSG_TAGTYPE_FLOAT:
                            data_size = 4 * dataitem->quantity;    /* 4 bytes per qty */
                            break;

                        default:
                            data_size = 0;
                            break;
                    }

                    fastmsg_tag_tree = proto_tree_add_subtree_format(fastmsg_tree, payload_tvb, payload_offset, data_size,
                                    ett_selfm_fastmsg_tag, NULL, "Data Item Name: %s", dataitem->name);

                    /* Load some information from the stored Data Format Response message into the tree for reference */
                    pi_fnum = proto_tree_add_uint_format(fastmsg_tag_tree, hf_selfm_fmdata_frame_data_format_reference, payload_tvb, payload_offset, data_size,
                                dataitem->fnum, "Using frame number %d (Index Pos: %d) as Data Format Reference",dataitem->fnum, dataitem->index_pos );
                    pi_type = proto_tree_add_uint(fastmsg_tag_tree, hf_selfm_fmdata_data_type, payload_tvb, payload_offset, 0, dataitem->data_type);
                    pi_qty = proto_tree_add_uint(fastmsg_tag_tree, hf_selfm_fmdata_quantity, payload_tvb, payload_offset, 0, dataitem->quantity );

                    PROTO_ITEM_SET_GENERATED(pi_fnum);
                    PROTO_ITEM_SET_GENERATED(pi_type);
                    proto_item_set_len(pi_type, data_size);
                    PROTO_ITEM_SET_GENERATED(pi_qty);
                    proto_item_set_len(pi_qty, data_size);

                    /* Data Item Type determines how to decode */
                    switch (dataitem->data_type) {

                        case FAST_MSG_TAGTYPE_DIGWORD8_BL:
                        case FAST_MSG_TAGTYPE_DIGWORD8:

                            for (cnt=1; cnt <= dataitem->quantity; cnt++) {

                                fmdata_dig_tree = proto_tree_add_subtree_format(fastmsg_tag_tree, payload_tvb, payload_offset, 1,
                                                    ett_selfm_fmdata_dig, &fmdata_dig_item, "8-bit Binary Items (Row: %2d)", cnt);

                                /* Display the bit pattern on the digital channel proto_item */
                                proto_item_append_text(fmdata_dig_item, " [  %d %d %d %d %d %d %d %d  ]",
                                ((tvb_get_guint8(payload_tvb, payload_offset) & 0x80) >> 7), ((tvb_get_guint8(payload_tvb, payload_offset) & 0x40) >> 6),
                                ((tvb_get_guint8(payload_tvb, payload_offset) & 0x20) >> 5), ((tvb_get_guint8(payload_tvb, payload_offset) & 0x10) >> 4),
                                ((tvb_get_guint8(payload_tvb, payload_offset) & 0x08) >> 3), ((tvb_get_guint8(payload_tvb, payload_offset) & 0x04) >> 2),
                                ((tvb_get_guint8(payload_tvb, payload_offset) & 0x02) >> 1), (tvb_get_guint8(payload_tvb, payload_offset) & 0x01));

                                proto_tree_add_item(fmdata_dig_tree, hf_selfm_fmdata_dig_b0, payload_tvb, payload_offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(fmdata_dig_tree, hf_selfm_fmdata_dig_b1, payload_tvb, payload_offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(fmdata_dig_tree, hf_selfm_fmdata_dig_b2, payload_tvb, payload_offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(fmdata_dig_tree, hf_selfm_fmdata_dig_b3, payload_tvb, payload_offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(fmdata_dig_tree, hf_selfm_fmdata_dig_b4, payload_tvb, payload_offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(fmdata_dig_tree, hf_selfm_fmdata_dig_b5, payload_tvb, payload_offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(fmdata_dig_tree, hf_selfm_fmdata_dig_b6, payload_tvb, payload_offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(fmdata_dig_tree, hf_selfm_fmdata_dig_b7, payload_tvb, payload_offset, 1, ENC_BIG_ENDIAN);

                                payload_offset += 1;

                            }

                            break;

                        case FAST_MSG_TAGTYPE_CHAR8:
                        case FAST_MSG_TAGTYPE_CHAR16:
                            proto_tree_add_item(fastmsg_tag_tree, hf_selfm_fmdata_ai_value_string, payload_tvb, payload_offset, data_size, ENC_ASCII|ENC_NA);
                            payload_offset += data_size;
                            break;

                        case FAST_MSG_TAGTYPE_INT16:
                            for (cnt=1; cnt <= dataitem->quantity; cnt++) {
                                fastmsg_tag_value_item = proto_tree_add_item(fastmsg_tag_tree, hf_selfm_fastmsg_dataitem_int16, payload_tvb, payload_offset, data_size/dataitem->quantity, ENC_BIG_ENDIAN);
                                proto_item_prepend_text(fastmsg_tag_value_item, "Value %d ", cnt);
                                payload_offset += data_size/dataitem->quantity;
                            }
                            break;

                        case FAST_MSG_TAGTYPE_UINT16:
                            for (cnt=1; cnt <= dataitem->quantity; cnt++) {
                                fastmsg_tag_value_item = proto_tree_add_item(fastmsg_tag_tree, hf_selfm_fastmsg_dataitem_uint16, payload_tvb, payload_offset, data_size/dataitem->quantity, ENC_BIG_ENDIAN);
                                proto_item_prepend_text(fastmsg_tag_value_item, "Value %d ", cnt);
                                payload_offset += data_size/dataitem->quantity;
                            }
                            break;

                        case FAST_MSG_TAGTYPE_INT32:
                            for (cnt=1; cnt <= dataitem->quantity; cnt++) {
                                fastmsg_tag_value_item = proto_tree_add_item(fastmsg_tag_tree, hf_selfm_fastmsg_dataitem_int32, payload_tvb, payload_offset, data_size/dataitem->quantity, ENC_BIG_ENDIAN);
                                proto_item_prepend_text(fastmsg_tag_value_item, "Value %d ", cnt);
                                payload_offset += data_size/dataitem->quantity;
                            }
                            break;

                        case FAST_MSG_TAGTYPE_UINT32:
                            for (cnt=1; cnt <= dataitem->quantity; cnt++) {
                                fastmsg_tag_value_item = proto_tree_add_item(fastmsg_tag_tree, hf_selfm_fastmsg_dataitem_uint32, payload_tvb, payload_offset, data_size/dataitem->quantity, ENC_BIG_ENDIAN);
                                proto_item_prepend_text(fastmsg_tag_value_item, "Value %d ", cnt);
                                payload_offset += data_size/dataitem->quantity;
                            }
                            break;

                        case FAST_MSG_TAGTYPE_FLOAT:
                            for (cnt=1; cnt <= dataitem->quantity; cnt++) {
                                fastmsg_tag_value_item = proto_tree_add_item(fastmsg_tag_tree, hf_selfm_fastmsg_dataitem_float, payload_tvb, payload_offset, data_size/dataitem->quantity, ENC_BIG_ENDIAN);
                                proto_item_prepend_text(fastmsg_tag_value_item, "Value %d ", cnt);
                                payload_offset += data_size/dataitem->quantity;
                            }
                            break;

                        default:
                            break;
                    } /* data item type switch */

                } /* base address is correct */

                /* After processing this frame/data item, proceed to the next */
                frame = wmem_list_frame_next(frame);

            } /* while (frame) */

        } /* if (conv) found */

    } /* if payload_tvb */

    /* Update the offset field before we leave this frame */
    offset += num_addr*2;

    return offset;

}


/******************************************************************************************************/
/* Code to dissect Fast Message Frames       */
/******************************************************************************************************/
static int
dissect_fastmsg_frame(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *fastmsg_def_fc_item, *fastmsg_elementlist_item;
    proto_item    *pi_baseaddr, *fastmsg_crc16_item;
    proto_tree    *fastmsg_tree, *fastmsg_def_fc_tree=NULL, *fastmsg_elementlist_tree=NULL;
    proto_tree    *fastmsg_element_tree=NULL, *fastmsg_datareg_tree=NULL, *fastmsg_tag_tree=NULL;
    gint          cnt, num_elements, elmt_status32_ofs=0, elmt_status, null_offset;
    guint8        len, funccode, seq, rx_num_fc, tx_num_fc;
    guint8        seq_cnt, elmt_idx, fc_enable;
    guint8        *tag_name_ptr;
    guint16       base_addr, num_addr, num_reg, addr1, addr2, crc16, crc16_calc;
    guint32       tod_ms, elmt_status32, elmt_ts_offset;
    static const int * seq_fields[] = {
        &hf_selfm_fastmsg_seq_fir,
        &hf_selfm_fastmsg_seq_fin,
        &hf_selfm_fastmsg_seq_cnt,
        NULL
    };

    len = tvb_get_guint8(tvb, offset);

    fastmsg_tree = proto_tree_add_subtree(tree, tvb, offset, len-2, ett_selfm_fastmsg, NULL, "Fast Message Details");

    /* Reported length */
    proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_len, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* 5-byte Future Routing Address */
    proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_routing_addr, tvb, offset+1, 5, ENC_NA);
    offset += 6;

    /* Add Status Byte to tree */
    proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Get Function Code, add to tree */
    funccode = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_funccode, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Append Column Info w/ Function Code */
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", val_to_str_ext_const(funccode, &selfm_fastmsg_func_code_vals_ext, "Unknown Function Code"));

    offset += 1;

    /* Get Sequence Byte, add to Tree */
    seq = tvb_get_guint8(tvb, offset);
    seq_cnt = seq & FAST_MSG_SEQ_CNT;

    proto_tree_add_bitmask_with_flags(fastmsg_tree, tvb, offset, hf_selfm_fastmsg_seq, ett_selfm_fastmsg_seq,
        seq_fields, ENC_NA, BMT_NO_APPEND);
    offset += 1;

    /* Add Response Number to tree */
    proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_resp_num, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Depending on Function Code used, remaining section of packet will be handled differently. */
    switch (funccode) {

        case FAST_MSG_EN_UNS_DATA:   /* 0x01 - Enabled Unsolicited Data Transfers */

            /* Function code to enable */
            fc_enable = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_uns_en_fc, tvb, offset, 1, ENC_BIG_ENDIAN);

            /* Append Column Info w/ "Enable" Function Code */
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Function to Enable (%#x)", fc_enable);

            /* 3-byte Function Code data */
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_uns_en_fc_data, tvb, offset+1, 3, ENC_NA);

            offset += 4;

            break;

        case FAST_MSG_DIS_UNS_DATA:   /* 0x02 - Disable Unsolicited Data Transfers */

            /* Function code to disable */
            fc_enable = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_uns_dis_fc, tvb, offset, 1, ENC_BIG_ENDIAN);

            /* Append Column Info w/ "Disable" Function Code */
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Function to Disable (%#x)", fc_enable);

            /* 1-byte Function Code data */
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_uns_dis_fc_data, tvb, offset+1, 1, ENC_NA);

            offset += 2;

            break;


        case FAST_MSG_READ_REQ:     /* 0x10 - Read Request */

            base_addr = tvb_get_ntohl(tvb, offset); /* 32-bit field with base address to read */

            /* Append Column Info w/ Base Address */
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x [%s]", base_addr, region_lookup(pinfo, base_addr));

            pi_baseaddr = proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_baseaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(pi_baseaddr, " [%s]", region_lookup(pinfo, base_addr));

            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_numwords, tvb, offset+4, 2, ENC_BIG_ENDIAN);
            offset += 6;
            break;

        case FAST_MSG_GEN_UNS_DATA: /* 0x12 - Generic Unsolicited Data */

            num_addr = len - 14; /* 12 header bytes + 2-byte CRC, whatever is left is the data portion of this message */
            num_reg = num_addr / 2;

            /* For the number of registers, step through and retrieve/print each 16-bit component */
            for (cnt=0; cnt < num_reg; cnt++) {
                proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_unswrite_reg_val, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }

            break;

        case FAST_MSG_SOE_STATE_REQ: /* 0x16 - SOE Present State Request */

            /* 4 bytes - "Origination Path" */
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_soe_req_orig, tvb, offset, 4, ENC_NA);
            offset += 4;

            break;

        case FAST_MSG_UNS_RESP:     /* 0x18 - Unsolicited Fast SER Data Response */

            /* 4 bytes - "Origination Path" */
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_unsresp_orig, tvb, offset, 4, ENC_NA);
            offset += 4;

            /* Timestamp: 2-byte day-of-year, 2-byte year, 4-byte time-of-day in milliseconds  */
            /* XXX - We can use a built-in function to convert the tod_ms to a readable time format, is there anything for day_of_year? */
            tod_ms = tvb_get_ntohl(tvb, offset+4);

            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_unsresp_doy, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_unsresp_year, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_uint_format_value(fastmsg_tree, hf_selfm_fastmsg_unsresp_todms, tvb, offset+4, 4,
                                        tod_ms, "%s", signed_time_msecs_to_str(wmem_packet_scope(), tod_ms));
            offset += 8;

            /* Build element tree */
            /* Determine the number of elements returned in this unsolicited message */
            /* The general formula is: (Length - 34) / 4 */
            num_elements = (len-34) / 4;

            fastmsg_elementlist_item = proto_tree_add_uint(fastmsg_tree, hf_selfm_fastmsg_unsresp_num_elmt, tvb, offset, (4*num_elements), num_elements);
            fastmsg_elementlist_tree = proto_item_add_subtree(fastmsg_elementlist_item, ett_selfm_fastmsg_element_list);

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
                fastmsg_element_tree = proto_tree_add_subtree_format(fastmsg_elementlist_tree, tvb, offset, 4, ett_selfm_fastmsg_element, NULL,
                    "Reported Event %d (Index: %d [%s], New State: %s)", cnt+1, elmt_idx, fastser_uns_wordbit_lookup(pinfo, elmt_idx),
                                                                         val_to_str_const(elmt_status, selfm_ser_status_vals, "Unknown"));

                /* Add Index Number and Timestamp offset to tree */
                proto_tree_add_item(fastmsg_element_tree, hf_selfm_fastmsg_unsresp_elmt_idx, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(fastmsg_element_tree, hf_selfm_fastmsg_unsresp_elmt_ts_ofs, tvb, offset+1, 3, ENC_BIG_ENDIAN);
                proto_tree_add_uint_format_value(fastmsg_element_tree, hf_selfm_fastmsg_unsresp_elmt_ts_ofs_decoded, tvb, offset+1, 3,
                                     tod_ms + (elmt_ts_offset/1000), "%s", signed_time_msecs_to_str(wmem_packet_scope(), tod_ms + (elmt_ts_offset/1000)));
                proto_tree_add_uint(fastmsg_element_tree, hf_selfm_fastmsg_unsresp_elmt_status, tvb, elmt_status32_ofs, 4, elmt_status);

                offset += 4;

            }

            /* 4-byte End-of-Record Terminator 0xFFFFFFFE */
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_unsresp_eor, tvb, offset, 4, ENC_NA);
            offset += 4;

            /* 4-byte Element Status word */
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_unsresp_elmt_statword, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            break;


        case FAST_MSG_UNS_WRITE:    /* 0x20 - Unsolicited Write */

            /* Write Address Region #1 and #2, along with number of 16-bit registers */
            addr1 =   tvb_get_ntohs(tvb, offset);
            addr2 =   tvb_get_ntohs(tvb, offset+2);
            num_reg = tvb_get_ntohs(tvb, offset+4);

            /* Append Column Info w/ Address Information */
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x, %#x", addr1, addr2);

            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_unswrite_addr1, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_unswrite_addr2, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_unswrite_num_reg, tvb, offset+4, 2, ENC_BIG_ENDIAN);

            offset += 6;

            /* For the number of registers, step through and retrieve/print each 16-bit component */
            for (cnt=0; cnt < num_reg; cnt++) {
                proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_unswrite_reg_val, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }

            break;

        case FAST_MSG_DATAFMT_REQ:   /* 0x31 - Data Format Request */

            base_addr = tvb_get_ntohl(tvb, offset); /* 32-bit field with base address to read */

            /* Append Column Info w/ Base Address */
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x [%s]", base_addr, region_lookup(pinfo, base_addr));

            /* Add Base Address to Tree */
            pi_baseaddr = proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_baseaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(pi_baseaddr, " [%s]", region_lookup(pinfo, base_addr));

            offset += 4;

            break;

        case FAST_MSG_BITLABEL_REQ:  /* 0x33 - Bit Label Request */

            base_addr = tvb_get_ntohl(tvb, offset); /* 32-bit field with base address to read */
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_baseaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Append Column Info w/ Base Address */
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x", base_addr);

            break;


        case FAST_MSG_CFG_BLOCK_RESP: /* 0x80 (resp to 0x00) - Fast Message Configuration Block Response */

             /* Routing Support */
             proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_def_route_sup, tvb, offset, 1, ENC_BIG_ENDIAN);
             offset += 1;

             /* RX / TX Status */
             proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_def_rx_stat, tvb, offset, 1, ENC_BIG_ENDIAN);
             proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_def_tx_stat, tvb, offset+1, 1, ENC_BIG_ENDIAN);
             offset += 2;

             /* Max Frames RX/TX */
             proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_def_rx_maxfr, tvb, offset, 1, ENC_BIG_ENDIAN);
             proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_def_tx_maxfr, tvb, offset+1, 1, ENC_BIG_ENDIAN);
             offset += 2;

             /* 6 bytes of reserved space */
             offset += 6;

             /* Number of Supported RX Function Codes */
             rx_num_fc = tvb_get_guint8(tvb, offset);
             fastmsg_def_fc_item = proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_def_rx_num_fc, tvb, offset, 1, ENC_BIG_ENDIAN);
             fastmsg_def_fc_tree = proto_item_add_subtree(fastmsg_def_fc_item, ett_selfm_fastmsg_def_fc);
             offset += 1;

             /* Add Supported RX Function Codes to tree */
             for (cnt=0; cnt<rx_num_fc; cnt++) {
                 proto_tree_add_item(fastmsg_def_fc_tree, hf_selfm_fastmsg_def_rx_fc, tvb, offset, 1, ENC_BIG_ENDIAN);
                 offset += 2;
             }

             /* Number of Supported TX Function Codes */
             tx_num_fc = tvb_get_guint8(tvb, offset);
             fastmsg_def_fc_item = proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_def_tx_num_fc, tvb, offset, 1, ENC_BIG_ENDIAN);
             fastmsg_def_fc_tree = proto_item_add_subtree(fastmsg_def_fc_item, ett_selfm_fastmsg_def_fc);
             offset += 1;

             /* Add Supported TX Function Codes to tree */
             for (cnt=0; cnt<tx_num_fc; cnt++) {
                 proto_tree_add_item(fastmsg_def_fc_tree, hf_selfm_fastmsg_def_tx_fc, tvb, offset, 1, ENC_BIG_ENDIAN);
                 offset += 2;
             }

             break;

        case FAST_MSG_READ_RESP:     /* 0x90 (resp to 0x10) - Read Response */

            offset = dissect_fastmsg_readresp_frame( tvb, fastmsg_tree, pinfo, offset, seq);

            break;

        case FAST_MSG_SOE_STATE_RESP: /* 0x96 - (resp to 0x16) SOE Present State Response */

            /* 16-bit field with number of blocks of present state data */
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_soe_resp_numblks, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* XXX - With examples, need to loop through each one of these items based on the num_blocks */
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_soe_resp_orig, tvb, offset, 4, ENC_NA);
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_soe_resp_numbits, tvb, offset+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_soe_resp_pad, tvb, offset+5, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_soe_resp_doy, tvb, offset+6, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_soe_resp_year, tvb, offset+8, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_soe_resp_tod, tvb, offset+10, 4, ENC_BIG_ENDIAN);
            /* proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_soe_resp_data, tvb, offset+14, 2, ENC_BIG_ENDIAN); */

            offset += 14;

            break;

        case FAST_MSG_DEVDESC_RESP:  /* 0xB0 (resp to 0x30) - Device Description Response */

            /* Add FID / RID ASCII data to tree */
            proto_tree_add_item(fastmsg_tree, hf_selfm_fid, tvb, offset, 50, ENC_ASCII|ENC_NA);
            proto_tree_add_item(fastmsg_tree, hf_selfm_rid, tvb, offset+50, 40, ENC_ASCII|ENC_NA);
            offset += 90;

            /* 16-bit field with number of data areas */
            num_reg = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_devdesc_num_region, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Maximum size of 7 regions per message, check the seq_cnt to determine if we have stepped into
               the next sequential message where the remaining regions would be described */
            if ((num_reg >= 8) && (seq_cnt == 0)) {
                num_reg = 7;
            }
            else{
                num_reg = num_reg - (seq_cnt * 7);
            }

            /* 16-bit field with number of control areas */
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_devdesc_num_ctrl, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Each 18-byte data area description has a 10 byte region name, followed by 32-bit base, */
            /* 16-bit message word count and 16-bit flag field */
            for (cnt=0; cnt<num_reg; cnt++) {

                fastmsg_datareg_tree = proto_tree_add_subtree_format(fastmsg_tree, tvb, offset, 18,
                                ett_selfm_fastmsg_datareg, NULL, "Fast Message Data Region #%d", cnt+1);

                /* 10-Byte Region description */
                proto_tree_add_item(fastmsg_datareg_tree, hf_selfm_fastmsg_data_region_name, tvb, offset, 10, ENC_ASCII|ENC_NA);
                offset += 10;

                /* 32-bit field with base address of data region */
                proto_tree_add_item(fastmsg_datareg_tree, hf_selfm_fastmsg_baseaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                /* 16-bit field with number of 16-bit words in region */
                proto_tree_add_item(fastmsg_datareg_tree, hf_selfm_fastmsg_numwords, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* 16-bit flag field */
                proto_tree_add_item(fastmsg_datareg_tree, hf_selfm_fastmsg_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

            }

            /* Some relays (4xx) don't follow the standard here and include an 8-byte sequence of all 0x00's to represent */
            /* 'reserved' space for the control regions.  Detect these and skip if they are present */
            for (cnt = offset; cnt < len; cnt++) {

                if (tvb_memeql(tvb, cnt, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0) {
                    offset = cnt+8;
                }
            }

            break;

        case FAST_MSG_DATAFMT_RESP: /* 0xB1 (resp to 0x31) - Data Format Response */

            base_addr = tvb_get_ntohl(tvb, offset); /* 32-bit field with base address to read */

            /* Add Base Address to Tree */
            pi_baseaddr = proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_baseaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(pi_baseaddr, " [%s]", region_lookup(pinfo, base_addr));

            offset += 4;

            /* Append Column Info w/ Base Address */
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%#x [%s]", base_addr, region_lookup(pinfo, base_addr));

            /* 16-bit field with number of data items to follow */
            proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_datafmt_resp_numitem, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            while ((tvb_reported_length_remaining(tvb, offset)) > 2) {
                /* Data Item record name 10 bytes */
                tag_name_ptr = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 10, ENC_ASCII);
                fastmsg_tag_tree = proto_tree_add_subtree_format(fastmsg_tree, tvb, offset, 14, ett_selfm_fastmsg_tag, NULL, "Data Item Record Name: %s", tag_name_ptr);

                /* Data item qty and type */
                proto_tree_add_item(fastmsg_tag_tree, hf_selfm_fastmsg_dataitem_qty, tvb, offset+10, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(fastmsg_tag_tree, hf_selfm_fastmsg_dataitem_type, tvb, offset+12, 2, ENC_BIG_ENDIAN);

                offset += 14;
            }
            break;

        case FAST_MSG_BITLABEL_RESP: /* 0xB3 (resp to 0x33) - Bit Label Response */

            /* The data in this response is a variable length string containing the names of 8 digital bits. */
            /* Each name is max 8 chars and each is null-seperated */
            cnt=1;

            /* find the null separators and add the bit label text strings to the tree */
            for (null_offset = offset; null_offset < len; null_offset++) {
                if ((tvb_memeql(tvb, null_offset, "\x00", 1) == 0) && (tvb_reported_length_remaining(tvb, offset) > 2)) {
                    gchar* str = tvb_format_text(tvb, offset, (null_offset-offset));
                    proto_tree_add_string_format(fastmsg_tree, hf_selfm_fastmsg_bit_label_name, tvb, offset, (null_offset-offset), str,
                            "Bit Label #%d Name: %s", cnt, str);
                    offset = null_offset+1; /* skip the null */
                    cnt++;
                }
            }

            break;

        default:
            break;
    } /* func_code */

    /* Add CRC16 to Tree */
    fastmsg_crc16_item = proto_tree_add_item(fastmsg_tree, hf_selfm_fastmsg_crc16, tvb, offset, 2, ENC_BIG_ENDIAN);
    crc16 = tvb_get_ntohs(tvb, offset);

    /* If option is enabled, validate the CRC16 */
    if (selfm_crc16) {
        crc16_calc = crc16_plain_tvb_offset_seed(tvb, 0, len-2, 0xFFFF);
        if (crc16_calc != crc16) {
            expert_add_info_format(pinfo, fastmsg_crc16_item, &ei_selfm_crc16_incorrect, "Incorrect CRC - should be 0x%04x", crc16_calc);
        }
        else {
            proto_item_append_text(fastmsg_crc16_item, " [OK]");
        }

    }

    return tvb_reported_length(tvb);

}


/******************************************************************************************************/
/* Code to dissect SEL Fast Message Protocol packets */
/* Will call other sub-dissectors, as needed         */
/******************************************************************************************************/
static int
dissect_selfm(tvbuff_t *selfm_tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *selfm_item=NULL;
    proto_tree    *selfm_tree=NULL;
    int           offset=0, cnt=0;
    guint32       base_addr;
    guint16       msg_type, len, num_items;
    guint8        seq, seq_cnt;
    gchar         **uns_ser_split_str;

    /* Make entries in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SEL Protocol");
    col_clear(pinfo->cinfo, COL_INFO);

    len = tvb_reported_length(selfm_tvb);

    msg_type = tvb_get_ntohs(selfm_tvb, offset);

    /* On first pass through the packets we have 4 tasks to complete - they are each noted below */
    if (!pinfo->fd->flags.visited) {
        conversation_t       *conversation;
        fm_conversation      *fm_conv_data;

        /* Find a conversation, create a new if no one exists */
        conversation = find_or_create_conversation(pinfo);

        fm_conv_data = (fm_conversation *)conversation_get_proto_data(conversation, proto_selfm);

        if (fm_conv_data == NULL) {
            fm_conv_data = wmem_new(wmem_file_scope(), fm_conversation);
            fm_conv_data->fm_config_frames = wmem_list_new(wmem_file_scope());
            fm_conv_data->fastmsg_dataitems = wmem_list_new(wmem_file_scope());
            fm_conv_data->fastmsg_dataregions = wmem_tree_new(wmem_file_scope());
            fm_conv_data->fastser_uns_wordbits = wmem_tree_new(wmem_file_scope());
            conversation_add_proto_data(conversation, proto_selfm, (void *)fm_conv_data);

            uns_ser_split_str = wmem_strsplit(wmem_packet_scope(), selfm_ser_list, ",", -1);

            for (cnt = 0; (uns_ser_split_str[cnt] != NULL); cnt++) {
                fastser_uns_wordbit *wordbit_ptr = fastser_uns_wordbit_save(cnt, uns_ser_split_str[cnt]);
                wmem_tree_insert32(fm_conv_data->fastser_uns_wordbits, cnt, wordbit_ptr);
            }

            /* Power Up (254) and Settings Changed (255) Indexes */
            for (cnt = 254; (cnt <= 255); cnt++) {
                fastser_uns_wordbit *wordbit_ptr = fastser_uns_wordbit_save(cnt, "unused");
                wmem_tree_insert32(fm_conv_data->fastser_uns_wordbits, cnt, wordbit_ptr);
            }
        }

        p_add_proto_data(wmem_file_scope(), pinfo, proto_selfm, 0, fm_conv_data);

        /* 1. Configuration frames (0xA5C1, 0xA5C2, 0xA5C3) need special treatment during the first run         */
        /* For each Fast Meter Configuration frame (0xA5Cx), a 'fm_config_frame' struct is created to hold the  */
        /* information necessary to decode subsequent matching Fast Meter Data frames (0xA5Dx). A pointer to    */
        /* this struct is saved in the conversation and is copied to the per-packet information if a            */
        /* Fast Meter Data frame is dissected.                                                                  */
        if ((CMD_FM_CONFIG == msg_type) || (CMD_DFM_CONFIG == msg_type) || (CMD_PDFM_CONFIG == msg_type)) {
            /* Fill the fm_config_frame */
            fm_config_frame *frame_ptr = fmconfig_frame_fast(selfm_tvb);
            frame_ptr->fnum = pinfo->num;
            wmem_list_prepend(fm_conv_data->fm_config_frames, frame_ptr);
        }

        /* 2. Fill conversation data array with Fast Msg Data Item info from Data Format Response Messages.   */
        /* These format definitions will later be retrieved to decode Read Response messages.                 */
        if ((CMD_FAST_MSG == msg_type) && (tvb_get_guint8(selfm_tvb, offset+9) == FAST_MSG_DATAFMT_RESP)) {

            seq = tvb_get_guint8(selfm_tvb, offset+10);
            seq_cnt = seq & FAST_MSG_SEQ_CNT;

            base_addr = tvb_get_ntohl(selfm_tvb, offset+12); /* 32-bit field with base address to read */
            num_items = tvb_get_ntohs(selfm_tvb, offset+16);

            /* When dealing with Data Format Response messages, there are a maximum of 16 items per frame */
            /* Use the sequence count if we have more 16 items to determine how many to expect in each frame */
            if ((num_items > 16) && (seq_cnt == 0)) {
                num_items = 16;
            }
            else {
                num_items = num_items - (seq_cnt * 16);
            }

            /* Set offset to start of data items */
            offset = 18;

            /* Enter the single frame multiple times, retrieving a single dataitem per entry */
            for (cnt = 1; (cnt <= num_items); cnt++) {
                fastmsg_dataitem *dataitem_ptr = fastmsg_dataitem_save(selfm_tvb, offset);
                dataitem_ptr->fnum = pinfo->num;
                dataitem_ptr->base_address = base_addr;
                dataitem_ptr->index_pos = cnt;

                /* Store the data item configuration info in the fastmsg_dataitems list */
                wmem_list_append(fm_conv_data->fastmsg_dataitems, dataitem_ptr);
                offset += 14;
            }
        }

        /* 3. Attempt re-assembly during first pass with Read Response Messages data payloads that span multiple */
        /* packets.  The final data payload will be assembled on the packet with the seq_fin bit set.            */
        if ((CMD_FAST_MSG == msg_type) && (tvb_get_guint8(selfm_tvb, offset+9) == FAST_MSG_READ_RESP)) {

            seq = tvb_get_guint8(selfm_tvb, offset+10);

            /* Set offset to where the dissect_fastmsg_readresp_frame function would normally be called, */
            /* right before base address & num_items */
            offset = 12;

            /* Call the same read response function that will be called during GUI dissection */
            offset = dissect_fastmsg_readresp_frame( selfm_tvb, tree, pinfo, offset, seq);

        }

        /* 4. Fill conversation data array with Fast Message Data Region info from Device Desc Response Messages.  This */
        /*    will retrieve a data region name (associated to an address) that can later be displayed in the tree.      */
        if ((CMD_FAST_MSG == msg_type) && (tvb_get_guint8(selfm_tvb, offset+9) == FAST_MSG_DEVDESC_RESP)) {

            seq = tvb_get_guint8(selfm_tvb, offset+10);
            seq_cnt = seq & FAST_MSG_SEQ_CNT;

            num_items = tvb_get_ntohs(selfm_tvb, offset+102);

            /* When dealing with Device Description Response messages, there are a maximum of 7 regions per frame */
            /* Use the sequence count if we have more 7 items to determine how many to expect in each frame */
            if ((num_items >= 8) && (seq_cnt == 0)) {
                num_items = 7;
            }
            else{
                num_items = num_items - (seq_cnt * 7);
            }

            /* Set offset to start of data regions */
            offset = 106;

            /* Enter the single frame multiple times, retrieving a single data region per entry */
            for (cnt = 1; (cnt <= num_items); cnt++) {
                guint32 base_address = tvb_get_ntohl(selfm_tvb, offset+10);
                fastmsg_dataregion *dataregion_ptr = fastmsg_dataregion_save(selfm_tvb, offset);

                /* Store the data region info in the fastmsg_dataregions tree */
                wmem_tree_insert32(fm_conv_data->fastmsg_dataregions, base_address, dataregion_ptr);
                offset += 18;
            }
        }
    } /* if (!visited) */

    {

        selfm_item = proto_tree_add_protocol_format(tree, proto_selfm, selfm_tvb, 0, len, "SEL Protocol");
        selfm_tree = proto_item_add_subtree(selfm_item, ett_selfm);

        /* Set INFO column with SEL Protocol Message Type */
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_ext_const(msg_type, &selfm_msgtype_vals_ext, "Unknown Message Type"));

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
                    case CMD_FAST_MSG:
                        dissect_fastmsg_frame(selfm_tvb, selfm_tree, pinfo, offset);
                        break;
                    case CMD_FASTOP_RB_CTRL:
                    case CMD_FASTOP_BR_CTRL:
                        dissect_fastop_frame(selfm_tvb, selfm_tree, pinfo, offset);
                        break;
                    case CMD_ALT_FASTOP_CONFIG:
                        dissect_alt_fastop_config_frame(selfm_tvb, selfm_tree, offset);
                        break;
                    case CMD_ALT_FASTOP_OPEN:
                    case CMD_ALT_FASTOP_CLOSE:
                    case CMD_ALT_FASTOP_SET:
                    case CMD_ALT_FASTOP_CLEAR:
                    case CMD_ALT_FASTOP_PULSE:
                        dissect_alt_fastop_frame(selfm_tvb, selfm_tree, pinfo, offset);
                        break;
                    default:
                        break;
                } /* msg_type */
        } /* remaining length > 0 */
    }

    return tvb_reported_length(selfm_tvb);
}

/******************************************************************************************************/
/* Return length of SEL Protocol over TCP message (used for re-assembly)                               */
/* SEL Protocol "Scan" messages are generally 2-bytes in length and only include a 16-bit message type */
/* SEL Protocol "Response" messages include a "length" byte in offset 2 of each response message       */
/******************************************************************************************************/
static guint
get_selfm_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
    guint message_len=0;  /* message length, inclusive of header, data, crc */

    /* Get length byte from message */
    if (tvb_reported_length(tvb) > 2) {
        message_len = tvb_get_guint8(tvb, offset+2);
    }
    /* for 2-byte poll messages, set the length to 2 */
    else if (tvb_reported_length(tvb) == 2) {
        message_len = 2;
    }

    return message_len;
}

/******************************************************************************************************/
/* Dissect (and possibly Re-assemble) SEL protocol payload data */
/******************************************************************************************************/
static int
dissect_selfm_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

    tvbuff_t      *selfm_tvb;
    gint length = tvb_reported_length(tvb);

    /* Check for a SEL Protocol packet.  It should begin with 0xA5 */
    if(length < 2 || tvb_get_guint8(tvb, 0) != 0xA5) {
        /* Not a SEL Protocol packet, just happened to use the same port */
        return 0;
    }

    /* If this is a Telnet-encapsulated Ethernet packet, let's clean out the IAC 0xFF instances */
    /* before we attempt any kind of re-assembly of the message */
    if ((pinfo->srcport) && selfm_telnet_clean) {
        selfm_tvb = clean_telnet_iac(pinfo, tvb, 0, length);
    }
    else {
        selfm_tvb = tvb_new_subset_length( tvb, 0, length);
    }


    tcp_dissect_pdus(selfm_tvb, pinfo, tree, selfm_desegment, 2,
                   get_selfm_len, dissect_selfm, data);

    return length;
}

/******************************************************************************************************/
/* SEL Fast Message Dissector initialization */
/******************************************************************************************************/
static void
selfm_init(void)
{
    reassembly_table_init(&selfm_reassembly_table,
                          &addresses_reassembly_table_functions);
}

static void
selfm_cleanup(void)
{
    reassembly_table_destroy(&selfm_reassembly_table);
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
        { &hf_selfm_padbyte,
        { "Pad Byte", "selfm.padbyte", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_checksum,
        { "Checksum", "selfm.checksum", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
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
        { &hf_selfm_fmconfig_cblk_rot,
        { "Rotation", "selfm.fmconfig.cblk_rot", FT_UINT8, BASE_HEX, VALS(selfm_fmconfig_cblk_rot_vals), 0x01, NULL, HFILL }},
        { &hf_selfm_fmconfig_cblk_vconn,
        { "Voltage Connection", "selfm.fmconfig.cblk_vconn", FT_UINT8, BASE_HEX, VALS(selfm_fmconfig_cblk_vconn_vals), 0x06, NULL, HFILL }},
        { &hf_selfm_fmconfig_cblk_iconn,
        { "Current Connection", "selfm.fmconfig.cblk_iconn", FT_UINT8, BASE_HEX, VALS(selfm_fmconfig_cblk_iconn_vals), 0x18, NULL, HFILL }},
        { &hf_selfm_fmconfig_cblk_ctype,
        { "Calculation Type", "selfm.fmconfig.cblk_ctype", FT_UINT8, BASE_DEC, VALS(selfm_fmconfig_cblk_ctype_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_cblk_deskew_ofs,
        { "Skew Correction Offset", "selfm.fmconfig.cblk_deskew_ofs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_cblk_rs_ofs,
        { "Rs Offset", "selfm.fmconfig.cblk_rs_ofs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_cblk_xs_ofs,
        { "Xs Offset", "selfm.fmconfig.cblk_xs_ofs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_cblk_ia_idx,
        { "Analog Record Ia Index Position", "selfm.fmconfig.cblk_ia_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_cblk_ib_idx,
        { "Analog Record Ib Index Position", "selfm.fmconfig.cblk_ib_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_cblk_ic_idx,
        { "Analog Record Ic Index Position", "selfm.fmconfig.cblk_ic_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_cblk_va_idx,
        { "Analog Record Va/Vab Index Position", "selfm.fmconfig.cblk_va_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_cblk_vb_idx,
        { "Analog Record Vb/Vbc Index Position", "selfm.fmconfig.cblk_vb_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_cblk_vc_idx,
        { "Analog Record Vc/Vca Index Position", "selfm.fmconfig.cblk_vc_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmconfig_ai_sf_float,
        { "AI Scale Factor (float)", "selfm.fmconfig.ai_sf_float", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
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
        { "Breaker Bit Open Command", "selfm.foconfig.brkr_open", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &selfm_fo_br_vals_ext, 0x0, NULL, HFILL }},
        { &hf_selfm_foconfig_brkr_close,
        { "Breaker Bit Close Command", "selfm.foconfig.brkr_close", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &selfm_fo_br_vals_ext, 0x0, NULL, HFILL }},
        { &hf_selfm_foconfig_rb_cmd,
        { "Remote Bit Command", "selfm.foconfig.rb_cmd", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &selfm_fo_rb_vals_ext, 0x0, NULL, HFILL }},
        /* "Alternate Fast Operate Configuration" specific fields */
        { &hf_selfm_alt_foconfig_len,
        { "Length", "selfm.alt_foconfig.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_alt_foconfig_num_ports,
        { "Number of Ports Available", "selfm.alt_foconfig.num_ports", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_alt_foconfig_num_brkr,
        { "Number of Breaker Bits per Port", "selfm.alt_foconfig.num_brkr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_alt_foconfig_num_rb,
        { "Number of Remote Bits per Port", "selfm.alt_foconfig.num_rb", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_alt_foconfig_funccode,
        { "Supported Function Code", "selfm.alt_foconfig.funccode", FT_UINT8, BASE_HEX, VALS(selfm_foconfig_alt_funccode_vals), 0x0, NULL, HFILL }},
        /* "Fast Operate Command" specific fields */
        { &hf_selfm_fastop_len,
        { "Length", "selfm.fastop.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastop_rb_code,
        { "Remote Bit Operate Code", "selfm.fastop.rb_code", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &selfm_fo_rb_vals_ext, 0x0, NULL, HFILL }},
        { &hf_selfm_fastop_br_code,
        { "Breaker Bit Operate Code", "selfm.fastop.br_code", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &selfm_fo_br_vals_ext, 0x0, NULL, HFILL }},
        { &hf_selfm_fastop_valid,
        { "Operate Code Validation", "selfm.fastop.valid", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        /* "Alternate Fast Operate Command" specific fields */
        { &hf_selfm_alt_fastop_len,
        { "Length", "selfm.alt_fastop.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_alt_fastop_code,
        { "Operate Code", "selfm.alt_fastop.code", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_alt_fastop_valid,
        { "Operate Code Validation", "selfm.alt_fastop.valid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        /* "Fast Message" specific fields */
        { &hf_selfm_fastmsg_len,
        { "Length", "selfm.fastmsg.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_routing_addr,
        { "Routing Address (future)", "selfm.fastmsg.routing_addr", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_status,
        { "Status Byte", "selfm.fastmsg.status", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_funccode,
        { "Function Code", "selfm.fastmsg.funccode", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &selfm_fastmsg_func_code_vals_ext, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_seq,
        { "Sequence Byte", "selfm.fastmsg.seq", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_seq_fir,
        { "FIR", "selfm.fastmsg.seq_fir", FT_BOOLEAN, 8, NULL, FAST_MSG_SEQ_FIR, NULL, HFILL }},
        { &hf_selfm_fastmsg_seq_fin,
        { "FIN", "selfm.fastmsg.seq_fin", FT_BOOLEAN, 8, NULL, FAST_MSG_SEQ_FIN, NULL, HFILL }},
        { &hf_selfm_fastmsg_seq_cnt,
        { "Count", "selfm.fastmsg.seq_cnt", FT_UINT8, BASE_DEC, NULL, FAST_MSG_SEQ_CNT, "Frame Count Number", HFILL }},
        { &hf_selfm_fastmsg_resp_num,
        { "Response Number", "selfm.fastmsg.resp_num", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_crc16,
        { "CRC-16", "selfm.fastmsg.crc16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_def_route_sup,
        { "Routing Support", "selfm.fastmsg.def_route_sup", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_def_rx_stat,
        { "Status RX", "selfm.fastmsg.def_rx_stat", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_def_tx_stat,
        { "Status TX", "selfm.fastmsg.def_tx_stat", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_def_rx_maxfr,
        { "Max Frames RX", "selfm.fastmsg.def_rx_maxfr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_def_tx_maxfr,
        { "Max Frames TX", "selfm.fastmsg.def_tx_maxfr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_def_rx_num_fc,
        { "Number of Supported RX Function Codes", "selfm.fastmsg.def_rx_num_fc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_def_rx_fc,
        { "Receive Function Code", "selfm.fastmsg.def_rx_fc", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &selfm_fastmsg_func_code_vals_ext, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_def_tx_num_fc,
        { "Number of Supported TX Function Codes", "selfm.fastmsg.def_tx_num_fc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_def_tx_fc,
        { "Transmit Function Code", "selfm.fastmsg.def_tx_fc", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &selfm_fastmsg_func_code_vals_ext, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_uns_en_fc,
        { "Function Code to Enable", "selfm.fastmsg.uns_en_fc", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &selfm_fastmsg_func_code_vals_ext, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_uns_en_fc_data,
        { "Function Code Data", "selfm.fastmsg.uns_en_fc_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_uns_dis_fc,
        { "Function Code to Disable", "selfm.fastmsg.uns_dis_fc", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &selfm_fastmsg_func_code_vals_ext, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_uns_dis_fc_data,
        { "Function Code Data", "selfm.fastmsg.uns_dis_fc_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unsresp_orig,
        { "Origination path", "selfm.fastmsg.unsresp_orig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unsresp_doy,
        { "Day of Year", "selfm.fastmsg.unsresp_doy", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unsresp_year,
        { "Year", "selfm.fastmsg.unsresp_year", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unsresp_todms,
        { "Time of Day (in ms)", "selfm.fastmsg.unsresp_todms", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unsresp_num_elmt,
        { "Number of SER Elements", "selfm.fastmsg.unsresp_num_elmt", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unsresp_elmt_idx,
        { "SER Element Index", "selfm.fastmsg.unsresp_elmt_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unsresp_elmt_ts_ofs,
        { "SER Element Timestamp Offset (us)", "selfm.fastmsg.unsresp_elmt_ts_ofs", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unsresp_elmt_status,
        { "SER Element Status", "selfm.fastmsg.unsresp_elmt_status", FT_UINT8, BASE_DEC, VALS(selfm_ser_status_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unsresp_eor,
        { "End of Record Indicator", "selfm.fastmsg.unsresp_eor", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unsresp_elmt_statword,
        { "SER Element Status Word", "selfm.fastmsg.unsresp_elmt_statword", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unswrite_addr1,
        { "Write Address Region #1", "selfm.fastmsg.unswrite_addr1", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &selfm_fastmsg_unswrite_com_vals_ext, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unswrite_addr2,
        { "Write Address Region #2", "selfm.fastmsg.unswrite_addr2", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unswrite_num_reg,
        { "Number of Registers", "selfm.fastmsg.unswrite_num_reg", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unswrite_reg_val,
        { "Register Value", "selfm.fastmsg.unswrite_reg_val", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_baseaddr,
        { "Base Address", "selfm.fastmsg.baseaddr", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_numwords,
        { "Number of 16-bit Words", "selfm.fastmsg.numwords", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_flags,
        { "Flag Word", "selfm.fastmsg.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_datafmt_resp_numitem,
        { "Number of Data Items Records", "selfm.fastmsg.datafmt_resp_numitem", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_dataitem_qty,
        { "Data Item Quantity", "selfm.fastmsg.dataitem_qty", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_dataitem_type,
        { "Data Item Type", "selfm.fastmsg.dataitem_type", FT_UINT16, BASE_HEX, VALS(selfm_fastmsg_tagtype_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_dataitem_uint16,
        { "(uint16)", "selfm.fastmsg.dataitem_uint16", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_dataitem_int16,
        { "(int16)", "selfm.fastmsg.dataitem_int16", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_dataitem_uint32,
        { "(uint32)", "selfm.fastmsg.dataitem_uint32", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_dataitem_int32,
        { "(int32)", "selfm.fastmsg.dataitem_int32", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_dataitem_float,
        { "(float)", "selfm.fastmsg.dataitem_float", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_devdesc_num_region,
        { "Number of Data Regions", "selfm.fastmsg.devdesc_num_region", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_devdesc_num_ctrl,
        { "Number of Control Regions", "selfm.fastmsg.devdesc_num_ctrl", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_soe_req_orig,
        { "Origination path", "selfm.fastmsg.soe_req_orig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_soe_resp_numblks,
        { "Number of Blocks", "selfm.fastmsg.soe_resp_numblks", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_soe_resp_orig,
        { "Origination path", "selfm.fastmsg.soe_resp_orig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_soe_resp_numbits,
        { "Number of Bits", "selfm.fastmsg.soe_resp_numbits", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_soe_resp_pad,
        { "Pad Byte", "selfm.fastmsg.soe_resp_pad", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_soe_resp_doy,
        { "Day of Year", "selfm.fastmsg.soe_resp_doy", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_soe_resp_year,
        { "Year", "selfm.fastmsg.soe_resp_year", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_soe_resp_tod,
        { "Time of Day (ms)", "selfm.fastmsg.soe_resp_tod", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        /* { &hf_selfm_fastmsg_soe_resp_data,
        { "Packed Binary State Data", "selfm.fastmsg.soe_resp_data", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }}, */

        /* "Fast Message" Re-assembly header fields */
        { &hf_selfm_fragment,
        { "SEL Fast Msg Response Data Fragment", "selfm.respdata.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "SEL Fast Message Response Data Fragment", HFILL }},
        { &hf_selfm_fragments,
        { "SEL Fast Msg Response Data Fragments", "selfm.respdata.fragments", FT_NONE, BASE_NONE, NULL, 0x0, "SEL Fast Message Response Data Fragments", HFILL }},
        { &hf_selfm_fragment_overlap,
        { "Fragment overlap", "selfm.respdata.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},
        { &hf_selfm_fragment_overlap_conflict,
        { "Conflicting data in fragment overlap", "selfm.respdata.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Overlapping fragments contained conflicting data", HFILL }},
        { &hf_selfm_fragment_multiple_tails,
        { "Multiple tail fragments found", "selfm.respdata.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Several tails were found when defragmenting the packet", HFILL }},
        { &hf_selfm_fragment_too_long_fragment,
        { "Fragment too long", "selfm.respdata.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Fragment contained data past end of packet", HFILL }},
        { &hf_selfm_fragment_error,
        { "Defragmentation error", "selfm.respdata.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},
        { &hf_selfm_fragment_count,
        { "Fragment count", "selfm.respdata.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fragment_reassembled_in,
        { "Reassembled PDU In Frame", "selfm.respdata.fragment.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "This PDU is reassembled in this frame", HFILL }},
        { &hf_selfm_fragment_reassembled_length,
        { "Reassembled SEL Fast Msg length", "selfm.respdata.fragment.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0, "The total length of the reassembled payload", HFILL }},
        /* Generated from convert_proto_tree_add_text.pl */
        { &hf_selfm_fmconfig_ai_channel, { "Analog Channel Name", "selfm.fmconfig.ai_channel", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmdata_ai_value16, { "Value (Raw)", "selfm.fmdata.ai.value16", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmdata_ai_scale_factor, { "Value (w/ Scale Factor)", "selfm.fmdata.ai.value_scale_factor", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmdata_ai_value_float, { "Value", "selfm.fmdata.ai.value_float", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmdata_ai_value_double, { "Value", "selfm.fmdata.ai.value_double", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmdata_data_type, { "Data_Type", "selfm.fmdata.data_type", FT_UINT32, BASE_DEC, VALS(selfm_fastmsg_tagtype_vals), 0x0, NULL, HFILL }},
        { &hf_selfm_fmdata_quantity, { "Quantity", "selfm.fmdata.quantity", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmdata_ai_value_string, { "Value", "selfm.fmdata.ai.value_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_unsresp_elmt_ts_ofs_decoded, { "SER Element Timestamp Offset (decoded)", "selfm.fastmsg.unsresp_elmt_ts_ofs.decoded", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fid, { "FID", "selfm.fid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_rid, { "RID", "selfm.rid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_data_region_name, { "Data Region Name", "selfm.fastmsg.data_region_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmdata_timestamp, { "Timestamp", "selfm.fmdata.timestamp", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fmdata_frame_data_format_reference, { "Frame Data Format Reference", "selfm.fmdata.frame_data_format_reference", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_selfm_fastmsg_bit_label_name, { "Bit Label Name", "selfm.fastmsg.bit_label_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    /* Register expert fields */
    static ei_register_info selfm_ei[] = {
        { &ei_selfm_crc16_incorrect, { "selfm.crc16.incorrect", PI_CHECKSUM, PI_WARN, "Incorrect CRC", EXPFILL }}
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
        &ett_selfm_fmconfig_calc,
        &ett_selfm_foconfig,
        &ett_selfm_foconfig_brkr,
        &ett_selfm_foconfig_rb,
        &ett_selfm_fastop,
        &ett_selfm_fmdata,
        &ett_selfm_fmdata_ai,
        &ett_selfm_fmdata_dig,
        &ett_selfm_fmdata_ai_ch,
        &ett_selfm_fmdata_dig_ch,
        &ett_selfm_fastmsg,
        &ett_selfm_fastmsg_seq,
        &ett_selfm_fastmsg_def_fc,
        &ett_selfm_fastmsg_tag,
        &ett_selfm_fastmsg_element_list,
        &ett_selfm_fastmsg_element,
        &ett_selfm_fastmsg_datareg,
        &ett_selfm_fragment,
        &ett_selfm_fragments

   };

    module_t *selfm_module;
    expert_module_t* expert_selfm;

    /* Register protocol init routine */
    register_init_routine(&selfm_init);
    register_cleanup_routine(&selfm_cleanup);

    /* Register the protocol name and description */
    proto_selfm = proto_register_protocol("SEL Protocol", "SEL Protocol", "selfm");

    /* Registering protocol to be called by another dissector */
    selfm_handle = register_dissector("selfm", dissect_selfm_tcp, proto_selfm);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_selfm, selfm_hf, array_length(selfm_hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_selfm = expert_register_protocol(proto_selfm);
    expert_register_field_array(expert_selfm, selfm_ei, array_length(selfm_ei));


    /* Register required preferences for SEL Protocol register decoding */
    selfm_module = prefs_register_protocol(proto_selfm, proto_reg_handoff_selfm);

    /*  SEL Protocol - Desegmentmentation; defaults to TRUE for TCP desegmentation*/
    prefs_register_bool_preference(selfm_module, "desegment",
                                  "Desegment packets spanning multiple TCP segments",
                                  "Whether the SEL Protocol dissector should desegment all messages spanning multiple TCP segments",
                                  &selfm_desegment);

    /* SEL Protocol - Telnet protocol IAC (0xFF) processing; defaults to TRUE to allow Telnet Encapsulated Data */
    prefs_register_bool_preference(selfm_module, "telnetclean",
                                  "Remove extra 0xFF (Telnet IAC) bytes",
                                  "Whether the SEL Protocol dissector should automatically pre-process Telnet data to remove duplicate 0xFF IAC bytes",
                                  &selfm_telnet_clean);

    /* SEL Protocol Preference - Default TCP Port, allows for "user" port either than 0. */
    prefs_register_uint_preference(selfm_module, "tcp.port", "SEL Protocol Port",
                       "Set the TCP port for SEL FM Protocol packets (if other than the default of 0)",
                       10, &global_selfm_tcp_port);

    /* SEL Protocol Preference - Disable/Enable CRC verification, */
    prefs_register_bool_preference(selfm_module, "crc_verification", "Validate Fast Message CRC16",
                                  "Perform CRC16 validation on Fast Messages",
                                  &selfm_crc16);

    prefs_register_string_preference(selfm_module, "ser_list",
                                   "SER Index List", "List of word bits contained in SER equations (Comma-separated, no Quotes or Checksums)", &selfm_ser_list);


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
    static unsigned int selfm_port;

    /* Make sure to use SEL FM Protocol Preferences field to determine default TCP port */
    if (! selfm_prefs_initialized) {
        selfm_prefs_initialized = TRUE;
    }
    else {
        dissector_delete_uint("tcp.port", selfm_port, selfm_handle);
    }

    selfm_port = global_selfm_tcp_port;

    dissector_add_uint("tcp.port", selfm_port, selfm_handle);
    dissector_add_for_decode_as("rtacser.data", selfm_handle);
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
