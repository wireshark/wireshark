/* packet-mux27010.c
 * Dissects a variant of 3GPP TS 27.010 multiplexing protocol
 * Copyright 2011, Hans-Christoph Schemmel <hans-christoph.schemmel[AT]cinterion.com>
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

#include <glib.h>

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/reassemble.h>
#include <epan/crc8-tvb.h>
#include <expert.h>

void proto_register_mux27010(void);
void proto_reg_handoff_mux27010(void);

#define PROTO_TAG_MUX27010  "MUX27010"

/*Extended Header*/
#define MUX27010_EXTENDED_HEADER_NOT_ENDED      0x01

/*Address flags*/
#define MUX27010_DLCI_ADDRESS_FLAG  0xFC
#define MUX27010_EA_ADDRESS_FLAG    0x01
#define MUX27010_CR_ADDRESS_FLAG    0x02

/*Control flags*/
#define MUX27010_FRAMETYPE_CONTROL_FLAG         0xEF
#define MUX27010_FRAMETYPE_CONTROL_FLAG_SABM    0x2F
#define MUX27010_FRAMETYPE_CONTROL_FLAG_UA      0x63
#define MUX27010_FRAMETYPE_CONTROL_FLAG_DM      0x0F
#define MUX27010_FRAMETYPE_CONTROL_FLAG_DISC    0x43
#define MUX27010_FRAMETYPE_CONTROL_FLAG_UIH     0xEF
#define MUX27010_PF_CONTROL_FLAG                0x10
#define MUX27010_FRAMETYPE_CONTROL_FLAG_UIH_E   0x00
#define MUX27010_FRAMETYPE_CONTROL_FLAG_RR      0x01
#define MUX27010_FRAMETYPE_CONTROL_FLAG_RNR     0x05
#define MUX27010_FRAMETYPE_CONTROL_FLAG_REJ     0x09
#define MUX27010_FRAMETYPE_CONTROL_FLAG_NS      0x0E
#define MUX27010_FRAMETYPE_CONTROL_FLAG_NR      0xE0
#define MUX27010_FRAMETYPE_CONTROL_FLAG_NOT_GREATER_THEN_7      0x07


/*Length*/
#define MUX27010_EA_LENGTH_FLAG             0x01
#define MUX27010_FRAMESIZE_LENGTH_FLAG      0xFE
#define MUX27010_FRAMESIZE_LENGTH_FLAG_EA   0xFFFE

/*Control Channel*/
#define MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG       0x01
#define MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG       0x02
#define MUX27010_COMMAND_CONTROLCHANNEL_FRAMETYPE_FLAG  0xFC
#define MUX27010_EA_CONTROLCHANNEL_LENGTH_FLAG          0x01
#define MUX27010_LENGTHFIELD_CONTROLCHANNEL_LENGTH_FLAG 0xFE
#define MUX27010_VALUE_CONTROLCHANNEL_TEST_VERSION      0xFF
#define MUX27010_VALUE_CONTROLCHANNEL_TEST_IEI_TE       0x04
#define MUX27010_VALUE_CONTROLCHANNEL_TEST_IEI_MS       0x08
#define MUX27010_VALUE_CONTROLCHANNEL_MSC_DCLI          0xFC
#define MUX27010_VALUE_CONTROLCHANNEL_MSC_V24_FC        0x02
#define MUX27010_VALUE_CONTROLCHANNEL_MSC_V24_RTC       0x04
#define MUX27010_VALUE_CONTROLCHANNEL_MSC_V24_RTR       0x08
#define MUX27010_VALUE_CONTROLCHANNEL_MSC_V24_RING      0x40
#define MUX27010_VALUE_CONTROLCHANNEL_MSC_V24_DCD       0x80
#define MUX27010_VALUE_CONTROLCHANNEL_PN_DLCI           0x3F
#define MUX27010_VALUE_CONTROLCHANNEL_PN_FRAMETYPE      0x0F
#define MUX27010_VALUE_CONTROLCHANNEL_PN_CL             0xF0
#define MUX27010_VALUE_CONTROLCHANNEL_PN_PRIO           0x3F
#define MUX27010_VALUE_CONTROLCHANNEL_PN_WINSIZE        0x07

/*Command pattern - set C/R bit to 1*/
#define MUX27010_COMMAND_MULTIPLEXER_CLOSEDOWN  0xC3                /*11000011*/
#define MUX27010_COMMAND_TEST_COMMAND           0x23                /*00100011*/
#define MUX27010_COMMAND_POWER_SAVING_CONTROL   0x43                /*01000011*/
#define MUX27010_COMMAND_NON_SUPPORTED_COMMAND_RESPONSE     0x13    /*00010011*/
#define MUX27010_COMMAND_MODEM_STATUS_COMMAND   0xE3                /*00010011*/
#define MUX27010_COMMAND_PARAMETER_NEGOTIATION  0x83                /*10000011*/


/* Wireshark ID of the MUX27010 protocol */
static int proto_mux27010 = -1;

/* Handles of subdissectors */
static dissector_handle_t ppp_handle;

#if 0
static const value_string packettypenames[] = {
    { 0, "TEXT" },
    { 1, "SOMETHING_ELSE" },
    { 0, NULL }
};
#endif

static const value_string direction_vals[] = {
    { 0, "Direction: Application => Module" },
    { 1, "Module => Application" },
    { 2, "Not valid" },
    { 3, "Not valid" },
    { 0, NULL }
};

static const value_string detailedvalue_response_vals[] = {
    { 0, "Failure" },
    { 1, "Success" },
    { 0, NULL }
};

static const value_string frame_type_vals[] = {
    { MUX27010_FRAMETYPE_CONTROL_FLAG_SABM, "SABM" },
    { MUX27010_FRAMETYPE_CONTROL_FLAG_UA, "UA" },
    { MUX27010_FRAMETYPE_CONTROL_FLAG_DM, "DM" },
    { MUX27010_FRAMETYPE_CONTROL_FLAG_DISC, "DISC" },
    { MUX27010_FRAMETYPE_CONTROL_FLAG_UIH, "UIH" },
    { MUX27010_FRAMETYPE_CONTROL_FLAG_UIH_E, "UIH_E" },
    { MUX27010_FRAMETYPE_CONTROL_FLAG_RR, "Receive Ready" },
    { MUX27010_FRAMETYPE_CONTROL_FLAG_RNR, "Receive Not Ready" },
    { MUX27010_FRAMETYPE_CONTROL_FLAG_REJ, "Reject" },
    { 0, NULL }
};

static const value_string command_vals[] = {
    { (MUX27010_COMMAND_MULTIPLEXER_CLOSEDOWN>>2), "Multiplexer Close Down" },
    { (MUX27010_COMMAND_TEST_COMMAND>>2), "Test Command" },
    { (MUX27010_COMMAND_POWER_SAVING_CONTROL>>2), "Power Saving Control" },
    { (MUX27010_COMMAND_NON_SUPPORTED_COMMAND_RESPONSE>>2), "Non-supported Command Response" },
    { (MUX27010_COMMAND_MODEM_STATUS_COMMAND>>2), "Modem Status Command" },
    { (MUX27010_COMMAND_PARAMETER_NEGOTIATION>>2), "Parameter Negotiation" },
    { 0, NULL }
};

static const value_string iei_coding_vals[] = {
    { MUX27010_VALUE_CONTROLCHANNEL_TEST_IEI_TE, "TEMUX_VERSION" },
    { MUX27010_VALUE_CONTROLCHANNEL_TEST_IEI_MS, "MSMUX_VERSION" },
    { 0, NULL }
};

/*Control channel*/
struct controlchannel_type
{
    guint8 cr;
    guint8 command;
    gint number_of_type_frames;
};

struct controlchannel
{
    guint8 length_value;
    gint number_of_length_frames;
};

/* The following hf_* variables are used to hold the Wireshark IDs of
* the header fields; they are filled out when call
* proto_register_field_array() in proto_register_mux27010()
*/

static gint hf_mux27010_extended_header = -1;
static gint hf_mux27010_direction = -1;
static gint hf_mux27010 = -1;
static gint hf_mux27010_address = -1;
static gint hf_mux27010_control = -1;
static gint hf_mux27010_length = -1;
static gint hf_mux27010_controlchannel = -1;

/*Extended Header*/
static int hf_mux27010_extended_header_size = -1;
static int hf_mux27010_extended_header_msg_number_I = -1;
static int hf_mux27010_extended_header_freq_number_I = -1;
static int hf_mux27010_extended_header_start_pos_I = -1;
static int hf_mux27010_extended_header_start_byte_I = -1;
static int hf_mux27010_extended_header_end_pos_I = -1;
static int hf_mux27010_extended_header_end_byte_I = -1;
static int hf_mux27010_extended_header_flag_ended_I = -1;

static int hf_mux27010_extended_header_msg_number_II = -1;
static int hf_mux27010_extended_header_freq_number_II = -1;
static int hf_mux27010_extended_header_start_pos_II = -1;
static int hf_mux27010_extended_header_start_byte_II = -1;
static int hf_mux27010_extended_header_end_pos_II = -1;
static int hf_mux27010_extended_header_end_byte_II = -1;
static int hf_mux27010_extended_header_flag_ended_II = -1;

static int hf_mux27010_extended_header_msg_number_III = -1;
static int hf_mux27010_extended_header_freq_number_III = -1;
static int hf_mux27010_extended_header_start_pos_III = -1;
static int hf_mux27010_extended_header_start_byte_III = -1;
static int hf_mux27010_extended_header_end_pos_III = -1;
static int hf_mux27010_extended_header_end_byte_III = -1;
static int hf_mux27010_extended_header_flag_ended_III = -1;

/*Address*/
static int hf_mux27010_dlciaddressflag = -1;
static int hf_mux27010_eaaddressflag = -1;
static int hf_mux27010_craddressflag = -1;
/* static int hf_mux27010_addressdirection = -1; */
/*Control*/
static int hf_mux27010_controlframetype = -1;
static int hf_mux27010_controlframetypens = -1;
static int hf_mux27010_controlframetypenr = -1;
static int hf_mux27010_pfcontrolflag = -1;
/*Length*/
static int hf_mux27010_ealengthflag = -1;
static int hf_mux27010_lengthframesize = -1;
static int hf_mux27010_lengthframesize_ea = -1;
/*Control channel dlci = 0*/
static int hf_mux27010_controlchannelframetype = -1;
static int hf_mux27010_controlchanneleaframetype = -1;
static int hf_mux27010_controlchannelcrframetype = -1;
static int hf_mux27010_controlchannelframetypecommand = -1;
static int hf_mux27010_controlchannellength = -1;
static int hf_mux27010_controlchannelealength = -1;
static int hf_mux27010_controlchannellengthfield = -1;
static int hf_mux27010_controlchannelvalue = -1;
static int hf_mux27010_controlchannel_iei_coding = -1;
static int hf_mux27010_controlchanneldetailedvalue = -1;
static int hf_mux27010_controlchannel_detailedvalue_response = -1;
static int hf_mux27010_controlchanneldetailedvaluetestcommandversion = -1;
static int hf_mux27010_controlchanneldetailedvaluemscdlci = -1;
/* static int hf_mux27010_controlchanneldetailedvaluemscv24 = -1; */
static int hf_mux27010_controlchanneldetailedvaluemscv24fc = -1;
static int hf_mux27010_controlchanneldetailedvaluemscv24rtc = -1;
static int hf_mux27010_controlchanneldetailedvaluemscv24rtr = -1;
static int hf_mux27010_controlchanneldetailedvaluemscv24ring = -1;
static int hf_mux27010_controlchanneldetailedvaluemscv24dcd = -1;
static int hf_mux27010_controlchanneldetailedvaluemscbreak = -1;
static int hf_mux27010_controlchanneldetailedvaluepndlci = -1;
static int hf_mux27010_controlchanneldetailedvaluepnframetype = -1;
static int hf_mux27010_controlchanneldetailedvaluepncl = -1;
static int hf_mux27010_controlchanneldetailedvaluepnprio = -1;
static int hf_mux27010_controlchanneldetailedvaluepntimer = -1;
static int hf_mux27010_controlchanneldetailedvaluepnframesize = -1;
static int hf_mux27010_controlchanneldetailedvaluepnna = -1;
static int hf_mux27010_controlchanneldetailedvaluepnwinsize = -1;
/*Information*/
static int hf_mux27010_information = -1;
static int hf_mux27010_information_str = -1;
/*Checksum*/
static int hf_mux27010_checksum = -1;
static int hf_mux27010_checksum_correct = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_mux27010_extended_header = -1;
static gint ett_mux27010 = -1;
static gint ett_mux27010_address = -1;
static gint ett_mux27010_control = -1;
static gint ett_mux27010_length = -1;
static gint ett_mux27010_controlchannel = -1;
static gint ett_mux27010_controlchannelframetype = -1;
static gint ett_mux27010_controlchannellength = -1;
static gint ett_mux27010_controlchannelvalue = -1;
static gint ett_mux27010_information = -1;
static gint ett_mux27010_checksum = -1;

static expert_field ei_mux27010_message_illogical = EI_INIT;
static expert_field ei_mux27010_checksum_incorrect = EI_INIT;

static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;

static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static dissector_handle_t mux27010_handle;

static const fragment_items msg_frag_items = {
    /* Fragment subtrees */
    &ett_msg_fragment,
    &ett_msg_fragments,
    /* Fragment fields */
    &hf_msg_fragments,
    &hf_msg_fragment,
    &hf_msg_fragment_overlap,
    &hf_msg_fragment_overlap_conflicts,
    &hf_msg_fragment_multiple_tails,
    &hf_msg_fragment_too_long_fragment,
    &hf_msg_fragment_error,
    &hf_msg_fragment_count,
    /* Reassembled in field */
    &hf_msg_reassembled_in,
    /* Reassembled length field */
    &hf_msg_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Message fragments"
    };

static reassembly_table msg_reassembly_table;



static int
getExtendedHeader(tvbuff_t *tvb, proto_tree *field_tree, int offset, guint8* sizeMuxPPPHeader){
    int i;

    *sizeMuxPPPHeader = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(field_tree, hf_mux27010_extended_header_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (*sizeMuxPPPHeader > 0){
        int tmpOffset = 1;
        guint16 tmpStartByte = 0;
        guint16 tmpLastByte = 0;
        for (i=0; i < *sizeMuxPPPHeader/7; i++){
            switch(i){
                case(0) :
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_msg_number_I, tvb, offset+tmpOffset, 2, ENC_BIG_ENDIAN);
                    tmpOffset+=2;

                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_freq_number_I, tvb, offset+tmpOffset, 2, ENC_BIG_ENDIAN);
                    tmpOffset+=2;

                    tmpStartByte = tvb_get_guint8(tvb, tmpOffset) + *sizeMuxPPPHeader + 1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_start_pos_I, tvb, offset+tmpOffset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_start_byte_I, tvb, tmpStartByte, 1, ENC_BIG_ENDIAN);
                    tmpOffset+=1;

                    tmpLastByte = tvb_get_guint8(tvb, tmpOffset) + *sizeMuxPPPHeader + 1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_end_pos_I, tvb, offset+tmpOffset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_end_byte_I, tvb, tmpLastByte, 1, ENC_BIG_ENDIAN);

                    tmpOffset+=1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_flag_ended_I, tvb, offset+tmpOffset, 1, ENC_BIG_ENDIAN);
                    if ((tvb_get_guint8(tvb, tmpOffset) & MUX27010_EXTENDED_HEADER_NOT_ENDED) == MUX27010_EXTENDED_HEADER_NOT_ENDED)
                        proto_tree_add_uint_format(field_tree, hf_mux27010_extended_header_flag_ended_I, tvb, offset+tmpOffset, 1, 1, "Not Last Packet in Frequence");
                    else
                        proto_tree_add_uint_format(field_tree, hf_mux27010_extended_header_flag_ended_I, tvb, offset+tmpOffset, 1, 1, "Last Packet in Frequence");
                    break;

                case(1) :
                    tmpOffset+=1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_msg_number_II, tvb, offset+tmpOffset, 2, ENC_BIG_ENDIAN);
                    tmpOffset+=2;

                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_freq_number_II, tvb, offset+tmpOffset, 2, ENC_BIG_ENDIAN);
                    tmpOffset+=2;

                    tmpStartByte = tvb_get_guint8(tvb, tmpOffset) + *sizeMuxPPPHeader + 1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_start_pos_II, tvb, offset+tmpOffset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_start_byte_II, tvb, tmpStartByte, 1, ENC_BIG_ENDIAN);
                    tmpOffset+=1;

                    tmpLastByte = tvb_get_guint8(tvb, tmpOffset) + *sizeMuxPPPHeader + 1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_end_pos_II, tvb, offset+tmpOffset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_end_byte_II, tvb, tmpLastByte, 1, ENC_BIG_ENDIAN);

                    tmpOffset+=1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_flag_ended_II, tvb, offset+tmpOffset, 1, ENC_BIG_ENDIAN);
                    if ((tvb_get_guint8(tvb, tmpOffset) & MUX27010_EXTENDED_HEADER_NOT_ENDED) == MUX27010_EXTENDED_HEADER_NOT_ENDED)
                        proto_tree_add_uint_format(field_tree, hf_mux27010_extended_header_flag_ended_II, tvb, offset+tmpOffset, 1, 1, "Not Last Packet in Frequence");
                    else
                        proto_tree_add_uint_format(field_tree, hf_mux27010_extended_header_flag_ended_II, tvb, offset+tmpOffset, 1, 1, "Last Packet in Frequence");
                    break;

                case(2) :
                    tmpOffset+=1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_msg_number_III, tvb, offset+tmpOffset, 2, ENC_BIG_ENDIAN);
                    tmpOffset+=2;

                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_freq_number_III, tvb, offset+tmpOffset, 2, ENC_BIG_ENDIAN);
                    tmpOffset+=2;

                    tmpStartByte = tvb_get_guint8(tvb, tmpOffset) + *sizeMuxPPPHeader + 1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_start_pos_III, tvb, offset+tmpOffset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_start_byte_III, tvb, tmpStartByte, 1, ENC_BIG_ENDIAN);
                    tmpOffset+=1;

                    tmpLastByte = tvb_get_guint8(tvb, tmpOffset) + *sizeMuxPPPHeader + 1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_end_pos_III, tvb, offset+tmpOffset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_end_byte_III, tvb, tmpLastByte, 1, ENC_BIG_ENDIAN);

                    tmpOffset+=1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_flag_ended_III, tvb, offset+tmpOffset, 1, ENC_BIG_ENDIAN);
                    if ((tvb_get_guint8(tvb, tmpOffset) & MUX27010_EXTENDED_HEADER_NOT_ENDED) == MUX27010_EXTENDED_HEADER_NOT_ENDED)
                        proto_tree_add_uint_format(field_tree, hf_mux27010_extended_header_flag_ended_III, tvb, offset+tmpOffset, 1, 1, "Not Last Packet in Frequence");
                    else
                        proto_tree_add_uint_format(field_tree, hf_mux27010_extended_header_flag_ended_III, tvb, offset+tmpOffset, 1, 1, "Last Packet in Frequence");
                    break;
            }

        }

    }

    return *sizeMuxPPPHeader;
}


/*Get the direction of the actual packet*/
static int
getFrameDirection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *field_tree, int offset){
    guint8 direction_in_out;

    /*Direction is coded in the first byte of the frame*/
    direction_in_out = tvb_get_guint8(tvb, offset);

    /*If first byte is 0 => Frame source is Application*/
    /*If first byte is 1 => Frame source is Module*/
    /*else Error*/
    proto_tree_add_uint(field_tree, hf_mux27010_direction, tvb, offset, 1, direction_in_out & 3);
    switch (direction_in_out & 3) {
        case (0):/*Application >> Module*/
            col_set_str(pinfo->cinfo, COL_DEF_SRC, "Application  DLCI ");
            col_set_str(pinfo->cinfo, COL_DEF_DST, "Module");
            break;
        case (1):/*Module >> Application*/
            col_set_str(pinfo->cinfo, COL_DEF_SRC, "Module       DLCI ");
            col_set_str(pinfo->cinfo, COL_DEF_DST, "Application");
            break;
        default:/*?? >> ??*/
            col_set_str(pinfo->cinfo, COL_DEF_SRC, "Direction not valid ");
            col_set_str(pinfo->cinfo, COL_DEF_DST, "Direction not valid ");
            break;
    }

    return 1;
}



/*Get the address of the actual frame*/
static int
getFrameAddress(tvbuff_t *tvb, packet_info *pinfo, proto_tree *field_tree_addr, int offset, guint8* dlci_number){
    guint8 byte;

    byte = tvb_get_guint8(tvb, offset);
    /*Get the DCLI number of the frame >> overwrite other bits (E/A, CR) >> shift*/
    *dlci_number = (byte & MUX27010_DLCI_ADDRESS_FLAG) >> 2;

    /*Add text to string for Source column*/
    col_append_fstr(pinfo->cinfo, COL_DEF_SRC, "%d ", *dlci_number);

    /*Add items to subtree to display the details*/
    proto_tree_add_item(field_tree_addr, hf_mux27010_eaaddressflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree_addr, hf_mux27010_craddressflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree_addr, hf_mux27010_dlciaddressflag, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}



/*Get frame data from control field*/
static int
getFrameControlData(tvbuff_t *tvb, packet_info *pinfo, proto_tree *field_tree, int offset, guint8* frame_type){
    /*if the frame type is known -> 1 else 0*/
    guint8 known_frame_type = 0;

    /*Get the type of frame*/
    *frame_type = tvb_get_guint8(tvb, offset) & MUX27010_FRAMETYPE_CONTROL_FLAG;

    /*Find out the frame type and write info into column*/
    switch (*frame_type) {
        case (MUX27010_FRAMETYPE_CONTROL_FLAG_SABM): /*SABM frame*/
        case (MUX27010_FRAMETYPE_CONTROL_FLAG_UA): /*UA frame*/
        case (MUX27010_FRAMETYPE_CONTROL_FLAG_DM): /*DM frame*/
        case (MUX27010_FRAMETYPE_CONTROL_FLAG_DISC): /*DISC frame*/
        case (MUX27010_FRAMETYPE_CONTROL_FLAG_UIH): /*UIH frame*/
            proto_tree_add_uint(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, *frame_type);
            break;

        default:
            /*Got another frame -> probably a UIH_E, RR, RNR or REJ frame from a DLCI channel != 0 ==> Data channel*/

            /*Check if frame is a UIH_E frame*/
            if ((MUX27010_FRAMETYPE_CONTROL_FLAG_UIH_E | MUX27010_FRAMETYPE_CONTROL_FLAG_NS | MUX27010_FRAMETYPE_CONTROL_FLAG_NR) == (*frame_type | MUX27010_FRAMETYPE_CONTROL_FLAG_NS | MUX27010_FRAMETYPE_CONTROL_FLAG_NR)) {
                *frame_type = MUX27010_FRAMETYPE_CONTROL_FLAG_UIH_E;
                /*Add frame type to column*/
                proto_tree_add_uint(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_UIH_E);
                /*Add info about sequence numbers to column*/
                proto_tree_add_item(field_tree, hf_mux27010_controlframetypens, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(field_tree, hf_mux27010_controlframetypenr, tvb, offset, 1, ENC_BIG_ENDIAN);

                /*Frame type is known*/
                known_frame_type = 1;
            }
            /*Check if frame is a RR frame*/
            if ((MUX27010_FRAMETYPE_CONTROL_FLAG_RR | MUX27010_FRAMETYPE_CONTROL_FLAG_NR) == (*frame_type | MUX27010_FRAMETYPE_CONTROL_FLAG_NR)) {
                *frame_type = MUX27010_FRAMETYPE_CONTROL_FLAG_RR;
                /*Add frame type to column*/
                proto_tree_add_uint(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_RR);
                /*Add info about sequence number to column*/
                proto_tree_add_item(field_tree, hf_mux27010_controlframetypenr, tvb, offset, 1, ENC_BIG_ENDIAN);

                /*Frame type is known*/
                known_frame_type = 1;
            }
            if ((MUX27010_FRAMETYPE_CONTROL_FLAG_RNR | MUX27010_FRAMETYPE_CONTROL_FLAG_NR) == (*frame_type | MUX27010_FRAMETYPE_CONTROL_FLAG_NR)) {
                *frame_type = MUX27010_FRAMETYPE_CONTROL_FLAG_RNR;
                /*Add frame type to column*/
                proto_tree_add_uint(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_RNR);
                /*Add info about sequence number to column*/
                proto_tree_add_item(field_tree, hf_mux27010_controlframetypenr, tvb, offset, 1, ENC_BIG_ENDIAN);

                /*Frame type is known*/
                known_frame_type = 1;
            }
            if ((MUX27010_FRAMETYPE_CONTROL_FLAG_REJ | MUX27010_FRAMETYPE_CONTROL_FLAG_NR) == (*frame_type | MUX27010_FRAMETYPE_CONTROL_FLAG_NR)) {
                *frame_type = MUX27010_FRAMETYPE_CONTROL_FLAG_REJ;
                /*Add frame type to column*/
                proto_tree_add_uint(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_REJ);
                /*Add info about sequence number to column*/
                proto_tree_add_item(field_tree, hf_mux27010_controlframetypenr, tvb, offset, 1, ENC_BIG_ENDIAN);

                /*Frame type is known*/
                known_frame_type = 1;
            }

            /*Unknown frame*/
            if (known_frame_type == 0) {
                /*Add frame type to column*/
                proto_tree_add_uint(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, *frame_type);
            }
    }

    /*Write information to string for column info*/
    col_add_fstr(pinfo->cinfo, COL_INFO, "(%s)", val_to_str_const(*frame_type, frame_type_vals, "Unknown"));

    /*Add Frame type value and PF bit to column*/
    proto_tree_add_item(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_mux27010_pfcontrolflag, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}




/*Get frame data from length field*/
static int
getFrameLength(tvbuff_t *tvb, proto_tree *field_tree, int offset, guint16* length_info){

    /*Get the E/A bit*/
    guint8 length_ea = tvb_get_guint8(tvb, offset) & MUX27010_EA_LENGTH_FLAG;
    proto_tree_add_item(field_tree, hf_mux27010_ealengthflag, tvb, offset, 1, ENC_BIG_ENDIAN);

    /*Get the length of the info field*/

    /*If E/A = 1 it is the last octet*/
    if (length_ea == 1) {

        /*Add the E/A bit and the length value to the subtree*/
        proto_tree_add_item(field_tree, hf_mux27010_lengthframesize, tvb, offset, 1, ENC_BIG_ENDIAN);
        *length_info = (tvb_get_guint8(tvb, offset) & MUX27010_FRAMESIZE_LENGTH_FLAG) >> 1; /*Shift because of EA bit*/
        return 1;
    }

    /*If E/A = 0 the length of the info field is >127*/
    proto_tree_add_item(field_tree, hf_mux27010_lengthframesize_ea, tvb, offset, 2, ENC_BIG_ENDIAN);
    *length_info = (tvb_get_ntohs(tvb, offset) & MUX27010_FRAMESIZE_LENGTH_FLAG_EA) >> 1; /*Shift because of EA bit*/

    return 2;
}


/*Get frame type of control channel frame*/
static int
getControlChannelFrameType(tvbuff_t *tvb, packet_info *pinfo, proto_tree *field_tree_ctr, int offset,
                           struct controlchannel_type* cctype){
    guint8 controlchannel_type_ea;

    /*Get the E/A bit*/
    controlchannel_type_ea = tvb_get_guint8(tvb, offset) & MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG;

    /*Set variable for number of octets for frame type to 0*/
    cctype->number_of_type_frames = 0;
    /*If E/A bit = 1, there will be no other frame type octet*/
    if (controlchannel_type_ea == 1)
        cctype->number_of_type_frames++;

    /*If E/A = 0, read all frame type octets*/
    while (controlchannel_type_ea == 0){
        cctype->number_of_type_frames++;
        controlchannel_type_ea = tvb_get_guint8(tvb, offset+cctype->number_of_type_frames) & MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG;
    }

    /*Get CR bit*/
    cctype->cr = (tvb_get_guint8(tvb, offset) & MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG) >> 1;

    /*Get command info*/
    cctype->command = tvb_get_guint8(tvb, offset) & MUX27010_COMMAND_CONTROLCHANNEL_FRAMETYPE_FLAG;

    /*Add info to subtree*/
    proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneleaframetype, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchannelcrframetype, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchannelframetypecommand, tvb, offset, 1, ENC_BIG_ENDIAN);

    /*Check the control channel frame types and add the name to the subtree and strcat the name to the info column*/
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str_const(cctype->command>>2, command_vals, "Unknown"));

    if (cctype->cr == 1) /*Command C/R*/{
        col_append_str(pinfo->cinfo, COL_INFO, " (Command)");
    }
    else{ /*Response*/
        col_append_str(pinfo->cinfo, COL_INFO, " (Response)");
    }

    return cctype->number_of_type_frames;
}


/*Get length of control channel info field*/
static int
getControlChannelLength(tvbuff_t *tvb, proto_tree *field_tree_ctr, int offset, struct controlchannel* cc) {
    guint8 controlchannel_length_ea;

    /*Get the E/A bit*/
    controlchannel_length_ea = tvb_get_guint8(tvb, offset) & MUX27010_EA_CONTROLCHANNEL_LENGTH_FLAG;

    /*Set variable for number of octets for info field to 0*/
    cc->number_of_length_frames = 0;
    /*If E/A bit = 1, there will be no other info field length octet*/
    if (controlchannel_length_ea == 1)
        cc->number_of_length_frames++;

    /*If E/A = 0, read all length of info field octets*/
    while (controlchannel_length_ea == 0){
        cc->number_of_length_frames++;
        controlchannel_length_ea = tvb_get_guint8(tvb, offset+cc->number_of_length_frames) & MUX27010_EA_CONTROLCHANNEL_LENGTH_FLAG;
    }

    /*Get the data from info field*/
    cc->length_value = (tvb_get_guint8(tvb, offset) & MUX27010_LENGTHFIELD_CONTROLCHANNEL_LENGTH_FLAG) >> 1;

    /*Add data to subtree*/
    proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchannelealength, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchannellengthfield, tvb, offset, 1, ENC_BIG_ENDIAN);

    return cc->number_of_length_frames;
}



/*Get values of control channel*/
static int
getControlChannelValues(tvbuff_t *tvb, proto_tree *field_tree_ctr, int offset,
                        struct controlchannel* cc, struct controlchannel_type* cctype){
    guint8 controlchannel_iei;
    guint8 controlchannel_psc;

    /*Command pattern for Test Command (C/R is set to 1)*/
    switch (cctype->command | MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG | MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG)
    {
    case MUX27010_COMMAND_TEST_COMMAND:
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluetestcommandversion, tvb, offset, 1, ENC_BIG_ENDIAN);
        controlchannel_iei = tvb_get_guint8(tvb, offset);
        if ((controlchannel_iei == MUX27010_VALUE_CONTROLCHANNEL_TEST_IEI_TE) ||
            (controlchannel_iei == MUX27010_VALUE_CONTROLCHANNEL_TEST_IEI_MS)) {
            proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchannel_iei_coding, tvb, offset, 1, ENC_BIG_ENDIAN);
        }

        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchannelvalue, tvb, offset+1, cc->length_value-1, ENC_NA|ENC_ASCII);
        break;

    /*Command pattern for Power saving control (C/R is set to 1)*/
    case MUX27010_COMMAND_POWER_SAVING_CONTROL:
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvalue, tvb, offset, 1, ENC_BIG_ENDIAN);
        controlchannel_psc = tvb_get_guint8(tvb, offset);
        if (cctype->cr == 0 && controlchannel_psc == 0) /*Response Failure*/
            proto_tree_add_uint(field_tree_ctr, hf_mux27010_controlchannel_detailedvalue_response, tvb, offset, cc->length_value, 0);
        if (cctype->cr == 0 && controlchannel_psc == 1) /*Response Success*/
            proto_tree_add_uint(field_tree_ctr, hf_mux27010_controlchannel_detailedvalue_response, tvb, offset, cc->length_value, 1);
        break;

    /*Command pattern for non-supported command response (C/R is set to 1)*/
    case MUX27010_COMMAND_NON_SUPPORTED_COMMAND_RESPONSE:
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvalue, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;

    /*Command pattern for Modem Status Command (C/R is set to 1)*/
    case MUX27010_COMMAND_MODEM_STATUS_COMMAND:
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscdlci, tvb, offset, 1, ENC_BIG_ENDIAN);

        /*Add bits of Flow Control*/
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscv24fc, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscv24rtc, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscv24rtr, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscv24ring, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscv24dcd, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        /**/

        if (cc->length_value == 3) {
            proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscbreak, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        }
        break;

    /*Command pattern for Parameter Negotiation (EA + C/R is set to 1)*/
    case MUX27010_COMMAND_PARAMETER_NEGOTIATION:
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepndlci, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepnframetype, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepncl, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepnprio, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepntimer, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepnframesize, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepnna, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepnwinsize, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        break;
    }

    return cc->length_value;
}



/*Get values information field*/
static int
getFrameInformation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *field_tree,
                    int offset, guint16 length_info){

    /*Get the data from information field as string*/
    char *information_field = tvb_get_string_enc(wmem_packet_scope(), tvb,offset,length_info, ENC_ASCII);

    /*delete unneeded signs out of info field -> for info column: CR (0x0d) and LF (0x0a)*/
    information_field = g_strdelimit(information_field, "\r\n", ' ');

    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", information_field);

    /*Add info to subtree*/
    proto_tree_add_string(field_tree, hf_mux27010_information_str, tvb, offset, length_info, information_field);

    /*Increment offset by the length of chars in info field*/
    return length_info;
}




static void
dissect_mux27010(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti, *tf, *tf_extended_header, *tf_addr, *tf_ctr;
    proto_tree *mux27010_tree, *field_tree, *field_tree_extended_header, *field_tree_addr, *field_tree_ctr;
    int offset = 0;
    guint16 length_info;
    packet_info pinfo_tmp;
    /*Address DLCI*/
    gint8 dlci_number = 0;
    guint8 frame_type;
    /*private MUX frame header (PPP)*/
    guint8 sizeMuxPPPHeader;
    struct controlchannel_type cc_type;
    struct controlchannel cc;

    /* Setup columns */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_MUX27010);
    col_clear(pinfo->cinfo, COL_INFO);

    /* Set offset to 0 => start to read at the begin of the frame*/
    offset = 0;

    ti = proto_tree_add_item(tree, proto_mux27010, tvb, 0, -1, ENC_NA);
    mux27010_tree = proto_item_add_subtree(ti, ett_mux27010);

    /*Add a subtree (=item) to the child node => in this subtree the details of extended header will be displayed*/
    tf_extended_header = proto_tree_add_item(mux27010_tree, hf_mux27010_extended_header, tvb, offset, 1, ENC_BIG_ENDIAN);
    field_tree_extended_header = proto_item_add_subtree(tf_extended_header, ett_mux27010_extended_header);

    offset += getExtendedHeader(tvb, field_tree_extended_header, offset, &sizeMuxPPPHeader);
    offset++;

    /*Get direction of the frame*/
    offset += getFrameDirection(tvb, pinfo, mux27010_tree, offset);

    /*~~~~~~~~Flag~~~~~~~~*/
    /*(Insert data into the child node)*/
    /*Create item to show/highlight flag sequence*/
    proto_tree_add_item(mux27010_tree, hf_mux27010, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*~~~~~~~~/Flag~~~~~~~~*/



    /*~~~~~~~~Address~~~~~~~~*/
    /*Add a subtree (=item) to the child node => in this subtree the details of address data will be displayed*/
    tf_addr = proto_tree_add_item(mux27010_tree, hf_mux27010_address, tvb, offset, 1, ENC_BIG_ENDIAN);
    field_tree_addr = proto_item_add_subtree(tf_addr, ett_mux27010_address);

    /*Get address data (DLCI, E/A, CR)*/
    offset += getFrameAddress(tvb, pinfo, field_tree_addr, offset, &dlci_number);
    /*~~~~~~~~/Address~~~~~~~~*/



    /*~~~~~~~~Control Data~~~~~~~~*/
    /*Add a subtree (=item) to the child node => in this subtree the details of control data will be displayed*/
    tf = proto_tree_add_item(mux27010_tree, hf_mux27010_control, tvb, offset, 1, ENC_BIG_ENDIAN);
    field_tree = proto_item_add_subtree(tf, ett_mux27010_control);

    /*Get control data of frame (Frame type)*/
    offset += getFrameControlData(tvb, pinfo, field_tree, offset, &frame_type);
    /*~~~~~~~~/Control Data~~~~~~~~*/




    /*~~~~~~~~Length~~~~~~~~*/
    /*Set the variable for length of the info field to 0*/
    length_info = 0;

    /*Check the frame type because in RR, RNR and REJ are no info and no lenght fields*/
    if ((frame_type != MUX27010_FRAMETYPE_CONTROL_FLAG_RR) && (frame_type != MUX27010_FRAMETYPE_CONTROL_FLAG_RNR) &&
        (frame_type != MUX27010_FRAMETYPE_CONTROL_FLAG_REJ)){
        /*Add a subtree (=item) to the child node => in this subtree will be the details of length field*/
        tf = proto_tree_add_item(mux27010_tree, hf_mux27010_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        field_tree = proto_item_add_subtree(tf, ett_mux27010_length);

        /*Get frame length data*/
        offset += getFrameLength(tvb, field_tree, offset, &length_info);
    }
    /*~~~~~~~~/Length~~~~~~~~*/



    /*~~~~~~~~Control Channel~~~~~~~~*/
    /*Control Channel only exists if DLCI = 0*/
    if (dlci_number == 0) {

        /*If length field > 0, otherwise the frame has no data*/
        if (length_info > 0) {

            /*--------Frame Type--------*/
            /*Get and display data of frame type*/

            /*Add a subtree (=item) to the child node => in this subtree the details of control channel will be displayed*/
            tf = proto_tree_add_item(mux27010_tree, hf_mux27010_controlchannel, tvb, offset, 1, ENC_BIG_ENDIAN);
            field_tree = proto_item_add_subtree(tf, ett_mux27010_controlchannel);

            /*Add another subtree to the control channel subtree => in this subtree the details of control channel frame type will be displayed*/
            tf_ctr = proto_tree_add_item(field_tree, hf_mux27010_controlchannelframetype, tvb, offset, 1, ENC_BIG_ENDIAN);
            field_tree_ctr = proto_item_add_subtree(tf_ctr, ett_mux27010_controlchannelframetype);

            /*Get data about the type of the frame*/
            offset += getControlChannelFrameType(tvb, pinfo, field_tree_ctr, offset, &cc_type);
            proto_item_set_len(tf_ctr, cc_type.number_of_type_frames);
            /*--------/Frame Type--------*/


            /*--------Length Field--------*/
            /*Add another subtree to the control channel subtree => in this subtree the details of control channel length field will be displayed*/
            tf_ctr = proto_tree_add_item(field_tree, hf_mux27010_controlchannellength, tvb, offset, 1, ENC_BIG_ENDIAN);
            field_tree_ctr = proto_item_add_subtree(tf_ctr, ett_mux27010_controlchannellength);

            /*Get data of length field*/
            offset += getControlChannelLength(tvb, field_tree_ctr, offset, &cc);
            proto_item_set_len(tf_ctr, cc.number_of_length_frames);
            /*--------/Length Field--------*/


            /*--------Values--------*/
            /*If frame has data inside the length_value is > 0*/
            if (cc.length_value > 0) {
                /*Add another subtree to the control channel subtree => in this subtree the details of control channel values/data will be displayed*/
                tf_ctr = proto_tree_add_text(field_tree, tvb, offset, cc.length_value, "Data: %i Byte(s)", cc.length_value);
                field_tree_ctr = proto_item_add_subtree(tf_ctr, ett_mux27010_controlchannelvalue);

                /*Get data of frame*/
                offset += getControlChannelValues(tvb, field_tree_ctr, offset, &cc, &cc_type);
            }/*(controlchannel_length_value > 0)*/
            /*--------/Values--------*/

        }/*length_info > 0*/
    }/*dlci_number == 0*/




    /*~~~~~~~~Information~~~~~~~~*/
    /*Display "normal" data/values (not control channel) if exists ==> length_info > 0*/
    if (dlci_number != 0 && length_info > 0) {
        /*Add a subtree (=item) to the child node => in this subtree will be the data*/
        tf = proto_tree_add_item(mux27010_tree, hf_mux27010_information, tvb, offset, 1, ENC_BIG_ENDIAN);
        field_tree = proto_item_add_subtree(tf, ett_mux27010_information);

        /*We have at least one PPP packet*/
        if (sizeMuxPPPHeader > 0){
            guint16 tmpOffset = 1;
            guint16 tmpOffsetBegin = 1;
            guint16 tmpOffsetEnd = 1;

            guint16 msg_seqid;
            guint16 msg_num;

            guint8 msg_start;
            guint8 msg_end;
            guint8 msg_flag;

            fragment_head *frag_msg = NULL;
            tvbuff_t *new_tvb = NULL;
            tvbuff_t *next_tvb2 = NULL;

            int i;

            for (i = 0; i < sizeMuxPPPHeader/7; i++){

                tmpOffset = 7;
                tmpOffset = (i * tmpOffset)+1;

                msg_seqid = tvb_get_ntohs(tvb, tmpOffset); tmpOffset += 2;
                msg_num   = tvb_get_ntohs(tvb, tmpOffset); tmpOffset += 2;
                msg_start = tvb_get_guint8(tvb, tmpOffset); tmpOffset += 1;
                msg_end   = tvb_get_guint8(tvb, tmpOffset); tmpOffset += 1;
                msg_flag  = tvb_get_guint8(tvb, tmpOffset); tmpOffset += 1;

                if (msg_end <= msg_start) {
                    proto_tree_add_expert(field_tree, pinfo, &ei_mux27010_message_illogical,
                                          tvb, tmpOffset-3, 2);
                    continue;
                }

                tmpOffsetBegin = sizeMuxPPPHeader + 1 + msg_start; /*+ Header_Size, + Direction*/
                tmpOffsetEnd = sizeMuxPPPHeader + 1 + msg_end;

                pinfo->fragmented = TRUE;

                /* XXX - WHY? Isn't there a simpler way? */
                memcpy(&pinfo_tmp, pinfo, sizeof(*pinfo));

                frag_msg = fragment_add_seq_check(&msg_reassembly_table,
                    tvb, tmpOffsetBegin,
                    pinfo,
                    msg_seqid,                       /* ID for fragments belonging together */
                    NULL,
                    msg_num,                         /* fragment sequence number */
                    (tmpOffsetEnd-tmpOffsetBegin)+1, /* fragment length */
                    msg_flag); /* More fragments? */



                new_tvb = process_reassembled_data(tvb, tmpOffsetBegin, pinfo,
                    "Reassembled Message", frag_msg, &msg_frag_items,
                    NULL, mux27010_tree);

                if (!frag_msg) { /* Not last packet of reassembled Message */
                    col_append_str(pinfo->cinfo, COL_INFO, " [Split Msg]");
                }

                if (new_tvb) { /* take it all */
                    next_tvb2 = tvb_new_subset_remaining(new_tvb, 1);
                    call_dissector(ppp_handle, next_tvb2, pinfo, tree);
                }

                pinfo = &pinfo_tmp;
            }
        }

        /*Get and display information*/
        offset += getFrameInformation(tvb, pinfo, field_tree, offset, length_info);

    }
    /*~~~~~~~~/Information~~~~~~~~*/


    /*~~~~~~~~Checksum~~~~~~~~*/
    /*Validate checksum of frame*/
    /*Add a subtree (=item) to the child node => in this subtree will be the checksum*/
    tf = proto_tree_add_item(mux27010_tree, hf_mux27010_checksum, tvb, offset, 1, ENC_BIG_ENDIAN);
    field_tree = proto_item_add_subtree(tf, ett_mux27010_checksum);

    /*Call method check_checksum and validate checksum*/
    if (check_fcs(tvb,offset-sizeMuxPPPHeader-3-length_info, sizeMuxPPPHeader+3, tvb_get_guint8(tvb, offset))){
        /*Checksum is correct*/
        proto_tree_add_boolean(field_tree, hf_mux27010_checksum_correct, tvb, offset, 1, TRUE);
    }
    else{
        /*Checksum is incorrect*/
        expert_add_info(pinfo, tf, &ei_mux27010_checksum_incorrect);
    }
    /*~~~~~~~~/Checksum~~~~~~~~*/
}

static void
mux27010_init(void)
{
    /*
     * Initialize the fragment and reassembly tables.
     */
    reassembly_table_init(&msg_reassembly_table,
                          &addresses_reassembly_table_functions);
}

/*Register the protocol*/
void
proto_register_mux27010 (void)
{
    /* A header field is something you can search/filter on.
    *
    * Create a structure to register fields. It consists of an
    * array of hf_register_info structures, each of which are of the format
    * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
    */

    static hf_register_info hf[] = {

        /*Extended MUX header (for PPP)*/

        {&hf_mux27010_extended_header,
         { "Extended Header", "mux27010.ext_header",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_size,
         { "Header Size", "mux27010.ext_header.size",
           FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_msg_number_I,
         { "Message Number I", "mux27010.ext_header.msg_number_I",
           FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_freq_number_I,
         { "Frequenz Number I", "mux27010.ext_header.frequenz_number_I",
           FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_start_pos_I,
         { "Start Position I", "mux27010.ext_header.start_pos_I",
           FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_start_byte_I,
         { "Start Byte I", "mux27010.ext_header.start_byte_I",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_end_pos_I,
         { "End Position I", "mux27010.ext_header.end_pos_I",
           FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_end_byte_I,
         { "End Byte I", "mux27010.ext_header.end_byte_I",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_flag_ended_I,
         { "Flag Ended I", "mux27010.ext_header.flag_ended_I",
           FT_UINT8, BASE_HEX, NULL, MUX27010_EXTENDED_HEADER_NOT_ENDED, NULL, HFILL }},

        {&hf_mux27010_extended_header_msg_number_II,
         { "Message Number II", "mux27010.ext_header.msg_number_II",
           FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_freq_number_II,
         { "Frequenz Number II", "mux27010.ext_header.frequenz_number_II",
           FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_start_pos_II,
         { "Start Position II", "mux27010.ext_header.start_pos_II",
           FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_start_byte_II,
         { "Start Byte II", "mux27010.ext_header.start_byte_II",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_end_pos_II,
         { "End Position II", "mux27010.ext_header.end_pos_II",
           FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_end_byte_II,
         { "End Byte II", "mux27010.ext_header.end_byte_II",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_flag_ended_II,
         { "Flag Ended II", "mux27010.ext_header.flag_ended_II",
           FT_UINT8, BASE_HEX, NULL, MUX27010_EXTENDED_HEADER_NOT_ENDED, NULL, HFILL }},

        {&hf_mux27010_extended_header_msg_number_III,
         { "Message Number III", "mux27010.ext_header.msg_number_III",
           FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_freq_number_III,
         { "Frequenz Number III", "mux27010.ext_header.frequenz_number_III",
           FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_start_pos_III,
         { "Start Position III", "mux27010.ext_header.start_pos_III",
           FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_start_byte_III,
         { "Start Byte III", "mux27010.ext_header.start_byte_III",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_end_pos_III,
         { "End Position III", "mux27010.ext_header.end_pos_III",
           FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_end_byte_III,
         { "End Byte III", "mux27010.ext_header.end_byte_III",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        {&hf_mux27010_extended_header_flag_ended_III,
         { "Flag Ended III", "mux27010.ext_header.flag_ended_III",
           FT_UINT8, BASE_HEX, NULL, MUX27010_EXTENDED_HEADER_NOT_ENDED, NULL, HFILL }},

        /*Direction*/

        {&hf_mux27010_direction,
         { "Direction", "mux27010.direction",
           FT_UINT8, BASE_HEX, VALS(direction_vals), 0x0, NULL, HFILL }},

        /*Flag*/

        {&hf_mux27010,
         { "Flag", "mux27010.flag",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        /*Address frame*/

        { &hf_mux27010_address,
          { "Address field", "mux27010.address",
            FT_UINT8, BASE_HEX, NULL, 0x0,NULL, HFILL }},

        { &hf_mux27010_dlciaddressflag,
          { "DLCI number (decimal)", "mux27010.address.dlciaddress",
              FT_UINT8, BASE_DEC, NULL, MUX27010_DLCI_ADDRESS_FLAG, NULL, HFILL }},

        { &hf_mux27010_eaaddressflag,
          { "EA Address Flag", "mux27010.address.eaaddress",
            FT_BOOLEAN, 8, NULL, MUX27010_EA_ADDRESS_FLAG, NULL, HFILL }},

        { &hf_mux27010_craddressflag,
          { "C/R Address Flag", "mux27010.address.craddress",
            FT_BOOLEAN, 8, NULL, MUX27010_CR_ADDRESS_FLAG, NULL, HFILL }},

#if 0
        { &hf_mux27010_addressdirection,
          { "Direction", "mux27010.address.direction",
            FT_UINT8, BASE_HEX, NULL, MUX27010_CR_ADDRESS_FLAG, NULL, HFILL }},
#endif

        /*Control frame*/

        { &hf_mux27010_control,
          { "Control field", "mux27010.control",
            FT_UINT8, BASE_HEX, NULL, 0x0,NULL, HFILL }},

        { &hf_mux27010_controlframetype,
          { "Frame Type", "mux27010.control.frametype",
            FT_UINT8, BASE_HEX, VALS(frame_type_vals), MUX27010_FRAMETYPE_CONTROL_FLAG, NULL, HFILL }},

        { &hf_mux27010_controlframetypens,
          { "N(S) Sequence Number", "mux27010.control.frametype.ns",
            FT_UINT8, BASE_DEC, NULL, MUX27010_FRAMETYPE_CONTROL_FLAG_NS, NULL, HFILL }},

        { &hf_mux27010_controlframetypenr,
          { "N(R) Receive Number", "mux27010.control.frametype.nr",
            FT_UINT8, BASE_DEC, NULL, MUX27010_FRAMETYPE_CONTROL_FLAG_NR, NULL, HFILL }},

        { &hf_mux27010_pfcontrolflag,
          { "Poll/Final bit", "mux27010.control.pfcontrol",
            FT_UINT8, BASE_DEC, NULL, MUX27010_PF_CONTROL_FLAG, NULL, HFILL }},

        /*Length frame*/

        { &hf_mux27010_length,
          { "Length field", "mux27010.length",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_mux27010_ealengthflag,
          { "E/A Flag", "mux27010.length.ealength",
            FT_BOOLEAN, 8, NULL, MUX27010_EA_LENGTH_FLAG, NULL, HFILL }},

        { &hf_mux27010_lengthframesize_ea,
          { "Info length", "mux27010.length.framesize_ea",
            FT_UINT16, BASE_DEC, NULL, MUX27010_FRAMESIZE_LENGTH_FLAG_EA, NULL, HFILL }},


        { &hf_mux27010_lengthframesize,
          { "Info length", "mux27010.length.framesize",
            FT_UINT8, BASE_DEC, NULL, MUX27010_FRAMESIZE_LENGTH_FLAG, NULL, HFILL }},

        /*Control Channel DLCI = 0*/

        { &hf_mux27010_controlchannel,
          { "Control Channel", "mux27010.controlchannel",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        /*Frame Type*/

        { &hf_mux27010_controlchannelframetype,
          { "Frame Type", "mux27010.controlchannel.frametype",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_mux27010_controlchanneleaframetype,
          { "EA Flag", "mux27010.controlchannel.frametype.eatype",
            FT_BOOLEAN, 8, NULL, MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG, NULL, HFILL }},

        { &hf_mux27010_controlchannelcrframetype,
          { "C/R Flag", "mux27010.controlchannel.frametype.crtype",
            FT_BOOLEAN, 8, NULL, MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG, NULL, HFILL }},

        { &hf_mux27010_controlchannelframetypecommand,
          { "Command Type", "mux27010.controlchannel.frametype.command",
            FT_UINT8, BASE_HEX, VALS(command_vals), MUX27010_COMMAND_CONTROLCHANNEL_FRAMETYPE_FLAG, NULL, HFILL }},

        /*Length*/

        { &hf_mux27010_controlchannellength,
          { "Length", "mux27010.controlchannel.length",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_mux27010_controlchannelealength,
          { "EA Flag", "mux27010.controlchannel.length.ealength",
            FT_BOOLEAN, 8, NULL, MUX27010_EA_CONTROLCHANNEL_LENGTH_FLAG, NULL, HFILL }},

        { &hf_mux27010_controlchannellengthfield,
          { "Length field", "mux27010.controlchannel.length.length",
            FT_UINT8, BASE_DEC, NULL, MUX27010_LENGTHFIELD_CONTROLCHANNEL_LENGTH_FLAG, NULL, HFILL }},

        /*Value*/

        { &hf_mux27010_controlchannelvalue,
          { "Value (ASCII)", "mux27010.controlchannel.value",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_mux27010_controlchannel_iei_coding,
          { "IEI coding", "mux27010.controlchannel.value.iei_coding",
            FT_UINT8, BASE_HEX, VALS(iei_coding_vals), 0x0, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvalue,
          { "Detailed Values", "mux27010.controlchannel.value.detailedvalues",
            FT_UINT8, BASE_HEX, NULL, 0xFF, NULL, HFILL }},

        { &hf_mux27010_controlchannel_detailedvalue_response,
          { "Resposne", "mux27010.controlchannel.value.detailedvalue.response",
            FT_UINT8, BASE_DEC, VALS(detailedvalue_response_vals), 0, NULL, HFILL }},

        /*Test Command*/

        { &hf_mux27010_controlchanneldetailedvaluetestcommandversion,
          { "Version", "mux27010.controlchannel.value.detailedvaluetestcommandversion",
            FT_UINT8, BASE_HEX, NULL, MUX27010_VALUE_CONTROLCHANNEL_TEST_VERSION, NULL, HFILL }},

        /*Modem Status Command*/

        { &hf_mux27010_controlchanneldetailedvaluemscdlci,
          { "DLCI number (decimal)", "mux27010.controlchannel.value.detailedvaluemscdlci",
            FT_UINT8, BASE_DEC, NULL, MUX27010_VALUE_CONTROLCHANNEL_MSC_DCLI, NULL, HFILL }},

#if 0
        { &hf_mux27010_controlchanneldetailedvaluemscv24,
          { "V.24 Signal", "mux27010.controlchannel.value.detailedvaluemscv24",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
#endif

        { &hf_mux27010_controlchanneldetailedvaluemscv24fc,
          { "FC", "mux27010.controlchannel.value.detailedvaluemscv24.fc",
            FT_BOOLEAN, 8, NULL, MUX27010_VALUE_CONTROLCHANNEL_MSC_V24_FC, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluemscv24rtc,
          { "RTC", "mux27010.controlchannel.value.detailedvaluemscv24.rtc",
            FT_BOOLEAN, 8, NULL, MUX27010_VALUE_CONTROLCHANNEL_MSC_V24_RTC, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluemscv24rtr,
          { "RTR", "mux27010.controlchannel.value.detailedvaluemscv24.rtr",
            FT_BOOLEAN, 8, NULL, MUX27010_VALUE_CONTROLCHANNEL_MSC_V24_RTR, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluemscv24ring,
          { "RING", "mux27010.controlchannel.value.detailedvaluemscv24.ring",
            FT_BOOLEAN, 8, NULL, MUX27010_VALUE_CONTROLCHANNEL_MSC_V24_RING, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluemscv24dcd,
          { "DCD", "mux27010.controlchannel.value.detailedvaluemscv24.dcd",
            FT_BOOLEAN, 8, NULL, MUX27010_VALUE_CONTROLCHANNEL_MSC_V24_DCD, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluemscbreak,
          { "Break Signal", "mux27010.controlchannel.value.detailedvaluemscbreak",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /*Parameter Negotation*/

        { &hf_mux27010_controlchanneldetailedvaluepndlci,
          { "DLCI", "mux27010.controlchannel.value.detailedvaluepndlci",
            FT_UINT8, BASE_DEC, NULL, MUX27010_VALUE_CONTROLCHANNEL_PN_DLCI, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluepnframetype,
          { "Frame Type", "mux27010.controlchannel.value.detailedvaluepnframetype",
            FT_UINT8, BASE_HEX, NULL, MUX27010_VALUE_CONTROLCHANNEL_PN_FRAMETYPE, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluepncl,
          { "Convergence Layer", "mux27010.controlchannel.value.detailedvaluepncl",
            FT_UINT8, BASE_DEC, NULL, MUX27010_VALUE_CONTROLCHANNEL_PN_CL, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluepnprio,
          { "Priority", "mux27010.controlchannel.value.detailedvaluepnprio",
            FT_UINT8, BASE_DEC, NULL, MUX27010_VALUE_CONTROLCHANNEL_PN_PRIO, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluepntimer,
          { "Acknowledgment Timer (ms)", "mux27010.controlchannel.value.detailedvaluepntimer",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluepnframesize,
          { "Max. Frame Size", "mux27010.controlchannel.value.detailedvaluepnframesize",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluepnna,
          { "Max. Number of Retransmissions", "mux27010.controlchannel.value.detailedvaluepnna",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluepnwinsize,
          { "Window Size for Error Recovery Mode", "mux27010.controlchannel.value.detailedvaluepnwinsize",
            FT_UINT8, BASE_DEC, NULL, MUX27010_VALUE_CONTROLCHANNEL_PN_WINSIZE, NULL, HFILL }},

        /*Information frame*/

        { &hf_mux27010_information,
          { "Information field", "mux27010.information",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_mux27010_information_str,
          { "Information", "mux27010.information_str",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        /*Checksum frame*/

        { &hf_mux27010_checksum,
          { "Checksum", "mux27010.checksum",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_mux27010_checksum_correct,
          { "Correct", "mux27010.checksum_correct",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        {&hf_msg_fragments,
         {"Message fragments", "mux27010.fragments",
          FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        {&hf_msg_fragment,
         {"Message fragment", "mux27010.fragment",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        {&hf_msg_fragment_overlap,
         {"Message fragment overlap", "mux27010.fragment.overlap",
          FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        {&hf_msg_fragment_overlap_conflicts,
         {"Message fragment overlapping with conflicting data",
          "mux27010.fragment.overlap.conflicts",
          FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        {&hf_msg_fragment_multiple_tails,
         {"Message has multiple tail fragments",
          "mux27010.fragment.multiple_tails",
          FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        {&hf_msg_fragment_too_long_fragment,
         {"Message fragment too long", "mux27010.fragment.too_long_fragment",
          FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        {&hf_msg_fragment_error,
         {"Message defragmentation error", "mux27010.fragment.error",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        {&hf_msg_fragment_count,
         {"Message fragment count", "mux27010.fragment.count",
          FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        {&hf_msg_reassembled_in,
         {"Reassembled in", "mux27010.reassembled.in",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        {&hf_msg_reassembled_length,
         {"Reassembled length", "mux27010.reassembled.length",
          FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    };


    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_mux27010_extended_header,
        &ett_mux27010,
        &ett_mux27010_address,
        &ett_mux27010_control,
        &ett_mux27010_length,
        &ett_mux27010_controlchannel,
        &ett_mux27010_controlchannelframetype,
        &ett_mux27010_controlchannellength,
        &ett_mux27010_controlchannelvalue,
        &ett_mux27010_information,
        &ett_mux27010_checksum,
        &ett_msg_fragment,
        &ett_msg_fragments
        };

    static ei_register_info ei[] = {
        { &ei_mux27010_message_illogical, { "mux27010.message_illogical", PI_MALFORMED, PI_ERROR, "Message start and end are illogical, aborting dissection", EXPFILL }},
        { &ei_mux27010_checksum_incorrect, { "mux27010.checksum_incorrect", PI_CHECKSUM, PI_WARN, "Checksum: incorrect", EXPFILL }},
    };

    expert_module_t* expert_mux27010;

    /*Register protocoll*/
    proto_mux27010 = proto_register_protocol ("MUX27010 Protocol", "MUX27010", "mux27010");

    /*Register arrays*/
    proto_register_field_array (proto_mux27010, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));

    mux27010_handle = register_dissector("mux27010", dissect_mux27010, proto_mux27010);

    expert_mux27010 = expert_register_protocol(proto_mux27010);
    expert_register_field_array(expert_mux27010, ei, array_length(ei));

    register_init_routine(mux27010_init);
}

/*Initialize dissector*/
void
proto_reg_handoff_mux27010(void)
{
    /*Initialization of dissector*/
    dissector_add_uint("wtap_encap", WTAP_ENCAP_MUX27010, mux27010_handle);

    ppp_handle = find_dissector("ppp");

}

