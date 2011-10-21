/* packet-mux27010.c
 * Dissects a variant of 3GPP TS 27.010 multiplexing protocol
 * Copyright 2011, Hans-Christoph Schemmel <hans-christoph.schemmel[AT]cinterion.com>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/crc8-tvb.h>
#include <expert.h>

#include <string.h>

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
#define MUX27010_COMMAND_NON_SUPPORTED_COMMAND_REPSONSE     0x13    /*00010011*/
#define MUX27010_COMMAND_MODEM_STATUS_COMMAND   0xE3                /*00010011*/
#define MUX27010_COMMAND_PARAMETER_NEGOTIATION  0x83                /*10000011*/


/* Wireshark ID of the MUX27010 protocol */
static int proto_mux27010 = -1;

/* Handles of subdissectors */
static dissector_handle_t ppp_handle;

static const value_string packettypenames[] = {
    { 0, "TEXT" },
    { 1, "SOMETHING_ELSE" },
    { 0, NULL }
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
static int hf_mux27010_addressdirection = -1;
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
static int hf_mux27010_controlchanneldetailedvalue = -1;
static int hf_mux27010_controlchanneldetailedvaluetestcommandversion = -1;
static int hf_mux27010_controlchanneldetailedvaluemscdlci = -1;
static int hf_mux27010_controlchanneldetailedvaluemscv24 = -1;
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
/*Checksum*/
static int hf_mux27010_checksum = -1;

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

/*private MUX frame header (PPP)*/
static guint8 sizeMuxPPPHeader = 0;
static guint8 sizeOfOneMuxPPPHeader = 0;
/*Offset of tvb*/
static gint offset = 0;
/*Address DLCI*/
static gint8 dlci_number = 0;
/*Frame type*/
static guint8 frame_type = 0;
/*Command*/
static guint8 command_or_response = 0;
/*Length*/
static guint8 length_ea = 0;
static guint16 length_info = 0;
static guint16 length_info_second_byte = 0;
/*Control channel*/
static guint8 controlchannel_type_ea = 0;
static guint8 controlchannel_type_cr = 0;
static guint8 controlchannel_type_command = 0;
static gint number_of_type_frames = 0;
static guint8 controlchannel_length_ea = 0;
static guint8 controlchannel_length_value = 0;
static gint number_of_length_frames = 0;
static guint8 controlchannel_value = 0;
static guint8 controlchannel_psc = 0;
static guint8 controlchannel_iei = 0;
static guint8 controlchannel_cl = 0;
/*Checksum*/
static gint8 checksum_validation = 0;

static guint8 direction_in_out = 0;
/*if the frame type is known -> 1 else 0*/
static guint8 known_frame_type = 0;


static char colInfoText[256];
static char colDestText[256];
static char colSourceText[256];
static char frameTypeText[64];

static char information_field_content[256];
static char *information_field;
static char dlci_char[3];

static guint8 i = 0;
static guint8 tmp = 0;


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
    /* Tag */
    "Message fragments"
    };

static GHashTable *msg_fragment_table = NULL;
static GHashTable *msg_reassembled_table = NULL;



static void
getExtendedHeader(tvbuff_t *tvb, proto_tree *field_tree){

    sizeMuxPPPHeader = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(field_tree, hf_mux27010_extended_header_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (sizeMuxPPPHeader > 0){
        int tmpOffset = 1;
        guint16 tmpStartByte = 0;
        guint16 tmpLastByte = 0;
        for (i=0; i < sizeMuxPPPHeader/7; i++){
            switch(i){
                case(0) :
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_msg_number_I, tvb, offset+tmpOffset, 2, ENC_BIG_ENDIAN);
                    tmpOffset+=2;

                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_freq_number_I, tvb, offset+tmpOffset, 2, ENC_BIG_ENDIAN);
                    tmpOffset+=2;

                    tmpStartByte = tvb_get_guint8(tvb, tmpOffset) + sizeMuxPPPHeader + 1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_start_pos_I, tvb, offset+tmpOffset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_start_byte_I, tvb, tmpStartByte, 1, ENC_BIG_ENDIAN);
                    tmpOffset+=1;

                    tmpLastByte = tvb_get_guint8(tvb, tmpOffset) + sizeMuxPPPHeader + 1;
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

                    tmpStartByte = tvb_get_guint8(tvb, tmpOffset) + sizeMuxPPPHeader + 1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_start_pos_II, tvb, offset+tmpOffset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_start_byte_II, tvb, tmpStartByte, 1, ENC_BIG_ENDIAN);
                    tmpOffset+=1;

                    tmpLastByte = tvb_get_guint8(tvb, tmpOffset) + sizeMuxPPPHeader + 1;
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

                    tmpStartByte = tvb_get_guint8(tvb, tmpOffset) + sizeMuxPPPHeader + 1;
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_start_pos_III, tvb, offset+tmpOffset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_tree, hf_mux27010_extended_header_start_byte_III, tvb, tmpStartByte, 1, ENC_BIG_ENDIAN);
                    tmpOffset+=1;

                    tmpLastByte = tvb_get_guint8(tvb, tmpOffset) + sizeMuxPPPHeader + 1;
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
    offset = offset + sizeMuxPPPHeader;

}


/*Get the direction of the actual packet*/
static void
getFrameDirection(tvbuff_t *tvb, proto_tree *field_tree){

    /*Direction is coded in the first byte of the frame*/
    direction_in_out = tvb_get_guint8(tvb, offset);
    colInfoText[0] = 0;

    /*If first byte is 0 => Frame source is Application*/
    /*If first byte is 1 => Frame source is Module*/
    /*else Error*/
    switch (direction_in_out) {
        case (0):/*Application >> Module*/
            g_snprintf(colSourceText,sizeof(colSourceText),"Application  DLCI ");
            g_snprintf(colDestText,sizeof(colDestText),"Module");
            proto_tree_add_uint_format(field_tree, hf_mux27010_direction, tvb, offset, 1, 0, "Direction: Application => Module");
            break;
        case (1):/*Module >> Application*/
            g_snprintf(colSourceText,sizeof(colSourceText), "Module       DLCI ");
            g_snprintf(colDestText,sizeof(colDestText), "Application");
            proto_tree_add_uint_format(field_tree, hf_mux27010_direction, tvb, offset, 1, 1, "Direction: Module => Application");
            break;
        default:/*?? >> ??*/
            g_snprintf(colSourceText,sizeof(colSourceText),"Direction not valid ");
            g_snprintf(colDestText,sizeof(colDestText),"Direction not valid ");
            proto_tree_add_uint_format(field_tree, hf_mux27010_direction, tvb, offset, 1, 2, "Direction not valid");
            break;
    }
    /*Increment offset*/
    offset++;

}



/*Get the address of the actual frame*/
static void
getFrameAddress(tvbuff_t *tvb, proto_tree *field_tree_addr){

    /*Get the DCLI number of the frame >> overwrite other bits (E/A, CR) >> shift*/
    dlci_number = tvb_get_guint8(tvb, offset);
    dlci_number = dlci_number & MUX27010_DLCI_ADDRESS_FLAG;
    dlci_number = dlci_number >> 2;

    /*Convert int to string*/
    dlci_char[0] = dlci_number+48;
    dlci_char[1] = ' ';
    dlci_char[2] = '\0';
    /*Add text to string for Source column*/
    g_snprintf(colSourceText,sizeof(colSourceText),"%s %s", colSourceText, dlci_char);

    /*Add items to subtree to display the details*/
    proto_tree_add_item(field_tree_addr, hf_mux27010_eaaddressflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree_addr, hf_mux27010_craddressflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree_addr, hf_mux27010_dlciaddressflag, tvb, offset, 1, ENC_BIG_ENDIAN);

    /*Get info if frame is command or response*/
    command_or_response = tvb_get_guint8(tvb, offset);
    command_or_response = command_or_response & MUX27010_CR_ADDRESS_FLAG;

    /*Increment offset*/
    offset += 1;
}



/*Get frame data from control field*/
static void
getFrameControlData(tvbuff_t *tvb, proto_tree *field_tree){

    /*Get the type of frame*/
    frame_type = tvb_get_guint8(tvb, offset);
    frame_type = frame_type & MUX27010_FRAMETYPE_CONTROL_FLAG;

    /*variable which stores if the frame type is un/known*/
    known_frame_type = 0;

    /*Find out the frame type and write info into column*/
    switch (frame_type) {
        case (MUX27010_FRAMETYPE_CONTROL_FLAG_SABM): /*SABM frame*/
            proto_tree_add_uint_format(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_SABM, "Frame Type= SABM");
            g_snprintf(frameTypeText,sizeof(frameTypeText),"SABM");
            break;

        case (MUX27010_FRAMETYPE_CONTROL_FLAG_UA): /*UA frame*/
            proto_tree_add_uint_format(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_UA, "Frame Type= UA");
            g_snprintf(frameTypeText,sizeof(frameTypeText),"UA");
            break;

        case (MUX27010_FRAMETYPE_CONTROL_FLAG_DM): /*DM frame*/
            proto_tree_add_uint_format(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_DM, "Frame Type= DM");
            g_snprintf(frameTypeText,sizeof(frameTypeText),"DM");
            break;

        case (MUX27010_FRAMETYPE_CONTROL_FLAG_DISC): /*DISC frame*/
            proto_tree_add_uint_format(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_DISC, "Frame Type= DISC");
            g_snprintf(frameTypeText,sizeof(frameTypeText),"DISC");
            break;

        case (MUX27010_FRAMETYPE_CONTROL_FLAG_UIH): /*UIH frame*/
            proto_tree_add_uint_format(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_UIH, "Frame Type= UIH");
            g_snprintf(frameTypeText,sizeof(frameTypeText),"UIH");
            break;

        default:
            /*Got another frame -> probably a UIH_E, RR, RNR or REJ frame from a DLCI channel != 0 ==> Data channel*/

            /*Check if frame is a UIH_E frame*/
            if ((MUX27010_FRAMETYPE_CONTROL_FLAG_UIH_E | MUX27010_FRAMETYPE_CONTROL_FLAG_NS | MUX27010_FRAMETYPE_CONTROL_FLAG_NR) == (frame_type | MUX27010_FRAMETYPE_CONTROL_FLAG_NS | MUX27010_FRAMETYPE_CONTROL_FLAG_NR)) {
                /*Add frame type to column*/
                proto_tree_add_uint_format(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_UIH_E, "Frame Type= UIH_E");
                /*Add info about sequence numbers to column*/
                proto_tree_add_item(field_tree, hf_mux27010_controlframetypens, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(field_tree, hf_mux27010_controlframetypenr, tvb, offset, 1, ENC_BIG_ENDIAN);

                /*Copy frame name to string for info column*/
                g_snprintf(frameTypeText,sizeof(frameTypeText),"UIH_E");
                /*Frame type is known*/
                known_frame_type = 1;
            }
            /*Check if frame is a RR frame*/
            if ((MUX27010_FRAMETYPE_CONTROL_FLAG_RR | MUX27010_FRAMETYPE_CONTROL_FLAG_NR) == (frame_type | MUX27010_FRAMETYPE_CONTROL_FLAG_NR)) {
                /*Add frame type to column*/
                proto_tree_add_uint_format(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_RR, "Frame Type= Receive Ready");
                /*Add info about sequence number to column*/
                proto_tree_add_item(field_tree, hf_mux27010_controlframetypenr, tvb, offset, 1, ENC_BIG_ENDIAN);

                /*Copy frame name to string for info column*/
                g_snprintf(frameTypeText,sizeof(frameTypeText),"RR");
                /*Frame type is known*/
                known_frame_type = 1;
            }
            if ((MUX27010_FRAMETYPE_CONTROL_FLAG_RNR | MUX27010_FRAMETYPE_CONTROL_FLAG_NR) == (frame_type | MUX27010_FRAMETYPE_CONTROL_FLAG_NR)) {
                /*Add frame type to column*/
                proto_tree_add_uint_format(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_RNR, "Frame Type= Receive Not Ready");
                /*Add info about sequence number to column*/
                proto_tree_add_item(field_tree, hf_mux27010_controlframetypenr, tvb, offset, 1, ENC_BIG_ENDIAN);

                /*Copy frame name to string for info column*/
                g_snprintf(frameTypeText,sizeof(frameTypeText),"RNR");
                /*Frame type is known*/
                known_frame_type = 1;
            }
            if ((MUX27010_FRAMETYPE_CONTROL_FLAG_REJ | MUX27010_FRAMETYPE_CONTROL_FLAG_NR) == (frame_type | MUX27010_FRAMETYPE_CONTROL_FLAG_NR)) {
                /*Add frame type to column*/
                proto_tree_add_uint_format(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, MUX27010_FRAMETYPE_CONTROL_FLAG_REJ, "Frame Type= Reject");
                /*Add info about sequence number to column*/
                proto_tree_add_item(field_tree, hf_mux27010_controlframetypenr, tvb, offset, 1, ENC_BIG_ENDIAN);

                /*Copy frame name to string for info column*/
                g_snprintf(frameTypeText,sizeof(frameTypeText),"REJ");
                /*Frame type is known*/
                known_frame_type = 1;
            }

            /*Unknown frame*/
            if (known_frame_type == 0) {
                /*Add frame type to column*/
                proto_tree_add_uint_format(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, frame_type, "Frame Type= Unknown");
                /*Copy frame name to string for info column*/
                g_snprintf(frameTypeText,sizeof(frameTypeText),"Unknown");
            }
    }

    /*Write information to string for column info*/
    g_snprintf(colInfoText,sizeof(colInfoText),"%s(", colInfoText);
    g_snprintf(colInfoText,sizeof(colInfoText),"%s%s", colInfoText, frameTypeText);
    g_snprintf(colInfoText,sizeof(colInfoText),"%s)", colInfoText);
    /*Add Frame type value and PF bit to column*/
    proto_tree_add_item(field_tree, hf_mux27010_controlframetype, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_mux27010_pfcontrolflag, tvb, offset, 1, ENC_BIG_ENDIAN);

    /*Increment offset*/
    offset += 1;
}




/*Get frame data from length field*/
static void
getFrameLength(tvbuff_t *tvb, proto_tree *field_tree){

    /*Get the E/A bit*/
    length_ea = tvb_get_guint8(tvb, offset);
    length_ea = length_ea & MUX27010_EA_LENGTH_FLAG;

    /*If E/A = 1 it is the last octet*/
    if (length_ea == 1) {
        /*Get the length of the info field*/
        length_info = tvb_get_guint8(tvb, offset);
        length_info = length_info & MUX27010_FRAMESIZE_LENGTH_FLAG;
        length_info = length_info >> 1; /*Shift because of EA bit*/

        /*Add the E/A bit and the length value to the subtree*/
        proto_tree_add_item(field_tree, hf_mux27010_ealengthflag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_uint_format(field_tree, hf_mux27010_lengthframesize, tvb, offset, 1, length_info, "Info length: %i", length_info);
    }
    /*If E/A = 0 the length of the info field is >127*/
    else {
        /*Get first Byte of length*/
        length_info = tvb_get_guint8(tvb, offset);
        length_info = length_info & MUX27010_FRAMESIZE_LENGTH_FLAG;
        length_info = length_info >> 1; /*Shift because of EA bit*/
        offset++;
        /*Get second byte of length byte*/
        length_info_second_byte = tvb_get_guint8(tvb, offset);
        /*shift the bits into the second byte of the length_info_second_byte*/
        length_info_second_byte = length_info_second_byte << 7;

        /*combine the two length bytes*/
        length_info = length_info | length_info_second_byte;

        offset--;
        /*Add info to subtree*/
        proto_tree_add_item(field_tree, hf_mux27010_ealengthflag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_uint_format(field_tree, hf_mux27010_lengthframesize_ea, tvb, offset, 2, length_info, "Info length: %i", length_info);
        offset++;
    }
    offset += 1;
}


/*Get frame type of control channel frame*/
static void
getControlChannelFrameType(tvbuff_t *tvb, proto_tree *field_tree_ctr){

    /*Get the E/A bit*/
    controlchannel_type_ea = tvb_get_guint8(tvb, offset);
    controlchannel_type_ea = controlchannel_type_ea & MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG;

    /*Set variable for number of octets for frame type to 0*/
    number_of_type_frames = 0;
    /*If E/A bit = 1, there will be no other frame type octet*/
    if (controlchannel_type_ea == 1) number_of_type_frames++;

    /*If E/A = 0, read all frame type octets*/
    while (controlchannel_type_ea == 0){
        number_of_type_frames++;
        controlchannel_type_ea = tvb_get_guint8(tvb, offset+number_of_type_frames);
        controlchannel_type_ea = controlchannel_type_ea & MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG;
    }

    /*Get CR bit*/
    controlchannel_type_cr = tvb_get_guint8(tvb, offset);
    controlchannel_type_cr = controlchannel_type_cr & MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG;
    controlchannel_type_cr = controlchannel_type_cr >> 1;

    /*Get command info*/
    controlchannel_type_command = tvb_get_guint8(tvb, offset);
    controlchannel_type_command = controlchannel_type_command & MUX27010_COMMAND_CONTROLCHANNEL_FRAMETYPE_FLAG;

    /*Add info to subtree*/
    proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneleaframetype, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchannelcrframetype, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchannelframetypecommand, tvb, offset, 1, ENC_BIG_ENDIAN);

    /*Check the control channel frame types and add the name to the subtree and strcat the name to the info column*/
    /*Command pattern for Multiplexer Close Down (C/R is set to 1)*/
    if ((controlchannel_type_command | MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG | MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG) == MUX27010_COMMAND_MULTIPLEXER_CLOSEDOWN){
        proto_tree_add_uint_format(field_tree_ctr, hf_mux27010_controlchannelframetypecommand, tvb, offset, 1, controlchannel_type_command, "Command   = Multiplexer Close Down");
        g_snprintf(colInfoText,sizeof(colInfoText),"%s Multiplexer Close Down", colInfoText);
    }
    /*Command pattern for Test Command (C/R is set to 1)*/
    if ((controlchannel_type_command | MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG | MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG) == MUX27010_COMMAND_TEST_COMMAND){
        proto_tree_add_uint_format(field_tree_ctr, hf_mux27010_controlchannelframetypecommand, tvb, offset, 1, controlchannel_type_command, "Command   = Test Command");
        g_snprintf(colInfoText,sizeof(colInfoText),"%s Test Command", colInfoText);
    }
    /*Command pattern for Power saving control (C/R is set to 1)*/
    if ((controlchannel_type_command | MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG | MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG) == MUX27010_COMMAND_POWER_SAVING_CONTROL){
        proto_tree_add_uint_format(field_tree_ctr, hf_mux27010_controlchannelframetypecommand, tvb, offset, 1, controlchannel_type_command, "Command   = Power Saving Control");
        g_snprintf(colInfoText,sizeof(colInfoText),"%s Power Saving Control", colInfoText);
    }
    /*Command pattern for non-supported command response (C/R is set to 1)*/
    if ((controlchannel_type_command | MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG | MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG) == MUX27010_COMMAND_NON_SUPPORTED_COMMAND_REPSONSE){
        proto_tree_add_uint_format(field_tree_ctr, hf_mux27010_controlchannelframetypecommand, tvb, offset, 1, controlchannel_type_command, "Command   = Non-supported Command Response");
        g_snprintf(colInfoText,sizeof(colInfoText),"%s Non-supported Command Response", colInfoText);
    }
    /*Command pattern for Modem Status Command (C/R is set to 1)*/
    if ((controlchannel_type_command | MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG | MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG) == MUX27010_COMMAND_MODEM_STATUS_COMMAND){
        proto_tree_add_uint_format(field_tree_ctr, hf_mux27010_controlchannelframetypecommand, tvb, offset, 1, controlchannel_type_command, "Command   = Modem Status Command");
        g_snprintf(colInfoText,sizeof(colInfoText),"%s Modem Status Command", colInfoText);
    }
    /*Command pattern for Parameter Negotiation (EA + C/R is set to 1)*/
    if ((controlchannel_type_command | MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG | MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG) == MUX27010_COMMAND_PARAMETER_NEGOTIATION){
        proto_tree_add_uint_format(field_tree_ctr, hf_mux27010_controlchannelframetypecommand, tvb, offset, 1, controlchannel_type_command, "Command   = Parameter Negotiation");
        g_snprintf(colInfoText,sizeof(colInfoText),"%s Parameter Negotiation", colInfoText);
    }

    if (controlchannel_type_cr == 1) /*Command C/R*/{
        g_snprintf(colInfoText,sizeof(colInfoText),"%s (Command)", colInfoText);
    }
    else{ /*Response*/
        g_snprintf(colInfoText,sizeof(colInfoText),"%s (Response)", colInfoText);
    }

    /*Increment the offset*/
    offset +=number_of_type_frames;

}


/*Get length of control channel info field*/
static void
getControlChannelLength(tvbuff_t *tvb, proto_tree *field_tree_ctr) {

    /*Get the E/A bit*/
    controlchannel_length_ea = tvb_get_guint8(tvb, offset);
    controlchannel_length_ea = controlchannel_length_ea & MUX27010_EA_CONTROLCHANNEL_LENGTH_FLAG;

    /*Set variable for number of octets for info field to 0*/
    number_of_length_frames = 0;
    /*If E/A bit = 1, there will be no other info field length octet*/
    if (controlchannel_length_ea == 1) number_of_length_frames++;

    /*If E/A = 0, read all length of info field octets*/
    while (controlchannel_length_ea == 0){
        number_of_length_frames++;
        controlchannel_length_ea = tvb_get_guint8(tvb, offset+number_of_length_frames);
        controlchannel_length_ea = controlchannel_length_ea & MUX27010_EA_CONTROLCHANNEL_LENGTH_FLAG;
    }

    /*Get the data from info field*/
    controlchannel_length_value = tvb_get_guint8(tvb, offset);
    controlchannel_length_value = controlchannel_length_value & MUX27010_LENGTHFIELD_CONTROLCHANNEL_LENGTH_FLAG;
    controlchannel_length_value = controlchannel_length_value >> 1; /*Shift because of EA bit*/

    /*Add data to subtree*/
    proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchannelealength, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchannellengthfield, tvb, offset, 1, ENC_BIG_ENDIAN);

    /*Increment the offset by the number of info octets*/
    offset +=number_of_length_frames;
}



/*Get values of control channel*/
static void
getControlChannelValues(tvbuff_t *tvb, proto_tree *field_tree_ctr){

    /*Command pattern for Test Command (C/R is set to 1)*/
    if ((controlchannel_type_command | MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG | MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG) == MUX27010_COMMAND_TEST_COMMAND){
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluetestcommandversion, tvb, offset, 1, ENC_BIG_ENDIAN);
        controlchannel_iei = tvb_get_guint8(tvb, offset);
        if (controlchannel_iei == MUX27010_VALUE_CONTROLCHANNEL_TEST_IEI_TE) {
            proto_tree_add_uint_format(field_tree_ctr, hf_mux27010_controlchannelvalue, tvb, offset, 1, controlchannel_value, "IEI coding: TEMUX_VERSION");
        }
        if (controlchannel_iei == MUX27010_VALUE_CONTROLCHANNEL_TEST_IEI_MS){
            proto_tree_add_uint_format(field_tree_ctr, hf_mux27010_controlchannelvalue, tvb, offset, 1, controlchannel_value, "IEI coding: MSMUX_VERSION");
        }
        proto_tree_add_uint_format(field_tree_ctr, hf_mux27010_controlchannelvalue, tvb, offset+1, controlchannel_length_value-1, controlchannel_value, "Value (ASCII): %s", tvb_get_string(tvb, offset+1,controlchannel_length_value-1));
    }

    /*Command pattern for Power saving control (C/R is set to 1)*/
    if ((controlchannel_type_command | MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG | MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG) == MUX27010_COMMAND_POWER_SAVING_CONTROL){
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvalue, tvb, offset, 1, ENC_BIG_ENDIAN);
        controlchannel_psc = tvb_get_guint8(tvb, offset);
        if (controlchannel_type_cr == 0 && controlchannel_psc == 0) /*Response Failure*/
            proto_tree_add_uint_format(field_tree_ctr, hf_mux27010_controlchanneldetailedvalue, tvb, offset, controlchannel_length_value, controlchannel_value, "Response: Failure");
        if (controlchannel_type_cr == 0 && controlchannel_psc == 1) /*Response Success*/
            proto_tree_add_uint_format(field_tree_ctr, hf_mux27010_controlchanneldetailedvalue, tvb, offset, controlchannel_length_value, controlchannel_value, "Response: Success");
    }

    /*Command pattern for non-supported command response (C/R is set to 1)*/
    if ((controlchannel_type_command | MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG | MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG) == MUX27010_COMMAND_NON_SUPPORTED_COMMAND_REPSONSE){
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvalue, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_uint_format(field_tree_ctr, hf_mux27010_controlchanneldetailedvalue, tvb, offset, controlchannel_length_value, controlchannel_value, "Non-supported Command");
    }
    /*Command pattern for Modem Status Command (C/R is set to 1)*/
    if ((controlchannel_type_command | MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG | MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG) == MUX27010_COMMAND_MODEM_STATUS_COMMAND){
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscdlci, tvb, offset, 1, ENC_BIG_ENDIAN);

        /*Add bits of Flow Control*/
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscv24fc, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscv24rtc, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscv24rtr, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscv24ring, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscv24dcd, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        /**/

        if (controlchannel_length_value == 3) {
            proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluemscbreak, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        }
    }
    /*Command pattern for Parameter Negotiation (EA + C/R is set to 1)*/
    if ((controlchannel_type_command | MUX27010_EA_CONTROLCHANNEL_FRAMETYPE_FLAG | MUX27010_CR_CONTROLCHANNEL_FRAMETYPE_FLAG) == MUX27010_COMMAND_PARAMETER_NEGOTIATION){
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepndlci, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepnframetype, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepncl, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        controlchannel_cl = tvb_get_guint8(tvb, offset+1);
        controlchannel_cl = controlchannel_cl & MUX27010_VALUE_CONTROLCHANNEL_PN_CL;
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepnprio, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepntimer, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepnframesize, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepnna, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree_ctr, hf_mux27010_controlchanneldetailedvaluepnwinsize, tvb, offset+7, 1, ENC_BIG_ENDIAN);

    }

    offset += controlchannel_length_value;
}



/*Get values information field*/
static void
getFrameInformation(tvbuff_t *tvb, proto_tree *field_tree){

    /*Get the data from information field as string*/
    information_field = tvb_get_string(tvb,offset,length_info);
    tmp = 0;

    /*Copy data from buffer to local array information_field_content*/
    /*and delete unneeded signs out of info field -> for info column: CR (0x0d) and LF (0x0a)*/
    for (i = 0; i<length_info && i<=50; i++) {
        /*Check every sign in information field for CR and LF*/
        if (*information_field != 0x0a && *information_field != 0x0d){
            /*Copy char to array*/
            information_field_content[i] = *information_field;
        }
        /*if CR or LF found ==> replace it ' '*/
        else {
            /*Copy ' '  to array*/
            information_field_content[i] =' ';
        }
        /*Increment pointer*/
        information_field++;
    }
    /*Add String end*/
    information_field_content[i] = '\0';

    /*strcat: for info column*/
    g_snprintf(colInfoText,sizeof(colInfoText),"%s %s", colInfoText, information_field_content);

    /*Get pointer to begin of buffer again*/
    information_field = tvb_get_string(tvb,offset,length_info);

    /*Add info to subtree*/
    proto_tree_add_uint_format(field_tree, hf_mux27010_information, tvb, offset, length_info, controlchannel_type_command, "Information: %s",information_field);

    /*Increment offset by the length of chars in info field*/
    offset +=length_info;
}




static void
dissect_mux27010(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *tf = NULL, *tf_extended_header, *tf_addr, *tf_ctr;
    proto_tree *mux27010_tree = NULL;
    proto_tree *field_tree, *field_tree_extended_header, *field_tree_addr, *field_tree_ctr;

    /* Set row to protocol*/
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_MUX27010);

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d Info Type:[]",pinfo->srcport, pinfo->destport);


    /* Set offset to 0 => start to read at the begin of the frame*/
    offset = 0;

    /*Strings for info column*/
    colInfoText[0] = 0;
    colDestText[0] = 0;
    colSourceText[0] = 0;
    frameTypeText[0] = 0;


    /*Add a subtree/item to wireshark => in this subtree the details will of the protocol will be displayed*/
    /*@param tree: Tree in WS (root)*/
    /*@param proto_mux27010: Protocol name*/
    /*@param tvb: Buffer to dissect (data for protocol)*/
    /*@param "0" and "-1": All data is for the protocol*/
    ti = proto_tree_add_item(tree, proto_mux27010, tvb, 0, -1, ENC_NA);

    /*Add a subtree to the protocol tree (child node)*/
    mux27010_tree = proto_item_add_subtree(ti, ett_mux27010);



    /*Size of one header in byte*/
    sizeOfOneMuxPPPHeader = 7;

    /*Add a subtree (=item) to the child node => in this subtree the details of extended header will be displayed*/
    tf_extended_header = proto_tree_add_item(mux27010_tree, hf_mux27010_extended_header, tvb, offset, 1, ENC_BIG_ENDIAN);
    /*Create the subtree*/
    field_tree_extended_header = proto_item_add_subtree(tf_extended_header, ett_mux27010_extended_header);

    getExtendedHeader(tvb, field_tree_extended_header);
    offset++;


    /*Get direction of the frame*/
    getFrameDirection(tvb, mux27010_tree);






    /*~~~~~~~~Flag~~~~~~~~*/
    /*(Insert data into the child node)*/
    /*Create item to show/highlight flag sequence*/
    proto_tree_add_item(mux27010_tree, hf_mux27010, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /*~~~~~~~~/Flag~~~~~~~~*/



    /*~~~~~~~~Address~~~~~~~~*/
    /*Add a subtree (=item) to the child node => in this subtree the details of address data will be displayed*/
    tf_addr = proto_tree_add_item(mux27010_tree, hf_mux27010_address, tvb, offset, 1, ENC_BIG_ENDIAN);
    /*Create the subtree*/
    field_tree_addr = proto_item_add_subtree(tf_addr, ett_mux27010_address);

    /*Get address data (DLCI, E/A, CR)*/
    getFrameAddress(tvb, field_tree_addr);
    /*~~~~~~~~/Address~~~~~~~~*/



    /*~~~~~~~~Control Data~~~~~~~~*/
    /*Add a subtree (=item) to the child node => in this subtree the details of control data will be displayed*/
    tf = proto_tree_add_item(mux27010_tree, hf_mux27010_control, tvb, offset, 1, ENC_BIG_ENDIAN);
    /*Create the subtree*/
    field_tree = proto_item_add_subtree(tf, ett_mux27010_control);

    /*Get control data of frame (Frame type)*/
    getFrameControlData(tvb, field_tree);
    /*~~~~~~~~/Control Data~~~~~~~~*/




    /*~~~~~~~~Length~~~~~~~~*/
    /*Set the variable for length of the info field to 0*/
    length_info = 0;

    /*Check the frame type because in RR, RNR and REJ are no info and no lenght fields*/
    if (strcmp(frameTypeText,"RR")!= 0 && strcmp(frameTypeText,"RNR")!= 0 && strcmp(frameTypeText,"REJ")!= 0){
        /*Add a subtree (=item) to the child node => in this subtree will be the details of length field*/
        tf = proto_tree_add_item(mux27010_tree, hf_mux27010_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        /*Create the subtree*/
        field_tree = proto_item_add_subtree(tf, ett_mux27010_length);

        /*Get frame length data*/
        getFrameLength(tvb, field_tree);
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
            /*Create the subtree*/
            field_tree = proto_item_add_subtree(tf, ett_mux27010_controlchannel);

            /*Add another subtree to the control channel subtree => in this subtree the details of control channel frame type will be displayed*/
            tf_ctr = proto_tree_add_item(field_tree, hf_mux27010_controlchannelframetype, tvb, offset, number_of_type_frames, ENC_BIG_ENDIAN);
            /*Create the subtree*/
            field_tree_ctr = proto_item_add_subtree(tf_ctr, ett_mux27010_controlchannelframetype);

            /*Get data about the type of the frame*/
            getControlChannelFrameType(tvb, field_tree_ctr);
            /*--------/Frame Type--------*/


            /*--------Length Field--------*/
            /*Add another subtree to the control channel subtree => in this subtree the details of control channel length field will be displayed*/
            tf_ctr = proto_tree_add_item(field_tree, hf_mux27010_controlchannellength, tvb, offset, number_of_length_frames, ENC_BIG_ENDIAN);
            /*Create the subtree*/
            field_tree_ctr = proto_item_add_subtree(tf_ctr, ett_mux27010_controlchannellength);

            /*Get data of length field*/
            getControlChannelLength(tvb, field_tree_ctr);
            /*--------/Length Field--------*/


            /*--------Values--------*/
            /*If frame has data inside the length_value is > 0*/
            if (controlchannel_length_value > 0) {
                /*Add another subtree to the control channel subtree => in this subtree the details of control channel values/data will be displayed*/
                tf_ctr = proto_tree_add_uint_format(field_tree, hf_mux27010_controlchannelvalue, tvb, offset, controlchannel_length_value, controlchannel_value, "Data: %i Byte(s)", controlchannel_length_value);
                /*Create the subtree*/
                field_tree_ctr = proto_item_add_subtree(tf_ctr, ett_mux27010_controlchannelvalue);

                /*Get data of frame*/
                getControlChannelValues(tvb, field_tree_ctr);
            }/*(controlchannel_length_value > 0)*/
            /*--------/Values--------*/

        }/*length_info > 0*/
    }/*dlci_number == 0*/




    /*~~~~~~~~Information~~~~~~~~*/
    /*Display "normal" data/values (not control channel) if exists ==> length_info > 0*/
    if (dlci_number != 0 && length_info > 0) {
        /*Add a subtree (=item) to the child node => in this subtree will be the data*/
        tf = proto_tree_add_item(mux27010_tree, hf_mux27010_information, tvb, offset, 1, ENC_BIG_ENDIAN);
        /*Create the subtree*/
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

            fragment_data *frag_msg = NULL;
            tvbuff_t *new_tvb = NULL;
            tvbuff_t *next_tvb2 = NULL;

            packet_info pinfo_tmp;

            for (i = 0; i < sizeMuxPPPHeader/7; i++){

                tmpOffset = 7;
                tmpOffset = (i * tmpOffset)+1;

                msg_seqid = tvb_get_ntohs(tvb, tmpOffset); tmpOffset += 2;
                msg_num   = tvb_get_ntohs(tvb, tmpOffset); tmpOffset += 2;
                msg_start = tvb_get_guint8(tvb, tmpOffset); tmpOffset += 1;
                msg_end   = tvb_get_guint8(tvb, tmpOffset); tmpOffset += 1;
                msg_flag  = tvb_get_guint8(tvb, tmpOffset); tmpOffset += 1;

                if (msg_end <= msg_start) {
		    proto_item *pi;
                    pi = proto_tree_add_text(field_tree, tvb, tmpOffset-3, 2,
                        "Message start and end are illogical, aborting dissection");
                    expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
		        "Message start and end are illogical");
                    continue;
                }

                tmpOffsetBegin = sizeMuxPPPHeader + 1 + msg_start; /*+ Header_Size, + Direction*/
                tmpOffsetEnd = sizeMuxPPPHeader + 1 + msg_end;

                pinfo->fragmented = TRUE;

                memcpy(&pinfo_tmp, pinfo, sizeof(*pinfo));

                frag_msg = fragment_add_seq_check(tvb, tmpOffsetBegin, pinfo,
                    msg_seqid,                       /* ID for fragments belonging together */
                    msg_fragment_table,              /* list of message fragments */
                    msg_reassembled_table,           /* list of reassembled messages */
                    msg_num,                         /* fragment sequence number */
                    (tmpOffsetEnd-tmpOffsetBegin)+1, /* fragment length */
                    msg_flag); /* More fragments? */



                new_tvb = process_reassembled_data(tvb, tmpOffsetBegin, pinfo,
                    "Reassembled Message", frag_msg, &msg_frag_items,
                    NULL, mux27010_tree);

                if (!frag_msg) { /* Not last packet of reassembled Message */
                    g_snprintf(colInfoText, sizeof(colInfoText), "%s [Splitted Msg]", colInfoText);
                }

                if (new_tvb) { /* take it all */
                    next_tvb2 = tvb_new_subset(new_tvb, 1, -1, -1);
                    call_dissector(ppp_handle, next_tvb2, pinfo, tree);
                }

                pinfo = &pinfo_tmp;
            }
        }

        /*Get and display information*/
        getFrameInformation(tvb, field_tree);

    }
    /*~~~~~~~~/Information~~~~~~~~*/


    /*~~~~~~~~Checksum~~~~~~~~*/
    /*Validate checksum of frame*/
    /*Add a subtree (=item) to the child node => in this subtree will be the checksum*/
    tf = proto_tree_add_item(mux27010_tree, hf_mux27010_checksum, tvb, offset, 1, ENC_BIG_ENDIAN);
    /*Create the subtree*/
    field_tree = proto_item_add_subtree(tf, ett_mux27010_checksum);

    /*Call method check_checksum and validate checksum*/
    if (check_fcs(tvb,offset-sizeMuxPPPHeader-3-length_info, sizeMuxPPPHeader+3, tvb_get_guint8(tvb, offset))){
        /*Checksum is correct*/

        /*WS Variable to identify correct (1) or incorrect (0) packets*/
        checksum_validation = 1;
        proto_tree_add_uint_format(field_tree, hf_mux27010_checksum, tvb, offset, 1, checksum_validation, "Checksum: correct");
    }
    else{
        /*Checksum is correct*/

        /*WS Variable to identify correct (1) or incorrect (0) packets*/
        checksum_validation = -1;
        proto_tree_add_uint_format(field_tree, hf_mux27010_checksum, tvb, offset, 1, checksum_validation, "Checksum: incorrect!");
    }
    /*~~~~~~~~/Checksum~~~~~~~~*/



    /*Write text into columns*/
    /*Info column*/
    col_add_str(pinfo->cinfo, COL_INFO, colInfoText);
    /*Source column*/
    col_add_str(pinfo->cinfo, COL_DEF_SRC, colSourceText);
    /*Destination column*/
    col_add_str(pinfo->cinfo, COL_DEF_DST, colDestText);
}

static void
mux27010_init(void)
{
    /*
     * Initialize the fragment and reassembly tables.
     */
    fragment_table_init(&msg_fragment_table);
    reassembled_table_init(&msg_reassembled_table);
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
         { "End Position I", "mux27010.ext_header.end_byte_I",
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
         { "End Position II", "mux27010.ext_header.end_byte_II",
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
         { "End Position III", "mux27010.ext_header.end_byte_III",
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
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

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

        { &hf_mux27010_addressdirection,
          { "Direction", "mux27010.address.direction",
            FT_UINT8, BASE_HEX, NULL, MUX27010_CR_ADDRESS_FLAG, NULL, HFILL }},

        /*Control frame*/

        { &hf_mux27010_control,
          { "Control field", "mux27010.control",
            FT_UINT8, BASE_HEX, NULL, 0x0,NULL, HFILL }},

        { &hf_mux27010_controlframetype,
          { "Frame Type", "mux27010.control.frametype",
            FT_UINT8, BASE_HEX, NULL, MUX27010_FRAMETYPE_CONTROL_FLAG, NULL, HFILL }},

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
          { "Frame Size", "mux27010.length.framesize_ea",
            FT_UINT16, BASE_DEC, NULL, MUX27010_FRAMESIZE_LENGTH_FLAG_EA, NULL, HFILL }},


        { &hf_mux27010_lengthframesize,
          { "Frame Size", "mux27010.length.framesize",
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
            FT_UINT8, BASE_HEX, NULL, MUX27010_COMMAND_CONTROLCHANNEL_FRAMETYPE_FLAG, NULL, HFILL }},

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
          { "Value", "mux27010.controlchannel.value",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvalue,
          { "Detailed Values", "mux27010.controlchannel.value.detailedvalues",
            FT_UINT8, BASE_HEX, NULL, 0xFF, NULL, HFILL }},

        /*Test Command*/

        { &hf_mux27010_controlchanneldetailedvaluetestcommandversion,
          { "Version", "mux27010.controlchannel.value.detailedvaluetestcommandversion",
            FT_UINT8, BASE_HEX, NULL, MUX27010_VALUE_CONTROLCHANNEL_TEST_VERSION, NULL, HFILL }},

        /*Modem Status Command*/

        { &hf_mux27010_controlchanneldetailedvaluemscdlci,
          { "DLCI number (decimal)", "mux27010.controlchannel.value.detailedvaluemscdlci",
            FT_UINT8, BASE_DEC, NULL, MUX27010_VALUE_CONTROLCHANNEL_MSC_DCLI, NULL, HFILL }},

        { &hf_mux27010_controlchanneldetailedvaluemscv24,
          { "V.24 Signal", "mux27010.controlchannel.value.detailedvaluemscv24",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

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

        /*Checksum frame*/

        { &hf_mux27010_checksum,
          { "Checksum", "mux27010.checksum",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

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

    /*Register protocoll*/
    proto_mux27010 = proto_register_protocol ("MUX27010 Protocol", "MUX27010", "mux27010");

    /*Register arrays*/
    proto_register_field_array (proto_mux27010, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    register_dissector("mux27010", dissect_mux27010, proto_mux27010);

    register_init_routine(mux27010_init);
}

/*Initialize dissector*/
void
proto_reg_handoff_mux27010(void)
{
    dissector_handle_t mux27010_handle;

    /*Initialization of dissector*/
    mux27010_handle = create_dissector_handle(dissect_mux27010, proto_mux27010);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_MUX27010, mux27010_handle);

    ppp_handle = find_dissector("ppp");

}

