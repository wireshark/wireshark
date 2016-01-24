/* packet-tn3270.c
 * Routines for tn3270.packet dissection
 *
 * References:
 *  3270 Information Display System: Data Stream Programmer's Reference
 *    GA23-0059-07
 *    http://publib.boulder.ibm.com/cgi-bin/bookmgr_OS390/BOOKS/CN7P4000
 *    (Paragraph references in the comments in this file (e.g., 6.15) are to the above document)
 *
 *  3174 Establishment Controller Functional Description
 *    GA23-0218-11
 *    http://publib.boulder.ibm.com/cgi-bin/bookmgr/BOOKS/cn7a7003
 *
 *
 *  RFC 1041: Telnet 3270 Regime Option
 *    http://tools.ietf.org/html/rfc1041
 *
 *  RFC 1576: TN3270 Current Practices
 *    http://tools.ietf.org/html/rfc1576
 *
 *  RFC 2355: TN3270 Enhancements
 *    http://tools.ietf.org/html/rfc2355
 *
 *
 * Copyright 2009, Robert Hogan <robert@roberthogan.net>
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
#include <epan/conversation.h>
#include <epan/expert.h>

#include "packet-tn3270.h"

void proto_register_tn3270(void);

/* Note well:
 *  In the IBM "3270 Information Display System: Data Stream Programmer's Reference"
 *  document, the references to bit numbers in the text and tables
 *  are based upon the "MSB 0" bit numbering scheme.
 *  That is: bits are numbered in a byte from left-to-right:
 *    "Bit 0" is the MSB of the byte
 *    "Bit 7" is the LSB of the byte
 */

/*
 ToDo:
  - better tree display: e.g., separate tree for each order code ....
  - review 'structured field grouping: 5.2
  - Telnet uses 0xFF as IAC ["interpret as command"] and thus for
     telnet: any actual 0xFF bytes in a 3270 data stream will be prefixed with
     a 0xFF escape. The escapes should be removed from the TVB before the
     buffer is passed to this dissector. See packet-telnet.c
  - Show the 'as a fraction" display as  xx/yy ?
*/

/* Dissection is for EBCDIC 3270 */

/* OUTBOUND DATA STREAM (MAINFRAME PROGRAM -> DISPLAY)

   ________________ _____ __________________
   | Command Code   |WCC  | Orders and Data  |
   |________________|_____|__________________|

   or
   ______ ______________________
   | WSF  | Structured Field(s)  |
   |______|______________________|

*/

/*--- 3270 Command Codes - "Local Attachment" ----- */
#define CC_LCL_W        0x01
#define CC_LCL_EW       0x05
#define CC_LCL_EWA      0x0D
#define CC_LCL_EAU      0x0F
#define CC_LCL_WSF      0x11

#define CC_LCL_RB       0x02
#define CC_LCL_RM       0x06
#define CC_LCL_RMA      0x0E  /* XXX Not valid ?? See 3174 Function Description 2.1.4 */

#if 0  /* ??? */
#define CC_NOP      0x03
#endif


/*--- 3.3 3270 Command Codes - "Remote Attachment" ----- */
#define CC_RMT_W    0xF1
#define CC_RMT_EW   0xF5
#define CC_RMT_EWA  0x7E
#define CC_RMT_EAU  0x6F
#define CC_RMT_WSF  0xF3

#define CC_RMT_RB   0xF2
#define CC_RMT_RM   0xF6
#define CC_RMT_RMA  0x6E

#define CC_SNA_BSC  0xF7   /* local copy in a BSC environment */

static const value_string vals_command_codes[] = {

  { CC_LCL_W,   "Write (Local)" },
  { CC_LCL_EW,  "Erase/Write (Local)" },
  { CC_LCL_EWA, "Erase/Write Alternate (Local)" },
  { CC_LCL_EAU, "Erase All Unprotected (Local)" },
  { CC_LCL_WSF, "Write Structured Field (Local)" },
  { CC_LCL_RB,  "Read Buffer (Local)" },
  { CC_LCL_RM,  "Read Modified (Local)" },
  { CC_LCL_RMA, "Read Modified All (Local)" },
  { CC_RMT_W,   "Write" },
  { CC_RMT_EW,  "Erase/Write" },
  { CC_RMT_EWA, "Erase/Write Alternate" },
  { CC_RMT_EAU, "Erase All Unprotected" },
  { CC_RMT_WSF, "Write Structured Field" },
  { CC_RMT_RB,  "Read Buffer" },
  { CC_RMT_RM,  "Read Modified" },
  { CC_RMT_RMA, "Read Modified All" },
  { CC_SNA_BSC, "BSC Copy" },
  { 0x00, NULL }
};

/*--- 3.4 WCC (Write Control Characters) ----- */
#define WCC_NOP               0x80 /* "Bit 0" */
#define WCC_RESET             0x40 /* "Bit 1" */
#define WCC_PRINTER1          0x20 /* "Bit 2" */
#define WCC_PRINTER2          0x10 /* "Bit 3" */
#define WCC_START_PRINTER     0x08 /* "Bit 4" */
#define WCC_SOUND_ALARM       0x04 /* "Bit 5" */
#define WCC_KEYBOARD_RESTORE  0x02 /* "Bit 6" */
#define WCC_RESET_MDT         0x01 /* "Bit 7" */

/*--- 4.3 Order Codes ----- */
#define OC_MAX  0x3F

#define OC_SF   0x1D
#define OC_SFE  0x29
#define OC_SBA  0x11
#define OC_SA   0x28
#define OC_MF   0x2C
#define OC_IC   0x13
#define OC_PT   0x05
#define OC_RA   0x3C
#define OC_EUA  0x12
#define OC_GE   0x08

static const value_string vals_order_codes[] = {
  { OC_SF,  "Start Field (SF)" },
  { OC_SFE, "Start Field Extended (SFE)" },
  { OC_SBA, "Set Buffer Address (SBA)" },
  { OC_SA,  "Set Attribute (SA)" },
  { OC_MF,  "Modify Field (MF)" },
  { OC_IC,  "Insert Cursor (IC)" },
  { OC_PT,  "Program Tab (PT)" },
  { OC_RA,  "Repeat to Address (RA)" },
  { OC_EUA, "Erase Unprotected to Address (EUA)" },
  { OC_GE,  "Graphic Escape (GE)" },
  { 0x00, NULL }
};

#if 0  /* Not used */
/*--- 4.3.11 Format Control Orders ----- */
/*        Special treatment for display */
#define FCO_NUL  0x00
#define FCO_SUB  0x3F
#define FCO_DUP  0x1C
#define FCO_FM   0x1E
#define FCO_FF   0x0C
#define FCO_CR   0x0D
#define FCO_NL   0x15
#define FCO_EM   0x19
#define FCO_EO   0xFF

static const value_string vals_format_control_orders[] = {
  { FCO_NUL, "Null" },
  { FCO_SUB, "Substitute" },
  { FCO_DUP, "Duplicate" },
  { FCO_FM,  "Field Mark" },
  { FCO_FF,  "Form Feed" },
  { FCO_CR,  "Carriage Return" },
  { FCO_NL,  "New Line" },
  { FCO_EM,  "End of Medium" },
  { FCO_EO,  "Eight Ones" },
  { 0x00, NULL }
};
#endif

/*--- 8.7 Copy Control Code ----- */
/* Use for "local Copy" in a "BSC [BiSync] Environment" */

/* "Coding Bits" are those required such that the   */
/*   complete 8 bit CCC is a valid EBCDIC character */
#define CCC_GRAPHIC_CONVERT_MASK          0xC0

#define CCC_PRINT_BITS_MASK               0x30
#define  CCC_PRINT_BITS_POINT_LINE_LENGTH  0x00
#define  CCC_PRINT_BITS_PRINT_LINE_40      0x01
#define  CCC_PRINT_BITS_PRINT_LINE_64      0x02
#define  CCC_PRINT_BITS_PRINT_LINE_80      0x03

static const value_string ccc_vals_printout_format[] = {
  { CCC_PRINT_BITS_POINT_LINE_LENGTH,
    "The NL, EM, and CR orders in the data stream determine pointline length. "
    "Provides a 132-print position line when the orders are not present." },
  { CCC_PRINT_BITS_PRINT_LINE_40,
    "Specifies a 40-character print line." },
  { CCC_PRINT_BITS_PRINT_LINE_64,
    "Specifies a 64-character print line." },
  { CCC_PRINT_BITS_PRINT_LINE_80,
    "Specifies an 80-character print line." },
  { 0x00, NULL }
};

#define CCC_START_PRINT                                         0x08
#define CCC_SOUND_ALARM                                         0x04

#define CCC_ATTRIBUTE_BITS_MASK                                 0x03
#define  CCC_ATTRIBUTE_BITS_ONLY_ATTRIBUTE_CHARACTERS            0x00
#define  CCC_ATTRIBUTE_BITS_ATTRIBUTE_CHARACTERS_UNPROTECTED_AN  0x01
#define  CCC_ATTRIBUTE_BITS_ALL_ATTRIBUTE_PROTECTED              0x02
#define  CCC_ATTRIBUTE_BITS_ENTIRE_CONTENTS                      0x03

static const value_string ccc_vals_copytype[] = {
  { CCC_ATTRIBUTE_BITS_ONLY_ATTRIBUTE_CHARACTERS,
    "Only attribute characters are copied." },
  { CCC_ATTRIBUTE_BITS_ATTRIBUTE_CHARACTERS_UNPROTECTED_AN,
    "Attribute characters and unprotected alphanumeric fields"
    " (including nulls) are copied. Nulls are transferred for"
    " the alphanumeric characters not copied from the"
    " protected fields." },
  { CCC_ATTRIBUTE_BITS_ALL_ATTRIBUTE_PROTECTED,
    "All attribute characters and protected alphanumeric fields"
    " (including nulls) are copied. Nulls are transferred for the alphanumeric characters not"
    " copied from the unprotected fields." },
  { CCC_ATTRIBUTE_BITS_ENTIRE_CONTENTS,
    "The entire contents of the storage buffer (including nulls) are copied." },
  { 0x00, NULL }
};

/*--- 4.4.1 Field Attributes ----- */
#define FA_GRAPHIC_CONVERT_MASK 0xC0

#define FA_PROTECTED         0x20 /* "Bit 2" */
#define FA_NUMERIC           0x10 /* "Bit 3" */

#define FA_RESERVED          0x02 /* "Bit 6" */
#define FA_MODIFIED          0x01 /* "Bit 7" */

#define FA_DISPLAY_BITS_MASK                                          0x0C /* "Bits 4,5" */
#define  FA_DISPLAY_BITS_DISPLAY_NOT_SELECTOR_PEN_DETECTABLE           0x00
#define  FA_DISPLAY_BITS_DISPLAY_SELECTOR_PEN_DETECTABLE               0x01
#define  FA_DISPLAY_BITS_INTENSIFIED_DISPLAY_SELECTOR_PEN_DETECTABLE   0x02
#define  FA_DISPLAY_BITS_NON_DISPLAY_NON_DETECTABLE                    0x03

static const value_string vals_fa_display[] = {
  { FA_DISPLAY_BITS_DISPLAY_NOT_SELECTOR_PEN_DETECTABLE,         "Display/Not Selector Pen Detectable" },
  { FA_DISPLAY_BITS_DISPLAY_SELECTOR_PEN_DETECTABLE,             "Display/Selector Pen Detectable" },
  { FA_DISPLAY_BITS_INTENSIFIED_DISPLAY_SELECTOR_PEN_DETECTABLE, "Intensified Display/Selector Pen Detectable" },
  { FA_DISPLAY_BITS_NON_DISPLAY_NON_DETECTABLE,                  "Non Display, Non Detectable (not printable)" },
  { 0x00, NULL }
};

/*--- 4.4.5 Attribute Types ----- */
#define AT_ALL_CHARACTER_ATTRIBUTES  0x00
#define AT_T3270_FIELD_ATTRIBUTE     0xC0
#define AT_FIELD_VALIDATION          0xC1
#define AT_FIELD_OUTLINING           0xC2
#define AT_EXTENDED_HIGHLIGHTING     0x41
#define AT_FOREGROUND_COLOR          0x42
#define AT_CHARACTER_SET             0x43
#define AT_BACKGROUND_COLOR          0x45
#define AT_TRANSPARENCY              0x46


static const value_string vals_attribute_types[] = {
  { AT_ALL_CHARACTER_ATTRIBUTES, "All character attributes" },
  { AT_T3270_FIELD_ATTRIBUTE,    "3270 Field attribute" },
  { AT_FIELD_VALIDATION,         "Field validation" },
  { AT_FIELD_OUTLINING,          "Field outlining" },
  { AT_EXTENDED_HIGHLIGHTING,    "Extended highlighting" },
  { AT_FOREGROUND_COLOR,         "Foreground color" },
  { AT_CHARACTER_SET,            "Character set" },
  { AT_BACKGROUND_COLOR,         "Background color" },
  { AT_TRANSPARENCY,             "Transparency" },
  { 0x00, NULL }
};

/*--- 4.4.6.3 Extended Highlighting ----- */
#define AT_EH_DEFAULT_HIGHLIGHTING  0x00
#define AT_EH_NORMAL                0xF0
#define AT_EH_BLINK                 0xF1
#define AT_EH_REVERSE_VIDEO         0xF2
#define AT_EH_UNDERSCORE            0xF4

static const value_string vals_at_extended_highlighting[] = {
  { AT_EH_DEFAULT_HIGHLIGHTING, "Default" },
  { AT_EH_NORMAL,               "Normal (as determined by the 3270 field attribute)" },
  { AT_EH_BLINK,                "Blink" },
  { AT_EH_REVERSE_VIDEO,        "Reverse video" },
  { AT_EH_UNDERSCORE,           "Underscore." },
  { 0x00, NULL }
};

/*--- 4.4.6.4 Color Identifications ----- */
#define AT_CI_ALL_PLANES      0x00
#define AT_CI_BLUE_PLANE      0x01
#define AT_CI_RED_PLANE       0x02
#define AT_CI_GREEN_PLANE     0x04
#define AT_CI_NEUTRAL1        0xF0
#define AT_CI_BLUE            0xF1
#define AT_CI_RED             0xF2
#define AT_CI_PINK            0xF3
#define AT_CI_GREEN           0xF4
#define AT_CI_TURQUOISE       0xF5
#define AT_CI_YELLOW          0xF6
#define AT_CI_NEUTRAL2        0xF7
#define AT_CI_BLACK           0xF8
#define AT_CI_DEEP_BLUE       0xF9
#define AT_CI_ORANGE          0xFA
#define AT_CI_PURPLE          0xFB
#define AT_CI_PALE_GREEN      0xFC
#define AT_CI_PALE_TURQUOISE  0xFD
#define AT_CI_GREY            0xFE
#define AT_CI_WHITE           0xFF


static const value_string vals_at_color_identifications[] = {
  { AT_CI_ALL_PLANES,     "ALL PLANES" },
  { AT_CI_BLUE_PLANE,     "BLUE PLANE" },
  { AT_CI_RED_PLANE,      "RED PLANE" },
  { AT_CI_GREEN_PLANE,    "GREEN PLANE" },
  { AT_CI_NEUTRAL1,       "Neutral" },
  { AT_CI_BLUE,           "Blue" },
  { AT_CI_RED,            "Red" },
  { AT_CI_PINK,           "Pink" },
  { AT_CI_GREEN,          "Green" },
  { AT_CI_TURQUOISE,      "Turquoise" },
  { AT_CI_YELLOW,         "Yellow" },
  { AT_CI_NEUTRAL2,       "Neutral" },
  { AT_CI_BLACK,          "Black" },
  { AT_CI_DEEP_BLUE,      "Deep Blue" },
  { AT_CI_ORANGE,         "Orange" },
  { AT_CI_PURPLE,         "Purple" },
  { AT_CI_PALE_GREEN,     "Pale Green" },
  { AT_CI_PALE_TURQUOISE, "Pale Turquoise" },
  { AT_CI_GREY,           "Grey" },
  { AT_CI_WHITE,          "White" },
  { 0x00, NULL }
};

/*--- 4.4.6.5 Character Set ----- */
#define AT_CS_DEFAULT_CHARACTER_SET                           0x00
#define AT_CS_MIN_LOCAL_ID_FOR_LOADABLE_CHARACTER_SETS        0x40
#define AT_CS_MAX_LOCAL_ID_FOR_LOADABLE_CHARACTER_SETS        0xEF
#define AT_CS_MIN_LOCAL_ID_FOR_NONLOADABLE_CHARACTER_SETS     0xF0
#define AT_CS_MAX_LOCAL_ID_FOR_NONLOADABLE_CHARACTER_SETS     0xF7
#define AT_CS_MIN_LOCAL_ID_FOR_TWO_BYTE_CODED_CHARACTER_SETS  0xF8
#define AT_CS_MAX_LOCAL_ID_FOR_TWO_BYTE_CODED_CHARACTER_SETS  0xFE

static const range_string rvals_at_character_set[] = {
  { AT_CS_DEFAULT_CHARACTER_SET,
    AT_CS_DEFAULT_CHARACTER_SET,
    "Default Character Set" },
  { AT_CS_MIN_LOCAL_ID_FOR_LOADABLE_CHARACTER_SETS,
    AT_CS_MAX_LOCAL_ID_FOR_LOADABLE_CHARACTER_SETS,
    "Local Id For Loadable Character Sets" },
  { AT_CS_MIN_LOCAL_ID_FOR_NONLOADABLE_CHARACTER_SETS,
    AT_CS_MAX_LOCAL_ID_FOR_NONLOADABLE_CHARACTER_SETS,
    "Local Id For Nonloadable Character Sets" },
  { AT_CS_MIN_LOCAL_ID_FOR_TWO_BYTE_CODED_CHARACTER_SETS,
    AT_CS_MAX_LOCAL_ID_FOR_TWO_BYTE_CODED_CHARACTER_SETS,
    "Local Id For Two Byte Coded Character Sets" },
  { 0,           0,          NULL                   }
};

/*--- 4.4.6.6 Field Outlining ----- */
#define AT_FO_NO_OUTLINING_LINES                   0X00
#define AT_FO_UNDERLINE_ONLY                       0X01
#define AT_FO_RIGHT_VERTICAL_LINE_ONLY             0X02
#define AT_FO_OVERLINE_ONLY                        0X04
#define AT_FO_LEFT_VERTICAL_LINE_ONLY              0X08
#define AT_FO_UNDERLINE_AND_RIGHT_VERTICAL_LINE    0X03
#define AT_FO_UNDERLINE_AND_OVERLINE               0X05
#define AT_FO_UNDERLINE_AND_LEFT_VERTICAL_LINE     0X09
#define AT_FO_RIGHT_VERTICAL_LINE_AND_OVERLINE     0X06
#define AT_FO_RIGHT_AND_LEFT_VERTICAL_LINES        0X0A
#define AT_FO_OVERLINE_AND_LEFT_VERTICAL_LINE      0X0C
#define AT_FO_RECTANGLE_MINUS_LEFT_VERTICAL_LINE   0X07
#define AT_FO_RECTANGLE_MINUS_OVERLINE             0X0B
#define AT_FO_RECTANGLE_MINUS_RIGHT_VERTICAL_LINE  0X0D
#define AT_FO_RECTANGLE_MINUS_UNDERLINE            0X0E
#define AT_FO_RECTANGLE                            0X0F

static const value_string vals_at_field_outlining[] = {
  { AT_FO_NO_OUTLINING_LINES,                  "No outlining lines" },
  { AT_FO_UNDERLINE_ONLY,                      "Underline only" },
  { AT_FO_RIGHT_VERTICAL_LINE_ONLY,            "Right vertical line only" },
  { AT_FO_OVERLINE_ONLY,                       "Overline only" },
  { AT_FO_LEFT_VERTICAL_LINE_ONLY,             "Left vertical line only" },
  { AT_FO_UNDERLINE_AND_RIGHT_VERTICAL_LINE,   "Underline and right vertical line" },
  { AT_FO_UNDERLINE_AND_OVERLINE,              "Underline and overline" },
  { AT_FO_UNDERLINE_AND_LEFT_VERTICAL_LINE,    "Underline and left vertical line" },
  { AT_FO_RIGHT_VERTICAL_LINE_AND_OVERLINE,    "Right vertical line and overline" },
  { AT_FO_RIGHT_AND_LEFT_VERTICAL_LINES,       "Right and left vertical lines" },
  { AT_FO_OVERLINE_AND_LEFT_VERTICAL_LINE,     "Overline and left vertical line" },
  { AT_FO_RECTANGLE_MINUS_LEFT_VERTICAL_LINE,  "Rectangle minus left vertical line" },
  { AT_FO_RECTANGLE_MINUS_OVERLINE,            "Rectangle minus overline" },
  { AT_FO_RECTANGLE_MINUS_RIGHT_VERTICAL_LINE, "Rectangle minus right vertical line" },
  { AT_FO_RECTANGLE_MINUS_UNDERLINE,           "Rectangle minus underline" },
  { AT_FO_RECTANGLE,                           "Rectangle" },
  { 0x00, NULL }
};

/*--- 4.4.6.7 Transparency ----- */
#define AT_TR_DEFAULT_TRANSPARENCY           0X00
#define AT_TR_BACKGROUND_IS_TRANSPARENT_OR   0XF0
#define AT_TR_BACKGROUND_IS_TRANSPARENT_XOR  0XF1
#define AT_TR_BACKGROUND_IS_OPAQUE           0XFF

static const value_string vals_at_transparency[] = {
  { AT_TR_DEFAULT_TRANSPARENCY,          "Default" },
  { AT_TR_BACKGROUND_IS_TRANSPARENT_OR,  "Background is transparent (OR)" },
  { AT_TR_BACKGROUND_IS_TRANSPARENT_XOR, "Background is transparent (XOR)" },
  { AT_TR_BACKGROUND_IS_OPAQUE,          "Background is opaque (non-transparent)" },
  { 0x00, NULL }
};

/*--- 4.4.6.8 Field Validation ----- */
#define AT_FV_MANDATORY_FILL         0x04 /* "Bit 5" */
#define AT_FV_MANDATORY_ENTRY        0x02 /* "Bit 6" */
#define AT_FV_TRIGGER                0x01 /* "Bit 7" */

static const struct true_false_string tn3270_field_validation_mandatory_fill = {
  "Mandatory fill",
  ""
};

static const struct true_false_string tn3270_field_validation_mandatory_entry = {
  "Mandatory entry",
  ""
};

static const struct true_false_string tn3270_field_validation_trigger = {
  "Trigger",
  ""
};

/*--- 5.1 Outbound Structured Fields ----- */
#define SF_OB_ACTIVATE_PARTITION             0x0E
#define SF_OB_BEGIN_OR_END_OF_FILE           0x0F85
#define SF_OB_CREATE_PARTITION               0x0C
#define SF_OB_DESTROY_PARTITION              0x0D
#define SF_OB_ERASE_OR_RESET                 0x03
#define SF_OB_LOAD_COLOR_TABLE               0x0F05
#define SF_OB_LOAD_FORMAT_STORAGE            0x0F24
#define SF_OB_LOAD_LINE_TYPE                 0x0F07
#define SF_OB_LOAD_PROGRAMMED_SYMBOLS        0x06
#define SF_OB_MODIFY_PARTITION               0x0F0A
#define SF_OB_OUTBOUND_TEXT_HEADER           0x0F71
#define SF_OB_OUTBOUND_3270DS                0x40
#define SF_OB_PRESENT_ABSOLUTE_FORMAT        0x4B
#define SF_OB_PRESENT_RELATIVE_FORMAT        0x4C
#define SF_OB_SET_PARTITION_CHARACTERISTICS  0x0F08
#define SF_OB_SET_REPLY_MODE                 0x09
#define SF_OB_TYPE_1_TEXT_OUTBOUND           0x0FC1
#define SF_OB_READ_PARTITION                 0x01
#define SF_OB_REQUEST_RECOVERY_DATA          0x1030
#define SF_OB_RESET_PARTITION                0x00
#define SF_OB_RESTART                        0x1033
#define SF_OB_SCS_DATA                       0x41
#define SF_OB_SELECT_COLOR_TABLE             0x0F04
#define SF_OB_SELECT_FORMAT_GROUP            0x4A
#define SF_OB_SET_CHECKPOINT_INTERVAL        0x1032
#define SF_OB_SET_MSR_CONTROL                0x0F01
#define SF_OB_SET_PRINTER_CHARACTERISTICS    0x0F84
#define SF_OB_SET_WINDOW_ORIGIN              0x0B


static const value_string vals_outbound_structured_fields[] = {
  { SF_OB_ACTIVATE_PARTITION,            "Activate Partition" },
  { SF_OB_BEGIN_OR_END_OF_FILE,          "Begin Or End Of File" },
  { SF_OB_CREATE_PARTITION,              "Create Partition" },
  { SF_OB_DESTROY_PARTITION,             "Destroy Partition" },
  { SF_OB_ERASE_OR_RESET,                "Erase Or Reset" },
  { SF_OB_LOAD_COLOR_TABLE,              "Load Color Table" },
  { SF_OB_LOAD_FORMAT_STORAGE,           "Load Format Storage" },
  { SF_OB_LOAD_LINE_TYPE,                "Load Line Type" },
  { SF_OB_LOAD_PROGRAMMED_SYMBOLS,       "Load Programmed Symbols" },
  { SF_OB_MODIFY_PARTITION,              "Modify Partition" },
  { SF_OB_OUTBOUND_TEXT_HEADER,          "Outbound Text Header" },
  { SF_OB_OUTBOUND_3270DS,               "Outbound 3270ds" },
  { SF_OB_PRESENT_ABSOLUTE_FORMAT,       "Present Absolute Format" },
  { SF_OB_PRESENT_RELATIVE_FORMAT,       "Present Relative Format" },
  { SF_OB_SET_PARTITION_CHARACTERISTICS, "Set Partition Characteristics" },
  { SF_OB_SET_REPLY_MODE,                "Set Reply Mode" },
  { SF_OB_TYPE_1_TEXT_OUTBOUND,          "Type 1 Text Outbound" },
  { SF_OB_READ_PARTITION,                "Read Partition" },
  { SF_OB_REQUEST_RECOVERY_DATA,         "Request Recovery Data" },
  { SF_OB_RESET_PARTITION,               "Reset Partition" },
  { SF_OB_RESTART,                       "Restart" },
  { SF_OB_SCS_DATA,                      "Scs Data" },
  { SF_OB_SELECT_COLOR_TABLE,            "Select Color Table" },
  { SF_OB_SELECT_FORMAT_GROUP,           "Select Format Group" },
  { SF_OB_SET_CHECKPOINT_INTERVAL,       "Set Checkpoint Interval" },
  { SF_OB_SET_MSR_CONTROL,               "Set Msr Control" },
  { SF_OB_SET_PRINTER_CHARACTERISTICS,   "Set Printer Characteristics" },
  { SF_OB_SET_WINDOW_ORIGIN,             "Set Window Origin" },
  { 0x00, NULL }
};

/*--- 5.1 Outbound/Inbound Structured Fields ----- */
#define SF_OB_IB_DATA_CHAIN              0x0F21
#define SF_OB_IB_DESTINATION_OR_ORIGIN   0x0F02
#define SF_OB_IB_OBJECT_CONTROL          0x0F11
#define SF_OB_IB_OBJECT_DATA             0x0F0F
#define SF_OB_IB_OBJECT_PICTURE          0x0F10
#define SF_OB_IB_OEM_DATA                0x0F1F
#define SF_OB_IB_SAVE_OR_RESTORE_FORMAT  0x1034
#define SF_OB_IB_SELECT_IPDS_MODE        0x0F83

static const value_string vals_outbound_inbound_structured_fields[] = {
  { SF_OB_IB_DATA_CHAIN,             "Data Chain" },
  { SF_OB_IB_DESTINATION_OR_ORIGIN,  "Destination/Origin" },
  { SF_OB_IB_OBJECT_CONTROL,         "Object Control" },
  { SF_OB_IB_OBJECT_DATA,            "Object Data" },
  { SF_OB_IB_OBJECT_PICTURE,         "Object Picture" },
  { SF_OB_IB_OEM_DATA,               "OEM Data" },
  { SF_OB_IB_SAVE_OR_RESTORE_FORMAT, "Save/Restore Format" },
  { SF_OB_IB_SELECT_IPDS_MODE,       "Select IPDS Mode." },
  { 0x00, NULL }
};

/*--- 5.11 Load Format Storage ----- */
#define LOAD_FORMAT_STORAGE_OPERAND_ADD                     0x01
#define LOAD_FORMAT_STORAGE_OPERAND_DELETE_FORMAT           0x02
#define LOAD_FORMAT_STORAGE_OPERAND_DELETE_GROUP            0x03
#define LOAD_FORMAT_STORAGE_OPERAND_RESET_ALL               0x04
#define LOAD_FORMAT_STORAGE_OPERAND_REQUEST_SUMMARY_STATUS  0x05
#define LOAD_FORMAT_STORAGE_OPERAND_REQUEST_GROUP_STATUS    0x06

static const value_string vals_load_storage_format_operand[] = {
  { LOAD_FORMAT_STORAGE_OPERAND_ADD,                     "Add" },
  { LOAD_FORMAT_STORAGE_OPERAND_DELETE_FORMAT,           "Delete Format" },
  { LOAD_FORMAT_STORAGE_OPERAND_DELETE_GROUP,            "Delete Group" },
  { LOAD_FORMAT_STORAGE_OPERAND_RESET_ALL,               "Reset All" },
  { LOAD_FORMAT_STORAGE_OPERAND_REQUEST_SUMMARY_STATUS,  "Request Summary Status" },
  { LOAD_FORMAT_STORAGE_OPERAND_REQUEST_GROUP_STATUS,    "Request Group Status" },
  { 0x00, NULL }
};

/*--- 5.19 Read Partition ----- */
#define READ_PARTITION_OPTYPE_QUERY              0x02
#define READ_PARTITION_OPTYPE_QUERY_LIST         0x03
#define READ_PARTITION_OPTYPE_READ_MODIFIED_ALL  0x6E
#define READ_PARTITION_OPTYPE_READ_BUFFER        0xF2
#define READ_PARTITION_OPTYPE_READ_MODIFIED      0xF6

static const value_string vals_read_partition_operation_type[] = {
  { READ_PARTITION_OPTYPE_QUERY,             "Read Partition Query" },
  { READ_PARTITION_OPTYPE_QUERY_LIST,        "Read Partition Query List" },
  { READ_PARTITION_OPTYPE_READ_MODIFIED_ALL, "Read Partition Read Modified All" },
  { READ_PARTITION_OPTYPE_READ_BUFFER,       "Read Partition Read Buffer" },
  { READ_PARTITION_OPTYPE_READ_MODIFIED,     "Read Partition Read Modified" },
  { 0x00, NULL }
};

#define READ_PARTITION_REQTYPE_MASK 0xC0
static const value_string vals_read_partition_reqtype[] = {
  { 0x00, "QCODE List" },
  { 0x01, "Equivalent + QCODE List" },
  { 0x02, "All" },
  { 0x00, NULL }
};

/*--- 5.34 Data Chain ----- */
#define DATA_CHAIN_GROUP_MASK           0x60
#define DATA_CHAIN_INBOUND_CONTROL_MASK 0x18

static const value_string vals_data_chain_group[] = {
  { 0x00, "Continue" },
  { 0x01, "End" },
  { 0x02, "Begin" },
  { 0x03, "Only" },
  { 0x00, NULL }
};

static const value_string vals_data_chain_inbound_control[] = {
  { 0x00, "No Change" },
  { 0x01, "Enable Inbound Data Chaining" },
  { 0x02, "Disable Inbound Data Chaining" },
  { 0x03, "Reserved" },
  { 0x00, NULL }
};

/*--- 5.35 Destination or Origin ----- */
#define DESTINATION_OR_ORIGIN_FLAGS_INPUT_CONTROL_MASK 0xC0

static const value_string vals_destination_or_origin_flags_input_control[] = {
  { 0x00, "Enable input" },
  { 0x01, "No Change" },
  { 0x02, "Disable Input" },
  { 0x03, "Reserved" },
  { 0x00, NULL }
};


/* INBOUND DATA STREAM (DISPLAY -> MAINFRAME PROGRAM) */

/*
  ______ _______ ________ _______
  |      |       |        |       |
  | AID  | Cursor address | Data |
  |      | (2 bytes)      |       |
  |      |       |        |       |
  |______|_______|________|_______|

  An inbound data stream can also consist of an AID (X'88') followed by
  structured fields as follows:
  ______ __________________ ________ ___________________
  |      |                  |        |                   |
  | AID  | Structured Field | ...... | Structured Field  |
  | 0x88 |                  |        |                   |
  |______|__________________|________|___________________|

*/


/*--- 3.5.6 Attention Identification Bytes (AID) ----- */
#define AID_NO_AID_GENERATED               0x60
#define AID_NO_AID_GENERATED_PRINTER_ONLY  0xE8
#define AID_STRUCTURED_FIELD               0x88
#define AID_READ_PARTITION_AID             0x61
#define AID_TRIGGER_ACTION                 0x7F
#define AID_TEST_REQ_AND_SYS_REQ           0xF0
#define AID_PF1_KEY                        0xF1
#define AID_PF2_KEY                        0xF2
#define AID_PF3_KEY                        0xF3
#define AID_PF4_KEY                        0xF4
#define AID_PF5_KEY                        0xF5
#define AID_PF6_KEY                        0xF6
#define AID_PF7_KEY                        0xF7
#define AID_PF8_KEY                        0xF8
#define AID_PF9_KEY                        0xF9
#define AID_PF10_KEY                       0x7A
#define AID_PF11_KEY                       0x7B
#define AID_PF12_KEY                       0x7C
#define AID_PF13_KEY                       0xC1
#define AID_PF14_KEY                       0xC2
#define AID_PF15_KEY                       0xC3
#define AID_PF16_KEY                       0xC4
#define AID_PF17_KEY                       0xC5
#define AID_PF18_KEY                       0xC6
#define AID_PF19_KEY                       0xC7
#define AID_PF20_KEY                       0xC8
#define AID_PF21_KEY                       0xC9
#define AID_PF22_KEY                       0x4A
#define AID_PF23_KEY                       0x4B
#define AID_PF24_KEY                       0x4C
#define AID_PA1_KEY                        0x6C
#define AID_PA2_KEY_CNCL                   0x6E
#define AID_PA3_KEY                        0x6B
#define AID_CLEAR_KEY                      0x6D
#define AID_CLEAR_PARTITION_KEY            0x6A
#define AID_ENTER_KEY                      0x7D
#define AID_SELECTOR_PEN_ATTENTION         0x7E
#define AID_OPERATOR_ID_READER             0xE6
#define AID_MAG_READER_NUMBER              0xE7

static const value_string vals_attention_identification_bytes[] = {
  { AID_NO_AID_GENERATED,              "No AID generated" },
  { AID_NO_AID_GENERATED_PRINTER_ONLY, "No AID generated (printer only)" },
  { AID_STRUCTURED_FIELD,              "Structured field" },
  { AID_READ_PARTITION_AID,            "Read partition" },
  { AID_TRIGGER_ACTION,                "Trigger action" },
  { AID_TEST_REQ_AND_SYS_REQ,          "Test Req and Sys Req" },
  { AID_PF1_KEY,                       "PF1 key" },
  { AID_PF2_KEY,                       "PF2 key" },
  { AID_PF3_KEY,                       "PF3 key" },
  { AID_PF4_KEY,                       "PF4 key" },
  { AID_PF5_KEY,                       "PF5 key" },
  { AID_PF6_KEY,                       "PF6 key" },
  { AID_PF7_KEY,                       "PF7 key" },
  { AID_PF8_KEY,                       "PF8 key" },
  { AID_PF9_KEY,                       "PF9 key" },
  { AID_PF10_KEY,                      "PF10 key" },
  { AID_PF11_KEY,                      "PF11 key" },
  { AID_PF12_KEY,                      "PF12 key" },
  { AID_PF13_KEY,                      "PF13 key" },
  { AID_PF14_KEY,                      "PF14 key" },
  { AID_PF15_KEY,                      "PF15 key" },
  { AID_PF16_KEY,                      "PF16 key" },
  { AID_PF17_KEY,                      "PF17 key" },
  { AID_PF18_KEY,                      "PF18 key" },
  { AID_PF19_KEY,                      "PF19 key" },
  { AID_PF20_KEY,                      "PF20 key" },
  { AID_PF21_KEY,                      "PF21 key" },
  { AID_PF22_KEY,                      "PF22 key" },
  { AID_PF23_KEY,                      "PF23 key" },
  { AID_PF24_KEY,                      "PF24 key" },
  { AID_PA1_KEY,                       "PA1 key" },
  { AID_PA2_KEY_CNCL,                  "PA2 key (Cncl)" },
  { AID_PA3_KEY,                       "PA3 key" },
  { AID_CLEAR_KEY,                     "Clear key" },
  { AID_CLEAR_PARTITION_KEY,           "Clear Partition key" },
  { AID_ENTER_KEY,                     "Enter key" },
  { AID_SELECTOR_PEN_ATTENTION,        "Selector pen attention" },
  { AID_OPERATOR_ID_READER,            "Operator ID reader" },
  { AID_MAG_READER_NUMBER,             "Mag Reader Number" },
  { 0x00, NULL }
};

/*--- 5.3.6 Object Control ----- */
#define OBJC_GRAPHICS  0x00
#define OBJC_IMAGE     0x01

static const value_string vals_oc_type[] = {
  { OBJC_GRAPHICS, "Graphics" },
  { OBJC_IMAGE,    "Image)" },
  { 0x00, NULL }
};

/*--- 6.1 Inbound Structured Fields ----- */
#define SF_IB_EXCEPTION_OR_STATUS                            0x0F22
#define SF_IB_INBOUND_TEXT_HEADER                            0x0FB1
#define SF_IB_INBOUND_3270DS                                 0x0F80 /* TODO: Check */
#define SF_IB_RECOVERY_DATA                                  0x1031
#define SF_IB_TYPE_1_TEXT_INBOUND                            0x0FC1
#define SF_IB_QUERY_REPLY_ALPHANUMERIC_PARTITIONS            0x8184
#define SF_IB_QUERY_REPLY_AUXILIARY_DEVICE                   0x8199
#define SF_IB_QUERY_REPLY_BEGIN_OR_END_OF_FILE               0x819F
#define SF_IB_QUERY_REPLY_CHARACTER_SETS                     0x8185
#define SF_IB_QUERY_REPLY_COLOR                              0x8186
#define SF_IB_QUERY_REPLY_COOPERATIVE_PROCESSING_REQUESTOR   0x81AB
#define SF_IB_QUERY_REPLY_DATA_CHAINING                      0x8198
#define SF_IB_QUERY_REPLY_DATA_STREAMS                       0x81A2
#define SF_IB_QUERY_REPLY_DBCS_ASIA                          0x8191
#define SF_IB_QUERY_REPLY_DEVICE_CHARACTERISTICS             0x81A0
#define SF_IB_QUERY_REPLY_DISTRIBUTED_DATA_MANAGEMENT        0x8195
#define SF_IB_QUERY_REPLY_DOCUMENT_INTERCHANGE_ARCHITECTURE  0x8197
#define SF_IB_QUERY_REPLY_EXTENDED_DRAWING_ROUTINE           0x81B5
#define SF_IB_QUERY_REPLY_FIELD_OUTLINING                    0x818C
#define SF_IB_QUERY_REPLY_FIELD_VALIDATION                   0x818A
#define SF_IB_QUERY_REPLY_FORMAT_PRESENTATION                0x8190
#define SF_IB_QUERY_REPLY_FORMAT_STORAGE_AUXILIARY_DEVICE    0x8194
#define SF_IB_QUERY_REPLY_GRAPHIC_COLOR                      0x81B4
#define SF_IB_QUERY_REPLY_GRAPHIC_SYMBOL_SETS                0x81B6
#define SF_IB_QUERY_REPLY_HIGHLIGHTING                       0x8187
#define SF_IB_QUERY_REPLY_IBM_AUXILIARY_DEVICE               0x819E
#define SF_IB_QUERY_REPLY_IMAGE                              0x8182
#define SF_IB_QUERY_REPLY_IMPLICIT_PARTITION                 0x81A6
#define SF_IB_QUERY_REPLY_IOCA_AUXILIARY_DEVICE              0x81AA
#define SF_IB_QUERY_REPLY_LINE_TYPE                          0x81B2
#define SF_IB_QUERY_REPLY_MSR_CONTROL                        0x818B
#define SF_IB_QUERY_REPLY_NULL                               0x81FF
#define SF_IB_QUERY_REPLY_OEM_AUXILIARY_DEVICE               0x818F
#define SF_IB_QUERY_REPLY_PAPER_FEED_TECHNIQUES              0x81A7
#define SF_IB_QUERY_REPLY_PARTITION_CHARACTERISTICS          0x818E
#define SF_IB_QUERY_REPLY_PORT                               0x81B3
#define SF_IB_QUERY_REPLY_PROCEDURE                          0x81B1
#define SF_IB_QUERY_REPLY_PRODUCT_DEFINED_DATA_STREAM        0x819C
#define SF_IB_QUERY_REPLY_REPLY_MODES                        0x8188
#define SF_IB_QUERY_REPLY_RPQ_NAMES                          0x81A1
#define SF_IB_QUERY_REPLY_SAVE_OR_RESTORE_FORMAT             0x8192
#define SF_IB_QUERY_REPLY_SEGMENT                            0x81B0
#define SF_IB_QUERY_REPLY_SETTABLE_PRINTER_CHARACTERISTICS   0x81A9
#define SF_IB_QUERY_REPLY_STORAGE_POOLS                      0x8196
#define SF_IB_QUERY_REPLY_SUMMARY                            0x8180
#define SF_IB_QUERY_REPLY_TEXT_PARTITIONS                    0x8183
#define SF_IB_QUERY_REPLY_TRANSPARENCY                       0x81A8
#define SF_IB_QUERY_REPLY_USABLE_AREA                        0x8181
#define SF_IB_QUERY_REPLY_3270_IPDS                          0x819A

static const value_string vals_inbound_structured_fields[] = {
  { SF_IB_EXCEPTION_OR_STATUS,                           "Exception/Status" },
  { SF_IB_INBOUND_TEXT_HEADER,                           "Inbound Text Header" },
  { SF_IB_INBOUND_3270DS,                                "Inbound 3270DS" },
  { SF_IB_RECOVERY_DATA,                                 "Recovery Data" },
  { SF_IB_TYPE_1_TEXT_INBOUND,                           "Type 1 Text Inbound" },
  { SF_IB_QUERY_REPLY_ALPHANUMERIC_PARTITIONS,           "Query Reply (Alphanumeric Partitions)" },
  { SF_IB_QUERY_REPLY_AUXILIARY_DEVICE,                  "Query Reply (Auxiliary Device)" },
  { SF_IB_QUERY_REPLY_BEGIN_OR_END_OF_FILE,              "Query Reply (Begin/End of File)" },
  { SF_IB_QUERY_REPLY_CHARACTER_SETS,                    "Query Reply (Character Sets)" },
  { SF_IB_QUERY_REPLY_COLOR,                             "Query Reply (Color)" },
  { SF_IB_QUERY_REPLY_COOPERATIVE_PROCESSING_REQUESTOR,  "Query Reply (Cooperative Processing Requestor)" },
  { SF_IB_QUERY_REPLY_DATA_CHAINING,                     "Query Reply (Data Chaining)" },
  { SF_IB_QUERY_REPLY_DATA_STREAMS,                      "Query Reply (Data Streams)" },
  { SF_IB_QUERY_REPLY_DBCS_ASIA,                         "Query Reply (DBCS-Asia)" },
  { SF_IB_QUERY_REPLY_DEVICE_CHARACTERISTICS,            "Query Reply (Device Characteristics)" },
  { SF_IB_QUERY_REPLY_DISTRIBUTED_DATA_MANAGEMENT,       "Query Reply (Distributed Data Management)" },
  { SF_IB_QUERY_REPLY_DOCUMENT_INTERCHANGE_ARCHITECTURE, "Query Reply (Document Interchange Architecture)" },
  { SF_IB_QUERY_REPLY_EXTENDED_DRAWING_ROUTINE,          "Query Reply (Extended Drawing Routine)" },
  { SF_IB_QUERY_REPLY_FIELD_OUTLINING,                   "Query Reply (Field Outlining)" },
  { SF_IB_QUERY_REPLY_FIELD_VALIDATION,                  "Query Reply (Field Validation)" },
  { SF_IB_QUERY_REPLY_FORMAT_PRESENTATION,               "Query Reply (Format Presentation)" },
  { SF_IB_QUERY_REPLY_FORMAT_STORAGE_AUXILIARY_DEVICE,   "Query Reply (Format Storage Auxiliary Device)" },
  { SF_IB_QUERY_REPLY_GRAPHIC_COLOR,                     "Query Reply (Graphic Color)" },
  { SF_IB_QUERY_REPLY_GRAPHIC_SYMBOL_SETS,               "Query Reply (Graphic Symbol Sets)" },
  { SF_IB_QUERY_REPLY_HIGHLIGHTING,                      "Query Reply (Highlighting)" },
  { SF_IB_QUERY_REPLY_IBM_AUXILIARY_DEVICE,              "Query Reply (IBM Auxiliary Device)" },
  { SF_IB_QUERY_REPLY_IMAGE,                             "Query Reply (Image)" },
  { SF_IB_QUERY_REPLY_IMPLICIT_PARTITION,                "Query Reply (Implicit Partition)" },
  { SF_IB_QUERY_REPLY_IOCA_AUXILIARY_DEVICE,             "Query Reply (IOCA Auxiliary Device)" },
  { SF_IB_QUERY_REPLY_LINE_TYPE,                         "Query Reply (Line Type)" },
  { SF_IB_QUERY_REPLY_MSR_CONTROL,                       "Query Reply (MSR Control)" },
  { SF_IB_QUERY_REPLY_NULL,                              "Query Reply (Null)" },
  { SF_IB_QUERY_REPLY_OEM_AUXILIARY_DEVICE,              "Query Reply (OEM Auxiliary Device)" },
  { SF_IB_QUERY_REPLY_PAPER_FEED_TECHNIQUES,             "Query Reply (Paper Feed Techniques)" },
  { SF_IB_QUERY_REPLY_PARTITION_CHARACTERISTICS,         "Query Reply (Partition Characteristics)" },
  { SF_IB_QUERY_REPLY_PORT,                              "Query Reply (Port)" },
  { SF_IB_QUERY_REPLY_PROCEDURE,                         "Query Reply (Procedure)" },
  { SF_IB_QUERY_REPLY_PRODUCT_DEFINED_DATA_STREAM,       "Query Reply (Product Defined Data Stream)" },
  { SF_IB_QUERY_REPLY_REPLY_MODES,                       "Query Reply (Reply Modes)" },
  { SF_IB_QUERY_REPLY_RPQ_NAMES,                         "Query Reply (RPQ Names)" },
  { SF_IB_QUERY_REPLY_SAVE_OR_RESTORE_FORMAT,            "Query Reply (Save/Restore Format)" },
  { SF_IB_QUERY_REPLY_SEGMENT,                           "Query Reply (Segment)" },
  { SF_IB_QUERY_REPLY_SETTABLE_PRINTER_CHARACTERISTICS,  "Query Reply (Settable Printer Characteristics)" },
  { SF_IB_QUERY_REPLY_STORAGE_POOLS,                     "Query Reply (Storage Pools)" },
  { SF_IB_QUERY_REPLY_SUMMARY,                           "Query Reply (Summary)" },
  { SF_IB_QUERY_REPLY_TEXT_PARTITIONS,                   "Query Reply (Text Partitions)" },
  { SF_IB_QUERY_REPLY_TRANSPARENCY,                      "Query Reply (Transparency)" },
  { SF_IB_QUERY_REPLY_USABLE_AREA,                       "Query Reply (Usable Area)" },
  { SF_IB_QUERY_REPLY_3270_IPDS,                         "Query Reply (3270 IPDS)." },
  { 0x00, NULL }
};

/*--- 6.2 - Exception/Status ----- */
#define SDP_STATCODE_ACKNOWLEDGED     0x0000
#define SDP_STATCODE_AUXDEVICEAVAIL   0X0001

static const value_string vals_sdp_statcode[] = {
  { SDP_STATCODE_ACKNOWLEDGED,   "Acknowledged. The formats were successfully loaded, and no exception occurred." },
  { SDP_STATCODE_AUXDEVICEAVAIL, "Auxiliary device available" },
  { 0x00, NULL }
};

#define SDP_EXCODE_INVALID_DOID    0x0801
#define SDP_EXCODE_DEVICENOTAVAIL  0X0802
#define SDP_EXCODE_RETIRED         0X0803
#define SDP_EXCODE_BUFFER_OVERRUN  0X0804
#define SDP_EXCODE_STORAGE         0X0805
#define SDP_EXCODE_FORMATNOTSPEC   0X0806
#define SDP_EXCODE_DATAERROR       0X0807
#define SDP_EXCODE_INSUFFRESOURCE  0X084B
#define SDP_EXCODE_EXCEEDSLIMIT    0X084C
#define SDP_EXCODE_FUNCTNOTSUPP    0X1003

static const value_string vals_sdp_excode[] = {
  { SDP_EXCODE_INVALID_DOID,
    "Invalid/unrecognized DOID in the Destination/Origin structured field."
    " AVAILSTAT must be set to B'0'." },
  { SDP_EXCODE_DEVICENOTAVAIL,
    "DOID valid, but the auxiliary device is not available because of an"
    " intervention required condition (for example, out of paper, power"
    " off, or processing code not resident). Available status is sent"
    " when the condition clears. AVAILSTAT must be set to B'1'." },
  { SDP_EXCODE_RETIRED,
    "Retired." },
  { SDP_EXCODE_BUFFER_OVERRUN,
    "Buffer overrun." },
  { SDP_EXCODE_STORAGE,
    "Insufficient storage. The loading of the formats could not be"
    " completed because storage was exhausted." },
  { SDP_EXCODE_FORMATNOTSPEC,
    "The format or group name was not specified in the Load Format"
    " Storage structured field." },
  { SDP_EXCODE_DATAERROR,
    "Data error." },
  { SDP_EXCODE_INSUFFRESOURCE,
    "Temporary insufficient resource. The application does not have"
    " a buffer available or is busy. The device chooses whether to"
    " set send status when the condition clears and set AVAILSTAT accordingly." },
  { SDP_EXCODE_EXCEEDSLIMIT,
    "The auxiliary device data in the transmission exceeds the limit specified"
    " in the LIMOUT parameter of the Query Reply for the auxiliary device."
    " AVAILSTAT must be set to B'0'." },
  { SDP_EXCODE_FUNCTNOTSUPP,
    "Function not supported." },
  { 0x00, NULL }
};

/* Query Reply Types */
#define SF_QR_ALPHANUMERIC_PARTITIONS            0x84
#define SF_QR_AUXILIARY_DEVICE                   0x99
#define SF_QR_QBEGIN_OR_END_OF_FILE              0x9F
#define SF_QR_CHARACTER_SETS                     0x85
#define SF_QR_COLOR                              0x86
#define SF_QR_COOPERATIVE_PROCESSING_REQUESTOR   0xAB
#define SF_QR_DATA_CHAINING                      0x98
#define SF_QR_DATA_STREAMS                       0xA2
#define SF_QR_DBCS_ASIA                          0x91
#define SF_QR_DEVICE_CHARACTERISTICS             0xA0
#define SF_QR_DISTRIBUTED_DATA_MANAGEMENT        0x95
#define SF_QR_DOCUMENT_INTERCHANGE_ARCHITECTURE  0x97
#define SF_QR_EXTENDED_DRAWING_ROUTINE           0xB5
#define SF_QR_QFIELD_OUTLINING                   0x8C
#define SF_QR_QFIELD_VALIDATION                  0x8A
#define SF_QR_FORMAT_PRESENTATION                0x90
#define SF_QR_FORMAT_STORAGE_AUXILIARY_DEVICE    0x94
#define SF_QR_GRAPHIC_COLOR                      0xB4
#define SF_QR_GRAPHIC_SYMBOL_SETS                0xB6
#define SF_QR_HIGHLIGHTING                       0x87
#define SF_QR_IBM_AUXILIARY_DEVICE               0x9E
#define SF_QR_IMAGE                              0x82
#define SF_QR_IMPLICIT_PARTITION                 0xA6
#define SF_QR_IOCA_AUXILIARY_DEVICE              0xAA
#define SF_QR_LINE_TYPE                          0xB2
#define SF_QR_MSR_CONTROL                        0x8B
#define SF_QR_QNULL                              0xFF
#define SF_QR_OEM_AUXILIARY_DEVICE               0x8F
#define SF_QR_PAPER_FEED_TECHNIQUES              0xA7
#define SF_QR_PARTITION_CHARACTERISTICS          0x8E
#define SF_QR_PORT                               0xB3
#define SF_QR_PROCEDURE                          0xB1
#define SF_QR_PRODUCT_DEFINED_DATA_STREAM        0x9C
#define SF_QR_REPLY_MODES                        0x88
#define SF_QR_RPQ_NAMES                          0xA1
#define SF_QR_QSAVE_OR_RESTORE_FORMAT            0x92
#define SF_QR_SEGMENT                            0xB0
#define SF_QR_SETTABLE_PRINTER_CHARACTERISTICS   0xA9
#define SF_QR_STORAGE_POOLS                      0x96
#define SF_QR_SUMMARY                            0x80
#define SF_QR_TEXT_PARTITIONS                    0x83
#define SF_QR_QTRANSPARENCY                      0xA8
#define SF_QR_USABLE_AREA                        0x81
#define SF_QR_T3270_IPDS                         0x9A

static const value_string vals_sf_query_replies[] = {
  { SF_QR_ALPHANUMERIC_PARTITIONS,           "Alphanumeric Partitions" },
  { SF_QR_AUXILIARY_DEVICE,                  "Auxiliary Device" },
  { SF_QR_QBEGIN_OR_END_OF_FILE,             "Begin/End of File" },
  { SF_QR_CHARACTER_SETS,                    "Character Sets" },
  { SF_QR_COLOR,                             "Color" },
  { SF_QR_COOPERATIVE_PROCESSING_REQUESTOR,  "Cooperative Processing Requestor" },
  { SF_QR_DATA_CHAINING,                     "Data Chaining" },
  { SF_QR_DATA_STREAMS,                      "Data Streams" },
  { SF_QR_DBCS_ASIA,                         "DBCS-Asia" },
  { SF_QR_DEVICE_CHARACTERISTICS,            "Device Characteristics" },
  { SF_QR_DISTRIBUTED_DATA_MANAGEMENT,       "Distributed Data Management" },
  { SF_QR_DOCUMENT_INTERCHANGE_ARCHITECTURE, "Document Interchange Architecture" },
  { SF_QR_EXTENDED_DRAWING_ROUTINE,          "Extended Drawing Routine" },
  { SF_QR_QFIELD_OUTLINING,                  "Field Outlining" },
  { SF_QR_QFIELD_VALIDATION,                 "Field Validation" },
  { SF_QR_FORMAT_PRESENTATION,               "Format Presentation" },
  { SF_QR_FORMAT_STORAGE_AUXILIARY_DEVICE,   "Format Storage Auxiliary Device" },
  { SF_QR_GRAPHIC_COLOR,                     "Graphic Color" },
  { SF_QR_GRAPHIC_SYMBOL_SETS,               "Graphic Symbol Sets" },
  { SF_QR_HIGHLIGHTING,                      "Highlighting" },
  { SF_QR_IBM_AUXILIARY_DEVICE,              "IBM Auxiliary Device" },
  { SF_QR_IMAGE,                             "Image" },
  { SF_QR_IMPLICIT_PARTITION,                "Implicit Partition" },
  { SF_QR_IOCA_AUXILIARY_DEVICE,             "IOCA Auxiliary Device" },
  { SF_QR_LINE_TYPE,                         "Line Type" },
  { SF_QR_MSR_CONTROL,                       "MSR Control" },
  { SF_QR_QNULL,                             "Null" },
  { SF_QR_OEM_AUXILIARY_DEVICE,              "OEM Auxiliary Device" },
  { SF_QR_PAPER_FEED_TECHNIQUES,             "Paper Feed Techniques" },
  { SF_QR_PARTITION_CHARACTERISTICS,         "Partition Characteristics" },
  { SF_QR_PORT,                              "Port" },
  { SF_QR_PROCEDURE,                         "Procedure" },
  { SF_QR_PRODUCT_DEFINED_DATA_STREAM,       "Product Defined Data Stream" },
  { SF_QR_REPLY_MODES,                       "Reply Modes" },
  { SF_QR_RPQ_NAMES,                         "RPQ Names" },
  { SF_QR_QSAVE_OR_RESTORE_FORMAT,           "Save/Restore Format" },
  { SF_QR_SEGMENT,                           "Segment" },
  { SF_QR_SETTABLE_PRINTER_CHARACTERISTICS,  "Settable Printer Characteristics" },
  { SF_QR_STORAGE_POOLS,                     "Storage Pools" },
  { SF_QR_SUMMARY,                           "Summary" },
  { SF_QR_TEXT_PARTITIONS,                   "Text Partitions" },
  { SF_QR_QTRANSPARENCY,                     "Transparency" },
  { SF_QR_USABLE_AREA,                       "Usable Area" },
  { SF_QR_T3270_IPDS,                        "3270 IPDS." },
  { 0x00, NULL }
};

/*--- 6.9 Query Reply Alphanumeric Partitions ----- */
#define QR_AP_VERTWIN  0x80
#define QR_AP_HORWIN   0x40
#define QR_AP_APRES1   0x20
#define QR_AP_APA_FLG  0x10
#define QR_AP_PROT     0x08
#define QR_AP_LCOPY    0x04
#define QR_AP_MODPART  0x02
#define QR_AP_APRES2   0x01

/*--- 6.12 - Query Reply (Character Sets) ----- */
#define QR_CS_ALT       0x80
#define QR_CS_MULTID    0x40
#define QR_CS_LOADABLE  0x20
#define QR_CS_EXT       0x10
#define QR_CS_MS        0x08
#define QR_CS_CH2       0x04
#define QR_CS_GF        0x02
#define QR_CS_CSRES     0x01

#define QR_CS_CSRES2    0x80
#define QR_CS_PSCS      0x40
#define QR_CS_CSRES3    0x20
#define QR_CS_CF        0x10
#define QR_CS_CSRES4    0x08
#define QR_CS_CSRES5    0x04
#define QR_CS_GCSRES6   0x02
#define QR_CS_CSRES7    0x01


/*--- 6.15 Query Reply (Data Chaining) ----- */
static const value_string vals_data_chaining_dir[] = {
  { 0x00, "Both" },
  { 0x01, "From device only" },
  { 0x02, "To device only" },
  { 0x00, NULL }
};

/*--- 6.16 Query Reply (Data Streams) ----- */
#define QR_DS_SCS       0x00
#define QR_DS_DCAL2     0x01
#define QR_DS_IPDS      0x02

static const value_string vals_data_streams[] = {
  { QR_DS_SCS,
    "SCS Base Data Stream with extensions as specified in the BIND request"
    " and Device Characteristics Query Reply structured field" },
  { QR_DS_DCAL2,
    "Document Content Architecture Level 2" },
  { QR_DS_IPDS,
    "IPDS as defined in related documentation" },
  { 0x00, NULL }
};

/*--- 6.51 Query Reply Usable Area ----- */
#define QR_UA_RESERVED1                         0x80
#define QR_UA_PAGE_PRINTER                      0x40
#define QR_UA_RESERVED2                         0x20
#define QR_UA_HARD_COPY                         0x10

#define QR_UA_ADDR_MODE_MASK                         0x0F
#define  QR_UA_ADDR_MODE_RESERVED1                    0x00
#define  QR_UA_ADDR_MODE_TWELVE_FOURTEEN_BIT_OK       0x01
#define  QR_UA_ADDR_MODE_RESERVED2                    0x02
#define  QR_UA_ADDR_MODE_TWELVE_FOURTEEN_SXTN_BIT_OK  0x03
#define  QR_UA_ADDR_MODE_UNMAPPED                     0x0F

static const value_string vals_usable_area_addr_mode[] = {
  { QR_UA_ADDR_MODE_RESERVED1,                    "Reserved" },
  { QR_UA_ADDR_MODE_TWELVE_FOURTEEN_BIT_OK,       "Twelve/Fourteen Bit Addressing Allowed" },
  { QR_UA_ADDR_MODE_RESERVED2,                    "Reserved" },
  { QR_UA_ADDR_MODE_TWELVE_FOURTEEN_SXTN_BIT_OK , "Twelve/Fourteen/Sixteen Bit Addressing Allowed" },
  { QR_UA_ADDR_MODE_UNMAPPED,                     "Unmapped" },
  { 0x00, NULL }
};

#define QR_UA_VARIABLE_CELLS  0x80
#define QR_UA_CHARACTERS      0x40
#define QR_UA_CELL_UNITS      0x20

static const struct true_false_string tn3270_tfs_ua_variable_cells = {
  "Supported",
  "Not supported"
};

static const struct true_false_string tn3270_tfs_ua_characters = {
  "Non-matrix character",
  "Matrix character"
};

static const struct true_false_string tn3270_tfs_ua_cell_units = {
  "Pels",
  "Cells"
};


#define QR_UA_UOM_INCHES       0x00
#define QR_UA_UOM_MILLIMETERS  0x01

static const value_string vals_usable_area_uom[] = {
  { QR_UA_UOM_INCHES,      "Inches" },
  { QR_UA_UOM_MILLIMETERS, "Millimeters" },
  { 0x00, NULL }
};

/*--- 6.42 - Query reply (Reply Modes) ----- */
/* Also for: 5.30 - Set Reply Mode */

#define RM_REPLY_FIELD_MODE           0x00
#define RM_REPLY_EXTENDED_FIELD_MODE  0x01
#define RM_REPLY_CHARACTER_MODE       0x02

static const value_string vals_reply_modes[] = {
  { RM_REPLY_FIELD_MODE,          "Field Mode" },
  { RM_REPLY_EXTENDED_FIELD_MODE, "Extended Field Mode" },
  { RM_REPLY_CHARACTER_MODE,      "Character Mode" },
  { 0x00, NULL }
};

/*--- 6.19 - Query Reply (Distributed Data Management) ----- */
#define QR_DDM_COPY_SUBSET_1  0x01

static const value_string vals_qr_ddm[] = {
  { QR_DDM_COPY_SUBSET_1, "DDM Copy Subset 1" },
  { 0x00, NULL }
};

/*--- 6.20 - Query Reply (Document Interchange Architecture) ----- */
#define QR_DIA_FILE_SERVER      0x01
#define QR_DIA_FILE_REQ         0x02
#define QR_DIA_FILE_SERVER_REQ  0x03

static const value_string vals_qr_dia[] = {
  { QR_DIA_FILE_SERVER,     "File Server" },
  { QR_DIA_FILE_REQ,        "File Requestor" },
  { QR_DIA_FILE_SERVER_REQ, "Both File Server and File Requestor" },
  { 0x00, NULL }
};

/*--- 6.31 - Query Reply (Implicit Partitions) ----- */
#define QR_IP_SDP_DISPLAY    0x01
#define QR_IP_SDP_PRINTER    0x02
#define QR_IP_SDP_CHARACTER  0x03

#if 0
static const value_string vals_qr_ip[] = {
  { QR_IP_SDP_DISPLAY,   "Display Devices" },
  { QR_IP_SDP_PRINTER,   "Printer Devices" },
  { QR_IP_SDP_CHARACTER, "Character Devices" },
  { 0x00, NULL }
};
#endif

/*--- 6.41 - Query Reply (Product Defined Data Streams) ----- */
#define QR_PDDS_REFID_GRAPH5080  0x01
#define QR_PDDS_REFID_WHIPAPI    0x02

static const value_string vals_qr_pdds_refid[] = {
  { QR_PDDS_REFID_GRAPH5080, "Supports the 5080 Graphics System" },
  { QR_PDDS_REFID_WHIPAPI,   "Supports the WHIP API data stream" },
  { 0x00, NULL }
};

#define QR_PDDS_SSID_HFGD   0x01
#define QR_PDDS_SSID_RS232  0x02

static const value_string vals_qr_pdds_ssid[] = {
  { QR_PDDS_SSID_HFGD , "5080 HFGD Graphics Subset" },
  { QR_PDDS_SSID_RS232, "5080 RS232 Ports Subset" },
  { 0x00, NULL }
};

/*--- 6.47 - Query Reply (Storage Pools) ----- */
#define QR_SP_OBJ_SEGMENT1          0x0001
#define QR_SP_OBJ_PROCEDURE1        0x0002
#define QR_SP_OBJ_EXTENDED_DRAWING  0x0003
#define QR_SP_OBJ_DATA_UNIT         0x0004
#define QR_SP_OBJ_TEMPORARY         0x0005
#define QR_SP_OBJ_LINE_TYPE1        0x0006
#define QR_SP_OBJ_SYMBOL_SET        0x0007

static const value_string vals_sp_objlist[] = {
  { QR_SP_OBJ_SEGMENT1,         "Segment" },
  { QR_SP_OBJ_PROCEDURE1,       "Procedure" },
  { QR_SP_OBJ_EXTENDED_DRAWING, "Extended drawing routine" },
  { QR_SP_OBJ_DATA_UNIT,        "Data unit" },
  { QR_SP_OBJ_TEMPORARY,        "Temporary" },
  { QR_SP_OBJ_LINE_TYPE1,       "Line type" },
  { QR_SP_OBJ_SYMBOL_SET,       "Symbol set" },
  { 0x00, NULL }
};

/* TN3270E Header - Data Type */
#define TN3270E_3270_DATA     0x00
#define TN3270E_BIND_IMAGE    0x03
#define TN3270E_NVT_DATA      0x05
#define TN3270E_REQUEST       0x06
#define TN3270E_RESPONSE      0x02
#define TN3270E_SCS_DATA      0x01
#define TN3270E_SSCP_LU_DATA  0x07
#define TN3270E_UNBIND        0x04

static const value_string vals_tn3270_header_data_types[] = {
  { TN3270E_3270_DATA,    "3270_DATA" },
  { TN3270E_BIND_IMAGE,   "BIND_IMAGE" },
  { TN3270E_NVT_DATA,     "NVT_DATA" },
  { TN3270E_REQUEST,      "REQUEST" },
  { TN3270E_RESPONSE,     "RESPONSE" },
  { TN3270E_SCS_DATA,     "SCS_DATA" },
  { TN3270E_SSCP_LU_DATA, "SSCP_LU_DATA" },
  { TN3270E_UNBIND,       "UNBIND" },
  { 0x00, NULL }
};


/* TN3270E Header - Request Flags */
#define TN3270E_COND_CLEARED        0x00

static const value_string vals_tn3270_header_request_flags[] = {
  { TN3270E_COND_CLEARED, "Condition Cleared" },
  { 0x00, NULL }
};

/* TN3270E Header - Response Flags - Data Type 3270 and SCS */
#define TN3270E_NO_RESPONSE      0x00
#define TN3270E_ERROR_RESPONSE   0x01
#define TN3270E_ALWAYS_RESPONSE  0x02

static const value_string vals_tn3270_header_response_flags_3270_SCS[] = {
  { TN3270E_NO_RESPONSE,     "No-Response" },
  { TN3270E_ERROR_RESPONSE,  "Error-Response" },
  { TN3270E_ALWAYS_RESPONSE, "Always-Response" },
  { 0x00, NULL }
};

/* TN3270E Header _ Response Flags - Data Type Response */
#define TN3270E_POSITIVE_RESPONSE  0x00
#define TN3270E_NEGATIVE_RESPONSE  0x01

static const value_string vals_tn3270_header_response_flags_response[] = {
  { TN3270E_POSITIVE_RESPONSE, "Positive-Response" },
  { TN3270E_NEGATIVE_RESPONSE, "Negative-Response" },
  { 0x00, NULL }
};

/*
 * Data structure attached to a conversation, giving authentication
 * information from a bind request.
 */
typedef struct tn3270_conv_info_t {
  address outbound_addr;
  guint32 outbound_port;
  address inbound_addr;
  guint32 inbound_port;
  gint    extended;
  guint8  altrows;
  guint8  altcols;
  guint8  rows;
  guint8  cols;
} tn3270_conv_info_t;


static int proto_tn3270 = -1;

static int hf_tn3270_fa_display = -1;
static int hf_tn3270_fa_graphic_convert = -1;
static int hf_tn3270_fa_modified = -1;
static int hf_tn3270_fa_numeric = -1;
static int hf_tn3270_fa_protected = -1;
static int hf_tn3270_fa_reserved = -1;
static int hf_tn3270_field_attribute = -1;
static int hf_tn3270_aid = -1;
static int hf_tn3270_all_character_attributes = -1;
static int hf_tn3270_attribute_type = -1;
static int hf_tn3270_begin_end_flags1 = -1;
static int hf_tn3270_begin_end_flags2 = -1;
static int hf_tn3270_bsc = -1;
static int hf_tn3270_buffer_address = -1;
static int hf_tn3270_c_cav = -1;
static int hf_tn3270_cc = -1;
static int hf_tn3270_character_code = -1;
static int hf_tn3270_character_set = -1;
static int hf_tn3270_charset = -1;
static int hf_tn3270_checkpoint = -1;
static int hf_tn3270_c_ci = -1;
static int hf_tn3270_c_offset = -1;
static int hf_tn3270_color = -1;
static int hf_tn3270_color_command = -1;
static int hf_tn3270_color_flags = -1;
static int hf_tn3270_command_code = -1;
static int hf_tn3270_cro = -1;
static int hf_tn3270_c_scsoff = -1;
static int hf_tn3270_c_seqoff = -1;
static int hf_tn3270_c_sequence = -1;
static int hf_tn3270_cursor_address = -1;
static int hf_tn3270_cw = -1;
static int hf_tn3270_data_chain_fields = -1;
static int hf_tn3270_data_chain_group = -1;
static int hf_tn3270_data_chain_inbound_control = -1;
static int hf_tn3270_destination_or_origin_flags_input_control = -1;
static int hf_tn3270_destination_or_origin_doid = -1;
static int hf_tn3270_erase_flags = -1;
static int hf_tn3270_exception_or_status_flags = -1;
static int hf_tn3270_extended_highlighting = -1;
static int hf_tn3270_extended_ps_color = -1;
static int hf_tn3270_extended_ps_echar = -1;
static int hf_tn3270_extended_ps_flags = -1;
static int hf_tn3270_extended_ps_length = -1;
static int hf_tn3270_extended_ps_lw = -1;
static int hf_tn3270_extended_ps_lh = -1;
static int hf_tn3270_extended_ps_nh = -1;
static int hf_tn3270_extended_ps_nw = -1;
static int hf_tn3270_extended_ps_res = -1;
static int hf_tn3270_extended_ps_stsubs = -1;
static int hf_tn3270_extended_ps_subsn = -1;
static int hf_tn3270_featl = -1;
static int hf_tn3270_feats = -1;
static int hf_tn3270_field_data = -1;
static int hf_tn3270_field_outlining = -1;
static int hf_tn3270_field_validation_mandatory_entry = -1;
static int hf_tn3270_field_validation_mandatory_fill = -1;
static int hf_tn3270_field_validation_trigger = -1;
static int hf_tn3270_format_group = -1;
static int hf_tn3270_format_name = -1;
static int hf_tn3270_fov = -1;
static int hf_tn3270_fpc = -1;
static int hf_tn3270_hilite = -1;
static int hf_tn3270_h_length = -1;
static int hf_tn3270_h_offset = -1;
static int hf_tn3270_horizon = -1;
static int hf_tn3270_h_sequence = -1;
static int hf_tn3270_hw = -1;
static int hf_tn3270_interval = -1;
static int hf_tn3270_limin = -1;
static int hf_tn3270_limout = -1;
static int hf_tn3270_lines = -1;
static int hf_tn3270_load_color_command = -1;
static int hf_tn3270_load_format_storage_flags1 = -1;
static int hf_tn3270_load_format_storage_flags2 = -1;
static int hf_tn3270_load_format_storage_format_data = -1;
static int hf_tn3270_load_format_storage_localname = -1;
static int hf_tn3270_load_format_storage_operand = -1;
static int hf_tn3270_load_line_type_command = -1;
static int hf_tn3270_lvl = -1;
static int hf_tn3270_mode = -1;
static int hf_tn3270_msr_ind_mask = -1;
static int hf_tn3270_msr_ind_value = -1;
static int hf_tn3270_msr_state_mask = -1;
static int hf_tn3270_msr_state_value = -1;
static int hf_tn3270_msr_type = -1;
static int hf_tn3270_ap_na = -1;
static int hf_tn3270_ap_m = -1;
static int hf_tn3270_ap_vertical_scrolling = -1;
static int hf_tn3270_ap_horizontal_scrolling = -1;
static int hf_tn3270_ap_apres1 = -1;
static int hf_tn3270_ap_apa = -1;
static int hf_tn3270_ap_pp = -1;
static int hf_tn3270_ap_lc = -1;
static int hf_tn3270_ap_mp = -1;
static int hf_tn3270_ap_apres2 = -1;
static int hf_tn3270_c_np = -1;
static int hf_tn3270_number_of_attributes = -1;
static int hf_tn3270_object_control_flags = -1;
static int hf_tn3270_object_type = -1;
static int hf_tn3270_order_code = -1;
static int hf_tn3270_outbound_text_header_operation_type = -1;
static int hf_tn3270_outbound_text_header_hdr = -1;
static int hf_tn3270_outbound_text_header_lhdr = -1;
static int hf_tn3270_pages = -1;
static int hf_tn3270_partition_command = -1;
static int hf_tn3270_partition_cv = -1;
static int hf_tn3270_partition_cw = -1;
static int hf_tn3270_partition_flags = -1;
static int hf_tn3270_partition_height = -1;
static int hf_tn3270_partition_hv = -1;
static int hf_tn3270_partition_id = -1;
static int hf_tn3270_partition_ph = -1;
static int hf_tn3270_partition_pw = -1;
static int hf_tn3270_partition_res = -1;
static int hf_tn3270_partition_rs = -1;
static int hf_tn3270_partition_rv = -1;
static int hf_tn3270_partition_rw = -1;
static int hf_tn3270_partition_uom = -1;
static int hf_tn3270_partition_width = -1;
static int hf_tn3270_partition_wv = -1;
static int hf_tn3270_prime = -1;
static int hf_tn3270_printer_flags = -1;
static int hf_tn3270_ps_char = -1;
static int hf_tn3270_ps_flags = -1;
static int hf_tn3270_ps_lcid = -1;
static int hf_tn3270_ps_rws = -1;
static int hf_tn3270_query_reply_alphanumeric_flags = -1;
static int hf_tn3270_recovery_data_flags = -1;
static int hf_tn3270_reply_mode_attr_list = -1;
static int hf_tn3270_read_partition_operation_type = -1;
static int hf_tn3270_read_partition_reqtyp = -1;
static int hf_tn3270_resbyte = -1;
static int hf_tn3270_resbytes = -1;
static int hf_tn3270_res_twobytes = -1;
static int hf_tn3270_rw = -1;
static int hf_tn3270_save_or_restore_format_flags = -1;
static int hf_tn3270_scs_data = -1;
static int hf_tn3270_sf_single_byte_id = -1;
static int hf_tn3270_sf_double_byte_id = -1;
static int hf_tn3270_sf_length = -1;
static int hf_tn3270_sf_query_reply = -1;
static int hf_tn3270_sld = -1;
static int hf_tn3270_spd = -1;
static int hf_tn3270_start_line = -1;
static int hf_tn3270_start_page = -1;
static int hf_tn3270_stop_address = -1;
static int hf_tn3270_transparency = -1;
static int hf_tn3270_type_1_text_outbound_data = -1;
static int hf_tn3270_vertical = -1;
static int hf_tn3270_v_length = -1;
static int hf_tn3270_v_offset = -1;
static int hf_tn3270_v_sequence = -1;
static int hf_tn3270_wcc_nop = -1;
static int hf_tn3270_wcc_reset = -1;
static int hf_tn3270_wcc_printer1 = -1;
static int hf_tn3270_wcc_printer2 = -1;
static int hf_tn3270_wcc_start_printer = -1;
static int hf_tn3270_wcc_sound_alarm = -1;
static int hf_tn3270_wcc_keyboard_restore = -1;
static int hf_tn3270_wcc_reset_mdt = -1;
static int hf_tn3270_ww = -1;
static int hf_tn3270_tn3270e_data_type = -1;
static int hf_tn3270_tn3270e_request_flag = -1;
static int hf_tn3270_tn3270e_response_flag_3270_SCS = -1;
static int hf_tn3270_tn3270e_response_flag_response = -1;
static int hf_tn3270_tn3270e_response_flag_unused = -1;
static int hf_tn3270_tn3270e_seq_number = -1;
static int hf_tn3270_tn3270e_header_data = -1;
static int hf_tn3270_ua_cell_units = -1;
static int hf_tn3270_ua_characters = -1;
static int hf_tn3270_ua_hard_copy = -1;
static int hf_tn3270_ua_page_printer = -1;
static int hf_tn3270_ua_reserved1 = -1;
static int hf_tn3270_ua_reserved2 = -1;
static int hf_tn3270_ua_variable_cells = -1;
static int hf_tn3270_usable_area_flags1 = -1;
static int hf_tn3270_usable_area_flags2 = -1;
static int hf_tn3270_ua_addressing = -1;
static int hf_tn3270_ua_width_cells_pels = -1;
static int hf_tn3270_ua_height_cells_pels = -1;
static int hf_tn3270_ua_uom_cells_pels = -1;
static int hf_tn3270_ua_xr = -1;
static int hf_tn3270_ua_yr = -1;
static int hf_tn3270_ua_aw = -1;
static int hf_tn3270_ua_ah = -1;
static int hf_tn3270_ua_buffsz = -1;
static int hf_tn3270_ua_xmin = -1;
static int hf_tn3270_ua_ymin = -1;
static int hf_tn3270_ua_xmax = -1;
static int hf_tn3270_ua_ymax = -1;
static int hf_tn3270_cs_ge = -1;
static int hf_tn3270_cs_mi = -1;
static int hf_tn3270_cs_lps = -1;
static int hf_tn3270_cs_lpse = -1;
static int hf_tn3270_cs_ms = -1;
static int hf_tn3270_cs_ch2 = -1;
static int hf_tn3270_cs_gf = -1;
static int hf_tn3270_cs_res = -1;
static int hf_tn3270_cs_res2 = -1;
static int hf_tn3270_cs_pscs = -1;
static int hf_tn3270_cs_res3 = -1;
static int hf_tn3270_cs_cf = -1;
static int hf_tn3270_cs_form_type1 = -1;
static int hf_tn3270_cs_form_type2 = -1;
static int hf_tn3270_cs_form_type3 = -1;
static int hf_tn3270_cs_form_type4 = -1;
static int hf_tn3270_cs_form_type5 = -1;
static int hf_tn3270_cs_form_type6 = -1;
static int hf_tn3270_cs_form_type8 = -1;
static int hf_tn3270_cs_ds_load = -1;
static int hf_tn3270_cs_ds_triple = -1;
static int hf_tn3270_cs_ds_char = -1;
static int hf_tn3270_cs_ds_cb = -1;
static int hf_tn3270_character_sets_flags1 = -1;
static int hf_tn3270_character_sets_flags2 = -1;
static int hf_tn3270_sdw = -1;
static int hf_tn3270_sdh = -1;
static int hf_tn3270_form = -1;
static int hf_tn3270_formres = -1;
static int hf_tn3270_cs_dl = -1;
static int hf_tn3270_cs_descriptor_set = -1;
static int hf_tn3270_cs_descriptor_flags = -1;
static int hf_tn3270_lcid = -1;
static int hf_tn3270_sw = -1;
static int hf_tn3270_sh = -1;
static int hf_tn3270_ssubsn = -1;
static int hf_tn3270_esubsn = -1;
static int hf_tn3270_ccsgid = -1;
static int hf_tn3270_ccsid = -1;
static int hf_tn3270_c_prtblk = -1;
static int hf_tn3270_h_np = -1;
static int hf_tn3270_h_vi = -1;
static int hf_tn3270_h_ai = -1;
static int hf_tn3270_ddm_flags = -1;
static int hf_tn3270_ddm_limin = -1;
static int hf_tn3270_ddm_limout = -1;
static int hf_tn3270_ddm_nss = -1;
static int hf_tn3270_ddm_ddmss = -1;
static int hf_tn3270_rpq_device = -1;
static int hf_tn3270_rpq_mid = -1;
static int hf_tn3270_rpq_rpql = -1;
static int hf_tn3270_rpq_name = -1;
static int hf_tn3270_ip_flags = -1;
static int hf_tn3270_ipdd_wd = -1;
static int hf_tn3270_ipdd_hd = -1;
static int hf_tn3270_ipdd_wa = -1;
static int hf_tn3270_ipdd_ha = -1;
static int hf_tn3270_ippd_dpbs = -1;
static int hf_tn3270_ippd_apbs = -1;
static int hf_tn3270_ipccd_wcd = -1;
static int hf_tn3270_ipccd_hcd = -1;
static int hf_tn3270_ipccd_wca = -1;
static int hf_tn3270_ipccd_hca = -1;
static int hf_tn3270_dc_dir = -1;
static int hf_tn3270_oem_dsref = -1;
static int hf_tn3270_oem_dtype = -1;
static int hf_tn3270_oem_uname = -1;
static int hf_tn3270_sdp_daid = -1;
static int hf_tn3270_oem_sdp_ll_limin = -1;
static int hf_tn3270_oem_sdp_ll_limout = -1;
static int hf_tn3270_oem_sdp_pclk_vers = -1;
static int hf_tn3270_null = -1;
static int hf_tn3270_unknown_data = -1;
static int hf_tn3270_ds_default_sfid = -1;
static int hf_tn3270_ds_sfid = -1;
static int hf_tn3270_asia_sdp_sosi_soset = -1;
static int hf_tn3270_asia_sdp_ic_func = -1;
static int hf_tn3270_ccc = -1;
static int hf_tn3270_ccc_coding = -1;
static int hf_tn3270_ccc_printout = -1;
static int hf_tn3270_ccc_start_print = -1;
static int hf_tn3270_ccc_sound_alarm = -1;
static int hf_tn3270_ccc_copytype = -1;
static int hf_tn3270_msr_user = -1;
static int hf_tn3270_msr_locked = -1;
static int hf_tn3270_msr_auto = -1;
static int hf_tn3270_msr_ind1 = -1;
static int hf_tn3270_msr_ind2 = -1;
static int hf_tn3270_spc_sdp_ot = -1;
static int hf_tn3270_spc_sdp_ob = -1;
static int hf_tn3270_spc_sdp_ol = -1;
static int hf_tn3270_spc_sdp_or = -1;
static int hf_tn3270_spc_sdp_eucflags = -1;
static int hf_tn3270_spc_sdp_srepc = -1;
static int hf_tn3270_srf_fpcb = -1;
static int hf_tn3270_sdp_statcode = -1;
static int hf_tn3270_sdp_excode = -1;
static int hf_tn3270_sdp_ngl = -1;
static int hf_tn3270_sdp_nml = -1;
static int hf_tn3270_sdp_nlml = -1;
static int hf_tn3270_sdp_stor = -1;
static int hf_tn3270_ap_cm = -1;
static int hf_tn3270_ap_ro = -1;
static int hf_tn3270_ap_co = -1;
static int hf_tn3270_ap_fo = -1;
static int hf_tn3270_sdp_ln = -1;
static int hf_tn3270_sdp_id = -1;
static int hf_tn3270_db_cavdef = -1;
static int hf_tn3270_db_cidef = -1;
static int hf_tn3270_dia_flags = -1;
static int hf_tn3270_dia_limin = -1;
static int hf_tn3270_dia_limout = -1;
static int hf_tn3270_dia_nfs = -1;
static int hf_tn3270_dia_diafs = -1;
static int hf_tn3270_dia_diafn = -1;
static int hf_tn3270_fo_flags = -1;
static int hf_tn3270_fo_vpos = -1;
static int hf_tn3270_fo_hpos = -1;
static int hf_tn3270_fo_hpos0 = -1;
static int hf_tn3270_fo_hpos1 = -1;
static int hf_tn3270_fsad_flags = -1;
static int hf_tn3270_fsad_limin = -1;
static int hf_tn3270_fsad_limout = -1;
static int hf_tn3270_fsad_size = -1;
static int hf_tn3270_ibm_flags = -1;
static int hf_tn3270_ibm_limin = -1;
static int hf_tn3270_ibm_limout = -1;
static int hf_tn3270_ibm_type = -1;
static int hf_tn3270_msr_nd = -1;
static int hf_tn3270_pft_flags = -1;
static int hf_tn3270_pft_tmo = -1;
static int hf_tn3270_pft_bmo = -1;
static int hf_tn3270_ioca_limin = -1;
static int hf_tn3270_ioca_limout = -1;
static int hf_tn3270_ioca_type = -1;
static int hf_tn3270_pc_vo_thickness = -1;
static int hf_tn3270_pdds_ssid = -1;
static int hf_tn3270_pdds_refid = -1;
static int hf_tn3270_srf_fpcbl = -1;
static int hf_tn3270_spc_epc_flags = -1;
static int hf_tn3270_sp_spid = -1;
static int hf_tn3270_sp_size = -1;
static int hf_tn3270_sp_space = -1;
static int hf_tn3270_sp_objlist = -1;
static int hf_tn3270_tp_nt = -1;
static int hf_tn3270_tp_m = -1;
static int hf_tn3270_tp_flags = -1;
static int hf_tn3270_tp_ntt = -1;
static int hf_tn3270_tp_tlist = -1;
static int hf_tn3270_t_np = -1;
static int hf_tn3270_t_vi = -1;
static int hf_tn3270_t_ai = -1;
static int hf_tn3270_3270_tranlim = -1;

static gint ett_tn3270 = -1;
static gint ett_tn3270e_hdr = -1;
static gint ett_sf = -1;
static gint ett_tn3270_field_attribute = -1;
static gint ett_tn3270_field_validation = -1;
static gint ett_tn3270_wcc = -1;
static gint ett_tn3270_usable_area_flags1 = -1;
static gint ett_tn3270_usable_area_flags2 = -1;
static gint ett_tn3270_query_reply_alphanumeric_flags = -1;
static gint ett_tn3270_character_sets_flags1 = -1;
static gint ett_tn3270_character_sets_flags2 = -1;
static gint ett_tn3270_character_sets_form = -1;
static gint ett_tn3270_cs_descriptor_flags = -1;
static gint ett_tn3270_color_flags = -1;
static gint ett_tn3270_ccc = -1;
static gint ett_tn3270_msr_state_mask = -1;
static gint ett_tn3270_data_chain_fields = -1;
static gint ett_tn3270_query_list = -1;

static expert_field ei_tn3270_order_code = EI_INIT;
static expert_field ei_tn3270_command_code = EI_INIT;
static expert_field ei_tn3270_aid = EI_INIT;

static gint dissect_orders_and_data(proto_tree *tn3270_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, tn3270_conv_info_t *tn3270_info);
static gint dissect_buffer_address(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset, gint hf, tn3270_conv_info_t *tn3270_info);

typedef struct hf_items {
  int         *hf_idx_p;
  gint        *bitmask_ett_idx_p;
  gint         length;
  const gint **bitmask;
  const gint   encoding;
} hf_items;

/* Utility Functions */

static gint
tn3270_add_hf_items(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                    const hf_items *fields)
{
  gint start = offset;
  gint i;

  for (i = 0; fields[i].hf_idx_p; i++) {
    if (fields[i].bitmask == 0) {
      proto_tree_add_item(tn3270_tree,
                          *fields[i].hf_idx_p,
                          tvb, offset,
                          fields[i].length,
                          fields[i].encoding);
    }
    else {
      proto_tree_add_bitmask(tn3270_tree, tvb, offset, *fields[i].hf_idx_p,
                             *fields[i].bitmask_ett_idx_p, fields[i].bitmask, ENC_BIG_ENDIAN);
    }
    offset += fields[i].length;
  }

  return (offset - start);
}

/*
 * offset;      tvb offset of next byte of data (first byte of unprocessed data);
 * start:       tvb offset of beginning of data;
 * data_length: total length of data;
 */
static gint
dissect_unknown_data(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset, gint start,
                     gint data_length)
{
  gint len_left;

  len_left = (data_length) - (offset - start);

  if (len_left > 0) {
    proto_tree_add_item(tn3270_tree, hf_tn3270_unknown_data,
                        tvb, offset, len_left,
                        ENC_NA);
    return len_left;
  }

  return 0;
}

static gint
add_data_until_next_order_code(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{
  gint datalen          = 0;
  gint length_remaining = tvb_reported_length_remaining(tvb, offset);

  /* XXX: From 4.3:
   *  "All order codes have an EBCDIC value in the range of hexadecimal 00
   *   (X'00') through hexadecimal 3F (X'3F').  Order codes with values in this
   *   range but not defined in this chapter are rejected."
   *  However, the code (as originally committed) treats a '0' order code as data.
   */

  while (datalen < length_remaining) {
    guint order_code;
    order_code = tvb_get_guint8(tvb, offset + datalen);
    if ((order_code > 0) && (order_code <= OC_MAX))
      break;
    datalen += 1;
  }

  if (datalen > 0) {
    /* XXX: Need to handle "Format Control Orders" ??  */
    proto_tree_add_item(tn3270_tree, hf_tn3270_field_data, tvb, offset,
                        datalen, ENC_EBCDIC|ENC_NA);
  }

  return datalen;
}

static gint
dissect_query_reply_resbytes(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                             gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_res_twobytes, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

static gint
dissect_wcc(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{

  static const gint *wcc_fields[] = {
    &hf_tn3270_wcc_nop,
    &hf_tn3270_wcc_reset,
    &hf_tn3270_wcc_printer1,
    &hf_tn3270_wcc_printer2,
    &hf_tn3270_wcc_start_printer,
    &hf_tn3270_wcc_sound_alarm,
    &hf_tn3270_wcc_keyboard_restore,
    &hf_tn3270_wcc_reset_mdt,
    NULL
  };

  /* Qualifier and DeviceType */
  proto_tree_add_bitmask_text(tn3270_tree, tvb, offset, 1, "Write Control Character: ", "None",
                              ett_tn3270_wcc, wcc_fields, ENC_BIG_ENDIAN, 0);
  return 1;

}

static gint
dissect_3270_field_validation(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{
  gint start = offset;

  static const gint *byte[] = {
    &hf_tn3270_field_validation_mandatory_fill,
    &hf_tn3270_field_validation_mandatory_entry,
    &hf_tn3270_field_validation_trigger,
    NULL
  };

  proto_tree_add_bitmask_text(tn3270_tree, tvb, 1, 1, "Field Validation: ",
                              "None", ett_tn3270_field_validation, byte, ENC_BIG_ENDIAN, 0);

  offset += 1;

  return (offset - start);
}


static gint
dissect_3270_field_attribute(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{
  gint start = offset;

  static const gint *byte[] = {
    &hf_tn3270_fa_graphic_convert,
    &hf_tn3270_fa_protected,
    &hf_tn3270_fa_numeric,
    &hf_tn3270_fa_display,
    &hf_tn3270_fa_reserved,
    &hf_tn3270_fa_modified,
    NULL
  };


  proto_tree_add_bitmask(tn3270_tree, tvb, offset, hf_tn3270_field_attribute,
                         ett_tn3270_field_attribute, byte, ENC_BIG_ENDIAN);

  offset += 1;

  return (offset - start);
}

/* 8.7 - Copy Control Code */
static gint
dissect_ccc(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{
  gint start = offset;

  static const gint *byte[] = {
    &hf_tn3270_ccc_coding,
    &hf_tn3270_ccc_printout,
    &hf_tn3270_ccc_start_print,
    &hf_tn3270_ccc_sound_alarm,
    &hf_tn3270_ccc_copytype,
    NULL
  };

  proto_tree_add_bitmask(tn3270_tree, tvb, offset, hf_tn3270_ccc,
                         ett_tn3270_ccc, byte, ENC_BIG_ENDIAN);

  offset += 1;

  return (offset - start);
}

/* End - Utility Functions */

/* Start: Handle Structured Fields */

/* --------------------------------------------------- */
/* 5.0 Outbound/Inbound and Outbound Structured Fields */
/* --------------------------------------------------- */

/* 5.5 Activate Partition - Search for ACTIVATE_PARTITION */
/* 5.6 Begin/End of File - Search for BEGIN_OR_END_OF_FILE */
/* 5.7 Create Partition */
static gint
dissect_create_partition(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset, gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_partition_id,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_uom,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_flags,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_height, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_width,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_rv,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_cv,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_hv,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_wv,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_rw,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_cw,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_rs,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_res,    NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_pw,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_ph,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 5.7 Create Partition  - Search for CREATE_PARTITION */
/* 5.8 Destroy Partition - Search for DESTROY_PARTITION */
/* 5.9 Erase/Reset       - Search for ERASE_OR_RESET */
/* 5.10 Load Color Table - Search for LOAD_COLOR_TABLE */

/* 5.11 Load Format Storage */
static gint
dissect_load_format_storage(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset, gint sf_body_length)
{
  gint start = offset;
  gint operand;

  static const hf_items fields[] = {
    { &hf_tn3270_load_format_storage_flags1,    NULL,  1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_load_format_storage_flags2,    NULL,  1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_load_format_storage_operand,   NULL,  1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_load_format_storage_localname, NULL,  8, NULL, ENC_EBCDIC|ENC_NA },
    { &hf_tn3270_format_group,                  NULL,  6, NULL, ENC_EBCDIC|ENC_NA },
    { &hf_tn3270_format_name,                   NULL, 16, NULL, ENC_EBCDIC|ENC_NA },
    { NULL, NULL, 0, NULL, 0 }
  };

  operand = tvb_get_guint8(tvb, offset+2);

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  if (operand == LOAD_FORMAT_STORAGE_OPERAND_ADD) {
    gint fmtln = sf_body_length - (offset - start);
    proto_tree_add_item(tn3270_tree, hf_tn3270_load_format_storage_format_data,
                        tvb, offset, fmtln, ENC_EBCDIC|ENC_NA);
    offset += fmtln;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 5.12 Load Line Type - Search for LOAD_LINE_TYPE */

/* 5.13 Load Programmed Symbols (Load PS) */
static gint
dissect_load_programmed_symbols(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset, gint sf_body_length)
{
  gint  start = offset, i;
  gint8 flags;
  gint8 extended_ps_length;

  static const hf_items ps_fields[] = {
    { &hf_tn3270_ps_flags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ps_lcid,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ps_char,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ps_rws,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items extended_ps_fields[] = {
    { &hf_tn3270_extended_ps_lw,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_extended_ps_lh,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_extended_ps_subsn,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_extended_ps_color,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_extended_ps_stsubs, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_extended_ps_echar,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_extended_ps_nw,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_extended_ps_nh,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_extended_ps_res,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  flags   = tvb_get_guint8(tvb, offset);
  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                ps_fields);

  /*If extended flag not set return */
  if (!(flags & 0x80)) {
    return (offset - start);
  }

  extended_ps_length = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tn3270_tree, hf_tn3270_extended_ps_length,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(tn3270_tree, hf_tn3270_extended_ps_flags,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  for (i = 0; i < extended_ps_length; ++i) {
    if (extended_ps_fields[i].hf_idx_p == NULL) {
      break;  /* Malformed (Bad value for extended_ps_length) ! ToDo: 'expert' */
    }
    proto_tree_add_item(tn3270_tree, *extended_ps_fields[i].hf_idx_p,
                        tvb, offset, extended_ps_fields[i].length,
                        extended_ps_fields[i].encoding);
    offset += extended_ps_fields[i].length;
  }


  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 5.14 Modify Partition) */
static gint
dissect_modify_partition(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset, gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_resbyte,         NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_id,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte,         NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_flags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte,         NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbytes,        NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_rv,    NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_cv,    NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_hv,    NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_wv,    NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_rw,    NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_cw,    NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_rs,    NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_res,   NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_pw,    NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_partition_ph,    NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 5.15 Outbound Text Header */
static gint
dissect_outbound_text_header(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                             gint sf_body_length)
{
  gint   start = offset;
  gint16 hdr_length;

  static const hf_items outbound_text_header_fields1[] = {
    { &hf_tn3270_partition_id,                        NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_outbound_text_header_operation_type, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items outbound_text_header_fields2[] = {
    { &hf_tn3270_resbyte, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_lvl,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_cro,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_cc,      NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                outbound_text_header_fields1);
  offset += dissect_wcc(tn3270_tree, tvb, offset);
  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                outbound_text_header_fields2);

  hdr_length = tvb_get_ntohs(tvb, offset);

  proto_tree_add_item(tn3270_tree, hf_tn3270_outbound_text_header_lhdr,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tn3270_tree, hf_tn3270_outbound_text_header_hdr,
                      tvb, offset, hdr_length, ENC_NA);
  offset += hdr_length;

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 5.16 Outbound 3270DS */
static gint
dissect_outbound_3270ds(proto_tree *tn3270_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset,
                        tn3270_conv_info_t *tn3270_info, gint sf_body_length )
{
  gint start = offset;
  gint cmd;

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_partition_id,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;

  cmd = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_partition_command,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;

  switch (cmd) {
    case CC_SNA_BSC:
      /* FIXME: the spec is ambiguous at best about what to expect here,
         need a live sample to validate. */
      offset += dissect_ccc(tn3270_tree, tvb, offset);
      proto_tree_add_item(tn3270_tree,
                          hf_tn3270_bsc,
                          tvb, offset,
                          2,
                          ENC_BIG_ENDIAN);
      offset += 2;
      break;
      /* XXX: are "local" commands valid for Outbound 3270DS ? */
    case CC_LCL_W:
    case CC_LCL_EW:
    case CC_LCL_EWA:
    case CC_LCL_EAU:
    case CC_RMT_W:
    case CC_RMT_EW:
    case CC_RMT_EWA:
    case CC_RMT_EAU:
      /* WCC */
      if ((offset - start) < sf_body_length)
        offset += dissect_wcc(tn3270_tree, tvb, offset);
      if ((offset - start) < sf_body_length)
        offset += dissect_orders_and_data(tn3270_tree, pinfo, tvb, offset, tn3270_info);
      break;
    default:
      break;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 5.17 Present Absolute Format */
static gint
dissect_present_absolute_format(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                gint sf_body_length)
{
  gint start = offset;

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_partition_id,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_fpc,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;

  offset += dissect_wcc(tn3270_tree, tvb, offset);

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_format_name,
                      tvb, offset,
                      sf_body_length - (offset - start),
                      ENC_EBCDIC|ENC_NA);
  offset += (sf_body_length - (offset - start));

  return (offset - start);
}

/* 5.18 Present Relative Format */
static gint
dissect_present_relative_format(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                gint sf_body_length)
{
  gint start = offset;

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_partition_id,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_fov,
                      tvb, offset,
                      2,
                      ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_fpc,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;

  offset += dissect_wcc(tn3270_tree, tvb, offset);

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_format_name,
                      tvb, offset,
                      sf_body_length - (offset - start),
                      ENC_EBCDIC|ENC_NA);
  offset += (sf_body_length - (offset - start));

  return (offset - start);
}

/* 5.19 Read Partition */
static gint
dissect_read_partition(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                       gint sf_body_length)
{
  gint        start = offset;
  gint        type;
  proto_tree *query_list_tree;
  gint        qcode_list_len, i;

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_partition_id,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;

  type = tvb_get_guint8(tvb, offset);
  if (type == 0xFF) { /* Partition ID of 0xFF is escaped with another 0xFF */
                      /* XXX: removing tn3270 IAX escapes should be handled in the telnet dissector ! */
    offset += 1;
    type = tvb_get_guint8(tvb, offset);
  }

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_read_partition_operation_type,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;

  if (type == READ_PARTITION_OPTYPE_QUERY_LIST) { /* 'Query List' */
    proto_tree_add_item(tn3270_tree,
                        hf_tn3270_read_partition_reqtyp,
                        tvb, offset,
                        1,
                        ENC_BIG_ENDIAN);
    offset += 1;

    if (sf_body_length > (offset - start)) {
      qcode_list_len = sf_body_length - (offset - start);
      query_list_tree = proto_tree_add_subtree(tn3270_tree, tvb, offset, qcode_list_len,
                               ett_tn3270_query_list, NULL, "Query List");
      for (i = 0; i < qcode_list_len; i++) {
        proto_tree_add_item(query_list_tree,
                            hf_tn3270_sf_query_reply,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
      }
    }
  }

  return (offset - start);
}

/*5.20 Request Recovery Data - Search for REQUEST_RECOVERY_DATA*/
/*5.21 Reset Partition - Search for RESET_PARTITION */

/*5.22 Restart */
static gint
dissect_restart(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                gint sf_body_length)
{
  gint start = offset;

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_resbyte,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_start_page,
                      tvb, offset,
                      2,
                      ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_start_line,
                      tvb, offset,
                      2,
                      ENC_BIG_ENDIAN);
  offset += 2;


  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_scs_data,
                      tvb, offset,
                      sf_body_length - (offset - start),
                      ENC_NA);
  offset += (sf_body_length - (offset - start));

  return (offset - start);
}

/* 5.23 SCS Data     - Search for SCS_DATA */
/* 5.24 Color Table  - Search for COLOR_TABLE */
/* 5.25 Format Group - Search for FORMAT_GROUP */
/* 5.26 Set Checkpoint Interval - Search for CHECKPOINT_INTERVAL */

/* 5.27 Set MSR Control */
static gint
dissect_set_msr_control(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                        gint sf_body_length)
{
  gint start = offset;

  static const gint *byte[] = {
    &hf_tn3270_msr_user,
    &hf_tn3270_msr_locked,
    &hf_tn3270_msr_auto,
    &hf_tn3270_msr_ind1,
    &hf_tn3270_msr_ind2,
    NULL
  };

  static const hf_items outbound_text_header_fields[] = {
    { &hf_tn3270_partition_id,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_msr_type,        NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_msr_state_mask, &ett_tn3270_msr_state_mask, 1, byte, 0 },
    { &hf_tn3270_msr_state_value, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_msr_ind_mask,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_msr_ind_value,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                outbound_text_header_fields);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 5.28 Set Partition Characteristics */
static gint
dissect_set_partition_characteristics_sd_parms(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{

  gint    start = offset;
  guint16 sdp;

  static const hf_items sdp1[] = {
    { &hf_tn3270_sdp_ln,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_spc_sdp_ot, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_spc_sdp_ob, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_spc_sdp_ol, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_spc_sdp_or, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items sdp2[] = {
    { &hf_tn3270_sdp_ln,           NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,           NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_spc_sdp_eucflags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items sdp3[] = {
    { &hf_tn3270_sdp_ln,           NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,           NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_spc_sdp_eucflags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_spc_sdp_eucflags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  sdp = tvb_get_ntohs(tvb, offset);

  switch (sdp) {
    case 0x0601: /*View Outport*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp1);
      break;
    case 0x0304: /*Enable User Call Up*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp2);
      break;
    case 0x0405: /*Select Base Character Set*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp3);
      break;
    default:
      return 0;
  }

  return (offset - start);

}

static gint
dissect_set_partition_characteristics(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                      gint sf_body_length)
{

  gint start = offset;
  gint i;

  static const hf_items fields[] = {
    { &hf_tn3270_partition_id, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbytes,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  for (i = 0; i < 3; i++) {
    offset += dissect_set_partition_characteristics_sd_parms(tn3270_tree, tvb, offset);
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
      break;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 5.29 Set Printer Characteristics */
static gint
dissect_set_printer_characteristics_sd_parms(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{

  gint    start = offset;
  guint16 sdp;

  static const hf_items sdp1[] = {
    { &hf_tn3270_sdp_ln,        NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,        NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_spc_sdp_srepc, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  sdp = tvb_get_ntohs(tvb, offset);

  switch (sdp) {
    case 0x0301: /*Early Print Complete*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp1);
      break;
    default:
      return 0;
  }

  return (offset - start);

}

static gint
dissect_set_printer_characteristics(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                    gint sf_body_length)
{

  gint start = offset;
  gint i;

  static const hf_items fields[] = {
    { &hf_tn3270_printer_flags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte,       NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  for (i = 0; i < 3; i++) {
    offset += dissect_set_printer_characteristics_sd_parms(tn3270_tree, tvb, offset);
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
      break;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}


/* 5.30 Set Reply Mode */
static gint
dissect_set_reply_mode(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                       gint sf_body_length)
{
  gint start = offset;
  gint type;
  gint i;

  static const hf_items fields[] = {
    { &hf_tn3270_partition_id, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_mode,         NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  type = tvb_get_guint8(tvb, offset+1);

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  if (type == 0x02) { /* 'Query List' */
    for (i = 0; i < (sf_body_length-(offset-start)); i++) {
      proto_tree_add_item(tn3270_tree,
                          hf_tn3270_reply_mode_attr_list,
                          tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
    }
  }

  return (offset - start);
}

/* 5.31 Set Window Origin - Search for SET_WINDOW_ORIGIN */
/* 6.6 Type 1 Text Inbound
   5.32 Type 1 Text Outbound */
static gint
dissect_type_1_text(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                    gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_partition_id, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbytes,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);
  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_field_data,
                      tvb, offset,
                      sf_body_length - (offset - start),
                      ENC_EBCDIC|ENC_NA);
  offset += (sf_body_length - (offset - start));

  return (offset - start);
}

/* 5.34 Data Chain */
static guint
dissect_data_chain(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                       gint sf_body_length)
{
  gint start = offset;

  static const gint *byte[] = {
    &hf_tn3270_data_chain_group,
    &hf_tn3270_data_chain_inbound_control,
    NULL
  };

  static const hf_items data_chain_fields[] = {
    { &hf_tn3270_data_chain_fields, &ett_tn3270_data_chain_fields, 1, byte, 0 },
    { &hf_tn3270_resbyte, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                data_chain_fields);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 5.35 Destination/Origin -  Search for DESTINATION_OR_ORIGIN*/

/* 5.36 Object Control */
static gint
dissect_object_control(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                       gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_partition_id,         NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_object_control_flags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_object_type,          NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_type_1_text_outbound_data,
                      tvb, offset,
                      sf_body_length - (offset - start),
                      ENC_NA);
  offset += (sf_body_length - (offset - start));

  return (offset - start);
}

/* 5.37 Object Data - Search for OBJECT_DATA*/
/* 5.38 Object Picture - Search for OBJECT_PICTURE */
/* 5.39 OEM Data - Search for OEM_DATA */

/* 5.40 Save/Restore Format */
static gint
dissect_save_or_restore_format(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                               gint sf_body_length)
{
  gint start = offset;

  hf_items fields[] = {
    { &hf_tn3270_save_or_restore_format_flags, NULL, 1,                NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_srf_fpcb,                     NULL, sf_body_length-1, NULL, ENC_NA },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 5.41 Select Intelligent Printer Data Stream (IPDS) Mode -  Search for SELECT_IPDS_MODE*/

/* -----------------------------------------*/
/* 6.0 CHAPTER 6. INBOUND STRUCTURED FIELDS */
/* -----------------------------------------*/

/* 6.2 Exception/Status */
static gint
dissect_exception_or_status_sd_parms(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{

  gint    start = offset;
  guint16 sdp;

  static const hf_items sdp1[] = {
    { &hf_tn3270_sdp_ln,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_excode, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items sdp2[] = {
    { &hf_tn3270_sdp_ln,       NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,       NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_statcode, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items sdp3[] = {
    { &hf_tn3270_sdp_ln,       NULL,  1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,       NULL,  1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_format_group, NULL, 16, NULL, ENC_EBCDIC|ENC_NA },
    { &hf_tn3270_format_name,  NULL, 16, NULL, ENC_EBCDIC|ENC_NA },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items sdp4[] = {
    { &hf_tn3270_sdp_ln,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_ngl,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_nml,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_nlml, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_stor, NULL, 4, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items sdp5[] = {
    { &hf_tn3270_sdp_ln,       NULL,  1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,       NULL,  1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_format_group, NULL, 16, NULL, ENC_EBCDIC|ENC_NA },
    { &hf_tn3270_sdp_nml,      NULL,  2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  sdp = tvb_get_ntohs(tvb, offset);

  switch (sdp) {
    case 0x0601: /*Auxiliary Device Exception*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp1);
      break;
    case 0x0402: /*Auxiliary Device status*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp2);
      break;
    case 0x2203: /*Failing Format status*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp3);
      break;
    case 0x0C04: /*Format status*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp4);
      break;
    case 0x1405: /*Group status*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp5);
      break;
    default:
      return 0;
  }

  return (offset - start);

}

static gint
dissect_exception_or_status(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                            gint sf_body_length)
{
  gint start = offset, i;

  static const hf_items fields[] = {
    { &hf_tn3270_partition_id,              NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_exception_or_status_flags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte,                   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  for (i = 0; i < 5; i++) {
    offset += dissect_exception_or_status_sd_parms(tn3270_tree, tvb, offset);
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
      break;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.3 Inbound Text Header */
static gint
dissect_inbound_text_header(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                            gint sf_body_length)
{
  gint start = offset;

  static const hf_items outbound_text_header_fields[] = {
    { &hf_tn3270_partition_id, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_aid,          NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte,      NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte,      NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte,      NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_lvl,          NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_cro,          NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_cc,           NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_rw,           NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_cw,           NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_hw,           NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ww,           NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                outbound_text_header_fields);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.4 Inbound 3270DS */
static gint
dissect_inbound_3270ds(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                       tn3270_conv_info_t *tn3270_info, gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields1[] = {
    { &hf_tn3270_partition_id,   NULL, 1,                  NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_aid,            NULL, 1,                  NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  hf_items fields2[] = {
    { &hf_tn3270_field_data,     NULL, sf_body_length - 4, NULL, ENC_EBCDIC|ENC_NA },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset, fields1);
  offset += dissect_buffer_address(tn3270_tree, tvb, offset, hf_tn3270_cursor_address, tn3270_info);
  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset, fields2);

  return (offset - start);
}



/* 6.5 Recovery Data */
static gint
dissect_recovery_data(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                      gint sf_body_length)
{
  gint start = offset;


  static const hf_items fields[] = {
    { &hf_tn3270_resbyte,             NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_recovery_data_flags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sld,                 NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_charset,             NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_vertical,            NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_v_offset,            NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_v_sequence,          NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_v_length,            NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_spd,                 NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_horizon,             NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_h_offset,            NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_h_sequence,          NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_h_length,            NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_color,               NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_hilite,              NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_pages,               NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_lines,               NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_checkpoint,          NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_c_offset,            NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_c_sequence,          NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_c_seqoff,            NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_c_scsoff,            NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_prime,               NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.6 Query Reply (Type 1 Text Inbound) - See above*/
/* 6.7 and 6.8 Query Reply - Introductory Matter */

/* 6.9 Query Reply (Alphanumeric Partitions) */
static gint
dissect_query_reply_alphanumeric_sd_parms(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{

  gint    start = offset;
  guint16 sdp;

  static const hf_items sdp1[] = {
    { &hf_tn3270_sdp_ln, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ap_cm,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ap_ro,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ap_co,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ap_fo,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  sdp = tvb_get_ntohs(tvb, offset);

  switch (sdp) {
    case 0x0702: /*Buffer Allocation*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp1);
      break;
    default:
      return 0;
  }

  return (offset - start);

}

static gint
dissect_query_reply_alphanumeric(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                 gint sf_body_length)
{
  gint start = offset;

  static const gint *byte[] = {
    &hf_tn3270_ap_vertical_scrolling,
    &hf_tn3270_ap_horizontal_scrolling,
    &hf_tn3270_ap_apres1,
    &hf_tn3270_ap_apa,
    &hf_tn3270_ap_pp,
    &hf_tn3270_ap_lc,
    &hf_tn3270_ap_mp,
    &hf_tn3270_ap_apres2,
    NULL
  };

  static const hf_items fields[] = {
    { &hf_tn3270_ap_na, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ap_m,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_query_reply_alphanumeric_flags, &ett_tn3270_query_reply_alphanumeric_flags, 1, byte, 0 },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  offset += dissect_query_reply_alphanumeric_sd_parms(tn3270_tree, tvb, offset);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.10 Query Reply (Auxiliary Device) - Search for QUERY_REPLY_AUXILIARY_DEVICE */
/* 6.11 Query Reply (BEGIN/End of File ) - Search for QUERY_REPLY_BEGIN_OR_END_OF_FILE */

/* 6.12 Query Reply (Character Sets) */
static gint
dissect_query_reply_character_sets(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                   gint sf_body_length)
{
  gint start = offset;
  gint flagbyte1, flagbyte2;

  static const gint *byte1[] = {
    &hf_tn3270_cs_ge,
    &hf_tn3270_cs_mi,
    &hf_tn3270_cs_lps,
    &hf_tn3270_cs_lpse,
    &hf_tn3270_cs_ms,
    &hf_tn3270_cs_ch2,
    &hf_tn3270_cs_gf,
    &hf_tn3270_cs_res,
    NULL
  };

  static const gint *byte2[] = {
    &hf_tn3270_cs_res2,
    &hf_tn3270_cs_pscs,
    &hf_tn3270_cs_res3,
    &hf_tn3270_cs_cf,
    NULL
  };

  static const gint *byte3[] = {
    &hf_tn3270_cs_form_type1,
    &hf_tn3270_cs_form_type2,
    &hf_tn3270_cs_form_type3,
    &hf_tn3270_cs_form_type4,
    &hf_tn3270_cs_form_type5,
    &hf_tn3270_cs_form_type6,
    &hf_tn3270_cs_form_type8,
    NULL
  };

  static const gint *byte4[] = {
    &hf_tn3270_cs_ds_load,
    &hf_tn3270_cs_ds_triple,
    &hf_tn3270_cs_ds_char,
    &hf_tn3270_cs_ds_cb,
    NULL
  };


  static const hf_items fields[] = {
    { &hf_tn3270_character_sets_flags1, &ett_tn3270_character_sets_flags1, 1, byte1, 0 },
    { &hf_tn3270_character_sets_flags2, &ett_tn3270_character_sets_flags2, 1, byte2, 0 },
    { &hf_tn3270_sdw,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdh,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_form,                  &ett_tn3270_character_sets_form,   1, byte3, 0 },
    { &hf_tn3270_formres, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_formres, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_formres, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_cs_dl,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items descriptors[] = {
    { &hf_tn3270_cs_descriptor_set,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_cs_descriptor_flags, &ett_tn3270_cs_descriptor_flags, 1, byte4, 0 },
    { &hf_tn3270_lcid,                NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items sw_sh[] = {
    { &hf_tn3270_sw, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sh, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items subsn[] = {
    { &hf_tn3270_ssubsn, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_esubsn, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items gf[] = {
    { &hf_tn3270_ccsgid, NULL, 4, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items cf[] = {
    { &hf_tn3270_ccsid,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  flagbyte1 = tvb_get_guint8(tvb, offset);
  flagbyte2 = tvb_get_guint8(tvb, offset+1);

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  while ((offset - start) < sf_body_length) {

    offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                  descriptors);

    if (flagbyte1 & QR_CS_MS) {
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sw_sh);
    }

    if (flagbyte1 & QR_CS_CH2) {
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    subsn);
    }

    if (flagbyte1 & QR_CS_GF) {
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    gf);
    }

    if (flagbyte2 & QR_CS_CF) {
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    cf);
    }
  }
  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.13 Query Reply (Color) */
static gint
dissect_query_reply_color_sd_parms(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{

  gint    start = offset;
  guint16 sdp;

  static const hf_items sdp1[] = {
    { &hf_tn3270_sdp_ln,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_db_cavdef, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_db_cidef,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  sdp = tvb_get_ntohs(tvb, offset);

  switch (sdp) {
    case 0x0402: /*Default Background Color*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp1);
      break;
    default:
      return 0;
  }

  return (offset - start);

}

static gint
dissect_query_reply_color(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                          gint sf_body_length)
{
  gint start = offset;
  gint i;
  gint np;

  static const gint *byte[] = {
    &hf_tn3270_c_prtblk,
    NULL
  };

  static const hf_items fields[] = {
    { &hf_tn3270_color_flags, &ett_tn3270_color_flags, 1, byte, 0 },
    { &hf_tn3270_c_np, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  np = tvb_get_guint8(tvb, offset +1);
  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  for (i=0; i < np; i++) {
    if (tvb_get_guint8(tvb, offset) == 0xFF) {
      offset += 1;
    }
    proto_tree_add_item(tn3270_tree,
                        hf_tn3270_c_cav,
                        tvb, offset,
                        1,
                        ENC_BIG_ENDIAN);
    offset += 1;
    if (tvb_get_guint8(tvb, offset) == 0xFF) {
      offset += 1;
    }
    proto_tree_add_item(tn3270_tree,
                        hf_tn3270_c_ci,
                        tvb, offset,
                        1,
                        ENC_BIG_ENDIAN);
    offset += 1;
  }
  offset += dissect_query_reply_color_sd_parms(tn3270_tree, tvb, offset);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}


/* 6.36 - Query Reply (OEM Auxiliary Device) Self-Defining Parameters */
static gint
dissect_daid_sd_parm(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{

  gint start = offset;

  static const hf_items sdp1[] = {
    { &hf_tn3270_sdp_ln,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_daid, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                sdp1);
  return (offset - start);

}

static gint
dissect_pclk_sd_parm(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{

  gint start = offset;

  static const hf_items sdp1[] = {
    { &hf_tn3270_sdp_ln,            NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,            NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_oem_sdp_pclk_vers, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                sdp1);
  return (offset - start);

}

static gint
dissect_query_reply_oem_auxiliary_device_sd_parms(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{

  gint start = offset;
  gint sdp_len;
  gint sdp;

  static const hf_items sdp1[] = {
    { &hf_tn3270_sdp_ln,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_daid, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items sdp2[] = {
    { &hf_tn3270_sdp_ln,            NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,            NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_oem_sdp_ll_limin,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_oem_sdp_ll_limout, NULL, 2, NULL, ENC_BIG_ENDIAN },

    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items sdp3[] = {
    { &hf_tn3270_sdp_ln,            NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,            NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_oem_sdp_pclk_vers, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  sdp_len = tvb_get_guint8(tvb, offset);
  if ((sdp_len != 0x04) && (sdp_len != 0x06)) {
    return 0;
  }

  sdp = tvb_get_guint8(tvb, offset+1);

  switch (sdp) {
    case 0x01:
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp1);
      break;
    case 0x02:
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp2);
      break;
    case 0x03:
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp3);
      break;
    default:
      return 0;
  }

  return (offset - start);

}

/* 6.14 - Query Reply (Cooperative Processing Requestor) */
static gint
dissect_query_reply_cooperative(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_res_twobytes, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_limin,        NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_limout,       NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_featl,        NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_feats,        NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

#if 0
  /*FIXME: Need to see this in action to dissect in detail */
  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_field_data,
                      tvb, offset,
                      sf_body_length - (offset-start),
                      ENC_EBCDIC|ENC_NA);
  offset += (sf_body_length - (offset - start));

  /* Uses same Self-Defining Parm as OEM Auxiliary Device */
  offset += dissect_query_reply_oem_auxiliary_device_sd_parms(tn3270_tree, tvb, offset);
#endif

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.15 - Query Reply (Data Chaining) */
static gint
dissect_query_reply_data_chaining(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                  gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_dc_dir,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.16 - Query Reply (Data Streams) */

static gint
dissect_query_reply_data_streams(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                 gint sf_body_length)
{
  gint start = offset;
  gint i;

  proto_tree_add_item(tn3270_tree, hf_tn3270_ds_default_sfid, tvb, offset, 1,
                      ENC_BIG_ENDIAN);
  offset += 1;

  for (i=0; i < (sf_body_length-(offset-start)); i++) {
    proto_tree_add_item(tn3270_tree,
                        hf_tn3270_ds_sfid,
                        tvb, offset,
                        1,
                        ENC_BIG_ENDIAN);
    offset += 1;
  }
  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.17 - Query Reply (DBCS Asia) */

static gint
dissect_query_reply_dbcs_asia_sd_parms(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{

  gint start = offset;
  gint sdp_len;
  gint sdp;

  static const hf_items sdp1[] = {
    { &hf_tn3270_sdp_ln,              NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,              NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_asia_sdp_sosi_soset, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items sdp2[] = {
    { &hf_tn3270_sdp_ln,           NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,           NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_asia_sdp_ic_func, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  sdp_len = tvb_get_guint8(tvb, offset);
  if (sdp_len != 0x03) {
    return 0;
  }

  sdp = tvb_get_guint8(tvb, offset+1);

  switch (sdp) {
    case 0x01: /*SO/SI*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp1);
      break;
    case 0x02: /*Input Control*/
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp2);
      break;
    default:
      return 0;
  }

  return (offset - start);

}

static gint
dissect_query_reply_dbcs_asia(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                              gint sf_body_length)
{

  gint start = offset;
  gint i;

  static const hf_items fields[] = {
    { &hf_tn3270_resbyte, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  for (i = 0; i < 3; i++) {
    offset += dissect_query_reply_dbcs_asia_sd_parms(tn3270_tree, tvb, offset);
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
      break;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.18 - Query Reply (Device Characteristics) */
static gint
dissect_query_reply_device_characteristics(proto_tree *tn3270_tree, tvbuff_t *tvb,
                                           gint offset, gint sf_body_length)
{
  gint start = offset;

#if 0 /* XXX: I don't think this is correct (i.e., this field is not part of this message) .... */
  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_sf_outbound_id,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;
#endif

  /* TODO: dissect descriptors */
  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.19 - Query Reply (Distributed Data Management) */
static gint
dissect_query_reply_distributed_data_management(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                                gint sf_body_length)
{
  gint     start = offset, i;
  gint     sdp;
  gboolean done  = FALSE;

  static const hf_items fields[] = {
    { &hf_tn3270_ddm_flags,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ddm_flags,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ddm_limin,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ddm_limout, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ddm_nss,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ddm_ddmss,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  for (i = 0; i < 3; i++) {
    sdp = tvb_get_guint8(tvb, offset+1);
    switch (sdp) {
      case 0x02: /*DDM*/
        /*TODO: DDM */
        offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, tvb_get_guint8(tvb,offset));
        break;
      case 0x01: /*DAID*/
        offset += dissect_daid_sd_parm(tn3270_tree, tvb, offset);
        break;
      case 0x03: /*PCLK*/
        offset += dissect_pclk_sd_parm(tn3270_tree, tvb, offset);
        break;
      default:
        done = TRUE;
        break;
    }
    if ((tvb_reported_length_remaining(tvb, offset) <= 0) || done)
      break;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.20 - Query Reply (Document Interchange Architecture) */
static gint
dissect_query_reply_document_interchange_architecture(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                                      gint sf_body_length)
{
  gint start = offset, sdp, ln, i;

  static const hf_items fields[] = {
    { &hf_tn3270_dia_flags,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_dia_limin,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_dia_limout, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  ln = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tn3270_tree, hf_tn3270_dia_nfs, tvb, offset, 1, ENC_BIG_ENDIAN);

  for (i=0; i < ln; i++) {
    proto_tree_add_item(tn3270_tree, hf_tn3270_dia_diafs, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tn3270_tree, hf_tn3270_dia_diafn, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    offset += 1;
  }

  sdp = tvb_get_guint8(tvb, offset+1);
  if (sdp == 0x01) { /*DAID*/
    offset += dissect_daid_sd_parm(tn3270_tree, tvb, offset);
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.21 - Query Reply (Extended Drawing Routine) */
static gint
dissect_query_reply_extended_drawing_routine(proto_tree *tn3270_tree, tvbuff_t *tvb,
                                             gint offset, gint sf_body_length)
{
  gint start = offset;

  proto_tree_add_item(tn3270_tree, hf_tn3270_field_data ,tvb, offset,
                      sf_body_length, ENC_EBCDIC|ENC_NA);

  offset += sf_body_length;

  return (offset - start);
}

/* 6.22 - Query Reply (Field Outlining) */
static gint
dissect_query_reply_field_outlining(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                    gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_resbyte,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_fo_flags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_fo_vpos,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_fo_hpos,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_fo_hpos0, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_fo_hpos1, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.23 - Query Reply (Field Validation) - Search for FIELD_VALIDATION*/
/* 6.24 - Query Reply (Format Presentation) - Search for FORMAT_PRESENTATION*/

/* 6.25 - Query Reply (Format Storage Auxiliary Device)*/
static gint
dissect_query_reply_format_storage_aux_device(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                              gint sf_body_length)
{
  gint start = offset, sdp;

  static const hf_items fields[] = {
    { &hf_tn3270_fsad_flags,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_fsad_limin,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_fsad_limout, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  sdp = tvb_get_guint8(tvb, offset+1);
  if (sdp == 0x01) { /*DAID*/
    offset += dissect_daid_sd_parm(tn3270_tree, tvb, offset);
    proto_tree_add_item(tn3270_tree, hf_tn3270_fsad_size ,tvb, offset,
                        2, ENC_BIG_ENDIAN);
    offset += 2;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.26 - Query Reply (Graphic Color) - Search for GRAPHIC_COLOR*/
/* 6.27 - Query Reply (Graphic Symbol Sets) - Search for GRAPHIC_SYMBOL_SETS*/

/* 6.28 - Query Reply (Highlighting) */
static gint
dissect_query_reply_highlighting(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                 gint sf_body_length)
{
  gint start = offset;
  gint i;
  gint np;

  static const hf_items fields[] = {
    { &hf_tn3270_h_np, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };


  np = tvb_get_guint8(tvb, offset);
  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  for (i=0; i < np; i++) {
    if (tvb_get_guint8(tvb, offset) == 0xFF) {
      offset += 1;
    }
    proto_tree_add_item(tn3270_tree,
                        hf_tn3270_h_vi,
                        tvb, offset,
                        1,
                        ENC_BIG_ENDIAN);
    offset += 1;
    if (tvb_get_guint8(tvb, offset) == 0xFF) {
      offset += 1;
    }
    proto_tree_add_item(tn3270_tree,
                        hf_tn3270_h_ai,
                        tvb, offset,
                        1,
                        ENC_BIG_ENDIAN);
    offset += 1;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.29 - Query Reply (IBM Auxiliary Device) */
static gint
dissect_query_reply_ibm_aux_device(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                   gint sf_body_length)
{
  gint     start = offset, i, sdp;
  gboolean done  = FALSE;

  static const hf_items fields[] = {
    { &hf_tn3270_ibm_flags,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ibm_limin,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ibm_limout, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ibm_type,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  for (i = 0; i < 3; i++) {
    sdp = tvb_get_guint8(tvb, offset+1);
    switch (sdp) {
      case 0x02: /*Printer Name*/
        /*TODO: Printer Name */
        offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, tvb_get_guint8(tvb,offset));
        break;
      case 0x01: /*DAID*/
        offset += dissect_daid_sd_parm(tn3270_tree, tvb, offset);
        break;
      case 0x03: /*PCLK*/
        offset += dissect_pclk_sd_parm(tn3270_tree, tvb, offset);
        break;
      default:
        done = TRUE;
        break;
    }
    if ((tvb_reported_length_remaining(tvb, offset) <= 0) || done)
      break;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.30 - Query Reply (Image) */

/* 6.31 - Query Reply (Implicit Partitions) */
static gint
dissect_query_reply_implicit_partitions_sd_parms(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{

  gint start = offset;
  gint sdp_len;
  gint sdp;

  static const hf_items sdp1[] = {
    { &hf_tn3270_sdp_ln,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ip_flags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ipdd_wd,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ipdd_hd,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ipdd_wa,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ipdd_ha,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items sdp2[] = {
    { &hf_tn3270_sdp_ln,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ip_flags,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ippd_dpbs, NULL, 4, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ippd_apbs, NULL, 4, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items sdp3[] = {
    { &hf_tn3270_sdp_ln,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ip_flags,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ipccd_wcd, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ipccd_hcd, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ipccd_wca, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ipccd_hca, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  sdp_len = tvb_get_guint8(tvb, offset);
  if (sdp_len != 0x0B) {
    return 0;
  }

  sdp = tvb_get_guint8(tvb, offset+1);

  switch (sdp) {
    case QR_IP_SDP_DISPLAY:
      /* XXX: Save default and alternate screen size info as reported ? */
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp1);
      break;
    case QR_IP_SDP_PRINTER:
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp2);
      break;
    case QR_IP_SDP_CHARACTER:
      offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                    sdp3);
      break;
    default:
      return 0;
  }

  return (offset - start);

}

static gint
dissect_query_reply_implicit_partitions(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                        gint sf_body_length)
{
  gint start = offset;
  gint i;

  static const hf_items fields[] = {
    { &hf_tn3270_ip_flags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ip_flags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  for (i = 0; i < 3; i++) {
    gint len;
    len = dissect_query_reply_implicit_partitions_sd_parms(tn3270_tree, tvb, offset);
    if ((len == 0) || (tvb_reported_length_remaining(tvb, offset) <= 0))
      break;
    offset += len;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.32 - Query Reply (IOCA Auxiliary Device) */
static gint
dissect_query_reply_ioca_aux_device(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                    gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_resbyte,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_resbyte,     NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ioca_limin,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ioca_limout, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ioca_type,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.33 - Query Reply (Line Type) - Search for LINE_TYPE*/

/* 6.34 - Query Reply (MSR Control) */
static gint
dissect_query_reply_msr_control(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_resbyte,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_msr_nd,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_msr_type, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);
  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.35 - Query Reply (Null) - Search for QUERY_REPLY_NULL */

/* 6.36 - Query Reply (OEM Auxiliary Device) */
static gint
dissect_query_reply_oem_auxiliary_device(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                         gint sf_body_length)
{
  gint start = offset;
  gint i;

  static const hf_items fields[] = {
    { &hf_tn3270_resbyte,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_oem_dsref, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_oem_dtype, NULL, 8, NULL, ENC_EBCDIC|ENC_NA },
    { &hf_tn3270_oem_uname, NULL, 8, NULL, ENC_EBCDIC|ENC_NA },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  for (i = 0; i < 3; i++) {
    offset += dissect_query_reply_oem_auxiliary_device_sd_parms(tn3270_tree, tvb, offset);
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
      break;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.37 - Query Reply (Paper Feed Techniques) */
static gint
dissect_query_reply_paper_feed_techniques(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                          gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_pft_flags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_pft_tmo,   NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_pft_bmo,   NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);
  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.38 - Query Reply (Partition Characteristics) */
static gint
dissect_query_reply_partition_characteristics(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                              gint sf_body_length)
{
  gint     start = offset, i, sdp;
  gboolean done  = FALSE;

  static const hf_items fields[] = {
    { &hf_tn3270_sdp_ln, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  for (i = 0; i < 2; i++) {
    sdp = tvb_get_guint8(tvb, offset+1);
    switch (sdp) {
      case 0x01: /*Viewport Outline*/
        offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                      fields);
        proto_tree_add_item(tn3270_tree, hf_tn3270_pc_vo_thickness,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;
      case 0x03: /*Enable User Call-Up*/
        offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                      fields);
        break;
      default:
        done = TRUE;
        break;
    }
    if ((tvb_reported_length_remaining(tvb, offset) <= 0) || done)
      break;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.39 - Query Reply (Port) - Search for QUERY_REPLY_PORT */
/* 6.40 - Query Reply (Procedure) - Search for QUERY_REPLY_PROCEDURE */

/* 6.41 - Query Reply ((Product Defined Data Stream) */
static gint
dissect_query_reply_product_defined_data_stream(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                                gint sf_body_length)
{
  gint start = offset, sdp;

  static const hf_items fields[] = {
    { &hf_tn3270_resbytes,   NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_pdds_refid, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_pdds_ssid,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  sdp = tvb_get_guint8(tvb, offset+1);
  if (sdp == 0x01) { /*DAID*/
    offset += dissect_daid_sd_parm(tn3270_tree, tvb, offset);
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.42 - Query Reply (Modes) */
static gint
dissect_query_reply_modes(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                          gint sf_body_length)
{
  gint start = offset;
  gint i;

  for (i=0; i < sf_body_length; i++) {
    proto_tree_add_item(tn3270_tree,
                        hf_tn3270_mode,
                        tvb, offset,
                        1,
                        ENC_BIG_ENDIAN);
    offset += 1;
  }

  return (offset - start);
}

/* 6.43 - Query Reply (RPQ Names) */
static gint
dissect_query_reply_rpq_names(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                              gint sf_body_length)
{
  gint start = offset;
  gint rpql;

  static const hf_items fields[] = {
    { &hf_tn3270_rpq_device, NULL, 4, NULL, ENC_EBCDIC|ENC_NA },
    { &hf_tn3270_rpq_mid,    NULL, 4, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  rpql = tvb_get_guint8(tvb, offset);

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_rpq_rpql,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_rpq_name,
                      tvb, offset,
                      (rpql - 1),
                      ENC_EBCDIC|ENC_NA);
  offset += (rpql-1);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.44 - Query Reply (Save/Restore Format) */
static gint
dissect_query_reply_save_or_restore_format(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                           gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_srf_fpcbl, NULL, 1, NULL, ENC_NA },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.45 - Query Reply (Segment) - Search for QUERY_REPLY_SEGMENT */

/* 6.46 - Query Reply ((Settable Printer Characteristics) */
static gint
dissect_query_reply_settable_printer_characteristics(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                                     gint sf_body_length)
{
  gint start = offset, sdp;

  static const hf_items fields[] = {
    { &hf_tn3270_resbytes, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items fields2[] = {
    { &hf_tn3270_sdp_ln, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  sdp = tvb_get_guint8(tvb, offset+1);
  if (sdp == 0x01) { /*Early Print Complete*/
    offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                  fields2);
    proto_tree_add_item(tn3270_tree, hf_tn3270_spc_epc_flags, tvb, offset,
                        1, ENC_BIG_ENDIAN);
    offset += 1;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.47 - Query Reply (Storage Pools) */
static gint
dissect_query_reply_storage_pools(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                  gint sf_body_length)
{
  gint start = offset, sdp, i;

  static const hf_items fields2[] = {
    { &hf_tn3270_sdp_ln,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sdp_id,   NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sp_spid,  NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sp_size,  NULL, 4, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_sp_space, NULL, 4, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  sdp = tvb_get_guint8(tvb, offset+1);
  if (sdp == 0x01) { /* Storage Pool Characteristics */
    offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                  fields2);
    for (i=0; i < (sf_body_length-(offset-start)); i+=2) {
      proto_tree_add_item(tn3270_tree, hf_tn3270_sp_objlist,
                          tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.48 - Query Reply (Summary) */
static gint
dissect_query_reply_summary(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                            gint sf_body_length)
{
  gint i;
  gint datalen          = 0;
  gint length_remaining = tvb_reported_length_remaining(tvb, offset);

  for (i=0; i < sf_body_length; i++) {
    if (datalen >= length_remaining) {
      return (datalen);
    }
    proto_tree_add_item(tn3270_tree,
                        hf_tn3270_sf_query_reply,
                        tvb, offset + datalen,
                        1,
                        ENC_BIG_ENDIAN);
    datalen += 1;
  }
  datalen += dissect_unknown_data(tn3270_tree, tvb, offset+datalen, offset, sf_body_length);

  return (datalen);
}

/* 6.49 - Query Reply (Text Partitions) */
static gint
dissect_query_reply_text_partitions(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                    gint sf_body_length)
{
  gint start = offset, len, i;

  static const hf_items fields[] = {
    { &hf_tn3270_tp_nt,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_tp_m,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_tp_flags, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  len = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tn3270_tree, hf_tn3270_tp_ntt, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  for (i=0; i < len; i++) {
    proto_tree_add_item(tn3270_tree, hf_tn3270_tp_tlist,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.50 - Query Reply (Transparency) */
static gint
dissect_query_reply_transparency(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                 gint sf_body_length)
{
  gint start = offset, i, len;

  len = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tn3270_tree, hf_tn3270_t_np, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  for (i=0; i < len; i+=2) {
    proto_tree_add_item(tn3270_tree, hf_tn3270_t_vi,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tn3270_tree, hf_tn3270_t_ai,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
  }

  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.51 - Query Reply Usable Area */
static gint
dissect_query_reply_usable_area(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                gint sf_body_length)
{
  gint start = offset;
  gint vcp;

  static const gint *byte1[] = {
    &hf_tn3270_ua_reserved1,
    &hf_tn3270_ua_page_printer,
    &hf_tn3270_ua_reserved2,
    &hf_tn3270_ua_hard_copy,
    &hf_tn3270_ua_addressing,
    NULL
  };

  static const gint *byte2[] = {
    &hf_tn3270_ua_variable_cells,
    &hf_tn3270_ua_characters,
    &hf_tn3270_ua_cell_units,
    NULL
  };

  static const hf_items fields[] = {
    { &hf_tn3270_usable_area_flags1,   &ett_tn3270_usable_area_flags1, 1, byte1, 0 },
    { &hf_tn3270_usable_area_flags2,   &ett_tn3270_usable_area_flags1, 1, byte2, 0 },
    { &hf_tn3270_ua_width_cells_pels,  NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ua_height_cells_pels, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ua_uom_cells_pels,    NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ua_xr,                NULL, 4, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ua_yr,                NULL, 4, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ua_aw,                NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ua_ah,                NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ua_buffsz,            NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  static const hf_items fields2[] = {
    { &hf_tn3270_ua_xmin, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ua_ymin, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ua_xmax, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_ua_ymax, NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  vcp = tvb_get_guint8(tvb, offset+1);

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);

  if ((vcp & QR_UA_VARIABLE_CELLS) != 0) {
    offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                  fields2);
  }

  /*TODO: self defining parms */
  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* 6.52 - Query Reply 3270 IPDS */
static gint
dissect_query_reply_3270_ipds(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                              gint sf_body_length)
{
  gint start = offset;

  static const hf_items fields[] = {
    { &hf_tn3270_resbytes,     NULL, 2, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_3270_tranlim, NULL, 2, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  offset += tn3270_add_hf_items(tn3270_tree, tvb, offset,
                                fields);
  offset += dissect_unknown_data(tn3270_tree, tvb, offset, start, sf_body_length);

  return (offset - start);
}

/* sf_body_length is the total length of the structured field including the sf_len and sf_id fields */
/* call only with valid sf_id */
static gint
process_inbound_structured_field(proto_tree *sf_tree, tvbuff_t *tvb, gint offset,
                                 tn3270_conv_info_t *tn3270_info, guint sf_id,  gint sf_body_length)
{
  gint start = offset;          /* start of structured field param(s) */

  switch (sf_id) {
  case SF_IB_EXCEPTION_OR_STATUS:
    offset += dissect_exception_or_status(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_INBOUND_TEXT_HEADER:
    offset += dissect_inbound_text_header(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_INBOUND_3270DS:
    offset += dissect_inbound_3270ds(sf_tree, tvb, offset, tn3270_info, sf_body_length);
    break;
  case SF_IB_RECOVERY_DATA:
    offset += dissect_recovery_data(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_TYPE_1_TEXT_INBOUND:
    offset += dissect_type_1_text(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_ALPHANUMERIC_PARTITIONS:
    offset += dissect_query_reply_alphanumeric(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_AUXILIARY_DEVICE:
  case SF_IB_QUERY_REPLY_BEGIN_OR_END_OF_FILE:
    offset += dissect_query_reply_resbytes(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_CHARACTER_SETS:
    offset += dissect_query_reply_character_sets(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_COLOR:
    offset += dissect_query_reply_color(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_COOPERATIVE_PROCESSING_REQUESTOR:
    offset += dissect_query_reply_cooperative(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_DATA_CHAINING:
    offset += dissect_query_reply_data_chaining(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_DATA_STREAMS:
    offset += dissect_query_reply_data_streams(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_DBCS_ASIA:
    offset += dissect_query_reply_dbcs_asia(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_DEVICE_CHARACTERISTICS:
    /*TODO: implement this beast */
    offset += dissect_query_reply_device_characteristics(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_SUMMARY:
    offset += dissect_query_reply_summary(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_USABLE_AREA:
    offset += dissect_query_reply_usable_area(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_HIGHLIGHTING:
    offset += dissect_query_reply_highlighting(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_REPLY_MODES:
    offset += dissect_query_reply_modes(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_DISTRIBUTED_DATA_MANAGEMENT:
    offset += dissect_query_reply_distributed_data_management(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_RPQ_NAMES:
    offset += dissect_query_reply_rpq_names(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_IMPLICIT_PARTITION:
    offset += dissect_query_reply_implicit_partitions(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_OEM_AUXILIARY_DEVICE:
    offset += dissect_query_reply_oem_auxiliary_device(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_DOCUMENT_INTERCHANGE_ARCHITECTURE:
    offset += dissect_query_reply_document_interchange_architecture(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_EXTENDED_DRAWING_ROUTINE:
    offset += dissect_query_reply_extended_drawing_routine(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_FIELD_OUTLINING:
    offset += dissect_query_reply_field_outlining(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_FIELD_VALIDATION:
    offset += dissect_3270_field_validation(sf_tree, tvb, offset);
    break;
  case SF_IB_QUERY_REPLY_FORMAT_STORAGE_AUXILIARY_DEVICE:
    offset += dissect_query_reply_format_storage_aux_device(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_GRAPHIC_COLOR:
  case SF_IB_QUERY_REPLY_GRAPHIC_SYMBOL_SETS:
  case SF_IB_QUERY_REPLY_IMAGE:
  case SF_IB_QUERY_REPLY_LINE_TYPE:
  case SF_IB_QUERY_REPLY_PROCEDURE:
  case SF_IB_QUERY_REPLY_SEGMENT:
    /* Not an error - just has a data field like 'extended drawing'*/
    offset += dissect_query_reply_extended_drawing_routine(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_IBM_AUXILIARY_DEVICE:
    offset += dissect_query_reply_ibm_aux_device(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_IOCA_AUXILIARY_DEVICE:
    offset += dissect_query_reply_ioca_aux_device(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_MSR_CONTROL:
    offset += dissect_query_reply_msr_control(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_FORMAT_PRESENTATION:
  case SF_IB_QUERY_REPLY_NULL:
  case SF_IB_QUERY_REPLY_PORT:
    /* This field is always empty */
    break;
  case SF_IB_QUERY_REPLY_PAPER_FEED_TECHNIQUES:
    offset += dissect_query_reply_paper_feed_techniques(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_PARTITION_CHARACTERISTICS:
    offset += dissect_query_reply_partition_characteristics(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_PRODUCT_DEFINED_DATA_STREAM:
    offset += dissect_query_reply_product_defined_data_stream(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_SAVE_OR_RESTORE_FORMAT:
    offset += dissect_query_reply_save_or_restore_format(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_SETTABLE_PRINTER_CHARACTERISTICS:
    offset += dissect_query_reply_settable_printer_characteristics(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_STORAGE_POOLS:
    offset += dissect_query_reply_storage_pools(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_TEXT_PARTITIONS:
    offset += dissect_query_reply_text_partitions(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_TRANSPARENCY:
    offset += dissect_query_reply_transparency(sf_tree, tvb, offset, sf_body_length);
    break;
  case SF_IB_QUERY_REPLY_3270_IPDS:
    offset += dissect_query_reply_3270_ipds(sf_tree, tvb, offset, sf_body_length);
    break;
  default:
    DISSECTOR_ASSERT_NOT_REACHED();
    break;
  }

  return (offset - start);
}


/* sf_body_length is the total length of the structured field including the sf_len and sf_id fields */
/* call only with valid sf_id */
static gint
process_outbound_structured_field(proto_tree *sf_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset,
                                  tn3270_conv_info_t *tn3270_info, guint sf_id, gint sf_body_length)
{
  gint start = offset;          /* start of structured field param(s) */

  switch (sf_id) {
    case SF_OB_READ_PARTITION:
      offset += dissect_read_partition(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_ACTIVATE_PARTITION:
    case SF_OB_DESTROY_PARTITION:
    case SF_OB_RESET_PARTITION:
      proto_tree_add_item(sf_tree,
                          hf_tn3270_partition_id,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      break;
    case SF_OB_CREATE_PARTITION:
      offset += dissect_create_partition(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_ERASE_OR_RESET:
      /* Bit 0: 0= Use default screen size; 1= use alternate screen size     */
      /* XXX: Not really valid: See comment under dissect_outbound_stream(). */
      if ((tvb_get_guint8(tvb, offset) & 0x80) != 0) {
        tn3270_info->rows = tn3270_info->altrows;
        tn3270_info->cols = tn3270_info->altcols;
      }
      else {
        tn3270_info->rows = 24;
        tn3270_info->cols = 80;
      }
      proto_tree_add_bits_item(sf_tree,
                               hf_tn3270_erase_flags,
                               tvb, offset<<3,
                               1,
                               ENC_BIG_ENDIAN);
      offset += 1;
      break;
    case SF_OB_LOAD_PROGRAMMED_SYMBOLS:
      offset += dissect_load_programmed_symbols(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_OUTBOUND_3270DS:
      offset += dissect_outbound_3270ds(sf_tree, pinfo, tvb, offset, tn3270_info, sf_body_length);
      break;
    case SF_OB_PRESENT_ABSOLUTE_FORMAT:
      offset += dissect_present_absolute_format(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_PRESENT_RELATIVE_FORMAT:
      offset += dissect_present_relative_format(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_SCS_DATA:
      proto_tree_add_item(sf_tree,
                          hf_tn3270_partition_id,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(sf_tree,
                          hf_tn3270_scs_data,
                          tvb, offset,
                          (sf_body_length - (offset - start)),
                          ENC_NA);
      offset += (sf_body_length - (offset - start));
      break;
    case SF_OB_SET_REPLY_MODE:
      offset += dissect_set_reply_mode(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_SELECT_FORMAT_GROUP:
      proto_tree_add_item(sf_tree,
                          hf_tn3270_partition_id,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(sf_tree,
                          hf_tn3270_format_group,
                          tvb, offset,
                          (sf_body_length - (offset - start)),
                          ENC_EBCDIC|ENC_NA);
      offset += (sf_body_length - (offset - start));
      break;
    case SF_OB_SET_WINDOW_ORIGIN:
      proto_tree_add_item(sf_tree,
                          hf_tn3270_partition_id,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(sf_tree,
                          hf_tn3270_partition_rw,
                          tvb, offset,
                          2,
                          ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(sf_tree,
                          hf_tn3270_partition_cw,
                          tvb, offset,
                          2,
                          ENC_BIG_ENDIAN);
      offset += 2;
      break;
    case SF_OB_BEGIN_OR_END_OF_FILE:
      proto_tree_add_item(sf_tree,
                          hf_tn3270_partition_id,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      /*TODO: use bits_text */
      proto_tree_add_bits_item(sf_tree,
                               hf_tn3270_begin_end_flags1,
                               tvb, offset<<3,
                               2,
                               ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(sf_tree,
                          hf_tn3270_begin_end_flags2,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      break;
    case SF_OB_LOAD_COLOR_TABLE:
      /* Refer to related graphics docs !*/
      proto_tree_add_item(sf_tree,
                          hf_tn3270_load_color_command,
                          tvb, offset,
                          sf_body_length,
                          ENC_NA);
      offset += sf_body_length;
      break;
    case SF_OB_LOAD_FORMAT_STORAGE:
      offset += dissect_load_format_storage(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_LOAD_LINE_TYPE:
      /* Refer to related graphics docs !*/
      proto_tree_add_item(sf_tree,
                          hf_tn3270_load_line_type_command,
                          tvb, offset,
                          sf_body_length,
                          ENC_NA);
      offset += sf_body_length;
      break;
    case SF_OB_MODIFY_PARTITION:
      offset += dissect_modify_partition(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_OUTBOUND_TEXT_HEADER:
      offset += dissect_outbound_text_header(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_REQUEST_RECOVERY_DATA:
      proto_tree_add_item(sf_tree,
                          hf_tn3270_resbyte,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      break;
    case SF_OB_RESTART:
      offset += dissect_restart(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_SELECT_COLOR_TABLE:
      proto_tree_add_item(sf_tree,
                          hf_tn3270_color_command,
                          tvb, offset,
                          2,
                          ENC_BIG_ENDIAN);
      offset += 2;
      break;
    case SF_OB_SET_CHECKPOINT_INTERVAL:
      proto_tree_add_item(sf_tree,
                          hf_tn3270_resbyte,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(sf_tree,
                          hf_tn3270_interval,
                          tvb, offset,
                          2,
                          ENC_BIG_ENDIAN);
      offset += 2;
      break;
    case SF_OB_SET_MSR_CONTROL:
      offset += dissect_set_msr_control(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_SET_PARTITION_CHARACTERISTICS:
      offset += dissect_set_partition_characteristics(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_SET_PRINTER_CHARACTERISTICS:
      offset += dissect_set_printer_characteristics(sf_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_TYPE_1_TEXT_OUTBOUND:
      offset += dissect_type_1_text(sf_tree, tvb, offset, sf_body_length);
      break;
    default:
      DISSECTOR_ASSERT_NOT_REACHED();
      break;
  }

  return (offset - start);
}

/* sf_body_length is the total length of the structured field including the sf_len and sf_id fields */
/* call only with valid sf_id */
static gint
process_outbound_inbound_structured_field(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                                           tn3270_conv_info_t *tn3270_info _U_, guint sf_id, gint sf_body_length)
{
  gint start = offset;

  switch (sf_id) {
    case SF_OB_IB_DATA_CHAIN:
      offset += dissect_data_chain(tn3270_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_IB_DESTINATION_OR_ORIGIN:
      proto_tree_add_item(tn3270_tree,
                               hf_tn3270_destination_or_origin_flags_input_control,
                               tvb, offset,
                               1,
                               ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(tn3270_tree,
                          hf_tn3270_resbyte,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(tn3270_tree,
                          hf_tn3270_destination_or_origin_doid,
                          tvb, offset,
                          2,
                          ENC_BIG_ENDIAN);
      offset += 2;
      break;
    case SF_OB_IB_OBJECT_DATA:
    case SF_OB_IB_OBJECT_CONTROL:
    case SF_OB_IB_OBJECT_PICTURE:
    case SF_OB_IB_OEM_DATA: /* FIXME: Not really but same layout */
      offset += dissect_object_control(tn3270_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_IB_SAVE_OR_RESTORE_FORMAT:
      offset += dissect_save_or_restore_format(tn3270_tree, tvb, offset, sf_body_length);
      break;
    case SF_OB_IB_SELECT_IPDS_MODE:
      proto_tree_add_item(tn3270_tree,
                          hf_tn3270_resbytes,
                          tvb, offset,
                          2,
                          ENC_BIG_ENDIAN);
      offset += 2;
      break;
    default:
      DISSECTOR_ASSERT_NOT_REACHED();
      break;
  }

  return (offset - start);
}

static proto_tree *
display_sf_hdr(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset,
                   gint sf_length, guint sf_id, guint sf_id_len, const gchar *sf_id_str)
{
  proto_tree *sf_tree;

  sf_tree = proto_tree_add_subtree_format(tn3270_tree, tvb, offset, sf_length,
                           ett_sf, NULL, "Structured Field: %s", sf_id_str);

  proto_tree_add_item(sf_tree,
                      hf_tn3270_sf_length,
                      tvb, offset,
                      2,
                      ENC_BIG_ENDIAN);

  proto_tree_add_uint_format_value(sf_tree,
                                   (sf_id_len == 1) ? hf_tn3270_sf_single_byte_id : hf_tn3270_sf_double_byte_id,
                                   tvb, offset+2, sf_id_len,
                                   sf_id, "%s (0x%0*x)", sf_id_str, sf_id_len*2, sf_id);

  return sf_tree;
}

static gint
dissect_structured_fields(proto_tree *tn3270_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset,
                          tn3270_conv_info_t *tn3270_info, gboolean direction_inbound)
{
  proto_tree  *sf_tree;
  gint         start;
  gint         sf_length;
  guint        sf_id;
  guint        sf_id_len;
  const gchar *sf_id_str;

  start = offset;

  while (tvb_reported_length_remaining(tvb, offset) >= 2) {

    /* Handle NULL bytes until we find a length value */
    /* XXX: An earlier version of the code for structured field    */
    /*      processing did this check only for inbound structured  */
    /*      fields. Should the same be done in this code which     */
    /*      combines handling for both inbound and outbound        */
    /*      structured fields ?                                    */
    if ((sf_length = tvb_get_ntohs(tvb, offset)) == 0) {
      proto_tree_add_item(tn3270_tree,
                          hf_tn3270_null,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      continue;
    }

    sf_id     = tvb_get_guint8(tvb, offset+2);
    sf_id_len = 1;
    if ((sf_id == 0x0F) ||
        (sf_id == 0x10) ||
        (sf_id == 0x81)) {
      sf_id = (sf_id << 8) + tvb_get_guint8(tvb, offset+3);
      sf_id_len = 2;
    }

    sf_id_str = try_val_to_str(sf_id, direction_inbound ?
                             vals_inbound_structured_fields : vals_outbound_structured_fields);
    if (sf_id_str != NULL) {
      sf_tree = display_sf_hdr(tn3270_tree, tvb, offset,
                               sf_length, sf_id, sf_id_len, sf_id_str);
      offset += (sf_id_len + 2);
      if (direction_inbound) {
        offset += process_inbound_structured_field(sf_tree, tvb, offset, tn3270_info, sf_id, sf_length-2-sf_id_len);
      }
      else {
        offset += process_outbound_structured_field(sf_tree, pinfo, tvb, offset, tn3270_info, sf_id, sf_length-2-sf_id_len);
      }
      continue;
    }

    /* Not found above: See if an "outbound-inbound" field */
    sf_id_str = try_val_to_str(sf_id, vals_outbound_inbound_structured_fields);
    if (sf_id_str != NULL) {
      sf_tree = display_sf_hdr(tn3270_tree, tvb, offset,
                               sf_length, sf_id, sf_id_len, sf_id_str);
      offset += (sf_id_len + 2);
      offset += process_outbound_inbound_structured_field(sf_tree, tvb, offset, tn3270_info, sf_id, sf_length-2-sf_id_len);
      continue;
    }

    /* Not found */
    sf_id_str = wmem_strdup_printf(wmem_packet_scope(), "Unknown [%0*x]", sf_id_len*2, sf_id);
    display_sf_hdr(tn3270_tree, tvb, offset, sf_length,
                   sf_length, sf_id_len, sf_id_str);
    offset += sf_length;
  } /* while */

  return (offset - start);
}


/* Start: Handle WCC, Orders and Data */

static gint
dissect_stop_address(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{
  gint start = offset;
  gint is_oc_ge;

  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_stop_address,
                      tvb, offset,
                      2,
                      ENC_BIG_ENDIAN);
  offset += 1;
  is_oc_ge = tvb_get_guint8(tvb, offset);
  if (is_oc_ge != OC_GE) {
    proto_tree_add_item(tn3270_tree,
                        hf_tn3270_character_code,
                        tvb, offset,
                        1,
                        ENC_BIG_ENDIAN);
    offset += 1;
  }

  return (offset - start);
}

/*
 * From section "4.3.3 Set Buffer Address (SBA)" of the IBM document
 * cited above.
 */

/*
 * Address format.
 *
 * XXX - what about 16-bit addressing?
 */
#define SBA_ADDRESS_FORMAT_MASK 0xC000
#define SBA_ADDRESS_MASK_SHIFT  14
#define SBA_ADDRESS_FORMAT(address)     (((address) & SBA_ADDRESS_FORMAT_MASK) >> SBA_ADDRESS_MASK_SHIFT)

#define SBA_ADDRESS_VALUE_MASK  0x3FFF
#define SBA_ADDRESS_VALUE(address)      ((address) & SBA_ADDRESS_VALUE_MASK)

#define SBA_14_BIT_BINARY       0x0
#define SBA_12_BIT_CODED_1      0x1
#define SBA_RESERVED            0x2
#define SBA_12_BIT_CODED_2      0x3

static gint
dissect_buffer_address(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset, gint hf, tn3270_conv_info_t *tn3270_info)
{
  gint    start = offset;
  guint16 buffer_addr;
  guint16 address_format, address_value;
  guint8  b1, b2;
  guint8  rowsx = tn3270_info->rows;
  guint8  colsx = tn3270_info->cols;

  buffer_addr    = tvb_get_ntohs(tvb, offset);
  address_format = SBA_ADDRESS_FORMAT(buffer_addr);
  address_value  = SBA_ADDRESS_VALUE(buffer_addr);

  /*
   * XXX - put the address format and address value into the protocol
   * tree as bitfields under these items?
   */
  switch (address_format) {

    case SBA_14_BIT_BINARY:
      proto_tree_add_uint_format_value(tn3270_tree,
                                       hf,
                                       tvb, offset, 2,
                                       buffer_addr,
                                       "14-bit address, %u = row %u, column %u [assuming a %ux%u display] (0x%04x)",
                                       address_value,
                                       (address_value / colsx) + 1,
                                       (address_value % colsx) + 1,
                                       rowsx, colsx,
                                       buffer_addr);
      break;

    case SBA_12_BIT_CODED_1:
    case SBA_12_BIT_CODED_2:
      /*
       * This is a wacky encoding.  At least as I read the IBM document
       * in question, the lower 6 bits of the first byte of the SBA
       * address, and the lower 6 bits of the second byte of the SBA
       * address, are combined into a 12-bit binary address.  The upper
       * 2 bits of the first byte are the address format; the upper 2
       * bits of the second byte are ignored.
       */
      b1 = (address_value >> 8) & 0x3F;
      b2 = (address_value >> 0) & 0x3F;
      address_value = (b1 << 6) | b2;
      proto_tree_add_uint_format_value(tn3270_tree,
                                       hf,
                                       tvb, offset, 2,
                                       buffer_addr,
                                       "12-bit address, %u = row %u, column %u [assuming a %ux%u display] (0x%04x)",
                                       address_value,
                                       (address_value / colsx) + 1,
                                       (address_value % colsx) + 1,
                                       rowsx, colsx,
                                       buffer_addr);
      break;

    case SBA_RESERVED:
      proto_tree_add_uint_format_value(tn3270_tree,
                                       hf,
                                       tvb, offset, 2,
                                       buffer_addr,
                                       "Reserved (0x%04x)",
                                       buffer_addr);
      break;
  }
  offset += 2;

  return (offset - start);
}

static gint
dissect_field_attribute_pair(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{
  gint start = offset;
  gint attribute_type;

  attribute_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_attribute_type,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;
  switch (attribute_type) {
    case AT_ALL_CHARACTER_ATTRIBUTES:
      proto_tree_add_item(tn3270_tree,
                          hf_tn3270_all_character_attributes,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      break;
    case AT_T3270_FIELD_ATTRIBUTE:
      offset += dissect_3270_field_attribute(tn3270_tree, tvb, offset);
      break;
    case AT_EXTENDED_HIGHLIGHTING:
      proto_tree_add_item(tn3270_tree,
                          hf_tn3270_extended_highlighting,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      break;
    case AT_FOREGROUND_COLOR:
    case AT_BACKGROUND_COLOR:
      proto_tree_add_item(tn3270_tree,
                          hf_tn3270_color,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      break;
    case AT_CHARACTER_SET:
      proto_tree_add_item(tn3270_tree,
                          hf_tn3270_character_set,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      break;
    case AT_FIELD_OUTLINING:
      proto_tree_add_item(tn3270_tree,
                          hf_tn3270_field_outlining,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      break;
    case AT_TRANSPARENCY:
      proto_tree_add_item(tn3270_tree,
                          hf_tn3270_transparency,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;
      break;
    case AT_FIELD_VALIDATION:
      offset += dissect_3270_field_validation(tn3270_tree, tvb, offset);
      break;
  }

  return (offset - start);
}

static gint
dissect_field_attribute_pairs(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{
  gint start = offset;
  gint no_of_pairs;
  gint i;

  no_of_pairs = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tn3270_tree,
                      hf_tn3270_number_of_attributes,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;

  for (i=0; i < no_of_pairs; i++) {
    offset += dissect_field_attribute_pair(tn3270_tree, tvb, offset);
  }

  return (offset - start);
}

static gint
dissect_orders_and_data(proto_tree *tn3270_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, tn3270_conv_info_t *tn3270_info)
{
  gint start = offset;
  gint order_code;
  proto_item* item;

  /* Order Code */

  /* XXX: '0' is treated as data; See comment under add_data_until_next_order_code() */
  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    order_code = tvb_get_guint8(tvb, offset);
    if ((order_code > 0) && (order_code <= OC_MAX)) {  /* XXX: also 0xFF ?? */
      item = proto_tree_add_item(tn3270_tree,
                          hf_tn3270_order_code,
                          tvb, offset,
                          1,
                          ENC_BIG_ENDIAN);
      offset += 1;

      switch (order_code) {
        case OC_SF:
          offset += dissect_3270_field_attribute(tn3270_tree, tvb, offset);
          break;
        case OC_MF:
        case OC_SFE:
          offset += dissect_field_attribute_pairs(tn3270_tree, tvb, offset);
          break;
        case OC_SA:
          offset += dissect_field_attribute_pair(tn3270_tree, tvb, offset);
          break;
        case OC_EUA:
        case OC_RA:
          offset += dissect_stop_address(tn3270_tree, tvb, offset);
          break;
        case OC_GE:
          proto_tree_add_item(tn3270_tree,
                              hf_tn3270_character_code,
                              tvb, offset,
                              1,
                              ENC_BIG_ENDIAN);
          offset += 1;
          break;
        case OC_SBA:
          offset += dissect_buffer_address(tn3270_tree, tvb, offset, hf_tn3270_buffer_address, tn3270_info);
          break;
        case OC_PT:   /* XXX: This case was previously commented out; I don't know why */
        case OC_IC:
          break;
        default:
          expert_add_info(pinfo, item, &ei_tn3270_order_code);
          break;
      } /* switch */
    }
    else {
      offset += add_data_until_next_order_code(tn3270_tree, tvb, offset);
    }
  } /* while */

  return (offset - start);
}

/* End: Handle WCC, Orders and Data */


static gint
dissect_tn3270e_header(proto_tree *tn3270_tree, tvbuff_t *tvb, gint offset)
{
  proto_item *pi;
  proto_tree *tn3270e_hdr_tree;
  gint        start = offset;
  gint        data_type;

  static const hf_items fields[] = {
    { &hf_tn3270_tn3270e_data_type,              NULL, 1, NULL, ENC_BIG_ENDIAN },
    { &hf_tn3270_tn3270e_request_flag,           NULL, 1, NULL, ENC_BIG_ENDIAN },
    { NULL, NULL, 0, NULL, 0 }
  };

  data_type = tvb_get_guint8(tvb, offset);

  tn3270e_hdr_tree = proto_tree_add_subtree_format(tn3270_tree, tvb, offset, -1,
                           ett_tn3270e_hdr, &pi, "TN3270E Header (Data Type: %s)",
                           val_to_str_const(data_type, vals_tn3270_header_data_types, "Unknown"));

  offset += tn3270_add_hf_items(tn3270e_hdr_tree, tvb, offset,
                                fields);
  switch(data_type) {
    case TN3270E_3270_DATA:
    case TN3270E_SCS_DATA:
      proto_tree_add_item(tn3270e_hdr_tree, hf_tn3270_tn3270e_response_flag_3270_SCS, tvb, offset, 1, ENC_BIG_ENDIAN);
      break;
    case TN3270E_RESPONSE:
      proto_tree_add_item(tn3270e_hdr_tree, hf_tn3270_tn3270e_response_flag_response, tvb, offset, 1, ENC_BIG_ENDIAN);
      break;
    case TN3270E_BIND_IMAGE:
    case TN3270E_NVT_DATA:
    case TN3270E_REQUEST:
    case TN3270E_SSCP_LU_DATA:
    case TN3270E_UNBIND:
    default:
      proto_tree_add_item(tn3270e_hdr_tree, hf_tn3270_tn3270e_response_flag_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
      break;
  }
  offset += 1;

  proto_tree_add_item(tn3270e_hdr_tree, hf_tn3270_tn3270e_seq_number, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  switch (data_type) {
    case TN3270E_BIND_IMAGE:
    case TN3270E_NVT_DATA:
    case TN3270E_REQUEST:
    case TN3270E_RESPONSE:
    case TN3270E_SCS_DATA:
    case TN3270E_SSCP_LU_DATA:
    case TN3270E_UNBIND:
      proto_tree_add_item(tn3270e_hdr_tree, hf_tn3270_tn3270e_header_data, tvb, offset, -1, ENC_EBCDIC|ENC_NA);
      offset += tvb_reported_length_remaining(tvb, offset);
      break;
    default:
      break;
  }

  proto_item_set_len(pi, offset - start);

  return (offset - start);
}

/* Detect and Handle Direction of Stream */
static gint
dissect_outbound_stream(proto_tree *tn3270_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, tn3270_conv_info_t *tn3270_info)
{
  gint command_code;
  gint start = offset;
  proto_item* item;

  /* Command Code*/
  command_code = tvb_get_guint8(tvb, offset);

  /* XXX: Storing rows/cols each time they change is not valid         */
  /*      since packets can (will be) randomly selected for dissection */
  /*      after the initial dissection pass. In actuality screen size  */
  /*      "state" needs to be associated in some manner with each      */
  /*      frame of a conversation.                                     */
  switch (command_code) {
    case CC_LCL_EW:
    case CC_RMT_EW:
      tn3270_info->rows = 24;
      tn3270_info->cols = 80;
      break;
    case CC_LCL_EWA:
    case CC_RMT_EWA:
      tn3270_info->rows = tn3270_info->altrows;
      tn3270_info->cols = tn3270_info->altcols;
      break;
    default:
      break;
  }

  item = proto_tree_add_item(tn3270_tree,
                        hf_tn3270_command_code,
                        tvb, offset,
                        1,
                        ENC_BIG_ENDIAN);
  offset += 1;

  switch (command_code) {
    case CC_LCL_W:
    case CC_LCL_EW:
    case CC_LCL_EWA:
    case CC_LCL_EAU:
    case CC_RMT_W:
    case CC_RMT_EW:
    case CC_RMT_EWA:
    case CC_RMT_EAU:
      /* WCC */
      offset += dissect_wcc(tn3270_tree, tvb, offset);
      offset += dissect_orders_and_data(tn3270_tree, pinfo, tvb, offset, tn3270_info);
      break;
    case CC_LCL_WSF:
    case CC_RMT_WSF:
      offset += dissect_structured_fields(tn3270_tree, pinfo, tvb, offset, tn3270_info, FALSE);
      break;
    case CC_LCL_RB:
    case CC_LCL_RM:
    case CC_LCL_RMA:
    case CC_RMT_RB:
    case CC_RMT_RM:
    case CC_RMT_RMA:
      break;
    default:
      expert_add_info(pinfo, item, &ei_tn3270_command_code);
      break;
  }

  return (offset - start);

}

/* INBOUND DATA STREAM (DISPLAY -> MAINFRAME PROGRAM) */
/* Dissect tvb as inbound */
static gint
dissect_inbound_stream(proto_tree *tn3270_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, tn3270_conv_info_t *tn3270_info)
{
  gint start = offset;
  gint aid;
  proto_item* item;

  /* Command Code*/
  aid = tvb_get_guint8(tvb, offset);
  item = proto_tree_add_item(tn3270_tree,
                      hf_tn3270_aid,
                      tvb, offset,
                      1,
                      ENC_BIG_ENDIAN);
  offset += 1;
  switch (aid) {
    case  AID_STRUCTURED_FIELD:
      offset += dissect_structured_fields(tn3270_tree, pinfo, tvb, offset, tn3270_info, TRUE);
      break;
    case  AID_PA1_KEY:
    case  AID_PA2_KEY_CNCL:
    case  AID_PA3_KEY:
    case  AID_CLEAR_KEY:
      /* Certain AID bytes need not be followed by anything */
      /* XXX: Is this the correct/complete set of AID bytes for this case ? */
      if (tvb_reported_length_remaining(tvb, offset) <= 0)
        break;
      /* fall into next */
    case  AID_READ_PARTITION_AID:
    case  AID_NO_AID_GENERATED:
    case  AID_NO_AID_GENERATED_PRINTER_ONLY:
    case  AID_TRIGGER_ACTION:
    case  AID_TEST_REQ_AND_SYS_REQ:
    case  AID_PF1_KEY:
    case  AID_PF2_KEY:
    case  AID_PF3_KEY:
    case  AID_PF4_KEY:
    case  AID_PF5_KEY:
    case  AID_PF6_KEY:
    case  AID_PF7_KEY:
    case  AID_PF8_KEY:
    case  AID_PF9_KEY:
    case  AID_PF10_KEY:
    case  AID_PF11_KEY:
    case  AID_PF12_KEY:
    case  AID_PF13_KEY:
    case  AID_PF14_KEY:
    case  AID_PF15_KEY:
    case  AID_PF16_KEY:
    case  AID_PF17_KEY:
    case  AID_PF18_KEY:
    case  AID_PF19_KEY:
    case  AID_PF20_KEY:
    case  AID_PF21_KEY:
    case  AID_PF22_KEY:
    case  AID_PF23_KEY:
    case  AID_PF24_KEY:
    case  AID_CLEAR_PARTITION_KEY:
    case  AID_ENTER_KEY:
    case  AID_SELECTOR_PEN_ATTENTION:
    case  AID_OPERATOR_ID_READER:
    case  AID_MAG_READER_NUMBER:
      offset += dissect_buffer_address(tn3270_tree, tvb, offset, hf_tn3270_cursor_address, tn3270_info);
      offset += dissect_orders_and_data(tn3270_tree, pinfo, tvb, offset, tn3270_info);
      break;
    default:
      expert_add_info(pinfo, item, &ei_tn3270_aid);
      offset += 1;
      break;
  }

  return (offset - start);
}


static int
dissect_tn3270(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree         *tn3270_tree;
  proto_item         *pi;
  gint                offset      = 0;
  conversation_t     *conversation;
  tn3270_conv_info_t *tn3270_info = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TN3270");

  pinfo->fd->flags.encoding = PACKET_CHAR_ENC_CHAR_EBCDIC;

  /* Do we have a conversation for this connection? */
  conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                   pinfo->ptype, pinfo->srcport,
                                   pinfo->destport, 0);
  if (conversation != NULL) {
    /* Do we already have a type and mechanism? */
    tn3270_info = (tn3270_conv_info_t *)conversation_get_proto_data(conversation, proto_tn3270);
  }

  if (tn3270_info == NULL)
    return 0;

  pi = proto_tree_add_item(tree, proto_tn3270, tvb, offset, -1, ENC_NA);
  tn3270_tree = proto_item_add_subtree(pi, ett_tn3270);
  col_clear(pinfo->cinfo, COL_INFO);

  if (tn3270_info->extended) {
    offset += dissect_tn3270e_header(tn3270_tree, tvb, offset);
  }

  if (tvb_reported_length_remaining(tvb, offset) <= 0)
    return offset;

  if (pinfo->srcport == tn3270_info->outbound_port) {
    col_set_str(pinfo->cinfo, COL_INFO, "TN3270 Data from Mainframe");
  }
  else {
    col_set_str(pinfo->cinfo, COL_INFO, "TN3270 Data to Mainframe");
  }

  if(tree) {
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
      if (pinfo->srcport == tn3270_info->outbound_port) {
        offset += dissect_outbound_stream(tn3270_tree, pinfo, tvb, offset, tn3270_info);
      }
      else {
        offset += dissect_inbound_stream(tn3270_tree, pinfo, tvb, offset, tn3270_info);
      }
    }
  }

  return tvb_captured_length(tvb);
}

void
add_tn3270_conversation(packet_info *pinfo, int tn3270e, gint model)
{
  conversation_t     *conversation;
  tn3270_conv_info_t *tn3270_info;

  conversation = find_or_create_conversation(pinfo);

  /*
   * Do we already have a type and mechanism?
   */
  tn3270_info = (tn3270_conv_info_t *)conversation_get_proto_data(conversation, proto_tn3270);
  if (tn3270_info == NULL) {
    /* No.  Attach that information to the conversation, and add
     * it to the list of information structures.
     */
    tn3270_info = wmem_new(wmem_file_scope(), tn3270_conv_info_t);

    copy_address(&(tn3270_info->outbound_addr), &(pinfo->dst));
    tn3270_info->outbound_port = pinfo->destport;

    copy_address(&(tn3270_info->inbound_addr), &(pinfo->src));
    tn3270_info->inbound_port  = pinfo->srcport;

    conversation_add_proto_data(conversation, proto_tn3270, tn3270_info);
  }

  /* The maximum rows/cols is tied to the 3270 model number */
  switch (model) {
    default:
    case 2:
      tn3270_info->altrows = 24;
      tn3270_info->altcols = 80;
      break;
    case 3:
      tn3270_info->altrows = 32;
      tn3270_info->altcols = 80;
      break;
    case 4:
      tn3270_info->altrows = 43;
      tn3270_info->altcols = 80;
      break;
    case 5:
      tn3270_info->altrows = 27;
      tn3270_info->altcols = 132;
      break;
  }
  tn3270_info->rows = 24;
  tn3270_info->cols = 80;

  tn3270_info->extended = tn3270e;

}

int
find_tn3270_conversation(packet_info *pinfo)
{
  conversation_t     *conversation = NULL;
  tn3270_conv_info_t *tn3270_info  = NULL;

  /*
   * Do we have a conversation for this connection?
   */
  conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                   pinfo->ptype, pinfo->srcport,
                                   pinfo->destport, 0);
  if (conversation != NULL) {
    tn3270_info = (tn3270_conv_info_t *)conversation_get_proto_data(conversation, proto_tn3270);
    if (tn3270_info != NULL) {
      /*
       * Do we already have a type and mechanism?
       */
      return 1;
    }
  }
  return 0;
}

void
proto_register_tn3270(void)
{
  static hf_register_info hf[] = {
    { &hf_tn3270_command_code,
      { "Command Code",
        "tn3270.command_code",
        FT_UINT8, BASE_HEX, VALS(vals_command_codes), 0x0,
        NULL, HFILL }
    },
    { &hf_tn3270_sf_length,
      { "Structured Field Length",
        "tn3270.sf_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    /* 3.4 Write Control Characters */
    { &hf_tn3270_wcc_nop,
      { "WCC NOP",
        "tn3270.wcc.nop",
        FT_BOOLEAN, 8, NULL, WCC_NOP,
        NULL, HFILL }
    },
    { &hf_tn3270_wcc_reset,
      { "WCC Reset",
        "tn3270.wcc.reset",
        FT_BOOLEAN, 8, NULL, WCC_RESET,
        NULL, HFILL }
    },
    { &hf_tn3270_wcc_printer1,
      { "WCC Printer1",
        "tn3270.wcc.printer1",
        FT_BOOLEAN, 8, NULL, WCC_PRINTER1,
        NULL, HFILL }
    },
    { &hf_tn3270_wcc_printer2,
      { "WCC Printer2",
        "tn3270.wcc.printer2",
        FT_BOOLEAN, 8, NULL, WCC_PRINTER2,
        NULL, HFILL }
    },
    { &hf_tn3270_wcc_start_printer,
      { "WCC Start Printer",
        "tn3270.wcc.start_printer",
        FT_BOOLEAN, 8, NULL, WCC_START_PRINTER,
        NULL, HFILL }
    },
    { &hf_tn3270_wcc_sound_alarm,
      { "WCC Sound Alarm",
        "tn3270.wcc.sound_alarm",
        FT_BOOLEAN, 8, NULL, WCC_SOUND_ALARM,
        NULL, HFILL }
    },
    { &hf_tn3270_wcc_keyboard_restore,
      { "WCC Keyboard Restore",
        "tn3270.wcc.keyboard_restore",
        FT_BOOLEAN, 8, NULL, WCC_KEYBOARD_RESTORE,
        NULL, HFILL }
    },
    { &hf_tn3270_wcc_reset_mdt,
      { "WCC Reset MDT",
        "tn3270.wcc.reset_mdt",
        FT_BOOLEAN, 8, NULL, WCC_RESET_MDT,
        NULL, HFILL }
    },

    /* 8.7 Copy Control Codes (CCC) */
    { &hf_tn3270_ccc,
      { "Copy Control Code",
        "tn3270.ccc",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_tn3270_ccc_coding,
      { "Coding",
        "tn3270.ccc_coding",
        FT_UINT8, BASE_HEX, NULL, CCC_GRAPHIC_CONVERT_MASK,
        NULL, HFILL }
    },
    { &hf_tn3270_ccc_printout,
      { "Printout Format",
        "tn3270.ccc_printout",
        FT_UINT8, BASE_HEX, VALS(ccc_vals_printout_format), CCC_PRINT_BITS_MASK,
        NULL, HFILL }
    },
    { &hf_tn3270_ccc_start_print,
      { "The start-print bit",
        "tn3270.ccc_start_print",
        FT_BOOLEAN, 8, NULL, CCC_START_PRINT,
        NULL, HFILL }
    },
    { &hf_tn3270_ccc_sound_alarm,
      { "The sound-alarm bit",
        "tn3270.ccc_sound_alarm",
        FT_BOOLEAN, 8, NULL, CCC_SOUND_ALARM,
        NULL, HFILL }
    },
    { &hf_tn3270_ccc_copytype,
      { "Type of Data to be Copied",
        "tn3270.ccc_copytype",
        FT_UINT8, BASE_HEX, VALS(ccc_vals_copytype), CCC_ATTRIBUTE_BITS_MASK,
        NULL, HFILL }
    },

    /* 4.4.1 Field Attributes */
    { &hf_tn3270_field_attribute,
      { "3270 Field Attribute",
        "tn3270.field_attribute",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_tn3270_fa_graphic_convert,
      { "Graphic Convert",
        "tn3270.fa.graphic_convert",
        FT_UINT8, BASE_HEX, NULL, FA_GRAPHIC_CONVERT_MASK,
        NULL, HFILL }
    },
    { &hf_tn3270_fa_protected,
      { "Protected",
        "tn3270.fa.protected",
        FT_BOOLEAN, 8, NULL, FA_PROTECTED,
        NULL, HFILL }
    },
    { &hf_tn3270_fa_numeric,
      { "Numeric",
        "tn3270.fa.numeric",
        FT_BOOLEAN, 8, NULL, FA_NUMERIC,
        NULL, HFILL }
    },
    { &hf_tn3270_fa_display,
      { "Display",
        "tn3270.fa.display",
        FT_UINT8, BASE_HEX, VALS(vals_fa_display), FA_DISPLAY_BITS_MASK,
        NULL, HFILL }
    },
    { &hf_tn3270_fa_reserved,
      { "Reserved",
        "tn3270.fa.reserved",
        FT_BOOLEAN, 8, NULL, FA_RESERVED,
        NULL, HFILL }
    },
    { &hf_tn3270_fa_modified,
      { "Modified",
        "tn3270.fa.modified",
        FT_BOOLEAN, 8, NULL, FA_MODIFIED,
        NULL, HFILL }
    },

    /* Order Code */
    { &hf_tn3270_order_code,
      { "Order Code",
        "tn3270.order_code",
        FT_UINT8, BASE_HEX, VALS(vals_order_codes), 0x0,
        NULL, HFILL }
    },
    { &hf_tn3270_character_code,
      { "Character Code",
        "tn3270.character_code",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_tn3270_stop_address,
      { "Stop Address",
        "tn3270.stop_address",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_tn3270_attribute_type,
      { "Attribute Type",
        "tn3270.attribute_type",
        FT_UINT8, BASE_HEX, VALS(vals_attribute_types), 0x0,
        NULL, HFILL }
    },
    { &hf_tn3270_extended_highlighting,
      { "Extended Highlighting",
        "tn3270.extended_highlighting",
        FT_UINT8, BASE_HEX, VALS(vals_at_extended_highlighting), 0x0,
        NULL, HFILL }
    },
    { &hf_tn3270_color,
      { "Color",
        "tn3270.color",
        FT_UINT8, BASE_HEX, VALS(vals_at_color_identifications), 0x0,
        NULL, HFILL }
    },
    { &hf_tn3270_character_set,
      { "Character Set",
        "tn3270.character_set",
        FT_UINT8, BASE_RANGE_STRING|BASE_HEX, RVALS(rvals_at_character_set), 0x0,
        NULL, HFILL }
    },
    { &hf_tn3270_field_outlining,
      { "Field Outlining",
        "tn3270.field_outlining",
        FT_UINT8, BASE_HEX, VALS(vals_at_field_outlining), 0x0,
        NULL, HFILL }
    },
    { &hf_tn3270_transparency,
      { "Transparency",
        "tn3270.transparency",
        FT_UINT8, BASE_HEX, VALS(vals_at_transparency), 0x0,
        NULL, HFILL }
    },

    { &hf_tn3270_field_validation_mandatory_fill,
      { "3270 Field validation_mandatory_fill",
        "tn3270.field_validation_mandatory_fill",
        FT_BOOLEAN, 8, TFS(&tn3270_field_validation_mandatory_fill), AT_FV_MANDATORY_FILL,
        NULL, HFILL }
    },
    { &hf_tn3270_field_validation_mandatory_entry,
      { "3270 Field validation_mandatory_entry",
        "tn3270.field_validation_mandatory_entry",
        FT_BOOLEAN, 8, TFS(&tn3270_field_validation_mandatory_entry), AT_FV_MANDATORY_ENTRY,
        NULL, HFILL }
    },
    { &hf_tn3270_field_validation_trigger,
      { "3270 Field validation_trigger",
        "tn3270.field_validation_trigger",
        FT_BOOLEAN, 8, TFS(&tn3270_field_validation_trigger), AT_FV_TRIGGER,
        NULL, HFILL }
    },

    { &hf_tn3270_all_character_attributes,
      { "all_character_attributes",
        "tn3270.all_character_attributes",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_tn3270_aid,
      { "Attention Identification",
        "tn3270.aid",
        FT_UINT8, BASE_HEX, VALS(vals_attention_identification_bytes), 0x0,
        NULL, HFILL }
    },

    { &hf_tn3270_buffer_address,
      { "Buffer Address",
        "tn3270.buffer_address",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    /* Self Defining Parameters */
    { &hf_tn3270_sdp_ln,
      {  "Length of this Self-Defining Parameter",
         "tn3270.sdp_ln",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sdp_id,
      {  "Self-Defining Parameter ID",
         "tn3270.sdp_id",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* Self Defining Parameters */

    /* 5.6 - Begin/End of File */
    { &hf_tn3270_begin_end_flags1,
      {  "Begin End Flags1",
         "tn3270.begin_end_flags1",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_begin_end_flags2,
      {  "Begin End Flags2",
         "tn3270.begin_end_flags2",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 5.6 - Begin/End of File */

    /* 5.7 - Create Partition */
    { &hf_tn3270_partition_id,
      {  "Partition ID",
         "tn3270.partition_id",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_uom,
      {  "The unit of measure and address mode",
         "tn3270.partition_uom",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_flags,
      {  "Flags",
         "tn3270.partition_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_height,
      {  "The height of the presentation space",
         "tn3270.partition_height",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_width,
      {  "The width of the presentation space",
         "tn3270.partition_width",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_rv,
      {  "The y, or row, origin of the viewport relative to the top edge of the usable area",
         "tn3270.partition_rv",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_cv,
      {  "The x, or column, origin of the viewport relative to the left side of the usable area",
         "tn3270.partition_cv",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_hv,
      {  "The height of the viewport",
         "tn3270.partition_hv",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_wv,
      {  "The width of the viewport",
         "tn3270.partition_wv",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_rw,
      {  "The y, or row, origin of the window relative to the top edge of the presentation space",
         "tn3270.partition_rw",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_cw,
      {  "The x, or column, origin of the window relative to the left edge of the presentation  space",
         "tn3270.partition_cw",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_rs,
      {  "The number of units to be scrolled in a vertical multiple scroll",
         "tn3270.partition_rs",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_res,
      {  "Reserved",
         "tn3270.partition_res",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_pw,
      {  "The number of points in the horizontal direction in a character cell in this presentation space",
         "tn3270.partition_pw",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_partition_ph,
      {  "The number of points in the vertical direction in a character cell in this presentation space",
         "tn3270.partition_ph",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },

    { &hf_tn3270_partition_command,
      {  "Partition Command",
         "tn3270.partition_command",
         FT_UINT8, BASE_HEX, VALS(vals_command_codes), 0x0,
         NULL, HFILL }
    },
    /* End - 5.7 - Create Partition */

    /* 5.9 - Erase/Reset */
    { &hf_tn3270_erase_flags,
      {  "Erase Flags",
         "tn3270.erase_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* End - 5.9 - Erase/Reset */

    /* 5.10 - Load Color Table */
    { &hf_tn3270_load_color_command,
      {  "Command",
         "tn3270.load_color_command",
         FT_BYTES, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },
    /* End - 5.10 - Load Color Table */

    /* 5.11 - Load Format Storage */
    { &hf_tn3270_load_format_storage_flags1,
      {  "Flags",
         "tn3270.load_format_storage_flags1",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_load_format_storage_flags2,
      {  "Flags (Reserved)",
         "tn3270.load_format_storage_flags2",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_load_format_storage_operand,
      {  "Operand:",
         "tn3270.load_format_storage_operand",
         FT_UINT8, BASE_HEX, VALS(vals_load_storage_format_operand), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_load_format_storage_localname,
      {  "Local name for user selectable formats",
         "tn3270.load_format_storage_localname",
         FT_STRING, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_format_group,
      {  "Format Group name",
         "tn3270.format_group_name",
         FT_STRING, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_format_name,
      {  "Format name",
         "tn3270.format_name",
         FT_STRING, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_load_format_storage_format_data,
      {  "Format data",
         "tn3270.load_format_storage_format_data",
         FT_STRING, BASE_NONE, NULL, 0x0,
         NULL, HFILL }},
    /* END - 5.11 - Load Format Storage */

    /* 5.12 - Load Line Type */
    { &hf_tn3270_load_line_type_command,
      {  "Line Type Command",
         "tn3270.load_line_type_command",
         FT_BYTES, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },

    /* 5.13 - Load Programmed Symbols */
    { &hf_tn3270_ps_flags,
      {  "Flags",
         "tn3270.ps_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ps_lcid,
      {  "Local character set ID",
         "tn3270.ps_lcid",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ps_char,
      {  "Beginning code point X'41' through X'FE'",
         "tn3270.ps_char",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ps_rws,
      {  "Loadable Character Set RWS Number",
         "tn3270.ps_rws",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_extended_ps_length,
      {  "Length of parameters for extended form, including the length parameter",
         "tn3270.extended_ps_length",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_extended_ps_flags,
      {  "Flags",
         "tn3270.extended_ps_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_extended_ps_lw,
      {  "Number of X-units in character cell (width of character matrixes)",
         "tn3270.extended_ps_lw",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_extended_ps_lh,
      {  "Number of Y-units in character cell (depth ofcharacter matrixes)",
         "tn3270.extended_ps_lh",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_extended_ps_subsn,
      {  "Subsection ID",
         "tn3270.extended_ps_subsn",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_extended_ps_color,
      {  "Color planes",
         "tn3270.extended_ps_color",
         FT_UINT8, BASE_HEX, VALS(vals_at_color_identifications), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_extended_ps_stsubs,
      {  "Starting Subsection Identifier",
         "tn3270.extended_ps_stsubs",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_extended_ps_echar,
      {  "Ending code point",
         "tn3270.extended_ps_echar",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_extended_ps_nw,
      {  "Number of width pairs",
         "tn3270.extended_ps_nw",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_extended_ps_nh,
      {  "Number of height pairs",
         "tn3270.extended_ps_nh",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_extended_ps_res,
      {  "Reserved",
         "tn3270.extended_ps_res",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 5.13 - Load Programmed Symbols */

    /* 5.15 - Outbound Text Header */
    /*        Note: some of these entries multiply used */
    { &hf_tn3270_outbound_text_header_operation_type,
      {  "Outbound Text Operation Type",
         "tn3270.outbound_text_operation_type",
         FT_UINT8, BASE_HEX, VALS(vals_command_codes), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_lvl,
      {  "Cursor level",
         "tn3270.lvl",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_cro,
      {  "Cursor row offset",
         "tn3270.cro",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_cc,
      {  "Cursor column offset",
         "tn3270.cc",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_outbound_text_header_lhdr,
      {  "Header length includes itself",
         "tn3270.outbound_text_header_lhdr",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_outbound_text_header_hdr,
      {  "Initial format controls",
         "tn3270.outbound_text_header_hdr",
         FT_BYTES, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 5.15 - Outbound Text Header */

    /* 5.16 - Outbound 3270DS */
    { &hf_tn3270_bsc,
      {  "SNA BSC",
         "tn3270.bsc",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 5.16 - Outbound 3270DS */

    /* 5.17 - Present Absolute Format */
    { &hf_tn3270_fpc,
      {  "Format Presentation Command",
         "tn3270.fpc",
         FT_UINT8, BASE_HEX, VALS(vals_command_codes), 0x0,
         NULL, HFILL }
    },
    /* END - 5.17 - Present Absolute Format */

    /* 5.18 - Present Relative Format */
    { &hf_tn3270_fov,
      {  "Format Offset Value",
         "tn3270.fov",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* End - 5.18 - Present Relative Format */

    /* 5.19 - Read Partition */
    { &hf_tn3270_read_partition_operation_type,
      {  "Read Partition Operation Type",
         "tn3270.read_partition_reqtyp",
         FT_UINT8, BASE_HEX, VALS(vals_read_partition_operation_type), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_read_partition_reqtyp,
      {  "Read Partition Request Type",
         "tn3270.read_partition_reqtyp",
         FT_UINT8, BASE_HEX, VALS(vals_read_partition_reqtype), READ_PARTITION_REQTYPE_MASK,
         NULL, HFILL }
    },
    /* End - 5.19 - Read Partition */

    /* 5.22 - Restart */
    { &hf_tn3270_start_page,
      {  "Number of pages to skip on restart",
         "tn3270.start_page",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_start_line,
      {  "Number of lines to skip on page for restart",
         "tn3270.start_line",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_scs_data,
      {  "SCS data (noncompressed and noncompacted) to set up for restart",
         "tn3270.scs_data",
         FT_BYTES, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },
    /* End - 5.22 - Restart */

    /* 5.24 - Select Color Table */
    { &hf_tn3270_color_command,
      {  "Color Command",
         "tn3270.color_command",
         FT_UINT16, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* 5.24 - Select Color Table */

    /* 5.26 - Set Checkpoint Interval */
    { &hf_tn3270_interval,
      {  "Checkpoint interval",
         "tn3270.interval",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         "Specifies the number of pages in the interval between terminal checkpoints", HFILL }
    },
    /* End - 5.26 - Set Checkpoint Interval */

    /* 5.27 - Set MSR Interval */
    { &hf_tn3270_msr_type,
      {  "MSR type",
         "tn3270.msr_type",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_msr_state_mask,
      {  "State Mask",
         "tn3270.msr_state_mask",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_msr_user,
      { "User Mode",
        "tn3270.msr.user",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }
    },
    { &hf_tn3270_msr_locked,
      { "Locked",
        "tn3270.msr.locked",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }
    },
    { &hf_tn3270_msr_auto,
      { "Auto Enter",
        "tn3270.msr.auto",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }
    },
    { &hf_tn3270_msr_ind1,
      { "Audible Ind 1 Suppress",
        "tn3270.msr.ind1",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }
    },
    { &hf_tn3270_msr_ind2,
      { "Audible Ind 2 Suppress",
        "tn3270.msr.ind2",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }
    },
    { &hf_tn3270_msr_state_value,
      {  "State Value", "tn3270.msr_state_value",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_msr_ind_mask,
      {  "Indicator Mask",
         "tn3270.msr_ind_mask",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_msr_ind_value,
      {  "Indicator Value",
         "tn3270.msr_ind_value",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* END -  5.27 - Set MSR Interval */

    /* 5.28 - Set Partition Characteristics */
    { &hf_tn3270_spc_sdp_ot,
      {  "Top edge outline thickness",
         "tn3270.spc_sdp_ot",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_spc_sdp_ob,
      {  "Bottom edge outline thickness",
         "tn3270.spc_sdp_ob",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_spc_sdp_ol,
      {  "Left edge outline thickness",
         "tn3270.spc_sdp_ol",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_spc_sdp_or,
      {  "Right edge outline thickness",
         "tn3270.spc_sdp_or",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_spc_sdp_eucflags,
      {  "Flags",
         "tn3270.spc_sdp_eucflags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 5.28 - Set Partition Characteristics */

    /* 5.29 - Set Printer Characteristics */
    { &hf_tn3270_printer_flags,
      {  "Flags",
         "tn3270.printer_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_spc_sdp_srepc,
      {  "Set/Reset Early Print Complete",
         "tn3270.spc_sdp_srepc",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 5.29 - Set Printer Characteristics */

    /* 5.30 - Set Reply Mode */
    /*  hf_tn3270_mode also used for 6.42: Query Reply (modes) */
    { &hf_tn3270_mode,
      {  "Mode",
         "tn3270.mode",
         FT_UINT8, BASE_HEX, VALS(vals_reply_modes), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_reply_mode_attr_list,
      {  "Type codes for the attribute types",
         "tn3270.reply_mode_attr_list",
         FT_UINT8, BASE_HEX, VALS(vals_attribute_types), 0x0,
         NULL, HFILL }
    },
    /* END - 5.30 - Set Reply Mode */

    /* 5.34 - Data Chain */
    { &hf_tn3270_data_chain_fields,
      {  "Data Chain Fields",
         "tn3270.data_chain_fields",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_data_chain_group,
      {  "Data Chain Group",
         "tn3270.data_chain_group",
         FT_UINT8, BASE_HEX, VALS(vals_data_chain_group), DATA_CHAIN_GROUP_MASK,
         NULL, HFILL }
    },
    { &hf_tn3270_data_chain_inbound_control,
      {  "Data Chain Inbound Control",
         "tn3270.data_chain_inbound_control",
         FT_UINT8, BASE_HEX, VALS(vals_data_chain_inbound_control), DATA_CHAIN_INBOUND_CONTROL_MASK,
         NULL, HFILL }
    },
    /* END - 5.34 - Data Chain */

    /* 5.35 - Destination/Origin */
    { &hf_tn3270_destination_or_origin_flags_input_control,
      {  "Input Control",
         "tn3270.destination_or_origin_flags_input_control",
         FT_UINT8, BASE_HEX, VALS(vals_destination_or_origin_flags_input_control), DESTINATION_OR_ORIGIN_FLAGS_INPUT_CONTROL_MASK,
         NULL, HFILL }
    },
    { &hf_tn3270_destination_or_origin_doid,
      {  "DOID",
         "tn3270.destination_or_origin_doid",
         FT_UINT16, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 5.35 - Destination/Origin */


    /* 5.36 - Object Control */
    { &hf_tn3270_object_control_flags,
      {  "Flags",
         "tn3270.object_control_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_object_type,
      {  "Object Type",
         "tn3270.object_type",
         FT_UINT8, BASE_HEX, VALS(vals_oc_type), 0x0,
         NULL, HFILL }
    },
    /* END - 5.36 - Object Control */

    /* 5.40 - Save/Restore Format */
    { &hf_tn3270_save_or_restore_format_flags,
      {  "Flags",
         "tn3270.save_or_restore_format_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_srf_fpcb,
      {  "Contents of the FPCB that is to be saved or restored",
         "tn3270.srf_fpcb",
         FT_BYTES, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },

    /* 5.40 - Save/Restore Format */
    { &hf_tn3270_type_1_text_outbound_data,
      {  "Type 1 text outbound data",
         "tn3270.type_1_text_outbound_data",
         FT_BYTES, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },

    /* 6.2 - Exception/Status */
    { &hf_tn3270_exception_or_status_flags,
      {  "Flags",
         "tn3270.exception_or_status_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sdp_excode,
      {  "Exception Code",
         "tn3270.sdp_excode",
         FT_UINT16, BASE_DEC, VALS(vals_sdp_excode), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sdp_statcode,
      {  "Status Code",
         "tn3270.sdp_statcode",
         FT_UINT16, BASE_DEC, VALS(vals_sdp_statcode), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sdp_ngl,
      {  "Number of groups currently assigned",
         "tn3270.sdp_ngl",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sdp_nml,
      {  "Number of formats currently loaded",
         "tn3270.sdp_nml",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sdp_nlml,
      {  "Number of local names used",
         "tn3270.sdp_nlml",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sdp_stor,
      {  "Amount of format storage space available (KB)",
         "tn3270.sdp_stor",
         FT_UINT32, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* 6.2 - Exception/Status */

    /* 6.3 - Inbound Text Header */
    { &hf_tn3270_hw,
      {  "Window height",
         "tn3270.hw",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_rw,
      {  "Row offset of window origin",
         "tn3270.rw",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ww,
      {  "Window width",
         "tn3270.ww",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_cw,
      {  "Column Offset of Window Origin",
         "tn3270.cw",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.3 - Inbound Text Header */

    /* 6.4 Inbound 3270DS */
    { &hf_tn3270_cursor_address,
      { "Cursor Address",
        "tn3270.cursor_address",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* END - 6.4 Inbound 3270DS */

    /* 6.5 - Recovery Data */
    { &hf_tn3270_recovery_data_flags,
      {  "Flags",
         "tn3270.recovery_data_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sld,
      {  "SLD -- Set line density parameter in effect at the checkpoint",
         "tn3270.sld",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_charset,
      {  "Character set parameter of Set Attribute control in effect at the checkpoint",
         "tn3270.charset",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_vertical,
      {  "Byte offset from Checkpoint Interval structured field to the Set Vertical Format control in effect for the checkpoint",
         "tn3270.vertical",
         FT_UINT32, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_v_offset,
      {  "Byte offset within the string control byte string or the SVF character",
         "tn3270.v_offset",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_v_sequence,
      {  "RU sequence number",
         "tn3270.v_sequence",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_v_length,
      {  "Length of the SVF character string required for restart",
         "tn3270.v_length",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_spd,
      {  "Set Primary Density parameter in effect at the checkpoint",
         "tn3270.spd",
         FT_UINT16, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_horizon,
      {  "Byte offset from Checkpoint Interval structured field to the Set Horizontal Format control in effect for the checkpoint",
         "tn3270.horizon",
         FT_UINT32, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_h_offset,
      {  "Byte offset from Checkpoint Interval structured field to the Set Horizontal Format control in effect for the checkpoint",
         "tn3270.h_offset",
         FT_UINT32, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_h_sequence,
      {  "RU sequence number",
         "tn3270.h_sequence",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_h_length,
      {  "Length of the SHF character string required for restart",
         "tn3270.h_length",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_hilite,
      {  "Highlighting",
         "tn3270.hilite",
         FT_UINT8, BASE_HEX, VALS(vals_at_extended_highlighting), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_pages,
      {  "Number of pages printed since the checkpoint",
         "tn3270.pages",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_lines,
      {  "Number of lines printed since the checkpoint",
         "tn3270.lines",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_checkpoint,
      {  "Byte offset from Set Checkpoint Interval structured field to the first"
         " character afterhe code point or character that caused an eject to the"
         " checkpointed page",
         "tn3270.checkpoint",
         FT_UINT32, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_c_offset,
      {  "Byte offset within the String Control Byte string or structured field of"
         " the checkpointed character",
         "tn3270.c_offset",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_c_sequence,
      {  "RU sequence number of the RU containing the checkpoint character",
         "tn3270.c_sequence",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_c_seqoff,
      {  "Byte offset within the RU of the checkpointed character",
         "tn3270.c_seqoff",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_c_scsoff,
      {  "Byte offset within the parameterized SCS control code (for example, TRN) of the checkpointed character.",
         "tn3270.c_scsoff",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_prime,
      {  "Prime compression character",
         "tn3270.prime",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.5 - Recovery Data */

    /* 6.9 - Query Reply (Alphanumeric Partitions) */
    { &hf_tn3270_ap_na,
      {  "Max number of alphanumeric partitions",
         "tn3270.ap_na",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ap_m,
      {  "Total available partition storage",
         "tn3270.ap_m",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_query_reply_alphanumeric_flags,
      {  "Flags",
         "tn3270.ap_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ap_vertical_scrolling,
      { "Vertical Scrolling Supported",
        "tn3270.ap_vertical_scrolling",
        FT_BOOLEAN, 8, NULL, QR_AP_VERTWIN,
        NULL, HFILL }
    },
    { &hf_tn3270_ap_horizontal_scrolling,
      { "Horizontal Scrolling Supported",
        "tn3270.ap_horizontal_scrolling",
        FT_BOOLEAN, 8, NULL, QR_AP_HORWIN,
        NULL, HFILL }
    },
    { &hf_tn3270_ap_apres1,
      { "Reserved",
        "tn3270.ap_apres1",
        FT_BOOLEAN, 8, NULL, QR_AP_APRES1,
        NULL, HFILL }
    },
    { &hf_tn3270_ap_apa,
      { "All Points addressability supported",
        "tn3270.ap_apa",
        FT_BOOLEAN, 8, NULL, QR_AP_APA_FLG,
        NULL, HFILL }
    },
    { &hf_tn3270_ap_pp,
      { "Partition protection supported",
        "tn3270.ap_pp",
        FT_BOOLEAN, 8, NULL, QR_AP_PROT,
        NULL, HFILL }
    },
    { &hf_tn3270_ap_lc,
      { "Presentation space local copy supported",
        "tn3270.ap_lc",
        FT_BOOLEAN, 8, NULL, QR_AP_LCOPY,
        NULL, HFILL }
    },
    { &hf_tn3270_ap_mp,
      { "Modify Partition supported",
        "tn3270.ap_mp",
        FT_BOOLEAN, 8, NULL, QR_AP_MODPART,
        NULL, HFILL }
    },
    { &hf_tn3270_ap_apres2,
      { "Reserved",
        "tn3270.ap_apres2",
        FT_BOOLEAN, 8, NULL, QR_AP_APRES2,
        NULL, HFILL }
    },

    { &hf_tn3270_ap_cm,
      {  "Character multiplier",
         "tn3270.ap_cm",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ap_ro,
      {  "Row overhead",
         "tn3270.ap_ro",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ap_co,
      {  "Column overhead",
         "tn3270.ap_co",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ap_fo,
      {  "Fixed overhead",
         "tn3270.ap_fo",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.9 - Query Reply (Alphanumeric Partitions) */

    /* 6.12 - Query Reply (Character Sets) */
    { &hf_tn3270_character_sets_flags1,
      {  "Flags (1)",
         "tn3270.character_sets_flags1",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_cs_ge,
      { "Graphic Escape supported",
        "tn3270.cs_ge",
        FT_BOOLEAN, 8, NULL, QR_CS_ALT,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_mi,
      { "Multiple LCIDs are supported",
        "tn3270.cs_mi",
        FT_BOOLEAN, 8, NULL, QR_CS_MULTID,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_lps,
      { "Load PSSF is supported",
        "tn3270.cs_lps",
        FT_BOOLEAN, 8, NULL, QR_CS_LOADABLE,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_lpse,
      { "Load PS EXTENDED is supported",
        "tn3270.cs_lpse",
        FT_BOOLEAN, 8, NULL, QR_CS_EXT,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_ms,
      { "More than one size of character slot is supported",
        "tn3270.cs_ms",
        FT_BOOLEAN, 8, NULL, QR_CS_MS,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_ch2,
      { "Two-byte coded character sets are supported",
        "tn3270.cs_ch2",
        FT_BOOLEAN, 8, NULL, QR_CS_CH2,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_gf,
      { "CGCSGID is present",
        "tn3270.cs_gf",
        FT_BOOLEAN, 8, NULL, QR_CS_GF,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_res,
      { "Reserved",
        "tn3270.cs_res",
        FT_BOOLEAN, 8, NULL, QR_CS_CSRES,
        NULL, HFILL }
    },

    { &hf_tn3270_character_sets_flags2,
      {  "Flags (2)",
         "tn3270.character_sets_flags2",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_cs_res2,
      { "Reserved",
        "tn3270.cs_res2",
        FT_BOOLEAN, 8, NULL, QR_CS_CSRES2,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_pscs,
      { "Load PS slot size match not required",
        "tn3270.cs_pscs",
        FT_BOOLEAN, 8, NULL, QR_CS_PSCS,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_res3,
      { "Reserved",
        "tn3270.cs_res3",
        FT_BOOLEAN, 8, NULL, QR_CS_CSRES3,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_cf,
      { "CCSID present",
        "tn3270.cs_cf",
        FT_BOOLEAN, 8, NULL, QR_CS_CF,
        NULL, HFILL }
    },

    { &hf_tn3270_sdw,
      {  "Default character slot width",
         "tn3270.cs_sdw",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sdh,
      {  "Default character slot height",
         "tn3270.cs_sdh",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_form,
      {  "Form Types",
         "tn3270.form",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_formres,
      {  "Form Types (Reserved)",
         "tn3270.formres",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_cs_form_type1,
      { "18-byte form",
        "tn3270.cs_form_type1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "the first 2 bytes contain a 16-bit vertical slice,"
        " the following 16 bytes contain 8-bit horizontal slices. For a 9"
        " x 12 character matrix the last 4 bytes contain binary zero.", HFILL }
    },
    { &hf_tn3270_cs_form_type2,
      { "18-byte form (COMPRESSED)",
        "tn3270.cs_form_type2",
        FT_BOOLEAN, 8, NULL, 0x40,
        "the first 2 bytes contain a 16-bit vertical slice,"
        " the following 16 bytes contain 8-bit horizontal slices. For a 9"
        " x 12 character matrix the last 4 bytes contain binary zero. (COMPRESSED)", HFILL }
    },
    { &hf_tn3270_cs_form_type3,
      { "Row loading (from top to bottom)",
        "tn3270.cs_form_type3",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_form_type4,
      { "Row loading (from top to bottom) (Compressed)",
        "tn3270.cs_form_type4",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_form_type5,
      { "Column loading (from left to right)",
        "tn3270.cs_form_type5",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_form_type6,
      { "Column loading (from left to right) (Compressed)",
        "tn3270.cs_form_type6",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_form_type8,
      { "Vector",
        "tn3270.cs_form_type8",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_dl,
      {  "Length of each descriptor",
         "tn3270.cs_dl",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },

    { &hf_tn3270_cs_descriptor_set,
      {  "Device Specific Character Set ID (PS store No.)",
         "tn3270.cs_descriptor_set",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_cs_descriptor_flags,
      {  "Flags",
         "tn3270.cs_descriptor_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_cs_ds_load,
      { "Loadable character set",
        "tn3270.cs_ds_load",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_ds_triple,
      { "Triple-plane character set",
        "tn3270.cs_ds_triple",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_ds_char,
      { "Double-Byte coded character set",
        "tn3270.cs_ds_char",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }
    },
    { &hf_tn3270_cs_ds_cb,
      { "No LCID compare",
        "tn3270.cs_ds_cb",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }
    },

    { &hf_tn3270_lcid,
      {  "Local character set ID (alias)",
         "tn3270.lcid",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sw,
      {  "Width of the character slots in this characterset.",
         "tn3270.sw",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sh,
      {  "Height of the character slots in this character set.",
         "tn3270.sh",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ssubsn,
      {  "Starting subsection.",
         "tn3270.ssubsn",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_esubsn,
      {  "Ending subsection.",
         "tn3270.esubsn",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ccsgid,
      {  "Coded Graphic Character Set Identifier.",
         "tn3270.ccsgid",
         FT_UINT64, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ccsid,
      {  "Coded Character Set Identifier.",
         "tn3270.ccsid",
         FT_UINT64, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.12 - Query Reply (Character Sets) */

    /* 6.13 - Query Reply (Color) */
    { &hf_tn3270_color_flags,
      {  "Flags",
         "tn3270.color_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_c_prtblk,
      { "Printer only - black ribbon is loaded",
        "tn3270.cc_prtblk",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }
    },
    { &hf_tn3270_c_np,
      {  "Length of color attribute list",
         "tn3270.np",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_c_cav,
      {  "Color attribute value accepted by the device",
         "tn3270.c_cav",
         FT_UINT8, BASE_HEX, VALS(vals_at_color_identifications), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_c_ci,
      {  "Color identifier",
         "tn3270.c_ci",
         FT_UINT8, BASE_HEX, VALS(vals_at_color_identifications), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_db_cavdef,
      {  "Default color attribute value",
         "tn3270.db_cavdef",
         FT_UINT8, BASE_HEX, VALS(vals_at_color_identifications), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_db_cidef,
      {  "Default background color identifier",
         "tn3270.db_cidef",
         FT_UINT8, BASE_HEX, VALS(vals_at_color_identifications), 0x0,
         NULL, HFILL }
    },
    /* END - 6.13 - Query Reply (Color) */

    /* 6.14 - Query Reply (Cooperative Processing Requestor) */
    { &hf_tn3270_limin,
      {  "Maximum CPR bytes/transmission allowed inbound",
         "tn3270.limin",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_limout,
      {  "Maximum CPR bytes/transmission allowed outbound",
         "tn3270.limout",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_featl,
      {  "Length (in bytes) of feature information that follows",
         "tn3270.featl",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_feats,
      {  "CPR length and feature flags",
         "tn3270.feats",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.14 - Query Reply (Cooperative Processing Requestor) */

    /* 6.15 - Query Reply (Data Chaining) */
    { &hf_tn3270_dc_dir,
      {  "Indicates which direction can use the Data Chain structured field.",
         "tn3270.dc_dir",
         FT_UINT8, BASE_HEX, VALS(vals_data_chaining_dir), 0xC0,
         NULL, HFILL }
    },
    /* END - 6.15 - Query Reply (Data Chaining) */

    /* 6.16 - Query Reply (Data Streams) */
    { &hf_tn3270_ds_default_sfid,
      {  "Default Data Stream",
         "tn3270.ds_default_sfid",
         FT_UINT8, BASE_HEX, VALS(vals_data_streams), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ds_sfid,
      {  "Supported Data Stream",
         "tn3270.ds_sfid",
         FT_UINT8, BASE_HEX, VALS(vals_data_streams), 0x0,
         NULL, HFILL }
    },
    /* END - 6.16 - Query Reply (Data Streams) */

    /* 6.17 - Query Reply (DBCS Asia) */
    { &hf_tn3270_asia_sdp_sosi_soset,
      {  "Set ID of the Shift Out (SO) character set",
         "tn3270.asia_sdp_sosi_soset",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_asia_sdp_ic_func,
      { "SO/SI Creation supported",
        "tn3270.asia_sdp_ic_func",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }
    },
    /* END - 6.17 - Query Reply (DBCS Asia) */

    /* 6.19 - Query Reply (Distributed Data Management) */
    { &hf_tn3270_ddm_flags,
      {  "Flags (Reserved)",
         "tn3270.ddm_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ddm_limin,
      {  "Maximum DDM bytes/transmission allowed inbound",
         "tn3270.ddm_limin",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ddm_limout,
      {  "Maximum DDM bytes/transmission allowed outbound",
         "tn3270.ddm_limout",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ddm_nss,
      {  "Number of subsets supported",
         "tn3270.ddm_nss",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ddm_ddmss,
      {  "DDM subset identifier",
         "tn3270.ddm_ddmss",
         FT_UINT8, BASE_HEX, VALS(vals_qr_ddm), 0x0,
         NULL, HFILL }
    },
    /* END - 6.19 - Query Reply (Distributed Data Management) */

    /* 6.20 - Query Reply (Document Interchange Architecture) */
    { &hf_tn3270_dia_flags,
      {  "Flags (Reserved)",
         "tn3270.dia_flags",
         FT_UINT16, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_dia_limin,
      {  "Maximum DIA bytes/transmission allowed inbound",
         "tn3270.dia_limin",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_dia_limout,
      {  "Maximum DIA bytes/transmission allowed outbound",
         "tn3270.dia_limout",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_dia_nfs,
      {  "Number of subsets supported",
         "tn3270.dia_nfs",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_dia_diafs,
      {  "DIA function set identifier",
         "tn3270.dia_diafs",
         FT_UINT8, BASE_HEX, VALS(vals_qr_dia), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_dia_diafn,
      {  "DIA function set number",
         "tn3270.dia_diafn",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.20 - Query Reply (Document Interchange Architecture) */

    /* 6.22 - Query Reply (Field Outlining) */
    { &hf_tn3270_fo_flags,
      {  "Flags",
         "tn3270.fo_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_fo_vpos,
      {  "Location of vertical line",
         "tn3270.fo_vpos",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_fo_hpos,
      {  "Location of overline/underline",
         "tn3270.fo_hpos",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_fo_hpos0,
      {  "Location of overline in case of separation",
         "tn3270.fo_hpos0",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_fo_hpos1,
      {  "Location of underline in case of separation",
         "tn3270.fo_hpos1",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.22 - Query Reply (Field Outlining) */

    /* 6.25 - Query Reply (Format Storage Auxiliary Device) */
    { &hf_tn3270_fsad_flags,
      {  "Flags",
         "tn3270.fsad_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_fsad_limin,
      {  "Reserved for LIMIN parameter. Must be set to zeros.",
         "tn3270.fsad_limin",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_fsad_limout,
      {  "Maximum bytes of format storage data per transmission allowed outbound.",
         "tn3270.fsad_limout",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_fsad_size,
      {  "Size of the format storage space",
         "tn3270.fsad_size",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.25 - Query Reply (Format Storage Auxiliary Device) */

    /* 6.28 - Query Reply (Highlighting) */
    { &hf_tn3270_h_np,
      {  "Number of attribute-value/action pairs",
         "tn3270.h_np",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_h_vi,
      {  "Data stream attribute value accepted",
         "tn3270.h_vi",
         FT_UINT8, BASE_HEX, VALS(vals_at_extended_highlighting), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_h_ai,
      {  "Data stream action",
         "tn3270.h_ai",
         FT_UINT8, BASE_HEX, VALS(vals_at_extended_highlighting), 0x0,
         NULL, HFILL }
    },
    /* END - Query Reply (Highlighting) */

    /* 6.29 - Query Reply (IBM Auxiliary Device) */
    { &hf_tn3270_ibm_flags,
      {  "Flags",
         "tn3270.ibm_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ibm_limin,
      {  "Inbound message size limit",
         "tn3270.ibm_limin",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ibm_limout,
      {  "Outbound message size limit",
         "tn3270.ibm_limout",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ibm_type,
      {  "Type of IBM Auxiliary Device",
         "tn3270.ibm_type",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.29 - Query Reply (IBM Auxiliary Device) */

    /* 6.31 - Query Reply (Implicit Partitions) */
    { &hf_tn3270_ip_flags,
      {  "Flags (Reserved)",
         "tn3270.ip_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ipdd_wd,
      {  "Width of the Implicit Partition default screen size (in character cells)",
         "tn3270.ipdd_wd",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ipdd_hd,
      {  "Height of the Implicit Partition default screen size",
         "tn3270.ipdd_hd",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ipdd_wa,
      {  "Width of the Implicit Partition alternate screen size",
         "tn3270.ipdd_wa",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ipdd_ha,
      {  "Height of the Implicit Partition alternate screen size",
         "tn3270.ipdd_ha",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ippd_dpbs,
      {  "Default printer buffer size (in character cells)",
         "tn3270.ippd_dpbs",
         FT_UINT64, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ippd_apbs,
      {  "Default printer buffer size (in character cells)",
         "tn3270.ippd_apbs",
         FT_UINT64, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ipccd_wcd,
      {  "Width of the character cell for the Implicit Partition default screen size",
         "tn3270.ipccd_wcd",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ipccd_hcd,
      {  "Height of the character cell for the Implicit Partition default screen size",
         "tn3270.ipccd_hcd",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ipccd_wca,
      {  "Width of the character cell for the Implicit Partition alternate screen size",
         "tn3270.ipccd_wca",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ipccd_hca,
      {  "Height of the character cell for the Implicit Partition alternate screen size",
         "tn3270.ipccd_hca",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - Query Reply (Implicit Partitions) */

    /* 6.32 - Query Reply (IOCA Auxiliary Device) */
    { &hf_tn3270_ioca_limin,
      {  "Max IOCA bytes/inbound transmission",
         "tn3270.ioca_limin",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ioca_limout,
      {  "Max IOCA bytes/outbound transmission",
         "tn3270.ioca_limout",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ioca_type,
      {  "Type of IOCA Auxiliary Device",
         "tn3270.ioca_type",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.32 - Query Reply (IOCA Auxiliary Device) */

    /* 6.34 - Query Reply (MSR Control) */
    { &hf_tn3270_msr_nd,
      {  "Number of MSR device types",
         "tn3270.msr_nd",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.34 - Query Reply (MSR Control) */

    /* 6.36 - Query Reply (OEM Auxiliary Device) */
    { &hf_tn3270_oem_dsref,
      {  "Data stream reference identifier",
         "tn3270.oem_dsref",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_oem_dtype,
      {  "Device type",
         "tn3270.oem_dtype",
         FT_STRING, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_oem_uname,
      {  "User assigned name",
         "tn3270.oem_uname",
         FT_STRING, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sdp_daid,
      {  "Destination/Origin ID",
         "tn3270.oem_sdp_daid_doid",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_oem_sdp_ll_limin,
      {  "Maximum OEM dsf bytes/transmission allowed inbound",
         "tn3270.oem_sdp_ll_limin",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_oem_sdp_ll_limout,
      {  "Maximum OEM dsf bytes/transmission allowed outbound",
         "tn3270.oem_sdp_ll_limout",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_oem_sdp_pclk_vers,
      {  "Protocol version",
         "tn3270.oem_sdp_pclk_vers",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.36 - Query Reply (OEM Auxiliary Device) */

    /* 6.37 - Query Reply (Paper Feed Techniques) */
    { &hf_tn3270_pft_flags,
      {  "Flags",
         "tn3270.pft_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_pft_tmo,
      {  "Top margin offset in 1/1440ths of an inch",
         "tn3270.pft_tmo",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_pft_bmo,
      {  "Bottom margin offset in 1/1440ths of an inch",
         "tn3270.pft_bmo",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.37 - Query Reply (Paper Feed Techniques) */

    /* 6.38 - Query Reply (Partition Characteristics) */
    { &hf_tn3270_pc_vo_thickness,
      {  "Thickness",
         "tn3270.pc_vo_thickness",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END- 6.38 - Query Reply (Partition Characteristics) */

    /* 6.41 - Query Reply (Product Defined Data Stream) */
    { &hf_tn3270_pdds_refid,
      {  "Reference identifier",
         "tn3270.pdds_refid",
         FT_UINT8, BASE_HEX, VALS(vals_qr_pdds_refid), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_pdds_ssid,
      {  "Subset identifier",
         "tn3270.pdds_ssid",
         FT_UINT8, BASE_HEX, VALS(vals_qr_pdds_ssid), 0x0,
         NULL, HFILL }
    },
    /* END - 6.41 - Query Reply (Product Defined Data Stream) */

    /* 6.43 - Query Reply (RPQ Names) */
    { &hf_tn3270_rpq_device,
      {  "Device type identifier",
         "tn3270.rpq_device",
         FT_STRING, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_rpq_mid,
      {  "Model type identifier",
         "tn3270.rpq_mid",
         FT_UINT64, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_rpq_rpql,
      {  "Length of RPQ name (including this byte)",
         "tn3270.rpq_rpql",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_rpq_name,
      {  "RPQ name",
         "tn3270.rpq_name",
         FT_STRING, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - Query Reply (Names) */

    /* 6.44 - Query Reply (Save or Restore Format) */
    { &hf_tn3270_srf_fpcbl,
      {  "Format parameter control block length",
         "tn3270.srf_fpcbl",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.44 - Query Reply (Save or Restore Format) */

    /* 6.45 - Query Reply (Settable Printer Characteristics) */
    { &hf_tn3270_spc_epc_flags,
      {  "Flags",
         "tn3270.spc_epc_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.45 - Query Reply (Settable Printer Characteristics) */

    /* 6.47 - Query Reply (Storage Pools) */
    { &hf_tn3270_sp_spid,
      {  "Storage pool identity",
         "tn3270.sp_spid",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sp_size,
      {  "Size of this storage pool when empty",
         "tn3270.sp_size",
         FT_UINT32, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sp_space,
      {  "Space available in this storage pool",
         "tn3270.sp_space",
         FT_UINT32, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sp_objlist,
      {  "Identifiers of objects housed in this storage pool",
         "tn3270.sp_objlist",
         FT_UINT16, BASE_HEX, VALS(vals_sp_objlist), 0x0,
         NULL, HFILL }
    },
    /* END - 6.47 - Query Reply (Storage Pools) */

    /* 6.49 - Query Reply (Text Partitions) */
    { &hf_tn3270_tp_nt,
      {  "Maximum number of text partitions",
         "tn3270.tp_nt",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_tp_m,
      {  "Maximum partition size",
         "tn3270.tp_m",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_tp_flags,
      {  "Flags",
         "tn3270.tp_flags",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_tp_ntt,
      {  "Number of text types supported",
         "tn3270.tp_ntt",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_tp_tlist,
      {  "List of types supported",
         "tn3270.tp_tlist",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.49 - Query Reply (Text Partitions) */

    /* 6.50 - Query Reply (Transparency) */
    { &hf_tn3270_t_np,
      {  "Number of pairs",
         "tn3270.t_np",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_t_vi,
      {  "Data stream attribute value accepted",
         "tn3270.t_vi",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_t_ai,
      {  "Associated action value",
         "tn3270.t_ai",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.50 - Query Reply (Transparency) */

    /* 6.51 Query Reply Usable Area */
    { &hf_tn3270_usable_area_flags1,
      {"Usable Area Flags",
       "tn3270.query_reply_usable_area_flags1",
       FT_UINT8, BASE_HEX, NULL, 0,
       NULL, HFILL}
    },
    { &hf_tn3270_ua_reserved1,
      { "Reserved",
        "tn3270.reserved",
        FT_BOOLEAN, 8, NULL, QR_UA_RESERVED1,
        NULL, HFILL }
    },
    { &hf_tn3270_ua_page_printer,
      { "Page Printer",
        "tn3270.ua_page_printer",
        FT_BOOLEAN, 8, NULL, QR_UA_PAGE_PRINTER,
        NULL, HFILL }
    },
    { &hf_tn3270_ua_reserved2,
      { "Reserved",
        "tn3270.reserved",
        FT_BOOLEAN, 8, NULL, QR_UA_RESERVED2,
        NULL, HFILL }
    },
    { &hf_tn3270_ua_hard_copy,
      { "Hard Copy",
        "tn3270.ua_hard_copy",
        FT_BOOLEAN, 8, NULL, QR_UA_HARD_COPY,
        NULL, HFILL }
    },
    { &hf_tn3270_ua_addressing,
      { "Usable Area Addressing",
        "tn3270.ua_addressing",
        FT_UINT8, BASE_HEX, VALS(vals_usable_area_addr_mode), QR_UA_ADDR_MODE_MASK,
        NULL, HFILL}
    },
    { &hf_tn3270_usable_area_flags2,
      { "Usable Area Flags",
        "tn3270.query_reply_usable_area_flags2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_tn3270_ua_variable_cells,
      { "Variable Cells",
        "tn3270.ua_variable_cells",
        FT_BOOLEAN, 8, TFS(&tn3270_tfs_ua_variable_cells), QR_UA_VARIABLE_CELLS,
        NULL, HFILL }
    },
    { &hf_tn3270_ua_characters,
      { "Characters",
        "tn3270.ua_characters",
        FT_BOOLEAN, 8, TFS(&tn3270_tfs_ua_characters), QR_UA_CHARACTERS,
        NULL, HFILL }
    },
    { &hf_tn3270_ua_cell_units,
      { "Cell Units",
        "tn3270.ua_cell_units",
        FT_BOOLEAN, 8, TFS(&tn3270_tfs_ua_cell_units), QR_UA_CELL_UNITS,
        NULL, HFILL }
    },
    { &hf_tn3270_ua_width_cells_pels,
      {  "Width of usable area in cells/pels",
         "tn3270.ua_width_cells_pels",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ua_height_cells_pels,
      {  "Height of usable area in cells/pels",
         "tn3270.ua_height_cells_pels",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ua_uom_cells_pels,
      {  "Units of measure for cells/pels",
         "tn3270.ua_uom_cells_pels",
         FT_UINT8, BASE_HEX, VALS(vals_usable_area_uom), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ua_xr,
      {  "Distance between points in X direction as a fraction",
         "tn3270.ua_xr",
         FT_UINT32, BASE_HEX, NULL, 0x0,
         "measured in UNITS, with 2-byte numerator and 2-byte denominator", HFILL }
    },
    { &hf_tn3270_ua_yr,
      {  "Distance between points in Y direction as a fraction",
         "tn3270.ua_xr",
         FT_UINT32, BASE_HEX, NULL, 0x0,
         "measured in UNITS, with 2-byte numerator and 2-byte denominator", HFILL }
    },
    { &hf_tn3270_ua_aw,
      {  "Number of X units in default cell",
         "tn3270.ua_aw",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ua_ah,
      {  "Number of Y units in default cell",
         "tn3270.ua_ah",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ua_buffsz,
      {  "Character buffer size (bytes)",
         "tn3270.ua_buffsz",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ua_xmin,
      {  "Minimum number of X units in variable cell",
         "tn3270.ua_xmin",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ua_ymin,
      {  "Minimum number of Y units in variable cell",
         "tn3270.ua_ymin",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ua_xmax,
      {  "Maximum number of X units in variable cell",
         "tn3270.ua_xmax",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_ua_ymax,
      {  "Maximum number of Y units in variable cell",
         "tn3270.ua_ymax",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* End - 6.51 Query Reply Usable Area */

    /* 6.52 - Query Reply (3270 IPDS) */
    { &hf_tn3270_3270_tranlim,
      {  "Maximum transmission size allowed outbound",
         "tn3270.3270_tranlim",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    /* END - 6.52 - Query Reply (3270 IPDS) */

    /* Miscellaneous */
    { &hf_tn3270_field_data,
      {  "Field Data",
         "tn3270.field_data",
         FT_STRING, BASE_NONE, NULL, 0x0,
         "tn3270.field_data", HFILL }
    },
    { &hf_tn3270_number_of_attributes,
      {  "Number of Attributes",
         "tn3270.number_of_attributes",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_resbyte,
      {  "Flags (Reserved)",
         "tn3270.resbyte",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_resbytes,
      {  "Flags (Reserved)",
         "tn3270.resbytes",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_res_twobytes,
      {  "Flags (Reserved)",
         "tn3270.res_twobytes",
         FT_UINT16, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sf_single_byte_id,
      {  "Structured Field",
         "tn3270.sf_id",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sf_double_byte_id,
      {  "Structured Field",
         "tn3270.sf_id",
         FT_UINT16, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_sf_query_reply,
      {  "Query Reply",
         "tn3270.sf_query_reply",
         FT_UINT8, BASE_HEX, VALS(vals_sf_query_replies), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_null,
      {  "Trailing Null (Possible Mainframe/Emulator Bug)",
         "tn3270.null",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_unknown_data,
      {  "Unknown Data (Possible Mainframe/Emulator Bug)",
         "tn3270.unknown_data",
         FT_BYTES, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    },

    /* TN3270E - Header Fields */
    { &hf_tn3270_tn3270e_data_type,
      {  "TN3270E Data Type",
         "tn3270.tn3270e_data_type",
         FT_UINT8, BASE_HEX, VALS(vals_tn3270_header_data_types), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_tn3270e_request_flag,
      {  "TN3270E Request Flag",
         "tn3270.tn3270e_request_flag",
         FT_UINT8, BASE_HEX, VALS(vals_tn3270_header_request_flags), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_tn3270e_response_flag_3270_SCS,
      {  "TN3270E Response Flag",
         "tn3270.tn3270e_response_flag",
         FT_UINT8, BASE_HEX, VALS(vals_tn3270_header_response_flags_3270_SCS), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_tn3270e_response_flag_response,
      {  "TN3270E Response Flag",
         "tn3270.tn3270e_response_flag",
         FT_UINT8, BASE_HEX, VALS(vals_tn3270_header_response_flags_response), 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_tn3270e_response_flag_unused,
      {  "TN3270E Response Flag",
         "tn3270.tn3270e_response_flag",
         FT_UINT8, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_tn3270e_seq_number,
      {  "TN3270E Seq Number",
         "tn3270.tn3270e_seq_number",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_tn3270_tn3270e_header_data,
      {  "TN3270E Header Data",
         "tn3270.tn3270e_header_data",
         FT_STRING, BASE_NONE, NULL, 0x0,
         NULL, HFILL }
    }
  };

  static gint *ett[] = {
    &ett_tn3270,
    &ett_tn3270e_hdr,
    &ett_sf,
    &ett_tn3270_field_attribute,
    &ett_tn3270_field_validation,
    &ett_tn3270_usable_area_flags1,
    &ett_tn3270_usable_area_flags2,
    &ett_tn3270_query_reply_alphanumeric_flags,
    &ett_tn3270_character_sets_flags1,
    &ett_tn3270_character_sets_flags2,
    &ett_tn3270_character_sets_form,
    &ett_tn3270_cs_descriptor_flags,
    &ett_tn3270_color_flags,
    &ett_tn3270_wcc,
    &ett_tn3270_ccc,
    &ett_tn3270_msr_state_mask,
    &ett_tn3270_data_chain_fields,
    &ett_tn3270_query_list
  };

  static ei_register_info ei[] = {
    { &ei_tn3270_order_code, { "tn3270.order_code.bogus", PI_PROTOCOL, PI_WARN, "Bogus value", EXPFILL }},
    { &ei_tn3270_command_code, { "tn3270.command_code.bogus", PI_PROTOCOL, PI_WARN, "Bogus value", EXPFILL }},
    { &ei_tn3270_aid, { "tn3270.aid.bogus", PI_PROTOCOL, PI_WARN, "Bogus value", EXPFILL }},
  };

  expert_module_t* expert_tn3270;

  proto_tn3270 = proto_register_protocol("TN3270 Protocol", "TN3270", "tn3270");
  register_dissector("tn3270", dissect_tn3270, proto_tn3270);
  proto_register_field_array(proto_tn3270, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_tn3270 = expert_register_protocol(proto_tn3270);
  expert_register_field_array(expert_tn3270, ei, array_length(ei));

}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
