/* packet-tn5250.c
 * Routines for tn5250.packet dissection
 *
 * Reference:
 *  5494 Remote Control Unit - Functions Reference
 *  Release 3.0 Document Number SC30-3533-04
 *  Chapters 12, 15, 16
 *  http://publibfp.dhe.ibm.com/cgi-bin/bookmgr/BOOKS/co2e2001/CCONTENTS
 *
 * Copyright 2009, Robert Hogan <robert@roberthogan.net>
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
#include <epan/address.h>
#include <epan/conversation.h>
#include "packet-tn5250.h"

typedef struct tn5250_conv_info_t {
  struct tn5250_conv_info_t *next;
  address outbound_addr;
  guint32 outbound_port;
  address inbound_addr;
  guint32 inbound_port;
  gint extended;
} tn5250_conv_info_t;

/* 13.4 SNA LU 4 and LU 7 Negative Responses */

#define NEGATIVE_RESPONSE1 0x081102
#define NEGATIVE_RESPONSE2 0x100301
#define NEGATIVE_RESPONSE3 0x100501
#define NEGATIVE_RESPONSE4 0x100502

static const value_string vals_tn5250_negative_responses[] = {
  { 0x08110200,  "The Cancel key of a printer was pressed when it was not in an error state"},
  { 0x08110201,  "The Cancel key of a printer was pressed when it was in an error state"},
  { 0x10030101,  "Command that is not valid encountered in data stream"},
  { 0x10030105,  "Clear unit alternate command not valid"},
  { 0x10030123,  "Command to enter text mode not valid for the keyboard or country language code used"},
  { 0x10050103,  "Format table resequencing error on display data stream"},
  { 0x10050110,  "Structured field length is not valid"},
  { 0x10050111,  "Structured field class or type is not valid"},
  { 0x10050112,  "Parameter is not valid in structured field"},
  { 0x10050113,  "Structured field minor structure length is not valid"},
  { 0x10050114,  "Parameter is not valid in structured field minor structure"},
  { 0x1005011B,  "Data stream command is not valid in WP mode"},
  { 0x1005011C,  "Data stream command is not valid in data processing (DP) mode"},
  { 0x1005011D,  "Command not allowed on display with unlocked keyboard"},
  { 0x10050121,  "Premature data stream termination"},
  { 0x10050122,  "Write to display order row/col address is not valid"},
  { 0x10050123,  "The address in the Repeat to Address is less than the current workstation screen address"},
  { 0x10050125,  "Start-of-field order length not valid"},
  { 0x10050126,  "Start-of-field order address not valid"},
  { 0x10050127,  "Data in restore not valid"},
  { 0x10050128,  "Field extends past the end of the display"},
  { 0x10050129,  "Format table overflow"},
  { 0x1005012A,  "An attempt was made to write past the end of display"},
  { 0x1005012B,  "Start-of-header length not valid"},
  { 0x1005012C,  "Parameter that is not valid is on the ROLL command"},
  { 0x1005012D,  "Extended attribute type not valid"},
  { 0x1005012E,  "RAM load parameter not valid"},
  { 0x1005012F,  "Extended attribute not valid"},
  { 0x10050130,  "Start-of-field attribute not valid"},
  { 0x10050131,  "No escape code was found where it was expected"},
  { 0x10050132,  "WRITE ERROR CODE TO WINDOW command row/col address is not valid"},
  { 0x10050133,  "WRITE ERROR CODE TO WINDOW command is not valid with the message error line that is in use"},
  { 0x10050134,  "SAVE PARTIAL SCREEN command was followed by an immediate read or another SAVE type command"},
  { 0x10050135,  "Continued entry field segment is not valid"},
  { 0x10050136,  "Word wrap not allowed for this type of entry field"},
  { 0x10050138,  "An attempt was made to write a scroll bar beyond the last display column"},
  { 0x10050139,  "The total row/col, slider position (sliderpos), or display row/col on a scroll bar is not valid"},
  { 0x1005013A,  "At least one selection field choice must be allowed to accept the cursor"},
  { 0x1005013B,  "An attempt was made to write a selection field choice before column 1 or beyond the last display column"},
  { 0x1005013C,  "An attempt was made to define too  many selection field choices"},
  { 0x1005013D,  "An attempt was made to define more than one default selected choice in a single choice selection field"},
  { 0x1005013E,  "Too many windows defined. 128 windows are allowed."},
  { 0x10050140,  "Write Data command to non-entry field"},
  { 0x10050141,  "Too much data or too little data in a Write Data command"},
  { 0x10050142,  "An attempt was made to write a X'FF' character to the display screen."},
  { 0x10050148,  "The Fax and Image feature is not supported on this device."},
  { 0x10050149,  "Data follows an image/fax download command in the data stream and the image/fax download command does"
                 " not contain the last  of the image data. No other commands are accepted until all the image/fax data has been received."},
  { 0x1005014C,  "The display is not capable of video delivery."},
  { 0x1005014D,  "The first 2 bytes of the PC/TV command were not X'E201' or X'E301'."},
  { 0x1005014F,  "Data stream longer than 16,368 bytes."},
  { 0x10050180,  "The printer LSID sent in the copy-to-printer data stream from the AS/400 system was not in the SNA session table"},
  { 0x10050181,  "The LSID sent in the copy-to-printer data stream from the AS/400 system was not a printer LSID"},
  { 0x10050187,  "Self-check field length (self-check field > 33 bytes) not valid"},
  { 0x10050188,  "Self-check field control word not valid"},
  { 0x10050228,  "SCS command not valid"},
  { 0x10050229,  "SCS parameter not valid"},
  { 0x1005022A,  "Intelligent Printer Data Stream (IPDS parameter error)"},
  { 0x10050260,  "IPDS printer's multistatus functions are available"},
  { 0x00000000, NULL }
};

#define TN5250_ESCAPE  0x04
static const value_string vals_tn5250_escape_codes[] = {
  { 0x04                                                  ,  "ESC"},
  { 0x00, NULL }
};

/* 15.1 Workstation Data Stream Commands*/
#define CLEAR_UNIT                                                              0x40
#define CLEAR_UNIT_ALTERNATE                                                    0x20
#define CLEAR_FORMAT_TABLE                                                      0x50
#define WRITE_TO_DISPLAY                                                        0x11
#define WRITE_ERROR_CODE                                                        0x21
#define WRITE_ERROR_CODE_TO_WINDOW                                              0x22
#define READ_INPUT_FIELDS                                                       0x42
#define READ_MDT_FIELDS                                                         0x52
#define READ_MDT_ALTERNATE                                                      0x82
#define READ_SCREEN                                                             0x62
#define READ_SCREEN_WITH_EXTENDED_ATTRIBUTES                                    0x64
#define READ_SCREEN_TO_PRINT                                                    0x66
#define READ_SCREEN_TO_PRINT_WITH_EXTENDED_ATTRIBUTES                           0x68
#define READ_SCREEN_TO_PRINT_WITH_GRIDLINES                                     0x6A
#define READ_SCREEN_TO_PRINT_WITH_EXTENDED_ATTRIBUTES_AND_GRIDLINES             0x6C
#define READ_IMMEDIATE                                                          0x72
#define READ_MODIFIED_IMMEDIATE_ALTERNATE                                       0x83
#define SAVE_SCREEN                                                             0x02
#define SAVE_PARTIAL_SCREEN                                                     0x03
#define RESTORE_SCREEN                                                          0x12
#define RESTORE_PARTIAL_SCREEN                                                  0x13
#define ROLL                                                                    0x23
#define WRITE_STRUCTURED_FIELD                                                  0xF3
#define WRITE_SINGLE_STRUCTURED_FIELD                                           0xF4
#define COPY_TO_PRINTER                                                         0x16

static const value_string vals_tn5250_command_codes[] = {
  { CLEAR_UNIT                                                  ,  "Clear Unit"},
  { CLEAR_UNIT_ALTERNATE                                        ,  "Clear Unit Alternate"},
  { CLEAR_FORMAT_TABLE                                          ,  "Clear Format Table"},
  { WRITE_TO_DISPLAY                                            ,  "Write To Display"},
  { WRITE_ERROR_CODE                                            ,  "Write Error Code"},
  { WRITE_ERROR_CODE_TO_WINDOW                                  ,  "Write Error Code To Window"},
  { READ_INPUT_FIELDS                                           ,  "Read Input Fields"},
  { READ_MDT_FIELDS                                             ,  "Read Mdt Fields"},
  { READ_MDT_ALTERNATE                                          ,  "Read Mdt Alternate"},
  { READ_SCREEN                                                 ,  "Read Screen"},
  { READ_SCREEN_WITH_EXTENDED_ATTRIBUTES                        ,  "Read Screen With Extended Attributes"},
  { READ_SCREEN_TO_PRINT                                        ,  "Read Screen To Print"},
  { READ_SCREEN_TO_PRINT_WITH_EXTENDED_ATTRIBUTES               ,  "Read Screen To Print With Extended Attributes"},
  { READ_SCREEN_TO_PRINT_WITH_GRIDLINES                         ,  "Read Screen To Print With Gridlines"},
  { READ_SCREEN_TO_PRINT_WITH_EXTENDED_ATTRIBUTES_AND_GRIDLINES ,  "Read Screen To Print With Extended Attributes And Gridlines"},
  { READ_IMMEDIATE                                              ,  "Read Immediate"},
  { READ_MODIFIED_IMMEDIATE_ALTERNATE                           ,  "Read Modified Immediate Alternate"},
  { SAVE_SCREEN                                                 ,  "Save Screen"},
  { SAVE_PARTIAL_SCREEN                                         ,  "Save Partial Screen"},
  { RESTORE_SCREEN                                              ,  "Restore Screen"},
  { RESTORE_PARTIAL_SCREEN                                      ,  "Restore Partial Screen"},
  { ROLL                                                        ,  "Roll"},
  { WRITE_STRUCTURED_FIELD                                      ,  "Write Structured Field"},
  { WRITE_SINGLE_STRUCTURED_FIELD                               ,  "Write Single Structured Field"},
  { COPY_TO_PRINTER                                             ,  "Copy-To-Printer"},
  { 0x00, NULL }
};

/* 15.4 Clear Unit Alternate*/
static const value_string vals_tn5250_cua_parms[] = {
  { 0x00                                                  ,  "Set screen size to 27 rows by 132 columns"},
  { 0x80                                                  ,  "Leave the screen size unchanged and do not erase image/fax data from the display memory."},
  { 0x00, NULL }
};


/* 15.6 Order Codes */
#define TN5250_SBA        0x11
#define TN5250_IC         0x13
#define TN5250_MC         0x14
#define TN5250_RA         0x02
#define TN5250_EA         0x03
#define TN5250_SOH        0x01
#define TN5250_TD         0x10
#define TN5250_WEA        0x12
#define TN5250_SF         0x1D
#define TN5250_WDSF       0x15

static const value_string vals_tn5250_order_codes[] = {
  { TN5250_SBA,  "Set Buffer Address (SBA)"},
  { TN5250_IC ,  "Insert Cursor (IC)"},
  { TN5250_MC ,  "Move Cursor (MC)"},
  { TN5250_RA ,  "Repeat to Address (RA)"},
  { TN5250_EA ,  "Erase to Address (EA)"},
  { TN5250_SOH , "Start of Header (SOH)"},
  { TN5250_TD ,  "Transparent Data (TD)"},
  { TN5250_WEA,  "Write Extended Attribute Order"},
  { TN5250_SF ,  "Start Field (SF)"},
  { TN5250_WDSF, "Write to Display Structured Field (WDSF)"},
  { 0x00, NULL }
};

/* 15.6.1 WTD Control Code */
#define CCBITS                                0xFF

static const value_string vals_tn5250_wtd_cc_byteone[] = {
  { 0x00  ,  ""},
  { 0x20  ,  "Reset pending AID, lock keyboard"},
  { 0x40  ,  "Reset pending AID, lock keyboard, Reset MDT flags in non-bypass fields"},
  { 0x60  ,  "Reset pending AID, lock keyboard, Reset MDT flags in all fields"},
  { 0x80  ,  "Reset pending AID, lock keyboard, Null all non-bypass fields with  MDT on"},
  { 0xA0  ,  "Reset pending AID, lock keyboard, Reset MDT flags in non-bypass fields, Null all non-bypass fields"},
  { 0xC0  ,  "Reset pending AID, lock keyboard, Reset MDT flags in non-bypass fields, Null all non-bypass fields with MDT on"},
  { 0xE0  ,  "Reset pending AID, lock keyboard, Reset MDT flags in all fields, Null all non-bypass fields"},
  { 0x00, NULL }
};

/* 15.6.8 Erase to Address Order */
/* 15.6.11 Write Extended Attribute Order */
#define EXTENDED_IDEOGRAPHIC_ATTRIBUTES          0x05
#define EXTENDED_FOREGROUND_COLOR_ATTRIBUTES     0x03
#define EXTENDED_PRIMARY_ATTRIBUTES              0x01

static const value_string vals_tn5250_attributes[] = {
  { 0x00,  "Display screen"},
  { 0x01,  "Extended primary attributes"},
  { 0x02,  "Extended text attributes (use in WP mode only)"},
  { 0x03,  "Extended foreground color attributes"},
  { 0x05,  "Extended ideographic attributes"},
  { 0xFF,  "Display screen and all extended attribute types supported by this "
    "workstation. Use X'FF' to clear all extended attribute types for "
    "optimum performance, even if all types are not used."},
  { 0x00, NULL }
};


/* 15.6.11.1 Write Extended Attribute Order - Extended Primary Attribute*/
/* 15.6.12.3 Start of Field Order - Field Attribute*/
#define FA_ID      0x20
#define FA_ID_BITS 0xE0
static const value_string vals_tn5250_fa_id[] = {
  { 0x01       ,  "Identifies Field as Field Format Word"},
  { 0x00, NULL }
};

static const struct true_false_string tn5250_field_attr_col = {
  "Column Separator On",
  "Column Separator Off"
};

static const struct true_false_string tn5250_field_attr_blink = {
  "Blink Field",
  "Do Not Blink Field"
};

static const struct true_false_string tn5250_field_attr_und = {
  "Underscore Field",
  "Do Not Underscore Field"
};

static const struct true_false_string tn5250_field_attr_int = {
  "High Intensity",
  "Low Intensity"
};

static const struct true_false_string tn5250_field_attr_rev = {
  "Reverse Image",
  "Normal Image"
};


/* 15.6.11.2 Write Extended Attribute Order - Valid Extended Foreground Color Attributes*/

static const value_string vals_tn5250_foreground_color_attributes[] = {
  { 0x00,  "Null - continue currently defined attribute"},
  { 0x80,  "Color of the display background medium; black on most models"},
  { 0x81 ,  "Color of the display background medium; black on most models"},
  { 0x82,  "blue"},
  { 0x83,  "blue; different shade of blue than X'82' on some displays"},
  { 0x84,  "green"},
  { 0x85,  "green; different shade of green than X'84' on some displays"},
  { 0x86,  "turquoise"},
  { 0x87,  "turquoise; different shade of turquoise than X'86' on some displays"},
  { 0x88,  "red"},
  { 0x89,  "red; different shade of red than X'88' on some displays"},
  { 0x8A,  "pink"},
  { 0x8B,  "pink; different shade of pink than X'8A' on some displays"},
  { 0x8C,  "yellow"},
  { 0x8D,  "yellow; different shade of pink than X'8C' on some displays"},
  { 0x8E,  "white"},
  { 0x8F,  "white; different shade of white than X'8E' on some displays"},
  { 0x00, NULL }
};


/* 15.6.11.3 Write Extended Attribute Order - Valid Extended Ideographic Attributes*/
static const value_string vals_tn5250_ideographic_attributes[] = {
  { 0x00,  "Null - continue currently defined attribute"},
  { 0x80,  "Normal display attribute - end double byte mode (SI)"},
  { 0x81,  "Begin double byte mode (SO)"},
  { 0x00, NULL }
};

/* 15.6.12.1 Start of Field Order - Field Format Word */
#define FFW_ID      0x40
#define FFW_ID_BITS 0xC0
static const value_string vals_tn5250_ffw_id[] = {
  { 0x01       ,  "Identifies Field as Field Format Word"},
  { 0x00, NULL }
};

static const struct true_false_string tn5250_field_ffw_bypass = {
  "This is a bypass field",
  "This is not a bypass field"
};

static const struct true_false_string tn5250_field_ffw_dup = {
  "Duplication or Field Mark is allowed in this field",
  "Duplication or Field Mark is not allowed in this field"
};

static const struct true_false_string tn5250_field_ffw_mdt = {
  "This field has been modified",
  "This field has not been modified"
};

#define FFW_SHIFT_BITS                        0x07

static const value_string vals_tn5250_ffw_shift[] = {
  { 0x00,  "Alpha shift"},
  { 0x01,  "Alpha only"},
  { 0x02,  "Numeric shift"},
  { 0x03,  "Numeric only"},
  { 0x04,  "Katakana shift"},
  { 0x05,  "Digits only"},
  { 0x06,  "I/O-(feature input field)"},
  { 0x07,  "Signed numeric"},
  { 0x00, NULL }
};

static const struct true_false_string tn5250_field_ffw_auto = {
  "Auto Enter When Field is Exited",
  "No Auto Enter"
};

static const struct true_false_string tn5250_field_ffw_fer = {
  "Field Exit key is required",
  "Field Exit key is not required"
};

static const struct true_false_string tn5250_field_ffw_monocase = {
  "Translate operator keyed letters to uppercase",
  "Accept lower case letters"
};

static const struct true_false_string tn5250_field_ffw_me = {
  "Mandatory Enter Field",
  "Not A Mandatory Enter Field"
};

#define FFW_ADJUST_BITS                0x07

static const value_string vals_tn5250_ffw_adjust[] = {
  { 0x00,  "No adjust specified"},
  { 0x01,  "Reserved"},
  { 0x02,  "Reserved"},
  { 0x03,  "Reserved"},
  { 0x04,  "Reserved"},
  { 0x05,  "Right adjust, zero fill"},
  { 0x06,  "Right adjust, blank fill"},
  { 0x07,  "Mandatory fill"},
  { 0x00, NULL }
};

/* 15.6.12.2 Start of Field Order - Field Control Word */

#define SELECTOR                                                     0x81
#define IDEOGRAPHIC                                                  0x82
#define FORWARD_EDGE                                                 0x85
#define CONTINUED_ENTRY                                              0x86
#define SELF_CHECK                                                   0xB1
#define ENTRY_FIELD_RESEQUENCING                                     0x80
#define CURSOR_PROGRESSION_ENTRY_FIELD                               0x88
#define HIGHLIGHTED_ENTRY_FIELD                                      0x89
#define POINTER_DEVICE_SELECTION_ENTRY_FIELD                         0x8A
#define TRANSPARENCY_ENTRY_FIELD                                     0x84

static const range_string vals_tn5250_fcw[] = {
  { 0x8000,  0x8080, "Entry field resequencing. The nn specifies the next entry field in the sequence (X'00' to X'80')."},
  { 0x8101,  0x8101, "Magnetic stripe reader entry field"},
  { 0x8102,  0x8102, "Selector light pen or cursor select field"},
  { 0x8103,  0x8103, "Magnetic stripe reader and selector light pen entry field"},
  { 0x8106,  0x8106, "Selector light pen and selectable attention entry field"},
  { 0x8200,  0x8200, "Ideographic-only entry field"},
  { 0x8220,  0x8220, "Ideographic data type entry field"},
  { 0x8240,  0x8240, "Ideographic-either entry field"},
  { 0x8280,  0x8280, "Ideographic-open entry field"},
  { 0x82C0,  0x82C0, "Ideographic-open entry field"},
  { 0x8400,  0x84FF, "Transparency entry field. The nn can be any two digits."},
  { 0x8501,  0x8501, "Forward edge trigger entry field"},
  { 0x8601,  0x8603, "Continued entry field"},
  { 0x8680,  0x8680, "Word Wrap entry field"},
  { 0x8800,  0x88FF, "Cursor progression entry field. The nn is the next entry field in the specified application cursor progression sequence."},
  { 0x8900,  0x89FF, "Highlighted entry field. The nn specifies the field attribute"},
  { 0x8A00,  0x8AFF, "Pointer device selection entry field. If a user selects the entry field, the nn specifies the AID to be returned."},
  { 0xB140,  0xB140, "Self-check modulus 11 entry field"},
  { 0xB1A0,  0xB1A0, "Self-check modulus 10 entry field"},
  { 0,  0,      NULL}
};


#if 0
#define MAGNETIC_STRIPE_READER_ENTRY_FIELD                           0x8101
#define SELECTOR_LIGHT_PEN_OR_CURSOR_SELECT_FIELD                    0x8102
#define MAGNETIC_STRIPE_READER_AND_SELECTOR_LIGHT_PEN_ENTRY_FIELD    0x8103
#define SELECTOR_LIGHT_PEN_AND_SELECTABLE_ATTENTION_ENTRY_FIELD      0x8106
#define IDEOGRAPHIC_ONLY_ENTRY_FIELD                                 0x8200
#define IDEOGRAPHIC_DATA_TYPE_ENTRY_FIELD                            0x8220
#define IDEOGRAPHIC_EITHER_ENTRY_FIELD                               0x8240
#define IDEOGRAPHIC_OPEN_ENTRY_FIELD                                 0x8280
#define IDEOGRAPHIC_OPEN_ENTRY_FIELD1                                0x82C0
#define FORWARD_EDGE_TRIGGER_ENTRY_FIELD                             0x8501
#define CONTINUED_ENTRY_FIELD                                        0x8601
#define CONTINUED_ENTRY_FIELD1                                       0x8602
#define CONTINUED_ENTRY_FIELD2                                       0x8603
#define WORD_WRAP_ENTRY_FIELD                                        0x8680
#define SELF_CHECK_MODULUS_11_ENTRY_FIELD                            0xB140
#define SELF_CHECK_MODULUS_10_ENTRY_FIELD                            0xB1A0

static const value_string vals_tn5250_fcw[] = {
  { ENTRY_FIELD_RESEQUENCING                                 ,  "Entry field resequencing. The NN specifies the next entry field "
    "in the sequence (X'00' to X'80')."},
  { MAGNETIC_STRIPE_READER_ENTRY_FIELD                       ,  "Magnetic stripe reader entry field"},
  { SELECTOR_LIGHT_PEN_OR_CURSOR_SELECT_FIELD                ,  "Selector light pen or cursor select field"},
  { MAGNETIC_STRIPE_READER_AND_SELECTOR_LIGHT_PEN_ENTRY_FIELD,  "Magnetic stripe reader and selector light pen entry field"},
  { SELECTOR_LIGHT_PEN_AND_SELECTABLE_ATTENTION_ENTRY_FIELD  ,  "Selector light pen and selectable attention entry field"},
  { IDEOGRAPHIC_ONLY_ENTRY_FIELD                             ,  "Ideographic-only entry field"},
  { IDEOGRAPHIC_DATA_TYPE_ENTRY_FIELD                        ,  "Ideographic data type entry field"},
  { IDEOGRAPHIC_EITHER_ENTRY_FIELD                           ,  "Ideographic-either entry field"},
  { IDEOGRAPHIC_OPEN_ENTRY_FIELD                             ,  "Ideographic-open entry field"},
  { IDEOGRAPHIC_OPEN_ENTRY_FIELD1                            ,  "Ideographic-open entry field"},
  { TRANSPARENCY_ENTRY_FIELD                                 ,  "Transparency entry field. The NN can be any two digits."},
  { FORWARD_EDGE_TRIGGER_ENTRY_FIELD                         ,  "Forward edge trigger entry field"},
  { CONTINUED_ENTRY_FIELD                                    ,  "Continued entry field"},
  { CONTINUED_ENTRY_FIELD1                                   ,  "Continued entry field"},
  { CONTINUED_ENTRY_FIELD2                                   ,  "Continued entry field"},
  { WORD_WRAP_ENTRY_FIELD                                    ,  "Word Wrap entry field"},
  { CURSOR_PROGRESSION_ENTRY_FIELD                           ,  "Cursor progression entry field. The NN is the next entry field "
                                                                "in the specified application cursor progression sequence."},
  { HIGHLIGHTED_ENTRY_FIELD                                  ,  "Highlighted entry field. The NN specifies the field attribute"},
  { POINTER_DEVICE_SELECTION_ENTRY_FIELD                     ,  "Pointer device selection entry field. If a user selects the "
                                                                "entry field, the NN specifies the AID to be returned."},
  { SELF_CHECK_MODULUS_11_ENTRY_FIELD                        ,  "Self-check modulus 11 entry field"},
  { SELF_CHECK_MODULUS_10_ENTRY_FIELD                        ,  "Self-check modulus 10 entry field"},
  { 0x00, NULL }
};
#endif

/* 15.6.12.3 Start of Field Order - Field Attribute */

static const value_string vals_tn5250_fa_color[] = {
  { 0x20,  "Green"},
  { 0x21,  "Green/Reverse image"},
  { 0x22,  "White"},
  { 0x23,  "White/Reverse image"},
  { 0x24,  "Green/Underscore"},
  { 0x25,  "Green/Underscore/Reverse image"},
  { 0x26,  "White/Underscore"},
  { 0x27,  "Nondisplay"},
  { 0x28,  "Red"},
  { 0x29,  "Red/Reverse image "},
  { 0x2A,  "Red/Blink"},
  { 0x2B,  "Red/Reverse image/Blink"},
  { 0x2C,  "Red/Underscore"},
  { 0x2D,  "Red/Underscore/Reverse image"},
  { 0x2E,  "Red/Underscore/Blink"},
  { 0x2F,  "Nondisplay"},
  { 0x30,  "Turquoise/Column separators "},
  { 0x31,  "Turquoise/Column separators/Reverse image"},
  { 0x32,  "Yellow/Column separators"},
  { 0x33,  "Yellow/Column separators/Reverse image"},
  { 0x34,  "Turquoise/Underscore"},
  { 0x35,  "Turquoise/Underscore/Reverse image"},
  { 0x36,  "Yellow/Underscore"},
  { 0x37,  "Nondisplay"},
  { 0x38,  "Pink"},
  { 0x39,  "Pink/Reverse image"},
  { 0x3A,  "Blue"},
  { 0x3B,  "Blue/Reverse image"},
  { 0x3C,  "Pink/Underscore"},
  { 0x3D,  "Pink/Underscore/Reverse image "},
  { 0x3E,  "Blue/Underscore"},
  { 0x3F,  "Nondisplay"},
  { 0x00, NULL }
};

/* 15.6.13  Write to Display Structured Field Order */
#define CLASS_5250            0xD9

static const value_string vals_tn5250_sf_class[] = {
  { CLASS_5250       ,  "5250 Class of Structured Field"},
  { 0x00, NULL }
};

/* 15.6.13 - Major Structure Types */
#define DEFINE_SELECTION_FIELD                     0x50
#define CREATE_WINDOW                              0x51
#define UNRESTRICTED_WINDOW_CURSOR_MOVEMENT        0x52
#define DEFINE_SCROLL_BAR_FIELD                    0x53
#define WRITE_DATA                                 0x54
#define PROGRAMMABLE_MOUSE_BUTTONS                 0x55
#define REMOVE_GUI_SELECTION_FIELD                 0x58
#define REMOVE_GUI_WINDOW                          0x59
#define REMOVE_GUI_SCROLL_BAR_FIELD                0x5B
#define REMOVE_ALL_GUI_CONSTRUCTS                  0x5F
#define DRAW_ERASE_GRID_LINES                      0x60
#define CLEAR_GRID_LINE_BUFFER                     0x61
#define IMAGE_FAX_CONTROL                          0x66
#define IMAGE_FAX_DOWNLOAD                         0x67
#define WSC_CUSTOMIZATION                          0x71
#define DEFINE_AUDIT_WINDOW__TABLE                 0x30
#define DEFINE_COMMAND_KEY_FUNCTION                0x31
#define READ_TEXT_SCREEN                           0x32
#define DEFINE_PENDING_OPERATIONS                  0x33
#define DEFINE_TEXT_SCREEN_FORMAT                  0x34
#define DEFINE_SCALE_LINE                          0x35
#define WRITE_TEXT_SCREEN                          0x36
#define DEFINE_SPECIAL_CHARACTERS                  0x37
#define PENDING_DATA                               0x38
#define DEFINE_OPERATOR_ERROR_MESSAGES             0x39
#define DEFINE_PITCH_TABLE                         0x3A
#define DEFINE_FAKE_DP_COMMAND_KEY_FUNCTION        0x3B
#define PASS_THROUGH                               0x3F
#define TN5250_QUERY                               0x70
#define TN5250_QUERY_STATION_STATE                 0x72
#define VIDEO_AUDIO_CONTROLS                       0x68
#define TRUE_TRANSPARENCY_WRITE                    0x6A

static const value_string vals_tn5250_sf_type[] = {
  { DEFINE_SELECTION_FIELD             ,  "Define Selection Field"},
  { CREATE_WINDOW                      ,  "Create Window"},
  { UNRESTRICTED_WINDOW_CURSOR_MOVEMENT,  "Unrestricted Window Cursor Movement"},
  { DEFINE_SCROLL_BAR_FIELD            ,  "Define Scroll Bar Field"},
  { WRITE_DATA                         ,  "Write Data"},
  { PROGRAMMABLE_MOUSE_BUTTONS         ,  "Programmable Mouse Buttons"},
  { REMOVE_GUI_SELECTION_FIELD         ,  "Remove Gui Selection Field"},
  { REMOVE_GUI_WINDOW                  ,  "Remove Gui Window"},
  { REMOVE_GUI_SCROLL_BAR_FIELD        ,  "Remove Gui Scroll Bar Field"},
  { REMOVE_ALL_GUI_CONSTRUCTS          ,  "Remove All Gui Constructs"},
  { DRAW_ERASE_GRID_LINES              ,  "Draw/Erase Grid Lines"},
  { CLEAR_GRID_LINE_BUFFER             ,  "Clear Grid Line Buffer"},
  { IMAGE_FAX_CONTROL                  ,  "Image Fax Control"},
  { IMAGE_FAX_DOWNLOAD                 ,  "Image Fax Download"},
  { WSC_CUSTOMIZATION                  ,  "Wsc Customization"},
  { DEFINE_AUDIT_WINDOW__TABLE         ,  "Define Audit Window Table"},
  { DEFINE_COMMAND_KEY_FUNCTION        ,  "Define Command Key Function"},
  { READ_TEXT_SCREEN                   ,  "Read Text Screen"},
  { DEFINE_PENDING_OPERATIONS          ,  "Define Pending Operations"},
  { DEFINE_TEXT_SCREEN_FORMAT          ,  "Define Text Screen Format"},
  { DEFINE_SCALE_LINE                  ,  "Define Scale Line"},
  { WRITE_TEXT_SCREEN                  ,  "Write Text Screen"},
  { DEFINE_SPECIAL_CHARACTERS          ,  "Define Special Characters"},
  { PENDING_DATA                       ,  "Pending Data"},
  { DEFINE_OPERATOR_ERROR_MESSAGES     ,  "Define Operator Error Messages"},
  { DEFINE_PITCH_TABLE                 ,  "Define Pitch Table"},
  { DEFINE_FAKE_DP_COMMAND_KEY_FUNCTION,  "Define Fake Dp Command Key Function"},
  { PASS_THROUGH                       ,  "Pass-Through"},
  { TN5250_QUERY                       ,  "5250 Query"},
  { TN5250_QUERY_STATION_STATE         ,  "5250 Query Station State"},
  { VIDEO_AUDIO_CONTROLS               ,  "Video/Audio Controls Command"},
  { TRUE_TRANSPARENCY_WRITE            ,  "True Transparency Write Command"},
  { 0x00, NULL }
};

/* 15.6.13.1  Write to Display Structured Field Order - Create Window */
static const struct true_false_string tn5250_field_wdsf_cw_flag1_1 = {
  "Cursor Restricted To Window",
  "Cursor Not Restricted To Window"
};

static const struct true_false_string tn5250_field_wdsf_cw_flag1_2 = {
  "Window Is A Pull-Down Menu Bar",
  "Window Is Not A Pull-Down Menu Bar"
};

#define CW_BORDER_PRESENTATION                     0x01
#define CW_TITLE_FOOTER                            0x10

static const value_string vals_tn5250_wdsf_cw_minor_type[] = {
  { CW_BORDER_PRESENTATION             ,  "Border Presentation"},
  { CW_TITLE_FOOTER                    ,  "Window Title/Footer"},
  { 0x00, NULL }
};

/* 15.6.13.1  Write to Display Structured Field Order - Create Window - Border Presentation Minor Structure */
static const struct true_false_string tn5250_field_wdsf_cw_bp_flag1_1 = {
  "Use Border Presentation Characters on a GUI-like NWS",
  "Do Not Use Border Presentation Characters on a GUI-like NWS"
};

/* 15.6.13.1  Write to Display Structured Field Order - Create Window - Window Title/Footer Minor Structure */
#define WTF_BITS         0xC0

static const value_string vals_tn5250_wdsf_cw_tf_flag_orientation[] = {
  { 0x00,  "Window Title or Footer is Centered"},
  { 0x40,  "Window Title or Footer is Right Justified"},
  { 0x80,  "Window Title or Footer is Left Justified"},
  { 0xC0,  "Reserved (Window Title or Footer is Centered)"},
  { 0x00, NULL }
};

static const struct true_false_string tn5250_field_wdsf_cw_tf_flag_1 = {
  "Window Footer is Defined",
  "Window Title is Defined"
};


/* 15.6.13.4  Write to Display Structured Field Order - Remove All GUI Constructs*/
static const struct true_false_string tn5250_field_wdsf_ragc_flag1_0 = {
  "5494 Maps GUI-like Characters",
  "5494 Does Not Map GUI-like Characters"
};


/* 15.6.13.5  Write to Display Structured Field Order - Define Selection Field*/
#define DS_CHOICE_TEXT                 0x10
#define DS_MENU_BAR_SEPARATOR          0x09
#define DS_CHOICE_PRESENTATION_DISPLAY 0x01
#define DS_CHOICE_INDICATORS           0x02
#define DS_SCROLLBAR_INDICATORS        0x03


static const value_string vals_tn5250_wdsf_ds_minor_type[] = {
  { DS_CHOICE_TEXT                ,  "Choice Text"},
  { DS_MENU_BAR_SEPARATOR         ,  "Menu Bar Separator"},
  { DS_CHOICE_PRESENTATION_DISPLAY,  "Choice Presentation Display Attributes"},
  { DS_CHOICE_INDICATORS          ,  "Choice Indicators"},
  { DS_SCROLLBAR_INDICATORS       ,  "Scroll Bar Indicators"},
  { 0x00, NULL }
};

#define MOUSE_CHARACTERISTICS_BITS         0x03

static const value_string vals_tn5250_wdsf_ds_flag1_mouse_characteristics[] = {
  { 0x00,  "Use this selection field in all cases"},
  { 0x02,  "Use this selection field only if the display does not have a mouse."},
  { 0x01,  "Use this selection field only if the display has a mouse."},
  { 0x03,  "Reserved"},
  { 0x00, NULL }
};

#define DS_AUTO_ENTER_BITS         0x30

static const value_string vals_tn5250_wdsf_ds_flag1_auto_enter[] = {
  { 0x00,  "Selection field is not auto-enter"},
  { 0x20,  "Selection field is auto-enter on selection except if double-digit numeric selection is used."},
  { 0x10,  "Selection field is auto-enter on selection or deselection except if double-digit numeric selection is used. "},
  { 0x30,  "Selection field is auto-enter on selection except if single-digit or double-digit numeric selection is used."},
  { 0x00, NULL }
};

static const struct true_false_string tn5250_field_wdsf_ds_flag1_1 = {
  "Auto-Select Enabled",
  "Auto-Select Not Enabled"
};

static const struct true_false_string tn5250_field_wdsf_ds_flag1_2 = {
  "Field MDT Enabled",
  "Field MDT Not Enabled"
};

static const struct true_false_string tn5250_field_wdsf_ds_flag2_1 = {
  "If set to on, a scroll bar should is created beside the selection field choices, and TotalRows and SliderPos that can "
  "be scrolled are included in the major structure.",
  "No Action"
};

static const struct true_false_string tn5250_field_wdsf_ds_flag2_2 = {
  "If set to on, one blank is added after the numeric separator character.",
  "No Action"
};

static const struct true_false_string tn5250_field_wdsf_ds_flag2_3 = {
  "If set to on, an asterisk (*) replaces the first character of an unavailable choice on monochrome display.",
  "No Action"
};

static const struct true_false_string tn5250_field_wdsf_ds_flag2_4 = {
  "If set to on, cursor is limited to input-capable positions only.",
  "No Action"
};

static const struct true_false_string tn5250_field_wdsf_ds_flag2_5 = {
  "If set to on, the Field Advance/Field Backspace function is like the Character Advance/Character Backspace keys within "
  "this selection field.",
  "No Action"
};

static const struct true_false_string tn5250_field_wdsf_ds_flag2_6 = {
  "If set to on, the cursor movement keys are not allowed to exit this selection field.",
  "No Action"
};

static const struct true_false_string tn5250_field_wdsf_ds_flag3_1 = {
  "If set to on, any selected choices are changed to available whenever the keyboard is unlocked.",
  "No Action"
};

#define MENU_BAR                                                 0x01
#define SINGLE_CHOICE_SELECTION_FIELD                            0x11
#define MULTIPLE_CHOICE_SELECTION_FIELD                          0x12
#define SINGLE_CHOICE_SELECTION_LIST                             0x21
#define MULTIPLE_CHOICE_SELECTION_LIST                           0x22
#define SINGLE_CHOICE_SELECTION_FIELD_AND_A_PULL_DOWN_LIST       0x31
#define MULTIPLE_CHOICE_SELECTION_FIELD_AND_A_PULL_DOWN_LIST     0x32
#define PUSH_BUTTONS                                             0x41
#define PUSH_BUTTONS_IN_A_PULL_DOWN_MENU_                        0x51

static const value_string vals_tn5250_wdsf_ds_type[] = {
  { MENU_BAR                                            ,  "Menu bar"},
  { SINGLE_CHOICE_SELECTION_FIELD                       ,  "Single choice selection field"},
  { MULTIPLE_CHOICE_SELECTION_FIELD                     ,  "Multiple choice selection field"},
  { SINGLE_CHOICE_SELECTION_LIST                        ,  "Single choice selection list"},
  { MULTIPLE_CHOICE_SELECTION_LIST                      ,  "Multiple choice selection list"},
  { SINGLE_CHOICE_SELECTION_FIELD_AND_A_PULL_DOWN_LIST  ,  "Single choice selection field and a pull-down list"},
  { MULTIPLE_CHOICE_SELECTION_FIELD_AND_A_PULL_DOWN_LIST,  "Multiple choice selection field and a pull-down list"},
  { PUSH_BUTTONS                                        ,  "Push buttons"},
  { PUSH_BUTTONS_IN_A_PULL_DOWN_MENU_                   ,  "Push buttons in a pull-down menu "},
  { 0x00, NULL }
};

#define DS_INDICATOR1              0x00
#define DS_INDICATOR2              0x02
#define DS_INDICATOR3              0x03
#define DS_INDICATOR4              0x04
#define DS_INDICATOR5              0x05
#define DS_INDICATOR6              0x06
#define DS_INDICATOR7              0x0F
#define DS_INDICATORS_BITS         0x0F

static const value_string vals_tn5250_wdsf_ds_gdc_indicators[] = {
  { DS_INDICATOR1,  "An indicator to the left of each choice (check box or radio button) is created."},
  { DS_INDICATOR2,  "A push button box is created around choice text and the choice text is padded with a blank on both sides."},
  { DS_INDICATOR3,  "A push button indicator specifies each choice instead of a push button  box on a GUI-like NWS. (A GUI "
                    "PWS treats this setting like B'0010'.)"},
  { DS_INDICATOR4,  "A push button box is created around choice text and choice text is padded  with a blank on both sides,"
                    " and a leading choice text attribute is written on top of the previous choice  text ending attribute."},
  { DS_INDICATOR5,  "A push button indicator specifies each choice instead of a push button box on a GUI-like NWS, and a leading "
                    "choice text attribute is specified on top of the previous ending choice text attribute. (A GUI PWS treats "
                    "this setting like B'0100'.)"},
  { DS_INDICATOR6,  "A push button box is created around choice text (with no padding)."},
  { DS_INDICATOR7,  "There are no indicators for this value. It is valid for all types of selection."},
  { 0x00, NULL }
};

#define DS_SELECTION_TECHNIQUES1             0x20
#define DS_SELECTION_TECHNIQUES2             0x40
#define DS_SELECTION_TECHNIQUES3             0xE0
#define DS_SELECTION_TECHNIQUES_BITS         0xE0

static const value_string vals_tn5250_wdsf_ds_gdc_selection_techniques[] = {
  { DS_SELECTION_TECHNIQUES1,  "Defines a mnemonic (or numeric) selection for some or all of the choices. The mnemonic is underscored."},
  { DS_SELECTION_TECHNIQUES2,  "Defines a mnemonic (or numeric) selection for some or all of the choices. "
    "The mnemonic is not underscored."},
  { DS_SELECTION_TECHNIQUES3,  "No mnemonic (or numeric) selection is specified."},
  { 0x00, NULL }
};


#define DS_NWS_INDICATOR1              0x00
#define DS_NWS_INDICATOR2              0x03
#define DS_NWS_INDICATOR3              0x05
#define DS_NWS_INDICATOR4              0x08
#define DS_NWS_INDICATOR5              0x0F
#define DS_NWS_INDICATORS_BITS         0x0F

static const value_string vals_tn5250_wdsf_ds_nws_indicators[] = {
  { DS_NWS_INDICATOR1,  "An indicator to the left of each  choice (for example, a slash (/)) is  created. (1)"},
  { DS_NWS_INDICATOR2,  "A push button indicator specifies each choice. (2)"},
  { DS_NWS_INDICATOR3,  "A push button indicator specifies each choice, and a leading choice text attribute is "
                        "specified on top of a previous ending choice text attribute. (2)"},
  { DS_NWS_INDICATOR4,  "A numeric field to the left of the first choice is created. (Single- or double-digit "
                        "numeric fields are determined by bits 5-7.) (3)"},
  { DS_NWS_INDICATOR5,  "No indicators are specified for this value. This is valid for all types of selection fields."},
  { 0x00, NULL }
};

#define DS_NWS_SELECTION_TECHNIQUES1             0x20
#define DS_NWS_SELECTION_TECHNIQUES2             0x40
#define DS_NWS_SELECTION_TECHNIQUES3             0x80
#define DS_NWS_SELECTION_TECHNIQUES4             0xA0
#define DS_NWS_SELECTION_TECHNIQUES5             0xE0
#define DS_NWS_SELECTION_TECHNIQUES_BITS         0xE0

static const value_string vals_tn5250_wdsf_ds_nws_selection_techniques[] = {
  { DS_NWS_SELECTION_TECHNIQUES1,  "Defines a mnemonic (or numeric) selection for some or all of the choices. "
                                   "The mnemonic is underscored."},
  { DS_NWS_SELECTION_TECHNIQUES2,  "Defines a mnemonic (or numeric) selection for some or all of the choices. "
                                   "The mnemonic is not underscored."},
  { DS_NWS_SELECTION_TECHNIQUES3,  "Defines a single-digit numeric selection."},
  { DS_NWS_SELECTION_TECHNIQUES4,  "Defines a double-digit numeric selection."},
  { DS_NWS_SELECTION_TECHNIQUES5,  "No mnemonic or numeric selection is defined."},
  { 0x00, NULL }
};

/* 15.6.13.5  Write to Display Structured Field Order - Define Selection Field - Choice Text Minor Structure*/
#define DS_CHOICE_STATE1             0x01
#define DS_CHOICE_STATE2             0x02
#define DS_CHOICE_STATE3             0x03
#define DS_CHOICE_STATE_BITS         0x03

static const value_string vals_tn5250_wdsf_ds_ct_flag1_choice_state[] = {
  { DS_CHOICE_STATE1,  "Available and not a default selection"},
  { DS_CHOICE_STATE2,  "Available and is a default selection (selected state)"},
  { DS_CHOICE_STATE3,  "Not available"},
  { 0x00, NULL }
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag1_2 = {
  "Set to on: specifies a menu bar choice that starts a new row.",
  "Set to on: does not specify a menu bar choice that starts a new row."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag1_3 = {
  "Reserved (incorrectly set to on).",
  "Reserved (set to zero)."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag1_4 = {
  "Set to on: specifies that a  mnemonic offset is included in the minor structure.",
  "Set to off: does not specify that a mnemonic offset is included in the minor structure."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag1_5 = {
  "If set to on, specifies an AID if 'selected' is included in this minor structure.",
  "No Action"
};

#define DS_NUMERIC_SELECTION_NOT_INCLUDED             0x00
#define DS_NUMERIC_SELECTION_SINGLE_DIGIT             0x40
#define DS_NUMERIC_SELECTION_DOUBLE_DIGIT             0x80
#define DS_NUMERIC_SELECTION_BITS                     0xC0

static const value_string vals_tn5250_wdsf_ds_ct_flag1_numeric_selection[] = {
  { DS_NUMERIC_SELECTION_NOT_INCLUDED,  "Numeric selection characters are not included in this minor structure."},
  { DS_NUMERIC_SELECTION_SINGLE_DIGIT,  "A single-digit numeric selection character is included in this minor structure."},
  { DS_NUMERIC_SELECTION_DOUBLE_DIGIT,  "Double-digit numeric selection characters are included in this minor structure."},
  { 0x00, NULL }
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag2_0 = {
  "Set to on, the choice cannot accept a cursor.",
  "Set to off, the choice can accept a cursor."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag2_1 = {
  "Set to on, the application user desires a roll-down AID if the Cursor Up key is pressed on this choice.",
  "Set to off, the application user does not desire a roll-down AID if the Cursor Up key is pressed on this choice."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag2_2 = {
  "Set to on, the application user desires a roll-up AID if the Cursor Up key is pressed on this choice.",
  "Set to off, the application user does not desire a roll-up AID if the Cursor Up key is pressed on this choice."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag2_3 = {
  "Set to on, the application user desires a roll-left AID if the Cursor Up key is pressed on this choice.",
  "Set to off, the application user does not desire a roll-left AID if the Cursor Up key is pressed on this choice."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag2_4 = {
  "Set to on, the application user desires a roll-right AID if the Cursor Up key is pressed on this choice.",
  "Set to off, the application user does not desire a roll-right AID if the Cursor Up key is pressed on this choice."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag2_5 = {
  "Set to on, no push-button box is written for this choice.",
  "Set to off, a push-button box is written for this choice."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag2_6 = {
  "Reserved (incorrectly set to on).",
  "Reserved (set to zero)."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag2_7 = {
  "Set to on, cursor direction is right to left.",
  "Set to off, cursor direction is left to right."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag3_0 = {
  "Set to on, use this minor structure for GUI devices (including GUI-like NWSs).",
  "Set to off, do not use this minor structure for GUI devices (including GUI-like NWSs)."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag3_1 = {
  "Set to on, use this minor structure for non-GUI NWSs that are capable of creating mnemonic underscores.",
  "Set to off, do not use this minor structure for non-GUI NWSs that are capable of creating mnemonic underscores."
};

static const struct true_false_string tn5250_field_wdsf_ds_ct_flag3_2 = {
  "Set to on, use this minor structure for NWS display devices that are not capable of creating underscores.",
  "Set to off, do not use this minor structure for NWS display devices that are not capable of creating underscores."
};

/* 15.6.13.5  Write to Display Structured Field Order - Define Selection Field - Menu Bar Separator Minor Structure*/

static const struct true_false_string tn5250_field_wdsf_ds_mbs_flag_0 = {
  "Use specified separator character on GUI-like NWSs.",
  "Do not use specified separator character on GUI-like NWSs."
};

static const struct true_false_string tn5250_field_wdsf_ds_mbs_flag_1 = {
  "Suppress writing of leading and ending attributes.",
  "Do not suppress writing of leading and ending attributes."
};

/* 15.6.13.5  Write to Display Structured Field Order - Define Selection Field - Choice Presentation Display Attributes Minor Structure*/

static const struct true_false_string tn5250_field_wdsf_ds_cpda_flag1_0 = {
  "Uses the minor structure for GUI devices (including GUI-like NWSs).",
  "Does not use the minor structure for GUI devices (including GUI-like NWSs)."
};

static const struct true_false_string tn5250_field_wdsf_ds_cpda_flag1_1 = {
  "Uses the minor structure for NWSs that are capable of creating underscores.",
  "Does not use the minor structure for NWSs that are capable of creating underscores."
};

static const struct true_false_string tn5250_field_wdsf_ds_cpda_flag1_2 = {
  "Uses the minor structure for NWSs that are not capable of creating mnemonic underscores.",
  "Does not use the minor structure for NWSs that are not capable of creating mnemonic underscores."
};

/* 15.6.13.5  Write to Display Structured Field Order - Define Selection Field - Choice Indicators Minor Structure*/

static const struct true_false_string tn5250_field_wdsf_ds_ci_flag1_0 = {
  "Use the specified indicators on GUI-like NWSs.",
  "Do Not Use the specified indicators on GUI-like NWSs"
};

/* 15.6.13.5  Write to Display Structured Field Order - Define Selection Field - Scroll Bar Indicators Minor Structure*/

static const struct true_false_string tn5250_field_wdsf_ds_sbi_flag1_0 = {
  "Use the specified indicators on GUI-like NWSs.",
  "Do Not Use the specified indicators on GUI-like NWSs"
};

/* 15.6.13.7  Write to Display Structured Field Order - Define Scroll Bar Field */

static const struct true_false_string tn5250_field_wdsf_dsb_flag1_0 = {
  "On: Vertical scroll bar is set to off and horizontal scroll bar is set to on.",
  "Off: Vertical scroll bar is set to off and horizontal scroll bar is set to on."
};

static const struct true_false_string tn5250_field_wdsf_dsb_flag1_1 = {
  "On: The cursor is moved to the scroll bar on a pointer device scroll bar interaction",
  "Off: The cursor is moved to the scroll bar on a pointer device scroll bar interaction."
};

static const struct true_false_string tn5250_field_wdsf_dsb_flag1_7 = {
  "On: Field MDT",
  "Off: Field MDT"
};

/* 15.6.13.9  Write to Display Structured Field Order - Write Data Field */

static const struct true_false_string tn5250_field_wdsf_wdf_flag1_0 = {
  "On: Write data to entry field",
  "Off: Do not write data to entry field"
};

/* 15.6.13.10  Write to Display Structured Field Order - Programmable Mouse Buttons */
static const struct true_false_string tn5250_field_wdsf_pmb_flag1_0 = {
  "Two-event definition",
  "Single-event definition"
};

static const struct true_false_string tn5250_field_wdsf_pmb_flag1_1 = {
  "On: The text cursor is moved to the location of the mouse cursor.",
  "Off: The text cursor is NOT moved to the location of the mouse cursor."
};

static const struct true_false_string tn5250_field_wdsf_pmb_flag1_2 = {
  "On: The single mouse event is queued if the keyboard is locked.",
  "Off: The single mouse event is not queued if the keyboard is locked"
};

static const struct true_false_string tn5250_field_wdsf_pmb_flag1_3 = {
  "On: A marker box is drawn on the first event of a two-event definition",
  "Off: A marker box is not drawn on the first event of a two-event definition"
};

#define PMB_RESERVED                              0x00
#define LEFT_BUTTON_PRESSED                       0x01
#define LEFT_BUTTON_RELEASED                      0x02
#define LEFT_BUTTON_DOUBLE_CLICK                  0x03
#define RIGHT_BUTTON_PRESSED                      0x04
#define RIGHT_BUTTON_RELEASED                     0x05
#define RIGHT_BUTTON_DOUBLE_CLICK                 0x06
#define MIDDLE_BUTTON_PRESSED                     0x07
#define MIDDLE_BUTTON_RELEASED                    0x08
#define MIDDLE_BUTTON_DOUBLE_CLICK                0x09
#define SHIFTED_LEFT_BUTTON_PRESSED               0x0A
#define SHIFTED_LEFT_BUTTON_RELEASED              0x0B
#define SHIFTED_LEFT_BUTTON_DOUBLE_CLICK          0x0C
#define SHIFTED_RIGHT_BUTTON_PRESSED              0x0D
#define SHIFTED_RIGHT_BUTTON_RELEASED             0x0E
#define SHIFTED_RIGHT_BUTTON_DOUBLE_CLICK         0x0F
#define SHIFTED_MIDDLE_BUTTON_PRESSED             0x10
#define SHIFTED_MIDDLE_BUTTON_RELEASED            0x11
#define SHIFTED_MIDDLE_BUTTON_DOUBLE_CLICK        0x12

static const value_string vals_tn5250_mouse_events[] = {
  { PMB_RESERVED                      ,  "Reserved"},
  { LEFT_BUTTON_PRESSED               ,  "Left button pressed"},
  { LEFT_BUTTON_RELEASED              ,  "Left button released"},
  { LEFT_BUTTON_DOUBLE_CLICK          ,  "Left button double click"},
  { RIGHT_BUTTON_PRESSED              ,  "Right button pressed"},
  { RIGHT_BUTTON_RELEASED             ,  "Right button released"},
  { RIGHT_BUTTON_DOUBLE_CLICK         ,  "Right button double click"},
  { MIDDLE_BUTTON_PRESSED             ,  "Middle button pressed"},
  { MIDDLE_BUTTON_RELEASED            ,  "Middle button released"},
  { MIDDLE_BUTTON_DOUBLE_CLICK        ,  "Middle button double click"},
  { SHIFTED_LEFT_BUTTON_PRESSED       ,  "Shifted left button pressed"},
  { SHIFTED_LEFT_BUTTON_RELEASED      ,  "Shifted left button released"},
  { SHIFTED_LEFT_BUTTON_DOUBLE_CLICK  ,  "Shifted left button double click"},
  { SHIFTED_RIGHT_BUTTON_PRESSED      ,  "Shifted right button pressed"},
  { SHIFTED_RIGHT_BUTTON_RELEASED     ,  "Shifted right button released"},
  { SHIFTED_RIGHT_BUTTON_DOUBLE_CLICK ,  "Shifted right button double click"},
  { SHIFTED_MIDDLE_BUTTON_PRESSED     ,  "Shifted middle button pressed"},
  { SHIFTED_MIDDLE_BUTTON_RELEASED    ,  "Shifted middle button released"},
  { SHIFTED_MIDDLE_BUTTON_DOUBLE_CLICK,  "Shifted middle button double click"},
  { 0x00, NULL }
};

/* 15.7 Draw/Erase Grid Lines Structured Field */
static const struct true_false_string tn5250_field_wdsf_deg_flag1_0 = {
  "On: Clear the grid line buffer specified by the partition byte",
  "Off: Do not clear the grid line buffer specified by the partition byte"
};

#define SOLID_LINE                           0x00
#define THICK_SOLID_LINE_BOLD                0x01
#define DOUBLE_LINE                          0x02
#define DOTTED_LINE                          0x03
#define DASHED_LINE                          0x08
#define THICK_DASHED_LINE_BOLD               0x09
#define DOUBLE_DASHED_LINE                   0x0A
#define USE_DEFAULT_LINE_FOR_THE_DISPLAY     0xFF

static const value_string vals_tn5250_deg_lines[] = {
  { SOLID_LINE                      ,  "Solid line"},
  { THICK_SOLID_LINE_BOLD           ,  "Thick solid line (bold)"},
  { DOUBLE_LINE                     ,  "Double line"},
  { DOTTED_LINE                     ,  "Dotted line"},
  { DASHED_LINE                     ,  "Dashed line"},
  { THICK_DASHED_LINE_BOLD          ,  "Thick dashed line (bold)"},
  { DOUBLE_DASHED_LINE              ,  "Double dashed line"},
  { USE_DEFAULT_LINE_FOR_THE_DISPLAY,  "Use default line for the display."},
  { 0x00, NULL }
};

/* 15.7.1 Draw/Erase Grid Lines Structured Field - Minor Structure*/
#define UPPER_HORIZONTAL_LINE                        0x00
#define LOWER_HORIZONTAL_LINE                        0x01
#define LEFT_VERTICAL_LINE                           0x02
#define RIGHT_VERTICAL_LINE                          0x03
#define PLAIN_BOX                                    0x04
#define HORIZONTALLY_RULED_BOX                       0x05
#define VERTICALLY_RULED_BOX                         0x06
#define HORIZONTALLY_AND_VERTICALLY_RULED_BOX        0x07

static const value_string vals_tn5250_wdsf_deg_minor_type[] = {
  { UPPER_HORIZONTAL_LINE                ,  "Upper horizontal line"},
  { LOWER_HORIZONTAL_LINE                ,  "Lower horizontal line"},
  { LEFT_VERTICAL_LINE                   ,  "Left vertical line"},
  { RIGHT_VERTICAL_LINE                  ,  "Right vertical line"},
  { PLAIN_BOX                            ,  "Plain box"},
  { HORIZONTALLY_RULED_BOX               ,  "Horizontally ruled box"},
  { VERTICALLY_RULED_BOX                 ,  "Vertically ruled box"},
  { HORIZONTALLY_AND_VERTICALLY_RULED_BOX,  "Horizontally and vertically ruled box"},
  { 0x00, NULL }
};

static const struct true_false_string tn5250_field_wdsf_deg_ms_flag1_0 = {
  "Erase the construct specified",
  "Draw the construct specified"
};

/* 15.22 SAVE PARTIAL SCREEN Command */
static const struct true_false_string tn5250_field_sps_flag1_0 = {
  "Do not include image/fax information",
  "Include image/fax information if image/fax data is on the 5250 session"
};

/* 15.25 ROLL Command */
static const struct true_false_string tn5250_field_roll_flag1_0 = {
  "Roll down",
  "Roll up"
};

/* 15.26.1 WRITE SINGLE STRUCTURED FIELD Command - 5250 WSC CUSTOMIZATION Command*/
#define KEYSTROKE_BUFFERING_CONTROL              0x01
#define CURSOR_CONTROL                           0x02

static const value_string vals_tn5250_wssf_minor_type[] = {
  { KEYSTROKE_BUFFERING_CONTROL      ,  "Keystroke Buffering Control"},
  { CURSOR_CONTROL                   ,  "Cursor Control"},
  { 0x00, NULL }
};

#define WSC_MINOR_STRUCTURE_LENGTH               0x03

static const struct true_false_string tn5250_field_wssf_flag2_0 = {
  "Reserved",
  "WARNING: Reserved, but set."
};

static const struct true_false_string tn5250_field_wssf_flag2_1 = {
  "Enhanced field exit required mode.",
  "Enhanced field exit required mode not set"
};

static const struct true_false_string tn5250_field_wssf_flag2_2 = {
  "Resets enhanced field exit required mode",
  "Does not reset enhanced field exit required mode"
};

static const struct true_false_string tn5250_field_wssf_flag2_3 = {
  "Sets System/36* mode of operation",
  "Does not set System/36* mode of operation"
};

static const struct true_false_string tn5250_field_wssf_flag2_4 = {
  "Resets System/36* mode of operation",
  "Does not reset System/36* mode of operation"
};

static const struct true_false_string tn5250_field_wssf_flag2_5 = {
  "Set SBA code to X'04' in data returned for READ commands if set to logic 1.",
  "Does not set SBA code to X'04' in data returned for READ commands."
};

static const struct true_false_string tn5250_field_wssf_flag2_6 = {
  "Set SBA code to X'11' in data returned for READ commands if set to logic 1.",
  "Does not set SBA code to X'11' in data returned for READ commands."
};

static const struct true_false_string tn5250_field_wssf_flag2_7 = {
  "Customization applies to entire 5494 if set to logic 1",
  "Customization does not apply to entire 5494 if set to logic 1"
};

/* 15.26.1 WRITE SINGLE STRUCTURED FIELD Command - 5250 WSC CUSTOMIZATION Command
   - Keystroke Buffering Control Minor Structure*/
static const struct true_false_string tn5250_field_wssf_kbc_flag1_5 = {
  "Change type-ahead state if set to logic 1",
  "Change type-ahead state not set"
};

static const struct true_false_string tn5250_field_wssf_kbc_flag1_6 = {
  "Indicates type-ahead is on if set to logic 1 (and bit 5 set to 1). If bit 6 is set to 0 and bit 5 is set to 1, type-ahead is turned off. If bit 5 is set to 0, bit 6 is ignored.",
  "Indicates type-ahead is on if set to logic 1 (and bit 5 set to 1). If bit 6 is set to 0 and bit 5 is set to 1, type-ahead is turned off. If bit 5 is set to 0, bit 6 is ignored."
};

static const struct true_false_string tn5250_field_wssf_kbc_flag1_7 = {
  "Attention key is buffered",
  "Attention key is not buffered"
};

/* 15.26.1 WRITE SINGLE STRUCTURED FIELD Command - 5250 WSC CUSTOMIZATION Command
   - Cursor Control Minor Structure*/

static const struct true_false_string tn5250_field_wssf_cc_flag1_7 = {
  "Cursor will blink",
  "Cursor will not blink"
};

/* 15.26.2 WRITE SINGLE STRUCTURED FIELD Command - IMAGE/FAX CONTROL Command */

static const struct true_false_string tn5250_field_wssf_ifc_flag1_0 = {
  "If the display supports a cache,this image/fax data remains in cache memory when the application "
  "sends one of the above commands to erase this image/fax data",
  "Erase this image/fax from memory whenever any of the following commands are received: CLEAR UNIT, CLEAR UNIT ALTERNATE "
  "(without saving image/fax), RESTORE RESTORE PARTIAL (if image/fax data was indicated in the SAVE PARTIAL), Another IMAGE/FAX CONTROL command"
};

static const value_string tn5250_vals_tn5250_wssf_ifc_vals[] = {
  { 0x00   ,  "Normal display (default)"},
  { 0x08   ,  "Transparent display (underlying text may be seen through the image/fax)"},
  { 0x04   ,  "Non-display (the image/fax data remains in memory until it is erased). All other parameters in this command are ignored."},
  { 0x02   ,  "Previously stored image/fax data is erased from the 5250 session and possibly from display memory "
              "(see bit 0 previously). All other parameters in this command are ignored."},
  { 0x00, NULL }
};

static const struct true_false_string tn5250_field_wssf_ifc_flag1_4 = {
  "The display does not present scroll bars",
  "The display presents vertical and horizontal scroll bars as needed and allows the user to scroll without "
  "any interaction with the AS/400 application"
};

static const struct true_false_string tn5250_field_wssf_ifc_flag1_5 = {
  "Image/fax is light foreground on dark background. Preserve the light foreground data during scaling",
  "Image/fax is dark foreground on light background. Preserve the dark foreground data during scaling"
};

static const struct true_false_string tn5250_field_wssf_ifc_flag1_6 = {
  "Background and foreground colors are reversed",
  "Normal image/fax display"
};

static const struct true_false_string tn5250_field_wssf_ifc_flag1_7 = {
  "Do not allow EasyScroll with the primary mouse button.",
  "Allow the primary mouse button to EasyScroll the image/fax"
};

static const struct true_false_string tn5250_field_wssf_ifc_flag2_0 = {
  "For Group 3 or 4 fax, each scan line is duplicated. For high-resolution fax transmission, characters would otherwise appear flattened on the display screen",
  "Normal image/fax display"
};

static const struct true_false_string tn5250_field_wssf_ifc_flag2_1 = {
  "Inhibit the secondary mouse button to Trim Magnify",
  "Allow the secondary mouse button to Trim Magnify the image/fax data"
};

static const struct true_false_string tn5250_field_wssf_ifc_flag2_7 = {
  "Reserved for IBM image/fax-capable displays. It is used to download compression algorithms. Non-IBM displays should ignore this bit.",
  "Reserved for IBM image/fax-capable displays. It is used to download compression algorithms. Non-IBM displays should ignore this bit."
};

static const value_string vals_tn5250_image_format[] = {
  { 0x0000,  "An unknown IBM-defined format."},
  { 0x0001,  "IOCA (The IOCA header defines the compression algorithm.)"},
  { 0x0002,  "TIFF (The TIFF header defines the compression algorithm.)"},
  { 0x0003,  "PCX"},
  { 0x0004,  "Stand alone Group 3 Fax compression."},
  { 0x00, NULL }
};


static const value_string vals_tn5250_wssf_ifc_scaling[] = {
  { 0xFFFE,  "No Scroll Bar Scaling. The data is scaled such that it fits within the Viewport without requiring scrolling in either direction."},
  { 0xFFFD,  "Fill Scaling. The data is scaled such that it fits horizontally within the Viewport without requiring horizontal scroll bars."},
  { 0xFFEA,  "Decrement Scaling Values."},
  { 0xFFDA,  "Increment Scaling Values."},
  { 0x00, NULL }
};


/* 15.26.3 WRITE SINGLE STRUCTURED FIELD Command - IMAGE/FAX DOWNLOAD Command */
static const struct true_false_string tn5250_field_wssf_ifd_flag1_0 = {
  "This is the last or only IMAGE/FAX DOWNLOAD command for this image/fax",
  "Additional IMAGE/FAX DOWNLOAD commands follow, containing data for this image/fax"
};

static const value_string vals_tn5250_image_fax_error[] = {
  { 0x0001, "Image/fax data was too large. Only the first portion of the data is displayed."},
  { 0x0002, " Image/fax data was too large. The data was ignored."},
  { 0x0003, " Invalid major length in the IMAGE/FAX CONTROL command"},
  { 0x0004, " Invalid major length in the IMAGE/FAX DOWNLOAD command"},
  { 0x0005, " Error in the IMAGE/FAX CONTROL command"},
  { 0x0006, " Error in the IMAGE/FAX DOWNLOAD command"},
  { 0x0007, " Error detected in the image/fax data"},
  { 0x0000, NULL }
};



/* 15.26.4 WRITE SINGLE STRUCTURED FIELD Command - Video/Audio Controls Command Major Structure */

static const range_string vals_tn5250_vac_data[] = {
  { 0x13000001, 0x13000001, "Set View Mode to PIP"},
  { 0x13000000, 0x13000000, "Set View Mode to Off"},
  { 0x14000000, 0x14000000, "Turn Audio On"},
  { 0x14000001, 0x14000001, "Turn Audio Off"},
  { 0x0C000000, 0x0C000064, "Set PC/TV Volume"},
  { 0x00000000, 0xFFFFFFFF, "Set PIP Location and Size"},
  { 0x1F000001, 0x1F000001, "Set PIP See Through On"},
  { 0x1F000000, 0x1F000000, "Set PIP SeeThrough Off"},
  { 0x20000001, 0x20000001, "Freeze PIP"},
  { 0x20000000, 0x20000000, "Resume After Freeze"},
  { 0x12000000, 0x12000064, "Set PC/TV Channel"},
  { 0x11000000, 0x11000000, "Set Antenna Tuner Source"},
  { 0x11000001, 0x11000001, "Set Cable Tuner Source"},
  { 0x21000001, 0x21000001, "Disable Internal Speaker"},
  { 0x21000000, 0x21000000, "Enable Internal  Speaker"},
  { 0x17000001, 0x17000001, "Keyboard Disable"},
  { 0x17000000, 0x17000000, "Keyboard Enable"},
  { 0x0D000000, 0x0D000064, "Set PC/TV Brightness"},
  { 0x0F000000, 0x0F000064, "Set PC/TV Color"},
  { 0x0E000000, 0x0E000064, "Set PC/TV Contrast"},
  { 0x10000000, 0x10006464, "Set PC/TV Tint"},
  { 0,  0,      NULL}
};

/* Appendix B.1 WRITE SINGLE STRUCTURED FIELD Command - True Transparency Write Command Major Structure */
static const value_string vals_tn5250_wssf_ttw_flag[] = {
  { 0x00, "Invalid"},
  { 0x01, "ASCII Data"},
  { 0x0000, NULL }
};


/* 15.27.3 WRITE STRUCTURED FIELD (WSF) Command - 5250 QUERY STATION STATE Command*/
static const struct true_false_string tn5250_field_wsf_qss_flag1_0 = {
  "QUERY STATION STATE Command Response",
  "QUERY STATION STATE Command"
};

static const struct true_false_string tn5250_field_wsf_qss_flag2_7 = {
  "Return all customization states",
  "Return Keystroke Buffering Control Minor Structure"
};

/* 15.27.4.1 DEFINE AUDIT WINDOW TABLE Command */
static const range_string vals_tn5250_dawt_id[] = {
  { 0x00, 0x7F, "Indicates if update of primary audit window table is necessary. If this byte matches the ID  of the existing primary audit window table, the  rest of this command is discarded" },
  { 0x80, 0xFE, "Indicates if update of secondary audit window table is necessary. If this byte matches the ID  of the existing secondary audit window table, the rest of this command is discarded" },
  { 0xFF, 0xFF, "Indicates the value of the ID bytes set by the  5494 when the table is built initially. If an ID value of X'FF' is received, both the primary  and secondary tables are initially emptied" },
  { 0,  0,      NULL}
};

static const range_string vals_tn5250_dawt_length[] = {
  { 0x00, 0x01, "Length of Table Entry is Invalid (should between 2 and 22)" },
  { 0x02, 0x16, "Length of Table Entry" },
  { 0x17, 0xFF, "Length of Table Entry is Invalid (should between 2 and 22)" },
  { 0,  0,      NULL}
};

/* 15.27.4.2 DEFINE COMMAND KEY FUNCTION Command */
static const range_string vals_tn5250_dckf_id[] = {
  { 0x00, 0x7F, "Indicates if update of primary command key function table is necessary. If this byte matches the ID  of the existing primary command key function table, the  rest of this command is discarded" },
  { 0x80, 0xFE, "Indicates if update of secondary command key function table is necessary. If this byte matches the ID  of the existing secondary command key function table, the rest of this command is discarded" },
  { 0xFF, 0xFF, "Indicates the value of the ID bytes set by the  5494 when the table is built initially. If an ID value of X'FF' is received, both the primary  and secondary tables are initially emptied" },
  { 0,  0,      NULL}
};

static const range_string vals_tn5250_dckf_length[] = {
  { 0x00, 0x02, "Length of Table Entry is Invalid (should between 3 and 82)" },
  { 0x03, 0x52, "Length of Table Entry" },
  { 0x53, 0xFF, "Length of Table Entry is Invalid (should between 3 and 82)" },
  { 0,  0,      NULL}
};

static const range_string vals_tn5250_dckf_key_code[] = {
  { 0x01, 0x18, "Command key number"},
  { 0xFB, 0xFB, "Symbols Support (Cmd + A) message"},
  { 0xFC, 0xFC, "Formatted text usage"},
  { 0xFD, 0xFD, "Stop code advance key"},
  { 0xFE, 0xFE, "Del key"},
  { 0xFF, 0xFF, "Home key"},
  { 0,  0,      NULL}
};

static const value_string vals_tn5250_dckf_function_code[] = {
  { 0x01,  "Perform general prompt"},
  { 0x02,  "Perform locate"},
  { 0x03,  "Perform copy text"},
  { 0x04,  "Perform move text"},
  { 0x05,  "Perform delete text"},
  { 0x06,  "Perform hyphenate text"},
  { 0x07,  "Display AS/400 system-defined prompt line message"},
  { 0x00, NULL }
};

/* 15.27.4.3 READ TEXT SCREEN Command */

static const range_string vals_tn5250_rts_partition[] = {
  { 0x00, 0x00, "Valid Parition ID" },
  { 0x01, 0xFF, "Invalid Partition ID" },
  { 0,  0,      NULL}
};

static const struct true_false_string tn5250_field_rts_flag1_0 = {
  "The data field is in IBM 5250 line format.The structured field command form is used. Command pending format is used. No pending data is included with the command.",
  "WARNING: Invalid Value"
};



/* 15.27.4.4 DEFINE PENDING OPERATIONS Command */

static const struct true_false_string tn5250_field_dpo_flag1_0 = {
  "Insert mode enabled",
  "Insert mode not enabled"
};

static const struct true_false_string tn5250_field_dpo_flag1_1 = {
  "Locate mode enabled",
  "Locate mode not enabled"
};

static const struct true_false_string tn5250_field_dpo_flag1_2 = {
  "AS/400 system controls text delete",
  "AS/400 system does not control text delete"
};

static const struct true_false_string tn5250_field_dpo_flag1_3 = {
  "5494 responds to the Error Reset key by locking the workstation keyboard and sending an X'4E' AID request to the AS/400 system",
  "5494 does not respond to the Error Reset key by locking the workstation keyboard and sending an X'4E' AID request to the AS/400 system"
};

static const struct true_false_string tn5250_field_dpo_flag1_4 = {
  "5494 must notify the AS/400 system on completion of a copy, move, or delete operation",
  "5494 does not need to notify the AS/400 system on completion of a copy, move, or delete operation"
};

static const struct true_false_string tn5250_field_dpo_flag1_5 = {
  "AS/400 system assisted locate function enabled",
  "AS/400 system assisted locate function not enabled"
};

static const struct true_false_string tn5250_field_dpo_flag1_6 = {
  "Tab function independent of shift status",
  "Tab function not independent of shift status"
};

static const struct true_false_string tn5250_field_dpo_flag1_7 = {
  "Insert mode is toggled by the Insert key",
  "Insert mode is toggled by the Insert key"
};

static const struct true_false_string tn5250_field_dpo_flag2_0 = {
  "Copy, move, or delete is pending",
  "Copy, move, or delete is not pending"
};


/* 15.27.4.5 DEFINE TEXT SCREEN FORMAT Command */
static const struct true_false_string tn5250_field_dtsf_flag1_0 = {
  "Column edit active",
  "Column edit is not active"
};

static const struct true_false_string tn5250_field_dtsf_flag1_1 = {
  "Data exists outside left margin",
  "No data outside left margin"
};

static const struct true_false_string tn5250_field_dtsf_flag1_2 = {
  "Data exists outside right margin",
  "No data outside right margin"
};

static const struct true_false_string tn5250_field_dtsf_flag1_3 = {
  "Cursor-sensitive scrolling active",
  "No cursor-sensitive scrolling active"
};

static const struct true_false_string tn5250_field_dtsf_flag1_4 = {
  "Fake DP mode active",
  "No fake DP mode active"
};

static const struct true_false_string tn5250_field_dtsf_flag1_5 = {
  "Do not clear screen",
  "Clear screen as normal"
};

static const struct true_false_string tn5250_field_dtsf_flag1_6 = {
  "Document orientation is right to left",
  "Document orientation is left to right"
};

static const struct true_false_string tn5250_field_dtsf_flag1_7 = {
  "Host does not have BIDI support.",
  "Host has bi-directional (BIDI) support"
};


static const struct true_false_string tn5250_field_dtsf_flag2_0 = {
  "Data stream from AS/400 system.",
  "Data stream from S/36 system."
};

static const struct true_false_string tn5250_field_dtsf_flag2_1 = {
  "The screen data does have extended attributes.",
  "The screen data in READ and WRITE commands does not have extended attributes."
};

static const struct true_false_string tn5250_field_dtsf_flag2_2 = {
  "WordPerfect/400* edit session",
  "OfficeVision/400* edit session"
};

static const struct true_false_string tn5250_field_dtsf_flag2_3 = {
  "Secondary language tables should be used.",
  "Primary language tables should be used."
};

static const range_string vals_tn5250_dtsf_flag2_vals[] = {
  { 0x00, 0x70, "Reserved"},
  { 0x80, 0x80, "System Version 2 Release 2.0"},
  { 0x90, 0x90, "System Version 2 Release 3.0"},
  { 0xA0, 0xA0, "System Version 3 Release 0.5"},
  { 0xB0, 0xB0, "System Version 3 Release 1.0"},
  { 0xC0, 0xF0, "Reserved"},
  { 0,  0,      NULL}
};

/* 15.27.4.6 DEFINE SCALE LINE Command */
static const struct true_false_string tn5250_field_dsl_flag1_0 = {
  "Suppress display of the right margin symbol",
  "Do not suppress display of the right margin symbol"
};

static const struct true_false_string tn5250_field_dsl_flag1_1 = {
  "Suppress display of the left margin symbol",
  "Do not suppress display of the left margin symbol"
};

static const struct true_false_string tn5250_field_dsl_flag1_2 = {
  "Indicate a tab stop located off the display if the absolute right margin is not defined",
  "Do not indicate a tab stop located off the display if the absolute right margin is not defined"
};

static const range_string vals_tn5250_dsl_function[] = {
  { 0x01,  0x01, "Left margin symbol"},
  { 0x02,  0x02, "Right margin symbol"},
  { 0x03,  0x03, "Left tab symbol"},
  { 0x04,  0x04, "Right tab symbol"},
  { 0x05,  0x05, "Center tab symbol"},
  { 0x06,  0x06, "Decimal align tab symbol"},
  { 0x07,  0x07, "Comma align tab symbol"},
  { 0x08,  0x08, "Colon align tab symbol"},
  { 0x09,  0x09, "Inactive tab stop symbol"},
  { 0x0A,  0x0A, "Center of margins symbol"},
  { 0x0B,  0x0B, "Paper edge symbol"},
  { 0x0C,  0x0C, "Pitch symbol"},
  { 0x0D,  0xFF, "Reserved."},
  { 0,  0,      NULL}
};


/* 15.27.4.7 WRITE TEXT SCREEN Command */
static const struct true_false_string tn5250_field_wts_flag1_0 = {
  "5250 format.",
  "3270 format (not supported on 5494)."
};

static const struct true_false_string tn5250_field_wts_flag1_1 = {
  "First line in body is an odd number of half-spacing units.",
  "First line in body is an even number of half-spacing units."
};

static const struct true_false_string tn5250_field_wts_flag1_2 = {
  "Cursor is on a line of formatted text. The 5494 displays text message defined in the Define Command Key table.",
  "Cursor is not on a line that contains formatted text. No function is performed."
};

static const struct true_false_string tn5250_field_wts_flag1_3 = {
  "Display the primary attribute at the cursor location.",
  "Do not display the primary attribute"
};

static const struct true_false_string tn5250_field_wts_flag2_6 = {
  "Lock keyboard to inhibit data input before any lines are written to screen",
  "Do not lock keyboard to inhibit data input before any lines are written to screen"
};

static const struct true_false_string tn5250_field_wts_flag3_0 = {
  "Reserved",
  "Reserved: should be 0!"
};

static const struct true_false_string tn5250_field_wts_flag3_1 = {
  "Moves cursor to home position after write operation is completed",
  "Does not move cursor to home position after write operation is completed"
};

static const struct true_false_string tn5250_field_wts_flag3_2 = {
  "Resets Cursor Blinking mode after write operation is completed",
  "Does not reset Cursor Blinking mode after write operation is completed"
};

static const struct true_false_string tn5250_field_wts_flag3_3 = {
  "Sets Cursor Blinking mode after write operation is completed",
  "Does not set Cursor Blinking mode after write operation is completed"
};

static const struct true_false_string tn5250_field_wts_flag3_4 = {
  "Resets keyboard locking function after write operation is completed",
  "Does not reset keyboard locking function after write operation is completed"
};

static const struct true_false_string tn5250_field_wts_flag3_5 = {
  "Enables audible alarm after write operation is completed",
  "Does not enable audible alarm after write operation is completed"
};

static const struct true_false_string tn5250_field_wts_flag3_6 = {
  "Resets Message Waiting indicator after write operation is completed",
  "Does not reset Message Waiting indicator after write operation is completed"
};

static const struct true_false_string tn5250_field_wts_flag3_7 = {
  "Sets Message Waiting indicator after write operation is completed",
  "Does not set Message Waiting indicator after write operation is completed"
};

/*  Structure of the WRITE TEXT SCREEN Command Line Data */
static const struct true_false_string tn5250_field_wts_cld_flag1_0 = {
  "Writes nulls to the line before writing data",
  "Does not write nulls to the line before writing data"
};

static const struct true_false_string tn5250_field_wts_cld_flag1_1 = {
  "Inhibits changes to text on this line",
  "Does not inhibit changes to text on this line"
};

static const struct true_false_string tn5250_field_wts_cld_flag1_2 = {
  "Inhibits all input functions on this line",
  "Does not inhibit all input functions on this line"
};

static const struct true_false_string tn5250_field_wts_cld_flag1_3 = {
  "Indicates that this line has been modified by the operator",
  "Indicates that this line has not been modified by the operator"
};

static const struct true_false_string tn5250_field_wts_cld_flag1_4 = {
  "Indicates that the text body has been modified",
  "Indicates that the text body has not been modified"
};

static const struct true_false_string tn5250_field_wts_cld_flag1_5 = {
  "Inhibits the word spill function on this line",
  "Does not inhibit the word spill function on this line"
};

static const struct true_false_string tn5250_field_wts_cld_flag1_6 = {
  "Spills the last word on this line to the next line",
  "Does not spill the last word on this line to the next line"
};

static const struct true_false_string tn5250_field_wts_cld_flag1_7 = {
  "Invalid Use of Reserved Field",
  "Reserved"
};

static const struct true_false_string tn5250_field_wts_cld_flag2_0 = {
  "Indicates that this row contains formatted text",
  "Indicates that this row does not contain formatted text"
};

static const struct true_false_string tn5250_field_wts_cld_flag2_1 = {
  "Indicates that a required tab character exists left of absolute left margin",
  "Indicates that a required tab character does not exist left of absolute left margin"
};

static const struct true_false_string tn5250_field_wts_cld_flag2_2 = {
  "Indicates that a tab character exists left of absolute left margin",
  "Indicates that a tab character does not exist left of absolute left margin"
};

static const struct true_false_string tn5250_field_wts_cld_flag2_3 = {
  "Indicates that a required tab character exists right of absolute right margin",
  "Indicates that a required tab character does not exist right of absolute right margin"
};

static const struct true_false_string tn5250_field_wts_cld_flag2_4 = {
  "Indicates that a tab character exists right of absolute right margin",
  "Indicates that a tab character does not exist right of absolute right margin"
};

static const struct true_false_string tn5250_field_wts_cld_flag3_0 = {
  "Indicates that line orientation is right to left",
  "Indicates that line orientation is not right to left"
};

static const struct true_false_string tn5250_field_wts_cld_flag3_1 = {
  "Indicates that 'begin reverse' exists to the left of left margin",
  "Indicates that 'begin reverse' is not to the left of left margin"
};

static const struct true_false_string tn5250_field_wts_cld_flag3_2 = {
  "Indicates that 'end reverse' exists to the right of right margin",
  "Indicates that 'end reverse' is not to the right of right margin"
};

static const struct true_false_string tn5250_field_wts_cld_flag3_3 = {
  "Invalid Use of Reserved Field",
  "Reserved"
};

static const struct true_false_string tn5250_field_wts_cld_flag3_4 = {
  "Indicates that a primary attribute exists on the line",
  "Indicates that a primary attribute does not exist on the line"
};

static const struct true_false_string tn5250_field_wts_cld_flag3_5 = {
  "Indicates that an end attribute exists one position to the right of right margin",
  "Indicates that an end attribute does not exist one position to the right of right margin"
};

static const struct true_false_string tn5250_field_wts_cld_flag3_6 = {
  "Indicates that one or more word underscore control characters (X'1D') exist on the line",
  "Indicates that one or more word underscore control characters (X'1D') do not exist on the line"
};

static const struct true_false_string tn5250_field_wts_cld_flag3_7 = {
  "Indicates that one or more half index up or half index down text attributes exist on the line",
  "Indicates that one or more half index up or half index down text attributes do not exist on the line"
};

/* 15.27.4.10 DEFINE OPERATOR ERROR MESSAGES Command */

static const range_string vals_tn5250_dorm_id[] = {
  { 0x00,  0x7F, "Indicates update of primary operator error message table is necessary."},
  { 0x80,  0xFE, "Indicates update of secondary operator error message table is necessary."},
  { 0xFF,  0xFF, "Indicates the value of the ID bytes set by the 5494 when the table is built initially."},
  { 0,  0,      NULL}
};

static const range_string vals_tn5250_dorm_length[] = {
  { 0x00, 0x02, "Length of Table Entry is Invalid (should between 3 and 82)" },
  { 0x03, 0x53, "Length of Table Entry" },
  { 0x54, 0xFF, "Length of Table Entry is Invalid (should between 3 and 82)" },
  { 0,  0,      NULL}
};

/* 15.27.4.11 DEFINE PITCH TABLE Command */

static const range_string vals_tn5250_dpt_id[] = {
  { 0x00,  0x7F, "Indicates update of primary pitch table is necessary."},
  { 0x80,  0xFE, "Indicates update of secondary pitch table is necessary."},
  { 0xFF,  0xFF, "Indicates the value of the ID bytes set by the 5494 when the table is built initially."},
  { 0,  0,      NULL}
};

/* 15.27.4.12 DEFINE FAKE DP COMMAND KEY FUNCTION Command */
#define TOP_ROW_COMMAND_KEYS    0x40
#define CORE_AREA_COMMAND_KEYS  0x80

static const range_string vals_tn5250_dfdpck_data_field[] = {
  { 0x00,  0x40, "Invalid Data Field Type"},
  { 0x40,  0x40, "Top Row Command Key Functions"},
  { 0x41,  0x79, "Invalid Data Field Type"},
  { 0x80,  0x80, "Core Area Key Command Functions"},
  { 0x81,  0xFF, "Invalid Data Field Type"},
  { 0,  0,      NULL}
};

/* Structure of the DEFINE FAKE DP COMMAND KEY FUNCTION Core Area Command Keys */

static const struct true_false_string tn5250_field_dfdpck_coreflag_0 = {
  "Typing Cmd u (begin underscore) causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_coreflag_1 = {
  "Typing Cmd j (end attribute) causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_coreflag_2 = {
  "Typing Cmd b (begin bold) causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_coreflag_3 = {
  "Typing Cmd w (word underscore) causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_coreflag_4 = {
  "Typing Cmd y (half-index-up) causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_coreflag_5 = {
  "Typing Cmd h (half-index-down) causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_coreflag_6 = {
  "Typing Cmd s (stop code) causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_coreflag_7 = {
  "Typing Cmd space (requiredspace) causes the operator error '77'.",
  ""
};

/* Structure of the DEFINE FAKE DP COMMAND KEY FUNCTION Top Row Command Keys */
static const struct true_false_string tn5250_field_dfdpck_toprowflag1_0 = {
  "Typing PFA1 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag1_1 = {
  "Typing PFA2 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag1_2 = {
  "Typing PFA3 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag1_3 = {
  "Typing PFA4 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag1_4 = {
  "Typing PFA5 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag1_5 = {
  "Typing PFA6 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag1_6 = {
  "Typing PFA7 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag1_7 = {
  "Typing PFA8 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag2_0 = {
  "Typing PFA9 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag2_1 = {
  "Typing PFA10 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag2_2 = {
  "Typing PFA11 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag2_3 = {
  "Typing PFA12 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag2_4 = {
  "Typing PFA13 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag2_5 = {
  "Typing PFA14 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag2_6 = {
  "Typing PFA15 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag2_7 = {
  "Typing PFA16 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag3_0 = {
  "Typing PFA17 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag3_1 = {
  "Typing PFA18 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag3_2 = {
  "Typing PFA19 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag3_3 = {
  "Typing PFA20 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag3_4 = {
  "Typing PFA21 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag3_5 = {
  "Typing PFA22 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag3_6 = {
  "Typing PFA23 causes the operator error '77'.",
  ""
};

static const struct true_false_string tn5250_field_dfdpck_toprowflag3_7 = {
  "Typing PFA24 causes the operator error '77'.",
  ""
};

/* 16.2.1 - AID Codes */
#define AID_CLEAR                                  0xBD
#define AID_ENTER_OR_RECORD_ADV                    0xF1
#define AID_HELP                                   0xF3
#define AID_ROLL_DOWN                              0xF4
#define AID_ROLL_UP                                0xF5
#define AID_ROLL_LEFT                              0xD9
#define AID_ROLL_RIGHT                             0xDA
#define AID_PRINT                                  0xF6
#define AID_RECORD_BACKSPACE                       0xF8
#define AID_SLP_AUTO_ENTER                         0x3F
#define AID_FORWARD_EDGE_TRIGGER_AUTO__ENTER       0x50
#define AID_PA1                                    0x6C
#define AID_PA2                                    0x6E
#define AID_PA3                                    0x6B
#define AID_CMD_01                                 0x31
#define AID_CMD_02                                 0x32
#define AID_CMD_03                                 0x33
#define AID_CMD_04                                 0x34
#define AID_CMD_05                                 0x35
#define AID_CMD_06                                 0x36
#define AID_CMD_07                                 0x37
#define AID_CMD_08                                 0x38
#define AID_CMD_09                                 0x39
#define AID_CMD_10                                 0x3A
#define AID_CMD_11                                 0x3B
#define AID_CMD_12                                 0x3C
#define AID_CMD_13                                 0xB1
#define AID_CMD_14                                 0xB2
#define AID_CMD_15                                 0xB3
#define AID_CMD_16                                 0xB4
#define AID_CMD_17                                 0xB5
#define AID_CMD_18                                 0xB6
#define AID_CMD_19                                 0xB7
#define AID_CMD_20                                 0xB8
#define AID_CMD_21                                 0xB9
#define AID_CMD_22                                 0xBA
#define AID_CMD_23                                 0xBB
#define AID_CMD_24                                 0xBC
#define AID_INBOUND_WRITE_STRUCTURED_FIELD         0x88
#define AID_PASS_THROUGH_RESPONSE                  0xFF
#define AID_IMAGE_FAX_REQUEST                      0x81
#define AID_UNKNOWN_IMAGE_FAX_FORMAT               0x82
#define AID_IMAGE_FAX_ERROR                        0x83

static const range_string vals_tn5250_attention_identification_bytes[] = {
  { AID_CLEAR                            ,  AID_CLEAR                            , "Clear"},
  { AID_ENTER_OR_RECORD_ADV              ,  AID_ENTER_OR_RECORD_ADV              , "Enter or Record Adv"},
  { AID_HELP                             ,  AID_HELP                             , "Help"},
  { AID_ROLL_DOWN                        ,  AID_ROLL_DOWN                        , "Roll Down"},
  { AID_ROLL_UP                          ,  AID_ROLL_UP                          , "Roll Up"},
  { AID_ROLL_LEFT                        ,  AID_ROLL_LEFT                        , "Roll Left"},
  { AID_ROLL_RIGHT                       ,  AID_ROLL_RIGHT                       , "Roll Right"},
  { AID_PRINT                            ,  AID_PRINT                            , "Print"},
  { AID_RECORD_BACKSPACE                 ,  AID_RECORD_BACKSPACE                 , "Record Backspace"},
  { AID_SLP_AUTO_ENTER                   ,  AID_SLP_AUTO_ENTER                   , "SLP Auto Enter"},
  { AID_FORWARD_EDGE_TRIGGER_AUTO__ENTER ,  AID_FORWARD_EDGE_TRIGGER_AUTO__ENTER , "Forward Edge Trigger Auto  Enter"},
  { AID_PA1                              ,  AID_PA1                              , "PA1"},
  { AID_PA2                              ,  AID_PA2                              , "PA2"},
  { AID_PA3                              ,  AID_PA3                              , "PA3"},
  { AID_CMD_01                           ,  AID_CMD_01                           , "Cmd 01"},
  { AID_CMD_02                           ,  AID_CMD_02                           , "Cmd 02"},
  { AID_CMD_03                           ,  AID_CMD_03                           , "Cmd 03"},
  { AID_CMD_04                           ,  AID_CMD_04                           , "Cmd 04"},
  { AID_CMD_05                           ,  AID_CMD_05                           , "Cmd 05"},
  { AID_CMD_06                           ,  AID_CMD_06                           , "Cmd 06"},
  { AID_CMD_07                           ,  AID_CMD_07                           , "Cmd 07"},
  { AID_CMD_08                           ,  AID_CMD_08                           , "Cmd 08"},
  { AID_CMD_09                           ,  AID_CMD_09                           , "Cmd 09"},
  { AID_CMD_10                           ,  AID_CMD_10                           , "Cmd 10"},
  { AID_CMD_11                           ,  AID_CMD_11                           , "Cmd 11"},
  { AID_CMD_12                           ,  AID_CMD_12                           , "Cmd 12"},
  { AID_CMD_13                           ,  AID_CMD_13                           , "Cmd 13"},
  { AID_CMD_14                           ,  AID_CMD_14                           , "Cmd 14"},
  { AID_CMD_15                           ,  AID_CMD_15                           , "Cmd 15"},
  { AID_CMD_16                           ,  AID_CMD_16                           , "Cmd 16"},
  { AID_CMD_17                           ,  AID_CMD_17                           , "Cmd 17"},
  { AID_CMD_18                           ,  AID_CMD_18                           , "Cmd 18"},
  { AID_CMD_19                           ,  AID_CMD_19                           , "Cmd 19"},
  { AID_CMD_20                           ,  AID_CMD_20                           , "Cmd 20"},
  { AID_CMD_21                           ,  AID_CMD_21                           , "Cmd 21"},
  { AID_CMD_22                           ,  AID_CMD_22                           , "Cmd 22"},
  { AID_CMD_23                           ,  AID_CMD_23                           , "Cmd 23"},
  { AID_CMD_24                           ,  AID_CMD_24                           , "Cmd 24"},
  { 0x70                                 ,  0x7F                                 , "Application Use"},
  { AID_INBOUND_WRITE_STRUCTURED_FIELD   ,  AID_INBOUND_WRITE_STRUCTURED_FIELD   , "AID Inbound Write Structured Field"},
  { AID_IMAGE_FAX_REQUEST                ,  AID_IMAGE_FAX_REQUEST                , "Image/Fax Request Aid"},
  { AID_UNKNOWN_IMAGE_FAX_FORMAT         ,  AID_UNKNOWN_IMAGE_FAX_FORMAT         , "Unknown Image/Fax Format Aid"},
  { AID_IMAGE_FAX_ERROR                  ,  AID_IMAGE_FAX_ERROR                  , " Image/Fax Error Reporting Aid"},
  { 0x00,  0x00,      NULL}
};


/*TN5250 - RFC1205 - Query Reply Fields */
static const struct true_false_string tn5250_field_qr_flag_0 = {
  "Query Reply",
  ""
};

static const value_string vals_tn5250_chc[] = {
  { 0x0001,  "Local Twinax Controller"},
  { 0x0061,  "Local ASCII Controller"},
  { 0x0101,  "SDLC/X.21/X.25 Twinax Controller (5394 emulating a 5294)"},
  { 0x0103,  "SDLC/X.21/X.25 Twinax Controller (5394)"},
  { 0x0200,  "PC DOS non-DBCS WSF"},
  { 0x0300,  "OS/2 non-DBCS WSF"},
  { 0x0400,  "PC DOS DBCS WSF"},
  { 0x0500,  "OS/2 DBCS WSF"},
  { 0x0600,  "Other WSF or any other 5250 Emulator"},
  { 0x00, NULL }
};

static const value_string vals_tn5250_dt[] = {
  { 0x01,  "5250 Display or 5250 Emulation"},
  { 0x02,  "Printer"},
  { 0x00, NULL }
};

static const value_string vals_tn5250_qr_ki[] = {
  { 0x02,  "Standard Keyboard"},
  { 0x82,  "G Keyboard"},
  { 0x00, NULL }
};

static const struct true_false_string tn5250_field_qr_flag1_1 = {
  "Row 1/Col 1 support",
  "No Row 1/Col 1 support"
};

static const struct true_false_string tn5250_field_qr_flag1_2 = {
  "Read MDT Alternate Command support",
  "No Read MDT Alternate Command support"
};

static const struct true_false_string tn5250_field_qr_flag1_3 = {
  "Display does have PA1/PA2 support",
  "Display does not have PA1/PA2 support"
};

static const struct true_false_string tn5250_field_qr_flag1_4 = {
  "Display does have PA3 support",
  "Display does not have PA3 support"
};

static const struct true_false_string tn5250_field_qr_flag1_5 = {
  "Display does have Cursor Select support",
  "Display does not have Cursor Select support"
};

static const struct true_false_string tn5250_field_qr_flag1_6 = {
  "Display does have Move Cursor Order support",
  "Display does not have Move Cursor Order support"
};

static const struct true_false_string tn5250_field_qr_flag1_7 = {
  "Read MDT Immediate Alt Command support",
  "No Read MDT Immediate Alt Command support"
};

static const value_string vals_tn5250_qr_flag2_0to3[] = {
  { 0x10,  "24 x 80 Screen Size"},
  { 0x30,  "Capable of 24 x 80 and 27 x 132"},
  { 0x00, NULL }
};

static const struct true_false_string tn5250_field_qr_flag2_4 = {
  "Light pen support",
  "No Light pen support"
};

static const struct true_false_string tn5250_field_qr_flag2_5 = {
  "Mag Stripe Reader support",
  "No Mag Stripe Reader support"
};

static const value_string vals_tn5250_qr_flag2_6to7[] = {
  { 0x00,  "Mono display"},
  { 0x01,  "5292/3179 style color, including color PCs"},
  { 0x00, NULL }
};

static const value_string vals_tn5250_qr_flag3[] = {
  { 0x00,  "No Double Byte Character Set (DBCS) capability"},
  { 0x20,  "Presentation screen DBCS capability only"},
  { 0x00, NULL }
};

static const value_string vals_tn5250_qr_flag4[] = {
  { 0x00,  "No graphics capability"},
  { 0x20,  "5292-2 style graphics"},
  { 0x00, NULL }
};


/* TN5250 Header - Data Type */
#define TN5250_5250_DATA        0x00
#define TN5250_BIND_IMAGE       0x03
#define TN5250_NVT_DATA         0x05
#define TN5250_REQUEST          0x06
#define TN5250_RESPONSE         0x02
#define TN5250_SCS_DATA         0x01
#define TN5250_SSCP_LU_DATA     0x07
#define TN5250_UNBIND           0x04

static const value_string vals_tn5250_header_data_types[] = {
  { TN5250_5250_DATA   ,  "5250_DATA"},
  { TN5250_BIND_IMAGE  ,  "BIND_IMAGE"},
  { TN5250_NVT_DATA    ,  "NVT_DATA"},
  { TN5250_REQUEST     ,  "REQUEST"},
  { TN5250_RESPONSE    ,  "RESPONSE"},
  { TN5250_SCS_DATA    ,  "SCS_DATA"},
  { TN5250_SSCP_LU_DATA,  "SSCP_LU_DATA"},
  { TN5250_UNBIND      ,  "UNBIND"},
  { 0x00, NULL }
};


/* TN5250 Header - Record Type */
#define GDS        0x12A0

static const value_string vals_tn5250_sna_record_type[] = {
  { GDS   ,  "General Data Stream"},
  { 0x00, NULL }
};

/* TN5250 Header - Operation Code */
#define NO_OPERATION                        0x00
#define INVITE_OPERATION                    0x01
#define OUTPUT_ONLY                         0x02
#define PUT_GET_OPERATION                   0x03
#define SAVE_SCREEN_OPERATION               0x04
#define RESTORE_SCREEN_OPERATION            0x05
#define READ_IMMEDIATE_OPERATION            0x06
#define RESERVED1                           0x07
#define READ_SCREEN_OPERATION               0x08
#define RESERVED2                           0x09
#define CANCEL_INVITE_OPERATION             0x0A
#define TURN_ON_MESSAGE_LIGHT               0x0B
#define TURN_OFF_MESSAGE_LIGHT              0x0C

static const value_string vals_tn5250_header_operation_code[] = {
  { NO_OPERATION            ,  "No Operation"},
  { INVITE_OPERATION        ,  "Invite Operation"},
  { OUTPUT_ONLY             ,  "Output Only"},
  { PUT_GET_OPERATION       ,  "Put or Get Operation"},
  { SAVE_SCREEN_OPERATION   ,  "Save Screen Operation"},
  { RESTORE_SCREEN_OPERATION,  "Restore Screen Operation"},
  { READ_IMMEDIATE_OPERATION,  "Read Immediate Operation"},
  { RESERVED1               ,  "Reserved"},
  { READ_SCREEN_OPERATION   ,  "Read Screen Operation"},
  { RESERVED2               ,  "Reserved"},
  { CANCEL_INVITE_OPERATION ,  "Cancel Invite Operation"},
  { TURN_ON_MESSAGE_LIGHT   ,  "Turn On Message Light"},
  { TURN_OFF_MESSAGE_LIGHT  ,  "Turn Off Message Light"},
  { 0x00, NULL }
};

/* TN5250 Header _ Response Flags - Data Type Response */
#define TN5250_POSITIVE_RESPONSE   0x00
#define TN5250_NEGATIVE_RESPONSE   0x01

static const value_string vals_tn5250_header_response_flags_response[] = {
  { TN5250_POSITIVE_RESPONSE,  "POSITIVE-RESPONSE"},
  { TN5250_NEGATIVE_RESPONSE,  "NEGATIVE-RESPONSE"},
  { 0x00, NULL }
};


static const value_string vals_tn5250_header_error_codes[] = {
  { 0x0000,  "Help key not allowed."},
  { 0x0001,  "Keyboard overrun."},
  { 0x0002,  "Incorrect scan code."},
  { 0x0003,  "Command or PF key not valid."},
  { 0x0004,  "Data not allowed in this field."},
  { 0x0005,  "Cursor in protected area of display."},
  { 0x0006,  "Key following Sys Req Key is not valid."},
  { 0x0007,  "Mandatory entry field; you must enter data."},
  { 0x0008,  "This field must have alphabetic characters."},
  { 0x0009,  "This field must have numeric characters."},
  { 0x0010,  "Only characters 0 through 9 allowed."},
  { 0x0011,  "You tried to enter data into the last position of a signed numeric field."},
  { 0x0012,  "Insert mode; no room to insert data."},
  { 0x0013,  "Insert mode; only data keys permitted."},
  { 0x0014,  "Must fill field to exit."},
  { 0x0015,  "Modulo 10 or 11 check digit error. You entered data into a self-check field, and the number you entered and the check digit do not compare."},
  { 0x0016,  "Field- not valid in this field."},
  { 0x0017,  "Mandatory-fill field; key pressed is not valid."},
  { 0x0018,  "Key used to exit this field not valid."},
  { 0x0019,  "Dup or Field Mark not permitted in this field."},
  { 0x0020,  "Function key not valid for right-adjust field."},
  { 0x0021,  "Must enter data in mandatory entry field."},
  { 0x0022,  "An AS/400 system error occurred. The status of the current field is not known. This error can occur during an insert or delete operation."},
  { 0x0023,  "Hexadecimal mode; entry not valid."},
  { 0x0024,  "Decimal field; entry not valid."},
  { 0x0026,  "Field- entry not allowed."},
  { 0x0027,  "Cannot use undefined key."},
  { 0x0029,  "Diacritic character not valid."},
  { 0x0031,  "Data buffer overflow."},
  { 0x0032,  "MSR error."},
  { 0x0033,  "MSR data not authorized."},
  { 0x0034,  "Magnetic stripe reader (MSR) data exceeds length of field."},
  { 0x0035,  "MSR error."},
  { 0x0036,  "Cursor select not allowed in field exit required state."},
  { 0x0037,  "You pressed Cursor Select in a non-selectable field."},
  { 0x0038,  "Light pen and magnetic stripe reader (MSR) not allowed."},
  { 0x0040,  "The modem or data circuit-terminating equipment (DCE) is not ready for one of the following reasons:"},
  { 0x0041,  "X.25: Idle condition has been detected. The receive line was idle for 15 or more contiguous bit-times."},
  { 0x0042,  "The receive clock signal is not being received from the modem or data circuit-terminating equipment (DCE)."},
  { 0x0043,  "The 5494 attempted to disconnect from the line, but the data set ready (DSR) signal was not deactivated by the modem or DCE."},
  { 0x0044,  "Switched lines: This error indicates that no valid data has been received for 30 seconds. The 5494 disconnected the line."},
  { 0x0045,  "X.25: The data circuit-terminating equipment (DCE) will not activate. Either a Disconnect mode (DM) or a Disconnect (DISC) command was received during the link setup sequence."},
  { 0x0046,  "X.25 or LAN: Frame reject received. The 5494 received a frame reject (FRMR) from the network, indicating that an error was detected in the last frame transmitted."},
  { 0x0047,  "X.25 or LAN: An unexpected Disconnect mode (DM) or a Disconnect (DISC) command was received while in information transfer state."},
  { 0x0048,  "X.25: An unexpected unnumbered acknowledgment (UA) frame was received."},
  { 0x0049,  "LAN: A set asynchronous balance mode extended (SABME) was received while the 5494 was in information transfer state."},
  { 0x0050,  "Error in ready-for-sending (RFS) signal, also known as the clear-to-send (CTS) signal, received from the modem or data circuit-terminating equipment (DCE). This error is posted when one of the following has occurred:"},
  { 0x0051,  "The transmit clock from the modem or data circuit-terminating equipment (DCE) failed during a transmit operation."},
  { 0x0052,  "The link adapter hardware failed to complete a transmit operation within 30 seconds, but no transmit clock or other modem or data circuit-terminating equipment (DCE) signal failure was detected."},
  { 0x0053,  "X.25: The retry count has expired. No acknowledgment of a transmission was received within the allowed timeout. Timeout retry count (N2) and retry interval (T1) are specified in the 5494 configuration."},
  { 0x0054,  "Frame reject (FRMR) sent. The 5494 sent a link-level FRMR response to the AS/400 system after receiving a data link control (DLC) or link access protocol balanced (LAPB) command that is not valid. Sense bytes S1, S2, and S3 preserve the contents of the FRMR I-field."},
  { 0x0055,  "The 5494 ran a cable wrap test and determined that the communication cable is not attached to the 5494."},
  { 0x0056,  "The link between the AS/400 system and the 5494 was lost. A bridge failure occurred, the AS/400 system has varied off line, or a node in an SNA Subarea network has failed."},
  { 0x0060,  "Ideographic support SRC: You attempted to enter alphanumeric data into a field that accepts only double-byte data characters."},
  { 0x0061,  "Ideographic support SRC: You attempted to enter a double-byte character into a field that accepts only alphanumeric data."},
  { 0x0062,  "You attempted to change the data type, but the cursor is not in an open field or in the first position of an ideographic either field."},
  { 0x0063,  "You entered an ideographic character that is not valid while operating in Alternate Entry mode."},
  { 0x0064,  "You pressed a key that is not valid for the current keyboard mode."},
  { 0x0065,  "The cursor is positioned in a column reserved for shift-out or shift-in characters."},
  { 0x0066,  "Repeat key not valid. The cursor is positioned under a shift character or attribute character, or at the first valid entry character position of an input field. Only data characters can be repeated at these positions."},
  { 0x0067,  "The workstation extension character RAM is full. Any additional extension characters display as special default characters."},
  { 0x0068,  "The output data stream to the 5494 is not valid for extension characters. Any additional extension characters display as special default characters."},
  { 0x0069,  "Ideographic support SRC: The output data stream to the 5494 contains extension characters that are not valid or are undefined. Any additional extension characters display as special default characters."},
  { 0x0070,  "An error occurred during the word spill function or the carriage return function."},
  { 0x0071,  "You attempted a start copy, move, or delete text operation while one of the previous operations was already in progress."},
  { 0x0072,  "The key pressed is not valid when the cursor is in the current position."},
  { 0x0073,  "An attempt was made to delete or replace an instruction or format change when the general prompt function was not active."},
  { 0x0074,  "A key was pressed that is not valid when using the general prompt function."},
  { 0x0075,  "The find function failed to find the keyed characters."},
  { 0x0076,  "The insert function failed because the AS/400 system has not processed the text on the screen."},
  { 0x0077,  "You either pressed a function key that is not valid at this time or tried to use a 5250 keyboard function while in word-processing mode."},
  { 0x0078,  "The required scale line is not defined for your workstation. There is an error in the application program."},
  { 0x0081,  "Too many workstations are attached to the 5494. The 5494 with LAN adapter installed allows a maximum of 80 devices."},
  { 0x0082,  "Keyboard function is not valid within a selection field. These invalid functions include Dup, Erase EOF, and Field Mark."},
  { 0x0083,  "A selection character is not valid. The numeric or mnemonic character you entered is not associated with any of the choices defined within the current selection field."},
  { 0x0084,  "An attempt has been made to select an unavailable selection field."},
  { 0x0087,  "X.25: A flow control entry error has occurred. The 5494 configuration settings for Flow Control Negotiation and Manual Options Allowed are not compatible. If the configuration setting for Flow Control Negotiation is permitted, then Manual Options must be allowed."},
  { 0x0089,  "One or more fields required for the operation of the 5494 are blank. When you press Enter, the 5494 checks for blank fields and moves the cursor to the first blank."},
  { 0x008A,  "One or more fields contain an embedded blank. When you press Enter, the 5494 checks for embedded blanks and moves the cursor to the first embedded blank."},
  { 0x008B,  "Too many different keyboard codes have been used. A maximum of 4 different keyboard codes can be selected (the master country and 3 others)."},
  { 0x008D,  "Printer port and station values are not valid. Valid ports for the Twinaxial Expansion Kit are 4-7. Valid stations are 0-7."},
  { 0x008E,  "One or more fields contain an insufficient number of characters. The cursor is positioned in the field that contains an insufficient number of characters."},
  { 0x008F,  "One or more fields contain a value that is outside the valid range. The cursor is placed under the first character of the field with a value that is out of range."},
  { 0x0091,  "Reverse and Close keys are not supported in a Word Wrap entry field."},
  { 0x0092,  "The reverse key is not supported on a display which is configured for shared addressing."},
  { 0x0097,  "A test request function is not supported by the AS/400 system."},
  { 0x0098,  "Undefined hardware error."},
  { 0x0099,  "A key requiring AS/400 system action was pressed, but one of the following has occurred:"},
  { 0x009A,  "An invalid password has been entered three times in an attempt to access concurrent diagnostics from a PWS."},
  { 0x0170,  "A problem with an attached workstation has been detected. The workstation failed to detect the end of a printer definition table (PDT). Sense data is 00."},
  { 0x0172,  "A problem with an attached workstation has been detected. The workstation detected invalid data in a printer definition table (PDT) sent to it from the AS/400 system. The sense data is 00ccxxyyyyyyyy, where cc is the command code of the definition containing invalid data, xx, is the offset from the command to invalid data in bytes, and yyyyyyyy is additional error data."},
  { 0x0173,  "A problem with an attached workstation has been detected. The workstation received a printer definition table (PDT) that was larger than its maximum size. Sense data is 00xxxxyyyy, where xxxx is the workstation's maximum PDT size, and yyyy was the size of the PDT sent to the display by the AS/400 system."},
  { 0x0176,  "A problem with an attached workstation has been detected. The workstation received a microcode correction file from the AS/400 system that was in error. The sense data defines the error as follows:"},
  { 0x0177,  "A problem with an attached workstation has been detected. The workstation received a font file from the AS/400 system that was in error. Sense data defines the error as follows:"},
  { 0x0000, NULL }
};

static const range_string vals_tn5250_reserved[] = {
  { 0x00,  0x00, "Reserved"},
  { 0x01,  0xFE, "Invalid Use of Reserved Field"},
  { 0,  0,      NULL}
};


static int proto_tn5250 = -1;
static int hf_tn5250_aid = -1;
static int hf_tn5250_attn_key = -1;
static int hf_tn5250_attribute_type = -1;
static int hf_tn5250_buffer_x = -1;
static int hf_tn5250_buffer_y = -1;
static int hf_tn5250_command_code = -1;
static int hf_tn5250_ctp_lsid = -1;
static int hf_tn5250_ctp_mlpp = -1;
static int hf_tn5250_cua_parm = -1;
static int hf_tn5250_dawt_char = -1;
static int hf_tn5250_dawt_id = -1;
static int hf_tn5250_dawt_length = -1;
static int hf_tn5250_dawt_message = -1;
static int hf_tn5250_dckf_function_code = -1;
static int hf_tn5250_dckf_id = -1;
static int hf_tn5250_dckf_key_code = -1;
static int hf_tn5250_dckf_length = -1;
static int hf_tn5250_dckf_prompt_text = -1;
static int hf_tn5250_dfdpck_coreflag = -1;
static int hf_tn5250_dfdpck_coreflag_0 = -1;
static int hf_tn5250_dfdpck_coreflag_1 = -1;
static int hf_tn5250_dfdpck_coreflag_2 = -1;
static int hf_tn5250_dfdpck_coreflag_3 = -1;
static int hf_tn5250_dfdpck_coreflag_4 = -1;
static int hf_tn5250_dfdpck_coreflag_5 = -1;
static int hf_tn5250_dfdpck_coreflag_6 = -1;
static int hf_tn5250_dfdpck_coreflag_7 = -1;
static int hf_tn5250_dfdpck_data_field = -1;
static int hf_tn5250_dfdpck_partition = -1;
static int hf_tn5250_dfdpck_toprowflag1 = -1;
static int hf_tn5250_dfdpck_toprowflag1_0 = -1;
static int hf_tn5250_dfdpck_toprowflag1_1 = -1;
static int hf_tn5250_dfdpck_toprowflag1_2 = -1;
static int hf_tn5250_dfdpck_toprowflag1_3 = -1;
static int hf_tn5250_dfdpck_toprowflag1_4 = -1;
static int hf_tn5250_dfdpck_toprowflag1_5 = -1;
static int hf_tn5250_dfdpck_toprowflag1_6 = -1;
static int hf_tn5250_dfdpck_toprowflag1_7 = -1;
static int hf_tn5250_dfdpck_toprowflag2 = -1;
static int hf_tn5250_dfdpck_toprowflag2_0 = -1;
static int hf_tn5250_dfdpck_toprowflag2_1 = -1;
static int hf_tn5250_dfdpck_toprowflag2_2 = -1;
static int hf_tn5250_dfdpck_toprowflag2_3 = -1;
static int hf_tn5250_dfdpck_toprowflag2_4 = -1;
static int hf_tn5250_dfdpck_toprowflag2_5 = -1;
static int hf_tn5250_dfdpck_toprowflag2_6 = -1;
static int hf_tn5250_dfdpck_toprowflag2_7 = -1;
static int hf_tn5250_dfdpck_toprowflag3 = -1;
static int hf_tn5250_dfdpck_toprowflag3_0 = -1;
static int hf_tn5250_dfdpck_toprowflag3_1 = -1;
static int hf_tn5250_dfdpck_toprowflag3_2 = -1;
static int hf_tn5250_dfdpck_toprowflag3_3 = -1;
static int hf_tn5250_dfdpck_toprowflag3_4 = -1;
static int hf_tn5250_dfdpck_toprowflag3_5 = -1;
static int hf_tn5250_dfdpck_toprowflag3_6 = -1;
static int hf_tn5250_dfdpck_toprowflag3_7 = -1;
static int hf_tn5250_dorm_ec = -1;
static int hf_tn5250_dorm_id = -1;
static int hf_tn5250_dorm_length = -1;
static int hf_tn5250_dorm_mt = -1;
static int hf_tn5250_dpo_displace_characters = -1;
static int hf_tn5250_dpo_flag1 = -1;
static int hf_tn5250_dpo_flag1_0 = -1;
static int hf_tn5250_dpo_flag1_1 = -1;
static int hf_tn5250_dpo_flag1_2 = -1;
static int hf_tn5250_dpo_flag1_3 = -1;
static int hf_tn5250_dpo_flag1_4 = -1;
static int hf_tn5250_dpo_flag1_5 = -1;
static int hf_tn5250_dpo_flag1_6 = -1;
static int hf_tn5250_dpo_flag1_7 = -1;
static int hf_tn5250_dpo_flag2 = -1;
static int hf_tn5250_dpo_flag2_0 = -1;
static int hf_tn5250_dpo_flag2_reserved = -1;
static int hf_tn5250_dpo_partition = -1;
static int hf_tn5250_dpo_start_location_col = -1;
static int hf_tn5250_dpo_start_location_row = -1;
static int hf_tn5250_dpt_ec = -1;
static int hf_tn5250_dpt_id = -1;
static int hf_tn5250_ds_output_error = -1;
static int hf_tn5250_dsc_ev = -1;
static int hf_tn5250_dsc_partition = -1;
static int hf_tn5250_dsc_sk = -1;
static int hf_tn5250_dsl_flag1 = -1;
static int hf_tn5250_dsl_flag1_0 = -1;
static int hf_tn5250_dsl_flag1_1 = -1;
static int hf_tn5250_dsl_flag1_2 = -1;
static int hf_tn5250_dsl_flag1_reserved = -1;
static int hf_tn5250_dsl_function = -1;
static int hf_tn5250_dsl_id = -1;
static int hf_tn5250_dsl_location = -1;
static int hf_tn5250_dsl_offset = -1;
static int hf_tn5250_dsl_partition = -1;
static int hf_tn5250_dsl_rtl_offset = -1;
static int hf_tn5250_dtsf_first_line = -1;
static int hf_tn5250_dtsf_flag1 = -1;
static int hf_tn5250_dtsf_flag1_0 = -1;
static int hf_tn5250_dtsf_flag1_1 = -1;
static int hf_tn5250_dtsf_flag1_2 = -1;
static int hf_tn5250_dtsf_flag1_3 = -1;
static int hf_tn5250_dtsf_flag1_4 = -1;
static int hf_tn5250_dtsf_flag1_5 = -1;
static int hf_tn5250_dtsf_flag1_6 = -1;
static int hf_tn5250_dtsf_flag1_7 = -1;
static int hf_tn5250_dtsf_flag2 = -1;
static int hf_tn5250_dtsf_flag2_0 = -1;
static int hf_tn5250_dtsf_flag2_1 = -1;
static int hf_tn5250_dtsf_flag2_2 = -1;
static int hf_tn5250_dtsf_flag2_3 = -1;
static int hf_tn5250_dtsf_flag2_4to7 = -1;
static int hf_tn5250_dtsf_line_cmd_field_size = -1;
static int hf_tn5250_dtsf_location_of_pitch = -1;
static int hf_tn5250_dtsf_partition = -1;
static int hf_tn5250_dtsf_text_body_height = -1;
static int hf_tn5250_dtsf_text_body_width = -1;
static int hf_tn5250_soh_err = -1;
static int hf_tn5250_error_code = -1;
static int hf_tn5250_error_state = -1;
static int hf_tn5250_escape_code = -1;
static int hf_tn5250_fa_color = -1;
static int hf_tn5250_fcw = -1;
static int hf_tn5250_ffw = -1;
static int hf_tn5250_ffw_adjust = -1;
static int hf_tn5250_ffw_auto = -1;
static int hf_tn5250_ffw_bypass = -1;
static int hf_tn5250_ffw_dup = -1;
static int hf_tn5250_ffw_fer = -1;
static int hf_tn5250_ffw_id = -1;
static int hf_tn5250_ffw_mdt = -1;
static int hf_tn5250_ffw_me = -1;
static int hf_tn5250_ffw_monocase = -1;
static int hf_tn5250_ffw_res = -1;
static int hf_tn5250_ffw_shift = -1;
static int hf_tn5250_field_data = -1;
static int hf_tn5250_foreground_color_attr = -1;
static int hf_tn5250_header_flags = -1;
static int hf_tn5250_ideographic_attr = -1;
static int hf_tn5250_length = -1;
static int hf_tn5250_length_twobyte = -1;
static int hf_tn5250_logical_record_length = -1;
static int hf_tn5250_operation_code = -1;
static int hf_tn5250_order_code = -1;
static int hf_tn5250_repeated_character = -1;
static int hf_tn5250_reserved = -1;
static int hf_tn5250_roll_bottom_line = -1;
static int hf_tn5250_roll_flag1 = -1;
static int hf_tn5250_roll_flag1_0 = -1;
static int hf_tn5250_roll_flag1_lines = -1;
static int hf_tn5250_roll_flag1_reserved = -1;
static int hf_tn5250_roll_top_line = -1;
static int hf_tn5250_rts_flag1 = -1;
static int hf_tn5250_rts_flag1_0 = -1;
static int hf_tn5250_rts_flag1_reserved = -1;
static int hf_tn5250_rts_partition = -1;
static int hf_tn5250_sf_attr_flag = -1;
static int hf_tn5250_sf_class = -1;
static int hf_tn5250_fa = -1;
static int hf_tn5250_sf_length = -1;
static int hf_tn5250_sf_type = -1;
static int hf_tn5250_sna_record_type = -1;
static int hf_tn5250_soh_cursor_direction = -1;
static int hf_tn5250_soh_flags = -1;
static int hf_tn5250_soh_input_capable_only = -1;
static int hf_tn5250_soh_pf1 = -1;
static int hf_tn5250_soh_pf10 = -1;
static int hf_tn5250_soh_pf11 = -1;
static int hf_tn5250_soh_pf12 = -1;
static int hf_tn5250_soh_pf13 = -1;
static int hf_tn5250_soh_pf14 = -1;
static int hf_tn5250_soh_pf15 = -1;
static int hf_tn5250_soh_pf16 = -1;
static int hf_tn5250_soh_pf16to9 = -1;
static int hf_tn5250_soh_pf17 = -1;
static int hf_tn5250_soh_pf18 = -1;
static int hf_tn5250_soh_pf19 = -1;
static int hf_tn5250_soh_pf2 = -1;
static int hf_tn5250_soh_pf20 = -1;
static int hf_tn5250_soh_pf21 = -1;
static int hf_tn5250_soh_pf22 = -1;
static int hf_tn5250_soh_pf23 = -1;
static int hf_tn5250_soh_pf24 = -1;
static int hf_tn5250_soh_pf24to17 = -1;
static int hf_tn5250_soh_pf3 = -1;
static int hf_tn5250_soh_pf4 = -1;
static int hf_tn5250_soh_pf5 = -1;
static int hf_tn5250_soh_pf6 = -1;
static int hf_tn5250_soh_pf7 = -1;
static int hf_tn5250_soh_pf8 = -1;
static int hf_tn5250_soh_pf8to1 = -1;
static int hf_tn5250_soh_pf9 = -1;
static int hf_tn5250_soh_resq = -1;
static int hf_tn5250_soh_screen_reverse = -1;
static int hf_tn5250_sps_flag1 = -1;
static int hf_tn5250_sps_flag1_0 = -1;
static int hf_tn5250_sps_flag1_reserved = -1;
static int hf_tn5250_sps_left_column = -1;
static int hf_tn5250_sps_top_row = -1;
static int hf_tn5250_sps_window_depth = -1;
static int hf_tn5250_sps_window_width = -1;
static int hf_tn5250_sys_request_key = -1;
static int hf_tn5250_test_request_key = -1;
static int hf_tn5250_unknown_data = -1;
static int hf_tn5250_variable_record_length = -1;
static int hf_tn5250_wdsf_cw_bp_flag1_reserved = -1;
static int hf_tn5250_wdsf_cw_tf_flag_reserved = -1;
static int hf_tn5250_wdsf_deg_flag2_reserved = -1;
static int hf_tn5250_wdsf_deg_ms_flag1_reserved = -1;
static int hf_tn5250_wdsf_ds_ci_flag1_reserved = -1;
static int hf_tn5250_wdsf_ds_cpda_flag1_reserved = -1;
static int hf_tn5250_wdsf_ds_ct_flag3_reserved = -1;
static int hf_tn5250_wdsf_ds_gdc_reserved = -1;
static int hf_tn5250_wdsf_ds_nws_reserved = -1;
static int hf_tn5250_wdsf_ds_sbi_flag1_reserved = -1;
static int hf_tn5250_wdsf_dsb_flag1_reserved = -1;
static int hf_tn5250_wdsf_pmb_flag1_reserved = -1;
static int hf_tn5250_wdsf_wdf_flag1_reserved = -1;
static int hf_tn5250_wdsf_cgl_partition = -1;
static int hf_tn5250_wdsf_cgl_rectangle_height = -1;
static int hf_tn5250_wdsf_cgl_rectangle_width = -1;
static int hf_tn5250_wdsf_cgl_start_column = -1;
static int hf_tn5250_wdsf_cgl_start_row = -1;
static int hf_tn5250_wdsf_cw_bp_bbc = -1;
static int hf_tn5250_wdsf_cw_bp_cba = -1;
static int hf_tn5250_wdsf_cw_bp_flag1 = -1;
static int hf_tn5250_wdsf_cw_bp_flag1_1 = -1;
static int hf_tn5250_wdsf_cw_bp_lbc = -1;
static int hf_tn5250_wdsf_cw_bp_llbc = -1;
static int hf_tn5250_wdsf_cw_bp_lrbc = -1;
static int hf_tn5250_wdsf_cw_bp_mba = -1;
static int hf_tn5250_wdsf_cw_bp_rbc = -1;
static int hf_tn5250_wdsf_cw_bp_tbc = -1;
static int hf_tn5250_wdsf_cw_bp_ulbc = -1;
static int hf_tn5250_wdsf_cw_bp_urbc = -1;
static int hf_tn5250_wdsf_cw_flag1 = -1;
static int hf_tn5250_wdsf_cw_flag1_1 = -1;
static int hf_tn5250_wdsf_cw_flag1_2 = -1;
static int hf_tn5250_wdsf_cw_flag1_reserved = -1;
static int hf_tn5250_wdsf_cw_minor_type = -1;
static int hf_tn5250_wdsf_cw_tf_cba = -1;
static int hf_tn5250_wdsf_cw_tf_flag = -1;
static int hf_tn5250_wdsf_cw_tf_flag_1 = -1;
static int hf_tn5250_wdsf_cw_tf_flag_orientation = -1;
static int hf_tn5250_wdsf_cw_tf_mba = -1;
static int hf_tn5250_wdsf_cw_tf_text = -1;
static int hf_tn5250_wdsf_cw_wd = -1;
static int hf_tn5250_wdsf_cw_ww = -1;
static int hf_tn5250_wdsf_deg_default_color = -1;
static int hf_tn5250_wdsf_deg_default_line = -1;
static int hf_tn5250_wdsf_deg_flag1 = -1;
static int hf_tn5250_wdsf_deg_flag1_0 = -1;
static int hf_tn5250_wdsf_deg_flag1_reserved = -1;
static int hf_tn5250_wdsf_deg_flag2 = -1;
static int hf_tn5250_wdsf_deg_flag2_0 = -1;
static int hf_tn5250_wdsf_deg_minor_type = -1;
static int hf_tn5250_wdsf_deg_ms_default_color = -1;
static int hf_tn5250_wdsf_deg_ms_flag1 = -1;
static int hf_tn5250_wdsf_deg_ms_flag1_0 = -1;
static int hf_tn5250_wdsf_deg_ms_horizontal_dimension = -1;
static int hf_tn5250_wdsf_deg_ms_line_interval = -1;
static int hf_tn5250_wdsf_deg_ms_line_repeat = -1;
static int hf_tn5250_wdsf_deg_ms_start_column = -1;
static int hf_tn5250_wdsf_deg_ms_start_row = -1;
static int hf_tn5250_wdsf_deg_ms_vertical_dimension = -1;
static int hf_tn5250_wdsf_deg_partition = -1;
static int hf_tn5250_wdsf_ds_cancel_aid = -1;
static int hf_tn5250_wdsf_ds_ci_first_choice = -1;
static int hf_tn5250_wdsf_ds_ci_flag1 = -1;
static int hf_tn5250_wdsf_ds_ci_flag1_0 = -1;
static int hf_tn5250_wdsf_ds_ci_left_push = -1;
static int hf_tn5250_wdsf_ds_ci_right_push = -1;
static int hf_tn5250_wdsf_ds_columns = -1;
static int hf_tn5250_wdsf_ds_country_sel = -1;
static int hf_tn5250_wdsf_ds_cpda_color_avail = -1;
static int hf_tn5250_wdsf_ds_cpda_color_indicator = -1;
static int hf_tn5250_wdsf_ds_cpda_color_sel_avail = -1;
static int hf_tn5250_wdsf_ds_cpda_color_sel_selected = -1;
static int hf_tn5250_wdsf_ds_cpda_color_sel_unavail = -1;
static int hf_tn5250_wdsf_ds_cpda_color_selected = -1;
static int hf_tn5250_wdsf_ds_cpda_color_unavail = -1;
static int hf_tn5250_wdsf_ds_cpda_color_unavail_indicator = -1;
static int hf_tn5250_wdsf_ds_cpda_flag1 = -1;
static int hf_tn5250_wdsf_ds_cpda_flag1_0 = -1;
static int hf_tn5250_wdsf_ds_cpda_flag1_1 = -1;
static int hf_tn5250_wdsf_ds_cpda_flag1_2 = -1;
static int hf_tn5250_wdsf_ds_cpda_monochrome_avail = -1;
static int hf_tn5250_wdsf_ds_cpda_monochrome_indicator = -1;
static int hf_tn5250_wdsf_ds_cpda_monochrome_sel_avail = -1;
static int hf_tn5250_wdsf_ds_cpda_monochrome_sel_selected = -1;
static int hf_tn5250_wdsf_ds_cpda_monochrome_sel_unavail = -1;
static int hf_tn5250_wdsf_ds_cpda_monochrome_selected = -1;
static int hf_tn5250_wdsf_ds_cpda_monochrome_unavail = -1;
static int hf_tn5250_wdsf_ds_cpda_monochrome_unavail_indicator = -1;
static int hf_tn5250_wdsf_ds_ct_aid = -1;
static int hf_tn5250_wdsf_ds_ct_flag1 = -1;
static int hf_tn5250_wdsf_ds_ct_flag1_2 = -1;
static int hf_tn5250_wdsf_ds_ct_flag1_3 = -1;
static int hf_tn5250_wdsf_ds_ct_flag1_4 = -1;
static int hf_tn5250_wdsf_ds_ct_flag1_5 = -1;
static int hf_tn5250_wdsf_ds_ct_flag1_choice_state = -1;
static int hf_tn5250_wdsf_ds_ct_flag1_numeric_selection = -1;
static int hf_tn5250_wdsf_ds_ct_flag2 = -1;
static int hf_tn5250_wdsf_ds_ct_flag2_0 = -1;
static int hf_tn5250_wdsf_ds_ct_flag2_1 = -1;
static int hf_tn5250_wdsf_ds_ct_flag2_2 = -1;
static int hf_tn5250_wdsf_ds_ct_flag2_3 = -1;
static int hf_tn5250_wdsf_ds_ct_flag2_4 = -1;
static int hf_tn5250_wdsf_ds_ct_flag2_5 = -1;
static int hf_tn5250_wdsf_ds_ct_flag2_6 = -1;
static int hf_tn5250_wdsf_ds_ct_flag2_7 = -1;
static int hf_tn5250_wdsf_ds_ct_flag3 = -1;
static int hf_tn5250_wdsf_ds_ct_flag3_0 = -1;
static int hf_tn5250_wdsf_ds_ct_flag3_1 = -1;
static int hf_tn5250_wdsf_ds_ct_flag3_2 = -1;
static int hf_tn5250_wdsf_ds_ct_mnemonic_offset = -1;
static int hf_tn5250_wdsf_ds_ct_numeric_onebyte = -1;
static int hf_tn5250_wdsf_ds_ct_numeric_twobyte = -1;
static int hf_tn5250_wdsf_ds_ct_text = -1;
static int hf_tn5250_wdsf_ds_flag1 = -1;
static int hf_tn5250_wdsf_ds_flag1_1 = -1;
static int hf_tn5250_wdsf_ds_flag1_2 = -1;
static int hf_tn5250_wdsf_ds_flag1_auto_enter = -1;
static int hf_tn5250_wdsf_ds_flag1_mouse_characteristics = -1;
static int hf_tn5250_wdsf_ds_flag1_reserved = -1;
static int hf_tn5250_wdsf_ds_flag2 = -1;
static int hf_tn5250_wdsf_ds_flag2_1 = -1;
static int hf_tn5250_wdsf_ds_flag2_2 = -1;
static int hf_tn5250_wdsf_ds_flag2_3 = -1;
static int hf_tn5250_wdsf_ds_flag2_4 = -1;
static int hf_tn5250_wdsf_ds_flag2_5 = -1;
static int hf_tn5250_wdsf_ds_flag2_6 = -1;
static int hf_tn5250_wdsf_ds_flag2_reserved = -1;
static int hf_tn5250_wdsf_ds_flag3 = -1;
static int hf_tn5250_wdsf_ds_flag3_1 = -1;
static int hf_tn5250_wdsf_ds_flag3_reserved = -1;
static int hf_tn5250_wdsf_ds_gdc = -1;
static int hf_tn5250_wdsf_ds_gdc_indicators = -1;
static int hf_tn5250_wdsf_ds_gdc_selection_techniques = -1;
static int hf_tn5250_wdsf_ds_mbs_color_sep = -1;
static int hf_tn5250_wdsf_ds_mbs_end_column = -1;
static int hf_tn5250_wdsf_ds_mbs_flag = -1;
static int hf_tn5250_wdsf_ds_mbs_flag_0 = -1;
static int hf_tn5250_wdsf_ds_mbs_flag_1 = -1;
static int hf_tn5250_wdsf_ds_mbs_flag_reserved = -1;
static int hf_tn5250_wdsf_ds_mbs_monochrome_sep = -1;
static int hf_tn5250_wdsf_ds_mbs_sep_char = -1;
static int hf_tn5250_wdsf_ds_mbs_start_column = -1;
static int hf_tn5250_wdsf_ds_minor_type = -1;
static int hf_tn5250_wdsf_ds_numeric_sep = -1;
static int hf_tn5250_wdsf_ds_nws = -1;
static int hf_tn5250_wdsf_ds_nws_indicators = -1;
static int hf_tn5250_wdsf_ds_nws_selection_techniques = -1;
static int hf_tn5250_wdsf_ds_nws_wout = -1;
static int hf_tn5250_wdsf_ds_padding = -1;
static int hf_tn5250_wdsf_ds_rows = -1;
static int hf_tn5250_wdsf_ds_sbi_bottom_character = -1;
static int hf_tn5250_wdsf_ds_sbi_color_top_highlight = -1;
static int hf_tn5250_wdsf_ds_sbi_color_top_highlight_shaft = -1;
static int hf_tn5250_wdsf_ds_sbi_empty_character = -1;
static int hf_tn5250_wdsf_ds_sbi_flag1 = -1;
static int hf_tn5250_wdsf_ds_sbi_flag1_0 = -1;
static int hf_tn5250_wdsf_ds_sbi_monochrome_top_highlight = -1;
static int hf_tn5250_wdsf_ds_sbi_monochrome_top_highlight_shaft = -1;
static int hf_tn5250_wdsf_ds_sbi_slider_character = -1;
static int hf_tn5250_wdsf_ds_sbi_top_character = -1;
static int hf_tn5250_wdsf_ds_sliderpos = -1;
static int hf_tn5250_wdsf_ds_textsize = -1;
static int hf_tn5250_wdsf_ds_totalrows = -1;
static int hf_tn5250_wdsf_ds_type = -1;
static int hf_tn5250_wdsf_dsb_flag1 = -1;
static int hf_tn5250_wdsf_dsb_flag1_0 = -1;
static int hf_tn5250_wdsf_dsb_flag1_1 = -1;
static int hf_tn5250_wdsf_dsb_flag1_7 = -1;
static int hf_tn5250_wdsf_pmb_first_mouse_event = -1;
static int hf_tn5250_wdsf_pmb_flag1 = -1;
static int hf_tn5250_wdsf_pmb_flag1_0 = -1;
static int hf_tn5250_wdsf_pmb_flag1_1 = -1;
static int hf_tn5250_wdsf_pmb_flag1_2 = -1;
static int hf_tn5250_wdsf_pmb_flag1_3 = -1;
static int hf_tn5250_wdsf_pmb_second_mouse_event = -1;
static int hf_tn5250_wdsf_ragc_flag1 = -1;
static int hf_tn5250_wdsf_ragc_flag1_0 = -1;
static int hf_tn5250_wdsf_ragc_reserved = -1;
static int hf_tn5250_wdsf_rgw_flag1 = -1;
static int hf_tn5250_wdsf_rgw_flag1_0 = -1;
static int hf_tn5250_wdsf_rgw_flag1_1 = -1;
static int hf_tn5250_wdsf_rgw_reserved = -1;
static int hf_tn5250_wdsf_sbi_rowscols = -1;
static int hf_tn5250_wdsf_sbi_sliderpos = -1;
static int hf_tn5250_wdsf_sbi_total_scroll = -1;
static int hf_tn5250_wdsf_wdf_flag1 = -1;
static int hf_tn5250_wdsf_wdf_flag1_0 = -1;
static int hf_tn5250_wea_prim_attr = -1;
static int hf_tn5250_wea_prim_attr_blink = -1;
static int hf_tn5250_wea_prim_attr_col = -1;
static int hf_tn5250_wea_prim_attr_flag = -1;
static int hf_tn5250_wea_prim_attr_int = -1;
static int hf_tn5250_wea_prim_attr_rev = -1;
static int hf_tn5250_wea_prim_attr_und = -1;
static int hf_tn5250_wectw_end_column = -1;
static int hf_tn5250_wectw_start_column = -1;
static int hf_tn5250_wsf_qss_flag1 = -1;
static int hf_tn5250_wsf_qss_flag1_0 = -1;
static int hf_tn5250_wsf_qss_flag1_reserved = -1;
static int hf_tn5250_wsf_qss_flag2 = -1;
static int hf_tn5250_wsf_qss_flag2_7 = -1;
static int hf_tn5250_wsf_qss_flag2_reserved = -1;
static int hf_tn5250_wssf_cc_flag1 = -1;
static int hf_tn5250_wssf_cc_flag1_7 = -1;
static int hf_tn5250_wssf_cc_flag1_reserved = -1;
static int hf_tn5250_wssf_flag1 = -1;
static int hf_tn5250_wssf_flag2 = -1;
static int hf_tn5250_wssf_flag2_0 = -1;
static int hf_tn5250_wssf_flag2_1 = -1;
static int hf_tn5250_wssf_flag2_2 = -1;
static int hf_tn5250_wssf_flag2_3 = -1;
static int hf_tn5250_wssf_flag2_4 = -1;
static int hf_tn5250_wssf_flag2_5 = -1;
static int hf_tn5250_wssf_flag2_6 = -1;
static int hf_tn5250_wssf_flag2_7 = -1;
static int hf_tn5250_wssf_ifc_background_color = -1;
static int hf_tn5250_wssf_ifc_flag1 = -1;
static int hf_tn5250_wssf_ifc_flag1_0 = -1;
static int hf_tn5250_wssf_ifc_flag1_1to3 = -1;
static int hf_tn5250_wssf_ifc_flag1_4 = -1;
static int hf_tn5250_wssf_ifc_flag1_5 = -1;
static int hf_tn5250_wssf_ifc_flag1_6 = -1;
static int hf_tn5250_wssf_ifc_flag1_7 = -1;
static int hf_tn5250_wssf_ifc_flag2 = -1;
static int hf_tn5250_wssf_ifc_flag2_0 = -1;
static int hf_tn5250_wssf_ifc_flag2_1 = -1;
static int hf_tn5250_wssf_ifc_flag2_7 = -1;
static int hf_tn5250_wssf_ifc_flag2_reserved = -1;
static int hf_tn5250_wssf_ifc_foreground_color = -1;
static int hf_tn5250_wssf_ifc_image_format = -1;
static int hf_tn5250_wssf_ifc_imagefax_name = -1;
static int hf_tn5250_wssf_ifc_rotation = -1;
static int hf_tn5250_wssf_ifc_scaling = -1;
static int hf_tn5250_wssf_ifc_viewimage_location_col = -1;
static int hf_tn5250_wssf_ifc_viewimage_location_row = -1;
static int hf_tn5250_wssf_ifc_viewport_location_col = -1;
static int hf_tn5250_wssf_ifc_viewport_location_row = -1;
static int hf_tn5250_wssf_ifc_viewport_size_col = -1;
static int hf_tn5250_wssf_ifc_viewport_size_row = -1;
static int hf_tn5250_wssf_ifd_flag1 = -1;
static int hf_tn5250_wssf_ifd_flag1_0 = -1;
static int hf_tn5250_wssf_ifd_flag1_reserved = -1;
static int hf_tn5250_wssf_ifd_imagefax_data = -1;
static int hf_tn5250_wssf_ifd_imagefax_name = -1;
static int hf_tn5250_wssf_kbc_flag1 = -1;
static int hf_tn5250_wssf_kbc_flag1_5 = -1;
static int hf_tn5250_wssf_kbc_flag1_6 = -1;
static int hf_tn5250_wssf_kbc_flag1_7 = -1;
static int hf_tn5250_wssf_kbc_flag1_reserved = -1;
static int hf_tn5250_wssf_wsc_minor_type = -1;
static int hf_tn5250_wtd_ccc1 = -1;
static int hf_tn5250_wtd_ccc2 = -1;
static int hf_tn5250_wtd_ccc2_alarm = -1;
static int hf_tn5250_wtd_ccc2_cursor = -1;
static int hf_tn5250_wtd_ccc2_off = -1;
static int hf_tn5250_wtd_ccc2_on = -1;
static int hf_tn5250_wtd_ccc2_res = -1;
static int hf_tn5250_wtd_ccc2_reset = -1;
static int hf_tn5250_wtd_ccc2_set = -1;
static int hf_tn5250_wtd_ccc2_unlock = -1;
static int hf_tn5250_wts_cld_flag1 = -1;
static int hf_tn5250_wts_cld_flag1_0 = -1;
static int hf_tn5250_wts_cld_flag1_1 = -1;
static int hf_tn5250_wts_cld_flag1_2 = -1;
static int hf_tn5250_wts_cld_flag1_3 = -1;
static int hf_tn5250_wts_cld_flag1_4 = -1;
static int hf_tn5250_wts_cld_flag1_5 = -1;
static int hf_tn5250_wts_cld_flag1_6 = -1;
static int hf_tn5250_wts_cld_flag1_7 = -1;
static int hf_tn5250_wts_cld_flag2 = -1;
static int hf_tn5250_wts_cld_flag2_0 = -1;
static int hf_tn5250_wts_cld_flag2_1 = -1;
static int hf_tn5250_wts_cld_flag2_2 = -1;
static int hf_tn5250_wts_cld_flag2_3 = -1;
static int hf_tn5250_wts_cld_flag2_4 = -1;
static int hf_tn5250_wts_cld_flag2_line_spacing = -1;
static int hf_tn5250_wts_cld_flag3 = -1;
static int hf_tn5250_wts_cld_flag3_0 = -1;
static int hf_tn5250_wts_cld_flag3_1 = -1;
static int hf_tn5250_wts_cld_flag3_2 = -1;
static int hf_tn5250_wts_cld_flag3_3 = -1;
static int hf_tn5250_wts_cld_flag3_4 = -1;
static int hf_tn5250_wts_cld_flag3_5 = -1;
static int hf_tn5250_wts_cld_flag3_6 = -1;
static int hf_tn5250_wts_cld_flag3_7 = -1;
static int hf_tn5250_wts_cld_io = -1;
static int hf_tn5250_wts_cld_li = -1;
static int hf_tn5250_wts_cld_lmo = -1;
static int hf_tn5250_wts_cld_page_num = -1;
static int hf_tn5250_wts_cld_row = -1;
static int hf_tn5250_wts_cld_sli = -1;
static int hf_tn5250_wts_flag1 = -1;
static int hf_tn5250_wts_flag1_0 = -1;
static int hf_tn5250_wts_flag1_1 = -1;
static int hf_tn5250_wts_flag1_2 = -1;
static int hf_tn5250_wts_flag1_3 = -1;
static int hf_tn5250_wts_flag1_reserved = -1;
static int hf_tn5250_wts_flag2 = -1;
static int hf_tn5250_wts_flag2_6 = -1;
static int hf_tn5250_wts_flag2_reserved = -1;
static int hf_tn5250_wts_flag2_reserved2 = -1;
static int hf_tn5250_wts_flag3 = -1;
static int hf_tn5250_wts_flag3_0 = -1;
static int hf_tn5250_wts_flag3_1 = -1;
static int hf_tn5250_wts_flag3_2 = -1;
static int hf_tn5250_wts_flag3_3 = -1;
static int hf_tn5250_wts_flag3_4 = -1;
static int hf_tn5250_wts_flag3_5 = -1;
static int hf_tn5250_wts_flag3_6 = -1;
static int hf_tn5250_wts_flag3_7 = -1;
static int hf_tn5250_wts_home_position_col = -1;
static int hf_tn5250_wts_home_position_row = -1;
static int hf_tn5250_wts_partition = -1;
static int hf_tn5250_soh_length = -1;
static int hf_tn5250_negative_response = -1;
static int hf_tn5250_qr_ccl = -1;
static int hf_tn5250_qr_chc= -1;
static int hf_tn5250_qr_dm= -1;
static int hf_tn5250_qr_dsn= -1;
static int hf_tn5250_qr_dt= -1;
static int hf_tn5250_qr_dtc= -1;
static int hf_tn5250_qr_eki= -1;
static int hf_tn5250_qr_flag= -1;
static int hf_tn5250_qr_flag1= -1;
static int hf_tn5250_qr_flag2= -1;
static int hf_tn5250_qr_flag3= -1;
static int hf_tn5250_qr_flag4= -1;
static int hf_tn5250_qr_ki= -1;
static int hf_tn5250_qr_flag1_0= -1;
static int hf_tn5250_qr_flag1_1= -1;
static int hf_tn5250_qr_flag1_2= -1;
static int hf_tn5250_qr_flag1_3= -1;
static int hf_tn5250_qr_flag1_4= -1;
static int hf_tn5250_qr_flag1_5= -1;
static int hf_tn5250_qr_flag1_6= -1;
static int hf_tn5250_qr_flag1_7= -1;
static int hf_tn5250_qr_flag2_0to3= -1;
static int hf_tn5250_qr_flag2_4= -1;
static int hf_tn5250_qr_flag2_5= -1;
static int hf_tn5250_qr_flag2_6to7= -1;
static int hf_tn5250_qr_flag_0= -1;
static int hf_tn5250_qr_flag_reserved= -1;
static int hf_tn5250_qr_mni= -1;
static int hf_tn5250_image_fax_error = -1;
static int hf_tn5250_vac_data = -1;
static int hf_tn5250_vac_prefix = -1;
static int hf_tn5250_wssf_ttw_flag = -1;
static int hf_tn5250_wssf_ttw_data = -1;

static gint ett_tn5250 = -1;
static gint ett_tn5250_wcc = -1;
static gint ett_sf = -1;
static gint ett_tn5250_field_attribute = -1;
static gint ett_tn5250_dfdpck_mask = -1;
static gint ett_tn5250_field_validation = -1;
static gint ett_tn5250_header_flags = -1;
static gint ett_tn5250_roll_mask = -1;
static gint ett_tn5250_soh_mask = -1;
static gint ett_tn5250_soh_pf16to9_mask = -1;
static gint ett_tn5250_soh_pf24to17_mask = -1;
static gint ett_tn5250_soh_pf8to1_mask = -1;
static gint ett_tn5250_sps_mask = -1;
static gint ett_tn5250_wdsf_cw_bp_mask = -1;
static gint ett_tn5250_wdsf_cw_mask = -1;
static gint ett_tn5250_wdsf_cw_tf_mask = -1;
static gint ett_tn5250_wdsf_deg_mask = -1;
static gint ett_tn5250_wdsf_deg_ms_mask = -1;
static gint ett_tn5250_wdsf_ds_ci_mask = -1;
static gint ett_tn5250_wdsf_ds_cpda_mask = -1;
static gint ett_tn5250_wdsf_ds_ct_mask = -1;
static gint ett_tn5250_wdsf_ds_mask = -1;
static gint ett_tn5250_wdsf_ds_mbs_mask = -1;
static gint ett_tn5250_wdsf_ds_sbi_mask = -1;
static gint ett_tn5250_wdsf_dsb_mask = -1;
static gint ett_tn5250_wdsf_pmb_mask = -1;
static gint ett_tn5250_wdsf_ragc_mask = -1;
static gint ett_tn5250_wdsf_rgw_mask = -1;
static gint ett_tn5250_wdsf_wdf_mask = -1;
static gint ett_tn5250_wsf_dpo_mask = -1;
static gint ett_tn5250_wsf_dsl_mask = -1;
static gint ett_tn5250_wsf_dtsf_mask = -1;
static gint ett_tn5250_wsf_qss_mask = -1;
static gint ett_tn5250_wsf_rts_mask = -1;
static gint ett_tn5250_wssf_cc_mask = -1;
static gint ett_tn5250_wssf_ifc_mask = -1;
static gint ett_tn5250_wssf_ifd_mask = -1;
static gint ett_tn5250_wssf_kbc_mask = -1;
static gint ett_tn5250_wssf_mask = -1;
static gint ett_tn5250_wts_mask = -1;
static gint ett_tn5250_qr_mask = -1;
static gint ett_tn5250_wea_prim_attr = -1;
static gint ett_cc = -1;

static tn5250_conv_info_t *tn5250_info_items;

static guint32 dissect_tn5250_orders_and_data(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset);

typedef struct hf_items {
  int hf;
  gint bitmask_ett;
  int length;
  const int **bitmask;
  gint encoding;
} hf_items;

/* Utility Functions */

static gint
tn5250_is_valid_aid(gint aid)
{
  switch (aid) {
    case AID_CLEAR:
    case AID_ENTER_OR_RECORD_ADV:
    case AID_HELP:
    case AID_ROLL_DOWN:
    case AID_ROLL_UP:
    case AID_ROLL_LEFT:
    case AID_ROLL_RIGHT:
    case AID_PRINT:
    case AID_RECORD_BACKSPACE:
    case AID_SLP_AUTO_ENTER:
    case AID_FORWARD_EDGE_TRIGGER_AUTO__ENTER:
    case AID_PA1:
    case AID_PA2:
    case AID_PA3:
    case AID_CMD_01:
    case AID_CMD_02:
    case AID_CMD_03:
    case AID_CMD_04:
    case AID_CMD_05:
    case AID_CMD_06:
    case AID_CMD_07:
    case AID_CMD_08:
    case AID_CMD_09:
    case AID_CMD_10:
    case AID_CMD_11:
    case AID_CMD_12:
    case AID_CMD_13:
    case AID_CMD_14:
    case AID_CMD_15:
    case AID_CMD_16:
    case AID_CMD_17:
    case AID_CMD_18:
    case AID_CMD_19:
    case AID_CMD_20:
    case AID_CMD_21:
    case AID_CMD_22:
    case AID_CMD_23:
    case AID_CMD_24:
    case AID_INBOUND_WRITE_STRUCTURED_FIELD:
    case AID_PASS_THROUGH_RESPONSE:
      return 1;
    default:
      break;
  }
  return 0;
}

static guint32
tn5250_add_hf_items(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset,
                    hf_items *fields)
{
  int start=offset, byte;
  int i;

  for (i = 0; fields[i].hf; ++i) {
    if (fields[i].bitmask == 0) {
      /* Skip an 0xFF byte acting as an escape byte */
      byte = tvb_get_guint8(tvb,offset);
      if (byte == 0xFF) {
        offset++;
      }
      proto_tree_add_item(tn5250_tree, fields[i].hf, tvb, offset,
                          fields[i].length, fields[i].encoding);
    } else {
      proto_tree_add_bitmask(tn5250_tree, tvb, offset, fields[i].hf,
                             fields[i].bitmask_ett, fields[i].bitmask, FALSE);
    }
    DISSECTOR_ASSERT(fields[i].length > 0);
    offset+=fields[i].length;
  }
  return (offset - start);
}

static guint32
dissect_unknown_data(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset,
                     gint start, gint sf_length)
{
  int len_left;

  len_left = sf_length - (offset - start);

  if (len_left > 0) {
    proto_tree_add_item(tn5250_tree, hf_tn5250_unknown_data, tvb, offset,
                        len_left, ENC_NA);
    return len_left;
  }
  return 0;
}

static guint32
dissect_wcc(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{

  static const int *wcc_byte[] = {
    &hf_tn5250_wtd_ccc2_res,
    &hf_tn5250_wtd_ccc2_cursor,
    &hf_tn5250_wtd_ccc2_reset,
    &hf_tn5250_wtd_ccc2_set,
    &hf_tn5250_wtd_ccc2_unlock,
    &hf_tn5250_wtd_ccc2_alarm,
    &hf_tn5250_wtd_ccc2_off,
    &hf_tn5250_wtd_ccc2_on,
    NULL
  };

  hf_items wcc_fields[] = {
    { hf_tn5250_wtd_ccc1, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wtd_ccc2, ett_tn5250_wcc, 1, wcc_byte, 0 },
    { 0, 0, 0, 0, 0 }
  };

  offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, wcc_fields);

  return 2;

}

static guint32
dissect_row_column(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;
  proto_tree_add_item(tn5250_tree, hf_tn5250_buffer_x, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  proto_tree_add_item(tn5250_tree, hf_tn5250_buffer_y, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  return (offset - start);
}

/* End - Utility Functions */


/* Start: Handle WCC, Orders and Data */

/* 15.6.8 Erase to Address Order */
static guint32
dissect_erase_to_address(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;
  int i, length = 0;

  dissect_row_column(tn5250_tree, tvb, offset);

  length = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tn5250_tree, hf_tn5250_length, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  for (i=1; i < length; i++) {
    proto_tree_add_item(tn5250_tree, hf_tn5250_attribute_type, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    offset++;
  }

  return (offset - start);
}

/* 15.6.9 Start of Header Order */
static guint32
dissect_start_of_header(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;

  /*TODO: Warn on invalid length. <= 7 */
  static const int *byte[] = {
    &hf_tn5250_soh_cursor_direction,
    &hf_tn5250_soh_screen_reverse,
    &hf_tn5250_soh_input_capable_only,
    NULL
  };

  static const int *byte1[] = {
    &hf_tn5250_soh_pf24, &hf_tn5250_soh_pf23, &hf_tn5250_soh_pf22,
    &hf_tn5250_soh_pf21, &hf_tn5250_soh_pf20, &hf_tn5250_soh_pf19,
    &hf_tn5250_soh_pf18, &hf_tn5250_soh_pf17,
    NULL
  };

  static const int *byte2[] = {
    &hf_tn5250_soh_pf16, &hf_tn5250_soh_pf15, &hf_tn5250_soh_pf14,
    &hf_tn5250_soh_pf13, &hf_tn5250_soh_pf12, &hf_tn5250_soh_pf11,
    &hf_tn5250_soh_pf10, &hf_tn5250_soh_pf9,
    NULL
  };

  static const int *byte3[] = {
    &hf_tn5250_soh_pf8, &hf_tn5250_soh_pf7, &hf_tn5250_soh_pf6,
    &hf_tn5250_soh_pf5, &hf_tn5250_soh_pf4, &hf_tn5250_soh_pf3,
    &hf_tn5250_soh_pf2, &hf_tn5250_soh_pf1,
    NULL
  };

  hf_items start_of_header_fields[] = {
    { hf_tn5250_soh_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_soh_flags, ett_tn5250_soh_mask, 1, byte, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_soh_resq, 1, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_soh_err, 1, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_soh_pf24to17, ett_tn5250_soh_pf24to17_mask, 1, byte1, 0 },
    { hf_tn5250_soh_pf16to9, ett_tn5250_soh_pf16to9_mask, 1, byte2, 0 },
    { hf_tn5250_soh_pf8to1, ett_tn5250_soh_pf8to1_mask, 1, byte3, 0 },
    { 0, 0, 0, 0, 0 }
  };


  offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                start_of_header_fields);

  return (offset - start);
}

/* 15.6.10 Transparent Data */
static guint32
dissect_twobyte_length_and_data(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;
  int length = 0;

  length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tn5250_tree, hf_tn5250_length_twobyte, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  offset+=2;

  if (tvb_reported_length_remaining(tvb, offset) >= length) {
    proto_tree_add_item(tn5250_tree, hf_tn5250_field_data, tvb, offset,
                        length, ENC_EBCDIC|ENC_NA);
    offset+=length;
  } else {
    offset += dissect_unknown_data(tn5250_tree, tvb, offset, start, length);
  }

  return (offset - start);
}

/* 15.6.11 Write Extended Attribute Order */
static guint32
dissect_field_attribute_pair(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;
  int attribute_type;

  static const int *byte[] = {
     &hf_tn5250_wea_prim_attr_flag, &hf_tn5250_wea_prim_attr_col,
     &hf_tn5250_wea_prim_attr_blink, &hf_tn5250_wea_prim_attr_und,
     &hf_tn5250_wea_prim_attr_int, &hf_tn5250_wea_prim_attr_rev,
     NULL
  };

  attribute_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tn5250_tree, hf_tn5250_attribute_type, tvb, offset, 1,
                      ENC_BIG_ENDIAN);
  offset++;
  switch (attribute_type) {
    case EXTENDED_PRIMARY_ATTRIBUTES:
      proto_tree_add_bitmask(tn5250_tree, tvb, offset, hf_tn5250_wea_prim_attr,
                             ett_tn5250_wea_prim_attr, byte, FALSE);
      offset++;
      break;
    case EXTENDED_FOREGROUND_COLOR_ATTRIBUTES:
      proto_tree_add_item(tn5250_tree, hf_tn5250_foreground_color_attr, tvb,
                          offset, 1, ENC_BIG_ENDIAN);
      offset++;
      break;
    case EXTENDED_IDEOGRAPHIC_ATTRIBUTES:
      proto_tree_add_item(tn5250_tree, hf_tn5250_ideographic_attr, tvb, offset,
                          1, ENC_BIG_ENDIAN);
      offset++;
      break;
    default:
      /*TODO: Add invalid data statement here*/
      break;
  }

  return (offset - start);
}

/* 15.6.12 Start of Field Order */
static guint32
dissect_start_of_field(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;
  int done = 0;
  int ffw = 0, fcw = 0, fa = 0;

  static const int *byte[] = {
    &hf_tn5250_ffw_id,
    &hf_tn5250_ffw_bypass,
    &hf_tn5250_ffw_dup,
    &hf_tn5250_ffw_mdt,
    &hf_tn5250_ffw_shift,
    NULL
  };

  static const int *byte1[] = {
    &hf_tn5250_ffw_auto,
    &hf_tn5250_ffw_fer,
    &hf_tn5250_ffw_monocase,
    &hf_tn5250_ffw_res,
    &hf_tn5250_ffw_me,
    &hf_tn5250_ffw_adjust,
    NULL
  };

  static const int *fabyte[] = {
    &hf_tn5250_sf_attr_flag, &hf_tn5250_wea_prim_attr_col,
    &hf_tn5250_wea_prim_attr_blink, &hf_tn5250_wea_prim_attr_und,
    &hf_tn5250_wea_prim_attr_int, &hf_tn5250_wea_prim_attr_rev,
    NULL
  };

  hf_items outbound_text_header_fields[] = {
    { hf_tn5250_ffw, ett_tn5250_soh_mask, 1, byte, 0 },
    { hf_tn5250_ffw, ett_tn5250_soh_mask, 1, byte1, 0 },
    { 0, 0, 0, 0, 0 }
  };

  ffw = tvb_get_guint8(tvb, offset);

  if (ffw & FFW_ID) {
    offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                  outbound_text_header_fields);
    while (tvb_reported_length_remaining(tvb, offset) > 0 && !done) {
      fcw = tvb_get_guint8(tvb, offset);
      switch (fcw) {
        case SELECTOR:
        case IDEOGRAPHIC:
        case FORWARD_EDGE:
        case CONTINUED_ENTRY:
        case SELF_CHECK:
        case ENTRY_FIELD_RESEQUENCING:
        case CURSOR_PROGRESSION_ENTRY_FIELD:
        case HIGHLIGHTED_ENTRY_FIELD:
        case POINTER_DEVICE_SELECTION_ENTRY_FIELD:
        case TRANSPARENCY_ENTRY_FIELD:
          proto_tree_add_item(tn5250_tree, hf_tn5250_fcw, tvb, offset,
                              2, ENC_BIG_ENDIAN);
          offset+=2;
          break;
        default:
          done = 1;
          break;
      }
    }
  }

  fa = tvb_get_guint8(tvb, offset);

  if (fa & FA_ID) {
    proto_tree_add_bitmask(tn5250_tree, tvb, offset, hf_tn5250_fa,
                           ett_tn5250_wea_prim_attr, fabyte, FALSE);
    offset++;
  } else {
    proto_tree_add_item(tn5250_tree, hf_tn5250_fa_color, tvb, offset,
                        1, ENC_BIG_ENDIAN);
    offset++;
  }
  proto_tree_add_item(tn5250_tree, hf_tn5250_length_twobyte, tvb, offset,
                      2, ENC_BIG_ENDIAN);
  offset+=2;

  return (offset - start);
}

/* 15.6.13 Write To Display Structured Field Order */
static guint32
dissect_create_window(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;
  int length = 0;
  int done = 0, minor_structure = 0;

  static const int *byte[] = {
    &hf_tn5250_wdsf_cw_flag1_1,
    &hf_tn5250_wdsf_cw_flag1_2,
    &hf_tn5250_wdsf_cw_flag1_reserved,
    NULL
  };

  hf_items cw_fields[] = {
    { hf_tn5250_wdsf_cw_flag1, ett_tn5250_wdsf_cw_mask, 1, byte, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cw_wd, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cw_ww, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *cw_bp_flag1[] = {
    &hf_tn5250_wdsf_cw_bp_flag1_1,
    &hf_tn5250_wdsf_cw_bp_flag1_reserved,
    NULL
  };


  hf_items cwbp_fields[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cw_minor_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cw_bp_flag1, ett_tn5250_wdsf_cw_bp_mask, 1, cw_bp_flag1, 0 },
    { hf_tn5250_wdsf_cw_bp_mba, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cw_bp_cba, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cw_bp_ulbc, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_cw_bp_tbc, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_cw_bp_urbc, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_cw_bp_lbc, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_cw_bp_rbc, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_cw_bp_llbc, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_cw_bp_bbc, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_cw_bp_lrbc, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { 0, 0, 0, 0, 0 }
  };

  static const int *cw_tf_flag1[] = {
    &hf_tn5250_wdsf_cw_tf_flag_orientation,
    &hf_tn5250_wdsf_cw_tf_flag_1,
    &hf_tn5250_wdsf_cw_tf_flag_reserved,
    NULL
  };


  hf_items cw_tf_fields[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cw_minor_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cw_tf_flag, ett_tn5250_wdsf_cw_tf_mask, 1, cw_tf_flag1, 0 },
    { hf_tn5250_wdsf_cw_tf_mba, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cw_tf_cba, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, cw_fields);

  while (tvb_reported_length_remaining(tvb, offset) > 0 && !done) {
    minor_structure = tvb_get_guint8(tvb, offset+1);
    switch (minor_structure) {
      case CW_BORDER_PRESENTATION:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, cwbp_fields);
      case CW_TITLE_FOOTER:
        length = tvb_get_guint8(tvb,offset);
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, cw_tf_fields);
        proto_tree_add_item(tn5250_tree, hf_tn5250_wdsf_cw_tf_text, tvb, offset,
                            (length - 6), ENC_EBCDIC|ENC_NA);
        offset += (guint32)((length - 6));
      default:
        done = 1;
        break;
    }
  }

  return (offset - start);
}

static guint32
dissect_define_selection(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;
  int length = 0;
  int done = 0, minor_structure = 0, digit_selection = 0;

  static const int *ds_flag1[] = {
    &hf_tn5250_wdsf_ds_flag1_mouse_characteristics, &hf_tn5250_wdsf_ds_flag1_reserved,
    &hf_tn5250_wdsf_ds_flag1_auto_enter, &hf_tn5250_wdsf_ds_flag1_1,
    &hf_tn5250_wdsf_ds_flag1_2, NULL
  };

  static const int *ds_flag2[] = {
    &hf_tn5250_wdsf_ds_flag2_1, &hf_tn5250_wdsf_ds_flag2_2,
    &hf_tn5250_wdsf_ds_flag2_3, &hf_tn5250_wdsf_ds_flag2_4,
    &hf_tn5250_wdsf_ds_flag2_5, &hf_tn5250_wdsf_ds_flag2_6,
    &hf_tn5250_wdsf_ds_flag2_reserved,
    NULL
  };

  static const int *ds_flag3[] = {
    &hf_tn5250_wdsf_ds_flag3_1, &hf_tn5250_wdsf_ds_flag3_reserved,
    NULL
  };

  static const int *ds_gdc[] = {
    &hf_tn5250_wdsf_ds_gdc_indicators, &hf_tn5250_wdsf_ds_gdc_reserved,
    &hf_tn5250_wdsf_ds_gdc_selection_techniques,
    NULL
  };

  static const int *ds_nws[] = {
    &hf_tn5250_wdsf_ds_nws_indicators, &hf_tn5250_wdsf_ds_nws_reserved,
    &hf_tn5250_wdsf_ds_nws_selection_techniques,
    NULL
  };

  hf_items ds_fields[] = {
    { hf_tn5250_wdsf_ds_flag1, ett_tn5250_wdsf_ds_mask, 1, ds_flag1, 0 },
    { hf_tn5250_wdsf_ds_flag2, ett_tn5250_wdsf_ds_mask, 1, ds_flag2, 0 },
    { hf_tn5250_wdsf_ds_flag3, ett_tn5250_wdsf_ds_mask, 1, ds_flag3, 0 },
    { hf_tn5250_wdsf_ds_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_gdc, ett_tn5250_wdsf_ds_mask, 1, ds_gdc, 0 },
    { hf_tn5250_wdsf_ds_nws, ett_tn5250_wdsf_ds_mask, 1, ds_nws, 0 },
    { hf_tn5250_wdsf_ds_nws_wout, ett_tn5250_wdsf_ds_mask, 1, ds_nws, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_textsize, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_rows, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_columns, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_padding, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_numeric_sep, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_ds_country_sel, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_ds_cancel_aid, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_totalrows, 0, 4, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_sliderpos, 0, 4, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *ds_ct_flag1[] = {
    &hf_tn5250_wdsf_ds_ct_flag1_choice_state, &hf_tn5250_wdsf_ds_ct_flag1_2,
    &hf_tn5250_wdsf_ds_ct_flag1_3, &hf_tn5250_wdsf_ds_ct_flag1_4,
    &hf_tn5250_wdsf_ds_ct_flag1_5, &hf_tn5250_wdsf_ds_ct_flag1_numeric_selection,
    NULL
  };

  static const int *ds_ct_flag2[] = {
    &hf_tn5250_wdsf_ds_ct_flag2_0, &hf_tn5250_wdsf_ds_ct_flag2_1,
    &hf_tn5250_wdsf_ds_ct_flag2_2, &hf_tn5250_wdsf_ds_ct_flag2_3,
    &hf_tn5250_wdsf_ds_ct_flag2_4, &hf_tn5250_wdsf_ds_ct_flag2_5,
    &hf_tn5250_wdsf_ds_ct_flag2_6, &hf_tn5250_wdsf_ds_ct_flag2_7,
    NULL
  };

  static const int *ds_ct_flag3[] = {
    &hf_tn5250_wdsf_ds_ct_flag3_0, &hf_tn5250_wdsf_ds_ct_flag3_1,
    &hf_tn5250_wdsf_ds_ct_flag3_2, &hf_tn5250_wdsf_ds_ct_flag3_reserved,
    NULL
  };

  hf_items ds_ct_fields[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_minor_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_ct_flag1, ett_tn5250_wdsf_ds_ct_mask, 1, ds_ct_flag1, 0 },
    { hf_tn5250_wdsf_ds_ct_flag2, ett_tn5250_wdsf_ds_ct_mask, 1, ds_ct_flag2, 0 },
    { hf_tn5250_wdsf_ds_ct_flag3, ett_tn5250_wdsf_ds_ct_mask, 1, ds_ct_flag3, 0 },
    { hf_tn5250_wdsf_ds_ct_mnemonic_offset, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_ct_aid, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_ct_numeric_onebyte, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_ct_numeric_twobyte, 0, 2, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *ds_mbs_flag[] = {
    &hf_tn5250_wdsf_ds_mbs_flag_0, &hf_tn5250_wdsf_ds_mbs_flag_1,
    &hf_tn5250_wdsf_ds_mbs_flag_reserved,
    NULL
  };

  hf_items ds_mbs_fields[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_minor_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_mbs_flag, ett_tn5250_wdsf_ds_mbs_mask, 1, ds_mbs_flag, 0 },
    { hf_tn5250_wdsf_ds_mbs_start_column, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_mbs_end_column, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_mbs_start_column, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_mbs_monochrome_sep, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_mbs_color_sep, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_mbs_sep_char, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { 0, 0, 0, 0, 0 }
  };

  static const int *ds_cpda_flag[] = {
    &hf_tn5250_wdsf_ds_cpda_flag1_0, &hf_tn5250_wdsf_ds_cpda_flag1_1,
    &hf_tn5250_wdsf_ds_cpda_flag1_2, &hf_tn5250_wdsf_ds_cpda_flag1_reserved,
    NULL
  };

  hf_items ds_cpda_fields[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_minor_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_flag1, ett_tn5250_wdsf_ds_cpda_mask, 1, ds_cpda_flag, 0 },
    { hf_tn5250_wdsf_ds_cpda_monochrome_sel_avail, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_color_sel_avail, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_monochrome_sel_selected, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_color_sel_selected, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_monochrome_sel_unavail, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_color_sel_unavail, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_monochrome_avail, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_color_avail, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_monochrome_selected, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_color_selected, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_monochrome_unavail, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_color_unavail, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_monochrome_indicator, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_color_indicator, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_monochrome_unavail_indicator, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_cpda_color_unavail_indicator, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *ds_ci_flag[] = {
    &hf_tn5250_wdsf_ds_ci_flag1_0, &hf_tn5250_wdsf_ds_ci_flag1_reserved,
    NULL
  };

  hf_items ds_ci_fields[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_minor_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_ci_flag1, ett_tn5250_wdsf_ds_ci_mask, 1, ds_ci_flag, 0 },
    { hf_tn5250_wdsf_ds_ci_left_push, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_ds_ci_right_push, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_ds_ci_first_choice, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { 0, 0, 0, 0, 0 }
  };

  static const int *ds_sbi_flag[] = {
    &hf_tn5250_wdsf_ds_sbi_flag1_0, &hf_tn5250_wdsf_ds_sbi_flag1_reserved,
    NULL
  };

  hf_items ds_sbi_fields[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_minor_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_sbi_flag1, ett_tn5250_wdsf_ds_sbi_mask, 1, ds_sbi_flag, 0 },
    { hf_tn5250_wdsf_ds_sbi_monochrome_top_highlight, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_sbi_color_top_highlight, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_sbi_monochrome_top_highlight_shaft, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_sbi_color_top_highlight_shaft, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_sbi_top_character, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_ds_sbi_bottom_character, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_ds_sbi_empty_character, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_ds_sbi_slider_character, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { 0, 0, 0, 0, 0 }
  };

  offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, ds_fields);

  while (tvb_reported_length_remaining(tvb, offset) > 0 && !done) {
    minor_structure = tvb_get_guint8(tvb, offset+1);
    switch (minor_structure) {
      case DS_CHOICE_TEXT:
        length = tvb_get_guint8(tvb, offset);
        digit_selection = tvb_get_guint8(tvb, offset+2);
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, ds_ct_fields);
        if (digit_selection & DS_NUMERIC_SELECTION_SINGLE_DIGIT) {
          proto_tree_add_item(tn5250_tree, hf_tn5250_wdsf_ds_ct_numeric_onebyte,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset++;
        } else if (digit_selection & DS_NUMERIC_SELECTION_DOUBLE_DIGIT) {
          proto_tree_add_item(tn5250_tree, hf_tn5250_wdsf_ds_ct_numeric_twobyte,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
          offset++;
        }
        proto_tree_add_item(tn5250_tree, hf_tn5250_wdsf_ds_ct_text, tvb, offset,
                            (length - (offset - start)), ENC_EBCDIC|ENC_NA);
        offset += (guint32)((length - (offset - start)));
        break;
      case DS_MENU_BAR_SEPARATOR:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, ds_mbs_fields);
        break;
      case DS_CHOICE_PRESENTATION_DISPLAY:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, ds_cpda_fields);
        break;
      case DS_CHOICE_INDICATORS:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, ds_ci_fields);
        break;
      case DS_SCROLLBAR_INDICATORS:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, ds_sbi_fields);
        break;
      default:
        done = 1;
        break;
    }
  }
  return (offset - start);
}

static guint32
dissect_define_scrollbar(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;
  int done = 0, minor_structure = 0;

  static const int *dsb_byte[] = {
    &hf_tn5250_wdsf_dsb_flag1_0, &hf_tn5250_wdsf_dsb_flag1_1,
    &hf_tn5250_wdsf_dsb_flag1_reserved, &hf_tn5250_wdsf_dsb_flag1_7,
    NULL
  };

  hf_items dsb_fields[] = {
    { hf_tn5250_wdsf_dsb_flag1, ett_tn5250_wdsf_dsb_mask, 1, dsb_byte, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_sbi_total_scroll, 0, 4, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_sbi_sliderpos, 0, 4, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_sbi_rowscols, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *ds_sbi_flag[] = {
    &hf_tn5250_wdsf_ds_sbi_flag1_0, &hf_tn5250_wdsf_ds_sbi_flag1_reserved,
    NULL
  };

  hf_items ds_sbi_fields[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_minor_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_sbi_flag1, ett_tn5250_wdsf_ds_sbi_mask, 1, ds_sbi_flag, 0 },
    { hf_tn5250_wdsf_ds_sbi_monochrome_top_highlight, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_sbi_color_top_highlight, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_sbi_monochrome_top_highlight_shaft, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_sbi_color_top_highlight_shaft, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_ds_sbi_top_character, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_ds_sbi_bottom_character, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_ds_sbi_empty_character, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_wdsf_ds_sbi_slider_character, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { 0, 0, 0, 0, 0 }
  };


  offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, dsb_fields);

  while (tvb_reported_length_remaining(tvb, offset) > 0 && !done) {
    minor_structure = tvb_get_guint8(tvb, offset+1);
    switch (minor_structure) {
      case DS_SCROLLBAR_INDICATORS:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, ds_sbi_fields);
        break;
      default:
        done = 1;
        break;
    }
  }
  return (offset - start);
}

static guint32
dissect_draw_erase_gridlines(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;
  int done = 0, minor_structure=0;

  static const int *deg_byte[] = {
    &hf_tn5250_wdsf_deg_flag1_0, &hf_tn5250_wdsf_deg_flag1_reserved,
    NULL
  };

  static const int *deg_byte2[] = {
    &hf_tn5250_wdsf_deg_flag2_0, &hf_tn5250_wdsf_deg_flag2_reserved,
    NULL
  };

  hf_items deg_fields[] = {
    { hf_tn5250_wdsf_deg_partition, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_deg_flag1, ett_tn5250_wdsf_deg_mask, 1, deg_byte, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_deg_flag2, ett_tn5250_wdsf_deg_mask, 1, deg_byte2, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_deg_default_color, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_deg_default_line, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };


  static const int *deg_ms_byte[] = {
    &hf_tn5250_wdsf_deg_ms_flag1_0, &hf_tn5250_wdsf_deg_ms_flag1_reserved,
    NULL
  };

  hf_items deg_ms_fields[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_deg_minor_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_deg_ms_flag1, ett_tn5250_wdsf_deg_ms_mask, 1, deg_ms_byte, 0 },
    { hf_tn5250_wdsf_deg_ms_start_row, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_deg_ms_start_column, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_deg_ms_horizontal_dimension, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_deg_ms_vertical_dimension, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_deg_ms_default_color, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_deg_ms_line_repeat, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_deg_ms_line_interval, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, deg_fields);

  while (tvb_reported_length_remaining(tvb, offset) > 0 && !done) {
    minor_structure = tvb_get_guint8(tvb, offset+1);
    switch (minor_structure) {
      case UPPER_HORIZONTAL_LINE:
      case LOWER_HORIZONTAL_LINE:
      case LEFT_VERTICAL_LINE:
      case RIGHT_VERTICAL_LINE:
      case PLAIN_BOX:
      case HORIZONTALLY_RULED_BOX:
      case VERTICALLY_RULED_BOX:
      case HORIZONTALLY_AND_VERTICALLY_RULED_BOX:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, deg_ms_fields);
        break;
      default:
        done = 1;
        break;
    }
  }
  return (offset - start);
}

static guint32
dissect_wdsf_structured_field(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;
  int length = 0, type;
  int done = 0, ln_left = 0, i = 0;

  hf_items standard_fields[] = {
    { hf_tn5250_sf_length, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sf_class, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sf_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *rgw_byte[] = {
    &hf_tn5250_wdsf_rgw_flag1_0,
    &hf_tn5250_wdsf_rgw_flag1_1,
    &hf_tn5250_wdsf_rgw_reserved,
    NULL
  };

  hf_items rgw_fields[] = {
    { hf_tn5250_wdsf_rgw_flag1, ett_tn5250_wdsf_rgw_mask, 1, rgw_byte, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *ragc_byte[] = {
    &hf_tn5250_wdsf_ragc_flag1_0,
    &hf_tn5250_wdsf_ragc_reserved,
    NULL
  };

  hf_items ragc_fields[] = {
    { hf_tn5250_wdsf_ragc_flag1, ett_tn5250_wdsf_ragc_mask, 1, ragc_byte, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *wdf_byte[] = {
    &hf_tn5250_wdsf_wdf_flag1_0,
    &hf_tn5250_wdsf_wdf_flag1_reserved,
    NULL
  };

  hf_items wdf_fields[] = {
    { hf_tn5250_wdsf_wdf_flag1, ett_tn5250_wdsf_wdf_mask, 1, wdf_byte, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *pmb_byte[] = {
    &hf_tn5250_wdsf_pmb_flag1_0, &hf_tn5250_wdsf_pmb_flag1_1,
    &hf_tn5250_wdsf_pmb_flag1_2, &hf_tn5250_wdsf_pmb_flag1_3,
    &hf_tn5250_wdsf_pmb_flag1_reserved,
    NULL
  };

  hf_items pmb_fields[] = {
    { hf_tn5250_wdsf_pmb_flag1, ett_tn5250_wdsf_pmb_mask, 1, pmb_byte, 0 },
    { hf_tn5250_wdsf_pmb_first_mouse_event, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_pmb_second_mouse_event, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_aid, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  hf_items cgl_fields[] = {
    { hf_tn5250_wdsf_cgl_partition, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cgl_start_row, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cgl_start_column, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cgl_rectangle_width, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wdsf_cgl_rectangle_height, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  length = tvb_get_ntohs(tvb,offset);
  type = tvb_get_guint8(tvb, offset+3);

  offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, standard_fields);

  while (tvb_reported_length_remaining(tvb, offset) > 0 && !done) {
    switch (type) {
      case CREATE_WINDOW:
        offset += dissect_create_window(tn5250_tree, tvb, offset);
        break;
      case UNRESTRICTED_WINDOW_CURSOR_MOVEMENT:
      case REMOVE_GUI_SELECTION_FIELD:
      case REMOVE_GUI_SCROLL_BAR_FIELD:
        proto_tree_add_item(tn5250_tree, hf_tn5250_reserved, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tn5250_tree, hf_tn5250_reserved, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        offset +=2;
        break;
      case REMOVE_GUI_WINDOW:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, rgw_fields);
        break;
      case REMOVE_ALL_GUI_CONSTRUCTS:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, ragc_fields);
        break;
      case DEFINE_SELECTION_FIELD:
        offset += dissect_define_selection(tn5250_tree, tvb, offset);
        break;
      case DEFINE_SCROLL_BAR_FIELD:
        offset += dissect_define_scrollbar(tn5250_tree, tvb, offset);
        break;
      case WRITE_DATA:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, wdf_fields);
        proto_tree_add_item(tn5250_tree, hf_tn5250_field_data, tvb, offset,
                            (length - 6), ENC_EBCDIC|ENC_NA);
        offset += (guint32)((length - 6));
        break;
      case PROGRAMMABLE_MOUSE_BUTTONS:
        proto_tree_add_item(tn5250_tree, hf_tn5250_reserved, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tn5250_tree, hf_tn5250_reserved, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        offset +=2;
        ln_left = length - (offset - start);
        for (i = 0; i < ln_left; i+=4) {
          offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, pmb_fields);
        }
        break;
      case DRAW_ERASE_GRID_LINES:
        offset += dissect_draw_erase_gridlines(tn5250_tree, tvb, offset);
        break;
      case CLEAR_GRID_LINE_BUFFER:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, cgl_fields);
        break;
      default:
        done = 1;
        break;
    }
  }
  offset += dissect_unknown_data(tn5250_tree, tvb, offset, start, length);

  return (offset - start);

}


/* 15.6 WRITE TO DISPLAY Command - Orders and Data */
static guint32
dissect_tn5250_ra_data(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  gint order_code, done = 0;
  gint start = offset;

  while (tvb_reported_length_remaining(tvb, offset) > 0 && !done) {
    order_code = tvb_get_guint8(tvb, offset);
    switch (order_code) {
      case TN5250_IC:
      case TN5250_MC:
      case TN5250_SBA:
      case TN5250_RA:
      case TN5250_EA:
      case TN5250_SOH:
      case TN5250_TD:
      case TN5250_WEA:
      case TN5250_SF:
      case TN5250_WDSF:
      case TN5250_ESCAPE:
        done = 1;
        break;
      default:
        offset++;
        break;
    }
  }

  if (offset > start) {
    proto_tree_add_item(tn5250_tree, hf_tn5250_repeated_character,
                        tvb, start, (offset - start), ENC_EBCDIC|ENC_NA);
  }
  return (offset - start);

}

static guint32
dissect_tn5250_orders_and_data(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  gint start = offset, done = 0;
  gint order_code;
  proto_tree   *cc_tree;
  proto_item   *ti;

  /* Order Code */

  while (tvb_reported_length_remaining(tvb, offset) > 0 && !done) {
    order_code = tvb_get_guint8(tvb, offset);
    switch (order_code) {
      case TN5250_IC:
      case TN5250_MC:
      case TN5250_SBA:
        ti = proto_tree_add_item(tn5250_tree, hf_tn5250_order_code, tvb,
                                 offset, 1, ENC_BIG_ENDIAN);
        offset++;
        cc_tree = proto_item_add_subtree(ti, ett_cc);
        offset += dissect_row_column(cc_tree, tvb, offset);
        offset += dissect_tn5250_ra_data(cc_tree, tvb, offset);
        break;
      case TN5250_RA:
        ti = proto_tree_add_item(tn5250_tree, hf_tn5250_order_code, tvb,
                                 offset, 1, ENC_BIG_ENDIAN);
        offset++;
        cc_tree = proto_item_add_subtree(ti, ett_cc);
        offset += dissect_row_column(cc_tree, tvb, offset);
        offset += dissect_tn5250_ra_data(cc_tree, tvb, offset);
        break;
      case TN5250_EA:
        ti = proto_tree_add_item(tn5250_tree, hf_tn5250_order_code, tvb,
                                 offset, 1, ENC_BIG_ENDIAN);
        offset++;
        cc_tree = proto_item_add_subtree(ti, ett_cc);
        offset += dissect_erase_to_address(cc_tree, tvb, offset);
        break;
      case TN5250_SOH:
        ti = proto_tree_add_item(tn5250_tree, hf_tn5250_order_code, tvb,
                                 offset, 1, ENC_BIG_ENDIAN);
        offset++;
        cc_tree = proto_item_add_subtree(ti, ett_cc);
        offset += dissect_start_of_header(cc_tree, tvb, offset);
        break;
      case TN5250_TD:
        ti = proto_tree_add_item(tn5250_tree, hf_tn5250_order_code, tvb,
                                 offset, 1, ENC_BIG_ENDIAN);
        offset++;
        cc_tree = proto_item_add_subtree(ti, ett_cc);
        offset += dissect_twobyte_length_and_data(cc_tree, tvb, offset);
        break;
      case TN5250_WEA:
        ti = proto_tree_add_item(tn5250_tree, hf_tn5250_order_code, tvb,
                                 offset, 1, ENC_BIG_ENDIAN);
        offset++;
        cc_tree = proto_item_add_subtree(ti, ett_cc);
        offset += dissect_field_attribute_pair(cc_tree, tvb, offset);
        break;
      case TN5250_SF:
        ti = proto_tree_add_item(tn5250_tree, hf_tn5250_order_code, tvb,
                                 offset, 1, ENC_BIG_ENDIAN);
        offset++;
        cc_tree = proto_item_add_subtree(ti, ett_cc);
        offset += dissect_start_of_field(cc_tree, tvb, offset);
        offset += dissect_tn5250_ra_data(cc_tree, tvb, offset);
        break;
      case TN5250_WDSF:
        ti = proto_tree_add_item(tn5250_tree, hf_tn5250_order_code, tvb,
                                 offset, 1, ENC_BIG_ENDIAN);
        offset++;
        cc_tree = proto_item_add_subtree(ti, ett_cc);
        offset += dissect_wdsf_structured_field(cc_tree, tvb, offset);
        break;
      default:
        done = 1;
        break;
    }
  }
  return (offset - start);
}

/* 15.22 SAVE PARTIAL SCREEN Command */
static guint32
dissect_save_partial_screen(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;
  int length = 0;

  static const int *byte[] = {
    &hf_tn5250_sps_flag1_0,
    &hf_tn5250_sps_flag1_reserved,
    NULL
  };

  hf_items save_partial_screen_fields[] = {
    { hf_tn5250_soh_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sps_flag1, ett_tn5250_sps_mask, 1, byte, 0 },
    { hf_tn5250_sps_top_row, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sps_left_column, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sps_window_depth, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sps_window_width, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  length = tvb_get_guint8(tvb, offset);

  offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                save_partial_screen_fields);

  offset += dissect_unknown_data(tn5250_tree, tvb, offset, start, length);

  return (offset - start);
}

/* 15.25 ROLL Command */
static guint32
dissect_roll(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;

  static const int *byte[] = {
    &hf_tn5250_roll_flag1_0,
    &hf_tn5250_roll_flag1_reserved,
    &hf_tn5250_roll_flag1_lines,
    NULL
  };

  hf_items roll_fields[] = {
    { hf_tn5250_roll_flag1, ett_tn5250_roll_mask, 1, byte, 0 },
    { hf_tn5250_roll_top_line, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_roll_bottom_line, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };


  offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, roll_fields);

  return (offset - start);
}

/* 15.26 WRITE SINGLE STRUCTURED FIELD Command */
static guint32
dissect_write_single_structured_field_minor_fields(proto_tree *tn5250_tree,
                                                   tvbuff_t *tvb, gint offset)
{

  int start = offset;
  int done = 0, type = 0;

  static const int *byte_wssf_kbc_flag1[] = {
    &hf_tn5250_wssf_kbc_flag1_reserved,
    &hf_tn5250_wssf_kbc_flag1_5,
    &hf_tn5250_wssf_kbc_flag1_6,
    &hf_tn5250_wssf_kbc_flag1_7,
    NULL
  };

  static const int *byte_wssf_cc_flag1[] = {
    &hf_tn5250_wssf_cc_flag1_reserved,
    &hf_tn5250_wssf_cc_flag1_7,
    NULL
  };

  hf_items wsc_customization_kbc_fields[] = {
    { hf_tn5250_sf_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_wsc_minor_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_kbc_flag1, ett_tn5250_wssf_kbc_mask, 1, byte_wssf_kbc_flag1, 0 },
    { 0, 0, 0, 0, 0 }
  };

  hf_items wsc_customization_cc_fields[] = {
    { hf_tn5250_sf_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_wsc_minor_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_cc_flag1, ett_tn5250_wssf_cc_mask, 1, byte_wssf_cc_flag1, 0 },
    { 0, 0, 0, 0, 0 }
  };

  while (tvb_reported_length_remaining(tvb, offset) > 0 && !done) {
    type = tvb_get_guint8(tvb, offset+1);
    switch (type) {
      case KEYSTROKE_BUFFERING_CONTROL:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                      wsc_customization_kbc_fields);
        break;
      case CURSOR_CONTROL:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                      wsc_customization_cc_fields);
        break;
      default:
        done = 1;
        break;
    }
  }

  return (offset - start);

}

static guint32
dissect_write_single_structured_field(proto_tree *tn5250_tree, tvbuff_t *tvb,
                                      gint offset)
{
  int start = offset;
  int length, type, done = 0;
  guint32 namelength;

  static const int *byte[] = {
    &hf_tn5250_wssf_flag2_0,
    &hf_tn5250_wssf_flag2_1,
    &hf_tn5250_wssf_flag2_2,
    &hf_tn5250_wssf_flag2_3,
    &hf_tn5250_wssf_flag2_4,
    &hf_tn5250_wssf_flag2_5,
    &hf_tn5250_wssf_flag2_6,
    &hf_tn5250_wssf_flag2_7,
    NULL
  };

  static const int *ifc_byte[] = {
    &hf_tn5250_wssf_ifc_flag1_0,
    &hf_tn5250_wssf_ifc_flag1_1to3,
    &hf_tn5250_wssf_ifc_flag1_4,
    &hf_tn5250_wssf_ifc_flag1_5,
    &hf_tn5250_wssf_ifc_flag1_6,
    &hf_tn5250_wssf_ifc_flag1_7,
    NULL
  };

  static const int *ifc_byte2[] = {
    &hf_tn5250_wssf_ifc_flag2_0,
    &hf_tn5250_wssf_ifc_flag2_1,
    &hf_tn5250_wssf_ifc_flag2_reserved,
    &hf_tn5250_wssf_ifc_flag2_7,
    NULL
  };

  static const int *ifd_byte[] = {
    &hf_tn5250_wssf_ifd_flag1_0,
    &hf_tn5250_wssf_ifd_flag1_reserved,
    NULL
  };


  hf_items standard_fields[] = {
    { hf_tn5250_sf_length, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sf_class, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sf_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  hf_items wsc_customization_fields[] = {
    { hf_tn5250_wssf_flag1, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_flag2, ett_tn5250_wssf_mask, 1, byte, 0 },
    { 0, 0, 0, 0, 0 }
  };

  hf_items wsc_image_control_fields[] = {
    { hf_tn5250_wssf_ifc_flag1, ett_tn5250_wssf_ifc_mask, 1, ifc_byte, 0 },
    { hf_tn5250_wssf_ifc_flag2, ett_tn5250_wssf_ifc_mask, 1, ifc_byte2, 0 },
    { hf_tn5250_wssf_ifc_image_format, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_ifc_viewport_location_row, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_ifc_viewport_location_col, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_ifc_viewport_size_row, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_ifc_viewport_size_col, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_ifc_scaling, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_ifc_viewimage_location_row, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_ifc_viewimage_location_col, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_ifc_rotation, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_ifc_foreground_color, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wssf_ifc_background_color, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  hf_items wsc_image_download_fields[] = {
    { hf_tn5250_wssf_ifd_flag1, ett_tn5250_wssf_ifd_mask, 1, ifd_byte, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_length, 0, 2, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  length = tvb_get_ntohs(tvb,offset);
  type = tvb_get_guint8(tvb, offset+3);

  offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, standard_fields);

  while (tvb_reported_length_remaining(tvb, offset) > 0 && !done) {
    switch (type) {
      case WSC_CUSTOMIZATION:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                      wsc_customization_fields);
        offset += dissect_write_single_structured_field_minor_fields(tn5250_tree, tvb, offset);
        break;
      case IMAGE_FAX_CONTROL:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                      wsc_image_control_fields);
        proto_tree_add_item(tn5250_tree, hf_tn5250_wssf_ifc_imagefax_name, tvb, offset,
                            (length - (start + offset)), ENC_EBCDIC|ENC_NA);
        if (length > (start + offset))
          offset += (guint32)(length - (start + offset));
        break;
      case IMAGE_FAX_DOWNLOAD:
        namelength = tvb_get_ntohs(tvb,offset+6);
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                      wsc_image_download_fields);
        proto_tree_add_item(tn5250_tree, hf_tn5250_wssf_ifd_imagefax_name, tvb, offset,
                            namelength, ENC_EBCDIC|ENC_NA);
        offset += namelength;
        proto_tree_add_item(tn5250_tree, hf_tn5250_wssf_ifd_imagefax_data, tvb, offset,
                            (length - (start + offset)), ENC_NA);
        if (length > (start + offset))
          offset += (guint32)(length - (start + offset));
        break;
      case VIDEO_AUDIO_CONTROLS:
        proto_tree_add_item(tn5250_tree, hf_tn5250_vac_prefix, tvb, offset,
                            2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(tn5250_tree, hf_tn5250_vac_data, tvb, offset,
                            4, ENC_BIG_ENDIAN);
        offset += 2;
        break;
      case TRUE_TRANSPARENCY_WRITE:
        proto_tree_add_item(tn5250_tree, hf_tn5250_wssf_ttw_flag, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        offset ++;
        proto_tree_add_item(tn5250_tree, hf_tn5250_wssf_ttw_data, tvb, offset,
                            (length - (start + offset)), ENC_NA);
        if (length > (start + offset))
          offset += (guint32)(length - (start + offset));
        break;
      default:
        done = 1;
        break;
    }
  }
  offset += dissect_unknown_data(tn5250_tree, tvb, offset, start, length);

  return (offset - start);
}

/* 15.27 WRITE STRUCTURED FIELD Command */
static guint32
dissect_write_structured_field(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;
  guint16 sf_length = 0;
  int length, type, done = 0, used = 0;

  hf_items standard_fields[] = {
    { hf_tn5250_sf_length, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sf_class, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sf_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *qss_byte1[] = {
    &hf_tn5250_wsf_qss_flag1_0,
    &hf_tn5250_wsf_qss_flag1_reserved,
    NULL
  };

  static const int *qss_byte2[] = {
    &hf_tn5250_wsf_qss_flag2_reserved,
    &hf_tn5250_wsf_qss_flag2_7,
    NULL
  };

  hf_items qss_fields[] = {
    { hf_tn5250_wsf_qss_flag1, ett_tn5250_wsf_qss_mask, 1, qss_byte1, 0 },
    { hf_tn5250_wsf_qss_flag2, ett_tn5250_wsf_qss_mask, 1, qss_byte2, 0 },
    { 0, 0, 0, 0, 0 }
  };

  hf_items dawt_fields[] = {
    { hf_tn5250_dawt_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dawt_char, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { 0, 0, 0, 0, 0 }
  };

  hf_items dckf_fields[] = {
    { hf_tn5250_dckf_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dckf_key_code, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dckf_function_code, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *rts_byte1[] = {
    &hf_tn5250_rts_flag1_0,
    &hf_tn5250_rts_flag1_reserved,
    NULL
  };

  hf_items rts_fields[] = {
    { hf_tn5250_rts_partition, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_rts_flag1, ett_tn5250_wsf_rts_mask, 1, rts_byte1, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *dpo_byte1[] = {
    &hf_tn5250_dpo_flag1_0,
    &hf_tn5250_dpo_flag1_1,
    &hf_tn5250_dpo_flag1_2,
    &hf_tn5250_dpo_flag1_3,
    &hf_tn5250_dpo_flag1_4,
    &hf_tn5250_dpo_flag1_5,
    &hf_tn5250_dpo_flag1_6,
    &hf_tn5250_dpo_flag1_7,
    NULL
  };

  static const int *dpo_byte2[] = {
    &hf_tn5250_dpo_flag2_0,
    &hf_tn5250_dpo_flag2_reserved,
    NULL
  };

  hf_items dpo_fields[] = {
    { hf_tn5250_dpo_partition, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dpo_flag1, ett_tn5250_wsf_dpo_mask, 1, dpo_byte1, 0 },
    { hf_tn5250_dpo_flag2, ett_tn5250_wsf_dpo_mask, 1, dpo_byte2, 0 },
    { hf_tn5250_dpo_displace_characters, 0, 3, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_dpo_start_location_row, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dpo_start_location_col, 0, 2, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *dtsf_byte1[] = {
    &hf_tn5250_dtsf_flag1_0,
    &hf_tn5250_dtsf_flag1_1,
    &hf_tn5250_dtsf_flag1_2,
    &hf_tn5250_dtsf_flag1_3,
    &hf_tn5250_dtsf_flag1_4,
    &hf_tn5250_dtsf_flag1_5,
    &hf_tn5250_dtsf_flag1_6,
    &hf_tn5250_dtsf_flag1_7,
    NULL
  };

  static const int *dtsf_byte2[] = {
    &hf_tn5250_dtsf_flag2_0,
    &hf_tn5250_dtsf_flag2_1,
    &hf_tn5250_dtsf_flag2_2,
    &hf_tn5250_dtsf_flag2_3,
    &hf_tn5250_dtsf_flag2_4to7,
    NULL
  };

  hf_items dtsf_fields[] = {
    { hf_tn5250_dtsf_partition, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dtsf_flag1, ett_tn5250_wsf_dtsf_mask, 1, dtsf_byte1, 0 },
    { hf_tn5250_dtsf_flag2, ett_tn5250_wsf_dtsf_mask, 1, dtsf_byte2, 0 },
    { hf_tn5250_dtsf_text_body_height, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dtsf_text_body_width, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dtsf_line_cmd_field_size, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dtsf_location_of_pitch, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dtsf_first_line, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *dsl_byte1[] = {
    &hf_tn5250_dsl_flag1_0,
    &hf_tn5250_dsl_flag1_1,
    &hf_tn5250_dsl_flag1_2,
    &hf_tn5250_dsl_flag1_reserved,
    NULL
  };

  hf_items dsl_fields[] = {
    { hf_tn5250_dsl_partition, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dsl_rtl_offset, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dsl_offset, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  hf_items dsl_fields2[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dsl_flag1, ett_tn5250_wsf_dsl_mask, 1, dsl_byte1, 0 },
    { hf_tn5250_dsl_id, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dsl_location, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dsl_function, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *wts_byte1[] = {
    &hf_tn5250_wts_flag1_0,
    &hf_tn5250_wts_flag1_1,
    &hf_tn5250_wts_flag1_2,
    &hf_tn5250_wts_flag1_3,
    &hf_tn5250_wts_flag1_reserved,
    NULL
  };

  static const int *wts_byte2[] = {
    &hf_tn5250_wts_flag2_reserved,
    &hf_tn5250_wts_flag2_6,
    &hf_tn5250_wts_flag2_reserved2,
    NULL
  };

  static const int *wts_byte3[] = {
    &hf_tn5250_wts_flag3_0,
    &hf_tn5250_wts_flag3_1,
    &hf_tn5250_wts_flag3_2,
    &hf_tn5250_wts_flag3_3,
    &hf_tn5250_wts_flag3_4,
    &hf_tn5250_wts_flag3_5,
    &hf_tn5250_wts_flag3_6,
    &hf_tn5250_wts_flag3_7,
    NULL
  };

  hf_items wts_fields[] = {
    { hf_tn5250_wts_partition, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wts_flag1, ett_tn5250_wts_mask, 1, wts_byte1, 0 },
    { hf_tn5250_wts_flag2, ett_tn5250_wts_mask, 1, wts_byte2, 0 },
    { hf_tn5250_wts_flag3, ett_tn5250_wts_mask, 1, wts_byte3, 0 },
    { hf_tn5250_wts_home_position_row, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wts_home_position_col, 0, 2, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  static const int *wts_cld_byte1[] = {
    &hf_tn5250_wts_cld_flag1_0,
    &hf_tn5250_wts_cld_flag1_1,
    &hf_tn5250_wts_cld_flag1_2,
    &hf_tn5250_wts_cld_flag1_3,
    &hf_tn5250_wts_cld_flag1_4,
    &hf_tn5250_wts_cld_flag1_5,
    &hf_tn5250_wts_cld_flag1_6,
    &hf_tn5250_wts_cld_flag1_7,
    NULL
  };

  static const int *wts_cld_byte2[] = {
    &hf_tn5250_wts_cld_flag2_0,
    &hf_tn5250_wts_cld_flag2_1,
    &hf_tn5250_wts_cld_flag2_2,
    &hf_tn5250_wts_cld_flag2_3,
    &hf_tn5250_wts_cld_flag2_4,
    &hf_tn5250_wts_cld_flag2_line_spacing,
    NULL
  };

  static const int *wts_cld_byte3[] = {
    &hf_tn5250_wts_cld_flag3_0,
    &hf_tn5250_wts_cld_flag3_1,
    &hf_tn5250_wts_cld_flag3_2,
    &hf_tn5250_wts_cld_flag3_3,
    &hf_tn5250_wts_cld_flag3_4,
    &hf_tn5250_wts_cld_flag3_5,
    &hf_tn5250_wts_cld_flag3_6,
    &hf_tn5250_wts_cld_flag3_7,
    NULL
  };

  hf_items wts_line_data_fields[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN }, /*FIXME: Could be one or two bytes! */
    { hf_tn5250_wts_cld_flag1, ett_tn5250_wts_mask, 1, wts_cld_byte1, 0 },
    { hf_tn5250_wts_cld_flag2, ett_tn5250_wts_mask, 1, wts_cld_byte2, 0 },
    { hf_tn5250_wts_cld_row, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wts_cld_flag3, ett_tn5250_wts_mask, 1, wts_cld_byte3, 0 },
    { hf_tn5250_wts_cld_page_num, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wts_cld_lmo, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wts_cld_io, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_wts_cld_sli, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };


  hf_items dsc_fields[] = {
    { hf_tn5250_dsc_partition, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dsc_sk, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dsc_ev, 0, 1, 0, ENC_EBCDIC|ENC_NA },
    { 0, 0, 0, 0, 0 }
  };

  hf_items dorm_fields[] = {
    { hf_tn5250_dorm_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dorm_ec, 0, 2, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };


  static const int *dfdpck_coreflag[] = {
    &hf_tn5250_dfdpck_coreflag_0,
    &hf_tn5250_dfdpck_coreflag_1,
    &hf_tn5250_dfdpck_coreflag_2,
    &hf_tn5250_dfdpck_coreflag_3,
    &hf_tn5250_dfdpck_coreflag_4,
    &hf_tn5250_dfdpck_coreflag_5,
    &hf_tn5250_dfdpck_coreflag_6,
    &hf_tn5250_dfdpck_coreflag_7,
    NULL
  };

  static const int *dfdpck_toprowflag1[] = {
    &hf_tn5250_dfdpck_toprowflag1_0,
    &hf_tn5250_dfdpck_toprowflag1_1,
    &hf_tn5250_dfdpck_toprowflag1_2,
    &hf_tn5250_dfdpck_toprowflag1_3,
    &hf_tn5250_dfdpck_toprowflag1_4,
    &hf_tn5250_dfdpck_toprowflag1_5,
    &hf_tn5250_dfdpck_toprowflag1_6,
    &hf_tn5250_dfdpck_toprowflag1_7,
    NULL
  };

  static const int *dfdpck_toprowflag2[] = {
    &hf_tn5250_dfdpck_toprowflag2_0,
    &hf_tn5250_dfdpck_toprowflag2_1,
    &hf_tn5250_dfdpck_toprowflag2_2,
    &hf_tn5250_dfdpck_toprowflag2_3,
    &hf_tn5250_dfdpck_toprowflag2_4,
    &hf_tn5250_dfdpck_toprowflag2_5,
    &hf_tn5250_dfdpck_toprowflag2_6,
    &hf_tn5250_dfdpck_toprowflag2_7,
    NULL
  };

  static const int *dfdpck_toprowflag3[] = {
    &hf_tn5250_dfdpck_toprowflag3_0,
    &hf_tn5250_dfdpck_toprowflag3_1,
    &hf_tn5250_dfdpck_toprowflag3_2,
    &hf_tn5250_dfdpck_toprowflag3_3,
    &hf_tn5250_dfdpck_toprowflag3_4,
    &hf_tn5250_dfdpck_toprowflag3_5,
    &hf_tn5250_dfdpck_toprowflag3_6,
    &hf_tn5250_dfdpck_toprowflag3_7,
    NULL
  };

  hf_items dfdpck_fields[] = {
    { hf_tn5250_dfdpck_partition, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  hf_items dfdpck_core_area_fields[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dfdpck_data_field, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dfdpck_coreflag, ett_tn5250_dfdpck_mask, 1, dfdpck_coreflag, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  hf_items dfdpck_top_row_fields[] = {
    { hf_tn5250_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dfdpck_data_field, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_dfdpck_toprowflag1, ett_tn5250_dfdpck_mask, 1, dfdpck_toprowflag1, 0 },
    { hf_tn5250_dfdpck_toprowflag2, ett_tn5250_dfdpck_mask, 1, dfdpck_toprowflag2, 0 },
    { hf_tn5250_dfdpck_toprowflag3, ett_tn5250_dfdpck_mask, 1, dfdpck_toprowflag3, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  while (tvb_reported_length_remaining(tvb, offset) > 0 && !done) {
    sf_length = tvb_get_ntohs(tvb,offset);
    type = tvb_get_guint8(tvb, offset+3);

    offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, standard_fields);

    switch (type) {
      case PASS_THROUGH:
        proto_tree_add_item(tn5250_tree, hf_tn5250_field_data, tvb, offset,
                            (sf_length - (start + offset)), ENC_EBCDIC|ENC_NA);
        offset += (guint32)(sf_length - (start + offset));
        break;
      case TN5250_QUERY:
        proto_tree_add_item(tn5250_tree, hf_tn5250_reserved, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        offset ++;
        break;
      case TN5250_QUERY_STATION_STATE:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, qss_fields);
        break;
      case DEFINE_AUDIT_WINDOW__TABLE:
        proto_tree_add_item(tn5250_tree, hf_tn5250_dawt_id, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        while ((offset - start) < sf_length) {
          length = tvb_get_guint8(tvb,offset);
          offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, dawt_fields);
          proto_tree_add_item(tn5250_tree, hf_tn5250_dawt_message, tvb, offset,
                              (length - 2), ENC_EBCDIC|ENC_NA);
          offset += length;
        }
        break;
      case DEFINE_COMMAND_KEY_FUNCTION:
        proto_tree_add_item(tn5250_tree, hf_tn5250_dckf_id, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        while ((offset - start) < sf_length) {
          length = tvb_get_guint8(tvb,offset);
          offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                        dckf_fields);
          proto_tree_add_item(tn5250_tree, hf_tn5250_dckf_prompt_text, tvb,
                              offset, (length - 2), ENC_EBCDIC|ENC_NA);
          offset += length;
        }
        break;
      case READ_TEXT_SCREEN:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, rts_fields);
        break;
      case DEFINE_PENDING_OPERATIONS:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, dpo_fields);
        break;
      case DEFINE_TEXT_SCREEN_FORMAT:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, dtsf_fields);
        break;
      case DEFINE_SCALE_LINE:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, dsl_fields);
        while ((offset - start) < sf_length) {
          /* XXX length unused */
          length = tvb_get_guint8(tvb,offset);
          offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, dsl_fields2);
        }
        break;
      case WRITE_TEXT_SCREEN:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                      wts_fields);
        length = tvb_get_guint8(tvb,offset);
        used = tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                   wts_line_data_fields);
        offset += used;
        proto_tree_add_item(tn5250_tree, hf_tn5250_wts_cld_li, tvb, offset,
                            (length - used), ENC_EBCDIC|ENC_NA);
        break;
      case DEFINE_SPECIAL_CHARACTERS:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                      dsc_fields);
        break;
      case DEFINE_OPERATOR_ERROR_MESSAGES:
        proto_tree_add_item(tn5250_tree, hf_tn5250_dorm_id, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        while ((offset - start) < sf_length) {
          length = tvb_get_guint8(tvb,offset);
          offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                        dorm_fields);
          proto_tree_add_item(tn5250_tree, hf_tn5250_dorm_mt, tvb, offset,
                              (length - 2), ENC_EBCDIC|ENC_NA);
          offset += length;
        }
        break;
      case DEFINE_PITCH_TABLE:
        proto_tree_add_item(tn5250_tree, hf_tn5250_dpt_id, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        while ((offset - start) < sf_length) {
          length = tvb_get_guint8(tvb,offset);
          proto_tree_add_item(tn5250_tree, hf_tn5250_length, tvb, offset,
                              1, ENC_BIG_ENDIAN);
          proto_tree_add_item(tn5250_tree, hf_tn5250_dpt_ec, tvb, offset,
                              length, ENC_EBCDIC|ENC_NA);
          offset += length;
        }
        break;
      case DEFINE_FAKE_DP_COMMAND_KEY_FUNCTION:
        offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                      dfdpck_fields);
        while ((offset - start) < sf_length) {
          length = tvb_get_guint8(tvb,offset);
          type = tvb_get_guint8(tvb,offset+1);
          if (type == CORE_AREA_COMMAND_KEYS) {
            offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                          dfdpck_core_area_fields);
          } else if (type == TOP_ROW_COMMAND_KEYS) {
            offset += tn5250_add_hf_items(tn5250_tree, tvb, offset,
                                          dfdpck_top_row_fields);
          } else {
            offset += dissect_unknown_data(tn5250_tree, tvb, offset, start, length);
          }
        }
        break;
      default:
        done = 1;
        break;
    }
  }

  offset += dissect_unknown_data(tn5250_tree, tvb, offset, start, sf_length);

  return (offset - start);
}

/* 15.27.2 5250 Query Command - Response */
/*TN5250 - RFC1205 - Query Reply Fields */
static guint32
dissect_query_reply(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  int start = offset;

  static const int *byte[] = {
    &hf_tn5250_qr_flag_0,
    &hf_tn5250_qr_flag_reserved,
    NULL
  };

  static const int *byte1[] = {
    &hf_tn5250_qr_flag1_0,
    &hf_tn5250_qr_flag1_1,
    &hf_tn5250_qr_flag1_2,
    &hf_tn5250_qr_flag1_3,
    &hf_tn5250_qr_flag1_4,
    &hf_tn5250_qr_flag1_5,
    &hf_tn5250_qr_flag1_6,
    &hf_tn5250_qr_flag1_7,
    NULL
  };

  static const int *byte2[] = {
    &hf_tn5250_qr_flag2_0to3,
    &hf_tn5250_qr_flag2_4,
    &hf_tn5250_qr_flag2_5,
    &hf_tn5250_qr_flag2_6to7,
    NULL
  };

  hf_items qr_fields[] = {
    { hf_tn5250_sf_length, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sf_class, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sf_type, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_qr_flag, ett_tn5250_qr_mask, 1, byte, 0 },
    { hf_tn5250_qr_chc, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_qr_ccl, 0, 3, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_qr_dt, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_qr_dtc, 0, 4, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_qr_dm, 0, 3, 0, ENC_EBCDIC|ENC_NA },
    { hf_tn5250_qr_ki, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_qr_eki, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_qr_dsn, 0, 4, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_qr_mni, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_qr_flag1, ett_tn5250_qr_mask, 1, byte1, 0 },
    { hf_tn5250_qr_flag2, ett_tn5250_qr_mask, 1, byte2, 0 },
    { hf_tn5250_qr_flag3, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_qr_flag4, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };


  offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, qr_fields);

  return (offset - start);
}

/* End: Handle WCC, Orders and Data */


static guint32
dissect_tn5250_header(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{

  int start=offset;
  int error_flag;

  static const int *byte[] = {
    &hf_tn5250_ds_output_error,
    &hf_tn5250_attn_key,
    &hf_tn5250_sys_request_key,
    &hf_tn5250_test_request_key,
    &hf_tn5250_error_state,
    NULL
  };

  hf_items fields[] = {
    { hf_tn5250_logical_record_length, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_sna_record_type, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_reserved, 0, 2, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_variable_record_length, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_header_flags, ett_tn5250_header_flags, 1, byte, 0 },
    { hf_tn5250_reserved, 0, 1, 0, ENC_BIG_ENDIAN },
    { hf_tn5250_operation_code, 0, 1, 0, ENC_BIG_ENDIAN },
    { 0, 0, 0, 0, 0 }
  };

  error_flag = tvb_get_guint8(tvb, offset+8);

  offset += tn5250_add_hf_items(tn5250_tree, tvb, offset, fields);

  if (error_flag & 0x02) { /*HLP*/
    proto_tree_add_item(tn5250_tree, hf_tn5250_error_code, tvb, offset, 2, ENC_BIG_ENDIAN);
  }

  return (offset - start);
}

#if 0
/* XXX - unused */
/* Detect and Handle Direction of Stream */
static gint
dissect_tn5250_data_until_next_command(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  gint order_code, done = 0;
  gint start = offset;

  while (tvb_reported_length_remaining(tvb, offset) > 0 && !done) {
    order_code = tvb_get_guint8(tvb, offset);
    switch (order_code) {
      case CLEAR_UNIT:
      case CLEAR_FORMAT_TABLE:
      case CLEAR_UNIT_ALTERNATE:
      case WRITE_TO_DISPLAY:
      case WRITE_ERROR_CODE:
      case RESTORE_SCREEN:
      case WRITE_ERROR_CODE_TO_WINDOW:
      case READ_INPUT_FIELDS:
      case READ_MDT_FIELDS:
      case READ_MDT_ALTERNATE:
      case READ_SCREEN:
      case READ_SCREEN_WITH_EXTENDED_ATTRIBUTES:
      case READ_SCREEN_TO_PRINT:
      case READ_SCREEN_TO_PRINT_WITH_EXTENDED_ATTRIBUTES:
      case READ_SCREEN_TO_PRINT_WITH_GRIDLINES:
      case READ_SCREEN_TO_PRINT_WITH_EXTENDED_ATTRIBUTES_AND_GRIDLINES:
      case READ_IMMEDIATE:
      case READ_MODIFIED_IMMEDIATE_ALTERNATE:
      case SAVE_SCREEN:
      case SAVE_PARTIAL_SCREEN:
      case RESTORE_PARTIAL_SCREEN:
      case ROLL:
      case WRITE_SINGLE_STRUCTURED_FIELD:
      case WRITE_STRUCTURED_FIELD:
      case COPY_TO_PRINTER:
        done = 1;
        break;
      default:
        offset++;
        break;
    }
  }

  if (offset > start) {
    proto_tree_add_item(tn5250_tree, hf_tn5250_field_data,
                        tvb, start, (offset - start), ENC_EBCDIC|ENC_NA);
  }

  return (offset - start);
}
#endif

static guint32
dissect_outbound_stream(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset)
{
  gint command_code;
  gint start = offset, length = 0;
  proto_tree   *cc_tree;
  proto_item   *ti;

  /*Escape*/
  ti = proto_tree_add_item(tn5250_tree, hf_tn5250_escape_code, tvb, offset, 1,
                           ENC_BIG_ENDIAN);
  offset++;
  cc_tree = proto_item_add_subtree(ti, ett_cc);

  /* Command Code*/
  command_code = tvb_get_guint8(tvb, offset);
  switch (command_code) {
    case CLEAR_UNIT:
    case CLEAR_FORMAT_TABLE:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      break;
    case CLEAR_UNIT_ALTERNATE:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(cc_tree, hf_tn5250_cua_parm, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      break;
    case WRITE_TO_DISPLAY:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      /* WCC */
      offset += dissect_wcc(cc_tree, tvb, offset);
      offset += dissect_tn5250_orders_and_data(cc_tree, tvb, offset);
      break;
    case WRITE_ERROR_CODE:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code,
                          tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      /* Check for the optional TN5250_IC */
      offset += dissect_tn5250_orders_and_data(cc_tree, tvb, offset);
      /* Add Field Data */
      proto_tree_add_item(cc_tree, hf_tn5250_fa, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(cc_tree, hf_tn5250_field_data, tvb, offset,
                          tvb_reported_length_remaining(tvb, offset) - 1,
                          ENC_EBCDIC|ENC_NA);
      offset += (guint32)(tvb_reported_length_remaining(tvb, offset) - 1);
      proto_tree_add_item(cc_tree, hf_tn5250_fa, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      break;
    case RESTORE_SCREEN:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      while (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset += dissect_outbound_stream(cc_tree, tvb, offset);
      }
      break;
    case WRITE_ERROR_CODE_TO_WINDOW:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(cc_tree, hf_tn5250_wectw_start_column, tvb, offset,
                          1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(cc_tree, hf_tn5250_wectw_end_column, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      break;
    case READ_INPUT_FIELDS:
    case READ_MDT_FIELDS:
    case READ_MDT_ALTERNATE:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      offset += dissect_wcc(cc_tree, tvb, offset);
      break;
    case READ_SCREEN:
    case READ_SCREEN_WITH_EXTENDED_ATTRIBUTES:
    case READ_SCREEN_TO_PRINT:
    case READ_SCREEN_TO_PRINT_WITH_EXTENDED_ATTRIBUTES:
    case READ_SCREEN_TO_PRINT_WITH_GRIDLINES:
    case READ_SCREEN_TO_PRINT_WITH_EXTENDED_ATTRIBUTES_AND_GRIDLINES:
    case READ_IMMEDIATE:
    case READ_MODIFIED_IMMEDIATE_ALTERNATE:
    case SAVE_SCREEN:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      break;
    case SAVE_PARTIAL_SCREEN:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      offset += dissect_save_partial_screen(cc_tree, tvb, offset);
      break;
    case RESTORE_PARTIAL_SCREEN:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      length = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(cc_tree, hf_tn5250_length_twobyte, tvb, offset, 2,
                          ENC_BIG_ENDIAN);
      offset++;
      offset += dissect_tn5250_orders_and_data(cc_tree, tvb, offset);
      proto_tree_add_item(cc_tree, hf_tn5250_field_data, tvb, offset,
                          (length - 2), ENC_EBCDIC|ENC_NA);
      offset++;
      break;
    case ROLL:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      offset += dissect_roll(cc_tree, tvb, offset);
      break;
    case WRITE_SINGLE_STRUCTURED_FIELD:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      offset += dissect_write_single_structured_field(cc_tree, tvb, offset);
      break;
    case WRITE_STRUCTURED_FIELD:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      offset += dissect_write_structured_field(cc_tree, tvb, offset);
      break;
    case COPY_TO_PRINTER:
      proto_tree_add_item(cc_tree, hf_tn5250_command_code, tvb, offset, 1,
                          ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(cc_tree, hf_tn5250_ctp_lsid, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(cc_tree, hf_tn5250_ctp_mlpp, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      break;
    default:
      proto_tree_add_text(cc_tree, tvb, offset, 1, "Bogus value: %u", command_code);
      offset ++;
      break;
  }

  return (offset - start);
}

static guint32
dissect_inbound_stream(proto_tree *tn5250_tree, tvbuff_t *tvb, gint offset, gint sna_flag)
{
  gint start = offset, aid;
  guint32 commands;


  if (sna_flag & 0x01) { /* Stream contains error code */
    proto_tree_add_item(tn5250_tree, hf_tn5250_error_code, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    offset+=2;
    return (offset - start);
  } else if (sna_flag & 0x80) { /* Stream contains negative response */
    proto_tree_add_item(tn5250_tree, hf_tn5250_negative_response,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;
    return (offset - start);
  }

  aid = tvb_get_guint8(tvb,offset+2);
  if (tn5250_is_valid_aid(aid)) {
    switch(aid) {
      case AID_IMAGE_FAX_REQUEST:
      case AID_UNKNOWN_IMAGE_FAX_FORMAT:
      case AID_IMAGE_FAX_ERROR:
        proto_tree_add_item(tn5250_tree, hf_tn5250_image_fax_error, tvb, offset,
                            2, ENC_BIG_ENDIAN);
        offset+=2;
        break;
      default:
        /*Response must be a normal row/col, aid, field data response */
        offset += dissect_row_column(tn5250_tree, tvb, offset);
        break;
    }

    proto_tree_add_item(tn5250_tree, hf_tn5250_aid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (aid == AID_INBOUND_WRITE_STRUCTURED_FIELD) {
      offset += dissect_query_reply(tn5250_tree, tvb, offset);
      return (offset - start);
    }
    /* Check for a response containing order codes */
    offset += dissect_tn5250_orders_and_data(tn5250_tree, tvb, offset);
  } else {
    /* FIXME: need to know when escape/commands are expected. */
    /* Check the response data for commands */
    if (tvb_get_guint8(tvb,offset) == TN5250_ESCAPE) {
      commands = dissect_outbound_stream(tn5250_tree, tvb, offset);
      /* It if contained commands then we're done. Anything else is unexpected data */
      if (commands) {
        offset += commands;
        if (tvb_reported_length_remaining(tvb, offset)) {
          proto_tree_add_item(tn5250_tree, hf_tn5250_unknown_data, tvb, offset,
                              tvb_reported_length_remaining(tvb, offset), ENC_NA);
          offset += tvb_reported_length_remaining(tvb, offset);
        }
        return (offset - start);
      }
    }
  }

  /* Anything else is unformatted field data */
  if (tvb_reported_length_remaining(tvb, offset)) {
    proto_tree_add_item(tn5250_tree, hf_tn5250_field_data, tvb, offset,
                        tvb_reported_length_remaining(tvb, offset),
                        ENC_EBCDIC|ENC_NA);
    offset += tvb_reported_length_remaining(tvb, offset);
  }

  return (offset - start);
}

static void
dissect_tn5250(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree   *tn5250_tree;
  proto_item   *ti;
  gint         offset = 0;
  conversation_t *conversation;
  tn5250_conv_info_t *tn5250_info = NULL;
  int sna_flag;

  pinfo->fd->flags.encoding = PACKET_CHAR_ENC_CHAR_EBCDIC;

  /* Do we have a conversation for this connection? */
  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                   pinfo->ptype, pinfo->srcport,
                                   pinfo->destport, 0);
  if (conversation != NULL) {
    /* Do we already have a type and mechanism? */
    tn5250_info = conversation_get_proto_data(conversation, proto_tn5250);
  }

  if (!tn5250_info)
    return;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TN5250");

  ti = proto_tree_add_item(tree, proto_tn5250, tvb, offset, -1, ENC_NA);
  tn5250_tree = proto_item_add_subtree(ti, ett_tn5250);
  col_clear(pinfo->cinfo, COL_INFO);
  if (pinfo->srcport == tn5250_info->outbound_port) {
    col_set_str(pinfo->cinfo, COL_INFO, "TN5250 Data from Mainframe");
  } else {
    col_set_str(pinfo->cinfo, COL_INFO, "TN5250 Data to Mainframe");
  }

  if (tree) {
    sna_flag = tvb_get_ntohs(tvb, offset+6);
    offset += dissect_tn5250_header(tn5250_tree, tvb, offset);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
      if (pinfo->srcport == tn5250_info->outbound_port) {
        offset += dissect_outbound_stream(tn5250_tree, tvb, offset);
      } else {
        offset += dissect_inbound_stream(tn5250_tree, tvb, offset, sna_flag);
      }
    }
  }

}

void
add_tn5250_conversation(packet_info *pinfo, int tn5250e)
{
  conversation_t *conversation;
  tn5250_conv_info_t *tn5250_info = NULL;

  conversation = find_or_create_conversation(pinfo);

  /*
   * Do we already have a type and mechanism?
   */
  tn5250_info = conversation_get_proto_data(conversation, proto_tn5250);
  if (tn5250_info == NULL) {
    /* No.  Attach that information to the conversation, and add
     * it to the list of information structures.
     */
    tn5250_info = se_alloc(sizeof(tn5250_conv_info_t));
    SE_COPY_ADDRESS(&(tn5250_info->outbound_addr),&(pinfo->dst));
    tn5250_info->outbound_port = pinfo->destport;
    SE_COPY_ADDRESS(&(tn5250_info->inbound_addr),&(pinfo->src));
    tn5250_info->inbound_port = pinfo->srcport;
    conversation_add_proto_data(conversation, proto_tn5250, tn5250_info);
    tn5250_info->next = tn5250_info_items;
    tn5250_info_items = tn5250_info;
  }

  tn5250_info->extended = tn5250e;

}

int
find_tn5250_conversation(packet_info *pinfo)
{
  conversation_t *conversation = NULL;
  tn5250_conv_info_t *tn5250_info = NULL;

  /*
   * Do we have a conversation for this connection?
   */
  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                   pinfo->ptype, pinfo->srcport,
                                   pinfo->destport, 0);

  if (conversation != NULL) {
    tn5250_info = conversation_get_proto_data(conversation, proto_tn5250);

    if (tn5250_info != NULL) {
      /*
       * Do we already have a type and mechanism?
       */
      return 1;
    }
  }
  return 0;
}

void
proto_register_tn5250(void)
{
  static hf_register_info hf[] = {
    { &hf_tn5250_escape_code,
      { "Escape Code",           "tn5250.escape_code",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_escape_codes), 0x0,
        NULL, HFILL }},
    { &hf_tn5250_command_code,
      { "Command Code",           "tn5250.command_code",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_command_codes), 0x0,
        NULL, HFILL }},
    { &hf_tn5250_sf_length,
      {  "Structured Field Length", "tn5250.sf_length",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }},
    { &hf_tn5250_sf_class,
      { "Structured Field Class", "tn5250.class",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_sf_class), 0,
        NULL, HFILL }},
    { &hf_tn5250_sf_type,
      { "Structured Field Type", "tn5250.type",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_sf_type), 0,
        NULL, HFILL }},

    /* 15.4 - Clear Unit Alternate Command Code*/
    { &hf_tn5250_cua_parm,
      { "TN5250 CUA Parameter", "tn5250.cua_parm",
        FT_UINT16, BASE_HEX, VALS(vals_tn5250_cua_parms), 0x0,
        NULL, HFILL }},

    /* 15.6 Write To Display Command Code */
    /* 15.6.1 WTD Control Code */
    { &hf_tn5250_wtd_ccc1,
      {"Write To Display Command Control Character Byte 1", "tn5250.wtd_ccc1",
       FT_UINT8, BASE_HEX,
       VALS (vals_tn5250_wtd_cc_byteone), CCBITS, NULL, HFILL}},
    { &hf_tn5250_wtd_ccc2,
      { "Write To Display Command Control Character Byte 2", "tn5250.wtd_ccc2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wtd_ccc2_res,
      { "Reserved",
        "tn5250.wtd_ccc_reserved", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
    { &hf_tn5250_wtd_ccc2_cursor,
      { "Cursor does not move when keyboard unlocks",
        "tn5250.wtd_ccc_cursor", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
    { &hf_tn5250_wtd_ccc2_reset,
      { "Reset blinking cursor",
        "tn5250.wtd_ccc_reset", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
    { &hf_tn5250_wtd_ccc2_set,
      { "Set blinking cursor",
        "tn5250.wtd_ccc_set", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
    { &hf_tn5250_wtd_ccc2_unlock,
      { "Unlock the keyboard and reset any pending AID bytes",
        "tn5250.wtd_ccc_unlock", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
    { &hf_tn5250_wtd_ccc2_alarm,
      { "Sound Alarm",
        "tn5250.wtd_ccc_alarm", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
    { &hf_tn5250_wtd_ccc2_off,
      { "Set Message Waiting indicator off",
        "tn5250.wtd_ccc_off", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
    { &hf_tn5250_wtd_ccc2_on,
      { "Set Message Waiting indicator on",
        "tn5250.wtd_ccc_on", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},


    /* 15.6.7 Repeat to Address Order */
    { &hf_tn5250_repeated_character,
      { "Repeated Character", "tn5250.repeated_character",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* 15.6.9 Start of Header Order */
    { &hf_tn5250_soh_length,
      { "Length", "tn5250.soh_length",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_soh_flags,
      { "Start of Header Flags", "tn5250.soh_flags",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_soh_cursor_direction,
      { "Right To Left Screen-Level Cursor Direction", "tn5250.soh_cursor_direction",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_tn5250_soh_screen_reverse,
      { "Automatic local screen reverse", "tn5250.soh_screen_reverse",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_tn5250_soh_input_capable_only,
      { "The cursor is allowed to move only to input-capable positions", "tn5250.soh_input_capable_only",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},

    { &hf_tn5250_soh_pf24to17, { "Command Key Switch 1", "tn5250.soh_pf24to17",
                                 FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
    { &hf_tn5250_soh_pf24, { "PF24", "tn5250.soh_pf24",
                             FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
    { &hf_tn5250_soh_pf23, { "PF22", "tn5250.soh_pf23",
                             FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
    { &hf_tn5250_soh_pf22, { "PF22", "tn5250.soh_pf22",
                             FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
    { &hf_tn5250_soh_pf21, { "PF21", "tn5250.soh_pf21",
                             FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
    { &hf_tn5250_soh_pf20, { "PF20", "tn5250.soh_pf20",
                             FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
    { &hf_tn5250_soh_pf19, { "PF19", "tn5250.soh_pf19",
                             FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
    { &hf_tn5250_soh_pf18, { "PF18", "tn5250.soh_pf18",
                             FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
    { &hf_tn5250_soh_pf17, { "PF17", "tn5250.soh_pf17",
                             FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

    { &hf_tn5250_soh_pf16to9, { "Command Key Switch 2", "tn5250.soh_pf16to9",
                                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
    { &hf_tn5250_soh_pf16, { "PF16", "tn5250.soh_pf16",
                             FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
    { &hf_tn5250_soh_pf15, { "PF15", "tn5250.soh_pf15",
                             FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
    { &hf_tn5250_soh_pf14, { "PF14", "tn5250.soh_pf14",
                             FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
    { &hf_tn5250_soh_pf13, { "PF13", "tn5250.soh_pf13",
                             FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
    { &hf_tn5250_soh_pf12, { "PF12", "tn5250.soh_pf12",
                             FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
    { &hf_tn5250_soh_pf11, { "PF11", "tn5250.soh_pf11",
                             FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
    { &hf_tn5250_soh_pf10, { "PF10", "tn5250.soh_pf10",
                             FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
    { &hf_tn5250_soh_pf9, { "PF9", "tn5250.soh_pf9",
                            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

    { &hf_tn5250_soh_pf8to1, { "Command Key Switch 3", "tn5250.soh_pf8to1",
                               FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
    { &hf_tn5250_soh_pf8, { "PF8", "tn5250.soh_pf8",
                            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
    { &hf_tn5250_soh_pf7, { "PF7", "tn5250.soh_pf7",
                            FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
    { &hf_tn5250_soh_pf6, { "PF6", "tn5250.soh_pf6",
                            FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
    { &hf_tn5250_soh_pf5, { "PF5", "tn5250.soh_pf5",
                            FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
    { &hf_tn5250_soh_pf4, { "PF4", "tn5250.soh_pf4",
                            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
    { &hf_tn5250_soh_pf3, { "PF3", "tn5250.soh_pf3",
                            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
    { &hf_tn5250_soh_pf2, { "PF2", "tn5250.soh_pf2",
                            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
    { &hf_tn5250_soh_pf1, { "PF1", "tn5250.soh_pf1",
                            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

    { &hf_tn5250_soh_resq, { "Resequence to Field", "tn5250.soh_resq",
                             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_tn5250_soh_err, { "Error Row", "tn5250.soh_err",
                            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},


    /* 15.6.11.1 Write Extended Attribute Order - Extended Primary Attribute*/
    /* 15.6.12.3 Start of Field Order - Field Attribute*/
    { &hf_tn5250_wea_prim_attr,
      { "Extended Primary Attributes", "tn5250.wea_prim_attr",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wea_prim_attr_flag,
      { "Attribute Change",
        "tn5250.wea_prim_attr_flag", FT_BOOLEAN, 8, NULL,
        0x80, NULL, HFILL }},
    { &hf_tn5250_wea_prim_attr_col,
      { "Column Separator",
        "tn5250.wea_prim_attr_col", FT_BOOLEAN, 8,
        TFS(&tn5250_field_attr_col), 0x10, NULL, HFILL }},
    { &hf_tn5250_wea_prim_attr_blink,
      { "Blink",
        "tn5250.wea_prim_attr_blink", FT_BOOLEAN, 8,
        TFS(&tn5250_field_attr_blink), 0x08, NULL, HFILL }},
    { &hf_tn5250_wea_prim_attr_und,
      { "Underscore",
        "tn5250.wea_prim_attr_und", FT_BOOLEAN, 8,
        TFS(&tn5250_field_attr_und), 0x04, NULL, HFILL }},
    { &hf_tn5250_wea_prim_attr_int,
      { "Intensity",
        "tn5250.wea_prim_attr_int", FT_BOOLEAN, 8,
        TFS(&tn5250_field_attr_int), 0x02, NULL, HFILL }},
    { &hf_tn5250_wea_prim_attr_rev,
      { "Reverse Image",
        "tn5250.wea_prim_attr_rev", FT_BOOLEAN, 8,
        TFS(&tn5250_field_attr_rev), 0x01, NULL, HFILL }},

    /* 15.6.11.2 Write Extended Attribute Order - Foreground Color Attribute*/
    { &hf_tn5250_foreground_color_attr,
      { "Foreground Color Attribute",           "tn5250.foreground_color_attr",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_foreground_color_attributes), 0x0,
        NULL, HFILL }},
    /* 15.6.11.3 Write Extended Attribute Order - Ideographic Attribute*/
    { &hf_tn5250_ideographic_attr,
      { "Ideographic Attribute",           "tn5250.ideographic_attr",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_ideographic_attributes), 0x0,
        NULL, HFILL }},

    /* 15.6.12 Start of Field Order - Field Format Word */
    { &hf_tn5250_ffw,
      { "Field Format Word", "tn5250.ffw",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_ffw_id,
      { "Field Format Word ID", "tn5250.ffw_id", FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_ffw_id), FFW_ID_BITS, NULL, HFILL }},
    { &hf_tn5250_ffw_bypass,
      { "Bypass", "tn5250.ffw_bypass",
        FT_BOOLEAN, 8, TFS(&tn5250_field_ffw_bypass),
        0x20, NULL, HFILL }},
    { &hf_tn5250_ffw_dup,
      { "Dupe or Field Mark Enable", "tn5250.ffw_dup",
        FT_BOOLEAN, 8, TFS(&tn5250_field_ffw_dup),
        0x10, NULL, HFILL }},
    { &hf_tn5250_ffw_mdt,
      { "Modified Data Tag", "tn5250.ffw_mdt",
        FT_BOOLEAN, 8, TFS(&tn5250_field_ffw_mdt),
        0x08, NULL, HFILL }},
    { &hf_tn5250_ffw_shift,
      { "Field Shift/Edit Specification", "tn5250.ffw_shift", FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_ffw_shift), FFW_SHIFT_BITS, NULL, HFILL }},
    { &hf_tn5250_ffw_auto,
      { "Auto Enter", "tn5250.ffw_auto",
        FT_BOOLEAN, 8, TFS(&tn5250_field_ffw_auto),
        0x80, NULL, HFILL }},
    { &hf_tn5250_ffw_fer,
      { "Field Exit Required", "tn5250.ffw_fer",
        FT_BOOLEAN, 8, TFS(&tn5250_field_ffw_fer),
        0x40, NULL, HFILL }},
    { &hf_tn5250_ffw_monocase,
      { "Monocase", "tn5250.ffw_monocase",
        FT_BOOLEAN, 8, TFS(&tn5250_field_ffw_monocase),
        0x20, NULL, HFILL }},
    { &hf_tn5250_ffw_res,
      { "Reserved", "tn5250.ffw_res",
        FT_BOOLEAN, 8, NULL,
        0x10, NULL, HFILL }},
    { &hf_tn5250_ffw_me,
      { "Mandatory Enter", "tn5250.ffw_me",
        FT_BOOLEAN, 8, TFS(&tn5250_field_ffw_me),
        0x08, NULL, HFILL }},
    { &hf_tn5250_ffw_adjust,
      { "Right Adjust/Mandatory Fill", "tn5250.ffw_adjust", FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_ffw_adjust), FFW_ADJUST_BITS, NULL, HFILL }},

    { &hf_tn5250_fcw,
      { "Field Control Word", "tn5250.fcw",
        FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_fcw), 0,
        NULL, HFILL }},

    { &hf_tn5250_fa_color,
      { "Field Attribute (Color)", "tn5250.fa_color",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_fa,
      { "Field Attributes", "tn5250.sf_fa",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_sf_attr_flag,
      { "Attribute ID",
        "tn5250.sf_attr_flag", FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_id), FA_ID_BITS, NULL, HFILL }},
    /* Use Attribute Field fields from 14.6.11.1 for rest of attribute fields */

    /* 15.6.13  Write to Display Structured Field Order */

    /* 15.6.13.1  Write to Display Structured Field Order - Create Window */
    { &hf_tn5250_wdsf_cw_flag1,
      { "Flags", "tn5250.wdsf_cw_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_flag1_1,
      { "Flag 1", "tn5250.wdsf_cw_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_cw_flag1_1),
        0x80, NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_flag1_2,
      { "Flag 2", "tn5250.wdsf_cw_flag1_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_cw_flag1_2),
        0x40, NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_flag1_reserved,
      { "Reserved", "tn5250.wdsf_cw_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0x3F, NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_wd,
      { "Window Depth", "tn5250.wdsf_cw_wd",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_ww,
      { "Window Width", "tn5250.wdsf_cw_ww",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_tn5250_wdsf_cw_minor_type,
      { "Minor Structured Field Type", "tn5250.wdsf_cw_minor_type",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_wdsf_cw_minor_type), 0,
        NULL, HFILL }},

    /* 15.6.13.1  Write to Display Structured Field Order - Create Window - Border Presentation Minor Structure */
    { &hf_tn5250_wdsf_cw_bp_flag1,
      { "Flags", "tn5250.wdsf_cw_bp_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_bp_flag1_1,
      { "Flag 1", "tn5250.wdsf_cw_bp_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_cw_bp_flag1_1),
        0x80, NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_bp_flag1_reserved,
      { "Reserved", "tn5250.wdsf_cw_bp_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0x7F, NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_bp_mba,
      { "Monochrome Border Attribute", "tn5250.wdsf_cw_bp_mba",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_bp_cba,
      { "Color Border Attribute", "tn5250.wdsf_cw_bp_cba",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_bp_ulbc,
      { "Upper Left Border Character", "tn5250.wdsf_cw_bp_ulbc",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_bp_tbc,
      { "Top Border Character", "tn5250.wdsf_cw_bp_tbc",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_bp_urbc,
      { "Upper Right Border Character", "tn5250.wdsf_cw_bp_urbc",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_bp_lbc,
      { "Left Border Character", "tn5250.wdsf_cw_bp_lbc",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_bp_rbc,
      { "Right Border Character", "tn5250.wdsf_cw_bp_rbc",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_bp_llbc,
      { "Lower Left Border Character", "tn5250.wdsf_cw_bp_llbc",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_bp_bbc,
      { "Bottom Border Character", "tn5250.wdsf_cw_bp_bbc",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_bp_lrbc,
      { "Lower Right Border Character", "tn5250.wdsf_cw_bp_lrbc",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.6.13.1  Write to Display Structured Field Order - Create Window - Window/Title Footer Minor Structure */
    { &hf_tn5250_wdsf_cw_tf_flag,
      { "Flags", "tn5250.wdsf_cw_tf_flag",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_tf_flag_orientation,
      { "Orientation", "tn5250.wdsf_cw_tf_flag_orientation", FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_wdsf_cw_tf_flag_orientation), WTF_BITS, NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_tf_flag_1,
      { "Title/Footer Defined", "tn5250.wdsf_cw_tf_flag_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_cw_tf_flag_1),
        0x20, NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_tf_flag_reserved,
      { "Reserved", "tn5250.wdsf_cw_tf_flag_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xF8, NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_tf_mba,
      { "Monochrome Title/Footer Attribute", "tn5250.wdsf_cw_tf_mba",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_tf_cba,
      { "Color Title/Footer Attribute", "tn5250.wdsf_cw_tf_cba",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cw_tf_text,
      { "Title Text", "tn5250.wdsf_cw_tf_text",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.6.13.2  Write to Display Structured Field Order - Unrestricted Window Cursor Movement */
    /* Consists of reserved fields only */

    /* 15.6.13.3  Write to Display Structured Field Order - Remove GUI Window */
    { &hf_tn5250_wdsf_rgw_flag1,
      { "Flags", "tn5250.wdsf_rgw_flag",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_rgw_flag1_0,
      { "Reserved", "tn5250.wdsf_rgw_flag1_0",
        FT_BOOLEAN, 8, NULL,
        0x80, NULL, HFILL }},
    { &hf_tn5250_wdsf_rgw_flag1_1,
      { "Window Pull-Down", "tn5250.wdsf_rgw_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_cw_flag1_2),
        0x40, NULL, HFILL }},
    { &hf_tn5250_wdsf_rgw_reserved,
      { "Reserved", "tn5250.wdsf_rgw_flag_reserved", FT_UINT8, BASE_HEX,
        NULL, 0x3F, NULL, HFILL }},

    /* 15.6.13.4  Write to Display Structured Field Order - Remove All GUI Constructs*/
    { &hf_tn5250_wdsf_ragc_flag1,
      { "Flags", "tn5250.wdsf_ragc_flag",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ragc_flag1_0,
      { "GUI-Like Characters", "tn5250.wdsf_ragc_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ragc_flag1_0),
        0x80, NULL, HFILL }},
    { &hf_tn5250_wdsf_ragc_reserved,
      { "Reserved", "tn5250.wdsf_ragc_flag_reserved", FT_UINT8, BASE_HEX,
        NULL, 0x7F, NULL, HFILL }},

    /* 15.6.13.5  Write to Display Structured Field Order - Define Selection Field*/
    { &hf_tn5250_wdsf_ds_flag1,
      { "Flags", "tn5250.wdsf_ds_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag1_mouse_characteristics,
      { "Mouse Characteristics", "tn5250.wdsf_ds_flag1_mouse_characteristics", FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_wdsf_ds_flag1_mouse_characteristics), MOUSE_CHARACTERISTICS_BITS, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag1_reserved,
      { "Reserved", "tn5250.wdsf_ds_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0x0C, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag1_auto_enter,
      { "Mouse Characteristics", "tn5250.wdsf_ds_flag1_auto_enter", FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_wdsf_ds_flag1_auto_enter), DS_AUTO_ENTER_BITS, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag1_1,
      { "Auto Select", "tn5250.wdsf_ds_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_flag1_1),
        0x40, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag1_2,
      { "Field MDT", "tn5250.wdsf_ds_flag1_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_flag1_2),
        0x80, NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_flag2,
      { "Flags", "tn5250.wdsf_ds_flag2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag2_1,
      { "Bit 0", "tn5250.wdsf_ds_flag2_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_flag2_1),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag2_2,
      { "Bit 1", "tn5250.wdsf_ds_flag2_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_flag2_2),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag2_3,
      { "Bit 2", "tn5250.wdsf_ds_flag2_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_flag2_3),
        0x04, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag2_4,
      { "Bit 3", "tn5250.wdsf_ds_flag2_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_flag2_4),
        0x08, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag2_5,
      { "Bit 4", "tn5250.wdsf_ds_flag2_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_flag2_5),
        0x10, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag2_6,
      { "Bit 5", "tn5250.wdsf_ds_flag2_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_flag2_6),
        0x20, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag2_reserved,
      { "Reserved", "tn5250.wdsf_ds_flag3_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xC0, NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_flag3,
      { "Flags", "tn5250.wdsf_ds_flag3",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag3_1,
      { "Bit 0", "tn5250.wdsf_ds_flag3_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_flag3_1),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_flag3_reserved,
      { "Reserved", "tn5250.wdsf_ds_flag3_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_type,
      { "Type of Selection Field", "tn5250.wdsf_ds_type",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_wdsf_ds_type), 0,
        NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_gdc,
      { "GUI Device Characteristics", "tn5250.wdsf_ds_gdc",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_gdc_indicators,
      { "Indicators", "tn5250.wdsf_ds_gdc_indicators", FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_wdsf_ds_gdc_indicators), DS_INDICATORS_BITS, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_gdc_reserved,
      { "Reserved", "tn5250.wdsf_ds_gdc_reserved", FT_BOOLEAN, 8,
        NULL, 0x10, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_gdc_selection_techniques,
      { "Selection Techniques", "tn5250.wdsf_ds_selection_techniques", FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_wdsf_ds_gdc_selection_techniques), DS_SELECTION_TECHNIQUES_BITS, NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_nws,
      { "NWS With Mnemonic Underscore Characteristics", "tn5250.wdsf_ds_nws",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_nws_indicators,
      { "Indicators", "tn5250.wdsf_ds_nws_indicators", FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_wdsf_ds_nws_indicators), DS_NWS_INDICATORS_BITS, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_nws_reserved,
      { "Reserved", "tn5250.wdsf_ds_nws_reserved", FT_BOOLEAN, 8,
        NULL, 0x10, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_nws_selection_techniques,
      { "Selection Techniques", "tn5250.wdsf_ds_selection_techniques", FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_wdsf_ds_nws_selection_techniques), DS_NWS_SELECTION_TECHNIQUES_BITS, NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_nws_wout,
      { "NWS Without Mnemonic Underscore Characteristics", "tn5250.wdsf_ds_nws",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    /* hf_tn5250_wdsf_ds_nws_wout uses same bitfields as hf_tn5250_wdsf_ds_nws */

    { &hf_tn5250_wdsf_ds_textsize,
      { "Text Size", "tn5250.wdsf_ds_textsize",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_rows,
      { "Rows", "tn5250.wdsf_ds_rows",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_columns,
      { "Columns/Menu Bar Choices", "tn5250.wdsf_ds_columns",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_padding,
      { "Padding Between Choices", "tn5250.wdsf_ds_padding",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_numeric_sep,
      { "Numeric Separator Character", "tn5250.wdsf_ds_numeric_sep",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_country_sel,
      { "Country Specific Selection Character", "tn5250.wdsf_ds_country_sel",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cancel_aid,
      { "Mouse Pull-Down Cancel AID", "tn5250.wdsf_ds_cancel_aid",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_totalrows,
      { "Total Rows or Minor Structures That Can Be Scrolled", "tn5250.wdsf_ds_totalrows",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_sliderpos,
      { "Slider Positions That Can Be Scrolled", "tn5250.wdsf_ds_sliderpos",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_minor_type,
      { "Minor Structured Field Type", "tn5250.wdsf_ds_minor_type",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_wdsf_ds_minor_type), 0,
        NULL, HFILL }},

    /* 15.6.13.5  Write to Display Structured Field Order - Define Selection Field - Choice Text Minor Structure*/
    { &hf_tn5250_wdsf_ds_ct_flag1,
      { "Flag Byte 1", "tn5250.wdsf_ds_ct_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag1_choice_state,
      { "Choice State", "tn5250.wdsf_ds_ct_flag1_choice_state", FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_wdsf_ds_ct_flag1_choice_state), DS_CHOICE_STATE_BITS, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag1_2,
      { "Bit 2", "tn5250.wdsf_ds_ct_flag1_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag1_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag1_3,
      { "Bit 3", "tn5250.wdsf_ds_ct_flag1_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag1_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag1_4,
      { "Bit 4", "tn5250.wdsf_ds_ct_flag1_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag1_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag1_5,
      { "Bit 5", "tn5250.wdsf_ds_ct_flag1_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag1_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag1_numeric_selection,
      { "Numeric Selection Characters", "tn5250.wdsf_ds_ct_flag1_numeric_selection", FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_wdsf_ds_ct_flag1_numeric_selection), DS_NUMERIC_SELECTION_BITS, NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_ct_flag2,
      { "Flag Byte 2", "tn5250.wdsf_ds_ct_flag2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag2_0,
      { "Bit 0", "tn5250.wdsf_ds_ct_flag2_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag2_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag2_1,
      { "Bit 1", "tn5250.wdsf_ds_ct_flag2_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag2_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag2_2,
      { "Bit 2", "tn5250.wdsf_ds_ct_flag2_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag2_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag2_3,
      { "Bit 3", "tn5250.wdsf_ds_ct_flag2_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag2_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag2_4,
      { "Bit 4", "tn5250.wdsf_ds_ct_flag2_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag2_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag2_5,
      { "Bit 5", "tn5250.wdsf_ds_ct_flag2_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag2_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag2_6,
      { "Bit 6", "tn5250.wdsf_ds_ct_flag2_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag2_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag2_7,
      { "Bit 7", "tn5250.wdsf_ds_ct_flag2_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag2_7),
        0x80, NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_ct_flag3,
      { "Flag Byte 3", "tn5250.wdsf_ds_ct_flag3",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag3_0,
      { "Bit 0", "tn5250.wdsf_ds_ct_flag3_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag3_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag3_1,
      { "Bit 1", "tn5250.wdsf_ds_ct_flag3_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag3_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag3_2,
      { "Bit 2", "tn5250.wdsf_ds_ct_flag3_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ct_flag3_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_flag3_reserved,
      { "Reserved", "tn5250.wdsf_ds_ct_flag3_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xF8, NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_ct_mnemonic_offset,
      { "Mnemonic Offset", "tn5250.wdsf_ds_ct_mnemonic_offset",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_aid,
      { "AID", "tn5250.wdsf_ds_ct_aid",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_numeric_onebyte,
      { "Numeric Characters", "tn5250.wdsf_ds_ct_numeric",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_numeric_twobyte,
      { "Numeric Characters", "tn5250.wdsf_ds_ct_numeric",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ct_text,
      { "Choice Text", "tn5250.wdsf_ds_ct_text",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.6.13.5  Write to Display Structured Field Order - Define Selection Field - Menu Bar Separator Minor Structure*/

    { &hf_tn5250_wdsf_ds_mbs_flag,
      { "Flags", "tn5250.wdsf_ds_mbs_flag",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_mbs_flag_0,
      { "Bit 0", "tn5250.wdsf_ds_mbs_flag_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_mbs_flag_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_mbs_flag_1,
      { "Bit 1", "tn5250.wdsf_ds_mbs_flag_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_mbs_flag_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_mbs_flag_reserved,
      { "Reserved", "tn5250.wdsf_ds_mbs_flag_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xF8, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_mbs_start_column,
      { "Start Column", "tn5250.wdsf_ds_mbs_start_column",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_mbs_end_column,
      { "End Column", "tn5250.wdsf_ds_mbs_end_column",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_mbs_monochrome_sep,
      { "Monochrome Separator Emphasis", "tn5250.wdsf_ds_mbs_monochrome_sep",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_mbs_color_sep,
      { "Color Separator Emphasis", "tn5250.wdsf_ds_mbs_color_sep",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_mbs_sep_char,
      { "Separator Character", "tn5250.wdsf_ds_mbs_sep_char",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.6.13.5  Write to Display Structured Field Order - Define Selection Field - Choice Presentation Display Attributes Minor Structure*/
    { &hf_tn5250_wdsf_ds_cpda_flag1,
      { "Flags", "tn5250.wdsf_ds_cpda_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_flag1_0,
      { "Bit 0", "tn5250.wdsf_ds_cpda_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_cpda_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_flag1_1,
      { "Bit 1", "tn5250.wdsf_ds_cpda_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_cpda_flag1_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_flag1_2,
      { "Bit 2", "tn5250.wdsf_ds_cpda_flag1_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_cpda_flag1_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_flag1_reserved,
      { "Reserved", "tn5250.wdsf_ds_cpda_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xF8, NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_cpda_monochrome_sel_avail,
      { "Monochrome Selection Cursor Available Emphasis", "tn5250.wdsf_ds_cpda_monochrome_sel_avail",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_color_sel_avail,
      { "Color Selection Cursor Available Emphasis", "tn5250.wdsf_ds_cpda_color_sel_avail",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_monochrome_sel_selected,
      { "Monochrome Selection Cursor Selected Emphasis", "tn5250.wdsf_ds_cpda_monochrome_sel_selected",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_color_sel_selected,
      { "Color Selection Cursor Selected Emphasis", "tn5250.wdsf_ds_cpda_color_sel_selected",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_cpda_monochrome_sel_unavail,
      { "Monochrome Selection Cursor Unavailable Emphasis", "tn5250.wdsf_ds_cpda_monochrome_sel_unavail",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_color_sel_unavail,
      { "Color Selection Cursor Unavailable Emphasis", "tn5250.wdsf_ds_cpda_color_sel_unavail",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_cpda_monochrome_avail,
      { "Monochrome Available Emphasis", "tn5250.wdsf_ds_cpda_monochrome_avail",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_color_avail,
      { "Color Available Emphasis", "tn5250.wdsf_ds_cpda_color_avail",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_cpda_monochrome_selected,
      { "Monochrome Selected Emphasis", "tn5250.wdsf_ds_cpda_monochrome_selected",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_color_selected,
      { "Color Selected Emphasis", "tn5250.wdsf_ds_cpda_color_selected",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_cpda_monochrome_unavail,
      { "Monochrome Unavailable Emphasis", "tn5250.wdsf_ds_cpda_monochrome_unavail",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_color_unavail,
      { "Color Unavailable Emphasis", "tn5250.wdsf_ds_cpda_color_unavail",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_cpda_monochrome_indicator,
      { "Monochrome Indicator Emphasis", "tn5250.wdsf_ds_cpda_monochrome_indicator",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_color_indicator,
      { "Color Indicator Emphasis", "tn5250.wdsf_ds_cpda_color_indicator",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_cpda_monochrome_unavail_indicator,
      { "Monochrome Unavailable Indicator Emphasis", "tn5250.wdsf_ds_cpda_monochrome_unavail_indicator",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_cpda_color_unavail_indicator,
      { "Color Unavailable Indicator Emphasis", "tn5250.wdsf_ds_cpda_color_unavail_indicator",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},



    /* 15.6.13.5  Write to Display Structured Field Order - Define Selection Field - Choice Indicators Minor Structure*/
    { &hf_tn5250_wdsf_ds_ci_flag1,
      { "Flags", "tn5250.wdsf_ds_ci_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ci_flag1_0,
      { "Bit 0", "tn5250.wdsf_ds_ci_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_ci_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ci_flag1_reserved,
      { "Reserved", "tn5250.wdsf_ds_ci_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_ci_left_push,
      { "Empty Indicator or Left Push Button", "tn5250.wdsf_ds_ci_left_push",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ci_right_push,
      { "Selected Indicator or Right Push Button", "tn5250.wdsf_ds_ci_right_push",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_ci_first_choice,
      { "Character That Replaces the First Choice Text Character for Unavailable Choices On a Monochrome Display", "tn5250.wdsf_ds_ci_first_choice",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.6.13.5  Write to Display Structured Field Order - Define Selection Field - Scroll Bar Indicators Minor Structure*/
    { &hf_tn5250_wdsf_ds_sbi_flag1,
      { "Flags", "tn5250.wdsf_ds_sbi_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_sbi_flag1_0,
      { "Bit 0", "tn5250.wdsf_ds_sbi_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_ds_sbi_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_sbi_flag1_reserved,
      { "Reserved", "tn5250.wdsf_ds_sbi_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_sbi_monochrome_top_highlight,
      { "Monochrome Top of ScrollBar Highlighting", "tn5250.wdsf_ds_sbi_monochrome_top_highlight",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_sbi_color_top_highlight,
      { "Color Top of ScrollBar Highlighting", "tn5250.wdsf_ds_sbi_color_top_highlightl",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_sbi_monochrome_top_highlight_shaft,
      { "Monochrome Shaft ScrollBar Highlighting", "tn5250.wdsf_ds_sbi_monochrome_top_highlight_shaft",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_sbi_color_top_highlight_shaft,
      { "Color Shaft ScrollBar Highlighting", "tn5250.wdsf_ds_sbi_color_top_highlight_shaft",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},

    { &hf_tn5250_wdsf_ds_sbi_top_character,
      { "Top Scroll Bar Character", "tn5250.wdsf_ds_sbi_top_character",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_sbi_bottom_character,
      { "Bottom Scroll Bar Character", "tn5250.wdsf_ds_sbi_bottom_character",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_sbi_empty_character,
      { "Empty Scroll Bar Character", "tn5250.wdsf_ds_sbi_empty_character",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_ds_sbi_slider_character,
      { "Slider Scroll Bar Character", "tn5250.wdsf_ds_sbi_slider_character",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.6.13.6  Write to Display Structured Field Order - Remove GUI Selection Field */
    /* Consists of reserved fields only */

    /* 15.6.13.7  Write to Display Structured Field Order - Define Scroll Bar Field */
    { &hf_tn5250_wdsf_dsb_flag1,
      { "Flags", "tn5250.wdsf_dsb_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_dsb_flag1_0,
      { "Bit 0", "tn5250.wdsf_dsb_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_dsb_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_dsb_flag1_1,
      { "Bit 1", "tn5250.wdsf_dsb_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_dsb_flag1_0),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wdsf_dsb_flag1_reserved,
      { "Reserved", "tn5250.wdsf_dsb_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0x7C, NULL, HFILL }},
    { &hf_tn5250_wdsf_dsb_flag1_7,
      { "Bit 7", "tn5250.wdsf_dsb_flag1_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_dsb_flag1_7),
        0x80, NULL, HFILL }},

    { &hf_tn5250_wdsf_sbi_total_scroll,
      { "TotalRows or TotalCols That Can  Be Scrolled", "tn5250.wdsf_sbi_total_scroll",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_sbi_sliderpos,
      { "SliderPos", "tn5250.wdsf_sbi_sliderpos",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_sbi_rowscols,
      { "Rows or Columns", "tn5250.wdsf_sbi_rowscols",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    /* 15.6.13.8  Write to Display Structured Field Order - Remove GUI Scroll Bar Field */
    /* Consists of reserved fields only */

    /* 15.6.13.9  Write to Display Structured Field Order - Write Data Field */
    { &hf_tn5250_wdsf_wdf_flag1,
      { "Flags", "tn5250.wdsf_wdf_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_wdf_flag1_0,
      { "Bit 0", "tn5250.wdsf_wdf_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_wdf_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_wdf_flag1_reserved,
      { "Reserved", "tn5250.wdsf_wdf_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},

    /* 15.6.13.10  Write to Display Structured Field Order - Programmable Mouse Buttons */
    { &hf_tn5250_wdsf_pmb_flag1,
      { "Flags", "tn5250.wdsf_pmb_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_pmb_flag1_0,
      { "Bit 0", "tn5250.wdsf_pmb_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_pmb_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_pmb_flag1_1,
      { "Bit 1", "tn5250.wdsf_pmb_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_pmb_flag1_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wdsf_pmb_flag1_2,
      { "Bit 2", "tn5250.wdsf_pmb_flag1_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_pmb_flag1_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_wdsf_pmb_flag1_3,
      { "Bit 3", "tn5250.wdsf_pmb_flag1_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_pmb_flag1_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_wdsf_pmb_flag1_reserved,
      { "Reserved", "tn5250.wdsf_pmb_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xF0, NULL, HFILL }},
    { &hf_tn5250_wdsf_pmb_first_mouse_event,
      { "First Mouse Event (Leading Edge Event)", "tn5250.wdsf_pmb_first_mouse_event",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_mouse_events), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_pmb_second_mouse_event,
      { "Second Mouse Event (Trailing Edge Event)", "tn5250.wdsf_pmb_second_mouse_event",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_mouse_events), 0,
        NULL, HFILL }},

    /* 15.7 Draw/Erase Grid Lines Structured Field */
    { &hf_tn5250_wdsf_deg_partition,
      { "Partition", "tn5250.wdsf_deg_partition",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_flag1,
      { "Flags", "tn5250.wdsf_deg_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_flag1_0,
      { "Bit 0", "tn5250.wdsf_deg_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_deg_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_flag1_reserved,
      { "Reserved", "tn5250.wdsf_deg_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_flag2,
      { "Flags", "tn5250.wdsf_deg_flag2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_flag2_0,
      { "Bit 0", "tn5250.wdsf_deg_flag2_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_deg_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_flag2_reserved,
      { "Reserved", "tn5250.wdsf_deg_flag2_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_default_color,
      { "Default Color for Grid Lines", "tn5250.wdsf_deg_default_color",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_default_line,
      { "Default Line Style", "tn5250.wdsf_deg_default_line",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_deg_lines), 0,
        NULL, HFILL }},

    /* 15.7.1 Draw/Erase Grid Lines Structured Field - Minor Structure*/
    { &hf_tn5250_wdsf_deg_minor_type,
      { "Construct", "tn5250.wdsf_deg_minor_type",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_wdsf_deg_minor_type), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_ms_flag1,
      { "Flags", "tn5250.wdsf_deg_ms_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_ms_flag1_0,
      { "Bit 0", "tn5250.wdsf_deg_ms_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wdsf_deg_ms_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_ms_flag1_reserved,
      { "Reserved", "tn5250.wdsf_deg_ms_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_ms_start_row,
      { "Start Row", "tn5250.wdsf_deg_ms_start_row",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_ms_start_column,
      { "Start Column", "tn5250.wdsf_deg_ms_start_column",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_ms_horizontal_dimension,
      { "Horizontal Dimenstion", "tn5250.wdsf_deg_ms_horizontal_dimension",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_ms_vertical_dimension,
      { "Vertical Dimenstion", "tn5250.wdsf_deg_ms_vertical_dimension",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_ms_default_color,
      { "Color", "tn5250.wdsf_deg_ms_default_color",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_fa_color), 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_ms_line_repeat,
      { "Line Repeat", "tn5250.wdsf_deg_ms_line_repeat",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_deg_ms_line_interval,
      { "Line Interval", "tn5250.wdsf_deg_ms_line_interval",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    /* 15.7.2 Clear Grid Lines Structured Field */
    { &hf_tn5250_wdsf_cgl_partition,
      { "Partition", "tn5250.wdsf_cgl_partition",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cgl_start_row,
      { "Start Row", "tn5250.wdsf_cgl_start_row",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cgl_start_column,
      { "Start Column", "tn5250.wdsf_cgl_start_column",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cgl_rectangle_width,
      { "Width of Rectangle", "tn5250.wdsf_cgl_rectangle_width",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wdsf_cgl_rectangle_height,
      { "Height of Rectangle", "tn5250.wdsf_cgl_rectangle_height",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    /* 15.8 WRITE ERROR CODE Command */
    /* 15.9 WRITE ERROR CODE TO WINDOW Command */
    { &hf_tn5250_wectw_start_column,
      { "Start Column", "tn5250.wectw_start_column",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wectw_end_column,
      { "End Column", "tn5250.wectw_end_column",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    /* 15.22 SAVE PARTIAL SCREEN Command */
    { &hf_tn5250_sps_flag1,
      { "Flags", "tn5250.sps_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_sps_flag1_0,
      { "Bit 0", "tn5250.sps_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_sps_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_sps_flag1_reserved,
      { "Reserved", "tn5250.sps_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},
    { &hf_tn5250_sps_top_row,
      { "Top Row", "tn5250.sps_top_row",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_sps_left_column,
      { "Left Column", "tn5250.sps_left_column",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_sps_window_depth,
      { "Window Depth", "tn5250.sps_window_depth",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_sps_window_width,
      { "Window Width", "tn5250.sps_window_width",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    /* 15.25 ROLL Command */
    { &hf_tn5250_roll_flag1,
      { "Byte 1", "tn5250.roll_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_roll_flag1_0,
      { "Bit 0", "tn5250.roll_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_roll_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_roll_flag1_reserved,
      { "Reserved", "tn5250.roll_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0x06, NULL, HFILL }},
    { &hf_tn5250_roll_flag1_lines,
      { "Number of lines that the designated area is to be rolled", "tn5250.roll_flag1_lines", FT_UINT8, BASE_DEC,
        NULL, 0xF8, NULL, HFILL }},
    { &hf_tn5250_roll_top_line,
      { "Line number defining the top line of the area that will participate in the roll", "tn5250.roll_top_line",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_roll_bottom_line,
      { "Line number defining the bottom line of the area that will participate in the roll", "tn5250.roll_bottom_line",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    /* 15.26.1 WRITE SINGLE STRUCTURED FIELD Command - 5250 WSC CUSTOMIZATION Command*/
    { &hf_tn5250_wssf_wsc_minor_type,
      { "Minor Structured Field Type", "tn5250.wssf_wsc_minor_type",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_wssf_minor_type), 0,
        NULL, HFILL }},

    { &hf_tn5250_wssf_flag1,
      { "Byte 1", "tn5250.wssf_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wssf_flag2,
      { "Byte 2", "tn5250.wssf_flag2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wssf_flag2_0,
      { "Bit 0", "tn5250.wssf_flag2_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_flag2_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wssf_flag2_1,
      { "Bit 1", "tn5250.wssf_flag2_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_flag2_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wssf_flag2_2,
      { "Bit 2", "tn5250.wssf_flag2_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_flag2_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_wssf_flag2_3,
      { "Bit 3", "tn5250.wssf_flag2_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_flag2_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_wssf_flag2_4,
      { "Bit 4", "tn5250.wssf_flag2_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_flag2_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_wssf_flag2_5,
      { "Bit 5", "tn5250.wssf_flag2_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_flag2_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_wssf_flag2_6,
      { "Bit 6", "tn5250.wssf_flag2_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_flag2_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_wssf_flag2_7,
      { "Bit 7", "tn5250.wssf_flag2_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_flag2_7),
        0x80, NULL, HFILL }},

    /* 15.26.1 WRITE SINGLE STRUCTURED FIELD Command - 5250 WSC CUSTOMIZATION Command
       - Keystroke Buffering Control Minor Structure*/
    { &hf_tn5250_wssf_kbc_flag1,
      { "Byte 1", "tn5250.wssf_kbc_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wssf_kbc_flag1_reserved,
      { "Reserved", "tn5250.wssf_kbc_flag1_reserved", FT_UINT8, BASE_HEX|BASE_RANGE_STRING,
        RVALS(vals_tn5250_reserved), 0x1F, NULL, HFILL }},
    { &hf_tn5250_wssf_kbc_flag1_5,
      { "Bit 5", "tn5250.wssf_kbc_flag1_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_kbc_flag1_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_wssf_kbc_flag1_6,
      { "Bit 6", "tn5250.wssf_kbc_flag1_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_kbc_flag1_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_wssf_kbc_flag1_7,
      { "Bit 7", "tn5250.wssf_kbc_flag1_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_kbc_flag1_7),
        0x80, NULL, HFILL }},

    /* 15.26.1 WRITE SINGLE STRUCTURED FIELD Command - 5250 WSC CUSTOMIZATION Command
       - Cursor Control Minor Structure*/
    { &hf_tn5250_wssf_cc_flag1,
      { "Byte 1", "tn5250.wssf_cc_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wssf_cc_flag1_reserved,
      { "Reserved", "tn5250.wssf_cc_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0x7F, NULL, HFILL }},
    { &hf_tn5250_wssf_cc_flag1_7,
      { "Bit 7", "tn5250.wssf_cc_flag1_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_cc_flag1_7),
        0x80, NULL, HFILL }},

    /* 15.26.2 WRITE SINGLE STRUCTURED FIELD Command - IMAGE/FAX CONTROL Command */
    { &hf_tn5250_wssf_ifc_flag1,
      { "Byte 1", "tn5250.wssf_ifc_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_flag1_0,
      { "Bit 0 (Cache allowed flag)", "tn5250.wssf_ifc_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_ifc_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_flag1_1to3,
      { "Bits 1-3 (Type of image/fax display)", "tn5250.wssf_ifc_flag1_1to3", FT_UINT8, BASE_HEX,
        VALS(tn5250_vals_tn5250_wssf_ifc_vals), 0x0E, NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_flag1_4,
      { "Bit 4 (Color importance during scaling)", "tn5250.wssf_ifc_flag1_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_ifc_flag1_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_flag1_5,
      { "Bit 5 (Allow display to control scaling)", "tn5250.wssf_ifc_flag1_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_ifc_flag1_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_flag1_6,
      { "Bit 6 (Reverse image)", "tn5250.wssf_ifc_flag1_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_ifc_flag1_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_flag1_7,
      { "Bit 7 (Allow/Inhibit EasyScroll with a mouse)", "tn5250.wssf_ifc_flag1_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_ifc_flag1_7),
        0x80, NULL, HFILL }},

    { &hf_tn5250_wssf_ifc_flag2,
      { "Byte 2", "tn5250.wssf_ifc_flag2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_flag2_0,
      { "Bit 0 (Duplicate Scan Lines)", "tn5250.wssf_ifc_flag2_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_ifc_flag2_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_flag2_1,
      { "Bit 1 (Allow/Inhibit Trim Magnify Scaling)", "tn5250.wssf_ifc_flag2_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_ifc_flag2_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_flag2_reserved,
      { "Reserved", "tn5250.wssf_ifc_flag2_reserved", FT_UINT8, BASE_HEX,
        NULL, 0x7C, NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_flag2_7,
      { "Bit 7", "tn5250.wssf_ifc_flag2_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_ifc_flag2_7),
        0x80, NULL, HFILL }},

    { &hf_tn5250_wssf_ifc_image_format,
      { "Image Format", "tn5250.wssf_ifc_image_format",
        FT_UINT16, BASE_DEC, VALS(vals_tn5250_image_format), 0,
        NULL, HFILL }},

    { &hf_tn5250_wssf_ifc_viewport_location_row,
      { "Viewport Location (Row)", "tn5250.wssf_ifc_viewport_location_row",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_viewport_location_col,
      { "Viewport Location (Column)", "tn5250.wssf_ifc_viewport_location_col",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_viewport_size_row,
      { "Viewport Size (Row)", "tn5250.wssf_ifc_viewport_size_row",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_viewport_size_col,
      { "Viewport Size (Column)", "tn5250.wssf_ifc_viewport_size_col",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_tn5250_wssf_ifc_scaling,
      { "Scaling", "tn5250.wssf_ifc_scaling",
        FT_UINT16, BASE_HEX, VALS(vals_tn5250_wssf_ifc_scaling), 0,
        NULL, HFILL }},

    { &hf_tn5250_wssf_ifc_viewimage_location_row,
      { "View Image Location (Vertical Percentage)", "tn5250.wssf_ifc_viewimage_location_row",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wssf_ifc_viewimage_location_col,
      { "View Image Location (Horizontal Position)", "tn5250.wssf_ifc_viewimage_location_col",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_tn5250_wssf_ifc_rotation,
      { "Rotation (Degrees)", "tn5250.wssf_ifc_rotation",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_tn5250_wssf_ifc_foreground_color,
      { "Foreground Color", "tn5250.wssf_ifc_foreground_color",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_foreground_color_attributes), 0,
        NULL, HFILL }},

    { &hf_tn5250_wssf_ifc_background_color,
      { "Background Color", "tn5250.wssf_ifc_background_color",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_foreground_color_attributes), 0,
        NULL, HFILL }},

    { &hf_tn5250_wssf_ifc_imagefax_name,
      { "Image/Fax Name", "tn5250.wssf_ifc_imagefax_name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.26.3 WRITE SINGLE STRUCTURED FIELD Command - IMAGE/FAX DOWNLOAD Command */
    { &hf_tn5250_wssf_ifd_flag1,
      { "Byte 1", "tn5250.wssf_ifd_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wssf_ifd_flag1_0,
      { "Bit 0 (Last Data Stream flag)", "tn5250.wssf_ifd_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wssf_ifd_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wssf_ifd_flag1_reserved,
      { "Reserved", "tn5250.wssf_ifd_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},

    { &hf_tn5250_wssf_ifd_imagefax_name,
      { "Image/Fax Name", "tn5250.wssf_ifd_imagefax_name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wssf_ifd_imagefax_data,
      { "Image/Fax Data", "tn5250.wssf_ifd_imagefax_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_tn5250_image_fax_error,
      { "Image/Fax Error", "tn5250.image_fax_error",
        FT_UINT16, BASE_HEX, VALS(vals_tn5250_image_fax_error), 0,
        NULL, HFILL }},

    /* 15.26.4 WRITE SINGLE STRUCTURED FIELD Command - Video/Audio Controls Command Major Structure */
    { &hf_tn5250_vac_prefix,
      { "Video/Audio Control Data Prefix", "tn5250.vac_data_prefix",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_vac_data,
      { "Video/Audio Control Data", "tn5250.vac_data",
        FT_UINT32, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_vac_data), 0,
        NULL, HFILL }},

    /* Appendix B.1 WRITE SINGLE STRUCTURED FIELD Command - True Transparency Write Command Major Structure */
    { &hf_tn5250_wssf_ttw_flag,
      { "Flag", "tn5250.wssf_ttw_flag",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_wssf_ttw_flag), 0,
        NULL, HFILL }},
    /* XXX - the document says "Currently, this command is designed 
       only to pass ASCII data to some type of ASCII device."; should it
       be treated as an ASCII string? */
    { &hf_tn5250_wssf_ttw_data,
      { "Transparent Data", "tn5250.wssf_ttw_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.27 WRITE STRUCTURED FIELD (WSF) Command */
    /* 15.27.3 WRITE STRUCTURED FIELD (WSF) Command - 5250 QUERY STATION STATE Command*/
    { &hf_tn5250_wsf_qss_flag1,
      { "Byte 1", "tn5250.wsf_qss_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wsf_qss_flag1_0,
      { "Bit 0", "tn5250.wsf_qss_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wsf_qss_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wsf_qss_flag1_reserved,
      { "Reserved", "tn5250.wsf_qss_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},
    { &hf_tn5250_wsf_qss_flag2,
      { "Byte 2", "tn5250.wsf_qss_flag2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wsf_qss_flag2_reserved,
      { "Reserved", "tn5250.wsf_qss_flag2_reserved", FT_UINT8, BASE_HEX,
        NULL, 0x7F, NULL, HFILL }},
    { &hf_tn5250_wsf_qss_flag2_7,
      { "Bit 7", "tn5250.wsf_qss_flag2_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wsf_qss_flag2_7),
        0x80, NULL, HFILL }},

    /* 15.27.4.1 DEFINE AUDIT WINDOW TABLE Command */
    { &hf_tn5250_dawt_id,
      { "ID", "tn5250.dawt_id",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_dawt_id), 0,
        NULL, HFILL }},
    { &hf_tn5250_dawt_length,
      { "Length", "tn5250.dawt_length",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_dawt_length), 0,
        NULL, HFILL }},

    { &hf_tn5250_dawt_char,
      { "Character", "tn5250.dawt_char",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dawt_message,
      { "Message", "tn5250.dawt_message",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.27.4.2 DEFINE COMMAND KEY FUNCTION Command */
    { &hf_tn5250_dckf_id,
      { "ID", "tn5250.dckf_id",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_dckf_id), 0,
        NULL, HFILL }},
    { &hf_tn5250_dckf_length,
      { "Length", "tn5250.dckf_length",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_dckf_length), 0,
        NULL, HFILL }},
    { &hf_tn5250_dckf_key_code,
      { "Key Code", "tn5250.dckf_key_code",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_dckf_key_code), 0,
        NULL, HFILL }},
    { &hf_tn5250_dckf_function_code,
      { "Function Code", "tn5250.dckf_function_code",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_dckf_function_code), 0,
        NULL, HFILL }},
    { &hf_tn5250_dckf_prompt_text,
      { "Prompt Text", "tn5250.dckf_prompt_text",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.27.4.3 READ TEXT SCREEN Command */
    { &hf_tn5250_rts_partition,
      { "Partition", "tn5250.rts_partition",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_rts_partition), 0,
        NULL, HFILL }},
    { &hf_tn5250_rts_flag1,
      { "Byte 1", "tn5250.rts_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_rts_flag1_0,
      { "Bit 0 (Last Data Stream flag)", "tn5250.rts_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_rts_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_rts_flag1_reserved,
      { "Reserved", "tn5250.rts_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},

    /* 15.27.4.4 DEFINE PENDING OPERATIONS Command */
    { &hf_tn5250_dpo_partition,
      { "Partition", "tn5250.dpo_partition",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_rts_partition), 0,
        NULL, HFILL }},
    { &hf_tn5250_dpo_flag1,
      { "Byte 1", "tn5250.dpo_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dpo_flag1_0,
      { "Bit 0", "tn5250.dpo_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dpo_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_dpo_flag1_1,
      { "Bit 1", "tn5250.dpo_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dpo_flag1_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_dpo_flag1_2,
      { "Bit 2", "tn5250.dpo_flag1_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dpo_flag1_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_dpo_flag1_3,
      { "Bit 3", "tn5250.dpo_flag1_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dpo_flag1_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_dpo_flag1_4,
      { "Bit 4", "tn5250.dpo_flag1_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dpo_flag1_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_dpo_flag1_5,
      { "Bit 5", "tn5250.dpo_flag1_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dpo_flag1_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_dpo_flag1_6,
      { "Bit 6", "tn5250.dpo_flag1_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dpo_flag1_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_dpo_flag1_7,
      { "Bit 7", "tn5250.dpo_flag1_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dpo_flag1_7),
        0x80, NULL, HFILL }},

    { &hf_tn5250_dpo_flag2,
      { "Byte 1", "tn5250.dpo_flag2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dpo_flag2_0,
      { "Bit 0", "tn5250.dpo_flag2_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dpo_flag2_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_dpo_flag2_reserved,
      { "Reserved", "tn5250.dpo_flag2_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},

    { &hf_tn5250_dpo_displace_characters,
      { "Displaced Characters", "tn5250.dpo_displace_characters",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_tn5250_dpo_start_location_row,
      { "Start Location (Row)", "tn5250.dpo_start_location_row",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dpo_start_location_col,
      { "Start Location (Column)", "tn5250.dpo_start_location_col",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    /* 15.27.4.5 DEFINE TEXT SCREEN FORMAT Command */
    { &hf_tn5250_dtsf_partition,
      { "Partition", "tn5250.dtsf_partition",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_rts_partition), 0,
        NULL, HFILL }},
    { &hf_tn5250_dtsf_flag1,
      { "Byte 1", "tn5250.dtsf_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dtsf_flag1_0,
      { "Bit 0", "tn5250.dtsf_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dtsf_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_dtsf_flag1_1,
      { "Bit 1", "tn5250.dtsf_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dtsf_flag1_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_dtsf_flag1_2,
      { "Bit 2", "tn5250.dtsf_flag1_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dtsf_flag1_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_dtsf_flag1_3,
      { "Bit 3", "tn5250.dtsf_flag1_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dtsf_flag1_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_dtsf_flag1_4,
      { "Bit 4", "tn5250.dtsf_flag1_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dtsf_flag1_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_dtsf_flag1_5,
      { "Bit 5", "tn5250.dtsf_flag1_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dtsf_flag1_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_dtsf_flag1_6,
      { "Bit 6", "tn5250.dtsf_flag1_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dtsf_flag1_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_dtsf_flag1_7,
      { "Bit 7", "tn5250.dtsf_flag1_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dtsf_flag1_7),
        0x80, NULL, HFILL }},

    { &hf_tn5250_dtsf_flag2,
      { "Byte 1", "tn5250.dtsf_flag2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dtsf_flag2_0,
      { "Bit 0", "tn5250.dtsf_flag2_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dtsf_flag2_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_dtsf_flag2_1,
      { "Bit 1", "tn5250.dtsf_flag2_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dtsf_flag2_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_dtsf_flag2_2,
      { "Bit 2", "tn5250.dtsf_flag2_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dtsf_flag2_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_dtsf_flag2_3,
      { "Bit 3", "tn5250.dtsf_flag2_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dtsf_flag2_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_dtsf_flag2_4to7,
      { "Bits 4 to 7", "tn5250.dtsf_flag2_4to7",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_dtsf_flag2_vals), 0xF0,
        NULL, HFILL }},

    { &hf_tn5250_dtsf_text_body_height,
      { "Text Body Height", "tn5250.dtsf_text_body_height",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dtsf_text_body_width,
      { "Text Body Width", "tn5250.dtsf_text_body_height",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_tn5250_dtsf_line_cmd_field_size,
      { "Line Cmd Field Size", "tn5250.dtsf_line_cmd_field_size",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dtsf_location_of_pitch,
      { "Location of Pitch", "tn5250.dtsf_location_of_pitch",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dtsf_first_line,
      { "First Line in Text Body", "tn5250.dtsf_first_line",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    /* 15.27.4.6 DEFINE SCALE LINE Command */
    { &hf_tn5250_dsl_partition,
      { "Partition", "tn5250.dsl_partition",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_rts_partition), 0,
        NULL, HFILL }},
    { &hf_tn5250_dsl_rtl_offset,
      { "RTL Offset", "tn5250.dsl_rtl_offset",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dsl_offset,
      { "Offset", "tn5250.dsl_offset",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_tn5250_dsl_flag1,
      { "Byte 1", "tn5250.dsl_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dsl_flag1_0,
      { "Bit 0", "tn5250.dsl_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dsl_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_dsl_flag1_1,
      { "Bit 1", "tn5250.dsl_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dsl_flag1_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_dsl_flag1_2,
      { "Bit 2", "tn5250.dsl_flag1_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dsl_flag1_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_dsl_flag1_reserved,
      { "Reserved", "tn5250.dsl_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xF8, NULL, HFILL }},

    { &hf_tn5250_dsl_id,
      { "ID", "tn5250.dsl_id",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dsl_location,
      { "Location", "tn5250.dsl_location",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dsl_function,
      { "Function", "tn5250.dsl_function",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_dsl_function), 0x00,
        NULL, HFILL }},

    /* 15.27.4.7 WRITE TEXT SCREEN Command */
    { &hf_tn5250_wts_partition,
      { "Partition", "tn5250.wts_partition",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_rts_partition), 0,
        NULL, HFILL }},

    { &hf_tn5250_wts_flag1,
      { "Byte 1", "tn5250.wts_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wts_flag1_0,
      { "Bit 0", "tn5250.wts_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wts_flag1_1,
      { "Bit 1", "tn5250.wts_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag1_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wts_flag1_2,
      { "Bit 2", "tn5250.wts_flag1_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag1_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_wts_flag1_3,
      { "Bit 3", "tn5250.wts_flag1_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag1_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_wts_flag1_reserved,
      { "Reserved", "tn5250.wts_flag1_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xF0, NULL, HFILL }},

    { &hf_tn5250_wts_flag2,
      { "Byte 2", "tn5250.wts_flag2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wts_flag2_reserved,
      { "Reserved", "tn5250.wts_flag2_reserved", FT_UINT8, BASE_HEX,
        NULL, 0x1F, NULL, HFILL }},
    { &hf_tn5250_wts_flag2_6,
      { "Bit 6", "tn5250.wts_flag2_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag2_6),
        0x20, NULL, HFILL }},
    { &hf_tn5250_wts_flag2_reserved2,
      { "Reserved", "tn5250.wts_flag2_reserved", FT_UINT8, BASE_HEX,
        NULL, 0xC0, NULL, HFILL }},

    { &hf_tn5250_wts_flag3,
      { "Byte 3", "tn5250.wts_flag3",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wts_flag3_0,
      { "Bit 0", "tn5250.wts_flag3_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag3_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wts_flag3_1,
      { "Bit 1", "tn5250.wts_flag3_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag3_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wts_flag3_2,
      { "Bit 2", "tn5250.wts_flag3_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag3_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_wts_flag3_3,
      { "Bit 3", "tn5250.wts_flag3_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag3_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_wts_flag3_4,
      { "Bit 4", "tn5250.wts_flag3_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag3_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_wts_flag3_5,
      { "Bit 5", "tn5250.wts_flag3_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag3_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_wts_flag3_6,
      { "Bit 6", "tn5250.wts_flag3_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag3_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_wts_flag3_7,
      { "Bit 7", "tn5250.wts_flag3_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_flag3_7),
        0x80, NULL, HFILL }},

    { &hf_tn5250_wts_home_position_row,
      { "Home Position (Row)", "tn5250.wts_home_position_row",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wts_home_position_col,
      { "Home Position (Column)", "tn5250.wts_home_position_col",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    /*  Structure of the WRITE TEXT SCREEN Command Line Data */
    { &hf_tn5250_wts_cld_flag1,
      { "Byte 1", "tn5250.wts_cld_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag1_0,
      { "Bit 0", "tn5250.wts_cld_flag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag1_1,
      { "Bit 1", "tn5250.wts_cld_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag1_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag1_2,
      { "Bit 2", "tn5250.wts_cld_flag1_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag1_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag1_3,
      { "Bit 3", "tn5250.wts_cld_flag1_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag1_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag1_4,
      { "Bit 4", "tn5250.wts_cld_flag1_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag1_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag1_5,
      { "Bit 5", "tn5250.wts_cld_flag1_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag1_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag1_6,
      { "Bit 6", "tn5250.wts_cld_flag1_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag1_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag1_7,
      { "Bit 7", "tn5250.wts_cld_flag1_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag1_7),
        0x80, NULL, HFILL }},

    { &hf_tn5250_wts_cld_flag2,
      { "Byte 2", "tn5250.wts_cld_flag2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag2_0,
      { "Bit 0", "tn5250.wts_cld_flag2_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag2_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag2_1,
      { "Bit 1", "tn5250.wts_cld_flag2_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag2_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag2_2,
      { "Bit 2", "tn5250.wts_cld_flag2_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag2_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag2_3,
      { "Bit 3", "tn5250.wts_cld_flag2_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag2_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag2_4,
      { "Bit 4", "tn5250.wts_cld_flag2_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag2_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag2_line_spacing,
      { "Line Spacing in Half-Units", "tn5250.wts_cld_flag2_line_spacing", FT_UINT8, BASE_DEC,
        NULL, 0xE0, NULL, HFILL }},

    { &hf_tn5250_wts_cld_row,
      { "Row", "tn5250.wts_cld_row",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_tn5250_wts_cld_flag3,
      { "Byte 3", "tn5250.wts_cld_flag3",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag3_0,
      { "Bit 0", "tn5250.wts_cld_flag3_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag3_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag3_1,
      { "Bit 1", "tn5250.wts_cld_flag3_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag3_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag3_2,
      { "Bit 2", "tn5250.wts_cld_flag3_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag3_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag3_3,
      { "Bit 3", "tn5250.wts_cld_flag3_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag3_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag3_4,
      { "Bit 4", "tn5250.wts_cld_flag3_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag3_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag3_5,
      { "Bit 5", "tn5250.wts_cld_flag3_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag3_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag3_6,
      { "Bit 6", "tn5250.wts_cld_flag3_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag3_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_wts_cld_flag3_7,
      { "Bit 7", "tn5250.wts_cld_flag3_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_wts_cld_flag3_7),
        0x80, NULL, HFILL }},

    { &hf_tn5250_wts_cld_page_num,
      { "Page Number", "tn5250.wts_cld_page_num",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_tn5250_wts_cld_lmo,
      { "Left Margin Offset", "tn5250.wts_cld_lmo",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wts_cld_io,
      { "Indent Offset", "tn5250.wts_cld_io",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wts_cld_sli,
      { "Scale Line ID", "tn5250.wts_cld_sli",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_wts_cld_li,
      { "Line Image", "tn5250.wts_cld_li",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.27.4.8 DEFINE SPECIAL CHARACTERS Command */
    { &hf_tn5250_dsc_partition,
      { "Partition", "tn5250.dsc_partition",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_rts_partition), 0,
        NULL, HFILL }},
    { &hf_tn5250_dsc_sk,
      { "Symbol Key", "tn5250.dsc_sk",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dsc_ev,
      { "EBCDIC Value", "tn5250.dsc_ev",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.27.4.10 DEFINE OPERATOR ERROR MESSAGES Command */
    { &hf_tn5250_dorm_id,
      { "ID", "tn5250.dorm_id",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_dorm_id), 0x00,
        NULL, HFILL }},
    { &hf_tn5250_dorm_length,
      { "Length", "tn5250.dorm_length",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_dorm_length), 0,
        NULL, HFILL }},

    { &hf_tn5250_dorm_ec,
      { "Error Code", "tn5250.dorm_ec",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dorm_mt,
      { "Message Text", "tn5250.dorm_mt",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.27.4.11 DEFINE PITCH TABLE Command */
    { &hf_tn5250_dpt_id,
      { "ID", "tn5250.dpt_id",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_dpt_id), 0x00,
        NULL, HFILL }},
    { &hf_tn5250_dpt_ec,
      { "EBCDIC Code", "tn5250.dpt_ec",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    /* 15.27.4.12 DEFINE FAKE DP COMMAND KEY FUNCTION Command */
    { &hf_tn5250_dfdpck_partition,
      { "Partition", "tn5250.dfdpck_partition",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_rts_partition), 0,
        NULL, HFILL }},

    { &hf_tn5250_dfdpck_data_field,
      { "Data Field", "tn5250.dfdpck_data_field",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_dfdpck_data_field), 0,
        NULL, HFILL }},

    /* Structure of the DEFINE FAKE DP COMMAND KEY FUNCTION Core Area Command Keys */
    { &hf_tn5250_dfdpck_coreflag,
      { "Core Area Flag", "tn5250.dfdpck_coreflag",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dfdpck_coreflag_0,
      { "Bit 0", "tn5250.dfdpck_coreflag_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_coreflag_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_dfdpck_coreflag_1,
      { "Bit 1", "tn5250.dfdpck_coreflag_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_coreflag_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_dfdpck_coreflag_2,
      { "Bit 2", "tn5250.dfdpck_coreflag_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_coreflag_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_dfdpck_coreflag_3,
      { "Bit 3", "tn5250.dfdpck_coreflag_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_coreflag_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_dfdpck_coreflag_4,
      { "Bit 4", "tn5250.dfdpck_coreflag_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_coreflag_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_dfdpck_coreflag_5,
      { "Bit 5", "tn5250.dfdpck_coreflag_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_coreflag_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_dfdpck_coreflag_6,
      { "Bit 6", "tn5250.dfdpck_coreflag_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_coreflag_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_dfdpck_coreflag_7,
      { "Bit 7", "tn5250.dfdpck_coreflag_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_coreflag_7),
        0x80, NULL, HFILL }},

    /* Structure of the DEFINE FAKE DP COMMAND KEY FUNCTION Top Row Command Keys */

    { &hf_tn5250_dfdpck_toprowflag1,
      { "Top Row Flags", "tn5250.dfdpck_toprowflag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag1_0,
      { "Bit 0", "tn5250.dfdpck_toprowflag1_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag1_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag1_1,
      { "Bit 1", "tn5250.dfdpck_toprowflag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag1_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag1_2,
      { "Bit 2", "tn5250.dfdpck_toprowflag1_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag1_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag1_3,
      { "Bit 3", "tn5250.dfdpck_toprowflag1_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag1_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag1_4,
      { "Bit 4", "tn5250.dfdpck_toprowflag1_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag1_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag1_5,
      { "Bit 5", "tn5250.dfdpck_toprowflag1_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag1_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag1_6,
      { "Bit 6", "tn5250.dfdpck_toprowflag1_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag1_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag1_7,
      { "Bit 7", "tn5250.dfdpck_toprowflag1_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag1_7),
        0x80, NULL, HFILL }},

    { &hf_tn5250_dfdpck_toprowflag2,
      { "Top Row Flags", "tn5250.dfdpck_toprowflag2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag2_0,
      { "Bit 0", "tn5250.dfdpck_toprowflag2_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag2_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag2_1,
      { "Bit 1", "tn5250.dfdpck_toprowflag2_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag2_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag2_2,
      { "Bit 2", "tn5250.dfdpck_toprowflag2_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag2_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag2_3,
      { "Bit 3", "tn5250.dfdpck_toprowflag2_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag2_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag2_4,
      { "Bit 4", "tn5250.dfdpck_toprowflag2_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag2_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag2_5,
      { "Bit 5", "tn5250.dfdpck_toprowflag2_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag2_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag2_6,
      { "Bit 6", "tn5250.dfdpck_toprowflag2_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag2_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag2_7,
      { "Bit 7", "tn5250.dfdpck_toprowflag2_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag2_7),
        0x80, NULL, HFILL }},

    { &hf_tn5250_dfdpck_toprowflag3,
      { "Top Row Flags", "tn5250.dfdpck_toprowflag3",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag3_0,
      { "Bit 0", "tn5250.dfdpck_toprowflag3_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag3_0),
        0x01, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag3_1,
      { "Bit 1", "tn5250.dfdpck_toprowflag3_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag3_1),
        0x02, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag3_2,
      { "Bit 2", "tn5250.dfdpck_toprowflag3_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag3_2),
        0x04, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag3_3,
      { "Bit 3", "tn5250.dfdpck_toprowflag3_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag3_3),
        0x08, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag3_4,
      { "Bit 4", "tn5250.dfdpck_toprowflag3_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag3_4),
        0x10, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag3_5,
      { "Bit 5", "tn5250.dfdpck_toprowflag3_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag3_5),
        0x20, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag3_6,
      { "Bit 6", "tn5250.dfdpck_toprowflag3_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag3_6),
        0x40, NULL, HFILL }},
    { &hf_tn5250_dfdpck_toprowflag3_7,
      { "Bit 7", "tn5250.dfdpck_toprowflag3_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_dfdpck_toprowflag3_7),
        0x80, NULL, HFILL }},

    /* 15.28 COPY-TO-PRINTER Command */
    { &hf_tn5250_ctp_lsid,
      { "Printer LSID", "tn5250.ctp_lsid",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_ctp_mlpp,
      { "Max Lines Per Page", "tn5250.ctp_mlpp",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    /*TN5250 - RFC1205 - Query Reply Fields */
    { &hf_tn5250_qr_flag,
      { "Flag", "tn5250.qr_flag",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_qr_flag_0,
      { "Bit 1", "tn5250.qr_flag_0",
        FT_BOOLEAN, 8, TFS(&tn5250_field_qr_flag_0),
        0x80, NULL, HFILL }},
    { &hf_tn5250_qr_flag_reserved,
      { "Reserved", "tn5250.qr_flag_reserved", FT_UINT8, BASE_HEX,
        NULL, 0x7F, NULL, HFILL }},
    { &hf_tn5250_qr_chc,
      { "Controller Hardware Class", "tn5250.qr_chc",
        FT_UINT16, BASE_HEX, VALS(vals_tn5250_chc), 0x0,
        NULL, HFILL }},
    { &hf_tn5250_qr_ccl,
      { "Controller Code Level", "tn5250.qr_ccl",
        FT_UINT24, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tn5250_qr_dt,
      { "Device Type", "tn5250.qr_dt",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_dt), 0x0,
        NULL, HFILL }},
    { &hf_tn5250_qr_dtc,
      { "Device Type", "tn5250.qr_dtc",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tn5250_qr_dm,
      { "Device Model", "tn5250.qr_dm",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tn5250_qr_ki,
      { "Keyboard ID", "tn5250.qr_ki",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_qr_ki), 0x0,
        NULL, HFILL }},
    { &hf_tn5250_qr_eki,
      { "Extended Keyboard ID", "tn5250.qr_eki",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tn5250_qr_dsn,
      { "Display Serial Number", "tn5250.qr_dsn",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_tn5250_qr_mni,
      { "Maximum number of input fields", "tn5250.qr_mni",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_tn5250_qr_flag1,
      { "Flags", "tn5250.qr_flag1",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_qr_flag1_0,
      { "Bit 0 (Reserved)", "tn5250.qr_flag1_0",
        FT_BOOLEAN, 8, NULL,
        0x80, NULL, HFILL }},
    { &hf_tn5250_qr_flag1_1,
      { "Bit 1", "tn5250.qr_flag1_1",
        FT_BOOLEAN, 8, TFS(&tn5250_field_qr_flag1_1),
        0x40, NULL, HFILL }},
    { &hf_tn5250_qr_flag1_2,
      { "Bit 2", "tn5250.qr_flag1_2",
        FT_BOOLEAN, 8, TFS(&tn5250_field_qr_flag1_2),
        0x20, NULL, HFILL }},
    { &hf_tn5250_qr_flag1_3,
      { "Bit 3", "tn5250.qr_flag1_3",
        FT_BOOLEAN, 8, TFS(&tn5250_field_qr_flag1_3),
        0x10, NULL, HFILL }},
    { &hf_tn5250_qr_flag1_4,
      { "Bit 4", "tn5250.qr_flag1_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_qr_flag1_4),
        0x08, NULL, HFILL }},
    { &hf_tn5250_qr_flag1_5,
      { "Bit 5", "tn5250.qr_flag1_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_qr_flag1_5),
        0x04, NULL, HFILL }},
    { &hf_tn5250_qr_flag1_6,
      { "Bit 6", "tn5250.qr_flag1_6",
        FT_BOOLEAN, 8, TFS(&tn5250_field_qr_flag1_6),
        0x02, NULL, HFILL }},
    { &hf_tn5250_qr_flag1_7,
      { "Bit 7", "tn5250.qr_flag1_7",
        FT_BOOLEAN, 8, TFS(&tn5250_field_qr_flag1_7),
        0x01, NULL, HFILL }},

    { &hf_tn5250_qr_flag2,
      { "Flags", "tn5250.qr_flag2",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_tn5250_qr_flag2_0to3,
      { "Bits 0 to 3", "tn5250.qr_flag2_0to3",  FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_qr_flag2_0to3), 0xF0, NULL, HFILL }},
    { &hf_tn5250_qr_flag2_4,
      { "Bit 4", "tn5250.qr_flag2_4",
        FT_BOOLEAN, 8, TFS(&tn5250_field_qr_flag2_4),
        0x08, NULL, HFILL }},
    { &hf_tn5250_qr_flag2_5,
      { "Bit 5", "tn5250.qr_flag2_5",
        FT_BOOLEAN, 8, TFS(&tn5250_field_qr_flag2_5),
        0x04, NULL, HFILL }},
    { &hf_tn5250_qr_flag2_6to7,
      { "Bits 6 to 7", "tn5250.qr_flag2_6to7",  FT_UINT8, BASE_HEX,
        VALS(vals_tn5250_qr_flag2_6to7), 0x03, NULL, HFILL }},

    { &hf_tn5250_qr_flag3,
      { "Flags", "tn5250.qr_flag3",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_qr_flag3), 0,
        NULL, HFILL }},
    { &hf_tn5250_qr_flag4,
      { "Flags", "tn5250.qr_flag4",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_qr_flag4), 0,
        NULL, HFILL }},


    /* Order Code */
    { &hf_tn5250_order_code, { "Order Code", "tn5250.order_code",
                               FT_UINT8, BASE_HEX, VALS(vals_tn5250_order_codes), 0x0, NULL, HFILL }},
    { &hf_tn5250_attribute_type, { "Attribute Type", "tn5250.attribute",
                                   FT_UINT8, BASE_HEX, VALS(vals_tn5250_attributes), 0x0, NULL, HFILL }},
    { &hf_tn5250_aid, {  "Attention Identification", "tn5250.aid",
                         FT_UINT8, BASE_HEX|BASE_RANGE_STRING,
                         RVALS(vals_tn5250_attention_identification_bytes), 0x0, NULL, HFILL }},

    /* Miscellaneous Fields */
    { &hf_tn5250_buffer_x, {  "Row Address", "tn5250.buffer_x",
                              FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_tn5250_buffer_y, {  "Column Address", "tn5250.buffer_y",
                              FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_tn5250_length, {  "Length", "tn5250.length",
                            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_tn5250_length_twobyte, {  "Length", "tn5250.length",
                                    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_tn5250_field_data,
      {  "Field Data", "tn5250.field_data", FT_STRING, BASE_NONE, NULL, 0x0,
         NULL, HFILL }},
    { &hf_tn5250_reserved, {  "Flags (Reserved):", "tn5250.reserved",
                              FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(vals_tn5250_reserved), 0,
                              NULL, HFILL }},
    { &hf_tn5250_unknown_data,
      {  "Unknown Data (Possible Mainframe/Emulator Bug)", "tn5250.unknown_data",
         FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    /*TN5250 - RFC1205 - SNA Header Fields */
    { &hf_tn5250_logical_record_length,
      { "TN5250 Logical Record Length", "tn5250.logical_record_length",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_tn5250_sna_record_type,
      { "TN5250 SNA Record Type", "tn5250.sna_record_type",
        FT_UINT16, BASE_HEX, VALS(vals_tn5250_sna_record_type), 0x0,
        NULL, HFILL }},
    { &hf_tn5250_variable_record_length,
      { "TN5250 Variable Record Length", "tn5250.variable_record_length",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_tn5250_header_flags, { "TN5250 SNA Flags", "tn5250.header_flags",
                                 FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_tn5250_ds_output_error,
      { "Data Stream Output Error",
        "tn5250.ds_output_error", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
    { &hf_tn5250_attn_key,
      { "5250 attention key was pressed.",
        "tn5250.attn_key", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
    { &hf_tn5250_sys_request_key,
      { "5250 System Request key was pressed",
        "tn5250.sys_request_key", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
    { &hf_tn5250_test_request_key,
      { "5250 Test Request key was pressed",
        "tn5250.test_request_key", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
    { &hf_tn5250_error_state,
      { "In Error State",
        "tn5250.error_state", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
    { &hf_tn5250_operation_code,
      { "TN5250 Operation Code",           "tn5250.operation_code",
        FT_UINT8, BASE_HEX, VALS(vals_tn5250_header_operation_code), 0x0,
        NULL, HFILL }},
    { &hf_tn5250_error_code,
      { "TN5250 Error Code",           "tn5250.error_code",
        FT_UINT16, BASE_HEX, VALS(vals_tn5250_header_error_codes), 0x0,
        NULL, HFILL }},

    /* 13.4 SNA LU 4 and LU 7 Negative Responses */
    { &hf_tn5250_negative_response,
      { "Negative Response",           "tn5250.negative_response",
        FT_UINT32, BASE_HEX, VALS(vals_tn5250_negative_responses), 0x0,
        NULL, HFILL }},

  };

  static gint *ett[] = {
    &ett_tn5250,
    &ett_sf,
    &ett_tn5250_wcc,
    &ett_tn5250_field_attribute,
    &ett_tn5250_dfdpck_mask,
    &ett_tn5250_field_validation,
    &ett_tn5250_header_flags,
    &ett_tn5250_roll_mask,
    &ett_tn5250_soh_mask,
    &ett_tn5250_soh_pf16to9_mask,
    &ett_tn5250_soh_pf24to17_mask,
    &ett_tn5250_soh_pf8to1_mask,
    &ett_tn5250_sps_mask,
    &ett_tn5250_wdsf_cw_bp_mask,
    &ett_tn5250_wdsf_cw_mask,
    &ett_tn5250_wdsf_cw_tf_mask,
    &ett_tn5250_wdsf_deg_mask,
    &ett_tn5250_wdsf_deg_ms_mask,
    &ett_tn5250_wdsf_ds_ci_mask,
    &ett_tn5250_wdsf_ds_cpda_mask,
    &ett_tn5250_wdsf_ds_ct_mask,
    &ett_tn5250_wdsf_ds_mask,
    &ett_tn5250_wdsf_ds_mbs_mask,
    &ett_tn5250_wdsf_ds_sbi_mask,
    &ett_tn5250_wdsf_dsb_mask,
    &ett_tn5250_wdsf_pmb_mask,
    &ett_tn5250_wdsf_ragc_mask,
    &ett_tn5250_wdsf_rgw_mask,
    &ett_tn5250_wdsf_wdf_mask,
    &ett_tn5250_wsf_dpo_mask,
    &ett_tn5250_wsf_dsl_mask,
    &ett_tn5250_wsf_dtsf_mask,
    &ett_tn5250_wsf_qss_mask,
    &ett_tn5250_wsf_rts_mask,
    &ett_tn5250_wssf_cc_mask,
    &ett_tn5250_wssf_ifc_mask,
    &ett_tn5250_wssf_ifd_mask,
    &ett_tn5250_wssf_kbc_mask,
    &ett_tn5250_wssf_mask,
    &ett_tn5250_wts_mask,
    &ett_tn5250_wea_prim_attr,
    &ett_tn5250_qr_mask,
    &ett_cc,
  };

  proto_tn5250 = proto_register_protocol("TN5250 Protocol", "TN5250", "tn5250");
  register_dissector("tn5250", dissect_tn5250, proto_tn5250);
  proto_register_field_array(proto_tn5250, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}
