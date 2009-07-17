/* packet-tn3270.h
 * Headers for tn3270.packet dissection
 *
 * Reference:
 * 3270 Information Display System: Data Stream Programmer's Reference
 *  GA23-0059-07
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

#ifndef TN3270_H_INCLUDED
#define TN3270_H_INCLUDED

/* OUTBOUND DATA STREAM (MAINFRAME PROGRAM -> DISPLAY)

 ________________ _____ __________________
| Command Code   |WCC  | Orders and Data  |
|________________|_____|__________________|

                 or
 ______ ______________________
| WSF  | Structured Field(s)  |
|______|______________________|

*/

/*3270 Command Codes - Undocumented*/
#define W        0x01
#define RB       0x02
#define NOP      0x03
#define EW       0x05
#define RM       0x06
#define EWA      0x0D
#define RMA      0x0E
#define EAU      0x0F
#define WSF      0x11

/* SNA 3270 Command Codes */
#define SNA_W          0xF1
#define SNA_EW         0xF5
#define SNA_EWA        0x7E
#define SNA_RB         0xF2
#define SNA_RM         0xF6
#define SNA_RMA        0x6E
#define SNA_EAU        0x6F
#define SNA_WSF        0xF3
#define SNA_BSC        0xF7

static const value_string vals_command_codes[] = {
	{ W  ,  "Write"},
	{ EW ,  "Erase/Write"},
	{ EWA,  "Erase/Write Alternate"},
	{ RB ,  "Read Buffer"},
	{ RM ,  "Read Modified"},
	{ RMA,  "Read Modified All"},
	{ EAU,  "Erase All Unprotected"},
	{ WSF,  "Write Structured Field"},
	{ SNA_W  ,  "Write"},
	{ SNA_EW ,  "Erase/Write"},
	{ SNA_EWA,  "Erase/Write Alternate"},
	{ SNA_RB ,  "Read Buffer"},
	{ SNA_RM ,  "Read Modified"},
	{ SNA_RMA,  "Read Modified All"},
	{ SNA_EAU,  "Erase All Unprotected"},
	{ SNA_WSF,  "Write Structured Field"},
	{ SNA_BSC,  "BSC Copy"},
	{ 0x00, NULL }
};

/* WCC (Write Control Characters) */
/*
#define NOP               0x01
#define WCC_RESET         0x02
#define PRINTER1          0x04
#define PRINTER2          0x08
#define START_PRINTER     0x10
#define SOUND_ALARM       0x20
#define KEYBOARD_RESTORE  0x40
#define RESET_MDT         0x80

static const value_string vals_write_control_characters[] = {
	{ NOP             ,  "Nop"},
	{ WCC_RESET       ,  "Wcc Reset"},
	{ PRINTER1        ,  "Printer"},
	{ PRINTER2        ,  "Printer"},
	{ START_PRINTER   ,  "Start Printer"},
	{ SOUND_ALARM     ,  "Sound Alarm"},
	{ KEYBOARD_RESTORE,  "Keyboard Restore"},
	{ RESET_MDT       ,  "Reset Mdt"},
	{ 0x00, NULL }
};
*/

/* Order Codes */

#define SF         0x1D
#define SFE        0x29
#define SBA        0x11
#define SA         0x28
#define MF         0x2C
#define IC         0x13
#define PT         0x05
#define RA         0x3C
#define EUA        0x12
#define GE         0x08

static const value_string vals_order_codes[] = {
	{ SF ,  "Start Field (SF)"},
	{ SFE,  "Start Field Extended (SFE)"},
	{ SBA,  "Set Buffer Address (SBA)"},
	{ SA ,  "Set Attribute (SA)"},
	{ MF ,  "Modify Field (MF)"},
	{ IC ,  "Insert Cursor (IC)"},
	{ PT ,  "Program Tab (PT)"},
	{ RA ,  "Repeat to Address (RA)"},
	{ EUA,  "Erase Unprotected to Address (EUA)"},
	{ GE ,  "Graphic Escape (GE)"},
	{ 0x00, NULL }
};

/* 4.3.11 Format Control Orders */

#define NUL                   0x00
#define SUB                   0x3F
#define DUP                   0x1C
#define FM                    0x1E
#define FF                    0x0C
#define CR                    0x0D
#define NL                    0x15
#define EM                    0x19
#define EO                    0xFF

static const value_string vals_format_control_orders[] = {
	{ NUL ,  "Null"},
	{ SUB ,  "Substitute"},
	{ DUP ,  "Duplicate"},
	{ FM  ,  "Field Mark"},
	{ FF  ,  "Form Feed"},
	{ CR  ,  "Carriage Return"},
	{ NL  ,  "New Line"},
	{ EM  ,  "End of Medium"},
	{ EO  ,  "Eight Ones"},
	{ 0x00, NULL }
};


/* 8.7 Copy Control Code */
#define BIT_14                                0x00
#define BIT_12                                0x40
#define RESERVEDCCC                           0x80
#define BIT_12_2                              0xC0
#define CODING_BITS                           0xC0

static const value_string vals_coding[] = {
	{ BIT_14  ,  "Display Selector Pen Detectable"},
	{ BIT_12  ,  "Intensified Display Selector Pen Detectable"},
	{ RESERVEDCCC,  "Non Display Non Detectable"},
	{ BIT_12_2,  "Display Not Selector Pen Detectable"},
	{ 0x00, NULL }
};

#define POINT_LINE_LENGTH                               0x00
#define PRINT_LINE_40                                   0x10
#define PRINT_LINE_64                                   0x20
#define PRINT_LINE_80                                   0x30
#define PRINT_BITS                                      0x30

static const value_string vals_printout_format[] = {
	{ POINT_LINE_LENGTH,  "The NL, EM, and CR orders in the data stream determine pointline length. "
	                      "Provides a 132-print position line when the orders are not present."},
	{ PRINT_LINE_40    ,  "Specifies a 40-character print line."},
	{ PRINT_LINE_64    ,  "Specifies a 64-character print line."},
	{ PRINT_LINE_80    ,  "Specifies an 80-character print line."},
	{ 0x00, NULL }
};

#define START_PRINT                                     0x08
#define SOUND_ALARM                                     0x04

#define ONLY_ATTRIBUTE_CHARACTERS                       0x00
#define ATTRIBUTE_CHARACTERS_UNPROTECTED_AN             0x01
#define ALL_ATTRIBUTE_PROTECTED                         0x02
#define ENTIRE_CONTENTS                                 0x03
#define ATTRIBUTE_BITS                                  0x03

static const value_string vals_copytype[] = {
	{ ONLY_ATTRIBUTE_CHARACTERS            ,  "Only attribute characters are copied."},
	{ ATTRIBUTE_CHARACTERS_UNPROTECTED_AN  ,  "Attribute characters and unprotected alphanumeric fields (including nulls) are copied. Nulls are transferred for the alphanumeric characters not copied from the protected fields."},
	{ ALL_ATTRIBUTE_PROTECTED              ,  "All attribute characters and protected alphanumeric fields (including nulls) are copied. Nulls are transferred for the alphanumeric characters not copied from the unprotected fields."},
	{ ENTIRE_CONTENTS                      ,  "The entire contents of the storage buffer (including nulls) are copied."},
	{ 0x00, NULL }
};

/* 4.4.1 Field Attributes */
#define GRAPHIC_CONVERT1                                0x80
#define GRAPHIC_CONVERT2                                0x40
#define PROTECTED                                       0x20
#define NUMERIC                                         0x10
#define RESERVED                                        0x08
#define MODIFIED                                        0x04

#define DISPLAY_NOT_SELECTOR_PEN_DETECTABLE             0x00
#define DISPLAY_SELECTOR_PEN_DETECTABLE                 0x01
#define INTENSIFIED_DISPLAY_SELECTOR_PEN_DETECTABLE     0x02
#define NON_DISPLAY_NON_DETECTABLE                      0x03
#define DISPLAY_BITS                                    0x03

static const value_string vals_fa_display[] = {
	{ DISPLAY_SELECTOR_PEN_DETECTABLE            ,  "Display Selector Pen Detectable"},
	{ INTENSIFIED_DISPLAY_SELECTOR_PEN_DETECTABLE,  "Intensified Display Selector Pen Detectable"},
	{ NON_DISPLAY_NON_DETECTABLE                 ,  "Non Display Non Detectable"},
	{ DISPLAY_NOT_SELECTOR_PEN_DETECTABLE        ,  "Display Not Selector Pen Detectable"},
	{ 0x00, NULL }
};

/* 4.4.5 Attribute Types */
#define ALL_CHARACTER_ATTRIBUTES  0x00
#define T3270_FIELD_ATTRIBUTE     0xC0
#define FIELD_VALIDATION          0xC1
#define FIELD_OUTLINING           0xC2
#define EXTENDED_HIGHLIGHTING     0x41
#define FOREGROUND_COLOR          0x42
#define CHARACTER_SET             0x43
#define BACKGROUND_COLOR          0x45
#define TRANSPARENCY              0x46


static const value_string vals_attribute_types[] = {
	{ ALL_CHARACTER_ATTRIBUTES,  "All character attributes"},
	{ T3270_FIELD_ATTRIBUTE   ,  "3270 Field attribute"},
	{ FIELD_VALIDATION        ,  "Field validation"},
	{ FIELD_OUTLINING         ,  "Field outlining"},
	{ EXTENDED_HIGHLIGHTING   ,  "Extended highlighting"},
	{ FOREGROUND_COLOR        ,  "Foreground color"},
	{ CHARACTER_SET           ,  "Character set"},
	{ BACKGROUND_COLOR        ,  "Background color"},
	{ TRANSPARENCY            ,  "Transparency"},
	{ 0x00, NULL }
};

/* 4.4.6.3 Extended Highlighting */
#define DEFAULT_HIGHLIGHTING        0x00
#define NORMAL         0xF0
#define BLINK          0xF1
#define REVERSE_VIDEO  0xF2
#define UNDERSCORE     0xF4

static const value_string vals_extended_highlighting[] = {
	{ DEFAULT_HIGHLIGHTING      ,  "Default"},
	{ NORMAL       ,  "Normal (as determined by the 3270 field attribute)"},
	{ BLINK        ,  "Blink"},
	{ REVERSE_VIDEO,  "Reverse video"},
	{ UNDERSCORE   ,  "Underscore."},
	{ 0x00, NULL }
};

/* 4.4.6.4 Color Identifications */
#define ALL_PLANES             0x00
#define BLUE_PLANE             0x01
#define RED_PLANE              0x02
#define GREEN_PLANE            0x04
#define NEUTRAL1               0xF0
#define BLUE                   0xF1
#define RED                    0xF2
#define PINK                   0xF3
#define GREEN                  0xF4
#define TURQUOISE              0xF5
#define YELLOW                 0xF6
#define NEUTRAL2               0xF7
#define BLACK                  0xF8
#define DEEP_BLUE              0xF9
#define ORANGE                 0xFA
#define PURPLE                 0xFB
#define PALE_GREEN             0xFC
#define PALE_TURQUOISE         0xFD
#define GREY                   0xFE
#define WHITE                  0xFF


static const value_string vals_color_identifications[] = {
	{ ALL_PLANES    ,  "ALL PLANES"},
	{ BLUE_PLANE    ,  "BLUE PLANE"},
	{ RED_PLANE     ,  "RED PLANE"},
	{ GREEN_PLANE   ,  "GREEN PLANE"},
	{ NEUTRAL1      ,  "Neutral"},
	{ BLUE          ,  "Blue"},
	{ RED           ,  "Red"},
	{ PINK          ,  "Pink"},
	{ GREEN         ,  "Green"},
	{ TURQUOISE     ,  "Turquoise"},
	{ YELLOW        ,  "Yellow"},
	{ NEUTRAL2      ,  "Neutral"},
	{ BLACK         ,  "Black"},
	{ DEEP_BLUE     ,  "Deep Blue"},
	{ ORANGE        ,  "Orange"},
	{ PURPLE        ,  "Purple"},
	{ PALE_GREEN    ,  "Pale Green"},
	{ PALE_TURQUOISE,  "Pale Turquoise"},
	{ GREY          ,  "Grey"},
	{ WHITE         ,  "White"},
	{ 0x00, NULL }
};

/* 4.4.6.5 Character Set */

#define DEFAULT_CHARACTER_SET                         0x00
#define MIN_LOCAL_ID_FOR_LOADABLE_CHARACTER_SETS      0x40
#define MAX_LOCAL_ID_FOR_LOADABLE_CHARACTER_SETS      0xEF
#define MIN_LOCAL_ID_FOR_NONLOADABLE_CHARACTER_SETS   0xF0
#define MAX_LOCAL_ID_FOR_NONLOADABLE_CHARACTER_SETS   0xF7
#define MIN_LOCAL_ID_FOR_TWO_BYTE_CODED_CHARACTER_SETS  0xF8
#define MAX_LOCAL_ID_FOR_TWO_BYTE_CODED_CHARACTER_SETS  0xFE


static const range_string rvals_character_set[] = {
    { DEFAULT_CHARACTER_SET, DEFAULT_CHARACTER_SET,
      "DEFAULT_CHARACTER_SET" },
    { MIN_LOCAL_ID_FOR_LOADABLE_CHARACTER_SETS, MAX_LOCAL_ID_FOR_LOADABLE_CHARACTER_SETS,
      "LOCAL_ID_FOR_LOADABLE_CHARACTER_SETS"},
    { MIN_LOCAL_ID_FOR_NONLOADABLE_CHARACTER_SETS, MAX_LOCAL_ID_FOR_NONLOADABLE_CHARACTER_SETS,
      "LOCAL_ID_FOR_NONLOADABLE_CHARACTER_SETS"},
    { MIN_LOCAL_ID_FOR_TWO_BYTE_CODED_CHARACTER_SETS, MAX_LOCAL_ID_FOR_TWO_BYTE_CODED_CHARACTER_SETS,
      "LOCAL_ID_FOR_TWO_BYTE_CODED_CHARACTER_SETS" },
    { 0,           0,          NULL                   }
};

/* 4.4.6.6 Field Outlining */
#define NO_OUTLINING_LINES                        0X00
#define UNDERLINE_ONLY                            0X01
#define RIGHT_VERTICAL_LINE_ONLY                  0X02
#define OVERLINE_ONLY                             0X04
#define LEFT_VERTICAL_LINE_ONLY                   0X08
#define UNDERLINE_AND_RIGHT_VERTICAL_LINE         0X03
#define UNDERLINE_AND_OVERLINE                    0X05
#define UNDERLINE_AND_LEFT_VERTICAL_LINE          0X09
#define RIGHT_VERTICAL_LINE_AND_OVERLINE          0X06
#define RIGHT_AND_LEFT_VERTICAL_LINES             0X0A
#define OVERLINE_AND_LEFT_VERTICAL_LINE           0X0C
#define RECTANGLE_MINUS_LEFT_VERTICAL_LINE        0X07
#define RECTANGLE_MINUS_OVERLINE                  0X0B
#define RECTANGLE_MINUS_RIGHT_VERTICAL_LINE       0X0D
#define RECTANGLE_MINUS_UNDERLINE                 0X0E
#define RECTANGLE                                 0X0F


static const value_string vals_field_outlining[] = {
	{ NO_OUTLINING_LINES                  ,  "No outlining lines"},
	{ UNDERLINE_ONLY                      ,  "Underline only"},
	{ RIGHT_VERTICAL_LINE_ONLY            ,  "Right vertical line only"},
	{ OVERLINE_ONLY                       ,  "Overline only"},
	{ LEFT_VERTICAL_LINE_ONLY             ,  "Left vertical line only"},
	{ UNDERLINE_AND_RIGHT_VERTICAL_LINE   ,  "Underline and right vertical line"},
	{ UNDERLINE_AND_OVERLINE              ,  "Underline and overline"},
	{ UNDERLINE_AND_LEFT_VERTICAL_LINE    ,  "Underline and left vertical line"},
	{ RIGHT_VERTICAL_LINE_AND_OVERLINE    ,  "Right vertical line and overline"},
	{ RIGHT_AND_LEFT_VERTICAL_LINES       ,  "Right and left vertical lines"},
	{ OVERLINE_AND_LEFT_VERTICAL_LINE     ,  "Overline and left vertical line"},
	{ RECTANGLE_MINUS_LEFT_VERTICAL_LINE  ,  "Rectangle minus left vertical line"},
	{ RECTANGLE_MINUS_OVERLINE            ,  "Rectangle minus overline"},
	{ RECTANGLE_MINUS_RIGHT_VERTICAL_LINE ,  "Rectangle minus right vertical line"},
	{ RECTANGLE_MINUS_UNDERLINE           ,  "Rectangle minus underline"},
	{ RECTANGLE                           ,  "Rectangle"},
	{ 0x00, NULL }
};


/* 4.4.6.7 Transparency */
#define DEFAULT_TRANSPARENCY                             0X00
#define BACKGROUND_IS_TRANSPARENT_OR                     0XF0
#define BACKGROUND_IS_TRANSPARENT_XOR                    0XF1
#define BACKGROUND_IS_OPAQUE                             0XFF

static const value_string vals_transparency[] = {
	{ DEFAULT_TRANSPARENCY         ,  "Default"},
	{ BACKGROUND_IS_TRANSPARENT_OR ,  "Background is transparent (OR)"},
	{ BACKGROUND_IS_TRANSPARENT_XOR,  "Background is transparent (XOR)"},
	{ BACKGROUND_IS_OPAQUE         ,  "Background is opaque (non-transparent)"},
	{ 0x00, NULL }
};

/* 4.4.6.8 Field Validation */
#define MANDATORY_FILL         0X10
#define MANDATORY_ENTRY        0X20
#define TRIGGER                0X40

static const value_string vals_field_validation[] = {
	{ MANDATORY_FILL ,  "Mandatory fill"},
	{ MANDATORY_ENTRY,  "Mandatory entry"},
	{ TRIGGER        ,  "Trigger"},
	{ 0x00, NULL }
};

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

/* 5.1 Outbound Structured Fields */

#define READ_PARTITION_QUERY                  0x02
#define READ_PARTITION_QUERY_LIST             0x03
#define READ_PARTITION_READ_MODIFIED_ALL      0x6E
#define READ_PARTITION_READ_BUFFER            0xF2
#define READ_PARTITION_READ_MODIFIED          0xF6

static const value_string vals_operation_types[] = {
	{ READ_PARTITION_QUERY             ,  "Read Partition Query"},
	{ READ_PARTITION_QUERY_LIST        ,  "Read Partition Query List"},
	{ READ_PARTITION_READ_MODIFIED_ALL ,  "Read Partition Read Modified All"},
	{ READ_PARTITION_READ_BUFFER       ,  "Read Partition Read Buffer"},
	{ READ_PARTITION_READ_MODIFIED     ,  "Read Partition Read Modified"},
	{ 0x00, NULL }
};


#define ACTIVATE_PARTITION                    0x0E
#define BEGIN_OR_END_OF_FILE                  0x0F85
#define CREATE_PARTITION                      0x0C
#define DESTROY_PARTITION                     0x0D
#define ERASE_OR_RESET                        0x03
#define LOAD_COLOR_TABLE                      0x0F05
#define LOAD_FORMAT_STORAGE                   0x0F24
#define LOAD_LINE_TYPE                        0x0F07
#define LOAD_PROGRAMMED_SYMBOLS               0x06
#define MODIFY_PARTITION                      0x0F0A
#define OUTBOUND_TEXT_HEADER                  0x0F71
#define OUTBOUND_3270DS                       0x40
#define PRESENT_ABSOLUTE_FORMAT               0x4B
#define PRESENT_RELATIVE_FORMAT               0x4C
#define SET_PARTITION_CHARACTERISTICS         0x0F08
#define SET_REPLY_MODE                        0x09
#define TYPE_1_TEXT_OUTBOUND                  0x0FC1
#define READ_PARTITION                        0x01
#define REQUEST_RECOVERY_DATA                 0x1030
#define RESET_PARTITION                       0x00
#define RESTART                               0x1033
#define SCS_DATA                              0x41
#define SELECT_COLOR_TABLE                    0x0F04
#define SELECT_FORMAT_GROUP                   0x4A
#define SET_CHECKPOINT_INTERVAL               0x1032
#define SET_MSR_CONTROL                       0x0F01
#define SET_PRINTER_CHARACTERISTICS           0x0F84
#define SET_WINDOW_ORIGIN                     0x0B


static const value_string vals_outbound_structured_fields[] = {
	{ ACTIVATE_PARTITION               ,  "Activate Partition"},
	{ BEGIN_OR_END_OF_FILE             ,  "Begin Or End Of File"},
	{ CREATE_PARTITION                 ,  "Create Partition"},
	{ DESTROY_PARTITION                ,  "Destroy Partition"},
	{ ERASE_OR_RESET                   ,  "Erase Or Reset"},
	{ LOAD_COLOR_TABLE                 ,  "Load Color Table"},
	{ LOAD_FORMAT_STORAGE              ,  "Load Format Storage"},
	{ LOAD_LINE_TYPE                   ,  "Load Line Type"},
	{ LOAD_PROGRAMMED_SYMBOLS          ,  "Load Programmed Symbols"},
	{ MODIFY_PARTITION                 ,  "Modify Partition"},
	{ OUTBOUND_TEXT_HEADER             ,  "Outbound Text Header"},
	{ OUTBOUND_3270DS                  ,  "Outbound 3270ds"},
	{ PRESENT_ABSOLUTE_FORMAT          ,  "Present Absolute Format"},
	{ PRESENT_RELATIVE_FORMAT          ,  "Present Relative Format"},
	{ SET_PARTITION_CHARACTERISTICS    ,  "Set Partition Characteristics"},
	{ SET_REPLY_MODE                   ,  "Set Reply Mode"},
	{ TYPE_1_TEXT_OUTBOUND             ,  "Type 1 Text Outbound"},
	{ READ_PARTITION                   ,  "Read Partition"},
	{ REQUEST_RECOVERY_DATA            ,  "Request Recovery Data"},
	{ RESET_PARTITION                  ,  "Reset Partition"},
	{ RESTART                          ,  "Restart"},
	{ SCS_DATA                         ,  "Scs Data"},
	{ SELECT_COLOR_TABLE               ,  "Select Color Table"},
	{ SELECT_FORMAT_GROUP              ,  "Select Format Group"},
	{ SET_CHECKPOINT_INTERVAL          ,  "Set Checkpoint Interval"},
	{ SET_MSR_CONTROL                  ,  "Set Msr Control"},
	{ SET_PRINTER_CHARACTERISTICS      ,  "Set Printer Characteristics"},
	{ SET_WINDOW_ORIGIN                ,  "Set Window Origin"},
	{ 0x00, NULL }
};

/* 5.1 Outbound/Inbound Structured Fields */

#define DATA_CHAIN               0x0F21
#define DESTINATION_OR_ORIGIN    0x0F02
#define OBJECT_CONTROL           0x0F11
#define OBJECT_DATA              0x0F0F
#define OBJECT_PICTURE           0x0F10
#define OEM_DATA                 0x0F1F
#define SAVE_OR_RESTORE_FORMAT   0x1034
#define SELECT_IPDS_MODE         0x0F83

static const value_string vals_outbound_inbound_structured_fields[] = {
	{ DATA_CHAIN             ,  "Data Chain"},
	{ DESTINATION_OR_ORIGIN  ,  "Destination/Origin"},
	{ OBJECT_CONTROL         ,  "Object Control"},
	{ OBJECT_DATA            ,  "Object Data"},
	{ OBJECT_PICTURE         ,  "Object Picture"},
	{ OEM_DATA               ,  "OEM Data"},
	{ SAVE_OR_RESTORE_FORMAT ,  "Save/Restore Format"},
	{ SELECT_IPDS_MODE       ,  "Select IPDS Mode."},
	{ 0x00, NULL }
};

/* 5.11 Load Format Storage */
#define ADD                         0x01
#define DELETE_FORMAT               0x02 
#define DELETE_GROUP                0x03
#define RESET_ALL                   0x04
#define REQUEST_SUMMARY_STATUS      0x05
#define REQUEST_GROUP_STATUS        0x06

static const value_string vals_operand[] = {
	{ ADD                     ,  "Add"},
	{ DELETE_FORMAT           ,  "Delete Format"},
	{ DELETE_GROUP            ,  "Delete Group"},
	{ RESET_ALL               ,  "Reset All"},
	{ REQUEST_SUMMARY_STATUS  ,  "Request Summary Status"},
	{ REQUEST_GROUP_STATUS    ,  "Request Group Status"},
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

/* 3.5.6 Attention Identification Bytes (AID) */

#define NO_AID_GENERATED                    0x60
#define NO_AID_GENERATED_(PRINTER_ONLY)     0xE8
#define STRUCTURED_FIELD                    0x88
#define READ_PARTITION_AID                  0x61
#define TRIGGER_ACTION                      0x7F
#define TEST_REQ_AND_SYS_REQ                0xF0
#define PF1_KEY                             0xF1
#define PF2_KEY                             0xF2
#define PF3_KEY                             0xF3
#define PF4_KEY                             0xF4
#define PF5_KEY                             0xF5
#define PF6_KEY                             0xF6
#define PF7_KEY                             0xF7
#define PF8_KEY                             0xF8
#define PF9_KEY                             0xF9
#define PF10_KEY                            0x7A
#define PF11_KEY                            0x7B
#define PF12_KEY                            0x7C
#define PF13_KEY                            0xC1
#define PF14_KEY                            0xC2
#define PF15_KEY                            0xC3
#define PF16_KEY                            0xC4
#define PF17_KEY                            0xC5
#define PF18_KEY                            0xC6
#define PF19_KEY                            0xC7
#define PF20_KEY                            0xC8
#define PF21_KEY                            0xC9
#define PF22_KEY                            0x4A
#define PF23_KEY                            0x4B
#define PF24_KEY                            0x4C
#define PA1_KEY                             0x6C
#define PA2_KEY_(CNCL)                      0x6E
#define PA3_KEY                             0x6B
#define CLEAR_KEY                           0x6D
#define CLEAR_PARTITION_KEY                 0x6A
#define ENTER_KEY                           0x7D
#define SELECTOR_PEN_ATTENTION              0x7E
#define OPERATOR_ID_READER                  0xE6
#define MAG_READER_NUMBER                   0xE7


static const value_string vals_attention_identification_bytes[] = {
	{ NO_AID_GENERATED               ,  "No AID generated"},
	{ NO_AID_GENERATED_(PRINTER_ONLY),  "No AID generated (printer only)"},
	{ STRUCTURED_FIELD               ,  "Structured field"},
	{ READ_PARTITION_AID             ,  "Read partition"},
	{ TRIGGER_ACTION                 ,  "Trigger action"},
	{ TEST_REQ_AND_SYS_REQ           ,  "Test Req and Sys Req"},
	{ PF1_KEY                        ,  "PF1 key"},
	{ PF2_KEY                        ,  "PF2 key"},
	{ PF3_KEY                        ,  "PF3 key"},
	{ PF4_KEY                        ,  "PF4 key"},
	{ PF5_KEY                        ,  "PF5 key"},
	{ PF6_KEY                        ,  "PF6 key"},
	{ PF7_KEY                        ,  "PF7 key"},
	{ PF8_KEY                        ,  "PF8 key"},
	{ PF9_KEY                        ,  "PF9 key"},
	{ PF10_KEY                       ,  "PF10 key"},
	{ PF11_KEY                       ,  "PF11 key"},
	{ PF12_KEY                       ,  "PF12 key"},
	{ PF13_KEY                       ,  "PF13 key"},
	{ PF14_KEY                       ,  "PF14 key"},
	{ PF15_KEY                       ,  "PF15 key"},
	{ PF16_KEY                       ,  "PF16 key"},
	{ PF17_KEY                       ,  "PF17 key"},
	{ PF18_KEY                       ,  "PF18 key"},
	{ PF19_KEY                       ,  "PF19 key"},
	{ PF20_KEY                       ,  "PF20 key"},
	{ PF21_KEY                       ,  "PF21 key"},
	{ PF22_KEY                       ,  "PF22 key"},
	{ PF23_KEY                       ,  "PF23 key"},
	{ PF24_KEY                       ,  "PF24 key"},
	{ PA1_KEY                        ,  "PA1 key"},
	{ PA2_KEY_(CNCL)                 ,  "PA2 key (Cncl)"},
	{ PA3_KEY                        ,  "PA3 key"},
	{ CLEAR_KEY                      ,  "Clear key"},
	{ CLEAR_PARTITION_KEY            ,  "Clear Partition key"},
	{ ENTER_KEY                      ,  "Enter key"},
	{ SELECTOR_PEN_ATTENTION         ,  "Selector pen attention"},
	{ OPERATOR_ID_READER             ,  "Operator ID reader"},
	{ MAG_READER_NUMBER              ,  "Mag Reader Number"},
	{ 0x00, NULL }
};



/* 5.3.6 Object Control */
#define OCGRAPHICS  0x00
#define OCIMAGE     0x01

static const value_string vals_oc_type[] = {
	{ OCGRAPHICS,  "Graphics"},
	{ OCIMAGE   ,  "Image)"},
	{ 0x00, NULL }
};

/* 6.1 Inbound Structured Fields */

#define EXCEPTION_OR_STATUS                                      0x0F22
#define INBOUND_TEXT_HEADER                                      0x0FB1
#define INBOUND_3270DS                                           0x0F80 /* TODO: Check */
#define RECOVERY_DATA                                            0x1031
#define TYPE_1_TEXT_INBOUND                                      0x0FC1
#define QUERY_REPLY_ALPHANUMERIC_PARTITIONS                      0x8184
#define QUERY_REPLY_AUXILIARY_DEVICE                             0x8199
#define QUERY_REPLY_BEGIN_OR_END_OF_FILE                         0x819F
#define QUERY_REPLY_CHARACTER_SETS                               0x8185
#define QUERY_REPLY_COLOR                                        0x8186
#define QUERY_REPLY_COOPERATIVE_PROCESSING_REQUESTOR             0x81AB
#define QUERY_REPLY_DATA_CHAINING                                0x8198
#define QUERY_REPLY_DATA_STREAMS                                 0x81A2
#define QUERY_REPLY_DBCS_ASIA                                    0x8191
#define QUERY_REPLY_DEVICE_CHARACTERISTICS                       0x81A0
#define QUERY_REPLY_DISTRIBUTED_DATA_MANAGEMENT                  0x8195
#define QUERY_REPLY_DOCUMENT_INTERCHANGE_ARCHITECTURE            0x8197
#define QUERY_REPLY_EXTENDED_DRAWING_ROUTINE                     0x81B5
#define QUERY_REPLY_FIELD_OUTLINING                              0x818C
#define QUERY_REPLY_FIELD_VALIDATION                             0x818A
#define QUERY_REPLY_FORMAT_PRESENTATION                          0x8190
#define QUERY_REPLY_FORMAT_STORAGE_AUXILIARY_DEVICE              0x8194
#define QUERY_REPLY_GRAPHIC_COLOR                                0x81B4
#define QUERY_REPLY_GRAPHIC_SYMBOL_SETS                          0x81B6
#define QUERY_REPLY_HIGHLIGHTING                                 0x8187
#define QUERY_REPLY_IBM_AUXILIARY_DEVICE                         0x819E
#define QUERY_REPLY_IMAGE                                        0x8182
#define QUERY_REPLY_IMPLICIT_PARTITION                           0x81A6
#define QUERY_REPLY_IOCA_AUXILIARY_DEVICE                        0x81AA
#define QUERY_REPLY_LINE_TYPE                                    0x81B2
#define QUERY_REPLY_MSR_CONTROL                                  0x818B
#define QUERY_REPLY_NULL                                         0x81FF
#define QUERY_REPLY_OEM_AUXILIARY_DEVICE                         0x818F
#define QUERY_REPLY_PAPER_FEED_TECHNIQUES                        0x81A7
#define QUERY_REPLY_PARTITION_CHARACTERISTICS                    0x818E
#define QUERY_REPLY_PORT                                         0x81B3
#define QUERY_REPLY_PROCEDURE                                    0x81B1
#define QUERY_REPLY_PRODUCT_DEFINED_DATA_STREAM                  0x819C
#define QUERY_REPLY_REPLY_MODES                                  0x8188
#define QUERY_REPLY_RPQ_NAMES                                    0x81A1
#define QUERY_REPLY_SAVE_OR_RESTORE_FORMAT                       0x8192
#define QUERY_REPLY_SEGMENT                                      0x81B0
#define QUERY_REPLY_SETTABLE_PRINTER_CHARACTERISTICS             0x81A9
#define QUERY_REPLY_STORAGE_POOLS                                0x8196
#define QUERY_REPLY_SUMMARY                                      0x8180
#define QUERY_REPLY_TEXT_PARTITIONS                              0x8183
#define QUERY_REPLY_TRANSPARENCY                                 0x81A8
#define QUERY_REPLY_USABLE_AREA                                  0x8181
#define QUERY_REPLY_3270_IPDS                                    0x819A


static const value_string vals_inbound_structured_fields[] = {
	{ EXCEPTION_OR_STATUS                            ,  "Exception/Status"},
	{ INBOUND_TEXT_HEADER                            ,  "Inbound Text Header"},
	{ INBOUND_3270DS                                 ,  "Inbound 3270DS"},
	{ RECOVERY_DATA                                  ,  "Recovery Data"},
	{ TYPE_1_TEXT_INBOUND                            ,  "Type 1 Text Inbound"},
	{ QUERY_REPLY_ALPHANUMERIC_PARTITIONS            ,  "Query Reply (Alphanumeric Partitions)"},
	{ QUERY_REPLY_AUXILIARY_DEVICE                   ,  "Query Reply (Auxiliary Device)"},
	{ QUERY_REPLY_BEGIN_OR_END_OF_FILE               ,  "Query Reply (Begin/End of File)"},
	{ QUERY_REPLY_CHARACTER_SETS                     ,  "Query Reply (Character Sets)"},
	{ QUERY_REPLY_COLOR                              ,  "Query Reply (Color)"},
	{ QUERY_REPLY_COOPERATIVE_PROCESSING_REQUESTOR   ,  "Query Reply (Cooperative Processing Requestor)"},
	{ QUERY_REPLY_DATA_CHAINING                      ,  "Query Reply (Data Chaining)"},
	{ QUERY_REPLY_DATA_STREAMS                       ,  "Query Reply (Data Streams)"},
	{ QUERY_REPLY_DBCS_ASIA                          ,  "Query Reply (DBCS-Asia)"},
	{ QUERY_REPLY_DEVICE_CHARACTERISTICS             ,  "Query Reply (Device Characteristics)"},
	{ QUERY_REPLY_DISTRIBUTED_DATA_MANAGEMENT        ,  "Query Reply (Distributed Data Management)"},
	{ QUERY_REPLY_DOCUMENT_INTERCHANGE_ARCHITECTURE  ,  "Query Reply (Document Interchange Architecture)"},
	{ QUERY_REPLY_EXTENDED_DRAWING_ROUTINE           ,  "Query Reply (Extended Drawing Routine)"},
	{ QUERY_REPLY_FIELD_OUTLINING                    ,  "Query Reply (Field Outlining)"},
	{ QUERY_REPLY_FIELD_VALIDATION                   ,  "Query Reply (Field Validation)"},
	{ QUERY_REPLY_FORMAT_PRESENTATION                ,  "Query Reply (Format Presentation)"},
	{ QUERY_REPLY_FORMAT_STORAGE_AUXILIARY_DEVICE    ,  "Query Reply (Format Storage Auxiliary Device)"},
	{ QUERY_REPLY_GRAPHIC_COLOR                      ,  "Query Reply (Graphic Color)"},
	{ QUERY_REPLY_GRAPHIC_SYMBOL_SETS                ,  "Query Reply (Graphic Symbol Sets)"},
	{ QUERY_REPLY_HIGHLIGHTING                       ,  "Query Reply (Highlighting)"},
	{ QUERY_REPLY_IBM_AUXILIARY_DEVICE               ,  "Query Reply (IBM Auxiliary Device)"},
	{ QUERY_REPLY_IMAGE                              ,  "Query Reply (Image)"},
	{ QUERY_REPLY_IMPLICIT_PARTITION                 ,  "Query Reply (Implicit Partition)"},
	{ QUERY_REPLY_IOCA_AUXILIARY_DEVICE              ,  "Query Reply (IOCA Auxiliary Device)"},
	{ QUERY_REPLY_LINE_TYPE                          ,  "Query Reply (Line Type)"},
	{ QUERY_REPLY_MSR_CONTROL                        ,  "Query Reply (MSR Control)"},
	{ QUERY_REPLY_NULL                               ,  "Query Reply (Null)"},
	{ QUERY_REPLY_OEM_AUXILIARY_DEVICE               ,  "Query Reply (OEM Auxiliary Device)"},
	{ QUERY_REPLY_PAPER_FEED_TECHNIQUES              ,  "Query Reply (Paper Feed Techniques)"},
	{ QUERY_REPLY_PARTITION_CHARACTERISTICS          ,  "Query Reply (Partition Characteristics)"},
	{ QUERY_REPLY_PORT                               ,  "Query Reply (Port)"},
	{ QUERY_REPLY_PROCEDURE                          ,  "Query Reply (Procedure)"},
	{ QUERY_REPLY_PRODUCT_DEFINED_DATA_STREAM        ,  "Query Reply (Product Defined Data Stream)"},
	{ QUERY_REPLY_REPLY_MODES                        ,  "Query Reply (Reply Modes)"},
	{ QUERY_REPLY_RPQ_NAMES                          ,  "Query Reply (RPQ Names)"},
	{ QUERY_REPLY_SAVE_OR_RESTORE_FORMAT             ,  "Query Reply (Save/Restore Format)"},
	{ QUERY_REPLY_SEGMENT                            ,  "Query Reply (Segment)"},
	{ QUERY_REPLY_SETTABLE_PRINTER_CHARACTERISTICS   ,  "Query Reply (Settable Printer Characteristics)"},
	{ QUERY_REPLY_STORAGE_POOLS                      ,  "Query Reply (Storage Pools)"},
	{ QUERY_REPLY_SUMMARY                            ,  "Query Reply (Summary)"},
	{ QUERY_REPLY_TEXT_PARTITIONS                    ,  "Query Reply (Text Partitions)"},
	{ QUERY_REPLY_TRANSPARENCY                       ,  "Query Reply (Transparency)"},
	{ QUERY_REPLY_USABLE_AREA                        ,  "Query Reply (Usable Area)"},
	{ QUERY_REPLY_3270_IPDS                          ,  "Query Reply (3270 IPDS)."},
	{ 0x00, NULL }
};

/* 6.2 - Exception/Status */

#define ACKNOWLEDGED     0x0000
#define AUXDEVICEAVAIL   0X0001

static const value_string vals_statcode[] = {
	{ ACKNOWLEDGED   ,  "Acknowledged. The formats were successfully loaded, and no exception occurred."},
	{ AUXDEVICEAVAIL ,  "Auxiliary device available"},
	{ 0x00, NULL }
};


#define INVALID_DOID     0x0801
#define DEVICENOTAVAIL   0X0802
#define RETIRED          0X0803
#define BUFFER_OVERRUN   0X0804
#define STORAGE          0X0805
#define FORMATNOTSPEC    0X0806
#define DATAERROR        0X0807
#define INSUFFRESOURCE   0X084B
#define EXCEEDSLIMIT     0X084C
#define FUNCTNOTSUPP     0X1003

static const value_string vals_excode[] = {
	{ INVALID_DOID    ,  "Invalid/unrecognized DOID in the Destination/Origin structured field. "
	                     "AVAILSTAT must be set to B'0'."},
	{ DEVICENOTAVAIL  ,  "DOID valid, but the auxiliary device is not available because of an "
	                     "intervention required condition (for example, out of paper, power "
	                     "off, or processing code not resident). Available status is sent "
	                     "when the condition clears. AVAILSTAT must be set to B'1'."},
	{ RETIRED         ,  "Retired."},
	{ BUFFER_OVERRUN  ,  "Buffer overrun."},
	{ STORAGE         ,  "Insufficient storage. The loading of the formats could not be "
	                     "completed because storage was exhausted."},
	{ FORMATNOTSPEC   ,  "The format or group name was not specified in the Load Format "
	                     "Storage structured field."},
	{ DATAERROR       ,  "Data error."},
	{ INSUFFRESOURCE  ,  "Temporary insufficient resource. The application does not have "
	                     "a buffer available or is busy. The device chooses whether to "
	                     "set send status when the condition clears and set AVAILSTAT accordingly."},
	{ EXCEEDSLIMIT    ,  "The auxiliary device data in the transmission exceeds the limit specified "
	                     "in the LIMOUT parameter of the Query Reply for the auxiliary device. "
	                     "AVAILSTAT must be set to B'0'."},
	{ FUNCTNOTSUPP    ,  "Function not supported."},
	{ 0x00, NULL }
};

/* Query Reply Types */
#define ALPHANUMERIC_PARTITIONS                      0x84
#define AUXILIARY_DEVICE                             0x99
#define QBEGIN_OR_END_OF_FILE                        0x9F
#define CHARACTER_SETS                               0x85
#define COLOR                                        0x86
#define COOPERATIVE_PROCESSING_REQUESTOR             0xAB
#define DATA_CHAINING                                0x98
#define DATA_STREAMS                                 0xA2
#define DBCS_ASIA                                    0x91
#define DEVICE_CHARACTERISTICS                       0xA0
#define DISTRIBUTED_DATA_MANAGEMENT                  0x95
#define DOCUMENT_INTERCHANGE_ARCHITECTURE            0x97
#define EXTENDED_DRAWING_ROUTINE                     0xB5
#define QFIELD_OUTLINING                             0x8C
#define QFIELD_VALIDATION                            0x8A
#define FORMAT_PRESENTATION                          0x90
#define FORMAT_STORAGE_AUXILIARY_DEVICE              0x94
#define GRAPHIC_COLOR                                0xB4
#define GRAPHIC_SYMBOL_SETS                          0xB6
#define HIGHLIGHTING                                 0x87
#define IBM_AUXILIARY_DEVICE                         0x9E
#define IMAGE                                        0x82
#define IMPLICIT_PARTITION                           0xA6
#define IOCA_AUXILIARY_DEVICE                        0xAA
#define LINE_TYPE                                    0xB2
#define MSR_CONTROL                                  0x8B
#define QNULL                                        0xFF
#define OEM_AUXILIARY_DEVICE                         0x8F
#define PAPER_FEED_TECHNIQUES                        0xA7
#define PARTITION_CHARACTERISTICS                    0x8E
#define PORT                                         0xB3
#define PROCEDURE                                    0xB1
#define PRODUCT_DEFINED_DATA_STREAM                  0x9C
#define REPLY_MODES                                  0x88
#define RPQ_NAMES                                    0xA1
#define QSAVE_OR_RESTORE_FORMAT                      0x92
#define SEGMENT                                      0xB0
#define SETTABLE_PRINTER_CHARACTERISTICS             0xA9
#define STORAGE_POOLS                                0x96
#define SUMMARY                                      0x80
#define TEXT_PARTITIONS                              0x83
#define QTRANSPARENCY                                0xA8
#define USABLE_AREA                                  0x81
#define T3270_IPDS                                   0x9A


static const value_string vals_query_replies[] = {
	{ ALPHANUMERIC_PARTITIONS            ,  "Alphanumeric Partitions"},
	{ AUXILIARY_DEVICE                   ,  "Auxiliary Device"},
	{ QBEGIN_OR_END_OF_FILE              ,  "Begin/End of File"},
	{ CHARACTER_SETS                     ,  "Character Sets"},
	{ COLOR                              ,  "Color"},
	{ COOPERATIVE_PROCESSING_REQUESTOR   ,  "Cooperative Processing Requestor"},
	{ DATA_CHAINING                      ,  "Data Chaining"},
	{ DATA_STREAMS                       ,  "Data Streams"},
	{ DBCS_ASIA                          ,  "DBCS-Asia"},
	{ DEVICE_CHARACTERISTICS             ,  "Device Characteristics"},
	{ DISTRIBUTED_DATA_MANAGEMENT        ,  "Distributed Data Management"},
	{ DOCUMENT_INTERCHANGE_ARCHITECTURE  ,  "Document Interchange Architecture"},
	{ EXTENDED_DRAWING_ROUTINE           ,  "Extended Drawing Routine"},
	{ QFIELD_OUTLINING                   ,  "Field Outlining"},
	{ QFIELD_VALIDATION                  ,  "Field Validation"},
	{ FORMAT_PRESENTATION                ,  "Format Presentation"},
	{ FORMAT_STORAGE_AUXILIARY_DEVICE    ,  "Format Storage Auxiliary Device"},
	{ GRAPHIC_COLOR                      ,  "Graphic Color"},
	{ GRAPHIC_SYMBOL_SETS                ,  "Graphic Symbol Sets"},
	{ HIGHLIGHTING                       ,  "Highlighting"},
	{ IBM_AUXILIARY_DEVICE               ,  "IBM Auxiliary Device"},
	{ IMAGE                              ,  "Image"},
	{ IMPLICIT_PARTITION                 ,  "Implicit Partition"},
	{ IOCA_AUXILIARY_DEVICE              ,  "IOCA Auxiliary Device"},
	{ LINE_TYPE                          ,  "Line Type"},
	{ MSR_CONTROL                        ,  "MSR Control"},
	{ QNULL                              ,  "Null"},
	{ OEM_AUXILIARY_DEVICE               ,  "OEM Auxiliary Device"},
	{ PAPER_FEED_TECHNIQUES              ,  "Paper Feed Techniques"},
	{ PARTITION_CHARACTERISTICS          ,  "Partition Characteristics"},
	{ PORT                               ,  "Port"},
	{ PROCEDURE                          ,  "Procedure"},
	{ PRODUCT_DEFINED_DATA_STREAM        ,  "Product Defined Data Stream"},
	{ REPLY_MODES                        ,  "Reply Modes"},
	{ RPQ_NAMES                          ,  "RPQ Names"},
	{ QSAVE_OR_RESTORE_FORMAT            ,  "Save/Restore Format"},
	{ SEGMENT                            ,  "Segment"},
	{ SETTABLE_PRINTER_CHARACTERISTICS   ,  "Settable Printer Characteristics"},
	{ STORAGE_POOLS                      ,  "Storage Pools"},
	{ SUMMARY                            ,  "Summary"},
	{ TEXT_PARTITIONS                    ,  "Text Partitions"},
	{ QTRANSPARENCY                      ,  "Transparency"},
	{ USABLE_AREA                        ,  "Usable Area"},
	{ T3270_IPDS                         ,  "3270 IPDS."},
	{ 0x00, NULL }
};

/* 6.9 Query Reply Alphanumeric Partitions */

#define VERTWIN          0x80
#define HORWIN           0x40
#define APRES1           0x20
#define APA_FLG          0x10
#define PROT             0x08
#define LCOPY            0x04
#define MODPART          0x02
#define APRES2           0x01

/* 6.12 - Query Reply (Character Sets) */
#define ALT              0x80
#define MULTID           0x40
#define LOADABLE         0x20
#define EXT              0x10
#define MS               0x08
#define CH2              0x04
#define GF               0x02
#define CSRES            0x01

#define CSRES2           0x80
#define PSCS             0x40
#define CSRES3           0x20
#define CF               0x10
#define CSRES4           0x08
#define CSRES5           0x04
#define GCSRES6          0x02
#define CSRES7           0x01


/* 6.16 Query Reply (Data Streams) */
#define SCS      0x00
#define DCAL2    0x01
#define IPDS     0x02

static const value_string vals_data_streams[] = {
	{ SCS  ,  "SCS Base Data Stream with extensions as specified in the BIND request and Device Characteristics Query Reply structured field"},
	{ DCAL2,  "Document Content Architecture Level 2"},
	{ IPDS ,  "IPDS as defined in related documentation"},
	{ 0x00, NULL }
};

/* 6.51 Query Reply Usable Area */
#define UA_RESERVED1                                    0x80
#define PAGE_PRINTER                                    0x40
#define UA_RESERVED2                                    0x20
#define HARD_COPY                                       0x10

#define UA_RESERVED3                                    0x00
#define TWELVE_FOURTEEN_BIT_ADDRESSING                  0x01
#define UA_RESERVED4                                    0x02
#define TWELVE_FOURTEEN_SXTN_BIT_ADDRESSING             0x03
#define UNMAPPED                                        0x0F

static const value_string vals_usable_area_flags1[] = {
	{ UA_RESERVED3                         ,  "RESERVED "},
	{ TWELVE_FOURTEEN_BIT_ADDRESSING       ,  "TWELVE FOURTEEN BIT ADDRESSING"},
	{ UA_RESERVED4                         ,  "RESERVED"},
	{ TWELVE_FOURTEEN_SXTN_BIT_ADDRESSING  ,  "TWELVE FOURTEEN SXTN BIT ADDRESSING"},
	{ UNMAPPED                             ,  "UNMAPPED"},
	{ 0x00, NULL }
};

#define VARIABLE_CELLS                                  0x10
#define CHARACTERS                                      0x20
#define CELL_UNITS                                      0x40

#define INCHES 0x00
#define MM     0x01

static const value_string vals_usable_area_uom[] = {
	{ INCHES    ,  "Inches"},
	{ MM        ,  "Millimetres"},
	{ 0x00, NULL }
};

/* 6.42 - Reply Modes */

#define FIELD_MODE              0x00
#define EXTENDED_FIELD_MODE     0x01
#define CHARACTER_MODE          0x02

static const value_string vals_modes[] = {
	{ FIELD_MODE         ,  "Field Mode"},
	{ EXTENDED_FIELD_MODE,  "Extended Field Mode"},
	{ CHARACTER_MODE     ,  "Character Mode"},
	{ 0x00, NULL }
};

/* 6.19 - Query Reply (Distributed Data Management) */
#define DDM_COPY_SUBSET_1       0x01

static const value_string vals_ddm[] = {
	{ DDM_COPY_SUBSET_1         ,  "DDM Copy Subset 1"},
	{ 0x00, NULL }
};

/* 6.20 - Query Reply (Document Interchange Architecture) */
#define FILE_SERVER       0x01
#define FILE_REQ          0x02
#define FILE_SERVER_REQ   0x03

static const value_string vals_dia[] = {
	{ FILE_SERVER             ,  "File Server"},
	{ FILE_REQ                ,  "File Requestor"},
	{ FILE_SERVER_REQ         ,  "Both File Server and File Requestor"},
	{ 0x00, NULL }
}; 

/* 6.31 - Query Reply (Implicit Partitions) */
#define DISPLAY       0x01
#define PRINTER       0x02
#define CHARACTER     0x03

static const value_string vals_ip[] = {
	{ DISPLAY           ,  "Display Devices"},
	{ PRINTER           ,  "Printer Devices"},
	{ CHARACTER         ,  "Character Devices"},
	{ 0x00, NULL }
};

/* 6.41 - Query Reply (Product Defined Data Streams) */
#define GRAPH5080     0x01
#define WHIPAPI       0x02

static const value_string vals_pdds_refid[] = {
	{ GRAPH5080        ,  "Supports the 5080 Graphics System"},
	{ WHIPAPI          ,  "Supports the WHIP API data stream"},
	{ 0x00, NULL }
};

#define HFGD          0x01
#define RS232         0x02

static const value_string vals_pdds_ssid[] = {
	{ HFGD            ,  "5080 HFGD Graphics Subset"},
	{ RS232           ,  "5080 RS232 Ports Subset"},
	{ 0x00, NULL }
};

/* 6.47 - Query Reply (Storage Pools) */
#define  SEGMENT1               0x0001
#define  PROCEDURE1             0x0002
#define  EXTENDED_DRAWING       0x0003
#define  DATA_UNIT              0x0004
#define  TEMPORARY              0x0005
#define  LINE_TYPE1             0x0006
#define  SYMBOL_SET             0x0007

static const value_string vals_objlist[] = {
	{ SEGMENT1          ,  "Segment"},
	{ PROCEDURE1        ,  "Procedure"},
	{ EXTENDED_DRAWING  ,  "Extended drawing routine"},
	{ DATA_UNIT         ,  "Data unit"},
	{ TEMPORARY         ,  "Temporary"},
	{ LINE_TYPE1        ,  "Line type"},
	{ SYMBOL_SET        ,  "Symbol set"},
	{ 0x00, NULL }
};

/* TN3270E Header - Data Type */
#define TN3270E_3270_DATA        0x00
#define TN3270E_BIND_IMAGE       0x03
#define TN3270E_NVT_DATA         0x05
#define TN3270E_REQUEST          0x06
#define TN3270E_RESPONSE         0x02
#define TN3270E_SCS_DATA         0x01
#define TN3270E_SSCP_LU_DATA     0x07
#define TN3270E_UNBIND           0x04

static const value_string vals_tn3270_header_data_types[] = {
	{ TN3270E_3270_DATA   ,  "3270_DATA"},
	{ TN3270E_BIND_IMAGE  ,  "BIND_IMAGE"},
	{ TN3270E_NVT_DATA    ,  "NVT_DATA"},
	{ TN3270E_REQUEST     ,  "REQUEST"},
	{ TN3270E_RESPONSE    ,  "RESPONSE"},
	{ TN3270E_SCS_DATA    ,  "SCS_DATA"},
	{ TN3270E_SSCP_LU_DATA,  "SSCP_LU_DATA"},
	{ TN3270E_UNBIND      ,  "UNBIND"},
	{ 0x00, NULL }
};


/* TN3270E Header - Request Flags */
#define TN3270E_COND_CLEARED        0x00

static const value_string vals_tn3270_header_request_flags[] = {
	{ TN3270E_COND_CLEARED   ,  "Condition Cleared"},
	{ 0x00, NULL }
};

/* TN3270E Header - Response Flags - Data Type 3270 and SCS */
#define TN3270E_ALWAYS_RESPONSE     0x02
#define TN3270E_ERROR_RESPONSE      0x01
#define TN3270E_NO_RESPONSE         0x00

static const value_string vals_tn3270_header_response_flags_3270_SCS[] = {
	{ TN3270E_ALWAYS_RESPONSE,  "ALWAYS-RESPONSE"},
	{ TN3270E_ERROR_RESPONSE ,  "ERROR-RESPONSE "},
	{ TN3270E_NO_RESPONSE    ,  "NO-RESPONSE    "},
	{ 0x00, NULL }
};

/* TN3270E Header _ Response Flags - Data Type Response */
#define TN3270E_POSITIVE_RESPONSE   0x00
#define TN3270E_NEGATIVE_RESPONSE   0x01

static const value_string vals_tn3270_header_response_flags_response[] = {
	{ TN3270E_POSITIVE_RESPONSE,  "POSITIVE-RESPONSE"},
	{ TN3270E_NEGATIVE_RESPONSE,  "NEGATIVE-RESPONSE"},
	{ 0x00, NULL }
};


/*
 * Data structure attached to a conversation, giving authentication
 * information from a bind request.
 * We keep a linked list of them, so that we can free up all the
 * authentication mechanism strings.
 */
typedef struct tn3270_conv_info_t {
  struct tn3270_conv_info_t *next;
  address outbound_addr;
  guint32 outbound_port;
  address inbound_addr;
  guint32 inbound_port;
  gint extended;
} tn3270_conv_info_t;

void add_tn3270_conversation(packet_info *pinfo, int tn3270e);
int find_tn3270_conversation(packet_info *pinfo);

#endif
