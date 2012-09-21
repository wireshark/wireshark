/* packet-bthid.c
 * Routines for Bluetooth HID dissection
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-btl2cap.h"
#include "packet-btsdp.h"

static int proto_bthid                                                     = -1;
static int hf_bthid_transaction_type                                       = -1;
static int hf_bthid_parameter_reserved                                     = -1;
static int hf_bthid_parameter_reserved_31                                  = -1;
static int hf_bthid_parameter_reserved_32                                  = -1;
static int hf_bthid_parameter_reserved_2                                   = -1;
static int hf_bthid_parameter_result_code                                  = -1;
static int hf_bthid_parameter_control_operation                            = -1;
static int hf_bthid_parameter_size                                         = -1;
static int hf_bthid_protocol                                               = -1;
static int hf_bthid_idle_rate                                              = -1;
static int hf_bthid_parameter_report_type                                  = -1;
static int hf_bthid_report_id                                              = -1;
static int hf_bthid_buffer_size                                            = -1;
static int hf_bthid_protocol_code                                          = -1;
static int hf_bthid_data_keyboard_modifier_right_gui                       = -1;
static int hf_bthid_data_keyboard_modifier_right_alt                       = -1;
static int hf_bthid_data_keyboard_modifier_right_shift                     = -1;
static int hf_bthid_data_keyboard_modifier_right_ctrl                      = -1;
static int hf_bthid_data_keyboard_modifier_left_gui                        = -1;
static int hf_bthid_data_keyboard_modifier_left_alt                        = -1;
static int hf_bthid_data_keyboard_modifier_left_shift                      = -1;
static int hf_bthid_data_keyboard_modifier_left_ctrl                       = -1;
static int hf_bthid_data_keyboard_reserved                                 = -1;
static int hf_bthid_data_keyboard_keycode_1                                = -1;
static int hf_bthid_data_keyboard_keycode_2                                = -1;
static int hf_bthid_data_keyboard_keycode_3                                = -1;
static int hf_bthid_data_keyboard_keycode_4                                = -1;
static int hf_bthid_data_keyboard_keycode_5                                = -1;
static int hf_bthid_data_keyboard_keycode_6                                = -1;
static int hf_bthid_data_keyboard_leds_constants                           = -1;
static int hf_bthid_data_keyboard_leds_kana                                = -1;
static int hf_bthid_data_keyboard_leds_compose                             = -1;
static int hf_bthid_data_keyboard_leds_scroll_lock                         = -1;
static int hf_bthid_data_keyboard_leds_caps_lock                           = -1;
static int hf_bthid_data_keyboard_leds_num_lock                            = -1;
static int hf_bthid_data_mouse_button_8                                    = -1;
static int hf_bthid_data_mouse_button_7                                    = -1;
static int hf_bthid_data_mouse_button_6                                    = -1;
static int hf_bthid_data_mouse_button_5                                    = -1;
static int hf_bthid_data_mouse_button_4                                    = -1;
static int hf_bthid_data_mouse_button_middle                               = -1;
static int hf_bthid_data_mouse_button_right                                = -1;
static int hf_bthid_data_mouse_button_left                                 = -1;
static int hf_bthid_data_mouse_x_displacement                              = -1;
static int hf_bthid_data_mouse_y_displacement                              = -1;
static int hf_bthid_data_mouse_horizontal_scroll_wheel                     = -1;
static int hf_bthid_data_mouse_vertical_scroll_wheel                       = -1;

static int hf_bthid_data                                                   = -1;

static gint ett_bthid             = -1;

static const value_string transaction_type_vals[] = {
    { 0x00,   "HANDSHAKE" },
    { 0x01,   "HID_CONTROL" },
    { 0x02,   "reserved" },
    { 0x03,   "reserved" },
    { 0x04,   "GET_REPORT" },
    { 0x05,   "SET_REPORT" },
    { 0x06,   "GET_PROTOCOL" },
    { 0x07,   "SET_PROTOCOL" },
    { 0x08,   "GET_IDLE" },
    { 0x09,   "SET_IDLE" },
    { 0x0A,   "DATA" },
    { 0x0B,   "DATC" },
    { 0x0C,   "reserved" },
    { 0x0D,   "reserved" },
    { 0x0E,   "reserved" },
    { 0x0F,   "reserved" },
    { 0, NULL }
};

static const value_string report_type_vals[] = {
    { 0x00,   "Other" },
    { 0x01,   "Input" },
    { 0x02,   "Output" },
    { 0x03,   "Feature" },
    { 0, NULL }
};

static const value_string result_code_vals[] = {
    { 0x00,   "Successful" },
    { 0x01,   "Not Ready" },
    { 0x02,   "Error, Invalid Report ID" },
    { 0x03,   "Error, Unsupported Request" },
    { 0x04,   "Error, Invalid Parameters" },
    { 0x0E,   "Error, Unknown " },
    { 0x0F,   "Error, Fatal " },
    { 0, NULL }
};

static const value_string control_operation_vals[] = {
    { 0x00,   "NOP" },
    { 0x01,   "Hard Reset" },
    { 0x02,   "Soft Reset" },
    { 0x03,   "Suspend" },
    { 0x04,   "Exit Suspend" },
    { 0x05,   "Virtual Cable Unplug" },
    { 0, NULL }
};

static const value_string size_vals[] = {
    { 0x00,   "Buffer equal to report size" },
    { 0x01,   "BufferSize field follows the Report ID" },
    { 0, NULL }
};

static const value_string protocol_vals[] = {
    { 0x00,   "Report" },
    { 0x01,   "Boot" },
    { 0, NULL }
};

static const value_string protocol_code_vals[] = {
    { 0x00,   "None" },
    { 0x01,   "Keyboard" },
    { 0x02,   "Mouse" },
    { 0, NULL }
};

static const value_string keycode_vals[] = {
    { 0x00,   "<ACTION KEY UP>" },
    { 0x01,   "ErrorRollOver" },
    { 0x02,   "POSTFail" },
    { 0x03,   "ErrorUndefined" },

    { 0x04,   "a" },
    { 0x05,   "b" },
    { 0x06,   "c" },
    { 0x07,   "d" },
    { 0x08,   "e" },
    { 0x09,   "f" },
    { 0x0A,   "g" },
    { 0x0B,   "h" },
    { 0x0C,   "i" },
    { 0x0D,   "j" },
    { 0x0E,   "k" },
    { 0x0F,   "l" },
    { 0x10,   "m" },
    { 0x11,   "n" },
    { 0x12,   "o" },
    { 0x13,   "p" },
    { 0x14,   "q" },
    { 0x15,   "r" },
    { 0x16,   "s" },
    { 0x17,   "t" },
    { 0x18,   "u" },
    { 0x19,   "v" },
    { 0x1A,   "w" },
    { 0x1B,   "x" },
    { 0x1C,   "y" },
    { 0x1D,   "z" },

    { 0x1E,   "1" },
    { 0x1F,   "2" },
    { 0x20,   "3" },
    { 0x21,   "4" },
    { 0x22,   "5" },
    { 0x23,   "6" },
    { 0x24,   "7" },
    { 0x25,   "8" },
    { 0x26,   "9" },
    { 0x27,   "0" },

    { 0x28,   "ENTER" },
    { 0x29,   "Escape" },
    { 0x2A,   "Backspace" },
    { 0x2B,   "Tab" },
    { 0x2C,   "Spacebar" },

    { 0x2D,   "-" },
    { 0x2E,   "=" },
    { 0x2F,   "[" },
    { 0x30,   "]" },
    { 0x31,   "\\" },
    { 0x32,   "NonUS #/~" },
    { 0x33,   ";" },
    { 0x34,   "'" },
    { 0x35,   "`" },
    { 0x36,   "," },
    { 0x37,   "." },
    { 0x38,   "/" },
    { 0x39,   "CapsLock" },
    { 0x3A,   "F1" },
    { 0x3B,   "F2" },
    { 0x3C,   "F3" },
    { 0x3D,   "F4" },
    { 0x3E,   "F5" },
    { 0x3F,   "F6" },
    { 0x40,   "F7" },
    { 0x41,   "F8" },
    { 0x42,   "F9" },
    { 0x43,   "F10" },
    { 0x44,   "F11" },
    { 0x45,   "F12" },
    { 0x46,   "PrintScreen" },
    { 0x47,   "ScrollLock" },
    { 0x48,   "Pause" },
    { 0x49,   "Insert" },
    { 0x4A,   "Home" },
    { 0x4B,   "PageUp" },
    { 0x4C,   "DeleteForward" },
    { 0x4D,   "End" },
    { 0x4E,   "PageDown" },
    { 0x4F,   "RightArrow" },
    { 0x50,   "LeftArrow" },
    { 0x51,   "DownArrow" },
    { 0x52,   "UpArrow" },
    { 0x53,   "NumLock" },

    /* Keypad */
    { 0x54,   "Keypad /" },
    { 0x55,   "Keypad *" },
    { 0x56,   "Keypad -" },
    { 0x57,   "Keypad +" },
    { 0x58,   "Keypad ENTER" },
    { 0x59,   "Keypad 1" },
    { 0x5A,   "Keypad 2" },
    { 0x5B,   "Keypad 3" },
    { 0x5C,   "Keypad 4" },
    { 0x5D,   "Keypad 5" },
    { 0x5E,   "Keypad 6" },
    { 0x5F,   "Keypad 7" },
    { 0x60,   "Keypad 8" },
    { 0x61,   "Keypad 9" },
    { 0x62,   "Keypad 0" },
    { 0x63,   "Keypad ." },

    /* non PC AT */
    { 0x64,   "NonUS \\/|" },
    { 0x65,   "Application" },
    { 0x66,   "Power" },
    { 0x67,   "Keypad =" },
    { 0x68,   "F13" },
    { 0x69,   "F14" },
    { 0x6A,   "F15" },
    { 0x6B,   "F16" },
    { 0x6C,   "F17" },
    { 0x6D,   "F18" },
    { 0x6E,   "F19" },
    { 0x6F,   "F20" },

    { 0x70,   "F21" },
    { 0x71,   "F22" },
    { 0x72,   "F23" },
    { 0x73,   "F24" },
    { 0x74,   "Execute" },
    { 0x75,   "Help" },
    { 0x76,   "Menu" },
    { 0x77,   "Select" },
    { 0x78,   "Stop" },
    { 0x79,   "Again" },
    { 0x7A,   "Undo" },
    { 0x7B,   "Cut" },
    { 0x7C,   "Copy" },
    { 0x7D,   "Paste" },
    { 0x7E,   "Find" },
    { 0x7F,   "Mute" },

    { 0x80,   "VolumeUp" },
    { 0x81,   "VolumeDown" },
    { 0x82,   "Locking CapsLock" },
    { 0x83,   "Locking NumLock" },
    { 0x84,   "Locking ScrollLock" },
    { 0x85,   "Keypad Comma" },
    { 0x86,   "Keypad EqualSign" },
    { 0x87,   "International1" },
    { 0x88,   "International2" },
    { 0x89,   "International3" },
    { 0x8A,   "International4" },
    { 0x8B,   "International5" },
    { 0x8C,   "International6" },
    { 0x8D,   "International7" },
    { 0x8E,   "International8" },
    { 0x8F,   "International9" },

    { 0x90,   "LANG1" },
    { 0x91,   "LANG2" },
    { 0x92,   "LANG3" },
    { 0x93,   "LANG4" },
    { 0x94,   "LANG5" },
    { 0x95,   "LANG6" },
    { 0x96,   "LANG7" },
    { 0x97,   "LANG8" },
    { 0x98,   "LANG9" },
    { 0x99,   "AlternateErase" },
    { 0x9A,   "SysReq/Attention" },
    { 0x9B,   "Cancel" },
    { 0x9C,   "Clear" },
    { 0x9D,   "Prior" },
    { 0x9E,   "Return" },
    { 0x9F,   "Separator" },

    { 0xA0,   "Out" },
    { 0xA1,   "Oper" },
    { 0xA2,   "Clear/Again" },
    { 0xA3,   "CrSel/Props" },
    { 0xA4,   "ExSel" },
    /* 0xA5..0xAF - reserved */
    { 0xB0,   "Keypad 00" },
    { 0xB1,   "Keypad 000" },
    { 0xB2,   "ThousandsSeparator" },
    { 0xB3,   "DecimalSeparator" },
    { 0xB4,   "CurrencyUnit" },
    { 0xB5,   "CurrencySubunit" },
    { 0xB6,   "Keypad (" },
    { 0xB7,   "Keypad )" },
    { 0xB8,   "Keypad {" },
    { 0xB9,   "Keypad }" },
    { 0xBA,   "Keypad Tab" },
    { 0xBB,   "Keypad Backspace" },
    { 0xBC,   "Keypad A" },
    { 0xBD,   "Keypad B" },
    { 0xBE,   "Keypad C" },
    { 0xBF,   "Keypad D" },

    { 0xC0,   "Keypad E" },
    { 0xC1,   "Keypad F" },
    { 0xC2,   "Keypad XOR" },
    { 0xC3,   "Keypad ^" },
    { 0xC4,   "Keypad %" },
    { 0xC5,   "Keypad <" },
    { 0xC6,   "Keypad >" },
    { 0xC7,   "Keypad &" },
    { 0xC8,   "Keypad &&" },
    { 0xC9,   "Keypad |" },
    { 0xCA,   "Keypad ||" },
    { 0xCB,   "Keypad :" },
    { 0xCC,   "Keypad #" },
    { 0xCD,   "Keypad Space" },
    { 0xCE,   "Keypad @" },
    { 0xCF,   "Keypad !" },

    { 0xD0,   "Keypad Memory Store" },
    { 0xD1,   "Keypad Memory Recall" },
    { 0xD2,   "Keypad Memory Clear" },
    { 0xD3,   "Keypad Memory Add" },
    { 0xD4,   "Keypad Memory Subtract" },
    { 0xD5,   "Keypad Memory Multiply" },
    { 0xD6,   "Keypad Memory Divide" },
    { 0xD7,   "Keypad +/-" },
    { 0xD8,   "Keypad Clear" },
    { 0xD9,   "Keypad Clear Entry" },
    { 0xDA,   "Keypad Binary" },
    { 0xDB,   "Keypad Octal" },
    { 0xDC,   "Keypad Decimal" },
    { 0xDD,   "Keypad Hexadecimal" },
    /* 0xDE..0xDF - reserved,  */
    { 0xE0,   "LeftControl" },
    { 0xE1,   "LeftShift" },
    { 0xE2,   "LeftAlt" },
    { 0xE3,   "LeftGUI" },
    { 0xE4,   "RightControl" },
    { 0xE5,   "RightShift" },
    { 0xE6,   "RightAlt" },
    { 0xE7,   "RightGUI" },

    { 0, NULL }
};

value_string_ext keycode_vals_ext = VALUE_STRING_EXT_INIT(keycode_vals);


static int
dissect_hid_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, unsigned int report_type)
{
    unsigned int protocol_code;
    unsigned int shortcut_helper = 0;
    unsigned int modifier;
    unsigned int keycode;
    unsigned int leds;
    unsigned int buttons;

    proto_tree_add_item(tree, hf_bthid_protocol_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    protocol_code = tvb_get_guint8(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str(protocol_code, protocol_code_vals, "unknown type"));
    offset += 1;


    switch (protocol_code) {
        case 0x01: /* Keyboard */
            if (report_type == 0x02) { /* Output - LEDs */
                proto_tree_add_item(tree, hf_bthid_data_keyboard_leds_constants, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_bthid_data_keyboard_leds_kana, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_bthid_data_keyboard_leds_compose, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_bthid_data_keyboard_leds_scroll_lock, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_bthid_data_keyboard_leds_caps_lock, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_bthid_data_keyboard_leds_num_lock, tvb, offset, 1, ENC_BIG_ENDIAN);
                leds = tvb_get_guint8(tvb, offset);

            col_append_fstr(pinfo->cinfo, COL_INFO, " - LEDs: ");
            if (leds & 0x01) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "NumLock");
                shortcut_helper = 1;
            }
            if (leds & 0x02) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "CapsLock");
                shortcut_helper = 1;
            }
            if (leds & 0x04) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "ScrollLock");
                shortcut_helper = 1;
            }
            if (leds & 0x08) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "Compose");
                shortcut_helper = 1;
            }
            if (leds & 0x10) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "Kana");
                shortcut_helper = 1;
            }
            if (leds & 0x20) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "Constant1");
                shortcut_helper = 1;
            }
            if (leds & 0x40) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "Constant2");
                shortcut_helper = 1;
            }
            if (leds & 0x80) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "Constant3");
                shortcut_helper = 1;
            }
            if (!leds) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "none");
            }

                offset += 1;
                break;
            } else if (report_type != 0x01) {/* is not Input (Keys) */
                break;
            }

            proto_tree_add_item(tree, hf_bthid_data_keyboard_modifier_right_gui, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_keyboard_modifier_right_alt, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_keyboard_modifier_right_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_keyboard_modifier_right_ctrl, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_keyboard_modifier_left_gui, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_keyboard_modifier_left_alt, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_keyboard_modifier_left_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_keyboard_modifier_left_ctrl, tvb, offset, 1, ENC_BIG_ENDIAN);
            modifier = tvb_get_guint8(tvb, offset);

            col_append_fstr(pinfo->cinfo, COL_INFO, " - ");
            if (modifier & 0x80) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "RIGHT GUI");
                shortcut_helper = 1;
            }
            if (modifier & 0x40) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "RIGHT ALT");
                shortcut_helper = 1;
            }
            if (modifier & 0x20) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "RIGHT SHIFT");
                shortcut_helper = 1;
            }
            if (modifier & 0x10) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "RIGHT CTRL");
                shortcut_helper = 1;
            }
            if (modifier & 0x08) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "LEFT GUI");
                shortcut_helper = 1;
            }
            if (modifier & 0x04) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "LEFT ALT");
                shortcut_helper = 1;
            }
            if (modifier & 0x02) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "LEFT SHIFT");
                shortcut_helper = 1;
            }
            if (modifier & 0x01) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "LEFT CTRL");
                shortcut_helper = 1;
            }
            offset += 1;

            proto_tree_add_item(tree, hf_bthid_data_keyboard_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree, hf_bthid_data_keyboard_keycode_1, tvb, offset, 1, ENC_BIG_ENDIAN);
            keycode = tvb_get_guint8(tvb, offset);
            offset += 1;

            if (keycode) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_ext(keycode, &keycode_vals_ext, "Unknown"));
                shortcut_helper = 1;
            }

            proto_tree_add_item(tree, hf_bthid_data_keyboard_keycode_2, tvb, offset, 1, ENC_BIG_ENDIAN);
            keycode = tvb_get_guint8(tvb, offset);
            offset += 1;

            if (keycode) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_ext(keycode, &keycode_vals_ext, "Unknown"));
                shortcut_helper = 1;
            }

            proto_tree_add_item(tree, hf_bthid_data_keyboard_keycode_3, tvb, offset, 1, ENC_BIG_ENDIAN);
            keycode = tvb_get_guint8(tvb, offset);
            offset += 1;

            if (keycode) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_ext(keycode, &keycode_vals_ext, "Unknown"));
                shortcut_helper = 1;
            }

            proto_tree_add_item(tree, hf_bthid_data_keyboard_keycode_4, tvb, offset, 1, ENC_BIG_ENDIAN);
            keycode = tvb_get_guint8(tvb, offset);
            offset += 1;

            if (keycode) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_ext(keycode, &keycode_vals_ext, "Unknown"));
                shortcut_helper = 1;
            }

            proto_tree_add_item(tree, hf_bthid_data_keyboard_keycode_5, tvb, offset, 1, ENC_BIG_ENDIAN);
            keycode = tvb_get_guint8(tvb, offset);
            offset += 1;

            if (keycode) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_ext(keycode, &keycode_vals_ext, "Unknown"));
                shortcut_helper = 1;
            }

            proto_tree_add_item(tree, hf_bthid_data_keyboard_keycode_6, tvb, offset, 1, ENC_BIG_ENDIAN);
            keycode = tvb_get_guint8(tvb, offset);
            offset += 1;

            if (keycode) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_ext(keycode, &keycode_vals_ext, "Unknown"));
                shortcut_helper = 1;
            }

            if (shortcut_helper == 0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "<action key up>");
            }

            break;
        case 0x02: /* Mouse */
            proto_tree_add_item(tree, hf_bthid_data_mouse_button_8, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_mouse_button_7, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_mouse_button_6, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_mouse_button_5, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_mouse_button_4, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_mouse_button_middle, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_mouse_button_right, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_bthid_data_mouse_button_left, tvb, offset, 1, ENC_BIG_ENDIAN);
            buttons = tvb_get_guint8(tvb, offset);
            offset += 1;

            if (buttons) col_append_fstr(pinfo->cinfo, COL_INFO, " - ");
            if (buttons & 0x01) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "Button LEFT");
                shortcut_helper = 1;
            }
            if (buttons & 0x02) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "Button RIGHT");
                shortcut_helper = 1;
            }
            if (buttons & 0x04) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "Button MIDDLE");
            }
            if (buttons & 0x08) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "Button 4");
                shortcut_helper = 1;
            }
            if (buttons & 0x10) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "Button 5");
                shortcut_helper = 1;
            }
            if (buttons & 0x20) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "Button 6");
                shortcut_helper = 1;
            }
            if (buttons & 0x40) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "Button 7");
                shortcut_helper = 1;
            }
            if (buttons & 0x80) {
                if (shortcut_helper) col_append_fstr(pinfo->cinfo, COL_INFO, " + ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "Button 8");
                shortcut_helper = 1;
            }

            proto_tree_add_item(tree, hf_bthid_data_mouse_x_displacement, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree, hf_bthid_data_mouse_y_displacement, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            /* not really in HID Specification */
            if (tvb_length_remaining(tvb, offset)) {
                proto_tree_add_item(tree, hf_bthid_data_mouse_horizontal_scroll_wheel, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }

            /* not really in HID Specification */
            if (tvb_length_remaining(tvb, offset)) {
                proto_tree_add_item(tree, hf_bthid_data_mouse_vertical_scroll_wheel, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }

            if (tvb_length_remaining(tvb, offset)) {
                proto_tree_add_item(tree, hf_bthid_data, tvb, offset, -1, ENC_BIG_ENDIAN);
                offset += tvb_length_remaining(tvb, offset);
            }
            break;
    }

    return offset;
}

static void
dissect_bthid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item   *ti;
    proto_tree   *bthid_tree;
    int offset = 0;
    unsigned int transaction_type;
    unsigned int parameter;
    unsigned int protocol;
    unsigned int idle_rate;
    proto_item   *pitem = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HID");
    col_clear(pinfo->cinfo, COL_INFO);

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_add_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_add_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        col_clear(pinfo->cinfo, COL_INFO);
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
            pinfo->p2p_dir);
        break;
    }

    ti = proto_tree_add_item(tree, proto_bthid, tvb, offset, -1, ENC_NA);
    bthid_tree = proto_item_add_subtree(ti, ett_bthid);

    proto_tree_add_item(bthid_tree, hf_bthid_transaction_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    transaction_type = tvb_get_guint8(tvb, offset);
    parameter = transaction_type & 0x0F;
    transaction_type = transaction_type >> 4;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(transaction_type, transaction_type_vals, "Unknown TransactionType"));

    switch(transaction_type) {
        case 0x00: /* HANDSHAKE */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " - Result Code: %s", val_to_str(parameter, result_code_vals, "reserved"));
            break;
        case 0x01: /* HID_CONTROL */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_control_operation, tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, " - Control Operation: %s", val_to_str(parameter, control_operation_vals, "reserved"));
            offset += 1;
            break;
        case 0x04: /* GET_REPORT */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_size, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_reserved_2, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_report_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " - Size: %s, Report Type: %s",
                            val_to_str(parameter >> 3 , size_vals, "reserved"),
                            val_to_str(parameter & 0x03, report_type_vals, "reserved"));

            if (tvb_length_remaining(tvb, offset) >= 1) {
                proto_tree_add_item(bthid_tree, hf_bthid_report_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }

            if (tvb_length_remaining(tvb, offset) >= 2) {
                proto_tree_add_item(bthid_tree, hf_bthid_buffer_size, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            break;
        case 0x05: /* SET_REPORT */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_reserved_32, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_report_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, " - Report Type: %s",
                            val_to_str(parameter & 0x03, report_type_vals, "reserved"));

            /* playload */
            proto_tree_add_item(bthid_tree, hf_bthid_data, tvb, offset, -1, ENC_BIG_ENDIAN);
            offset += tvb_length_remaining(tvb, offset);
            break;
        case 0x06: /* GET_PROTOCOL */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(bthid_tree, hf_bthid_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
            protocol = tvb_get_guint8(tvb, offset) & 0x01;
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, " - Protocol: %s",
                            val_to_str(protocol, protocol_vals, "reserved"));

            break;
        case 0x07: /* SET_PROTOCOL */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_reserved_31, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bthid_tree, hf_bthid_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, " - Protocol: %s",
                            val_to_str(parameter & 0x01, protocol_vals, "reserved"));
            break;
        case 0x08: /* GET_IDLE */
        case 0x09: /* SET_IDLE */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            pitem = proto_tree_add_item(bthid_tree, hf_bthid_idle_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
            idle_rate = tvb_get_guint8(tvb, offset);
            proto_item_append_text(pitem, " (%u.%03u ms)", idle_rate * 4 / 1000, idle_rate * 4 % 1000);
            col_append_fstr(pinfo->cinfo, COL_INFO, " - Idle Rate: %u.%03u ms", idle_rate*4/1000, idle_rate*4%1000);
            offset += 1;
            break;
        case 0x0A: /* DATA */
        case 0x0B: /* DATC */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_reserved_32, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_report_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str(parameter, report_type_vals, "reserved"));

            /* playload */
            offset = dissect_hid_data(tvb, pinfo,  bthid_tree, offset, parameter & 0x03);
            break;
    }

    if ((int)tvb_length(tvb) > offset) {
        proto_tree_add_item(bthid_tree, hf_bthid_data, tvb, offset, -1, ENC_BIG_ENDIAN);
        offset += tvb_length_remaining(tvb, offset);
    }
}


void
proto_register_bthid(void)
{
    module_t *module;

    static hf_register_info hf[] = {
        { &hf_bthid_transaction_type,
            { "Transaction Type",                "bthid.transaction_type",
            FT_UINT8, BASE_HEX, VALS(transaction_type_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_reserved,
            { "Parameter reserved",              "bthid.parameter.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_reserved_32,
            { "Parameter reserved",              "bthid.parameter.reserved_32",
            FT_UINT8, BASE_HEX, NULL, 0x0C,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_reserved_31,
            { "Parameter reserved",              "bthid.parameter.reserved_31",
            FT_UINT8, BASE_HEX, NULL, 0x0E,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_reserved_2,
            { "Parameter reserved",              "bthid.parameter.reserved_2",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_report_type,
            { "Report Type",                     "bthid.parameter.report_type",
            FT_UINT8, BASE_HEX, VALS(report_type_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_size,
            { "Size",                            "bthid.parameter.size",
            FT_UINT8, BASE_HEX, VALS(size_vals), 0x08,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_result_code,
            { "Result Code",                     "bthid.result_code",
            FT_UINT8, BASE_HEX, VALS(result_code_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_control_operation,
            { "Control Operation",               "bthid.control_operation",
            FT_UINT8, BASE_HEX, VALS(control_operation_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_bthid_protocol,
            { "Protocol",                        "bthid.protocol",
            FT_UINT8, BASE_HEX, VALS(protocol_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_bthid_idle_rate,
            { "Idle Rate",                       "bthid.idle_rate",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_report_id,
            { "Report Id",                       "bthid.report_id",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_buffer_size,
            { "Buffer Size",                     "bthid.buffer_size",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_protocol_code,
            { "Protocol Code",                   "bthid.data.protocol_code",
            FT_UINT8, BASE_HEX, VALS(protocol_code_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_reserved,
            { "Reserved",                        "bthid.data.keyboard.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_keycode_1,
            { "Keycode 1",                       "bthid.data.keyboard.keycode_1",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keycode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_keycode_2,
            { "Keycode 2",                       "bthid.data.keyboard.keycode_2",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keycode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_keycode_3,
            { "Keycode 3",                       "bthid.data.keyboard.keycode_3",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keycode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_keycode_4,
            { "Keycode 4",                       "bthid.data.keyboard.keycode_4",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keycode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_keycode_5,
            { "Keycode 5",                       "bthid.data.keyboard.keycode_5",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keycode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_keycode_6,
            { "Keycode 6",                       "bthid.data.keyboard.keycode_6",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keycode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_modifier_right_gui,
            { "Modifier: RIGHT GUI",             "bthid.data.keyboard.modifier.right_gui",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_modifier_right_alt,
            { "Modifier: RIGHT ALT",             "bthid.data.keyboard.modifier.right_alt",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_modifier_right_shift,
            { "Modifier: RIGHT SHIFT",           "bthid.data.keyboard.modifier.right_shift",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_modifier_right_ctrl,
            { "Modifier: RIGHT CTRL",            "bthid.data.keyboard.modifier.right_ctrl",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_modifier_left_gui,
            { "Modifier: LEFT GUI",              "bthid.data.keyboard.modifier.left_gui",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_modifier_left_alt,
            { "Modifier: LEFT ALT",              "bthid.data.keyboard.modifier.left_alt",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_modifier_left_shift,
            { "Modifier: LEFT SHIFT",            "bthid.data.keyboard.modifier.left_shift",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_modifier_left_ctrl,
            { "Modifier: LEFT CTRL",             "bthid.data.keyboard.modifier.left_ctrl",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_leds_constants,
            { "Constants",                       "bthid.data.keyboard.leds.constants",
            FT_UINT8, BASE_HEX, NULL, 0xE0,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_leds_kana,
            { "KANA",                            "bthid.data.keyboard.leds.kana",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_leds_compose,
            { "COMPOSE",                         "bthid.data.keyboard.leds.compose",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_leds_scroll_lock,
            { "SCROLL LOCK",                     "bthid.data.keyboard.leds.scroll_lock",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_leds_caps_lock,
            { "CAPS LOCK",                       "bthid.data.keyboard.leds.caps_lock",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_bthid_data_keyboard_leds_num_lock,
            { "NUM LOCK",                        "bthid.data.keyboard.leds.num_lock",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_bthid_data_mouse_button_8,
            { "Button 8",                        "bthid.data.mouse.button.8",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_bthid_data_mouse_button_7,
            { "Button 7",                        "bthid.data.mouse.button.7",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_bthid_data_mouse_button_6,
            { "Button 6",                        "bthid.data.mouse.button.6",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_bthid_data_mouse_button_5,
            { "Button 5",                        "bthid.data.mouse.button.5",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_bthid_data_mouse_button_4,
            { "Button 4",                        "bthid.data.mouse.button.4",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_bthid_data_mouse_button_middle,
            { "Button Middle",                   "bthid.data.mouse.button.middle",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_bthid_data_mouse_button_right,
            { "Button Right",                    "bthid.data.mouse.button.right",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_bthid_data_mouse_button_left,
            { "Button Left",                     "bthid.data.mouse.button.left",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_bthid_data_mouse_x_displacement,
            { "X Displacement",                  "bthid.data.mouse.x_displacement",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data_mouse_y_displacement,
            { "Y Displacement",                  "bthid.data.mouse.y_displacement",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data_mouse_horizontal_scroll_wheel,
            { "Horizontal Scroll Wheel",         "bthid.data.mouse.scroll_wheel.horizontal",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data_mouse_vertical_scroll_wheel,
            { "Vertical Scroll Wheel",           "bthid.data.mouse.scroll_wheel.vertical",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data,
            { "Data",                            "bthid.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },

    };

    static gint *ett[] = {
        &ett_bthid
    };

    proto_bthid = proto_register_protocol("Bluetooth HID Profile", "HID", "bthid");
    register_dissector("bthid", dissect_bthid, proto_bthid);

    proto_register_field_array(proto_bthid, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module = prefs_register_protocol(proto_bthid, NULL);
    prefs_register_static_text_preference(module, "hid.version",
            "Bluetooth Profile HID version: 1.0",
            "Version of profile supported by this dissector.");
}


void
proto_reg_handoff_bthid(void)
{
    dissector_handle_t bthid_handle;

    bthid_handle = find_dissector("bthid");

    dissector_add_uint("btl2cap.service", BTSDP_HID_SERVICE_UUID, bthid_handle);
    dissector_add_uint("btl2cap.service", BTSDP_HIDP_PROTOCOL_UUID, bthid_handle);

    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_HID_CTRL, bthid_handle);
    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_HID_INTR, bthid_handle);
    dissector_add_handle("btl2cap.cid", bthid_handle);
}
