/* packet-slimp3.c
 * Routines for SliMP3 protocol dissection
 *
 * Ashok Narayanan <ashokn@cisco.com>
 *
 * Adds support for the data packet protocol for the SliMP3
 * See www.slimdevices.com for details.
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
#include <string.h>
#include <ctype.h>
#include <epan/packet.h>
#include <epan/to_str.h>

void proto_register_slimp3(void);
void proto_reg_handoff_slimp3(void);

static int proto_slimp3 = -1;
static int hf_slimp3_opcode = -1;
static int hf_slimp3_control = -1;
static int hf_slimp3_uptime = -1;
static int hf_slimp3_code_id = -1;
static int hf_slimp3_code_bits = -1;
static int hf_slimp3_infrared_slimp3 = -1;
static int hf_slimp3_infrared_jvc = -1;
static int hf_slimp3_infrared = -1;
static int hf_slimp3_device_id = -1;
static int hf_slimp3_fw_rev = -1;
static int hf_slimp3_data_offset = -1;
static int hf_slimp3_data_command = -1;
static int hf_slimp3_data_write_pointer = -1;
static int hf_slimp3_data_sequence = -1;
static int hf_slimp3_disc_rsp_server_ip = -1;
static int hf_slimp3_disc_rsp_server_port = -1;
static int hf_slimp3_data_ack_write_pointer = -1;
static int hf_slimp3_data_ack_read_pointer = -1;
static int hf_slimp3_data_ack_sequence = -1;
static int hf_slimp3_data_req_offset = -1;

static gint ett_slimp3 = -1;

#define UDP_PORT_SLIMP3_V1    1069
#define UDP_PORT_SLIMP3_V2    3483

#define SLIMP3_IR       'i'
#define SLIMP3_CONTROL  's'
#define SLIMP3_HELLO    'h'
#define SLIMP3_DATA     'm'
#define SLIMP3_DATA_REQ 'r'
#define SLIMP3_DISPLAY  'l'
#define SLIMP3_I2C      '2'
#define SLIMP3_DISC_REQ 'd'
#define SLIMP3_DISC_RSP 'D'
#define SLIMP3_DATA_ACK 'a'

static const value_string slimp3_opcode_vals[] = {
    { SLIMP3_IR,       "Infrared Remote Code" },
    { SLIMP3_CONTROL,  "Stream Control" },
    { SLIMP3_DATA,     "MPEG Data" },
    { SLIMP3_DATA_REQ, "Data Request" },
    { SLIMP3_HELLO,    "Hello" },
    { SLIMP3_DISPLAY,  "Display" },
    { SLIMP3_I2C,      "I2C" },
    { SLIMP3_DISC_REQ, "Discovery Request" },
    { SLIMP3_DISC_RSP, "Discovery Response" },
    { SLIMP3_DATA_ACK, "Ack" },
    { 0,               NULL }
};

/* IR remote control types */
static const value_string slimp3_ir_types[] = {
    { 0x02, "SLIMP3" },
    { 0xff, "JVC DVD Player" },

    { 0, NULL }
};

/* IR codes for the custom SLIMP3 remote control */
static const value_string slimp3_ir_codes_slimp3[] = {
    { 0x768900ff, "voldown" },
    { 0x768904fb, "brightness" },
    { 0x768908f7, "2" },
    { 0x768910ef, "play" },
    { 0x768920df, "pause" },
    { 0x768928d7, "6" },
    { 0x768938c7, "repeat" },
    { 0x768940bf, "power" },
    { 0x768948b7, "4" },
    { 0x768958a7, "search" },
    { 0x7689609f, "add" },
    { 0x76896897, "8" },
    { 0x76897887, "now_playing" },
    { 0x7689807f, "volup" },
    { 0x76898877, "3" },
    { 0x7689906f, "arrow_left" },
    { 0x76899867, "0" },
    { 0x7689a05f, "fwd" },
    { 0x7689a857, "7" },
    { 0x7689b04f, "arrow_down" },
    { 0x7689b847, "sleep" },
    { 0x7689c03f, "rew" },
    { 0x7689c837, "5" },
    { 0x7689d02f, "arrow_right" },
    { 0x7689d827, "shuffle" },
    { 0x7689e01f, "arrow_up" },
    { 0x7689e817, "9" },
    { 0x7689f00f, "1" },
    { 0x7689f807, "size" },

    { 0,      NULL }
};
static value_string_ext slimp3_ir_codes_slimp3_ext = VALUE_STRING_EXT_INIT(slimp3_ir_codes_slimp3);

/* IR codes for the JVC remote control */
static const value_string slimp3_ir_codes_jvc[] = {
    { 0xf786, "One" },
    { 0xf746, "Two" },
    { 0xf7c6, "Three" },
    { 0xf726, "Four" },
    { 0xf7a6, "Five" },
    { 0xf766, "Six" },
    { 0xf7e6, "Seven" },
    { 0xf716, "Eight" },
    { 0xf796, "Nine" },
    { 0xf776, "Ten" },

    { 0xf7f6, "Picture-In-Picture" },
    /* { 0xf7XX, "Enter" }, */
    { 0xf70e, "Back" },
    { 0xf732, "Play" },
    { 0xf76e, "Forward" },
    { 0xf743, "Record" },
    { 0xf7c2, "Stop" },
    { 0xf7b2, "Pause" },
    /* { 0xf7XX, "TV/Video" }, */
    { 0xf703, "Display" },
    { 0xf7b3, "Sleep" },
    { 0xf7b6, "Guide" },
    { 0xf70b, "Up" },
    { 0xf74b, "Left" },
    { 0xf7cb, "Right" },
    { 0xf78b, "Down" },
    { 0xf783, "Menu" },
    { 0xf72b, "OK" },
    { 0xf778, "Volume Up" },
    { 0xf7f8, "Volume Down" },
    { 0xf70d, "Channel Up" },
    { 0xf78d, "Channel Down" },
    /* { 0xf7XX, "Mute" },  */
    { 0xf7ab, "Recall" },
    { 0xf702, "Power" },

    { 0,      NULL }
};


static const value_string slimp3_display_commands[] = {
    {  0x1, "Clear Display"},
    {  0x2, "Cursor to 1st Line Home"},

    {  0x4, "Mode: Decrement Address, Shift Cursor"},
    {  0x5, "Mode: Decrement Address, Shift Display"},
    {  0x6, "Mode: Increment Address, Shift Cursor"},
    {  0x7, "Mode: Increment Address, Shift Display"},

    {  0x8, "Display Off"},
    {  0xd, "Display On, With Blinking"},
    {  0xe, "Display On, With Cursor"},
    {  0xf, "Display On, With Cursor And Blinking"},

    { 0x10, "Move Cursor Left"},
    { 0x14, "Move Cursor Right"},
    { 0x18, "Shift Display Left"},
    { 0x1b, "Shift Display Right"},

    { 0x30, "Set (8-bit)"},
    { 0x20, "Set (4-bit)"},

    { 0xa0, "Cursor to Top Right"},
    { 0xc0, "Cursor to 2nd Line Home"},

    {    0, NULL},
};

static const value_string slimp3_display_fset8[] = {
    { 0x0, "Brightness 100%"},
    { 0x1, "Brightness 75%"},
    { 0x2, "Brightness 50%"},
    { 0x3, "Brightness 25%"},

    {   0, NULL },
};

static const value_string slimp3_stream_control[] = {
    { 1, "Reset buffer, Start New Stream"},
    { 2, "Pause Playback"},
    { 4, "Resume Playback"},
    { 0, NULL },
};


static const value_string slimp3_mpg_control[] = {
    { 0, "Go"},           /* Run the decoder */
    { 1, "Stop"},         /* Halt decoder but don't reset rptr */
    { 3, "Reset"},        /* Halt decoder and reset rptr */

    { 0, NULL }
};

#define MAX_LCD_STR_LEN 128
static int
dissect_slimp3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    const char *opcode_str;
    proto_tree *slimp3_tree;
    proto_item *ti;
    gint        i1;
    gint        offset = 0;
    guint16     opcode;
    guchar      lcd_char;
    char        lcd_str[MAX_LCD_STR_LEN + 1];
    int         to_server    = FALSE;
    int         old_protocol = FALSE;
    address     tmp_addr;
    gboolean    in_str;
    int         lcd_strlen;

    /*
     * If it doesn't begin with a known opcode, reject it, so that
     * traffic that happens to be do or from one of our ports
     * doesn't get misidentified as SliMP3 traffic.
     */
    if (!tvb_bytes_exist(tvb, offset, 1))
        return 0;   /* not even an opcode */
    opcode = tvb_get_guint8(tvb, offset);
    opcode_str = try_val_to_str(opcode, slimp3_opcode_vals);
    if (opcode_str == NULL)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SliMP3");
    col_add_str(pinfo->cinfo, COL_INFO, opcode_str);

    ti = proto_tree_add_item(tree, proto_slimp3, tvb, offset, -1, ENC_NA);
    slimp3_tree = proto_item_add_subtree(ti, ett_slimp3);

    proto_tree_add_uint(slimp3_tree, hf_slimp3_opcode, tvb,
                        offset, 1, opcode);

    /* The new protocol (v1.3 and later) uses an IANA-assigned port number.
     * It usually uses the same number for both sizes of the conversation, so
     * the port numbers can't always be used to determine client and server.
     * The new protocol places the clients MAC address in the packet, so that
     * is used to identify packets originating at the client.
     */
    if ((pinfo->destport == UDP_PORT_SLIMP3_V2) && (pinfo->srcport == UDP_PORT_SLIMP3_V2)) {
        TVB_SET_ADDRESS(&tmp_addr, AT_ETHER, tvb, offset+12, 6);
        to_server = ADDRESSES_EQUAL(&tmp_addr, &pinfo->dl_src);
    }
    else if (pinfo->destport == UDP_PORT_SLIMP3_V2) {
        to_server = TRUE;
    }
    else if (pinfo->srcport == UDP_PORT_SLIMP3_V2) {
        to_server = FALSE;
    }
    if (pinfo->destport == UDP_PORT_SLIMP3_V1) {
        to_server = TRUE;
        old_protocol = TRUE;
    }
    else if (pinfo->srcport == UDP_PORT_SLIMP3_V1) {
        to_server = FALSE;
        old_protocol = TRUE;
    }

    switch (opcode) {

    case SLIMP3_IR:
        /* IR code
         *
         * [0]        'i' as in "IR"
         * [1]        0x00
         * [2..5]     player's time since startup in ticks @625 KHz
         * [6]        IR code id, ff=JVC, 02=SLIMP3
         * [7]        number of meaningful bits - 16 for JVC, 32 for SLIMP3
         * [8..11]    the 32-bit IR code
         * [12..17]   reserved
         */
        if (tree) {
            i1 = tvb_get_ntohl(tvb, offset+2);
            proto_tree_add_uint_format_value(slimp3_tree, hf_slimp3_uptime, tvb, offset+2, 4, i1,
                                             "%u sec (%u ticks)", i1/625000, i1);

            proto_tree_add_item(slimp3_tree, hf_slimp3_code_id, tvb, offset+6, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(slimp3_tree, hf_slimp3_code_bits, tvb, offset+7, 1, ENC_BIG_ENDIAN);

            i1 = tvb_get_ntohl(tvb, offset+8);
            /* Check the code to figure out which remote is being used. */
            if (tvb_get_guint8(tvb, offset+6) == 0x02 &&
                tvb_get_guint8(tvb, offset+7) == 32) {
                /* This is the custom SLIMP3 remote. */
                proto_tree_add_item(slimp3_tree, hf_slimp3_infrared_slimp3, tvb, offset+8, 4, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", SLIMP3: %s",
                                val_to_str_ext(i1, &slimp3_ir_codes_slimp3_ext, "Unknown (0x%0x)"));
            }
            else if (tvb_get_guint8(tvb, offset+6) == 0xff &&
                     tvb_get_guint8(tvb, offset+7) == 16) {
                /* This is a JVC DVD player remote */
                proto_tree_add_item(slimp3_tree, hf_slimp3_infrared_jvc, tvb, offset+8, 4, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", JVC: %s",
                                val_to_str(i1, slimp3_ir_codes_jvc, "Unknown (0x%0x)"));
            } else {
                /* Unknown code; just write it */
                proto_tree_add_item(slimp3_tree, hf_slimp3_infrared, tvb, offset+8, 4, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", 0x%0x", i1);
            }
        }
        break;

    case SLIMP3_DISPLAY:
        if (tree) {
            /* Loop through the commands */
            i1 = 18;
            in_str = FALSE;
            lcd_strlen = 0;
            while (i1 < tvb_reported_length_remaining(tvb, offset)) {
                switch(tvb_get_guint8(tvb, offset + i1)) {
                case 0:
                    in_str = FALSE;
                    lcd_strlen = 0;
                    proto_tree_add_text(slimp3_tree, tvb, offset + i1, 2,
                                        "Delay (%u ms)", tvb_get_guint8(tvb, offset + i1 + 1));
                    i1 += 2;
                    break;
                case 3:
                    lcd_char = tvb_get_guint8(tvb, offset + i1 + 1);
                    if (!g_ascii_isprint(lcd_char))
                        lcd_char = '.';
                    if (ti && in_str) {
                        lcd_strlen += 2;
                        proto_item_append_text(ti, "%c", lcd_char);
                        proto_item_set_len(ti, lcd_strlen);
                    } else {
                        ti = proto_tree_add_text(slimp3_tree, tvb, offset + i1, 2,
                                                 "String: %c", lcd_char);
                        in_str = TRUE;
                        lcd_strlen = 2;
                    }
                    i1 += 2;
                    break;

                case 2:
                    in_str = FALSE;
                    lcd_strlen = 0;
                    ti = proto_tree_add_text(slimp3_tree, tvb, offset + i1, 2,
                                             "Command: %s",
                                             val_to_str(tvb_get_guint8(tvb, offset + i1 + 1),
                                                        slimp3_display_commands,
                                                        "Unknown (0x%0x)"));
                    if ((tvb_get_guint8(tvb, offset + i1 + 1) & 0xf0) == 0x30) {
                        proto_item_append_text(ti, ": %s",
                                               val_to_str(tvb_get_guint8(tvb, offset + i1 + 2),
                                                          slimp3_display_fset8,
                                                          "Unknown (0x%0x)"));
                        i1 += 2;
                    }
                    i1 += 2;
                    break;

                default:
                    proto_tree_add_text(slimp3_tree, tvb, offset + i1, 2,
                                        "Unknown 0x%0x, 0x%0x",
                                        tvb_get_guint8(tvb, offset + i1),
                                        tvb_get_guint8(tvb, offset + i1 + 1));
                    i1 += 2;
                    break;
                }
            }
        }

        i1 = 18;
        lcd_strlen = 0;
        while (tvb_offset_exists(tvb, offset + i1) &&
               lcd_strlen < MAX_LCD_STR_LEN) {
            switch (tvb_get_guint8(tvb, offset + i1)) {

            case 0:
                lcd_str[lcd_strlen++] = '.';
                break;

            case 2:
                lcd_str[lcd_strlen++] = '|';
                if (tvb_offset_exists(tvb, offset + i1 + 1) &&
                    (tvb_get_guint8(tvb, offset + i1 + 1) & 0xf0) == 0x30)
                    i1 += 2;
                break;

            case 3:
                if (tvb_offset_exists(tvb, offset + i1 + 1)) {
                    if ((lcd_strlen < 1) ||
                        (lcd_str[lcd_strlen-1] != ' ') ||
                        (tvb_get_guint8(tvb, offset + i1 + 1) != ' ')) {
                        lcd_char = tvb_get_guint8(tvb, offset + i1 + 1);
                        lcd_str[lcd_strlen++] = g_ascii_isprint(lcd_char) ? lcd_char : '.';
                    }
                }
            }

            i1 += 2;
        }
        lcd_str[lcd_strlen] = '\0';
        if (lcd_strlen > 0)
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", lcd_str);
        break;

    case SLIMP3_CONTROL:
        proto_tree_add_item(slimp3_tree, hf_slimp3_control, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                        val_to_str(tvb_get_guint8(tvb, offset+1),
                                   slimp3_stream_control, "Unknown (0x%0x)"));
        break;

    case SLIMP3_HELLO:
        if (tree) {
            if (to_server) {
                guint8 fw_ver;
                /* Hello response; client->server */
                proto_tree_add_text(slimp3_tree, tvb, offset, 1, "Hello Response (Client --> Server)");
                proto_tree_add_item(slimp3_tree, hf_slimp3_device_id, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                fw_ver = tvb_get_guint8(tvb, offset+2);
                proto_tree_add_uint_format_value(slimp3_tree, hf_slimp3_fw_rev, tvb, offset+2, 1, fw_ver,
                                                 "%u.%u (0x%0x)", fw_ver>>4, fw_ver & 0xf, fw_ver);
            } else {
                /* Hello request; server->client */
                proto_tree_add_text(slimp3_tree, tvb, offset, 1, "Hello Request (Server --> Client)");
            }
        }
        break;

    case SLIMP3_I2C:
        if (to_server) {
            /* Hello response; client->server */
            proto_tree_add_text(slimp3_tree, tvb, offset, -1,
                                "I2C Response (Client --> Server)");
            col_append_str(pinfo->cinfo, COL_INFO, ", Response");
        } else {
            /* Hello request; server->client */
            proto_tree_add_text(slimp3_tree, tvb, offset, -1,
                                "I2C Request (Server --> Client)");
            col_append_str(pinfo->cinfo, COL_INFO, ", Request");
        }
        break;

    case SLIMP3_DATA_REQ:
        proto_tree_add_item(slimp3_tree, hf_slimp3_data_req_offset, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Offset: %u bytes",
                        tvb_get_ntohs(tvb, offset+2)*2);
        break;

    case SLIMP3_DATA:
        /* MPEG data (v1.3 and later)
         *
         *  [0]       'm'
         *  [1..5]    reserved
         *  [6..7]    Write pointer (in words)
         *  [8..9]    reserved
         *  [10..11]  Sequence number
         *  [12..17]  reserved
         *  [18..]    MPEG data
         */
        if (old_protocol) {
            guint offset_buffer;
            proto_tree_add_text(slimp3_tree, tvb, offset, -1,
                                "Length: %d bytes",
                                tvb_reported_length_remaining(tvb, offset+18));
            offset_buffer = tvb_get_ntohs(tvb, offset+2) * 2;
            proto_tree_add_uint(slimp3_tree, hf_slimp3_data_offset, tvb, offset+2, 2, offset_buffer);

            col_append_fstr(pinfo->cinfo, COL_INFO,
                            ", Length: %d bytes, Offset: %u bytes.",
                            tvb_reported_length_remaining(tvb, offset+18),
                            offset_buffer);
        }
        else {
            guint write_pointer;
            proto_tree_add_item(slimp3_tree, hf_slimp3_data_command, tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_text(slimp3_tree, tvb, offset, -1,
                                "Length: %d bytes",
                                tvb_reported_length_remaining(tvb, offset+18));
            write_pointer = tvb_get_ntohs(tvb, offset+6) * 2;
            proto_tree_add_uint(slimp3_tree, hf_slimp3_data_write_pointer, tvb, offset+6, 2, write_pointer);
            proto_tree_add_item(slimp3_tree, hf_slimp3_data_sequence, tvb, offset+10, 2, ENC_BIG_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO,
                            ", %s, %d bytes at %u, Sequence: %u",
                            val_to_str(tvb_get_guint8(tvb, offset+1),
                                       slimp3_mpg_control, "Unknown (0x%0x)"),
                            tvb_reported_length_remaining(tvb, offset+18),
                            write_pointer,
                            tvb_get_ntohs(tvb, offset+10));
        }
        break;

    case SLIMP3_DISC_REQ:
    {
        guint8 fw_ver;
        proto_tree_add_item(slimp3_tree, hf_slimp3_device_id, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        fw_ver = tvb_get_guint8(tvb, offset+2);
        proto_tree_add_uint_format_value(slimp3_tree, hf_slimp3_fw_rev, tvb, offset+2, 1, fw_ver,
                                         "%u.%u (0x%0x)", fw_ver>>4, fw_ver & 0xf, fw_ver);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Device ID: %u. Firmware: %u.%u",
                        tvb_get_guint8(tvb, offset+1), fw_ver>>4, fw_ver & 0xf);
    }
    break;

    case SLIMP3_DISC_RSP:
        if (tree) {
            proto_tree_add_item(slimp3_tree, hf_slimp3_disc_rsp_server_ip, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(slimp3_tree, hf_slimp3_disc_rsp_server_port, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, ", Server Address: %s. Server Port: %u",
                        tvb_ip_to_str(tvb, offset+2),
                        tvb_get_ntohs(tvb, offset + 6));
        break;

    case SLIMP3_DATA_ACK:
        /* Acknowledge MPEG data
         *
         *  [0]       'a'
         *  [1..5]
         *  [6..7]    Write pointer (in words)
         *  [8..9]    Read pointer (in words)
         *  [10..11]  Sequence number
         *  [12..17]  client MAC address (v1.3 and later)
         */
        if (tree) {
            guint pointer;

            pointer = tvb_get_ntohs(tvb, offset+6) * 2;
            proto_tree_add_uint(slimp3_tree, hf_slimp3_data_ack_write_pointer, tvb, offset+6, 2, pointer);
            pointer = tvb_get_ntohs(tvb, offset+8) * 2;
            proto_tree_add_uint(slimp3_tree, hf_slimp3_data_ack_read_pointer, tvb, offset+8, 2, pointer);
            proto_tree_add_item(slimp3_tree, hf_slimp3_data_ack_sequence, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, ", Sequence: %u",
                        tvb_get_ntohs(tvb, offset+10));
        break;

    default:
        if (tree) {
            proto_tree_add_text(slimp3_tree, tvb, offset, -1,
                                "Data (%d bytes)", tvb_reported_length_remaining(tvb, offset));
        }
        break;
    }

    return tvb_reported_length(tvb);
}

void
proto_register_slimp3(void)
{
    static hf_register_info hf[] = {
        { &hf_slimp3_opcode,
          { "Opcode", "slimp3.opcode",
            FT_UINT8, BASE_DEC, VALS(slimp3_opcode_vals), 0x0,
            "SLIMP3 message type", HFILL }},

        { &hf_slimp3_control,
          { "Control Packet", "slimp3.control",
            FT_UINT8, BASE_DEC, VALS(slimp3_stream_control), 0x0,
            "SLIMP3 control", HFILL }},

        { &hf_slimp3_uptime,
          { "Uptime", "slimp3.uptime",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_code_id,
          { "Code identifier", "slimp3.code_id",
            FT_UINT8, BASE_DEC, VALS(slimp3_ir_types), 0x0,
            NULL, HFILL }},

        { &hf_slimp3_code_bits,
          { "Code bits", "slimp3.code_bits",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_infrared_slimp3,
          { "Infrared Code", "slimp3.infrared",
            FT_UINT32, BASE_HEX | BASE_EXT_STRING, &slimp3_ir_codes_slimp3_ext, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_infrared_jvc,
          { "Infrared Code", "slimp3.infrared",
            FT_UINT32, BASE_HEX, VALS(slimp3_ir_codes_jvc), 0x0,
            NULL, HFILL }},

        { &hf_slimp3_infrared,
          { "Infrared Code", "slimp3.infrared",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_device_id,
          { "Device ID", "slimp3.device_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_fw_rev,
          { "Firmware Revision", "slimp3.fw_rev",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_data_offset,
          { "Buffer offset", "slimp3.data.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_data_command,
          { "Command", "slimp3.data.command",
            FT_UINT8, BASE_HEX, VALS(slimp3_mpg_control), 0x0,
            NULL, HFILL }},

        { &hf_slimp3_data_write_pointer,
          { "Write Pointer", "slimp3.data.write_pointer",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_data_sequence,
          { "Sequence", "slimp3.data.sequence",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_disc_rsp_server_ip,
          { "Server Address", "slimp3.disc_rsp.server_ip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_disc_rsp_server_port,
          { "Server Port", "slimp3.disc_rsp.server_port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_data_ack_write_pointer,
          { "Write Pointer", "slimp3.data_ack.write_pointer",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_data_ack_read_pointer,
          { "Read Pointer", "slimp3.data_ack.read_pointer",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_data_ack_sequence,
          { "Sequence", "slimp3.data_ack.sequence",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_slimp3_data_req_offset,
          { "Requested offset", "slimp3.data_req.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_slimp3,
    };

    proto_slimp3 = proto_register_protocol("SliMP3 Communication Protocol",
                                           "SliMP3", "slimp3");
    proto_register_field_array(proto_slimp3, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_slimp3(void)
{
    dissector_handle_t slimp3_handle;

    slimp3_handle = new_create_dissector_handle(dissect_slimp3, proto_slimp3);
    dissector_add_uint("udp.port", UDP_PORT_SLIMP3_V1, slimp3_handle);
    dissector_add_uint("udp.port", UDP_PORT_SLIMP3_V2, slimp3_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
