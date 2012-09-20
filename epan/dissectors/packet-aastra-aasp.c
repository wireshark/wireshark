/* packet-aastra-aasp.c
 * Routines for AASP (Aastra Signalling Protocol) packet dissection.
 * Copyright 2011, Marek Tews <marek.tews@gmail.com>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 *	AASP over SIP
 *	Content-Type: message/x-aasp-signalling
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

/* commands id */
#define BEGIN_BLOCK_DATA    0x80
#define WINDOW              0x81
#define TITLE               0x83
#define ROW                 0x84
#define MENU_ITEM           0x85
#define CONTEXT_INFO        0x86
#define BUTTON_PRESSED      0x87
#define COLUMN              0x88
#define SET_TEXT            0x89
#define DATE_TIME_INFO      0xA4
#define INCOMING_CALLER     0xA5
#define DO_COMMAND          0xA9
#define PUSH_BTN_C          0xC8
#define PUSH_BTN_TASK       0xC9
#define PUSH_BTN_PLUS       0xCA
#define PUSH_BTN_MINUS      0xCB
#define PUSH_BTN_MIC        0xCC
#define PUSH_BTN_SPK        0xCD
#define PUSH_BTN_TBOOK      0xCE
#define PUSH_BTN_DBL_ARROW  0xCF
#define PUSH_BTN_ON_HOOK    0xD0
#define PUSH_BTN_OFF_HOOK   0xD1
#define PUSH_BTN_UP         0xD2
#define PUSH_BTN_DOWN       0xD3
#define PUSH_BTN_LEFT       0xD4
#define PUSH_BTN_RIGHT      0xD5
#define END_BLOCK_DATA      0xFE


void proto_reg_handoff_aasp(void);

/* Initialize the protocol and registered fields */
static gint proto_aasp = -1;

static gint hf_a_data = -1;
static gint hf_a_cmd = -1;
static gint hf_a_id = -1;
static gint hf_a_length = -1;
static gint hf_a_text = -1;
static gint hf_a_line = -1;
static gint hf_a_cdpn = -1;
static gint hf_a_button_id = -1;

static gint hf_a_attr = -1;

static gint hf_a_item = -1;
static gint hf_a_hour = -1;
static gint hf_a_minute = -1;
static gint hf_a_day = -1;
static gint hf_a_month = -1;
static gint hf_a_weekofyear = -1;
static gint hf_a_weekday = -1;
static gint hf_a_month_name = -1;
static gint hf_a_weekofyear_prefix = -1;

/* Initialize the subtree pointers */
static gint ett_aasp = -1;
static gint ett_a_cmd = -1;
static gint ett_a_item = -1;

/* Preferences */

/**
 * Commands
 */
static const value_string szCmdID[] =
{
    { BEGIN_BLOCK_DATA, "Begin Block Data" },
    { WINDOW, "Window" },
    { TITLE, "Title" },
    { ROW, "Row" },
    { MENU_ITEM, "Menu Item" },
    { CONTEXT_INFO, "Context Info" },
    { BUTTON_PRESSED, "Button Pressed" },
    { COLUMN, "Column" },
    { SET_TEXT, "Set Text" },
    { DATE_TIME_INFO, "Date Time Info" },
    { INCOMING_CALLER, "Incoming Caller" },
    { DO_COMMAND, "Do Command" },
    { PUSH_BTN_C, "Push Button 'C'" },
    { PUSH_BTN_TASK, "Push Button 'Task'" },
    { PUSH_BTN_PLUS, "Push Button '+'" },
    { PUSH_BTN_MINUS, "Push Button '-'" },
    { PUSH_BTN_MIC, "Push Button 'Microphone'" },
    { PUSH_BTN_SPK, "Push Button 'Speaker'" },
    { PUSH_BTN_TBOOK, "Push Button 'Telephone Book'" },
    { PUSH_BTN_DBL_ARROW, "Push Button 'Double-Arrow'" },
    { PUSH_BTN_ON_HOOK, "Red Button 'On Hook'" },
    { PUSH_BTN_OFF_HOOK, "Green Button 'Off Hook'" },
    { PUSH_BTN_UP, "Push Button 'Up'" },
    { PUSH_BTN_DOWN, "Push Button 'Down'" },
    { PUSH_BTN_LEFT, "Push Button 'Left'" },
    { PUSH_BTN_RIGHT, "Push Button 'Right'" },
    { END_BLOCK_DATA, "End Block Data" },
    { 0, NULL }
};

/**
 *	Dissect single command
 */
static void
dissect_a_binary_command(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *subtree;
    guint8* pstr;
    guint i, len;

    /* create command subtree */
    ti = proto_tree_add_item(tree, hf_a_cmd, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_a_cmd);
    proto_item_append_text(ti, ", %s", val_to_str(tvb_get_guint8(tvb, 0), szCmdID, "Unk %d"));

    /* command id */
    proto_tree_add_item(subtree, hf_a_id, tvb, 0, 1, ENC_NA);

    /* attributes */
    switch(tvb_get_guint8(tvb, 0))
    {
    default:
        {
            if(tvb_length(tvb) > 1)
                proto_tree_add_item(subtree, hf_a_data, tvb, 1, -1, ENC_NA);
            break;
        }
    case CONTEXT_INFO:
        {
            for(i = 1; i<tvb_length(tvb); )
            {
                switch(tvb_get_guint8(tvb, i))
                {
                default: i = tvb_length(tvb); continue;

                case 1:
                case 3:
                case 7:
                    {
                        ti = proto_tree_add_item(subtree, hf_a_attr, tvb, i, 2, ENC_NA);
                        proto_item_append_text(ti, " %d", tvb_get_guint8(tvb, i));
                        i+=2; break;
                    }

                case 0:
                case 4:
                    {
                        ti = proto_tree_add_item(subtree, hf_a_attr, tvb, i, 3, ENC_NA);
                        proto_item_append_text(ti, " %d", tvb_get_guint8(tvb, i));
                        i+=3; break;
                    }

                case 2:
                    {
                        ti = proto_tree_add_item(subtree, hf_a_attr, tvb, i, 5, ENC_NA);
                        proto_item_append_text(ti, " %d", tvb_get_guint8(tvb, i));
                        i+=5; break;
                    }
                }
            }
            break;
        }
    case BUTTON_PRESSED:
        {
            guint8 c = tvb_get_guint8(tvb, 5);
            proto_item_append_text(ti, ": %d '%c'", c, c);

            proto_tree_add_item(subtree, hf_a_data, tvb, 1, 4, ENC_NA);
            ti = proto_tree_add_item(subtree, hf_a_button_id, tvb, 5, 1, ENC_NA);
            if(ti)
                proto_item_append_text(ti, " '%c'", c);
            break;
        }
    case SET_TEXT:
        {
            if(tvb_length(tvb) > 3)
            {
                proto_tree_add_item(subtree, hf_a_data, tvb, 1, 3, ENC_NA);
                proto_tree_add_item(subtree, hf_a_length, tvb, 4, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_a_text, tvb, 5, -1, ENC_ASCII|ENC_NA);

                pstr = tvb_get_ephemeral_string(tvb, 5, tvb_get_guint8(tvb, 4));
                if(pstr)
                {
                    proto_item_append_text(ti, ": '%s'", pstr);
                }
            }
            else
            {
                proto_tree_add_item(subtree, hf_a_data, tvb, 1, -1, ENC_NA);
            }
            break;
        }
    case DATE_TIME_INFO:
        {
            proto_tree *infotree;

            for(i=1; i<tvb_length(tvb); )
            {
                switch(tvb_get_guint8(tvb, i))
                {
                default: i++; break;
                case 1:
                    {
                        len = 2;
                        ti = proto_tree_add_item(subtree, hf_a_item, tvb, i, len, ENC_NA);
                        infotree = proto_item_add_subtree(ti, ett_a_item);
                        proto_tree_add_item(infotree, hf_a_day, tvb, i+1, 1, ENC_NA);
                        proto_item_append_text(ti, ", Day: '%d'", tvb_get_guint8(tvb, i+1));
                        i += len;
                        break;
                    }
                case 2:
                    {
                        len = 2;
                        ti = proto_tree_add_item(subtree, hf_a_item, tvb, i, len, ENC_NA);
                        infotree = proto_item_add_subtree(ti, ett_a_item);
                        proto_tree_add_item(infotree, hf_a_month, tvb, i+1, 1, ENC_NA);
                        proto_item_append_text(ti, ", Month: '%d'", tvb_get_guint8(tvb, i+1));
                        i += len;
                        break;
                    }
                case 3:
                    {
                        len = 2;
                        ti = proto_tree_add_item(subtree, hf_a_item, tvb, i, len, ENC_NA);
                        infotree = proto_item_add_subtree(ti, ett_a_item);
                        proto_tree_add_item(infotree, hf_a_weekofyear, tvb, i+1, 1, ENC_NA);
                        proto_item_append_text(ti, ", Week of the year: '%d'", tvb_get_guint8(tvb, i+1));
                        i += len;
                        break;
                    }
                case 4:
                    {
                        len = tvb_get_guint8(tvb, i+1);
                        ti = proto_tree_add_item(subtree, hf_a_item, tvb, i, len+2, ENC_NA);
                        infotree = proto_item_add_subtree(ti, ett_a_item);
                        proto_tree_add_item(infotree, hf_a_data, tvb, i+2, len, ENC_NA);
                        i += len +2;
                        break;
                    }
                case 5:
                    {
                        len = tvb_get_guint8(tvb, i+1);
                        ti = proto_tree_add_item(subtree, hf_a_item, tvb, i, len+2, ENC_NA);
                        infotree = proto_item_add_subtree(ti, ett_a_item);
                        proto_tree_add_item(infotree, hf_a_weekday, tvb, i+2, len, ENC_ASCII|ENC_NA);
                        pstr = tvb_get_ephemeral_string(tvb, i+2, len);
                        if(pstr)
                            proto_item_append_text(ti, ", Weekday: '%s'", pstr);

                        i += len +2;
                        break;
                    }
                case 6:
                    {
                        len = tvb_get_guint8(tvb, i+1);
                        ti = proto_tree_add_item(subtree, hf_a_item, tvb, i, len+2, ENC_NA);
                        infotree = proto_item_add_subtree(ti, ett_a_item);
                        proto_tree_add_item(infotree, hf_a_month_name, tvb, i+2, len, ENC_ASCII|ENC_NA);
                        pstr = tvb_get_ephemeral_string(tvb, i+2, len);
                        if(pstr)
                            proto_item_append_text(ti, ", Month name: '%s'", pstr);
                        i += len +2;
                        break;
                    }
                case 7:
                    {
                        len = tvb_get_guint8(tvb, i+1);
                        ti = proto_tree_add_item(subtree, hf_a_item, tvb, i, len+2, ENC_NA);
                        infotree = proto_item_add_subtree(ti, ett_a_item);
                        proto_tree_add_item(infotree, hf_a_weekofyear_prefix, tvb, i+2, len, ENC_ASCII|ENC_NA);
                        pstr = tvb_get_ephemeral_string(tvb, i+2, len);
                        if(pstr)
                            proto_item_append_text(ti, ", Week of the year prefix: '%s'", pstr);
                        i += len +2;
                        break;
                    }
                case 8:
                    {
                        len = 2;
                        ti = proto_tree_add_item(subtree, hf_a_item, tvb, i, len, ENC_NA);
                        infotree = proto_item_add_subtree(ti, ett_a_item);
                        proto_tree_add_item(infotree, hf_a_hour, tvb, i+1, 1, ENC_NA);
                        proto_item_append_text(ti, ", Hour: '%d'", tvb_get_guint8(tvb, i+1));
                        i += len;
                        break;
                    }
                case 9:
                    {
                        len = 2;
                        ti = proto_tree_add_item(subtree, hf_a_item, tvb, i, len, ENC_NA);
                        infotree = proto_item_add_subtree(ti, ett_a_item);
                        proto_tree_add_item(infotree, hf_a_minute, tvb, i+1, 1, ENC_NA);
                        proto_item_append_text(ti, ", Minute: '%d'", tvb_get_guint8(tvb, i+1));
                        i += len;
                        break;
                    }
                case 10:
                    {
                        len = 2;
                        ti = proto_tree_add_item(subtree, hf_a_item, tvb, i, len, ENC_NA);
                        infotree = proto_item_add_subtree(ti, ett_a_item);
                        proto_tree_add_item(infotree, hf_a_data, tvb, i+1, 1, ENC_NA);
                        i += len;
                        break;
                    }
                }
            }
            break;
        }
    case DO_COMMAND:
        {
            if(tvb_length(tvb) > 1)
            {
                proto_tree_add_item(subtree, hf_a_line, tvb, 1, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_a_length, tvb, 2, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_a_cdpn, tvb, 3, -1, ENC_ASCII|ENC_NA);

                pstr = tvb_get_ephemeral_string(tvb, 3, tvb_get_guint8(tvb, 2));
                if(pstr)
                    proto_item_append_text(ti, ": '%s'", pstr);
            }
            else
                proto_item_append_text(ti, ": ???");
            break;
        }
    }
}

/**
 *	Searching for the next command when the variable or unknown length.
 */
static guint searchNext(tvbuff_t *tvb, guint begin, guint end)
{
    for(; begin < end; begin++)
    {
        if(tvb_get_guint8(tvb, begin) & 0x80)
            return begin;
    }
    return end;
}

/**
 * AASP-over-SIP
 */
static int
dissect_aasp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti; proto_tree *aasp_tree; guint n;

    /* Check that there's enough data */
    n = tvb_length(tvb);
    if(n < 3) return 0;

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/AASP");

    if(tree)
    {
        guint i, prev;

        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_aasp, tvb, 0, -1, ENC_NA);
        aasp_tree = proto_item_add_subtree(ti, ett_aasp);

        /* separation of command; jump "a=" */
        if(tvb_memeql(tvb, 0, "a=", 2) == 0)
        {
            prev = 2;
            for(i=2; i<n;)
            {
                switch(tvb_get_guint8(tvb, i))
                {
#if 0
                case CONTEXT_INFO:
                    {
                        /* 86:02:00:02:00:23:04:00 */
                        /* 86:02:00:12:00:23:04:00 */
                        /* 86:02:00:3a:02:77 */
                        /* 86:02:00:45:02:77 */
                        /* 86:02:00:62:02:77 */
                        /* 86:02:00:61:02:77 */
                        /* 86:02:00:1e:02:77 */
                        /* 86:02:00:00:12:77 */
                        /* 86:02:00:07:12:77 */
                        /* 86:02:00:00:00:01:03:02 */
                        /* 86:02:00:00:01:03:02 */
                        switch(tvb_get_guint8(tvb, i+2))
                        {
                        case 0x00:	i += 11; break;
                        case 0x02:  i +=  8; break;
                        }
                        break;
                    }
#endif
                default:	i = searchNext(tvb, i+1, n); break;
                }
                dissect_a_binary_command(tvb_new_subset(tvb, prev, i-prev, i-prev), pinfo, aasp_tree);
                prev = i;
            }
        }
        else
        {
            proto_tree_add_item(aasp_tree, hf_a_text, tvb, 0, -1, ENC_ASCII|ENC_NA);
        }
    }

    /* Return the amount of data this dissector was able to dissect */
    return n;
}

/* Register the protocol with Wireshark */
void
proto_register_aasp(void)
{
    /*module_t *aasp_module;*/

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_a_data,
          { "Data", "aasp.bin.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_a_cmd,
          { "Bin Cmd", "aasp.a", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_a_id,
          { "ID", "aasp.a.id", FT_UINT8, BASE_DEC, VALS(szCmdID), 0, NULL, HFILL }},
        { &hf_a_length,
          { "Length", "aasp.bin.length", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_a_text,
          { "Text", "aasp.bin.text", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_a_line,
          { "Line", "aasp.bin.line", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_a_cdpn,
          { "CDPN", "aasp.bin.cdpn", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_a_button_id,
          { "Button ID", "aasp.bin.btnid", FT_UINT8, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},

        { &hf_a_attr,
          { "Attribute", "aasp.a.attr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_a_item,
          { "Info item", "aasp.bin.infoitem", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_a_hour,
          { "Hour", "aasp.bin.hour", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_a_minute,
          { "Minute", "aasp.bin.minute", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_a_day,
          { "Day", "aasp.bin.day", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_a_month,
          { "Month", "aasp.bin.month", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_a_weekofyear,
          { "Week of the year", "aasp.bin.weekofyear", FT_UINT8, BASE_DEC, NULL, 0,
            "Week number in the year", HFILL }},
        { &hf_a_weekday,
          { "Weekday", "aasp.bin.weekday", FT_STRING, BASE_NONE, NULL, 0,
            "Short weekday name in the PBX current language", HFILL }},
        { &hf_a_month_name,
          { "Month name", "aasp.bin.monthname", FT_STRING, BASE_NONE, NULL, 0,
            "Short month name in the PBX current language", HFILL }},
        { &hf_a_weekofyear_prefix,
          { "Week of the year prefix", "aasp.bin.weekofyearprefix", FT_STRING, BASE_NONE, NULL, 0,
            "Precedes the number on the screen which is the week number in year", HFILL }},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_aasp,
        &ett_a_cmd,
        &ett_a_item,
    };

    /* Register the protocol name and description */
    proto_aasp = proto_register_protocol("Aastra Signalling Protocol", "AASP", "aasp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_aasp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register our configuration options */
    /* aasp_module = prefs_register_protocol(proto_aasp, proto_reg_handoff_aasp); */
}

/* */
void
proto_reg_handoff_aasp(void)
{
    dissector_handle_t aasp_handle;
    aasp_handle = new_create_dissector_handle(dissect_aasp, proto_aasp);
    dissector_add_string("media_type", "message/x-aasp-signalling", aasp_handle);
}
