/* stock_icons.h
 * Wireshark specific stock icons
 * Copyright 2003-2008, Ulf Lamping <ulf.lamping@web.de>
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

#ifndef __STOCK_ICONS_H__
#define __STOCK_ICONS_H__


#define WIRESHARK_STOCK_CAPTURE_INTERFACES       "Wireshark_Stock_CaptureInterfaces"
#define WIRESHARK_STOCK_CAPTURE_OPTIONS          "Wireshark_Stock_CaptureOptionss"
#define WIRESHARK_STOCK_CAPTURE_START            "Wireshark_Stock_CaptureStart"
#define WIRESHARK_STOCK_CAPTURE_STOP             "Wireshark_Stock_CaptureStop"
#define WIRESHARK_STOCK_CAPTURE_RESTART          "Wireshark_Stock_CaptureRestart"
#define WIRESHARK_STOCK_CAPTURE_FILTER           "Wireshark_Stock_CaptureFilter"
#define WIRESHARK_STOCK_CAPTURE_FILTER_ENTRY     "Wireshark_Stock_CaptureFilter_Entry"
#define WIRESHARK_STOCK_CAPTURE_DETAILS          "Wireshark_Stock_CaptureDetails"
#ifdef HAVE_GEOIP
#define WIRESHARK_STOCK_MAP                      "Wireshark_Stock_Map"
#endif
#define WIRESHARK_STOCK_FOLLOW_STREAM            "Wireshark_Stock_FollowStream"
#define WIRESHARK_STOCK_DISPLAY_FILTER           "Wireshark_Stock_DisplayFilter"
#define WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY     "Wireshark_Stock_DisplayFilter_Entry"
#define WIRESHARK_STOCK_BROWSE                   "Wireshark_Stock_Browse"
#define WIRESHARK_STOCK_CREATE_STAT              "Wireshark_Stock_CreateStat"
#define WIRESHARK_STOCK_EXPORT                   "Wireshark_Stock_Export"
#define WIRESHARK_STOCK_IMPORT                   "Wireshark_Stock_Import"
#define WIRESHARK_STOCK_EDIT                     "Wireshark_Stock_Edit"
#define WIRESHARK_STOCK_ADD_EXPRESSION           "Wireshark_Stock_Edit_Add_Expression"
#define WIRESHARK_STOCK_CLEAR_EXPRESSION         "Wireshark_Stock_Clear_Expression"
#define WIRESHARK_STOCK_APPLY_EXPRESSION         "Wireshark_Stock_Apply_Expression"
#define WIRESHARK_STOCK_DONT_SAVE                "Wireshark_Stock_Continue_without_Saving"
#define WIRESHARK_STOCK_QUIT_DONT_SAVE           "Wireshark_Stock_Quit_without_Saving"
#define WIRESHARK_STOCK_SAVE_ALL                 "Wireshark_Stock_Save_All"
#define WIRESHARK_STOCK_ABOUT                    "Wireshark_Stock_About"
#define WIRESHARK_STOCK_COLORIZE                 "Wireshark_Stock_Colorize"
#define WIRESHARK_STOCK_AUTOSCROLL               "Wireshark_Stock_Autoscroll"
#define WIRESHARK_STOCK_RESIZE_COLUMNS           "Wireshark_Stock_Resize_Columns"
#define WIRESHARK_STOCK_TIME                     "Wireshark_Stock_Time"
#define WIRESHARK_STOCK_INTERNET                 "Wireshark_Stock_Internet"
#define WIRESHARK_STOCK_WEB_SUPPORT              "Wireshark_Stock_Web_Support"
#define WIRESHARK_STOCK_WIKI                     "Wireshark_Stock_Wiki"
#define WIRESHARK_STOCK_CONVERSATIONS            "Wireshark_Stock_Conversations"
#define WIRESHARK_STOCK_ENDPOINTS                "Wireshark_Stock_Endpoints"
#define WIRESHARK_STOCK_EXPERT_INFO              "Wireshark_Stock_Expert_Info"
#define WIRESHARK_STOCK_GRAPHS                   "Wireshark_Stock_Graphs"
#define WIRESHARK_STOCK_FLOW_GRAPH               "Wireshark_Stock_Flow_Graph"
#define WIRESHARK_STOCK_TELEPHONY                "Wireshark_Stock_Telephony"
#define WIRESHARK_STOCK_DECODE_AS                "Wireshark_Stock_DecodeAs"
#define WIRESHARK_STOCK_CHECKBOX                 "Wireshark_Stock_Checkbox"
#define WIRESHARK_STOCK_FILE_SET_LIST            "Wireshark_Stock_File_Set_List"
#define WIRESHARK_STOCK_FILE_SET_NEXT            "Wireshark_Stock_File_Set_Next"
#define WIRESHARK_STOCK_FILE_SET_PREVIOUS        "Wireshark_Stock_File_Set_Previous"
#define WIRESHARK_STOCK_FILTER_OUT_STREAM        "Wireshark_Stock_Filter_Out_This_Stream"
#define WIRESHARK_STOCK_ENABLE                   "Wireshark_Stock_Enable"
#define WIRESHARK_STOCK_DISABLE                  "Wireshark_Stock_Disable"
#define WIRESHARK_STOCK_COLOR1                   "Wireshark_Stock_Color_1"
#define WIRESHARK_STOCK_COLOR2                   "Wireshark_Stock_Color_2"
#define WIRESHARK_STOCK_COLOR3                   "Wireshark_Stock_Color_3"
#define WIRESHARK_STOCK_COLOR4                   "Wireshark_Stock_Color_4"
#define WIRESHARK_STOCK_COLOR5                   "Wireshark_Stock_Color_5"
#define WIRESHARK_STOCK_COLOR6                   "Wireshark_Stock_Color_6"
#define WIRESHARK_STOCK_COLOR7                   "Wireshark_Stock_Color_7"
#define WIRESHARK_STOCK_COLOR8                   "Wireshark_Stock_Color_8"
#define WIRESHARK_STOCK_COLOR9                   "Wireshark_Stock_Color_9"
#define WIRESHARK_STOCK_COLOR0                   "Wireshark_Stock_Color_10"
#define WIRESHARK_STOCK_DECODE                   "Wireshark_Stock_Decode"
#define WIRESHARK_STOCK_AUDIO_PLAYER             "Wireshark_Audio_Player"
#define WIRESHARK_STOCK_VOIP_FLOW                "Wireshark_Voip_Flow"
#define WIRESHARK_STOCK_TELEPHONE                "Wireshark_Telephone"
#define WIRESHARK_STOCK_PREPARE_FILTER           "Wireshark_Prepare_Filter"
#define WIRESHARK_STOCK_ANALYZE                  "Wireshark_Analyze"
#define WIRESHARK_STOCK_FILE                     "Wireshark_File"

void stock_icons_init(void);

#endif /* __STOCK_ICONS_H__ */
