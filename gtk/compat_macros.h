/* compat_macros.h
 * GTK-related Global defines, etc.
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

#ifndef __COMPAT_MACROS_H__
#define __COMPAT_MACROS_H__


/** @file
 *
 * Helper macros for gtk1.x / gtk2.x compatibility. Use these macros instead of the GTK deprecated functions,
 * to keep compatibility between GTK 1.x and 2.x.
 * For example in gtk2.x, gtk_signal_xxx is deprecated in favor of g_signal_xxx,
 *          gtk_object_xxx is deprecated in favor of g_object_xxx,
 *          gtk_widget_set_usize is deprecated in favor of
 *              gtk_widget_set_size_request, ...
 */

#ifdef HAVE_LIBPCAP
#define WIRESHARK_STOCK_LABEL_CAPTURE_INTERFACES       "_Interfaces"
#define WIRESHARK_STOCK_LABEL_CAPTURE_AIRPCAP          "_Wireless"
#define WIRESHARK_STOCK_LABEL_CAPTURE_OPTIONS          "_Options"
#define WIRESHARK_STOCK_LABEL_CAPTURE_START            "_Start"
#define WIRESHARK_STOCK_LABEL_CAPTURE_STOP             "S_top"
#define WIRESHARK_STOCK_LABEL_CAPTURE_RESTART          "_Restart"
#define WIRESHARK_STOCK_LABEL_CAPTURE_FILTER           "_CFilter"
#define WIRESHARK_STOCK_LABEL_CAPTURE_FILTER_ENTRY     "_Capture Filter:"
#define WIRESHARK_STOCK_LABEL_CAPTURE_DETAILS          "_Details"
#endif
#define WIRESHARK_STOCK_LABEL_DISPLAY_FILTER           "_Filter"
#define WIRESHARK_STOCK_LABEL_DISPLAY_FILTER_ENTRY     "_Filter:"
#define WIRESHARK_STOCK_LABEL_PREFS                    "_Prefs"
#define WIRESHARK_STOCK_LABEL_BROWSE                   "_Browse..."
#define WIRESHARK_STOCK_LABEL_CREATE_STAT              "Create _Stat"
#define WIRESHARK_STOCK_LABEL_EXPORT                   "_Export..."
#define WIRESHARK_STOCK_LABEL_IMPORT                   "_Import..."
#define WIRESHARK_STOCK_LABEL_EDIT                     "_Edit..."
#define WIRESHARK_STOCK_LABEL_ADD_EXPRESSION           "_Expression..." /* plus sign coming from icon */
#define WIRESHARK_STOCK_LABEL_DONT_SAVE                "Continue _without Saving"
#define WIRESHARK_STOCK_LABEL_ABOUT                    "_About"
#define WIRESHARK_STOCK_LABEL_COLORIZE                 "_Colorize"
#define WIRESHARK_STOCK_LABEL_AUTOSCROLL               "_Auto Scroll in Live Capture"
#define WIRESHARK_STOCK_LABEL_RESIZE_COLUMNS           "Resize Columns"
#define WIRESHARK_STOCK_LABEL_TIME                     "Time"
#define WIRESHARK_STOCK_LABEL_INTERNET                 "Internet"
#define WIRESHARK_STOCK_LABEL_WEB_SUPPORT              "Web Support"
#define WIRESHARK_STOCK_LABEL_WIKI                     "Wiki"
#define WIRESHARK_STOCK_LABEL_CONVERSATIONS            "Conversations"
#define WIRESHARK_STOCK_LABEL_ENDPOINTS                "Endpoints"
#define WIRESHARK_STOCK_LABEL_GRAPHS                   "Graphs"
#define WIRESHARK_STOCK_LABEL_TELEPHONY                "Telephony"
#define WIRESHARK_STOCK_LABEL_DECODE_AS                "Decode As"
#define WIRESHARK_STOCK_LABEL_CHECKBOX                 "Checkbox"
#define WIRESHARK_STOCK_LABEL_FILE_SET_LIST            "List Files"
#define WIRESHARK_STOCK_LABEL_FILE_SET_NEXT            "Next File"
#define WIRESHARK_STOCK_LABEL_FILE_SET_PREVIOUS        "Previous File"
#define WIRESHARK_STOCK_LABEL_FILTER_OUT_STREAM        "Filter Out This Stream"
#define WIRESHARK_STOCK_LABEL_ENABLE                   "Enable"
#define WIRESHARK_STOCK_LABEL_DISABLE                  "Disable"
#define WIRESHARK_STOCK_LABEL_COLOR1                   "Color 1"
#define WIRESHARK_STOCK_LABEL_COLOR2                   "Color 2"
#define WIRESHARK_STOCK_LABEL_COLOR3                   "Color 3"
#define WIRESHARK_STOCK_LABEL_COLOR4                   "Color 4"
#define WIRESHARK_STOCK_LABEL_COLOR5                   "Color 5"
#define WIRESHARK_STOCK_LABEL_COLOR6                   "Color 6"
#define WIRESHARK_STOCK_LABEL_COLOR7                   "Color 7"
#define WIRESHARK_STOCK_LABEL_COLOR8                   "Color 8"
#define WIRESHARK_STOCK_LABEL_COLOR9                   "Color 9"
#define WIRESHARK_STOCK_LABEL_COLOR0                   "Color 10"

#ifdef HAVE_LIBPCAP
#define WIRESHARK_STOCK_CAPTURE_INTERFACES       "Wireshark_Stock_CaptureInterfaces"
#define WIRESHARK_STOCK_CAPTURE_AIRPCAP			 "Wireshark_Stock_CaptureAirpcap"
#define WIRESHARK_STOCK_CAPTURE_OPTIONS          "Wireshark_Stock_CaptureOptionss"
#define WIRESHARK_STOCK_CAPTURE_START            "Wireshark_Stock_CaptureStart"
#define WIRESHARK_STOCK_CAPTURE_STOP             "Wireshark_Stock_CaptureStop"
#define WIRESHARK_STOCK_CAPTURE_RESTART          "Wireshark_Stock_CaptureRestart"
#define WIRESHARK_STOCK_CAPTURE_FILTER           "Wireshark_Stock_CaptureFilter"
#define WIRESHARK_STOCK_CAPTURE_FILTER_ENTRY     "Wireshark_Stock_CaptureFilter_Entry"
#define WIRESHARK_STOCK_CAPTURE_DETAILS          "Wireshark_Stock_CaptureDetails"
#endif
#define WIRESHARK_STOCK_DISPLAY_FILTER           "Wireshark_Stock_DisplayFilter"
#define WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY     "Wireshark_Stock_DisplayFilter_Entry"
#define WIRESHARK_STOCK_BROWSE                   "Wireshark_Stock_Browse"
#define WIRESHARK_STOCK_CREATE_STAT              "Wireshark_Stock_CreateStat"
#define WIRESHARK_STOCK_EXPORT                   "Wireshark_Stock_Export"
#define WIRESHARK_STOCK_IMPORT                   "Wireshark_Stock_Import"
#define WIRESHARK_STOCK_EDIT                     "Wireshark_Stock_Edit"
#define WIRESHARK_STOCK_ADD_EXPRESSION           "Wireshark_Stock_Edit_Add_Expression"
#define WIRESHARK_STOCK_DONT_SAVE                "Wireshark_Stock_Continue_without_Saving"
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
#define WIRESHARK_STOCK_GRAPHS                   "Wireshark_Stock_Graphs"
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

/* for details, see "Pango Text Attribute Markup" */
/* maybe it's a good idea to keep this macro beyond the ongoing GTK1 cleanup!
   If we want to change the look of the dialog boxes primary line the other day,
   we can easily do so, without changing lot's of places */
/* XXX - moving it to a better place (file) might be a good idea anyway */
#define PRIMARY_TEXT_START "<span weight=\"bold\" size=\"larger\">"
#define PRIMARY_TEXT_END "</span>"

#endif /* __COMPAT_MACROS_H__ */
