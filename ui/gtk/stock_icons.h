/* stock_icons.h
 * Wireshark specific stock icons
 * Copyright 2003-2008, Ulf Lamping <ulf.lamping@web.de>
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

#ifndef __STOCK_ICONS_H__
#define __STOCK_ICONS_H__

#include <gtk/gtk.h>

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
#define WIRESHARK_STOCK_GRAPH_A_B                "Wireshark_Stock_Graph_A_B"
#define WIRESHARK_STOCK_GRAPH_B_A                "Wireshark_Stock_Graph_B_A"
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
#define WIRESHARK_STOCK_STOP_DONT_SAVE           "Wireshark_Stock_Stop_and_Continue_without_Saving"
#define WIRESHARK_STOCK_STOP_QUIT_DONT_SAVE      "Wireshark_Stock_Stop_and_Quit_without_Saving"
#define WIRESHARK_STOCK_STOP_SAVE                "Wireshark_Stock_Stop_and_Save"
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
#define WIRESHARK_STOCK_SAVE                     "Wireshark_Save"

/*
 * Use of GTK_STOCK_.* is deprecated from 3.10
 * https://developer.gnome.org/gtk3/stable/gtk3-Stock-Items.html
 * We keep the defined names in the code and provide mapping for them
 * to labels and standard icons based on
 * https://docs.google.com/spreadsheet/pub?key=0AsPAM3pPwxagdGF4THNMMUpjUW5xMXZfdUNzMXhEa2c&output=html
 */
#if GTK_CHECK_VERSION(3, 10, 0)

#ifdef GTK_STOCK_ABOUT
#undef GTK_STOCK_ABOUT
#endif
#define GTK_STOCK_ABOUT "gtk-about"

#ifdef GTK_STOCK_ADD
#undef GTK_STOCK_ADD
#endif
#define GTK_STOCK_ADD "gtk-add"

#ifdef GTK_STOCK_APPLY
#undef GTK_STOCK_APPLY
#endif
#define GTK_STOCK_APPLY "gtk-apply"

#ifdef GTK_STOCK_BOLD
#undef GTK_STOCK_BOLD
#endif
#define GTK_STOCK_BOLD "gtk-bold"

#ifdef GTK_STOCK_CANCEL
#undef GTK_STOCK_CANCEL
#endif
#define GTK_STOCK_CANCEL "gtk-cancel"

#ifdef GTK_STOCK_CAPS_LOCK_WARNING
#undef GTK_STOCK_CAPS_LOCK_WARNING
#endif
#define GTK_STOCK_CAPS_LOCK_WARNING "gtk-caps-lock-warning"

#ifdef GTK_STOCK_CDROM
#undef GTK_STOCK_CDROM
#endif
#define GTK_STOCK_CDROM "gtk-cdrom"

#ifdef GTK_STOCK_CLEAR
#undef GTK_STOCK_CLEAR
#endif
#define GTK_STOCK_CLEAR "gtk-clear"

#ifdef GTK_STOCK_CLOSE
#undef GTK_STOCK_CLOSE
#endif
#define GTK_STOCK_CLOSE "gtk-close"

#ifdef GTK_STOCK_COLOR_PICKER
#undef GTK_STOCK_COLOR_PICKER
#endif
#define GTK_STOCK_COLOR_PICKER "gtk-color-picker"

#ifdef GTK_STOCK_CONNECT
#undef GTK_STOCK_CONNECT
#endif
#define GTK_STOCK_CONNECT "gtk-connect"

#ifdef GTK_STOCK_CONVERT
#undef GTK_STOCK_CONVERT
#endif
#define GTK_STOCK_CONVERT "gtk-convert"

#ifdef GTK_STOCK_COPY
#undef GTK_STOCK_COPY
#endif
#define GTK_STOCK_COPY "gtk-copy"

#ifdef GTK_STOCK_CUT
#undef GTK_STOCK_CUT
#endif
#define GTK_STOCK_CUT "gtk-cut"

#ifdef GTK_STOCK_DELETE
#undef GTK_STOCK_DELETE
#endif
#define GTK_STOCK_DELETE "gtk-delete"

#ifdef GTK_STOCK_DIALOG_AUTHENTICATION
#undef GTK_STOCK_DIALOG_AUTHENTICATION
#endif
#define GTK_STOCK_DIALOG_AUTHENTICATION "gtk-dialog-authentication"

#ifdef GTK_STOCK_DIALOG_INFO
#undef GTK_STOCK_DIALOG_INFO
#endif
#define GTK_STOCK_DIALOG_INFO "gtk-dialog-info"

#ifdef GTK_STOCK_DIALOG_WARNING
#undef GTK_STOCK_DIALOG_WARNING
#endif
#define GTK_STOCK_DIALOG_WARNING "gtk-dialog-warning"

#ifdef GTK_STOCK_DIALOG_ERROR
#undef GTK_STOCK_DIALOG_ERROR
#endif
#define GTK_STOCK_DIALOG_ERROR "gtk-dialog-error"

#ifdef GTK_STOCK_DIALOG_QUESTION
#undef GTK_STOCK_DIALOG_QUESTION
#endif
#define GTK_STOCK_DIALOG_QUESTION "gtk-dialog-question"

#ifdef GTK_STOCK_DIRECTORY
#undef GTK_STOCK_DIRECTORY
#endif
#define GTK_STOCK_DIRECTORY "gtk-directory"

#ifdef GTK_STOCK_DISCARD
#undef GTK_STOCK_DISCARD
#endif
#define GTK_STOCK_DISCARD "gtk-discard"

#ifdef GTK_STOCK_DISCONNECT
#undef GTK_STOCK_DISCONNECT
#endif
#define GTK_STOCK_DISCONNECT "gtk-disconnect"

#ifdef GTK_STOCK_DND
#undef GTK_STOCK_DND
#endif
#define GTK_STOCK_DND "gtk-dnd"

#ifdef GTK_STOCK_DND_MULTIPLE
#undef GTK_STOCK_DND_MULTIPLE
#endif
#define GTK_STOCK_DND_MULTIPLE "gtk-dnd-multiple"

#ifdef GTK_STOCK_EDIT
#undef GTK_STOCK_EDIT
#endif
#define GTK_STOCK_EDIT "gtk-edit"

#ifdef GTK_STOCK_EXECUTE
#undef GTK_STOCK_EXECUTE
#endif
#define GTK_STOCK_EXECUTE "gtk-execute"

#ifdef GTK_STOCK_FILE
#undef GTK_STOCK_FILE
#endif
#define GTK_STOCK_FILE "gtk-file"

#ifdef GTK_STOCK_FIND
#undef GTK_STOCK_FIND
#endif
#define GTK_STOCK_FIND "gtk-find"

#ifdef GTK_STOCK_FIND_AND_REPLACE
#undef GTK_STOCK_FIND_AND_REPLACE
#endif
#define GTK_STOCK_FIND_AND_REPLACE "gtk-find-and-replace"

#ifdef GTK_STOCK_FLOPPY
#undef GTK_STOCK_FLOPPY
#endif
#define GTK_STOCK_FLOPPY "gtk-floppy"

#ifdef GTK_STOCK_FULLSCREEN
#undef GTK_STOCK_FULLSCREEN
#endif
#define GTK_STOCK_FULLSCREEN "gtk-fullscreen"

#ifdef GTK_STOCK_GOTO_BOTTOM
#undef GTK_STOCK_GOTO_BOTTOM
#endif
#define GTK_STOCK_GOTO_BOTTOM "gtk-goto-bottom"

#ifdef GTK_STOCK_GOTO_FIRST
#undef GTK_STOCK_GOTO_FIRST
#endif
#define GTK_STOCK_GOTO_FIRST "gtk-goto-first"

#ifdef GTK_STOCK_GOTO_LAST
#undef GTK_STOCK_GOTO_LAST
#endif
#define GTK_STOCK_GOTO_LAST "gtk-goto-last"

#ifdef GTK_STOCK_GOTO_TOP
#undef GTK_STOCK_GOTO_TOP
#endif
#define GTK_STOCK_GOTO_TOP "gtk-goto-top"

#ifdef GTK_STOCK_GO_BACK
#undef GTK_STOCK_GO_BACK
#endif
#define GTK_STOCK_GO_BACK "gtk-go-back"

#ifdef GTK_STOCK_GO_DOWN
#undef GTK_STOCK_GO_DOWN
#endif
#define GTK_STOCK_GO_DOWN "gtk-go-down"

#ifdef GTK_STOCK_GO_FORWARD
#undef GTK_STOCK_GO_FORWARD
#endif
#define GTK_STOCK_GO_FORWARD "gtk-go-forward"

#ifdef GTK_STOCK_GO_UP
#undef GTK_STOCK_GO_UP
#endif
#define GTK_STOCK_GO_UP "gtk-go-up"

#ifdef GTK_STOCK_HARDDISK
#undef GTK_STOCK_HARDDISK
#endif
#define GTK_STOCK_HARDDISK "gtk-harddisk"

#ifdef GTK_STOCK_HELP
#undef GTK_STOCK_HELP
#endif
#define GTK_STOCK_HELP "gtk-help"

#ifdef GTK_STOCK_HOME
#undef GTK_STOCK_HOME
#endif
#define GTK_STOCK_HOME "gtk-home"

#ifdef GTK_STOCK_INDEX
#undef GTK_STOCK_INDEX
#endif
#define GTK_STOCK_INDEX "gtk-index"

#ifdef GTK_STOCK_INDENT
#undef GTK_STOCK_INDENT
#endif
#define GTK_STOCK_INDENT "gtk-indent"

#ifdef GTK_STOCK_INFO
#undef GTK_STOCK_INFO
#endif
#define GTK_STOCK_INFO "gtk-info"

#ifdef GTK_STOCK_ITALIC
#undef GTK_STOCK_ITALIC
#endif
#define GTK_STOCK_ITALIC "gtk-italic"

#ifdef GTK_STOCK_JUMP_TO
#undef GTK_STOCK_JUMP_TO
#endif
#define GTK_STOCK_JUMP_TO "gtk-jump-to"

#ifdef GTK_STOCK_JUSTIFY_CENTER
#undef GTK_STOCK_JUSTIFY_CENTER
#endif
#define GTK_STOCK_JUSTIFY_CENTER "gtk-justify-center"

#ifdef GTK_STOCK_JUSTIFY_FILL
#undef GTK_STOCK_JUSTIFY_FILL
#endif
#define GTK_STOCK_JUSTIFY_FILL "gtk-justify-fill"

#ifdef GTK_STOCK_JUSTIFY_LEFT
#undef GTK_STOCK_JUSTIFY_LEFT
#endif
#define GTK_STOCK_JUSTIFY_LEFT "gtk-justify-left"

#ifdef GTK_STOCK_JUSTIFY_RIGHT
#undef GTK_STOCK_JUSTIFY_RIGHT
#endif
#define GTK_STOCK_JUSTIFY_RIGHT "gtk-justify-right"

#ifdef GTK_STOCK_LEAVE_FULLSCREEN
#undef GTK_STOCK_LEAVE_FULLSCREEN
#endif
#define GTK_STOCK_LEAVE_FULLSCREEN "gtk-leave-fullscreen"

#ifdef GTK_STOCK_MISSING_IMAGE
#undef GTK_STOCK_MISSING_IMAGE
#endif
#define GTK_STOCK_MISSING_IMAGE "gtk-missing-image"

#ifdef GTK_STOCK_MEDIA_FORWARD
#undef GTK_STOCK_MEDIA_FORWARD
#endif
#define GTK_STOCK_MEDIA_FORWARD "gtk-media-forward"

#ifdef GTK_STOCK_MEDIA_NEXT
#undef GTK_STOCK_MEDIA_NEXT
#endif
#define GTK_STOCK_MEDIA_NEXT "gtk-media-next"

#ifdef GTK_STOCK_MEDIA_PAUSE
#undef GTK_STOCK_MEDIA_PAUSE
#endif
#define GTK_STOCK_MEDIA_PAUSE "gtk-media-pause"

#ifdef GTK_STOCK_MEDIA_PLAY
#undef GTK_STOCK_MEDIA_PLAY
#endif
#define GTK_STOCK_MEDIA_PLAY "gtk-media-play"

#ifdef GTK_STOCK_MEDIA_PREVIOUS
#undef GTK_STOCK_MEDIA_PREVIOUS
#endif
#define GTK_STOCK_MEDIA_PREVIOUS "gtk-media-previous"

#ifdef GTK_STOCK_MEDIA_RECORD
#undef GTK_STOCK_MEDIA_RECORD
#endif
#define GTK_STOCK_MEDIA_RECORD "gtk-media-record"

#ifdef GTK_STOCK_MEDIA_REWIND
#undef GTK_STOCK_MEDIA_REWIND
#endif
#define GTK_STOCK_MEDIA_REWIND "gtk-media-rewind"

#ifdef GTK_STOCK_MEDIA_STOP
#undef GTK_STOCK_MEDIA_STOP
#endif
#define GTK_STOCK_MEDIA_STOP "gtk-media-stop"

#ifdef GTK_STOCK_NETWORK
#undef GTK_STOCK_NETWORK
#endif
#define GTK_STOCK_NETWORK "gtk-network"

#ifdef GTK_STOCK_NEW
#undef GTK_STOCK_NEW
#endif
#define GTK_STOCK_NEW "gtk-new"

#ifdef GTK_STOCK_NO
#undef GTK_STOCK_NO
#endif
#define GTK_STOCK_NO "gtk-no"

#ifdef GTK_STOCK_OK
#undef GTK_STOCK_OK
#endif
#define GTK_STOCK_OK "gtk-ok"

#ifdef GTK_STOCK_OPEN
#undef GTK_STOCK_OPEN
#endif
#define GTK_STOCK_OPEN "gtk-open"

#ifdef GTK_STOCK_ORIENTATION_PORTRAIT
#undef GTK_STOCK_ORIENTATION_PORTRAIT
#endif
#define GTK_STOCK_ORIENTATION_PORTRAIT "gtk-orientation-portrait"

#ifdef GTK_STOCK_ORIENTATION_LANDSCAPE
#undef GTK_STOCK_ORIENTATION_LANDSCAPE
#endif
#define GTK_STOCK_ORIENTATION_LANDSCAPE "gtk-orientation-landscape"

#ifdef GTK_STOCK_ORIENTATION_REVERSE_LANDSCAPE
#undef GTK_STOCK_ORIENTATION_REVERSE_LANDSCAPE
#endif
#define GTK_STOCK_ORIENTATION_REVERSE_LANDSCAPE "gtk-orientation-reverse-landscape"

#ifdef GTK_STOCK_ORIENTATION_REVERSE_PORTRAIT
#undef GTK_STOCK_ORIENTATION_REVERSE_PORTRAIT
#endif
#define GTK_STOCK_ORIENTATION_REVERSE_PORTRAIT "gtk-orientation-reverse-portrait"

#ifdef GTK_STOCK_PAGE_SETUP
#undef GTK_STOCK_PAGE_SETUP
#endif
#define GTK_STOCK_PAGE_SETUP "gtk-page-setup"

#ifdef GTK_STOCK_PASTE
#undef GTK_STOCK_PASTE
#endif
#define GTK_STOCK_PASTE "gtk-paste"

#ifdef GTK_STOCK_PREFERENCES
#undef GTK_STOCK_PREFERENCES
#endif
#define GTK_STOCK_PREFERENCES "gtk-preferences"

#ifdef GTK_STOCK_PRINT
#undef GTK_STOCK_PRINT
#endif
#define GTK_STOCK_PRINT "gtk-print"

#ifdef GTK_STOCK_PRINT_ERROR
#undef GTK_STOCK_PRINT_ERROR
#endif
#define GTK_STOCK_PRINT_ERROR "gtk-print-error"

#ifdef GTK_STOCK_PRINT_PAUSED
#undef GTK_STOCK_PRINT_PAUSED
#endif
#define GTK_STOCK_PRINT_PAUSED "gtk-print-paused"

#ifdef GTK_STOCK_PRINT_PREVIEW
#undef GTK_STOCK_PRINT_PREVIEW
#endif
#define GTK_STOCK_PRINT_PREVIEW "gtk-print-preview"

#ifdef GTK_STOCK_PRINT_REPORT
#undef GTK_STOCK_PRINT_REPORT
#endif
#define GTK_STOCK_PRINT_REPORT "gtk-print-report"

#ifdef GTK_STOCK_PRINT_WARNING
#undef GTK_STOCK_PRINT_WARNING
#endif
#define GTK_STOCK_PRINT_WARNING "gtk-print-warning"

#ifdef GTK_STOCK_PROPERTIES
#undef GTK_STOCK_PROPERTIES
#endif
#define GTK_STOCK_PROPERTIES "gtk-properties"

#ifdef GTK_STOCK_QUIT
#undef GTK_STOCK_QUIT
#endif
#define GTK_STOCK_QUIT "gtk-quit"

#ifdef GTK_STOCK_REDO
#undef GTK_STOCK_REDO
#endif
#define GTK_STOCK_REDO "gtk-redo"

#ifdef GTK_STOCK_REFRESH
#undef GTK_STOCK_REFRESH
#endif
#define GTK_STOCK_REFRESH "gtk-refresh"

#ifdef GTK_STOCK_REMOVE
#undef GTK_STOCK_REMOVE
#endif
#define GTK_STOCK_REMOVE "gtk-remove"

#ifdef GTK_STOCK_REVERT_TO_SAVED
#undef GTK_STOCK_REVERT_TO_SAVED
#endif
#define GTK_STOCK_REVERT_TO_SAVED "gtk-revert-to-saved"

#ifdef GTK_STOCK_SAVE
#undef GTK_STOCK_SAVE
#endif
#define GTK_STOCK_SAVE "gtk-save"

#ifdef GTK_STOCK_SAVE_AS
#undef GTK_STOCK_SAVE_AS
#endif
#define GTK_STOCK_SAVE_AS "gtk-save-as"

#ifdef GTK_STOCK_SELECT_ALL
#undef GTK_STOCK_SELECT_ALL
#endif
#define GTK_STOCK_SELECT_ALL "gtk-select-all"

#ifdef GTK_STOCK_SELECT_COLOR
#undef GTK_STOCK_SELECT_COLOR
#endif
#define GTK_STOCK_SELECT_COLOR "gtk-select-color"

#ifdef GTK_STOCK_SELECT_FONT
#undef GTK_STOCK_SELECT_FONT
#endif
#define GTK_STOCK_SELECT_FONT "gtk-select-font"

#ifdef GTK_STOCK_SORT_ASCENDING
#undef GTK_STOCK_SORT_ASCENDING
#endif
#define GTK_STOCK_SORT_ASCENDING "gtk-sort-ascending"

#ifdef GTK_STOCK_SORT_DESCENDING
#undef GTK_STOCK_SORT_DESCENDING
#endif
#define GTK_STOCK_SORT_DESCENDING "gtk-sort-descending"

#ifdef GTK_STOCK_SPELL_CHECK
#undef GTK_STOCK_SPELL_CHECK
#endif
#define GTK_STOCK_SPELL_CHECK "gtk-spell-check"

#ifdef GTK_STOCK_STOP
#undef GTK_STOCK_STOP
#endif
#define GTK_STOCK_STOP "gtk-stop"

#ifdef GTK_STOCK_STRIKETHROUGH
#undef GTK_STOCK_STRIKETHROUGH
#endif
#define GTK_STOCK_STRIKETHROUGH "gtk-strikethrough"

#ifdef GTK_STOCK_UNDELETE
#undef GTK_STOCK_UNDELETE
#endif
#define GTK_STOCK_UNDELETE "gtk-undelete"

#ifdef GTK_STOCK_UNDERLINE
#undef GTK_STOCK_UNDERLINE
#endif
#define GTK_STOCK_UNDERLINE "gtk-underline"

#ifdef GTK_STOCK_UNDO
#undef GTK_STOCK_UNDO
#endif
#define GTK_STOCK_UNDO "gtk-undo"

#ifdef GTK_STOCK_UNINDENT
#undef GTK_STOCK_UNINDENT
#endif
#define GTK_STOCK_UNINDENT "gtk-unindent"

#ifdef GTK_STOCK_YES
#undef GTK_STOCK_YES
#endif
#define GTK_STOCK_YES "gtk-yes"

#ifdef GTK_STOCK_ZOOM_100
#undef GTK_STOCK_ZOOM_100
#endif
#define GTK_STOCK_ZOOM_100 "gtk-zoom-100"

#ifdef GTK_STOCK_ZOOM_FIT
#undef GTK_STOCK_ZOOM_FIT
#endif
#define GTK_STOCK_ZOOM_FIT "gtk-zoom-fit"

#ifdef GTK_STOCK_ZOOM_IN
#undef GTK_STOCK_ZOOM_IN
#endif
#define GTK_STOCK_ZOOM_IN "gtk-zoom-in"

#ifdef GTK_STOCK_ZOOM_OUT
#undef GTK_STOCK_ZOOM_OUT
#endif
#define GTK_STOCK_ZOOM_OUT "gtk-zoom-out"

#endif /* GTK_CHECK_VERSION(3, 10, 0) */

void stock_icons_init(void);

/**
 * Creates a GtkButton with a preset icon and label.
 * @param stock_id Id of the icon and label pair
 * @return The newly created GtkButton widget.
 */
GtkWidget * ws_gtk_button_new_from_stock(const gchar *stock_id);

/**
 * Creates a GtkToolButton with a preset icon and label.
 * @param stock_id Id of the icon and label pair
 * @return The newly created GtkButton widget.
 */
GtkToolItem * ws_gtk_tool_button_new_from_stock(const gchar *stock_id);

/**
 * Creates a GtkToggleToolButton with a preset icon and label.
 * @param stock_id Id of the icon and label pair
 * @return The newly created GtkButton widget.
 */
GtkToolItem * ws_gtk_toggle_tool_button_new_from_stock(const gchar *stock_id);

/**
 * Creates a GtkImage displaying a stock icon.
 * @param stock_id a stock icon name
 * @param size a stock icon size of GtkIconSize type
 */
GtkWidget * ws_gtk_image_new_from_stock(const gchar *stock_id, GtkIconSize size);

#endif /* __STOCK_ICONS_H__ */
