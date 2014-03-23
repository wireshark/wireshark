/* stock_icons.c
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

#include "config.h"

#include <gtk/gtk.h>

#include <stdlib.h>
#include <string.h>

#include "ui/gtk/stock_icons.h"
#include "ui/gtk/toolbar_icons.h"
#include "ui/gtk/wsicon.h"

#include "ui/utf8_entities.h"

/* these icons are derived from the original stock icons */
#include "../../image/toolbar/capture_filter_24.xpm"
#include "../../image/toolbar/capture_details_24.xpm"
#include "../../image/toolbar/display_filter_24.xpm"
#include "../../image/toolbar/colorize_24.xpm"
#include "../../image/toolbar/autoscroll_24.xpm"
#include "../../image/toolbar/resize_columns_24.xpm"
#include "../../image/toolbar/time_24.xpm"
#include "../../image/toolbar/internet_24.xpm"
#include "../../image/toolbar/web_support_24.xpm"
#include "../../image/toolbar/conversations_16.xpm"
#include "../../image/toolbar/endpoints_16.xpm"
#include "../../image/toolbar/expert_info_16.xpm"
#include "../../image/toolbar/flow_graph_16.xpm"
#include "../../image/toolbar/graphs_16.xpm"
#include "../../image/toolbar/telephony_16.xpm"
#include "../../image/toolbar/decode_as_16.xpm"
#include "../../image/toolbar/checkbox_16.xpm"
#include "../../image/toolbar/file_set_list_16.xpm"
#include "../../image/toolbar/file_set_next_16.xpm"
#include "../../image/toolbar/file_set_previous_16.xpm"
#include "../../image/toolbar/icon_color_1.xpm"
#include "../../image/toolbar/icon_color_2.xpm"
#include "../../image/toolbar/icon_color_3.xpm"
#include "../../image/toolbar/icon_color_4.xpm"
#include "../../image/toolbar/icon_color_5.xpm"
#include "../../image/toolbar/icon_color_6.xpm"
#include "../../image/toolbar/icon_color_7.xpm"
#include "../../image/toolbar/icon_color_8.xpm"
#include "../../image/toolbar/icon_color_9.xpm"
#include "../../image/toolbar/icon_color_0.xpm"
#include "../../image/toolbar/decode_24.xpm"
#include "../../image/toolbar/audio_player_24.xpm"
#include "../../image/toolbar/voip_flow_24.xpm"
#include "../../image/toolbar/telephone_16.xpm"
#include "../../image/toolbar/analyze_24.xpm"

/*
 * the minimal value is 10, since gtk_button_new_from_icon_name() is available
 * from GTK+ 3.10
 */
#define WS_GTK3_MINOR_STOCK_DEPRECATION_STARTS 99

typedef struct stock_item_tag {
    const char * name;
    const char * icon;
    const char * label;
} stock_item_t;

typedef struct stock_pixmap_tag{
    const char *    name;
    const char **   xpm_data;
    const guint     size;
} stock_pixmap_t;

typedef struct stock_pixbuf_tag{
    const char    * name;
    const guint8 * pb_data16; /* Optional */
    const guint8 * pb_data24; /* Mandatory */
} stock_pixbuf_t;

/*
 * Register non-standard pixmaps with the gtk-stock engine.
 * Most of the icon names match the item name here.
 * Use default stock icons for Wireshark specifics where the icon metapher makes sense.
 * PLEASE DON'T REUSE STOCK ICONS IF THEY ARE USUALLY USED FOR SOME DIFFERENT MEANING!!!)
 */
static stock_item_t ws_stock_items[] = {
    {(const char *)WIRESHARK_STOCK_CAPTURE_INTERFACES,    (char *)WIRESHARK_STOCK_CAPTURE_INTERFACES,     (const char *)"_Interfaces"},
    {(const char *)WIRESHARK_STOCK_CAPTURE_OPTIONS,       (const char *)WIRESHARK_STOCK_CAPTURE_OPTIONS,        (const char *)"_Options"},
    {(const char *)WIRESHARK_STOCK_CAPTURE_START,         (const char *)WIRESHARK_STOCK_CAPTURE_START,          (const char *)"_Start"},
    {(const char *)WIRESHARK_STOCK_CAPTURE_STOP,          (const char *)WIRESHARK_STOCK_CAPTURE_STOP,           (const char *)"S_top"},
    {(const char *)WIRESHARK_STOCK_CAPTURE_RESTART,       (const char *)WIRESHARK_STOCK_CAPTURE_RESTART,        (const char *)"_Restart"},
    {(const char *)WIRESHARK_STOCK_CAPTURE_FILTER,        (const char *)WIRESHARK_STOCK_CAPTURE_FILTER,         (const char *)"_Capture Filter"},
    {(const char *)WIRESHARK_STOCK_CAPTURE_FILTER_ENTRY,  (const char *)WIRESHARK_STOCK_CAPTURE_FILTER_ENTRY,   (const char *)"_Capture Filter:"},
    {(const char *)WIRESHARK_STOCK_CAPTURE_DETAILS,       (const char *)WIRESHARK_STOCK_CAPTURE_DETAILS,        (const char *)"_Details"},
    #ifdef HAVE_GEOIP
    {(const char *)WIRESHARK_STOCK_MAP,                   (const char *)WIRESHARK_STOCK_MAP,                    (const char *)"Map"},
    #endif
    {(const char *)WIRESHARK_STOCK_GRAPH_A_B,             (const char *)WIRESHARK_STOCK_GRAPH_A_B,              (const char *)"Graph A" UTF8_RIGHTWARDS_ARROW "B"},
    {(const char *)WIRESHARK_STOCK_GRAPH_B_A,             (const char *)WIRESHARK_STOCK_GRAPH_B_A,              (const char *)"Graph A" UTF8_LEFTWARDS_ARROW  "B"},
    {(const char *)WIRESHARK_STOCK_FOLLOW_STREAM,         (const char *)WIRESHARK_STOCK_FOLLOW_STREAM,          (const char *)"Follow Stream"},
    {(const char *)WIRESHARK_STOCK_DISPLAY_FILTER,        (const char *)WIRESHARK_STOCK_DISPLAY_FILTER,         (const char *)"Display _Filter"},
    {(const char *)WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY,  (const char *)WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY,   (const char *)"F_ilter:"},
    {(const char *)WIRESHARK_STOCK_BROWSE,                (const char *)GTK_STOCK_OPEN,                         (const char *)"_Browse..."},
    {(const char *)WIRESHARK_STOCK_CREATE_STAT,           (const char *)GTK_STOCK_OK,                           (const char *)"Create _Stat"},
    {(const char *)WIRESHARK_STOCK_EXPORT,                (const char *)GTK_STOCK_SAVE,                         (const char *)"_Export..."}, /* XXX: needs a better icon */
    {(const char *)WIRESHARK_STOCK_IMPORT,                (const char *)GTK_STOCK_OPEN,                         (const char *)"_Import..."}, /* XXX: needs a better icon */
    {(const char *)WIRESHARK_STOCK_EDIT,                  (const char *)GTK_STOCK_PROPERTIES,                   (const char *)"_Edit..."},
    {(const char *)WIRESHARK_STOCK_ADD_EXPRESSION,        (const char *)GTK_STOCK_ADD,                          (const char *)"E_xpression..." }, /* plus sign coming from icon */
    {(const char *)WIRESHARK_STOCK_CLEAR_EXPRESSION,      (const char *)GTK_STOCK_CLEAR,                        (const char *)"Clea_r" },
    {(const char *)WIRESHARK_STOCK_APPLY_EXPRESSION,      (const char *)GTK_STOCK_APPLY,                        (const char *)"App_ly" },
    {(const char *)WIRESHARK_STOCK_SAVE_ALL,              (const char *)GTK_STOCK_SAVE,                        (const char *)"Save A_ll"}, /* XXX: needs a better icon */
    {(const char *)WIRESHARK_STOCK_DONT_SAVE,             (const char *)GTK_STOCK_CLEAR,                        (const char *)"Continue _without Saving"},
    {(const char *)WIRESHARK_STOCK_QUIT_DONT_SAVE,        (const char *)GTK_STOCK_CLEAR,                        (const char *)"Quit _without Saving"},
    {(const char *)WIRESHARK_STOCK_STOP_DONT_SAVE,        (const char *)GTK_STOCK_CLEAR,                        (const char *)"Stop and Continue _without Saving"},
    {(const char *)WIRESHARK_STOCK_STOP_QUIT_DONT_SAVE,   (const char *)GTK_STOCK_CLEAR,                        (const char *)"Stop and Quit _without Saving"},
    {(const char *)WIRESHARK_STOCK_STOP_SAVE,             (const char *)GTK_STOCK_SAVE,                         (const char *)"Stop and Save"},
    {(const char *)WIRESHARK_STOCK_ABOUT,                 (const char *)WIRESHARK_STOCK_ABOUT,                  (const char *)"_About"},
    {(const char *)WIRESHARK_STOCK_COLORIZE,              (const char *)WIRESHARK_STOCK_COLORIZE,               (const char *)"_Colorize"},
    {(const char *)WIRESHARK_STOCK_AUTOSCROLL,            (const char *)WIRESHARK_STOCK_AUTOSCROLL,             (const char *)"_Auto Scroll"},
    {(const char *)WIRESHARK_STOCK_RESIZE_COLUMNS,        (const char *)WIRESHARK_STOCK_RESIZE_COLUMNS,         (const char *)"Resize Columns"},
    {(const char *)WIRESHARK_STOCK_TIME,                  (const char *)WIRESHARK_STOCK_TIME,                   (const char *)"Time"},
    {(const char *)WIRESHARK_STOCK_INTERNET,              (const char *)WIRESHARK_STOCK_INTERNET,               (const char *)"Internet"},
    {(const char *)WIRESHARK_STOCK_WEB_SUPPORT,           (const char *)WIRESHARK_STOCK_WEB_SUPPORT,            (const char *)"Web Support"},
    {(const char *)WIRESHARK_STOCK_WIKI,                  (const char *)WIRESHARK_STOCK_WIKI,                   (const char *)"Wiki"},
    {(const char *)WIRESHARK_STOCK_CONVERSATIONS,         (const char *)WIRESHARK_STOCK_CONVERSATIONS,          (const char *)"Conversations"},
    {(const char *)WIRESHARK_STOCK_ENDPOINTS,             (const char *)WIRESHARK_STOCK_ENDPOINTS,              (const char *)"Endpoints"},
    {(const char *)WIRESHARK_STOCK_EXPERT_INFO,           (const char *)WIRESHARK_STOCK_EXPERT_INFO,            (const char *)"Expert Info"},
    {(const char *)WIRESHARK_STOCK_GRAPHS,                (const char *)WIRESHARK_STOCK_GRAPHS,                 (const char *)"Graphs"},
    {(const char *)WIRESHARK_STOCK_FLOW_GRAPH,            (const char *)WIRESHARK_STOCK_FLOW_GRAPH,             (const char *)"Flow Graph"},
    {(const char *)WIRESHARK_STOCK_TELEPHONY,             (const char *)WIRESHARK_STOCK_TELEPHONY,              (const char *)"Telephony"},
    {(const char *)WIRESHARK_STOCK_DECODE_AS,             (const char *)WIRESHARK_STOCK_DECODE_AS,              (const char *)"Decode As"},
    {(const char *)WIRESHARK_STOCK_CHECKBOX,              (const char *)WIRESHARK_STOCK_CHECKBOX,               (const char *)"Checkbox"},
    {(const char *)WIRESHARK_STOCK_FILE_SET_LIST,         (const char *)WIRESHARK_STOCK_FILE_SET_LIST,          (const char *)"List Files"},
    {(const char *)WIRESHARK_STOCK_FILE_SET_NEXT,         (const char *)WIRESHARK_STOCK_FILE_SET_NEXT,          (const char *)"Next File"},
    {(const char *)WIRESHARK_STOCK_FILE_SET_PREVIOUS,     (const char *)WIRESHARK_STOCK_FILE_SET_PREVIOUS,      (const char *)"Previous File"},
    {(const char *)WIRESHARK_STOCK_FILTER_OUT_STREAM,     (const char *)WIRESHARK_STOCK_FILTER_OUT_STREAM,      (const char *)"Filter Out This Stream"},
    {(const char *)WIRESHARK_STOCK_ENABLE,                (const char *)WIRESHARK_STOCK_ENABLE,                 (const char *)"Enable"},
    {(const char *)WIRESHARK_STOCK_DISABLE,               (const char *)GTK_STOCK_CLOSE,                        (const char *)"Disable"},
    {(const char *)WIRESHARK_STOCK_COLOR1,                (const char *)WIRESHARK_STOCK_COLOR1,                 (const char *)"Color 1"},
    {(const char *)WIRESHARK_STOCK_COLOR2,                (const char *)WIRESHARK_STOCK_COLOR2,                 (const char *)"Color 2"},
    {(const char *)WIRESHARK_STOCK_COLOR3,                (const char *)WIRESHARK_STOCK_COLOR3,                 (const char *)"Color 3"},
    {(const char *)WIRESHARK_STOCK_COLOR4,                (const char *)WIRESHARK_STOCK_COLOR4,                 (const char *)"Color 4"},
    {(const char *)WIRESHARK_STOCK_COLOR5,                (const char *)WIRESHARK_STOCK_COLOR5,                 (const char *)"Color 5"},
    {(const char *)WIRESHARK_STOCK_COLOR6,                (const char *)WIRESHARK_STOCK_COLOR6,                 (const char *)"Color 6"},
    {(const char *)WIRESHARK_STOCK_COLOR7,                (const char *)WIRESHARK_STOCK_COLOR7,                 (const char *)"Color 7"},
    {(const char *)WIRESHARK_STOCK_COLOR8,                (const char *)WIRESHARK_STOCK_COLOR8,                 (const char *)"Color 8"},
    {(const char *)WIRESHARK_STOCK_COLOR9,                (const char *)WIRESHARK_STOCK_COLOR9,                 (const char *)"Color 9"},
    {(const char *)WIRESHARK_STOCK_COLOR0,                (const char *)WIRESHARK_STOCK_COLOR0,                 (const char *)"Color 10"},
    {(const char *)WIRESHARK_STOCK_DECODE,                (const char *)WIRESHARK_STOCK_DECODE,                 (const char *)"Decode"},
    {(const char *)WIRESHARK_STOCK_AUDIO_PLAYER,          (const char *)WIRESHARK_STOCK_AUDIO_PLAYER,           (const char *)"Player"},
    {(const char *)WIRESHARK_STOCK_VOIP_FLOW,             (const char *)WIRESHARK_STOCK_VOIP_FLOW,              (const char *)"Flow"},
    {(const char *)WIRESHARK_STOCK_TELEPHONE,             (const char *)WIRESHARK_STOCK_TELEPHONE,              (const char *)"Telephone"},
    {(const char *)WIRESHARK_STOCK_PREPARE_FILTER,        (const char *)WIRESHARK_STOCK_PREPARE_FILTER,         (const char *)"Prepare Filter"},
    {(const char *)WIRESHARK_STOCK_ANALYZE,               (const char *)WIRESHARK_STOCK_ANALYZE,                (const char *)"Analyze"},
    {(const char *)WIRESHARK_STOCK_SAVE,                  (const char *)WIRESHARK_STOCK_SAVE,                   (const char *)"Save"}
};

static stock_item_t gtk_stock_items[] = {
    {(const char *)GTK_STOCK_ABOUT,                         (const char *)"help-about",                (const char *)"_About"},
    {(const char *)GTK_STOCK_ADD,                           (const char *)"list-add",                  (const char *)"_Add"},
    {(const char *)GTK_STOCK_APPLY,                         NULL,                                (const char *)"_Apply"},
    {(const char *)GTK_STOCK_BOLD,                          (const char *)"format-text-bold",          (const char *)"_Bold"},
    {(const char *)GTK_STOCK_CANCEL,                        NULL,                                (const char *)"_Cancel"},
#ifdef GTK_STOCK_CAPS_LOCK_WARNING
    {(const char *)GTK_STOCK_CAPS_LOCK_WARNING,             NULL,                                NULL},
#endif
    {(const char *)GTK_STOCK_CDROM,                         (const char *)"media-optical",             (const char *)"_CD-ROM"},
    {(const char *)GTK_STOCK_CLEAR,                         (const char *)"edit-clear",                (const char *)"_Clear"},
    {(const char *)GTK_STOCK_CLOSE,                         (const char *)"window-close",              (const char *)"_Close"},
    {(const char *)GTK_STOCK_COLOR_PICKER,                  NULL,                                NULL},
    {(const char *)GTK_STOCK_CONNECT,                       NULL,                                (const char *)"C_onnect"},
    {(const char *)GTK_STOCK_CONVERT,                       NULL,                                (const char *)"_Convert"},
    {(const char *)GTK_STOCK_COPY,                          (const char *)"edit-copy",                 (const char *)"_Copy"},
    {(const char *)GTK_STOCK_CUT,                           (const char *)"edit-cut",                  (const char *)"Cu_t"},
    {(const char *)GTK_STOCK_DELETE,                        (const char *)"edit-delete",               (const char *)"_Delete"},
    {(const char *)GTK_STOCK_DIALOG_AUTHENTICATION,         (const char *)"dialog-password",           NULL},
    {(const char *)GTK_STOCK_DIALOG_INFO,                   (const char *)"dialog-information",        (const char *)"Information"},
    {(const char *)GTK_STOCK_DIALOG_WARNING,                (const char *)"dialog-warning",            (const char *)"Warning"},
    {(const char *)GTK_STOCK_DIALOG_ERROR,                  (const char *)"dialog-error",              (const char *)"Error"},
    {(const char *)GTK_STOCK_DIALOG_QUESTION,               (const char *)"dialog-question",           (const char *)"Question"},
    {(const char *)GTK_STOCK_DIRECTORY,                     (const char *)"folder",                    NULL},
    {(const char *)GTK_STOCK_DISCARD,                       NULL,                                (const char *)"_Discard"},
    {(const char *)GTK_STOCK_DISCONNECT,                    NULL,                                (const char *)"_Disconnect"},
    {(const char *)GTK_STOCK_DND,                           NULL,                                NULL},
    {(const char *)GTK_STOCK_DND_MULTIPLE,                  NULL,                                NULL},
    {(const char *)GTK_STOCK_EDIT,                          NULL,                                (const char *)"_Edit"},
    {(const char *)GTK_STOCK_EXECUTE,                       (const char *)"system-run",                (const char *)"_Execute"},
    {(const char *)GTK_STOCK_FILE,                          (const char *)"text-x-generic",            (const char *)"_File"},
    {(const char *)GTK_STOCK_FIND,                          (const char *)"edit-find",                 (const char *)"_Find"},
    {(const char *)GTK_STOCK_FIND_AND_REPLACE,              (const char *)"edit-find-replace",         (const char *)"Find     and _Replace"},
    {(const char *)GTK_STOCK_FLOPPY,                        (const char *)"media-floppy",              (const char *)"_Floppy"},
    {(const char *)GTK_STOCK_FULLSCREEN,                    (const char *)"view-fullscreen",           (const char *)"_Fullscreen"},
    {(const char *)GTK_STOCK_GOTO_BOTTOM,                   (const char *)"go-bottom",                 (const char *)"_Bottom"},
    {(const char *)GTK_STOCK_GOTO_FIRST,                    (const char *)"go-first",                  (const char *)"_First"},
    {(const char *)GTK_STOCK_GOTO_LAST,                     (const char *)"go-last",                   (const char *)"_Last"},
    {(const char *)GTK_STOCK_GOTO_TOP,                      (const char *)"go-top",                    (const char *)"_Top"},
    {(const char *)GTK_STOCK_GO_BACK,                       (const char *)"go-previous",               (const char *)"_Back"},
    {(const char *)GTK_STOCK_GO_DOWN,                       (const char *)"go-down",                   (const char *)"_Down"},
    {(const char *)GTK_STOCK_GO_FORWARD,                    (const char *)"go-next",                   (const char *)"_Forward"},
    {(const char *)GTK_STOCK_GO_UP,                         (const char *)"go-up",                     (const char *)"_Up"},
    {(const char *)GTK_STOCK_HARDDISK,                      (const char *)"drive-harddisk",            (const char *)"_Hard    Disk"},
    {(const char *)GTK_STOCK_HELP,                          (const char *)"help-browser",              (const char *)"_Help"},
    {(const char *)GTK_STOCK_HOME,                          (const char *)"go-home",                   (const char *)"_Home"},
    {(const char *)GTK_STOCK_INDEX,                         NULL,                                (const char *)"_Index"},
    {(const char *)GTK_STOCK_INDENT,                        (const char *)"format-indent-more",        (const char *)"Increase Indent"},
    {(const char *)GTK_STOCK_INFO,                          (const char *)"dialog-information",        (const char *)"_Information"},
    {(const char *)GTK_STOCK_ITALIC,                        (const char *)"format-text-italic",        (const char *)"_Italic"},
    {(const char *)GTK_STOCK_JUMP_TO,                       (const char *)"go-jump",                   (const char *)"_Jump    to"},
    {(const char *)GTK_STOCK_JUSTIFY_CENTER,                (const char *)"format-justify-center",     (const char *)"_Center"},
    {(const char *)GTK_STOCK_JUSTIFY_FILL,                  (const char *)"format-justify-fill",       (const char *)"_Fill"},
    {(const char *)GTK_STOCK_JUSTIFY_LEFT,                  (const char *)"format-justify-left",       (const char *)"_Left"},
    {(const char *)GTK_STOCK_JUSTIFY_RIGHT,                 (const char *)"format-justify-right",      (const char *)"_Right"},
    {(const char *)GTK_STOCK_LEAVE_FULLSCREEN,              (const char *)"view-restore",              (const char *)"_Leave   Fullscreen"},
    {(const char *)GTK_STOCK_MISSING_IMAGE,                 (const char *)"image-missing",             NULL},
    {(const char *)GTK_STOCK_MEDIA_FORWARD,                 (const char *)"media-seek-forward",        (const char *)"_Forward"},
    {(const char *)GTK_STOCK_MEDIA_NEXT,                    (const char *)"media-skip-forward",        (const char *)"_Next"},
    {(const char *)GTK_STOCK_MEDIA_PAUSE,                   (const char *)"media-playback-pause",      (const char *)"P_ause"},
    {(const char *)GTK_STOCK_MEDIA_PLAY,                    (const char *)"media-playback-start",      (const char *)"_Play"},
    {(const char *)GTK_STOCK_MEDIA_PREVIOUS,                (const char *)"media-skip-backward",       (const char *)"Pre_vious"},
    {(const char *)GTK_STOCK_MEDIA_RECORD,                  (const char *)"media-record",              (const char *)"_Record"},
    {(const char *)GTK_STOCK_MEDIA_REWIND,                  (const char *)"media-seek-backward",       (const char *)"R_ewind"},
    {(const char *)GTK_STOCK_MEDIA_STOP,                    (const char *)"media-playback-stop",       (const char *)"_Stop"},
    {(const char *)GTK_STOCK_NETWORK,                       (const char *)"network-workgroup",         (const char *)"_Network"},
    {(const char *)GTK_STOCK_NEW,                           (const char *)"document-new",              (const char *)"_New"},
    {(const char *)GTK_STOCK_NO,                            NULL,                                (const char *)"_No"},
    {(const char *)GTK_STOCK_OK,                            NULL,                                (const char *)"_OK"},
    {(const char *)GTK_STOCK_OPEN,                          (const char *)"document-open",             (const char *)"_Open"},
    {(const char *)GTK_STOCK_ORIENTATION_PORTRAIT,          (const char *)"?",                         (const char *)"Portrait"},
    {(const char *)GTK_STOCK_ORIENTATION_LANDSCAPE,         (const char *)"?",                         (const char *)"Landscape"},
    {(const char *)GTK_STOCK_ORIENTATION_REVERSE_LANDSCAPE, (const char *)"?",                         (const char *)"Reverse  landscape"},
    {(const char *)GTK_STOCK_ORIENTATION_REVERSE_PORTRAIT,  (const char *)"?",                         (const char *)"Reverse  portrait"},
#ifdef GTK_STOCK_PAGE_SETUP
    {(const char *)GTK_STOCK_PAGE_SETUP,                    (const char *)"document-page-setup",       (const char *)"Page     Set_up"},
#endif
    {(const char *)GTK_STOCK_PASTE,                         (const char *)"edit-paste",                (const char *)"_Paste"},
    {(const char *)GTK_STOCK_PREFERENCES,                   (const char *)"preferences-system",        (const char *)"_Preferences"},
    {(const char *)GTK_STOCK_PRINT,                         (const char *)"document-print",            (const char *)"_Print"},
#ifdef GTK_STOCK_PRINT_ERROR
    {(const char *)GTK_STOCK_PRINT_ERROR,                   (const char *)"printer-error",             NULL},
#endif
#ifdef GTK_STOCK_PRINT_PAUSED
    {(const char *)GTK_STOCK_PRINT_PAUSED,                  NULL,                                NULL},
#endif
    {(const char *)GTK_STOCK_PRINT_PREVIEW,                 NULL,                                (const char *)"Print Pre_view"},
#ifdef GTK_STOCK_PRINT_REPORT
    {(const char *)GTK_STOCK_PRINT_REPORT,                  NULL,                                NULL},
#endif
#ifdef GTK_STOCK_PRINT_WARNING
    {(const char *)GTK_STOCK_PRINT_WARNING,                 NULL,                                NULL},
#endif
    {(const char *)GTK_STOCK_PROPERTIES,                    (const char *)"document-properties",       (const char *)"_Properties"},
    {(const char *)GTK_STOCK_QUIT,                          (const char *)"application-exit",          (const char *)"_Quit"},
    {(const char *)GTK_STOCK_REDO,                          (const char *)"edit-redo",                 (const char *)"_Redo"},
    {(const char *)GTK_STOCK_REFRESH,                       (const char *)"view-refresh",              (const char *)"_Refresh"},
    {(const char *)GTK_STOCK_REMOVE,                        (const char *)"list-remove",               (const char *)"_Remove"},
    {(const char *)GTK_STOCK_REVERT_TO_SAVED,               (const char *)"document-revert",           (const char *)"_Revert"},
    {(const char *)GTK_STOCK_SAVE,                          (const char *)"document-save",             (const char *)"_Save"},
    {(const char *)GTK_STOCK_SAVE_AS,                       (const char *)"document-save-as",          (const char *)"Save     _As"},
    {(const char *)GTK_STOCK_SELECT_ALL,                    (const char *)"edit-select-all",           (const char *)"Select   _All"},
    {(const char *)GTK_STOCK_SELECT_COLOR,                  NULL,                                (const char *)"_Color"},
    {(const char *)GTK_STOCK_SELECT_FONT,                   NULL,                                (const char *)"_Font"},
    {(const char *)GTK_STOCK_SORT_ASCENDING,                (const char *)"view-sort-ascending",       (const char *)"_Ascending"},
    {(const char *)GTK_STOCK_SORT_DESCENDING,               (const char *)"view-sort-descending",      (const char *)"_Descending"},
    {(const char *)GTK_STOCK_SPELL_CHECK,                   (const char *)"tools-check-spelling",      (const char *)"_Spell   Check"},
    {(const char *)GTK_STOCK_STOP,                          (const char *)"process-stop",              (const char *)"_Stop"},
    {(const char *)GTK_STOCK_STRIKETHROUGH,                 (const char *)"format-text-strikethrough", (const char *)"_Strikethrough"},
    {(const char *)GTK_STOCK_UNDELETE,                      NULL,                                (const char *)"_Undelete"},
    {(const char *)GTK_STOCK_UNDERLINE,                     (const char *)"format-text-underline",     (const char *)"_Underline"},
    {(const char *)GTK_STOCK_UNDO,                          (const char *)"edit-undo",                 (const char *)"_Undo"},
    {(const char *)GTK_STOCK_UNINDENT,                      (const char *)"format-indent-less",        NULL},
    {(const char *)GTK_STOCK_YES,                           NULL,                                (const char *)"_Yes"},
    {(const char *)GTK_STOCK_ZOOM_100,                      (const char *)"zoom-original",             (const char *)"_Normal  Size"},
    {(const char *)GTK_STOCK_ZOOM_FIT,                      (const char *)"zoom-fit-best",             (const char *)"Best     _Fit"},
    {(const char *)GTK_STOCK_ZOOM_IN,                       (const char *)"zoom-in",                   (const char *)"Zoom     _In"},
    {(const char *)GTK_STOCK_ZOOM_OUT,                      (const char *)"zoom-out",                  (const char *)"Zoom     _Out"},
};

/**
 * Compare two stock items by name.
 */
static int si_cmp(const stock_item_t * a, const stock_item_t * b) {
    return strcmp(a->name, b->name);
}


#define BS(item, arr) (stock_item_t *)bsearch((void*)(((char*)&item) - offsetof(stock_item_t, name)), \
                                              (void*)arr, sizeof(arr) / sizeof(arr[0]), sizeof(arr[0]), \
                                              (int (*)(const void *, const void *))si_cmp)

/* generate application specific stock items */
void stock_icons_init(void) {
    guint32 i;
#if !GTK_CHECK_VERSION(3, WS_GTK3_MINOR_STOCK_DEPRECATION_STARTS, 0)
    GtkIconFactory * factory;
    GtkIconSet *icon_set;
    GtkIconSource *source16;
#endif

    static const stock_pixbuf_t pixbufs[] = {
        { WIRESHARK_STOCK_ABOUT,              wsicon_16_pb_data, wsicon_24_pb_data },
        { WIRESHARK_STOCK_CAPTURE_INTERFACES, capture_interfaces_16_pb_data, capture_interfaces_24_pb_data },
        { WIRESHARK_STOCK_CAPTURE_OPTIONS,    capture_options_alt1_16_pb_data, capture_options_alt1_24_pb_data },
        { WIRESHARK_STOCK_CAPTURE_RESTART,    capture_restart_16_pb_data, capture_restart_24_pb_data },
        { WIRESHARK_STOCK_CAPTURE_START,      capture_start_16_pb_data, capture_start_24_pb_data },
        { WIRESHARK_STOCK_CAPTURE_STOP,       capture_stop_16_pb_data, capture_stop_24_pb_data },
        { WIRESHARK_STOCK_SAVE,               toolbar_wireshark_file_16_pb_data, toolbar_wireshark_file_24_pb_data},
        { WIRESHARK_STOCK_WIKI,               gnome_emblem_web_16_pb_data, gnome_emblem_web_24_pb_data },
        { NULL, NULL, NULL }
    };

    /* New images should be PNGs + pixbufs above. Please don't add to this list. */
    static const stock_pixmap_t pixmaps[] = {
        { WIRESHARK_STOCK_CAPTURE_FILTER,       capture_filter_24_xpm,    24},
        { WIRESHARK_STOCK_CAPTURE_FILTER_ENTRY, capture_filter_24_xpm,    24},
        { WIRESHARK_STOCK_CAPTURE_DETAILS,      capture_details_24_xpm,   24},
#ifdef HAVE_GEOIP
        { WIRESHARK_STOCK_MAP,                  internet_24_xpm,          24},
#endif
        { WIRESHARK_STOCK_DISPLAY_FILTER,       display_filter_24_xpm,    24},
        { WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY, display_filter_24_xpm,    24},
        { WIRESHARK_STOCK_COLORIZE,             colorize_24_xpm,          24},
        { WIRESHARK_STOCK_AUTOSCROLL,           autoscroll_24_xpm,        24},
        { WIRESHARK_STOCK_RESIZE_COLUMNS,       resize_columns_24_xpm,    24},
        { WIRESHARK_STOCK_TIME,                 time_24_xpm,              24},
        { WIRESHARK_STOCK_INTERNET,             internet_24_xpm,          24},
        { WIRESHARK_STOCK_WEB_SUPPORT,          web_support_24_xpm,       24},
        { WIRESHARK_STOCK_CONVERSATIONS,        conversations_16_xpm,     16},
        { WIRESHARK_STOCK_ENDPOINTS,            endpoints_16_xpm,         16},
        { WIRESHARK_STOCK_EXPERT_INFO,          expert_info_16_xpm,       16},
        { WIRESHARK_STOCK_GRAPHS,               graphs_16_xpm,            16},
        { WIRESHARK_STOCK_FLOW_GRAPH,           flow_graph_16_xpm,        16},
        { WIRESHARK_STOCK_TELEPHONY,            telephony_16_xpm,         16},
        { WIRESHARK_STOCK_DECODE_AS,            decode_as_16_xpm,         16},
        { WIRESHARK_STOCK_CHECKBOX,             checkbox_16_xpm,          16},
        { WIRESHARK_STOCK_FILE_SET_LIST,        file_set_list_16_xpm,     16},
        { WIRESHARK_STOCK_FILE_SET_NEXT,        file_set_next_16_xpm,     16},
        { WIRESHARK_STOCK_FILE_SET_PREVIOUS,    file_set_previous_16_xpm, 16},
        { WIRESHARK_STOCK_FILTER_OUT_STREAM,    display_filter_24_xpm,    24},
        { WIRESHARK_STOCK_ENABLE,               checkbox_16_xpm,          16},
        { WIRESHARK_STOCK_COLOR1,               icon_color_1_xpm,         24},
        { WIRESHARK_STOCK_COLOR2,               icon_color_2_xpm,         24},
        { WIRESHARK_STOCK_COLOR3,               icon_color_3_xpm,         24},
        { WIRESHARK_STOCK_COLOR4,               icon_color_4_xpm,         24},
        { WIRESHARK_STOCK_COLOR5,               icon_color_5_xpm,         24},
        { WIRESHARK_STOCK_COLOR6,               icon_color_6_xpm,         24},
        { WIRESHARK_STOCK_COLOR7,               icon_color_7_xpm,         24},
        { WIRESHARK_STOCK_COLOR8,               icon_color_8_xpm,         24},
        { WIRESHARK_STOCK_COLOR9,               icon_color_9_xpm,         24},
        { WIRESHARK_STOCK_COLOR0,               icon_color_0_xpm,         24},
        { WIRESHARK_STOCK_DECODE,               decode_24_xpm,            24},
        { WIRESHARK_STOCK_AUDIO_PLAYER,         audio_player_24_xpm,      24},
        { WIRESHARK_STOCK_VOIP_FLOW,            voip_flow_24_xpm,         24},
        { WIRESHARK_STOCK_TELEPHONE,            telephone_16_xpm,         16},
        { WIRESHARK_STOCK_PREPARE_FILTER,       display_filter_24_xpm,    24},
        { WIRESHARK_STOCK_ANALYZE,              analyze_24_xpm,           24},
        { NULL,                                 NULL,                     0}
    };

    /* sort lookup arrays */
    qsort(ws_stock_items, sizeof(ws_stock_items)/sizeof(ws_stock_items[0]),
          sizeof(ws_stock_items[0]), (int (*)(const void *, const void *))si_cmp);
    qsort(gtk_stock_items, sizeof(gtk_stock_items)/sizeof(gtk_stock_items[0]),
          sizeof(gtk_stock_items[0]), (int (*)(const void *, const void *))si_cmp);

#if !GTK_CHECK_VERSION(3, WS_GTK3_MINOR_STOCK_DEPRECATION_STARTS, 0)
    for (i = 0; i < (sizeof(ws_stock_items) / sizeof(ws_stock_items[0])) ; i++) {
        GtkStockItem stock_item =
                {(char *)ws_stock_items[i].name,
                 (char *)ws_stock_items[i].label,
                 (GdkModifierType)0, 0, NULL};
        gtk_stock_add(&stock_item, 1);
    }
    /* Add our custom icon factory to the list of defaults */
    factory = gtk_icon_factory_new();
    gtk_icon_factory_add_default(factory);
#endif

    /* Add pixmaps as builtin theme icons */
    /* Please use pixbufs (below) for new icons */
    for (i = 0; pixmaps[i].name != NULL; i++) {
        /* The default icon */
        GdkPixbuf * pixbuf = gdk_pixbuf_new_from_xpm_data((const char **) (pixmaps[i].xpm_data));
        g_assert(pixbuf);
#if !GTK_CHECK_VERSION(3, WS_GTK3_MINOR_STOCK_DEPRECATION_STARTS, 0)
        icon_set = gtk_icon_set_new_from_pixbuf (pixbuf);
        gtk_icon_factory_add (factory, pixmaps[i].name, icon_set);
        gtk_icon_set_unref (icon_set);
#endif
        gtk_icon_theme_add_builtin_icon(pixmaps[i].name, pixmaps[i].size, pixbuf);
        g_object_unref (G_OBJECT (pixbuf));
    }

    /* Add pixbufs as builtin theme icons */
    for (i = 0; pixbufs[i].name != NULL; i++) {
        GdkPixbuf * pixbuf24 = gdk_pixbuf_new_from_inline(-1, pixbufs[i].pb_data24, FALSE, NULL);
        g_assert(pixbuf24);
#if !GTK_CHECK_VERSION(3, WS_GTK3_MINOR_STOCK_DEPRECATION_STARTS, 0)
        icon_set = gtk_icon_set_new_from_pixbuf(pixbuf24);
        gtk_icon_factory_add (factory, pixbufs[i].name, icon_set);
        gtk_icon_set_unref (icon_set);
#endif
        /* Default image */
        gtk_icon_theme_add_builtin_icon(pixbufs[i].name, 24, pixbuf24);


        if (pixbufs[i].pb_data16) {
            GdkPixbuf * pixbuf16 = gdk_pixbuf_new_from_inline(-1, pixbufs[i].pb_data16, FALSE, NULL);
            g_assert(pixbuf16);
#if !GTK_CHECK_VERSION(3, WS_GTK3_MINOR_STOCK_DEPRECATION_STARTS, 0)
            source16 = gtk_icon_source_new();
            gtk_icon_source_set_pixbuf(source16, pixbuf16);
            gtk_icon_source_set_size_wildcarded(source16, FALSE);
            gtk_icon_source_set_size(source16, GTK_ICON_SIZE_MENU);

            /* Twice? Really? Seriously? */
            source16 = gtk_icon_source_new();
            gtk_icon_source_set_pixbuf(source16, pixbuf16);
            gtk_icon_source_set_size_wildcarded(source16, FALSE);
            gtk_icon_source_set_size(source16, GTK_ICON_SIZE_SMALL_TOOLBAR);
#else
            gtk_icon_theme_add_builtin_icon(pixbufs[i].name, 16, pixbuf16);
#endif
            g_object_unref (G_OBJECT (pixbuf16));
        }
        g_object_unref (G_OBJECT (pixbuf24));
    }
#if !GTK_CHECK_VERSION(3, WS_GTK3_MINOR_STOCK_DEPRECATION_STARTS, 0)
    /* use default stock icons for Wireshark specifics where the icon metapher makes sense */
    /* PLEASE DON'T REUSE STOCK ICONS IF THEY ARE USUALLY USED FOR SOME DIFFERENT MEANING!!!) */

    for (i = 0; i < (sizeof(ws_stock_items) / sizeof(ws_stock_items[0])) ; i++) {
        stock_item_t * fallback_item = NULL;
        if (NULL != (fallback_item = BS(ws_stock_items[i].icon, gtk_stock_items))) {
            icon_set = gtk_icon_factory_lookup_default(fallback_item->name);
            gtk_icon_factory_add(factory, ws_stock_items[i].name, icon_set);
        }
    }
#endif
}

GtkWidget * ws_gtk_button_new_from_stock(const gchar *stock_id) {
#if !GTK_CHECK_VERSION(3, WS_GTK3_MINOR_STOCK_DEPRECATION_STARTS, 0)
        return gtk_button_new_from_stock(stock_id);
#else
    GtkWidget * b;
    stock_item_t * i = NULL;
    if (NULL != (i = BS(stock_id, gtk_stock_items))) {
        /* GTK stock item*/
        return gtk_button_new_with_mnemonic(i->label);
    } else if (NULL != (i = BS(stock_id, ws_stock_items))) {
        /* Wireshark stock item*/
        stock_item_t * fallback_item;
        if (NULL != (fallback_item = BS(i->icon, gtk_stock_items))) {
            /* Wireshark fallback item uses a GTK stock icon*/
            b = gtk_button_new_from_icon_name(fallback_item->icon, GTK_ICON_SIZE_BUTTON);
        } else {
            b = gtk_button_new_from_icon_name(i->icon, GTK_ICON_SIZE_BUTTON);
        }
        gtk_button_set_label(GTK_BUTTON(b), i->label);
        gtk_button_set_use_underline(GTK_BUTTON(b), TRUE);
        return b;
    }
    return NULL;
#endif
}

#define LBL_UNDERLINE(type, tb, lbl_item)                    \
    gtk_tool_button_set_label(type(tb), (lbl_item)->label);  \
    gtk_tool_button_set_use_underline(type(tb), TRUE);

GtkToolItem * ws_gtk_tool_button_new_from_stock(const gchar *stock_id) {
#if !GTK_CHECK_VERSION(3, WS_GTK3_MINOR_STOCK_DEPRECATION_STARTS, 0)
    return gtk_tool_button_new_from_stock(stock_id);
#else
    GtkToolItem * b = NULL;
    stock_item_t * i = NULL;
    if (NULL != (i = BS(stock_id, gtk_stock_items))) {
        /* GTK stock item*/
        b = gtk_tool_button_new(NULL, i->label);
        gtk_tool_button_set_use_underline(GTK_TOOL_BUTTON(b), TRUE);
        gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON (b), i->icon);
    } else if (NULL != (i = BS(stock_id, ws_stock_items))) {
        /* Wireshark stock item*/
        stock_item_t * fallback_item;
        if (NULL != (fallback_item = BS(i->icon, gtk_stock_items))) {
            /* Wireshark fallback item uses a GTK stock icon*/
            b = gtk_tool_button_new(NULL, i->label);
            gtk_tool_button_set_use_underline(GTK_TOOL_BUTTON(b), TRUE);
            gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON(b), fallback_item->icon);
        } else {
            b = gtk_tool_button_new(NULL, i->label);
            gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON(b), i->icon);
        }
    }
    return b;
#endif
}

GtkToolItem * ws_gtk_toggle_tool_button_new_from_stock(const gchar *stock_id) {
#if !GTK_CHECK_VERSION(3, WS_GTK3_MINOR_STOCK_DEPRECATION_STARTS, 0)
    return gtk_toggle_tool_button_new_from_stock(stock_id);
#else
    GtkToolItem * b = NULL;
    stock_item_t * i = NULL;
    if (NULL != (i = BS(stock_id, gtk_stock_items))) {
        /* GTK stock item*/
        b = gtk_toggle_tool_button_new();
        gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON (b), i->icon);
        LBL_UNDERLINE(GTK_TOOL_BUTTON, b, i);
    } else if (NULL != (i = BS(stock_id, ws_stock_items))) {
        /* Wireshark stock item*/
        stock_item_t * fallback_item;
        if (NULL != (fallback_item = BS(i->icon, gtk_stock_items))) {
            /* Wireshark fallback item uses a GTK stock icon*/
            b = gtk_toggle_tool_button_new();
            gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON (b), fallback_item->icon);
            LBL_UNDERLINE(GTK_TOOL_BUTTON, b, i);
        } else {
            b = gtk_toggle_tool_button_new();
            gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON (b), i->icon);
            LBL_UNDERLINE(GTK_TOOL_BUTTON, b, i);
        }
    }
    return b;
#endif
}

GtkWidget * ws_gtk_image_new_from_stock(const gchar *stock_id, GtkIconSize size) {
#if !GTK_CHECK_VERSION(3, WS_GTK3_MINOR_STOCK_DEPRECATION_STARTS, 0)
        return gtk_image_new_from_stock(stock_id, size);
#else
    stock_item_t * i = NULL;
    if (NULL != (i = BS(stock_id, gtk_stock_items))) {
        /* GTK stock item*/
        return gtk_image_new_from_icon_name(i->icon, size);
    } else if (NULL != (i = BS(stock_id, ws_stock_items))) {
        /* Wireshark stock item*/
        stock_item_t * fallback_item;
        if (NULL != (fallback_item = BS(i->icon, gtk_stock_items))) {
            /* Wireshark fallback item uses a GTK stock icon*/
            return gtk_image_new_from_icon_name(fallback_item->icon, size);
        } else {
            return gtk_image_new_from_icon_name(i->icon, size);
        }
    }
    return NULL;
#endif
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
