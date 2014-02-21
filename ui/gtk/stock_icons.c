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
    {(char *)WIRESHARK_STOCK_CAPTURE_INTERFACES,    (char *)WIRESHARK_STOCK_CAPTURE_INTERFACES,     (char *)"_Interfaces"},
    {(char *)WIRESHARK_STOCK_CAPTURE_OPTIONS,       (char *)WIRESHARK_STOCK_CAPTURE_OPTIONS,        (char *)"_Options"},
    {(char *)WIRESHARK_STOCK_CAPTURE_START,         (char *)WIRESHARK_STOCK_CAPTURE_START,          (char *)"_Start"},
    {(char *)WIRESHARK_STOCK_CAPTURE_STOP,          (char *)WIRESHARK_STOCK_CAPTURE_STOP,           (char *)"S_top"},
    {(char *)WIRESHARK_STOCK_CAPTURE_RESTART,       (char *)WIRESHARK_STOCK_CAPTURE_RESTART,        (char *)"_Restart"},
    {(char *)WIRESHARK_STOCK_CAPTURE_FILTER,        (char *)WIRESHARK_STOCK_CAPTURE_FILTER,         (char *)"_Capture Filter"},
    {(char *)WIRESHARK_STOCK_CAPTURE_FILTER_ENTRY,  (char *)WIRESHARK_STOCK_CAPTURE_FILTER_ENTRY,   (char *)"_Capture Filter:"},
    {(char *)WIRESHARK_STOCK_CAPTURE_DETAILS,       (char *)WIRESHARK_STOCK_CAPTURE_DETAILS,        (char *)"_Details"},
    #ifdef HAVE_GEOIP
    {(char *)WIRESHARK_STOCK_MAP,                   (char *)WIRESHARK_STOCK_MAP,                    (char *)"Map"},
    #endif
    {(char *)WIRESHARK_STOCK_GRAPH_A_B,             (char *)WIRESHARK_STOCK_GRAPH_A_B,              (char *)"Graph A" UTF8_RIGHTWARDS_ARROW "B"},
    {(char *)WIRESHARK_STOCK_GRAPH_B_A,             (char *)WIRESHARK_STOCK_GRAPH_B_A,              (char *)"Graph A" UTF8_LEFTWARDS_ARROW  "B"},
    {(char *)WIRESHARK_STOCK_FOLLOW_STREAM,         (char *)WIRESHARK_STOCK_FOLLOW_STREAM,          (char *)"Follow Stream"},
    {(char *)WIRESHARK_STOCK_DISPLAY_FILTER,        (char *)WIRESHARK_STOCK_DISPLAY_FILTER,         (char *)"Display _Filter"},
    {(char *)WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY,  (char *)WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY,   (char *)"F_ilter:"},
    {(char *)WIRESHARK_STOCK_BROWSE,                (char *)GTK_STOCK_OPEN,                         (char *)"_Browse..."},
    {(char *)WIRESHARK_STOCK_CREATE_STAT,           (char *)GTK_STOCK_OK,                           (char *)"Create _Stat"},
    {(char *)WIRESHARK_STOCK_EXPORT,                (char *)GTK_STOCK_SAVE,                         (char *)"_Export..."}, /* XXX: needs a better icon */
    {(char *)WIRESHARK_STOCK_IMPORT,                (char *)GTK_STOCK_OPEN,                         (char *)"_Import..."}, /* XXX: needs a better icon */
    {(char *)WIRESHARK_STOCK_EDIT,                  (char *)GTK_STOCK_PROPERTIES,                   (char *)"_Edit..."},
    {(char *)WIRESHARK_STOCK_ADD_EXPRESSION,        (char *)GTK_STOCK_ADD,                          (char *)"E_xpression..." }, /* plus sign coming from icon */
    {(char *)WIRESHARK_STOCK_CLEAR_EXPRESSION,      (char *)GTK_STOCK_CLEAR,                        (char *)"Clea_r" },
    {(char *)WIRESHARK_STOCK_APPLY_EXPRESSION,      (char *)GTK_STOCK_APPLY,                        (char *)"App_ly" },
    {(char *)WIRESHARK_STOCK_SAVE_ALL,              (char *)GTK_STOCK_SAVE,                        (char *)"Save A_ll"}, /* XXX: needs a better icon */
    {(char *)WIRESHARK_STOCK_DONT_SAVE,             (char *)GTK_STOCK_CLEAR,                        (char *)"Continue _without Saving"},
    {(char *)WIRESHARK_STOCK_QUIT_DONT_SAVE,        (char *)GTK_STOCK_CLEAR,                        (char *)"Quit _without Saving"},
    {(char *)WIRESHARK_STOCK_STOP_DONT_SAVE,        (char *)GTK_STOCK_CLEAR,                        (char *)"Stop and Continue _without Saving"},
    {(char *)WIRESHARK_STOCK_STOP_QUIT_DONT_SAVE,   (char *)GTK_STOCK_CLEAR,                        (char *)"Stop and Quit _without Saving"},
    {(char *)WIRESHARK_STOCK_STOP_SAVE,             (char *)GTK_STOCK_SAVE,                         (char *)"Stop and Save"},
    {(char *)WIRESHARK_STOCK_ABOUT,                 (char *)WIRESHARK_STOCK_ABOUT,                  (char *)"_About"},
    {(char *)WIRESHARK_STOCK_COLORIZE,              (char *)WIRESHARK_STOCK_COLORIZE,               (char *)"_Colorize"},
    {(char *)WIRESHARK_STOCK_AUTOSCROLL,            (char *)WIRESHARK_STOCK_AUTOSCROLL,             (char *)"_Auto Scroll"},
    {(char *)WIRESHARK_STOCK_RESIZE_COLUMNS,        (char *)WIRESHARK_STOCK_RESIZE_COLUMNS,         (char *)"Resize Columns"},
    {(char *)WIRESHARK_STOCK_TIME,                  (char *)WIRESHARK_STOCK_TIME,                   (char *)"Time"},
    {(char *)WIRESHARK_STOCK_INTERNET,              (char *)WIRESHARK_STOCK_INTERNET,               (char *)"Internet"},
    {(char *)WIRESHARK_STOCK_WEB_SUPPORT,           (char *)WIRESHARK_STOCK_WEB_SUPPORT,            (char *)"Web Support"},
    {(char *)WIRESHARK_STOCK_WIKI,                  (char *)WIRESHARK_STOCK_WIKI,                   (char *)"Wiki"},
    {(char *)WIRESHARK_STOCK_CONVERSATIONS,         (char *)WIRESHARK_STOCK_CONVERSATIONS,          (char *)"Conversations"},
    {(char *)WIRESHARK_STOCK_ENDPOINTS,             (char *)WIRESHARK_STOCK_ENDPOINTS,              (char *)"Endpoints"},
    {(char *)WIRESHARK_STOCK_EXPERT_INFO,           (char *)WIRESHARK_STOCK_EXPERT_INFO,            (char *)"Expert Info"},
    {(char *)WIRESHARK_STOCK_GRAPHS,                (char *)WIRESHARK_STOCK_GRAPHS,                 (char *)"Graphs"},
    {(char *)WIRESHARK_STOCK_FLOW_GRAPH,            (char *)WIRESHARK_STOCK_FLOW_GRAPH,             (char *)"Flow Graph"},
    {(char *)WIRESHARK_STOCK_TELEPHONY,             (char *)WIRESHARK_STOCK_TELEPHONY,              (char *)"Telephony"},
    {(char *)WIRESHARK_STOCK_DECODE_AS,             (char *)WIRESHARK_STOCK_DECODE_AS,              (char *)"Decode As"},
    {(char *)WIRESHARK_STOCK_CHECKBOX,              (char *)WIRESHARK_STOCK_CHECKBOX,               (char *)"Checkbox"},
    {(char *)WIRESHARK_STOCK_FILE_SET_LIST,         (char *)WIRESHARK_STOCK_FILE_SET_LIST,          (char *)"List Files"},
    {(char *)WIRESHARK_STOCK_FILE_SET_NEXT,         (char *)WIRESHARK_STOCK_FILE_SET_NEXT,          (char *)"Next File"},
    {(char *)WIRESHARK_STOCK_FILE_SET_PREVIOUS,     (char *)WIRESHARK_STOCK_FILE_SET_PREVIOUS,      (char *)"Previous File"},
    {(char *)WIRESHARK_STOCK_FILTER_OUT_STREAM,     (char *)WIRESHARK_STOCK_FILTER_OUT_STREAM,      (char *)"Filter Out This Stream"},
    {(char *)WIRESHARK_STOCK_ENABLE,                (char *)WIRESHARK_STOCK_ENABLE,                 (char *)"Enable"},
    {(char *)WIRESHARK_STOCK_DISABLE,               (char *)GTK_STOCK_CLOSE,                        (char *)"Disable"},
    {(char *)WIRESHARK_STOCK_COLOR1,                (char *)WIRESHARK_STOCK_COLOR1,                 (char *)"Color 1"},
    {(char *)WIRESHARK_STOCK_COLOR2,                (char *)WIRESHARK_STOCK_COLOR2,                 (char *)"Color 2"},
    {(char *)WIRESHARK_STOCK_COLOR3,                (char *)WIRESHARK_STOCK_COLOR3,                 (char *)"Color 3"},
    {(char *)WIRESHARK_STOCK_COLOR4,                (char *)WIRESHARK_STOCK_COLOR4,                 (char *)"Color 4"},
    {(char *)WIRESHARK_STOCK_COLOR5,                (char *)WIRESHARK_STOCK_COLOR5,                 (char *)"Color 5"},
    {(char *)WIRESHARK_STOCK_COLOR6,                (char *)WIRESHARK_STOCK_COLOR6,                 (char *)"Color 6"},
    {(char *)WIRESHARK_STOCK_COLOR7,                (char *)WIRESHARK_STOCK_COLOR7,                 (char *)"Color 7"},
    {(char *)WIRESHARK_STOCK_COLOR8,                (char *)WIRESHARK_STOCK_COLOR8,                 (char *)"Color 8"},
    {(char *)WIRESHARK_STOCK_COLOR9,                (char *)WIRESHARK_STOCK_COLOR9,                 (char *)"Color 9"},
    {(char *)WIRESHARK_STOCK_COLOR0,                (char *)WIRESHARK_STOCK_COLOR0,                 (char *)"Color 10"},
    {(char *)WIRESHARK_STOCK_DECODE,                (char *)WIRESHARK_STOCK_DECODE,                 (char *)"Decode"},
    {(char *)WIRESHARK_STOCK_AUDIO_PLAYER,          (char *)WIRESHARK_STOCK_AUDIO_PLAYER,           (char *)"Player"},
    {(char *)WIRESHARK_STOCK_VOIP_FLOW,             (char *)WIRESHARK_STOCK_VOIP_FLOW,              (char *)"Flow"},
    {(char *)WIRESHARK_STOCK_TELEPHONE,             (char *)WIRESHARK_STOCK_TELEPHONE,              (char *)"Telephone"},
    {(char *)WIRESHARK_STOCK_PREPARE_FILTER,        (char *)WIRESHARK_STOCK_PREPARE_FILTER,         (char *)"Prepare Filter"},
    {(char *)WIRESHARK_STOCK_ANALYZE,               (char *)WIRESHARK_STOCK_ANALYZE,                (char *)"Analyze"},
    {(char *)WIRESHARK_STOCK_SAVE,                  (char *)WIRESHARK_STOCK_SAVE,                   (char *)"Save"}
};

static stock_item_t gtk_stock_items[] = {
    {(char *)GTK_STOCK_ABOUT,                         (char *)"help-about",                (char *)"_About"},
    {(char *)GTK_STOCK_ADD,                           (char *)"list-add",                  (char *)"_Add"},
    {(char *)GTK_STOCK_APPLY,                         NULL,                                (char *)"_Apply"},
    {(char *)GTK_STOCK_BOLD,                          (char *)"format-text-bold",          (char *)"_Bold"},
    {(char *)GTK_STOCK_CANCEL,                        NULL,                                (char *)"_Cancel"},
    {(char *)GTK_STOCK_CAPS_LOCK_WARNING,             NULL,                                NULL},
    {(char *)GTK_STOCK_CDROM,                         (char *)"media-optical",             (char *)"_CD-ROM"},
    {(char *)GTK_STOCK_CLEAR,                         (char *)"edit-clear",                (char *)"_Clear"},
    {(char *)GTK_STOCK_CLOSE,                         (char *)"window-close",              (char *)"_Close"},
    {(char *)GTK_STOCK_COLOR_PICKER,                  NULL,                                NULL},
    {(char *)GTK_STOCK_CONNECT,                       NULL,                                (char *)"C_onnect"},
    {(char *)GTK_STOCK_CONVERT,                       NULL,                                (char *)"_Convert"},
    {(char *)GTK_STOCK_COPY,                          (char *)"edit-copy",                 (char *)"_Copy"},
    {(char *)GTK_STOCK_CUT,                           (char *)"edit-cut",                  (char *)"Cu_t"},
    {(char *)GTK_STOCK_DELETE,                        (char *)"edit-delete",               (char *)"_Delete"},
    {(char *)GTK_STOCK_DIALOG_AUTHENTICATION,         (char *)"dialog-password",           NULL},
    {(char *)GTK_STOCK_DIALOG_INFO,                   (char *)"dialog-information",        (char *)"Information"},
    {(char *)GTK_STOCK_DIALOG_WARNING,                (char *)"dialog-warning",            (char *)"Warning"},
    {(char *)GTK_STOCK_DIALOG_ERROR,                  (char *)"dialog-error",              (char *)"Error"},
    {(char *)GTK_STOCK_DIALOG_QUESTION,               (char *)"dialog-question",           (char *)"Question"},
    {(char *)GTK_STOCK_DIRECTORY,                     (char *)"folder",                    NULL},
    {(char *)GTK_STOCK_DISCARD,                       NULL,                                (char *)"_Discard"},
    {(char *)GTK_STOCK_DISCONNECT,                    NULL,                                (char *)"_Disconnect"},
    {(char *)GTK_STOCK_DND,                           NULL,                                NULL},
    {(char *)GTK_STOCK_DND_MULTIPLE,                  NULL,                                NULL},
    {(char *)GTK_STOCK_EDIT,                          NULL,                                (char *)"_Edit"},
    {(char *)GTK_STOCK_EXECUTE,                       (char *)"system-run",                (char *)"_Execute"},
    {(char *)GTK_STOCK_FILE,                          (char *)"text-x-generic",            (char *)"_File"},
    {(char *)GTK_STOCK_FIND,                          (char *)"edit-find",                 (char *)"_Find"},
    {(char *)GTK_STOCK_FIND_AND_REPLACE,              (char *)"edit-find-replace",         (char *)"Find     and _Replace"},
    {(char *)GTK_STOCK_FLOPPY,                        (char *)"media-floppy",              (char *)"_Floppy"},
    {(char *)GTK_STOCK_FULLSCREEN,                    (char *)"view-fullscreen",           (char *)"_Fullscreen"},
    {(char *)GTK_STOCK_GOTO_BOTTOM,                   (char *)"go-bottom",                 (char *)"_Bottom"},
    {(char *)GTK_STOCK_GOTO_FIRST,                    (char *)"go-first",                  (char *)"_First"},
    {(char *)GTK_STOCK_GOTO_LAST,                     (char *)"go-last",                   (char *)"_Last"},
    {(char *)GTK_STOCK_GOTO_TOP,                      (char *)"go-top",                    (char *)"_Top"},
    {(char *)GTK_STOCK_GO_BACK,                       (char *)"go-previous",               (char *)"_Back"},
    {(char *)GTK_STOCK_GO_DOWN,                       (char *)"go-down",                   (char *)"_Down"},
    {(char *)GTK_STOCK_GO_FORWARD,                    (char *)"go-next",                   (char *)"_Forward"},
    {(char *)GTK_STOCK_GO_UP,                         (char *)"go-up",                     (char *)"_Up"},
    {(char *)GTK_STOCK_HARDDISK,                      (char *)"drive-harddisk",            (char *)"_Hard    Disk"},
    {(char *)GTK_STOCK_HELP,                          (char *)"help-browser",              (char *)"_Help"},
    {(char *)GTK_STOCK_HOME,                          (char *)"go-home",                   (char *)"_Home"},
    {(char *)GTK_STOCK_INDEX,                         NULL,                                (char *)"_Index"},
    {(char *)GTK_STOCK_INDENT,                        (char *)"format-indent-more",        (char *)"Increase Indent"},
    {(char *)GTK_STOCK_INFO,                          (char *)"dialog-information",        (char *)"_Information"},
    {(char *)GTK_STOCK_ITALIC,                        (char *)"format-text-italic",        (char *)"_Italic"},
    {(char *)GTK_STOCK_JUMP_TO,                       (char *)"go-jump",                   (char *)"_Jump    to"},
    {(char *)GTK_STOCK_JUSTIFY_CENTER,                (char *)"format-justify-center",     (char *)"_Center"},
    {(char *)GTK_STOCK_JUSTIFY_FILL,                  (char *)"format-justify-fill",       (char *)"_Fill"},
    {(char *)GTK_STOCK_JUSTIFY_LEFT,                  (char *)"format-justify-left",       (char *)"_Left"},
    {(char *)GTK_STOCK_JUSTIFY_RIGHT,                 (char *)"format-justify-right",      (char *)"_Right"},
    {(char *)GTK_STOCK_LEAVE_FULLSCREEN,              (char *)"view-restore",              (char *)"_Leave   Fullscreen"},
    {(char *)GTK_STOCK_MISSING_IMAGE,                 (char *)"image-missing",             NULL},
    {(char *)GTK_STOCK_MEDIA_FORWARD,                 (char *)"media-seek-forward",        (char *)"_Forward"},
    {(char *)GTK_STOCK_MEDIA_NEXT,                    (char *)"media-skip-forward",        (char *)"_Next"},
    {(char *)GTK_STOCK_MEDIA_PAUSE,                   (char *)"media-playback-pause",      (char *)"P_ause"},
    {(char *)GTK_STOCK_MEDIA_PLAY,                    (char *)"media-playback-start",      (char *)"_Play"},
    {(char *)GTK_STOCK_MEDIA_PREVIOUS,                (char *)"media-skip-backward",       (char *)"Pre_vious"},
    {(char *)GTK_STOCK_MEDIA_RECORD,                  (char *)"media-record",              (char *)"_Record"},
    {(char *)GTK_STOCK_MEDIA_REWIND,                  (char *)"media-seek-backward",       (char *)"R_ewind"},
    {(char *)GTK_STOCK_MEDIA_STOP,                    (char *)"media-playback-stop",       (char *)"_Stop"},
    {(char *)GTK_STOCK_NETWORK,                       (char *)"network-workgroup",         (char *)"_Network"},
    {(char *)GTK_STOCK_NEW,                           (char *)"document-new",              (char *)"_New"},
    {(char *)GTK_STOCK_NO,                            NULL,                                (char *)"_No"},
    {(char *)GTK_STOCK_OK,                            NULL,                                (char *)"_OK"},
    {(char *)GTK_STOCK_OPEN,                          (char *)"document-open",             (char *)"_Open"},
    {(char *)GTK_STOCK_ORIENTATION_PORTRAIT,          (char *)"?",                         (char *)"Portrait"},
    {(char *)GTK_STOCK_ORIENTATION_LANDSCAPE,         (char *)"?",                         (char *)"Landscape"},
    {(char *)GTK_STOCK_ORIENTATION_REVERSE_LANDSCAPE, (char *)"?",                         (char *)"Reverse  landscape"},
    {(char *)GTK_STOCK_ORIENTATION_REVERSE_PORTRAIT,  (char *)"?",                         (char *)"Reverse  portrait"},
    {(char *)GTK_STOCK_PAGE_SETUP,                    (char *)"document-page-setup",       (char *)"Page     Set_up"},
    {(char *)GTK_STOCK_PASTE,                         (char *)"edit-paste",                (char *)"_Paste"},
    {(char *)GTK_STOCK_PREFERENCES,                   (char *)"preferences-system",        (char *)"_Preferences"},
    {(char *)GTK_STOCK_PRINT,                         (char *)"document-print",            (char *)"_Print"},
    {(char *)GTK_STOCK_PRINT_ERROR,                   (char *)"printer-error",             NULL},
    {(char *)GTK_STOCK_PRINT_PAUSED,                  NULL,                                NULL},
    {(char *)GTK_STOCK_PRINT_PREVIEW,                 NULL,                                (char *)"Print Pre_view"},
    {(char *)GTK_STOCK_PRINT_REPORT,                  NULL,                                NULL},
    {(char *)GTK_STOCK_PRINT_WARNING,                 NULL,                                NULL},
    {(char *)GTK_STOCK_PROPERTIES,                    (char *)"document-properties",       (char *)"_Properties"},
    {(char *)GTK_STOCK_QUIT,                          (char *)"application-exit",          (char *)"_Quit"},
    {(char *)GTK_STOCK_REDO,                          (char *)"edit-redo",                 (char *)"_Redo"},
    {(char *)GTK_STOCK_REFRESH,                       (char *)"view-refresh",              (char *)"_Refresh"},
    {(char *)GTK_STOCK_REMOVE,                        (char *)"list-remove",               (char *)"_Remove"},
    {(char *)GTK_STOCK_REVERT_TO_SAVED,               (char *)"document-revert",           (char *)"_Revert"},
    {(char *)GTK_STOCK_SAVE,                          (char *)"document-save",             (char *)"_Save"},
    {(char *)GTK_STOCK_SAVE_AS,                       (char *)"document-save-as",          (char *)"Save     _As"},
    {(char *)GTK_STOCK_SELECT_ALL,                    (char *)"edit-select-all",           (char *)"Select   _All"},
    {(char *)GTK_STOCK_SELECT_COLOR,                  NULL,                                (char *)"_Color"},
    {(char *)GTK_STOCK_SELECT_FONT,                   NULL,                                (char *)"_Font"},
    {(char *)GTK_STOCK_SORT_ASCENDING,                (char *)"view-sort-ascending",       (char *)"_Ascending"},
    {(char *)GTK_STOCK_SORT_DESCENDING,               (char *)"view-sort-descending",      (char *)"_Descending"},
    {(char *)GTK_STOCK_SPELL_CHECK,                   (char *)"tools-check-spelling",      (char *)"_Spell   Check"},
    {(char *)GTK_STOCK_STOP,                          (char *)"process-stop",              (char *)"_Stop"},
    {(char *)GTK_STOCK_STRIKETHROUGH,                 (char *)"format-text-strikethrough", (char *)"_Strikethrough"},
    {(char *)GTK_STOCK_UNDELETE,                      NULL,                                (char *)"_Undelete"},
    {(char *)GTK_STOCK_UNDERLINE,                     (char *)"format-text-underline",     (char *)"_Underline"},
    {(char *)GTK_STOCK_UNDO,                          (char *)"edit-undo",                 (char *)"_Undo"},
    {(char *)GTK_STOCK_UNINDENT,                      (char *)"format-indent-less",        NULL},
    {(char *)GTK_STOCK_YES,                           NULL,                                (char *)"_Yes"},
    {(char *)GTK_STOCK_ZOOM_100,                      (char *)"zoom-original",             (char *)"_Normal  Size"},
    {(char *)GTK_STOCK_ZOOM_FIT,                      (char *)"zoom-fit-best",             (char *)"Best     _Fit"},
    {(char *)GTK_STOCK_ZOOM_IN,                       (char *)"zoom-in",                   (char *)"Zoom     _In"},
    {(char *)GTK_STOCK_ZOOM_OUT,                      (char *)"zoom-out",                  (char *)"Zoom     _Out"},
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
#if !GTK_CHECK_VERSION(3, 10, 0)
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

#if !GTK_CHECK_VERSION(3, 10, 0)
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
#if !GTK_CHECK_VERSION(3, 10, 0)
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
#if !GTK_CHECK_VERSION(3, 10, 0)
        icon_set = gtk_icon_set_new_from_pixbuf(pixbuf24);
        gtk_icon_factory_add (factory, pixbufs[i].name, icon_set);
        gtk_icon_set_unref (icon_set);
#endif
        /* Default image */
        gtk_icon_theme_add_builtin_icon(pixbufs[i].name, 24, pixbuf24);


        if (pixbufs[i].pb_data16) {
            GdkPixbuf * pixbuf16 = gdk_pixbuf_new_from_inline(-1, pixbufs[i].pb_data16, FALSE, NULL);
            g_assert(pixbuf16);
#if !GTK_CHECK_VERSION(3, 10, 0)
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
#if !GTK_CHECK_VERSION(3, 10, 0)
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
#if !GTK_CHECK_VERSION(3, 10, 0)
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
#if !GTK_CHECK_VERSION(3, 10, 0)
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
#if !GTK_CHECK_VERSION(3, 10, 0)
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
#if !GTK_CHECK_VERSION(3, 10, 0)
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
