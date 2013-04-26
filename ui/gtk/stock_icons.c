/* stock_icons.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <gtk/gtk.h>

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

#define NO_MOD (GdkModifierType)0

typedef struct stock_pixmap_tag{
    const char *    name;
    const char **   xpm_data;
} stock_pixmap_t;

typedef struct stock_pixbuf_tag{
    const char    * name;
    const guint8 * pb_data16; /* Optional */
    const guint8 * pb_data24; /* Mandatory */
} stock_pixbuf_t;

/* generate application specific stock items */
void stock_icons_init(void) {
    GtkIconFactory * factory;
    gint32 i;
    GdkPixbuf * pixbuf;
    GtkIconSet *icon_set;


    /* register non-standard pixmaps with the gtk-stock engine */
    static const GtkStockItem stock_items[] = {
        { (char *)WIRESHARK_STOCK_CAPTURE_INTERFACES,    (char *)"_Interfaces",    NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_CAPTURE_OPTIONS,       (char *)"_Options",       NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_CAPTURE_START,         (char *)"_Start",         NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_CAPTURE_STOP,          (char *)"S_top",          NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_CAPTURE_RESTART,       (char *)"_Restart",       NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_CAPTURE_FILTER,        (char *)"_Capture Filter",   NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_CAPTURE_FILTER_ENTRY,  (char *)"_Capture Filter:",  NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_CAPTURE_DETAILS,       (char *)"_Details",       NO_MOD, 0, NULL },
#ifdef HAVE_GEOIP
        { (char *)WIRESHARK_STOCK_MAP,                   (char *)"Map",                   NO_MOD, 0, NULL },
#endif
        { (char *)WIRESHARK_STOCK_GRAPH_A_B,             (char *)"Graph A" UTF8_RIGHTWARDS_ARROW "B", NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_GRAPH_B_A,             (char *)"Graph B" UTF8_RIGHTWARDS_ARROW "A", NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_FOLLOW_STREAM,         (char *)"Follow Stream",         NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_DISPLAY_FILTER,        (char *)"Display _Filter",       NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY,  (char *)"F_ilter:",  NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_BROWSE,                (char *)"_Browse...",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_CREATE_STAT,           (char *)"Create _Stat",           NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_EXPORT,                (char *)"_Export...",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_IMPORT,                (char *)"_Import...",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_EDIT,                  (char *)"_Edit...",                  NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_ADD_EXPRESSION,        (char *)"E_xpression..." ,        NO_MOD, 0, NULL }, /* plus sign coming from icon */
        { (char *)WIRESHARK_STOCK_CLEAR_EXPRESSION,      (char *)"Clea_r" ,                   NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_APPLY_EXPRESSION,      (char *)"App_ly" ,                   NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_SAVE_ALL,              (char *)"Save A_ll",             NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_DONT_SAVE,             (char *)"Continue _without Saving",             NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_QUIT_DONT_SAVE,        (char *)"Quit _without Saving",             NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_STOP_DONT_SAVE,        (char *)"Stop and Continue _without Saving",             NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_STOP_QUIT_DONT_SAVE,   (char *)"Stop and Quit _without Saving",             NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_STOP_SAVE,             (char *)"Stop and Save",             NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_ABOUT,                 (char *)"_About",                 NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_COLORIZE,              (char *)"_Colorize",              NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_AUTOSCROLL,            (char *)"_Auto Scroll",            NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_RESIZE_COLUMNS,        (char *)"Resize Columns",        NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_TIME,                  (char *)"Time",                  NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_INTERNET,              (char *)"Internet",              NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_WEB_SUPPORT,           (char *)"Web Support",           NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_WIKI,                  (char *)"Wiki",                  NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_CONVERSATIONS,         (char *)"Conversations",         NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_ENDPOINTS,             (char *)"Endpoints",             NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_EXPERT_INFO,           (char *)"Expert Info",           NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_GRAPHS,                (char *)"Graphs",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_FLOW_GRAPH,            (char *)"Flow Graph",            NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_TELEPHONY,             (char *)"Telephony",             NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_DECODE_AS,             (char *)"Decode As",             NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_CHECKBOX,              (char *)"Checkbox",              NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_FILE_SET_LIST,         (char *)"List Files",         NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_FILE_SET_NEXT,         (char *)"Next File",         NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_FILE_SET_PREVIOUS,     (char *)"Previous File",     NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_FILTER_OUT_STREAM,     (char *)"Filter Out This Stream",     NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_ENABLE,                (char *)"Enable",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_DISABLE,               (char *)"Disable",               NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_COLOR1,                (char *)"Color 1",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_COLOR2,                (char *)"Color 2",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_COLOR3,                (char *)"Color 3",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_COLOR4,                (char *)"Color 4",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_COLOR5,                (char *)"Color 5",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_COLOR6,                (char *)"Color 6",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_COLOR7,                (char *)"Color 7",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_COLOR8,                (char *)"Color 8",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_COLOR9,                (char *)"Color 9",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_COLOR0,                (char *)"Color 10",               NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_DECODE,                (char *)"Decode",                 NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_AUDIO_PLAYER,          (char *)"Player",                 NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_VOIP_FLOW,             (char *)"Flow",                   NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_TELEPHONE,             (char *)"Telephone",              NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_PREPARE_FILTER,        (char *)"Prepare Filter",         NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_ANALYZE,               (char *)"Analyze",                NO_MOD, 0, NULL },
        { (char *)WIRESHARK_STOCK_SAVE,                  (char *)"Save",                   NO_MOD, 0, NULL }
    };

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
        { WIRESHARK_STOCK_CAPTURE_FILTER,        capture_filter_24_xpm },
        { WIRESHARK_STOCK_CAPTURE_FILTER_ENTRY,  capture_filter_24_xpm },
        { WIRESHARK_STOCK_CAPTURE_DETAILS,       capture_details_24_xpm },
#ifdef HAVE_GEOIP
        { WIRESHARK_STOCK_MAP,                   internet_24_xpm},
#endif
        { WIRESHARK_STOCK_DISPLAY_FILTER,        display_filter_24_xpm },
        { WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY,  display_filter_24_xpm },
        { WIRESHARK_STOCK_COLORIZE,              colorize_24_xpm },
        { WIRESHARK_STOCK_AUTOSCROLL,            autoscroll_24_xpm },
        { WIRESHARK_STOCK_RESIZE_COLUMNS,        resize_columns_24_xpm},
        { WIRESHARK_STOCK_TIME,                  time_24_xpm},
        { WIRESHARK_STOCK_INTERNET,              internet_24_xpm},
        { WIRESHARK_STOCK_WEB_SUPPORT,           web_support_24_xpm},
        { WIRESHARK_STOCK_CONVERSATIONS,         conversations_16_xpm},
        { WIRESHARK_STOCK_ENDPOINTS,             endpoints_16_xpm},
        { WIRESHARK_STOCK_EXPERT_INFO,           expert_info_16_xpm},
        { WIRESHARK_STOCK_GRAPHS,                graphs_16_xpm},
        { WIRESHARK_STOCK_FLOW_GRAPH,            flow_graph_16_xpm},
        { WIRESHARK_STOCK_TELEPHONY,             telephony_16_xpm},
        { WIRESHARK_STOCK_DECODE_AS,             decode_as_16_xpm},
        { WIRESHARK_STOCK_CHECKBOX,              checkbox_16_xpm},
        { WIRESHARK_STOCK_FILE_SET_LIST,         file_set_list_16_xpm},
        { WIRESHARK_STOCK_FILE_SET_NEXT,         file_set_next_16_xpm},
        { WIRESHARK_STOCK_FILE_SET_PREVIOUS,     file_set_previous_16_xpm},
        { WIRESHARK_STOCK_FILTER_OUT_STREAM,     display_filter_24_xpm},
        { WIRESHARK_STOCK_ENABLE,                checkbox_16_xpm},
        { WIRESHARK_STOCK_COLOR1,                icon_color_1_xpm},
        { WIRESHARK_STOCK_COLOR2,                icon_color_2_xpm},
        { WIRESHARK_STOCK_COLOR3,                icon_color_3_xpm},
        { WIRESHARK_STOCK_COLOR4,                icon_color_4_xpm},
        { WIRESHARK_STOCK_COLOR5,                icon_color_5_xpm},
        { WIRESHARK_STOCK_COLOR6,                icon_color_6_xpm},
        { WIRESHARK_STOCK_COLOR7,                icon_color_7_xpm},
        { WIRESHARK_STOCK_COLOR8,                icon_color_8_xpm},
        { WIRESHARK_STOCK_COLOR9,                icon_color_9_xpm},
        { WIRESHARK_STOCK_COLOR0,                icon_color_0_xpm},
        { WIRESHARK_STOCK_DECODE,                decode_24_xpm},
        { WIRESHARK_STOCK_AUDIO_PLAYER,          audio_player_24_xpm},
        { WIRESHARK_STOCK_VOIP_FLOW,             voip_flow_24_xpm},
        { WIRESHARK_STOCK_TELEPHONE,             telephone_16_xpm},
        { WIRESHARK_STOCK_PREPARE_FILTER,        display_filter_24_xpm},
        { WIRESHARK_STOCK_ANALYZE,               analyze_24_xpm},
        { NULL, NULL }
    };

    /* Register our stock items */
    gtk_stock_add (stock_items, G_N_ELEMENTS (stock_items));

    /* Add our custom icon factory to the list of defaults */
    factory = gtk_icon_factory_new();
    gtk_icon_factory_add_default(factory);

    /* Add pixmaps our icon factory */
    /* Please use pixbufs (below) for new icons */
    for (i = 0; pixmaps[i].name != NULL; i++) {
        /* The default icon */
        pixbuf = gdk_pixbuf_new_from_xpm_data((const char **) (pixmaps[i].xpm_data));
        g_assert(pixbuf);
        icon_set = gtk_icon_set_new_from_pixbuf (pixbuf);

        /* XXX - add different sized icons here (some 16*16 icons look a bit blurred) */
        /*gtk_icon_set_add_source(icon_set, const GtkIconSource *source);*/

        gtk_icon_factory_add (factory, pixmaps[i].name, icon_set);
        gtk_icon_set_unref (icon_set);
        g_object_unref (G_OBJECT (pixbuf));
    }

    /* Add pixbufs our icon factory */
    for (i = 0; pixbufs[i].name != NULL; i++) {
        /* Default image */
        icon_set = gtk_icon_set_new_from_pixbuf(gdk_pixbuf_new_from_inline(-1, pixbufs[i].pb_data24, FALSE, NULL));

        if (pixbufs[i].pb_data16) {
            GtkIconSource *source16 = gtk_icon_source_new();
            gtk_icon_source_set_pixbuf(source16, gdk_pixbuf_new_from_inline(-1, pixbufs[i].pb_data16, FALSE, NULL));
            gtk_icon_source_set_size_wildcarded(source16, FALSE);
            gtk_icon_source_set_size(source16, GTK_ICON_SIZE_MENU);
            gtk_icon_set_add_source(icon_set, source16);

            /* Twice? Really? Seriously? */
            source16 = gtk_icon_source_new();
            gtk_icon_source_set_pixbuf(source16, gdk_pixbuf_new_from_inline(-1, pixbufs[i].pb_data16, FALSE, NULL));
            gtk_icon_source_set_size_wildcarded(source16, FALSE);
            gtk_icon_source_set_size(source16, GTK_ICON_SIZE_SMALL_TOOLBAR);
            gtk_icon_set_add_source(icon_set, source16);
        }

        gtk_icon_factory_add (factory, pixbufs[i].name, icon_set);
        gtk_icon_set_unref (icon_set);
    }

    /* use default stock icons for Wireshark specifics where the icon metapher makes sense */
    /* PLEASE DON'T REUSE STOCK ICONS IF THEY ARE USUALLY USED FOR SOME DIFFERENT MEANING!!!) */
    icon_set = gtk_icon_factory_lookup_default(GTK_STOCK_OPEN);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_BROWSE, icon_set);
    icon_set = gtk_icon_factory_lookup_default(GTK_STOCK_OK);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_CREATE_STAT, icon_set);
    icon_set = gtk_icon_factory_lookup_default(GTK_STOCK_SAVE);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_EXPORT, icon_set);    /* XXX: needs a better icon */
    icon_set = gtk_icon_factory_lookup_default(GTK_STOCK_OPEN);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_IMPORT, icon_set);    /* XXX: needs a better icon */
    icon_set = gtk_icon_factory_lookup_default(GTK_STOCK_PROPERTIES);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_EDIT, icon_set);
    icon_set = gtk_icon_factory_lookup_default(GTK_STOCK_ADD);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_ADD_EXPRESSION, icon_set);
    icon_set = gtk_icon_factory_lookup_default(GTK_STOCK_CLEAR);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_CLEAR_EXPRESSION, icon_set);
    icon_set = gtk_icon_factory_lookup_default(GTK_STOCK_APPLY);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_APPLY_EXPRESSION, icon_set);
    icon_set = gtk_icon_factory_lookup_default(GTK_STOCK_CLEAR);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_DONT_SAVE, icon_set);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_QUIT_DONT_SAVE, icon_set);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_STOP_DONT_SAVE, icon_set);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_STOP_QUIT_DONT_SAVE, icon_set);
    icon_set = gtk_icon_factory_lookup_default(GTK_STOCK_SAVE);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_STOP_SAVE, icon_set);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_SAVE_ALL, icon_set);  /* XXX: needs a better icon */
    icon_set = gtk_icon_factory_lookup_default(GTK_STOCK_CLOSE);
    gtk_icon_factory_add(factory, WIRESHARK_STOCK_DISABLE, icon_set);

    /* Drop our reference to the factory, GTK will hold a reference.*/
    g_object_unref (G_OBJECT (factory));
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
