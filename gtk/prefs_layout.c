/* layout_prefs.c
 * Dialog box for layout preferences
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gtk/gtk.h>

#include <epan/prefs.h>

#include "../ui_util.h"

#include "gtk/prefs_layout.h"
#include "gtk/gtkglobals.h"
#include "gtk/prefs_dlg.h"
#include "gtk/gui_utils.h"
#include "gtk/main.h"
#include "gtk/dlg_utils.h"

#include "../image/icon_layout_1.xpm"
#include "../image/icon_layout_2.xpm"
#include "../image/icon_layout_3.xpm"
#include "../image/icon_layout_4.xpm"
#include "../image/icon_layout_5.xpm"
#include "../image/icon_layout_6.xpm"


#define LAYOUT_QTY (layout_type_max - 1)


static void layout_validate_cb(GtkWidget *w _U_, gpointer data);
static gint fetch_enum_value(gpointer control, const enum_val_t *enumvals);


typedef struct {
    layout_type_e           type;
    layout_pane_content_e   content[3];
} layout_t;


#define LAYOUT_TYPE_BUTTONS_KEY     "layout_type_buttons"

#define LAYOUT_NONE_RB_KEY          "layout_none_radio_button"
#define LAYOUT_PLIST_RB_KEY         "layout_plist_radio_button"
#define LAYOUT_PDETAILS_RB_KEY      "layout_pdetails_radio_button"
#define LAYOUT_PBYTES_RB_KEY        "layout_pbytes_radio_button"

#define LAYOUT_CONTENT1_VB_KEY      "layout_content1_vbox"
#define LAYOUT_CONTENT2_VB_KEY      "layout_content2_vbox"
#define LAYOUT_CONTENT3_VB_KEY      "layout_content3_vbox"


static GtkWidget *layout_content_radio_vbox(GtkWidget *main_vb, int i, layout_pane_content_e content) {
    GtkWidget	*radio_vb, *radio_lb;
    GtkWidget	*radio_none_rb, *radio_plist_rb, *radio_pdetails_rb, *radio_pbytes_rb;
    char buf[64];


    /* radio vbox */
    radio_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(radio_vb), 6);

    g_snprintf (buf, sizeof(buf), "Pane %d:", i);
    radio_lb = gtk_label_new(buf);
    gtk_misc_set_alignment(GTK_MISC(radio_lb), 0.0f, 0.5f);
    gtk_container_add(GTK_CONTAINER(radio_vb), radio_lb);

    radio_none_rb = gtk_radio_button_new_with_mnemonic_from_widget(NULL, "None");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_none_rb), content == layout_pane_content_none);
    gtk_widget_set_tooltip_text (radio_none_rb, "Put nothing in this pane.");
    gtk_container_add(GTK_CONTAINER(radio_vb), radio_none_rb);

    radio_plist_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(radio_none_rb), "Packet List");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_plist_rb), content == layout_pane_content_plist);
    gtk_widget_set_tooltip_text (radio_plist_rb, "Put the packet list in this pane.");
    gtk_container_add(GTK_CONTAINER(radio_vb), radio_plist_rb);

    radio_pdetails_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(radio_none_rb), "Packet Details");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_pdetails_rb), content == layout_pane_content_pdetails);
    gtk_widget_set_tooltip_text (radio_pdetails_rb, "Put the packet details tree in this pane.");
    gtk_container_add(GTK_CONTAINER(radio_vb), radio_pdetails_rb);

    radio_pbytes_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(radio_none_rb), "Packet Bytes");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_pbytes_rb), content == layout_pane_content_pbytes);
    gtk_widget_set_tooltip_text (radio_pbytes_rb, "Put the packet bytes dump in this pane.");
    gtk_container_add(GTK_CONTAINER(radio_vb), radio_pbytes_rb);

    g_object_set_data(G_OBJECT(radio_vb), LAYOUT_NONE_RB_KEY,       radio_none_rb);
    g_object_set_data(G_OBJECT(radio_vb), LAYOUT_PLIST_RB_KEY,      radio_plist_rb);
    g_object_set_data(G_OBJECT(radio_vb), LAYOUT_PDETAILS_RB_KEY,   radio_pdetails_rb);
    g_object_set_data(G_OBJECT(radio_vb), LAYOUT_PBYTES_RB_KEY,     radio_pbytes_rb);

    g_signal_connect(radio_none_rb,       "toggled", G_CALLBACK(layout_validate_cb), main_vb);
    g_signal_connect(radio_plist_rb,      "toggled", G_CALLBACK(layout_validate_cb), main_vb);
    g_signal_connect(radio_pdetails_rb,   "toggled", G_CALLBACK(layout_validate_cb), main_vb);
    g_signal_connect(radio_pbytes_rb,     "toggled", G_CALLBACK(layout_validate_cb), main_vb);

    return radio_vb;
}

static void
layout_type_changed_cb (GtkToggleButton * togglebutton, gpointer user_data)
{
	GtkWidget ** layout_type_buttons = (GtkWidget**) user_data;
	static gboolean dampen_feedback_loop = FALSE;

	if (!dampen_feedback_loop) {
		int i;
		dampen_feedback_loop = TRUE;
		for (i=0; i<LAYOUT_QTY; ++i) {
			GtkToggleButton * tb = GTK_TOGGLE_BUTTON(layout_type_buttons[i]);
			gboolean active = togglebutton==tb;
			if (gtk_toggle_button_get_active(tb) != active)
				gtk_toggle_button_set_active (tb, active);
		}
		dampen_feedback_loop = FALSE;
	}
}


static layout_pane_content_e  layout_pane_get_content(GtkWidget * radio_vb) {

    if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_object_get_data(G_OBJECT(radio_vb), LAYOUT_NONE_RB_KEY))))
        return layout_pane_content_none;
    if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_object_get_data(G_OBJECT(radio_vb), LAYOUT_PLIST_RB_KEY))))
        return layout_pane_content_plist;
    if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_object_get_data(G_OBJECT(radio_vb), LAYOUT_PDETAILS_RB_KEY))))
        return layout_pane_content_pdetails;
    if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_object_get_data(G_OBJECT(radio_vb), LAYOUT_PBYTES_RB_KEY))))
        return layout_pane_content_pbytes;

    g_assert_not_reached();
    return -1;
}

static void layout_pane_set_content(GtkWidget * radio_vb, layout_pane_content_e pane_content) {


    switch(pane_content) {
    case(layout_pane_content_none):
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(g_object_get_data(G_OBJECT(radio_vb), LAYOUT_NONE_RB_KEY)), TRUE);
        break;
    case(layout_pane_content_plist):
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(g_object_get_data(G_OBJECT(radio_vb), LAYOUT_PLIST_RB_KEY)), TRUE);
        break;
    case(layout_pane_content_pdetails):
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(g_object_get_data(G_OBJECT(radio_vb), LAYOUT_PDETAILS_RB_KEY)), TRUE);
        break;
    case(layout_pane_content_pbytes):
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(g_object_get_data(G_OBJECT(radio_vb), LAYOUT_PBYTES_RB_KEY)), TRUE);
        break;
    default:
        g_assert_not_reached();
    }
}



static void layout_set(GtkWidget * main_vb, layout_t *layout) {
    GtkWidget	*radio_vb;
    GtkWidget ** layout_type_buttons = g_object_get_data(G_OBJECT(main_vb), LAYOUT_TYPE_BUTTONS_KEY);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(layout_type_buttons[layout->type - 1]), TRUE);

    radio_vb = g_object_get_data(G_OBJECT(main_vb), LAYOUT_CONTENT1_VB_KEY);
    layout_pane_set_content(radio_vb, layout->content[0]);
    radio_vb = g_object_get_data(G_OBJECT(main_vb), LAYOUT_CONTENT2_VB_KEY);
    layout_pane_set_content(radio_vb, layout->content[1]);
    radio_vb = g_object_get_data(G_OBJECT(main_vb), LAYOUT_CONTENT3_VB_KEY);
    layout_pane_set_content(radio_vb, layout->content[2]);
}

static void layout_get(GtkWidget * main_vb, layout_t *layout_out) {
    GtkWidget	*radio_vb;
    GtkWidget ** layout_type_buttons = g_object_get_data(G_OBJECT(main_vb), LAYOUT_TYPE_BUTTONS_KEY);
    int i;

    for (i=0; i<LAYOUT_QTY; ++i) {
        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(layout_type_buttons[i]))) {
            layout_out->type = i + 1;
            break;
        }
    }

    radio_vb = g_object_get_data(G_OBJECT(main_vb), LAYOUT_CONTENT1_VB_KEY);
    layout_out->content[0] = layout_pane_get_content(radio_vb);
    radio_vb = g_object_get_data(G_OBJECT(main_vb), LAYOUT_CONTENT2_VB_KEY);
    layout_out->content[1] = layout_pane_get_content(radio_vb);
    radio_vb = g_object_get_data(G_OBJECT(main_vb), LAYOUT_CONTENT3_VB_KEY);
    layout_out->content[2] = layout_pane_get_content(radio_vb);
}

static void layout_validate(layout_t *layout) {

    if(layout->content[1] == layout->content[0]) {
        layout->content[1] = layout_pane_content_none;
    }
    if(layout->content[2] == layout->content[0] || layout->content[2] == layout->content[1]) {
        layout->content[2] = layout_pane_content_none;
    }
}


static void layout_validate_cb(GtkWidget *w _U_, gpointer data) {
    layout_t    layout;

    layout_get(data, &layout);
    layout_validate(&layout);
    layout_set(data, &layout);
}

static void
layout_defaults_cb (GtkWidget * w _U_, gpointer data)
{
    layout_t default_layout = {
        layout_type_5,
        {
            layout_pane_content_plist,
            layout_pane_content_pdetails,
            layout_pane_content_pbytes
        }
    };

    layout_set(data, &default_layout);
}

#define SCROLLBAR_PLACEMENT_KEY         "scrollbar_placement"
#define ALTERN_COLORS_KEY               "altern_colors"
#define HEX_DUMP_HIGHLIGHT_STYLE_KEY	"hex_dump_highlight_style"
#define FILTER_TOOLBAR_PLACEMENT_KEY    "filter_toolbar_show_in_statusbar"
#define GUI_TOOLBAR_STYLE_KEY           "toolbar_style"
#define GUI_FILTER_TOOLBAR_STYLE_KEY    "filter_toolbar_style"
#define GUI_WINDOW_TITLE_KEY            "window_title"


#define GUI_TABLE_ROWS 6

static const enum_val_t scrollbar_placement_vals[] = {
    { "FALSE", "Left", FALSE },
    { "TRUE",  "Right", TRUE },
    { NULL,    NULL,    0 }
};
static const enum_val_t altern_colors_vals[] = {
    { "FALSE", "No",  FALSE },
    { "TRUE",  "Yes", TRUE },
    { NULL,    NULL,  0 }
};
static const enum_val_t highlight_style_vals[] = {
    { "FALSE", "Bold",     FALSE },
    { "TRUE",  "Inverse",  TRUE },
    { NULL,    NULL,       0 }
};
static const enum_val_t filter_toolbar_placement_vals[] = {
    { "FALSE", "Below the main toolbar", FALSE },
    { "TRUE",  "Insert into statusbar",  TRUE },
    { NULL,    NULL,                     0 }
};
static const enum_val_t toolbar_style_vals[] = {
    { "ICONS", "Icons only",     TB_STYLE_ICONS },
    { "TEXT",  "Text only",      TB_STYLE_TEXT },
    { "BOTH",  "Icons & Text",   TB_STYLE_BOTH },
    { NULL,    NULL,             0 }
};

GtkWidget*
layout_prefs_show(void)
{
    GtkWidget	*main_vb, *button_hb, *type_tb;
    GtkWidget	*pane_fr, *pane_vb;
    GtkWidget	*radio_hb, *radio_vb;
    GtkWidget	*default_vb, *default_bt;
    GtkWidget   *main_tb, *hbox;
    GtkWidget	*scrollbar_om;
    GtkWidget	*altern_colors_om;
    GtkWidget	*highlight_style_om;
    GtkWidget	*toolbar_style_om;
	GtkWidget	*filter_toolbar_style_om;
    GtkWidget	*filter_toolbar_placement_om;
    GtkWidget	*window_title_te;

    const char ** inline_txt [LAYOUT_QTY] = {
		icon_layout_5_xpm, icon_layout_2_xpm, icon_layout_1_xpm,
		icon_layout_4_xpm, icon_layout_3_xpm, icon_layout_6_xpm };
    GtkWidget ** layout_type_buttons = g_malloc (sizeof(GtkWidget*) * LAYOUT_QTY);

    int        pos = 0;
    int i;


    /* main vertical box */
    main_vb = gtk_vbox_new(FALSE, 7);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);

    /* pane frame */
    pane_fr = gtk_frame_new("Panes");
    gtk_box_pack_start(GTK_BOX(main_vb), pane_fr, FALSE, FALSE, 0);
    gtk_widget_show(pane_fr);

    /* pane vertical box */
    pane_vb = gtk_vbox_new(FALSE, 7);
    gtk_container_set_border_width(GTK_CONTAINER(pane_vb), 5);
    gtk_container_add(GTK_CONTAINER(pane_fr), pane_vb);
    gtk_widget_show(pane_vb);

    /* button hbox */
    button_hb = gtk_hbox_new(FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(button_hb), 6);
    gtk_box_pack_start (GTK_BOX(pane_vb), button_hb, FALSE, FALSE, 0);

    /* pane layout */
    for (i=0; i<LAYOUT_QTY; ++i)
    {
	type_tb = gtk_toggle_button_new ();
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(type_tb),
	    (layout_type_e)(i + 1) == prefs.gui_layout_type);

	gtk_container_add (GTK_CONTAINER(type_tb), xpm_to_widget(inline_txt[i]));

	g_signal_connect(type_tb, "toggled", G_CALLBACK(layout_type_changed_cb), layout_type_buttons);
	layout_type_buttons[i] = type_tb;
	gtk_box_pack_start (GTK_BOX(button_hb), type_tb, TRUE, FALSE, 0);
    }

    g_object_set_data(G_OBJECT(main_vb), LAYOUT_TYPE_BUTTONS_KEY, layout_type_buttons);

    /* radio hbox */
    radio_hb = gtk_hbox_new(FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(radio_hb), 6);
    gtk_box_pack_start (GTK_BOX(pane_vb), radio_hb, FALSE, FALSE, 0);

    radio_vb = layout_content_radio_vbox(main_vb, 1, prefs.gui_layout_content_1);
    gtk_container_set_border_width(GTK_CONTAINER(radio_vb), 6);
    gtk_box_pack_start (GTK_BOX(radio_hb), radio_vb, FALSE, FALSE, 0);
    g_object_set_data(G_OBJECT(main_vb), LAYOUT_CONTENT1_VB_KEY, radio_vb);

    radio_vb = layout_content_radio_vbox(main_vb, 2, prefs.gui_layout_content_2);
    gtk_container_set_border_width(GTK_CONTAINER(radio_vb), 6);
    gtk_box_pack_start (GTK_BOX(radio_hb), radio_vb, FALSE, FALSE, 0);
    g_object_set_data(G_OBJECT(main_vb), LAYOUT_CONTENT2_VB_KEY, radio_vb);

    radio_vb = layout_content_radio_vbox(main_vb, 3, prefs.gui_layout_content_3);
    gtk_container_set_border_width(GTK_CONTAINER(radio_vb), 6);
    gtk_box_pack_start (GTK_BOX(radio_hb), radio_vb, FALSE, FALSE, 0);
    g_object_set_data(G_OBJECT(main_vb), LAYOUT_CONTENT3_VB_KEY, radio_vb);

    default_vb = gtk_vbox_new(FALSE, 0);
    default_bt = gtk_button_new_with_label("Default panes");
    gtk_widget_set_tooltip_text (default_bt, "Reset the pane layout settings to default values.");
    g_signal_connect(default_bt, "clicked", G_CALLBACK(layout_defaults_cb), main_vb);
    gtk_box_pack_end(GTK_BOX(default_vb), default_bt, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(radio_hb), default_vb, FALSE, FALSE, 0);

    /* Main horizontal box  */
    /* XXX - Is there a better way to center the table? */
    hbox = gtk_hbox_new(FALSE, 7);
    gtk_box_pack_start (GTK_BOX(main_vb), hbox, TRUE, FALSE, 0);

    /* Main table */
    main_tb = gtk_table_new(GUI_TABLE_ROWS, 2, FALSE);
    gtk_box_pack_start( GTK_BOX(hbox), main_tb, FALSE, FALSE, 0 );
    gtk_table_set_row_spacings( GTK_TABLE(main_tb), 10 );
    gtk_table_set_col_spacings( GTK_TABLE(main_tb), 15 );

    /* Scrollbar placement */
    scrollbar_om = create_preference_option_menu(main_tb, pos++,
        "Vertical scrollbar placement:",
        "Select where the vertical scrollbar will be displayed in the panes.",
        scrollbar_placement_vals, prefs.gui_scrollbar_on_right);
    g_object_set_data(G_OBJECT(main_vb), SCROLLBAR_PLACEMENT_KEY, scrollbar_om);

    /* Alternating row colors in list and tree views */
    altern_colors_om = create_preference_option_menu(main_tb, pos++,
        "Alternating row colors in lists and trees:",
        "Select whether or not the rows of lists and trees have alternating color.",
        altern_colors_vals, prefs.gui_altern_colors);
    g_object_set_data(G_OBJECT(main_vb), ALTERN_COLORS_KEY, altern_colors_om);

    /* Packet Bytes Dump highlight style */
    highlight_style_om = create_preference_option_menu(main_tb, pos++,
        "Packet bytes highlight style:",
        "Select the style in which the packet bytes dump will be displayed.",
        highlight_style_vals, prefs.gui_hex_dump_highlight_style);
    g_object_set_data(G_OBJECT(main_vb), HEX_DUMP_HIGHLIGHT_STYLE_KEY, highlight_style_om);

    /* Toolbar prefs */
    toolbar_style_om = create_preference_option_menu(main_tb, pos++,
        "Toolbar style:",
        "Select the style in which the toolbar will be displayed.",
        toolbar_style_vals, prefs.gui_toolbar_main_style);
    g_object_set_data(G_OBJECT(main_vb), GUI_TOOLBAR_STYLE_KEY, toolbar_style_om);

    /* Filter toolbar prefs */
    filter_toolbar_style_om = create_preference_option_menu(main_tb, pos++,
        "Filter toolbar style:",
        "Select the style in which the filter toolbar will be displayed.",
        toolbar_style_vals, prefs.gui_toolbar_filter_style);
    g_object_set_data(G_OBJECT(main_vb), GUI_FILTER_TOOLBAR_STYLE_KEY, filter_toolbar_style_om);

    /* Placement of Filter toolbar */
    filter_toolbar_placement_om = create_preference_option_menu(main_tb, pos++,
        "Filter toolbar placement:",
        "Select where the filter toolbar will be displayed.",
        filter_toolbar_placement_vals, prefs.filter_toolbar_show_in_statusbar);
    g_object_set_data(G_OBJECT(main_vb), FILTER_TOOLBAR_PLACEMENT_KEY, filter_toolbar_placement_om);

    /* Window title */
    window_title_te = create_preference_entry(main_tb, pos++,
        "Custom window title (appended to existing titles):",
        "Enter the text to be appended to the window title.",
        prefs.gui_window_title);
    gtk_entry_set_text(GTK_ENTRY(window_title_te), prefs.gui_window_title);
    g_object_set_data(G_OBJECT(main_vb), GUI_WINDOW_TITLE_KEY, window_title_te);

    /* Show 'em what we got */
    gtk_widget_show_all(main_vb);

    return(main_vb);
}

static gint
fetch_enum_value(gpointer control, const enum_val_t *enumvals)
{
    return fetch_preference_option_menu_val(GTK_WIDGET(control), enumvals);
}

void
layout_prefs_fetch(GtkWidget *w)
{
    layout_t layout_fetched;

    layout_get(w, &layout_fetched);

    prefs.gui_layout_type = layout_fetched.type;
    prefs.gui_layout_content_1 = layout_fetched.content[0];
    prefs.gui_layout_content_2 = layout_fetched.content[1];
    prefs.gui_layout_content_3 = layout_fetched.content[2];

    prefs.gui_scrollbar_on_right = fetch_enum_value(
        g_object_get_data(G_OBJECT(w), SCROLLBAR_PLACEMENT_KEY),
        scrollbar_placement_vals);

    prefs.gui_altern_colors = fetch_enum_value(
        g_object_get_data(G_OBJECT(w), ALTERN_COLORS_KEY), altern_colors_vals);
    prefs.filter_toolbar_show_in_statusbar = fetch_enum_value(
        g_object_get_data(G_OBJECT(w), FILTER_TOOLBAR_PLACEMENT_KEY), filter_toolbar_placement_vals);
    prefs.gui_hex_dump_highlight_style = fetch_enum_value(
        g_object_get_data(G_OBJECT(w), HEX_DUMP_HIGHLIGHT_STYLE_KEY),  highlight_style_vals);
    prefs.gui_toolbar_main_style = fetch_enum_value(
        g_object_get_data(G_OBJECT(w), GUI_TOOLBAR_STYLE_KEY), toolbar_style_vals);
    prefs.gui_toolbar_filter_style = fetch_enum_value(
        g_object_get_data(G_OBJECT(w), GUI_FILTER_TOOLBAR_STYLE_KEY), toolbar_style_vals);

    g_free(prefs.gui_window_title);
    prefs.gui_window_title = g_strdup(gtk_entry_get_text(
                                          GTK_ENTRY(g_object_get_data(G_OBJECT(w), GUI_WINDOW_TITLE_KEY))));
}

void
layout_prefs_apply(GtkWidget *w _U_)
{
    update_main_window_title();
    main_widgets_rearrange();
}

void
layout_prefs_destroy(GtkWidget *main_vb)
{
    GtkWidget ** layout_type_buttons = g_object_get_data(G_OBJECT(main_vb), LAYOUT_TYPE_BUTTONS_KEY);

    g_free(layout_type_buttons);
}

