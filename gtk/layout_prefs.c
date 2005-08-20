/* layout_prefs.c
 * Dialog box for layout preferences
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include "globals.h"
#include "layout_prefs.h"
#include "gtkglobals.h"
#include <epan/prefs.h>
#include "gui_utils.h"
#include "main.h"
#include "compat_macros.h"
#include "dlg_utils.h"

#include "../image/icon_layout_1.xpm"
#include "../image/icon_layout_2.xpm"
#include "../image/icon_layout_3.xpm"
#include "../image/icon_layout_4.xpm"
#include "../image/icon_layout_5.xpm"
#include "../image/icon_layout_6.xpm"

#define LAYOUT_QTY (layout_type_max - 1)


static void layout_validate_cb(GtkWidget *w _U_, gpointer data);



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


static GtkWidget *layout_content_radio_vbox(GtkWidget *main_vb, GtkTooltips *tooltips, int i, layout_pane_content_e content) {
    GtkWidget	*radio_vb, *radio_lb;
    GtkWidget	*radio_none_rb, *radio_plist_rb, *radio_pdetails_rb, *radio_pbytes_rb;
    char buf[64];


    /* radio vbox */
    radio_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(radio_vb), 6);

    g_snprintf (buf, sizeof(buf), "Pane %d:", i);
    radio_lb = gtk_label_new(buf);
    gtk_misc_set_alignment(GTK_MISC(radio_lb), 0.0, 0.5);
    gtk_container_add(GTK_CONTAINER(radio_vb), radio_lb);

    radio_none_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(NULL, "None", NULL);
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(radio_none_rb), content == layout_pane_content_none);
    gtk_tooltips_set_tip (tooltips, radio_none_rb, "Put nothing in this pane.", NULL);
    gtk_container_add(GTK_CONTAINER(radio_vb), radio_none_rb);

    radio_plist_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(radio_none_rb, "Packet List", NULL);
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(radio_plist_rb), content == layout_pane_content_plist);
    gtk_tooltips_set_tip (tooltips, radio_plist_rb, "Put the packet list in this pane.", NULL);
    gtk_container_add(GTK_CONTAINER(radio_vb), radio_plist_rb);

    radio_pdetails_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(radio_none_rb, "Packet Details", NULL);
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(radio_pdetails_rb), content == layout_pane_content_pdetails);
    gtk_tooltips_set_tip (tooltips, radio_pdetails_rb, "Put the packet details tree in this pane.", NULL);
    gtk_container_add(GTK_CONTAINER(radio_vb), radio_pdetails_rb);

    radio_pbytes_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(radio_none_rb, "Packet Bytes", NULL);
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(radio_pbytes_rb), content == layout_pane_content_pbytes);
    gtk_tooltips_set_tip (tooltips, radio_pbytes_rb, "Put the packet bytes hexdump in this pane.", NULL);
    gtk_container_add(GTK_CONTAINER(radio_vb), radio_pbytes_rb);

    OBJECT_SET_DATA(radio_vb, LAYOUT_NONE_RB_KEY,       radio_none_rb);
    OBJECT_SET_DATA(radio_vb, LAYOUT_PLIST_RB_KEY,      radio_plist_rb);
    OBJECT_SET_DATA(radio_vb, LAYOUT_PDETAILS_RB_KEY,   radio_pdetails_rb);
    OBJECT_SET_DATA(radio_vb, LAYOUT_PBYTES_RB_KEY,     radio_pbytes_rb);

    SIGNAL_CONNECT(radio_none_rb,       "toggled", layout_validate_cb, main_vb);
    SIGNAL_CONNECT(radio_plist_rb,      "toggled", layout_validate_cb, main_vb);
    SIGNAL_CONNECT(radio_pdetails_rb,   "toggled", layout_validate_cb, main_vb);
    SIGNAL_CONNECT(radio_pbytes_rb,     "toggled", layout_validate_cb, main_vb);

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

    if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(OBJECT_GET_DATA(radio_vb, LAYOUT_NONE_RB_KEY))))
        return layout_pane_content_none;
    if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(OBJECT_GET_DATA(radio_vb, LAYOUT_PLIST_RB_KEY))))
        return layout_pane_content_plist;
    if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(OBJECT_GET_DATA(radio_vb, LAYOUT_PDETAILS_RB_KEY))))
        return layout_pane_content_pdetails;
    if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(OBJECT_GET_DATA(radio_vb, LAYOUT_PBYTES_RB_KEY))))
        return layout_pane_content_pbytes;

    g_assert_not_reached();
    return -1;
}

static void layout_pane_set_content(GtkWidget * radio_vb, layout_pane_content_e pane_content) {


    switch(pane_content) {
    case(layout_pane_content_none):
        gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(OBJECT_GET_DATA(radio_vb, LAYOUT_NONE_RB_KEY)), TRUE);
        break;
    case(layout_pane_content_plist):
        gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(OBJECT_GET_DATA(radio_vb, LAYOUT_PLIST_RB_KEY)), TRUE);
        break;
    case(layout_pane_content_pdetails):
        gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(OBJECT_GET_DATA(radio_vb, LAYOUT_PDETAILS_RB_KEY)), TRUE);
        break;
    case(layout_pane_content_pbytes):
        gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(OBJECT_GET_DATA(radio_vb, LAYOUT_PBYTES_RB_KEY)), TRUE);
        break;
    default:
        g_assert_not_reached();
    }
}



static void layout_set(GtkWidget * main_vb, layout_t *layout) {
    GtkWidget	*radio_vb;
    GtkWidget ** layout_type_buttons = OBJECT_GET_DATA(main_vb, LAYOUT_TYPE_BUTTONS_KEY);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(layout_type_buttons[layout->type - 1]), TRUE);

    radio_vb = OBJECT_GET_DATA(main_vb, LAYOUT_CONTENT1_VB_KEY);
    layout_pane_set_content(radio_vb, layout->content[0]);
    radio_vb = OBJECT_GET_DATA(main_vb, LAYOUT_CONTENT2_VB_KEY);
    layout_pane_set_content(radio_vb, layout->content[1]);
    radio_vb = OBJECT_GET_DATA(main_vb, LAYOUT_CONTENT3_VB_KEY);
    layout_pane_set_content(radio_vb, layout->content[2]);
}

static void layout_get(GtkWidget * main_vb, layout_t *layout_out) {
    GtkWidget	*radio_vb;
    GtkWidget ** layout_type_buttons = OBJECT_GET_DATA(main_vb, LAYOUT_TYPE_BUTTONS_KEY);
    int i;

    for (i=0; i<LAYOUT_QTY; ++i) {
        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(layout_type_buttons[i]))) {
            layout_out->type = i + 1;
            break;
        }
    }

    radio_vb = OBJECT_GET_DATA(main_vb, LAYOUT_CONTENT1_VB_KEY);
    layout_out->content[0] = layout_pane_get_content(radio_vb);
    radio_vb = OBJECT_GET_DATA(main_vb, LAYOUT_CONTENT2_VB_KEY);
    layout_out->content[1] = layout_pane_get_content(radio_vb);
    radio_vb = OBJECT_GET_DATA(main_vb, LAYOUT_CONTENT3_VB_KEY);
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
layout_defaults_cb (GtkWidget * w _U_, gpointer data _U_)
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


GtkWidget*
layout_prefs_show(void)
{
#if GTK_MAJOR_VERSION < 2
    GtkAccelGroup *accel_group;
#endif
    GtkTooltips   *tooltips;

    GtkWidget	*main_vb, *button_hb, *type_tb;
    GtkWidget	*radio_hb, *radio_vb;
    GtkWidget	*default_vb, *default_bt;

    const char ** inline_txt [LAYOUT_QTY] = {
		icon_layout_5_xpm, icon_layout_2_xpm, icon_layout_1_xpm,
		icon_layout_4_xpm, icon_layout_3_xpm, icon_layout_6_xpm };
    GtkWidget ** layout_type_buttons = g_malloc (sizeof(GtkWidget*) * LAYOUT_QTY);

    int i;


    /* main vertical box */
    main_vb = gtk_vbox_new(FALSE, 7);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);

#if GTK_MAJOR_VERSION < 2
    /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
    accel_group = gtk_accel_group_new();
    /*gtk_window_add_accel_group(GTK_WINDOW(main_win), accel_group);*/
#endif

    /* Enable tooltips */
    tooltips = gtk_tooltips_new();


    /* button hbox */
    button_hb = gtk_hbox_new(FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(button_hb), 6);
    gtk_box_pack_start (GTK_BOX(main_vb), button_hb, FALSE, FALSE, 0);

    /* pane layout */
    for (i=0; i<LAYOUT_QTY; ++i)
    {
	type_tb = gtk_toggle_button_new ();
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(type_tb),
	    (layout_type_e)(i + 1) == prefs.gui_layout_type);

	gtk_container_add (GTK_CONTAINER(type_tb), xpm_to_widget(inline_txt[i]));

	SIGNAL_CONNECT(type_tb, "toggled", layout_type_changed_cb, layout_type_buttons);
	layout_type_buttons[i] = type_tb;
	gtk_box_pack_start (GTK_BOX(button_hb), type_tb, TRUE, FALSE, 0);
    }

    OBJECT_SET_DATA(main_vb, LAYOUT_TYPE_BUTTONS_KEY, layout_type_buttons);

    /* radio hbox */
    radio_hb = gtk_hbox_new(FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(radio_hb), 6);
    gtk_box_pack_start (GTK_BOX(main_vb), radio_hb, FALSE, FALSE, 0);

    radio_vb = layout_content_radio_vbox(main_vb, tooltips, 1, prefs.gui_layout_content_1);
    gtk_container_set_border_width(GTK_CONTAINER(radio_vb), 6);
    gtk_box_pack_start (GTK_BOX(radio_hb), radio_vb, FALSE, FALSE, 0);
    OBJECT_SET_DATA(main_vb, LAYOUT_CONTENT1_VB_KEY, radio_vb);

    radio_vb = layout_content_radio_vbox(main_vb, tooltips, 2, prefs.gui_layout_content_2);
    gtk_container_set_border_width(GTK_CONTAINER(radio_vb), 6);
    gtk_box_pack_start (GTK_BOX(radio_hb), radio_vb, FALSE, FALSE, 0);
    OBJECT_SET_DATA(main_vb, LAYOUT_CONTENT2_VB_KEY, radio_vb);

    radio_vb = layout_content_radio_vbox(main_vb, tooltips, 3, prefs.gui_layout_content_3);
    gtk_container_set_border_width(GTK_CONTAINER(radio_vb), 6);
    gtk_box_pack_start (GTK_BOX(radio_hb), radio_vb, FALSE, FALSE, 0);
    OBJECT_SET_DATA(main_vb, LAYOUT_CONTENT3_VB_KEY, radio_vb);

    default_vb = gtk_vbox_new(FALSE, 0);
    default_bt = gtk_button_new_with_label("Defaults");
    gtk_tooltips_set_tip (tooltips, default_bt, "Reset the pane layout settings to default values.", NULL);
    SIGNAL_CONNECT(default_bt, "clicked", layout_defaults_cb, main_vb);
    gtk_box_pack_end(GTK_BOX(default_vb), default_bt, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(radio_hb), default_vb, FALSE, FALSE, 0);

    /* Show 'em what we got */
    gtk_widget_show_all(main_vb);

    return(main_vb);
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
}

void
layout_prefs_apply(GtkWidget *w _U_)
{
    main_widgets_rearrange();
}

void
layout_prefs_destroy(GtkWidget *main_vb)
{
    GtkWidget ** layout_type_buttons = OBJECT_GET_DATA(main_vb, LAYOUT_TYPE_BUTTONS_KEY);

    g_free(layout_type_buttons);
}

