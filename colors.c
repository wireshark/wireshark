/* colors.c
 * Definitions for color structures and routines
 *
 * $Id: colors.c,v 1.23 1999/12/19 09:22:18 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>
#include <sys/types.h>

#include "gtk/main.h"
#include "packet.h"
#include "colors.h"
#include "file.h"
#include "dfilter.h"
#include "ui_util.h"

extern capture_file cf;

static color_filter_t *new_color_filter(colfilter *filters, gchar *name,
				 gchar *filter_string);
static gboolean read_filters(colfilter *filter);
static GtkWidget* create_color_win(colfilter *filter);
static GtkWidget* create_edit_color_filter_win(colfilter *filter,
				 GtkWidget *color_filters,
				 GtkWidget **colorize_filter_name,
				 GtkWidget **colorize_filter_text);
static GtkWidget* create_color_sel_win(colfilter *filter, GdkColor *);
static gboolean get_color(GdkColor *new_color);

GSList *filter_list;

static GdkColormap*	sys_cmap;
static GdkColormap*	our_cmap = NULL;

static GtkWidget *colorize_win;

static gchar *titles[2] = { "Name", "Filter String" };
GdkColor	WHITE = { 0, 65535, 65535, 65535 };
GdkColor	BLACK = { 0, 0, 0, 0 };

#define COLOR_CHANGE_COLORS_LB	"color_change_colors_lb"
#define COLOR_FILTERS_CL	"color_filters_cl"

/* This structure is used to allow you to compile in default colors if
 * you wish.  They can be later changed by a user.
 */
#ifdef READ_DEFAULT_COLOR_LIST
struct _default_colors {
	gchar* proto;
	gchar* color; /* background only */
} default_colors[]  = {
	{"arp",	"green2"},
	{"ip",	"light red"},
	{"tcp",  "light blue"}
};
#endif

colfilter *
colfilter_new(void)
{
  colfilter *filter;
  gboolean got_white, got_black;
#ifdef READ_DEFAULT_COLOR_LIST
  color_filter_t *colorf;
  gint i;
  GdkColor color;
#endif

  filter = (colfilter *)g_malloc(sizeof(colfilter));
  filter->num_of_filters = 0;

  sys_cmap = gdk_colormap_get_system();

  /* Allocate "constant" colors. */
  got_white = get_color(&WHITE);
  got_black = get_color(&BLACK);

  /* Got milk? */
  if (!got_white) {
    if (!got_black)
      simple_dialog(ESD_TYPE_WARN, NULL, "Could not allocate colors black or white.");
    else
      simple_dialog(ESD_TYPE_WARN, NULL, "Could not allocate color white.");
  } else {
    if (!got_black)
      simple_dialog(ESD_TYPE_WARN, NULL, "Could not allocate color black.");
  }

#ifdef READ_DEFAULT_COLOR_LIST
  /* Now process defaults */
  for (i = 0 ; i < sizeof default_colors/sizeof (struct _default_colors); i++){
	gdk_color_parse(default_colors[i].color, &color);
	
	if( !get_color(&color)){
		/* oops */
		simple_dialog(ESD_TYPE_WARN, NULL, "Could not allocate color %s.",
		    default_colors[i].color);
	}

	colorf = new_color_filter(filter, default_colors[i].proto,
	    default_colors[i].proto);
	colorf->bg_color = color;

	if (dfilter_compile(default_colors[i].proto,
	    &colorf->c_colorfilter) != 0) {
		simple_dialog(ESD_TYPE_WARN, NULL,
		  "Cannot compile default color filter %s.\n%s",
		  default_colors[i].proto, dfilter_error_msg);
		/* should reject this filter */
	}
	filter->num_of_filters++;
  }
#endif
  read_filters(filter);
  return filter;
}

static color_filter_t *
new_color_filter(colfilter *filters, gchar *name, gchar *filter_string)
{
	color_filter_t *colorf;

	colorf = (color_filter_t *)g_malloc(sizeof (color_filter_t));
	colorf->filter_name = g_strdup(name);
	colorf->filter_text = g_strdup(filter_string);
	colorf->bg_color = WHITE;
	colorf->fg_color = BLACK;
	colorf->c_colorfilter = NULL;
	filter_list = g_slist_append(filter_list, colorf);
        return colorf;
}

static void
delete_color_filter(color_filter_t *colorf)
{
	if (colorf->filter_name != NULL)
	  g_free(colorf->filter_name);
	if (colorf->filter_text != NULL)
	  g_free(colorf->filter_text);
	if (colorf->c_colorfilter != NULL)
	  dfilter_destroy(colorf->c_colorfilter);
	filter_list = g_slist_remove(filter_list, colorf);
	g_free(colorf);
}

static gboolean
read_filters(colfilter *filter)
{
	/* TODO: Lots more syntax checking on the file */
	/* I hate these fixed length names! TODO: make more dynamic */
	/* XXX - buffer overflow possibility here */
	gchar name[256],filter_exp[256], buf[1024];
	guint16 fg_r, fg_g, fg_b, bg_r, bg_g, bg_b;
	GdkColor fg_color, bg_color;
	color_filter_t *colorf;
	int i;
	FILE *f;
	gchar *path;
	gchar *fname = PF_DIR "/colorfilters";
	dfilter *temp_dfilter;

	/* decide what file to open (from dfilter code) */

	/* should only be called by colors_init.
	 */
	if(filter == NULL)
		return FALSE;
	/* we have a clist */

	path = (gchar *) g_malloc(strlen(getenv("HOME")) + strlen(fname) +  4);
	sprintf(path, "%s/%s", getenv("HOME"), fname);

	if ((f = fopen(path, "r")) == NULL) {
	  if (errno != ENOENT) {
	    simple_dialog(ESD_TYPE_WARN, NULL,
	      "Could not open filter file\n\"%s\": %s.", path,
	      strerror(errno));
	  }
	  g_free(path);
	  return FALSE;
	}
	g_free(path);

	i = 0;

	do{
	  if(!fgets(buf,sizeof buf, f))
		break;
		
	  if(strspn( buf," \t") == (strchr(buf,'*') - buf)){
		/* leading # comment */
		continue;
	  }

	  /* we get the @ delimiter.  It is not in any strings */
	  if(sscanf(buf," @%[^@]@%[^@]@[%hu,%hu,%hu][%hu,%hu,%hu]",
		name, filter_exp, &bg_r, &bg_g, &bg_b, &fg_r, &fg_g, &fg_b) == 8){
		/* we got a filter */

	    if(dfilter_compile(filter_exp, &temp_dfilter) != 0){
		simple_dialog(ESD_TYPE_WARN, NULL,
		 "Could not compile color filter %s from saved filters.\n%s",
		 name, dfilter_error_msg);
		continue;
	    }
            colorf = new_color_filter(filter, name, filter_exp);
	    colorf->c_colorfilter = temp_dfilter;
	    filter->num_of_filters++;
	    fg_color.red = fg_r;
	    fg_color.green = fg_g;
	    fg_color.blue = fg_b;
	    bg_color.red = bg_r;
	    bg_color.green = bg_g;
	    bg_color.blue = bg_b;
	    if( !get_color(&fg_color)){
		/* oops */
		simple_dialog(ESD_TYPE_WARN, NULL, "Could not allocate fg color specified"
		  "in input file for %s.", name);

		i++;
		continue;
	    }
	    if( !get_color(&bg_color)){
		/* oops */
		simple_dialog(ESD_TYPE_WARN, NULL, "Could not allocate bg color specified"
		  "in input file for %s.", name);
		i++;
		continue;
	    }

            colorf->bg_color = bg_color;
            colorf->fg_color = fg_color;
	    i++;
	  }    /* if sscanf */
	} while( !feof(f));
	return TRUE;
}

static void
write_filter(gpointer filter_arg, gpointer file_arg)
{
	color_filter_t *colorf = filter_arg;
	FILE *f = file_arg;

	fprintf(f,"@%s@%s@[%d,%d,%d][%d,%d,%d]\n",
	    colorf->filter_name,
	    colorf->filter_text,
	    colorf->bg_color.red,
	    colorf->bg_color.green,
	    colorf->bg_color.blue,
	    colorf->fg_color.red,
	    colorf->fg_color.green,
	    colorf->fg_color.blue);
}
	
static gboolean
write_filters(colfilter *filter)
{
	FILE *f;
	gchar *path;
	gchar *name = PF_DIR "/colorfilters";
	/* decide what file to open (from dfilter code) */
	path = (gchar *) g_malloc(strlen(getenv("HOME")) + strlen(name) +  4);
	sprintf(path, "%s/%s", getenv("HOME"), name);

	if ((f = fopen(path, "w+")) == NULL) {
	  simple_dialog(ESD_TYPE_WARN, NULL,
		"Could not open\n%s\nfor writing: %s.",
		path, strerror(errno));
	  g_free(path);
	  return FALSE;
	}
        fprintf(f,"# DO NOT EDIT THIS FILE!  It was created by Ethereal\n");
        g_slist_foreach(filter_list, write_filter, f);
	fclose(f);
	g_free(path);
	return TRUE;
}

		
/* ===================== USER INTERFACE ====================== */
void
color_display_cb(GtkWidget *w, gpointer d)
{
  if (colorize_win != NULL) {
    /* There's already a color dialog box active; raise it.
       XXX - give it focus, too.  Alas, GDK has nothing that
       calls "XSetInputFocus()" on a window.... */
    gdk_window_raise(colorize_win->window);
  } else {
    colorize_win = create_color_win(cf.colors);
  }
}

static void
color_cancel_cb                        (GtkWidget       *widget,
                                        gpointer         user_data)
{
  /* Delete the dialog box */
  gtk_widget_destroy(colorize_win);
  colorize_win = NULL;
}

static void
color_delete_cb(GtkWidget *widget, gpointer user_data)
{
  colfilter *filter;
  GtkWidget *color_filters;
  color_filter_t *colorf;
  GtkWidget *color_change_colors;

  filter = (colfilter *)user_data;
  if(filter->row_selected != -1){
  	color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(widget),
		      COLOR_FILTERS_CL);
  	colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters),
	   filter->row_selected);
	gtk_clist_remove(GTK_CLIST(color_filters), filter->row_selected);
	delete_color_filter(colorf);
	filter->num_of_filters--;
        if(!filter->num_of_filters){
        	/* No filters any more, so none can be selected... */
		filter->row_selected = -1;
		color_change_colors =
		    (GtkWidget *) gtk_object_get_data(GTK_OBJECT(widget),
		      COLOR_CHANGE_COLORS_LB);

		/* ...and none can be edited. */
		gtk_widget_set_sensitive (color_change_colors, FALSE);
	} else {
		filter->row_selected--;
		if(filter->row_selected < 0)
			filter->row_selected = 0;
		gtk_clist_select_row(GTK_CLIST(color_filters),
		    filter->row_selected, 0);
	}
  }
}

/* Move the selected filter up in the list */
static void
color_filter_up_cb                     (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  gint filter_number;
  GtkWidget *color_filters;
  color_filter_t *colorf;

  filter = (colfilter *)user_data;
  filter_number = filter->row_selected;

  /* If it is filter number 0, it cannot be moved, as it's already
     at the top of the filter.
     If there's only one filter in the list, it cannot be moved,
     as there's no place to move it. */
  if(filter_number != 0 && filter->num_of_filters >= 2) {
  	color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
        colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters),
	   filter_number);
	gtk_clist_swap_rows(GTK_CLIST(color_filters), filter_number,
			filter_number-1);
	filter_list = g_slist_remove(filter_list, colorf);
	filter_list = g_slist_insert(filter_list, colorf, filter_number-1);
	filter->row_selected--;
  }
}

/* Move the selected filter down in the list */
static void
color_filter_down_cb                   (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  gint filter_number;
  GtkWidget *color_filters;
  color_filter_t *colorf;

  filter = (colfilter *)user_data;
  filter_number = filter->row_selected;

  /* If it is the last filter in the list, it cannot be moved, as it's
     already at the bottom of the filter.
     If there's only one filter in the list, it cannot be moved,
     as there's no place to move it. */
  if(filter_number != filter->num_of_filters-1 && filter->num_of_filters >= 2) {
  	color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
        colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters),
	   filter_number);
	gtk_clist_swap_rows(GTK_CLIST(color_filters), filter_number+1,
			filter_number);
	filter_list = g_slist_remove(filter_list, colorf);
	filter_list = g_slist_insert(filter_list, colorf, filter_number+1);
	filter->row_selected++;
  }
  else
	return;
}

/* Set selected row in cf */
static void
remember_selected_row                 (GtkCList        *clist,
                                        gint             row,
                                        gint             column,
                                        GdkEvent        *event,
                                        gpointer         user_data)
{
  colfilter *filter = (colfilter *)user_data;

  filter->row_selected = row;
}

static GtkWidget *filt_name_entry;
static GtkWidget *filt_text_entry;

/* Create a new filter in the list */
static void
color_new_cb                          (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  color_filter_t *colorf;
  GtkWidget *color_filters;
  gchar *data[2];
  gint row;
  GtkWidget *color_change_colors;

  filter = (colfilter *)user_data;
  colorf = new_color_filter(filter, "name", "filter"); /* Adds at end! */

  color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
  data[0] = colorf->filter_name;
  data[1] = colorf->filter_text;
  row = gtk_clist_append(GTK_CLIST(color_filters), data);
  gtk_clist_set_row_data(GTK_CLIST(color_filters), row, colorf);

  /* A row has been added, so we can edit it. */
  color_change_colors = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
					COLOR_CHANGE_COLORS_LB);
  gtk_widget_set_sensitive (color_change_colors, TRUE);

  /* select the new (last) row */
  filter->row_selected = filter->num_of_filters;
  filter->num_of_filters++;
  gtk_clist_select_row(GTK_CLIST(color_filters), filter->row_selected, -1);
  create_edit_color_filter_win(filter, color_filters, &filt_name_entry,
				&filt_text_entry);
}

/* Change a filter */
static void
color_edit_cb                        (GtkButton       *button,
                                      gpointer         user_data)
{
  colfilter *filter;
  GtkWidget *color_filters;

  filter = (colfilter *)user_data;
  color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
  if(filter->row_selected == -1){
	/* select the first row */
	filter->row_selected = 0;
	gtk_clist_select_row(GTK_CLIST(color_filters), filter->row_selected,
				-1);
  }
  create_edit_color_filter_win(filter, color_filters, &filt_name_entry,
				&filt_text_entry);
}


/* save filters in file */
static void
color_save_cb                          (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter = (colfilter *)user_data;

  if (!write_filters(filter))
	simple_dialog(ESD_TYPE_WARN, NULL, "Could not open filter file: %s",
	    strerror(errno));

}

/* Exit dialog and process list */
static void
color_ok_cb                            (GtkButton       *button,
                                        gpointer         user_data)
{
  /* colorize list */
  colorize_packets(&cf);

  /* Delete the dialog box */
  gtk_widget_destroy(colorize_win);
  colorize_win = NULL;
}

/* Process all data by applying filters in list */
static void
color_apply_cb                         (GtkButton       *button,
                                        gpointer         user_data)
{
  colorize_packets(&cf);
}

/* Exit dialog and do not process list */
static void
edit_color_filter_cancel_cb            (GtkObject       *object,
                                        gpointer         user_data)
{

  GtkWidget *dialog;
  dialog = (GtkWidget *)user_data;

  gtk_widget_destroy(dialog);
}

static gint bg_set_flag; /* 0 -> setting foreground, 1-> setting background */
/* Change the foreground color */
static void
edit_color_filter_fg_cb                (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  GtkWidget *color_filters;
  color_filter_t *colorf;

  filter = (colfilter *)user_data;
  color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
  colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters),
	   filter->row_selected);
  create_color_sel_win(filter, &colorf->fg_color);
  bg_set_flag = 0;
}

/* Change the background color */
static void
edit_color_filter_bg_cb                (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  GtkWidget *color_filters;
  color_filter_t *colorf;

  filter = (colfilter *)user_data;
  color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
  colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters),
	   filter->row_selected);
  create_color_sel_win(filter, &colorf->bg_color);
  bg_set_flag = 1;
}

/* accept color (and potential content) change */
static void
edit_color_filter_ok_cb                (GtkButton       *button,
                                        gpointer         user_data)
{
  GtkWidget *dialog;
  GtkStyle *style;
  GdkColor new_fg_color;
  GdkColor new_bg_color;
  gchar *filter_name;
  gchar *filter_text;
  color_filter_t *colorf;
  dfilter *compiled_filter;
  GtkWidget *color_filters;

  dialog = (GtkWidget *)user_data;

  style = gtk_widget_get_style(filt_name_entry);
  new_bg_color = style->base[GTK_STATE_NORMAL];
  new_fg_color = style->fg[GTK_STATE_NORMAL];

  filter_name = g_strdup(gtk_entry_get_text(GTK_ENTRY(filt_name_entry)));
  filter_text = g_strdup(gtk_entry_get_text(GTK_ENTRY(filt_text_entry)));

  if(strchr(filter_name,'@') || strchr(filter_text,'@')){
	simple_dialog(ESD_TYPE_WARN,NULL, "Filter names and strings must not"
	  " use the '@' character. Filter unchanged.");
	g_free(filter_name);
  	g_free(filter_text);
	return;
  }

  if(dfilter_compile(filter_text, &compiled_filter) != 0 ){
	simple_dialog(ESD_TYPE_WARN, NULL, "Filter \"%s\" did not compile correctly.\n"
		" Please try again. Filter unchanged.\n%s\n", filter_name,
		dfilter_error_msg);
  } else {
	color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
	colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters),
	   cf.colors->row_selected);

	if (colorf->filter_name != NULL)
	    g_free(colorf->filter_name);
	colorf->filter_name = filter_name;
	if (colorf->filter_text != NULL)
	    g_free(colorf->filter_text);
	colorf->filter_text = filter_text;
	colorf->fg_color = new_fg_color;
	colorf->bg_color = new_bg_color;
	gtk_clist_set_foreground(GTK_CLIST(color_filters),
	    cf.colors->row_selected, &new_fg_color);
	gtk_clist_set_background(GTK_CLIST(color_filters),
	    cf.colors->row_selected, &new_bg_color);
	if(colorf->c_colorfilter != NULL)
	    dfilter_destroy(colorf->c_colorfilter);
	colorf->c_colorfilter = compiled_filter;
	/* gtk_clist_set_text frees old text (if any) and allocates new space */
	gtk_clist_set_text(GTK_CLIST(color_filters),
		cf.colors->row_selected, 0, filter_name);
	gtk_clist_set_text(GTK_CLIST(color_filters),
		cf.colors->row_selected, 1, filter_text);
        gtk_widget_destroy(dialog);
  }
}

/* Revert to existing colors */
static void
color_sel_cancel_cb                    (GtkObject       *object,
                                        gpointer         user_data)
{
  GtkWidget *color_dialog;
  color_dialog = (GtkWidget *)user_data;
  /* nothing to change here.  Just get rid of the dialog box. */

  gtk_widget_destroy(color_dialog);
}

/* Retrieve selected color */
static void
color_sel_ok_cb                        (GtkButton       *button,
                                        gpointer         user_data)
{
  GdkColor new_color; /* Color from color selection dialog */
  gdouble new_colors[3];
  GtkWidget *color_dialog;
  GtkStyle  *style;

  color_dialog = (GtkWidget *)user_data;

  gtk_color_selection_get_color(GTK_COLOR_SELECTION(
   GTK_COLOR_SELECTION_DIALOG(color_dialog)->colorsel), new_colors);

  new_color.red   = (guint16)(new_colors[0]*65535.0);
  new_color.green = (guint16)(new_colors[1]*65535.0);
  new_color.blue  = (guint16)(new_colors[2]*65535.0);

  if ( ! get_color(&new_color) ){
	simple_dialog(ESD_TYPE_WARN, NULL, "Could not allocate color.  Try again.");
  } else {
	gtk_widget_destroy(color_dialog);

	/* now apply the change to the fore/background */
	
	style = gtk_style_copy(gtk_widget_get_style(filt_name_entry));
	if( bg_set_flag)
	  style->base[GTK_STATE_NORMAL] = new_color;
	else
	  style->fg[GTK_STATE_NORMAL] = new_color;
	gtk_widget_set_style(filt_name_entry, style);
	gtk_widget_set_style(filt_text_entry, style);	
  }
}

static void
add_filter_to_clist(gpointer filter_arg, gpointer clist_arg)
{
  color_filter_t *colorf = filter_arg;
  GtkWidget *color_filters = clist_arg;
  gchar *data[2];
  gint row;

  data[0] = colorf->filter_name;
  data[1] = colorf->filter_text;
  row = gtk_clist_append(GTK_CLIST(color_filters), data);
  gtk_clist_set_row_data(GTK_CLIST(color_filters), row, colorf);
  gtk_clist_set_foreground(GTK_CLIST(color_filters), row, &colorf->fg_color);
  gtk_clist_set_background(GTK_CLIST(color_filters), row, &colorf->bg_color);
}

static GtkWidget*
create_color_win (colfilter *filter)
{
  GtkWidget *color_win;
  GtkWidget *vbox1;
  GtkWidget *hbox1;
  GtkWidget *vbox2;
  GtkWidget *color_filter_up;
  GtkWidget *label4;
  GtkWidget *color_filter_down;
  GtkWidget *scrolledwindow1;
  GtkWidget *color_filters;
  GtkWidget *hbox2;
  GtkWidget *color_new;
  GtkWidget *color_change_colors;
  GtkWidget *color_delete;
  GtkWidget *color_save;
  GtkWidget *hbox3;
  GtkWidget *color_ok;
  GtkWidget *color_apply;
  GtkWidget *color_cancel;
  GtkTooltips *tooltips;

  filter->row_selected = -1; /* no row selected */
  tooltips = gtk_tooltips_new ();

  color_win = gtk_window_new (GTK_WINDOW_DIALOG);
  gtk_object_set_data (GTK_OBJECT (color_win), "color_win", color_win);
  gtk_window_set_title (GTK_WINDOW (color_win), ("Add color to protocols"));

  vbox1 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox1);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "vbox1", vbox1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox1);
  gtk_container_add (GTK_CONTAINER (color_win), vbox1);

  hbox1 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox1);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "hbox1", hbox1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox1);
  gtk_box_pack_start (GTK_BOX (vbox1), hbox1, TRUE, TRUE, 0);

  vbox2 = gtk_vbox_new (TRUE, 0);
  gtk_widget_ref (vbox2);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "vbox2", vbox2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox2);
  gtk_box_pack_start (GTK_BOX (hbox1), vbox2, FALSE, TRUE, 0);
  gtk_widget_set_usize (vbox2, 150, -2);

  color_filter_up = gtk_button_new_with_label (("Up"));
  gtk_widget_ref (color_filter_up);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_filter_up", color_filter_up,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_filter_up);
  gtk_box_pack_start (GTK_BOX (vbox2), color_filter_up, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_filter_up, ("Move filter higher in list"), NULL);

  label4 = gtk_label_new (("Move filter\nup or down\n[List is processed \n"
			  "in order until\nmatch is found]"));
  gtk_widget_ref (label4);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "label4", label4,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (label4);
  gtk_box_pack_start (GTK_BOX (vbox2), label4, FALSE, FALSE, 0);

  color_filter_down = gtk_button_new_with_label (("Down"));
  gtk_widget_ref (color_filter_down);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_filter_down", color_filter_down,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_filter_down);
  gtk_box_pack_start (GTK_BOX (vbox2), color_filter_down, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_filter_down, ("Move filter lower in list"), NULL);

  scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_ref (scrolledwindow1);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "scrolledwindow1", scrolledwindow1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (scrolledwindow1);
  gtk_box_pack_start (GTK_BOX (hbox1), scrolledwindow1, TRUE, TRUE, 0);

  color_filters = gtk_clist_new_with_titles(2, titles);

#if 0
  /* I don't seem to need this, but just in case, I'll if0 it */
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_filters",
                            color_filters,
                            (GtkDestroyNotify) gtk_widget_unref);
#endif
  g_slist_foreach(filter_list, add_filter_to_clist, color_filters);

  gtk_widget_show (color_filters);
  gtk_container_add (GTK_CONTAINER (scrolledwindow1), color_filters);
  gtk_widget_set_usize (color_filters, 300, -2);
  gtk_clist_set_column_width (GTK_CLIST (color_filters), 0, 80);
  gtk_clist_set_column_width (GTK_CLIST (color_filters), 1, 80);
  gtk_clist_column_titles_show (GTK_CLIST (color_filters));

  hbox2 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox2);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "hbox2", hbox2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox2);
  gtk_box_pack_start (GTK_BOX (vbox1), hbox2, TRUE, FALSE, 5);
  gtk_widget_set_usize (hbox2, -2, 40);

  color_new = gtk_button_new_with_label (("New"));
  gtk_widget_ref (color_new);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_new", color_new,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_new);
  gtk_box_pack_start (GTK_BOX (hbox2), color_new, TRUE, FALSE, 5);
  gtk_widget_set_usize (color_new, 50, 30);
  gtk_tooltips_set_tip (tooltips, color_new, ("Create a new colorization filter after selected filter"), NULL);

  color_change_colors = gtk_button_new_with_label (("Edit"));
  gtk_widget_ref (color_change_colors);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_change_colors", color_change_colors,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_change_colors);
  gtk_widget_set_usize(color_change_colors, 50, 30);
  gtk_box_pack_start (GTK_BOX (hbox2), color_change_colors, TRUE, FALSE, 5);
  gtk_tooltips_set_tip (tooltips, color_change_colors, ("Change color of selected filter"), NULL);
  gtk_widget_set_sensitive (color_change_colors,
      (filter->num_of_filters != 0));

  color_delete = gtk_button_new_with_label (("Delete"));
  gtk_widget_ref (color_delete);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_delete", color_delete,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_delete);
  gtk_box_pack_start (GTK_BOX (hbox2), color_delete, TRUE, FALSE, 5);
  gtk_widget_set_usize (color_delete, 50, 30);
  gtk_tooltips_set_tip (tooltips, color_delete, ("Delete selected colorization filter"), NULL);

  color_save = gtk_button_new_with_label (("Save"));
  gtk_widget_ref (color_save);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_save", color_save,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_save);
  gtk_box_pack_start (GTK_BOX (hbox2), color_save, TRUE, FALSE, 5);
  gtk_widget_set_usize (color_save, 50, 30);
  gtk_tooltips_set_tip (tooltips, color_save, ("Save all filters to disk"), NULL);

  hbox3 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox3);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "hbox3", hbox3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox3);
  gtk_box_pack_start (GTK_BOX (vbox1), hbox3, TRUE, FALSE, 5);
  gtk_widget_set_usize (hbox3, 177, 40);

  color_ok = gtk_button_new_with_label (("OK"));
  gtk_widget_ref (color_ok);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_ok", color_ok,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_ok);
  gtk_box_pack_start (GTK_BOX (hbox3), color_ok, TRUE, FALSE, 0);
  gtk_widget_set_usize (color_ok, 50, 30);
  gtk_tooltips_set_tip (tooltips, color_ok, ("Accept filter list; apply changes"), NULL);

  color_apply = gtk_button_new_with_label (("Apply"));
  gtk_widget_ref (color_apply);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_apply", color_apply,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_apply);
  gtk_box_pack_start (GTK_BOX (hbox3), color_apply, TRUE, FALSE, 0);
  gtk_widget_set_usize (color_apply, 50, 30);
  gtk_tooltips_set_tip (tooltips, color_apply, ("Apply filters in list"), NULL);

  color_cancel = gtk_button_new_with_label (("Cancel"));
  gtk_widget_ref (color_cancel);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_cancel", color_cancel,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_cancel);
  gtk_box_pack_start (GTK_BOX (hbox3), color_cancel, TRUE, FALSE, 0);
  gtk_widget_set_usize (color_cancel, 50, 30);
  gtk_tooltips_set_tip (tooltips, color_cancel, ("No more filter changes; don't apply"), NULL);

  gtk_object_set_data(GTK_OBJECT (color_filter_up), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (color_filter_up), "clicked",
                      GTK_SIGNAL_FUNC (color_filter_up_cb),
                      filter);
  gtk_object_set_data(GTK_OBJECT (color_filter_down), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (color_filter_down), "clicked",
                      GTK_SIGNAL_FUNC (color_filter_down_cb),
                      filter);
  gtk_signal_connect (GTK_OBJECT (color_filters), "select_row",
                      GTK_SIGNAL_FUNC (remember_selected_row),
                      filter);
  gtk_object_set_data(GTK_OBJECT (color_new), COLOR_CHANGE_COLORS_LB,
                      color_change_colors);
  gtk_object_set_data(GTK_OBJECT (color_new), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (color_new), "clicked",
                      GTK_SIGNAL_FUNC (color_new_cb),
                      filter);
  gtk_object_set_data(GTK_OBJECT (color_change_colors), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (color_change_colors), "clicked",
                      GTK_SIGNAL_FUNC (color_edit_cb),
                      filter);
  gtk_object_set_data(GTK_OBJECT (color_delete), COLOR_CHANGE_COLORS_LB,
                      color_change_colors);
  gtk_object_set_data(GTK_OBJECT (color_delete), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (color_delete), "clicked",
                      GTK_SIGNAL_FUNC (color_delete_cb),
                      filter);
  gtk_signal_connect (GTK_OBJECT (color_save), "clicked",
                      GTK_SIGNAL_FUNC (color_save_cb),
                      filter);
  gtk_signal_connect (GTK_OBJECT (color_ok), "clicked",
                      GTK_SIGNAL_FUNC (color_ok_cb),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (color_apply), "clicked",
                      GTK_SIGNAL_FUNC (color_apply_cb),
                      filter);
  gtk_signal_connect (GTK_OBJECT (color_cancel), "clicked",
                      GTK_SIGNAL_FUNC (color_cancel_cb),
                      NULL);

  gtk_widget_grab_focus (color_filters);
  gtk_object_set_data (GTK_OBJECT (color_win), "tooltips", tooltips);
  gtk_widget_show (color_win);

  return color_win;
}

static GtkWidget*
create_edit_color_filter_win (colfilter *filter,
	GtkWidget *color_filters,
	GtkWidget **colorize_filter_name,
	GtkWidget **colorize_filter_text)
{
  color_filter_t *colorf;
  GtkWidget *colorize_win;
  GtkWidget *vbox3;
  GtkWidget *hbox6;
  GtkWidget *color_filter_name;
  GtkWidget *hbox7;
  GtkWidget *color_filter_text;
  GtkWidget *hbox5;
  GtkWidget *colorize_filter_fg;
  GtkWidget *colorize_filter_bg;
  GtkWidget *hbox4;
  GtkWidget *edit_color_filter_ok;
  GtkWidget *edit_color_filter_cancel;
  GtkTooltips *tooltips;
  GtkStyle  *style;

  colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters),
	   filter->row_selected);

  tooltips = gtk_tooltips_new ();

  colorize_win = gtk_window_new (GTK_WINDOW_DIALOG);
  gtk_object_set_data (GTK_OBJECT (colorize_win), "colorize_win", colorize_win);
  gtk_window_set_title (GTK_WINDOW (colorize_win), ("Edit color filter"));

  vbox3 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox3);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "vbox3", vbox3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox3);
  gtk_container_add (GTK_CONTAINER (colorize_win), vbox3);

  hbox6 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox6);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "hbox6", hbox6,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox6);
  gtk_box_pack_start (GTK_BOX (vbox3), hbox6, TRUE, FALSE, 5);

  color_filter_name = gtk_label_new (("Name: "));
  gtk_widget_ref (color_filter_name);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "color_filter_name", color_filter_name,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_filter_name);
  gtk_box_pack_start (GTK_BOX (hbox6), color_filter_name, FALSE, FALSE, 0);

  *colorize_filter_name = gtk_entry_new ();
  gtk_widget_ref (*colorize_filter_name);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "*colorize_filter_name", *colorize_filter_name,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_entry_set_text(GTK_ENTRY(*colorize_filter_name), colorf->filter_name);

  style = gtk_style_copy(gtk_widget_get_style(*colorize_filter_name));
  style->base[GTK_STATE_NORMAL] = colorf->bg_color;
  style->fg[GTK_STATE_NORMAL]   = colorf->fg_color;
  gtk_widget_set_style(*colorize_filter_name, style);

  gtk_widget_show (*colorize_filter_name);
  gtk_box_pack_start (GTK_BOX (hbox6), *colorize_filter_name, TRUE, TRUE, 0);
  gtk_tooltips_set_tip (tooltips, *colorize_filter_name, ("This is the editable name of the filter. (No @ characters allowed.)"), NULL);

  hbox7 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox7);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "hbox7", hbox7,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox7);
  gtk_box_pack_start (GTK_BOX (vbox3), hbox7, TRUE, FALSE, 5);

  color_filter_text = gtk_label_new (("Filter text:"));
  gtk_widget_ref (color_filter_text);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "color_filter_text", color_filter_text,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_filter_text);
  gtk_box_pack_start (GTK_BOX (hbox7), color_filter_text, FALSE, FALSE, 0);

  *colorize_filter_text = gtk_entry_new ();
  gtk_widget_ref (*colorize_filter_text);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "*colorize_filter_text", *colorize_filter_text,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_entry_set_text(GTK_ENTRY(*colorize_filter_text), colorf->filter_text);
#if 0
  style = gtk_style_copy(gtk_widget_get_style(*colorize_filter_text));
  style->base[GTK_STATE_NORMAL] = colorf->bg_color;
  style->fg[GTK_STATE_NORMAL]   = colorf->fg_color;
#endif
  gtk_widget_set_style(*colorize_filter_text, style);
  gtk_widget_show (*colorize_filter_text);
  gtk_box_pack_start (GTK_BOX (hbox7), *colorize_filter_text, TRUE, TRUE, 0);
  gtk_tooltips_set_tip (tooltips, *colorize_filter_text, ("This is the editable text of the filter"), NULL);

  hbox5 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox5);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "hbox5", hbox5,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox5);
  gtk_box_pack_start (GTK_BOX (vbox3), hbox5, FALSE, FALSE, 5);
  gtk_widget_set_usize (hbox5, -2, 60);

  colorize_filter_fg = gtk_button_new_with_label (("Choose \nforeground\ncolor"));
  gtk_widget_ref (colorize_filter_fg);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "colorize_filter_fg", colorize_filter_fg,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (colorize_filter_fg);
  gtk_box_pack_start (GTK_BOX (hbox5), colorize_filter_fg, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, colorize_filter_fg, ("Select color for data display"), NULL);

  colorize_filter_bg = gtk_button_new_with_label (("Choose\nbackground\ncolor"));
  gtk_widget_ref (colorize_filter_bg);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "colorize_filter_bg", colorize_filter_bg,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (colorize_filter_bg);
  gtk_box_pack_start (GTK_BOX (hbox5), colorize_filter_bg, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, colorize_filter_bg, ("Select color for data display"), NULL);

  hbox4 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox4);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "hbox4", hbox4,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox4);
  gtk_box_pack_start (GTK_BOX (vbox3), hbox4, TRUE, FALSE, 5);
  gtk_widget_set_usize (hbox4, -2, 40);

  edit_color_filter_ok = gtk_button_new_with_label (("OK"));
  gtk_widget_ref (edit_color_filter_ok);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "edit_color_filter_ok", edit_color_filter_ok,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_set_usize (edit_color_filter_ok, 50, 30);
  gtk_widget_show (edit_color_filter_ok);
  gtk_box_pack_start (GTK_BOX (hbox4), edit_color_filter_ok, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, edit_color_filter_ok, ("Accept filter color change"), NULL);

  edit_color_filter_cancel = gtk_button_new_with_label (("Cancel"));
  gtk_widget_ref (edit_color_filter_cancel);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "edit_color_filter_cancel", edit_color_filter_cancel,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_set_usize (edit_color_filter_cancel, 50, 30);
  gtk_widget_show (edit_color_filter_cancel);
  gtk_box_pack_start (GTK_BOX (hbox4), edit_color_filter_cancel, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, edit_color_filter_cancel, ("Reject filter color change"), NULL);
#if 0
  gtk_signal_connect (GTK_OBJECT (colorize_win), "destroy",
                      GTK_SIGNAL_FUNC (edit_color_filter_cancel_cb),
                      colorize_win);
#endif
  gtk_object_set_data(GTK_OBJECT (colorize_filter_fg), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (colorize_filter_fg), "clicked",
                      GTK_SIGNAL_FUNC (edit_color_filter_fg_cb),
                      filter);
  gtk_object_set_data(GTK_OBJECT (colorize_filter_bg), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (colorize_filter_bg), "clicked",
                      GTK_SIGNAL_FUNC (edit_color_filter_bg_cb),
                      filter);
  gtk_object_set_data(GTK_OBJECT (edit_color_filter_ok), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (edit_color_filter_ok), "clicked",
                      GTK_SIGNAL_FUNC (edit_color_filter_ok_cb),
                      colorize_win);
  gtk_signal_connect (GTK_OBJECT (edit_color_filter_cancel), "clicked",
                      GTK_SIGNAL_FUNC (edit_color_filter_cancel_cb),
                      colorize_win);

  gtk_object_set_data (GTK_OBJECT (colorize_win), "tooltips", tooltips);
  gtk_widget_show (colorize_win);
  return colorize_win;
}

static GtkWidget*
create_color_sel_win (colfilter *filter, GdkColor * color)
{
  GtkWidget *color_sel_win;
  GtkWidget *color_sel_ok;
  GtkWidget *color_sel_cancel;
  GtkWidget *color_sel_help;

  color_sel_win = gtk_color_selection_dialog_new (("Choose color"));
  gtk_object_set_data (GTK_OBJECT (color_sel_win), "color_sel_win", color_sel_win);
  gtk_container_set_border_width (GTK_CONTAINER (color_sel_win), 10);

  if (color != NULL) {
    gdouble cols[3];

    cols[0] = (gdouble)color->red / 65536.0;
    cols[1] = (gdouble)color->green / 65536.0;
    cols[2] = (gdouble)color->blue / 65536.0;

    gtk_color_selection_set_color(
		    GTK_COLOR_SELECTION(
			    GTK_COLOR_SELECTION_DIALOG(color_sel_win)->colorsel), cols);
  }

  color_sel_ok = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->ok_button;
  gtk_object_set_data (GTK_OBJECT (color_sel_win), "color_sel_ok", color_sel_ok);
  gtk_widget_show (color_sel_ok);
  GTK_WIDGET_SET_FLAGS (color_sel_ok, GTK_CAN_DEFAULT);

  color_sel_cancel = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->cancel_button;
  gtk_object_set_data (GTK_OBJECT (color_sel_win), "color_sel_cancel", color_sel_cancel);
  gtk_widget_show (color_sel_cancel);
  GTK_WIDGET_SET_FLAGS (color_sel_cancel, GTK_CAN_DEFAULT);


  color_sel_help = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->help_button;
  gtk_object_set_data (GTK_OBJECT (color_sel_win), "color_sel_help", color_sel_help);
  gtk_widget_show (color_sel_help);


  GTK_WIDGET_SET_FLAGS (color_sel_help, GTK_CAN_DEFAULT);
#if 0
  gtk_signal_connect (GTK_OBJECT (color_sel_win), "destroy",
                      GTK_SIGNAL_FUNC (color_sel_cancel_cb),
                      color_sel_win);
#endif

  gtk_signal_connect (GTK_OBJECT (color_sel_ok), "clicked",
                      GTK_SIGNAL_FUNC (color_sel_ok_cb),
                      color_sel_win);
  gtk_signal_connect (GTK_OBJECT (color_sel_cancel), "clicked",
                      GTK_SIGNAL_FUNC (color_sel_cancel_cb),
                      color_sel_win);

  gtk_widget_show(color_sel_win);
  return color_sel_win;
}

static gboolean
get_color (GdkColor *new_color)
{
    GdkVisual *pv;

    if (!our_cmap) {
	if ( !gdk_colormap_alloc_color (sys_cmap, new_color, FALSE, TRUE)) {
	    pv = gdk_visual_get_best();
	    if ( !(our_cmap = gdk_colormap_new(pv, TRUE)))
		simple_dialog(ESD_TYPE_WARN, NULL, "Could not create new colormap");
	} else
	    return (TRUE);
    }
    return ( gdk_colormap_alloc_color ( our_cmap, new_color, FALSE, TRUE) );
}
