/* colors.c
 * Definitions for color structures and routines
 *
 * $Id: colors.c,v 1.1 1999/08/24 16:27:21 gram Exp $
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
#include <gtk/gtkwidget.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glibconfig.h>
#include <glib.h>

#include <gdk/gdkkeysyms.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <signal.h>

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include "ethereal.h"
#include "packet.h"
#include "colors.h"
#include "file.h"
#include "dfilter.h"
#include "util.h"

extern capture_file cf;

static gboolean read_filters(capture_file *cf);

GdkColor 	proto_colors[MAXCOLORS];
GdkColormap*	sys_cmap;

static gchar *titles[2] = { "Name", "Filter String" };
GdkColor	color_light_gray = { 0, 45000, 45000, 45000 };
GdkColor	WHITE = { 0,65535, 65535, 65535};
GdkColor	BLACK = { 0, 0, 0, 0};

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

void
colors_init(capture_file *cf)
{

#ifdef READ_DEFAULT_COLOR_LIST
  gint i;
  GdkColor color;
#endif
  cf->colors = (colfilter *)g_malloc(sizeof(colfilter));
  cf->colors->num_of_filters = 0;
  cf->colors->color_filters = gtk_clist_new_with_titles(2, titles);

  gtk_widget_ref(cf->colors->color_filters); /* so it doesn't go away */
  /* color_filters will ALWAYS be a GtkCList */
  sys_cmap = gdk_colormap_get_system();

  /* Allocate "constant" colors. */
  if( !gdk_colormap_alloc_color(sys_cmap, &WHITE, TRUE, TRUE)){
	/* oops */
	simple_dialog(ESD_TYPE_WARN, NULL, "Could not allocate color white.");
	fprintf(stderr,"Color allocation failed\n");
        fflush(stderr);
  }

  if( !gdk_colormap_alloc_color(sys_cmap, &BLACK, TRUE, TRUE)){
	/* oops */
	simple_dialog(ESD_TYPE_WARN, NULL, "Could not allocate color black.");
	fprintf(stderr,"Color allocation failed\n");
        fflush(stderr);
  }

#ifdef READ_DEFAULT_COLOR_LIST
  /* Now process defaults */
  for (i = 0 ; i < sizeof default_colors/sizeof (struct _default_colors); i++){
	gdk_color_parse(default_colors[i].color, &color);
	
	if( !gdk_colormap_alloc_color(sys_cmap, &color, TRUE, TRUE)){
		/* oops */
		simple_dialog(ESD_TYPE_WARN, NULL, "Could not allocate color %s.",
		    default_colors[i].color);
		fprintf(stderr,"Color allocation failed\n");
		fflush(stderr);
	}

	new_color_filter(cf->colors, default_colors[i].proto, default_colors[i].proto);
	color_filter(cf,i)->bg_color = color;

	color_filter(cf,i)->c_colorfilter = dfilter_new();
	if(dfilter_compile((color_filter(cf,i)->c_colorfilter),
	  default_colors[i].proto) != 0}{
		simple_dialog(ESD_TYPE_WARN, NULL, "Cannot compile default filter %s.\n%s",
		  default_colors[i].proto, dfilter_error_msg);
		/* should reject this filter */
	}
	cf->colors->num_of_filters++;
  }
#endif
  if(!read_filters(cf))
    /* again, no window because it is not up, yet */
	fprintf(stderr,"Cound not open filter file\n");

  fprintf(stderr,"Colors initialized\n");
  fflush(stderr);
}

void
set_color_filter_name(capture_file *cf, gint n, gchar *str)
{
	
	/* gtk_clist_set_text frees old text (if any) and allocates new space */
	gtk_clist_set_text(GTK_CLIST(cf->colors->color_filters),n,0,str);
}


gchar *
get_color_filter_name(capture_file *cf, gint n)
{
	gchar *filter_name;
	gtk_clist_get_text(GTK_CLIST(cf->colors->color_filters),n,0,
		(gchar **)&filter_name);
	return filter_name;
}

void
set_color_filter_string(capture_file *cf, gint n, gchar *str)
{

	gtk_clist_set_text(GTK_CLIST(cf->colors->color_filters),n,1,str);
}


gchar *
get_color_filter_string(capture_file *cf, gint n)
{
	gchar *filter_string;
	gtk_clist_get_text(GTK_CLIST(cf->colors->color_filters),n,1,
		(gchar **)&filter_string);
	return filter_string;
}

color_filter_t *
color_filter(capture_file *cf, gint n)
{
	return gtk_clist_get_row_data(GTK_CLIST(cf->colors->color_filters),n);
}

void
new_color_filter(colfilter *filters, gchar *name, gchar *filter_string)
{
	color_filter_t *colorf;
        gchar *data[2];
	
	gint row;

	data[0] = g_strdup(name);
	data[1] = g_strdup(filter_string);
        row = gtk_clist_append(GTK_CLIST(filters->color_filters), data);

	colorf = (color_filter_t *)g_malloc(sizeof (color_filter_t));
	colorf->bg_color = WHITE;
	colorf->fg_color = BLACK;
	colorf->c_colorfilter = NULL;
 	gtk_clist_set_row_data(GTK_CLIST(filters->color_filters), row, colorf);
}

static gboolean
read_filters(capture_file *cf)
{
	/* TODO: Lots more syntax checking on the file */
	/* I hate these fixed length names! TODO: make more dynamic */
	gchar name[256],filter[256], buf[1024];
	guint16 fg_r, fg_g, fg_b, bg_r, bg_g, bg_b;
	GdkColor fg_color, bg_color;

	int i;
	FILE *f;
	gchar *path;
	gchar *fname = PF_DIR "/colorfilters";
	/* decide what file to open (from dfilter code) */

	/* should only be called by colors_init.
	 * cf->colors->color_filters must exist
	 */
	if(cf == NULL || cf->colors == NULL || cf->colors->color_filters == NULL)
		return FALSE;
	/* we have a clist */

	path = (gchar *) g_malloc(strlen(getenv("HOME")) + strlen(fname) +  4);
	sprintf(path, "%s/%s", getenv("HOME"), fname);

	if ((f = fopen(path, "r")) == NULL) {
	  g_free(path);
	  return FALSE;
	}

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
		name, filter, &bg_r, &bg_g, &bg_b, &fg_r, &fg_g, &fg_b) == 8){
		/* we got a filter */

            new_color_filter(cf->colors, name, filter);
	    color_filter(cf,i)->c_colorfilter = dfilter_new();
	    if(dfilter_compile((color_filter(cf,i)->c_colorfilter),filter) != 0){
		simple_dialog(ESD_TYPE_WARN, NULL,
		 "Could not compile filter %s from saved filters because\n%s",
		 name, dfilter_error_msg);
	    }
	    cf->colors->num_of_filters++;
	    fg_color.red = fg_r;
	    fg_color.green = fg_g;
	    fg_color.blue = fg_b;
	    bg_color.red = bg_r;
	    bg_color.green = bg_g;
	    bg_color.blue = bg_b;
	    if( !gdk_colormap_alloc_color(sys_cmap, &fg_color, TRUE, TRUE)){
			/* oops */
			simple_dialog(ESD_TYPE_WARN, NULL, "Could not allocate fg color specified"
			    "in input file for %s.", name);

			fprintf(stderr,"Color allocation failed\n");
			fflush(stderr);
			i++;
			continue;
	    }
	    	if( !gdk_colormap_alloc_color(sys_cmap, &bg_color, TRUE, TRUE)){
			/* oops */
			simple_dialog(ESD_TYPE_WARN, NULL, "Could not allocate bg color specified"
			    "in input file for %s.", name);
			fprintf(stderr,"Color allocation failed\n");
			fflush(stderr);
			i++;
			continue;
	    }

        color_filter(cf,i)->bg_color = bg_color;
        color_filter(cf,i)->fg_color = fg_color;
        gtk_clist_set_foreground(GTK_CLIST(cf->colors->color_filters),
			i,&fg_color);
        gtk_clist_set_background(GTK_CLIST(cf->colors->color_filters),
			i,&bg_color);

	    i++;
	  }    /* if sscanf */
	}   while( !feof(f));
	return TRUE;
}

static gboolean
write_filters(capture_file *cf)
{
	int i;
	FILE *f;
	gchar *path;
	gchar *name = PF_DIR "/colorfilters";
	/* decide what file to open (from dfilter code) */
	path = (gchar *) g_malloc(strlen(getenv("HOME")) + strlen(name) +  4);
	sprintf(path, "%s/%s", getenv("HOME"), name);

	if ((f = fopen(path, "w+")) == NULL) {
	  simple_dialog(ESD_TYPE_WARN, NULL, "Could not open\n%s\nfor writing.",
	  	path);
	  g_free(path);
	  return FALSE;
	}
        fprintf(f,"# DO NOT EDIT THIS FILE!  It was created by Ethereal\n");
	for(i = 0; i < cf->colors->num_of_filters; i++){
	  fprintf(f,"@%s@%s@[%d,%d,%d][%d,%d,%d]\n",
		get_color_filter_name(cf,i),
		get_color_filter_string(cf,i),
		color_filter(cf,i)->bg_color.red,
		color_filter(cf,i)->bg_color.green,
		color_filter(cf,i)->bg_color.blue,
		color_filter(cf,i)->fg_color.red,
		color_filter(cf,i)->fg_color.green,
		color_filter(cf,i)->fg_color.blue);
	}
	fclose(f);
	g_free(path);
	return TRUE;
}

		
/* ===================== USER INTERFACE ====================== */
void
color_display_cb(GtkWidget *w, gpointer d)
{
  /* cf already exists as a global */
  /* create the color dialog */
  create_color_win(&cf);

}

void
color_cancel_cb                        (GtkWidget       *widget,
                                        gpointer         user_data)
{
  GtkWidget *win = (GtkWidget *)user_data;
  /* delete the window */
  gtk_container_remove(GTK_CONTAINER(GTK_WIDGET(cf.colors->color_filters)->parent),
	cf.colors->color_filters);
  gtk_widget_destroy(win);
}

void
color_delete_cb(GtkWidget *widget, gpointer user_data)
{
  if(cf.colors->row_selected != -1){
	gtk_clist_remove(GTK_CLIST(cf.colors->color_filters),
	   cf.colors->row_selected);
	cf.colors->num_of_filters--;
        if(!cf.colors->num_of_filters){
		cf.colors->row_selected = -1;
	} else {
		cf.colors->row_selected--;
		if(cf.colors->row_selected < 0)
			cf.colors->row_selected = 0;
		gtk_clist_select_row(GTK_CLIST(cf.colors->color_filters),
		  cf.colors->row_selected,0);
	}
  }
}

/* Move the selected filter up in the list */
void
color_filt_up_cb                       (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  gint filter_number;

  filter = (colfilter *)user_data;

  /* verify filter exists */
  filter_number = filter->row_selected;
  /* if it is filter number 0, it cannot be moved */
  if(filter != NULL &&
     (filter_number = filter->row_selected)  != 0 &&
      filter->num_of_filters >= 2){
	gtk_clist_swap_rows(GTK_CLIST(filter->color_filters),filter_number, filter_number-1);
	filter->row_selected--;
      }
  else {
	return;
  }

}

/* Move the selected filter down in the list */
void
color_filter_down_cb                   (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  gint filter_number;

  filter = (colfilter *)user_data;
  /* verify filter exists */
  filter_number = filter->row_selected;
  if(filter != NULL && 
     (filter_number = filter->row_selected) != filter->num_of_filters-1 && 
      filter->num_of_filters >= 2){
	gtk_clist_swap_rows(GTK_CLIST(filter->color_filters),filter_number+1, filter_number);
	filter->row_selected++;
  }
  else
	return;
}

/* Set selected row in cf */
void
rembember_selected_row                 (GtkCList        *clist,
                                        gint             row,
                                        gint             column,
                                        GdkEvent        *event,
                                        gpointer         user_data)
{
  capture_file *cf;
  cf = (capture_file *) user_data;

  cf->colors->row_selected = row;
}

/* change name to color_new_cb */
static GtkWidget *filt_name_entry;
static GtkWidget *filt_text_entry;

/* Create a new filter in the list */
void
create_new_cb                          (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;

  filter = (colfilter *)user_data;
  new_color_filter(filter, "name", "filter"); /* Adds at end! */
  
  /* select the last row */
  cf.colors->row_selected = cf.colors->num_of_filters;
  cf.colors->num_of_filters++;
  gtk_clist_select_row(GTK_CLIST(cf.colors->color_filters),cf.colors->row_selected,0);
  /* this is the global cf! */
  create_colorize_win(&cf, &filt_name_entry, &filt_text_entry);
}

/* Change a filter */
/* probably should change name to color_edit_cb */
void
color_change_cb                        (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  filter = (colfilter *)user_data;

  if(cf.colors->row_selected == -1){
	  /* select the first row */
	  cf.colors->row_selected = 0;
	  gtk_clist_select_row(GTK_CLIST(cf.colors->color_filters),cf.colors->row_selected,0);
  }
  /* this is the global cf! */
  /*Default colors are in cf in the e entry itself.*/
  create_colorize_win(&cf, &filt_name_entry, &filt_text_entry);
}


/* save filters in file */
void
color_save_cb                          (GtkButton       *button,
                                        gpointer         user_data)
{
  capture_file *cf;
  cf = (capture_file *)user_data;
  if(!write_filters(cf))
	simple_dialog(ESD_TYPE_WARN, NULL, "Could not open filter file!");

}

/* Exit dialog and process list */
void
color_ok_cb                            (GtkButton       *button,
                                        gpointer         user_data)
{
  GtkWidget *dialog;
  dialog = (GtkWidget *)user_data;

  /* colorize list */

  filter_packets(&cf);
  gtk_container_remove(GTK_CONTAINER(GTK_WIDGET(cf.colors->color_filters)->parent),
	cf.colors->color_filters);
  gtk_widget_destroy(dialog);

}

/* Process all data by applying filters in list */
void
color_apply_cb                         (GtkButton       *button,
                                        gpointer         user_data)
{
  capture_file *cf;
  cf = (capture_file *)user_data;
  filter_packets(cf);
}

/* Exit dialog and do not process list */
void
colorize_cancel_cb                     (GtkObject       *object,
                                        gpointer         user_data)
{

  GtkWidget *dialog;
  dialog = (GtkWidget *)user_data;

  gtk_widget_destroy(dialog);
}

static gint bg_set_flag; /* 0 -> setting foreground, 1-> setting background */
/* Change the foreground color */
void
colorize_fg_cb                         (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  filter = (colfilter *)user_data; /* UNUSED */
  create_color_sel_win(&cf);
  bg_set_flag = 0;

}

/* Change the background color */
void
colorize_bg_cb                         (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  filter = (colfilter *)user_data; /* UNUSED */
  create_color_sel_win(&cf);
  bg_set_flag = 1;

}

/* accept color (and potential content) change */
void
colorize_ok_cb                         (GtkButton       *button,
                                        gpointer         user_data)
{
  GtkWidget *dialog;
  GtkStyle *style;
  GdkColor new_fg_color;
  GdkColor new_bg_color;
  gchar *filter_name;
  gchar *filter_text;
  dfilter *compiled_filter;

  dialog = (GtkWidget *)user_data;

  style = gtk_widget_get_style(filt_name_entry);
  new_bg_color = style->base[GTK_STATE_NORMAL];
  new_fg_color = style->fg[GTK_STATE_NORMAL];

  filter_name = g_strdup(gtk_entry_get_text(GTK_ENTRY(filt_name_entry)));
  filter_text = g_strdup(gtk_entry_get_text(GTK_ENTRY(filt_text_entry)));

  if(index(filter_name,'@') || index(filter_text,'@')){
	simple_dialog(ESD_TYPE_WARN,NULL, "Filter names and strings must not"
	  " use the '@' character. Filter unchanged.");
	g_free(filter_name);
  	g_free(filter_text);
	return;
  }
	

  color_filter(&cf,cf.colors->row_selected)->fg_color = new_fg_color;
  color_filter(&cf,cf.colors->row_selected)->bg_color = new_bg_color;
  gtk_clist_set_foreground(GTK_CLIST(cf.colors->color_filters),
	cf.colors->row_selected, &new_fg_color);
  gtk_clist_set_background(GTK_CLIST(cf.colors->color_filters),
	cf.colors->row_selected, &new_bg_color);



  compiled_filter = dfilter_new();
  
  if( dfilter_compile( compiled_filter, filter_text) != 0 ){
	simple_dialog(ESD_TYPE_WARN, NULL, "Filter \"%s\" did not compile correctly.\n"
		" Please try again. Filter unchanged.\n%s\n", filter_name,dfilter_error_msg);
	dfilter_destroy(compiled_filter);
  } else {

	if( color_filter(&cf, cf.colors->row_selected)->c_colorfilter != NULL)
	    dfilter_destroy(color_filter(&cf,cf.colors->row_selected)->c_colorfilter);
	color_filter(&cf,cf.colors->row_selected)->c_colorfilter = compiled_filter;
	set_color_filter_string(&cf,cf.colors->row_selected,filter_text);
	set_color_filter_name(&cf,cf.colors->row_selected,filter_name);
        gtk_widget_destroy(dialog);
  }
  g_free(filter_name);
  g_free(filter_text);


}

/* Revert to existing colors */
void
color_cel_cancel_cb                    (GtkObject       *object,
                                        gpointer         user_data)
{
  GtkWidget *color_dialog;
  color_dialog = (GtkWidget *)user_data;
  /* nothing to change here.  Just get rid of the dialog box. */

  gtk_widget_destroy(color_dialog);
}

/* Retrieve selected color */
void
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

  if ( ! gdk_colormap_alloc_color(sys_cmap, &new_color, TRUE, TRUE) ){
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





GtkWidget*
create_color_win (capture_file *cf)
{
  GtkWidget *color_win;
  GtkWidget *vbox1;
  GtkWidget *hbox1;
  GtkWidget *vbox2;
  GtkWidget *color_filt_up;
  GtkWidget *label4;
  GtkWidget *color_filter_down;
  GtkWidget *scrolledwindow1;
  GtkWidget *clist1;
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

  cf->colors->row_selected = -1; /* no row selected */
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

  color_filt_up = gtk_button_new_with_label (("Up"));
  gtk_widget_ref (color_filt_up);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_filt_up", color_filt_up,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_filt_up);
  gtk_box_pack_start (GTK_BOX (vbox2), color_filt_up, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_filt_up, ("Move filter higher in list"), NULL);

  label4 = gtk_label_new (("Move filter\nup or down\n[List is processed \nin order]"));
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


  /* Do we have a list of filters, yet? */
  if( cf->colors->color_filters == NULL) {
	/* no color filters as of now.
	 * This should probably be an assert...
	 */
        fprintf(stderr,"Null clist\n");
		fflush(stderr);
  }

  clist1 = cf->colors->color_filters;
  gtk_widget_ref (clist1);

#if 0
  /* I don't seem to need this, but just in case, I'll if0 it */
  gtk_object_set_data_full (GTK_OBJECT (color_win), "clist1", clist1,
                            (GtkDestroyNotify) gtk_widget_unref);
#endif

  gtk_widget_show (clist1);
  gtk_container_add (GTK_CONTAINER (scrolledwindow1), clist1);
  gtk_widget_set_usize (clist1, 300, -2);
  gtk_clist_set_column_width (GTK_CLIST (clist1), 0, 80);
  gtk_clist_set_column_width (GTK_CLIST (clist1), 1, 80);
  gtk_clist_column_titles_show (GTK_CLIST (clist1));

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

  gtk_signal_connect (GTK_OBJECT (color_filt_up), "clicked",
                      GTK_SIGNAL_FUNC (color_filt_up_cb),
                      cf->colors);
  gtk_signal_connect (GTK_OBJECT (color_filter_down), "clicked",
                      GTK_SIGNAL_FUNC (color_filter_down_cb),
                      cf->colors);
  gtk_signal_connect (GTK_OBJECT (clist1), "select_row",
                      GTK_SIGNAL_FUNC (rembember_selected_row),
                      cf);
  gtk_signal_connect (GTK_OBJECT (color_new), "clicked",
                      GTK_SIGNAL_FUNC (create_new_cb),
                      cf->colors);
  gtk_signal_connect (GTK_OBJECT (color_change_colors), "clicked",
                      GTK_SIGNAL_FUNC (color_change_cb),
                      cf->colors);
  gtk_signal_connect (GTK_OBJECT (color_delete), "clicked",
                      GTK_SIGNAL_FUNC (color_delete_cb),
                      color_delete);
  gtk_signal_connect (GTK_OBJECT (color_save), "clicked",
                      GTK_SIGNAL_FUNC (color_save_cb),
                      cf);
  gtk_signal_connect (GTK_OBJECT (color_ok), "clicked",
                      GTK_SIGNAL_FUNC (color_ok_cb),
                      color_win);
  gtk_signal_connect (GTK_OBJECT (color_apply), "clicked",
                      GTK_SIGNAL_FUNC (color_apply_cb),
                      cf);
  gtk_signal_connect (GTK_OBJECT (color_cancel), "clicked",
                      GTK_SIGNAL_FUNC (color_cancel_cb),
                      color_win);

  gtk_widget_grab_focus (clist1);
  gtk_object_set_data (GTK_OBJECT (color_win), "tooltips", tooltips);
  gtk_widget_show (color_win);

  return color_win;
}

GtkWidget*
create_colorize_win (capture_file *cf,
	GtkWidget **colorize_filter_name,
	GtkWidget **colorize_filter_text)
	
{
  GtkWidget *colorize_win;
  GtkWidget *vbox3;
  GtkWidget *hbox6;
  GtkWidget *color_filter_name;
  GtkWidget *hbox7;
  GtkWidget *color_filter_text;
  GtkWidget *hbox5;
  GtkWidget *colorize_filter_fg;
  GtkWidget *colorize_protocol_bg;
  GtkWidget *hbox4;
  GtkWidget *colorize_proto_ok;
  GtkWidget *colorize_proto_cancel;
  GtkTooltips *tooltips;
  GtkStyle  *style;

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
  gtk_entry_set_text(GTK_ENTRY(*colorize_filter_name),
	get_color_filter_name(cf, cf->colors->row_selected));

  style = gtk_style_copy(gtk_widget_get_style(*colorize_filter_name));
  style->base[GTK_STATE_NORMAL] = color_filter(cf,cf->colors->row_selected)->bg_color;
  style->fg[GTK_STATE_NORMAL]   = color_filter(cf,cf->colors->row_selected)->fg_color;
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
  gtk_entry_set_text(GTK_ENTRY(*colorize_filter_text),
	get_color_filter_string(cf, cf->colors->row_selected));
#if 0
  style = gtk_style_copy(gtk_widget_get_style(*colorize_filter_text));
  style->base[GTK_STATE_NORMAL] = color_filter(cf,cf->colors->row_selected)->bg_color;
  style->fg[GTK_STATE_NORMAL]   = color_filter(cf,cf->colors->row_selected)->fg_color;
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

  colorize_protocol_bg = gtk_button_new_with_label (("Choose\nbackground\ncolor"));
  gtk_widget_ref (colorize_protocol_bg);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "colorize_protocol_bg", colorize_protocol_bg,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (colorize_protocol_bg);
  gtk_box_pack_start (GTK_BOX (hbox5), colorize_protocol_bg, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, colorize_protocol_bg, ("Select color for data display"), NULL);

  hbox4 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox4);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "hbox4", hbox4,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox4);
  gtk_box_pack_start (GTK_BOX (vbox3), hbox4, TRUE, FALSE, 5);
  gtk_widget_set_usize (hbox4, -2, 40);

  colorize_proto_ok = gtk_button_new_with_label (("OK"));
  gtk_widget_ref (colorize_proto_ok);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "colorize_proto_ok", colorize_proto_ok,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_set_usize (colorize_proto_ok, 50, 30);
  gtk_widget_show (colorize_proto_ok);
  gtk_box_pack_start (GTK_BOX (hbox4), colorize_proto_ok, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, colorize_proto_ok, ("Accept filter color change"), NULL);

  colorize_proto_cancel = gtk_button_new_with_label (("Cancel"));
  gtk_widget_ref (colorize_proto_cancel);
  gtk_object_set_data_full (GTK_OBJECT (colorize_win), "colorize_proto_cancel", colorize_proto_cancel,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_set_usize (colorize_proto_cancel, 50, 30);
  gtk_widget_show (colorize_proto_cancel);
  gtk_box_pack_start (GTK_BOX (hbox4), colorize_proto_cancel, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, colorize_proto_cancel, ("Reject filter color change"), NULL);
#if 0
  gtk_signal_connect (GTK_OBJECT (colorize_win), "destroy",
                      GTK_SIGNAL_FUNC (colorize_cancel_cb),
                      colorize_win);
#endif
  gtk_signal_connect (GTK_OBJECT (colorize_filter_fg), "clicked",
                      GTK_SIGNAL_FUNC (colorize_fg_cb),
                      cf->colors);
  gtk_signal_connect (GTK_OBJECT (colorize_protocol_bg), "clicked",
                      GTK_SIGNAL_FUNC (colorize_bg_cb),
                      cf->colors);
  gtk_signal_connect (GTK_OBJECT (colorize_proto_ok), "clicked",
                      GTK_SIGNAL_FUNC (colorize_ok_cb),
                      colorize_win);
  gtk_signal_connect (GTK_OBJECT (colorize_proto_cancel), "clicked",
                      GTK_SIGNAL_FUNC (colorize_cancel_cb),
                      colorize_win);

  gtk_object_set_data (GTK_OBJECT (colorize_win), "tooltips", tooltips);
  gtk_widget_show (colorize_win);
  return colorize_win;
}

GtkWidget*
create_color_sel_win (capture_file *cf)
{
  GtkWidget *color_sel_win;
  GtkWidget *color_sel_ok;
  GtkWidget *color_cel_cancel;
  GtkWidget *color_sel_help;

  color_sel_win = gtk_color_selection_dialog_new (("Choose color"));
  gtk_object_set_data (GTK_OBJECT (color_sel_win), "color_sel_win", color_sel_win);
  gtk_container_set_border_width (GTK_CONTAINER (color_sel_win), 10);

  color_sel_ok = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->ok_button;
  gtk_object_set_data (GTK_OBJECT (color_sel_win), "color_sel_ok", color_sel_ok);
  gtk_widget_show (color_sel_ok);
  GTK_WIDGET_SET_FLAGS (color_sel_ok, GTK_CAN_DEFAULT);

  color_cel_cancel = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->cancel_button;
  gtk_object_set_data (GTK_OBJECT (color_sel_win), "color_cel_cancel", color_cel_cancel);
  gtk_widget_show (color_cel_cancel);
  GTK_WIDGET_SET_FLAGS (color_cel_cancel, GTK_CAN_DEFAULT);


  color_sel_help = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->help_button;
  gtk_object_set_data (GTK_OBJECT (color_sel_win), "color_sel_help", color_sel_help);
  gtk_widget_show (color_sel_help);


  GTK_WIDGET_SET_FLAGS (color_sel_help, GTK_CAN_DEFAULT);
#if 0
  gtk_signal_connect (GTK_OBJECT (color_sel_win), "destroy",
                      GTK_SIGNAL_FUNC (color_cel_cancel_cb),
                      color_sel_win);
#endif

  gtk_signal_connect (GTK_OBJECT (color_sel_ok), "clicked",
                      GTK_SIGNAL_FUNC (color_sel_ok_cb),
                      color_sel_win);
  gtk_signal_connect (GTK_OBJECT (color_cel_cancel), "clicked",
                      GTK_SIGNAL_FUNC (color_cel_cancel_cb),
                      color_sel_win);

  gtk_widget_show(color_sel_win);
  return color_sel_win;
}

