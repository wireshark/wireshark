/* colors.c
 * Definitions for color structures and routines
 *
 * $Id: colors.c,v 1.7 2001/02/01 20:21:21 gram Exp $
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <epan.h>
#include "gtk/main.h"
#include "packet.h"
#include "colors.h"
#include "file.h"
#include "dfilter/dfilter.h"
#include "simple_dialog.h"
#include "util.h"

extern capture_file cf;

static gboolean read_filters(colfilter *filter);

GSList *filter_list;

static GdkColormap*	sys_cmap;
static GdkColormap*	our_cmap = NULL;

GdkColor	WHITE = { 0, 65535, 65535, 65535 };
GdkColor	BLACK = { 0, 0, 0, 0 };

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

	if (!dfilter_compile(default_colors[i].proto,
	    &colorf->c_colorfilter)) {
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

color_filter_t *
new_color_filter(colfilter *filters, gchar *name, gchar *filter_string)
{
	color_filter_t *colorf;

	colorf = (color_filter_t *)g_malloc(sizeof (color_filter_t));
	colorf->filter_name = g_strdup(name);
	colorf->filter_text = g_strdup(filter_string);
	colorf->bg_color = WHITE;
	colorf->fg_color = BLACK;
	colorf->c_colorfilter = NULL;
	colorf->edit_dialog = NULL;
	filter_list = g_slist_append(filter_list, colorf);
        return colorf;
}

void
delete_color_filter(color_filter_t *colorf)
{
	if (colorf->filter_name != NULL)
	  g_free(colorf->filter_name);
	if (colorf->filter_text != NULL)
	  g_free(colorf->filter_text);
	if (colorf->c_colorfilter != NULL)
	  dfilter_free(colorf->c_colorfilter);
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
	dfilter_t *temp_dfilter;

	/* decide what file to open (from dfilter code) */

	/* should only be called by colors_init.
	 */
	if(filter == NULL)
		return FALSE;
	/* we have a clist */

	path = (gchar *) g_malloc(strlen(get_home_dir()) + strlen(fname) +  4);
	sprintf(path, "%s/%s", get_home_dir(), fname);

	if ((f = fopen(path, "r")) == NULL) {
	  if (errno != ENOENT) {
	    simple_dialog(ESD_TYPE_CRIT, NULL,
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

	    if(!dfilter_compile(filter_exp, &temp_dfilter)) {
		simple_dialog(ESD_TYPE_CRIT, NULL,
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
	
gboolean
write_filters(colfilter *filter)
{
	FILE *f;
	gchar *path;
	gchar *name = PF_DIR "/colorfilters";
	/* decide what file to open (from dfilter code) */
	path = (gchar *) g_malloc(strlen(get_home_dir()) + strlen(name) +  4);
	sprintf(path, "%s/%s", get_home_dir(), name);

	if ((f = fopen(path, "w+")) == NULL) {
	  simple_dialog(ESD_TYPE_CRIT, NULL,
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

gboolean
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
