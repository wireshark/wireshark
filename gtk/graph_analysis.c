/* graph_analysis.c
 * Graphic Analysis addition for ethereal
 *
 * $Id$
 *
 * Copyright 2004, Verso Technologies Inc.
 * By Alejandro Vaquero <alejandrovaquero@yahoo.com>
 *
 * based on rtp_analysis.c and io_stat
 *
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "graph_analysis.h"

#include <epan/epan_dissect.h>
#include <epan/filesystem.h>

#include "util.h"
#include <epan/tap.h>
#include "register.h"
#include <epan/dissectors/packet-rtp.h>

/* in /gtk ... */
#include <gtk/gtk.h>
#include "gtkglobals.h"

#include "dlg_utils.h"
#include "ui_util.h"
#include "alert_box.h"
#include "simple_dialog.h"
#include "tap_menu.h"
#include "main.h"
#include "progress_dlg.h"
#include "compat_macros.h"
#include "../color.h"

#include <math.h>
#include <fcntl.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_IO_H
#include <io.h> /* open/close on win32 */
#endif

/* Win32 needs the O_BINARY flag for open() */
#ifndef O_BINARY
#define O_BINARY 0
#endif

/****************************************************************************/


#define OK_TEXT "[ Ok ]"
#define PT_UNDEFINED -1


#if GTK_MAJOR_VERSION < 2
GtkRcStyle *rc_style;
GdkColormap *colormap;
#endif

typedef const guint8 * ip_addr_p;


/****************************************************************************/
/* Reset the user_data structure */
static void graph_analysis_reset(graph_analysis_data_t* user_data)
{
	int i;

	user_data->num_nodes = 0;
	user_data->num_items = 0;
	for (i=0; i<MAX_NUM_NODES; i++){
		user_data->nodes[i] = 0;
	}
	
	user_data->dlg.first_node=0;
	user_data->dlg.first_item=0;
	user_data->dlg.left_x_border=0;
	user_data->dlg.selected_item=0xFFFFFFFF;    /*not item selected */
}

/****************************************************************************/
/* Reset the user_data structure */
static void graph_analysis_init_dlg(graph_analysis_data_t* user_data)
{
    /* init dialog_graph */
    user_data->dlg.needs_redraw=TRUE;
    user_data->dlg.draw_area=NULL;
    user_data->dlg.pixmap=NULL;
    user_data->dlg.h_scrollbar=NULL;
    user_data->dlg.h_scrollbar_adjustment=NULL;
    user_data->dlg.v_scrollbar=NULL;
    user_data->dlg.v_scrollbar_adjustment=NULL;
    user_data->dlg.pixmap_width=600;
    user_data->dlg.pixmap_height=400;
	user_data->dlg.first_node=0;
	user_data->dlg.first_item=0;
	user_data->dlg.left_x_border=0;
	user_data->dlg.selected_item=0xFFFFFFFF;    /*not item selected */
	user_data->dlg.window=NULL;
}

/****************************************************************************/
/* CALLBACKS */


/****************************************************************************/
/* close the dialog window and remove the tap listener */
static void on_destroy(GtkWidget *win _U_, graph_analysis_data_t *user_data _U_)
{

	g_free(user_data);
}


/****************************************************************************/
static void dialog_graph_set_title(graph_analysis_data_t* user_data)
{
	char            *title;
	if (!user_data->dlg.window){
		return;
	}
	title = g_strdup_printf("Ale");

	gtk_window_set_title(GTK_WINDOW(user_data->dlg.window), title);
	g_free(title);	
}

#define RIGHT_ARROW 1
#define LEFT_ARROW 0
#define WIDTH_ARROW 8
#define HEIGHT_ARROW 6

/****************************************************************************/
static void draw_arrow(GdkDrawable *pixmap, GdkGC *gc, gint x, gint y, gboolean direction)
{
	GdkPoint arrow_point[3];

	arrow_point[0].x = x;
	arrow_point[0].y = y-HEIGHT_ARROW/2;
	if (direction == RIGHT_ARROW)
		arrow_point[1].x = x+WIDTH_ARROW;
	else
		arrow_point[1].x = x-WIDTH_ARROW;
	arrow_point[1].y = y;
	arrow_point[2].x = x;
	arrow_point[2].y = y+HEIGHT_ARROW/2;;

	gdk_draw_polygon(pixmap, gc, TRUE, 
		arrow_point, 3);
}

#define MAX_LABEL 50
#define MAX_COMMENT 60
#define ITEM_HEIGHT 20
#define NODE_WIDTH 100
#define TOP_Y_BORDER 40
#define BOTTOM_Y_BORDER 0
#define COMMENT_WIDTH 250

/****************************************************************************/
static void dialog_graph_draw(graph_analysis_data_t* user_data)
{
        guint32 i, last_item, first_item, last_node, first_node, display_items, display_nodes;
		guint32 start_arrow, end_arrow, label_x, src_port_x, dst_port_x, arrow_width;
        guint32 current_item;
        guint32 left_x_border;
        guint32 right_x_border;
        guint32 top_y_border;
        guint32 bottom_y_border;
		graph_analysis_item_t *gai;
		gboolean display_label;

#if GTK_MAJOR_VERSION < 2
        GdkFont *font;
		FONT_TYPE *big_font;
		FONT_TYPE *small_font;
#else
        PangoLayout  *layout;
        PangoLayout  *big_layout;
        PangoLayout  *small_layout;
#endif
        guint32 label_width, label_height;
        guint32 draw_width, draw_height;
        char label_string[MAX_COMMENT];
		GList* list;

        /* new variables */

#if GTK_MAJOR_VERSION <2
        font = user_data->dlg.draw_area->style->font;
		big_font = gdk_font_load("-adobe-helvetica-bold-r-normal--12-120-75-75-p-70-iso8859-1");
		small_font = gdk_font_load("-adobe-helvetica-bold-r-normal--10-120-75-75-p-70-iso8859-1");
#endif
        if(!user_data->dlg.needs_redraw){
                return;
        }
        user_data->dlg.needs_redraw=FALSE;

        /*
         * Clear out old plot
         */
        gdk_draw_rectangle(user_data->dlg.pixmap,
                           user_data->dlg.draw_area->style->white_gc,
                           TRUE,
                           0, 0,
                           user_data->dlg.draw_area->allocation.width,
                           user_data->dlg.draw_area->allocation.height);

		/* Calculate the y border */
        top_y_border=TOP_Y_BORDER;	/* to display the node IP address */
        bottom_y_border=BOTTOM_Y_BORDER;

        draw_height=user_data->dlg.pixmap_height-top_y_border-bottom_y_border;

		first_item = user_data->dlg.first_item;
		display_items = draw_height/ITEM_HEIGHT;
		last_item = first_item+display_items-1;

		/* get the items to display and fill the matrix array */
		list = g_list_first(user_data->graph_info->list);
		current_item = 0;
		i = 0;
		while (list)
		{
			gai = list->data;
			if (gai->display){
				if (current_item>=display_items) break;		/* the item is outside the display */
				if (i>=first_item){
					user_data->dlg.items[current_item].frame_num = gai->frame_num;
					user_data->dlg.items[current_item].time = gai->time;
					user_data->dlg.items[current_item].port_src = gai->port_src;
					user_data->dlg.items[current_item].port_dst = gai->port_dst;
					/* Add "..." if the length is 50 characters */
					if (strlen(gai->frame_label) > 48) {
						gai->frame_label[48] = '.';
						gai->frame_label[47] = '.';
						gai->frame_label[46] = '.';
					}
					user_data->dlg.items[current_item].frame_label = gai->frame_label;
					user_data->dlg.items[current_item].comment = gai->comment;
					user_data->dlg.items[current_item].conv_num = gai->conv_num;
					user_data->dlg.items[current_item].src_node = gai->src_node;
					user_data->dlg.items[current_item].dst_node = gai->dst_node;
					user_data->dlg.items[current_item].line_style = gai->line_style;
					current_item++;
				}
				i++;
			}

			list = g_list_next(list);
		}
		/* in case the windows is resized so we have to move the top item */
		if ((first_item + display_items) > user_data->num_items){
			if (display_items>user_data->num_items)
				first_item=0;
			else
				first_item = user_data->num_items - display_items;
		}
		
		/* in case there are less items than possible displayed */
		display_items = current_item;
		last_item = first_item+display_items-1;

		/* if not items to display */
		if (display_items == 0)	return;				


		/* Calculate the x borders */
		/* We use time from the last display item to calcultate the x left border */
		g_snprintf(label_string, MAX_LABEL, "%.3f", user_data->dlg.items[display_items-1].time);
#if GTK_MAJOR_VERSION < 2
        label_width=gdk_string_width(font, label_string);
        label_height=gdk_string_height(font, label_string);
#else
        layout = gtk_widget_create_pango_layout(user_data->dlg.draw_area, label_string);
        big_layout = gtk_widget_create_pango_layout(user_data->dlg.draw_area, label_string);
        small_layout = gtk_widget_create_pango_layout(user_data->dlg.draw_area, label_string);

		pango_layout_set_font_description(big_layout, pango_font_description_from_string("Helvetica-Bold 8"));
		pango_layout_set_font_description(small_layout, pango_font_description_from_string("Helvetica-Bold 7"));

        pango_layout_get_pixel_size(layout, &label_width, &label_height);
#endif
        left_x_border=label_width+10;
		user_data->dlg.left_x_border = left_x_border;

        right_x_border=COMMENT_WIDTH;

		/* Calculate the number of nodes to display */
        draw_width=user_data->dlg.pixmap_width-right_x_border-left_x_border;
		display_nodes = draw_width/NODE_WIDTH;
		first_node = user_data->dlg.first_node;

		/* in case the windows is resized so we have to move the left node */
		if ((first_node + display_nodes) > user_data->num_nodes){
			if (display_nodes>user_data->num_nodes) 
				first_node=0;
			else
				first_node=user_data->num_nodes - display_nodes;
		}

		/* in case there are less nodes than possible displayed */
		if (display_nodes>user_data->num_nodes) display_nodes=user_data->num_nodes;

		last_node = first_node + display_nodes-1;

		/* Paint the background items */ 
		for (current_item=0; current_item<display_items; current_item++){
			/* Paint background */
	        gdk_draw_rectangle(user_data->dlg.pixmap,
                           user_data->dlg.bg_gc[user_data->dlg.items[current_item].conv_num%MAX_NUM_COL_CONV],
                           TRUE,
                           left_x_border, 
						   top_y_border+current_item*ITEM_HEIGHT,
                           draw_width,
                           ITEM_HEIGHT);
		}


		/* Draw the node names on top and the division lines */
		for (i=0; i<display_nodes; i++){
			/* draw the node IPs */
			g_snprintf(label_string, MAX_LABEL, "%s",
				ip_to_str((guint8 *)&(user_data->nodes[i+first_node])));
#if GTK_MAJOR_VERSION < 2
	        label_width=gdk_string_width(font, label_string);
	        label_height=gdk_string_height(font, label_string);
			gdk_draw_string(user_data->dlg.pixmap,
                font,
                user_data->dlg.draw_area->style->black_gc,
                left_x_border+NODE_WIDTH/2-label_width/2+NODE_WIDTH*i,
                top_y_border/2-label_height/2,
                label_string);
#else
			pango_layout_set_text(layout, label_string, -1);
	        pango_layout_get_pixel_size(layout, &label_width, &label_height);
	        gdk_draw_layout(user_data->dlg.pixmap,
                user_data->dlg.draw_area->style->black_gc,
                left_x_border+NODE_WIDTH/2-label_width/2+NODE_WIDTH*i,
                top_y_border/2-label_height/2,
                layout);
#endif		

			/* draw the node division lines */
			gdk_draw_line(user_data->dlg.pixmap, user_data->dlg.div_line_gc,
				left_x_border+NODE_WIDTH/2+NODE_WIDTH*i,
				top_y_border,
				left_x_border+NODE_WIDTH/2+NODE_WIDTH*i,
				user_data->dlg.pixmap_height-bottom_y_border);

		}

		/*
		 * Draw the items 
		 */


		for (current_item=0; current_item<display_items; current_item++){
			/* draw the time */
			g_snprintf(label_string, MAX_LABEL, "%.3f", user_data->dlg.items[current_item].time);
#if GTK_MAJOR_VERSION < 2
	        label_width=gdk_string_width(font, label_string);
	        label_height=gdk_string_height(font, label_string);
			gdk_draw_string(user_data->dlg.pixmap,
                font,
                user_data->dlg.draw_area->style->black_gc,
                left_x_border-label_width-4,
                top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT/2+label_height/4,
                label_string);
#else
			pango_layout_set_text(layout, label_string, -1);
	        pango_layout_get_pixel_size(layout, &label_width, &label_height);
	        gdk_draw_layout(user_data->dlg.pixmap,
                user_data->dlg.draw_area->style->black_gc,
                left_x_border-label_width-4,
                top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT/2-label_height/2,
                layout);
#endif

			/*draw the comments */
			g_snprintf(label_string, MAX_COMMENT, "%s", user_data->dlg.items[current_item].comment);
#if GTK_MAJOR_VERSION < 2
			label_width=gdk_string_width(small_font, label_string);
			label_height=gdk_string_height(small_font, label_string);
			gdk_draw_string(user_data->dlg.pixmap,
                small_font,
                user_data->dlg.draw_area->style->black_gc,
                user_data->dlg.pixmap_width-right_x_border+3,
                top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT/2+label_height/4,
                label_string);
#else
			pango_layout_set_text(small_layout, label_string, -1);
			pango_layout_get_pixel_size(small_layout, &label_width, &label_height);
	        gdk_draw_layout(user_data->dlg.pixmap,
                user_data->dlg.draw_area->style->black_gc,
                user_data->dlg.pixmap_width-right_x_border+3,
                top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT/2-label_height/2,
                small_layout);
#endif
			
			/* draw the arrow an frame label*/
			display_label = FALSE;
			if (user_data->dlg.items[current_item].src_node>=first_node){
				if (user_data->dlg.items[current_item].src_node<=last_node){
					start_arrow = left_x_border+(user_data->dlg.items[current_item].src_node-first_node)*NODE_WIDTH+NODE_WIDTH/2;
					display_label = TRUE;
				} else {
					start_arrow = user_data->dlg.pixmap_width - right_x_border;
				}
			} else {
				start_arrow = left_x_border;
			}

			if (user_data->dlg.items[current_item].dst_node>=first_node){
				if (user_data->dlg.items[current_item].dst_node<=last_node){
					end_arrow = left_x_border+(user_data->dlg.items[current_item].dst_node-first_node)*NODE_WIDTH+NODE_WIDTH/2;
					display_label = TRUE;
				} else {
					end_arrow = user_data->dlg.pixmap_width - right_x_border;
				}
			} else {
				end_arrow = left_x_border;
			}

			if (start_arrow != end_arrow){
				/* draw the arrow line */
				gdk_draw_line(user_data->dlg.pixmap, user_data->dlg.draw_area->style->black_gc,
					start_arrow,
					top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-7,
					end_arrow,
					top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-7);

				/* draw the additional line when line style is 2 pixels width */
				if (user_data->dlg.items[current_item].line_style == 2){
					gdk_draw_line(user_data->dlg.pixmap, user_data->dlg.draw_area->style->black_gc,
						start_arrow,
						top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-6,
						end_arrow,
						top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-6);
				}					

				/* draw the arrow */
				if (start_arrow<end_arrow)
					draw_arrow(user_data->dlg.pixmap, user_data->dlg.draw_area->style->black_gc, end_arrow-WIDTH_ARROW,top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-7, RIGHT_ARROW);
				else
					draw_arrow(user_data->dlg.pixmap, user_data->dlg.draw_area->style->black_gc, end_arrow+WIDTH_ARROW,top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-7, LEFT_ARROW);
			}

			/* draw the frame comment */
			if (display_label){
				g_snprintf(label_string, MAX_LABEL, "%s", user_data->dlg.items[current_item].frame_label);
#if GTK_MAJOR_VERSION < 2
				label_width=gdk_string_width(big_font, label_string);
				label_height=gdk_string_height(big_font, label_string);
#else
				pango_layout_set_text(big_layout, label_string, -1);
				pango_layout_get_pixel_size(big_layout, &label_width, &label_height);
#endif

				if (start_arrow<end_arrow){
					arrow_width = end_arrow-start_arrow;
					label_x = arrow_width/2+start_arrow;
				}
				else {
					arrow_width = start_arrow-end_arrow;
					label_x = arrow_width/2+end_arrow;
				}

				if (label_width>arrow_width) arrow_width = label_width;

				if (left_x_border > (label_x-label_width/2)) label_x = left_x_border + label_width/2;

				if ((user_data->dlg.pixmap_width - right_x_border) < (label_x+label_width/2)) label_x = user_data->dlg.pixmap_width - right_x_border - label_width/2;

#if GTK_MAJOR_VERSION < 2
				gdk_draw_string(user_data->dlg.pixmap,
					big_font,
					user_data->dlg.draw_area->style->black_gc,
					label_x - label_width/2,
					top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT/2+label_height/4-3,
					label_string);
#else
				gdk_draw_layout(user_data->dlg.pixmap,
					user_data->dlg.draw_area->style->black_gc,
					label_x - label_width/2,
					top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT/2-label_height/2-3,
					big_layout);
#endif

				/* draw the source port number */
				if ((start_arrow != left_x_border) && (start_arrow != (user_data->dlg.pixmap_width - right_x_border))){ 
					g_snprintf(label_string, MAX_LABEL, "(%i)", user_data->dlg.items[current_item].port_src);
#if GTK_MAJOR_VERSION < 2
					label_width=gdk_string_width(small_font, label_string);
					label_height=gdk_string_height(small_font, label_string);
#else
					pango_layout_set_text(small_layout, label_string, -1);
					pango_layout_get_pixel_size(small_layout, &label_width, &label_height);
#endif
					if (start_arrow<end_arrow){
						src_port_x = start_arrow - label_width - 2;
					}
					else {
						src_port_x = start_arrow + 2;
					}
#if GTK_MAJOR_VERSION < 2
					gdk_draw_string(user_data->dlg.pixmap,
						small_font,
						user_data->dlg.div_line_gc,
						src_port_x,
						top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-2+label_height/4-2,
						label_string);
#else
					gdk_draw_layout(user_data->dlg.pixmap,
						user_data->dlg.div_line_gc,
						src_port_x,
						top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-2-label_height/2-2,
						small_layout);
#endif
				}

				/* draw the destination port number */
				if ((end_arrow != left_x_border) && (end_arrow != (user_data->dlg.pixmap_width - right_x_border))){ 
					g_snprintf(label_string, MAX_LABEL, "(%i)", user_data->dlg.items[current_item].port_dst);
#if GTK_MAJOR_VERSION < 2
					label_width=gdk_string_width(small_font, label_string);
					label_height=gdk_string_height(small_font, label_string);
#else
					pango_layout_set_text(small_layout, label_string, -1);
					pango_layout_get_pixel_size(small_layout, &label_width, &label_height);
#endif
					if (start_arrow<end_arrow){
						dst_port_x = end_arrow + 2;
					}
					else {
						dst_port_x = end_arrow - label_width - 2;
					}
#if GTK_MAJOR_VERSION < 2
					gdk_draw_string(user_data->dlg.pixmap,
						small_font,
						user_data->dlg.div_line_gc,
						dst_port_x,
						top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-2+label_height/4-2,
						label_string);
#else
					gdk_draw_layout(user_data->dlg.pixmap,
						user_data->dlg.div_line_gc,
						dst_port_x,
						top_y_border+current_item*ITEM_HEIGHT+ITEM_HEIGHT-2-label_height/2-2,
						small_layout);
#endif
				}

			}
		}

#if GTK_MAJOR_VERSION >= 2
        g_object_unref(G_OBJECT(layout));
#endif

		/* draw the border on the selected item */
		if ( (user_data->dlg.selected_item != 0xFFFFFFFF) && ( (user_data->dlg.selected_item>=first_item) && (user_data->dlg.selected_item<=last_item) )){
			gdk_draw_rectangle(user_data->dlg.pixmap, user_data->dlg.draw_area->style->black_gc,
				FALSE,
				left_x_border-1,
				(user_data->dlg.selected_item-first_item)*ITEM_HEIGHT+TOP_Y_BORDER,
				user_data->dlg.pixmap_width-COMMENT_WIDTH-left_x_border+1,
				ITEM_HEIGHT);
		}



        gdk_draw_pixmap(user_data->dlg.draw_area->window,
                        user_data->dlg.draw_area->style->fg_gc[GTK_WIDGET_STATE(user_data->dlg.draw_area)],
                        user_data->dlg.pixmap,
                        0, 0,
                        0, 0,
                        user_data->dlg.pixmap_width, user_data->dlg.pixmap_height);


        /* update the h_scrollbar */
        user_data->dlg.h_scrollbar_adjustment->upper=(gfloat) user_data->num_nodes-1;
        user_data->dlg.h_scrollbar_adjustment->step_increment=1;
        user_data->dlg.h_scrollbar_adjustment->page_increment=(gfloat) (last_node-first_node);
        user_data->dlg.h_scrollbar_adjustment->page_size=(gfloat) (last_node-first_node);
        user_data->dlg.h_scrollbar_adjustment->value=(gfloat) first_node;

		gtk_adjustment_changed(user_data->dlg.h_scrollbar_adjustment);
        gtk_adjustment_value_changed(user_data->dlg.h_scrollbar_adjustment);

        /* update the v_scrollbar */
        user_data->dlg.v_scrollbar_adjustment->upper=(gfloat) user_data->num_items-1;
        user_data->dlg.v_scrollbar_adjustment->step_increment=1;
        user_data->dlg.v_scrollbar_adjustment->page_increment=(gfloat) (last_item-first_item);
        user_data->dlg.v_scrollbar_adjustment->page_size=(gfloat) (last_item-first_item);
        user_data->dlg.v_scrollbar_adjustment->value=(gfloat) first_item;

		gtk_adjustment_changed(user_data->dlg.v_scrollbar_adjustment);
        gtk_adjustment_value_changed(user_data->dlg.v_scrollbar_adjustment);

}

/****************************************************************************/
static void dialog_graph_redraw(graph_analysis_data_t* user_data)
{
        user_data->dlg.needs_redraw=TRUE;
        dialog_graph_draw(user_data); 
}

/****************************************************************************/
static gint quit(GtkWidget *widget, GdkEventExpose *event _U_)
{
        graph_analysis_data_t *user_data;

        user_data=(graph_analysis_data_t *)OBJECT_GET_DATA(widget, "graph_analysis_data_t");

		user_data->dlg.window = NULL;

		user_data = NULL;
        return TRUE;
}

/****************************************************************************/
static gint button_press_event(GtkWidget *widget, GdkEventButton *event _U_)
{
        graph_analysis_data_t *user_data;
		guint32 item;

        user_data=(graph_analysis_data_t *)OBJECT_GET_DATA(widget, "graph_analysis_data_t");

		if (event->type != GDK_BUTTON_PRESS) return TRUE;

		if (event->y<TOP_Y_BORDER) return TRUE;

		/* get the item clicked */
		item = ((guint32)event->y - TOP_Y_BORDER) / ITEM_HEIGHT;
		user_data->dlg.selected_item = item + user_data->dlg.first_item;

		user_data->dlg.needs_redraw=TRUE;
		dialog_graph_draw(user_data);

		goto_frame(&cfile, user_data->dlg.items[item].frame_num);

        return TRUE;
}

/****************************************************************************/
static gint expose_event(GtkWidget *widget, GdkEventExpose *event)
{
	graph_analysis_data_t *user_data;

	user_data=(graph_analysis_data_t *)OBJECT_GET_DATA(widget, "graph_analysis_data_t");
        if(!user_data){
                exit(10);
        }


        gdk_draw_pixmap(widget->window,
                        widget->style->fg_gc[GTK_WIDGET_STATE(widget)],
                        user_data->dlg.pixmap,
                        event->area.x, event->area.y,
                        event->area.x, event->area.y,
                        event->area.width, event->area.height);

        return FALSE;
}

static const GdkColor COLOR_GRAY = {0, 0x7fff, 0x7fff, 0x7fff};

/****************************************************************************/
static gint configure_event(GtkWidget *widget, GdkEventConfigure *event _U_)
{
        graph_analysis_data_t *user_data;
		int i;
		GdkColor color_div_line = COLOR_GRAY;

		static GdkColor col[MAX_NUM_COL_CONV] = {
       		{0,     0x00FF, 0xFFFF, 0x00FF},
        	{0,     0xFFFF, 0xFFFF, 0x00FF},
        	{0,     0xFFFF, 0x00FF, 0x00FF},
        	{0,     0xFFFF, 0x00FF, 0xFFFF},
			{0,     0x00FF, 0x00FF, 0xFFFF},
			{0,     0x00FF, 0xFFFF, 0xFFFF},
			{0,     0xFFFF, 0x80FF, 0x00FF},
			{0,     0x80FF, 0x00FF, 0xFFFF},
			{0,     0x00FF, 0x80FF, 0xFFFF},
			{0,     0xFFFF, 0x00FF, 0x80FF}
		};

        user_data=(graph_analysis_data_t *)OBJECT_GET_DATA(widget, "graph_analysis_data_t");

        if(!user_data){
                exit(10);
        }

        if(user_data->dlg.pixmap){
                gdk_pixmap_unref(user_data->dlg.pixmap);
                user_data->dlg.pixmap=NULL;
        }

        user_data->dlg.pixmap=gdk_pixmap_new(widget->window,
                        widget->allocation.width,
                        widget->allocation.height,
                        -1);
        user_data->dlg.pixmap_width=widget->allocation.width;
        user_data->dlg.pixmap_height=widget->allocation.height;

        gdk_draw_rectangle(user_data->dlg.pixmap,
                        widget->style->white_gc,
                        TRUE,
                        0, 0,
                        widget->allocation.width,
                        widget->allocation.height);

		/* create gc for division lines and set the line stype to dash*/
		user_data->dlg.div_line_gc=gdk_gc_new(user_data->dlg.pixmap);
		gdk_gc_set_line_attributes(user_data->dlg.div_line_gc, 1, GDK_LINE_ON_OFF_DASH, 0, 0);
#if GTK_MAJOR_VERSION < 2
        colormap = gtk_widget_get_colormap (widget);
        if (!gdk_color_alloc (colormap, &color_div_line)){
                     g_warning ("Couldn't allocate color");
        }
        gdk_gc_set_foreground(user_data->dlg.div_line_gc, &color_div_line);
#else
        gdk_gc_set_rgb_fg_color(user_data->dlg.div_line_gc, &color_div_line);
#endif
	
		/* create gcs for the background items */

		for (i=0; i<MAX_NUM_COL_CONV; i++){
			user_data->dlg.bg_gc[i]=gdk_gc_new(user_data->dlg.pixmap);
#if GTK_MAJOR_VERSION < 2
			colormap = gtk_widget_get_colormap (widget);
			if (!gdk_color_alloc (colormap, &col[i])){
						 g_warning ("Couldn't allocate color");
			}
			gdk_gc_set_foreground(user_data->dlg.bg_gc[i], &col[i]);
#else
	        gdk_gc_set_rgb_fg_color(user_data->dlg.bg_gc[i], &col[i]);
#endif
		}

	dialog_graph_redraw(user_data);
        return TRUE;
}

/****************************************************************************/
static gint h_scrollbar_changed(GtkWidget *widget _U_, gpointer data)
{
    graph_analysis_data_t *user_data=(graph_analysis_data_t *)data;

	if ((user_data->dlg.first_node+user_data->dlg.h_scrollbar_adjustment->page_size+1 == user_data->num_nodes) 
		&& (user_data->dlg.h_scrollbar_adjustment->value >= user_data->dlg.first_node ))
		return TRUE;

	if (user_data->dlg.first_node == (guint16) user_data->dlg.h_scrollbar_adjustment->value)
		return TRUE;

    user_data->dlg.first_node = (guint16) user_data->dlg.h_scrollbar_adjustment->value;

	dialog_graph_redraw(user_data);
    return TRUE;
}

/****************************************************************************/
static gint v_scrollbar_changed(GtkWidget *widget _U_, gpointer data)
{
    graph_analysis_data_t *user_data=(graph_analysis_data_t *)data;
	if ((user_data->dlg.first_item+user_data->dlg.v_scrollbar_adjustment->page_size+1 == user_data->num_items) 
		&& (user_data->dlg.v_scrollbar_adjustment->value >= user_data->dlg.first_item ))
		return TRUE;

	if (user_data->dlg.first_item == user_data->dlg.v_scrollbar_adjustment->value)
		return TRUE;
		
    user_data->dlg.first_item = (guint32) user_data->dlg.v_scrollbar_adjustment->value;

	dialog_graph_redraw(user_data);
    return TRUE;
}

/****************************************************************************/
static void create_draw_area(graph_analysis_data_t* user_data, GtkWidget *box)
{
	    GtkWidget *vbox;
        GtkWidget *hbox;

        hbox=gtk_hbox_new(FALSE, 0);
        gtk_widget_show(hbox);

        vbox=gtk_vbox_new(FALSE, 0);
        gtk_widget_show(vbox);


        user_data->dlg.draw_area=gtk_drawing_area_new();
        SIGNAL_CONNECT(user_data->dlg.draw_area, "destroy", quit, user_data);
        OBJECT_SET_DATA(user_data->dlg.draw_area, "graph_analysis_data_t", user_data);

        WIDGET_SET_SIZE(user_data->dlg.draw_area, user_data->dlg.pixmap_width, user_data->dlg.pixmap_height);

        /* signals needed to handle backing pixmap */
        SIGNAL_CONNECT(user_data->dlg.draw_area, "expose_event", expose_event, NULL);
        SIGNAL_CONNECT(user_data->dlg.draw_area, "configure_event", configure_event, user_data);

		gtk_widget_add_events (user_data->dlg.draw_area,
			 GDK_BUTTON_PRESS_MASK);
		SIGNAL_CONNECT(user_data->dlg.draw_area, "button_press_event", button_press_event, user_data);

        gtk_widget_show(user_data->dlg.draw_area);
        gtk_box_pack_start(GTK_BOX(vbox), user_data->dlg.draw_area, TRUE, TRUE, 0);

        /* create the associated h_scrollbar */
        user_data->dlg.h_scrollbar_adjustment=(GtkAdjustment *)gtk_adjustment_new(0,0,0,0,0,0);
        user_data->dlg.h_scrollbar=gtk_hscrollbar_new(user_data->dlg.h_scrollbar_adjustment);
        gtk_widget_show(user_data->dlg.h_scrollbar);
        gtk_box_pack_end(GTK_BOX(vbox), user_data->dlg.h_scrollbar, FALSE, FALSE, 0);
        SIGNAL_CONNECT(user_data->dlg.h_scrollbar_adjustment, "value_changed", h_scrollbar_changed, user_data);

        gtk_box_pack_start(GTK_BOX(hbox), vbox, TRUE, TRUE, 0);

       /* create the associated v_scrollbar */
        user_data->dlg.v_scrollbar_adjustment=(GtkAdjustment *)gtk_adjustment_new(0,0,0,0,0,0);
        user_data->dlg.v_scrollbar=gtk_vscrollbar_new(user_data->dlg.v_scrollbar_adjustment);
        gtk_widget_show(user_data->dlg.v_scrollbar);
        gtk_box_pack_end(GTK_BOX(hbox), user_data->dlg.v_scrollbar, FALSE, FALSE, 0);
		SIGNAL_CONNECT(user_data->dlg.v_scrollbar_adjustment, "value_changed", v_scrollbar_changed, user_data);

        gtk_box_pack_start(GTK_BOX(box), hbox, TRUE, TRUE, 0);
}


/****************************************************************************/
static void dialog_graph_create_window(graph_analysis_data_t* user_data)
{
        GtkWidget *vbox;
        GtkWidget *hbox;
    	GtkWidget *bt_close;

        /* create the main window */
        user_data->dlg.window=window_new(GTK_WINDOW_TOPLEVEL, "Graph Analysis");


        vbox=gtk_vbox_new(FALSE, 0);
        gtk_container_add(GTK_CONTAINER(user_data->dlg.window), vbox);
        gtk_widget_show(vbox);

        create_draw_area(user_data, vbox);

        hbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
        gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
        gtk_widget_show(hbox);

        bt_close = OBJECT_GET_DATA(hbox, GTK_STOCK_CLOSE);
        window_set_cancel_button(user_data->dlg.window, bt_close, window_cancel_button_cb);

        SIGNAL_CONNECT(user_data->dlg.window, "delete_event", window_delete_event_cb, NULL);

        gtk_widget_show(user_data->dlg.window);
        window_present(user_data->dlg.window);
}

/* Return the index array if the node is in the array. Return -1 if there is room in the array
 * and Return -2 if the array is full
 */
/****************************************************************************/
gint is_node_array(graph_analysis_data_t* user_data, guint32 node)
{
	int i;
	for (i=0; i<MAX_NUM_NODES; i++){
		if (user_data->nodes[i] == 0)	return -1;	/* it is not in the array */
		if (user_data->nodes[i] == node) return i;	/* it is in the array */
	}
	return -2;		/* array full */
}


/* Get the nodes (IPs) from the list */
/****************************************************************************/
void get_nodes(graph_analysis_data_t* user_data)
{
	GList* list;
	graph_analysis_item_t *gai;
	gint index;

	/* fill the node array */
	list = g_list_first(user_data->graph_info->list);
	while (list)
	{
		gai = list->data;
		if (gai->display){
			user_data->num_items++;
			/* check source IP node */
			index = is_node_array(user_data, gai->ip_src);
			switch(index){
				case -2: /* array full */
					gai->src_node = NODE_OVERFLOW;
					break;
				case -1: /* not in array */
					user_data->nodes[user_data->num_nodes] = gai->ip_src;
					gai->src_node = user_data->num_nodes;
					user_data->num_nodes++;
					break;
				default: /* it is in the array, just update the src_node */
					gai->src_node = (guint16)index;
			}

			/* check destination  IP node */
			index = is_node_array(user_data, gai->ip_dst);
			switch(index){
				case -2: /* array full */
					gai->dst_node = NODE_OVERFLOW;
					break;
				case -1: /* not in array */
					user_data->nodes[user_data->num_nodes] = gai->ip_dst;
					gai->dst_node = user_data->num_nodes;
					user_data->num_nodes++;
					break;
				default: /* it is in the array, just update the dst_node */
					gai->dst_node = (guint16)index;
			}
		}

		list = g_list_next(list);
	}
}

/****************************************************************************/
/* XXX only handles IPv4, should add IPv6 support */
graph_analysis_data_t* graph_analysis_init(void)
{
	graph_analysis_data_t* user_data;
	/* init */
	user_data = g_malloc(sizeof(graph_analysis_data_t));

	/* init user_data */
	graph_analysis_init_dlg(user_data);

	return user_data;
}

/****************************************************************************/
void graph_analysis_create(graph_analysis_data_t* user_data)
{
	/* reset the data */
	graph_analysis_reset(user_data);

	/* get nodes (each node is an IP address) */
	get_nodes(user_data);

	/* create the graph windows */
	dialog_graph_create_window(user_data);

	/* redraw the graph */
	dialog_graph_redraw(user_data); 

	return;
}

/****************************************************************************/
void graph_analysis_update(graph_analysis_data_t* user_data)
{
	/* reset the data */
	graph_analysis_reset(user_data);

	/* get nodes (each node is an IP address) */
	get_nodes(user_data);

	/* redraw the graph */
	dialog_graph_redraw(user_data); 

    window_present(user_data->dlg.window);
	return;
}
