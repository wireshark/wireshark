/* packet_win.c
 * Routines for popping a window to display current packet
 *
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
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
 *
 * To do:
 * - Add close button to bottom.
 * - improve the window Title and allow user to config it
 * - Add print support ? ( could be a mess)
 * - Add button to have main window jump to this packet ?
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#include <string.h>

#include <epan/epan.h>
#include <epan/timestamp.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/addr_resolv.h>
#include <epan/plugins.h>
#include <epan/epan_dissect.h>
#include <epan/strutil.h>

#include "../file.h"
#include "../print.h"
#include "../ui_util.h"
#include "../summary.h"
#include "../simple_dialog.h"

#include "gtk/font_utils.h"
#include "gtk/main.h"
#include "gtk/packet_win.h"
#include "gtk/main_proto_draw.h"
#include "gtk/keys.h"
#include "gtk/gtkglobals.h"
#include "gtk/gui_utils.h"
#include "gtk/recent.h"

#define BV_SIZE 75

/* Data structure holding information about a packet-detail window. */
struct PacketWinData {
	frame_data *frame;	   /* The frame being displayed */
	union wtap_pseudo_header pseudo_header; /* Pseudo-header for packet */
	guint8     *pd;		   /* Data for packet */
	GtkWidget  *main;
	GtkWidget  *tv_scrollw;
	GtkWidget  *tree_view;
	GtkWidget  *bv_nb_ptr;
 	field_info *finfo_selected;
	epan_dissect_t	edt;

	int pd_offset;
	int pd_bitoffset;
};

struct FieldinfoWinData {
	frame_data *frame;	   /* The frame being displayed */
	union wtap_pseudo_header pseudo_header; /* Pseudo-header for packet */
	guint8     *pd;		   /* Data for packet */
	int start_offset;

	field_info *finfo;
/* fvalue */
	GtkWidget *edit;
	GtkWidget *repr;
/* byteviews */
	GtkWidget *bv;
	GtkWidget *app_bv;
};

/* List of all the packet-detail windows popped up. */
static GList *detail_windows;

static void new_tree_view_selection_changed_cb(GtkTreeSelection *sel,
                                               gpointer user_data);


static void destroy_new_window(GtkObject *object, gpointer user_data);

static gboolean
button_press_handler(GtkWidget *widget, GdkEvent *event, gpointer data _U_)
{
  if (widget == NULL || event == NULL) {
    return FALSE;
  }

  tree_view_select(widget, (GdkEventButton *) event);

  /* GDK_2BUTTON_PRESS is a doubleclick -> expand/collapse tree row */
  if (event->type == GDK_2BUTTON_PRESS) {
    GtkTreePath      *path;

    if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(widget),
				      (gint) (((GdkEventButton *)event)->x),
				      (gint) (((GdkEventButton *)event)->y),
				      &path, NULL, NULL, NULL))
    {
      if (gtk_tree_view_row_expanded(GTK_TREE_VIEW(widget), path)) {
	gtk_tree_view_collapse_row(GTK_TREE_VIEW(widget), path);
      }	else {
	gtk_tree_view_expand_row(GTK_TREE_VIEW(widget), path, FALSE);
      }
      gtk_tree_path_free(path);
    }
  }

  return FALSE;
}

static field_info *
proto_finfo_find(proto_tree *tree, field_info *old_finfo)
{
	proto_node *node;

	for (node = tree->first_child; node != NULL; node = node->next) {
		field_info *cur = PNODE_FINFO(node);

		if (!cur)
			continue;

		/* check everything, if it doesn't work report to me */
		if (cur->hfinfo == old_finfo->hfinfo && 
			cur->start == old_finfo->start && cur->length == old_finfo->length &&
			cur->appendix_start == old_finfo->appendix_start && cur->appendix_length == old_finfo->appendix_length &&
			cur->tree_type == old_finfo->tree_type && cur->flags == old_finfo->flags)
		{
			return cur;
		}

		if ((cur = proto_finfo_find((proto_tree *)node, old_finfo)))
			return cur;
	}
	return NULL;
}

static gboolean
finfo_window_refresh(struct FieldinfoWinData *DataPtr)
{
	field_info *old_finfo = DataPtr->finfo;
	field_info *finfo = NULL;
	epan_dissect_t edt;

	const guint8 *data;
	GtkWidget *byte_view;
	gchar label_str[ITEM_LABEL_LENGTH];

	/* redisect */
	epan_dissect_init(&edt, TRUE, TRUE);
	/* Makes any sense?
	if (old_finfo->hfinfo)
		proto_tree_prime_hfid(edt.tree, old_finfo->hfinfo->id);
	*/
	epan_dissect_run(&edt, &DataPtr->pseudo_header, DataPtr->pd, DataPtr->frame, NULL);

	/* Try to find finfo which looks like old_finfo.
	 * We might not found one, if protocol requires specific magic values, etc... */
	if (!(finfo = proto_finfo_find(edt.tree, old_finfo))) {
		epan_dissect_cleanup(&edt);
		gtk_entry_set_text(GTK_ENTRY(DataPtr->repr), "[finfo not found, try with another value, or restore old. If you think it is bug, fill bugreport]");
		return FALSE;
	}

	if (DataPtr->bv && (byte_view = get_notebook_bv_ptr(DataPtr->bv))) {
		data = tvb_get_ptr(finfo->ds_tvb, finfo->start, finfo->length);
		packet_hex_print(byte_view, data, cfile.current_frame, NULL, finfo->length);
	}

	if (DataPtr->app_bv && (byte_view = get_notebook_bv_ptr(DataPtr->app_bv))) {
		data = tvb_get_ptr(finfo->ds_tvb, finfo->appendix_start, finfo->appendix_length);
		packet_hex_print(byte_view, data, cfile.current_frame, NULL, finfo->appendix_length);
	}

	/* XXX, update fvalue_edit, e.g. when hexedit was changed */

	proto_item_fill_label(finfo, label_str);
	gtk_entry_set_text(GTK_ENTRY(DataPtr->repr), label_str);
	epan_dissect_cleanup(&edt);
	return TRUE;
}

static void
finfo_integer_changed(GtkSpinButton *spinbutton, gpointer user_data)
{
	struct FieldinfoWinData *DataPtr = (struct FieldinfoWinData *) user_data;
	const field_info *finfo = DataPtr->finfo;

	gdouble val = gtk_spin_button_get_value(spinbutton);

	int finfo_type = (finfo->hfinfo) ? finfo->hfinfo->type : FT_NONE;

	/* XXX, appendix? */
	unsigned int finfo_offset = DataPtr->start_offset + finfo->start;	
	int finfo_length = finfo->length;

	if (finfo_offset < DataPtr->frame->cap_len && finfo_offset + finfo_length < DataPtr->frame->cap_len) {
		guint64 u_val;

		if (finfo_type == FT_INT8 || finfo_type == FT_INT16 || finfo_type == FT_INT24 || finfo_type == FT_INT32 || finfo_type == FT_INT64)
			u_val = (guint64) ((gint) val);

		else if (finfo_type == FT_UINT8 || finfo_type == FT_UINT16 || finfo_type == FT_UINT24 || finfo_type == FT_UINT32 || finfo_type == FT_UINT64)
			u_val = (guint64) val;

		if (FI_GET_FLAG(finfo, FI_LITTLE_ENDIAN)) {
			while (finfo_length) {
				/* XXX, bitmask */
				DataPtr->pd[finfo_offset++] = u_val & 0xff;
				u_val >>= 8;
				finfo_length--;
			}
		} else {
			while (finfo_length) {
				/* XXX, bitmask */
				DataPtr->pd[finfo_offset + (--finfo_length)] = u_val & 0xff;
				u_val >>= 8;
			}
		}
	}
	finfo_window_refresh(user_data);
}

static gint
new_finfo_window(GtkWidget *w _U_, struct FieldinfoWinData *DataPtr)
{
	field_info *finfo = DataPtr->finfo;
	GtkWidget *dialog = gtk_dialog_new_with_buttons("Editing finfo: ....",
			GTK_WINDOW(w),
			GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
			GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
			NULL);

	GtkWidget *dialog_vbox = GTK_DIALOG(dialog)->vbox;
	GtkWidget *fvalue_edit;
	GtkWidget *native_repr;

	GtkWidget *bv_nb_ptr;

	int finfo_type = (finfo->hfinfo) ? finfo->hfinfo->type : FT_NONE;
	gint result;

	if (finfo_type == FT_INT8 || finfo_type == FT_INT16 || finfo_type == FT_INT24 || finfo_type == FT_INT32 ||
			finfo_type == FT_UINT8 || finfo_type == FT_UINT16 || finfo_type == FT_UINT24 || finfo_type == FT_UINT32)
	{
		GtkObject *adj;
		int bitcount = 0;

		if (finfo_type == FT_INT8 || finfo_type == FT_UINT8)
			bitcount = 8;
		if (finfo_type == FT_INT16 || finfo_type == FT_UINT16)
			bitcount = 16;
		if (finfo_type == FT_INT24 || finfo_type == FT_UINT24)
			bitcount = 24;
		if (finfo_type == FT_INT32 || finfo_type == FT_UINT32)
			bitcount = 32;

		/* XXX, limit to finfo->length */
		/* XXX, I'm little worried about these casts from (unsigned) integer to double... */

		if (finfo_type == FT_INT8 || finfo_type == FT_INT16 || finfo_type == FT_INT24 || finfo_type == FT_INT32 || finfo_type == FT_INT64)
			adj = gtk_adjustment_new((double) fvalue_get_sinteger(&finfo->value), (double) -(G_GINT64_CONSTANT(1) << (bitcount-1)), (double) ((G_GINT64_CONSTANT(1) << (bitcount-1))-1), 1.0, 10.0, 0);
		else if (finfo_type == FT_UINT8 || finfo_type == FT_UINT16 || finfo_type == FT_UINT24 || finfo_type == FT_UINT32 || finfo_type == FT_UINT64)
			adj = gtk_adjustment_new((double) fvalue_get_uinteger(&finfo->value), 0.0, (double) ((G_GINT64_CONSTANT(1U) << bitcount)-1), 1.0, 10.0, 0);
		else {
			g_assert_not_reached();
			goto not_supported;
		}
		fvalue_edit = gtk_spin_button_new(GTK_ADJUSTMENT(adj), 1.0, 0);

		gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(fvalue_edit), TRUE);
		g_signal_connect(fvalue_edit, "value-changed", G_CALLBACK(finfo_integer_changed), DataPtr);

	} else if (finfo_type == FT_BOOLEAN) {
		fvalue_edit = gtk_check_button_new();

	} else {
not_supported:
		fvalue_edit = gtk_entry_new();
		gtk_entry_set_text(GTK_ENTRY(fvalue_edit), "<not supported>");
		gtk_entry_set_editable(GTK_ENTRY(fvalue_edit), FALSE);
		gtk_widget_set_sensitive(fvalue_edit, FALSE);
	}
	gtk_box_pack_start(GTK_BOX(dialog_vbox), fvalue_edit, FALSE, FALSE, 0);
	gtk_widget_show(fvalue_edit);

	DataPtr->edit = fvalue_edit;

	native_repr = gtk_entry_new();
	gtk_entry_set_editable(GTK_ENTRY(native_repr), FALSE);
	gtk_widget_set_sensitive(native_repr, FALSE);
	gtk_box_pack_start(GTK_BOX(dialog_vbox), native_repr, FALSE, FALSE, 0);
	gtk_widget_show(native_repr);

	DataPtr->repr = native_repr;

	/* raw hex edit */
	if (finfo->start >= 0 && finfo->length > 0) {
		/* Byte view */
		bv_nb_ptr = byte_view_new();
		gtk_container_add(GTK_CONTAINER(dialog_vbox), bv_nb_ptr);
		gtk_widget_set_size_request(bv_nb_ptr, -1, BV_SIZE);
		gtk_widget_show(bv_nb_ptr);

		DataPtr->bv = bv_nb_ptr;
	}
	if (finfo->appendix_start >= 0 && finfo->appendix_length > 0) {
		/* Appendix byte view */
		bv_nb_ptr = byte_view_new();
		gtk_container_add(GTK_CONTAINER(dialog_vbox), bv_nb_ptr);
		gtk_widget_set_size_request(bv_nb_ptr, -1, BV_SIZE);
		gtk_widget_show(bv_nb_ptr);

		DataPtr->app_bv = bv_nb_ptr;
	}

	gtk_window_set_default_size(GTK_WINDOW(dialog), DEF_WIDTH, -1);
	finfo_window_refresh(DataPtr);
	result = gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
	return result;
}

static void
edit_pkt_tree_row_activated_cb(GtkTreeView *tree_view, GtkTreePath *path, GtkTreeViewColumn *column _U_, gpointer user_data)
{
	struct PacketWinData *DataPtr = (struct PacketWinData*)user_data;
	GtkTreeModel *model;
	GtkTreeIter iter;
	field_info *finfo;

	model = gtk_tree_view_get_model(tree_view);
	if (!gtk_tree_model_get_iter(model, &iter, path))
		return;

	gtk_tree_model_get(model, &iter, 1, &finfo, -1);
	if (!finfo) 
		return;

	/* XXX, simple_dialog() is shown on top of main_window, instead of edit_window. */

	if (!FI_GET_FLAG(finfo, FI_GENERATED) &&
			finfo->ds_tvb && finfo->ds_tvb->real_data >= DataPtr->pd && finfo->ds_tvb->real_data <= DataPtr->pd + DataPtr->frame->cap_len)
	{
		struct FieldinfoWinData data;

		if (!FI_GET_FLAG(finfo, FI_LITTLE_ENDIAN) && !FI_GET_FLAG(finfo, FI_BIG_ENDIAN)) {
			simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK, "Item can't be edited. Not added by proto_tree_add_item()");
			return;
		}
		/* XXX, verify if value stored in finfo is the same as in backed tvb
		if (0) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Item can't be edited. Value stored in finfo doesn't match value from tvb.");
			return;
		}
		 */

		data.frame = DataPtr->frame;
		data.pseudo_header = DataPtr->pseudo_header;
		data.pd = g_memdup(DataPtr->pd, DataPtr->frame->cap_len);
		data.start_offset = (int) (finfo->ds_tvb->real_data - DataPtr->pd);

		data.finfo = finfo;
		data.app_bv = data.bv = NULL;
		data.repr = data.edit = NULL;

		if (new_finfo_window(DataPtr->main, &data) == GTK_RESPONSE_ACCEPT) {
			/* DataPtr->pseudo_header = data.pseudo_header; */
			memcpy(DataPtr->pd, data.pd, DataPtr->frame->cap_len);

			epan_dissect_cleanup(&(DataPtr->edt));
			epan_dissect_init(&(DataPtr->edt), TRUE, TRUE);
			epan_dissect_run(&(DataPtr->edt), &DataPtr->pseudo_header, DataPtr->pd, DataPtr->frame, NULL);
			add_byte_views(&(DataPtr->edt), DataPtr->tree_view, DataPtr->bv_nb_ptr);
			proto_tree_draw(DataPtr->edt.tree, DataPtr->tree_view);
		}
		g_free(data.pd);

	} else
		simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK, "Item can't be edited. FI_GENERATED or tvb not subset of packet data (uncompressed?)");
}

static gboolean
edit_pkt_win_key_pressed_cb(GtkWidget *win _U_, GdkEventKey *event, gpointer user_data)
{
	struct PacketWinData *DataPtr = (struct PacketWinData*)user_data;
	header_field_info faked_hfinfo;
	field_info faked_finfo;
	int val = -1;
	GSList *src_le;

	switch (recent.gui_bytes_view) {
	case BYTES_HEX:
		if (event->keyval >= 'a' && event->keyval <= 'f')
			val = (event->keyval - 'a') + 10;
		else if (event->keyval >= 'A' && event->keyval <= 'F')
			val = (event->keyval - 'A') + 10;
		else if (event->keyval >= '0' && event->keyval <= '9')
			val = (event->keyval - '0');
		else if (event->keyval == GDK_Left)
			DataPtr->pd_bitoffset -= 4;
		else if (event->keyval == GDK_Right)
			DataPtr->pd_bitoffset += 4;
		else
			return FALSE;

		if (val != -1) {
			/* Lazy... 
			 * XXX Allow (DataPtr->pd_bitoffset % 4) != 0 ? */
			if (DataPtr->pd_bitoffset < 4) {
				DataPtr->pd[DataPtr->pd_offset] = (DataPtr->pd[DataPtr->pd_offset] & 0x0f) | (val << 4);
				DataPtr->pd_bitoffset = 4;
			} else {
				DataPtr->pd[DataPtr->pd_offset] = (DataPtr->pd[DataPtr->pd_offset] & 0xf0) | val;
				DataPtr->pd_bitoffset = 8;
			}
			/* DataPtr->pd_bitoffset += 4; */
		}
		break;

	case BYTES_BITS:
		if (event->keyval == '0' || event->keyval == '1')
			val = (event->keyval != '0');
		else if (event->keyval == GDK_Left)
			DataPtr->pd_bitoffset -= 1;
		else if (event->keyval == GDK_Right)
			DataPtr->pd_bitoffset += 1;
		else
			return FALSE;

		if (val != -1) {
			if (val)
				DataPtr->pd[DataPtr->pd_offset] |= (1 << (7-DataPtr->pd_bitoffset));
			else
				DataPtr->pd[DataPtr->pd_offset] &= ~(1 << (7-DataPtr->pd_bitoffset));
			DataPtr->pd_bitoffset += 1;
		}
		break;

	default:
		g_assert_not_reached();
		return FALSE;
	}

	while (DataPtr->pd_bitoffset >= 8) {
		DataPtr->pd_offset += 1;
		DataPtr->pd_bitoffset -= 8;
	}
	while (DataPtr->pd_bitoffset < 0) {
		DataPtr->pd_offset -= 1;
		DataPtr->pd_bitoffset += 8;
	}

	if (DataPtr->pd_offset < 0) {
		DataPtr->pd_offset = DataPtr->frame->cap_len-1;
		/* XXX, last bit/octect? */
	}

	if ((guint)DataPtr->pd_offset >= DataPtr->frame->cap_len) {
		DataPtr->pd_offset = 0;
		DataPtr->pd_bitoffset = 0; /* first bit */
	}

	switch (recent.gui_bytes_view) {
	case BYTES_HEX:
		faked_hfinfo.bitmask = 
			(DataPtr->pd_bitoffset == 0) ? 0xf0 :
			(DataPtr->pd_bitoffset == 4) ? 0x0f :
			0xff;
		break;

	case BYTES_BITS:
		faked_hfinfo.bitmask = (1 << (7-DataPtr->pd_bitoffset));
		break;
	}

	/* redissect if changed */
	if (val != -1) {
		/* XXX, can be optimized? */
		epan_dissect_cleanup(&(DataPtr->edt));
		epan_dissect_init(&(DataPtr->edt), TRUE, TRUE);
		epan_dissect_run(&(DataPtr->edt), &DataPtr->pseudo_header, DataPtr->pd, DataPtr->frame, NULL);
		add_byte_views(&(DataPtr->edt), DataPtr->tree_view, DataPtr->bv_nb_ptr);
		proto_tree_draw(DataPtr->edt.tree, DataPtr->tree_view);
	}

	/* hack, fake finfo, point to DataPtr->pd_offset */
	faked_finfo.appendix_length = 0;
	faked_finfo.start = DataPtr->pd_offset;
	faked_finfo.length = 1;
	faked_finfo.hfinfo = &faked_hfinfo;
	faked_finfo.flags = FI_BIG_ENDIAN;
	faked_finfo.ds_tvb = NULL;

	for (src_le = DataPtr->edt.pi.data_src; src_le != NULL; src_le = src_le->next) {
		const data_source *src = src_le->data;
		tvbuff_t *tvb = src->tvb;
		
		if (tvb && tvb->real_data == DataPtr->pd) {
			faked_finfo.ds_tvb = tvb;
			break;
		}
	}

	if (faked_finfo.ds_tvb != NULL) {
		GtkWidget    *byte_view;

		set_notebook_page(DataPtr->bv_nb_ptr, faked_finfo.ds_tvb);
		byte_view = get_notebook_bv_ptr(DataPtr->bv_nb_ptr);
		if (byte_view)
			packet_hex_print(byte_view, DataPtr->pd, DataPtr->frame, &faked_finfo, DataPtr->frame->cap_len);
	}
	return TRUE;
}

void new_packet_window(GtkWidget *w _U_, gboolean editable)
{
#define NewWinTitleLen 1000
  char Title[NewWinTitleLen] = "";
  const char *TextPtr;
  gint tv_size = 95;
  GtkWidget *main_w, *main_vbox, *pane,
                      *tree_view, *tv_scrollw,
                      *bv_nb_ptr;
  struct PacketWinData *DataPtr;
  int i;

  if (!cfile.current_frame) {
    /* nothing has been captured so far */
    return;
  }

  /* With the new packetlists "lazy columns" it's neccesary to reread the frame */
  if (!cf_read_frame(&cfile, cfile.current_frame)) {
    /* error reading the frame */
    return;
  }

  /* Allocate data structure to represent this window. */
  DataPtr = (struct PacketWinData *) g_malloc(sizeof(struct PacketWinData));

  DataPtr->frame = cfile.current_frame;
  memcpy(&DataPtr->pseudo_header, &cfile.pseudo_header, sizeof DataPtr->pseudo_header);
  DataPtr->pd = g_malloc(DataPtr->frame->cap_len);
  memcpy(DataPtr->pd, cfile.pd, DataPtr->frame->cap_len);

  epan_dissect_init(&(DataPtr->edt), TRUE, TRUE);
  epan_dissect_run(&(DataPtr->edt), &DataPtr->pseudo_header, DataPtr->pd,
          DataPtr->frame, &cfile.cinfo);
  epan_dissect_fill_in_columns(&(DataPtr->edt), FALSE, TRUE);

  /*
   * Build title of window by getting column data constructed when the
   * frame was dissected.
   */
  for (i = 0; i < cfile.cinfo.num_cols; ++i) {
    TextPtr = cfile.cinfo.col_data[i];
    if ((strlen(Title) + strlen(TextPtr)) < NewWinTitleLen - 1) {
      g_strlcat(Title, TextPtr, NewWinTitleLen);
      g_strlcat(Title, " ", NewWinTitleLen);
    }
  }

  main_w = window_new(GTK_WINDOW_TOPLEVEL, Title);
  gtk_window_set_default_size(GTK_WINDOW(main_w), DEF_WIDTH, -1);

  /* Container for paned windows  */
  main_vbox = gtk_vbox_new(FALSE, 1);
  gtk_container_set_border_width(GTK_CONTAINER(main_vbox), 1);
  gtk_container_add(GTK_CONTAINER(main_w), main_vbox);
  gtk_widget_show(main_vbox);

  /* Panes for the tree and byte view */
  pane = gtk_vpaned_new();
  gtk_container_add(GTK_CONTAINER(main_vbox), pane);
  gtk_widget_show(pane);

  /* Tree view */
  tv_scrollw = main_tree_view_new(&prefs, &tree_view);
  gtk_paned_pack1(GTK_PANED(pane), tv_scrollw, TRUE, TRUE);
  gtk_widget_set_size_request(tv_scrollw, -1, tv_size);
  gtk_widget_show(tv_scrollw);
  gtk_widget_show(tree_view);

  /* Byte view */
  bv_nb_ptr = byte_view_new();
  gtk_paned_pack2(GTK_PANED(pane), bv_nb_ptr, FALSE, FALSE);
  gtk_widget_set_size_request(bv_nb_ptr, -1, BV_SIZE);
  gtk_widget_show(bv_nb_ptr);

  DataPtr->main = main_w;
  DataPtr->tv_scrollw = tv_scrollw;
  DataPtr->tree_view = tree_view;
  DataPtr->bv_nb_ptr = bv_nb_ptr;
  detail_windows = g_list_append(detail_windows, DataPtr);

  /* load callback handlers */
  g_signal_connect(gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view)),
                 "changed", G_CALLBACK(new_tree_view_selection_changed_cb), DataPtr);
  g_signal_connect(tree_view, "button_press_event", G_CALLBACK(button_press_handler), NULL);
  if (editable && DataPtr->frame->cap_len != 0) {
    g_signal_connect(main_w, "key-press-event", G_CALLBACK(edit_pkt_win_key_pressed_cb), DataPtr);
    /* XXX, popup-menu instead of row-activated? */
    g_signal_connect(tree_view, "row-activated", G_CALLBACK(edit_pkt_tree_row_activated_cb), DataPtr);
  }
  g_signal_connect(main_w, "destroy", G_CALLBACK(destroy_new_window), DataPtr);

  /* draw the protocol tree & print hex data */
  add_byte_views(&(DataPtr->edt), tree_view, DataPtr->bv_nb_ptr);
  proto_tree_draw(DataPtr->edt.tree, tree_view);

  DataPtr->finfo_selected = NULL;
  DataPtr->pd_offset = 0;
  DataPtr->pd_bitoffset = 0;
  gtk_widget_show(main_w);
}

static void
destroy_new_window(GtkObject *object _U_, gpointer user_data)
{
  struct PacketWinData *DataPtr = user_data;

  detail_windows = g_list_remove(detail_windows, DataPtr);
  epan_dissect_cleanup(&(DataPtr->edt));
  g_free(DataPtr->pd);
  g_free(DataPtr);
}

/* called when a tree row is (un)selected in the popup packet window */
static void
new_tree_view_selection_changed_cb(GtkTreeSelection *sel, gpointer user_data)
{
    field_info   *finfo;
    GtkWidget    *byte_view;
    const guint8 *data;
    guint         len;
    GtkTreeModel *model;
    GtkTreeIter   iter;

    struct PacketWinData *DataPtr = (struct PacketWinData*)user_data;

    /* if something is selected */
    if (gtk_tree_selection_get_selected(sel, &model, &iter))
    {
        gtk_tree_model_get(model, &iter, 1, &finfo, -1);
        if (!finfo) return;

        set_notebook_page(DataPtr->bv_nb_ptr, finfo->ds_tvb);
        byte_view = get_notebook_bv_ptr(DataPtr->bv_nb_ptr);
        if (!byte_view)	/* exit if no hex window to write in */
            return;

        data = get_byte_view_data_and_length(byte_view, &len);
        if (data == NULL) {
            data = DataPtr->pd;
            len =  DataPtr->frame->cap_len;
        }

        DataPtr->finfo_selected = finfo;

        DataPtr->pd_offset = 0;
        DataPtr->pd_bitoffset = 0;

        if (!FI_GET_FLAG(finfo, FI_GENERATED) &&
            finfo->ds_tvb && finfo->ds_tvb->real_data >= DataPtr->pd && finfo->ds_tvb->real_data <= DataPtr->pd + DataPtr->frame->cap_len)
        {
            /* I haven't really test if TVB subsets works, but why not? :> */
            int pd_offset = (int) (finfo->ds_tvb->real_data - DataPtr->pd);

            /* some code from packet_hex_print */
            int finfo_offset = finfo->start;
            int finfo_len = finfo->length;

            if (!(finfo_offset >= 0 && finfo_len > 0)) {
                finfo_offset = finfo->appendix_start;
                finfo_len = finfo->appendix_length;
            }

            /* Don't care about things like bitmask or LE/BE, just point DataPtr->tvb_[bit]offset to proper offsets. */
            if (finfo_offset >= 0 && finfo_len > 0) {
                DataPtr->pd_offset = pd_offset + finfo_offset;
                DataPtr->pd_bitoffset = 0; /* XXX */
            }

            if (DataPtr->pd_offset < 0)
                DataPtr->pd_offset = 0;
            if ((guint)DataPtr->pd_offset >= DataPtr->frame->cap_len)
                DataPtr->pd_offset = 0;
        }

        packet_hex_print(byte_view, data, DataPtr->frame, finfo, len);
    }
    else
    {
        DataPtr->finfo_selected = NULL;

        byte_view = get_notebook_bv_ptr(DataPtr->bv_nb_ptr);
        if (!byte_view)	/* exit if no hex window to write in */
            return;

        data = get_byte_view_data_and_length(byte_view, &len);
        g_assert(data != NULL);
        packet_hex_reprint(byte_view);
    }
}

/* Functions called from elsewhere to act on all popup packet windows. */

/* Destroy all popup packet windows. */
void
destroy_packet_wins(void)
{
	struct PacketWinData *DataPtr;

	/* Destroying a packet window causes it to be removed from
	   the list of packet windows, so we can't do a "g_list_foreach()"
	   to go through the list of all packet windows and destroy them
	   as we find them; instead, as long as the list is non-empty,
	   we destroy the first window on the list. */
	while (detail_windows != NULL) {
		DataPtr = (struct PacketWinData *)(detail_windows->data);
		window_destroy(DataPtr->main);
	}
}

static void
redraw_packet_bytes_cb(gpointer data, gpointer user_data _U_)
{
	struct PacketWinData *DataPtr = (struct PacketWinData *)data;

	redraw_packet_bytes(DataPtr->bv_nb_ptr, DataPtr->frame, DataPtr->finfo_selected);
}

/* Redraw the packet bytes part of all the popup packet windows. */
void
redraw_packet_bytes_packet_wins(void)
{
	g_list_foreach(detail_windows, redraw_packet_bytes_cb, NULL);
}
