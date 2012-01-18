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
#if GTK_CHECK_VERSION(3,0,0)
# include <gdk/gdkkeysyms-compat.h>
#endif

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
#include <epan/tvbuff-int.h>

#include "../file.h"
#include "../print.h"
#include "../summary.h"

#include "ui/recent.h"
#include "ui/simple_dialog.h"
#include "ui/ui_util.h"

#include "ui/gtk/font_utils.h"
#include "ui/gtk/main.h"
#include "ui/gtk/packet_win.h"
#include "ui/gtk/main_proto_draw.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/gui_utils.h"

#define BV_SIZE 75
#define TV_SIZE 95

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

#ifdef WANT_PACKET_EDITOR
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

	int pd_offset;
	int pd_bitoffset;
};

struct CommonWinData {
	frame_data *frame;	   /* The frame being displayed */
	guint8     *pd;		   /* Data for packet */

	int pd_offset;
	int pd_bitoffset;
	int val;
};

static gboolean edit_pkt_common_key_pressed_cb(GdkEventKey *event, struct CommonWinData *DataPtr);
#endif

/* List of all the packet-detail windows popped up. */
static GList *detail_windows;

static void new_tree_view_selection_changed_cb(GtkTreeSelection *sel,
                                               gpointer user_data);


static void destroy_new_window(GObject *object, gpointer user_data);

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

#ifdef WANT_PACKET_EDITOR
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
	field_info *finfo;
	epan_dissect_t edt;

	const guint8 *data;
	GtkWidget *byte_view;
	gchar label_str[ITEM_LABEL_LENGTH];

	/* always update byteviews */
	if (DataPtr->bv && (byte_view = get_notebook_bv_ptr(DataPtr->bv))) {
		int pos_inside = DataPtr->pd_offset - DataPtr->start_offset - old_finfo->start;

		if (pos_inside < 0 || pos_inside >= old_finfo->length)
			pos_inside = -1;

		data = DataPtr->pd + DataPtr->start_offset + old_finfo->start;
		packet_hex_editor_print(byte_view, data, DataPtr->frame, pos_inside, DataPtr->pd_bitoffset, old_finfo->length);
	}

	if (DataPtr->app_bv && (byte_view = get_notebook_bv_ptr(DataPtr->app_bv))) {
		int pos_inside = DataPtr->pd_offset - DataPtr->start_offset - old_finfo->appendix_start;

		if (pos_inside < 0 || pos_inside >= old_finfo->appendix_length)
			pos_inside = -1;

		data = DataPtr->pd + DataPtr->start_offset + old_finfo->appendix_start;
		packet_hex_editor_print(byte_view, data, DataPtr->frame, pos_inside, DataPtr->pd_bitoffset, old_finfo->appendix_length);
	}

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

	/* XXX, update fvalue_edit, e.g. when hexedit was changed */

	if (finfo->rep == NULL) {
		proto_item_fill_label(finfo, label_str);
		gtk_entry_set_text(GTK_ENTRY(DataPtr->repr), label_str);
	} else
		gtk_entry_set_text(GTK_ENTRY(DataPtr->repr), finfo->rep->representation);

	epan_dissect_cleanup(&edt);
	return TRUE;
}

static void
finfo_integer_common(struct FieldinfoWinData *DataPtr, guint64 u_val)
{
	const field_info *finfo = DataPtr->finfo;
	const header_field_info *hfinfo = finfo->hfinfo;
	/* XXX, appendix? */
	unsigned int finfo_offset = DataPtr->start_offset + finfo->start;
	int finfo_length = finfo->length;

	if (finfo_offset <= DataPtr->frame->cap_len && finfo_offset + finfo_length <= DataPtr->frame->cap_len) {
		guint32 u_mask = hfinfo->bitmask;

		while (finfo_length--) {
			guint8 *ptr = (FI_GET_FLAG(finfo, FI_LITTLE_ENDIAN)) ?
					&(DataPtr->pd[finfo_offset++]) :
					&(DataPtr->pd[finfo_offset + finfo_length]);

			if (u_mask) {
				guint8 n_val = *ptr;
				int i;

				for (i = 0; i < 8; i++) {
					if (u_mask & 1) {
						if (u_val & 1)
							n_val |= (1 << i);
						else
							n_val &= ~(1 << i);
					}
					u_mask >>= 1;
					u_val >>= 1;
				}
				*ptr = n_val;

				if (!u_mask)
					break;
			} else {
				*ptr = u_val & 0xff;
				u_val >>= 8;
			}
		}
	}
	finfo_window_refresh(DataPtr);
}

static void
finfo_string_changed(GtkEditable *editable, gpointer user_data)
{
	struct FieldinfoWinData *DataPtr = (struct FieldinfoWinData *) user_data;

	/* XXX, appendix? */
	const field_info *finfo = DataPtr->finfo;
	unsigned int finfo_offset = DataPtr->start_offset + finfo->start;
	int finfo_length = finfo->length;
	int finfo_type = (finfo->hfinfo) ? finfo->hfinfo->type : FT_NONE;

	const gchar *val = gtk_entry_get_text(GTK_ENTRY(editable));

	if (finfo_offset <= DataPtr->frame->cap_len && finfo_offset + finfo_length <= DataPtr->frame->cap_len) {
		/* strncpy */
		while (finfo_length && *val) {
			DataPtr->pd[finfo_offset++] = *val;
			finfo_length--;
			val++;
		}

		/* When FT_STRINGZ is there free space for NUL? */
		if (finfo_type == FT_STRINGZ && finfo_length) {
			DataPtr->pd[finfo_offset++] = '\0';
			finfo_length--;
		}

		/* XXX, string shorter than previous one. Warn user (red background?), for now fill with NULs */
		while (finfo_length > 0) {
			DataPtr->pd[finfo_offset++] = '\0';
			finfo_length--;
		}
	}
	finfo_window_refresh(DataPtr);
}

static void
finfo_boolean_changed(GtkToggleButton *togglebutton, gpointer user_data)
{
	struct FieldinfoWinData *DataPtr = (struct FieldinfoWinData *) user_data;

	gboolean val = gtk_toggle_button_get_active(togglebutton);

	finfo_integer_common(DataPtr, val ? G_MAXUINT64 : 0);
}

static void
finfo_integer_changed(GtkSpinButton *spinbutton, gpointer user_data)
{
	struct FieldinfoWinData *DataPtr = (struct FieldinfoWinData *) user_data;

	const field_info *finfo = DataPtr->finfo;
	const header_field_info *hfinfo = finfo->hfinfo;
	int finfo_type = (hfinfo) ? hfinfo->type : FT_NONE;

	gdouble val = gtk_spin_button_get_value(spinbutton);
	guint64 u_val;

	if (finfo_type == FT_INT8 || finfo_type == FT_INT16 || finfo_type == FT_INT24 || finfo_type == FT_INT32 || finfo_type == FT_INT64)
		u_val = (guint64) ((gint64) val);

	else if (finfo_type == FT_UINT8 || finfo_type == FT_UINT16 || finfo_type == FT_UINT24 || finfo_type == FT_UINT32 || finfo_type == FT_UINT64)
		u_val = (guint64) val;
	else {
		g_assert_not_reached();
		return;
	}

	if (hfinfo->bitmask && hfinfo->bitshift > 0)
		u_val <<= hfinfo->bitshift;

	finfo_integer_common(DataPtr, u_val);
}

static void
finfo_ipv4_changed(GtkSpinButton *spinbutton, gpointer user_data)
{
	struct FieldinfoWinData *DataPtr = (struct FieldinfoWinData *) user_data;

	gdouble val = gtk_spin_button_get_value(spinbutton);

	finfo_integer_common(DataPtr, (guint32) val);
}

static gboolean
finfo_bv_key_pressed_cb(GtkWidget *bv _U_, GdkEventKey *event, gpointer user_data)
{
	struct FieldinfoWinData *DataPtr = (struct FieldinfoWinData *)user_data;
	const field_info *finfo = DataPtr->finfo;
	struct CommonWinData data;
	gboolean have_appendix;
	gboolean ret;

	/* save */
	data.frame = DataPtr->frame;
	data.pd = DataPtr->pd;
	data.pd_offset = DataPtr->pd_offset;
	data.pd_bitoffset = DataPtr->pd_bitoffset;

	ret = edit_pkt_common_key_pressed_cb(event, &data);

	/* restore */
	DataPtr->pd_offset = data.pd_offset;
	DataPtr->pd_bitoffset = data.pd_bitoffset;

	/* XXX, assuming finfo->appendix_start >= finfo->start, and if appendix exists, main exists also.
	 *      easy to fix if needed */
	have_appendix = (finfo->appendix_start >= 0 && finfo->appendix_length > 0);

	if ((DataPtr->pd_offset >= DataPtr->start_offset + finfo->start && DataPtr->pd_offset < DataPtr->start_offset + finfo->start + finfo->length) ||
		(have_appendix && DataPtr->pd_offset >= DataPtr->start_offset + finfo->appendix_start && DataPtr->pd_offset < DataPtr->start_offset + finfo->appendix_start + finfo->appendix_length))
		{ /* pd_offset ok */ }
	else
	if (have_appendix && DataPtr->pd_offset >= DataPtr->start_offset + finfo->appendix_start + finfo->appendix_length) {
		DataPtr->pd_offset = DataPtr->start_offset + finfo->start;
		DataPtr->pd_bitoffset = 0; /* first bit */

	} else if (DataPtr->pd_offset >= DataPtr->start_offset + finfo->start + finfo->length) {
		if (have_appendix)
			DataPtr->pd_offset = DataPtr->start_offset + finfo->appendix_start;
		else
			DataPtr->pd_offset = DataPtr->start_offset + finfo->start;
		DataPtr->pd_bitoffset = 0; /* first bit */
	}
	else
	if (DataPtr->pd_offset < DataPtr->start_offset + finfo->start) {
		if (have_appendix)
			DataPtr->pd_offset = DataPtr->start_offset + finfo->appendix_start + finfo->appendix_length-1;
		else
			DataPtr->pd_offset = DataPtr->start_offset + finfo->start + finfo->length-1;
		/* XXX, last bit/octect? */

	} else if (have_appendix && DataPtr->pd_offset < DataPtr->start_offset + finfo->appendix_start) {
		DataPtr->pd_offset = DataPtr->start_offset + finfo->start + finfo->length-1;
		/* XXX, last bit/octect? */
	}

	if (ret)
		finfo_window_refresh(DataPtr);
	return ret;
}

static gint
finfo_ipv4_input(GtkSpinButton *spinbutton, gpointer arg1, gpointer user_data _U_)
{
	const gchar *addr_str = gtk_entry_get_text(GTK_ENTRY(spinbutton));
	gdouble *out_val = (gdouble *) arg1;
	guint32 addr;
#if 0
	/* XXX, get_host_ipaddr() support hostname resolution */
	if (!get_host_ipaddr(addr_str, &addr))
		return GTK_INPUT_ERROR;
	addr = GUINT32_FROM_BE(addr);
#else
	unsigned int a0, a1, a2, a3;

	if (sscanf(addr_str, "%u.%u.%u.%u", &a0, &a1, &a2, &a3) != 4)
		return GTK_INPUT_ERROR;

	if (a0 > 255 || a1 > 255 || a2 > 255 || a3 > 255)
		return GTK_INPUT_ERROR;

	addr = a0 << 24 | a1 << 16 | a2 << 8 | a3;
#endif
	*out_val = (gdouble) addr;
	return TRUE;
}

static gboolean
finfo_ipv4_output(GtkSpinButton *spinbutton, gpointer user_data _U_)
{
	GtkAdjustment *adj;
	guint32 value;

	adj = gtk_spin_button_get_adjustment(spinbutton);
	value = (guint32) gtk_adjustment_get_value(adj);
	value = GUINT32_TO_BE(value);
	/* ip_to_str_buf((guint8*)&value, buf, MAX_IP_STR_LEN); */	/* not exported */
	gtk_entry_set_text(GTK_ENTRY(spinbutton), ip_to_str((guint8*)&value));	/* XXX, can we ep_alloc() inside gui? */
	return TRUE;
}

static gint
new_finfo_window(GtkWidget *w, struct FieldinfoWinData *DataPtr)
{
	field_info *finfo = DataPtr->finfo;
	const header_field_info *hfinfo = finfo->hfinfo;
	int finfo_type = (hfinfo) ? hfinfo->type : FT_NONE;

	GtkWidget *dialog = gtk_dialog_new_with_buttons("Editing finfo: ....",
			GTK_WINDOW(w),
			GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
			GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
			NULL);

	GtkWidget *dialog_vbox = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
	GtkWidget *fvalue_edit;
	GtkWidget *native_repr;
	GtkWidget *bv_nb_ptr;
	GtkWidget *frame, *frame_vbox;

	gint result;

	if (!FI_GET_FLAG(finfo, FI_LITTLE_ENDIAN) && !FI_GET_FLAG(finfo, FI_BIG_ENDIAN)) {
		fvalue_edit = gtk_entry_new();
		gtk_entry_set_text(GTK_ENTRY(fvalue_edit), "<not added by proto_tree_add_item()>");
		gtk_editable_set_editable(GTK_EDITABLE(fvalue_edit), FALSE);
		gtk_widget_set_sensitive(fvalue_edit, FALSE);

	} /* else if (XXX) {
		fvalue_edit = gtk_entry_new();
		gtk_entry_set_text(GTK_ENTRY(fvalue_edit), "<ERROR: Value stored in finfo doesn't match value from tvb>");
		gtk_editable_set_editable(GTK_EDITABLE(fvalue_edit), FALSE);
		gtk_widget_set_sensitive(fvalue_edit, FALSE);

	} */ else if (finfo_type == FT_INT8 || finfo_type == FT_INT16 || finfo_type == FT_INT24 || finfo_type == FT_INT32 ||
			finfo_type == FT_UINT8 || finfo_type == FT_UINT16 || finfo_type == FT_UINT24 || finfo_type == FT_UINT32)
	{
#if GTK_CHECK_VERSION(3,0,0)
		GtkAdjustment *adj;
#else
		GtkObject *adj;
#endif
		int bitcount = 0;

		if (finfo_type == FT_INT8 || finfo_type == FT_UINT8)
			bitcount = 8;
		if (finfo_type == FT_INT16 || finfo_type == FT_UINT16)
			bitcount = 16;
		if (finfo_type == FT_INT24 || finfo_type == FT_UINT24)
			bitcount = 24;
		if (finfo_type == FT_INT32 || finfo_type == FT_UINT32)
			bitcount = 32;
		/* if (finfo_type == FT_INT64 || finfo_type == FT_UINT64)
			bitcount = 64; */

		if (finfo->length * 8 < bitcount)
			bitcount = finfo->length / 8;

		if (hfinfo->bitmask && hfinfo->bitshift > 0)
			bitcount -= hfinfo->bitshift;

		/* XXX, hfinfo->bitmask: Can we configure GTK_ADJUSTMENT to do custom step? (value-changed signal?) */

		/* XXX, I'm little worried about these casts from (unsigned) integer to double... */

		if (finfo_type == FT_INT8 || finfo_type == FT_INT16 || finfo_type == FT_INT24 || finfo_type == FT_INT32 /* || finfo_type == FT_INT64 */)
			adj = gtk_adjustment_new((double) fvalue_get_sinteger(&finfo->value), (double) -(G_GINT64_CONSTANT(1) << (bitcount-1)), (double) ((G_GINT64_CONSTANT(1) << (bitcount-1))-1), 1.0, 10.0, 0);
		else if (finfo_type == FT_UINT8 || finfo_type == FT_UINT16 || finfo_type == FT_UINT24 || finfo_type == FT_UINT32 /* || finfo_type == FT_UINT64 */ )
			adj = gtk_adjustment_new((double) fvalue_get_uinteger(&finfo->value), 0.0, (double) ((G_GINT64_CONSTANT(1U) << bitcount)-1), 1.0, 10.0, 0);
		else {
			g_assert_not_reached();
			goto not_supported;
		}

		fvalue_edit = gtk_spin_button_new(GTK_ADJUSTMENT(adj), 1.0, 0);
		gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(fvalue_edit), TRUE);
		g_signal_connect(fvalue_edit, "value-changed", G_CALLBACK(finfo_integer_changed), DataPtr);

	} else if (finfo_type == FT_STRING || finfo_type == FT_STRINGZ) {
		fvalue_edit = gtk_entry_new();
		gtk_entry_set_max_length(GTK_ENTRY(fvalue_edit), finfo->length);
		gtk_entry_set_text(GTK_ENTRY(fvalue_edit), fvalue_get(&finfo->value));
		g_signal_connect(fvalue_edit, "changed", G_CALLBACK(finfo_string_changed), DataPtr);

	} else if (finfo_type == FT_BOOLEAN) {
		fvalue_edit = gtk_check_button_new();
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(fvalue_edit), (fvalue_get_uinteger(&finfo->value) != 0));
		g_signal_connect(fvalue_edit, "toggled", G_CALLBACK(finfo_boolean_changed), DataPtr);

	} else if (finfo_type == FT_IPv4) {
		guint32 net_addr = ipv4_get_net_order_addr(fvalue_get(&finfo->value));
#if GTK_CHECK_VERSION(3,0,0)
		GtkAdjustment *adj;
#else
		GtkObject *adj;
#endif
		adj = gtk_adjustment_new((double) (GUINT32_FROM_BE(net_addr)), 0.0, 4294967295.0 /* (2^32)-1 */, 1.0, 256.0, 0);

		/* XXX, create four gtk_spin_button_new which takes 0..255 */
		fvalue_edit = gtk_spin_button_new(GTK_ADJUSTMENT(adj), 1.0, 0);
		gtk_spin_button_set_update_policy(GTK_SPIN_BUTTON(fvalue_edit), GTK_UPDATE_IF_VALID);
		g_signal_connect(fvalue_edit, "value-changed", G_CALLBACK(finfo_ipv4_changed), DataPtr);
		g_signal_connect(fvalue_edit, "input", G_CALLBACK(finfo_ipv4_input), NULL);
		g_signal_connect(fvalue_edit, "output", G_CALLBACK(finfo_ipv4_output), NULL);

	} else {
not_supported:
		/* List of unsupported FT_*:
			FT_NONE, FT_PROTOCOL,
			FT_BYTES, FT_UINT_BYTES,
			FT_INT64, FT_UINT64,			; should work with FT_INT[8,16,24,32] code
			FT_FLOAT, FT_DOUBLE,
			FT_IPXNET, FT_IPv6, FT_ETHER,
			FT_GUID, FT_OID,
			FT_UINT_STRING,
			FT_ABSOLUTE_TIME, FT_RELATIVE_TIME
		*/
		fvalue_edit = gtk_entry_new();
		gtk_entry_set_text(GTK_ENTRY(fvalue_edit), "<not supported>");
		gtk_editable_set_editable(GTK_EDITABLE(fvalue_edit), FALSE);
		gtk_widget_set_sensitive(fvalue_edit, FALSE);
	}
	gtk_box_pack_start(GTK_BOX(dialog_vbox), fvalue_edit, FALSE, FALSE, 0);
	gtk_widget_show(fvalue_edit);

	DataPtr->edit = fvalue_edit;

	native_repr = gtk_entry_new();
	gtk_editable_set_editable(GTK_EDITABLE(native_repr), FALSE);
	gtk_widget_set_sensitive(native_repr, FALSE);
	gtk_box_pack_start(GTK_BOX(dialog_vbox), native_repr, FALSE, FALSE, 0);
	gtk_widget_show(native_repr);

	DataPtr->repr = native_repr;

	frame = gtk_frame_new("Hex edit");
	frame_vbox = gtk_vbox_new(TRUE, 1);

	/* raw hex edit */
	if (finfo->start >= 0 && finfo->length > 0) {
		GtkWidget *byte_view;
		/* Byte view */
		bv_nb_ptr = byte_view_new();
		gtk_container_add(GTK_CONTAINER(frame_vbox), bv_nb_ptr);
		gtk_widget_set_size_request(bv_nb_ptr, -1, BV_SIZE);
		gtk_widget_show(bv_nb_ptr);

		if ((byte_view = get_notebook_bv_ptr(bv_nb_ptr)))
			g_signal_connect(byte_view, "key-press-event", G_CALLBACK(finfo_bv_key_pressed_cb), DataPtr);
		DataPtr->bv = bv_nb_ptr;
	}

	if (finfo->appendix_start >= 0 && finfo->appendix_length > 0) {
		GtkWidget *byte_view;
		/* Appendix byte view */
		bv_nb_ptr = byte_view_new();
		gtk_container_add(GTK_CONTAINER(frame_vbox), bv_nb_ptr);
		gtk_widget_set_size_request(bv_nb_ptr, -1, BV_SIZE);
		gtk_widget_show(bv_nb_ptr);

		if ((byte_view = get_notebook_bv_ptr(bv_nb_ptr)))
			g_signal_connect(byte_view, "key-press-event", G_CALLBACK(finfo_bv_key_pressed_cb), DataPtr);
		DataPtr->app_bv = bv_nb_ptr;
	}
	gtk_container_add(GTK_CONTAINER(frame), frame_vbox);
	gtk_widget_show(frame_vbox); gtk_widget_show(frame);
	gtk_container_add(GTK_CONTAINER(dialog_vbox), frame);

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

	if (!FI_GET_FLAG(finfo, FI_GENERATED) &&
			finfo->ds_tvb && finfo->ds_tvb->real_data >= DataPtr->pd && finfo->ds_tvb->real_data <= DataPtr->pd + DataPtr->frame->cap_len)
	{
		struct FieldinfoWinData data;

		data.frame = DataPtr->frame;
		data.pseudo_header = DataPtr->pseudo_header;
		data.pd = g_memdup(DataPtr->pd, DataPtr->frame->cap_len);
		data.start_offset = (int) (finfo->ds_tvb->real_data - DataPtr->pd);

		data.finfo = finfo;
		data.app_bv = data.bv = NULL;
		data.repr = data.edit = NULL;

		data.pd_offset = data.start_offset + finfo->start;
		data.pd_bitoffset = 0;

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

	} else {
		/* XXX, simple_dialog() is shown on top of main_window, instead of edit_window. */
		simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK, "Item can't be edited. FI_GENERATED or tvb not subset of packet data (uncompressed?)");
	}
}

static gboolean
edit_pkt_common_key_pressed_cb(GdkEventKey *event, struct CommonWinData *DataPtr)
{
	int val = -1;

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

	DataPtr->val = val;
	return TRUE;
}

static gboolean
edit_pkt_win_key_pressed_cb(GtkWidget *win _U_, GdkEventKey *event, gpointer user_data)
{
	struct PacketWinData *DataPtr = (struct PacketWinData *)user_data;
	struct CommonWinData data;
	GSList *src_le;
	gboolean ret;
	tvbuff_t *ds_tvb = NULL;

	/* save */
	data.frame = DataPtr->frame;
	data.pd = DataPtr->pd;
	data.pd_offset = DataPtr->pd_offset;
	data.pd_bitoffset = DataPtr->pd_bitoffset;

	ret = edit_pkt_common_key_pressed_cb(event, &data);

	/* restore */
	DataPtr->pd_offset = data.pd_offset;
	DataPtr->pd_bitoffset = data.pd_bitoffset;

	if (DataPtr->pd_offset < 0) {
		DataPtr->pd_offset = DataPtr->frame->cap_len-1;
		/* XXX, last bit/octect? */
	}

	if ((guint)DataPtr->pd_offset >= DataPtr->frame->cap_len) {
		DataPtr->pd_offset = 0;
		DataPtr->pd_bitoffset = 0; /* first bit */
	}

	if (!ret)
		return FALSE;

	/* redissect if changed */
	if (data.val != -1) {
		/* XXX, can be optimized? */
		epan_dissect_cleanup(&(DataPtr->edt));
		epan_dissect_init(&(DataPtr->edt), TRUE, TRUE);
		epan_dissect_run(&(DataPtr->edt), &DataPtr->pseudo_header, DataPtr->pd, DataPtr->frame, NULL);
		add_byte_views(&(DataPtr->edt), DataPtr->tree_view, DataPtr->bv_nb_ptr);
		proto_tree_draw(DataPtr->edt.tree, DataPtr->tree_view);
	}

	for (src_le = DataPtr->edt.pi.data_src; src_le != NULL; src_le = src_le->next) {
		const data_source *src = src_le->data;
		tvbuff_t *tvb = src->tvb;

		if (tvb && tvb->real_data == DataPtr->pd) {
			ds_tvb = tvb;
			break;
		}
	}

	if (ds_tvb != NULL) {
		GtkWidget    *byte_view;

		set_notebook_page(DataPtr->bv_nb_ptr, ds_tvb);
		byte_view = get_notebook_bv_ptr(DataPtr->bv_nb_ptr);
		if (byte_view)
			packet_hex_editor_print(byte_view, DataPtr->pd, DataPtr->frame, DataPtr->pd_offset, DataPtr->pd_bitoffset, DataPtr->frame->cap_len);
	}
	return TRUE;
}

static void
edit_pkt_destroy_new_window(GObject *object _U_, gpointer user_data)
{
	/* like destroy_new_window, but without freeding DataPtr->pd */
	struct PacketWinData *DataPtr = user_data;

	detail_windows = g_list_remove(detail_windows, DataPtr);
	epan_dissect_cleanup(&(DataPtr->edt));
	g_free(DataPtr);

	/* XXX, notify main packet list that packet should be redisplayed */
}

static gint g_direct_compare_func(gconstpointer a, gconstpointer b, gpointer user_data _U_) {
	if (a > b)
		return 1;
	else if (a < b)
		return -1;
	else
		return 0;
}

static void modifed_frame_data_free(gpointer data) {
	modified_frame_data *mfd = (modified_frame_data *) data;

	g_free(mfd->pd);
	g_free(mfd);
}

#endif /* WANT_PACKET_EDITOR */

void new_packet_window(GtkWidget *w _U_, gboolean editable _U_)
{
#define NewWinTitleLen 1000
	char Title[NewWinTitleLen] = "";
	const char *TextPtr;
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
	gtk_widget_set_size_request(tv_scrollw, -1, TV_SIZE);
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
#ifdef WANT_PACKET_EDITOR
	if (editable && DataPtr->frame->cap_len != 0) {
		g_signal_connect(main_w, "key-press-event", G_CALLBACK(edit_pkt_win_key_pressed_cb), DataPtr);
		/* XXX, popup-menu instead of row-activated? */
		g_signal_connect(tree_view, "row-activated", G_CALLBACK(edit_pkt_tree_row_activated_cb), DataPtr);
		g_signal_connect(main_w, "destroy", G_CALLBACK(edit_pkt_destroy_new_window), DataPtr);
	} else
#endif
		g_signal_connect(main_w, "destroy", G_CALLBACK(destroy_new_window), DataPtr);

	/* draw the protocol tree & print hex data */
	add_byte_views(&(DataPtr->edt), tree_view, DataPtr->bv_nb_ptr);
	proto_tree_draw(DataPtr->edt.tree, tree_view);

	DataPtr->finfo_selected = NULL;
	DataPtr->pd_offset = 0;
	DataPtr->pd_bitoffset = 0;
	gtk_widget_show(main_w);

#ifdef WANT_PACKET_EDITOR
	if (editable && DataPtr->frame->cap_len != 0) {
		/* XXX, there's no Save button here, so lets assume packet is always edited */
		modified_frame_data *mfd = g_malloc(sizeof(modified_frame_data));

		mfd->pd = DataPtr->pd;
		mfd->ph = DataPtr->pseudo_header;

		if (cfile.edited_frames == NULL)
			cfile.edited_frames = g_tree_new_full(g_direct_compare_func, NULL, NULL, modifed_frame_data_free);
		g_tree_insert(cfile.edited_frames, GINT_TO_POINTER(DataPtr->frame->num), mfd);
		DataPtr->frame->file_off = -1;
	}
#endif
}

static void
destroy_new_window(GObject *object _U_, gpointer user_data)
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

#ifdef WANT_PACKET_EDITOR
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
#endif

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
