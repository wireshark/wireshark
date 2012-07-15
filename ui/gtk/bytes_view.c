/* bytes_view.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

/* Code based on:
 *   xtext, the text widget used by X-Chat. Peter Zelezny <zed@xchat.org>.
 *   GtkTextView. Copyright (C) 2000 Red Hat, Inc.
 *   GtkHex. Jaka Mocnik <jaka@gnu.org>.
 *   pango-layout.c: High-level layout driver. Copyright (C) 2000, 2001, 2006 Red Hat Software
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#undef GTK_DISABLE_DEPRECATED
#undef GSEAL_ENABLE

#include <gtk/gtk.h>
#include "ui/gtk/old-gtk-compat.h"

#include <string.h>

#include "../isprint.h"

#include <epan/charsets.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#include "ui/recent.h"

#include "packet_panes.h"

#define MARGIN 2
#define REFRESH_TIMEOUT 10

static GtkWidgetClass *parent_class = NULL;

struct _BytesView
{
	GtkWidget widget;

	PangoContext *context;

	PangoFontDescription *font;
	int font_ascent;
	int font_descent;
	int fontsize;

	gint adj_tag;
	GtkAdjustment *vadj;
	GtkAdjustment *hadj;
	int max_width;

	gboolean bold_highlight;
	int state;

/* data */
	int encoding;
	int format;
	guint8 *pd;
	int len;
/* data-highlight */
	int start[2];
	int end[2];

	int per_line;
	int use_digits;
};

#include "bytes_view.h"

typedef struct _BytesViewClass
{
	GtkWidgetClass parent_class;

	void (*set_scroll_adjustments)(BytesView *, GtkAdjustment *, GtkAdjustment *);

} BytesViewClass;

static void bytes_view_set_scroll_adjustments(BytesView *, GtkAdjustment *, GtkAdjustment *);
static void bytes_view_adjustment_set(BytesView *);

static void 
bytes_view_init(BytesView *bv)
{
	bv->context = NULL;

	bv->encoding = PACKET_CHAR_ENC_CHAR_ASCII;
	bv->format = BYTES_HEX;

	bv->per_line = 16;
	bv->use_digits = 4;

	bv->max_width = 0;
}

static void 
bytes_view_destroy(GtkObject *object)
{
	BytesView *bv = BYTES_VIEW(object);

	if (bv->pd) {
		g_free(bv->pd);
		bv->pd = NULL;
	}
	if (bv->adj_tag) {
		g_source_remove(bv->adj_tag);
		bv->adj_tag = 0;
	}
	if (bv->vadj) {
		g_object_unref(G_OBJECT(bv->vadj));
		bv->vadj = NULL;
	}
	if (bv->hadj) {
		g_object_unref(G_OBJECT(bv->hadj));
		bv->hadj = NULL;
	}
	if (bv->font) {
		pango_font_description_free(bv->font);
		bv->font = NULL;
	}
	if (bv->context) {
		g_object_unref(bv->context);
		bv->context = NULL;
	}
	if (GTK_OBJECT_CLASS(parent_class)->destroy)
		(*GTK_OBJECT_CLASS(parent_class)->destroy)(object);
}

static void
bytes_view_ensure_layout(BytesView *bv)
{
	if (bv->context == NULL) {
		bv->context = gtk_widget_get_pango_context(GTK_WIDGET(bv));
		g_object_ref(bv->context);

		{
		PangoLanguage *lang;
		PangoFontMetrics *metrics;

			/* vte and xchat does it this way */
			lang = pango_context_get_language(bv->context);
			metrics = pango_context_get_metrics(bv->context, bv->font, lang);
			bv->font_ascent = pango_font_metrics_get_ascent(metrics) / PANGO_SCALE;
			bv->font_descent = pango_font_metrics_get_descent(metrics) / PANGO_SCALE;
			pango_font_metrics_unref(metrics);

			bv->fontsize = bv->font_ascent + bv->font_descent;
		}
		g_assert(bv->context);
		bytes_view_adjustment_set(bv);
	}
}

static void 
bytes_view_realize(GtkWidget *widget)
{
	BytesView *bv;
	GdkWindowAttr attributes;
 
	_gtk_widget_set_realized_true(widget);
	bv = BYTES_VIEW(widget);

	attributes.window_type = GDK_WINDOW_CHILD;
	attributes.x = widget->allocation.x;
	attributes.y = widget->allocation.y;
	attributes.width = widget->allocation.width;
	attributes.height = widget->allocation.height;
	attributes.wclass = GDK_INPUT_OUTPUT;
	attributes.visual = gtk_widget_get_visual(widget);
	attributes.colormap = gtk_widget_get_colormap(widget);

	attributes.event_mask = gtk_widget_get_events(widget) | GDK_EXPOSURE_MASK | GDK_BUTTON_PRESS_MASK | GDK_BUTTON_RELEASE_MASK | GDK_POINTER_MOTION_MASK;

	widget->window = gdk_window_new(widget->parent->window, &attributes, GDK_WA_X | GDK_WA_Y | GDK_WA_VISUAL | GDK_WA_COLORMAP);

	gdk_window_set_user_data(widget->window, widget);

	gdk_window_set_back_pixmap(widget->window, NULL, FALSE);
	widget->style = gtk_style_attach(widget->style, widget->window);
	bytes_view_ensure_layout(bv);
}

static void 
bytes_view_unrealize(GtkWidget *widget)
{
	BytesView *bv = BYTES_VIEW(widget);

	if (bv->context) {
		g_object_unref(bv->context);
		bv->context = NULL;
	}
	/* if there are still events in the queue, this'll avoid segfault */
	gdk_window_set_user_data(widget->window, NULL);

	if (parent_class->unrealize)
		(*GTK_WIDGET_CLASS(parent_class)->unrealize)(widget);
}

static GtkAdjustment *
bytes_view_ensure_vadj(BytesView *bv)
{
	if (bv->vadj == NULL) {
		bytes_view_set_scroll_adjustments(bv, bv->hadj, bv->vadj);
		g_assert(bv->vadj != NULL);
	}
	return bv->vadj;
}

static GtkAdjustment *
bytes_view_ensure_hadj(BytesView *bv)
{
	if (bv->hadj == NULL) {
		bytes_view_set_scroll_adjustments(bv, bv->hadj, bv->vadj);
		g_assert(bv->hadj != NULL);
	}
	return bv->hadj;
}

static gboolean 
bytes_view_scroll(GtkWidget *widget, GdkEventScroll *event)
{
	BytesView *bv = BYTES_VIEW(widget);

	gfloat new_value;

	if (event->direction == GDK_SCROLL_UP) {	/* mouse wheel pageUp */
		bytes_view_ensure_vadj(bv);

		new_value = bv->vadj->value - (bv->vadj->page_increment / 10);
		if (new_value < bv->vadj->lower)
			new_value = bv->vadj->lower;
		gtk_adjustment_set_value(bv->vadj, new_value);

	} else if (event->direction == GDK_SCROLL_DOWN) {	/* mouse wheel pageDn */
		bytes_view_ensure_vadj(bv);

		new_value = bv->vadj->value + (bv->vadj->page_increment / 10);
		if (new_value > (bv->vadj->upper - bv->vadj->page_size))
			new_value = bv->vadj->upper - bv->vadj->page_size;
		gtk_adjustment_set_value(bv->vadj, new_value);
	}
	return FALSE;
}

static void 
bytes_view_allocate(GtkWidget *widget, GtkAllocation *allocation)
{
	widget->allocation = *allocation;
	if (gtk_widget_get_realized(widget)) {
		BytesView *bv = BYTES_VIEW(widget);

		gdk_window_move_resize(widget->window, allocation->x, allocation->y, allocation->width, allocation->height);
		bytes_view_adjustment_set(bv);
	}
}

static void 
bytes_view_size_request(GtkWidget *widget _U_, GtkRequisition *requisition)
{
	requisition->width = 200;
	requisition->height = 90;
}

static GSList *
_pango_runs_build(BytesView *bv, const char *str, int len)
{
	GSList *runs = NULL;

	PangoAttrList *attrs;
	PangoAttrIterator *iter;

	GList *run_list;
	GList *tmp_list;

	attrs = pango_attr_list_new();
	pango_attr_list_insert_before(attrs, pango_attr_font_desc_new(bv->font));

	iter = pango_attr_list_get_iterator(attrs);

	run_list = pango_itemize(bv->context, str, 0, len, attrs, iter);

	for (tmp_list = run_list; tmp_list; tmp_list = tmp_list->next) {
		PangoLayoutRun *run = g_slice_new(PangoLayoutRun);
		PangoItem *run_item = tmp_list->data;

		run->item = run_item;

		/* XXX pango_layout_get_item_properties(run_item, &state->properties); */

		run->glyphs = pango_glyph_string_new();
		pango_shape(str + run_item->offset, run_item->length, &run_item->analysis, run->glyphs);

		runs = g_slist_prepend(runs, run);
	}

	g_list_free(run_list);

	pango_attr_iterator_destroy(iter);
	pango_attr_list_unref(attrs);

	return g_slist_reverse(runs);
}

static int
_pango_glyph_string_to_pixels(PangoGlyphString *glyphs, PangoFont *font _U_)
{
#if PANGO_VERSION_MAJOR == 1 && PANGO_VERSION_MINOR >= 14
	return pango_glyph_string_get_width(glyphs) / PANGO_SCALE;
#else
	PangoRectangle logical_rect;

	pango_glyph_string_extents(glyphs, font, NULL, &logical_rect);
 	/*  pango_extents_to_pixels(&logical_rect, NULL); */

	return (logical_rect.width / PANGO_SCALE);
#endif
}

static int
xtext_draw_layout_line(cairo_t *cr, gint x, gint y, GSList *runs)
{
	while (runs) {
		PangoLayoutRun *run = runs->data;

		cairo_move_to(cr, x, y);
		pango_cairo_show_glyph_string(cr, run->item->analysis.font, run->glyphs);

		x += _pango_glyph_string_to_pixels(run->glyphs, run->item->analysis.font);
		runs = runs->next;
	}
	return x;
}

static int
_pango_runs_width(GSList *runs)
{
	int width = 0;

	while (runs) {
		PangoLayoutRun *run = runs->data;

		width += _pango_glyph_string_to_pixels(run->glyphs, run->item->analysis.font);
		runs = runs->next;
	}
	return width;
}

static void
_pango_runs_free(GSList *runs)
{
	GSList *list = runs;

	while (list) {
		PangoLayoutRun *run = list->data;

		pango_item_free(run->item);
		pango_glyph_string_free(run->glyphs);
		g_slice_free(PangoLayoutRun, run);

		list = list->next;
	}
	g_slist_free(runs);
}

typedef int bytes_view_line_cb(BytesView *, void *data, int x, int arg1, const char *str, int len);

static int
bytes_view_flush_render(BytesView *bv, void *data, int x, int y, const char *str, int len)
{
	cairo_t *cr = data;
	GSList *line_runs;
	int str_width;

	if (len < 1)
		return 0;

	line_runs = _pango_runs_build(bv, str, len);

	/* XXX, cliping */

	if (bv->state != GTK_STATE_NORMAL) {
		str_width = _pango_runs_width(line_runs);

		/* background */
		gdk_cairo_set_source_color(cr, &gtk_widget_get_style(GTK_WIDGET(bv))->base[bv->state]);
		cairo_rectangle(cr, x, y - bv->font_ascent, str_width, bv->fontsize);
		cairo_fill(cr);
	}

	/* text */
	gdk_cairo_set_source_color(cr, &gtk_widget_get_style(GTK_WIDGET(bv))->text[bv->state]);
	str_width = xtext_draw_layout_line(cr, x, y, line_runs)-x;

	_pango_runs_free(line_runs);

	return str_width;
}

static int
_pango_runs_find_index(GSList *runs, int x_pos, const char *str)
{
	int start_pos = 0;

	while (runs) {
		PangoLayoutRun *run = runs->data;
		int width;

		width = _pango_glyph_string_to_pixels(run->glyphs, run->item->analysis.font);

		if (x_pos >= start_pos && x_pos < start_pos + width) {
			gboolean char_trailing;
			int pos;

			pango_glyph_string_x_to_index(run->glyphs,
					(char *) str + run->item->offset, run->item->length,
					&run->item->analysis,
					(x_pos - start_pos) * PANGO_SCALE,
					&pos, &char_trailing);

			return run->item->offset + pos;
		}

		start_pos += width;
		runs = runs->next;
	}
	return -1;
}

static int
bytes_view_flush_pos(BytesView *bv, void *data, int x, int search_x, const char *str, int len)
{
	int *pos_x = data;
	GSList *line_runs;
	int line_width;

	if (len < 1)
		return 0;

	line_runs = _pango_runs_build(bv, str, len);

	line_width = _pango_runs_width(line_runs);

	if (x <= search_x && x + line_width > search_x) {
		int off_x = search_x - x;
		int pos_run;
		
		if ((pos_run = _pango_runs_find_index(line_runs, off_x, str)) != -1)
			*pos_x = (-*pos_x) + pos_run;

		return -1;	/* terminate */
	} else
		*pos_x -= len;

	_pango_runs_free(line_runs);

	return line_width;
}

static void
bytes_view_render_state(BytesView *bv, int state)
{
	g_assert(state == GTK_STATE_NORMAL || state == GTK_STATE_SELECTED);

	if (bv->bold_highlight) {
		pango_font_description_set_weight(bv->font, 
				(state == GTK_STATE_SELECTED) ? PANGO_WEIGHT_BOLD : PANGO_WEIGHT_NORMAL);
		bv->state = GTK_STATE_NORMAL;
	} else
		bv->state = state;
}

#define BYTE_VIEW_SEP    8      /* insert a space every BYTE_VIEW_SEP bytes */

static void
_bytes_view_line_common(BytesView *bv, void *data, const int org_off, int xx, int arg1, bytes_view_line_cb flush)
{
	static const guchar hexchars[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	const guint8 *pd = bv->pd;
	const int len = bv->len;

	int state;

	char str[128];
	int cur = 0;

	int off;
	guchar c;
	int byten;
	int j;

	int scroll_x;
	int dx;

	g_assert(org_off >= 0);

	scroll_x = bytes_view_ensure_hadj(bv)->value;

	state = GTK_STATE_NORMAL;
	bytes_view_render_state(bv, GTK_STATE_NORMAL);

	/* Print the line number */
	j = bv->use_digits;
	do {
		j--;
		c = (org_off >> (j*4)) & 0xF;
		str[cur++] = hexchars[c];
	} while (j != 0);
	str[cur++] = ' ';
	str[cur++] = ' ';

	/* Print the hex bit */
	for (byten = 0, off = org_off; byten < bv->per_line; byten++) {
		gboolean byte_highlighted = 
			(off >= bv->start[0] && off < bv->end[0]) ||
			(off >= bv->start[1] && off < bv->end[1]);
		int state_cur = (off < len && byte_highlighted) ?
				GTK_STATE_SELECTED : GTK_STATE_NORMAL;

		if (state_cur != state) {
			if (state == GTK_STATE_NORMAL && byten) {
				str[cur++] = ' ';
				/* insert a space every BYTE_VIEW_SEP bytes */
				if ((off % BYTE_VIEW_SEP) == 0)
					str[cur++] = ' ';
			}

			if ((dx = flush(bv, data, xx - scroll_x, arg1, str, cur)) < 0)
				return;
			xx += dx;
			cur = 0;
			bytes_view_render_state(bv, state_cur);
			state = state_cur;

			if (state == GTK_STATE_NORMAL && byten) {
				str[cur++] = ' ';
				/* insert a space every BYTE_VIEW_SEP bytes */
				if ((off % BYTE_VIEW_SEP) == 0)
					str[cur++] = ' ';
			}

		} else if (byten) {
			str[cur++] = ' ';
			/* insert a space every BYTE_VIEW_SEP bytes */
			if ((off % BYTE_VIEW_SEP) == 0)
				str[cur++] = ' ';
		}

		if (off < len) {
			switch (bv->format) {
				case BYTES_HEX:
					str[cur++] = hexchars[(pd[off] & 0xf0) >> 4];
					str[cur++] = hexchars[pd[off] & 0x0f];
					break;
				case BYTES_BITS:
					/* XXX, bitmask */
					for (j = 7; j >= 0; j--)
						str[cur++] = (pd[off] & (1 << j)) ? '1' : '0';
					break;
			}
		} else {
			switch (bv->format) {
				case BYTES_HEX:
					str[cur++] = ' ';
					str[cur++] = ' ';
					break;
				case BYTES_BITS:
					for (j = 7; j >= 0; j--)
						str[cur++] = ' ';
					break;
			}
		}
		off++;
	}

	if (state != GTK_STATE_NORMAL) {
		if ((dx = flush(bv, data, xx - scroll_x, arg1, str, cur)) < 0)
			return;
		xx += dx;
		cur = 0;
		bytes_view_render_state(bv, GTK_STATE_NORMAL);
		state = GTK_STATE_NORMAL;
	}

	/* Print some space at the end of the line */
	str[cur++] = ' '; str[cur++] = ' '; str[cur++] = ' ';

	/* Print the ASCII bit */
	for (byten = 0, off = org_off; byten < bv->per_line; byten++) {
		gboolean byte_highlighted = 
			(off >= bv->start[0] && off < bv->end[0]) ||
			(off >= bv->start[1] && off < bv->end[1]);
		int state_cur = (off < len && byte_highlighted) ?
				GTK_STATE_SELECTED : GTK_STATE_NORMAL;

		if (state_cur != state) {
			if (state == GTK_STATE_NORMAL && byten) {
				/* insert a space every BYTE_VIEW_SEP bytes */
				if ((off % BYTE_VIEW_SEP) == 0)
					str[cur++] = ' ';
			}

			if ((dx = flush(bv, data, xx - scroll_x, arg1, str, cur)) < 0)
				return;
			xx += dx;
			cur = 0;
			bytes_view_render_state(bv, state_cur);
			state = state_cur;

			if (state == GTK_STATE_NORMAL && byten) {
				/* insert a space every BYTE_VIEW_SEP bytes */
				if ((off % BYTE_VIEW_SEP) == 0)
					str[cur++] = ' ';
			}

		} else if (byten) {
			/* insert a space every BYTE_VIEW_SEP bytes */
			if ((off % BYTE_VIEW_SEP) == 0)
				str[cur++] = ' ';
		}

		if (off < len) {
			c = (bv->encoding == PACKET_CHAR_ENC_CHAR_EBCDIC) ? 
				EBCDIC_to_ASCII1(pd[off]) :
				pd[off];

			str[cur++] = isprint(c) ? c : '.';
		} else
			str[cur++] = ' ';

		off++;
	}

	if (cur) {
		if ((dx = flush(bv, data, xx - scroll_x, arg1, str, cur)) < 0)
			return;
		xx += dx;
		/* cur = 0; */
	}

	if (state != GTK_STATE_NORMAL) {
		bytes_view_render_state(bv, GTK_STATE_NORMAL);
		/* state = GTK_STATE_NORMAL; */
	}

	if (bv->max_width < xx)
		bv->max_width = xx;
}

static void
_bytes_view_render_line(BytesView *bv, cairo_t *cr, const int org_off, int yy)
{
	_bytes_view_line_common(bv, cr, org_off, MARGIN, yy, bytes_view_flush_render);
}

static int
_bytes_view_find_pos(BytesView *bv, const int org_off, int search_x)
{
	int pos_x = 0;

	_bytes_view_line_common(bv, &pos_x, org_off, MARGIN, search_x, bytes_view_flush_pos);

	return pos_x;
}

static void
bytes_view_render(BytesView *bv, GdkRectangle *area)
{
	const int old_max_width = bv->max_width;

	int width, height;
	GdkDrawable *draw_buf;
	cairo_t *cr;
	int y;
	int off;

	guint line, lines_max;
	guint lines_max_full;

	if (!gtk_widget_get_realized(GTK_WIDGET(bv)))
		return;

	bytes_view_ensure_layout(bv);

	draw_buf = GTK_WIDGET(bv)->window;
	gdk_drawable_get_size(draw_buf, &width, &height);

	if (width < 32 + MARGIN || height < bv->fontsize)
		return;

	if (area) {
		line = area->y / bv->fontsize;
		lines_max = 1 + (area->y + area->height) / bv->fontsize;
	} else {
		line = 0;
		lines_max = (guint) -1;
	}

	off = 0;
	y = (bv->fontsize * line);

	cr = gdk_cairo_create(draw_buf);
	if (area) {
		gdk_cairo_rectangle(cr, area);
		/* gdk_cairo_area(cr, rectangle); */
		cairo_clip(cr);
	}

	/* clear */
	gdk_cairo_set_source_color(cr, &gtk_widget_get_style(GTK_WIDGET(bv))->base[GTK_STATE_NORMAL]);
	if (area)
		cairo_rectangle(cr, area->x, area->y, area->x + area->width, area->y + area->height);
	else
		cairo_rectangle(cr, 0, 0, width, height);
	cairo_fill(cr);

	if (bv->pd) {
		guint real_line = line + bytes_view_ensure_vadj(bv)->value;

		lines_max_full = (height / bv->fontsize) + 1;
		if (lines_max_full < lines_max)
			lines_max = lines_max_full;

		off = real_line * bv->per_line;

		while (off < bv->len) {
			_bytes_view_render_line(bv, cr, off, y + bv->font_ascent);
			line++;
			if (line >= lines_max)
				break;

			off += bv->per_line;
			y += bv->fontsize;
		}
	}

	cairo_destroy(cr);

	if (old_max_width != bv->max_width)
		bytes_view_adjustment_set(bv);
}

static void
bytes_view_render_full(BytesView *bv)
{
	if (bv->adj_tag) {
		g_source_remove(bv->adj_tag);
		bv->adj_tag = 0;
	}
	bytes_view_render(bv, NULL);
}

static void
bytes_view_paint(GtkWidget *widget, GdkRectangle *area)
{
	BytesView *bv = BYTES_VIEW(widget);

	if (area->x == 0 && area->y == 0 && area->height == widget->allocation.height && area->width == widget->allocation.width)
		bytes_view_render_full(bv);
	else
		bytes_view_render(bv, area);
}

static gboolean 
bytes_view_expose(GtkWidget *widget, GdkEventExpose *event)
{
	bytes_view_paint(widget, &event->area);
	return FALSE;
}

static void 
bytes_view_adjustment_set(BytesView *bv)
{
	if (bv->vadj) {
		bv->vadj->lower = 0;
		bv->vadj->upper = (int) (bv->len / bv->per_line);
		if ((bv->len % bv->per_line))
			bv->vadj->upper++;

		bytes_view_ensure_layout(bv);

		bv->vadj->page_size =
			(GTK_WIDGET(bv)->allocation.height - bv->font_descent) / bv->fontsize;
		bv->vadj->step_increment = 1;
		bv->vadj->page_increment = bv->vadj->page_size;

		if (bv->vadj->value > bv->vadj->upper - bv->vadj->page_size)
			bv->vadj->value = bv->vadj->upper - bv->vadj->page_size;

		if (bv->vadj->value < 0)
			bv->vadj->value = 0;

		gtk_adjustment_changed(bv->vadj);
	}

	if (bv->hadj) {
		bv->hadj->lower = 0;
		bv->hadj->upper = bv->max_width;

		bytes_view_ensure_layout(bv);

		bv->hadj->page_size = (GTK_WIDGET(bv)->allocation.width);
		bv->hadj->step_increment = bv->hadj->page_size / 10.0;
		bv->hadj->page_increment = bv->hadj->page_size;

		if (bv->hadj->value > bv->hadj->upper - bv->hadj->page_size)
			bv->hadj->value = bv->hadj->upper - bv->hadj->page_size;

		if (bv->hadj->value < 0)
			bv->hadj->value = 0;

		gtk_adjustment_changed(bv->hadj);
	}
}

static gint 
bytes_view_adjustment_timeout(BytesView *bv)
{
	bv->adj_tag = 0;
	bytes_view_render_full(bv);
	return 0;
}

static void 
bytes_view_adjustment_changed(GtkAdjustment *adj, BytesView *bv)
{
	/*  delay rendering when scrolling (10ms) */
	if (adj && ((adj == bv->vadj) || (adj == bv->hadj))) {
		if (!bv->adj_tag)
			bv->adj_tag = g_timeout_add(REFRESH_TIMEOUT, (GSourceFunc) bytes_view_adjustment_timeout, bv);
	}
}

static void
bytes_view_set_scroll_adjustments(BytesView *bv, GtkAdjustment *hadj, GtkAdjustment *vadj)
{
	gboolean need_adjust = FALSE;

	g_return_if_fail(!hadj || GTK_IS_ADJUSTMENT(hadj));
	g_return_if_fail(!vadj || GTK_IS_ADJUSTMENT(vadj));

	if (!vadj)
		vadj = GTK_ADJUSTMENT(gtk_adjustment_new(0.0, 0.0, 0.0, 0.0, 0.0, 0.0));

	if (!hadj)
		hadj = GTK_ADJUSTMENT(gtk_adjustment_new(0.0, 0.0, 0.0, 0.0, 0.0, 0.0));

	if (bv->vadj && (bv->vadj != vadj)) {
		g_signal_handlers_disconnect_by_func(bv->vadj, bytes_view_adjustment_changed, bv);
		g_object_unref(bv->vadj);
	}
	if (bv->vadj != vadj) {
		bv->vadj = vadj;
		g_object_ref_sink(bv->vadj);

		g_signal_connect(bv->vadj, "value-changed", G_CALLBACK(bytes_view_adjustment_changed), bv);
		need_adjust = TRUE;
	}

	if (bv->hadj && (bv->hadj != hadj)) {
		g_signal_handlers_disconnect_by_func(bv->hadj, bytes_view_adjustment_changed, bv);
		g_object_unref(bv->hadj);
	}
	if (bv->hadj != hadj) {
		bv->hadj = hadj;
		g_object_ref_sink(bv->hadj);

		g_signal_connect(bv->hadj, "value-changed", G_CALLBACK(bytes_view_adjustment_changed), bv);
		need_adjust = TRUE;
	}

	if (need_adjust)
		bytes_view_adjustment_set(bv);
}

static void 
bytes_view_class_init(BytesViewClass *klass)
{
	GtkObjectClass *object_class;
	GtkWidgetClass *widget_class;

	parent_class = (GtkWidgetClass *) g_type_class_peek_parent(klass);

	object_class = (GtkObjectClass *) klass;
	widget_class = (GtkWidgetClass *) klass;

	object_class->destroy = bytes_view_destroy;
	widget_class->realize = bytes_view_realize;
	widget_class->unrealize = bytes_view_unrealize;
	widget_class->size_request = bytes_view_size_request;
	widget_class->size_allocate = bytes_view_allocate;
	widget_class->expose_event = bytes_view_expose;
	widget_class->scroll_event = bytes_view_scroll;

	klass->set_scroll_adjustments = bytes_view_set_scroll_adjustments;

	widget_class->set_scroll_adjustments_signal = 
		g_signal_new(g_intern_static_string("set-scroll-adjustments"),
			G_OBJECT_CLASS_TYPE(object_class),
			G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
			G_STRUCT_OFFSET(BytesViewClass, set_scroll_adjustments),
			NULL, NULL,
			gtk_marshal_VOID__POINTER_POINTER,
/*			_gtk_marshal_VOID__OBJECT_OBJECT, */
			G_TYPE_NONE, 2,
			GTK_TYPE_ADJUSTMENT,
			GTK_TYPE_ADJUSTMENT);
}

GType 
bytes_view_get_type(void)
{
	static GType bytes_view_type = 0;
	
	if (!bytes_view_type) {
		static const GTypeInfo bytes_view_info = {
			sizeof (BytesViewClass),
			NULL, /* base_init */
			NULL, /* base_finalize */
			(GClassInitFunc) bytes_view_class_init,
			NULL, /* class finalize */
			NULL, /* class_data */
			sizeof(BytesView),
			0, /* n_preallocs */
			(GInstanceInitFunc) bytes_view_init,
			NULL /* value_table */
		};
	
		bytes_view_type = g_type_register_static(GTK_TYPE_WIDGET,
							"BytesView",
							&bytes_view_info,
							(GTypeFlags)0);	
	}
	return bytes_view_type;
}

int 
bytes_view_byte_from_xy(BytesView *bv, int x, int y)
{
	/* hex_pos_byte array generated with hex_view_get_byte(0, 0, 0...70) */
	static const int hex_pos_byte[70] = { 
		-1, -1,
		0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3,
		4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7,
		-1,
		8, 8, 8, 9, 9, 9, 10, 10, 10, 11, 11, 11,
		12, 12, 12, 13, 13, 13, 14, 14, 14, 15, 15, 15,
		-1, -1,
		0, 1, 2, 3, 4, 5, 6, 7,
		-1,
		8, 9, 10, 11, 12, 13, 14, 15
	};

	/* bits_pos_byte array generated with bit_view_get_byte(0, 0, 0...84) */
	static const int bits_pos_byte[84] = {
		-1, -1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5,
		6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		-1, -1,
		0, 1, 2, 3, 4, 5, 6, 7
	};

	int char_x, off_x = 1;
	int char_y, off_y;

	if (x < MARGIN)
		return -1;

	bytes_view_ensure_layout(bv);

	char_y = bytes_view_ensure_vadj(bv)->value + (y / bv->fontsize);
	off_y = char_y * bv->per_line;

	char_x = _bytes_view_find_pos(bv, off_y, x);
	if (/* char_x < 0 || */ char_x < bv->use_digits)
		return -1;
	char_x -= bv->use_digits;

	switch (bv->format) {
		case BYTES_BITS:
			g_return_val_if_fail(char_x >= 0 && char_x < (int) G_N_ELEMENTS(bits_pos_byte), -1);
			off_x = bits_pos_byte[char_x];
			break;

		case BYTES_HEX:
			g_return_val_if_fail(char_x >= 0 && char_x < (int) G_N_ELEMENTS(hex_pos_byte), -1);
			off_x = hex_pos_byte[char_x];
			break;
	}

	if (off_x == -1)
		return -1;

	return off_y + off_x;
}

void 
bytes_view_scroll_to_byte(BytesView *bv, int byte)
{
	int line;

	g_return_if_fail(byte >= 0 && byte < bv->len);

	line = byte / bv->per_line;

	bytes_view_ensure_vadj(bv);

	if (line > bv->vadj->upper - bv->vadj->page_size) {
		line = bv->vadj->upper - bv->vadj->page_size;

		if (line < 0)
			line = 0;
	}

	/* after bytes_view_scroll_to_byte() we always do bytes_view_refresh() so we can block it */
	g_signal_handlers_block_by_func(bv->vadj, bytes_view_adjustment_changed, bv);
	gtk_adjustment_set_value(bv->vadj, line);
	g_signal_handlers_unblock_by_func(bv->vadj, bytes_view_adjustment_changed, bv);

	/* XXX, scroll hadj? */
}

void
bytes_view_set_font(BytesView *bv, PangoFontDescription *font)
{
	if (bv->font)
		pango_font_description_free(bv->font);

	bv->font = pango_font_description_copy(font);
	bv->max_width = 0;

	if (bv->context) {
		g_object_unref(bv->context);
		bv->context = NULL;
		bytes_view_ensure_layout(bv);
	}
}

void 
bytes_view_set_data(BytesView *bv, const guint8 *data, int len)
{
	g_free(bv->pd);
	bv->pd = g_memdup(data, len);
	bv->len = len;

	/*
	 * How many of the leading digits of the offset will we supply?
	 * We always supply at least 4 digits, but if the maximum offset
	 * won't fit in 4 digits, we use as many digits as will be needed.
	 */
	if (((len - 1) & 0xF0000000) != 0)
		bv->use_digits = 8; /* need all 8 digits */
	else if (((len - 1) & 0x0F000000) != 0)
		bv->use_digits = 7; /* need 7 digits */
	else if (((len - 1) & 0x00F00000) != 0)
		bv->use_digits = 6; /* need 6 digits */
	else if (((len - 1) & 0x000F0000) != 0)
		bv->use_digits = 5; /* need 5 digits */
	else
		bv->use_digits = 4; /* we'll supply 4 digits */

	bytes_view_ensure_vadj(bv);

	bytes_view_adjustment_set(bv);
}

void 
bytes_view_set_encoding(BytesView *bv, int enc)
{
	g_assert(enc == PACKET_CHAR_ENC_CHAR_ASCII || enc == PACKET_CHAR_ENC_CHAR_EBCDIC);

	bv->encoding = enc;
}

void 
bytes_view_set_format(BytesView *bv, int format)
{
	g_assert(format == BYTES_HEX || format == BYTES_BITS);

	bv->format = format;

	switch (format) {
		case BYTES_BITS:
			bv->per_line = 8;
			break;

		case BYTES_HEX:
			bv->per_line = 16;
			break;
	}
}

void
bytes_view_set_highlight_style(BytesView *bv, gboolean inverse)
{
	bv->bold_highlight = !inverse;
}

void 
bytes_view_set_highlight(BytesView *bv, int start, int end, guint32 mask _U_, int maskle _U_)
{
	bv->start[0] = start;
	bv->end[0] = end;
}

void 
bytes_view_set_highlight_appendix(BytesView *bv, int start, int end)
{
	bv->start[1] = start;
	bv->end[1] = end;
}

void 
bytes_view_refresh(BytesView *bv)
{
	/* bytes_view_render_full(bv); */
	gtk_widget_queue_draw(GTK_WIDGET(bv));
}

GtkWidget *
bytes_view_new(void)
{
	GtkWidget *widget;

	widget = (GtkWidget *) g_object_new(BYTES_VIEW_TYPE, NULL);

	g_assert(widget != NULL);

	return widget;
}
