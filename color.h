/* color.h
 * Definitions for "toolkit-independent" colors
 *
 * $Id: color.h,v 1.3 2002/09/23 19:09:47 oabad Exp $
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

#ifndef __COLOR_H__
#define __COLOR_H__

#include "epan/dfilter/dfilter.h"

/*
 * Data structure holding RGB value for a color.
 *
 * XXX - yes, I know, there's a "pixel" value in there as well; for
 * now, it's intended to look just like a GdkColor but not to require
 * that any GTK+ header files be included in order to use it.
 * The way we handle colors needs to be cleaned up somewhat, in order
 * to keep toolkit-specific stuff separate from toolkit-independent stuff.
 */
typedef struct {
	guint32 pixel;
	guint16 red;
	guint16 green;
	guint16 blue;
} color_t;

/* Data for a color filter. */
typedef struct _color_filter {
        gchar     *filter_name;   /* name of the filter */
        gchar     *filter_text;   /* text of the filter expression */
        color_t    bg_color;      /* background color for packets that match */
        color_t    fg_color;      /* foreground color for packets that match */
        dfilter_t *c_colorfilter; /* compiled filter expression */
        void      *edit_dialog;   /* if filter is being edited, dialog
                                   * box for it */
} color_filter_t;

/* List of all color filters. */
extern GSList *filter_list;

void
filter_list_prime_edt(epan_dissect_t *edt);

#endif
