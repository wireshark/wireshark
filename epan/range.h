/* range.h
 * Range routines
 *
 * $Id$
 *
 * Dick Gooris <gooris@lucent.com>
 * Ulf Lamping <ulf.lamping@web.de>
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

#ifndef __RANGE_H__
#define __RANGE_H__

#include <glib.h>

#include <epan/frame_data.h>

/* Range parser variables */
#define MaxRange  30

typedef struct range_admin_tag {
    guint32 low;
    guint32 high;
} range_admin_t;

typedef struct range {
    /* user specified range(s) */
    guint           nranges;        /* number of entries in ranges (0 based) */
    range_admin_t   ranges[MaxRange];
} range_t;

extern void range_init(range_t *range);

extern void range_convert_str(range_t *range, const gchar *es,
    guint32 max_value);

extern gboolean value_is_in_range(range_t *range, guint32 val);

#endif /* __RANGE_H__ */
