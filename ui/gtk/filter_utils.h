/* filter_utils.h
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
 */

#ifndef __FILTER_UTILS_H__
#define __FILTER_UTILS_H__

#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))

/* Filter actions */
#define ACTION_MATCH            0
#define ACTION_PREPARE          1
#define ACTION_FIND_FRAME       2
#define ACTION_FIND_NEXT        3
#define ACTION_FIND_PREVIOUS    4
#define ACTION_COLORIZE         5
#define ACTION_WEB_LOOKUP       6
#define ACTION_COPY             7


/* Action type - says what to do with the filter */
#define ACTYPE_SELECTED         0
#define ACTYPE_NOT_SELECTED     1
#define ACTYPE_AND_SELECTED     2
#define ACTYPE_OR_SELECTED      3
#define ACTYPE_AND_NOT_SELECTED 4
#define ACTYPE_OR_NOT_SELECTED  5

/* Encoded callback arguments */
#define CALLBACK_MATCH(type, extra)         ((ACTION_MATCH<<16) | ((type)<<8) | (extra))
#define CALLBACK_PREPARE(type, extra)       ((ACTION_PREPARE<<16) | ((type)<<8) | (extra))
#define CALLBACK_FIND_FRAME(type, extra)    ((ACTION_FIND_FRAME<<16) | ((type)<<8) | (extra))
#define CALLBACK_FIND_NEXT(type, extra)     ((ACTION_FIND_NEXT<<16) | ((type)<<8) | (extra))
#define CALLBACK_FIND_PREVIOUS(type, extra) ((ACTION_FIND_PREVIOUS<<16) | ((type)<<8) | (extra))
#define CALLBACK_COLORIZE(type, extra)      ((ACTION_COLORIZE<<16) | ((type)<<8) | (extra))
#define CALLBACK_WEB_LOOKUP                 (ACTION_WEB_LOOKUP<<16)
#define CALLBACK_COPY                       (ACTION_COPY<<16)


/* Extract components of callback argument */
#define FILTER_ACTION(cb_arg)           (((cb_arg)>>16) & 0xff)
#define FILTER_ACTYPE(cb_arg)           (((cb_arg)>>8) & 0xff)
#define FILTER_EXTRA(cb_arg)            ((cb_arg) & 0xff)


extern void apply_selected_filter (guint callback_action, char *filter);

#endif /* __FILTER_UTILS_H__ */
