/* util.h
 * Utility definitions
 *
 * $Id: util.h,v 1.10 1999/06/12 09:10:20 guy Exp $
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

#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Dialog type. */
#define ESD_TYPE_INFO 0
#define ESD_TYPE_WARN 1
#define ESD_TYPE_CRIT 2

/* Which buttons to display. */
#define ESD_BTN_OK     0
#define ESD_BTN_CANCEL 1

#if __GNUC__ == 2
void simple_dialog(gint, gint *, gchar *, ...)
    __attribute__((format (printf, 3, 4)));
#else
void simple_dialog(gint, gint *, gchar *, ...);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UTIL_H__ */
