/* guid-utils.h
 * Definitions for GUID handling
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 *
 * Copyright 1998 Gerald Combs
 *
 * MobileIPv6 support added by Tomislav Borosa <tomislav.borosa@siemens.hr>
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

#ifndef __GUID_UTILS_H__
#define __GUID_UTILS_H__

typedef struct _e_guid_t {
    guint32 data1;
    guint16 data2;
    guint16 data3;
    guint8  data4[8];
} e_guid_t;

#endif /* __GUID_UTILS_H__ */
