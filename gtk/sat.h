/* sat.h
 * 2003 Ronnie Sahlberg
 * Sub-address types for MAC/URI addresses
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

#ifndef __GTK_SAT_H__
#define __GTK_SAT_H__

/** @file
 *  Sub-address type definitions.
 */

/** Address type */
typedef enum {
    SAT_NONE,       /**< no address type */
    SAT_ETHER,      /**< MAC : Ethernet */
    SAT_FDDI,       /**< MAC : FDDI */
    SAT_TOKENRING,  /**< MAC : Token Ring */
    SAT_JXTA        /**< URI : JXTA */
} SAT_E;

#endif /* __GTK_SAT_H__ */
