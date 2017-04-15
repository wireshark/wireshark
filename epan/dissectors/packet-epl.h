/* packet-epl.h
 * Routines for "Ethernet POWERLINK 2.0" dissection
 * (Ethernet POWERLINK V2.0 Communication Profile Specification Draft Standard Version 1.2.0)
 *
 * A dissector for:
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __EPL_H_
#define __EPL_H_

#include <glib.h>
#include <epan/address.h>
#include <epan/wmem/wmem.h>
#include <epan/range.h>

typedef struct epl_wmem_iarray epl_wmem_iarray_t;

#endif
