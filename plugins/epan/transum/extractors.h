/* extractors.h
* Header file for the TRANSUM response time analyzer post-dissector
* By Paul Offord <paul.offord@advance7.com>
* Copyright 2016 Advance Seven Limited
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
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "config.h"
#include <epan/prefs.h>
#include <epan/packet.h>

#define MAX_RETURNED_ELEMENTS 16

int extract_uint(proto_tree *tree, int field_id, guint32 *result_array, size_t *element_count);
int extract_ui64(proto_tree *tree, int field_id, guint64 *result_array, size_t *element_count);
int extract_si64(proto_tree *tree, int field_id, guint64 *result_array, size_t *element_count);
int extract_bool(proto_tree *tree, int field_id, gboolean *result_array, size_t *element_count);
