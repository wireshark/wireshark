/* packet-protobuf.h
 * Routines for Google Protocol Buffers dissection
 * Copyright 2017, Huang Qiangxiong <qiangxiong.huang@qq.com>
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

#ifndef __PACKET_PROTOBUF_H__
#define __PACKET_PROTOBUF_H__

/* Protobuf wire type. Must be kept in sync with WireType of protobuf wire_format_lite.h
    0 used for int32, int64, uint32, uint64, sint32, sint64, bool, enum
    1 used for fixed64, sfixed64, double
    2 used for string, bytes, embedded messages, packed repeated fields
    3 used for groups (deprecated)
    4 used for groups (deprecated)
    5 used for fixed32, sfixed32, float
*/
#define protobuf_wire_type_VALUE_STRING_LIST(XXX)    \
    XXX(PROTOBUF_WIRETYPE_VARINT, 0, "varint")  \
    XXX(PROTOBUF_WIRETYPE_FIXED64, 1, "64-bit")   \
    XXX(PROTOBUF_WIRETYPE_LENGTH_DELIMITED, 2, "Length-delimited") \
    XXX(PROTOBUF_WIRETYPE_START_GROUP, 3, "Start group (deprecated)") \
    XXX(PROTOBUF_WIRETYPE_END_GROUP, 4, "End group (deprecated)") \
    XXX(PROTOBUF_WIRETYPE_FIXED32, 5, "32-bit")

VALUE_STRING_ENUM(protobuf_wire_type);
VALUE_STRING_ARRAY_GLOBAL_DCL(protobuf_wire_type);

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
