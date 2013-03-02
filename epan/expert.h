/* expert.h
 * Collecting of Expert information.
 *
 * For further info, see: http://wiki.wireshark.org/Development/ExpertInfo
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __EXPERT_H__
#define __EXPERT_H__

#include <epan/packet_info.h>
#include <epan/proto.h>
#include "value_string.h"
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** only for internal and display use. */
typedef struct expert_info_s {
	guint32 packet_num;
	int group;
	int severity;
	const gchar *protocol;
	gchar *summary;
	proto_item *pitem;
} expert_info_t;

static const value_string expert_group_vals[] = {
        { PI_CHECKSUM,          "Checksum" },
        { PI_SEQUENCE,          "Sequence" },
        { PI_RESPONSE_CODE,     "Response" },
        { PI_REQUEST_CODE,      "Request" },
        { PI_UNDECODED,         "Undecoded" },
        { PI_REASSEMBLE,        "Reassemble" },
        { PI_MALFORMED,         "Malformed" },
        { PI_DEBUG,             "Debug" },
        { PI_PROTOCOL,          "Protocol" },
        { PI_SECURITY,          "Security" },
        { PI_COMMENTS_GROUP,    "Comment" },
        { 0, NULL }
};

static const value_string expert_severity_vals[] = {
        { PI_ERROR,             "Error" },
        { PI_WARN,              "Warn" },
        { PI_NOTE,              "Note" },
        { PI_CHAT,              "Chat" },
        { PI_COMMENT,           "Comment" },
        { 0,                    "Ok" },
        { 0, NULL }
};

/* "proto_expert" is exported from libwireshark.dll.
 * Thus we need a special declaration.
 */
WS_DLL_PUBLIC int proto_expert;

extern void
expert_init(void);

extern void
expert_cleanup(void);

WS_DLL_PUBLIC int
expert_get_highest_severity(void);

/** Add an expert info.
 Add an expert info tree to a protocol item, with classification and message.
 @param pinfo Packet info of the currently processed packet. May be NULL if
        pi is supplied
 @param pi Current protocol item (or NULL)
 @param group The expert group (like PI_CHECKSUM - see: proto.h)
 @param severity The expert severity (like PI_WARN - see: proto.h)
 @param format Printf-style format string for additional arguments
 */
WS_DLL_PUBLIC void
expert_add_info_format(packet_info *pinfo, proto_item *pi, int group,
	int severity, const char *format, ...)
	G_GNUC_PRINTF(5, 6);

/** Add an expert info about not dissected "item"
 Add an expert info tree to a not dissected protocol item.
 @patam tvb The tvb associated with the item.
 @param pinfo Packet info of the currently processed packet. May be NULL.
 @param tree Tree to add the item to
 @param offset Offset in tvb
 @param length The length of the item.
 @param severity The expert severity (like PI_WARN - see: proto.h)
  */

WS_DLL_PUBLIC void
expert_add_undecoded_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length, const int severity);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EXPERT_H__ */
