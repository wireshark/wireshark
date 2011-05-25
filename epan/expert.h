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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __EXPERT_H__
#define __EXPERT_H__

#include <epan/proto.h>
#include "value_string.h"

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

WS_VAR_IMPORT const value_string expert_severity_vals[];
WS_VAR_IMPORT const value_string expert_group_vals[];

extern void
expert_init(void);

extern void
expert_cleanup(void);

extern int
expert_get_highest_severity(void);

/** Add an expert info.
 Add an expert info tree to a protocol item, with classification and message.
 @param pinfo packet info of the currently processed packet
 @param pi current protocol item (or NULL)
 @param group the expert group (like PI_CHECKSUM - see: proto.h)
 @param severity the expert severity (like PI_WARN - see: proto.h)
 @param format printf like format string with further infos
 */
extern void
expert_add_info_format(packet_info *pinfo, proto_item *pi, int group,
	int severity, const char *format, ...)
	G_GNUC_PRINTF(5, 6);

/** Add an expert info about not dissected "item"
 Add an expert info tree to a not dissected protocol item.
 @patam tvb the tvb with the item.
 @param pinfo packet info of the currently processed packet
 @param tree tree to add the item to
 @param offset in tvb
 @param length the length of the item.
 @param severity the expert severity (like PI_WARN - see: proto.h)
  */

extern void
expert_add_undecoded_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length, const int severity);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EXPERT_H__ */
