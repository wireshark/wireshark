/* packet-flexray.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_FLEXRAY_H__
#define __PACKET_FLEXRAY_H__

/* Structure that gets passed between dissectors. */
/* Structure that gets passed between dissectors (containing of
 frame id, counter cycle and channel).
*/
typedef struct flexray_info
{
	guint16 id;
	guint8  cc;
	guint8  ch;
	guint16 bus_id;
} flexray_info_t;

#define FLEXRAY_ID_CYCLE_MASK    0x000000FF
#define FLEXRAY_ID_FRAME_ID_MASK 0x00FFFF00
#define FLEXRAY_ID_CHANNEL_MASK  0x0F000000
#define FLEXRAY_ID_BUS_ID_MASK   0xF0000000

guint32  flexray_calc_flexrayid(guint16 bus_id, guint8 channel, guint16 frame_id, guint8 cycle);
guint32  flexray_flexrayinfo_to_flexrayid(flexray_info_t *flexray_info);
gboolean flexray_call_subdissectors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, flexray_info_t *flexray_info, const gboolean use_heuristics_first);

#endif /* __PACKET_FLEXRAY_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
