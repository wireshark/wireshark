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
typedef struct flexray_identifier
{
	guint16 id;
	guint8 cc;
	guint8 ch;
} flexray_identifier;

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
