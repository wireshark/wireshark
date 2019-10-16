/* packet-quic.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_QUIC_H__
#define __PACKET_QUIC_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "ws_symbol_export.h"

/** Returns the number of items for quic.connection.number. */
WS_DLL_PUBLIC guint32 get_quic_connections_count(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* __PACKET_QUIC_H__ */
