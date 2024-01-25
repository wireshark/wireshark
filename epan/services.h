/* services.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <wireshark.h>

typedef enum {
    ws_tcp,
    ws_udp,
    ws_sctp,
    ws_dccp,
} ws_services_proto_t;

typedef struct {
    uint16_t port;
    const char *name;
    const char *description;
} ws_services_entry_t;

ws_services_entry_t const *
global_services_lookup(uint16_t value, ws_services_proto_t proto);

WS_DLL_PUBLIC void
global_services_dump(FILE *fp);
