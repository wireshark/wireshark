/* manuf.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __MANUF_H__
#define __MANUF_H__

#include <wireshark.h>

typedef struct {
    uint8_t oui24[3];
    /* Identifies the 3-byte prefix as part of MA-M or MA-S (or MA-L if none of those). */
    uint8_t kind;
} ws_manuf_registry_t;

typedef struct {
    uint8_t oui24[3];
    const char *short_name;
    const char *long_name;
} ws_manuf_oui24_t;

typedef struct {
    uint8_t oui28[4];
    const char *short_name;
    const char *long_name;
} ws_manuf_oui28_t;

typedef struct {
    uint8_t oui36[5];
    const char *short_name;
    const char *long_name;
} ws_manuf_oui36_t;

struct ws_manuf *
global_manuf_lookup(const uint8_t addr[6], struct ws_manuf *result);

struct ws_manuf_iter {
    size_t idx24, idx28, idx36;
};

typedef struct ws_manuf_iter ws_manuf_iter_t;

void
ws_manuf_iter_init(ws_manuf_iter_t *iter);

struct ws_manuf {
    uint8_t addr[6];
    uint8_t mask;
    const char *short_name;
    const char *long_name;
};

struct ws_manuf *
ws_manuf_iter_next(ws_manuf_iter_t *iter, struct ws_manuf manuf_ptr[3]);

WS_DLL_PUBLIC void
ws_manuf_dump(FILE *fp);

#endif
