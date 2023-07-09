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

const char *
global_manuf_lookup(const uint8_t addr[6], const char **long_name_ptr);

#endif
