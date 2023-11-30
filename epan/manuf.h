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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MANUF_BLOCK_SIZE 5

struct ws_manuf {
    uint8_t block[MANUF_BLOCK_SIZE];
    uint8_t mask;
    const char *short_name;
    const char *long_name;
};

/* Internal structure, not supposed to be accessed by users. */
struct ws_manuf_iter {
    size_t idx24, idx28, idx36;
    struct ws_manuf buf24;
    struct ws_manuf buf28;
    struct ws_manuf buf36;
};

typedef struct ws_manuf_iter ws_manuf_iter_t;

/* Returns the short name. Takes an optional pointer to return the long name. */
WS_DLL_PUBLIC
const char *
ws_manuf_lookup_str(const uint8_t addr[6], const char **long_name_ptr);

/* Returns the short name. Takes an optional pointer to return the long name.
 * Takes an optional pointer to return the length of the mask. */
WS_DLL_PUBLIC
const char *
ws_manuf_lookup(const uint8_t addr[6], const char **long_name_ptr, unsigned *mask_ptr);

/* Search only in the OUI/MA-L/CID tables for a 24-bit OUI. Returns the short
 * name. Takes an optional pointer to return the long time. */
WS_DLL_PUBLIC
const char *
ws_manuf_lookup_oui24(const uint8_t oui[3], const char **long_name_ptr);

WS_DLL_PUBLIC
void
ws_manuf_iter_init(ws_manuf_iter_t *iter);

WS_DLL_PUBLIC
bool
ws_manuf_iter_next(ws_manuf_iter_t *iter, struct ws_manuf *result);

WS_DLL_PUBLIC
const char *
ws_manuf_block_str(char *buf, size_t buf_size, const struct ws_manuf *ptr);

WS_DLL_PUBLIC void
ws_manuf_dump(FILE *fp);

WS_DLL_PUBLIC
size_t
ws_manuf_count(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
