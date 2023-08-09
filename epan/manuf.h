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

struct ws_manuf {
    uint8_t addr[6];
    uint8_t mask;
    const char *short_name;
    const char *long_name;
};

struct ws_manuf_iter {
    size_t idx24, idx28, idx36;
};

typedef struct ws_manuf_iter ws_manuf_iter_t;

WS_DLL_PUBLIC
struct ws_manuf *
ws_manuf_lookup(const uint8_t addr[6], struct ws_manuf *result);

WS_DLL_PUBLIC
void
ws_manuf_iter_init(ws_manuf_iter_t *iter);

WS_DLL_PUBLIC
struct ws_manuf *
ws_manuf_iter_next(ws_manuf_iter_t *iter, struct ws_manuf manuf_ptr[3]);

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
