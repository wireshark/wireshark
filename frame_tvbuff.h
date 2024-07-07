/** @file
 *
 * Implements a tvbuff for frame
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FRAME_TVBUFF_H__
#define __FRAME_TVBUFF_H__

#include "cfile.h"

#include <wiretap/wtap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern tvbuff_t *frame_tvbuff_new(const struct packet_provider_data *prov,
    const frame_data *fd, const uint8_t *buf);

extern tvbuff_t *frame_tvbuff_new_buffer(const struct packet_provider_data *prov,
    const frame_data *fd, Buffer *buf);

extern tvbuff_t *file_tvbuff_new(const struct packet_provider_data *prov,
    const frame_data *fd, const uint8_t *buf);

extern tvbuff_t *file_tvbuff_new_buffer(const struct packet_provider_data *prov,
    const frame_data *fd, Buffer *buf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FRAME_TVBUFF_H__ */
