/** @file
 *
 *	Various decompression routines used by RDP
 *
 * Copyright (c) 2021 by David Fort <contact@hardening-consulting.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TVBUFF_RDP_H__
#define __TVBUFF_RDP_H__

#include <glib.h>
#include <epan/wmem_scopes.h>
#include <epan/tvbuff.h>

typedef struct _zgfx_context_t zgfx_context_t;

zgfx_context_t *zgfx_context_new(wmem_allocator_t *allocator);

tvbuff_t *rdp8_decompress(zgfx_context_t *zgfx, wmem_allocator_t *allocator, tvbuff_t *tvb, unsigned offset);


#endif /* __TVBUFF_RDP_H__ */
