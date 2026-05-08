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
#pragma once
#include <epan/wmem_scopes.h>
#include <epan/tvbuff.h>

typedef struct _zgfx_context_t zgfx_context_t;

/**
 * @brief Create a new zgfx context.
 *
 * @param allocator Memory allocator to use for allocating the context.
 * @return Pointer to the newly created zgfx_context_t, or NULL on failure.
 */
WS_DLL_PUBLIC zgfx_context_t *zgfx_context_new(wmem_allocator_t *allocator);

/**
 * @brief Decompress RDP8 data.
 *
 * @param zgfx Pointer to the zgfx context.
 * @param allocator Memory allocator to use for allocating the decompressed data.
 * @param tvb Pointer to the input tvbuff containing the compressed data.
 * @param offset The offset within the tvbuff where the compressed data starts.
 * @return Pointer to the decompressed tvbuff, or NULL on failure.
 */
WS_DLL_PUBLIC tvbuff_t *rdp8_decompress(zgfx_context_t *zgfx, wmem_allocator_t *allocator, tvbuff_t *tvb, unsigned offset);
