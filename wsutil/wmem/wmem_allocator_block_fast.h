/** @file
 *
 * Definitions for the Wireshark Memory Manager Fast Large-Block Allocator
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_ALLOCATOR_BLOCK_FAST_H__
#define __WMEM_ALLOCATOR_BLOCK_FAST_H__

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Initialize a fast block-based memory allocator.
 *
 * Sets up a `wmem_allocator_t` to use a fast block-based memory management strategy.
 * This variant is optimized for performance and may use different allocation heuristics
 * compared to the standard block allocator. It assigns function pointers for allocation,
 * reallocation, freeing, and cleanup operations, and initializes internal block tracking
 * structures.
 *
 * @param allocator Pointer to the allocator structure to initialize.
 *
 * @note After initialization, the allocator can be used for fast block-based memory operations.
 *       The allocator must not be NULL.
 */
void
wmem_block_fast_allocator_init(wmem_allocator_t *allocator);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_ALLOCATOR_BLOCK_FAST_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
