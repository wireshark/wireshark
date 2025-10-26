/** @file
 *
 * Definitions for the Wireshark Memory Manager Large-Block Allocator
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_ALLOCATOR_BLOCK_H__
#define __WMEM_ALLOCATOR_BLOCK_H__

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Initialize a block-based memory allocator.
 *
 * Sets up a `wmem_allocator_t` to use block-based memory management by assigning
 * function pointers for allocation, reallocation, freeing, and cleanup operations.
 * Internally, it creates a `wmem_block_allocator_t` structure to manage memory blocks
 * and assigns it to the allocator's private data.
 *
 * @param allocator Pointer to the allocator structure to initialize.
 *
 * @note After initialization, the allocator can be used for block-based memory operations.
 *       The allocator must not be NULL.
 */
void
wmem_block_allocator_init(wmem_allocator_t *allocator);

/**
 * @brief Verifies internal consistency of a wmem block allocator.
 *
 * This function performs integrity checks on the internal state of a block-based
 * `wmem_allocator_t`. It is intended for use in unit tests or debugging scenarios
 * to detect memory corruption, invalid pointers, or unexpected allocator behavior.
 *
 * @param allocator Pointer to the block allocator to verify.
 *
 * @note This function is exposed only for testing purposes and should not be used
 *       in production code.
 */
void
wmem_block_verify(wmem_allocator_t *allocator);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_ALLOCATOR_BLOCK_H__ */

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
