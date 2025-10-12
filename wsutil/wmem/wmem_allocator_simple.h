/** @file
 *
 * Definitions for the Wireshark Memory Manager Simple Allocator
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_ALLOCATOR_SIMPLE_H__
#define __WMEM_ALLOCATOR_SIMPLE_H__

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Initialize a simple memory allocator.
 *
 * Sets up a `wmem_allocator_t` to use a simple allocation strategy that tracks
 * allocated pointers in an internal array. This allocator is suitable for basic
 * memory management tasks and provides cleanup and garbage collection support.
 *
 * Initializes function pointers for allocation, reallocation, freeing, and cleanup,
 * and allocates an internal pointer array for tracking allocations.
 *
 * @param allocator Pointer to the allocator structure to initialize.
 *
 * @note After initialization, the allocator can be used for simple memory operations.
 *       The allocator must not be NULL.
 */
void
wmem_simple_allocator_init(wmem_allocator_t *allocator);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_ALLOCATOR_SIMPLE_H__ */

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
