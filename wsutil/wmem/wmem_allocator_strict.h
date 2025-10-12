/** @file
 *
 * Definitions for the Wireshark Memory Manager Strict Allocator
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_ALLOCATOR_STRICT_H__
#define __WMEM_ALLOCATOR_STRICT_H__

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Initialize a strict memory allocator.
 *
 * Sets up a `wmem_allocator_t` to use a strict allocation strategy that enforces
 * tighter control over memory usage.
 * In this allocator, we do everything we can to catch invalid memory accesses.
 * This includes using canaries (what Valgrind calls redzones) and
 * filling allocated and freed memory with garbage. Valgrind is still the
 * better tool on the platforms where it is available - use it instead if
 * possible.
 *
 * Initializes function pointers for allocation, reallocation, freeing, and cleanup,
 * and sets up internal block tracking.
 *
 * @param allocator Pointer to the allocator structure to initialize.
 *
 * @note After initialization, the allocator can be used for strict memory operations.
 *       The allocator must not be NULL.
 */
void
wmem_strict_allocator_init(wmem_allocator_t *allocator);


/**
 * @brief Verify memory canaries for a strict allocator.
 *
 * Performs integrity checks on all memory blocks managed by a strict allocator
 * by validating their canary values. This helps detect memory corruption such as
 * buffer overflows or underflows.
 *
 * This function only operates if the allocator's type is `WMEM_ALLOCATOR_STRICT`.
 * If the allocator is not of this type, the function returns immediately.
 *
 * @param allocator Pointer to the strict memory allocator to check.
 *
 * @note This function is typically used for debugging or validating memory safety.
 */
void
wmem_strict_check_canaries(wmem_allocator_t *allocator);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_ALLOCATOR_STRICT_H__ */

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
