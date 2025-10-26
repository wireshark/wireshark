/** @file
 *
 * Definitions for the Wireshark Memory Manager Allocator
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_ALLOCATOR_H__
#define __WMEM_ALLOCATOR_H__

#include <glib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct _wmem_user_cb_container_t;

/**
 * @brief Internal memory allocator interface used by the wmem subsystem.
 *
 * This structure defines the contract between the wmem core and a specific
 * allocator implementation. It includes consumer-facing allocation functions,
 * producer-side lifecycle management, and internal state tracking.
 *
 * For design details, see section "4. Internal Design" of `doc/README.wmem`.
 */
struct _wmem_allocator_t {
    /* Consumer functions */
    void *(*walloc)(void *private_data, const size_t size); /**< Allocate memory of given size. */
    void  (*wfree)(void *private_data, void *ptr);          /**< Free previously allocated memory. */
    void *(*wrealloc)(void *private_data, void *ptr, const size_t size); /**< Resize an existing allocation. */

    /* Producer/Manager functions */
    void  (*free_all)(void *private_data); /**< Free all allocations managed by this allocator. */
    void  (*gc)(void *private_data);       /**< Perform garbage collection or cleanup. */
    void  (*cleanup)(void *private_data);  /**< Final cleanup before allocator destruction. */

    /* Callback List */
    struct _wmem_user_cb_container_t *callbacks; /**< Optional user-defined callbacks for lifecycle events. */

    /* Implementation details */
    void *private_data; /**< Allocator-specific internal state. */
    enum _wmem_allocator_type_t type; /**< Allocator type (e.g., scope, file-backed, slab). */
    bool in_scope; /**< Indicates whether the allocator is currently active in a scope. */
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_ALLOCATOR_H__ */

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
