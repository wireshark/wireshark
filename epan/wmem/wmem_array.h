/* wmem_array.h
 * Definitions for the Wireshark Memory Manager Array
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_ARRAY_H__
#define __WMEM_ARRAY_H__

#include <string.h>
#include <glib.h>

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-array Array
 *
 *    A resizable array implementation on top of wmem.
 *
 *    @{
 */

struct _wmem_array_t;

typedef struct _wmem_array_t wmem_array_t;

WS_DLL_PUBLIC
wmem_array_t *
wmem_array_sized_new(wmem_allocator_t *allocator, gsize elem_size,
                     guint alloc_count)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
wmem_array_t *
wmem_array_new(wmem_allocator_t *allocator, const gsize elem_size)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
void
wmem_array_grow(wmem_array_t *array, const guint to_add);

WS_DLL_PUBLIC
void
wmem_array_set_null_terminator(wmem_array_t *array);

WS_DLL_PUBLIC
void
wmem_array_bzero(wmem_array_t *array);

WS_DLL_PUBLIC
void
wmem_array_append(wmem_array_t *array, const void *in, guint count);

#define wmem_array_append_one(ARRAY, VAL) \
    wmem_array_append((ARRAY), &(VAL), 1)

WS_DLL_PUBLIC
void *
wmem_array_index(wmem_array_t *array, guint array_index);

WS_DLL_PUBLIC
int
wmem_array_try_index(wmem_array_t *array, guint array_index, void *val);

WS_DLL_PUBLIC
void
wmem_array_sort(wmem_array_t *array, int (*compar)(const void*,const void*));

WS_DLL_PUBLIC
void *
wmem_array_get_raw(wmem_array_t *array);

WS_DLL_PUBLIC
guint
wmem_array_get_count(wmem_array_t *array);

WS_DLL_PUBLIC
void
wmem_destroy_array(wmem_array_t *array);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_ARRAY_H__ */

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
