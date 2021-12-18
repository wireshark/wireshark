/** @file
 * Definitions for the Wireshark Memory Manager String Utilities
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_STRUTL_H__
#define __WMEM_STRUTL_H__

#include <wireshark.h>
#include <stdarg.h>

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-strutl String Utilities
 *
 *    A collection of utility function for operating on C strings with wmem.
 *
 *    @{
 */

WS_DLL_PUBLIC
gchar *
wmem_strdup(wmem_allocator_t *allocator, const gchar *src)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
gchar *
wmem_strndup(wmem_allocator_t *allocator, const gchar *src, const size_t len)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
gchar *
wmem_strdup_printf(wmem_allocator_t *allocator, const gchar *fmt, ...)
G_GNUC_MALLOC G_GNUC_PRINTF(2, 3);

WS_DLL_PUBLIC
gchar *
wmem_strdup_vprintf(wmem_allocator_t *allocator, const gchar *fmt, va_list ap)
G_GNUC_MALLOC;

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_STRUTL_H__ */

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
