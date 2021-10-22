/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_RETURN_H__
#define __WS_RETURN_H__

#include <wsutil/wslog.h>
#include <wsutil/wmem/wmem.h>

#define ws_warn_zero_len() ws_warning("Zero length passed to %s", __func__)

#define ws_warn_null_ptr() ws_warning("Null pointer passed to %s", __func__)


#define ws_return_str_if_zero(scope, len) \
        do { \
            if (!(len)) { \
                ws_warn_zero_len(); \
                return wmem_strdup(scope, "(zero length)"); \
            } \
        } while (0)


#define ws_return_str_if_null(scope, ptr) \
        do { \
            if (!(ptr)) { \
                ws_warn_null_ptr(); \
                return wmem_strdup(scope, "(null pointer)"); \
            } \
        } while (0)


#define ws_return_ptr_if_null(ptr, val) \
        do { \
            if (!(ptr)) { \
                ws_warn_null_ptr(); \
                return (val); \
            } \
        } while (0)

#endif /* WS_RETURN_H_ */
