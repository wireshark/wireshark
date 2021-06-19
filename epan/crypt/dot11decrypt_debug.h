/* airpcap_debug.h
 *
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

#ifndef	_DOT11DECRYPT_DEBUG_H
#define	_DOT11DECRYPT_DEBUG_H

#define WS_LOG_DOMAIN "dot11decrypt"

#include "dot11decrypt_interop.h"
#include <wsutil/wslog.h>

/******************************************************************************/
/* Debug section: internal function to print debug information						*/
/*																										*/
#ifndef WS_DISABLE_DEBUG
#include <epan/to_str.h>

static inline void
debug_dump(const char *file, int line, const char* func,
           const char* x, const guint8* y, size_t z, enum ws_log_level level)
{
    if (!ws_log_msg_is_active(WS_LOG_DOMAIN, level))
        return;
    char* tmp_str = bytes_to_str(NULL, y, (z));
    ws_log_full(WS_LOG_DOMAIN, level, file, line, func, "%s: %s", x, tmp_str);
    wmem_free(NULL, tmp_str);
}

#define DEBUG_DUMP(x, y, z, level) debug_dump(__FILE__, __LINE__, G_STRFUNC, x, y, z, level)

#else	/* defined WS_DISABLE_DEBUG */

#define DEBUG_DUMP(x, y, z, level)

#endif	/* ?defined WS_DISABLE_DEBUG */


#endif	/* ?defined _DOT11DECRYPT_DEBUG_H	*/
