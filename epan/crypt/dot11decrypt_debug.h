/** @file
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

#define DEBUG_DUMP(name, ptr, size, level) \
    ws_log_buffer_full(WS_LOG_DOMAIN, level, __FILE__, __LINE__, G_STRFUNC, ptr, size, 72, name);

#else	/* defined WS_DISABLE_DEBUG */

#define DEBUG_DUMP(name, ptr, size, level)

#endif	/* ?defined WS_DISABLE_DEBUG */


#endif	/* ?defined _DOT11DECRYPT_DEBUG_H	*/
