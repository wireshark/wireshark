/** @file
 * Declaration of Internet checksum routine.
 *
 * Copyright (c) 1988, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __IN_CKSUM_H__
#define __IN_CKSUM_H__

#include "ws_symbol_export.h"

typedef struct {
	const uint8_t *ptr;
	int	len;
} vec_t;

#define SET_CKSUM_VEC_PTR(vecelem, data, length) \
	G_STMT_START { \
		vecelem.ptr = (data); \
		vecelem.len = (length); \
	} G_STMT_END

#define SET_CKSUM_VEC_TVB(vecelem, tvb, offset, length) \
	G_STMT_START { \
		vecelem.len = (length); \
		vecelem.ptr = tvb_get_ptr((tvb), (offset), vecelem.len); \
	} G_STMT_END

WS_DLL_PUBLIC uint16_t ip_checksum(const uint8_t *ptr, int len);

WS_DLL_PUBLIC uint16_t ip_checksum_tvb(tvbuff_t *tvb, int offset, int len);

WS_DLL_PUBLIC int in_cksum_ret_partial(const vec_t *vec, int veclen, uint16_t *partial);

WS_DLL_PUBLIC int in_cksum(const vec_t *vec, int veclen);

uint16_t in_cksum_shouldbe(uint16_t sum, uint16_t computed_sum);

#endif /* __IN_CKSUM_H__ */
