/* in_cksum.h
 * Declaration of  Internet checksum routine.
 *
 * $Id$
 */

#ifndef __IN_CKSUM_H__
#define __IN_CKSUM_H__

#include "ws_symbol_export.h"

typedef struct {
	const guint8 *ptr;
	int	len;
} vec_t;

WS_DLL_PUBLIC int in_cksum(const vec_t *vec, int veclen);

guint16 in_cksum_shouldbe(guint16 sum, guint16 computed_sum);

#endif /* __IN_CKSUM_H__ */
