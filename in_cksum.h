/* in_cksum.h
 * Declaration of  Internet checksum routine.
 *
 * $Id: in_cksum.h,v 1.1 2000/12/13 02:24:22 guy Exp $
 */

typedef struct {
	const guint8 *ptr;
	int	len;
} vec_t;

extern int in_cksum(const vec_t *vec, int veclen);

extern guint16 in_cksum_shouldbe(guint16 sum, guint16 computed_sum);
