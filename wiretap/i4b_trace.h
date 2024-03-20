/** @file
 *
 * Copyright (c) 1997, 1999 Hellmuth Michaelis. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 *---------------------------------------------------------------------------*/

#ifndef _I4B_TRACE_H_
#define _I4B_TRACE_H_

#include <glib.h>

/*---------------------------------------------------------------------------*
 *	structure of the header at the beginning of every trace mbuf
 *---------------------------------------------------------------------------*/
typedef struct {
	uint32_t length;	/* length of the following mbuf		*/
	uint32_t unit;		/* controller unit number		*/
	uint32_t type;		/* type of channel			*/
#define TRC_CH_I	0		/* Layer 1 INFO's		*/
#define TRC_CH_D	1		/* D channel			*/
#define TRC_CH_B1	2		/* B1 channel			*/
#define TRC_CH_B2	3		/* B2 channel			*/
	int32_t dir;		/* direction				*/
#define FROM_TE	0			/* user -> network		*/
#define FROM_NT 1			/* network -> user		*/
	uint32_t trunc;		/* # of truncated bytes (frame > MCLBYTES) */
	uint32_t count;		/* frame count for this unit/type	*/
	uint32_t ts_sec;	/* timestamp seconds */
	uint32_t ts_usec;	/* timestamp microseconds */
} i4b_trace_hdr_t;

#define INFO0		0	/* layer 1 */
#define INFO1_8		1
#define INFO1_10	2
#define INFO2		3
#define INFO3		4
#define INFO4_8		5
#define INFO4_10	6

/*---------------------------------------------------------------------------*
 *	ioctl via /dev/i4btrc device(s):
 *	get/set current trace flag settings
 *---------------------------------------------------------------------------*/

#define	I4B_TRC_GET	_IOR('T', 0, int)	/* get trace settings	*/
#define	I4B_TRC_SET	_IOW('T', 1, int)	/* set trace settings	*/

#define TRACE_OFF       0x00		/* tracing off		*/
#define TRACE_I		0x01		/* trace L1 INFO's on	*/
#define TRACE_D_TX	0x02		/* trace D channel on	*/
#define TRACE_D_RX	0x04		/* trace D channel on	*/
#define TRACE_B_TX	0x08		/* trace B channel on	*/
#define TRACE_B_RX	0x10		/* trace B channel on	*/

typedef struct {
	int32_t rxunit;		/* unit # for rx frames	*/
	int32_t rxflags;	/* d and/or b channel	*/
	int32_t txunit;		/* unit # for tx frames */
	int32_t txflags;	/* d and/or b channel	*/
} i4b_trace_setupa_t;

#define	I4B_TRC_SETA	_IOW('T', 2, i4b_trace_setupa_t) /* set analyze mode */
#define	I4B_TRC_RESETA	_IOW('T', 3, int)	/* reset analyze mode	*/

#endif /* _I4B_TRACE_H_ */
