/** @file
 *
 * Copyright (c) 1997, 1999 Hellmuth Michaelis. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 *---------------------------------------------------------------------------*/

#ifndef _I4B_TRACE_H_
#define _I4B_TRACE_H_

/*---------------------------------------------------------------------------*
 *	structure of the header at the beginning of every trace mbuf
 *---------------------------------------------------------------------------*/
/**
 * @brief Header prepended to each ISDN4BSD kernel trace buffer entry describing a captured channel frame.
 */
typedef struct {
    uint32_t length;   /**< Length in bytes of the trace data (mbuf payload) that follows this header. */
    uint32_t unit;     /**< ISDN controller unit number that captured this frame. */
    uint32_t type;     /**< Channel type from which this frame was captured; one of the TRC_CH_* values below. */
#define TRC_CH_I    0  /**< Layer 1 INFO signal (physical layer). */
#define TRC_CH_D    1  /**< D channel (signalling). */
#define TRC_CH_B1   2  /**< B1 bearer channel. */
#define TRC_CH_B2   3  /**< B2 bearer channel. */
    int32_t  dir;      /**< Transmission direction; one of the FROM_* values below. */
#define FROM_TE 0      /**< Frame originated from the Terminal Equipment (user → network). */
#define FROM_NT 1      /**< Frame originated from the Network Termination (network → user). */
    uint32_t trunc;    /**< Number of bytes truncated when the frame exceeded MCLBYTES. */
    uint32_t count;    /**< Running frame count for this controller unit and channel type. */
    uint32_t ts_sec;   /**< Timestamp seconds component at the time of capture. */
    uint32_t ts_usec;  /**< Timestamp microseconds component at the time of capture. */
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

/**
 * @brief Configuration parameters specifying which ISDN controller units and channels to trace.
 */
typedef struct {
    int32_t rxunit;   /**< Controller unit number from which to capture received (RX) frames. */
    int32_t rxflags;  /**< Bitmask selecting the RX channel(s) to trace (D channel and/or B channel). */
    int32_t txunit;   /**< Controller unit number from which to capture transmitted (TX) frames. */
    int32_t txflags;  /**< Bitmask selecting the TX channel(s) to trace (D channel and/or B channel). */
} i4b_trace_setupa_t;

#define	I4B_TRC_SETA	_IOW('T', 2, i4b_trace_setupa_t) /* set analyze mode */
#define	I4B_TRC_RESETA	_IOW('T', 3, int)	/* reset analyze mode	*/

#endif /* _I4B_TRACE_H_ */
