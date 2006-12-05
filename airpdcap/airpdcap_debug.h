#ifndef	_AIRPDCAP_DEBUG_H
#define	_AIRPDCAP_DEBUG_H

#include "airpdcap_interop.h"

void print_debug_line(CHAR *function, CHAR *msg, INT level);

#ifdef	_DEBUG
#ifdef	__FUNCTION__
#define	AIRPDCAP_DEBUG_PRINT_LINE(notdefined, msg, level) print_debug_line(__FUNCTION__, msg, level);
#else
#define	AIRPDCAP_DEBUG_PRINT_LINE(function, msg, level) print_debug_line(function, msg, level);
#endif
#else
#ifdef	__FUNCTION__
#define	AIRPDCAP_DEBUG_PRINT_LINE(notdefined, msg, level)
#else
#define	AIRPDCAP_DEBUG_PRINT_LINE(function, msg, level)
#endif
#endif

/******************************************************************************/
/* Debug section: internal function to print debug information						*/
/*																										*/
#ifdef	_DEBUG
#include "stdio.h"
#include <time.h>

/*	Debug level definition																		*/
#define	AIRPDCAP_DEBUG_LEVEL_1	1
#define	AIRPDCAP_DEBUG_LEVEL_2	2
#define	AIRPDCAP_DEBUG_LEVEL_3	3
#define	AIRPDCAP_DEBUG_LEVEL_4	4
#define	AIRPDCAP_DEBUG_LEVEL_5	5

#define	AIRPDCAP_DEBUG_USED_LEVEL	AIRPDCAP_DEBUG_LEVEL_3

#ifdef	_TRACE
#ifdef	__FUNCTION__
#define	AIRPDCAP_DEBUG_TRACE_START(notdefined) print_debug_line(__FUNCTION__, "Start!", AIRPDCAP_DEBUG_USED_LEVEL);
#define	AIRPDCAP_DEBUG_TRACE_END(notdefined) print_debug_line(__FUNCTION__, "End!", AIRPDCAP_DEBUG_USED_LEVEL);
#else
#define	AIRPDCAP_DEBUG_TRACE_START(function) print_debug_line(function, "Start!", AIRPDCAP_DEBUG_USED_LEVEL);
#define	AIRPDCAP_DEBUG_TRACE_END(function) print_debug_line(function, "End!", AIRPDCAP_DEBUG_USED_LEVEL);
#endif
#else
#ifdef	__FUNCTION__
#define	AIRPDCAP_DEBUG_TRACE_START(notdefined)
#define	AIRPDCAP_DEBUG_TRACE_END(notdefined)
#else
#define	AIRPDCAP_DEBUG_TRACE_START(function)
#define	AIRPDCAP_DEBUG_TRACE_END(function)
#endif
#endif

#else	/* !defined _DEBUG	*/

#define	AIRPDCAP_DEBUG_LEVEL_1
#define	AIRPDCAP_DEBUG_LEVEL_2
#define	AIRPDCAP_DEBUG_LEVEL_3
#define	AIRPDCAP_DEBUG_LEVEL_4
#define	AIRPDCAP_DEBUG_LEVEL_5

#define	AIRPDCAP_DEBUG_TRACE_START(function)
#define	AIRPDCAP_DEBUG_TRACE_END(function)

#endif	/* ?defined _DEBUG	*/


#endif	/* ?defined _AIRPDCAP_DEBUG_H	*/