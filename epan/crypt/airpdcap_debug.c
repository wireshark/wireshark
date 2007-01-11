/******************************************************************************/
/*	File includes																					*/
/*																										*/
#include "airpdcap_debug.h"
/*																										*/
/******************************************************************************/

#ifdef	_DEBUG

#ifdef	__cplusplus
extern "C" {
#endif
	void print_debug_line(CHAR *function, CHAR *msg, INT level) {
		if (level<=AIRPDCAP_DEBUG_USED_LEVEL)
			g_warning("dbg(%d)|(%s) %s", level, function, msg);
	}
#ifdef	__cplusplus
}
#endif

#endif
