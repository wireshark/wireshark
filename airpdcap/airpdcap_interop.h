#ifndef	_AIRPDCAP_INTEROP_H
#define	_AIRPDCAP_INTEROP_H

#ifdef	HAVE_WIRESHARK
/* built with Wireshark																			*/

#ifndef	UINT8
typedef	unsigned char	UINT8;
#endif

#ifndef	UINT16
typedef unsigned short	UINT16;
#endif

#ifdef	_WIN32
/* built with Win32																				*/

#include <windows.h>

#else
/*	build without Win32																			*/

#endif	/* ? _WIN32	*/

#else
/* built without Wireshark																		*/

#ifdef	_WIN32
/* built with Win32																				*/

#include <windows.h>

#else
/*	build without Win32																			*/

#endif	/* ? _WIN32	*/

#endif	/* ? _WIRESHARK	*/

#endif	/* ? _AIRPDCAP_INTEROP_H	*/