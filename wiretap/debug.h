/*  debug.h
	-------
	Macros for doing debug work.

	Define DEBUG_PROGRAM_NAME to the name of your program. It will print out in
	all debug messages, to separate your program's debug messages from
	other programs' messages.

	Define DEBUG to invoke the debug macros. Undefine (or don't define)
	DEBUG to not have debug messages.

	In either case, you now have three printf()-like functions:

		debug()	for debug-only messages
		warn()	to print to stderr
		die()	to print to stderr and exit with failure

    Copyright (C) 1997  Gilbert Ramirez <gram@merece.uthscsa.edu>
    $Id: debug.h,v 1.1 1998/11/12 00:06:45 gram Exp $

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public
    License along with this library; if not, write to the Free
    Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/


#ifdef DEBUG
 #define debug(format, args...) fprintf(stdout, format, ## args)
 #define warn(format, args...) { \
 	 fprintf(stdout, DEBUG_PROGRAM_NAME ": " format, ## args); \
 	 fprintf(stderr, DEBUG_PROGRAM_NAME ": " format, ## args); \
 	 }
 #define die(format, args...) { \
	 fprintf(stdout, DEBUG_PROGRAM_NAME ": " format, ## args); \
	 fprintf(stderr, DEBUG_PROGRAM_NAME ": " format, ## args); \
	 exit(-1); \
	 }
#else /* not DEBUG */
 #define debug(format, args...) 
 #define warn(format, args...) \
	 fprintf(stderr, DEBUG_PROGRAM_NAME ": " format, ## args)
 #define die(format, args...) { \
	 fprintf(stderr, DEBUG_PROGRAM_NAME ": " format, ## args); \
	 exit(-1); \
	 }
#endif /* DEBUG */
