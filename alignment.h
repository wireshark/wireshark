 /*
  * alignment.h, Copyright, 1998, Richard Sharpe, All Rights Reserved
  *
  * Please see the file COPYING in the top level for details of copying
  * this software. Use of this software is approved only under certain 
  * conditions.
  * 
  * This file implements the alignment macros for the Threaded SMB Server
  *
  * For the moment we assume Intel style architecture, but can support 
  * others.
  *
  * Modification History
  *
  * 16-Oct-1998, RJS, Initial Coding
  *
  */

#ifndef __ALIGNMENT_H
#define __ALIGNMENT_H
#ifdef __i386__

#define GBYTE(buf, pos)        (unsigned char)((char)buf[pos])
#define PBYTE(buf, pos, val)   GBYTE(buf, pos) = (unsigned char)(val)
#define GSHORT(buf, pos)       ((unsigned short *)((buf) + pos))[0]
#define PSHORT(buf, pos, val)  GSHORT(buf, pos) = (unsigned short)(val)
#define GSSHORT(buf, pos)      ((signed short *)((buf) + pos))[0]

#define GWORD(buf, pos)        ((unsigned int *)((buf) + pos))[0]
#define PWORD(buf, pos, val)   GWORD(buf, pos) = (unsigned int)(val)

#else


#endif
#endif
