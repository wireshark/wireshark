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

#define GBYTE(buf, pos)        (unsigned char)((char)buf[pos])
#define GSHORT(buf, pos)       pletohs(&buf[pos])
#define GSSHORT(buf, pos)      (signed)pletohs(&buf[pos])
#define GWORD(buf, pos)        pletohl(&buf[pos])

#endif
