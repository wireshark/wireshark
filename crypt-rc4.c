/* 
   Unix SMB/CIFS implementation.

   a partial implementation of RC4 designed for use in the 
   SMB authentication protocol

   Copyright (C) Andrew Tridgell 1998

   $Id: crypt-rc4.c,v 1.1 2002/12/03 00:37:27 guy Exp $
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <glib.h>

/* Perform RC4 on a block of data using specified key.  "data" is a pointer
   to the block to be processed.  Output is written to same memory as input,
   so caller may need to make a copy before calling this function, since
   the input will be overwritten.  "val" specifies length of data buffer.
   "key" is assumed to be a 16 octets in length
   
   Taken from Samba source code.  In the long term, it might be nice to have
   the input and output buffer differ, have a length specifier for the key,
   and separate the initialization function from the process function (as is
   done with the Alleged-RC4 implementation).
*/

void crypt_rc4( unsigned char *data, const unsigned char *key, int val)
{
  unsigned char s_box[256];
  unsigned char index_i = 0;
  unsigned char index_j = 0;
  unsigned char j = 0;
  int ind;

  for (ind = 0; ind < 256; ind++)
  {
    s_box[ind] = (unsigned char)ind;
  }

  for( ind = 0; ind < 256; ind++)
  {
     unsigned char tc;

     j += (s_box[ind] + key[ind%16]);

     tc = s_box[ind];
     s_box[ind] = s_box[j];
     s_box[j] = tc;
  }
  for( ind = 0; ind < val; ind++)
  {
    unsigned char tc;
    unsigned char t;

    index_i++;
    index_j += s_box[index_i];

    tc = s_box[index_i];
    s_box[index_i] = s_box[index_j];
    s_box[index_j] = tc;

    t = s_box[index_i] + s_box[index_j];
    data[ind] = data[ind] ^ s_box[t];
  }
}
