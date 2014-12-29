/*
   Unix SMB/CIFS implementation.

   a partial implementation of RC4 designed for use in the
   SMB authentication protocol

   Copyright (C) Andrew Tridgell 1998

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
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "config.h"

#include <string.h>

#include "rc4.h"

/* Perform RC4 on a block of data using specified key.  "data" is a pointer
   to the block to be processed.  Output is written to same memory as input,
   so caller may need to make a copy before calling this function, since
   the input will be overwritten.

   Taken from Samba source code.  Modified to allow us to maintain state
   between calls to crypt_rc4.
*/

void crypt_rc4_init(rc4_state_struct *rc4_state,
                    const unsigned char *key, int key_len)
{
  int ind;
  unsigned char j = 0;
  unsigned char *s_box;

  memset(rc4_state, 0, sizeof(rc4_state_struct));
  s_box = rc4_state->s_box;

  for (ind = 0; ind < 256; ind++)
  {
    s_box[ind] = (unsigned char)ind;
  }

  for( ind = 0; ind < 256; ind++)
  {
     unsigned char tc;

     j += (s_box[ind] + key[ind%key_len]);

     tc = s_box[ind];
     s_box[ind] = s_box[j];
     s_box[j] = tc;
  }

}

void crypt_rc4(rc4_state_struct *rc4_state, unsigned char *data, int data_len)
{
  unsigned char *s_box;
  unsigned char index_i;
  unsigned char index_j;
  int ind;

  /* retrieve current state from the state struct (so we can resume where
     we left off) */
  index_i = rc4_state->index_i;
  index_j = rc4_state->index_j;
  s_box = rc4_state->s_box;

  for( ind = 0; ind < data_len; ind++)
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

  /* Store the updated state */
  rc4_state->index_i = index_i;
  rc4_state->index_j = index_j;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
