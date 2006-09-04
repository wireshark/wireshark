/* G711udecode.c
 * mu-law G.711 codec
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <glib.h>
#include "G711udecode.h"
#include "G711utable.h"

int
decodeG711u(void *input, int inputSizeBytes, void *output, int *outputSizeBytes)
{
  guint8 *dataIn = (guint8 *)input;
  gint16 *dataOut = (gint16 *)output;
  int i;

  for (i=0; i<inputSizeBytes; i++)
  {
    dataOut[i] = ulaw_exp_table[dataIn[i]];
  }
  *outputSizeBytes = inputSizeBytes * 2;
  return 0;
}
