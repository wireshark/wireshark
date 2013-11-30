/* G726decode.c
 * G.726 codec
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
#ifdef HAVE_SPANDSP
#include "telephony.h"
#include "bitstream.h"
#include "g726.h"
#endif
#include "G726decode.h"

#ifdef HAVE_SPANDSP
/* this isn't reentrant. Making it might involve quite a few changes to be able to pass a g726 state
 * variable to the various functions involved in G.726 decoding.
 */
static g726_state_t state;
#endif

/* Currently, only G.726-32, linear encoding, left packed is supported */
void initG726_32(void)
{
#ifdef HAVE_SPANDSP
    memset (&state, 0, sizeof (state));
    g726_init(&state, 32000, 0, 1);
#endif
}

/* Packing should be user defined (via the decode dialog) since due to historical reasons two diverging
 * de facto standards are in use today (see RFC3551).
 */
int
decodeG726_32(void *input, int inputSizeBytes, void *output, int *outputSizeBytes)
{
#ifdef HAVE_SPANDSP
    *outputSizeBytes = 2 * g726_decode(&state, output, (void*) input, inputSizeBytes);
#endif
    return 0;
}
