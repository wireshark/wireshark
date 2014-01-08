/* G722decode.c
 * A-law G.711 codec
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#ifdef HAVE_SPANDSP
#include "telephony.h"
#include "g722.h"
#include "G722decode.h"

static g722_decode_state_t state;

void
initG722(void)
{
    memset (&state, 0, sizeof (state));
    g722_decode_init(&state, 64000, 0);
}

int
decodeG722(void *input _U_NOSPANDSP_, int inputSizeBytes _U_NOSPANDSP_,
           void *output _U_NOSPANDSP_, int *outputSizeBytes _U_NOSPANDSP_)
{
    *outputSizeBytes = g722_decode(&state, output, input, inputSizeBytes);
    return 0;
}

#endif
