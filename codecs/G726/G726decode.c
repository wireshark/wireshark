/* G726decode.c
 * G.726 codec
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
#include "bitstream.h"
#include "g726.h"
#include "G726decode.h"

/* this isn't reentrant. Making it might involve quite a few changes to be able to pass a g726 state
 * variable to the various functions involved in G.726 decoding.
 */
static g726_state_t state;

/* Currently, only G.726-32, linear encoding, left packed is supported */
void *
codec_g726_init(void)
{
    memset (&state, 0, sizeof (state));
    g726_init(&state, 32000, 0, 1);

    return NULL;
}

void
codec_g726_release(void *ctx _U_)
{

}

int
codec_g726_get_channels(void *ctx _U_)
{
    return 1;
}

int
codec_g726_get_frequency(void *ctx _U_)
{
    return 32000;
}

/* Packing should be user defined (via the decode dialog) since due to historical reasons two diverging
 * de facto standards are in use today (see RFC3551).
 */
int
codec_g726_decode(void *ctx _U_, const void *input, int inputSizeBytes, void *output,
        int *outputSizeBytes)
{
    *outputSizeBytes = 2 * g726_decode(&state, output, (void*) input, inputSizeBytes);
    return 0;
}

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

