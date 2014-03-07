/* codec-g7231.c
* Easy codecs stub for EasyG7231
* 2007 Ales Kocourek
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
#include <memory.h>

#include "codec-g7231.h"

#include "EasyG7231/EasyG7231.h"

struct g7231_context {
  CODER_HANDLE handle;
  short speach_buffer[L_G7231_FRAME];
  int l_g7231_frame_compressed;
};

void *codec_g7231_init(void) {
  struct g7231_context *ctx = 0;

  ctx = (struct g7231_context*)g_malloc0(sizeof(struct g7231_context));
  ctx->handle = -1;
  return ctx;
}

void codec_g7231_release(void *context) {
  struct g7231_context *ctx = (struct g7231_context*)context;

  if (!ctx) return;
  EasyG7231_release_decoder(ctx->handle);
  g_free(ctx);
}

int codec_g7231_decode(void *context, const void *input, int inputSizeBytes, void *output, int *outputSizeBytes) {
  struct g7231_context *ctx = (struct g7231_context*)context;
  const unsigned char *bitstream = (const unsigned char*)input;
  short *speech = (short*)output;
  int decodedBytes = 0;

  if (!ctx) return 0;

  if ( ctx->handle == -1) {
  	if ( bitstream[0] & 0x03 ) {
  	   ctx->handle=EasyG7231_init_decoder(FALSE);
  	   ctx->l_g7231_frame_compressed = L_G7231_FRAME_COMPRESSED_53;
  	} else {
  	   ctx->handle=EasyG7231_init_decoder(TRUE);
  	   ctx->l_g7231_frame_compressed = L_G7231_FRAME_COMPRESSED_63;
  	}
  }

  if ((inputSizeBytes % ctx->l_g7231_frame_compressed) != 0)
    return 0;

  if (!output)
    return (inputSizeBytes / ctx->l_g7231_frame_compressed) * L_G7231_FRAME * sizeof(short);


  while ((inputSizeBytes >= ctx->l_g7231_frame_compressed) &&
         ((*outputSizeBytes - decodedBytes) >= L_G7231_FRAME * sizeof(short))) {
    if (EasyG7231_decoder(ctx->handle, (unsigned char*)bitstream, ctx->speach_buffer)) {

      memcpy(speech, ctx->speach_buffer, L_G7231_FRAME * sizeof(short));
      speech += L_G7231_FRAME;
      decodedBytes += L_G7231_FRAME * sizeof(short);

    }
    bitstream += ctx->l_g7231_frame_compressed;
    inputSizeBytes -= ctx->l_g7231_frame_compressed;
  }

  return decodedBytes;
}

