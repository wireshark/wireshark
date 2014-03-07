/* easy_codec_plugin.c
* Easy codecs plugin registration file
* 2007 Tomas Kukosa
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

#ifndef ENABLE_STATIC
#include "config.h"

#include <gmodule.h>
/* plugins are DLLs */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

#include <epan/codecs.h>

#include "codec-g7231.h"
#include "codec-g729a.h"
#include "codec-g722.h"

WS_DLL_PUBLIC_DEF const gchar version[] = "0.0.1";

WS_DLL_PUBLIC_DEF void register_codec_module(void)
{
  register_codec("g723", codec_g7231_init, codec_g7231_release, codec_g7231_decode);
  register_codec("g729", codec_g729a_init, codec_g729a_release, codec_g729a_decode);
  register_codec("g722", codec_g722_init, codec_g722_release, codec_g722_decode);
}

#endif
