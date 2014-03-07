/* codec-g7231.h
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

#ifndef _CODEC_G7231_H_
#define _CODEC_G7231_H_

#ifdef __cplusplus
extern "C" {
#endif

void *codec_g7231_init(void);
void codec_g7231_release(void *ctx);
int codec_g7231_decode(void *ctx, const void *input, int inputSizeBytes, void *output, int *outputSizeBytes);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* _CODEC_G729_H_ */
