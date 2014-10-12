/* version_info.h
 * Declarations of outines to report version information for stuff used
 * by Wireshark
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

#ifndef __VERSION_INFO_H__
#define __VERSION_INFO_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Get various library compile-time versions and append them to
 * the specified GString.
 *
 * "prepend_info" is called at the start to prepend any additional
 * information.
 *
 * "append_info" is called at the end to append any additional
 * information; this is required in order to, for example, put the
 * Portaudio information at the end of the string, as we currently
 * don't use Portaudio in TShark.
 */
void get_compiled_version_info(GString *str,
    void (*prepend_info)(GString *),
    void (*append_info)(GString *));

/*
 * Get various library run-time versions, and the OS version, and append
 * them to the specified GString.
 */
void get_runtime_version_info(GString *str,
    void (*additional_info)(GString *));

#ifdef __cplusplus
}
#endif /* __cplusplus */

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

#endif /* __VERSION_INFO_H__ */
