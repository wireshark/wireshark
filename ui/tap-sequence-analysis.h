/* tap-sequence-analysis.h
 * Flow sequence analysis
 *
 * Copied from gtk/graph_analysis.h
 *
 * Copyright 2004, Verso Technologies Inc.
 * By Alejandro Vaquero <alejandrovaquero@yahoo.com>
 *
 * based on rtp_analysis.c and io_stat
 *
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
 * Foundation,  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __TAP_SEQUENCE_ANALYSIS_H__
#define __TAP_SEQUENCE_ANALYSIS_H__

#include <glib.h>

#include "cfile.h"
#include "epan/address.h"

#include <epan/sequence_analysis.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Fill in the segment list for sequence analysis
 *
 * @param cf Capture file to scan
 * @param sainfo Sequence analysis information. A valid type must be set.
 */
void sequence_analysis_list_get(capture_file *cf, seq_analysis_info_t *sainfo);

/** Write an ASCII version of the sequence diagram to a file.
 *
 * @param pathname Pathname of the file to write.
 * @param sainfo Sequence analysis information.
 * @param cf Capture file associated with the diagram.
 * @param first_node Start drawing at this node.
 * @return TRUE on success, FALSE on failure.
 */
gboolean sequence_analysis_dump_to_file(const char *pathname, seq_analysis_info_t *sainfo, capture_file *cf, unsigned int first_node);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_SEQUENCE_ANALYSIS_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
