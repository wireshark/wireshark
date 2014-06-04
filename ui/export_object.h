/* export_object.h
 * Common routines for tracking & saving objects found in streams of data
 * Copyright 2007, Stephen Fisher (see AUTHORS file)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __EXPORT_OBJECT_H__
#define __EXPORT_OBJECT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Common between protocols */

struct _export_object_list_t;
typedef struct _export_object_list_t export_object_list_t;

typedef struct _export_object_entry_t {
    guint32 pkt_num;
    gchar *hostname;
    gchar *content_type;
    gchar *filename;
    /* We need to store a 64 bit integer to hold a file length
      (was guint payload_len;) */
    gint64 payload_len;
    guint8 *payload_data;
} export_object_entry_t;

void object_list_add_entry(export_object_list_t *object_list, export_object_entry_t *entry);
export_object_entry_t *object_list_get_entry(export_object_list_t *object_list, int row);

gboolean eo_save_entry(const gchar *save_as_filename, export_object_entry_t *entry, gboolean show_err);
GString *eo_massage_str(const gchar *in_str, gsize maxlen, int dup);
const char *ct2ext(const char *content_type);


/* Protocol specific */
gboolean eo_dicom_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_,
        const void *data);
gboolean eo_http_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_,
	const void *data);
gboolean eo_smb_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_,
	const void *data);
gboolean eo_tftp_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_,
	const void *data);

void eo_smb_cleanup(void);
void eo_tftp_cleanup(void);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EXPORT_OBJECT_H__ */

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
