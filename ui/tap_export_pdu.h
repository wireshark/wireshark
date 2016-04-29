/* tap_export_pdu.h
 * Routines for exporting PDUs to file
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

#ifndef __TAP_EXPORT_PDU_H__
#define __TAP_EXPORT_PDU_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _exp_pdu_t {
    int          pkt_encap;
    wtap_dumper* wdh;
} exp_pdu_t;

/**
* Registers the tap listener which will add matching packets to the exported
* file. Must be called before exp_pdu_open.
*
* @param tap_name  One of the names registered with register_export_pdu_tap().
* @param filter    An tap filter, may be NULL to disable filtering which
* improves performance if you do not need a filter.
* @return NULL on success or an error string on failure which must be freed
* with g_free(). Failure could occur when the filter or tap_name are invalid.
*/
char *exp_pdu_pre_open(const char *tap_name, const char *filter,
    exp_pdu_t *exp_pdu_tap_data);

/**
* Use the given file descriptor for writing an output file. Can only be called
* once and exp_pdu_pre_open() must be called before.
*
* @return 0 on success or a wtap error code.
*/
int exp_pdu_open(exp_pdu_t *data, int fd, char *comment);

/* Stops the PDUs export. */
int exp_pdu_close(exp_pdu_t *exp_pdu_tap_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_EXPORT_PDU_H__ */

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
