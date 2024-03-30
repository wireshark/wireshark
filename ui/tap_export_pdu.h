/** @file
 *
 * Routines for exporting PDUs to file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_EXPORT_PDU_H__
#define __TAP_EXPORT_PDU_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _exp_pdu_t {
    char*        pathname;
    int          pkt_encap;
    wtap_dumper* wdh;
    GArray* shb_hdrs;
    wtapng_iface_descriptions_t* idb_inf;
    uint32_t     framenum;
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
* @param[out] err Will be set to an error code on failure.
* @param[out] err_info for some errors, a string giving more details of
* the error
* @return true on success or false on failure.
*/
bool exp_pdu_open(exp_pdu_t *data, char *pathname, int file_type_subtype,
    int fd, const char *comment, int *err, char **err_info);

/* Stops the PDUs export. */
bool exp_pdu_close(exp_pdu_t *exp_pdu_tap_data, int *err, char **err_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_EXPORT_PDU_H__ */
