/* read_keytab_file.h
 * Routines for reading Kerberos keytab files
 * Copyright 2007, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __READ_KEYTAB_FILE_H
#define __READ_KEYTAB_FILE_H

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC
void keytab_file_read(const char *);

#ifdef HAVE_KERBEROS
#define KRB_MAX_KEY_LENGTH	32

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)

typedef struct _enc_key_t {
    struct _enc_key_t* next;
    int keytype;
    int keylength;
    uint8_t keyvalue[KRB_MAX_KEY_LENGTH];
    char* key_origin;
    int fd_num; /* remember where we learned a key */
    unsigned id; /* a unique id of the key, relative to fd_num */
    char* id_str;
    /* EncTicketPart_key */
    bool is_ticket_key;
    /* EncAPRepPart_subkey */
    bool is_ap_rep_key;
    /*
     * for now taken from dissect_krb5_PAC_UPN_DNS_INFO,
     * we could also use dissect_krb5_PAC_LOGON_INFO if needed
     *
     * we get device_sid from dissect_krb5_PAC_DEVICE_INFO if available.
     *
     * We remember these from the PAC and
     * attach it to EncTicketPart_key so it
     * might be valid if is_ticket_key is true.
     *
     * When learning a EncAPRepPart_subkey
     * we copy the details from the EncTicketPart_key,
     * so when is_ap_rep_key is true we may also have it.
     *
     * So application protocols like SMB2 could use the
     * is_ap_rep_key=true key details in order to identify
     * the authenticated user.
     */
    struct {
        const char* account_name;
        const char* account_domain;
        const char* account_sid;
        const char* device_sid;
    } pac_names;
    struct _enc_key_t* same_list;
    unsigned num_same;
    struct _enc_key_t* src1;
    struct _enc_key_t* src2;
} enc_key_t;

extern const enc_key_t* keytab_get_enc_key_list(void);
extern void keytab_set_enc_key_list(enc_key_t* list);
extern const wmem_map_t* keytab_get_file_longterm_keys(void);
extern wmem_map_t* keytab_get_file_all_keys(void);
extern wmem_map_t* keytab_get_file_session_keys(void);

extern void keytab_file_key_map_insert(wmem_map_t* key_map, enc_key_t* new_key);

#endif /* defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS) */

#endif /* HAVE_KERBEROS */

WS_DLL_LOCAL
void keytab_file_data_init(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* __READ_KEYTAB_FILE_H */
