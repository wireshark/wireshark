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
#pragma once
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Reads a Kerberos keytab file.
 *
 * @param filename The path to the keytab file to read.
 */
WS_DLL_PUBLIC
void keytab_file_read(const char *filename);

#ifdef HAVE_KERBEROS
#define KRB_MAX_KEY_LENGTH	32

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)

/* Try to avoid having to include krb5.h especially when other files
 * include this or packet-kerberos.h */
struct _krb5_context;

typedef struct _krb5_context *krb5_context;

extern krb5_context keytab_krb5_ctx;

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

WS_DLL_PUBLIC const enc_key_t* keytab_get_enc_key_list(void);
WS_DLL_PUBLIC void keytab_set_enc_key_list(enc_key_t* list);
WS_DLL_PUBLIC const wmem_map_t* keytab_get_file_longterm_keys(void);
WS_DLL_PUBLIC wmem_map_t* keytab_get_file_all_keys(void);
WS_DLL_PUBLIC wmem_map_t* keytab_get_file_session_keys(void);

WS_DLL_PUBLIC void keytab_file_key_map_insert(wmem_map_t* key_map, enc_key_t* new_key);

#endif /* defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS) */

#endif /* HAVE_KERBEROS */

 /**
  * @brief Initializes data structures for keytab file processing.
  *
  * This function initializes any necessary data structures or variables required
  * for reading and processing keytab files.
  */
WS_DLL_LOCAL
void keytab_file_data_init(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
