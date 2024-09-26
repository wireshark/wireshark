/* packet-nts-ke.h
 *
 * Copyright (c) 2024 by Martin Mayer <martin.mayer@m2-it-solutions.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_NTS_KE_H__
#define __PACKET_NTS_KE_H__

#include <wsutil/wsgcrypt.h>

#define NTS_KE_TLS13_KEY_MAX_LEN     64

typedef struct _nts_aead {
    uint16_t    id;             /* IANA assigned AEAD parameter ID */
    uint16_t    cipher;         /* gcrypt cipher */
    uint8_t     mode;           /* gcrypt cipher mode */
    uint16_t    key_len;        /* Length of key for this cipher */
    uint16_t    tag_len;        /* Length of authentication tag for this cipher */
} nts_aead;

typedef struct _nts_cookie_t {
    uint32_t    frame_received;                    /* Frame no. which provided the cookie */
    wmem_list_t *frames_used;                      /* List of frame no. which used the cookie */
    wmem_list_t *frames_used_uid;                  /* List of request UIDs which used the cookie */
    uint16_t    aead;                              /* AEAD parameter */
    bool        keys_present;                      /* Are keys present (export successful) */
    uint8_t     key_c2s[NTS_KE_TLS13_KEY_MAX_LEN]; /* Derived client to server key */
    uint8_t     key_s2c[NTS_KE_TLS13_KEY_MAX_LEN]; /* Derived server to client key */
} nts_cookie_t;

/* Helper structure to pass data to nts_append_used_frames_to_tree() */
typedef struct _nts_used_frames_lookup_t {
    tvbuff_t *tvb;
    proto_tree *tree;
    int hfindex;
} nts_used_frames_lookup_t;

/** Append a NTS cookie to the file-scoped wmem map and extract C2S and S2C keys.
 *
 * @param tvb The backing tvbuff of the cookie (only!) (may use tvb_new_subset_*()).
 * @param aead The IANA assigned ID of the AEAD parameter used for the cookie.
 * @param pinfo The packet_info of the packet which provided the cookie.
 *
 * @return A pointer to the cookie's nts_cookie_t data */
nts_cookie_t* nts_new_cookie(tvbuff_t *tvb, uint16_t aead, packet_info *pinfo);

/** Append a NTS cookie to the file-scoped wmem map and copy crypto data from existing cookie.
 *
 * @param tvb The backing tvbuff of the cookie (only!) (may use tvb_new_subset_*()).
 * @param ref_cookie The reference cookie from which crypto data can be copied.
 * @param pinfo The packet_info of the packet which provided the cookie.
 *
 * @return A pointer to the cookie's nts_cookie_t data */
nts_cookie_t* nts_new_cookie_copy(tvbuff_t *tvb, nts_cookie_t *ref_cookie, packet_info *pinfo);

/** Finds a NTS cookie in the wmem map and sets the frame_used and frame_used_uid info.
 *
 * @param tvb_cookie The backing tvbuff of the cookie (only!) (may use tvb_new_subset_*()).
 * @param tvb_uid The backing tvbuff of the packet's NTS UID (only!) (may use tvb_new_subset_*()).
 * @param pinfo The packet_info of the packet which provided the cookie.
 *
 * @return A pointer to the cookie's nts_cookie_t data if found */
nts_cookie_t* nts_use_cookie(tvbuff_t *tvb_cookie, tvbuff_t *tvb_uid, packet_info *pinfo);

/** Finds a NTS cookie in the wmem map by a provided tvbuff of NTS UID.
 *
 * @param tvb_uid The backing tvbuff of the packet's UID (only!) (may use tvb_new_subset_*()).
 *
 * @return A pointer to the cookie's nts_cookie_t data if found */
nts_cookie_t* nts_find_cookie_by_uid(tvbuff_t *tvb_uid);

/** Finds a matching AEAD algorithm entry by a given NTS-KE AEAD-Algo-ID.
 *
 * @param id The ID of an AEAD algorithm.
 *
 * @return A pointer to the AEAD's nts_aead algorithm data if found. */
const nts_aead * nts_find_aead(uint16_t id);

/** Helper function for wmem_list_foreach() to append used cookies to proto_tree.
 *
 * @param data pointer to wmem_list_t of frame numbers. Typically frames_used in a nts_cookie_t.
 * @param user_data pointer to nts_used_frames_lookup_t with tree and field infos. */
void nts_append_used_frames_to_tree(void *data, void *user_data);

#endif
