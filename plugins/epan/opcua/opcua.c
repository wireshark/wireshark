/******************************************************************************
** Copyright (C) 2006-2007 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
**
** SPDX-License-Identifier: GPL-2.0-or-later
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** Project: OpcUa Wireshark Plugin
**
** Description: OpcUa Protocol Decoder.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
******************************************************************************/

#include "config.h"
#define WS_LOG_DOMAIN "opcua"
#include <wireshark.h>
#include <glib.h>

#include <epan/dissectors/packet-tcp.h>
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/prefs.h>
#include <epan/range.h>
#include <epan/reassemble.h>
#include <epan/secrets.h>
#include <epan/tvbuff.h>
#include <gcrypt.h>
#include <wiretap/secrets-types.h>
#include <wsutil/file_util.h>

#include "opcua.h"
#include "opcua_application_layer.h"
#include "opcua_complextypeparser.h"
#include "opcua_enumparser.h"
#include "opcua_hfindeces.h"
#include "opcua_infomodel.h"
#include "opcua_keyset.h"
#include "opcua_security_layer.h"
#include "opcua_serviceparser.h"
#include "opcua_serviceids.h"
#include "opcua_servicetable.h"
#include "opcua_simpletypes.h"
#include "opcua_transport_layer.h"

void proto_register_opcua(void);

static const char *g_opcua_debug_file_name;
int g_opcua_default_sig_len;

/* forward reference */
void proto_reg_handoff_opcua(void);
/* declare parse function pointer */
typedef int (*FctParse)(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);

int proto_opcua;
static dissector_handle_t opcua_handle;
static module_t *opcua_module;

/** Official IANA registered port for OPC UA Binary Protocol. */
#define OPCUA_DEFAULT_PORT 4840
/* default port range for preferences */
#define OPCUA_PORT_RANGE "4840"
/** header length that is needed to compute the pdu length.
  * @see get_opcua_message_len
  */
#define FRAME_HEADER_LEN 8
/* AES block size: for both AES128 and AES256 the block size is 128 bits */
#define AES_BLOCK_SIZE 16

/** subtree types used locally */
static int ett_opcua_transport;

static expert_field ei_opcua_bad_footer;
static int ett_opcua_fragment;
static int ett_opcua_fragments;

static int hf_opcua_fragments;
static int hf_opcua_fragment;
static int hf_opcua_fragment_overlap;
static int hf_opcua_fragment_overlap_conflicts;
static int hf_opcua_fragment_multiple_tails;
static int hf_opcua_fragment_too_long_fragment;
static int hf_opcua_fragment_error;
static int hf_opcua_fragment_count;
static int hf_opcua_reassembled_in;
static int hf_opcua_reassembled_length;

static const fragment_items opcua_frag_items = {
    /* Fragment subtrees */
    &ett_opcua_fragment,
    &ett_opcua_fragments,
    /* Fragment fields */
    &hf_opcua_fragments,
    &hf_opcua_fragment,
    &hf_opcua_fragment_overlap,
    &hf_opcua_fragment_overlap_conflicts,
    &hf_opcua_fragment_multiple_tails,
    &hf_opcua_fragment_too_long_fragment,
    &hf_opcua_fragment_error,
    &hf_opcua_fragment_count,
    /* Reassembled in field */
    &hf_opcua_reassembled_in,
    /* Reassembled length field */
    &hf_opcua_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Message fragments"
};

static reassembly_table opcua_reassembly_table;

/** OpcUa Transport Message Types */
enum MessageType
{
    MSG_HELLO = 0,
    MSG_ACKNOWLEDGE,
    MSG_ERROR,
    MSG_REVERSEHELLO,
    MSG_MESSAGE,
    MSG_OPENSECURECHANNEL,
    MSG_CLOSESECURECHANNEL,
    MSG_INVALID
};

/** OpcUa Transport Message Type Names */
static const char* g_szMessageTypes[] =
{
    "Hello message",
    "Acknowledge message",
    "Error message",
    "Reverse Hello message",
    "UA Secure Conversation Message",
    "OpenSecureChannel message",
    "CloseSecureChannel message",
    "Invalid message"
};

static const enum_val_t opcua_sig_len_enum[] = {
    { "None",    "Unsigned",        0 },
    { "20",      "20 Bytes",       20 },
    { "32",      "32 Bytes",       32 },
    { NULL, NULL, 0 }
};

#ifdef _MSC_VER
static char *ua_strtok_r(char *str, const char *delim, char **saveptr)
{
    /* use MSVC specific strtok_s */
    return strtok_s(str, delim, saveptr);
}
#else
static char *ua_strtok_r(char *str, const char *delim, char **saveptr)
{
    /* use POSIX strtok_r */
    return strtok_r(str, delim, saveptr);
}
#endif

/** returns the length of an OpcUa message.
  * This function reads the length information from
  * the transport header.
  */
static unsigned get_opcua_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                                   int offset, void *data _U_)
{
    int32_t plen;

    /* the message length starts at offset 4 */
    plen = tvb_get_letohl(tvb, offset + 4);

    return plen;
}

/* Helper function for case-insensitive substring search */
static bool opcua_str_contains_caseless(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return false;
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen > hlen) return false;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        bool match = true;
        for (size_t j = 0; j < nlen; j++) {
            if (g_ascii_tolower(haystack[i + j]) != g_ascii_tolower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}
unsigned hex_to_bin(const char *hex_string, unsigned char *binary_data, unsigned int binary_size)
{
    unsigned length = (unsigned)strlen(hex_string);
    unsigned i;

    for (i = 0; i < length / 2 && i < binary_size; ++i) {
        sscanf(hex_string + 2 * i, "%2hhx", &binary_data[i]);
    }

    return i;
}

/** Parsing context */
struct opcua_keylog_parser_ctx {
    struct ua_keyset *keyset; /**< current keyset */
    uint64_t last_id; /**< the id of the previous line, this is also the id of the keyset */
};

/**
 * Common function for parsing key log line used by opcua_keylog_process_lines and opcua_load_keylog_file.
 *
 * @param ctx Parsing context.
 * @param line Current line to parse.
 */
static void opcua_keylog_process_line(struct opcua_keylog_parser_ctx *ctx, const char *line)
{
    struct ua_keyset *keyset;
    char key[33]; /* 32 chars + null terminator */
    char value[65]; /* 64 hex chars + null terminator */
    const char *parts[4]; /* for string split */
    unsigned int num_parts;
    char *tmp, *saveptr;
    uint32_t token_id = 0;
    uint32_t channel_id = 0;
    uint64_t id = 0;
    int n;

    /* Skip UTF-8 BOM if present at the beginning of a line */
    if ((uint8_t)line[0] == 0xEF && (uint8_t)line[1] == 0xBB && (uint8_t)line[2] == 0xBF) {
        line += 3;
    }

    /* parse key/value pair */
    n = sscanf(line, "%32[^:]: %64s\n", key, value);
    if (n != 2) return;

    ws_debug("%s = %s", key, value);

    /* split key into parts */
    num_parts = 0;
    tmp = ua_strtok_r(key, "_", &saveptr);
    while (tmp && num_parts < 4) {
        parts[num_parts++] = tmp;
        tmp = ua_strtok_r(NULL, "_", &saveptr);
    }
    if (num_parts != 4) return; /* skip invalid enty */
    channel_id = (uint32_t)strtoul(parts[2], NULL, 10);
    token_id = (uint32_t)strtoul(parts[3], NULL, 10);

    ws_debug("channel_id = %u", channel_id);
    ws_debug("token_id = %u", token_id);

    /* create unique keyset id */
    id = ua_keyset_id(channel_id, token_id);

    if (ctx->keyset == NULL || id != ctx->last_id) {
        ctx->keyset = ua_keysets_lookup(id);
        if (ctx->keyset == NULL) {
            ws_debug("Adding new keyset for id %" PRIu64 "u...", id);
            /* create new keyset for new id */
            ctx->keyset = ua_keysets_add();
        }
        ctx->last_id = id;
    }
    keyset = ctx->keyset;
    if (keyset) {
        keyset->id = id;
        /* store key material */
        if (strcmp(parts[0], "client") == 0) {
            if (strcmp(parts[1], "iv") == 0) {
                keyset->client_iv_len = (unsigned int)hex_to_bin(value, keyset->client_iv, sizeof(keyset->client_iv));
                if ((keyset->client_iv_len == 8 || keyset->client_iv_len == 12) && keyset->cipher_type == OPCUA_CIPHER_AES_CBC) {
                    keyset->cipher_type = OPCUA_CIPHER_AES_GCM;
                }
            } else if (strcmp(parts[1], "key") == 0) {
                keyset->client_key_len = (unsigned int)hex_to_bin(value, keyset->client_key, sizeof(keyset->client_key));
            } else if (strcmp(parts[1], "siglen") == 0) {
                keyset->client_sig_len = (unsigned int)strtoul(value, NULL, 10);
            } else if (strcmp(parts[1], "cipher") == 0 || strcmp(parts[1], "mode") == 0 || strcmp(parts[1], "algo") == 0) {
                if (opcua_str_contains_caseless(value, "gcm")) {
                    keyset->cipher_type = OPCUA_CIPHER_AES_GCM;
                } else if (opcua_str_contains_caseless(value, "chacha") || opcua_str_contains_caseless(value, "poly1305")) {
                    keyset->cipher_type = OPCUA_CIPHER_CHACHA20_POLY1305;
                }
            }
        } else if (strcmp(parts[0], "server") == 0) {
            if (strcmp(parts[1], "iv") == 0) {
                keyset->server_iv_len = (unsigned int)hex_to_bin(value, keyset->server_iv, sizeof(keyset->server_iv));
                if ((keyset->server_iv_len == 8 || keyset->server_iv_len == 12) && keyset->cipher_type == OPCUA_CIPHER_AES_CBC) {
                    keyset->cipher_type = OPCUA_CIPHER_AES_GCM;
                }
            } else if (strcmp(parts[1], "key") == 0) {
                keyset->server_key_len = (unsigned int)hex_to_bin(value, keyset->server_key, sizeof(keyset->server_key));
            } else if (strcmp(parts[1], "siglen") == 0) {
                keyset->server_sig_len = (unsigned int)strtoul(value, NULL, 10);
            } else if (strcmp(parts[1], "cipher") == 0 || strcmp(parts[1], "mode") == 0 || strcmp(parts[1], "algo") == 0) {
                if (opcua_str_contains_caseless(value, "gcm")) {
                    keyset->cipher_type = OPCUA_CIPHER_AES_GCM;
                } else if (opcua_str_contains_caseless(value, "chacha") || opcua_str_contains_caseless(value, "poly1305")) {
                    keyset->cipher_type = OPCUA_CIPHER_CHACHA20_POLY1305;
                }
            }
        }
    }
}

/**
 * Parses key log data from PCAP file.
 * This function splits the data by \n and calls opcua_keylog_process_line.
 */
static void opcua_keylog_process_lines(char *data)
{
    struct opcua_keylog_parser_ctx ctx = { NULL, 0 };
    char *saveptr;
    const char *line = ua_strtok_r(data, "\n", &saveptr);

    while (line) {
        opcua_keylog_process_line(&ctx, line);
        line = ua_strtok_r(NULL, "\n", &saveptr);
    }

    /* sort data by id to make lookup working */
    ua_keysets_sort();
}

/**
 * Loads the configured OPCUA Keylog file.
 */
static void opcua_load_keylog_file(const char *filename)
{
    struct opcua_keylog_parser_ctx ctx = { NULL, 0 };
    char line[256];

    ws_debug("Loading key file '%s'...", filename);
    FILE *f = ws_fopen(filename, "r");
    if (f == NULL) {
        ws_debug("error: '%s' not found", filename);
        return;
    }

    /* parse file contents */
    while (fgets(line, sizeof(line), f)) {
        opcua_keylog_process_line(&ctx, line);
    }
    fclose(f);

    /* sort data by id to make lookup working */
    ua_keysets_sort();
}

/**
 * Checks the padding of a symmetric signed message.
 * A message always contains a padding_len byte, which tells us the length of
 * the padding. All following padding bytes contain the same value. This makes it
 * possible the padding from the end of the message.
 * Example Paddings:
 * - 00
 * - 01 01
 * - 02 02 02
 * @param padding Pointer to last padding byte.
 * @return padding length on success, -1 if the padding is invalid.
 */
static int verify_padding(const uint8_t *padding, unsigned available)
{
    uint8_t pad_len;
    uint8_t i;

    pad_len = *padding;

    if (pad_len > available) {
        ws_debug("padding length %u exceeds available space %u", pad_len, available);
        return -1;
    }

    for (i = 0; i < pad_len; ++i) {
        if (padding[-pad_len + i] != pad_len) return -1;
    }

    return pad_len;
}
/**
 * Gets security footer info.
 *
 * @param channel_id SecureChannelId for keyset lookup.
 * @param token_id TokenId for keyset lookup.
 * @param sig_len Returns the length of the signature.
 * @param from_server True of the message is sent from the server, false when sent from the client.
 *
 * @return Returns 0 on success, -1 if parsing failed.
 */
static int opcua_get_footer_info(uint32_t channel_id, uint32_t token_id, uint8_t *sig_len, bool from_server)
{
    struct ua_keyset *keyset;
    uint64_t id;

    id = ua_keyset_id(channel_id, token_id);

    /* try to get correct signature length from key log file */
    keyset = ua_keysets_lookup(id);
    if (keyset) {
        /* The Client keys are used to secure Messages sent by the Client. The Server keys are used to
         * secure Messages sent by the Server.
         */
        if (from_server) {
            *sig_len = keyset->server_sig_len;
        } else {
            *sig_len = keyset->client_sig_len;
        }
    } else {
        ws_debug("no keyset found for channel_id=%u and token_id=%u", channel_id, token_id);
        /* we use sig_len set from OpenSecureChannel Policy in this case.
         * this requires to have the OPN in the capture file, otherwise we are out of luck.
         */
    }

    return 0;
}

/**
 * Decrypts OPC UA message using AEAD (AES-GCM or ChaCha20-Poly1305).
 */
static int decrypt_opcua_aead(
        struct ua_keyset *keyset,
        const uint8_t *aad, unsigned aad_len,
        const uint8_t *cipher, unsigned cipher_len,
        uint8_t *plaintext, unsigned *out_plaintext_len,
        bool from_server)
{
    unsigned int keylen, ivlen;
    unsigned char *keydata, *ivdata;
    int cipher_algo, cipher_mode;
    unsigned char nonce[12];
    gcry_cipher_hd_t handle;
    gcry_error_t res;

    if (cipher_len < 16) {
        ws_debug("AEAD ciphertext too short for 16-byte auth tag.");
        return -1;
    }

    unsigned payload_len = cipher_len - 16;
    const uint8_t *tag = cipher + payload_len;

    for (int side = 0; side < 2; side++) {
        bool try_server = (side == 0) ? from_server : !from_server;
        if (try_server) {
            ivlen = keyset->server_iv_len ? keyset->server_iv_len : 12;
            ivdata = keyset->server_iv;
            keylen = keyset->server_key_len;
            keydata = keyset->server_key;
        } else {
            ivlen = keyset->client_iv_len ? keyset->client_iv_len : 12;
            ivdata = keyset->client_iv;
            keylen = keyset->client_key_len;
            keydata = keyset->client_key;
        }

        if (keylen == 0) continue;

        /* Select cipher algorithm and mode */
        if (keyset->cipher_type == OPCUA_CIPHER_CHACHA20_POLY1305) {
            cipher_algo = GCRY_CIPHER_CHACHA20;
            cipher_mode = GCRY_CIPHER_MODE_POLY1305;
        } else {
            /* AES-GCM */
            cipher_algo = (keylen == 16) ? GCRY_CIPHER_AES128 : GCRY_CIPHER_AES256;
            cipher_mode = GCRY_CIPHER_MODE_GCM;
        }

        for (uint32_t seq = 1; seq <= 4096; seq++) {
            for (int nmode = 0; nmode < 4; nmode++) {
                memset(nonce, 0, sizeof(nonce));
                if (ivlen >= 12) {
                    memcpy(nonce, ivdata, 12);
                } else {
                    memcpy(nonce, ivdata, ivlen);
                }

                if (nmode == 0) {
                    /* First 4 bytes XORed with token_id (LE), bytes 4..7 XORed with seq (LE) */
                    uint32_t token_id = (uint32_t)(keyset->id & 0xffffffff);
                    uint32_t seq_le = GUINT32_TO_LE(seq);
                    uint32_t tok_le = GUINT32_TO_LE(token_id);
                    uint32_t first4, mid4;
                    memcpy(&first4, &nonce[0], 4);
                    memcpy(&mid4, &nonce[4], 4);
                    first4 ^= tok_le;
                    mid4 ^= seq_le;
                    memcpy(&nonce[0], &first4, 4);
                    memcpy(&nonce[4], &mid4, 4);
                } else if (nmode == 1) {
                    /* First 4 bytes XORed with seq in Little-Endian, bytes 4..7 XORed with token_id in Little-Endian */
                    uint32_t token_id = (uint32_t)(keyset->id & 0xffffffff);
                    uint32_t seq_le = GUINT32_TO_LE(seq);
                    uint32_t tok_le = GUINT32_TO_LE(token_id);
                    uint32_t first4, mid4;
                    memcpy(&first4, &nonce[0], 4);
                    memcpy(&mid4, &nonce[4], 4);
                    first4 ^= seq_le;
                    mid4 ^= tok_le;
                    memcpy(&nonce[0], &first4, 4);
                    memcpy(&nonce[4], &mid4, 4);
                } else if (nmode == 2) {
                    /* First 4 bytes XORed with seq in Little-Endian */
                    uint32_t seq_le = GUINT32_TO_LE(seq);
                    uint32_t first4;
                    memcpy(&first4, &nonce[0], 4);
                    first4 ^= seq_le;
                    memcpy(&nonce[0], &first4, 4);
                } else if (nmode == 3) {
                    /* 8-byte implicit salt + 4-byte SequenceNumber (LE) */
                    uint32_t seq_le = GUINT32_TO_LE(seq);
                    memcpy(&nonce[8], &seq_le, 4);
                }

                res = gcry_cipher_open(&handle, cipher_algo, cipher_mode, 0);
                if (res) continue;

                if (gcry_cipher_setkey(handle, keydata, keylen) != 0 ||
                    gcry_cipher_setiv(handle, nonce, sizeof(nonce)) != 0) {
                    gcry_cipher_close(handle);
                    continue;
                }

                if (aad != NULL && aad_len > 0) {
                    if (gcry_cipher_authenticate(handle, aad, aad_len) != 0) {
                        gcry_cipher_close(handle);
                        continue;
                    }
                }

                if (gcry_cipher_decrypt(handle, plaintext, payload_len, cipher, payload_len) == 0) {
                    if (gcry_cipher_checktag(handle, tag, 16) == 0) {
                        gcry_cipher_close(handle);
                        *out_plaintext_len = payload_len;
                        ws_debug("AEAD decryption succeeded with seq=%u.", seq);
                        return 0;
                    }
                }
                gcry_cipher_close(handle);
            }
        }
    }

    ws_debug("AEAD decryption failed: authentication tag mismatch.");
    return -1;
}

/**
 * This function to perform AES decryption on service data in-place.
 * Add also determines the payload length by removing the padding and signature.
 *
 * @param channel_id SecureChannelId for keyset lookup.
 * @param token_id TokenId for keyset lookup.
 * @param aad Additional Authenticated Data (unencrypted OPC UA header).
 * @param aad_len Length of AAD in bytes.
 * @param cipher The cipher text.
 * @param cipher_len The cipher test length in bytes.
 * @param plaintext The plaintext to return.
 * @param out_plaintext_len Input/output length of plaintext buffer.
 * @param padding_len Returns the length of the padding.
 * @param sig_len Returns the length of the signature.
 * @param from_server True of the message is sent from the server, false when sent from the client.
 *
 * @return Returns 0 on success, -1 if decryption failed.
 */
static int decrypt_opcua(
        uint32_t channel_id, uint32_t token_id,
        const uint8_t *aad, unsigned aad_len,
        const uint8_t *cipher, unsigned cipher_len,
        uint8_t *plaintext, unsigned *out_plaintext_len,
        uint8_t *padding_len, uint8_t *sig_len, bool from_server)
{
    struct ua_keyset *keyset;
    uint64_t id;
    unsigned int keylen, ivlen;
    unsigned char *keydata, *ivdata;
    int cipher_mode;
    gcry_error_t res;
    int ret = 0;

    id = ua_keyset_id(channel_id, token_id);

    keyset = ua_keysets_lookup(id);
    if (keyset == NULL) {
        ws_debug("no keyset found for channel_id=%u and token_id=%u", channel_id, token_id);
        /* col_append_fstr(pinfo->cinfo, COL_INFO, " (encrypted)"); */
        return -1;
    }
    ws_debug("found keyset for channel_id=%u and token_id=%u", channel_id, token_id);

    if (keyset->cipher_type == OPCUA_CIPHER_AES_GCM || keyset->cipher_type == OPCUA_CIPHER_CHACHA20_POLY1305) {
        *padding_len = 0;
        *sig_len = 0;
        return decrypt_opcua_aead(keyset, aad, aad_len, cipher, cipher_len, plaintext, out_plaintext_len, from_server);
    }

    /* CBC Decryption */
    if (from_server) {
        ivlen = sizeof(keyset->server_iv);
        ivdata = keyset->server_iv;
        keylen = keyset->server_key_len;
        keydata = keyset->server_key;
        *sig_len = keyset->server_sig_len;
    } else {
        ivlen = sizeof(keyset->client_iv);
        ivdata = keyset->client_iv;
        keylen = keyset->client_key_len;
        keydata = keyset->client_key;
        *sig_len = keyset->client_sig_len;
    }

    unsigned plaintext_len = *out_plaintext_len;

    /* derive AES mode from key length */
    switch (keylen) {
    case 16:
        ws_debug("using AES-128-CBC");
        cipher_mode = GCRY_CIPHER_AES128;
        break;
    case 32:
        ws_debug("using AES-256-CBC");
        cipher_mode = GCRY_CIPHER_AES256;
        break;
    default:
        ws_debug("invalid AES key length: %u bytes", keylen);
        /* col_append_fstr(pinfo->cinfo, COL_INFO, " (encrypted)"); */
        return -1;
    }

    ws_debug("cipher_len=%u", cipher_len);
    if (cipher_len % 16 != 0) {
        ws_debug("warning: cipher_len not a multiple of 16.");
    }

    gcry_cipher_hd_t handle;
    res = gcry_cipher_open(&handle, cipher_mode, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
    if (res) {
        ws_debug("opening cipher failed: %s %s.", gcry_strsource(res), gcry_strerror(res));
        return -1;
    }
    res = gcry_cipher_setkey(handle, keydata, keylen);
    if (res) {
        ws_debug("setkey failed: %s %s.", gcry_strsource(res), gcry_strerror(res));
        gcry_cipher_close(handle);
        return -1;
    }
    res = gcry_cipher_setiv(handle, ivdata, ivlen);
    if (res) {
        ws_debug("setiv failed: %s %s.", gcry_strsource(res), gcry_strerror(res));
        gcry_cipher_close(handle);
        return -1;
    }

    /* Decrypt the data in-place */
    res = gcry_cipher_decrypt(handle, plaintext, plaintext_len, cipher, cipher_len);
    if (res == 0) {
        /* col_append_fstr(pinfo->cinfo, COL_INFO, " (decrypted)"); */
        ws_debug("decryption succeeded.");
    } else {
        /* col_append_fstr(pinfo->cinfo, COL_INFO, " (encrypted)"); */
        ws_debug("decryption failed %s %s.", gcry_strsource(res), gcry_strerror(res));
        ret = -1;
    }
    gcry_cipher_close(handle);
    /* it makes no sense to continue and verify the padding if decryption failed */
    if (ret != 0) {
        return ret;
    }

    /* guard: need at least sig_len + 1 bytes for the padding-length byte */
    if (plaintext_len < (unsigned)*sig_len + 1) {
        ws_debug("plaintext too short for signature and padding");
        return -1;
    }

    unsigned pad_offset = plaintext_len - *sig_len - 1;
    ret = verify_padding(&plaintext[pad_offset], pad_offset);
    if (ret < 0) {
        ws_debug("padding is invalid.");
        return -1;
    }

    /* return padding length */
    *padding_len = plaintext[pad_offset];
    ws_debug("sig_len=%u", *sig_len);
    ws_debug("pad_len=%u", *padding_len);

    return 0;
}

/* Keys for p_add_proto_data(). Key 0 is the nesting counter of
 * opcua_simpletypes.c. */
#define OPCUA_PD_MSG_COUNT   1U             /* per frame pass: UA messages seen so far */
#define OPCUA_PD_STATE_BASE  2U             /* per message: state at the start of the message */
#define OPCUA_PD_STATE_VALID 0x10000U

/** The OpcUa message dissector.
  * This method dissects full OpcUa messages.
  * It gets only called with reassembled data
  * from tcp_dissect_pdus.
  */
static int dissect_opcua_message_inner(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    FctParse pfctParse = NULL;
    enum MessageType msgtype = MSG_INVALID;
    uint16_t src_port = pinfo->srcport;
    range_t *port_range;
    bool from_server = false;
    bool decrypted = false; /* successfully decrypted secure message */
    enum ua_message_mode mode = UA_MessageMode_None;
    uint8_t sig_len = 0;
    struct ua_metadata metadata;
    tvbuff_t *decrypted_tvb = NULL;
    int ret;

    /* determine if telegram is from server or from client by checking the port number */
    if (src_port == OPCUA_DEFAULT_PORT) {
        from_server = true;
    } else {
        port_range = prefs_get_range_value("opcua", "tcp.port");
        if (port_range && value_is_in_range(port_range, src_port)) {
            from_server = true;
        }
    }

    metadata.encrypted = false;
    {
        /* The conversation holds the state after the latest message of the
         * connection, so it is only valid on the first pass. Keep the state
         * this message started with per message, to get the same result
         * when the frame is dissected again.
         */
        unsigned msg_idx = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_opcua, OPCUA_PD_MSG_COUNT));
        uintptr_t saved;

        p_add_proto_data(pinfo->pool, pinfo, proto_opcua, OPCUA_PD_MSG_COUNT, GUINT_TO_POINTER(msg_idx + 1));
        saved = (uintptr_t)p_get_proto_data(wmem_file_scope(), pinfo, proto_opcua, OPCUA_PD_STATE_BASE + msg_idx);
        if (!PINFO_FD_VISITED(pinfo) || saved == 0) {
            get_encryption_info(pinfo, &mode, &sig_len);
            if (!PINFO_FD_VISITED(pinfo)) {
                saved = construct_encryption_info(mode, sig_len) | OPCUA_PD_STATE_VALID;
                p_add_proto_data(wmem_file_scope(), pinfo, proto_opcua, OPCUA_PD_STATE_BASE + msg_idx, (void *)saved);
            }
        } else {
            mode = extract_message_mode(saved & 0xffff);
            sig_len = extract_signature_length(saved & 0xffff);
        }
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OpcUa");


    /* parse message type */
    if (tvb_memeql(tvb, 0, (const uint8_t * )"HEL", 3) == 0)
    {
        msgtype = MSG_HELLO;
        pfctParse = parseHello;
    }
    else if (tvb_memeql(tvb, 0, (const uint8_t*)"ACK", 3) == 0)
    {
        msgtype = MSG_ACKNOWLEDGE;
        pfctParse = parseAcknowledge;
    }
    else if (tvb_memeql(tvb, 0, (const uint8_t*)"ERR", 3) == 0)
    {
        msgtype = MSG_ERROR;
        pfctParse = parseError;
    }
    else if (tvb_memeql(tvb, 0, (const uint8_t*)"RHE", 3) == 0)
    {
        msgtype = MSG_REVERSEHELLO;
        pfctParse = parseReverseHello;
    }
    else if (tvb_memeql(tvb, 0, (const uint8_t*)"MSG", 3) == 0)
    {
        msgtype = MSG_MESSAGE;
        pfctParse = parseMessage;
    }
    else if (tvb_memeql(tvb, 0, (const uint8_t*)"OPN", 3) == 0)
    {
        msgtype = MSG_OPENSECURECHANNEL;
        pfctParse = parseOpenSecureChannel;
    }
    else if (tvb_memeql(tvb, 0, (const uint8_t*)"CLO", 3) == 0)
    {
        msgtype = MSG_CLOSESECURECHANNEL;
        pfctParse = parseCloseSecureChannel;
    }
    else
    {
        msgtype = MSG_INVALID;

        /* Clear out stuff in the info column */
        col_set_str(pinfo->cinfo, COL_INFO, g_szMessageTypes[msgtype]);

        /* add empty item to make filtering by 'opcua' work */
        proto_tree_add_item(tree, proto_opcua, tvb, 0, -1, ENC_NA);

        return tvb_reported_length(tvb);
    }

    /* Clear out stuff in the info column */
    col_set_str(pinfo->cinfo, COL_INFO, g_szMessageTypes[msgtype]);

    if (pfctParse)
    {
        int offset = 0;
        int iServiceId;
        bool bParseService = false; /* Only MSG, OPN and CLO have a service payload */
        bool bIsFinalChunk = false;
        unsigned payload_len = 0;
        uint8_t pad_len = 0;

        /* we are being asked for details */
        proto_item *ti = NULL;
        proto_tree *transport_tree = NULL;

        ti = proto_tree_add_item(tree, proto_opcua, tvb, 0, -1, ENC_NA);
        transport_tree = proto_item_add_subtree(ti, ett_opcua_transport);

        /* call the transport message dissector */
        (*pfctParse)(transport_tree, tvb, pinfo, &offset, &metadata);

        /* MSG_MESSAGE and MSG_CLOSESECURECHANNEL can be decrypted.
         * Also handle chunked message reassembly for MSG_MESSAGE.
         */
        if (msgtype == MSG_MESSAGE || msgtype == MSG_CLOSESECURECHANNEL)
        {
            uint8_t chunkType = 0;
            uint32_t opcua_seqno = 0; /* OPCUA sequence number */
            uint32_t opcua_reqid = 0; /* OPCUA request id */
            fragment_head *frag_msg = NULL;

            bParseService = true;
            offset = 3;
            chunkType = tvb_get_uint8(tvb, offset); offset += 1;
            offset += 4; /* message size */
            offset += 4; /* skip secure channel_id */
            parseSecurityHeader(transport_tree, tvb, &offset, &metadata); /* only token_id (4 byte) */

            if (mode == UA_MessageMode_MaybeEncrypted) {
                /* try to parse ServiceId */
                iServiceId = getServiceNodeId(tvb, offset + 8); /* skip 4 byte SeqNo and 4 byte RequestId */
                const char *szServiceName = val_to_str_const((uint32_t)iServiceId, g_requesttypes, "not found");
                if (strcmp(szServiceName, "not found") == 0) {
                    mode = UA_MessageMode_SignAndEncrypt;
                } else {
                    mode = UA_MessageMode_Sign;
                }
                store_encryption_info(pinfo, mode, sig_len);
            }

            /* Message Structure:
             *             +-----------------+
             *          /  | Message Header  |   MSGF, MessageSize
             *          |  +-----------------+
             *          |  | Security Header |   SecureChannelId, TokenId
             *          |  +-----------------+
             * Signed  <   | Sequence Header | \ SequenceNumber, RequestId
             *          |  +-----------------+ |
             *          |  | Body            | |
             *          |  +-----------------+  > Encrypted
             *          \  | Padding         | |
             *             +-----------------+ |
             *             | Signature       | /
             *             +-----------------+
             */
            if (mode == UA_MessageMode_SignAndEncrypt) {
                uint32_t channel_id = tvb_get_letohl(tvb, 8);
                uint32_t token_id = tvb_get_letohl(tvb, 12);
                unsigned cipher_len = tvb_ensure_captured_length_remaining(tvb, 16);
                unsigned plaintext_len = cipher_len;
                const uint8_t *cipher = tvb_get_ptr(tvb, 16, (int)cipher_len);
                unsigned char *plaintext = (unsigned char*)wmem_alloc(pinfo->pool, plaintext_len);

                /* Extract first 16 bytes of unencrypted OPC UA header as AAD for AEAD profiles */
                const uint8_t *aad = tvb_get_ptr(tvb, 0, 16);
                unsigned aad_len = 16;
                unsigned out_plaintext_len = plaintext_len;

                ret = decrypt_opcua(channel_id, token_id, aad, aad_len, cipher, cipher_len, plaintext, &out_plaintext_len, &pad_len, &sig_len, from_server);
                if (ret == 0 && !(pad_len == 0 && sig_len == 0 && out_plaintext_len < plaintext_len) &&
                    (unsigned)pad_len + sig_len + 9 > plaintext_len) {
                    /* CBC profile with a padding and signature footer longer than the plaintext */
                    expert_add_info(pinfo, ti, &ei_opcua_bad_footer);
                    ret = -1;
                }
                if (ret == 0) {
                    /* decrypted */
                    if (pad_len == 0 && sig_len == 0 && out_plaintext_len < plaintext_len) {
                        /* AEAD profile (AES-GCM / ChaCha20-Poly1305): no padding byte or signature footer */
                        plaintext_len = out_plaintext_len;
                        payload_len = (plaintext_len >= 8) ? (plaintext_len - 8) : 0;
                    } else {
                        /* CBC profile */
                        /* to get the payload length we need to subtract the sequence header (8) byte,
                         * the padding (pad_len+1), and the signature from the plaintext */
                        payload_len = plaintext_len - pad_len - sig_len - 9; /* pad_len 2 = 02 02 02 */
                    }
                    /* Now re-setup the tvb buffer to have the new data */
                    decrypted_tvb = tvb_new_child_real_data(tvb, plaintext, (unsigned)plaintext_len, (unsigned)plaintext_len);
                    add_new_data_source(pinfo, decrypted_tvb, "Decrypted Data");
                    /* process decrypted_tvb from here */
                    tvb = decrypted_tvb;
                    offset = 0;
                    decrypted = true;
                } else {
                    /* decryption failed */
                    metadata.encrypted = true;
                }
            } else if (mode == UA_MessageMode_Sign) {
                uint32_t channel_id = tvb_get_letohl(tvb, 8);
                uint32_t token_id = tvb_get_letohl(tvb, 12);
                payload_len = tvb_ensure_captured_length_remaining(tvb, 24); /* subtract header */

                ret = opcua_get_footer_info(channel_id, token_id, &sig_len, from_server);
                if (ret != 0) {
                    ws_debug("Processing security footer of signed message failed.");
                } else {
                    /* signed only messages have no padding, so the payload is the message size
                     * without 24 byte header and without signature */
                    if (sig_len > payload_len) {
                        expert_add_info(pinfo, ti, &ei_opcua_bad_footer);
                        sig_len = 0;
                    } else {
                        payload_len -= sig_len;
                    }
                }
                /* store the current tvb as decrypted tvb, because we need this to parse the signature
                 * at the end, and tvb gets replaces with the reassembled UA message if the message was chunked.
                 */
                decrypted_tvb = tvb;
            } else {
                /* no padding, no signature, just payload */
                payload_len = tvb_ensure_captured_length_remaining(tvb, 24); /* subtract header */
                pad_len= 0;
                sig_len = 0;
            }

            opcua_seqno = tvb_get_letohl(tvb, offset); /* Sequence.Sequence Number */
            opcua_reqid = tvb_get_letohl(tvb, offset + 4); /* Sequence.RequestId */
            parseSequenceHeader(transport_tree, tvb, &offset, &metadata);

            if (chunkType == 'A')
            {
                /* cancel chunk reassembly */
                fragment_delete(&opcua_reassembly_table, pinfo, opcua_reqid, NULL);

                col_clear_fence(pinfo->cinfo, COL_INFO);
                col_set_str(pinfo->cinfo, COL_INFO, "Abort message");

                parseAbort(transport_tree, tvb, pinfo, &offset, &metadata);

                return tvb_reported_length(tvb);
            }

            /* check if tvb is part of a chunked message:
               the UA protocol does not tell us that, so we look into
               opcua_reassembly_table if the opcua_reqid belongs to a
               chunked message */
            frag_msg = fragment_get(&opcua_reassembly_table, pinfo, opcua_reqid, NULL);
            if (frag_msg == NULL)
            {
                frag_msg = fragment_get_reassembled_id(&opcua_reassembly_table, pinfo, opcua_reqid);
            }

            if (frag_msg != NULL || chunkType == 'C')
            {
                bool bSaveFragmented = pinfo->fragmented;
                bool bMoreFragments = true;
                tvbuff_t *reassembled_tvb = NULL;
                bool first_frag = false;

                pinfo->fragmented = true;

                if (frag_msg == NULL)
                {
                    first_frag = true;
                }
                else
                {
                    if (chunkType == 'F')
                    {
                        bMoreFragments = false;
                    }
                }

                frag_msg = fragment_add_seq_check(&opcua_reassembly_table,
                                                  tvb,
                                                  offset,
                                                  pinfo,
                                                  opcua_reqid, /* ID for fragments belonging together */
                                                  NULL,
                                                  first_frag ? 0 : opcua_seqno, /* fragment sequence number */
                                                  payload_len,
                                                  bMoreFragments); /* More fragments? */

                if (first_frag) {
                        /* the UA protocol does not number the chunks beginning
                         * from 0 but uses the common sequence number. We
                         * handle that in Wireshark by setting the sequence
                         * offset here, after passing in 0 for the first
                         * fragment. For later fragments we can use the
                         * sequence number as contained in the protocol.
                         */

                        fragment_add_seq_offset(&opcua_reassembly_table, pinfo, opcua_reqid, NULL, opcua_seqno);
                }
                reassembled_tvb = process_reassembled_data(tvb,
                                                   offset,
                                                   pinfo,
                                                   "Reassembled UA Message",
                                                   frag_msg,
                                                   &opcua_frag_items,
                                                   NULL,
                                                   transport_tree);

                if (reassembled_tvb)
                {
                    /* Reassembled */
                    bIsFinalChunk = true;
                    /* take it all */
                    tvb = reassembled_tvb;
                    /* new tvb starts at payload */
                    offset = 0;
                }
                else
                {
                    /* Not last packet of reassembled UA message */
                    col_append_fstr(pinfo->cinfo, COL_INFO, " (Message fragment %u)", opcua_seqno);
                    /* only show transport header */
                    bParseService = false;
                    tvb = tvb_new_subset_remaining(tvb, 0);
                }

                pinfo->fragmented = bSaveFragmented;
            }
        }

        /* parse payload if not encrypted */
        if (!metadata.encrypted && bParseService) {
            if (msgtype == MSG_CLOSESECURECHANNEL) {
                iServiceId = parseService(transport_tree, tvb, pinfo, &offset, &metadata);
                if (iServiceId == OpcUaId_CloseSecureChannelRequest_Encoding_DefaultBinary) {
                    col_append_str(pinfo->cinfo, COL_INFO, ": CloseSecureChannelRequest");
                } else if (iServiceId == OpcUaId_CloseSecureChannelResponse_Encoding_DefaultBinary) {
                    col_append_str(pinfo->cinfo, COL_INFO, ": CloseSecureChannelResponse");
                } else {
                    const char *szServiceName = val_to_str(pinfo->pool, (uint32_t)iServiceId, g_requesttypes, "ServiceId %d");
                    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s (Wrong ServiceId)", szServiceName);
                }
            } else if (msgtype == MSG_MESSAGE) {
                /* parse the service if not chunked or message was reassembled */
                iServiceId = parseService(transport_tree, tvb, pinfo, &offset, &metadata);

                /* display the service type in addition to the message type */
                if (iServiceId != -1)
                {
                    const char *szServiceName = val_to_str(pinfo->pool, (uint32_t)iServiceId, g_requesttypes, "ServiceId %d");

                    if (bIsFinalChunk == false)
                    {
                        /* normal message in one chunk */
                        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", szServiceName);
                    }
                    else
                    {
                        /* reassembled message from multiple chunks */
                        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s (Message Reassembled)", szServiceName);
                    }
                }
            }
            if (mode == UA_MessageMode_SignAndEncrypt && decrypted && sig_len > 0) {
                /* parse padding and signature (CBC profiles only; AEAD has no padding byte in plaintext) */
                parseSecurityFooterSAE(transport_tree, decrypted_tvb, 8 + payload_len, pad_len, sig_len);
            } else if (mode == UA_MessageMode_Sign && sig_len > 0) {
                /* parse signature */
                parseSecurityFooterSO(transport_tree, decrypted_tvb, 24 + payload_len, sig_len);
            }
        }
        if (metadata.encrypted) {
            col_append_str(pinfo->cinfo, COL_INFO, " (encrypted)");
        } else if (mode == UA_MessageMode_SignAndEncrypt && msgtype != MSG_OPENSECURECHANNEL) {
            col_append_str(pinfo->cinfo, COL_INFO, " (decrypted)");
        }
    }

    return tvb_reported_length(tvb);
}

/** Dissect one UA message. An exception thrown while parsing a message
  * (tcp_dissect_pdus goes on with the next message in the frame) skips the
  * decrements of the nesting counters, so start every message from zero
  * and restore the state afterwards.
  */
static int dissect_opcua_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    unsigned saved_depth = pinfo->dissection_depth;
    volatile int ret = 0;

    p_add_proto_data(pinfo->pool, pinfo, proto_opcua, 0, GUINT_TO_POINTER(0U));
    TRY {
        ret = dissect_opcua_message_inner(tvb, pinfo, tree);
    }
    FINALLY {
        pinfo->dissection_depth = saved_depth;
        p_add_proto_data(pinfo->pool, pinfo, proto_opcua, 0, GUINT_TO_POINTER(0U));
    }
    ENDTRY;

    return ret;
}

/** The main OpcUa dissector functions.
  * It uses tcp_dissect_pdus from packet-tcp.h
  * to reassemble the TCP data.
  */
static int dissect_opcua(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, FRAME_HEADER_LEN,
                     get_opcua_message_len, dissect_opcua_message, data);
    return tvb_reported_length(tvb);
}

/** Init plugin resources */
void proto_init_opcua(void)
{
    ws_debug("proto_init_opcua called.");
    ua_keysets_init();
    opcua_load_keylog_file(g_opcua_debug_file_name);
}

/** Cleanup plugin resources */
void proto_cleanup_opcua(void)
{
    ws_debug("proto_cleanup_opcua called.");
    ua_keysets_clear();
}

/** secrets callback called from Wireshark when loading a capture file with OPC UA Keylog File. */
static void opcua_secrets_block_callback(const void *secrets, unsigned size)
{
    char *tmp = g_malloc0(size + 1);
    memcpy(tmp, secrets, size);
    ws_debug("Loading secrets block '%s'...", tmp);
    ws_debug("size = %u", size);
    /* parse data */
    opcua_keylog_process_lines(tmp);
    g_free(tmp);
}

/** plugin entry functions.
 * This registers the OpcUa protocol.
 */
void proto_register_opcua(void)
{
    static hf_register_info hf[] =
        {
            /* id                                    full name                                              abbreviation                        type            display     strings bitmask blurb HFILL */
            {&hf_opcua_fragments,                   {"Message fragments",                                   "opcua.fragments",                  FT_NONE,        BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment,                    {"Message fragment",                                    "opcua.fragment",                   FT_FRAMENUM,    BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment_overlap,            {"Message fragment overlap",                            "opcua.fragment.overlap",           FT_BOOLEAN,     BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment_overlap_conflicts,  {"Message fragment overlapping with conflicting data",  "opcua.fragment.overlap.conflicts", FT_BOOLEAN,     BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment_multiple_tails,     {"Message has multiple tail fragments",                 "opcua.fragment.multiple_tails",    FT_BOOLEAN,     BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment_too_long_fragment,  {"Message fragment too long",                           "opcua.fragment.too_long_fragment", FT_BOOLEAN,     BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment_error,              {"Message defragmentation error",                       "opcua.fragment.error",             FT_FRAMENUM,    BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_fragment_count,              {"Message fragment count",                              "opcua.fragment.count",             FT_UINT32,      BASE_DEC,   NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_reassembled_in,              {"Reassembled in",                                      "opcua.reassembled.in",             FT_FRAMENUM,    BASE_NONE,  NULL,   0x00,   NULL, HFILL}},
            {&hf_opcua_reassembled_length,          {"Reassembled length",                                  "opcua.reassembled.length",         FT_UINT32,      BASE_DEC,   NULL,   0x00,   NULL, HFILL}}
        };

    static ei_register_info ei[] =
        {
            { &ei_opcua_bad_footer, { "opcua.bad_footer", PI_MALFORMED, PI_ERROR, "Message too short for padding and signature", EXPFILL }}
        };
    expert_module_t *expert_opcua;

    /** Setup protocol subtree array */
    static int *ett[] =
        {
            &ett_opcua_transport,
            &ett_opcua_fragment,
            &ett_opcua_fragments
        };

    proto_opcua = proto_register_protocol("OpcUa Binary Protocol", "OpcUa", "opcua");
    opcua_handle = register_dissector("opcua", dissect_opcua, proto_opcua);

    register_init_routine(proto_init_opcua);
    register_cleanup_routine(proto_cleanup_opcua);

    opcua_module = prefs_register_protocol(proto_opcua, proto_reg_handoff_opcua);
    prefs_register_filename_preference(opcua_module, "debug_file", "OPCUA debug file",
            "Redirect OPC UA Secure Conversion session keys to the file specified to enable decryption.",
            &g_opcua_debug_file_name, false);

    prefs_register_enum_preference(opcua_module, "signature_length", "Default signature length",
            "Default signature length to use if the OpenSecureChannel message is missing.",
            &g_opcua_default_sig_len, opcua_sig_len_enum, false);

    registerTransportLayerTypes(proto_opcua);
    registerSecurityLayerTypes(proto_opcua);
    registerSequenceLayerTypes(proto_opcua);
    registerApplicationLayerTypes(proto_opcua);
    registerSimpleTypes(proto_opcua);
    registerEnumTypes(proto_opcua);
    registerComplexTypes();
    registerServiceTypes();
    registerFieldTypes(proto_opcua);
    opcua_infomodel_register(proto_opcua, opcua_module);

    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_opcua, hf, array_length(hf));
    expert_opcua = expert_register_protocol(proto_opcua);
    expert_register_field_array(expert_opcua, ei, array_length(ei));

    reassembly_table_register(&opcua_reassembly_table,
                          &addresses_reassembly_table_functions);
    secrets_register_type(SECRETS_TYPE_OPCUA, opcua_secrets_block_callback);
}

void proto_reg_handoff_opcua(void)
{
    dissector_add_uint_range_with_preference("tcp.port", OPCUA_PORT_RANGE, opcua_handle);
    opcua_infomodel_apply();
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
