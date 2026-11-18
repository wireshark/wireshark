/** @file
 *
 * Copyright 2025, Daniel Salloum <daniel.salloum@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"
#define WS_LOG_DOMAIN "MModuleFile"
#include "mmodule.h"

#include "wtap_module.h"
#include "file_wrappers.h"

#include <wsutil/pint.h>

static int mmodule_file_type_subtype = -1;

void register_mmodule(void);

#define MMODULE_HDR_SIZE   0x30
#define MMODULE_CHUNK_SIZE (64 * 1024)  // must be a multiple of 4

/*
 * Sum the little-endian 32-bit words in a buffer, ignoring any trailing
 * partial word.
 */
static uint32_t
mmodule_sum_words(const uint8_t *buf, unsigned len)
{
    uint32_t sum = 0;

    for (unsigned i = 0; i + 4 <= len; i += 4) {
        sum += pletohu32(buf + i);
    }
    return sum;
}

/*
 * Read the rest of the file, which must be exactly file_len bytes long,
 * and check that its little-endian 32-bit words (the header's included)
 * sum to 0. The header's checksum field is chosen to make them do so.
 *
 * This reads at most file_len + 1 bytes, so a short header with a large
 * length isn't followed by a read of an arbitrarily large (perhaps
 * compressed) file.
 */
static wtap_open_return_val
mmodule_check_length_and_checksum(FILE_T fh, uint32_t file_len,
    uint32_t checksum, int *err, char **err_info)
{
    wtap_open_return_val ret = WTAP_OPEN_NOT_MINE;
    uint8_t *buf = g_malloc(MMODULE_CHUNK_SIZE);
    uint32_t remaining = file_len - MMODULE_HDR_SIZE;

    while (remaining > 0) {
        unsigned n = MIN(remaining, MMODULE_CHUNK_SIZE);

        if (!wtap_read_bytes(fh, buf, n, err, err_info)) {
            // A short read means the file is shorter than reported.
            if (*err != WTAP_ERR_SHORT_READ) {
                ret = WTAP_OPEN_ERROR;
            }
            goto done;
        }
        checksum += mmodule_sum_words(buf, n);
        remaining -= n;
    }

    // There must be nothing past the reported length.
    if (wtap_read_bytes_or_eof(fh, buf, 1, err, err_info)) {
        goto done;
    }
    if (*err != 0) {
        ret = WTAP_OPEN_ERROR;
        goto done;
    }

    if (checksum == 0) {
        ret = WTAP_OPEN_MINE;
    }

done:
    g_free(buf);
    return ret;
}

wtap_open_return_val mmodule_open(wtap *wth, int *err, char **err_info)
{
    uint8_t hdr[MMODULE_HDR_SIZE];
    wtap_open_return_val ret;

    if (!wtap_read_bytes(wth->fh, hdr, sizeof hdr, err, err_info)) {
        if (*err != WTAP_ERR_SHORT_READ) {
            return WTAP_OPEN_ERROR;
        }
        return WTAP_OPEN_NOT_MINE;
    }

    // Check if a file tag we recognize
    uint32_t tag = pletohu32(hdr + 0x00);
    if (tag > 10 || tag < 1) {
        return WTAP_OPEN_NOT_MINE;
    }

    // Check if a version type we recognize
    uint32_t vtype = pletohu32(hdr + 0x10);
    if (vtype > 3 || vtype < 1) {
        return WTAP_OPEN_NOT_MINE;
    }

    // The reported length must cover the header and match the actual
    // length, and the entire file checksum must be valid.
    uint32_t reported_len = pletohu32(hdr + 0x20);
    if (reported_len < MMODULE_HDR_SIZE) {
        return WTAP_OPEN_NOT_MINE;
    }
    // If the file is neither compressed nor a pipe, its size is that of
    // its contents; check it before reading the whole file.
    if (!wth->ispipe && !file_iscompressed(wth->fh)) {
        int64_t file_size = wtap_file_size(wth, err);
        if (file_size == -1) {
            return WTAP_OPEN_ERROR;
        }
        if (file_size != reported_len) {
            return WTAP_OPEN_NOT_MINE;
        }
    }
    ret = mmodule_check_length_and_checksum(wth->fh, reported_len,
        mmodule_sum_words(hdr, sizeof hdr), err, err_info);
    if (ret != WTAP_OPEN_MINE) {
        return ret;
    }

    wth->file_type_subtype = mmodule_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_MMODULE;
    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_SEC;
    wth->subtype_read = wtap_full_file_read;
    wth->subtype_seek_read = wtap_full_file_seek_read;

    // Explicitly set, in case code gets updated somewhere
    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        return WTAP_OPEN_ERROR;
    }

    return WTAP_OPEN_MINE;
}

static const struct supported_block_type mmodule_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    // Use this if we break it up into different packets
    //{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
    { WTAP_BLOCK_PACKET, ONE_BLOCK_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info mmodule_info = {
    "Bachmann M-Module file", // description
    "m_module", // name
    "m", // extension
    NULL, // extra extensions
    false, // seek required?
    BLOCKS_SUPPORTED(mmodule_blocks_supported), // num blocks and block_type
    NULL,  // write support?
    NULL,  // open write support ?
    NULL   // We're not a lua writer
};

void register_mmodule(void)
{
    mmodule_file_type_subtype = wtap_register_file_type_subtype(&mmodule_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("MMODULE",
                                                   mmodule_file_type_subtype);
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
