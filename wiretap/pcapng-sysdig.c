/** @file
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "wtap-int.h"
#include "pcapng-sysdig-int.h"
#include "file_wrappers.h"


 /*
  * We split libscap events into two parts: A preamble from which we read metadata
  * and the event itself which we pass to epan.
  */
#define MIN_SYSDIG_PREAMBLE_SIZE (16/8) /* CPU ID */
#define MIN_SYSDIG_EVENT_SIZE    ((64 + 64 + 32 + 16)/8) /* Timestamp + Thread ID + Event len + Event type */

static inline bool
sysdig_has_flags(unsigned block_type) {
    return block_type == BLOCK_TYPE_SYSDIG_EVF
        || block_type == BLOCK_TYPE_SYSDIG_EVF_V2
        || block_type == BLOCK_TYPE_SYSDIG_EVF_V2_LARGE;
}

static inline bool
sysdig_has_nparams(unsigned block_type) {
    return block_type == BLOCK_TYPE_SYSDIG_EVENT_V2
        || block_type == BLOCK_TYPE_SYSDIG_EVENT_V2_LARGE
        || block_type == BLOCK_TYPE_SYSDIG_EVF_V2
        || block_type == BLOCK_TYPE_SYSDIG_EVF_V2_LARGE;
}

 // Preamble:
 //   uint16_t CPU ID
 //   uint32_t Flags (optional, sysdig_has_flags)
 // Event header (libs:driver/ppm_events_public.h:ppm_evt_hdr):
 //   uint64_t Timestamp
 //   uint64_t Thread ID
 //   uint32_t Event length. Includes this header.
 //   uint16_t Event type
 //   uint32_t Number of params (optional, sysdig_has_nparams)

bool
pcapng_read_sysdig_event_block(wtap* wth, FILE_T fh, pcapng_block_header_t* bh,
    section_info_t* section_info,
    wtapng_block_t* wblock,
    int* err, char** err_info)
{
    uint16_t cpu_id;
    uint64_t ts;
    uint64_t thread_id;
    uint32_t event_len;
    uint16_t event_type;
    uint32_t nparams = 0;
    uint32_t flags = 0;
    bool has_flags = sysdig_has_flags(bh->block_type);
    bool has_nparams = sysdig_has_nparams(bh->block_type);
    unsigned preamble_len = MIN_SYSDIG_PREAMBLE_SIZE + (has_flags ? 4 : 0);
    unsigned event_header_len = MIN_SYSDIG_EVENT_SIZE + (has_nparams ? 4 : 0);

    wblock->block = wtap_block_create(WTAP_BLOCK_SYSDIG_EVENT);

    if (bh->block_total_length < MIN_BLOCK_SIZE + preamble_len + event_header_len) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of a Sysdig event block is too small (< %u)",
            bh->block_total_length, MIN_BLOCK_SIZE + preamble_len + event_header_len);
        return false;
    }

    wtap_setup_syscall_rec(wblock->rec);
    wblock->rec->rec_header.syscall_header.record_type = bh->block_type;
    wblock->rec->presence_flags = WTAP_HAS_CAP_LEN /*|WTAP_HAS_INTERFACE_ID */;
    wblock->rec->tsprec = WTAP_TSPREC_NSEC;
    wblock->rec->rec_header.syscall_header.pathname = wth->pathname;

    // Preamble
    if (!wtap_read_bytes(fh, &cpu_id, sizeof cpu_id, err, err_info)) {
        ws_debug("failed to read sysdig event cpu id");
        return false;
    }
    if (has_flags) {
        if (!wtap_read_bytes(fh, &flags, sizeof flags, err, err_info)) {
            ws_debug("failed to read sysdig flags");
            return false;
        }
    }
    // Event header
    if (!wtap_read_bytes(fh, &ts, sizeof ts, err, err_info)) {
        ws_debug("failed to read sysdig event timestamp");
        return false;
    }
    if (!wtap_read_bytes(fh, &thread_id, sizeof thread_id, err, err_info)) {
        ws_debug("failed to read sysdig event thread id");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_len, sizeof event_len, err, err_info)) {
        ws_debug("failed to read sysdig event length");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_type, sizeof event_type, err, err_info)) {
        ws_debug("failed to read sysdig event type");
        return false;
    }
    if (has_nparams) {
        if (!wtap_read_bytes(fh, &nparams, sizeof nparams, err, err_info)) {
            ws_debug("failed to read sysdig number of parameters");
            return false;
        }
    }

    if (section_info->byte_swapped) {
        wblock->rec->rec_header.syscall_header.byte_order =
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
            G_BIG_ENDIAN;
#else
            G_LITTLE_ENDIAN;
#endif
        cpu_id = GUINT16_SWAP_LE_BE(cpu_id);
        ts = GUINT64_SWAP_LE_BE(ts);
        flags = GUINT32_SWAP_LE_BE(flags);
        thread_id = GUINT64_SWAP_LE_BE(thread_id);
        event_len = GUINT32_SWAP_LE_BE(event_len);
        event_type = GUINT16_SWAP_LE_BE(event_type);
        nparams = GUINT32_SWAP_LE_BE(nparams);
    }
    else {
        wblock->rec->rec_header.syscall_header.byte_order = G_BYTE_ORDER;
    }

    if (ts) {
        wblock->rec->presence_flags |= WTAP_HAS_TS;
    }

    wblock->rec->ts.secs = (time_t)(ts / 1000000000);
    wblock->rec->ts.nsecs = (int)(ts % 1000000000);

    unsigned block_remaining = bh->block_total_length - MIN_BLOCK_SIZE - preamble_len - event_header_len;
    if (event_len > block_remaining + event_header_len) {
        ws_debug("Truncating event length %u to %u", event_len, block_remaining + event_header_len);
        // ...or should we just return false here?
        event_len = block_remaining + event_header_len;
    }

    uint32_t event_data_len = event_len - event_header_len;

    wblock->rec->rec_header.syscall_header.cpu_id = cpu_id;
    wblock->rec->rec_header.syscall_header.flags = flags;
    wblock->rec->rec_header.syscall_header.thread_id = thread_id;
    wblock->rec->rec_header.syscall_header.event_len = event_len;
    wblock->rec->rec_header.syscall_header.event_data_len = event_data_len;
    wblock->rec->rec_header.syscall_header.event_type = event_type;
    wblock->rec->rec_header.syscall_header.nparams = nparams;

    // Event data
    // XXX Should we include the event header here? It would ensure that
    // we always have data and avoid the "consumed = 1" workaround in the
    // Falco Events dissector.
    if (!wtap_read_bytes_buffer(fh, &wblock->rec->data, event_data_len, err, err_info)) {
        return false;
    }

    unsigned pad_len = 0;
    if ((event_len + preamble_len) % 4) {
        pad_len = 4 - ((event_len + preamble_len) % 4);
    }
    if (pad_len && file_seek(fh, pad_len, SEEK_CUR, err) < 0) {
        return false;   /* Seek error */
    }

    /* Options */
    unsigned opt_cont_buf_len = block_remaining - (event_data_len + pad_len);
    if (!pcapng_process_options(fh, wblock, section_info, opt_cont_buf_len,
        NULL,
        OPT_LITTLE_ENDIAN, err, err_info))
        return false;

    /*
     * We return these to the caller in pcapng_read().
     */
    wblock->internal = false;

    /*
     * We want dissectors (particularly packet_frame) to be able to
     * access packet comments and whatnot that are in the block. wblock->block
     * will be unref'd by pcapng_seek_read(), so move the block to where
     * dissectors can find it.
     */
    wblock->rec->block = wblock->block;
    wblock->block = NULL;

    return true;
}

bool
pcapng_write_sysdig_event_block(wtap_dumper* wdh, const wtap_rec* rec,
    int* err, char** err_info)
{
    pcapng_block_header_t bh;
    const uint32_t zero_pad = 0;
    uint32_t pad_len;
    uint32_t options_size = 0;
    bool has_flags = sysdig_has_flags(rec->rec_header.syscall_header.record_type);
    bool has_nparams = sysdig_has_nparams(rec->rec_header.syscall_header.record_type);
    unsigned preamble_len = MIN_SYSDIG_PREAMBLE_SIZE + (has_flags ? 4 : 0);
    unsigned event_header_len = MIN_SYSDIG_EVENT_SIZE + (has_nparams ? 4 : 0);

    /* Don't write anything we're not willing to read. */
    if (rec->rec_header.syscall_header.event_data_len > WTAP_MAX_PACKET_SIZE_STANDARD) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return false;
    }

    if ((rec->rec_header.syscall_header.event_data_len + event_header_len + preamble_len) % 4) {
        pad_len = 4 - ((rec->rec_header.syscall_header.event_data_len + event_header_len + preamble_len) % 4);
    }
    else {
        pad_len = 0;
    }

    if (rec->block != NULL) {
        /* Compute size of all the options */
        options_size = pcapng_compute_options_size(rec->block, NULL);
    }

    /* write sysdig event block header */
    bh.block_type = rec->rec_header.syscall_header.record_type;
    bh.block_total_length = MIN_BLOCK_SIZE + preamble_len + event_header_len + rec->rec_header.syscall_header.event_data_len + pad_len + options_size;

    if (!wtap_dump_file_write(wdh, &bh, sizeof(bh), err))
        return false;

    uint16_t cpu_id = rec->rec_header.syscall_header.cpu_id;
    uint64_t ts = (((uint64_t)rec->ts.secs) * 1000000000) + rec->ts.nsecs;
    uint64_t thread_id = rec->rec_header.syscall_header.thread_id;
    uint32_t event_len = rec->rec_header.syscall_header.event_data_len + event_header_len;
    uint16_t event_type = rec->rec_header.syscall_header.event_type;

    // Preamble
    if (!wtap_dump_file_write(wdh, &cpu_id, sizeof cpu_id, err))
        return false;

    if (has_flags) {
        uint32_t flags = rec->rec_header.syscall_header.flags;
        if (!wtap_dump_file_write(wdh, &flags, sizeof(flags), err)) {
            return false;
        }
    }

    // Event header
    if (!wtap_dump_file_write(wdh, &ts, sizeof(ts), err))
        return false;

    if (!wtap_dump_file_write(wdh, &thread_id, sizeof(thread_id), err))
        return false;

    if (!wtap_dump_file_write(wdh, &event_len, sizeof(event_len), err))
        return false;

    if (!wtap_dump_file_write(wdh, &event_type, sizeof(event_type), err))
        return false;

    if (has_nparams) {
        uint32_t nparams = rec->rec_header.syscall_header.nparams;
        if (!wtap_dump_file_write(wdh, &nparams, sizeof(nparams), err)) {
            return false;
        }
    }

    /* Event data */
    if (!wtap_dump_file_write(wdh, ws_buffer_start_ptr(&rec->data), rec->rec_header.syscall_header.event_data_len, err))
        return false;

    /* Write padding (if any) */
    if (pad_len != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad_len, err))
            return false;
    }

    /* Write options, if we have any */
    if (options_size != 0) {
        if (!pcapng_write_options(wdh, OPT_SECTION_BYTE_ORDER,
            rec->block, NULL, err, err_info))
            return false;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
        sizeof bh.block_total_length, err))
        return false;

    return true;

}

/* Process a Sysdig meta event block that we have just read. */
void
pcapng_process_meta_event(wtap* wth, wtapng_block_t* wblock)
{
    // XXX add wtapng_process_meta_event(wth, wblock->block);

    /* Store meta event such that it can be saved by the dumper. */
    g_array_append_val(wth->meta_events, wblock->block);
}

bool
pcapng_read_meta_event_block(FILE_T fh, pcapng_block_header_t* bh,
    wtapng_block_t* wblock,
    int* err, char** err_info)
{
    unsigned to_read;
    wtapng_meta_event_mandatory_t* mev_mand;

    /*
     * Set wblock->block to a newly-allocated Sysdig meta event block.
     */
    wblock->block = wtap_block_create(WTAP_BLOCK_META_EVENT);

    /*
     * Set the mandatory values for the block.
     */
    mev_mand = (wtapng_meta_event_mandatory_t*)wtap_block_get_mandatory_data(wblock->block);
    mev_mand->mev_block_type = bh->block_type;
    mev_mand->mev_data_len = bh->block_total_length -
        (int)sizeof(pcapng_block_header_t) -
        (int)sizeof(bh->block_total_length);

    /* Sanity check: assume event data can't be larger than 1 GiB */
    if (mev_mand->mev_data_len > 1024 * 1024 * 1024) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: Sysdig mev block is too large: %u", mev_mand->mev_data_len);
        return false;
    }
    mev_mand->mev_data = (uint8_t*)g_malloc(mev_mand->mev_data_len);
    if (!wtap_read_bytes(fh, mev_mand->mev_data, mev_mand->mev_data_len, err, err_info)) {
        ws_debug("failed to read Sysdig mev");
        return false;
    }

    /* Skip past padding and discard options (not supported yet). */
    to_read = bh->block_total_length - MIN_BLOCK_SIZE - mev_mand->mev_data_len;
    if (!wtap_read_bytes(fh, NULL, to_read, err, err_info)) {
        ws_debug("failed to read Sysdig mev options");
        return false;
    }

    /*
     * We don't return these to the caller in pcapng_read().
     */
    wblock->internal = true;

    return true;
}

void register_sysdig(void)
{
    /* Nothing to register, yet, because there isn't a way to
       register things, yet. */
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
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
