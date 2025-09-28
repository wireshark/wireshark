/* blf.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * File format support for the Binary Log File (BLF) file format from
 * Vector Informatik decoder
 * Copyright (c) 2021-2025 by Dr. Lars Völker <lars.voelker@technica-engineering.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
  * The following was used as a reference for the file format:
  *     https://bitbucket.org/tobylorenz/vector_blf
  * The repo above includes multiple examples files as well.
  */

#include <config.h>
#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP

#include "blf.h"

#include <epan/dissectors/packet-socketcan.h>
#include <epan/dissectors/packet-flexray.h>
#include <epan/dissectors/packet-lin.h>
#include <string.h>
#include <errno.h>
#include <wsutil/value_string.h>
#include <wiretap/wtap.h>
#include <wiretap/wtap_opttypes.h>
#include <wsutil/wslog.h>
#include <wsutil/exported_pdu_tlvs.h>
#include <wsutil/pint.h>
#include <wsutil/report_message.h>
#include <wsutil/strtoi.h>
#include <wsutil/time_util.h>
#include <wsutil/zlib_compat.h>
#include <wsutil/pint.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include "file_wrappers.h"
#include "wtap-int.h"

static const uint8_t blf_magic[] = { 'L', 'O', 'G', 'G' };
static const uint8_t blf_obj_magic[] = { 'L', 'O', 'B', 'J' };

static const value_string blf_application_names[] = {
    { 0,    "Unknown" },
    { 1,    "Vector CANalyzer" },
    { 2,    "Vector CANoe" },
    { 3,    "Vector CANstress" },
    { 4,    "Vector CANlog" },
    { 5,    "Vector CANape" },
    { 6,    "Vector CANcaseXL log" },
    { 7,    "Vector Logger Configurator" },
    { 200,  "Porsche Logger" },
    { 201,  "CAETEC Logger" },
    { 202,  "Vector Network Simulator" },
    { 203,  "IPETRONIK logger" },
    { 204,  "RT PK" },
    { 205,  "PikeTec" },
    { 206,  "Sparks" },
    { 0, NULL }
};

static int blf_file_type_subtype = -1;

void register_blf(void);

static bool blf_read(wtap *wth, wtap_rec *rec, int *err, char **err_info, int64_t *data_offset);
static bool blf_seek_read(wtap *wth, int64_t seek_off, wtap_rec* rec, int *err, char **err_info);
static void blf_close(wtap *wth);

/*
 * The virtual buffer looks like this (skips all headers):
 * uncompressed log container data
 * uncompressed log container data
 * ...
 *
 * The "real" positions, length, etc. reference this layout and not the file.
 */
typedef struct blf_log_container {
    int64_t  infile_start_pos;        /* start position of log container in file */
    uint64_t infile_length;           /* length of log container in file */
    uint64_t infile_data_start;       /* start position of data in log container in file */

    uint64_t real_start_pos;          /* decompressed (virtual) start position including header */
    uint64_t real_length;             /* decompressed length */

    uint16_t compression_method;      /* 0: uncompressed, 2: zlib */

    unsigned char  *real_data;        /* cache for decompressed data */
} blf_log_container_t;

typedef struct blf_data {
    int64_t     start_of_last_obj;
    int64_t     current_real_seek_pos;
    uint64_t    start_offset_ns;
    uint64_t    end_offset_ns;

    GArray     *log_containers;

    GHashTable *channel_to_iface_ht;
    GHashTable *channel_to_name_ht;
    uint32_t    next_interface_id;
} blf_t;

typedef struct blf_params {
    wtap     *wth;
    wtap_rec *rec;
    FILE_T    fh;
    bool      random;
    bool      pipe;

    blf_t    *blf_data;
} blf_params_t;

typedef struct blf_channel_to_iface_entry {
    int             pkt_encap;
    uint16_t        channel;
    uint16_t        hwchannel;
    uint32_t        interface_id;
} blf_channel_to_iface_entry_t;

typedef struct blf_metadata_info {
    size_t  metadata_cont;
    size_t  payload_start;
    bool    valid;
} blf_metadata_info_t;

static void
blf_free_key(void *key) {
    g_free(key);
}

static void
blf_free_channel_to_iface_entry(void *data) {
     g_free(data);
}

static void
blf_free_channel_to_name_entry(void *data) {
    g_free(data);
}

static int64_t
blf_calc_key_value(int pkt_encap, uint16_t channel, uint16_t hwchannel) {
    return (int64_t)(((uint64_t)pkt_encap << 32) | ((uint64_t)hwchannel << 16) | (uint64_t)channel);
}

static time_t
blf_date_to_sec(const blf_date_t *date) {
    struct tm timestamp;
    timestamp.tm_year = (date->year > 1970) ? date->year - 1900 : 70;
    timestamp.tm_mon = date->month - 1;
    timestamp.tm_mday = date->day;
    timestamp.tm_hour = date->hour;
    timestamp.tm_min = date->mins;
    timestamp.tm_sec = date->sec;
    timestamp.tm_isdst = -1;

    return mktime(&timestamp);
}

/** Return the Epoch ns time of the blf date
 *
 * This is not intended to fully validate the date and time,
 * but just to check if the values are plausible.
 */
static uint64_t
blf_data_to_ns(const blf_date_t *date) {
    if (date != NULL &&
        (date->month >= 1 && date->month <= 12) &&
        (date->day >= 1 && date->day <= 31) &&
        (date->hour <= 23) && (date->mins <= 59) &&
        (date->sec <= 61)  /* Apparently can be up to 61 on certain systems */
        ) { /* Not checking if milliseconds are actually less than 1000 */
        time_t offset_s = blf_date_to_sec(date);
        if (offset_s >= 0) {
            return (1000 * 1000 * (date->ms + (1000 * (uint64_t)offset_s)));
        }
    }

    return 0;
}

static void add_interface_name(wtap_block_t int_data, int pkt_encap, uint16_t channel, uint16_t hwchannel, char *name) {
    if (name != NULL) {
        wtap_block_add_string_option_format(int_data, OPT_IDB_NAME, "%s", name);
    } else {
        switch (pkt_encap) {
        case WTAP_ENCAP_ETHERNET:
            /* we use UINT16_MAX to encode no hwchannel */
            if (hwchannel == UINT16_MAX) {
                wtap_block_add_string_option_format(int_data, OPT_IDB_NAME, "ETH-%u", channel);
            } else {
                wtap_block_add_string_option_format(int_data, OPT_IDB_NAME, "ETH-%u-%u", channel, hwchannel);
            }
            break;
        case WTAP_ENCAP_IEEE_802_11:
            wtap_block_add_string_option_format(int_data, OPT_IDB_NAME, "WLAN-%u", channel);
            break;
        case WTAP_ENCAP_FLEXRAY:
            wtap_block_add_string_option_format(int_data, OPT_IDB_NAME, "FR-%u", channel);
            break;
        case WTAP_ENCAP_LIN:
            wtap_block_add_string_option_format(int_data, OPT_IDB_NAME, "LIN-%u", channel);
            break;
        case WTAP_ENCAP_SOCKETCAN:
            wtap_block_add_string_option_format(int_data, OPT_IDB_NAME, "CAN-%u", channel);
            break;
        default:
            wtap_block_add_string_option_format(int_data, OPT_IDB_NAME, "ENCAP_%d-%u", pkt_encap, channel);
        }
    }

    /* Add a defined description format to recover the original channel/hwchannel mapping, when we ever convert back to BLF */
    /* Changing the names might break the BLF writing! */
    switch (pkt_encap) {
    case WTAP_ENCAP_ETHERNET:
        wtap_block_add_string_option_format(int_data, OPT_IDB_DESCRIPTION, "BLF-ETH-0x%04x-0x%04x", channel, hwchannel);
        break;
    case WTAP_ENCAP_IEEE_802_11:
        wtap_block_add_string_option_format(int_data, OPT_IDB_DESCRIPTION, "BLF-WLAN-0x%04x", channel);
        break;
    case WTAP_ENCAP_FLEXRAY:
        wtap_block_add_string_option_format(int_data, OPT_IDB_DESCRIPTION, "BLF-FR-0x%04x", channel);
        break;
    case WTAP_ENCAP_LIN:
        wtap_block_add_string_option_format(int_data, OPT_IDB_DESCRIPTION, "BLF-LIN-0x%04x", channel);
        break;
    case WTAP_ENCAP_SOCKETCAN:
        wtap_block_add_string_option_format(int_data, OPT_IDB_DESCRIPTION, "BLF-CAN-0x%04x", channel);
        break;
    default:
        wtap_block_add_string_option_format(int_data, OPT_IDB_DESCRIPTION, "BLF-ENCAP_%d-0x%04x-0x%04x", pkt_encap, channel, hwchannel);
    }
}

static uint32_t
blf_add_interface(blf_params_t *params, int pkt_encap, uint32_t channel, uint16_t hwchannel, char *name) {
    wtap_block_t int_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
    wtapng_if_descr_mandatory_t *if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);
    blf_channel_to_iface_entry_t *item = NULL;

    if_descr_mand->wtap_encap = pkt_encap;
    add_interface_name(int_data, pkt_encap, channel, hwchannel, name);
    /*
     * The time stamp resolution in these files can be per-record;
     * the maximum resolution is nanoseconds, so we specify that
     * as the interface's resolution.
     *
     * We set the resolution for a record on a per-record basis,
     * based on what the record specifies.
     */
    if_descr_mand->time_units_per_second = 1000 * 1000 * 1000;
    if_descr_mand->tsprecision = WTAP_TSPREC_NSEC;
    wtap_block_add_uint8_option(int_data, OPT_IDB_TSRESOL, 9);
    if_descr_mand->snap_len = WTAP_MAX_PACKET_SIZE_STANDARD;
    if_descr_mand->num_stat_entries = 0;
    if_descr_mand->interface_statistics = NULL;
    wtap_add_idb(params->wth, int_data);

    if (params->wth->file_encap == WTAP_ENCAP_NONE) {
        params->wth->file_encap = if_descr_mand->wtap_encap;
    } else {
        if (params->wth->file_encap != if_descr_mand->wtap_encap) {
            params->wth->file_encap = WTAP_ENCAP_PER_PACKET;
        }
    }

    int64_t *key = NULL;
    key = g_new(int64_t, 1);
    *key = blf_calc_key_value(pkt_encap, channel, hwchannel);

    item = g_new(blf_channel_to_iface_entry_t, 1);
    item->channel = channel;
    item->hwchannel = hwchannel;
    item->pkt_encap = pkt_encap;
    item->interface_id = params->blf_data->next_interface_id++;
    g_hash_table_insert(params->blf_data->channel_to_iface_ht, key, item);

    return item->interface_id;
}

/** This is used to save the interface name without creating it.
 *
 * This approach allows up to update the name of the interface
 * up until the first captured packet.
 */
static bool
// NOLINTNEXTLINE(misc-no-recursion)
blf_prepare_interface_name(blf_params_t* params, int pkt_encap, uint16_t channel, uint16_t hwchannel, const char* name, bool force_new_name) {
    int64_t key = blf_calc_key_value(pkt_encap, channel, hwchannel);
    char* old_name;
    char* new_name;
    char* iface_name;
    int64_t* new_key;
    bool ret;

    if (params->blf_data->channel_to_name_ht == NULL) {
        return false;
    }

    old_name = (char *)g_hash_table_lookup(params->blf_data->channel_to_name_ht, &key);

    if (old_name != NULL && force_new_name) {
        if (!g_hash_table_remove(params->blf_data->channel_to_name_ht, &key)) {
            return false;
        }

        old_name = NULL;
    }

    if (old_name == NULL && name != NULL) {
        new_key = g_new(int64_t, 1);
        *new_key = key;
        new_name = ws_strdup(name);
        if (!g_hash_table_insert(params->blf_data->channel_to_name_ht, new_key, new_name)) {
            return false;
        }
    } else {
        new_name = old_name;
    }

    if (pkt_encap == WTAP_ENCAP_ETHERNET) {
        /* Just for Ethernet, prepare the equivalent STATUS interface */
        iface_name = new_name != NULL ? ws_strdup_printf("STATUS-%s", new_name) : NULL;

        // We recurse here once.
        ret = blf_prepare_interface_name(params, WTAP_ENCAP_WIRESHARK_UPPER_PDU, channel, hwchannel, iface_name, force_new_name);
        if (iface_name) {
            g_free(iface_name);
        }
        if (!ret) {
            return false;
        }
    }

    return true;
}

static uint32_t
blf_lookup_interface(blf_params_t *params, int pkt_encap, uint16_t channel, uint16_t hwchannel, char *name) {
    int64_t key = blf_calc_key_value(pkt_encap, channel, hwchannel);
    blf_channel_to_iface_entry_t* item;
    char* saved_name;
    uint32_t ret;

    if (params->blf_data->channel_to_iface_ht == NULL) {
        return 0;
    }

    item = (blf_channel_to_iface_entry_t *)g_hash_table_lookup(params->blf_data->channel_to_iface_ht, &key);

    if (item != NULL) {
        return item->interface_id;
    } else {
        saved_name = (char*)g_hash_table_lookup(params->blf_data->channel_to_name_ht, &key);

        if (saved_name != NULL) {
            ret = blf_add_interface(params, pkt_encap, channel, hwchannel, saved_name);
            g_hash_table_remove(params->blf_data->channel_to_name_ht, &key);

            return ret;
        } else {
            return blf_add_interface(params, pkt_encap, channel, hwchannel, name);
        }
    }
}

static void
fix_endianness_blf_date(blf_date_t *date) {
    date->year = GUINT16_FROM_LE(date->year);
    date->month = GUINT16_FROM_LE(date->month);
    date->dayofweek = GUINT16_FROM_LE(date->dayofweek);
    date->day = GUINT16_FROM_LE(date->day);
    date->hour = GUINT16_FROM_LE(date->hour);
    date->mins = GUINT16_FROM_LE(date->mins);
    date->sec = GUINT16_FROM_LE(date->sec);
    date->ms = GUINT16_FROM_LE(date->ms);
}

static void
fix_endianness_blf_fileheader(blf_fileheader_t *header) {
    header->header_length = GUINT32_FROM_LE(header->header_length);
    header->api_version = GUINT32_FROM_LE(header->api_version);
    header->len_compressed = GUINT64_FROM_LE(header->len_compressed);
    header->len_uncompressed = GUINT64_FROM_LE(header->len_uncompressed);
    header->obj_count = GUINT32_FROM_LE(header->obj_count);
    header->application_build = GUINT32_FROM_LE(header->application_build);
    fix_endianness_blf_date(&(header->start_date));
    fix_endianness_blf_date(&(header->end_date));
    header->restore_point_offset = GUINT32_FROM_LE(header->restore_point_offset);
}

static void
fix_endianness_blf_blockheader(blf_blockheader_t *header) {
    header->header_length = GUINT16_FROM_LE(header->header_length);
    header->header_type = GUINT16_FROM_LE(header->header_type);
    header->object_length = GUINT32_FROM_LE(header->object_length);
    header->object_type = GUINT32_FROM_LE(header->object_type);
}

static void
fix_endianness_blf_logcontainerheader(blf_logcontainerheader_t *header) {
    header->compression_method = GUINT16_FROM_LE(header->compression_method);
    header->res1 = GUINT16_FROM_LE(header->res1);
    header->res2 = GUINT32_FROM_LE(header->res2);
    header->uncompressed_size = GUINT32_FROM_LE(header->uncompressed_size);
    header->res4 = GUINT32_FROM_LE(header->res4);
}

static void
fix_endianness_blf_logobjectheader(blf_logobjectheader_t *header) {
    header->flags = GUINT32_FROM_LE(header->flags);
    header->client_index = GUINT16_FROM_LE(header->client_index);
    header->object_version = GUINT16_FROM_LE(header->object_version);
    header->object_timestamp = GUINT64_FROM_LE(header->object_timestamp);
}

static void
fix_endianness_blf_logobjectheader2(blf_logobjectheader2_t *header) {
    header->flags = GUINT32_FROM_LE(header->flags);
    header->object_version = GUINT16_FROM_LE(header->object_version);
    header->object_timestamp = GUINT64_FROM_LE(header->object_timestamp);
    header->original_timestamp = GUINT64_FROM_LE(header->object_timestamp);
}

static void
fix_endianness_blf_logobjectheader3(blf_logobjectheader3_t *header) {
    header->flags = GUINT32_FROM_LE(header->flags);
    header->static_size = GUINT16_FROM_LE(header->static_size);
    header->object_version = GUINT16_FROM_LE(header->object_version);
    header->object_timestamp = GUINT64_FROM_LE(header->object_timestamp);
}

static void
fix_endianness_blf_ethernetframeheader(blf_ethernetframeheader_t *header) {
    header->channel = GUINT16_FROM_LE(header->channel);
    header->direction = GUINT16_FROM_LE(header->direction);
    header->ethtype = GUINT16_FROM_LE(header->ethtype);
    header->tpid = GUINT16_FROM_LE(header->tpid);
    header->tci = GUINT16_FROM_LE(header->tci);
    header->payloadlength = GUINT16_FROM_LE(header->payloadlength);
}

static void
fix_endianness_blf_ethernetframeheader_ex(blf_ethernetframeheader_ex_t *header) {
    header->struct_length = GUINT16_FROM_LE(header->struct_length);
    header->flags = GUINT16_FROM_LE(header->flags);
    header->channel = GUINT16_FROM_LE(header->channel);
    header->hw_channel = GUINT16_FROM_LE(header->hw_channel);
    header->frame_duration = GUINT64_FROM_LE(header->frame_duration);
    header->frame_checksum = GUINT32_FROM_LE(header->frame_checksum);
    header->direction = GUINT16_FROM_LE(header->direction);
    header->frame_length = GUINT16_FROM_LE(header->frame_length);
    header->frame_handle = GUINT32_FROM_LE(header->frame_handle);
    header->error = GUINT32_FROM_LE(header->error);
}

static void
fix_endianness_blf_ethernet_rxerror(blf_ethernet_rxerror_t* header) {
    header->struct_length = GUINT16_FROM_LE(header->struct_length);
    header->channel = GUINT16_FROM_LE(header->channel);
    header->direction = GUINT16_FROM_LE(header->direction);
    header->hw_channel = GUINT16_FROM_LE(header->hw_channel);
    header->frame_checksum = GUINT32_FROM_LE(header->frame_checksum);
    header->frame_length = GUINT16_FROM_LE(header->frame_length);
    header->error = GUINT32_FROM_LE(header->error);
}

static void
fix_endianness_blf_wlanframeheader(blf_wlanframeheader_t* header) {
    header->channel = GUINT16_FROM_LE(header->channel);
    header->flags = GUINT16_FROM_LE(header->flags);
    header->signal_strength = GUINT16_FROM_LE(header->signal_strength);
    header->signal_quality = GUINT16_FROM_LE(header->signal_quality);
    header->frame_length = GUINT16_FROM_LE(header->frame_length);
}

static void
fix_endianness_blf_canmessage(blf_canmessage_t *header) {
    header->channel = GUINT16_FROM_LE(header->channel);
    header->id = GUINT32_FROM_LE(header->id);
}

static void
fix_endianness_blf_canmessage2_trailer(blf_canmessage2_trailer_t *header) {
    header->frameLength_in_ns = GUINT32_FROM_LE(header->frameLength_in_ns);
    header->reserved2 = GUINT16_FROM_LE(header->reserved1);
}

static void
fix_endianness_blf_canfdmessage(blf_canfdmessage_t *header) {
    header->channel = GUINT16_FROM_LE(header->channel);
    header->id = GUINT32_FROM_LE(header->id);
    header->frameLength_in_ns = GUINT32_FROM_LE(header->frameLength_in_ns);
    header->reservedCanFdMessage2 = GUINT32_FROM_LE(header->reservedCanFdMessage2);
}

static void
fix_endianness_blf_canfdmessage64(blf_canfdmessage64_t *header) {
    header->id = GUINT32_FROM_LE(header->id);
    header->frameLength_in_ns = GUINT32_FROM_LE(header->frameLength_in_ns);
    header->flags = GUINT32_FROM_LE(header->flags);
    header->btrCfgArb = GUINT32_FROM_LE(header->btrCfgArb);
    header->btrCfgData = GUINT32_FROM_LE(header->btrCfgData);
    header->timeOffsetBrsNs = GUINT32_FROM_LE(header->timeOffsetBrsNs);
    header->timeOffsetCrcDelNs = GUINT32_FROM_LE(header->timeOffsetCrcDelNs);
    header->bitCount = GUINT16_FROM_LE(header->bitCount);
    header->crc = GUINT32_FROM_LE(header->crc);
}

static void
fix_endianness_blf_canerror(blf_canerror_t *header) {
    header->channel = GUINT16_FROM_LE(header->channel);
    header->length = GUINT16_FROM_LE(header->length);
}

static void
fix_endianness_blf_canerrorext(blf_canerrorext_t *header) {
    header->channel = GUINT16_FROM_LE(header->channel);
    header->length = GUINT16_FROM_LE(header->length);
    header->flags = GUINT32_FROM_LE(header->flags);
    header->frameLength_in_ns = GUINT32_FROM_LE(header->frameLength_in_ns);
    header->id = GUINT32_FROM_LE(header->id);
    header->errorCodeExt = GUINT16_FROM_LE(header->errorCodeExt);
}

static void
fix_endianness_blf_canfderror64(blf_canfderror64_t *header) {
    header->flags = GUINT16_FROM_LE(header->flags);
    header->errorCodeExt = GUINT16_FROM_LE(header->errorCodeExt);
    header->extFlags = GUINT16_FROM_LE(header->extFlags);
    header->id = GUINT32_FROM_LE(header->id);
    header->frameLength_in_ns = GUINT32_FROM_LE(header->frameLength_in_ns);
    header->btrCfgArb = GUINT32_FROM_LE(header->btrCfgArb);
    header->btrCfgData = GUINT32_FROM_LE(header->btrCfgData);
    header->timeOffsetBrsNs = GUINT32_FROM_LE(header->timeOffsetBrsNs);
    header->timeOffsetCrcDelNs = GUINT32_FROM_LE(header->timeOffsetCrcDelNs);
    header->crc = GUINT32_FROM_LE(header->crc);
    header->errorPosition = GUINT16_FROM_LE(header->errorPosition);
}

static void
fix_endianness_blf_canxlchannelframe(blf_canxlchannelframe_t *header) {
    header->frameLength_in_ns = GUINT32_FROM_LE(header->frameLength_in_ns);
    header->bitCount = GUINT16_FROM_LE(header->bitCount);
    header->res2 = GUINT16_FROM_LE(header->res2);
    header->frameIdentifier = GUINT32_FROM_LE(header->frameIdentifier);
    header->dlc = GUINT16_FROM_LE(header->dlc);
    header->dataLength = GUINT16_FROM_LE(header->dataLength);
    header->stuffBitCount = GUINT16_FROM_LE(header->stuffBitCount);
    header->prefaceCRC = GUINT16_FROM_LE(header->prefaceCRC);
    header->acceptanceField = GUINT32_FROM_LE(header->acceptanceField);
    header->res5 = GUINT16_FROM_LE(header->res5);
    header->crc = GUINT32_FROM_LE(header->crc);
    header->timeOffsetBrsNs = GUINT32_FROM_LE(header->timeOffsetBrsNs);
    header->timeOffsetCrcDelNs = GUINT32_FROM_LE(header->timeOffsetCrcDelNs);
    header->flags = GUINT32_FROM_LE(header->flags);
    header->reserved = GUINT32_FROM_LE(header->reserved);
    header->arbitrationDataBitTimingConfig = GUINT64_FROM_LE(header->arbitrationDataBitTimingConfig);
    header->arbitrationDataHwChannelSettings = GUINT64_FROM_LE(header->arbitrationDataHwChannelSettings);
    header->fdPhaseBitTimingConfig = GUINT64_FROM_LE(header->fdPhaseBitTimingConfig);
    header->fdPhaseHwChannelSettings = GUINT64_FROM_LE(header->fdPhaseHwChannelSettings);
    header->xlPhaseBitTimingConfig = GUINT64_FROM_LE(header->xlPhaseBitTimingConfig);
    header->xlPhaseHwChannelSettings = GUINT64_FROM_LE(header->xlPhaseHwChannelSettings);
}


static void
fix_endianness_blf_flexraydata(blf_flexraydata_t *header) {
    header->channel = GUINT16_FROM_LE(header->channel);
    header->messageId = GUINT16_FROM_LE(header->messageId);
    header->crc = GUINT16_FROM_LE(header->crc);
    header->reservedFlexRayData2 = GUINT16_FROM_LE(header->reservedFlexRayData2);
}

static void
fix_endianness_blf_flexraymessage(blf_flexraymessage_t *header) {
    header->channel = GUINT16_FROM_LE(header->channel);
    header->fpgaTick = GUINT32_FROM_LE(header->fpgaTick);
    header->fpgaTickOverflow = GUINT32_FROM_LE(header->fpgaTickOverflow);
    header->clientIndexFlexRayV6Message = GUINT32_FROM_LE(header->clientIndexFlexRayV6Message);
    header->clusterTime = GUINT32_FROM_LE(header->clusterTime);
    header->frameId = GUINT16_FROM_LE(header->frameId);
    header->headerCrc = GUINT16_FROM_LE(header->headerCrc);
    header->frameState = GUINT16_FROM_LE(header->frameState);
    header->reservedFlexRayV6Message2 = GUINT16_FROM_LE(header->reservedFlexRayV6Message2);
}

static void
fix_endianness_blf_flexrayrcvmessage(blf_flexrayrcvmessage_t *header) {
    header->channel = GUINT16_FROM_LE(header->channel);
    header->version = GUINT16_FROM_LE(header->version);
    header->channelMask = GUINT16_FROM_LE(header->channelMask);
    header->dir = GUINT16_FROM_LE(header->dir);
    header->clientIndex = GUINT32_FROM_LE(header->clientIndex);
    header->clusterNo = GUINT32_FROM_LE(header->clusterNo);
    header->frameId = GUINT16_FROM_LE(header->frameId);
    header->headerCrc1 = GUINT16_FROM_LE(header->headerCrc1);
    header->headerCrc2 = GUINT16_FROM_LE(header->headerCrc2);
    header->payloadLength = GUINT16_FROM_LE(header->payloadLength);
    header->payloadLengthValid = GUINT16_FROM_LE(header->payloadLengthValid);
    header->cycle = GUINT16_FROM_LE(header->cycle);
    header->tag = GUINT32_FROM_LE(header->tag);
    header->data = GUINT32_FROM_LE(header->data);
    header->frameFlags = GUINT32_FROM_LE(header->frameFlags);
    header->appParameter = GUINT32_FROM_LE(header->appParameter);
/*  this would be extra for ext format:
    header->frameCRC = GUINT32_FROM_LE(header->frameCRC);
    header->frameLengthInNs = GUINT32_FROM_LE(header->frameLengthInNs);
    header->frameId1 = GUINT16_FROM_LE(header->frameId1);
    header->pduOffset = GUINT16_FROM_LE(header->pduOffset);
    header->blfLogMask = GUINT16_FROM_LE(header->blfLogMask);
*/
}

static void
fix_endianness_blf_linmessage(blf_linmessage_t* message) {
    message->channel = GUINT16_FROM_LE(message->channel);
    message->crc = GUINT16_FROM_LE(message->crc);
/*  skip the optional part
    message->res2 = GUINT32_FROM_LE(message->res2);
*/
}

static void
fix_endianness_blf_linbusevent(blf_linbusevent_t* linbusevent) {
    linbusevent->sof = GUINT64_FROM_LE(linbusevent->sof);
    linbusevent->eventBaudrate = GUINT32_FROM_LE(linbusevent->eventBaudrate);
    linbusevent->channel = GUINT16_FROM_LE(linbusevent->channel);
}

static void
fix_endianness_blf_linsynchfieldevent(blf_linsynchfieldevent_t* linsynchfieldevent) {
    fix_endianness_blf_linbusevent(&linsynchfieldevent->linBusEvent);
    linsynchfieldevent->synchBreakLength = GUINT64_FROM_LE(linsynchfieldevent->synchBreakLength);
    linsynchfieldevent->synchDelLength = GUINT64_FROM_LE(linsynchfieldevent->synchDelLength);
}

static void
fix_endianness_blf_linmessagedescriptor(blf_linmessagedescriptor_t* linmessagedescriptor) {
    fix_endianness_blf_linsynchfieldevent(&linmessagedescriptor->linSynchFieldEvent);
    linmessagedescriptor->supplierId = GUINT16_FROM_LE(linmessagedescriptor->supplierId);
    linmessagedescriptor->messageId = GUINT16_FROM_LE(linmessagedescriptor->messageId);
}

static void
fix_endianness_blf_lindatabytetimestampevent(blf_lindatabytetimestampevent_t* lindatabytetimestampevent) {
    int i;
    fix_endianness_blf_linmessagedescriptor(&lindatabytetimestampevent->linMessageDescriptor);
    for (i = 0; i < 9; i++) {
        lindatabytetimestampevent->databyteTimestamps[i] = GUINT64_FROM_LE(lindatabytetimestampevent->databyteTimestamps[i]);
    }
}

static void
fix_endianness_blf_linmessage2(blf_linmessage2_t* message) {
    fix_endianness_blf_lindatabytetimestampevent(&message->linDataByteTimestampEvent);
    message->crc = GUINT16_FROM_LE(message->crc);
/*  skip the optional part
    message->respBaudrate = GUINT32_FROM_LE(message->respBaudrate);
    message->exactHeaderBaudrate = GUINT64_FROM_LE(message->exactHeaderBaudrate);
    message->earlyStopBitOffset = GUINT32_FROM_LE(message->earlyStopBitOffset);
    message->earlyStopBitOffsetResponse = GUINT32_FROM_LE(message->earlyStopBitOffsetResponse);
*/
}

static void
fix_endianness_blf_lincrcerror2(blf_lincrcerror2_t* message) {
    fix_endianness_blf_lindatabytetimestampevent(&message->linDataByteTimestampEvent);
    message->crc = GUINT16_FROM_LE(message->crc);
/*  skip the optional part
    message->respBaudrate = GUINT32_FROM_LE(message->respBaudrate);
    message->exactHeaderBaudrate = GUINT64_FROM_LE(message->exactHeaderBaudrate);
    message->earlyStopBitOffset = GUINT32_FROM_LE(message->earlyStopBitOffset);
    message->earlyStopBitOffsetResponse = GUINT32_FROM_LE(message->earlyStopBitOffsetResponse);
*/
}

static void
fix_endianness_blf_linrcverror2(blf_linrcverror2_t* message) {
    fix_endianness_blf_lindatabytetimestampevent(&message->linDataByteTimestampEvent);
/*  skip the optional part
    message->respBaudrate = GUINT32_FROM_LE(message->respBaudrate);
    message->exactHeaderBaudrate = GUINT64_FROM_LE(message->exactHeaderBaudrate);
    message->earlyStopBitOffset = GUINT32_FROM_LE(message->earlyStopBitOffset);
    message->earlyStopBitOffsetResponse = GUINT32_FROM_LE(message->earlyStopBitOffsetResponse);
*/
}

static void
fix_endianness_blf_linsenderror2(blf_linsenderror2_t* message) {
    fix_endianness_blf_linmessagedescriptor(&message->linMessageDescriptor);
    message->eoh = GUINT64_FROM_LE(message->eoh);
/*  skip the optional part
    message->exactHeaderBaudrate = GUINT64_FROM_LE(message->exactHeaderBaudrate);
    message->earlyStopBitOffset = GUINT32_FROM_LE(message->earlyStopBitOffset);
*/
}

static void
fix_endianness_blf_linwakeupevent2(blf_linwakeupevent2_t* message) {
    fix_endianness_blf_linbusevent(&message->linBusEvent);
}

static void
fix_endianness_blf_apptext_header(blf_apptext_t *header) {
    header->source = GUINT32_FROM_LE(header->source);
    header->reservedAppText1 = GUINT32_FROM_LE(header->reservedAppText1);
    header->textLength = GUINT32_FROM_LE(header->textLength);
    header->reservedAppText2 = GUINT32_FROM_LE(header->reservedAppText2);
}

static void
fix_endianness_blf_ethernet_status_header(blf_ethernet_status_t* header) {
    header->channel = GUINT16_FROM_LE(header->channel);
    header->flags = GUINT16_FROM_LE(header->flags);
    /*uint8_t linkStatus;*/
    /*uint8_t ethernetPhy;*/
    /*uint8_t duplex;*/
    /*uint8_t mdi;*/
    /*uint8_t connector;*/
    /*uint8_t clockMode;*/
    /*uint8_t pairs;*/
    /*uint8_t hardwareChannel;*/
    header->bitrate = GUINT32_FROM_LE(header->bitrate);
}

static void
fix_endianness_blf_ethernet_phystate_header(blf_ethernet_phystate_t* header) {
    header->channel = GUINT16_FROM_LE(header->channel);
    header->flags = GUINT16_FROM_LE(header->flags);
}

static void
blf_init_logcontainer(blf_log_container_t *tmp) {
    tmp->infile_start_pos = 0;
    tmp->infile_length = 0;
    tmp->infile_data_start = 0;
    tmp->real_start_pos = 0;
    tmp->real_length = 0;
    tmp->real_data = NULL;
    tmp->compression_method = 0;
}

int
blf_logcontainers_cmp(const void *a, const void *b) {
    const blf_log_container_t* container_a = (blf_log_container_t*)a;
    const blf_log_container_t* container_b = (blf_log_container_t*)b;

    if (container_a->real_start_pos < container_b->real_start_pos) {
        return -1;
    } else if (container_a->real_start_pos > container_b->real_start_pos) {
        return 1;
    } else {
        return 0;
    }
}

int
blf_logcontainers_search(const void *a, const void *b) {
    const blf_log_container_t* container_a = (blf_log_container_t*)a;
    uint64_t pos = *(uint64_t*)b;

    if (container_a->real_start_pos > pos) {
        return 1;
    } else if (pos >= container_a->real_start_pos + container_a->real_length) {
        return -1;
    } else {
        return 0;
    }
}

/** Ensures the given log container is in memory
 *
 * If the log container already is not already in memory,
 * it reads it from the current seek position, allocating a
 * properly sized buffer.
 * The file offset must be set to the start of the container
 * data (container->infile_data_start) before calling this function.
 */
static bool
blf_pull_logcontainer_into_memory(blf_params_t *params, blf_log_container_t *container, int *err, char **err_info) {

    if (container == NULL) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("blf_pull_logcontainer_into_memory called with NULL container");
        return false;
    }

    if (container->real_data != NULL) {
        return true;
    }

    /* pull compressed data into buffer */
    if (container->infile_start_pos < 0) {
        /*
         * XXX - does this represent a bug (WTAP_ERR_INTERNAL) or a
         * malformed file (WTAP_ERR_BAD_FILE)?
         */
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf_pull_logcontainer_into_memory: container.infile_start_pos (%" PRId64 ") < 0",
            container->infile_start_pos);
        return false;
    }
    if (container->infile_data_start < (uint64_t)container->infile_start_pos) {
        /*
         * XXX - does this represent a bug (WTAP_ERR_INTERNAL) or a
         * malformed file (WTAP_ERR_BAD_FILE)?
         */
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf_pull_logcontainer_into_memory: container.infile_data_start (%" PRIu64 ") < container.infile_start_pos (%" PRId64 ")",
            container->infile_data_start, container->infile_start_pos);
        return false;
    }
    if (container->infile_length < container->infile_data_start - (uint64_t)container->infile_start_pos) {
        /*
         * XXX - does this represent a bug (WTAP_ERR_INTERNAL) or a
         * malformed file (WTAP_ERR_BAD_FILE)?
         */
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf_pull_logcontainer_into_memory: container.infile_length (%" PRIu64 ") < (container.infile_data_start (%" PRIu64 ") - container.infile_start_pos (%" PRId64 ")) = %" PRIu64,
            container->infile_length,
            container->infile_data_start, container->infile_start_pos,
            container->infile_data_start - (uint64_t)container->infile_start_pos);
        return false;
    }
    uint64_t data_length = container->infile_length - (container->infile_data_start - (uint64_t)container->infile_start_pos);
    if (data_length > UINT_MAX) {
        /*
         * XXX - does this represent a bug (WTAP_ERR_INTERNAL) or a
         * malformed file (WTAP_ERR_BAD_FILE)?
         */
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf_pull_logcontainer_into_memory: data_length (%" PRIu64 ") > UINT_MAX",
            data_length);
        return false;
    }

    if (container->real_length == 0) {
        ws_info("blf_pull_logcontainer_into_memory: found container with 0 length");
        /* Skip empty container */
        if (!wtap_read_bytes_or_eof(params->fh, NULL, (unsigned int)data_length, err, err_info)) {
            if (*err == WTAP_ERR_SHORT_READ) {
                /*
                 * XXX - our caller will turn this into an EOF.
                 * How *should* it be treated?
                 * For now, we turn it into Yet Another Internal Error,
                 * pending having better documentation of the file
                 * format.
                 */
                *err = WTAP_ERR_INTERNAL;
                *err_info = ws_strdup("blf_pull_logcontainer_into_memory: short read on 0-length container");
            }
            return false;
        }
        return true;
    }

    if (container->compression_method == BLF_COMPRESSION_NONE) {
        unsigned char* buf = g_try_malloc((size_t)container->real_length);
        if (buf == NULL) {
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup("blf_pull_logcontainer_into_memory: cannot allocate memory");
            return false;
        }
        if (!wtap_read_bytes_or_eof(params->fh, buf, (unsigned int)data_length, err, err_info)) {
            g_free(buf);
            if (*err == WTAP_ERR_SHORT_READ) {
                /*
                 * XXX - our caller will turn this into an EOF.
                 * How *should* it be treated?
                 * For now, we turn it into Yet Another Internal Error,
                 * pending having better documentation of the file
                 * format.
                 */
                *err = WTAP_ERR_INTERNAL;
                *err_info = ws_strdup("blf_pull_logcontainer_into_memory: short read on uncompressed data");
            }
            return false;
        }
        container->real_data = buf;
        return true;

    } else if (container->compression_method == BLF_COMPRESSION_ZLIB) {
#ifdef USE_ZLIB_OR_ZLIBNG
        unsigned char *compressed_data = g_try_malloc((size_t)data_length);
        if (compressed_data == NULL) {
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup("blf_pull_logcontainer_into_memory: cannot allocate memory");
            return false;
        }
        if (!wtap_read_bytes_or_eof(params->fh, compressed_data, (unsigned int)data_length, err, err_info)) {
            g_free(compressed_data);
            if (*err == WTAP_ERR_SHORT_READ) {
                /*
                 * XXX - our caller will turn this into an EOF.
                 * How *should* it be treated?
                 * For now, we turn it into Yet Another Internal Error,
                 * pending having better documentation of the file
                 * format.
                 */
                *err = WTAP_ERR_INTERNAL;
                *err_info = ws_strdup("blf_pull_logcontainer_into_memory: short read on compressed data");
            }
            return false;
        }

        unsigned char *buf = g_try_malloc((size_t)container->real_length);
        if (buf == NULL) {
            g_free(compressed_data);
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup("blf_pull_logcontainer_into_memory: cannot allocate memory");
            return false;
        }
        zlib_stream infstream = {0};

        infstream.avail_in  = (unsigned int)data_length;
        infstream.next_in   = compressed_data;
        infstream.avail_out = (unsigned int)container->real_length;
        infstream.next_out  = buf;

        /* the actual DE-compression work. */
        if (Z_OK != ZLIB_PREFIX(inflateInit)(&infstream)) {
            /*
             * XXX - check the error code and handle this appropriately.
             */
            g_free(buf);
            g_free(compressed_data);
            *err = WTAP_ERR_INTERNAL;
            if (infstream.msg != NULL) {
                *err_info = ws_strdup_printf("blf_pull_logcontainer_into_memory: inflateInit failed for LogContainer, message\"%s\"",
                                              infstream.msg);
            } else {
                *err_info = ws_strdup("blf_pull_logcontainer_into_memory: inflateInit failed for LogContainer");
            }
            ws_debug("inflateInit failed for LogContainer");
            if (infstream.msg != NULL) {
                ws_debug("inflateInit returned: \"%s\"", infstream.msg);
            }
            return false;
        }

        int ret = ZLIB_PREFIX(inflate)(&infstream, Z_NO_FLUSH);
        /* Z_OK should not happen here since we know how big the buffer should be */
        if (Z_STREAM_END != ret) {
            switch (ret) {

            case Z_NEED_DICT:
                *err = WTAP_ERR_DECOMPRESS;
                *err_info = ws_strdup("preset dictionary needed");
                break;

            case Z_STREAM_ERROR:
                *err = WTAP_ERR_INTERNAL;
                *err_info = ws_strdup_printf("blf_pull_logcontainer_into_memory: Z_STREAM_ERROR from inflate(), message \"%s\"",
                                             (infstream.msg != NULL) ? infstream.msg : "(none)");
                break;

            case Z_MEM_ERROR:
                /* This means "not enough memory". */
                *err = ENOMEM;
                *err_info = NULL;
                break;

            case Z_DATA_ERROR:
                /* This means "deflate stream invalid" */
                *err = WTAP_ERR_DECOMPRESS;
                *err_info = (infstream.msg != NULL) ? ws_strdup(infstream.msg) : NULL;
                break;

            case Z_BUF_ERROR:
                /* XXX - this is recoverable; what should we do here? */
                *err = WTAP_ERR_INTERNAL;
                *err_info = ws_strdup_printf("blf_pull_logcontainer_into_memory: Z_BUF_ERROR from inflate(), message \"%s\"",
                                             (infstream.msg != NULL) ? infstream.msg : "(none)");
                break;

            case Z_VERSION_ERROR:
                *err = WTAP_ERR_INTERNAL;
                *err_info = ws_strdup_printf("blf_pull_logcontainer_into_memory: Z_VERSION_ERROR from inflate(), message \"%s\"",
                                             (infstream.msg != NULL) ? infstream.msg : "(none)");
                break;

            default:
                *err = WTAP_ERR_INTERNAL;
                *err_info = ws_strdup_printf("blf_pull_logcontainer_into_memory: unexpected error %d from inflate(), message \"%s\"",
                                             ret,
                                             (infstream.msg != NULL) ? infstream.msg : "(none)");
                break;
            }
            g_free(buf);
            g_free(compressed_data);
            ws_debug("inflate failed (return code %d) for LogContainer", ret);
            if (infstream.msg != NULL) {
                ws_debug("inflate returned: \"%s\"", infstream.msg);
            }
            /* Free up any dynamically-allocated memory in infstream */
            ZLIB_PREFIX(inflateEnd)(&infstream);
            return false;
        }

        if (Z_OK != ZLIB_PREFIX(inflateEnd)(&infstream)) {
            /*
             * The zlib manual says this only returns Z_OK on success
             * and Z_STREAM_ERROR if the stream state was inconsistent.
             *
             * It's not clear what useful information can be reported
             * for Z_STREAM_ERROR; a look at the 1.2.11 source indicates
             * that no string is returned to indicate what the problem
             * was.
             *
             * It's also not clear what to do about infstream if this
             * fails.
             */
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup("blf_pull_logcontainer_into_memory: inflateEnd failed for LogContainer");
            g_free(buf);
            g_free(compressed_data);
            ws_debug("inflateEnd failed for LogContainer");
            if (infstream.msg != NULL) {
                ws_debug("inflateEnd returned: \"%s\"", infstream.msg);
            }
            return false;
        }

        g_free(compressed_data);
        container->real_data = buf;
        return true;
#else /* USE_ZLIB_OR_ZLIBNG */
        (void) params;
        *err = WTAP_ERR_DECOMPRESSION_NOT_SUPPORTED;
        *err_info = ws_strdup("blf_pull_logcontainer_into_memory: reading gzip-compressed containers isn't supported");
        return false;
#endif /* USE_ZLIB_OR_ZLIBNG */
    }

    return false;
}

/** Finds the next log container starting at the current file offset
 *
 * Adds the container to the containers array for later access
 */
static bool
blf_find_next_logcontainer(blf_params_t* params, int* err, char** err_info) {
    blf_blockheader_t           header;
    blf_logcontainerheader_t    logcontainer_header;
    blf_log_container_t         tmp;
    unsigned char*              header_ptr;
    unsigned int                i;

    uint64_t current_real_start;
    if (params->blf_data->log_containers->len == 0) {
        current_real_start = 0;
    } else {
        const blf_log_container_t* container = &g_array_index(params->blf_data->log_containers, blf_log_container_t, params->blf_data->log_containers->len - 1);
        current_real_start = container->real_start_pos + container->real_length;
    }

    header_ptr = (unsigned char*)&header;
    i = 0;

    /** Find Object
     *
     * We read one byte at a time so that we don't have to seek backward (allows us to do a linear read)
     */
    while (i < sizeof(blf_obj_magic)) {
        if (!wtap_read_bytes_or_eof(params->fh, &header_ptr[i], 1, err, err_info)) {
            ws_debug("we found end of file");
            return false;
        }
        if (header_ptr[i] != blf_obj_magic[i]) {
            if (params->pipe) {
                ws_debug("container object magic is not LOBJ");
            } else {
                ws_debug("container object magic is not LOBJ (pos: 0x%" PRIx64 ")", file_tell(params->fh) - 1);
            }
            if (i > 0) {
                int j = i;

                while (memcmp(&header_ptr[i - j + 1], blf_obj_magic, j)) {
                    /* Check if the last j bytes match the first j bytes of the magic */
                    j--;
                }

                /* The last j bytes match, and the first j bytes are already in the buffer, since j<=i */
                i = j;
            }
        } else {
            /* Character matches */
            i++;
        }
    }

    if (!wtap_read_bytes_or_eof(params->fh, &header.header_length, sizeof(blf_blockheader_t) - sizeof(blf_obj_magic), err, err_info)) {
        ws_debug("we found end of file");
        return false;
    }

    fix_endianness_blf_blockheader(&header);

    if (header.header_length < sizeof(blf_blockheader_t)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: header length too short while looking for object");
        return false;
    }

    if (header.header_type != BLF_HEADER_TYPE_DEFAULT) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = ws_strdup_printf("blf: unknown header type (%u), I know only BLF_HEADER_TYPE_DEFAULT (1)", header.header_type);
        return false;
    }

    if (header.object_length < header.header_length) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: header object length less than header length while looking for objects");
        return false;
    }

    if (header.object_type == BLF_OBJTYPE_LOG_CONTAINER) {
        /* skip unknown header part if needed */
        if (header.header_length > sizeof(blf_blockheader_t)) {
            /* seek over unknown header part */
            if (!wtap_read_bytes(params->fh, NULL, header.header_length - sizeof(blf_blockheader_t), err, err_info)) {
                ws_debug("error skipping unknown header bytes in log container");
                return false;
            }
        }

        /* Read the log container header */
        if (!wtap_read_bytes_or_eof(params->fh, &logcontainer_header, sizeof(blf_logcontainerheader_t), err, err_info)) {
            ws_debug("not enough bytes for log container header");
            return false;
        }

        fix_endianness_blf_logcontainerheader(&logcontainer_header);

        blf_init_logcontainer(&tmp);

        if (params->pipe) {
            tmp.infile_start_pos = 0;
            tmp.infile_data_start = sizeof(blf_logcontainerheader_t) + header.header_length;
        } else {
            tmp.infile_data_start = file_tell(params->fh);
            tmp.infile_start_pos = tmp.infile_data_start - sizeof(blf_logcontainerheader_t) - header.header_length;
        }
        tmp.infile_length = header.object_length;

        tmp.real_start_pos = current_real_start;
        tmp.real_length = logcontainer_header.uncompressed_size;
        tmp.compression_method = logcontainer_header.compression_method;

        ws_debug("found log container with real_pos=0x%" PRIx64 ", real_length=0x%" PRIx64, tmp.real_start_pos, tmp.real_length);
    } else {
        ws_debug("found BLF object without log container");

        /* Create a fake log container for the lone object.
         * In order to avoid seeking backwards, we need to pull the fake log container now.
         */
        unsigned char* buf = g_try_malloc((size_t)header.object_length);
        if (buf == NULL) {
            /*
             * XXX - we need an "out of memory" error code here.
             */
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup("blf_find_next_logcontainer: cannot allocate memory");
            return false;
        }

        memcpy(buf, &header, sizeof(blf_blockheader_t));

        if (header.object_length > sizeof(blf_blockheader_t)) {
            if (!wtap_read_bytes(params->fh, buf + sizeof(blf_blockheader_t), header.object_length - sizeof(blf_blockheader_t), err, err_info)) {
                g_free(buf);
                ws_debug("cannot pull object without log container");
                return false;
            }
        }

        blf_init_logcontainer(&tmp);

        tmp.infile_start_pos = params->pipe ? 0 : (file_tell(params->fh) - header.object_length);
        tmp.infile_data_start = tmp.infile_start_pos;
        tmp.infile_length = header.object_length;

        tmp.real_start_pos = current_real_start;
        tmp.real_length = header.object_length;
        tmp.compression_method = BLF_COMPRESSION_NONE;

        tmp.real_data = buf;

        ws_debug("found non-log-container object with real_pos=0x%" PRIx64 ", real_length=0x%" PRIx64, tmp.real_start_pos, tmp.real_length);
    }

    g_array_append_val(params->blf_data->log_containers, tmp);

    return true;
}

static bool
// NOLINTNEXTLINE(misc-no-recursion)
blf_pull_next_logcontainer(blf_params_t* params, int* err, char** err_info) {
    blf_log_container_t* container;

    if (!blf_find_next_logcontainer(params, err, err_info)) {
        return false;
    }

    /* Is there a next log container to pull? */
    if (params->blf_data->log_containers->len == 0) {
        /* No. */
        return false;
    }

    container = &g_array_index(params->blf_data->log_containers, blf_log_container_t, params->blf_data->log_containers->len - 1);
    if (!blf_pull_logcontainer_into_memory(params, container, err, err_info)) {
        if (*err == WTAP_ERR_DECOMPRESS) {
            report_warning("Error while decompressing BLF log container number %u (file pos. 0x%" PRIx64 "): %s",
                            params->blf_data->log_containers->len - 1, container->infile_start_pos, *err_info ? *err_info : "(none)");
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;

            /* Skip this log container and try to get the next one. */
            g_array_remove_index(params->blf_data->log_containers, params->blf_data->log_containers->len - 1);
            /* Calling blf_pull_logcontainer_into_memory advances the file pointer. Eventually we will reach the end of the file and stop recursing. */
            return blf_pull_next_logcontainer(params, err, err_info);
        }

        return false;
    }

    return true;
}

static bool
blf_read_bytes_or_eof(blf_params_t *params, uint64_t real_pos, void *target_buffer, uint64_t count, int *err, char **err_info) {
    blf_log_container_t*    container;
    unsigned container_index;

    uint64_t end_pos = real_pos + count;

    uint64_t copied = 0;
    uint64_t data_left;
    uint64_t start_in_buf;

    unsigned char *buf = (unsigned char *)target_buffer;

    if (count == 0) {
        ws_debug("called blf_read_bytes_or_eof with 0 count");
        return false;
    }

    if (count > UINT32_MAX) {
        ws_debug("trying to read too many bytes");
        return false;
    }

    if (params->random) {
        /*
         * Do a binary search for the container in which real_pos
         * is included.
         */
        if (!g_array_binary_search(params->blf_data->log_containers, &real_pos, blf_logcontainers_search, &container_index)) {
            /*
             * XXX - why is this treated as an EOF rather than an error?
             * *err appears to be 0, which means our caller treats it as an
             * EOF, at least when reading the log object header.
             */
            ws_debug("cannot read data because start position cannot be mapped");
            return false;
        }
        container = &g_array_index(params->blf_data->log_containers, blf_log_container_t, container_index);
    } else {
        if (params->blf_data->log_containers->len == 0) {
            /*
             * This is the first (linear) pass, and we haven't yet
             * added any containers.  Pull the next log container
             * into memory, so that the array isn't empty.
             */
            if (!blf_pull_next_logcontainer(params, err, err_info)) {
                return false;
            }
        }

        /*
         * Search backwards in the array, from the last entry to the
         * first, to find the log container in which real_pos is
         * included.
         */
        container_index = params->blf_data->log_containers->len;
        do {
            container = &g_array_index(params->blf_data->log_containers, blf_log_container_t, --container_index);
        } while (real_pos < container->real_start_pos && container_index > 0);  /* For some reason we skipped past the correct container */
    }

    while (real_pos < end_pos) {

        while (real_pos >= container->real_start_pos + container->real_length) {
            container_index++;
            if (!params->random) {  /* First (linear) pass */
                if (!blf_pull_next_logcontainer(params, err, err_info)) {
                    return false;
                }
            }
            if (container_index >= params->blf_data->log_containers->len) {
                ws_debug("cannot find real_pos in container");
                return false;
            }
            container = &g_array_index(params->blf_data->log_containers, blf_log_container_t, container_index);
            if (real_pos < container->real_start_pos) {
                ws_debug("cannot find real_pos in container");
                return false;
            }
        }

        if (real_pos < container->real_start_pos) {
            ws_debug("cannot find real_pos in container");
            return false;
        }

        start_in_buf = real_pos - container->real_start_pos;

        if (params->random) {
            if (file_seek(params->fh, container->infile_data_start, SEEK_SET, err) == -1) {
                return false;
            }
            if (!blf_pull_logcontainer_into_memory(params, container, err, err_info)) {
                return false;
            }
        }

        data_left = container->real_length - start_in_buf;

        if (data_left < (count - copied)) {
            memcpy(buf + copied, container->real_data + start_in_buf, data_left);
            copied += data_left;
            real_pos += data_left;
        } else {
            memcpy(buf + copied, container->real_data + start_in_buf, count - copied);
            return true;
        }

    }

    /*
     * XXX - does this represent a bug (WTAP_ERR_INTERNAL) or a
     * malformed file (WTAP_ERR_BAD_FILE)?
     */
    *err = WTAP_ERR_INTERNAL;
    *err_info = ws_strdup("blf_read_bytes_or_eof: ran out of containers");
    return false;
}

static bool
blf_read_bytes(blf_params_t *params, uint64_t real_pos, void *target_buffer, uint64_t count, int *err, char **err_info) {
    if (!blf_read_bytes_or_eof(params, real_pos, target_buffer, count, err, err_info)) {
        if (*err == 0) {
            *err = WTAP_ERR_SHORT_READ;
        }
        return false;
    }
    return true;
}

static void
blf_init_rec(blf_params_t *params, uint32_t flags, uint64_t object_timestamp, int pkt_encap, uint16_t channel, uint16_t hwchannel, unsigned caplen, unsigned len) {
    wtap_setup_packet_rec(params->rec, pkt_encap);
    params->rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    params->rec->presence_flags = WTAP_HAS_CAP_LEN | WTAP_HAS_INTERFACE_ID;
    switch (flags) {
    case BLF_TIMESTAMP_RESOLUTION_10US:
        params->rec->presence_flags |= WTAP_HAS_TS;
        params->rec->tsprec = WTAP_TSPREC_10_USEC;
        object_timestamp *= 10000;
        object_timestamp += params->blf_data->start_offset_ns;
        break;

    case BLF_TIMESTAMP_RESOLUTION_1NS:
        params->rec->presence_flags |= WTAP_HAS_TS;
        params->rec->tsprec = WTAP_TSPREC_NSEC;
        object_timestamp += params->blf_data->start_offset_ns;
        break;

    default:
        /* Metadata objects have both flags and timestamp equal to zero, so that combination is not an error. */
        if (flags != 0 || object_timestamp != 0) {
            /*
             * XXX - report this as an error?
             *
             * Or provide a mechanism to allow file readers to report
             * a warning (an error that the reader tries to work
             * around and that the caller should report)?
             */
            ws_debug("Unknown combination of flags and timestamp (0x%x, %" PRIu64 ")", flags, object_timestamp);
            object_timestamp = 0;
        }
        break;
    }
    params->rec->ts.secs = object_timestamp / (1000 * 1000 * 1000);
    params->rec->ts.nsecs = object_timestamp % (1000 * 1000 * 1000);
    params->rec->rec_header.packet_header.caplen = caplen;
    params->rec->rec_header.packet_header.len = len;

    params->rec->rec_header.packet_header.interface_id = blf_lookup_interface(params, pkt_encap, channel, hwchannel, NULL);

    /* TODO: before we had to remove comments and verdict here to not leak memory but APIs have changed ... */
}

static void
blf_add_direction_option(blf_params_t *params, uint16_t direction) {
    uint32_t tmp = PACK_FLAGS_DIRECTION_INBOUND; /* don't care */

    switch (direction) {
    case BLF_DIR_RX:
        tmp = PACK_FLAGS_DIRECTION_INBOUND; /* inbound */
        break;
    case BLF_DIR_TX:
    case BLF_DIR_TX_RQ:
        tmp = PACK_FLAGS_DIRECTION_OUTBOUND; /* outbound */
        break;
    }

    wtap_block_add_uint32_option(params->rec->block, OPT_PKT_FLAGS, tmp);
}

static bool
blf_read_log_object_header(blf_params_t *params, int *err, char **err_info, int64_t header2_start, int64_t data_start, blf_logobjectheader_t *logheader) {
    if (data_start - header2_start < (int64_t)sizeof(blf_logobjectheader_t)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: not enough bytes for log object header");
        ws_debug("not enough bytes for timestamp header");
        return false;
    }

    if (!blf_read_bytes_or_eof(params, header2_start, logheader, sizeof(*logheader), err, err_info)) {
        ws_debug("not enough bytes for logheader");
        return false;
    }
    fix_endianness_blf_logobjectheader(logheader);
    return true;
}

static bool
blf_read_log_object_header2(blf_params_t *params, int *err, char **err_info, int64_t header2_start, int64_t data_start, blf_logobjectheader2_t *logheader) {
    if (data_start - header2_start < (int64_t)sizeof(blf_logobjectheader2_t)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: not enough bytes for log object header");
        ws_debug("not enough bytes for timestamp header");
        return false;
    }

    if (!blf_read_bytes_or_eof(params, header2_start, logheader, sizeof(*logheader), err, err_info)) {
        ws_debug("not enough bytes for logheader");
        return false;
    }
    fix_endianness_blf_logobjectheader2(logheader);
    return true;
}

static bool
blf_read_log_object_header3(blf_params_t *params, int *err, char **err_info, int64_t header2_start, int64_t data_start, blf_logobjectheader3_t *logheader) {
    if (data_start - header2_start < (int64_t)sizeof(blf_logobjectheader3_t)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: not enough bytes for log object header");
        ws_debug("not enough bytes for timestamp header");
        return false;
    }

    if (!blf_read_bytes_or_eof(params, header2_start, logheader, sizeof(*logheader), err, err_info)) {
        ws_debug("not enough bytes for logheader");
        return false;
    }
    fix_endianness_blf_logobjectheader3(logheader);
    return true;
}

static bool
blf_read_ethernetframe(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_ethernetframeheader_t ethheader;
    uint8_t tmpbuf[18];
    unsigned caplen, len;

    if (object_length < (data_start - block_start) + (int) sizeof(blf_ethernetframeheader_t)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: ETHERNET_FRAME: not enough bytes for ethernet frame header in object");
        ws_debug("not enough bytes for ethernet frame header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &ethheader, sizeof(ethheader), err, err_info)) {
        ws_debug("not enough bytes for ethernet frame header in file");
        return false;
    }
    fix_endianness_blf_ethernetframeheader(&ethheader);

    /*
     * BLF breaks up and reorders the Ethernet header and VLAN tag fields.
     * This is a really bad design and makes this format one of the worst.
     * If you want a fast format that keeps your data intact, avoid this format!
     * So, lets hope we can reconstruct the original packet successfully.
     */

    tmpbuf[0] = ethheader.dst_addr[0];
    tmpbuf[1] = ethheader.dst_addr[1];
    tmpbuf[2] = ethheader.dst_addr[2];
    tmpbuf[3] = ethheader.dst_addr[3];
    tmpbuf[4] = ethheader.dst_addr[4];
    tmpbuf[5] = ethheader.dst_addr[5];

    tmpbuf[6] = ethheader.src_addr[0];
    tmpbuf[7] = ethheader.src_addr[1];
    tmpbuf[8] = ethheader.src_addr[2];
    tmpbuf[9] = ethheader.src_addr[3];
    tmpbuf[10] = ethheader.src_addr[4];
    tmpbuf[11] = ethheader.src_addr[5];

    if (ethheader.tpid != 0 && ethheader.tci != 0) {
        phtonu16(tmpbuf + 12, ethheader.tpid);
        phtonu16(tmpbuf + 14, ethheader.tci);
        phtonu16(tmpbuf + 16, ethheader.ethtype);
        ws_buffer_assure_space(&params->rec->data, (size_t)18 + ethheader.payloadlength);
        ws_buffer_append(&params->rec->data, tmpbuf, (size_t)18);
        caplen = ((uint32_t)18 + ethheader.payloadlength);
        len = ((uint32_t)18 + ethheader.payloadlength);
    } else {
        phtonu16(tmpbuf + 12, ethheader.ethtype);
        ws_buffer_assure_space(&params->rec->data, (size_t)14 + ethheader.payloadlength);
        ws_buffer_append(&params->rec->data, tmpbuf, (size_t)14);
        caplen = ((uint32_t)14 + ethheader.payloadlength);
        len = ((uint32_t)14 + ethheader.payloadlength);
    }

    if (!blf_read_bytes(params, data_start + sizeof(blf_ethernetframeheader_t), ws_buffer_end_ptr(&params->rec->data), ethheader.payloadlength, err, err_info)) {
        ws_debug("copying ethernet frame failed");
        return false;
    }
    ws_buffer_increase_length(&params->rec->data, ethheader.payloadlength);

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_ETHERNET, ethheader.channel, UINT16_MAX, caplen, len);
    blf_add_direction_option(params, ethheader.direction);

    return true;
}

static bool
blf_read_ethernetframe_ext(blf_params_t *params, int *err, char **err_info, int64_t block_start,int64_t data_start,
                            int64_t object_length, uint32_t flags, uint64_t object_timestamp, gboolean error) {
    blf_ethernetframeheader_ex_t ethheader;

    if (object_length < (data_start - block_start) + (int) sizeof(blf_ethernetframeheader_ex_t)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: %s: not enough bytes for ethernet frame header in object", error ? "ETHERNET_ERROR_EX" : "ETHERNET_FRAME_EX");
        ws_debug("not enough bytes for ethernet frame header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &ethheader, sizeof(blf_ethernetframeheader_ex_t), err, err_info)) {
        ws_debug("not enough bytes for ethernet frame header in file");
        return false;
    }
    fix_endianness_blf_ethernetframeheader_ex(&ethheader);

    if (object_length - (data_start - block_start) - sizeof(blf_ethernetframeheader_ex_t) < ethheader.frame_length) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: %s: frame too short", error ? "ETHERNET_ERROR_EX" : "ETHERNET_FRAME_EX");
        ws_debug("frame too short");
        return false;
    }

    ws_buffer_assure_space(&params->rec->data, ethheader.frame_length);

    if (!blf_read_bytes(params, data_start + sizeof(blf_ethernetframeheader_ex_t), ws_buffer_end_ptr(&params->rec->data), ethheader.frame_length, err, err_info)) {
        ws_debug("copying ethernet frame failed");
        return false;
    }
    ws_buffer_increase_length(&params->rec->data, ethheader.frame_length);

    if (ethheader.flags & BLF_ETHERNET_EX_HARDWARECHANNEL) {
        blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_ETHERNET, ethheader.channel, ethheader.hw_channel, ethheader.frame_length, ethheader.frame_length);
        wtap_block_add_uint32_option(params->rec->block, OPT_PKT_QUEUE, ethheader.hw_channel);
    } else {
        blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_ETHERNET, ethheader.channel, UINT16_MAX, ethheader.frame_length, ethheader.frame_length);
    }

    blf_add_direction_option(params, ethheader.direction);

    return true;
}

static bool
blf_read_ethernet_rxerror(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_ethernet_rxerror_t ethheader;

    if (object_length < (data_start - block_start) + (int)sizeof(blf_ethernet_rxerror_t)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: ETHERNET_RXERROR: not enough bytes for ethernet frame header in object");
        ws_debug("not enough bytes for ethernet rx error header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &ethheader, sizeof(blf_ethernet_rxerror_t), err, err_info)) {
        ws_debug("not enough bytes for ethernet rx error header in file");
        return false;
    }
    fix_endianness_blf_ethernet_rxerror(&ethheader);

    if (object_length - (data_start - block_start) < ethheader.frame_length) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: ETHERNET_RXERROR: frame too short");
        ws_debug("frame too short");
        return false;
    }

    ws_buffer_assure_space(&params->rec->data, ethheader.frame_length);

    if (!blf_read_bytes(params, data_start + sizeof(blf_ethernet_rxerror_t), ws_buffer_end_ptr(&params->rec->data), ethheader.frame_length, err, err_info)) {
        ws_debug("copying ethernet rx error failed");
        return false;
    }
    ws_buffer_increase_length(&params->rec->data, ethheader.frame_length);

    if (ethheader.hw_channel != 0) {    /* In this object type, a value of 0 is considered invalid. */
        blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_ETHERNET, ethheader.channel, ethheader.hw_channel, ethheader.frame_length, ethheader.frame_length);
        wtap_block_add_uint32_option(params->rec->block, OPT_PKT_QUEUE, ethheader.hw_channel);
    } else {
        blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_ETHERNET, ethheader.channel, UINT16_MAX, ethheader.frame_length, ethheader.frame_length);
    }
    blf_add_direction_option(params, ethheader.direction);

    return true;
}

/*
 * XXX - provide radio information to our caller in the pseudo-header.
 */
static bool
blf_read_wlanframe(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_wlanframeheader_t wlanheader;

    if (object_length < (data_start - block_start) + (int)sizeof(blf_wlanframeheader_t)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: WLAN_FRAME: not enough bytes for wlan frame header in object");
        ws_debug("not enough bytes for wlan frame header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &wlanheader, sizeof(blf_wlanframeheader_t), err, err_info)) {
        ws_debug("not enough bytes for wlan frame header in file");
        return false;
    }
    fix_endianness_blf_wlanframeheader(&wlanheader);

    if (object_length - (data_start - block_start) - sizeof(blf_wlanframeheader_t) < wlanheader.frame_length) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: WLAN_FRAME: frame too short");
        ws_debug("frame too short");
        return false;
    }

    ws_buffer_assure_space(&params->rec->data, wlanheader.frame_length);

    if (!blf_read_bytes(params, data_start + sizeof(blf_wlanframeheader_t), ws_buffer_end_ptr(&params->rec->data), wlanheader.frame_length, err, err_info)) {
        ws_debug("copying wlan frame failed");
        return false;
    }
    ws_buffer_increase_length(&params->rec->data, wlanheader.frame_length);

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_IEEE_802_11, wlanheader.channel, UINT16_MAX, wlanheader.frame_length, wlanheader.frame_length);
    blf_add_direction_option(params, wlanheader.direction);

    return true;
}

static const uint8_t can_dlc_to_length[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8 };
static const uint8_t canfd_dlc_to_length[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64 };

static bool
blf_can_fill_buf_and_rec(blf_params_t *params, int *err, char **err_info, uint32_t canid, uint8_t payload_length, uint8_t payload_length_valid, uint64_t start_position,
                         uint32_t flags, uint64_t object_timestamp, uint16_t channel, uint8_t canfd_flags) {
    uint8_t  tmpbuf[8];
    unsigned caplen, len;

    phtonu32(tmpbuf, canid);
    tmpbuf[4] = payload_length;
    tmpbuf[5] = canfd_flags;
    tmpbuf[6] = 0;
    tmpbuf[7] = 0;

    ws_buffer_assure_space(&params->rec->data, sizeof(tmpbuf) + payload_length_valid);
    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));
    caplen = sizeof(tmpbuf) + payload_length_valid;
    len = sizeof(tmpbuf) + payload_length;

    if (payload_length_valid > 0 && !blf_read_bytes(params, start_position, ws_buffer_end_ptr(&params->rec->data), payload_length_valid, err, err_info)) {
        ws_debug("copying can payload failed");
        return false;
    }
    ws_buffer_increase_length(&params->rec->data, payload_length_valid);

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_SOCKETCAN, channel, UINT16_MAX, caplen, len);

    return true;
}

static bool
blf_read_canmessage(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp, bool can_message2) {
    blf_canmessage_t canheader;
    blf_canmessage2_trailer_t can2trailer;

    uint32_t canid;
    uint8_t  payload_length;

    if (object_length < (data_start - block_start) + (int) sizeof(canheader)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: %s: not enough bytes for can header in object",
                                    can_message2 ? "CAN_MESSAGE2" : "CAN_MESSAGE");
        ws_debug("not enough bytes for can header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &canheader, sizeof(canheader), err, err_info)) {
        ws_debug("not enough bytes for can header in file");
        return false;
    }
    fix_endianness_blf_canmessage(&canheader);

    canheader.dlc &= 0x0f;

    payload_length = canheader.dlc;
    if (payload_length > 8) {
        ws_debug("regular CAN tries more than 8 bytes? Cutting to 8!");
        payload_length = 8;
    }

    canid = canheader.id;

    if ((canheader.flags & BLF_CANMESSAGE_FLAG_RTR) == BLF_CANMESSAGE_FLAG_RTR) {
        canid |= CAN_RTR_FLAG;
        payload_length = 0;
    }

    if (!blf_can_fill_buf_and_rec(params, err, err_info, canid, payload_length, payload_length, data_start + sizeof(canheader), flags, object_timestamp, canheader.channel, 0)) {
        return false;
    }

    /* actually, we do not really need the data, right now.... */
    if (can_message2) {
        if (object_length < (data_start - block_start) + (int) sizeof(canheader) + 8 + (int) sizeof(can2trailer)) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup("blf: CAN_MESSAGE2: not enough bytes for can message 2 trailer");
            ws_debug("not enough bytes for can message 2 trailer");
            return false;
        }
        if (!blf_read_bytes(params, data_start + sizeof(canheader) + 8, &can2trailer, sizeof(can2trailer), err, err_info)) {
            ws_debug("not enough bytes for can message 2 trailer in file");
            return false;
        }
        fix_endianness_blf_canmessage2_trailer(&can2trailer);
    }

    blf_add_direction_option(params, (canheader.flags & BLF_CANMESSAGE_FLAG_TX) == BLF_CANMESSAGE_FLAG_TX ? BLF_DIR_TX: BLF_DIR_RX);

    return true;
}

static bool
blf_read_canfdmessage(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_canfdmessage_t canheader;

    bool     canfd;
    uint32_t canid;
    uint8_t  payload_length;
    uint8_t  payload_length_valid;
    uint8_t  canfd_flags;

    if (object_length < (data_start - block_start) + (int) sizeof(canheader)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: CAN_FD_MESSAGE: not enough bytes for canfd header in object");
        ws_debug("not enough bytes for canfd header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &canheader, sizeof(canheader), err, err_info)) {
        ws_debug("not enough bytes for canfd header in file");
        return false;
    }
    fix_endianness_blf_canfdmessage(&canheader);

    canheader.dlc &= 0x0f;

    canfd = (canheader.canfdflags & BLF_CANFDMESSAGE_CANFDFLAG_EDL) == BLF_CANFDMESSAGE_CANFDFLAG_EDL;
    if (canfd) {
        payload_length = canfd_dlc_to_length[canheader.dlc];
        canfd_flags = (canheader.canfdflags & BLF_CANFDMESSAGE_CANFDFLAG_EDL) << 2 | (canheader.canfdflags & BLF_CANFDMESSAGE_CANFDFLAG_ESI) >> 1 | (canheader.canfdflags & BLF_CANFDMESSAGE_CANFDFLAG_BRS) >> 1;
    } else {
        if (canheader.dlc > 8) {
            ws_debug("regular CAN tries more than 8 bytes?");
        }
        payload_length = can_dlc_to_length[canheader.dlc];
        canfd_flags = 0;
    }

    if (payload_length > canheader.validDataBytes) {
        ws_debug("shortening canfd payload because valid data bytes shorter!");
        payload_length = canheader.validDataBytes;
    }

    canid = canheader.id;

    if (!canfd && (canheader.flags & BLF_CANMESSAGE_FLAG_RTR) == BLF_CANMESSAGE_FLAG_RTR) {
        canid |= CAN_RTR_FLAG;
        payload_length = 0; /* Should already be zero from validDataBytes */
    }

    payload_length_valid = payload_length;

    if (payload_length_valid > object_length - (data_start - block_start) + sizeof(canheader)) {
        ws_debug("shortening can payload because buffer is too short!");
        payload_length_valid = (uint8_t)(object_length - (data_start - block_start));
    }

    if (!blf_can_fill_buf_and_rec(params, err, err_info, canid, payload_length, payload_length_valid, data_start + sizeof(canheader), flags, object_timestamp, canheader.channel, canfd_flags)) {
        return false;
    }

    blf_add_direction_option(params, (canheader.flags & BLF_CANMESSAGE_FLAG_TX) == BLF_CANMESSAGE_FLAG_TX ? BLF_DIR_TX : BLF_DIR_RX);

    return true;
}

static bool
blf_read_canfdmessage64(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_canfdmessage64_t canheader;

    bool     canfd;
    uint32_t canid;
    uint8_t  payload_length;
    uint8_t  payload_length_valid;
    uint8_t  canfd_flags;

    if (object_length < (data_start - block_start) + (int) sizeof(canheader)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: CAN_FD_MESSAGE_64: not enough bytes for canfd header in object");
        ws_debug("not enough bytes for canfd header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &canheader, sizeof(canheader), err, err_info)) {
        ws_debug("not enough bytes for canfd header in file");
        return false;
    }
    fix_endianness_blf_canfdmessage64(&canheader);

    canheader.dlc &= 0x0f;

    canfd = (canheader.flags & BLF_CANFDMESSAGE64_FLAG_EDL) == BLF_CANFDMESSAGE64_FLAG_EDL;
    if (canfd) {
        payload_length = canfd_dlc_to_length[canheader.dlc];
        canfd_flags = (canheader.flags & BLF_CANFDMESSAGE64_FLAG_EDL) >> 10 | (canheader.flags & BLF_CANFDMESSAGE64_FLAG_ESI) >> 13 | (canheader.flags & BLF_CANFDMESSAGE64_FLAG_BRS) >> 13;
    } else {
        if (canheader.dlc > 8) {
            ws_debug("regular CAN tries more than 8 bytes?");
        }
        payload_length = can_dlc_to_length[canheader.dlc];
        canfd_flags = 0;
    }

    if (payload_length > canheader.validDataBytes) {
        ws_debug("shortening canfd payload because valid data bytes shorter!");
        payload_length = canheader.validDataBytes;
    }

    canid = canheader.id;

    if (!canfd && (canheader.flags & BLF_CANFDMESSAGE64_FLAG_REMOTE_FRAME) == BLF_CANFDMESSAGE64_FLAG_REMOTE_FRAME) {
        canid |= CAN_RTR_FLAG;
        payload_length = 0; /* Should already be zero from validDataBytes */
    }

    payload_length_valid = payload_length;

    if (payload_length_valid > object_length - (data_start - block_start)) {
        ws_debug("shortening can payload because buffer is too short!");
        payload_length_valid = (uint8_t)(object_length - (data_start - block_start));
    }

    if (!blf_can_fill_buf_and_rec(params, err, err_info, canid, payload_length, payload_length_valid, data_start + sizeof(canheader), flags, object_timestamp, canheader.channel, canfd_flags)) {
        return false;
    }

    blf_add_direction_option(params, canheader.dir);

    return true;
}

static bool
blf_read_canerror(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp, bool overload) {
    blf_canerror_t canheader;
    uint32_t canid;
    uint8_t  payload_length;
    uint8_t  tmpbuf[16] = {0};

    if (object_length < (data_start - block_start) + (int) sizeof(canheader)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: CAN_ERROR: not enough bytes for canerror header in object");
        ws_debug("not enough bytes for canerror header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &canheader, sizeof(canheader), err, err_info)) {
        ws_debug("not enough bytes for canerror header in file");
        return false;
    }
    fix_endianness_blf_canerror(&canheader);

    // Set CAN_ERR_FLAG in unused bits of Can ID to indicate error in socketcan
    canid = CAN_ERR_FLAG;

    // Fixed packet data length for socketcan error messages
    payload_length = CAN_ERR_DLC;

    if (overload) {
        tmpbuf[10] = CAN_ERR_PROT_OVERLOAD;
        canid |= CAN_ERR_PROT;
    }

    phtonu32(tmpbuf, canid);
    tmpbuf[4] = payload_length;

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_SOCKETCAN, canheader.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));
    return true;
}

static bool
blf_read_canerrorext(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_canerrorext_t canheader;

    bool     err_ack = false;
    bool     err_prot = false;
    bool     direction_tx;
    uint32_t canid;
    uint8_t  payload_length;
    uint8_t  tmpbuf[16] = {0};

    if (object_length < (data_start - block_start) + (int) sizeof(canheader)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: CAN_ERROR_EXT: not enough bytes for canerrorext header in object");
        ws_debug("not enough bytes for canerrorext header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &canheader, sizeof(canheader), err, err_info)) {
        ws_debug("not enough bytes for canerrorext header in file");
        return false;
    }
    fix_endianness_blf_canerrorext(&canheader);

    if (canheader.flags & BLF_CANERROREXT_FLAG_CANCORE) {
        // Map Vector Can Core error codes to compareable socketcan errors
        switch ((canheader.errorCodeExt >> 6) & 0x3f) {
        case BLF_CANERROREXT_ECC_MEANING_BIT_ERROR:
            err_prot = true;
            tmpbuf[10] = CAN_ERR_PROT_BIT;
            break;
        case BLF_CANERROREXT_ECC_MEANING_FORM_ERROR:
            err_prot = true;
            tmpbuf[10] = CAN_ERR_PROT_FORM;
            break;
        case BLF_CANERROREXT_ECC_MEANING_STUFF_ERROR:
            err_prot = true;
            tmpbuf[10] = CAN_ERR_PROT_STUFF;
            break;
        case BLF_CANERROREXT_ECC_MEANING_CRC_ERROR:
            err_prot = true;
            tmpbuf[11] = CAN_ERR_PROT_LOC_CRC_SEQ;
            break;
        case BLF_CANERROREXT_ECC_MEANING_NACK_ERROR:
            err_ack = true;
            tmpbuf[11] = CAN_ERR_PROT_LOC_ACK;
            break;
        case BLF_CANERROREXT_ECC_MEANING_OVERLOAD:
            err_prot = true;
            tmpbuf[10] = CAN_ERR_PROT_OVERLOAD;
            break;
        default:
            err_prot = true;
            tmpbuf[10] = CAN_ERR_PROT_UNSPEC;
            break;
        }
        err_ack = err_ack || (canheader.errorCodeExt & BLF_CANERROREXT_EXTECC_NOT_ACK) == 0x0;
        if (err_ack) {
            // Don't set protocol error on ack errors
            err_prot = false;
        }
    }

    // CanID contains error class in socketcan
    canid = CAN_ERR_FLAG;
    canid |= err_prot ? CAN_ERR_PROT : 0;
    canid |= err_ack ? CAN_ERR_ACK : 0;

    // Fixed packet data length for socketcan error messages
    payload_length = CAN_ERR_DLC;
    canheader.dlc = payload_length;

    phtonu32(tmpbuf, canid);
    tmpbuf[4] = payload_length;

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_SOCKETCAN, canheader.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));
    if (canheader.flags & BLF_CANERROREXT_FLAG_CANCORE) {
        direction_tx = (canheader.errorCodeExt & BLF_CANERROREXT_EXTECC_TX) == BLF_CANERROREXT_EXTECC_TX;
        blf_add_direction_option(params, direction_tx ? BLF_DIR_TX: BLF_DIR_RX);
    }
    return true;
}

static bool
blf_read_canfderror64(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_canfderror64_t canheader;

    bool     err_ack = false;
    bool     err_prot = false;
    bool     direction_tx;
    uint32_t canid;
    uint8_t  payload_length;
    uint8_t  tmpbuf[16] = {0};

    if (object_length < (data_start - block_start) + (int) sizeof(canheader)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: CAN_FD_ERROR_64: not enough bytes for canfderror header in object");
        ws_debug("not enough bytes for canfderror header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &canheader, sizeof(canheader), err, err_info)) {
        ws_debug("not enough bytes for canfderror header in file");
        return false;
    }
    fix_endianness_blf_canfderror64(&canheader);

    if (canheader.flags & BLF_CANERROREXT_FLAG_CANCORE) {
        // Map Vector Can Core error codes to compareable socketcan errors
        switch ((canheader.errorCodeExt >> 6) & 0x3f) {
        case BLF_CANERROREXT_ECC_MEANING_BIT_ERROR:
            err_prot = true;
            tmpbuf[10] = CAN_ERR_PROT_BIT;
            break;
        case BLF_CANERROREXT_ECC_MEANING_FORM_ERROR:
            err_prot = true;
            tmpbuf[10] = CAN_ERR_PROT_FORM;
            break;
        case BLF_CANERROREXT_ECC_MEANING_STUFF_ERROR:
            err_prot = true;
            tmpbuf[10] = CAN_ERR_PROT_STUFF;
            break;
        case BLF_CANERROREXT_ECC_MEANING_CRC_ERROR:
            err_prot = true;
            tmpbuf[11] = CAN_ERR_PROT_LOC_CRC_SEQ;
            break;
        case BLF_CANERROREXT_ECC_MEANING_NACK_ERROR:
            err_ack = true;
            tmpbuf[11] = CAN_ERR_PROT_LOC_ACK;
            break;
        case BLF_CANERROREXT_ECC_MEANING_OVERLOAD:
            err_prot = true;
            tmpbuf[10] = CAN_ERR_PROT_OVERLOAD;
            break;
        default:
            err_prot = true;
            tmpbuf[10] = CAN_ERR_PROT_UNSPEC;
            break;
        }
        err_ack = err_ack || (canheader.errorCodeExt & BLF_CANERROREXT_EXTECC_NOT_ACK) == 0x0;
        if (err_ack) {
            // Don't set protocol error on ack errors
            err_prot = false;
        }
    }

    // CanID contains error class in socketcan
    canid = CAN_ERR_FLAG;
    canid |= err_prot ? CAN_ERR_PROT : 0;
    canid |= err_ack ? CAN_ERR_ACK : 0;

    // Fixed packet data length for socketcan error messages
    payload_length = CAN_ERR_DLC;
    canheader.dlc = payload_length;

    phtonu32(tmpbuf, canid);
    tmpbuf[4] = payload_length;
    // Don't set FDF, ESI and BRS flags, since error messages are always encapsulated in Classic CAN frames

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_SOCKETCAN, canheader.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));
    if (canheader.flags & BLF_CANERROREXT_FLAG_CANCORE) {
        direction_tx = (canheader.errorCodeExt & BLF_CANERROREXT_EXTECC_TX) == BLF_CANERROREXT_EXTECC_TX;
        blf_add_direction_option(params, direction_tx ? BLF_DIR_TX: BLF_DIR_RX);
    }
    return true;
}

static bool
blf_read_canxlchannelframe(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_canxlchannelframe_t canxlheader;

    if (object_length < (data_start - block_start) + (int)sizeof(canxlheader)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: CAN_XL_CHANNEL_HEADER: not enough bytes for canxlchannelframe header in object");
        ws_debug("not enough bytes for canxlchannelframe header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &canxlheader, sizeof(canxlheader), err, err_info)) {
        ws_debug("not enough bytes for canxlchannelframe header in file");
        return false;
    }
    fix_endianness_blf_canxlchannelframe(&canxlheader);

    uint16_t payload_length = canxlheader.dataLength;
    bool is_canxl = canxlheader.flags & BLF_CANXLCHANNELFRAME_FLAG_XLF;

    if (is_canxl) {
        uint16_t canid = canxlheader.frameIdentifier & CAN_SFF_MASK;

        uint8_t canxl_flags = 0;
        if ((canxlheader.flags & BLF_CANXLCHANNELFRAME_FLAG_XLF) == BLF_CANXLCHANNELFRAME_FLAG_XLF) {
            canxl_flags |= CANXL_XLF;
        }

        if ((canxlheader.flags & BLF_CANXLCHANNELFRAME_FLAG_SEC) == BLF_CANXLCHANNELFRAME_FLAG_SEC) {
            canxl_flags |= CANXL_SEC;
        }

        if ((canxlheader.flags & BLF_CANXLCHANNELFRAME_FLAG_RRS) == BLF_CANXLCHANNELFRAME_FLAG_RRS) {
            canxl_flags |= CANXL_RRS;
        }

        uint8_t  tmpbuf[12] = { 0 };
        tmpbuf[1] = canxlheader.virtualControllerAreaNetChannelID;
        phtonu16(tmpbuf + 2, canid);
        tmpbuf[4] = canxl_flags;
        tmpbuf[5] = canxlheader.serviceDataUnitType;
        phtoleu16(tmpbuf + 6, payload_length);
        phtoleu32(tmpbuf + 8, canxlheader.acceptanceField);

        ws_buffer_assure_space(&params->rec->data, sizeof(tmpbuf) + payload_length);
        ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));

        if (payload_length > 0 && !blf_read_bytes(params, data_start + sizeof(blf_canxlchannelframe_t), ws_buffer_end_ptr(&params->rec->data), payload_length, err, err_info)) {
            ws_error("copying canxl payload failed");
            return false;
        }
        ws_buffer_increase_length(&params->rec->data, payload_length);

        blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_SOCKETCAN, canxlheader.channel, UINT16_MAX, sizeof(tmpbuf) + payload_length, sizeof(tmpbuf) + payload_length);
    } else {
        // Support for CAN or CAN-FD in CAN-XL Channel Frame format is experimental as of 2025!
        // If you have samples traces, please create a ticket and attach them to it: https://gitlab.com/wireshark/wireshark/-/issues

        bool canfd = canxlheader.flags & BLF_CANXLCHANNELFRAME_FLAG_FDF;
        uint8_t canfd_flags = 0;

        if (canfd) {
            if ((canxlheader.flags & BLF_CANXLCHANNELFRAME_FLAG_BRS) == BLF_CANXLCHANNELFRAME_FLAG_BRS) {
                canfd_flags |= CANFD_BRS;
            }
            if ((canxlheader.flags & BLF_CANXLCHANNELFRAME_FLAG_ESI) == BLF_CANXLCHANNELFRAME_FLAG_ESI) {
                canfd_flags |= CANFD_ESI;
            }
            if ((canxlheader.flags & BLF_CANXLCHANNELFRAME_FLAG_FDF) == BLF_CANXLCHANNELFRAME_FLAG_FDF) {
                canfd_flags |= CANFD_FDF;
            }
        } else {
            if (canxlheader.dlc > 8) {
                ws_debug("Regular CAN should not have DLC > 8!");
            }

            canfd_flags = 0;
        }

        uint32_t canid = canxlheader.frameIdentifier;

        /* Unclear how to reconstruct the EFF Flag. Let's make sure, we set it if the ID is more than 11 bits */
        if ((canid & CAN_EFF_MASK) > CAN_SFF_MASK) {
            canid |= CAN_EFF_FLAG;
        }

        if (!canfd && (canxlheader.flags & BLF_CANXLCHANNELFRAME_FLAG_REMOTE_FRAME) == BLF_CANXLCHANNELFRAME_FLAG_REMOTE_FRAME) {
            canid |= CAN_RTR_FLAG;
            payload_length = 0;
        }

        if (!blf_can_fill_buf_and_rec(params, err, err_info, canid, (uint8_t)payload_length, (uint8_t)payload_length, data_start + sizeof(canxlheader), flags, object_timestamp, canxlheader.channel, canfd_flags)) {
            return false;
        }
    }

    blf_add_direction_option(params, canxlheader.dir ? BLF_DIR_TX : BLF_DIR_RX);

    return true;
}

static bool
blf_read_flexraydata(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_flexraydata_t frheader;

    uint8_t  payload_length;
    uint8_t  payload_length_valid;
    uint8_t  tmpbuf[7];
    unsigned caplen, len;

    if (object_length < (data_start - block_start) + (int) sizeof(frheader)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: FLEXRAY_DATA: not enough bytes for flexrayheader in object");
        ws_debug("not enough bytes for flexrayheader in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &frheader, sizeof(frheader), err, err_info)) {
        ws_debug("not enough bytes for flexrayheader header in file");
        return false;
    }
    fix_endianness_blf_flexraydata(&frheader);

    payload_length = frheader.len;
    payload_length_valid = payload_length;

    if ((frheader.len & 0x01) == 0x01) {
        ws_debug("reading odd length in FlexRay!?");
    }

    if (payload_length_valid > object_length - (data_start - block_start) - sizeof(frheader)) {
        ws_debug("shortening FlexRay payload because buffer is too short!");
        payload_length_valid = (uint8_t)(object_length - (data_start - block_start) - sizeof(frheader));
    }

    if (frheader.channel != 0 && frheader.channel != 1) {
        ws_debug("FlexRay supports only two channels.");
    }

    /* Measurement Header */
    if (frheader.channel == 0) {
        tmpbuf[0] = BLF_FLEXRAYDATA_FRAME;
    } else {
        tmpbuf[0] = BLF_FLEXRAYDATA_FRAME | BLF_FLEXRAYDATA_CHANNEL_B;
    }

    /* Error Flags */
    tmpbuf[1] = 0;

    /* Frame Header */
    tmpbuf[2] = 0x20 | ((0x0700 & frheader.messageId) >> 8);
    tmpbuf[3] = 0x00ff & frheader.messageId;
    tmpbuf[4] = (0xfe & frheader.len) | ((frheader.crc & 0x0400) >> 10);
    tmpbuf[5] = (0x03fc & frheader.crc) >> 2;
    tmpbuf[6] = ((0x0003 & frheader.crc) << 6) | (0x3f & frheader.mux);

    ws_buffer_assure_space(&params->rec->data, sizeof(tmpbuf) + payload_length_valid);
    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));
    caplen = sizeof(tmpbuf) + payload_length_valid;
    len = sizeof(tmpbuf) + payload_length;

    if (payload_length_valid > 0 && !blf_read_bytes(params, data_start + sizeof(frheader), ws_buffer_end_ptr(&params->rec->data), payload_length_valid, err, err_info)) {
        ws_debug("copying flexray payload failed");
        return false;
    }
    ws_buffer_increase_length(&params->rec->data, payload_length_valid);

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_FLEXRAY, frheader.channel, UINT16_MAX, caplen, len);
    blf_add_direction_option(params, frheader.dir);

    return true;
}

static bool
blf_read_flexraymessage(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_flexraymessage_t frheader;

    uint8_t  payload_length;
    uint8_t  payload_length_valid;
    uint8_t  tmpbuf[7];
    unsigned caplen, len;

    if (object_length < (data_start - block_start) + (int) sizeof(frheader)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: FLEXRAY_MESSAGE: not enough bytes for flexrayheader in object");
        ws_debug("not enough bytes for flexrayheader in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &frheader, sizeof(frheader), err, err_info)) {
        ws_debug("not enough bytes for flexrayheader header in file");
        return false;
    }
    fix_endianness_blf_flexraymessage(&frheader);

    payload_length = frheader.length;
    payload_length_valid = payload_length;

    if ((frheader.length & 0x01) == 0x01) {
        ws_debug("reading odd length in FlexRay!?");
    }

    if (payload_length_valid > object_length - (data_start - block_start) - sizeof(frheader)) {
        ws_debug("shortening FlexRay payload because buffer is too short!");
        payload_length_valid = (uint8_t)(object_length - (data_start - block_start) - sizeof(frheader));
    }

    if (frheader.channel != 0 && frheader.channel != 1) {
        ws_debug("FlexRay supports only two channels.");
    }

    /* Measurement Header */
    if (frheader.channel == 0) {
        tmpbuf[0] = BLF_FLEXRAYDATA_FRAME;
    } else {
        tmpbuf[0] = BLF_FLEXRAYDATA_FRAME | BLF_FLEXRAYDATA_CHANNEL_B;
    }

    /* Error Flags */
    tmpbuf[1] = 0;

    /* Frame Header */
    tmpbuf[2] = ((0x0700 & frheader.frameId) >> 8);
    if ((frheader.frameState & BLF_FLEXRAYMESSAGE_STATE_PPI) == BLF_FLEXRAYMESSAGE_STATE_PPI) {
        tmpbuf[2] |= BLF_DLT_FLEXRAY_PPI;
    }

    if ((frheader.frameState & BLF_FLEXRAYMESSAGE_STATE_SFI) == BLF_FLEXRAYMESSAGE_STATE_SFI) {
        tmpbuf[2] |= BLF_DLT_FLEXRAY_SFI;
    }

    if ((frheader.frameState & BLF_FLEXRAYMESSAGE_STATE_NFI) != BLF_FLEXRAYMESSAGE_STATE_NFI) {
        /* NFI needs to be inversed !? */
        tmpbuf[2] |= BLF_DLT_FLEXRAY_NFI;
    }

    if ((frheader.frameState & BLF_FLEXRAYMESSAGE_STATE_STFI) == BLF_FLEXRAYMESSAGE_STATE_STFI) {
        tmpbuf[2] |= BLF_DLT_FLEXRAY_STFI;
    }

    tmpbuf[3] = 0x00ff & frheader.frameId;
    tmpbuf[4] = (0xfe & frheader.length) | ((frheader.headerCrc & 0x0400) >> 10);
    tmpbuf[5] = (0x03fc & frheader.headerCrc) >> 2;
    tmpbuf[6] = ((0x0003 & frheader.headerCrc) << 6) | (0x3f & frheader.cycle);

    ws_buffer_assure_space(&params->rec->data, sizeof(tmpbuf) + payload_length_valid);
    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));
    caplen = sizeof(tmpbuf) + payload_length_valid;
    len = sizeof(tmpbuf) + payload_length;

    if (payload_length_valid > 0 && !blf_read_bytes(params, data_start + sizeof(frheader), ws_buffer_end_ptr(&params->rec->data), payload_length_valid, err, err_info)) {
        ws_debug("copying flexray payload failed");
        return false;
    }
    ws_buffer_increase_length(&params->rec->data, payload_length_valid);

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_FLEXRAY, frheader.channel, UINT16_MAX, caplen, len);
    blf_add_direction_option(params, frheader.dir);

    return true;
}

static bool
blf_read_flexrayrcvmessageex(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp, bool ext) {
    blf_flexrayrcvmessage_t frheader;

    uint16_t payload_length;
    uint16_t payload_length_valid;
    uint8_t  tmpbuf[7];
    int      frheadersize = sizeof(frheader);
    unsigned caplen, len;

    if (ext) {
        frheadersize += 40;
    }

    if ((int64_t)object_length < (data_start - block_start) + frheadersize) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: %s: not enough bytes for flexrayheader in object",
                                    ext ? "FLEXRAY_RCVMESSAGE_EX" : "FLEXRAY_RCVMESSAGE");
        ws_debug("not enough bytes for flexrayheader in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &frheader, sizeof(frheader), err, err_info)) {
        ws_debug("not enough bytes for flexrayheader header in file");
        return false;
    }
    fix_endianness_blf_flexrayrcvmessage(&frheader);

    if (!ext) {
        frheader.dir &= 0xff;
        frheader.cycle &= 0xff;
    }

    payload_length = frheader.payloadLength;
    payload_length_valid = frheader.payloadLengthValid;

    if ((frheader.payloadLength & 0x01) == 0x01) {
        ws_debug("reading odd length in FlexRay!?");
    }

    if (payload_length_valid > object_length - (data_start - block_start) - frheadersize) {
        ws_debug("shortening FlexRay payload because buffer is too short!");
        payload_length_valid = (uint8_t)(object_length - (data_start - block_start) - frheadersize);
    }

    /* Measurement Header */
    /* TODO: It seems that this format support both channels at the same time!? */
    if (frheader.channelMask == BLF_FLEXRAYRCVMSG_CHANNELMASK_A) {
        tmpbuf[0] = BLF_FLEXRAYDATA_FRAME;
    } else {
        tmpbuf[0] = BLF_FLEXRAYDATA_FRAME | BLF_FLEXRAYDATA_CHANNEL_B;
    }

    /* Error Flags */
    tmpbuf[1] = 0;

    /* Frame Header */
    tmpbuf[2] = ((0x0700 & frheader.frameId) >> 8);
    if ((frheader.frameFlags & BLF_FLEXRAYRCVMSG_FRAME_FLAG_PAYLOAD_PREAM) == BLF_FLEXRAYRCVMSG_FRAME_FLAG_PAYLOAD_PREAM) {
        tmpbuf[2] |= BLF_DLT_FLEXRAY_PPI;
    }

    if ((frheader.frameFlags & BLF_FLEXRAYRCVMSG_FRAME_FLAG_SYNC) == BLF_FLEXRAYRCVMSG_FRAME_FLAG_SYNC) {
        tmpbuf[2] |= BLF_DLT_FLEXRAY_SFI;
    }

    if ((frheader.frameFlags & BLF_FLEXRAYRCVMSG_FRAME_FLAG_NULL_FRAME) != BLF_FLEXRAYRCVMSG_FRAME_FLAG_NULL_FRAME) {
        /* NFI needs to be inversed !? */
        tmpbuf[2] |= BLF_DLT_FLEXRAY_NFI;
    }

    if ((frheader.frameFlags & BLF_FLEXRAYRCVMSG_FRAME_FLAG_STARTUP) == BLF_FLEXRAYRCVMSG_FRAME_FLAG_STARTUP) {
        tmpbuf[2] |= BLF_DLT_FLEXRAY_STFI;
    }

    tmpbuf[3] = 0x00ff & frheader.frameId;
    tmpbuf[4] = (0xfe & frheader.payloadLength) | ((frheader.headerCrc1 & 0x0400) >> 10);
    tmpbuf[5] = (0x03fc & frheader.headerCrc1) >> 2;
    tmpbuf[6] = ((0x0003 & frheader.headerCrc1) << 6) | (0x3f & frheader.cycle);

    ws_buffer_assure_space(&params->rec->data, sizeof(tmpbuf) + payload_length_valid);
    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));
    caplen = sizeof(tmpbuf) + payload_length_valid;
    len = sizeof(tmpbuf) + payload_length;

    if (payload_length_valid > 0 && !blf_read_bytes(params, data_start + frheadersize, ws_buffer_end_ptr(&params->rec->data), payload_length_valid, err, err_info)) {
        ws_debug("copying flexray payload failed");
        return false;
    }
    ws_buffer_increase_length(&params->rec->data, payload_length_valid);

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_FLEXRAY, frheader.channelMask, UINT16_MAX, caplen, len);
    blf_add_direction_option(params, frheader.dir);

    return true;
}

static bool
blf_read_linmessage(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp, bool crc_error) {
    blf_linmessage_t         linmessage;

    uint8_t  payload_length;
    unsigned len;

    if (object_length < (data_start - block_start) + (int)sizeof(linmessage)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: %s: not enough bytes for %s in object", crc_error ? "LIN_CRC_ERROR" : "LIN_MESSAGE", crc_error ? "lincrcerror" : "linmessage");
        ws_debug("not enough bytes for %s in object", crc_error ? "lincrcerror" : "linmessage");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &linmessage, sizeof(linmessage), err, err_info)) {
        ws_debug("not enough bytes for %s in file", crc_error ? "lincrcerror" : "linmessage");
        return false;
    }
    fix_endianness_blf_linmessage(&linmessage);

    linmessage.dlc &= 0x0f;
    linmessage.id &= 0x3f;

    payload_length = MIN(linmessage.dlc, 8);

    uint8_t tmpbuf[8];
    tmpbuf[0] = 1; /* message format rev = 1 */
    tmpbuf[1] = 0; /* reserved */
    tmpbuf[2] = 0; /* reserved */
    tmpbuf[3] = 0; /* reserved */
    tmpbuf[4] = linmessage.dlc << 4; /* dlc (4bit) | type (2bit) | checksum type (2bit) */
    tmpbuf[5] = linmessage.id; /* parity (2bit) | id (6bit) */
    tmpbuf[6] = (uint8_t)(linmessage.crc & 0xff); /* checksum */
    tmpbuf[7] = 0; /* errors */

    if (crc_error) {
        tmpbuf[7] |= 0x08;
    }

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));
    ws_buffer_append(&params->rec->data, linmessage.data, payload_length);
    len = sizeof(tmpbuf) + payload_length;

    /* make sure that the payload is 4 or 8 bytes long */
    const uint8_t padding[4] = { 0, 0, 0, 0 };
    if (payload_length < 4) {
        ws_buffer_append(&params->rec->data, padding, 4 - payload_length);
        len += 4 - payload_length;
    } else if (payload_length > 4 && payload_length < 8) {
        ws_buffer_append(&params->rec->data, padding, 8 - payload_length);
        len += 8 - payload_length;
    }

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linmessage.channel, UINT16_MAX, len, len);
    blf_add_direction_option(params, linmessage.dir);

    return true;
}

static bool
blf_read_linrcverror(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_linrcverror_t   linmessage;

    if (object_length < (data_start - block_start) + (int)sizeof(linmessage)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: LIN_RCV_ERROR: not enough bytes for linrcverror in object");
        ws_debug("not enough bytes for linrcverror in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &linmessage, sizeof(linmessage), err, err_info)) {
        ws_debug("not enough bytes for linrcverror in file");
        return false;
    }
    linmessage.channel = GUINT16_FROM_LE(linmessage.channel);

    linmessage.dlc &= 0x0f;
    linmessage.id &= 0x3f;

    uint8_t tmpbuf[12];
    tmpbuf[0] = 1; /* message format rev = 1 */
    tmpbuf[1] = 0; /* reserved */
    tmpbuf[2] = 0; /* reserved */
    tmpbuf[3] = 0; /* reserved */
    tmpbuf[4] = linmessage.dlc << 4; /* dlc (4bit) | type (2bit) | checksum type (2bit) */
    tmpbuf[5] = linmessage.id; /* parity (2bit) | id (6bit) */
    tmpbuf[6] = 0; /* checksum */
    /* XXX - This object can represent many different error types.
     * For now we always treat it as framing error,
     * but in the future we should expand it. */
    tmpbuf[7] = LIN_ERROR_FRAMING_ERROR; /* errors */
    tmpbuf[8] = 0;
    tmpbuf[9] = 0;
    tmpbuf[10] = 0;
    tmpbuf[11] = 0;

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));
    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linmessage.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));

    return true;
}

static bool
blf_read_linsenderror(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_linsenderror_t         linmessage;

    if (object_length < (data_start - block_start) + (int)sizeof(linmessage)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: LIN_SND_ERROR: not enough bytes for linsenderror in object");
        ws_debug("not enough bytes for linsenderror in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &linmessage, sizeof(linmessage), err, err_info)) {
        ws_debug("not enough bytes for linsenderror in file");
        return false;
    }
    linmessage.channel = GUINT16_FROM_LE(linmessage.channel);

    linmessage.dlc &= 0x0f;
    linmessage.id &= 0x3f;

    uint8_t tmpbuf[12];
    tmpbuf[0] = 1; /* message format rev = 1 */
    tmpbuf[1] = 0; /* reserved */
    tmpbuf[2] = 0; /* reserved */
    tmpbuf[3] = 0; /* reserved */
    tmpbuf[4] = linmessage.dlc << 4; /* dlc (4bit) | type (2bit) | checksum type (2bit) */
    tmpbuf[5] = linmessage.id; /* parity (2bit) | id (6bit) */
    tmpbuf[6] = 0; /* checksum */
    tmpbuf[7] = LIN_ERROR_NO_SLAVE_RESPONSE; /* errors */
    tmpbuf[8] = 0;
    tmpbuf[9] = 0;
    tmpbuf[10] = 0;
    tmpbuf[11] = 0;

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));
    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linmessage.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));

    return true;
}

static bool
blf_read_linwakeupevent(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_linwakeupevent_t    linevent;

    if (object_length < (data_start - block_start) + (int)sizeof(linevent)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: LIN_WAKEUP: not enough bytes for linwakeup in object");
        ws_debug("not enough bytes for linwakeup in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &linevent, sizeof(linevent), err, err_info)) {
        ws_debug("not enough bytes for linwakeup in file");
        return false;
    }
    linevent.channel = GUINT16_FROM_LE(linevent.channel);

    uint8_t tmpbuf[12]; /* LIN events have a fixed length of 12 bytes */
    tmpbuf[0] = 1; /* message format rev = 1 */
    tmpbuf[1] = 0; /* reserved */
    tmpbuf[2] = 0; /* reserved */
    tmpbuf[3] = 0; /* reserved */
    tmpbuf[4] = 3 << 2; /* dlc (4bit) | type (2bit) | checksum type (2bit) */
    tmpbuf[5] = 0; /* parity (2bit) | id (6bit) */
    tmpbuf[6] = 0; /* checksum */
    tmpbuf[7] = 0; /* errors */

    /* Wake-up event */
    tmpbuf[8] = 0xB0;
    tmpbuf[9] = 0xB0;
    tmpbuf[10] = 0x00;
    tmpbuf[11] = 0x04;

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linevent.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));

    return true;
}

static bool
blf_read_linmessage2(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp, uint16_t object_version) {
    blf_linmessage2_t         linmessage;

    uint8_t  payload_length;
    unsigned len;

    if (object_length < (data_start - block_start) + (int)sizeof(linmessage)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: LIN_MESSAGE2: not enough bytes for linmessage2 in object");
        ws_debug("not enough bytes for linmessage2 in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &linmessage, sizeof(linmessage), err, err_info)) {
        ws_debug("not enough bytes for linmessage2 in file");
        return false;
    }
    fix_endianness_blf_linmessage2(&linmessage);

    linmessage.linDataByteTimestampEvent.linMessageDescriptor.dlc &= 0x0f;
    linmessage.linDataByteTimestampEvent.linMessageDescriptor.id &= 0x3f;

    payload_length = MIN(linmessage.linDataByteTimestampEvent.linMessageDescriptor.dlc, 8);

    uint8_t tmpbuf[8];
    tmpbuf[0] = 1; /* message format rev = 1 */
    tmpbuf[1] = 0; /* reserved */
    tmpbuf[2] = 0; /* reserved */
    tmpbuf[3] = 0; /* reserved */
    tmpbuf[4] = linmessage.linDataByteTimestampEvent.linMessageDescriptor.dlc << 4; /* dlc (4bit) | type (2bit) | checksum type (2bit) */
    if (object_version >= 1) { /* The 'checksumModel' field is valid only if objectVersion >= 1 */
        switch (linmessage.linDataByteTimestampEvent.linMessageDescriptor.checksumModel) {
        case 0:
            tmpbuf[4] |= 1; /* Classic */
            break;
        case 1:
            tmpbuf[4] |= 2; /* Enhanced */
            break;
        default:
            break;
        }
    }
    tmpbuf[5] = linmessage.linDataByteTimestampEvent.linMessageDescriptor.id; /* parity (2bit) | id (6bit) */
    tmpbuf[6] = (uint8_t)(linmessage.crc & 0xff); /* checksum */
    tmpbuf[7] = 0; /* errors */

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));
    ws_buffer_append(&params->rec->data, linmessage.data, payload_length);
    len = sizeof(tmpbuf) + payload_length;

    /* make sure that the payload is 4 or 8 bytes long */
    const uint8_t padding[4] = { 0, 0, 0, 0 };
    if (payload_length < 4) {
        ws_buffer_append(&params->rec->data, padding, 4 - payload_length);
        len += 4 - payload_length;
    } else if (payload_length > 4 && payload_length < 8) {
        ws_buffer_append(&params->rec->data, padding, 8 - payload_length);
        len += 8 - payload_length;
    }

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linmessage.linDataByteTimestampEvent.linMessageDescriptor.linSynchFieldEvent.linBusEvent.channel, UINT16_MAX, len, len);
    blf_add_direction_option(params, linmessage.dir);

    return true;
}

static bool
blf_read_lincrcerror2(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp, uint16_t object_version) {
    blf_lincrcerror2_t         linmessage;

    uint8_t  payload_length;
    unsigned len;

    if (object_length < (data_start - block_start) + (int)sizeof(linmessage)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: LIN_CRC_ERROR2: not enough bytes for lincrcerror2 in object");
        ws_debug("not enough bytes for lincrcerror2 in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &linmessage, sizeof(linmessage), err, err_info)) {
        ws_debug("not enough bytes for lincrcerror2 in file");
        return false;
    }
    fix_endianness_blf_lincrcerror2(&linmessage);

    linmessage.linDataByteTimestampEvent.linMessageDescriptor.dlc &= 0x0f;
    linmessage.linDataByteTimestampEvent.linMessageDescriptor.id &= 0x3f;

    payload_length = MIN(linmessage.linDataByteTimestampEvent.linMessageDescriptor.dlc, 8);

    uint8_t tmpbuf[12];
    tmpbuf[0] = 1; /* message format rev = 1 */
    tmpbuf[1] = 0; /* reserved */
    tmpbuf[2] = 0; /* reserved */
    tmpbuf[3] = 0; /* reserved */
    tmpbuf[4] = linmessage.linDataByteTimestampEvent.linMessageDescriptor.dlc << 4; /* dlc (4bit) | type (2bit) | checksum type (2bit) */
    if (object_version >= 1) { /* The 'checksumModel' field is valid only if objectVersion >= 1 */
        switch (linmessage.linDataByteTimestampEvent.linMessageDescriptor.checksumModel) {
        case 0:
            tmpbuf[4] |= 1; /* Classic */
            break;
        case 1:
            tmpbuf[4] |= 2; /* Enhanced */
            break;
        default:
            break;
        }
    }
    tmpbuf[5] = linmessage.linDataByteTimestampEvent.linMessageDescriptor.id; /* parity (2bit) | id (6bit) */
    tmpbuf[6] = (uint8_t)(linmessage.crc & 0xff); /* checksum */
    tmpbuf[7] = LIN_ERROR_CHECKSUM_ERROR; /* errors */
    tmpbuf[8] = 0;
    tmpbuf[9] = 0;
    tmpbuf[10] = 0;
    tmpbuf[11] = 0;

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));
    ws_buffer_append(&params->rec->data, linmessage.data, payload_length);
    len = sizeof(tmpbuf) + payload_length;

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linmessage.linDataByteTimestampEvent.linMessageDescriptor.linSynchFieldEvent.linBusEvent.channel, UINT16_MAX, len, len);
    blf_add_direction_option(params, linmessage.dir);

    return true;
}

static bool
blf_read_linrcverror2(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp, uint16_t object_version) {
    blf_linrcverror2_t         linmessage;

    uint8_t  payload_length;
    unsigned len;

    if (object_length < (data_start - block_start) + (int)sizeof(linmessage)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: LIN_RCV_ERROR2: not enough bytes for linrcverror2 in object");
        ws_debug("not enough bytes for linrcverror2 in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &linmessage, sizeof(linmessage), err, err_info)) {
        ws_debug("not enough bytes for linrcverror2 in file");
        return false;
    }
    fix_endianness_blf_linrcverror2(&linmessage);

    linmessage.linDataByteTimestampEvent.linMessageDescriptor.dlc &= 0x0f;
    linmessage.linDataByteTimestampEvent.linMessageDescriptor.id &= 0x3f;

    if (linmessage.hasDataBytes) {
        payload_length = MIN(linmessage.linDataByteTimestampEvent.linMessageDescriptor.dlc, 8);
    } else {
        payload_length = 0;
    }

    uint8_t tmpbuf[12];
    tmpbuf[0] = 1; /* message format rev = 1 */
    tmpbuf[1] = 0; /* reserved */
    tmpbuf[2] = 0; /* reserved */
    tmpbuf[3] = 0; /* reserved */
    tmpbuf[4] = linmessage.linDataByteTimestampEvent.linMessageDescriptor.dlc << 4; /* dlc (4bit) | type (2bit) | checksum type (2bit) */
    if (object_version >= 1) { /* The 'checksumModel' field is valid only if objectVersion >= 1 */
        switch (linmessage.linDataByteTimestampEvent.linMessageDescriptor.checksumModel) {
        case 0:
            tmpbuf[4] |= 1; /* Classic */
            break;
        case 1:
            tmpbuf[4] |= 2; /* Enhanced */
            break;
        default:
            break;
        }
    }
    tmpbuf[5] = linmessage.linDataByteTimestampEvent.linMessageDescriptor.id; /* parity (2bit) | id (6bit) */
    tmpbuf[6] = 0; /* checksum */
    /* XXX - This object can represent many different error types.
     * For now we always treat it as framing error,
     * but in the future we should expand it. */
    tmpbuf[7] = LIN_ERROR_FRAMING_ERROR; /* errors */
    tmpbuf[8] = 0;
    tmpbuf[9] = 0;
    tmpbuf[10] = 0;
    tmpbuf[11] = 0;

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));
    if (payload_length > 0) {
        ws_buffer_append(&params->rec->data, linmessage.data, payload_length);
    }
    len = sizeof(tmpbuf) + payload_length;

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linmessage.linDataByteTimestampEvent.linMessageDescriptor.linSynchFieldEvent.linBusEvent.channel, UINT16_MAX, len, len);

    return true;
}

static bool
blf_read_linsenderror2(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp, uint16_t object_version) {
    blf_linsenderror2_t         linmessage;

    if (object_length < (data_start - block_start) + (int)sizeof(linmessage)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: LIN_SND_ERROR2: not enough bytes for linsenderror2 in object");
        ws_debug("not enough bytes for linsenderror2 in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &linmessage, sizeof(linmessage), err, err_info)) {
        ws_debug("not enough bytes for linsenderror2 in file");
        return false;
    }
    fix_endianness_blf_linsenderror2(&linmessage);

    linmessage.linMessageDescriptor.dlc &= 0x0f;
    linmessage.linMessageDescriptor.id &= 0x3f;

    uint8_t tmpbuf[12];
    tmpbuf[0] = 1; /* message format rev = 1 */
    tmpbuf[1] = 0; /* reserved */
    tmpbuf[2] = 0; /* reserved */
    tmpbuf[3] = 0; /* reserved */
    tmpbuf[4] = linmessage.linMessageDescriptor.dlc << 4; /* dlc (4bit) | type (2bit) | checksum type (2bit) */
    if (object_version >= 1) { /* The 'checksumModel' field is valid only if objectVersion >= 1 */
        switch (linmessage.linMessageDescriptor.checksumModel) {
        case 0:
            tmpbuf[4] |= 1; /* Classic */
            break;
        case 1:
            tmpbuf[4] |= 2; /* Enhanced */
            break;
        default:
            break;
        }
    }
    tmpbuf[5] = linmessage.linMessageDescriptor.id; /* parity (2bit) | id (6bit) */
    tmpbuf[6] = 0; /* checksum */
    tmpbuf[7] = LIN_ERROR_NO_SLAVE_RESPONSE; /* errors */
    tmpbuf[8] = 0;
    tmpbuf[9] = 0;
    tmpbuf[10] = 0;
    tmpbuf[11] = 0;

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linmessage.linMessageDescriptor.linSynchFieldEvent.linBusEvent.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));

    return true;
}

static bool
blf_read_linwakeupevent2(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_linwakeupevent2_t   linevent;

    if (object_length < (data_start - block_start) + (int)sizeof(linevent)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: LIN_WAKEUP2: not enough bytes for linwakeup2 in object");
        ws_debug("not enough bytes for linwakeup2 in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &linevent, sizeof(linevent), err, err_info)) {
        ws_debug("not enough bytes for linwakeup2 in file");
        return false;
    }
    fix_endianness_blf_linwakeupevent2(&linevent);

    uint8_t tmpbuf[12]; /* LIN events have a fixed length of 12 bytes */
    tmpbuf[0] = 1; /* message format rev = 1 */
    tmpbuf[1] = 0; /* reserved */
    tmpbuf[2] = 0; /* reserved */
    tmpbuf[3] = 0; /* reserved */
    tmpbuf[4] = 3 << 2; /* dlc (4bit) | type (2bit) | checksum type (2bit) */
    tmpbuf[5] = 0; /* parity (2bit) | id (6bit) */
    tmpbuf[6] = 0; /* checksum */
    tmpbuf[7] = 0; /* errors */

    /* Wake-up event */
    tmpbuf[8] = 0xB0;
    tmpbuf[9] = 0xB0;
    tmpbuf[10] = 0x00;
    tmpbuf[11] = 0x04;

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linevent.linBusEvent.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));

    return true;
}

static bool
blf_read_linsleepmodeevent(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_linsleepmodeevent_t   linevent;

    if (object_length < (data_start - block_start) + (int)sizeof(linevent)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: LIN_SLEEP: not enough bytes for linsleep in object");
        ws_debug("not enough bytes for linsleep in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &linevent, sizeof(linevent), err, err_info)) {
        ws_debug("not enough bytes for linsleep in file");
        return false;
    }
    linevent.channel = GUINT16_FROM_LE(linevent.channel);

    uint8_t tmpbuf[12]; /* LIN events have a fixed length of 12 bytes */
    tmpbuf[0] = 1; /* message format rev = 1 */
    tmpbuf[1] = 0; /* reserved */
    tmpbuf[2] = 0; /* reserved */
    tmpbuf[3] = 0; /* reserved */
    tmpbuf[4] = 3 << 2; /* dlc (4bit) | type (2bit) | checksum type (2bit) */
    tmpbuf[5] = 0; /* parity (2bit) | id (6bit) */
    tmpbuf[6] = 0; /* checksum */
    tmpbuf[7] = 0; /* errors */

    switch (linevent.reason) {
    case BLF_LIN_SLEEP_REASON_GO_TO_SLEEP_FRAME:
        /* Go-to-Sleep event by Go-to-Sleep frame */
        tmpbuf[8] = 0xB0;
        tmpbuf[9] = 0xB0;
        tmpbuf[10] = 0x00;
        tmpbuf[11] = 0x01;
        break;
    case BLF_LIN_SLEEP_REASON_BUS_IDLE_TIMEOUT:
    case BLF_LIN_SLEEP_REASON_SILENT_SLEEPMODE_CMD:
        /* Go-to-Sleep event by Inactivity for more than 4s */
        tmpbuf[8] = 0xB0;
        tmpbuf[9] = 0xB0;
        tmpbuf[10] = 0x00;
        tmpbuf[11] = 0x02;
        break;
    case BLF_LIN_WU_REASON_EXTERNAL_WAKEUP_SIG:
    case BLF_LIN_WU_REASON_INTERNAL_WAKEUP_SIG:
    case BLF_LIN_WU_REASON_BUS_TRAFFIC: /* There's no "wake-up by bus traffic" event in the LIN packet. */
        /* Wake-up event by Wake-up signal */
        tmpbuf[8] = 0xB0;
        tmpbuf[9] = 0xB0;
        tmpbuf[10] = 0x00;
        tmpbuf[11] = 0x04;
        break;
    case BLF_LIN_WU_SLEEP_REASON_START_STATE:
    case BLF_LIN_NO_SLEEP_REASON_BUS_TRAFFIC:
        /* If we're just reporting on the initial state,
         * or the interface doesn't want to go to sleep,
         * report the current state as "event". */
        if (linevent.flags & 0x2) {
            /* Wake-up event by Wake-up signal */
            tmpbuf[8] = 0xB0;
            tmpbuf[9] = 0xB0;
            tmpbuf[10] = 0x00;
            tmpbuf[11] = 0x04;
        } else {
            /* Go-to-Sleep event by Inactivity for more than 4s */
            tmpbuf[8] = 0xB0;
            tmpbuf[9] = 0xB0;
            tmpbuf[10] = 0x00;
            tmpbuf[11] = 0x02;
        }
        break;
    default:
        tmpbuf[8] = 0x00;
        tmpbuf[9] = 0x00;
        tmpbuf[10] = 0x00;
        tmpbuf[11] = 0x00;
        break;
    }

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linevent.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));

    return true;
}

static bool
blf_parse_xml_port(const xmlChar* str, char** name, uint16_t* hwchannel, bool* simulated) {
    static const char name_magic[] = "name=";
    static const char hwchannel_magic[] = "hwchannel=";
    static const char simulated_magic[] = "simulated=";

    if (str == NULL) return false;

    char** tokens = g_strsplit_set((const gchar*)str, ";", -1);
    if (tokens == NULL) {
        ws_debug("cannot split XML port data");
        return false;
    }

    for (int i = 0; tokens[i] != NULL; i++) {
        const char* token = tokens[i];
        if (name && strncmp(token, name_magic, strlen(name_magic)) == 0) {
            if (*name == NULL) {    /* Avoid memory leak in case of repeated names */
                *name = ws_strdup(token + strlen(name_magic));
            }
        } else if (hwchannel && strncmp(token, hwchannel_magic, strlen(hwchannel_magic)) == 0) {
            if (!ws_strtou16(token + strlen(hwchannel_magic), NULL, hwchannel)) {
                *hwchannel = UINT16_MAX;
            }
        } else if (simulated && strncmp(token, simulated_magic, strlen(simulated_magic)) == 0) {
            if (strlen(token) > strlen(simulated_magic) && token[strlen(simulated_magic)] != '0') {
                *simulated = true;  /* TODO: Find a way to use this information */
            }
        }
    }

    g_strfreev(tokens);

    return true;
}

static int
blf_get_xml_pkt_encap(const xmlChar* str) {
    if (str == NULL) return 0;

    if (xmlStrcmp(str, "CAN") == 0) {
        return WTAP_ENCAP_SOCKETCAN;
    }
    if (xmlStrcmp(str, "FlexRay") == 0) {
        return WTAP_ENCAP_FLEXRAY;
    }
    if (xmlStrcmp(str, "LIN") == 0) {
        return WTAP_ENCAP_LIN;
    }
    if (xmlStrcmp(str, "Ethernet") == 0) {
        return WTAP_ENCAP_ETHERNET;
    }
    if (xmlStrcmp(str, "WLAN") == 0) {    /* Not confirmed with a real capture */
        return WTAP_ENCAP_IEEE_802_11;
    }

    return WTAP_ENCAP_UNKNOWN;
}


/** Extracts the channel and port names from a channels XML.
 *
 * A sample channels XML looks like this:
 *
 * <?xml version="1.0" encoding="UTF-8"?>
 * <channels version="1">
 *   <channel number="1" type="CAN" network="CAN01">
 *     <databases>
 *       <database file="DB.arxml" path="C:\...\" cluster="CAN01" />
 *       <database file="DB.dbc" path="C:\...\" cluster="General" />
 *     </databases>
 *   </channel>
 *   <channel number="1" type="LIN" network="LIN01">
 *     <databases>
 *       <database file="DB.dbc" path="C:\...\" cluster="General" />
 *       <database file="DB.ldf" path="C:\...\" cluster="LIN01" />
 *     </databases>
 *   </channel>
 *   <channel number="1" type="Ethernet" network="ETH01">
 *     <databases>
 *       <database file="DB.dbc" path="C:\...\" cluster="General" />
 *     </databases>
 *     <channel_properties>
 *       <elist name="ports">
 *         <eli name="port">name=Port1;hwchannel=11;simulated=1</eli>
 *         <eli name="port">name=Port2;hwchannel=12;simulated=0</eli>
 *       </elist>
 *     </channel_properties>
 *   </channel>
 * </channels>
 */
static bool
blf_set_xml_channels(blf_params_t* params, const char* text, size_t len) {
    xmlDocPtr doc;
    xmlNodePtr root_element = NULL;
    xmlNodePtr channels = NULL;

    if (text == NULL) return false;

    /* Now it can be parsed into a proper structure */
    doc = xmlParseMemory(text, (int)len);
    if (doc == NULL) {
        ws_debug("invalid xml found");
        return false;
    }

    root_element = xmlDocGetRootElement(doc);
    if (root_element == NULL) {
        ws_debug("empty xml doc");
        xmlFreeDoc(doc);
        return false;
    }

    if (xmlStrcmp(root_element->name, (const xmlChar*)"channels") == 0) {
        channels = root_element;
    } else {
        for (xmlNodePtr cur = root_element->children; cur != NULL; cur = cur->next) {
            if (cur->type == XML_ELEMENT_NODE && xmlStrcmp(cur->name, (const xmlChar*)"channels") == 0) {
                channels = cur;
                break;
            }
        }
    }

    if (channels == NULL) {
        ws_debug("No channels found");
        xmlFreeDoc(doc);
        return false;
    }

    for (xmlNodePtr current_channel_node = channels->children; current_channel_node != NULL; current_channel_node = current_channel_node->next) {
        if ((current_channel_node->type == XML_ELEMENT_NODE) && (xmlStrcmp(current_channel_node->name, (const xmlChar*)"channel") == 0)) {
            /* Reset the found attributes */
            int pkt_encap = WTAP_ENCAP_UNKNOWN;
            uint16_t channel = UINT16_MAX;
            char* channel_name = NULL;

            for (xmlAttrPtr attr = current_channel_node->properties; attr; attr = attr->next) {
                if (xmlStrcmp(attr->name, (const xmlChar*)"number") == 0) {
                    xmlChar* str_channel = xmlNodeListGetString(current_channel_node->doc, attr->children, 1);
                    if (str_channel != NULL) {
                        ws_strtou16(str_channel, NULL, &channel);
                        xmlFree(str_channel);
                    }
                } else if (xmlStrcmp(attr->name, (const xmlChar*)"type") == 0) {
                    xmlChar* str_type = xmlNodeListGetString(current_channel_node->doc, attr->children, 1);
                    if (str_type != NULL) {
                        pkt_encap = blf_get_xml_pkt_encap(str_type);
                        xmlFree(str_type);
                    }
                } else if (xmlStrcmp(attr->name, (const xmlChar*)"network") == 0) {
                    xmlChar* str_network = xmlNodeListGetString(current_channel_node->doc, attr->children, 1);
                    if (str_network != NULL) {
                        channel_name = ws_strdup((const char*)str_network);
                        xmlFree(str_network);
                    }
                }
            }

            if (pkt_encap != WTAP_ENCAP_UNKNOWN && channel != UINT16_MAX && channel_name != NULL) {
                ws_debug("Found channel in XML: PKT_ENCAP: %d, ID: %u, name: %s", pkt_encap, channel, channel_name);
                blf_prepare_interface_name(params, pkt_encap, channel, UINT16_MAX, channel_name, true);

                /* Look for ports under the channel properties */
                for (xmlNodePtr channel_property = current_channel_node->children; channel_property != NULL; channel_property = channel_property->next) {
                    if ((channel_property->type == XML_ELEMENT_NODE) && (xmlStrcmp(channel_property->name, (const xmlChar*)"channel_properties") == 0)) {
                        for (xmlNodePtr prop_child = channel_property->children; prop_child != NULL; prop_child = prop_child->next) {
                            if (prop_child->type == XML_ELEMENT_NODE && xmlStrcmp(prop_child->name, (const xmlChar*)"elist") == 0) {
                                xmlNodePtr elist_node = prop_child;
                                xmlChar* str_name = xmlGetProp(elist_node, (const xmlChar*)"name");
                                if (xmlStrcmp(str_name, (const xmlChar*)"ports") == 0) {
                                    for (xmlNodePtr eli_node = elist_node->children; eli_node != NULL; eli_node = eli_node->next) {
                                        if (eli_node->type == XML_ELEMENT_NODE && xmlStrcmp(eli_node->name, (const xmlChar*)"eli") == 0) {
                                            xmlChar* eli_name_attr = xmlGetProp(eli_node, (const xmlChar*)"name");
                                            if (xmlStrcmp(eli_name_attr, (const xmlChar*)"port") == 0) {
                                                char* port_name = NULL;
                                                uint16_t hwchannel = UINT16_MAX;
                                                bool simulated = false;
                                                char* iface_name = NULL;
                                                xmlChar* eli_content = xmlNodeGetContent(eli_node);

                                                bool res = blf_parse_xml_port(eli_content, &port_name, &hwchannel, &simulated);
                                                if (res && port_name != NULL && hwchannel != UINT16_MAX) {
                                                    iface_name = ws_strdup_printf("%s::%s", channel_name, port_name);
                                                    ws_debug("Found channel in XML: PKT_ENCAP: %d, ID: %u, HW ID: %u, name: %s", pkt_encap, channel, hwchannel, iface_name);
                                                    blf_prepare_interface_name(params, pkt_encap, channel, hwchannel, iface_name, true);
                                                    g_free(iface_name);
                                                } else {
                                                    ws_debug("port with missing or malformed info found in xml");
                                                }
                                                g_free(port_name);
                                                xmlFree(eli_content);
                                            }
                                            xmlFree(eli_name_attr);
                                        }
                                    }
                                }
                                xmlFree(str_name);
                            }
                        }
                    }
                }
            }
            g_free(channel_name);
        }
    }

    xmlFreeDoc(doc);
    return true;
}

static int
blf_read_apptextmessage(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp, blf_metadata_info_t* metadata_info) {
    blf_apptext_t            apptextheader;

    if (object_length < (data_start - block_start) + (int)sizeof(apptextheader)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: APP_TEXT: not enough bytes for apptext header in object");
        ws_debug("not enough bytes for apptext header in object");
        return BLF_APPTEXT_FAILED;
    }

    if (!blf_read_bytes(params, data_start, &apptextheader, sizeof(apptextheader), err, err_info)) {
        ws_debug("not enough bytes for apptext header in file");
        return BLF_APPTEXT_FAILED;
    }
    fix_endianness_blf_apptext_header(&apptextheader);

    if (metadata_info->valid && apptextheader.source != BLF_APPTEXT_METADATA) {
        /* If we're in the middle of a sequence of metadata objects,
         * but we get an AppText object from another source,
         * skip the previously incomplete object and start fresh.
         */
        metadata_info->valid = false;
    }

    /* Add an extra byte for a terminating '\0' */
    char* text = g_try_malloc((size_t)apptextheader.textLength + 1);
    if (text == NULL) {
        ws_debug("cannot allocate memory");
        return BLF_APPTEXT_FAILED;
    }

    if (!blf_read_bytes(params, data_start + sizeof(apptextheader), text, apptextheader.textLength, err, err_info)) {
        ws_debug("not enough bytes for apptext text in file");
        g_free(text);
        return BLF_APPTEXT_FAILED;
    }
    text[apptextheader.textLength] = '\0'; /* Here's the '\0' */

    switch (apptextheader.source) {
    case BLF_APPTEXT_CHANNEL:
    {

        /* returns a NULL terminated array of NULL terminates strings */
        char** tokens = g_strsplit_set(text, ";", -1);

        if (tokens == NULL || tokens[0] == NULL || tokens[1] == NULL) {
            if (tokens != NULL) {
                g_strfreev(tokens);
            }
            g_free(text);
            return BLF_APPTEXT_CHANNEL;
        }

        uint16_t channel = (apptextheader.reservedAppText1 >> 8) & 0xff;
        int pkt_encap;

        switch ((apptextheader.reservedAppText1 >> 16) & 0xff) {
        case BLF_BUSTYPE_CAN:
            pkt_encap = WTAP_ENCAP_SOCKETCAN;
            break;

        case BLF_BUSTYPE_FLEXRAY:
            pkt_encap = WTAP_ENCAP_FLEXRAY;
            break;

        case BLF_BUSTYPE_LIN:
            pkt_encap = WTAP_ENCAP_LIN;
            break;

        case BLF_BUSTYPE_ETHERNET:
            pkt_encap = WTAP_ENCAP_ETHERNET;
            break;

        case BLF_BUSTYPE_WLAN:
            pkt_encap = WTAP_ENCAP_IEEE_802_11;
            break;

        default:
            pkt_encap = WTAP_ENCAP_UNKNOWN;
            break;
        }

        if (pkt_encap != WTAP_ENCAP_UNKNOWN) {
            /* we use lookup to create interface, if not existing yet */
            blf_prepare_interface_name(params, pkt_encap, channel, UINT16_MAX, tokens[1], false);
        }

        g_strfreev(tokens);
        g_free(text);
        return BLF_APPTEXT_CHANNEL;
    }
    case BLF_APPTEXT_METADATA:
        if (metadata_info->valid) {
            /* Set the buffer pointer to the end of the previous object */
            params->rec->data.first_free = metadata_info->metadata_cont;
        } else {
            /* First object of a sequence of one or more */
            wtap_buffer_append_epdu_string(&params->rec->data, EXP_PDU_TAG_DISSECTOR_NAME, BLF_APPTEXT_TAG_DISS_DEFAULT);
            wtap_buffer_append_epdu_string(&params->rec->data, EXP_PDU_TAG_COL_PROT_TEXT, BLF_APPTEXT_COL_PROT_TEXT);
            switch (((apptextheader.reservedAppText1 >> 24) & 0xff)) {
            case BLF_APPTEXT_XML_GENERAL:
                wtap_buffer_append_epdu_string(&params->rec->data, EXP_PDU_TAG_COL_INFO_TEXT, BLF_APPTEXT_COL_INFO_TEXT_GENERAL);
                break;

            case BLF_APPTEXT_XML_CHANNELS:
                wtap_buffer_append_epdu_string(&params->rec->data, EXP_PDU_TAG_COL_INFO_TEXT, BLF_APPTEXT_COL_INFO_TEXT_CHANNELS);
                break;

            case BLF_APPTEXT_XML_IDENTITY:
                wtap_buffer_append_epdu_string(&params->rec->data, EXP_PDU_TAG_COL_INFO_TEXT, BLF_APPTEXT_COL_INFO_TEXT_IDENTITY);
                break;

            default:
                wtap_buffer_append_epdu_string(&params->rec->data, EXP_PDU_TAG_COL_INFO_TEXT, BLF_APPTEXT_COL_INFO_TEXT);
            }
            wtap_buffer_append_epdu_end(&params->rec->data);
            metadata_info->payload_start = params->rec->data.first_free;
        }

        ws_buffer_append(&params->rec->data, text, apptextheader.textLength);
        g_free(text);

        if ((apptextheader.reservedAppText1 & 0x00ffffff) > apptextheader.textLength) {
            /* Continues in the next object */
            return BLF_APPTEXT_CONT;
        }

        if (((apptextheader.reservedAppText1 >> 24) & 0xff) == BLF_APPTEXT_XML_CHANNELS) {
            blf_set_xml_channels(params, params->rec->data.data + metadata_info->payload_start, params->rec->data.first_free - metadata_info->payload_start);
        }

        /* Override the timestamp with 0 for metadata objects. Thay can only occur at the beginning of the file, and they usually already have a timestamp of 0. */
        blf_init_rec(params, 0, 0, WTAP_ENCAP_WIRESHARK_UPPER_PDU, 0, UINT16_MAX, (uint32_t)ws_buffer_length(&params->rec->data), (uint32_t)ws_buffer_length(&params->rec->data));
        return BLF_APPTEXT_METADATA;
    case BLF_APPTEXT_COMMENT:
    case BLF_APPTEXT_ATTACHMENT:
    case BLF_APPTEXT_TRACELINE:
    {
        wtap_buffer_append_epdu_string(&params->rec->data, EXP_PDU_TAG_DISSECTOR_NAME, BLF_APPTEXT_TAG_DISS_DEFAULT);
        wtap_buffer_append_epdu_string(&params->rec->data, EXP_PDU_TAG_COL_PROT_TEXT, BLF_APPTEXT_COL_PROT_TEXT);

        char* info_line = NULL;
        switch (apptextheader.source) {
        case BLF_APPTEXT_COMMENT:
            info_line = ws_strdup_printf("Comment: %s", text);
            break;
        case BLF_APPTEXT_ATTACHMENT:
            info_line = ws_strdup_printf("Attachment: %s", text);
            break;
        case BLF_APPTEXT_TRACELINE:
            info_line = ws_strdup_printf("Trace line%s: %s", (apptextheader.reservedAppText1 & 0x00000010) ? "" : " (hidden)", text);
            break;
        default:
            break;
        }

        wtap_buffer_append_epdu_string(&params->rec->data, EXP_PDU_TAG_COL_INFO_TEXT, info_line);
        wtap_buffer_append_epdu_end(&params->rec->data);

        size_t text_length = strlen(text);  /* The string can contain '\0' before textLength bytes */
        ws_buffer_append(&params->rec->data, text, text_length);    /* The dissector doesn't need NULL-terminated strings */

        /* We'll write this as a WS UPPER PDU packet with a text blob */
        blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_WIRESHARK_UPPER_PDU, 0, UINT16_MAX, (uint32_t)ws_buffer_length(&params->rec->data), (uint32_t)ws_buffer_length(&params->rec->data));
        g_free(text);
        if (info_line) {
            g_free(info_line);
        }
        return apptextheader.source;
    }
    default:
        g_free(text);
        return BLF_APPTEXT_CHANNEL; /* Cheat - no block to write */;
    }
    return BLF_APPTEXT_CHANNEL; /* Cheat - no block to write */
}

static bool
blf_read_ethernet_status(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp, uint16_t object_version) {
    blf_ethernet_status_t            ethernet_status_header;
    uint8_t tmpbuf[24];
    uint64_t linkUpDuration;

    if (object_length < (data_start - block_start) + (int)sizeof(ethernet_status_header) + (int)(object_version >= 1 ? 8 : 0)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: ETHERNET_STATUS: not enough bytes for ethernet status header in object");
        ws_debug("not enough bytes for ethernet status header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &ethernet_status_header, sizeof(ethernet_status_header), err, err_info)) {
        ws_debug("not enough bytes for ethernet_status_header header in file");
        return false;
    }

    if (object_version >= 1) {
        if (!blf_read_bytes(params, data_start + sizeof(ethernet_status_header), &linkUpDuration, 8, err, err_info)) {
            ws_debug("not enough bytes for ethernet_status_header header in file");
            return false;
        }
        linkUpDuration = GUINT64_FROM_LE(linkUpDuration);
    }

    fix_endianness_blf_ethernet_status_header(&ethernet_status_header);

    phtonu16(tmpbuf, ethernet_status_header.channel);
    phtonu16(tmpbuf + 2, ethernet_status_header.flags);
    tmpbuf[4] = (ethernet_status_header.linkStatus);
    tmpbuf[5] = (ethernet_status_header.ethernetPhy);
    tmpbuf[6] = (ethernet_status_header.duplex);
    tmpbuf[7] = (ethernet_status_header.mdi);
    tmpbuf[8] = (ethernet_status_header.connector);
    tmpbuf[9] = (ethernet_status_header.clockMode);
    tmpbuf[10] = (ethernet_status_header.pairs);
    tmpbuf[11] = (ethernet_status_header.hardwareChannel);
    phtonu32(tmpbuf + 12, ethernet_status_header.bitrate);

    if (object_version >= 1) {
        phtonu64(tmpbuf + 16, linkUpDuration);
    }

    wtap_buffer_append_epdu_string(&params->rec->data, EXP_PDU_TAG_DISSECTOR_NAME, BLF_APPTEXT_TAG_DISS_ETHSTATUS);
    wtap_buffer_append_epdu_end(&params->rec->data);

    ws_buffer_append(&params->rec->data, tmpbuf, (size_t)(object_version >= 1 ? 24 : 16));

    /* We'll write this as a WS UPPER PDU packet with a data blob */
    /* This will create an interface with the "name" of the matching
     * WTAP_ENCAP_ETHERNET interface with the same channel and hardware
     * channel prefixed with "STATUS" and with a different interface ID,
     * because IDBs in pcapng can only have one linktype.
     * The other option would be to write everything as UPPER_PDU, including
     * the Ethernet data (with one of the "eth_" dissectors.)
     */
    char* iface_name = ws_strdup_printf("STATUS-ETH-%u-%u", ethernet_status_header.channel, ethernet_status_header.hardwareChannel);
    blf_lookup_interface(params, WTAP_ENCAP_WIRESHARK_UPPER_PDU, ethernet_status_header.channel, ethernet_status_header.hardwareChannel, iface_name);
    g_free(iface_name);
    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_WIRESHARK_UPPER_PDU, ethernet_status_header.channel, ethernet_status_header.hardwareChannel, (uint32_t)ws_buffer_length(&params->rec->data), (uint32_t)ws_buffer_length(&params->rec->data));

    if ((ethernet_status_header.flags & BLF_ETH_STATUS_HARDWARECHANNEL) == BLF_ETH_STATUS_HARDWARECHANNEL) {
        /* If HW channel valid */
        wtap_block_add_uint32_option(params->rec->block, OPT_PKT_QUEUE, ethernet_status_header.hardwareChannel);
    }

    return true;
}

static bool
blf_read_ethernet_phystate(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_ethernet_phystate_t ethernet_phystate_header;
    uint8_t tmpbuf[8];

    if (object_length < (data_start - block_start) + (int)sizeof(ethernet_phystate_header)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: ETHERNET_PHY_STATE: not enough bytes for ethernet phystate header in object");
        ws_debug("not enough bytes for ethernet phystate header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &ethernet_phystate_header, sizeof(ethernet_phystate_header), err, err_info)) {
        ws_debug("not enough bytes for ethernet phystate header in file");
        return false;
    }

    fix_endianness_blf_ethernet_phystate_header(&ethernet_phystate_header);

    phtonu16(tmpbuf, ethernet_phystate_header.channel);
    phtonu16(tmpbuf + 2, ethernet_phystate_header.flags);
    tmpbuf[4] = (ethernet_phystate_header.phyState);
    tmpbuf[5] = (ethernet_phystate_header.phyEvent);
    tmpbuf[6] = (ethernet_phystate_header.hardwareChannel);
    tmpbuf[7] = (ethernet_phystate_header.res1);

    wtap_buffer_append_epdu_string(&params->rec->data, EXP_PDU_TAG_DISSECTOR_NAME, BLF_APPTEXT_TAG_DISS_ETHPHYSTATUS);
    wtap_buffer_append_epdu_end(&params->rec->data);

    ws_buffer_append(&params->rec->data, tmpbuf, sizeof(tmpbuf));

    /* We'll write this as a WS UPPER PDU packet with a data blob */
    /* This will create an interface with the "name" of the matching
     * WTAP_ENCAP_ETHERNET interface with the same channel and hardware
     * channel prefixed with "STATUS" and with a different interface ID,
     * because IDBs in pcapng can only have one linktype.
     * The other option would be to write everything as UPPER_PDU, including
     * the Ethernet data (with one of the "eth_" dissectors.)
     */
    char* iface_name = ws_strdup_printf("STATUS-ETH-%u-%u", ethernet_phystate_header.channel, ethernet_phystate_header.hardwareChannel);
    blf_lookup_interface(params, WTAP_ENCAP_WIRESHARK_UPPER_PDU, ethernet_phystate_header.channel, ethernet_phystate_header.hardwareChannel, iface_name);
    g_free(iface_name);
    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_WIRESHARK_UPPER_PDU, ethernet_phystate_header.channel, ethernet_phystate_header.hardwareChannel, (uint32_t)ws_buffer_length(&params->rec->data), (uint32_t)ws_buffer_length(&params->rec->data));

    if ((ethernet_phystate_header.flags & BLF_PHY_STATE_HARDWARECHANNEL) == BLF_PHY_STATE_HARDWARECHANNEL) {
        /* If HW channel valid */
        wtap_block_add_uint32_option(params->rec->block, OPT_PKT_QUEUE, ethernet_phystate_header.hardwareChannel);
    }

    return true;
}

static bool
blf_read_block(blf_params_t *params, int64_t start_pos, int *err, char **err_info) {
    blf_blockheader_t        header;
    blf_logobjectheader_t    logheader;
    blf_logobjectheader2_t   logheader2;
    blf_logobjectheader3_t   logheader3;
    uint32_t                 flags;
    uint64_t                 object_timestamp;
    uint16_t                 object_version;
    blf_metadata_info_t      metadata_info = { 0, 0, false };
    int64_t                  last_metadata_start = 0;

    while (1) {
        /* Find Object */

        /* Resetting buffer */
        params->rec->data.first_free = params->rec->data.start;

        while (1) {
            if (!blf_read_bytes_or_eof(params, start_pos, &header, sizeof header, err, err_info)) {
                ws_debug("not enough bytes for block header or unsupported file");
                if (*err == WTAP_ERR_SHORT_READ) {
                    /* we have found the end that is not a short read therefore. */
                    *err = 0;
                    g_free(*err_info);
                    *err_info = NULL;
                }
                return false;
            }

            fix_endianness_blf_blockheader(&header);

            if (memcmp(header.magic, blf_obj_magic, sizeof(blf_obj_magic))) {
                ws_debug("object magic is not LOBJ (pos: 0x%" PRIx64 ")", start_pos);
            } else {
                break;
            }

            /* we are moving back and try again but 1 byte later */
            /* TODO: better understand how this paddings works... */
            start_pos++;
        }
        params->blf_data->start_of_last_obj = start_pos;

        if (!params->random) {
            /* Make sure that we start after this object next time,
             * but only if it's a linear read. We can have random reads
             * during the linear read, so we have to make sure we don't
             * lose track of our position.
             */
            params->blf_data->current_real_seek_pos = start_pos + MAX(MAX(16, header.object_length), header.header_length);
        }

        switch (header.header_type) {
        case BLF_HEADER_TYPE_DEFAULT:
            if (!blf_read_log_object_header(params, err, err_info, start_pos + sizeof(blf_blockheader_t), start_pos + header.header_length, &logheader)) {
                return false;
            }
            flags = logheader.flags;
            object_timestamp = logheader.object_timestamp;
            object_version = logheader.object_version;
            break;

        case BLF_HEADER_TYPE_2:
            if (!blf_read_log_object_header2(params, err, err_info, start_pos + sizeof(blf_blockheader_t), start_pos + header.header_length, &logheader2)) {
                return false;
            }
            flags = logheader2.flags;
            object_timestamp = logheader2.object_timestamp;
            object_version = logheader2.object_version;
            break;

        case BLF_HEADER_TYPE_3:
            if (!blf_read_log_object_header3(params, err, err_info, start_pos + sizeof(blf_blockheader_t), start_pos + header.header_length, &logheader3)) {
                return false;
            }
            flags = logheader3.flags;
            object_timestamp = logheader3.object_timestamp;
            object_version = logheader3.object_version;
            break;

        default:
            *err = WTAP_ERR_UNSUPPORTED;
            *err_info = ws_strdup_printf("blf: unknown header type %u", header.header_type);
            ws_debug("unknown header type");
            return false;
        }

        if (metadata_info.valid && header.object_type != BLF_OBJTYPE_APP_TEXT) {
            /* If we're in the middle of a sequence of AppText metadata objects,
             * but we get an AppText object from another source,
             * skip the previous incomplete packet and start fresh.
             */
            metadata_info.valid = false;
        }

        switch (header.object_type) {
        case BLF_OBJTYPE_LOG_CONTAINER:
            *err = WTAP_ERR_UNSUPPORTED;
            *err_info = ws_strdup("blf: log container in log container not supported");
            ws_debug("log container in log container not supported");
            return false;

        case BLF_OBJTYPE_ETHERNET_FRAME:
            return blf_read_ethernetframe(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_ETHERNET_FRAME_EX:
            return blf_read_ethernetframe_ext(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, false);

        case BLF_OBJTYPE_ETHERNET_RX_ERROR:
            return blf_read_ethernet_rxerror(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_ETHERNET_ERROR_EX:
            return blf_read_ethernetframe_ext(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, true);

        case BLF_OBJTYPE_WLAN_FRAME:
            return blf_read_wlanframe(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_CAN_MESSAGE:
            return blf_read_canmessage(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, false);

        case BLF_OBJTYPE_CAN_ERROR:
            return blf_read_canerror(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, false);

        case BLF_OBJTYPE_CAN_OVERLOAD:
            return blf_read_canerror(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, true);

        case BLF_OBJTYPE_CAN_MESSAGE2:
            return blf_read_canmessage(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, true);

        case BLF_OBJTYPE_CAN_ERROR_EXT:
            return blf_read_canerrorext(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_CAN_FD_MESSAGE:
            return blf_read_canfdmessage(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_CAN_FD_MESSAGE_64:
            return blf_read_canfdmessage64(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_CAN_FD_ERROR_64:
            return blf_read_canfderror64(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_CAN_XL_CHANNEL_FRAME:
            return blf_read_canxlchannelframe(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_FLEXRAY_DATA:
            return blf_read_flexraydata(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_FLEXRAY_MESSAGE:
            return blf_read_flexraymessage(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_FLEXRAY_RCVMESSAGE:
            return blf_read_flexrayrcvmessageex(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, false);

        case BLF_OBJTYPE_FLEXRAY_RCVMESSAGE_EX:
            return blf_read_flexrayrcvmessageex(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, true);

        case BLF_OBJTYPE_LIN_MESSAGE:
            return blf_read_linmessage(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, false);

        case BLF_OBJTYPE_LIN_CRC_ERROR:
            return blf_read_linmessage(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, true);

        case BLF_OBJTYPE_LIN_RCV_ERROR:
            return blf_read_linrcverror(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_LIN_SND_ERROR:
            return blf_read_linsenderror(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_LIN_WAKEUP:
            return blf_read_linwakeupevent(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_LIN_MESSAGE2:
            return blf_read_linmessage2(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, object_version);

        case BLF_OBJTYPE_LIN_CRC_ERROR2:
            return blf_read_lincrcerror2(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, object_version);

        case BLF_OBJTYPE_LIN_RCV_ERROR2:
            return blf_read_linrcverror2(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, object_version);

        case BLF_OBJTYPE_LIN_SND_ERROR2:
            return blf_read_linsenderror2(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, object_version);

        case BLF_OBJTYPE_LIN_WAKEUP2:
            return blf_read_linwakeupevent2(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_LIN_SLEEP:
            return blf_read_linsleepmodeevent(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_APP_TEXT:
        {
            int result = blf_read_apptextmessage(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, &metadata_info);
            if (result == BLF_APPTEXT_CONT) {
                if (!metadata_info.valid) {
                    /* First object of a sequence, save its start position */
                    last_metadata_start = start_pos;
                    metadata_info.valid = true;
                }
                /* Save a pointer to the end of the buffer */
                metadata_info.metadata_cont = params->rec->data.first_free;
            } else {
                if (result == BLF_APPTEXT_METADATA && metadata_info.valid) {
                    /* Last object of a sequence, restore the start position of the first object */
                    params->blf_data->start_of_last_obj = last_metadata_start;
                }
                /* Reset everything and start fresh */
                metadata_info.valid = false;
            }
            switch (result) {
                case BLF_APPTEXT_FAILED:
                    return false;
                case BLF_APPTEXT_COMMENT:
                case BLF_APPTEXT_METADATA:
                case BLF_APPTEXT_ATTACHMENT:
                case BLF_APPTEXT_TRACELINE:
                    return true;
                case BLF_APPTEXT_CHANNEL:
                case BLF_APPTEXT_CONT:
                default:
                    /* we do not return since there is no packet to show here */
                    start_pos += MAX(MAX(16, header.object_length), header.header_length);
                    break;
            }
        }
            break;

        case BLF_OBJTYPE_ETHERNET_STATUS:
            return blf_read_ethernet_status(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, object_version);

        case BLF_OBJTYPE_ETHERNET_PHY_STATE:
            return blf_read_ethernet_phystate(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp);

        case BLF_OBJTYPE_ENV_INTEGER:
        case BLF_OBJTYPE_ENV_DOUBLE:
        case BLF_OBJTYPE_ENV_STRING:
        case BLF_OBJTYPE_ENV_DATA:
        case BLF_OBJTYPE_SYS_VARIABLE:
        case BLF_OBJTYPE_RESERVED5: /* Despite the name, this is actually used. Maybe it's worth investigating the content. */
        case BLF_OBJTYPE_TEST_STRUCTURE:
            ws_debug("skipping unsupported object type 0x%04x", header.object_type);
            start_pos += MAX(MAX(16, header.object_length), header.header_length);
            break;
        default:
            ws_info("unknown object type 0x%04x", header.object_type);
            start_pos += MAX(MAX(16, header.object_length), header.header_length);
            break;
        }
    }
    return true;
}

static bool blf_read(wtap *wth, wtap_rec *rec, int *err, char **err_info, int64_t *data_offset) {
    blf_params_t blf_tmp;

    blf_tmp.wth = wth;
    blf_tmp.fh  = wth->fh;
    blf_tmp.random = false;
    blf_tmp.pipe = wth->ispipe;
    blf_tmp.rec = rec;
    blf_tmp.blf_data = (blf_t *)wth->priv;

    if (!blf_read_block(&blf_tmp, blf_tmp.blf_data->current_real_seek_pos, err, err_info)) {
        return false;
    }
    *data_offset = blf_tmp.blf_data->start_of_last_obj;

    return true;
}

static bool blf_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec, int *err, char **err_info) {
    blf_params_t blf_tmp;

    blf_tmp.wth = wth;
    blf_tmp.fh  = wth->random_fh;
    blf_tmp.random = true;
    blf_tmp.pipe = wth->ispipe;
    blf_tmp.rec = rec;
    blf_tmp.blf_data = (blf_t *)wth->priv;

    if (!blf_read_block(&blf_tmp, seek_off, err, err_info)) {
        ws_debug("couldn't read packet block (err=%d).", *err);
        return false;
    }

    return true;
}

static void blf_free(blf_t *blf) {
    if (blf != NULL) {
        if (blf->log_containers != NULL) {
            for (unsigned i = 0; i < blf->log_containers->len; i++) {
                blf_log_container_t* log_container = &g_array_index(blf->log_containers, blf_log_container_t, i);
                if (log_container->real_data != NULL) {
                    g_free(log_container->real_data);
                }
            }
            g_array_free(blf->log_containers, true);
            blf->log_containers = NULL;
        }
        if (blf->channel_to_iface_ht != NULL) {
            g_hash_table_destroy(blf->channel_to_iface_ht);
            blf->channel_to_iface_ht = NULL;
        }
        if (blf->channel_to_name_ht != NULL) {
            g_hash_table_destroy(blf->channel_to_name_ht);
            blf->channel_to_name_ht = NULL;
        }
    }
}

static void blf_close(wtap *wth) {
    blf_free((blf_t *)wth->priv);

    /* TODO: do we need to reverse the wtap_add_idb? how? */
}

wtap_open_return_val
blf_open(wtap *wth, int *err, char **err_info) {
    blf_fileheader_t  header;
    blf_t            *blf;

    ws_debug("opening file");

    if (!wtap_read_bytes_or_eof(wth->fh, &header, sizeof(blf_fileheader_t), err, err_info)) {

        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ) {
            /*
             * Short read or EOF.
             *
             * We're reading this as part of an open, so
             * the file is too short to be a blf file.
             */
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
            return WTAP_OPEN_NOT_MINE;
        }
        return WTAP_OPEN_ERROR;
    }

    fix_endianness_blf_fileheader(&header);

    if (memcmp(header.magic, blf_magic, sizeof(blf_magic))) {
        return WTAP_OPEN_NOT_MINE;
    }

    /* This seems to be an BLF! */
    /* Check for a valid header length */
    if (header.header_length < sizeof(blf_fileheader_t)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("blf: file header length too short");
        return WTAP_OPEN_ERROR;
    }

    /* skip past the header, which may include padding/reserved space */
    if (!wtap_read_bytes(wth->fh, NULL, header.header_length - sizeof(blf_fileheader_t), err, err_info)) {
        return WTAP_OPEN_ERROR;
    }

    /* Prepare our private context. */
    blf = g_new(blf_t, 1);
    blf->log_containers = g_array_new(false, false, sizeof(blf_log_container_t));
    blf->current_real_seek_pos = 0;
    blf->start_offset_ns = blf_data_to_ns(&header.start_date);
    blf->end_offset_ns = blf_data_to_ns(&header.end_date);

    blf->channel_to_iface_ht = g_hash_table_new_full(g_int64_hash, g_int64_equal, &blf_free_key, &blf_free_channel_to_iface_entry);
    blf->channel_to_name_ht = g_hash_table_new_full(g_int64_hash, g_int64_equal, &blf_free_key, &blf_free_channel_to_name_entry);
    blf->next_interface_id = 0;

    wth->priv = (void *)blf;
    wth->file_encap = WTAP_ENCAP_NONE;
    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_UNKNOWN;
    wth->file_start_ts.secs = blf->start_offset_ns / (1000 * 1000 * 1000);
    wth->file_start_ts.nsecs = blf->start_offset_ns % (1000 * 1000 * 1000);
    wth->file_end_ts.secs = blf->end_offset_ns / (1000 * 1000 * 1000);
    wth->file_end_ts.nsecs = blf->end_offset_ns % (1000 * 1000 * 1000);
    wth->subtype_read = blf_read;
    wth->subtype_seek_read = blf_seek_read;
    wth->subtype_close = blf_close;
    wth->file_type_subtype = blf_file_type_subtype;

    wtap_block_t block = wtap_block_create(WTAP_BLOCK_SECTION);
    wtapng_section_mandatory_t *shb_mand = (wtapng_section_mandatory_t *)wtap_block_get_mandatory_data(block);
    shb_mand->section_length = UINT64_MAX;

    wtap_block_add_string_option_format(block, OPT_SHB_USERAPPL, "%s %d.%d.%d", try_val_to_str(header.application, blf_application_names),
                                        header.application_major, header.application_minor, header.application_build);
    wtap_block_copy(g_array_index(wth->shb_hdrs, wtap_block_t, 0), block);
    wtap_block_unref(block);

    return WTAP_OPEN_MINE;
}

/* Options for interface blocks. */
static const struct supported_option_type interface_block_options_supported[] = {
    /* No comments, just an interface name. */
    { OPT_IDB_NAME, ONE_OPTION_SUPPORTED }
};

static const struct supported_block_type blf_blocks_supported[] = {
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED },
    { WTAP_BLOCK_IF_ID_AND_INFO, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(interface_block_options_supported) },
};


/***********************/
/* BLF Writing Support */
/***********************/

/* 10MB = 10485760 */
#define LOG_CONTAINER_BUFFER_SIZE 10485760

#define LOG_CONTAINER_NONE UINT64_MAX

typedef struct _blf_writer_data {
    GArray *iface_to_channel_array;
    bool iface_to_channel_names_recovered;

    blf_fileheader_t *fileheader;
    uint32_t object_count;
    uint64_t start_time;
    bool start_time_set;
    uint64_t end_time;

    uint64_t logcontainer_start;
    blf_blockheader_t logcontainer_block_header;
    blf_logcontainerheader_t logcontainer_header;
} blf_writer_data_t;

static void
blf_dump_init_channel_to_iface_entry(blf_channel_to_iface_entry_t* tmp, unsigned int if_id) {
    tmp->channel = 0;
    tmp->hwchannel = UINT16_MAX;
    tmp->interface_id = if_id;
    tmp->pkt_encap = WTAP_ENCAP_NONE;
}

static void
blf_dump_expand_interface_mapping(wtap_dumper *wdh, int new_size) {
    blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;

    int old_size = writer_data->iface_to_channel_array->len;

    if (old_size < new_size) {
        /* we need to expand array */
        unsigned int number_of_new_elements = new_size - old_size;

        blf_channel_to_iface_entry_t *newdata = g_new0(blf_channel_to_iface_entry_t, number_of_new_elements);
        g_array_append_vals(writer_data->iface_to_channel_array, newdata, number_of_new_elements);

        for (unsigned int i = old_size; i < writer_data->iface_to_channel_array->len; i++) {
            blf_channel_to_iface_entry_t *tmp = &g_array_index(writer_data->iface_to_channel_array, blf_channel_to_iface_entry_t, i);
            blf_dump_init_channel_to_iface_entry(tmp, i);
        }
    }
}

static bool
blf_dump_set_interface_mapping(wtap_dumper *wdh, uint32_t interface_id, int pkt_encap, uint16_t channel, uint16_t hw_channel) {
    if (channel == 0) {
        ws_warning("Trying to set channel to 0! That will probably lead to an unreadable file! Replacing by 1 to limit problem!");
        channel = 1;
    }

    blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;

    blf_dump_expand_interface_mapping(wdh, interface_id + 1);

    blf_channel_to_iface_entry_t *tmp = &g_array_index(writer_data->iface_to_channel_array, blf_channel_to_iface_entry_t, interface_id);
    tmp->channel = channel;
    tmp->hwchannel = hw_channel;
    tmp->interface_id = interface_id;
    tmp->pkt_encap = pkt_encap;

    return true;
}

static blf_channel_to_iface_entry_t *
blf_dump_get_interface_mapping(wtap_dumper *wdh, const wtap_rec *rec, int *err, char **err_info) {
    blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;

    uint32_t interface_id = rec->rec_header.packet_header.interface_id;
    if (interface_id < writer_data->iface_to_channel_array->len) {
        return &g_array_index(writer_data->iface_to_channel_array, blf_channel_to_iface_entry_t, interface_id);
    }

    *err = WTAP_ERR_INTERNAL;
    *err_info = ws_strdup_printf("blf: cannot find interface mapping for %u", interface_id);
    ws_critical("BLF Interface Mapping cannot be found!");

    return NULL;
}

static bool
blf_init_file_header(wtap_dumper *wdh, int *err) {
    if (wdh == NULL || wdh->priv == NULL) {
        *err = WTAP_ERR_INTERNAL;
        ws_debug("internal error: blf private data not found!");
        return false;
    }

    blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;

    writer_data->fileheader = g_new0(blf_fileheader_t, 1);

    /* set magic */
    int i;
    for (i = 0; i < 4; i++) {
        writer_data->fileheader->magic[i] = blf_magic[i];
    }

    /* currently only support 144 byte length*/
    writer_data->fileheader->header_length = 144;

    writer_data->fileheader->application_major = WIRESHARK_VERSION_MAJOR;
    writer_data->fileheader->application_minor = WIRESHARK_VERSION_MINOR;
    writer_data->fileheader->application_build = WIRESHARK_VERSION_MICRO;

    return true;
}

static bool
blf_write_add_padding(wtap_dumper *wdh, int *err, uint8_t count) {
    if (count > 0 && count < 4) {
        uint8_t padding[3] = { 0 };
        if (!wtap_dump_file_write(wdh, &padding, count, err)) {
            return false;
        }
    }
    return true;
}

static bool
blf_write_file_header_zeros(wtap_dumper *wdh, int *err) {
    /* lets add 144 bytes for the header and padding */
    uint8_t padding[144] = { 0 };
    if (!wtap_dump_file_write(wdh, &padding, 144, err)) {
        return false;
    }

    return true;
}

static void
blf_write_date_to_blf_header(blf_fileheader_t *fileheader, bool start, uint64_t ns_timestamp) {
    struct tm tmp;
    const time_t date = (time_t)(ns_timestamp / (1000 * 1000 * 1000));

    if (ws_localtime_r(&date, &tmp) != NULL) {
        blf_date_t *target = start ? &(fileheader->start_date) : &(fileheader->end_date);
        target->year = 1900 + tmp.tm_year;
        target->month = tmp.tm_mon + 1;
        target->day = tmp.tm_mday;
        target->hour = tmp.tm_hour;
        target->mins = tmp.tm_min;
        target->sec = tmp.tm_sec;

        uint64_t tmp_date = blf_data_to_ns((const blf_date_t *)target);

        target->ms = (uint16_t)((ns_timestamp - tmp_date) / (1000 * 1000));
    }

}

static bool
blf_finalize_file_header(wtap_dumper *wdh, int *err) {
    blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;
    blf_fileheader_t *fileheader = writer_data->fileheader;
    int64_t bytes_written = wtap_dump_file_tell(wdh, err);

    /* update the header and convert all to LE */
    fileheader->api_version = (((WIRESHARK_VERSION_MAJOR * 100) + WIRESHARK_VERSION_MINOR) * 100 + WIRESHARK_VERSION_MICRO) * 100;
    fileheader->application_major = WIRESHARK_VERSION_MAJOR;
    fileheader->application_minor = WIRESHARK_VERSION_MINOR;
    fileheader->application_build = WIRESHARK_VERSION_MICRO;

    fileheader->len_compressed = (uint64_t)bytes_written;
    fileheader->len_uncompressed = (uint64_t)bytes_written;

    fileheader->obj_count = writer_data->object_count;

    if (writer_data->start_time_set) {
        blf_write_date_to_blf_header(fileheader, true, writer_data->start_time);
    }

    blf_write_date_to_blf_header(fileheader, false, writer_data->end_time);

    fix_endianness_blf_fileheader(fileheader);

    /* seek to start of file */
    int64_t tmp = wtap_dump_file_seek(wdh, 0, SEEK_SET, err);
    if (*err != 0 || tmp != 0) {
        return false;
    }

    if (!wtap_dump_file_write(wdh, fileheader, fileheader->header_length, err)) {
        return false;
    }

    return true;
}

static bool blf_dump_write_logcontainer(wtap_dumper *wdh, int *err, char **err_info) {
    blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;

    if (!wtap_dump_file_write(wdh, &(writer_data->logcontainer_block_header), sizeof(blf_blockheader_t), err)) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf: cannot write Log Container Block Header");
        ws_warning("Cannot write Log Container Block Header");
        return false;
    }

    if (!wtap_dump_file_write(wdh, &(writer_data->logcontainer_header), sizeof(blf_logcontainerheader_t), err)) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf: cannot write Log Container");
        ws_warning("Cannot write Log Container");
        return false;
    }

    return true;
}

static bool blf_dump_close_logcontainer(wtap_dumper *wdh, int *err, char **err_info) {
    blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;

    int64_t current_position = wtap_dump_file_tell(wdh, err);

    int64_t tmp = wtap_dump_file_seek(wdh, writer_data->logcontainer_start, SEEK_SET, err);
    if (*err != 0 || tmp != 0) {
        return false;
    }

    int64_t logcontainer_length = current_position - writer_data->logcontainer_start;
    if (logcontainer_length < 32) {
        *err = WTAP_ERR_INTERNAL;
    }
    writer_data->logcontainer_block_header.object_length = GUINT32_TO_LE((uint32_t)logcontainer_length);
    writer_data->logcontainer_header.uncompressed_size = GUINT32_TO_LE((uint32_t)(logcontainer_length - 32));

    if (!blf_dump_write_logcontainer(wdh, err, err_info)) {
        return false;
    }

    tmp = wtap_dump_file_seek(wdh, current_position, SEEK_SET, err);
    if (*err != 0 || tmp != 0) {
        return false;
    }

    return true;
}

static bool blf_dump_start_logcontainer(wtap_dumper *wdh, int *err, char **err_info) {
    blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;

    if (writer_data->logcontainer_start != LOG_CONTAINER_NONE) {
        if (!blf_dump_close_logcontainer(wdh, err, err_info)) {
            return false;
        }
    }

    /* start new log container */
    /* set magic */
    int i;
    for (i = 0; i < 4; i++) {
        writer_data->logcontainer_block_header.magic[i] = blf_obj_magic[i];
    }
    writer_data->logcontainer_block_header.header_length = 16;
    writer_data->logcontainer_block_header.header_type = 1;
    writer_data->logcontainer_block_header.object_length = 32;
    writer_data->logcontainer_block_header.object_type = BLF_OBJTYPE_LOG_CONTAINER;
    fix_endianness_blf_blockheader(&(writer_data->logcontainer_block_header));

    writer_data->logcontainer_header.compression_method = 0;
    writer_data->logcontainer_header.res1 = 0;
    writer_data->logcontainer_header.res2 = 0;
    writer_data->logcontainer_header.uncompressed_size = 0;
    writer_data->logcontainer_header.res4 = 0;
    fix_endianness_blf_logcontainerheader(&(writer_data->logcontainer_header));

    writer_data->logcontainer_start = wtap_dump_file_tell(wdh, err);

    return blf_dump_write_logcontainer(wdh, err, err_info);
}

static bool blf_dump_check_logcontainer_full(wtap_dumper *wdh, int *err, char **err_info, uint32_t length) {
    const blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;

    uint64_t position = (uint64_t)wtap_dump_file_tell(wdh, err);
    if (position - writer_data->logcontainer_start + length <= LOG_CONTAINER_BUFFER_SIZE) {
        return true;
    }

    return blf_dump_start_logcontainer(wdh, err, err_info);
}

static bool blf_dump_objheader(wtap_dumper *wdh, int *err, uint64_t obj_timestamp, uint32_t obj_type, uint32_t obj_length) {
    blf_logobjectheader_t logheader;
    logheader.flags = BLF_TIMESTAMP_RESOLUTION_1NS;
    logheader.client_index = 0;
    logheader.object_version = 1;
    logheader.object_timestamp = obj_timestamp;
    fix_endianness_blf_logobjectheader(&logheader);

    blf_blockheader_t blockheader;
    /* set magic */
    int i;
    for (i = 0; i < 4; i++) {
        blockheader.magic[i] = blf_obj_magic[i];
    }
    blockheader.header_length = sizeof(blf_blockheader_t) + sizeof(blf_logobjectheader_t);
    blockheader.header_type = 1;
    blockheader.object_length = sizeof(blf_blockheader_t) + sizeof(blf_logobjectheader_t) + obj_length;
    blockheader.object_type = obj_type;
    fix_endianness_blf_blockheader(&blockheader);

    if (!wtap_dump_file_write(wdh, &(blockheader), sizeof(blf_blockheader_t), err)) {
        return false;
    }

    if (!wtap_dump_file_write(wdh, &(logheader), sizeof(blf_logobjectheader_t), err)) {
        return false;
    }

    return true;
}

/* return standard direction format of BLF, RX on error or unknown */
static uint8_t blf_get_direction(const wtap_rec *rec) {
    uint32_t tmp_direction = 0;
    if (WTAP_OPTTYPE_SUCCESS != wtap_block_get_uint32_option_value(rec->block, OPT_PKT_FLAGS, &tmp_direction)) {
        return BLF_DIR_RX;
    }

    if (tmp_direction == PACK_FLAGS_DIRECTION_OUTBOUND) {
        return BLF_DIR_TX;

    }

    return BLF_DIR_RX;
}

static bool blf_dump_ethernet(wtap_dumper *wdh, const wtap_rec *rec, int *err, char **err_info, uint64_t obj_timestamp) {
    /* LINKTYPE_ETHERNET */
    /* https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html */

    //blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;
    const blf_channel_to_iface_entry_t *iface_entry = blf_dump_get_interface_mapping(wdh, rec, err, err_info);

    const uint8_t *pd = ws_buffer_start_ptr(&rec->data);
    size_t length = ws_buffer_length(&rec->data);

    /* 14 bytes is the full Ethernet Header up to EtherType */
    if (length < 14) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf: record length %u for Ethernet message is lower than minimum of 14", (uint32_t)length);
        ws_warning("LINKTYPE_ETHERNET Data is too short!");
        return false;
    }

    uint32_t offset = 12;

    blf_ethernetframeheader_t ethheader;
    ethheader.src_addr[0] = pd[6];
    ethheader.src_addr[1] = pd[7];
    ethheader.src_addr[2] = pd[8];
    ethheader.src_addr[3] = pd[9];
    ethheader.src_addr[4] = pd[10];
    ethheader.src_addr[5] = pd[11];

    ethheader.channel = iface_entry->channel;

    ethheader.dst_addr[0] = pd[0];
    ethheader.dst_addr[1] = pd[1];
    ethheader.dst_addr[2] = pd[2];
    ethheader.dst_addr[3] = pd[3];
    ethheader.dst_addr[4] = pd[4];
    ethheader.dst_addr[5] = pd[5];

    ethheader.direction = blf_get_direction(rec);

    uint16_t eth_type = pntohu16(pd + offset);
    offset += 2;

    if (eth_type == 0x8100 || eth_type == 0x9100 || eth_type == 0x88a8) {
        ethheader.tpid = eth_type;
        ethheader.tci = pntohu16(pd + offset);
        offset += 2;

        eth_type = pntohu16(pd + offset);
        offset += 2;
    } else {
        ethheader.tpid = 0;
        ethheader.tci = 0;
    }

    ethheader.ethtype = eth_type;
    ethheader.payloadlength = rec->rec_header.packet_header.caplen - offset;
    ethheader.res = 0;
    fix_endianness_blf_ethernetframeheader(&ethheader);

    if (!blf_dump_objheader(wdh, err, obj_timestamp, BLF_OBJTYPE_ETHERNET_FRAME, sizeof(blf_ethernetframeheader_t) + ethheader.payloadlength)) {
        return false;
    }

    if (!wtap_dump_file_write(wdh, &(ethheader), sizeof(blf_ethernetframeheader_t), err)) {
        return false;
    }

    if (!wtap_dump_file_write(wdh, &(pd[offset]), ethheader.payloadlength, err)) {
        return false;
    }

    /* Add strange padding to 4 bytes. */
    uint8_t padding_needed = (sizeof(blf_ethernetframeheader_t) + ethheader.payloadlength) % 4;
    return blf_write_add_padding(wdh, err, padding_needed);
}

static bool blf_dump_socketcanxl(wtap_dumper *wdh, const wtap_rec *rec, int *err _U_, char **err_info _U_, uint64_t obj_timestamp,
                                 const uint8_t *pd, size_t length, bool is_rx, bool is_tx) {
    /* LINKTYPE_CAN_SOCKETCAN */
    /* https://www.tcpdump.org/linktypes/LINKTYPE_CAN_SOCKETCAN.html */

    //blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;
    blf_channel_to_iface_entry_t *iface_entry = blf_dump_get_interface_mapping(wdh, rec, err, err_info);

    uint8_t  socketcan_vcid = pd[1];
    uint16_t socketcan_id = pntohu16(pd + 2) & CAN_SFF_MASK;
    uint8_t  socketcan_flags = pd[4];
    uint8_t  socketcan_sdut = pd[5];
    uint16_t socketcan_payload_length = pletohu16(pd + 6);

    if ((socketcan_flags & CANXL_XLF) != CANXL_XLF) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf: Socket CAN XL message does not have XL Flag set!");
        ws_error("LINKTYPE_CAN_SOCKETCAN CAN XL flag not set for CAN XL?");
        return false;
    }

    if (length < (size_t)socketcan_payload_length + 12) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf: Socket CAN message (length %u) does not contain full payload (%u) (CAN XL)", (uint32_t)length, socketcan_payload_length);
        ws_error("LINKTYPE_CAN_SOCKETCAN header is too short (CAN XL)!");
        return false;
    }
    uint32_t socketcan_acceptance_field = pletohu32(pd + 8);

    /* LINKTYPE_LINUX_SLL would have set is_tx or is_rx */
    uint8_t frame_dir = is_tx ? BLF_DIR_TX : BLF_DIR_RX;
    if (!is_rx && !is_tx) {
        frame_dir = blf_get_direction(rec);
    }

    blf_canxlchannelframe_t canxl = {0};
    canxl.channel = (uint8_t)iface_entry->channel;
    canxl.dir = frame_dir;
    canxl.frameIdentifier = socketcan_id;
    canxl.serviceDataUnitType = socketcan_sdut;
    canxl.dlc = socketcan_payload_length - 1;
    canxl.dataLength = socketcan_payload_length;
    canxl.virtualControllerAreaNetChannelID = socketcan_vcid;
    canxl.acceptanceField = socketcan_acceptance_field;

    if ((socketcan_flags & CANXL_XLF) == CANXL_XLF) {
        /* should be always true but we might refactor */
        canxl.flags |= BLF_CANXLCHANNELFRAME_FLAG_XLF;
    }
    if ((socketcan_flags & CANXL_SEC) == CANXL_SEC) {
        canxl.flags |= BLF_CANXLCHANNELFRAME_FLAG_SEC;
    }
    if ((socketcan_flags & CANXL_RRS) == CANXL_RRS) {
        canxl.flags |= BLF_CANXLCHANNELFRAME_FLAG_RRS;
    }

    fix_endianness_blf_canxlchannelframe(&canxl);

    if (!blf_dump_objheader(wdh, err, obj_timestamp, BLF_OBJTYPE_CAN_XL_CHANNEL_FRAME, sizeof(blf_canxlchannelframe_t) + socketcan_payload_length)) {
        return false;
    }

    if (!wtap_dump_file_write(wdh, &(canxl), sizeof(blf_canxlchannelframe_t), err)) {
        return false;
    }

    if (!wtap_dump_file_write(wdh, &(pd[12]), socketcan_payload_length, err)) {
        return false;
    }

    return true;
}

static const uint8_t canfd_length_to_dlc[] = { 0, 1, 2, 3,   4, 5, 6, 7,   8, 0, 0, 0,  9, 0, 0, 0,
                                              10, 0, 0, 0,  11, 0, 0, 0,  12, 0, 0, 0,  0, 0, 0, 0,
                                              13, 0, 0, 0,   0, 0, 0, 0,   0, 0, 0, 0,  0, 0, 0, 0,
                                              14, 0, 0, 0,   0, 0, 0, 0,   0, 0, 0, 0,  0, 0, 0, 0,
                                              15 };

static bool blf_dump_socketcan(wtap_dumper *wdh, const wtap_rec *rec, int *err, char **err_info, uint64_t obj_timestamp,
                               const uint8_t *pd, size_t length, bool is_can, bool is_canfd, bool is_rx, bool is_tx) {
    /* LINKTYPE_CAN_SOCKETCAN */
    /* https://www.tcpdump.org/linktypes/LINKTYPE_CAN_SOCKETCAN.html */

    if (length < 8) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf: record length %u for Socket CAN message header is lower than minimum of 8", (uint32_t)length);
        ws_warning("LINKTYPE_CAN_SOCKETCAN header is too short!");
        return false;
    }

    /* check for CAN-XL */
    if ((pd[4] & CANXL_XLF) == CANXL_XLF) {
        return blf_dump_socketcanxl(wdh, rec, err, err_info, obj_timestamp, pd, length, is_rx, is_tx);
    }

    //blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;
    blf_channel_to_iface_entry_t *iface_entry = blf_dump_get_interface_mapping(wdh, rec, err, err_info);

    uint8_t payload_length = pd[4];

    if (length < (size_t)payload_length + 8) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf: Socket CAN message (length %u) does not contain full payload (%u)", (uint32_t)length, payload_length);
        ws_warning("LINKTYPE_CAN_SOCKETCAN header is too short!");
        return false;
    }

    /* LINKTYPE_LINUX_SLL would have set is_tx or is_rx */
    uint8_t frame_dir = is_tx ? BLF_DIR_TX : BLF_DIR_RX;
    if (!is_rx && !is_tx) {
        frame_dir = blf_get_direction(rec);
    }

    bool canfd = is_canfd;

    /* LINKTYPE_LINUX_SLL would have set one */
    if (!is_can && !is_canfd) {
        if ((pd[5] & CANFD_FDF) == CANFD_FDF) {
            canfd = true;
        } else {
            /* heuristic. if longer than header + 8 bytes data, its CAN-FD*/
            canfd = rec->rec_header.packet_header.caplen > 16;
        }
    }

    /* XXX endianness is not defined. Assuming BE as this seems the common choice*/
    uint32_t can_id = pntohu32(pd);

    /* lets check if can_id makes sense
     * 29bit CAN ID mask 0x1fffffff CAN_EFF_MASK
     * 11bit CAN ID mask 0x000007ff CAN_SFF_MASK
     * 29 only bits      0x1ffff800 CAN_EFF_MASK & !CAN_SFF_MASK
     */
    if (((can_id & CAN_EFF_FLAG) == 0) && ((can_id & (CAN_EFF_MASK & (!CAN_SFF_MASK))) != 0)) {
        ws_message("CAN-ID 0x%08x seems to be in wrong byte order, changing to little-endian", can_id);
        can_id = pletohu32(pd);
    }

    bool err_flag = (can_id & CAN_ERR_FLAG) == CAN_ERR_FLAG;
    bool rtr_flag = (can_id & CAN_RTR_FLAG) == CAN_RTR_FLAG;
    //bool ext_id_flag = (can_id & CAN_EFF_FLAG) == CAN_EFF_FLAG;
    can_id &= (CAN_EFF_MASK | CAN_EFF_FLAG);

    if (canfd) {
        /* CAN-FD */
        bool brs_flag = (pd[5] & CANFD_BRS) == CANFD_BRS;
        bool esi_flag = (pd[5] & CANFD_ESI) == CANFD_ESI;
        bool fdf_flag = (pd[5] & CANFD_FDF) == CANFD_FDF;

        blf_canfdmessage64_t canfdmsg;
        canfdmsg.channel = (uint8_t)iface_entry->channel;

        canfdmsg.dlc = (payload_length <= 64) ? canfd_length_to_dlc[payload_length] : 0;
        canfdmsg.validDataBytes = payload_length;
        canfdmsg.txCount = 0;
        canfdmsg.id = can_id;
        canfdmsg.frameLength_in_ns = 0;
        canfdmsg.flags = 0;

        /* TODO: fdf_flag is not always set for CAN-FD */
        if (fdf_flag) {
            canfdmsg.flags = BLF_CANFDMESSAGE64_FLAG_EDL; // CAN-FD
        } else {
            ws_warning("CAN-FD has not CANFD_FDF set. File not correct.");
        }
        if (brs_flag) {
            canfdmsg.flags |= BLF_CANFDMESSAGE64_FLAG_BRS;
        }
        if (esi_flag) {
            canfdmsg.flags |= BLF_CANFDMESSAGE64_FLAG_ESI;
        }

        canfdmsg.btrCfgArb = 0;
        canfdmsg.btrCfgData = 0;
        canfdmsg.timeOffsetBrsNs = 0;
        canfdmsg.timeOffsetCrcDelNs = 0;
        canfdmsg.bitCount = 0;
        canfdmsg.dir = frame_dir;
        canfdmsg.extDataOffset = 0;
        canfdmsg.crc = 0;

        fix_endianness_blf_canfdmessage64(&canfdmsg);

        if (!blf_dump_objheader(wdh, err, obj_timestamp, BLF_OBJTYPE_CAN_FD_MESSAGE_64, sizeof(blf_canfdmessage64_t) + payload_length)) {
            return false;
        }

        if (!wtap_dump_file_write(wdh, &(canfdmsg), sizeof(blf_canfdmessage64_t), err)) {
            return false;
        }
    } else {
        /* CAN */
        blf_canmessage_t canmsg;

        if (payload_length > 8) {
            ws_warning("CAN frames can only have up to 8 bytes of payload! We have %d bytes", payload_length);
            payload_length = 8;
        }

        canmsg.dlc = payload_length;
        canmsg.channel = iface_entry->channel;

        canmsg.flags = 0;
        if (frame_dir == BLF_DIR_TX) {
            canmsg.flags |= BLF_CANMESSAGE_FLAG_TX;
        }

        if (err_flag) {
            // TODO: we need to implement CAN ERROR, ignore for now
            return true;
            //canmsg.flags |= BLF_CANMESSAGE_FLAG_NERR; - NERR is not error
        }

        if (rtr_flag) {
            canmsg.flags |= BLF_CANMESSAGE_FLAG_RTR;
        }

        canmsg.id = can_id;

        fix_endianness_blf_canmessage(&canmsg);

        if (!blf_dump_objheader(wdh, err, obj_timestamp, BLF_OBJTYPE_CAN_MESSAGE, sizeof(blf_canmessage_t) + 8)) {
            return false;
        }

        if (!wtap_dump_file_write(wdh, &(canmsg), sizeof(blf_canmessage_t), err)) {
            return false;
        }
    }

    if (!wtap_dump_file_write(wdh, &(pd[8]), payload_length, err)) {
        return false;
    }

    if (!canfd && payload_length < 8) {
        uint8_t padding[8] = { 0 };
        if (!wtap_dump_file_write(wdh, &padding, 8 - payload_length, err)) {
            return false;
        }
    }

    /* no padding */

    return true;
}

static bool blf_dump_sll(wtap_dumper *wdh, const wtap_rec *rec, int *err, char **err_info, uint64_t obj_timestamp) {
    /* Linux Cooked CAN / CAN-FD */
    /* https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html */

    const uint8_t *pd = ws_buffer_start_ptr(&rec->data);
    size_t length = ws_buffer_length(&rec->data);

    if (length < 16) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf: record length %u for CAN message header (LINKTYPE_LINUX_SLL) is lower than minimum of 16", (uint32_t)length);
        ws_warning("LINKTYPE_LINUX_SLL header is too short!");
        return false;
    }

    bool frame_tx = false;
    if (pd[0] == 0 && pd[1] == 4) {
        frame_tx = true;
    }

    uint16_t protocol_type = pntohu16(pd + 14);

    switch (protocol_type) {
    case 0x000C: /* CAN */
        return blf_dump_socketcan(wdh, rec, err, err_info, obj_timestamp, &(pd[16]), length - 16, true, false, !frame_tx, frame_tx);
        break;
    case 0x000D: /* CAN-FD */
        return blf_dump_socketcan(wdh, rec, err, err_info, obj_timestamp, &(pd[16]), length - 16, false, true, !frame_tx, frame_tx);
        break;
    case 0x000E: /* CAN-XL */
        return blf_dump_socketcanxl(wdh, rec, err, err_info, obj_timestamp, &(pd[16]), length - 16, !frame_tx, frame_tx);
        break;
    default:
        return false;
    }

    /* not reachable? */
    return true;
}

static bool blf_dump_flexray(wtap_dumper *wdh, const wtap_rec *rec, int *err, char **err_info, uint64_t obj_timestamp) {
    /* FlexRay */
    /* https://www.tcpdump.org/linktypes/LINKTYPE_FLEXRAY.html */

    //blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;
    blf_channel_to_iface_entry_t *iface_entry = blf_dump_get_interface_mapping(wdh, rec, err, err_info);

    const uint8_t *pd = ws_buffer_start_ptr(&rec->data);
    size_t length = ws_buffer_length(&rec->data);

    if (length < 1) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf: record length %u for FlexRay header (LINKTYPE_FLEXRAY) is lower than minimum of 1", (uint32_t)length);
        ws_warning("LINKTYPE_FLEXRAY header is too short (< 1 Byte)!");
        return false;
    }

    /* Check Measurement Header for Type */
    if ((pd[0] & FLEXRAY_TYPE_MASK) == FLEXRAY_SYMBOL) {
        /* Symbol */

        if (length < 2) {
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup_printf("blf: record length %u for FlexRay Symbol (LINKTYPE_FLEXRAY) is lower than minimum of 2", (uint32_t)length);
            ws_warning("LINKTYPE_FLEXRAY Symbol is too short (< 2 Byte)!");
            return false;
        }

        /* TODO: SYMBOL */

        return true;
    }

    if ((pd[0] & FLEXRAY_TYPE_MASK) == FLEXRAY_FRAME) {
        /* Frame */

        if (length < 2 + FLEXRAY_HEADER_LENGTH) {
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup_printf("blf: record length %u for FlexRay Frame header (LINKTYPE_FLEXRAY) is lower than minimum of 7", (uint32_t)length);
            ws_warning("LINKTYPE_FLEXRAY Frame Header is too short (< 7 Byte)!");
            return false;
        }

        uint8_t payload_length = pd[4] & FLEXRAY_LENGTH_MASK;

        /* FLEXRAY FRAME */
        blf_flexrayrcvmessage_t frmsg;

        frmsg.channel = (uint16_t)iface_entry->channel;
        frmsg.version = 1;

        uint32_t header_crc = (pntohu24(pd + 4) & FLEXRAY_HEADER_CRC_MASK) >> FLEXRAY_HEADER_CRC_SHFT;

        if ((pd[0] & FLEXRAY_CHANNEL_MASK) == 0) {
            frmsg.channelMask = BLF_FLEXRAYRCVMSG_CHANNELMASK_A;
            frmsg.headerCrc1 = header_crc;
            frmsg.headerCrc2 = 0;
        } else {
            frmsg.channelMask = BLF_FLEXRAYRCVMSG_CHANNELMASK_B;
            frmsg.headerCrc1 = 0;
            frmsg.headerCrc2 = header_crc;
        }

        frmsg.dir = blf_get_direction(rec);
        frmsg.clientIndex = 0;
        frmsg.clusterNo = 0;
        frmsg.frameId = (pntohu16(pd + 2)) & FLEXRAY_ID_MASK;
        frmsg.payloadLength = payload_length;
        frmsg.payloadLengthValid = payload_length;
        frmsg.cycle = pd[6] & FLEXRAY_CC_MASK;
        frmsg.tag = 0;
        frmsg.data = 0;
        frmsg.frameFlags = 0;

        /* The NULL Flag 1 -> False */
        bool null_frame = (pd[2] & FLEXRAY_NFI_MASK) != FLEXRAY_NFI_MASK;

        if (null_frame) {
            frmsg.frameFlags &= BLF_FLEXRAYRCVMSG_FRAME_FLAG_NULL_FRAME;
            /* LINKTYPE_FLEXRAY has no payload for Null Frames present */
            payload_length = 0;
        }

        /* TODO: check truncated data */
        if (payload_length > 0) {
            /* Data Valid*/
            frmsg.frameFlags &= BLF_FLEXRAYRCVMSG_FRAME_FLAG_VALID_DATA;
        }

        if ((pd[2] & FLEXRAY_SFI_MASK) == FLEXRAY_SFI_MASK) {
            frmsg.frameFlags &= BLF_FLEXRAYRCVMSG_FRAME_FLAG_SYNC;
        }

        if ((pd[2] & FLEXRAY_STFI_MASK) == FLEXRAY_STFI_MASK) {
            frmsg.frameFlags &= BLF_FLEXRAYRCVMSG_FRAME_FLAG_STARTUP;
        }

        if ((pd[2] & FLEXRAY_PPI_MASK) == FLEXRAY_PPI_MASK) {
            frmsg.frameFlags &= BLF_FLEXRAYRCVMSG_FRAME_FLAG_PAYLOAD_PREAM;
        }

        if ((pd[2] & FLEXRAY_RES_MASK) == FLEXRAY_RES_MASK) {
            frmsg.frameFlags &= BLF_FLEXRAYRCVMSG_FRAME_FLAG_RES_20;
        }

        /* if any error flag is set */
        if ((pd[1] & FLEXRAY_ERRORS_DEFINED) != 0x00) {
            frmsg.frameFlags &= BLF_FLEXRAYRCVMSG_FRAME_FLAG_ERROR;
        }

        /* Not sure how to determine this as we do not know the low level parameters */
        //if ( ) {
        //    /* DYNAMIC SEG =1 (Bit 20)*/
        //    frmsg.frameFlags &= 0x100000;
        //}

        frmsg.appParameter = 0;

        fix_endianness_blf_flexrayrcvmessage(&frmsg);

        if (!blf_dump_objheader(wdh, err, obj_timestamp, BLF_OBJTYPE_FLEXRAY_RCVMESSAGE, sizeof(blf_flexrayrcvmessage_t) + 254)) {
            return false;
        }

        if (!wtap_dump_file_write(wdh, &(frmsg), sizeof(blf_flexrayrcvmessage_t), err)) {
            return false;
        }

        if (length < (size_t)payload_length + 2 + FLEXRAY_HEADER_LENGTH) {
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup_printf("blf: record length %u for FlexRay Frame (LINKTYPE_FLEXRAY) is truncated", (uint32_t)length);
            ws_warning("LINKTYPE_FLEXRAY Frame truncated!");
            return false;
        }

        if (payload_length > 0) {
            if (!wtap_dump_file_write(wdh, &(pd[7]), payload_length, err)) {
                return false;
            }
        }

        const uint8_t zero_bytes[256] = { 0 };

        if (payload_length < 254) {
            if (!wtap_dump_file_write(wdh, &zero_bytes[0], 254 - payload_length, err)) {
                return false;
            }
        }

        return true;
    }

    /* no padding */

    return true;
}

static bool blf_dump_lin(wtap_dumper *wdh, const wtap_rec *rec, int *err, char **err_info, uint64_t obj_timestamp) {
    /* LIN */
    /* https://www.tcpdump.org/linktypes/LINKTYPE_LIN.html */

    //blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;
    blf_channel_to_iface_entry_t *iface_entry = blf_dump_get_interface_mapping(wdh, rec, err, err_info);

    const uint8_t *pd = ws_buffer_start_ptr(&rec->data);
    size_t length = ws_buffer_length(&rec->data);

    if (length < 8) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf: record length %u for LIN message/symbol/error is lower than minimum of 8", (uint32_t)length);
        ws_warning("LIN Data is too short (less than 8 bytes)!");
        return false;
    }

    uint8_t lin_err = pd[7] & 0x3f;
    if (lin_err != 0) {
        // TODO: handle LIN errors
        return true;
    }

    int i;
    uint8_t dlc = (pd[4] & LIN_PAYLOAD_LENGTH_MASK) >> 4;
    uint8_t msg_type = (pd[4] & LIN_MSG_TYPE_MASK) >> 2;

    if (msg_type != LIN_MSG_TYPE_FRAME) {
        // TODO: handle LIN events
        return true;
    }

    /* we need to have at least the data */
    if (length < (size_t)dlc + 8) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("blf: record length %u for LIN message is too low for data. DLC: %u.", (uint32_t)length, dlc);
        ws_error("LIN Data is too short (less than needed)!");
        return false;
    }

    /* we ignore padding as we do not need it anyhow */

    blf_linmessage_t linmsg;
    linmsg.channel = (uint16_t)iface_entry->channel;
    linmsg.id = pd[5];
    linmsg.dlc = dlc;
    for (i = 0; i < 8; i++) {
        if (i < dlc) {
            linmsg.data[i] = pd[i + 8];
        } else {
            linmsg.data[i] = 0;
        }
    }
    linmsg.fsmId = 0;
    linmsg.fsmState = 0;
    linmsg.headerTime = 0;
    linmsg.fullTime = 0;
    linmsg.crc = pd[6];
    linmsg.dir = blf_get_direction(rec);
    linmsg.res1 = 0;

    fix_endianness_blf_linmessage(&linmsg);

    if (!blf_dump_objheader(wdh, err, obj_timestamp, BLF_OBJTYPE_LIN_MESSAGE, sizeof(blf_linmessage_t) + 4)) {
        return false;
    }

    if (!wtap_dump_file_write(wdh, &(linmsg), sizeof(blf_linmessage_t), err)) {
        return false;
    }

    uint8_t rest_of_header[4] = { 0, 0, 0, 0};

    if (!wtap_dump_file_write(wdh, &(rest_of_header), 4, err)) {
        return false;
    }

    /* no padding! */

    return true;
}

static bool blf_dump_upper_pdu(wtap_dumper *wdh, const wtap_rec *rec, int *err, char **err_info, uint64_t obj_timestamp) {
    const blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;

    const uint8_t *pd = ws_buffer_start_ptr(&rec->data);
    size_t length = ws_buffer_length(&rec->data);

    unsigned tag_diss_pos = 0;
    size_t tag_diss_len = 0;
    unsigned col_proto_pos = 0;
    size_t col_proto_len = 0;
    unsigned col_info_pos = 0;
    size_t col_info_len = 0;

    /* parse the tags */
    size_t pos = 0;
    bool done = false;
    while (!done) {
        if (length - pos < 4) {
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup_printf("blf: Upper PDU has no or truncated tags (pos: %u, length: %u)", (uint32_t)pos, (uint32_t)length);
            ws_warning("Upper PDU has truncated tags!");
            return false;
        }

        uint16_t tag_type = pntohu16(pd + pos);
        uint16_t tag_len = pntohu16(pd + pos + 2);

        if ((length - pos) < (size_t)tag_len + 4) {
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup_printf("blf: Upper PDU has truncated tags (pos: %u, tag_type: %u, tag_len: %u)", (uint32_t)pos, tag_type, tag_len);
            ws_warning("Upper PDU has truncated tags!");
            return false;
        }

        switch (tag_type) {
        case EXP_PDU_TAG_DISSECTOR_NAME:
            tag_diss_pos = (unsigned)pos + 4;
            tag_diss_len = tag_len;
            break;

        case EXP_PDU_TAG_COL_PROT_TEXT:
            col_proto_pos = (unsigned)pos + 4;
            col_proto_len = tag_len;
            break;

        case EXP_PDU_TAG_COL_INFO_TEXT:
            col_info_pos = (unsigned)pos + 4;
            col_info_len = tag_len;
            break;

        case EXP_PDU_TAG_END_OF_OPT:
            done = true;
            break;
        }

        pos += 4;
        pos += tag_len;
    }

    /* strip zero termination, if existing */
    while (pd[tag_diss_pos + tag_diss_len - 1] == 0) {
        tag_diss_len -= 1;
    }

    while (pd[col_proto_pos + col_proto_len - 1] == 0) {
        col_proto_len -= 1;
    }

    while (pd[col_info_pos + col_info_len - 1] == 0) {
        col_info_len -= 1;
    }

    if (tag_diss_len == strlen(BLF_APPTEXT_TAG_DISS_DEFAULT) && 0 == strncmp(BLF_APPTEXT_TAG_DISS_DEFAULT, &pd[tag_diss_pos], tag_diss_len)) {
        if (col_proto_len == strlen(BLF_APPTEXT_COL_PROT_TEXT) && 0 == strncmp(BLF_APPTEXT_COL_PROT_TEXT, &pd[col_proto_pos], col_proto_len)) {
            blf_apptext_t apptext_header;
            apptext_header.source = BLF_APPTEXT_METADATA;
            apptext_header.reservedAppText1 = 0;
            apptext_header.reservedAppText2 = 412; /* not sure what to put in but this is commonly used!? */
            uint32_t payload_len = (uint32_t)(length - pos);
            apptext_header.textLength = payload_len;

            /* Metadata */
            /* tags: BLF_APPTEXT_TAG_DISS_DEFAULT, BLF_APPTEXT_COL_PROT_TEXT, BLF_APPTEXT_COL_INFO_TEXT_... */
            if (col_info_len == strlen(BLF_APPTEXT_COL_INFO_TEXT_GENERAL) && 0 == strncmp(BLF_APPTEXT_COL_INFO_TEXT_GENERAL, &pd[col_info_pos], col_info_len)) {
                /* BLF_APPTEXT_METADATA: BLF_APPTEXT_XML_GENERAL */
                apptext_header.reservedAppText1 = (BLF_APPTEXT_XML_GENERAL << 24) | (0xffffff & payload_len);
            } else if (col_info_len == strlen(BLF_APPTEXT_COL_INFO_TEXT_CHANNELS) && 0 == strncmp(BLF_APPTEXT_COL_INFO_TEXT_CHANNELS, &pd[col_info_pos], col_info_len)) {
                /* BLF_APPTEXT_METADATA: BLF_APPTEXT_XML_CHANNELS */
                    if (writer_data->iface_to_channel_names_recovered) {
                    apptext_header.reservedAppText1 = (BLF_APPTEXT_XML_CHANNELS << 24) | (0xffffff & payload_len);
                }
            } else if (col_info_len == strlen(BLF_APPTEXT_COL_INFO_TEXT_IDENTITY) && 0 == strncmp(BLF_APPTEXT_COL_INFO_TEXT_IDENTITY, &pd[col_info_pos], col_info_len)) {
                /* BLF_APPTEXT_METADATA: BLF_APPTEXT_XML_IDENTITY */
                apptext_header.reservedAppText1 = (BLF_APPTEXT_XML_IDENTITY << 24) | (0xffffff & payload_len);

            //} else if
                /* BLF_APPTEXT_COMMENT */
                /* tags: BLF_APPTEXT_TAG_DISS_DEFAULT, BLF_APPTEXT_COL_PROT_TEXT, "Comment: %s" */
                // TODO
            //} else if
                /* BLF_APPTEXT_ATTACHMENT */
                /* tags: BLF_APPTEXT_TAG_DISS_DEFAULT, BLF_APPTEXT_COL_PROT_TEXT, "Attachment: %s" */
                // TODO
            //} else if
                /* BLF_APPTEXT_TRACELINE */
                /* tags: BLF_APPTEXT_TAG_DISS_DEFAULT, BLF_APPTEXT_COL_PROT_TEXT, "Trace line%s: %s" */
                // TODO
            } else {
                return true; /* just leave */
            }

            if (payload_len > 2048 && (apptext_header.source != BLF_APPTEXT_METADATA)) {
                ws_warning("Only Meta Data can be broken into smaller chunks!");
            }

            uint32_t chunk_size = payload_len;
            bool last_round = false;
            do {
                if (payload_len > 2048 && apptext_header.source == BLF_APPTEXT_METADATA) {
                    chunk_size = 2048;
                } else {
                    chunk_size = payload_len;
                    last_round = true;
                }

                if (!blf_dump_objheader(wdh, err, obj_timestamp, BLF_OBJTYPE_APP_TEXT, sizeof(blf_apptext_t) + chunk_size)) {
                    return false;
                }

                if (apptext_header.source == BLF_APPTEXT_METADATA) {
                    apptext_header.reservedAppText1 = (0xff000000 & apptext_header.reservedAppText1) | (0x00ffffff & payload_len);
                }

                apptext_header.textLength = chunk_size;
                fix_endianness_blf_apptext_header(&apptext_header);
                if (!wtap_dump_file_write(wdh, &(apptext_header), sizeof(blf_apptext_t), err)) {
                    return false;
                }
                if (!last_round) {
                    fix_endianness_blf_apptext_header(&apptext_header);
                }

                if (!wtap_dump_file_write(wdh, &(pd[pos]), chunk_size, err)) {
                    return false;
                }
                pos += chunk_size;

                /* Add strange padding to 4 bytes. */
                uint8_t padding_needed = (sizeof(blf_apptext_t) + chunk_size) % 4;
                if (!blf_write_add_padding(wdh, err, padding_needed)) {
                    return false;
                }

                if (!last_round) {
                    payload_len -= 2048;
                }
            } while (!last_round);

            return true;
        }
        // else if
        /* BLF_OBJTYPE_ETHERNET_STATUS */
        /* tags: BLF_APPTEXT_TAG_DISS_ETHSTATUS */
        // TODO

        // else if
        /* BLF_OBJTYPE_ETHERNET_PHY_STATE */
        /* tags: BLF_APPTEXT_TAG_DISS_ETHPHYSTATUS */
        // TODO
    }

    return true;
}

static bool blf_dump_interface_setup_by_blf_based_idb_desc(wtap_dumper *wdh, int *err _U_) {
    blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;
    bool iface_descr_found;

    /* check all interfaces first to avoid inconsistent state */
    for (unsigned i = 0; i < wdh->interface_data->len; i++) {
        ws_debug("interface: %d (pass 1)", i);

        /* get interface data */
        wtap_block_t idb = g_array_index(wdh->interface_data, wtap_block_t, i);
        if (idb == NULL) {
            return false;
        }

        char *iface_descr = NULL;
        iface_descr_found = wtap_block_get_string_option_value(idb, OPT_IDB_DESCRIPTION, &iface_descr) == WTAP_OPTTYPE_SUCCESS;

        if (!iface_descr_found) {
            ws_debug("IDB interface description not found! We need to map the interfaces.");
            return false;
        }

        if (strncmp(iface_descr, "BLF-", 4) != 0) {
            ws_debug("IDB interface description found but not BLF format! We have to map freely the interfaces.");
            return false;
        }
    }

    for (unsigned i = 0; i < wdh->interface_data->len; i++) {
        ws_debug("interface: %d (pass 2)", i);

        /* get interface data */
        wtap_block_t idb = g_array_index(wdh->interface_data, wtap_block_t, i);
        if (idb == NULL) {
            return false;
        }

        char *iface_descr = NULL;
        iface_descr_found = wtap_block_get_string_option_value(idb, OPT_IDB_DESCRIPTION, &iface_descr);

        if (!iface_descr_found) {
            /* This cannot be reached but it removes a warning. */
            ws_debug("IDB interface description not found! We need to map the interfaces.");
            return false;
        }

        if (strncmp(iface_descr, "BLF-ETH-", 8) == 0) {
            char *endptr;
            uint16_t channel = (uint16_t)strtol(&iface_descr[8], &endptr, 16);
            uint16_t hwchannel = (uint16_t)strtol(&endptr[1], NULL, 16);

            if (!blf_dump_set_interface_mapping(wdh, i, WTAP_ENCAP_ETHERNET, channel, hwchannel)) {
                return false;
            }
        } else if (strncmp(iface_descr, "BLF-CAN-", 8) == 0) {
            uint16_t channel = (uint16_t)strtol(&iface_descr[8], NULL, 16);

            if (!blf_dump_set_interface_mapping(wdh, i, WTAP_ENCAP_SOCKETCAN, channel, UINT16_MAX)) {
                return false;
            }
        } else if (strncmp(iface_descr, "BLF-LIN-", 8) == 0) {
            uint16_t channel = (uint16_t)strtol(&iface_descr[8], NULL, 16);

            if (!blf_dump_set_interface_mapping(wdh, i, WTAP_ENCAP_LIN, channel, UINT16_MAX)) {
                return false;
            }
        } else if (strncmp(iface_descr, "BLF-FR-", 7) == 0) {
            uint16_t channel = (uint16_t)strtol(&iface_descr[7], NULL, 16);

            if (!blf_dump_set_interface_mapping(wdh, i, WTAP_ENCAP_FLEXRAY, channel, UINT16_MAX)) {
                return false;
            }
        }
    }

    writer_data->iface_to_channel_names_recovered = true;
    return true;
}

static bool blf_dump_interface_setup(wtap_dumper *wdh, int *err) {
    //blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;

    /* Try 1: BLF details in Interface Description */
    if (blf_dump_interface_setup_by_blf_based_idb_desc(wdh, err)) {
        return true;
    }

    /* Try 2: Generate new IDs by mapping Interface IDs and also add names to BLF */
    for (unsigned i = 0; i < wdh->interface_data->len; i++) {
        ws_debug("i: %d", i);

        /* get interface data */
        wtap_block_t idb = g_array_index(wdh->interface_data, wtap_block_t, i);
        if (idb == NULL) {
            return false;
        }

        const wtapng_if_descr_mandatory_t *mand_data = (wtapng_if_descr_mandatory_t *) idb->mandatory_data;

        if (mand_data->wtap_encap == WTAP_ENCAP_ETHERNET || mand_data->wtap_encap == WTAP_ENCAP_SLL ||
            mand_data->wtap_encap == WTAP_ENCAP_LIN || mand_data->wtap_encap == WTAP_ENCAP_SOCKETCAN) {

            char *iface_name = NULL;
            bool iface_name_found = wtap_block_get_string_option_value(idb, OPT_IDB_NAME, &iface_name) == WTAP_OPTTYPE_SUCCESS;

            /* BLF can only support 255 channels */
            if (iface_name_found && iface_name != NULL && (i) < 255) {
                uint8_t iface_id = (uint8_t)(i + 1);

                /* we are not even trying to create APPTEXT CHANNELS as we are missing too much information */

                /* mapping up to 255 interface ids to channels directly */
                if (!blf_dump_set_interface_mapping(wdh, i, mand_data->wtap_encap, (uint16_t)iface_id, UINT16_MAX)) {
                    return false;
                }
            }
        }
    }

    return true;
}

static bool blf_dump(wtap_dumper *wdh, const wtap_rec *rec, int *err, char **err_info) {
    blf_writer_data_t *writer_data = (blf_writer_data_t *)wdh->priv;
    ws_debug("encap = %d (%s) rec type = %u", rec->rec_header.packet_header.pkt_encap,
        wtap_encap_description(rec->rec_header.packet_header.pkt_encap), rec->rec_type);

    /* TODO */
    switch (rec->rec_type) {
    case REC_TYPE_PACKET:
        break;
    default:
        *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
        return false;
    }

    /* logcontainer full already? we just estimate the headers/overhead to be less than 100 */
    blf_dump_check_logcontainer_full(wdh, err, err_info, rec->rec_header.packet_header.len + 100);

    if (!writer_data->start_time_set) {
        /* TODO: consider to set trace start time to first packet time stamp - is this the lowest timestamp? how to know? */
        writer_data->start_time = 0;
        writer_data->start_time_set = true;
    }

    uint64_t obj_timestamp = (rec->ts.secs * 1000 * 1000 * 1000 + rec->ts.nsecs);

    if (writer_data->end_time < obj_timestamp) {
        writer_data->end_time = obj_timestamp;
    }

    /* reduce by BLF start offset */
    obj_timestamp = obj_timestamp - writer_data->start_time;
    writer_data->object_count += 1;

    switch (rec->rec_header.packet_header.pkt_encap) {
    case WTAP_ENCAP_ETHERNET: /* 1 */
        return blf_dump_ethernet(wdh, rec, err, err_info, obj_timestamp);
        break;

    case WTAP_ENCAP_SLL: /* 25 */
        return blf_dump_sll(wdh, rec, err, err_info, obj_timestamp);
        break;

    case WTAP_ENCAP_FLEXRAY: /* 106 */
        return blf_dump_flexray(wdh, rec, err, err_info, obj_timestamp);
        break;

    case WTAP_ENCAP_LIN: /* 107 */
        return blf_dump_lin(wdh, rec, err, err_info, obj_timestamp);
        break;

    case WTAP_ENCAP_SOCKETCAN: { /* 125 */
        const uint8_t *pd = ws_buffer_start_ptr(&rec->data);
        size_t length = ws_buffer_length(&rec->data);
        return blf_dump_socketcan(wdh, rec, err, err_info, obj_timestamp, pd, length, false, false, false, false);
    }
        break;

    case WTAP_ENCAP_WIRESHARK_UPPER_PDU: /* 155 */
        return blf_dump_upper_pdu(wdh, rec, err, err_info, obj_timestamp);
        break;

    default:
        /* we did not write, so correct count */
        writer_data->object_count -= 1;
    }

    return true;
}

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
static int blf_dump_can_write_encap(int wtap_encap) {
    ws_debug("encap = %d (%s)", wtap_encap, wtap_encap_description(wtap_encap));

    /* Per-packet encapsulation is supported. */
    if (wtap_encap == WTAP_ENCAP_PER_PACKET)
        return 0;

    switch (wtap_encap) {
    /* fall through */
    case WTAP_ENCAP_ETHERNET:
    case WTAP_ENCAP_SLL:
    case WTAP_ENCAP_FLEXRAY:
    case WTAP_ENCAP_LIN:
    case WTAP_ENCAP_SOCKETCAN:
    case WTAP_ENCAP_WIRESHARK_UPPER_PDU:
        return 0;
    }

    return WTAP_ERR_UNWRITABLE_ENCAP;
}

static bool blf_add_idb(wtap_dumper *wdh _U_, wtap_block_t idb _U_, int *err _U_, char **err_info _U_) {
    ws_debug("entering function");
    /* TODO: is there any reason to keep this? */

    return true;
}

/* Finish writing to a dump file.
   Returns true on success, false on failure. */
static bool blf_dump_finish(wtap_dumper *wdh, int *err, char **err_info) {
    if (!blf_dump_close_logcontainer(wdh, err, err_info)) {
        return false;
    }

    if (!blf_finalize_file_header(wdh, err)) {
        return false;
    }

    /* File is finished, do not touch anymore ! */

    ws_debug("leaving function");
    return true;
}

/* Returns true on success, false on failure; sets "*err" to an error code on
   failure */
static bool
blf_dump_open(wtap_dumper *wdh, int *err, char **err_info) {
    ws_debug("entering function");

    if (wdh == NULL || wdh->priv != NULL) {
        *err = WTAP_ERR_INTERNAL;
        ws_debug("internal error: blf wdh is NULL or private data already set!");
        return false;
    }

    wdh->subtype_add_idb = blf_add_idb;
    wdh->subtype_write = blf_dump;
    wdh->subtype_finish = blf_dump_finish;

    /* set up priv data */
    blf_writer_data_t *writer_data = g_new(blf_writer_data_t, 1);
    wdh->priv = writer_data;

    /* set up and init interface mappings */
    writer_data->iface_to_channel_array = g_array_new(true, true, sizeof(blf_channel_to_iface_entry_t));
    blf_dump_expand_interface_mapping(wdh, wdh->interface_data->len);
    writer_data->iface_to_channel_names_recovered = false;

    writer_data->fileheader = NULL;
    writer_data->object_count = 0;
    writer_data->start_time = 0;
    writer_data->start_time_set = false;
    writer_data->end_time = 0;

    writer_data->logcontainer_start = LOG_CONTAINER_NONE;

    /* create the blf header structure and attach to wdh */
    if (!blf_init_file_header(wdh, err)) {
        return false;
    }

    /* write space in output file for header */
    if (!blf_write_file_header_zeros(wdh, err)) {
        return false;
    }

    ws_debug("wrote blf file header");

    /* Create first log_container */
    if (!blf_dump_start_logcontainer(wdh, err, err_info)) {
        return false;
    }

    if (!blf_dump_interface_setup(wdh, err)) {
        return false;
    }

    return true;
}

static const struct file_type_subtype_info blf_info = {
        "Vector Informatik Binary Logging Format (BLF) logfile", "blf", "blf", NULL,
        false, BLOCKS_SUPPORTED(blf_blocks_supported),
        blf_dump_can_write_encap, blf_dump_open, NULL
};

void register_blf(void) {

    blf_file_type_subtype = wtap_register_file_type_subtype(&blf_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("BLF", blf_file_type_subtype);
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
