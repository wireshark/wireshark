/* blf.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * File format support for the Binary Log File (BLF) file format from
 * Vector Informatik decoder
 * Copyright (c) 2021-2024 by Dr. Lars Voelker <lars.voelker@technica-engineering.de>
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
#include <string.h>
#include <errno.h>
#include <epan/value_string.h>
#include <wsutil/wslog.h>
#include <wsutil/exported_pdu_tlvs.h>
#include <wsutil/strtoi.h>
#include "file_wrappers.h"
#include "wtap-int.h"

#ifdef HAVE_ZLIBNG
#include <zlib-ng.h>
#define ZLIB_PREFIX(x) zng_ ## x
typedef zng_stream zlib_stream;
#else
#ifdef HAVE_ZLIB
#define ZLIB_PREFIX(x) x
#include <zlib.h>
typedef z_stream zlib_stream;
#endif /* HAVE_ZLIB */
#endif

static const uint8_t blf_magic[] = { 'L', 'O', 'G', 'G' };
static const uint8_t blf_obj_magic[] = { 'L', 'O', 'B', 'J' };

static int blf_file_type_subtype = -1;

void register_blf(void);

static bool blf_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, char **err_info, int64_t *data_offset);
static bool blf_seek_read(wtap *wth, int64_t seek_off, wtap_rec* rec, Buffer *buf, int *err, char **err_info);
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

    GArray     *log_containers;

    GHashTable *channel_to_iface_ht;
    GHashTable *channel_to_name_ht;
    uint32_t    next_interface_id;
} blf_t;

typedef struct blf_params {
    wtap     *wth;
    wtap_rec *rec;
    Buffer   *buf;
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
blf_prepare_interface_name(blf_params_t* params, int pkt_encap, uint16_t channel, uint16_t hwchannel, char* name, bool force_new_name) {
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
    }
    else {
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
    }
    else {
        saved_name = (char*)g_hash_table_lookup(params->blf_data->channel_to_name_ht, &key);

        if (saved_name != NULL) {
            ret = blf_add_interface(params, pkt_encap, channel, hwchannel, saved_name);
            g_hash_table_remove(params->blf_data->channel_to_name_ht, &key);

            return ret;
        }
        else {
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
    header->len_compressed = GUINT64_FROM_LE(header->len_compressed);
    header->len_uncompressed = GUINT64_FROM_LE(header->len_uncompressed);
    header->obj_count = GUINT32_FROM_LE(header->obj_count);
    header->obj_read = GUINT32_FROM_LE(header->obj_read);
    fix_endianness_blf_date(&(header->start_date));
    fix_endianness_blf_date(&(header->end_date));
    header->length3 = GUINT32_FROM_LE(header->length3);
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
    blf_log_container_t* container_a = (blf_log_container_t*)a;
    blf_log_container_t* container_b = (blf_log_container_t*)b;

    if (container_a->real_start_pos < container_b->real_start_pos) {
        return -1;
    }
    else if (container_a->real_start_pos > container_b->real_start_pos) {
        return 1;
    }
    else {
        return 0;
    }
}

int
blf_logcontainers_search(const void *a, const void *b) {
    blf_log_container_t* container_a = (blf_log_container_t*)a;
    uint64_t pos = *(uint64_t*)b;

    if (container_a->real_start_pos > pos) {
        return 1;
    }
    else if (pos >= container_a->real_start_pos + container_a->real_length) {
        return -1;
    }
    else {
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
        *err_info = ws_strdup_printf("blf_pull_logcontainer_into_memory called with NULL container");
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
            /*
             * XXX - our caller will turn this into an EOF.
             * How *should* it be treated?
             * For now, we turn it into Yet Another Internal Error,
             * pending having better documentation of the file
             * format.
             */
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup("blf_pull_logcontainer_into_memory: cannot allocate memory");
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

    }
    else if (container->compression_method == BLF_COMPRESSION_ZLIB) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
        unsigned char *compressed_data = g_try_malloc((size_t)data_length);
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
            /*
             * XXX - our caller will turn this into an EOF.
             * How *should* it be treated?
             * For now, we turn it into Yet Another Internal Error,
             * pending having better documentation of the file
             * format.
             */
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup("blf_pull_logcontainer_into_memory: cannot allocate memory");
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
                *err_info = ws_strdup_printf("blf_pull_logcontainer_into_memory: inflateInit failed for LogContainer");
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
                *err = WTAP_ERR_DECOMPRESS;
                *err_info = (infstream.msg != NULL) ? ws_strdup(infstream.msg) : NULL;
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
            *err_info = ws_strdup_printf("blf_pull_logcontainer_into_memory: inflateEnd failed for LogContainer");
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
#else
        (void) params;
        *err = WTAP_ERR_DECOMPRESSION_NOT_SUPPORTED;
        *err_info = ws_strdup("blf_pull_logcontainer_into_memory: reading gzip-compressed containers isn't supported");
        return false;
#endif
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
    }
    else {
        blf_log_container_t* container = &g_array_index(params->blf_data->log_containers, blf_log_container_t, params->blf_data->log_containers->len - 1);
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
            }
            else {
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
        }
        else {
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
        }
        else {
            tmp.infile_data_start = file_tell(params->fh);
            tmp.infile_start_pos = tmp.infile_data_start - sizeof(blf_logcontainerheader_t) - header.header_length;
        }
        tmp.infile_length = header.object_length;

        tmp.real_start_pos = current_real_start;
        tmp.real_length = logcontainer_header.uncompressed_size;
        tmp.compression_method = logcontainer_header.compression_method;

        ws_debug("found log container with real_pos=0x%" PRIx64 ", real_length=0x%" PRIx64, tmp.real_start_pos, tmp.real_length);
    }
    else {
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
    }
    else {
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
        }
        else {
            memcpy(buf + copied, container->real_data + start_in_buf, count - copied);
            return true;
        }

    }

    /*
     * XXX - does this represent a bug (WTAP_ERR_INTERNAL) or a
     * malformed file (WTAP_ERR_BAD_FILE)?
     */
    *err = WTAP_ERR_INTERNAL;
    *err_info = ws_strdup_printf("blf_read_bytes_or_eof: ran out of containers");
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
    params->rec->rec_type = REC_TYPE_PACKET;
    params->rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    params->rec->presence_flags = WTAP_HAS_CAP_LEN | WTAP_HAS_INTERFACE_ID;
    params->rec->ts_rel_cap_valid = false;
    switch (flags) {
    case BLF_TIMESTAMP_RESOLUTION_10US:
        params->rec->presence_flags |= WTAP_HAS_TS;
        params->rec->tsprec = WTAP_TSPREC_10_USEC;
        object_timestamp *= 10000;
        object_timestamp += params->blf_data->start_offset_ns;
        params->rec->ts_rel_cap_valid = true;
        break;

    case BLF_TIMESTAMP_RESOLUTION_1NS:
        params->rec->presence_flags |= WTAP_HAS_TS;
        params->rec->tsprec = WTAP_TSPREC_NSEC;
        object_timestamp += params->blf_data->start_offset_ns;
        params->rec->ts_rel_cap_valid = true;
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

    nstime_t tmp_ts;
    tmp_ts.secs = params->blf_data->start_offset_ns / (1000 * 1000 * 1000);
    tmp_ts.nsecs = params->blf_data->start_offset_ns % (1000 * 1000 * 1000);
    nstime_delta(&params->rec->ts_rel_cap, &params->rec->ts, &tmp_ts);

    params->rec->rec_header.packet_header.pkt_encap = pkt_encap;
    params->rec->rec_header.packet_header.interface_id = blf_lookup_interface(params, pkt_encap, channel, hwchannel, NULL);

    /* TODO: before we had to remove comments and verdict here to not leak memory but APIs have changed ... */
}

static void
blf_add_direction_option(blf_params_t *params, uint16_t direction) {
    uint32_t tmp = 0; /* dont care */

    switch (direction) {
    case BLF_DIR_RX:
        tmp = 1; /* inbound */
        break;
    case BLF_DIR_TX:
    case BLF_DIR_TX_RQ:
        tmp = 2; /* outbound */
        break;
    }

    /* pcapng.c: #define OPT_EPB_FLAGS 0x0002 */
    wtap_block_add_uint32_option(params->rec->block, 0x0002, tmp);
}

static bool
blf_read_log_object_header(blf_params_t *params, int *err, char **err_info, int64_t header2_start, int64_t data_start, blf_logobjectheader_t *logheader) {
    if (data_start - header2_start < (int64_t)sizeof(blf_logobjectheader_t)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: not enough bytes for log object header");
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
        *err_info = ws_strdup_printf("blf: not enough bytes for log object header");
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
        *err_info = ws_strdup_printf("blf: not enough bytes for log object header");
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
        *err_info = ws_strdup_printf("blf: ETHERNET_FRAME: not enough bytes for ethernet frame header in object");
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
        tmpbuf[12] = (ethheader.tpid & 0xff00) >> 8;
        tmpbuf[13] = (ethheader.tpid & 0x00ff);
        tmpbuf[14] = (ethheader.tci & 0xff00) >> 8;
        tmpbuf[15] = (ethheader.tci & 0x00ff);
        tmpbuf[16] = (ethheader.ethtype & 0xff00) >> 8;
        tmpbuf[17] = (ethheader.ethtype & 0x00ff);
        ws_buffer_assure_space(params->buf, (size_t)18 + ethheader.payloadlength);
        ws_buffer_append(params->buf, tmpbuf, (size_t)18);
        caplen = ((uint32_t)18 + ethheader.payloadlength);
        len = ((uint32_t)18 + ethheader.payloadlength);
    } else {
        tmpbuf[12] = (ethheader.ethtype & 0xff00) >> 8;
        tmpbuf[13] = (ethheader.ethtype & 0x00ff);
        ws_buffer_assure_space(params->buf, (size_t)14 + ethheader.payloadlength);
        ws_buffer_append(params->buf, tmpbuf, (size_t)14);
        caplen = ((uint32_t)14 + ethheader.payloadlength);
        len = ((uint32_t)14 + ethheader.payloadlength);
    }

    if (!blf_read_bytes(params, data_start + sizeof(blf_ethernetframeheader_t), ws_buffer_end_ptr(params->buf), ethheader.payloadlength, err, err_info)) {
        ws_debug("copying ethernet frame failed");
        return false;
    }
    params->buf->first_free += ethheader.payloadlength;

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

    ws_buffer_assure_space(params->buf, ethheader.frame_length);

    if (object_length - (data_start - block_start) - sizeof(blf_ethernetframeheader_ex_t) < ethheader.frame_length) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: %s: frame too short", error ? "ETHERNET_ERROR_EX" : "ETHERNET_FRAME_EX");
        ws_debug("frame too short");
        return false;
    }

    if (!blf_read_bytes(params, data_start + sizeof(blf_ethernetframeheader_ex_t), ws_buffer_start_ptr(params->buf), ethheader.frame_length, err, err_info)) {
        ws_debug("copying ethernet frame failed");
        return false;
    }

    if (ethheader.flags & BLF_ETHERNET_EX_HARDWARECHANNEL) {
        blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_ETHERNET, ethheader.channel, ethheader.hw_channel, ethheader.frame_length, ethheader.frame_length);
        wtap_block_add_uint32_option(params->rec->block, OPT_PKT_QUEUE, ethheader.hw_channel);
    }
    else {
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
        *err_info = ws_strdup_printf("blf: ETHERNET_RXERROR: not enough bytes for ethernet frame header in object");
        ws_debug("not enough bytes for ethernet rx error header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &ethheader, sizeof(blf_ethernet_rxerror_t), err, err_info)) {
        ws_debug("not enough bytes for ethernet rx error header in file");
        return false;
    }
    fix_endianness_blf_ethernet_rxerror(&ethheader);

    ws_buffer_assure_space(params->buf, ethheader.frame_length);

    if (object_length - (data_start - block_start) < ethheader.frame_length) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: ETHERNET_RXERROR: frame too short");
        ws_debug("frame too short");
        return false;
    }

    if (!blf_read_bytes(params, data_start + sizeof(blf_ethernet_rxerror_t), ws_buffer_start_ptr(params->buf), ethheader.frame_length, err, err_info)) {
        ws_debug("copying ethernet rx error failed");
        return false;
    }

    if (ethheader.hw_channel != 0) {    /* In this object type, a value of 0 is considered invalid. */
        blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_ETHERNET, ethheader.channel, ethheader.hw_channel, ethheader.frame_length, ethheader.frame_length);
        wtap_block_add_uint32_option(params->rec->block, OPT_PKT_QUEUE, ethheader.hw_channel);
    }
    else {
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
        *err_info = ws_strdup_printf("blf: WLAN_FRAME: not enough bytes for wlan frame header in object");
        ws_debug("not enough bytes for wlan frame header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &wlanheader, sizeof(blf_wlanframeheader_t), err, err_info)) {
        ws_debug("not enough bytes for wlan frame header in file");
        return false;
    }
    fix_endianness_blf_wlanframeheader(&wlanheader);

    ws_buffer_assure_space(params->buf, wlanheader.frame_length);

    if (object_length - (data_start - block_start) - sizeof(blf_wlanframeheader_t) < wlanheader.frame_length) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: WLAN_FRAME: frame too short");
        ws_debug("frame too short");
        return false;
    }

    if (!blf_read_bytes(params, data_start + sizeof(blf_wlanframeheader_t), ws_buffer_start_ptr(params->buf), wlanheader.frame_length, err, err_info)) {
        ws_debug("copying wlan frame failed");
        return false;
    }

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_IEEE_802_11, wlanheader.channel, UINT16_MAX, wlanheader.frame_length, wlanheader.frame_length);
    blf_add_direction_option(params, wlanheader.direction);

    return true;
}

static uint8_t can_dlc_to_length[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8 };
static uint8_t canfd_dlc_to_length[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64 };

static bool
blf_can_fill_buf_and_rec(blf_params_t *params, int *err, char **err_info, uint32_t canid, uint8_t payload_length, uint8_t payload_length_valid, uint64_t start_position,
                         uint32_t flags, uint64_t object_timestamp, uint16_t channel, uint8_t canfd_flags) {
    uint8_t  tmpbuf[8];
    unsigned caplen, len;

    tmpbuf[0] = (canid & 0xff000000) >> 24;
    tmpbuf[1] = (canid & 0x00ff0000) >> 16;
    tmpbuf[2] = (canid & 0x0000ff00) >> 8;
    tmpbuf[3] = (canid & 0x000000ff);
    tmpbuf[4] = payload_length;
    tmpbuf[5] = canfd_flags;
    tmpbuf[6] = 0;
    tmpbuf[7] = 0;

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf) + payload_length_valid);
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));
    caplen = sizeof(tmpbuf) + payload_length_valid;
    len = sizeof(tmpbuf) + payload_length;

    if (payload_length_valid > 0 && !blf_read_bytes(params, start_position, ws_buffer_end_ptr(params->buf), payload_length_valid, err, err_info)) {
        ws_debug("copying can payload failed");
        return false;
    }
    params->buf->first_free += payload_length_valid;

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
            *err_info = ws_strdup_printf("blf: CAN_MESSAGE2: not enough bytes for can message 2 trailer");
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
        *err_info = ws_strdup_printf("blf: CAN_FD_MESSAGE: not enough bytes for canfd header in object");
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
        *err_info = ws_strdup_printf("blf: CAN_FD_MESSAGE_64: not enough bytes for canfd header in object");
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
        *err_info = ws_strdup_printf("blf: CAN_ERROR: not enough bytes for canerror header in object");
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

    tmpbuf[0] = (canid & 0xff000000) >> 24;
    tmpbuf[1] = (canid & 0x00ff0000) >> 16;
    tmpbuf[2] = (canid & 0x0000ff00) >> 8;
    tmpbuf[3] = (canid & 0x000000ff);
    tmpbuf[4] = payload_length;

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf));
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));

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
        *err_info = ws_strdup_printf("blf: CAN_ERROR_EXT: not enough bytes for canerrorext header in object");
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

    tmpbuf[0] = (canid & 0xff000000) >> 24;
    tmpbuf[1] = (canid & 0x00ff0000) >> 16;
    tmpbuf[2] = (canid & 0x0000ff00) >> 8;
    tmpbuf[3] = (canid & 0x000000ff);
    tmpbuf[4] = payload_length;

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf));
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));

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
        *err_info = ws_strdup_printf("blf: CAN_FD_ERROR_64: not enough bytes for canfderror header in object");
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

    tmpbuf[0] = (canid & 0xff000000) >> 24;
    tmpbuf[1] = (canid & 0x00ff0000) >> 16;
    tmpbuf[2] = (canid & 0x0000ff00) >> 8;
    tmpbuf[3] = (canid & 0x000000ff);
    tmpbuf[4] = payload_length;
    // Don't set FDF, ESI and BRS flags, since error messages are always encapsulated in Classic CAN frames

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf));
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_SOCKETCAN, canheader.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));
    if (canheader.flags & BLF_CANERROREXT_FLAG_CANCORE) {
        direction_tx = (canheader.errorCodeExt & BLF_CANERROREXT_EXTECC_TX) == BLF_CANERROREXT_EXTECC_TX;
        blf_add_direction_option(params, direction_tx ? BLF_DIR_TX: BLF_DIR_RX);
    }
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
        *err_info = ws_strdup_printf("blf: FLEXRAY_DATA: not enough bytes for flexrayheader in object");
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

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf) + payload_length_valid);
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));
    caplen = sizeof(tmpbuf) + payload_length_valid;
    len = sizeof(tmpbuf) + payload_length;

    if (payload_length_valid > 0 && !blf_read_bytes(params, data_start + sizeof(frheader), ws_buffer_end_ptr(params->buf), payload_length_valid, err, err_info)) {
        ws_debug("copying flexray payload failed");
        return false;
    }
    params->buf->first_free += payload_length_valid;

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
        *err_info = ws_strdup_printf("blf: FLEXRAY_MESSAGE: not enough bytes for flexrayheader in object");
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

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf) + payload_length_valid);
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));
    caplen = sizeof(tmpbuf) + payload_length_valid;
    len = sizeof(tmpbuf) + payload_length;

    if (payload_length_valid > 0 && !blf_read_bytes(params, data_start + sizeof(frheader), ws_buffer_end_ptr(params->buf), payload_length_valid, err, err_info)) {
        ws_debug("copying flexray payload failed");
        return false;
    }
    params->buf->first_free += payload_length_valid;

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

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf) + payload_length_valid);
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));
    caplen = sizeof(tmpbuf) + payload_length_valid;
    len = sizeof(tmpbuf) + payload_length;

    if (payload_length_valid > 0 && !blf_read_bytes(params, data_start + frheadersize, ws_buffer_end_ptr(params->buf), payload_length_valid, err, err_info)) {
        ws_debug("copying flexray payload failed");
        return false;
    }
    params->buf->first_free += payload_length_valid;

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

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf) + payload_length);
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));
    ws_buffer_append(params->buf, linmessage.data, payload_length);
    len = sizeof(tmpbuf) + payload_length;

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linmessage.channel, UINT16_MAX, len, len);
    blf_add_direction_option(params, linmessage.dir);

    return true;
}

static bool
blf_read_linrcverror(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_linrcverror_t   linmessage;

    if (object_length < (data_start - block_start) + (int)sizeof(linmessage)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: LIN_RCV_ERROR: not enough bytes for linrcverror in object");
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

    uint8_t tmpbuf[8];
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
    tmpbuf[7] = 0x02; /* errors */

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf));
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linmessage.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));

    return true;
}

static bool
blf_read_linsenderror(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_linsenderror_t         linmessage;

    if (object_length < (data_start - block_start) + (int)sizeof(linmessage)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: LIN_SND_ERROR: not enough bytes for linsenderror in object");
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

    uint8_t tmpbuf[8];
    tmpbuf[0] = 1; /* message format rev = 1 */
    tmpbuf[1] = 0; /* reserved */
    tmpbuf[2] = 0; /* reserved */
    tmpbuf[3] = 0; /* reserved */
    tmpbuf[4] = linmessage.dlc << 4; /* dlc (4bit) | type (2bit) | checksum type (2bit) */
    tmpbuf[5] = linmessage.id; /* parity (2bit) | id (6bit) */
    tmpbuf[6] = 0; /* checksum */
    tmpbuf[7] = 0x01; /* errors */

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf));
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linmessage.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));

    return true;
}

static bool
blf_read_linwakeupevent(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_linwakeupevent_t    linevent;

    if (object_length < (data_start - block_start) + (int)sizeof(linevent)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: LIN_WAKEUP: not enough bytes for linwakeup in object");
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

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf));
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));

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
        *err_info = ws_strdup_printf("blf: LIN_MESSAGE2: not enough bytes for linmessage2 in object");
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

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf) + payload_length);
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));
    ws_buffer_append(params->buf, linmessage.data, payload_length);
    len = sizeof(tmpbuf) + payload_length;

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
        *err_info = ws_strdup_printf("blf: LIN_CRC_ERROR2: not enough bytes for lincrcerror2 in object");
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
    tmpbuf[7] = 0x08; /* errors */

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf) + payload_length);
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));
    ws_buffer_append(params->buf, linmessage.data, payload_length);
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
        *err_info = ws_strdup_printf("blf: LIN_RCV_ERROR2: not enough bytes for linrcverror2 in object");
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
    }
    else {
        payload_length = 0;
    }

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
    tmpbuf[6] = 0; /* checksum */
    /* XXX - This object can represent many different error types.
     * For now we always treat it as framing error,
     * but in the future we should expand it. */
    tmpbuf[7] = 0x02; /* errors */

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf) + payload_length);
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));
    if (payload_length > 0) {
        ws_buffer_append(params->buf, linmessage.data, payload_length);
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
        *err_info = ws_strdup_printf("blf: LIN_SND_ERROR2: not enough bytes for linsenderror2 in object");
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

    uint8_t tmpbuf[8];
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
    tmpbuf[7] = 0x01; /* errors */

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf));
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linmessage.linMessageDescriptor.linSynchFieldEvent.linBusEvent.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));

    return true;
}

static bool
blf_read_linwakeupevent2(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_linwakeupevent2_t   linevent;

    if (object_length < (data_start - block_start) + (int)sizeof(linevent)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: LIN_WAKEUP2: not enough bytes for linwakeup2 in object");
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

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf));
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linevent.linBusEvent.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));

    return true;
}

static bool
blf_read_linsleepmodeevent(blf_params_t* params, int* err, char** err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp) {
    blf_linsleepmodeevent_t   linevent;

    if (object_length < (data_start - block_start) + (int)sizeof(linevent)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: LIN_SLEEP: not enough bytes for linsleep in object");
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
        }
        else {
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

    ws_buffer_assure_space(params->buf, sizeof(tmpbuf));
    ws_buffer_append(params->buf, tmpbuf, sizeof(tmpbuf));

    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_LIN, linevent.channel, UINT16_MAX, sizeof(tmpbuf), sizeof(tmpbuf));

    return true;
}

uint16_t blf_get_xml_channel_number(const char* start, const char* end) {
    char* text;
    size_t len;
    uint16_t res;

    if (start == NULL || end == NULL || end <= start) {
        return UINT16_MAX;
    }

    len = (size_t)(end - start);
    text = g_try_malloc(len + 1);  /* Accommodate '\0' */
    if (text == NULL) {
        ws_debug("cannot allocate memory");
        return UINT16_MAX;
    }
    memcpy(text, start, len);
    text[len] = '\0';

    if (!ws_strtou16(text, NULL, &res)) {
        res = UINT16_MAX;
    }

    g_free(text);
    return res;
}

char* blf_get_xml_channel_name(const char* start, const char* end) {
    char* text;
    size_t len;

    if (start == NULL || end == NULL || end <= start) {
        return NULL;
    }

    len = (size_t)(end - start);
    text = g_try_malloc(len + 1);  /* Accommodate '\0' */
    if (text == NULL) {
        ws_debug("cannot allocate memory");
        return NULL;
    }
    memcpy(text, start, len);
    text[len] = '\0';

    return text;
}

bool blf_parse_xml_port(const char* start, const char* end, char** name, uint16_t* hwchannel, bool* simulated) {
    static const char name_magic[] = "name=";
    static const char hwchannel_magic[] = "hwchannel=";
    static const char simulated_magic[] = "simulated=";

    char* text;
    size_t len;
    char** tokens;
    char* token;

    if (start == NULL || end == NULL || name == NULL || end <= start) {
        return false;
    }

    len = (size_t)(end - start);
    text = g_try_malloc(len + 1);  /* Accommodate '\0' */
    if (text == NULL) {
        ws_debug("cannot allocate memory");
        return false;
    }
    memcpy(text, start, len);
    text[len] = '\0';

    tokens = g_strsplit_set(text, ";", -1);
    g_free(text);
    if (tokens == NULL) {
        ws_debug("cannot split XML port data");
        return false;
    }

    *name = NULL;
    *hwchannel = UINT16_MAX;
    *simulated = false;

    for (int i = 0; tokens[i] != NULL; i++) {
        token = tokens[i];
        if (strncmp(token, name_magic, strlen(name_magic)) == 0) {
            if (*name == NULL) { /* Avoid memory leak in case of malformed string */
                *name = ws_strdup(token + strlen(name_magic));
            }
        }
        else if (strncmp(token, hwchannel_magic, strlen(hwchannel_magic)) == 0) {
            if (!ws_strtou16(token + strlen(hwchannel_magic), NULL, hwchannel)) {
                *hwchannel = UINT16_MAX;
            }
        }
        else if (strncmp(token, simulated_magic, strlen(simulated_magic)) == 0) {
            if (strlen(token) > strlen(simulated_magic) && token[strlen(simulated_magic)] != '0') {
                *simulated = true;  /* TODO: Find a way to use this information */
            }
        }
    }

    g_strfreev(tokens);

    return true;
}

int blf_get_xml_pkt_encap(const char* start, const char* end) {
    size_t len;

    if (start == NULL || end == NULL || end <= start) {
        return 0;
    }

    len = (size_t)(end - start);

    if (strncmp(start, "CAN", len) == 0) {
        return WTAP_ENCAP_SOCKETCAN;
    }
    if (strncmp(start, "FlexRay", len) == 0) {
        return WTAP_ENCAP_FLEXRAY;
    }
    if (strncmp(start, "LIN", len) == 0) {
        return WTAP_ENCAP_LIN;
    }
    if (strncmp(start, "Ethernet", len) == 0) {
        return WTAP_ENCAP_ETHERNET;
    }
    if (strncmp(start, "WLAN", len) == 0) { /* Not confirmed with a real capture */
        return WTAP_ENCAP_IEEE_802_11;
    }

    return 0xffffffff;
}

/** Finds a NULL-terminated string in a block of memory.
 *
 * 'start' points to the first byte of the block of memory.
 * 'end' points to the first byte after the end of the block of memory,
 * so that the size of the block is end-start.
 * 'str' is a NULL-terminated string.
 */
const char* blf_strmem(const char* start, const char* end, const char* str) {
    if (start == NULL || end == NULL || str == NULL || end <= start) {
        return NULL;
    }

    return ws_memmem(start, end - start, str, strlen(str));
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
    static const char xml_magic[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
    static const char channels_start_magic[] = "<channels ";
    static const char channels_end_magic[] = "</channels>";
    static const char channel_start_magic[] = "<channel ";
    static const char channel_end_magic[] = "</channel>";
    static const char number_start_magic[] = "number=\"";
    static const char number_end_magic[] = "\"";
    static const char type_start_magic[] = "type=\"";
    static const char type_end_magic[] = "\"";
    static const char network_start_magic[] = "network=\"";
    static const char network_end_magic[] = "\"";
    static const char ports_start_magic[] = "<elist name=\"ports\">";
    static const char ports_end_magic[] = "</elist>";
    static const char port_start_magic[] = "<eli name=\"port\">";
    static const char port_end_magic[] = "</eli>";

    const char* xml_start;
    const char* channels_start;
    const char* channels_end;
    const char* channel_start;
    const char* channel_end;
    const char* number_start;
    const char* number_end;
    const char* type_start;
    const char* type_end;
    const char* network_start;
    const char* network_end;
    const char* ports_start;
    const char* ports_end;
    const char* port_start;
    const char* port_end;

    const char* search_start;
    bool res;

    int pkt_encap;
    uint16_t channel;
    uint16_t hwchannel = UINT16_MAX;
    char* channel_name = NULL;
    char* port_name = NULL;
    bool simulated = false;
    char* iface_name = NULL;

    if (text == NULL || len < strlen(xml_magic)) {
        return false;
    }

    xml_start = blf_strmem(text, text + len, xml_magic);
    if (xml_start == NULL) {
        ws_debug("no valid xml magic found");
        return false;
    }
    search_start = xml_start + strlen(xml_magic);

    channels_start = blf_strmem(search_start, text + len, channels_start_magic);
    channels_end = blf_strmem(search_start, text + len, channels_end_magic);
    if (channels_start == NULL || channels_end == NULL || channels_end <= channels_start + strlen(channels_start_magic)) {
        ws_debug("no channels tag found in xml");
        return false;
    }
    search_start = channels_start + strlen(channels_start_magic);

    while (search_start < channels_end) {
        channel_start = blf_strmem(search_start, channels_end, channel_start_magic);
        search_start = search_start + strlen(channel_start_magic);
        channel_end = blf_strmem(search_start, channels_end, channel_end_magic);
        if (channel_start == NULL || channel_end == NULL || channel_end <= channel_start + strlen(channel_start_magic)) {
            ws_debug("found end of channel list");
            return true;
        }

        number_start = blf_strmem(channel_start, channel_end, number_start_magic);
        if (number_start == NULL) {
            ws_debug("channel without number found in xml");
            search_start = channel_end + strlen(channel_end_magic);
            continue;
        }

        number_end = blf_strmem(number_start + strlen(number_start_magic), channel_end, number_end_magic);
        if (number_end == NULL) {
            ws_debug("channel with malformed number attribute found in xml");
            search_start = channel_end + strlen(channel_end_magic);
            continue;
        }

        channel = blf_get_xml_channel_number(number_start + strlen(number_start_magic), number_end);
        if (channel == UINT16_MAX) {
            ws_debug("invalid channel number found in xml");
            search_start = channel_end + strlen(channel_end_magic);
            continue;
        }

        type_start = blf_strmem(channel_start, channel_end, type_start_magic);
        if (type_start == NULL) {
            ws_debug("channel without type found in xml");
            search_start = channel_end + strlen(channel_end_magic);
            continue;
        }

        type_end = blf_strmem(type_start + strlen(type_start_magic), channel_end, type_end_magic);
        if (type_end == NULL) {
            ws_debug("channel with malformed type attribute found in xml");
            search_start = channel_end + strlen(channel_end_magic);
            continue;
        }

        pkt_encap = blf_get_xml_pkt_encap(type_start + strlen(type_start_magic), type_end);

        network_start = blf_strmem(channel_start, channel_end, network_start_magic);
        if (network_start == NULL) {
            ws_debug("channel without name found in xml");
            search_start = channel_end + strlen(channel_end_magic);
            continue;
        }

        network_end = blf_strmem(network_start + strlen(network_start_magic), channel_end, network_end_magic);
        if (network_end == NULL) {
            ws_debug("channel with malformed network attribute found in xml");
            search_start = channel_end + strlen(channel_end_magic);
            continue;
        }

        channel_name = blf_get_xml_channel_name(network_start + strlen(network_start_magic), network_end);
        if (channel_name == NULL || strlen(channel_name) == 0) {
            ws_debug("channel with empty name found in xml");
            if (channel_name) {
                g_free(channel_name);
                channel_name = NULL;
            }
            search_start = channel_end + strlen(channel_end_magic);
            continue;
        }

        ws_debug("Found channel in XML: PKT_ENCAP: %d, ID: %u, name: %s", pkt_encap, channel, channel_name);
        blf_prepare_interface_name(params, pkt_encap, channel, UINT16_MAX, channel_name, true);

        search_start = MAX(MAX(number_end + strlen(number_end_magic), type_end + strlen(type_end_magic)), network_end + strlen(network_end_magic));

        ports_start = blf_strmem(search_start, channel_end, ports_start_magic);
        if (ports_start == NULL) {
            /* Not an error, channel has no ports */
            if (channel_name) {
                g_free(channel_name);
                channel_name = NULL;
            }
            search_start = channel_end + strlen(channel_end_magic);
            continue;
        }

        search_start = ports_start + strlen(ports_start_magic);

        ports_end = blf_strmem(search_start, channel_end, ports_end_magic);
        if (ports_end == NULL) {
            ws_debug("channel with malformed ports tag found in xml");
            if (channel_name) {
                g_free(channel_name);
                channel_name = NULL;
            }
            search_start = channel_end + strlen(channel_end_magic);
            continue;
        }

        while (search_start < ports_end) {
            port_start = blf_strmem(search_start, ports_end, port_start_magic);
            port_end = blf_strmem(search_start + strlen(port_start_magic), ports_end, port_end_magic);
            if (port_start == NULL || port_end == NULL || port_end <= port_start + strlen(port_start_magic)) {
                ws_debug("found end of ports list");
                search_start = ports_end + strlen(ports_end_magic);
                continue;
            }

            res = blf_parse_xml_port(port_start + strlen(port_start_magic), port_end, &port_name, &hwchannel, &simulated);
            if (!res || port_name == NULL || hwchannel == UINT16_MAX) {
                if (port_name) {
                    g_free(port_name);
                    port_name = NULL;
                }
                ws_debug("port with missing or malformed info found in xml");
                search_start = port_end + strlen(port_end_magic);
                continue;
            }

            iface_name = ws_strdup_printf("%s::%s", channel_name, port_name);
            ws_debug("Found channel in XML: PKT_ENCAP: %d, ID: %u, HW ID: %u, name: %s", pkt_encap, channel, hwchannel, iface_name);
            blf_prepare_interface_name(params, pkt_encap, channel, hwchannel, iface_name, true);
            g_free(iface_name);

            if (port_name) {
                g_free(port_name);
                port_name = NULL;
            }

            search_start = port_end + strlen(port_end_magic);
        }

        if (channel_name) {
            g_free(channel_name);
            channel_name = NULL;
        }

        search_start = channel_end + strlen(channel_end_magic);
    }

    return true;
}

static int
blf_read_apptextmessage(blf_params_t *params, int *err, char **err_info, int64_t block_start, int64_t data_start, int64_t object_length, uint32_t flags, uint64_t object_timestamp, size_t metadata_cont) {
    blf_apptext_t            apptextheader;

    if (object_length < (data_start - block_start) + (int)sizeof(apptextheader)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("blf: APP_TEXT: not enough bytes for apptext header in object");
        ws_debug("not enough bytes for apptext header in object");
        return BLF_APPTEXT_FAILED;
    }

    if (!blf_read_bytes(params, data_start, &apptextheader, sizeof(apptextheader), err, err_info)) {
        ws_debug("not enough bytes for apptext header in file");
        return BLF_APPTEXT_FAILED;
    }
    fix_endianness_blf_apptext_header(&apptextheader);

    if (metadata_cont && apptextheader.source != BLF_APPTEXT_METADATA) {
        /* If we're in the middle of a sequence of metadata objects,
         * but we get an AppText object from another source,
         * skip the previously incomplete object and start fresh.
         */
        metadata_cont = 0;
    }

    /* Add an extra byte for a terminating '\0' */
    char* text = g_try_malloc((size_t)apptextheader.textLength + 1);

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
            pkt_encap = 0xffffffff;
            break;
        }

        /* we use lookup to create interface, if not existing yet */
        blf_prepare_interface_name(params, pkt_encap, channel, UINT16_MAX, tokens[1], false);

        g_strfreev(tokens);
        g_free(text);
        return BLF_APPTEXT_CHANNEL;
    }
    case BLF_APPTEXT_METADATA:
        if (metadata_cont) {
            /* Set the buffer pointer to the end of the previous object */
            params->buf->first_free = metadata_cont;
        }
        else {
            /* First object of a sequence of one or more */
            wtap_buffer_append_epdu_string(params->buf, EXP_PDU_TAG_DISSECTOR_NAME, "data-text-lines");
            wtap_buffer_append_epdu_string(params->buf, EXP_PDU_TAG_COL_PROT_TEXT, "BLF App text");
            wtap_buffer_append_epdu_string(params->buf, EXP_PDU_TAG_COL_INFO_TEXT, "Metadata");
            wtap_buffer_append_epdu_end(params->buf);
        }

        ws_buffer_assure_space(params->buf, apptextheader.textLength);
        ws_buffer_append(params->buf, text, apptextheader.textLength);
        g_free(text);

        if ((apptextheader.reservedAppText1 & 0x00ffffff) > apptextheader.textLength) {
            /* Continues in the next object */
            return BLF_APPTEXT_CONT;
        }

        if (((apptextheader.reservedAppText1 >> 24) & 0xff) == BLF_APPTEXT_XML_CHANNELS) {
            blf_set_xml_channels(params, params->buf->data, ws_buffer_length(params->buf));
        }

        /* Override the timestamp with 0 for metadata objects. Thay can only occur at the beginning of the file, and they usually alrady have a timestamp of 0. */
        blf_init_rec(params, 0, 0, WTAP_ENCAP_WIRESHARK_UPPER_PDU, 0, UINT16_MAX, (uint32_t)ws_buffer_length(params->buf), (uint32_t)ws_buffer_length(params->buf));
        return BLF_APPTEXT_METADATA;
    case BLF_APPTEXT_COMMENT:
    case BLF_APPTEXT_ATTACHMENT:
    case BLF_APPTEXT_TRACELINE:
    {
        wtap_buffer_append_epdu_string(params->buf, EXP_PDU_TAG_DISSECTOR_NAME, "data-text-lines");
        wtap_buffer_append_epdu_string(params->buf, EXP_PDU_TAG_COL_PROT_TEXT, "BLF App text");

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

        wtap_buffer_append_epdu_string(params->buf, EXP_PDU_TAG_COL_INFO_TEXT, info_line);
        wtap_buffer_append_epdu_end(params->buf);

        size_t text_length = strlen(text);  /* The string can contain '\0' before textLength bytes */
        ws_buffer_assure_space(params->buf, text_length); /* The dissector doesn't need NULL-terminated strings */
        ws_buffer_append(params->buf, text, text_length);

        /* We'll write this as a WS UPPER PDU packet with a text blob */
        blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_WIRESHARK_UPPER_PDU, 0, UINT16_MAX, (uint32_t)ws_buffer_length(params->buf), (uint32_t)ws_buffer_length(params->buf));
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
        *err_info = ws_strdup_printf("blf: ETHERNET_STATUS: not enough bytes for ethernet status header in object");
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
        GUINT64_FROM_LE(linkUpDuration);
    }

    fix_endianness_blf_ethernet_status_header(&ethernet_status_header);

    tmpbuf[0] = (ethernet_status_header.channel & 0xff00) >> 8;
    tmpbuf[1] = (ethernet_status_header.channel & 0x00ff);
    tmpbuf[2] = (ethernet_status_header.flags & 0xff00) >> 8;
    tmpbuf[3] = (ethernet_status_header.flags & 0x00ff);
    tmpbuf[4] = (ethernet_status_header.linkStatus);
    tmpbuf[5] = (ethernet_status_header.ethernetPhy);
    tmpbuf[6] = (ethernet_status_header.duplex);
    tmpbuf[7] = (ethernet_status_header.mdi);
    tmpbuf[8] = (ethernet_status_header.connector);
    tmpbuf[9] = (ethernet_status_header.clockMode);
    tmpbuf[10] = (ethernet_status_header.pairs);
    tmpbuf[11] = (ethernet_status_header.hardwareChannel);
    tmpbuf[12] = (ethernet_status_header.bitrate & 0xff000000) >> 24;
    tmpbuf[13] = (ethernet_status_header.bitrate & 0x00ff0000) >> 16;
    tmpbuf[14] = (ethernet_status_header.bitrate & 0x0000ff00) >> 8;
    tmpbuf[15] = (ethernet_status_header.bitrate & 0x000000ff);

    if (object_version >= 1) {
        tmpbuf[16] = (linkUpDuration & UINT64_C(0xff00000000000000)) >> 56;
        tmpbuf[17] = (linkUpDuration & UINT64_C(0x00ff000000000000)) >> 48;
        tmpbuf[18] = (linkUpDuration & UINT64_C(0x0000ff0000000000)) >> 40;
        tmpbuf[19] = (linkUpDuration & UINT64_C(0x000000ff00000000)) >> 32;
        tmpbuf[20] = (linkUpDuration & UINT64_C(0x00000000ff000000)) >> 24;
        tmpbuf[21] = (linkUpDuration & UINT64_C(0x0000000000ff0000)) >> 16;
        tmpbuf[22] = (linkUpDuration & UINT64_C(0x000000000000ff00)) >> 8;
        tmpbuf[23] = (linkUpDuration & UINT64_C(0x00000000000000ff));
    }

    wtap_buffer_append_epdu_string(params->buf, EXP_PDU_TAG_DISSECTOR_NAME, "blf-ethernetstatus-obj");
    wtap_buffer_append_epdu_end(params->buf);

    ws_buffer_assure_space(params->buf, sizeof(ethernet_status_header));
    ws_buffer_append(params->buf, tmpbuf, (size_t)(object_version >= 1 ? 24 : 16));

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
    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_WIRESHARK_UPPER_PDU, ethernet_status_header.channel, ethernet_status_header.hardwareChannel, (uint32_t)ws_buffer_length(params->buf), (uint32_t)ws_buffer_length(params->buf));

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
        *err_info = ws_strdup_printf("blf: ETHERNET_PHY_STATE: not enough bytes for ethernet phystate header in object");
        ws_debug("not enough bytes for ethernet phystate header in object");
        return false;
    }

    if (!blf_read_bytes(params, data_start, &ethernet_phystate_header, sizeof(ethernet_phystate_header), err, err_info)) {
        ws_debug("not enough bytes for ethernet phystate header in file");
        return false;
    }

    fix_endianness_blf_ethernet_phystate_header(&ethernet_phystate_header);

    tmpbuf[0] = (ethernet_phystate_header.channel & 0xff00) >> 8;
    tmpbuf[1] = (ethernet_phystate_header.channel & 0x00ff);
    tmpbuf[2] = (ethernet_phystate_header.flags & 0xff00) >> 8;
    tmpbuf[3] = (ethernet_phystate_header.flags & 0x00ff);
    tmpbuf[4] = (ethernet_phystate_header.phyState);
    tmpbuf[5] = (ethernet_phystate_header.phyEvent);
    tmpbuf[6] = (ethernet_phystate_header.hardwareChannel);
    tmpbuf[7] = (ethernet_phystate_header.res1);

    wtap_buffer_append_epdu_string(params->buf, EXP_PDU_TAG_DISSECTOR_NAME, "blf-ethernetphystate-obj");
    wtap_buffer_append_epdu_end(params->buf);

    ws_buffer_assure_space(params->buf, sizeof(ethernet_phystate_header));
    ws_buffer_append(params->buf, tmpbuf, sizeof(ethernet_phystate_header));

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
    blf_init_rec(params, flags, object_timestamp, WTAP_ENCAP_WIRESHARK_UPPER_PDU, ethernet_phystate_header.channel, ethernet_phystate_header.hardwareChannel, (uint32_t)ws_buffer_length(params->buf), (uint32_t)ws_buffer_length(params->buf));

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
    int64_t                  last_metadata_start = 0;
    size_t                   metadata_cont = 0;

    while (1) {
        /* Find Object */

        /* Resetting buffer */
        params->buf->first_free = params->buf->start;

        while (1) {
            if (!blf_read_bytes_or_eof(params, start_pos, &header, sizeof header, err, err_info)) {
                ws_debug("not enough bytes for block header or unsupported file");
                if (*err == WTAP_ERR_SHORT_READ) {
                    /* we have found the end that is not a short read therefore. */
                    *err = 0;
                    g_free(*err_info);
                }
                return false;
            }

            fix_endianness_blf_blockheader(&header);

            if (memcmp(header.magic, blf_obj_magic, sizeof(blf_obj_magic))) {
                ws_debug("object magic is not LOBJ (pos: 0x%" PRIx64 ")", start_pos);
            }
            else {
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

        if (metadata_cont && header.object_type != BLF_OBJTYPE_APP_TEXT) {
            /* If we're in the middle of a sequence of AppText metadata objects,
             * but we get an AppText object from another source,
             * skip the previous incomplete packet and start fresh.
             */
            metadata_cont = 0;
            last_metadata_start = 0;
        }

        switch (header.object_type) {
        case BLF_OBJTYPE_LOG_CONTAINER:
            *err = WTAP_ERR_UNSUPPORTED;
            *err_info = ws_strdup_printf("blf: log container in log container not supported");
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
            int result = blf_read_apptextmessage(params, err, err_info, start_pos, start_pos + header.header_length, header.object_length, flags, object_timestamp, metadata_cont);
            if (result == BLF_APPTEXT_CONT) {
                if (!metadata_cont) {
                    /* First object of a sequence, save its start position */
                    last_metadata_start = start_pos;
                }
                /* Save a pointer to the end of the buffer */
                metadata_cont = params->buf->first_free;
            }
            else {
                if (result == BLF_APPTEXT_METADATA && metadata_cont) {
                    /* Last object of a sequence, restore the start position of the first object */
                    params->blf_data->start_of_last_obj = last_metadata_start;
                }
                /* Reset everything and start fresh */
                last_metadata_start = 0;
                metadata_cont = 0;
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

static bool blf_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, char **err_info, int64_t *data_offset) {
    blf_params_t blf_tmp;

    blf_tmp.wth = wth;
    blf_tmp.fh  = wth->fh;
    blf_tmp.random = false;
    blf_tmp.pipe = wth->ispipe;
    blf_tmp.rec = rec;
    blf_tmp.buf = buf;
    blf_tmp.blf_data = (blf_t *)wth->priv;

    if (!blf_read_block(&blf_tmp, blf_tmp.blf_data->current_real_seek_pos, err, err_info)) {
        return false;
    }
    *data_offset = blf_tmp.blf_data->start_of_last_obj;

    return true;
}

static bool blf_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec, Buffer *buf, int *err, char **err_info) {
    blf_params_t blf_tmp;

    blf_tmp.wth = wth;
    blf_tmp.fh  = wth->random_fh;
    blf_tmp.random = true;
    blf_tmp.pipe = wth->ispipe;
    blf_tmp.rec = rec;
    blf_tmp.buf = buf;
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

    struct tm timestamp;
    timestamp.tm_year = (header.start_date.year > 1970) ? header.start_date.year - 1900 : 70;
    timestamp.tm_mon  = header.start_date.month -1;
    timestamp.tm_mday = header.start_date.day;
    timestamp.tm_hour = header.start_date.hour;
    timestamp.tm_min  = header.start_date.mins;
    timestamp.tm_sec  = header.start_date.sec;
    timestamp.tm_isdst = -1;

    /* Prepare our private context. */
    blf = g_new(blf_t, 1);
    blf->log_containers = g_array_new(false, false, sizeof(blf_log_container_t));
    blf->current_real_seek_pos = 0;
    blf->start_offset_ns = 1000 * 1000 * 1000 * (uint64_t)mktime(&timestamp);
    blf->start_offset_ns += 1000 * 1000 * header.start_date.ms;

    blf->channel_to_iface_ht = g_hash_table_new_full(g_int64_hash, g_int64_equal, &blf_free_key, &blf_free_channel_to_iface_entry);
    blf->channel_to_name_ht = g_hash_table_new_full(g_int64_hash, g_int64_equal, &blf_free_key, &blf_free_channel_to_name_entry);
    blf->next_interface_id = 0;

    wth->priv = (void *)blf;
    wth->file_encap = WTAP_ENCAP_NONE;
    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_UNKNOWN;
    wth->subtype_read = blf_read;
    wth->subtype_seek_read = blf_seek_read;
    wth->subtype_close = blf_close;
    wth->file_type_subtype = blf_file_type_subtype;

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

static const struct file_type_subtype_info blf_info = {
        "Vector Informatik Binary Logging Format (BLF) logfile", "blf", "blf", NULL,
        false, BLOCKS_SUPPORTED(blf_blocks_supported),
        NULL, NULL, NULL
};

void register_blf(void)
{
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
