/** procmon.c
 *
 * Implements reading of MS Procmon files
 * Used a lot of information from https://github.com/eronnen/procmon-parser
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP

#include "procmon.h"
#include "file_wrappers.h"
#include "wtap_module.h"
#include "pcapng_module.h"

#include <wsutil/buffer.h>

// To do:
// - Figure out module timestamps
// - Read the ports array? Is there any advantage to doing that vs our built in
//   port number resolution?

#pragma pack(push,1)
typedef struct procmon_header_s {
    uint32_t signature;                 // Magic Signature - 'PML_'
    uint32_t version;                   // Version of the PML file. 9 in the current version.
    uint32_t system_bitness;            // System bitness: 1 if the system is 64 bit, 0 otherwise.
    uint16_t computer_name[16];         // Name of the computer (that did the capture).
    uint16_t system_root_path[260];     // System root path (e.g. "C:\Windows").
    uint32_t num_events;                // Total number of events in the log file.
    uint64_t unused;                    // ? (seems to be unused)
    uint64_t start_events_offset;       // File offset to the start of the events array.
    uint64_t event_offsets_array_offset;// File offset to an array of offsets to all the events.
    uint64_t process_array_offset;      // File offset to the array of processes.
    uint64_t string_array_offset;       // File offset to the array of strings.
    uint64_t icon_array_offset;         // File offset to the icons array.
    uint64_t maximum_user_address;      // SYSTEM_INFO.lpMaximumApplicationAddress: Maximum User Address
    uint32_t os_version_info_size;      // OSVERSIONINFOEXW.dwOSVersionInfoSize: sizeof(OSVERSIONINFOEXW)
    uint32_t major_version;             // OSVERSIONINFOEXW.dwMajorVersion: Major version number of the operating system.
    uint32_t minor_version;             // OSVERSIONINFOEXW.dwMinorVersion: Minor version number of the operating system.
    uint32_t build_number;              // OSVERSIONINFOEXW.dwBuildNumber: Build number of the operating system.
    uint32_t platform_id;               // OSVERSIONINFOEXW.dwPlatformId: Operating system platform.
    uint16_t csd_version[128];          // OSVERSIONINFOEXW.szCSDVersion: Indicates the latest Service Pack installed.
    uint16_t service_pack_major;        // OSVERSIONINFOEXW.wServicePackMajor: Major version number of the latest Service Pack.
    uint16_t service_pack_minor;        // OSVERSIONINFOEXW.wServicePackMinor: Minor version number of the latest Service Pack.
    uint16_t suite_mask;                // OSVERSIONINFOEXW.wSuiteMask: Bit mask that identifies the product suites available.
    uint8_t product_type;               // OSVERSIONINFOEXW.wProductType: Additional information about the system.
    uint8_t version_reserved;           // OSVERSIONINFOEXW.wReserved: Reserved for future use.
    uint32_t num_processors;            // SYSTEM_INFO.dwNumberOfProcessors: Number of logical processors.
    uint64_t total_physical_memory;     // MEMORYSTATUSEX.ullTotalPhys: Total physical memory (in bytes).
    uint64_t start_events_offset_dup;   // File offset to the start of the events array (again).
    uint64_t host_port_array_offset;    // File offset to hosts and ports arrays.
} procmon_header_t;

typedef enum {
    PROCMON_EVENT_TYPE_UNKNOWN = 0,
    PROCMON_EVENT_TYPE_PROCESS = 1,
    PROCMON_EVENT_TYPE_REGISTRY = 2,
    PROCMON_EVENT_TYPE_FILE_SYSTEM = 3,
    PROCMON_EVENT_TYPE_PROFILING = 4,
    PROCMON_EVENT_TYPE_NETWORK = 5,
} procmon_event_class_type_t;

typedef struct procmon_event_header_s {
    uint32_t process_index;             // The index to the process of the event.
    uint32_t thread_id;                 // Thread Id.
    uint32_t event_class;               // Event class (of type procmon_event_class_type_t)
    uint16_t operation_type;            // Operation type (dependent on the event class)
    uint8_t  unknown[6];                // Unknown
    uint64_t duration;                  // Duration of the operation in 100 nanoseconds interval.
    uint64_t timestamp;                 // The time when the event was captured (in FILETIME format)
    uint32_t event_result;              // The value of the event result.
    uint16_t stack_trace_depth;         // The depth of the captured stack trace.
    uint16_t unknown3;                  // Unknown
    uint32_t details_size;              // The size of the specific detail structure (contains path and other details)
    uint32_t extra_details_offset;      // The offset from the start of the event to extra detail structure (not necessarily continuous with this structure).

} procmon_event_header_t;
#pragma pack(pop)

typedef struct {
    uint32_t process_index;
    uint32_t process_id;
    uint32_t parent_process_id;
    uint32_t parent_process_index;
    uint64_t authentication_id;
    uint32_t session_number;
    uint32_t unknown1;
    uint64_t start_time;    // FILETIME
    uint64_t end_time;      // FILETIME
    uint32_t is_virtualized;
    uint32_t is_64_bit;
    uint32_t integrity_si;
    uint32_t user_name_si;
    uint32_t process_name_si;
    uint32_t image_path_si;
    uint32_t command_line_si;
    uint32_t company_si;
    uint32_t version_si;
    uint32_t description_si;
    uint32_t icon_index_big;
    uint32_t icon_index_small;
} procmon_raw_process_t;

typedef struct {
    uint32_t unknown1;
    uint32_t base_address;
    uint32_t size;
    uint32_t image_path_si;
    uint32_t version_si;
    uint32_t company_si;
    uint32_t description_si;
    uint32_t timestamp;
    uint64_t unknown2[3];
} procmon_raw_module_32_t;

typedef struct {
    uint64_t unknown1;
    uint64_t base_address;
    uint32_t size;
    uint32_t image_path_si;
    uint32_t version_si;
    uint32_t company_si;
    uint32_t description_si;
    uint32_t timestamp;
    uint64_t unknown2[3];
} procmon_raw_module_64_t;

typedef struct {
    procmon_header_t header;
    uint32_t *event_offsets;
    uint32_t cur_event;
    const char **string_array;
    size_t string_array_size;
    uint32_t *process_index_map;    /* Map of process index to process array index */
    size_t process_index_map_size;
    struct procmon_process_t *process_array;
    size_t process_array_size;
} procmon_file_info_t;

#define COMMON_EVENT_STRUCT_SIZE 52
// Most of these are arbitrary
#define MAX_PROCMON_EVENTS (500 * 1000 * 1000)
#define MAX_PROCMON_STRINGS (1000 * 1000)
#define MAX_PROCMON_STRING_LENGTH 8192
#define MAX_PROCMON_PROCESSES (500 * 1000)
#define MAX_PROCMON_MODULES 1000

static int procmon_file_type_subtype = -1;

void register_procmon(void);

static void file_info_cleanup(procmon_file_info_t* file_info)
{
    g_free(file_info->event_offsets);
    g_free(file_info->string_array);
    g_free(file_info->process_index_map);
    if (file_info->process_array) {
        for (size_t idx = 0; idx < file_info->process_array_size; idx++) {
            g_free(file_info->process_array[idx].modules);
        }
        g_free(file_info->process_array);
    }
    g_free(file_info);
}

static const char *procmon_string(procmon_file_info_t* file_info, uint32_t str_index)
{
    if (str_index >= file_info->string_array_size) {
        return "<unknown>";
    }
    return file_info->string_array[str_index];
}

static char *procmon_read_string(FILE_T fh, gunichar2 *str_buf, int *err, char **err_info)
{
    uint32_t cur_str_size;
    if (!wtap_read_bytes_or_eof(fh, &cur_str_size, sizeof(cur_str_size), err, err_info))
    {
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
        {
            // Short read or EOF.
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
        }
        return NULL;
    }
    cur_str_size = GUINT32_FROM_LE(cur_str_size);
    if (cur_str_size > MAX_PROCMON_STRING_LENGTH)
    {
        if (file_seek(fh, cur_str_size - MAX_PROCMON_STRING_LENGTH, SEEK_CUR, err) == -1)
        {
            ws_debug("Failed to skip excess string data");
            return NULL;
        }
        ws_debug("Truncating string from %u bytes to %u", cur_str_size, MAX_PROCMON_STRING_LENGTH);
        cur_str_size = MAX_PROCMON_STRING_LENGTH;
    }
    // XXX Make sure cur_str_size is even?
    if (!wtap_read_bytes_or_eof(fh, str_buf, cur_str_size, err, err_info))
    {
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
        {
            // Short read or EOF.
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
        }
        return NULL;
    }
    return g_utf16_to_utf8(str_buf, cur_str_size, NULL, NULL, NULL);
}

// Read the hosts array. Assume failures here are non-fatal.
static void procmon_read_hosts(wtap *wth, int64_t host_port_array_offset, int *err, char **err_info)
{
    if (!(wth->add_new_ipv4 && wth->add_new_ipv6)) {
        return;
    }

    if (file_seek(wth->fh, host_port_array_offset, SEEK_SET, err) == -1)
    {
        ws_debug("Failed to locate procmon hosts+ports data");
        return;
    }
    uint32_t num_hosts;
    if (!wtap_read_bytes_or_eof(wth->fh, &num_hosts, sizeof(num_hosts), err, err_info))
    {
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        return;
    }
    num_hosts = GUINT32_FROM_LE(num_hosts);
    if (num_hosts > MAX_PROCMON_STRINGS)
    {
        ws_debug("Truncating hosts from %u to %u", num_hosts, MAX_PROCMON_STRINGS);
        num_hosts = MAX_PROCMON_STRINGS;
    }
    gunichar2 *str_buf = g_new(gunichar2, MAX_PROCMON_STRING_LENGTH);
    // Procmon appears to use the hosts table to store ASCII representations of
    // addresses, so skip those.
    GRegex *numeric_re = g_regex_new("^([0-9.]+|.*:.*)$", (GRegexCompileFlags)(G_REGEX_CASELESS | G_REGEX_RAW | G_REGEX_OPTIMIZE), (GRegexMatchFlags)0, NULL);
    for (unsigned idx = 0; idx < num_hosts; idx++)
    {
        ws_in6_addr addr;
        if (!wtap_read_bytes_or_eof(wth->fh, &addr, sizeof(addr), err, err_info))
        {
            ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
            return;
        }
        char *name = procmon_read_string(wth->fh, str_buf, err, err_info);
        if (!name) {
            continue;
        }
        if (g_regex_match(numeric_re, name, (GRegexMatchFlags)0, NULL))
        {
            g_free(name);
            continue;
        }
        // The PML format gives us a 16 byte blob with no indication as to
        // whether or not the blob is a v4 or v6 address. Given that there are
        // several pingable v6 addresses that end with 12 bytes of zeroes (at
        // the time of this writing 2600::, 2409::, 2a09::, and 2a11:: are all
        // pingable), let's assume that all addresses are v6 and ones that end
        // with 12 bytes of zeroes are also v4.
        wth->add_new_ipv6(&addr, name, false);
        if (!*(uint32_t*)(&addr.bytes[4]) && !*(uint64_t*)(&addr.bytes[8])) {
            ws_in4_addr v4addr = *(uint32_t *)(&addr.bytes[4]);
            wth->add_new_ipv4(v4addr, name, false);
        }
        g_free(name);
    }
    g_regex_unref(numeric_re);
    g_free(str_buf);
}

static bool procmon_read_event(FILE_T fh, wtap_rec* rec, procmon_file_info_t* file_info, int* err, char** err_info)
{
    wtapng_block_t wblock;
    procmon_event_header_t event_header;

    wblock.rec = rec;

    wblock.block = wtap_block_create(WTAP_BLOCK_FT_SPECIFIC_EVENT);

    wblock.rec->presence_flags = WTAP_HAS_CAP_LEN;
    wblock.rec->tsprec = WTAP_TSPREC_NSEC;

    /* Read the event header */
    if (!wtap_read_bytes(fh, &event_header, sizeof event_header, err, err_info)) {
        ws_debug("Failed to read procmon process index");
        return false;
    }

    /* Append the raw data of the event header */
    ws_buffer_append(&wblock.rec->data, (const uint8_t*)&event_header, sizeof event_header);

    wblock.rec->presence_flags |= WTAP_HAS_TS;
    filetime_to_nstime(&wblock.rec->ts, GUINT64_FROM_LE(event_header.timestamp));

    /* Read stack trace data */
    uint32_t sizeof_stacktrace = event_header.stack_trace_depth * (file_info->header.system_bitness ? 8 : 4);

    /* Append the size of the stack trace data so the dissector doesn't need to know about system bitness */
    ws_buffer_append(&wblock.rec->data, (const uint8_t*)&sizeof_stacktrace, sizeof sizeof_stacktrace);

    if (!wtap_read_bytes_buffer(fh, &wblock.rec->data, sizeof_stacktrace, err, err_info)) {
        ws_debug("Failed to read procmon stack trace data");
        return false;
    }

    /* Read detail data */
    if (!wtap_read_bytes_buffer(fh, &wblock.rec->data, event_header.details_size, err, err_info)) {
        ws_debug("Failed to read procmon detail data");
        return false;
    }

    if (event_header.extra_details_offset > 0)
    {
        int64_t current_offset = file_tell(fh);

        /* The extra details structure surprisingly can be separated from the event structure */
        int64_t real_details_offset = event_header.extra_details_offset - (COMMON_EVENT_STRUCT_SIZE + event_header.details_size + sizeof_stacktrace);
        if (file_seek(fh, real_details_offset, SEEK_CUR, err) == -1) {
            ws_debug("Failed to locate procmon extra details data");
            return false;
        }
        /* However, pass the record data up as if it's consecutive */
        uint16_t extra_details_stream_size;
        if (!wtap_read_bytes(fh, &extra_details_stream_size, sizeof extra_details_stream_size, err, err_info)) {
            ws_debug("Failed to read procmon extra details offset");
            return false;
        }
        ws_buffer_append(&wblock.rec->data, (const uint8_t*)&extra_details_stream_size, sizeof extra_details_stream_size);

        if (!wtap_read_bytes_buffer(fh, &wblock.rec->data, extra_details_stream_size, err, err_info)) {
            ws_debug("Failed to read procmon extra detail data");
            return false;
        }

        /* If the extra data doesn't immediately follow the other data */
        if (real_details_offset != 0)
        {
            if (file_seek(fh, current_offset, SEEK_SET, err) == -1) {
                ws_debug("Failed to restore procmon event data location");
                return false;
            }
        }
    }

    /*
     * We return these to the caller in procmon_read().
     */
    wtap_setup_ft_specific_event_rec(wblock.rec, procmon_file_type_subtype, event_header.event_class);
    wblock.rec->rec_header.ft_specific_header.record_len = (uint32_t)ws_buffer_length(&wblock.rec->data);
    wblock.rec->rec_header.ft_specific_header.pseudo_header.procmon.process_index_map = file_info->process_index_map;
    wblock.rec->rec_header.ft_specific_header.pseudo_header.procmon.process_index_map_size = file_info->process_index_map_size;
    wblock.rec->rec_header.ft_specific_header.pseudo_header.procmon.process_array = file_info->process_array;
    wblock.rec->rec_header.ft_specific_header.pseudo_header.procmon.process_array_size = file_info->process_array_size;
    wblock.rec->rec_header.ft_specific_header.pseudo_header.procmon.system_bitness = (file_info->header.system_bitness != 0);
    wblock.internal = false;

    /*
     * We want dissectors (particularly packet_frame) to be able to
     * access packet comments and whatnot that are in the block. wblock->block
     * will be unref'd by procmon_seek_read(), so move the block to where
     * dissectors can find it.
     */
    wblock.rec->block = wblock.block;
    wblock.block = NULL;
    return true;
}

static bool procmon_read(wtap *wth, wtap_rec *rec,
    int *err, char **err_info, int64_t *data_offset)
{
    procmon_file_info_t* file_info = (procmon_file_info_t*)wth->priv;

    // file.c and strato.c call wtap_set_cb_new_ipv{4,6} after calling
    // wtap_open_offline, so read our hosts array here.
    if (file_info->cur_event == 0) {
        procmon_read_hosts(wth, file_info->header.host_port_array_offset, err, err_info);
    }

    *data_offset = file_info->event_offsets[file_info->cur_event];
    ws_noisy("file offset is %" PRId64 " array offset is %" PRId64, file_tell(wth->fh), *data_offset);

    if (file_seek(wth->fh, *data_offset, SEEK_SET, err) == -1)
    {
        ws_debug("Failed to seek to event %u at offsets %" PRId64, file_info->cur_event, *data_offset);
        return false;
    }

    /* Stop processing once offset reaches past events */
    if (file_info->cur_event >= file_info->header.num_events)
    {
        ws_debug("end of events");
        return false;
    }
    file_info->cur_event++;

    // if (*data_offset+COMMON_EVENT_STRUCT_SIZE >= (int64_t)file_info->header.event_offsets_array_offset) {
    //     *err = WTAP_ERR_BAD_FILE;
    //     *err_info = ws_strdup_printf("procmon: Not enough room for event content at offset %"  PRIi64, *data_offset);
    //     return false;
    // }

    return procmon_read_event(wth->fh, rec, file_info, err, err_info);
}

static bool procmon_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
    int *err, char **err_info)
{
    procmon_file_info_t* file_info = (procmon_file_info_t*)wth->priv;

    /* seek to the right file position */
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) < 0) {
        return false;   /* Seek error */
    }
    ws_noisy("reading at offset %" PRIu64, seek_off);

    return procmon_read_event(wth->random_fh, rec, file_info, err, err_info);
}

static const uint8_t procmon_magic[] = { 'P', 'M', 'L', '_' };

wtap_open_return_val procmon_open(wtap *wth, int *err, char **err_info)
{
    procmon_file_info_t* file_info = g_new0(procmon_file_info_t, 1);
    procmon_header_t* header = &file_info->header;

    ws_debug("opening file");
    /*
     * First, try to read the procmon header.
     */
    if (!wtap_read_bytes_or_eof(wth->fh, header, sizeof(procmon_header_t), err, err_info))
    {
        file_info_cleanup(file_info);
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ) {
            /*
             * Short read or EOF.
             *
             * We're reading this as part of an open, so
             * the file is too short to be a procmon file.
             */
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
        }
        return WTAP_OPEN_NOT_MINE;
    }

    if (memcmp(&header->signature, procmon_magic, sizeof(procmon_magic)))
    {
        file_info_cleanup(file_info);
        return WTAP_OPEN_NOT_MINE;
    }

#if G_BYTE_ORDER == G_BIG_ENDIAN
    header->version = GUINT32_SWAP_LE_BE(header->version);
    header->system_bitness = GUINT32_SWAP_LE_BE(header->system_bitness);
    header->num_events = GUINT32_SWAP_LE_BE(header->num_events);
    header->start_events_offset = GUINT64_SWAP_LE_BE(header->start_events_offset);
    header->event_offsets_array_offset = GUINT64_SWAP_LE_BE(header->event_offsets_array_offset);
    header->process_array_offset = GUINT64_SWAP_LE_BE(header->process_array_offset);
    header->string_array_offset = GUINT64_SWAP_LE_BE(header->string_array_offset);
    header->icon_array_offset = GUINT64_SWAP_LE_BE(header->icon_array_offset);
    header->maximum_user_address = GUINT64_SWAP_LE_BE(header->maximum_user_address);
    header->os_version_info_size = GUINT32_SWAP_LE_BE(header->os_version_info_size);
    header->major_version = GUINT32_SWAP_LE_BE(header->major_version);
    header->minor_version = GUINT32_SWAP_LE_BE(header->minor_version);
    header->build_number = GUINT32_SWAP_LE_BE(header->build_number);
    header->platform_id = GUINT32_SWAP_LE_BE(header->platform_id);
    header->service_pack_major = GUINT16_SWAP_LE_BE(header->service_pack_major);
    header->service_pack_minor = GUINT16_SWAP_LE_BE(header->service_pack_minor);
    header->suite_mask = GUINT16_SWAP_LE_BE(header->suite_mask);
    header->num_processors = GUINT32_SWAP_LE_BE(header->num_processors);
    header->total_physical_memory = GUINT64_SWAP_LE_BE(header->total_physical_memory);
    header->start_events_offset_dup = GUINT64_SWAP_LE_BE(header->start_events_offset_dup);
    header->host_port_array_offset = GUINT64_SWAP_LE_BE(header->host_port_array_offset);
#endif

    if (header->num_events > MAX_PROCMON_EVENTS) {
        ws_debug("Truncating events from %u to %u", header->num_events, MAX_PROCMON_EVENTS);
        header->num_events = MAX_PROCMON_EVENTS;
    }

    // Read the event offsets array, which we use in procmon_read(). It's not clear
    // if we really need this; in a test capture here the offsets in the array were
    // identical to the file positions we end up with if we just read sequentially.
    if (file_seek(wth->fh, header->event_offsets_array_offset, SEEK_SET, err) == -1)
    {
        file_info_cleanup(file_info);
        ws_debug("Failed to locate event offsets data");
        return WTAP_OPEN_NOT_MINE;
    }
    file_info->event_offsets = g_new(uint32_t, header->num_events);
    for (unsigned idx = 0; idx < header->num_events; idx++) {
        uint32_t event_offset;
        // Each offset entry is a uint32_t offset followed by a uint8_t maybe-flags
        if (!wtap_read_bytes_or_eof(wth->fh, &event_offset, sizeof(event_offset), err, err_info))
        {
            file_info_cleanup(file_info);
            ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
            if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
            {
                // Short read or EOF.
                *err = 0;
                g_free(*err_info);
                *err_info = NULL;
            }
            return WTAP_OPEN_NOT_MINE;
        }
        if (file_seek(wth->fh, 1, SEEK_CUR, err) == -1)
        {
            file_info_cleanup(file_info);
            ws_debug("Failed to skip flags");
            return WTAP_OPEN_NOT_MINE;
        }
        file_info->event_offsets[idx] = GUINT32_FROM_LE(event_offset);
    }

    if (file_seek(wth->fh, header->string_array_offset, SEEK_SET, err) == -1)
    {
        ws_debug("Failed to locate procmon string data");
        return WTAP_OPEN_NOT_MINE;
    }

    uint32_t num_strings;
    if (!wtap_read_bytes_or_eof(wth->fh, &num_strings, sizeof(num_strings), err, err_info))
    {
        file_info_cleanup(file_info);
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
        {
            // Short read or EOF.
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
        }
        return WTAP_OPEN_NOT_MINE;
    }
    num_strings = GUINT32_FROM_LE(num_strings);
    if (num_strings > MAX_PROCMON_STRINGS) {
        ws_debug("Truncating strings from %u to %u", num_strings, MAX_PROCMON_STRINGS);
        num_strings = MAX_PROCMON_STRINGS;
    }

    // Strings aren't necessarily contiguous (or even in order?)
    uint32_t *str_offsets = g_new(uint32_t, num_strings);
    if (!wtap_read_bytes_or_eof(wth->fh, str_offsets, sizeof(uint32_t) * num_strings, err, err_info))
    {
        file_info_cleanup(file_info);
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
        {
            // Short read or EOF.
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
        }
        g_free(str_offsets);
        return WTAP_OPEN_NOT_MINE;
    }
#if G_BYTE_ORDER == G_BIG_ENDIAN
    for (unsigned idx = 0; idx < num_strings; idx++)
    {
        str_offsets[idx] = GUINT32_SWAP_LE_BE(str_offsets[idx]);
    }
#endif

    file_info->string_array_size = num_strings;
    file_info->string_array = g_new0(const char *, num_strings);
    gunichar2 *str_buf = g_new(gunichar2, MAX_PROCMON_STRING_LENGTH);
    for (unsigned idx = 0; idx < num_strings; idx++) {
        if (file_seek(wth->fh, header->string_array_offset + str_offsets[idx], SEEK_SET, err) == -1)
        {
            file_info_cleanup(file_info);
            g_free(str_offsets);
            g_free(str_buf);
            ws_debug("Failed to locate procmon string %u", idx);
            return WTAP_OPEN_NOT_MINE;
        }

        const char *cur_str = procmon_read_string(wth->fh, str_buf, err, err_info);
        if (!cur_str) {
            file_info_cleanup(file_info);
            g_free(str_offsets);
            g_free(str_buf);
            ws_debug("Failed to read procmon string %u", idx);
            return WTAP_OPEN_NOT_MINE;
        }

        file_info->string_array[idx] = cur_str;
    }
    g_free(str_offsets);
    g_free(str_buf);

    if (file_seek(wth->fh, header->process_array_offset, SEEK_SET, err) == -1)
    {
        ws_debug("Failed to locate procmon process data");
        return WTAP_OPEN_NOT_MINE;
    }

    uint32_t num_processes;
    if (!wtap_read_bytes_or_eof(wth->fh, &num_processes, sizeof(num_processes), err, err_info))
    {
        file_info_cleanup(file_info);
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
        {
            // Short read or EOF.
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
        }
        return WTAP_OPEN_NOT_MINE;
    }
    num_processes = GUINT32_FROM_LE(num_processes);
    if (num_processes > MAX_PROCMON_PROCESSES) {
        ws_debug("Truncating processes from %u to %u", num_processes, MAX_PROCMON_PROCESSES);
        num_processes = MAX_PROCMON_PROCESSES;
    }

    uint32_t *process_indices = g_new(uint32_t, num_processes);
    if (!wtap_read_bytes_or_eof(wth->fh, process_indices, sizeof(uint32_t) * num_processes, err, err_info))
    {
        file_info_cleanup(file_info);
        g_free(process_indices);
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
        {
            // Short read or EOF.
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
        }
        return WTAP_OPEN_NOT_MINE;
    }

    uint32_t max_process_index = 0;
    for (unsigned idx = 0; idx < num_processes; idx++) {
        process_indices[idx] = GUINT32_FROM_LE(process_indices[idx]);
        max_process_index = MAX(max_process_index, process_indices[idx]);
    }
    g_free(process_indices);
    if (max_process_index > MAX_PROCMON_PROCESSES * 2) {
        ws_debug("Truncating max process index from %u to %u", max_process_index, MAX_PROCMON_PROCESSES * 2);
        max_process_index = MAX_PROCMON_PROCESSES * 2;
    }
    file_info->process_index_map = g_new(uint32_t, max_process_index + 1);
    // Try to make invalid entries obvious.
    memset(file_info->process_index_map, 0xff, sizeof(uint32_t) * (max_process_index + 1));
    file_info->process_index_map_size = max_process_index + 1;

    uint32_t *proc_offsets = g_new(uint32_t, num_processes);
    if (!wtap_read_bytes_or_eof(wth->fh, proc_offsets, sizeof(uint32_t) * num_processes, err, err_info))
    {
        file_info_cleanup(file_info);
        g_free(proc_offsets);
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
        {
            // Short read or EOF.
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
        }
        return WTAP_OPEN_NOT_MINE;
    }

    file_info->process_array = g_new(procmon_process_t, num_processes);
    file_info->process_array_size = num_processes;
    for (unsigned idx = 0; idx < num_processes; idx++) {
        if (file_seek(wth->fh, header->process_array_offset + proc_offsets[idx], SEEK_SET, err) == -1)
        {
            file_info_cleanup(file_info);
            g_free(proc_offsets);
            ws_debug("Failed to locate procmon process %u", idx);
            return WTAP_OPEN_NOT_MINE;
        }
        procmon_raw_process_t cur_raw_process;
        if (!wtap_read_bytes_or_eof(wth->fh, &cur_raw_process, sizeof(cur_raw_process), err, err_info))
        {
            file_info_cleanup(file_info);
            g_free(proc_offsets);
            ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
            if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
            {
                // Short read or EOF.
                *err = 0;
                g_free(*err_info);
                *err_info = NULL;
            }
            return WTAP_OPEN_NOT_MINE;
        }
        uint32_t process_index = GUINT32_FROM_LE(cur_raw_process.process_index);
        if (process_index <= max_process_index) {
            file_info->process_index_map[process_index] = idx;
        } else {
            ws_debug("Process %u index %u exceeds max process index %u", idx, process_index, max_process_index);
        }
        procmon_process_t *cur_process = &file_info->process_array[idx];
        cur_raw_process.start_time = GUINT64_FROM_LE(cur_raw_process.start_time);
        cur_raw_process.end_time = GUINT64_FROM_LE(cur_raw_process.end_time);
        uint64_t filetime = GUINT64_FROM_LE(cur_raw_process.start_time);
        filetime_to_nstime(&cur_process->start_time, filetime);
        filetime = GUINT64_FROM_LE(cur_raw_process.end_time);
        filetime_to_nstime(&cur_process->end_time, filetime);

        cur_process->process_id = GUINT32_FROM_LE(cur_raw_process.process_id);
        cur_process->parent_process_id = GUINT32_FROM_LE(cur_raw_process.parent_process_id);
        cur_process->parent_process_index = MAX(GUINT32_FROM_LE(cur_raw_process.parent_process_index), max_process_index);
        cur_process->authentication_id = GUINT64_FROM_LE(cur_raw_process.authentication_id);
        cur_process->session_number = GUINT32_FROM_LE(cur_raw_process.session_number);
        cur_process->is_virtualized = cur_raw_process.is_virtualized != 0;
        cur_process->is_64_bit = cur_raw_process.is_64_bit != 0;
        cur_process->integrity = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_process.integrity_si));
        cur_process->user_name = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_process.user_name_si));
        cur_process->process_name = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_process.process_name_si));
        cur_process->image_path = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_process.image_path_si));
        cur_process->command_line = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_process.command_line_si));
        cur_process->company = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_process.company_si));
        cur_process->version = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_process.version_si));
        cur_process->description = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_process.description_si));
        if (file_seek(wth->fh, header->system_bitness ? 8 : 4, SEEK_CUR, err) == -1)
        {
            file_info_cleanup(file_info);
            g_free(proc_offsets);
            ws_debug("Failed to locate number of modules %u", idx);
            return WTAP_OPEN_NOT_MINE;
        }
        uint32_t num_modules;
        if (!wtap_read_bytes_or_eof(wth->fh, &num_modules, sizeof(num_modules), err, err_info))
        {
            file_info_cleanup(file_info);
            g_free(proc_offsets);
            ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
            if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
            {
                // Short read or EOF.
                *err = 0;
                g_free(*err_info);
                *err_info = NULL;
            }
            return WTAP_OPEN_NOT_MINE;
        }

        cur_process->num_modules = MIN(GUINT32_FROM_LE(num_modules), MAX_PROCMON_MODULES);
        if (cur_process->num_modules > 0) {
            cur_process->modules = g_new(procmon_module_t, cur_process->num_modules);
            for (unsigned mod_idx = 0; mod_idx < cur_process->num_modules; mod_idx++) {
                if (cur_process->is_64_bit) {
                procmon_raw_module_64_t cur_raw_module;
                    if (!wtap_read_bytes_or_eof(wth->fh, &cur_raw_module, sizeof(cur_raw_module), err, err_info)) {
                        file_info_cleanup(file_info);
                        g_free(proc_offsets);
                        g_free(cur_process->modules);
                        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
                        if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
                        {
                            // Short read or EOF.
                            *err = 0;
                            g_free(*err_info);
                            *err_info = NULL;
                        }
                        return WTAP_OPEN_NOT_MINE;
                    }
                    procmon_module_t *cur_module = &cur_process->modules[mod_idx];
                    cur_module->base_address = GUINT64_FROM_LE(cur_raw_module.base_address);
                    cur_module->size = GUINT32_FROM_LE(cur_raw_module.size);
                    cur_module->image_path = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_module.image_path_si));
                    cur_module->version = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_module.version_si));
                    cur_module->company = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_module.company_si));
                    cur_module->description = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_module.description_si));
                    // filetime = GUINT64_FROM_LE(cur_raw_module.timestamp);
                    // filetime_to_nstime(&cur_module->timestamp, filetime);
                } else {
                    procmon_raw_module_32_t cur_raw_module;
                    if (!wtap_read_bytes_or_eof(wth->fh, &cur_raw_module, sizeof(cur_raw_module), err, err_info)) {
                        file_info_cleanup(file_info);
                        g_free(proc_offsets);
                        g_free(cur_process->modules);
                        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
                        if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
                        {
                            // Short read or EOF.
                            *err = 0;
                            g_free(*err_info);
                            *err_info = NULL;
                        }
                        return WTAP_OPEN_NOT_MINE;
                    }
                    procmon_module_t *cur_module = &cur_process->modules[mod_idx];
                    cur_module->base_address = GUINT32_FROM_LE(cur_raw_module.base_address);
                    cur_module->size = GUINT32_FROM_LE(cur_raw_module.size);
                    cur_module->image_path = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_module.image_path_si));
                    cur_module->version = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_module.version_si));
                    cur_module->company = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_module.company_si));
                    cur_module->description = procmon_string(file_info, GUINT32_FROM_LE(cur_raw_module.description_si));
                    // filetime = GUINT64_FROM_LE(cur_raw_module.timestamp);
                    // filetime_to_nstime(&cur_module->timestamp, filetime);
                }
            }
        } else {
            cur_process->modules = NULL;
        }
    }
    g_free(proc_offsets);

    if (file_seek(wth->fh, header->start_events_offset, SEEK_SET, err) == -1)
    {
        ws_debug("Failed to locate procmon events data");
        return WTAP_OPEN_NOT_MINE;
    }

    wth->meta_events = g_array_new(false, false, sizeof(wtap_block_t));

    wth->priv = file_info;
    wth->file_type_subtype = procmon_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_PROCMON;

    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_SEC;

    wth->subtype_read = procmon_read;
    wth->subtype_seek_read = procmon_seek_read;

    return WTAP_OPEN_MINE;
}

/* Options for meta event blocks. */
static const struct supported_option_type ft_specific_event_block_options_supported[] = {
    { OPT_COMMENT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED }
};

static const struct supported_block_type procmon_blocks_supported[] = {

    /* Multiple file-type specific events (including local ones). */
    { WTAP_BLOCK_FT_SPECIFIC_EVENT, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(ft_specific_event_block_options_supported) },

    /* Multiple custom blocks. */
    { WTAP_BLOCK_CUSTOM, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED },
};

static const struct file_type_subtype_info procmon_info = {
    "MS Procmon files", "procmon", NULL, NULL,
    false, BLOCKS_SUPPORTED(procmon_blocks_supported),
    NULL, NULL, NULL
};

void register_procmon(void)
{
    procmon_file_type_subtype = wtap_register_file_type_subtype(&procmon_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("Procmon", procmon_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
