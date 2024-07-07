/** @file
 *
 * capture_file definition & GUI-independent manipulation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CFILE_H__
#define __CFILE_H__

#include <epan/epan.h>
#include <epan/column-info.h>
#include <epan/dfilter/dfilter.h>
#include <epan/frame_data.h>
#include <epan/frame_data_sequence.h>
#include <wiretap/wtap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Current state of file. */
typedef enum {
    FILE_CLOSED,                  /* No file open */
    FILE_READ_PENDING,            /* A file to read, but haven't opened it yet */
    FILE_READ_IN_PROGRESS,        /* Reading a file we've opened */
    FILE_READ_ABORTED,            /* Read aborted by user */
    FILE_READ_DONE                /* Read completed */
} file_state;

/* Requested packets rescan action. */
typedef enum {
    RESCAN_NONE = 0,              /* No rescan requested */
    RESCAN_SCAN,                  /* Request rescan without full redissection. */
    RESCAN_REDISSECT              /* Request full redissection. */
} rescan_type;

/* Character set for text search. */
typedef enum {
    SCS_NARROW_AND_WIDE,
    SCS_NARROW,
    SCS_WIDE
        /* add EBCDIC when it's implemented */
} search_charset_t;

typedef enum {
    SD_FORWARD,
    SD_BACKWARD
} search_direction;

/*
 * Packet provider for programs using a capture file.
 */
struct packet_provider_data {
    wtap        *wth;                    /* Wiretap session */
    const frame_data *ref;
    frame_data  *prev_dis;
    frame_data  *prev_cap;
    frame_data_sequence *frames;         /* Sequence of frames, if we're keeping that information */
    GTree       *frames_modified_blocks; /* BST with modified blocks for frames (key = frame_data) */
};

typedef struct _capture_file {
    epan_t                     *epan;
    file_state                  state;                /* Current state of capture file */
    char                       *filename;             /* Name of capture file */
    char                       *source;               /* Temp file source, e.g. "Pipe from elsewhere" */
    bool                        is_tempfile;          /* Is capture file a temporary file? */
    bool                        unsaved_changes;      /* Does the capture file have changes that have not been saved? */
    bool                        stop_flag;            /* Stop current processing (loading, searching, etc.) */

    int64_t                     f_datalen;            /* Size of capture file data (uncompressed) */
    uint16_t                    cd_t;                 /* File type of capture file */
    unsigned int                open_type;            /* open_routine index+1 used, if selected, or WTAP_TYPE_AUTO */
    wtap_compression_type       compression_type;     /* Compression type of the file, or uncompressed */
    int                         lnk_t;                /* File link-layer type; could be WTAP_ENCAP_PER_PACKET */
    GArray                     *linktypes;            /* Array of packet link-layer types */
    uint32_t                    count;                /* Total number of frames */
    uint64_t                    packet_comment_count; /* Number of comments in frames (could be >1 per frame... */
    uint32_t                    displayed_count;      /* Number of displayed frames */
    uint32_t                    marked_count;         /* Number of marked frames */
    uint32_t                    ignored_count;        /* Number of ignored frames */
    uint32_t                    ref_time_count;       /* Number of time referenced frames */
    bool                        drops_known;          /* true if we know how many packets were dropped */
    uint32_t                    drops;                /* Dropped packets */
    nstime_t                    elapsed_time;         /* Elapsed time */
    int                         snap;                 /* Maximum captured packet length; 0 if unknown */
    dfilter_t                  *rfcode;               /* Compiled read filter program */
    dfilter_t                  *dfcode;               /* Compiled display filter program */
    char                       *dfilter;              /* Display filter string */
    bool                        redissecting;         /* true if currently redissecting (cf_redissect_packets) */
    bool                        read_lock;            /* true if currently processing a file (cf_read) */
    rescan_type                 redissection_queued;  /* Queued redissection type. */
    /* search */
    char                       *sfilter;              /* Filter, hex value, or string being searched */
    /* XXX: Some of these booleans should be enums; they're exclusive cases */
    bool                        hex;                  /* true if "Hex value" search was last selected */
    bool                        string;               /* true if "String" (or "Regex"?) search was last selected */
    bool                        summary_data;         /* true if "String" search in "Packet list" (Info column) was last selected */
    bool                        decode_data;          /* true if "String" search in "Packet details" was last selected */
    bool                        packet_data;          /* true if "String" search in "Packet data" was last selected */
    uint32_t                    search_pos;           /* Byte position of first byte found in a hex search */
    uint32_t                    search_len;           /* Length of bytes matching the search */
    bool                        case_type;            /* true if case-insensitive text search */
    ws_regex_t                 *regex;                /* Set if regular expression search */
    search_charset_t            scs_type;             /* Character set for text search */
    search_direction            dir;                  /* Direction in which to do searches */
    bool                        search_in_progress;   /* true if user just clicked OK in the Find dialog or hit <control>N/B */
    /* packet provider */
    struct packet_provider_data provider;
    /* frames */
    uint32_t                    first_displayed;      /* Frame number of first frame displayed */
    uint32_t                    last_displayed;       /* Frame number of last frame displayed */
    /* Data for currently selected frame */
    column_info                 cinfo;                /* Column formatting information */
    frame_data                 *current_frame;        /* Frame data */
    epan_dissect_t             *edt;                  /* Protocol dissection */
    field_info                 *finfo_selected;       /* Field info */
    wtap_rec                    rec;                  /* Record header */
    Buffer                      buf;                  /* Record data */

    void *                      window;               /* Top-level window associated with file */
    unsigned long               computed_elapsed;     /* Elapsed time to load the file (in msec). */

    uint32_t                    cum_bytes;
} capture_file;

extern void cap_file_init(capture_file *cf);

const nstime_t *cap_file_provider_get_frame_ts(struct packet_provider_data *prov, uint32_t frame_num);
const char *cap_file_provider_get_interface_name(struct packet_provider_data *prov, uint32_t interface_id, unsigned section_number);
const char *cap_file_provider_get_interface_description(struct packet_provider_data *prov, uint32_t interface_id, unsigned section_number);
wtap_block_t cap_file_provider_get_modified_block(struct packet_provider_data *prov, const frame_data *fd);
void cap_file_provider_set_modified_block(struct packet_provider_data *prov, frame_data *fd, const wtap_block_t new_block);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* cfile.h */
