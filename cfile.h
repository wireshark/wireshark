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
    gchar                      *filename;             /* Name of capture file */
    gchar                      *source;               /* Temp file source, e.g. "Pipe from elsewhere" */
    gboolean                    is_tempfile;          /* Is capture file a temporary file? */
    gboolean                    unsaved_changes;      /* Does the capture file have changes that have not been saved? */
    gboolean                    stop_flag;            /* Stop current processing (loading, searching, etc.) */

    gint64                      f_datalen;            /* Size of capture file data (uncompressed) */
    guint16                     cd_t;                 /* File type of capture file */
    unsigned int                open_type;            /* open_routine index+1 used, if selected, or WTAP_TYPE_AUTO */
    wtap_compression_type       compression_type;     /* Compression type of the file, or uncompressed */
    int                         lnk_t;                /* File link-layer type; could be WTAP_ENCAP_PER_PACKET */
    GArray                     *linktypes;            /* Array of packet link-layer types */
    guint32                     count;                /* Total number of frames */
    guint64                     packet_comment_count; /* Number of comments in frames (could be >1 per frame... */
    guint32                     displayed_count;      /* Number of displayed frames */
    guint32                     marked_count;         /* Number of marked frames */
    guint32                     ignored_count;        /* Number of ignored frames */
    guint32                     ref_time_count;       /* Number of time referenced frames */
    gboolean                    drops_known;          /* TRUE if we know how many packets were dropped */
    guint32                     drops;                /* Dropped packets */
    nstime_t                    elapsed_time;         /* Elapsed time */
    int                         snap;                 /* Maximum captured packet length; 0 if unknown */
    dfilter_t                  *rfcode;               /* Compiled read filter program */
    dfilter_t                  *dfcode;               /* Compiled display filter program */
    gchar                      *dfilter;              /* Display filter string */
    gboolean                    redissecting;         /* TRUE if currently redissecting (cf_redissect_packets) */
    gboolean                    read_lock;            /* TRUE if currently processing a file (cf_read) */
    rescan_type                 redissection_queued;  /* Queued redissection type. */
    /* search */
    gchar                      *sfilter;              /* Filter, hex value, or string being searched */
    gboolean                    hex;                  /* TRUE if "Hex value" search was last selected */
    gboolean                    string;               /* TRUE if "String" search was last selected */
    gboolean                    summary_data;         /* TRUE if "String" search in "Packet list" (Info column) was last selected */
    gboolean                    decode_data;          /* TRUE if "String" search in "Packet details" was last selected */
    gboolean                    packet_data;          /* TRUE if "String" search in "Packet data" was last selected */
    guint32                     search_pos;           /* Byte position of last byte found in a hex search */
    guint32                     search_len;           /* Length of bytes matching the search */
    gboolean                    case_type;            /* TRUE if case-insensitive text search */
    GRegex                     *regex;                /* Set if regular expression search */
    search_charset_t            scs_type;             /* Character set for text search */
    search_direction            dir;                  /* Direction in which to do searches */
    gboolean                    search_in_progress;   /* TRUE if user just clicked OK in the Find dialog or hit <control>N/B */
    /* packet provider */
    struct packet_provider_data provider;
    /* frames */
    guint32                     first_displayed;      /* Frame number of first frame displayed */
    guint32                     last_displayed;       /* Frame number of last frame displayed */
    /* Data for currently selected frame */
    column_info                 cinfo;                /* Column formatting information */
    frame_data                 *current_frame;        /* Frame data */
    epan_dissect_t             *edt;                  /* Protocol dissection */
    field_info                 *finfo_selected;       /* Field info */
    wtap_rec                    rec;                  /* Record header */
    Buffer                      buf;                  /* Record data */

    gpointer                    window;               /* Top-level window associated with file */
    gulong                      computed_elapsed;     /* Elapsed time to load the file (in msec). */

    guint32                     cum_bytes;
} capture_file;

extern void cap_file_init(capture_file *cf);

const char *cap_file_provider_get_interface_name(struct packet_provider_data *prov, guint32 interface_id);
const char *cap_file_provider_get_interface_description(struct packet_provider_data *prov, guint32 interface_id);
wtap_block_t cap_file_provider_get_modified_block(struct packet_provider_data *prov, const frame_data *fd);
void cap_file_provider_set_modified_block(struct packet_provider_data *prov, frame_data *fd, const wtap_block_t new_block);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* cfile.h */
