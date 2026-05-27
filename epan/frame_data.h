/* frame_data.h
 * Definitions for frame_data structures and routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <ws_diag_control.h>
#include <ws_symbol_export.h>
#include <wsutil/nstime.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct wtap_rec wtap_rec;
struct _packet_info;
struct epan_session;

#define PINFO_FD_VISITED(pinfo)   ((pinfo)->fd->visited)

/** @file
 * Low-level frame data and metadata.
 */

/** @defgroup framedata Frame Data
 *
 * @{
 */

/** @todo XXX - some of this stuff is used only while a packet is being dissected;
   should we keep that stuff in the "packet_info" structure, instead, to
   save memory? */

/** @brief Types of character encodings */
typedef enum {
  PACKET_CHAR_ENC_CHAR_ASCII     = 0, /**< ASCII */
  PACKET_CHAR_ENC_CHAR_EBCDIC    = 1  /**< EBCDIC */
} packet_char_enc;


/** The frame number is the ordinal number of the frame in the capture, so
   it's 1-origin.  In various contexts, 0 as a frame number means "frame
   number unknown".

   There is one of these structures for every frame in the capture.
   That means a lot of memory if we have a lot of frames.
   They are packed into power-of-2 chunks, so their size is effectively
   rounded up to a power of 2.
   Try to keep it close to, and less than or equal to, a power of 2.
   "Smaller than a power of 2" is OK for ILP32 platforms.

   XXX - shuffle the fields to try to keep the most commonly-accessed
   fields within the first 16 or 32 bytes, so they all fit in a cache
   line? */
struct _color_filter; /* Forward */
DIAG_OFF_PEDANTIC
typedef struct _frame_data {
  uint32_t     num;          /**< Frame number */
  uint32_t     dis_num;      /**< Displayed frame number */
  uint32_t     pkt_len;      /**< Packet length */
  uint32_t     cap_len;      /**< Amount actually captured */
  int64_t      file_off;     /**< File offset */
  /* These two are pointers, meaning 64-bit on LP64 (64-bit UN*X) and
     LLP64 (64-bit Windows) platforms.  Put them here, one after the
     other, so they don't require padding between them. */
  GSList      *pfd;          /**< Per frame proto data */
  GHashTable  *dependent_frames;     /**< A hash table of frames which this one depends on */
  const struct _color_filter *color_filter;  /**< Per-packet matching color_filter_t object */
  uint32_t     cum_bytes;    /**< Cumulative bytes into the capture */
  /* XXX - cum_bytes presumably ought to be 64-bit as well now */
  uint8_t      tcp_snd_manual_analysis;   /**< TCP SEQ Analysis Overriding, 0 = none, 1 = OOO, 2 = RET , 3 = Fast RET, 4 = Spurious RET  */
  /* Keep the bitfields below to 24 bits, so this plus the previous field
     are 32 bits. (XXX - The previous field could be a bitfield too.) */
  unsigned int passed_dfilter   : 1; /**< 1 = display, 0 = no display */
  unsigned int dependent_of_displayed : 1; /**< 1 if a displayed frame depends on this frame */
  /* Do NOT use packet_char_enc enum here: MSVC compiler does not handle an enum in a bit field properly */
  unsigned int encoding         : 1; /**< Character encoding (ASCII, EBCDIC...) */
  unsigned int visited          : 1; /**< Has this packet been visited yet? 1=Yes,0=No*/
  unsigned int marked           : 1; /**< 1 = marked by user, 0 = normal */
  unsigned int ref_time         : 1; /**< 1 = marked as a reference time frame, 0 = normal */
  unsigned int ignored          : 1; /**< 1 = ignore this frame, 0 = normal */
  unsigned int has_ts           : 1; /**< 1 = has time stamp, 0 = no time stamp */
  unsigned int has_modified_block : 1; /** 1 = block for this packet has been modified */
  unsigned int need_colorize    : 1; /**< 1 = need to (re-)calculate packet color */
  unsigned int tsprec           : 4; /**< Time stamp precision -2^tsprec gives up to femtoseconds */
  nstime_t     abs_ts;       /**< Absolute timestamp */
  nstime_t     shift_offset; /**< How much the abs_tm of the frame is shifted */
  uint32_t     frame_ref_num; /**< Reference frame for relative timestamps (can be this frame) */
  /* frame_ref_num == num if ref_time == true, but also if this is the first
   * record that has_ts (or if somehow a record without a TS is a reference
   * time frame, the first frame after that with has_ts == true.) */
  uint32_t     prev_dis_num; /**< Previous displayed frame (0 if first one) */
  gchar*       aggregation_key; /**< Holds the aggregation_key values used for rendering the aggregation view. */
  bool         aggregated; /**<  * True if this frame is not displayed individually because it is represented
   * by another frame sharing the same aggregation_key. */
} frame_data;
DIAG_ON_PEDANTIC

/** @brief Compare two frame_data structs by a given field.
 *  @param epan   The epan session context.
 *  @param fdata1 The first frame_data to compare.
 *  @param fdata2 The second frame_data to compare.
 *  @param field  The field ID to compare on.
 *  @return Negative if @p fdata1 < @p fdata2, 0 if equal, positive if
 *          @p fdata1 > @p fdata2. */
WS_DLL_PUBLIC int frame_data_compare(const struct epan_session *epan, const frame_data *fdata1, const frame_data *fdata2, int field);

/**
 * @brief Reset a frame_data struct to its initial state without freeing it.
 *
 * @param fdata The frame_data to reset.
 */
WS_DLL_PUBLIC void frame_data_reset(frame_data *fdata);

/**
 * @brief Free all resources owned by a frame_data struct.
 *
 * @param fdata The frame_data to destroy.
 */
WS_DLL_PUBLIC void frame_data_destroy(frame_data *fdata);

/**
 * @brief Free the aggregation data associated with a frame_data struct.
 *
 * @param fdata The frame_data whose aggregation data to free.
 */
WS_DLL_PUBLIC void frame_data_aggregation_free(frame_data *fdata);

/**
 * @brief Initialize a frame_data struct for a newly read frame.
 *
 * @param fdata     The frame_data to initialize.
 * @param num       The frame number.
 * @param rec       The wtap record for this frame.
 * @param offset    The file offset of this frame.
 * @param cum_bytes The cumulative byte count before this frame.
 */
WS_DLL_PUBLIC void frame_data_init(frame_data *fdata, uint32_t num,
                const wtap_rec *rec, int64_t offset,
                uint32_t cum_bytes);

/**
 * @brief Compute the time delta from the first frame to this frame.
 *
 * @param epan  The epan session context.
 * @param fdata The frame_data for the current frame.
 * @param delta Output pointer for the computed time delta.
 * @return true if the delta was computed successfully, false otherwise.
 */
extern bool frame_rel_first_frame_time(const struct epan_session *epan,
                                       const frame_data *fdata,
                                       nstime_t *delta);

/**
 * @brief Compute the time delta from the capture start to this frame.
 *
 * @param epan  The epan session context.
 * @param fdata The frame_data for the current frame.
 * @param delta Output pointer for the computed time delta.
 * @return true if the delta was computed successfully, false otherwise.
 */
extern bool frame_rel_time(const struct epan_session *epan,
                           const frame_data *fdata, nstime_t *delta);

/**
 * @brief Compute the time delta from the first displayed frame to this frame.
 *
 * @param epan  The epan session context.
 * @param fdata The frame_data for the current frame.
 * @param delta Output pointer for the computed time delta.
 * @return true if the delta was computed successfully, false otherwise.
 */
extern bool frame_rel_start_time(const struct epan_session *epan,
                                 const frame_data *fdata, nstime_t *delta);

/**
 * @brief Compute the time delta from the previous captured frame to this frame.
 *
 * @param epan  The epan session context.
 * @param fdata The frame_data for the current frame.
 * @param delta Output pointer for the computed time delta.
 * @return true if the delta was computed successfully, false otherwise.
 */
extern bool frame_delta_time_prev_captured(const struct epan_session *epan,
                                           const frame_data *fdata,
                                           nstime_t *delta);

/**
 * @brief Compute the time delta from the previous displayed frame to this frame.
 *
 * @param epan  The epan session context.
 * @param fdata The frame_data for the current frame.
 * @param delta Output pointer for the computed time delta.
 * @return true if the delta was computed successfully, false otherwise.
 */
extern bool frame_delta_time_prev_displayed(const struct epan_session *epan,
                                            const frame_data *fdata,
                                            nstime_t *delta);

/**
 * @brief Set frame_data fields before dissection.
 *
 * @param fdata        The frame_data to update.
 * @param elapsed_time The elapsed capture time; updated with this frame's
 *                     timestamp.
 * @param frame_ref    Pointer to the reference frame pointer; updated if
 *                     this frame becomes the new reference.
 * @param prev_dis     The most recently displayed frame, or NULL if none.
 */
WS_DLL_PUBLIC void frame_data_set_before_dissect(frame_data *fdata,
                nstime_t *elapsed_time,
                const frame_data **frame_ref,
                const frame_data *prev_dis);

/**
 * @brief Set frame_data fields after dissection.
 *
 * @param fdata     The frame_data to update.
 * @param cum_bytes The running cumulative byte count; updated to include
 *                  this frame.
 */
WS_DLL_PUBLIC void frame_data_set_after_dissect(frame_data *fdata,
                uint32_t *cum_bytes);

/** @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
