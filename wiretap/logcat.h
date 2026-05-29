/** @file
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __LOGCAT_H__
#define __LOGCAT_H__

#include "wtap.h"

/* The log format can be found on:
 * https://android.googlesource.com/platform/system/core/+/master/include/log/logger.h
 * Log format is assumed to be little-endian (Android platform).
 */
/* maximum size of a message payload in a log entry */
#define LOGGER_ENTRY_MAX_PAYLOAD 4076

/**
 * @brief Version 1 Android logger entry header, preceding the log message payload.
 */
struct logger_entry {
    uint16_t len;    /**< Length in bytes of the message payload that follows this header. */
    uint16_t __pad;  /**< Explicit padding to maintain 4-byte alignment; value is undefined. */
    int32_t  pid;    /**< Process ID of the process that generated this log entry. */
    int32_t  tid;    /**< Thread ID of the thread that generated this log entry. */
    int32_t  sec;    /**< Timestamp seconds component, seconds since the Unix epoch. */
    int32_t  nsec;   /**< Timestamp nanoseconds component. */
/*  char     msg[0]; */ /**< Variable-length message payload immediately following this header. */
};

/**
 * @brief Version 2/3 Android logger entry header, extending v1 with a self-describing size field and an ID union.
 */
struct logger_entry_v2 {
    uint16_t len;       /**< Length in bytes of the message payload that follows this header. */
    uint16_t hdr_size;  /**< Size of this header structure in bytes, used to distinguish v2/v3 from v1. */
    int32_t  pid;       /**< Process ID of the process that generated this log entry. */
    int32_t  tid;       /**< Thread ID of the thread that generated this log entry. */
    int32_t  sec;       /**< Timestamp seconds component, seconds since the Unix epoch. */
    int32_t  nsec;      /**< Timestamp nanoseconds component. */
    union {
        uint32_t euid;  /**< v2: Effective UID of the process that wrote this log entry. */
        uint32_t lid;   /**< v3: Log buffer ID identifying the log stream (e.g., main, radio, events). */
    } id;               /**< Identifier field whose interpretation depends on the header version. */
/*  char     msg[0]; */ /**< Variable-length message payload immediately following this header. */
};

/**
 * @brief Opens a logcat capture file for reading.
 *
 * This function initializes the wtap structure to read from a JSON log file.
 *
 * @param wth Pointer to the wtap structure that will be initialized.
 * @param err Pointer to an integer where error codes can be stored.
 * @param err_info Pointer to a string where error information can be stored.
 * @return A value indicating the success or failure of the operation.
 */
wtap_open_return_val  logcat_open(wtap *wth, int *err, char **err_info);

/**
 * @brief Calculate the length of a PDU (Protocol Data Unit) in a Logcat packet.
 *
 * This function calculates the total length of a PDU by iterating through the tags and their lengths.
 *
 * @param pd Pointer to the beginning of the PDU data.
 * @return The calculated length of the PDU.
 */
int      logcat_exported_pdu_length(const uint8_t *pd);
#endif

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
