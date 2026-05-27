/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for Busmaster log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BUSMASTER_PRIV_H__
#define BUSMASTER_PRIV_H__

#include <gmodule.h>
#include <wiretap/wtap.h>
#include <wiretap/socketcan.h>

/**
 * @brief Classifies a parsed line or record within a BusMaster log file.
 */
typedef enum {
    LOG_ENTRY_ERROR          = -1, /**< A parse error was encountered while reading the entry */
    LOG_ENTRY_NONE           =  0, /**< No entry has been parsed yet; initial state */
    LOG_ENTRY_EMPTY,               /**< A blank or whitespace-only line */
    LOG_ENTRY_HEADER,              /**< A log file section header (contains metadata such as protocol and time mode) */
    LOG_ENTRY_FOOTER,              /**< A log file section footer */
    LOG_ENTRY_FOOTER_AND_HEADER,   /**< A line that simultaneously closes one section and opens another */
    LOG_ENTRY_MSG,                 /**< A CAN/LIN bus message data record */
    LOG_ENTRY_EOF,                 /**< End of the log file has been reached */
} log_entry_type_t;

/**
 * @brief Identifies the bus protocol recorded in a BusMaster log file.
 */
typedef enum {
    PROTOCOL_UNKNOWN = 0, /**< Protocol has not been identified */
    PROTOCOL_CAN,         /**< Controller Area Network (CAN) protocol */
    PROTOCOL_LIN,         /**< Local Interconnect Network (LIN) protocol */
    PROTOCOL_J1939,       /**< SAE J1939 protocol (CAN-based, heavy vehicle networking) */
} protocol_type_t;

/**
 * @brief Indicates the numeric base used to encode payload data values in the log file.
 */
typedef enum {
    DATA_MODE_UNKNOWN = 0, /**< Data encoding format has not been identified */
    DATA_MODE_HEX,         /**< Payload bytes are encoded as hexadecimal values */
    DATA_MODE_DEC,         /**< Payload bytes are encoded as decimal values */
} data_mode_t;

/**
 * @brief Indicates how timestamps are represented in the log file.
 */
typedef enum {
    TIME_MODE_UNKNOWN  = 0, /**< Timestamp format has not been identified */
    TIME_MODE_ABSOLUTE,     /**< Timestamps are absolute wall-clock times */
    TIME_MODE_SYSTEM,       /**< Timestamps are sourced from the system clock at log time */
    TIME_MODE_RELATIVE,     /**< Timestamps are relative to the start of the log session */
} time_mode_t;

/**
 * @brief Represents a calendar date as parsed from a BusMaster log header.
 */
typedef struct {
    unsigned year;  /**< Full calendar year (e.g. 2024) */
    unsigned month; /**< Month of the year (1–12) */
    unsigned day;   /**< Day of the month (1–31) */
} msg_date_t;

/**
 * @brief Represents a time-of-day value as parsed from a BusMaster log entry.
 */
typedef struct {
    unsigned hours;   /**< Hours component (0–23) */
    unsigned minutes; /**< Minutes component (0–59) */
    unsigned seconds; /**< Seconds component (0–59) */
    unsigned micros;  /**< Microseconds component (0–999999) */
} msg_time_t;

/**
 * @brief Combines a calendar date and time-of-day into a single timestamp.
 */
typedef struct {
    msg_date_t d; /**< Calendar date component */
    msg_time_t t; /**< Time-of-day component */
} msg_date_time_t;

/**
 * @brief Represents a single decoded CAN or LIN bus message record from the log.
 */
typedef struct {
    msg_time_t          timestamp; /**< Timestamp of the message as recorded in the log */
    wtap_can_msg_type_t type;      /**< CAN message type (data frame, remote frame, error frame, etc.) */
    uint32_t            id;        /**< CAN message identifier (11-bit or 29-bit) */
    wtap_can_msg_data_t data;      /**< Message payload and associated metadata */
} msg_t;

/**
 * @brief General-purpose four-field integer token produced by the BusMaster log lexer.
 */
typedef struct {
    int64_t v0; /**< First token field */
    int64_t v1; /**< Second token field */
    int64_t v2; /**< Third token field */
    int64_t v3; /**< Fourth token field */
} token_t;

/**
 * @brief Per-section metadata extracted from a BusMaster log file header.
 */
typedef struct {
    int64_t         file_start_offset; /**< Byte offset in the file where this section's data begins */
    int64_t         file_end_offset;   /**< Byte offset in the file where this section's data ends */
    protocol_type_t protocol;          /**< Bus protocol recorded in this section */
    data_mode_t     data_mode;         /**< Numeric encoding of payload data in this section */
    time_mode_t     time_mode;         /**< Timestamp representation used in this section */
    msg_date_time_t start;             /**< Wall-clock date and time at which this log section began */
} busmaster_priv_t;

/**
 * @brief Complete parser state for an open BusMaster log file.
 */
typedef struct {
    FILE_T  fh;              /**< Wiretap file handle for the open BusMaster log file */
    int64_t file_bytes_read; /**< Total number of bytes consumed from the file so far */

    char *parse_error; /**< Human-readable description of the most recent parse error, or NULL */
    int   err;         /**< Wiretap error code set when a read or parse failure occurs */
    char *err_info;    /**< Additional detail string associated with @p err, or NULL */

    token_t token; /**< Most recently lexed token from the input stream */

    log_entry_type_t entry_type; /**< Type of the most recently parsed log entry */
    busmaster_priv_t header;     /**< Metadata parsed from the current log section header */
    msg_t            msg;        /**< Most recently parsed bus message record */
} busmaster_state_t;

/**
 * @brief Runs the Busmaster parser to process log entries.
 *
 * @param state Pointer to the busmaster state structure.
 * @param err Pointer to an integer where any error code will be stored.
 * @param err_info Pointer to a char pointer where any error information will be stored.
 * @return true if the parser ran successfully, false if an error occurred.
 */
bool
run_busmaster_parser(busmaster_state_t *state,
                     int               *err, char **err_info);

#endif  /* BUSMASTER_PRIV_H__ */
