/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WTAP_INT_H__
#define __WTAP_INT_H__

#include "wtap.h"
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

#include <wsutil/array.h>
#include <wsutil/file_util.h>

#include "wtap_opttypes.h"

/**
 * @brief Initialize file type subtypes for wiretap.
 */
void wtap_init_file_type_subtypes(void);

/**
 * @brief Retrieve file statistics for a wiretap handle.
 *
 * @param wth Wiretap handle.
 * @param statb Pointer to stat structure to populate.
 * @param err Optional error code output.
 * @return 0 on success, -1 on failure.
 */
WS_DLL_PUBLIC
int wtap_fstat(wtap *wth, ws_statb64 *statb, int *err);

/**
 * @brief Function pointer type for reading a record.
 *
 * @param wtap Wiretap handle.
 * @param rec Output record.
 * @param err Optional error code output.
 * @param err_info Optional error info string.
 * @param offset Optional offset output.
 * @return true on success, false on failure.
 */
typedef bool (*subtype_read_func)(struct wtap* wtap, wtap_rec* rec,
                                  int* err, char** err_info, int64_t* offset);

/**
 * @brief Function pointer type for seeking and reading a record.
 *
 * @param wtap Wiretap handle.
 * @param seek_off Offset to seek to.
 * @param rec Output record.
 * @param err Optional error code output.
 * @param err_info Optional error info string.
 * @return true on success, false on failure.
 */
typedef bool (*subtype_seek_read_func)(struct wtap* wtap, int64_t seek_off, wtap_rec* rec,
                                       int* err, char** err_info);

/**
 * Struct holding data of the currently read file.
 */
struct wtap {
    FILE_T                      fh;                     /**< Primary FILE_T for sequential reads */
    FILE_T                      random_fh;              /**< Secondary FILE_T for random access */
    bool                        ispipe;                 /**< true if the file is a pipe */
    int                         file_type_subtype;      /**< File type subtype. */
    unsigned                    snapshot_length;        /**< Maximum captured packet length. */
    GArray                      *shb_hdrs;              /**< Section Header Blocks. */
    GArray                      *shb_iface_to_global;   /**< An array mapping the per-section interface numbers to global IDs */
    GArray                      *interface_data;        /**< An array holding the interface data from pcapng IDB:s or equivalent(?)*/
    unsigned                    next_interface_data;    /**< Next interface data that wtap_get_next_interface_description() will show */
    GArray                      *nrbs;                  /**< Holds the Name Res Blocks, or NULL */
    GArray                      *dsbs;                  /**< An array of DSBs (of type wtap_block_t), or NULL if not supported. */
    GArray                      *meta_events;           /**< An array of meta events (of type wtap_block_t), or NULL if not supported. */
    GArray                      *dpibs;                 /**< An array of DPIBs (of type wtap_block_t), or NULL if not supported. */
    unsigned                    next_dpib_id;           /**< Next DPIB id  */
    char                        *pathname;              /**< File pathname; might just be "-" */

    void                        *priv;                  /**< Stores per-file state and is free'd automatically by wtap_close() */
    void                        *wslua_data;            /**< Stores wslua state info and is not free'd */

    subtype_read_func           subtype_read;           /**< Function called for sequential reads */
    subtype_seek_read_func      subtype_seek_read;      /**< Function called for random access reads */
    void                        (*subtype_sequential_close)(struct wtap*); /**< Cleanup for sequential read state. */
    void                        (*subtype_close)(struct wtap*);            /**< Cleanup for general file state. */
    int                         file_encap;    /**< Per-file encapsulation type, for those
                                                * file formats that have
                                                * per-file encapsulation
                                                * types rather than per-packet
                                                * encapsulation types
                                                */
    int                         file_tsprec;    /**< Per-file timestamp precision
                                                * of the fractional part of
                                                * the time stamp, for those
                                                * file formats that have
                                                * per-file timestamp
                                                * precision rather than
                                                * per-packet timestamp
                                                * precision
                                                * e.g. WTAP_TSPREC_USEC
                                                */
    nstime_t                    file_start_ts; /**< Per-file start time, for
                                                * those file formats that have
                                                * a start time distinct from
                                                * that of the first record with
                                                * a timestamp. (Can be unset.)
                                                */
    nstime_t                    file_end_ts;   /**< Per-file end time, for
                                                * those file formats that have
                                                * a end time distinct from
                                                * that of the last record with
                                                * a timestamp. (Can be unset.)
                                                */
    wtap_new_ipv4_callback_t    add_new_ipv4;    /**< Callback for new IPv4 addresses. */
    wtap_new_ipv6_callback_t    add_new_ipv6;    /**< Callback for new IPv6 addresses. */
    wtap_new_secrets_callback_t add_new_secrets; /**< Callback for new secrets. */
    GPtrArray                   *fast_seek;      /**< Fast seek index. */
};

struct wtap_dumper;

/**
 * @brief Abstract file handle for writing.
 *
 * May represent a FILE* or a handle for writing a compressed file.
 */
typedef void *WFILE_T;

/**
 * @brief Function pointer type for adding an Interface Description Block (IDB).
 *
 * @param dumper Wiretap dumper handle.
 * @param idb Interface Description Block to add.
 * @param err Optional error code output.
 * @param err_info Optional error info string.
 * @return true on success, false on failure.
 */
typedef bool (*subtype_add_idb_func)(struct wtap_dumper* dumper, wtap_block_t idb,
                                         int* err, char** err_info);

/**
 * @brief Function pointer type for writing a record.
 *
 * @param dumper Wiretap dumper handle.
 * @param rec Record to write.
 * @param err Optional error code output.
 * @param err_info Optional error info string.
 * @return true on success, false on failure.
 */
typedef bool (*subtype_write_func)(struct wtap_dumper* dumper, const wtap_rec* rec,
                                   int* err, char** err_info);

/**
 * @brief Function pointer type for finalizing a dump file.
 *
 * @param dumper Wiretap dumper handle.
 * @param err Optional error code output.
 * @param err_info Optional error info string.
 * @return true on success, false on failure.
 */
typedef bool (*subtype_finish_func)(struct wtap_dumper* dumper, int* err, char** err_info);

/**
 * @brief Wiretap dumper handle and associated state.
 *
 * Used for writing capture data to output files, including metadata and block structures.
 */
struct wtap_dumper {
    WFILE_T                 fh;              /**< Output file handle. */
    int                     file_type_subtype; /**< File type subtype. */
    int                     snaplen;         /**< Maximum captured packet length. */
    int                     file_encap;      /** per-file, for those
                                              * file formats that have
                                              * per-file encapsulation
                                              * types rather than per-packet
                                              * encapsulation types
                                              */
    ws_compression_type     compression_type; /**< Compression type used for output. */
    bool                    needs_reload;    /**< true if the file requires re-loading after saving with wtap */
    int64_t                 bytes_dumped;    /**< Total bytes written. */

    void                    *priv;           /**< this one holds per-file state and is free'd automatically by wtap_dump_close() */
    void                    *wslua_data;     /**< this one holds wslua state info and is not free'd */

    subtype_add_idb_func    subtype_add_idb; /**< add an IDB, writing it as necessary */
    subtype_write_func      subtype_write;   /**< write out a record */
    subtype_finish_func     subtype_finish;  /**< write out information to finish writing file */

    addrinfo_lists_t        *addrinfo_lists; /**< Struct containing lists of resolved addresses */
    GArray                  *shb_hdrs;       /**< Section Header Blocks. */
    const GArray            *shb_iface_to_global; /**< An array mapping the per-section interface numbers to global IDs */
    GArray                  *interface_data; /**< An array holding the interface data from pcapng IDB:s or equivalent(?) NULL if not present.*/
    GArray                  *dsbs_initial;   /**< An array of initial DSBs (of type wtap_block_t) */

    /*
     * Additional blocks that might grow as data is being collected.
     * Subtypes should write these blocks before writing new packet blocks.
     */
    const GArray            *nrbs_growing;          /**< A reference to an array of NRBs (of type wtap_block_t) */
    const GArray            *dsbs_growing;          /**< A reference to an array of DSBs (of type wtap_block_t) */
    const GArray            *mevs_growing;          /**< A reference to an array of Sysdig meta events (of type wtap_block_t) */
    const GArray            *dpibs_growing;          /**< A reference to an array of DPIBs (of type wtap_block_t) */
    unsigned                nrbs_growing_written;   /**< Number of already processed NRBs in nrbs_growing. */
    unsigned                dsbs_growing_written;   /**< Number of already processed DSBs in dsbs_growing. */
    unsigned                mevs_growing_written;   /**< Number of already processed meta events in mevs_growing. */
    unsigned                dpibs_growing_written;   /**< Number of already processed DPIBs in dsbs_growing. */
};

/**
 * @brief Write raw data to the dump file.
 *
 * @param wdh Wiretap dumper handle.
 * @param buf Pointer to data buffer.
 * @param bufsize Size of buffer in bytes.
 * @param err Optional error code output.
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC bool wtap_dump_file_write(wtap_dumper *wdh, const void *buf,
                                        size_t bufsize, int *err);

/**
 * @brief Seek to a position in the dump file.
 *
 * @param wdh Wiretap dumper handle.
 * @param offset Byte offset to seek to.
 * @param whence Seek origin (e.g., SEEK_SET).
 * @param err Optional error code output.
 * @return New file position on success, -1 on failure.
 */
WS_DLL_PUBLIC int64_t wtap_dump_file_seek(wtap_dumper *wdh, int64_t offset,
                                          int whence, int *err);

/**
 * @brief Get current position in the dump file.
 *
 * @param wdh Wiretap dumper handle.
 * @param err Optional error code output.
 * @return Current file position on success, -1 on failure.
 */
WS_DLL_PUBLIC int64_t wtap_dump_file_tell(wtap_dumper *wdh, int *err);

/**
 * @brief Number of supported wiretap file types.
 *
 * Externally visible count of registered file types.
 */
extern int wtap_num_file_types;

/* Macros to byte-swap possibly-unaligned 64-bit, 32-bit and 16-bit quantities;
 * they take a pointer to the quantity, and byte-swap it in place.
 */
 /**
 * @brief Byte-swap an unaligned 64-bit quantity in place.
 * @param p Pointer to 8-byte array to swap.
 */
#define PBSWAP64(p) \
    {            \
        uint8_t tmp;        \
        tmp = (p)[7];      \
        (p)[7] = (p)[0];   \
        (p)[0] = tmp;      \
        tmp = (p)[6];      \
        (p)[6] = (p)[1];   \
        (p)[1] = tmp;      \
        tmp = (p)[5];      \
        (p)[5] = (p)[2];   \
        (p)[2] = tmp;      \
        tmp = (p)[4];      \
        (p)[4] = (p)[3];   \
        (p)[3] = tmp;      \
    }

/**
 * @brief Byte-swap an unaligned 32-bit quantity in place.
 * @param p Pointer to 4-byte array to swap.
 */
#define PBSWAP32(p) \
    {            \
        uint8_t tmp;         \
        tmp = (p)[3];       \
        (p)[3] = (p)[0];    \
        (p)[0] = tmp;       \
        tmp = (p)[2];       \
        (p)[2] = (p)[1];    \
        (p)[1] = tmp;       \
    }

/**
 * @brief Byte-swap an unaligned 16-bit quantity in place.
 * @param p Pointer to 2-byte array to swap.
 */
#define PBSWAP16(p) \
    {            \
        uint8_t tmp;        \
        tmp = (p)[1];      \
        (p)[1] = (p)[0];   \
        (p)[0] = tmp;      \
    }

/**
 * @brief Read a specified number of bytes from a file or discard them.
 *
 * - If buf is NULL, bytes are discarded.
 * - On EOF: returns false, *err = 0.
 * - On short read: returns false, *err = WTAP_ERR_SHORT_READ.
 * - On error: returns false, *err and *err_info set appropriately.
 *
 * @param fh File handle to read from.
 * @param buf Destination buffer, or NULL to discard bytes.
 * @param count Number of bytes to read.
 * @param err Output error code (0 for EOF, WTAP_ERR_SHORT_READ for short read, or other on failure).
 * @param err_info Optional error info string on failure.
 * @return true on success; false on EOF, short read, or error.
 */
WS_DLL_PUBLIC
bool
wtap_read_bytes_or_eof(FILE_T fh, void *buf, unsigned int count, int *err,
    char **err_info);

/**
 * @brief Read a specified number of bytes from a file or discard them.
 *
 * - If buf is NULL, bytes are discarded.
 * - On short read or EOF: returns false, *err = WTAP_ERR_SHORT_READ.
 * - On read error: returns false, *err and *err_info set appropriately.
 *
 * @param fh File handle to read from.
 * @param buf Destination buffer, or NULL to discard bytes.
 * @param count Number of bytes to read.
 * @param err Output error code (WTAP_ERR_SHORT_READ on short read or EOF).
 * @param err_info Optional error info string on failure.
 * @return true on success; false on short read or error.
 */
WS_DLL_PUBLIC
bool
wtap_read_bytes(FILE_T fh, void *buf, unsigned int count, int *err,
    char **err_info);

/**
 * @brief Read a specified number of bytes into a Buffer, growing it as needed.
 *
 * This returns an error on a short read, even if the short read hit
 * the EOF immediately.  (The assumption is that each packet has a
 * header followed by raw packet data, and that we've already read the
 * header, so if we get an EOF trying to read the packet data, the file
 * has been cut short, even if the read didn't read any data at all.)
 *
 * @param fh File handle to read from.
 * @param buf Buffer to receive data.
 * @param length Number of bytes to read.
 * @param err Output error code (WTAP_ERR_SHORT_READ on short read or EOF).
 * @param err_info Optional error info string on failure.
 * @return true on success; false on short read or error.
 */
WS_DLL_PUBLIC
bool
wtap_read_bytes_buffer(FILE_T fh, Buffer *buf, unsigned length, int *err,
                       char **err_info);

/**
 * @brief Read entire file contents as a single packet (sequential mode).
 *
 * Used for formats that treat the whole file as one record.
 *
 * @param wth Wiretap handle.
 * @param rec Output record.
 * @param err Output error code.
 * @param err_info Optional error info string.
 * @param data_offset Output offset of packet data.
 * @return true on success; false on error.
 */
bool
wtap_full_file_read(wtap *wth, wtap_rec *rec, int *err, char **err_info,
                    int64_t *data_offset);

/**
 * @brief Read entire file contents as a single packet (seek mode).
 *
 * Used for formats that support random access to a single-record file.
 *
 * @param wth Wiretap handle.
 * @param seek_off Offset to seek to.
 * @param rec Output record.
 * @param err Output error code.
 * @param err_info Optional error info string.
 * @return true on success; false on error.
 */
bool
wtap_full_file_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
                         int *err, char **err_info);

/**
 * @brief Add an Interface Description Block (IDB) to a wiretap handle.
 *
 * Used during file parsing to register interface metadata.
 *
 * @param wth Wiretap handle.
 * @param idb IDB block to add.
 */
void
wtap_add_idb(wtap *wth, wtap_block_t idb);

/**
 * @brief Add a DPIB to the dpibs list for a file.
 *
 * Used during parsing to register a Decryption Parameters Info Block (DPIB).
 *
 * @param wth Wiretap handle.
 * @param dpib DPIB block to add.
 */
void
wtap_add_dpib(wtap *wth, wtap_block_t dpib);

/**
 * @brief Invoke the registered callback with a Name Resolution Block (NRB).
 *
 * Used to process NRBs during capture file parsing.
 *
 * @param wth Wiretap handle.
 * @param nrb NRB block to process.
 */
void
wtapng_process_nrb(wtap *wth, wtap_block_t nrb);

/**
 * @brief Invoke the registered callback with a Decryption Secrets Block (DSB).
 *
 * Used to process DSBs during capture file parsing.
 *
 * @param wth Wiretap handle.
 * @param dsb DSB block to process.
 */
void
wtapng_process_dsb(wtap *wth, wtap_block_t dsb);

/**
 * @brief Register a compatibility alias for a file subtype name.
 *
 * Used to map legacy subtype names to updated identifiers.
 *
 * @param old_name Deprecated subtype name.
 * @param new_name Canonical subtype name.
 */
void
wtap_register_compatibility_file_subtype_name(const char *old_name,
                                              const char *new_name);

/**
 * @brief Register a backwards compatibility Lua name for a file type.
 *
 * Associates a legacy Lua-accessible name with a file type identifier.
 *
 * @param name Legacy Lua name.
 * @param ft File type identifier.
 */
void
wtap_register_backwards_compatibility_lua_name(const char *name, int ft);

/**
 * @struct backwards_compatibiliity_lua_name
 * @brief Mapping between a Lua name and a file type.
 *
 * Used to support backwards compatibility for Lua scripts referencing legacy file type names.
 */
struct backwards_compatibiliity_lua_name {
    const char *name; /**< Legacy Lua name. */
    int ft;           /**< File type identifier. */
};

/**
 * @brief Retrieve the table of backwards compatibility Lua names.
 *
 * Returns a GArray of backwards_compatibiliity_lua_name entries.
 *
 * @return Pointer to GArray of compatibility mappings.
 */
WS_DLL_PUBLIC
const GArray *get_backwards_compatibility_lua_table(void);

/**
 * @brief Gets new section header block for new file, based on existing info.
 * @details Creates a new wtap_block_t section header block and only
 *          copies appropriate members of the SHB for a new file. In
 *          particular, the comment string is copied, and any custom options
 *          which should be copied are copied. The os, hardware, and
 *          application strings are *not* copied.
 *
 * @note Use wtap_free_shb() to free the returned section header.
 *
 * @param wth The wiretap session.
 * @return The new section header, which must be wtap_free_shb'd.
 */
GArray* wtap_file_get_shb_for_new_file(wtap *wth);

/**
 * @brief Generate an IDB, given a wiretap handle for the file,
 *      using the file's encapsulation type, snapshot length,
 *      and time stamp resolution, and add it to the interface
 *      data for a file.
 * @note This requires that the encapsulation type and time stamp
 *      resolution not be per-packet; it will terminate the process
 *      if either of them are.
 *
 * @param wth The wiretap handle for the file.
 */
WS_DLL_PUBLIC
void wtap_add_generated_idb(wtap *wth);

/**
 * @brief Generate an IDB, given a set of dump parameters, using the
 *      parameters' encapsulation type, snapshot length, and time stamp
 *      resolution. For use when a dump file has a given encapsulation type,
 *      and the source is not passing IDBs.
 * @note This requires that the encapsulation type and time stamp
 *      resolution not be per-packet; it will terminate the process
 *      if either of them are.
 *
 * @param params The wtap dump parameters.
 * @return A newly allocated IDB block.
 */
wtap_block_t wtap_dump_params_generate_idb(const wtap_dump_params *params);

/**
 * @brief Generate an IDB, given a packet record, using the records's
 *      encapsulation type and time stamp resolution, and the default
 *      snap length for the encapsulation type. For use when a file has
 *      per-packet encapsulation, and the source is not passing along IDBs.
 * @note This requires that the record type be REC_TYPE_PACKET, and the
 *      encapsulation type and time stamp resolution not be per-packet;
 *      it will terminate the process if any of them are.
 *
 * @param rec The packet record.
 * @return A newly allocated IDB block.
 */
wtap_block_t wtap_rec_generate_idb(const wtap_rec *rec);

/**
 * @brief Gets new name resolution info for new file, based on existing info.
 * @details Creates a new wtap_block_t of name resolution info and only
 *          copies appropriate members for a new file.
 *
 * @note Use wtap_free_nrb() to free the returned pointer.
 *
 * @param wth The wiretap session.
 * @return The new name resolution info, which must be freed.
 */
GArray* wtap_file_get_nrb_for_new_file(wtap *wth);

#endif /* __WTAP_INT_H__ */

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
