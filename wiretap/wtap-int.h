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

void wtap_init_file_type_subtypes(void);

WS_DLL_PUBLIC
int wtap_fstat(wtap *wth, ws_statb64 *statb, int *err);

typedef bool (*subtype_read_func)(struct wtap*, wtap_rec *,
                                      Buffer *, int *, char **, int64_t *);
typedef bool (*subtype_seek_read_func)(struct wtap*, int64_t, wtap_rec *,
                                           Buffer *, int *, char **);

/**
 * Struct holding data of the currently read file.
 */
struct wtap {
    FILE_T                      fh;
    FILE_T                      random_fh;              /**< Secondary FILE_T for random access */
    bool                        ispipe;                 /**< true if the file is a pipe */
    int                         file_type_subtype;
    unsigned                    snapshot_length;
    GArray                      *shb_hdrs;
    GArray                      *shb_iface_to_global;   /**< An array mapping the per-section interface numbers to global IDs */
    GArray                      *interface_data;        /**< An array holding the interface data from pcapng IDB:s or equivalent(?)*/
    unsigned                    next_interface_data;    /**< Next interface data that wtap_get_next_interface_description() will show */
    GArray                      *nrbs;                  /**< holds the Name Res Blocks, or NULL */
    GArray                      *dsbs;                  /**< An array of DSBs (of type wtap_block_t), or NULL if not supported. */
    GArray                      *meta_events;           /**< An array of meta eventss (of type wtap_block_t), or NULL if not supported. */

    char                        *pathname;              /**< File pathname; might just be "-" */

    void                        *priv;          /* this one holds per-file state and is free'd automatically by wtap_close() */
    void                        *wslua_data;    /* this one holds wslua state info and is not free'd */

    subtype_read_func           subtype_read;
    subtype_seek_read_func      subtype_seek_read;
    void                        (*subtype_sequential_close)(struct wtap*);
    void                        (*subtype_close)(struct wtap*);
    int                         file_encap;    /* per-file, for those
                                                * file formats that have
                                                * per-file encapsulation
                                                * types rather than per-packet
                                                * encapsulation types
                                                */
    int                         file_tsprec;   /* per-file timestamp precision
                                                * of the fractional part of
                                                * the time stamp, for those
                                                * file formats that have
                                                * per-file timestamp
                                                * precision rather than
                                                * per-packet timestamp
                                                * precision
                                                * e.g. WTAP_TSPREC_USEC
                                                */
    wtap_new_ipv4_callback_t    add_new_ipv4;
    wtap_new_ipv6_callback_t    add_new_ipv6;
    wtap_new_secrets_callback_t add_new_secrets;
    GPtrArray                   *fast_seek;
};

struct wtap_dumper;

/*
 * This could either be a FILE * or a gzFile.
 */
typedef void *WFILE_T;

typedef bool (*subtype_add_idb_func)(struct wtap_dumper*, wtap_block_t,
                                         int *, char **);

typedef bool (*subtype_write_func)(struct wtap_dumper*,
                                       const wtap_rec *rec,
                                       const uint8_t*, int*, char**);
typedef bool (*subtype_finish_func)(struct wtap_dumper*, int*, char**);

struct wtap_dumper {
    WFILE_T                 fh;
    int                     file_type_subtype;
    int                     snaplen;
    int                     file_encap;      /* per-file, for those
                                              * file formats that have
                                              * per-file encapsulation
                                              * types rather than per-packet
                                              * encapsulation types
                                              */
    wtap_compression_type   compression_type;
    bool                    needs_reload;    /* true if the file requires re-loading after saving with wtap */
    int64_t                 bytes_dumped;

    void                    *priv;           /* this one holds per-file state and is free'd automatically by wtap_dump_close() */
    void                    *wslua_data;     /* this one holds wslua state info and is not free'd */

    subtype_add_idb_func    subtype_add_idb; /* add an IDB, writing it as necessary */
    subtype_write_func      subtype_write;   /* write out a record */
    subtype_finish_func     subtype_finish;  /* write out information to finish writing file */

    addrinfo_lists_t        *addrinfo_lists; /**< Struct containing lists of resolved addresses */
    GArray                  *shb_hdrs;
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
    unsigned                nrbs_growing_written;   /**< Number of already processed NRBs in nrbs_growing. */
    unsigned                dsbs_growing_written;   /**< Number of already processed DSBs in dsbs_growing. */
    unsigned                mevs_growing_written;   /**< Number of already processed meta events in mevs_growing. */
};

WS_DLL_PUBLIC bool wtap_dump_file_write(wtap_dumper *wdh, const void *buf,
    size_t bufsize, int *err);
WS_DLL_PUBLIC int64_t wtap_dump_file_seek(wtap_dumper *wdh, int64_t offset, int whence, int *err);
WS_DLL_PUBLIC int64_t wtap_dump_file_tell(wtap_dumper *wdh, int *err);

extern int wtap_num_file_types;

#include <wsutil/pint.h>

/* Macros to byte-swap possibly-unaligned 64-bit, 32-bit and 16-bit quantities;
 * they take a pointer to the quantity, and byte-swap it in place.
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
#define PBSWAP16(p) \
    {            \
        uint8_t tmp;        \
        tmp = (p)[1];      \
        (p)[1] = (p)[0];   \
        (p)[0] = tmp;      \
    }


/* Pointer routines to put items out in a particular byte order.
 * These will work regardless of the byte alignment of the pointer.
 */

#ifndef phtons
#define phtons(p, v) \
    {                 \
        (p)[0] = (uint8_t)((v) >> 8);    \
        (p)[1] = (uint8_t)((v) >> 0);    \
    }
#endif

#ifndef phton24
#define phton24(p, v) \
    {                 \
        (p)[0] = (uint8_t)((v) >> 16);    \
        (p)[1] = (uint8_t)((v) >> 8);     \
        (p)[2] = (uint8_t)((v) >> 0);     \
    }
#endif

#ifndef phtonl
#define phtonl(p, v) \
    {                 \
        (p)[0] = (uint8_t)((v) >> 24);    \
        (p)[1] = (uint8_t)((v) >> 16);    \
        (p)[2] = (uint8_t)((v) >> 8);     \
        (p)[3] = (uint8_t)((v) >> 0);     \
    }
#endif

#ifndef phtonll
#define phtonll(p, v) \
    {                 \
        (p)[0] = (uint8_t)((v) >> 56);    \
        (p)[1] = (uint8_t)((v) >> 48);    \
        (p)[2] = (uint8_t)((v) >> 40);    \
        (p)[3] = (uint8_t)((v) >> 32);    \
        (p)[4] = (uint8_t)((v) >> 24);    \
        (p)[5] = (uint8_t)((v) >> 16);    \
        (p)[6] = (uint8_t)((v) >> 8);     \
        (p)[7] = (uint8_t)((v) >> 0);     \
    }
#endif

#ifndef phtole8
#define phtole8(p, v) \
    {                 \
        (p)[0] = (uint8_t)((v) >> 0);    \
    }
#endif

#ifndef phtoles
#define phtoles(p, v) \
    {                 \
        (p)[0] = (uint8_t)((v) >> 0);    \
        (p)[1] = (uint8_t)((v) >> 8);    \
    }
#endif

#ifndef phtole24
#define phtole24(p, v) \
    {                 \
        (p)[0] = (uint8_t)((v) >> 0);     \
        (p)[1] = (uint8_t)((v) >> 8);     \
        (p)[2] = (uint8_t)((v) >> 16);    \
    }
#endif

#ifndef phtolel
#define phtolel(p, v) \
    {                 \
        (p)[0] = (uint8_t)((v) >> 0);     \
        (p)[1] = (uint8_t)((v) >> 8);     \
        (p)[2] = (uint8_t)((v) >> 16);    \
        (p)[3] = (uint8_t)((v) >> 24);    \
    }
#endif

#ifndef phtolell
#define phtolell(p, v) \
    {                 \
        (p)[0] = (uint8_t)((v) >> 0);     \
        (p)[1] = (uint8_t)((v) >> 8);     \
        (p)[2] = (uint8_t)((v) >> 16);    \
        (p)[3] = (uint8_t)((v) >> 24);    \
        (p)[4] = (uint8_t)((v) >> 32);    \
        (p)[5] = (uint8_t)((v) >> 40);    \
        (p)[6] = (uint8_t)((v) >> 48);    \
        (p)[7] = (uint8_t)((v) >> 56);    \
    }
#endif

/*
 * Read a given number of bytes from a file into a buffer or, if
 * buf is NULL, just discard them.
 *
 * If we succeed, return true.
 *
 * If we get an EOF, return false with *err set to 0, reporting this
 * as an EOF.
 *
 * If we get fewer bytes than the specified number, return false with
 * *err set to WTAP_ERR_SHORT_READ, reporting this as a short read
 * error.
 *
 * If we get a read error, return false with *err and *err_info set
 * appropriately.
 */
WS_DLL_PUBLIC
bool
wtap_read_bytes_or_eof(FILE_T fh, void *buf, unsigned int count, int *err,
    char **err_info);

/*
 * Read a given number of bytes from a file into a buffer or, if
 * buf is NULL, just discard them.
 *
 * If we succeed, return true.
 *
 * If we get fewer bytes than the specified number, including getting
 * an EOF, return false with *err set to WTAP_ERR_SHORT_READ, reporting
 * this as a short read error.
 *
 * If we get a read error, return false with *err and *err_info set
 * appropriately.
 */
WS_DLL_PUBLIC
bool
wtap_read_bytes(FILE_T fh, void *buf, unsigned int count, int *err,
    char **err_info);

/*
 * Read packet data into a Buffer, growing the buffer as necessary.
 *
 * This returns an error on a short read, even if the short read hit
 * the EOF immediately.  (The assumption is that each packet has a
 * header followed by raw packet data, and that we've already read the
 * header, so if we get an EOF trying to read the packet data, the file
 * has been cut short, even if the read didn't read any data at all.)
 */
WS_DLL_PUBLIC
bool
wtap_read_packet_bytes(FILE_T fh, Buffer *buf, unsigned length, int *err,
    char **err_info);

/*
 * Implementation of wth->subtype_read that reads the full file contents
 * as a single packet.
 */
bool
wtap_full_file_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset);

/*
 * Implementation of wth->subtype_seek_read that reads the full file contents
 * as a single packet.
 */
bool
wtap_full_file_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec, Buffer *buf, int *err, char **err_info);

/**
 * Add an IDB to the interface data for a file.
 */
void
wtap_add_idb(wtap *wth, wtap_block_t idb);

/**
 * Invokes the callback with the given name resolution block.
 */
void
wtapng_process_nrb(wtap *wth, wtap_block_t nrb);

/**
 * Invokes the callback with the given decryption secrets block.
 */
void
wtapng_process_dsb(wtap *wth, wtap_block_t dsb);

void
wtap_register_compatibility_file_subtype_name(const char *old_name,
    const char *new_name);

void
wtap_register_backwards_compatibility_lua_name(const char *name, int ft);

struct backwards_compatibiliity_lua_name {
	const char *name;
	int ft;
};

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
