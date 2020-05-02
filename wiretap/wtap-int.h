/* wtap-int.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WTAP_INT_H__
#define __WTAP_INT_H__

#include <glib.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

#include <wsutil/file_util.h>

#include "wtap.h"
#include "wtap_opttypes.h"

WS_DLL_PUBLIC
int wtap_fstat(wtap *wth, ws_statb64 *statb, int *err);

typedef gboolean (*subtype_read_func)(struct wtap*, wtap_rec *,
                                      Buffer *, int *, char **, gint64 *);
typedef gboolean (*subtype_seek_read_func)(struct wtap*, gint64, wtap_rec *,
                                           Buffer *, int *, char **);

/**
 * Struct holding data of the currently read file.
 */
struct wtap {
    FILE_T                      fh;
    FILE_T                      random_fh;              /**< Secondary FILE_T for random access */
    gboolean                    ispipe;                 /**< TRUE if the file is a pipe */
    int                         file_type_subtype;
    guint                       snapshot_length;
    GArray                      *shb_hdrs;
    GArray                      *interface_data;        /**< An array holding the interface data from pcapng IDB:s or equivalent(?)*/
    GArray                      *nrb_hdrs;              /**< holds the Name Res Block's comment/custom_opts, or NULL */
    GArray                      *dsbs;                  /**< An array of DSBs (of type wtap_block_t), or NULL if not supported. */

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

typedef gboolean (*subtype_write_func)(struct wtap_dumper*,
                                       const wtap_rec *rec,
                                       const guint8*, int*, gchar**);
typedef gboolean (*subtype_finish_func)(struct wtap_dumper*, int*);

struct wtap_dumper {
    WFILE_T                 fh;
    int                     file_type_subtype;
    int                     snaplen;
    int                     encap;
    wtap_compression_type   compression_type;
    gboolean                needs_reload;   /* TRUE if the file requires re-loading after saving with wtap */
    gint64                  bytes_dumped;

    void                    *priv;          /* this one holds per-file state and is free'd automatically by wtap_dump_close() */
    void                    *wslua_data;    /* this one holds wslua state info and is not free'd */

    subtype_write_func      subtype_write;  /* write out a record */
    subtype_finish_func     subtype_finish; /* write out information to finish writing file */

    addrinfo_lists_t        *addrinfo_lists; /**< Struct containing lists of resolved addresses */
    GArray                  *shb_hdrs;
    GArray                  *nrb_hdrs;        /**< name resolution comment/custom_opt, or NULL */
    GArray                  *interface_data; /**< An array holding the interface data from pcapng IDB:s or equivalent(?) NULL if not present.*/
    GArray                  *dsbs_initial;   /**< An array of initial DSBs (of type wtap_block_t) */

    /*
     * Additional blocks that might grow as data is being collected.
     * Subtypes should write these blocks before writing new packet blocks.
     */
    const GArray            *dsbs_growing;          /**< A reference to an array of DSBs (of type wtap_block_t) */
    guint                   dsbs_growing_written;   /**< Number of already processed DSBs in dsbs_growing. */
};

WS_DLL_PUBLIC gboolean wtap_dump_file_write(wtap_dumper *wdh, const void *buf,
    size_t bufsize, int *err);
WS_DLL_PUBLIC gint64 wtap_dump_file_seek(wtap_dumper *wdh, gint64 offset, int whence, int *err);
WS_DLL_PUBLIC gint64 wtap_dump_file_tell(wtap_dumper *wdh, int *err);


extern gint wtap_num_file_types;

#include <wsutil/pint.h>

/* Macros to byte-swap possibly-unaligned 64-bit, 32-bit and 16-bit quantities;
 * they take a pointer to the quantity, and byte-swap it in place.
 */
#define PBSWAP64(p) \
    {            \
        guint8 tmp;        \
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
        guint8 tmp;         \
        tmp = (p)[3];       \
        (p)[3] = (p)[0];    \
        (p)[0] = tmp;       \
        tmp = (p)[2];       \
        (p)[2] = (p)[1];    \
        (p)[1] = tmp;       \
    }
#define PBSWAP16(p) \
    {            \
        guint8 tmp;        \
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
        (p)[0] = (guint8)((v) >> 8);    \
        (p)[1] = (guint8)((v) >> 0);    \
    }
#endif

#ifndef phton24
#define phton24(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 16);    \
        (p)[1] = (guint8)((v) >> 8);     \
        (p)[2] = (guint8)((v) >> 0);     \
    }
#endif

#ifndef phtonl
#define phtonl(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 24);    \
        (p)[1] = (guint8)((v) >> 16);    \
        (p)[2] = (guint8)((v) >> 8);     \
        (p)[3] = (guint8)((v) >> 0);     \
    }
#endif

#ifndef phtonll
#define phtonll(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 56);    \
        (p)[1] = (guint8)((v) >> 48);    \
        (p)[2] = (guint8)((v) >> 40);    \
        (p)[3] = (guint8)((v) >> 32);    \
        (p)[4] = (guint8)((v) >> 24);    \
        (p)[5] = (guint8)((v) >> 16);    \
        (p)[6] = (guint8)((v) >> 8);     \
        (p)[7] = (guint8)((v) >> 0);     \
    }
#endif

#ifndef phtole8
#define phtole8(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 0);    \
    }
#endif

#ifndef phtoles
#define phtoles(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 0);    \
        (p)[1] = (guint8)((v) >> 8);    \
    }
#endif

#ifndef phtole24
#define phtole24(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 0);     \
        (p)[1] = (guint8)((v) >> 8);     \
        (p)[2] = (guint8)((v) >> 16);    \
    }
#endif

#ifndef phtolel
#define phtolel(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 0);     \
        (p)[1] = (guint8)((v) >> 8);     \
        (p)[2] = (guint8)((v) >> 16);    \
        (p)[3] = (guint8)((v) >> 24);    \
    }
#endif

#ifndef phtolell
#define phtolell(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 0);     \
        (p)[1] = (guint8)((v) >> 8);     \
        (p)[2] = (guint8)((v) >> 16);    \
        (p)[3] = (guint8)((v) >> 24);    \
        (p)[4] = (guint8)((v) >> 32);    \
        (p)[5] = (guint8)((v) >> 40);    \
        (p)[6] = (guint8)((v) >> 48);    \
        (p)[7] = (guint8)((v) >> 56);    \
    }
#endif

/* glib doesn't have g_ptr_array_len of all things!*/
#ifndef g_ptr_array_len
#define g_ptr_array_len(a)      ((a)->len)
#endif

/*
 * Read a given number of bytes from a file into a buffer or, if
 * buf is NULL, just discard them.
 *
 * If we succeed, return TRUE.
 *
 * If we get an EOF, return FALSE with *err set to 0, reporting this
 * as an EOF.
 *
 * If we get fewer bytes than the specified number, return FALSE with
 * *err set to WTAP_ERR_SHORT_READ, reporting this as a short read
 * error.
 *
 * If we get a read error, return FALSE with *err and *err_info set
 * appropriately.
 */
WS_DLL_PUBLIC
gboolean
wtap_read_bytes_or_eof(FILE_T fh, void *buf, unsigned int count, int *err,
    gchar **err_info);

/*
 * Read a given number of bytes from a file into a buffer or, if
 * buf is NULL, just discard them.
 *
 * If we succeed, return TRUE.
 *
 * If we get fewer bytes than the specified number, including getting
 * an EOF, return FALSE with *err set to WTAP_ERR_SHORT_READ, reporting
 * this as a short read error.
 *
 * If we get a read error, return FALSE with *err and *err_info set
 * appropriately.
 */
WS_DLL_PUBLIC
gboolean
wtap_read_bytes(FILE_T fh, void *buf, unsigned int count, int *err,
    gchar **err_info);

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
gboolean
wtap_read_packet_bytes(FILE_T fh, Buffer *buf, guint length, int *err,
    gchar **err_info);

/*
 * Implementation of wth->subtype_read that reads the full file contents
 * as a single packet.
 */
gboolean
wtap_full_file_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, gchar **err_info, gint64 *data_offset);

/*
 * Implementation of wth->subtype_seek_read that reads the full file contents
 * as a single packet.
 */
gboolean
wtap_full_file_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info);

/**
 * Add an IDB to the interface data for a file.
 */
void
wtap_add_idb(wtap *wth, wtap_block_t idb);

/**
 * Invokes the callback with the given decryption secrets block.
 */
void
wtapng_process_dsb(wtap *wth, wtap_block_t dsb);
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
