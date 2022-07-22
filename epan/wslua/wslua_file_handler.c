/*
 * wslua_file_handler.c
 *
 * Wireshark's interface to the Lua Programming Language
 * for custom file reading/writing.
 *
 * (c) 2014, Hadriel Kaplan <hadrielk@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include "wslua_file_common.h"
#include <wiretap/file_wrappers.h>

/* WSLUA_CONTINUE_MODULE File */


WSLUA_CLASS_DEFINE(FileHandler,NOP);
/*
    A FileHandler object, created by a call to FileHandler.new(arg1, arg2, ...).
    The FileHandler object lets you create a file-format reader, or writer, or
    both, by setting your own read_open/read or write_open/write functions.

    @since 1.11.3
 */

static int filehandler_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    const gchar* functype = luaL_optstring(L, lua_upvalueindex(1), "UNKNOWN");
    report_failure("Lua: Error During execution of FileHandler %s callback:\n %s",functype,error);
    lua_pop(L, 1);
    return 0;
}

static int push_error_handler(lua_State* L, const gchar* funcname) {
    lua_pushstring(L, funcname);
    lua_pushcclosure(L, filehandler_cb_error_handler, 1);
    return 1;
}


/* Keep track of registered FileHandlers such that reloading plugins works. */
static GSList *registered_file_handlers;

/* During file routines, we cannot allow the FileHandler to get deregistered, since
   that would change the GArray's in file_access.c and hilarity would ensue. So we
   set this to true right before pcall(), and back to false afterwards */
static gboolean in_routine = FALSE;

static void
report_error(int *err, gchar **err_info, const char *fmt, ...)
{
    va_list ap;
    gchar *msg;

    va_start(ap, fmt);
    msg = ws_strdup_vprintf(fmt, ap);
    va_end(ap);
    if (err != NULL) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = msg;
    } else {
        ws_warning("%s", msg);
        g_free(msg);
    }
}

/* This does the verification and setup common to all open/read/seek_read/close routines */
#define INIT_FILEHANDLER_ROUTINE(name,retval,err,err_info) \
    if (!fh) { \
        report_error(err, err_info, "Error in file %s: no Lua FileHandler object", #name); \
        return retval; \
    } \
    if (fh->removed) { \
        return retval; \
    } \
    if (!fh->registered) { \
        report_error(err, err_info, "Error in file %s: Lua FileHandler is not registered", #name); \
        return retval; \
    } \
    if (!fh->L) { \
        report_error(err, err_info, "Error in file %s: no FileHandler Lua state", #name); \
        return retval; \
    } \
    if (fh->name##_ref == LUA_NOREF) { \
        report_error(err, err_info, "Error in file %s: no FileHandler %s routine reference", #name, #name); \
        return retval; \
    } \
    L = fh->L; \
    lua_settop(L,0); \
    push_error_handler(L, #name " routine"); \
    lua_rawgeti(L, LUA_REGISTRYINDEX, fh->name##_ref); \
    if (!lua_isfunction(L, -1)) { \
        report_error(err, err_info, "Error in file %s: no FileHandler %s routine function in Lua", #name, #name); \
        return retval; \
    } \
    /* now guard against deregistering during pcall() */ \
    in_routine = TRUE

#define END_FILEHANDLER_ROUTINE() \
    /* now allow deregistering again */ \
    in_routine = FALSE


/* LUA_ERRGCMM is in Lua 5.2 only - making it 9 disables it */
#ifndef LUA_ERRGCMM
#define LUA_ERRGCMM 9
#endif

#define CASE_ERROR(name,err,err_info) \
    case LUA_ERRRUN: \
        report_error(err, err_info, "Run-time error while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRMEM: \
        report_error(err, err_info, "Memory alloc error while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRERR: \
        report_error(err, err_info, "Error in error handling while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRGCMM: \
        report_error(err, err_info, "Error in garbage collector while calling FileHandler %s routine", name); \
        break; \
    default: \
        ws_assert_not_reached(); \
        break;

/* some declarations */
static gboolean
wslua_filehandler_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                       int *err, gchar **err_info, gint64 *offset);
static gboolean
wslua_filehandler_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec, Buffer *buf,
                            int *err, gchar **err_info);
static void
wslua_filehandler_close(wtap *wth);
static void
wslua_filehandler_sequential_close(wtap *wth);


/* This is our one-and-only open routine for file handling.  When called by
 * file_access.c, the wtap wth argument has a void* wslua_data that holds the specific
 * FileHandler for the specific registered file format reader.  It has this because
 * we passed it in when we registered the open routine.
 * The open_file_* routines should return:
 *  -1 on an I/O error;
 *  1 if the file they're reading is one of the types it handles;
 *  0 if the file they're reading isn't the type they're checking for.
 * If the routine handles this type of file, it should set the "file_type"
 * field in the "struct wtap" to the type of the file.
 */
static wtap_open_return_val
wslua_filehandler_open(wtap *wth, int *err, gchar **err_info)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);
    wtap_open_return_val retval = WTAP_OPEN_NOT_MINE;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfo *fc = NULL;

    INIT_FILEHANDLER_ROUTINE(read_open,WTAP_OPEN_ERROR,err,err_info);

    create_wth_priv(L, wth);

    fp = push_File(L, wth->fh);
    fc = push_CaptureInfo(L, wth, TRUE);

    errno = WTAP_ERR_CANT_OPEN;
    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            retval = (wtap_open_return_val)wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR("read_open",err,err_info)
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;

    if (retval == WTAP_OPEN_MINE) {
        /* this is our file type - set the routines and settings into wtap */

        if (fh->read_ref != LUA_NOREF) {
            wth->subtype_read = wslua_filehandler_read;
        }
        else {
            ws_warning("Lua file format module lacks a read routine");
            return WTAP_OPEN_NOT_MINE;
        }

        /* when not having a seek_read routine a default will be used */
        wth->subtype_seek_read = wslua_filehandler_seek_read;

        /* it's ok to not have a close routine */
        if (fh->read_close_ref != LUA_NOREF)
            wth->subtype_close = wslua_filehandler_close;
        else
            wth->subtype_close = NULL;

        /* it's ok to not have a sequential close routine */
        if (fh->seq_read_close_ref != LUA_NOREF)
            wth->subtype_sequential_close = wslua_filehandler_sequential_close;
        else
            wth->subtype_sequential_close = NULL;

        wth->file_type_subtype = fh->file_type;
    }
    else if (retval == WTAP_OPEN_ERROR) {
        /* open error - we *must* return an error code! */
        if (err) {
            *err = WTAP_ERR_CANT_OPEN;
        }
    }
    else if (retval == WTAP_OPEN_NOT_MINE) {
        /* not our file type */
        remove_wth_priv(L, wth);
    }
    else {
        /* not a valid return type */
        if (err) {
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup_printf("FileHandler read_open routine returned %d", retval);
        }
        retval = WTAP_OPEN_ERROR;
    }

    lua_settop(L,0);
    return retval;
}

static gboolean
wslua_filehandler_read_packet(wtap *wth, FILE_T wth_fh, wtap_rec *rec, Buffer *buf,
                              int *err, gchar **err_info, gint64 *offset)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);
    int retval = -1;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfo *fc = NULL;
    FrameInfo *fi = NULL;

    INIT_FILEHANDLER_ROUTINE(read,FALSE,err,err_info);

    /* Reset errno */
    if (err) {
        *err = errno = 0;
    }

    wtap_block_unref(rec->block);
    rec->block = NULL;

    fp = push_File(L, wth_fh);
    fc = push_CaptureInfo(L, wth, FALSE);
    fi = push_FrameInfo(L, rec, buf);

    switch ( lua_pcall(L,3,1,1) ) {
        case 0:
            /*
             * Return values for FileHandler:read():
             * Integer is the number of read bytes.
             * Boolean false indicates an error.
             * XXX handling of boolean true is not documented. Currently it will
             * succeed without advancing data offset. Should it fail instead?
             */
            if (lua_type(L, -1) == LUA_TNUMBER) {
                *offset = wslua_togint64(L, -1);
                retval = 1;
                break;
            }
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR("read",err,err_info)
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;
    (*fi)->expired = TRUE;
    lua_settop(L,0);

    return (retval == 1);
}

/* The classic wtap read routine.  This returns TRUE if it found the next packet,
 * else FALSE.
 * If it finds a frame/packet, it should set the pseudo-header info (ie, let Lua set it).
 * Also Lua needs to set data_offset to the beginning of the line we're returning.
 * This will be the seek_off parameter when this frame is re-read.
 */
static gboolean
wslua_filehandler_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                       int *err, gchar **err_info, gint64 *offset)
{
    return wslua_filehandler_read_packet(wth, wth->fh, rec, buf, err, err_info, offset);
}

static gboolean
wslua_filehandler_seek_read_packet(wtap *wth, gint64 seek_off, wtap_rec *rec, Buffer *buf,
                            int *err, gchar **err_info)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);
    int retval = -1;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfo *fc = NULL;
    FrameInfo *fi = NULL;

    INIT_FILEHANDLER_ROUTINE(seek_read,FALSE,err,err_info);

    /* Reset errno */
    if (err) {
        *err = errno = 0;
    }

    wtap_block_unref(rec->block);
    rec->block = NULL;

    fp = push_File(L, wth->random_fh);
    fc = push_CaptureInfo(L, wth, FALSE);
    fi = push_FrameInfo(L, rec, buf);
    lua_pushnumber(L, (lua_Number)seek_off);

    switch ( lua_pcall(L,4,1,1) ) {
        case 0:
            /*
             * Return values for FileHandler:seek_read():
             * Boolean true for successful parsing, false/nil on error.
             * Numbers (including zero) are interpreted as success for
             * compatibility to match FileHandler:seek semantics.
             * (Other values are unspecified/undocumented, but happen to be
             * treated as success.)
             */
            retval = lua_toboolean(L, -1);
            break;
        CASE_ERROR("seek_read",err,err_info)
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;
    (*fi)->expired = TRUE;
    lua_settop(L,0);

    return (retval == 1);
}

/* Default FileHandler:seek_read() implementation.
 * Do a standard file_seek() and then call FileHandler:read().
 */
static gboolean
wslua_filehandler_seek_read_default(wtap *wth, gint64 seek_off, wtap_rec *rec, Buffer *buf,
                                    int *err, gchar **err_info)
{
    gint64 offset = file_seek(wth->random_fh, seek_off, SEEK_SET, err);

    if (offset < 0) {
        return FALSE;
    }

    return wslua_filehandler_read_packet(wth, wth->random_fh, rec, buf, err, err_info, &offset);
}

/* Classic wtap seek_read function, called by wtap core.  This must return TRUE on
 * success, FALSE on error.
 */
static gboolean
wslua_filehandler_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec, Buffer *buf,
                            int *err, gchar **err_info)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);

    if (fh->removed) {
        /* Return success when removed during reloading Lua plugins */
        return TRUE;
    }

    if (fh->seek_read_ref != LUA_NOREF) {
        return wslua_filehandler_seek_read_packet(wth, seek_off, rec, buf, err, err_info);
    } else {
        return wslua_filehandler_seek_read_default(wth, seek_off, rec, buf, err, err_info);
    }
}

/* Classic wtap close function, called by wtap core.
 */
static void
wslua_filehandler_close(wtap *wth)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfo *fc = NULL;

    INIT_FILEHANDLER_ROUTINE(read_close,,NULL,NULL);

    fp = push_File(L, wth->fh);
    fc = push_CaptureInfo(L, wth, FALSE);

    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            break;
        CASE_ERROR("read_close",NULL,NULL)
    }

    END_FILEHANDLER_ROUTINE();

    remove_wth_priv(L, wth);

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;
    lua_settop(L,0);

    return;
}

/* Classic wtap sequential close function, called by wtap core.
 */
static void
wslua_filehandler_sequential_close(wtap *wth)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfo *fc = NULL;

    INIT_FILEHANDLER_ROUTINE(seq_read_close,,NULL,NULL);

    fp = push_File(L, wth->fh);
    fc = push_CaptureInfo(L, wth, FALSE);

    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            break;
        CASE_ERROR("seq_read_close",NULL,NULL)
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;
    lua_settop(L,0);

    return;
}


/* basically a dummy function to use for can_write_encap so that the caller calls
 * wslua_can_write_encap instead (which will be wslua_filehandler_can_write_encap)
 */
static int
wslua_dummy_can_write_encap(int encap _U_)
{
    return WTAP_ERR_CHECK_WSLUA;
}

/* Similar to the classic wtap can_write_encap function.
 * This returns 0 if the encap is ok for this file type.
 */
static int
wslua_filehandler_can_write_encap(int encap, void* data)
{
    FileHandler fh = (FileHandler)(data);
    int retval = WTAP_ERR_UNWRITABLE_ENCAP;
    lua_State* L = NULL;

    INIT_FILEHANDLER_ROUTINE(can_write_encap,WTAP_ERR_UNWRITABLE_ENCAP,NULL,NULL);

    lua_pushnumber(L, encap);

    switch ( lua_pcall(L,1,1,1) ) {
        case 0:
            retval = wslua_optboolint(L,-1,WTAP_ERR_UNWRITABLE_ENCAP);
            break;
        CASE_ERROR("can_write_encap",NULL,NULL)
    }

    END_FILEHANDLER_ROUTINE();

    /* the retval we got was either a 1 for true, 0 for false, or WTAP_ERR_UNWRITABLE_ENCAP;
       but can_write_encap() expects 0 to be true/yes */
    if (retval == 1) {
        retval = 0;
    } else if (retval == 0) {
        retval = WTAP_ERR_UNWRITABLE_ENCAP;
    }

    return retval;
}

/* some declarations */
static gboolean
wslua_filehandler_dump(wtap_dumper *wdh, const wtap_rec *rec,
                      const guint8 *pd, int *err, gchar **err_info);
static gboolean
wslua_filehandler_dump_finish(wtap_dumper *wdh, int *err, gchar **err_info);


/* The classic wtap dump_open function.
 * This returns 1 (TRUE) on success.
 */
static int
wslua_filehandler_dump_open(wtap_dumper *wdh, int *err, gchar **err_info)
{
    FileHandler fh = (FileHandler)(wdh->wslua_data);
    int retval = 0;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfoConst *fc = NULL;

    INIT_FILEHANDLER_ROUTINE(write_open,0,err,err_info);

    create_wdh_priv(L, wdh);

    fp = push_Wdh(L, wdh);
    fc = push_CaptureInfoConst(L,wdh);

    /* Reset err */
    if (err) {
        *err = 0;
    }

    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR("write_open",err,err_info)
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;

    if (retval == 1) {
        /* this is our file type - set the routines and settings into wtap */

        if (fh->write_ref != LUA_NOREF) {
            wdh->subtype_write = wslua_filehandler_dump;
        }
        else {
            ws_warning("FileHandler was not set with a write function, even though write_open() returned true");
            return 0;
        }

        /* it's ok to not have a finish routine */
        if (fh->write_close_ref != LUA_NOREF)
            wdh->subtype_finish = wslua_filehandler_dump_finish;
        else
            wdh->subtype_finish = NULL;
    }
    else {
        /* not our file type? */
        remove_wdh_priv(L, wdh);
    }

    return retval;
}

/* The classic wtap dump routine.  This returns TRUE if it writes the current packet,
 * else FALSE.
*/
static gboolean
wslua_filehandler_dump(wtap_dumper *wdh, const wtap_rec *rec,
                      const guint8 *pd, int *err, gchar **err_info)
{
    FileHandler fh = (FileHandler)(wdh->wslua_data);
    int retval = -1;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfoConst *fc = NULL;
    FrameInfoConst *fi = NULL;

    INIT_FILEHANDLER_ROUTINE(write,FALSE,err,err_info);

    /* Reset errno */
    if (err) {
        *err = errno = 0;
    }

    fp = push_Wdh(L, wdh);
    fc = push_CaptureInfoConst(L,wdh);
    fi = push_FrameInfoConst(L, rec, pd);

    errno = WTAP_ERR_CANT_WRITE;
    switch ( lua_pcall(L,3,1,1) ) {
        case 0:
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR("write",err,err_info)
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;
    (*fi)->expired = TRUE;

    return (retval == 1);
}

/* The classic wtap dump_finish routine.  This returns TRUE if it
 * writes out the last information cleanly, else FALSE.
*/
static gboolean
wslua_filehandler_dump_finish(wtap_dumper *wdh, int *err, gchar **err_info)
{
    FileHandler fh = (FileHandler)(wdh->wslua_data);
    int retval = -1;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfoConst *fc = NULL;

    INIT_FILEHANDLER_ROUTINE(write_close,FALSE,err,err_info);

    /* Reset errno */
    if (err) {
        *err = errno = 0;
    }

    fp = push_Wdh(L, wdh);
    fc = push_CaptureInfoConst(L,wdh);

    errno = WTAP_ERR_CANT_CLOSE;
    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR("write_close",err,err_info)
    }

    END_FILEHANDLER_ROUTINE();

    remove_wdh_priv(L, wdh);

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;

    return (retval == 1);
}

/*
 * Prototype table of option support.
 * We start out saying we don't support comments, and we don't mention
 * other options.
 */
static const struct supported_option_type option_type_proto[] = {
	{ OPT_COMMENT, OPTION_NOT_SUPPORTED }
};

/*
 * Prototype table of block type support.
 * We start out saying we only support packets.
 */
static const struct supported_block_type block_type_proto[] = {
	{ WTAP_BLOCK_SECTION, BLOCK_NOT_SUPPORTED, 0, NULL },
	{ WTAP_BLOCK_IF_ID_AND_INFO, BLOCK_NOT_SUPPORTED, 0, NULL },
	{ WTAP_BLOCK_NAME_RESOLUTION, BLOCK_NOT_SUPPORTED, 0, NULL },
	{ WTAP_BLOCK_IF_STATISTICS, BLOCK_NOT_SUPPORTED, 0, NULL },
	{ WTAP_BLOCK_DECRYPTION_SECRETS, BLOCK_NOT_SUPPORTED, 0, NULL },
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, 0, NULL },
	{ WTAP_BLOCK_FT_SPECIFIC_REPORT, BLOCK_NOT_SUPPORTED, 0, NULL },
	{ WTAP_BLOCK_FT_SPECIFIC_EVENT, BLOCK_NOT_SUPPORTED, 0, NULL }
};

#define NUM_LISTED_BLOCK_TYPES (sizeof block_type_proto / sizeof block_type_proto[0])

WSLUA_CONSTRUCTOR FileHandler_new(lua_State* L) {
    /* Creates a new FileHandler */
#define WSLUA_ARG_FileHandler_new_DESCRIPTION 1 /* A description of the file type, for display purposes only. E.g., "Wireshark - pcapng" */
#define WSLUA_ARG_FileHandler_new_NAME 2 /* The file type name, used to look up the file type in various places. E.g., "pcapng". Note: The name cannot already be in use. */
#define WSLUA_ARG_FileHandler_new_INTERNAL_DESCRIPTION 3 /* Descriptive text about this file format, for internal display purposes only */
#define WSLUA_ARG_FileHandler_new_TYPE 4 /* The type of FileHandler, "r"/"w"/"rw" for reader/writer/both, include "m" for magic, "s" for strong heuristic */

    const gchar* description = luaL_checkstring(L,WSLUA_ARG_FileHandler_new_DESCRIPTION);
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_FileHandler_new_NAME);
    const gchar* internal_description = luaL_checkstring(L,WSLUA_ARG_FileHandler_new_INTERNAL_DESCRIPTION);
    const gchar* type = luaL_checkstring(L,WSLUA_ARG_FileHandler_new_TYPE);
    FileHandler fh = (FileHandler) g_malloc0(sizeof(struct _wslua_filehandler));
    struct supported_block_type *supported_blocks;

    fh->is_reader = (strchr(type,'r') != NULL) ? TRUE : FALSE;
    fh->is_writer = (strchr(type,'w') != NULL) ? TRUE : FALSE;

    if (fh->is_reader && wtap_has_open_info(name)) {
        g_free(fh);
        return luaL_error(L, "FileHandler.new: '%s' name already exists for a reader!", name);
    }

    if (fh->is_writer && wtap_name_to_file_type_subtype(name) > -1) {
        g_free(fh);
        return luaL_error(L, "FileHandler.new: '%s' name already exists for a writer!", name);
    }

    fh->type = g_strdup(type);
    fh->extensions = NULL;
    fh->finfo.description = g_strdup(description);
    fh->finfo.name = g_strdup(name);
    fh->finfo.default_file_extension = NULL;
    fh->finfo.additional_file_extensions = NULL;
    fh->finfo.writing_must_seek = FALSE;
    supported_blocks = (struct supported_block_type  *)g_memdup2(&block_type_proto, sizeof block_type_proto);
    /*
     * Add a list of options to the seciton block, interface block, and
     * packet block, so the file handler can indicate comment support.
     */
    for (size_t i = 0; i < NUM_LISTED_BLOCK_TYPES; i++) {
        switch (supported_blocks[i].type) {

        case WTAP_BLOCK_SECTION:
        case WTAP_BLOCK_IF_ID_AND_INFO:
        case WTAP_BLOCK_PACKET:
            supported_blocks[i].num_supported_options = OPTION_TYPES_SUPPORTED(option_type_proto);
            supported_blocks[i].supported_options = (struct supported_option_type *)g_memdup2(&option_type_proto, sizeof option_type_proto);
            break;

        default:
            break;
        }
    }
    fh->finfo.num_supported_blocks = NUM_LISTED_BLOCK_TYPES;
    fh->finfo.supported_blocks = supported_blocks;
    fh->finfo.can_write_encap = NULL;
    fh->finfo.dump_open = NULL;
    /* this will be set to a new file_type when registered */
    fh->file_type = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;

    fh->internal_description = g_strdup(internal_description);
    fh->L = L;
    fh->read_open_ref = LUA_NOREF;
    fh->read_ref = LUA_NOREF;
    fh->seek_read_ref = LUA_NOREF;
    fh->read_close_ref = LUA_NOREF;
    fh->seq_read_close_ref = LUA_NOREF;
    fh->write_open_ref = LUA_NOREF;
    fh->write_ref = LUA_NOREF;
    fh->write_close_ref = LUA_NOREF;
    fh->can_write_encap_ref = LUA_NOREF;

    fh->registered = FALSE;

    pushFileHandler(L,fh);
    WSLUA_RETURN(1); /* The newly created FileHandler object */
}

WSLUA_METAMETHOD FileHandler__tostring(lua_State* L) {
    /* Generates a string of debug info for the FileHandler */
    FileHandler fh = toFileHandler(L,1);

    if (!fh) {
        lua_pushstring(L,"FileHandler pointer is NULL!");
    } else {
        lua_pushfstring(L, "FileHandler(%s): description='%s', internal description='%s', read_open=%d, read=%d, write=%d",
            fh->finfo.name, fh->finfo.description, fh->internal_description, fh->read_open_ref, fh->read_ref, fh->write_ref);
    }

    WSLUA_RETURN(1); /* String of debug information. */
}

static int FileHandler__gc(lua_State* L _U_) {
    /* do NOT free FileHandler, it's never free'd */
    /* TODO: handle this and other Lua things that should be free'd on exit, in a better way */
    return 0;
}

/* A Lua File handler must not be expired, and must be either a reader or writer, and
 * a *reader* one MUST at least define read_open, read, and seek_read funcs; and
 * a *writer* one MUST at least define can_write_encap, write_open, and write funcs
 */
static gboolean verify_filehandler_complete(FileHandler fh) {
    return ((fh->is_reader || fh->is_writer) &&
            (!fh->is_reader ||
             (fh->is_reader &&
              fh->read_open_ref != LUA_NOREF &&
              fh->read_ref      != LUA_NOREF)) &&
            (!fh->is_writer ||
             (fh->is_writer &&
              fh->can_write_encap_ref != LUA_NOREF &&
              fh->write_open_ref      != LUA_NOREF &&
              fh->write_ref           != LUA_NOREF)) );
}


WSLUA_FUNCTION wslua_register_filehandler(lua_State* L) {
    /* Register the FileHandler into Wireshark/TShark, so they can read/write this new format.
       All functions and settings must be complete before calling this registration function.
       This function cannot be called inside the reading/writing callback functions. */
#define WSLUA_ARG_register_filehandler_FILEHANDLER 1 /* The FileHandler object to be registered */
    FileHandler fh = checkFileHandler(L,WSLUA_ARG_register_filehandler_FILEHANDLER);

    if (in_routine)
        return luaL_error(L,"a FileHandler cannot be registered during reading/writing callback functions");

    if (fh->registered)
        return luaL_error(L,"this FileHandler is already registered");

    if (!verify_filehandler_complete(fh))
        return luaL_error(L,"this FileHandler is not complete enough to register");

    if (fh->is_writer) {
        if (fh->extensions && fh->extensions[0]) {
            char *extension = g_strdup(fh->extensions);
            char *extra_extensions = strchr(extension, ';');
            if (extra_extensions) {
                /* Split "cap;pcap" -> "cap" and "pcap" */
                *extra_extensions++ = '\0';
            }
            fh->finfo.default_file_extension = extension;
            fh->finfo.additional_file_extensions = extra_extensions;
        }
        fh->finfo.can_write_encap = wslua_dummy_can_write_encap;
        fh->finfo.wslua_info = g_new0(wtap_wslua_file_info_t, 1);
        fh->finfo.wslua_info->wslua_can_write_encap = wslua_filehandler_can_write_encap;
        fh->finfo.wslua_info->wslua_data = (void*)(fh);
        fh->finfo.dump_open = wslua_filehandler_dump_open;
    }

    fh->file_type = wtap_register_file_type_subtype(&(fh->finfo));

    if (fh->is_reader) {
        struct open_info oi = { NULL, OPEN_INFO_HEURISTIC, NULL, NULL, NULL, NULL };
        oi.name = fh->finfo.name;
        oi.open_routine = wslua_filehandler_open;
        oi.extensions = fh->extensions;
        oi.wslua_data = (void*)(fh);
        if (strchr(fh->type,'m') != NULL) {
            oi.type = OPEN_INFO_MAGIC;
        } else {
            oi.type = OPEN_INFO_HEURISTIC;
        }
        wtap_register_open_info(&oi, (strchr(fh->type,'s') != NULL));
    }

    fh->registered = TRUE;
    registered_file_handlers = g_slist_prepend(registered_file_handlers, fh);

    lua_pushnumber(L, fh->file_type);

    WSLUA_RETURN(1); /* the new type number for this file reader/write */
}

static void
wslua_deregister_filehandler_work(FileHandler fh)
{
    /* undo writing stuff, even if it wasn't a writer */
    fh->finfo.can_write_encap = NULL;
    if (fh->finfo.wslua_info) {
        fh->finfo.wslua_info->wslua_can_write_encap = NULL;
        fh->finfo.wslua_info->wslua_data = NULL;
        g_free(fh->finfo.wslua_info);
        fh->finfo.wslua_info = NULL;
    }
    g_free((char *)fh->finfo.default_file_extension);
    fh->finfo.default_file_extension = NULL;
    fh->finfo.additional_file_extensions = NULL;
    fh->finfo.dump_open = NULL;

    if (fh->file_type != WTAP_FILE_TYPE_SUBTYPE_UNKNOWN) {
        wtap_deregister_file_type_subtype(fh->file_type);
    }

    if (fh->is_reader && wtap_has_open_info(fh->finfo.name)) {
        wtap_deregister_open_info(fh->finfo.name);
    }

    fh->registered = FALSE;
}

WSLUA_FUNCTION wslua_deregister_filehandler(lua_State* L) {
    /* Deregister the FileHandler from Wireshark/TShark, so it no longer gets used for reading/writing/display.
       This function cannot be called inside the reading/writing callback functions. */
#define WSLUA_ARG_deregister_filehandler_FILEHANDLER 1 /* The FileHandler object to be deregistered */
    FileHandler fh = checkFileHandler(L,WSLUA_ARG_deregister_filehandler_FILEHANDLER);

    if (in_routine)
        return luaL_error(L,"A FileHandler cannot be deregistered during reading/writing callback functions");

    if (!fh->registered)
        return 0;

    wslua_deregister_filehandler_work(fh);
    registered_file_handlers = g_slist_remove(registered_file_handlers, fh);

    return 0;
}

/* The following macros generate setter functions for Lua, for the following Lua
   function references in _wslua_filehandler struct:
    int read_open_ref;
    int read_ref;
    int seek_read_ref;
    int read_close_ref;
    int seq_read_close_ref;
    int can_write_encap_ref;
    int write_open_ref;
    int write_ref;
    int write_close_ref;
*/

/* WSLUA_ATTRIBUTE FileHandler_read_open WO The Lua function to be called when Wireshark opens a file for reading.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfo` object

    The purpose of the Lua function set to this `read_open` field is to check if the file Wireshark is opening is of its type,
    for example by checking for magic numbers or trying to parse records in the file, etc.  The more can be verified
    the better, because Wireshark tries all file readers until it finds one that accepts the file, so accepting an
    incorrect file prevents other file readers from reading their files.

    The called Lua function should return true if the file is its type (it accepts it), false if not.  The Lua
    function must also set the File offset position (using `file:seek()`) to where it wants it to be for its first
    `read()` call.
    */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,read_open);

/* WSLUA_ATTRIBUTE FileHandler_read WO The Lua function to be called when Wireshark wants to read a packet from the file.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfo` object
        3. A `FrameInfo` object

    The purpose of the Lua function set to this `read` field is to read the next packet from the file, and setting the parsed/read
    packet into the frame buffer using `FrameInfo.data = foo` or `FrameInfo:read_data(file, frame.captured_length)`.

    The called Lua function should return the file offset/position number where the packet begins, or false if it hit an
    error.  The file offset will be saved by Wireshark and passed into the set `seek_read()` Lua function later.
    */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,read);

/* WSLUA_ATTRIBUTE FileHandler_seek_read WO The Lua function to be called when Wireshark wants to read a packet from the file at the given offset.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfo` object
        3. A `FrameInfo` object
        4. The file offset number previously set by the `read()` function call

    The called Lua function should return true if the read was successful, or false if it hit an error.
    Since 2.4.0, a number is also acceptable to signal success, this allows for reuse of `FileHandler:read`:

    [source,lua]
    ----
    local function fh_read(file, capture, frame) ... end
    myfilehandler.read = fh_read

    function myfilehandler.seek_read(file, capture, frame, offset)
        if not file:seek("set", offset) then
            -- Seeking failed, return failure
            return false
        end

        -- Now try to read one frame
        return fh_read(file, capture, frame)
    end
    ----

    Since 3.6.0, it's possible to omit the `FileHandler:seek_read()` function to get a default seek_read implementation.
 */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,seek_read);

/* WSLUA_ATTRIBUTE FileHandler_read_close WO The Lua function to be called when Wireshark wants to close the read file completely.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfo` object

    It is not necessary to set this field to a Lua function - FileHandler can be registered without doing so - it
    is available in case there is memory/state to clear in your script when the file is closed. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,read_close);

/* WSLUA_ATTRIBUTE FileHandler_seq_read_close WO The Lua function to be called when Wireshark wants to close the sequentially-read file.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfo` object

    It is not necessary to set this field to a Lua
    function - FileHandler can be registered without doing so - it is available in case there is memory/state to clear in your script
    when the file is closed for the sequential reading portion.  After this point, there will be no more calls to `read()`, only `seek_read()`. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,seq_read_close);


/* WSLUA_ATTRIBUTE FileHandler_can_write_encap WO The Lua function to be called when Wireshark wants to write a file,
    by checking if this file writer can handle the wtap packet encapsulation(s).

    When later called by Wireshark, the Lua function will be given a Lua number, which matches one of the encapsulations
    in the Lua `wtap_encaps` table.  This might be the `wtap_encap.PER_PACKET` number, meaning the capture contains multiple
    encapsulation types, and the file reader should only return true if it can handle multiple encap types in one file. The
    function will then be called again, once for each encap type in the file, to make sure it can write each one.

    If the Lua file writer can write the given type of encapsulation into a file, then it returns the boolean true, else false. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,can_write_encap);

/* WSLUA_ATTRIBUTE FileHandler_write_open WO The Lua function to be called when Wireshark opens a file for writing.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfoConst` object

    The purpose of the Lua function set to this `write_open` field is similar to the read_open callback function:
    to initialize things necessary for writing the capture to a file. For example, if the output file format has a
    file header, then the file header should be written within this write_open function.

    The called Lua function should return true on success, or false if it hit an error.

    Also make sure to set the `FileHandler.write` (and potentially `FileHandler.write_finish`) functions before
    returning true from this function. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,write_open);

/* WSLUA_ATTRIBUTE FileHandler_write WO The Lua function to be called when Wireshark wants to write a packet to the file.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfoConst` object
        3. A `FrameInfoConst` object of the current frame/packet to be written

    The purpose of the Lua function set to this `write` field is to write the next packet to the file.

    The called Lua function should return true on success, or false if it hit an error. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,write);

/* WSLUA_ATTRIBUTE FileHandler_write_finish WO The Lua function to be called when Wireshark wants to close the written file.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfoConst` object

    It is not necessary to set this field to a Lua function - `FileHandler` can be registered without doing so - it is available
    in case there is memory/state to clear in your script when the file is closed. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,write_close);

/* generate other member accessors setters/getters */

/* WSLUA_ATTRIBUTE FileHandler_type RO The internal file type.  This is automatically set with a new
    number when the FileHandler is registered. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FileHandler,type,file_type);

/* WSLUA_ATTRIBUTE FileHandler_extensions RW One or more semicolon-separated file extensions that this file type usually uses.

    For readers using heuristics to determine file type, Wireshark will try the readers of the file's
    extension first, before trying other readers.  But ultimately Wireshark tries all file readers
    for any file extension, until it finds one that accepts the file.

    (Since 2.6) For writers, the first extension is used to suggest the default file extension. */
WSLUA_ATTRIBUTE_STRING_GETTER(FileHandler,extensions);
WSLUA_ATTRIBUTE_STRING_SETTER(FileHandler,extensions,TRUE);

/* WSLUA_ATTRIBUTE FileHandler_writing_must_seek RW True if the ability to seek is required when writing
    this file format, else false.

    This will be checked by Wireshark when writing out to compressed
    file formats, because seeking is not possible with compressed files. Usually a file writer only
    needs to be able to seek if it needs to go back in the file to change something, such as a block or
    file length value earlier in the file. */
WSLUA_ATTRIBUTE_NAMED_BOOLEAN_GETTER(FileHandler,writing_must_seek,finfo.writing_must_seek);
WSLUA_ATTRIBUTE_NAMED_BOOLEAN_SETTER(FileHandler,writing_must_seek,finfo.writing_must_seek);

/* WSLUA_ATTRIBUTE FileHandler_writes_name_resolution RW True if the file format supports name resolution
    records, else false. */
static inline struct supported_block_type *
safe_cast_away_block_type_const(const struct supported_block_type *arg)
{
    /*
     * Cast away constness without a warning; we know we can do this
     * because, for Lua file handlers, the table of supported block
     * types is in allocated memory, so that we *can* modify it.
     *
     * The pointer in the file_type_subtype_info structure is a
     * pointer to const because compiled file handlers will
     * normally set it to point to a static const structure.
     */
DIAG_OFF_CAST_AWAY_CONST
    return (struct supported_block_type *)arg;
DIAG_ON_CAST_AWAY_CONST
}

WSLUA_ATTRIBUTE_GET(FileHandler,writes_name_resolution,{ \
    gboolean supports_name_resolution = FALSE; \
    for (size_t i = 0; i < obj->finfo.num_supported_blocks; i++) { \
        /* \
         * If WTAP_BLOCK_NAME_RESOLUTION is supported, name \
         * resolution is supported. \
         */ \
        if (obj->finfo.supported_blocks[i].type == WTAP_BLOCK_NAME_RESOLUTION) { \
            supports_name_resolution = (obj->finfo.supported_blocks[i].support != BLOCK_NOT_SUPPORTED); \
            break; \
        } \
    } \
    lua_pushboolean(L, supports_name_resolution); \
});
WSLUA_ATTRIBUTE_SET(FileHandler,writes_name_resolution, { \
    gboolean supports_name_resolution; \
    if (!lua_isboolean(L,-1) ) \
        return luaL_error(L, "FileHandler's attribute`writes_name_resolution' must be a boolean"); \
    supports_name_resolution = lua_toboolean(L,-1); \
    /* \
     * Update support for WTAP_BLOCK_NAME_RESOLUTION; the entry for \
     * it should be there. \
     */ \
    for (size_t i = 0; i < obj->finfo.num_supported_blocks; i++) { \
        if (obj->finfo.supported_blocks[i].type == WTAP_BLOCK_NAME_RESOLUTION) { \
            struct supported_block_type *supported_blocks;
            supported_blocks = safe_cast_away_block_type_const(obj->finfo.supported_blocks); \

            supported_blocks[i].support = supports_name_resolution ? ONE_BLOCK_SUPPORTED : BLOCK_NOT_SUPPORTED; \
            break; \
        } \
    } \
});

/* WSLUA_ATTRIBUTE FileHandler_supported_comment_types RW Set to the bit-wise OR'ed number representing
    the type of comments the file writer supports writing, based on the numbers in the `wtap_comments` table. */
static inline struct supported_option_type *
safe_cast_away_option_type_const(const struct supported_option_type *arg)
{
    /*
     * Cast away constness without a warning; we know we can do this
     * because, for Lua file handlers, the table of supported option
     * types is in allocated memory, so that we *can* modify it.
     *
     * The pointer in the file_type_subtype_info structure is a
     * pointer to const because compiled file handlers will
     * normally set it to point to a static const structure.
     */
DIAG_OFF_CAST_AWAY_CONST
    return (struct supported_option_type *)arg;
DIAG_ON_CAST_AWAY_CONST
}

WSLUA_ATTRIBUTE_GET(FileHandler,supported_comment_types,{ \
    guint supported_comment_types = 0; \
    for (size_t i = 0; i < obj->finfo.num_supported_blocks; i++) { \
        size_t num_supported_options; \
        const struct supported_option_type *supported_options;
\
        /* \
         * Is this block type supported? \
         */ \
        if (obj->finfo.supported_blocks[i].support == BLOCK_NOT_SUPPORTED) { \
            /* \
             * No - skip it. \
             */ \
            continue; \
        } \
\
        /* \
         * Yes - what type of block is it? \
         */ \
        switch (obj->finfo.supported_blocks[i].type) { \
\
        case WTAP_BLOCK_SECTION: \
            /* \
             * Section block - does this block type support comments? \
             */ \
            num_supported_options = obj->finfo.supported_blocks[i].num_supported_options; \
            supported_options = obj->finfo.supported_blocks[i].supported_options; \
            for (size_t j = 0; j < num_supported_options; i++) { \
                if (supported_options[i].opt == OPT_COMMENT) { \
                    if (supported_options[i].support != OPTION_NOT_SUPPORTED) \
                        supported_comment_types |= WTAP_COMMENT_PER_SECTION; \
                    break; \
                } \
            } \
            break; \
\
        case WTAP_BLOCK_IF_ID_AND_INFO: \
            /* \
             * Interface block - does this block type support comments? \
             */ \
            num_supported_options = obj->finfo.supported_blocks[i].num_supported_options; \
            supported_options = obj->finfo.supported_blocks[i].supported_options; \
            for (size_t j = 0; j < num_supported_options; i++) { \
                if (supported_options[i].opt == OPT_COMMENT) { \
                    if (supported_options[i].support != OPTION_NOT_SUPPORTED) \
                        supported_comment_types |= WTAP_COMMENT_PER_INTERFACE; \
                    break; \
                } \
            } \
            break; \
\
        case WTAP_BLOCK_PACKET: \
            /* \
             * Packet block - does this block type support comments? \
             */ \
            num_supported_options = obj->finfo.supported_blocks[i].num_supported_options; \
            supported_options = obj->finfo.supported_blocks[i].supported_options; \
            for (size_t j = 0; j < num_supported_options; i++) { \
                if (supported_options[i].opt == OPT_COMMENT) { \
                    if (supported_options[i].support != OPTION_NOT_SUPPORTED) \
                        supported_comment_types |= WTAP_COMMENT_PER_PACKET; \
                    break; \
                } \
            } \
            break; \
\
        default: \
            break;\
        } \
    } \
    lua_pushnumber(L, (lua_Number)supported_comment_types); \
});
WSLUA_ATTRIBUTE_SET(FileHandler,supported_comment_types, { \
    guint supported_comment_types; \
    size_t num_supported_options; \
    struct supported_option_type *supported_options; \
    if (!lua_isnumber(L,-1) ) \
        return luaL_error(L, "FileHandler's attribute`supported_comment_types' must be a number"); \
    supported_comment_types = wslua_toguint(L,-1); \
    /* \
     * Update support for comments in the relevant block types; the entries \
     * for comments in those types should be there. \
     */ \
    for (size_t i = 0; i < obj->finfo.num_supported_blocks; i++) { \
\
        /* \
         * Is this block type supported? \
         */ \
        if (obj->finfo.supported_blocks[i].support == BLOCK_NOT_SUPPORTED) { \
            /* \
             * No - skip it. \
             */ \
            continue; \
        } \
\
        /* \
         * Yes - what type of block is it? \
         */ \
        switch (obj->finfo.supported_blocks[i].type) { \
\
        case WTAP_BLOCK_SECTION: \
            /* \
             * Section block - update the comment support. \
             */ \
            num_supported_options = obj->finfo.supported_blocks[i].num_supported_options; \
            supported_options = safe_cast_away_option_type_const(obj->finfo.supported_blocks[i].supported_options); \
            for (size_t j = 0; j < num_supported_options; i++) { \
                if (supported_options[i].opt == OPT_COMMENT) { \
                    supported_options[i].support = \
                        (supported_comment_types &= WTAP_COMMENT_PER_SECTION) ? \
                            ONE_OPTION_SUPPORTED : OPTION_NOT_SUPPORTED ; \
                    break; \
                } \
            } \
            break; \
\
        case WTAP_BLOCK_IF_ID_AND_INFO: \
            /* \
             * Interface block - does this block type support comments? \
             */ \
            num_supported_options = obj->finfo.supported_blocks[i].num_supported_options; \
            supported_options = safe_cast_away_option_type_const(obj->finfo.supported_blocks[i].supported_options); \
            for (size_t j = 0; j < num_supported_options; i++) { \
                if (supported_options[i].opt == OPT_COMMENT) { \
                    supported_options[i].support = \
                        (supported_comment_types &= WTAP_COMMENT_PER_INTERFACE) ? \
                            ONE_OPTION_SUPPORTED : OPTION_NOT_SUPPORTED ; \
                    break; \
                } \
            } \
            break; \
\
        case WTAP_BLOCK_PACKET: \
            /* \
             * Packet block - does this block type support comments? \
             */ \
            num_supported_options = obj->finfo.supported_blocks[i].num_supported_options; \
            supported_options = safe_cast_away_option_type_const(obj->finfo.supported_blocks[i].supported_options); \
            for (size_t j = 0; j < num_supported_options; i++) { \
                if (supported_options[i].opt == OPT_COMMENT) { \
                    supported_options[i].support = \
                        (supported_comment_types &= WTAP_COMMENT_PER_PACKET) ? \
                            ONE_OPTION_SUPPORTED : OPTION_NOT_SUPPORTED ; \
                    break; \
                } \
            } \
            break; \
\
        default: \
            break;\
        } \
    } \
});

/* This table is ultimately registered as a sub-table of the class' metatable,
 * and if __index/__newindex is invoked then it calls the appropriate function
 * from this table for getting/setting the members.
 */
WSLUA_ATTRIBUTES FileHandler_attributes[] = {
    WSLUA_ATTRIBUTE_WOREG(FileHandler,read_open),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,read),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,seek_read),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,read_close),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,seq_read_close),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,can_write_encap),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,write_open),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,write),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,write_close),
    WSLUA_ATTRIBUTE_ROREG(FileHandler,type),
    WSLUA_ATTRIBUTE_RWREG(FileHandler,extensions),
    WSLUA_ATTRIBUTE_RWREG(FileHandler,writing_must_seek),
    WSLUA_ATTRIBUTE_RWREG(FileHandler,writes_name_resolution),
    WSLUA_ATTRIBUTE_RWREG(FileHandler,supported_comment_types),
    { NULL, NULL, NULL }
};

WSLUA_METHODS FileHandler_methods[] = {
    WSLUA_CLASS_FNREG(FileHandler,new),
    { NULL, NULL }
};

WSLUA_META FileHandler_meta[] = {
    WSLUA_CLASS_MTREG(FileHandler,tostring),
    { NULL, NULL }
};

int FileHandler_register(lua_State* L) {
    WSLUA_REGISTER_CLASS_WITH_ATTRS(FileHandler);
    return 0;
}

int wslua_deregister_filehandlers(lua_State* L _U_) {
    for (GSList *it = registered_file_handlers; it; it = it->next) {
        FileHandler fh = (FileHandler)it->data;
        wslua_deregister_filehandler_work(fh);

        for (size_t i = 0; i < fh->finfo.num_supported_blocks; i++) {
            g_free((struct supported_option_type *)fh->finfo.supported_blocks[i].supported_options);
        }
        g_free((struct supported_block_type  *)fh->finfo.supported_blocks);
        g_free((char *)fh->extensions);
        g_free((char *)fh->internal_description);
        g_free((char *)fh->finfo.description);
        g_free((char *)fh->finfo.name);
        g_free(fh->type);

        memset(fh, 0, sizeof(*fh));
        fh->removed = TRUE;
        proto_add_deregistered_data(fh);
    }
    g_slist_free(registered_file_handlers);
    registered_file_handlers = NULL;
    return 0;
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
