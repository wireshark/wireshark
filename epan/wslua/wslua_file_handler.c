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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "wslua_file_common.h"


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


/* During file routines, we cannot allow the FileHandler to get de-registered, since
   that would change the GArray's in file_access.c and hilarity would ensue. So we
   set this to true right before pcall(), and back to false afterwards */
static gboolean in_routine = FALSE;

/* This does the verification and setup common to all open/read/seek_read/close routines */
#define INIT_FILEHANDLER_ROUTINE(name,retval) \
    if (!fh) { \
        g_warning("Error in file %s: no Lua FileHandler object", #name); \
        return retval; \
    } \
    if (!fh->registered) { \
        g_warning("Error in file %s: Lua FileHandler is not registered", #name); \
        return retval; \
    } \
    if (!fh->L) { \
        g_warning("Error in file %s: no FileHandler Lua state", #name); \
        return retval; \
    } \
    if (fh->name##_ref == LUA_NOREF) { \
        g_warning("Error in file %s: no FileHandler %s routine reference", #name, #name); \
        return retval; \
    } \
    L = fh->L; \
    lua_settop(L,0); \
    push_error_handler(L, #name " routine"); \
    lua_rawgeti(L, LUA_REGISTRYINDEX, fh->name##_ref); \
    if (!lua_isfunction(L, -1)) { \
         g_warning("Error in file %s: no FileHandler %s routine function in Lua", #name, #name); \
        return retval; \
    } \
    /* now guard against de-registering during pcall() */ \
    in_routine = TRUE;

#define END_FILEHANDLER_ROUTINE() \
    /* now allow de-registering again */ \
    in_routine = TRUE;


/* LUA_ERRGCMM is in Lua 5.2 only - making it 9 disables it */
#ifndef LUA_ERRGCMM
#define LUA_ERRGCMM 9
#endif

#define CASE_ERROR(name) \
    case LUA_ERRRUN: \
        g_warning("Run-time error while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRMEM: \
        g_warning("Memory alloc error while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRERR: \
        g_warning("Error in error handling while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRGCMM: \
        g_warning("Error in garbage collector while calling FileHandler %s routine", name); \
        break; \
    default: \
        g_assert_not_reached(); \
        break;

#define CASE_ERROR_ERRINFO(name) \
    case LUA_ERRRUN: \
        g_warning("Run-time error while calling FileHandler %s routine", name); \
        *err_info = g_strdup_printf("Run-time error while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRMEM: \
        g_warning("Memory alloc error while calling FileHandler %s routine", name); \
        *err_info = g_strdup_printf("Memory alloc error while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRERR: \
        g_warning("Error in error handling while calling FileHandler %s routine", name); \
        *err_info = g_strdup_printf("Error in error handling while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRGCMM: \
        g_warning("Error in garbage collector while calling FileHandler %s routine", name); \
        *err_info = g_strdup_printf("Error in garbage collector while calling FileHandler %s routine", name); \
        break; \
    default: \
        g_assert_not_reached(); \
        break;


/* some declarations */
static gboolean
wslua_filehandler_read(wtap *wth, int *err, gchar **err_info,
                      gint64 *data_offset);
static gboolean
wslua_filehandler_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf,
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

    INIT_FILEHANDLER_ROUTINE(read_open,WTAP_OPEN_NOT_MINE);

    create_wth_priv(L, wth);

    fp = push_File(L, wth->fh);
    fc = push_CaptureInfo(L, wth, TRUE);

    errno = WTAP_ERR_CANT_OPEN;
    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            retval = (wtap_open_return_val)wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR_ERRINFO("read_open")
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
            g_warning("Lua file format module lacks a read routine");
            return WTAP_OPEN_NOT_MINE;
        }

        if (fh->seek_read_ref != LUA_NOREF) {
            wth->subtype_seek_read = wslua_filehandler_seek_read;
        }
        else {
            g_warning("Lua file format module lacks a seek-read routine");
            return WTAP_OPEN_NOT_MINE;
        }

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
        g_warning("FileHandler read_open routine returned %d", retval);
        if (err) {
            *err = WTAP_ERR_INTERNAL;
        }
        retval = WTAP_OPEN_ERROR;
    }

    lua_settop(L,0);
    return retval;
}

/* The classic wtap read routine.  This returns TRUE if it found the next packet,
 * else FALSE.
 * If it finds a frame/packet, it should set the pseudo-header info (ie, let Lua set it).
 * Also Lua needs to set data_offset to the beginning of the line we're returning.
 * This will be the seek_off parameter when this frame is re-read.
*/
static gboolean
wslua_filehandler_read(wtap *wth, int *err, gchar **err_info,
                      gint64 *data_offset)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);
    int retval = -1;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfo *fc = NULL;
    FrameInfo *fi = NULL;

    INIT_FILEHANDLER_ROUTINE(read,FALSE);

    /* Reset errno */
    if (err) {
        *err = errno = 0;
    }

    wth->phdr.opt_comment = NULL;

    fp = push_File(L, wth->fh);
    fc = push_CaptureInfo(L, wth, FALSE);
    fi = push_FrameInfo(L, &wth->phdr, wth->frame_buffer);

    switch ( lua_pcall(L,3,1,1) ) {
        case 0:
            if (lua_isnumber(L,-1)) {
                *data_offset = wslua_togint64(L, -1);
                retval = 1;
                break;
            }
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR_ERRINFO("read")
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;
    (*fi)->expired = TRUE;
    lua_settop(L,0);

    return (retval == 1);
}

/* Classic wtap seek_read function, called by wtap core.  This must return TRUE on
 * success, FALSE on error.
 */
static gboolean
wslua_filehandler_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf,
    int *err, gchar **err_info)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);
    int retval = -1;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfo *fc = NULL;
    FrameInfo *fi = NULL;

    INIT_FILEHANDLER_ROUTINE(seek_read,FALSE);

    /* Reset errno */
    if (err) {
        *err = errno = 0;
    }
    phdr->opt_comment = NULL;

    fp = push_File(L, wth->random_fh);
    fc = push_CaptureInfo(L, wth, FALSE);
    fi = push_FrameInfo(L, phdr, buf);
    lua_pushnumber(L, (lua_Number)seek_off);

    switch ( lua_pcall(L,4,1,1) ) {
        case 0:
            if (lua_isstring(L,-1)) {
                size_t len = 0;
                const gchar* fd = lua_tolstring(L, -1, &len);
                if (len < WTAP_MAX_PACKET_SIZE)
                    memcpy(ws_buffer_start_ptr(buf), fd, len);
                retval = 1;
                break;
            }
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR_ERRINFO("seek_read")
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;
    (*fi)->expired = TRUE;
    lua_settop(L,0);

    return (retval == 1);
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

    INIT_FILEHANDLER_ROUTINE(read_close,);

    fp = push_File(L, wth->fh);
    fc = push_CaptureInfo(L, wth, FALSE);

    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            break;
        CASE_ERROR("read_close")
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

    INIT_FILEHANDLER_ROUTINE(seq_read_close,);

    fp = push_File(L, wth->fh);
    fc = push_CaptureInfo(L, wth, FALSE);

    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            break;
        CASE_ERROR("seq_read_close")
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

    INIT_FILEHANDLER_ROUTINE(can_write_encap,WTAP_ERR_INTERNAL);

    lua_pushnumber(L, encap);

    switch ( lua_pcall(L,1,1,1) ) {
        case 0:
            retval = wslua_optboolint(L,-1,WTAP_ERR_UNWRITABLE_ENCAP);
            break;
        CASE_ERROR("can_write_encap")
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
wslua_filehandler_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
                      const guint8 *pd, int *err, gchar **err_info);
static gboolean
wslua_filehandler_dump_finish(wtap_dumper *wdh, int *err);


/* The classic wtap dump_open function.
 * This returns 1 (TRUE) on success.
 */
static int
wslua_filehandler_dump_open(wtap_dumper *wdh, int *err)
{
    FileHandler fh = (FileHandler)(wdh->wslua_data);
    int retval = 0;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfoConst *fc = NULL;

    INIT_FILEHANDLER_ROUTINE(write_open,0);

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
        CASE_ERROR("write_open")
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
            g_warning("FileHandler was not set with a write function, even though write_open() returned true");
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
wslua_filehandler_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
                      const guint8 *pd, int *err, gchar **err_info _U_)
{
    FileHandler fh = (FileHandler)(wdh->wslua_data);
    int retval = -1;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfoConst *fc = NULL;
    FrameInfoConst *fi = NULL;

    INIT_FILEHANDLER_ROUTINE(write,FALSE);

    /* Reset errno */
    if (err) {
        *err = errno = 0;
    }

    fp = push_Wdh(L, wdh);
    fc = push_CaptureInfoConst(L,wdh);
    fi = push_FrameInfoConst(L, phdr, pd);

    errno = WTAP_ERR_CANT_WRITE;
    switch ( lua_pcall(L,3,1,1) ) {
        case 0:
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR("write")
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
wslua_filehandler_dump_finish(wtap_dumper *wdh, int *err)
{
    FileHandler fh = (FileHandler)(wdh->wslua_data);
    int retval = -1;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfoConst *fc = NULL;

    INIT_FILEHANDLER_ROUTINE(write_close,FALSE);

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
        CASE_ERROR("write_close")
    }

    END_FILEHANDLER_ROUTINE();

    remove_wdh_priv(L, wdh);

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;

    return (retval == 1);
}


WSLUA_CONSTRUCTOR FileHandler_new(lua_State* L) {
    /* Creates a new FileHandler */
#define WSLUA_ARG_FileHandler_new_NAME 1 /* The name of the file type, for display purposes only. E.g., "Wireshark - pcapng" */
#define WSLUA_ARG_FileHandler_new_SHORTNAME 2 /* the file type short name, used as a shortcut in various places. E.g., "pcapng". Note: the name cannot already be in use. */
#define WSLUA_ARG_FileHandler_new_DESCRIPTION 3 /* Descriptive text about this file format, for display purposes only */
#define WSLUA_ARG_FileHandler_new_TYPE 4 /* The type of FileHandler, "r"/"w"/"rw" for reader/writer/both, include "m" for magic, "s" for strong heuristic */

    const gchar* name = luaL_checkstring(L,WSLUA_ARG_FileHandler_new_NAME);
    const gchar* short_name = luaL_checkstring(L,WSLUA_ARG_FileHandler_new_SHORTNAME);
    const gchar* desc = luaL_checkstring(L,WSLUA_ARG_FileHandler_new_DESCRIPTION);
    const gchar* type = luaL_checkstring(L,WSLUA_ARG_FileHandler_new_TYPE);
    FileHandler fh = (FileHandler) g_malloc0(sizeof(struct _wslua_filehandler));

    fh->is_reader = (strchr(type,'r') != NULL) ? TRUE : FALSE;
    fh->is_writer = (strchr(type,'w') != NULL) ? TRUE : FALSE;

    if (fh->is_reader && wtap_has_open_info(short_name)) {
        return luaL_error(L, "FileHandler.new: '%s' short name already exists for a reader!", short_name);
    }

    if (fh->is_writer && wtap_short_string_to_file_type_subtype(short_name) > -1) {
        return luaL_error(L, "FileHandler.new: '%s' short name already exists for a writer!", short_name);
    }

    fh->type = g_strdup(type);
    fh->finfo.name = g_strdup(name);
    fh->finfo.short_name = g_strdup(short_name);
    fh->finfo.default_file_extension = NULL;
    fh->finfo.additional_file_extensions = NULL;
    fh->finfo.writing_must_seek = FALSE;
    fh->finfo.has_name_resolution = FALSE;
    fh->finfo.can_write_encap = NULL;
    fh->finfo.dump_open = NULL;
    /* this will be set to a new file_type when registered */
    fh->file_type = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;

    fh->description = g_strdup(desc);
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
        lua_pushfstring(L, "FileHandler(%s): short-name='%s', description='%s', read_open=%d, read=%d, write=%d",
            fh->finfo.name, fh->finfo.short_name, fh->description, fh->read_open_ref, fh->read_ref, fh->write_ref);
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
              fh->read_ref      != LUA_NOREF &&
              fh->seek_read_ref != LUA_NOREF)) &&
            (!fh->is_writer ||
             (fh->is_writer &&
              fh->can_write_encap_ref != LUA_NOREF &&
              fh->write_open_ref      != LUA_NOREF &&
              fh->write_ref           != LUA_NOREF)) );
}


WSLUA_FUNCTION wslua_register_filehandler(lua_State* L) {
    /* Register the FileHandler into Wireshark/tshark, so they can read/write this new format.
       All functions and settings must be complete before calling this registration function.
       This function cannot be called inside the reading/writing callback functions. */
#define WSLUA_ARG_register_filehandler_FILEHANDLER 1 /* the FileHandler object to be registered */
    FileHandler fh = checkFileHandler(L,WSLUA_ARG_register_filehandler_FILEHANDLER);

    if (in_routine)
        return luaL_error(L,"a FileHAndler cannot be registered during reading/writing callback functions");

    if (fh->registered)
        return luaL_error(L,"this FileHandler is already registered");

    if (!verify_filehandler_complete(fh))
        return luaL_error(L,"this FileHandler is not complete enough to register");

    if (fh->is_writer) {
        fh->finfo.can_write_encap = wslua_dummy_can_write_encap;
        fh->finfo.wslua_info = (wtap_wslua_file_info_t*) g_malloc0(sizeof(wtap_wslua_file_info_t));
        fh->finfo.wslua_info->wslua_can_write_encap = wslua_filehandler_can_write_encap;
        fh->finfo.wslua_info->wslua_data = (void*)(fh);
        fh->finfo.dump_open = wslua_filehandler_dump_open;
    }

    fh->file_type = wtap_register_file_type_subtypes(&(fh->finfo),fh->file_type);

    if (fh->is_reader) {
        struct open_info oi = { NULL, OPEN_INFO_HEURISTIC, NULL, NULL, NULL, NULL };
        oi.name = fh->finfo.short_name;
        oi.open_routine = wslua_filehandler_open;
        oi.extensions = fh->finfo.additional_file_extensions;
        oi.wslua_data = (void*)(fh);
        if (strchr(fh->type,'m') != NULL) {
            oi.type = OPEN_INFO_MAGIC;
        } else {
            oi.type = OPEN_INFO_HEURISTIC;
        }
        wtap_register_open_info(&oi, (strchr(fh->type,'s') != NULL));
    }

    fh->registered = TRUE;

    lua_pushnumber(L, fh->file_type);

    WSLUA_RETURN(1); /* the new type number for this file reader/write */
}

WSLUA_FUNCTION wslua_deregister_filehandler(lua_State* L) {
    /* De-register the FileHandler from Wireshark/tshark, so it no longer gets used for reading/writing/display.
       This function cannot be called inside the reading/writing callback functions. */
#define WSLUA_ARG_register_filehandler_FILEHANDLER 1 /* the FileHandler object to be de-registered */
    FileHandler fh = checkFileHandler(L,WSLUA_ARG_register_filehandler_FILEHANDLER);

    if (in_routine)
        return luaL_error(L,"A FileHAndler cannot be de-registered during reading/writing callback functions");

    if (!fh->registered)
        return 0;

    /* undo writing stuff, even if it wasn't a writer */
    fh->finfo.can_write_encap = NULL;
    if (fh->finfo.wslua_info) {
        fh->finfo.wslua_info->wslua_can_write_encap = NULL;
        fh->finfo.wslua_info->wslua_data = NULL;
        g_free(fh->finfo.wslua_info);
        fh->finfo.wslua_info = NULL;
    }
    fh->finfo.dump_open = NULL;

    if (fh->file_type != WTAP_FILE_TYPE_SUBTYPE_UNKNOWN)
        wtap_deregister_file_type_subtype(fh->file_type);

    if (fh->is_reader && wtap_has_open_info(fh->finfo.short_name)) {
        wtap_deregister_open_info(fh->finfo.short_name);
    }

    fh->registered = FALSE;

    return 0;
}

/* The folllowing macros generate setter functions for Lua, for the following Lua
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
    packet into the frame buffer using `FrameInfo.data = foo` or `FrameInfo:read_data()`.

    The called Lua function should return the file offset/position number where the packet begins, or false if it hit an
    error.  The file offset will be saved by Wireshark and passed into the set `seek_read()` Lua function later. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,read);

/* WSLUA_ATTRIBUTE FileHandler_seek_read WO The Lua function to be called when Wireshark wants to read a packet from the file at the given offset.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfo` object
        3. A `FrameInfo` object
        4. The file offset number previously set by the `read()` function call
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

/* WSLUA_ATTRIBUTE FileHandler_extensions RW One or more file extensions that this file type usually uses.

    For readers using heuristics to determine file type, Wireshark will try the readers of the file's
    extension first, before trying other readers.  But ultimately Wireshark tries all file readers
    for any file extension, until it finds one that accepts the file. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(FileHandler,extensions,finfo.additional_file_extensions);
WSLUA_ATTRIBUTE_NAMED_STRING_SETTER(FileHandler,extensions,finfo.additional_file_extensions,TRUE);

/* WSLUA_ATTRIBUTE FileHandler_writing_must_seek RW true if the ability to seek is required when writing
    this file format, else false.

    This will be checked by Wireshark when writing out to compressed
    file formats, because seeking is not possible with compressed files. Usually a file writer only
    needs to be able to seek if it needs to go back in the file to change something, such as a block or
    file length value earlier in the file. */
WSLUA_ATTRIBUTE_NAMED_BOOLEAN_GETTER(FileHandler,writing_must_seek,finfo.writing_must_seek);
WSLUA_ATTRIBUTE_NAMED_BOOLEAN_SETTER(FileHandler,writing_must_seek,finfo.writing_must_seek);

/* WSLUA_ATTRIBUTE FileHandler_writes_name_resolution RW true if the file format supports name resolution
    records, else false. */
WSLUA_ATTRIBUTE_NAMED_BOOLEAN_GETTER(FileHandler,writes_name_resolution,finfo.has_name_resolution);
WSLUA_ATTRIBUTE_NAMED_BOOLEAN_SETTER(FileHandler,writes_name_resolution,finfo.has_name_resolution);

/* WSLUA_ATTRIBUTE FileHandler_supported_comment_types RW set to the bit-wise OR'ed number representing
    the type of comments the file writer supports writing, based on the numbers in the `wtap_comments` table. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FileHandler,supported_comment_types,finfo.supported_comment_types);
WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(FileHandler,supported_comment_types,finfo.supported_comment_types,guint32);

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
    WSLUA_REGISTER_CLASS(FileHandler);
    WSLUA_REGISTER_ATTRIBUTES(FileHandler);
    return 0;
}

int wslua_deregister_filehandlers(lua_State* L _U_) {
    /* TODO: Implement */
    return 0;
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
