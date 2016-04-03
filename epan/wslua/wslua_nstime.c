/*
 * wslua_nstime.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
 * (c) 2011, Stig Bjorlykke <stig@bjorlykke.org>
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

#include "config.h"

#include "wslua.h"


/* WSLUA_CONTINUE_MODULE Pinfo */


WSLUA_CLASS_DEFINE(NSTime,FAIL_ON_NULL("NSTime"));
/* NSTime represents a nstime_t.  This is an object with seconds and nanoseconds. */

WSLUA_CONSTRUCTOR NSTime_new(lua_State *L) {
    /* Creates a new NSTime object. */
#define WSLUA_OPTARG_NSTime_new_SECONDS 1 /* Seconds. */
#define WSLUA_OPTARG_NSTime_new_NSECONDS 2 /* Nano seconds. */
    NSTime nstime = (NSTime)g_malloc(sizeof(nstime_t));

    if (!nstime) return 0;

    nstime->secs = (time_t) luaL_optinteger(L,WSLUA_OPTARG_NSTime_new_SECONDS,0);
    nstime->nsecs = (int) luaL_optinteger(L,WSLUA_OPTARG_NSTime_new_NSECONDS,0);

    pushNSTime(L,nstime);

    WSLUA_RETURN(1); /* The new NSTime object. */
}

WSLUA_METAMETHOD NSTime__call(lua_State* L) { /* Creates a NSTime object. */
#define WSLUA_OPTARG_NSTime__call_SECONDS 1 /* Seconds. */
#define WSLUA_OPTARG_NSTime__call_NSECONDS 2 /* Nanoseconds. */
    lua_remove(L,1); /* remove the table */
    WSLUA_RETURN(NSTime_new(L)); /* The new NSTime object. */
}

WSLUA_METAMETHOD NSTime__tostring(lua_State* L) {
    NSTime nstime = checkNSTime(L,1);
    gchar *str;

    str = wmem_strdup_printf(NULL, "%ld.%09d", (long)nstime->secs, nstime->nsecs);
    lua_pushstring(L, str);
    wmem_free(NULL, str);

    WSLUA_RETURN(1); /* The string representing the nstime. */
}
WSLUA_METAMETHOD NSTime__add(lua_State* L) { /* Calculates the sum of two NSTimes. */
    NSTime time1 = checkNSTime(L,1);
    NSTime time2 = checkNSTime(L,2);
    NSTime time3 = (NSTime)g_malloc (sizeof (nstime_t));

    nstime_sum (time3, time1, time2);
    pushNSTime (L, time3);

    return 1;
}

WSLUA_METAMETHOD NSTime__sub(lua_State* L) { /* Calculates the diff of two NSTimes. */
    NSTime time1 = checkNSTime(L,1);
    NSTime time2 = checkNSTime(L,2);
    NSTime time3 = (NSTime)g_malloc (sizeof (nstime_t));

    nstime_delta (time3, time1, time2);
    pushNSTime (L, time3);

    return 1;
}

WSLUA_METAMETHOD NSTime__unm(lua_State* L) { /* Calculates the negative NSTime. */
    NSTime time1 = checkNSTime(L,1);
    NSTime time2 = (NSTime)g_malloc (sizeof (nstime_t));

    nstime_set_zero (time2);
    nstime_subtract (time2, time1);
    pushNSTime (L, time2);

    return 1;
}

WSLUA_METAMETHOD NSTime__eq(lua_State* L) { /* Compares two NSTimes. */
    NSTime time1 = checkNSTime(L,1);
    NSTime time2 = checkNSTime(L,2);
    gboolean result = FALSE;

    if (nstime_cmp(time1, time2) == 0)
        result = TRUE;

    lua_pushboolean(L,result);

    return 1;
}

WSLUA_METAMETHOD NSTime__le(lua_State* L) { /* Compares two NSTimes. */
    NSTime time1 = checkNSTime(L,1);
    NSTime time2 = checkNSTime(L,2);
    gboolean result = FALSE;

    if (nstime_cmp(time1, time2) <= 0)
        result = TRUE;

    lua_pushboolean(L,result);

    return 1;
}

WSLUA_METAMETHOD NSTime__lt(lua_State* L) { /* Compares two NSTimes. */
    NSTime time1 = checkNSTime(L,1);
    NSTime time2 = checkNSTime(L,2);
    gboolean result = FALSE;

    if (nstime_cmp(time1, time2) < 0)
        result = TRUE;

    lua_pushboolean(L,result);

    return 1;
}


/* WSLUA_ATTRIBUTE NSTime_secs RW The NSTime seconds. */
WSLUA_ATTRIBUTE_NUMBER_GETTER(NSTime,secs);
WSLUA_ATTRIBUTE_NUMBER_SETTER(NSTime,secs,time_t);

/* WSLUA_ATTRIBUTE NSTime_nsecs RW The NSTime nano seconds. */
WSLUA_ATTRIBUTE_NUMBER_GETTER(NSTime,nsecs);
WSLUA_ATTRIBUTE_NUMBER_SETTER(NSTime,nsecs,int);

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int NSTime__gc(lua_State* L) {
    NSTime nstime = toNSTime(L,1);

    if (!nstime) return 0;

    g_free (nstime);
    return 0;
}

/* This table is ultimately registered as a sub-table of the class' metatable,
 * and if __index/__newindex is invoked then it calls the appropriate function
 * from this table for getting/setting the members.
 */
WSLUA_ATTRIBUTES NSTime_attributes[] = {
    WSLUA_ATTRIBUTE_RWREG(NSTime,secs),
    WSLUA_ATTRIBUTE_RWREG(NSTime,nsecs),
    { NULL, NULL, NULL }
};

WSLUA_METHODS NSTime_methods[] = {
    WSLUA_CLASS_FNREG(NSTime,new),
    { NULL, NULL }
};

WSLUA_META NSTime_meta[] = {
    WSLUA_CLASS_MTREG(NSTime,tostring),
    WSLUA_CLASS_MTREG(NSTime,add),
    WSLUA_CLASS_MTREG(NSTime,sub),
    WSLUA_CLASS_MTREG(NSTime,unm),
    WSLUA_CLASS_MTREG(NSTime,eq),
    WSLUA_CLASS_MTREG(NSTime,le),
    WSLUA_CLASS_MTREG(NSTime,lt),
    WSLUA_CLASS_MTREG(NSTime,call),
   { NULL, NULL }
};

int NSTime_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(NSTime);
    WSLUA_REGISTER_ATTRIBUTES(NSTime);
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
