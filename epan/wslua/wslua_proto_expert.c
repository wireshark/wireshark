/*
 * wslua_proto_expert.c
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


/* WSLUA_CONTINUE_MODULE Proto */


WSLUA_CLASS_DEFINE(ProtoExpert,FAIL_ON_NULL("null ProtoExpert"));
    /* A Protocol expert info field, to be used when adding items to the dissection tree.

       @since 1.11.3
     */

WSLUA_CONSTRUCTOR ProtoExpert_new(lua_State* L) {
    /* Creates a new `ProtoExpert` object to be used for a protocol's expert information notices.

       @since 1.11.3
     */
#define WSLUA_ARG_ProtoExpert_new_ABBR 1 /* Filter name of the expert info field (the string that
                                            is used in filters). */
#define WSLUA_ARG_ProtoExpert_new_TEXT 2 /* The default text of the expert field. */
#define WSLUA_ARG_ProtoExpert_new_GROUP 3 /* Expert group type: one of: `expert.group.CHECKSUM`,
                                             `expert.group.SEQUENCE`, `expert.group.RESPONSE_CODE`,
                                             `expert.group.REQUEST_CODE`, `expert.group.UNDECODED`,
                                             `expert.group.REASSEMBLE`, `expert.group.MALFORMED`,
                                             `expert.group.DEBUG`, `expert.group.PROTOCOL`,
                                             `expert.group.SECURITY`, `expert.group.COMMENTS_GROUP`
                                             or `expert.group.DECRYPTION`. */
#define WSLUA_ARG_ProtoExpert_new_SEVERITY 4 /* Expert severity type: one of:
                                                `expert.severity.COMMENT`, `expert.severity.CHAT`,
                                                `expert.severity.NOTE`, `expert.severity.WARN`,
                                                or `expert.severity.ERROR`. */

    ProtoExpert pe    = NULL;
    const gchar* abbr = wslua_checkstring_only(L,WSLUA_ARG_ProtoExpert_new_ABBR);
    const gchar* text = wslua_checkstring_only(L,WSLUA_ARG_ProtoExpert_new_TEXT);
    int group         = (int)luaL_checkinteger(L, WSLUA_ARG_ProtoExpert_new_GROUP);
    int severity      = (int)luaL_checkinteger(L, WSLUA_ARG_ProtoExpert_new_SEVERITY);

    if (!abbr[0]) {
        luaL_argerror(L, WSLUA_ARG_ProtoExpert_new_ABBR, "Empty field name abbrev");
        return 0;
    }

    if (proto_check_field_name(abbr)) {
        luaL_argerror(L, WSLUA_ARG_ProtoExpert_new_ABBR, "Invalid char in abbrev");
        return 0;
    }

    if (proto_registrar_get_byname(abbr)) {
        luaL_argerror(L, WSLUA_ARG_ProtoExpert_new_ABBR, "This abbrev already exists");
        return 0;
    }

    switch (group) {
    case PI_CHECKSUM:
    case PI_SEQUENCE:
    case PI_RESPONSE_CODE:
    case PI_REQUEST_CODE:
    case PI_UNDECODED:
    case PI_REASSEMBLE:
    case PI_MALFORMED:
    case PI_DEBUG:
    case PI_PROTOCOL:
    case PI_SECURITY:
    case PI_COMMENTS_GROUP:
    case PI_DECRYPTION:
        break;
    default:
        luaL_argerror(L, WSLUA_ARG_ProtoExpert_new_GROUP, "Group must be one of expert.group.*");
        return 0;
    }

    switch (severity) {
    case PI_COMMENT:
    case PI_CHAT:
    case PI_NOTE:
    case PI_WARN:
    case PI_ERROR:
        break;
    default:
        luaL_argerror(L, WSLUA_ARG_ProtoExpert_new_SEVERITY, "Severity must be one of expert.severity.*");
        return 0;
    }

    pe = g_new(wslua_expert_field_t,1);

    pe->ids.ei   = EI_INIT_EI;
    pe->ids.hf   = EI_INIT_HF;
    pe->abbrev   = g_strdup(abbr);
    pe->text     = g_strdup(text);
    pe->group    = group;
    pe->severity = severity;

    pushProtoExpert(L,pe);

    WSLUA_RETURN(1); /* The newly created `ProtoExpert` object. */
}

WSLUA_METAMETHOD ProtoExpert__tostring(lua_State* L) {
    /* Returns a string with debugging information about a `ProtoExpert` object.

       @since 1.11.3
     */
    ProtoExpert pe = toProtoExpert(L,1);

    if (!pe) {
        lua_pushstring(L,"ProtoExpert pointer is NULL!");
    } else {
        lua_pushfstring(L, "ProtoExpert: ei=%d, hf=%d, abbr=%s, text=%s, group=%d, severity=%d",
                        pe->ids.ei, pe->ids.hf, pe->abbrev, pe->text, pe->group, pe->severity);
    }
    return 1;
}

static int ProtoExpert__gc(lua_State* L) {
    ProtoExpert pe = toProtoExpert(L,1);

    if (pe->ids.hf == -2) {
        /* Only free unregistered and deregistered ProtoExpert */
        g_free(pe);
    }

    return 0;
}

WSLUA_METHODS ProtoExpert_methods[] = {
    WSLUA_CLASS_FNREG(ProtoExpert,new),
    { NULL, NULL }
};

WSLUA_META ProtoExpert_meta[] = {
    WSLUA_CLASS_MTREG(ProtoExpert,tostring),
    { NULL, NULL }
};

int ProtoExpert_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(ProtoExpert);
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
