/* packet-user_encap.c
 * Allow users to specify the dissectors for DLTs
 * Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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

#include <stdio.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/wmem/wmem.h>
#include <wiretap/wtap.h>

#ifdef _MSC_VER
/* disable: warning C4090: 'XY' : different 'const' qualifiers */
#pragma warning(disable:4090)
#endif

void proto_register_user_encap(void);
void proto_reg_handoff_user_encap(void);

typedef struct _user_encap_t {
    guint encap;
    char* payload_proto_name;
    dissector_handle_t payload_proto;
    char* header_proto_name;
    dissector_handle_t header_proto;
    char* trailer_proto_name;
    dissector_handle_t trailer_proto;
    guint header_size;
    guint trailer_size;
} user_encap_t;

#define ENCAP0_STR "User 0 (DLT=147)"
static const value_string user_dlts[] = {
    { WTAP_ENCAP_USER0, ENCAP0_STR},
    { WTAP_ENCAP_USER1, "User 1 (DLT=148)"},
    { WTAP_ENCAP_USER2, "User 2 (DLT=149)"},
    { WTAP_ENCAP_USER3, "User 3 (DLT=150)"},
    { WTAP_ENCAP_USER4, "User 4 (DLT=151)"},
    { WTAP_ENCAP_USER5, "User 5 (DLT=152)"},
    { WTAP_ENCAP_USER6, "User 6 (DLT=153)"},
    { WTAP_ENCAP_USER7, "User 7 (DLT=154)"},
    { WTAP_ENCAP_USER8, "User 8 (DLT=155)"},
    { WTAP_ENCAP_USER9, "User 9 (DLT=156)"},
    { WTAP_ENCAP_USER10, "User 10 (DLT=157)"},
    { WTAP_ENCAP_USER11, "User 11 (DLT=158)"},
    { WTAP_ENCAP_USER12, "User 12 (DLT=159)"},
    { WTAP_ENCAP_USER13, "User 13 (DLT=160)"},
    { WTAP_ENCAP_USER14, "User 14 (DLT=161)"},
    { WTAP_ENCAP_USER15, "User 15 (DLT=162)"},
    { 0, NULL }
};
static int proto_user_encap = -1;

static expert_field ei_user_encap_not_handled = EI_INIT;

static user_encap_t* encaps = NULL;
static guint num_encaps = 0;
static uat_t* encaps_uat;
static dissector_handle_t data_handle;

/*
 * Use this for DLT_USER2 if we don't have an encapsulation for it.
 */
static user_encap_t user2_encap;

static void dissect_user(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree) {
    user_encap_t* encap = NULL;
    tvbuff_t* payload_tvb;
    proto_item* item;
    gint len, reported_len;
    guint i;

    for (i = 0; i < num_encaps; i++) {
        if (encaps[i].encap == pinfo->match_uint) {
            encap = &(encaps[i]);
            break;
        }
    }

    item = proto_tree_add_item(tree,proto_user_encap,tvb,0,-1,ENC_NA);
    if (!encap && pinfo->match_uint == WTAP_ENCAP_USER2) {
        /*
         * Special-case DLT_USER2 - Apple hijacked it for use as DLT_PKTAP.
         * The user hasn't assigned anything to it, so default it to
         * the PKTAP dissector.
         */
        encap = &user2_encap;
    }
    if (!encap) {
        char* msg = wmem_strdup_printf(wmem_packet_scope(),
                                     "User encapsulation not handled: DLT=%d, "
                                     "check your Preferences->Protocols->DLT_USER",
                         pinfo->match_uint + 147 - WTAP_ENCAP_USER0);
        proto_item_set_text(item,"%s",msg);
        expert_add_info_format(pinfo, item, &ei_user_encap_not_handled, "%s", msg);

        call_dissector(data_handle, tvb, pinfo, tree);
        return;
    }
    if (encap->payload_proto == NULL) {
        char* msg = wmem_strdup_printf(wmem_packet_scope(),
                                     "User encapsulation's protocol %s not found: "
                                     "DLT=%d, check your Preferences->Protocols->DLT_USER",
                                     encap->payload_proto_name,
                                     pinfo->match_uint + 147 - WTAP_ENCAP_USER0);
        proto_item_set_text(item,"%s",msg);
        expert_add_info_format(pinfo, item, &ei_user_encap_not_handled, "%s", msg);

        call_dissector(data_handle, tvb, pinfo, tree);
        return;
    }

    proto_item_set_text(item,"DLT: %d",pinfo->match_uint + 147 - WTAP_ENCAP_USER0);

    if (encap->header_size) {
        tvbuff_t* hdr_tvb = tvb_new_subset_length(tvb, 0, encap->header_size);
        call_dissector(encap->header_proto, hdr_tvb, pinfo, tree);
        if (encap->header_proto_name) {
            const char *proto_name = dissector_handle_get_long_name(find_dissector(encap->header_proto_name));
            if (proto_name) {
                proto_item_append_text(item, ", Header: %s (%s)", encap->header_proto_name, proto_name);
            }
        }
    }

    len = tvb_length(tvb) - (encap->header_size + encap->trailer_size);
    reported_len = tvb_reported_length(tvb) - (encap->header_size + encap->trailer_size);

    payload_tvb = tvb_new_subset(tvb, encap->header_size, len, reported_len);
    call_dissector(encap->payload_proto, payload_tvb, pinfo, tree);
    if (encap->payload_proto_name) {
        const char *proto_name = dissector_handle_get_long_name(find_dissector(encap->payload_proto_name));
        if (proto_name) {
            proto_item_append_text(item, ", Payload: %s (%s)", encap->payload_proto_name, proto_name);
        }
    }

    if (encap->trailer_size) {
        tvbuff_t* trailer_tvb = tvb_new_subset_length(tvb, encap->header_size + len, encap->trailer_size);
        call_dissector(encap->trailer_proto, trailer_tvb, pinfo, tree);
        if (encap->trailer_proto_name) {
            const char *proto_name = dissector_handle_get_long_name(find_dissector(encap->trailer_proto_name));
            if (proto_name) {
                proto_item_append_text(item, ", Trailer: %s (%s)", encap->trailer_proto_name, proto_name);
            }
        }
    }
}

static void* user_copy_cb(void* dest, const void* orig, size_t len _U_)
{
    const user_encap_t *o = (const user_encap_t *)orig;
    user_encap_t *d = (user_encap_t *)dest;

    d->payload_proto_name = g_strdup(o->payload_proto_name);
    d->header_proto_name  = g_strdup(o->header_proto_name);
    d->trailer_proto_name = g_strdup(o->trailer_proto_name);

    return d;
}

static void user_free_cb(void* record)
{
    user_encap_t *u = (user_encap_t *)record;

    g_free(u->payload_proto_name);
    g_free(u->header_proto_name);
    g_free(u->trailer_proto_name);
}

UAT_VS_DEF(user_encap, encap, user_encap_t, guint, WTAP_ENCAP_USER0, ENCAP0_STR)
UAT_PROTO_DEF(user_encap, payload_proto, payload_proto, payload_proto_name, user_encap_t)
UAT_DEC_CB_DEF(user_encap, header_size, user_encap_t)
UAT_DEC_CB_DEF(user_encap, trailer_size, user_encap_t)
UAT_PROTO_DEF(user_encap, header_proto, header_proto, header_proto_name, user_encap_t)
UAT_PROTO_DEF(user_encap, trailer_proto, trailer_proto, trailer_proto_name, user_encap_t)

void proto_reg_handoff_user_encap(void)
{
    dissector_handle_t user_encap_handle;
    guint i;

    user_encap_handle = find_dissector("user_dlt");
    data_handle = find_dissector("data");

    user2_encap.encap = WTAP_ENCAP_USER2;
    user2_encap.payload_proto_name = g_strdup("pktap");
    user2_encap.payload_proto = find_dissector("pktap");
    user2_encap.header_proto_name = g_strdup("");
    user2_encap.header_proto = NULL;
    user2_encap.trailer_proto_name = g_strdup("");
    user2_encap.trailer_proto = NULL;
    user2_encap.header_size = 0;
    user2_encap.trailer_size = 0;

    for (i = WTAP_ENCAP_USER0 ; i <= WTAP_ENCAP_USER15; i++)
        dissector_add_uint("wtap_encap", i, user_encap_handle);

}


void proto_register_user_encap(void)
{
    module_t *module;
    expert_module_t* expert_user_encap;

    static uat_field_t user_flds[] = {
        UAT_FLD_VS(user_encap,encap,"DLT",user_dlts,"The DLT"),
        UAT_FLD_PROTO(user_encap,payload_proto,"Payload protocol",
                      "Protocol to be used for the payload of this DLT"),
        UAT_FLD_DEC(user_encap,header_size,"Header size",
                    "Size of an eventual header that precedes the actual payload, 0 means none"),
        UAT_FLD_PROTO(user_encap,header_proto,"Header protocol",
                      "Protocol to be used for the header (empty = data)"),
        UAT_FLD_DEC(user_encap,trailer_size,"Trailer size",
                    "Size of an eventual trailer that follows the actual payload, 0 means none"),
        UAT_FLD_PROTO(user_encap,trailer_proto,"Trailer protocol",
                      "Protocol to be used for the trailer (empty = data)"),
        UAT_END_FIELDS
    };

    static ei_register_info ei[] = {
        { &ei_user_encap_not_handled, { "user_dlt.not_handled", PI_UNDECODED, PI_WARN, "Formatted text", EXPFILL }},
    };

    proto_user_encap = proto_register_protocol("DLT User","DLT_USER","user_dlt");
    expert_user_encap = expert_register_protocol(proto_user_encap);
    expert_register_field_array(expert_user_encap, ei, array_length(ei));

    module = prefs_register_protocol(proto_user_encap, NULL);

    encaps_uat = uat_new("User DLTs Table",
                         sizeof(user_encap_t),
                         "user_dlts",
                         TRUE,
                         &encaps,
                         &num_encaps,
                         UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
                         "ChUserDLTsSection",
                         user_copy_cb,
                         NULL,
                         user_free_cb,
                         NULL,
                         user_flds );

    prefs_register_uat_preference(module,
                      "encaps_table",
                      "Encapsulations Table",
                      "A table that enumerates the various protocols to be used against a certain user DLT",
                      encaps_uat);


    register_dissector("user_dlt",dissect_user,proto_user_encap);

    /*
    prefs_register_protocol_obsolete(proto_register_protocol("DLT User A","DLT_USER_A","user_dlt_a"));
    prefs_register_protocol_obsolete(proto_register_protocol("DLT User B","DLT_USER_B","user_dlt_b"));
    prefs_register_protocol_obsolete(proto_register_protocol("DLT User C","DLT_USER_C","user_dlt_c"));
    prefs_register_protocol_obsolete(proto_register_protocol("DLT User D","DLT_USER_D","user_dlt_d"));
    */
}
