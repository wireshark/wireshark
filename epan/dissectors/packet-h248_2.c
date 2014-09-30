/*
 *  packet-h248_2.c
 *
 *  H.248.2
 *  Gateway control protocol: Facsimile, text conversation and call discrimination packages
 *
 *  (c) 2012, Anders broman <anders.broman@ericsson.com>
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
 *
 */

#include "config.h"

#include "packet-h248.h"

void proto_register_h248_dot2(void);

#define PNAME  "H.248.2"
#define PSNAME "H248_2"
#define PFNAME "h248.2"

static int proto_h248_2 = -1;

/* static int hf_h248_2_dtone_evt = -1; */
static int hf_h248_2_dtone_dtt_obs_evt = -1;
static int hf_h248_2_dtone_dtt_obs_evt_val = -1;

static gint ett_h248_2 = -1;
static gint ett_h248_2_dtone_dtt_obs_evt = -1;


static const value_string hf_h248_2_dtone_dtt_obs_evt_val_values[] = {
    /*For FAX*/
    { 0x0001, "CNG"},           /* A T.30 fax calling tone */
    { 0x0002, "V21flag"},       /* V21 tone and flags for fax answering */
    /* For TEXT */
    { 0x0003, "XCI"},           /* A V.18 XCI */
    { 0x0004, "V18txp1"},       /* A V.18 txp signal in channel V.21(1) */
    { 0x0005, "V18txp2"},       /* A V.18 txp signal in channel V.21(2) */
    { 0x0006, "BellHi"},        /* A Bell 103 carrier on the high channel */
    { 0x0007, "BellLo"},        /* A Bell 103 low channel */
    { 0x0008, "Baudot45"},      /* Baudot45 initial carrier and characters */
    { 0x0009, "Baudot50"},      /* A Baudot50 initial carrier and characters */
    { 0x000a, "Edt"},           /* An EDT initial tone and characters */
    { 0x000b, "DTMF"},          /* DTMF signals */
    { 0x001c, "CTM"},           /* CTM signals */
    /* For DATA */
    { 0x000c, "Sig"},           /* Modulation signal from a mode only used for data, i.e., not V.21, V.23 nor Bell 103 */
    /* Common to TEXT and DATA */
    { 0x000d, "CT"},            /* A V.25 calling tone */
    { 0x000e, "V21hi"},         /* A V.21 carrier on the higher frequency channel */
    { 0x000f, "V21lo"},         /* A V.21 carrier on the low frequency channel */
    { 0x0010, "V23hi"},         /* A V.23 high carrier */
    { 0x0011, "V23lo"},         /*  A V.23 low carrier */
    { 0x0012, "CI"},            /* A V.8 CI with contents in "dtvalue" */
    /* Common to FAX, TEXT and DATA */
    { 0x0013, "ANS(T.30 CED)"}, /* V.25 ANS, equivalent to T.30 CED from answering terminal */
    { 0x0014, "ANSbar"},        /* V.25 ANS with phase reversals" */
    { 0x0015, "ANSAM"},         /* V.8 ANSam */
    { 0x0016, "ANSAMbar"},      /* V.8 ANSam with phase reversals */
    { 0x0017, "CM"},            /* V.8 CM with contents in "dtvalue" */
    { 0x0018, "CJ"},            /* V.8 CJ */
    { 0x0019, "JM"},            /* V.8 JM with contents in "dtvalue" */
    { 0x001a, "ENDOFSIG"},      /* End of reported signal detected reported for continuous or repeated signals */
    { 0x001b, "V8BIS"},         /* V.8 bis signal, with signal type in parameter V8bistype and value in "dtvalue" */
    { 0, NULL }
};

static h248_pkg_param_t h248_2_dtone_dtt_obs_evt_params[] = {
    { 0x0001, &hf_h248_2_dtone_dtt_obs_evt_val, h248_param_ber_integer, NULL },
    { 0, NULL, NULL, NULL}
};


static const value_string h248_2_ctype_events_vals[] = {
    { 0x0001, "Discriminating Tone Detected(dtone)"},
    { 0x0002, "Call Type Discrimination Result(calldisres)"},
    { 0, NULL }
};

static h248_pkg_evt_t h248_pkg_generic_cause_evts[] = {
    { 0x0001, &hf_h248_2_dtone_dtt_obs_evt, &ett_h248_2_dtone_dtt_obs_evt, h248_2_dtone_dtt_obs_evt_params, h248_2_ctype_events_vals},
    { 0, NULL, NULL, NULL, NULL}
};



/* Call Type Discrimination Package */
static h248_package_t h248_pkg_ctype = {
    0x0011,                     /* Id */
    &proto_h248_2,              /* hfid */
    &ett_h248_2,                /* ett */

    NULL,                       /* value_string param_names */
    NULL,                       /* value_string signal_names */
    h248_2_ctype_events_vals,   /* value_string event_names */
    NULL,                       /* value_string stats_names */

    NULL,                       /* properties */
    NULL,                       /* signals */
    h248_pkg_generic_cause_evts,                        /* events */
    NULL                        /* statistics */
};

void proto_register_h248_dot2(void) {
    static hf_register_info hf[] = {
#if 0
        { &hf_h248_2_dtone_evt,
            { "Discriminating Tone Type", "h248.2.dtt",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
#endif
        { &hf_h248_2_dtone_dtt_obs_evt,
            { "Discriminating Tone Type(dtt)", "h248.2.dtt",
            FT_BYTES, BASE_NONE, NULL, 0,
                          NULL, HFILL },
        },
        { &hf_h248_2_dtone_dtt_obs_evt_val,
            { "call type", "h248.2.dtt.val",
            FT_UINT32, BASE_DEC, VALS(hf_h248_2_dtone_dtt_obs_evt_val_values) , 0,
            NULL, HFILL }
        },

    };

    static gint *ett[] = {
        &ett_h248_2,
        &ett_h248_2_dtone_dtt_obs_evt,
    };

    proto_h248_2 = proto_register_protocol(PNAME, PSNAME, PFNAME);

    proto_register_field_array(proto_h248_2, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));

    h248_register_package(&h248_pkg_ctype,MERGE_PKG_HIGH);
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
