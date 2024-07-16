/* packet-distcc.c
 * Routines for distcc dissection
 * Copyright 2003, Brad Hards <bradh@frogmouth.net>
 * Copyright 2003, Ronnie Sahlberg, added TCP desegmentation.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This dissector supports version 1 of the DISTCC protocol:
 *
 *    https://github.com/distcc/distcc/blob/master/doc/protocol-1.txt
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include <wsutil/strtoi.h>

static int proto_distcc;
static int hf_distcc_version;
static int hf_distcc_argc;
static int hf_distcc_argv;
static int hf_distcc_doti_source;
static int hf_distcc_stat;
static int hf_distcc_serr;
static int hf_distcc_sout;
static int hf_distcc_doto_object;


static int ett_distcc;

static expert_field ei_distcc_short_pdu;


static bool distcc_desegment = true;


#define TCP_PORT_DISTCC 3632

void proto_register_distcc(void);
extern void proto_reg_handoff_distcc(void);

static dissector_handle_t distcc_handle;

#define CHECK_PDU_LEN(x) \
    if(parameter>(unsigned)tvb_captured_length_remaining(tvb, offset) || parameter < 1){\
        len=tvb_captured_length_remaining(tvb, offset);\
        col_append_str(pinfo->cinfo, COL_INFO, "[Short" x " PDU]");\
    } \
    tvb_ensure_bytes_exist(tvb, offset, len);


#define DESEGMENT_TCP(x) \
    if(distcc_desegment && pinfo->can_desegment){\
        /* only attempt reassembly if we have the full segment */\
        if(tvb_captured_length_remaining(tvb, offset)==tvb_reported_length_remaining(tvb, offset)){\
            if(parameter>(unsigned)tvb_captured_length_remaining(tvb, offset)){\
                proto_tree_add_expert_format(tree, pinfo, &ei_distcc_short_pdu, tvb, offset-12, -1, "[Short " x " PDU]");\
                pinfo->desegment_offset=offset-12;\
                pinfo->desegment_len=parameter-tvb_captured_length_remaining(tvb, offset);\
                return offset+len;\
            }\
        }\
    }

static int
dissect_distcc_dist(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint32_t parameter)
{
    proto_tree_add_uint_format(tree, hf_distcc_version, tvb, offset-12, 12, parameter, "DIST: %u", parameter);

    col_append_fstr(pinfo->cinfo, COL_INFO, "DIST:%u ", parameter);

    return offset;
}

static int
dissect_distcc_done(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint32_t parameter)
{
    proto_tree_add_uint_format(tree, hf_distcc_version, tvb, offset-12, 12, parameter, "DONE: %u", parameter);

    col_append_fstr(pinfo->cinfo, COL_INFO, "DONE:%u ", parameter);

    return offset;
}

static int
dissect_distcc_stat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint32_t parameter)
{
    proto_tree_add_uint_format(tree, hf_distcc_stat, tvb, offset-12, 12, parameter, "STAT: %u", parameter);

    col_append_fstr(pinfo->cinfo, COL_INFO, "STAT:%u ", parameter);

    return offset;
}

static int
dissect_distcc_argc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint32_t parameter)
{
    proto_tree_add_uint(tree, hf_distcc_argc, tvb, offset-12, 12, parameter);

    col_append_fstr(pinfo->cinfo, COL_INFO, "ARGC:%u ", parameter);

    return offset;
}

static int
dissect_distcc_argv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, unsigned parameter)
{
    int len=(int)parameter;
    char *argv;
    proto_item* ti;

    CHECK_PDU_LEN("ARGV");

    /* see if we need to desegment the PDU */
    DESEGMENT_TCP("ARGV");

    /*
     * XXX - we have no idea what encoding is being used, other than
     * it being some flavor of "extended ASCII"; these days, it's
     * *probably* UTF-8, but it could conceivably be something else.
     */
    ti = proto_tree_add_item_ret_display_string(tree, hf_distcc_argv, tvb, offset, len, ENC_ASCII|ENC_NA, pinfo->pool, &argv);

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", argv);

    if(len!=(int)parameter){
        expert_add_info_format(pinfo, ti, &ei_distcc_short_pdu, "[Short ARGV PDU]");
    }
    return offset+len;
}

static int
dissect_distcc_serr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, unsigned parameter)
{
    int len=(int)parameter;
    char *serr;
    proto_item* ti;

    CHECK_PDU_LEN("SERR");

    /* see if we need to desegment the PDU */
    DESEGMENT_TCP("SERR");

    /*
     * XXX - we have no idea what encoding is being used, other than
     * it being some flavor of "extended ASCII"; these days, it's
     * *probably* UTF-8, but it could conceivably be something else.
     */
    ti = proto_tree_add_item_ret_display_string(tree, hf_distcc_serr, tvb, offset, len, ENC_ASCII|ENC_NA, pinfo->pool, &serr);

    col_append_fstr(pinfo->cinfo, COL_INFO, "SERR:%s ", serr);

    if(len!=(int)parameter){
        expert_add_info_format(pinfo, ti, &ei_distcc_short_pdu, "[Short SERR PDU]");
    }
    return offset+len;
}

static int
dissect_distcc_sout(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, unsigned parameter)
{
    int len=(int)parameter;
    char *sout;
    proto_item* ti;

    CHECK_PDU_LEN("SOUT");

    /* see if we need to desegment the PDU */
    DESEGMENT_TCP("SOUT");

    /*
     * XXX - we have no idea what encoding is being used, other than
     * it being some flavor of "extended ASCII"; these days, it's
     * *probably* UTF-8, but it could conceivably be something else.
     */
    ti = proto_tree_add_item_ret_display_string(tree, hf_distcc_sout, tvb, offset, len, ENC_ASCII|ENC_NA, pinfo->pool, &sout);

    col_append_fstr(pinfo->cinfo, COL_INFO, "SOUT:%s ", sout);

    if(len!=(int)parameter){
        expert_add_info_format(pinfo, ti, &ei_distcc_short_pdu, "[Short SOUT PDU]");
    }
    return offset+len;
}


static int
dissect_distcc_doti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, unsigned parameter)
{
    int len=(int)parameter;
    proto_item* ti;

    CHECK_PDU_LEN("DOTI");

    /* see if we need to desegment the PDU */
    DESEGMENT_TCP("DOTI");

    col_append_str(pinfo->cinfo, COL_INFO, "DOTI source ");

    ti = proto_tree_add_item(tree, hf_distcc_doti_source, tvb, offset, len, ENC_ASCII);

    if(len!=(int)parameter){
        expert_add_info_format(pinfo, ti, &ei_distcc_short_pdu, "[Short DOTI PDU]");
    }
    return offset+len;
}

static int
dissect_distcc_doto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, unsigned parameter)
{
    int len=(int)parameter;
    proto_item* ti;

    CHECK_PDU_LEN("DOTO");

    /* see if we need to desegment the PDU */
    DESEGMENT_TCP("DOTO");

    col_append_str(pinfo->cinfo, COL_INFO, "DOTO object ");

    ti = proto_tree_add_item(tree, hf_distcc_doto_object, tvb, offset, len, ENC_NA);

    if(len!=(int)parameter){
        expert_add_info_format(pinfo, ti, &ei_distcc_short_pdu, "[Short DOTO PDU]");
    }
    return offset+len;
}



/* Packet dissection routine called by tcp (& udp) when port 3632 detected */
static int
dissect_distcc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    int offset=0;
    proto_tree *tree=NULL;
    proto_item *item=NULL;
    char buf[13];
    uint32_t parameter;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DISTCC ");

    col_clear(pinfo->cinfo, COL_INFO);

    if (parent_tree) {
        item = proto_tree_add_item(parent_tree, proto_distcc, tvb, offset,
            -1, ENC_NA);
        tree = proto_item_add_subtree(item, ett_distcc);
    }

    while (true) {
        /* read the raw token (4 bytes) and parameter (8 bytes) */
        tvb_memcpy(tvb, buf, offset, 12);
        buf[12] = '\0';
        offset+=12;

        /* get the parameter value */
        if (!ws_hexstrtou32(buf + 4, NULL, &parameter))
            return offset;

        if(!strncmp(buf, "DIST", 4)){
            offset=dissect_distcc_dist(tvb, pinfo, tree, offset, parameter);
        } else if(!strncmp(buf, "ARGC", 4)){
            offset=dissect_distcc_argc(tvb, pinfo, tree, offset, parameter);
        } else if(!strncmp(buf, "ARGV", 4)){
            offset=dissect_distcc_argv(tvb, pinfo, tree, offset, parameter);
        } else if(!strncmp(buf, "DOTI", 4)){
            offset=dissect_distcc_doti(tvb, pinfo, tree, offset, parameter);
        } else if(!strncmp(buf, "DONE", 4)){
            offset=dissect_distcc_done(tvb, pinfo, tree, offset, parameter);
        } else if(!strncmp(buf, "STAT", 4)){
            offset=dissect_distcc_stat(tvb, pinfo, tree, offset, parameter);
        } else if(!strncmp(buf, "SERR", 4)){
            offset=dissect_distcc_serr(tvb, pinfo, tree, offset, parameter);
        } else if(!strncmp(buf, "SOUT", 4)){
            offset=dissect_distcc_sout(tvb, pinfo, tree, offset, parameter);
        } else if(!strncmp(buf, "DOTO", 4)){
            offset=dissect_distcc_doto(tvb, pinfo, tree, offset, parameter);
        } else {
            call_data_dissector(tvb, pinfo, tree);
            return tvb_captured_length(tvb);
        }
    }

    return tvb_captured_length(tvb);
}

/* Register protocol with Wireshark. */
void
proto_register_distcc(void)
{
    static hf_register_info hf[] = {
    {&hf_distcc_version,
     {"DISTCC Version", "distcc.version",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    {&hf_distcc_argc,
     {"ARGC", "distcc.argc",
      FT_UINT32, BASE_DEC, NULL, 0x0, "Number of arguments", HFILL }
    },
    {&hf_distcc_argv,
     {"ARGV", "distcc.argv",
      FT_STRING, BASE_NONE, NULL, 0x0, "ARGV argument", HFILL }
    },
    {&hf_distcc_doti_source,
     {"Source", "distcc.doti_source",
      FT_STRING, BASE_NONE, NULL, 0x0, "DOTI Preprocessed Source File (.i)", HFILL }
    },
    {&hf_distcc_stat,
     {"Status", "distcc.status",
      FT_UINT32, BASE_DEC, NULL, 0x0, "Unix wait status for command completion", HFILL }
    },
    {&hf_distcc_serr,
     {"SERR", "distcc.serr",
      FT_STRING, BASE_NONE, NULL, 0x0, "STDERR output", HFILL }
    },
    {&hf_distcc_sout,
     {"SOUT", "distcc.sout",
      FT_STRING, BASE_NONE, NULL, 0x0, "STDOUT output", HFILL }
    },
    {&hf_distcc_doto_object,
     {"Object", "distcc.doto_object",
      FT_BYTES, BASE_NONE, NULL, 0x0, "DOTO Compiled object file (.o)", HFILL }
    }

    };

    static int *ett[] = {
        &ett_distcc,
    };

    static ei_register_info ei[] = {
        { &ei_distcc_short_pdu, { "distcc.short_pdu", PI_MALFORMED, PI_ERROR, "Short PDU", EXPFILL }},
    };

    module_t *distcc_module;
    expert_module_t* expert_distcc;

    proto_distcc = proto_register_protocol("Distcc Distributed Compiler", "DISTCC", "distcc");

    proto_register_field_array(proto_distcc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_distcc = expert_register_protocol(proto_distcc);
    expert_register_field_array(expert_distcc, ei, array_length(ei));

    distcc_module = prefs_register_protocol(proto_distcc, NULL);

    prefs_register_bool_preference(distcc_module, "desegment_distcc_over_tcp",
        "Reassemble DISTCC-over-TCP messages spanning multiple TCP segments",
        "Whether the DISTCC dissector should reassemble messages spanning multiple TCP segments."
        " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
        &distcc_desegment);

    distcc_handle = register_dissector("distcc", dissect_distcc, proto_distcc);
}

void
proto_reg_handoff_distcc(void)
{
    dissector_add_uint_with_preference("tcp.port", TCP_PORT_DISTCC, distcc_handle);
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
