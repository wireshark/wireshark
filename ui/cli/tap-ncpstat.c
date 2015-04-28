/* tap-ncpstat.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include "epan/value_string.h"
#include <ui/cli/cli_service_response_time_table.h>
#include <epan/dissectors/packet-ncp-int.h>
#include "epan/timestats.h"

void register_tap_listener_ncpstat(void);

#define NCP_NUM_PROCEDURES     0

/* used to keep track of the statistics for an entire program interface */
typedef struct _ncpstat_t {
    srt_stat_table ncp_srt_table;
    srt_stat_table nds_srt_table;
    srt_stat_table func_srt_table;
    srt_stat_table sss_srt_table;
    srt_stat_table nmas_srt_table;
    srt_stat_table sub_17_srt_table;
    srt_stat_table sub_21_srt_table;
    srt_stat_table sub_22_srt_table;
    srt_stat_table sub_23_srt_table;
    srt_stat_table sub_32_srt_table;
    srt_stat_table sub_34_srt_table;
    srt_stat_table sub_35_srt_table;
    srt_stat_table sub_36_srt_table;
    srt_stat_table sub_86_srt_table;
    srt_stat_table sub_87_srt_table;
    srt_stat_table sub_89_srt_table;
    srt_stat_table sub_90_srt_table;
    srt_stat_table sub_92_srt_table;
    srt_stat_table sub_94_srt_table;
    srt_stat_table sub_104_srt_table;
    srt_stat_table sub_111_srt_table;
    srt_stat_table sub_114_srt_table;
    srt_stat_table sub_123_srt_table;
    srt_stat_table sub_131_srt_table;
} ncpstat_t;

static int
ncpstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv)
{
    ncpstat_t *ss=(ncpstat_t *)pss;
    const ncp_req_hash_value *request_val=(const ncp_req_hash_value *)prv;
    gchar* tmp_str;

    /* if we haven't seen the request, just ignore it */
    if(!request_val || request_val->ncp_rec==0){
        return 0;
    }
    /* By Group */
    tmp_str = val_to_str_wmem(NULL, request_val->ncp_rec->group, ncp_group_vals, "Unknown(%u)");
    init_srt_table_row(&ss->ncp_srt_table, request_val->ncp_rec->group, tmp_str);
    wmem_free(NULL, tmp_str);
    add_srt_table_data(&ss->ncp_srt_table, request_val->ncp_rec->group, &request_val->req_frame_time, pinfo);
    /* By NCP number without subfunction*/
    if (request_val->ncp_rec->subfunc==0) {
        init_srt_table_row(&ss->func_srt_table, request_val->ncp_rec->func, request_val->ncp_rec->name);
        add_srt_table_data(&ss->func_srt_table, request_val->ncp_rec->func, &request_val->req_frame_time, pinfo);
    }
    /* By Subfunction number */
    if(request_val->ncp_rec->subfunc!=0){
        if (request_val->ncp_rec->func==17) {
            init_srt_table_row(&ss->sub_17_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_17_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==21) {
            init_srt_table_row(&ss->sub_21_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_21_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==22) {
            init_srt_table_row(&ss->sub_22_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_22_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==23) {
            init_srt_table_row(&ss->sub_23_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_23_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==32) {
            init_srt_table_row(&ss->sub_32_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_32_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==34) {
            init_srt_table_row(&ss->sub_34_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_34_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==35) {
            init_srt_table_row(&ss->sub_35_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_35_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==36) {
            init_srt_table_row(&ss->sub_36_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_36_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==86) {
            init_srt_table_row(&ss->sub_86_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_86_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==87) {
            init_srt_table_row(&ss->sub_87_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_87_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==89) {
            init_srt_table_row(&ss->sub_89_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_89_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==90) {
            init_srt_table_row(&ss->sub_90_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_90_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==92) {
            init_srt_table_row(&ss->sub_92_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_92_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==94) {
            init_srt_table_row(&ss->sub_94_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_94_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==104) {
            init_srt_table_row(&ss->sub_104_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_104_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==111) {
            init_srt_table_row(&ss->sub_111_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_111_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==114) {
            init_srt_table_row(&ss->sub_114_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_114_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==123) {
            init_srt_table_row(&ss->sub_123_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_123_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==131) {
            init_srt_table_row(&ss->sub_131_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_131_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
    }
    /* By NDS verb */
    if (request_val->ncp_rec->func==0x68) {
        tmp_str = val_to_str_wmem(NULL, request_val->nds_request_verb, ncp_nds_verb_vals, "Unknown(%u)");
        init_srt_table_row(&ss->nds_srt_table, (request_val->nds_request_verb), tmp_str);
        wmem_free(NULL, tmp_str);
        add_srt_table_data(&ss->nds_srt_table, (request_val->nds_request_verb), &request_val->req_frame_time, pinfo);
    }
    if (request_val->ncp_rec->func==0x5c) {
        tmp_str = val_to_str_wmem(NULL, request_val->req_nds_flags, sss_verb_enum, "Unknown(%u)");
        init_srt_table_row(&ss->sss_srt_table, (request_val->req_nds_flags), tmp_str);
        wmem_free(NULL, tmp_str);
        add_srt_table_data(&ss->sss_srt_table, (request_val->req_nds_flags), &request_val->req_frame_time, pinfo);
    }
    if (request_val->ncp_rec->func==0x5e) {
        tmp_str = val_to_str_wmem(NULL, request_val->req_nds_flags, nmas_subverb_enum, "Unknown(%u)");
        init_srt_table_row(&ss->nmas_srt_table, (request_val->req_nds_flags), tmp_str);
        wmem_free(NULL, tmp_str);
        add_srt_table_data(&ss->nmas_srt_table, (request_val->req_nds_flags), &request_val->req_frame_time, pinfo);
    }
    return 1;
}

static void
ncpstat_draw_header(srt_stat_table *rst)
{
    printf("%s SRT Statistics:\n", rst->name);
    printf("Filter: %s\n", rst->filter_string ? rst->filter_string : "");
}

static void
ncpstat_draw(void *pss)
{
    ncpstat_t *ss = (ncpstat_t *)pss;

    printf("\n");
    printf("===================================================================\n");

    /* Tables were intentionally initialized to 0 rows, so only output tables with rows > 0 */
    if (ss->ncp_srt_table.num_procs > 0) {
        ncpstat_draw_header(&ss->ncp_srt_table);
        draw_srt_table_data(&ss->ncp_srt_table, FALSE, FALSE);
    }
    if (ss->func_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->func_srt_table);
        draw_srt_table_data(&ss->func_srt_table, FALSE, FALSE);
    }
    if (ss->nds_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->nds_srt_table);
        draw_srt_table_data(&ss->nds_srt_table, FALSE, FALSE);
    }
    if (ss->sss_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sss_srt_table);
        draw_srt_table_data(&ss->sss_srt_table, FALSE, FALSE);
    }
    if (ss->nmas_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->nmas_srt_table);
        draw_srt_table_data(&ss->nmas_srt_table, FALSE, FALSE);
    }
    if (ss->sub_17_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_17_srt_table);
        draw_srt_table_data(&ss->sub_17_srt_table, FALSE, FALSE);
    }
    if (ss->sub_21_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_21_srt_table);
        draw_srt_table_data(&ss->sub_21_srt_table, FALSE, FALSE);
    }
    if (ss->sub_22_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_22_srt_table);
        draw_srt_table_data(&ss->sub_22_srt_table, FALSE, FALSE);
    }
    if (ss->sub_23_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_23_srt_table);
        draw_srt_table_data(&ss->sub_23_srt_table, FALSE, FALSE);
    }
    if (ss->sub_32_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_32_srt_table);
        draw_srt_table_data(&ss->sub_32_srt_table, FALSE, FALSE);
    }
    if (ss->sub_34_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_34_srt_table);
        draw_srt_table_data(&ss->sub_34_srt_table, FALSE, FALSE);
    }
    if (ss->sub_35_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_35_srt_table);
        draw_srt_table_data(&ss->sub_35_srt_table, FALSE, FALSE);
    }
    if (ss->sub_36_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_36_srt_table);
        draw_srt_table_data(&ss->sub_36_srt_table, FALSE, FALSE);
    }
    if (ss->sub_86_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_86_srt_table);
        draw_srt_table_data(&ss->sub_86_srt_table, FALSE, FALSE);
    }
    if (ss->sub_87_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_87_srt_table);
        draw_srt_table_data(&ss->sub_87_srt_table, FALSE, FALSE);
    }
    if (ss->sub_89_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_89_srt_table);
        draw_srt_table_data(&ss->sub_89_srt_table, FALSE, FALSE);
    }
    if (ss->sub_90_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_90_srt_table);
        draw_srt_table_data(&ss->sub_90_srt_table, FALSE, FALSE);
    }
    if (ss->sub_92_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_92_srt_table);
        draw_srt_table_data(&ss->sub_92_srt_table, FALSE, FALSE);
    }
    if (ss->sub_94_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_94_srt_table);
        draw_srt_table_data(&ss->sub_94_srt_table, FALSE, FALSE);
    }
    if (ss->sub_104_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_104_srt_table);
        draw_srt_table_data(&ss->sub_104_srt_table, FALSE, FALSE);
    }
    if (ss->sub_111_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_111_srt_table);
        draw_srt_table_data(&ss->sub_111_srt_table, FALSE, FALSE);
    }
    if (ss->sub_114_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_114_srt_table);
        draw_srt_table_data(&ss->sub_114_srt_table, FALSE, FALSE);
    }
    if (ss->sub_123_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_123_srt_table);
        draw_srt_table_data(&ss->sub_123_srt_table, FALSE, FALSE);
    }
    if (ss->sub_131_srt_table.num_procs > 0) {
        printf("\n");
        ncpstat_draw_header(&ss->sub_131_srt_table);
        draw_srt_table_data(&ss->sub_131_srt_table, FALSE, FALSE);
    }

    printf("===================================================================\n");
}


static void
ncpstat_init(const char *opt_arg, void *userdata _U_)
{
    ncpstat_t *ss;
    const char *filter = NULL;
    GString *error_string;

    if (!strncmp(opt_arg, "ncp,srt,", 8)) {
        filter = opt_arg + 8;
    }

    ss = g_new(ncpstat_t, 1);

    /* Initialize all of the SRT tables with 0 rows.  That way we can "filter" the drawing
       function to only output tables with rows > 0 */
    init_srt_table("NCP", &ss->ncp_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.group");

    /* NCP Functions */
    init_srt_table("NCP Functions without Subfunctions", &ss->func_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func");

    /* NCP Subfunctions */
    init_srt_table("Subfunctions for NCP 17", &ss->sub_17_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==17 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 21", &ss->sub_21_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==21 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 22", &ss->sub_22_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==22 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 23", &ss->sub_23_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==23 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 32", &ss->sub_32_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==32 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 34", &ss->sub_34_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==34 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 35", &ss->sub_35_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==35 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 36", &ss->sub_36_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==36 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 86", &ss->sub_86_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==86 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 87", &ss->sub_87_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==87 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 89 (Extended NCP's with UTF8 Support)", &ss->sub_89_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==89 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 90", &ss->sub_90_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==90 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 92 (Secret Store Services)", &ss->sub_92_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==92 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 94 (Novell Modular Authentication Services)", &ss->sub_94_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==94 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 104", &ss->sub_104_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==104 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 111", &ss->sub_111_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==111 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 114", &ss->sub_114_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==114 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 123", &ss->sub_123_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==123 && ncp.subfunc");
    init_srt_table("Subfunctions for NCP 131", &ss->sub_131_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.func==131 && ncp.subfunc");

    /* NDS Verbs */
    init_srt_table("NDS Verbs", &ss->nds_srt_table, NCP_NUM_PROCEDURES, NULL, "ncp.ndsverb");
    /* Secret Store Verbs */
    init_srt_table("Secret Store Verbs", &ss->sss_srt_table, NCP_NUM_PROCEDURES, NULL, "sss.subverb");
    /* NMAS Verbs */
    init_srt_table("NMAS Verbs", &ss->nmas_srt_table, NCP_NUM_PROCEDURES, NULL, "nmas.subverb");

    error_string = register_tap_listener("ncp_srt", ss, filter, 0, NULL, ncpstat_packet, ncpstat_draw);
	if (error_string) {
        /* error, we failed to attach to the tap. clean up */
        free_srt_table_data(&ss->ncp_srt_table);
        free_srt_table_data(&ss->nds_srt_table);
        free_srt_table_data(&ss->func_srt_table);
        free_srt_table_data(&ss->sss_srt_table);
        free_srt_table_data(&ss->nmas_srt_table);
        free_srt_table_data(&ss->sub_17_srt_table);
        free_srt_table_data(&ss->sub_21_srt_table);
        free_srt_table_data(&ss->sub_22_srt_table);
        free_srt_table_data(&ss->sub_23_srt_table);
        free_srt_table_data(&ss->sub_32_srt_table);
        free_srt_table_data(&ss->sub_34_srt_table);
        free_srt_table_data(&ss->sub_35_srt_table);
        free_srt_table_data(&ss->sub_36_srt_table);
        free_srt_table_data(&ss->sub_86_srt_table);
        free_srt_table_data(&ss->sub_87_srt_table);
        free_srt_table_data(&ss->sub_89_srt_table);
        free_srt_table_data(&ss->sub_90_srt_table);
        free_srt_table_data(&ss->sub_92_srt_table);
        free_srt_table_data(&ss->sub_94_srt_table);
        free_srt_table_data(&ss->sub_104_srt_table);
        free_srt_table_data(&ss->sub_111_srt_table);
        free_srt_table_data(&ss->sub_114_srt_table);
        free_srt_table_data(&ss->sub_123_srt_table);
        free_srt_table_data(&ss->sub_131_srt_table);
        g_free(ss);

        fprintf(stderr, "tshark: Couldn't register ncp,srt tap: %s\n",
	        error_string->str);
        g_string_free(error_string, TRUE);
        exit(1);
    }
}

static stat_tap_ui ncpstat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "ncp,srt",
    ncpstat_init,
    0,
    NULL
};

void
register_tap_listener_ncpstat(void)
{
    register_stat_tap_ui(&ncpstat_ui, NULL);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 noexpandtab:
 * :indentSize=4:tabSize=4:noTabs=false:
 */
