/* tap-gsm_astat.c
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This TAP provides statistics for the GSM A Interface:
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet_info.h>
#include <epan/value_string.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/dissectors/packet-bssap.h>
#include <epan/dissectors/packet-gsm_a_common.h>

#include <wsutil/cmdarg_err.h>

void register_tap_listener_gsm_astat(void);

typedef struct _gsm_a_stat_t {
    int         bssmap_message_type[0x100];
    int         dtap_mm_message_type[0x100];
    int         dtap_rr_message_type[0x100];
    int         dtap_cc_message_type[0x100];
    int         dtap_gmm_message_type[0x100];
    int         dtap_sms_message_type[0x100];
    int         dtap_sm_message_type[0x100];
    int         dtap_ss_message_type[0x100];
    int         dtap_tp_message_type[0x100];
    int         sacch_rr_message_type[0x100];
} gsm_a_stat_t;

static const value_string gsm_a_pd_vals[] = {
    {PD_GCC, "Group Call Control"},
    {PD_BCC, "Broadcast Call Control"},
    {PD_RSVD_1, "EPS session management messages"},
    {PD_CC, "Call Control; call related SS messages"},
    {PD_GTTP, "GPRS Transparent Transport Protocol (GTTP)"},
    {PD_MM, "Mobility Management messages"},
    {PD_RR, "Radio Resources Management messages"},
    {PD_UNK_1, "EPS mobility management messages"},
    {PD_GMM, "GPRS Mobility Management messages"},
    {PD_SMS, "SMS messages"},
    {PD_SM, "GPRS Session Management messages"},
    {PD_SS, "Non call related SS messages"},
    {PD_LCS, "Location services specified in 3GPP TS 44.071"},
    {PD_UNK_2, "Unknown"},
    {PD_RSVD_EXT, "Reserved for extension of the PD to one octet length"},
    {PD_TP, "Special conformance testing functions"},
    { 0,    NULL }
};


static tap_packet_status
gsm_a_stat_packet(
    void                        *tapdata,
    packet_info                 *pinfo _U_,
    epan_dissect_t              *edt _U_,
    const void                  *data,
    tap_flags_t flags  _U_)
{
    gsm_a_stat_t                *stat_p = (gsm_a_stat_t *)tapdata;
    const gsm_a_tap_rec_t       *tap_p = (const gsm_a_tap_rec_t *)data;

    switch (tap_p->pdu_type)
    {
    case BSSAP_PDU_TYPE_BSSMAP:
        stat_p->bssmap_message_type[tap_p->message_type]++;
        break;

    case BSSAP_PDU_TYPE_DTAP:
        switch (tap_p->protocol_disc)
        {
        case PD_CC:
            stat_p->dtap_cc_message_type[tap_p->message_type]++;
            break;
        case PD_MM:
            stat_p->dtap_mm_message_type[tap_p->message_type]++;
            break;
        case PD_RR:
            stat_p->dtap_rr_message_type[tap_p->message_type]++;
            break;
        case PD_GMM:
            stat_p->dtap_gmm_message_type[tap_p->message_type]++;
            break;
        case PD_SMS:
            stat_p->dtap_sms_message_type[tap_p->message_type]++;
            break;
        case PD_SM:
            stat_p->dtap_sm_message_type[tap_p->message_type]++;
            break;
        case PD_SS:
            stat_p->dtap_ss_message_type[tap_p->message_type]++;
            break;
        case PD_TP:
            stat_p->dtap_tp_message_type[tap_p->message_type]++;
            break;
        default:
            /*
             * unsupported PD
             */
            return(TAP_PACKET_DONT_REDRAW);
        }
        break;

   case GSM_A_PDU_TYPE_SACCH:
        switch (tap_p->protocol_disc)
        {
        case 0:
            stat_p->sacch_rr_message_type[tap_p->message_type]++;
            break;
        default:
            /* unknown Short PD */
            break;
        }
        break;

    default:
        /*
         * unknown PDU type !!!
         */
        return(TAP_PACKET_DONT_REDRAW);
    }

    return(TAP_PACKET_REDRAW);
}

static void
gsm_a_stat_draw_vs_helper(int* message_type, value_string* vs_draw)
{
    uint8_t i = 0;
    while (vs_draw[i].strptr)
    {
        const value_string* vs = &vs_draw[i];
        if (message_type[vs->value] > 0)
        {
            printf("0x%02x  %-50s%d\n",
                vs->value,
                vs->strptr,
                message_type[vs->value]);
        }

        i++;
    }

}

static void
gsm_a_stat_draw(
    void                *tapdata)
{
    gsm_a_stat_t        *stat_p = (gsm_a_stat_t *)tapdata;

    printf("\n");
    printf("=========== GS=M A-i/f Statistics ============================\n");
    printf("BSSMAP\n");
    printf("Message (ID)Type                                        Number\n");

    gsm_a_stat_draw_vs_helper(stat_p->bssmap_message_type, vs_get_external_value_string("gsm_a_bssmap_msg_strings"));

    printf("\nDTAP %s\n", val_to_str_const(PD_MM, gsm_a_pd_vals, "Unknown Type"));
    printf("Message (ID)Type                                        Number\n");

    gsm_a_stat_draw_vs_helper(stat_p->dtap_mm_message_type, vs_get_external_value_string("gsm_a_dtap_msg_mm_strings"));

    printf("\nDTAP %s\n", val_to_str_const(PD_RR, gsm_a_pd_vals, "Unknown Type"));
    printf("Message (ID)Type                                        Number\n");

    gsm_a_stat_draw_vs_helper(stat_p->dtap_rr_message_type, vs_get_external_value_string("gsm_a_dtap_msg_rr_strings"));

    printf("\nDTAP %s\n", val_to_str_const(PD_CC, gsm_a_pd_vals, "Unknown Type"));
    printf("Message (ID)Type                                        Number\n");

    gsm_a_stat_draw_vs_helper(stat_p->dtap_cc_message_type, vs_get_external_value_string("gsm_a_dtap_msg_cc_strings"));

    printf("\nDTAP %s\n", val_to_str_const(PD_GMM, gsm_a_pd_vals, "Unknown Type"));
    printf("Message (ID)Type                                        Number\n");

    gsm_a_stat_draw_vs_helper(stat_p->dtap_gmm_message_type, vs_get_external_value_string("gsm_a_dtap_msg_gmm_strings"));

    printf("\nDTAP %s\n", val_to_str_const(PD_SMS, gsm_a_pd_vals, "Unknown Type"));
    printf("Message (ID)Type                                        Number\n");

    gsm_a_stat_draw_vs_helper(stat_p->dtap_sms_message_type, vs_get_external_value_string("gsm_a_dtap_msg_sms_strings"));

    printf("\nDTAP %s\n", val_to_str_const(PD_SM, gsm_a_pd_vals, "Unknown Type"));
    printf("Message (ID)Type                                        Number\n");

    gsm_a_stat_draw_vs_helper(stat_p->dtap_sm_message_type, vs_get_external_value_string("gsm_a_dtap_msg_sm_strings"));

    printf("\nDTAP %s\n", val_to_str_const(PD_SS, gsm_a_pd_vals, "Unknown Type"));
    printf("Message (ID)Type                                        Number\n");

    gsm_a_stat_draw_vs_helper(stat_p->dtap_ss_message_type, vs_get_external_value_string("gsm_a_dtap_msg_ss_strings"));

    printf("\nDTAP %s\n", val_to_str_const(PD_TP, gsm_a_pd_vals, "Unknown Type"));
    printf("Message (ID)Type                                        Number\n");

    gsm_a_stat_draw_vs_helper(stat_p->dtap_tp_message_type, vs_get_external_value_string("gsm_a_dtap_msg_tp_strings"));

    printf("\nSACCH Radio Resources Management messages\n");
    printf("Message (ID)Type                                        Number\n");

    gsm_a_stat_draw_vs_helper(stat_p->sacch_rr_message_type, vs_get_external_value_string("gsm_a_rr_short_pd_msg_strings"));

    printf("==============================================================\n");
}


static void
gsm_a_stat_reset(
    void                *tapdata)
{
    gsm_a_stat_t        *stat_p = (gsm_a_stat_t *)tapdata;

    memset(stat_p, 0, sizeof(gsm_a_stat_t));
}


static void
gsm_a_stat_finish(
    void                *tapdata)
{
    gsm_a_stat_t        *stat_p = (gsm_a_stat_t *)tapdata;

    g_free(stat_p);
}


static bool
gsm_a_stat_init(const char *opt_arg _U_, void *userdata _U_)
{
    gsm_a_stat_t        *stat_p;
    GString             *err_p;

    stat_p = g_new(gsm_a_stat_t, 1);

    memset(stat_p, 0, sizeof(gsm_a_stat_t));

    err_p =
        register_tap_listener("gsm_a", stat_p, NULL, TL_REQUIRES_NOTHING,
            gsm_a_stat_reset,
            gsm_a_stat_packet,
            gsm_a_stat_draw,
            gsm_a_stat_finish);

    if (err_p != NULL)
    {
        g_free(stat_p);
        cmdarg_err("Couldn't register gsm_a tap: %s",
                   err_p->str);
        g_string_free(err_p, TRUE);

        return false;
    }

    return true;
}

static stat_tap_ui gsm_a_stat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "gsm_a",
    gsm_a_stat_init,
    0,
    NULL
};

void
register_tap_listener_gsm_astat(void)
{
    register_stat_tap_ui(&gsm_a_stat_ui, NULL);
}
