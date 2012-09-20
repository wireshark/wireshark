/* tap-gsm_astat.c
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * $Id$
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

/*
 * This TAP provides statistics for the GSM A Interface:
 */

#include "config.h"

#include <stdio.h>

#include <string.h>
#include "epan/packet_info.h"
#include "epan/value_string.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/dissectors/packet-bssap.h>
#include <epan/dissectors/packet-gsm_a_common.h>


typedef struct _gsm_a_stat_t {
    int		bssmap_message_type[0xff];
    int		dtap_mm_message_type[0xff];
    int		dtap_rr_message_type[0xff];
    int		dtap_cc_message_type[0xff];
    int		dtap_gmm_message_type[0xff];
    int		dtap_sms_message_type[0xff];
    int		dtap_sm_message_type[0xff];
    int		dtap_ss_message_type[0xff];
    int		dtap_tp_message_type[0xff];
    int		sacch_rr_message_type[0xff];
} gsm_a_stat_t;


static int
gsm_a_stat_packet(
    void			*tapdata,
    packet_info			*pinfo _U_,
    epan_dissect_t		*edt _U_,
    const void			*data)
{
    gsm_a_stat_t		*stat_p = tapdata;
    const gsm_a_tap_rec_t	*tap_p = data;

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
	    return(0);
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
	return(0);
    }

    return(1);
}


static void
gsm_a_stat_draw(
    void		*tapdata)
{
    gsm_a_stat_t	*stat_p = tapdata;
    guint8		i;


    printf("\n");
    printf("=========== GS=M A-i/f Statistics ============================\n");
    printf("BSSMAP\n");
    printf("Message (ID)Type                                        Number\n");

    i = 0;
    while (gsm_a_bssmap_msg_strings[i].strptr)
    {
	if (stat_p->bssmap_message_type[gsm_a_bssmap_msg_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		gsm_a_bssmap_msg_strings[i].value,
		gsm_a_bssmap_msg_strings[i].strptr,
		stat_p->bssmap_message_type[gsm_a_bssmap_msg_strings[i].value]);
	}

	i++;
    }

    printf("\nDTAP %s\n", gsm_a_pd_str[PD_MM]);
    printf("Message (ID)Type                                        Number\n");

    i = 0;
    while (gsm_a_dtap_msg_mm_strings[i].strptr)
    {
	if (stat_p->dtap_mm_message_type[gsm_a_dtap_msg_mm_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		gsm_a_dtap_msg_mm_strings[i].value,
		gsm_a_dtap_msg_mm_strings[i].strptr,
		stat_p->dtap_mm_message_type[gsm_a_dtap_msg_mm_strings[i].value]);
	}

	i++;
    }

    printf("\nDTAP %s\n", gsm_a_pd_str[PD_RR]);
    printf("Message (ID)Type                                        Number\n");

    i = 0;
    while (gsm_a_dtap_msg_rr_strings[i].strptr)
    {
	if (stat_p->dtap_rr_message_type[gsm_a_dtap_msg_rr_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		gsm_a_dtap_msg_rr_strings[i].value,
		gsm_a_dtap_msg_rr_strings[i].strptr,
		stat_p->dtap_rr_message_type[gsm_a_dtap_msg_rr_strings[i].value]);
	}

	i++;
    }

    printf("\nDTAP %s\n", gsm_a_pd_str[PD_CC]);
    printf("Message (ID)Type                                        Number\n");

    i = 0;
    while (gsm_a_dtap_msg_cc_strings[i].strptr)
    {
	if (stat_p->dtap_cc_message_type[gsm_a_dtap_msg_cc_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		gsm_a_dtap_msg_cc_strings[i].value,
		gsm_a_dtap_msg_cc_strings[i].strptr,
		stat_p->dtap_cc_message_type[gsm_a_dtap_msg_cc_strings[i].value]);
	}

	i++;
    }

    printf("\nDTAP %s\n", gsm_a_pd_str[PD_GMM]);
    printf("Message (ID)Type                                        Number\n");

    i = 0;
    while (gsm_a_dtap_msg_gmm_strings[i].strptr)
    {
	if (stat_p->dtap_gmm_message_type[gsm_a_dtap_msg_gmm_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		gsm_a_dtap_msg_gmm_strings[i].value,
		gsm_a_dtap_msg_gmm_strings[i].strptr,
		stat_p->dtap_gmm_message_type[gsm_a_dtap_msg_gmm_strings[i].value]);
	}

	i++;
    }

    printf("\nDTAP %s\n", gsm_a_pd_str[PD_SMS]);
    printf("Message (ID)Type                                        Number\n");

    i = 0;
    while (gsm_a_dtap_msg_sms_strings[i].strptr)
    {
	if (stat_p->dtap_sms_message_type[gsm_a_dtap_msg_sms_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		gsm_a_dtap_msg_sms_strings[i].value,
		gsm_a_dtap_msg_sms_strings[i].strptr,
		stat_p->dtap_sms_message_type[gsm_a_dtap_msg_sms_strings[i].value]);
	}

	i++;
    }

    printf("\nDTAP %s\n", gsm_a_pd_str[PD_SM]);
    printf("Message (ID)Type                                        Number\n");

    i = 0;
    while (gsm_a_dtap_msg_sm_strings[i].strptr)
    {
	if (stat_p->dtap_sm_message_type[gsm_a_dtap_msg_sm_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		gsm_a_dtap_msg_sm_strings[i].value,
		gsm_a_dtap_msg_sm_strings[i].strptr,
		stat_p->dtap_sm_message_type[gsm_a_dtap_msg_sm_strings[i].value]);
	}

	i++;
    }

    printf("\nDTAP %s\n", gsm_a_pd_str[PD_SS]);
    printf("Message (ID)Type                                        Number\n");

    i = 0;
    while (gsm_a_dtap_msg_ss_strings[i].strptr)
    {
	if (stat_p->dtap_ss_message_type[gsm_a_dtap_msg_ss_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		gsm_a_dtap_msg_ss_strings[i].value,
		gsm_a_dtap_msg_ss_strings[i].strptr,
		stat_p->dtap_ss_message_type[gsm_a_dtap_msg_ss_strings[i].value]);
	}

	i++;
    }

    printf("\nDTAP %s\n", gsm_a_pd_str[PD_TP]);
    printf("Message (ID)Type                                        Number\n");

    i = 0;
    while (gsm_a_dtap_msg_tp_strings[i].strptr)
    {
	if (stat_p->dtap_tp_message_type[gsm_a_dtap_msg_tp_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		gsm_a_dtap_msg_tp_strings[i].value,
		gsm_a_dtap_msg_tp_strings[i].strptr,
		stat_p->dtap_tp_message_type[gsm_a_dtap_msg_tp_strings[i].value]);
	}

	i++;
    }

    printf("\nSACCH Radio Resources Management messages\n");
    printf("Message (ID)Type                                        Number\n");

    i = 0;
    while (gsm_a_rr_short_pd_msg_strings[i].strptr)
    {
	if (stat_p->sacch_rr_message_type[gsm_a_rr_short_pd_msg_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		gsm_a_rr_short_pd_msg_strings[i].value,
		gsm_a_rr_short_pd_msg_strings[i].strptr,
		stat_p->sacch_rr_message_type[gsm_a_rr_short_pd_msg_strings[i].value]);
	}

	i++;
    }

    printf("==============================================================\n");
}


static void
gsm_a_stat_init(const char *optarg _U_,void* userdata _U_)
{
    gsm_a_stat_t	*stat_p;
    GString		*err_p;

    stat_p = g_malloc(sizeof(gsm_a_stat_t));

    memset(stat_p, 0, sizeof(gsm_a_stat_t));

    err_p =
	register_tap_listener("gsm_a", stat_p, NULL, 0,
	    NULL,
	    gsm_a_stat_packet,
	    gsm_a_stat_draw);

    if (err_p != NULL)
    {
	g_free(stat_p);
	g_string_free(err_p, TRUE);

	exit(1);
    }
}


void
register_tap_listener_gsm_astat(void)
{
    register_stat_cmd_arg("gsm_a,", gsm_a_stat_init,NULL);
}
