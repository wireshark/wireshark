/* tap-ansi_astat.c
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * $Id: tap-ansi_astat.c,v 1.1 2003/12/01 23:05:09 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * This TAP provides statistics for the ANSI A Interface:
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include "epan/packet_info.h"
#include "epan/value_string.h"
#include "tap.h"
#include "packet-bssap.h"
#include "packet-ansi_a.h"
#include "register.h"


/*
 * taken from packet-ansi_a.c
 * TODO:
 *	Have these moved from packet-ansi_a.c to packet-ansi_a.h
 *	and then we would automatically get them!
 */
static const value_string ansi_bsmap_strings[] = {
    { 0x69,	"Additional Service Notification" },
    { 0x65,	"ADDS Page" },
    { 0x66,	"ADDS Page Ack" },
    { 0x67,	"ADDS Transfer" },
    { 0x68,	"ADDS Transfer Ack" },
    { 0x02,	"Assignment Complete" },
    { 0x03,	"Assignment Failure" },
    { 0x01,	"Assignment Request" },
    { 0x45,	"Authentication Request" },
    { 0x46,	"Authentication Response" },
    { 0x48,	"Base Station Challenge" },
    { 0x49,	"Base Station Challenge Response" },
    { 0x40,	"Block" },
    { 0x41,	"Block Acknowledge" },
    { 0x09,	"BS Service Request" },
    { 0x0A,	"BS Service Response" },
    { 0x20,	"Clear Command" },
    { 0x21,	"Clear Complete" },
    { 0x22,	"Clear Request" },
    { 0x57,	"Complete Layer 3 Information" },
    { 0x60,	"Feature Notification" },
    { 0x61,	"Feature Notification Ack" },
    { 0x13,	"Handoff Command" },
    { 0x15,	"Handoff Commenced" },
    { 0x14,	"Handoff Complete" },
    { 0x16,	"Handoff Failure" },
    { 0x17,	"Handoff Performed" },
    { 0x10,	"Handoff Request" },
    { 0x12,	"Handoff Request Acknowledge" },
    { 0x11,	"Handoff Required" },
    { 0x1A,	"Handoff Required Reject" },
    { 0x6C,	"PACA Command" },
    { 0x6D,	"PACA Command Ack" },
    { 0x6E,	"PACA Update" },
    { 0x6F,	"PACA Update Ack" },
    { 0x52,	"Paging Request" },
    { 0x53,	"Privacy Mode Command" },
    { 0x55,	"Privacy Mode Complete" },
    { 0x23,	"Radio Measurements for Position Request" },
    { 0x25,	"Radio Measurements for Position Response" },
    { 0x56,	"Rejection" },
    { 0x05,	"Registration Request" },
    { 0x30,	"Reset" },
    { 0x31,	"Reset Acknowledge" },
    { 0x34,	"Reset Circuit" },
    { 0x35,	"Reset Circuit Acknowledge" },
    { 0x47,	"SSD Update Request" },
    { 0x4A,	"SSD Update Response" },
    { 0x6A,	"Status Request" },
    { 0x6B,	"Status Response" },
    { 0x39,	"Transcoder Control Acknowledge" },
    { 0x38,	"Transcoder Control Request" },
    { 0x42,	"Unblock" },
    { 0x43,	"Unblock Acknowledge" },
    { 0x0B,	"User Zone Reject" },
    { 0x04,	"User Zone Update" },
    { 0, NULL },
};

static const value_string ansi_dtap_strings[] = {
    { 0x62,	"Additional Service Request" },
    { 0x53,	"ADDS Deliver" },
    { 0x54,	"ADDS Deliver Ack" },
    { 0x26,	"Alert With Information" },
    { 0x45,	"Authentication Request" },
    { 0x46,	"Authentication Response" },
    { 0x48,	"Base Station Challenge" },
    { 0x49,	"Base Station Challenge Response" },
    { 0x24,	"CM Service Request" },
    { 0x25,	"CM Service Request Continuation" },
    { 0x07,	"Connect" },
    { 0x10,	"Flash with Information" },
    { 0x50,	"Flash with Information Ack" },
    { 0x02,	"Location Updating Accept" },
    { 0x04,	"Location Updating Reject" },
    { 0x08,	"Location Updating Request" },
    { 0x27,	"Paging Response" },
    { 0x2B,	"Parameter Update Confirm" },
    { 0x2C,	"Parameter Update Request" },
    { 0x56,	"Rejection" },
    { 0x03,	"Progress" },
    { 0x70,	"Service Redirection" },
    { 0x2E,	"Service Release" },
    { 0x2F,	"Service Release Complete" },
    { 0x47,	"SSD Update Request" },
    { 0x4A,	"SSD Update Response" },
    { 0x6A,	"Status Request" },
    { 0x6B,	"Status Response" },
    { 0x0B,	"User Zone Reject" },
    { 0x0C,	"User Zone Update" },
    { 0x0D,	"User Zone Update Request" },
    { 0, NULL },
};

#define	ANSI_A_STAT_NUM_IOS401_BSMAP_MSG (sizeof(ansi_bsmap_strings)/sizeof(value_string))
#define	ANSI_A_STAT_NUM_IOS401_DTAP_MSG (sizeof(ansi_dtap_strings)/sizeof(value_string))

typedef struct _ansi_a_stat_t {
    int		bsmap_message_type[0xff];
    int		dtap_message_type[0xff];
} ansi_a_stat_t;


static int
ansi_a_stat_packet(
    void			*tapdata,
    packet_info			*pinfo,
    epan_dissect_t		*edt _U_,
    void			*data)
{
    ansi_a_stat_t		*stat_p = tapdata;
    ansi_a_tap_rec_t		*tap_p = data;


    pinfo = pinfo;

    switch (tap_p->pdu_type)
    {
    case BSSAP_PDU_TYPE_BSMAP:
	stat_p->bsmap_message_type[tap_p->message_type]++;
	break;

    case BSSAP_PDU_TYPE_DTAP:
	stat_p->dtap_message_type[tap_p->message_type]++;
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
ansi_a_stat_draw(
    void		*tapdata)
{
    ansi_a_stat_t	*stat_p = tapdata;
    guint8		i;


    printf("\n");
    printf("=========== ANSI A-i/f Statistics ============================\n");
    printf("BSMAP\n");
    printf("Message (ID)Type                                        Number\n");

    for (i=0; i < ANSI_A_STAT_NUM_IOS401_BSMAP_MSG; i++)
    {
	if (stat_p->bsmap_message_type[ansi_bsmap_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		i,
		ansi_bsmap_strings[i].strptr,
		stat_p->bsmap_message_type[ansi_bsmap_strings[i].value]);
	}
    }

    printf("\nDTAP\n");
    printf("Message (ID)Type                                        Number\n");

    for (i=0; i < ANSI_A_STAT_NUM_IOS401_DTAP_MSG; i++)
    {
	if (stat_p->dtap_message_type[ansi_dtap_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		i,
		ansi_dtap_strings[i].strptr,
		stat_p->dtap_message_type[ansi_dtap_strings[i].value]);
	}
    }

    printf("==============================================================\n");
}


static void
ansi_a_stat_init(char *optarg)
{
    ansi_a_stat_t	*stat_p;
    GString		*err_p;


    optarg = optarg;

    stat_p = g_malloc(sizeof(ansi_a_stat_t));

    memset(stat_p, 0, sizeof(ansi_a_stat_t));

    err_p =
	register_tap_listener("ansi_a", stat_p, NULL,
	    NULL,
	    ansi_a_stat_packet,
	    ansi_a_stat_draw);

    if (err_p != NULL)
    {
	g_free(stat_p);
	g_string_free(err_p, TRUE);

	exit(1);
    }
}


void
register_tap_listener_ansi_astat(void)
{
    register_ethereal_tap("ansi_a,", ansi_a_stat_init);
}
