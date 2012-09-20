/* tap-ansi_astat.c
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
 * This TAP provides statistics for the ANSI A Interface:
 */

#include "config.h"

#include <stdio.h>

#include <string.h>
#include "epan/packet_info.h"
#include "epan/value_string.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/dissectors/packet-bssap.h>
#include <epan/dissectors/packet-ansi_a.h>


typedef struct _ansi_a_stat_t {
    int		bsmap_message_type[0xff];
    int		dtap_message_type[0xff];
} ansi_a_stat_t;


static int
ansi_a_stat_packet(
    void			*tapdata,
    packet_info			*pinfo _U_,
    epan_dissect_t		*edt _U_,
    const void			*data)
{
    ansi_a_stat_t		*stat_p = tapdata;
    const ansi_a_tap_rec_t	*tap_p = data;


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

    i = 0;
    while (ansi_a_ios401_bsmap_strings[i].strptr)
    {
	if (stat_p->bsmap_message_type[ansi_a_ios401_bsmap_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		ansi_a_ios401_bsmap_strings[i].value,
		ansi_a_ios401_bsmap_strings[i].strptr,
		stat_p->bsmap_message_type[ansi_a_ios401_bsmap_strings[i].value]);
	}

	i++;
    }

    printf("\nDTAP\n");
    printf("Message (ID)Type                                        Number\n");

    i = 0;
    while (ansi_a_ios401_dtap_strings[i].strptr)
    {
	if (stat_p->dtap_message_type[ansi_a_ios401_dtap_strings[i].value] > 0)
	{
	    printf("0x%02x  %-50s%d\n",
		ansi_a_ios401_dtap_strings[i].value,
		ansi_a_ios401_dtap_strings[i].strptr,
		stat_p->dtap_message_type[ansi_a_ios401_dtap_strings[i].value]);
	}

	i++;
    }

    printf("==============================================================\n");
}


static void
ansi_a_stat_init(const char *optarg _U_, void* userdata _U_)
{
    ansi_a_stat_t	*stat_p;
    GString		*err_p;

    stat_p = g_malloc(sizeof(ansi_a_stat_t));

    memset(stat_p, 0, sizeof(ansi_a_stat_t));

    err_p =
	register_tap_listener("ansi_a", stat_p, NULL, 0,
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
    register_stat_cmd_arg("ansi_a,", ansi_a_stat_init,NULL);
}
