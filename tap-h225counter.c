/* tap_h225counter.c
 * h225 message counter for wireshark
 * Copyright 2003 Lars Roland
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include "epan/value_string.h"
#include "register.h"
#include <epan/dissectors/packet-h225.h>

/* following values represent the size of their valuestring arrays */

#define RAS_MSG_TYPES 33
#define CS_MSG_TYPES 13

#define GRJ_REASONS 8
#define RRJ_REASONS 18
#define URQ_REASONS 6
#define URJ_REASONS 6
#define ARJ_REASONS 22
#define BRJ_REASONS 8
#define DRQ_REASONS 3
#define DRJ_REASONS 4
#define LRJ_REASONS 16
#define IRQNAK_REASONS 4
#define REL_CMP_REASONS 26
#define FACILITY_REASONS 11


/* used to keep track of the statistics for an entire program interface */
typedef struct _h225counter_t {
	char *filter;
	guint32 ras_msg[RAS_MSG_TYPES + 1];
        guint32 cs_msg[CS_MSG_TYPES + 1];
        guint32 grj_reason[GRJ_REASONS + 1];
        guint32 rrj_reason[RRJ_REASONS + 1];
        guint32 urq_reason[URQ_REASONS + 1];
        guint32 urj_reason[URJ_REASONS + 1];
        guint32 arj_reason[ARJ_REASONS + 1];
        guint32 brj_reason[BRJ_REASONS + 1];
        guint32 drq_reason[DRQ_REASONS + 1];
        guint32 drj_reason[DRJ_REASONS + 1];
        guint32 lrj_reason[LRJ_REASONS + 1];
        guint32 irqnak_reason[IRQNAK_REASONS + 1];
        guint32 rel_cmp_reason[REL_CMP_REASONS + 1];
        guint32 facility_reason[FACILITY_REASONS + 1];
} h225counter_t;


static void
h225counter_reset(void *phs)
{
	h225counter_t *hs=(h225counter_t *)phs;
	int i;

	for(i=0;i<=RAS_MSG_TYPES;i++) {
		hs->ras_msg[i] = 0;
	}
	for(i=0;i<=CS_MSG_TYPES;i++) {
		hs->cs_msg[i] = 0;
	}
	for(i=0;i<=GRJ_REASONS;i++) {
		hs->grj_reason[i] = 0;
	}
	for(i=0;i<=RRJ_REASONS;i++) {
		hs->rrj_reason[i] = 0;
	}
	for(i=0;i<=URQ_REASONS;i++) {
		hs->urq_reason[i] = 0;
	}
	for(i=0;i<=URJ_REASONS;i++) {
		hs->urj_reason[i] = 0;
	}
	for(i=0;i<=ARJ_REASONS;i++) {
		hs->arj_reason[i] = 0;
	}
	for(i=0;i<=BRJ_REASONS;i++) {
		hs->brj_reason[i] = 0;
	}
	for(i=0;i<=DRQ_REASONS;i++) {
		hs->drq_reason[i] = 0;
	}
	for(i=0;i<=DRJ_REASONS;i++) {
		hs->drj_reason[i] = 0;
	}
	for(i=0;i<=LRJ_REASONS;i++) {
		hs->lrj_reason[i] = 0;
	}
	for(i=0;i<=IRQNAK_REASONS;i++) {
		hs->irqnak_reason[i] = 0;
	}
	for(i=0;i<=REL_CMP_REASONS;i++) {
		hs->rel_cmp_reason[i] = 0;
	}
	for(i=0;i<=FACILITY_REASONS;i++) {
		hs->facility_reason[i] = 0;
	}
}

static int
h225counter_packet(void *phs, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *phi)
{
	h225counter_t *hs=(h225counter_t *)phs;
	const h225_packet_info *pi=phi;

	switch (pi->msg_type) {

	case H225_RAS:
		if(pi->msg_tag==-1) { /* uninitialized */
			return 0;
		}
		else if (pi->msg_tag >= RAS_MSG_TYPES) { /* unknown */
			hs->ras_msg[RAS_MSG_TYPES]++;
		}
		else {
			hs->ras_msg[pi->msg_tag]++;
		}

		/* Look for reason tag */
		if(pi->reason==-1) { /* uninitialized */
			break;
		}

		switch(pi->msg_tag) {

		case 2:	/* GRJ */
			if(pi->reason < GRJ_REASONS)
				hs->grj_reason[pi->reason]++;
			else
				hs->grj_reason[GRJ_REASONS]++;
			break;
		case 5:	/* RRJ */
			if(pi->reason < RRJ_REASONS)
				hs->rrj_reason[pi->reason]++;
			else
				hs->rrj_reason[RRJ_REASONS]++;
			break;
		case 6:	/* URQ */
			if(pi->reason < URQ_REASONS)
				hs->urq_reason[pi->reason]++;
			else
				hs->urq_reason[URQ_REASONS]++;
			break;
		case 8:	/* URJ */
			if(pi->reason < URJ_REASONS)
				hs->urj_reason[pi->reason]++;
			else
				hs->urj_reason[URJ_REASONS]++;
			break;
		case 11: /* ARJ */
			if(pi->reason < ARJ_REASONS)
				hs->arj_reason[pi->reason]++;
			else
				hs->arj_reason[ARJ_REASONS]++;
			break;
		case 14: /* BRJ */
			if(pi->reason < BRJ_REASONS)
				hs->brj_reason[pi->reason]++;
			else
				hs->brj_reason[BRJ_REASONS]++;
			break;
		case 15: /* DRQ */
			if(pi->reason < DRQ_REASONS)
				hs->drq_reason[pi->reason]++;
			else
				hs->drq_reason[DRQ_REASONS]++;
			break;
		case 17: /* DRJ */
			if(pi->reason < DRJ_REASONS)
				hs->drj_reason[pi->reason]++;
			else
				hs->drj_reason[DRJ_REASONS]++;
			break;
		case 20: /* LRJ */
			if(pi->reason < LRJ_REASONS)
				hs->lrj_reason[pi->reason]++;
			else
				hs->lrj_reason[LRJ_REASONS]++;
			break;
		case 29: /* IRQ Nak */
			if(pi->reason < IRQNAK_REASONS)
				hs->irqnak_reason[pi->reason]++;
			else
				hs->irqnak_reason[IRQNAK_REASONS]++;
			break;

		default:
			/* do nothing */
			break;
		}

		break;

	case H225_CS:
		if(pi->msg_tag==-1) { /* uninitialized */
			return 0;
		}
		else if (pi->msg_tag >= CS_MSG_TYPES) { /* unknown */
			hs->cs_msg[CS_MSG_TYPES]++;
		}
		else {
			hs->cs_msg[pi->msg_tag]++;
		}

		/* Look for reason tag */
		if(pi->reason==-1) { /* uninitialized */
			break;
		}

		switch(pi->msg_tag) {

		case 5:	/* ReleaseComplete */
			if(pi->reason < REL_CMP_REASONS)
				hs->rel_cmp_reason[pi->reason]++;
			else
				hs->rel_cmp_reason[REL_CMP_REASONS]++;
			break;
		case 6:	/* Facility */
			if(pi->reason < FACILITY_REASONS)
				hs->facility_reason[pi->reason]++;
			else
				hs->facility_reason[FACILITY_REASONS]++;
			break;
		default:
			/* do nothing */
			break;
		}

		break;

	default:
		return 0;
		break;
	}

	return 1;
}


static void
h225counter_draw(void *phs)
{
	h225counter_t *hs=(h225counter_t *)phs;
	int i,j;

	printf("================== H225 Message and Reason Counter ==================\n");
	printf("RAS-Messages:\n");
	for(i=0;i<=RAS_MSG_TYPES;i++) {
		if(hs->ras_msg[i]!=0) {
			printf("  %s : %u\n", val_to_str(i,RasMessage_vals,"unknown ras-messages  "), hs->ras_msg[i]);
			/* reason counter */
			switch(i) {
			case 2: /* GRJ */
				for(j=0;j<=GRJ_REASONS;j++) {
					if(hs->grj_reason[j]!=0) {
						printf("    %s : %u\n", val_to_str(j,GatekeeperRejectReason_vals,"unknown reason   "), hs->grj_reason[j]);
					}
				}
				break;
			case 5: /* RRJ */
				for(j=0;j<=RRJ_REASONS;j++) {
					if(hs->rrj_reason[j]!=0) {
						printf("    %s : %u\n", val_to_str(j,RegistrationRejectReason_vals,"unknown reason   "), hs->rrj_reason[j]);
					}
				}
				break;
			case 6: /* URQ */
				for(j=0;j<=URQ_REASONS;j++) {
					if(hs->urq_reason[j]!=0) {
						printf("    %s : %u\n", val_to_str(j,UnregRequestReason_vals,"unknown reason   "), hs->urq_reason[j]);
					}
				}
				break;
			case 8: /* URJ */
				for(j=0;j<=URJ_REASONS;j++) {
					if(hs->urj_reason[j]!=0) {
						printf("    %s : %u\n", val_to_str(j,UnregRejectReason_vals,"unknown reason   "), hs->urj_reason[j]);
					}
				}
				break;
			case 11: /* ARJ */
				for(j=0;j<=ARJ_REASONS;j++) {
					if(hs->arj_reason[j]!=0) {
						printf("    %s : %u\n", val_to_str(j,AdmissionRejectReason_vals,"unknown reason   "), hs->arj_reason[j]);
					}
				}
				break;
			case 14: /* BRJ */
				for(j=0;j<=BRJ_REASONS;j++) {
					if(hs->brj_reason[j]!=0) {
						printf("    %s : %u\n", val_to_str(j,BandRejectReason_vals,"unknown reason   "), hs->brj_reason[j]);
					}
				}
				break;
			case 15: /* DRQ */
				for(j=0;j<=DRQ_REASONS;j++) {
					if(hs->drq_reason[j]!=0) {
						printf("    %s : %u\n", val_to_str(j,DisengageReason_vals,"unknown reason   "), hs->drq_reason[j]);
					}
				}
				break;
			case 17: /* DRJ */
				for(j=0;j<=DRJ_REASONS;j++) {
					if(hs->drj_reason[j]!=0) {
						printf("    %s : %u\n", val_to_str(j,DisengageRejectReason_vals,"unknown reason   "), hs->drj_reason[j]);
					}
				}
				break;
			case 20: /* LRJ */
				for(j=0;j<=LRJ_REASONS;j++) {
					if(hs->lrj_reason[j]!=0) {
						printf("    %s : %u\n", val_to_str(j,LocationRejectReason_vals,"unknown reason   "), hs->lrj_reason[j]);
					}
				}
			case 29: /* IRQNak */
				for(j=0;j<=IRQNAK_REASONS;j++) {
					if(hs->irqnak_reason[j]!=0) {
						printf("    %s : %u\n", val_to_str(j,InfoRequestNakReason_vals,"unknown reason   "), hs->irqnak_reason[j]);
					}
				}
				break;
			default:
				break;
			}
			/* end of reason counter*/
		}
	}
	printf("Call Signalling:\n");
	for(i=0;i<=CS_MSG_TYPES;i++) {
		if(hs->cs_msg[i]!=0) {
			printf("  %s : %u\n", val_to_str(i,T_h323_message_body_vals,"unknown cs-messages   "), hs->cs_msg[i]);
			/* reason counter */
			switch(i) {
			case 5: /* ReleaseComplete */
				for(j=0;j<=REL_CMP_REASONS;j++) {
					if(hs->rel_cmp_reason[j]!=0) {
						printf("    %s : %u\n", val_to_str(j,ReleaseCompleteReason_vals,"unknown reason   "), hs->rel_cmp_reason[j]);
					}
				}
				break;
			case 6: /* Facility */
				for(j=0;j<=FACILITY_REASONS;j++) {
					if(hs->facility_reason[j]!=0) {
						printf("    %s : %u\n", val_to_str(j,FacilityReason_vals,"unknown reason   "), hs->facility_reason[j]);
					}
				}
				break;
			default:
				break;
			}
		}
	}
        printf("=====================================================================\n");
}


static void
h225counter_init(const char *optarg, void* userdata _U_)
{
	h225counter_t *hs;
	const char *filter=NULL;
	GString *error_string;

	if(!strncmp(optarg,"h225,counter,",13)){
		filter=optarg+13;
	} else {
		filter="";
	}

	hs = g_malloc(sizeof(h225counter_t));
	hs->filter=g_malloc(strlen(filter)+1);
	strcpy(hs->filter, filter);

	h225counter_reset(hs);

    	error_string=register_tap_listener("h225", hs, filter, NULL, h225counter_packet, h225counter_draw);
    	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(hs->filter);
		g_free(hs);

		fprintf(stderr, "twireshark: Couldn't register h225,counter tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_h225counter(void)
{
	register_stat_cmd_arg("h225,counter", h225counter_init,NULL);
}
