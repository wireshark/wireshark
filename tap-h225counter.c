/* tap_h225counter.c
 * h225 message counter for ethereal
 * Copyright 2003 Lars Roland
 *
 * $Id: tap-h225counter.c,v 1.1 2003/10/28 00:31:16 guy Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include "epan/packet_info.h"
#include "tap.h"
#include "epan/value_string.h"
#include "register.h"
#include "packet-h225.h"

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



static const value_string RasMessage_vals[] = {
	{ 0, "gatekeeperRequest" },
	{ 1, "gatekeeperConfirm" },
	{ 2, "gatekeeperReject" },
	{ 3, "registrationRequest" },
	{ 4, "registrationConfirm" },
	{ 5, "registrationReject" },
	{ 6, "unregistrationRequest" },
	{ 7, "unregistrationConfirm" },
	{ 8, "unregistrationReject" },
	{ 9, "admissionRequest" },
	{10, "admissionConfirm" },
	{11, "admissionReject" },
	{12, "bandwidthRequest" },
	{13, "bandwidthConfirm" },
	{14, "bandwidthReject" },
	{15, "disengageRequest" },
	{16, "disengageConfirm" },
	{17, "disengageReject" },
	{18, "locationRequest" },
	{19, "locationConfirm" },
	{20, "locationReject" },
	{21, "infoRequest" },
	{22, "infoRequestResponse" },
	{23, "nonStandardMessage" },
	{24, "unknownMessageResponse" },
	{25, "requestInProgress" },
	{26, "resourcesAvailableIndicate" },
	{27, "resourcesAvailableConfirm" },
	{28, "infoRequestAck" },
	{29, "infoRequestNak" },
	{30, "serviceControlIndication" },
	{31, "serviceControlResponse" },
	{32, "admissionConfirmSequence" },
	{ 0, NULL}
};

static const value_string h323_message_body_vals[] = {
	{ 0, "setup" },
	{ 1, "callProceeding" },
	{ 2, "connect" },
	{ 3, "alerting" },
	{ 4, "information" },
	{ 5, "releaseComplete" },
	{ 6, "facility" },
	{ 7, "progress" },
	{ 8, "empty" },
	{ 9, "status" },
	{ 10, "statusInquiry" },
	{ 11, "setupAcknowledge" },
	{ 12, "notify" },
	{ 0, NULL}
};

static const value_string FacilityReason_vals[] = {
	{ 0, "routeCallToGatekeeper" },
	{ 1, "callForwarded" },
	{ 2, "routeCallToMC" },
	{ 3, "undefinedReason" },
	{ 4, "conferenceListChoice" },
	{ 5, "startH245" },
	{ 6, "noH245" },
	{ 7, "newTokens" },
	{ 8, "featureSetUpdate" },
	{ 9, "forwardedElements" },
	{ 10, "transportedInformation" },
	{ 0, NULL}
};

static const value_string GatekeeperRejectReason_vals[] = {
	{ 0, "resourceUnavailable" },
	{ 1, "terminalExcluded" },
	{ 2, "invalidRevision" },
	{ 3, "undefinedReason" },
	{ 4, "securityDenial" },
	{ 5, "genericDataReason" },
	{ 6, "neededFeatureNotSupported" },
	{ 7, "securityError" },
	{ 0, NULL}
};

static const value_string UnregRequestReason_vals[] = {
	{ 0, "reregistrationRequired" },
	{ 1, "ttlExpired" },
	{ 2, "securityDenial" },
	{ 3, "undefinedReason" },
	{ 4, "maintenance" },
	{ 5, "securityError" },
	{ 0, NULL}
};

static const value_string UnregRejectReason_vals[] = {
	{ 0, "notCurrentlyRegistered" },
	{ 1, "callInProgress" },
	{ 2, "undefinedReason" },
	{ 3, "permissionDenied" },
	{ 4, "securityDenial" },
	{ 5, "securityError" },
	{ 0, NULL}
};

static const value_string BandRejectReason_vals[] = {
	{ 0, "notBound" },
	{ 1, "invalidConferenceID" },
	{ 2, "invalidPermission" },
	{ 3, "insufficientResources" },
	{ 4, "invalidRevision" },
	{ 5, "undefinedReason" },
	{ 6, "securityDenial" },
	{ 7, "securityError" },
	{ 0, NULL}
};

static const value_string DisengageReason_vals[] = {
	{ 0, "forcedDrop" },
	{ 1, "normalDrop" },
	{ 2, "undefinedReason" },
	{ 0, NULL}
};

static const value_string DisengageRejectReason_vals[] = {
	{ 0, "notRegistered" },
	{ 1, "requestToDropOther" },
	{ 2, "securityDenial" },
	{ 3, "securityError" },
	{ 0, NULL}
};

static const value_string InfoRequestNakReason_vals[] = {
	{ 0, "notRegistered" },
	{ 1, "securityDenial" },
	{ 2, "undefinedReason" },
	{ 3, "securityError" },
	{ 0, NULL}
};

static const value_string ReleaseCompleteReason_vals[] = {
	{ 0, "noBandwidth" },
	{ 1, "gatekeeperResources" },
	{ 2, "unreachableDestination" },
	{ 3, "destinationRejection" },
	{ 4, "invalidRevision" },
	{ 5, "noPermission" },
	{ 6, "unreachableGatekeeper" },
	{ 7, "gatewayResources" },
	{ 8, "badFormatAddress" },
	{ 9, "adaptiveBusy" },
	{ 10, "inConf" },
	{ 11, "undefinedReason" },
	{ 12, "facilityCallDeflection" },
	{ 13, "securityDenied" },
	{ 14, "calledPartyNotRegistered" },
	{ 15, "callerNotRegistered" },
	{ 16, "newConnectionNeeded" },
	{ 17, "nonStandardReason" },
	{ 18, "replaceWithConferenceInvite" },
	{ 19, "genericDataReason" },
	{ 20, "neededFeatureNotSupported" },
	{ 21, "tunnelledSignallingRejected" },
	{ 22, "invalidCID" },
	{ 23, "invalidCID" },
	{ 24, "securityError" },
	{ 25, "hopCountExceeded" },
	{ 0, NULL}
};

static const value_string AdmissionRejectReason_vals[] = {
	{ 0, "calledPartyNotRegistered" },
	{ 1, "invalidPermission" },
	{ 2, "requestDenied" },
	{ 3, "undefinedReason" },
	{ 4, "callerNotRegistered" },
	{ 5, "routeCallToGatekeeper" },
	{ 6, "invalidEndpointIdentifier" },
	{ 7, "resourceUnavailable" },
	{ 8, "securityDenial" },
	{ 9, "qosControlNotSupported" },
	{ 10, "incompleteAddress" },
	{ 11, "aliasesInconsistent" },
	{ 12, "routeCallToSCN" },
	{ 13, "exceedsCallCapacity" },
	{ 14, "collectDestination" },
	{ 15, "collectPIN" },
	{ 16, "genericDataReason" },
	{ 17, "neededFeatureNotSupported" },
	{ 18, "securityErrors" },
	{ 19, "securityDHmismatch" },
	{ 20, "noRouteToDestination" },
	{ 21, "unallocatedNumber" },
	{ 0, NULL}
};

static const value_string LocationRejectReason_vals[] = {
	{ 0, "notRegistered" },
	{ 1, "invalidPermission" },
	{ 2, "requestDenied" },
	{ 3, "undefinedReason" },
	{ 4, "securityDenial" },
	{ 5, "aliasesInconsistent" },
	{ 6, "routeCalltoSCN" },
	{ 7, "resourceUnavailable" },
	{ 8, "genericDataReason" },
	{ 9, "neededFeatureNotSupported" },
	{10, "hopCountExceeded" },
	{11, "incompleteAddress" },
	{12, "securityError" },
	{13, "securityDHmismatch" },
	{14, "noRouteToDestination" },
	{15, "unallocatedNumber" },
	{ 0, NULL}
};

static const value_string RegistrationRejectReason_vals[] = {
	{ 0, "discoveryRequired" },
	{ 1, "invalidRevision" },
	{ 2, "invalidCallSignalAddress" },
	{ 3, "invalidRASAddress" },
	{ 4, "duplicateAlias" },
	{ 5, "invalidTerminalType" },
	{ 6, "undefinedReason" },
	{ 7, "transportNotSupported" },
	{ 8, "transportQOSNotSupported" },
	{ 9, "resourceUnavailable" },
	{ 10, "invalidAlias" },
	{ 11, "securityDenial" },
	{ 12, "fullRegistrationRequired" },
	{ 13, "additiveRegistrationNotSupported" },
	{ 14, "invalidTerminalAliases" },
	{ 15, "genericDataReason" },
	{ 16, "neededFeatureNotSupported" },
	{ 17, "securityError" },
	{ 0, NULL}
};

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
h225counter_packet(void *phs, packet_info *pinfo _U_, epan_dissect_t *edt _U_, void *phi)
{
	h225counter_t *hs=(h225counter_t *)phs;
	h225_packet_info *pi=phi;

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
			printf("  %s : %u\n", val_to_str(i,h323_message_body_vals,"unknown cs-messages   "), hs->cs_msg[i]);
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
h225counter_init(char *optarg)
{
	h225counter_t *hs;
	char *filter=NULL;
	GString *error_string;

	if(!strncmp(optarg,"h225,counter,",13)){
		filter=optarg+13;
	} else {
		filter=g_malloc(1);
		*filter='\0';
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

		fprintf(stderr, "tethereal: Couldn't register h225,counter tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_h225counter(void)
{
	register_ethereal_tap("h225,counter", h225counter_init);
}
