/*
 * camel-persistentdata.c
 * Source for lists and hash tables used in wireshark's camel dissector
 * for calculation of delays in camel calls
 * Copyright 2006 Florent Drouin
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

#include <glib.h>
#include <stdio.h>
#include <string.h>

#include <epan/emem.h>
#include "epan/packet.h"
#include "epan/conversation.h"
#include "epan/camel-persistentdata.h"
#include "epan/dissectors/packet-tcap.h"
#include "epan/dissectors/packet-mtp3.h"

static gint camelsrt_call_equal(gconstpointer k1, gconstpointer k2);
static guint camelsrt_call_hash(gconstpointer k);
static struct camelsrt_call_t * find_camelsrt_call(struct camelsrt_call_info_key_t * p_camelsrt_call_key,
						   packet_info *pinfo);
static struct camelsrt_call_t * new_camelsrt_call(struct camelsrt_call_info_key_t * p_camelsrt_call_key,
						  packet_info *pinfo);

static void update_camelsrt_call(struct camelsrt_call_t * p_camelsrt_call,
				 packet_info *pinfo,
				 guint msg_category _U_);

static struct camelsrt_call_t * append_camelsrt_call(struct camelsrt_call_t * prev_call,
						     packet_info *pinfo);

static void camelsrt_begin_call_matching(tvbuff_t *tvb,
					 packet_info * pinfo _U_,
					 proto_tree *tree,
					 struct camelsrt_info_t * p_camelsrt_info);

static void camelsrt_request_call_matching(tvbuff_t *tvb,
					   packet_info * pinfo _U_,
					   proto_tree *tree,
					   struct camelsrt_info_t * p_camelsrt_info,
					   guint srt_type);

static void camelsrt_report_call_matching(tvbuff_t *tvb,
					  packet_info * pinfo _U_,
					  proto_tree *tree,
					  struct camelsrt_info_t * p_camelsrt_info,
					  guint srt_type);

static void camelsrt_close_call_matching(tvbuff_t *tvb,
					 packet_info * pinfo _U_,
					 proto_tree *tree,
					 struct camelsrt_info_t * p_camelsrt_info);

static void camelsrt_display_DeltaTime(proto_tree *tree,
				       tvbuff_t *tvb,
				       nstime_t* value_ptr,
				       guint category);

static void raz_camelsrt_call (struct camelsrt_call_t * p_camelsrt_call);

void camelsrt_tcap_matching(tvbuff_t *tvb,
			    packet_info * pinfo _U_,
			    proto_tree *tree,
			    struct tcaphash_context_t * tcap_context);

/* When several Camel components are received in a single TCAP message,
   we have to use several buffers for the stored parameters
   because else this data are erased during TAP dissector call */
#define MAX_CAMEL_INSTANCE 10
int camelsrt_global_current=0;
struct camelsrt_info_t camelsrt_global_info[MAX_CAMEL_INSTANCE];

/* Configuration parameters to enable or disable the Service Response Time */
extern gboolean gcamel_HandleSRT;
gboolean gcamel_PersistentSRT=FALSE;
gboolean gcamel_DisplaySRT=FALSE;
gboolean gcamel_StatSRT=FALSE;

extern int camel_tap;

extern int hf_camelsrt_SessionId;
extern int hf_camelsrt_RequestNumber;
extern int hf_camelsrt_Duplicate;
extern int hf_camelsrt_RequestFrame;
extern int hf_camelsrt_ResponseFrame;
extern int hf_camelsrt_DeltaTime;
extern int hf_camelsrt_SessionTime;
extern int hf_camelsrt_DeltaTime31;
extern int hf_camelsrt_DeltaTime75;
extern int hf_camelsrt_DeltaTime65;
extern int hf_camelsrt_DeltaTime22;
extern int hf_camelsrt_DeltaTime35;
extern int hf_camelsrt_DeltaTime80;

/* Global hash tables*/
static GHashTable *srt_calls = NULL;
guint32 camelsrt_global_SessionId=1;

/*
 * DEBUG fonctions
 */

#undef DEBUG_CAMELSRT
/* #define DEBUG_CAMELSRT */

#ifdef DEBUG_CAMELSRT
#include <stdio.h>
#include <stdarg.h>
static unsigned debug_level = 99;

static void dbg(unsigned  level, char* fmt, ...) {
  va_list ap;
  
  if (level > debug_level) return;
  va_start(ap,fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}
#endif

/*
 * Functions needed for Hash-Table
 */

/* compare 2 keys */
static gint camelsrt_call_equal(gconstpointer k1, gconstpointer k2)
{
  const struct camelsrt_call_info_key_t * key1 = (const struct camelsrt_call_info_key_t *) k1;
  const struct camelsrt_call_info_key_t * key2 = (const struct camelsrt_call_info_key_t *) k2;
  
  return (key1->SessionIdKey == key2->SessionIdKey) ;
}

/* calculate a hash key */
static guint camelsrt_call_hash(gconstpointer k)
{
  const struct camelsrt_call_info_key_t * key = (const struct camelsrt_call_info_key_t *) k;
  return key->SessionIdKey;
}

/* 
 * Find the dialog by Key and Time 
 */
static struct camelsrt_call_t * find_camelsrt_call(struct camelsrt_call_info_key_t * p_camelsrt_call_key,
						   packet_info *pinfo)
{
  struct camelsrt_call_t * p_camelsrt_call = NULL;
  p_camelsrt_call = (struct camelsrt_call_t *)g_hash_table_lookup(srt_calls, p_camelsrt_call_key);

  if(p_camelsrt_call) {
#ifdef DEBUG_CAMELSRT
    dbg(10,"D%d ", p_camelsrt_call->session_id);
#endif
  } else {
#ifdef DEBUG_CAMELSRT
    dbg(23,"Not in hash ");
#endif  
  }

  return p_camelsrt_call;
}

/*
 * New record to create, to identify a new transaction 
 */
static struct camelsrt_call_t * new_camelsrt_call(struct camelsrt_call_info_key_t * p_camelsrt_call_key,
						  packet_info *pinfo)
  
{
  struct camelsrt_call_info_key_t * p_new_camelsrt_call_key;
  struct camelsrt_call_t * p_new_camelsrt_call = NULL;
  
  /* Register the transaction in the hash table 
     with the tcap transaction Id as main Key
     Once created, this entry will be updated later */

  p_new_camelsrt_call_key = se_alloc(sizeof(struct camelsrt_call_info_key_t));
  p_new_camelsrt_call_key->SessionIdKey = p_camelsrt_call_key->SessionIdKey;
  p_new_camelsrt_call = se_alloc(sizeof(struct camelsrt_call_t));
  raz_camelsrt_call(p_new_camelsrt_call);
  p_new_camelsrt_call->session_id = camelsrt_global_SessionId++;
#ifdef DEBUG_CAMELSRT
  dbg(10,"D%d ", p_new_camelsrt_call->session_id);
#endif
  /* store it */
  g_hash_table_insert(srt_calls, p_new_camelsrt_call_key, p_new_camelsrt_call);
  return p_new_camelsrt_call;
}

/* 
 * Update a record with the data of the Request 
 */
static void update_camelsrt_call(struct camelsrt_call_t * p_camelsrt_call,
				 packet_info *pinfo,
				 guint msg_category _U_)
{
  p_camelsrt_call->category[msg_category].req_num = pinfo->fd->num;
  p_camelsrt_call->category[msg_category].rsp_num = 0;
  p_camelsrt_call->category[msg_category].responded = FALSE;
  p_camelsrt_call->category[msg_category].req_time = pinfo->fd->abs_ts;
}


/*
 * Routine called when the TAP is initialized.
 * so hash table are (re)created
 */
void camelsrt_init_routine(void)
{

  /* free hash-tables and mem_chunks for SRT */
  if (srt_calls != NULL) {
#ifdef DEBUG_CAMELSRT
    dbg(16,"Destroy hash ");
#endif
    g_hash_table_destroy(srt_calls);
  }
  
  /* create new hash-tables and mem_chunks for SRT */
  srt_calls = g_hash_table_new(camelsrt_call_hash, camelsrt_call_equal);
#ifdef DEBUG_CAMELSRT
  dbg(16,"Create hash ");
#endif
  /* Reset the session counter */
  camelsrt_global_SessionId=1;

  /* The Display of SRT is enable 
   * 1) For wireshark only if Persistent Stat is enable
   * 2) For Tshark, if the SRT handling is enable
   */
  gcamel_DisplaySRT=gcamel_PersistentSRT || gcamel_HandleSRT&gcamel_StatSRT;
}

/*
 * Service Response Time analyze, called just after the camel dissector
 * According to the camel operation, we 
 * - open/close a context for the camel session
 * - look for a request, or look for the corresponding response 
 */
void camelsrt_call_matching(tvbuff_t *tvb,
			    packet_info * pinfo _U_,
			    proto_tree *tree,
			    struct camelsrt_info_t * p_camelsrt_info)
{ 

#ifdef DEBUG_CAMELSRT
  dbg(10,"tcap_session #%d ", p_camelsrt_info->tcap_session_id);
#endif
  
  switch (p_camelsrt_info->opcode) {

  case 0:  /*InitialDP*/
    camelsrt_begin_call_matching(tvb, pinfo, tree, p_camelsrt_info);
    camelsrt_request_call_matching(tvb, pinfo, tree, p_camelsrt_info,
				   CAMELSRT_VOICE_INITIALDP);
    break;
  case 60: /*InitialDPSMS*/
    camelsrt_begin_call_matching(tvb, pinfo, tree, p_camelsrt_info);
    camelsrt_request_call_matching(tvb, pinfo, tree, p_camelsrt_info,
				   CAMELSRT_SMS_INITIALDP); 
    break;
  case 78: /*InitialDPGPRS*/
    camelsrt_begin_call_matching(tvb, pinfo, tree, p_camelsrt_info);
    camelsrt_request_call_matching(tvb, pinfo, tree, p_camelsrt_info,
				   CAMELSRT_GPRS_INITIALDP); 
    break;

  case 23: /*RequestReportBCSMEvent*/
    break;

  case 63: /*RequestReportSMSEvent*/
    break;

  case 81: /*RequestReportGPRSEvent*/
    break;

  case 24: /*EventReportBCSMEvent*/
    camelsrt_request_call_matching(tvb, pinfo, tree, p_camelsrt_info,
				   CAMELSRT_VOICE_DISC );
    break;
    
  case 64: /*EventReportSMS*/
    /* Session has been explicity closed without TC_END */
    camelsrt_close_call_matching(tvb, pinfo, tree, p_camelsrt_info);
    tcapsrt_close(p_camelsrt_info->tcap_context, pinfo);
    break;
    
  case 80: /*EventReportGPRS*/
    camelsrt_begin_call_matching(tvb, pinfo, tree, p_camelsrt_info);
    camelsrt_request_call_matching(tvb, pinfo, tree, p_camelsrt_info,
				   CAMELSRT_GPRS_REPORT);
    break;
    
  case 35: /*ApplyCharging*/
    camelsrt_report_call_matching(tvb, pinfo, tree, p_camelsrt_info,
				  CAMELSRT_VOICE_ACR1 ); 
    break;
    
  case 71: /*ApplyChargingGPRS*/
    break;
    
  case 36: /*ApplyChargingReport*/
    camelsrt_request_call_matching(tvb, pinfo, tree, p_camelsrt_info,
				   CAMELSRT_VOICE_ACR1 );
    break;
    
  case 72: /*ApplyChargingReportGPRS*/
    break;
    
  case 31: /*Continue*/
    camelsrt_report_call_matching(tvb, pinfo, tree, p_camelsrt_info,
    				  CAMELSRT_VOICE_INITIALDP);
    break;
  case 65: /*ContinueSMS*/
    camelsrt_report_call_matching(tvb, pinfo, tree, p_camelsrt_info,
				  CAMELSRT_SMS_INITIALDP);
    break;
  case 75: /*ContinueGPRS*/
    camelsrt_report_call_matching(tvb, pinfo, tree, p_camelsrt_info,
				  CAMELSRT_GPRS_INITIALDP);
    camelsrt_report_call_matching(tvb, pinfo, tree, p_camelsrt_info,
				  CAMELSRT_GPRS_REPORT);
    break;

  case 22: /*ReleaseCall*/
    camelsrt_report_call_matching(tvb, pinfo, tree, p_camelsrt_info,
    				  CAMELSRT_VOICE_DISC);
    /* Session has been closed by Network */
    camelsrt_close_call_matching(tvb, pinfo, tree, p_camelsrt_info);
    break;

  case 66: /*ReleaseSMS*/
    /* Session has been closed by Network */
    camelsrt_close_call_matching(tvb, pinfo, tree, p_camelsrt_info); 
    tcapsrt_close(p_camelsrt_info->tcap_context,pinfo);
    break;

  case 79: /*ReleaseGPRS*/
    /* Session has been closed by Network */
    camelsrt_close_call_matching(tvb, pinfo, tree, p_camelsrt_info);
    break;
  } /* switch opcode */
}

/*
 * Callback function for the TCAP dissector
 * This callback function is used to inform the camel layer, that the session 
 * has been Closed or Aborted by a TCAP message without Camel component
 * So, we can close the context for camel session, and update the stats.
 */
void camelsrt_tcap_matching(tvbuff_t *tvb,
			    packet_info * pinfo _U_,
			    proto_tree *tree,
			    struct tcaphash_context_t * p_tcap_context)
{  
  struct camelsrt_info_t * p_camelsrt_info;
  
#ifdef DEBUG_CAMELSRT
  dbg(11,"Camel_CallBack ");
#endif
  p_camelsrt_info=camelsrt_razinfo();
  
  p_camelsrt_info->tcap_context=p_tcap_context; 
  if (p_tcap_context) {
#ifdef DEBUG_CAMELSRT
    dbg(11,"Close TCAP ");
#endif
    p_camelsrt_info->tcap_session_id = p_tcap_context->session_id;
    camelsrt_close_call_matching(tvb, pinfo, tree, p_camelsrt_info);
    tap_queue_packet(camel_tap, pinfo, p_camelsrt_info);
  }
}


/* 
 * Create the record identifiying the Camel session
 * As the Tcap session id given by the TCAP dissector is uniq, it will be
 * used as main key.
 */
static void camelsrt_begin_call_matching(tvbuff_t *tvb,
					 packet_info * pinfo _U_,
					 proto_tree *tree,
					 struct camelsrt_info_t * p_camelsrt_info)
{
  struct camelsrt_call_t * p_camelsrt_call;
  struct camelsrt_call_info_key_t camelsrt_call_key;

  p_camelsrt_info->bool_msginfo[CAMELSRT_SESSION]=TRUE;
  
  /* prepare the key data */  
  camelsrt_call_key.SessionIdKey = p_camelsrt_info->tcap_session_id;

  /* look up the request */
#ifdef DEBUG_CAMELSRT
  dbg(10,"\n Session begin #%d\n", pinfo->fd->num);
  dbg(11,"Search key %lu ",camelsrt_call_key.SessionIdKey);
#endif
  p_camelsrt_call = (struct camelsrt_call_t *)g_hash_table_lookup(srt_calls, &camelsrt_call_key);
  if (p_camelsrt_call) {
    /* We have seen this request before -> do nothing */
#ifdef DEBUG_CAMELSRT
    dbg(22,"Already seen ");
#endif
  } else { /* p_camelsrt_call has not been found */
#ifdef DEBUG_CAMELSRT
    dbg(10,"New key %lu ",camelsrt_call_key.SessionIdKey);
#endif
    p_camelsrt_call = new_camelsrt_call(&camelsrt_call_key, pinfo); 
    p_camelsrt_call->tcap_context=p_camelsrt_info->tcap_context;
    update_camelsrt_call(p_camelsrt_call, pinfo,CAMELSRT_SESSION);

#ifdef DEBUG_CAMELSRT
    dbg(11,"Update Callback ");
#endif
    p_camelsrt_call->tcap_context->callback=camelsrt_tcap_matching;
  }
}
  
/*
 * Register the request, and try to find the response
 *
 */
static void camelsrt_request_call_matching(tvbuff_t *tvb,
					   packet_info * pinfo _U_,
					   proto_tree *tree,
					   struct camelsrt_info_t * p_camelsrt_info,
					   guint srt_type )
{
  struct camelsrt_call_t * p_camelsrt_call;
  struct camelsrt_call_info_key_t camelsrt_call_key;
  proto_item *ti;
  
#ifdef DEBUG_CAMELSRT
  dbg(10,"\n %s #%d\n", val_to_str(srt_type, camelSRTtype_naming, "Unk"),pinfo->fd->num);
#endif 

  /* look only for matching request, if matching conversation is available. */
  camelsrt_call_key.SessionIdKey = p_camelsrt_info->tcap_session_id;

#ifdef DEBUG_CAMELSRT
  dbg(11,"Search key %lu ", camelsrt_call_key.SessionIdKey);
#endif
  p_camelsrt_call = find_camelsrt_call(&camelsrt_call_key, pinfo);
  if(p_camelsrt_call) {
#ifdef DEBUG_CAMELSRT
    dbg(12,"Found ");
#endif 
    if (gcamel_DisplaySRT)
      proto_tree_add_uint(tree, hf_camelsrt_SessionId, tvb, 0,0, p_camelsrt_call->session_id);


    /* Hmm.. As there are several slices ApplyChargingReport/ApplyCharging
     * we will prepare the measurement for 3 slices with 3 categories */
    if (srt_type==CAMELSRT_VOICE_ACR1) { 
      if (p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].req_num == 0) {
	srt_type=CAMELSRT_VOICE_ACR1;
      } else  if ( (p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].req_num == 0) 
		   && (p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].rsp_num != 0)
		   && (p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].rsp_num < pinfo->fd->num) ) {
	srt_type=CAMELSRT_VOICE_ACR2;
      } else  if ( (p_camelsrt_call->category[CAMELSRT_VOICE_ACR3].req_num == 0)
		   && (p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].rsp_num != 0)
		   && (p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].rsp_num < pinfo->fd->num) ) {
	srt_type=CAMELSRT_VOICE_ACR3;
      } else if (p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].rsp_num != 0
		 && p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].rsp_num > pinfo->fd->num) {
	srt_type=CAMELSRT_VOICE_ACR1;
      } else  if ( p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].rsp_num != 0
		   && p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].rsp_num > pinfo->fd->num) {
	srt_type=CAMELSRT_VOICE_ACR2;
      } else  if (p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].rsp_num != 0
		  && p_camelsrt_call->category[CAMELSRT_VOICE_ACR3].rsp_num > pinfo->fd->num) {
	srt_type=CAMELSRT_VOICE_ACR3;
      }
#ifdef DEBUG_CAMELSRT
      dbg(70,"Request ACR %u ",srt_type); 
      dbg(70,"ACR1 %u %u",p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].req_num, p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].rsp_num);
      dbg(70,"ACR2 %u %u",p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].req_num, p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].rsp_num);
      dbg(70,"ACR3 %u %u",p_camelsrt_call->category[CAMELSRT_VOICE_ACR3].req_num, p_camelsrt_call->category[CAMELSRT_VOICE_ACR3].rsp_num);
#endif
    } /* not ACR */
    p_camelsrt_info->bool_msginfo[srt_type]=TRUE;

    
    if (p_camelsrt_call->category[srt_type].req_num == 0) { 
      /* We have not yet seen a request to that call, so this must be the first request
	 remember its frame number. */ 
#ifdef DEBUG_CAMELSRT
      dbg(5,"Set reqlink #%d ", pinfo->fd->num);
#endif
      update_camelsrt_call(p_camelsrt_call, pinfo, srt_type);
    } else {
      /* We have seen a request to this call - but was it *this* request? */
      if (p_camelsrt_call->category[srt_type].req_num != pinfo->fd->num) {
	
	if (srt_type!=CAMELSRT_VOICE_DISC) { 
	  /* No, so it's a duplicate resquest. Mark it as such. */ 
#ifdef DEBUG_CAMELSRT
	  dbg(21,"Display_duplicate with req %d ", p_camelsrt_call->category[srt_type].req_num);
#endif
	  p_camelsrt_info->msginfo[srt_type].is_duplicate = TRUE;
	  if (gcamel_DisplaySRT) 
	    proto_tree_add_uint_hidden(tree, hf_camelsrt_Duplicate, tvb, 0,0, 77);

	} else {
	  /* Ignore duplicate frame */
	  if (pinfo->fd->num > p_camelsrt_call->category[srt_type].req_num) {
	    p_camelsrt_call->category[srt_type].req_num = pinfo->fd->num;
#ifdef DEBUG_CAMELSRT
	    dbg(5,"DISC Set reqlink #%d ", pinfo->fd->num);
#endif
	    update_camelsrt_call(p_camelsrt_call, pinfo, srt_type);
	  } /* greater frame */
	} /* DISC */
      } /* req_num already seen */
    } /* req_num != 0 */
    
      /* add link to response frame, if available */
    if ( gcamel_DisplaySRT &&
	 (p_camelsrt_call->category[srt_type].rsp_num != 0) &&
	 (p_camelsrt_call->category[srt_type].req_num != 0) &&
	 (p_camelsrt_call->category[srt_type].req_num == pinfo->fd->num) ) {
#ifdef DEBUG_CAMELSRT
      dbg(20,"Display_framersplink %d ",p_camelsrt_call->category[srt_type].rsp_num);
#endif
      ti = proto_tree_add_uint_format(tree, hf_camelsrt_RequestFrame, tvb, 0, 0, 
				      p_camelsrt_call->category[srt_type].rsp_num,
				      "Linked response %s in frame %u", 
				      val_to_str(srt_type, camelSRTtype_naming, "Unk"),
				      p_camelsrt_call->category[srt_type].rsp_num);
      PROTO_ITEM_SET_GENERATED(ti);
    } /* frame valid */
  }/* call reference */
}


/*
 * Check if the received message is a response to a previous request
 * registered is the camel session context.
 */
static void camelsrt_report_call_matching(tvbuff_t *tvb,
					  packet_info * pinfo _U_,
					  proto_tree *tree,
					  struct camelsrt_info_t * p_camelsrt_info,
					  guint srt_type )
{
  struct camelsrt_call_t * p_camelsrt_call;
  struct camelsrt_call_info_key_t camelsrt_call_key;
  nstime_t delta;
  proto_item *ti;

#ifdef DEBUG_CAMELSRT
  dbg(10,"\n %s #%d\n", val_to_str(srt_type, camelSRTtype_naming, "Unk"),pinfo->fd->num);
#endif  
  camelsrt_call_key.SessionIdKey = p_camelsrt_info->tcap_session_id;
  /* look only for matching request, if matching conversation is available. */

#ifdef DEBUG_CAMELSRT
  dbg(11,"Search key %lu ",camelsrt_call_key.SessionIdKey);
#endif
  p_camelsrt_call = find_camelsrt_call(&camelsrt_call_key, pinfo);
  if(p_camelsrt_call) {
#ifdef DEBUG_CAMELSRT
    dbg(12,"Found, req=%d ",p_camelsrt_call->category[srt_type].req_num);
#endif
    if ( gcamel_DisplaySRT )
      proto_tree_add_uint(tree, hf_camelsrt_SessionId, tvb, 0,0, p_camelsrt_call->session_id);

    if (srt_type==CAMELSRT_VOICE_ACR1) { 
      if (p_camelsrt_call->category[CAMELSRT_VOICE_ACR3].req_num != 0
	  && p_camelsrt_call->category[CAMELSRT_VOICE_ACR3].req_num < pinfo->fd->num) {
	srt_type=CAMELSRT_VOICE_ACR1;
      } else  if ( p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].req_num != 0
		   && p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].req_num < pinfo->fd->num) {
	srt_type=CAMELSRT_VOICE_ACR2;
      } else  if (p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].req_num != 0
		  && p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].req_num < pinfo->fd->num) {
	srt_type=CAMELSRT_VOICE_ACR1;
      }
#ifdef DEBUG_CAMELSRT
      dbg(70,"Report ACR %u ",srt_type);
#endif
    } /* not ACR */
    p_camelsrt_info->bool_msginfo[srt_type]=TRUE;

    if (p_camelsrt_call->category[srt_type].rsp_num == 0) {
      if  ( (p_camelsrt_call->category[srt_type].req_num != 0)
	    && (pinfo->fd->num > p_camelsrt_call->category[srt_type].req_num) ){
	/* We have not yet seen a response to that call, so this must be the first response;
	   remember its frame number only if response comes after request */ 
#ifdef DEBUG_CAMELSRT
	dbg(14,"Set reslink #%d req %d ",pinfo->fd->num, p_camelsrt_call->category[srt_type].req_num);
#endif
	p_camelsrt_call->category[srt_type].rsp_num = pinfo->fd->num;

      } else {
#ifdef DEBUG_CAMELSRT
	dbg(2,"badreslink #%d req %u ",pinfo->fd->num, p_camelsrt_call->category[srt_type].req_num);
#endif
      } /* req_num != 0 */
    } else { /* rsp_num != 0 */
      /* We have seen a response to this call - but was it *this* response? */
      if (p_camelsrt_call->category[srt_type].rsp_num != pinfo->fd->num) {
	/* No, so it's a duplicate response. Mark it as such. */
#ifdef DEBUG_CAMELSRT
	dbg(21,"Display_duplicate rsp=%d ", p_camelsrt_call->category[srt_type].rsp_num);
#endif
	p_camelsrt_info->msginfo[srt_type].is_duplicate = TRUE; 
	if ( gcamel_DisplaySRT )
	  proto_tree_add_uint_hidden(tree, hf_camelsrt_Duplicate, tvb, 0,0, 77);
      }
    } /* rsp_num != 0 */
    
    if ( (p_camelsrt_call->category[srt_type].req_num != 0) &&
	 (p_camelsrt_call->category[srt_type].rsp_num != 0) &&
	 (p_camelsrt_call->category[srt_type].rsp_num == pinfo->fd->num) ) {
      
      p_camelsrt_call->category[srt_type].responded = TRUE;
      p_camelsrt_info->msginfo[srt_type].request_available = TRUE;
#ifdef DEBUG_CAMELSRT
      dbg(20,"Display_frameReqlink %d ",p_camelsrt_call->category[srt_type].req_num);
#endif
      /* Indicate the frame to which this is a reply. */
      if ( gcamel_DisplaySRT ) {
	ti = proto_tree_add_uint_format(tree, hf_camelsrt_ResponseFrame, tvb, 0, 0,
					p_camelsrt_call->category[srt_type].req_num,
					"Linked request %s in frame %u",
					val_to_str(srt_type, camelSRTtype_naming, "Unk"),
					p_camelsrt_call->category[srt_type].req_num);
	PROTO_ITEM_SET_GENERATED(ti);
      }
      /* Calculate Service Response Time */
      nstime_delta(&delta, &pinfo->fd->abs_ts, &p_camelsrt_call->category[srt_type].req_time);
      
      p_camelsrt_info->msginfo[srt_type].is_delta_time = TRUE;
      p_camelsrt_info->msginfo[srt_type].delta_time = delta; /* give it to tap */
      p_camelsrt_info->msginfo[srt_type].req_time = p_camelsrt_call->category[srt_type].req_time;
      
      /* display Service Response Time and make it filterable */
      camelsrt_display_DeltaTime(tree, tvb, &delta, srt_type);
      
    } /*req_num != 0 && not duplicate */
  } /* call reference found */
}

/*
 * Update the Camel session info, and close the session.
 * Then remove the associated context, if we do not have persistentSRT enable
 */
static void camelsrt_close_call_matching(tvbuff_t *tvb,
					 packet_info * pinfo _U_,
					 proto_tree *tree,
					 struct camelsrt_info_t * p_camelsrt_info)
{
  struct camelsrt_call_t * p_camelsrt_call;
  struct camelsrt_call_info_key_t camelsrt_call_key;
  nstime_t delta;

  p_camelsrt_info->bool_msginfo[CAMELSRT_SESSION]=TRUE;
#ifdef DEBUG_CAMELSRT
  dbg(10,"\n Session end #%d\n", pinfo->fd->num);
#endif
  /* look only for matching request, if matching conversation is available. */
  camelsrt_call_key.SessionIdKey = p_camelsrt_info->tcap_session_id;

#ifdef DEBUG_CAMELSRT
  dbg(11,"Search key %lu ",camelsrt_call_key.SessionIdKey);
#endif
  p_camelsrt_call = find_camelsrt_call(&camelsrt_call_key, pinfo);
  if(p_camelsrt_call) {
#ifdef DEBUG_CAMELSRT
    dbg(12,"Found ");
#endif 
    /* Calculate Service Response Time */
    nstime_delta(&delta, &pinfo->fd->abs_ts, &p_camelsrt_call->category[CAMELSRT_SESSION].req_time);
    p_camelsrt_call->category[CAMELSRT_SESSION].responded = TRUE;
    p_camelsrt_info->msginfo[CAMELSRT_SESSION].request_available = TRUE;      
    p_camelsrt_info->msginfo[CAMELSRT_SESSION].is_delta_time = TRUE;
    p_camelsrt_info->msginfo[CAMELSRT_SESSION].delta_time = delta; /* give it to tap */
    p_camelsrt_info->msginfo[CAMELSRT_SESSION].req_time = p_camelsrt_call->category[CAMELSRT_SESSION].req_time;
      
    if ( !gcamel_PersistentSRT ) {
      g_hash_table_remove(srt_calls, &camelsrt_call_key);
#ifdef DEBUG_CAMELSRT
      dbg(20,"remove hash ");
#endif
    } else {
#ifdef DEBUG_CAMELSRT
      dbg(20,"keep hash ");
#endif
    }
  } /* call reference found */
}

/*
 * Display the delta time between two messages in a field corresponding 
 * to the category (hf_camelsrt_DeltaTimexx).
 */
static void camelsrt_display_DeltaTime(proto_tree *tree,
				       tvbuff_t *tvb,
				       nstime_t* value_ptr,
				       guint category)
{ 
  proto_item *ti;
  
  if ( gcamel_DisplaySRT ) {
    switch(category) {
    case CAMELSRT_VOICE_INITIALDP:
      ti = proto_tree_add_time(tree, hf_camelsrt_DeltaTime31, tvb, 0, 0, value_ptr);
      PROTO_ITEM_SET_GENERATED(ti);
      break;
      
    case CAMELSRT_VOICE_ACR1:
    case CAMELSRT_VOICE_ACR2:
    case CAMELSRT_VOICE_ACR3: 
      ti = proto_tree_add_time(tree, hf_camelsrt_DeltaTime22, tvb, 0, 0, value_ptr);
      PROTO_ITEM_SET_GENERATED(ti);
      break;
   
    case CAMELSRT_VOICE_DISC:
      ti = proto_tree_add_time(tree, hf_camelsrt_DeltaTime35, tvb, 0, 0, value_ptr);
      PROTO_ITEM_SET_GENERATED(ti);
      break;
    
    case CAMELSRT_GPRS_INITIALDP:
      ti = proto_tree_add_time(tree, hf_camelsrt_DeltaTime75, tvb, 0, 0, value_ptr);
      PROTO_ITEM_SET_GENERATED(ti);
      break;
   
    case CAMELSRT_GPRS_REPORT:
      ti = proto_tree_add_time(tree, hf_camelsrt_DeltaTime80, tvb, 0, 0, value_ptr);
      PROTO_ITEM_SET_GENERATED(ti);
      break;
    
    case CAMELSRT_SMS_INITIALDP: 
      ti = proto_tree_add_time(tree, hf_camelsrt_DeltaTime65, tvb, 0, 0, value_ptr);
      PROTO_ITEM_SET_GENERATED(ti);
      break;

    default:
      break;
    }
  }
}

/*
 * Initialize the Message Info used by the main dissector
 * Data are linked to a TCAP transaction 
 */
struct camelsrt_info_t * camelsrt_razinfo(void)
{
  struct camelsrt_info_t * p_camelsrt_info ;

  /* Global buffer for packet extraction */
  camelsrt_global_current++;
  if(camelsrt_global_current==MAX_CAMEL_INSTANCE){
    camelsrt_global_current=0;
  }
  
  p_camelsrt_info=&camelsrt_global_info[camelsrt_global_current];
  memset(p_camelsrt_info,0,sizeof(struct camelsrt_info_t));  
  
  p_camelsrt_info->opcode=255; 
  
  return p_camelsrt_info;
}

/*
 * Initialize the data per call for the Service Response Time Statistics
 * Data are linked to a Camel operation in a TCAP transaction
 */
static void raz_camelsrt_call (struct camelsrt_call_t * p_camelsrt_call)
{  
  memset(p_camelsrt_call,0,sizeof(struct camelsrt_call_t));
}
