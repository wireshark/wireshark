/* tap_camelsrt.c
 * CAMEL Service Response Time statistics for tshark
 * Copyright 2006 Florent Drouin (based on tap_h225rassrt.c from Lars Roland)
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
#include "epan/value_string.h"
#include "register.h"
#include "epan/dissectors/packet-camel.h"
#include "epan/camel-persistentdata.h"
#include "timestats.h"
#include "epan/stat_cmd_args.h"

#undef  MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))

void register_tap_listener_camelsrt(void);

/* Save the the first NUM_RAS_STATS stats in the array to calculate percentile */
#define NUM_RAS_STATS 500000

/* Number of couple message Request/Response to analyze*/
#define NB_CRITERIA 7

/* used to keep track of the statistics for an entire program interface */
struct camelsrt_t {
  char *filter;
  guint32 count[NB_CAMELSRT_CATEGORY];
  timestat_t stats[NB_CAMELSRT_CATEGORY];
  nstime_t delta_time[NB_CAMELSRT_CATEGORY][NUM_RAS_STATS];
};

/* Check if we have to inhibit the display or not 
 * cannot be static because it's exported in libwireshark.def
 */
gboolean gcamel_StatSRT;
gboolean gtcap_StatSRT;

/* Reset the counter */
static void camelsrt_reset(void *phs)
{
  struct camelsrt_t *hs=(struct camelsrt_t *)phs;
  memset(hs,0,sizeof(struct camelsrt_t));
}


static int camelsrt_packet(void *phs, 
			   packet_info *pinfo _U_, 
			   epan_dissect_t *edt _U_,
			   const void *phi)
{
  struct camelsrt_t *hs=(struct camelsrt_t *)phs;
  const struct camelsrt_info_t * pi=phi;
  int i;

  for (i=0; i<NB_CAMELSRT_CATEGORY; i++) {
    if (pi->bool_msginfo[i] &&
      	pi->msginfo[i].is_delta_time 
	&& pi->msginfo[i].request_available
	&& !pi->msginfo[i].is_duplicate ) {
      
      time_stat_update(&(hs->stats[i]),
		       &(pi->msginfo[i].delta_time),
		       pinfo);
	
      if (hs->count[i] < NUM_RAS_STATS) {
	hs->delta_time[i][hs->count[i]++] 
	  = pi->msginfo[i].delta_time;
      }
    }
  }
  return 1;
}


static void camelsrt_draw(void *phs)
{
  struct camelsrt_t *hs=(struct camelsrt_t *)phs;
  guint j,z;
  guint32 li;
  int somme,iteration=0;
  timestat_t *rtd_temp;
  double x,delay,delay_max,delay_min,delta;
  double criteria[NB_CRITERIA]={ 5.0, 10.0, 75.0, 90.0, 95.0,99.0,99.90 };
  double delay_criteria[NB_CRITERIA];

  printf("\n");
  printf("Camel Service Response Time (SRT) Statistics:\n");
  printf("=================================================================================================\n");
  printf("|        Category         | Measure |  Min SRT  |  Max SRT  |  Avg SRT  | Min frame | Max frame |\n");
  printf("|-------------------------|---------|-----------|-----------|-----------|-----------|-----------|\n");
 
  j=1;
  printf("|%24s |%8u |%8.2f s |%8.2f s |%8.2f s |%10u |%10u |\n",
	 val_to_str(j,camelSRTtype_naming,"Unknown Message 0x%02x"),
	 hs->stats[j].num,
	 nstime_to_sec(&(hs->stats[j].min)),
	 nstime_to_sec(&(hs->stats[j].max)),
	 get_average(&(hs->stats[j].tot),hs->stats[j].num)/1000.0,
	 hs->stats[j].min_num, 
	 hs->stats[j].max_num
	 );
  for(j=2; j<NB_CAMELSRT_CATEGORY; j++) { 
    if(hs->stats[j].num==0){ 
      printf("|%24s |%8u |%8.2f ms|%8.2f ms|%8.2f ms|%10u |%10u |\n",
	     val_to_str(j,camelSRTtype_naming,"Unknown Message 0x%02x"),
	     0, 0.0, 0.0, 0.0, 0, 0);
      continue;
    }
    
    printf("|%24s |%8u |%8.2f ms|%8.2f ms|%8.2f ms|%10u |%10u |\n",
	   val_to_str(j,camelSRTtype_naming,"Unknown Message 0x%02x"),
	   hs->stats[j].num,
	   MIN(9999,nstime_to_msec(&(hs->stats[j].min))),
	   MIN(9999,nstime_to_msec(&(hs->stats[j].max))),
	   MIN(9999,get_average(&(hs->stats[j].tot),hs->stats[j].num)),
	   hs->stats[j].min_num, 
	   hs->stats[j].max_num
	   );
  } /* j category */ 

  printf("=================================================================================================\n");
  /*
   * Display 95%
   */

  printf("|   Category/Criteria     |");
  for(z=0; z<NB_CRITERIA; z++) printf("%7.2f%% |", criteria[z]);
  printf("\n");

  printf("|-------------------------|");
  for(z=0; z<NB_CRITERIA; z++) printf("---------|");
  printf("\n");
  /* calculate the delay max to have a given number of messages (in percentage) */
  for(j=2;j<NB_CAMELSRT_CATEGORY;j++) {
    
    rtd_temp = &(hs->stats[j]);
    
    if (hs->count[j]>0) { 
      /* Calculate the delay to answer to p% of the MS */
      for(z=0; z<NB_CRITERIA; z++) {
	iteration=0;
	delay_max=(double)rtd_temp->max.secs*1000 +(double)rtd_temp->max.nsecs/1000000;
	delay_min=(double)rtd_temp->min.secs*1000 +(double)rtd_temp->min.nsecs/1000000;
	delay=delay_min;
	delta=delay_max-delay_min;
	while( (delta > 0.001) && (iteration < 10000) ) {
	  somme=0;
	  iteration++;
	  
	  for(li=0;li<hs->count[j];li++) {
	    x=hs->delta_time[j][li].secs*1000 
	      + (double)hs->delta_time[j][li].nsecs/1000000;
	    if (x <= delay) somme++;
	  }
	  if ( somme*100 > hs->count[j]*criteria[z] ) { /* trop grand */
	    delay_max=delay;
	    delay=(delay_max+delay_min)/2;
	    delta=delay_max-delay_min;
	  } else { /* trop petit */
	    delay_min=delay;
	    delay=(delay_max+delay_min)/2;
	    delta=delay_max-delay_min;
	  }
	} /* while */
	delay_criteria[z]=delay;
      } /* z criteria */
      /* Append the result to the table */
      printf("X%24s |", val_to_str(j, camelSRTtype_naming, "Unknown") );
      for(z=0; z<NB_CRITERIA; z++) printf("%8.2f |", MIN(9999,delay_criteria[z]));
      printf("\n");
    } else { /* count */ 
      printf("X%24s |", val_to_str(j, camelSRTtype_naming, "Unknown") );
      for(z=0; z<NB_CRITERIA; z++) printf("%8.2f |", 0.0);
      printf("\n");
    } /* count */ 
  }/* j category */ 
  printf("===========================");
  for(z=0; z<NB_CRITERIA; z++) printf("==========");
  printf("\n");
}

static void camelsrt_init(const char *optarg, void* userdata _U_)
{
  struct camelsrt_t *p_camelsrt;
  const char *filter=NULL;
  const char *emptyfilter=""; 

  GString *error_string;

  if(!strncmp(optarg,"camel,srt,",9)){
    filter=optarg+9;
  } else {
    filter=NULL;
  }

  p_camelsrt = g_malloc(sizeof(struct camelsrt_t));
  if(filter){
    p_camelsrt->filter=g_malloc(strlen(filter)+1);
    strcpy(p_camelsrt->filter,filter);
  } else {
    p_camelsrt->filter=NULL;
  }
  camelsrt_reset(p_camelsrt);
  
  if (filter) {
    error_string=register_tap_listener("CAMEL",
				       p_camelsrt,
				       filter,
				       NULL,
				       camelsrt_packet,
				       camelsrt_draw);
  } else { 
    error_string=register_tap_listener("CAMEL",
				       p_camelsrt,
				       emptyfilter,
				       NULL,
				       camelsrt_packet,
				       camelsrt_draw);
  }
  
  if(error_string){
    /* error, we failed to attach to the tap. clean up */
    g_free(p_camelsrt->filter);
    g_free(p_camelsrt);
    
    fprintf(stderr, "tshark: Couldn't register camel,srt tap: %s\n",
	    error_string->str);
    g_string_free(error_string, TRUE);
    exit(1);
  }

  /*
   * If we are using tshark, we have to display the stats, even if the stats are not persistent
   * As the frame are proceeded in the chronological order, we do not need persistent stats
   * Whereas, with wireshark, it is not possible to have the correct display, if the stats are
   * not saved along the analyze
   */ 
  gtcap_StatSRT=TRUE;
  gcamel_StatSRT=TRUE;
}


void /* Next line mandatory */
register_tap_listener_camelsrt(void)
{
  register_stat_cmd_arg("camel,srt", camelsrt_init, NULL);
}
