/* mkcap.c
 * A small program to generate the ASCII form of a capture with TCP
 * segments of a reasonable nature. The payload is all zeros.
 *
 * By Ronnie Sahlberg and Richard Sharpe. From a program initially
 * written by Ronnie.
 * Copyright 2003 Ronnie Sahlberg and Richard Sharpe
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
 *
 * Using it to generate a capture file:
 * ./mkcap [some-flags] > some-file
 * text2pcap [some-other-flags] some-file some-file.cap
 * For example:

./mkcap -a 2500 -s 15 -I "02 03 04 05" -i "45 45 45 45" -P "00 14"  > ftp.cap.asci
text2pcap -t "%Y/%m/%d%t%H:%M:%S." ftp.cap.asci ftp.cap

 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define ETH_1 "00 00 9c fa 1d 74"
#define ETH_2 "00 1a b8 93 f6 71"
#define IP_1  "0a 01 01 17"
#define IP_2  "0a 01 01 ea"
#define PORT_1 "01 00"
#define PORT_2 "10 00"

char *eth_1 = ETH_1;
char *eth_2 = ETH_2;
char *ip_1 = IP_1;
char *ip_2 = IP_2;
char *port_1 = PORT_1;
char *port_2 = PORT_2;

int verbose = 0;

typedef enum {
  normal = 0,
  random_ack_drop = 1,
  random_data_drop = 2,
} run_type_t;

typedef struct {
  int drop_seg_start;
  int drop_seg_count;
} seg_drop_t;

/*
 * The array of which segments should be dropped ...
 */
seg_drop_t *drops = NULL;
int seg_drop_count = 0;
/* The array of which ACKs should be dropped. This is complicated because
 * An ack might not be generated for a segment because of delayed ACKs.
 */
seg_drop_t *ack_drops = NULL;
int ack_drop_count = 0;

int total_bytes = 32768;
int run_type = 0;

int seq_2=0;
int seq_1=0;
int ts=0;
int jitter = 0;
int send_spacing = 10;
int ack_delay = 5000;
int tcp_nodelay = 0;
int tcp_delay_time = 1000; /* What is the real time here? */
/*
 * If tcp_nodelay is set, then this is the amount of data left ...
 */
int remaining_data = 0;
int snap_len = 1500;
int window = 32768;
int ssthresh = 16384;
int cwnd = 1460;
int used_win = 0;
int segment = 0;

#define SEG_ACK_LOST 1
#define SEG_SEG_LOST 2

struct seg_hist_s {
  int seq_num;           /* First sequence number in segment     */
  int len;               /* Number of bytes in segment           */
  int ts;                /* Timestamp when sent                  */
  int seg_num;           /* Segment number sent. This can change */
                         /* but a retransmit will have a new seg */
  int flags;             /* Flags as above for ack and seg loss  */
  int acks_first_seq;    /* How many times we have seen an ack
			    for the first seq number in this seg */
};

#define SEG_HIST_SIZE 128
struct seg_hist_s seg_hist[128];    /* This should be dynamic */
int next_slot = 0;
int first_slot = 0;

int delayed_ack = 1;          /* Default is delayed ACKs in use ...  */
int delayed_ack_wait = 30000; /* 30 mS before an ACK is generated if */
                              /* no other traffic                    */

void
makeseg(char *eth1, char *eth2, char *ip1, char *ip2, char *p1, char *p2, int *s1, int *s2, char *flags, int len)
{
	int i;

	printf("2002/01/07 00:00:%02d.%06d\n", ts/1000000, ts%1000000);
	printf("0000 %s %s 08 00\n", eth1, eth2);
	printf("000e 45 00 %02x %02x 00 00 00 00 40 06 00 00 %s %s\n", (len+40)>>8, (len+40)&0xff, ip1, ip2);
	printf("0022 %s %s %02x %02x %02x %02x %02x %02x %02x %02x 50 %s 80 00 00 00 00 00", p1, p2,
		((*s1)>>24)&0xff,
		((*s1)>>16)&0xff,
		((*s1)>>8)&0xff,
		((*s1))&0xff,
		((*s2)>>24)&0xff,
		((*s2)>>16)&0xff,
		((*s2)>>8)&0xff,
		((*s2))&0xff,
		flags );
	for(i=0;i<(len<(snap_len-40)?len:snap_len-40);i++)printf(" 00");
	printf("\n");
	printf("\n");
	(*s1)+=len;
}

/*
 * Figure out when the next ack is due ... here we must skip the acks for
 * frames that are marked as ACKs dropped as well as the frames marked as
 * frames dropped. These will be marked by the routine that generates ACKs.
 * Returns a timestamp value. Returns 2^^31-1 if none are due at all
 */
int next_ack_due()
{
  int slot = next_slot;
  int ack_lost = 0, seg_lost = 0;

  if (next_slot == first_slot)
    return (((unsigned int)(1<<31)) - 1);

  /*
   * Figure out if we need to issue an ACK. We skip all outstanding packets
   * that are marked as ack lost or packet lost.
   *
   * We would not usually come in here with a frame marked as lost or ack lost
   * rather, we will come in here and specify that the ack was due at a
   * certain time, and gen_next_ack would then determine that the ack
   * should be lost or the packet lost.
   */

  /*
   * Look for a seg slot that is not lost or dropped
   */

  while (seg_hist[slot].flags & (SEG_ACK_LOST || SEG_SEG_LOST)) {
    if (seg_hist[slot].flags & SEG_ACK_LOST)
      ack_lost++;
    if (seg_hist[slot].flags & SEG_SEG_LOST)
      seg_lost++;
    slot = (slot + 1) % SEG_HIST_SIZE;
  }

  if (slot == next_slot)
    return (((unsigned int)(1<<31)) - 1);

  /*
   * If there is only one slot occupied, or a segment was lost then
   * an ACK is due after the last [good] segment left plus ack_delay
   */

  if (slot == first_slot && next_slot == ((first_slot + 1) % SEG_HIST_SIZE))
    return (seg_hist[first_slot].ts + ack_delay + jitter);

  if (seg_lost)
    return (seg_hist[slot].ts + ack_delay + jitter);

  /*
   * OK, now, either we have only seen lost acks, or there are more than
   * one outstanding segments, so figure out when the ACK is due.
   *
   * If delayed ACK is in force, ACK is due after every second seg, but
   * if we had a lost ack, then we must ignore 2*lost_ack segments. So,
   * if there has not been that many segments sent, we return infinity
   * as the next ACK time
   */

  if (ack_lost) {
    if (delayed_ack) {
      if (((first_slot + 1 + 2 * ack_lost) % SEG_HIST_SIZE) >= next_slot)
	/* XXX: FIXME, what about when the window is closed */
	/* XXX: FIXME, use the correct value for this       */
	return (((unsigned int)(1<<31)) - 1);
      else
	return seg_hist[(first_slot + 1 + 2 * ack_lost) % SEG_HIST_SIZE].ts +
	  ack_delay + jitter;
    }
    else
      return seg_hist[slot].ts + ack_delay + jitter;
  }
  else {
    if (delayed_ack)
      return (seg_hist[(first_slot + 1)%SEG_HIST_SIZE].ts+ack_delay+jitter);
    else
      return (seg_hist[first_slot].ts+ack_delay+jitter);
  }
}

/*
 * Update the relevant info of the sent seg
 */
add_seg_sent(int seq, int len)
{

  /*
   * Should check we have not wrapped around and run into the unacked
   * stuff ...
   */
  /*if (next_slot == first_slot) ;*/

  segment++;
  seg_hist[next_slot].seq_num        = seq;
  seg_hist[next_slot].len            = len;
  seg_hist[next_slot].ts             = ts;
  seg_hist[next_slot].seg_num        = segment;
  seg_hist[next_slot].flags          = 0;
  seg_hist[next_slot].acks_first_seq = 0;
  used_win = used_win + len;          /* Update the window used */

  /*
   * Now, update next_slot ...
   */

  next_slot = (next_slot + 1) % SEG_HIST_SIZE;

}

/*
 * Generate the next ack based on the above reasoning ...
 */

#define NO_FORCE_ACK 0
#define FORCE_ACK 1

/*
 * Generate the next ACK. If we did not generate an ACK, return 0,
 * else return 1.
 */
int
gen_next_ack(int force, int spacing)
{
  int seq_to_ack, new_ts, data_acked;

  /*
   * We need to check if the segment that we are about to generate an
   * ack for is a segment that should be dropped ... or an ack that should
   * be dropped.
   *
   * Figure out what we are doing before freeing segments ...
   */

  seq_to_ack = seg_hist[first_slot].seq_num + seg_hist[first_slot].len;
  used_win = used_win - seg_hist[first_slot].len;
  data_acked = seg_hist[first_slot].len;
  new_ts = seg_hist[first_slot].ts + ack_delay;
  first_slot = (first_slot + 1) % SEG_HIST_SIZE;

  /*
   * If delayed ACK in force, then ACK the next segment if there is one
   */
  if (delayed_ack && (first_slot != next_slot)) {
    seq_to_ack += seg_hist[first_slot].len;
    used_win = used_win - seg_hist[first_slot].len;
    data_acked += seg_hist[first_slot].len;
    new_ts = seg_hist[first_slot].ts + ack_delay;
    first_slot = (first_slot + 1) % SEG_HIST_SIZE;
  }

  /*
   * We don't want time to go backward ...
   */
  if (new_ts + jitter <= ts)
    ts++;
  else
    ts = new_ts + jitter;

  jitter = (rand() % 10 - 5);  /* Update jitter ... */

  makeseg(eth_2, eth_1, ip_2, ip_1, port_2, port_1, &seq_2, &seq_to_ack, "10", 0);
  /*
   * Do we want the exponential part or the linear part?
   */
  if (cwnd >= ssthresh)
    cwnd += (1460*data_acked)/cwnd;      /* is this right? */
  else
    cwnd = cwnd + data_acked;
  if (verbose) fprintf(stderr, "Ack rcvd. ts: %d, data_acked: %d, cwnd: %d, window: %d\n",
	  ts, data_acked, cwnd, window);
  if (cwnd > window) cwnd = window;
}

void
makeackedrun(int len, int spacing, int ackdelay)
{
	int next_ack_ts=0;
        if (verbose) fprintf(stderr, "makeackedrun: Len=%d, spacing=%d, ackdelay=%d\n",
		len, spacing, ackdelay);
	while(len>0){

	  /*
	   * Each time we output a segment, we should check to see if an
	   * ack is due back before the next segment is due ...
	   */
		int seglen, saved_seq;
		seglen=(len>1460)?1460:len;
		/*
		 * Only output what is left in the cwnd.
		 * We assume there is space in the congestion window here
		 */
		if (seglen > (cwnd - used_win)) seglen = cwnd - used_win;

		len-=seglen;
		saved_seq = seq_1;
		if (verbose) fprintf(stderr, "Sending segment. ts: %d, jitter: %d\n", ts, jitter);
		if(len){
			makeseg(eth_1, eth_2, ip_1, ip_2, port_1, port_2, &seq_1, &seq_2, "10", seglen);
		} else {
			makeseg(eth_1, eth_2, ip_1, ip_2, port_1, port_2, &seq_1, &seq_2, "18", seglen);
		}
		add_seg_sent(saved_seq, seglen);

		/*
		 * Now, if the window is closed, then we have to eject an
		 * ack, otherwise we can eject more data.
		 * Also, the other end will tend to ack two segments at
		 * a time ... and that ack might fall between two
		 * outgoing segments
		 */
		jitter = (rand()%10) - 5; /* What if spacing too small */

		if (verbose) fprintf(stderr, "used win: %d, cwnd: %d\n", used_win, cwnd);

		if ((next_ack_ts = next_ack_due()) < ts + spacing + jitter) {
		  int old_ts = ts;

		  /*
		   * Generate the ack and retire the segments
		   * If delayed ACK in use, there should be two
		   * or more outstanding segments ...
		   */
		  if (verbose) fprintf(stderr, "Non forced ACK ...ts + spacing + jitter:%d, jitter: %d\n", ts + spacing + jitter, jitter);
		  gen_next_ack(NO_FORCE_ACK, spacing);
		  /*
		   * We don't want time to go backwards ...
		   */
		  if (old_ts + spacing + jitter <= ts)
		    ts++;
		  else
		    ts = old_ts + spacing + jitter;

		} else if (used_win == cwnd) {

		  /*
		   * We need an ACK, so generate it and retire the
		   * segments and advance the ts to the time of the ack
		   */

		  if (verbose) fprintf(stderr, "Forced ACK ... \n");
		  gen_next_ack(FORCE_ACK, spacing);

		  ts+=(spacing+jitter);   /* Should not use spacing here */

		}
		else {
		  ts+=(spacing+jitter);
		}

		if (verbose) fprintf(stderr, "Next Ack Due: %d\n", next_ack_ts);
	}

}


void
makeackedrundroppedtail8kb(int len, int spacing, int ackdelay)
{
	int old_seq1;
	int dropped_tail;
	int i;
	int num_dupes;
        if (verbose) fprintf(stderr, "makeackedrundroppedtail8kB: Len=%d, spacing=%d, ackdelay=%d\n",
		len, spacing, ackdelay);
	old_seq1=seq_1;
	while(len>0){
		int seglen;
		seglen=(len>1460)?1460:len;
		len-=seglen;
		if(seglen==1460){
			makeseg(eth_1, eth_2, ip_1, ip_2, port_1, port_2, &seq_1, &seq_2, "10", seglen);
		} else {
			makeseg(eth_1, eth_2, ip_1, ip_2, port_1, port_2, &seq_1, &seq_2, "18", seglen);
		}
		ts+=spacing;
	}

	ts+=ackdelay;

	i=0;
	num_dupes=-1;
	dropped_tail=0;
	while(old_seq1!=seq_1){
		int ack_len;

		ack_len=((seq_1-old_seq1)>2920)?2920:(seq_1-old_seq1);

		i++;
		if(i==6){
			dropped_tail=old_seq1;
		}
		old_seq1+=ack_len;
		if(i<6){
			makeseg(eth_2, eth_1, ip_2, ip_1, port_2, port_1, &seq_2, &old_seq1, "10", 0);
		} else if (i==6) {
			makeseg(eth_2, eth_1, ip_2, ip_1, port_2, port_1, &seq_2, &dropped_tail, "10", 0);
			num_dupes+=2;
		} else {
			makeseg(eth_2, eth_1, ip_2, ip_1, port_2, port_1, &seq_2, &dropped_tail, "10", 0);
			makeseg(eth_2, eth_1, ip_2, ip_1, port_2, port_1, &seq_2, &dropped_tail, "10", 0);
			num_dupes+=2;
		}
		ts+=spacing/2;
	}

	if(!dropped_tail){
		return;
	}

	if(num_dupes<3){
		int seglen;
		ts+=1000000;
		seglen=((seq_1-dropped_tail)>1460)?1460:(seq_1-dropped_tail);
		if(seglen==1460){
			makeseg(eth_1, eth_2, ip_1, ip_2, port_1, port_2, &dropped_tail, &seq_2, "10", seglen);
		} else {
			makeseg(eth_1, eth_2, ip_1, ip_2, port_1, port_2, &dropped_tail, &seq_2, "18", seglen);
		}
		ts+=ackdelay;

		makeseg(eth_2, eth_1, ip_2, ip_1, port_2, port_1, &seq_2, &seq_1, "10", 0);
		ts+=spacing;
		return;
	}

	while(dropped_tail!=seq_1){
		int seglen;
		int ack;
		seglen=((seq_1-dropped_tail)>1460)?1460:(seq_1-dropped_tail);
		if(seglen==1460){
			makeseg(eth_1, eth_2, ip_1, ip_2, port_1, port_2, &dropped_tail, &seq_2, "10", seglen);
		} else {
			makeseg(eth_1, eth_2, ip_1, ip_2, port_1, port_2, &dropped_tail, &seq_2, "18", seglen);
		}
		ts+=ackdelay;

		ack=dropped_tail;
		makeseg(eth_2, eth_1, ip_2, ip_1, port_2, port_1, &seq_2, &ack, "10", 0);
		ts+=spacing;
	}
}

void usage()
{
  fprintf(stderr, "Usage: mkcap [OPTIONS], where\n");
  fprintf(stderr, "\t-a <ack-delay>        is the delay to an ACK (SRT)\n");
  fprintf(stderr, "\t-b <bytes-to-send>    is the bytes to send on connection\n");
  fprintf(stderr, "\t-i <ip-addr-hex>      is the sender IP address in hex\n");
  fprintf(stderr, "\t-I <ip-addr-hex>      is the recipient IP address in hex\n");
  fprintf(stderr, "\t-n <ISN>              is almost the ISN for the sender\n");
  fprintf(stderr, "\t-N <ISN>              is almost the ISN for the recipient\n");
  fprintf(stderr, "\t-p <port-number-hex>  is the port number for sender\n");
  fprintf(stderr, "\t-P <port-number-hex>  is the port number for recipient\n");
  fprintf(stderr, "\t-s <send-spacing>     is the send spacing\n");
  fprintf(stderr, "\t-w <window-size>      is the window size\n");
}

int
all_digits(char *str)
{
  int i;
  if (!str || !(*str)) {
    return 0;
  }

  for (i = 0; str[i]; i++) {
    if (!isdigit(str[i]))
      return 0;
  }

  return 1;
}

/*
 * Process a list of drops. These are of the form:
 *
 * first_seg,seg_count[,first_seg,seg_count]*
 */
void
process_drop_list(char *drop_list)
{
  int commas=0;
  char *tok, *save;

  if (!drop_list || !(*drop_list)) {
    fprintf(stderr, "Strange drop list. NULL or an empty string. No drops!\n");
    return;
  }
  save = (char *)g_strdup(drop_list);

  for (tok=(char *)strtok(drop_list, ","); tok; tok=(char *)strtok(NULL, ",")) {
    commas++;
  }

  /* Now, we have commas, divide by two and round up */

  seg_drop_count = (commas+1)/2;
  drops = (seg_drop_t *)g_malloc(sizeof(seg_drop_t) * seg_drop_count);
  if (!drops) {
    fprintf(stderr, "Unable to allocate space for drops ... going without!\n");
    seg_drop_count = 0;
    g_free(save);
    return;
  }

  /* Now, go through the list again and build the drop list. Any errors and */
  /* we abort and print a usage message                                     */

  commas = 0;
  for (tok=(char *)strtok(save, ","); tok; tok=(char *)strtok(NULL, ",")) {
    int num = atoi(tok);

    if (!all_digits(tok)) {
      fprintf(stderr, "Error in segment offset or count. Not all digits: %s\n",
	      tok);
      fprintf(stderr, "No packet drops being performed!\n");
      g_free(save);
      g_free(drops);
      seg_drop_count = 0; drops = NULL;
      return;
    }
    if (num == 0) num = 1;
    if (commas % 2)
      drops[commas / 2].drop_seg_count = num;
    else
      drops[commas / 2].drop_seg_start = num;
  }

  g_free(save);

}

int
main(int argc, char *argv[])
{
	int i;
	int len;
	int type;
	int cnt;
	extern char *optarg;
	extern int optind;
	int opt;

	while ((opt = getopt(argc, argv, "a:b:d:Di:I:j:l:n:N:p:P:r:s:vw:")) != EOF) {
	  switch (opt) {
	  case 'a':
	    ack_delay = atoi(optarg);
	    break;

	  case 'b': /* Bytes ... */
	    total_bytes = atoi(optarg);
	    break;

	  case 'd': /* A list of drops to simulate */
	    process_drop_list(optarg);
	    break;

	  case 'D': /* Toggle tcp_nodelay */
	    tcp_nodelay = (tcp_nodelay + 1) % 1;
	    break;

	  case 'i':
	    ip_1 = optarg;
	    break;

	  case 'I':
	    ip_2 = optarg;
	    break;

	  case 'l':
	    snap_len = atoi(optarg);
	    break;

	  case 'n': /* ISN for send dirn, ie, seq_1 */
	    seq_1 = atoi(optarg);
	    break;

	  case 'N': /* ISN for recv dirn, ie, seq_2 */
	    seq_2 = atoi(optarg);
	    break;

	  case 'p':
	    port_1 = optarg;
	    break;

	  case 'P':
	    port_2 = optarg;
	    break;

	  case 'r':
	    run_type = atoi(optarg);
	    break;

	  case 's':
	    send_spacing = atoi(optarg);
	    break;

	  case 'v':
	    verbose++;
	    break;

	  case 'w':  /* Window ... */
	    window = atoi(optarg);
	    ssthresh = window / 2;   /* Have to recalc this ... */
	    break;

	  default:
	    usage();
	    break;
	  }
	}

	if (verbose) fprintf(stderr, "IP1: %s, IP2: %s, P1: %s, P2: %s, Ack Delay: %d, Send Spacing: %d\n",
		ip_1, ip_2, port_1, port_2, ack_delay, send_spacing);

	/*return 0; */

	if (run_type == 0) {
	  makeackedrun(total_bytes, send_spacing, ack_delay);
	}
	else {
	  for(cnt=0;cnt<200;cnt++){
	    type=rand()%150;
	    if(type<75){
	      int j;
	      j=5+rand()%10;
	      for(i=0;i<j;i++){
		makeackedrun(32768, send_spacing, ack_delay);
	      }
	    } else if(type<90) {
	      int j;
	      j=4+rand()%4;
	      for(i=0;i<j;i++){
		len=100+rand()&0xfff;
		makeackedrun(len, send_spacing, ack_delay);
	      }
	    } else {
	      for(i=0;i<5;i++){
		len=100+rand()&0x3fff+0x1fff;
		makeackedrun(len, send_spacing, ack_delay);
		/*makeackedrundroppedtail8kb(len, send_spacing, ack_delay);*/
	      }
	    }
	  }
	}
	return 0;
}

