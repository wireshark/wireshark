/*
 * trigcap
 * a simple triggered libpcap-based capture agent
 *
 * (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <pcap.h>

static int dumping;
static volatile int keep_going;
static pcap_t* listener;
static struct bpf_program stop_filter;
static int captured = 0;
static int debug_level = 0;

static void panic(int err, const char* fmt, ...) {
	va_list ap;
	va_start(ap,fmt);
	vfprintf(stderr,fmt,ap);
	va_end(ap);
	exit(err);
}

static void dprintf(int lev, const char* fmt, ...) {
	va_list ap;

	if (lev <= debug_level) {
		va_start(ap,fmt);
		vfprintf(stderr,fmt,ap);
		va_end(ap);
		fflush(stderr);
	}
}


static void usage(int err) {
	const char* usage_str = "usage:\n"
	"trigcap -w outfile -b begin -e end [-f capture] [-i iface] [-s snaplen] [-p] [-q] [-d [-d [-d [-d]]]]\n"
	"   -w output file\n"
	"   -b filter to start capturing\n"
	"   -e filter to stop capturing\n"
	"   -f capture filter\n"
	"   -p promiscuous mode\n"
	"   -s snapshot length\n"
	"   -q quiet\n"
	"   -d increase debug level\n"
	"   -h prints this message\n"
	;

	panic(err,usage_str);
}

static void listener_handler(u_char* u, const struct pcap_pkthdr * ph, const u_char* buf) {
	char errbuf[PCAP_ERRBUF_SIZE];

	dprintf(2,"listener handler invoked dumping=%d\n",dumping);

	if (dumping) {
		dprintf(2,"last round\n");
		keep_going = 0;
	} else {
		if (pcap_setfilter(listener, &stop_filter) < 0) {
			panic(23,"could not apply stop filter to listener: %s\n",pcap_geterr(listener));
		}

		dprintf(2,"apply stop filter to listener\n");

		if (pcap_setnonblock(listener, 1, errbuf) < 0) {
			panic(24,"could not set listener in non blocking mode: %s\n",errbuf);
		}

		dprintf(2,"listener -> non_blocking\n");
		dumping = 1;
	}
}

static void capture_handler(u_char* dumper, const struct pcap_pkthdr * ph, const u_char* buf) {
	dprintf(4,"capture handler invoked dumping=%d\n",dumping);
	if (dumping) {
		captured++;
		pcap_dump(dumper, ph, buf);
	}
}

static void sig_int(int sig) {
	keep_going = 0;
}

int main(int argc, char** argv) {
	char errbuf[PCAP_ERRBUF_SIZE];
	char* interface = NULL;
	char* outfile = NULL;
	guint snaplen = 65536;
	char* start_filter_str = NULL;
	char* stop_filter_str = NULL;
	char* capture_filter_str = NULL;
	int promisc = 0;
	int quiet = 0;
	struct bpf_program start_filter;
	struct bpf_program capture_filter;
	pcap_t* capturer = NULL;
	pcap_dumper_t* dumper = NULL;
	int opt;

	while ((opt = getopt(argc, argv, "i:w:s:b:e:f:phdq")) != -1) {
		switch (opt) {
			case 'i':
				if (interface) panic(1,"interface already given");
				interface = g_strdup(optarg);
				break;
			case 'w':
				if (outfile) panic(3,"output file already given");
				outfile = g_strdup(optarg);
				break;
			case 's':
				snaplen = strtoul(optarg,NULL,10);
				if ( snaplen == 0 )
					panic(4,"invalid snaplen");
				break;
			case 'b':
				if (start_filter_str) panic(5,"start filter already given");
				start_filter_str = g_strdup(optarg);
				break;
			case 'e':
				if (stop_filter_str) panic(6,"stop filter already given");
				stop_filter_str = g_strdup(optarg);
				break;
			case 'f':
				if (capture_filter_str) panic(7,"capture filter already given");
				capture_filter_str = g_strdup(optarg);
				break;
			case 'p':
				promisc = 1;
				break;
			case 'q':
				quiet = 1;
				break;
			case 'd':
				debug_level++;
				break;
			case 'h':
			default:
				usage(0);
				break;
			}
		}

	dprintf(1,"starting with:\n interface: %s\n snaplen: %d\n promisc: %d"
			"\n outfile: %s\n capture filter: %s\n start: %s\n stop: %s\n debug level: %d\n",
			interface ? interface : "to be chosen",
			snaplen,
			promisc,
			outfile ? outfile : "** missing **",
			capture_filter_str ? capture_filter_str : "** none given **",
			start_filter_str ? start_filter_str : "** missing **",
			stop_filter_str ? stop_filter_str : "** missing **",
			debug_level);

	if (! ( start_filter_str && stop_filter_str && outfile ) ) {
		usage(10);
	}

	if (! interface) {
		interface = pcap_lookupdev(errbuf);
		if (!interface) {
			panic(11, "could not obtain an interface: %s\n",errbuf);
		}
	}

#ifdef HAVE_PCAP_OPEN
	if ( ! ( capturer = pcap_open(interface, snaplen, promisc, 1, NULL, errbuf) )) {
#else
	if ( ! ( capturer = pcap_open_live(interface, snaplen, promisc, 1, errbuf) )) {
#endif
		panic(12,"could not open interface '%s' for listener: %s\n",interface,errbuf);
	}

	dprintf(1,"opened listener (%s,%d,%d)\n",interface,snaplen, promisc);

	if (pcap_compile(listener, &start_filter, start_filter_str, 1, 0) < 0) {
		panic(13,"could not compile start filter: %s\n",pcap_geterr(listener));
	}

	dprintf(2,"compiled start filter %s\n",start_filter_str);

	if (pcap_compile(listener, &stop_filter, stop_filter_str, 1, 0) < 0) {
		panic(14,"could not compile stop filter: %s\n",pcap_geterr(listener));
	}

	dprintf(2,"compiled stop filter %s\n",stop_filter_str);

#ifdef HAVE_PCAP_OPEN
	if ( ! ( capturer = pcap_open(interface, snaplen, promisc, 1, NULL, errbuf) )) {
#else
	if ( ! ( capturer = pcap_open_live(interface, snaplen, promisc, 1, errbuf) )) {
#endif
		panic(15,"could not open interface '%s' for capturer: %s\n",interface, errbuf);
	}

	dprintf(1,"opened capturer (%s,%d,%d)\n",interface,snaplen, promisc);

	if (capture_filter_str) {
		if (pcap_compile(capturer, &capture_filter, capture_filter_str, 1, 0) < 0) {
			panic(16,"could not compile capture filter: %s\n",pcap_geterr(capturer));
		}
		if (pcap_setfilter(capturer, &capture_filter) < 0) {
			panic(17,"could not apply start filter to capturer: %s\n",pcap_geterr(capturer));
		}

		dprintf(2,"compiled and set capture filter (%s)\n",capture_filter_str);
	}

	if (pcap_setfilter(listener, &start_filter) < 0) {
		panic(18,"could not apply start filter to listener: %s\n",pcap_geterr(listener));
	}
	dprintf(2,"set start filter on listener\n");


	if (pcap_setnonblock(listener, 0, errbuf) < 0) {
		panic(19,"could not set listener in blocking mode: %s\n",errbuf);
	}
	dprintf(2,"listener -> blocking\n");

	if (pcap_setnonblock(capturer, 1, errbuf) < 0) {
		panic(20,"could not set capturer in non blocking mode: %s\n",errbuf);
	}
	dprintf(2,"capturer -> non_blocking\n");

	if (! (dumper = pcap_dump_open(listener,outfile)) ) {
		panic(21,"open dumper file '%s': %s\n",outfile,pcap_geterr(listener));
	}
	dprintf(2,"opened dumper file '%s'\n",outfile);

	signal(SIGINT, sig_int);
#ifdef SIGQUIT
	signal(SIGQUIT, sig_int);
#endif
#ifdef SIGTERM
	signal(SIGTERM, sig_int);
#endif
#ifdef SIGSTOP
	signal(SIGSTOP, sig_int);
#endif

	keep_going = 1;
	dumping = 0;

	do {
		if (pcap_dispatch(listener, -1, listener_handler, NULL) < 0 ) {
			panic(22,"pcap_dispatch(listener) failed: %s\n",pcap_geterr(listener));
		}

		if (pcap_dispatch(capturer, -1, capture_handler, (void*)dumper) < 0 ) {
			panic(23,"pcap_dispatch(capturer) failed: %s\n",pcap_geterr(capturer));
		}
	} while(keep_going);

	if (!quiet) {
		printf("%d packets captured\n",captured);
	}

	dprintf(1,"done!\n");

	pcap_dump_close(dumper);
	pcap_close(listener);
	pcap_close(capturer);

	return 0;
}
