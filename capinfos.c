/* capinfos.c
 * Reports capture file information including # of packets, duration, others
 *
 * Copyright 2004 Ian Schorr
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
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/filesystem.h>
#include <epan/plugins.h>
#include <epan/report_err.h>
#include "wtap.h"
#include <wsutil/privileges.h>

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

static gboolean cap_file_type = FALSE;      /* Do not report capture type     */
static gboolean cap_file_encap = FALSE;     /* Do not report encapsulation    */
static gboolean cap_packet_count = FALSE;   /* Do not produce packet count    */
static gboolean cap_file_size = FALSE;      /* Do not report file size        */
static gboolean cap_data_size = FALSE;      /* Do not report packet byte size */
static gboolean cap_duration = FALSE;       /* Do not report capture duration */
static gboolean cap_start_time = FALSE;
static gboolean cap_end_time = FALSE;

static gboolean cap_data_rate_byte = FALSE;
static gboolean cap_data_rate_bit = FALSE;
static gboolean cap_packet_size = FALSE;
static gboolean cap_packet_rate = FALSE;


typedef struct _capture_info {
	const char		*filename;
	guint16			file_type;
	int			file_encap;
	gint64			filesize;
	guint64			packet_bytes;
	double			start_time;
	double			stop_time;
	guint32			packet_count;
	gboolean		snap_set;
	guint32			snaplen;
	gboolean		drops_known;
	guint32			drop_count;

	double			duration;
	double			packet_rate;
	double			packet_size;
	double			data_rate;		/* in bytes */
} capture_info;

static double
secs_nsecs(const struct wtap_nstime * nstime)
{
  return (nstime->nsecs / 1000000000.0) + (double)nstime->secs;
}

static void
print_stats(capture_info *cf_info)
{
  const gchar		*file_type_string, *file_encap_string;
  time_t		start_time_t;
  time_t		stop_time_t;

  /* Build printable strings for various stats */
  file_type_string = wtap_file_type_string(cf_info->file_type);
  file_encap_string = wtap_encap_string(cf_info->file_encap);
  start_time_t = (time_t)cf_info->start_time;
  stop_time_t = (time_t)cf_info->stop_time;

  if (cap_file_type) printf("File type: %s\n", file_type_string);
  if (cap_file_encap) printf("File encapsulation: %s\n", file_encap_string);
  if (cap_packet_count) printf("Number of packets: %u \n", cf_info->packet_count);
  if (cap_file_size) printf("File size: %" G_GINT64_MODIFIER "d bytes\n", cf_info->filesize);
  if (cap_data_size) printf("Data size: %" G_GINT64_MODIFIER "u bytes\n", cf_info->packet_bytes);
  if (cap_duration) printf("Capture duration: %f seconds\n", cf_info->duration);
  if (cap_start_time) printf("Start time: %s", (cf_info->packet_count>0) ? ctime (&start_time_t) : "n/a\n");
  if (cap_end_time) printf("End time: %s",     (cf_info->packet_count>0) ? ctime (&stop_time_t)  : "n/a\n");
  if (cap_data_rate_byte) printf("Data rate: %.2f bytes/s\n", cf_info->data_rate);
  if (cap_data_rate_bit) printf("Data rate: %.2f bits/s\n", cf_info->data_rate*8);
  if (cap_packet_size) printf("Average packet size: %.2f bytes\n", cf_info->packet_size);
  if (cap_packet_rate) printf("Average packet rate: %.2f packets/s\n", cf_info->packet_rate);
}

static int
process_cap_file(wtap *wth, const char *filename)
{
  int			err;
  gchar			*err_info;
  gint64		size;
  gint64		data_offset;

  guint32		packet = 0;
  gint64		bytes = 0;
  const struct wtap_pkthdr *phdr;
  capture_info  cf_info;
  double		start_time = 0;
  double		stop_time = 0;
  double		cur_time = 0;

  /* Tally up data that we need to parse through the file to find */
  while (wtap_read(wth, &err, &err_info, &data_offset))  {
    phdr = wtap_phdr(wth);
    cur_time = secs_nsecs(&phdr->ts);
    if(packet==0) {
      start_time = cur_time;
      stop_time = cur_time;
    }
    if (cur_time < start_time) {
      start_time = cur_time;
    }
    if (cur_time > stop_time) {
      stop_time = cur_time;
    }
    bytes+=phdr->len;
    packet++;
  }

  if (err != 0) {
    fprintf(stderr,
            "capinfos: An error occurred after reading %u packets from \"%s\": %s.\n",
	    packet, filename, wtap_strerror(err));
    switch (err) {

    case WTAP_ERR_UNSUPPORTED:
    case WTAP_ERR_UNSUPPORTED_ENCAP:
    case WTAP_ERR_BAD_RECORD:
      fprintf(stderr, "(%s)\n", err_info);
      g_free(err_info);
      break;
    }
    return 1;
  }

  /* File size */
  size = wtap_file_size(wth, &err);
  if (size == -1) {
    fprintf(stderr,
            "capinfos: Can't get size of \"%s\": %s.\n",
	    filename, strerror(err));
    return 1;
  }

  cf_info.filesize = size;

  /* File Type */
  cf_info.file_type = wtap_file_type(wth);

  /* File Encapsulation */
  cf_info.file_encap = wtap_file_encap(wth);

  /* # of packets */
  cf_info.packet_count = packet;

  /* File Times */
  cf_info.start_time = start_time;
  cf_info.stop_time = stop_time;
  cf_info.duration = stop_time-start_time;

  /* Number of packet bytes */
  cf_info.packet_bytes = bytes;

  if (packet > 0) {
    cf_info.data_rate   = (double)bytes / (stop_time-start_time);  /* Data rate per second */
    cf_info.packet_rate = (double)packet / (stop_time-start_time); /* packet rate per second */
    cf_info.packet_size = (double)bytes / packet;                  /* Avg packet size      */
  }
  else {
    cf_info.data_rate   = 0.0;
    cf_info.packet_rate = 0.0;
    cf_info.packet_size = 0.0;
  }

  printf("File name: %s\n", filename);
  print_stats(&cf_info);

  return 0;
}

static void
usage(gboolean is_error)
{
  FILE *output;

  if (!is_error) {
    output = stdout;
    /* XXX - add capinfos header info here */
  }
  else {
    output = stderr;
  }

  fprintf(output, "Capinfos %s"
#ifdef SVNVERSION
	  " (" SVNVERSION ")"
#endif
	  "\n", VERSION);
  fprintf(output, "Prints information about capture files.\n");
  fprintf(output, "See http://www.wireshark.org for more information.\n");
  fprintf(output, "\n");
  fprintf(output, "Usage: capinfos [options] <infile> ...\n");
  fprintf(output, "\n");
  fprintf(output, "General:\n");
  fprintf(output, "  -t display the capture file type\n");
  fprintf(output, "  -E display the capture file encapsulation\n");
  fprintf(output, "\n");
  fprintf(output, "Size:\n");
  fprintf(output, "  -c display the number of packets\n");
  fprintf(output, "  -s display the size of the file (in bytes)\n");
  fprintf(output, "  -d display the total length of all packets (in bytes)\n");
  fprintf(output, "\n");
  fprintf(output, "Time:\n");
  fprintf(output, "  -u display the capture duration (in seconds) \n");
  fprintf(output, "  -a display the capture start time\n");
  fprintf(output, "  -e display the capture end time\n");
  fprintf(output, "\n");
  fprintf(output, "Statistic:\n");
  fprintf(output, "  -y display average data rate (in bytes/s)\n");
  fprintf(output, "  -i display average data rate (in bits/s)\n");
  fprintf(output, "  -z display average packet size (in bytes)\n");
  fprintf(output, "  -x display average packet rate (in packets/s)\n");
  fprintf(output, "\n");
  fprintf(output, "Miscellaneous:\n");
  fprintf(output, "  -h display this help and exit\n");
  fprintf(output, "\n");
  fprintf(output, "If no options are given, default is to display all infos\n");
}

#ifdef HAVE_PLUGINS
/*
 *  Don't report failures to load plugins because most (non-wiretap) plugins
 *  *should* fail to load (because we're not linked against libwireshark and
 *  dissector plugins need libwireshark).
 */
static void
failure_message(const char *msg_format _U_, va_list ap _U_)
{
	return;
}
#endif


int
main(int argc, char *argv[])
{
  wtap *wth;
  int err;
  gchar *err_info;
  extern int optind;
  int opt;
  int status = 0;
#ifdef HAVE_PLUGINS
  char* init_progfile_dir_error;
#endif

  /*
   * Get credential information for later use.
   */
  get_credential_info();

#ifdef HAVE_PLUGINS
  /* Register wiretap plugins */

    if ((init_progfile_dir_error = init_progfile_dir(argv[0],
        (const void *)main))) {
		g_warning("capinfos: init_progfile_dir(): %s", init_progfile_dir_error);
		g_free(init_progfile_dir_error);
    } else {
		init_report_err(failure_message,NULL,NULL,NULL);
		init_plugins();
    }
#endif

  /* Process the options */

  while ((opt = getopt(argc, argv, "tEcsduaeyizvhx")) !=-1) {

    switch (opt) {

    case 't':
      cap_file_type = TRUE;
      break;

    case 'E':
      cap_file_encap = TRUE;
      break;

    case 'c':
      cap_packet_count = TRUE;
      break;

    case 's':
      cap_file_size = TRUE;
      break;

    case 'd':
      cap_data_size = TRUE;
      break;

    case 'u':
      cap_duration = TRUE;
      break;

    case 'a':
      cap_start_time = TRUE;
      break;

    case 'e':
      cap_end_time = TRUE;
      break;

    case 'y':
      cap_data_rate_byte = TRUE;
      break;

    case 'i':
      cap_data_rate_bit = TRUE;
      break;

    case 'z':
      cap_packet_size = TRUE;
      break;

    case 'x':
      cap_packet_rate = TRUE;
      break;

    case 'h':
      usage(FALSE);
      exit(1);
      break;

    case '?':              /* Bad flag - print usage message */
      usage(TRUE);
      exit(1);
      break;
    }
  }

  if (optind < 2) {

    /* If no arguments were given, by default display all statistics */
    cap_file_type = TRUE;
    cap_file_encap = TRUE;
    cap_packet_count = TRUE;
    cap_file_size = TRUE;
    cap_data_size = TRUE;
    cap_duration = TRUE;
    cap_start_time = TRUE;
    cap_end_time = TRUE;

    cap_data_rate_byte = TRUE;
    cap_data_rate_bit = TRUE;
    cap_packet_size = TRUE;
    cap_packet_rate = TRUE;
  }

  if ((argc - optind) < 1) {
    usage(TRUE);
    exit(1);
  }

  for (opt = optind; opt < argc; opt++) {

    wth = wtap_open_offline(argv[opt], &err, &err_info, FALSE);

    if (!wth) {
      fprintf(stderr, "capinfos: Can't open %s: %s\n", argv[opt],
	wtap_strerror(err));
      switch (err) {

      case WTAP_ERR_UNSUPPORTED:
      case WTAP_ERR_UNSUPPORTED_ENCAP:
      case WTAP_ERR_BAD_RECORD:
        fprintf(stderr, "(%s)\n", err_info);
        g_free(err_info);
        break;
      }
      exit(1);
    }

    if (opt > optind)
      printf("\n");
    status = process_cap_file(wth, argv[opt]);

    wtap_close(wth);
    if (status)
      exit(status);
  }
  return 0;
}

