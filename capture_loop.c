/* capture_loop.c
 * The actual capturing loop, getting packets and storing it
 *
 * $Id$
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


/** @file
 *  
 * Capture loop (internal interface).
 *
 * It will open the input and output files, capture the packets, 
 * change ringbuffer output files while capturing and close all files again.
 * 
 * The input file can be a network interface or capture pipe (unix only).
 * The output file can be a single or a ringbuffer file handled by wiretap.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP

#include <string.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#include <signal.h>
#include <errno.h>

#include <pcap.h>

#include <glib.h>

#include <epan/packet.h>
#include "capture.h"
#include "capture_loop.h"
#include "capture_info.h"
#include "capture_sync.h"
#include "pcap-util.h"

#include "simple_dialog.h"
#include "conditions.h"
#include "capture_stop_conditions.h"
#include "ringbuffer.h"

#include "wiretap/libpcap.h"
#include "wiretap/wtap.h"
#include "wiretap/wtap-capture.h"

/* XXX - try to remove this later */
#include <epan/prefs.h>
#include "ui_util.h"
/* XXX - try to remove this later */
#include "util.h"
#include "alert_box.h"
#include "log.h"
#include "file_util.h"




/*
 * We don't want to do a "select()" on the pcap_t's file descriptor on
 * BSD (because "select()" doesn't work correctly on BPF devices on at
 * least some releases of some flavors of BSD), and we don't want to do
 * it on Windows (because "select()" is something for sockets, not for
 * arbitrary handles).  (Note that "Windows" here includes Cygwin;
 * even in its pretend-it's-UNIX environment, we're using WinPcap, not
 * a UNIX libpcap.)
 *
 * We *do* want to do it on other platforms, as, on other platforms (with
 * the possible exception of Ultrix and Digital UNIX), the read timeout
 * doesn't expire if no packets have arrived, so a "pcap_dispatch()" call
 * will block until packets arrive, causing the UI to hang.
 *
 * XXX - the various BSDs appear to define BSD in <sys/param.h>; we don't
 * want to include it if it's not present on this platform, however.
 */
#if !defined(__FreeBSD__) && !defined(__NetBSD__) && !defined(__OpenBSD__) && \
    !defined(__bsdi__) && !defined(__APPLE__) && !defined(_WIN32) && \
    !defined(__CYGWIN__)
# define MUST_DO_SELECT
#endif


typedef struct _loop_data {
  /* common */
  gboolean       go;                    /* TRUE as long as we're supposed to keep capturing */
  int            err;                   /* if non-zero, error seen while capturing */
  gint           packets_curr;          /* Number of packets we have already captured */
  gint           packets_max;           /* Number of packets we're supposed to capture - 0 means infinite */
  gint           packets_sync_pipe;     /* packets not already send out to the sync_pipe */
  packet_counts  counts;                /* several packet type counters */
  gboolean       show_info;             /* show(hide) capture info dialog */

  /* pcap "input file" */
  pcap_t        *pcap_h;                /* pcap handle */
  gboolean       pcap_err;              /* TRUE if error from pcap */
#ifdef MUST_DO_SELECT
  int            pcap_fd;               /* pcap file descriptor */
#endif

  /* capture pipe (unix only "input file") */
  gboolean       from_cap_pipe;         /* TRUE if we are capturing data from a capture pipe */
#ifndef _WIN32
  struct pcap_hdr cap_pipe_hdr;
  struct pcaprec_modified_hdr cap_pipe_rechdr;
  int            cap_pipe_fd;           /* the file descriptor of the capture pipe */
  gboolean       cap_pipe_modified;     /* TRUE if data in the pipe uses modified pcap headers */
  gboolean       cap_pipe_byte_swapped; /* TRUE if data in the pipe is byte swapped */
  unsigned int   cap_pipe_bytes_to_read;/* Used by cap_pipe_dispatch */
  unsigned int   cap_pipe_bytes_read;   /* Used by cap_pipe_dispatch */
  enum {
         STATE_EXPECT_REC_HDR,
         STATE_READ_REC_HDR,
         STATE_EXPECT_DATA,
         STATE_READ_DATA
       } cap_pipe_state;

  enum { PIPOK, PIPEOF, PIPERR, PIPNEXIST } cap_pipe_err;
#endif

  /* wiretap (output file) */
  wtap_dumper   *wtap_pdh;
  gint           wtap_linktype;

} loop_data;


/*
 * Timeout, in milliseconds, for reads from the stream of captured packets.
 */
#define	CAP_READ_TIMEOUT	250

static void capture_loop_packet_cb(u_char *user, const struct pcap_pkthdr *phdr,
  const u_char *pd);
static void capture_loop_get_errmsg(char *errmsg, int errmsglen, const char *fname,
			  int err, gboolean is_close);



#ifndef _WIN32
/* Take care of byte order in the libpcap headers read from pipes.
 * (function taken from wiretap/libpcap.c) */
static void
cap_pipe_adjust_header(loop_data *ld, struct pcap_hdr *hdr, struct pcaprec_hdr *rechdr)
{
  if (ld->cap_pipe_byte_swapped) {
    /* Byte-swap the record header fields. */
    rechdr->ts_sec = BSWAP32(rechdr->ts_sec);
    rechdr->ts_usec = BSWAP32(rechdr->ts_usec);
    rechdr->incl_len = BSWAP32(rechdr->incl_len);
    rechdr->orig_len = BSWAP32(rechdr->orig_len);
  }

  /* In file format version 2.3, the "incl_len" and "orig_len" fields were
     swapped, in order to match the BPF header layout.

     Unfortunately, some files were, according to a comment in the "libpcap"
     source, written with version 2.3 in their headers but without the
     interchanged fields, so if "incl_len" is greater than "orig_len" - which
     would make no sense - we assume that we need to swap them.  */
  if (hdr->version_major == 2 &&
      (hdr->version_minor < 3 ||
       (hdr->version_minor == 3 && rechdr->incl_len > rechdr->orig_len))) {
    guint32 temp;

    temp = rechdr->orig_len;
    rechdr->orig_len = rechdr->incl_len;
    rechdr->incl_len = temp;
  }
}

/* Mimic pcap_open_live() for pipe captures
 * We check if "pipename" is "-" (stdin) or a FIFO, open it, and read the
 * header.
 * N.B. : we can't read the libpcap formats used in RedHat 6.1 or SuSE 6.3
 * because we can't seek on pipes (see wiretap/libpcap.c for details) */
static int
cap_pipe_open_live(char *pipename, struct pcap_hdr *hdr, loop_data *ld,
                 char *errmsg, int errmsgl)
{
  struct stat pipe_stat;
  int         fd;
  guint32     magic;
  int         b, sel_ret;
  unsigned int bytes_read;
  fd_set      rfds;
  struct timeval timeout;


  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "cap_pipe_open_live: %s", pipename);

  /*
   * XXX Ethereal blocks until we return
   */
  if (strcmp(pipename, "-") == 0)
    fd = 0; /* read from stdin */
  else {
    if (eth_stat(pipename, &pipe_stat) < 0) {
      if (errno == ENOENT || errno == ENOTDIR)
        ld->cap_pipe_err = PIPNEXIST;
      else {
        g_snprintf(errmsg, errmsgl,
          "The capture session could not be initiated "
          "due to error on pipe: %s", strerror(errno));
        ld->cap_pipe_err = PIPERR;
      }
      return -1;
    }
    if (! S_ISFIFO(pipe_stat.st_mode)) {
      if (S_ISCHR(pipe_stat.st_mode)) {
        /*
         * Assume the user specified an interface on a system where
         * interfaces are in /dev.  Pretend we haven't seen it.
         */
         ld->cap_pipe_err = PIPNEXIST;
      } else {
        g_snprintf(errmsg, errmsgl,
            "The capture session could not be initiated because\n"
            "\"%s\" is neither an interface nor a pipe", pipename);
        ld->cap_pipe_err = PIPERR;
      }
      return -1;
    }
    fd = eth_open(pipename, O_RDONLY | O_NONBLOCK, 0000 /* no creation so don't matter */);
    if (fd == -1) {
      g_snprintf(errmsg, errmsgl,
          "The capture session could not be initiated "
          "due to error on pipe open: %s", strerror(errno));
      ld->cap_pipe_err = PIPERR;
      return -1;
    }
  }

  ld->from_cap_pipe = TRUE;

  /* read the pcap header */
  FD_ZERO(&rfds);
  bytes_read = 0;
  while (bytes_read < sizeof magic) {
    FD_SET(fd, &rfds);
    timeout.tv_sec = 0;
    timeout.tv_usec = CAP_READ_TIMEOUT*1000;
    sel_ret = select(fd+1, &rfds, NULL, NULL, &timeout);
    if (sel_ret < 0) {
      g_snprintf(errmsg, errmsgl,
        "Unexpected error from select: %s", strerror(errno));
      goto error;
    } else if (sel_ret > 0) {
      b = read(fd, ((char *)&magic)+bytes_read, sizeof magic-bytes_read);
      if (b <= 0) {
        if (b == 0)
          g_snprintf(errmsg, errmsgl, "End of file on pipe during open");
        else
          g_snprintf(errmsg, errmsgl, "Error on pipe during open: %s",
            strerror(errno));
        goto error;
      }
      bytes_read += b;
    }
  }

  switch (magic) {
  case PCAP_MAGIC:
    /* Host that wrote it has our byte order, and was running
       a program using either standard or ss990417 libpcap. */
    ld->cap_pipe_byte_swapped = FALSE;
    ld->cap_pipe_modified = FALSE;
    break;
  case PCAP_MODIFIED_MAGIC:
    /* Host that wrote it has our byte order, but was running
       a program using either ss990915 or ss991029 libpcap. */
    ld->cap_pipe_byte_swapped = FALSE;
    ld->cap_pipe_modified = TRUE;
    break;
  case PCAP_SWAPPED_MAGIC:
    /* Host that wrote it has a byte order opposite to ours,
       and was running a program using either standard or
       ss990417 libpcap. */
    ld->cap_pipe_byte_swapped = TRUE;
    ld->cap_pipe_modified = FALSE;
    break;
  case PCAP_SWAPPED_MODIFIED_MAGIC:
    /* Host that wrote it out has a byte order opposite to
       ours, and was running a program using either ss990915
       or ss991029 libpcap. */
    ld->cap_pipe_byte_swapped = TRUE;
    ld->cap_pipe_modified = TRUE;
    break;
  default:
    /* Not a "libpcap" type we know about. */
    g_snprintf(errmsg, errmsgl, "Unrecognized libpcap format");
    goto error;
  }

  /* Read the rest of the header */
  bytes_read = 0;
  while (bytes_read < sizeof(struct pcap_hdr)) {
    FD_SET(fd, &rfds);
    timeout.tv_sec = 0;
    timeout.tv_usec = CAP_READ_TIMEOUT*1000;
    sel_ret = select(fd+1, &rfds, NULL, NULL, &timeout);
    if (sel_ret < 0) {
      g_snprintf(errmsg, errmsgl,
        "Unexpected error from select: %s", strerror(errno));
      goto error;
    } else if (sel_ret > 0) {
      b = read(fd, ((char *)hdr)+bytes_read,
            sizeof(struct pcap_hdr) - bytes_read);
      if (b <= 0) {
        if (b == 0)
          g_snprintf(errmsg, errmsgl, "End of file on pipe during open");
        else
          g_snprintf(errmsg, errmsgl, "Error on pipe during open: %s",
            strerror(errno));
        goto error;
      }
      bytes_read += b;
    }
  }

  if (ld->cap_pipe_byte_swapped) {
    /* Byte-swap the header fields about which we care. */
    hdr->version_major = BSWAP16(hdr->version_major);
    hdr->version_minor = BSWAP16(hdr->version_minor);
    hdr->snaplen = BSWAP32(hdr->snaplen);
    hdr->network = BSWAP32(hdr->network);
  }

  if (hdr->version_major < 2) {
    g_snprintf(errmsg, errmsgl, "Unable to read old libpcap format");
    goto error;
  }

  ld->cap_pipe_state = STATE_EXPECT_REC_HDR;
  ld->cap_pipe_err = PIPOK;
  return fd;

error:
  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "cap_pipe_open_live: error %s", errmsg);
  ld->cap_pipe_err = PIPERR;
  eth_close(fd);
  return -1;

}


/* We read one record from the pipe, take care of byte order in the record
 * header, write the record to the capture file, and update capture statistics. */
static int
cap_pipe_dispatch(int fd, loop_data *ld, struct pcap_hdr *hdr,
		struct pcaprec_modified_hdr *rechdr, guchar *data,
		char *errmsg, int errmsgl)
{
  struct pcap_pkthdr phdr;
  int b;
  enum { PD_REC_HDR_READ, PD_DATA_READ, PD_PIPE_EOF, PD_PIPE_ERR,
          PD_ERR } result;


#ifdef LOG_CAPTURE_VERBOSE
  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "cap_pipe_dispatch");
#endif

  switch (ld->cap_pipe_state) {

  case STATE_EXPECT_REC_HDR:
    ld->cap_pipe_bytes_to_read = ld->cap_pipe_modified ?
      sizeof(struct pcaprec_modified_hdr) : sizeof(struct pcaprec_hdr);
    ld->cap_pipe_bytes_read = 0;
    ld->cap_pipe_state = STATE_READ_REC_HDR;
    /* Fall through */

  case STATE_READ_REC_HDR:
    b = read(fd, ((char *)rechdr)+ld->cap_pipe_bytes_read,
      ld->cap_pipe_bytes_to_read - ld->cap_pipe_bytes_read);
    if (b <= 0) {
      if (b == 0)
        result = PD_PIPE_EOF;
      else
        result = PD_PIPE_ERR;
      break;
    }
    if ((ld->cap_pipe_bytes_read += b) < ld->cap_pipe_bytes_to_read)
        return 0;
    result = PD_REC_HDR_READ;
    break;

  case STATE_EXPECT_DATA:
    ld->cap_pipe_bytes_read = 0;
    ld->cap_pipe_state = STATE_READ_DATA;
    /* Fall through */

  case STATE_READ_DATA:
    b = read(fd, data+ld->cap_pipe_bytes_read, rechdr->hdr.incl_len - ld->cap_pipe_bytes_read);
    if (b <= 0) {
      if (b == 0)
        result = PD_PIPE_EOF;
      else
        result = PD_PIPE_ERR;
      break;
    }
    if ((ld->cap_pipe_bytes_read += b) < rechdr->hdr.incl_len)
      return 0;
    result = PD_DATA_READ;
    break;

  default:
    g_snprintf(errmsg, errmsgl, "cap_pipe_dispatch: invalid state");
    result = PD_ERR;

  } /* switch (ld->cap_pipe_state) */

  /*
   * We've now read as much data as we were expecting, so process it.
   */
  switch (result) {

  case PD_REC_HDR_READ:
    /* We've read the header. Take care of byte order. */
    cap_pipe_adjust_header(ld, hdr, &rechdr->hdr);
    if (rechdr->hdr.incl_len > WTAP_MAX_PACKET_SIZE) {
      g_snprintf(errmsg, errmsgl, "Frame %u too long (%d bytes)",
        ld->packets_curr+1, rechdr->hdr.incl_len);
      break;
    }
    ld->cap_pipe_state = STATE_EXPECT_DATA;
    return 0;

  case PD_DATA_READ:
    /* Fill in a "struct pcap_pkthdr", and process the packet. */
    phdr.ts.tv_sec = rechdr->hdr.ts_sec;
    phdr.ts.tv_usec = rechdr->hdr.ts_usec;
    phdr.caplen = rechdr->hdr.incl_len;
    phdr.len = rechdr->hdr.orig_len;

    capture_loop_packet_cb((u_char *)ld, &phdr, data);

    ld->cap_pipe_state = STATE_EXPECT_REC_HDR;
    return 1;

  case PD_PIPE_EOF:
    ld->cap_pipe_err = PIPEOF;
    return -1;

  case PD_PIPE_ERR:
    g_snprintf(errmsg, errmsgl, "Error reading from pipe: %s",
      strerror(errno));
    /* Fall through */
  case PD_ERR:
    break;
  }

  ld->cap_pipe_err = PIPERR;
  /* Return here rather than inside the switch to prevent GCC warning */
  return -1;
}
#endif /* not _WIN32 */


/* open the capture input file (pcap or capture pipe) */
static int capture_loop_open_input(capture_options *capture_opts, loop_data *ld, char *errmsg, int errmsg_len) {
  gchar       open_err_str[PCAP_ERRBUF_SIZE];
  const char *set_linktype_err_str;
#ifdef _WIN32
  int         err;
  WORD        wVersionRequested;
  WSADATA     wsaData;
#else
  static const char ppamsg[] = "can't find PPA for ";
  const char  *libpcap_warn;
#endif


  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_open_input : %s", capture_opts->iface);

  /* Initialize Windows Socket if we are in a WIN32 OS
     This needs to be done before querying the interface for network/netmask */
#ifdef _WIN32
  /* XXX - do we really require 1.1 or earlier?
     Are there any versions that support only 2.0 or higher? */
  wVersionRequested = MAKEWORD(1, 1);
  err = WSAStartup(wVersionRequested, &wsaData);
  if (err != 0) {
    switch (err) {

    case WSASYSNOTREADY:
      g_snprintf(errmsg, errmsg_len,
        "Couldn't initialize Windows Sockets: Network system not ready for network communication");
      break;

    case WSAVERNOTSUPPORTED:
      g_snprintf(errmsg, errmsg_len,
        "Couldn't initialize Windows Sockets: Windows Sockets version %u.%u not supported",
        LOBYTE(wVersionRequested), HIBYTE(wVersionRequested));
      break;

    case WSAEINPROGRESS:
      g_snprintf(errmsg, errmsg_len,
        "Couldn't initialize Windows Sockets: Blocking operation is in progress");
      break;

    case WSAEPROCLIM:
      g_snprintf(errmsg, errmsg_len,
        "Couldn't initialize Windows Sockets: Limit on the number of tasks supported by this WinSock implementation has been reached");
      break;

    case WSAEFAULT:
      g_snprintf(errmsg, errmsg_len,
        "Couldn't initialize Windows Sockets: Bad pointer passed to WSAStartup");
      break;

    default:
      g_snprintf(errmsg, errmsg_len,
        "Couldn't initialize Windows Sockets: error %d", err);
      break;
    }
    return FALSE;
  }
#endif

  /* Open the network interface to capture from it.
     Some versions of libpcap may put warnings into the error buffer
     if they succeed; to tell if that's happened, we have to clear
     the error buffer, and check if it's still a null string.  */
  open_err_str[0] = '\0';
  ld->pcap_h = pcap_open_live(capture_opts->iface,
		       capture_opts->has_snaplen ? capture_opts->snaplen :
						  WTAP_MAX_PACKET_SIZE,
		       capture_opts->promisc_mode, CAP_READ_TIMEOUT,
		       open_err_str);

  if (ld->pcap_h != NULL) {
    /* we've opened "iface" as a network device */
#ifdef _WIN32
    /* try to set the capture buffer size */
    if (pcap_setbuff(ld->pcap_h, capture_opts->buffer_size * 1024 * 1024) != 0) {
        simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
          "%sCouldn't set the capture buffer size!%s\n"
          "\n"
          "The capture buffer size of %luMB seems to be too high for your machine,\n"
          "the default of 1MB will be used.\n"
          "\n"
          "Nonetheless, the capture is started.\n",
          simple_dialog_primary_start(), simple_dialog_primary_end(), capture_opts->buffer_size);
    }
#endif

    /* setting the data link type only works on real interfaces */
    if (capture_opts->linktype != -1) {
      set_linktype_err_str = set_pcap_linktype(ld->pcap_h, capture_opts->iface,
	capture_opts->linktype);
      if (set_linktype_err_str != NULL) {
	g_snprintf(errmsg, errmsg_len, "Unable to set data link type (%s).",
	  set_linktype_err_str);
	return FALSE;
      }
    }
  } else {
    /* We couldn't open "iface" as a network device. */
#ifdef _WIN32
    /* On Windows, we don't support capturing on pipes, so we give up. */

    /* On Win32 OSes, the capture devices are probably available to all
       users; don't warn about permissions problems.

       Do, however, warn that WAN devices aren't supported. */
    g_snprintf(errmsg, errmsg_len,
"%sThe capture session could not be initiated!%s\n"
"\n"
"(%s)\n"
"\n"
"Please check that you have the proper interface specified.\n"
"\n"
"\n"
"Help can be found at:\n"
"\n"
"       %shttp://wiki.ethereal.com/CaptureSetup%s\n"
"\n"
"64-bit Windows:\n"
"WinPcap does not support 64-bit Windows, you will have to use some other\n"
"tool to capture traffic, such as netcap.\n"
"For netcap details see: http://support.microsoft.com/?id=310875\n"
"\n"
"Modem (PPP/WAN):\n"
"Note that version 3.0 of WinPcap, and earlier versions of WinPcap, don't\n"
"support capturing on PPP/WAN interfaces on Windows NT 4.0 / 2000 / XP /\n"
"Server 2003.\n"
"WinPcap 3.1 has support for it on Windows 2000 / XP / Server 2003, but has no\n"
"support for it on Windows NT 4.0 or Windows Vista (Beta 1).",
	simple_dialog_primary_start(), simple_dialog_primary_end(),
    open_err_str,
	simple_dialog_primary_start(), simple_dialog_primary_end());
    return FALSE;
#else
    /* try to open iface as a pipe */
    ld->cap_pipe_fd = cap_pipe_open_live(capture_opts->iface, &ld->cap_pipe_hdr, ld, errmsg, errmsg_len);

    if (ld->cap_pipe_fd == -1) {

      if (ld->cap_pipe_err == PIPNEXIST) {
	/* Pipe doesn't exist, so output message for interface */

	/* If we got a "can't find PPA for XXX" message, warn the user (who
	   is running Ethereal on HP-UX) that they don't have a version
	   of libpcap that properly handles HP-UX (libpcap 0.6.x and later
	   versions, which properly handle HP-UX, say "can't find /dev/dlpi
	   PPA for XXX" rather than "can't find PPA for XXX"). */
	if (strncmp(open_err_str, ppamsg, sizeof ppamsg - 1) == 0)
	  libpcap_warn =
	    "\n\n"
	    "You are running Ethereal with a version of the libpcap library\n"
	    "that doesn't handle HP-UX network devices well; this means that\n"
	    "Ethereal may not be able to capture packets.\n"
	    "\n"
	    "To fix this, you should install libpcap 0.6.2, or a later version\n"
	    "of libpcap, rather than libpcap 0.4 or 0.5.x.  It is available in\n"
	    "packaged binary form from the Software Porting And Archive Centre\n"
	    "for HP-UX; the Centre is at http://hpux.connect.org.uk/ - the page\n"
	    "at the URL lists a number of mirror sites.";
	else
	  libpcap_warn = "";
	g_snprintf(errmsg, errmsg_len,
	  "The capture session could not be initiated (%s).\n"
	  "Please check to make sure you have sufficient permissions, and that\n"
	  "you have the proper interface or pipe specified.%s", open_err_str,
	  libpcap_warn);
      }
      /*
       * Else pipe (or file) does exist and cap_pipe_open_live() has
       * filled in errmsg
       */
      return FALSE;
    } else
      /* cap_pipe_open_live() succeeded; don't want
         error message from pcap_open_live() */
      open_err_str[0] = '\0';
#endif
  }

#ifdef MUST_DO_SELECT
  if (!ld->from_cap_pipe) {
#ifdef HAVE_PCAP_GET_SELECTABLE_FD
    ld->pcap_fd = pcap_get_selectable_fd(ld->pcap_h);
#else
    ld->pcap_fd = pcap_fileno(ld->pcap_h);
#endif
  }
#endif

  /* Does "open_err_str" contain a non-empty string?  If so, "pcap_open_live()"
     returned a warning; print it, but keep capturing. */
  if (open_err_str[0] != '\0')
    g_warning("%s.", open_err_str);

  return TRUE;
}


/* open the capture input file (pcap or capture pipe) */
static void capture_loop_close_input(loop_data *ld) {

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_close_input");

#ifndef _WIN32
  /* if open, close the capture pipe "input file" */
  if (ld->cap_pipe_fd >= 0) {
    g_assert(ld->from_cap_pipe);
    eth_close(ld->cap_pipe_fd);
  }
#endif

  /* if open, close the pcap "input file" */
  if(ld->pcap_h != NULL) {
    g_assert(!ld->from_cap_pipe);
    pcap_close(ld->pcap_h);
  }

#ifdef _WIN32
  /* Shut down windows sockets */
  WSACleanup();
#endif
}


/* init the capture filter */
static int capture_loop_init_filter(loop_data *ld, const gchar * iface, gchar * cfilter, char *errmsg, int errmsg_len) {
  bpf_u_int32 netnum, netmask;
  gchar       lookup_net_err_str[PCAP_ERRBUF_SIZE];
  struct bpf_program fcode;


  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_init_filter: %s", cfilter);

  /* capture filters only work on real interfaces */
  if (cfilter && !ld->from_cap_pipe) {
    /* A capture filter was specified; set it up. */
    if (pcap_lookupnet(iface, &netnum, &netmask, lookup_net_err_str) < 0) {
      /*
       * Well, we can't get the netmask for this interface; it's used
       * only for filters that check for broadcast IP addresses, so
       * we just punt and use 0.  It might be nice to warn the user,
       * but that's a pain in a GUI application, as it'd involve popping
       * up a message box, and it's not clear how often this would make
       * a difference (only filters that check for IP broadcast addresses
       * use the netmask).
       */
      netmask = 0;
    }
    if (pcap_compile(ld->pcap_h, &fcode, cfilter, 1, netmask) < 0) {
      dfilter_t   *rfcode = NULL;
      gchar *safe_cfilter = simple_dialog_format_message(cfilter);
      gchar *safe_cfilter_error_msg = simple_dialog_format_message(
	  pcap_geterr(ld->pcap_h));

      /* filter string invalid, did the user tried a display filter? */
#ifndef DUMPCAP
      if (dfilter_compile(cfilter, &rfcode) && rfcode != NULL) {
        g_snprintf(errmsg, errmsg_len,
          "%sInvalid capture filter: \"%s\"!%s\n"
          "\n"
          "That string looks like a valid display filter; however, it isn't a valid\n"
          "capture filter (%s).\n"
          "\n"
          "Note that display filters and capture filters don't have the same syntax,\n"
          "so you can't use most display filter expressions as capture filters.\n"
          "\n"
          "See the help for a description of the capture filter syntax.",
          simple_dialog_primary_start(), safe_cfilter,
          simple_dialog_primary_end(), safe_cfilter_error_msg);
	dfilter_free(rfcode);
      } else 
#endif
      {
        g_snprintf(errmsg, errmsg_len,
          "%sInvalid capture filter: \"%s\"!%s\n"
          "\n"
          "That string isn't a valid capture filter (%s).\n"
          "See the help for a description of the capture filter syntax.",
          simple_dialog_primary_start(), safe_cfilter,
          simple_dialog_primary_end(), safe_cfilter_error_msg);
      }
      g_free(safe_cfilter_error_msg);
      g_free(safe_cfilter);
      return FALSE;
    }
    if (pcap_setfilter(ld->pcap_h, &fcode) < 0) {
      g_snprintf(errmsg, errmsg_len, "Can't install filter (%s).",
	pcap_geterr(ld->pcap_h));
#ifdef HAVE_PCAP_FREECODE
      pcap_freecode(&fcode);
#endif
      return FALSE;
    }
#ifdef HAVE_PCAP_FREECODE
    pcap_freecode(&fcode);
#endif
  }

  return TRUE;
}


/* open the wiretap part of the capture output file */
static int capture_loop_init_wiretap_output(capture_options *capture_opts, int save_file_fd, loop_data *ld, char *errmsg, int errmsg_len) {
  int         pcap_encap;
  int         file_snaplen;
  int         err;


  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_init_wiretap_output");

  /* get packet encapsulation type and snaplen */
#ifndef _WIN32
  if (ld->from_cap_pipe) {
    pcap_encap = ld->cap_pipe_hdr.network;
    file_snaplen = ld->cap_pipe_hdr.snaplen;
  } else
#endif
  {
    pcap_encap = get_pcap_linktype(ld->pcap_h, capture_opts->iface);
    file_snaplen = pcap_snapshot(ld->pcap_h);
  }

  /* Set up to write to the capture file. */
  ld->wtap_linktype = wtap_pcap_encap_to_wtap_encap(pcap_encap);
  if (ld->wtap_linktype == WTAP_ENCAP_UNKNOWN) {
    g_snprintf(errmsg, errmsg_len,
	"The network you're capturing from is of a type"
	" that Ethereal doesn't support (data link type %d).", pcap_encap);
    return FALSE;
  }
  if (capture_opts->multi_files_on) {
    ld->wtap_pdh = ringbuf_init_wtap_dump_fdopen(WTAP_FILE_PCAP, ld->wtap_linktype,
      file_snaplen, &err);
  } else {
    ld->wtap_pdh = wtap_dump_fdopen(save_file_fd, WTAP_FILE_PCAP,
      ld->wtap_linktype, file_snaplen, FALSE /* compressed */, &err);
  }

  if (ld->wtap_pdh == NULL) {
    /* We couldn't set up to write to the capture file. */
    switch (err) {

    case WTAP_ERR_CANT_OPEN:
      strcpy(errmsg, "The file to which the capture would be saved"
               " couldn't be created for some unknown reason.");
      break;

    case WTAP_ERR_SHORT_WRITE:
      strcpy(errmsg, "A full header couldn't be written to the file"
               " to which the capture would be saved.");
      break;

    default:
      if (err < 0) {
        g_snprintf(errmsg, errmsg_len,
		     "The file to which the capture would be"
                     " saved (\"%s\") could not be opened: Error %d.",
 			capture_opts->save_file, err);
      } else {
        g_snprintf(errmsg, errmsg_len,
		     "The file to which the capture would be"
                     " saved (\"%s\") could not be opened: %s.",
 			capture_opts->save_file, strerror(err));
      }
      break;
    }

    return FALSE;
  }

  return TRUE;
}

static gboolean capture_loop_close_output(capture_options *capture_opts, loop_data *ld, int *err_close) {

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_close_output");

  if (capture_opts->multi_files_on) {
    return ringbuf_wtap_dump_close(&capture_opts->save_file, err_close);
  } else {
    return wtap_dump_close(ld->wtap_pdh, err_close);
  }
}

/* dispatch incoming packets (pcap or capture pipe) */
static int
capture_loop_dispatch(capture_options *capture_opts, loop_data *ld,
		      char *errmsg, int errmsg_len) {
  int       inpkts;
#ifndef _WIN32
  fd_set    set1;
  struct timeval timeout;
  int         sel_ret;
  guchar pcap_data[WTAP_MAX_PACKET_SIZE];
#endif

#ifndef _WIN32
    if (ld->from_cap_pipe) {
      /* dispatch from capture pipe */
#ifdef LOG_CAPTURE_VERBOSE
      g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_dispatch: from capture pipe");
#endif
      FD_ZERO(&set1);
      FD_SET(ld->cap_pipe_fd, &set1);
      timeout.tv_sec = 0;
      timeout.tv_usec = CAP_READ_TIMEOUT*1000;
      sel_ret = select(ld->cap_pipe_fd+1, &set1, NULL, NULL, &timeout);
      if (sel_ret <= 0) {
	inpkts = 0;
        if (sel_ret < 0 && errno != EINTR) {
          g_snprintf(errmsg, errmsg_len,
            "Unexpected error from select: %s", strerror(errno));
          sync_pipe_errmsg_to_parent(errmsg);
          ld->go = FALSE;
        }
      } else {
	/*
	 * "select()" says we can read from the pipe without blocking
	 */
	inpkts = cap_pipe_dispatch(ld->cap_pipe_fd, ld, &ld->cap_pipe_hdr, &ld->cap_pipe_rechdr, pcap_data,
          errmsg, errmsg_len);
	if (inpkts < 0) {
	  ld->go = FALSE;
        }
      }
    }
    else
#endif /* _WIN32 */
    {
      /* dispatch from pcap */
#ifdef MUST_DO_SELECT
      /*
       * Sigh.  The semantics of the read timeout argument to
       * "pcap_open_live()" aren't particularly well specified by
       * the "pcap" man page - at least with the BSD BPF code, the
       * intent appears to be, at least in part, a way of cutting
       * down the number of reads done on a capture, by blocking
       * until the buffer fills or a timer expires - and the Linux
       * libpcap doesn't actually support it, so we can't use it
       * to break out of the "pcap_dispatch()" every 1/4 of a second
       * or so.  Linux's libpcap is not the only libpcap that doesn't
       * support the read timeout.
       *
       * Furthermore, at least on Solaris, the bufmod STREAMS module's
       * read timeout won't go off if no data has arrived, i.e. it cannot
       * be used to guarantee that a read from a DLPI stream will return
       * within a specified amount of time regardless of whether any
       * data arrives or not.
       *
       * Thus, on all platforms other than BSD, we do a "select()" on the
       * file descriptor for the capture, with a timeout of CAP_READ_TIMEOUT
       * milliseconds, or CAP_READ_TIMEOUT*1000 microseconds.
       *
       * "select()", on BPF devices, doesn't work as you might expect;
       * at least on some versions of some flavors of BSD, the timer
       * doesn't start until a read is done, so it won't expire if
       * only a "select()" or "poll()" is posted.
       *
       * If we have "pcap_get_selectable_fd()", we use it to get the
       * descriptor on which to select; if that's -1, it means there
       * is no descriptor on which you can do a "select()" (perhaps
       * because you're capturing on a special device, and that device's
       * driver unfortunately doesn't support "select()", in which case
       * we don't do the select - which means Ethereal might block,
       * unable to accept user input, until a packet arrives.  If
       * that's unacceptable, plead with whoever supplies the software
       * for that device to add "select()" support.
       */
#ifdef LOG_CAPTURE_VERBOSE
      g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_dispatch: from pcap_dispatch with select");
#endif
      if (ld->pcap_fd != -1) {
        FD_ZERO(&set1);
        FD_SET(ld->pcap_fd, &set1);
        timeout.tv_sec = 0;
        timeout.tv_usec = CAP_READ_TIMEOUT*1000;
        sel_ret = select(ld->pcap_fd+1, &set1, NULL, NULL, &timeout);
        if (sel_ret > 0) {
          /*
           * "select()" says we can read from it without blocking; go for
           * it.
           */
          inpkts = pcap_dispatch(ld->pcap_h, 1, capture_loop_packet_cb, (u_char *)ld);
          if (inpkts < 0) {
            ld->pcap_err = TRUE;
            ld->go = FALSE;
          }
        } else {
          inpkts = 0;
          if (sel_ret < 0 && errno != EINTR) {
            g_snprintf(errmsg, errmsg_len,
              "Unexpected error from select: %s", strerror(errno));
            sync_pipe_errmsg_to_parent(errmsg);
            ld->go = FALSE;
          }
        }
      }
      else
#endif /* MUST_DO_SELECT */
      {
        /* dispatch from pcap without select */
#if 1
#ifdef LOG_CAPTURE_VERBOSE
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_dispatch: from pcap_dispatch");
#endif
        inpkts = pcap_dispatch(ld->pcap_h, 1, capture_loop_packet_cb, (u_char *) ld);
        if (inpkts < 0) {
          ld->pcap_err = TRUE;
          ld->go = FALSE;
        }
#else
        {
#ifdef LOG_CAPTURE_VERBOSE
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_dispatch: from pcap_next_ex");
#endif
            /* XXX - this is currently unused, as there is some confusion with pcap_next_ex() vs. pcap_dispatch() */

            /* WinPcap's remote capturing feature doesn't work, see http://wiki.ethereal.com/CaptureSetup_2fWinPcapRemote */
            /* for reference, an example remote interface: rpcap://[1.2.3.4]/\Device\NPF_{39993D68-7C9B-4439-A329-F2D888DA7C5C} */

            /* emulate dispatch from pcap */
            int in;
            struct pcap_pkthdr *pkt_header;
		    u_char *pkt_data;

            inpkts = 0;
            while( (in = pcap_next_ex(ld->pcap_h, &pkt_header, &pkt_data)) == 1) {
                capture_loop_packet_cb( (u_char *) ld, pkt_header, pkt_data);
                inpkts++;
            }

            if(in < 0) {
              ld->pcap_err = TRUE;
              ld->go = FALSE;
              inpkts = in;
            }
        }
#endif
      }
    }

#ifdef LOG_CAPTURE_VERBOSE
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_dispatch: %d new packet%s", inpkts, plurality(inpkts, "", "s"));
#endif

    return inpkts;
}


/* open the output file (temporary/specified name/ringbuffer) */
/* Returns TRUE if the file opened successfully, FALSE otherwise. */
static gboolean
capture_loop_open_output(capture_options *capture_opts, int *save_file_fd,
		      char *errmsg, int errmsg_len) {

  char tmpname[128+1];
  gchar *capfile_name;
  gboolean is_tempfile;


  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_open_output: %s", 
      (capture_opts->save_file) ? capture_opts->save_file : "");

  if (capture_opts->save_file != NULL) {
    /* We return to the caller while the capture is in progress.  
     * Therefore we need to take a copy of save_file in
     * case the caller destroys it after we return.
     */
    capfile_name = g_strdup(capture_opts->save_file);
    if (capture_opts->multi_files_on) {
      /* ringbuffer is enabled */
      *save_file_fd = ringbuf_init(capfile_name,
          (capture_opts->has_ring_num_files) ? capture_opts->ring_num_files : 0);

      /* we need the ringbuf name */
      if(*save_file_fd != -1) {
          g_free(capfile_name);
          capfile_name = g_strdup(ringbuf_current_filename());
      }
    } else {
      /* Try to open/create the specified file for use as a capture buffer. */
      *save_file_fd = open(capfile_name, O_RDWR|O_BINARY|O_TRUNC|O_CREAT,
				0600);
    }
    is_tempfile = FALSE;
  } else {
    /* Choose a random name for the temporary capture buffer */
    *save_file_fd = create_tempfile(tmpname, sizeof tmpname, "ether");
    capfile_name = g_strdup(tmpname);
    is_tempfile = TRUE;
  }

  /* did we fail to open the output file? */
  if (*save_file_fd == -1) {
    if (is_tempfile) {
      g_snprintf(errmsg, errmsg_len,
	"The temporary file to which the capture would be saved (\"%s\") "
	"could not be opened: %s.", capfile_name, strerror(errno));
    } else {
      if (capture_opts->multi_files_on) {
        ringbuf_error_cleanup();
      }

      g_snprintf(errmsg, errmsg_len,
	    "The file to which the capture would be saved (\"%s\") "
        "could not be opened: %s.", capfile_name, 
        strerror(errno));

      /*open_failure_alert_box(capfile_name, errno, TRUE);*/
    }
    g_free(capfile_name);
    return FALSE;
  }

  if(capture_opts->save_file != NULL) {
    g_free(capture_opts->save_file);
  }
  capture_opts->save_file = capfile_name;
  /* capture_opts.save_file is "g_free"ed later, which is equivalent to
     "g_free(capfile_name)". */

  return TRUE;
}


#ifndef _WIN32
static void
capture_loop_stop_signal_handler(int signo _U_)
{
  capture_loop_stop();
}
#endif

#ifdef _WIN32
#define TIME_GET() GetTickCount()
#else
#define TIME_GET() time(NULL)
#endif

/*
 * This needs to be static, so that the SIGUSR1 handler can clear the "go"
 * flag.
 */
static loop_data   ld;

/* Do the low-level work of a capture.
   Returns TRUE if it succeeds, FALSE otherwise. */
int
capture_loop_start(capture_options *capture_opts, gboolean *stats_known, struct pcap_stat *stats)
{
  time_t      upd_time, cur_time;
  time_t      start_time;
  int         err_close, inpkts;
  condition  *cnd_file_duration = NULL;
  condition  *cnd_autostop_files = NULL;
  condition  *cnd_autostop_size = NULL;
  condition  *cnd_autostop_duration = NULL;
  guint32     autostop_files = 0;
  gboolean    write_ok;
  gboolean    close_ok;
  capture_info   capture_ui;
  char        errmsg[4096+1];
  int         save_file_fd;


  /* init the loop data */
  ld.go                 = TRUE;
  ld.packets_curr       = 0;
  if (capture_opts->has_autostop_packets)
    ld.packets_max      = capture_opts->autostop_packets;
  else
    ld.packets_max      = 0;	/* no limit */
  ld.err                = 0;	/* no error seen yet */
  ld.wtap_linktype      = WTAP_ENCAP_UNKNOWN;
  ld.pcap_err           = FALSE;
  ld.from_cap_pipe      = FALSE;
  ld.packets_sync_pipe  = 0;
  ld.wtap_pdh           = NULL;
#ifndef _WIN32
  ld.cap_pipe_fd        = -1;
#endif
#ifdef MUST_DO_SELECT
  ld.pcap_fd            = 0;
#endif
  ld.show_info          = capture_opts->show_info;

#ifndef _WIN32
  /*
   * Catch SIGUSR1, so that we exit cleanly if the parent process
   * kills us with it due to the user selecting "Capture->Stop".
   */
    signal(SIGUSR1, capture_loop_stop_signal_handler);
#endif

  /* We haven't yet gotten the capture statistics. */
  *stats_known      = FALSE;

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture child starting ...");
  capture_opts_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, capture_opts);

  /* open the output file (temporary/specified name/ringbuffer) */
  if (!capture_loop_open_output(capture_opts, &save_file_fd, errmsg, sizeof(errmsg))) {
    goto error;    
  }

  /* open the "input file" from network interface or capture pipe */
  if (!capture_loop_open_input(capture_opts, &ld, errmsg, sizeof(errmsg))) {
    goto error;
  }

  /* init the input filter from the network interface (capture pipe will do nothing) */
  if (!capture_loop_init_filter(&ld, capture_opts->iface, capture_opts->cfilter, errmsg, sizeof(errmsg))) {
    goto error;
  }

  /* open the wiretap part of the output file (the output file is already open) */
  if (!capture_loop_init_wiretap_output(capture_opts, save_file_fd, &ld, errmsg, sizeof(errmsg))) {
    goto error;
  }

  /* XXX - capture SIGTERM and close the capture, in case we're on a
     Linux 2.0[.x] system and you have to explicitly close the capture
     stream in order to turn promiscuous mode off?  We need to do that
     in other places as well - and I don't think that works all the
     time in any case, due to libpcap bugs. */

  /* Well, we should be able to start capturing.

     Sync out the capture file, so the header makes it to the file system,
     and send a "capture started successfully and capture file created"
     message to our parent so that they'll open the capture file and
     update its windows to indicate that we have a live capture in
     progress. */
  wtap_dump_flush(ld.wtap_pdh);
  sync_pipe_filename_to_parent(capture_opts->save_file);

  /* initialize capture stop (and alike) conditions */
  init_capture_stop_conditions();
  /* create stop conditions */
  if (capture_opts->has_autostop_filesize)
    cnd_autostop_size =
        cnd_new(CND_CLASS_CAPTURESIZE,(long)capture_opts->autostop_filesize * 1024);
  if (capture_opts->has_autostop_duration)
    cnd_autostop_duration =
        cnd_new(CND_CLASS_TIMEOUT,(gint32)capture_opts->autostop_duration);

  if (capture_opts->multi_files_on) {
      if (capture_opts->has_file_duration)
        cnd_file_duration =
	    cnd_new(CND_CLASS_TIMEOUT, capture_opts->file_duration);

      if (capture_opts->has_autostop_files)
        cnd_autostop_files =
	    cnd_new(CND_CLASS_CAPTURESIZE, capture_opts->autostop_files);
  }

  /* start capture info dialog */
  if(capture_opts->show_info) {
      capture_info_init(&ld.counts);
      capture_ui.counts = &ld.counts;
      capture_info_ui_create(&capture_ui, capture_opts->iface);
  }

  /* init the time values */
  start_time = TIME_GET();
  upd_time = TIME_GET();


  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture child running!");

  /* WOW, everything is prepared! */
  /* please fasten your seat belts, we will enter now the actual capture loop */
  while (ld.go) {
    main_window_update();

    /* dispatch incoming packets */
    inpkts = capture_loop_dispatch(capture_opts, &ld, errmsg, sizeof(errmsg));

    main_window_update();

#ifdef _WIN32
      /* some news from our parent (signal pipe)? -> just stop the capture */
      {
          HANDLE handle;
          DWORD avail = 0;
          gboolean result;


          handle = (HANDLE) _get_osfhandle (0);
          result = PeekNamedPipe(handle, NULL, 0, NULL, &avail, NULL);

          if(!result || avail > 0) {
            /* XXX - doesn't work with dumpcap as a command line tool */
            /* as we have no input pipe, need to find a way to circumvent this */
#ifndef DUMPCAP
            ld.go = FALSE;
#endif
            /*g_warning("loop closing");*/
          }
      }
#endif

    if (inpkts > 0) {
      ld.packets_sync_pipe += inpkts;

      /* check capture size condition */
      if (cnd_autostop_size != NULL && cnd_eval(cnd_autostop_size,
                    (guint32)wtap_get_bytes_dumped(ld.wtap_pdh))){
        /* Capture size limit reached, do we have another file? */
        if (capture_opts->multi_files_on) {
          if (cnd_autostop_files != NULL && cnd_eval(cnd_autostop_files, ++autostop_files)) {
            /* no files left: stop here */
            ld.go = FALSE;
            continue;
          }

          /* Switch to the next ringbuffer file */
          if (ringbuf_switch_file(&ld.wtap_pdh, &capture_opts->save_file, &save_file_fd, &ld.err)) {
            /* File switch succeeded: reset the conditions */
            cnd_reset(cnd_autostop_size);
            if (cnd_file_duration) {
              cnd_reset(cnd_file_duration);
            }
            wtap_dump_flush(ld.wtap_pdh);
            sync_pipe_filename_to_parent(capture_opts->save_file);
			ld.packets_sync_pipe = 0;
          } else {
            /* File switch failed: stop here */
            ld.go = FALSE;
            continue;
          }
        } else {
          /* single file, stop now */
          ld.go = FALSE;
          continue;
        }
      } /* cnd_autostop_size */
    } /* inpkts */

    /* Only update once a second (Win32: 500ms) so as not to overload slow displays */
    cur_time = TIME_GET();
#ifdef _WIN32
    if ( (cur_time - upd_time) > 500) {
#else
    if (cur_time - upd_time > 0) {
#endif
        upd_time = cur_time;

      /*if (pcap_stats(pch, stats) >= 0) {
        *stats_known = TRUE;
      }*/

      /* calculate and display running time */
      if(capture_opts->show_info) {
          cur_time -= start_time;
#ifdef _WIN32
          capture_ui.running_time   = cur_time / 1000;
#else
          capture_ui.running_time   = cur_time;
#endif
          capture_ui.new_packets    = ld.packets_sync_pipe;
          capture_info_ui_update(&capture_ui);
      }

      /* Let the parent process know. */
      if (ld.packets_sync_pipe) {
        /* do sync here */
        wtap_dump_flush(ld.wtap_pdh);

	  /* Send our parent a message saying we've written out "ld.sync_packets"
	     packets to the capture file. */
        sync_pipe_packet_count_to_parent(ld.packets_sync_pipe);

        ld.packets_sync_pipe = 0;
      }

      /* check capture duration condition */
      if (cnd_autostop_duration != NULL && cnd_eval(cnd_autostop_duration)) {
        /* The maximum capture time has elapsed; stop the capture. */
        ld.go = FALSE;
        continue;
      }
      
      /* check capture file duration condition */
      if (cnd_file_duration != NULL && cnd_eval(cnd_file_duration)) {
        /* duration limit reached, do we have another file? */
        if (capture_opts->multi_files_on) {
          if (cnd_autostop_files != NULL && cnd_eval(cnd_autostop_files, ++autostop_files)) {
            /* no files left: stop here */
            ld.go = FALSE;
            continue;
          }

          /* Switch to the next ringbuffer file */
          if (ringbuf_switch_file(&ld.wtap_pdh, &capture_opts->save_file, &save_file_fd, &ld.err)) {
            /* file switch succeeded: reset the conditions */
            cnd_reset(cnd_file_duration);
            if(cnd_autostop_size)
              cnd_reset(cnd_autostop_size);
            wtap_dump_flush(ld.wtap_pdh);
            sync_pipe_filename_to_parent(capture_opts->save_file);
			ld.packets_sync_pipe = 0;
          } else {
            /* File switch failed: stop here */
	        ld.go = FALSE;
            continue;
          }
        } else {
          /* single file, stop now */
          ld.go = FALSE;
          continue;
        }
      } /* cnd_file_duration */
    }

  } /* while (ld.go) */

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture child stopping ...");

  /* close capture info dialog */
  if(capture_opts->show_info) {
    capture_info_ui_destroy(&capture_ui);
  }

  /* delete stop conditions */
  if (cnd_file_duration != NULL)
    cnd_delete(cnd_file_duration);
  if (cnd_autostop_files != NULL)
    cnd_delete(cnd_autostop_files);
  if (cnd_autostop_size != NULL)
    cnd_delete(cnd_autostop_size);
  if (cnd_autostop_duration != NULL)
    cnd_delete(cnd_autostop_duration);

  /* did we had a pcap (input) error? */
  if (ld.pcap_err) {
    g_snprintf(errmsg, sizeof(errmsg), "Error while capturing packets: %s",
      pcap_geterr(ld.pcap_h));
    sync_pipe_errmsg_to_parent(errmsg);
  }
#ifndef _WIN32
    else if (ld.from_cap_pipe && ld.cap_pipe_err == PIPERR)
      sync_pipe_errmsg_to_parent(errmsg);
#endif

  /* did we had an error while capturing? */
  if (ld.err == 0) {
    write_ok = TRUE;
  } else {
    capture_loop_get_errmsg(errmsg, sizeof(errmsg), capture_opts->save_file, ld.err,
			      FALSE);
    sync_pipe_errmsg_to_parent(errmsg);
    write_ok = FALSE;
  }

  /* close the wiretap (output) file */
  close_ok = capture_loop_close_output(capture_opts, &ld, &err_close);

  /* If we've displayed a message about a write error, there's no point
     in displaying another message about an error on close. */
  if (!close_ok && write_ok) {
    capture_loop_get_errmsg(errmsg, sizeof(errmsg), capture_opts->save_file, err_close,
		TRUE);
    sync_pipe_errmsg_to_parent(errmsg);
  }

  /*
   * XXX We exhibit different behaviour between normal mode and sync mode
   * when the pipe is stdin and not already at EOF.  If we're a child, the
   * parent's stdin isn't closed, so if the user starts another capture,
   * cap_pipe_open_live() will very likely not see the expected magic bytes and
   * will say "Unrecognized libpcap format".  On the other hand, in normal
   * mode, cap_pipe_open_live() will say "End of file on pipe during open".
   */

  /* get packet drop statistics from pcap */
  if(ld.pcap_h != NULL) {
    g_assert(!ld.from_cap_pipe);
    /* Get the capture statistics, so we know how many packets were
       dropped. */
    if (pcap_stats(ld.pcap_h, stats) >= 0) {
      *stats_known = TRUE;
      /* Let the parent process know. */
      sync_pipe_drops_to_parent(stats->ps_drop);
    } else {
      g_snprintf(errmsg, sizeof(errmsg),
		"Can't get packet-drop statistics: %s",
		pcap_geterr(ld.pcap_h));
      sync_pipe_errmsg_to_parent(errmsg);
    }
  }

  /* close the input file (pcap or capture pipe) */
  capture_loop_close_input(&ld);

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture child stopped!");

  /* ok, if the write and the close were successful. */
  return write_ok && close_ok;

error:
  if (capture_opts->multi_files_on) {
    /* cleanup ringbuffer */
    ringbuf_error_cleanup();
  } else {
    /* We can't use the save file, and we have no wtap_dump stream
       to close in order to close it, so close the FD directly. */
    eth_close(save_file_fd);

    /* We couldn't even start the capture, so get rid of the capture
       file. */
    eth_unlink(capture_opts->save_file); /* silently ignore error */
    g_free(capture_opts->save_file);
  }
  capture_opts->save_file = NULL;
  sync_pipe_errmsg_to_parent(errmsg);

  /* close the input file (pcap or cap_pipe) */
  capture_loop_close_input(&ld);

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture child stopped with error");

  return FALSE;
}


void capture_loop_stop(void)
{
    ld.go = FALSE;
}
 

static void
capture_loop_get_errmsg(char *errmsg, int errmsglen, const char *fname,
			  int err, gboolean is_close)
{
  switch (err) {

  case ENOSPC:
    g_snprintf(errmsg, errmsglen,
		"Not all the packets could be written to the file"
		" to which the capture was being saved\n"
		"(\"%s\") because there is no space left on the file system\n"
		"on which that file resides.",
		fname);
    break;

#ifdef EDQUOT
  case EDQUOT:
    g_snprintf(errmsg, errmsglen,
		"Not all the packets could be written to the file"
		" to which the capture was being saved\n"
		"(\"%s\") because you are too close to, or over,"
		" your disk quota\n"
		"on the file system on which that file resides.",
		fname);
  break;
#endif

  case WTAP_ERR_CANT_CLOSE:
    g_snprintf(errmsg, errmsglen,
		"The file to which the capture was being saved"
		" couldn't be closed for some unknown reason.");
    break;

  case WTAP_ERR_SHORT_WRITE:
    g_snprintf(errmsg, errmsglen,
		"Not all the packets could be written to the file"
		" to which the capture was being saved\n"
		"(\"%s\").",
		fname);
    break;

  default:
    if (is_close) {
      g_snprintf(errmsg, errmsglen,
		"The file to which the capture was being saved\n"
		"(\"%s\") could not be closed: %s.",
		fname, wtap_strerror(err));
    } else {
      g_snprintf(errmsg, errmsglen,
		"An error occurred while writing to the file"
		" to which the capture was being saved\n"
		"(\"%s\"): %s.",
		fname, wtap_strerror(err));
    }
    break;
  }
}


/* one packet was captured, process it */
static void
capture_loop_packet_cb(u_char *user, const struct pcap_pkthdr *phdr,
  const u_char *pd)
{
  struct wtap_pkthdr whdr;
  union wtap_pseudo_header pseudo_header;
  loop_data *ld = (loop_data *) user;
  int err;

  /* if the user told us to stop after x packets, do we have enough? */
  ld->packets_curr++;
  if ((ld->packets_max > 0) && (ld->packets_curr >= ld->packets_max))
  {
     ld->go = FALSE;
  }

  /* Convert from libpcap to Wiretap format.
     If that fails, set "ld->go" to FALSE, to stop the capture, and set
     "ld->err" to the error. */
  pd = wtap_process_pcap_packet(ld->wtap_linktype, phdr, pd, &pseudo_header,
				&whdr, &err);
  if (pd == NULL) {
    ld->go = FALSE;
    ld->err = err;
    return;
  }

  if (ld->wtap_pdh) {
    /* We're supposed to write the packet to a file; do so.
       If this fails, set "ld->go" to FALSE, to stop the capture, and set
       "ld->err" to the error. */
    if (!wtap_dump(ld->wtap_pdh, &whdr, &pseudo_header, pd, &err)) {
      ld->go = FALSE;
      ld->err = err;
    }
  }

#ifndef DUMPCAP
  /* if the capture info dialog is hidden, no need to create the packet info */
  if(!ld->show_info) {
      return;
  }

  capture_info_packet(&ld->counts, ld->wtap_linktype, pd, whdr.caplen, pseudo_header);
#endif
}

#endif /* HAVE_LIBPCAP */

