/* tap-follow.c
 *
 * Copyright 2011, QA Cafe <info@qacafe.com>
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

/* This module provides udp and tcp follow stream capabilities to tshark.
 * It is only used by tshark and not wireshark.
 */

#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ctype.h>
#include <stdio.h>

#include <glib.h>
#include <epan/addr_resolv.h>
#include <epan/epan_dissect.h>
#include <epan/follow.h>
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/tvbuff-int.h>

#include "wsutil/file_util.h"
#include "tempfile.h"

WS_VAR_IMPORT FILE *data_out_file;

typedef enum
{
  type_TCP,
  type_UDP
} type_e;

typedef enum
{
  mode_HEX,
  mode_ASCII,
  mode_RAW
} mode_e;

typedef struct
{
  type_e        type;
  mode_e        mode;

  /* filter */
  guint32       index;
  address       addr[2];
  int           port[2];
  guint8        addrBuf[2][16];

  /* range */
  guint32       chunkMin;
  guint32       chunkMax;

  /* stream chunk file */
  FILE *        filep;
  gchar *       filenamep;
} follow_t;

#define STR_FOLLOW      "follow,"
#define STR_FOLLOW_TCP  STR_FOLLOW "tcp"
#define STR_FOLLOW_UDP  STR_FOLLOW "udp"

#define STR_HEX         ",hex"
#define STR_ASCII       ",ascii"
#define STR_RAW         ",raw"

static void
followExit(
  const char *  strp
  )
{
  fprintf(stderr, "tshark: follow - %s\n", strp);
  exit(1);
}

static const char *
followStrType(
  const follow_t *      fp
  )
{
  switch (fp->type)
  {
  case type_TCP:        return "tcp";
  case type_UDP:        return "udp";
  }

  g_assert_not_reached();

  return "<unknown-type>";
}

static const char *
followStrMode(
  const follow_t *      fp
  )
{
  switch (fp->mode)
  {
  case mode_HEX:        return "hex";
  case mode_ASCII:      return "ascii";
  case mode_RAW:        return "raw";
  }

  g_assert_not_reached();

  return "<unknown-mode>";
}

static const char *
followStrFilter(
  const follow_t *      fp
  )
{
  static char   filter[512];
  int           len     = 0;
  const gchar * verp;
  gchar         ip0[MAX_IP6_STR_LEN];
  gchar         ip1[MAX_IP6_STR_LEN];

  if (fp->index != G_MAXUINT32)
  {
    switch (fp->type)
    {
    case type_TCP:
      len = g_snprintf(filter, sizeof filter,
                     "tcp.stream eq %d", fp->index);
      break;
    case type_UDP:
      break;
    }
  }
  else
  {
    verp = fp->addr[0].type == AT_IPv6 ? "v6" : "";
    address_to_str_buf(&fp->addr[0], ip0, sizeof ip0);
    address_to_str_buf(&fp->addr[1], ip1, sizeof ip1);

    switch (fp->type)
    {
    case type_TCP:
      len = g_snprintf(filter, sizeof filter,
                     "((ip%s.src eq %s and tcp.srcport eq %d) and "
                     "(ip%s.dst eq %s and tcp.dstport eq %d))"
                     " or "
                     "((ip%s.src eq %s and tcp.srcport eq %d) and "
                     "(ip%s.dst eq %s and tcp.dstport eq %d))",
                     verp, ip0, fp->port[0],
                     verp, ip1, fp->port[1],
                     verp, ip1, fp->port[1],
                     verp, ip0, fp->port[0]);
      break;
    case type_UDP:
      len = g_snprintf(filter, sizeof filter,
                     "((ip%s.src eq %s and udp.srcport eq %d) and "
                     "(ip%s.dst eq %s and udp.dstport eq %d))"
                     " or "
                     "((ip%s.src eq %s and udp.srcport eq %d) and "
                     "(ip%s.dst eq %s and udp.dstport eq %d))",
                     verp, ip0, fp->port[0],
                     verp, ip1, fp->port[1],
                     verp, ip1, fp->port[1],
                     verp, ip0, fp->port[0]);
      break;
    }
  }

  if (len == 0)
  {
    followExit("Don't know how to create filter.");
  }

  if (len == sizeof filter)
  {
    followExit("Filter buffer overflow.");
  }

  return filter;
}

static void
followFileClose(
  follow_t *    fp
  )
{
  if (fp->filep != NULL)
  {
    fclose(fp->filep);
    fp->filep = NULL;
    if (fp->type == type_TCP)
    {
      data_out_file = NULL;
    }
  }

  if (fp->filenamep != NULL)
  {
    ws_unlink(fp->filenamep);
    g_free(fp->filenamep);
    fp->filenamep = NULL;
  }
}

static void
followFileOpen(
  follow_t *    fp
  )
{
  int           fd;
  char *        tempfilep;

  if (fp->type == type_TCP && data_out_file != NULL)
  {
    followExit("Only one TCP stream can be followed at a time.");
  }

  followFileClose(fp);

  fd = create_tempfile(&tempfilep, "follow");
  if (fd == -1)
  {
    followExit("Error creating temp file.");
  }

  fp->filenamep = g_strdup(tempfilep);
  if (fp->filenamep == NULL)
  {
    ws_close(fd);
    ws_unlink(tempfilep);
    followExit("Error duping temp file name.");
  }

  fp->filep = fdopen(fd, "w+b");
  if (fp->filep == NULL)
  {
    ws_close(fd);
    ws_unlink(fp->filenamep);
    g_free(fp->filenamep);
    fp->filenamep = NULL;
    followExit("Error opening temp file stream.");
  }

  if (fp->type == type_TCP)
  {
    data_out_file = fp->filep;
  }
}

static follow_t *
followAlloc(
  type_e        type
  )
{
  follow_t *    fp;

  fp = g_malloc0(sizeof *fp);

  fp->type = type;
  SET_ADDRESS(&fp->addr[0], AT_NONE, 0, fp->addrBuf[0]);
  SET_ADDRESS(&fp->addr[1], AT_NONE, 0, fp->addrBuf[1]);

  return fp;
}

static void
followFree(
  follow_t *    fp
  )
{
  followFileClose(fp);
  g_free(fp);
}

static int
followPacket(
  void *                contextp,
  packet_info *         pip,
  epan_dissect_t *      edp _U_,
  const void *          datap
  )
{
  follow_t *            fp      = contextp;
  const tvbuff_t *      tvbp    = datap;
  tcp_stream_chunk      sc;
  size_t                size;

  if (tvbp->length > 0)
  {
    memcpy(sc.src_addr, pip->net_src.data, pip->net_src.len);
    sc.src_port = pip->srcport;
    sc.dlen     = tvbp->length;

    size = fwrite(&sc, 1, sizeof sc, fp->filep);
    if (sizeof sc != size)
    {
      followExit("Error writing stream chunk header.");
    }

    size = fwrite(tvbp->real_data, 1, sc.dlen, fp->filep);
    if (sc.dlen != size)
    {
      followExit("Error writing stream chunk data.");
    }
  }

  return 0;
}

#define BYTES_PER_LINE  16
#define OFFSET_START    0
#define OFFSET_LEN      8
#define OFFSET_SPACE    2
#define HEX_START       (OFFSET_START + OFFSET_LEN + OFFSET_SPACE)
#define HEX_LEN         (BYTES_PER_LINE * 3)    /* extra space at column 8 */
#define HEX_SPACE       2
#define ASCII_START     (HEX_START + HEX_LEN + HEX_SPACE)
#define ASCII_LEN       (BYTES_PER_LINE + 1)    /* extra space at column 8 */
#define ASCII_SPACE     0
#define LINE_LEN        (ASCII_START + ASCII_LEN + ASCII_SPACE)

static const char       bin2hex[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
static void
followPrintHex(
  const char *  prefixp,
  guint32       offset,
  void *        datap,
  int           len
  )
{
  int           ii;
  int           jj;
  int           kk;
  guint8        val;
  char          line[LINE_LEN + 1];

  for (ii = 0, jj = 0, kk = 0; ii < len; )
  {
    if ((ii % BYTES_PER_LINE) == 0)
    {
      /* new line */
      g_snprintf(line, LINE_LEN + 1, "%0*X", OFFSET_LEN, offset);
      memset(line + HEX_START - OFFSET_SPACE, ' ',
             HEX_LEN + OFFSET_SPACE + HEX_SPACE);

      /* offset of hex */
      jj = HEX_START;

      /* offset of ascii */
      kk = ASCII_START;
    }

    val = ((guint8 *)datap)[ii];

    line[jj++] = bin2hex[val >> 4];
    line[jj++] = bin2hex[val & 0xf];
    jj++;

    line[kk++] = val >= ' ' && val < 0x7f ? val : '.';

    /* extra space at column 8 */
    if (++ii % BYTES_PER_LINE == BYTES_PER_LINE/2)
    {
      line[jj++] = ' ';
      line[kk++] = ' ';
    }

    if ((ii % BYTES_PER_LINE) == 0 || ii == len)
    {
      /* end of line or buffer */
      if (line[kk - 1] == ' ')
      {
        kk--;
      }
      line[kk] = 0;
      printf("%s%s\n", prefixp, line);
      offset += BYTES_PER_LINE;
    }
  }
}

static void
followDraw(
  void *        contextp
  )
{
  static const char     seperator[] =
    "===================================================================\n";

  follow_t *            fp      = contextp;
  tcp_stream_chunk      sc;
  int                   node;
  const address *       addr[2];
  int                   port[2];
  gchar                 buf[MAX_IP6_STR_LEN];
  guint32               ii;
  guint32               jj;
  guint32               len;
  guint32               chunk;
  guint32               offset[2];
  guint8                bin[4096];
  char                  data[(sizeof bin * 2) + 2];

  g_assert(sizeof bin % BYTES_PER_LINE == 0);

  if (fp->type == type_TCP)
  {
    follow_stats_t      stats;
    address_type        type;

    follow_stats(&stats);

    if (stats.is_ipv6)
    {
      type = AT_IPv6;
      len  = 16;
    }
    else
    {
      type = AT_IPv4;
      len  = 4;
    }

    for (node = 0; node < 2; node++)
    {
      memcpy(fp->addrBuf[node], stats.ip_address[node], len);
      SET_ADDRESS(&fp->addr[node], type, len, fp->addrBuf[node]);
      fp->port[node] = stats.port[node];
    }
  }

  /* find first stream chunk */
  rewind(fp->filep);
  for (chunk = 0;;)
  {
    len = (guint32)fread(&sc, 1, sizeof sc, fp->filep);
    if (len != sizeof sc)
    {
      /* no data */
      sc.dlen = 0;
      memcpy(sc.src_addr, fp->addr[0].data, fp->addr[0].len) ;
      sc.src_port = fp->port[0];
      break;
    }
    if (sc.dlen > 0)
    {
      chunk++;
      break;
    }
  }

  /* node 0 is source of first chunk with data */
  if (memcmp(sc.src_addr, fp->addr[0].data, fp->addr[0].len) == 0 &&
      sc.src_port == fp->port[0])
  {
    addr[0] = &fp->addr[0];
    port[0] = fp->port[0];
    addr[1] = &fp->addr[1];
    port[1] = fp->port[1];
  }
  else
  {
    addr[0] = &fp->addr[1];
    port[0] = fp->port[1];
    addr[1] = &fp->addr[0];
    port[1] = fp->port[0];
  }

  printf("\n%s", seperator);
  printf("Follow: %s,%s\n", followStrType(fp), followStrMode(fp));
  printf("Filter: %s\n", followStrFilter(fp));

  for (node = 0; node < 2; node++)
  {
    address_to_str_buf(addr[node], buf, sizeof buf);
    if (addr[node]->type == AT_IPv6)
    {
      printf("Node %u: [%s]:%d\n", node, buf, port[node]);
    }
    else
    {
      printf("Node %u: %s:%d\n", node, buf, port[node]);
    }
  }

  offset[0] = offset[1] = 0;

  while (chunk <= fp->chunkMax)
  {
    node = (memcmp(addr[0]->data, sc.src_addr, addr[0]->len) == 0 &&
            port[0] == sc.src_port) ? 0 : 1;

    if (chunk < fp->chunkMin)
    {
      while (sc.dlen > 0)
      {
        len = sc.dlen < sizeof bin ? sc.dlen : sizeof bin;
        sc.dlen -= len;
        if (fread(bin, 1, len, fp->filep) != len)
        {
          followExit("Error reading stream chunk data.");
        }
        offset[node] += len;
      }
    }
    else
    {
      switch (fp->mode)
      {
      case mode_HEX:
        break;

      case mode_ASCII:
        printf("%s%d\n", node ? "\t" : "", sc.dlen);
        break;

      case mode_RAW:
        if (node)
        {
          putchar('\t');
        }
        break;
      }

      while (sc.dlen > 0)
      {
        len = sc.dlen < sizeof bin ? sc.dlen : sizeof bin;
        sc.dlen -= len;
        if (fread(bin, 1, len, fp->filep) != len)
        {
          followExit("Error reading stream chunk data.");
        }

        switch (fp->mode)
        {
        case mode_HEX:
          followPrintHex(node ? "\t" : "", offset[node], bin, len);
          break;

        case mode_ASCII:
          for (ii = 0; ii < len; ii++)
          {
            switch (bin[ii])
            {
            case '\r':
            case '\n':
              data[ii] = bin[ii];
            break;
            default:
              data[ii] = isprint(bin[ii]) ? bin[ii] : '.';
              break;
            }
          }
          if (sc.dlen == 0)
          {
            data[ii++] = '\n';
          }
          data[ii] = 0;
          printf("%s", data);
          break;

        case mode_RAW:
          for (ii = 0, jj = 0; ii < len; ii++)
          {
            data[jj++] = bin2hex[bin[ii] >> 4];
            data[jj++] = bin2hex[bin[ii] & 0xf];
          }
          if (sc.dlen == 0)
          {
            data[jj++] = '\n';
          }
          data[jj] = 0;
          printf("%s", data);
        }

        offset[node] += len;
      }
    }

    for (;;)
    {
      len = (guint32)fread(&sc, 1, sizeof sc, fp->filep);
      if (len != sizeof sc)
      {
        /* no more data */
        sc.dlen = 0;
        chunk = G_MAXUINT32;
        goto done;
      }
      if (sc.dlen > 0)
      {
        chunk++;
        break;
      }
    }
  }

done:

  printf("%s", seperator);

  followFileClose(fp);
}

static gboolean
followArgStrncmp(
  const char ** optargp,
  const char *  strp
  )
{
  int           len     = (guint32)strlen(strp);

  if (strncmp(*optargp, strp, len) == 0)
  {
    *optargp += len;
    return TRUE;
  }
  return FALSE;
}

static void
followArgMode(
  const char ** optargp,
  follow_t *    fp
  )
{
  if (followArgStrncmp(optargp, STR_HEX))
  {
    fp->mode = mode_HEX;
  }
  else if (followArgStrncmp(optargp, STR_ASCII))
  {
    fp->mode = mode_ASCII;
  }
  else if (followArgStrncmp(optargp, STR_RAW))
  {
    fp->mode = mode_RAW;
  }
  else
  {
    followExit("Invalid display mode.");
  }
}

static void
followArgFilter(
  const char ** optargp,
  follow_t *    fp
  )
{
#define _STRING(s)      # s
#define STRING(s)       _STRING(s)

#define ADDR_CHARS      80
#define ADDR_LEN        (ADDR_CHARS + 1)
#define ADDRv6_FMT      ",[%" STRING(ADDR_CHARS) "[^]]]:%d%n"
#define ADDRv4_FMT      ",%" STRING(ADDR_CHARS) "[^:]:%d%n"

  int           len;
  unsigned int  ii;
  char          addr[ADDR_LEN];

  if (sscanf(*optargp, ",%u%n", &fp->index, &len) == 1 &&
      ((*optargp)[len] == 0 || (*optargp)[len] == ','))
  {
    *optargp += len;
  }
  else
  {
    for (ii = 0; ii < sizeof fp->addr/sizeof *fp->addr; ii++)
    {
      if ((sscanf(*optargp, ADDRv6_FMT, addr, &fp->port[ii], &len) != 2 &&
           sscanf(*optargp, ADDRv4_FMT, addr, &fp->port[ii], &len) != 2) ||
          fp->port[ii] <= 0 || fp->port[ii] > G_MAXUINT16)
      {
        followExit("Invalid address:port pair.");
      }

      if (strcmp("ip6", host_ip_af(addr)) == 0)
      {
        if (!get_host_ipaddr6(addr, (struct e_in6_addr *)fp->addrBuf[ii]))
        {
          followExit("Can't get IPv6 address");
        }
        SET_ADDRESS(&fp->addr[ii], AT_IPv6, 16, fp->addrBuf[ii]);
      }
      else
      {
        if (!get_host_ipaddr(addr, (guint32 *)fp->addrBuf[ii]))
        {
          followExit("Can't get IPv4 address");
        }
        SET_ADDRESS(&fp->addr[ii], AT_IPv4, 4, fp->addrBuf[ii]);
      }

      *optargp += len;
    }

    if (fp->addr[0].type != fp->addr[1].type)
    {
      followExit("Mismatched IP address types.");
    }
    fp->index = G_MAXUINT32;
  }
}

static void
followArgRange(
  const char ** optargp,
  follow_t *    fp
  )
{
  int           len;

  if (**optargp == 0)
  {
    fp->chunkMin = 1;
    fp->chunkMax = G_MAXUINT32;
  }
  else
  {
    if (sscanf(*optargp, ",%u-%u%n",  &fp->chunkMin, &fp->chunkMax, &len) == 2)
    {
      *optargp += len;
    }
    else if (sscanf(*optargp, ",%u%n", &fp->chunkMin, &len) == 1)
    {
      fp->chunkMax = fp->chunkMin;
      *optargp += len;
    }
    else
    {
      followExit("Invalid range.");
    }

    if (fp->chunkMin < 1 || fp->chunkMin > fp->chunkMax)
    {
      followExit("Invalid range value.");
    }
  }
}

static void
followArgDone(
  const char * optargp
  )
{
  if (*optargp != 0)
  {
    followExit("Invalid parameter.");
  }
}

static void
followTcp(
  const char *  optargp,
  void *        userdata _U_
  )
{
  follow_t *    fp;
  GString *     errp;

  optargp += strlen(STR_FOLLOW_TCP);

  fp = followAlloc(type_TCP);

  followArgMode(&optargp, fp);
  followArgFilter(&optargp, fp);
  followArgRange(&optargp, fp);
  followArgDone(optargp);

  reset_tcp_reassembly();
  if (fp->index != G_MAXUINT32)
  {
    if (!follow_tcp_index(fp->index))
    {
      followExit("Can't follow tcp index.");
    }
  }
  else
  {
    if (!follow_tcp_addr(&fp->addr[0], fp->port[0],
                         &fp->addr[1], fp->port[1]))
    {
      followExit("Can't follow tcp address/port pairs.");
    }
  }

  followFileOpen(fp);

  errp = register_tap_listener("frame", fp, NULL, 0,
                               NULL, NULL, followDraw);
  if (errp != NULL)
  {
    followFree(fp);
    g_string_free(errp, TRUE);
    followExit("Error registering tcp tap listner.");
  }
}

static void
followUdp(
  const char *  optargp,
  void *        userdata _U_
  )
{
  follow_t *    fp;
  GString *     errp;

  optargp += strlen(STR_FOLLOW_UDP);

  fp = followAlloc(type_UDP);

  followArgMode(&optargp, fp);
  followArgFilter(&optargp, fp);
  followArgRange(&optargp, fp);
  followArgDone(optargp);

  if (fp->index != G_MAXUINT32)
  {
    followExit("UDP does not support index filters.");
  }

  followFileOpen(fp);

  errp = register_tap_listener("udp_follow", fp, followStrFilter(fp), 0,
                               NULL, followPacket, followDraw);
  if (errp != NULL)
  {
    followFree(fp);
    g_string_free(errp, TRUE);
    followExit("Error registering udp tap listner.");
  }
}

void
register_tap_listener_follow(void)
{
  register_stat_cmd_arg(STR_FOLLOW_TCP, followTcp, NULL);
  register_stat_cmd_arg(STR_FOLLOW_UDP, followUdp, NULL);
}
