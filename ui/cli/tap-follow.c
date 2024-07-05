/* tap-follow.c
 *
 * Copyright 2011-2013, QA Cafe <info@qacafe.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This module provides udp and tcp follow stream capabilities to tshark.
 * It is only used by tshark and not wireshark.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include <glib.h>
#include <epan/addr_resolv.h>
#include <wsutil/str_util.h>
#include <wsutil/unicode-utils.h>
#include <epan/follow.h>
#include <epan/stat_tap_ui.h>
#include <epan/tap.h>
#include <wsutil/ws_assert.h>

void register_tap_listener_follow(void);

/* Show Type */
typedef enum {
    SHOW_ASCII,
    SHOW_CARRAY,
    SHOW_EBCDIC,
    SHOW_HEXDUMP,
    SHOW_RAW,
    SHOW_CODEC, // Ordered to match UTF-8 combobox index
    SHOW_YAML
} show_type_t;

typedef struct _cli_follow_info {
  show_type_t     show_type;
  register_follow_t* follower;

  /* range */
  uint32_t      chunkMin;
  uint32_t      chunkMax;

  /* filter */
  int           stream_index;
  int           sub_stream_index;
  int           port[2];
  address       addr[2];
  union {
    uint32_t          addrBuf_v4;
    ws_in6_addr addrBuf_v6;
  }             addrBuf[2];
} cli_follow_info_t;


#define STR_FOLLOW      "follow,"

#define STR_HEX         ",hex"
#define STR_ASCII       ",ascii"
#define STR_EBCDIC      ",ebcdic"
#define STR_RAW         ",raw"
#define STR_CODEC       ",utf-8"
#define STR_YAML        ",yaml"

WS_NORETURN static void follow_exit(const char *strp)
{
  fprintf(stderr, "tshark: follow - %s\n", strp);
  exit(1);
}

static const char * follow_str_type(cli_follow_info_t* cli_follow_info)
{
  switch (cli_follow_info->show_type)
  {
  case SHOW_HEXDUMP:    return "hex";
  case SHOW_ASCII:      return "ascii";
  case SHOW_EBCDIC:     return "ebcdic";
  case SHOW_RAW:        return "raw";
  case SHOW_CODEC:      return "utf-8";
  case SHOW_YAML:       return "yaml";
  default:
    ws_assert_not_reached();
    break;
  }

  ws_assert_not_reached();

  return "<unknown-mode>";
}

static void
follow_free(follow_info_t *follow_info)
{
  cli_follow_info_t* cli_follow_info = (cli_follow_info_t*)follow_info->gui_data;

  g_free(cli_follow_info);
  follow_info_free(follow_info);
}

#define BYTES_PER_LINE  16
#define OFFSET_LEN      8
#define OFFSET_SPACE    2
#define HEX_START       (OFFSET_LEN + OFFSET_SPACE)
#define HEX_LEN         (BYTES_PER_LINE * 3)    /* extra space at column 8 */
#define HEX_SPACE       2
#define ASCII_START     (HEX_START + HEX_LEN + HEX_SPACE)
#define ASCII_LEN       (BYTES_PER_LINE + 1)    /* extra space at column 8 */
#define LINE_LEN        (ASCII_START + ASCII_LEN)

static const char       bin2hex[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static void follow_print_hex(const char *prefixp, uint32_t offset, void *datap, int len)
{
  int           ii;
  int           jj;
  int           kk;
  uint8_t       val;
  char          line[LINE_LEN + 1];

  for (ii = 0, jj = 0, kk = 0; ii < len; )
  {
    if ((ii % BYTES_PER_LINE) == 0)
    {
      /* new line */
      snprintf(line, LINE_LEN + 1, "%0*X", OFFSET_LEN, offset);
      memset(line + HEX_START - OFFSET_SPACE, ' ',
             HEX_LEN + OFFSET_SPACE + HEX_SPACE);

      /* offset of hex */
      jj = HEX_START;

      /* offset of ascii */
      kk = ASCII_START;
    }

    val = ((uint8_t *)datap)[ii];

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

static void follow_draw(void *contextp)
{
  static const char     separator[] =
    "===================================================================\n";

  follow_info_t *follow_info = (follow_info_t*)contextp;
  cli_follow_info_t* cli_follow_info = (cli_follow_info_t*)follow_info->gui_data;
  char              buf[WS_INET6_ADDRSTRLEN];
  uint32_t global_client_pos = 0, global_server_pos = 0;
  uint32_t *global_pos;
  uint32_t          ii, jj;
  char              *buffer;
  wmem_strbuf_t     *strbuf;
  GList             *cur;
  follow_record_t   *follow_record;
  unsigned          chunk;
  char              *b64encoded;
  const uint32_t    base64_raw_len = 57; /* Encodes to 76 bytes, common in RFCs */

  /* Print header */
  switch (cli_follow_info->show_type)
  {
    case SHOW_YAML:
      printf("peers:\n");
      printf("  - peer: 0\n");
      address_to_str_buf(&follow_info->client_ip, buf, sizeof buf);
      printf("    host: %s\n", buf);
      printf("    port: %d\n", follow_info->client_port);
      printf("  - peer: 1\n");
      address_to_str_buf(&follow_info->server_ip, buf, sizeof buf);
      printf("    host: %s\n", buf);
      printf("    port: %d\n", follow_info->server_port);
      printf("packets:\n");
      break;

    default:
      printf("\n%s", separator);
      printf("Follow: %s,%s\n", proto_get_protocol_filter_name(get_follow_proto_id(cli_follow_info->follower)), follow_str_type(cli_follow_info));
      printf("Filter: %s\n", follow_info->filter_out_filter);

      address_to_str_buf(&follow_info->client_ip, buf, sizeof buf);
      if (follow_info->client_ip.type == AT_IPv6)
        printf("Node 0: [%s]:%u\n", buf, follow_info->client_port);
      else
        printf("Node 0: %s:%u\n", buf, follow_info->client_port);

      address_to_str_buf(&follow_info->server_ip, buf, sizeof buf);
      if (follow_info->server_ip.type == AT_IPv6)
        printf("Node 1: [%s]:%u\n", buf, follow_info->server_port);
      else
        printf("Node 1: %s:%u\n", buf, follow_info->server_port);
      break;
  }

  for (cur = g_list_last(follow_info->payload), chunk = 1;
       cur != NULL;
       cur = g_list_previous(cur), chunk++)
  {
    follow_record = (follow_record_t *)cur->data;
    if (!follow_record->is_server) {
      global_pos = &global_client_pos;
    } else {
      global_pos = &global_server_pos;
    }

    /* ignore chunks not in range */
    if ((chunk < cli_follow_info->chunkMin) || (chunk > cli_follow_info->chunkMax)) {
      (*global_pos) += follow_record->data->len;
      continue;
    }

    /* Print start of line */
    switch (cli_follow_info->show_type)
    {
    case SHOW_HEXDUMP:
    case SHOW_YAML:
    case SHOW_CODEC: /* The transformation to UTF-8 can change the length */
      break;

    case SHOW_ASCII:
    case SHOW_EBCDIC:
      printf("%s%u\n", follow_record->is_server ? "\t" : "", follow_record->data->len);
      break;

    case SHOW_RAW:
      if (follow_record->is_server)
      {
        putchar('\t');
      }
      break;

    default:
      ws_assert_not_reached();
    }

    /* Print data */
    switch (cli_follow_info->show_type)
    {
    case SHOW_HEXDUMP:
      follow_print_hex(follow_record->is_server ? "\t" : "", *global_pos, follow_record->data->data, follow_record->data->len);
      (*global_pos) += follow_record->data->len;
      break;

    case SHOW_ASCII:
    case SHOW_EBCDIC:
      buffer = (char *)g_malloc(follow_record->data->len+2);

      for (ii = 0; ii < follow_record->data->len; ii++)
      {
        switch (follow_record->data->data[ii])
        {
        // XXX: qt/follow_stream_dialog.c sanitize_buffer() also passes
        // tabs ('\t') through. Should we do that here too?
        // The Qt code has automatic universal new line handling for reading
        // so, e.g., \r\n in HTML becomes just \n, but we don't do that here.
        // (The Qt version doesn't write the file as Text, so all files use
        // Unix line endings, including on Windows.)
        case '\r':
        case '\n':
          buffer[ii] = follow_record->data->data[ii];
          break;
        default:
          buffer[ii] = g_ascii_isprint(follow_record->data->data[ii]) ? follow_record->data->data[ii] : '.';
          break;
        }
      }

      buffer[ii++] = '\n';
      buffer[ii] = 0;
      if (cli_follow_info->show_type == SHOW_EBCDIC) {
        EBCDIC_to_ASCII(buffer, ii);
      }
      printf("%s", buffer);
      g_free(buffer);
      break;

    case SHOW_CODEC:
      // This does the same as the Show As UTF-8 code in the Qt version
      // (passing through all legal UTF-8, including control codes and
      // internal NULs, substituting illegal UTF-8 sequences with
      // REPLACEMENT CHARACTER, and not handling valid UTF-8 sequences
      // which are split between unreassembled frames), except for the
      // end of line terminator issue as above.
      strbuf = ws_utf8_make_valid_strbuf(NULL, follow_record->data->data, follow_record->data->len);
      printf("%s%zu\n", follow_record->is_server ? "\t" : "", wmem_strbuf_get_len(strbuf));
      fwrite(wmem_strbuf_get_str(strbuf), 1, wmem_strbuf_get_len(strbuf), stdout);
      wmem_strbuf_destroy(strbuf);
      putchar('\n');
      break;

    case SHOW_RAW:
      buffer = (char *)g_malloc((follow_record->data->len*2)+2);

      for (ii = 0, jj = 0; ii < follow_record->data->len; ii++)
      {
        buffer[jj++] = bin2hex[follow_record->data->data[ii] >> 4];
        buffer[jj++] = bin2hex[follow_record->data->data[ii] & 0xf];
      }

      buffer[jj++] = '\n';
      buffer[jj] = 0;
      printf("%s", buffer);
      g_free(buffer);
      break;

    case SHOW_YAML:
      printf("  - packet: %d\n", follow_record->packet_num);
      printf("    peer: %d\n", follow_record->is_server ? 1 : 0);
      printf("    timestamp: %.9f\n", nstime_to_sec(&follow_record->abs_ts));
      printf("    data: !!binary |\n");
      ii = 0;
      while (ii < follow_record->data->len) {
          uint32_t len = ii + base64_raw_len < follow_record->data->len
                ? base64_raw_len
                : follow_record->data->len - ii;
          b64encoded = g_base64_encode(&follow_record->data->data[ii], len);
          printf("      %s\n", b64encoded);
          g_free(b64encoded);
          ii += len;
      }
      break;

    default:
      ws_assert_not_reached();
    }
  }

  /* Print footer */
  switch (cli_follow_info->show_type)
  {
    case SHOW_YAML:
      break;

    default:
      printf("%s", separator);
      break;
  }
}

static bool follow_arg_strncmp(const char **opt_argp, const char *strp)
{
  size_t len = strlen(strp);

  if (strncmp(*opt_argp, strp, len) == 0)
  {
    *opt_argp += len;
    return true;
  }
  return false;
}

static void
follow_arg_mode(const char **opt_argp, follow_info_t *follow_info)
{
  cli_follow_info_t* cli_follow_info = (cli_follow_info_t*)follow_info->gui_data;

  if (follow_arg_strncmp(opt_argp, STR_HEX))
  {
    cli_follow_info->show_type = SHOW_HEXDUMP;
  }
  else if (follow_arg_strncmp(opt_argp, STR_ASCII))
  {
    cli_follow_info->show_type = SHOW_ASCII;
  }
  else if (follow_arg_strncmp(opt_argp, STR_EBCDIC))
  {
    cli_follow_info->show_type = SHOW_EBCDIC;
  }
  else if (follow_arg_strncmp(opt_argp, STR_RAW))
  {
    cli_follow_info->show_type = SHOW_RAW;
  }
  else if (follow_arg_strncmp(opt_argp, STR_CODEC))
  {
    cli_follow_info->show_type = SHOW_CODEC;
  }
  else if (follow_arg_strncmp(opt_argp, STR_YAML))
  {
    cli_follow_info->show_type = SHOW_YAML;
  }
  else
  {
    follow_exit("Invalid display mode.");
  }
}

#define _STRING(s)      # s
#define STRING(s)       _STRING(s)

#define ADDR_CHARS      80
#define ADDR_LEN        (ADDR_CHARS + 1)
#define ADDRv6_FMT      ",[%" STRING(ADDR_CHARS) "[^]]]:%d%n"
#define ADDRv4_FMT      ",%" STRING(ADDR_CHARS) "[^:]:%d%n"

static void
follow_arg_filter(const char **opt_argp, follow_info_t *follow_info)
{
  int           len;
  unsigned int  ii;
  char          addr[ADDR_LEN];
  cli_follow_info_t* cli_follow_info = (cli_follow_info_t*)follow_info->gui_data;
  bool is_ipv6;

  if (sscanf(*opt_argp, ",%d%n", &cli_follow_info->stream_index, &len) == 1 &&
      ((*opt_argp)[len] == 0 || (*opt_argp)[len] == ','))
  {
    *opt_argp += len;

    /* if it's HTTP2 or QUIC protocol we should read substream id otherwise it's a range parameter from follow_arg_range */
    if (cli_follow_info->sub_stream_index == -1 && sscanf(*opt_argp, ",%d%n", &cli_follow_info->sub_stream_index, &len) == 1 &&
        ((*opt_argp)[len] == 0 || (*opt_argp)[len] == ','))
    {
      *opt_argp += len;
      follow_info->substream_id = cli_follow_info->sub_stream_index;
    }
  }
  else
  {
    for (ii = 0; ii < array_length(cli_follow_info->addr); ii++)
    {
      if (sscanf(*opt_argp, ADDRv6_FMT, addr, &cli_follow_info->port[ii], &len) == 2)
      {
        is_ipv6 = true;
      }
      else if (sscanf(*opt_argp, ADDRv4_FMT, addr, &cli_follow_info->port[ii], &len) == 2)
      {
        is_ipv6 = false;
      }
      else
      {
        follow_exit("Invalid address.");
      }

      if (cli_follow_info->port[ii] <= 0 || cli_follow_info->port[ii] > UINT16_MAX)
      {
        follow_exit("Invalid port.");
      }

      if (is_ipv6)
      {
        if (!get_host_ipaddr6(addr, &cli_follow_info->addrBuf[ii].addrBuf_v6))
        {
          follow_exit("Can't get IPv6 address");
        }
        set_address(&cli_follow_info->addr[ii], AT_IPv6, 16, (void *)&cli_follow_info->addrBuf[ii].addrBuf_v6);
      }
      else
      {
        if (!get_host_ipaddr(addr, &cli_follow_info->addrBuf[ii].addrBuf_v4))
        {
          follow_exit("Can't get IPv4 address");
        }
        set_address(&cli_follow_info->addr[ii], AT_IPv4, 4, (void *)&cli_follow_info->addrBuf[ii].addrBuf_v4);
      }

      *opt_argp += len;
    }

    if (cli_follow_info->addr[0].type != cli_follow_info->addr[1].type)
    {
      follow_exit("Mismatched IP address types.");
    }
    cli_follow_info->stream_index = -1;
  }
}

static void follow_arg_range(const char **opt_argp, cli_follow_info_t* cli_follow_info)
{
  int           len;

  if (**opt_argp == 0)
  {
    cli_follow_info->chunkMin = 1;
    cli_follow_info->chunkMax = UINT32_MAX;
  }
  else
  {
    if (sscanf(*opt_argp, ",%u-%u%n",  &cli_follow_info->chunkMin, &cli_follow_info->chunkMax, &len) == 2)
    {
      *opt_argp += len;
    }
    else if (sscanf(*opt_argp, ",%u%n", &cli_follow_info->chunkMin, &len) == 1)
    {
      cli_follow_info->chunkMax = cli_follow_info->chunkMin;
      *opt_argp += len;
    }
    else
    {
      follow_exit("Invalid range.");
    }

    if (cli_follow_info->chunkMin < 1 || cli_follow_info->chunkMin > cli_follow_info->chunkMax)
    {
      follow_exit("Invalid range value.");
    }
  }
}

static void
follow_arg_done(const char *opt_argp)
{
  if (*opt_argp != 0)
  {
    follow_exit("Invalid parameter.");
  }
}

static void follow_stream(const char *opt_argp, void *userdata)
{
  follow_info_t *follow_info;
  cli_follow_info_t* cli_follow_info;
  GString  *errp;
  register_follow_t* follower = (register_follow_t*)userdata;
  follow_index_filter_func index_filter;
  follow_address_filter_func address_filter;
  int proto_id = get_follow_proto_id(follower);
  const char* proto_filter_name = proto_get_protocol_filter_name(proto_id);

  opt_argp += strlen(STR_FOLLOW);
  opt_argp += strlen(proto_filter_name);

  cli_follow_info = g_new0(cli_follow_info_t, 1);
  cli_follow_info->stream_index = -1;
  /* use second parameter only for followers that have sub streams
   * (currently HTTP2 or QUIC) */
  if (get_follow_sub_stream_id_func(follower)) {
      cli_follow_info->sub_stream_index = -1;
  } else {
      cli_follow_info->sub_stream_index = 0;
  }
  follow_info = g_new0(follow_info_t, 1);
  follow_info->gui_data = cli_follow_info;
  follow_info->substream_id = SUBSTREAM_UNUSED;
  cli_follow_info->follower = follower;

  follow_arg_mode(&opt_argp, follow_info);
  follow_arg_filter(&opt_argp, follow_info);
  follow_arg_range(&opt_argp, cli_follow_info);
  follow_arg_done(opt_argp);

  if (cli_follow_info->stream_index >= 0)
  {
    index_filter = get_follow_index_func(follower);
    follow_info->filter_out_filter = index_filter(cli_follow_info->stream_index, cli_follow_info->sub_stream_index);
    if (follow_info->filter_out_filter == NULL || cli_follow_info->sub_stream_index < 0)
    {
      follow_exit("Error creating filter for this stream.");
    }
  }
  else
  {
    address_filter = get_follow_address_func(follower);
    follow_info->filter_out_filter = address_filter(&cli_follow_info->addr[0], &cli_follow_info->addr[1], cli_follow_info->port[0], cli_follow_info->port[1]);
    if (follow_info->filter_out_filter == NULL)
    {
      follow_exit("Error creating filter for this address/port pair.\n");
    }
  }

  errp = register_tap_listener(get_follow_tap_string(follower), follow_info, follow_info->filter_out_filter, 0,
                               NULL, get_follow_tap_handler(follower), follow_draw, (tap_finish_cb)follow_free);

  if (errp != NULL)
  {
    follow_free(follow_info);
    g_string_free(errp, TRUE);
    follow_exit("Error registering tap listener.");
  }
}

static bool
follow_register(const void *key _U_, void *value, void *userdata _U_)
{
  register_follow_t *follower = (register_follow_t*)value;
  stat_tap_ui follow_ui;
  char *cli_string;

  cli_string = follow_get_stat_tap_string(follower);
  follow_ui.group = REGISTER_STAT_GROUP_GENERIC;
  follow_ui.title = NULL;   /* construct this from the protocol info? */
  follow_ui.cli_string = cli_string;
  follow_ui.tap_init_cb = follow_stream;
  follow_ui.nparams = 0;
  follow_ui.params = NULL;
  register_stat_tap_ui(&follow_ui, follower);
  g_free(cli_string);
  return false;
}

void
register_tap_listener_follow(void)
{
  follow_iterate_followers(follow_register, NULL);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
