/* packet-imap.c
 * Routines for imap packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/strutil.h>
#include <wsutil/strtoi.h>
#include "packet-tls.h"
#include "packet-tls-utils.h"
#include <ui/tap-credentials.h>
#include <tap.h>

void proto_register_imap(void);
void proto_reg_handoff_imap(void);

static int proto_imap;
static int hf_imap_isrequest;
static int hf_imap_line;
static int hf_imap_request;
static int hf_imap_request_tag;
static int hf_imap_response;
static int hf_imap_response_tag;
static int hf_imap_request_command;
static int hf_imap_response_command;
static int hf_imap_tag;
static int hf_imap_command;
static int hf_imap_response_status;
static int hf_imap_request_folder;
static int hf_imap_request_username;
static int hf_imap_request_password;
static int hf_imap_request_uid;
static int hf_imap_response_in;
static int hf_imap_response_to;
static int hf_imap_time;

static int ett_imap;
static int ett_imap_reqresp;

static int credentials_tap;

static dissector_handle_t imap_handle;
static dissector_handle_t tls_handle;
static dissector_handle_t imf_handle;

static bool imap_ssl_heuristic = true;

/* patterns used for tvb_ws_mempbrk_pattern_guint8 */
static ws_mempbrk_pattern pbrk_whitespace;

#define TCP_PORT_IMAP     143
#define TCP_PORT_SSL_IMAP 993
#define IMAP_HEUR_LEN     5
#define NUM_LOOKAHEAD_TOKENS  3

struct simple_token_info
{
  uint8_t* token;
  int token_start_offset;
  int token_end_offset;
};

typedef struct imap_state {
  bool      ssl_requested;
  int       ssl_heur_tries_left;
} imap_state_t;

typedef struct imap_request_key {
  char* tag;
  uint32_t conversation;
} imap_request_key_t;

typedef struct imap_request_val {
  wmem_tree_t *frames;
} imap_request_val_t;

typedef struct {
  uint32_t req_num;
  uint32_t rep_num;
  nstime_t req_time;
} imap_request_info_t;

static wmem_map_t *imap_requests;

static int
imap_request_equal(const void *v, const void *w)
{
  const imap_request_key_t *v1 = (const imap_request_key_t*)v;
  const imap_request_key_t *v2 = (const imap_request_key_t*)w;

  if ((v1->conversation == v2->conversation) &&
      (!strcmp(v1->tag, v2->tag)))
    return 1;

  return 0;
}

static unsigned
imap_request_hash(const void *v)
{
  const imap_request_key_t *key = (const imap_request_key_t*)v;
  unsigned val;

  val = (unsigned)(wmem_str_hash(key->tag) * 37 + key->conversation * 765);

  return val;
}

static void
imap_match_request(packet_info *pinfo, proto_tree *tree, imap_request_key_t *request_key, bool is_request)
{
  imap_request_key_t  *new_request_key;
  imap_request_val_t  *request_val;
  imap_request_info_t *request_info = NULL;

  request_info = NULL;
  request_val = (imap_request_val_t *)wmem_map_lookup(imap_requests, request_key);
  if (!pinfo->fd->visited)
  {
    if (is_request)
    {
      if (request_val == NULL)
      {
        new_request_key = (imap_request_key_t *)wmem_memdup(wmem_file_scope(), request_key, sizeof(imap_request_key_t));
        new_request_key->tag = wmem_strdup(wmem_file_scope(), request_key->tag);

        request_val = wmem_new(wmem_file_scope(), imap_request_val_t);
        request_val->frames = wmem_tree_new(wmem_file_scope());

        wmem_map_insert(imap_requests, new_request_key, request_val);
      }

      request_info = wmem_new(wmem_file_scope(), imap_request_info_t);
      request_info->req_num = pinfo->num;
      request_info->rep_num = 0;
      request_info->req_time = pinfo->abs_ts;
      wmem_tree_insert32(request_val->frames, pinfo->num, (void *)request_info);
    }
    if (request_val && !is_request)
    {
      request_info = (imap_request_info_t*)wmem_tree_lookup32_le(request_val->frames, pinfo->num);
      if (request_info)
      {
        request_info->rep_num = pinfo->num;
      }
    }
  }
  else
  {
    if (request_val)
      request_info = (imap_request_info_t *)wmem_tree_lookup32_le(request_val->frames, pinfo->num);
  }

  if (tree && request_info)
  {
    proto_item *it;

    /* print request/response tracking in the tree */
    if (is_request)
    {
      /* This is a request */
      if (request_info->rep_num)
      {

        it = proto_tree_add_uint(tree, hf_imap_response_in, NULL, 0, 0, request_info->rep_num);
        proto_item_set_generated(it);
      }
    }
    else
    {
      /* This is a reply */
      if (request_info->req_num)
      {
        nstime_t    ns;

        it = proto_tree_add_uint(tree, hf_imap_response_to, NULL, 0, 0, request_info->req_num);
        proto_item_set_generated(it);

        nstime_delta(&ns, &pinfo->abs_ts, &request_info->req_time);
        it = proto_tree_add_time(tree, hf_imap_time, NULL, 0, 0, &ns);
        proto_item_set_generated(it);
      }
    }
  }

}

static bool
dissect_imap_fetch(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree* main_tree, proto_tree* imap_tree, proto_tree** reqresp_tree,
                            int fetch_offset, int offset, int* next_offset, bool* first_line)
{
  tvbuff_t       *next_tvb;
  bool need_more = true;

  //All information in encapsulated in () so make sure there are existing and matching parenthesis
  int first_parenthesis = tvb_find_guint8(tvb, fetch_offset, -1, '(');
  if (first_parenthesis >= 0)
  {
    int remaining_size = tvb_reported_length_remaining(tvb, first_parenthesis + 1);
    if (remaining_size > 0)
    {
      //look for the size field
      int size_start = tvb_find_guint8(tvb, first_parenthesis, remaining_size, '{');
      if (size_start >= 0)
      {
        int size_end = tvb_find_guint8(tvb, size_start + 1, remaining_size - (size_start - first_parenthesis), '}');
        if (size_end > 0)
        {
          //Have a size field, convert it to an integer to see how long the contents are
          uint32_t size = 0;
          const char* size_str = (const char *)tvb_get_string_enc(pinfo->pool, tvb, size_start + 1, size_end - size_start - 1, ENC_ASCII);
          if (ws_strtou32(size_str, NULL, &size))
          {
            int remaining = tvb_reported_length_remaining(tvb, size_end + size);
            if (remaining > 0)
            {
              //Look for the ) after the size field
              int parenthesis_end = tvb_find_guint8(tvb, size_end + size, remaining, ')');
              if (parenthesis_end >= 0)
              {
                need_more = false;

                // Put the line into the protocol tree.
                proto_item *ti = proto_tree_add_item(imap_tree, hf_imap_line, tvb, offset, *next_offset - offset, ENC_ASCII | ENC_NA);
                *reqresp_tree = proto_item_add_subtree(ti, ett_imap_reqresp);

                //no need to overwrite column information since subdissector was called
                *first_line = false;

                next_tvb = tvb_new_subset_length(tvb, *next_offset, size);
                call_dissector(imf_handle, next_tvb, pinfo, main_tree);
                if ((int)(*next_offset + size) > *next_offset)
                  (*next_offset) += size;
              }
            }
          }
        }
      }
      else
      {
        //See if there is no size field, just and end of line
        int linelen = tvb_find_line_end(tvb, first_parenthesis, -1, next_offset, true);
        if (linelen >= 0)
        {
          need_more = false;

          // Put the line into the protocol tree.
          proto_item *ti = proto_tree_add_item(imap_tree, hf_imap_line, tvb, offset, *next_offset - offset, ENC_ASCII | ENC_NA);
          *reqresp_tree = proto_item_add_subtree(ti, ett_imap_reqresp);
        }
      }
    }
  }

  return need_more;
}

/* Heuristic to detect plaintext or TLS ciphertext IMAP */
static bool
check_imap_heur(tvbuff_t *tvb)
{
  if (!tvb_bytes_exist(tvb, 0, IMAP_HEUR_LEN)) {
    return true;
  }

  if (!tvb_ascii_isprint(tvb, 0, IMAP_HEUR_LEN))
    return false;

  return true;
}

static int
dissect_imap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  bool            is_request;
  proto_tree      *imap_tree, *reqresp_tree;
  proto_item      *ti, *hidden_item;
  int             offset = 0;
  int             uid_offset = 0;
  int             folder_offset = 0;
  int             next_offset;
  int             linelen, tokenlen, uidlen, uid_tokenlen, folderlen, folder_tokenlen;
  int             next_token, uid_next_token, folder_next_token;
  const char     *tokenbuf = NULL;
  const char     *command_token;
  int             commandlen;
  bool            first_line = true;
  imap_request_key_t request_key;

  conversation_t *conversation;
  imap_state_t   *session_state;

  conversation = find_or_create_conversation(pinfo);
  session_state = (imap_state_t *)conversation_get_proto_data(conversation, proto_imap);
  if (!session_state) {
    session_state = wmem_new0(wmem_file_scope(), imap_state_t);
    session_state->ssl_requested = false;
    if (imap_ssl_heuristic)
      session_state->ssl_heur_tries_left = 2;
    else
      session_state->ssl_heur_tries_left = -1; /* Disabled */
    conversation_add_proto_data(conversation, proto_imap, session_state);
  }

  request_key.tag = NULL;
  request_key.conversation = conversation->conv_index;

  if (imap_ssl_heuristic && session_state->ssl_heur_tries_left < 0) {
    /* Preference changed to enabled */
    session_state->ssl_heur_tries_left = 2;
  }
  else if (!imap_ssl_heuristic && session_state->ssl_heur_tries_left >= 0) {
    /* Preference changed to disabled */
    session_state->ssl_heur_tries_left = -1;
  }

  /*
   * It is possible the IMAP session is already running over TLS and the
   * STARTTLS request/response happened before the capture began. Don't assume
   * we have plaintext without performing some heuristic checks first.
   * We have three cases:
   *   1. capture includes STARTTLS command: no need for heuristics
   *   2. capture starts with STARTTLS OK response: next frame will be TLS (need to retry heuristic)
   *   3. capture start after STARTTLS negotiation: current frame is TLS
   */
  if (session_state->ssl_heur_tries_left > 0) {
    session_state->ssl_heur_tries_left--;
    if (!check_imap_heur(tvb)) {
      ssl_starttls_post_ack(tls_handle, pinfo, imap_handle);
      session_state->ssl_heur_tries_left = 0;
      return call_dissector(tls_handle, tvb, pinfo, tree);
    }
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IMAP");

  if (pinfo->match_uint == pinfo->destport)
    is_request = true;
  else
    is_request = false;

  /*
   * Put the first line from the buffer into the summary
   * (but leave out the line terminator).
   */
  linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, true);
  if (linelen == -1)
  {
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    return tvb_captured_length(tvb);
  }

  ti = proto_tree_add_item(tree, proto_imap, tvb, offset, -1, ENC_NA);
  imap_tree = proto_item_add_subtree(ti, ett_imap);

  hidden_item = proto_tree_add_boolean(imap_tree, hf_imap_isrequest, tvb, 0, 0, is_request);
  proto_item_set_hidden(hidden_item);

  while(tvb_offset_exists(tvb, offset)) {

    commandlen = 0;
    folder_offset = 0;
    folder_tokenlen = 0;

    /*
     * Find the end of each line
     *
     * Note that "tvb_find_line_end()" will return a value that is
     * not longer than what's in the buffer, so the "tvb_get_ptr()"
     * call won't throw an exception.
     */
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, true);
    if (linelen == -1)
    {
      pinfo->desegment_offset = offset;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return tvb_captured_length(tvb);
    }

    /*
     * Check that the line doesn't begin with '*', because that's a continuation line.
     * Otherwise if a tag is present then extract tokens.
     */
    if (tvb_get_uint8(tvb, offset) == '*') {
      bool show_line = true;

      //find up to NUM_LOOKAHEAD_TOKENS tokens
      int start_offset;
      int next_pattern = offset, token_count = 0;
      struct simple_token_info tokens[NUM_LOOKAHEAD_TOKENS];
      do
      {
        start_offset = next_pattern+1;
        next_pattern = tvb_ws_mempbrk_pattern_guint8(tvb, start_offset, next_offset - start_offset, &pbrk_whitespace, NULL);
        if (next_pattern > start_offset)
        {
          tokens[token_count].token = tvb_get_string_enc(pinfo->pool, tvb, start_offset, next_pattern-start_offset, ENC_ASCII);
          tokens[token_count].token_start_offset = start_offset;
          tokens[token_count].token_end_offset = next_pattern;
          token_count++;
        }
      } while ((next_pattern != -1) && (token_count < NUM_LOOKAHEAD_TOKENS));

      if (token_count >= 2)
      {
        bool need_more = false;
        for (int token = 0; token < token_count; token++)
        {
          if (!tvb_strncaseeql(tvb, tokens[token].token_start_offset, "FETCH", tokens[token].token_end_offset - tokens[token].token_start_offset))
          {
            //FETCH command.  Presume we need more data until we find a complete command
            need_more = dissect_imap_fetch(tvb, pinfo, tree, imap_tree, &reqresp_tree,
                                           tokens[token].token_end_offset, offset, &next_offset, &first_line);
            if (!need_more)
            {
              show_line = false;
            }
            break;
          }
        }

        if (need_more)
        {
          pinfo->desegment_offset = offset;
          pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
          return tvb_captured_length(tvb);
        }
      }

      if (show_line)
        proto_tree_add_item(imap_tree, hf_imap_line, tvb, offset, next_offset - offset, ENC_ASCII | ENC_NA);

    } else {

      if (first_line) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s", is_request ? "Request" : "Response", tvb_format_text(pinfo->pool, tvb, offset, linelen));
        first_line = false;
      }

      // Put the line into the protocol tree.
      ti = proto_tree_add_item(imap_tree, hf_imap_line, tvb, offset, next_offset - offset, ENC_ASCII | ENC_NA);
      reqresp_tree = proto_item_add_subtree(ti, ett_imap_reqresp);

      /*
       * Show each line as requests or replies + tags.
       */

      /*
       * Add the line as request or reply data.
       */
      if (linelen != 0) {
        proto_tree_add_item(reqresp_tree, (is_request) ? hf_imap_request : hf_imap_response, tvb, offset, linelen, ENC_ASCII|ENC_NA);
      }

      /*
       * Extract the first token, and, if there is a first
       * token, add it as the request or reply tag.
       */
      tokenlen = tvb_get_token_len(tvb, offset, linelen, &next_token, false);
      if (tokenlen != 0) {
        const char* tag = (const char*)tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_ASCII);
        request_key.tag = wmem_ascii_strdown(pinfo->pool, tag, strlen(tag));

        proto_tree_add_string(reqresp_tree, (is_request) ? hf_imap_request_tag : hf_imap_response_tag, tvb, offset, tokenlen, tag);
        hidden_item = proto_tree_add_string(reqresp_tree, hf_imap_tag, tvb, offset, tokenlen, tag);
        proto_item_set_hidden(hidden_item);

        linelen -= (next_token-offset);
        offset = next_token;
      }

      /*
       * Extract second token, and, if there is a second
       * token, and it's not uid, add it as the request or reply command.
       */
      tokenlen = tvb_get_token_len(tvb, offset, linelen, &next_token, false);
      if (tokenlen != 0) {

        tokenbuf = (const char*)tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_ASCII);
        tokenbuf = wmem_ascii_strdown(pinfo->pool, tokenbuf, tokenlen);

        if (is_request && !tvb_strncaseeql(tvb, offset, "UID", tokenlen)) {
          proto_tree_add_item(reqresp_tree, hf_imap_request_uid, tvb, offset, tokenlen, ENC_ASCII|ENC_NA);
          /*
           * UID is a precursor to a command, if following the tag,
           * so move to next token to grab the actual command.
           */
          uidlen = linelen - (next_token - offset);
          uid_offset = next_token;
          uid_tokenlen = tvb_get_token_len(tvb, next_token, uidlen, &uid_next_token, false);
          if (uid_tokenlen != 0) {
            proto_tree_add_item(reqresp_tree, hf_imap_request_command, tvb, uid_offset, uid_tokenlen, ENC_ASCII);
            hidden_item = proto_tree_add_item(reqresp_tree, hf_imap_command, tvb, offset, tokenlen, ENC_ASCII | ENC_NA);
            proto_item_set_hidden(hidden_item);

            /*
             * Save command string to do specialized processing.
             */
            commandlen = uid_tokenlen;
            command_token = (const char*)tvb_get_string_enc(pinfo->pool, tvb, next_token, commandlen, ENC_ASCII);
            command_token = wmem_ascii_strdown(pinfo->pool, command_token, commandlen);

            folderlen = linelen - (uid_next_token - offset);
            folder_offset = uid_next_token;
            folder_tokenlen = tvb_get_token_len(tvb, uid_next_token, folderlen, &folder_next_token, false);
          }
        } else {
          /*
           * Not a UID request so perform normal parsing.
           */
          proto_tree_add_item(reqresp_tree, (is_request) ? hf_imap_request_command : hf_imap_response_status, tvb, offset, tokenlen, ENC_ASCII|ENC_NA);
          if (is_request) {
            hidden_item = proto_tree_add_item(reqresp_tree, hf_imap_command, tvb, offset, tokenlen, ENC_ASCII | ENC_NA);
            proto_item_set_hidden(hidden_item);

            /*
             * Save command string to do specialized processing.
             */
            commandlen = tokenlen;
            command_token = (const char*)tvb_get_string_enc(pinfo->pool, tvb, offset, commandlen, ENC_ASCII);
            command_token = wmem_ascii_strdown(pinfo->pool, command_token, commandlen);

            folderlen = linelen - (next_token - offset);
            folder_offset = next_token;
            folder_tokenlen = tvb_get_token_len(tvb, next_token, folderlen, &folder_next_token, false);
          }
        }

        if (commandlen > 0) { // implies is_request (i.e. can be true only if is_request but is not equivalent)
          if (strncmp(command_token, "select", commandlen) == 0 ||
              strncmp(command_token, "examine", commandlen) == 0 ||
              strncmp(command_token, "create", commandlen) == 0 ||
              strncmp(command_token, "delete", commandlen) == 0 ||
              strncmp(command_token, "rename", commandlen) == 0 ||
              strncmp(command_token, "subscribe", commandlen) == 0 ||
              strncmp(command_token, "unsubscribe", commandlen) == 0 ||
              strncmp(command_token, "status", commandlen) == 0 ||
              strncmp(command_token, "append", commandlen) == 0 ||
              strncmp(command_token, "search", commandlen) == 0) {

            /*
             * These commands support folder as an argument,
             * so parse out the folder name.
             */
            if (folder_tokenlen != 0)
              proto_tree_add_item(reqresp_tree, hf_imap_request_folder, tvb, folder_offset, folder_tokenlen, ENC_ASCII | ENC_NA);
          }
          else if ((linelen > 0) && strncmp(command_token, "copy", commandlen) == 0) {
            /*
             * Handle the copy command separately since folder
             * is the second argument for this command.
             */
            folderlen = linelen - (folder_next_token - offset);
            folder_offset = folder_next_token;
            folder_tokenlen = tvb_get_token_len(tvb, folder_offset, folderlen, &folder_next_token, false);

            if (folder_tokenlen != 0)
              proto_tree_add_item(reqresp_tree, hf_imap_request_folder, tvb, folder_offset, folder_tokenlen, ENC_ASCII | ENC_NA);
          }
          else if (strncmp(command_token, "starttls", commandlen) == 0) {
            /* If next response is OK, then TLS should be commenced. */
            session_state->ssl_requested = true;
          }
          else if (strncmp(command_token, "login", commandlen) == 0) {
            int usernamelen = linelen - (next_token - offset);
            int username_offset = next_token;
            int username_next_token;
            int username_tokenlen = tvb_get_token_len(tvb, next_token, usernamelen, &username_next_token, false);
            char *username = (char*)tvb_get_string_enc(pinfo->pool, tvb, username_offset, username_tokenlen, ENC_ASCII | ENC_NA);
            proto_tree_add_string(reqresp_tree, hf_imap_request_username, tvb, username_offset, username_tokenlen, username);

            int passwordlen = linelen - (username_next_token - offset);
            int password_offset = username_next_token;
            int password_tokenlen = tvb_get_token_len(tvb, username_next_token, passwordlen, NULL, false);
            const char* password = tvb_get_string_enc(pinfo->pool, tvb, password_offset + 1, password_tokenlen - 2, ENC_ASCII | ENC_NA);
            proto_tree_add_string(reqresp_tree, hf_imap_request_password, tvb, password_offset, password_tokenlen, password);

            tap_credential_t* auth = wmem_new0(pinfo->pool, tap_credential_t);
            auth->num = auth->username_num = pinfo->num;
            auth->password_hf_id = hf_imap_request_password;
            auth->username = username;
            auth->proto = "IMAP";
            tap_queue_packet(credentials_tap, pinfo, auth);
          }
        }

        if (!is_request) {
          //See if there is the response command
          int command_next_token;
          int command_offset = next_token;
          commandlen = linelen - (next_token-offset);
          commandlen = tvb_get_token_len(tvb, next_token, commandlen, &command_next_token, false);
          if (commandlen > 0) {
            proto_tree_add_item(reqresp_tree, hf_imap_response_command, tvb, command_offset, commandlen, ENC_ASCII | ENC_NA);
            hidden_item = proto_tree_add_item(reqresp_tree, hf_imap_command, tvb, command_offset, commandlen, ENC_ASCII | ENC_NA);
            proto_item_set_hidden(hidden_item);
          }
        }

        /* If not yet switched to TLS, check for STARTTLS. */
        if (session_state->ssl_requested) {
          if (!is_request && (tokenbuf != NULL) && strncmp(tokenbuf, "ok", tokenlen) == 0) {
            /* STARTTLS accepted, next reply will be TLS. */
            ssl_starttls_ack(tls_handle, pinfo, imap_handle);
            if (session_state->ssl_heur_tries_left > 0) {
              session_state->ssl_heur_tries_left = 0;
            }
             session_state->ssl_requested = false;
          }
        }
      }

      /* Add request/response statistics */
      if (request_key.tag != NULL)
      {
        imap_match_request(pinfo, reqresp_tree, &request_key, is_request);
      }
    }

    offset = next_offset; /* Skip over last line and \r\n at the end of it */
  }

  // If there is only lines that begin with *, at least show the first one
  if (first_line) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s", is_request ? "Request" : "Response", tvb_format_text(pinfo->pool, tvb, 0, linelen));
  }

  return tvb_captured_length(tvb);
}

void
proto_register_imap(void)
{
  static hf_register_info hf[] = {

    { &hf_imap_isrequest,
      { "Request", "imap.isrequest",
         FT_BOOLEAN, BASE_NONE, NULL, 0x0,
         "true if IMAP request, false otherwise", HFILL }
    },
    { &hf_imap_line,
      { "Line", "imap.line",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "A line of an IMAP message", HFILL }
    },
    { &hf_imap_request,
      { "Request", "imap.request",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "Remainder of request line", HFILL }
    },
    { &hf_imap_request_tag,
      { "Request Tag", "imap.request_tag",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "First token of request line", HFILL }
    },
    { &hf_imap_response,
      { "Response", "imap.response",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "Remainder of response line", HFILL }
    },
    { &hf_imap_response_tag,
      { "Response Tag", "imap.response_tag",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "First token of response line", HFILL }
    },
    { &hf_imap_request_command,
      { "Request Command", "imap.request.command",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Request command name", HFILL }
    },
    { &hf_imap_response_command,
      { "Response Command", "imap.response.command",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Response command name", HFILL }
    },
    { &hf_imap_response_status,
      { "Response Status", "imap.response.status",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Response status code", HFILL }
    },
    { &hf_imap_tag,
      { "Tag", "imap.tag",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "First token of line", HFILL }
    },
    { &hf_imap_command,
      { "Command", "imap.command",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Request or Response command name", HFILL }
    },
    { &hf_imap_request_folder,
      { "Request Folder", "imap.request.folder",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "Request command folder", HFILL }
    },
    { &hf_imap_request_uid,
      { "Request isUID", "imap.request.command.uid",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Request command uid", HFILL }
    },
    { &hf_imap_request_username,
      { "Request Username", "imap.request.username",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Request command username", HFILL }
    },
    { &hf_imap_request_password,
      { "Request Password", "imap.request.password",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Request command password", HFILL }
    },

    /* Request/Response Matching */
    { &hf_imap_response_in,
      { "Response In", "imap.response_in",
      FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
      "The response to this IMAP request is in this frame", HFILL }
    },
    { &hf_imap_response_to,
      { "Request In", "imap.response_to",
      FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
      "This is a response to the IMAP request in this frame", HFILL }
    },
    { &hf_imap_time,
      { "Response Time", "imap.time",
      FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
      "The time between the request and response", HFILL }
    },
  };

  static int *ett[] = {
    &ett_imap,
    &ett_imap_reqresp,
  };

  module_t *imap_module;

  proto_imap = proto_register_protocol("Internet Message Access Protocol", "IMAP", "imap");

  imap_handle = register_dissector("imap", dissect_imap, proto_imap);

  proto_register_field_array(proto_imap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  imap_module = prefs_register_protocol(proto_imap, NULL);
  prefs_register_bool_preference(imap_module, "ssl_heuristic",
                                   "Use heuristic detection for TLS",
                                   "Whether to use heuristics for post-STARTTLS detection of encrypted IMAP conversations",
                                   &imap_ssl_heuristic);

  imap_requests = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), imap_request_hash, imap_request_equal);

  /* compile patterns */
  ws_mempbrk_compile(&pbrk_whitespace, " \t\r\n");

  credentials_tap = register_tap("credentials");
}

void
proto_reg_handoff_imap(void)
{
  dissector_add_uint_with_preference("tcp.port", TCP_PORT_IMAP, imap_handle);
  ssl_dissector_add(TCP_PORT_SSL_IMAP, imap_handle);
  tls_handle = find_dissector("tls");
  imf_handle = find_dissector("imf");
}
/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true
 */
