/* packet-smtp.c
 * Routines for SMTP packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2000 by Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#include <stdlib.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/emem.h>
#include <epan/reassemble.h>
#include <epan/dissectors/packet-ssl.h>

/* RFC 2821 */
#define TCP_PORT_SMTP 25
#define TCP_PORT_SSL_SMTP 465

/* RFC 4409 */
#define TCP_PORT_SUBMISSION 587

static int proto_smtp = -1;

static int hf_smtp_req = -1;
static int hf_smtp_rsp = -1;
static int hf_smtp_req_command = -1;
static int hf_smtp_req_parameter = -1;
static int hf_smtp_rsp_code = -1;
static int hf_smtp_rsp_parameter = -1;

static int hf_smtp_data_fragments = -1;
static int hf_smtp_data_fragment = -1;
static int hf_smtp_data_fragment_overlap = -1;
static int hf_smtp_data_fragment_overlap_conflicts = -1;
static int hf_smtp_data_fragment_multiple_tails = -1;
static int hf_smtp_data_fragment_too_long_fragment = -1;
static int hf_smtp_data_fragment_error = -1;
static int hf_smtp_data_fragment_count = -1;
static int hf_smtp_data_reassembled_in = -1;
static int hf_smtp_data_reassembled_length = -1;

static int ett_smtp = -1;
static int ett_smtp_cmdresp = -1;

static gint ett_smtp_data_fragment = -1;
static gint ett_smtp_data_fragments = -1;

/* desegmentation of SMTP command and response lines */
static gboolean smtp_desegment = TRUE;
static gboolean smtp_data_desegment = TRUE;

static GHashTable *smtp_data_segment_table = NULL;
static GHashTable *smtp_data_reassembled_table = NULL;

static const fragment_items smtp_data_frag_items = {
  /* Fragment subtrees */
  &ett_smtp_data_fragment,
  &ett_smtp_data_fragments,
  /* Fragment fields */
  &hf_smtp_data_fragments,
  &hf_smtp_data_fragment,
  &hf_smtp_data_fragment_overlap,
  &hf_smtp_data_fragment_overlap_conflicts,
  &hf_smtp_data_fragment_multiple_tails,
  &hf_smtp_data_fragment_too_long_fragment,
  &hf_smtp_data_fragment_error,
  &hf_smtp_data_fragment_count,
  /* Reassembled in field */
  &hf_smtp_data_reassembled_in,
  /* Reassembled length field */
  &hf_smtp_data_reassembled_length,
  /* Tag */
  "DATA fragments"
};

static  dissector_handle_t ssl_handle;
static  dissector_handle_t imf_handle;

/*
 * A CMD is an SMTP command, MESSAGE is the message portion, and EOM is the
 * last part of a message
 */
#define SMTP_PDU_CMD     0
#define SMTP_PDU_MESSAGE 1
#define SMTP_PDU_EOM     2

struct smtp_proto_data {
  guint16 pdu_type;
  guint16 conversation_id;
  gboolean more_frags;
};

/*
 * State information stored with a conversation.
 */
typedef enum {
  SMTP_STATE_READING_CMDS,              /* reading commands */
  SMTP_STATE_READING_DATA,              /* reading message data */
  SMTP_STATE_AWAITING_STARTTLS_RESPONSE /* sent STARTTLS, awaiting response */
} smtp_state_t;

struct smtp_session_state {
  smtp_state_t smtp_state;    /* Current state */
  gboolean crlf_seen;         /* Have we seen a CRLF on the end of a packet */
  gboolean data_seen;         /* Have we seen a DATA command yet */
  guint32  msg_read_len;      /* Length of BDAT message read so far */
  guint32  msg_tot_len;       /* Total length of BDAT message */
  gboolean msg_last;          /* Is this the last BDAT chunk */
  guint32  last_nontls_frame; /* last non-TLS frame; 0 if not known or no TLS */
};

/*
 * See
 *
 *      http://support.microsoft.com/default.aspx?scid=kb;[LN];812455
 *
 * for the Exchange extensions.
 */
static const struct {
  const char *command;
  int len;
} commands[] = {
  { "STARTTLS", 8 },            /* RFC 2487 */
  { "X-EXPS", 6 },              /* Microsoft Exchange */
  { "X-LINK2STATE", 12 },       /* Microsoft Exchange */
  { "XEXCH50", 7 }              /* Microsoft Exchange */
};

#define NCOMMANDS       (sizeof commands / sizeof commands[0])

/* The following were copied from RFC 2821 */
static const value_string response_codes_vs[] = {
  { 211, "System status, or system help reply" },
  { 214, "Help message" },
  { 220, "<domain> Service ready" },
  { 221, "<domain> Service closing transmission channel" },
  { 250, "Requested mail action okay, completed" },
  { 251, "User not local; will forward to <forward-path>" },
  { 252, "Cannot VRFY user, but will accept message and attempt delivery" },
  { 354, "Start mail input; end with <CRLF>.<CRLF>" },
  { 421, "<domain> Service not available, closing transmission channel" },
  { 450, "Requested mail action not taken: mailbox unavailable" },
  { 451, "Requested action aborted: local error in processing" },
  { 452, "Requested action not taken: insufficient system storage" },
  { 500, "Syntax error, command unrecognized" },
  { 501, "Syntax error in parameters or arguments" },
  { 502, "Command not implemented" },
  { 503, "Bad sequence of commands" },
  { 504, "Command parameter not implemented" },
  { 550, "Requested action not taken: mailbox unavailable" },
  { 551, "User not local; please try <forward-path>" },
  { 552, "Requested mail action aborted: exceeded storage allocation" },
  { 553, "Requested action not taken: mailbox name not allowed" },
  { 554, "Transaction failed" },
  { 0, NULL }
};


static gboolean
line_is_smtp_command(const guchar *command, int commandlen)
{
  size_t i;

  /*
   * To quote RFC 821, "Command codes are four alphabetic
   * characters".
   *
   * However, there are some SMTP extensions that involve commands
   * longer than 4 characters and/or that contain non-alphabetic
   * characters; we treat them specially.
   *
   * XXX - should we just have a table of known commands?  Or would
   * that fail to catch some extensions we don't know about?
   */
  if (commandlen == 4 && g_ascii_isalpha(command[0]) &&
      g_ascii_isalpha(command[1]) && g_ascii_isalpha(command[2]) &&
      g_ascii_isalpha(command[3])) {
    /* standard 4-alphabetic command */
    return TRUE;
  }

  /*
   * Check the list of non-4-alphabetic commands.
   */
  for (i = 0; i < NCOMMANDS; i++) {
    if (commandlen == commands[i].len &&
        g_ascii_strncasecmp(command, commands[i].command, commands[i].len) == 0)
      return TRUE;
  }
  return FALSE;
}

static void
dissect_smtp_data(tvbuff_t *tvb, int offset, proto_tree *smtp_tree)
{
  gint next_offset;

  if (smtp_tree) {
    while (tvb_offset_exists(tvb, offset)) {
      /*
       * Find the end of the line.
       */
      tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);

      /*
       * Put this line.
       */
      proto_tree_add_text(smtp_tree, tvb, offset, next_offset - offset,
                          "Message: %s",
                          tvb_format_text(tvb, offset, next_offset - offset));

      /*
       * Step to the next line.
       */
      offset = next_offset;
    }
  }
}

static void
dissect_smtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct smtp_proto_data    *spd_frame_data;
  proto_tree                *smtp_tree = NULL;
  proto_tree                *cmdresp_tree;
  proto_item                *ti, *hidden_item;
  int                       offset = 0;
  int                       request = 0;
  conversation_t            *conversation;
  struct smtp_session_state *session_state;
  const guchar              *line, *linep, *lineend;
  guint32                   code;
  int                       linelen = 0;
  gint                      length_remaining;
  gboolean                  eom_seen = FALSE;
  gint                      next_offset;
  gint                      loffset = 0;
  int                       cmdlen;
  fragment_data             *frag_msg = NULL;
  tvbuff_t                  *next_tvb;

  /* As there is no guarantee that we will only see frames in the
   * the SMTP conversation once, and that we will see them in
   * order - in Wireshark, the user could randomly click on frames
   * in the conversation in any order in which they choose - we
   * have to store information with each frame indicating whether
   * it contains commands or data or an EOM indication.
   *
   * XXX - what about frames that contain *both*?  TCP is a
   * byte-stream protocol, and there are no guarantees that
   * TCP segment boundaries will correspond to SMTP commands
   * or EOM indications.
   *
   * We only need that for the client->server stream; responses
   * are easy to manage.
   *
   * If we have per frame data, use that, else, we must be on the first
   * pass, so we figure it out on the first pass.
   */

  /*
   * Find or create the conversation for this.
   */
  conversation = find_or_create_conversation(pinfo);

  /*
   * Is there a request structure attached to this conversation?
   */
  session_state = conversation_get_proto_data(conversation, proto_smtp);
  if (!session_state) {
    /*
     * No - create one and attach it.
     */
    session_state = se_alloc(sizeof(struct smtp_session_state));
    session_state->smtp_state = SMTP_STATE_READING_CMDS;
    session_state->crlf_seen = FALSE;
    session_state->data_seen = FALSE;
    session_state->msg_read_len = 0;
    session_state->msg_tot_len = 0;
    session_state->msg_last = TRUE;
    session_state->last_nontls_frame = 0;

    conversation_add_proto_data(conversation, proto_smtp, session_state);
  }

  /* Are we doing TLS?
   * FIXME In my understanding of RFC 2487 client and server can send SMTP cmds
   * after a rejected TLS negotiation
   */
  if (session_state->last_nontls_frame != 0 && pinfo->fd->num > session_state->last_nontls_frame) {
    guint16 save_can_desegment;
    guint32 save_last_nontls_frame;

    /* This is TLS, not raw SMTP. TLS can desegment */
    save_can_desegment = pinfo->can_desegment;
    pinfo->can_desegment = pinfo->saved_can_desegment;

    /* Make sure the SSL dissector will not be called again after decryption */
    save_last_nontls_frame = session_state->last_nontls_frame;
    session_state->last_nontls_frame = 0;

    call_dissector(ssl_handle, tvb, pinfo, tree);

    pinfo->can_desegment = save_can_desegment;
    session_state->last_nontls_frame = save_last_nontls_frame;
    return;
  }

  /* Is this a request or a response? */
  request = pinfo->destport == pinfo->match_uint;

  /*
   * Is there any data attached to this frame?
   */
  spd_frame_data = p_get_proto_data(pinfo->fd, proto_smtp);

  if (!spd_frame_data) {

    /*
     * No frame data.
     */
    if(request) {

      /*
       * Create a frame data structure and attach it to the packet.
       */
      spd_frame_data = se_alloc0(sizeof(struct smtp_proto_data));

      spd_frame_data->conversation_id = conversation->index;
      spd_frame_data->more_frags = TRUE;

      p_add_proto_data(pinfo->fd, proto_smtp, spd_frame_data);

    }

    /*
     * Get the first line from the buffer.
     *
     * Note that "tvb_find_line_end()" will, if it doesn't return
     * -1, return a value that is not longer than what's in the buffer,
     * and "tvb_find_line_end()" will always return a value that is not
     * longer than what's in the buffer, so the "tvb_get_ptr()" call
     * won't throw an exception.
     */
    loffset = offset;
    while (tvb_offset_exists(tvb, loffset)) {
      linelen = tvb_find_line_end(tvb, loffset, -1, &next_offset,
                                  smtp_desegment && pinfo->can_desegment);
      if (linelen == -1) {
        if (offset == loffset) {
          /*
           * We didn't find a line ending, and we're doing desegmentation;
           * tell the TCP dissector where the data for this message starts
           * in the data it handed us, and tell it we need more bytes
           */
          pinfo->desegment_offset = loffset;
          pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
          return;
        } else {
          linelen = tvb_length_remaining(tvb, loffset);
          next_offset = loffset + linelen;
        }
      }
      line = tvb_get_ptr(tvb, loffset, linelen);

      /*
       * Check whether or not this packet is an end of message packet
       * We should look for CRLF.CRLF and they may be split.
       * We have to keep in mind that we may see what we want on
       * two passes through here ...
       */
      if (session_state->smtp_state == SMTP_STATE_READING_DATA) {
        /*
         * The order of these is important ... We want to avoid
         * cases where there is a CRLF at the end of a packet and a
         * .CRLF at the begining of the same packet.
         */
        if ((session_state->crlf_seen && tvb_strneql(tvb, loffset, ".\r\n", 3) == 0) ||
            tvb_strneql(tvb, loffset, "\r\n.\r\n", 5) == 0)
          eom_seen = TRUE;

        length_remaining = tvb_length_remaining(tvb, loffset);
        if (length_remaining == tvb_reported_length_remaining(tvb, loffset) &&
            tvb_strneql(tvb, loffset + length_remaining - 2, "\r\n", 2) == 0)
          session_state->crlf_seen = TRUE;
        else
          session_state->crlf_seen = FALSE;
      }

      /*
       * OK, Check if we have seen a DATA request. We do it here for
       * simplicity, but we have to be careful below.
       */
      if (request) {
        if (session_state->smtp_state == SMTP_STATE_READING_DATA) {
          /*
           * This is message data.
           */
          if (eom_seen) { /* Seen the EOM */
            /*
             * EOM.
             * Everything that comes after it is commands.
             */
            spd_frame_data->pdu_type = SMTP_PDU_EOM;
            session_state->smtp_state = SMTP_STATE_READING_CMDS;
            break;
          } else {
            /*
             * Message data with no EOM.
             */
            spd_frame_data->pdu_type = SMTP_PDU_MESSAGE;

            if (session_state->msg_tot_len > 0) {
              /*
               * We are handling a BDAT message.
               * Check if we have reached end of the data chunk.
               */
              session_state->msg_read_len += tvb_length_remaining(tvb, loffset);

              if (session_state->msg_read_len == session_state->msg_tot_len) {
                /*
                 * We have reached end of BDAT data chunk.
                 * Everything that comes after this is commands.
                 */
                session_state->smtp_state = SMTP_STATE_READING_CMDS;

                if (session_state->msg_last) {
                  /*
                   * We have found the LAST data chunk.
                   * The message can now be reassembled.
                   */
                  spd_frame_data->more_frags = FALSE;
                }

                break; /* no need to go through the remaining lines */
              }
            }
          }
        } else {
          /*
           * This is commands - unless the capture started in the
           * middle of a session, and we're in the middle of data.
           *
           * Commands are not necessarily 4 characters; look
           * for a space or the end of the line to see where
           * the putative command ends.
           */
          linep = line;
          lineend = line + linelen;
          while (linep < lineend && *linep != ' ')
            linep++;
          cmdlen = (int)(linep - line);
          if (line_is_smtp_command(line, cmdlen)) {
            if (g_ascii_strncasecmp(line, "DATA", 4) == 0) {
              /*
               * DATA command.
               * This is a command, but everything that comes after it,
               * until an EOM, is data.
               */
              spd_frame_data->pdu_type = SMTP_PDU_CMD;
              session_state->smtp_state = SMTP_STATE_READING_DATA;
              session_state->data_seen = TRUE;
            } else if (g_ascii_strncasecmp(line, "BDAT", 4) == 0) {
              /*
               * BDAT command.
               * This is a command, but everything that comes after it,
               * until given length is received, is data.
               */
              guint32 msg_len;

              msg_len = strtoul (line+5, NULL, 10);

              spd_frame_data->pdu_type = SMTP_PDU_CMD;
              session_state->data_seen = TRUE;
              session_state->msg_tot_len += msg_len;

              if (msg_len == 0) {
                /* No data to read, next will be a command */
                session_state->smtp_state = SMTP_STATE_READING_CMDS;
              } else {
                session_state->smtp_state = SMTP_STATE_READING_DATA;
              }

              if (g_ascii_strncasecmp(line+linelen-4, "LAST", 4) == 0) {
                /*
                 * This is the last data chunk.
                 */
                session_state->msg_last = TRUE;

                if (msg_len == 0) {
                  /*
                   * No more data to expect.
                   * The message can now be reassembled.
                   */
                  spd_frame_data->more_frags = FALSE;
                }
              } else {
                session_state->msg_last = FALSE;
              }
            } else if (g_ascii_strncasecmp(line, "STARTTLS", 8) == 0) {
              /*
               * STARTTLS command.
               * This is a command, but if the response is 220,
               * everything after the response is TLS.
               */
              session_state->smtp_state = SMTP_STATE_AWAITING_STARTTLS_RESPONSE;
              spd_frame_data->pdu_type = SMTP_PDU_CMD;
            } else {
              /*
               * Regular command.
               */
              spd_frame_data->pdu_type = SMTP_PDU_CMD;
            }
          } else {
            /*
             * Assume it's message data.
             */
            spd_frame_data->pdu_type = session_state->data_seen ? SMTP_PDU_MESSAGE : SMTP_PDU_CMD;
          }
        }
      }

      /*
       * Step past this line.
       */
      loffset = next_offset;
    }
  }


  /*
   * From here, we simply add items to the tree and info to the info
   * fields ...
   */

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMTP");

  if (check_col(pinfo->cinfo, COL_INFO)) {  /* Add the appropriate type here */
    col_clear(pinfo->cinfo, COL_INFO);

    /*
     * If it is a request, we have to look things up, otherwise, just
     * display the right things
     */

    if (request) {
      /* We must have frame_data here ... */
      switch (spd_frame_data->pdu_type) {
      case SMTP_PDU_MESSAGE:

        length_remaining = tvb_length_remaining(tvb, offset);
        col_set_str(pinfo->cinfo, COL_INFO, smtp_data_desegment ? "C: DATA fragment" : "C: Message Body");
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %d byte%s", length_remaining,
                        plurality (length_remaining, "", "s"));
        break;

      case SMTP_PDU_EOM:
        col_set_str(pinfo->cinfo, COL_INFO, "C: .");
        break;

      case SMTP_PDU_CMD:
        loffset = offset;
        while (tvb_offset_exists(tvb, loffset)) {
          /*
           * Find the end of the line.
           */
          linelen = tvb_find_line_end(tvb, loffset, -1, &next_offset, FALSE);
          line = tvb_get_ptr(tvb, loffset, linelen);

          if(loffset == offset)
            col_append_fstr(pinfo->cinfo, COL_INFO, "C: %s",
                            format_text(line, linelen));
          else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " | %s",
                            format_text(line, linelen));
          }

          loffset = next_offset;
        }
        break;
      }
    } else {
      loffset = offset;
      while (tvb_offset_exists(tvb, loffset)) {
        /*
         * Find the end of the line.
         */
        linelen = tvb_find_line_end(tvb, loffset, -1, &next_offset, FALSE);
        line = tvb_get_ptr(tvb, loffset, linelen);

        if (loffset == offset)
          col_append_fstr(pinfo->cinfo, COL_INFO, "S: %s",
                          format_text(line, linelen));
        else {
          col_append_fstr(pinfo->cinfo, COL_INFO, " | %s",
                          format_text(line, linelen));
        }

        loffset = next_offset;
      }
    }
  }

  if (tree) { /* Build the tree info ... */
    ti = proto_tree_add_item(tree, proto_smtp, tvb, offset, -1, ENC_NA);
    smtp_tree = proto_item_add_subtree(ti, ett_smtp);
  }

  if (request) {
    /*
     * Check out whether or not we can see a command in there ...
     * What we are looking for is not data_seen and the word DATA
     * and not eom_seen.
     *
     * We will see DATA and session_state->data_seen when we process the
     * tree view after we have seen a DATA packet when processing
     * the packet list pane.
     *
     * On the first pass, we will not have any info on the packets
     * On second and subsequent passes, we will.
     */
    switch (spd_frame_data->pdu_type) {

    case SMTP_PDU_MESSAGE:
      if (smtp_data_desegment) {
        frag_msg = fragment_add_seq_next(tvb, 0, pinfo, spd_frame_data->conversation_id,
                                         smtp_data_segment_table, smtp_data_reassembled_table,
                                         tvb_length(tvb), spd_frame_data->more_frags);
      } else {
        /*
         * Message body.
         * Put its lines into the protocol tree, a line at a time.
         */
        dissect_smtp_data(tvb, offset, smtp_tree);
      }
      break;

    case SMTP_PDU_EOM:
      /*
       * End-of-message-body indicator.
       *
       * XXX - what about stuff after the first line?
       * Unlikely, as the client should wait for a response to the
       * DATA command this terminates before sending another
       * request, but we should probably handle it.
       */
      proto_tree_add_text(smtp_tree, tvb, offset, linelen, "C: .");

      if (smtp_data_desegment) {
        /* add final data segment */
        if (loffset)
          fragment_add_seq_next(tvb, 0, pinfo, spd_frame_data->conversation_id,
                                smtp_data_segment_table, smtp_data_reassembled_table,
                                loffset, spd_frame_data->more_frags);

        /* terminate the desegmentation */
        frag_msg = fragment_end_seq_next (pinfo, spd_frame_data->conversation_id, smtp_data_segment_table,
                                          smtp_data_reassembled_table);
      }
      break;

    case SMTP_PDU_CMD:
      /*
       * Command.
       *
       * XXX - what about stuff after the first line?
       * Unlikely, as the client should wait for a response to the
       * previous command before sending another request, but we
       * should probably handle it.
       */

      loffset = offset;
      while (tvb_offset_exists(tvb, loffset)) {
        /*
         * Find the end of the line.
         */
        linelen = tvb_find_line_end(tvb, loffset, -1, &next_offset, FALSE);

        if (linelen >= 4)
          cmdlen = 4;
        else
          cmdlen = linelen;
        hidden_item = proto_tree_add_boolean(smtp_tree, hf_smtp_req, tvb,
                                             0, 0, TRUE);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        /*
         * Put the command line into the protocol tree.
         */
        ti = proto_tree_add_text(smtp_tree, tvb, loffset, next_offset - loffset,
                                 "Command: %s",
                                 tvb_format_text(tvb, loffset, next_offset - loffset));
        cmdresp_tree = proto_item_add_subtree(ti, ett_smtp_cmdresp);

        proto_tree_add_item(cmdresp_tree, hf_smtp_req_command, tvb,
                            loffset, cmdlen, ENC_ASCII|ENC_NA);
        if (linelen > 5) {
          proto_tree_add_item(cmdresp_tree, hf_smtp_req_parameter, tvb,
                              loffset + 5, linelen - 5, ENC_ASCII|ENC_NA);
        }

        if (smtp_data_desegment && !spd_frame_data->more_frags) {
          /* terminate the desegmentation */
          frag_msg = fragment_end_seq_next (pinfo, spd_frame_data->conversation_id, smtp_data_segment_table,
                                            smtp_data_reassembled_table);
        }

        /*
         * Step past this line.
         */
        loffset = next_offset;
      }
    }

    if (smtp_data_desegment) {
      next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled SMTP",
                                          frag_msg, &smtp_data_frag_items, NULL, smtp_tree);
      if (next_tvb) {
        /* XXX: this is presumptious - we may have negotiated something else */
        if (imf_handle) {
          call_dissector(imf_handle, next_tvb, pinfo, tree);
        } else {
          /*
           * Message body.
           * Put its lines into the protocol tree, a line at a time.
           */
          dissect_smtp_data(tvb, offset, smtp_tree);
        }

        pinfo->fragmented = FALSE;
      } else {
        pinfo->fragmented = TRUE;
      }
    }
  } else {
    /*
     * Process the response, a line at a time, until we hit a line
     * that doesn't have a continuation indication on it.
     */
    if (tree) {
      hidden_item = proto_tree_add_boolean(smtp_tree, hf_smtp_rsp, tvb,
                                           0, 0, TRUE);
      PROTO_ITEM_SET_HIDDEN(hidden_item);
    }

    while (tvb_offset_exists(tvb, offset)) {
      /*
       * Find the end of the line.
       */
      linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);

      if (tree) {
        /*
         * Put it into the protocol tree.
         */
        ti = proto_tree_add_text(smtp_tree, tvb, offset,
                                 next_offset - offset, "Response: %s",
                                 tvb_format_text(tvb, offset,
                                                 next_offset - offset));
        cmdresp_tree = proto_item_add_subtree(ti, ett_smtp_cmdresp);
      } else
        cmdresp_tree = NULL;

      line = tvb_get_ptr(tvb, offset, linelen);
      if (linelen >= 3 && isdigit(line[0]) && isdigit(line[1])
          && isdigit(line[2])) {
        /*
         * We have a 3-digit response code.
         */
        code = (line[0] - '0')*100 + (line[1] - '0')*10 + (line[2] - '0');

        /*
         * If we're awaiting the response to a STARTTLS code, this
         * is it - if it's 220, all subsequent traffic will
         * be TLS, otherwise we're back to boring old SMTP.
         */
        if (session_state->smtp_state == SMTP_STATE_AWAITING_STARTTLS_RESPONSE) {
          if (code == 220) {
            /* This is the last non-TLS frame. */
            session_state->last_nontls_frame = pinfo->fd->num;
          }
          session_state->smtp_state =  SMTP_STATE_READING_CMDS;
        }

        if (tree) {
          /*
           * Put the response code and parameters into the protocol tree.
           */
          proto_tree_add_uint(cmdresp_tree, hf_smtp_rsp_code, tvb, offset, 3,
                              code);

          if (linelen >= 4) {
            proto_tree_add_item(cmdresp_tree, hf_smtp_rsp_parameter, tvb,
                                offset + 4, linelen - 4, ENC_ASCII|ENC_NA);
          }
        }
      }

      /*
       * Step past this line.
       */
      offset = next_offset;

    }
  }
}

static void smtp_data_reassemble_init (void)
{
        fragment_table_init (&smtp_data_segment_table);
        reassembled_table_init (&smtp_data_reassembled_table);
}


/* Register all the bits needed by the filtering engine */

void
proto_register_smtp(void)
{
  static hf_register_info hf[] = {
    { &hf_smtp_req,
      { "Request", "smtp.req",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_smtp_rsp,
      { "Response", "smtp.rsp",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_smtp_req_command,
      { "Command", "smtp.req.command",
        FT_STRING,  BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_smtp_req_parameter,
      { "Request parameter", "smtp.req.parameter",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_smtp_rsp_code,
      { "Response code", "smtp.response.code",
        FT_UINT32, BASE_DEC, VALS(response_codes_vs), 0x0, NULL, HFILL }},

    { &hf_smtp_rsp_parameter,
      { "Response parameter", "smtp.rsp.parameter",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    /* Fragment entries */
    { &hf_smtp_data_fragments,
      { "DATA fragments", "smtp.data.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, "Message fragments", HFILL } },

    { &hf_smtp_data_fragment,
      { "DATA fragment", "smtp.data.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, "Message fragment", HFILL } },

    { &hf_smtp_data_fragment_overlap,
      { "DATA fragment overlap", "smtp.data.fragment.overlap", FT_BOOLEAN,
        BASE_NONE, NULL, 0x0, "Message fragment overlap", HFILL } },

    { &hf_smtp_data_fragment_overlap_conflicts,
      { "DATA fragment overlapping with conflicting data",
        "smtp.data.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL,
        0x0, "Message fragment overlapping with conflicting data", HFILL } },

    { &hf_smtp_data_fragment_multiple_tails,
      { "DATA has multiple tail fragments", "smtp.data.fragment.multiple_tails",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Message has multiple tail fragments", HFILL } },

    { &hf_smtp_data_fragment_too_long_fragment,
      { "DATA fragment too long", "smtp.data.fragment.too_long_fragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Message fragment too long", HFILL } },

    { &hf_smtp_data_fragment_error,
      { "DATA defragmentation error", "smtp.data.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, "Message defragmentation error", HFILL } },

    { &hf_smtp_data_fragment_count,
      { "DATA fragment count", "smtp.data.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },

    { &hf_smtp_data_reassembled_in,
      { "Reassembled DATA in frame", "smtp.data.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, "This DATA fragment is reassembled in this frame", HFILL } },

    { &hf_smtp_data_reassembled_length,
      { "Reassembled DATA length", "smtp.data.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, "The total length of the reassembled payload", HFILL } },
  };
  static gint *ett[] = {
    &ett_smtp,
    &ett_smtp_cmdresp,
    &ett_smtp_data_fragment,
    &ett_smtp_data_fragments,

  };
  module_t *smtp_module;

  proto_smtp = proto_register_protocol("Simple Mail Transfer Protocol",
                                       "SMTP", "smtp");

  proto_register_field_array(proto_smtp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine (&smtp_data_reassemble_init);

  /* Allow dissector to find be found by name. */
  register_dissector("smtp", dissect_smtp, proto_smtp);

  /* Preferences */
  smtp_module = prefs_register_protocol(proto_smtp, NULL);
  prefs_register_bool_preference(smtp_module, "desegment_lines",
    "Reassemble SMTP command and response lines\nspanning multiple TCP segments",
    "Whether the SMTP dissector should reassemble command and response lines"
    " spanning multiple TCP segments. To use this option, you must also enable "
    "\"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &smtp_desegment);

  prefs_register_bool_preference(smtp_module, "desegment_data",
    "Reassemble SMTP DATA commands spanning multiple TCP segments",
    "Whether the SMTP dissector should reassemble DATA command and lines"
    " spanning multiple TCP segments. To use this option, you must also enable "
    "\"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &smtp_data_desegment);

}

/* The registration hand-off routine */
void
proto_reg_handoff_smtp(void)
{
  dissector_handle_t smtp_handle;

  smtp_handle = find_dissector("smtp");
  dissector_add_uint("tcp.port", TCP_PORT_SMTP, smtp_handle);
  ssl_dissector_add(TCP_PORT_SSL_SMTP, "smtp", TRUE);
  dissector_add_uint("tcp.port", TCP_PORT_SUBMISSION, smtp_handle);

  /* find the IMF dissector */
  imf_handle = find_dissector("imf");

  /* find the SSL dissector */
  ssl_handle = find_dissector("ssl");
}
