/* byte_view_text.cpp
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

#include "monospace_font.h"
#include "byte_view_text.h"

#include <epan/charsets.h>

#include <QTextCursor>
#include <QApplication>
#include <QMouseEvent>

// XXX - Use KHexEdit instead?
// http://api.kde.org/4.x-api/kdelibs-apidocs/interfaces/khexedit/html/index.html

ByteViewText::ByteViewText(QWidget *parent, tvbuff_t *tvb, proto_tree *tree, QTreeWidget *protoTree, unsigned int encoding) :
    QTextEdit(parent)
{
    setReadOnly(true);
    setLineWrapMode(QTextEdit::NoWrap);
    setCurrentFont(get_monospace_font());

    m_tvb = tvb;
    m_tree = tree;
    m_protoTree = protoTree;
    m_encoding = encoding;
    m_start = m_len = 0;

//    m_background = textBackgroundColor();
//    m_foreground = textColor();

//    g_log(NULL, G_LOG_LEVEL_DEBUG, "fg %d %d %d bg %d %d %d",
//          m_foreground.red(), m_foreground.green(), m_foreground.blue(),
//          m_background.red(), m_background.green(), m_background.blue()
//          );

    hexPrintCommon();
}

#define MAX_OFFSET_LEN   8      /* max length of hex offset of bytes */
#define BYTES_PER_LINE  16      /* max byte values in a line */
#define BITS_PER_LINE    8      /* max bit values in a line */
#define BYTE_VIEW_SEP    8      /* insert a space every BYTE_VIEW_SEP bytes */
#define HEX_DUMP_LEN    (BYTES_PER_LINE*3 + 1)
/* max number of characters hex dump takes -
   2 digits plus trailing blank
   plus separator between first and
   second 8 digits */
#define DATA_DUMP_LEN   (HEX_DUMP_LEN + 2 + BYTES_PER_LINE)
/* number of characters those bytes take;
   3 characters per byte of hex dump,
   2 blanks separating hex from ASCII,
   1 character per byte of ASCII dump */
#define MAX_LINE_LEN    (MAX_OFFSET_LEN + 2 + DATA_DUMP_LEN)
/* number of characters per line;
   offset, 2 blanks separating offset
   from data dump, data dump */
#define MAX_LINES       100
#define MAX_LINES_LEN   (MAX_LINES*MAX_LINE_LEN)

// Copied from packet_hex_print_common
void
ByteViewText::hexPrintCommon()
{
    int            i = 0, j, k = 0, len;
    const guint8  *pd;
    QString        line;
    static guchar  hexchars[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
//    static const guint8 bitmask[8] = {
//        0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
    guchar         c = '\0';

//    progdlg_t  *progbar = NULL;
//    float       progbar_val;
//    gboolean    progbar_stop_flag;
//    GTimeVal    progbar_start_time;
//    gchar       progbar_status_str[100];
//    int         progbar_nextstep;
//    int         progbar_quantum;

    setPlainText("");
    // Replaces get_byte_view_data_and_length().
    if (!m_tvb)
        return;
    len = tvb_length(m_tvb);
    pd = tvb_get_ptr(m_tvb, 0, -1);

    /*
     * How many of the leading digits of the offset will we supply?
     * We always supply at least 4 digits, but if the maximum offset
     * won't fit in 4 digits, we use as many digits as will be needed.
     */
    if (((len - 1) & 0xF0000000) != 0)
        m_useDigits = 8; /* need all 8 digits */
    else if (((len - 1) & 0x0F000000) != 0)
        m_useDigits = 7; /* need 7 digits */
    else if (((len - 1) & 0x00F00000) != 0)
        m_useDigits = 6; /* need 6 digits */
    else if (((len - 1) & 0x000F0000) != 0)
        m_useDigits = 5; /* need 5 digits */
    else
        m_useDigits = 4; /* we'll supply 4 digits */

    /* Update the progress bar when it gets to this value. */
//    if (len > MIN_PACKET_LENGTH){
//        progbar_nextstep = 0;
//    }else{
//        /* If length =< MIN_PACKET_LENGTH
//         * there is no need to calculate the progress
//         */
//        progbar_nextstep = len+1;
//    }

//    /* When we reach the value that triggers a progress bar update,
//       bump that value by this amount. */
//    progbar_quantum = len/N_PROGBAR_UPDATES;
//    /* Progress so far. */
//    progbar_val = 0.0f;

//    progbar_stop_flag = FALSE;
//    g_get_current_time(&progbar_start_time);

    while (i < len) {
        /* Create the progress bar if necessary.
           We check on every iteration of the loop, so that it takes no
           longer than the standard time to create it (otherwise, for a
           large packet, we might take considerably longer than that standard
           time in order to get to the next progress bar step). */
//        if ((progbar == NULL) && (len > MIN_PACKET_LENGTH))
//            progbar = delayed_create_progress_dlg("Processing", "Packet Details",
//                                                  TRUE,
//                                                  &progbar_stop_flag,
//                                                  &progbar_start_time,
//                                                  progbar_val);

        /* Update the progress bar, but do it only N_PROGBAR_UPDATES times;
           when we update it, we have to run the GTK+ main loop to get it
           to repaint what's pending, and doing so may involve an "ioctl()"
           to see if there's any pending input from an X server, and doing
           that for every packet can be costly, especially on a big file. */
//        if (i >= progbar_nextstep) {

//            if (progbar != NULL) {
//                /* let's not divide by zero. I should never be started
//                 * with count == 0, so let's assert that
//                 */
//                g_assert(len > 0);
//                progbar_val = (gfloat) i / len;
//                g_snprintf(progbar_status_str, sizeof(progbar_status_str),
//                           "%4u of %u bytes", i, len);
//                update_progress_dlg(progbar, progbar_val, progbar_status_str);
//            }

//            progbar_nextstep += progbar_quantum;
//        }

//        if (progbar_stop_flag) {
//            /* Well, the user decided to abort the operation.  Just stop,
//           and arrange to return TRUE to our caller, so they know it
//           was stopped explicitly. */
//            break;
//        }

        /* Print the line number */
        j = m_useDigits;
        do {
            j--;
            c = (i >> (j*4)) & 0xF;
            line += hexchars[c];
        } while (j != 0);
        line += "  ";

        j   = i;
//        switch (recent.gui_bytes_view) {
//        case BYTES_HEX:
            k = i + BYTES_PER_LINE;
//            break;
//        case BYTES_BITS:
//            k = i + BITS_PER_LINE;
//            break;
//        default:
//            g_assert_not_reached();
//        }
        /* Print the hex bit */
        while (i < k) {
            if (i < len) {
//                switch (recent.gui_bytes_view) {
//                case BYTES_HEX:
                    line += hexchars[(pd[i] & 0xf0) >> 4];
                    line += hexchars[pd[i] & 0x0f];
//                    break;
//                case BYTES_BITS:
//                    for (b = 0; b < 8; b++) {
//                        line += (pd[i] & bitmask[b]) ? '1' : '0';
//                    }
//                    break;
//            default:
//                    g_assert_not_reached();
//                }
            } else {
//                switch (recent.gui_bytes_view) {
//                case BYTES_HEX:
                    line += "  ";
//                    break;
//                case BYTES_BITS:
//                    for (b = 0; b < 8; b++) {
//                        line += ' ';
//                    }
//                    break;
//            default:
//                    g_assert_not_reached();
//                }
            }
            i++;
            /* Inter byte space if not at end of line */
            if (i < k) {
                line += ' ';
                /* insert a space every BYTE_VIEW_SEP bytes */
                if( ( i % BYTE_VIEW_SEP ) == 0 ) {
                    line += ' ';
                }
            }
        }

        /* Print some space at the end of the line */
        line += "   ";

        /* Print the ASCII bit */
        i = j;

        while (i < k) {
            if (i < len) {
                if (m_encoding == PACKET_CHAR_ENC_CHAR_ASCII) {
                    c = pd[i];
                }
                else if (m_encoding == PACKET_CHAR_ENC_CHAR_EBCDIC) {
                    c = EBCDIC_to_ASCII1(pd[i]);
                }
                else {
                    g_assert_not_reached();
                }
                line += isprint(c) ? c : '.';
            } else {
                line += ' ';
            }
            i++;
            if (i < k) {
                /* insert a space every BYTE_VIEW_SEP bytes */
                if( ( i % BYTE_VIEW_SEP ) == 0 ) {
                    line += ' ';
                }
            }
        }
        line += '\n';
        if (line.length() >= (MAX_LINES_LEN - MAX_LINE_LEN)) {
            append(line);
            line.clear();
        }
    }

//    /* We're done printing the packets; destroy the progress bar if
//       it was created. */
//    if (progbar != NULL)
//        destroy_progress_dlg(progbar);

    if (line.length()) {
        append(line);
    }
}

bool ByteViewText::hasDataSource(tvbuff_t *ds_tvb) {
    if (ds_tvb != NULL && ds_tvb == m_tvb)
        return true;
    return false;
}

// Copied from packet_hex_apply_reverse_tag
void ByteViewText::highlight(int bstart, int blen, bool is_root) {
    m_start = bstart;
//    m_len = blen;

//    g_log(NULL, G_LOG_LEVEL_DEBUG, "hl %d %d %d %d", start, len, m_foreground.color().red(), m_background.color().red());
    QTextCursor cursor(textCursor());
    QTextCharFormat format = cursor.charFormat();

    QPalette pal = QApplication::palette();

    if (is_root) {
        cursor.movePosition(QTextCursor::Start);
        cursor.movePosition(QTextCursor::End, QTextCursor::KeepAnchor);
        format.setForeground(pal.text());
        format.setBackground(pal.base());
        cursor.setCharFormat(format);
    }

    // XXX - We should probably use the same colors as the packet list and proto tree selections.
    // It isn't obvious how to fetch these.
    format.setForeground(is_root ? pal.text() : pal.base());
    format.setBackground(is_root ? pal.alternateBase() : pal.text());

    int bend = bstart + blen;
    int per_line = 0;
    int per_one = 0;
    int bits_per_one = 0;
    int hex_offset, ascii_offset;

    int start_line, start_line_pos;
    int stop_line, stop_line_pos;

    if (bstart == -1 || blen == -1)
        return;

//    /* Display with inverse video ? */
//    if (prefs.gui_hex_dump_highlight_style)
//        revstyle = "reverse";
//    else
//        revstyle = "bold";

//    switch (recent.gui_bytes_view) {
//    case BYTES_HEX:
        per_line = BYTES_PER_LINE;
        per_one  = 2+1;  /* "ff " */
        bits_per_one = 4;
//        break;
//    case BYTES_BITS:
//        per_line = BITS_PER_LINE;
//        per_one  = 8+1;  /* "10101010 " */
//        bits_per_one = 1;
//        break;
//    default:
//        g_assert_not_reached();
//    }

    start_line = bstart / per_line;
    start_line_pos = bstart % per_line;

    stop_line = bend / per_line;
    stop_line_pos = bend % per_line;

#define hex_fix(pos)   hex_offset + (pos * per_one) + (pos / BYTE_VIEW_SEP) - (pos == per_line)
#define ascii_fix(pos) pos + (pos / BYTE_VIEW_SEP) - (pos == per_line)

    hex_offset = m_useDigits + 2;
    ascii_offset = hex_fix(per_line) + 2;

    cursor.setPosition(0);
    cursor.movePosition(QTextCursor::Down, QTextCursor::MoveAnchor, start_line);

//    if (mask == 0x00) {
        while (start_line <= stop_line) {
            int line_pos_end = (start_line == stop_line) ? stop_line_pos : per_line;
//            int first_block_adjust = (recent.gui_bytes_view == BYTES_HEX) ? (line_pos_end == per_line/2) : 0;
            int first_block_adjust = line_pos_end == per_line/2;

            if (start_line_pos == line_pos_end) break;

            // Should we just jump to absolute offsets instead?
            /* bits/hex */
            int cursor_start = hex_fix(start_line_pos);
            int cursor_len = hex_fix(line_pos_end) - cursor_start - 1 - first_block_adjust;
            cursor.movePosition(QTextCursor::Right, QTextCursor::MoveAnchor, cursor_start);
            cursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, cursor_len);
            cursor.setCharFormat(format);
            cursor.movePosition(QTextCursor::Right, QTextCursor::MoveAnchor, ascii_offset - cursor_start - cursor_len);

            /* ascii */
            cursor_start = ascii_fix(start_line_pos);
            cursor_len = ascii_fix(line_pos_end) - cursor_start - first_block_adjust;
            cursor.movePosition(QTextCursor::Right, QTextCursor::MoveAnchor, cursor_start);
            cursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, cursor_len);
            cursor.setCharFormat(format);

            start_line_pos = 0;
            start_line++;
            // You are encouraged to make carriage return and line feed sound
            // effects as you read the next two lines.
            cursor.movePosition(QTextCursor::StartOfLine);
            cursor.movePosition(QTextCursor::Down);
        }

//    } else if (mask_le) { /* LSB of mask first (little-endian) */
//        while (start_line <= stop_line) {
//            int line_pos_end = (start_line == stop_line) ? stop_line_pos : per_line;
//            int line_pos = start_line_pos;

//            while (line_pos < line_pos_end) {
//                int lop = 8 / bits_per_one;
//                int mask_per_one = (1 << bits_per_one) - 1;
//                int ascii_on = 0;

//                while (lop--) {
//                    if ((mask & mask_per_one)) {
//                        /* bits/hex */
//                        gtk_text_buffer_get_iter_at_line_index(buf, &i_start, start_line, hex_fix(line_pos)+lop);
//                        gtk_text_buffer_get_iter_at_line_index(buf, &i_stop, start_line, hex_fix(line_pos)+lop+1);
//                        gtk_text_buffer_apply_tag(buf, revstyle_tag, &i_start, &i_stop);

//                        ascii_on = 1;
//                    }
//                    mask >>= bits_per_one;
//                }

//                /* at least one bit of ascii was one -> turn ascii on */
//                if (ascii_on) {
//                    /* ascii */
//                    gtk_text_buffer_get_iter_at_line_index(buf, &i_start, start_line, ascii_fix(line_pos));
//                    gtk_text_buffer_get_iter_at_line_index(buf, &i_stop, start_line, ascii_fix(line_pos)+1);
//                    gtk_text_buffer_apply_tag(buf, revstyle_tag, &i_start, &i_stop);
//                }

//                if (!mask)
//                    goto xend;

//                line_pos++;
//            }

//            start_line_pos = 0;
//            start_line++;
//        }
//    } else { /* mask starting from end (big-endian) */
//        while (start_line <= stop_line) {
//            int line_pos_start = (start_line == stop_line) ? start_line_pos : 0;
//            int line_pos = stop_line_pos-1;

//            while (line_pos >= line_pos_start) {
//                int lop = 8 / bits_per_one;
//                int mask_per_one = (1 << bits_per_one) - 1;
//                int ascii_on = 0;

//                while (lop--) {
//                    if ((mask & mask_per_one)) {
//                        /* bits/hex */
//                        gtk_text_buffer_get_iter_at_line_index(buf, &i_start, stop_line, hex_fix(line_pos)+lop);
//                        gtk_text_buffer_get_iter_at_line_index(buf, &i_stop, stop_line, hex_fix(line_pos)+lop+1);
//                        gtk_text_buffer_apply_tag(buf, revstyle_tag, &i_start, &i_stop);

//                        ascii_on = 1;
//                    }
//                    mask >>= bits_per_one;
//                }

//                /* at least one bit of ascii was one -> turn ascii on */
//                if (ascii_on) {
//                    /* ascii */
//                    gtk_text_buffer_get_iter_at_line_index(buf, &i_start, stop_line, ascii_fix(line_pos));
//                    gtk_text_buffer_get_iter_at_line_index(buf, &i_stop, stop_line, ascii_fix(line_pos)+1);
//                    gtk_text_buffer_apply_tag(buf, revstyle_tag, &i_start, &i_stop);
//                }

//                if (!mask)
//                    goto xend;

//                line_pos--;
//            }

//            stop_line_pos = per_line;
//            stop_line--;
//        }
//    }
//xend:

#undef hex_fix
#undef ascii_fix
}

// XXX - Copied from main_proto_draw.c
/* Which byte the offset is referring to. Associates
 * whitespace with the preceding digits. */
static int
byte_num(int offset, int start_point)
{
    return (offset - start_point) / 3;
}

// XXX - Copied from main_proto_draw.c
//static int
//bit_num(int offset, int start_point)
//{
//    return (offset - start_point) / 9;
//}

// XXX - Copied from main_proto_draw.c
static int
hex_view_get_byte(guint ndigits, int row, int column)
{
    int           byte;
    int           digits_start_1;
    int           digits_end_1;
    int           digits_start_2;
    int           digits_end_2;
    int           text_start_1;
    int           text_end_1;
    int           text_start_2;
    int           text_end_2;

    /*
     * The column of the first hex digit in the first half.
     * That starts after "ndigits" digits of offset and two
     * separating blanks.
     */
    digits_start_1 = ndigits + 2;

    /*
     * The column of the last hex digit in the first half.
     * There are BYTES_PER_LINE/2 bytes displayed in the first
     * half; there are 2 characters per byte, plus a separating
     * blank after all but the last byte's characters.
     */
    digits_end_1 = digits_start_1 + (BYTES_PER_LINE/2)*2 +
        (BYTES_PER_LINE/2 - 1);

    /*
     * The column of the first hex digit in the second half.
     * Add 2 for the 2 separating blanks between the halves.
     */
    digits_start_2 = digits_end_1 + 2;

    /*
     * The column of the last hex digit in the second half.
     * Add the same value we used to get "digits_end_1" from
     * "digits_start_1".
     */
    digits_end_2 = digits_start_2 + (BYTES_PER_LINE/2)*2 +
        (BYTES_PER_LINE/2 - 1);

    /*
     * The column of the first "text dump" character in the first half.
     * Add 3 for the 3 separating blanks between the hex and text dump.
     */
    text_start_1 = digits_end_2 + 3;

    /*
     * The column of the last "text dump" character in the first half.
     * There are BYTES_PER_LINE/2 bytes displayed in the first
     * half; there is 1 character per byte.
     *
     * Then subtract 1 to get the last column of the first half
     * rather than the first column after the first half.
     */
    text_end_1 = text_start_1 + BYTES_PER_LINE/2 - 1;

    /*
     * The column of the first "text dump" character in the second half.
     * Add back the 1 to get the first column after the first half,
     * and then add 1 for the separating blank between the halves.
     */
    text_start_2 = text_end_1 + 2;

    /*
     * The column of the last "text dump" character in second half.
     * Add the same value we used to get "text_end_1" from
     * "text_start_1".
     */
    text_end_2 = text_start_2 + BYTES_PER_LINE/2 - 1;

    /* Given the column and row, determine which byte offset
     * the user clicked on. */
    if (column >= digits_start_1 && column <= digits_end_1) {
        byte = byte_num(column, digits_start_1);
        if (byte == -1) {
            return byte;
        }
    }
    else if (column >= digits_start_2 && column <= digits_end_2) {
        byte = byte_num(column, digits_start_2);
        if (byte == -1) {
            return byte;
        }
        byte += 8;
    }
    else if (column >= text_start_1 && column <= text_end_1) {
        byte = column - text_start_1;
    }
    else if (column >= text_start_2 && column <= text_end_2) {
        byte = 8 + column - text_start_2;
    }
    else {
        /* The user didn't select a hex digit or
         * text-dump character. */
        return -1;
    }

    /* Add the number of bytes from the previous rows. */
    byte += row * BYTES_PER_LINE;

    return byte;
}

void ByteViewText::mousePressEvent (QMouseEvent * event) {
    if (event->button() == Qt::LeftButton) {
        int byte;
        QTextCursor cursor(cursorForPosition(event->pos()));
        field_info *fi;

        byte = hex_view_get_byte(m_useDigits, cursor.blockNumber(), cursor.columnNumber());
        fi = proto_find_field_from_offset(m_tree, byte, m_tvb);
        g_log(NULL, G_LOG_LEVEL_DEBUG, "byte %d  fi %p", byte, fi);

        if (fi && m_protoTree) {
            // XXX - This should probably be a ProtoTree method.
            QTreeWidgetItemIterator iter(m_protoTree);
            QVariant v;
            while (*iter) {
                v = (*iter)->data(0, Qt::UserRole);
                if (fi == (field_info *) v.value<void *>()) {
                    g_log(NULL, G_LOG_LEVEL_DEBUG, "found %p", fi);
                    m_protoTree->setCurrentItem((*iter));
                }

                iter++;
            }
        }
    }

    QWidget::mousePressEvent (event);
}
