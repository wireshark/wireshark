/** @file
 * Dialog display for duplication detection table
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TCP_DEDUP_DIALOG_H
#define TCP_DEDUP_DIALOG_H

#include <config.h>

#include <stdint.h>

#include <epan/tap.h>
#include <wsutil/nstime.h>

#include <QDialogButtonBox>
#include <QLineEdit>
#include <QList>
#include <QMap>
#include <QSet>
#include <QString>
#include <QTableWidget>

#include "capture_file.h"
#include "wireshark_dialog.h"

struct _packet_info;
struct epan_dissect;

class TcpDedupDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit TcpDedupDialog(QWidget &parent, CaptureFile &cf);
    ~TcpDedupDialog();

signals:
    void goToPacket(int packet_num);

private:
    struct DedupGroup {
        nstime_t        first_abs_ts  = {0, 0}; /* abs_ts of first occurrence */
        double          delta_secs    = -1.0;    /* secs since previous stream pkt; -1 = first */
        uint32_t        orig_frame    = 0;
        uint32_t        max_count     = 0;
        QString         info;                    /* Info column text from first occurrence */
        QList<uint32_t> frames;
    };

    uint32_t                    stream_;
    QMap<uint32_t, DedupGroup>  groups_;
    nstime_t                    prev_stream_ts_; /* abs_ts of last-seen stream packet */
    bool                        first_stream_pkt_;
    QTableWidget               *table_;
    QDialogButtonBox           *button_box_;
    QLineEdit                  *stream_edit_;

    static void              tapReset(void *tapdata);
    static tap_packet_status tapPacket(void *tapdata, struct _packet_info *pinfo,
                                       struct epan_dissect *edt, const void *data,
                                       tap_flags_t flags);
    static void              tapDraw(void *tapdata);

    void populateTable();

    /* Live-instance registry: tap callbacks check membership before
     * dereferencing tapdata, so a stale listener firing on a destroyed
     * dialog becomes a silent no-op instead of a UAF crash. */
    static QSet<TcpDedupDialog *> live_instances_;
};

#endif // TCP_DEDUP_DIALOG_H
