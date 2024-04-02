/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FOLLOW_STREAM_DIALOG_H
#define FOLLOW_STREAM_DIALOG_H

#include <config.h>

#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "file.h"

#include "epan/follow.h"

#include "wireshark_dialog.h"

#include <QFile>
#include <QMap>
#include <QPushButton>
#include <QTextCodec>

namespace Ui {
class FollowStreamDialog;
}

class FollowStreamDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit FollowStreamDialog(QWidget &parent, CaptureFile &cf, int proto_id);
    ~FollowStreamDialog();

    void addCodecs(const QMap<QString, QTextCodec *> &codecMap);
    bool follow(QString previous_filter = QString(), bool use_stream_index = false, unsigned stream_num = 0, unsigned sub_stream_num = 0);

protected:
    bool eventFilter(QObject *obj, QEvent *event);
    void keyPressEvent(QKeyEvent *event);
    void captureFileClosed();

private slots:
    void cbCharsetCurrentIndexChanged(int idx);
    void deltaComboBoxCurrentIndexChanged(int idx);
    void cbDirectionsCurrentIndexChanged(int idx);
    void bFindClicked();
    void leFindReturnPressed();

    void helpButton();
    void backButton();
    void close();
    void filterOut();
    void useRegexFind(bool use_regex);
    void findText(bool go_back = true);
    void saveAs();
    void printStream();
    void fillHintLabel(int pkt = 0);
    void goToPacketForTextPos(int pkt = 0);

    void streamNumberSpinBoxValueChanged(int stream_num);
    void subStreamNumberSpinBoxValueChanged(int sub_stream_num);

    void buttonBoxRejected();

signals:
    void updateFilter(QString filter, bool force);
    void goToPacket(int packet_num);

private:
    // Callback for register_tap_listener
    static void resetStream(void *tapData);

    void removeStreamControls();
    void resetStream(void);
    void updateWidgets(bool follow_in_progress);
    void updateWidgets() { updateWidgets(false); } // Needed for WiresharkDialog?
    void showBuffer(QByteArray &buffer, size_t nchars, bool is_from_server,
                uint32_t packet_num, nstime_t abs_ts, uint32_t *global_pos);
    void readStream();
    void readFollowStream();

    void followStream();
    void addText(QString text, bool is_from_server, uint32_t packet_num, bool colorize = true);

    Ui::FollowStreamDialog  *ui;

    QPushButton             *b_filter_out_;
    QPushButton             *b_find_;
    QPushButton             *b_print_;
    QPushButton             *b_save_;
    QPushButton             *b_back_;

    follow_info_t           follow_info_;
    register_follow_t*      follower_;
    QString                 previous_filter_;
    QString                 filter_out_filter_;
    QString                 output_filter_;
    int                     client_buffer_count_;
    int                     server_buffer_count_;
    int                     client_packet_count_;
    int                     server_packet_count_;
    uint32_t                last_packet_;
    bool                    last_from_server_;
    nstime_t                last_ts_;
    int                     turns_;

    bool                    use_regex_find_;

    bool                    terminating_;

    int                     previous_sub_stream_num_;
};

#endif // FOLLOW_STREAM_DIALOG_H
