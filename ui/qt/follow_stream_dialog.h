/* follow_stream_dialog.h
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

#include <glib.h>

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

namespace Ui {
class FollowStreamDialog;
}

class FollowStreamDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit FollowStreamDialog(QWidget &parent, CaptureFile &cf, follow_type_t type = FOLLOW_TCP);
    ~FollowStreamDialog();

    void addCodecs(const QMap<QString, QTextCodec *> &codecMap);
    bool follow(QString previous_filter = QString(), bool use_stream_index = false, guint stream_num = 0, guint sub_stream_num = 0);

public slots:
    void captureEvent(CaptureEvent e);

protected:
    bool eventFilter(QObject *obj, QEvent *event);
    void keyPressEvent(QKeyEvent *event);

private slots:
    void on_cbCharset_currentIndexChanged(int idx);
    void on_cbDirections_currentIndexChanged(int idx);
    void on_bFind_clicked();
    void on_leFind_returnPressed();

    void helpButton();
    void backButton();
    void close();
    void filterOut();
    void useRegexFind(bool use_regex);
    void findText(bool go_back = true);
    void saveAs();
    void printStream();
    void fillHintLabel(int text_pos);
    void goToPacketForTextPos(int text_pos);

    void on_streamNumberSpinBox_valueChanged(int stream_num);
    void on_subStreamNumberSpinBox_valueChanged(int sub_stream_num);

    void on_buttonBox_rejected();

signals:
    void updateFilter(QString filter, bool force);
    void goToPacket(int packet_num);

private:
    void removeStreamControls();
    void resetStream(void);
    void updateWidgets(bool follow_in_progress);
    void updateWidgets() { updateWidgets(false); } // Needed for WiresharkDialog?
    frs_return_t
    showBuffer(char *buffer, size_t nchars, gboolean is_from_server,
                guint32 packet_num, guint32 *global_pos);

    frs_return_t readStream();
    frs_return_t readFollowStream();
    frs_return_t readSslStream();

    void followStream();
    void addText(QString text, gboolean is_from_server, guint32 packet_num);

    Ui::FollowStreamDialog  *ui;

    QPushButton             *b_filter_out_;
    QPushButton             *b_find_;
    QPushButton             *b_print_;
    QPushButton             *b_save_;
    QPushButton             *b_back_;

    follow_type_t           follow_type_;
    follow_info_t           follow_info_;
    register_follow_t*      follower_;
    show_type_t             show_type_;
    QString                 data_out_filename_;
    static const int        max_document_length_;
    bool                    truncated_;
    QString                 previous_filter_;
    QString                 filter_out_filter_;
    QString                 output_filter_;
    int                     client_buffer_count_;
    int                     server_buffer_count_;
    int                     client_packet_count_;
    int                     server_packet_count_;
    guint32                 last_packet_;
    gboolean                last_from_server_;
    int                     turns_;
    QMap<int,guint32>       text_pos_to_packet_;

    bool                    use_regex_find_;

    bool                    terminating_;

    int                     previous_sub_stream_num_;
};

#endif // FOLLOW_STREAM_DIALOG_H

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
