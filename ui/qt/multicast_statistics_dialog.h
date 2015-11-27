/* multicast_statistics_dialog.h
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

#ifndef MULTICASTSTATISTICSDIALOG_H
#define MULTICASTSTATISTICSDIALOG_H

#include "tap_parameter_dialog.h"
#include "ui/mcast_stream.h"

class SyntaxLineEdit;

class MulticastStatisticsDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    MulticastStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter = NULL);
    ~MulticastStatisticsDialog();

private:
    struct _mcaststream_tapinfo *tapinfo_;
    SyntaxLineEdit *burst_measurement_interval_le_;
    SyntaxLineEdit *burst_alarm_threshold_le_;
    SyntaxLineEdit *buffer_alarm_threshold_le_;
    SyntaxLineEdit *stream_empty_speed_le_;
    SyntaxLineEdit *total_empty_speed_le_;
    QList<QWidget *> line_edits_;

    // Callbacks for register_tap_listener
    static void tapReset(mcaststream_tapinfo_t *tapinfo);
    static void tapDraw(mcaststream_tapinfo_t *tapinfo);

    virtual const QString filterExpression();

private slots:
    void updateWidgets();
    void updateMulticastParameters();
    virtual void fillTree();
    void captureFileClosing();
};

#endif // MULTICASTSTATISTICSDIALOG_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
