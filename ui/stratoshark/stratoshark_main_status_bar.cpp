/* stratoshark_main_status_bar.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "stratoshark_main_status_bar.h"
#include <ui/qt/main_window.h>
#include <wsutil/utf8_entities.h>
#include "file.h"

StratosharkMainStatusBar::StratosharkMainStatusBar(QWidget *parent) :
    MainStatusBar(parent)
{
}

StratosharkMainStatusBar::~StratosharkMainStatusBar()
{
}

void StratosharkMainStatusBar::showCaptureStatistics()
{
    QString packets_str;

    QList<int> rows;
    MainWindow * mw = mainApp->mainWindow();
    if (mw) {
        rows = mw->selectedRows(true);
    }

#ifdef HAVE_LIBPCAP
    if (cap_file_) {
        /* Do we have any packets? */
        if (!cs_fixed_) {
            cs_count_ = cap_file_->count;
        }
        if (cs_count_ > 0) {
            if (prefs.gui_show_selected_packet && rows.count() == 1) {
                packets_str.append(tr("Selected Event: %1 %2 ")
                                        .arg(rows.at(0))
                                        .arg(UTF8_MIDDLE_DOT));
            }

            packets_str.append(tr("Events: %1").arg(cs_count_));

            if (cap_file_->dfilter) {
                packets_str.append(tr(" %1 Displayed: %2 (%3%)")
                                       .arg(UTF8_MIDDLE_DOT)
                                       .arg(cap_file_->displayed_count)
                                       .arg((100.0*cap_file_->displayed_count)/cs_count_, 0, 'f', 1));
            }
            if (rows.count() > 1) {
                packets_str.append(tr(" %1 Selected: %2 (%3%)")
                                   .arg(UTF8_MIDDLE_DOT)
                                   .arg(rows.count())
                                   .arg((100.0*rows.count())/cs_count_, 0, 'f', 1));
            }
            if (cap_file_->marked_count > 0) {
                packets_str.append(tr(" %1 Marked: %2 (%3%)")
                                   .arg(UTF8_MIDDLE_DOT)
                                   .arg(cap_file_->marked_count)
                                   .arg((100.0*cap_file_->marked_count)/cs_count_, 0, 'f', 1));
            }
            if (cap_file_->drops_known) {
                packets_str.append(tr(" %1 Dropped: %2 (%3%)")
                                   .arg(UTF8_MIDDLE_DOT)
                                   .arg(cap_file_->drops)
                                   .arg((100.0*cap_file_->drops)/(cs_count_ + cap_file_->drops), 0, 'f', 1));
            }
            if (cap_file_->ignored_count > 0) {
                packets_str.append(tr(" %1 Ignored: %2 (%3%)")
                                   .arg(UTF8_MIDDLE_DOT)
                                   .arg(cap_file_->ignored_count)
                                   .arg((100.0*cap_file_->ignored_count)/cs_count_, 0, 'f', 1));
            }
            if (cap_file_->packet_comment_count > 0) {
                packets_str.append(tr(" %1 Comments: %2")
                    .arg(UTF8_MIDDLE_DOT)
                    .arg(cap_file_->packet_comment_count));
            }
            if (prefs.gui_show_file_load_time && !cap_file_->is_tempfile) {
                /* Loading an existing file */
                unsigned long computed_elapsed = cf_get_computed_elapsed(cap_file_);
                packets_str.append(tr(" %1  Load time: %2:%3.%4")
                                   .arg(UTF8_MIDDLE_DOT)
                                   .arg(computed_elapsed/60000, 2, 10, QLatin1Char('0'))
                                   .arg(computed_elapsed%60000/1000, 2, 10, QLatin1Char('0'))
                                   .arg(computed_elapsed%1000, 3, 10, QLatin1Char('0')));
            }
        }
    } else if (cs_fixed_ && cs_count_ > 0) {
        /* There shouldn't be any rows without a cap_file_ but this is benign */
        if (prefs.gui_show_selected_packet && rows.count() == 1) {
            packets_str.append(tr("Selected Event: %1 %2 ")
                                    .arg(rows.at(0))
                                    .arg(UTF8_MIDDLE_DOT));
        }
        packets_str.append(tr("Events: %1").arg(cs_count_));
    }
#endif // HAVE_LIBPCAP

    if (packets_str.isEmpty()) {
        packets_str = tr("No Events");
    }

    popGenericStatus(STATUS_CTX_MAIN);
    pushGenericStatus(STATUS_CTX_MAIN, packets_str);
}
