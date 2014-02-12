/* search_frame.cpp
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

#include "search_frame.h"
#include "ui_search_frame.h"

#include <epan/proto.h>
#include <epan/strutil.h>

#include "wireshark_application.h"
#include <QKeyEvent>
#include <QCheckBox>

const int in_packet_list = 0;
const int in_proto_tree = 1;
const int in_bytes = 2;

const int df_search = 0;
const int hex_search = 1;
const int string_search = 2;

const int narrow_and_wide_chars = 0;
const int narrow_chars = 1;
const int wide_chars = 2;

SearchFrame::SearchFrame(QWidget *parent) :
    AccordionFrame(parent),
    sf_ui_(new Ui::SearchFrame),
    cap_file_(NULL)
{
    sf_ui_->setupUi(this);

#ifdef Q_OS_MAC
    foreach (QWidget *w, findChildren<QWidget *>()) {
        w->setAttribute(Qt::WA_MacSmallSize, true);
    }
#endif
    sf_ui_->searchTypeComboBox->setCurrentIndex(0);
    enableWidgets();
}

SearchFrame::~SearchFrame()
{
    delete sf_ui_;
}

void SearchFrame::animatedShow()
{
    sf_ui_->searchLineEdit->setFocus();

    AccordionFrame::animatedShow();
}

void SearchFrame::findNext()
{
    if (!cap_file_) return;

    cap_file_->dir = SD_FORWARD;
    if (isHidden()) {
        animatedShow();
        return;
    }
    on_findButton_clicked();
}

void SearchFrame::findPrevious()
{
    if (!cap_file_) return;

    cap_file_->dir = SD_BACKWARD;
    if (isHidden()) {
        animatedShow();
        return;
    }
    on_findButton_clicked();
}

void SearchFrame::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
    if (!cf && isVisible()) {
        animatedHide();
    }
    enableWidgets();
}

void SearchFrame::findFrameWithFilter(QString &filter)
{
    animatedShow();
    sf_ui_->searchLineEdit->setText(filter);
    sf_ui_->searchTypeComboBox->setCurrentIndex(0);
    enableWidgets();
}

void SearchFrame::keyPressEvent(QKeyEvent *event)
{
    if (wsApp->focusWidget() == sf_ui_->searchLineEdit) {
        if (event->modifiers() == Qt::NoModifier) {
            if (event->key() == Qt::Key_Escape) {
                on_cancelButton_clicked();
            } else if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) {
                on_findButton_clicked();
            }
        }
        return; // searchLineEdit didn't want it and we don't either.
    }
}

void SearchFrame::enableWidgets()
{
    if (cap_file_) {
        setEnabled(true);
    } else {
        setEnabled(false);
        return;
    }

    bool enable = sf_ui_->searchTypeComboBox->currentIndex() == string_search;
    sf_ui_->searchInComboBox->setEnabled(enable);
    sf_ui_->caseCheckBox->setEnabled(enable);
    sf_ui_->charEncodingComboBox->setEnabled(enable);

    switch (sf_ui_->searchTypeComboBox->currentIndex()) {
    case df_search:
        sf_ui_->searchLineEdit->checkDisplayFilter(sf_ui_->searchLineEdit->text());
        break;
    case hex_search:
        if (sf_ui_->searchLineEdit->text().isEmpty()) {
            sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Invalid);
        } else {
            guint8 *bytes;
            size_t nbytes;
            bytes = convert_string_to_hex(sf_ui_->searchLineEdit->text().toUtf8().constData(), &nbytes);
            if (bytes == NULL)
                sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Invalid);
            else {
              g_free(bytes);
              sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Valid);
            }
        }
        break;
    case string_search:
        if (sf_ui_->searchLineEdit->text().isEmpty()) {
            sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Invalid);
        } else {
            sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Valid);
        }
        break;
    default:
        QString err_string = tr("No valid search type selected. Please report this to the development team.");
        emit pushFilterSyntaxStatus(err_string);
        return;
    }

    if (sf_ui_->searchLineEdit->text().isEmpty() || sf_ui_->searchLineEdit->syntaxState() == SyntaxLineEdit::Invalid) {
        sf_ui_->findButton->setEnabled(false);
    } else {
        sf_ui_->findButton->setEnabled(true);
    }
}

void SearchFrame::on_searchTypeComboBox_currentIndexChanged(int index)
{
    Q_UNUSED(index);
    enableWidgets();
}

void SearchFrame::on_searchLineEdit_textChanged(const QString &search_string)
{
    Q_UNUSED(search_string);
    enableWidgets();
}

void SearchFrame::on_findButton_clicked()
{
    guint8 *bytes = NULL;
    size_t nbytes;
    char *string = NULL;
    dfilter_t *dfp;
    gboolean found_packet = FALSE;
    QString err_string;

    if (!cap_file_) {
        return;
    }

    cap_file_->hex = FALSE;
    cap_file_->string = FALSE;
    cap_file_->case_type = FALSE;
    cap_file_->packet_data  = FALSE;
    cap_file_->decode_data  = FALSE;
    cap_file_->summary_data = FALSE;
    cap_file_->scs_type = SCS_NARROW_AND_WIDE;

    switch (sf_ui_->searchTypeComboBox->currentIndex()) {
    case df_search:
        if (!dfilter_compile(sf_ui_->searchLineEdit->text().toUtf8().constData(), &dfp)) {
            err_string = tr("Invalid filter.");
            emit pushFilterSyntaxStatus(err_string);
            return;
        }

        if (dfp == NULL) {
            err_string = tr("That filter doesn't test anything.");
            emit pushFilterSyntaxStatus(err_string);
            return;
        }
        break;
    case hex_search:
        bytes = convert_string_to_hex(sf_ui_->searchLineEdit->text().toUtf8().constData(), &nbytes);
        if (bytes == NULL) {
            err_string = tr("That's not a valid hex string.");
            emit pushFilterSyntaxStatus(err_string);
            return;
        }
        cap_file_->hex = TRUE;
        break;
    case string_search:
        if (sf_ui_->searchLineEdit->text().isEmpty()) {
            err_string = tr("You didn't specify any text for which to search.");
            emit pushFilterSyntaxStatus(err_string);
            return;
        }
        cap_file_->string = TRUE;
        cap_file_->case_type = sf_ui_->caseCheckBox->isChecked() ? FALSE : TRUE;
        switch (sf_ui_->charEncodingComboBox->currentIndex()) {
        case narrow_and_wide_chars:
            cap_file_->scs_type = SCS_NARROW_AND_WIDE;
            break;
        case narrow_chars:
            cap_file_->scs_type = SCS_NARROW;
            break;
        case wide_chars:
            cap_file_->scs_type = SCS_WIDE;
            break;
        default:
            err_string = tr("No valid character set selected. Please report this to the development team.");
            emit pushFilterSyntaxStatus(err_string);
            return;
        }
        string = convert_string_case(sf_ui_->searchLineEdit->text().toUtf8().constData(), cap_file_->case_type);
        break;
    default:
        err_string = tr("No valid search type selected. Please report this to the development team.");
        emit pushFilterSyntaxStatus(err_string);
        return;
    }

    switch (sf_ui_->searchInComboBox->currentIndex()) {
    case in_packet_list:
        cap_file_->summary_data = TRUE;
        break;
    case in_proto_tree:
        cap_file_->decode_data  = TRUE;
        break;
    case in_bytes:
        cap_file_->packet_data  = TRUE;
        break;
    default:
        err_string = tr("No valid search area selected. Please report this to the development team.");
        emit pushFilterSyntaxStatus(err_string);
        return;
    }

    g_free(cap_file_->sfilter);
    cap_file_->sfilter = g_strdup(sf_ui_->searchLineEdit->text().toUtf8().constData());

    if (cap_file_->hex) {
        /* Hex value in packet data */
        found_packet = cf_find_packet_data(cap_file_, bytes, nbytes, cap_file_->dir);
        g_free(bytes);
        if (!found_packet) {
            /* We didn't find a packet */
            err_string = tr("No packet contained those bytes.");
            emit pushFilterSyntaxStatus(err_string);
            return;
        }
    } else if (cap_file_->string) {
        if (cap_file_->summary_data) {
            /* String in the Info column of the summary line */
            found_packet = cf_find_packet_summary_line(cap_file_, string, cap_file_->dir);
            g_free(string);
            if (!found_packet) {
                err_string = tr("No packet contained that string in its Info column.");
                emit pushFilterSyntaxStatus(err_string);
                return;
            }
        } else if (cap_file_->decode_data) {
            /* String in the protocol tree headings */
            found_packet = cf_find_packet_protocol_tree(cap_file_, string, cap_file_->dir);
            g_free(string);
            if (!found_packet) {
                err_string = tr("No packet contained that string in its dissected display.");
                emit pushFilterSyntaxStatus(err_string);
                return;
            }
        } else if (cap_file_->packet_data && string) {
            /* String in the ASCII-converted packet data */
            found_packet = cf_find_packet_data(cap_file_, (guint8 *) string, strlen(string), cap_file_->dir);
            g_free(string);
            if (!found_packet) {
                err_string = tr("No packet contained that string in its converted data.");
                emit pushFilterSyntaxStatus(err_string);
                return;
            }
        }
    } else {
        /* Search via display filter */
        found_packet = cf_find_packet_dfilter(cap_file_, dfp, cap_file_->dir);
        dfilter_free(dfp);
        if (!found_packet) {
            err_string = tr("No packet matched that filter.");
            emit pushFilterSyntaxStatus(err_string);
            g_free(bytes);
            return;
        }
    }
}

void SearchFrame::on_cancelButton_clicked()
{
    animatedHide();
}

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
