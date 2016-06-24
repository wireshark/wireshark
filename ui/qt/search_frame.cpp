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
#include <ui_search_frame.h>

#include "file.h"

#include <epan/proto.h>
#include <epan/strutil.h>

#include "wireshark_application.h"
#include <QKeyEvent>
#include <QCheckBox>

enum {
    in_packet_list_,
    in_proto_tree_,
    in_bytes_
};

enum {
    df_search_,
    hex_search_,
    string_search_,
    regex_search_
};

enum {
    narrow_and_wide_chars_,
    narrow_chars_,
    wide_chars_
};

SearchFrame::SearchFrame(QWidget *parent) :
    AccordionFrame(parent),
    sf_ui_(new Ui::SearchFrame),
    cap_file_(NULL),
    regex_(NULL)
{
    sf_ui_->setupUi(this);

#ifdef Q_OS_MAC
    foreach (QWidget *w, findChildren<QWidget *>()) {
        w->setAttribute(Qt::WA_MacSmallSize, true);
    }
#endif
    sf_ui_->searchTypeComboBox->setCurrentIndex(df_search_);
    updateWidgets();
}

SearchFrame::~SearchFrame()
{
    if (regex_) {
        g_regex_unref(regex_);
    }
    delete sf_ui_;
}

void SearchFrame::animatedShow()
{
    AccordionFrame::animatedShow();

    sf_ui_->searchLineEdit->setFocus();
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

void SearchFrame::setFocus()
{
    sf_ui_->searchLineEdit->setFocus();
    cap_file_->dir = SD_FORWARD;
}

void SearchFrame::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
    if (!cf && isVisible()) {
        animatedHide();
    }
    updateWidgets();
}

void SearchFrame::findFrameWithFilter(QString &filter)
{
    animatedShow();
    sf_ui_->searchLineEdit->setText(filter);
    sf_ui_->searchLineEdit->setCursorPosition(0);
    sf_ui_->searchTypeComboBox->setCurrentIndex(df_search_);
    updateWidgets();
    on_findButton_clicked();
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

bool SearchFrame::regexCompile()
{
    int flags = (G_REGEX_OPTIMIZE);
    if (!sf_ui_->caseCheckBox->isChecked()) {
        flags |= G_REGEX_CASELESS;
    }

    if (regex_) {
        g_regex_unref(regex_);
    }

    if (sf_ui_->searchLineEdit->text().isEmpty()) {
        regex_ = NULL;
        return false;
    }

    GError *g_error = NULL;
    regex_ = g_regex_new(sf_ui_->searchLineEdit->text().toUtf8().constData(),
                         (GRegexCompileFlags)flags, (GRegexMatchFlags) 0, &g_error);
    if (g_error) {
        regex_error_ = g_error->message;
        g_error_free(g_error);
    }

    return regex_ ? true : false;
}

void SearchFrame::updateWidgets()
{
    if (cap_file_) {
        setEnabled(true);
    } else {
        setEnabled(false);
        return;
    }

    int search_type = sf_ui_->searchTypeComboBox->currentIndex();
    sf_ui_->searchInComboBox->setEnabled(search_type == string_search_ || search_type == regex_search_);
    sf_ui_->caseCheckBox->setEnabled(search_type == string_search_ || search_type == regex_search_);
    sf_ui_->charEncodingComboBox->setEnabled(search_type == string_search_);

    switch (search_type) {
    case df_search_:
        sf_ui_->searchLineEdit->checkDisplayFilter(sf_ui_->searchLineEdit->text());
        break;
    case hex_search_:
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
    case string_search_:
        if (sf_ui_->searchLineEdit->text().isEmpty()) {
            sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Invalid);
        } else {
            sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Valid);
        }
        break;
    case regex_search_:
        if (regexCompile()) {
            sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Valid);
        } else {
            sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Invalid);
        }
        break;
    default:
        // currentIndex is probably -1. Nothing is selected or list is empty.
        return;
    }

    if (sf_ui_->searchLineEdit->text().isEmpty() || sf_ui_->searchLineEdit->syntaxState() == SyntaxLineEdit::Invalid) {
        sf_ui_->findButton->setEnabled(false);
    } else {
        sf_ui_->findButton->setEnabled(true);
    }
}

void SearchFrame::on_caseCheckBox_toggled(bool)
{
    regexCompile();
}

void SearchFrame::on_searchTypeComboBox_currentIndexChanged(int)
{
    updateWidgets();
}

void SearchFrame::on_searchLineEdit_textChanged(const QString &)
{
    updateWidgets();
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
    cap_file_->regex = NULL;
    cap_file_->packet_data  = FALSE;
    cap_file_->decode_data  = FALSE;
    cap_file_->summary_data = FALSE;
    cap_file_->scs_type = SCS_NARROW_AND_WIDE;

    int search_type = sf_ui_->searchTypeComboBox->currentIndex();
    switch (search_type) {
    case df_search_:
        if (!dfilter_compile(sf_ui_->searchLineEdit->text().toUtf8().constData(), &dfp, NULL)) {
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
    case hex_search_:
        bytes = convert_string_to_hex(sf_ui_->searchLineEdit->text().toUtf8().constData(), &nbytes);
        if (bytes == NULL) {
            err_string = tr("That's not a valid hex string.");
            emit pushFilterSyntaxStatus(err_string);
            return;
        }
        cap_file_->hex = TRUE;
        break;
    case string_search_:
    case regex_search_:
        if (sf_ui_->searchLineEdit->text().isEmpty()) {
            err_string = tr("You didn't specify any text for which to search.");
            emit pushFilterSyntaxStatus(err_string);
            return;
        }
        cap_file_->string = TRUE;
        cap_file_->case_type = sf_ui_->caseCheckBox->isChecked() ? FALSE : TRUE;
        cap_file_->regex = (search_type == regex_search_ ? regex_ : NULL);
        switch (sf_ui_->charEncodingComboBox->currentIndex()) {
        case narrow_and_wide_chars_:
            cap_file_->scs_type = SCS_NARROW_AND_WIDE;
            break;
        case narrow_chars_:
            cap_file_->scs_type = SCS_NARROW;
            break;
        case wide_chars_:
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
    case in_packet_list_:
        cap_file_->summary_data = TRUE;
        break;
    case in_proto_tree_:
        cap_file_->decode_data  = TRUE;
        break;
    case in_bytes_:
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
        if (search_type == regex_search_ && !cap_file_->regex) {
            emit pushFilterSyntaxStatus(regex_error_);
            return;
        }
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

void SearchFrame::changeEvent(QEvent* event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            sf_ui_->retranslateUi(this);
            break;
        default:
            break;
        }
    }
    AccordionFrame::changeEvent(event);
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
