/* search_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "search_frame.h"
#include <ui_search_frame.h>

#include "file.h"
#include "ui/recent.h"

#include <epan/proto.h>
#include <epan/strutil.h>

#include <wsutil/filesystem.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/regex.h>

#include "main_application.h"
#include "utils/qt_ui_utils.h"

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
    cap_file_(nullptr),
    regex_(nullptr)
{
    sf_ui_->setupUi(this);

#ifdef Q_OS_MAC
    foreach (QWidget *w, findChildren<QWidget *>()) {
        w->setAttribute(Qt::WA_MacSmallSize, true);
    }
#endif

    if (!is_packet_configuration_namespace()) {
        sf_ui_->searchInComboBox->setItemText(0, tr("Event List"));
        sf_ui_->searchInComboBox->setItemText(1, tr("Event Details"));
        sf_ui_->searchInComboBox->setItemText(2, tr("Event Bytes"));
        sf_ui_->searchInComboBox->setToolTip(tr("<html><head/><body>"
                                                "<p>Search the Info column of the event list (summary pane), "
                                                "decoded event display labels (tree view pane) or the "
                                                "ASCII-converted event data (hex view pane).</p>"
                                                "</body></html>"));
    }


    applyRecentSearchSettings();

    updateWidgets();
}

SearchFrame::~SearchFrame()
{
    if (regex_) {
        ws_regex_free(regex_);
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

    sf_ui_->dirCheckBox->setChecked(false);
    if (isHidden()) {
        animatedShow();
        return;
    }
    on_findButton_clicked();
}

void SearchFrame::findPrevious()
{
    if (!cap_file_) return;

    sf_ui_->dirCheckBox->setChecked(true);
    if (isHidden()) {
        animatedShow();
        return;
    }
    on_findButton_clicked();
}

void SearchFrame::setFocus()
{
    sf_ui_->searchLineEdit->setFocus();
    sf_ui_->searchLineEdit->selectAll();
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
    if (event->modifiers() == Qt::NoModifier) {
        if (event->key() == Qt::Key_Escape) {
            on_cancelButton_clicked();
        } else if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) {
            on_findButton_clicked();
        }
    }

    AccordionFrame::keyPressEvent(event);
}

bool SearchFrame::regexCompile()
{
    unsigned flags = 0;
    if (!sf_ui_->caseCheckBox->isChecked()) {
        flags |= WS_REGEX_CASELESS;
    }
    if (sf_ui_->dirCheckBox->isChecked()) {
        flags |= WS_REGEX_ANCHORED;
    }

    if (regex_) {
        ws_regex_free(regex_);
    }

    if (sf_ui_->searchLineEdit->text().isEmpty()) {
        regex_ = nullptr;
        return false;
    }

    char *errmsg = nullptr;
    regex_ = ws_regex_compile_ex(sf_ui_->searchLineEdit->text().toUtf8().constData(), -1,
                         &errmsg, flags);

    if (errmsg != nullptr) {
        regex_error_ = errmsg;
    }

    return regex_ ? true : false;
}

void SearchFrame::applyRecentSearchSettings()
{
    int search_in_idx = in_packet_list_;
    int char_encoding_idx = narrow_and_wide_chars_;
    int search_type_idx = df_search_;

    switch (recent.gui_search_in) {
    case SEARCH_IN_PACKET_LIST:
        search_in_idx = in_packet_list_;
        break;
    case SEARCH_IN_PACKET_DETAILS:
        search_in_idx = in_proto_tree_;
        break;
    case SEARCH_IN_PACKET_BYTES:
        search_in_idx = in_bytes_;
        break;
    default:
        break;
    }

    switch (recent.gui_search_char_set) {
    case SEARCH_CHAR_SET_NARROW_AND_WIDE:
        char_encoding_idx = narrow_and_wide_chars_;
        break;
    case SEARCH_CHAR_SET_NARROW:
        char_encoding_idx = narrow_chars_;
        break;
    case SEARCH_CHAR_SET_WIDE:
        char_encoding_idx = wide_chars_;
        break;
    default:
        break;
    }

    switch (recent.gui_search_type) {
    case SEARCH_TYPE_DISPLAY_FILTER:
        search_type_idx = df_search_;
        break;
    case SEARCH_TYPE_HEX_VALUE:
        search_type_idx = hex_search_;
        break;
    case SEARCH_TYPE_STRING:
        search_type_idx = string_search_;
        break;
    case SEARCH_TYPE_REGEX:
        search_type_idx = regex_search_;
        break;
    default:
        break;
    }

    sf_ui_->searchInComboBox->setCurrentIndex(search_in_idx);
    sf_ui_->charEncodingComboBox->setCurrentIndex(char_encoding_idx);
    sf_ui_->caseCheckBox->setChecked(recent.gui_search_case_sensitive);
    sf_ui_->searchTypeComboBox->setCurrentIndex(search_type_idx);
    sf_ui_->dirCheckBox->setChecked(recent.gui_search_reverse_dir);
    sf_ui_->multipleCheckBox->setChecked(recent.gui_search_multiple_occurs);
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
    // The encoding only is used when searching the raw Packet Bytes
    // (otherwise all strings have already been converted to UTF-8)
    sf_ui_->charEncodingComboBox->setEnabled(search_type == string_search_ && sf_ui_->searchInComboBox->currentIndex() == in_bytes_);

    // We can search for multiple matches in the same frame if we're doing
    // a Proto Tree search or a Frame Bytes search, but not a string/regex
    // search in the Packet List, or a display filter search (since those
    // don't highlight what fields / offsets caused the match.)
    sf_ui_->multipleCheckBox->setEnabled((sf_ui_->searchInComboBox->isEnabled() && sf_ui_->searchInComboBox->currentIndex() != in_packet_list_) || search_type == hex_search_);

    switch (search_type) {
    case df_search_:
        sf_ui_->searchLineEdit->checkDisplayFilter(sf_ui_->searchLineEdit->text());
        break;
    case hex_search_:
        if (sf_ui_->searchLineEdit->text().isEmpty()) {
            sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Invalid);
        } else {
            uint8_t *bytes;
            size_t nbytes;
            bytes = convert_string_to_hex(sf_ui_->searchLineEdit->text().toUtf8().constData(), &nbytes);
            if (bytes == nullptr)
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

void SearchFrame::on_searchInComboBox_currentIndexChanged(int idx)
{
    switch (idx) {
    case in_packet_list_:
        recent.gui_search_in = SEARCH_IN_PACKET_LIST;
        break;
    case in_proto_tree_:
        recent.gui_search_in = SEARCH_IN_PACKET_DETAILS;
        break;
    case in_bytes_:
        recent.gui_search_in = SEARCH_IN_PACKET_BYTES;
        break;
    default:
        break;
    }

    // We only search for multiple occurrences in packet list and bytes
    updateWidgets();
}

void SearchFrame::on_charEncodingComboBox_currentIndexChanged(int idx)
{
    switch (idx) {
    case narrow_and_wide_chars_:
        recent.gui_search_char_set = SEARCH_CHAR_SET_NARROW_AND_WIDE;
        break;
    case narrow_chars_:
        recent.gui_search_char_set = SEARCH_CHAR_SET_NARROW;
        break;
    case wide_chars_:
        recent.gui_search_char_set = SEARCH_CHAR_SET_WIDE;
        break;
    default:
        break;
    }
}

void SearchFrame::on_caseCheckBox_toggled(bool checked)
{
    recent.gui_search_case_sensitive = checked;
    regexCompile();
}

void SearchFrame::on_searchTypeComboBox_currentIndexChanged(int idx)
{
    switch (idx) {
    case df_search_:
        recent.gui_search_type = SEARCH_TYPE_DISPLAY_FILTER;
        break;
    case hex_search_:
        recent.gui_search_type = SEARCH_TYPE_HEX_VALUE;
        break;
    case string_search_:
        recent.gui_search_type = SEARCH_TYPE_STRING;
        break;
    case regex_search_:
        recent.gui_search_type = SEARCH_TYPE_REGEX;
        break;
    default:
        break;
    }

    // Enable completion only for display filter search.
    sf_ui_->searchLineEdit->allowCompletion(idx == df_search_);

    if (idx == df_search_) {
        sf_ui_->searchLineEdit->checkFilter();
    } else {
        sf_ui_->searchLineEdit->setToolTip(QString());
        mainApp->popStatus(MainApplication::FilterSyntax);
    }

    updateWidgets();
}

void SearchFrame::on_searchLineEdit_textChanged(const QString &)
{
    updateWidgets();
}

void SearchFrame::on_dirCheckBox_toggled(bool checked)
{
    recent.gui_search_reverse_dir = checked;
}

void SearchFrame::on_multipleCheckBox_toggled(bool checked)
{
    recent.gui_search_multiple_occurs = checked;
}

void SearchFrame::on_findButton_clicked()
{
    uint8_t *bytes = nullptr;
    size_t nbytes = 0;
    char *string = nullptr;
    dfilter_t *dfp = nullptr;
    bool found_packet = false;
    QString err_string;

    if (!cap_file_) {
        return;
    }

    cap_file_->hex = false;
    cap_file_->string = false;
    cap_file_->case_type = false;
    cap_file_->regex = nullptr;
    cap_file_->packet_data  = false;
    cap_file_->decode_data  = false;
    cap_file_->summary_data = false;
    cap_file_->scs_type = SCS_NARROW_AND_WIDE;
    cap_file_->dir = sf_ui_->dirCheckBox->isChecked() ? SD_BACKWARD : SD_FORWARD;
    bool multiple_occurrences = sf_ui_->multipleCheckBox->isChecked();

    int search_type = sf_ui_->searchTypeComboBox->currentIndex();
    switch (search_type) {
    case df_search_:
        if (!dfilter_compile(sf_ui_->searchLineEdit->text().toUtf8().constData(), &dfp, nullptr)) {
            err_string = tr("Invalid filter.");
            goto search_done;
        }

        if (dfp == nullptr) {
            err_string = tr("That filter doesn't test anything.");
            goto search_done;
        }
        break;
    case hex_search_:
        bytes = convert_string_to_hex(sf_ui_->searchLineEdit->text().toUtf8().constData(), &nbytes);
        if (bytes == nullptr) {
            err_string = tr("That's not a valid hex string.");
            goto search_done;
        }
        cap_file_->hex = true;
        break;
    case string_search_:
    case regex_search_:
        if (sf_ui_->searchLineEdit->text().isEmpty()) {
            err_string = tr("You didn't specify any text for which to search.");
            goto search_done;
        }
        cap_file_->string = true;
        cap_file_->case_type = sf_ui_->caseCheckBox->isChecked() ? false : true;
        cap_file_->regex = (search_type == regex_search_ ? regex_ : nullptr);
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
            goto search_done;
        }
        string = convert_string_case(sf_ui_->searchLineEdit->text().toUtf8().constData(), cap_file_->case_type);
        break;
    default:
        err_string = tr("No valid search type selected. Please report this to the development team.");
        goto search_done;
    }

    switch (sf_ui_->searchInComboBox->currentIndex()) {
    case in_packet_list_:
        cap_file_->summary_data = true;
        break;
    case in_proto_tree_:
        cap_file_->decode_data  = true;
        break;
    case in_bytes_:
        cap_file_->packet_data  = true;
        break;
    default:
        err_string = tr("No valid search area selected. Please report this to the development team.");
        goto search_done;
    }

    g_free(cap_file_->sfilter);
    cap_file_->sfilter = qstring_strdup(sf_ui_->searchLineEdit->text());
    mainApp->popStatus(MainApplication::FileStatus);
    mainApp->pushStatus(MainApplication::FileStatus, tr("Searching for %1…").arg(sf_ui_->searchLineEdit->text()));

    if (cap_file_->hex) {
        /* Hex value in packet data */
        found_packet = cf_find_packet_data(cap_file_, bytes, nbytes, cap_file_->dir, multiple_occurrences);
        g_free(bytes);
        if (!found_packet) {
            /* We didn't find a packet */
            err_string = tr("No packet contained those bytes.");
            goto search_done;
        }
    } else if (cap_file_->string) {
        if (search_type == regex_search_ && !cap_file_->regex) {
            err_string = regex_error_;
            goto search_done;
        }
        if (cap_file_->summary_data) {
            /* String in the Info column of the summary line */
            found_packet = cf_find_packet_summary_line(cap_file_, string, cap_file_->dir);
            g_free(string);
            if (!found_packet) {
                err_string = tr("No packet contained that string in its Info column.");
                goto search_done;
            }
        } else if (cap_file_->decode_data) {
            /* String in the protocol tree headings */
            found_packet = cf_find_packet_protocol_tree(cap_file_, string, cap_file_->dir, multiple_occurrences);
            g_free(string);
            if (!found_packet) {
                err_string = tr("No packet contained that string in its dissected display.");
                goto search_done;
            }
        } else if (cap_file_->packet_data && string) {
            /* String in the ASCII-converted packet data */
            found_packet = cf_find_packet_data(cap_file_, (uint8_t *) string, strlen(string), cap_file_->dir, multiple_occurrences);
            g_free(string);
            if (!found_packet) {
                err_string = tr("No packet contained that string in its converted data.");
                goto search_done;
            }
        }
    } else {
        /* Search via display filter */
        found_packet = cf_find_packet_dfilter(cap_file_, dfp, cap_file_->dir);
        dfilter_free(dfp);
        if (!found_packet) {
            err_string = tr("No packet matched that filter.");
            g_free(bytes);
            goto search_done;
        }
    }

    search_done:
    mainApp->popStatus(MainApplication::FileStatus);
    if (!err_string.isEmpty()) {
        mainApp->pushStatus(MainApplication::FilterSyntax, err_string);
    }
}

void SearchFrame::on_cancelButton_clicked()
{
    mainApp->popStatus(MainApplication::FilterSyntax);
    animatedHide();
}

void SearchFrame::changeEvent(QEvent* event)
{
    if (event)
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
