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

#include <wsutil/utf8_entities.h>
#include <wsutil/regex.h>
#include "main_window.h"
#include "main_application.h"
#include "main_status_bar.h"
#include "utils/qt_ui_utils.h"

#include <QKeyEvent>
#include <QCheckBox>
#include <QApplication>
#include <QSignalBlocker>
#include <QCompleter>
#include "in_packet_search.h"

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
    in_packet_search_(nullptr),
    in_packet_debounce_timer_(new QTimer(this)),
    sf_ui_(new Ui::SearchFrame),
    cap_file_(nullptr),
    regex_(nullptr),
    packet_selected_(false)
{
    sf_ui_->setupUi(this);
    sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Invalid);

    connect(sf_ui_->findButton, &QPushButton::clicked, this, &SearchFrame::executeSearch);
    connect(sf_ui_->cancelButton, &QPushButton::clicked, this, &SearchFrame::cancelSearch);
    connect(sf_ui_->searchLineEdit, &QLineEdit::returnPressed, this, &SearchFrame::executeSearch);

    if (sf_ui_->searchLineEdit->completer()) {
        connect(sf_ui_->searchLineEdit->completer(), QOverload<const QString &>::of(&QCompleter::activated),
                [this](const QString &s){
                    sf_ui_->searchLineEdit->setText(s);
                    executeSearch();
                });
    }

#ifdef Q_OS_MAC
    foreach (QWidget *w, findChildren<QWidget *>()) {
        w->setAttribute(Qt::WA_MacSmallSize, true);
    }
#endif

    applyRecentSearchSettings();

    connect(qApp, &QApplication::focusChanged, this, &SearchFrame::onApplicationFocusChanged);
    connect(sf_ui_->inPacketCheckBox, &QCheckBox::toggled, this, &SearchFrame::inPacketCheckBoxToggled);

    full_search_type_tooltip_ = sf_ui_->searchTypeComboBox->toolTip();
    in_packet_string_tooltip_ = tr("Search for a plain text string in the current packet details tree (e.g. My String).");
    in_packet_regex_tooltip_ = tr("Search using a regular expression in the current packet details tree (e.g. colou?r).");

    connect(sf_ui_->searchTypeComboBox, QOverload<int>::of(&QComboBox::highlighted),
            this, &SearchFrame::updateSearchTypeToolTip);

    sf_ui_->inPacketCheckBox->setToolTip(tr("Search the selected packet details tree"));

    sf_ui_->searchLineEdit->installEventFilter(this);
    sf_ui_->findButton->installEventFilter(this);
    sf_ui_->inPacketCheckBox->installEventFilter(this);

    /* Enter is handled in the search field event filter; don't auto-click Find. */
    sf_ui_->findButton->setAutoDefault(false);

    in_packet_debounce_timer_->setSingleShot(true);
    in_packet_debounce_timer_->setInterval(50);
    connect(in_packet_debounce_timer_, &QTimer::timeout,
            this, &SearchFrame::executeInPacketSearch);

    updateWidgets();
}

SearchFrame::~SearchFrame()
{
    if (regex_) {
        ws_regex_free(regex_);
    }
    delete sf_ui_;
}

QComboBox* SearchFrame::searchInComboBox() const
{
    return sf_ui_->searchInComboBox;
}

void SearchFrame::setInPacketSearch(InPacketSearch *search)
{
    in_packet_search_ = search;
    if (in_packet_search_) {
        connect(in_packet_search_, &InPacketSearch::matchesChanged,
                this, &SearchFrame::updateWidgets, Qt::UniqueConnection);
    }
}

void SearchFrame::setInPacketMode(bool enabled)
{
    if (enabled && !packet_selected_) {
        return;
    }
    {
        QSignalBlocker blocker(sf_ui_->inPacketCheckBox);
        sf_ui_->inPacketCheckBox->setChecked(enabled);
    }
    inPacketCheckBoxToggled(enabled);
}

void SearchFrame::setPacketSelected(bool selected)
{
    if (packet_selected_ == selected) {
        return;
    }
    packet_selected_ = selected;

    if (!packet_selected_ && sf_ui_->inPacketCheckBox->isChecked()) {
        QSignalBlocker blocker(sf_ui_->inPacketCheckBox);
        sf_ui_->inPacketCheckBox->setChecked(false);
        inPacketCheckBoxToggled(false);
    }
    updateWidgets();
}

bool SearchFrame::inPacketMode() const
{
    return sf_ui_->inPacketCheckBox->isChecked();
}

void SearchFrame::animatedShow()
{
    AccordionFrame::animatedShow();

    sf_ui_->searchLineEdit->setFocus();
}

void SearchFrame::findNext()
{
    if (!cap_file_) return;

    if (sf_ui_->inPacketCheckBox->isChecked() && in_packet_search_) {
        if (isHidden()) {
            animatedShow();
            return;
        }
        if (in_packet_search_->matchCount() == 0 && !sf_ui_->searchLineEdit->text().trimmed().isEmpty()) {
            executeInPacketSearch();
            return;
        }
        in_packet_search_->findNext();
        return;
    }

    sf_ui_->dirCheckBox->setChecked(false);
    if (isHidden()) {
        animatedShow();
        return;
    }
    executeSearch();
}

void SearchFrame::findPrevious()
{
    if (!cap_file_) return;

    if (sf_ui_->inPacketCheckBox->isChecked() && in_packet_search_) {
        if (isHidden()) {
            animatedShow();
            return;
        }
        if (in_packet_search_->matchCount() == 0 && !sf_ui_->searchLineEdit->text().trimmed().isEmpty()) {
            executeInPacketSearch();
            return;
        }
        in_packet_search_->findPrevious();
        return;
    }

    sf_ui_->dirCheckBox->setChecked(true);
    if (isHidden()) {
        animatedShow();
        return;
    }
    executeSearch();
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

void SearchFrame::refreshWidgets()
{
    updateWidgets();
}

void SearchFrame::findFrameWithFilter(QString &filter)
{
    animatedShow();
    sf_ui_->searchLineEdit->setText(filter);
    sf_ui_->searchLineEdit->setCursorPosition(0);
    sf_ui_->searchTypeComboBox->setCurrentIndex(df_search_);
    updateWidgets();
    executeSearch();
}

bool SearchFrame::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress
            && sf_ui_->inPacketCheckBox->isChecked() && in_packet_search_) {
        QKeyEvent *ke = static_cast<QKeyEvent *>(event);
        if (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter) {
            if (obj == sf_ui_->searchLineEdit || obj == sf_ui_->findButton
                    || obj == sf_ui_->inPacketCheckBox) {
                advanceInPacketSearch(ke->modifiers() & Qt::ShiftModifier);
                return true;
            }
        }
    }
    return AccordionFrame::eventFilter(obj, event);
}

void SearchFrame::keyPressEvent(QKeyEvent *event)
{
    if ((event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return)
            && sf_ui_->inPacketCheckBox->isChecked() && in_packet_search_) {
        advanceInPacketSearch(event->modifiers() & Qt::ShiftModifier);
        event->accept();
        return;
    }
    if (event->modifiers() == Qt::NoModifier) {
        if (event->key() == Qt::Key_Escape) {
            cancelSearch();
        } else if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) {
            executeSearch();
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

int SearchFrame::searchTypeIndex() const
{
    const QComboBox *cb = sf_ui_->searchTypeComboBox;
    const int idx = cb->currentIndex();
    if (cb->count() == 2) {
        return idx == 1 ? regex_search_ : string_search_;
    }
    return idx;
}

void SearchFrame::configureSearchTypeComboBox(bool in_packet_mode)
{
    QComboBox *cb = sf_ui_->searchTypeComboBox;
    QSignalBlocker blocker(cb);

    int search_type = searchTypeIndex();
    if (in_packet_mode && cb->count() != 2
            && search_type != string_search_ && search_type != regex_search_) {
        search_type = string_search_;
    }

    cb->clear();
    if (in_packet_mode) {
        cb->addItem(tr("String"));
        cb->setItemData(0, in_packet_string_tooltip_, Qt::ToolTipRole);
        cb->addItem(tr("Regular Expression"));
        cb->setItemData(1, in_packet_regex_tooltip_, Qt::ToolTipRole);
        cb->setCurrentIndex(search_type == regex_search_ ? 1 : 0);
        updateSearchTypeToolTip(cb->currentIndex());
    } else {
        cb->addItem(tr("Display filter"));
        cb->addItem(tr("Hex value"));
        cb->addItem(tr("String"));
        cb->addItem(tr("Regular Expression"));
        cb->setToolTip(full_search_type_tooltip_);
        if (search_type >= df_search_ && search_type <= regex_search_) {
            cb->setCurrentIndex(search_type);
        } else {
            cb->setCurrentIndex(df_search_);
        }
    }
}

void SearchFrame::updateSearchTypeToolTip(int combo_index)
{
    if (sf_ui_->searchTypeComboBox->count() != 2) {
        sf_ui_->searchTypeComboBox->setToolTip(full_search_type_tooltip_);
        return;
    }
    if (combo_index < 0) {
        combo_index = sf_ui_->searchTypeComboBox->currentIndex();
    }
    if (combo_index == 1) {
        sf_ui_->searchTypeComboBox->setToolTip(in_packet_regex_tooltip_);
    } else if (combo_index == 0) {
        sf_ui_->searchTypeComboBox->setToolTip(in_packet_string_tooltip_);
    }
}

void SearchFrame::updateWidgets()
{
    if (cap_file_) {
        setEnabled(true);
    } else {
        setEnabled(false);
        return;
    }

    int search_type = searchTypeIndex();
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

    // In-packet search needs a dissected packet in the details tree.
    sf_ui_->inPacketCheckBox->setEnabled(packet_selected_);

    const bool in_packet_mode = sf_ui_->inPacketCheckBox->isChecked();
    if (in_packet_mode) {
        sf_ui_->searchInComboBox->setEnabled(false);
        sf_ui_->charEncodingComboBox->setEnabled(false);
        sf_ui_->multipleCheckBox->setEnabled(false);
        sf_ui_->dirCheckBox->setEnabled(false);

        updateInPacketSearchSyntax();
        bool can_find = !sf_ui_->searchLineEdit->text().trimmed().isEmpty();
        if (can_find && search_type == regex_search_) {
            can_find = regexCompile();
        }
        sf_ui_->findButton->setEnabled(can_find);
        updateInPacketFindCounter();
        return;
    }

    sf_ui_->dirCheckBox->setEnabled(true);

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
    updateInPacketFindCounter();
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
    if (sf_ui_->inPacketCheckBox->isChecked() && in_packet_search_
            && !sf_ui_->searchLineEdit->text().trimmed().isEmpty()) {
        in_packet_debounce_timer_->start();
    }
    updateWidgets();
}

void SearchFrame::on_searchTypeComboBox_currentIndexChanged(int idx)
{
    const int search_type = searchTypeIndex();

    switch (search_type) {
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
    sf_ui_->searchLineEdit->allowCompletion(search_type == df_search_);

    if (search_type == df_search_) {
        sf_ui_->searchLineEdit->setPlaceholderText(DisplayFilterEdit::tr("Enter a display filter %1").arg(UTF8_HORIZONTAL_ELLIPSIS));
        sf_ui_->searchLineEdit->checkFilter();
    } else {
        sf_ui_->searchLineEdit->setPlaceholderText(QString());
        sf_ui_->searchLineEdit->setToolTip(QString());
        mainApp->popStatus(MainApplication::FilterSyntax);
    }

    if (sf_ui_->inPacketCheckBox->isChecked()) {
        in_packet_last_pattern_.clear();
        updateSearchTypeToolTip(idx);
    }

    updateWidgets();
}

void SearchFrame::on_searchLineEdit_textChanged(const QString &)
{
    if (sf_ui_->inPacketCheckBox->isChecked() && in_packet_search_) {
        const QString pattern = sf_ui_->searchLineEdit->text();
        if (pattern.trimmed().isEmpty()) {
            in_packet_debounce_timer_->stop();
            in_packet_search_->clearMatches();
            in_packet_last_pattern_.clear();
        } else {
            in_packet_debounce_timer_->start();
        }
    }
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

void SearchFrame::executeSearch()
{
    if (!cap_file_) {
        return;
    }

    if (sf_ui_->inPacketCheckBox->isChecked()) {
        advanceInPacketSearch(false);
        return;
    }

    uint8_t *bytes = nullptr;
    size_t nbytes = 0;
    char *string = nullptr;
    dfilter_t *dfp = nullptr;
    bool found_packet = false;
    QString err_string;

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

    int search_type = searchTypeIndex();
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
        found_packet = cf_find_packet_dfilter(cap_file_, dfp, cap_file_->dir, true);
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

void SearchFrame::executeInPacketSearch()
{
    if (!in_packet_search_) {
        return;
    }

    const int search_type = searchTypeIndex();
    if (search_type != string_search_ && search_type != regex_search_) {
        mainApp->pushStatus(MainApplication::FilterSyntax,
                tr("Find in Packet supports string and regular expression search only."));
        return;
    }

    const QString pattern = sf_ui_->searchLineEdit->text();
    if (pattern.trimmed().isEmpty()) {
        in_packet_search_->clearMatches();
        in_packet_search_->setHighlightEnabled(true);
        in_packet_last_pattern_.clear();
        updateWidgets();
        return;
    }

    if (search_type == regex_search_ && !regexCompile()) {
        in_packet_search_->clearMatches();
        mainApp->pushStatus(MainApplication::FilterSyntax, regex_error_);
        updateWidgets();
        return;
    }

    in_packet_search_->setHighlightEnabled(true);
    const bool case_sensitive = sf_ui_->caseCheckBox->isChecked();
    const bool use_regex = (search_type == regex_search_);
    in_packet_search_->search(pattern, case_sensitive, use_regex);
    in_packet_last_pattern_ = pattern;

    updateWidgets();
}

void SearchFrame::advanceInPacketSearch(bool backward)
{
    if (!in_packet_search_) {
        return;
    }

    const QString pattern = sf_ui_->searchLineEdit->text();
    if (pattern != in_packet_last_pattern_) {
        in_packet_debounce_timer_->stop();
        executeInPacketSearch();
    }
    if (in_packet_search_->matchCount() > 0) {
        if (backward) {
            in_packet_search_->findPrevious();
        } else {
            in_packet_search_->findNext();
        }
    }
    sf_ui_->searchLineEdit->setFocus();
}

void SearchFrame::inPacketCheckBoxToggled(bool checked)
{
    if (checked && !packet_selected_) {
        QSignalBlocker blocker(sf_ui_->inPacketCheckBox);
        sf_ui_->inPacketCheckBox->setChecked(false);
        return;
    }

    if (!checked) {
        in_packet_debounce_timer_->stop();
        configureSearchTypeComboBox(false);
        if (in_packet_search_) {
            in_packet_search_->setHighlightEnabled(false);
            in_packet_search_->clearMatches();
        }
        in_packet_last_pattern_.clear();
        updateWidgets();
        return;
    }

    configureSearchTypeComboBox(true);
    if (!in_packet_search_) {
        updateWidgets();
        return;
    }

    in_packet_search_->setHighlightEnabled(true);
    if (!sf_ui_->searchLineEdit->text().trimmed().isEmpty()) {
        executeInPacketSearch();
    }
    updateWidgets();
    sf_ui_->searchLineEdit->setFocus();
}

void SearchFrame::updateInPacketSearchSyntax()
{
    const QString pattern = sf_ui_->searchLineEdit->text();
    if (pattern.trimmed().isEmpty()) {
        sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Invalid);
        return;
    }

    const int search_type = searchTypeIndex();
    if (search_type == regex_search_ && !regexCompile()) {
        sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Invalid);
        return;
    }

    sf_ui_->searchLineEdit->setSyntaxState(SyntaxLineEdit::Valid);
}

void SearchFrame::updateInPacketFindCounter()
{
    MainWindow *mw = mainApp->mainWindow();
    if (!mw) {
        return;
    }
    MainStatusBar *status_bar = mw->statusBar();
    if (!status_bar) {
        return;
    }

    auto clearFindInPacketStatus = [status_bar]() {
        status_bar->setFindInPacketStatus(QString());
        mainApp->popStatus(MainApplication::FilterSyntax);
    };

    if (!sf_ui_->inPacketCheckBox->isChecked() || !in_packet_search_) {
        clearFindInPacketStatus();
        return;
    }

    const QString pattern = sf_ui_->searchLineEdit->text();
    if (pattern.isEmpty()) {
        clearFindInPacketStatus();
        return;
    }

    const int search_type = searchTypeIndex();
    if (search_type == regex_search_ && !regexCompile()) {
        clearFindInPacketStatus();
        return;
    }

    mainApp->popStatus(MainApplication::FilterSyntax);

    if (in_packet_search_->isRegexInvalid()) {
        status_bar->setFindInPacketStatus(QString());
    } else if (in_packet_search_->matchCount() == 0) {
        const QString search_type_name = (search_type == regex_search_)
                ? tr("Regular Expression") : tr("String");
        status_bar->setFindInPacketStatus(tr("[no matches]"),
                tr("No %1 found.").arg(search_type_name));
    } else {
        status_bar->setFindInPacketStatus(tr("[%1 of %2]")
                .arg(in_packet_search_->currentMatchIndex() + 1)
                .arg(in_packet_search_->matchCount()));
    }
}

void SearchFrame::onApplicationFocusChanged(QWidget *old, QWidget *now)
{
    Q_UNUSED(old)
    Q_UNUSED(now)
    // Re-evaluate checkbox state when focus changes
    updateWidgets();
}

void SearchFrame::cancelSearch()
{
    in_packet_debounce_timer_->stop();
    if (in_packet_search_) {
        in_packet_search_->setHighlightEnabled(false);
        in_packet_search_->clearMatches();
    }
    in_packet_last_pattern_.clear();
    if (sf_ui_->inPacketCheckBox->isChecked()) {
        QSignalBlocker blocker(sf_ui_->inPacketCheckBox);
        sf_ui_->inPacketCheckBox->setChecked(false);
        configureSearchTypeComboBox(false);
    }
    updateWidgets();
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
            full_search_type_tooltip_ = sf_ui_->searchTypeComboBox->toolTip();
            in_packet_string_tooltip_ = tr("Search for a plain text string/char in the current packet details tree (e.g. 'flag' or 'f').");
            in_packet_regex_tooltip_ = tr("Search using a regular expression in the current packet details tree (e.g. 'd').");
            sf_ui_->inPacketCheckBox->setToolTip(tr("Search the selected packet details tree"));
            configureSearchTypeComboBox(sf_ui_->inPacketCheckBox->isChecked());
            updateInPacketFindCounter();
            break;
        default:
            break;
        }
    }
    AccordionFrame::changeEvent(event);
}
