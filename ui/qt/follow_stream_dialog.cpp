/* follow_stream_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "follow_stream_dialog.h"
#include <ui_follow_stream_dialog.h>

#include "main_application.h"
#include "main_window.h"

#include "frame_tvbuff.h"
#include "epan/follow.h"
#include "epan/prefs.h"
#include "epan/addr_resolv.h"
#include "epan/charsets.h"
#include "epan/epan_dissect.h"
#include "epan/tap.h"

#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include <ui/recent.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/ws_assert.h>

#include "wsutil/file_util.h"
#include "wsutil/str_util.h"
#include "wsutil/filesystem.h"

#include "ws_symbol_export.h"

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>

#include "progress_frame.h"

#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QElapsedTimer>
#include <QKeyEvent>
#include <QMessageBox>
#include <QMutex>
#include <QPrintDialog>
#include <QPrinter>
#include <QScrollBar>
#include <QTextCodec>

// To do:
// - Show text while tapping.
// - Instead of calling QMessageBox, display the error message in the text
//   box and disable the appropriate controls.
// - Add a progress bar and connect captureCaptureUpdateContinue to it

// Matches SplashOverlay.
static int info_update_freq_ = 100;

// Handle the loop breaking notification properly
static QMutex loop_break_mutex;

// Indicates that a Follow Stream is currently running
static bool isReadRunning;

Q_DECLARE_METATYPE(bytes_show_type)

FollowStreamDialog::FollowStreamDialog(QWidget &parent, CaptureFile &cf, int proto_id) :
    WiresharkDialog(parent, cf),
    ui(new Ui::FollowStreamDialog),
    b_find_(NULL),
    follower_(NULL),
    client_buffer_count_(0),
    server_buffer_count_(0),
    client_packet_count_(0),
    server_packet_count_(0),
    last_packet_(0),
    last_from_server_(0),
    turns_(0),
    use_regex_find_(false),
    terminating_(false),
    previous_sub_stream_num_(0)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 2 / 3, parent.height());

    ui->streamNumberSpinBox->setStyleSheet("QSpinBox { min-width: 2em; }");
    ui->subStreamNumberSpinBox->setStyleSheet("QSpinBox { min-width: 2em; }");
    ui->streamNumberSpinBox->setKeyboardTracking(false);
    ui->subStreamNumberSpinBox->setKeyboardTracking(false);

    follower_ = get_follow_by_proto_id(proto_id);
    if (follower_ == NULL) {
        ws_assert_not_reached();
    }

    memset(&follow_info_, 0, sizeof(follow_info_));
    follow_info_.show_stream = BOTH_HOSTS;
    follow_info_.substream_id = SUBSTREAM_UNUSED;

    nstime_set_zero(&last_ts_);

    ui->teStreamContent->installEventFilter(this);

    connect(ui->leFind, SIGNAL(useRegexFind(bool)), this, SLOT(useRegexFind(bool)));

    QComboBox *cbcs = ui->cbCharset;
    cbcs->blockSignals(true);
    cbcs->addItem(tr("ASCII"), SHOW_ASCII);
    cbcs->addItem(tr("C Arrays"), SHOW_CARRAY);
    cbcs->addItem(tr("EBCDIC"), SHOW_EBCDIC);
    cbcs->addItem(tr("Hex Dump"), SHOW_HEXDUMP);
    cbcs->addItem(tr("Raw"), SHOW_RAW);
    // UTF-8 is guaranteed to exist as a QTextCodec
    cbcs->addItem(tr("UTF-8"), SHOW_CODEC);
    cbcs->addItem(tr("YAML"), SHOW_YAML);
    cbcs->setCurrentIndex(cbcs->findData(recent.gui_follow_show));
    cbcs->blockSignals(false);

    ui->deltaComboBox->setCurrentIndex(recent.gui_follow_delta);

    b_filter_out_ = ui->buttonBox->addButton(tr("Filter Out This Stream"), QDialogButtonBox::ActionRole);
    connect(b_filter_out_, &QPushButton::clicked, this, &FollowStreamDialog::filterOut);

    b_print_ = ui->buttonBox->addButton(tr("Print"), QDialogButtonBox::ActionRole);
    connect(b_print_, &QPushButton::clicked, this, &FollowStreamDialog::printStream);

    b_save_ = ui->buttonBox->addButton(tr("Save as…"), QDialogButtonBox::ActionRole);
    connect(b_save_, &QPushButton::clicked, this, &FollowStreamDialog::saveAs);

    b_back_ = ui->buttonBox->addButton(tr("Back"), QDialogButtonBox::ActionRole);
    connect(b_back_, &QPushButton::clicked, this, &FollowStreamDialog::backButton);

    ProgressFrame::addToButtonBox(ui->buttonBox, &parent);

    connect(ui->cbDirections, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
            this, &FollowStreamDialog::cbDirectionsCurrentIndexChanged);
    connect(ui->cbCharset, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
            this, &FollowStreamDialog::cbCharsetCurrentIndexChanged);
    connect(ui->deltaComboBox, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
            this, &FollowStreamDialog::deltaComboBoxCurrentIndexChanged);

    connect(ui->streamNumberSpinBox, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &FollowStreamDialog::streamNumberSpinBoxValueChanged);
    connect(ui->subStreamNumberSpinBox, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &FollowStreamDialog::subStreamNumberSpinBoxValueChanged);

    connect(ui->buttonBox, &QDialogButtonBox::helpRequested, this, &FollowStreamDialog::helpButton);
    connect(ui->teStreamContent, &FollowStreamText::mouseMovedToPacket,
            this, &FollowStreamDialog::fillHintLabel);
    connect(ui->teStreamContent, &FollowStreamText::mouseClickedOnPacket,
            this, &FollowStreamDialog::goToPacketForTextPos);

    connect(ui->bFind, &QPushButton::clicked, this, &FollowStreamDialog::bFindClicked);
    connect(ui->leFind, &FindLineEdit::returnPressed, this, &FollowStreamDialog::leFindReturnPressed);

    connect(ui->buttonBox, &QDialogButtonBox::rejected, this, &FollowStreamDialog::buttonBoxRejected);

    fillHintLabel();
}

FollowStreamDialog::~FollowStreamDialog()
{
    delete ui;
    resetStream(); // Frees payload
}

void FollowStreamDialog::addCodecs(const QMap<QString, QTextCodec *> &codecMap)
{
    // Make the combobox respect max visible items?
    //ui->cbCharset->setStyleSheet("QComboBox { combobox-popup: 0;}");
    ui->cbCharset->insertSeparator(ui->cbCharset->count());
    for (const auto &codec : codecMap) {
        // This is already in the menu and handled separately
        if (codec->name() != "US-ASCII" && codec->name() != "UTF-8")
            ui->cbCharset->addItem(tr(codec->name()), SHOW_CODEC);
    }
}

void FollowStreamDialog::printStream()
{
#ifndef QT_NO_PRINTER
    QPrinter printer(QPrinter::HighResolution);
    QPrintDialog dialog(&printer, this);
    if (dialog.exec() == QDialog::Accepted)
        ui->teStreamContent->print(&printer);
#endif
}

void FollowStreamDialog::fillHintLabel(int pkt)
{
    QString hint;

    bool is_logray = strcmp(get_configuration_namespace(), "Logray") == 0;

    if (is_logray)  {
        if (pkt > 0) {
            hint = QString(tr("Event %1. ")).arg(pkt);
        }

        hint += tr("%Ln <span style=\"color: %1; background-color:%2\">reads</span>, ", "", client_packet_count_)
                .arg(ColorUtils::fromColorT(prefs.st_client_fg).name(),
                ColorUtils::fromColorT(prefs.st_client_bg).name())
                + tr("%Ln <span style=\"color: %1; background-color:%2\">writes</span>, ", "", server_packet_count_)
                .arg(ColorUtils::fromColorT(prefs.st_server_fg).name(),
                ColorUtils::fromColorT(prefs.st_server_bg).name())
                + tr("%Ln turn(s).", "", turns_);
    } else {
        if (pkt > 0) {
            hint = QString(tr("Packet %1. ")).arg(pkt);
        }

        hint += tr("%Ln <span style=\"color: %1; background-color:%2\">client</span> pkt(s), ", "", client_packet_count_)
                .arg(ColorUtils::fromColorT(prefs.st_client_fg).name(),
                ColorUtils::fromColorT(prefs.st_client_bg).name())
                + tr("%Ln <span style=\"color: %1; background-color:%2\">server</span> pkt(s), ", "", server_packet_count_)
                .arg(ColorUtils::fromColorT(prefs.st_server_fg).name(),
                ColorUtils::fromColorT(prefs.st_server_bg).name())
                + tr("%Ln turn(s).", "", turns_);
    }

    if (pkt > 0) {
        hint.append(QString(tr(" Click to select.")));
    }

    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);
}

void FollowStreamDialog::goToPacketForTextPos(int pkt)
{
    if (file_closed_) {
        return;
    }

    if (pkt > 0) {
        emit goToPacket(pkt);
    }
}

void FollowStreamDialog::updateWidgets(bool follow_in_progress)
{
    // XXX: If follow_in_progress set cursor to Qt::BusyCursor or WaitCursor,
    // otherwise unset cursor?
    bool enable = !follow_in_progress;
    if (file_closed_) {
        ui->teStreamContent->setEnabled(true);
        enable = false;
    }

    ui->cbDirections->setEnabled(enable);
    ui->cbCharset->setEnabled(enable);
    ui->streamNumberSpinBox->setReadOnly(!enable);
    if (get_follow_sub_stream_id_func(follower_) != NULL) {
        ui->subStreamNumberSpinBox->setReadOnly(!enable);
    }
    ui->leFind->setEnabled(enable);
    ui->bFind->setEnabled(enable);
    b_filter_out_->setEnabled(enable);
    b_print_->setEnabled(enable);
    b_save_->setEnabled(enable);

    WiresharkDialog::updateWidgets();
}

void FollowStreamDialog::useRegexFind(bool use_regex)
{
    use_regex_find_ = use_regex;
    if (use_regex_find_)
        ui->lFind->setText(tr("Regex Find:"));
    else
        ui->lFind->setText(tr("Find:"));
}

// This only calls itself with go_back false, so never recurses more than once.
// NOLINTNEXTLINE(misc-no-recursion)
void FollowStreamDialog::findText(bool go_back)
{
    if (ui->leFind->text().isEmpty()) return;

    bool found;

    QTextDocument::FindFlags options;
    if (ui->caseCheckBox->isChecked()) {
        options |= QTextDocument::FindCaseSensitively;
    }
    if (use_regex_find_) {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 13, 0))
        // https://bugreports.qt.io/browse/QTBUG-88721
        // QPlainTextEdit::find() searches case-insensitively unless
        // QTextDocument::FindCaseSensitively is explicitly given.
        // This *does* apply to QRegularExpression (overriding
        // CaseInsensitiveOption), but not QRegExp.
        //
        // QRegularExpression and QRegExp do not support Perl's /i, but
        // the former at least does support the mode modifiers (?i) and
        // (?-i), which can override QTextDocument::FindCaseSensitively.
        //
        // To make matters worse, while the QTextDocument::find() documentation
        // is correct, QPlainTextEdit::find() claims that QRegularExpression
        // works like QRegExp, which is incorrect.
        QRegularExpression regex(ui->leFind->text(), QRegularExpression::UseUnicodePropertiesOption);
#else
        QRegExp regex(ui->leFind->text(), (options & QTextDocument::FindCaseSensitively) ? Qt::CaseSensitive : Qt::CaseInsensitive);
#endif
        found = ui->teStreamContent->find(regex, options);
    } else {
        found = ui->teStreamContent->find(ui->leFind->text(), options);
    }

    if (found) {
        ui->teStreamContent->setFocus();
    } else if (go_back) {
        ui->teStreamContent->moveCursor(QTextCursor::Start);
        findText(false);
    }
}

void FollowStreamDialog::saveAs()
{
    QString file_name = WiresharkFileDialog::getSaveFileName(this, mainApp->windowTitleString(tr("Save Stream Content As…")));
    if (file_name.isEmpty()) {
        return;
    }

    QFile file(file_name);
    if (!file.open(QIODevice::WriteOnly)) {
        open_failure_alert_box(file_name.toUtf8().constData(), errno, true);
        return;
    }

    // XXX: What if truncated_ is true? We should save the entire stream.
    // Unconditionally save data as UTF-8 (even if data is decoded otherwise).
    QByteArray bytes = ui->teStreamContent->toPlainText().toUtf8();
    if (recent.gui_follow_show == SHOW_RAW) {
        // The "Raw" format is currently displayed as hex data and needs to be
        // converted to binary data. fromHex() skips over non hex characters
        // including line breaks, which is what we want.
        bytes = QByteArray::fromHex(bytes);
    }

    QDataStream out(&file);
    out.writeRawData(bytes.constData(), static_cast<int>(bytes.size()));
}

void FollowStreamDialog::helpButton()
{
    mainApp->helpTopicAction(HELP_FOLLOW_STREAM_DIALOG);
}

void FollowStreamDialog::backButton()
{
    if (terminating_)
        return;

    output_filter_ = previous_filter_;

    close();
}

void FollowStreamDialog::filterOut()
{
    if (terminating_)
        return;

    output_filter_ = filter_out_filter_;

    close();
}

void FollowStreamDialog::close()
{
    terminating_ = true;

    // Update filter - Use:
    //     previous_filter if 'Close' (passed in follow() method)
    //     filter_out_filter_ if 'Filter Out This Stream' (built by appending !current_stream to previous_filter)
    //     leave filter alone if window closed. (current stream)
    emit updateFilter(output_filter_, true);

    WiresharkDialog::close();
}

void FollowStreamDialog::cbDirectionsCurrentIndexChanged(int idx)
{
    switch(idx)
    {
    case 0 :
        follow_info_.show_stream = BOTH_HOSTS;
        break;
    case 1 :
        follow_info_.show_stream = FROM_SERVER;
        break;
    case 2 :
        follow_info_.show_stream = FROM_CLIENT;
        break;
    default:
        return;
    }

    readStream();
}

void FollowStreamDialog::cbCharsetCurrentIndexChanged(int idx)
{
    if (idx < 0) return;
    recent.gui_follow_show = ui->cbCharset->currentData().value<bytes_show_type>();

    switch (recent.gui_follow_show) {
    case SHOW_EBCDIC:
    case SHOW_ASCII:
    case SHOW_CODEC:
        ui->deltaComboBox->setEnabled(true);
        break;
    default:
        ui->deltaComboBox->setEnabled(false);
    }

    readStream();
}

void FollowStreamDialog::deltaComboBoxCurrentIndexChanged(int idx)
{
    if (idx < 0) return;
    recent.gui_follow_delta = static_cast<follow_delta_type>(ui->deltaComboBox->currentIndex());

    readStream();
}

void FollowStreamDialog::bFindClicked()
{
    findText();
}

void FollowStreamDialog::leFindReturnPressed()
{
    findText();
}

void FollowStreamDialog::streamNumberSpinBoxValueChanged(int stream_num)
{
    if (file_closed_) return;

    int sub_stream_num = 0;
    ui->subStreamNumberSpinBox->blockSignals(true);
    sub_stream_num = ui->subStreamNumberSpinBox->value();
    ui->subStreamNumberSpinBox->blockSignals(false);

    bool ok;
    if (ui->subStreamNumberSpinBox->isVisible()) {
        /* We need to find a suitable sub stream for the new stream */
        follow_sub_stream_id_func sub_stream_func;
        sub_stream_func = get_follow_sub_stream_id_func(follower_);

        if (sub_stream_func == NULL) {
            // Should not happen, this field is only visible for suitable protocols.
            return;
        }

        unsigned sub_stream_num_new = static_cast<unsigned>(sub_stream_num);
        if (sub_stream_num < 0) {
            // Stream ID 0 should always exist as it is used for control messages.
            // XXX: That is only guaranteed for HTTP2. For example, in QUIC,
            // stream ID 0 is a normal stream used by the first standard client-
            // initiated bidirectional stream (if it exists, and it might not)
            // and we might have a stream (connection) but only the CRYPTO
            // stream, which does not have a (sub) stream ID.
            // What should we do if there is a stream with no substream to
            // follow? Right now the substream spinbox is left active and
            // the user can change the value to no effect.
            sub_stream_num_new = 0;
            ok = true;
        } else {
            ok = sub_stream_func(static_cast<unsigned>(stream_num), sub_stream_num_new, false, &sub_stream_num_new);
            if (!ok) {
                ok = sub_stream_func(static_cast<unsigned>(stream_num), sub_stream_num_new, true, &sub_stream_num_new);
            }
        }
        sub_stream_num = static_cast<int>(sub_stream_num_new);
    } else {
        /* XXX: For HTTP and TLS, we use the TCP stream index, and really should
         * return false if the TCP stream doesn't have HTTP or TLS. (Or we could
         * switch to having separate HTTP and TLS stream numbers.)
         */
        ok = true;
    }

    if (stream_num >= 0 && ok) {
        follow(previous_filter_, true, stream_num, sub_stream_num);
        previous_sub_stream_num_ = sub_stream_num;
    }
}


void FollowStreamDialog::subStreamNumberSpinBoxValueChanged(int sub_stream_num)
{
    if (file_closed_) return;

    int stream_num = 0;
    ui->streamNumberSpinBox->blockSignals(true);
    stream_num = ui->streamNumberSpinBox->value();
    ui->streamNumberSpinBox->blockSignals(false);

    follow_sub_stream_id_func sub_stream_func;
    sub_stream_func = get_follow_sub_stream_id_func(follower_);

    if (sub_stream_func == NULL) {
        // Should not happen, this field is only visible for suitable protocols.
        return;
    }

    unsigned sub_stream_num_new = static_cast<unsigned>(sub_stream_num);
    bool ok;
    /* previous_sub_stream_num_ is a hack to track which buttons was pressed without event handling */
    if (sub_stream_num < 0) {
        // Stream ID 0 should always exist as it is used for control messages.
        // XXX: That is only guaranteed for HTTP2, see above.
        sub_stream_num_new = 0;
        ok = true;
    } else if (previous_sub_stream_num_ < sub_stream_num) {
        ok = sub_stream_func(static_cast<unsigned>(stream_num), sub_stream_num_new, false, &sub_stream_num_new);
    } else {
        ok = sub_stream_func(static_cast<unsigned>(stream_num), sub_stream_num_new, true, &sub_stream_num_new);
    }
    sub_stream_num = static_cast<int>(sub_stream_num_new);

    if (ok) {
        follow(previous_filter_, true, stream_num, sub_stream_num);
        previous_sub_stream_num_ = sub_stream_num;
    }
}

void FollowStreamDialog::buttonBoxRejected()
{
    // Ignore the close button if FollowStreamDialog::close() is running.
    if (terminating_)
        return;

    WiresharkDialog::reject();
}

void FollowStreamDialog::removeStreamControls()
{
    ui->horizontalLayout->removeItem(ui->streamNumberSpacer);
    ui->streamNumberLabel->setVisible(false);
    ui->streamNumberSpinBox->setVisible(false);
    ui->subStreamNumberLabel->setVisible(false);
    ui->subStreamNumberSpinBox->setVisible(false);
}

void FollowStreamDialog::resetStream(void *tap_data)
{
    follow_info_t *follow_info = static_cast<follow_info_t*>(tap_data);
    follow_reset_stream(follow_info);
    // If we ever draw the text while tapping (instead of only after
    // the tap finishes), reset the GUI here too.
}

void FollowStreamDialog::resetStream()
{
    FollowStreamDialog::resetStream(&follow_info_);
}

void FollowStreamDialog::readStream()
{

    // interrupt any reading already running
    loop_break_mutex.lock();
    isReadRunning = false;
    loop_break_mutex.unlock();

    double scroll_ratio = 0.0;
    int doc_length = ui->teStreamContent->verticalScrollBar()->maximum() + ui->teStreamContent->verticalScrollBar()->pageStep();
    if (doc_length > 0) {
        scroll_ratio = static_cast<double>(ui->teStreamContent->verticalScrollBar()->value()) / doc_length;
    }

    ui->teStreamContent->clear();
    switch (recent.gui_follow_show) {

    case SHOW_CARRAY:
    case SHOW_HEXDUMP:
    case SHOW_YAML:
        /* We control the width and insert line breaks in these formats. */
        ui->teStreamContent->setWordWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
        break;

    default:
        /* Everything else might have extremely long lines without whitespace,
         * (SHOW_RAW almost surely so), and QTextEdit is O(N^2) trying
         * to search for word boundaries on long lines when adding text.
         */
        ui->teStreamContent->setWordWrapMode(QTextOption::WrapAnywhere);
    }

    client_buffer_count_ = 0;
    server_buffer_count_ = 0;
    client_packet_count_ = 0;
    server_packet_count_ = 0;
    last_packet_ = 0;
    turns_ = 0;

    if (!follower_) {
        ws_assert_not_reached();
    }

    readFollowStream();

    ui->teStreamContent->moveCursor(QTextCursor::Start);

    doc_length = ui->teStreamContent->verticalScrollBar()->maximum() + ui->teStreamContent->verticalScrollBar()->pageStep();
    ui->teStreamContent->verticalScrollBar()->setValue(doc_length * scroll_ratio);
}

void
FollowStreamDialog::followStream()
{
    readStream();
}

void FollowStreamDialog::addText(QString text, bool is_from_server, uint32_t packet_num, bool colorize)
{
    ui->teStreamContent->addText(std::move(text), is_from_server, packet_num, colorize);
}

// The following keyboard shortcuts should work (although
// they may not work consistently depending on focus):
// / (slash), Ctrl-F - Focus and highlight the search box
// Ctrl-G, Ctrl-N, F3 - Find next
// Should we make it so that typing any text starts searching?
bool FollowStreamDialog::eventFilter(QObject *, QEvent *event)
{
    if (ui->teStreamContent->hasFocus() && event->type() == QEvent::KeyPress) {
        QKeyEvent *keyEvent = static_cast<QKeyEvent*>(event);
        if (keyEvent->matches(QKeySequence::SelectAll) || keyEvent->matches(QKeySequence::Copy)
                || keyEvent->text().isEmpty()) {
            return false;
        }
        ui->leFind->setFocus();
        if (keyEvent->matches(QKeySequence::Find)) {
            return true;
        } else if (keyEvent->matches(QKeySequence::FindNext)) {
            findText();
            return true;
        }
    }

    return false;
}

void FollowStreamDialog::keyPressEvent(QKeyEvent *event)
{
    if (ui->leFind->hasFocus()) {
        if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) {
            findText();
            return;
        }
    } else {
        if (event->key() == Qt::Key_Slash || event->matches(QKeySequence::Find)) {
            ui->leFind->setFocus();
            ui->leFind->selectAll();
        }
        return;
    }

    if (event->key() == Qt::Key_F3 || (event->key() == Qt::Key_N && event->modifiers() & Qt::ControlModifier)) {
        findText();
        return;
    }

    QDialog::keyPressEvent(event);
}

// Replaces non printable ASCII characters in the QByteArray with .
// Causes buffer to detach/deep copy *only* if a character has to be
// replaced.
static inline void sanitize_buffer(QByteArray &buffer, size_t nchars) {
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    for (int i = 0; i < (int)nchars; i++) {
#else
    for (qsizetype i = 0; i < (qsizetype)nchars; i++) {
#endif
        if (buffer.at(i) == '\n' || buffer.at(i) == '\r' || buffer.at(i) == '\t')
            continue;
        if (! g_ascii_isprint((unsigned char)buffer.at(i))) {
            buffer[i] = '.';
        }
    }
}

void FollowStreamDialog::showBuffer(QByteArray &buffer, size_t nchars, bool is_from_server, uint32_t packet_num,
                                nstime_t abs_ts, uint32_t *global_pos)
{
    char initbuf[256];
    uint32_t current_pos;
    static const char hexchars[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    bool show_delta = false;

    if (last_packet_ == 0) {
        last_from_server_ = is_from_server;
    } else {
        if (recent.gui_follow_delta == FOLLOW_DELTA_ALL ||
            (recent.gui_follow_delta == FOLLOW_DELTA_TURN && last_from_server_ != is_from_server)) {
                show_delta = true;
        }
    }

    double delta = 0.0;
    if (!nstime_is_zero(&abs_ts)) {
        // packet-tcp.c and possibly other dissectors can return a zero abs_ts when
        // a fragment is missing.
        nstime_t delta_ts;
        nstime_delta(&delta_ts, &abs_ts, &last_ts_);
        delta = nstime_to_sec(&delta_ts);
        last_ts_ = abs_ts;
    }

    switch (recent.gui_follow_show) {

    case SHOW_EBCDIC:
    {
        /* If our native arch is ASCII, call: */
        EBCDIC_to_ASCII((uint8_t*)buffer.data(), (unsigned) nchars);
        if (show_delta) {
            ui->teStreamContent->addDeltaTime(delta);
        }
        if (show_delta || last_from_server_ != is_from_server) {
            addText("\n", is_from_server, packet_num);
        }
        sanitize_buffer(buffer, nchars);
        addText(buffer, is_from_server, packet_num);
        break;
    }

    case SHOW_ASCII:
    {
        /* If our native arch is EBCDIC, call:
         * ASCII_TO_EBCDIC(buffer, nchars);
         */
        if (show_delta) {
            ui->teStreamContent->addDeltaTime(delta);
        }
        if (show_delta || last_from_server_ != is_from_server) {
            addText("\n", is_from_server, packet_num);
        }
        sanitize_buffer(buffer, nchars);
        addText(buffer, is_from_server, packet_num);
        break;
    }

    case SHOW_CODEC:
    {
        if (show_delta) {
            ui->teStreamContent->addDeltaTime(delta);
        }
        if (show_delta || last_from_server_ != is_from_server) {
            addText("\n", is_from_server, packet_num);
        }
        // This assumes that multibyte characters don't span packets in the
        // stream. To handle that case properly (which might occur with fixed
        // block sizes, e.g. transferring over TFTP, we would need to create
        // two stateful QTextDecoders, one for each direction, presumably in
        // on_cbCharset_currentIndexChanged()
        QTextCodec *codec = QTextCodec::codecForName(ui->cbCharset->currentText().toUtf8());
        addText(codec->toUnicode(buffer), is_from_server, packet_num);
        break;
    }

    case SHOW_HEXDUMP:
        current_pos = 0;
        while (current_pos < nchars) {
            char hexbuf[256];
            int i;
            char *cur = hexbuf, *ascii_start;

            /* is_from_server indentation : put 4 spaces at the
             * beginning of the string */
            /* XXX - We might want to prepend each line with "C" or "S" instead. */
            if (is_from_server && follow_info_.show_stream == BOTH_HOSTS) {
                memset(cur, ' ', 4);
                cur += 4;
            }
            cur += snprintf(cur, 20, "%08X  ", *global_pos);
            /* 49 is space consumed by hex chars */
            ascii_start = cur + 49 + 2;
            for (i = 0; i < 16 && current_pos + i < nchars; i++) {
                *cur++ =
                        hexchars[(buffer.at(current_pos + i) & 0xf0) >> 4];
                *cur++ =
                        hexchars[buffer.at(current_pos + i) & 0x0f];
                *cur++ = ' ';
                if (i == 7)
                    *cur++ = ' ';
            }
            /* Fill it up if column isn't complete */
            while (cur < ascii_start)
                *cur++ = ' ';

            /* Now dump bytes as text */
            for (i = 0; i < 16 && current_pos + i < nchars; i++) {
                *cur++ =
                        (g_ascii_isprint((unsigned char)buffer.at(current_pos + i)) ?
                            buffer.at(current_pos + i) : '.');
                if (i == 7) {
                    *cur++ = ' ';
                }
            }
            current_pos += i;
            (*global_pos) += i;
            *cur++ = '\n';
            *cur = 0;

            addText(hexbuf, is_from_server, packet_num);
        }
        break;

    case SHOW_CARRAY:
        current_pos = 0;
        snprintf(initbuf, sizeof(initbuf), "char peer%d_%d[] = { /* Packet %u */\n",
                   is_from_server ? 1 : 0,
                   is_from_server ? server_buffer_count_++ : client_buffer_count_++,
                   packet_num);
        addText(initbuf, is_from_server, packet_num);

        while (current_pos < nchars) {
            char hexbuf[256];
            int i, cur;

            cur = 0;
            for (i = 0; i < 8 && current_pos + i < nchars; i++) {
                /* Prepend entries with "0x" */
                hexbuf[cur++] = '0';
                hexbuf[cur++] = 'x';
                hexbuf[cur++] =
                        hexchars[(buffer.at(current_pos + i) & 0xf0) >> 4];
                hexbuf[cur++] =
                        hexchars[buffer.at(current_pos + i) & 0x0f];

                /* Delimit array entries with a comma */
                if (current_pos + i + 1 < nchars)
                    hexbuf[cur++] = ',';

                hexbuf[cur++] = ' ';
            }

            /* Terminate the array if we are at the end */
            if (current_pos + i == nchars) {
                hexbuf[cur++] = '}';
                hexbuf[cur++] = ';';
            }

            current_pos += i;
            (*global_pos) += i;
            hexbuf[cur++] = '\n';
            hexbuf[cur] = 0;
            addText(hexbuf, is_from_server, packet_num);
        }
        break;

    case SHOW_YAML:
    {
        QString yaml_text;

        const int base64_raw_len = 57; // Encodes to 76 bytes, common in RFCs
        current_pos = 0;

        if (last_packet_ == 0) {
            // Header with general info about peers
            const char *hostname0 = address_to_name(&follow_info_.client_ip);
            const char *hostname1 = address_to_name(&follow_info_.server_ip);

            char *port0 = get_follow_port_to_display(follower_)(NULL, follow_info_.client_port);
            char *port1 = get_follow_port_to_display(follower_)(NULL, follow_info_.server_port);

            addText("peers:\n", false, 0, false);

            addText(QString(
                "  - peer: 0\n"
                "    host: %1\n"
                "    port: %2\n")
                .arg(hostname0, port0), false, 0);

            addText(QString(
                "  - peer: 1\n"
                "    host: %1\n"
                "    port: %2\n")
                .arg(hostname1, port1), true, 0);

            wmem_free(NULL, port0);
            wmem_free(NULL, port1);

            addText("packets:\n", false, 0, false);
        }

        if (packet_num != last_packet_) {
            yaml_text.append(QString("  - packet: %1\n")
                    .arg(packet_num));
            yaml_text.append(QString("    peer: %1\n")
                    .arg(is_from_server ? 1 : 0));
            yaml_text.append(QString("    index: %1\n")
                    .arg(is_from_server ? server_buffer_count_++ : client_buffer_count_++));
            yaml_text.append(QString("    timestamp: %1.%2\n")
                    .arg(abs_ts.secs)
                    .arg(abs_ts.nsecs, 9, 10, QChar('0')));
            yaml_text.append(QString("    data: !!binary |\n"));
        }
        while (current_pos < nchars) {
            int len = current_pos + base64_raw_len < nchars ? base64_raw_len : (int) nchars - current_pos;
            QByteArray base64_data(&buffer.constData()[current_pos], len);

            /* XXX: GCC 12.1 has a bogus stringop-overread warning using the Qt
             * conversions from QByteArray to QString at -O2 and higher due to
             * computing a branch that will never be taken.
             */
#if WS_IS_AT_LEAST_GNUC_VERSION(12,1)
DIAG_OFF(stringop-overread)
#endif
            yaml_text += "      " + base64_data.toBase64() + "\n";
#if WS_IS_AT_LEAST_GNUC_VERSION(12,1)
DIAG_ON(stringop-overread)
#endif

            current_pos += len;
            (*global_pos) += len;
        }
        addText(std::move(yaml_text), is_from_server, packet_num);
        break;
    }

    case SHOW_RAW:
    {
        addText(buffer.toHex() + '\n', is_from_server, packet_num);
        break;
    }

    default:
        /* The other Show types are supported in Show Packet Bytes but
         * not here in Follow. (XXX: Maybe some could be added?)
         */
        ws_assert_not_reached();
    }

    if (packet_num != last_packet_) {
        last_packet_ = packet_num;
        if (is_from_server) {
            server_packet_count_++;
        } else {
            client_packet_count_++;
        }
        if (last_from_server_ != is_from_server) {
            last_from_server_ = is_from_server;
            turns_++;
        }
    }
}

bool FollowStreamDialog::follow(QString previous_filter, bool use_stream_index, unsigned stream_num, unsigned sub_stream_num)
{
    QString             follow_filter;
    const char          *hostname0 = NULL, *hostname1 = NULL;
    char                *port0 = NULL, *port1 = NULL;
    QString             server_to_client_string;
    QString             client_to_server_string;
    QString             both_directions_string;
    bool                is_follower = false;
    int                 stream_count;
    follow_stream_count_func stream_count_func = NULL;

    if (file_closed_)
    {
        QMessageBox::warning(this, tr("No capture file."), tr("Please make sure you have a capture file opened."));
        return false;
    }

    if (!use_stream_index) {
        if (cap_file_.capFile()->edt == NULL)
        {
            QMessageBox::warning(this, tr("Error following stream."), tr("Capture file invalid."));
            return false;
        }
        is_follower = proto_is_frame_protocol(cap_file_.capFile()->edt->pi.layers, proto_get_protocol_filter_name(get_follow_proto_id(follower_)));
        if (!is_follower) {
            QMessageBox::warning(this, tr("Error following stream."), tr("Please make sure you have a %1 packet selected.").arg
                                    (proto_get_protocol_short_name(find_protocol_by_id(get_follow_proto_id(follower_)))));
            return false;
        }
    }

    /* Create a new filter that matches all packets in the TCP stream,
        and set the display filter entry accordingly */
    if (use_stream_index) {
        follow_filter = gchar_free_to_qstring(get_follow_index_func(follower_)(stream_num, sub_stream_num));
    } else {
        follow_filter = gchar_free_to_qstring(get_follow_conv_func(follower_)(cap_file_.capFile()->edt, &cap_file_.capFile()->edt->pi, &stream_num, &sub_stream_num));
    }
    if (follow_filter.isEmpty()) {
        // XXX: This error probably has to do with tunneling (#18231), where
        // the addresses or ports changed after the TCP or UDP layer.
        // (The appropriate layer must be present, or else the GUI
        // doesn't allow the option to be selected.)
        QMessageBox::warning(this,
                             tr("Error creating filter for this stream."),
                             tr("%1 stream not found on the selected packet.").arg(proto_get_protocol_short_name(find_protocol_by_id(get_follow_proto_id(follower_)))));
        return false;
    }

    previous_filter_ = previous_filter;
    /* append the negation */
    if (!previous_filter.isEmpty()) {
        filter_out_filter_ = QString("%1 and !(%2)")
                .arg(previous_filter, follow_filter);
    }
    else
    {
        filter_out_filter_ = QString("!(%1)").arg(follow_filter);
    }

    follow_info_.substream_id = sub_stream_num;

    /* data will be passed via tap callback*/
    if (!registerTapListener(get_follow_tap_string(follower_), &follow_info_,
                                follow_filter.toUtf8().constData(),
                                0, FollowStreamDialog::resetStream,
                                get_follow_tap_handler(follower_), NULL)) {
        return false;
    }

    stream_count_func = get_follow_stream_count_func(follower_);

    if (stream_count_func == NULL) {
        removeStreamControls();
    } else {
        stream_count = stream_count_func();
        ui->streamNumberSpinBox->blockSignals(true);
        ui->streamNumberSpinBox->setMaximum(stream_count-1);
        ui->streamNumberSpinBox->setValue(stream_num);
        ui->streamNumberSpinBox->blockSignals(false);
        ui->streamNumberSpinBox->setToolTip(tr("%Ln total stream(s).", "", stream_count));
        ui->streamNumberLabel->setToolTip(ui->streamNumberSpinBox->toolTip());
    }

    follow_sub_stream_id_func sub_stream_func;
    sub_stream_func = get_follow_sub_stream_id_func(follower_);
    if (sub_stream_func != NULL) {
        unsigned substream_max_id = 0;
        sub_stream_func(static_cast<unsigned>(stream_num), INT32_MAX, true, &substream_max_id);
        stream_count = static_cast<int>(substream_max_id);
        ui->subStreamNumberSpinBox->blockSignals(true);
        ui->subStreamNumberSpinBox->setEnabled(true);
        ui->subStreamNumberSpinBox->setMaximum(stream_count);
        ui->subStreamNumberSpinBox->setValue(sub_stream_num);
        ui->subStreamNumberSpinBox->blockSignals(false);
        ui->subStreamNumberSpinBox->setToolTip(tr("Max sub stream ID for the selected stream: %Ln", "", stream_count));
        ui->subStreamNumberSpinBox->setToolTip(ui->subStreamNumberSpinBox->toolTip());
        ui->subStreamNumberSpinBox->setVisible(true);
        ui->subStreamNumberLabel->setVisible(true);
    } else {
        /* disable substream spin box for protocols without substreams */
        ui->subStreamNumberSpinBox->blockSignals(true);
        ui->subStreamNumberSpinBox->setEnabled(false);
        ui->subStreamNumberSpinBox->setValue(0);
        ui->subStreamNumberSpinBox->setKeyboardTracking(false);
        ui->subStreamNumberSpinBox->blockSignals(false);
        ui->subStreamNumberSpinBox->setVisible(false);
        ui->subStreamNumberLabel->setVisible(false);
    }

    beginRetapPackets();
    updateWidgets(true);

    /* Run the display filter so it goes in effect - even if it's the
       same as the previous display filter. */
    /* XXX: This forces a cf_filter_packets() - but if a rescan (or something else
     * that sets cf->read_lock) is in progress, this will queue the filter
     * and return immediately. It will also cause a rescan in progress to
     * stop and restart with the new filter. That also applies to this rescan;
     * changing the main display filter (from the main window, or from, e.g.
     * another FollowStreamDialog) will cause this to restart and reset the
     * tap.
     *
     * Other tapping dialogs call cf_retap_packets (which retaps but doesn't
     * set the main display filter, freeze the packet list, etc.), which
     * has somewhat different behavior when another dialog tries to retap,
     * but also results in the taps being reset mid tap.
     *
     * Either way, we should be event driven and listening for CaptureEvents
     * instead of drawing after this returns. (Or like other taps, draw
     * periodically in a callback, provided that can be done without causing
     * issues with changing the Decode As type.)
     */
    emit updateFilter(follow_filter, true);

    removeTapListeners();

    bool is_logray = strcmp(get_configuration_namespace(), "Logray") == 0;

    if (is_logray)  {
        server_to_client_string =
                tr("Read activity(%6)")
                .arg(gchar_free_to_qstring(format_size(
                                                follow_info_.bytes_written[0],
                                            FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI)));

        client_to_server_string =
                tr("Write activity(%6)")
                .arg(gchar_free_to_qstring(format_size(
                                                follow_info_.bytes_written[1],
                                            FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI)));

        both_directions_string = tr("Entire I/O activity (%1)")
                .arg(gchar_free_to_qstring(format_size(
                                                follow_info_.bytes_written[0] + follow_info_.bytes_written[1],
                        FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI)));
    } else {
        hostname0 = address_to_name(&follow_info_.client_ip);
        hostname1 = address_to_name(&follow_info_.server_ip);

        port0 = get_follow_port_to_display(follower_)(NULL, follow_info_.client_port);
        port1 = get_follow_port_to_display(follower_)(NULL, follow_info_.server_port);

        server_to_client_string =
                QString("%1:%2 %3 %4:%5 (%6)")
                .arg(hostname0, port0)
                .arg(UTF8_RIGHTWARDS_ARROW)
                .arg(hostname1, port1)
                .arg(gchar_free_to_qstring(format_size(
                                                follow_info_.bytes_written[0],
                                            FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI)));

        client_to_server_string =
                QString("%1:%2 %3 %4:%5 (%6)")
                .arg(hostname1, port1)
                .arg(UTF8_RIGHTWARDS_ARROW)
                .arg(hostname0, port0)
                .arg(gchar_free_to_qstring(format_size(
                                                follow_info_.bytes_written[1],
                                            FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI)));

        wmem_free(NULL, port0);
        wmem_free(NULL, port1);

        both_directions_string = tr("Entire conversation (%1)")
                .arg(gchar_free_to_qstring(format_size(
                                                follow_info_.bytes_written[0] + follow_info_.bytes_written[1],
                        FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI)));
    }

    setWindowSubtitle(tr("Follow %1 Stream (%2)").arg(proto_get_protocol_short_name(find_protocol_by_id(get_follow_proto_id(follower_))),
                                                follow_filter));

    ui->cbDirections->blockSignals(true);
    ui->cbDirections->clear();
    ui->cbDirections->addItem(both_directions_string);
    ui->cbDirections->addItem(client_to_server_string);
    ui->cbDirections->addItem(server_to_client_string);
    ui->cbDirections->blockSignals(false);

    followStream();
    fillHintLabel();

    updateWidgets(false);
    endRetapPackets();

    if (prefs.restore_filter_after_following_stream) {
        emit updateFilter(previous_filter_, true);
    }

    return true;
}

void FollowStreamDialog::captureFileClosed()
{
    QString tooltip = tr("File closed.");
    ui->streamNumberSpinBox->setToolTip(tooltip);
    ui->streamNumberLabel->setToolTip(tooltip);
    WiresharkDialog::captureFileClosed();
}

void FollowStreamDialog::readFollowStream()
{
    uint32_t global_client_pos = 0, global_server_pos = 0;
    uint32_t *global_pos;
    bool skip;
    GList* cur;
    follow_record_t *follow_record;
    QElapsedTimer elapsed_timer;
    QByteArray buffer;

    elapsed_timer.start();

    loop_break_mutex.lock();
    isReadRunning = true;
    loop_break_mutex.unlock();

    for (cur = g_list_last(follow_info_.payload); cur; cur = g_list_previous(cur)) {
        if (dialogClosed() || !isReadRunning) break;

        follow_record = (follow_record_t *)cur->data;
        skip = false;
        if (!follow_record->is_server) {
            global_pos = &global_client_pos;
            if (follow_info_.show_stream == FROM_SERVER) {
                skip = true;
            }
        } else {
            global_pos = &global_server_pos;
            if (follow_info_.show_stream == FROM_CLIENT) {
                skip = true;
            }
        }

        if (!skip) {
            // This will only detach / deep copy if the buffer data is
            // modified. Try to avoid doing that as much as possible
            // (and avoid new memory allocations that have to be freed).
            buffer.setRawData((char*)follow_record->data->data, follow_record->data->len);
            showBuffer(
                    buffer,
                    follow_record->data->len,
                    follow_record->is_server,
                    follow_record->packet_num,
                    follow_record->abs_ts,
                    global_pos);
            if (elapsed_timer.elapsed() > info_update_freq_) {
                fillHintLabel(ui->teStreamContent->currentPacket());
                mainApp->processEvents();
                elapsed_timer.start();
            }
        }
    }

    loop_break_mutex.lock();
    isReadRunning = false;
    loop_break_mutex.unlock();
}

