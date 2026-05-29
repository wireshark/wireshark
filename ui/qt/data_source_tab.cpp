/* data_source_tab.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "data_source_tab.h"

#include <QApplication>
#include <QClipboard>
#include <QColorDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QMimeData>
#include <QTabBar>

#include <epan/cfile.h>

#include <app/application_flavor.h>

#include <main_application.h>

#include <ui/qt/main_window.h>
#include <ui/qt/main_status_bar.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/color_math.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/widgets/hex_data_source_view.h>
#include <ui/qt/widgets/json_data_source_view.h>

namespace {
class AnnotationEditDialog : public QDialog
{
public:
    static int commentMaxChars() { return 256; }

    explicit AnnotationEditDialog(QWidget *parent = nullptr) :
        QDialog(parent),
        color_button_(new QPushButton(this)),
        comment_edit_(new QPlainTextEdit(this))
    {
        color_ = ThemeManager::instance()->color(ThemeManager::ExpertComment);
        QFormLayout *form = new QFormLayout;

        color_button_->setAutoDefault(false);
        updateColorButton();
        form->addRow(tr("Color:"), color_button_);

        comment_edit_->setPlaceholderText(tr("Comment (max %1 characters)").arg(commentMaxChars()));
        form->addRow(tr("Comment:"), comment_edit_);
        connect(comment_edit_, &QPlainTextEdit::textChanged, this, [this]() {
            QString text = comment_edit_->toPlainText();
            if (text.size() <= commentMaxChars()) {
                return;
            }
            int cursor_pos = comment_edit_->textCursor().position();
            text.truncate(commentMaxChars());
            QSignalBlocker blocker(comment_edit_);
            comment_edit_->setPlainText(text);
            QTextCursor cursor = comment_edit_->textCursor();
            cursor.setPosition(qMin(cursor_pos, commentMaxChars()));
            comment_edit_->setTextCursor(cursor);
        });

        QDialogButtonBox *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
        connect(color_button_, &QPushButton::clicked, this, [this]() {
            QColor new_color = QColorDialog::getColor(color_, this, tr("Select Annotation Color"));
            if (new_color.isValid()) {
                color_ = new_color;
                updateColorButton();
            }
        });

        QVBoxLayout *layout = new QVBoxLayout;
        layout->addLayout(form);
        QLabel *session_label = new QLabel(tr("Annotations are session-only and will be lost when the capture is closed."), this);
        session_label->setWordWrap(true);
        layout->addWidget(session_label);
        layout->addWidget(buttons);
        setLayout(layout);
    }

    void setColor(const QColor &color)
    {
        if (color.isValid()) {
            color_ = color;
            updateColorButton();
        }
    }

    QColor color() const { return color_; }

    void setComment(const QString &comment)
    {
        QString truncated = comment;
        if (truncated.size() > commentMaxChars()) {
            truncated.truncate(commentMaxChars());
        }
        comment_edit_->setPlainText(truncated);
    }

    QString comment() const
    {
        return comment_edit_->toPlainText().left(commentMaxChars());
    }

private:
    void updateColorButton()
    {
        QString bg = color_.name(QColor::HexRgb);
        QString fg = ColorMath::contrastingText(color_).name(QColor::HexRgb);
        QString label = color_.alpha() < 255 ? color_.name(QColor::HexArgb) : bg;
        color_button_->setText(label);
        color_button_->setStyleSheet(QStringLiteral("QPushButton { background-color: %1; color: %2; }").arg(bg, fg));
    }

    QColor color_;
    QPushButton *color_button_;
    QPlainTextEdit *comment_edit_;
};
} // namespace

#if QT_VERSION >= QT_VERSION_CHECK(6, 3, 0) && QT_VERSION < QT_VERSION_CHECK(6, 10, 1)
// Short-circuit minimumTabSizeHint and tabSizeHint if the TabBar is not visible
// to workaround https://bugreports.qt.io/browse/QTBUG-141187
// The real fix is in Qt 6.10.1 and later.
class DataSourceTabBar : public QTabBar
{
    Q_OBJECT

public:
    explicit DataSourceTabBar(QWidget *parent = nullptr);

protected:
    virtual QSize minimumTabSizeHint(int) const override;
    virtual QSize tabSizeHint(int) const override;
};

DataSourceTabBar::DataSourceTabBar(QWidget *parent) :
    QTabBar(parent) {}

QSize DataSourceTabBar::minimumTabSizeHint(int index) const
{
    if (!isVisible()) {
        return QSize();
    }
    return QTabBar::minimumTabSizeHint(index);
}

QSize DataSourceTabBar::tabSizeHint(int index) const
{
    if (!isVisible()) {
        return QSize();
    }
    return QTabBar::tabSizeHint(index);
}
#endif

DataSourceTab::DataSourceTab(QWidget *parent, epan_dissect_t *edt_fixed) :
    QTabWidget(parent),
    cap_file_(0),
    is_fixed_packet_(edt_fixed != NULL),
    edt_(edt_fixed),
    disable_hover_(false),
    annotations_session_notice_shown_(false)
{
    last_annotation_color_ = ThemeManager::instance()->color(ThemeManager::ExpertComment);
    last_themed_annotation_color_ = last_annotation_color_;
    connect(ThemeManager::instance(), &ThemeManager::themeChanged, this, [this]() {
        QColor nextThemed = ThemeManager::instance()->color(ThemeManager::ExpertComment);
        // Refresh the annotation default only if the user hasn't picked a
        // custom color since the last theme update.
        if (last_annotation_color_ == last_themed_annotation_color_)
            last_annotation_color_ = nextThemed;
        last_themed_annotation_color_ = nextThemed;
    });
#if QT_VERSION >= QT_VERSION_CHECK(6, 3, 0) && QT_VERSION < QT_VERSION_CHECK(6, 10, 1)
    setTabBar(new DataSourceTabBar(this));
#endif
    if (application_flavor_is_wireshark()) {
        setAccessibleName(tr("Packet bytes"));
        setAccessibleDescription(tr("Displays the raw bytes of the selected packet in hexadecimal and ASCII."));
    } else {
        setAccessibleName(tr("Event data"));
        setAccessibleDescription(tr("Displays the raw data of the selected event."));
    }
    setTabPosition(QTabWidget::South);
    setDocumentMode(true);

    // Shrink down to a small but nonzero size in the main splitter.
    int one_em = fontMetrics().height();
    setMinimumSize(one_em, one_em);

    if (!edt_fixed) {
        connect(mainApp, &MainApplication::appInitialized, this, &DataSourceTab::connectToMainWindow);
    }
}

// Connects the byte view with the main window, acting on changes to the packet
// list selection. It MUST NOT be used with the packet dialog as that is
// independent of the selection in the packet list.
void DataSourceTab::connectToMainWindow()
{
    connect(this, &DataSourceTab::fieldSelected, mainApp->mainWindow(), &MainWindow::fieldSelected);
    connect(this, &DataSourceTab::fieldHighlight, mainApp->mainWindow(), &MainWindow::fieldHighlight);

    /* Connect change of packet selection */
    connect(mainApp->mainWindow(), &MainWindow::framesSelected, this, &DataSourceTab::DataSourceTab::selectedFrameChanged);
    connect(mainApp->mainWindow(), &MainWindow::setCaptureFile, this, &DataSourceTab::setCaptureFile);
    connect(mainApp->mainWindow(), &MainWindow::fieldSelected, this, &DataSourceTab::selectedFieldChanged);

    connect(mainApp->mainWindow(), &MainWindow::captureActive, this, &DataSourceTab::captureActive);
}

void DataSourceTab::captureActive(int cap)
{
    if (cap == 0)
    {
        QList<HexDataSourceView *> allBVTs = findChildren<HexDataSourceView *>();
        if (allBVTs.count() > 0)
        {
            HexDataSourceView * bvt = allBVTs.at(0);
            tvbuff_t * stored = bvt->tvb();

            if (! stored)
                selectedFrameChanged(QList<int>());
        }
    }
}

void DataSourceTab::addTab(const char *name, const struct data_source *source)
{

    if (count() == 1) { // Remove empty placeholder.
        BaseDataSourceView *cur_view = qobject_cast<BaseDataSourceView *>(currentWidget());
        if (cur_view && cur_view->isEmpty()) delete currentWidget();
    }

    BaseDataSourceView *data_source_view;
    tvbuff_t *tvb = get_data_source_tvb(source);
    QByteArray data;

    if (tvb) {
        int data_len = (int) tvb_captured_length(tvb);
        if (data_len > 0) {
            // Note: this does not copy the data and will be invalidated
            // when the tvbuff's real data becomes invalid (which is not
            // necessarily when the tvb itself becomes invalid.)
            data = QByteArray::fromRawData((const char *) tvb_get_ptr(tvb, 0, data_len), data_len);
        }
    }

    switch (get_data_source_media_type(source)) {
    case DS_MEDIA_TYPE_APPLICATION_JSON:
    {
        proto_node *root_node = nullptr;
        if (cap_file_ && cap_file_->edt && cap_file_->edt->tree) {
            root_node = cap_file_->edt->tree;
        }

        data_source_view = new JsonDataSourceView(data, root_node, this);
    }
        break;
    default:
    {
        packet_char_enc encoding = PACKET_CHAR_ENC_CHAR_ASCII;
        if (cap_file_ && cap_file_->current_frame) {
            encoding = (packet_char_enc)cap_file_->current_frame->encoding;
        }

        data_source_view = new HexDataSourceView(data, encoding, this);
    }
    }

    data_source_view->setAccessibleName(name);
    data_source_view->setMonospaceFont(mainApp->monospaceFont(true));

    if (tvb)
    {
        // There are some secondary data source tvbuffs whose data is not freed
        // when the epan_dissect_t is freed, but at some other point expected
        // to outlive the packet, generally when the capture file is closed.
        // If this is a PacketDialog, it can break that assumption.
        // To get around this, we deep copy their data when the file is closed.
        //
        // XXX: We could add a function to the tvbuff API and only do this if
        // there is no free_cb (a free_cb implies the data is freed at the
        // same time as the tvb, i.e. when leaving the packet.)
        if (is_fixed_packet_ && count() > 0) {
            connect(this, &DataSourceTab::detachData, data_source_view, &BaseDataSourceView::detachData);
        }
        // See above - this tvb is (expected to be) scoped to the packet, but
        // the real data is not necessarily so. If this is a PacketDialog
        // and such a secondary data source, then we MUST NOT use any tvb
        // function that accesses the real data after the capture file closes.
        // That includes via the ds_tvb item of a field_info in the tree.
        // proto_find_field_from_offset() is OK. See #14363.
        //
        // XXX: It sounds appealing to clone the secondary data source tvbs
        // and set them to be freed when the hex_data_source_view is freed, perhaps
        // even doing so only when the capture file is closing. However, while
        // relatively simple for the few number of secondary data sources, it
        // would be a pain to change the pointers for every field_info.
        data_source_view->setTvb(tvb);

        connect(mainApp, &MainApplication::zoomMonospaceFont, data_source_view, &BaseDataSourceView::setMonospaceFont);
        connect(data_source_view, &HexDataSourceView::byteSelected, this, &DataSourceTab::byteViewTextMarked);

        if (HexDataSourceView *hex_data_source_view = qobject_cast<HexDataSourceView *>(data_source_view)) {
            connect(hex_data_source_view, &HexDataSourceView::byteHovered, this, &DataSourceTab::byteViewTextHovered);
            connect(hex_data_source_view, &HexDataSourceView::byteViewSettingsChanged, this, &DataSourceTab::byteViewSettingsChanged);
            connect(this, &DataSourceTab::byteViewSettingsChanged, hex_data_source_view, &HexDataSourceView::updateByteViewSettings);
            connect(this, &DataSourceTab::byteViewUnmarkField, hex_data_source_view, &HexDataSourceView::unmarkField);
            connect(hex_data_source_view, &HexDataSourceView::addAnnotationRequested, this, &DataSourceTab::handleAddAnnotation);
            connect(hex_data_source_view, &HexDataSourceView::editAnnotationRequested, this, &DataSourceTab::handleEditAnnotation);
            connect(hex_data_source_view, &HexDataSourceView::removeAnnotationRequested, this, &DataSourceTab::handleRemoveAnnotation);
            connect(hex_data_source_view, &HexDataSourceView::offsetStartRequested, this, &DataSourceTab::handleSetOffsetStart);
            connect(hex_data_source_view, &HexDataSourceView::offsetEndRequested, this, &DataSourceTab::handleSetOffsetEnd);
            connect(hex_data_source_view, &HexDataSourceView::offsetMarkersCleared, this, &DataSourceTab::handleClearOffsetMarkers);
        }
    }

    int idx = QTabWidget::addTab(data_source_view, name);
    data_source_view->setTabIndex(idx);

    QTabWidget::setTabToolTip(idx, name);
}

int DataSourceTab::currentFrameNumber() const
{
    if (!cap_file_ || !cap_file_->current_frame) {
        return -1;
    }
    return static_cast<int>(cap_file_->current_frame->num);
}

void DataSourceTab::showAnnotationsSessionNotice()
{
    if (annotations_session_notice_shown_) {
        return;
    }

    annotations_session_notice_shown_ = true;
    if (mainApp && mainApp->mainWindow() && mainApp->mainWindow()->statusBar()) {
        mainApp->mainWindow()->statusBar()->showMessage(
            tr("Packet annotations are not saved and will be lost when the capture is closed."), 8000);
    }
}

void DataSourceTab::applyAnnotationsToViews()
{
    int frame = currentFrameNumber();
    QList<HexDataSourceView *> views = findChildren<HexDataSourceView *>();
    for (HexDataSourceView *view : views) {
        QVector<HexDataSourceView::ByteViewAnnotation> view_annotations;
        int data_len = view->dataSize();
        if (frame > 0 && data_len > 0) {
            for (const FrameByteAnnotation &ann : annotations_) {
                if (ann.frame != frame) {
                    continue;
                }
                if (ann.start < 0 || ann.length <= 0 || ann.start >= data_len) {
                    continue;
                }
                int clipped_len = qMin(ann.length, data_len - ann.start);
                if (clipped_len <= 0) {
                    continue;
                }
                HexDataSourceView::ByteViewAnnotation view_ann;
                view_ann.start = ann.start;
                view_ann.length = clipped_len;
                view_ann.color = ann.color;
                view_ann.comment = ann.comment;
                view_annotations.append(view_ann);
            }
        }
        view->setAnnotations(view_annotations);
    }
}

int DataSourceTab::findAnnotationIndexAt(int frame, int byte) const
{
    if (frame <= 0 || byte < 0) {
        return -1;
    }

    for (auto i = annotations_.size(); i > 0; ) {
        --i;
        const FrameByteAnnotation &ann = annotations_.at(i);
        if (ann.frame != frame) {
            continue;
        }
        if (byte >= ann.start && byte < ann.start + ann.length) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int DataSourceTab::findAnnotationIndexIntersecting(int frame, int start, int length) const
{
    if (frame <= 0 || start < 0 || length <= 0) {
        return -1;
    }
    int end = start + length - 1;

    for (auto i = annotations_.size(); i > 0; ) {
        --i;
        const FrameByteAnnotation &ann = annotations_.at(i);
        if (ann.frame != frame) {
            continue;
        }
        int ann_end = ann.start + ann.length - 1;
        if (ann.start <= end && ann_end >= start) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

HexDataSourceView *DataSourceTab::activeHexView() const
{
    return qobject_cast<HexDataSourceView *>(currentWidget());
}

void DataSourceTab::byteViewTextHovered(int idx)
{
    if (idx >= 0 && edt_)
    {
        BaseDataSourceView *source = qobject_cast<BaseDataSourceView *>(sender());
        tvbuff_t * tvb = source ? source->tvb() : nullptr;
        proto_tree * tree = edt_->tree;

        if (tvb && tree)
        {
            field_info * fi = proto_find_field_from_offset(tree, idx, tvb);
            if (fi)
            {
                FieldInformation finfo(fi, this);
                highlightedFieldChanged(&finfo);
                emit fieldHighlight(&finfo);
                return;
            }
        }
    }

    emit fieldHighlight((FieldInformation *)0);
}

void DataSourceTab::byteViewTextMarked(int idx)
{
    if (idx >= 0 && edt_)
    {
        BaseDataSourceView *source = qobject_cast<BaseDataSourceView *>(sender());
        tvbuff_t * tvb = source ? source->tvb() : nullptr;
        proto_tree * tree = edt_->tree;

        if (tvb && tree)
        {
            field_info * fi = proto_find_field_from_offset(tree, idx, tvb);
            if (fi)
            {
                FieldInformation finfo(fi, this);
                emit fieldSelected(&finfo);
                return;
            }
        }
    }

    emit fieldSelected((FieldInformation *)0);
}

void DataSourceTab::handleAddAnnotation()
{
    HexDataSourceView *view = qobject_cast<HexDataSourceView *>(sender());
    if (!view) {
        view = activeHexView();
    }
    if (!view) {
        return;
    }

    int frame = currentFrameNumber();
    if (frame <= 0) {
        return;
    }

    int sel_start = -1;
    int sel_length = 0;
    bool has_selection = view->selectionRange(&sel_start, &sel_length);
    if (!has_selection) {
        int ctx = view->contextByteOffset();
        if (ctx >= 0) {
            sel_start = ctx;
            sel_length = 1;
            has_selection = true;
        }
    }
    if (!has_selection || sel_length <= 0) {
        QMessageBox::information(this, tr("Packet Annotations"),
                                 tr("Select one or more bytes first."));
        return;
    }

    AnnotationEditDialog dialog(this);
    dialog.setWindowTitle(tr("Add Annotation"));
    dialog.setColor(last_annotation_color_);
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }

    FrameByteAnnotation ann;
    ann.frame = frame;
    ann.start = sel_start;
    ann.length = sel_length;
    ann.color = dialog.color();
    ann.comment = dialog.comment().trimmed();
    annotations_.append(ann);

    last_annotation_color_ = ann.color;
    showAnnotationsSessionNotice();
    applyAnnotationsToViews();
}

void DataSourceTab::handleEditAnnotation()
{
    HexDataSourceView *view = qobject_cast<HexDataSourceView *>(sender());
    if (!view) {
        view = activeHexView();
    }
    if (!view) {
        return;
    }

    int frame = currentFrameNumber();
    if (frame <= 0) {
        return;
    }

    int sel_start = -1;
    int sel_length = 0;
    bool has_selection = view->selectionRange(&sel_start, &sel_length);
    int ctx = view->contextByteOffset();
    int ann_idx = findAnnotationIndexAt(frame, ctx);
    if (ann_idx < 0 && has_selection) {
        ann_idx = findAnnotationIndexIntersecting(frame, sel_start, sel_length);
    }
    if (ann_idx < 0) {
        QMessageBox::information(this, tr("Packet Annotations"),
                                 tr("No annotation found at the selection."));
        return;
    }

    FrameByteAnnotation &ann = annotations_[ann_idx];

    AnnotationEditDialog dialog(this);
    dialog.setWindowTitle(tr("Edit Annotation"));
    dialog.setColor(ann.color);
    dialog.setComment(ann.comment);
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }

    ann.color = dialog.color();
    ann.comment = dialog.comment().trimmed();

    showAnnotationsSessionNotice();
    applyAnnotationsToViews();
}

void DataSourceTab::handleRemoveAnnotation()
{
    HexDataSourceView *view = qobject_cast<HexDataSourceView *>(sender());
    if (!view) {
        view = activeHexView();
    }
    if (!view) {
        return;
    }

    int frame = currentFrameNumber();
    if (frame <= 0) {
        return;
    }

    int sel_start = -1;
    int sel_length = 0;
    bool has_selection = view->selectionRange(&sel_start, &sel_length);
    int ctx = view->contextByteOffset();
    int ann_idx = findAnnotationIndexAt(frame, ctx);
    if (ann_idx < 0 && has_selection) {
        ann_idx = findAnnotationIndexIntersecting(frame, sel_start, sel_length);
    }
    if (ann_idx < 0) {
        QMessageBox::information(this, tr("Packet Annotations"),
                                 tr("No annotation found at the selection."));
        return;
    }

    annotations_.removeAt(ann_idx);
    showAnnotationsSessionNotice();
    applyAnnotationsToViews();
}

void DataSourceTab::handleSetOffsetStart(int byte)
{
    HexDataSourceView *view = qobject_cast<HexDataSourceView *>(sender());
    if (!view) {
        view = activeHexView();
    }
    if (!view || byte < 0) {
        return;
    }

    view->setOffsetStart(byte);
    view->setOffsetEnd(-1);

    if (mainApp && mainApp->mainWindow() && mainApp->mainWindow()->statusBar()) {
        mainApp->mainWindow()->statusBar()->showMessage(
            tr("Start byte set: %1").arg(byte), 5000);
    }
}

void DataSourceTab::handleSetOffsetEnd(int byte)
{
    HexDataSourceView *view = qobject_cast<HexDataSourceView *>(sender());
    if (!view) {
        view = activeHexView();
    }
    if (!view || byte < 0) {
        return;
    }

    int start = view->offsetStart();
    if (start < 0) {
        if (mainApp && mainApp->mainWindow() && mainApp->mainWindow()->statusBar()) {
            mainApp->mainWindow()->statusBar()->showMessage(
                tr("Set start byte first."), 5000);
        }
        return;
    }

    view->setOffsetEnd(byte);

    int signed_offset = byte - start;
    int abs_offset = qAbs(signed_offset);

    QString msg = tr("Start byte (absolute): %1\nEnd byte (absolute): %2\nDistance (absolute, bytes): %3\nDistance (signed, bytes): %4")
                      .arg(start)
                      .arg(byte)
                      .arg(abs_offset)
                      .arg(signed_offset);

    int ref_start = -1;
    int ref_len = -1;
    QString ref_label;

    if (view->selectedFieldIsProtocol()) {
        ref_start = view->selectedFieldStart();
        ref_len = view->selectedFieldLength();
        ref_label = tr("selected protocol");
    } else if (view->selectedFieldUsesOwnRange()) {
        ref_start = view->selectedFieldStart();
        ref_len = view->selectedFieldLength();
        ref_label = tr("selected field");
    } else {
        ref_start = view->selectedProtocolStart();
        ref_len = view->selectedProtocolLength();
        ref_label = tr("parent protocol");
    }

    if (ref_start < 0 || ref_len <= 0) {
        ref_start = view->selectedFieldStart();
        ref_len = view->selectedFieldLength();
        ref_label = tr("selected field");
    }

    if (ref_start >= 0 && ref_len > 0) {
        int ref_end = ref_start + ref_len - 1;
        msg.append(tr("\nReference range (%1): start %2, length %3")
                       .arg(ref_label)
                       .arg(ref_start)
                       .arg(ref_len));
        if (start >= ref_start && start <= ref_end &&
                byte >= ref_start && byte <= ref_end) {
            msg.append(tr("\nStart byte (relative to reference): %1\nEnd byte (relative to reference): %2")
                           .arg(start - ref_start)
                           .arg(byte - ref_start));
        } else {
            msg.append(tr("\nRelative to reference: n/a (outside reference range)"));
        }
    }

    QMessageBox::information(this, tr("Compute Offset"), msg);
}

void DataSourceTab::handleClearOffsetMarkers()
{
    HexDataSourceView *view = qobject_cast<HexDataSourceView *>(sender());
    if (!view) {
        view = activeHexView();
    }
    if (!view) {
        return;
    }

    view->clearOffsetMarkers();
    if (mainApp && mainApp->mainWindow() && mainApp->mainWindow()->statusBar()) {
        mainApp->mainWindow()->statusBar()->showMessage(
            tr("Offset markers cleared."), 5000);
    }
}

BaseDataSourceView *DataSourceTab::findDataSourceViewForTvb(tvbuff_t * search_tvb, int * idx)
{
    if (! search_tvb) {
        return nullptr;
    }

    BaseDataSourceView *item = nullptr;

    QList<BaseDataSourceView *> all_sources = findChildren<BaseDataSourceView *>();
    for (int i = 0; i < all_sources.size() && !item; ++i)
    {
        BaseDataSourceView * dsv = all_sources.at(i);
        tvbuff_t * stored = dsv->tvb();
        if (stored == search_tvb)
        {
            int wdgIdx = dsv->tabIndex();
            if (idx)
            {
                *idx = wdgIdx;
            }
            item = qobject_cast<BaseDataSourceView *>(widget(wdgIdx));
        }
    }

    return item;
}

void DataSourceTab::tabInserted(int tab_index) {
    setTabsVisible();
    QTabWidget::tabInserted(tab_index);
}

void DataSourceTab::tabRemoved(int tab_index) {
    setTabsVisible();
    QTabWidget::tabRemoved(tab_index);
}

void DataSourceTab::setTabsVisible() {
    if (count() > 1)
        tabBar()->show();
    else
        tabBar()->hide();
}

void DataSourceTab::selectedFrameChanged(QList<int> frames)
{
    if (!is_fixed_packet_) {
        /* If this is not a fixed packet (not the packet dialog), it must be the
         * byte view associated with the packet list. */
        if (cap_file_ && cap_file_->edt) {
            /* Assumes that this function is called as a result of selecting a
             * packet in the packet list (PacketList::selectionChanged). That
             * invokes "cf_select_packet" which will update "cap_file_->edt". */
            edt_ = cap_file_->edt;
        } else {
            /* capture file is closing or packet is deselected. */
            edt_ = NULL;
        }
    }

    /* We don't need to call clear() on Linux because Qt will remove the child
     * widgets when they're deleted, but need to on MacOS and maybe Windows.
     * We want to hide the QTabWidget so that the QTabBar doesn't calculate
     * the sizeHint for each tab remaining every time a tab is removed, instead
     * deferring until later. */
    /* !isHidden and isVisible are different; during startup this widget might
     * not be visible because its parent is not (i.e., the Welcome Screen is
     * being shown instead), but whether it's hidden or not is set by the layout
     * regardless. */
    bool save_hidden = isHidden();
    setVisible(false);
#if QT_VERSION < QT_VERSION_CHECK(6, 8, 2)
    /* Pick up this performance improvement from Qt 6.8.2:
     * https://github.com/qt/qtbase/commit/8717c1752f9b72ac7c028b722f0a068e84e64eca
     * https://github.com/qt/qtbase/commit/828ece4743a0d44f7f37f1a980dec076783a8abe
     */
    int c = count();
    while (c)
        removeTab(--c);
#else
    clear();
#endif
    qDeleteAll(findChildren<BaseDataSourceView *>(QString(), Qt::FindDirectChildrenOnly));
    setVisible(!save_hidden);

    /* only show the bytes for single selections */
    if (frames.count() == 1)
    {
        if (! cap_file_ || ! cap_file_->edt)
            return;

        /* Unfortunately in Qt 6.3 and later adding a tab still causes a
         * relayout thanks to the following commit:
         * https://github.com/qt/qtbase/commit/02164b292f002b051f34a88871145415fad94f32
         * Filed: https://bugreports.qt.io/browse/QTBUG-141187
         */
        setVisible(false);
        /* This code relies on a dissection, which had happened somewhere else. It also does not
         * really check, if the dissection happened for the correct frame. In the future we might
         * rewrite this for directly calling the dissection engine here. */
        GSList *src_le;
        for (src_le = edt_->pi.data_src; src_le != NULL; src_le = src_le->next) {
            struct data_source *source;
            char* source_description;
            source = (struct data_source *)src_le->data;
            source_description = get_data_source_description(source);
            addTab(source_description, source);
            wmem_free(NULL, source_description);
        }
        setVisible(!save_hidden);
    }
    else
        addTab("PlaceHolder", 0);

    setCurrentIndex(0);
    applyAnnotationsToViews();
}

void DataSourceTab::selectedFieldChanged(FieldInformation *selected)
{
    // We need to handle both selection and deselection.
    BaseDataSourceView * data_source_view = qobject_cast<BaseDataSourceView *>(currentWidget());
    int f_start = -1, f_length = -1;
    int p_start = -1, p_length = -1;
    int fa_start = -1, fa_length = -1;
    bool selected_is_protocol = false;
    bool selected_force_own_range = false;

    if (selected) {
        if (selected->parent() == this) {
            // We only want inbound signals.
            return;
        }
        const field_info *fi = selected->fieldInfo();
        FieldInformation::HeaderInfo header = selected->headerInfo();
        selected_is_protocol = header.isValid && header.type == FT_PROTOCOL;
        if (header.isValid) {
            selected_force_own_range = (header.abbreviation == QLatin1String("tcp.segment_data") ||
                                       header.abbreviation == QLatin1String("tcp.payload"));
        }

        int idx = 0;
        if (fi) {
            data_source_view = findDataSourceViewForTvb(fi->ds_tvb, &idx);
        }

        if (cap_file_->search_in_progress && (cap_file_->hex || (cap_file_->string && cap_file_->packet_data))) {
            // In the hex view, only highlight the target bytes or string. The entire
            // field can then be displayed by clicking on any of the bytes in the field.
            f_start = (int)cap_file_->search_pos;
            f_length = (int) cap_file_->search_len;
        } else {
            f_start = selected->position().start;
            f_length = selected->position().length;
        }

        setCurrentIndex(idx);

        FieldInformation *parentField = selected->parentField();

        p_start = parentField->position().start;
        p_length = parentField->position().length;
        fa_start = selected->appendix().start;
        fa_length = selected->appendix().length;

        delete parentField;
    }

    if (data_source_view)
    {
        data_source_view->markField(f_start, f_length);
        data_source_view->markProtocol(p_start, p_length);
        data_source_view->markAppendix(fa_start, fa_length);
        HexDataSourceView *hex_view = qobject_cast<HexDataSourceView *>(data_source_view);
        if (hex_view) {
            hex_view->setSelectedFieldIsProtocol(selected_is_protocol);
            hex_view->setSelectedFieldUsesOwnRange(selected_force_own_range);
        }
    } else {
        emit byteViewUnmarkField();
    }
}
void DataSourceTab::highlightedFieldChanged(FieldInformation *highlighted)
{
    BaseDataSourceView * data_source_view = qobject_cast<BaseDataSourceView *>(currentWidget());
    if (!highlighted || !data_source_view) {
        return;
    }

    int f_start = -1, f_length = -1;

    if (cap_file_->search_in_progress && (cap_file_->hex || (cap_file_->string && cap_file_->packet_data))) {
        // In the hex view, only highlight the target bytes or string. The entire
        // field can then be displayed by clicking on any of the bytes in the field.
        f_start = cap_file_->search_pos - cap_file_->search_len + 1;
        f_length = (int) cap_file_->search_len;
    } else {
        f_start = highlighted->position().start;
        f_length = highlighted->position().length;
    }

    data_source_view->markField(f_start, f_length, false, true);
}

void DataSourceTab::setCaptureFile(capture_file *cf)
{
    annotations_.clear();
    annotations_session_notice_shown_ = false;
    selectedFrameChanged(QList<int>());

    cap_file_ = cf;
    applyAnnotationsToViews();
}

void DataSourceTab::captureFileClosing()
{
    emit detachData();
    annotations_.clear();
    annotations_session_notice_shown_ = false;
}

#if QT_VERSION >= QT_VERSION_CHECK(6, 3, 0) && QT_VERSION < QT_VERSION_CHECK(6, 10, 1)
#include "data_source_tab.moc"
#endif
