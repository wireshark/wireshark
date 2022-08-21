/* display_filter_edit.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/dfilter/dfilter.h>

#include <ui/recent.h>

#include <wsutil/utf8_entities.h>

#include "main_application.h"

#include <ui/qt/widgets/display_filter_edit.h>
#include "filter_dialog.h"
#include <ui/qt/widgets/stock_icon_tool_button.h>
#include <ui/qt/widgets/syntax_line_edit.h>
#include <ui/qt/utils/wireshark_mime_data.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/models/pref_models.h>
#include <ui/qt/filter_action.h>
#include <ui/qt/display_filter_expression_dialog.h>
#include <ui/qt/main_window.h>

#include <QAction>
#include <QAbstractItemView>
#include <QComboBox>
#include <QCompleter>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QStringListModel>
#include <QWidget>
#include <QObject>
#include <QDrag>
#include <QDropEvent>
#include <QMimeData>
#include <QJsonDocument>
#include <QJsonObject>

// To do:
// - Get rid of shortcuts and replace them with "n most recently applied filters"?
// - We need simplified (button- and dropdown-free) versions for use in dialogs and field-only checking.
// - Add a separator or otherwise distinguish between recent items and fields
//   in the completion dropdown.

#ifdef __APPLE__
#define DEFAULT_MODIFIER UTF8_PLACE_OF_INTEREST_SIGN
#else
#define DEFAULT_MODIFIER "Ctrl-"
#endif

// proto.c:fld_abbrev_chars
static const QString fld_abbrev_chars_ = "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

DisplayFilterEdit::DisplayFilterEdit(QWidget *parent, DisplayFilterEditType type) :
    SyntaxLineEdit(parent),
    type_(type),
    save_action_(NULL),
    remove_action_(NULL),
    actions_(Q_NULLPTR),
    bookmark_button_(NULL),
    clear_button_(NULL),
    apply_button_(NULL),
    leftAlignActions_(false),
    last_applied_(QString())
{
    setAccessibleName(tr("Display filter entry"));

    completion_model_ = new QStringListModel(this);
    setCompleter(new QCompleter(completion_model_, this));
    setCompletionTokenChars(fld_abbrev_chars_);

    QString buttonStyle = QString(
        "QToolButton {"
        "  border: none;"
        "  background: transparent;" // Disables platform style on Windows.
        "  padding: 0 0 0 0;"
        "}"
        "QToolButton::menu-indicator {"
        "  image: none;"
        "}"
    );

    leftAlignActions_ = recent.gui_geometry_leftalign_actions;

    if (type_ == DisplayFilterToApply) {
        bookmark_button_ = new StockIconToolButton(this, "x-display-filter-bookmark");
        bookmark_button_->setMenu(new QMenu(bookmark_button_));
        bookmark_button_->setPopupMode(QToolButton::InstantPopup);
        bookmark_button_->setToolTip(tr("Manage saved bookmarks."));
        bookmark_button_->setIconSize(QSize(14, 14));
        bookmark_button_->setStyleSheet(buttonStyle);
        bookmark_button_->setVisible(false);

        clear_button_ = new StockIconToolButton(this, "x-filter-clear");
        clear_button_->setToolTip(tr("Clear display filter"));
        clear_button_->setIconSize(QSize(14, 14));
        clear_button_->setStyleSheet(buttonStyle);
        clear_button_->setVisible(false);

        apply_button_ = new StockIconToolButton(this, "x-filter-apply");
        apply_button_->setEnabled(false);
        apply_button_->setToolTip(tr("Apply display filter"));
        apply_button_->setIconSize(QSize(24, 14));
        apply_button_->setStyleSheet(buttonStyle);
        apply_button_->setVisible(false);

        connect(clear_button_, &StockIconToolButton::clicked, this, &DisplayFilterEdit::clearFilter);
        connect(apply_button_, &StockIconToolButton::clicked, this, &DisplayFilterEdit::applyDisplayFilter);
        connect(this, &DisplayFilterEdit::returnPressed, this, &DisplayFilterEdit::applyDisplayFilter);
    }

    connect(this, &DisplayFilterEdit::textChanged, this,
            static_cast<void (DisplayFilterEdit::*)(const QString &)>(&DisplayFilterEdit::checkFilter));

    connect(mainApp, &MainApplication::appInitialized, this, &DisplayFilterEdit::updateBookmarkMenu);
    connect(mainApp, &MainApplication::displayFilterListChanged, this, &DisplayFilterEdit::updateBookmarkMenu);
    connect(mainApp, SIGNAL(preferencesChanged()), this, SLOT(checkFilter()));

    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(connectToMainWindow()));
}

void DisplayFilterEdit::connectToMainWindow()
{
    connect(this, SIGNAL(filterPackets(QString, bool)), mainApp->mainWindow(), SLOT(filterPackets(QString, bool)));
    connect(this, SIGNAL(showPreferencesDialog(QString)),
            mainApp->mainWindow(), SLOT(showPreferencesDialog(QString)));
    connect(mainApp->mainWindow(), SIGNAL(displayFilterSuccess(bool)),
            this, SLOT(displayFilterSuccess(bool)));
}

void DisplayFilterEdit::contextMenuEvent(QContextMenuEvent *event) {
    QMenu *menu = this->createStandardContextMenu();
    menu->setAttribute(Qt::WA_DeleteOnClose);

    if (menu->actions().count() <= 0) {
        menu->deleteLater();
        return;
    }

    QAction * first = menu->actions().at(0);

    QAction * na = new QAction(tr("Left align buttons"), this);
    na->setCheckable(true);
    na->setChecked(leftAlignActions_);
    connect(na, &QAction::triggered, this, &DisplayFilterEdit::triggerAlignementAction);
    menu->addSeparator();
    menu->addAction(na);

    na = new QAction(tr("Display Filter Expression…"), this);
    connect(na, &QAction::triggered, this, &DisplayFilterEdit::displayFilterExpression);
    menu->insertAction(first, na);

    menu->insertSeparator(first);

    menu->popup(event->globalPos());
}

void DisplayFilterEdit::triggerAlignementAction()
{
    leftAlignActions_ = ! leftAlignActions_;
    if (qobject_cast<QAction *>(sender()))
        qobject_cast<QAction *>(sender())->setChecked(leftAlignActions_);

    recent.gui_geometry_leftalign_actions = leftAlignActions_;
    write_recent();

    alignActionButtons();
}

void DisplayFilterEdit::alignActionButtons()
{
    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    QSize bksz, cbsz, apsz;
    bksz = apsz = cbsz = QSize(0,0);

    if (type_ == DisplayFilterToApply) {
        bookmark_button_->setMinimumHeight(contentsRect().height());
        bookmark_button_->setMaximumHeight(contentsRect().height());
        bksz = bookmark_button_->sizeHint();

        apsz = apply_button_->sizeHint();
        apply_button_->setMinimumHeight(contentsRect().height());
        apply_button_->setMaximumHeight(contentsRect().height());

        if (clear_button_->isVisible())
        {
            cbsz = clear_button_->sizeHint();
            clear_button_->setMinimumHeight(contentsRect().height());
            clear_button_->setMaximumHeight(contentsRect().height());
        }
    }

    int leftPadding = frameWidth + 1;
    int leftMargin = bksz.width();
    int rightMargin = cbsz.width() + apsz.width() + frameWidth + 1;
    if (leftAlignActions_)
    {
        leftMargin = rightMargin + bksz.width() + 2;
        rightMargin = 0;
    }

    setStyleSheet(QString(
            "DisplayFilterEdit {"
            "  padding-left: %1px;"
            "  margin-left: %2px;"
            "  margin-right: %3px;"
            "}"
            )
            .arg(leftPadding)
            .arg(leftMargin)
            .arg(rightMargin)
    );

    if (apply_button_) {
        if (! leftAlignActions_)
        {
            apply_button_->move(contentsRect().right() - frameWidth - apsz.width(),
                            contentsRect().top());
        } else {
            apply_button_->move(contentsRect().left() + bookmark_button_->width(), contentsRect().top());
        }
    }

    if (clear_button_ && apply_button_) {
        if (! leftAlignActions_)
        {
            clear_button_->move(contentsRect().right() - frameWidth - cbsz.width() - apsz.width(),
                            contentsRect().top());
        } else {
            int width = bookmark_button_->width() + apply_button_->width();
            clear_button_->move(contentsRect().left() + width, contentsRect().top());
        }
    }

    update();
}

void DisplayFilterEdit::setDefaultPlaceholderText()
{
    switch (type_) {

    case DisplayFilterToApply:
        placeholder_text_ = QString(tr("Apply a display filter %1 <%2/>")).arg(UTF8_HORIZONTAL_ELLIPSIS)
    .arg(DEFAULT_MODIFIER);
        break;

    case DisplayFilterToEnter:
        placeholder_text_ = QString(tr("Enter a display filter %1")).arg(UTF8_HORIZONTAL_ELLIPSIS);
        break;

    case ReadFilterToApply:
        placeholder_text_ = QString(tr("Apply a read filter %1")).arg(UTF8_HORIZONTAL_ELLIPSIS);
        break;
    }
    setPlaceholderText(placeholder_text_);
}

void DisplayFilterEdit::paintEvent(QPaintEvent *evt) {
    SyntaxLineEdit::paintEvent(evt);

    if (bookmark_button_ && isEnabled()) {

        if (! bookmark_button_->isVisible())
        {
            bookmark_button_->setVisible(true);
            apply_button_->setVisible(true);
            setDefaultPlaceholderText();
            alignActionButtons();
            return;
        }

        // Draw the right border by hand. We could try to do this in the
        // style sheet but it's a pain.
#ifdef Q_OS_MAC
        QColor divider_color = Qt::gray;
#else
        QColor divider_color = palette().shadow().color();
#endif
        QPainter painter(this);
        painter.setPen(divider_color);
        QRect cr = contentsRect();
        int xpos = 0;
        if (leftAlignActions_)
        {
            xpos = 1 + bookmark_button_->size().width() + apply_button_->size().width();
            if (clear_button_->isVisible())
                xpos += clear_button_->size().width();
        }
        else
            xpos = bookmark_button_->size().width();

        painter.drawLine(xpos, cr.top(), xpos, cr.bottom() + 1);
    }
}

void DisplayFilterEdit::resizeEvent(QResizeEvent *)
{
    alignActionButtons();
}

void DisplayFilterEdit::focusOutEvent(QFocusEvent *event)
{
    if (syntaxState() == Valid) {
        emit popFilterSyntaxStatus();
        setToolTip(QString());
    }
    SyntaxLineEdit::focusOutEvent(event);
}

bool DisplayFilterEdit::checkFilter()
{
    checkFilter(text());

    return syntaxState() != Invalid;
}

void DisplayFilterEdit::checkFilter(const QString& filter_text)
{
    if (text().length() == 0 && actions_ && actions_->checkedAction())
        actions_->checkedAction()->setChecked(false);

    if (clear_button_) {

        if (filter_text.length() > 0)
            clear_button_->setVisible(true);
        else if (last_applied_.length() > 0)
            setPlaceholderText(tr("Current filter: %1").arg(last_applied_));
        else if (filter_text.length() <= 0 && last_applied_.length() <= 0)
            clear_button_->setVisible(false);

        alignActionButtons();
    }

    if (filter_text.length() <= 0)
        mainApp->popStatus(MainApplication::FilterSyntax);

    emit popFilterSyntaxStatus();
    if (!checkDisplayFilter(filter_text))
        return;

    switch (syntaxState()) {
    case Deprecated:
    {
        mainApp->pushStatus(MainApplication::FilterSyntax, syntaxErrorMessage());
        setToolTip(syntaxErrorMessage());
        break;
    }
    case Invalid:
    {
        mainApp->pushStatus(MainApplication::FilterSyntax, syntaxErrorMessage());
        setToolTip(syntaxErrorMessageFull());
        break;
    }
    default:
        setToolTip(QString());
        break;
    }

    if (bookmark_button_) {

        bookmark_button_->setStockIcon("x-display-filter-bookmark");
        if (remove_action_ && save_action_)
        {
            remove_action_->setEnabled(false);
            save_action_->setEnabled(false);
        }

        if (filter_text.length() > 0)
        {
            bool enable_save_action = false;
            bool match = false;

            FilterListModel model(FilterListModel::Display);
            QModelIndex idx = model.findByExpression(filter_text);
            if (idx.isValid()) {
                match = true;

                bookmark_button_->setStockIcon("x-filter-matching-bookmark");
                if (remove_action_) {
                    remove_action_->setData(text());
                    remove_action_->setEnabled(true);
                }
            } else {
                bookmark_button_->setStockIcon("x-display-filter-bookmark");
                if (remove_action_) {
                    remove_action_->setEnabled(false);
                }
            }

            if (!match && (syntaxState() == Valid || syntaxState() == Deprecated) && !filter_text.isEmpty()) {
                enable_save_action = true;
            }
            if (save_action_) {
                save_action_->setEnabled(enable_save_action);
            }
        }

        apply_button_->setEnabled(syntaxState() != Invalid);
    }
}

void DisplayFilterEdit::updateBookmarkMenu()
{
    if (!bookmark_button_)
        return;

    QMenu *bb_menu = bookmark_button_->menu();
    bb_menu->clear();

    save_action_ = bb_menu->addAction(tr("Save this filter"));
    connect(save_action_, &QAction::triggered, this, &DisplayFilterEdit::saveFilter);
    remove_action_ = bb_menu->addAction(tr("Remove this filter"));
    connect(remove_action_, &QAction::triggered, this, &DisplayFilterEdit::removeFilter);
    QAction *manage_action = bb_menu->addAction(tr("Manage Display Filters"));
    connect(manage_action, &QAction::triggered, this, &DisplayFilterEdit::showFilters);
    QAction *expr_action = bb_menu->addAction(tr("Filter Button Preferences..."));
    connect(expr_action, &QAction::triggered, this, &DisplayFilterEdit::showExpressionPrefs);
    bb_menu->addSeparator();

    FilterListModel model(FilterListModel::Display);
    QModelIndex idx = model.findByExpression(text());

    int one_em = bb_menu->fontMetrics().height();

    if (! actions_)
        actions_ = new QActionGroup(this);

    for (int row = 0; row < model.rowCount(); row++)
    {
        QModelIndex nameIdx = model.index(row, FilterListModel::ColumnName);
        QString name = nameIdx.data().toString();
        QString expr = model.index(row, FilterListModel::ColumnExpression).data().toString();
        QString prep_text = QString("%1: %2").arg(name).arg(expr);

        prep_text = bb_menu->fontMetrics().elidedText(prep_text, Qt::ElideRight, one_em * 40);
        QAction * prep_action = bb_menu->addAction(prep_text);
        prep_action->setCheckable(true);
        if (nameIdx == idx)
            prep_action->setChecked(true);

        prep_action->setProperty("display_filter", expr);
        actions_->addAction(prep_action);

        connect(prep_action, &QAction::triggered, this, &DisplayFilterEdit::applyOrPrepareFilter);
    }

    checkFilter();
}

// GTK+ behavior:
// - Operates on words (proto.c:fld_abbrev_chars).
// - Popup appears when you enter or remove text.

// Our behavior:
// - Operates on words (fld_abbrev_chars_).
// - Popup appears when you enter or remove text.
// - Popup appears when you move the cursor.
// - Popup does not appear when text is selected.
// - Recent and saved display filters in popup when editing first word.

// ui/gtk/filter_autocomplete.c:build_autocompletion_list
void DisplayFilterEdit::buildCompletionList(const QString &field_word)
{
    // Push a hint about the current field.
    if (syntaxState() == Valid) {
        mainApp->popStatus(MainApplication::FilterSyntax);

        header_field_info *hfinfo = proto_registrar_get_byname(field_word.toUtf8().constData());
        if (hfinfo) {
            QString cursor_field_msg = QString("%1: %2")
                    .arg(hfinfo->name)
                    .arg(ftype_pretty_name(hfinfo->type));
            mainApp->pushStatus(MainApplication::FilterSyntax, cursor_field_msg);
        }
    }

    if (field_word.length() < 1) {
        completion_model_->setStringList(QStringList());
        return;
    }

    // Grab matching display filters from our parent combo and from the
    // saved display filters file. Skip ones that look like single fields
    // and assume they will be added below.
    QStringList complex_list;
    QComboBox *df_combo = qobject_cast<QComboBox *>(parent());
    if (df_combo) {
        for (int i = 0; i < df_combo->count() ; i++) {
            QString recent_filter = df_combo->itemText(i);

            if (isComplexFilter(recent_filter)) {
                complex_list << recent_filter;
            }
        }
    }
    FilterListModel model(FilterListModel::Display);
    for (int row = 0; row < model.rowCount(); row++)
    {
        QString saved_filter = model.index(row, FilterListModel::ColumnExpression).data().toString();

        if (isComplexFilter(saved_filter) && !complex_list.contains(saved_filter)) {
            complex_list << saved_filter;
        }
    }

    completion_model_->setStringList(complex_list);
    completer()->setCompletionPrefix(field_word);

    void *proto_cookie;
    QStringList field_list;
    int field_dots = static_cast<int>(field_word.count('.')); // Some protocol names (_ws.expert) contain periods.
    for (int proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1; proto_id = proto_get_next_protocol(&proto_cookie)) {
        protocol_t *protocol = find_protocol_by_id(proto_id);
        if (!proto_is_protocol_enabled(protocol)) continue;

        const QString pfname = proto_get_protocol_filter_name(proto_id);
        field_list << pfname;

        // Add fields only if we're past the protocol name and only for the
        // current protocol.
        if (field_dots > pfname.count('.')) {
            void *field_cookie;
            const QByteArray fw_ba = field_word.toUtf8(); // or toLatin1 or toStdString?
            const char *fw_utf8 = fw_ba.constData();
            gsize fw_len = (gsize) strlen(fw_utf8);
            for (header_field_info *hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo; hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie)) {
                if (hfinfo->same_name_prev_id != -1) continue; // Ignore duplicate names.

                if (!g_ascii_strncasecmp(fw_utf8, hfinfo->abbrev, fw_len)) {
                    if ((gsize) strlen(hfinfo->abbrev) != fw_len) field_list << hfinfo->abbrev;
                }
            }
        }
    }
    field_list.sort();

    completion_model_->setStringList(complex_list + field_list);
    completer()->setCompletionPrefix(field_word);
}

void DisplayFilterEdit::clearFilter()
{
    clear();

    last_applied_ = QString();
    updateClearButton();

    emit filterPackets(QString(), true);
}

void DisplayFilterEdit::applyDisplayFilter()
{
    if (syntaxState() == Invalid)
        return;

    if (text().length() > 0)
        last_applied_ = text();

    updateClearButton();

    emit filterPackets(text(), true);
}

void DisplayFilterEdit::updateClearButton()
{
    setDefaultPlaceholderText();
    clear_button_->setVisible(!text().isEmpty());
    alignActionButtons();
}

void DisplayFilterEdit::displayFilterSuccess(bool success)
{
    if (apply_button_)
        apply_button_->setEnabled(!success);
}

void DisplayFilterEdit::changeEvent(QEvent* event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            setDefaultPlaceholderText();
            break;
        default:
            break;
        }
    }
    SyntaxLineEdit::changeEvent(event);
}

void DisplayFilterEdit::saveFilter()
{
    FilterDialog *display_filter_dlg = new FilterDialog(window(), FilterDialog::DisplayFilter, text());
    display_filter_dlg->setWindowModality(Qt::ApplicationModal);
    display_filter_dlg->setAttribute(Qt::WA_DeleteOnClose);
    display_filter_dlg->show();
}

void DisplayFilterEdit::removeFilter()
{
    if (! actions_ || ! actions_->checkedAction())
        return;

    QAction *ra = actions_->checkedAction();
    if (ra->property("display_filter").toString().isEmpty())
        return;

    QString remove_filter = ra->property("display_filter").toString();

    FilterListModel model(FilterListModel::Display);
    QModelIndex idx = model.findByExpression(remove_filter);

    if (idx.isValid())
    {
        model.removeFilter(idx);
        model.saveList();
    }

    updateBookmarkMenu();
}

void DisplayFilterEdit::showFilters()
{
    FilterDialog *display_filter_dlg = new FilterDialog(window(), FilterDialog::DisplayFilter);
    display_filter_dlg->setWindowModality(Qt::ApplicationModal);
    display_filter_dlg->setAttribute(Qt::WA_DeleteOnClose);
    display_filter_dlg->show();
}

void DisplayFilterEdit::showExpressionPrefs()
{
    emit showPreferencesDialog(PrefsModel::typeToString(PrefsModel::FilterButtons));
}

void DisplayFilterEdit::applyOrPrepareFilter()
{
    QAction *pa = qobject_cast<QAction*>(sender());
    if (! pa || pa->property("display_filter").toString().isEmpty())
        return;

    QString filterText = pa->property("display_filter").toString();
    last_applied_ = filterText;
    setText(filterText);

    // Holding down the Shift key will only prepare filter.
    if (!(QApplication::keyboardModifiers() & Qt::ShiftModifier)) {
        applyDisplayFilter();
    }
}

void DisplayFilterEdit::dragEnterEvent(QDragEnterEvent *event)
{
    if (! event || ! event->mimeData())
        return;

    if (qobject_cast<const ToolbarEntryMimeData *>(event->mimeData()) ||
            event->mimeData()->hasFormat(WiresharkMimeData::DisplayFilterMimeType)) {
        if (event->source() != this)
        {
            event->setDropAction(Qt::CopyAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    } else {
        event->ignore();
    }
}

void DisplayFilterEdit::dragMoveEvent(QDragMoveEvent *event)
{
    if (! event || ! event->mimeData())
        return;

    if (qobject_cast<const ToolbarEntryMimeData *>(event->mimeData()) ||
            event->mimeData()->hasFormat(WiresharkMimeData::DisplayFilterMimeType)) {
        if (event->source() != this)
        {
            event->setDropAction(Qt::CopyAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    } else {
        event->ignore();
    }
}

void DisplayFilterEdit::dropEvent(QDropEvent *event)
{
    if (! event || ! event->mimeData())
        return;

    QString filterText = "";
    if (event->mimeData()->hasFormat(WiresharkMimeData::DisplayFilterMimeType))
    {
        QByteArray jsonData = event->mimeData()->data(WiresharkMimeData::DisplayFilterMimeType);
        QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonData);
        if (! jsonDoc.isObject())
            return;

        QJsonObject data = jsonDoc.object();

        if ((QApplication::keyboardModifiers() & Qt::AltModifier) && data.contains("field"))
            filterText = data["field"].toString();
        else if (data.contains("filter"))
            filterText = data["filter"].toString();
    }
    else if (qobject_cast<const ToolbarEntryMimeData *>(event->mimeData()))
    {
        const ToolbarEntryMimeData * data = qobject_cast<const ToolbarEntryMimeData *>(event->mimeData());

        filterText = data->filter();
    }

    /* Moving items around */
    if (filterText.length() > 0) {
        if (event->source() != this)
        {
            event->setDropAction(Qt::CopyAction);
            event->accept();

            bool prepare = QApplication::keyboardModifiers() & Qt::ShiftModifier;

            if (text().length() > 0 || QApplication::keyboardModifiers() & Qt::MetaModifier)
            {
                createFilterTextDropMenu(event, prepare, filterText);
                return;
            }

            last_applied_ = filterText;
            setText(filterText);

            // Holding down the Shift key will only prepare filter.
            if (! prepare) {
                applyDisplayFilter();
            }

        } else {
            event->acceptProposedAction();
        }

    } else {
        event->ignore();
    }
}

void DisplayFilterEdit::createFilterTextDropMenu(QDropEvent *event, bool prepare, QString filterText)
{
    if (filterText.isEmpty())
        return;

    FilterAction::Action filterAct = prepare ? FilterAction::ActionPrepare : FilterAction::ActionApply;
    QMenu * applyMenu = FilterAction::createFilterMenu(filterAct, filterText, true, this);
    applyMenu->setAttribute(Qt::WA_DeleteOnClose);

#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
    applyMenu->popup(this->mapToGlobal(event->position().toPoint()));
#else
    applyMenu->popup(this->mapToGlobal(event->pos()));
#endif
}

void DisplayFilterEdit::displayFilterExpression()
{
    DisplayFilterExpressionDialog *dfe_dialog = new DisplayFilterExpressionDialog(this);

    connect(dfe_dialog, &DisplayFilterExpressionDialog::insertDisplayFilter,
            this, &DisplayFilterEdit::insertFilter);

    dfe_dialog->show();
}
