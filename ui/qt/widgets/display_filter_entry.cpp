/* display_filter_entry.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/widgets/display_filter_entry.h>

#include <ui/qt/models/display_filter_validator.h>
#include <ui/qt/models/display_filter_completer.h>
#include <ui/qt/models/display_filter_history_model.h>
#include <ui/qt/models/display_filter_bookmark_model.h>

#include <ui/qt/filter_action.h>
#include <ui/qt/filter_dialog.h>
#include <ui/qt/display_filter_expression_dialog.h>
#include <ui/qt/main_application.h>
#include <ui/qt/main_window.h>
#include <ui/qt/models/pref_models.h>
#include <ui/qt/utils/themes/themed_icon.h>
#include <ui/qt/utils/wireshark_mime_data.h>

#include <wsutil/utf8_entities.h>

#include <QApplication>
#include <QConcatenateTablesProxyModel>
#include <QContextMenuEvent>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMenu>
#include <QMimeData>
#include <QStringListModel>

#ifdef __APPLE__
#define DEFAULT_MODIFIER UTF8_PLACE_OF_INTEREST_SIGN
#else
#define DEFAULT_MODIFIER "Ctrl-"
#endif

DisplayFilterEntry::DisplayFilterEntry(QWidget *parent) :
    FilterExpressionEdit(parent)
{
    setAccessibleName(tr("Display filter entry"));
    setAcceptDrops(true);

    // Backends. setValidator/setCompleter/setBookmarkModel are widget-owned; the
    // history model is a thin view over the global recent store, parented here
    // for lifetime.
    setValidator(new DisplayFilterValidator(this));

    DisplayFilterCompleter *completer = new DisplayFilterCompleter(this);
    setCompleter(completer);

    setHistoryModel(new DisplayFilterHistoryModel(this));
    setBookmarkModel(new DisplayFilterBookmarkModel());

    // Merged typeahead source: recent history + saved bookmarks + the dynamic
    // protocol-field list.
    completionModel()->addSourceModel(completer->fieldsModel());
    completer->setModel(completionModel());

    // Display chrome and mode. Blue bookmark; yellow when the filter is saved.
    setBookmarkIcon(ThemedIcon(":/svg_icons/x-display-filter-bookmark.svg",
                               ThemeManager::FilterBookmark),
                    ThemedIcon(":/svg_icons/x-display-filter-bookmark.svg",
                               ThemeManager::FilterBookmarkMatch));
    setBookmarkMenuLabels(tr("Saved Display Filters"),
                          tr("Save this filter"),
                          tr("Remove this filter"),
                          tr("Manage Display Filters"),
                          tr("Filter Button Preferences…"));
    setApplyActionVisible(true);        // explicit apply
    setPreferencesActionVisible(true);  // display has a filter-button prefs pane

    setPlaceholderText(tr("Apply a display filter %1 <%2/>")
                           .arg(UTF8_HORIZONTAL_ELLIPSIS).arg(DEFAULT_MODIFIER));

    // Generic base signals -> display vocabulary.
    connect(this, &FilterExpressionEdit::applied, this, [this](const QString &expr) {
        last_applied_ = expr;
        emit filterPackets(expr, true);
    });
    connect(this, &FilterExpressionEdit::cleared, this, [this]() {
        last_applied_.clear();
        emit filterPackets(QString(), true);
    });
    connect(this, &FilterEdit::syntaxStateChanged, this, [this](FilterEdit::SyntaxState s) {
        updateStatus(s);
    });

    // Bookmark menu behaviour.
    connect(this, &FilterExpressionEdit::saveBookmarkRequested, this, [this](const QString &expr) {
        FilterDialog *dlg = new FilterDialog(window(), FilterDialog::DisplayFilter, expr);
        dlg->setWindowModality(Qt::ApplicationModal);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    connect(this, &FilterExpressionEdit::removeBookmarkRequested, this, [this](const QString &expr) {
        if (DisplayFilterBookmarkModel *bm = qobject_cast<DisplayFilterBookmarkModel *>(bookmarkModel()))
            bm->removeBookmark(expr);
    });
    connect(this, &FilterExpressionEdit::manageBookmarksRequested, this, [this]() {
        FilterDialog *dlg = new FilterDialog(window(), FilterDialog::DisplayFilter);
        dlg->setWindowModality(Qt::ApplicationModal);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    connect(this, &FilterExpressionEdit::preferencesRequested, this, [this]() {
        emit showPreferencesDialog(PrefsModel::typeToString(PrefsModel::FilterButtons));
    });

    // Keep the injected stores fresh when they change elsewhere.
    connect(mainApp, &MainApplication::displayFilterListChanged, this, [this]() {
        if (DisplayFilterBookmarkModel *bm = qobject_cast<DisplayFilterBookmarkModel *>(bookmarkModel()))
            bm->reload();
    });
    connect(mainApp, &MainApplication::preferencesChanged, this, [this]() {
        if (DisplayFilterHistoryModel *hm = qobject_cast<DisplayFilterHistoryModel *>(historyModel()))
            hm->reload();
        recheck();
    });

    mainApp->whenInitialized(this, [this]() { connectToMainWindow(); });
}

void DisplayFilterEntry::connectToMainWindow()
{
    connect(this, &DisplayFilterEntry::showPreferencesDialog, mainApp->mainWindow(), &MainWindow::showPreferencesDialog);
    connect(mainApp->mainWindow(), &MainWindow::displayFilterSuccess, this, &DisplayFilterEntry::displayFilterSuccess);
}

void DisplayFilterEntry::recheck()
{
    validateNow();
}

void DisplayFilterEntry::setDisplayFilter(QString filter)
{
    setText(filter);
    setFocus();
}

void DisplayFilterEntry::applyDisplayFilter()
{
    applyExpression();
}

bool DisplayFilterEntry::checkDisplayFilter()
{
    validateNow();
    return state() != SyntaxState::Invalid;
}

void DisplayFilterEntry::displayFilterSuccess(bool success)
{
    // After a successful apply the field already matches the active filter; the
    // base re-enables the apply action on the next edit or state change.
    if (success)
        last_applied_ = text();
}

void DisplayFilterEntry::updateStatus(SyntaxState state)
{
    MainWindow *mw = mainApp->mainWindow();
    const bool active = mw && mw->isActiveWindow();

    if (state == SyntaxState::Invalid || state == SyntaxState::Deprecated) {
        const QString msg = lastError();
        if (active)
            mainApp->pushStatus(MainApplication::FilterSyntax, msg);
        emit pushFilterSyntaxStatus(msg);
        setToolTip(state == SyntaxState::Invalid ? lastErrorFull() : msg);
    } else {
        if (active)
            mainApp->popStatus(MainApplication::FilterSyntax);
        emit popFilterSyntaxStatus();
        setToolTip(QString());
    }
}

void DisplayFilterEntry::dragEnterEvent(QDragEnterEvent *event)
{
    if (!event || !event->mimeData())
        return;

    if (qobject_cast<const ToolbarEntryMimeData *>(event->mimeData()) ||
        event->mimeData()->hasFormat(WiresharkMimeData::DisplayFilterMimeType)) {
        if (event->source() != this) {
            event->setDropAction(Qt::CopyAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    } else {
        event->ignore();
    }
}

void DisplayFilterEntry::dragMoveEvent(QDragMoveEvent *event)
{
    if (!event || !event->mimeData())
        return;

    if (qobject_cast<const ToolbarEntryMimeData *>(event->mimeData()) ||
        event->mimeData()->hasFormat(WiresharkMimeData::DisplayFilterMimeType)) {
        if (event->source() != this) {
            event->setDropAction(Qt::CopyAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    } else {
        event->ignore();
    }
}

void DisplayFilterEntry::dropEvent(QDropEvent *event)
{
    if (!event || !event->mimeData())
        return;

    QString filterText;
    if (event->mimeData()->hasFormat(WiresharkMimeData::DisplayFilterMimeType)) {
        QByteArray jsonData = event->mimeData()->data(WiresharkMimeData::DisplayFilterMimeType);
        QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonData);
        if (!jsonDoc.isObject())
            return;

        QJsonObject data = jsonDoc.object();
        if ((QApplication::keyboardModifiers() & Qt::AltModifier) && data.contains("field"))
            filterText = data["field"].toString();
        else if (data.contains("filter"))
            filterText = data["filter"].toString();
    } else if (qobject_cast<const ToolbarEntryMimeData *>(event->mimeData())) {
        filterText = qobject_cast<const ToolbarEntryMimeData *>(event->mimeData())->filter();
    }

    if (filterText.length() > 0) {
        if (event->source() != this) {
            event->setDropAction(Qt::CopyAction);
            event->accept();

            bool prepare = QApplication::keyboardModifiers() & Qt::ShiftModifier;

            if (text().length() > 0 || (QApplication::keyboardModifiers() & Qt::MetaModifier)) {
                createFilterTextDropMenu(event, prepare, filterText);
                return;
            }

            setText(filterText);

            // Holding down Shift only prepares (stages) the filter.
            if (!prepare)
                applyExpression();
        } else {
            event->acceptProposedAction();
        }
    } else {
        event->ignore();
    }
}

void DisplayFilterEntry::createFilterTextDropMenu(QDropEvent *event, bool prepare, QString filterText)
{
    if (filterText.isEmpty())
        return;

    FilterAction::Action filterAct = prepare ? FilterAction::ActionPrepare : FilterAction::ActionApply;
    QMenu *applyMenu = FilterAction::createFilterMenu(filterAct, filterText, true, this);
    applyMenu->setAttribute(Qt::WA_DeleteOnClose);
    applyMenu->popup(mapToGlobal(event->position().toPoint()));
}

void DisplayFilterEntry::contextMenuEvent(QContextMenuEvent *event)
{
    QMenu *menu = createStandardContextMenu();
    menu->setAttribute(Qt::WA_DeleteOnClose);

    QAction *na = new QAction(tr("Display Filter Expression…"), this);
    connect(na, &QAction::triggered, this, &DisplayFilterEntry::displayFilterExpression);

    if (!menu->actions().isEmpty()) {
        QAction *first = menu->actions().at(0);
        menu->insertAction(first, na);
        menu->insertSeparator(first);
    } else {
        menu->addAction(na);
    }

    QAction *la = new QAction(tr("Left align buttons"), this);
    la->setCheckable(true);
    la->setChecked(buttonsLeftAligned());
    connect(la, &QAction::triggered, this, &DisplayFilterEntry::setButtonsLeftAligned);
    menu->addSeparator();
    menu->addAction(la);

    menu->popup(event->globalPos());
}

void DisplayFilterEntry::displayFilterExpression()
{
    DisplayFilterExpressionDialog *dfe_dialog = new DisplayFilterExpressionDialog(this);
    // Setting the modality also sets the parent of a GeometryStateDialog and is
    // necessary if our current window is modal. Don't do it for the main window,
    // where a user might want to change the current dissection tree while
    // building an expression.
    if (!mainApp->mainWindow()->isActiveWindow())
        dfe_dialog->setWindowModality(Qt::WindowModal);

    connect(dfe_dialog, &DisplayFilterExpressionDialog::insertDisplayFilter,
            this, &DisplayFilterEntry::insertFilter);

    dfe_dialog->show();
}
