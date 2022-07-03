/* filter_expression_toolbar.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/filter_expression_toolbar.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/wireshark_mime_data.h>
#include <ui/qt/models/uat_model.h>
#include <ui/qt/filter_action.h>
#include <ui/qt/main_application.h>

#include <epan/filter_expressions.h>
#include <ui/preference_utils.h>

#include <QApplication>
#include <QFrame>
#include <QMenu>
#include <QEvent>
#include <QContextMenuEvent>
#include <QToolButton>
#include <QToolTip>

static const char *dfe_property_ = "display filter expression"; //TODO : Fix Translate
static const char *dfe_property_label_ = "display_filter_expression_label";
static const char *dfe_property_expression_ = "display_filter_expression_expr";
static const char *dfe_property_comment_ = "display_filter_expression_comment";
static const char *dfe_menu_ = "filter_menu";

#define PARENT_SEPARATOR "//"

struct filter_expression_data
{
    FilterExpressionToolBar* toolbar;
    bool actions_added;
};

FilterExpressionToolBar::FilterExpressionToolBar(QWidget * parent) :
    DragDropToolBar(parent)
{
    updateStyleSheet();

    setContextMenuPolicy(Qt::CustomContextMenu);
    /* Give minimum space to the bar, so that drops on an empty bar will work */
    setMinimumWidth(10);

    connect (this, &QWidget::customContextMenuRequested, this, &FilterExpressionToolBar::onCustomMenuHandler);
    connect(this, &DragDropToolBar::actionMoved, this, &FilterExpressionToolBar::onActionMoved);
    connect(this, &DragDropToolBar::newFilterDropped, this, &FilterExpressionToolBar::onFilterDropped);

    connect(mainApp, &MainApplication::appInitialized,
            this, &FilterExpressionToolBar::filterExpressionsChanged);
    connect(mainApp, &MainApplication::filterExpressionsChanged,
            this, &FilterExpressionToolBar::filterExpressionsChanged);

}

bool FilterExpressionToolBar::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ApplicationPaletteChange:
        updateStyleSheet();
        break;
    default:
        break;

    }
    return DragDropToolBar::event(event);
}

void FilterExpressionToolBar::onCustomMenuHandler(const QPoint& pos)
{
    QAction * filterAction = actionAt(pos);
    if (! filterAction)
        return;

    customMenu(this, filterAction, pos);
}

void FilterExpressionToolBar::customMenu(FilterExpressionToolBar * target, QAction * filterAction, const QPoint& pos)
{
    QMenu * filterMenu = new QMenu(target);
    filterMenu->setAttribute(Qt::WA_DeleteOnClose);

    /* Only display context menu for actual filter actions */
    QString filterText = filterAction->property(dfe_property_expression_).toString().trimmed();

    if (!filterText.isEmpty())
    {
        filterMenu->addMenu(FilterAction::createFilterMenu(FilterAction::ActionApply, filterText, true, target));
        filterMenu->addMenu(FilterAction::createFilterMenu(FilterAction::ActionPrepare, filterText, true, target));
        filterMenu->addSeparator();
        filterMenu->addAction(FilterAction::copyFilterAction(filterText, target));
        filterMenu->addSeparator();
        QAction * actEdit = filterMenu->addAction(tr("Edit"));
        connect(actEdit, &QAction::triggered, target, &FilterExpressionToolBar::editFilter);
        actEdit->setProperty(dfe_property_label_, filterAction->property(dfe_property_label_));
        actEdit->setProperty(dfe_property_expression_, filterAction->property(dfe_property_expression_));
        actEdit->setData(filterAction->data());
        QAction * actDisable = filterMenu->addAction(tr("Disable"));
        connect(actDisable, &QAction::triggered, target, &FilterExpressionToolBar::disableFilter);
        actDisable->setProperty(dfe_property_label_, filterAction->property(dfe_property_label_));
        actDisable->setProperty(dfe_property_expression_, filterAction->property(dfe_property_expression_));
        actDisable->setData(filterAction->data());
        QAction * actRemove = filterMenu->addAction(tr("Remove"));
        connect(actRemove, &QAction::triggered, target, &FilterExpressionToolBar::removeFilter);
        actRemove->setProperty(dfe_property_label_, filterAction->property(dfe_property_label_));
        actRemove->setProperty(dfe_property_expression_, filterAction->property(dfe_property_expression_));
        actRemove->setData(filterAction->data());
        filterMenu->addSeparator();
    }
    QAction *actFilter = filterMenu->addAction(tr("Filter Button Preferences..."));
    connect(actFilter, &QAction::triggered, target, &FilterExpressionToolBar::toolBarShowPreferences);

    /* Forcing the menus to get closed, no matter which action has been triggered */
    connect(filterMenu, &QMenu::triggered, this, &FilterExpressionToolBar::closeMenu);

    filterMenu->popup(mapToGlobal(pos));
}

void FilterExpressionToolBar::filterExpressionsChanged()
{
    struct filter_expression_data data;

    data.toolbar = this;
    data.actions_added = false;

    // Hiding and showing seems to be the only way to get the layout to
    // work correctly in some cases. See bug 14121 for details.
    clear();
    setUpdatesEnabled(false);
    hide();

    // XXX Add a context menu for removing and changing buttons.
    filter_expression_iterate_expressions(filter_expression_add_action, &data);

    show();
    setUpdatesEnabled(true);
}

void FilterExpressionToolBar::removeFilter()
{
    UatModel * uatModel = new UatModel(this, "Display expressions");

    QString label = ((QAction *)sender())->property(dfe_property_label_).toString();
    QString expr = ((QAction *)sender())->property(dfe_property_expression_).toString();

    int idx = uatRowIndexForFilter(label, expr);

    QModelIndex rowIndex = uatModel->index(idx, 0);
    if (rowIndex.isValid()) {
        uatModel->removeRow(rowIndex.row());

        save_migrated_uat("Display expressions", &prefs.filter_expressions_old);
        filterExpressionsChanged();
    }
}

WiresharkMimeData * FilterExpressionToolBar::createMimeData(QString name, int position)
{
    ToolbarEntryMimeData * element = new ToolbarEntryMimeData(name, position);
    UatModel * uatModel = new UatModel(this, "Display expressions");

    QModelIndex rowIndex;
    for (int cnt = 0; cnt < uatModel->rowCount() && ! rowIndex.isValid(); cnt++)
    {
        if (uatModel->data(uatModel->index(cnt, 1), Qt::DisplayRole).toString().compare(name) == 0)
        {
            rowIndex = uatModel->index(cnt, 2);
            element->setFilter(rowIndex.data().toString());
        }
    }

    return element;
}

void FilterExpressionToolBar::onActionMoved(QAction* action, int oldPos, int newPos)
{
    gchar* err = NULL;
    if (oldPos == newPos)
        return;

    QString label = action->property(dfe_property_label_).toString();
    QString expr = action->property(dfe_property_expression_).toString();

    int idx = uatRowIndexForFilter(label, expr);

    if (idx > -1 && oldPos > -1 && newPos > -1)
    {
        uat_t * table = uat_get_table_by_name("Display expressions");
        uat_move_index(table, oldPos, newPos);
        uat_save(table, &err);

        g_free(err);
    }
}

void FilterExpressionToolBar::disableFilter()
{
    QString label = ((QAction *)sender())->property(dfe_property_label_).toString();
    QString expr = ((QAction *)sender())->property(dfe_property_expression_).toString();

    int idx = uatRowIndexForFilter(label, expr);
    UatModel * uatModel = new UatModel(this, "Display expressions");

    QModelIndex rowIndex = uatModel->index(idx, 0);
    if (rowIndex.isValid()) {
        uatModel->setData(rowIndex, QVariant::fromValue(false));

        save_migrated_uat("Display expressions", &prefs.filter_expressions_old);
        filterExpressionsChanged();
    }
}

void FilterExpressionToolBar::editFilter()
{
    if (! sender())
        return;

    QString label = ((QAction *)sender())->property(dfe_property_label_).toString();
    QString expr = ((QAction *)sender())->property(dfe_property_expression_).toString();

    int idx = uatRowIndexForFilter(label, expr);

    if (idx > -1)
        emit filterEdit(idx);
}

void FilterExpressionToolBar::onFilterDropped(QString description, QString filter)
{
    if (filter.length() == 0)
        return;

    filter_expression_new(qUtf8Printable(description),
            qUtf8Printable(filter), qUtf8Printable(description), TRUE);

    save_migrated_uat("Display expressions", &prefs.filter_expressions_old);
    filterExpressionsChanged();
}

void FilterExpressionToolBar::toolBarShowPreferences()
{
    emit filterPreferences();
}

void FilterExpressionToolBar::updateStyleSheet()
{
    // Try to draw 1-pixel-wide separator lines from the button label
    // ascent to its baseline.
    setStyleSheet(QString(
                "QToolBar { background: none; border: none; spacing: 1px; }"
                "QFrame { background: none; min-width: 1px; max-width: 1px; }"
                ));
}

int FilterExpressionToolBar::uatRowIndexForFilter(QString label, QString expression)
{
    int result = -1;

    if (expression.length() == 0)
        return result;

    UatModel * uatModel = new UatModel(this, "Display expressions");

    QModelIndex rowIndex;

    if (label.length() > 0)
    {
        for (int cnt = 0; cnt < uatModel->rowCount() && ! rowIndex.isValid(); cnt++)
        {
            if (uatModel->data(uatModel->index(cnt, 1), Qt::DisplayRole).toString().compare(label) == 0 &&
                    uatModel->data(uatModel->index(cnt, 2), Qt::DisplayRole).toString().compare(expression) == 0)
            {
                rowIndex = uatModel->index(cnt, 2);
            }
        }
    }
    else
    {
        rowIndex = uatModel->findRowForColumnContent(((QAction *)sender())->data(), 2);
    }

    if (rowIndex.isValid())
        result = rowIndex.row();

    delete uatModel;

    return result;
}

bool FilterExpressionToolBar::eventFilter(QObject *obj, QEvent *event)
{
    QMenu * qm = qobject_cast<QMenu *>(obj);

    if (qm && qm->property(dfe_menu_).toBool())
    {

        if (event->type() == QEvent::ContextMenu)
        {
            QContextMenuEvent *ctx = static_cast<QContextMenuEvent *>(event);
            QAction * filterAction = qm->actionAt(ctx->pos());

            if (filterAction)
                customMenu(this, filterAction, ctx->pos());
            return true;
        }
        else if (event->type() == QEvent::ToolTip)
        {
            QHelpEvent *helpEvent = static_cast<QHelpEvent *>(event);
            QAction * filterAction = qm->actionAt(helpEvent->pos());
            if (filterAction) {
                QToolTip::showText(helpEvent->globalPos(), filterAction->property(dfe_property_comment_).toString().trimmed());
            } else {
                QToolTip::hideText();
                event->ignore();
            }

            return true;
        }
    }

    return QToolBar::eventFilter(obj, event);
}

void FilterExpressionToolBar::closeMenu(QAction * /*sender*/)
{
    foreach(QAction * entry, actions())
    {
        QWidget * widget = widgetForAction(entry);
        QToolButton * tb = qobject_cast<QToolButton *>(widget);
        if (tb && tb->menu())
            tb->menu()->close();
    }
}

QMenu * FilterExpressionToolBar::findParentMenu(const QStringList tree, void *fed_data, QMenu *parent )
{
    if (!fed_data)
        return Q_NULLPTR;

    struct filter_expression_data* data = (filter_expression_data*)fed_data;
    if (!data->toolbar)
        return Q_NULLPTR;

    if (! tree.isEmpty())
    {
        if (!parent)
        {
            /* Searching existing main menus */
            foreach(QAction * entry, data->toolbar->actions())
            {
                QWidget * widget = data->toolbar->widgetForAction(entry);
                QToolButton * tb = qobject_cast<QToolButton *>(widget);
                if (tb && tb->menu() && tb->text().compare(tree.at(0).trimmed()) == 0)
                    return findParentMenu(tree.mid(1), fed_data, tb->menu());
            }
        }
        else if (parent)
        {
            QString menuName = tree.at(0).trimmed();
            /* Iterate to see, if we next have to jump into another submenu */
            foreach(QAction *entry, parent->actions())
            {
                if (entry->menu() && entry->text().compare(menuName) == 0)
                    return findParentMenu(tree.mid(1), fed_data, entry->menu());
            }

            /* Submenu not found, creating */
            QMenu * subMenu = new QMenu(menuName);
            subMenu->installEventFilter(data->toolbar);
            subMenu->setProperty(dfe_menu_, QVariant::fromValue(true));
            parent->addMenu(subMenu);
            return findParentMenu(tree.mid(1), fed_data, subMenu);
        }

        /* No menu has been found, create one */
        QString parentName = tree.at(0).trimmed();
        QToolButton * menuButton = new QToolButton();
        menuButton->setText(parentName);
        menuButton->setPopupMode(QToolButton::MenuButtonPopup);
        QMenu * parentMenu = new QMenu(menuButton);
        parentMenu->installEventFilter(data->toolbar);
        parentMenu->setProperty(dfe_menu_, QVariant::fromValue(true));
        menuButton->setMenu(parentMenu);
        // Required for QToolButton::MenuButtonPopup.
        connect(menuButton, &QToolButton::pressed, menuButton, &QToolButton::showMenu);
        data->toolbar->addWidget(menuButton);

        return findParentMenu(tree.mid(1), fed_data, parentMenu);
    }
    else if (parent)
        return parent;

    return Q_NULLPTR;
}

gboolean FilterExpressionToolBar::filter_expression_add_action(const void *key _U_, void *value, void *user_data)
{
    filter_expression_t* fe = (filter_expression_t*)value;
    struct filter_expression_data* data = (filter_expression_data*)user_data;

    if (!fe->enabled)
        return FALSE;

    QString label = QString(fe->label);

    /* Search for parent menu and create if not found */
    QStringList tree = label.split(PARENT_SEPARATOR);
    if (!tree.isEmpty())
        tree.removeLast();
    QMenu * parentMenu = findParentMenu(tree, data);
    if (parentMenu)
        label = label.mid(label.lastIndexOf(PARENT_SEPARATOR) + QString(PARENT_SEPARATOR).length()).trimmed();

    QAction *dfb_action = new QAction(label, data->toolbar);
    if (strlen(fe->comment) > 0)
    {
        QString tooltip = QString("%1\n%2").arg(fe->comment).arg(fe->expression);
        dfb_action->setToolTip(tooltip);
        dfb_action->setProperty(dfe_property_comment_, tooltip);
    }
    else
    {
        dfb_action->setToolTip(fe->expression);
        dfb_action->setProperty(dfe_property_comment_, QString(fe->expression));
    }
    dfb_action->setData(fe->expression);
    dfb_action->setProperty(dfe_property_, true);
    dfb_action->setProperty(dfe_property_label_, QString(fe->label));
    dfb_action->setProperty(dfe_property_expression_, QString(fe->expression));

    if (data->actions_added) {
        QFrame *sep = new QFrame();
        sep->setEnabled(false);
        data->toolbar->addWidget(sep);
    }

    if (parentMenu)
        parentMenu->addAction(dfb_action);
    else
        data->toolbar->addAction(dfb_action);

    connect(dfb_action, &QAction::triggered, data->toolbar, &FilterExpressionToolBar::filterClicked);
    data->actions_added = true;
    return FALSE;
}

void FilterExpressionToolBar::filterClicked()
{
    bool prepare = false;
    QAction *dfb_action = qobject_cast<QAction*>(sender());

    if (!dfb_action)
        return;

    QString filterText = dfb_action->data().toString();
    prepare = (QApplication::keyboardModifiers() & Qt::ShiftModifier);

    emit filterSelected(filterText, prepare);
}
