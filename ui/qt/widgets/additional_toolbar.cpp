/* additional_toolbar.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <glib.h>

#include <ui/qt/widgets/additional_toolbar.h>
#include <ui/qt/widgets/apply_line_edit.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/wireshark_application.h>

#include <QLabel>
#include <QLineEdit>
#include <QHBoxLayout>
#include <QComboBox>
#include <QWidget>
#include <QCheckBox>
#include <QPushButton>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QLayoutItem>

const char * AdditionalToolbarWidgetAction::propertyName = "additional_toolbar_item";

AdditionalToolBar::AdditionalToolBar(ext_toolbar_t * exttoolbar, QWidget * parent)
: QToolBar(parent),
  toolbar(exttoolbar)
{ }

AdditionalToolBar::~AdditionalToolBar()
{ }

AdditionalToolBar * AdditionalToolBar::create(QWidget * parent, ext_toolbar_t * toolbar)
{
    if (g_list_length(toolbar->children) == 0)
        return NULL;

    AdditionalToolBar * result = new AdditionalToolBar(toolbar, parent);
    result->setMovable(false);
    result->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::MinimumExpanding);
    result->layout()->setMargin(0);
    result->layout()->setSpacing(4);

    GList * walker = toolbar->children;
    bool spacerNeeded = true;

    while (walker && walker->data)
    {
        ext_toolbar_t * item = gxx_list_data(ext_toolbar_t *, walker);
        if (item->type == EXT_TOOLBAR_ITEM)
        {
            if (item->item_type == EXT_TOOLBAR_STRING)
                spacerNeeded = false;

            QAction * newAction = new AdditionalToolbarWidgetAction(item, result);
            if (newAction)
            {
                result->addAction(newAction);
                /* Necessary, because enable state is reset upon adding the action */
                result->actions()[result->actions().count() - 1]->setEnabled(!item->capture_only);
            }
        }

        walker = gxx_list_next (walker);
    }

    if (result->children().count() == 0)
        return Q_NULLPTR;

    if (spacerNeeded)
    {
        QWidget * empty = new QWidget();
        empty->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Preferred);
        result->addWidget(empty);

    }

    return result;
}

QString AdditionalToolBar::menuName()
{
    return (toolbar && toolbar->name) ? QString(toolbar->name) : QString();
}

AdditionalToolbarWidgetAction::AdditionalToolbarWidgetAction(QObject * parent)
: QWidgetAction(parent),
  toolbar_item(0)
{ }

AdditionalToolbarWidgetAction::AdditionalToolbarWidgetAction(ext_toolbar_t * item, QObject * parent)
: QWidgetAction(parent),
  toolbar_item(item)
{
    connect(wsApp, &WiresharkApplication::captureActive, this, &AdditionalToolbarWidgetAction::captureActive);
}

AdditionalToolbarWidgetAction::AdditionalToolbarWidgetAction(const AdditionalToolbarWidgetAction & copy_object)
:  QWidgetAction(copy_object.parent()),
   toolbar_item(copy_object.toolbar_item)
{
    connect(wsApp, &WiresharkApplication::captureActive, this, &AdditionalToolbarWidgetAction::captureActive);
}


void AdditionalToolbarWidgetAction::captureActive(int activeCaptures)
{
    if (toolbar_item && toolbar_item->capture_only)
    {
        setEnabled(activeCaptures != 0);
    }
}

/* Exists, so a default deconstructor does not call delete on toolbar_item */
AdditionalToolbarWidgetAction::~AdditionalToolbarWidgetAction() { }

QWidget * AdditionalToolbarWidgetAction::createWidget(QWidget * parent)
{
    QWidget * barItem = 0;

    if (toolbar_item->type != EXT_TOOLBAR_ITEM)
        return barItem;

    switch (toolbar_item->item_type)
    {
    case EXT_TOOLBAR_BUTTON:
        barItem = createButton(toolbar_item, parent);
        break;
    case EXT_TOOLBAR_BOOLEAN:
        barItem = createBoolean(toolbar_item, parent);
        break;
    case EXT_TOOLBAR_STRING:
        barItem = createTextEditor(toolbar_item, parent);
        break;
    case EXT_TOOLBAR_SELECTOR:
        barItem = createSelector(toolbar_item, parent);
        break;
    }

    if (! barItem)
        return 0;

    barItem->setToolTip(toolbar_item->tooltip);
    barItem->setProperty(propertyName, VariantPointer<ext_toolbar_t>::asQVariant(toolbar_item));

#ifdef Q_OS_MAC
    barItem->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    return barItem;
}

static void
toolbar_button_cb(gpointer item, gpointer item_data, gpointer user_data)
{
    if (! item || ! item_data || ! user_data)
        return;

    QPushButton * widget = (QPushButton *)(item_data);
    ext_toolbar_update_t * update_entry = (ext_toolbar_update_t *)user_data;

    if (widget)
    {
        if (update_entry->type == EXT_TOOLBAR_UPDATE_VALUE)
            widget->setText((gchar *)update_entry->user_data);
        else if (update_entry->type == EXT_TOOLBAR_SET_ACTIVE)
        {
            bool enableState = GPOINTER_TO_INT(update_entry->user_data) == 1;
            widget->setEnabled(enableState);
        }

    }
}

QWidget * AdditionalToolbarWidgetAction::createButton(ext_toolbar_t * item, QWidget * parent)
{
    if (! item || item->type != EXT_TOOLBAR_ITEM || item->item_type != EXT_TOOLBAR_BUTTON)
        return 0;

    QPushButton * button = new QPushButton(item->name, parent);
    button->setText(item->name);
    connect(button, &QPushButton::clicked, this, &AdditionalToolbarWidgetAction::onButtonClicked);

    ext_toolbar_register_update_cb(item, (ext_toolbar_action_cb)&toolbar_button_cb, (void *)button);

    return button;
}

static void
toolbar_boolean_cb(gpointer item, gpointer item_data, gpointer user_data)
{
    if (! item || ! item_data || ! user_data)
        return;

    QCheckBox * widget = (QCheckBox *)(item_data);

    ext_toolbar_update_t * update_entry = (ext_toolbar_update_t *)user_data;

    if (update_entry->type == EXT_TOOLBAR_UPDATE_VALUE)
    {
        bool oldState = false;
        if (update_entry->silent)
            oldState = widget->blockSignals(true);

        widget->setCheckState(GPOINTER_TO_INT(update_entry->user_data) == 1 ? Qt::Checked : Qt::Unchecked);

        if (update_entry->silent)
            widget->blockSignals(oldState);
    }
    else if (update_entry->type == EXT_TOOLBAR_SET_ACTIVE)
    {
        bool enableState = GPOINTER_TO_INT(update_entry->user_data) == 1;
        widget->setEnabled(enableState);
    }
}

QWidget * AdditionalToolbarWidgetAction::createBoolean(ext_toolbar_t * item, QWidget * parent)
{
    if (! item || item->type != EXT_TOOLBAR_ITEM || item->item_type != EXT_TOOLBAR_BOOLEAN)
        return 0;

    QString defValue = toolbar_item->defvalue;

    QCheckBox * checkbox = new QCheckBox(item->name, parent);
    checkbox->setText(item->name);
    setCheckable(true);
    checkbox->setCheckState(defValue.compare("true", Qt::CaseInsensitive) == 0 ? Qt::Checked : Qt::Unchecked);
    connect(checkbox, &QCheckBox::stateChanged, this, &AdditionalToolbarWidgetAction::onCheckBoxChecked);

    ext_toolbar_register_update_cb(item, (ext_toolbar_action_cb)&toolbar_boolean_cb, (void *)checkbox);

    return checkbox;
}

QWidget * AdditionalToolbarWidgetAction::createLabelFrame(ext_toolbar_t * item, QWidget * parent)
{
    if (! item)
        return new QWidget();

    QWidget * frame = new QWidget(parent);

    QHBoxLayout * frameLayout = new QHBoxLayout(frame);
    frameLayout->setMargin(0);
    frameLayout->setSpacing(0);

    QLabel * strLabel = new QLabel(item->name, frame);
    strLabel->setToolTip(item->tooltip);

#ifdef Q_OS_MAC
    frame->setAttribute(Qt::WA_MacSmallSize, true);
    strLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    frameLayout->addWidget(strLabel);

    frame->setLayout(frameLayout);

    return frame;
}

static void
toolbar_string_cb(gpointer item, gpointer item_data, gpointer user_data)
{
    if (! item || ! item_data || ! user_data)
        return;

    ApplyLineEdit * edit = (ApplyLineEdit *)(item_data);

    ext_toolbar_update_t * update_entry = (ext_toolbar_update_t *)user_data;

    if (update_entry->type == EXT_TOOLBAR_UPDATE_VALUE)
    {
        bool oldState = false;
        if (update_entry->silent)
            oldState = edit->blockSignals(true);

        edit->setText((gchar *)update_entry->user_data);

        if (update_entry->silent)
            edit->blockSignals(oldState);
    }
    else if (update_entry->type == EXT_TOOLBAR_SET_ACTIVE)
    {
        bool enableState = GPOINTER_TO_INT(update_entry->user_data) == 1;
        edit->setEnabled(enableState);
    }
}

QWidget * AdditionalToolbarWidgetAction::createTextEditor(ext_toolbar_t * item, QWidget * parent)
{
    if (! item || item->type != EXT_TOOLBAR_ITEM || item->item_type != EXT_TOOLBAR_STRING)
        return 0;

    QWidget * frame = createLabelFrame(toolbar_item, parent);

    ApplyLineEdit * strEdit = new ApplyLineEdit(toolbar_item->defvalue, frame);
    strEdit->setToolTip(toolbar_item->tooltip);
    strEdit->setRegEx(toolbar_item->regex);
    strEdit->setEmptyAllowed(toolbar_item->is_required);
    strEdit->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Fixed);

#ifdef Q_OS_MAC
    strEdit->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    frame->layout()->addWidget(strEdit);

    connect(strEdit, &ApplyLineEdit::textApplied, this, &AdditionalToolbarWidgetAction::sendTextToCallback);

    ext_toolbar_register_update_cb(item, (ext_toolbar_action_cb)&toolbar_string_cb, (void *)strEdit);

    return frame;
}

static void
toolbar_selector_cb(gpointer item, gpointer item_data, gpointer user_data)
{
    if (! item || ! item_data || ! user_data)
        return;

    QComboBox * comboBox = (QComboBox *)(item_data);
    ext_toolbar_update_t * update_entry = (ext_toolbar_update_t *)user_data;

    bool oldState = false;

    if (update_entry->silent)
        oldState = comboBox->blockSignals(true);

    QStandardItemModel * sourceModel = (QStandardItemModel *)comboBox->model();

    if (update_entry->type == EXT_TOOLBAR_SET_ACTIVE)
    {
        bool enableState = GPOINTER_TO_INT(update_entry->user_data) == 1;
        comboBox->setEnabled(enableState);
    }
    else if (update_entry->type != EXT_TOOLBAR_UPDATE_DATA_REMOVE && ! update_entry->user_data)
        return;

    if (update_entry->type == EXT_TOOLBAR_UPDATE_VALUE)
    {
        QString data = QString((gchar *)update_entry->user_data);

        for (int i = 0; i < sourceModel->rowCount(); i++)
        {
            QStandardItem * dataValue = ((QStandardItemModel *)sourceModel)->item(i, 0);
            ext_toolbar_value_t * tbValue = VariantPointer<ext_toolbar_value_t>::asPtr(dataValue->data(Qt::UserRole));
            if (tbValue && data.compare(QString(tbValue->value)) == 0)
            {
                comboBox->setCurrentIndex(i);
                break;
            }
        }
    }
    else if (update_entry->type == EXT_TOOLBAR_UPDATE_DATA)
    {
        GList * walker = (GList *)update_entry->user_data;
        if (g_list_length(walker) == 0)
            return;

        sourceModel->clear();

        while (walker && walker->data)
        {
            ext_toolbar_value_t * listvalue = gxx_list_data(ext_toolbar_value_t *, walker);

            QStandardItem * si = new QStandardItem(listvalue->display);
            si->setData(VariantPointer<ext_toolbar_value_t>::asQVariant(listvalue), Qt::UserRole);
            sourceModel->appendRow(si);

            walker = gxx_list_next(walker);
        }
    }
    else if (update_entry->type == EXT_TOOLBAR_UPDATE_DATABYINDEX ||
            update_entry->type == EXT_TOOLBAR_UPDATE_DATA_ADD ||
            update_entry->type == EXT_TOOLBAR_UPDATE_DATA_REMOVE)
    {
        if (! update_entry->data_index)
            return;

        gchar * idx = (gchar *)update_entry->data_index;
        gchar * display = (gchar *)update_entry->user_data;

        if (update_entry->type == EXT_TOOLBAR_UPDATE_DATABYINDEX)
        {
            for (int i = 0; i < sourceModel->rowCount(); i++)
            {
                QStandardItem * dataValue = sourceModel->item(i, 0);
                ext_toolbar_value_t * entry = VariantPointer<ext_toolbar_value_t>::asPtr(dataValue->data(Qt::UserRole));
                if (entry && g_strcmp0(entry->value, idx) == 0)
                {
                    g_free(entry->display);
                    entry->display = g_strdup(display);
                    dataValue->setData(VariantPointer<ext_toolbar_value_t>::asQVariant(entry), Qt::UserRole);
                    dataValue->setText(display);
                    break;
                }
            }
        }
        else if (update_entry->type == EXT_TOOLBAR_UPDATE_DATA_ADD)
        {
            ext_toolbar_value_t * listvalue = g_new0(ext_toolbar_value_t, 1);
            listvalue->display = g_strdup(display);
            listvalue->value = g_strdup(idx);

            QStandardItem * si = new QStandardItem(listvalue->display);
            si->setData(VariantPointer<ext_toolbar_value_t>::asQVariant(listvalue), Qt::UserRole);
            sourceModel->appendRow(si);
        }
        else if (update_entry->type == EXT_TOOLBAR_UPDATE_DATA_REMOVE)
        {
            QList<QStandardItem *> entryList = sourceModel->findItems(display);
            /* Search for index if display did not find anything */
            if (entryList.size() == 0)
                entryList = sourceModel->findItems(idx);

            foreach(QStandardItem *entry, entryList)
            {
                QModelIndex index = sourceModel->indexFromItem(entry);
                if (index.isValid())
                    sourceModel->removeRow(index.row());
            }
        }
    }

    if (update_entry->silent)
        comboBox->blockSignals(oldState);

}

QWidget * AdditionalToolbarWidgetAction::createSelector(ext_toolbar_t * item, QWidget * parent)
{
    if (! item || item->type != EXT_TOOLBAR_ITEM || item->item_type != EXT_TOOLBAR_SELECTOR)
        return 0;

    if (g_list_length(item->values) == 0)
        return 0;

    QWidget * frame = createLabelFrame(item, parent);

    QComboBox * myBox = new QComboBox(parent);
    myBox->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);

    QStandardItemModel * sourceModel = new QStandardItemModel();

    GList * walker = item->values;
    int selIndex = 0;
    while (walker && walker->data)
    {
        ext_toolbar_value_t * listvalue = gxx_list_data(ext_toolbar_value_t *, walker);

        QStandardItem * si = new QStandardItem(listvalue->display);
        si->setData(VariantPointer<ext_toolbar_value_t>::asQVariant(listvalue), Qt::UserRole);
        sourceModel->appendRow(si);

        if (listvalue->is_default)
            selIndex = sourceModel->rowCount();

        walker = gxx_list_next(walker);
    }

    myBox->setModel(sourceModel);
    myBox->setCurrentIndex(selIndex);

#ifdef Q_OS_MAC
    myBox->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    frame->layout()->addWidget(myBox);

    connect(myBox, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
            this, &AdditionalToolbarWidgetAction::onSelectionInWidgetChanged);

    ext_toolbar_register_update_cb(item, (ext_toolbar_action_cb)&toolbar_selector_cb, (void *)myBox);

    return frame;
}

ext_toolbar_t * AdditionalToolbarWidgetAction::extractToolbarItemFromObject(QObject * object)
{
    QWidget * widget = dynamic_cast<QWidget *>(object);
    if (! widget)
        return 0;

    QVariant propValue = widget->property(propertyName);

    /* If property is invalid, look if our parent has this property */
    if (! propValue.isValid())
    {
        QWidget * frame = dynamic_cast<QWidget *>(widget->parent());
        if (! frame)
            return 0;

        propValue = frame->property(propertyName);
    }

    if (! propValue.isValid())
        return 0;

    return VariantPointer<ext_toolbar_t>::asPtr(propValue);
}

void AdditionalToolbarWidgetAction::onButtonClicked()
{
    ext_toolbar_t * item = extractToolbarItemFromObject(sender());
    if (! item)
        return;

    item->callback(item, 0, item->user_data);
}

void AdditionalToolbarWidgetAction::onCheckBoxChecked(int checkState)
{
    ext_toolbar_t * item = extractToolbarItemFromObject(sender());
    if (! item)
        return;

    gboolean value = checkState == Qt::Checked ? true : false;

    item->callback(item, &value, item->user_data);
}

void AdditionalToolbarWidgetAction::sendTextToCallback()
{
    ext_toolbar_t * item = extractToolbarItemFromObject(sender());
    if (! item)
        return;

    if (item->item_type != EXT_TOOLBAR_STRING)
        return;

    ApplyLineEdit * editor = dynamic_cast<ApplyLineEdit *>(sender());
    if (! editor)
    {
        /* Called from button, searching for acompanying line edit */
        QWidget * parent = dynamic_cast<QWidget *>(sender()->parent());
        if (parent)
        {
            QList<ApplyLineEdit *> children = parent->findChildren<ApplyLineEdit *>();
            if (children.count() >= 0)
                editor = children.at(0);
        }
    }

    if (editor)
        item->callback(item, qstring_strdup(editor->text()), item->user_data);
}

void AdditionalToolbarWidgetAction::onSelectionInWidgetChanged(int idx)
{
    QComboBox * editor = dynamic_cast<QComboBox *>(sender());
    ext_toolbar_t * item = extractToolbarItemFromObject(editor);
    if (! item || item->item_type != EXT_TOOLBAR_SELECTOR)
        return;

    QStandardItemModel * sourceModel = (QStandardItemModel *) editor->model();
    if (sourceModel->rowCount() <= idx)
        return;

    QModelIndex mdIdx = sourceModel->index(idx, 0);
    QVariant dataSet = sourceModel->data(mdIdx, Qt::UserRole);
    if (dataSet.isValid())
    {
        ext_toolbar_value_t * value_entry = VariantPointer<ext_toolbar_value_t>::asPtr(dataSet);
        item->callback(item, value_entry, item->user_data);
    }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
