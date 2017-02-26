/* additional_toolbar.cpp
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

#include <additional_toolbar.h>
#include <config.h>

#include <glib.h>

#include <ui/qt/apply_line_edit.h>
#include <ui/qt/qt_ui_utils.h>
#include <ui/qt/variant_pointer.h>
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
    if ( g_list_length( toolbar->children ) == 0 )
        return NULL;

    AdditionalToolBar * result = new AdditionalToolBar(toolbar, parent);
    result->setMovable(false);
    result->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::MinimumExpanding);
    result->layout()->setMargin(0);
    result->layout()->setSpacing(4);

    GList * walker = toolbar->children;
    bool spacerNeeded = true;

    while ( walker && walker->data )
    {
        ext_toolbar_t * item = (ext_toolbar_t *)walker->data;
        if ( item->type == EXT_TOOLBAR_ITEM )
        {
            if ( item->item_type == EXT_TOOLBAR_STRING )
                spacerNeeded = false;

            QAction * newAction = new AdditionalToolbarWidgetAction(item, result);
            if ( newAction )
            {
                result->addAction(newAction);
                /* Necessary, because enable state is resetted upon adding the action */
                result->actions()[result->actions().count() - 1]->setEnabled(!item->capture_only);
            }
        }

        walker = g_list_next ( walker );
    }

    if ( result->children().count() == 0 )
        return NULL;

    if ( spacerNeeded )
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
    connect(wsApp, SIGNAL(captureActive(int)), this, SLOT(captureActive(int)));
}

AdditionalToolbarWidgetAction::AdditionalToolbarWidgetAction(const AdditionalToolbarWidgetAction & copy_object)
:  QWidgetAction(copy_object.parent()),
   toolbar_item(copy_object.toolbar_item)
{
    connect(wsApp, SIGNAL(captureActive(int)), this, SLOT(captureActive(int)));
}


void AdditionalToolbarWidgetAction::captureActive(int activeCaptures)
{
    if ( toolbar_item && toolbar_item->capture_only )
    {
        setEnabled(activeCaptures != 0);
    }
}

/* Exists, so a default deconstructor does not call delete on toolbar_item */
AdditionalToolbarWidgetAction::~AdditionalToolbarWidgetAction() { }

QWidget * AdditionalToolbarWidgetAction::createWidget(QWidget * parent)
{
    QWidget * barItem = 0;

    if ( toolbar_item->type != EXT_TOOLBAR_ITEM )
        return barItem;

    switch ( toolbar_item->item_type )
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

    if ( ! barItem )
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
    if ( ! item || ! item_data || ! user_data )
        return;

    QPushButton * widget = (QPushButton *)(item_data);
    ext_toolbar_update_t * update_entry = (ext_toolbar_update_t *)user_data;

    if ( widget && update_entry->type == EXT_TOOLBAR_UPDATE_VALUE )
        widget->setText((gchar *)update_entry->user_data);
}

QWidget * AdditionalToolbarWidgetAction::createButton(ext_toolbar_t * item, QWidget * parent)
{
    if ( ! item || item->type != EXT_TOOLBAR_ITEM || item->item_type != EXT_TOOLBAR_BUTTON )
        return 0;

    QString defValue = item->defvalue;

    QPushButton * button = new QPushButton(item->name, parent);
    button->setText(item->name);
    connect(button, SIGNAL(clicked()), this, SLOT(onButtonClicked()));

    ext_toolbar_register_update_cb(item, (ext_toolbar_action_cb)&toolbar_button_cb, (void *)button);

    return button;
}

static void
toolbar_boolean_cb(gpointer item, gpointer item_data, gpointer user_data)
{
    if ( ! item || ! item_data || ! user_data )
        return;

    QCheckBox * widget = (QCheckBox *)(item_data);
    ext_toolbar_update_t * update_entry = (ext_toolbar_update_t *)user_data;

    if ( widget && update_entry->type == EXT_TOOLBAR_UPDATE_VALUE )
    {
        bool oldState = false;
        if ( update_entry->silent )
            oldState = widget->blockSignals(true);

        widget->setCheckState(GPOINTER_TO_INT(update_entry->user_data) == 1 ? Qt::Checked : Qt::Unchecked);

        if ( update_entry->silent )
            widget->blockSignals(oldState);
    }
}

QWidget * AdditionalToolbarWidgetAction::createBoolean(ext_toolbar_t * item, QWidget * parent)
{
    if ( ! item || item->type != EXT_TOOLBAR_ITEM || item->item_type != EXT_TOOLBAR_BOOLEAN )
        return 0;

    QString defValue = toolbar_item->defvalue;

    QCheckBox * checkbox = new QCheckBox(item->name, parent);
    checkbox->setText(item->name);
    setCheckable(true);
    checkbox->setCheckState(defValue.compare("true", Qt::CaseInsensitive) == 0 ? Qt::Checked : Qt::Unchecked);
    connect(checkbox, SIGNAL(stateChanged(int)), this, SLOT(onCheckBoxChecked(int)));

    ext_toolbar_register_update_cb(item, (ext_toolbar_action_cb)&toolbar_boolean_cb, (void *)checkbox);

    return checkbox;
}

QWidget * AdditionalToolbarWidgetAction::createLabelFrame(ext_toolbar_t * item, QWidget * parent)
{
    if ( ! item )
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
    if ( ! item || ! item_data || ! user_data )
        return;

    ApplyLineEdit * edit = (ApplyLineEdit *)(item_data);
    ext_toolbar_update_t * update_entry = (ext_toolbar_update_t *)user_data;

    if ( edit && update_entry->type == EXT_TOOLBAR_UPDATE_VALUE )
    {
        bool oldState = false;
        if ( update_entry->silent )
            oldState = edit->blockSignals(true);

        edit->setText((gchar *)update_entry->user_data);

        if ( update_entry->silent )
            edit->blockSignals(oldState);
    }
}

QWidget * AdditionalToolbarWidgetAction::createTextEditor(ext_toolbar_t * item, QWidget * parent)
{
    if ( ! item || item->type != EXT_TOOLBAR_ITEM || item->item_type != EXT_TOOLBAR_STRING )
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

    connect(strEdit, SIGNAL(textApplied()), this, SLOT(sendTextToCallback()));

    ext_toolbar_register_update_cb(item, (ext_toolbar_action_cb)&toolbar_string_cb, (void *)strEdit);

    return frame;
}

static void
toolbar_selector_cb(gpointer item, gpointer item_data, gpointer user_data)
{
    if ( ! item || ! item_data || ! user_data )
        return;

    QComboBox * comboBox = (QComboBox *)(item_data);
    ext_toolbar_update_t * update_entry = (ext_toolbar_update_t *)user_data;

    bool oldState = false;

    if ( update_entry->silent )
        oldState = comboBox->blockSignals(true);

    if ( update_entry->type == EXT_TOOLBAR_UPDATE_VALUE )
    {
        QString data = QString((gchar *)update_entry->user_data);
        bool conv_ok = false;

        int dataValue = data.toInt(&conv_ok, 10);
        if ( conv_ok && dataValue >= 0 && comboBox->model()->rowCount() < dataValue )
            comboBox->setCurrentIndex(dataValue);
        else
        {
#if QT_VERSION >= QT_VERSION_CHECK(5, 0, 0)
            comboBox->setCurrentText(data);
#else
            for(int i = 0; i < comboBox->model()->rowCount(); i++)
            {
                QStandardItem * dataValue = ((QStandardItemModel *)comboBox->model())->item(i, 0);
                ext_toolbar_value_t * tbValue = VariantPointer<ext_toolbar_value_t>::asPtr(dataValue->data());
                if ( data.compare(QString(tbValue->display)) )
                {
                    comboBox->setCurrentIndex(i);
                    break;
                }
            }
#endif
        }
    }
    else if ( update_entry->type == EXT_TOOLBAR_UPDATE_DATA )
    {
        QStandardItemModel * sourceModel = (QStandardItemModel *)comboBox->model();

        GList * walker = (GList *)update_entry->user_data;
        if ( g_list_length(walker) == 0 )
            return;

        sourceModel->clear();

        while ( walker && walker->data )
        {
            ext_toolbar_value_t * listvalue = (ext_toolbar_value_t *)walker->data;

            QStandardItem * si = new QStandardItem(listvalue->display);
            si->setData(VariantPointer<ext_toolbar_value_t>::asQVariant(listvalue), Qt::UserRole);
            sourceModel->appendRow(si);

            walker = g_list_next(walker);
        }
    }
    else if ( update_entry->type == EXT_TOOLBAR_UPDATE_DATABYINDEX )
    {
        QStandardItemModel * sourceModel = (QStandardItemModel *)comboBox->model();

        if ( ! update_entry->user_data || ! update_entry->data_index )
            return;

        gchar * idx = (gchar *)update_entry->data_index;
        gchar * display = (gchar *)update_entry->user_data;

        for ( int i = 0; i < sourceModel->rowCount(); i++ )
        {
            QStandardItem * item = sourceModel->item(i, 0);
            ext_toolbar_value_t * entry = VariantPointer<ext_toolbar_value_t>::asPtr(item->data(Qt::UserRole));
            if ( entry && g_strcmp0( entry->value, idx) == 0 )
            {
                item->setText(display);
                break;
            }
        }
    }

    if ( update_entry->silent )
        comboBox->blockSignals(oldState);

}

QWidget * AdditionalToolbarWidgetAction::createSelector(ext_toolbar_t * item, QWidget * parent)
{
    if ( ! item || item->type != EXT_TOOLBAR_ITEM || item->item_type != EXT_TOOLBAR_SELECTOR )
        return 0;

    if ( g_list_length(item->values) == 0 )
        return 0;

    QWidget * frame = createLabelFrame(item, parent);

    QComboBox * myBox = new QComboBox(parent);
    myBox->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);

    QStandardItemModel * sourceModel = new QStandardItemModel();

    GList * walker = item->values;
    int selIndex = 0;
    while ( walker && walker->data )
    {
        ext_toolbar_value_t * listvalue = (ext_toolbar_value_t *)walker->data;

        QStandardItem * si = new QStandardItem(listvalue->display);
        si->setData(VariantPointer<ext_toolbar_value_t>::asQVariant(listvalue), Qt::UserRole);
        sourceModel->appendRow(si);

        if ( listvalue->is_default )
            selIndex = sourceModel->rowCount();

        walker = g_list_next(walker);
    }

    myBox->setModel(sourceModel);
    myBox->setCurrentIndex(selIndex);

#ifdef Q_OS_MAC
    myBox->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    frame->layout()->addWidget(myBox);

    connect(myBox, SIGNAL(currentIndexChanged(int)), this, SLOT(onSelectionInWidgetChanged(int)));

    ext_toolbar_register_update_cb(item, (ext_toolbar_action_cb)&toolbar_selector_cb, (void *)myBox);

    return frame;
}

ext_toolbar_t * AdditionalToolbarWidgetAction::extractToolbarItemFromObject(QObject * object)
{
    QWidget * widget = dynamic_cast<QWidget *>(object);
    if ( ! widget )
        return 0;

    QVariant propValue = widget->property(propertyName);

    /* If property is invalid, look if our parent has this property */
    if ( ! propValue.isValid() )
    {
        QWidget * frame = dynamic_cast<QWidget *>(widget->parent());
        if ( ! frame )
            return 0;

        propValue = frame->property(propertyName);
    }

    if ( ! propValue.isValid() )
        return 0;

    return VariantPointer<ext_toolbar_t>::asPtr(propValue);
}

void AdditionalToolbarWidgetAction::onButtonClicked()
{
    ext_toolbar_t * item = extractToolbarItemFromObject(sender());
    if ( ! item )
        return;

    item->callback(item, 0, item->user_data);
}

void AdditionalToolbarWidgetAction::onCheckBoxChecked(int checkState)
{
    ext_toolbar_t * item = extractToolbarItemFromObject(sender());
    if ( ! item )
        return;

    gboolean value = checkState == Qt::Checked ? true : false;

    item->callback(item, &value, item->user_data);
}

void AdditionalToolbarWidgetAction::sendTextToCallback()
{
    ext_toolbar_t * item = extractToolbarItemFromObject(sender());
    if ( ! item )
        return;

    if (item->item_type != EXT_TOOLBAR_STRING )
        return;

    ApplyLineEdit * editor = dynamic_cast<ApplyLineEdit *>(sender());
    if ( ! editor )
    {
        /* Called from button, searching for acompanying line edit */
        QWidget * parent = dynamic_cast<QWidget *>(sender()->parent());
        if ( parent )
        {
            QList<ApplyLineEdit *> children = parent->findChildren<ApplyLineEdit *>();
            if ( children.count() >= 0 )
                editor = children.at(0);
        }
    }

    if ( editor )
        item->callback(item, qstring_strdup(editor->text()), item->user_data);
}

void AdditionalToolbarWidgetAction::onSelectionInWidgetChanged(int idx)
{
    QComboBox * editor = dynamic_cast<QComboBox *>(sender());
    ext_toolbar_t * item = extractToolbarItemFromObject(editor);
    if ( ! item || item->item_type != EXT_TOOLBAR_SELECTOR )
        return;

    QStandardItemModel * sourceModel = (QStandardItemModel *) editor->model();
    if ( sourceModel->rowCount() <= idx )
        return;

    QModelIndex mdIdx = sourceModel->index(idx, 0);
    QVariant dataSet = sourceModel->data(mdIdx, Qt::UserRole);
    if ( dataSet.isValid() )
    {
        ext_toolbar_value_t * value_entry = VariantPointer<ext_toolbar_value_t>::asPtr(dataSet);
        item->callback(item, value_entry, item->user_data);
    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
