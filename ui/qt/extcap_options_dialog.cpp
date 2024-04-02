/* extcap_options_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <extcap_options_dialog.h>
#include <ui_extcap_options_dialog.h>

#include <main_application.h>

#include <QMessageBox>
#include <QHash>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QUrl>
#include <QDesktopServices>
#include <QTabWidget>

#include "ringbuffer.h"
#include "ui/capture_ui_utils.h"
#include "ui/capture_globals.h"
#include "ui/iface_lists.h"

#include "ui/ws_ui_util.h"
#include "ui/util.h"
#include <wsutil/utf8_entities.h>

#include <cstdio>
#include <epan/addr_resolv.h>
#include <wsutil/filesystem.h>

#include <extcap.h>
#include <extcap_parser.h>

#include <ui/qt/utils/qt_ui_utils.h>

#include <epan/prefs.h>
#include <ui/preference_utils.h>

#include <ui/qt/main_application.h>
#include <ui/qt/utils/stock_icon.h>
#include <ui/qt/utils/variant_pointer.h>

#include <ui/qt/extcap_argument.h>
#include <ui/qt/extcap_argument_file.h>
#include <ui/qt/extcap_argument_multiselect.h>

ExtcapOptionsDialog::ExtcapOptionsDialog(bool startCaptureOnClose, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ExtcapOptionsDialog),
    device_name(""),
    device_idx(0),
    defaultValueIcon_(StockIcon("x-reset"))
{
    ui->setupUi(this);

    setWindowTitle(mainApp->windowTitleString(tr("Interface Options")));

    ui->checkSaveOnStart->setCheckState(prefs.extcap_save_on_start ? Qt::Checked : Qt::Unchecked);

    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Start"));
    if (startCaptureOnClose) {
        // This dialog was spawned because the user wanted to start a capture
        // immediately but a mandatory parameter was not configured.
        ui->buttonBox->button(QDialogButtonBox::Save)->hide();
    }
}

ExtcapOptionsDialog * ExtcapOptionsDialog::createForDevice(QString &dev_name, bool startCaptureOnClose, QWidget *parent)
{
    interface_t *device;
    ExtcapOptionsDialog * resultDialog = NULL;
    bool dev_found = false;
    unsigned if_idx;

    if (dev_name.length() == 0)
        return NULL;

    for (if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++)
    {
        device = &g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
        if (dev_name.compare(QString(device->name)) == 0 && device->if_info.type == IF_EXTCAP)
        {
            dev_found = true;
            break;
        }
    }

    if (! dev_found)
        return NULL;

    resultDialog = new ExtcapOptionsDialog(startCaptureOnClose, parent);
    resultDialog->device_name = QString(dev_name);
    resultDialog->device_idx = if_idx;

    resultDialog->setWindowTitle(mainApp->windowTitleString(tr("Interface Options") + ": " + device->display_name));

    resultDialog->updateWidgets();

    /* mark required fields */
    resultDialog->anyValueChanged();

    return resultDialog;
}


ExtcapOptionsDialog::~ExtcapOptionsDialog()
{
    delete ui;
}

void ExtcapOptionsDialog::anyValueChanged()
{
    bool allowStart = true;

    ExtcapArgumentList::const_iterator iter;

    /* All arguments are being iterated, to ensure, that any error handling catches all arguments */
    for (iter = extcapArguments.constBegin(); iter != extcapArguments.constEnd(); ++iter)
    {
        /* The dynamic casts are necessary, because we come here using the Signal/Slot system
         * of Qt, and -in short- Q_OBJECT classes cannot be multiple inherited. Another possibility
         * would be to use Q_INTERFACE, but this causes way more nightmares, and we really just
         * need here an explicit cast for the check functionality */
        if (dynamic_cast<ExtArgBool *>((*iter)) != NULL)
        {
            if (! ((ExtArgBool *)*iter)->isValid())
                allowStart = false;
        }
        else if (dynamic_cast<ExtArgRadio *>((*iter)) != NULL)
        {
            if (! ((ExtArgRadio *)*iter)->isValid())
                allowStart = false;
        }
        else if (dynamic_cast<ExtArgSelector *>((*iter)) != NULL)
        {
            if (! ((ExtArgSelector *)*iter)->isValid())
                allowStart = false;
        }
        else if (dynamic_cast<ExtArgMultiSelect *>((*iter)) != NULL)
        {
            if (! ((ExtArgMultiSelect *)*iter)->isValid())
                allowStart = false;
        }
        else if (dynamic_cast<ExtcapArgumentFileSelection *>((*iter)) != NULL)
        {
            if (! ((ExtcapArgumentFileSelection *)*iter)->isValid())
                allowStart = false;
        }
        else if (dynamic_cast<ExtArgNumber *>((*iter)) != NULL)
        {
            if (! ((ExtArgNumber *)*iter)->isValid())
                allowStart = false;
        }
        else if (dynamic_cast<ExtArgText *>((*iter)) != NULL)
        {
            if (! ((ExtArgText *)*iter)->isValid())
                allowStart = false;
        }
        else if (dynamic_cast<ExtArgTimestamp *>((*iter)) != NULL)
        {
            if (! ((ExtArgTimestamp *)*iter)->isValid())
                allowStart = false;
        }
        else
            if (! (*iter)->isValid())
                allowStart = false;
    }

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(allowStart);
}

void ExtcapOptionsDialog::loadArguments()
{
    GList * arguments = Q_NULLPTR, * walker = Q_NULLPTR, * item = Q_NULLPTR;
    ExtcapArgument * argument = Q_NULLPTR;

    if (device_name.length() == 0  )
        return;

    extcapArguments.clear();

    arguments = g_list_first(extcap_get_if_configuration(device_name.toUtf8().constData()));

    ExtcapArgumentList required;
    ExtcapArgumentList optional;

    walker = arguments;
    while (walker != Q_NULLPTR)
    {
        item = g_list_first(gxx_list_data(GList *, walker));
        while (item != Q_NULLPTR)
        {
            argument = ExtcapArgument::create(gxx_list_data(extcap_arg *, item), this);
            if (argument != Q_NULLPTR)
            {
                if (argument->isRequired())
                    required << argument;
                else
                    optional << argument;

            }
            item = item->next;
        }
        walker = gxx_list_next(walker);
    }

    if (required.length() > 0)
        extcapArguments << required;

    if (optional.length() > 0)
        extcapArguments << optional;

    /* argument items are now owned by ExtcapArgument. Only free the lists */
    extcap_free_if_configuration(arguments, false);
}

void ExtcapOptionsDialog::updateWidgets()
{
    QWidget * lblWidget = NULL, *editWidget = NULL;
    ExtcapArgument * argument = NULL;
    bool allowStart = true;

    unsigned int counter = 0;

    if (device_name.length() == 0  )
        return;

    /* find existing layout */
    if (ui->verticalLayout->children().count() > 0)
    {
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
        QWidget * item = ui->verticalLayout->itemAt(0)->widget();
        if (item)
        {
            ui->verticalLayout->removeItem(ui->verticalLayout->itemAt(0));
            delete item;
        }
    }

    QHash<QString, QWidget *> layouts;

    /* Load all extcap arguments */
    loadArguments();

    /* exit if no arguments have been found. This is a precaution, it should
     * never happen, that this dialog get's called without any arguments */
    if (extcapArguments.count() == 0)
    {
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
        return;
    }
    ui->checkSaveOnStart->setText(tr("Save parameter(s) on capture start", "", static_cast<int>(extcapArguments.count())));

    QStringList groupKeys;
    QString defaultKeyName(tr("Default"));
    /* QMap sorts keys, therefore the groups are sorted by appearance */
    QMap<int, QString> groups;

    /* Look for all necessary tabs */
    ExtcapArgumentList::iterator iter = extcapArguments.begin();
    while (iter != extcapArguments.end())
    {
        argument = (ExtcapArgument *)(*iter);
        QString groupKey = argument->group();
        if (groupKey.length() > 0)
        {
            if (! groups.values().contains(groupKey))
                groups.insert(argument->argNr(), groupKey);
        }
        else if (! groups.keys().contains(0))
        {
            groups.insert(0, defaultKeyName);
            groupKey = defaultKeyName;
        }

        if (! layouts.keys().contains(groupKey))
        {
            QWidget * tabWidget = new QWidget(this);
            QGridLayout * tabLayout = new QGridLayout(tabWidget);
            tabWidget->setLayout(tabLayout);

            layouts.insert(groupKey, tabWidget);
        }

        ++iter;
    }
    groupKeys << groups.values();

    /* Iterate over all arguments and do the following:
     *  1. create the label for each element
     *  2. create an editor for each element
     *  3. add both to the layout for the tab widget
     */
    iter = extcapArguments.begin();
    while (iter != extcapArguments.end())
    {
        argument = (ExtcapArgument *)(*iter);
        QString groupKey = defaultKeyName;
        if (argument->group().length() > 0)
            groupKey = argument->group();

        /* Skip non-assigned group keys, this happens if the configuration of the extcap is faulty */
        if (! layouts.keys().contains(groupKey))
        {
            ++iter;
            continue;
        }

        QGridLayout * layout = ((QGridLayout *)layouts[groupKey]->layout());
        lblWidget = argument->createLabel((QWidget *)this);
        if (lblWidget != NULL)
        {
            layout->addWidget(lblWidget, counter, 0, Qt::AlignVCenter);
            editWidget = argument->createEditor((QWidget *) this);
            if (editWidget != NULL)
            {
                editWidget->setProperty("extcap", VariantPointer<ExtcapArgument>::asQVariant(argument));
                layout->addWidget(editWidget, counter, 1, Qt::AlignVCenter);

                if (argument->isSetDefaultValueSupported())
                {
                    QPushButton *button = new QPushButton(defaultValueIcon_,"");
                    button->setToolTip(tr("Restore default value of the item"));
                    layout->addWidget(button, counter, 2, Qt::AlignVCenter);
                    connect(button, SIGNAL(clicked()), argument, SLOT(setDefaultValue()));
                }
            }

            if (argument->isRequired() && ! argument->isValid())
                allowStart = false;

            connect(argument, &ExtcapArgument::valueChanged, this, &ExtcapOptionsDialog::anyValueChanged);

            counter++;
        }
        ++iter;
    }

    if (counter > 0)
    {
        setStyleSheet ("QLabel[isRequired=\"true\"] { font-weight: bold; } ");

        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(allowStart);

        QWidget * mainWidget = Q_NULLPTR;

        /* We should never display the dialog, if no settings are present */
        Q_ASSERT(layouts.count() > 0);

        if (layouts.count() > 1)
        {
            QTabWidget * tabs = new QTabWidget(this);
            foreach (QString key, groupKeys)
            {
                layouts[key]->layout()->addItem(new QSpacerItem(0, 0, QSizePolicy::Minimum, QSizePolicy::MinimumExpanding));
                tabs->addTab(layouts[key], key);
            }

            tabs->setCurrentIndex(0);
            mainWidget = tabs;
        }
        else if (layouts.count() == 1)
            mainWidget = layouts[layouts.keys().at(0)];

        ui->verticalLayout->addWidget(mainWidget);
        ui->verticalLayout->addSpacerItem(new QSpacerItem(20, 100, QSizePolicy::Minimum, QSizePolicy::Expanding));
    }
    else
    {
        QList<QString> keys = layouts.keys();
        foreach (QString key, keys)
            delete(layouts[key]);
    }
}

void ExtcapOptionsDialog::on_buttonBox_helpRequested()
{
    interface_t *device;
    QString interface_help = NULL;

    device = &g_array_index(global_capture_opts.all_ifaces, interface_t, device_idx);
    interface_help = QString(extcap_get_help_for_ifname(device->name));
    /* The extcap interface didn't provide an help. Let's go with the default */
    if (interface_help.isEmpty()) {
        mainApp->helpTopicAction(HELP_EXTCAP_OPTIONS_DIALOG);
        return;
    }

    QUrl help_url(interface_help);

    /* Check the existence for a local file */
    if (help_url.isLocalFile()) {
        QString local_path = help_url.toLocalFile();
        QFileInfo help_file(local_path);
        if (!help_file.exists()) {
            QMessageBox::warning(this, tr("Extcap Help cannot be found"),
                QString(tr("The help for the extcap interface %1 cannot be found. Given file: %2"))
                    .arg(device->name).arg(QDir::toNativeSeparators(local_path)),
                QMessageBox::Ok);
            return;
        }
    }

    /* We have an actual url or an existing local file. Let's open it. */
    QDesktopServices::openUrl(help_url);
}

bool ExtcapOptionsDialog::saveOptionToCaptureInfo()
{
    GHashTable * ret_args;
    interface_t *device;

    device = &g_array_index(global_capture_opts.all_ifaces, interface_t, device_idx);
    ret_args = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    ExtcapArgumentList::const_iterator iter;

    for (iter = extcapArguments.constBegin(); iter != extcapArguments.constEnd(); ++iter)
    {
        QString call = (*iter)->call();
        QString value = (*iter)->value();
        QString prefValue = (*iter)->prefValue();

        if ((*iter)->argument()->arg_type != EXTCAP_ARG_BOOLFLAG && value.length() == 0)
            continue;

        if (call.length() <= 0) {
            continue;
        }

        if (value.compare((*iter)->defaultValue()) == 0) {
            // What _does_ required and also has a default mean (And how is
            // it different, if at all, from has a default and also placeholder
            // text)? Will the extcap use the default if we don't pass the
            // argument (so it's not really required)?
            // To be safe we can pass the default explicitly.
            if (!(*iter)->isRequired())
                continue;
        }

        char * call_string = qstring_strdup(call);
        char * value_string = NULL;
        if (value.length() > 0)
            value_string = qstring_strdup(value);

        g_hash_table_insert(ret_args, call_string, value_string);
    }

    if (device->external_cap_args_settings != NULL)
      g_hash_table_unref(device->external_cap_args_settings);
    device->external_cap_args_settings = ret_args;
    return true;
}

void ExtcapOptionsDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    /* Only the save button has the ActionRole */
    switch (ui->buttonBox->buttonRole(button)) {
    case QDialogButtonBox::ResetRole:
        resetValues();
        break;
    case QDialogButtonBox::RejectRole:
    case QDialogButtonBox::DestructiveRole:
        /* entries are only saved if saveOptionToCaptureInfo() is called,
         * so do nothing. */
        reject();
        break;
    case QDialogButtonBox::AcceptRole:
        if (saveOptionToCaptureInfo()) {
            /* Starting a new capture with those values */
            prefs.extcap_save_on_start = ui->checkSaveOnStart->checkState() == Qt::Checked;

            /* XXX - If extcap_save_on_start is the only preference that has
             * changed, or if it changed from true to false, we should write
             * out a new preference file with its new value, but don't.
             */
            if (ui->buttonBox->standardButton(button) == QDialogButtonBox::Save) {
                storeValues();
                /* Reject the dialog, because we don't want to start a capture. */
                reject();
            } else {
                /* Start */
                if (prefs.extcap_save_on_start) {
                    storeValues();
                }
                accept();
            }
        }
        break;
    default:
        break;
    }
}

void ExtcapOptionsDialog::resetValues()
{
    int count = ui->verticalLayout->count();
    if (count > 0)
    {
        QList<QLayout *> layouts;

        /* Find all layouts */
        if (qobject_cast<QTabWidget *>(ui->verticalLayout->itemAt(0)->widget()))
        {
            QTabWidget * tabs = qobject_cast<QTabWidget *>(ui->verticalLayout->itemAt(0)->widget());
            for (int cnt = 0; cnt < tabs->count(); cnt++)
            {
                layouts.append(tabs->widget(cnt)->layout());
            }
        }
        else
            layouts.append(ui->verticalLayout->itemAt(0)->layout());

        /* Loop over all layouts */
        for (int cnt = 0; cnt < layouts.count(); cnt++)
        {
            QGridLayout * layout = qobject_cast<QGridLayout *>(layouts.at(cnt));
            if (! layout)
                continue;

            /* Loop over all widgets in column 1 on layout */
            for (int row = 0; row < layout->rowCount(); row++)
            {
                QWidget * child = Q_NULLPTR;
                if (layout->itemAtPosition(row, 1))
                    child = qobject_cast<QWidget *>(layout->itemAtPosition(row, 1)->widget());

                if (child)
                {
                    /* Don't need labels, the edit widget contains the extcapargument property value */
                    ExtcapArgument * arg = 0;
                    QVariant prop = child->property("extcap");

                    if (prop.isValid())
                    {
                        arg = VariantPointer<ExtcapArgument>::asPtr(prop);

                        /* value<> can fail */
                        if (arg)
                        {
                            arg->setDefaultValue();
                        }
                    }
                }
            }

        }

        /* Values are stored when dialog is committed, just check validity */
        anyValueChanged();
    }
}

GHashTable *ExtcapOptionsDialog::getArgumentSettings(bool useCallsAsKey, bool includeEmptyValues)
{
    GHashTable * entries = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    ExtcapArgumentList::const_iterator iter;

    QString value;

    /* All arguments are being iterated, to ensure, that any error handling catches all arguments */
    for (iter = extcapArguments.constBegin(); iter != extcapArguments.constEnd(); ++iter)
    {
        ExtcapArgument * argument = (ExtcapArgument *)(*iter);
        bool isBoolflag = false;

        /* The dynamic casts are necessary, because we come here using the Signal/Slot system
         * of Qt, and -in short- Q_OBJECT classes cannot be multiple inherited. Another possibility
         * would be to use Q_INTERFACE, but this causes way more nightmares, and we really just
         * need here an explicit cast for the check functionality */
        if (dynamic_cast<ExtArgBool *>((*iter)) != NULL)
        {
            value = ((ExtArgBool *)*iter)->prefValue();
            // For boolflag there should be no value
            if ((*iter)->argument()->arg_type != EXTCAP_ARG_BOOLFLAG)
                isBoolflag = true;
        }
        else if (dynamic_cast<ExtArgRadio *>((*iter)) != NULL)
        {
            value = ((ExtArgRadio *)*iter)->prefValue();
        }
        else if (dynamic_cast<ExtArgSelector *>((*iter)) != NULL)
        {
            value = ((ExtArgSelector *)*iter)->prefValue();
        }
        else if (dynamic_cast<ExtArgMultiSelect *>((*iter)) != NULL)
        {
            value = ((ExtArgMultiSelect *)*iter)->prefValue();
        }
        else if (dynamic_cast<ExtcapArgumentFileSelection *>((*iter)) != NULL)
        {
            value = ((ExtcapArgumentFileSelection *)*iter)->prefValue();
        }
        else if (dynamic_cast<ExtArgNumber *>((*iter)) != NULL)
        {
            value = ((ExtArgNumber *)*iter)->prefValue();
        }
        else if (dynamic_cast<ExtArgText *>((*iter)) != NULL)
        {
            value = ((ExtArgText *)*iter)->prefValue();
        }
        else if (dynamic_cast<ExtArgTimestamp *>((*iter)) != NULL)
        {
            value = ((ExtArgTimestamp *)*iter)->prefValue();
        }
        else
            value = (*iter)->prefValue();

        QString key = argument->prefKey(device_name);
        if (useCallsAsKey)
            key = argument->call();

        if ((key.length() > 0) && (includeEmptyValues || isBoolflag || value.length() > 0) )
        {
            char * val = qstring_strdup(value);

            g_hash_table_insert(entries, qstring_strdup(key), val);
        }
    }

    return entries;
}

void ExtcapOptionsDialog::storeValues()
{
    GHashTable * entries = getArgumentSettings();

    if (g_hash_table_size(entries) > 0)
    {
        if (prefs_store_ext_multiple("extcap", entries))
            mainApp->emitAppSignal(MainApplication::PreferencesChanged);

    }

    g_hash_table_unref(entries);
}

ExtcapValueList ExtcapOptionsDialog::loadValuesFor(int argNum, QString argumentName, QString parent)
{
    ExtcapValueList elements;
    GList * walker = 0, * values = 0;
    extcap_value * v;

    QList<QWidget *> children = findChildren<QWidget *>();
    foreach (QWidget * child, children)
        child->setEnabled(false);

    QString argcall = argumentName;
    if (argcall.startsWith("--"))
        argcall = argcall.right(argcall.size()-2);

    GHashTable * entries = getArgumentSettings(true, false);

    values = extcap_get_if_configuration_values(this->device_name.toStdString().c_str(), argcall.toStdString().c_str(), entries);

    for (walker = g_list_first((GList *)(values)); walker != NULL ; walker = walker->next)
    {
        v = (extcap_value *) walker->data;
        if (v == NULL || v->display == NULL || v->call == NULL)
            break;

        /* Only accept values for this argument */
        if (v->arg_num != argNum)
            break;

        QString valParent = QString().fromUtf8(v->parent);

        if (parent.compare(valParent) == 0)
        {

            QString display = QString().fromUtf8(v->display);
            QString call = QString().fromUtf8(v->call);

            ExtcapValue element = ExtcapValue(display, call,
                            v->enabled == true, v->is_default == true);

#if 0
            /* TODO: Disabled due to wrong parent handling. It leads to an infinite loop for now. To implement this properly, other things
               will be needed, like new arguments for setting the parent in the call to the extcap utility*/
            if (!call.isEmpty())
                element.setChildren(this->loadValuesFor(argumentName, call));
#endif

            elements.append(element);
        }
    }

    foreach (QWidget * child, children)
        child->setEnabled(true);

    return elements;
}
