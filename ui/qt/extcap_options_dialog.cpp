/* extcap_options_dialog.cpp
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

#include <config.h>

#include <glib.h>

#include <extcap_options_dialog.h>
#include <ui_extcap_options_dialog.h>

#include <wireshark_application.h>

#ifdef HAVE_EXTCAP
#include <QMessageBox>
#include <QMap>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>

#include "ringbuffer.h"
#include "ui/capture_ui_utils.h"
#include "ui/capture_globals.h"
#include "ui/iface_lists.h"
#include "ui/last_open_dir.h"

#include "ui/ui_util.h"
#include "ui/util.h"
#include <wsutil/utf8_entities.h>

#include <cstdio>
#include <epan/addr_resolv.h>
#include <wsutil/filesystem.h>

#include <extcap.h>
#include <extcap_parser.h>

#include "qt_ui_utils.h"

#include <epan/prefs.h>
#include <ui/preference_utils.h>

#include <ui/qt/wireshark_application.h>

#include <ui/qt/extcap_argument.h>
#include <ui/qt/extcap_argument_file.h>
#include <ui/qt/extcap_argument_multiselect.h>

ExtcapOptionsDialog::ExtcapOptionsDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ExtcapOptionsDialog),
    device_name(""),
    device_idx(0)
{
    ui->setupUi(this);

    setWindowTitle(wsApp->windowTitleString(tr("Extcap Interface Options")));

    ui->checkSaveOnStart->setCheckState(prefs.extcap_save_on_start ? Qt::Checked : Qt::Unchecked);

    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Start"));
}

ExtcapOptionsDialog * ExtcapOptionsDialog::createForDevice(QString &dev_name, QWidget *parent)
{
    interface_t device;
    ExtcapOptionsDialog * resultDialog = NULL;
    bool dev_found = false;
    guint if_idx;

    if ( dev_name.length() == 0 )
        return NULL;

    for (if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++)
    {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
        if (dev_name.compare(QString(device.name)) == 0 && device.if_info.type == IF_EXTCAP)
        {
            dev_found = true;
            break;
        }
    }

    if ( ! dev_found )
        return NULL;

    resultDialog = new ExtcapOptionsDialog(parent);
    resultDialog->device_name = QString(dev_name);
    resultDialog->device_idx = if_idx;

    resultDialog->setWindowTitle(wsApp->windowTitleString(tr("Extcap Interface Options") + ": " + device.display_name));

    resultDialog->updateWidgets();

    /* mark required fields */
    resultDialog->anyValueChanged();

    return resultDialog;
}


ExtcapOptionsDialog::~ExtcapOptionsDialog()
{
    delete ui;
}

void ExtcapOptionsDialog::on_buttonBox_accepted()
{
    if (saveOptionToCaptureInfo()) {
        /* Starting a new capture with those values */
        prefs.extcap_save_on_start = ui->checkSaveOnStart->checkState() == Qt::Checked;

        if ( prefs.extcap_save_on_start )
            storeValues();

        accept();
    }
}

void ExtcapOptionsDialog::anyValueChanged()
{
    bool allowStart = true;

    ExtcapArgumentList::const_iterator iter;

    /* All arguments are being iterated, to ensure, that any error handling catches all arguments */
    for(iter = extcapArguments.constBegin(); iter != extcapArguments.constEnd(); ++iter)
    {
        /* The dynamic casts are necessary, because we come here using the Signal/Slot system
         * of Qt, and -in short- Q_OBJECT classes cannot be multiple inherited. Another possibility
         * would be to use Q_INTERFACE, but this causes way more nightmares, and we really just
         * need here an explicit cast for the check functionality */
        if ( dynamic_cast<ExtArgBool *>((*iter)) != NULL)
        {
            if ( ! ((ExtArgBool *)*iter)->isValid() )
                allowStart = false;
        }
        else if ( dynamic_cast<ExtArgRadio *>((*iter)) != NULL)
        {
            if ( ! ((ExtArgRadio *)*iter)->isValid() )
                allowStart = false;
        }
        else if ( dynamic_cast<ExtArgSelector *>((*iter)) != NULL)
        {
            if ( ! ((ExtArgSelector *)*iter)->isValid() )
                allowStart = false;
        }
        else if ( dynamic_cast<ExtArgMultiSelect *>((*iter)) != NULL)
        {
            if ( ! ((ExtArgMultiSelect *)*iter)->isValid() )
                allowStart = false;
        }
        else if ( dynamic_cast<ExtcapArgumentFileSelection *>((*iter)) != NULL)
        {
            if ( ! ((ExtcapArgumentFileSelection *)*iter)->isValid() )
                allowStart = false;
        }
        else if ( dynamic_cast<ExtArgNumber *>((*iter)) != NULL)
        {
            if ( ! ((ExtArgNumber *)*iter)->isValid() )
                allowStart = false;
        }
        else if ( dynamic_cast<ExtArgText *>((*iter)) != NULL)
        {
            if ( ! ((ExtArgText *)*iter)->isValid() )
                allowStart = false;
        }
        else
            if ( ! (*iter)->isValid() )
                allowStart = false;
    }

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(allowStart);
}

void ExtcapOptionsDialog::loadArguments()
{
    GList * arguments = NULL, * item = NULL;
    ExtcapArgument * argument = NULL;

    if ( device_name.length() == 0  )
        return;

    extcapArguments.clear();

    arguments = g_list_first(extcap_get_if_configuration((const char *)( device_name.toStdString().c_str() ) ));

    ExtcapArgumentList required;
    ExtcapArgumentList optional;

    while ( arguments != NULL )
    {
        item = g_list_first((GList *)(arguments->data));
        while ( item != NULL )
        {
            argument = ExtcapArgument::create((extcap_arg *)(item->data));
            if ( argument != NULL )
            {
                if ( argument->isRequired() )
                    required << argument;
                else
                    optional << argument;

            }
            item = item->next;
        }
        arguments = g_list_next(arguments);
    }

    if ( required.length() > 0 )
        extcapArguments << required;

    if ( optional.length() > 0 )
        extcapArguments << optional;
}

void ExtcapOptionsDialog::updateWidgets()
{
    QWidget * lblWidget = NULL, *editWidget = NULL;
    ExtcapArgument * argument = NULL;
    bool allowStart = true;

    unsigned int counter = 0;

    if ( device_name.length() == 0  )
        return;

    /* find existing layout */
    if (ui->verticalLayout->children().count() > 0)
    {
        QGridLayout * layout = (QGridLayout *)ui->verticalLayout->itemAt(0);
        ui->verticalLayout->removeItem(layout);
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    }

    QGridLayout * layout = new QGridLayout();

    /* Load all extcap arguments */
    loadArguments();


    ExtcapArgumentList::iterator iter = extcapArguments.begin();
    while ( iter != extcapArguments.end() )
    {
        argument = (ExtcapArgument *)(*iter);
        lblWidget = argument->createLabel((QWidget *)this);
        if ( lblWidget != NULL )
        {
            layout->addWidget(lblWidget, counter, 0, Qt::AlignVCenter);
            editWidget = argument->createEditor((QWidget *) this);
            if ( editWidget != NULL )
            {
                editWidget->setProperty(QString("extcap").toLocal8Bit(), QVariant::fromValue(argument));
                layout->addWidget(editWidget, counter, 1, Qt::AlignVCenter);
            }

            if ( argument->isRequired() && ! argument->isValid() )
                allowStart = false;

            connect(argument, SIGNAL(valueChanged()), this, SLOT(anyValueChanged()));

            counter++;
        }
        ++iter;
    }

    if ( counter > 0 )
    {
        setStyleSheet ( "QLabel[isRequired=\"true\"] { font-weight: bold; } ");

        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(allowStart);

        ui->verticalLayout->addLayout(layout);
        ui->verticalLayout->addSpacerItem(new QSpacerItem(20, 100, QSizePolicy::Minimum, QSizePolicy::Expanding));
    }
    else
    {
        delete layout;
    }
}

// Not sure why we have to do this manually.
void ExtcapOptionsDialog::on_buttonBox_rejected()
{
    reject();
}

void ExtcapOptionsDialog::on_buttonBox_helpRequested()
{
    // Probably the wrong URL.
    wsApp->helpTopicAction(HELP_EXTCAP_OPTIONS_DIALOG);
}

bool ExtcapOptionsDialog::saveOptionToCaptureInfo()
{
    GHashTable * ret_args;
    interface_t device;

    device = g_array_index(global_capture_opts.all_ifaces, interface_t, device_idx);
    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, device_idx);

    ret_args = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    ExtcapArgumentList::const_iterator iter;

    for(iter = extcapArguments.constBegin(); iter != extcapArguments.constEnd(); ++iter)
    {
        QString call = (*iter)->call();
        QString value = (*iter)->value();

        if ((*iter)->argument()->arg_type != EXTCAP_ARG_BOOLFLAG && value.length() == 0)
            continue;

        if ( call.length() <= 0 )
            continue;

        if ( value.compare((*iter)->defaultValue()) == 0 )
            continue;

        gchar * call_string = g_strdup(call.toStdString().c_str());
        gchar * value_string = g_strdup(value.toStdString().c_str());

        g_hash_table_insert(ret_args, call_string, value_string );
    }

    if (device.external_cap_args_settings != NULL)
      g_hash_table_unref(device.external_cap_args_settings);
    device.external_cap_args_settings = ret_args;

    g_array_insert_val(global_capture_opts.all_ifaces, device_idx, device);

    return true;
}

void ExtcapOptionsDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    /* Only the save button has the ActionRole */
    if ( ui->buttonBox->buttonRole(button) == QDialogButtonBox::ResetRole )
        resetValues();
}

void ExtcapOptionsDialog::resetValues()
{
    ExtcapArgumentList::const_iterator iter;
    QString value;

    if (ui->verticalLayout->children().count() > 0)
    {
        QGridLayout * layout = (QGridLayout *)ui->verticalLayout->findChild<QGridLayout *>();

        for ( int row = 0; row < layout->rowCount(); row++ )
        {
            QWidget * child = layout->itemAtPosition(row, 1)->widget();

            if ( child )
            {
                /* Don't need labels, the edit widget contains the extcapargument property value */
                ExtcapArgument * arg = 0;
                QVariant prop = child->property(QString("extcap").toLocal8Bit());

                if ( prop.isValid() && prop.canConvert<ExtcapArgument *>())
                {
                    arg = prop.value<ExtcapArgument *>();

                    /* value<> can fail */
                    if (arg)
                    {
                        arg->resetValue();

                        /* replacing the edit widget after resetting will lead to default value */
                        layout->removeItem(layout->itemAtPosition(row, 1));
                        QWidget * editWidget = arg->createEditor((QWidget *) this);
                        if ( editWidget != NULL )
                        {
                            editWidget->setProperty(QString("extcap").toLocal8Bit(), QVariant::fromValue(arg));
                            layout->addWidget(editWidget, row, 1, Qt::AlignVCenter);
                        }
                    }
                }
            }
        }

        /* this stores all values to the preferences */
        storeValues();
    }
}

void ExtcapOptionsDialog::storeValues()
{
    GHashTable * entries = g_hash_table_new(g_str_hash, g_str_equal);
    ExtcapArgumentList::const_iterator iter;

    QString value;

    /* All arguments are being iterated, to ensure, that any error handling catches all arguments */
    for(iter = extcapArguments.constBegin(); iter != extcapArguments.constEnd(); ++iter)
    {
        ExtcapArgument * argument = (ExtcapArgument *)(*iter);

        /* The dynamic casts are necessary, because we come here using the Signal/Slot system
         * of Qt, and -in short- Q_OBJECT classes cannot be multiple inherited. Another possibility
         * would be to use Q_INTERFACE, but this causes way more nightmares, and we really just
         * need here an explicit cast for the check functionality */
        if ( dynamic_cast<ExtArgBool *>((*iter)) != NULL)
        {
            value = ((ExtArgBool *)*iter)->prefValue();
        }
        else if ( dynamic_cast<ExtArgRadio *>((*iter)) != NULL)
        {
            value = ((ExtArgRadio *)*iter)->prefValue();
        }
        else if ( dynamic_cast<ExtArgSelector *>((*iter)) != NULL)
        {
            value = ((ExtArgSelector *)*iter)->prefValue();
        }
        else if ( dynamic_cast<ExtArgMultiSelect *>((*iter)) != NULL)
        {
            value = ((ExtArgMultiSelect *)*iter)->prefValue();
        }
        else if ( dynamic_cast<ExtcapArgumentFileSelection *>((*iter)) != NULL)
        {
            value = ((ExtcapArgumentFileSelection *)*iter)->prefValue();
        }
        else if ( dynamic_cast<ExtArgNumber *>((*iter)) != NULL)
        {
            value = ((ExtArgNumber *)*iter)->prefValue();
        }
        else if ( dynamic_cast<ExtArgText *>((*iter)) != NULL)
        {
            value = ((ExtArgText *)*iter)->prefValue();
        }
        else
            value = (*iter)->prefValue();

        QString key = argument->prefKey(device_name);
        if (key.length() > 0)
        {
            gchar * val = g_strdup(value.length() == 0 ? " " : value.toStdString().c_str());

            /* Setting the internally stored value for the preference to the new value */
            extcap_pref_store((*iter)->argument(), val);

            g_hash_table_insert(entries, g_strdup(key.toStdString().c_str()), val);
        }
    }

    if ( g_hash_table_size(entries) > 0 )
    {
        if ( prefs_store_ext_multiple("extcap", entries) )
            wsApp->emitAppSignal(WiresharkApplication::PreferencesChanged);

    }
}


#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
