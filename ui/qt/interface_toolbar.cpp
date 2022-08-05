/* interface_toolbar.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>

#include "interface_toolbar.h"
#include <ui/qt/widgets/interface_toolbar_lineedit.h>
#include "simple_dialog.h"
#include "main_application.h"
#include <ui_interface_toolbar.h>

#include "capture_opts.h"
#include "ui/capture_globals.h"
#include "sync_pipe.h"
#include "wsutil/file_util.h"

#ifdef _WIN32
#include <wsutil/win32-utils.h>
#endif

#include <QCheckBox>
#include <QComboBox>
#include <QDesktopServices>
#include <QLineEdit>
#include <QPushButton>
#include <QThread>
#include <QUrl>

static const char *interface_type_property = "control_type";
static const char *interface_role_property = "control_role";

// From interface control protocol.
enum InterfaceControlCommand {
    commandControlInitialized  = 0,
    commandControlSet          = 1,
    commandControlAdd          = 2,
    commandControlRemove       = 3,
    commandControlEnable       = 4,
    commandControlDisable      = 5,
    commandStatusMessage       = 6,
    commandInformationMessage  = 7,
    commandWarningMessage      = 8,
    commandErrorMessage        = 9
};

// To do:
// - Move control pipe handling to extcap

InterfaceToolbar::InterfaceToolbar(QWidget *parent, const iface_toolbar *toolbar) :
    QFrame(parent),
    ui(new Ui::InterfaceToolbar),
    help_link_(toolbar->help),
    use_spacer_(true)
{
    ui->setupUi(this);

    // Fill inn interfaces list and initialize default interface values
    for (GList *walker = toolbar->ifnames; walker; walker = walker->next)
    {
        QString ifname((gchar *)walker->data);
        interface_[ifname].reader_thread = NULL;
        interface_[ifname].out_fd = -1;
    }

    initializeControls(toolbar);

#ifdef Q_OS_MAC
    foreach (QWidget *w, findChildren<QWidget *>())
    {
        w->setAttribute(Qt::WA_MacSmallSize, true);
    }
#endif

    if (!use_spacer_)
    {
        ui->horizontalSpacer->changeSize(0,0, QSizePolicy::Fixed, QSizePolicy::Fixed);
    }

    updateWidgets();
}

InterfaceToolbar::~InterfaceToolbar()
{
    foreach (QString ifname, interface_.keys())
    {
        foreach (int num, control_widget_.keys())
        {
            if (interface_[ifname].log_dialog.contains(num))
            {
                interface_[ifname].log_dialog[num]->close();
            }
        }
    }

    delete ui;
}

void InterfaceToolbar::initializeControls(const iface_toolbar *toolbar)
{
    for (GList *walker = toolbar->controls; walker; walker = walker->next)
    {
        iface_toolbar_control *control = (iface_toolbar_control *)walker->data;

        if (control_widget_.contains(control->num))
        {
            // Already have a widget with this number
            continue;
        }

        QWidget *widget = NULL;
        switch (control->ctrl_type)
        {
            case INTERFACE_TYPE_BOOLEAN:
                widget = createCheckbox(control);
                break;

            case INTERFACE_TYPE_BUTTON:
                widget = createButton(control);
                break;

            case INTERFACE_TYPE_SELECTOR:
                widget = createSelector(control);
                break;

            case INTERFACE_TYPE_STRING:
                widget = createString(control);
                break;

            default:
                // Not supported
                break;
        }

        if (widget)
        {
            widget->setProperty(interface_type_property, control->ctrl_type);
            widget->setProperty(interface_role_property, control->ctrl_role);
            control_widget_[control->num] = widget;
        }
    }
}

void InterfaceToolbar::setDefaultValue(int num, const QByteArray &value)
{
    foreach (QString ifname, interface_.keys())
    {
        // Adding default value to all interfaces
        interface_[ifname].value[num] = value;
    }
    default_value_[num] = value;
}

QWidget *InterfaceToolbar::createCheckbox(iface_toolbar_control *control)
{
    QCheckBox *checkbox = new QCheckBox(QString().fromUtf8(control->display));
    checkbox->setToolTip(QString().fromUtf8(control->tooltip));

    if (control->default_value.boolean)
    {
        checkbox->setCheckState(Qt::Checked);
        QByteArray default_value(1, 1);
        setDefaultValue(control->num, default_value);
    }

    connect(checkbox, SIGNAL(stateChanged(int)), this, SLOT(onCheckBoxChanged(int)));

    ui->leftLayout->addWidget(checkbox);

    return checkbox;
}

QWidget *InterfaceToolbar::createButton(iface_toolbar_control *control)
{
    QPushButton *button = new QPushButton(QString().fromUtf8((gchar *)control->display));
    button->setMaximumHeight(27);
    button->setToolTip(QString().fromUtf8(control->tooltip));

    switch (control->ctrl_role)
    {
        case INTERFACE_ROLE_CONTROL:
            setDefaultValue(control->num, (gchar *)control->display);
            connect(button, SIGNAL(clicked()), this, SLOT(onControlButtonClicked()));
            break;

        case INTERFACE_ROLE_HELP:
            connect(button, SIGNAL(clicked()), this, SLOT(onHelpButtonClicked()));
            if (help_link_.isEmpty())
            {
                // No help URL provided
                button->hide();
            }
            break;

        case INTERFACE_ROLE_LOGGER:
            connect(button, SIGNAL(clicked()), this, SLOT(onLogButtonClicked()));
            break;

        case INTERFACE_ROLE_RESTORE:
            connect(button, SIGNAL(clicked()), this, SLOT(onRestoreButtonClicked()));
            break;

        default:
            // Not supported
            break;
    }

    ui->rightLayout->addWidget(button);

    return button;
}

QWidget *InterfaceToolbar::createSelector(iface_toolbar_control *control)
{
    QLabel *label = new QLabel(QString().fromUtf8(control->display));
    label->setToolTip(QString().fromUtf8(control->tooltip));
    QComboBox *combobox = new QComboBox();
    combobox->setToolTip(QString().fromUtf8(control->tooltip));
    combobox->setSizeAdjustPolicy(QComboBox::AdjustToContents);

    for (GList *walker = control->values; walker; walker = walker->next)
    {
        iface_toolbar_value *val = (iface_toolbar_value *)walker->data;
        QString value = QString().fromUtf8((gchar *)val->value);
        if (value.isEmpty())
        {
            // Invalid value
            continue;
        }
        QString display = QString().fromUtf8((gchar *)val->display);
        QByteArray interface_value;

        interface_value.append(value.toUtf8());
        if (display.isEmpty())
        {
            display = value;
        }
        else
        {
            interface_value.append(QString('\0' + display).toUtf8());
        }
        combobox->addItem(display, value);
        if (val->is_default)
        {
            combobox->setCurrentText(display);
            setDefaultValue(control->num, value.toUtf8());
        }
        foreach (QString ifname, interface_.keys())
        {
            // Adding values to all interfaces
            interface_[ifname].list[control->num].append(interface_value);
        }
        default_list_[control->num].append(interface_value);
    }

    connect(combobox, SIGNAL(currentIndexChanged(int)), this, SLOT(onComboBoxChanged(int)));

    ui->leftLayout->addWidget(label);
    ui->leftLayout->addWidget(combobox);
    label_widget_[control->num] = label;

    return combobox;
}

QWidget *InterfaceToolbar::createString(iface_toolbar_control *control)
{
    QLabel *label = new QLabel(QString().fromUtf8(control->display));
    label->setToolTip(QString().fromUtf8(control->tooltip));
    InterfaceToolbarLineEdit *lineedit = new InterfaceToolbarLineEdit(NULL, control->validation, control->is_required);
    lineedit->setToolTip(QString().fromUtf8(control->tooltip));
    lineedit->setPlaceholderText(QString().fromUtf8(control->placeholder));

    if (control->default_value.string)
    {
        lineedit->setText(QString().fromUtf8(control->default_value.string));
        setDefaultValue(control->num, control->default_value.string);
    }

    connect(lineedit, SIGNAL(editedTextApplied()), this, SLOT(onLineEditChanged()));

    ui->leftLayout->addWidget(label);
    ui->leftLayout->addWidget(lineedit);
    label_widget_[control->num] = label;
    use_spacer_ = false;

    return lineedit;
}

void InterfaceToolbar::setWidgetValue(QWidget *widget, int command, QByteArray payload)
{
    if (QComboBox *combobox = qobject_cast<QComboBox *>(widget))
    {
        combobox->blockSignals(true);
        switch (command)
        {
            case commandControlSet:
            {
                int idx = combobox->findData(payload);
                if (idx != -1)
                {
                    combobox->setCurrentIndex(idx);
                }
                break;
            }

            case commandControlAdd:
            {
                QString value;
                QString display;
                if (payload.contains('\0'))
                {
                    // The payload contains "value\0display"
                    QList<QByteArray> values = payload.split('\0');
                    value = values[0];
                    display = values[1];
                }
                else
                {
                    value = display = payload;
                }

                int idx = combobox->findData(value);
                if (idx != -1)
                {
                    // The value already exists, update item text
                    combobox->setItemText(idx, display);
                }
                else
                {
                    combobox->addItem(display, value);
                }
                break;
            }

            case commandControlRemove:
            {
                if (payload.size() == 0)
                {
                    combobox->clear();
                }
                else
                {
                    int idx = combobox->findData(payload);
                    if (idx != -1)
                    {
                        combobox->removeItem(idx);
                    }
                }
                break;
            }

            default:
                break;
        }
        combobox->blockSignals(false);
    }
    else if (InterfaceToolbarLineEdit *lineedit = qobject_cast<InterfaceToolbarLineEdit *>(widget))
    {
        // We don't block signals here because changes are applied with enter or apply button,
        // and we want InterfaceToolbarLineEdit to always syntax check the text.
        switch (command)
        {
            case commandControlSet:
                lineedit->setText(payload);
                lineedit->disableApplyButton();
                break;

            default:
                break;
        }
    }
    else if (QCheckBox *checkbox = qobject_cast<QCheckBox *>(widget))
    {
        checkbox->blockSignals(true);
        switch (command)
        {
            case commandControlSet:
            {
                Qt::CheckState state = Qt::Unchecked;
                if (payload.size() > 0 && payload.at(0) != 0)
                {
                    state = Qt::Checked;
                }
                checkbox->setCheckState(state);
                break;
            }

            default:
                break;
        }
        checkbox->blockSignals(false);
    }
    else if (QPushButton *button = qobject_cast<QPushButton *>(widget))
    {
        if ((command == commandControlSet) &&
            widget->property(interface_role_property).toInt() == INTERFACE_ROLE_CONTROL)
        {
            button->setText(payload);
        }
    }
}

void InterfaceToolbar::setInterfaceValue(QString ifname, QWidget *widget, int num, int command, QByteArray payload)
{
    if (!widget) {
        return;
    }

    if (qobject_cast<QComboBox *>(widget))
    {
        switch (command)
        {
            case commandControlSet:
                if (interface_[ifname].value[num] != payload)
                {
                    interface_[ifname].value_changed[num] = false;
                }
                foreach (QByteArray entry, interface_[ifname].list[num])
                {
                    if (entry == payload || entry.startsWith(payload + '\0'))
                    {
                        interface_[ifname].value[num] = payload;
                    }
                }
                break;

            case commandControlAdd:
                interface_[ifname].list[num].append(payload);
                break;

            case commandControlRemove:
                if (payload.size() == 0)
                {
                    interface_[ifname].value[num].clear();
                    interface_[ifname].list[num].clear();
                }
                else
                {
                    foreach (QByteArray entry, interface_[ifname].list[num])
                    {
                        if (entry == payload || entry.startsWith(payload + '\0'))
                        {
                            interface_[ifname].list[num].removeAll(entry);
                        }
                    }
                }
                break;

            default:
                break;
        }
    }
    else if (qobject_cast<InterfaceToolbarLineEdit *>(widget))
    {
        switch (command)
        {
            case commandControlSet:
                if (interface_[ifname].value[num] != payload)
                {
                    interface_[ifname].value_changed[num] = false;
                }
                interface_[ifname].value[num] = payload;
                break;

            default:
                break;
        }
    }
    else if ((widget->property(interface_type_property).toInt() == INTERFACE_TYPE_BUTTON) &&
             (widget->property(interface_role_property).toInt() == INTERFACE_ROLE_LOGGER))
    {
        if (command == commandControlSet)
        {
            if (interface_[ifname].log_dialog.contains(num))
            {
                interface_[ifname].log_dialog[num]->clearText();
            }
            interface_[ifname].log_text.clear();
        }
        if (command == commandControlSet || command == commandControlAdd)
        {
            if (interface_[ifname].log_dialog.contains(num))
            {
                interface_[ifname].log_dialog[num]->appendText(payload);
            }
            interface_[ifname].log_text[num].append(payload);
        }
    }
    else if (widget->property(interface_role_property).toInt() == INTERFACE_ROLE_CONTROL)
    {
        // QCheckBox or QPushButton
        switch (command)
        {
            case commandControlSet:
                if (interface_[ifname].value[num] != payload)
                {
                    interface_[ifname].value_changed[num] = false;
                }
                interface_[ifname].value[num] = payload;
                break;

            default:
                break;
        }
    }
}

void InterfaceToolbar::controlReceived(QString ifname, int num, int command, QByteArray payload)
{
    switch (command)
    {
        case commandControlSet:
        case commandControlAdd:
        case commandControlRemove:
            if (control_widget_.contains(num))
            {
                QWidget *widget = control_widget_[num];
                setInterfaceValue(ifname, widget, num, command, payload);

                if (ifname.compare(ui->interfacesComboBox->currentText()) == 0)
                {
                    setWidgetValue(widget, command, payload);
                }
            }
            break;

        case commandControlEnable:
        case commandControlDisable:
            if (control_widget_.contains(num))
            {
                QWidget *widget = control_widget_[num];
                if (widget->property(interface_role_property).toInt() == INTERFACE_ROLE_CONTROL)
                {
                    bool enable = (command == commandControlEnable ? true : false);
                    interface_[ifname].widget_disabled[num] = !enable;

                    if (ifname.compare(ui->interfacesComboBox->currentText()) == 0)
                    {
                        widget->setEnabled(enable);
                        if (label_widget_.contains(num))
                        {
                            label_widget_[num]->setEnabled(enable);
                        }
                    }
                }
            }
            break;

        case commandStatusMessage:
            mainApp->pushStatus(MainApplication::TemporaryStatus, payload);
            break;

        case commandInformationMessage:
            simple_dialog_async(ESD_TYPE_INFO, ESD_BTN_OK, "%s", payload.data());
            break;

        case commandWarningMessage:
            simple_dialog_async(ESD_TYPE_WARN, ESD_BTN_OK, "%s", payload.data());
            break;

        case commandErrorMessage:
            simple_dialog_async(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", payload.data());
            break;

        default:
            // Unknown commands are silently ignored
            break;
    }
}

void InterfaceToolbar::controlSend(QString ifname, int num, int command, const QByteArray &payload = QByteArray())
{
    if (payload.length() > 65535)
    {
        // Not supported
        return;
    }

    if (ifname.isEmpty() || interface_[ifname].out_fd == -1)
    {
        // Does not have a control out channel
        return;
    }

    ssize_t payload_length = payload.length() + 2;
    unsigned char high_nibble = (payload_length >> 16) & 0xFF;
    unsigned char mid_nibble = (payload_length >> 8) & 0xFF;
    unsigned char low_nibble = (payload_length >> 0) & 0xFF;

    QByteArray ba;

    ba.append(SP_TOOLBAR_CTRL);
    ba.append(high_nibble);
    ba.append(mid_nibble);
    ba.append(low_nibble);
    ba.append(num);
    ba.append(command);
    ba.append(payload);

    if (ws_write(interface_[ifname].out_fd, ba.data(), ba.length()) != ba.length())
    {
        simple_dialog_async(ESD_TYPE_ERROR, ESD_BTN_OK,
                            "Unable to send control message:\n%s.",
                            g_strerror(errno));
    }
}

void InterfaceToolbar::onControlButtonClicked()
{
    const QString &ifname = ui->interfacesComboBox->currentText();
    QPushButton *button = static_cast<QPushButton *>(sender());
    int num = control_widget_.key(button);

    controlSend(ifname, num, commandControlSet);
}

void InterfaceToolbar::onCheckBoxChanged(int state)
{
    const QString &ifname = ui->interfacesComboBox->currentText();
    QCheckBox *checkbox = static_cast<QCheckBox *>(sender());
    int num = control_widget_.key(checkbox);

    QByteArray payload(1, state == Qt::Unchecked ? 0 : 1);
    controlSend(ifname, num, commandControlSet, payload);
    interface_[ifname].value[num] = payload;
    interface_[ifname].value_changed[num] = true;
}

void InterfaceToolbar::onComboBoxChanged(int idx)
{
    const QString &ifname = ui->interfacesComboBox->currentText();
    QComboBox *combobox = static_cast<QComboBox *>(sender());
    int num = control_widget_.key(combobox);
    QString value = combobox->itemData(idx).toString();

    QByteArray payload(value.toUtf8());
    controlSend(ifname, num, commandControlSet, payload);
    interface_[ifname].value[num] = payload;
    interface_[ifname].value_changed[num] = true;
}

void InterfaceToolbar::onLineEditChanged()
{
    const QString &ifname = ui->interfacesComboBox->currentText();
    InterfaceToolbarLineEdit *lineedit = static_cast<InterfaceToolbarLineEdit *>(sender());
    int num = control_widget_.key(lineedit);

    QByteArray payload(lineedit->text().toUtf8());
    controlSend(ifname, num, commandControlSet, payload);
    interface_[ifname].value[num] = payload;
    interface_[ifname].value_changed[num] = true;
}

void InterfaceToolbar::onLogButtonClicked()
{
    const QString &ifname = ui->interfacesComboBox->currentText();
    QPushButton *button = static_cast<QPushButton *>(sender());
    int num = control_widget_.key(button);

    if (!interface_[ifname].log_dialog.contains(num))
    {
        interface_[ifname].log_dialog[num] = new FunnelTextDialog(window(), ifname + " " + button->text());
        connect(interface_[ifname].log_dialog[num], SIGNAL(accepted()), this, SLOT(closeLog()));
        connect(interface_[ifname].log_dialog[num], SIGNAL(rejected()), this, SLOT(closeLog()));

        interface_[ifname].log_dialog[num]->setText(interface_[ifname].log_text[num]);
    }

    interface_[ifname].log_dialog[num]->show();
    interface_[ifname].log_dialog[num]->raise();
    interface_[ifname].log_dialog[num]->activateWindow();
}

void InterfaceToolbar::onHelpButtonClicked()
{
    QUrl help_url(help_link_);

    if (help_url.scheme().compare("file") != 0)
    {
        QDesktopServices::openUrl(help_url);
    }
}

void InterfaceToolbar::closeLog()
{
    FunnelTextDialog *log_dialog = static_cast<FunnelTextDialog *>(sender());

    foreach (QString ifname, interface_.keys())
    {
        foreach (int num, control_widget_.keys())
        {
            if (interface_[ifname].log_dialog.value(num) == log_dialog)
            {
                interface_[ifname].log_dialog.remove(num);
            }
        }
    }
}


void InterfaceToolbar::startReaderThread(QString ifname, void *control_in)
{
    QThread *thread = new QThread;
    InterfaceToolbarReader *reader = new InterfaceToolbarReader(ifname, control_in);
    reader->moveToThread(thread);

    connect(thread, SIGNAL(started()), reader, SLOT(loop()));
    connect(reader, SIGNAL(finished()), thread, SLOT(quit()));
    connect(reader, SIGNAL(finished()), reader, SLOT(deleteLater()));
    connect(thread, SIGNAL(finished()), reader, SLOT(deleteLater()));
    connect(reader, SIGNAL(received(QString, int, int, QByteArray)),
            this, SLOT(controlReceived(QString, int, int, QByteArray)));

    interface_[ifname].reader_thread = thread;

    thread->start();
}

void InterfaceToolbar::startCapture(GArray *ifaces)
{
    if (!ifaces || ifaces->len == 0)
        return;

    const QString &selected_ifname = ui->interfacesComboBox->currentText();
    QString first_capturing_ifname;
    bool selected_found = false;

    for (guint i = 0; i < ifaces->len; i++)
    {
        interface_options *interface_opts = &g_array_index(ifaces, interface_options, i);
        QString ifname(interface_opts->name);

        if (!interface_.contains(ifname))
            // This interface is not for us
            continue;

        if (first_capturing_ifname.isEmpty())
            first_capturing_ifname = ifname;

        if (ifname.compare(selected_ifname) == 0)
            selected_found = true;

        if (interface_[ifname].out_fd != -1)
            // Already have control channels for this interface
            continue;

        // Open control out channel
#ifdef _WIN32
        startReaderThread(ifname, interface_opts->extcap_control_in_h);
        // Duplicate control out handle and pass the duplicate handle to _open_osfhandle().
        // This allows the C run-time file descriptor (out_fd) and the extcap_control_out_h to be closed independently.
        // The duplicated handle will get closed at the same time the file descriptor is closed.
        // The control out pipe will close when both out_fd and extcap_control_out_h are closed.
        HANDLE duplicate_out_handle = INVALID_HANDLE_VALUE;
        if (!DuplicateHandle(GetCurrentProcess(), interface_opts->extcap_control_out_h,
                             GetCurrentProcess(), &duplicate_out_handle, 0, TRUE, DUPLICATE_SAME_ACCESS))
        {
            simple_dialog_async(ESD_TYPE_ERROR, ESD_BTN_OK,
                                "Failed to duplicate extcap control out handle: %s\n.",
                                win32strerror(GetLastError()));
        }
        else
        {
            interface_[ifname].out_fd = _open_osfhandle((intptr_t)duplicate_out_handle, O_APPEND | O_BINARY);
        }
#else
        startReaderThread(ifname, interface_opts->extcap_control_in);
        interface_[ifname].out_fd = ws_open(interface_opts->extcap_control_out, O_WRONLY | O_BINARY, 0);
#endif
        sendChangedValues(ifname);
        controlSend(ifname, 0, commandControlInitialized);
    }

    if (!selected_found && !first_capturing_ifname.isEmpty())
    {
        ui->interfacesComboBox->setCurrentText(first_capturing_ifname);
    }
    else
    {
        updateWidgets();
    }
}

void InterfaceToolbar::stopCapture()
{
    foreach (QString ifname, interface_.keys())
    {
        if (interface_[ifname].reader_thread)
        {
            if (!interface_[ifname].reader_thread->isFinished())
            {
                interface_[ifname].reader_thread->requestInterruption();
            }
            interface_[ifname].reader_thread = NULL;
        }

        if (interface_[ifname].out_fd != -1)
        {
            ws_close_if_possible (interface_[ifname].out_fd);

            interface_[ifname].out_fd = -1;
        }

        foreach (int num, control_widget_.keys())
        {
            // Reset disabled property for all widgets
            interface_[ifname].widget_disabled[num] = false;

            QWidget *widget = control_widget_[num];
            if ((widget->property(interface_type_property).toInt() == INTERFACE_TYPE_BUTTON) &&
                (widget->property(interface_role_property).toInt() == INTERFACE_ROLE_CONTROL))
            {
                // Reset default value for control buttons
                interface_[ifname].value[num] = default_value_[num];

                if (ifname.compare(ui->interfacesComboBox->currentText()) == 0)
                {
                    setWidgetValue(widget, commandControlSet, default_value_[num]);
                }
            }
        }
    }

    updateWidgets();
}

void InterfaceToolbar::sendChangedValues(QString ifname)
{
    // Send all values which has changed
    foreach (int num, control_widget_.keys())
    {
        QWidget *widget = control_widget_[num];
        if ((interface_[ifname].value_changed[num]) &&
            (widget->property(interface_type_property).toInt() != INTERFACE_TYPE_BUTTON) &&
            (widget->property(interface_role_property).toInt() == INTERFACE_ROLE_CONTROL))
        {
            controlSend(ifname, num, commandControlSet, interface_[ifname].value[num]);
        }
    }
}

void InterfaceToolbar::onRestoreButtonClicked()
{
    const QString &ifname = ui->interfacesComboBox->currentText();

    // Set default values to all widgets and interfaces
    foreach (int num, control_widget_.keys())
    {
        QWidget *widget = control_widget_[num];
        if (default_list_[num].size() > 0)
        {
            // This is a QComboBox.  Clear list and add new entries.
            setWidgetValue(widget, commandControlRemove, QByteArray());
            interface_[ifname].list[num].clear();

            foreach (QByteArray value, default_list_[num])
            {
                setWidgetValue(widget, commandControlAdd, value);
                interface_[ifname].list[num].append(value);
            }
        }

        switch (widget->property(interface_role_property).toInt())
        {
            case INTERFACE_ROLE_CONTROL:
                setWidgetValue(widget, commandControlSet, default_value_[num]);
                interface_[ifname].value[num] = default_value_[num];
                interface_[ifname].value_changed[num] = false;
                break;

            case INTERFACE_ROLE_LOGGER:
                if (interface_[ifname].log_dialog.contains(num))
                {
                    interface_[ifname].log_dialog[num]->clearText();
                }
                interface_[ifname].log_text[num].clear();
                break;

            default:
                break;
        }
    }
}

bool InterfaceToolbar::hasInterface(QString ifname)
{
    return interface_.contains(ifname);
}

void InterfaceToolbar::updateWidgets()
{
    const QString &ifname = ui->interfacesComboBox->currentText();
    bool is_capturing = (interface_[ifname].out_fd == -1 ? false : true);

    foreach (int num, control_widget_.keys())
    {
        QWidget *widget = control_widget_[num];
        bool widget_enabled = true;

        if (ifname.isEmpty() &&
            (widget->property(interface_role_property).toInt() != INTERFACE_ROLE_HELP))
        {
            // No interface selected, disable all but Help button
            widget_enabled = false;
        }
        else if (!is_capturing &&
                 (widget->property(interface_type_property).toInt() == INTERFACE_TYPE_BUTTON) &&
                 (widget->property(interface_role_property).toInt() == INTERFACE_ROLE_CONTROL))
        {
            widget_enabled = false;
        }
        else if (widget->property(interface_role_property).toInt() == INTERFACE_ROLE_CONTROL)
        {
            widget_enabled = !interface_[ifname].widget_disabled[num];
        }

        widget->setEnabled(widget_enabled);
        if (label_widget_.contains(num))
        {
            label_widget_[num]->setEnabled(widget_enabled);
        }
    }

    foreach (int num, control_widget_.keys())
    {
        QWidget *widget = control_widget_[num];
        if ((widget->property(interface_type_property).toInt() == INTERFACE_TYPE_BUTTON) &&
            (widget->property(interface_role_property).toInt() == INTERFACE_ROLE_RESTORE))
        {
            widget->setEnabled(!is_capturing);
        }
    }
}

void InterfaceToolbar::interfaceListChanged()
{
#ifdef HAVE_LIBPCAP
    const QString &selected_ifname = ui->interfacesComboBox->currentText();
    bool keep_selected = false;

    ui->interfacesComboBox->blockSignals(true);
    ui->interfacesComboBox->clear();

    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++)
    {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (device->hidden)
            continue;

        if (interface_.keys().contains(device->name))
        {
            ui->interfacesComboBox->addItem(device->name);
            if (selected_ifname.compare(device->name) == 0)
            {
                // Keep selected interface
                ui->interfacesComboBox->setCurrentText(device->name);
                keep_selected = true;
            }
        }
    }

    ui->interfacesComboBox->blockSignals(false);

    if (!keep_selected)
    {
        // Select the first interface
        on_interfacesComboBox_currentTextChanged(ui->interfacesComboBox->currentText());
    }

    updateWidgets();
#endif
}

void InterfaceToolbar::on_interfacesComboBox_currentTextChanged(const QString &ifname)
{
    foreach (int num, control_widget_.keys())
    {
        QWidget *widget = control_widget_[num];
        if (interface_[ifname].list[num].size() > 0)
        {
            // This is a QComboBox.  Clear list and add new entries.
            setWidgetValue(widget, commandControlRemove, QByteArray());

            foreach (QByteArray value, interface_[ifname].list[num])
            {
                setWidgetValue(widget, commandControlAdd, value);
            }
        }

        if (widget->property(interface_role_property).toInt() == INTERFACE_ROLE_CONTROL)
        {
            setWidgetValue(widget, commandControlSet, interface_[ifname].value[num]);
        }
    }

    updateWidgets();
}
