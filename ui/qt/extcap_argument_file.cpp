/* extcap_argument_file.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <extcap_argument.h>
#include <extcap_argument_file.h>

#include <wsutil/utf8_entities.h>

#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QObject>
#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QBoxLayout>
#include <QPushButton>
#include <QDir>
#include <QFileInfo>
#include <QVariant>

#include <epan/prefs.h>
#include <ui/qt/utils/color_utils.h>

#include <ui/all_files_wildcard.h>

#include <extcap_parser.h>

ExtcapArgumentFileSelection::ExtcapArgumentFileSelection (extcap_arg * argument, QObject *parent) :
    ExtcapArgument(argument, parent), textBox(0)
{
}

ExtcapArgumentFileSelection::~ExtcapArgumentFileSelection()
{
    if (textBox != NULL)
        delete textBox;
}

QWidget * ExtcapArgumentFileSelection::createEditor(QWidget * parent)
{
    QString text = defaultValue();
    QString buttonText(UTF8_HORIZONTAL_ELLIPSIS);
    QString buttonClearText(tr("Clear"));

    QWidget * fileWidget = new QWidget(parent);
    QHBoxLayout * editLayout = new QHBoxLayout();
    QMargins margins = editLayout->contentsMargins();
    editLayout->setContentsMargins(0, 0, 0, margins.bottom());
    fileWidget->setContentsMargins(margins.left(), margins.right(), 0, margins.bottom());
    QPushButton * buttonSelect = new QPushButton(buttonText, fileWidget);
    QPushButton * buttonClear = new QPushButton(buttonClearText, fileWidget);

    textBox = new QLineEdit(text, parent);
    textBox->setReadOnly(true);

    const char *prefval = _argument->pref_valptr ? *_argument->pref_valptr : NULL;
    if (prefval)
    {
        QString storeValue(prefval);

        if (storeValue.length() > 0 && storeValue.compare(text) != 0)
            text = storeValue.trimmed();
    }
    textBox->setText(text);

    if (_argument->tooltip != NULL)
    {
        textBox->setToolTip(QString().fromUtf8(_argument->tooltip));
        buttonSelect->setToolTip(QString().fromUtf8(_argument->tooltip));
    }

    connect(buttonSelect, SIGNAL(clicked()), (QObject *)this, SLOT(openFileDialog()));
    connect(buttonClear, SIGNAL(clicked()), (QObject *)this, SLOT(clearFilename()));

    editLayout->addWidget(textBox);
    editLayout->addWidget(buttonSelect);
    editLayout->addWidget(buttonClear);

    fileWidget->setLayout(editLayout);

    return fileWidget;
}

QString ExtcapArgumentFileSelection::value()
{
    if (textBox == 0)
        return QString();
    return textBox->text();
}

/* opens the file dialog */
void ExtcapArgumentFileSelection::openFileDialog()
{
    QString filename = textBox->text();

    QDir workingDir = QDir::currentPath();
    if (QFileInfo(filename).exists())
        workingDir = QFileInfo(filename).dir();

    QString fileExt(tr("All Files (" ALL_FILES_WILDCARD ")"));
    if (_argument->fileextension != NULL)
    {
        QString givenExt = QString().fromUtf8(_argument->fileextension);
        if (givenExt.length() != 0)
            fileExt.prepend(";;").prepend(givenExt);
    }

    if (fileExists())
    {
        /* UI should check that the file exists */
        filename = WiresharkFileDialog::getOpenFileName((QWidget*)(textBox->parent()),
            QString().fromUtf8(_argument->display) + " " + tr("Open File"),
            workingDir.absolutePath(), fileExt);
    }
    else
    {
        /* File might or might not exist. Actual overwrite handling is extcap specific
         * (e.g. boolflag argument if user wants to always overwrite the file)
         */
        filename = WiresharkFileDialog::getSaveFileName((QWidget*)(textBox->parent()),
            QString().fromUtf8(_argument->display) + " " + tr("Select File"),
            workingDir.absolutePath(), fileExt, nullptr, QFileDialog::Option::DontConfirmOverwrite);
    }

    if (! filename.isEmpty() && (! fileExists() || QFileInfo(filename).exists()))
    {
        textBox->setText(filename);
        emit valueChanged();
    }
}

void ExtcapArgumentFileSelection::clearFilename()
{
    textBox->clear();
    emit valueChanged();
}

bool ExtcapArgumentFileSelection::isValid()
{
    bool valid = false;

    if (textBox->text().length() > 0)
    {
        if (_argument->fileexists)
            valid = QFileInfo(textBox->text()).exists();
        else
            valid = true;
    }
    else if (! isRequired())
        valid = true;

    QString lblInvalidColor = ColorUtils::fromColorT(prefs.gui_text_invalid).name();
    QString txtStyle("QLineEdit { background-color: %1; } ");
    textBox->setStyleSheet(txtStyle.arg(valid ? QString("") : lblInvalidColor));

    return valid;
}

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
