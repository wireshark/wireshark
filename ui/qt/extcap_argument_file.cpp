/* extcap_argument_file.cpp
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

#include <extcap_argument.h>
#include <extcap_argument_file.h>

#include <wsutil/utf8_entities.h>

#include <QObject>
#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QBoxLayout>
#include <QPushButton>
#include <QFileDialog>
#include <QDir>
#include <QFileInfo>
#include <QVariant>

#include <epan/prefs.h>
#include <color_utils.h>

#include <ui/all_files_wildcard.h>

#include <extcap_parser.h>

ExtcapArgumentFileSelection::ExtcapArgumentFileSelection (extcap_arg * argument) :
    ExtcapArgument(argument), textBox(0)
{
}

ExtcapArgumentFileSelection::~ExtcapArgumentFileSelection()
{
    if ( textBox != NULL )
        delete textBox;
}

QWidget * ExtcapArgumentFileSelection::createEditor(QWidget * parent)
{
    QString text = defaultValue();
    QString buttonText(UTF8_HORIZONTAL_ELLIPSIS);

    QWidget * fileWidget = new QWidget(parent);
    QHBoxLayout * editLayout = new QHBoxLayout();
    QMargins margins = editLayout->contentsMargins();
    editLayout->setContentsMargins(0, 0, 0, margins.bottom());
    fileWidget->setContentsMargins(margins.left(), margins.right(), 0, margins.bottom());
    QPushButton * button = new QPushButton(buttonText, fileWidget);

    textBox = new QLineEdit(text, parent);
    textBox->setReadOnly(true);

    const char *prefval = _argument->pref_valptr ? *_argument->pref_valptr : NULL;
    if (prefval)
    {
        QString storeValue(prefval);

        if ( storeValue.length() > 0 && storeValue.compare(text) != 0 )
            text = storeValue.trimmed();
    }
    textBox->setText(text);

    if ( _argument->tooltip != NULL )
    {
        textBox->setToolTip(QString().fromUtf8(_argument->tooltip));
        button->setToolTip(QString().fromUtf8(_argument->tooltip));
    }

    connect(button, SIGNAL(clicked()), (QObject *)this, SLOT(openFileDialog()));

    editLayout->addWidget(textBox);
    editLayout->addWidget(button);

    fileWidget->setLayout(editLayout);

    return fileWidget;
}

QString ExtcapArgumentFileSelection::value()
{
    if ( textBox == 0 )
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
    if ( _argument->fileextension != NULL )
    {
        QString givenExt = QString().fromUtf8(_argument->fileextension);
        if ( givenExt.length() != 0 )
            fileExt.prepend(";;").prepend(givenExt);
    }

    filename = QFileDialog::getOpenFileName((QWidget *)(textBox->parent()),
        QString().fromUtf8(_argument->display) + " " + tr("Open File"),
        workingDir.absolutePath(), fileExt);

    if ( ! fileExists() || QFileInfo(filename).exists() )
    {
        textBox->setText(filename);
        emit valueChanged();
    }
}

bool ExtcapArgumentFileSelection::isValid()
{
    bool valid = false;

    if ( textBox->text().length() > 0 )
    {
        if ( QFileInfo(textBox->text()).exists() && _argument->fileexists )
            valid = true;
    }
    else if ( ! isRequired() )
        valid = true;

    QString lblInvalidColor = ColorUtils::fromColorT(prefs.gui_text_invalid).name();
    QString txtStyle("QLineEdit { background-color: %1; } ");
    textBox->setStyleSheet( txtStyle.arg(valid ? QString("") : lblInvalidColor) );

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
