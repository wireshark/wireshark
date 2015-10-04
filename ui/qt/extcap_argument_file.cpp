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

#include <extcap_parser.h>


ExtcapArgumentFileSelection::ExtcapArgumentFileSelection (extcap_arg * argument) :
    ExtcapArgument(argument), textBox(0)
{
    _default = new QVariant(QString(""));
}

QWidget * ExtcapArgumentFileSelection::createEditor(QWidget * parent)
{
    QWidget * fileWidget = new QWidget(parent);
    QHBoxLayout * editLayout = new QHBoxLayout();
    QMargins margins = editLayout->contentsMargins();
    editLayout->setContentsMargins(0, 0, 0, margins.bottom());
    fileWidget->setContentsMargins(margins.left(), margins.right(), 0, margins.bottom());
    QPushButton * button = new QPushButton(UTF8_HORIZONTAL_ELLIPSIS, fileWidget);

    textBox = new QLineEdit(_default->toString(), parent);
    textBox->setReadOnly(true);

    if ( _argument->default_complex != NULL && _argument->arg_type == EXTCAP_ARG_STRING )
        textBox->setText(QString().fromUtf8(extcap_complex_get_string(_argument->default_complex)));

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

    filename = QFileDialog::getOpenFileName((QWidget *)(textBox->parent()),
        QString().fromUtf8(_argument->display) + " " + tr("Open File"),
        workingDir.absolutePath(), tr("All Files (*.*)"));

    if ( QFileInfo(filename).exists() )
        textBox->setText(filename);
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
