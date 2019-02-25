/********************************************************************************
** Form generated from reading UI file 'packet_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PACKET_DIALOG_H
#define UI_PACKET_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QVBoxLayout>
#include "widgets/elided_label.h"

QT_BEGIN_NAMESPACE

class Ui_PacketDialog
{
public:
    QVBoxLayout *verticalLayout;
    QSplitter *packetSplitter;
    ElidedLabel *hintLabel;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *PacketDialog)
    {
        if (PacketDialog->objectName().isEmpty())
            PacketDialog->setObjectName(QString::fromUtf8("PacketDialog"));
        PacketDialog->resize(641, 450);
        verticalLayout = new QVBoxLayout(PacketDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        packetSplitter = new QSplitter(PacketDialog);
        packetSplitter->setObjectName(QString::fromUtf8("packetSplitter"));
        packetSplitter->setFrameShape(QFrame::StyledPanel);
        packetSplitter->setFrameShadow(QFrame::Raised);
        packetSplitter->setOrientation(Qt::Vertical);

        verticalLayout->addWidget(packetSplitter);

        hintLabel = new ElidedLabel(PacketDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));

        verticalLayout->addWidget(hintLabel);

        buttonBox = new QDialogButtonBox(PacketDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help);

        verticalLayout->addWidget(buttonBox);

        verticalLayout->setStretch(0, 1);

        retranslateUi(PacketDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), PacketDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), PacketDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(PacketDialog);
    } // setupUi

    void retranslateUi(QDialog *PacketDialog)
    {
        PacketDialog->setWindowTitle(QApplication::translate("PacketDialog", "Dialog", nullptr));
        hintLabel->setText(QApplication::translate("PacketDialog", "<small><i></i></small>", nullptr));
    } // retranslateUi

};

namespace Ui {
    class PacketDialog: public Ui_PacketDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PACKET_DIALOG_H
