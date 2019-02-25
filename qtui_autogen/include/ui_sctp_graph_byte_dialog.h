/********************************************************************************
** Form generated from reading UI file 'sctp_graph_byte_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SCTP_GRAPH_BYTE_DIALOG_H
#define UI_SCTP_GRAPH_BYTE_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>
#include "widgets/qcustomplot.h"

QT_BEGIN_NAMESPACE

class Ui_SCTPGraphByteDialog
{
public:
    QAction *actionGoToPacket;
    QVBoxLayout *verticalLayout_2;
    QVBoxLayout *verticalLayout;
    QCustomPlot *sctpPlot;
    QLabel *hintLabel;
    QHBoxLayout *horizontalLayout;
    QPushButton *pushButton_4;
    QPushButton *saveButton;
    QSpacerItem *horizontalSpacer;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *SCTPGraphByteDialog)
    {
        if (SCTPGraphByteDialog->objectName().isEmpty())
            SCTPGraphByteDialog->setObjectName(QString::fromUtf8("SCTPGraphByteDialog"));
        SCTPGraphByteDialog->resize(800, 546);
        actionGoToPacket = new QAction(SCTPGraphByteDialog);
        actionGoToPacket->setObjectName(QString::fromUtf8("actionGoToPacket"));
        verticalLayout_2 = new QVBoxLayout(SCTPGraphByteDialog);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        verticalLayout = new QVBoxLayout();
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        sctpPlot = new QCustomPlot(SCTPGraphByteDialog);
        sctpPlot->setObjectName(QString::fromUtf8("sctpPlot"));
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(1);
        sizePolicy.setHeightForWidth(sctpPlot->sizePolicy().hasHeightForWidth());
        sctpPlot->setSizePolicy(sizePolicy);

        verticalLayout->addWidget(sctpPlot);

        hintLabel = new QLabel(SCTPGraphByteDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));
        hintLabel->setWordWrap(true);

        verticalLayout->addWidget(hintLabel);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        pushButton_4 = new QPushButton(SCTPGraphByteDialog);
        pushButton_4->setObjectName(QString::fromUtf8("pushButton_4"));
        pushButton_4->setFocusPolicy(Qt::NoFocus);

        horizontalLayout->addWidget(pushButton_4);

        saveButton = new QPushButton(SCTPGraphByteDialog);
        saveButton->setObjectName(QString::fromUtf8("saveButton"));

        horizontalLayout->addWidget(saveButton);

        horizontalSpacer = new QSpacerItem(428, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        buttonBox = new QDialogButtonBox(SCTPGraphByteDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setFocusPolicy(Qt::NoFocus);
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close);

        horizontalLayout->addWidget(buttonBox);


        verticalLayout->addLayout(horizontalLayout);


        verticalLayout_2->addLayout(verticalLayout);


        retranslateUi(SCTPGraphByteDialog);
        QObject::connect(buttonBox, SIGNAL(clicked(QAbstractButton*)), SCTPGraphByteDialog, SLOT(close()));

        QMetaObject::connectSlotsByName(SCTPGraphByteDialog);
    } // setupUi

    void retranslateUi(QDialog *SCTPGraphByteDialog)
    {
        SCTPGraphByteDialog->setWindowTitle(QApplication::translate("SCTPGraphByteDialog", "SCTP Graph", nullptr));
        actionGoToPacket->setText(QApplication::translate("SCTPGraphByteDialog", "goToPacket", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoToPacket->setToolTip(QApplication::translate("SCTPGraphByteDialog", "Go to Packet", nullptr));
#endif // QT_NO_TOOLTIP
        hintLabel->setText(QApplication::translate("SCTPGraphByteDialog", "<html><head/><body><p><br/></p></body></html>", nullptr));
        pushButton_4->setText(QApplication::translate("SCTPGraphByteDialog", "Reset to full size", nullptr));
        saveButton->setText(QApplication::translate("SCTPGraphByteDialog", "Save Graph", nullptr));
    } // retranslateUi

};

namespace Ui {
    class SCTPGraphByteDialog: public Ui_SCTPGraphByteDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SCTP_GRAPH_BYTE_DIALOG_H
