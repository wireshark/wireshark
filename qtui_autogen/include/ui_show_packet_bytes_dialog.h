/********************************************************************************
** Form generated from reading UI file 'show_packet_bytes_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SHOW_PACKET_BYTES_DIALOG_H
#define UI_SHOW_PACKET_BYTES_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QVBoxLayout>
#include "show_packet_bytes_dialog.h"
#include "widgets/find_line_edit.h"

QT_BEGIN_NAMESPACE

class Ui_ShowPacketBytesDialog
{
public:
    QVBoxLayout *verticalLayout;
    ShowPacketBytesTextEdit *tePacketBytes;
    QLabel *hintLabel;
    QHBoxLayout *horizontalLayout_1;
    QLabel *lDecodeAs;
    QComboBox *cbDecodeAs;
    QLabel *lShowAs;
    QComboBox *cbShowAs;
    QSpacerItem *horizontalSpacer;
    QLabel *lStart;
    QSpinBox *sbStart;
    QLabel *lEnd;
    QSpinBox *sbEnd;
    QHBoxLayout *horizontalLayout_2;
    QLabel *lFind;
    FindLineEdit *leFind;
    QPushButton *bFind;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *ShowPacketBytesDialog)
    {
        if (ShowPacketBytesDialog->objectName().isEmpty())
            ShowPacketBytesDialog->setObjectName(QString::fromUtf8("ShowPacketBytesDialog"));
        ShowPacketBytesDialog->resize(710, 620);
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(ShowPacketBytesDialog->sizePolicy().hasHeightForWidth());
        ShowPacketBytesDialog->setSizePolicy(sizePolicy);
        ShowPacketBytesDialog->setSizeGripEnabled(true);
        verticalLayout = new QVBoxLayout(ShowPacketBytesDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        tePacketBytes = new ShowPacketBytesTextEdit(ShowPacketBytesDialog);
        tePacketBytes->setObjectName(QString::fromUtf8("tePacketBytes"));
        tePacketBytes->setReadOnly(true);

        verticalLayout->addWidget(tePacketBytes);

        hintLabel = new QLabel(ShowPacketBytesDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));
        hintLabel->setWordWrap(true);
        hintLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);

        verticalLayout->addWidget(hintLabel);

        horizontalLayout_1 = new QHBoxLayout();
        horizontalLayout_1->setObjectName(QString::fromUtf8("horizontalLayout_1"));
        lDecodeAs = new QLabel(ShowPacketBytesDialog);
        lDecodeAs->setObjectName(QString::fromUtf8("lDecodeAs"));

        horizontalLayout_1->addWidget(lDecodeAs);

        cbDecodeAs = new QComboBox(ShowPacketBytesDialog);
        cbDecodeAs->setObjectName(QString::fromUtf8("cbDecodeAs"));

        horizontalLayout_1->addWidget(cbDecodeAs);

        lShowAs = new QLabel(ShowPacketBytesDialog);
        lShowAs->setObjectName(QString::fromUtf8("lShowAs"));

        horizontalLayout_1->addWidget(lShowAs);

        cbShowAs = new QComboBox(ShowPacketBytesDialog);
        cbShowAs->setObjectName(QString::fromUtf8("cbShowAs"));

        horizontalLayout_1->addWidget(cbShowAs);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_1->addItem(horizontalSpacer);

        lStart = new QLabel(ShowPacketBytesDialog);
        lStart->setObjectName(QString::fromUtf8("lStart"));

        horizontalLayout_1->addWidget(lStart);

        sbStart = new QSpinBox(ShowPacketBytesDialog);
        sbStart->setObjectName(QString::fromUtf8("sbStart"));

        horizontalLayout_1->addWidget(sbStart);

        lEnd = new QLabel(ShowPacketBytesDialog);
        lEnd->setObjectName(QString::fromUtf8("lEnd"));

        horizontalLayout_1->addWidget(lEnd);

        sbEnd = new QSpinBox(ShowPacketBytesDialog);
        sbEnd->setObjectName(QString::fromUtf8("sbEnd"));

        horizontalLayout_1->addWidget(sbEnd);

        horizontalLayout_1->setStretch(4, 1);

        verticalLayout->addLayout(horizontalLayout_1);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        lFind = new QLabel(ShowPacketBytesDialog);
        lFind->setObjectName(QString::fromUtf8("lFind"));

        horizontalLayout_2->addWidget(lFind);

        leFind = new FindLineEdit(ShowPacketBytesDialog);
        leFind->setObjectName(QString::fromUtf8("leFind"));

        horizontalLayout_2->addWidget(leFind);

        bFind = new QPushButton(ShowPacketBytesDialog);
        bFind->setObjectName(QString::fromUtf8("bFind"));

        horizontalLayout_2->addWidget(bFind);

        horizontalLayout_2->setStretch(1, 1);

        verticalLayout->addLayout(horizontalLayout_2);

        buttonBox = new QDialogButtonBox(ShowPacketBytesDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(ShowPacketBytesDialog);

        cbShowAs->setCurrentIndex(-1);


        QMetaObject::connectSlotsByName(ShowPacketBytesDialog);
    } // setupUi

    void retranslateUi(QDialog *ShowPacketBytesDialog)
    {
        ShowPacketBytesDialog->setWindowTitle(QApplication::translate("ShowPacketBytesDialog", "Show Packet Bytes", nullptr));
        hintLabel->setText(QApplication::translate("ShowPacketBytesDialog", "Hint.", nullptr));
        lDecodeAs->setText(QApplication::translate("ShowPacketBytesDialog", "Decode as", nullptr));
        lShowAs->setText(QApplication::translate("ShowPacketBytesDialog", "Show as", nullptr));
        lStart->setText(QApplication::translate("ShowPacketBytesDialog", "Start", nullptr));
        lEnd->setText(QApplication::translate("ShowPacketBytesDialog", "End", nullptr));
        lFind->setText(QApplication::translate("ShowPacketBytesDialog", "Find:", nullptr));
        bFind->setText(QApplication::translate("ShowPacketBytesDialog", "Find &Next", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ShowPacketBytesDialog: public Ui_ShowPacketBytesDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SHOW_PACKET_BYTES_DIALOG_H
