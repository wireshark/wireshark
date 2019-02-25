/********************************************************************************
** Form generated from reading UI file 'supported_protocols_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SUPPORTED_PROTOCOLS_DIALOG_H
#define UI_SUPPORTED_PROTOCOLS_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_SupportedProtocolsDialog
{
public:
    QVBoxLayout *verticalLayout;
    QTreeView *supportedProtocolsTreeView;
    QHBoxLayout *horizontalLayout;
    QLabel *searchLabel;
    QLineEdit *searchLineEdit;
    QSpacerItem *horizontalSpacer;
    QLabel *hintLabel;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *SupportedProtocolsDialog)
    {
        if (SupportedProtocolsDialog->objectName().isEmpty())
            SupportedProtocolsDialog->setObjectName(QString::fromUtf8("SupportedProtocolsDialog"));
        SupportedProtocolsDialog->resize(640, 540);
        verticalLayout = new QVBoxLayout(SupportedProtocolsDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        supportedProtocolsTreeView = new QTreeView(SupportedProtocolsDialog);
        supportedProtocolsTreeView->setObjectName(QString::fromUtf8("supportedProtocolsTreeView"));

        verticalLayout->addWidget(supportedProtocolsTreeView);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        searchLabel = new QLabel(SupportedProtocolsDialog);
        searchLabel->setObjectName(QString::fromUtf8("searchLabel"));

        horizontalLayout->addWidget(searchLabel);

        searchLineEdit = new QLineEdit(SupportedProtocolsDialog);
        searchLineEdit->setObjectName(QString::fromUtf8("searchLineEdit"));

        horizontalLayout->addWidget(searchLineEdit);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);


        verticalLayout->addLayout(horizontalLayout);

        hintLabel = new QLabel(SupportedProtocolsDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));
        hintLabel->setWordWrap(true);

        verticalLayout->addWidget(hintLabel);

        buttonBox = new QDialogButtonBox(SupportedProtocolsDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(SupportedProtocolsDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), SupportedProtocolsDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), SupportedProtocolsDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(SupportedProtocolsDialog);
    } // setupUi

    void retranslateUi(QDialog *SupportedProtocolsDialog)
    {
        SupportedProtocolsDialog->setWindowTitle(QApplication::translate("SupportedProtocolsDialog", "Dialog", nullptr));
#ifndef QT_NO_TOOLTIP
        searchLabel->setToolTip(QApplication::translate("SupportedProtocolsDialog", "<html><head/><body><p>Search the list of field names.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        searchLabel->setText(QApplication::translate("SupportedProtocolsDialog", "Search:", nullptr));
        hintLabel->setText(QApplication::translate("SupportedProtocolsDialog", "<small><i>Gathering protocol information\342\200\246</i></small>", nullptr));
    } // retranslateUi

};

namespace Ui {
    class SupportedProtocolsDialog: public Ui_SupportedProtocolsDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SUPPORTED_PROTOCOLS_DIALOG_H
