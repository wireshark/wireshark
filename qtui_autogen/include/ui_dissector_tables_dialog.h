/********************************************************************************
** Form generated from reading UI file 'dissector_tables_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_DISSECTOR_TABLES_DIALOG_H
#define UI_DISSECTOR_TABLES_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QVBoxLayout>
#include "widgets/dissector_tables_view.h"

QT_BEGIN_NAMESPACE

class Ui_DissectorTablesDialog
{
public:
    QVBoxLayout *verticalLayout;
    DissectorTablesTreeView *tableTree;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QLineEdit *txtSearchLine;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *DissectorTablesDialog)
    {
        if (DissectorTablesDialog->objectName().isEmpty())
            DissectorTablesDialog->setObjectName(QString::fromUtf8("DissectorTablesDialog"));
        DissectorTablesDialog->resize(400, 300);
        verticalLayout = new QVBoxLayout(DissectorTablesDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        tableTree = new DissectorTablesTreeView(DissectorTablesDialog);
        tableTree->setObjectName(QString::fromUtf8("tableTree"));
        tableTree->setUniformRowHeights(true);

        verticalLayout->addWidget(tableTree);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(DissectorTablesDialog);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        txtSearchLine = new QLineEdit(DissectorTablesDialog);
        txtSearchLine->setObjectName(QString::fromUtf8("txtSearchLine"));

        horizontalLayout->addWidget(txtSearchLine);


        verticalLayout->addLayout(horizontalLayout);

        buttonBox = new QDialogButtonBox(DissectorTablesDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(DissectorTablesDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), DissectorTablesDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), DissectorTablesDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(DissectorTablesDialog);
    } // setupUi

    void retranslateUi(QDialog *DissectorTablesDialog)
    {
        DissectorTablesDialog->setWindowTitle(QApplication::translate("DissectorTablesDialog", "Dialog", nullptr));
        label->setText(QApplication::translate("DissectorTablesDialog", "Search:", nullptr));
    } // retranslateUi

};

namespace Ui {
    class DissectorTablesDialog: public Ui_DissectorTablesDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_DISSECTOR_TABLES_DIALOG_H
