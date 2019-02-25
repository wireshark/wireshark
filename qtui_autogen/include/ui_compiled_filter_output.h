/********************************************************************************
** Form generated from reading UI file 'compiled_filter_output.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_COMPILED_FILTER_OUTPUT_H
#define UI_COMPILED_FILTER_OUTPUT_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_CompiledFilterOutput
{
public:
    QVBoxLayout *verticalLayout;
    QHBoxLayout *horizontalLayout;
    QListWidget *interfaceList;
    QTextBrowser *filterList;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *CompiledFilterOutput)
    {
        if (CompiledFilterOutput->objectName().isEmpty())
            CompiledFilterOutput->setObjectName(QString::fromUtf8("CompiledFilterOutput"));
        CompiledFilterOutput->resize(654, 380);
        verticalLayout = new QVBoxLayout(CompiledFilterOutput);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        interfaceList = new QListWidget(CompiledFilterOutput);
        interfaceList->setObjectName(QString::fromUtf8("interfaceList"));
        interfaceList->setEditTriggers(QAbstractItemView::NoEditTriggers);

        horizontalLayout->addWidget(interfaceList);

        filterList = new QTextBrowser(CompiledFilterOutput);
        filterList->setObjectName(QString::fromUtf8("filterList"));

        horizontalLayout->addWidget(filterList);

        horizontalLayout->setStretch(0, 2);
        horizontalLayout->setStretch(1, 5);

        verticalLayout->addLayout(horizontalLayout);

        buttonBox = new QDialogButtonBox(CompiledFilterOutput);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close);
        buttonBox->setCenterButtons(false);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(CompiledFilterOutput);
        QObject::connect(buttonBox, SIGNAL(accepted()), CompiledFilterOutput, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), CompiledFilterOutput, SLOT(reject()));

        QMetaObject::connectSlotsByName(CompiledFilterOutput);
    } // setupUi

    void retranslateUi(QDialog *CompiledFilterOutput)
    {
        CompiledFilterOutput->setWindowTitle(QApplication::translate("CompiledFilterOutput", "Compiled Filter Output", nullptr));
    } // retranslateUi

};

namespace Ui {
    class CompiledFilterOutput: public Ui_CompiledFilterOutput {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_COMPILED_FILTER_OUTPUT_H
