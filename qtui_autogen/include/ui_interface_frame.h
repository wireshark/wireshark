/********************************************************************************
** Form generated from reading UI file 'interface_frame.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_INTERFACE_FRAME_H
#define UI_INTERFACE_FRAME_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QFrame>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_InterfaceFrame
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *lblNoInterfaces;
    QTreeView *interfaceTree;

    void setupUi(QFrame *InterfaceFrame)
    {
        if (InterfaceFrame->objectName().isEmpty())
            InterfaceFrame->setObjectName(QString::fromUtf8("InterfaceFrame"));
        InterfaceFrame->resize(676, 350);
        QSizePolicy sizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::MinimumExpanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(InterfaceFrame->sizePolicy().hasHeightForWidth());
        InterfaceFrame->setSizePolicy(sizePolicy);
        InterfaceFrame->setLineWidth(0);
        verticalLayout = new QVBoxLayout(InterfaceFrame);
        verticalLayout->setSpacing(1);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        verticalLayout->setContentsMargins(0, 0, 0, 0);
        lblNoInterfaces = new QLabel(InterfaceFrame);
        lblNoInterfaces->setObjectName(QString::fromUtf8("lblNoInterfaces"));
        QSizePolicy sizePolicy1(QSizePolicy::Preferred, QSizePolicy::MinimumExpanding);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(lblNoInterfaces->sizePolicy().hasHeightForWidth());
        lblNoInterfaces->setSizePolicy(sizePolicy1);
        lblNoInterfaces->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignTop);

        verticalLayout->addWidget(lblNoInterfaces);

        interfaceTree = new QTreeView(InterfaceFrame);
        interfaceTree->setObjectName(QString::fromUtf8("interfaceTree"));
        interfaceTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
        interfaceTree->setRootIsDecorated(false);
        interfaceTree->setHeaderHidden(true);

        verticalLayout->addWidget(interfaceTree);


        retranslateUi(InterfaceFrame);

        QMetaObject::connectSlotsByName(InterfaceFrame);
    } // setupUi

    void retranslateUi(QFrame *InterfaceFrame)
    {
        InterfaceFrame->setWindowTitle(QApplication::translate("InterfaceFrame", "Frame", nullptr));
        lblNoInterfaces->setText(QApplication::translate("InterfaceFrame", "No interfaces found", nullptr));
    } // retranslateUi

};

namespace Ui {
    class InterfaceFrame: public Ui_InterfaceFrame {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_INTERFACE_FRAME_H
