QT -= gui
QT += dbus

TEMPLATE = app

TARGET = timed-qt5

VERSION = $$(TIMED_VERSION)

INCLUDEPATH += ../h

QMAKE_LIBDIR_FLAGS += -L../lib -L../voland
LIBS += -ltimed-qt5 -ltimed-voland-qt5 -liodata-qt5

IODATA_TYPES = queue.type settings.type

HEADERS += \
    settings.h \
    dbus_adaptor.h \
    timed.h \
    state.h \
    cluster.h \
    machine.h \
    pinguin.h \
    unix-signal.h \
    credentials.h \
    kernel_notification.h \
    ntpcontroller.h

SOURCES += \
    cluster.cpp \
    machine.cpp \
    state.cpp \
    main.cpp \
    timed.cpp \
    timeutil.cpp \
    event.cpp \
    misc.cpp \
    settings.cpp \
    pinguin.cpp \
    unix-signal.cpp \
    credentials.cpp \
    kernel_notification.cpp \
    ntpcontroller.cpp \
    queue.type.cpp \
    settings.type.cpp

CONFIG += link_pkgconfig iodata-qt5
PKGCONFIG += libpcrecpp libsystemd

target.path = $$(DESTDIR)/usr/bin

dbusconf.path  = $$(DESTDIR)/etc/dbus-1/system.d
dbusconf.files = timed-qt5.conf

systemd.path = $$(DESTDIR)/usr/lib/systemd/user
systemd.files = timed-qt5.service

INSTALLS += target dbusconf systemd

