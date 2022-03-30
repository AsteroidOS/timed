/***************************************************************************
 **                                                                        **
 **   Copyright (C) 2009-2011 Nokia Corporation.                           **
 **                                                                        **
 **   Author: Ilya Dogolazky <ilya.dogolazky@nokia.com>                    **
 **   Author: Simo Piiroinen <simo.piiroinen@nokia.com>                    **
 **   Author: Victor Portnov <ext-victor.portnov@nokia.com>                **
 **                                                                        **
 **     This file is part of Timed                                         **
 **                                                                        **
 **     Timed is free software; you can redistribute it and/or modify      **
 **     it under the terms of the GNU Lesser General Public License        **
 **     version 2.1 as published by the Free Software Foundation.          **
 **                                                                        **
 **     Timed is distributed in the hope that it will be useful, but       **
 **     WITHOUT ANY WARRANTY;  without even the implied warranty  of       **
 **     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               **
 **     See the GNU Lesser General Public License  for more details.       **
 **                                                                        **
 **   You should have received a copy of the GNU  Lesser General Public    **
 **   License along with Timed. If not, see http://www.gnu.org/licenses/   **
 **                                                                        **
 ***************************************************************************/

#include "../voland/interface.h"
#include "../common/log.h"

#include "voland_ping.h"

void voland_ping_t::timeout()
{
    if(!needed) // could rarely happen
        return;
    counter ++;
    log_info("pinging voland activation service, try %d out of %d", counter, max_num);
    ping();
    if(counter<max_num)
        timer.start(period);
}

void voland_ping_t::voland_needed()
{
    log_debug();
    needed = true;
    if(!timer.isActive())
        timeout();
}

void voland_ping_t::voland_registered()
{
    log_debug();
    timer.stop();
    needed = false;
    counter = 0;
}

voland_ping_t::voland_ping_t(unsigned p, unsigned n, QObject *parent) :
    QObject(parent), max_num(n), counter(0)
{
    period = p;
    timer.setSingleShot(true);
    needed = false;
    QObject::connect(&timer, SIGNAL(timeout()), this, SLOT(timeout()));
}

void voland_ping_t::ping()
{
    log_debug();
    const char *serv = Maemo::Timed::Voland::/*activation_*/service();
    const char *path = Maemo::Timed::Voland::/*activation_*/objpath();
    const char *ifac = Maemo::Timed::Voland::/*activation_*/interface();
    const char *meth = "pid";
    QDBusMessage mess = QDBusMessage::createMethodCall(serv, path, ifac, meth);
    if(QDBusConnection::sessionBus().send(mess))
        log_info("the 'pid' request sent asyncronosly");
    else
        log_error("Can't send the 'pid' request: %s", QDBusConnection::sessionBus().lastError().message().toStdString().c_str());
}

