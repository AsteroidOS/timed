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

#ifndef VOLAND_PING_H
#define VOLAND_PING_H

#include <QObject>
#include <QTimer>

class voland_ping_t : public QObject
{
    Q_OBJECT;
public:
    voland_ping_t(unsigned p, unsigned n, QObject *parent);
    void ping();
private:
    unsigned max_num;
    unsigned counter;
    bool needed;
    QTimer timer;
    unsigned period;
private Q_SLOTS:
    void timeout();
    void voland_needed();
    void voland_registered();
};

#endif
