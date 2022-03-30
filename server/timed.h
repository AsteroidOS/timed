/***************************************************************************
 **                                                                        **
 **   Copyright (c) 2009 - 2011 Nokia Corporation.                         **
 **   Copyright (c) 2013 - 2020 Jolla Ltd.                                 **
 **   Copyright (c) 2019 - 2020 Open Mobile Platform LLC.                  **
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

#ifndef TIMED_H
#define TIMED_H

#include <QCoreApplication>
#include <QMetaMethod>
#include <QDBusConnectionInterface>
#include <QDBusServiceWatcher>

#include <iodata-qt5/validator>
#include <iodata-qt5/storage>

#include "wrappers.h"
#include "settings.h"
#include "machine.h"
#include "event.h"

class voland_ping_t;
class UnixSignal;
class kernel_notification_t;
class NtpController;

struct Timed : public QCoreApplication
{
    Q_OBJECT;
public:
    Timed(int ac, char **av);
    virtual ~Timed();
    int get_default_gmt_offset() { return default_gmt_offset; }

    bool is_nitz_supported() { return nitz_supported; }
    const string &default_timezone() { return tz_by_default; }
    const QString get_settings_path() { return shared_settings_path; }
    void init_first_boot_hwclock_time_adjustment_check();

    void stop_machine();
    void stop_stuff();
    void stop_dbus();

    machine_t *am;
    voland_ping_t *ping;
    source_settings *settings;

    void load_events();
    void check_voland_service();
    void start_voland_watcher();
    void stop_voland_watcher();
    cookie_t add_event(cookie_t remove, const Maemo::Timed::event_io_t &event, const QDBusMessage &message);
    void add_events(const Maemo::Timed::event_list_io_t &events, QList<QVariant> &res, const QDBusMessage &message);
    bool get_event(cookie_t c, Maemo::Timed::event_io_t &res);
    bool get_events(const QList<uint> &cookies, Maemo::Timed::event_list_io_t &res);
    bool dialog_response(cookie_t c, int value);
    bool cancel(cookie_t c) { return am->cancel_by_cookie(c); }
    void cancel_events(const QList<uint> &cookies, QList<uint> &failed) { am->cancel_events(cookies, failed);}
    bool dismiss(cookie_t c) { return am->dismiss_by_cookie(c); }
    void alarm_gate(bool value) { return am->alarm_gate(value); }
    int default_snooze(int value) { return settings->default_snooze(value); }
    bool get_alarm_present();
    Maemo::Timed::Event::Triggers get_alarm_triggers();
    void enable_ntp_time_adjustment(bool enable);

    QDBusConnectionInterface *ses_iface;

    map<int,unsigned> children;

    bool permissions_shared_events() const;
    bool permissions_private_events() const;
    bool permissions_shared_settings(bool write_access) const;
    bool permissions_private_settings(bool write_access) const;
    void save_settings();

    kernel_notification_t *notificator;
    void invoke_signal(const nanotime_t &);
    void invoke_signal() { nanotime_t zero=0; invoke_signal(zero); }
    void clear_invokation_flag() { signal_invoked = false; systime_back.set(0); }

    void update_oracle_context(bool set);
    void open_epoch();

private:
    bool format24_by_default;
    bool auto_time_by_default;
    bool guess_tz_by_default;

    bool nitz_supported;
    string tz_by_default;
    bool first_boot_date_adjusted;

    // init_* methods, to be called by constructor only
    void init_unix_signal_handler();
    void init_configuration();
    void init_customization();
    void init_read_settings();
    void init_create_event_machine();
    void init_dbus();
    void init_load_events();
    void init_dst_checker();
    void init_start_event_machine();
    void init_cellular_services();
    void init_ntp();
    void init_apply_tz_settings();
    void init_kernel_notification();

    QDBusServiceWatcher *voland_watcher;
    iodata::storage *private_event_storage;
    iodata::storage *private_settings_storage;
    iodata::storage *shared_settings_storage;
    iodata::storage *shared_event_storage;

    QTimer *short_save_threshold_timer;
    QTimer *long_save_threshold_timer;
    unsigned threshold_period_long;
    unsigned threshold_period_short;
    unsigned ping_period;
    unsigned ping_max_num;
    bool alarm_present;
    Maemo::Timed::Event::Triggers alarm_triggers;
    QString private_data_directory;
    QString private_events_path;
    QString private_settings_path;
    QString shared_settings_directory;
    QString shared_settings_path;
    QString shared_events_directory;
    QString shared_events_path;
    int default_gmt_offset;
    std::string current_mode;
    void load_rc();
    void load_settings();
    bool permissions_helper(const QString &label, const QString &directory, bool write_access) const;

    UnixSignal *signal_object;

    Q_INVOKABLE void save_event_queue();

    machine_t::pause_t *q_pause;
    Q_INVOKABLE void send_time_settings();
    bool signal_invoked;
    nanotime_t systime_back;
    QTimer *dst_timer;
    std::string sent_signature;
    NtpController *ntp_controller;

private Q_SLOTS:
    void queue_threshold_timeout();
    void unix_signal(int signo);
    void devicelock_state_changed(int state);
    void kernel_notification(const nanotime_t &jump_forwards);
    void restart_alarm_timer();
    void set_alarm_present(bool present);
    void set_alarm_trigger(const QMap<QString, QVariant> &triggers);

public Q_SLOTS:
    void system_owner_changed(const QString &name, const QString &oldowner, const QString &newowner);
    void register_child(unsigned cookie, int pid) { children[pid] = cookie; }

    void event_queue_changed();

    void check_dst();

Q_SIGNALS:
    void voland_registered();
    void voland_unregistered();
    void settings_changed(const Maemo::Timed::WallClock::Info &, bool system_time);
    void alarm_present_changed(bool present);
    void alarm_triggers_changed(Maemo::Timed::Event::Triggers);
};

#endif
