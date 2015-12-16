/*
 * VPN Service Module
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __VPNSERVICE_VPNDBUS_H__
#define __VPNSERVICE_VPNDBUS_H__

#include <glib.h>
#include <gio/gio.h>
#include <glib-object.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VPNSERVICE_SERVICE		"org.tizen.vpnsvc"
#define VPNSERVICE_INTERFACE		"org.tizen.vpnsvc"
#define VPNSERVICE_PATH			"/org/tizen/vpnsvc"

typedef void (*vpnsvc_got_name_cb)(void);

GDBusObjectManagerServer *vpnsvc_get_vpn_manager(void);
GDBusConnection *vpnsvc_gdbus_get_connection(void);
GCancellable *vpnsvc_gdbus_get_gdbus_cancellable(void);
void vpnsvc_gdbus_pending_call_ref(void);
void vpnsvc_gdbus_pending_call_unref(void);
int vpnsvc_create_gdbus_call(GDBusConnection *conn);

gboolean vpnsvc_invoke_dbus_method_nonblock(const char *dest, const char *path,
		const char *interface_name, const char *method, GVariant *params,
		GAsyncReadyCallback notify_func);
GVariant *vpnsvc_invoke_dbus_method(const char *dest, const char *path,
		const char *interface_name, const char *method,
		GVariant *params);

int vpnsvc_setup_gdbus(vpnsvc_got_name_cb cb);
void vpnsvc_cleanup_gdbus(void);

#ifdef __cplusplus
}
#endif

#endif /* __VPNSERVICE_VPNDBUS_H__ */
