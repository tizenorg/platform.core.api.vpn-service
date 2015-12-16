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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dlog/dlog.h>

#include "vpndbus.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "VPNSVC_DAEMON"

#define DBUS_REPLY_TIMEOUT (120 * 1000)

static GDBusObjectManagerServer *manager_server_vpn = NULL;
static guint owner_id = 0;
static vpnsvc_got_name_cb g_callback = NULL;

struct gdbus_conn_data {
	GDBusConnection *connection;
	int conn_ref_count;
	GCancellable *cancellable;
};

static struct gdbus_conn_data gconn_data = {NULL, 0, NULL};

GDBusObjectManagerServer *vpnsvc_get_vpn_manager(void)
{
	return manager_server_vpn;
}

GDBusConnection *vpnsvc_gdbus_get_connection(void)
{
	return gconn_data.connection;
}

GCancellable *vpnsvc_gdbus_get_gdbus_cancellable(void)
{
	return gconn_data.cancellable;
}

void vpnsvc_gdbus_pending_call_ref(void)
{
	g_object_ref(gconn_data.connection);

	__sync_fetch_and_add(&gconn_data.conn_ref_count, 1);
}

void vpnsvc_gdbus_pending_call_unref(void)
{
	if (gconn_data.conn_ref_count < 1)
		return;

	g_object_unref(gconn_data.connection);

	if (__sync_sub_and_fetch(&gconn_data.conn_ref_count, 1) < 1) {
		/* TODO: Check this
		 * gconn_data.connection = NULL;
		 */
	}
}

int vpnsvc_create_gdbus_call(GDBusConnection *conn)
{
	if (gconn_data.connection != NULL) {
		LOGE("Connection already set");
		return -1;
	}

	gconn_data.connection = conn;
	if (gconn_data.connection == NULL) {
		LOGE("Failed to connect to the D-BUS daemon");
		return -1;
	}

	gconn_data.cancellable = g_cancellable_new();

	return 0;
}


gboolean vpnsvc_invoke_dbus_method_nonblock(const char *dest, const char *path,
		const char *interface_name, const char *method, GVariant *params,
		GAsyncReadyCallback notify_func)
{
	GDBusConnection *connection = NULL;

	LOGD("[GDBUS Async] %s %s %s", interface_name, method, path);

	connection = vpnsvc_gdbus_get_connection();
	if (connection == NULL) {
		LOGE("Failed to get gdbus connection");
		return FALSE;
	}

	g_dbus_connection_call(connection,
			dest,
			path,
			interface_name,
			method,
			params,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			DBUS_REPLY_TIMEOUT,
			vpnsvc_gdbus_get_gdbus_cancellable(),
			(GAsyncReadyCallback) notify_func,
			NULL);

	if (notify_func != NULL)
		vpnsvc_gdbus_pending_call_ref();

	return TRUE;
}

GVariant *vpnsvc_invoke_dbus_method(const char *dest, const char *path,
		const char *interface_name, const char *method, GVariant *params)
{

	GError *error = NULL;
	GVariant *reply = NULL;
	GDBusConnection *connection;

	connection = vpnsvc_gdbus_get_connection();
	if (connection == NULL) {
		LOGE("Failed to get GDBusconnection");
		return reply;
	}

	reply = g_dbus_connection_call_sync(
			connection,
			dest,
			path,
			interface_name,
			method,
			params,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			DBUS_REPLY_TIMEOUT,
			vpnsvc_gdbus_get_gdbus_cancellable(),
			&error);

	if (reply == NULL) {
		if (error != NULL) {
			LOGE("g_dbus_connection_call_sync() failed"
						"error [%d: %s]", error->code, error->message);
			g_error_free(error);
		} else {
			LOGE("g_dbus_connection_call_sync() failed");
		}

		return NULL;
	}

	return reply;
}

static void __vpnsvc_got_bus_cb(GDBusConnection *conn, const gchar *name,
		gpointer user_data)
{
	LOGD("connection: [%p] name: [%s] user_data: [%p]", conn, name, user_data);

	vpnsvc_create_gdbus_call(conn);
}

static void __vpnsvc_got_name_cb(GDBusConnection *conn, const gchar *name,
		gpointer user_data)
{
	LOGD("connection: [%p] name: [%s] user_data: [%p]", conn, name, user_data);

	if (g_callback != NULL)
		g_callback();
}

static void __vpnsvc_lost_name_cb(GDBusConnection *conn, const gchar *name,
		gpointer user_data)
{
	LOGD("connection: [%p] name: [%s] user_data: [%p]", conn, name, user_data);
	/* May service name is already in use */
	LOGE("Service name is already in use");

	/* The result of DBus name request is only permitted,
	 *  such as DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER.
	 */
	exit(2);
}

int vpnsvc_setup_gdbus(vpnsvc_got_name_cb cb)
{
	LOGD("VPN Service Setup!");

	g_callback = cb;

	manager_server_vpn = g_dbus_object_manager_server_new(
				VPNSERVICE_PATH);
	if (manager_server_vpn == NULL) {
		LOGE("Manager server for VPNSERVICE_PATH not created.");
		exit(1);
	}

	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM, VPNSERVICE_SERVICE,
			G_BUS_NAME_OWNER_FLAGS_NONE, __vpnsvc_got_bus_cb,
			__vpnsvc_got_name_cb, __vpnsvc_lost_name_cb,
			NULL, NULL);
	if (!owner_id) {
		LOGE("Could not get system bus!");
		return -EIO;
	}

	LOGI("Got system bus!");
	return 0;
}

void vpnsvc_cleanup_gdbus(void)
{
	LOGD("VPN Service Cleanup!");

	g_bus_unown_name(owner_id);

	return;
}
