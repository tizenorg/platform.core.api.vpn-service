/*
* Network VPN library
*
* Copyright (c) 2014-2015 Samsung Electronics. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*              http://www.apache.org/licenses/LICENSE-2.0
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
#include <ctype.h>
#include <glib.h>

#include <dvpnlib-vpn.h>
#include <dvpnlib-vpn-manager.h>
#include <dvpnlib-vpn-connection.h>

#include "vpn-internal.h"

struct _vpn_cb_s {
	vpn_created_cb create_cb;
	void *create_user_data;
	vpn_removed_cb remove_cb;
	void *remove_user_data;
	vpn_connect_cb connect_cb;
	void *connect_user_data;
	vpn_disconnect_cb disconnect_cb;
	void *disconnect_user_data;
};

static struct _vpn_cb_s vpn_callbacks = {0,};
static GHashTable *settings_hash;

/*
 * Utility Functions
 */

static void print_key_value_string(gpointer key,
				gpointer value, gpointer user_data)
{
	if (user_data) {
		VPN_LOG(VPN_INFO, " %s[%s]=%s",
			(gchar *)user_data, (gchar *)key, (gchar *)value);
		return;
	}
	VPN_LOG(VPN_INFO, " %s=%s", (gchar *)key, (gchar *)value);
}

vpn_error_e _dvpnlib_error2vpn_error(enum dvpnlib_err err_type)
{
	switch (err_type) {
	case DVPNLIB_ERR_NONE:
		return VPN_ERROR_NONE;
	case DVPNLIB_ERR_ALREADY_EXISTS:
		return VPN_ERROR_INVALID_OPERATION;
	case DVPNLIB_ERR_NOT_REGISTERED:
		return VPN_ERROR_INVALID_OPERATION;
	case DVPNLIB_ERR_NOT_CONNECTED:
		return VPN_ERROR_NO_CONNECTION;
	case DVPNLIB_ERR_ALREADY_CONNECTED:
		return VPN_ERROR_ALREADY_EXISTS;
	case DVPNLIB_ERR_IN_PROGRESS:
		return VPN_ERROR_NOW_IN_PROGRESS;
	case DVPNLIB_ERR_OPERATION_ABORTED:
		return VPN_ERROR_OPERATION_ABORTED;
	case DVPNLIB_ERR_OPERATION_TIMEOUT:
	case DVPNLIB_ERR_TIMEOUT:
		return VPN_ERROR_NO_REPLY;
	default:
		return VPN_ERROR_OPERATION_FAILED;
	}
}

/*
 *Functions Actually use Default VPN Library
 */

bool _vpn_init(void)
{
	int rv;

	rv = dvpnlib_vpn_init();

	if (rv != 0)
		return false;

	return true;
}

bool _vpn_deinit(void)
{
	dvpnlib_vpn_deinit();
	return true;
}

int _vpn_settings_init()
{
	if (settings_hash != NULL) {
		VPN_LOG(VPN_INFO,
			"Settings Hash: %p Already present!", settings_hash);
		return VPN_ERROR_INVALID_OPERATION;
	}

	settings_hash = g_hash_table_new_full(
				g_str_hash, g_str_equal,
				g_free, g_free);
	VPN_LOG(VPN_INFO, "Settings Hash: %p", settings_hash);

	return VPN_ERROR_NONE;
}

int _vpn_settings_deinit()
{
	if (settings_hash == NULL)
		return VPN_ERROR_INVALID_OPERATION;

	VPN_LOG(VPN_INFO, "Settings Hash: %p Destroyed", settings_hash);
	g_hash_table_destroy(settings_hash);
	settings_hash = NULL;

	return VPN_ERROR_NONE;
}

int _vpn_settings_set_specific(const char *key, const char *value)
{
	VPN_LOG(VPN_INFO,
		"Settings Hash: %p {%s=%s}", settings_hash, key, value);

	if (key == NULL)
		return VPN_ERROR_INVALID_PARAMETER;

	if (g_hash_table_contains(settings_hash, key)) {
		if (value == NULL) {
			VPN_LOG(VPN_INFO, "Settings Hash: %p {%s=%s} (Removed)",
				settings_hash, key,
				(gchar *)g_hash_table_lookup(
					settings_hash, key));
			g_hash_table_remove(settings_hash, key);
			return VPN_ERROR_NONE;
		}
	}

	g_hash_table_replace(settings_hash,
			(gpointer)g_strdup(key),
			(gpointer)g_strdup(value));

	return VPN_ERROR_NONE;
}

/*
 *Callbacks
 */
static void __vpn_create_cb(vpn_error_e result)
{
	if (vpn_callbacks.create_cb)
		vpn_callbacks.create_cb(result,
				vpn_callbacks.create_user_data);

	vpn_callbacks.create_cb = NULL;
	vpn_callbacks.create_user_data = NULL;
}

static void vpn_manager_create_cb(enum dvpnlib_err result,
							void *user_data)
{
	VPN_LOG(VPN_INFO, "callback: %d Settings: %p\n", result, user_data);

	__vpn_create_cb(_dvpnlib_error2vpn_error(result));
}

static void __vpn_remove_cb(vpn_error_e result)
{
	if (vpn_callbacks.create_cb)
		vpn_callbacks.create_cb(result,
				vpn_callbacks.create_user_data);

	vpn_callbacks.remove_cb = NULL;
	vpn_callbacks.remove_user_data = NULL;
}

static void vpn_manager_remove_cb(enum dvpnlib_err result,
							void *user_data)
{
	VPN_LOG(VPN_INFO, "callback: %d Settings: %p\n", result, user_data);

	__vpn_remove_cb(_dvpnlib_error2vpn_error(result));
}

int _vpn_create(vpn_created_cb callback, void *user_data)
{
	enum dvpnlib_err err = DVPNLIB_ERR_NONE;
	if (!settings_hash)
		return VPN_ERROR_INVALID_OPERATION;

	VPN_LOG(VPN_INFO, "");

	vpn_callbacks.create_cb = callback;
	vpn_callbacks.create_user_data = user_data;

	g_hash_table_foreach(settings_hash,
		print_key_value_string, "VPNSettings");

	err = dvpnlib_vpn_manager_create(settings_hash,
		vpn_manager_create_cb, NULL);
	if (err != DVPNLIB_ERR_NONE)
		return _dvpnlib_error2vpn_error(err);

	return VPN_ERROR_NONE;

}

int _vpn_remove(vpn_h handle, vpn_removed_cb callback, void *user_data)
{
	enum dvpnlib_err err = DVPNLIB_ERR_NONE;

	VPN_LOG(VPN_INFO, "");

	vpn_callbacks.remove_cb = callback;
	vpn_callbacks.remove_user_data = user_data;

	GList *connections = vpn_get_connections();
	if (NULL == g_list_find(connections, handle)) {
		VPN_LOG(VPN_ERROR, "No Connections with the %p Handle", handle);
		return VPN_ERROR_INVALID_PARAMETER;
	}

	const char *path = vpn_connection_get_path(handle);
	err = dvpnlib_vpn_manager_remove(path, vpn_manager_remove_cb, NULL);
	if (err != DVPNLIB_ERR_NONE)
		return _dvpnlib_error2vpn_error(err);

	return VPN_ERROR_NONE;
}

/*
 *Connect Disconnect Callbacks
 */

static void __vpn_connect_cb(vpn_error_e result)
{
	if (vpn_callbacks.connect_cb)
		vpn_callbacks.connect_cb(result,
				vpn_callbacks.connect_user_data);

	vpn_callbacks.connect_cb = NULL;
	vpn_callbacks.connect_user_data = NULL;
}

static void vpn_manager_connect_cb(enum dvpnlib_err result,
							void *user_data)
{
	VPN_LOG(VPN_INFO, "callback: %d Settings: %p\n", result, user_data);

	__vpn_connect_cb(_dvpnlib_error2vpn_error(result));
}

/*
 *Connect to VPN Profile
 */

int _vpn_connect(vpn_h handle, vpn_removed_cb callback, void *user_data)
{
	enum dvpnlib_err err = DVPNLIB_ERR_NONE;

	VPN_LOG(VPN_INFO, "");

	vpn_callbacks.connect_cb = callback;
	vpn_callbacks.connect_user_data = user_data;

	GList *connections = vpn_get_connections();
	if (NULL == g_list_find(connections, handle)) {
		VPN_LOG(VPN_ERROR, "No Connections with the %p Handle", handle);
		return VPN_ERROR_INVALID_PARAMETER;
	}

	enum vpn_connection_state state = vpn_connection_get_state(handle);
	if (state == VPN_CONN_STATE_READY)
		return VPN_ERROR_ALREADY_EXISTS;

	err = vpn_connection_connect(handle, vpn_manager_connect_cb, NULL);
	if (err != DVPNLIB_ERR_NONE)
		return _dvpnlib_error2vpn_error(err);

	return VPN_ERROR_NONE;
}

/*
 *Disconnect from VPN Profile
 */

int _vpn_disconnect(vpn_h handle)
{
	enum dvpnlib_err err = DVPNLIB_ERR_NONE;

	VPN_LOG(VPN_INFO, "");

	GList *connections = vpn_get_connections();
	if (NULL == g_list_find(connections, handle)) {
		VPN_LOG(VPN_ERROR, "No Connections with the %p Handle", handle);
		return VPN_ERROR_INVALID_PARAMETER;
	}

	enum vpn_connection_state state = vpn_connection_get_state(handle);
	if (state != VPN_CONN_STATE_READY)
		return VPN_ERROR_NO_CONNECTION;

	err = vpn_connection_disconnect(handle);
	if (err != DVPNLIB_ERR_NONE)
		return _dvpnlib_error2vpn_error(err);

	return VPN_ERROR_NONE;
}

/*
 *Gets the VPN Handles List from VPN Profile
 */
GList *_vpn_get_vpn_handle_list(void)
{
	return vpn_get_connections();
}

/*
 * Get a specific VPN Handle based on host & domain parameters
 */
int _vpn_get_vpn_handle(const char *host, const char *domain, vpn_h *handle)
{
	VPN_LOG(VPN_INFO, "");

	struct vpn_connection *connection = vpn_get_connection(host, domain);

	if (connection == NULL) {
		VPN_LOG(VPN_ERROR, "host=%s domain=%s", host, domain);
		return VPN_ERROR_INVALID_PARAMETER;
	}

	*handle = connection;
	return VPN_ERROR_NONE;
}

/*
 * Get VPN Info (Name) from VPN Handle
 */
int _vpn_get_vpn_info_name(vpn_h handle, const char **name)
{
	VPN_LOG(VPN_INFO, "");

	GList *connections = vpn_get_connections();
	if (NULL == g_list_find(connections, handle)) {
		VPN_LOG(VPN_ERROR, "No Connections with the %p Handle", handle);
		return VPN_ERROR_INVALID_PARAMETER;
	}

	*name = vpn_connection_get_name(handle);
	return VPN_ERROR_NONE;
}

/*
 * Get VPN Info (Type) from VPN Handle
 */
int _vpn_get_vpn_info_type(vpn_h handle, const char **type)
{
	VPN_LOG(VPN_INFO, "");

	GList *connections = vpn_get_connections();
	if (NULL == g_list_find(connections, handle)) {
		VPN_LOG(VPN_ERROR, "No Connections with the %p Handle", handle);
		return VPN_ERROR_INVALID_PARAMETER;
	}

	*type = vpn_connection_get_type(handle);
	return VPN_ERROR_NONE;
}

/*
 * Get VPN Info (Host) from VPN Handle
 */
int _vpn_get_vpn_info_host(vpn_h handle, const char **host)
{
	VPN_LOG(VPN_INFO, "");

	GList *connections = vpn_get_connections();
	if (NULL == g_list_find(connections, handle)) {
		VPN_LOG(VPN_ERROR, "No Connections with the %p Handle", handle);
		return VPN_ERROR_INVALID_PARAMETER;
	}

	*host = vpn_connection_get_host(handle);
	return VPN_ERROR_NONE;
}

/*
 * Get VPN Info (Domain) from VPN Handle
 */
int _vpn_get_vpn_info_domain(vpn_h handle, const char **domain)
{
	VPN_LOG(VPN_INFO, "");

	GList *connections = vpn_get_connections();
	if (NULL == g_list_find(connections, handle)) {
		VPN_LOG(VPN_ERROR, "No Connections with the %p Handle", handle);
		return VPN_ERROR_INVALID_PARAMETER;
	}

	*domain = vpn_connection_get_domain(handle);
	return VPN_ERROR_NONE;
}
