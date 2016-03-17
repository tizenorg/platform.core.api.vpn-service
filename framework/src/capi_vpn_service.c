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


#include "capi_vpn_service_private.h"
#include <app.h>
#include <app_info.h>
#include <system_info.h>
#include <gio/gunixfdlist.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "CAPI_VPNSVC"

#define DBUS_REPLY_TIMEOUT (120 * 1000)
#define BUF_SIZE_FOR_ERR 100

GVariant *op = NULL;

static __thread bool is_feature_checked = false;
static __thread bool feature_supported = false;

int _vpnsvc_check_feature_supported(const char *feature_name)
{
	if (is_feature_checked) {
		if (!feature_supported) {
			LOGE("%s feature is disabled", feature_name); //LCOV_EXCL_LINE
			return VPNSVC_ERROR_NOT_SUPPORTED; //LCOV_EXCL_LINE
		}
	} else {
		if (!system_info_get_platform_bool(feature_name, &feature_supported)) {
			is_feature_checked = true;
			if (!feature_supported) {
				LOGE("%s feature is disabled", feature_name); //LCOV_EXCL_LINE
				return VPNSVC_ERROR_NOT_SUPPORTED; //LCOV_EXCL_LINE
			}
		} else {
			LOGE("Error - Feature getting from System Info"); //LCOV_EXCL_LINE
			return VPNSVC_ERROR_IO_ERROR; //LCOV_EXCL_LINE
		}
	}

	return VPNSVC_ERROR_NONE;
}

static void _vpnsvc_init_vpnsvc_tun_s(vpnsvc_tun_s **s)
{
	LOGD(" tun_s: %p", s);

	if (s == NULL) return;
	if (*s != NULL) {
		LOGE("Can't Initialize vpnsvc_tun_s: %p", *s); //LCOV_EXCL_LINE
		return; //LCOV_EXCL_LINE
	}
	*s = (vpnsvc_tun_s*)g_malloc0(sizeof(vpnsvc_tun_s));

	if ((*s)->connection == NULL) {
		GDBusConnection *connection = NULL;
		GError* error = NULL;

#if !GLIB_CHECK_VERSION(2, 36, 0)
		g_type_init();
#endif

		connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
		if (error != NULL) {
			LOGE("Error creating Connection: %s", error->message); //LCOV_EXCL_LINE
			g_error_free(error); //LCOV_EXCL_LINE
		} else {
			LOGD("Created Connection: %p", connection);
			(*s)->connection = connection;
		}
	}

	/* Setting Default User Settings */
	(*s)->mtu = _USER_SETTING_DEFAULT_MTU;
	strncpy((*s)->session, _USER_SETTING_DEFAULT_SESSION, VPNSVC_SESSION_STRING_LEN);
	(*s)->session[VPNSVC_SESSION_STRING_LEN-1] = '\0';
}

static void _vpnsvc_deinit_vpnsvc_tun_s(vpnsvc_tun_s *s)
{
	if (s == NULL) return;

	if (s->connection)
		s->connection = NULL;

	s->fd = 0;
	s->index = 0;
	memset(s->name, 0, VPNSVC_VPN_IFACE_NAME_LEN);
	memset(s->session, 0, VPNSVC_SESSION_STRING_LEN);

	if (s)
		g_free(s);
}

/*****************************************************************************
* Global Functions Definition
*****************************************************************************/
GVariant *_vpnsvc_invoke_dbus_method(GDBusConnection *connection,
		const char *dest, const char *path,
		const char *interface_name, const char *method,
		GVariant *params, int *dbus_error)
{
	GError *error = NULL;
	GVariant *reply = NULL;
	*dbus_error = VPNSVC_ERROR_NONE;

	LOGD("Method Call() dest=%s path=%s iface=%s method=%s", dest, path, interface_name, method);

	if (connection == NULL) {
		LOGD("GDBusconnection is NULL"); //LCOV_EXCL_LINE
		*dbus_error = VPNSVC_ERROR_IO_ERROR; //LCOV_EXCL_LINE
		return reply; //LCOV_EXCL_LINE
	}

	reply = g_dbus_connection_call_sync(connection,
										dest,
										path,
										interface_name,
										method,
										params,
										NULL,
										G_DBUS_CALL_FLAGS_NONE,
										DBUS_REPLY_TIMEOUT,
										NULL,
										&error);

	if (reply == NULL) {
		if (error != NULL) {
			if (error->code == G_DBUS_ERROR_ACCESS_DENIED){
				LOGE("g_dbus_connection_call_sync() failed"
					"error [%d: %s]", error->code, error->message);//LCOV_EXCL_LINE
				*dbus_error = VPNSVC_ERROR_PERMISSION_DENIED;//LCOV_EXCL_LINE
				g_error_free(error);//LCOV_EXCL_LINE
			} else {
				LOGE("g_dbus_connection_call_sync() failed"
						"error [%d: %s]", error->code, error->message);//LCOV_EXCL_LINE
				*dbus_error = VPNSVC_ERROR_IO_ERROR;//LCOV_EXCL_LINE
				g_error_free(error);//LCOV_EXCL_LINE
			}
		} else {
			LOGE("g_dbus_connection_call_sync() failed");//LCOV_EXCL_LINE
			*dbus_error = VPNSVC_ERROR_IPC_FAILED;//LCOV_EXCL_LINE
		}

		return NULL;
	}

	return reply;
}
GVariant *_vpnsvc_invoke_dbus_method_with_fd(GDBusConnection *connection,
	const char *dest, const char *path,
	const char *interface_name, const char *method,
	GVariant *params, int fd, int *dbus_error)
{
	GError *error = NULL;
	GVariant *reply = NULL;
	GUnixFDList *fd_list = NULL;
	*dbus_error = VPNSVC_ERROR_NONE;

	LOGD("Method Call() dest=%s path=%s iface=%s method=%s fd=%d", dest, path, interface_name, method, fd);

	if (connection == NULL) {
		LOGD("GDBusconnection is NULL"); //LCOV_EXCL_LINE
		*dbus_error = VPNSVC_ERROR_IO_ERROR; //LCOV_EXCL_LINE
		return reply; //LCOV_EXCL_LINE
	}

	/* Setting the fd_list */
	fd_list = g_unix_fd_list_new();
	if (fd_list == NULL) {
		LOGE("g_unix_fd_list_new() failed!"); //LCOV_EXCL_LINE
		return NULL; //LCOV_EXCL_LINE
	}
	g_unix_fd_list_append(fd_list, fd, &error);
	if (error != NULL) {
		LOGE("g_unix_fd_list_append() failed" //LCOV_EXCL_LINE
				"error [%d: %s]", error->code, error->message);
		*dbus_error = VPNSVC_ERROR_IO_ERROR; //LCOV_EXCL_LINE
		g_error_free(error); //LCOV_EXCL_LINE
		return NULL; //LCOV_EXCL_LINE
	}

	reply = g_dbus_connection_call_with_unix_fd_list_sync(connection,
														dest,
														path,
														interface_name,
														method,
														params,
														NULL,
														G_DBUS_CALL_FLAGS_NONE,
														DBUS_REPLY_TIMEOUT,
														fd_list,
														NULL,
														NULL,
														&error);

	if (reply == NULL) {
		if (error != NULL) {
			LOGE("g_dbus_connection_call_sync() failed" //LCOV_EXCL_LINE
					"error [%d: %s]", error->code, error->message);
			*dbus_error = VPNSVC_ERROR_IO_ERROR; //LCOV_EXCL_LINE
			g_error_free(error); //LCOV_EXCL_LINE
		} else {
			LOGE("g_dbus_connection_call_sync() failed"); //LCOV_EXCL_LINE
			*dbus_error = VPNSVC_ERROR_IPC_FAILED; //LCOV_EXCL_LINE
		}

		return NULL;
	}

	return reply;
}

EXPORT_API int vpnsvc_init(const char* iface_name, vpnsvc_h *handle)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	int result = VPNSVC_ERROR_NONE;
	int dbus_result;
	int iface_fd = 0;

	LOGD("enter vpnsvc_init, iface_name : %s", iface_name);
	LOGD("handle : %p\n", handle);

	/* parameter check */
	if (iface_name == NULL || strlen(iface_name) <= 0) {
		LOGE("iface_name is a NULL");
		return VPNSVC_ERROR_INVALID_PARAMETER;
	} else if (handle == NULL) {
		LOGE("handle is a NULL");
		return VPNSVC_ERROR_INVALID_PARAMETER;
	} else if (*handle != NULL) {
		LOGE("handle already created");
		return VPNSVC_ERROR_INVALID_PARAMETER;
	}

	vpnsvc_tun_s *tmp_s = NULL;
	_vpnsvc_init_vpnsvc_tun_s(&tmp_s);

	op = _vpnsvc_invoke_dbus_method(tmp_s->connection,
									DBUS_DAEMON_SERVICE_NAME,
									DBUS_DAEMON_OBJECT_NAME,
									DBUS_DAEMON_INTERFACE_NAME,
									DBUS_DAEMON_START_SERVICE_METHOD_NAME,
									g_variant_new("(su)", VPNSVC_DBUS_SERVICE_NAME, 0),
									&dbus_result);

	if (dbus_result == VPNSVC_ERROR_PERMISSION_DENIED){
		return VPNSVC_ERROR_PERMISSION_DENIED;
	}

	if (op == NULL) {
		_vpnsvc_deinit_vpnsvc_tun_s(tmp_s); //LCOV_EXCL_LINE
		LOGD("Service [%s] Start Failed!", VPNSVC_DBUS_SERVICE_NAME); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_IPC_FAILED; //LCOV_EXCL_LINE
	} else {
		unsigned int status = 0;
		g_variant_get(op, "(u)", &status);
		if (1 == status) {	/* DBUS_START_REPLY_SUCCESS */
			LOGD("Service [%s] Started Successfully!", VPNSVC_DBUS_SERVICE_NAME);
		} else if (2 == status) {	/* DBUS_START_REPLY_ALREADY_RUNNING */
			LOGD("Service [%s] Already Running!", VPNSVC_DBUS_SERVICE_NAME);
		} else {
			LOGD("Service [%s] Not Started! Status[%d]", VPNSVC_DBUS_SERVICE_NAME, status); //LCOV_EXCL_LINE
			g_variant_unref(op); //LCOV_EXCL_LINE
			op = NULL; //LCOV_EXCL_LINE
			_vpnsvc_deinit_vpnsvc_tun_s(tmp_s); //LCOV_EXCL_LINE
			return VPNSVC_ERROR_IO_ERROR; //LCOV_EXCL_LINE
		}
		g_variant_unref(op);
		op = NULL;
	}

	if ((iface_fd = open("/dev/net/tun", O_RDWR)) < 0) {
		LOGE("tun device open fail\n"); //LCOV_EXCL_LINE
		_vpnsvc_deinit_vpnsvc_tun_s(tmp_s); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_IO_ERROR; //LCOV_EXCL_LINE
	}

	LOGD("client iface_fd : %d", iface_fd);

	op = _vpnsvc_invoke_dbus_method_with_fd(tmp_s->connection,
							VPNSVC_DBUS_SERVICE_NAME,
							VPNSVC_DBUS_INTERFACE_OBJ_NAME,
							VPNSVC_DBUS_INTERFACE_NAME,
							"vpn_init",
							g_variant_new("(su)", iface_name, strlen(iface_name)),
							iface_fd,
							&dbus_result);

	if (op == NULL) {
		close(iface_fd); //LCOV_EXCL_LINE
		_vpnsvc_deinit_vpnsvc_tun_s(tmp_s); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_IPC_FAILED; //LCOV_EXCL_LINE
	} else {
		int tmp_index;
		char* tmp_name;

		g_variant_get(op, "(iis)", &result, &tmp_index, &tmp_name);
		if (result != VPNSVC_ERROR_NONE) {
			LOGE("vpnsvc_init() failed"); //LCOV_EXCL_LINE
			_vpnsvc_deinit_vpnsvc_tun_s(tmp_s); //LCOV_EXCL_LINE
			result = VPNSVC_ERROR_IPC_FAILED; //LCOV_EXCL_LINE
		} else {
			LOGD("vpnsvc_init() succeed");
			tmp_s->fd = iface_fd;	/* client fd must be set */
			tmp_s->index = tmp_index;
			strncpy(tmp_s->name, tmp_name, VPNSVC_VPN_IFACE_NAME_LEN);
			tmp_s->name[VPNSVC_VPN_IFACE_NAME_LEN-1] = '\0';
			*handle = tmp_s;
			LOGD("handle : %p, handle->fd : %d, handle->index : %d, handle->name : %s",
				(*handle), ((vpnsvc_tun_s*)*handle)->fd, ((vpnsvc_tun_s*)*handle)->index, ((vpnsvc_tun_s*)*handle)->name);
		}
		if (op) {
			g_variant_unref(op);
			op = NULL;
		}
	}

	return result;
}

EXPORT_API int vpnsvc_deinit(vpnsvc_h handle)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	int result = VPNSVC_ERROR_NONE;
	int dbus_result;
	vpnsvc_tun_s *tun_s = NULL;
	char buf[BUF_SIZE_FOR_ERR] = { 0 };

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}
	tun_s = (vpnsvc_tun_s*)handle;

	LOGD("enter vpnsvc_deinit, iface_fd : %d", tun_s->fd);

	if (tun_s->fd > 0) {
		op = _vpnsvc_invoke_dbus_method(tun_s->connection,
									VPNSVC_DBUS_SERVICE_NAME,
									VPNSVC_DBUS_INTERFACE_OBJ_NAME,
									VPNSVC_DBUS_INTERFACE_NAME,
									"vpn_deinit",
									g_variant_new("(s)", tun_s->name),
									&dbus_result);

		if (dbus_result == VPNSVC_ERROR_PERMISSION_DENIED){
			return VPNSVC_ERROR_PERMISSION_DENIED;
		}

		if (op == NULL) {
			return VPNSVC_ERROR_IPC_FAILED; //LCOV_EXCL_LINE
		} else {
			g_variant_get(op, "(i)", &result);
			if (result != VPNSVC_ERROR_NONE)
				LOGE("vpn_deinit() failed"); //LCOV_EXCL_LINE
			else
				LOGD("vpn_deinit() succeed");
		}

		if (close(tun_s->fd) != 0) {
			LOGE("tun fd close : %s", strerror_r(errno, buf, BUF_SIZE_FOR_ERR)); //LCOV_EXCL_LINE
			return VPNSVC_ERROR_IO_ERROR; //LCOV_EXCL_LINE
		} else
			LOGD("tun fd close success");

		/* free allocared handle memory */
		_vpnsvc_deinit_vpnsvc_tun_s(tun_s);
	}

	return result;
}

EXPORT_API int vpnsvc_protect(vpnsvc_h handle, int socket_fd, const char* iface_name)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	int result = VPNSVC_ERROR_NONE;
	int dbus_result;
	vpnsvc_tun_s *tun_s = NULL;

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}
	tun_s = (vpnsvc_tun_s*)handle;

	LOGD("enter vpnsvc_protect, socket : %d, dev_name : %s", socket_fd, iface_name);

	if (tun_s->connection == NULL) {
		LOGE("Connection Object is NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	/* call vpnsvc_protect */
	op = _vpnsvc_invoke_dbus_method_with_fd(tun_s->connection,
						VPNSVC_DBUS_SERVICE_NAME,
						VPNSVC_DBUS_INTERFACE_OBJ_NAME,
						VPNSVC_DBUS_INTERFACE_NAME,
						"vpn_protect",
						g_variant_new("(s)", iface_name),
						socket_fd,
						&dbus_result);

	if (dbus_result == VPNSVC_ERROR_PERMISSION_DENIED){
		return VPNSVC_ERROR_PERMISSION_DENIED;
	}

	if (op == NULL) {
		return VPNSVC_ERROR_IPC_FAILED; //LCOV_EXCL_LINE
	} else {
		g_variant_get(op, "(i)", &result);

		if (result != VPNSVC_ERROR_NONE)
			LOGE("vpn_protect() failed"); //LCOV_EXCL_LINE
		else
			LOGD("vpn_protect() succeed");
	}

	return result;
}

EXPORT_API int vpnsvc_up(vpnsvc_h handle, const char* local_ip, const char* remote_ip,
				const char* routes_dest_add[], int routes_prefix[], size_t num_routes,
				const char** dns_servers, size_t num_dns_servers,
				const char* dns_suffix)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	int result = VPNSVC_ERROR_NONE;
	int dbus_result;
	GVariantBuilder route_builder, dns_builder;
	size_t i = 0;
	GVariant *route_param = NULL;
	GVariant *dns_param = NULL;
	vpnsvc_tun_s *tun_s = NULL;

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}
	tun_s = (vpnsvc_tun_s*)handle;

	LOGD("enter vpnsvc_up");

	if (tun_s->index <= 0) {
		LOGE("invalid handle"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	} else if (tun_s->connection == NULL) {
		LOGE("Connection Object is NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	if (local_ip == NULL || remote_ip == NULL) {
		LOGE("local and remote ip are invalid"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	LOGD("iface_index %d", tun_s->index);
	LOGD("local_ip : %s, remote_ip : %s", local_ip, remote_ip);

	/* make a route parameter */
	g_variant_builder_init(&route_builder, G_VARIANT_TYPE("a{si}"));
	for (i = 0 ; i < num_routes ; i++) {
		if (strlen(routes_dest_add[i]) <= 0) {
			LOGE("invalid dest[%d]", i); //LCOV_EXCL_LINE
			return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
		}
		g_variant_builder_add(&route_builder, "{si}", routes_dest_add[i], routes_prefix[i]);
		LOGD("dest[%d] : %s", i, routes_dest_add[i]);
		LOGD("prefix[i] : %d", i,  routes_prefix[i]);
	}
	route_param = g_variant_builder_end(&route_builder);

	/* make a dns parameter */
	g_variant_builder_init(&dns_builder, G_VARIANT_TYPE("as"));
	for (i = 0 ; i < num_dns_servers ; i++) {
		if (strlen(dns_servers[i]) <= 0) {
			LOGE("invalid dns_servers[%d]", i); //LCOV_EXCL_LINE
			return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
		}
		LOGD("dns_servers[%d] : %s", i, dns_servers[i]);
		g_variant_builder_add(&dns_builder, "s", dns_servers[i]);
	}
	dns_param = g_variant_builder_end(&dns_builder);

	LOGD("dns_suffix : %s", dns_suffix);

	op = _vpnsvc_invoke_dbus_method(tun_s->connection,
								VPNSVC_DBUS_SERVICE_NAME,
								VPNSVC_DBUS_INTERFACE_OBJ_NAME,
								VPNSVC_DBUS_INTERFACE_NAME,
								"vpn_up",
								g_variant_new("(issvuvusu)", tun_s->index, local_ip, \
								remote_ip, route_param, num_routes, dns_param, num_dns_servers, \
								dns_suffix, tun_s->mtu),
								&dbus_result);

	if (op == NULL) {
		return VPNSVC_ERROR_IPC_FAILED; //LCOV_EXCL_LINE
	} else {
		g_variant_get(op, "(i)", &result);
		if (result != VPNSVC_ERROR_NONE)
			LOGE("vpn_up() failed"); //LCOV_EXCL_LINE
		else
			LOGD("vpn_up() succeed");
	}

	return result;
}

EXPORT_API int vpnsvc_down(vpnsvc_h handle)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	int result = VPNSVC_ERROR_NONE;
	int dbus_result;
	vpnsvc_tun_s *tun_s = NULL;

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}
	tun_s = (vpnsvc_tun_s*)handle;

	LOGD("enter vpnsvc_down");

	if (tun_s == NULL) {
		LOGE("handle is a NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	} else if (tun_s->index <= 0) {
		LOGE("invalid handle"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	} else if (tun_s->connection == NULL) {
		LOGE("Connection Object is NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	op = _vpnsvc_invoke_dbus_method(tun_s->connection,
								VPNSVC_DBUS_SERVICE_NAME,
								VPNSVC_DBUS_INTERFACE_OBJ_NAME,
								VPNSVC_DBUS_INTERFACE_NAME,
								"vpn_down",
								g_variant_new("(i)", tun_s->index),
								&dbus_result);

	if (op == NULL) {
		return VPNSVC_ERROR_IPC_FAILED; //LCOV_EXCL_LINE
	} else {
		g_variant_get(op, "(i)", &result);
		if (result != VPNSVC_ERROR_NONE)
			LOGE("vpn_down() failed"); //LCOV_EXCL_LINE
		else
			LOGD("vpn_down() succeed");
	}

	return result;

}

/* this API must not be use IPC */
EXPORT_API int vpnsvc_read(vpnsvc_h handle, int timeout_ms)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	fd_set read_set;
	struct timeval tv;
	int ret, retVal;
	vpnsvc_tun_s *tun_s = NULL;

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}
	tun_s = (vpnsvc_tun_s*)handle;

	if (tun_s->fd <= 0) {
		LOGE("invalid handle"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	/* listen for events */
	FD_ZERO(&read_set);
	FD_SET(tun_s->fd, &read_set);
	tv.tv_usec = timeout_ms*1000;
	retVal = select(tun_s->fd +1, &read_set, NULL, NULL, &tv);

	if (retVal) {
		LOGD("Data is available now.\n");
		ret = VPNSVC_ERROR_NONE;
	} else if (retVal == 0) {
		LOGD("No data within %d ms\n", timeout_ms); //LCOV_EXCL_LINE
		ret = VPNSVC_ERROR_TIMEOUT; //LCOV_EXCL_LINE
	} else {
		LOGE("select failed\n"); //LCOV_EXCL_LINE
		ret = VPNSVC_ERROR_IO_ERROR; //LCOV_EXCL_LINE
	}

	return ret;
}

/* this API must not be use IPC */
EXPORT_API int vpnsvc_write(vpnsvc_h handle, const char* data, size_t size)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	vpnsvc_tun_s *tun_s = NULL;

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}
	tun_s = (vpnsvc_tun_s*)handle;

	if (tun_s->fd <= 0) {
		LOGE("invalid handle"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	return write(tun_s->fd, data, size);
}


EXPORT_API int vpnsvc_block_networks(vpnsvc_h handle,
		const char* routes_dest_vpn_addr[],
		int routes_vpn_prefix[],
		size_t num_allow_routes_vpn,
		const char* routes_dest_orig_addr[],
		int routes_orig_prefix[],
		size_t num_allow_routes_orig)

{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	int result = VPNSVC_ERROR_NONE;
	int dbus_result;
	GVariantBuilder nets_builder;
	size_t i = 0;
	GVariant *nets_param_vpn;
	GVariant *nets_param_orig;
	vpnsvc_tun_s *tun_s = NULL;

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}
	tun_s = (vpnsvc_tun_s*)handle;

	LOGD("enter vpnsvc_block_networks");

	if (tun_s->connection == NULL) {
		LOGE("Connection Object is NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}
	/* make a route parameter for allowed VPN interface routes */
	g_variant_builder_init(&nets_builder, G_VARIANT_TYPE("a{si}"));
	for (i = 0 ; i < num_allow_routes_vpn ; i++) {
		g_variant_builder_add(&nets_builder, "{si}", routes_dest_vpn_addr[i], routes_vpn_prefix[i]);
		LOGD("dest_vpn[%d] : %s", i, routes_dest_vpn_addr[i]);
		LOGD("prefix_vpn[%d] : %d", i,  routes_vpn_prefix[i]);
	}
	nets_param_vpn = g_variant_builder_end(&nets_builder);

	/* make a route parameter for allowed Original interface Routes */
	g_variant_builder_init(&nets_builder, G_VARIANT_TYPE("a{si}"));
	for (i = 0 ; i < num_allow_routes_orig ; i++) {
		g_variant_builder_add(&nets_builder, "{si}", routes_dest_orig_addr[i], routes_orig_prefix[i]);
		LOGD("dest_orig[%d] : %s", i, routes_dest_orig_addr[i]);
		LOGD("prefix_orig[%d] : %d", i,  routes_orig_prefix[i]);
	}
	nets_param_orig = g_variant_builder_end(&nets_builder);

	op = _vpnsvc_invoke_dbus_method(tun_s->connection,
								VPNSVC_DBUS_SERVICE_NAME,
								VPNSVC_DBUS_INTERFACE_OBJ_NAME,
								VPNSVC_DBUS_INTERFACE_NAME,
								"vpn_block_networks",
								g_variant_new("(vuvu)", nets_param_vpn, num_allow_routes_vpn,
								nets_param_orig, num_allow_routes_orig),
								&dbus_result);

	if (dbus_result == VPNSVC_ERROR_PERMISSION_DENIED){
		return VPNSVC_ERROR_PERMISSION_DENIED;
	}

	if (op == NULL) {
		return VPNSVC_ERROR_IPC_FAILED; //LCOV_EXCL_LINE
	} else {
		g_variant_get(op, "(i)", &result);
		if (result != VPNSVC_ERROR_NONE)
			LOGE("vpn_block_networks() failed"); //LCOV_EXCL_LINE
		else
			LOGD("vpn_block_networks() succeed");
	}

	return result;
}

EXPORT_API int vpnsvc_unblock_networks(vpnsvc_h handle)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	int result = VPNSVC_ERROR_NONE;
	int dbus_result;
	vpnsvc_tun_s *tun_s = NULL;

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}
	tun_s = (vpnsvc_tun_s*)handle;

	LOGD("enter vpnsvc_unblock_networks");

	if (tun_s == NULL) {
		LOGE("handle is a NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	} else if (tun_s->connection == NULL) {
		LOGE("Connection Object is NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	op = _vpnsvc_invoke_dbus_method(tun_s->connection,
									VPNSVC_DBUS_SERVICE_NAME,
									VPNSVC_DBUS_INTERFACE_OBJ_NAME,
									VPNSVC_DBUS_INTERFACE_NAME,
									"vpn_unblock_networks",
									g_variant_new("()"),
									&dbus_result);

	if (dbus_result == VPNSVC_ERROR_PERMISSION_DENIED){
		return VPNSVC_ERROR_PERMISSION_DENIED;
	}

	if (op == NULL) {
		return VPNSVC_ERROR_IPC_FAILED; //LCOV_EXCL_LINE
	} else {
		g_variant_get(op, "(i)", &result);
		if (result != VPNSVC_ERROR_NONE)
			LOGE("vpn_unblock_networks() failed"); //LCOV_EXCL_LINE
		else
			LOGD("vpn_unblock_networks() succeed");
	}

	return result;
}

EXPORT_API int vpnsvc_get_iface_fd(vpnsvc_h handle, int* iface_fd)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	vpnsvc_tun_s *tun_s = NULL;

	/* parameter check */
	if (handle == NULL || iface_fd == NULL) {
		LOGE("Invalid parameter"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}
	tun_s = (vpnsvc_tun_s*)handle;

	if (tun_s->fd <= 0) {
		LOGE("invalid handle"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	*iface_fd = (int)(tun_s->fd);

	return VPNSVC_ERROR_NONE;
}

EXPORT_API int vpnsvc_get_iface_index(vpnsvc_h handle, int* iface_index)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	vpnsvc_tun_s *tun_s = NULL;

	/* parameter check */
	if (handle == NULL || iface_index == NULL) {
		LOGE("Invalid parameter"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	tun_s = (vpnsvc_tun_s*)handle;

	if (tun_s->index <= 0) {
		LOGE("invalid handle"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	*iface_index = (int)(tun_s->index);

	return VPNSVC_ERROR_NONE;
}

EXPORT_API int vpnsvc_get_iface_name(vpnsvc_h handle, char** iface_name)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	vpnsvc_tun_s *tun_s = NULL;
	char la_iface_name[VPNSVC_VPN_IFACE_NAME_LEN + 1] = { 0, };

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}
	tun_s = (vpnsvc_tun_s*)handle;

	if (strlen(tun_s->name) <= 0) {
		LOGE("invalid handle"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	if (iface_name == NULL) {
		LOGE("tun name string is NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	g_strlcpy(la_iface_name, tun_s->name, VPNSVC_VPN_IFACE_NAME_LEN + 1);
	*iface_name = g_strdup(la_iface_name);

	return VPNSVC_ERROR_NONE;
}

EXPORT_API int vpnsvc_set_mtu(vpnsvc_h handle, int mtu)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	vpnsvc_tun_s *tun_s = NULL;

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}
	tun_s = (vpnsvc_tun_s*)handle;

	if (mtu <= 0) {
		LOGE("Incorrect MTU Size = %d", mtu); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	tun_s->mtu = mtu;
	return VPNSVC_ERROR_NONE;
}

EXPORT_API int vpnsvc_set_blocking(vpnsvc_h handle, bool blocking)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	vpnsvc_tun_s *tun_s = NULL;

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL");
		return VPNSVC_ERROR_INVALID_PARAMETER;
	}
	tun_s = (vpnsvc_tun_s*)handle;

	int flags;

	if (tun_s->fd <= 0) {
		LOGE("The Tunnel File Descriptor fd = %d", tun_s->fd); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	flags = fcntl(tun_s->fd, F_GETFL);
	if (flags < 0) {
		LOGD("File Descriptor Flags GET Failed fd = %d", tun_s->fd); //LCOV_EXCL_LINE
		flags = 0; //LCOV_EXCL_LINE
	}

	if (blocking == false)
		flags = flags | O_NONBLOCK;
	else
		flags = flags & (~O_NONBLOCK);

	if (fcntl(tun_s->fd, F_SETFL, flags) < 0) {
		LOGE("Failed fd = %d F_SETFL(flags) = %d", tun_s->fd, flags); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_IO_ERROR; //LCOV_EXCL_LINE
	}
	return VPNSVC_ERROR_NONE;
}

EXPORT_API int vpnsvc_set_session(vpnsvc_h handle, const char* session)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	vpnsvc_tun_s *tun_s = NULL;

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL");
		return VPNSVC_ERROR_INVALID_PARAMETER;
	}
	tun_s = (vpnsvc_tun_s*)handle;

	if (session == NULL) {
		LOGE("Session Name string is NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	strncpy(tun_s->session, session, VPNSVC_SESSION_STRING_LEN);
	tun_s->session[VPNSVC_SESSION_STRING_LEN-1] = '\0';

	return VPNSVC_ERROR_NONE;
}

EXPORT_API int vpnsvc_get_session(vpnsvc_h handle, char** session)
{
	CHECK_FEATURE_SUPPORTED(VPN_SERVICE_FEATURE);

	vpnsvc_tun_s *tun_s = NULL;
	char la_session[VPNSVC_SESSION_STRING_LEN + 1] = { 0, };

	/* parameter check */
	if (handle == NULL) {
		LOGE("handle is a NULL");
		return VPNSVC_ERROR_INVALID_PARAMETER;
	}
	tun_s = (vpnsvc_tun_s*)handle;

	if (session == NULL) {
		LOGE("Session Name string is NULL"); //LCOV_EXCL_LINE
		return VPNSVC_ERROR_INVALID_PARAMETER; //LCOV_EXCL_LINE
	}

	g_strlcpy(la_session, tun_s->session, VPNSVC_SESSION_STRING_LEN + 1);
	*session = g_strdup(la_session);

	return VPNSVC_ERROR_NONE;
}
