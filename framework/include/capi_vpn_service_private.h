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

#ifndef __VPN_SERVICE_H__
#define __VPN_SERVICE_H__

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <dlog/dlog.h>
#include <glib.h>
#include <gio/gio.h>

#include "vpn_service.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define DBUS_DAEMON_SERVICE_NAME  "org.freedesktop.DBus"
#define DBUS_DAEMON_OBJECT_NAME  "/org/freedesktop/DBus"
#define DBUS_DAEMON_INTERFACE_NAME  "org.freedesktop.DBus"
#define DBUS_DAEMON_START_SERVICE_METHOD_NAME  "StartServiceByName"

#define VPNSVC_DBUS_SERVICE_NAME  "org.tizen.vpnsvc"
#define VPNSVC_DBUS_INTERFACE_NAME  "org.tizen.vpnsvc"
#define VPNSVC_DBUS_INTERFACE_OBJ_NAME  "/org/tizen/vpnsvc"

#define _MAX_FILE_PATH_LEN 512
#define _USER_SETTING_DEFAULT_MTU 1500
#define _USER_SETTING_DEFAULT_SESSION "VPN_Session"

#define VPN_SERVICE_FEATURE	"http://tizen.org/feature/network.vpn"

#define CHECK_FEATURE_SUPPORTED(feature_name) \
	do { \
		int feature_rv = _vpnsvc_check_feature_supported(feature_name); \
		if (feature_rv != VPNSVC_ERROR_NONE) \
			return feature_rv; \
	} while(0)

/**
  * @brief This data structure has a fido data and its length.
  */
typedef struct _vpnsvc_tun_s {
	GDBusConnection *connection;            /**< D-Bus Connection */
	int fd;                                 /**< tun socket fd */
	int index;                              /**< tun index (if.if_index) */
	char name[VPNSVC_TUN_IF_NAME_LEN];      /**< tun name (if.if_name) */
	char session[VPNSVC_SESSION_STRING_LEN];/**< session name (user setting) */
	unsigned int mtu;                       /**< mtu (user setting) */
} vpnsvc_tun_s;

int _vpnsvc_check_feature_supported(const char *feature_name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
