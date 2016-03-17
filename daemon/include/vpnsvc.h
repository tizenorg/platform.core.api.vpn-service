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

#ifndef __VPNSERVICE_VPNSVC_H__
#define __VPNSERVICE_VPNSVC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include <gio/gio.h>
#include <glib-object.h>

#include "generated-code.h"

typedef enum _net_vpn_service_privilege_e
{
	PRIVILEGE_VPN_SERVICE = 0x00,
	PRIVILEGE_VPN_SERVICE_ADMIN,
	PRIVILEGE_INTERNET,
} net_vpn_service_privilege_e;

void vpnsvc_create_and_init(void);
Vpnsvc *get_vpnsvc_object(void);
gboolean vpn_service_gdbus_check_privilege(GDBusMethodInvocation *invocation,
	net_vpn_service_privilege_e _privilege);

#ifdef __cplusplus
}
#endif

#endif /* __VPNSERVICE_VPNSVC_H__ */
