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

#include <glib.h>
#include <dlog/dlog.h>

#include "vpndbus.h"
#include "vpnerror.h"

#define VPNSVC_ERROR_INTERFACE VPNSERVICE_INTERFACE ".Error"

void vpnsvc_error_inprogress(GDBusMethodInvocation *context)
{
	LOGE("dbus method return error");
	g_dbus_method_invocation_return_error(context,
		G_DBUS_ERROR,
		G_DBUS_ERROR_ACCESS_DENIED,
		VPNSVC_ERROR_INTERFACE ".InProgress");
}

void vpnsvc_error_invalid_parameter(GDBusMethodInvocation *context)
{
	LOGE("dbus method return error");
	g_dbus_method_invocation_return_error(context,
		G_DBUS_ERROR,
		G_DBUS_ERROR_ACCESS_DENIED,
		VPNSVC_ERROR_INTERFACE ".InvalidParameter");
}

void vpnsvc_error_permission_denied(GDBusMethodInvocation *context)
{
	LOGE("dbus method return error");
	g_dbus_method_invocation_return_error(context,
		G_DBUS_ERROR,
		G_DBUS_ERROR_ACCESS_DENIED,
		VPNSVC_ERROR_INTERFACE ".PermissionDenied");
}
