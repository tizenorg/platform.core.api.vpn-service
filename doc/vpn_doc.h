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



#ifndef __TIZEN_NETWORK_VPN_DOC_H__
#define __TIZEN_NETWORK_VPN_DOC_H__

/**
 * @defgroup CAPI_NETWORK_VPN_MODULE VPN
 * @brief The Virtual Private Network (VPN) API provides functions for managing VPN.
 * @ingroup CAPI_NETWORK_FRAMEWORK
 *
 * @section CAPI_NETWORK_VPN_MODULE_HEADER Required Header
 *   \#include <vpn_service.h>
 *
 * @section CAPI_NETWORK_VPN_MODULE_OVERVIEW Overview
 * VPN allows your application to manage VPN features.
 * The VPN Service enables your application to init and deinit a VPN device(TUN(namely netowrk TUNel) interface),
 * Routing management, DNS management and Firewall management.
 */

/**
 * @defgroup CAPI_NETWORK_VPN_SERVICE_MODULE  VPN Service
 * @brief The VPN API provides functions for managing VPN.
 * @ingroup CAPI_NETWORK_VPN_MODULE
 *
 * @section CAPI_NETWORK_VPN_SERVICE_MODULE_HEADER Required Header
 *   \#include <vpn_service.h>
 *
 * @section CAPI_NETWORK_VPN_SERVICE_MODULE_OVERVEW Overview
 * The VPN Service functions for managing VPN.
 * Using the VPN Service, you can implement features that allow the users of your application to:
 *	- Initialize / Deinitialize the VPN device
 *	- Routing management
 *	- DNS management
 *	- Firewall management
 * @section CAPI_NETWORK_VPN_SERVICE_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.vpn\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 * More details on featuring your application can be found from <a href="../org.tizen.mobile.native.appprogramming/html/ide_sdk_tools/feature_element.htm"><b>Feature Element</b>.</a>
 *
 */

#endif /* __TIZEN_NETWORK_VPN_DOC_H__ */
