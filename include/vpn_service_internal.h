/*
opyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
*/

#ifndef __TIZEN_VPN_SERVICE_INTERNAL_H__
#define __TIZEN_VPN_SERVICE_INTERNAL_H__

/**
 * @addtogroup	CAPI_NETWORK_VPN_MODULE
 * @{
 */

#include <tizen.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @file vpn_service_internal.h
 */

/**
 * @internal
 * @brief Sets-up VPN interface and brings it up. Installs specified routes/DNS servers/DNS suffix.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/vpnservice.admin
 * @param[in] handle				The VPN interface handle
 * @param[in] local_ip				The local(vpn client) IP address
 * @param[in] remote_ip				The remote(vpn server) IP address
 * @param[in] routes_dest_addr		Destination address of the routes
 * @param[in] routes_prefix         The prefix of routes, netmask length (also called a prefix, e.g. 8, 16, 24, 32)
 * @param[in] num_routes			The number of routes, Unlimitation
 * @param[in] dns_servers			The list of DNS server names - Optional
 * @param[in] num_dns_servers		The number of DNS server names - Optionl, Unlimitation
 * @param[in] dns_suffix     		The DNS suffix - Optional (e.g. tizen.org)
 * @return 0 on success. otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_IPC_FAILED            Cannot connect to service daemon
 * @retval #VPNSVC_ERROR_PERMISSION_DENIED     Permission Denied
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @pre The VPN interface should be initialized already.
 * @post If you want to set interface down, please call vpnsvc_down().
 * @see vpnsvc_init()
 * @see vpnsvc_down()
 */
int vpnsvc_up(vpnsvc_h handle, const char* local_ip, const char* remote_ip,
				char *routes_dest_addr[], int routes_prefix[], size_t num_routes,
				const char** dns_servers, size_t num_dns_servers,
				const char* dns_suffix);

/**
 * @internal
 * @brief Brings the VPN interface down and restores original DNS servers/domains.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/vpnservice.admin
 * @param[in] handle The VPN interface handle
 * @return 0 on success. otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_IPC_FAILED            Cannot connect to service daemon
 * @retval #VPNSVC_ERROR_PERMISSION_DENIED     Permission Denied
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @pre The VPN interface should be initialized and sets-up VPN interface already.
 * @post Please call vpnsvc_deinit() if you want to de-initialize VPN interface.
 * @see vpnsvc_up()
 * @see vpnsvc_deinit()
 */
int vpnsvc_down(vpnsvc_h handle);


#ifdef __cplusplus
}
#endif // __cplusplus

/**
* @}
*/

#endif /* __TIZEN_CAPI_VPN_SERVICE_H__ */





