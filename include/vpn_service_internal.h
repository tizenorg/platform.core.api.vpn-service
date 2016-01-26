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
#include <tizen_vpn_error.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @file vpn_service_internal.h
 */

/**
 * @internal
 * @brief Sets-up TUN interface and brings it up. Installs specified routes/DNS servers/DNS suffix.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/vpnservice.admin
 * @param[in] handle         The VPN tun interface handle
 * @param[in] local_ip       The local IP address
 * @param[in] remote_ip      The remote IP address
 * @param[in] dest           Destination address of the route
 * @param[in] prefix         The prefix of route
 * @param[in] nr_routes      The number of routes
 * @param[in] dns_servers    The list of DNS server names - Optional
 * @param[in] nr_dns_servers The number of DNS server names - Optionl
 * @param[in] dns_suffix     The DNS suffix - Optional
 * @return 0 on success. otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_IPC_FAILED            Cannot connect to service daemon
 * @retval #VPNSVC_ERROR_PERMISSION_DENIED     Permission Denied
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @pre The VPN tun interface should be initialized already.
 * @post If you want to set interface down, please call vpnsvc_down().
 * @see vpnsvc_init()
 * @see vpnsvc_down()
 */
API int vpnsvc_up(vpnsvc_tun_h handle, const char* local_ip, const char* remote_ip,
				const char *dest[], int prefix[], size_t nr_routes,
				const char** dns_servers, size_t nr_dns_servers,
				const char* dns_suffix);

/**
 * @internal
 * @brief Brings the TUN interface down and restores original DNS servers/domains.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/vpnservice.admin
 * @param[in] handle The VPN tun interface handle
 * @return 0 on success. otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_IPC_FAILED            Cannot connect to service daemon
 * @retval #VPNSVC_ERROR_PERMISSION_DENIED     Permission Denied
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @pre The VPN tun interface should be initialized already.
 * @post Please call vpnsvc_deinit() if you want to de-initialize VPN tun interface.
 * @see vpnsvc_up()
 * @see vpnsvc_deinit()
 */
API int vpnsvc_down(vpnsvc_tun_h handle);


#ifdef __cplusplus
}
#endif // __cplusplus

/**
* @}
*/

#endif /* __TIZEN_CAPI_VPN_SERVICE_H__ */





