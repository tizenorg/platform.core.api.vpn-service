/*
 * Copyright (c) 2014-2015 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef __TIZEN_NETWORK_VPN_H__
#define __TIZEN_NETWORK_VPN_H__

#include <tizen.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
* @addtogroup CAPI_NETWORK_VPN_MANAGER_MODULE
* @{
*/

/**
 * @brief The handle for vpn.
 */
typedef void *vpn_h;
typedef void *vpn_settings_h;

/**
* @brief The VPN error type
*/
typedef enum {
	VPN_ERROR_NONE = TIZEN_ERROR_NONE, /**< Successful */
	VPN_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER, /**< Invalid parameter */
	VPN_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY, /**< Out of memory error */
	VPN_ERROR_INVALID_OPERATION = TIZEN_ERROR_INVALID_OPERATION, /**< Invalid operation */
	VPN_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED = TIZEN_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED, /**< Address family not supported */
	VPN_ERROR_OPERATION_FAILED = TIZEN_ERROR_NETWORK_CLASS|0x0301, /**< Operation failed */
	VPN_ERROR_NO_CONNECTION = TIZEN_ERROR_NETWORK_CLASS|0x0302, /**< There is no connected AP */
	VPN_ERROR_NOW_IN_PROGRESS = TIZEN_ERROR_NOW_IN_PROGRESS, /** Now in progress */
	VPN_ERROR_ALREADY_EXISTS = TIZEN_ERROR_NETWORK_CLASS|0x0303, /**< Already exists */
	VPN_ERROR_OPERATION_ABORTED = TIZEN_ERROR_NETWORK_CLASS|0x0304, /**< Operation is aborted */
	VPN_ERROR_DHCP_FAILED = TIZEN_ERROR_NETWORK_CLASS|0x0306, /**< DHCP failed */
	VPN_ERROR_INVALID_KEY = TIZEN_ERROR_NETWORK_CLASS|0x0307, /**< Invalid key */
	VPN_ERROR_NO_REPLY = TIZEN_ERROR_NETWORK_CLASS|0x0308, /**< No reply */
	VPN_ERROR_SECURITY_RESTRICTED = TIZEN_ERROR_NETWORK_CLASS|0x0309, /**< Restricted by security system policy */
} vpn_error_e;

/**
* @}
*/

/**
* @addtogroup CAPI_NETWORK_VPN_MONITOR_MODULE
* @{
*/

/**
* @brief Called after vpn_create() is completed.
* @param[in] result  The result
* @param[in] user_data The user data passed from vpn_create()
* @pre vpn_create() will invoke this callback function.
* @see vpn_create()
*/
typedef void(*vpn_created_cb)(vpn_error_e result, void *user_data);

/**
* @brief Called after vpn_remove() is completed.
* @param[in] result  The result
* @param[in] user_data The user data passed from vpn_remove()
* @pre vpn_remove() will invoke this callback function.
* @see vpn_remove()
*/
typedef void(*vpn_removed_cb)(vpn_error_e result, void *user_data);
/**
* @}
*/

/**
* @brief Called after vpn_connect() is completed.
* @param[in] result  The result
* @param[in] user_data The user data passed from vpn_connect()
* @pre vpn_connect() will invoke this callback function.
* @see vpn_connect()
*/
typedef void(*vpn_connect_cb)(vpn_error_e result, void *user_data);

/**
* @brief Called after vpn_disconnect() is completed.
* @param[in] result  The result
* @param[in] user_data The user data passed from vpn_disconnect()
* @pre vpn_disconnect() will invoke this callback function.
* @see vpn_disconnect()
*/
typedef void(*vpn_disconnect_cb)(vpn_error_e result, void *user_data);
/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_VPN_MODULE
* @{
*/

/**
* @brief Initializes VPN
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
*/
int vpn_initialize(void);

/**
* @brief Deinitializes VPN
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
*/
int vpn_deinitialize(void);

/**
* @}
*/

/**
* @addtogroup CAPI_NETWORK_VPN_SETTINGS
* @{
*/

/**
* @brief Initializes VPN Settings
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
* @see vpn_settings_deinit()
*/
int vpn_settings_init();

/**
* @brief De-Initializes VPN Settings
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
* @pre vpn_settings_init() Must be called before deinit
* @see vpn_settings_deinit()
*/
int vpn_settings_deinit();

/**
* @brief Sets VPN Specific Settings
* @param[in] key  The Key for the Settings
* @param[in] value The Value for the Settings
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @pre vpn_settings_init() must be  called before calling this API
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
* @see vpn_settings_deinit()
*/
int vpn_settings_set_specific(const char *key, const char *value);

/**
* @brief Sets VPN Type
* @param[in] type  The VPN Settings Type
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @pre vpn_settings_init() must be  called before calling this API
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
* @see vpn_settings_deinit() vpn_settings_init()
*/
int vpn_settings_set_type(const char *type);

/**
* @brief Sets VPN Profile Name
* @param[in] name  The VPN Settings Name
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @pre vpn_settings_init() must be  called before calling this API
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
* @see vpn_settings_deinit() vpn_settings_init()
*/
int vpn_settings_set_name(const char *name);

/**
* @brief Sets VPN Profile Host (Name or Address)
* @param[in] host  The VPN Settings Host
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @pre vpn_settings_init() must be  called before calling this API
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
* @see vpn_settings_deinit() vpn_settings_init()
*/
int vpn_settings_set_host(const char *host);

/**
* @brief Sets VPN Profile Domain
* @param[in] domain  The VPN Settings Domain
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @pre vpn_settings_init() must be  called before calling this API
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
* @see vpn_settings_deinit() vpn_settings_init()
*/
int vpn_settings_set_domain(const char *domain);

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_VPN_MANAGER_MODULE
* @{
*/

/**
* @brief Create VPN Profile, asynchronously.
* @param[in] settings  The VPN related Settings Handler, This can't be NULL.
* @param[in] callback  The callback function to be called.
*   This can be NULL if you don't want to get the notification.
* @param[in] user_data The user data passed to the callback function
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
* @retval #VPN_ERROR_SECURITY_RESTRICTED  Restricted by security system policy
* @post vpn_created_cb() will be invoked
* @see vpn_settings()
* @see vpn_created_cb()
* @see vpn_remove()
*/
int vpn_create(vpn_created_cb callback, void *user_data);

/**
* @brief Remove VPN Profile, asynchronously.
* @param[in] handle  The VPN Connection Identifier.
* @param[in] callback  The callback function to be called.
*   This can be NULL if you don't want to get the notification.
* @param[in] user_data The user data passed to the callback function
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
* @post vpn_removed_cb() will be invoked
* @see vpn_removed_cb()
* @see vpn_create()
*/
int vpn_remove(vpn_h handle, vpn_removed_cb callback, void *user_data);

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_VPN_CONNECTION_MODULE
* @{
*/

/**
* @brief Connect to a VPN Profile, asynchronously.
* @param[in] settings  The VPN related Settings Handler, This can't be NULL.
* @param[in] callback  The callback function to be called.
*   This can be NULL if you don't want to get the notification.
* @param[in] user_data The user data passed to the callback function
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
* @retval #VPN_ERROR_ALREADY_EXISTS  Restricted by security system policy
* @see vpn_connect_cb()
* @see vpn_disconnect()
*/
int vpn_connect(vpn_h handle, vpn_connect_cb callback, void *user_data);

/**
* @brief Disconnect from VPN Profile, asynchronously.
* @param[in] handle  The VPN Connection Identifier.
* @param[in] callback  The callback function to be called.
*   This can be NULL if you don't want to get the notification.
* @param[in] user_data The user data passed to the callback function
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_OPERATION_FAILED  Operation failed
* @retval #VPN_ERROR_NO_CONNECTION  No Connection
* @see vpn_disconnect_cb()
* @see vpn_connect()
*/
int vpn_disconnect(vpn_h handle, vpn_disconnect_cb callback, void *user_data);

/**
* @brief Gets the VPN Handle List.
* @return Valid GList Pointer on success, otherwise NULL.
* @see vpn_get_vpn_handle()
*/
GList *vpn_get_vpn_handle_list(void);

/**
* @brief Get Specific VPN Handle based on host & domain.
* @param[in] host  The VPN Host Identifier.
* @param[in] domain  The VPN Domain Identifier.
* @param[out] handle The VPN handle that matches host & domain.
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_INVALID_PARAMETER  Operation failed
* @see vpn_get_vpn_handle_list()
*/
int vpn_get_vpn_handle(const char *host, const char *domain, vpn_h *handle);

/**
* @brief Get VPN Info (Name)
* @param[in] handle The VPN handle for the Request
* @param[out] name  Name of the VPN
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_INVALID_PARAMETER  Operation failed
*/
int vpn_get_vpn_info_name(const vpn_h handle, const char **name);

/**
* @brief Get VPN Info (Type)
* @param[in] handle The VPN handle for the Request
* @param[out] type  Type of the VPN
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_INVALID_PARAMETER  Operation failed
*/
int vpn_get_vpn_info_type(const vpn_h handle, const char **type);

/**
* @brief Get VPN Info (Host)
* @param[in] handle The VPN handle for the Request
* @param[out] host  Host of the VPN
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_INVALID_PARAMETER  Operation failed
*/
int vpn_get_vpn_info_host(const vpn_h handle, const char **host);

/**
* @brief Get VPN Info (Domain)
* @param[in] handle The VPN handle for the Request
* @param[out] domain  Domain of the VPN
* @return 0 on success, otherwise negative error value.
* @retval #VPN_ERROR_NONE  Successful
* @retval #VPN_ERROR_INVALID_OPERATION  Invalid operation
* @retval #VPN_ERROR_INVALID_PARAMETER  Operation failed
*/
int vpn_get_vpn_info_domain(const vpn_h handle, const char **domain);

/**
* @}
*/

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_NETWORK_VPN_H__ */
