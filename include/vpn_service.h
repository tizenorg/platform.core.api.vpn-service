/*
* Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef __TIZEN_VPN_SERVICE_H__
#define __TIZEN_VPN_SERVICE_H__

#include <tizen.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @file vpn_service.h
 */

/**
 * @addtogroup	CAPI_NETWORK_VPN_SERVICE_MODULE
 * @{
 */

/**
  * @brief IPv4 address string length (includes end null character).
  * @since_tizen 3.0
  */
#define VPNSVC_IP4_STRING_LEN 16

/**
  * @brief VPN interface name length.
  * @since_tizen 3.0
  */
#define VPNSVC_VPN_IFACE_NAME_LEN 16

/**
  * @brief Session name string length (includes end null character).
  * @since_tizen 3.0
  */
#define VPNSVC_SESSION_STRING_LEN 32

/**
  * @brief   Enumeration for VPN service error types.
  * @details Indicate formats of error type field
  */
typedef enum
{
    VPNSVC_ERROR_NONE = TIZEN_ERROR_NONE,                            /**< Successful */
    VPNSVC_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER,  /**< Invalid parameter */
    VPNSVC_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY,          /**< Out of memory */
    VPNSVC_ERROR_PERMISSION_DENIED = TIZEN_ERROR_PERMISSION_DENIED,  /**< Permission denied */
    VPNSVC_ERROR_NO_SUCH_FILE = TIZEN_ERROR_NO_SUCH_FILE,            /**< No such file or directory */
    VPNSVC_ERROR_IO_ERROR = TIZEN_ERROR_IO_ERROR,                    /**< IO error */
    VPNSVC_ERROR_TIMEOUT = TIZEN_ERROR_TIMED_OUT,                    /**< Time out error or no answer */
    VPNSVC_ERROR_IPC_FAILED = TIZEN_ERROR_VPNSVC | 0x02,             /**< Failed to communicate with server */
    VPNSVC_ERROR_NOT_SUPPORTED = TIZEN_ERROR_NOT_SUPPORTED           /**< Not Supported */
} vpnsvc_error_e;


/**
  * @brief   The VPN interface handle.
  * @details This handle can be obtained by calling vpnsvc_init() and destroyed by calling vpnsvc_deinit().
  * @since_tizen 3.0
  * @see vpnsvc_init()
  * @see vpnsvc_deinit()
  */
typedef void* vpnsvc_h;

/**
 * @brief  Initializes VPN interface.
 * @detail You should call vpnsvc_get_iface_name() for checking the actual initialized VPN interface name. (In case of duplicated interface name)
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/vpnservice \n
 *            %http://tizen.org/privilege/internet
 * @remarks The @a handle should be released using vpnsvc_deinit().
 * @param[in] iface_name The VPN interface name
 * @param[out] handle  The VPN interface handle
 * @return 0 on success. otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_IO_ERROR              I/O Error (e.g. socket I/O error)
 * @retval #VPNSVC_ERROR_IPC_FAILED            Cannot connect to service daemon
 * @retval #VPNSVC_ERROR_PERMISSION_DENIED     Permission Denied
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @post Please call vpnsvc_deinit() if you want to de-initialize VPN interface.
 * @post Please call vpnsvc_get_iface_fd() if you want to know the fd(file descriptor) of VPN interface.
 * @post Please call vpnsvc_get_iface_index() if you want to know the index of VPN interface.
 * @post Please call vpnsvc_get_iface_name() if you want to know the name of VPN interface.
 * @see vpnsvc_deinit()
 * @see vpnsvc_get_iface_fd()
 * @see vpnsvc_get_iface_index()
 * @see vpnsvc_get_iface_name()
 */
int vpnsvc_init(const char* iface_name, vpnsvc_h *handle);

/**
 * @brief De-Initializes VPN interface.
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/vpnservice \n
 *            %http://tizen.org/privilege/internet
 * @param[in] handle The VPN interface handle
 * @return 0 on success. otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_IPC_FAILED            Cannot connect to service daemon
 * @retval #VPNSVC_ERROR_PERMISSION_DENIED     Permission Denied
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @pre Before calling this function, VPN interface should be initialized already.
 * @see vpnsvc_init()
 */
int vpnsvc_deinit(vpnsvc_h handle);

/**
 * @brief Protect a socket from VPN connections.
 * @details After protecting, data sent through this socket will go directly to the underlying network.
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/vpnservice \n
 *            %http://tizen.org/privilege/internet
 * @param[in] handle    The VPN interface handle
 * @param[in] socket_fd The opened socket file descriptor
 * @param[in] iface_name  The network interface name (e.g., interface name such as eth0, ppp0, etc) through which the VPN is working
 * @return 0 on success. otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_IO_ERROR              I/O Error (e.g. socket I/O error)
 * @retval #VPNSVC_ERROR_IPC_FAILED            Cannot connect to service daemon
 * @retval #VPNSVC_ERROR_PERMISSION_DENIED     Permission Denied
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 */
int vpnsvc_protect(vpnsvc_h handle, int socket_fd, const char* iface_name);

/**
 * @brief Waits for the read event on VPN interface descriptor, but no more than the indicated timeout in milliseconds.
 * @since_tizen 3.0
 * @param[in] handle      The VPN interface handle
 * @param[in] timeout_ms  The value of timeout (milliseconds)
 * @return 0 on success. otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_IO_ERROR              I/O Error (e.g. socket I/O error)
 * @retval #VPNSVC_ERROR_TIMEOUT               Timeout (no answer in timeout_ms)
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @pre The VPN interface should be initialized already.
 * @see vpnsvc_init()
 */
int vpnsvc_read(vpnsvc_h handle, int timeout_ms);

/**
 * @brief Writes the data supplied into the VPN interface.
 * @since_tizen 3.0
 * @param[in] handle The VPN interface handle
 * @param[in] data   Data writing to VPN interface
 * @param[in] size   The size of data
 * @return On success, the number of bytes written is returned (zero indicates nothing was written). Otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @retval In case of negative error, please refer to standard posix write API's error code.
 * @pre The VPN interface should be initialized already.
 * @see vpnsvc_init()
 */
int vpnsvc_write(vpnsvc_h handle, const char* data, size_t size);

/**
 * @brief Blocks all traffics except specified allowing networks.
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/vpnservice \n
 *            %http://tizen.org/privilege/internet
 * @param[in] handle                  The VPN interface handle
 * @param[in] routes_dest_vpn_addr    Destination address of the routes, the list of allowing networks over VPN interface (e.g., VPN interface such as tun0, etc).
 * @param[in] routes_vpn_prefix       The prefix of VPN interface, netmask length (also called a prefix, e.g. 8, 16, 24, 32).
 * @param[in] num_allow_routes_vpn    The number of allowing networks over VPN interface
 * @param[in] routes_dest_orig_addr   Destination address of the routes, the list of allowing networks over the original interface (e.g., original interface such as eth0, wlan0, etc).
 * @param[in] routes_orig_prefix      The prefix of Original interface, netmask length (also called a prefix, e.g. 8, 16, 24, 32).
 * @param[in] num_allow_routes_orig   The number of allowing networks over the original interface
 * @return 0 on success. otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_IPC_FAILED            Cannot connect to service daemon
 * @retval #VPNSVC_ERROR_PERMISSION_DENIED     Permission Denied
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @post Please call vpnsvc_unblock_networks() if you want to allow all traffics.
 * @see vpnsvc_unblock_networks()
 */
int vpnsvc_block_networks(vpnsvc_h handle,
		char *routes_dest_vpn_addr[],
		int routes_vpn_prefix[],
		size_t num_allow_routes_vpn,
		char *routes_dest_orig_addr[],
		int routes_orig_prefix[],
		size_t num_allow_routes_orig);

/**
 * @brief Removes any restrictions imposed by vpnsvc_block_networks().
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/vpnservice \n
 *            %http://tizen.org/privilege/internet
 * @param[in] handle The VPN interface handle
 * @return 0 on success. otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_IPC_FAILED            Cannot connect to service daemon
 * @retval #VPNSVC_ERROR_PERMISSION_DENIED     Permission Denied
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 */
int vpnsvc_unblock_networks(vpnsvc_h handle);

/**
 * @brief Gets the fd of the VPN interface.
 * @since_tizen 3.0
 * @param[in] handle The VPN interface handle
 * @param[out] iface_fd The vpn interface fd
 * @return The fd value of VPN interface. Otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 */
int vpnsvc_get_iface_fd(vpnsvc_h handle, int* iface_fd);

/**
 * @brief Gets the index of VPN interface.
 * @since_tizen 3.0
 * @param[in] handle The VPN interface handle
 * @param[out] iface_index The VPN interface index
 * @return The index of the VPN interface. otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @pre Before calling this function, VPN interface should be initialized already.
 * @see vpnsvc_init()
 */
int vpnsvc_get_iface_index(vpnsvc_h handle, int* iface_index);

/**
 * @brief Gets the name of VPN interface.
 * @since_tizen 3.0
 * @remarks The @a iface_name should be released using free()
 * @param[in] handle    The VPN interface handle
 * @param[out] iface_name The name of VPN interface name
 * @return 0 on success. Otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @pre Before calling this function, VPN interface should be initialized already.
 * @see vpnsvc_init()
 */
int vpnsvc_get_iface_name(vpnsvc_h handle, char** iface_name);

/**
 * @brief Sets the MTU of the VPN interface.
 * @since_tizen 3.0
 * @param[in] handle The VPN interface handle
 * @param[in] mtu    The MTU (Maximum Transmission Unit) value to be set for VPN interface. Default MTU size is 1500.
 * @return 0 on success. Otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @pre Before calling this function, VPN interface should be initialized already.
 * @see vpnsvc_init()
 */
int vpnsvc_set_mtu(vpnsvc_h handle, int mtu);

/**
 * @brief Sets blocking mode of the file descriptor of VPN interface.
 * @since_tizen 3.0
 * @param[in] handle    The VPN interface handle
 * @param[in] blocking  The blocking mode flag; True = BLOCKING, False = NON_BLOCKING (Default : BLOCKING)
 * @return 0 on success. Otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_IO_ERROR              Failed to set the blocking flags
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @pre Before calling this function, VPN interface should be initialized already.
 * @see vpnsvc_init()
 */
int vpnsvc_set_blocking(vpnsvc_h handle, bool blocking);

/**
 * @brief Sets the session name for the VPN. (It will be displayed in system-managed dialogs and notifications.)
 * @since_tizen 3.0
 * @param[in] handle       The VPN interface handle
 * @param[in] session      The Session Name
 * @return 0 on success. Otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @pre Before calling this function, VPN interface should be initialized already.
 * @see vpnsvc_init()
 */
int vpnsvc_set_session(vpnsvc_h handle, const char* session);

/**
 * @brief Gets the session name for the VPN.
 * @since_tizen 3.0
 * @remarks The @a session should be released using free()
 * @param[in] handle   The VPN interface handle
 * @param[out] session The Session Name returned
 * @return 0 on success. Otherwise, a negative error value.
 * @retval #VPNSVC_ERROR_NONE                  Success
 * @retval #VPNSVC_ERROR_INVALID_PARAMETER     Invalid parameter
 * @retval #VPNSVC_ERROR_NOT_SUPPORTED         Not Supported
 * @pre Before calling this function, VPN interface should be initialized already.
 * @see vpnsvc_init()
 */
int vpnsvc_get_session(vpnsvc_h handle, char** session);

/**
* @}
*/

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* __TIZEN_CAPI_VPN_SERVICE_H__ */
