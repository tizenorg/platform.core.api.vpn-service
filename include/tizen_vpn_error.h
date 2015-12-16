/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __TIZEN_COMMON_VPN_ERROR_H__
#define __TIZEN_COMMON_VPN_ERROR_H__

#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup CAPI_COMMON_VPN_ERROR Common VPN Error
 * @brief This file provides error codes that are common for the whole TIZEN VPN API.
 * @section CAPI_COMMON_VPN_ERROR_HEADER Required Header
 *   \#include <tizen_vpn_error.h>
 * @ingroup CAPI_COMMON_ERROR
 * @{
 */

#define TIZEN_ERROR_MIN_VPN_ERROR (-268435456) /* = -268435455(0x0FFFFFFF) -1 */

/* Check if slp error or not */
#define TIZEN_ERROR_IS_VPN_ERROR(x) (TIZEN_ERROR_MIN_VPN_ERROR >= (x) && (x) < 0)

/* Tizen VPN Service Error */
#define TIZEN_ERROR_VPNSVC             -0x10000000

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif         /**<__TIZEN_COMMON_VPN_ERROR_H__ */
