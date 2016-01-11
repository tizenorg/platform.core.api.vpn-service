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


#ifndef __TIZEN_CAPI_VPN_SERVICE_DAEMON_H__
#define __TIZEN_CAPI_VPN_SERVICE_DAEMON_H__

#include "capi_vpn_service_private.h"

int vpn_daemon_init(const char* tun_name, size_t tun_name_len, int fd, vpnsvc_tun_s *handle_s);
int vpn_daemon_deinit(const char* dev_name);
int vpn_daemon_protect(int socket, const char* dev_name);
int vpn_daemon_up(int tun_index, const char* local_ip, const char* remote_ip,
						const char** routes, int prefix[], size_t nr_routes,
						char** dns_servers, size_t nr_dns, size_t total_dns_string_cnt,
						const char* dns_suffix, const unsigned int mtu);
int vpn_daemon_down(int tun_index);
int vpn_daemon_block_networks(const char** nets_vpn, int prefix_vpn[], size_t nr_nets_vpn,
		const char** nets_orig, int prefix_orig[], size_t nr_nets_orig);
int vpn_daemon_unblock_networks(void);

#endif /* __TIZEN_CAPI_VPN_SERVICE_DAEMON_H__ */
