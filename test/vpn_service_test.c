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

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>

#include "capi_vpn_service_private.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "VPNSVC_TEST"

#define TEST_VPN_IF_NAME "vpnsvc_test"

#define TEST_CONSOLE_PRINT(FMT, ARG...) fprintf(stderr, FMT, ##ARG); \
	fprintf(stderr, "\n")
#define TEST_CONSOLE_INPUT(BUFFER, LENGTH) \
	do {\
	if (fgets(BUFFER, sizeof BUFFER, stdin) == NULL) \
		perror("fgets() failed!!!");\
	} while (0);

vpnsvc_tun_h handle = NULL;

int test_vpnsvc_init()
{
	char *name = TEST_VPN_IF_NAME;
	int ret = VPNSVC_ERROR_NONE;

	printf("test vpnsvc_init\n");

	ret = vpnsvc_init(name, &handle);

	if (ret != VPNSVC_ERROR_NONE) {
		printf("vpnsvc_init failed : %d\n", ret);
	} else {
		char result_name[VPNSVC_TUN_IF_NAME_LEN] = {0, };
		printf("vpnsvc_init Succeed : %d\n", ret);

		printf("tun_fd : %d\n", vpnsvc_get_tun_fd(handle));
		printf("tun_index : %d\n", vpnsvc_get_tun_index(handle));
		ret = vpnsvc_get_tun_name(handle, result_name);
		if (ret == VPNSVC_ERROR_NONE)
			printf("tun_name : %s\n", result_name);
	}

	return 0;
}

int test_vpnsvc_deinit()
{
	printf("test vpnsvc_deinit\n");

	if (handle)
		vpnsvc_deinit(handle);

	handle = NULL;

	return 0;

}

int test_vpnsvc_protect()
{
	int sock, ret;

	printf("test vpnsvc_protect\n");

	if (!handle) {
		printf("invalid handle\n");
		return -1;
	}

	if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		printf("socket failed\n");
		return -2;
	}

	ret = vpnsvc_protect(handle, sock, "wlan0");
	if (ret != VPNSVC_ERROR_NONE)
		printf("vpnsvc_protect failed!\n");
	else
		printf("vpnsvc_protect Succeed!\n");

	close(sock);

	return 0;
}

int test_vpnsvc_up()
{
	int ret;
	char local[VPNSVC_IP4_STRING_LEN] = {'\0',};
	char remote[VPNSVC_IP4_STRING_LEN] = {'\0',};
	struct vpnsvc_route routes[2];
	int nr_routes = 2;
	const char *dns_server[2];
	int nr_dns = 2;
	char dns_suffix[100] = "tizen.org";

	if (!handle) {
		printf("invalid handle\n");
		return -1;
	}

	strncpy(local, "192.168.0.82", VPNSVC_IP4_STRING_LEN);
	strncpy(remote, "192.168.0.1", VPNSVC_IP4_STRING_LEN);

	memset(routes, 0, sizeof(routes));
	strncpy(routes[0].dest, "192.168.0.10", VPNSVC_IP4_STRING_LEN);
	routes[0].prefix = 32;
	strncpy(routes[1].dest, "192.168.0.11", VPNSVC_IP4_STRING_LEN);
	routes[1].prefix = 32;

	char *dns1 = "1.1.1.1";
	char *dns2 = "2.2.2.2";

	dns_server[0] = dns1;
	dns_server[1] = dns2;

	ret = vpnsvc_up(handle, local, remote, routes, nr_routes, dns_server, nr_dns, dns_suffix);
	if (ret != VPNSVC_ERROR_NONE)
		printf("vpnsvc_up failed!\n");
	else
		printf("vpnsvc_up Succeed!\n");

	return 0;
}

int test_vpnsvc_down()
{
	int ret;

	if (!handle) {
		printf("invalid handle\n");
		return -1;
	}

	ret = vpnsvc_down(handle);

	if (ret != VPNSVC_ERROR_NONE)
		printf("vpnsvc_down failed!\n");
	else
		printf("vpnsvc_down Succeed!\n");

	return 0;

}

int test_vpnsvc_read()
{
	return 0;
}

int test_vpnsvc_write()
{
	return 0;
}

int test_vpnsvc_block_networks()
{
	struct vpnsvc_route block_nets[2];
	int block_nr_nets = 2;
	struct vpnsvc_route allow_nets[2];
	int allow_nr_nets = 2;
	int ret;

	if (!handle) {
		printf("invalid handle\n");
		return -1;
	}

	memset(block_nets, 0, sizeof(block_nets));
	strncpy(block_nets[0].dest, "125.209.222.141", VPNSVC_IP4_STRING_LEN);
	block_nets[0].prefix = 32;
	strncpy(block_nets[1].dest, "180.70.134.19", VPNSVC_IP4_STRING_LEN);
	block_nets[1].prefix = 32;

	memset(allow_nets, 0, sizeof(allow_nets));
	strncpy(allow_nets[0].dest, "216.58.221.142", VPNSVC_IP4_STRING_LEN); /* google.com */
	allow_nets[0].prefix = 32;
	strncpy(allow_nets[1].dest, "206.190.36.45", VPNSVC_IP4_STRING_LEN); /* yahoo.com */
	allow_nets[1].prefix = 32;

	ret = vpnsvc_block_networks(handle, block_nets, block_nr_nets, allow_nets, allow_nr_nets);

	if (ret != VPNSVC_ERROR_NONE)
		printf("vpnsvc_block_networks failed!\n");
	else
		printf("vpnsvc_block_networks Succeed!\n");

	return 0;

}

int test_vpnsvc_unblock_networks()
{
	int ret;

	if (!handle) {
		printf("invalid handle\n");
		return -1;
	}

	ret = vpnsvc_unblock_networks(handle);

	if (ret != VPNSVC_ERROR_NONE)
		printf("vpnsvc_unblock_networks failed!\n");
	else
		printf("vpnsvc_unblock_networks Succeed!\n");

	return 0;
}

int test_vpnsvc_set_mtu()
{
	int ret;

	ret = vpnsvc_set_mtu(handle, 9000);

	if (ret != VPNSVC_ERROR_NONE)
		printf("vpnsvc_set_mtu failed!\n");
	else
		printf("vpnsvc_set_mtu Succeed!\n");

	return 0;
}

bool g_blocking = false;

int test_vpnsvc_set_blocking()
{
	int ret;
	g_blocking = !g_blocking;

	printf("Blocking Parameter: %s\n", g_blocking ? "true" : "false");
	ret = vpnsvc_set_blocking(handle, g_blocking);

	if (ret != VPNSVC_ERROR_NONE)
		printf("vpnsvc_set_blocking failed!\n");
	else
		printf("vpnsvc_set_blocking Succeed!\n");

	return 0;
}

int test_vpnsvc_set_session()
{
	int ret;
	char *set_session = "vpnsvc_test VPN Session";
	char get_session[VPNSVC_SESSION_STRING_LEN];

	ret = vpnsvc_set_session(handle, set_session);

	if (ret != VPNSVC_ERROR_NONE) {
		printf("vpnsvc_set_session failed!\n");
	} else {
		ret = vpnsvc_get_session(handle, get_session);
		printf("Session Name = %s\n", get_session);
		printf("vpnsvc_set_session Succeed!\n");
	}

	return 0;
}

int test_exit()
{
	exit(0);
}


int (*test_function_table[])(void) = {
	test_vpnsvc_init,
	test_vpnsvc_deinit,
	test_vpnsvc_protect,
	test_vpnsvc_up,
	test_vpnsvc_down,
	test_vpnsvc_read,
	test_vpnsvc_write,
	test_vpnsvc_block_networks,
	test_vpnsvc_unblock_networks,
	test_vpnsvc_set_mtu,
	test_vpnsvc_set_blocking,
	test_vpnsvc_set_session,
	test_exit,
};

int main()
{
	char input[3] = {0,};

	printf("capi_vpn_service test\n");
	while (1) {
		__fpurge(stdin);
		printf("1  : vpnsvc_init\n");
		printf("2  : vpnsvc_deinit\n");
		printf("3  : vpnsvc_protect\n");
		printf("4  : vpnsvc_up\n");
		printf("5  : vpnsvc_down\n");
		printf("6  : vpnsvc_read\n");
		printf("7  : vpnsvc_write\n");
		printf("8  : vpnsvc_block_networks\n");
		printf("9  : vpnsvc_unblock_networks\n");
		printf("10 : vpnsvc_set_mtu\n");
		printf("11 : vpnsvc_set_blocking\n");
		printf("12 : vpnsvc_set_session\n");
		printf("q  : quit\n");

		TEST_CONSOLE_INPUT(input, 3);
		unsigned int comm = strtoul(input, NULL, 0);
		if (comm <= 0 || comm > (sizeof(test_function_table) / sizeof(int))) {
			if (input[0] == 'q') {
				test_exit();
				return 0;
			}

			printf("Invalid index. Retry\n");
			continue;
		}

		test_function_table[comm-1]();
	}
	return 0;
}
