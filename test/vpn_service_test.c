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

vpnsvc_h handle = NULL;

static const char *test_print_error(vpnsvc_error_e error)
{
	switch (error) {
	case VPNSVC_ERROR_NONE:
		return "VPNSVC_ERROR_NONE";
	case VPNSVC_ERROR_INVALID_PARAMETER:
		return "VPNSVC_ERROR_INVALID_PARAMETER";
	case VPNSVC_ERROR_OUT_OF_MEMORY:
		return "VPNSVC_ERROR_OUT_OF_MEMORY";
	case VPNSVC_ERROR_PERMISSION_DENIED:
		return "VPNSVC_ERROR_PERMISSION_DENIED";
	case VPNSVC_ERROR_NO_SUCH_FILE:
		return "VPNSVC_ERROR_NO_SUCH_FILE";
	case VPNSVC_ERROR_IO_ERROR:
		return "VPNSVC_ERROR_IO_ERROR";
	case VPNSVC_ERROR_TIMEOUT:
		return "VPNSVC_ERROR_TIMEOUT";
	case VPNSVC_ERROR_IPC_FAILED:
		return "VPNSVC_ERROR_IPC_FAILED";
	case VPNSVC_ERROR_NOT_SUPPORTED:
		return "VPNSVC_ERROR_NOT_SUPPORTED";
	default:
		return "VPNSVC_ERROR_UNKNOWN";
	}
}

int test_vpnsvc_init()
{
	char *name = TEST_VPN_IF_NAME;
	int rv = VPNSVC_ERROR_NONE;
	int int_value;

	rv = vpnsvc_init(name, &handle);

	if (rv != VPNSVC_ERROR_NONE) {
		printf("vpnsvc initialize fail [%s]\n", test_print_error(rv));
		return -1;
	} else {
		char* result_name = NULL;

		if (vpnsvc_get_iface_fd(handle, &int_value) == VPNSVC_ERROR_NONE)
			printf("iface_fd : %d\n", int_value);
		else
			printf("Fail to get iface_fd\n");

		if (vpnsvc_get_iface_index(handle, &int_value) == VPNSVC_ERROR_NONE)
			printf("iface_index : %d\n", int_value);
		else
			printf("Fail to get iface_index\n");

		if (vpnsvc_get_iface_name(handle, &result_name) == VPNSVC_ERROR_NONE)
			printf("iface_name : %s\n", result_name);
		else
			printf("Fail to get iface_name\n");
	}

	printf("vpnsvc initialize success\n");
	return 1;
}

int test_vpnsvc_deinit()
{
	int rv = 0;

	if (handle)
		rv = vpnsvc_deinit(handle);
	else {
		printf("cannot deinitialize : handle is NULL\n");
		rv = VPNSVC_ERROR_INVALID_PARAMETER;
	}

	if (rv != VPNSVC_ERROR_NONE) {
		printf("vpnsvc deinitialize fail [%s]\n", test_print_error(rv));
		return -1;
	}

	handle = NULL;
	printf("vpnsvc deinitialize success\n");
	return 1;
}

int test_vpnsvc_protect()
{
	int sock, rv;

	if (!handle) {
		printf("invalid handle\n");
		return -1;
	}

	if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		printf("socket failed\n");
		return -2;
	}

	rv = vpnsvc_protect(handle, sock, "wlan0");
	if (rv != VPNSVC_ERROR_NONE)
		printf("vpnsvc protect fail [%s]\n", test_print_error(rv));
	else
		printf("vpnsvc protect success\n");

	close(sock);

	return 1;
}

int test_vpnsvc_up()
{
	int rv;
	char local[VPNSVC_IP4_STRING_LEN] = {'\0',};
	char remote[VPNSVC_IP4_STRING_LEN] = {'\0',};
	char *routes[2];
	int prefix[2];
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

	routes[0] = malloc(sizeof(char) * VPNSVC_IP4_STRING_LEN);
	routes[1] = malloc(sizeof(char) * VPNSVC_IP4_STRING_LEN);

	memset(routes[0], 0, sizeof(char) * VPNSVC_IP4_STRING_LEN);
	memset(routes[1], 0, sizeof(char) * VPNSVC_IP4_STRING_LEN);

	strncpy(routes[0], "192.168.0.10", VPNSVC_IP4_STRING_LEN);
	prefix[0] = 32;

	strncpy(routes[1], "192.168.0.11", VPNSVC_IP4_STRING_LEN);
	prefix[1] = 32;

	char *dns1 = "1.1.1.1";
	char *dns2 = "2.2.2.2";

	dns_server[0] = dns1;
	dns_server[1] = dns2;

	rv = vpnsvc_up(handle, local, remote, routes, prefix, nr_routes, dns_server, nr_dns, dns_suffix);

	free(routes[0]);
	free(routes[1]);

	routes[0] = NULL;
	routes[1] = NULL;

	if (rv != VPNSVC_ERROR_NONE)
		printf("vpnsvc up fail [%s]\n", test_print_error(rv));
	else
		printf("vpnsvc up success\n");

	return 1;
}

int test_vpnsvc_down()
{
	int rv;

	if (!handle) {
		printf("invalid handle\n");
		return -1;
	}

	rv = vpnsvc_down(handle);
	if (rv != VPNSVC_ERROR_NONE) {
		printf("vpnsvc down fail [%s]\n", test_print_error(rv));
		return -1;
	} else {
		printf("vpnsvc down success\n");
		return 1;
	}
}

int test_vpnsvc_read()
{
	return -1;
}

int test_vpnsvc_write()
{
	return -1;
}

int test_vpnsvc_block_networks()
{
	char* block_nets[2];
	int block_prefix[2];
	int block_nr_nets = 2;
	char* allow_nets[2];
	int allow_prefix[2];
	int allow_nr_nets = 2;
	int rv;

	if (!handle) {
		printf("invalid handle\n");
		return -1;
	}

	block_nets[0] = malloc(sizeof(char) * VPNSVC_IP4_STRING_LEN);
	block_nets[1] = malloc(sizeof(char) * VPNSVC_IP4_STRING_LEN);
	memset(block_nets[0], 0, sizeof(char) * VPNSVC_IP4_STRING_LEN);
	memset(block_nets[1], 0, sizeof(char) * VPNSVC_IP4_STRING_LEN);
	strncpy(block_nets[0], "125.209.222.141", VPNSVC_IP4_STRING_LEN);
	block_prefix[0] = 32;
	strncpy(block_nets[1], "180.70.134.19", VPNSVC_IP4_STRING_LEN);
	block_prefix[1] = 32;

	allow_nets[0] = malloc(sizeof(char) * VPNSVC_IP4_STRING_LEN);
	allow_nets[1] = malloc(sizeof(char) * VPNSVC_IP4_STRING_LEN);
	memset(allow_nets[0], 0, sizeof(char) * VPNSVC_IP4_STRING_LEN);
	memset(allow_nets[1], 0, sizeof(char) * VPNSVC_IP4_STRING_LEN);
	strncpy(allow_nets[0], "216.58.221.142", VPNSVC_IP4_STRING_LEN);
	allow_prefix[0] = 32;
	strncpy(allow_nets[1], "206.190.36.45", VPNSVC_IP4_STRING_LEN);
	allow_prefix[1] = 32;

	rv = vpnsvc_block_networks(handle, block_nets, block_prefix, block_nr_nets, allow_nets, allow_prefix, allow_nr_nets);

	free(block_nets[0]);
	free(block_nets[1]);
	free(allow_nets[0]);
	free(allow_nets[1]);

	block_nets[0] = NULL;
	block_nets[1] = NULL;
	allow_nets[0] = NULL;
	allow_nets[1] = NULL;

	if (rv != VPNSVC_ERROR_NONE) {
		printf("vpnsvc block networks fail [%s]\n", test_print_error(rv));
		return -1;
	} else {
		printf("vpnsvc block networks success\n");
		return 1;
	}
}

int test_vpnsvc_unblock_networks()
{
	int rv;

	if (!handle) {
		printf("invalid handle\n");
		return -1;
	}

	rv = vpnsvc_unblock_networks(handle);
	if (rv != VPNSVC_ERROR_NONE) {
		printf("vpnsvc unblock networks fail [%s]\n", test_print_error(rv));
		return -1;
	} else {
		printf("vpnsvc unblock networks success");
		return 1;
	}
}

int test_vpnsvc_set_mtu()
{
	int rv;

	rv = vpnsvc_set_mtu(handle, 9000);
	if (rv != VPNSVC_ERROR_NONE) {
		printf("vpnsvc set mtu fail [%s]\n", test_print_error(rv));
		return -1;
	} else {
		printf("vpnsvc set mtu success\n");
		return 1;
	}
}

bool g_blocking = false;

int test_vpnsvc_set_blocking()
{
	int rv;
	g_blocking = !g_blocking;

	printf("Blocking Parameter: %s\n", g_blocking ? "true" : "false");
	rv = vpnsvc_set_blocking(handle, g_blocking);

	if (rv != VPNSVC_ERROR_NONE) {
		printf("vpnsvc set blocking fail [%s]\n", test_print_error(rv));
		return -1;
	} else {
		printf("vpnsvc set blocking success\n");
		return 1;
	}
}

int test_vpnsvc_set_session()
{
	int rv;
	char *set_session = "vpnsvc_test VPN Session";
	char *get_session = NULL;

	rv = vpnsvc_set_session(handle, set_session);

	if (rv != VPNSVC_ERROR_NONE) {
		printf("vpnsvc set session fail [%s]\n", test_print_error(rv));
		return -1;
	} else {
		rv = vpnsvc_get_session(handle, &get_session);
		printf("session name = %s\n", get_session);
		printf("vpnsvc set session Success\n");
		return 1;
	}
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

		int rv = test_function_table[comm-1]();
		if (rv == 1)
			printf("Operation succeeded!\n");
		else
			printf("Operation failed!\n");
	}
	return 0;
}
