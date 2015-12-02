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

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <assert.h>
#include <vpn.h>
#include <tizen_error.h>

gboolean test_thread(GIOChannel *source,
			GIOCondition condition,
			gpointer data);

static const char *__test_convert_error_to_string(vpn_error_e err_type)
{
	switch (err_type) {
	case VPN_ERROR_NONE:
		return "NONE";
	case VPN_ERROR_INVALID_PARAMETER:
		return "INVALID_PARAMETER";
	case VPN_ERROR_OUT_OF_MEMORY:
		return "OUT_OF_MEMORY";
	case VPN_ERROR_INVALID_OPERATION:
		return "INVALID_OPERATION";
	case VPN_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED:
		return "ADDRESS_FAMILY_NOT_SUPPORTED";
	case VPN_ERROR_OPERATION_FAILED:
		return "OPERATION_FAILED";
	case VPN_ERROR_NO_CONNECTION:
		return "NO_CONNECTION";
	case VPN_ERROR_NOW_IN_PROGRESS:
		return "NOW_IN_PROGRESS";
	case VPN_ERROR_ALREADY_EXISTS:
		return "ALREADY_EXISTS";
	case VPN_ERROR_OPERATION_ABORTED:
		return "OPERATION_ABORTED";
	case VPN_ERROR_DHCP_FAILED:
		return "DHCP_FAILED";
	case VPN_ERROR_INVALID_KEY:
		return "INVALID_KEY";
	case VPN_ERROR_NO_REPLY:
		return "NO_REPLY";
	case VPN_ERROR_SECURITY_RESTRICTED:
		return "SECURITY_RESTRICTED";
	}

	return "UNKNOWN";
}

static void __test_created_callback(vpn_error_e result,
				void *user_data)
{
	if (result == VPN_ERROR_NONE)
		printf("VPN Create Succeeded\n");
	else
		printf("VPN Create Failed! error : %s",
				__test_convert_error_to_string(result));
}

static void __test_removed_callback(vpn_error_e result,
				void *user_data)
{
	if (result == VPN_ERROR_NONE)
		printf("VPN Remove Succeeded\n");
	else
		printf("VPN Remove Failed! error : %s",
				__test_convert_error_to_string(result));
}

static void __test_connect_callback(vpn_error_e result,
				void *user_data)
{
	if (result == VPN_ERROR_NONE)
		printf("VPN Connect Succeeded\n");
	else
		printf("VPN Connect Failed! error : %s",
				__test_convert_error_to_string(result));
}

static void __test_disconnect_callback(vpn_error_e result,
				void *user_data)
{
	if (result == VPN_ERROR_NONE)
		printf("VPN Disconnect Succeeded\n");
	else
		printf("VPN Disconnect Failed! error : %s",
				__test_convert_error_to_string(result));
}

static void _test_get_vpn_handle(vpn_h *handle_ptr)
{
	assert(handle_ptr != NULL);

	char host_str[128] = { 0 };
	char domain_str[128] = { 0 };
	const char *name = NULL;
	const char *type = NULL;
	const char *host = NULL;
	const char *domain = NULL;

	GList *iter;
	GList *handles = vpn_get_vpn_handle_list();
	for (iter = handles; iter != NULL; iter = iter->next) {
		printf("\n Handle = %p\n", iter->data);
		vpn_get_vpn_info_name(iter->data, &name);
		vpn_get_vpn_info_type(iter->data, &type);
		vpn_get_vpn_info_host(iter->data, &host);
		vpn_get_vpn_info_domain(iter->data, &domain);
		printf(" Name[%p] - %s\n", iter->data, name);
		printf(" Type[%p] - %s\n", iter->data, type);
		printf(" Host[%p] - %s\n", iter->data, host);
		printf(" Domain[%p] - %s\n", iter->data, domain);
	}

	printf("==================================\n");
	printf(" Please ENTER Host: ");
	if (scanf(" %s", host_str) < 0)
		printf("Error in Reading Host String\n");

	printf(" Please ENTER Domain: ");
	if (scanf(" %s", domain_str) < 0)
		printf("Error in Reading Domain String\n");

	vpn_get_vpn_handle(host_str, domain_str, handle_ptr);
}

static void _test_get_user_input(char *buf, char *what)
{
	printf("Please ENTER %s:", what);
	if (scanf(" %[^\n]s", buf) < 0) {
		printf("Error in Reading the data to Buffer\n");
	}
}

int test_vpn_init(void)
{
	int rv = vpn_initialize();

	if (rv == VPN_ERROR_NONE) {
		printf("Register Callbacks if Initialize is Successful\n");
	} else {
		printf("VPN init failed [%s]\n",
			__test_convert_error_to_string(rv));
		return -1;
	}

	printf("VPN init succeeded\n");
	return 1;
}

int test_vpn_deinit(void)
{
	int rv = vpn_deinitialize();

	if (rv != VPN_ERROR_NONE) {
		printf("VPN init failed [%s]\n",
			__test_convert_error_to_string(rv));
		return -1;
	}

	printf("VPN deinit succeeded\n");
	return 1;
}

int test_vpn_settings_init(void)
{
	int rv = 0;

	rv = vpn_settings_init();

	if (rv != VPN_ERROR_NONE) {
		printf("Fail to Initialize Settings [%s]\n",
				__test_convert_error_to_string(rv));
		return -1;
	}

	printf("Success Creating Settings API's\n");

	return 1;
}

int test_vpn_settings_add(void)
{
	int rv = 0;
	char buf[100];

	_test_get_user_input(&buf[0], "Type");
	rv = vpn_settings_set_type(&buf[0]);
	if (rv != VPN_ERROR_NONE) {
		printf("Fail to VPN Settings Type[%s]\n",
				__test_convert_error_to_string(rv));
		return -1;
	}

	_test_get_user_input(&buf[0], "Name");
	rv = vpn_settings_set_name(&buf[0]);
	if (rv != VPN_ERROR_NONE) {
		printf("Fail to VPN Settings Name[%s]\n",
				__test_convert_error_to_string(rv));
		return -1;
	}

	_test_get_user_input(&buf[0], "Host");
	rv = vpn_settings_set_host(&buf[0]);
	if (rv != VPN_ERROR_NONE) {
		printf("Fail to VPN Settings Host[%s]\n",
				__test_convert_error_to_string(rv));
		return -1;
	}

	_test_get_user_input(&buf[0], "Domain");
	rv = vpn_settings_set_domain(&buf[0]);
	if (rv != VPN_ERROR_NONE) {
		printf("Fail to VPN Settings Domain[%s]\n",
				__test_convert_error_to_string(rv));
		return -1;
	}

	printf("Success Creating Settings API's\n");

	return 1;
}

int test_vpn_settings_deinit(void)
{
	int rv = 0;

	rv = vpn_settings_deinit();

	if (rv != VPN_ERROR_NONE) {
		printf("Fail to Deinitialize Settings [%s]\n",
				__test_convert_error_to_string(rv));
		return -1;
	}

	printf("Success Deleting Settings API's\n");

	return 1;
}

int test_vpn_settings_set_specific(void)
{
	int rv = 0;
	char key[100];
	char value[200];

	_test_get_user_input(&key[0], "Key");
	_test_get_user_input(&value[0], "Value");
	rv = vpn_settings_set_specific(&key[0], &value[0]);
	if (rv != VPN_ERROR_NONE) {
		printf("Fail to Set Specific VPN Settings %s[%s]\n",
				key, __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Success in VPN Settings Add %s=%s\n", key, value);

	return 1;
}

int test_vpn_create(void)
{
	int rv = 0;

	rv = vpn_create(__test_created_callback, NULL);

	if (rv != VPN_ERROR_NONE) {
		printf("Fail to Create VPN Profile [%s]\n",
				__test_convert_error_to_string(rv));
		return -1;
	}

	printf("Success to Create VPN Profile\n");

	return 1;
}

int test_vpn_remove(void)
{
	int rv = 0;

	/*TODO: Get the List of VPN Profiles Identifiers
	 * Prompt user to which one to be deleted */

	rv = vpn_remove(NULL, __test_removed_callback, NULL);

	if (rv != VPN_ERROR_NONE) {
		printf("Fail to Remove VPN Profile [%s]\n",
				__test_convert_error_to_string(rv));
		return -1;
	}

	printf("Success to Remove VPN Profile\n");

	return 1;
}

int test_vpn_connect(void)
{
	int rv = 0;
	vpn_h handle = NULL;

	_test_get_vpn_handle(&handle);

	rv = vpn_connect(handle, __test_connect_callback, NULL);

	if (rv != VPN_ERROR_NONE) {
		printf("Fail to Connect to VPN Profile [%s]\n",
				__test_convert_error_to_string(rv));
		return -1;
	}

	printf("Success to Connect VPN Profile\n");

	return 1;
}

int test_vpn_disconnect(void)
{
	int rv = 0;
	vpn_h handle = NULL;

	_test_get_vpn_handle(&handle);

	rv = vpn_disconnect(handle, __test_disconnect_callback, NULL);

	if (rv != VPN_ERROR_NONE) {
		printf("Fail to Disconnect from VPN Profile [%s]\n",
				__test_convert_error_to_string(rv));
		return -1;
	}

	printf("Success to Disconnect VPN Profile\n");

	return 1;
}

int main(int argc, char **argv)
{
	GMainLoop *mainloop;
	mainloop = g_main_loop_new(NULL, FALSE);

	GIOChannel *channel = g_io_channel_unix_new(0);
	g_io_add_watch(channel, (G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL),
			test_thread, NULL);

	printf("Test Thread created...\n");

	g_main_loop_run(mainloop);

	return 0;
}

gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data)
{
	int rv;
	char a[10];

	printf("Event received from stdin\n");

	rv = read(0, a, 10);

	if (rv <= 0 || a[0] == '0') {
		rv = vpn_deinitialize();

		if (rv != VPN_ERROR_NONE)
			printf("Fail to deinitialize.\n");

		exit(1);
	}

	if (a[0] == '\n' || a[0] == '\r') {
		printf("\n\n Network Connection API Test App\n\n");
		printf("Options..\n");
		printf("1\t- VPN init and set callbacks\n");
		printf("2\t- VPN deinit(unset callbacks automatically)\n");
		printf("3\t- VPN Settings Initialize - Initialize Settings for Creating a VPN profile\n");
		printf("4\t- VPN Settings Delete - Delete Settings VPN profile\n");
		printf("5\t- VPN Settings Set Specific - Allows to add a specific setting\n");
		printf("6\t- VPN Settings Add - Add Type,Host,Name,Domain settings\n");
		printf("7\t- VPN Create - Creates the VPN profile\n");
		printf("8\t- VPN Remove - Removes the VPN profile\n");
		printf("9\t- VPN Connect - Connect the VPN profile\n");
		printf("a\t- VPN Disconnect - Disconnect the VPN profile\n");
		printf("0\t- Exit\n");

		printf("ENTER  - Show options menu.......\n");
	}

	switch (a[0]) {
	case '1':
		rv = test_vpn_init();
		break;
	case '2':
		rv = test_vpn_deinit();
		break;
	case '3':
		rv = test_vpn_settings_init();
		break;
	case '4':
		rv = test_vpn_settings_deinit();
		break;
	case '5':
		rv = test_vpn_settings_set_specific();
		break;
	case '6':
		rv = test_vpn_settings_add();
		break;
	case '7':
		rv = test_vpn_create();
		break;
	case '8':
		rv = test_vpn_remove();
		break;
	case '9':
		rv = test_vpn_connect();
		break;
	case 'a':
		rv = test_vpn_disconnect();
		break;
	default:
		break;
	}

	if (rv == 1)
		printf("Operation succeeded!\n");
	else
		printf("Operation failed!\n");

	return TRUE;
}


