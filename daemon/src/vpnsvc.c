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
#include <unistd.h>
#include <dlog/dlog.h>
#include <gio/gunixfdlist.h>

#include "vpnsvc.h"
#include "vpndbus.h"
#include "vpn_service_daemon.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "VPNSVC_DAEMON"

static Vpnsvc *vpnsvc = NULL;

/*********************
 * Handler Functions *
 ********************/
gboolean handle_vpn_init(Vpnsvc *object,
								GDBusMethodInvocation *invocation,
								const gchar *arg_tun_name,
								guint arg_tun_name_len)
{
	LOGD("handle_vpn_init");

	vpnsvc_tun_s handle_s;
	int result = VPNSVC_ERROR_NONE;
	GDBusMessage *msg;
	GUnixFDList *fd_list;
	int fd_list_length;
	const int *fds;

	LOGD("vpn_init, %s, %u\n", arg_tun_name, arg_tun_name_len);

	msg = g_dbus_method_invocation_get_message(invocation);
	fd_list = g_dbus_message_get_unix_fd_list(msg);
	fds = g_unix_fd_list_peek_fds(fd_list, &fd_list_length);

	if (fd_list_length <= 0)
		LOGD("D-Bus Message doesn't contain any fd!");

	LOGD("fd:%d\n", *fds);

	result = vpn_daemon_init(arg_tun_name, arg_tun_name_len, *fds, &handle_s);

	LOGD("handle_s.fd : %d, handle_s.index : %d, handle_s.name : %s",
			handle_s.fd, handle_s.index, handle_s.name);

	vpnsvc_complete_vpn_init(object, invocation, result, handle_s.index, handle_s.name);

	return TRUE;
}

gboolean handle_vpn_deinit(Vpnsvc *object,
									GDBusMethodInvocation *invocation,
									const gchar *arg_dev_name)
{
	int result = VPNSVC_ERROR_NONE;

	LOGD("handle_vpn_deinit");
	LOGD("vpn_deinit, %s\n", arg_dev_name);

	result = vpn_daemon_deinit(arg_dev_name);

	vpnsvc_complete_vpn_deinit(object, invocation, result);

	return TRUE;
}

gboolean handle_vpn_protect(Vpnsvc *object,
									GDBusMethodInvocation *invocation,
									const gchar *arg_dev_name)
{
	int result = VPNSVC_ERROR_NONE;
	int socket;
	GDBusMessage *msg;
	GUnixFDList *fd_list;
	int fd_list_length;
	const int *fds;

	LOGD("handle_vpn_protect");

	msg = g_dbus_method_invocation_get_message(invocation);
	fd_list = g_dbus_message_get_unix_fd_list(msg);
	fds = g_unix_fd_list_peek_fds(fd_list, &fd_list_length);
	if (fd_list_length <= 0)
		LOGD("D-Bus Message doesn't contain any fd!");

	socket = *fds;
	LOGD("vpn_protect, %d, %s\n", socket, arg_dev_name);

	result = vpn_daemon_protect(socket, arg_dev_name);

	vpnsvc_complete_vpn_protect(object, invocation, result);

	return TRUE;
}

gboolean handle_vpn_up(Vpnsvc *object,
								GDBusMethodInvocation *invocation,
								gint arg_tun_index,
								const gchar *arg_local_ip,
								const gchar *arg_remote_ip,
								GVariant *arg_routes,
								guint arg_nr_routes,
								GVariant *arg_dns_servers,
								guint arg_nr_dns,
								const gchar *arg_dns_suffix,
								guint arg_mtu)
{
	int result = VPNSVC_ERROR_NONE;

	LOGD("handle_vpn_up");

	char* routes[arg_nr_routes];
	int prefix[arg_nr_routes];
	char **dns_servers = NULL;

	unsigned int i = 0;
	size_t total_dns_string_cnt = 0;
	gchar* temp_dns_server;
	GVariantIter iter;

	gchar* route_dest;
	gint route_prefix;

	LOGD("tun_index : %d", arg_tun_index);
	LOGD("local ip : %s", arg_local_ip);
	LOGD("remote ip : %s", arg_remote_ip);
	LOGD("dns_suffix : %s", arg_dns_suffix);
	LOGD("mtu : %u", arg_mtu);
	LOGD("arg_routes: %p", arg_routes);
	LOGD("nr_routes : %u", arg_nr_routes);
	LOGD("arg_dns_servers: %p", arg_dns_servers);
	LOGD("nr_dns : %u", arg_nr_dns);

	/* arg_routes check */
	if (arg_nr_routes > 0) {
		if (arg_routes != NULL) {
			GVariant *dict = g_variant_get_variant(arg_routes);
			g_variant_iter_init(&iter, dict);
			i = 0;
			while (g_variant_iter_loop(&iter, "{si}", &route_dest, &route_prefix)) {
				int temp_dest_str_len = strlen(route_dest);
				routes[i] = malloc((sizeof(char) * temp_dest_str_len)+1);
				memset(routes[i], 0, sizeof(char) * temp_dest_str_len);
				strncpy(routes[i], route_dest, temp_dest_str_len);
				routes[i][temp_dest_str_len] = '\0';
				prefix[i] = route_prefix;
				LOGD("routes[%d] = %s \t", i, (routes[i] == NULL) ? "" : routes[i]);
				LOGD("prefix[%d] = %d ", i, prefix[i]);
				i++;
			}
		}
	}


	/* arg_nr_dns check */
	if (arg_nr_dns > 0) {
		if (arg_dns_servers != NULL) {
			GVariant *array = g_variant_get_variant(arg_dns_servers);
			dns_servers = (char **)malloc(arg_nr_dns*sizeof(char *));
			if (dns_servers == NULL) {
				LOGE("malloc failed.");
				result = VPNSVC_ERROR_OUT_OF_MEMORY;
				goto done;
			}
			g_variant_iter_init(&iter, array);
			i = 0;
			while (g_variant_iter_loop(&iter, "s", &temp_dns_server)) {
				int temp_dns_str_len = strlen(temp_dns_server);
				dns_servers[i] = (char *)malloc((temp_dns_str_len+1)*sizeof(char));
				strncpy(dns_servers[i], temp_dns_server, strlen(temp_dns_server));
				dns_servers[i][temp_dns_str_len] = '\0';
				total_dns_string_cnt += temp_dns_str_len;
				LOGD("dns_servers[%d] : %s", i, (dns_servers[i] == NULL) ? "" : dns_servers[i]);
				i++;
			}
		}
	}

	result = vpn_daemon_up(arg_tun_index, arg_local_ip, arg_remote_ip,
			routes, prefix, arg_nr_routes, dns_servers, arg_nr_dns,
			total_dns_string_cnt, arg_dns_suffix, arg_mtu);
done:
	/* free pointers */
	if (dns_servers) {
		for (i = 0; i < arg_nr_dns; i++) {
			if (dns_servers[i])
				free(dns_servers[i]);
		}
		free(dns_servers);
	}

	vpnsvc_complete_vpn_up(object, invocation, result);

	return TRUE;
}

gboolean handle_vpn_down(Vpnsvc *object,
									GDBusMethodInvocation *invocation,
									gint arg_tun_index)
{
	LOGD("handle_vpn_down");
	int result = VPNSVC_ERROR_NONE;

	LOGD("vpn_down, %d\n", arg_tun_index);

	result = vpn_daemon_down(arg_tun_index);

	vpnsvc_complete_vpn_down(object, invocation, result);

	return TRUE;
}

gboolean handle_vpn_block_networks(Vpnsvc *object,
											GDBusMethodInvocation *invocation,
											GVariant *arg_nets_vpn,
											guint arg_nr_nets_vpn,
											GVariant *arg_nets_orig,
											guint arg_nr_nets_orig)
{
	LOGD("handle_vpn_block_networks");
	int result = VPNSVC_ERROR_NONE;

	char *nets_vpn[arg_nr_nets_vpn];
	int prefix_vpn[arg_nr_nets_vpn];

	char *nets_orig[arg_nr_nets_vpn];
	int prefix_orig[arg_nr_nets_vpn];

	int i = 0;
	GVariantIter iter;
	gchar* route_dest;
	gint route_prefix;

	LOGD("vpn_block_networks");

	/* arg_nets_vpn check */
	if (arg_nr_nets_vpn > 0) {
		if (arg_nets_vpn != NULL) {
			GVariant *dict_nets_vpn = g_variant_get_variant(arg_nets_vpn);
			g_variant_iter_init(&iter, dict_nets_vpn);
			i = 0;
			while (g_variant_iter_loop(&iter, "{si}", &route_dest, &route_prefix)) {
				int tmp_route_len = strlen(route_dest);
				nets_vpn[i] = malloc(sizeof(char) * tmp_route_len + 1);
				memset(nets_vpn[i], 0, sizeof(char) * tmp_route_len);
				strncpy(nets_vpn[i], route_dest, tmp_route_len);
				nets_vpn[i][tmp_route_len] = '\0';
				prefix_vpn[i] = route_prefix;
				LOGD("nets_vpn[%d] = %s prefix_vpn[%d] = %d", i,i, (nets_vpn[i] == NULL) ? "" : nets_vpn[i], prefix_vpn[i]);
				i++;
			}
		}
	}

	/* arg_nets_orig check */
	if (arg_nr_nets_orig > 0) {
		if (arg_nets_orig != NULL) {
			GVariant *dict_nets_orig = g_variant_get_variant(arg_nets_orig);
			g_variant_iter_init(&iter, dict_nets_orig);
			i = 0;
			while (g_variant_iter_loop(&iter, "{si}", &route_dest, &route_prefix)) {
				int tmp_route_len = strlen(route_dest);
				nets_orig[i] = malloc(sizeof(char) * tmp_route_len + 1);
				memset(nets_orig[i], 0, sizeof(char) * tmp_route_len);
				strncpy(nets_orig[i], route_dest, tmp_route_len);
				nets_orig[i][tmp_route_len] = '\0';
				prefix_orig[i] = route_prefix;
				LOGD("nets_orig[%d] = %s prefix_orig[%d] = %d", i, i, (nets_orig[i] == NULL) ? "" : nets_orig[i], prefix_orig[i]);
				i++;
			}
		}
	}

	/* call function */
	result = vpn_daemon_block_networks(nets_vpn, prefix_vpn, arg_nr_nets_vpn, nets_orig, prefix_orig, arg_nr_nets_orig);

	vpnsvc_complete_vpn_block_networks(object, invocation, result);

	return TRUE;
}

gboolean handle_vpn_unblock_networks(Vpnsvc *object,
											GDBusMethodInvocation *invocation)
{
	int result = VPNSVC_ERROR_NONE;

	LOGD("handle_vpn_unblock_networks");
	LOGD("vpn_unblock_networks");

	result = vpn_daemon_unblock_networks();

	vpnsvc_complete_vpn_unblock_networks(object, invocation, result);

	return TRUE;
}

/*****************************
 * Initializations Functions *
 ****************************/
Vpnsvc *get_vpnsvc_object(void)
{
	return vpnsvc;
}

void vpnsvc_create_and_init(void)
{
	LOGD("Create vpn object.");
	GDBusInterfaceSkeleton *interface = NULL;
	GDBusConnection *connection;
	GDBusObjectManagerServer *server = vpnsvc_get_vpn_manager();
	if (server == NULL)
		return;

	connection = vpnsvc_gdbus_get_connection();
	g_dbus_object_manager_server_set_connection(server, connection);

	/* Interface */
	vpnsvc = vpnsvc_skeleton_new();
	interface = G_DBUS_INTERFACE_SKELETON(vpnsvc);

	/* VPN Service */
	g_signal_connect(vpnsvc, "handle-vpn-init",
			G_CALLBACK(handle_vpn_init), NULL);
	g_signal_connect(vpnsvc, "handle-vpn-deinit",
			G_CALLBACK(handle_vpn_deinit), NULL);
	g_signal_connect(vpnsvc, "handle-vpn-protect",
			G_CALLBACK(handle_vpn_protect), NULL);
	g_signal_connect(vpnsvc, "handle-vpn-up",
			G_CALLBACK(handle_vpn_up), NULL);
	g_signal_connect(vpnsvc, "handle-vpn-down",
			G_CALLBACK(handle_vpn_down), NULL);
	g_signal_connect(vpnsvc, "handle-vpn-block-networks",
			G_CALLBACK(handle_vpn_block_networks), NULL);
	g_signal_connect(vpnsvc, "handle-vpn-unblock-networks",
			G_CALLBACK(handle_vpn_unblock_networks), NULL);

	if (!g_dbus_interface_skeleton_export(interface, connection,
			VPNSERVICE_PATH, NULL)) {
		LOGE("Export VPNSERVICE_PATH for vpn failed");
	}

	return;
}

