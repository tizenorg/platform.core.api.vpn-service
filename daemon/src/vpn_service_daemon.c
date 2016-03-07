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


#include <errno.h>
#include <net/route.h>
#include <glib.h>
#include <gio/gio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>

#include "vpn_service_daemon.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "VPNSVC_DAEMON"
#define ERROR_BUF_SIZE 256

#define CONNMAN_SERVICE "net.connman"
#define CONNMAN_INTERFACE_MANAGER "net.connman.Manager"
#define CONNMAN_INTERFACE_SERVICE "net.connman.Service"


/* for iptables */
static char iptables_cmd[] = "/usr/sbin/iptables";
static char iptables_filter_prefix[] = "CAPI_VPN_SERVICE_";
static char iptables_filter_out[] = "OUTPUT";
static char iptables_filter_in[] = "INPUT";
static char iptables_filter_interface_wlan[] = "wlan0";
/* static char iptables_register_fmt[] = "%s -N %s%s -w;" "%s -F %s%s -w;" "%s -A %s%s -j RETURN -w;" "%s -I %s -j %s%s -w;"; */
static char iptables_register_fmt[] = "%s -N %s%s -w;" "%s -F %s%s -w;" "%s -A %s%s -j DROP -w;" "%s -A %s%s -j RETURN -w;" "%s -I %s -j %s%s -w;";
static char iptables_unregister_fmt[] = "%s -D %s -j %s%s -w;" "%s -F %s%s -w;" "%s -X %s%s -w;";
static char iptables_rule_fmt[] = "%s -%c %s%s -%c %s/%d -j ACCEPT -w;";
static char iptables_rule_with_interface_fmt[] = "%s -%c %s%s -%c %s -%c %s/%d -j ACCEPT -w;";
/*static char iptables_usage_fmt[] = "%s -L %s%s -n -v -w;";*/

typedef unsigned long int ipv4;	/* Declare variable type for ipv4 net address. */

static GDBusConnection *global_connection = NULL;

static ipv4 make_mask(int prefix)
{
	ipv4 mask = 0;
	int i = 0;

	for (i = prefix; i > 0; i--)
		mask += (ipv4) (1 << (32 - i));
	return mask;
}

static in_addr_t host2net(ipv4 host)
{
	in_addr_t net;

	net = 0;

	net |= (host & 0x000000FF) << 24;
	net |= (host & 0x0000FF00) <<  8;
	net |= (host & 0x00FF0000) >>  8;
	net |= (host & 0xFF000000) >> 24;

	return net;
}

static int add_routes(char* iface_name, const char* routes[], int prefix[], size_t nr_routes)
{
	struct rtentry rt;
	struct sockaddr_in addr;
	int sk;
	unsigned int i = 0;
	char buf[ERROR_BUF_SIZE];

	LOGD("Enter add_routes");

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		LOGE("socket failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		return VPNSVC_ERROR_IO_ERROR;
	}

	for (i = 0; i < nr_routes; i++) {
		memset(&rt, 0, sizeof(rt));
		rt.rt_flags = RTF_UP;

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr(routes[i]);
		memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		memcpy(&rt.rt_gateway, &addr, sizeof(rt.rt_gateway));

		/* set mask using by prefix length */
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_addr.s_addr = host2net(make_mask(prefix[i]));
		memcpy(&rt.rt_genmask, &addr, sizeof(rt.rt_genmask));

		rt.rt_dev = iface_name;

		if (ioctl(sk, SIOCADDRT, &rt) < 0) {
			LOGE("ioctl SIOCADDRT failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
			close(sk);
			return VPNSVC_ERROR_IO_ERROR;
		}
	}

	close(sk);

	return VPNSVC_ERROR_NONE;
}

static void connman_connection_open(void)
{
	if (global_connection == NULL) {
		GError *error = NULL;
#if !GLIB_CHECK_VERSION(2, 36, 0)
		g_type_init();
#endif

		global_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
		if (global_connection == NULL) {
			if (error != NULL) {
				LOGE("Error connman connection open: %s", error->message);
				g_error_free(error);
			}
		}
	}
}

static void connman_connection_close(GDBusConnection *connection)
{
	if (connection)
		g_object_unref(connection);
}

static GVariant *connman_method_call(
	GDBusConnection *connection, char *service, char *path,
	char *interface, char *method, GVariant *params)
{
	GError *error = NULL;
	GVariant *message = NULL;

	message = g_dbus_connection_call_sync(
		connection, service, path, interface, method, params,
		NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (message == NULL) {
		if (error != NULL) {
			LOGE("error: g_dbus_connection_call_sync [%d: %s]", error->code, error->message);
			g_error_free(error);
		} else {
			LOGE("error: g_dbus_connection_call_sync\n");
		}
	}

	return message;
}

static char *connman_default_profile(GDBusConnection *connection)
{
	gchar *key = NULL;
	GVariantIter *value = NULL;
	GVariant *message = NULL;
	GVariantIter *iter = NULL;
	char *profile = NULL;

	message = connman_method_call(connection, CONNMAN_SERVICE, "/",
								  CONNMAN_INTERFACE_MANAGER, "GetServices", NULL);

	if (message) {
		g_variant_get(message, "(a(oa{sv}))", &iter);
		while (g_variant_iter_loop(iter, "(oa{sv})", &key, &value)) {
			profile = strdup(key);
			break;
		}

		if (value)
			g_variant_iter_free(value);
		if (key)
			g_free(key);

		g_variant_iter_free(iter);
		g_variant_unref(message);
	}

	return profile;
}

static char *connman_get_items(GDBusConnection *connection, char *profile, const char *keystr)
{
	GVariant *message = NULL;
	GVariantIter *iter = NULL;
	GVariantIter *next = NULL;
	gchar *obj = NULL;
	char *items = NULL;
	unsigned int tmp_items_len;

	message = connman_method_call(connection, CONNMAN_SERVICE, "/",
								  CONNMAN_INTERFACE_MANAGER, "GetServices", NULL);

	if (message) {
		g_variant_get(message, "(a(oa{sv}))", &iter);
		while (g_variant_iter_loop(iter, "(oa{sv})", &obj, &next)) {
			if (strcmp(obj, profile) == 0) {
				GVariant *var;
				gchar *key;

				while (g_variant_iter_loop(next, "{sv}", &key, &var)) {
					if (g_strcmp0(key, keystr) == 0) {
						GVariantIter *iter_item;
						const gchar *value = NULL;

						g_variant_get(var, "as", &iter_item);
						while (g_variant_iter_loop(iter_item, "s", &value)) {
							if (items) {
								char *tmp_items;

								tmp_items = (char *) malloc(strlen(items) + 1 + strlen(value) + 1);
								tmp_items_len = strlen(tmp_items);
								if (items) {
									sprintf(tmp_items, tmp_items_len, "%s,%s", items, value);
									free(items);
									items = tmp_items;
								}
							} else {
								items = strdup(value);
							}
						}
						g_variant_iter_free(iter_item);
						break;
					}
				}
				break;
			}
		}
		g_variant_iter_free(iter);
		g_variant_unref(message);
	}

	return items;
}

static void connman_set_items(GDBusConnection *connection, char *profile,
							  const char *keystr, char *items)
{
	GVariant *message = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *params = NULL;
	char *strings = strdup(items);
	char *addr = NULL;
	char *saveptr1, *saveptr2;

	builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
	if ((addr = strtok_r(strings, ", ", &saveptr1)) != NULL) {
		do {
			g_variant_builder_add(builder, "s", addr);
		} while ((addr = strtok_r(NULL, ", ", &saveptr2)) != NULL);
	}
	free(strings);
	params = g_variant_new("(sv)", keystr,
						   g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	message = connman_method_call(connection, CONNMAN_SERVICE, profile,
								  CONNMAN_INTERFACE_SERVICE, "SetProperty", params);
	if (message)
		g_variant_unref(message);

}

static char *connman_get_nameservers(GDBusConnection *connection, char *profile)
{
	return connman_get_items(connection, profile, "Nameservers");
}

static char *connman_get_nameservers_conf(GDBusConnection *connection, char *profile)
{
	return connman_get_items(connection, profile, "Nameservers.Configuration");
}

static void connman_set_nameservers(GDBusConnection *connection, char *profile,
									char *nameservers)
{
	return connman_set_items(connection, profile,
							 "Nameservers.Configuration", nameservers);
}

static char *connman_get_domains(GDBusConnection *connection, char *profile)
{
	return connman_get_items(connection, profile, "Domains");
}

static char *connman_get_domains_conf(GDBusConnection *connection, char *profile)
{
	return connman_get_items(connection, profile, "Domains.Configuration");
}

static void connman_set_domains(GDBusConnection *connection, char *profile,
									char *domains)
{
	return connman_set_items(connection, profile,
							 "Domains.Configuration", domains);
}

static int add_dns_servers(char** dns_servers, size_t nr_dns, size_t total_dns_string_cnt)
{
	char *profile = NULL;
	char *items = NULL;
	char *org_items = NULL;
	char *new_items = NULL;
	unsigned int i;
	unsigned int dns_server_len;

	connman_connection_open();
	dns_server_len = strlen(dns_servers[i]);

	profile = connman_default_profile(global_connection);
	if (profile == NULL) {
		LOGE("connman_default_profile failed");
		connman_connection_close(global_connection);
		return VPNSVC_ERROR_IPC_FAILED;
	}

	LOGD("profile : %s\n", profile);

	/* add name servers */
	org_items = connman_get_nameservers(global_connection, profile);

	if (org_items) {
		LOGD("original DNS : %s\n", org_items);
		/* nr_dns = comma(,) count */
		items = (char *) calloc((total_dns_string_cnt + nr_dns + strlen(org_items) + 1), sizeof(char));
		if (items == NULL) {
			LOGE("OOM while malloc\n");
			return VPNSVC_ERROR_OUT_OF_MEMORY;
		}
		strncpy(items, org_items, strlen(org_items));
		for (i = 0 ; i < nr_dns ; i++) {
			strncat(items, ",", 1);
			strncat(items, dns_servers[i], dns_server_len);
		}
		free(org_items);
		org_items = NULL;
	} else {
		/* nr_dns = comma(,) count + end null char */
		items = (char *) calloc(total_dns_string_cnt + nr_dns, sizeof(char));
		if (items == NULL) {
			LOGE("OOM while malloc\n");
			return VPNSVC_ERROR_OUT_OF_MEMORY;
		}
		for (i = 0 ; i < nr_dns ; i++) {
			strncat(items, dns_servers[i], dns_server_len);
			if (i != nr_dns - 1)
				strncat(items, ",", 1);
		}
	}

	if (items) {
		LOGD("adding DNS : %s\n", items);
		connman_set_nameservers(global_connection, profile, items);
		free(items);
		items = NULL;
	}

	/* print new DNSs */
	new_items = connman_get_nameservers_conf(global_connection, profile);
	LOGD("new_dns : %s\n", new_items);

	if (new_items)
		free(new_items);
	free(profile);
	return VPNSVC_ERROR_NONE;
}

static int del_dns_servers()
{
	char *profile = NULL;

	connman_connection_open();

	profile = connman_default_profile(global_connection);
	if (profile == NULL) {
		LOGE("connman_default_profile failed");
		connman_connection_close(global_connection);
		return VPNSVC_ERROR_IPC_FAILED;
	}

	LOGD("profile : %s", profile);

	/* del name servers */
	connman_set_nameservers(global_connection, profile, "");

	if (profile)
		free(profile);

	return VPNSVC_ERROR_NONE;
}

static int add_dns_suffix(const char* dns_suffix, size_t dns_suffix_len)
{
	char *profile = NULL;
	char *items = NULL;
	char *org_items = NULL;
	char *new_items = NULL;

	connman_connection_open();

	profile = connman_default_profile(global_connection);
	if (profile == NULL) {
		LOGE("connman_default_profile failed");
		connman_connection_close(global_connection);
		return VPNSVC_ERROR_IPC_FAILED;
	}

	LOGD("profile : %s", profile);

	/* add name servers */
	org_items = connman_get_domains(global_connection, profile);

	if (org_items) {
		LOGD("original DNS suffix : %s", org_items);
		/* comma(,) and end null character included */
		items = (char *) calloc((dns_suffix_len + strlen(org_items) + 2), sizeof(char));
		if (items == NULL) {
			LOGE("OOM while malloc");
			return VPNSVC_ERROR_OUT_OF_MEMORY;
		}
		strncpy(items, org_items, strlen(org_items));
		strncat(items, ",", 1);
		strncat(items, dns_suffix, dns_suffix_len);
		free(org_items);
		org_items = NULL;
	} else {
		/* nr_dns = comma(,) count + end null char */
		items = (char *) calloc((dns_suffix_len + 1), sizeof(char));
		if (items == NULL) {
			LOGE("OOM while malloc");
			return VPNSVC_ERROR_OUT_OF_MEMORY;
		}
		strncat(items, dns_suffix, dns_suffix_len);
	}

	if (items) {
		LOGD("adding DNS suffix : %s\n", items);
		connman_set_domains(global_connection, profile, items);
		free(items);
		items = NULL;
	}

	/* print new domains */
	new_items = connman_get_domains_conf(global_connection, profile);
	LOGD("new DNS suffix : %s\n", new_items);

	if (new_items)
		free(new_items);

	if (profile)
		free(profile);

	return VPNSVC_ERROR_NONE;
}

static int del_dns_suffix()
{
	char *profile = NULL;

	connman_connection_open();

	profile = connman_default_profile(global_connection);
	if (profile == NULL) {
		LOGE("connman_default_profile failed");
		connman_connection_close(global_connection);
		return VPNSVC_ERROR_IPC_FAILED;
	}

	LOGD("profile : %s", profile);

	/* del DNS suffix */
	connman_set_domains(global_connection, profile, "");

	if (profile)
		free(profile);

	return VPNSVC_ERROR_NONE;
}


static void iptables_exec(char *cmdline)
{
	FILE *fp = NULL;

	fp = popen(cmdline, "r");

	if (fp != NULL)
		pclose(fp);
}

static void iptables_register(void)
{
	int size = 0;
	char buf[8192], *filter;

	filter = iptables_filter_out;
	snprintf(buf + size, sizeof(buf) - size, iptables_register_fmt,
			 iptables_cmd, iptables_filter_prefix, filter,
			 iptables_cmd, iptables_filter_prefix, filter,
			 iptables_cmd, iptables_filter_prefix, filter,
			 iptables_cmd, iptables_filter_prefix, filter,
			 iptables_cmd, filter, iptables_filter_prefix, filter);
	size = strlen(buf);
	filter = iptables_filter_in;
	snprintf(buf + size, sizeof(buf) - size, iptables_register_fmt,
			 iptables_cmd, iptables_filter_prefix, filter,
			 iptables_cmd, iptables_filter_prefix, filter,
			 iptables_cmd, iptables_filter_prefix, filter,
			 iptables_cmd, iptables_filter_prefix, filter,
			 iptables_cmd, filter, iptables_filter_prefix, filter);
	LOGD("iptable reg cmd : %s", buf);
	iptables_exec(buf);
}

static void iptables_unregister(void)
{
	int size = 0;
	char buf[8192], *filter;

	filter = iptables_filter_out;
	snprintf(buf + size, sizeof(buf) - size, iptables_unregister_fmt,
			 iptables_cmd, filter, iptables_filter_prefix, filter,
			 iptables_cmd, iptables_filter_prefix, filter,
			 iptables_cmd, iptables_filter_prefix, filter);
	size = strlen(buf);
	filter = iptables_filter_in;
	snprintf(buf + size, sizeof(buf) - size, iptables_unregister_fmt,
			 iptables_cmd, filter, iptables_filter_prefix, filter,
			 iptables_cmd, iptables_filter_prefix, filter,
			 iptables_cmd, iptables_filter_prefix, filter);
	LOGD("iptable unreg cmd : %s", buf);
	iptables_exec(buf);
}

static void iptables_rule(const char c, const char *addr, const int mask)
{
	int size = 0;
	char buf[4096];

	snprintf(buf + size, sizeof(buf) - size, iptables_rule_fmt, iptables_cmd, c,
			 iptables_filter_prefix, iptables_filter_out, 'd', addr, mask);
	size = strlen(buf);
	snprintf(buf + size, sizeof(buf) - size, iptables_rule_fmt, iptables_cmd, c,
			 iptables_filter_prefix, iptables_filter_in, 's', addr, mask);
	LOGD("iptable cmd : %s", buf);
	iptables_exec(buf);
}

static void iptables_rule_interface(const char c, const char *addr, const int mask, const char *interface)
{
	int size = 0;
	char buf[4096];

	snprintf(buf + size, sizeof(buf) - size,
			iptables_rule_with_interface_fmt, iptables_cmd,
			c, iptables_filter_prefix, iptables_filter_out,
			'o', interface, 'd', addr, mask);
	size = strlen(buf);
	snprintf(buf + size, sizeof(buf) - size,
			iptables_rule_with_interface_fmt, iptables_cmd,
			c, iptables_filter_prefix, iptables_filter_in,
			'i', interface, 's', addr, mask);
	LOGD("iptable cmd : %s", buf);
	iptables_exec(buf);
}

void iptables_add_orig(const char *addr, const int mask)
{
	iptables_rule_interface('I', addr, mask, iptables_filter_interface_wlan);
}

void iptables_delete_orig(const char *addr, const int mask)
{
	iptables_rule_interface('D', addr, mask, iptables_filter_interface_wlan);
}

void iptables_add(const char *addr, const int mask)
{
	iptables_rule('I', addr, mask);
}

void iptables_delete(const char *addr, const int mask)
{
	iptables_rule('D', addr, mask);
}

static int get_interface_index(const char *iface_name)
{
	struct ifreq ifr;
	int sk = 0;
	char buf[ERROR_BUF_SIZE];

	LOGD("enter get_interface_index, iface_name : %s", iface_name);

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		LOGE("socket failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		return VPNSVC_ERROR_IO_ERROR;
	}

	memset(&ifr, 0, sizeof(ifr));

	if (*iface_name)
	strncpy(ifr.ifr_name, iface_name, strlen(iface_name));

	/* get an interface name by ifindex */
	if (ioctl(sk, SIOCGIFINDEX, &ifr) < 0) {
		LOGE("ioctl SIOCGIFINDEX failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(sk);
		return VPNSVC_ERROR_IO_ERROR;
	}

	close(sk);

	return ifr.ifr_ifindex;
}


int vpn_daemon_init(const char* iface_name, size_t iface_name_len, int fd, vpnsvc_tun_s *handle_s)
{
	struct ifreq ifr;
	size_t len = 0;
	char buf[ERROR_BUF_SIZE];

	LOGD("enter vpn_daemon_init, iface_name : %s, iface_name_len : %d, fd : %d\n", iface_name, iface_name_len, fd);

	memset(&ifr, 0, sizeof(ifr));

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	*		IFF_TAP   - TAP device
	*
	*		IFF_NO_PI - Do not provide packet information
	*/

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (*iface_name)
		strncpy(ifr.ifr_name, iface_name, iface_name_len);

	LOGD("before init, ifindex : %d", ifr.ifr_ifindex);

	if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
		LOGE("TUNSETIFF Failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(fd);
		return VPNSVC_ERROR_IO_ERROR;
	}

	if (ioctl(fd, TUNSETOWNER, 5000) < 0) {
		LOGE("TUNSETOWNER Failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(fd);
		return VPNSVC_ERROR_IO_ERROR;
	}

	if (ioctl(fd, TUNSETPERSIST, 1) < 0) {
		LOGE("TUNSETPERSIST Failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(fd);
		return VPNSVC_ERROR_IO_ERROR;
	}

	handle_s->fd = 0;   /* server fd does not meaning */
	handle_s->index = get_interface_index(iface_name);
	len = strlen(ifr.ifr_name);
	strncpy(handle_s->name, ifr.ifr_name, len);
	handle_s->name[len] = '\0';

	return VPNSVC_ERROR_NONE;
}

int vpn_daemon_deinit(const char* dev_name)
{
	char buf[100];
	FILE *fp = NULL;

	snprintf(buf, sizeof(buf), "/usr/sbin/ip link del %s", dev_name);
	LOGD("link delete cmd : %s", buf);

	fp = popen(buf, "r");
	if (fp != NULL) {
		pclose(fp);
		return VPNSVC_ERROR_NONE;
	} else {
		return VPNSVC_ERROR_IO_ERROR;
	}
}

int vpn_daemon_protect(int socket_fd, const char* dev_name)
{
	int ret = VPNSVC_ERROR_NONE;
	char buf[ERROR_BUF_SIZE];
	LOGD("enter vpn_daemon_protect, socket : %d, dev_name : %s\n", socket_fd, dev_name);

	ret = setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE,
					dev_name, strlen(dev_name));

	if (ret < 0) {
		LOGD("setsockopt failed : %d, %s", ret, strerror_r(errno, buf, ERROR_BUF_SIZE));
		ret = VPNSVC_ERROR_IO_ERROR;
	} else {
		ret = VPNSVC_ERROR_NONE;
	}

	return ret;
}

int vpn_daemon_up(int iface_index, const char* local_ip, const char* remote_ip,
						const char* routes[], int prefix[], size_t nr_routes,
						char** dns_servers, size_t nr_dns, size_t total_dns_string_cnt,
						const char* dns_suffix, const unsigned int mtu) {

	struct sockaddr_in local_addr;
	struct sockaddr_in remote_addr;
	struct ifreq ifr_tun;
	int sk;
	int ret = VPNSVC_ERROR_NONE;
	char buf[ERROR_BUF_SIZE];

	LOGD("enter vpn_daemon_up");

	LOGD("iface_index : %d", iface_index);
	LOGD("local ip : %s", local_ip);
	LOGD("remote ip : %s", remote_ip);
	LOGD("route pointer : %p, nr_routes : %d, dns_server pointer : %p, nr_dns : %d, dns_suffix : %s, mtu : %d", routes, nr_routes, dns_servers, nr_dns, dns_suffix, mtu);


	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		LOGE("socket failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		return VPNSVC_ERROR_IO_ERROR;
	}

	memset(&ifr_tun, 0, sizeof(ifr_tun));
	ifr_tun.ifr_ifindex = iface_index;

	/* get an interface name by ifindex */
	if (ioctl(sk, SIOCGIFNAME, &ifr_tun) < 0) {
		LOGE("ioctl SIOCGIFNAME failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(sk);
		return VPNSVC_ERROR_IO_ERROR;
	}

	/* local ip setting */
	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sin_addr.s_addr = inet_addr(local_ip); /* network byte order */
	local_addr.sin_family = AF_INET;
	memcpy(&ifr_tun.ifr_addr, &local_addr, sizeof(ifr_tun.ifr_addr));
	if (ioctl(sk, SIOCSIFADDR, &ifr_tun) < 0) {
		LOGE("ioctl SIOCSIFADDR failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(sk);
		return VPNSVC_ERROR_IO_ERROR;
	}

	/* remote ip setting */
	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_addr.s_addr = inet_addr(remote_ip); /*network byte order*/
	remote_addr.sin_family = AF_INET;
	memcpy(&ifr_tun.ifr_dstaddr, &remote_addr, sizeof(ifr_tun.ifr_dstaddr));
	if (ioctl(sk, SIOCSIFDSTADDR, &ifr_tun) < 0) {
		LOGE("ioctl SIOCSIFDSTADDR failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(sk);
		return VPNSVC_ERROR_IO_ERROR;
	}

	/* set the flags for vpn up */
	if (ioctl(sk, SIOCGIFFLAGS, &ifr_tun) < 0) {
		LOGE("ioctl SIOCGIFFLAGS failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(sk);
		return VPNSVC_ERROR_IO_ERROR;
	}

	ifr_tun.ifr_flags |= IFF_UP;
	ifr_tun.ifr_flags |= IFF_RUNNING;

	if (ioctl(sk, SIOCSIFFLAGS, &ifr_tun) < 0)  {
		LOGE("ioctl SIOCSIFFLAGS failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(sk);
		return VPNSVC_ERROR_IO_ERROR;
	}

	/* mtu setting */
	if (ioctl(sk, SIOCGIFMTU, &ifr_tun) < 0) {
		LOGE("ioctl SIOCGIFMTU failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(sk);
		return VPNSVC_ERROR_IO_ERROR;
	}

	if (mtu > 0 && ifr_tun.ifr_mtu != (int)mtu) {
		ifr_tun.ifr_mtu = mtu;
		if (ioctl(sk, SIOCSIFMTU, &ifr_tun) < 0) {
			LOGE("ioctl SIOCSIFMTU failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
			close(sk);
			return VPNSVC_ERROR_IO_ERROR;
		}
	}

	close(sk);

	/* add routes */
	if (nr_routes > 0) {
		ret = add_routes(ifr_tun.ifr_name, routes, prefix, nr_routes);
		if (ret != VPNSVC_ERROR_NONE) {
			LOGE("add_routes failed");
			return ret;
		}
	}

	/* add DNS servers */
	if (nr_dns > 0) {
		ret = add_dns_servers(dns_servers, nr_dns, total_dns_string_cnt);
		if (ret != VPNSVC_ERROR_NONE) {
			LOGE("add_dns failed");
			return ret;
		}
	}

	/* add_dns_suffix */
	if (dns_suffix) {
		ret = add_dns_suffix(dns_suffix, strlen(dns_suffix));
		if (ret != VPNSVC_ERROR_NONE) {
			LOGE("add_dns_suffix failed");
			return ret;
		}
	}

	return ret;
}

int vpn_daemon_down(int iface_index)
{
	struct ifreq ifr, addr_ifr;
	struct sockaddr_in *addr = NULL;
	int sk;
	char buf[ERROR_BUF_SIZE];

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		LOGE("socket failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		return VPNSVC_ERROR_IO_ERROR;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface_index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		LOGE("ioctl SIOCGIFNAME failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(sk);
		return VPNSVC_ERROR_IO_ERROR;
	}

	if (ioctl(sk, SIOCGIFFLAGS, &ifr) < 0) {
		LOGE("ioctl SIOCGIFFLAGS failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(sk);
		return VPNSVC_ERROR_IO_ERROR;
	}

	memset(&addr_ifr, 0, sizeof(addr_ifr));
	memcpy(&addr_ifr.ifr_name, &ifr.ifr_name, sizeof(ifr.ifr_name) - 1);
	addr = (struct sockaddr_in *)&addr_ifr.ifr_addr;
	addr->sin_family = AF_INET;
	if (ioctl(sk, SIOCSIFADDR, &addr_ifr) < 0)
		LOGD("ioctl SIOCSIFADDR (could not clear IP address) failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));

	if (!(ifr.ifr_flags & IFF_UP)) {
		LOGD("Interface already down");
		close(sk);
		return VPNSVC_ERROR_NONE;
	}

	ifr.ifr_flags = (ifr.ifr_flags & ~IFF_UP) | IFF_DYNAMIC;
	if (ioctl(sk, SIOCSIFFLAGS, &ifr) < 0) {
		LOGE("ioctl SIOCSIFFLAGS (interface down) failed : %s", strerror_r(errno, buf, ERROR_BUF_SIZE));
		close(sk);
		return VPNSVC_ERROR_IO_ERROR;
	}

	close(sk);

	/* routes are will be removed  automatically while down interfaces */
	/* remove dns servers */
	del_dns_servers();

	/* remove dns suffix */
	del_dns_suffix();

	return VPNSVC_ERROR_NONE;
}

int vpn_daemon_block_networks(const char* nets_vpn[], int prefix_vpn[], size_t nr_nets_vpn,
		const char* nets_orig[], int prefix_orig[], size_t nr_nets_orig) {
	unsigned int i;

	/* iptable chain regist */
	iptables_register();

	for (i = 0; i < nr_nets_vpn; i++) {
		LOGD("block[%d] ip/mask : %s/%d", i, nets_vpn[i], prefix_vpn[i]);
		iptables_add(nets_vpn[i], prefix_vpn[i]);
	}

	for (i = 0; i < nr_nets_orig; i++) {
		LOGD("allow[%d] ip/mask : %s/%d", i, nets_orig[i], prefix_orig[i]);
		iptables_add_orig(nets_orig[i], prefix_orig[i]);
	}

	return VPNSVC_ERROR_NONE;
}

int vpn_daemon_unblock_networks(void)
{
	iptables_unregister();

	return VPNSVC_ERROR_NONE;
}
