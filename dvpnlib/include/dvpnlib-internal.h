#ifndef __DVPNLIB_INTERNAL_H__
#define __DVPNLIB_INTERNAL_H__

#include <gio/gio.h>
#include <assert.h>

#include "debug.h"
#include "dvpnlib-common.h"

struct vpn_manager;
struct vpn_connection;

extern struct vpn_manager *vpn_manager;

#define VPN_NAME "net.connman.vpn"
#define VPN_MANAGER_INTERFACE "net.connman.vpn.Manager"
#define VPN_CONNECTION_INTERFACE "net.connman.vpn.Connection"
#define VPN_MANAGER_PATH "/"

struct common_reply_data {
	void *cb;
	void *data;
	void *user;
	bool flag;		/*TODO: */
};

struct error_map_t {
	const gchar *error_key_str;
	enum dvpnlib_err type;
};

/*
 * D-Bus
 */
enum dvpnlib_err common_set_property(GDBusProxy *dbus_proxy,
					 const char *property,
					 GVariant *value);
GVariant *common_get_call_method_result(GDBusProxy *dbus_proxy,
					  const char *method);
enum dvpnlib_err common_set_interface_call_method_sync(
						GDBusProxy *dbus_proxy,
						const char *method,
						GVariant **parameters);
enum dvpnlib_err common_set_interface_call_method(GDBusProxy *dbus_proxy,
						const char *method,
						GVariant **parameters,
						GAsyncReadyCallback callback,
						gpointer user_data);

/*
 * VPN Manager
 */
struct vpn_manager *create_vpn_manager(void);
void free_vpn_manager(struct vpn_manager *manager);
GDBusProxy *get_vpn_manager_dbus_proxy(void);

/*
 * VPN Connection
 */
void sync_vpn_connections(void);
void destroy_vpn_connections(void);
struct vpn_connection *get_connection_by_path(const gchar *path);
gboolean add_vpn_connection(GVariant **parameters,
			    struct vpn_connection **connection);
void remove_vpn_connection(struct vpn_connection *connection);

struct common_reply_data *common_reply_data_new(void *cb,
						void *data,
						void *user, bool flag);
/*
 * Error
 */
enum dvpnlib_err get_error_type(GError *error);

#endif
