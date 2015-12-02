#ifndef __VPN_MANAGER_H__
#define __VPN_MANAGER_H__

#include "dvpnlib-common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vpn_manager;
struct vpn_connection;

struct vpn_setting_entry {
	gchar *key;
	gchar *value;
};

/*
 * Callback prototype
 */
typedef void (*vpn_connection_added_cb)(
				struct vpn_connection *connection,
				void *user_data);
typedef void (*vpn_connection_removed_cb)(
				struct vpn_connection *connection,
				void *user_data);
/*
* Methods
*/
GList *vpn_get_connections(void);
enum dvpnlib_err dvpnlib_vpn_manager_create(GHashTable *settings,
				dvpnlib_reply_cb callback,
				void *user_data);
enum dvpnlib_err dvpnlib_vpn_manager_remove(const char *path,
				dvpnlib_reply_cb callback,
				void *user_data);
enum dvpnlib_err dvpnlib_vpn_manager_register_agent(const char *path);
enum dvpnlib_err dvpnlib_vpn_manager_unregister_agent(const char *path);

/*
 * Signals
 */
void dvpnlib_vpn_manager_set_connection_added_cb(
				vpn_connection_added_cb cb,
				void *user_data);
void dvpnlib_vpn_manager_unset_connection_added_cb();
void dvpnlib_vpn_manager_set_connection_removed_cb(
				vpn_connection_removed_cb cb,
				void *user_data);
void dvpnlib_vpn_manager_unset_connection_removed_cb();
#ifdef __cplusplus
}
#endif

#endif
