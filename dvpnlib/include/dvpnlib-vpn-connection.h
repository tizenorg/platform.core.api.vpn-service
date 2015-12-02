#ifndef __VPN_CONNECTION_H__
#define __VPN_CONNECTION_H__

#include "dvpnlib-common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vpn_connection;

enum vpn_connection_state {
	VPN_CONN_STATE_IDLE,
	VPN_CONN_STATE_READY,
	VPN_CONN_STATE_CONFIGURATION,
	VPN_CONN_STATE_DISCONNECT,
	VPN_CONN_STATE_FAILURE,
	VPN_CONN_STATE_UNKNOWN,
};

enum vpn_connection_property_type {
	VPN_CONN_PROP_NONE,

	/*string State [readonly]*/
	VPN_CONN_PROP_STATE,
	/*string Name [readonly]*/
	VPN_CONN_PROP_NAME,
	/*boolean Immutable [readonly]*/
	VPN_CONN_PROP_IMMUTABLE,

	/*string Domain [readonly]*/
	VPN_CONN_PROP_DOMAIN,
	/*string Host [readonly]*/
	VPN_CONN_PROP_HOST,
	/*string Type [readonly]*/
	VPN_CONN_PROP_TYPE,
	/*int Index [readonly]*/
	VPN_CONN_PROP_INDEX,
	/*dict IPv4 [readonly]*/
	VPN_CONN_PROP_IPV4,
	/*dict IPv6 [readonly]*/
	VPN_CONN_PROP_IPV6,
	/*array{string} Nameservers [readonly]*/
	VPN_CONN_PROP_NAMESERVERS,
	/* array{dict} UserRoutes [readwrite] */
	VPN_CONN_PROP_USERROUTES,
	/* array{dict} ServerRoutes [readonly] */
	VPN_CONN_PROP_SERVERROUTES,
};

/*
 * Connection Property Structures
 */
struct vpn_connection_ipv4 {
	gchar *address;
	gchar *netmask;
	gchar *gateway;
	gchar *peer;
};

struct vpn_connection_ipv6 {
	gchar *address;
	gchar *prefix_length;
	gchar *gateway;
	gchar *peer;
};

struct vpn_connection_route {
	int protocol_family;
	gchar *network;
	gchar *netmask;
	gchar *gateway;
};

/*
 * Callback prototype
 */
typedef void (*vpn_connection_property_changed_cb)(
				struct vpn_connection *connection,
				void *user_data);

/*
* Methods
*/
/* experimental */
GList *vpn_get_connections(void);
struct vpn_connection *vpn_get_connection(
				const char *host, const char *domain);
enum dvpnlib_err vpn_connection_clear_property(
				struct vpn_connection *connection);
enum dvpnlib_err vpn_connection_connect(struct vpn_connection *connection,
				dvpnlib_reply_cb callback,
				void *user_data);
enum dvpnlib_err
vpn_connection_disconnect(struct vpn_connection *connection);

/*
 * Properties
 */
/* Set */
enum dvpnlib_err
vpn_connection_set_user_routes(struct vpn_connection *connection,
			struct vpn_connection_route **user_routes);

/* Get */
const char *vpn_connection_get_type(
				struct vpn_connection *connection);
const char *vpn_connection_get_name(
				struct vpn_connection *connection);
const char *vpn_connection_get_path(
				struct vpn_connection *connection);
const char *vpn_connection_get_domain(
				struct vpn_connection *connection);
const char *vpn_connection_get_host(
				struct vpn_connection *connection);
bool vpn_connection_get_immutable(
				struct vpn_connection *connection);
int vpn_connection_get_index(
				struct vpn_connection *connection);

enum vpn_connection_state vpn_connection_get_state(
				struct vpn_connection *connection);
const struct vpn_connection_ipv4 *vpn_connection_get_ipv4(
				struct vpn_connection *connection);
const struct vpn_connection_ipv6 *vpn_connection_get_ipv6(
				struct vpn_connection *connection);
char **vpn_connection_get_nameservers(
				struct vpn_connection *connection);
GSList *vpn_connection_get_user_routes(
				struct vpn_connection *connection);
GSList *vpn_connection_get_server_routes(
				struct vpn_connection *connection);
/*
 * Signals
 */
enum dvpnlib_err vpn_connection_set_property_changed_cb(
				struct vpn_connection *connection,
				enum vpn_connection_property_type type,
				vpn_connection_property_changed_cb cb,
				void *user_data);
enum dvpnlib_err vpn_connection_unset_property_changed_cb(
				struct vpn_connection *connection,
				enum vpn_connection_property_type type);

#ifdef __cplusplus
}
#endif

#endif
