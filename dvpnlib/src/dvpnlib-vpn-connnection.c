#include "dvpnlib-internal.h"
#include "dvpnlib-vpn-connection.h"

static GList *vpn_connection_list;
static GHashTable *vpn_connection_hash;

struct connection_property_changed_cb {
	vpn_connection_property_changed_cb property_changed_cb;
	void *user_data;
};

struct vpn_connection {
	GDBusProxy *dbus_proxy;
	gchar *type;
	gchar *path;
	gchar *name;
	gchar *domain;
	gchar *host;
	gboolean immutable;
	gint index;
	enum vpn_connection_state state;
	struct vpn_connection_ipv4 *ipv4;
	struct vpn_connection_ipv6 *ipv6;
	gchar **nameservers;
	GSList *user_routes; /*struct vpn_connection_route */
	GSList *server_routes; /* struct vpn_connection_route */
	GHashTable *property_changed_cb_hash;
};

static void free_vpn_connection_ipv4(struct vpn_connection_ipv4 *ipv4_info);
static void free_vpn_connection_ipv6(struct vpn_connection_ipv6 *ipv6_info);
static void free_vpn_connection_route(gpointer data);

enum dvpnlib_err
vpn_connection_set_user_routes(struct vpn_connection *connection,
			    struct vpn_connection_route **user_routes)
{
	if (!connection || !user_routes)
		return DVPNLIB_ERR_INVALID_PARAMETER;

	GVariantBuilder user_routes_b;
	GVariant *user_routes_v;

	g_variant_builder_init(&user_routes_b, G_VARIANT_TYPE("a(a{sv})"));

	while (*user_routes != NULL) {

		g_variant_builder_open(&user_routes_b,
				G_VARIANT_TYPE("(a{sv})"));
		g_variant_builder_open(&user_routes_b,
				G_VARIANT_TYPE("a{sv}"));

		if ((*user_routes)->protocol_family) {
			g_variant_builder_add(&user_routes_b, "{sv}",
				"ProtocolFamily",
				g_variant_new_int32(
					(*user_routes)->protocol_family));
		}

		if ((*user_routes)->network) {
			g_variant_builder_add(&user_routes_b, "{sv}",
				"Network",
				g_variant_new_string((*user_routes)->network));
		}

		if ((*user_routes)->netmask) {
			g_variant_builder_add(&user_routes_b, "{sv}",
				"Netmask",
				g_variant_new_string((*user_routes)->netmask));
		}

		if ((*user_routes)->gateway) {
			g_variant_builder_add(&user_routes_b, "{sv}",
				"Gateway",
				g_variant_new_string((*user_routes)->gateway));
		}

		g_variant_builder_close(&user_routes_b);
		g_variant_builder_close(&user_routes_b);

		user_routes++;
	}

	user_routes_v = g_variant_builder_end(&user_routes_b);

	return common_set_property(connection->dbus_proxy, "UserRoutes",
			user_routes_v);

}

static struct connection_property_changed_cb
		*get_connection_property_changed_cb(
			struct vpn_connection *connection,
			enum vpn_connection_property_type type)
{
	return g_hash_table_lookup(connection->property_changed_cb_hash,
					GINT_TO_POINTER(type));
}

static void parse_connection_property_ipv4(
				struct vpn_connection *connection,
				GVariant *ipv4)
{
	DBG("");

	GVariantIter *iter;
	gchar *key;
	GVariant *value;

	g_variant_get(ipv4, "a{sv}", &iter);
	if (g_variant_iter_n_children(iter) == 0) {
		g_variant_iter_free(iter);
		return;
	}

	if (connection->ipv4)
		free_vpn_connection_ipv4(connection->ipv4);

	connection->ipv4 = g_try_new0(struct vpn_connection_ipv4, 1);
	if (connection->ipv4 == NULL) {
		ERROR("no memory");
		g_variant_iter_free(iter);
		return;
	}

	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		if (!g_strcmp0(key, "Address")) {
			const char *property_value =
				g_variant_get_string(value, NULL);
			DBG("Address is %s", property_value);
			connection->ipv4->address = g_strdup(property_value);
		} else if (!g_strcmp0(key, "Netmask")) {
			const char *property_value =
				g_variant_get_string(value, NULL);
			DBG("Netmask is %s", property_value);
			connection->ipv4->netmask = g_strdup(property_value);
		} else if (!g_strcmp0(key, "Gateway")) {
			const char *property_value =
				g_variant_get_string(value, NULL);
			DBG("Gateway is %s", property_value);
			connection->ipv4->gateway = g_strdup(property_value);
		} else if (!g_strcmp0(key, "Peer")) {
			const char *property_value =
				g_variant_get_string(value, NULL);
			DBG("Peer is %s", property_value);
			connection->ipv4->peer = g_strdup(property_value);
		}
	}

	g_variant_iter_free(iter);
}

static void parse_connection_property_ipv6(
				struct vpn_connection *connection,
				GVariant *ipv6)
{
	DBG("");

	GVariantIter *iter;
	gchar *key;
	GVariant *value;

	g_variant_get(ipv6, "a{sv}", &iter);
	if (g_variant_iter_n_children(iter) == 0) {
		g_variant_iter_free(iter);
		return;
	}

	if (connection->ipv6)
		free_vpn_connection_ipv6(connection->ipv6);

	connection->ipv6 = g_try_new0(struct vpn_connection_ipv6, 1);
	if (connection->ipv6 == NULL) {
		ERROR("no memory");
		g_variant_iter_free(iter);
		return;
	}

	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		if (!g_strcmp0(key, "Address")) {
			const char *property_value =
				g_variant_get_string(value, NULL);
			DBG("Address is %s", property_value);
			connection->ipv6->address = g_strdup(property_value);
		} else if (!g_strcmp0(key, "PrefixLength")) {
			const char *property_value =
				g_variant_get_string(value, NULL);
			DBG("PrefixLength is %s", property_value);
			connection->ipv6->prefix_length =
				g_strdup(property_value);
		} else if (!g_strcmp0(key, "Gateway")) {
			const char *property_value =
				g_variant_get_string(value, NULL);
			DBG("Gateway is %s", property_value);
			connection->ipv6->gateway = g_strdup(property_value);
		} else if (!g_strcmp0(key, "Peer")) {
			const char *property_value =
				g_variant_get_string(value, NULL);
			DBG("Peer is %s", property_value);
			connection->ipv6->peer = g_strdup(property_value);
		}
	}

	g_variant_iter_free(iter);
}

static void parse_connection_property_nameservers(
				struct vpn_connection *connection,
				GVariant *nameservers)
{
	DBG("");

	GVariantIter *iter;
	gchar *value;
	int i = 0, n;

	g_variant_get(nameservers, "as", &iter);
	if (g_variant_iter_n_children(iter) == 0) {
		g_variant_iter_free(iter);
		return;
	}

	g_strfreev(connection->nameservers);
	n = g_variant_iter_n_children(iter);
	connection->nameservers = g_try_new0(char *, n+1);
	if (connection->nameservers == NULL) {
		ERROR("no memory");
		g_variant_iter_free(iter);
		return;
	}

	while (g_variant_iter_loop(iter, "s", &value) && i < n) {
		DBG("Nameserver Entry is %s", value);
		connection->nameservers[i] = g_strdup(value);
		i++;
	}
	connection->nameservers[n] = NULL;

	g_variant_iter_free(iter);
}

static void print_variant(const gchar *s, GVariant *v)
{
	gchar *temp = g_variant_print(v, true);
	DBG("%s => %s", s, temp);
	g_free(temp);
}

static void parse_connection_property_user_routes(
				struct vpn_connection *connection,
				GVariant *user_routes)
{
	DBG("");

	GVariantIter outer;
	GVariantIter *route_entry;

	print_variant("Incoming : ", user_routes);

	g_variant_iter_init(&outer, user_routes);
	if (g_variant_iter_n_children(&outer) == 0)
		return;

	if (connection->user_routes)
		g_slist_free_full(connection->user_routes,
				free_vpn_connection_route);

	while (g_variant_iter_loop(&outer, "(a{sv})", &route_entry)) {
		gchar *key;
		GVariant *value;

		if (g_variant_iter_n_children(route_entry) == 0)
			continue;

		struct vpn_connection_route *route =
			g_try_new0(struct vpn_connection_route, 1);
		if (route == NULL) {
			ERROR("no memory");
			return;
		}

		while (g_variant_iter_loop(route_entry, "{sv}", &key, &value)) {
			if (!g_strcmp0(key, "ProtocolFamily")) {
				int property_value = g_variant_get_int32(value);
				DBG("ProtocolFamily is %d", property_value);
				route->protocol_family = property_value;
			} else if (!g_strcmp0(key, "Network")) {
				const char *property_value =
					g_variant_get_string(value, NULL);
				DBG("Network is %s", property_value);
				route->network = g_strdup(property_value);
			} else if (!g_strcmp0(key, "Netmask")) {
				const char *property_value =
					g_variant_get_string(value, NULL);
				DBG("Netmask is %s", property_value);
				route->netmask = g_strdup(property_value);
			} else if (!g_strcmp0(key, "Gateway")) {
				const char *property_value =
					g_variant_get_string(value, NULL);
				DBG("Gateway is %s", property_value);
				route->gateway = g_strdup(property_value);
			}
		}

		/*TODO: See if g_slist_prepend works better*/
		connection->user_routes =
			g_slist_append(connection->user_routes, route);

	}
}

static void parse_connection_property_server_routes(
				struct vpn_connection *connection,
				GVariant *server_routes)
{
	DBG("");

	GVariantIter outer;
	GVariantIter *route_entry;

	g_variant_iter_init(&outer, server_routes);
	if (g_variant_iter_n_children(&outer) == 0) {
		return;
	}

	if (connection->server_routes)
		g_slist_free_full(connection->server_routes,
				free_vpn_connection_route);

	while (g_variant_iter_loop(&outer, "(a{sv})", &route_entry)) {
		gchar *key;
		GVariant *value;

		if (g_variant_iter_n_children(route_entry) == 0)
			continue;

		struct vpn_connection_route *route =
			g_try_new0(struct vpn_connection_route, 1);
		if (route == NULL) {
			ERROR("no memory");
			return;
		}

		while (g_variant_iter_loop(route_entry, "{sv}", &key, &value)) {
			if (!g_strcmp0(key, "ProtocolFamily")) {
				int property_value = g_variant_get_int32(value);
				DBG("ProtocolFamily is %d", property_value);
				route->protocol_family = property_value;
			} else if (!g_strcmp0(key, "Network")) {
				const char *property_value =
					g_variant_get_string(value, NULL);
				DBG("Network is %s", property_value);
				route->network = g_strdup(property_value);
			} else if (!g_strcmp0(key, "Netmask")) {
				const char *property_value =
					g_variant_get_string(value, NULL);
				DBG("Netmask is %s", property_value);
				route->netmask = g_strdup(property_value);
			} else if (!g_strcmp0(key, "Gateway")) {
				const char *property_value =
					g_variant_get_string(value, NULL);
				DBG("Gateway is %s", property_value);
				route->gateway = g_strdup(property_value);
			}
		}

		/*TODO: See if g_slist_prepend works better*/
		connection->server_routes =
			g_slist_append(connection->server_routes, route);
	}
}

static enum vpn_connection_property_type parse_connection_property(
					struct vpn_connection *connection,
					gchar *key, GVariant *value)
{
	assert(connection != NULL);
	enum vpn_connection_property_type property_type = VPN_CONN_PROP_NONE;

	if (!g_strcmp0(key, "State")) {
		const gchar *property_value;
		property_value = g_variant_get_string(value, NULL);
		DBG("connection state is %s", property_value);
		if (!g_strcmp0(property_value, "idle"))
			connection->state = VPN_CONN_STATE_IDLE;
		else if (!g_strcmp0(property_value, "failure"))
			connection->state = VPN_CONN_STATE_FAILURE;
		else if (!g_strcmp0(property_value, "configuration"))
			connection->state = VPN_CONN_STATE_CONFIGURATION;
		else if (!g_strcmp0(property_value, "ready"))
			connection->state = VPN_CONN_STATE_READY;
		else if (!g_strcmp0(property_value, "disconnect"))
			connection->state = VPN_CONN_STATE_DISCONNECT;
		property_type = VPN_CONN_PROP_STATE;
	} else if (!g_strcmp0(key, "Type")) {
		const gchar *property_value;
		property_value = g_variant_get_string(value, NULL);
		DBG("connection type is %s", property_value);
		g_free(connection->type);
		connection->type = g_strdup(property_value);
		property_type = VPN_CONN_PROP_TYPE;
	} else if (!g_strcmp0(key, "Name")) {
		const gchar *property_value;
		property_value = g_variant_get_string(value, NULL);
		g_free(connection->name);
		connection->name = g_strdup(property_value);
		property_type = VPN_CONN_PROP_NAME;
	} else if (!g_strcmp0(key, "Domain")) {
		const gchar *property_value;
		property_value = g_variant_get_string(value, NULL);
		g_free(connection->domain);
		connection->domain = g_strdup(property_value);
		property_type = VPN_CONN_PROP_DOMAIN;
	} else if (!g_strcmp0(key, "Host")) {
		const gchar *property_value;
		property_value = g_variant_get_string(value, NULL);
		g_free(connection->host);
		connection->host = g_strdup(property_value);
		property_type = VPN_CONN_PROP_HOST;
	} else if (!g_strcmp0(key, "Immutable")) {
		connection->immutable = g_variant_get_boolean(value);
		property_type = VPN_CONN_PROP_IMMUTABLE;
	} else if (!g_strcmp0(key, "Index")) {
		connection->index = g_variant_get_int32(value);
		property_type = VPN_CONN_PROP_INDEX;
	}
	/* TODO:
	 * Add IPv4/IPV6/Nameservers
	 * UserRoutes/ServerRoutes
	 * Parsing code */

	else if (!g_strcmp0(key, "IPv4")) {
		parse_connection_property_ipv4(connection, value);
		property_type = VPN_CONN_PROP_IPV4;
	} else if (!g_strcmp0(key, "IPv6")) {
		parse_connection_property_ipv6(connection, value);
		property_type = VPN_CONN_PROP_IPV6;
	} else if (!g_strcmp0(key, "Nameservers")) {
		parse_connection_property_nameservers(connection, value);
		property_type = VPN_CONN_PROP_USERROUTES;
	} else if (!g_strcmp0(key, "UserRoutes")) {
		parse_connection_property_user_routes(connection, value);
		property_type = VPN_CONN_PROP_USERROUTES;
	} else if (!g_strcmp0(key, "ServerRoutes")) {
		parse_connection_property_server_routes(connection, value);
		property_type = VPN_CONN_PROP_SERVERROUTES;
	}

	return property_type;
}

static void parse_connection_properties(
				struct vpn_connection *connection,
				GVariantIter *properties)
{
	gchar *key;
	GVariant *value;

	while (g_variant_iter_next(properties, "{sv}", &key, &value)) {
		parse_connection_property(connection, key, value);

		g_free(key);
		g_variant_unref(value);
	}
}

static void connection_property_changed(
				struct vpn_connection *connection,
				GVariant *parameters)
{
	gchar *key;
	GVariant *value;
	enum vpn_connection_property_type property_type;

	DBG("");

	g_variant_get(parameters, "(sv)", &key, &value);
	property_type = parse_connection_property(connection, key, value);

	if (property_type != VPN_CONN_PROP_NONE) {
		DBG("Now check property changed callback");

		struct connection_property_changed_cb *property_changed_cb_t;

		property_changed_cb_t = get_connection_property_changed_cb(
							connection,
							property_type);
		if (property_changed_cb_t != NULL) {
			DBG("property changed callback has been set");
			property_changed_cb_t->property_changed_cb(connection,
					property_changed_cb_t->user_data);
		}
	}

	g_free(key);
	g_variant_unref(value);
}

static void connection_signal_handler(GDBusProxy *proxy,
					   gchar *sender_name,
					   gchar *signal_name,
					   GVariant *parameters,
					   gpointer user_data)
{
	DBG("signal_name: %s", signal_name);

	struct vpn_connection *connection = user_data;

	if (!g_strcmp0(signal_name, "PropertyChanged"))
		connection_property_changed(connection, parameters);
}

static void free_connection_property_changed_cb(gpointer data)
{
	DBG("");
	struct connection_property_changed_cb *property_changed_cb = data;

	g_free(property_changed_cb);
}

void destroy_vpn_connections(void)
{
	if (vpn_connection_list != NULL) {
		g_list_free(vpn_connection_list);
		vpn_connection_list = NULL;
	}
	if (vpn_connection_hash != NULL) {
		g_hash_table_destroy(vpn_connection_hash);
		vpn_connection_hash = NULL;
	}
}

static struct vpn_connection *create_vpn_connection(
						gchar *object_path,
						GVariantIter *properties)
{
	GDBusProxy *connection_proxy;
	struct vpn_connection *connection;
	GError *error = NULL;

	DBG("");

	connection_proxy = g_dbus_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
					G_DBUS_PROXY_FLAGS_NONE, NULL,
					VPN_NAME, object_path,
					VPN_CONNECTION_INTERFACE, NULL, &error);
	if (connection_proxy == NULL) {
		ERROR("error info: %s", error->message);
		g_error_free(error);
		return NULL;
	}

	connection = g_try_new0(struct vpn_connection, 1);
	if (connection == NULL) {
		ERROR("no memory");
		g_object_unref(connection_proxy);
		return NULL;
	}

	connection->dbus_proxy = connection_proxy;
	connection->path = g_strdup(object_path);

	parse_connection_properties(connection, properties);

	g_hash_table_insert(vpn_connection_hash,
				(gpointer)connection->path,
				(gpointer)connection);

	vpn_connection_list = g_list_append(vpn_connection_list,
						connection);

	connection->property_changed_cb_hash = g_hash_table_new_full(
					g_direct_hash, g_direct_equal, NULL,
					free_connection_property_changed_cb);

	g_signal_connect(connection->dbus_proxy, "g-signal",
			G_CALLBACK(connection_signal_handler), connection);

	return connection;
}

static void free_vpn_connection_ipv4(struct vpn_connection_ipv4 *ipv4_info)
{
	DBG("");

	g_free(ipv4_info->address);
	g_free(ipv4_info->netmask);
	g_free(ipv4_info->gateway);
	g_free(ipv4_info->peer);
	g_free(ipv4_info);
}

static void free_vpn_connection_ipv6(struct vpn_connection_ipv6 *ipv6_info)
{
	DBG("");

	g_free(ipv6_info->address);
	g_free(ipv6_info->prefix_length);
	g_free(ipv6_info->gateway);
	g_free(ipv6_info->peer);
	g_free(ipv6_info);
}

static void free_vpn_connection_route(gpointer data)
{
	DBG("");

	struct vpn_connection_route *route = data;

	if (route == NULL) {
		DBG("Nothing to Delete!");
		return;
	}

	g_free(route->network);
	g_free(route->netmask);
	g_free(route->gateway);

	g_free(route);
}

static void free_vpn_connection(gpointer data)
{
	DBG("");

	struct vpn_connection *connection = data;

	if (connection == NULL)
		return;

	if (connection->dbus_proxy != NULL)
		g_object_unref(connection->dbus_proxy);

	if (connection->property_changed_cb_hash != NULL)
		g_hash_table_destroy(connection->property_changed_cb_hash);

	g_free(connection->path);
	g_free(connection->name);
	g_free(connection->domain);
	g_free(connection->host);

	if (connection->ipv4)
		free_vpn_connection_ipv4(connection->ipv4);

	if (connection->ipv6)
		free_vpn_connection_ipv6(connection->ipv6);

	g_strfreev(connection->nameservers);

	if (connection->user_routes)
		g_slist_free_full(connection->user_routes,
				free_vpn_connection_route);

	if (connection->server_routes)
		g_slist_free_full(connection->server_routes,
				free_vpn_connection_route);

	g_free(connection);
}

static void create_vpn_connections(GVariant *connections)
{
	GVariantIter *iter;
	gchar *path;
	GVariantIter *properties;

	g_variant_get(connections, "(a(oa{sv}))", &iter);
	if (g_variant_iter_n_children(iter) == 0) {
		g_variant_iter_free(iter);
		return;
	}

	while (g_variant_iter_loop(iter, "(oa{sv})", &path, &properties))
		create_vpn_connection(path, properties);

	g_variant_iter_free(iter);
}

struct vpn_connection *get_connection_by_path(const gchar *path)
{
	DBG("path: %s", path);

	return g_hash_table_lookup(vpn_connection_hash, (gpointer)path);
}

gboolean add_vpn_connection(GVariant **parameters,
				struct vpn_connection **connection)
{
	gchar *print_str;
	gchar *connection_path;
	GVariantIter *properties;
	gboolean ret;

	g_variant_get(*parameters, "(oa{sv})", &connection_path, &properties);

	print_str = g_variant_print(*parameters, TRUE);
	DBG("connection path: %s, parameters: %s", connection_path, print_str);
	g_free(print_str);

	/*
	 * Lookup if it has existed in the hash table
	 */
	*connection = g_hash_table_lookup(vpn_connection_hash,
						(gpointer) connection_path);
	if (*connection != NULL) {
		DBG("Repetitive connection %s", (*connection)->name);

		ret = FALSE;
	} else {
		*connection = create_vpn_connection(connection_path,
								properties);
		if (*connection != NULL)
			ret = TRUE;
		else
			ret = FALSE;
	}

	g_variant_iter_free(properties);
	return ret;
}

void remove_vpn_connection(struct vpn_connection *connection)
{
	DBG("");

	assert(connection != NULL);

	vpn_connection_list = g_list_remove(vpn_connection_list,
						(gpointer)connection);

	g_hash_table_remove(vpn_connection_hash,
			(gconstpointer)connection->path);
}

void sync_vpn_connections(void)
{
	DBG("");

	gchar *print_str;
	GVariant *connections;
	GError *error = NULL;

	connections = g_dbus_proxy_call_sync(get_vpn_manager_dbus_proxy(),
						"GetConnections", NULL,
						G_DBUS_CALL_FLAGS_NONE,
						-1, NULL, &error);
	if (connections == NULL) {
		ERROR("error info: %s", error->message);
		g_error_free(error);
		return;
	}

	print_str = g_variant_print(connections, TRUE);
	DBG("connections: %s", print_str);
	g_free(print_str);

	if (!vpn_connection_hash)
		vpn_connection_hash = g_hash_table_new_full(
					g_str_hash, g_str_equal,
					NULL, free_vpn_connection);
	DBG("hash: %p", vpn_connection_hash);

	create_vpn_connections(connections);

	g_variant_unref(connections);
}

/**
 * VPN Connection Methods
 */
GList *vpn_get_connections(void)
{
	DBG("");

	return vpn_connection_list;
}

struct vpn_connection *vpn_get_connection(
					const char *host, const char *domain)
{
	if (!host || !domain)
		return NULL;

	GList *iter;

	for (iter = vpn_connection_list; iter != NULL;
	     iter = iter->next) {
		struct vpn_connection *connection =
		    (struct vpn_connection *)(iter->data);

		if (g_str_equal(connection->host, host) &&
				g_str_equal(connection->domain, domain))
			return connection;
	}

	return NULL;
}

enum dvpnlib_err vpn_connection_clear_property(
				struct vpn_connection *connection)
{
	GVariant *value;

	assert(connection != NULL);

	/**
	 * Only supported the "UserRoutes" item now;
	 */
	value = g_variant_new("(s)", "UserRoutes");

	return common_set_interface_call_method_sync(connection->dbus_proxy,
						"ClearProperty", &value);
}

/**
 * Asynchronous connect callback
 */
static void connect_callback(GObject *source_object,
			     GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	enum dvpnlib_err error_type = DVPNLIB_ERR_NONE;
	GVariant *ret;
	struct common_reply_data *reply_data;
	struct vpn_connection *connection;

	reply_data = user_data;
	if (!reply_data)
		return;

	connection = reply_data->user;
	if (!connection)
		goto done;

	if (!connection->dbus_proxy)
		goto done;

	ret = g_dbus_proxy_call_finish(connection->dbus_proxy, res, &error);
	if (!ret) {
		DBG("%s", error->message);
		error_type = get_error_type(error);

		g_error_free(error);
	} else
		g_variant_unref(ret);

	if (reply_data->cb) {
		dvpnlib_reply_cb callback = reply_data->cb;
		callback(error_type, reply_data->data);
	}

done:
	g_free(reply_data);
}

enum dvpnlib_err vpn_connection_connect(struct vpn_connection *connection,
				 dvpnlib_reply_cb callback,
				 void *user_data)
{
	DBG("");

	struct common_reply_data *reply_data;

	assert(connection != NULL);

	reply_data =
	    common_reply_data_new(callback, user_data, connection, TRUE);

	return common_set_interface_call_method(connection->dbus_proxy,
					 "Connect", NULL,
					 (GAsyncReadyCallback)
					 connect_callback, reply_data);
}

enum dvpnlib_err
vpn_connection_disconnect(struct vpn_connection *connection)
{
	DBG("");

	assert(connection != NULL);

	return common_set_interface_call_method_sync(connection->dbus_proxy,
					 "Disconnect", NULL);

}

const char *vpn_connection_get_type(
					struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->type;
}

const char *vpn_connection_get_name(
					struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->name;
}

const char *vpn_connection_get_path(
				struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->path;
}

const char *vpn_connection_get_domain(
				struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->domain;
}

const char *vpn_connection_get_host(
				struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->host;
}

bool vpn_connection_get_immutable(
				struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->immutable;
}

int vpn_connection_get_index(
				struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->index;
}

enum vpn_connection_state vpn_connection_get_state(
				struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->state;
}

const struct vpn_connection_ipv4 *vpn_connection_get_ipv4(
				struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->ipv4;
}

const struct vpn_connection_ipv6 *vpn_connection_get_ipv6(
				struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->ipv6;
}

char **vpn_connection_get_nameservers(
				struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->nameservers;
}

GSList *vpn_connection_get_user_routes(
				struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->user_routes;
}

GSList *vpn_connection_get_server_routes(
				struct vpn_connection *connection)
{
	assert(connection != NULL);

	return connection->server_routes;
}

enum dvpnlib_err vpn_connection_set_property_changed_cb(
				struct vpn_connection *connection,
				enum vpn_connection_property_type type,
				vpn_connection_property_changed_cb cb,
				void *user_data)
{
	DBG("");

	if (connection == NULL)
		return DVPNLIB_ERR_INVALID_PARAMETER;

	struct connection_property_changed_cb *property_changed_cb_t =
			g_try_new0(struct connection_property_changed_cb, 1);
	if (property_changed_cb_t == NULL) {
		ERROR("no memory");
		return DVPNLIB_ERR_FAILED;
	}
	property_changed_cb_t->property_changed_cb = cb;
	property_changed_cb_t->user_data = user_data;

	g_hash_table_insert(connection->property_changed_cb_hash,
				GINT_TO_POINTER(type),
				(gpointer)property_changed_cb_t);

	return DVPNLIB_ERR_NONE;
}

enum dvpnlib_err vpn_connection_unset_property_changed_cb(
				struct vpn_connection *connection,
				enum vpn_connection_property_type type)
{
	DBG("");

	if (connection == NULL)
		return DVPNLIB_ERR_INVALID_PARAMETER;

	struct connection_property_changed_cb *property_changed_cb_t =
			get_connection_property_changed_cb(connection, type);

	if (property_changed_cb_t == NULL) {
		DBG("Can't find connection property changed callback");
		return DVPNLIB_ERR_FAILED;
	}

	g_hash_table_remove(connection->property_changed_cb_hash,
				GINT_TO_POINTER(type));

	return DVPNLIB_ERR_NONE;
}
