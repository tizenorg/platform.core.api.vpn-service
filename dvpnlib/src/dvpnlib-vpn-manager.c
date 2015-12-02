#include "dvpnlib-internal.h"
#include "dvpnlib-vpn-manager.h"

struct vpn_manager {
	GDBusProxy *dbus_proxy;
	void *connection_added_cb_data;
	void *connection_removed_cb_data;
	vpn_connection_added_cb connection_added_cb;
	vpn_connection_removed_cb connection_removed_cb;
};

static void connection_added(GVariant *parameters)
{
	struct vpn_connection *connection;

	DBG("");

	if (add_vpn_connection(&parameters, &connection)) {
		if (vpn_manager->connection_added_cb) {
			vpn_manager->connection_added_cb(connection,
				vpn_manager->connection_added_cb_data);
		}
	}
}

static void connection_removed(GVariant *parameters)
{
	DBG("");

	const gchar *connection_path;
	struct vpn_connection *connection;

	g_variant_get(parameters, "(o)", &connection_path);

	connection = get_connection_by_path(connection_path);
	if (connection == NULL)
		return;

	if (vpn_manager->connection_removed_cb) {
		void *user_data = vpn_manager->connection_removed_cb_data;
		vpn_manager->connection_removed_cb(connection, user_data);
	}

	remove_vpn_connection(connection);
}

static void manager_signal_handler(GDBusProxy *proxy, gchar *sender_name,
				gchar *signal_name, GVariant *parameters,
				gpointer user_data)
{
	DBG("signal_name: %s", signal_name);

	if (!g_strcmp0(signal_name, "ConnectionAdded"))
		connection_added(parameters);
	else if (!g_strcmp0(signal_name, "ConnectionRemoved"))
		connection_removed(parameters);
}

void free_vpn_manager(struct vpn_manager *manager)
{
	DBG("");

	if (manager == NULL)
		return;

	if (manager->dbus_proxy != NULL)
		g_object_unref(manager->dbus_proxy);

	g_free(manager);
}

struct vpn_manager *create_vpn_manager(void)
{
	GError *error = NULL;
	struct vpn_manager *manager;

	DBG("");
	manager = g_try_new0(struct vpn_manager, 1);
	if (manager == NULL) {
		ERROR("no memory");
		return NULL;
	}

	manager->dbus_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SYSTEM,
					G_DBUS_PROXY_FLAGS_NONE, NULL,
					VPN_NAME, VPN_MANAGER_PATH,
					VPN_MANAGER_INTERFACE, NULL, &error);

	if (manager->dbus_proxy == NULL) {
		ERROR("error info: %s", error->message);
		g_error_free(error);
		free_vpn_manager(manager);
		return NULL;
	}

	g_signal_connect(manager->dbus_proxy, "g-signal",
			G_CALLBACK(manager_signal_handler), NULL);

	return manager;
}

GDBusProxy *get_vpn_manager_dbus_proxy(void)
{
	return vpn_manager->dbus_proxy;
}

/**
 * Asynchronous Methods Create/Remove callback
 */
static void create_remove_callback(GObject *source_object,
			     GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	enum dvpnlib_err error_type = DVPNLIB_ERR_NONE;
	GVariant *ret;
	struct common_reply_data *reply_data;

	reply_data = user_data;
	if (!reply_data)
		return;

	if (!vpn_manager)
		goto done;

	if (!vpn_manager->dbus_proxy)
		goto done;

	ret = g_dbus_proxy_call_finish(vpn_manager->dbus_proxy, res, &error);
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

/* Implementation vpn-manager.h */

static void print_variant(const gchar *s, GVariant *v)
{
	gchar *temp = g_variant_print(v, true);
	DBG("%s => %s", s, temp);
	g_free(temp);
}

static GVariant *
settings_from_hash_table(GHashTable *hash_table)
{
	GVariantBuilder builder;

	g_variant_builder_init(&builder, G_VARIANT_TYPE("(a{sv})"));
	g_variant_builder_open(&builder, G_VARIANT_TYPE("a{sv}"));

	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, hash_table);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		g_variant_builder_add(&builder, "{sv}",
				key,
				g_variant_new_string(value));
	}

	g_variant_builder_close(&builder);

	return g_variant_builder_end(&builder);
}

enum dvpnlib_err dvpnlib_vpn_manager_create(GHashTable *settings,
				 dvpnlib_reply_cb callback,
				 void *user_data)
{
	GVariant *settings_v;

	assert(vpn_manager != NULL);
	assert(settings != NULL);

	settings_v = settings_from_hash_table(settings);
	print_variant("Settings", settings_v);

	struct common_reply_data *reply_data;

	reply_data =
		common_reply_data_new(callback, user_data, NULL, TRUE);

	if (NULL == reply_data) {
		DBG("No Memory Available!");
		return DVPNLIB_ERR_FAILED;
	}

	return common_set_interface_call_method(
			vpn_manager->dbus_proxy,
			"Create",
			&settings_v,
			(GAsyncReadyCallback)create_remove_callback,
			reply_data);
}

enum dvpnlib_err dvpnlib_vpn_manager_remove(const char *path,
				 dvpnlib_reply_cb callback,
				 void *user_data)
{
	GVariant *value;
	enum dvpnlib_err ret = DVPNLIB_ERR_NONE;

	assert(vpn_manager != NULL);

	if (!g_variant_is_object_path(path))
		return DVPNLIB_ERR_FAILED;

	value = g_variant_new("(o)", path);

	struct common_reply_data *reply_data;

	reply_data =
	    common_reply_data_new(callback, user_data, NULL, TRUE);

	if (NULL == reply_data) {
		DBG("No Memory Available!");
		return DVPNLIB_ERR_FAILED;

	}

	ret = common_set_interface_call_method(
			vpn_manager->dbus_proxy,
			"Remove",
			&value,
			(GAsyncReadyCallback)create_remove_callback,
			reply_data);

	return ret;
}

enum dvpnlib_err dvpnlib_vpn_manager_register_agent(const char *path)
{
	GVariant *value;

	assert(vpn_manager != NULL);

	if (!g_variant_is_object_path(path))
		return DVPNLIB_ERR_FAILED;

	value = g_variant_new("(o)", path);

	return common_set_interface_call_method_sync(
			vpn_manager->dbus_proxy,
			"RegisterAgent",
			&value);
}

enum dvpnlib_err dvpnlib_vpn_manager_unregister_agent(const char *path)
{
	GVariant *value;

	assert(vpn_manager != NULL);

	if (!g_variant_is_object_path(path))
		return DVPNLIB_ERR_FAILED;

	value = g_variant_new("(o)", path);

	return common_set_interface_call_method_sync(
			vpn_manager->dbus_proxy,
			"UnregisterAgent",
			&value);
}

void dvpnlib_vpn_manager_set_connection_added_cb(
				vpn_connection_added_cb cb,
				void *user_data)
{
	DBG("");

	assert(vpn_manager != NULL);

	vpn_manager->connection_added_cb = cb;
	vpn_manager->connection_added_cb_data = user_data;
}

void dvpnlib_vpn_manager_unset_connection_added_cb()
{
	DBG("");

	assert(vpn_manager != NULL);

	vpn_manager->connection_added_cb = NULL;
	vpn_manager->connection_added_cb_data = NULL;
}

void dvpnlib_vpn_manager_set_connection_removed_cb(
				vpn_connection_removed_cb cb,
				void *user_data)
{
	DBG("");

	assert(vpn_manager != NULL);

	vpn_manager->connection_removed_cb = cb;
	vpn_manager->connection_removed_cb_data = user_data;
}

void dvpnlib_vpn_manager_unset_connection_removed_cb()
{
	DBG("");

	assert(vpn_manager != NULL);

	vpn_manager->connection_removed_cb = NULL;
	vpn_manager->connection_removed_cb_data = NULL;
}

