#include "dvpnlib-internal.h"

/*
 * D-Bus
 */
enum dvpnlib_err common_set_property(GDBusProxy *dbus_proxy,
				const char *property,
				GVariant *value)
{
	gchar *print_str;
	GError *error = NULL;
	enum dvpnlib_err ret = DVPNLIB_ERR_NONE;

	print_str = g_variant_print(value, TRUE);
	DBG("set object %s property %s to %s",
		g_dbus_proxy_get_object_path(dbus_proxy),
		property, print_str);
	g_free(print_str);

	g_dbus_proxy_call_sync(dbus_proxy, "SetProperty",
				g_variant_new("(sv)", property, value),
				G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error) {
		ERROR("%s", error->message);
		ret = get_error_type(error);
		g_error_free(error);
	}

	return ret;
}

GVariant *common_get_call_method_result(GDBusProxy *dbus_proxy,
					  const char *method)
{
	if ((!dbus_proxy) || (!method))
		return NULL;

	GError *error = NULL;
	GVariant *result;

	DBG("get object %s method %s",
		g_dbus_proxy_get_object_path(dbus_proxy), method);

	result = g_dbus_proxy_call_sync(dbus_proxy, method, NULL,
					    G_DBUS_CALL_FLAGS_NONE, -1,
					    NULL, &error);
	if (!result) {
		ERROR("%s", error->message);
		g_error_free(error);
		return NULL;
	}

	return result;
}

enum dvpnlib_err common_set_interface_call_method_sync(
						GDBusProxy *dbus_proxy,
						const char *method,
						GVariant **parameters)
{
	if ((!dbus_proxy) || (!method))
		return DVPNLIB_ERR_FAILED;

	GVariant *result;
	GError *error = NULL;
	enum dvpnlib_err ret = DVPNLIB_ERR_NONE;

	DBG("get object %s property %s",
		g_dbus_proxy_get_object_path(dbus_proxy), method);

	if (parameters)
		result = g_dbus_proxy_call_sync(dbus_proxy, method, *parameters,
			       G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	else
		result = g_dbus_proxy_call_sync(dbus_proxy, method, NULL,
			       G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error) {
		ERROR("%s", error->message);
		ret = get_error_type(error);
		g_error_free(error);
		return ret;
	}

	g_variant_unref(result);

	return ret;
}

enum dvpnlib_err common_set_interface_call_method(GDBusProxy *dbus_proxy,
						const char *method,
						GVariant **parameters,
						GAsyncReadyCallback callback,
						gpointer user_data)
{
	if ((!dbus_proxy) || (!method))
		return DVPNLIB_ERR_FAILED;

	DBG("get object %s property %s",
		g_dbus_proxy_get_object_path(dbus_proxy), method);

	if (parameters) {
		g_dbus_proxy_call(dbus_proxy,
				method,
				*parameters,
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL, callback, user_data);
	} else {
		g_dbus_proxy_call(dbus_proxy,
				method,
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL, callback, user_data);
	}

	return DVPNLIB_ERR_NONE;
}

struct common_reply_data *common_reply_data_new(void *cb, void *data,
						void *user, bool flag)
{
	struct common_reply_data *ret;

	ret = g_try_new0(struct common_reply_data, 1);
	if (!ret)
		return NULL;

	ret->cb = cb;
	ret->data = data;
	ret->user = user;
	ret->flag = flag;

	return ret;
}

/*
 * Error
 */
struct error_map_t error_map[] = {
	{"Error.Failed", DVPNLIB_ERR_OPERATION_FAILED},
	{"Error.InvalidArguments", DVPNLIB_ERR_INVALID_PARAMETER},
	{"Error.PermissionDenied", DVPNLIB_ERR_PERMISSION_DENIED},
	{"Error.PassphraseRequired", DVPNLIB_ERR_PASSPHRASE_REQUIRED},
	{"Error.NotRegistered", DVPNLIB_ERR_NOT_REGISTERED},
	{"Error.NotUnique", DVPNLIB_ERR_NOT_UNIQUE},
	{"Error.NotSupported", DVPNLIB_ERR_NOT_SUPPORTED},
	{"Error.NotImplemented", DVPNLIB_ERR_NOT_IMPLEMENTED},
	{"Error.NotFound", DVPNLIB_ERR_NOT_FOUND},
	{"Error.InProgress", DVPNLIB_ERR_IN_PROGRESS},
	{"Error.AlreadyExists", DVPNLIB_ERR_ALREADY_EXISTS},
	{"Error.AlreadyEnabled", DVPNLIB_ERR_ALREADY_ENABLED},
	{"Error.AlreadyDisabled", DVPNLIB_ERR_ALREADY_DISABLED},
	{"Error.AlreadyConnected", DVPNLIB_ERR_ALREADY_CONNECTED},
	{"Error.NotConnected", DVPNLIB_ERR_NOT_CONNECTED},
	{"Error.OperationAborted", DVPNLIB_ERR_OPERATION_ABORTED},
	{"Error.OperationTimeout", DVPNLIB_ERR_OPERATION_TIMEOUT},
	{"Error.InvalidService", DVPNLIB_ERR_INVALID_SERVICE},
	{"Error.InvalidProperty", DVPNLIB_ERR_INVALID_PROPERTY},

	{"Error.Timeout", DVPNLIB_ERR_TIMEOUT},
	{"Error.Timedout", DVPNLIB_ERR_TIMEOUT},
	{"Error.UnknownProperty", DVPNLIB_ERR_UNKNOWN_PROPERTY},
	{"Error.PropertyReadOnly", DVPNLIB_ERR_PROPERTY_READONLY},
	{"Error.UnknownMethod", DVPNLIB_ERR_UNKNOWN_METHOD},
};

enum dvpnlib_err get_error_type(GError *error)
{
	int i = 0;

	while (error_map[i].error_key_str != NULL) {
		const gchar *error_info = error_map[i].error_key_str;

		if (g_strrstr(error->message, error_info))
			return error_map[i].type;

		i++;
	}

	return DVPNLIB_ERR_FAILED;
}
