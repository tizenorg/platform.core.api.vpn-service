#include "dvpnlib-internal.h"
#include "dvpnlib-vpn.h"

struct vpn_manager *vpn_manager;

int dvpnlib_vpn_init(void)
{
	DBG("");

	if (vpn_manager != NULL)
		return 0;

	vpn_manager = create_vpn_manager();

	if (vpn_manager == NULL) {
		DBG("can't create vpn manager");
		return -1;
	}

	sync_vpn_connections();

	return 0;
}

void dvpnlib_vpn_deinit(void)
{
	DBG("");

	free_vpn_manager(vpn_manager);
	vpn_manager = NULL;

	destroy_vpn_connections();
}
