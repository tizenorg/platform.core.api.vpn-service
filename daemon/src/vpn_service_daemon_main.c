/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <stdlib.h> /* exit, EXIT_FAILURE */
#include <dlog/dlog.h>

#include "vpnsvc.h"
#include "vpndbus.h"


#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "VPNSVC_DAEMON"

static GMainLoop *main_loop = NULL;

static void __vpnsvc_got_name_cb(void)
{
	vpnsvc_create_and_init();
}

int main(void)
{
	int ret;

	LOGD("VPN Service");
	if (daemon(0, 0) != 0)
		LOGD("Cannot start daemon");

#if !GLIB_CHECK_VERSION(2, 36, 0)
	g_type_init();
#endif

	main_loop = g_main_loop_new(NULL, FALSE);
	if (main_loop == NULL) {
		LOGE("Couldn't create GMainLoop\n");
		return 0;
	}

	ret = vpnsvc_setup_gdbus(__vpnsvc_got_name_cb);
	if (ret > 0) {
		LOGE("_vpnsvc_setup_gdbus is failed\n");
		return 0;
	}

	g_main_loop_run(main_loop);

	vpnsvc_cleanup_gdbus();

	return 0;
}
