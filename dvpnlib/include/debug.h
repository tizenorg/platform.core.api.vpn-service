#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>

#ifndef RELEASE

#include <dlog.h>

#undef LOG_TAG
#define LOG_TAG "DVPN_LIB"

#define DBG(fmt, arg...) SLOGD(fmt, ##arg)

#define WARN(fmt, arg...) SLOGI(fmt, ##arg)

#define ERROR(fmt, arg...) SLOGE(fmt, ##arg)

#else

#define DBG(fmt, arg...)
#define WARN(fmt, arg...)
#define ERROR(fmt, arg...)

#endif

#endif
