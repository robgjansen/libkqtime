#include <pcap.h>
#include <glib.h>

#include "kqtime.h"
#include "kqtime-preload.h"

struct _KQTime {
	struct {
		KQTimePreloadInitFunc init;
		KQTimePreloadRegisterFunc reg;
		KQTimePreloadRegisterFunc dereg;
	} preloadLibFuncs;

	KQTimeFoundMatchFunc inMatchCallback;
	KQTimeFoundMatchFunc outMatchCallback;
};

static void _kqtime_inDataHandler(gint fd, gconstpointer buf, gsize n) {

}

static void _kqtime_outDataHandler(gint fd, gconstpointer buf, gsize n) {

}

KQTime* kqtime_new(KQTimeFoundMatchFunc inMatchCallback,
		KQTimeFoundMatchFunc outMatchCallback) {
	KQTime* kqt = g_new0(KQTime, 1);

	/* lookup the init function in the dynamically loaded preload lib */
	GET_PRELOAD_FUNC(kqt->preloadLibFuncs.init, "kqtime_preload_init");

	if(!kqt->preloadLibFuncs.init) {
		log("kqtime: unable to load kqtime_preload_init");
		g_free(kqt);
		return NULL;
	}

	/* set our data handlers and get the registration funcs */
	kqt->preloadLibFuncs.init(_kqtime_inDataHandler, _kqtime_outDataHandler,
			&kqt->preloadLibFuncs.reg, &kqt->preloadLibFuncs.dereg);

	if (!kqt->preloadLibFuncs.reg || !kqt->preloadLibFuncs.dereg) {
		log("kqtime: unable to get kqtime-preload registration functions");
		g_free(kqt);
		return NULL;
	}

	if(inMatchCallback) {
		kqt->inMatchCallback = inMatchCallback;
	}
	if(outMatchCallback) {
		kqt->outMatchCallback = outMatchCallback;
	}

	log("kqtime: successfully initialized");

	return kqt;
}

void kqtime_free(KQTime* kqt) {
	g_assert(kqt);

}

void kqtime_register(KQTime* kqt, int fd) {
	g_assert(kqt && kqt->preloadLibFuncs.reg);
	kqt->preloadLibFuncs.reg(fd);
}

void kqtime_deregister(KQTime* kqt, int fd) {
	g_assert(kqt && kqt->preloadLibFuncs.dereg);
	kqt->preloadLibFuncs.dereg(fd);
}
