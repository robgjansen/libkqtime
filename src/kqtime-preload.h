#ifndef KQTIME_PRELOAD_H_
#define KQTIME_PRELOAD_H_

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include <dlfcn.h>

#undef log
#ifdef DEBUG
#define log(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define log(fmt, ...)
#endif

#define SETSYM_OR_FAIL(handle, funcptr, funcstr) { \
	dlerror(); \
	funcptr = dlsym(handle, funcstr); \
	char* errorMessage = dlerror(); \
	if(errorMessage != NULL) { \
		log("dlsym(%s): dlerror(): %s\n", funcstr, errorMessage); \
		exit(EXIT_FAILURE); \
	} else if(funcptr == NULL) { \
		log("dlsym(%s): returned NULL pointer\n", funcstr); \
		exit(EXIT_FAILURE); \
	} \
}

#define GET_SYSTEM_FUNC(funcptr, funcstr) SETSYM_OR_FAIL(RTLD_NEXT, funcptr, funcstr)
#define GET_PRELOAD_FUNC(funcptr, funcstr) SETSYM_OR_FAIL(RTLD_DEFAULT, funcptr, funcstr)

typedef void (*KQTimePreloadHandlerFunc)(int fd, const void* buf, size_t n);
typedef void (*KQTimePreloadRegisterFunc)(int);
typedef void (*KQTimePreloadInitFunc)(KQTimePreloadHandlerFunc,
		KQTimePreloadHandlerFunc, KQTimePreloadRegisterFunc*,
		KQTimePreloadRegisterFunc*);

void kqtime_preload_init(KQTimePreloadHandlerFunc inHandler,
		KQTimePreloadHandlerFunc outHandler, KQTimePreloadRegisterFunc* reg,
		KQTimePreloadRegisterFunc* dereg);

#endif /* KQTIME_PRELOAD_H_ */
