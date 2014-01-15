#include <string.h>

#include <glib.h>
#include "kqtime-preload.h"

typedef size_t (*SendFunc)(int, const void*, size_t, int);
typedef size_t (*RecvFunc)(int, void*, size_t, int);
typedef size_t (*WriteFunc)(int, const void*, int);
typedef size_t (*ReadFunc)(int, void*, int);

typedef struct _KQTimePreload {
  KQTimePreloadHandlerFunc inHandler;
  KQTimePreloadHandlerFunc outHandler;
  SendFunc send;
  RecvFunc recv;
  WriteFunc write;
  ReadFunc read;
  GHashTable* registry;
} KQTimePreload;

static KQTimePreload _state;

/* this function is called when the library is loaded,
 * and only once per program not once per thread */
void __attribute__((constructor)) construct() {
  /* here we are guaranteed no threads have started yet */
  memset(&_state, 0, sizeof(KQTimePreload));
  GET_SYSTEM_FUNC(_state.send, "send");
  GET_SYSTEM_FUNC(_state.recv, "recv");
  GET_SYSTEM_FUNC(_state.write, "write");
  GET_SYSTEM_FUNC(_state.read, "read");
  _state.registry = g_hash_table_new(g_direct_hash, g_direct_equal);
  log("kqtime-preload: constructed\n");
}

/* this function is called when the library is unloaded */
void __attribute__((destructor)) destruct() {
  g_hash_table_destroy(_state.registry);
  log("kqtime-preload: destructed\n");
}

static void _kqtime_preload_register(int fd) {
  g_hash_table_replace(_state.registry, GINT_TO_POINTER(fd), GINT_TO_POINTER(1));
  log("kqtime-preload: registered descriptor %d\n", fd);
}

static void _kqtime_preload_deregister(int fd) {
  g_hash_table_remove(_state.registry, GINT_TO_POINTER(fd));
  log("kqtime-preload: deregistered descriptor %d\n", fd);
}

void kqtime_preload_init(KQTimePreloadHandlerFunc inHandler,
		KQTimePreloadHandlerFunc outHandler, KQTimePreloadRegisterFunc* reg,
		KQTimePreloadRegisterFunc* dereg) {
	g_assert(reg && dereg);

	_state.inHandler = inHandler;
	_state.outHandler = outHandler;

	*reg = _kqtime_preload_register;
	*dereg = _kqtime_preload_deregister;
}

ssize_t send(int fd, const void *buf, size_t n, int flags) {
	log("kqtime-preload: send() for %d\n", fd);

	/* intercept the sys call and send to handler first, but only if the fd is registered */
	if (_state.outHandler && _state.registry
			&& g_hash_table_lookup(_state.registry, GINT_TO_POINTER(fd))) {
        log("kqtime-preload: send() calling handler for %d\n", fd);
		_state.outHandler(fd, buf, n);
	}

	/* finally, let the OS handle this like normal */
	return _state.send(fd, buf, n, flags);
}

ssize_t recv(int fd, void *buf, size_t n, int flags) {
	log("kqtime-preload: recv() for %d\n", fd);

	/* intercept the sys call and send to handler first, but only if the fd is registered */
	if (_state.inHandler && _state.registry
			&& g_hash_table_lookup(_state.registry, GINT_TO_POINTER(fd))) {
        log("kqtime-preload: recv() calling handler for %d\n", fd);
		_state.inHandler(fd, buf, n);
	}

	/* finally, let the OS handle this like normal */
	return _state.recv(fd, buf, n, flags);
}

ssize_t write(int fd, const void *buf, int n) {
    log("kqtime-preload: write() for %d\n", fd);

	/* intercept the sys call and send to handler first, but only if the fd is registered */
	if (_state.outHandler && _state.registry
			&& g_hash_table_lookup(_state.registry, GINT_TO_POINTER(fd))) {
        log("kqtime-preload: write() calling handler for %d\n", fd);
		_state.outHandler(fd, buf, (size_t) n);
	}

	/* finally, let the OS handle this like normal */
	return _state.write(fd, buf, n);
}

ssize_t read(int fd, void *buf, int n) {
	log("kqtime-preload: read() for %d\n", fd);

	/* intercept the sys call and send to handler first, but only if the fd is registered */
	if (_state.inHandler && _state.registry
			&& g_hash_table_lookup(_state.registry, GINT_TO_POINTER(fd))) {
        log("kqtime-preload: read() calling handler for %d\n", fd);
		_state.inHandler(fd, buf, n);
	}

	/* finally, let the OS handle this like normal */
	return _state.read(fd, buf, n);
}

