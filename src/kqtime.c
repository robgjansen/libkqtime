#include <pcap.h>
#include <glib.h>
#include <string.h>

#include "kqtime.h"
#include "kqtime-preload.h"

#define KQTIME_TAG_OFFSET 200
#define KQTIME_TAG_LENGTH 16
#define KQTIME_MAX_SEARCH_TIME 2

typedef enum _KQTimeCommandType {
	KQTIME_CMD_NONE, KQTIME_CMD_READY, KQTIME_CMD_EXIT,
	KQTIME_CMD_TAG, KQTIME_CMD_DATA,
} KQTimeCommandType;

typedef struct _KQTimeCommand {
	KQTimeCommandType type;
} KQTimeCommand;

typedef struct _KQTimeTagCommand {
	KQTimeCommand base;
	gint fd;
	gpointer fdUserData;
	guchar tag[KQTIME_TAG_LENGTH];
	struct timeval tagTime;
} KQTimeTagCommand;

typedef struct _KQTimeDataCommand {
	KQTimeCommand base;
	gint fd;
	gpointer fdUserData;
	gpointer data;
	gint dataLength;
	struct timeval dataTime;
} KQTimeDataCommand;

typedef struct _KQTimePCapWorker {
	GAsyncQueue* commands;
	GAsyncQueue* searchWorkerCommands;
	pcap_t* pcapHandle;
	gboolean isInbound;
} KQTimePCapWorker;

typedef struct _KQTimeSearchWorker {
	GAsyncQueue* commands;
	GAsyncQueue* pcapWorkerCommands;
	KQTimeFoundMatchFunc matchCallback;
	gint fd;
	gpointer fdUserData;
	guchar tag[KQTIME_TAG_LENGTH];
	gboolean hasTag;
	struct timeval tagTime;
} KQTimeSearchWorker;

struct _KQTime {
	struct {
		KQTimePreloadInitFunc init;
		KQTimePreloadRegisterFunc reg;
		KQTimePreloadDeregisterFunc dereg;
	} preloadLibFuncs;

	GThread* inPCapThread;
	KQTimePCapWorker* inPCapWorker;

	GThread* outPCapThread;
	KQTimePCapWorker* outPCapWorker;

	GThread* inSearchThread;
	KQTimeSearchWorker* inSearchWorker;

	GThread* outSearchThread;
	KQTimeSearchWorker* outSearchWorker;
};

/* this is running in main thread, so keep it as short as possible */
static void _kqtime_inboundInterposedDataHandler(KQTime* kqt,
		gint fd, gconstpointer buf, gsize n, gpointer fdData) {
	/* if the worker has a tag, send it data */
	if(kqt->inSearchWorker && kqt->inSearchWorker->hasTag) {
		KQTimeDataCommand* dataCommand = g_new0(KQTimeDataCommand, 1);
		gettimeofday(&dataCommand->dataTime, NULL);
		dataCommand->base.type = KQTIME_CMD_DATA;
		dataCommand->fd = fd;
		dataCommand->fdUserData = fdData;
		dataCommand->dataLength = (gint)n;
		dataCommand->data = g_new(guchar, dataCommand->dataLength);
		memcpy(dataCommand->data,buf, n);
		g_async_queue_push(kqt->outSearchWorker->commands, dataCommand);
	}
}

/* this is running in main thread, so keep it as short as possible */
static void _kqtime_outboundInterposedDataHandler(KQTime* kqt,
		gint fd, gconstpointer buf, gsize n, gpointer fdData) {
	/* if the worker is idle, send it another tag */
	if(kqt->outSearchWorker && !kqt->outSearchWorker->hasTag) {
		if(n < ((gsize) KQTIME_TAG_OFFSET+KQTIME_TAG_LENGTH)) {
			return;
		}

		struct timeval now;
		gettimeofday(&now, NULL);

		KQTimeTagCommand* tagCommand = g_new0(KQTimeTagCommand, 1);
		tagCommand->base.type = KQTIME_CMD_TAG;
		tagCommand->fd = fd;
		tagCommand->fdUserData = fdData;
		tagCommand->tagTime = now;
		memcpy(tagCommand->tag, &((const guchar*)buf)[KQTIME_TAG_OFFSET], KQTIME_TAG_LENGTH);
		g_async_queue_push(kqt->outSearchWorker->commands, tagCommand);
	}
}

static int _kqtime_findByteMatch(const u_char *in, int in_len,
		const u_char *tag, int tag_len) {
  if (tag_len > in_len)
    return 0;

  u_char goal = tag[0];
  int matched = 0;
  const u_char *next = in;

  while(((int)(next - in)) < in_len) {
    if (*next == goal) {
      matched++;
      /*log"Matched %d bytes of %d\n", matched, tag_len);*/
      if (matched == tag_len) {
        return matched;
      }
      goal = tag[matched];
    } else if(matched > 0) {
      /* start over searching from beginning */
      matched = 0;
      goal = tag[matched];
      continue;
    }
    next++;
  }
  return 0;
}

static void _kqtime_searchWorkerThreadMain(KQTimeSearchWorker* worker) {
	gboolean doExit = FALSE;
	gboolean isIdle = FALSE;

	while(!doExit) {
		KQTimeCommand* command = g_async_queue_pop(worker->commands);

		if(!command) {
			continue;
		}

		switch(command->type) {
			case KQTIME_CMD_TAG: {
				if(!worker->hasTag) {
					KQTimeTagCommand* tagCommand = (KQTimeTagCommand*) command;
					memcpy(worker->tag, tagCommand->tag, (gsize)KQTIME_TAG_LENGTH);
					worker->tagTime = tagCommand->tagTime;
					worker->hasTag = TRUE;

					/* tag commands sometimes contains the fd */
					if(tagCommand->fd) {
						worker->fd = tagCommand->fd;
						worker->fdUserData = tagCommand->fdUserData;
					}
				}
				break;
			}

			case KQTIME_CMD_DATA: {
				KQTimeDataCommand* dataCommand = (KQTimeDataCommand*) command;

				if(worker->hasTag) {
					/* check if we probably missed the tag */
					if ((dataCommand->dataTime.tv_sec - worker->tagTime.tv_sec)
							> KQTIME_MAX_SEARCH_TIME) {
						isIdle = TRUE;
					} else {
						/* data commands sometimes contains the fd */
						if(dataCommand->fd) {
							worker->fd = dataCommand->fd;
							worker->fdUserData = dataCommand->fdUserData;
						}

						/* look for a match */
						gint match = _kqtime_findByteMatch((u_char *)dataCommand->data,
								dataCommand->dataLength, (u_char *)worker->tag, KQTIME_TAG_LENGTH);

						/* tell the app we found a match, and the times */
						if (match) {
							worker->matchCallback(worker->fdUserData, worker->fd,
									worker->tagTime, dataCommand->dataTime);
							isIdle = TRUE;
						}
					}
				}

				g_free(dataCommand->data);
				break;
			}

			case KQTIME_CMD_EXIT: {
				doExit = TRUE;
				break;
			}

			case KQTIME_CMD_READY:
			case KQTIME_CMD_NONE:
			default:
				break;
		}

		/* all cmds except data have no internals and can be freed normally */
		g_free(command);

		/* tell the pcap thread if we finished a search */
		if(isIdle) {
			worker->hasTag = FALSE;
			worker->fd = 0;
			worker->fdUserData = NULL;
			command = g_new0(KQTimeCommand, 1);
			command->type = KQTIME_CMD_READY;
			g_async_queue_push(worker->pcapWorkerCommands, command);
			isIdle = FALSE;
		}
	}
}

static void _kqtime_handlePacket(KQTimePCapWorker* worker,
		const struct pcap_pkthdr *hdr, const u_char *bytes) {
	// ETH2 header is 64 bytes?
	// IP header is 20 bytes min + possible ? bytes for options
	// TCP header is 20 bytes min + possible 80 bytes for options
	/* check if it is long enough to have data in it */
	if (hdr->caplen < (KQTIME_TAG_OFFSET+KQTIME_TAG_LENGTH)) {
		return;
	}

	KQTimeCommand* command = g_async_queue_try_pop(worker->commands);

	if(command) {
		KQTimeCommandType type = command->type;
		g_free(command);

		switch(type) {
			case KQTIME_CMD_EXIT: {
				pcap_breakloop(worker->pcapHandle);
				return;
			}

			case KQTIME_CMD_READY: {
				/* if we are inbound, the searcher is ready, send it a tag */
				if(worker->isInbound) {
					KQTimeTagCommand* tagCommand = g_new0(KQTimeTagCommand, 1);
					tagCommand->base.type = KQTIME_CMD_TAG;
					tagCommand->tagTime = hdr->ts;
					memcpy(tagCommand->tag, &bytes[KQTIME_TAG_OFFSET], KQTIME_TAG_LENGTH);

					g_async_queue_push(worker->searchWorkerCommands, tagCommand);
					return;
				}

				/* outbound workers ignore ready commands */
				break;
			}

			case KQTIME_CMD_TAG:
			case KQTIME_CMD_DATA:
			case KQTIME_CMD_NONE:
			default:
				break;
		}
	}

	/* only outbound thread sends data to searcher */
	if(!worker->isInbound) {
		KQTimeDataCommand* dataCommand = g_new0(KQTimeDataCommand, 1);
		dataCommand->base.type = KQTIME_CMD_DATA;
		dataCommand->dataLength = (gint)hdr->caplen;
		dataCommand->dataTime = hdr->ts;
		dataCommand->data = g_new(guchar, dataCommand->dataLength);
		memcpy(dataCommand->data, bytes, (gsize) dataCommand->data);
		g_async_queue_push(worker->searchWorkerCommands, dataCommand);
	}
}

static void _kqtime_pcapWorkerThreadMain(KQTimePCapWorker* worker) {
	log("kqtime: outbound thread activated - starting packet capture loop\n");
	int rc = pcap_loop(worker->pcapHandle, -1,
			(pcap_handler)_kqtime_handlePacket, (u_char*)worker);
	log("kqtime: packet capture stopped [%d]\n", rc);
}

static pcap_t* _kqtime_newPCap(pcap_direction_t pcapdir, int snaplen) {
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;

	pcap_t* handle = pcap_create(NULL, errbuf);
	if(!handle) {
		log("kqtime: error obtaining pcap handle: %s\n", errbuf);
		return NULL;
	}

	if(pcap_set_snaplen(handle, 65536) != 0) {
		log("kqtime: error setting pcap snaplen %d\n", snaplen);
		pcap_close(handle);
		return NULL;
	}

	if(pcap_activate(handle) != 0) {
		log("kqtime: error activating capture device: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return NULL;
	}

	if(pcap_setdirection(handle, pcapdir) != 0) {
		log("kqtime: error setting capture direction: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return NULL;
	}

	if(pcap_compile(handle, &filter, "tcp and not port ssh",
			0, PCAP_NETMASK_UNKNOWN) != 0) {
		log("kqtime: error compiling filter: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return NULL;
	}

	if(pcap_setfilter(handle, &filter) < 0) {
		log("kqtime: error setting filter: %s\n", pcap_geterr(handle));
		pcap_freecode(&filter);
		pcap_close(handle);
		return NULL;
	}

	return handle;
}

static void _kqtime_freePCapThreadWorkerHelper(GThread* thread, KQTimePCapWorker* worker) {
	if(thread) {
		/* tell the thread to exit */
		if(worker && worker->commands) {
			KQTimeCommand* exitCommand = g_new0(KQTimeCommand, 1);
			exitCommand->type = KQTIME_CMD_EXIT;
			g_async_queue_push(worker->commands, exitCommand);
		}

		/* wait for the thread to exit */
		g_thread_join(thread);
		g_thread_unref(thread);
	}

	if(worker) {
		if(worker->pcapHandle) {
			pcap_close(worker->pcapHandle);
		}
		if(worker->commands) {
			g_async_queue_unref(worker->commands);
		}
		g_free(worker);
	}
}

static void _kqtime_freeSearchThreadWorkerHelper(GThread* thread, KQTimeSearchWorker* worker) {
	if(thread) {
		/* tell the thread to exit */
		if(worker && worker->commands) {
			KQTimeCommand* exitCommand = g_new0(KQTimeCommand, 1);
			exitCommand->type = KQTIME_CMD_EXIT;
			g_async_queue_push(worker->commands, exitCommand);
		}

		/* wait for the thread to exit */
		g_thread_join(thread);
		g_thread_unref(thread);
	}

	if(worker) {
		if(worker->commands) {
			g_async_queue_unref(worker->commands);
		}
		g_free(worker);
	}
}

void kqtime_free(KQTime* kqt) {
	g_assert(kqt);

	/* tell the preload lib to stop calling us */
	if(kqt->preloadLibFuncs.init) {
		kqt->preloadLibFuncs.init(NULL, NULL, NULL, NULL, NULL);
	}

	/* cleanup our threads */
	_kqtime_freePCapThreadWorkerHelper(kqt->inPCapThread, kqt->inPCapWorker);
	_kqtime_freePCapThreadWorkerHelper(kqt->outPCapThread, kqt->outPCapWorker);

	_kqtime_freeSearchThreadWorkerHelper(kqt->inSearchThread, kqt->inSearchWorker);
	_kqtime_freeSearchThreadWorkerHelper(kqt->outSearchThread, kqt->outSearchWorker);

	g_free(kqt);
}

KQTime* kqtime_new(KQTimeFoundMatchFunc inMatchCallback,
		KQTimeFoundMatchFunc outMatchCallback) {
	KQTime* kqt = g_new0(KQTime, 1);

	/* lookup the init function in the dynamically loaded preload lib */
	GET_PRELOAD_FUNC(kqt->preloadLibFuncs.init, "kqtime_preload_init");

	if(!kqt->preloadLibFuncs.init) {
		log("kqtime: unable to load kqtime_preload_init");
		kqtime_free(kqt);
		return NULL;
	}

	/* set our interposed application data handlers and get the registration funcs */
	kqt->preloadLibFuncs.init(kqt,
			(KQTimePreloadHandlerFunc) _kqtime_inboundInterposedDataHandler,
			(KQTimePreloadHandlerFunc) _kqtime_outboundInterposedDataHandler,
			&kqt->preloadLibFuncs.reg, &kqt->preloadLibFuncs.dereg);

	if (!kqt->preloadLibFuncs.reg || !kqt->preloadLibFuncs.dereg) {
		log("kqtime: unable to get kqtime-preload registration functions");
		kqtime_free(kqt);
		return NULL;
	}

	if(inMatchCallback) {
		kqt->inPCapWorker = g_new0(KQTimePCapWorker, 1);
		kqt->inPCapWorker->isInbound = TRUE;
		kqt->inPCapWorker->commands = g_async_queue_new();

		kqt->inPCapWorker->pcapHandle = _kqtime_newPCap(PCAP_D_IN, 300);
		if(!kqt->inPCapWorker->pcapHandle) {
			kqtime_free(kqt);
			return NULL;
		}

		kqt->inSearchWorker = g_new0(KQTimeSearchWorker, 1);
		kqt->inSearchWorker->matchCallback = inMatchCallback;
		kqt->inSearchWorker->commands = g_async_queue_new();

		kqt->inPCapWorker->searchWorkerCommands = kqt->inSearchWorker->commands;
		kqt->inSearchWorker->pcapWorkerCommands = kqt->inPCapWorker->commands;

		kqt->inPCapThread = g_thread_new("kqtime-inbound-pcap-worker",
						(GThreadFunc)_kqtime_pcapWorkerThreadMain, kqt->inPCapWorker);
		kqt->inSearchThread = g_thread_new("kqtime-inbound-search-worker",
				(GThreadFunc)_kqtime_searchWorkerThreadMain, kqt->inSearchWorker);
	}

	if(outMatchCallback) {
		kqt->outPCapWorker = g_new0(KQTimePCapWorker, 1);
		kqt->outPCapWorker->isInbound = FALSE;
		kqt->outPCapWorker->commands = g_async_queue_new();

		kqt->outPCapWorker->pcapHandle = _kqtime_newPCap(PCAP_D_OUT, 65536);
		if(!kqt->outPCapWorker->pcapHandle) {
			kqtime_free(kqt);
			return NULL;
		}

		kqt->outSearchWorker = g_new0(KQTimeSearchWorker, 1);
		kqt->outSearchWorker->matchCallback = outMatchCallback;
		kqt->outSearchWorker->commands = g_async_queue_new();

		kqt->outPCapWorker->searchWorkerCommands = kqt->outSearchWorker->commands;
		kqt->outSearchWorker->pcapWorkerCommands = kqt->outPCapWorker->commands;

		kqt->outPCapThread = g_thread_new("kqtime-outbound-pcap-worker",
						(GThreadFunc)_kqtime_pcapWorkerThreadMain, kqt->outPCapWorker);
		kqt->outSearchThread = g_thread_new("kqtime-outbound-search-worker",
				(GThreadFunc)_kqtime_searchWorkerThreadMain, kqt->outSearchWorker);
	}

	log("kqtime: successfully initialized");

	return kqt;
}

void* kqtime_register(KQTime* kqt, int fd, void* fdUserData) {
	g_assert(kqt && kqt->preloadLibFuncs.reg);
	return kqt->preloadLibFuncs.reg(fd, fdUserData);
}

void* kqtime_deregister(KQTime* kqt, int fd) {
	g_assert(kqt && kqt->preloadLibFuncs.dereg);
	return kqt->preloadLibFuncs.dereg(fd);
}
