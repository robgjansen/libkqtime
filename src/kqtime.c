#include <pcap.h>
#include <glib.h>
#include <string.h>

#include "kqtime.h"
#include "kqtime-preload.h"

#define KQTIME_TAG_LENGTH 16
#define KQTIME_MAX_SEARCH_TIME 2

typedef enum _KQTimeCommandType {
	KQTIME_CMD_NONE, KQTIME_CMD_SEARCH, KQTIME_CMD_EXIT,
} KQTimeCommandType;

typedef struct _KQTimeCommand {
	KQTimeCommandType type;
	gint fd;
	u_char tag[KQTIME_TAG_LENGTH];
	gpointer data;
} KQTimeCommand;

typedef struct _KQTimeWorker {
	GAsyncQueue* commands;
	KQTimeCommand* currentCommand;
	struct timeval searchStartTime;
	pcap_t* pcapHandle;
	KQTimeFoundMatchFunc matchCallback;
} KQTimeWorker;

struct _KQTime {
	struct {
		KQTimePreloadInitFunc init;
		KQTimePreloadRegisterFunc reg;
		KQTimePreloadRegisterFunc dereg;
	} preloadLibFuncs;

	KQTimeWorker* inWorker;
	KQTimeWorker* outWorker;

	GThread* inThread;
	GThread* outThread;
};


static int _kqtime_findByteMatch(const u_char *in, int in_len, const u_char *tag, int tag_len)
{
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

static void _kqtime_inboundInterposedDataHandler(KQTime* kqt,
		gint fd, gconstpointer buf, gsize n) {
	/* this is running in main thread, so keep it as short as possible. */

}

static void _kqtime_outboundInterposedDataHandler(KQTime* kqt,
		gint fd, gconstpointer buf, gsize n) {
	/* this is running in main thread, so keep it as short as possible.
	 * grab tag from buffer. skip 100 bytes for tls offset */
	if(n < 100+KQTIME_TAG_LENGTH) {
		return;
	}

	KQTimeCommand* searchCommand = g_new0(KQTimeCommand, 1);
	searchCommand->type = KQTIME_CMD_SEARCH;
	searchCommand->fd = fd;
	memmove(searchCommand->tag, &((const char*)buf)[100], KQTIME_TAG_LENGTH);
	g_async_queue_push(kqt->outWorker->commands, searchCommand);
}

static void _kqtime_freeCommand(KQTimeCommand* command) {
	if(command) {
		if(command->data) {
			g_free(command->data);
		}
		g_free(command);
	}
}

static void _kqtime_handleInboundPacket(KQTime* kq, const struct pcap_pkthdr *hdr,
                       const u_char *bytes) {

}

static void _kqtime_inboundThread(KQTimeWorker* worker) {
	// ETH2 header is 64 bytes?
	// IP header is 20 bytes min + possible ? bytes for options
	// TCP header is 20 bytes min + possible 80 bytes for options
//	log("Activated. Starting packet capture loop\n");
//	rc = pcap_loop(handle, -1, handle_captured_packet, (u_char *) region);
//	log("Packet capture stopped [%d]\n",rc);
}

static void _kqtime_handleOutboundPacket(KQTimeWorker* worker,
		const struct pcap_pkthdr *hdr, const u_char *bytes) {
	/* check if is is long enough to have data in it */
	if (hdr->len < 100) {
		return;
	}

	/* check if we are looking for a tag */
	if(!worker->currentCommand) {
		worker->currentCommand = g_async_queue_try_pop(worker->commands);

		/* did we just get a new command? */
		if(!worker->currentCommand) {
			return;
		}

		switch(worker->currentCommand->type) {
			case KQTIME_CMD_EXIT:
				_kqtime_freeCommand(worker->currentCommand);
				worker->currentCommand = NULL;
				pcap_breakloop(worker->pcapHandle);
				return;
			case KQTIME_CMD_SEARCH:
				worker->searchStartTime = hdr->ts;
				break;
			case KQTIME_CMD_NONE:
			default:
				return;
		}
	}

	if (hdr->ts.tv_sec - worker->searchStartTime.tv_sec > KQTIME_MAX_SEARCH_TIME) {
		_kqtime_freeCommand(worker->currentCommand);
		worker->currentCommand = NULL;
	};

	int matched = _kqtime_findByteMatch(&bytes[100], hdr->caplen-100,
			(u_char *) worker->currentCommand->tag, KQTIME_TAG_LENGTH);

	if (matched) {
		struct timeval searchEndTime;
		gettimeofday(&searchEndTime, 0);

		worker->matchCallback(NULL, worker->currentCommand->fd,
				worker->searchStartTime, searchEndTime);

		_kqtime_freeCommand(worker->currentCommand);
		worker->currentCommand = NULL;
	}
}

static void _kqtime_outboundThread(KQTimeWorker* worker) {
	log("Outbound Thread Activated. Starting packet capture loop\n");
	int rc = pcap_loop(worker->pcapHandle, -1,
			(pcap_handler)_kqtime_handleOutboundPacket, (u_char*)worker);
	log("Packet capture stopped [%d]\n", rc);
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


void kqtime_free(KQTime* kqt) {
	g_assert(kqt);

	if(kqt->inWorker) {
		if(kqt->inWorker->pcapHandle) {
			pcap_close(kqt->inWorker->pcapHandle);
		}
		if(kqt->inWorker->commands) {
			g_async_queue_unref(kqt->inWorker->commands);
		}
		g_free(kqt->inWorker);
	}

	if(kqt->outWorker) {
		if(kqt->outWorker->pcapHandle) {
			pcap_close(kqt->outWorker->pcapHandle);
		}
		if(kqt->outWorker->commands) {
			g_async_queue_unref(kqt->outWorker->commands);
		}
		g_free(kqt->outWorker);
	}

	if(kqt->inThread) {
		g_thread_join(kqt->inThread);
		g_thread_unref(kqt->inThread);
	}

	if(kqt->outThread) {
		g_thread_join(kqt->outThread);
		g_thread_unref(kqt->outThread);
	}

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
		kqt->inWorker = g_new0(KQTimeWorker, 1);
		kqt->inWorker->matchCallback = inMatchCallback;

		kqt->inWorker->pcapHandle = _kqtime_newPCap(PCAP_D_IN, 300);
		if(!kqt->inWorker->pcapHandle) {
			kqtime_free(kqt);
			return NULL;
		}

		kqt->inWorker->commands = g_async_queue_new();
		kqt->inThread = g_thread_new("kqtime_inbound_worker",
				(GThreadFunc)_kqtime_inboundThread, kqt->inWorker);
	}

	if(outMatchCallback) {
		kqt->outWorker = g_new0(KQTimeWorker, 1);
		kqt->outWorker->matchCallback = outMatchCallback;

		kqt->outWorker->pcapHandle = _kqtime_newPCap(PCAP_D_OUT, 65536);
		if(!kqt->outWorker->pcapHandle) {
			kqtime_free(kqt);
			return NULL;
		}

		kqt->outWorker->commands = g_async_queue_new();
		kqt->outThread = g_thread_new("kqtime_outbound_worker",
				(GThreadFunc)_kqtime_outboundThread, kqt->outWorker);
	}

	log("kqtime: successfully initialized");

	return kqt;
}

void kqtime_register(KQTime* kqt, int fd) {
	g_assert(kqt && kqt->preloadLibFuncs.reg);
	kqt->preloadLibFuncs.reg(fd);
}

void kqtime_deregister(KQTime* kqt, int fd) {
	g_assert(kqt && kqt->preloadLibFuncs.dereg);
	kqt->preloadLibFuncs.dereg(fd);
}
