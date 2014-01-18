#include <string.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <pcap.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "kqtime.h"
#include "kqtime-preload.h"

#define KQTIME_TAG_OFFSET 200
#define KQTIME_TAG_LENGTH 16
#define KQTIME_MAX_SEARCH_TIME 2

#undef KQTIME_IOCTL_INQ
#ifdef SIOCINQ
#define KQTIME_IOCTL_INQ SIOCINQ
#elif defined ( TIOCINQ )
#define KQTIME_IOCTL_INQ TIOCINQ
#elif defined ( FIONREAD )
#define KQTIME_IOCTL_INQ FIONREAD
#endif

#undef KQTIME_IOCTL_OUTQ
#ifdef SIOCOUTQ
#define KQTIME_IOCTL_OUTQ SIOCOUTQ
#elif defined ( TIOCOUTQ )
#define KQTIME_IOCTL_OUTQ TIOCOUTQ
#endif

typedef enum _KQTimeCommandType {
	KQTIME_CMD_NONE, KQTIME_CMD_READY, KQTIME_CMD_EXIT,
	KQTIME_CMD_TAG, KQTIME_CMD_DATA, KQTIME_CMD_LOG,
	KQTIME_CMD_ADDFD, KQTIME_CMD_DELFD, KQTIME_CMD_COLLECT,
} KQTimeCommandType;

typedef struct _KQTimeCommand {
	KQTimeCommandType type;
	gint fd;
} KQTimeCommand;

typedef struct _KQTimeFDCommand {
	KQTimeCommand base;
	gchar* fdName;
} KQTimeFDCommand;

typedef struct _KQTimeTagCommand {
	KQTimeCommand base;
	guchar tag[KQTIME_TAG_LENGTH];
	struct timeval tagTime;
} KQTimeTagCommand;

typedef struct _KQTimeDataCommand {
	KQTimeCommand base;
	gpointer data;
	gint dataLength;
	struct timeval dataTime;
} KQTimeDataCommand;

typedef struct _KQTimeLogCommand {
	KQTimeCommand base;
	struct timeval tagTime;
	struct timeval matchTime;
	gboolean isInbound;
} KQTimeLogCommand;

typedef struct _KQTimePCapWorker {
	GAsyncQueue* commands;
	GAsyncQueue* searchWorkerCommands;
	pcap_t* pcapHandle;
	gboolean isInbound;
} KQTimePCapWorker;

typedef struct _KQTimeSearchWorker {
	GAsyncQueue* commands;
	GAsyncQueue* pcapWorkerCommands;
	GAsyncQueue* statsWorkerCommands;
	GAsyncQueue* logWorkerCommands;
	gint fd;
	guchar tag[KQTIME_TAG_LENGTH];
	gboolean hasTag;
	struct timeval tagTime;
	gboolean isInbound;
} KQTimeSearchWorker;

typedef struct _KQTimeStatsWorker {
	GAsyncQueue* commands;
	FILE* logFile;
} KQTimeStatsWorker;

struct _KQTime {
	struct {
		KQTimePreloadInitFunc init;
		KQTimePreloadRegisterFunc reg;
		KQTimePreloadRegisterFunc dereg;
	} preloadLibFuncs;

	GThread* inPCapThread;
	KQTimePCapWorker* inPCapWorker;

	GThread* outPCapThread;
	KQTimePCapWorker* outPCapWorker;

	GThread* inSearchThread;
	KQTimeSearchWorker* inSearchWorker;

	GThread* outSearchThread;
	KQTimeSearchWorker* outSearchWorker;

	GThread* statsThread;
	KQTimeStatsWorker* statsWorker;
};

static const gchar* _kqtime_commandTypeToString(KQTimeCommandType t) {
  switch(t) {
	  case KQTIME_CMD_READY: return "READY";
	  case KQTIME_CMD_EXIT: return "EXIT";
	  case KQTIME_CMD_TAG: return "TAG";
	  case KQTIME_CMD_DATA: return "DATA";
	  case KQTIME_CMD_LOG: return "LOG";
	  case KQTIME_CMD_ADDFD: return "ADDFD";
	  case KQTIME_CMD_DELFD: return "DELFD";
	  case KQTIME_CMD_COLLECT: return "COLLECT";
	  case KQTIME_CMD_NONE: return "NONE";
	  default: break;
  }
  return "ERR";
}

/* this is running in main thread, so keep it as short as possible */
static void _kqtime_inboundInterposedDataHandler(KQTime* kqt,
		gint fd, gconstpointer buf, gsize n) {
	/* if the worker has a tag, send it data */
	if(kqt->inSearchWorker && kqt->inSearchWorker->hasTag) {
		KQTimeDataCommand* dataCommand = g_new0(KQTimeDataCommand, 1);
		gettimeofday(&dataCommand->dataTime, NULL);
		dataCommand->base.type = KQTIME_CMD_DATA;
		dataCommand->base.fd = fd;
		dataCommand->dataLength = (gint)n;
		dataCommand->data = g_new(guchar, dataCommand->dataLength);
		memcpy(dataCommand->data,buf, n);
		g_async_queue_push(kqt->outSearchWorker->commands, dataCommand);
	}
}

/* this is running in main thread, so keep it as short as possible */
static void _kqtime_outboundInterposedDataHandler(KQTime* kqt,
		gint fd, gconstpointer buf, gsize n) {
	/* if the worker is idle, send it another tag */
	if(kqt->outSearchWorker && !kqt->outSearchWorker->hasTag) {
		if(n < ((gsize) KQTIME_TAG_OFFSET+KQTIME_TAG_LENGTH)) {
			return;
		}

		struct timeval now;
		gettimeofday(&now, NULL);

		KQTimeTagCommand* tagCommand = g_new0(KQTimeTagCommand, 1);
		tagCommand->base.type = KQTIME_CMD_TAG;
		tagCommand->base.fd = fd;
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
					if(tagCommand->base.fd) {
						worker->fd = tagCommand->base.fd;
					}

					/* notify the stats worker to collect */
					if(worker->statsWorkerCommands) {
						KQTimeCommand* collectCommand = g_new0(KQTimeCommand, 1);
						collectCommand->type = KQTIME_CMD_COLLECT;
						g_async_queue_push(worker->statsWorkerCommands, collectCommand);
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
						if(dataCommand->base.fd) {
							worker->fd = dataCommand->base.fd;
						}

						/* look for a match */
						gint match = _kqtime_findByteMatch((u_char *)dataCommand->data,
								dataCommand->dataLength, (u_char *)worker->tag, KQTIME_TAG_LENGTH);

						if (match) {
							/* notify the stats worker to collect */
							if(worker->statsWorkerCommands) {
								KQTimeCommand* collectCommand = g_new0(KQTimeCommand, 1);
								collectCommand->type = KQTIME_CMD_COLLECT;
								g_async_queue_push(worker->statsWorkerCommands, collectCommand);
							}

							/* log the fact that we found a match, and the times */
							if(worker->logWorkerCommands) {
								KQTimeLogCommand* logCommand = g_new0(KQTimeLogCommand, 1);
								logCommand->base.type = KQTIME_CMD_LOG;
								logCommand->base.fd = worker->fd;
								logCommand->tagTime = worker->tagTime;
								logCommand->matchTime = dataCommand->dataTime;
								logCommand->isInbound = worker->isInbound;
								g_async_queue_push(worker->logWorkerCommands, logCommand);
							}

							/* we are ready to look for the next match */
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

			default:
				break;
		}

		/* all cmds except data have no internals and can be freed normally */
		g_free(command);

		/* tell the pcap thread if we finished a search */
		if(isIdle) {
			worker->hasTag = FALSE;
			worker->fd = 0;
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
		dataCommand->data = g_malloc((gsize)dataCommand->dataLength);
		memcpy(dataCommand->data, bytes, (gsize) dataCommand->dataLength);
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

static void _kqtime_collectStats(gpointer key, gpointer value, GString* status) {
	if (!key) {
		return;
	}

	gint fd = GPOINTER_TO_INT(key);
	gint numErrors = 0;
	guint sendSize = 0, receiveSize = 0, sendLength = 0, receiveLength = 0;
	socklen_t optionLength;

	optionLength = (socklen_t) sizeof(guint);
	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sendSize, &optionLength) < 0) {
		log("kqtime: failed to obtain SNDBUF for socket %d: %s\n", fd, strerror(errno));
		numErrors++;
	}

	optionLength = (socklen_t) sizeof(guint);
	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receiveSize, &optionLength)
			< 0) {
		log("kqtime: failed to obtain RCVBUF for socket %d: %s\n", fd, strerror(errno));
		numErrors++;
	}

#ifdef KQTIME_IOCTL_OUTQ
	if (ioctl(fd, KQTIME_IOCTL_OUTQ, &sendLength) < 0) {
		log("kqtime: failed to obtain OUTQLEN for socket %d: %s\n", fd, strerror(errno));
		numErrors++;
	}
#endif

#ifdef KQTIME_IOCTL_INQ
	if (ioctl(fd, KQTIME_IOCTL_INQ, &receiveLength) < 0) {
		log("kqtime: failed to obtain INQLEN for socket %d: %s\n", fd, strerror(errno));
		numErrors++;
	}
#endif

	if (numErrors == 0 && status) {
		g_string_append_printf(status,
				"fd=%d,snd_sz=%u,snd_len=%u,rcv_sz=%u,rcv_len=%u;", fd,
				sendSize, sendLength, receiveSize, receiveLength);
	}
}

static void _kqtime_statsWorkerThreadMain(KQTimeStatsWorker* worker) {
	g_assert(worker);

	gboolean doExit = FALSE;
	GHashTable* descs = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

	while (!doExit) {
		/* wait for command */
		KQTimeCommand* command = g_async_queue_pop(worker->commands);

		if (!command) {
			continue;
		}

		log("kqtime: got command %s for fd %d\n",
				_kqtime_commandTypeToString(command->type), command->fd);

		switch (command->type) {
			case KQTIME_CMD_ADDFD: {
				KQTimeFDCommand* fdCommand = (KQTimeFDCommand*) command;
				g_hash_table_replace(descs, GINT_TO_POINTER(command->fd), fdCommand->fdName);
				break;
			}

			case KQTIME_CMD_DELFD: {
				g_hash_table_remove(descs, GINT_TO_POINTER(command->fd));
				break;
			}

			case KQTIME_CMD_COLLECT: {
				guint n = g_hash_table_size(descs);
				if (n == 0) {
					log("kqtime: skipping stats collection on empty hash table\n");
					break;
				}

				GString* status = g_string_new(NULL);

				struct timeval start;
				struct timeval end;

				gettimeofday(&start, NULL);
				g_hash_table_foreach(descs, (GHFunc)_kqtime_collectStats, status);
				gettimeofday(&end, NULL);

				g_fprintf(worker->logFile, "KQTIME-STATS;start=%lu.%06lu,end=%lu.%06lu,num_fds=%u;%s\n",
						(gulong) start.tv_sec, (gulong) start.tv_usec,
						(gulong) end.tv_sec, (gulong) end.tv_usec,
						n, status->str);

				g_string_free(status, TRUE);

				break;
			}

			case KQTIME_CMD_LOG: {
				KQTimeLogCommand* logCommand = (KQTimeLogCommand*) command;

				gchar* fdName = g_hash_table_lookup(descs, GINT_TO_POINTER(logCommand->base.fd));

				g_fprintf(worker->logFile, "KQTIME-%s;start=%lu.%06lu,end=%lu.%06lu,fd=%d;name=%s;\n",
						logCommand->isInbound ? "IN" : "OUT",
						(gulong) logCommand->tagTime.tv_sec, (gulong) logCommand->tagTime.tv_usec,
						(gulong) logCommand->matchTime.tv_sec, (gulong) logCommand->matchTime.tv_usec,
						logCommand->base.fd, fdName ? (gchar*)fdName : "NULL");
				break;
			}

			case KQTIME_CMD_EXIT: {
				doExit = TRUE;
				break;
			}

			default: {
				break;
			}
		}

		g_free(command);
	}

	g_hash_table_destroy(descs);
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

static void _kqtime_freeStatsThreadWorkerHelper(GThread* thread, KQTimeStatsWorker* worker) {
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

	if(worker->logFile) {
		fclose(worker->logFile);
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

	_kqtime_freeStatsThreadWorkerHelper(kqt->statsThread, kqt->statsWorker);

	g_free(kqt);
}

KQTime* kqtime_new(const gchar* logFilePath, gint logBufferStats, gint logInTimes, gint logOutTimes) {
	if(!logFilePath) {
		return NULL;
	}

	KQTime* kqt = g_new0(KQTime, 1);

	/* lookup the init function in the dynamically loaded preload lib */
	GET_PRELOAD_FUNC(kqt->preloadLibFuncs.init, "kqtime_preload_init");

	if(!kqt->preloadLibFuncs.init) {
		log("kqtime: unable to load kqtime_preload_init\n");
		kqtime_free(kqt);
		return NULL;
	}

	/* set our interposed application data handlers and get the registration funcs */
	kqt->preloadLibFuncs.init(kqt,
			(KQTimePreloadHandlerFunc) _kqtime_inboundInterposedDataHandler,
			(KQTimePreloadHandlerFunc) _kqtime_outboundInterposedDataHandler,
			&kqt->preloadLibFuncs.reg, &kqt->preloadLibFuncs.dereg);

	if (!kqt->preloadLibFuncs.reg || !kqt->preloadLibFuncs.dereg) {
		log("kqtime: unable to get kqtime-preload registration functions\n");
		kqtime_free(kqt);
		return NULL;
	}

	/* we use the stats worker to log and to gather info from kernel */
	if(logInTimes || logOutTimes || logBufferStats) {
		kqt->statsWorker = g_new0(KQTimeStatsWorker, 1);
		kqt->statsWorker->commands = g_async_queue_new();

		kqt->statsWorker->logFile = g_fopen(logFilePath, "ab");
		if(!kqt->statsWorker->logFile) {
			log("kqtime: unable to open log file for appending\n");
			kqtime_free(kqt);
			return NULL;
		}
	}

	if(logInTimes) {
		kqt->inPCapWorker = g_new0(KQTimePCapWorker, 1);
		kqt->inPCapWorker->isInbound = TRUE;
		kqt->inPCapWorker->commands = g_async_queue_new();

		kqt->inPCapWorker->pcapHandle = _kqtime_newPCap(PCAP_D_IN, 300);
		if(!kqt->inPCapWorker->pcapHandle) {
			kqtime_free(kqt);
			return NULL;
		}

		kqt->inSearchWorker = g_new0(KQTimeSearchWorker, 1);
		kqt->inSearchWorker->isInbound = TRUE;
		kqt->inSearchWorker->commands = g_async_queue_new();

		/* make sure both inbound workers can communicate */
		kqt->inPCapWorker->searchWorkerCommands = kqt->inSearchWorker->commands;
		kqt->inSearchWorker->pcapWorkerCommands = kqt->inPCapWorker->commands;
		kqt->inSearchWorker->logWorkerCommands = kqt->statsWorker->commands;

		/* start up the threads */
		kqt->inPCapThread = g_thread_new("kqtime-in-pcap",
						(GThreadFunc)_kqtime_pcapWorkerThreadMain, kqt->inPCapWorker);
		kqt->inSearchThread = g_thread_new("kqtime-in-srch",
				(GThreadFunc)_kqtime_searchWorkerThreadMain, kqt->inSearchWorker);
	}

	if(logOutTimes) {
		kqt->outPCapWorker = g_new0(KQTimePCapWorker, 1);
		kqt->outPCapWorker->isInbound = FALSE;
		kqt->outPCapWorker->commands = g_async_queue_new();

		kqt->outPCapWorker->pcapHandle = _kqtime_newPCap(PCAP_D_OUT, 65536);
		if(!kqt->outPCapWorker->pcapHandle) {
			kqtime_free(kqt);
			return NULL;
		}

		kqt->outSearchWorker = g_new0(KQTimeSearchWorker, 1);
		kqt->outSearchWorker->commands = g_async_queue_new();

		/* make sure both outbound workers can communicate */
		kqt->outPCapWorker->searchWorkerCommands = kqt->outSearchWorker->commands;
		kqt->outSearchWorker->pcapWorkerCommands = kqt->outPCapWorker->commands;
		kqt->outSearchWorker->logWorkerCommands = kqt->statsWorker->commands;

		/* start up the threads */
		kqt->outPCapThread = g_thread_new("kqtime-out-pcap",
						(GThreadFunc)_kqtime_pcapWorkerThreadMain, kqt->outPCapWorker);
		kqt->outSearchThread = g_thread_new("kqtime-out-srch",
				(GThreadFunc)_kqtime_searchWorkerThreadMain, kqt->outSearchWorker);
	}

	if(logBufferStats) {
		/* the searchers should tell us when to collect stats */
		if(kqt->inSearchWorker) {
			kqt->inSearchWorker->statsWorkerCommands = kqt->statsWorker->commands;
		}
		if(kqt->outSearchWorker) {
			kqt->outSearchWorker->statsWorkerCommands = kqt->statsWorker->commands;
		}
	}
	/* start the stats/logging thread */
	kqt->statsThread = g_thread_new("kqtime-stats",
			(GThreadFunc)_kqtime_statsWorkerThreadMain, kqt->statsWorker);

	log("kqtime: successfully initialized\n");

	return kqt;
}

void kqtime_register(KQTime* kqt, gint fd, const gchar* fdName) {
	if(fd < 1) {
		return;
	}

	g_assert(kqt && kqt->preloadLibFuncs.reg);

	/* notify the stats worker */
	if(kqt->statsWorker) {
		KQTimeFDCommand* addFDCommand = g_new0(KQTimeFDCommand, 1);
		addFDCommand->base.type = KQTIME_CMD_ADDFD;
		addFDCommand->base.fd = fd;
		addFDCommand->fdName = g_strdup(fdName);
		g_async_queue_push(kqt->statsWorker->commands, addFDCommand);
	}

	kqt->preloadLibFuncs.reg(fd);
}

void kqtime_deregister(KQTime* kqt, gint fd) {
	if(fd < 1) {
		return;
	}

	g_assert(kqt && kqt->preloadLibFuncs.dereg);

	/* notify the stats worker */
	if(kqt->statsWorker) {
		KQTimeCommand* delFDCommand = g_new0(KQTimeCommand, 1);
		delFDCommand->type = KQTIME_CMD_DELFD;
		delFDCommand->fd = fd;
		g_async_queue_push(kqt->statsWorker->commands, delFDCommand);
	}

	kqt->preloadLibFuncs.dereg(fd);
}
