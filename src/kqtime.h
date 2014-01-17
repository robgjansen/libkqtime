#ifndef KQTIME_H_
#define KQTIME_H_

#include <stddef.h>

typedef struct _KQTime KQTime;

typedef void (*KQTimeFoundMatchFunc)(void* fdUserData, int fd,
		struct timeval tsArrived, struct timeval tsMatched);
typedef void (*KQTimeStatsReportFunc)(struct timeval tsCollectStart,
		struct timeval tsCollectEnd, unsigned int numFD, const char* reportString);

KQTime* kqtime_new(KQTimeStatsReportFunc statsReportCallback,
		KQTimeFoundMatchFunc inMatchCallback, KQTimeFoundMatchFunc outMatchCallback);
void kqtime_free(KQTime* kqt);
void* kqtime_register(KQTime* kqt, int fd, void* fdUserData);
void* kqtime_deregister(KQTime* kqt, int fd);

#endif /* KQTIME_H_ */
