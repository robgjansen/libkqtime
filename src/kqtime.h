#ifndef KQTIME_H_
#define KQTIME_H_

#include <stddef.h>

typedef struct _KQTime KQTime;

typedef void (*KQTimeFoundMatchFunc)(KQTime kqt, int fd,
		struct timeval tsArrived, struct timeval tsMatched);

KQTime* kqtime_new(KQTimeFoundMatchFunc inMatchCallback,
		KQTimeFoundMatchFunc outMatchCallback);
void kqtime_free(KQTime* kqt);
void kqtime_register(KQTime* kqt, int fd);
void kqtime_deregister(KQTime* kqt, int fd);

#endif /* KQTIME_H_ */
