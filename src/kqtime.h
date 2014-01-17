#ifndef KQTIME_H_
#define KQTIME_H_

typedef struct _KQTime KQTime;

KQTime* kqtime_new(const char* logFilePath, int logBufferStats, int logInTimes, int logOutTimes);
void kqtime_free(KQTime* kqt);
void kqtime_register(KQTime* kqt, int fd, const char* fdName);
void kqtime_deregister(KQTime* kqt, int fd);

#endif /* KQTIME_H_ */
