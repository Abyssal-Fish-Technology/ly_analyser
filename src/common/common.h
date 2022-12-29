#ifndef __COMMON_COMMON_H__
#define __COMMON_COMMON_H__

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifdef __APPLE__
  #include <sys/mount.h>
#else
  #include <sys/vfs.h>
#endif
#include <time.h>
#include <unistd.h>
#include <algorithm>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <functional>
#include <memory>
//#include <HTTPHTMLHeader.h>
//#include <HTMLClasses.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef char s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#define nullptr NULL
#define SECONDS_PER_DAY 86400UL
#define MAX_BACKTRACK_DAY 365
#ifndef MAX
#define MAX(a, b)	((a)>(b)?(a):(b))
#endif /* MAX */
#ifndef MIN
#define MIN(a, b)	((a)<(b)?(a):(b))
#endif /* MIN */

#define UNUSED(expr) (void)(expr)

#endif // __COMMON_COMMON_H__
