#define _GNU_SOURCE
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct timezone {
  int tz_minuteswest;
  int tz_dsttime;
};

int clock_gettime(clockid_t clock_id, struct timespec *value) {
  return syscall(SYS_clock_gettime, clock_id, value) == -1 ? -1 : 0;
}

int clock_getres(clockid_t clock_id, struct timespec *value) {
  return syscall(SYS_clock_getres, clock_id, value) == -1 ? -1 : 0;
}

time_t time(time_t *value) {
  long result = syscall(SYS_time, value);
  return result == -1 ? (time_t)-1 : (time_t)result;
}

int gettimeofday(struct timeval *value, struct timezone *zone) {
  return syscall(SYS_gettimeofday, value, zone) == -1 ? -1 : 0;
}

int getcpu(unsigned *cpu, unsigned *node, void *cache) {
  return syscall(SYS_getcpu, cpu, node, cache) == -1 ? -1 : 0;
}
