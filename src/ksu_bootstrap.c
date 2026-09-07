#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define APP_KSU_SOURCE "/data/user/0/dev.busung.s25uroot/files/ksu-bootstrap/ksud-s25u-kdp"
#define KSU_LOADER_PATH "/data/local/tmp/ksud-s25u-kdp"
#define KSU_LOADER_TMP "/data/local/tmp/.ksud-loader-refresh"
#define KSU_STAGE_PATH "/data/local/tmp/.ksud-stage"
#define KSU_STAGE_TMP "/data/local/tmp/.ksud-stage-refresh"
#define KSU_STAGE_LOG "/data/local/tmp/ksu_auto_stage.log"

static void stage_log(const char *format, ...) {
  int fd = open(KSU_STAGE_LOG,
                O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                0666);
  if (fd < 0) {
    return;
  }
  va_list ap;
  va_start(ap, format);
  vdprintf(fd, format, ap);
  va_end(ap);
  close(fd);
  chmod(KSU_STAGE_LOG, 0666);
}

static int is_umh_invocation(void) {
  int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  char buffer[4096];
  ssize_t count = read(fd, buffer, sizeof(buffer) - 1);
  close(fd);
  if (count <= 0) {
    return 0;
  }
  buffer[count] = '\0';
  size_t offset = 0;
  while (offset < (size_t)count) {
    const char *arg = buffer + offset;
    size_t len = strnlen(arg, (size_t)count - offset);
    if (strcmp(arg, "--umh") == 0) {
      return 1;
    }
    offset += len + 1;
  }
  return 0;
}

static int copy_atomic(const char *source, const char *temporary,
                       const char *destination) {
  int in = open(source, O_RDONLY | O_CLOEXEC);
  if (in < 0) {
    return -errno;
  }
  struct stat st;
  if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
    int saved = errno ? errno : EINVAL;
    close(in);
    return -saved;
  }

  unlink(temporary);
  int out = open(temporary,
                 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                 0755);
  if (out < 0) {
    int saved = errno;
    close(in);
    return -saved;
  }

  char buffer[128 * 1024];
  int result = 0;
  for (;;) {
    ssize_t got = read(in, buffer, sizeof(buffer));
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got < 0) {
      result = -errno;
      break;
    }
    if (got == 0) {
      break;
    }
    ssize_t offset = 0;
    while (offset < got) {
      ssize_t written = write(out, buffer + offset, (size_t)(got - offset));
      if (written < 0 && errno == EINTR) {
        continue;
      }
      if (written <= 0) {
        result = -(errno ? errno : EIO);
        break;
      }
      offset += written;
    }
    if (result != 0) {
      break;
    }
  }

  if (result == 0 && fsync(out) != 0) {
    result = -errno;
  }
  if (result == 0 && fchmod(out, 0755) != 0) {
    result = -errno;
  }
  if (result == 0) {
    (void)fchown(out, 0, 0);
  }
  close(out);
  close(in);

  if (result == 0 && rename(temporary, destination) != 0) {
    result = -errno;
  }
  if (result != 0) {
    unlink(temporary);
  }
  return result;
}

/*
 * The constructor runs only for the kernel UMH invocation. At that point the
 * exploit has already obtained UID 0 and temporarily disabled SELinux
 * enforcing, but KernelSU has not been late-loaded yet.
 *
 * Standalone Auto Root deliberately cannot touch /data/local/tmp pre-root.
 * The Android app therefore keeps the feed-verified ksud in a deterministic
 * app-private path. Promote that exact source into the two locations required
 * by the CZG3 v3.3.0 late-load handoff before su_daemon.c starts its existing
 * auto-late-load sequence.
 *
 * This is post-race work: no exploit/FOPS/KASLR timing is changed.
 */
__attribute__((constructor)) static void prepare_kernelsu_bootstrap(void) {
  if (geteuid() != 0 || !is_umh_invocation()) {
    return;
  }

  unlink(KSU_STAGE_LOG);
  stage_log("ksu-auto-stage: begin source=%s\n", APP_KSU_SOURCE);

  int loader = copy_atomic(APP_KSU_SOURCE, KSU_LOADER_TMP, KSU_LOADER_PATH);
  if (loader != 0) {
    stage_log("ksu-auto-stage: loader copy failed rc=%d errno=%d\n",
              loader, -loader);
    return;
  }

  int stage = copy_atomic(KSU_LOADER_PATH, KSU_STAGE_TMP, KSU_STAGE_PATH);
  if (stage != 0) {
    stage_log("ksu-auto-stage: .ksud-stage copy failed rc=%d errno=%d\n",
              stage, -stage);
    return;
  }

  struct stat st;
  if (stat(KSU_LOADER_PATH, &st) == 0) {
    stage_log("ksu-auto-stage: ready loader=%s stage=%s size=%lld\n",
              KSU_LOADER_PATH, KSU_STAGE_PATH, (long long)st.st_size);
  } else {
    stage_log("ksu-auto-stage: ready loader=%s stage=%s\n",
              KSU_LOADER_PATH, KSU_STAGE_PATH);
  }
}
