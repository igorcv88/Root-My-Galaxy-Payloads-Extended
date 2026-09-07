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
/* The app verifies the feed-declared size and SHA-256 before root. A fixed
 * byte count here would make every legitimate ksud rebuild unusable before
 * the helper itself can be rebuilt. Zero keeps the regular/nonempty checks
 * while treating the app's verified source as the integrity authority. */
#define KSU_EXPECTED_SIZE 0LL
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

/*
 * Promote exactly one verified ksud copy into the path expected by the PR #300
 * helper. Do not fsync here and do not create .ksud-stage here: su_daemon.c's
 * original PR #300 auto-late-load path already creates that stage itself.
 *
 * This constructor executes before umh_main(), and root.c only waits about two
 * seconds for the helper socket. Keeping this to one buffered copy prevents
 * post-root staging I/O from being misclassified as an exploit/root-landing
 * failure while preserving the original PR #300 ordering inside the SELinux
 * permissive handoff window.
 */
static int copy_loader_atomic(const char *source, const char *temporary,
                              const char *destination, off_t expected_size) {
  int in = open(source, O_RDONLY | O_CLOEXEC);
  if (in < 0) {
    return -errno;
  }

  struct stat st;
  if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
      (expected_size > 0 && st.st_size != expected_size)) {
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

  char buffer[256 * 1024];
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

static void invalidate_stale_stage(void) {
  unlink(KSU_LOADER_TMP);
  unlink(KSU_STAGE_TMP);
  unlink(KSU_LOADER_PATH);
  unlink(KSU_STAGE_PATH);
}

__attribute__((constructor)) static void prepare_kernelsu_bootstrap(void) {
  if (geteuid() != 0 || !is_umh_invocation()) {
    return;
  }

  unlink(KSU_STAGE_LOG);
  /* Never let a previous .ksud-stage survive into this boot. The PR #300
   * su_daemon path will recreate it from the freshly promoted loader. */
  unlink(KSU_STAGE_TMP);
  unlink(KSU_STAGE_PATH);

  stage_log("ksu-auto-stage: begin source=%s expected_size=%lld\n",
            APP_KSU_SOURCE, KSU_EXPECTED_SIZE);

  int loader = copy_loader_atomic(APP_KSU_SOURCE,
                                  KSU_LOADER_TMP,
                                  KSU_LOADER_PATH,
                                  (off_t)KSU_EXPECTED_SIZE);
  if (loader != 0) {
    invalidate_stale_stage();
    stage_log("ksu-auto-stage: loader copy failed rc=%d errno=%d; stale stage removed\n",
              loader, -loader);
    return;
  }

  struct stat st;
  if (stat(KSU_LOADER_PATH, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
    stage_log("ksu-auto-stage: loader ready path=%s size=%lld; PR300 stage pending\n",
              KSU_LOADER_PATH, (long long)st.st_size);
  } else {
    invalidate_stale_stage();
    stage_log("ksu-auto-stage: final loader stat failed errno=%d\n", errno);
  }
}
