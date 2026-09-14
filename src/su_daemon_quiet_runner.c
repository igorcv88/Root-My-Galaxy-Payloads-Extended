/*
 * Root My Galaxy payload-runner overlay.
 *
 * Keep the canonical su/root-daemon implementation intact, but replace only
 * --run-payload supervision: while the scheduler-sensitive payload is alive,
 * the parent blocks in waitpid(2) and performs no 100 ms log-file polling.
 * After the payload exits, the persistent log is relayed once to the transport
 * so callers retain the same post-run diagnostics and child exit status.
 */
#define main su_daemon_original_main
#define payload_runner_main payload_runner_main_live
#include "su_daemon.c"
#undef payload_runner_main
#undef main

static void relay_payload_log_after_exit(const char *path, int transport_fd) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    dprintf(transport_fd, "[runner-tail] open failed errno=%d\n", errno);
    return;
  }

  char buffer[4096];
  for (;;) {
    ssize_t got = read(fd, buffer, sizeof(buffer));
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got <= 0 || !write_full(transport_fd, buffer, (size_t)got)) {
      break;
    }
  }
  close(fd);
}

static int payload_runner_main_quiet(int argc, char **argv) {
  if (argc != 5) {
    return 2;
  }

  int transport_fd = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
  if (transport_fd < 0) {
    return errno;
  }

  int log_fd = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (log_fd < 0 || dup2(log_fd, STDOUT_FILENO) < 0 ||
      dup2(log_fd, STDERR_FILENO) < 0) {
    int saved_errno = errno ? errno : EIO;
    dprintf(transport_fd, "[runner-tail] log setup failed errno=%d\n",
            saved_errno);
    close(transport_fd);
    return saved_errno;
  }
  if (log_fd > STDERR_FILENO) {
    close(log_fd);
  }
  if (setvbuf(stdout, NULL, _IONBF, 0) != 0 ||
      setvbuf(stderr, NULL, _IONBF, 0) != 0) {
    close(transport_fd);
    return errno ? errno : EIO;
  }

  /*
   * Preserve the existing detached payload child, but make the supervisor
   * quiescent for the complete payload lifetime.  No log open/read/usleep
   * loop runs concurrently with FOPS/P0.  The log is consumed only after the
   * child has been reaped.
   */
  signal(SIGHUP, SIG_IGN);
  pid_t payload_pid = fork();
  if (payload_pid < 0) {
    int saved_errno = errno;
    close(transport_fd);
    return saved_errno;
  }

  if (payload_pid > 0) {
    int status = 0;
    pid_t waited;
    do {
      waited = waitpid(payload_pid, &status, 0);
    } while (waited < 0 && errno == EINTR);

    if (waited < 0) {
      int saved_errno = errno;
      relay_payload_log_after_exit(argv[4], transport_fd);
      close(transport_fd);
      return saved_errno;
    }

    relay_payload_log_after_exit(argv[4], transport_fd);
    close(transport_fd);
    if (WIFEXITED(status)) {
      return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
      return 128 + WTERMSIG(status);
    }
    return ECHILD;
  }

  close(transport_fd);
  signal(SIGHUP, SIG_IGN);
  if (prctl(PR_SET_PDEATHSIG, 0) != 0 || setsid() < 0) {
    return errno ? errno : EPERM;
  }
  prctl(PR_SET_NAME, "cve43499-run", 0, 0, 0);

  char root_helper_path[PATH_MAX];
  if (!realpath(argv[3], root_helper_path)) {
    dprintf(STDERR_FILENO,
            "[app] root helper realpath failed path=%s errno=%d\n", argv[3],
            errno);
    return errno ? errno : ENOENT;
  }
  if (setenv("CVE43499_ROOT_HELPER", root_helper_path, 1) != 0) {
    return errno;
  }
  dprintf(STDERR_FILENO, "[app] root helper=%s\n", root_helper_path);
  dprintf(STDERR_FILENO, "[app] loading verified payload=%s\n", argv[2]);
  void *handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    dprintf(STDERR_FILENO, "[app] dlopen failed: %s\n", dlerror());
    return ENOEXEC;
  }
  dprintf(STDERR_FILENO, "[app] payload constructor returned\n");
  fflush(NULL);
  fsync(STDOUT_FILENO);
  return 0;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "--run-payload") == 0) {
    return payload_runner_main_quiet(argc, argv);
  }
  return su_daemon_original_main(argc, argv);
}
