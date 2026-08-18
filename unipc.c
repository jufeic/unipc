#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int write_file(const char *path, const char *content)
{
    /*
     * 0600 when creating new files, e.g. daemon_global.pid and
     * user_ns_global.inum
     */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        return -1;
    }

    size_t len = strlen(content);
    ssize_t written = write(fd, content, len);
    close(fd);

    return (written == (ssize_t)len) ? 0 : -1;
}

int map_current_user()
{
    int rc;
    char map[128];
    uid_t uid = getuid();
    gid_t gid = getgid();

    rc = -1;

    if (write_file("/proc/self/setgroups", "deny") != 0)
    {
        perror("Failed to deny setgroups");
        goto EXIT;
    }

    snprintf(map, sizeof(map), "%u %u 1\n", uid, uid);
    if (write_file("/proc/self/uid_map", map) != 0)
    {
        perror("Failed to map UID");
        goto EXIT;
    }

    snprintf(map, sizeof(map), "%u %u 1\n", gid, gid);
    if (write_file("/proc/self/gid_map", map) != 0)
    {
        perror("Failed to map GID");
        goto EXIT;
    }

    rc = 0;
EXIT:
    return rc;
}

/*
 * the only process with a start time of 0 is kernels idle process (PID 0)
 */
unsigned long long get_process_starttime(pid_t pid)
{
    char path_proc_pid_stat[64];
    snprintf(path_proc_pid_stat, sizeof(path_proc_pid_stat), "/proc/%d/stat",
             pid);

    int fd = open(path_proc_pid_stat, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        return 0;
    }

    /*
     * Buffer size to read /proc/<pid>/stat:
     * field 1 (pid): %d (32-bit signed int): 11 characters
     * field 2 (comm): %s (format: "(N)"); N = TASK_COMM_LEN - 1 = 15 + '(' +
     * ')' = 17 characters
     * field 3 (state): %c: 1 character
     * field 4-52: %lu (64-bit integers): 20 characters * 49 fields = 980
     * characters
     * Spaces between 52 fields: 51 characters
     * newline at the end: 1 character
     * Total: 11 + 17 + 1 + 980 + 51 + 1 = 1061 characters
     */
    char buf_stat[2048];
    ssize_t n = read(fd, buf_stat, sizeof(buf_stat) - 1);
    close(fd);
    if (n <= 0)
    {
        return 0;
    }
    buf_stat[n] = '\0';

    /*
     * Find last closing parenthesis to skip process name which could contain
     * spaces.
     * Example: "123 (my process) S 456 ..."
     */
    char *p = strrchr(buf_stat, ')');
    if (!p)
    {
        return 0;
    }

    /* Move pointer past the ") " to start exactly at field 3 (state) */
    p += 2;

    /* Tokenize the remaining string by spaces */
    char *saveptr;
    char *token = strtok_r(p, " ", &saveptr);

    /* Since we skipped field 1 and 2, the first token is field 3 */
    int current_field = 3;

    while (token != NULL)
    {
        /* 'starttime' value is the 22nd field */
        if (current_field == 22)
        {
            return strtoull(token, NULL, 10);
        }
        token = strtok_r(NULL, " ", &saveptr);
        current_field++;
    }

    return 0;
}

int register_current_process(const char *processes_dir)
{
    pid_t current_pid = getpid();
    unsigned long long current_starttime = get_process_starttime(current_pid);
    if (current_starttime == 0)
    {
        return -1;
    }

    char process_file[PATH_MAX];
    snprintf(process_file, sizeof(process_file), "%s/%d-%llu", processes_dir,
             current_pid, current_starttime);
    int fd = open(process_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
    {
        return -1;
    }
    close(fd);

    return 0;
}

int try_connect_daemon(const char *pid_file, pid_t *pid_daemon, int *fd_user_ns,
                       int *fd_ipc_ns)
{
    int rc = -1;
    FILE *fd_pid = fopen(pid_file, "r");
    if (!fd_pid)
    {
        return rc;
    }

    pid_t pid_stored;
    unsigned long long starttime_stored;

    if (fscanf(fd_pid, "%d\n%llu", &pid_stored, &starttime_stored) == 2)
    {
        if (kill(pid_stored, 0) == 0)
        {
            /*
             * early pinning:
             * pin the user and ipc namespace before even checking with
             * the start time that the stored pid still matches the same
             * daemon process. If we would first check the start time, then
             * the daemon terminates and the pid is reused by a new process
             * before we call open, we would access the wrong namespaces.
             *
             * This mechanism (open fd for /proc/<pid>/ns/ file) pins the
             * namespaces and prevents the deletion of the namespaces even
             * if there is no process left in the namespace (man 7
             * namespaces).
             */
            char path_proc_pid_ns[256];
            snprintf(path_proc_pid_ns, sizeof(path_proc_pid_ns),
                     "/proc/%d/ns/user", pid_stored);
            int fd_user_ns_tmp = open(path_proc_pid_ns, O_RDONLY | O_CLOEXEC);

            snprintf(path_proc_pid_ns, sizeof(path_proc_pid_ns),
                     "/proc/%d/ns/ipc", pid_stored);
            int fd_ipc_ns_tmp = open(path_proc_pid_ns, O_RDONLY | O_CLOEXEC);

            if (fd_user_ns_tmp >= 0 && fd_ipc_ns_tmp >= 0)
            {
                unsigned long long actual_starttime =
                    get_process_starttime(pid_stored);
                if (actual_starttime > 0 &&
                    actual_starttime == starttime_stored)
                {
                    /*
                     * Success: pid is alive and not reused
                     */
                    *pid_daemon = pid_stored;
                    *fd_user_ns = fd_user_ns_tmp;
                    *fd_ipc_ns = fd_ipc_ns_tmp;
                    rc = 0;
                }
                else
                {
                    /*
                     * Fail: Start times do not match, pid was reused
                     */
                    close(fd_user_ns_tmp);
                    close(fd_ipc_ns_tmp);
                }
            }
            else
            {
                /*
                 * Fail: Race condition
                 *
                 * Daemon process died after kill(<pid>, 0) check but before
                 * opening / pinning the /proc/<pid>/ns/ files.
                 */
                if (fd_user_ns_tmp >= 0)
                {
                    close(fd_user_ns_tmp);
                }
                if (fd_ipc_ns_tmp >= 0)
                {
                    close(fd_ipc_ns_tmp);
                }
            }
        }
    }
    fclose(fd_pid);

    return rc;
}

int cleanup_and_find_survivor(const char *processes_dir,
                              const char *user_ns_inum_file,
                              const char *ipc_ns_inum_file, int *fd_user_ns,
                              int *fd_ipc_ns)
{
    DIR *dir = opendir(processes_dir);
    if (!dir)
    {
        return -1;
    }

    char target_user_ns_inum[256] = {0};
    char target_ipc_ns_inum[256] = {0};

    int f1 = open(user_ns_inum_file, O_RDONLY | O_CLOEXEC);
    int f2 = open(ipc_ns_inum_file, O_RDONLY | O_CLOEXEC);
    if (f1 >= 0)
    {
        read(f1, target_user_ns_inum, sizeof(target_user_ns_inum) - 1);
        close(f1);
    }
    if (f2 >= 0)
    {
        read(f2, target_ipc_ns_inum, sizeof(target_ipc_ns_inum) - 1);
        close(f2);
    }

    struct dirent *ent;
    pid_t survivor_pid = -1;

    while ((ent = readdir(dir)) != NULL)
    {
        if (ent->d_name[0] == '.')
        {
            continue;
        }

        pid_t pid = 0;
        unsigned long long stored_starttime = 0;
        if (sscanf(ent->d_name, "%d-%llu", &pid, &stored_starttime) != 2)
        {
            continue;
        }

        char file_path[PATH_MAX];
        snprintf(file_path, sizeof(file_path), "%s/%s", processes_dir,
                 ent->d_name);

        if (kill(pid, 0) != 0 || get_process_starttime(pid) != stored_starttime)
        {
            unlink(file_path);
            continue;
        }

        if (survivor_pid == -1 && target_user_ns_inum[0] != '\0' &&
            target_ipc_ns_inum[0] != '\0')
        {
            char path_ns[128];
            snprintf(path_ns, sizeof(path_ns), "/proc/%d/ns/user", pid);
            int fd_u = open(path_ns, O_RDONLY | O_CLOEXEC);

            snprintf(path_ns, sizeof(path_ns), "/proc/%d/ns/ipc", pid);
            int fd_i = open(path_ns, O_RDONLY | O_CLOEXEC);

            if (fd_u >= 0 && fd_i >= 0)
            {
                char cand_user[256] = {0};
                char cand_ipc[256] = {0};
                snprintf(path_ns, sizeof(path_ns), "/proc/%d/ns/user", pid);
                ssize_t len_cand_user =
                    readlink(path_ns, cand_user, sizeof(cand_user) - 1);
                snprintf(path_ns, sizeof(path_ns), "/proc/%d/ns/ipc", pid);
                ssize_t len_cand_ipc =
                    readlink(path_ns, cand_ipc, sizeof(cand_ipc) - 1);

                if (len_cand_user > 0 && len_cand_ipc > 0 &&
                    strcmp(cand_user, target_user_ns_inum) == 0 &&
                    strcmp(cand_ipc, target_ipc_ns_inum) == 0)
                {
                    *fd_user_ns = fd_u;
                    *fd_ipc_ns = fd_i;
                    survivor_pid = pid;
                }
                else
                {
                    close(fd_u);
                    close(fd_i);
                }
            }
            else
            {
                if (fd_u >= 0)
                {
                    close(fd_u);
                }
                if (fd_i >= 0)
                {
                    close(fd_i);
                }
            }
        }
    }

    closedir(dir);
    return survivor_pid;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ns_group = "global";

    char runtime_dir[PATH_MAX];
    const char *xdg_runtime = getenv("XDG_RUNTIME_DIR");

    /*
     * Runtime directory: $XDG_RUNTIME_DIR or /tmp
     *
     * Both directories are on a file system of type tmpfs
     * (see findmnt -T <dir>). Therefore, all files are in kernel memory
     * and wiped on reboot.
     */
    if (xdg_runtime && xdg_runtime[0] != '\0' &&
        strlen(xdg_runtime) < (PATH_MAX - 128))
    {
        snprintf(runtime_dir, sizeof(runtime_dir), "%s/unipc", xdg_runtime);
    }
    else
    {
        snprintf(runtime_dir, sizeof(runtime_dir), "/tmp/unipc-%d", getuid());
    }

    if (mkdir(runtime_dir, 0700) != 0 && errno != EEXIST)
    {
        perror("Failed to create unipc runtime directory");
        return EXIT_FAILURE;
    }

    char processes_dir[PATH_MAX];
    snprintf(processes_dir, sizeof(processes_dir), "%s/processes", runtime_dir);
    if (mkdir(processes_dir, 0700) != 0 && errno != EEXIST)
    {
        perror("Failed to create unipc processes directory");
        return EXIT_FAILURE;
    }

    struct stat st;
    if (lstat(runtime_dir, &st) != 0)
    {
        perror("Failed to stat runtime directory");
        return EXIT_FAILURE;
    }

    /* must be a real directory (no symlink or regular file attacks on /tmp) */
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid() ||
        (st.st_mode & 0777) != 0700)
    {
        fprintf(stderr,
                "Error: Runtime directory %s has unsafe ownership or "
                "permissions.\n",
                runtime_dir);
        return EXIT_FAILURE;
    }

    char pid_file[PATH_MAX];
    char user_ns_inum_file[PATH_MAX];
    char ipc_ns_inum_file[PATH_MAX];
    char lock_file[PATH_MAX];
    snprintf(pid_file, sizeof(pid_file), "%s/daemon_%s.pid", runtime_dir,
             ns_group);
    snprintf(user_ns_inum_file, sizeof(user_ns_inum_file), "%s/user_ns_%s.inum",
             runtime_dir, ns_group);
    snprintf(ipc_ns_inum_file, sizeof(ipc_ns_inum_file), "%s/ipc_ns_%s.inum",
             runtime_dir, ns_group);
    snprintf(lock_file, sizeof(lock_file), "%s/unipc_%s.lock", runtime_dir,
             ns_group);

    /*
     * FAST PATH:
     *
     * Only checking if the user ns inum of the current unipc process
     * matches the stored user ns inum of the daemon is not sufficient.
     * A process in host initial user and ipc ns could join only the user ns of
     * the daemon but stay in its ipc ns, e.g.
     * nsenter -t <daemon_pid> -U --preserve-credentials bash
     *
     * When only checking user ns, unipc would directly execute the program
     * but then in the wrong ipc ns.
     */
    char current_user_ns_inum[256] = {0};
    char current_ipc_ns_inum[256] = {0};

    ssize_t len_current_user_ns_inum =
        readlink("/proc/self/ns/user", current_user_ns_inum,
                 sizeof(current_user_ns_inum) - 1);
    ssize_t len_current_ipc_ns_inum =
        readlink("/proc/self/ns/ipc", current_ipc_ns_inum,
                 sizeof(current_ipc_ns_inum) - 1);
    if (len_current_user_ns_inum <= 0 || len_current_ipc_ns_inum <= 0)
    {
        fprintf(stderr, "Failed to determine current namespace inums\n");
        return EXIT_FAILURE;
    }

    int lock_fd = open(lock_file, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0)
    {
        fprintf(stderr, "Could not open lock file\n");
        return EXIT_FAILURE;
    }
    if (flock(lock_fd, LOCK_SH) != 0)
    {
        fprintf(stderr, "Could not acquire lock file\n");
        close(lock_fd);
        return EXIT_FAILURE;
    }

    int fd_user_ns_inum = open(user_ns_inum_file, O_RDONLY | O_CLOEXEC);
    int fd_ipc_ns_inum = open(ipc_ns_inum_file, O_RDONLY | O_CLOEXEC);
    if (fd_user_ns_inum >= 0 && fd_ipc_ns_inum >= 0)
    {
        char target_user_ns_inum[256] = {0};
        char target_ipc_ns_inum[256] = {0};
        ssize_t bytes_read_user = read(fd_user_ns_inum, target_user_ns_inum,
                                       sizeof(target_user_ns_inum) - 1);
        ssize_t bytes_read_ipc = read(fd_ipc_ns_inum, target_ipc_ns_inum,
                                      sizeof(target_ipc_ns_inum) - 1);
        close(fd_user_ns_inum);
        close(fd_ipc_ns_inum);

        if (bytes_read_user > 0 && bytes_read_ipc > 0 &&
            strcmp(current_user_ns_inum, target_user_ns_inum) == 0 &&
            strcmp(current_ipc_ns_inum, target_ipc_ns_inum) == 0)
        {
            /* Fast path taken: execute directly */
            if (register_current_process(processes_dir) != 0)
            {
                fprintf(stderr, "Failed to register process\n");
                return EXIT_FAILURE;
            }

            /* O_CLOEXEC ensures lock_fd is closed on exec */
            execvp(argv[1], &argv[1]);
            perror("execvp (Fast path failed)");
            return EXIT_FAILURE;
        }
    }
    if (fd_user_ns_inum >= 0)
    {
        close(fd_user_ns_inum);
    }
    if (fd_ipc_ns_inum >= 0)
    {
        close(fd_ipc_ns_inum);
    }

    /* Fast path failed: release shared lock */
    flock(lock_fd, LOCK_UN);
    close(lock_fd);

    pid_t pid_daemon = -1;
    int fd_user_ns = -1;
    int fd_ipc_ns = -1;

    if (try_connect_daemon(pid_file, &pid_daemon, &fd_user_ns, &fd_ipc_ns) != 0)
    {
        /*
         * Cannot retrieve ns fds of daemon. Some unipc process must spawn
         * a new daemon. The new daemon process either joins the user and ipc
         * ns of an existing unipc survivor process or unshares to create new
         * user and ipc ns.
         */
        int lock_fd = open(lock_file, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (lock_fd < 0)
        {
            fprintf(stderr, "Could not open lock file\n");
            return EXIT_FAILURE;
        }
        if (flock(lock_fd, LOCK_EX) != 0)
        {
            fprintf(stderr, "Could not acquire lock file\n");
            close(lock_fd);
            return EXIT_FAILURE;
        }

        /* Critical section starts */

        /*
         * Double-check if there is an existing daemon. Necessary because
         * it is possible that while unipc process A waits for the lock,
         * unipc process B already spawned a new daemon whose namespaces we
         * can join.
         */
        if (try_connect_daemon(pid_file, &pid_daemon, &fd_user_ns,
                               &fd_ipc_ns) != 0)
        {
            int survivor_fd_user_ns = -1;
            int survivor_fd_ipc_ns = -1;

            pid_t survivor = cleanup_and_find_survivor(
                processes_dir, user_ns_inum_file, ipc_ns_inum_file,
                &survivor_fd_user_ns, &survivor_fd_ipc_ns);
            if (survivor > 0 && survivor_fd_user_ns >= 0 &&
                survivor_fd_ipc_ns >= 0)
            {
                /*
                 * Taking this path if:
                 *  - no daemon process exists, even after the double-check
                 *    after acquiring the lock
                 *  - a surviving unipc process is remaining in the user and
                 *    ipc namespace
                 *
                 * Instead of just interpreting the survivor as the new daemon
                 * and joining it without creating a new daemon, we fork to
                 * create a new daemon process. That daemon process joins the
                 * user and ipc ns of the survivor.
                 */
                int sync_pipe[2];
                if (pipe2(sync_pipe, O_CLOEXEC) != 0)
                {
                    close(survivor_fd_user_ns);
                    close(survivor_fd_ipc_ns);
                    flock(lock_fd, LOCK_UN);
                    close(lock_fd);
                    return EXIT_FAILURE;
                }

                pid_t pid_child = fork();
                if (pid_child < 0)
                {
                    close(survivor_fd_user_ns);
                    close(survivor_fd_ipc_ns);
                    close(sync_pipe[0]);
                    close(sync_pipe[1]);
                    flock(lock_fd, LOCK_UN);
                    close(lock_fd);
                    return EXIT_FAILURE;
                }

                if (pid_child == 0)
                {
                    /* close read end */
                    close(sync_pipe[0]);
                    /* close inherited lock fd */
                    close(lock_fd);

                    if (setsid() < 0)
                    {
                        perror("setsid() failed");
                        exit(EXIT_FAILURE);
                    }

                    if (setns(survivor_fd_user_ns, CLONE_NEWUSER) != 0)
                    {
                        perror("Daemon failed to join user ns");
                        exit(EXIT_FAILURE);
                    }

                    if (setns(survivor_fd_ipc_ns, CLONE_NEWIPC) != 0)
                    {
                        perror("Daemon failed to join ipc ns");
                        exit(EXIT_FAILURE);
                    }
                    close(survivor_fd_user_ns);
                    close(survivor_fd_ipc_ns);

                    unsigned long long starttime_daemon =
                        get_process_starttime(getpid());
                    char pid_file_content[128];
                    snprintf(pid_file_content, sizeof(pid_file_content),
                             "%d\n%llu\n", getpid(), starttime_daemon);
                    if (write_file(pid_file, pid_file_content) != 0)
                    {
                        perror("Failed to write pid file");
                        return EXIT_FAILURE;
                    }

                    if (write(sync_pipe[1], "K", 1) != 1)
                    {
                        exit(EXIT_FAILURE);
                    }
                    close(sync_pipe[1]);

                    while (1)
                    {
                        pause();
                    }
                    exit(EXIT_SUCCESS);
                }

                /* close write end */
                close(sync_pipe[1]);
                char ready_signal;

                if (read(sync_pipe[0], &ready_signal, 1) <= 0)
                {
                    close(survivor_fd_user_ns);
                    close(survivor_fd_ipc_ns);
                    close(sync_pipe[0]);
                    flock(lock_fd, LOCK_UN);
                    close(lock_fd);
                    return EXIT_FAILURE;
                }
                close(sync_pipe[0]);

                pid_daemon = pid_child;
                /*
                 * The daemon used the fds of the survivor to join those
                 * namespaces so they already reference the right namespaces.
                 */
                fd_user_ns = survivor_fd_user_ns;
                fd_ipc_ns = survivor_fd_ipc_ns;
            }
            else
            {
                /*
                 * Taking this path if:
                 *  - no daemon process exists, even after the double-check
                 *    after acquiring the lock
                 *  - no other unipc process is remaining in the user and
                 *    ipc namespace
                 */
                int sync_pipe[2];
                /* ensure the pipe does not leak into the exec'd process */
                if (pipe2(sync_pipe, O_CLOEXEC) != 0)
                {
                    perror("pipe2() failed");
                    flock(lock_fd, LOCK_UN);
                    close(lock_fd);
                    return EXIT_FAILURE;
                }

                pid_t pid_child = fork();
                if (pid_child < 0)
                {
                    perror("fork() failed");
                    flock(lock_fd, LOCK_UN);
                    close(lock_fd);
                    return EXIT_FAILURE;
                }

                if (pid_child == 0)
                {
                    /* close read end */
                    close(sync_pipe[0]);
                    /* close inherited lock fd */
                    close(lock_fd);

                    if (setsid() < 0)
                    {
                        perror("setsid() failed");
                        exit(EXIT_FAILURE);
                    }

                    if (unshare(CLONE_NEWUSER | CLONE_NEWIPC) != 0)
                    {
                        perror("unshare() failed");
                        exit(EXIT_FAILURE);
                    }

                    /*
                     * After successfully creating a new user and ipc ns, the
                     * daemon gains a full set of capabilities in that user ns
                     * (man 7 user_namespaces).
                     *
                     * Therefore, the daemon has CAP_SETUID/CAP_SETGID in the
                     * user ns of the process it writes the uid_map and gid_map
                     * files (which is this user ns). The daemon writes its own
                     * mapping and underlies the restrictions to map the writing
                     * processes EUID in the parent user ns, to have the same
                     * EUID as process that created the user ns and do deny the
                     * use of the setgroups() syscall.
                     */
                    if (map_current_user() != 0)
                    {
                        perror("Mapping of user failed");
                        exit(EXIT_FAILURE);
                    }

                    /*
                     * The daemon itself writes the user ns inum. Readiness of
                     * the /proc/<pid>/ns/ files is the reason why we do not
                     * want to read those from the parent wrapper. Inside the
                     * new process, we can be completely sure to access those
                     * files.
                     */
                    char daemon_user_ns_inum[256] = {0};
                    char daemon_ipc_ns_inum[256] = {0};
                    ssize_t len_daemon_user_ns_inum =
                        readlink("/proc/self/ns/user", daemon_user_ns_inum,
                                 sizeof(daemon_user_ns_inum) - 1);
                    if (len_daemon_user_ns_inum < 0)
                    {
                        perror("Reading user ns inum failed");
                        exit(EXIT_FAILURE);
                    }
                    ssize_t len_daemon_ipc_ns_inum =
                        readlink("/proc/self/ns/ipc", daemon_ipc_ns_inum,
                                 sizeof(daemon_ipc_ns_inum) - 1);
                    if (len_daemon_ipc_ns_inum < 0)
                    {
                        perror("Reading ipc ns inum failed");
                        exit(EXIT_FAILURE);
                    }

                    if (write_file(user_ns_inum_file, daemon_user_ns_inum) != 0)
                    {
                        perror("Writing user ns inum file failed");
                        exit(EXIT_FAILURE);
                    }

                    if (write_file(ipc_ns_inum_file, daemon_ipc_ns_inum) != 0)
                    {
                        perror("Writing ipc ns inum file failed");
                        exit(EXIT_FAILURE);
                    }

                    /* Signal parent that namespace files are configured */
                    if (write(sync_pipe[1], "K", 1) != 1)
                    {
                        perror("Failed to notify parent");
                        exit(EXIT_FAILURE);
                    }
                    close(sync_pipe[1]);

                    /*
                     * Sleep forever in the kernel holding the namespaces open
                     */
                    while (1)
                    {
                        pause();
                    }
                    exit(EXIT_SUCCESS);
                }

                /* close write end */
                close(sync_pipe[1]);

                /*
                 * "If all fds referring to write end of a pipe have been
                 * closed, a read from the pipe will see end-of-file and read()
                 * will return 0." (man 7 pipe) The parent closed the write end
                 * and if the daemon (child) is killed or crashes or just
                 * terminates with an error if something like unshare() fails,
                 * before the daemon was able to write to the pipe, the kernel
                 * closes all open fds owned by that process.
                 *
                 * If the daemon calls exit(), glibc calls _exit() (man 2 _exit)
                 * which executes the exit syscall. The kernel calls the
                 * do_exit() syscall handler that does all the teardown and
                 * cleanup of the process, e.g. calling exit_files() to close
                 * all open fds. In case of a SIGKILL, the exact same kernel
                 * function do_exit() is part of the chain.
                 *
                 * Therefore, all fds referring to write end are closed. The
                 * read() will not block the parent forever.
                 */
                char ready_signal;
                if (read(sync_pipe[0], &ready_signal, 1) <= 0)
                {
                    perror("Daemon failed to initialize");
                    flock(lock_fd, LOCK_UN);
                    close(lock_fd);
                    return EXIT_FAILURE;
                }
                close(sync_pipe[0]);

                pid_daemon = pid_child;
                /*
                 * After syncing, we are sure that /proc/<daemon_pid>/ns/ files
                 * are accessible so we attempt to directly pin those namespaces
                 * so that even if the daemon dies, we try to minimize this
                 * time frame. After pinning, it does not matter if the daemon
                 * dies.
                 */
                char path_proc_pid_ns[256];
                snprintf(path_proc_pid_ns, sizeof(path_proc_pid_ns),
                         "/proc/%d/ns/user", pid_daemon);
                fd_user_ns = open(path_proc_pid_ns, O_RDONLY | O_CLOEXEC);

                snprintf(path_proc_pid_ns, sizeof(path_proc_pid_ns),
                         "/proc/%d/ns/ipc", pid_daemon);
                fd_ipc_ns = open(path_proc_pid_ns, O_RDONLY | O_CLOEXEC);

                if (fd_user_ns < 0 || fd_ipc_ns < 0)
                {
                    perror("Failed to pin newly spawned daemon");
                    flock(lock_fd, LOCK_UN);
                    close(lock_fd);
                    return EXIT_FAILURE;
                }

                unsigned long long starttime_daemon =
                    get_process_starttime(pid_daemon);

                char pid_file_content[128];
                snprintf(pid_file_content, sizeof(pid_file_content),
                         "%d\n%llu\n", pid_daemon, starttime_daemon);
                if (write_file(pid_file, pid_file_content) != 0)
                {
                    perror("Failed to write pid file");
                    flock(lock_fd, LOCK_UN);
                    close(lock_fd);
                    return EXIT_FAILURE;
                }
            }
        }

        flock(lock_fd, LOCK_UN);
        close(lock_fd);

        /* Critical section ends */
    }

    /*
     * Join user ns BEFORE joining ipc ns (see below)
     */
    if (setns(fd_user_ns, CLONE_NEWUSER) != 0)
    {
        perror("Failed to join user namespace");
        close(fd_user_ns);
        close(fd_ipc_ns);
        return EXIT_FAILURE;
    }
    close(fd_user_ns);

    /*
     * After successfully joining the daemon user ns, the unipc wrapper has all
     * capabilities in that user namespace, regardless of UID/GID (man 2 setns).
     *
     * This is necessary, because to join an ipc namespace, the process needs to
     * have CAP_SYS_ADMIN in its own user namespace and the user namespace that
     * owns the ipc namespace (which is the same here).
     */
    if (setns(fd_ipc_ns, CLONE_NEWIPC) != 0)
    {
        perror("Failed to join ipc namespace");
        close(fd_ipc_ns);
        return EXIT_FAILURE;
    }
    close(fd_ipc_ns);

    if (register_current_process(processes_dir) != 0)
    {
        fprintf(stderr, "Failed to register process\n");
        return EXIT_FAILURE;
    }
    /*
     * "If a process with nonzero UID in this user namespace performs execve,
     * all its capabilities are cleared." (man 7 capabilities)
     */
    execvp(argv[1], &argv[1]);

    /* If execvp returns, the command failed to launch, e.g. binary not found */
    perror("execvp target failed");

    return EXIT_FAILURE;
}
