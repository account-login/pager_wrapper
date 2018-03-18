#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/ioctl.h>


static void log_err(int errnum, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    if (errnum != 0) {
        fprintf(stderr, " [errno:%d] %s", errnum, strerror(errnum));
    }
    fputc('\n', stderr);
}

static void log_debug(const char *fmt, ...) {
    static int got_flag = 0;
    static const char *debug_flag = NULL;
    if (!got_flag) {
        debug_flag = getenv("PW_DEBUG");
        got_flag = 1;
    }
    if (!debug_flag) {
        return;
    }

    fprintf(stderr, "PW_DEBUG: ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
}

static int close_fd(int fd) {
    if (close(fd) != 0) {
        log_err(errno, "close() error for [fd:%d]", fd);
        return -1;
    }
    return 0;
}

static uint64_t get_time_msec() {
    struct timeval tv = {0, 0};
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static size_t count_lines(const char *buf, size_t bufsize) {
    const char *end = buf + bufsize;
    size_t count = 0;
    for (const char *cur = buf; cur != NULL && cur < end; ) {
        cur = strchr(cur, '\n');
        if (cur == NULL) {
            break;
        } else {
            count++;
            cur++;
        }
    }
    if (bufsize > 0 && buf[bufsize - 1] != '\n') {
        count++;    // fixup
    }
    return count;
}

static ssize_t write_all(int fd, const char *buf, size_t bufsize) {
    size_t remain = bufsize;
    while (remain > 0) {
        ssize_t rv = write(fd, buf, remain);
        if (rv < 0) {
            log_err(errno, "write() error");
            return rv;
        } else {
            assert((ssize_t)remain >= rv);
            buf += rv;
            remain -= rv;
        }
    }

    return bufsize;
}

static int read_timeout(
    size_t *nread, int *is_timeout, int fd, char *buf, size_t bufsize, uint64_t msec)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    struct timeval tv = {msec / 1000, (msec % 1000) * 1000};
    int rv = select(fd + 1, &fds, NULL, NULL, &tv);
    if (rv < 0) {
        log_err(errno, "select() error");
        return -1;
    } else if (rv == 0) {
        // timeout
        *nread = 0;
        *is_timeout = 1;
        return 0;
    } else {
        ssize_t n = read(fd, buf, bufsize);
        if (n < 0) {
            log_err(errno, "read(%d, %p, %zu) error", fd, buf, bufsize);
            return -1;
        } else {
            *nread = (size_t)n;
            *is_timeout = 0;
            return 0;
        }
    }
}


struct Context {
    // params
    int         pager_argc;
    char      **pager_argv;
    size_t      line_threshold;
    uint64_t    waiting_time_msec;

    // states
    size_t      bufused;
    char        buf[1024 * 16];
};


static int do_error(struct Context *ctx) {
    if (ctx->bufused > 0) {
        write(STDOUT_FILENO, ctx->buf, ctx->bufused);   // do not care about the return value
    }
    return -1;
}

static int do_pager(struct Context *ctx) {
    int rwfds[2];
    int rv = pipe(rwfds);
    if (rv != 0) {
        log_err(errno, "pipe() error");
        return do_error(ctx);
    }

    int rfd = rwfds[0];
    int wfd = rwfds[1];

    pid_t pid = fork();
    if (pid < 0) {
        log_err(errno, "fork() error");
        return do_error(ctx);
    }

    if (pid == 0) {
        // child

        close_fd(wfd);

        // replace stdin with pipe
        int newstdin = dup2(rfd, STDIN_FILENO);
        if (newstdin < 0) {
            log_err(errno, "dup2() error");
            return -1;
        }
        assert(newstdin == STDIN_FILENO);
        close_fd(rfd);

        // exec to pager
        assert(ctx->pager_argc > 0);
        rv = execvp(ctx->pager_argv[0], ctx->pager_argv);   // no return

        assert(rv != 0);
        log_err(errno, "execvp() error");
        return -1;
    } else {
        // parent

        int retcode = 0;
        close_fd(rfd);

        // proxy stdin to pipe
        while (1) {
            // write
            if (ctx->bufused > 0) {
                log_debug("parent write: %zu", ctx->bufused);
                ssize_t n = write_all(wfd, ctx->buf, ctx->bufused);
                if (n != (ssize_t)ctx->bufused) {
                    return -1;
                }
            }
            ctx->bufused = 0;

            // read
            ssize_t n = read(STDIN_FILENO, ctx->buf, sizeof(ctx->buf));
            log_debug("parent read: %ld", n);
            if (n < 0) {
                log_err(errno, "read(STDIN_FILENO, ctx->buf, sizeof(ctx->buf)) error");
                retcode = -1;
                break;
            } else if (n == 0) {
                break;
            } else {
                ctx->bufused = (size_t)n;
            }
        }

        close_fd(wfd);  // send eof to child

        close_fd(STDIN_FILENO);

        // wait for child
        rv = wait(NULL);
        log_debug("wait returns: %d", rv);
        if (rv < 0) {
            log_err(errno, "wait(NULL) error");
            retcode = -1;
        }
        return retcode;
    }
}

static int do_nopager(struct Context *ctx) {
    if (ctx->bufused > 0) {
        ssize_t rv = write_all(STDOUT_FILENO, ctx->buf, ctx->bufused);
        if (rv != (ssize_t)ctx->bufused) {
            return -1;
        }
    }
    return 0;
}

static int get_win_size(struct winsize *ws) {
    int rv = ioctl(STDOUT_FILENO, TIOCGWINSZ, ws);
    if (rv != 0) {
        log_err(errno, "ioctl(STDOUT_FILENO, TIOCGWINSZ, ws) error");
    }
    return rv;
}

int main(int argc, char **argv)
{
    // pager not needed if not using tty
    if (!isatty(STDOUT_FILENO)) {
        char *cat[] = {"cat", NULL};
        int rv = execvp(cat[0], cat);
        assert(rv != 0);
        log_err(errno, "execvp() error");
        return -1;
    }

    // main begins
    static char *default_pager[] = {"less", NULL};

    struct Context ctx = {};

    // params: pager
    if (argc > 1) {
        ctx.pager_argv = argv + 1;
        ctx.pager_argc = argc - 1;
    } else {
        ctx.pager_argv = default_pager;
        ctx.pager_argc = 1;
    }

    // params: line threshold
    ctx.line_threshold = 20;    // default
    struct winsize ws = {};
    if (get_win_size(&ws) == 0) {
        log_debug("rows: %d", ws.ws_row);
        if (ws.ws_row > 5) {
            ctx.line_threshold = ws.ws_row - (short)5;  // reserve 5 rows for bash prompt
        }
    }

    // params: time to count lines
    ctx.waiting_time_msec = 200;

    // states
    ctx.bufused = 0;

    // wait for data by doing a blocking read
    ssize_t first = read(STDIN_FILENO, ctx.buf, sizeof(ctx.buf));
    if (first < 0) {
        log_err(errno, "read(STDIN_FILENO, buf, sizeof(buf)) error");
        return -1;
    } else if (first == 0) {
        // EOF, no data
        return 0;
    }
    ctx.bufused = (size_t)first;

    // buffer full or got too many lines
    if (ctx.bufused >= sizeof(ctx.buf)
        || count_lines(ctx.buf, ctx.bufused) > ctx.line_threshold)
    {
        // use pager
        return do_pager(&ctx);
    }

    // some data received, wait for some time to determine weither to use pager or not

    uint64_t deadline = get_time_msec() + ctx.waiting_time_msec;
    while (1) {
        uint64_t now = get_time_msec();
        if (now >= deadline) {
            return do_nopager(&ctx);
        }

        size_t nread = 0;
        int timeout = 0;
        int rv = read_timeout(
            &nread, &timeout,
            STDIN_FILENO, &ctx.buf[ctx.bufused], sizeof(ctx.buf) - ctx.bufused, deadline - now
        );
        if (rv < 0) {
            return do_error(&ctx);
        } else {
            ctx.bufused += nread;
            if (timeout
                || ctx.bufused >= sizeof(ctx.buf)
                || count_lines(ctx.buf, ctx.bufused) > ctx.line_threshold)
            {
                // use pager
                return do_pager(&ctx);
            }
            if (nread == 0) {
                return do_nopager(&ctx);    // EOF reached, must break
            }
            // continue reading
        }
    }

    assert(!"Unreachable");
}
