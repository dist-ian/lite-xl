#include <pty.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "tmt/minivt.h"

extern pthread_t pty_thread;

#define MIN(a, b) ((a) > (b) ? (b) : (a))
#define MAX_PTY_SIZE 999
#define BUFFER_SIZE (1024 * 1024)

typedef struct {
    pthread_mutex_t read_write_mutex;
    char buffer[BUFFER_SIZE];
    int buffer_wait_reading;
    int master;
    vt_parser_t *vt;
} pty_poll_context;

static void vt_callback(int type, vt_answer_t *ans, void *data) {
    pty_poll_context *ctx = (pty_poll_context *) data;
    int master = ctx->master;;
    struct winsize wp = { 0 };

    switch (type) {
    // FIXME: ignoring MSG_CONTENT here
    case VT_MSG_PASS:
        write(master, ans->buffer.b, ans->buffer.len);
        break;
    case VT_MSG_RESIZE:
        wp.ws_col = MIN(MAX_PTY_SIZE, ans->point.c);
        wp.ws_row = MIN(MAX_PTY_SIZE, ans->point.r);
        ioctl(master, TIOCSWINSZ, &wp);
        break;
    }
}

void pty_begin_read(pty_poll_context *ctx) {
    pthread_mutex_lock(&ctx->read_write_mutex);
}

void pty_end_read(pty_poll_context *ctx) {
    ctx->buffer_wait_reading = 0;
    pthread_mutex_unlock(&ctx->read_write_mutex);
}

void pty_write_data(pty_poll_context *ctx, char *buffer, size_t length) {
    vtparse(ctx->vt, buffer, length);
}

static void *pty_poll_thread_start(void *data) {
    pty_poll_context *ctx = (pty_poll_context *) data;
    
    struct pollfd fds[1] = {
        { .fd = ctx->master, .events = POLLIN },
    };

    ctx->vt = vtnew(vt_callback, (void *) ctx);

    while (1) {
        poll(fds, 1, -1);
        // if (fds[1].revents & POLLIN) {
        //     pthread_mutex_lock(&thread_data->ctx->read_write_mutex);
        //     length = read(STDIN_FILENO, buffer, BUFFER_SIZE);
        //     vtparse(vt, buffer, length);
        // }
        if (fds[0].revents & POLLIN) {
            pthread_mutex_lock(&ctx->read_write_mutex);
            size_t rem_buffer_size = BUFFER_SIZE;
            char *buffer_ptr = ctx->buffer;
            while (rem_buffer_size > 0) {
                size_t length = read(ctx->master, buffer_ptr, rem_buffer_size);
                buffer_ptr += length;
                rem_buffer_size -= length;
                poll(fds, 1, 0);
                if (fds[0].revents & POLLIN == 0) break;
            }
            SDL_Event ev;
            SDL_zero(ev);
            ev.type = SDL_USEREVENT;
            ev.user.code = 0xff; // ((watch_id.id & 0xffff) << 16) | (action & 0xffff);
            // ev.user.data1 = new_filepath;
            SDL_PushEvent(&ev);
            ctx->buffer_wait_reading = 1;
            while (ctx->buffer_wait_reading) {
                pthread_cond_wait(&ctx->data_read_cond, &ctx->read_write_mutex);
            }
            pthread_mutex_unlock(&ctx->read_write_mutex);
        }

        if (fds[0].revents & POLLHUP) {
            // waitpid(pid, &status, 0);
            vtfree(ctx->vt);
            break;
        }
        if (fds[0].revents & POLLERR) {
            vtfree(ctx->vt);
            break;
        }
    }
    return NULL;
}

int start_pty() {
#define LOG_ERR(S) (err = errno, perror(S), err)

    int master;
    pid_t pid;

    int err = openpty(&master, NULL, NULL, NULL);
    if(pid == -1)
        return LOG_ERR("forkpty(): ");

    if (pid != 0) {
        // parent
        int r = pthread_create(&pty_thread, NULL, pty_poll_thread_start, NULL);

    } else {
        // child
        setenv("TERM", "ansi", 1);
        execl("/bin/bash", "bash", (char *) NULL);
        return LOG_ERR("execl(): ");
    }
}
