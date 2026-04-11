/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * Intentionally partial starter:
 *   - command-line shape is defined
 *   - key runtime data structures are defined
 *   - bounded-buffer skeleton is defined
 *   - supervisor / client split is outlined
 *
 * Students are expected to design:
 *   - the control-plane IPC implementation
 *   - container lifecycle and metadata synchronization
 *   - clone + namespace setup for each container
 *   - producer/consumer behavior for log buffering
 *   - signal handling and graceful shutdown
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    char rootfs_path[256];
    char command[CHILD_COMMAND_LEN];
    int run_client_fd;
    int log_write_fd;
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    char log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

typedef struct {
    supervisor_ctx_t *ctx;
    int read_fd;
    char container_id[CONTAINER_ID_LEN];
} producer_args_t;

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }

    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }

    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;

    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }

        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }

    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }

    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING:
        return "starting";
    case CONTAINER_RUNNING:
        return "running";
    case CONTAINER_STOPPED:
        return "stopped";
    case CONTAINER_KILLED:
        return "killed";
    case CONTAINER_EXITED:
        return "exited";
    default:
        return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;

    memset(buffer, 0, sizeof(*buffer));

    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0)
        return rc;

    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

/*
 * TODO:
 * Implement producer-side insertion into the bounded buffer.
 *
 * Requirements:
 *   - block or fail according to your chosen policy when the buffer is full
 *   - wake consumers correctly
 *   - stop cleanly if shutdown begins
 */
int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    // If the buffer is full, GO TO SLEEP. 
    // We use a 'while' loop to protect against "spurious wakeups".
    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);
    }

    // If the supervisor initiated a shutdown while we were sleeping, bail out.
    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1; 
    }

    // Insert the item at the tail
    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;

    // Wake up the consumer! (Tell it the buffer is no longer empty)
    pthread_cond_signal(&buffer->not_empty);
    
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * TODO:
 * Implement consumer-side removal from the bounded buffer.
 *
 * Requirements:
 *   - wait correctly while the buffer is empty
 *   - return a useful status when shutdown is in progress
 *   - avoid races with producers and shutdown
 */
int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    // If the buffer is empty, GO TO SLEEP.
    while (buffer->count == 0 && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);
    }

    // Crucial Clean Shutdown Logic (Task 6 prep): 
    // We only exit if we are shutting down AND the buffer is completely empty. 
    // This ensures no log lines are dropped when a container exits abruptly.
    if (buffer->count == 0 && buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1; 
    }

    // Extract the item from the head
    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;

    // Wake up any sleeping producers! (Tell them the buffer is no longer full)
    pthread_cond_signal(&buffer->not_full);
    
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * TODO:
 * Implement the logging consumer thread.
 *
 * Suggested responsibilities:
 *   - remove log chunks from the bounded buffer
 *   - route each chunk to the correct per-container log file
 *   - exit cleanly when shutdown begins and pending work is drained
 */
void *logging_thread(void *arg)
{
    // The thread gets passed a pointer to the supervisor context
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;
    char filepath[PATH_MAX];

    // Ensure the logs directory actually exists on the host before we try to write to it!
    // 0777 gives read/write/execute permissions (modified by your system's umask)
    mkdir(LOG_DIR, 0777); 

    printf("[Logger] Consumer thread started.\n");

    while (1) {
        // 1. Pop an item from the buffer. 
        // Remember: pop() puts this thread to sleep if the buffer is empty.
        // It ONLY returns -1 if the supervisor is shutting down AND the buffer is completely empty.
        if (bounded_buffer_pop(&ctx->log_buffer, &item) == -1) {
            printf("[Logger] Buffer empty and shutdown requested. Exiting cleanly.\n");
            break;
        }

        // 2. Build the target log file path (e.g., "logs/alpha.log")
        snprintf(filepath, sizeof(filepath), "%s/%s.log", LOG_DIR, item.container_id);

        // 3. Open the file in Append mode (O_APPEND). 
        // O_CREAT creates it if it doesn't exist. 0644 sets standard read/write permissions.
        int fd = open(filepath, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd == -1) {
            perror("[Logger] Failed to open log file");
            continue; // Skip this chunk, don't crash the whole thread
        }

        // 4. Write the EXACT number of bytes we received in the chunk
        ssize_t written = write(fd, item.data, item.length);
        if (written == -1) {
            perror("[Logger] Failed to write to log file");
        }

        // 5. Close the file so the OS can flush it to disk
        close(fd);
    }

    return NULL; // Thread exits cleanly (Task 6 satisfied!)
}

/*
 * TODO:
 * Implement the clone child entrypoint.
 *
 * Required outcomes:
 *   - isolated PID / UTS / mount context
 *   - chroot or pivot_root into rootfs
 *   - working /proc inside container
 *   - stdout / stderr redirected to the supervisor logging path
 *   - configured command executed inside the container
 */
int child_fn(void *arg)
{
    (void)arg;
    return 1;
}

int register_with_monitor(int monitor_fd,
                          const char *container_id,
                          pid_t host_pid,
                          unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

int container_entry(void *arg){
    container_record_t *cont = (container_record_t *)arg;
    dup2(cont->log_write_fd, STDOUT_FILENO);
    dup2(cont->log_write_fd, STDERR_FILENO);
    mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL);
    chroot(cont->rootfs_path);
    chdir("/");
    mount("proc", "/proc", "proc", 0, NULL);
    char *args[] = {"sh", "-c", cont->command, NULL};
    execvp("/bin/sh",args);
}

/*
 * TODO:
 * Implement the long-running supervisor process.
 *
 * Suggested responsibilities:
 *   - create and bind the control-plane IPC endpoint
 *   - initialize shared metadata and the bounded buffer
 *   - start the logging thread
 *   - accept control requests and update container state
 *   - reap children and respond to signals
 */
 void *producer_thread(void *arg)
{
    // 1. Unpack the arguments
    producer_args_t *args = (producer_args_t *)arg;
    log_item_t item;
    
    // Copy the ID into the item so the consumer knows whose log this is
    strncpy(item.container_id, args->container_id, sizeof(item.container_id) - 1);

    printf("[Producer] Started listening to container '%s'...\n", args->container_id);

    // 2. The Read Loop
    while (1) {
        // Read up to LOG_CHUNK_SIZE bytes from the pipe
        ssize_t bytes_read = read(args->read_fd, item.data, sizeof(item.data));
        
        if (bytes_read < 0) {
            perror("[Producer] Error reading from container pipe");
            break;
        } 
        else if (bytes_read == 0) {
            // EOF (End of File) - The container has died and its end of the pipe is closed.
            printf("[Producer] Container '%s' pipe closed. Thread exiting.\n", args->container_id);
            break;
        }

        item.length = bytes_read;

        // 3. Push the chunk into the bounded buffer
        // (This will automatically put this thread to sleep if the buffer is full!)
        if (bounded_buffer_push(&args->ctx->log_buffer, &item) == -1) {
            printf("[Producer] Supervisor is shutting down. Thread exiting.\n");
            break;
        }
    }

    // 4. Clean up resources before the thread dies
    close(args->read_fd);
    free(args); 
    
    return NULL;
}

static int launch_container(supervisor_ctx_t *ctx, const control_request_t *req){
container_record_t *con1 = malloc(sizeof(container_record_t));
con1->run_client_fd = -1;
    strncpy(con1->id, req->container_id, sizeof(con1->id) - 1);
    strncpy(con1->command, req->command, sizeof(con1->command) - 1);
    con1->started_at = time(NULL);
    con1->state = CONTAINER_STARTING;
    con1->soft_limit_bytes = req->soft_limit_bytes;
    con1->hard_limit_bytes = req->hard_limit_bytes;


    char cmd[512];
    char rootfs_path[256];
    snprintf(rootfs_path, sizeof(rootfs_path),"./rootfs-%s",con1->id);
    snprintf(cmd,sizeof(cmd),"cp -a ./rootfs-base %s",rootfs_path);
    int status = system(cmd);

    if (status !=0){
        fprintf(stderr,"Failed to duplicate the root file system\n");
        return(-1);
    }
    strncpy(con1->rootfs_path, rootfs_path, sizeof(con1->rootfs_path) - 1);


    // Create a pipe: fd[0] is for the parent to read, fd[1] is for the child to write
    int log_pipe[2];
    if (pipe(log_pipe) == -1) {
        perror("pipe failed");
        return -1;
    }

    // Save the WRITE end to your container record so the child can access it
    con1->log_write_fd = log_pipe[1];

    // 1. Allocate memory for the thread arguments
    producer_args_t *p_args = malloc(sizeof(producer_args_t));
    if (p_args == NULL) {
        perror("Failed to allocate producer args");
        return -1;
    }

    // 2. Pack the data
    p_args->ctx = ctx;
    p_args->read_fd = log_pipe[0]; // The read-end of the pipe
    strncpy(p_args->container_id, con1->id, sizeof(p_args->container_id) - 1);

    // 3. Spawn the producer thread
    pthread_t prod_tid;
    if (pthread_create(&prod_tid, NULL, producer_thread, p_args) != 0) {
        perror("Failed to create producer thread");
        free(p_args);
        return -1;
    }

    // 4. Detach the thread. 
    // This tells the OS to automatically clean up the thread's memory when it exits.
    // (We don't need to pthread_join() it later because it will naturally die when the container dies).
    pthread_detach(prod_tid);


// Inside your start_container function:

// 1. Allocate memory for the child's stack
char *stack = malloc(STACK_SIZE);
if (stack == NULL) {
    perror("Failed to allocate memory for container stack");
    return -1;
}

// 2. Point to the TOP of the stack (highest memory address)
char *stack_top = stack + STACK_SIZE;

// 3. Call clone(), passing the TOP of the stack
// (Assuming you've defined your flags and container_entry function)
int clone_flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD;

con1->host_pid = clone(
    container_entry, // The function the child will run
    stack_top,       // The TOP of the allocated stack memory
    clone_flags,     // The namespace isolation flags
    con1           // Pass your container struct so the child knows its ID/paths
);

if (con1->host_pid == -1) {
    perror("clone failed");
    free(stack); // Clean up if it fails!
    return -1;
}

pthread_mutex_lock(&ctx->metadata_lock);
con1->next = ctx->containers;
ctx->containers = con1;
pthread_mutex_unlock(&ctx->metadata_lock);

close(log_pipe[1]);
}



static int run_supervisor(const char *rootfs)
{

    supervisor_ctx_t ctx;
    int rc;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = -1;

    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) {
        errno = rc;
        perror("pthread_mutex_init");
        return 1; 
    }

    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc;
        perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx);


    





    /*
     * TODO:
     *   1) open /dev/container_monitor
     *   2) create the control socket / FIFO / shared-memory channel
     *   3) install SIGCHLD / SIGINT / SIGTERM handling
     *   4) spawn the logger thread
     *   5) enter the supervisor event loop
     */
    // --- IPC SOCKET SETUP ---
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd == -1) {
        perror("Supervisor socket failed");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    unlink(CONTROL_PATH); // Clean up stale socket file from previous crashes

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("Supervisor bind failed");
        return 1;
    }

    if (listen(ctx.server_fd, 5) == -1) {
        perror("Supervisor listen failed");
        return 1;
    }

    // Make accept() non-blocking so the loop doesn't freeze
    int flags = fcntl(ctx.server_fd, F_GETFL, 0);
    fcntl(ctx.server_fd, F_SETFL, flags | O_NONBLOCK);

    printf("Supervisor listening for commands on %s...\n", CONTROL_PATH);


    // --- THE MAIN EVENT LOOP ---
    while (!ctx.should_stop) {
        
        // 1. Reap any containers that have exited in the background
        int wstatus;
        pid_t reaped_pid = waitpid(-1, &wstatus, WNOHANG);
        if (reaped_pid > 0) {
            printf("[Supervisor] Reaped container with host PID: %d\n", reaped_pid);
            // TODO later: Free the container's stack, update its state in the struct, etc.
            container_record_t *temp = ctx.containers;
            while(temp){
                if (temp->host_pid == reaped_pid){
                    temp->state = CONTAINER_EXITED;
                    temp->exit_code = WIFEXITED(wstatus);
                    if (temp->run_client_fd != -1) {
                        control_response_t run_res;
                        memset(&run_res, 0, sizeof(run_res));
                        run_res.status = temp->exit_code; // Return the actual exit code to the CLI!
                        snprintf(run_res.message, sizeof(run_res.message), "Container exited with code %d", temp->exit_code);
                        
                        write(temp->run_client_fd, &run_res, sizeof(run_res));
                        close(temp->run_client_fd);
                        temp->run_client_fd = -1; // Reset it
                    }
                    char removecommand[500];
                    snprintf(removecommand,sizeof(removecommand),"rm -rf %s",temp->rootfs_path);
                    system(removecommand);
                }
                temp = temp->next;
            }
        }



// 2. Check for incoming CLI commands
        int client_fd = accept(ctx.server_fd, NULL, NULL);
        if (client_fd > 0) {
            control_request_t req;
            control_response_t res;
            memset(&res, 0, sizeof(res));

            // Read the command from the CLI
            if (read(client_fd, &req, sizeof(req)) > 0) {
                printf("[Supervisor] Received command kind %d for container ID '%s'\n", req.kind, req.container_id);

                if (req.kind == CMD_START) {
                    
                    int rc = launch_container(&ctx, &req);
                    
                    if (rc == 0) {


                        // Normal 'start' behavior: reply and hang up
                        res.status = 0;
                        snprintf(res.message, sizeof(res.message), "Container '%s' started in background.", req.container_id);
                        write(client_fd, &res, sizeof(res));
                        close(client_fd);
                    
                    } else {
                        // Launch failed, send error and hang up
                        res.status = 1;
                        snprintf(res.message, sizeof(res.message), "Failed to start container '%s'.", req.container_id);
                        write(client_fd, &res, sizeof(res));
                        close(client_fd);
                    }
                    
                    write(client_fd, &res, sizeof(res));
                    close(client_fd);
                }

                else if (req.kind == CMD_RUN){
                    int rc = launch_container(&ctx, &req);
                    if (rc == 0) {

                        // HOSTAGE SITUATION: 
                        // Save the client's socket into the container record.
                        // Do NOT send a response, and do NOT close the socket!
                        pthread_mutex_lock(&ctx.metadata_lock);
                        // Because launch_container inserts at the head, our new container is ctx.containers
                        ctx.containers->run_client_fd = client_fd;
                        pthread_mutex_unlock(&ctx.metadata_lock);
                        
                    } else {
                        // Launch failed, send error and hang up
                        res.status = 1;
                        snprintf(res.message, sizeof(res.message), "Failed to start container '%s'.", req.container_id);
                        write(client_fd, &res, sizeof(res));
                        close(client_fd);
                    }
                }
                
                else if (req.kind == CMD_PS){
                    container_record_t *temp = ctx.containers;
                    while(temp){
                        char printvalue[500];
                        snprintf(printvalue,sizeof(printvalue),"Container Name: %s PID: %d State: %d",temp->id,temp->host_pid,temp->state);
                        printf("%s\n",printvalue);
                        temp = temp->next;
                    }
                    write(client_fd, &res, sizeof(res));
                    close(client_fd);
                }

                else if (req.kind == CMD_STOP){
                    container_record_t *temp = ctx.containers;
                    
                    while(temp){
                        printf("Found the container %s %s \n",req.container_id,temp->id);
                        if (strcmp(req.container_id,temp->id) == 0){
                            
                            kill(temp->host_pid,SIGKILL);
                            break;
                        }

                        temp = temp->next;
                    }
                    write(client_fd, &res, sizeof(res));
                    close(client_fd);
                }

                else {
                    res.status = 1;
                    strncpy(res.message, "Error: Command not implemented yet.", sizeof(res.message) - 1);
                    write(client_fd, &res, sizeof(res));
                    close(client_fd);
                }

                // Send the result back to the CLI terminal
                
            }
            
        }

        // 3. Sleep briefly to avoid maxing out CPU cores
        usleep(100000); // 100 milliseconds
    }

    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    return 1;
}




/*
 * TODO:
 * Implement the client-side control request path.
 *
 * The CLI commands should use a second IPC mechanism distinct from the
 * logging pipe. A UNIX domain socket is the most direct option, but a
 * FIFO or shared memory design is also acceptable if justified.
 */
static int send_control_request(const control_request_t *req)
{
    // 1. Create a UNIX domain socket
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        perror("Client socket creation failed");
        return 1;
    }

    // 2. Target the supervisor's socket file path
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    // 3. Connect to the running supervisor daemon
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("Failed to connect to supervisor (is it running?)");
        close(sock_fd);
        return 1;
    }

    // 4. Send the request struct
    if (write(sock_fd, req, sizeof(*req)) == -1) {
        perror("Failed to send request to supervisor");
        close(sock_fd);
        return 1;
    }

    // 5. Wait for the supervisor to reply
    control_response_t res;
    if (read(sock_fd, &res, sizeof(res)) > 0) {
        printf("Supervisor responded: %s\n", res.message);
    } else {
        printf("Error: No response from supervisor.\n");
    }

    close(sock_fd);
    return res.status;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;

    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;

    /*
     * TODO:
     * The supervisor should respond with container metadata.
     * Keep the rendering format simple enough for demos and debugging.
     */
    printf("Expected states include: %s, %s, %s, %s, %s\n",
           state_to_string(CONTAINER_STARTING),
           state_to_string(CONTAINER_RUNNING),
           state_to_string(CONTAINER_STOPPED),
           state_to_string(CONTAINER_KILLED),
           state_to_string(CONTAINER_EXITED));
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc, argv);

    if (strcmp(argv[1], "run") == 0)
        return cmd_run(argc, argv);

    if (strcmp(argv[1], "ps") == 0)
        return cmd_ps();

    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs(argc, argv);

    if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
