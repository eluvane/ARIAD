#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "ariad.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
typedef HANDLE worker_thread;
#else
#include <pthread.h>
#include <time.h>
typedef pthread_t worker_thread;
#endif

static int check_status(const char *operation, int32_t status) {
    if (status == ARIAD_OK) {
        return 1;
    }
    (void)fprintf(stderr, "%s failed: %s (%d)\n", operation, ariad_status_name(status),
                  (int)status);
    return 0;
}

static int check_status_names(void) {
    const int32_t statuses[] = {ARIAD_OK, ARIAD_EOF, ARIAD_ERROR_INTERNAL, INT32_MIN, INT32_MAX};
    const char *const expected[] = {"ARIAD_OK", "ARIAD_EOF", "ARIAD_ERROR_INTERNAL",
                                    "ARIAD_STATUS_UNKNOWN", "ARIAD_STATUS_UNKNOWN"};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        const char *name = ariad_status_name(statuses[i]);
        if (name == NULL || strcmp(name, expected[i]) != 0 ||
            name != ariad_status_name(statuses[i])) {
            (void)fprintf(stderr, "invalid static status name for %d\n", (int)statuses[i]);
            return 0;
        }
    }
    return 1;
}

typedef struct {
    ariad_handle stream;
    uint8_t output[8];
    size_t count;
    int32_t status;
    atomic_int finished;
} pending_read;

static uint64_t monotonic_ms(void) {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        (void)fprintf(stderr, "monotonic clock failed\n");
        _Exit(1);
    }
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
#endif
}

static void pause_ms(unsigned milliseconds) {
#ifdef _WIN32
    Sleep(milliseconds);
#else
    struct timespec delay = {(time_t)(milliseconds / 1000), (long)(milliseconds % 1000) * 1000000};
    (void)nanosleep(&delay, NULL);
#endif
}

static void read_on_worker(pending_read *read) {
    read->status = ariad_stream_read(read->stream, read->output, sizeof(read->output),
                                     ARIAD_MAX_TIMEOUT_MS, &read->count);
    atomic_store_explicit(&read->finished, 1, memory_order_release);
}

#ifdef _WIN32
static DWORD WINAPI read_thread(void *argument) {
    read_on_worker(argument);
    return 0;
}
#else
static void *read_thread(void *argument) {
    read_on_worker(argument);
    return NULL;
}
#endif

static pending_read *spawn_read(ariad_handle stream, worker_thread *worker) {
    pending_read *read = calloc(1, sizeof(*read));
    if (read == NULL) {
        (void)fprintf(stderr, "pending read allocation failed\n");
        return NULL;
    }
    read->stream = stream;
    read->count = 123;
    memset(read->output, 0x7e, sizeof(read->output));
    atomic_init(&read->finished, 0);
#ifdef _WIN32
    *worker = CreateThread(NULL, 0, read_thread, read, 0, NULL);
    if (*worker == NULL) {
#else
    if (pthread_create(worker, NULL, read_thread, read) != 0) {
#endif
        (void)fprintf(stderr, "pending read thread failed\n");
        free(read);
        return NULL;
    }
    return read;
}

static int wait_flag(atomic_int *flag) {
    uint64_t started = monotonic_ms();
    while (!atomic_load_explicit(flag, memory_order_acquire)) {
        if (monotonic_ms() - started >= 2000) {
            return 0;
        }
        pause_ms(1);
    }
    return 1;
}

static void finish_read(worker_thread worker, pending_read *read) {
    if (!wait_flag(&read->finished)) {
        (void)fprintf(stderr, "pending read did not stop within two seconds\n");
        /* Keep memory still borrowed by the worker alive until process exit. */
        _Exit(1);
    }
#ifdef _WIN32
    if (WaitForSingleObject(worker, 2000) != WAIT_OBJECT_0 || !CloseHandle(worker)) {
#else
    if (pthread_join(worker, NULL) != 0) {
#endif
        (void)fprintf(stderr, "pending read thread did not join\n");
        _Exit(1);
    }
}

static int read_has_status(const pending_read *read, int32_t expected) {
    if (read->status != expected || read->count != 0) {
        (void)fprintf(stderr, "read status or count mismatch: got %d, expected %d\n",
                      (int)read->status, (int)expected);
        return 0;
    }
    for (size_t i = 0; i < sizeof(read->output); ++i) {
        if (read->output[i] != 0x7e) {
            (void)fprintf(stderr, "failed read changed output\n");
            return 0;
        }
    }
    return 1;
}

static pending_read *start_pending_read(ariad_handle stream, worker_thread *worker) {
    worker_thread first_worker;
    worker_thread second_worker;
    pending_read *first = spawn_read(stream, &first_worker);
    if (first == NULL) {
        return NULL;
    }
    pending_read *second = spawn_read(stream, &second_worker);
    if (second == NULL) {
        (void)ariad_stream_cancel(stream);
        finish_read(first_worker, first);
        free(first);
        return NULL;
    }
    uint64_t started = monotonic_ms();
    int first_finished;
    int second_finished;
    do {
        first_finished = atomic_load_explicit(&first->finished, memory_order_acquire);
        second_finished = atomic_load_explicit(&second->finished, memory_order_acquire);
        if (first_finished || second_finished) {
            break;
        }
        pause_ms(1);
    } while (monotonic_ms() - started < 2000);
    if (first_finished != second_finished) {
        pending_read *completed = first_finished ? first : second;
        pending_read *pending = first_finished ? second : first;
        worker_thread completed_worker = first_finished ? first_worker : second_worker;
        if (read_has_status(completed, ARIAD_ERROR_BUSY)) {
            finish_read(completed_worker, completed);
            free(completed);
            *worker = first_finished ? second_worker : first_worker;
            return pending;
        }
    }
    (void)fprintf(stderr, "two readers did not establish pending direction contention\n");
    (void)ariad_stream_cancel(stream);
    finish_read(first_worker, first);
    finish_read(second_worker, second);
    free(first);
    free(second);
    return NULL;
}

static int concurrent_streams(ariad_handle session, const char *destination) {
    ariad_handle first = 0;
    ariad_handle second = 0;
    if (!check_status("open pending stream",
                      ariad_session_open_stream(session, (const uint8_t *)destination,
                                                strlen(destination), 10000, &first)) ||
        !check_status("open independent stream",
                      ariad_session_open_stream(session, (const uint8_t *)destination,
                                                strlen(destination), 10000, &second))) {
        return 0;
    }
    worker_thread worker;
    pending_read *read = start_pending_read(first, &worker);
    if (read == NULL) {
        return 0;
    }
    uint8_t reply[4];
    size_t accepted = 0;
    uint64_t write_started = monotonic_ms();
    int32_t write_status;
    do {
        write_status = ariad_stream_write(second, (const uint8_t *)"ping", 4, 10000, &accepted);
        if (write_status != ARIAD_ERROR_BUSY || accepted != 0) {
            break;
        }
        pause_ms(1);
    } while (monotonic_ms() - write_started < 2000);
    int passed = check_status("independent stream write", write_status);
    if (passed && (accepted == 0 || accepted > sizeof(reply))) {
        (void)fprintf(stderr, "independent write returned an invalid prefix\n");
        passed = 0;
    }
    size_t received = 0;
    while (passed && received < accepted) {
        size_t count = 0;
        passed = check_status(
            "independent stream read",
            ariad_stream_read(second, reply + received, accepted - received, 10000, &count));
        if (passed && (count == 0 || count > accepted - received)) {
            (void)fprintf(stderr, "independent read returned an invalid prefix\n");
            passed = 0;
        }
        if (passed) {
            received += count;
        }
    }
    if (passed && (memcmp(reply, "ping", accepted) != 0 ||
                   atomic_load_explicit(&read->finished, memory_order_acquire))) {
        (void)fprintf(stderr, "independent progress changed the pending stream\n");
        passed = 0;
    }
    uint64_t cancel_started = monotonic_ms();
    if (!check_status("cancel pending stream", ariad_stream_cancel(first))) {
        passed = 0;
    }
    finish_read(worker, read);
    if (monotonic_ms() - cancel_started >= 2000 || !read_has_status(read, ARIAD_ERROR_CANCELLED)) {
        passed = 0;
    }
    free(read);
    if (!check_status("destroy pending stream", ariad_stream_destroy(first)) ||
        ariad_stream_destroy(first) != ARIAD_ERROR_INVALID_HANDLE ||
        !check_status("destroy independent stream", ariad_stream_destroy(second))) {
        passed = 0;
    }
    return passed;
}

static int destroy_during_read(const char *endpoint, const char *identity,
                               const uint8_t *trust_root, size_t trust_root_len,
                               const char *destination) {
    ariad_handle engine = 0;
    ariad_handle session = 0;
    ariad_handle stream = 0;
    if (!check_status("race engine create",
                      ariad_engine_create((const uint8_t *)endpoint, strlen(endpoint),
                                          (const uint8_t *)identity, strlen(identity), trust_root,
                                          trust_root_len, &engine))) {
        return 0;
    }
    uint8_t credential[ARIAD_CREDENTIAL_BYTES];
    memset(credential, 0x11, sizeof(credential));
    int32_t status = ariad_engine_connect(engine, credential, sizeof(credential), 10000, &session);
    memset(credential, 0, sizeof(credential));
    if (!check_status("race engine connect", status) ||
        !check_status("race stream open",
                      ariad_session_open_stream(session, (const uint8_t *)destination,
                                                strlen(destination), 10000, &stream))) {
        (void)ariad_engine_destroy(engine, 1000);
        return 0;
    }
    worker_thread worker;
    pending_read *read = start_pending_read(stream, &worker);
    if (read == NULL) {
        (void)ariad_engine_destroy(engine, 1000);
        return 0;
    }
    int passed = 1;
    uint64_t destroy_started = monotonic_ms();
    do {
        status = ariad_engine_destroy(engine, 1000);
        if (status != ARIAD_ERROR_BUSY) {
            break;
        }
        pause_ms(1);
    } while (monotonic_ms() - destroy_started < 2000);
    if ((status != ARIAD_OK && status != ARIAD_FORCED) ||
        monotonic_ms() - destroy_started >= 2000) {
        (void)fprintf(stderr, "engine destroy did not complete within its bounded wait\n");
        passed = 0;
    }
    finish_read(worker, read);
    if (!read_has_status(read, ARIAD_ERROR_CANCELLED)) {
        passed = 0;
    }
    free(read);
    if (ariad_stream_destroy(stream) != ARIAD_ERROR_INVALID_HANDLE ||
        ariad_session_destroy(session) != ARIAD_ERROR_INVALID_HANDLE ||
        ariad_engine_destroy(engine, 1000) != ARIAD_ERROR_INVALID_HANDLE) {
        (void)fprintf(stderr, "racing destroy retained child or engine handles\n");
        passed = 0;
    }
    return passed;
}

static int datagram_echo(ariad_handle session, const char *destination) {
    ariad_handle association = 0;
    if (!check_status("session_open_datagram",
                      ariad_session_open_datagram(session, (const uint8_t *)destination,
                                                  strlen(destination), 0, 10000, &association))) {
        return 0;
    }
    uint32_t mode = 0;
    size_t max_payload = 0;
    if (!check_status("association_delivery_mode",
                      ariad_association_delivery_mode(association, &mode)) ||
        !check_status("association_max_payload",
                      ariad_association_max_payload(association, &max_payload))) {
        return 0;
    }
    if (mode != ARIAD_DELIVERY_RELIABLE || max_payload < 6 || max_payload > ARIAD_MAX_COPY) {
        (void)fprintf(stderr, "invalid negotiated H2 datagram contract\n");
        return 0;
    }
    uint8_t reply[4];
    size_t bytes_read = 0;
    if (!check_status("association_send",
                      ariad_association_send(association, (const uint8_t *)"ping", 4, 10000)) ||
        !check_status("association_recv", ariad_association_recv(association, reply, sizeof(reply),
                                                                 10000, &bytes_read))) {
        return 0;
    }
    if (bytes_read != 4 || memcmp(reply, "ping", 4) != 0) {
        (void)fprintf(stderr, "datagram echo mismatch\n");
        return 0;
    }
    /* The UDP echo fixture must preserve zero-length messages. */
    if (!check_status("empty association_send",
                      ariad_association_send(association, NULL, 0, 10000)) ||
        !check_status("empty association_recv",
                      ariad_association_recv(association, NULL, 0, 10000, &bytes_read))) {
        return 0;
    }
    if (bytes_read != 0) {
        (void)fprintf(stderr, "empty datagram was changed\n");
        return 0;
    }
    memset(reply, 0x7e, sizeof(reply));
    if (!check_status("large association_send",
                      ariad_association_send(association, (const uint8_t *)"larger", 6, 10000))) {
        return 0;
    }
    if (ariad_association_recv(association, reply, sizeof(reply), 10000, &bytes_read) !=
            ARIAD_ERROR_MESSAGE_TOO_LARGE ||
        bytes_read != 0) {
        (void)fprintf(stderr, "oversized datagram returned a prefix\n");
        return 0;
    }
    for (size_t i = 0; i < sizeof(reply); ++i) {
        if (reply[i] != 0x7e) {
            (void)fprintf(stderr, "oversized datagram changed output\n");
            return 0;
        }
    }
    if (!check_status("association_send after discard",
                      ariad_association_send(association, (const uint8_t *)"ping", 4, 10000)) ||
        !check_status(
            "association_recv after discard",
            ariad_association_recv(association, reply, sizeof(reply), 10000, &bytes_read))) {
        return 0;
    }
    if (bytes_read != 4 || memcmp(reply, "ping", 4) != 0) {
        (void)fprintf(stderr, "oversized datagram was not discarded\n");
        return 0;
    }
    if (!check_status("association_close", ariad_association_close(association)) ||
        !check_status("association_destroy", ariad_association_destroy(association))) {
        return 0;
    }
    if (ariad_association_delivery_mode(association, &mode) != ARIAD_ERROR_INVALID_HANDLE ||
        mode != 0) {
        (void)fprintf(stderr, "destroyed association accepted again\n");
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    if ((argc != 5 && argc != 6) || (argc == 6 && strcmp(argv[5], "--udp") != 0)) {
        (void)fprintf(
            stderr,
            "usage: consumer <endpoint-ip:port> <tls-name> <ca.der> <echo-destination> [--udp]\n");
        return 2;
    }
    int use_datagrams = argc == 6;
    FILE *trust_root_file = fopen(argv[3], "rb");
    if (trust_root_file == NULL) {
        (void)fprintf(stderr, "cannot open trust root\n");
        return 2;
    }
    uint8_t trust_root_der[ARIAD_MAX_COPY];
    size_t trust_root_len = fread(trust_root_der, 1, sizeof(trust_root_der), trust_root_file);
    int read_failed = ferror(trust_root_file);
    int trailing_byte = EOF;
    if (!read_failed && !feof(trust_root_file)) {
        trailing_byte = fgetc(trust_root_file);
        read_failed = ferror(trust_root_file);
    }
    int close_failed = fclose(trust_root_file);
    if (trust_root_len == 0 || trailing_byte != EOF || read_failed || close_failed != 0) {
        (void)fprintf(stderr, "invalid trust root size or read failure\n");
        return 2;
    }
    if (ariad_abi_version() != ARIAD_ABI_VERSION) {
        (void)fprintf(stderr, "ABI version mismatch\n");
        return 2;
    }
    if (!check_status_names()) {
        return 1;
    }
    ariad_handle engine = 0;
    ariad_handle session = 0;
    ariad_handle stream = 0;
    for (size_t cycle = 0; cycle < 32; ++cycle) {
        if (!check_status("engine_create",
                          ariad_engine_create((const uint8_t *)argv[1], strlen(argv[1]),
                                              (const uint8_t *)argv[2], strlen(argv[2]),
                                              trust_root_der, trust_root_len, &engine))) {
            return 1;
        }
        if (ariad_stream_destroy(engine) != ARIAD_ERROR_INVALID_HANDLE) {
            (void)fprintf(stderr, "engine accepted as a stream\n");
            goto failed;
        }
        if (!check_status("engine_destroy", ariad_engine_destroy(engine, 1000))) {
            goto failed;
        }
        if (ariad_engine_destroy(engine, 1000) != ARIAD_ERROR_INVALID_HANDLE) {
            (void)fprintf(stderr, "destroyed engine accepted again\n");
            return 1;
        }
        engine = 0;
    }
    if (!check_status("engine_create",
                      ariad_engine_create((const uint8_t *)argv[1], strlen(argv[1]),
                                          (const uint8_t *)argv[2], strlen(argv[2]), trust_root_der,
                                          trust_root_len, &engine))) {
        return 1;
    }
    /* The echo fixture must authorize this demonstration credential. */
    uint8_t credential[ARIAD_CREDENTIAL_BYTES];
    memset(credential, 0x11, sizeof(credential));
    int32_t status = ariad_engine_connect(engine, credential, sizeof(credential), 10000, &session);
    memset(credential, 0, sizeof(credential));
    if (!check_status("engine_connect", status)) {
        goto failed;
    }
    ariad_handle unsupported_association = 123;
    if (ariad_session_open_datagram(session, (const uint8_t *)argv[4], strlen(argv[4]), 1, 10000,
                                    &unsupported_association) != ARIAD_ERROR_UNSUPPORTED ||
        unsupported_association != 0) {
        (void)fprintf(stderr, "H2 accepted an unreliable requirement\n");
        goto failed;
    }
    if (use_datagrams) {
        if (!datagram_echo(session, argv[4])) {
            goto failed;
        }
        goto completed;
    }
    if (!concurrent_streams(session, argv[4])) {
        goto failed;
    }
    if (!check_status("session_open_stream",
                      ariad_session_open_stream(session, (const uint8_t *)argv[4], strlen(argv[4]),
                                                10000, &stream))) {
        goto failed;
    }
    uint8_t payload[4096] = {0};
    uint8_t reply[4096];
    size_t verified_bytes = 0;
    const size_t payload_bytes = (size_t)256 * 1024;
    while (verified_bytes < payload_bytes) {
        size_t chunk_bytes = payload_bytes - verified_bytes;
        if (chunk_bytes > sizeof(payload)) {
            chunk_bytes = sizeof(payload);
        }
        for (size_t i = 0; i < chunk_bytes; ++i) {
            payload[i] = (uint8_t)((verified_bytes + i) % 251);
        }
        size_t accepted_bytes = 0;
        if (!check_status("stream_write", ariad_stream_write(stream, payload, chunk_bytes, 10000,
                                                             &accepted_bytes))) {
            goto failed;
        }
        if (accepted_bytes == 0 || accepted_bytes > chunk_bytes) {
            (void)fprintf(stderr, "invalid accepted prefix\n");
            goto failed;
        }
        size_t chunk_reply_bytes = 0;
        while (chunk_reply_bytes < accepted_bytes) {
            size_t bytes_read = 0;
            if (!check_status("stream_read",
                              ariad_stream_read(stream, reply, accepted_bytes - chunk_reply_bytes,
                                                10000, &bytes_read))) {
                goto failed;
            }
            if (bytes_read == 0 || bytes_read > accepted_bytes - chunk_reply_bytes ||
                memcmp(reply, payload + chunk_reply_bytes, bytes_read) != 0) {
                (void)fprintf(stderr, "echo mismatch\n");
                goto failed;
            }
            chunk_reply_bytes += bytes_read;
        }
        verified_bytes += accepted_bytes;
    }
    if (!check_status("stream_end_write", ariad_stream_end_write(stream, 10000))) {
        goto failed;
    }
    size_t bytes_read = 123;
    if (ariad_stream_read(stream, reply, sizeof(reply), 10000, &bytes_read) != ARIAD_EOF ||
        bytes_read != 0) {
        (void)fprintf(stderr, "missing stream EOF\n");
        goto failed;
    }
    if (!check_status("stream_destroy", ariad_stream_destroy(stream))) {
        goto failed;
    }
    if (ariad_stream_destroy(stream) != ARIAD_ERROR_INVALID_HANDLE) {
        (void)fprintf(stderr, "destroyed stream accepted again\n");
        goto failed;
    }
completed:
    if (!check_status("session_close", ariad_session_close(session, ARIAD_CLOSE_GRACEFUL, 10000))) {
        goto failed;
    }
    if (!use_datagrams &&
        !destroy_during_read(argv[1], argv[2], trust_root_der, trust_root_len, argv[4])) {
        goto failed;
    }
    if (!check_status("engine_destroy", ariad_engine_destroy(engine, 10000))) {
        goto failed;
    }
    if (ariad_session_destroy(session) != ARIAD_ERROR_INVALID_HANDLE) {
        (void)fprintf(stderr, "engine destroy retained session\n");
        return 1;
    }
    if (use_datagrams) {
        puts("c_h2_datagram=ok");
    } else {
        printf("c_h2_echo=ok bytes=%zu\n", verified_bytes);
    }
    return 0;

failed:
    if (engine != 0) {
        int32_t cleanup = ariad_engine_destroy(engine, 1000);
        if (cleanup != ARIAD_OK && cleanup != ARIAD_FORCED) {
            (void)fprintf(stderr, "engine cleanup failed: %d\n", (int)cleanup);
        }
    }
    return 1;
}
