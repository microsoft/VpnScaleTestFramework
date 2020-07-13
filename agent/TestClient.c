#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <nettle/base64.h>
#include <curl/curl.h>
#include <jansson.h>
#include <gnutls/abstract.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <stdlib.h>

typedef struct fetch_string_context
{
    char *buffer;
    size_t length;
    size_t offset;
} fetch_string_context;

static void kill_on_parent_kill()
{
    prctl(PR_SET_PDEATHSIG, SIGKILL);
}

// Callback from CURL for each block as it is downloaded
static size_t fetch_string_context_callback(char *ptr, size_t size,
                                            size_t nmemb, void *userdata)
{
    fetch_string_context *context =
        (fetch_string_context *)userdata;
    size_t new_offset = context->offset + nmemb;

    // Check for buffer overflow
    if (new_offset < nmemb)
    {
        return 0;
    }

    if (context->offset + nmemb > context->length)
    {
        size_t new_size = (nmemb + context->length) * 3 / 2;
        void *new_buffer = realloc(context->buffer, new_size);
        if (new_buffer)
        {
            context->buffer = new_buffer;
            context->length = new_size;
        }
        else
        {
            return 0;
        }
    }

    memcpy(context->buffer + context->offset, ptr, nmemb);
    context->offset = new_offset;

    return nmemb;
}

// Download a string from the provided URI
static char *fetch_string_from_uri(const char *uri)
{
    fetch_string_context context = {NULL, 0, 0};
    json_t *json = NULL;
    json_error_t err;
    CURL *curl = NULL;
    CURLcode res;

    context.length = 4096;
    context.buffer = malloc(context.length);

    if (context.buffer == NULL)
    {
        goto cleanup;
    }

    curl = curl_easy_init();
    if (!curl)
    {
        fprintf(stderr,
                "Failed to download JSON document: URI %s\n",
                uri);
        goto cleanup;
    }

    res = curl_easy_setopt(curl, CURLOPT_URL, uri);
    if (res != CURLE_OK)
    {
        fprintf(stderr,
                "Failed to download JSON document: URI %s, CURLcode %d\n",
                uri, res);
        goto cleanup;
    }

    res =
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                         fetch_string_context_callback);
    if (res != CURLE_OK)
    {
        fprintf(stderr,
                "Failed to download JSON document: URI %s, CURLcode %d\n",
                uri, res);
        goto cleanup;
    }

    res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &context);
    if (res != CURLE_OK)
    {
        fprintf(stderr,
                "Failed to download JSON document: URI %s, CURLcode %d\n",
                uri, res);
        goto cleanup;
    }

    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        fprintf(stderr,
                "Failed to download JSON document: URI %s, CURLcode %d\n",
                uri, res);
        goto cleanup;
    }

cleanup:
    if (res != 0 && context.buffer)
    {
        free(context.buffer);
        context.buffer = NULL;
    }
    else
    {
        context.buffer[context.offset] = '\0';
    }

    if (curl)
    {
        curl_easy_cleanup(curl);
    }

    return context.buffer;
}

static int base64_decode_to_datum(const char *base64, gnutls_datum_t *datum)
{
    int err = 1;
    struct base64_decode_ctx decode_ctx;
    size_t base64_length = strlen(base64);
    uint8_t *local_binary = NULL;
    size_t local_binary_length = 0;

    nettle_base64_decode_init(&decode_ctx);

    local_binary_length = BASE64_DECODE_LENGTH(base64_length);
    local_binary = malloc(local_binary_length);

    if (!nettle_base64_decode_update(&decode_ctx, &local_binary_length, local_binary, base64_length, base64))
    {
        fprintf(stderr,
                "nettle_base64_decode_update failed\n");
        goto cleanup;
    }

    if (!nettle_base64_decode_final(&decode_ctx))
    {
        fprintf(stderr,
                "nettle_base64_decode_final failed\n");
        goto cleanup;
    }

    datum->data = local_binary;
    local_binary = NULL;
    datum->size = local_binary_length;
    err = 0;

cleanup:
    if (local_binary)
    {
        free(local_binary);
    }
    return err;
}

gnutls_x509_crt_t load_cert_from_file(const char *file)
{
    int retval = -1;
    gnutls_datum_t data = {NULL, 0};
    gnutls_x509_crt_t cert = NULL;
    int err = -1;

    if (err = gnutls_x509_crt_init(&cert))
    {
        fprintf(stderr,
                "gnutls_x509_crt_init failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

    if (err = gnutls_load_file(file, &data))
    {
        fprintf(stderr,
                "gnutls_load_file failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

    if (err = gnutls_x509_crt_import(cert, &data, GNUTLS_X509_FMT_PEM))
    {
        fprintf(stderr,
                "gnutls_x509_crt_import failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

cleanup:
    if (data.data)
    {
        gnutls_free(data.data);
    }

    if (err != 0 && cert != NULL)
    {
        gnutls_x509_crt_deinit(cert);
        cert = NULL;
    }

    return cert;
}

int registration(const char *base_url, gnutls_x509_crt_t root_cert, char client_id_str[128], gnutls_x509_crt_t *cert)
{
    int err = 1;
    char register_url[1024];
    char *registration_string = NULL;
    json_t *registration_json = NULL;
    json_t *client_id = NULL;
    json_t *certificate = NULL;
    gnutls_datum_t der_cert = {NULL, 0};
    gnutls_x509_trust_list_t trust_list = NULL;
    unsigned int verify = 0;

    *cert = NULL;

    snprintf(register_url, sizeof(register_url), "%s/register", base_url);

    registration_string = fetch_string_from_uri(register_url);
    if (registration_string == NULL)
    {
        fprintf(stderr, "fetch_string_from_uri failed for %s\n", register_url);
        goto cleanup;
    }

    if (strcmp(registration_string, "No active tests\n") == 0)
    {
        err = 0;
        goto cleanup;
    }

    registration_json = json_loads(registration_string, 0, NULL);
    if (registration_json == NULL)
    {
        fprintf(stderr, "json_loads failed for %s\n", register_url);
        goto cleanup;
    }

    client_id = json_object_get(registration_json, "ClientId");
    if (!client_id)
    {
        fprintf(stderr, "ClientId not found\n");
        goto cleanup;
    }
    if (!json_string_value(client_id))
    {
        fprintf(stderr, "ClientId not found\n");
        goto cleanup;
    }

    strncpy(client_id_str, json_string_value(client_id), 128);

    certificate = json_object_get(registration_json, "Certificate");
    if (!certificate)
    {
        fprintf(stderr, "Certificate not found\n");
        goto cleanup;
    }

    if (!certificate || !json_string_value(certificate))
    {
        fprintf(stderr, "Certificate not found\n");
        goto cleanup;
    }

    if (base64_decode_to_datum(json_string_value(certificate), &der_cert))
    {
        fprintf(stderr, "base64_decode failed\n");
        goto cleanup;
    }

    if (err = gnutls_x509_crt_init(cert))
    {
        fprintf(stderr,
                "gnutls_x509_crt_init failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

    if (err = gnutls_x509_crt_import(*cert, &der_cert, GNUTLS_X509_FMT_DER))
    {
        fprintf(stderr,
                "gnutls_x509_crt_init failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

    if (err = gnutls_x509_trust_list_init(&trust_list, 0))
    {
        fprintf(stderr,
                "gnutls_x509_trust_list_init failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

    if (gnutls_x509_trust_list_add_cas(trust_list, &root_cert, 1, 0) != 1)
    {
        fprintf(stderr,
                "gnutls_x509_trust_list_add_cas failed\n");
        goto cleanup;
    }

    if (err = gnutls_x509_trust_list_verify_crt(trust_list, cert, 1, 0, &verify, NULL))
    {
        fprintf(stderr,
                "gnutls_x509_trust_list_verify_crt failed - %d %s\n", err, gnutls_strerror(err));
        goto cleanup;
    }

cleanup:
    if (registration_json)
    {
        json_decref(registration_json);
    }

    if (der_cert.data)
    {
        free(der_cert.data);
    }

    if (err != 0 && *cert != NULL)
    {
        gnutls_x509_crt_deinit(*cert);
        *cert = NULL;
    }

    if (registration_string)
    {
        free(registration_string);
    }

    if (trust_list)
    {
        gnutls_x509_trust_list_deinit(trust_list, 0);
    }

    return err;
}

int next_command(const char *base_url, const char *client_id, gnutls_pubkey_t pub_key, char *previous_signature, char **command, char **signature)
{
    int err = 1;
    char next_command_url[1024];
    char *next_command_string = NULL;
    json_t *json = NULL;
    json_t *json_command = NULL;
    json_t *json_signature = NULL;
    char *local_command = NULL;
    char *local_signature = NULL;
    char *previous_signature_and_data = NULL;
    size_t previous_signature_and_data_length = 0;
    gnutls_datum_t data = {NULL, 0};
    gnutls_datum_t signature_blob = {NULL, 0};

    snprintf(next_command_url, sizeof(next_command_url), "%s/NextCommand?id=%s", base_url, client_id);

    next_command_string = fetch_string_from_uri(next_command_url);
    if (next_command_string == NULL)
    {
        fprintf(stderr, "fetch_string_from_uri failed for %s\n", next_command_url);
        goto cleanup;
    }

    if (strncmp(next_command_string, "wait", 4) == 0)
    {
        err = 0;
        *command = next_command_string;
        next_command_string = NULL;
        goto cleanup;
    }

    if (strncmp(next_command_string, "exit", 4) == 0)
    {
        err = 0;
        *command = next_command_string;
        next_command_string = NULL;
        goto cleanup;
    }

    json = json_loads(next_command_string, 0, NULL);
    if (json == NULL)
    {
        fprintf(stderr, "json_loads failed for %s\n", next_command_string);
        goto cleanup;
    }

    json_command = json_object_get(json, "Value");
    if (!json_command || !json_string_value(json_command))
    {
        fprintf(stderr, "Value not found\n");
        goto cleanup;
    }

    json_signature = json_object_get(json, "Signature");
    if (!json_signature || !json_string_value(json_signature))
    {
        fprintf(stderr, "Signature not found\n");
        goto cleanup;
    }

    local_command = strdup(json_string_value(json_command));
    if (!local_command)
    {
        goto cleanup;
    }

    local_signature = strdup(json_string_value(json_signature));
    if (!local_signature)
    {
        goto cleanup;
    }

    if (base64_decode_to_datum(local_signature, &signature_blob))
    {
        fprintf(stderr, "base64_decode failed\n");
        goto cleanup;
    }

    previous_signature_and_data_length = previous_signature ? strlen(previous_signature) : 0 + sizeof(' ') + strlen(local_command) + 1;
    previous_signature_and_data = malloc(previous_signature_and_data_length);
    previous_signature_and_data[0] = '\0';
    snprintf(previous_signature_and_data, previous_signature_and_data_length, "%s %s", previous_signature ? previous_signature : "", local_command);
    data.data = previous_signature_and_data;
    previous_signature_and_data = NULL;
    data.size = strlen(data.data);

    if (err = gnutls_pubkey_verify_data2(pub_key, GNUTLS_SIGN_ECDSA_SHA256, 0, &data, &signature_blob))
    {
        fprintf(stderr, "gnutls_pubkey_verify_data2 returned %d - %s\n", err, gnutls_strerror(err));
        goto cleanup;
    }

    *command = local_command;
    local_command = NULL;
    *signature = local_signature;
    local_signature = NULL;
    err = 0;

cleanup:
    if (json)
    {
        json_decref(json);
    }

    if (data.data)
    {
        free(data.data);
    }

    if (signature_blob.data)
    {
        free(signature_blob.data);
    }

    if (local_command)
    {
        free(local_command);
    }
    if (local_signature)
    {
        free(local_signature);
    }

    if (previous_signature_and_data)
    {
        free(previous_signature_and_data);
    }

    if (next_command_string)
    {
        free(next_command_string);
    }

    return err;
}

int run_command(char *command, char **result, int * exit_code)
{
    int err = -1;
    int sockets[2] = {-1, -1};
    pid_t pid_child;
    char *local_result = NULL;
    size_t index = 0;
    int wait_for_child = command[strlen(command) - 1] != '&';
    pid_t ppid = getpid();

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0)
    {
        goto cleanup;
    }

    pid_child = fork();
    if (pid_child == 0)
    {
        int argc = 10;
        int current_arg = 0;
        char **argv = malloc(sizeof(char *) * (argc + 1));
        char *ptok = NULL;

        // Send SIGKILL when the parent process dies.
        kill_on_parent_kill();

        // Check for the case where the parent died before installing the handler.
        if (ppid != getppid()) {
            exit(0);
        }

        memset(argv, 0, sizeof(char *) * (argc + 1));
        argv[current_arg++] = "bash";
        argv[current_arg++] = "-c";
        argv[current_arg++] = command;
        argv[current_arg++] = NULL;

        close(sockets[0]);

        dup2(sockets[1], STDIN_FILENO);
        dup2(sockets[1], STDOUT_FILENO);
        dup2(sockets[1], STDERR_FILENO);
        
        switch(sockets[1]) {
        case STDIN_FILENO:
        case STDOUT_FILENO:
        case STDERR_FILENO:
            break;
        default:
            close(sockets[1]);
        }

        execvp("bash", argv);
        exit(1);
    }
    else
    {
        size_t local_result_size = 4096;
        size_t local_result_offset = 0;
        int stat;

        local_result = malloc(local_result_size);
        close(sockets[1]);

        if (!wait_for_child)
        {
            *result = strdup("Background");
            err = 0;
            goto cleanup;
        }

        for (;;)
        {
            int bytes_read = read(sockets[0], local_result + local_result_offset, local_result_size - local_result_offset);
            if (bytes_read == 0)
            {
                err = 0;
                break;
            }
            else if (bytes_read == -1)
            {
                err = errno;
                fprintf(stderr, "read failed %s\n", strerror(err));
                break;
            }
            else
            {
                local_result_offset += bytes_read;
                if (local_result_offset == local_result_size)
                {
                    size_t new_size = local_result_size + local_result_size / 2;
                    void *p;
                    p = realloc(local_result, new_size);
                    if (!p)
                    {
                        err = errno;
                        break;
                    }
                    local_result = p;
                    local_result_size = new_size;
                }
            }
        }
        local_result[local_result_offset] = '\0';
        wait(&stat);

        if (err != 0)
        {
            goto cleanup;
        }
    }

    *result = local_result;
    local_result = NULL;

cleanup:
    if (sockets[0] != -1)
    {
        close(sockets[0]);
    }
    if (sockets[1] != -1)
    {
        close(sockets[1]);
    }
    if (local_result)
    {
        free(local_result);
    }
    return err;
}

int post_result(const char *base_url, const char *client_id, const char *value)
{
    CURL *curl = NULL;
    CURLcode res;

    char uri[1024];
    snprintf(uri, sizeof(uri), "%s/CommandResult?id=%s", base_url, client_id);

    curl = curl_easy_init();
    if (!curl)
    {
        fprintf(stderr,
                "curl_easy_init error %d\n",
                res);
        goto cleanup;
    }

    res = curl_easy_setopt(curl, CURLOPT_URL, uri);
    if (res != CURLE_OK)
    {
        fprintf(stderr,
                "curl_easy_setopt CURLOPT_URL failed CURLcode %d\n",
                res);
        goto cleanup;
    }

    res = curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if (res != CURLE_OK)
    {
        fprintf(stderr,
                "curl_easy_setopt CURLOPT_POST failed CURLcode %d\n",
                res);
        goto cleanup;
    }

    res =
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, value);
    if (res != CURLE_OK)
    {
        fprintf(stderr,
                "curl_easy_setopt CURLOPT_POSTFIELDS failed CURLcode %d\n",
                res);
        goto cleanup;
    }

    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        fprintf(stderr,
                "curl_easy_perform failed CURLcode %d\n",
                res);
        goto cleanup;
    }

cleanup:
    if (curl)
    {
        curl_easy_cleanup(curl);
    }

    return res;
}

int set_watchdog(int delay)
{
    struct itimerval new_interval = {};

    new_interval.it_value.tv_sec = delay;
    if (setitimer(ITIMER_REAL, &new_interval, NULL))
    {
        exit(1);
    }
}

void sig_alarm_handler(int signal)
{
    fprintf(stderr, "Watchdog timeout\n");
    exit(1);
}

int main(int argc, char **argv)
{
    gnutls_x509_crt_t root_cert = NULL;
    const char *base_url;
    char client_id[128];
    char next_cmd_url[1024];
    char result_url[1024];
    gnutls_x509_crt_t cert = NULL;
    gnutls_pubkey_t pub_key = NULL;
    char *previous_signature = NULL;
    char *command = NULL;
    char *signature = NULL;
    int err = 1;
    int wait = 0;
    int exit_code = 0;
    char *result = NULL;
    int retry_delay = 1;
    int max_command_duration = 3600;
    struct sigaction alarm_signal = {sig_alarm_handler};
    char directory_template[] = "/tmp/test_client_XXXXXX";


    sigaction(SIGALRM, &alarm_signal, NULL);

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s base_uri root_cert\n", argv[0]);
        goto cleanup;
    }

    if (!mkdtemp(directory_template))
    {
        int err = errno;
        fprintf(stderr, "Failed to create temp folder : %s\n", strerror(err));
    }
    if (chdir(directory_template))
    {
        int err = errno;
        fprintf(stderr, "Failed to chdir to %s : %s\n", directory_template, strerror(err));
    }


    base_url = argv[1];

    root_cert = load_cert_from_file(argv[2]);
    if (!root_cert)
    {
        goto cleanup;
    }

    for (;;)
    {
        set_watchdog(max_command_duration);
        if (registration(base_url, root_cert, client_id, &cert))
        {
            fprintf(stderr, "registration failed\n");
            goto cleanup;
        }
        if (cert != NULL)
        {
            break;
        }
        fprintf(stderr, "No tests waiting\n");
        sleep(30);
    }

    if (err = gnutls_pubkey_init(&pub_key))
    {
        fprintf(stderr, "gnutls_pubkey_init failed - %s\n", gnutls_strerror(err));
    }

    if (err = gnutls_pubkey_import_x509(pub_key, cert, 0))
    {
        fprintf(stderr, "gnutls_pubkey_import_x509 failed - %s\n", gnutls_strerror(err));
    }

    for (;;)
    {
        set_watchdog(max_command_duration);
        retry_delay = 1;
        // Retry until the watchdog kills this process.
        for (;;)
        {
            if (!next_command(base_url, client_id, pub_key, previous_signature, &command, &signature))
            {
                break;
            }
            // If we fail to get a command, wait and retry.
            sleep(retry_delay);
            retry_delay = retry_delay > 30 ? 30 : retry_delay * 2;
        }

        if (strncmp(command, "wait", 4) == 0)
        {
            sleep(5);
        }
        else if (strncmp(command, "exit", 4) == 0)
        {
            break;
        }
        else
        {
            set_watchdog(max_command_duration);
            fprintf(stderr, "Running command %s\n", command);
            // Run the command until the watchdog kills this process.
            if (err = run_command(command, &result, &exit_code))
            {
                char failed_result[100];
                snprintf(failed_result, sizeof(failed_result), "Command failed %d", err);
                result = strdup(failed_result);
            }

            set_watchdog(max_command_duration);
            retry_delay = 1;
            fprintf(stderr, "posting result\n");
            // Retry until the watchdog kills this process.
            for (;;)
            {
                if (!post_result(base_url, client_id, result))
                {
                    break;
                }
                sleep(retry_delay);
                retry_delay = retry_delay > 30 ? 30 : retry_delay * 2;
            }
            
            // If a command fails, terminate the test.
            if (exit_code)
            {
                break;
            }

            free(result);
            result = NULL;
            if (previous_signature)
            {
                free(previous_signature);
            }
            previous_signature = signature;
            signature = NULL;
        }
        free(command);
        command = NULL;
    }

cleanup:
    if (result)
    {
        free(result);
    }

    if (command)
    {
        free(command);
    }

    if (signature)
    {
        free(signature);
    }

    if (previous_signature)
    {
        free(previous_signature);
    }

    if (pub_key)
    {
        gnutls_pubkey_deinit(pub_key);
    }

    if (root_cert)
    {
        gnutls_x509_crt_deinit(root_cert);
    }

    if (cert)
    {
        gnutls_x509_crt_deinit(cert);
    }
    return err;
}