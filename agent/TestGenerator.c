#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>
#include <nettle/base64.h>
#include <jansson.h>
#include <gnutls/abstract.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <ctype.h>

int load_priv_key_from_pkcs12(const char *file, const char *password, gnutls_x509_privkey_t *priv_key, char **cert)
{
    int err;
    gnutls_pkcs12_t p12 = NULL;
    gnutls_datum_t data = {NULL, 0};
    gnutls_x509_privkey_t local_priv_key = NULL;
    gnutls_x509_crt_t *chain = NULL;
    unsigned int chain_length = 0;
    gnutls_datum_t cert_der = {NULL, 0};
    size_t local_cert_length = 0;
    char *local_cert = NULL;

    if (err = gnutls_pkcs12_init(&p12))
    {
        fprintf(stderr, "gnutls_pkcs12_init failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

    if (err = gnutls_load_file(file, &data))
    {
        fprintf(stderr,
                "gnutls_load_file failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

    if (err = gnutls_pkcs12_import(p12, &data, GNUTLS_X509_FMT_DER, 0))
    {
        fprintf(stderr, "gnutls_pkcs12_import failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

    if (err = gnutls_pkcs12_simple_parse(p12, password, &local_priv_key, &chain, &chain_length, NULL, NULL, NULL, 0))
    {
        fprintf(stderr, "gnutls_pkcs12_simple_parse failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

    if (err = gnutls_x509_crt_export2(chain[0], GNUTLS_X509_FMT_DER, &cert_der))
    {
        fprintf(stderr, "gnutls_x509_crt_export2 failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

    local_cert_length = BASE64_ENCODE_RAW_LENGTH(cert_der.size);
    local_cert = malloc(local_cert_length + 1);

    nettle_base64_encode_raw(local_cert, cert_der.size, cert_der.data);

    *cert = local_cert;
    local_cert = NULL;

    *priv_key = local_priv_key;
    local_priv_key = NULL;

    err = 0;
cleanup:
    if (data.data)
    {
        gnutls_free(data.data);
    }

    if (local_priv_key)
    {
        gnutls_x509_privkey_deinit(local_priv_key);
    }

    if (p12)
    {
        gnutls_pkcs12_deinit(p12);
    }

    return err;
}

int sign_command(gnutls_x509_privkey_t priv_key, const char *command, const char *previous_signature, char **signature)
{
    int err;
    gnutls_datum_t data = {NULL, 0};
    void *sign = NULL;
    size_t sign_len = 0;
    char *previous_signature_and_data = NULL;
    size_t previous_signature_and_data_length = 0;
    struct base64_encode_ctx encode_ctx;
    char *local_signature = NULL;
    size_t local_signature_length = 0;

    previous_signature_and_data_length = previous_signature ? strlen(previous_signature) : 0 + sizeof(' ') + strlen(command) + 1;
    previous_signature_and_data = malloc(previous_signature_and_data_length);
    previous_signature_and_data[0] = '\0';
    snprintf(previous_signature_and_data, previous_signature_and_data_length, "%s %s", previous_signature ? previous_signature : "", command);
    data.data = previous_signature_and_data;
    data.size = strlen(data.data);

    sign_len = 1024;
    sign = malloc(sign_len);

    if (err = gnutls_x509_privkey_sign_data(priv_key, GNUTLS_DIG_SHA256, 0, &data, sign, &sign_len))
    {
        fprintf(stderr, "gnutls_x509_privkey_sign_data failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

    local_signature_length = BASE64_ENCODE_RAW_LENGTH(sign_len);
    local_signature = malloc(local_signature_length + 1);

    nettle_base64_encode_raw(local_signature, sign_len, sign);

    local_signature[local_signature_length] = '\0';

    *signature = local_signature;
    local_signature = NULL;

cleanup:
    if (sign)
    {
        free(sign);
    }
    if (local_signature)
    {
        free(local_signature);
    }
    err = 0;
}

int main(int argc, char **argv)
{
    int err = 1;
    int index;
    gnutls_x509_privkey_t priv_key = NULL;
    char *cert = NULL;
    char *signature = NULL;
    char *previous_signature = NULL;
    json_t *root_json = json_object();
    json_t *commands_json = json_array();
    json_t *command_json = NULL;
    char *line = NULL;
    size_t line_len = 0;

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s pfx test_id minimum\n", argv[0]);
        goto cleanup;
    }

    if (err = load_priv_key_from_pkcs12(argv[1], getpass("PFX Password:"), &priv_key, &cert))
    {
        fprintf(stderr, "load_priv_key_from_pkcs12 failed - %s\n", gnutls_strerror(err));
        goto cleanup;
    }

    json_object_set_new(root_json, "Id", json_string(argv[2]));
    json_object_set_new(root_json, "Certificate", json_string(cert));
    json_object_set_new(root_json, "Minimum", json_integer(atoi(argv[3])));
    json_object_set_new(root_json, "Maximum", json_integer(atoi(argv[3]) * 11 / 10));
    json_object_set_new(root_json, "Commands", commands_json);

    while (getline(&line, &line_len, stdin) > 0)
    {
        // Strip trailing new space
        for (index = strlen(line); index >= 0; index --) 
        {
            switch (line[index]) 
            {
            case ' ':
            case '\t':
            case '\n':
            case '\v':
            case '\f':
            case '\r':
            case '\0':
                line[index] = '\0';
                break;
            default:
                index = -1;
                break;
            }
        }
        
        if (strlen(line) == 0) 
        {
            continue;
        }
        if (line[0] == '#')
        {
            continue;
        }
        if (err = sign_command(priv_key, line, previous_signature, &signature))
        {
            fprintf(stderr, "sign_command failed - %s\n", gnutls_strerror(err));
            goto cleanup;
        }

        if (previous_signature)
        {
            free(previous_signature);
        }

        previous_signature = signature;

        command_json = json_object();
        json_object_set_new(command_json, "Value", json_string(line));
        json_object_set_new(command_json, "Signature", json_string(signature));
        json_array_append_new(commands_json, command_json);
    }

    printf("%s\n", json_dumps(root_json, JSON_INDENT(2)));
    err = 0;

cleanup:

    return err;
}