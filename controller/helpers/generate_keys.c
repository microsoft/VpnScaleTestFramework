#include <stdio.h>
#include <unistd.h>

#include <cjose/cjose.h>
#include <jansson.h>
#include <string.h>

json_t *create_keys(cjose_jwk_t * key)
{
	cjose_err err;
	json_t *keys_json = json_object();
	json_t *keys_array = json_array();
	json_t *key_json;

	const char *key_str = cjose_jwk_to_json(key, false, &err);
	key_json = json_loads(key_str, 0, NULL);
	json_array_append_new(keys_array, key_json);
	json_object_set_new(keys_json, "keys", keys_array);
	return keys_json;
}

cjose_jwk_t * make_public(cjose_jwk_t * private_key)
{
	cjose_jwk_t * key;
	cjose_err err;
	char * key_str = cjose_jwk_to_json(private_key, false, &err);
	key = cjose_jwk_import(key_str, strlen(key_str), &err);
	if (!key) {
		printf("Failed: %s %s %ld\n", err.message, err.file, err.line);
	}
	return key;
}


int main(int argc, char ** argv) 
{
	cjose_err err;
	json_error_t err1;
    char * line = NULL;
	size_t line_len = 0;
	cjose_jwk_t * key;
	getline(&line, &line_len, stdin);

	json_t * json_key = json_loads(line, 0, &err1);
	if (!json_key) {
		printf("Failed: %s\n", err1.text);
		return -1;
	}

	key = cjose_jwk_import_json(json_key, &err);
	if (!key) {
		printf("Failed: %s %s %ld\n", err.message, err.file, err.line);
		return -1;
	}

	printf("%s", json_dumps(create_keys(make_public(key)), 0));

    return 0;
}