#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <cjose/cjose.h>
#include <jansson.h>
#include <string.h>

json_t *create_openid_configuration(char *key_url)
{
	json_t *config = json_object();
	if (json_object_set_new(config, "jwks_uri", json_string(key_url))) {
		json_decref(config);
		return NULL;
	}
	return config;
}

int main(int argc, char ** argv) 
{
	if (argc < 2) {
		fprintf(stderr, "Missing argument: %s key_url\n", argv[0]);
		return -1;
	}

	json_t * config = create_openid_configuration(argv[1]);
	printf("%s", json_dumps(config, 0));

	// free(line);
    return 0;
}