#include <stdio.h>
#include <unistd.h>

#include <cjose/cjose.h>
#include <jansson.h>
#include <string.h>

cjose_jwk_t *create_key(const char *kid)
{
	cjose_err err;
	cjose_jwk_t *key = cjose_jwk_create_EC_random(CJOSE_JWK_EC_P_256, &err);
	if (!key) {
		return NULL;
	}

	if (!cjose_jwk_set_kid(key, kid, strlen(kid), &err)) {
		return NULL;
	}
	return key;
}

int main(int argc, char ** argv) 
{
	cjose_err err;
	if (argc < 2) {
		fprintf(stderr, "Missing argument: %s kid\n", argv[0]);
		return -1;
	}

    cjose_jwk_t * key = create_key(argv[1]);
    printf("%s", cjose_jwk_to_json(key, true, &err));
    return 0;
}