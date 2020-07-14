#include <stdio.h>
#include <unistd.h>

#include <cjose/cjose.h>
#include <jansson.h>
#include <string.h>

cjose_jws_t *create_jws(cjose_jwk_t * key, json_t * header, json_t * claims)
{
	cjose_err err;
	char *claims_str = json_dumps(claims, 0);
	cjose_jws_t *jws =
	    cjose_jws_sign(key, header, (const uint8_t *)claims_str,
			   strlen(claims_str), &err);
	free(claims_str);
	return jws;
}

json_t *create_header(const char *typ, const char *alg, const char *kid)
{
	json_t *header_json = json_object();
	if (typ) {
		json_object_set_new(header_json, "typ", json_string(typ));
	}
	if (alg) {
		json_object_set_new(header_json, "alg", json_string(alg));
	}
	if (kid) {
		json_object_set_new(header_json, "kid", json_string(kid));
	}
	return header_json;
}

json_t *create_claims(const char *audience, const char *issuer,
		      json_int_t issued_at, json_int_t not_before,
		      json_int_t expires, const char *preferred_user_name)
{
	json_t *claims_json = json_object();
	if (audience) {
		json_object_set_new(claims_json, "aud", json_string(audience));
	}
	if (issuer) {
		json_object_set_new(claims_json, "iss", json_string(issuer));
	}
	if (issued_at) {
		json_object_set_new(claims_json, "iat",
				    json_integer(issued_at));
	}
	if (not_before) {
		json_object_set_new(claims_json, "nbf",
				    json_integer(not_before));
	}
	if (expires) {
		json_object_set_new(claims_json, "exp", json_integer(expires));
	}
	if (preferred_user_name) {
		json_object_set_new(claims_json, "oid",
				    json_string(preferred_user_name));
	}
	return claims_json;
}

void generate_token(cjose_jwk_t * key, const char *typ, const char *alg,
		    const char *kid, const char *audience, const char *issuer,
		    const char *user_name, json_int_t issued_at,
		    json_int_t not_before, json_int_t expires)
{
	cjose_err err;
	json_t *header = create_header(typ, alg, kid);
	json_t *claims =
	    create_claims(audience, issuer, issued_at, not_before, expires,
			  user_name);
	cjose_jws_t *jws = create_jws(key, header, claims);
	const char * token = NULL;
	cjose_jws_export(jws, &token, &err);
	printf("%s", token);

	cjose_jws_release(jws);
	json_decref(header);
	json_decref(claims);
}


int main(int argc, char ** argv) 
{
	cjose_err err;
	json_error_t err1;
    char * line = NULL;
	size_t line_len = 0;
	cjose_jwk_t * key;
	const char audience[] = "SomeAudience";
	const char issuer[] = "SomeIssuer";
	const char * kid;
	const char typ[] = "JWT";
	const char alg[] = "ES256";
	time_t now = time(NULL);

	if (argc < 2) {
		fprintf(stderr, "Missing argument: %s user_name\n", argv[0]);
		return -1;
	}

	getline(&line, &line_len, stdin);

	json_t * json_key = json_loads(line, 0, &err1);
	if (!json_key) {
		printf("Failed: %s\n", err1.text);
		return -1;
	}

	key = cjose_jwk_import_json(json_key, &err);
	if (!key) {
		fprintf(stderr, "Failed: %s %s %ld\n", err.message, err.file, err.line);
		return -1;
	}

	kid = cjose_jwk_get_kid(key, &err);

	generate_token(key, typ, alg, kid,
		       audience, issuer, argv[1], now - 60, now - 60,
		       now + 3600);

    return 0;
}