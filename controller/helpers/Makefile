CC=gcc
LIBS=-lcjose -ljansson
CFLAGS=

TARGETS=bin/generate_keys bin/generate_root_key bin/generate_oidc_config bin/generate_token

all: bin $(TARGETS)

%: ../%.c
	$(CC) -o $@ $< $(CFLAGS) $(LIBS)

bin:
	mkdir bin


clean:
	rm -rf bin

install:
	
