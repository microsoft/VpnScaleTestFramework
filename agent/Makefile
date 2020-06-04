all: TestClient TestGenerator

TestClient: TestClient.c 
	gcc -g TestClient.c -o TestClient -lgnutls -lnettle -ljansson -lcurl

TestGenerator: TestGenerator.c 
	gcc -g TestGenerator.c -o TestGenerator -lgnutls -lnettle -ljansson -lcurl

clean: 
	rm TestGenerator TestClient