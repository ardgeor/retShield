#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


void usage(char* progName) {
    printf("Usage: %s <string>\n", progName);
    exit(0);
}

void processData(char *data) {
    char buffer[64];    
    strcpy(buffer, data);    
    printf("Data processed: %s\n", buffer);
}

int main(int argc, char** argv) {    

    if(argc < 2) {
        usage(argv[0]);
    }

    printf("[*] Initializing...\n");
    sleep(5);
    printf("[*] Processing data...\n");

    char buffer[64];
    char* input = argv[1];
    processData(input);
    printf("Bye\n");
    return 0;
}

