
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SERIAL_DELIMS 8;

void delete(char *data) { printf("deleting: \"%s\"\n", data + 2); }

void store(char *data) { printf("stored: \"%s\"\n", data + 2); }

void validateCommand(char *command) {
    for (int idx = 0; command[idx]; idx++) {
        if (command[idx] == ';') {
            puts("bad command!");
            exit(1);
        }
    }
}

void receiver(char *serialized) {
  char *saveptr;
  char *command = strtok_r(serialized, ";", &saveptr);
  char *role = strtok_r(NULL, ";", &saveptr);
  char *data = strtok_r(NULL, "", &saveptr);

  // "sanitize" input
  if ((strcmp(command, "c:DELETE") != 0 && strcmp(command, "c:STORE") != 0) ||
      (strcmp(role, "r:root") != 0 && strcmp(role, "r:guest") != 0)) {
    puts("bad input!");
    exit(1);
  }

  if (strcmp(command, "c:DELETE") == 0 && strcmp(role, "r:root") == 0) {
    delete(data);
  } else if (strcmp(command, "c:STORE") == 0) {
    store(data);
  } else {
    puts("permission denied");
  }
  exit(0);
}

int main(int argc, char **argv) {
  // make sure we have enough arguments
  if (argc != 4)
    return 1;
  char *command = argv[1];
  char *role = argv[2];
  char *data = argv[3];

  validateCommand(command);

  int len = strlen(command) + strlen(role) + strlen(data) + SERIAL_DELIMS;

  char *serialized = malloc(len * sizeof(char));

  sprintf(serialized, "c:%s;r:%s;d:%s", command, role, data);

  receiver(serialized);
}
