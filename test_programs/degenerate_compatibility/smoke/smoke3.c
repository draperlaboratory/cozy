#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

int THRESHOLD = 100;

void check_smoke_detectors(int a, int b, int c, bool actual_fire) {
  
  int avg;
  // incorporate c into avg if non-zero
  if (c == 0) {
    avg = (a + b) / 2;
  } else {
    avg = (a + b + c) / 3;
  }

  if (avg > THRESHOLD == actual_fire) {
    printf("Detectors are working!\n");
  } else {
    printf("Incorrect :(\n");
  }
}


int main(int argc, char *argv[]) {

  int a = atoi(argv[1]);
  int b = atoi(argv[2]);
  int c = atoi(argv[3]);
  bool actual_fire = atoi(argv[4]) != 0;

  check_smoke_detectors(a, b, c, actual_fire);

  return EXIT_SUCCESS;
}
