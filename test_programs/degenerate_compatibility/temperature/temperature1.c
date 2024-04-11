#include <stdio.h>
#include <stdlib.h>

int THRESHOLD = 100;

void check_avg_temp(int a, int b, int c) {
  
  int avg = (a + b + c) / 3;

  if (avg > THRESHOLD) {
    printf("It's too darn hot!\n");
  } else {
    printf("All clear\n");
  }
}


int main(int argc, char *argv[]) {

  int a = atoi(argv[1]);
  int b = atoi(argv[2]);
  int c = atoi(argv[3]);

  check_avg_temp(a, b, c);

  return EXIT_SUCCESS;
}
