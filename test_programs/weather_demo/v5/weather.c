#include <stdio.h>
#include <stdlib.h>
#include "sensors.h"

int process_sensor_data() {
  int i, sum = 0;
  sensor_row *row;
  for (i = 0; (row = get_next_sensor_data()); i++) {
#ifdef PATCH1
    if (row->num_vals > 0) {
#endif
      sum += sensor_fusion(row);
#ifdef PATCH1
    }
#endif
#ifdef PATCH2
    else { i--; }
#endif    
  }
  return sum / i;
}

int main(int argc, char *argv[]) {
  int ave;
  char *fname;
  if (argc == 1) {
    fname = "data/data.txt";
  } else {
    fname = argv[1];
  }
  printf("reading data from: %s.\n", fname);
  prepopulate_sensor_data(fname);
  ave = process_sensor_data();
  printf("Average value = %d\n", ave);
  return 0;
}
