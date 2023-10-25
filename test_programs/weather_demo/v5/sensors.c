#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sensors.h"

sensor_row *latest_data;

sensor_row *get_next_sensor_data() {
  sensor_row *ret = NULL;
  if (latest_data) {
    ret = latest_data;
    latest_data = latest_data->next;
  }
  return ret;
}

// updates global linked list `latest_data`
void prepopulate_sensor_data(char *filename) {
  latest_data = NULL;		/* start with empty linked list */
  FILE *file = fopen(filename,"r");
  if (file == NULL) {
    perror("Error opening file");
  } else {
    int temp_vals[NUM_SENSORS];	/* row currently being built/read from file */
    sensor_row *new_row;
    char line[MAX_LINE_LEN];

    while (fgets(line, sizeof(line), file)) {
      // read space or tab-separated values
      int n = 0;	   /* how many ints read so for for new row */
      char *token = strtok(line, " \t\n"); // get first token, if any
      while ((token != NULL) && (n < NUM_SENSORS)) {
	temp_vals[n++] = atoi(token);
	token = strtok(NULL, " \t\n"); // advance to the next token
      }

      // allocate and populate new row

      new_row = malloc(sizeof(sensor_row));
      new_row->num_vals = n;
      new_row->vals = malloc(n * sizeof(int));
      memcpy(new_row->vals, temp_vals, n * sizeof(int));
      new_row->next = latest_data;
      latest_data = new_row;
    }

    fclose(file);
  }
}

int sensor_fusion(sensor_row *row) {
  int ret = 0;
  for (int i = 0; i < row->num_vals; i++) {
    ret += row->vals[i];
  }
  if (row->num_vals == 0) {
      fprintf(stderr, "Error, divide by zero\n");
      abort();
  }
  return (ret / row->num_vals);
}
