#ifndef SENSORS_H
#define SENSORS_H

#define MAX_LINE_LEN 256
#define NUM_SENSORS 4

/* struct SensorRow is a linked list, with each entry being an array 'vals' of 'num_vals' ints */
typedef struct SensorRow {
  int *vals;			/* array of 'num_vals' ints */
  int num_vals;
  struct SensorRow *next;
} sensor_row;

void prepopulate_sensor_data(char *filename); /* populates linked list `latest_data` */
sensor_row *get_next_sensor_data(); /* return NULL if no next row of data */
int sensor_fusion(sensor_row *row);

#endif
