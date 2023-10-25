# Weather demo

Basic application, in `weather.c` and `sensors.c` works as follows:

1. `weather.c/main()` calls
   `sensors.c/prepopulate_sensor_data(argv[1])`
   (uses file "data/data.txt" if no argument given)
2. `prepopulate_sensor_data` reads each row of argument data file,
   breaks the line into space- or tab-separated values, and creates a
   new (dynamically allocated) `sensor_row` struct (defined in
   `sensors.h`) `sr` with an array of int's in `sr->vals[]` indexed
   0..`sr->num_vals - 1`
   - there is a maximum number `NUM_SENSORS` of values read from each
     line of the file
   - there is a maximum length for a single line of `MAX_LINE_LEN`
   - there is no checking whether the `atoi` conversion to an integer
     succeeds
   - a line can contain less than `NUM_SENSORS` values, including 0
   - a linked list of `sensor_row` structs (linked via `next` field)
     is returned by `prepopulate_sensor_data`, with head of list
     pointed to by `latest_data`
3. `weather.c/main` calls `weather.c/process_sensor_data()`, which
   proceeds through each `sensor_row` starting with `latest_data`. 
4. for each `sensor_row` struct `row`, `process_sensor_data` calls
   `sensor.c/sensor_fusion(row)`, which simply averages sensor values
   (unsafely). Then `process_sensor_data` adds the fusion result to a
   running total, `sum`.
5. finally, `process_sensor_data` returns the average result, by
   dividing the running total `sum` by the number of rows, `i`.

## Error and first not-quite-right patch

The `sensors.c/sensor_fusion` function does not check for a row having
0 values before dividing by the number of values, and so is vulnerable
to a divide-by-0 error.

The first (not quite right) patch is in `weather.c/process_sensor_data` and does not call
`sensor_fusion` if the `row->num_vals` is 0.

## Patch error and second patch

The first patch does not account for the fact that `i`, the number of
rows processed, will be incremented even in the case of a row having
no values. Thus in the case that a data file has one or more empty
rows, the denominator (`i`) of the final average calculation will be
too large. 

The second patch decrements `i` in the case that a row has 0 values.


## Build and run

To build all 3 versions of the application, just type `make`. That
builds 3 targets:

  - orig: builds `build/weather-orig` executable
  - patch-1: builds `build/weather-patched-1` executable, which has
    first (not quite right) patch applied, and
  - patch-2: builds `build/weather-patched-2` executable, which has
    both first and second patches applied
	
To run, invoke one of the above executables with a data file
containing rows of integers. There are several sample data files in
the `data` folder. For example, to run the original unpatched program
on rows containing all '20's as data, 

```
./build/weather-orig data/data20s.txt
```

To run the original on a data file with all '20's and with one blank
line, 


```
./build/weather-orig data/data20s1blank.txt
```

and observe the crash due to division by 0.

To run the program with the first (not quite right) patch, on a data
file with all '20's and with one blank line,


```
./build/weather-patched-1 data/data20s1blank.txt
```

and observe that there is no crash, but the average reading is
incorrect.

Finally, to run the program with both patches, on a data file with all
'20's and with one blank line,


```
./build/weather-patched-1 data/data20s1blank.txt
```

and observe both no crash and the correct average.


<!--  LocalWords:  executables
 -->
