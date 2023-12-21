
## Overview

Target 5 for the NASA combined challenge problem is a GSFC-developed processing node that demonstrates a Ground Data System (GDS) performing processing that is typically necessary for uncrewed science missions. It integrates the open-source Telemetry & Commanding (T&C) system OpenC3 COSMOS (https://openc3.com/) with a custom science data processing and satellite encoding adapter implemented as Linux ELF applications running in a RHEL8 containerized x86_64 (amd64) environment.

Science Data Decoder Binary information:

gs_data_processor: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=901d15768fa5d08002d0e12bcab36a736aba9b75, not stripped

## Features

- Initialize communication channel with the Comm Relay Satellite with predefined settings.
- Construct CCSDS command packets for both the Comm Relay Satellite and Rover and commands.
- Parse CCSDS telemetry packets from both the Comm Relay Satellite and Rover.
- Convert temperature readings from Celsius to Fahenheit.
- Display direction of Rover movement.

## Identified Bug and Implications

The binary contains an error in the temperature conversion. 

Implications:

- Potential misinterpretation of the temperature data by the receiving system due to format inconsistencies.

## Possible Micro-Patch

### Temperature Formating

To address the formatting error, replace:

```c
int32_t rover_process(RoverMessage_t* msg){

    //convert Kelvin to Farhenheit.
    temp = ( (temp - 273) * 1.8 ) + 32;

}
```
With:

```c
int32_t rover_process(RoverMessage_t* msg){

    //convert Celsius to Farhenheit.
    temp = ( temp * 1.8 ) + 32;

}
```

These changes will ensure that the we have data in farhenheit.

### Output expectation

The packet viewer in Cosmos will display both the incomping data to and outgoing data from the science data app and can be used to determine the correctness of the temperature conversion performed in the app.  

Also there will be a telemetry screen in Cosmos that will display the converted value
