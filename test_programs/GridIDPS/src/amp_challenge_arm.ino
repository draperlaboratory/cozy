/* AMP Challenge ARM Final
 *  Buffer Overflow Challenge for AMP Hackathon on ARM v7
 *  Code contains an unchecked buffer that accept uer inputs from serial as commands
 *  Aim: Fix the buffer overflow and any emergent behaviors the fix might cause
*/

//includes
#include <Arduino.h>
#include <FlexCAN_T4.h>
#include "header.h"

//defines
#define BUFFER_SIZE 18

//globals
FlexCAN_T4<CAN1, RX_SIZE_256, TX_SIZE_16> can1;
FlexCAN_T4<CAN2, RX_SIZE_256, TX_SIZE_16> can2;
CAN_message_t msg;
int led = 13;
uint8_t prog_state = 0;
struct Bitchunk* bt_recv;
uint8_t bitpos;
int8_t bit_endpos;
uint8_t data_byte_array[8];
uint8_t byte_start_pos = 39;
uint8_t byte_pos = 0;
bool rep = false;
bool killed = false;
unsigned long ml;
uint8_t chunk_masks_l[2][5] = {{0,0,0,0,0},{1,3,7,15,31}};
uint8_t max_last_byte = 0;
long overlap_l;
int bufferPosition = 0;
char inputBuffer[BUFFER_SIZE];

void setup(void) {
  pinMode(led, OUTPUT);
  digitalWrite(led, HIGH);
  Serial.begin(115200);
  while (!Serial);
  delay(1000);
  controller_setup();
  load();
  Serial.println("Ready for commands:");
  Serial.println("1.Setup CAN1 <speed>");
  Serial.println("2.Setup CAN2 <speed>");
  Serial.println("3.Read CAN1");
  Serial.println("4.Read CAN2");  
  Serial.println("5.Write CAN1");
  Serial.println("6.Write CAN2");
}

void set_can1(int br){
  can1.begin();
  if (br == 250){
    can1.setBaudRate(250000);
  }
  else if (br == 500){
    can1.setBaudRate(500000);
  }
  else if (br == 1000){
    can1.setBaudRate(1000000);
  }
  else{
    return;
  }
  Serial.println("CAN1 Setup Successfully");
}


void set_can2(int br){
  can2.begin();
  if (br == 250){
    can2.setBaudRate(250000);
  }
  else if (br == 500){
    can2.setBaudRate(500000);
  }
  else if (br == 1000){
    can2.setBaudRate(1000000);
  }
  else{
    return;
  }
  Serial.println("CAN2 Setup Successfully");
}

void read_can1(){
    if ( can1.read(msg) ) {
    Serial.print("CAN1 "); 
    Serial.print("MB: "); Serial.print(msg.mb);
    Serial.print("  ID: 0x"); Serial.print(msg.id, HEX );
    Serial.print("  EXT: "); Serial.print(msg.flags.extended );
    Serial.print("  LEN: "); Serial.print(msg.len);
    Serial.print(" DATA: ");
    for ( uint8_t i = 0; i < 8; i++ ) {
      Serial.print(msg.buf[i]); Serial.print(" ");
    }
    Serial.print("  TS: "); Serial.println(msg.timestamp);
  }
}

void read_can2(){
    if ( can2.read(msg) ) {
    Serial.print("CAN2 "); 
    Serial.print("MB: "); Serial.print(msg.mb);
    Serial.print("  ID: 0x"); Serial.print(msg.id, HEX );
    Serial.print("  EXT: "); Serial.print(msg.flags.extended );
    Serial.print("  LEN: "); Serial.print(msg.len);
    Serial.print(" DATA: ");
    for ( uint8_t i = 0; i < 8; i++ ) {
      Serial.print(msg.buf[i]); Serial.print(" ");
    }
    Serial.print("  TS: "); Serial.println(msg.timestamp);
  }
}

void write_can1(){
  can1.write(msg);
}

void write_can2(){
  can2.write(msg);
}

void do_nothing(){
  int a = 0;
  int b = 0;
  int c = 0;
  int d = 0;
  int e = 0;
  int f = 0;
  int g = 0;
  int h = 0;
  int i = 0;
  int j = 0;
  int k = 0;
  int l = 0;
  int m = 0;
  int n = 0;
}

void process_command(const char* buf) {
  
  char newBuf[11];
  strncpy(newBuf, buf, 10);
  newBuf[10] = '\0';
  
  if (strcmp(newBuf, "Setup CAN1") == 0) {
    
    char* baudrate = buf + 11;
    int len = strlen(baudrate);
    baudrate[len] = '\0';

    if(strcmp(baudrate, "250000") == 0){
      set_can1(250);
    }
    else if(strcmp(baudrate, "500000") == 0){
      set_can1(500);
    }
    else if(strcmp(baudrate, "1000000") == 0){
      set_can1(1000);
   }
    else {
      Serial.println("Invalid Speed");
    }
  } 
  
  else if (strcmp(newBuf, "Setup CAN2") == 0) {
    char* baudrate = buf +11;
    int len = strlen(baudrate);
    baudrate[len] = '\0';
    if(strcmp(baudrate, "250000") == 0){
      set_can2(250);
    }
    else if(strcmp(baudrate, "500000") == 0){
      set_can2(500);
    }
    else if(strcmp(baudrate, "1000000") == 0){
      set_can2(1000);
    }
    else {
      Serial.println("Invalid Speed");
    }
  } 
  
  else if (strcmp(buf, "Read CAN1") == 0) {
    read_can1();
  }
  
  else if (strcmp(buf, "Read CAN2") == 0) {
    read_can2();
  }
  
  else if (strcmp(buf, "Write CAN1") == 0) {
    write_can1();
  }
  
  else if (strcmp(buf, "Write CAN2") == 0) {
    write_can2();
  }
  
  else {
    Serial.println("Unknown command. Try Again....");
  }
}

void read_bits(){
  if ((bt_recv = get_bitchunk()) != NULL){
        
        if (SOF){
            SOF = false;
            bit_endpos = -1;
            if (prog_state == 0){
                node = root;
                nodepos = 4;
                prog_state = 1;
            }
        }
        bitpos = bit_endpos + 1;
        bit_endpos = bitpos + bt_recv->bitnum -1;

        #ifdef debug_loop
        print("SOF: %d bitpos: %u bitendpos: %u ", SOF, bitpos, bit_endpos);
        print(" bitchunk: ");
        for (uint8_t tmp = 0; tmp < bt_recv->bitnum; tmp ++){
        print("%d", bt_recv->bitlevel);
        }
        print("\n");
        #endif


        if (prog_state == 1){ // TRACE
            trace_radix_tree(bt_recv, bitpos, bit_endpos);
            if (attack_detected == true){
                prog_state = 0;
            }
            else{
                if (node == NULL){
                    #ifdef debug_loop
                    print ("End of tracing!!\n");
                    #endif
                    max_last_byte = 0;
                    if (num_targets == 0){
                        prog_state = 0;
                    }
                    else{
                        for (uint8_t i = 0; i < num_targets; i ++){
                        max_last_byte = MAX(max_last_byte,targets[i]->last_byte);
                        if (targets[i]->num_rlinks > 0){
                            prog_state = 2;
                        }
                        else{
                            if (prog_state != 2){
                                prog_state = 0;
                            }
                        }
                    }
                    }
                    
                }
            }
        }

    if (prog_state == 2){ // PROCESS
        rep = true;
        while (rep){
            overlap_l = MIN(bit_endpos, byte_start_pos + 7) - MAX(bitpos,byte_start_pos) + 1;
            if (overlap_l > 0){
                data_byte_array[byte_pos] = data_byte_array[byte_pos] << overlap_l | chunk_masks_l[bt_recv->bitlevel][overlap_l -1];
            }
            if (bit_endpos > byte_start_pos + 7){
                byte_start_pos = byte_start_pos + 8;
                byte_pos ++;
            }
            else{
                rep = false;
            }
        }
        #ifdef debug_loop
        print ("Buffered bytes until %u: ", byte_pos);
        for (int i = 0; i < byte_pos + 1; i++){
            print("%02x ", data_byte_array[i]);
        }
        print ("\n");
        #endif
        if (byte_pos > max_last_byte){
            process_rules(targets, num_targets, data_byte_array);
            prog_state = 0;
            byte_pos = 0;
            byte_start_pos = 39;
            data_byte_array[byte_pos] = 0;
        }

    }

    #ifdef debug_loop
    print ("PROG STATE: %u\n", prog_state);
    #endif
  }
}


void printLR() {
  uintptr_t lr;
  asm volatile ("mov %0, lr\n" : "=r" (lr));
  Serial.print("LR: 0x");
  Serial.println(lr, HEX);
}

void printSP() {
    uintptr_t sp;
    asm volatile ("mov %0, sp" : "=r"(sp) );
    Serial.print("SP at start of function: ");
    Serial.println(sp, HEX);
}

void loop() {
//    printLR();
//    printSP();
//    Serial.print("Buffer address: ");
//    Serial.println((uintptr_t)inputBuffer, HEX);
    if (Serial.available()) {
    
    char inChar = Serial.read();
    if (inChar == '\n' || inChar == '\r') {
      if (bufferPosition > 0) {
        inputBuffer[bufferPosition] = '\0'; 
        Serial.print("Command received: ");
        Serial.println(inputBuffer);
        process_command(inputBuffer);
        bufferPosition = 0;
      }
    } 
    
    else{
//      if (bufferPosition > BUFFER_SIZE - 1 ) {
//          Serial.println("Buffer overflow detected. Resetting buffer.");
//          bufferPosition = 0;
//          memset(inputBuffer, 0, BUFFER_SIZE);
//          while(Serial.available() > 0) {
//            char t = Serial.read();
//          }
//          Serial.println("Try Again");
//          return;
//      }
      inputBuffer[bufferPosition++] = inChar;
    }
  }
//  read_bits();        
}
