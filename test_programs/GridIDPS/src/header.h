#include <stdint.h>

#define ARD
#ifdef ARD
#include <Arduino.h>
#include<SD.h>
#include<SPI.h>
#include<Wire.h>
#include <Ethernet.h>
#include <Servo.h>
#include <LiquidCrystal.h>
#include <MIDI.h>
#include <ADC.h>
#include <Adafruit_NeoPixel.h>
#include <AccelStepper.h>
#include <Artnet.h>
#include <Audio.h>
#include <SerialFlash.h>
#include <Bounce.h>
#include <CapacitiveSensor.h>
#include <DmxSimple.h>
#include <TimeLib.h>
#include <EasyTransfer.h>
#include <EEPROM.h>
#include <Encoder.h>
#include <FlexiTimer2.h>
#include <FreqMeasure.h>
#include <Keypad.h>
#include <MFRC522.h>
#include <OneWire.h>
#include <NXPMotionSense.h>
#include <OSCBundle.h>
#include <Ping.h>
#include <PulsePosition.h>
#include <PWMServo.h>
#include <ResponsiveAnalogRead.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#endif

typedef struct FieldFilter{
    uint8_t t_bytes[2];
    uint8_t t_bits[2]; //Starting from 0
    uint8_t t_masks[2];
    uint8_t first_length;
    unsigned long value[2];
}FieldFilter;

typedef struct SFieldFilter : FieldFilter{
    uint8_t prevm;
}SFieldFilter;

typedef struct L2Rule{
   unsigned long ncc;
   unsigned long max_ncc;
   unsigned long cth;
   unsigned long threshold;
   unsigned long last_time;
   unsigned long interval;
   unsigned long num_moi;
   FieldFilter* moi;
   unsigned long num_context;
   SFieldFilter* context;
}L2Rule;

typedef struct RLink{
   L2Rule *rule;
   uint8_t relation;
   unsigned long num_indexes;
   uint8_t *indexes;
} RLink;

typedef struct Target{
   uint8_t num_np_l2rules;
   struct L2Rule **np_l2rules;
   unsigned long num_rlinks;
   struct RLink *rlinks;
   uint8_t last_byte;
} Target;

typedef struct RadixTreeNode{
   unsigned long value;
   unsigned long length;
   Target* target;
   RadixTreeNode* lchild;
   RadixTreeNode* rchild;
} RadixTreeNode;

struct Bitchunk{
 bool bitlevel;
 uint8_t bitnum;
};

extern uint8_t num_targets;
extern Target* targets[3];
extern bool attack_detected;
extern RadixTreeNode *node;
extern RadixTreeNode *root;
extern uint8_t nodepos;
extern bool SOF;


#define MIN(a,b) (a ^ ((b ^ a) & -(b < a)))
#define MAX(a,b) (a ^ ((a ^ b) & -(a < b)))

struct Bitchunk* get_bitchunk();
void load();
void trace_radix_tree(struct Bitchunk* bt_recv, uint8_t bitpos, uint8_t bit_endpos);
void reset_dbyte();
uint64_t extract_data(uint8_t* barray, FieldFilter *cpf);
// void process_rlinks(RLink *rindexes, unsigned long num_rules, uint8_t *barray, unsigned long test_num_param, FieldFilter *fake_test_ff, uint8_t msg_type);
void process_rules(Target **targets, uint8_t num_trg, uint8_t *barray);
void controller_setup();
void print(const char * format, ...);
void close_outfile();
