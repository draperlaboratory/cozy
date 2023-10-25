LIBS = -lm
CC = gcc
CFLAGS = -g -Wall
HEADERS = $(wildcard *.h)
BUILD_DIR = build

.PHONY: clean default all orig patch-1 patch-2

# the first named target in a Makefile is what is built with just 'make'
default: all

all: orig patch-1 patch-2

orig: $(BUILD_DIR)/weather-orig

patch-1: $(BUILD_DIR)/weather-patched-1

patch-2: $(BUILD_DIR)/weather-patched-2

$(BUILD_DIR)/sensors.o: sensors.c $(HEADERS)
	@mkdir -p $(BUILD_DIR)
	@echo "building $@"
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/weather-orig: weather.c $(BUILD_DIR)/sensors.o $(HEADERS)
	@mkdir -p $(BUILD_DIR)
	@echo "building $@; compiling $<"
	$(CC) $(CFLAGS) -c $< -o $(BUILD_DIR)/$(@F).o
	$(CC) $(BUILD_DIR)/sensors.o $(BUILD_DIR)/$(@F).o -Wall $(LIBS) -o $@

$(BUILD_DIR)/weather-patched-1: weather.c $(BUILD_DIR)/sensors.o $(HEADERS)
	@mkdir -p $(BUILD_DIR)
	@echo "bulding $@; compiling $< with -DPATCH1"
	$(CC) $(CFLAGS) -DPATCH1 -c $< -o $(BUILD_DIR)/$(@F).o
	$(CC) $(BUILD_DIR)/sensors.o $(BUILD_DIR)/$(@F).o -Wall $(LIBS) -o $@

$(BUILD_DIR)/weather-patched-2: weather.c $(BUILD_DIR)/sensors.o $(HEADERS)
	@mkdir -p $(BUILD_DIR)
	@echo "bulding $@; compiling $< with -DPATCH1"
	$(CC) $(CFLAGS) -DPATCH1 -DPATCH2 -c $< -o $(BUILD_DIR)/$(@F).o
	$(CC) $(BUILD_DIR)/sensors.o $(BUILD_DIR)/$(@F).o -Wall $(LIBS) -o $@

clean:
	rm -rf $(BUILD_DIR)
