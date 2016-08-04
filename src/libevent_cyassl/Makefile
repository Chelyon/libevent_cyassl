.PHONY: clean all

#TODO: get MODEL/SOFTWARE_VERSION at runtime
###############################################
PLATFORM ?= ARM
export PLATFORM
###############################################

COMMON_DIR := $(shell pwd)/common
CFLAGS := -I./include -I$(COMMON_DIR) -D$(PLATFORM) -Wall $(CFLAGS)

LDFLAGS += -lm -levent -lpthread -lcyassl

CLIST := $(shell find . -name "*.c")
TARGET = libevent_cyassl.so

all: $(CLIST)
	@echo -e "  Build\t$(TARGET)"
	$(CC) $(CFLAGS) -fPIC -shared -o $(TARGET) $^ $(LDFLAGS)
	@cp $(TARGET) ./lib/
clean:
	@echo -e "  Clean\t$(TARGET)"
	rm -rf $(OBJS) $(TARGET) ./lib
