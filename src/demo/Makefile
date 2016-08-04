CFLAGS += -I../libevent_cyassl/include
LDFLAGS += -levent -lm -lpthread -L../lib/ -levent_cyassl
TARGET?=hello_world

all:
	$(CC) $(CFLAGS) hello_world.c -o $(TARGET) $(LDFLAGS)
	cp $(TARGET) ./bin/
.PHONY:clean
clean:
	rm -rf *.o TARGET ./bin
