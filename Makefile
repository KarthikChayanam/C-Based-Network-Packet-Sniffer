# ---------- Makefile ----------
CC      = gcc
CFLAGS  = -Wall -Wextra -std=c99
LDFLAGS = -lpcap

SRC := $(wildcard src/*.c)
BIN = build
LOG = log

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LDFLAGS)

run: $(BIN)
	sudo ./$(BIN) -i en0 --udp -n 50 -o $(LOG)/packets1.csv

clean:
	rm -f $(BIN)

.PHONY: all run clean
# --------------------------------
