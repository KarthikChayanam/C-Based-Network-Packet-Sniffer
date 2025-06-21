# ---------- Makefile ----------
CC      = gcc
CFLAGS  = -Wall -Wextra -std=c99
LDFLAGS = -lpcap

SRC := $(wildcard src/*.c src/decode/*.c)
BIN = build
LOG = log

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LDFLAGS)

run: $(BIN)
	sudo ./$(BIN) -i en0 --all -n 100 --pcap $(LOG)/dump.pcap

clean:
	rm -f $(BIN)

report:
	python3 src/scripts/report.py


.PHONY: all run clean
# --------------------------------
