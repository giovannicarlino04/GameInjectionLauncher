# Compiler and compiler flags
CC := g++
CFLAGS := -Wall -std=c++11 -fpermissive

# Linker flags
LDFLAGS := -static-libgcc -static-libstdc++ -lkernel32

# Source file and output binary
INJECTOR_SRC := main.cpp
INJECTOR_BIN := GIL32.exe

# Default target
all: $(INJECTOR_BIN)

# Rule to build the executable
$(INJECTOR_BIN): $(INJECTOR_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Rule to clean up generated files
clean:
	rm -f $(INJECTOR_BIN)

# Specify the "clean" rule as a phony target
.PHONY: all clean
