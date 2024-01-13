CC := g++

INJECTOR_SRC := main.cpp

INJECTOR_BIN := GIL.exe

CFLAGS := -Wall -std=c++11 -fpermissive
LDFLAGS := -lkernel32

all: $(INJECTOR_BIN) $(DLL_BIN)

$(INJECTOR_BIN): $(INJECTOR_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(DLL_BIN): $(DLL_SRC)
	$(CC) $(CFLAGS) -shared -o $@ $<

clean:
	rm -f $(INJECTOR_BIN) $(DLL_BIN)

.PHONY: all clean
