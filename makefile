CC = gcc
CFLAGS = -O2 -Wall -fopenmp
SRCS = gmult.c aes.c main.c
OBJS = $(SRCS:.c=.o)
TARGET = aes

ifeq ($(OS),Windows_NT)
    EXE = $(TARGET).exe
else
    EXE = $(TARGET)
endif

.PHONY: all clean run debug

all: $(EXE) run

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run:
	@echo Executando $(EXE)...
	@$(EXE) input.txt output.aes || ./$(TARGET) input.txt output.aes

debug:
	$(MAKE) CFLAGS="-g -O0 -Wall -fopenmp" all

clean:
	del /Q $(OBJS) $(EXE) 2>nul || rm -f $(OBJS) $(EXE)
