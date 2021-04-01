CC := gcc
FLAGS := -Wall -Werror -Iinclude
TARGET := vm_inspector
CFILE := vm_inspector.c

all: $(OFILE)
	$(CC) $(FLAGS) -o $(TARGET) $(CFILE)

clean:
	rm -f $(TARGET)

.PHONY: clean
