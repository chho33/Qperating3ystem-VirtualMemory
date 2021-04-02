CC := gcc
FLAGS := -Wall -Werror -Iinclude
TARGET := vm_inspector
TARGET2 := demo 
CFILE := vm_inspector.c
CFILE2 := demo.c

all:
	$(CC) $(FLAGS) -o $(TARGET) $(CFILE)
	$(CC) $(FLAGS) -o $(TARGET2) $(CFILE2)

clean:
	rm -f $(TARGET)
	rm -f $(TARGET2)

.PHONY: clean
