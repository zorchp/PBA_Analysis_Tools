CC = g++
CFLAGS = -Wall -Wextra -std=c++14
LDFLAGS = -lcapstone -lbfd

SOURCES = loader/loader.cpp capstone_gadget_finder.cpp
OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = capstone_gadget_finder.out

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)

.PHONY: all clean