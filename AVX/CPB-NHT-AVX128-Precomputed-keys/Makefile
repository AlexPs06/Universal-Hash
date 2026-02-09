# CC=g++
# CFLAGS= -march=native 
# LIB= -O3 
# SOURCES= CPB.cpp
# all: 
# 	$(CC) -o test $(SOURCES) $(LIB) $(CFLAGS) 
# clean: 
# 	rm *.o  

# CC=g++
# CFLAGS= -march=armv8-a+crypto
# LIB= -Os 
# SOURCES= CPB_V2.cpp
# SOURCES2= ParaHash-V3.cpp
# all: 
# 	$(CC) -o CPB $(SOURCES) $(SOURCES2)  $(LIB) $(CFLAGS) 
# clean: 
# 	rm *.o  


# Compiler
CXX := g++

# Target
TARGET := test

# Source files
SRCS := CPB.cpp NHT.cpp

# Header files (for dependency tracking)
HDRS := NHT.h

# Compiler flags
CXXFLAGS := -O3 -std=c++17 -march=native \
            -Wall -Wextra -Wno-unused-parameter

# Linker flags (empty but kept for clarity)
LDFLAGS :=

# Default rule
all: $(TARGET)

# Link
$(TARGET): $(SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

# Clean
clean:
	rm -f $(TARGET)

.PHONY: all clean
