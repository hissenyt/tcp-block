CXX=g++
CXXFLAGS=-Wall -Wextra -std=c++17
LDLIBS=-lpcap

TARGET=tcp-block
SRCS=main.cpp mac.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)
