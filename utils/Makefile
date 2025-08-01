# Define the compiler
CC = gcc

# Define compilation flags (e.g., disable optimization for precise timing tests)
CFLAGS = -Os 

# Define the target executable name
TARGET = tt


# Default target
all: $(TARGET)

# Build the target executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c


# Clean up compiled files
clean:
	rm -f $(TARGET)

# Run the program
run: $(TARGET)
	./$(TARGET)
