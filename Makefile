.DEFAULT_GOAL := help

CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -I./include $(shell pkg-config --cflags wolfssl 2>/dev/null || echo "-I/usr/local/include") -I./vendor/wolfCOSE/include
LDFLAGS = $(shell pkg-config --libs wolfssl 2>/dev/null || echo "-L/usr/local/lib -lwolfssl") -lwolfcose -L./vendor/wolfCOSE
SRC     = src/cosechat.c
OBJ     = src/cosechat.o

.PHONY: help
help: ## Display this help message with descriptions of available targets
	@echo "Available commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: format
format: ## Format all C source and header files using JavaScript-style layout
	find . -name "*.c" -o -name "*.h" | xargs clang-format -i

$(OBJ): $(SRC) include/cosechat.h
	$(CC) $(CFLAGS) -c -o $@ $<

test/test_cosechat: test/test_cosechat.c $(OBJ)
	$(CC) $(CFLAGS) -DCC_POW_DIFFICULTY=1 -o $@ $^ $(LDFLAGS)

examples/keygen: examples/keygen.c $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

examples/announce: examples/announce.c $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

examples/chat: examples/chat.c $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: all
all: test/test_cosechat examples/keygen examples/announce examples/chat ## Build all targets

.PHONY: test
test: test/test_cosechat ## Build and run tests (POW_DIFFICULTY=1 for speed)
	./test/test_cosechat

.PHONY: clean
clean: ## Remove built files
	rm -f $(OBJ) test/test_cosechat examples/keygen examples/announce examples/chat

