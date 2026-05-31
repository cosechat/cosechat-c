.DEFAULT_GOAL := help
BUILD_DIR     := build

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

.PHONY: configure
configure: ## Configure cmake build (run once or after CMakeLists changes)
	cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=RelWithDebInfo

.PHONY: build
build: ## Build library, examples, and tests
	cmake --build $(BUILD_DIR) --parallel

.PHONY: test
test: build ## Build and run tests
	ctest --test-dir $(BUILD_DIR) -R cosechat --output-on-failure

.PHONY: format
format: ## Format all C source and header files
	find . -name "*.c" -o -name "*.h" | grep -v build | xargs clang-format -i

.PHONY: clean
clean: ## Remove build directory
	rm -rf $(BUILD_DIR)
