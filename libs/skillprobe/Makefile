.PHONY: help install test unit integration lint format type demo ui all

.DEFAULT_GOAL := help

TEST_FILE ?= tests/unit_tests/

install: ## Sync the dev environment
	uv sync --group test

test unit: ## Run unit tests
	uv run pytest $(TEST_FILE)

integration: ## Run integration tests against real deepagents backends
	uv run pytest tests/integration_tests/

lint: ## Lint and check formatting
	uv run ruff check src tests
	uv run ruff format src tests --diff

format: ## Auto-format and fix
	uv run ruff format src tests
	uv run ruff check --fix src tests

demo: ## Run the packed-skill detonation demo
	uv run python examples/packed_skill_demo.py

ui: ## Open the local review UI
	uv run skillprobe ui

all: lint test ## Lint then test

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
