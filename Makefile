.PHONY: install dev test lint format scan scan-staged

install:
	python -m pip install -e .

dev:
	python -m pip install -e '.[dev]'

test:
	pytest

lint:
	ruff check src tests

format:
	ruff format src tests

scan:
	python -m leaklens scan .

scan-staged:
	python -m leaklens scan --staged
