.PHONY: help install demo attack test lint report clean

help:
	@echo "make install   install Tobira and dev dependencies"
	@echo "make demo      bring the lab up and walk through it"
	@echo "make attack    run the 21 adversary scenarios, write reports/"
	@echo "make test      run the test suite"
	@echo "make lint      ruff check"
	@echo "make report    attack + print the generated report"
	@echo "make clean     remove generated files"

install:
	pip install -e ".[dev]"

demo:
	python -m tobira.cli demo

attack:
	python -m tobira.cli attack

test:
	pytest -q

lint:
	ruff check src tests

report: attack
	@echo
	@cat reports/control-verification.md

clean:
	rm -rf reports .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
