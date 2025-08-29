.PHONY: test fmt

test: fmt
	uv run python -m doctest duo.py

fmt:
	black duo.py
	isort duo.py

