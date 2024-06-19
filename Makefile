.PHONY: test fmt

test: fmt
	python -m doctest duo.py

fmt:
	black duo.py
	isort duo.py

