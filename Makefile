# Log Forensics Engine - common tasks.  Override the interpreter with: make test PYTHON=python
PYTHON ?= python3

.PHONY: help install install-dev test lint demo eval dashboard dashboard-udp udp-demo bench charts

help:
	@echo "make install      install runtime + test dependencies"
	@echo "make test         run the test suite"
	@echo "make lint         ruff (needs requirements-dev.txt)"
	@echo "make demo         synthetic pipeline run + per-type evaluation table"
	@echo "make dashboard    live dashboard on http://127.0.0.1:8000 (synthetic source)"
	@echo "make dashboard-udp  dashboard fed by the UDP syslog listener on :5140"
	@echo "make udp-demo     send synthetic syslog to the UDP listener"
	@echo "make bench        memory benchmark of the full engine, 1K..1M lines"
	@echo "make charts       regenerate the report charts in docs/images/"

install:
	$(PYTHON) -m pip install -r requirements.txt

install-dev:
	$(PYTHON) -m pip install -r requirements-dev.txt

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .

demo:
	$(PYTHON) pipeline.py --n 1500 --baseline 300 --quiet
	$(PYTHON) evaluate.py

eval:
	$(PYTHON) evaluate.py --n 3000 --seeds 5

dashboard:
	$(PYTHON) -m dashboard.server --source synthetic

dashboard-udp:
	$(PYTHON) -m dashboard.server --source udp --port 5140

udp-demo:
	$(PYTHON) demo_syslog_sender.py --port 5140 --count 3000 --delay 0.02

bench:
	$(PYTHON) memory_benchmark.py

charts:
	$(PYTHON) generate_charts.py
