# Contributing to SentinelNet

Thanks for helping improve this defensive-security project.

## Local setup

```bash
git clone https://github.com/darshnoor30/SentinelNet.git
cd SentinelNet
python -m venv .venv
```

Activate the environment (`.venv\Scripts\activate` on Windows or
`source .venv/bin/activate` on macOS/Linux), then install the development tools:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

## Quality checks

Run the same commands used by continuous integration:

```bash
ruff check .
ruff format --check .
pytest --cov=analytics --cov=detection_engine --cov=packet_capture --cov-report=term-missing
```

## Pull requests

1. Create a focused branch from `main`.
2. Add or update tests for behavior changes.
3. Keep detection rules explainable and document false-positive tradeoffs.
4. Never commit real network telemetry, secrets, or personal data.
5. Describe the validation commands and results in the pull request.

Only test packet capture on networks you are authorized to monitor.
