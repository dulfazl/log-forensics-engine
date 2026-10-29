"""Vercel entry point: the serverless dashboard (see dashboard/serverless.py)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.serverless import create_serverless_app  # noqa: E402

app = create_serverless_app()
