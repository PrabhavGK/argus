"""
api/index.py - Vercel Serverless Entrypoint for Argus FastAPI Application.
Imports and exposes the ASGI app instance for @vercel/python.
"""

import sys
import os

# Ensure the root directory is on the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# Vercel's Python runtime invokes the callable named 'app'
# No additional wrapper is needed for FastAPI ASGI applications.
