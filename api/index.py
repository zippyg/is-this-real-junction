"""Vercel entry point for free recordings and explicitly enabled live checks."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from real_app import app
