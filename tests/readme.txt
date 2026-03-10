running /tests from cratch

git clone https://github.com/nikl11/egi-notebooks-hub.git
cd egi-notebooks-hub
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
pip install pytest pytest-asyncio
pip install -e .
pytest -q tests/test_egiauthenticator.py
