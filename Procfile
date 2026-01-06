# API Web Server (Scales with user traffic)
web: gunicorn main:app -k uvicorn.workers.UvicornWorker -w 4 -b 0.0.0.0:$PORT --max-requests 1000 --max-requests-jitter 50 --timeout 120 --access-logfile - --error-logfile -

# Payment Worker (Scales with transaction volume - Consumer Groups prevent duplicates)
worker: python worker.py
