web: gunicorn main:app -k uvicorn.workers.UvicornWorker -w 1 -b 0.0.0.0:$PORT --max-requests 1000 --max-requests-jitter 50 --timeout 120 --access-logfile - --error-logfile -
