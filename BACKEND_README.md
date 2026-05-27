# LinkWatcher Backend

This branch contains a deployment-ready Flask backend structure for the
LinkWatcher phishing URL detection website. It keeps the trained model runtime
from `app.py`, while the web backend concerns live in the `backend/` package.

## What This Backend Provides

- Flask application factory in `backend/app_factory.py`
- Environment-based settings in `backend/config.py`
- API routing in `backend/routes.py`
- JSON request validation in `backend/validation.py`
- Centralized JSON error responses in `backend/errors.py`
- Basic in-memory rate limiting in `backend/rate_limit.py`
- Security and CORS headers
- Request logging with request IDs
- WSGI entrypoint in `wsgi.py`
- Local backend runner in `run_backend.py`

## API

```text
GET  /
GET  /api/health
GET  /api/backend-info
POST /api/predict
```

Prediction request:

```json
{
  "url": "https://example.com",
  "inspect_page": true
}
```

Prediction response includes the model prediction, confidence, evidence
decision, XAI explanation, and batch statistics.

## Local Run

```powershell
cd "C:\Users\CSOS\Desktop\졸업작품_나희\phishing-url-detection"
C:\Users\CSOS\anaconda3\python.exe -m pip install -r requirements.txt
C:\Users\CSOS\anaconda3\python.exe run_backend.py
```

Open:

```text
http://127.0.0.1:8765
```

## WSGI Run

For a production-style local run on Windows:

```powershell
cd "C:\Users\CSOS\Desktop\졸업작품_나희\phishing-url-detection"
C:\Users\CSOS\anaconda3\python.exe -m waitress --host=0.0.0.0 --port=8765 wsgi:app
```

## Environment

Copy `.env.example` to `.env` when deploying or running through a process manager
that loads environment variables.

Important settings:

```text
PORT=8765
CORS_ORIGINS=*
MAX_URLS_PER_REQUEST=10
RATE_LIMIT_ENABLED=true
```

## Backend Claim

This branch can be described as:

> A deployment-ready Flask web backend for the LinkWatcher website, including
> structured API routing, environment configuration, validation, centralized
> error handling, logging, security headers, rate limiting, and a WSGI
> entrypoint. Actual external deployment is not included.
