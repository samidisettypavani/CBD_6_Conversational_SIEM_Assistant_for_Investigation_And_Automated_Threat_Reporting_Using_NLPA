# FastAPI Backend

## Run locally

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The frontend expects the backend at `http://127.0.0.1:8000` by default.

## Current scope

- `POST /chat`
- `GET /alerts`
- `GET /investigations`
- `GET /health`
- `POST /simulation/tick`

This scaffold still uses generated mock log events behind FastAPI so the frontend can migrate cleanly before PostgreSQL is added.
