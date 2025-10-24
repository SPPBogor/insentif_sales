FROM python:3.11-slim

# Pakai ENV per-baris (tanpa backslash) agar aman di Windows/CRLF
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DEFAULT_TIMEOUT=100
ENV PORT=8080

WORKDIR /app

# Paket OS umum supaya pip build lancar
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential gcc libffi-dev libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Install deps Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir gunicorn

# Copy source
COPY . .

# Jalankan app Flask (ganti app:app kalau nama file/variabel berbeda)
CMD exec gunicorn -b :$PORT -w 2 app:app
