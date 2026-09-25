FROM python:3.11-slim

# Semgrep-in bəzi qaydaları və build üçün əsas alətlər
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Render bu env dəyişənini avtomatik verir; lokal test üçün default dəyər
ENV PORT=8080
EXPOSE 8080

CMD ["python", "bot.py"]
