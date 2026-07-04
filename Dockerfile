FROM python:3.11-slim

# YARA needs some build tools / libs at runtime for yara-python wheels on some platforms
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 8501

# Default: launch the dashboard. Override with `docker run ... soc-toolkit enrich <ioc>`
ENTRYPOINT ["soc-toolkit"]
CMD ["dashboard", "--port", "8501"]
