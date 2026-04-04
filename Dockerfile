FROM python:3.11
WORKDIR /app
COPY pyproject.toml ./
RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir -e ".[dev]"
COPY . .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]