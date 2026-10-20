# Stage 1: build the dashboard
FROM node:20.18-alpine AS dashboard
WORKDIR /dashboard
COPY dashboard/package.json ./
RUN npm install --no-audit --no-fund
COPY dashboard/ ./
RUN npm run build

# Stage 2: API + static dashboard
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY parser/ parser/
COPY detections/ detections/
COPY correlation/ correlation/
COPY incident_reports/ incident_reports/
COPY ai/ ai/
COPY api/ api/
COPY examples/ examples/
COPY --from=dashboard /dashboard/dist dashboard/dist
RUN useradd --create-home --uid 10001 identitytrace
USER identitytrace
EXPOSE 8000
CMD ["uvicorn", "api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
