FROM python:3.13.5-slim-bookworm

WORKDIR /flaskapp
COPY . .
# hadolint ignore=DL3008,DL3009,DL3015
RUN apt-get update && apt-get install python3-venv python3-pip curl -y && python3 -m venv work_env
ENV PATH="/flaskapp/work_env/bin:$PATH"
RUN pip3 install --no-cache-dir -r ./requirements.txt
EXPOSE 5000
CMD ["python3.13", "app.py"]

HEALTHCHECK --interval=10s --timeout=10s --retries=3 CMD curl -sS 127.0.0.1:5000 || exit 1