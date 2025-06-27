FROM python:3.13.5-slim-bookworm

WORKDIR /flaskapp
COPY . .
RUN apt-get update && apt-get install python3-venv python3-pip -y && python3 -m venv work_env
ENV PATH="/flaskapp/work_env/bin:$PATH"
RUN pip3 install -r ./requirements.txt
CMD ["python3.13", "app.py"]

HEALTHCHECK --interval=5s --timeout=10s --retries=3 CMD curl -sS 127.0.0.1 || exit 1