FROM python:3.13.5-slim-bookworm

WORKDIR /flaskapp
COPY . .
RUN apt-get update && apt-get install python3-venv -y && python3 -m venv work_env
ENV PATH="/flaskapp/work_env/bin:$PATH"
RUN pip3 install -r ./requirements.txt
ENTRYPOINT ['python3']
CMD ['app.py']