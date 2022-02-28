FROM python:3

ENV TZ=Europe/Moscow

RUN pip3 install --no-cache --upgrade \
                              flask \
                              loguru \
                              requests \
                              paramiko

COPY . /opt/

CMD ["/usr/local/bin/python3", "/opt/versions-exporter.py"]
