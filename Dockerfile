FROM python:3

ENV TZ=Europe/Moscow

#RUN apt update && apt install vim curl -y
RUN pip3 install --no-cache --upgrade \
                              flask \
                              loguru \
                              requests \
                              paramiko \
                              pyopenssl

COPY . /opt/

CMD ["/usr/local/bin/python3", "/opt/versions-exporter.py"]
