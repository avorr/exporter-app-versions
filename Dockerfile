FROM python:3.10

ENV TZ=Europe/Moscow

ENV PYTHONWARNINGS="ignore:Unverified HTTPS request"

RUN set -ex && \
    apt-get update && \
    apt-get -y install cron && \
    apt -y remove python3.9 \
                  unzip \
                  zip \
                  bzip2 \
                  curl \
                  python3-minimal \
                  libpython3.9-minimal \
                  libpython3.9-stdlib \
                  libpython3.9  && \
    rm -rf /var/lib/apt/lists/*

#RUN set -ex && \
#    apt-get update && \
#    apt-get -y install curl \
#                       iputils-ping \
#                       telnet  \
#                       vim && \
#    rm -rf /var/lib/apt/lists/*

RUN set -ex && \
    pip3 install --no-cache --upgrade \
                              flask \
                              loguru \
                              requests \
                              paramiko \
                              python-dotenv

# Copy update-json file to the cron.d directory
COPY update-json-cron /etc/cron.d/update-json

# Give execution rights on the cron job
# Create the log file to be able to run tail
# Apply cron job
RUN chmod 0644 /etc/cron.d/update-json && \
    touch /var/log/cron.log && \
    crontab /etc/cron.d/update-json

COPY . /opt/

# Run the command on container startup
ENTRYPOINT ["/bin/bash", "/opt/main.sh"]