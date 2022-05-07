#!/usr/bin/python3

import os
import json
from flask import Flask
from env import portal_info
from threading import Thread

from update_json import write_to_json

app = Flask(__name__)

json_path: str = '/opt/app-versions.json'
host: str = '0.0.0.0'


def run_web_server() -> None:
    """
    Func to run flask web server
    :return: None
    """
    app.run(host=host, port=5002)


@app.route("/versions-%s" % next(iter(portal_info)).lower(), methods=['GET'])
def summary() -> dict:
    with open(json_path) as json_file:
        while os.path.getsize(json_path) != 0:
            return json.load(json_file)


if __name__ in ("__main__", "exporter-apps-versions.versions-exporter"):
    Thread(target=write_to_json()).start()
    Thread(target=run_web_server()).start()
