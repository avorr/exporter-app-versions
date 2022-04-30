#!/usr/bin/python3

import os
import json
import time
import datetime
from flask import Flask
from threading import Thread

from app_versions import get_app_versions, json_read
from env import portal_info

app = Flask(__name__)

json_path: str = '/opt/app-versions.json'
#json_path: str = 'app-versions.json'
host: str = '0.0.0.0'
#host: str = 'localhost'


def write_to_json():
    """
    Func to write info to json
    :return:
    """
    while True:
        try:
            server_output = get_app_versions(next(iter(portal_info)))
#            print({'info': server_output, 'update_time': str(datetime.datetime.now())})
            with open(json_path, 'w') as json_file:
                json.dump(
                    {
                        'info': server_output, 'update_time': str(datetime.datetime.now())
                    }, json_file
                )
                print('###' * 30, 'UPDATE JSON', '###' * 30)
            time.sleep(3600 * 3.5)
        except NameError as error:
            print(error)


def run_web_server():
    """
    Func to run flask web server
    :return: None
    """
    app.run(host=host, port=5002)


@app.route("/%sversions" % next(iter(portal_info)), methods=['GET'])
def summary() -> dict:
    with open(json_path) as json_file:
        while os.path.getsize(json_path) != 0:
            return json.load(json_file)


if __name__ == "__main__":
    Thread(target=run_web_server).start()
    # Thread(target=write_to_json).start()
