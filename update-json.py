#!/usr/bin/python3

import json
import time
import datetime
from threading import Thread

from app_versions import get_app_versions
from env import portal_info

json_path: str = '/opt/app-versions.json'
# json_path: str = 'app-versions.json'
host: str = '0.0.0.0'


# host: str = 'localhost'


def write_to_json() -> None:
    """
    Func to write info to json
    :return: None
    """
    # while True:
    try:
        # server_output = get_app_versions(next(iter(portal_info)))
        print('Cron work inside the container!!!!')

        #            print({'info': server_output, 'update_time': str(datetime.datetime.now())})

        # with open(json_path, 'w') as json_file:
        #     json.dump(
        #         {
        #             'info': server_output, 'update_time': str(datetime.datetime.now())
        #         }, json_file
        #     )
        #     print('###' * 30, 'UPDATE JSON', '###' * 30)

        # time.sleep(3600 * 3.5)
    except NameError as error:
        print(error)


if __name__ == "__main__":
    Thread(target=write_to_json).start()
