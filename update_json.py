#!/usr/local/bin/python3

import json
import datetime
from loguru import logger

from app_versions import get_app_versions
from env import portal_info

json_path: str = '/opt/app-versions.json'
host: str = '0.0.0.0'


def write_to_json() -> None:
    """
    Func to write info to json
    :return: None
    """
    try:
        server_output: list = get_app_versions(next(iter(portal_info)))
        with open(json_path, 'w') as json_file:
            json.dump(
                {
                    'info': server_output, 'update_time': str(datetime.datetime.now())
                }, json_file
            )

            # print({'info': server_output, 'update_time': str(datetime.datetime.now())}, json_file)
            logger.info('###' * 10, 'Update json %s' % json_path, '###' * 10)
    except NameError as error:
        logger.error(error)


if __name__ == "__main__":
    write_to_json()
