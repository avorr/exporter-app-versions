#!/usr/bin/python3

import os

from creds import *

ssh_login: str = os.environ['SSH_LOGIN']
ssh_pass: str = os.environ['SSH_PASS']

env: dict = {url: os.environ[url] for url in os.environ if 'PORTAL_' in url or 'OS_METRICS_' in url}

portal_info: dict = \
    {url[11:]: {'url': env[url], 'token': env[url.replace('URL', 'TOKEN')], 'metrics': env[f'OS_METRICS_{url[11:]}']}
     for url in env if '_URL_' in url}
