#!/usr/bin/python3

from creds_pd15 import *

# from creds_pd20 import *
# from creds_pd23 import *
# from creds_pd24 import *

# from dotenv import load_dotenv

# load_dotenv(dotenv_path="/root/.exporter_env")

ssh_login: str = os.getenv('SSH_LOGIN')
ssh_pass: str = os.getenv('SSH_PASS')
pm_login: str = os.getenv('PM_LOGIN')
pm_pass: str = os.getenv('PM_PASS')
pm_pass_enc: str = os.getenv('PM_PASS_ENC')

env: dict = {
    url: os.environ[url] for url in os.environ if 'PORTAL_' in url or 'OS_METRICS_' in url
}

portal_info: dict = \
    {
        url[11:]: {
            'url': env[url],
            'token': env[url.replace('URL', 'TOKEN')],
            'metrics': env['OS_METRICS_%s' % url[11:]]
        }
        for url in env if '_URL_' in url
    }
