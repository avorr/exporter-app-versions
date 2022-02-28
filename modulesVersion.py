#!/usr/bin/python3

import time
import json
import socket
import paramiko
import requests
from requests.auth import HTTPDigestAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from env import portal_info
from env import ssh_login, ssh_pass

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def jsonRead(json_object: dict):
    print(json.dumps(json_object, indent=4))


def writeToFile(object: str):
    separator: int = object.index('=')
    with open('%s.py' % object[:separator], 'w') as file:
        file.write('%s = %s' % (object[:separator], object[(separator + 1):]))


def getPprb3Versions(portal_name: str) -> list:
    def sbercloudApi(api_method: str) -> dict:
        """Func for work with Portal REST-API"""
        headers: dict = {
            'user-agent': 'CMDB',
            'Content-type': 'application/json',
            'Accept': 'text/plain',
            'authorization': 'Token %s' % portal_info[portal_name]['token']}
        response = requests.get('%s%s' % (portal_info[portal_name]['url'], api_method), headers=headers, verify=False)
        return dict(stdout=json.loads(response.content), status_code=response.status_code)

    # wildflyTag = max(filter(lambda x: x['tag_name'] == 'wildfly', sbercloudApi('dict/tags')['stdout']['tags']))
    pprb3_tags = sbercloudApi('dict/tags')['stdout']['tags']
    pprb3_tags = filter(lambda x: x['tag_name'] in ('wildfly', 'postgres', 'iam', 'kafkase'), pprb3_tags)
    pprb3_tags: dict = {tag['tag_name']: tag['id'] for tag in pprb3_tags}
    # pprb3_tags = {'postgres': '0c893657-aa08-4f4c-8e2b-da386a1f53cd', 'wildfly': 'fac9523e-a251-4847-b8ab-687655813559'}

    # from cloud_domains import cloud_domains
    cloud_domains = sbercloudApi('domains')
    cloud_domains = {key['id']: key['name'] for key in cloud_domains['stdout']['domains']}

    cloud_projects = sbercloudApi('projects')

    # writeToFile(f'{cloud_projects=}')
    # from cloud_projects import cloud_projects

    def checkPort(checked_host: str) -> bool:
        # while time.time()
        if not checked_host:
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            return s.connect_ex((checked_host, 9990)) == 0

    def getWfInfo(host: str) -> dict:
        headers: dict = {
            'Content-type': 'application/json'
        }
        payload: dict = {
            "operation": "read-attribute",
            "address": [{"deployment": "*"}],
            "name": "enabled", "json.pretty": 1
        }

        if checkPort(host):
            try:
                response = requests.get('http://%s:9990/management' % host, auth=HTTPDigestAuth('admin', 'admin'),
                                        headers=headers, data=json.dumps(payload), timeout=5)
            except requests.exceptions.RequestException as error:
                return {'ERROR': str(error)}
                # raise SystemExit(error)

            if response.status_code == 200:
                return json.loads(response.content)
            elif response.status_code == 401:
                response = requests.get('http://%s:9990/management' % host, auth=HTTPDigestAuth('fly', 'fly'),
                                        headers=headers, data=json.dumps(payload))
                if response.status_code == 200:
                    return json.loads(response.content)
                else:
                    return {'ERROR': 'WildFly is Unreacheble'}
            else:
                return {'ERROR': 'WildFly is Unreacheble'}
        else:
            return {'ERROR': 'The port 9990 is not available on the host ----> %s' % host}

    def remoteShellExecute(command: str, vm_ip: str, username: str, password: str, multiprocess=False) -> dict:
        try:
            with paramiko.SSHClient() as ssh_client:
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(hostname=vm_ip, username=username, password=password, port=9022, timeout=3.0)
                stdin, stdout, stderr = ssh_client.exec_command(command)
                time.sleep(0.5)
                data = stdout.read() + stderr.read()
                ssh_client.close()
            if multiprocess:
                return [vm_ip, data.decode('ascii')]
            else:
                return data.decode('ascii')

        except paramiko.ssh_exception.NoValidConnectionsError as error:
            print("Failed to connect to host '%s' with error: %s" % (vm_ip, error))
            return {
                "ERROR": "Failed to connect to host '%s' with error: %s" % (vm_ip, error)
            }
        except paramiko.ssh_exception.AuthenticationException as error:
            print(str(error), vm_ip)
            return {
                "ERROR": "Failed to connect to host '%s' with error: %s" % (vm_ip, error)
            }
        except paramiko.ssh_exception.SSHException as error:
            print(str(error), vm_ip)
            return {
                "ERROR": "Failed to connect to host '%s' with error: %s" % (vm_ip, error)
            }
        except EOFError as error:
            print(str(error), vm_ip)
            return {
                "ERROR": "Failed to connect to host '%s' with error: %s" % (vm_ip, error)
            }
        except (paramiko.SSHException, socket.error) as error:
            print(vm_ip, str(error))
            return {
                "ERROR": "Cinnection %s to %s" % (str(error), vm_ip)
            }
        except:
            print(vm_ip, 'error')
            return {
                "ERROR": "unknown connection error to %s" % vm_ip
            }

    # cloud_projects['stdout']['projects'] = tuple(filter(lambda x: x['name'] == 'gt-foms-prod-platform',
    #                                                     cloud_projects['stdout']['projects']))
    # list(filter(lambda x: x['id'] == 'e594bc83-938c-48c4-a208-038aedad01de', cloud_projects['stdout']['projects']))

    info = list()

    for cloud_project in cloud_projects['stdout']['projects']:
        print(cloud_project['name'], cloud_project['id'])

        project_modules_info: dict = {
            'project_id': cloud_project['id'],
            'project_name': cloud_project['name'],
            'domain_id': cloud_project['domain_id'],
            'domain_name': cloud_domains[cloud_project['domain_id']],
            'group_id': cloud_project['group_id'],
            'group_name': cloud_project['group_name'],
            # 'service_name': wildfly_vm['service_name'],
            'modules_version': list()
        }
        project_vms: dict = sbercloudApi(f"servers?project_id={cloud_project['id']}")['stdout']
        # writeToFile(f'{project_vms=}')
        # from project_vms import project_vms
        if project_vms['servers']:
            all_wildfly_vms, all_postgres_vms, all_nginx_vms, all_kafka_vms = list(), list(), list(), list()
            for server in project_vms['servers']:
                if server['tag_ids']:
                    if pprb3_tags['wildfly'] in server['tag_ids']:
                        all_wildfly_vms.append(server)
                    if pprb3_tags['postgres'] in server['tag_ids']:
                        all_postgres_vms.append(server)
                    if pprb3_tags['iam'] in server['tag_ids']:
                        all_nginx_vms.append(server)
                    if pprb3_tags['kafkase'] in server['tag_ids']:
                        all_kafka_vms.append(server)

            # if all_wildfly_vms:
            # wfInfo = list()
            for wildfly_vm in all_wildfly_vms:
                wf_info_tmp: dict = getWfInfo(wildfly_vm['ip'])
                # print(wf_info_tmp)
                if next(iter(wf_info_tmp)) != 'ERROR':
                    wf_info_tmp: dict = {
                        'name': wf_info_tmp['name'],
                        'product-version': wf_info_tmp['product-version'],
                        'release-version': wf_info_tmp['release-version'],
                        'deployment': wf_info_tmp['deployment'],
                        'deployment-overlay': wf_info_tmp['deployment-overlay']
                    }
                project_modules_info['modules_version'].append({
                    'tag': 'wildfly',
                    'ip': wildfly_vm['ip'],
                    'name': wildfly_vm['name'],
                    'service_name': wildfly_vm['service_name'],
                    'wf_info': wf_info_tmp
                })
            # info.append(dict(project_id=cloud_project['id'], project_name=cloud_project['name'],
            #                  pprb3_services=project_modules_info))
            info.append(project_modules_info)

            for postgres_vm in all_postgres_vms:
                # print('PGSE', postgres_vm)
                # shell_command = "$(whereis -b psql | awk {'print $2'}) --version"
                # shell_command = "$(whereis -b psql | awk {'print $2'}) --version | " \
                #                "awk '{for (i=2; i<NF; i++) printf $i " "; print $NF}'"

                # shell_command: str = "printf $($(whereis -b psql | awk {'print $2'}) --version | " \
                #                     "awk '{for (i=2; i<NF; i++) printf $i " "; print $NF}')"

                # shell_command: str = "$(whereis -b psql | awk {'print $2'}) --version | " \
                #                     "awk '{for (i=2; i<NF; i++) printf $i " "; print $NF}' |tr '\n' ' '"

                # shell_command: str = "$(whereis -b psql | awk {'print $2'}) --version | awk '{$1=""; print $0}'"

                shell_command: str = """$(whereis -b psql | awk {'print $2'}) --version | awk '{$1=""; print $0}'"""
                pgsqlse_version: str = remoteShellExecute(shell_command, postgres_vm['ip'], ssh_login, ssh_pass)
                # print(pgsqlse_version)

                if isinstance(pgsqlse_version, dict):
                    # print(nginx_version, '*******8')
                    pgsqlse_version: str = pgsqlse_version['ERROR']
                if not pgsqlse_version:
                    pgsqlse_version: str = f"ERROR: Psql binary not found on {postgres_vm['name']}, {postgres_vm['ip']}"
                project_modules_info['modules_version'].append({
                    'tag': 'postgres',
                    'ip': postgres_vm['ip'],
                    'name': postgres_vm['name'],
                    'service_name': postgres_vm['service_name'],
                    'pgsqlse_version': pgsqlse_version.strip()
                })

            for nginx_vm in all_nginx_vms:
                shell_command: str = \
                    "test -f /usr/local/openresty/nginx/sbin/nginx && /usr/local/openresty/nginx/sbin/nginx -v"
                nginx_version: str = remoteShellExecute(shell_command, nginx_vm['ip'], ssh_login, ssh_pass)
                # print(nginx_version)

                if not nginx_version:
                    nginx_version: str = f"ERROR: Nginx binary not found on {nginx_vm['name']}, {nginx_vm['ip']}"

                if isinstance(nginx_version, dict):
                    nginx_version: str = nginx_version['ERROR']

                project_modules_info['modules_version'].append({
                    'tag': 'iam',
                    'ip': nginx_vm['ip'],
                    'name': nginx_vm['name'],
                    'service_name': nginx_vm['service_name'],
                    'nginx_version': nginx_version.strip()
                })

            for kafka_vm in all_kafka_vms:
                shell_command: str = \
                    "basename $(find / -user kafka -group kafka -path '*kafka/libs*' -type d 2>/dev/null)/kafka_*[[:digit:]].jar"

                kafka_version: str = remoteShellExecute(shell_command, kafka_vm['ip'], ssh_login, ssh_pass)

                if not kafka_version:
                    kafka_version: str = f"ERROR: Kafka binary not found on {kafka_vm['name']}, {kafka_vm['ip']}"

                if isinstance(kafka_version, dict):
                    kafka_version: str = kafka_version['ERROR']

                project_modules_info['modules_version'].append({
                    'tag': 'kafka',
                    'ip': kafka_vm['ip'],
                    'name': kafka_vm['name'],
                    'service_name': kafka_vm['service_name'],
                    'kafka_version': kafka_version.strip()[6:-4]
                })

    # writeToFile(f'{info=}')
    # jsonRead(info)
    return info


if __name__ == '__main__':
    getPprb3Versions(next(iter(portal_info)))

# def rsh(command: str, vm_ip: str, username: str, password: str, multitreading=False):
#     try:
#         # with paramiko.SSHClient() as ssh_client:
#         # print(command)
#         sshtransport = paramiko.Transport((vm_ip, 9022))
#         sshtransport.connect(username=username, password=password)
#         session = sshtransport.open_channel(kind='session')
#         output = list()
#         session.exec_command(str(command))
#         while True:
#             if session.recv_ready():
#                 output.append(session.recv(3000).decode('ascii'))
#             if session.recv_stderr_ready():
#                 output.append(session.recv_stderr(3000).decode('ascii'))
#             if session.exit_status_ready():
#                 break
#         if multitreading:
#             return [vm_ip, ''.join(output)]
#         else:
#             return output
#     except paramiko.ssh_exception.AuthenticationException as e:
#         print(str(e))
#     except paramiko.ssh_exception.SSHException as e:
#         print(str(e))
#     except EOFError as e:
#         print(str(e))
#     session.close()
#     sshtransport.close()
