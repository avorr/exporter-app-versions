#!/usr/local/bin/python3

import time
import json
import socket
import paramiko
import requests
from requests.auth import HTTPDigestAuth

from env import portal_info
from env import ssh_login, ssh_pass


# foo = {'hash': 'a4ebd3d70bafb8012e9c0fb2c8689c85164bbc57', 'release': 'R20.1.1', 'subsystem': 'SGW', 'buildVersion': 'D-04.001.00-24_release_20_1_1_sgw_rhel7.x86_64'}
# sgw_version = '\n'.join(('Release=%s' % foo['release'], 'Version=%s' % foo['buildVersion']))


def json_read(json_object: dict) -> None:
    print(json.dumps(json_object, indent=4))


def write_to_file(object: str) -> None:
    separator: int = object.index("=")
    with open("%s.py" % object[:separator], "w") as file:
        file.write(f"{object[:separator]} = {object[(separator + 1):]}")


def get_app_versions(portal_name: str) -> list:
    """
    main func to get info from servers
    :param portal_name:
    :return: list
    """

    def portal_api(api_method: str) -> dict:
        """
        Func for work with Portal REST-API
        :param api_method: ex: servers, projects, domains
        :return: list
        """
        headers: dict = {
            "user-agent": "CMDB",
            "Content-type": "application/json",
            "Accept": "text/plain",
            "authorization": "Token %s" % portal_info[portal_name]["token"]
        }
        response = requests.get("%s%s" % (portal_info[portal_name]["url"], api_method), headers=headers, verify=False)
        return dict(stdout=json.loads(response.content), status_code=response.status_code)

    app_tags: list = portal_api("dict/tags")["stdout"]["tags"]
    # from app_tags import app_tags

    app_tags: dict = {
        tag["tag_name"]: tag["id"] for tag in filter(
            lambda x: x["tag_name"] in ("wildfly", "postgres", "iam", "kafka", "ignite", "hadoop", "sgw", "iag"),
            app_tags
        )
    }

    cloud_domains: dict = portal_api("domains")
    # from cloud_domains import cloud_domains

    cloud_domains: dict = {
        key["id"]: key["name"] for key in cloud_domains["stdout"]["domains"]
    }

    cloud_projects: dict = portal_api("projects")
    # from cloud_projects import cloud_projects

    def vdc_filter(vdc_projects: list) -> list:
        filtered_info = list()
        for vdc in vdc_projects:
            if vdc['name'] in (
                    "gt-solution-uat-alt-platform",
                    "gt-mintrud-test-platform",
                    "gt-business-test-platform",
                    "gt-business-dev-platform",
                    "gt-bootcamp-test",
                    "gt-rosim-test-platform",
                    "gt-rosim-dev-platform",
                    "gt-minsport-test-platform",
                    "gt-minsport-dev-platform",
                    "gt-foms-test-platform",
                    "gt-foms-dev-platform"
            ):
                filtered_info.append(vdc)
        return filtered_info

    # cloud_projects['stdout']['projects'] = vdc_filter(cloud_projects['stdout']['projects'])

    def check_port(checked_host: str, port: int) -> bool:
        """
        function to check server's port availability
        :param checked_host:
        :return: bool
        """
        if not checked_host:
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            return s.connect_ex((checked_host, port)) == 0

    def get_wf_info(host: str) -> dict:
        """
        func to get info from wildfly via rest-api
        :param host:
        :return: dick
        """
        headers: dict = {
            "Content-type": "application/json"
        }

        payload: dict = {
            "operation": "read-attribute",
            "address": [{"deployment": "*"}],
            "name": "enabled", "json.pretty": 1
        }

        if check_port(host, 9990):
            try:
                response = requests.get("http://%s:9990/management" % host, auth=HTTPDigestAuth("admin", "admin"),
                                        headers=headers, data=json.dumps(payload), timeout=5)
            except requests.exceptions.RequestException as error:
                return {
                    "ERROR": str(error)
                }
                # raise SystemExit(error)

            if response.status_code == 200:
                return json.loads(response.content)
            elif response.status_code == 401:
                response = requests.get("http://%s:9990/management" % host, auth=HTTPDigestAuth("fly", "fly"),
                                        headers=headers, data=json.dumps(payload))
                if response.status_code == 200:
                    return json.loads(response.content)
                else:
                    return {
                        "ERROR": "WildFly is Unreachable"
                    }
            else:
                return {
                    "ERROR": "WildFly is Unreachable"
                }
        else:
            return {
                "ERROR": "The port 9990 is not available on the host ----> %s" % host
            }

    def remote_execute(command: str, vm_ip: str, username: str, password: str, multiprocess=False) -> list | str | dict:
        """
        func to remote command execute on vms
        :param command:
        :param vm_ip:
        :param username:
        :param password:
        :param multiprocess:
        :return: dict or list or str
        """
        try:
            with paramiko.SSHClient() as ssh_client:
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(hostname=vm_ip, username=username, password=password, port=9022, timeout=3.0)
                stdin, stdout, stderr = ssh_client.exec_command(command)
                time.sleep(0.5)
                data = stdout.read() + stderr.read()
                ssh_client.close()
            if multiprocess:
                return [vm_ip, data.decode("ascii")]
            # else:
            return data.decode("ascii")

        except paramiko.ssh_exception.NoValidConnectionsError as error:
            print(f"Failed connect to  '{vm_ip}' with error: {error}")
            return {
                "ERROR": f"Failed connect to '{vm_ip}' with error: {error}"
            }
        except paramiko.ssh_exception.AuthenticationException as error:
            print(str(error), vm_ip)
            return {
                "ERROR": f"Failed connect to '{vm_ip}' with error: {error}"
            }
        except paramiko.ssh_exception.SSHException as error:
            print(str(error), vm_ip)
            return {
                "ERROR": f"Failed connect to '{vm_ip}' with error: {error}"
            }
        except EOFError as error:
            print(str(error), vm_ip)
            return {
                "ERROR": f"Failed connect to '{vm_ip}' with error: {error}"
            }
        except (paramiko.SSHException, socket.error) as error:
            print(vm_ip, str(error))
            return {
                "ERROR": f"Connection {str(error)} to {vm_ip}"
            }
        except:
            print(vm_ip, "error")
            return {
                "ERROR": "unknown connection error to %s" % vm_ip
            }

    info = list()

    for cloud_project in cloud_projects["stdout"]["projects"]:

        # if cloud_project["name"] not in ("gt-bootcamp-test", "gt-minsport-dev-platform"):
        #     continue

        print('#### VDC name %s' % cloud_project["name"])

        project_modules_info: dict = {
            "project_id": cloud_project["id"],
            "project_name": cloud_project["name"],
            "domain_id": cloud_project["domain_id"],
            "domain_name": cloud_domains[cloud_project["domain_id"]],
            "group_id": cloud_project["group_id"],
            "group_name": cloud_project["group_name"],
            "modules_version": list()
        }

        project_vms: dict = portal_api("servers?project_id=%s" % cloud_project["id"])["stdout"]

        if project_vms["servers"]:
            wildfly_vms, postgres_vms, nginx_vms, kafka_vms, ignite_vms, hadoop_vms, sgw_vms, iag_vms = \
                ([] for _ in range(8))

            for server in project_vms["servers"]:
                if server["tag_ids"]:
                    if app_tags["wildfly"] in server["tag_ids"]:
                        wildfly_vms.append(server)
                    if app_tags["postgres"] in server["tag_ids"]:
                        postgres_vms.append(server)
                    if app_tags["iam"] in server["tag_ids"]:
                        nginx_vms.append(server)
                    if app_tags["kafka"] in server["tag_ids"]:
                        kafka_vms.append(server)
                    if app_tags["ignite"] in server["tag_ids"]:
                        ignite_vms.append(server)
                    if app_tags["hadoop"] in server["tag_ids"]:
                        hadoop_vms.append(server)
                    if app_tags["sgw"] in server["tag_ids"]:
                        sgw_vms.append(server)
                    if app_tags["iag"] in server["tag_ids"]:
                        iag_vms.append(server)

            for wildfly_vm in wildfly_vms:
                wf_info_tmp: dict = get_wf_info(wildfly_vm["ip"])
                if next(iter(wf_info_tmp)) != "ERROR":
                    wf_info_tmp: dict = {
                        "name": wf_info_tmp["name"],
                        "product-version": wf_info_tmp["product-version"],
                        "release-version": wf_info_tmp["release-version"],
                        "deployment": wf_info_tmp["deployment"],
                        "deployment-overlay": wf_info_tmp["deployment-overlay"]
                    }
                project_modules_info["modules_version"].append(
                    {
                        "tag": "wildfly",
                        "ip": wildfly_vm["ip"],
                        "id": wildfly_vm["id"],
                        "name": wildfly_vm["name"],
                        "service_name": wildfly_vm["service_name"],
                        "version": wf_info_tmp
                    }
                )

            info.append(project_modules_info)

            for postgres_vm in postgres_vms:
                if "etcd-" not in postgres_vm["service_name"]:

                    # 181
                    # shell_command: str = "sudo $(sudo find /usr -user postgres -group postgres \
                    #                      -path '*pgsql*/bin/psql*' -type f 2>/dev/null) --version | grep ^psql"

                    # shell_command = "sudo su -c 'psql --version 2>/dev/null' -s /bin/bash postgres | head -n 1"
                    # shell_command = "sudo su postgres -c 'source ~/.bash_profile; psql --version 2>/dev/null'"

                    # 181
                    shell_command = "sudo su - postgres -c 'psql --version 2>/dev/null' | grep ^psql"

                    pgsql_version: str = remote_execute(shell_command, postgres_vm["ip"], ssh_login, ssh_pass)

                    if isinstance(pgsql_version, dict):
                        pgsql_version: str = pgsql_version["ERROR"]

                    if not pgsql_version:
                        pgsql_version: str = \
                            f"ERROR: Psql binary not found on {postgres_vm['name']}, {postgres_vm['ip']}"

                    print(pgsql_version)
                    print(postgres_vm['ip'])
                    print('###' * 10)

                    project_modules_info["modules_version"].append(
                        {
                            "tag": "postgres",
                            "ip": postgres_vm["ip"],
                            "id": postgres_vm["id"],
                            "name": postgres_vm["name"],
                            "service_name": postgres_vm["service_name"],
                            "version": pgsql_version.strip()
                        }
                    )

            for nginx_vm in nginx_vms:
                shell_command: str = \
                    "test -f /usr/local/openresty/nginx/sbin/nginx && /usr/local/openresty/nginx/sbin/nginx -v"
                nginx_version: str = remote_execute(shell_command, nginx_vm["ip"], ssh_login, ssh_pass)

                if not nginx_version:
                    nginx_version: str = f"ERROR: Nginx binary not found on {nginx_vm['name']}, {nginx_vm['ip']}"

                if isinstance(nginx_version, dict):
                    nginx_version: str = nginx_version["ERROR"]

                print(nginx_version)
                print(nginx_vm['ip'])
                print('###' * 10)

                project_modules_info["modules_version"].append(
                    {
                        "tag": "iam",
                        "ip": nginx_vm["ip"],
                        "id": nginx_vm["id"],
                        "name": nginx_vm["name"],
                        "service_name": nginx_vm["service_name"],
                        "version": nginx_version.strip()
                    }
                )

            for kafka_vm in kafka_vms:
                shell_command: str = \
                    "KAFKA_API=$(find /opt/Apache /KAFKA/kafkaabyss/ -name 'kafka-broker-api-versions.sh'\
                     -type f 2>/dev/null | head -n 1);if [ -f $KAFKA_API ];\
                     then $KAFKA_API --version; else echo Kafka not found; fi"

                kafka_version: str = remote_execute(shell_command, kafka_vm["ip"], ssh_login, ssh_pass)

                if not kafka_version:
                    kafka_version: str = f"ERROR: Kafka binary not found on {kafka_vm['name']}, {kafka_vm['ip']}"

                if isinstance(kafka_version, dict):
                    kafka_version: str = kafka_version["ERROR"]

                print(kafka_version)
                print(kafka_vm['ip'])
                print('###' * 10)

                project_modules_info["modules_version"].append(
                    {
                        "tag": "kafka",
                        "ip": kafka_vm["ip"],
                        "id": kafka_vm["id"],
                        "name": kafka_vm["name"],
                        "service_name": kafka_vm["service_name"],
                        "version": kafka_version.strip()
                    }
                )

            for ignite_vm in ignite_vms:
                shell_command: str = "IGNITE_API=/opt/ignite/server/bin/control.sh; if sudo test -f $IGNITE_API;\
                then sudo $IGNITE_API --system-view nodes --illegal-access=warn 2>/dev/null | head -n 1;\
                else echo Ignite not found; fi"

                ignite_version: str = remote_execute(shell_command, ignite_vm["ip"], ssh_login, ssh_pass)

                if not ignite_version:
                    ignite_version: str = f"ERROR: Ignite not found on {ignite_vm['name']}, {ignite_vm['ip']}"

                if isinstance(ignite_version, dict):
                    ignite_version: str = ignite_version["ERROR"]

                print(ignite_version)
                print(ignite_vm['ip'])
                print('###' * 10)

                project_modules_info["modules_version"].append(
                    {
                        "tag": "ignite",
                        "ip": ignite_vm["ip"],
                        "id": ignite_vm["id"],
                        "name": ignite_vm["name"],
                        "service_name": ignite_vm["service_name"],
                        "version": ignite_version.strip()
                    }
                )

            for hadoop_vm in hadoop_vms:
                shell_command: str = "hadoop version | head -n1"
                hadoop_version: str = remote_execute(shell_command, hadoop_vm["ip"], ssh_login, ssh_pass)

                if not hadoop_version:
                    hadoop_version: str = f"ERROR: Hadoop not found on {hadoop_vm['name']}, {hadoop_vm['ip']}"

                if isinstance(hadoop_version, dict):
                    hadoop_version: str = hadoop_version["ERROR"]

                print(hadoop_version)
                print(hadoop_vm['ip'])
                print('###' * 10)

                project_modules_info["modules_version"].append(
                    {
                        "tag": "hadoop",
                        "ip": hadoop_vm["ip"],
                        "id": hadoop_vm["id"],
                        "name": hadoop_vm["name"],
                        "service_name": hadoop_vm["service_name"],
                        "version": hadoop_version.rstrip()
                    }
                )

            for sgw_vm in sgw_vms:
                if check_port(sgw_vm["ip"], 9080):
                    response = requests.get("http://%s:9080/environment/product" % sgw_vm["ip"])

                    if response.status_code == 200:
                        sgw_version: str = json.loads(response.content)["buildVersion"]
                    else:
                        sgw_version: str = "SGW version not found, Response status code = %s" % response.status_code

                else:
                    sgw_version: str = "SGW is unreachable on port 9080"

                print(sgw_version)
                print(sgw_vm['ip'])
                print('###' * 10)

                project_modules_info["modules_version"].append(
                    {
                        "tag": "sgw",
                        "ip": sgw_vm["ip"],
                        "id": sgw_vm["id"],
                        "name": sgw_vm["name"],
                        "service_name": sgw_vm["service_name"],
                        "version": sgw_version
                    }
                )

            for iag_vm in iag_vms:
                if check_port(iag_vm["ip"], 9080):
                    response = requests.get("http://%s:9080/product" % iag_vm["ip"])
                    if response.status_code == 200:
                        sgw_version: str = json.loads(response.content)["buildVersion"]
                    else:
                        sgw_version: str = "IAG version not found, Response status code = %s" % response.status_code
                else:
                    sgw_version: str = "IAG is unreachable on port 9080"

                print(sgw_version)
                print(sgw_vm['ip'])
                print('###' * 10)

                project_modules_info["modules_version"].append(
                    {
                        "tag": "iag",
                        "ip": iag_vm["ip"],
                        "id": iag_vm["id"],
                        "name": iag_vm["name"],
                        "service_name": iag_vm["service_name"],
                        "version": sgw_version
                    }
                )

    write_to_file(f'{info=}')
    return info


if __name__ == "__main__":
    get_app_versions(next(iter(portal_info)))
