#!/usr/bin/python3

import time
import json
import socket
import paramiko
import requests
from requests.auth import HTTPDigestAuth

from env import portal_info
from env import ssh_login, ssh_pass


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

    app_tags: dict = {
        tag["tag_name"]: tag["id"] for tag in filter(
            lambda x: x["tag_name"] in ("wildfly", "postgres", "iam", "kafka"), app_tags
        )
    }


    cloud_domains: dict = portal_api("domains")

    
    cloud_domains: dict = {
        key["id"]: key["name"] for key in cloud_domains["stdout"]["domains"]
    }

    cloud_projects: dict = portal_api("projects")

    def check_port(checked_host: str) -> bool:
        """
        function to check server's port availability
        :param checked_host:
        :return: bool
        """
        if not checked_host:
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            return s.connect_ex((checked_host, 9990)) == 0

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

        if check_port(host):
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
            print(f"Failed to connect to host '{vm_ip}' with error: {error}")
            return {
                "ERROR": f"Failed to connect to host '{vm_ip}' with error: {error}"
            }
        except paramiko.ssh_exception.AuthenticationException as error:
            print(str(error), vm_ip)
            return {
                "ERROR": f"Failed to connect to host '{vm_ip}' with error: {error}"
            }
        except paramiko.ssh_exception.SSHException as error:
            print(str(error), vm_ip)
            return {
                "ERROR": f"Failed to connect to host '{vm_ip}' with error: {error}"
            }
        except EOFError as error:
            print(str(error), vm_ip)
            return {
                "ERROR": f"Failed to connect to host '{vm_ip}' with error: {error}"
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

        project_modules_info: dict = {
            "project_id": cloud_project["id"],
            "project_name": cloud_project["name"],
            "domain_id": cloud_project["domain_id"],
            "domain_name": cloud_domains[cloud_project["domain_id"]],
            "group_id": cloud_project["group_id"],
            "group_name": cloud_project["group_name"],
            # "service_name": wildfly_vm["service_name"],
            "modules_version": list()
        }

        project_vms: dict = portal_api("servers?project_id=%s" % cloud_project["id"])["stdout"]

        if project_vms["servers"]:
            all_wildfly_vms, all_postgres_vms, all_nginx_vms, all_kafka_vms = list(), list(), list(), list()
            for server in project_vms["servers"]:
                if server["tag_ids"]:
                    if app_tags["wildfly"] in server["tag_ids"]:
                        all_wildfly_vms.append(server)
                    if app_tags["postgres"] in server["tag_ids"]:
                        all_postgres_vms.append(server)
                    if app_tags["iam"] in server["tag_ids"]:
                        all_nginx_vms.append(server)
                    if app_tags["kafka"] in server["tag_ids"]:
                        all_kafka_vms.append(server)

            for wildfly_vm in all_wildfly_vms:
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

            for postgres_vm in all_postgres_vms:
                if "etcd-" not in postgres_vm["service_name"]:

                    shell_command: str = \
                        "$(find /usr -user postgres -group postgres -path '*pgsql*/bin/psql*' -type f 2>/dev/null) --version"

                    pgsql_version: str = remote_execute(shell_command, postgres_vm["ip"], ssh_login, ssh_pass)

                    if isinstance(pgsql_version, dict):
                        pgsql_version: str = pgsql_version["ERROR"]

                    if not pgsql_version:
                        pgsql_version: str = \
                            f"ERROR: Psql binary not found on {postgres_vm['name']}, {postgres_vm['ip']}"
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

            for nginx_vm in all_nginx_vms:
                shell_command: str = \
                    "test -f /usr/local/openresty/nginx/sbin/nginx && /usr/local/openresty/nginx/sbin/nginx -v"
                nginx_version: str = remote_execute(shell_command, nginx_vm["ip"], ssh_login, ssh_pass)

                if not nginx_version:
                    nginx_version: str = f"ERROR: Nginx binary not found on {nginx_vm['name']}, {nginx_vm['ip']}"

                if isinstance(nginx_version, dict):
                    nginx_version: str = nginx_version["ERROR"]

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

            for kafka_vm in all_kafka_vms:
                shell_command: str = \
                    "basename $(find /opt -user kafka -group kafka -path '*kafka/libs/kafka_*.jar' -print -quit -type f 2>/dev/null)"
                # "basename $(find / -user kafka -group kafka -path '*kafka/libs*' -type d 2>/dev/null)/kafka_*[[:digit:]].jar"

                kafka_version: str = remote_execute(shell_command, kafka_vm["ip"], ssh_login, ssh_pass)

                if not kafka_version:
                    kafka_version: str = f"ERROR: Kafka binary not found on {kafka_vm['name']}, {kafka_vm['ip']}"

                if isinstance(kafka_version, dict):
                    kafka_version: str = kafka_version["ERROR"]

                project_modules_info["modules_version"].append(
                    {
                        "tag": "kafka",
                        "ip": kafka_vm["ip"],
                        "id": kafka_vm["id"],
                        "name": kafka_vm["name"],
                        "service_name": kafka_vm["service_name"],
                        "version": kafka_version.strip()[6:-4]
                    }
                )

    return info


if __name__ == "__main__":
    get_app_versions(next(iter(portal_info)))

    # ssh = paramiko.SSHClient()
    # ssh.connect(server, username=username, password=password)
    # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd_to_execute)


# def rsh(command: str, vm_ip: str, username: str, password: str, multitreading=False):
#     try:
#         # with paramiko.SSHClient() as ssh_client:
#         # print(command)
#         sshtransport = paramiko.Transport((vm_ip, 9022))
#         sshtransport.connect(username=username, password=password)
#         session = sshtransport.open_channel(kind="session")
#         output = list()
#         session.exec_command(str(command))
#         while True:
#             if session.recv_ready():
#                 output.append(session.recv(3000).decode("ascii"))
#             if session.recv_stderr_ready():
#                 output.append(session.recv_stderr(3000).decode("ascii"))
#             if session.exit_status_ready():
#                 break
#         if multitreading:
#             return [vm_ip, "".join(output)]
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
