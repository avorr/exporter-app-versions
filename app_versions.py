#!/usr/local/bin/python3

import ssl
import time
import json
import socket
import requests
from loguru import logger
from requests.auth import HTTPDigestAuth, HTTPBasicAuth

import warnings
from cryptography.utils import CryptographyDeprecationWarning

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    import paramiko

from env import portal_info
from env import ssh_login, ssh_pass, pm_login, pm_pass, pm_pass_enc


def json_read(json_object: dict) -> None:
    print(json.dumps(json_object, indent=4, default=str))


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
        portal_response = requests.get(f'{portal_info[portal_name]["url"]}{api_method}', headers=headers, verify=False)
        return {
            "stdout": json.loads(portal_response.content),
            "status_code": portal_response.status_code
        }

    app_tags: list = portal_api("dict/tags")["stdout"]["tags"]
    logger.info("Get all portal tags")

    app_tags: dict = {
        tag["tag_name"]: tag["id"] for tag in filter(
            lambda x: x["tag_name"] in
                      ("wildfly", "postgres", "nginx", "kafka", "ignite",
                       "hadoop", "sgw", "iag", "etcd", "zookeeper", "victoria",
                       "keycloak", "elk", "jenkinsslave", "ipa", "ipareplica",
                       "eskkd", "sds", "nifi", "datalab", "ambari", "synapse_flink"), app_tags
        )
    }

    cloud_domains: dict = portal_api("domains")
    logger.info("Get all portal domains")

    cloud_domains: dict = {
        key["id"]: key["name"] for key in cloud_domains["stdout"]["domains"]
    }

    cloud_projects: dict = portal_api("projects")
    logger.info("Get all portal projects")

    def vdc_filter(vdc_projects: list) -> list:
        filtered_info = list()
        for vdc in vdc_projects:
            if vdc['name'] in (
                    ### PD24
                    # "gt-rosim-nt-platform",
                    ### PD23
                    # "gt-minsport-prod-customer",
                    # "gt-common-admins",
                    # "gt-minsport-nt-platform",

                    # "gt-minsport-prod-platform",

                    # "gt-minsport-uat-platform",

                    ### PD15
                    "gt-sberworks-uat",
                    # "gt-solution-uat-alt-platform",
                    # "gt-business-test-platform",
                    # "gt-solution-uat-platform",
                    # "gt-mintrud-test-platform",
                    # "gt-mintrud-dev-platform",
                    # "gt-business-test-platform",
                    # "gt-business-dev-platform",
                    # "gt-business-test-platform",

                    # "gt-bootcamp-test",
                    # "gt-common-admins",

                    # "gt-rosim-test-platform",
                    # "gt-rosim-dev-platform",
                    # "gt-minsport-test-platform",
                    # "gt-minsport-dev-platform",

                    # "gt-foms-test-platform",
                    # "gt-foms-dev-platform",

                    # "gt-foms-prod-platform"
            ):
                filtered_info.append(vdc)
        return filtered_info

    # cloud_projects["stdout"]["projects"] = vdc_filter(cloud_projects["stdout"]["projects"])

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

    def check_resolves(dns_name: str) -> bool:
        """
        function for checking resolving dns names
        :param dns_name:
        :return: bool
        """
        try:
            socket.gethostbyname(dns_name)
            return True
        except socket.error as Error:
            print(dns_name, Error)
            return False

    def check_ssl(host: str, port: int) -> bool:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    print(ssock.version())
                    return True
        except:
            return False

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
                logger.error(host, str(error))
                return {
                    "ERROR": str(error)
                }
                # raise SystemExit(error)

            if response.status_code == 200:
                return json.loads(response.content)
            elif response.status_code == 401:
                try:
                    response = requests.get("http://%s:9990/management" % host, auth=HTTPDigestAuth("fly", "fly"),
                                            headers=headers, data=json.dumps(payload))
                except requests.exceptions.RequestException as error:
                    logger.error(host, str(error))
                    return {
                        "ERROR": str(error)
                    }

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
            return data.decode("ascii")

        except paramiko.ssh_exception.NoValidConnectionsError as error:
            logger.error(f"Failed connect to  '{vm_ip}' with error: {error}")
            return {
                "ERROR": f"Failed connect to '{vm_ip}' with error: {error}"
            }
        except paramiko.ssh_exception.AuthenticationException as error:
            logger.error(vm_ip, str(error))
            return {
                "ERROR": f"Failed connect to '{vm_ip}' with error: {error}"
            }
        except paramiko.ssh_exception.SSHException as error:
            logger.error(vm_ip, str(error))
            return {
                "ERROR": f"Failed connect to '{vm_ip}' with error: {error}"
            }
        except EOFError as error:
            logger.error(vm_ip, str(error))
            return {
                "ERROR": f"Failed connect to '{vm_ip}' with error: {error}"
            }
        except (paramiko.SSHException, socket.error) as error:
            logger.error(vm_ip, str(error))
            return {
                "ERROR": f"Connection {str(error)} to {vm_ip}"
            }
        except Exception as error:
            logger.error(vm_ip, str(error))
            return {
                "ERROR": "unknown connection error to %s" % vm_ip
            }

    output_info = list()

    for cloud_project in cloud_projects["stdout"]["projects"]:

        project_modules_info: dict = {
            "project_id": cloud_project["id"],
            "project_name": cloud_project["name"],
            "domain_id": cloud_project["domain_id"],
            "domain_name": cloud_domains[cloud_project["domain_id"]],
            "group_id": cloud_project["group_id"],
            "group_name": cloud_project["group_name"],
            "desc": cloud_project["desc"] if "desc" in cloud_project else "",
            "modules_version": list()
        }

        project_vms: dict = portal_api("servers?project_id=%s" % cloud_project["id"])["stdout"]

        if project_vms["servers"]:
            wildfly_vms, postgres_vms, nginx_vms, kafka_vms, ignite_vms, hadoop_vms, sgw_vms, iag_vms, \
            etcd_vms, zookeeper_vms, victoria_vms, keycloak_vms, elk_vms, jenkins_vms, ipa_vms, eskkd_vms, \
            sds_vms, etl_vms, datalab_vms, ambari_vms, synapseflink_vms = ([] for _ in range(21))

            for server in project_vms["servers"]:
                if server["tag_ids"]:
                    if app_tags["wildfly"] in server["tag_ids"]:  ## +
                        wildfly_vms.append(server)
                    elif app_tags["postgres"] in server["tag_ids"]:
                        postgres_vms.append(server)
                    elif app_tags["nginx"] in server["tag_ids"]:
                        nginx_vms.append(server)
                    elif app_tags["kafka"] in server["tag_ids"]:
                        kafka_vms.append(server)
                    elif app_tags["ignite"] in server["tag_ids"]:
                        ignite_vms.append(server)
                    elif app_tags["hadoop"] in server["tag_ids"]:
                        hadoop_vms.append(server)
                    elif app_tags["sgw"] in server["tag_ids"]:  ## +
                        sgw_vms.append(server)
                    elif app_tags["iag"] in server["tag_ids"]:  ## +
                        iag_vms.append(server)
                    elif app_tags["etcd"] in server["tag_ids"]:
                        etcd_vms.append(server)
                    elif app_tags["zookeeper"] in server["tag_ids"]:
                        zookeeper_vms.append(server)
                    elif app_tags["victoria"] in server["tag_ids"]:
                        victoria_vms.append(server)
                    elif app_tags["keycloak"] in server["tag_ids"]:
                        keycloak_vms.append(server)
                    elif app_tags["elk"] in server["tag_ids"]:  ## +
                        elk_vms.append(server)
                    elif app_tags["jenkinsslave"] in server["tag_ids"]:
                        jenkins_vms.append(server)
                    elif app_tags["ipa"] in server["tag_ids"]:
                        ipa_vms.append(server)
                    elif app_tags["ipareplica"] in server["tag_ids"]:
                        ipa_vms.append(server)
                    elif app_tags["eskkd"] in server["tag_ids"]:
                        eskkd_vms.append(server)
                    elif app_tags["sds"] in server["tag_ids"]:
                        sds_vms.append(server)
                    elif app_tags["nifi"] in server["tag_ids"]:
                        etl_vms.append(server)
                    elif app_tags["datalab"] in server["tag_ids"]:
                        datalab_vms.append(server)
                    elif app_tags["ambari"] in server["tag_ids"]:
                        ambari_vms.append(server)
                    elif app_tags["synapse_flink"] in server["tag_ids"]:
                        synapseflink_vms.append(server)

            for wildfly_vm in wildfly_vms:  ## ++++
                wf_info_tmp: dict = get_wf_info(wildfly_vm["ip"])
                if next(iter(wf_info_tmp)) != "ERROR":
                    wf_info_tmp: dict = {
                        "name": wf_info_tmp["name"],
                        "product-version": wf_info_tmp["product-version"],
                        "release-version": wf_info_tmp["release-version"],
                        "deployment": wf_info_tmp["deployment"],
                        "deployment-overlay": wf_info_tmp["deployment-overlay"]
                    }
                if next(iter(wf_info_tmp)) == "ERROR":
                    wf_info_tmp = wf_info_tmp["ERROR"]

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

            output_info.append(project_modules_info)

            for postgres_vm in postgres_vms:
                if "etcd-" not in postgres_vm["service_name"]:

                    logger.info(f"Get postgres version from {postgres_vm['ip']}")

                    shell_command = "sudo su - postgres -c 'psql --version 2>/dev/null' | grep ^psql"

                    pgsql_version: str = remote_execute(shell_command, postgres_vm["ip"], ssh_login, ssh_pass)

                    if isinstance(pgsql_version, dict):
                        pgsql_version: str = pgsql_version["ERROR"]

                    if not pgsql_version:
                        pgsql_version: str = \
                            f"ERROR: Psql binary not found on {postgres_vm['name']}, {postgres_vm['ip']}"

                    logger.info(f"Postgres version = {pgsql_version.strip()}")

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
                logger.info(f"Get nginx version from {nginx_vm['ip']}")
                shell_command: str = """sudo pidof -s nginx > /dev/null && $(sudo readlink -f /proc/$(sudo pidof -s nginx)/exe) -v"""
                nginx_version: str = remote_execute(shell_command, nginx_vm["ip"], ssh_login, ssh_pass)

                if not nginx_version:
                    nginx_version: str = f"ERROR: Nginx binary not found on {nginx_vm['name']}, {nginx_vm['ip']}"

                if isinstance(nginx_version, dict):
                    nginx_version: str = nginx_version["ERROR"]

                logger.info(f"Nginx version = {nginx_version.strip()}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "nginx",
                        "ip": nginx_vm["ip"],
                        "id": nginx_vm["id"],
                        "name": nginx_vm["name"],
                        "service_name": nginx_vm["service_name"],
                        "version": nginx_version.strip()
                    }
                )

            for kafka_vm in kafka_vms:
                logger.info(f"Get kafka version from {kafka_vm['ip']}")
                shell_command: str = \
                    "KAFKA_API=$(find /opt/Apache /KAFKA/kafkaabyss/ /ditmsk/apps/kafka\
                     -name 'kafka-broker-api-versions.sh' -type f 2>/dev/null | head -n 1);if [ -f $KAFKA_API ];\
                     then $KAFKA_API --version; else echo Kafka not found; fi"

                kafka_version: str = remote_execute(shell_command, kafka_vm["ip"], ssh_login, ssh_pass)

                if not kafka_version:
                    kafka_version: str = f"ERROR: Kafka binary not found on {kafka_vm['name']}, {kafka_vm['ip']}"

                if isinstance(kafka_version, dict):
                    kafka_version: str = kafka_version["ERROR"]

                logger.info(f"Kafka version = {kafka_version.strip()}")
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
                logger.info(f"Get ignite version from {ignite_vm['ip']}")
                shell_command: str = "IGNITE_API=/opt/ignite/server/bin/control.sh; if sudo test -f $IGNITE_API;\
                then sudo $IGNITE_API --system-view nodes --illegal-access=warn 2>/dev/null | head -n 1;\
                else echo Ignite not found; fi"

                ignite_version: str = remote_execute(shell_command, ignite_vm["ip"], ssh_login, ssh_pass)

                if not ignite_version:
                    ignite_version: str = f"ERROR: Ignite not found on {ignite_vm['name']}, {ignite_vm['ip']}"

                if isinstance(ignite_version, dict):
                    ignite_version: str = ignite_version["ERROR"]

                logger.info(f"Ignite version = {ignite_version.strip()}")
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
                logger.info(f"Get hadoop version from {hadoop_vm['ip']}")
                shell_command: str = "hadoop version | head -n1"
                hadoop_version: str = remote_execute(shell_command, hadoop_vm["ip"], ssh_login, ssh_pass)

                if not hadoop_version:
                    hadoop_version: str = f"Error: Hadoop not found on {hadoop_vm['name']}, {hadoop_vm['ip']}"

                if isinstance(hadoop_version, dict):
                    hadoop_version: str = hadoop_version["ERROR"]
                logger.info(f"Hadoop version = {hadoop_version.strip()}")
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

            for sgw_vm in sgw_vms:  ## +++
                logger.info(f"Get sgw version from {sgw_vm['ip']}")
                if check_port(sgw_vm["ip"], 9080):
                    try:
                        response = requests.get("http://%s:9080/environment/product" % sgw_vm["ip"], timeout=5)

                        if response.status_code == 200:
                            sgw_version: str = json.loads(response.content)["buildVersion"]
                        else:
                            sgw_version: str = "Sgw version not found, response status code = %s" % response.status_code
                    except Exception as error:
                        sgw_version = str(error)
                else:
                    sgw_version: str = "Sgw is not available on port 9080"

                logger.info(f"Sgw version = {sgw_version}")
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

            for iag_vm in iag_vms:  ### ++++
                logger.info(f"Get iag version from {iag_vm['ip']}")
                if check_port(iag_vm["ip"], 9080):
                    try:
                        response = requests.get("http://%s:9080/product" % iag_vm["ip"], timeout=5)
                        if response.status_code == 200:
                            iag_version: str = json.loads(response.content)["buildVersion"]
                        else:
                            iag_version: str = "Iag version not found, response status code = %s" % response.status_code
                    except Exception as error:
                        iag_version = str(error)
                else:
                    iag_version: str = "Iag is not available on port 9080"
                logger.info(f"Iag version = {iag_version}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "iag",
                        "ip": iag_vm["ip"],
                        "id": iag_vm["id"],
                        "name": iag_vm["name"],
                        "service_name": iag_vm["service_name"],
                        "version": iag_version
                    }
                )

            for etcd_vm in etcd_vms:
                logger.info(f"Get etcd version from {etcd_vm['ip']}")
                shell_command: str = """etcdctl --endpoints=127.0.0.1:2379 endpoint status | awk -F ", " '{print $3}'"""
                etcd_version: str = remote_execute(shell_command, etcd_vm["ip"], ssh_login, ssh_pass)

                if not etcd_version:
                    etcd_version: str = f"ERROR: Etcd not found on {etcd_vm['name']}, {etcd_vm['ip']}"

                if isinstance(etcd_version, dict):
                    etcd_version: str = etcd_version["ERROR"]
                logger.info(f"Etcd version = {etcd_version.strip()}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "etcd",
                        "ip": etcd_vm["ip"],
                        "id": etcd_vm["id"],
                        "name": etcd_vm["name"],
                        "service_name": etcd_vm["service_name"],
                        "version": etcd_version.strip()
                    }
                )

            for zookeeper_vm in zookeeper_vms:
                logger.info(f"Get zookeeper version from {zookeeper_vm['ip']}")
                shell_command: str = 'echo "status" | nc localhost 2181 | head -n 1'
                zookeeper_version: str = remote_execute(shell_command, zookeeper_vm["ip"], ssh_login, ssh_pass)

                if not zookeeper_version:
                    zookeeper_version = f"ERROR: Zookeeper not found on {zookeeper_vm['name']}, {zookeeper_vm['ip']}"

                if isinstance(zookeeper_version, dict):
                    zookeeper_version: str = zookeeper_version["ERROR"]
                logger.info(f"Zookeeper version = {zookeeper_version.strip()}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "zookeeper",
                        "ip": zookeeper_vm["ip"],
                        "id": zookeeper_vm["id"],
                        "name": zookeeper_vm["name"],
                        "service_name": zookeeper_vm["service_name"],
                        "version": zookeeper_version.strip()
                    }
                )

            for victoria_vm in victoria_vms:
                logger.info(f"Get victoria version from {victoria_vm['ip']}")
                shell_command: str = """curl -silent http://localhost:8428/metrics | grep vm_app_version | awk -F '"' '{print $4}'"""
                victoria_version: str = remote_execute(shell_command, victoria_vm["ip"], ssh_login, ssh_pass)

                if not victoria_version:
                    victoria_version: str = f"ERROR: Victoria not found on {victoria_vm['name']}, {victoria_vm['ip']}"

                if isinstance(victoria_version, dict):
                    victoria_version: str = victoria_version["ERROR"]

                logger.info(f"Victoria version = {victoria_version.strip()}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "victoria",
                        "ip": victoria_vm["ip"],
                        "id": victoria_vm["id"],
                        "name": victoria_vm["name"],
                        "service_name": victoria_vm["service_name"],
                        "version": victoria_version.strip()
                    }
                )

            for keycloak_vm in keycloak_vms:
                logger.info(f"Get keycloak version from {keycloak_vm['ip']}")
                shell_command: str = 'cat /opt/keycloak/welcome-content/version.txt | grep version'
                keycloak_version: str = remote_execute(shell_command, keycloak_vm["ip"], ssh_login, ssh_pass)

                if not keycloak_version:
                    keycloak_version: str = f"ERROR: Keycloak not found on {keycloak_vm['name']}, {keycloak_vm['ip']}"

                if isinstance(keycloak_version, dict):
                    keycloak_version: str = keycloak_version["ERROR"]

                logger.info(f"Keycloak version = {keycloak_version.strip()}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "keycloak",
                        "ip": keycloak_vm["ip"],
                        "id": keycloak_vm["id"],
                        "name": keycloak_vm["name"],
                        "service_name": keycloak_vm["service_name"],
                        "version": keycloak_version.strip()
                    }
                )

            for elk_vm in elk_vms:  ### ++++
                logger.info(f"Get elk version from {['ip']}")
                if check_port(elk_vm["ip"], 9200):
                    try:
                        response = requests.get("https://%s:9200/_nodes/_local/os" % elk_vm["ip"], timeout=5,
                                                verify=False, auth=HTTPBasicAuth(pm_login, pm_pass))
                        if response.status_code == 200:
                            elk_version: str = tuple(json.loads(response.content)["nodes"].values())[0]["version"]
                        else:
                            elk_version: str = "Elk version not found, response status code %s" % response.status_code
                    except Exception as error:
                        elk_version = str(error)
                else:
                    elk_version: str = "Elk is not available on port 9200"

                logger.info(f"Elk version = {elk_version}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "elk",
                        "ip": elk_vm["ip"],
                        "id": elk_vm["id"],
                        "name": elk_vm["name"],
                        "service_name": elk_vm["service_name"],
                        "version": elk_version
                    }
                )

            for jenkins_vm in jenkins_vms:
                logger.info(f"Get jenkins version from {jenkins_vm['ip']}")
                if check_resolves("sw.%s.gtp" % portal_name.lower()):
                    if check_port("sw.%s.gtp" % portal_name.lower(), 443):
                        try:
                            response = requests.head("https://sw.%s.gtp/jenkins-cd/api/" % portal_name.lower(),
                                                     verify=False, timeout=5)
                            if response.status_code == 403:
                                jenkins_version: str = response.headers["x-jenkins"]
                            else:
                                jenkins_version: str = f"Jenkins version not found on https://sw.{portal_name.lower()}.gtp/jenkins-cd/api/, Response status code = %s" % response.status_code
                        except Exception as error:
                            jenkins_version = str(error)
                    else:
                        jenkins_version: str = f"Jenkins is not available on port https://sw.{portal_name.lower()}.gtp/jenkins-cd/api/"
                else:
                    jenkins_version: str = "sw.%s.gtp dns name does not resolve" % portal_name.lower()

                logger.info(f"Jenkins version = {jenkins_version.strip()}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "jenkinsslave",
                        "ip": jenkins_vm["ip"],
                        "id": jenkins_vm["id"],
                        "name": jenkins_vm["name"],
                        "service_name": jenkins_vm["service_name"],
                        "version": jenkins_version.strip()
                    }
                )

            for ipa_vm in ipa_vms:
                logger.info(f"Get ipa version from {ipa_vm['ip']}")
                for server in project_vms["servers"]:
                    if server["tag_ids"] and app_tags["ipa"] not in server["tag_ids"] and app_tags["ipareplica"] not in \
                            server["tag_ids"]:
                        if check_resolves(f"{server['name']}.gostech.novalocal"):
                            if check_port(server["ip"], 9022):
                                shell_command: str = f"""curl -silent -k -H referer:https://{ipa_vm['name']}.gostech.novalocal/ipa -H "Content-Type:application/json" -H "Accept:applicaton/json" --negotiate -u :  -X POST https://{ipa_vm['name']}.gostech.novalocal/ipa/json | sed -e 's/[{{}}]/''/g' |  awk -v RS=',' -F: '{{print $1 $2}}' | grep version | awk -F '"' '{{print $4}}'"""
                                ipa_version: str = remote_execute(shell_command, server["ip"], ssh_login, ssh_pass)

                                if not ipa_version:
                                    ipa_version: str = f"ERROR: Ipa version not found from {server['name']}, {server['ip']}"

                                if isinstance(ipa_version, dict):
                                    ipa_version: str = ipa_version["ERROR"]
                                    if ipa_version == f'Connection timed out to {server["ip"]}':
                                        print("CONTINUE")
                                        continue

                                logger.info(f"Ipa version = {ipa_version.strip()}")
                                project_modules_info["modules_version"].append(
                                    {
                                        "tag": "ipareplica",
                                        "ip": ipa_vm["ip"],
                                        "id": ipa_vm["id"],
                                        "name": ipa_vm["name"],
                                        "service_name": ipa_vm["service_name"],
                                        "version": ipa_version.strip()
                                    }
                                )
                                break

            for eskkd_vm in eskkd_vms:
                logger.info(f"Get eskkd version from {eskkd_vm['ip']}")
                shell_command: str = """cat /opt/eskkd/current/package.json | grep version | awk -F '"' '{print $4}' | head -n 1"""
                eskkd_version: str = remote_execute(shell_command, eskkd_vm["ip"], ssh_login, ssh_pass)

                if not eskkd_version:
                    eskkd_version: str = f"ERROR: Eskkd not found on {eskkd_vm['name']}, {eskkd_vm['ip']}"

                if isinstance(eskkd_version, dict):
                    eskkd_version: str = eskkd_version["ERROR"]
                logger.info(f"Eskkd version = {eskkd_version.strip()}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "eskkd",
                        "ip": eskkd_vm["ip"],
                        "id": eskkd_vm["id"],
                        "name": eskkd_vm["name"],
                        "service_name": eskkd_vm["service_name"],
                        "version": eskkd_version.strip()
                    }
                )

            for sds_vm in sds_vms:
                logger.info(f"Get sds version from {sds_vm['ip']}")
                if check_port(sds_vm["ip"], 9080):
                    try:
                        response = requests.get(
                            f'http://{sds_vm["ip"]}:9080/ufs-session-master/rest/environment/product', timeout=5
                        )

                        if response.status_code == 200:
                            sds_version: str = json.loads(response.content)["body"]["version"]
                        else:
                            sds_version: str = "Sds version not found, Response status code = %s" % response.status_code
                    except Exception as error:
                        sds_version = str(error)
                else:
                    sds_version: str = "Sds is unreachable on port 9080"

                logger.info(f"Sds version = {sds_version}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "sds",
                        "ip": sds_vm["ip"],
                        "id": sds_vm["id"],
                        "name": sds_vm["name"],
                        "service_name": sds_vm["service_name"],
                        "version": sds_version
                    }
                )

            for etl_vm in etl_vms:
                logger.info(f"Get etl version from {etl_vm['ip']}")
                if check_port(etl_vm["ip"], 8443):
                    headers: dict = {
                        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    }

                    try:
                        etl_token = requests.post(f"https://{etl_vm['ip']}:8443/nifi-api/access/token", headers=headers,
                                                  data=f'username={pm_login}&password={pm_pass_enc}', verify=False)

                        if etl_token.status_code == 201:

                            headers: dict = {
                                'Authorization': 'Bearer %s' % etl_token.text
                            }

                            etl_version: str = json.loads(
                                requests.get(f"https://{etl_vm['ip']}:8443/nifi-api/flow/about", headers=headers,
                                             verify=False).content)["about"]["version"]
                        else:
                            etl_version: str = f"Error getting etl token, response status code = {etl_token.status_code}"
                    except Exception as error:
                        etl_version = str(error)
                else:
                    etl_version: str = "Etl is not available on port 8443"

                logger.info(f"Etl version = {etl_version}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "nifi",
                        "ip": etl_vm["ip"],
                        "id": etl_vm["id"],
                        "name": etl_vm["name"],
                        "service_name": etl_vm["service_name"],
                        "version": etl_version
                    }
                )

            for datalab_vm in datalab_vms:
                logger.info(f"Get datalab version from {datalab_vm['ip']}")
                if check_port(datalab_vm["ip"], 8000):
                    try:
                        response = requests.get("https://%s:8000/JupyterHub/hub/api" % datalab_vm["ip"], timeout=5,
                                                verify=False)
                        if response.status_code == 200:
                            datalab_version: str = json.loads(response.content)["version"]
                        else:
                            datalab_version: str = \
                                "Datalab version not found, response status code = %s" % response.status_code
                    except Exception as error:
                        datalab_version = str(error)
                else:
                    datalab_version: str = "Datalab is not available on port 8000"

                logger.info(f"Datalab version = {datalab_version}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "datalab",
                        "ip": datalab_vm["ip"],
                        "id": datalab_vm["id"],
                        "name": datalab_vm["name"],
                        "service_name": datalab_vm["service_name"],
                        "version": datalab_version
                    }
                )

            for ambari_vm in ambari_vms:
                logger.info(f"Get ambari version from {ambari_vm['ip']}")
                shell_command: str = """sudo ambari-server --version"""
                ambari_version: str = remote_execute(shell_command, ambari_vm["ip"], ssh_login, ssh_pass)

                if not ambari_version:
                    ambari_version: str = f"ERROR: Ambari not found on {ambari_vm['name']}, {ambari_vm['ip']}"

                if isinstance(ambari_version, dict):
                    ambari_version: str = ambari_version["ERROR"]

                logger.info(f"Ambari version = {ambari_version.strip()}")
                project_modules_info["modules_version"].append(
                    {
                        "tag": "ambari",
                        "ip": ambari_vm["ip"],
                        "id": ambari_vm["id"],
                        "name": ambari_vm["name"],
                        "service_name": ambari_vm["service_name"],
                        "version": ambari_version.strip()
                    }
                )

            for synapseflink_vm in synapseflink_vms:
                logger.info(f"Get synapse flink version from {synapseflink_vm['ip']}")
                shell_command: str = """sudo /opt/Apache/flink/bin/flink --version | grep Version"""
                synapseflink_version: str = remote_execute(shell_command, synapseflink_vm["ip"], ssh_login, ssh_pass)

                if not synapseflink_version:
                    synapseflink_version: str = \
                        f"ERROR: Ambari not found on {synapseflink_vm['name']}, {synapseflink_vm['ip']}"

                if isinstance(synapseflink_version, dict):
                    synapseflink_version: str = synapseflink_version["ERROR"]

                logger.info(f"Synapse flink version = {synapseflink_version.strip()}")

                project_modules_info["modules_version"].append(
                    {
                        "tag": "synapse_flink",
                        "ip": synapseflink_vm["ip"],
                        "id": synapseflink_vm["id"],
                        "name": synapseflink_vm["name"],
                        "service_name": synapseflink_vm["service_name"],
                        "version": synapseflink_version.strip()
                    }
                )
    return output_info


if __name__ == "__main__":
    get_app_versions(next(iter(portal_info)))
