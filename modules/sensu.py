import datetime
import json
import logging
import subprocess

import requests
from argo_scg.exceptions import SensuException, SCGException, SCGWarnException
from argo_scg.generator import create_attribute_env, create_label, is_attribute_secret


class Sensu:
    def __init__(self, url, token, namespaces):
        self.url = url
        self.token = token
        self.non_poem_checks = ["sensu.cpu.usage", "sensu.memory.usage"]
        self.namespaces = namespaces
        self.logger = logging.getLogger("argo-scg.sensu")

    def _get_namespaces(self):
        exceptions = ["sensu-system"]
        response = requests.get(
            f"{self.url}/api/core/v2/namespaces",
            headers={"Authorization": f"Key {self.token}", "Content-Type": "application/json"},
        )

        if not response.ok:
            msg = f"Namespaces fetch error: {response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.error(msg)
            self.logger.warning("Unable to proceed")
            raise SensuException(msg)

        else:
            return [
                namespace["name"]
                for namespace in response.json()
                if namespace["name"] not in exceptions
            ]

    def handle_namespaces(self):
        existing_namespaces = self._get_namespaces()

        for namespace, tenants in self.namespaces.items():
            if namespace not in existing_namespaces:
                response = requests.put(
                    f"{self.url}/api/core/v2/namespaces/{namespace}",
                    headers={
                        "Authorization": f"Key {self.token}",
                        "Content-Type": "application/json",
                    },
                    data=json.dumps({"name": namespace}),
                )

                if not response.ok:
                    msg = (
                        f"Namespace {namespace} create error: "
                        f"{response.status_code} {response.reason}"
                    )

                    try:
                        msg = f"{msg}: {response.json()['message']}"

                    except (ValueError, TypeError, KeyError):
                        pass

                    self.logger.error(msg)
                    self.logger.warning("Unable to proceed")
                    raise SensuException(msg)

                else:
                    self.logger.info(f"Namespace {namespace} created")

        for namespace in set(existing_namespaces).difference(set(self.namespaces.keys())):
            try:
                subprocess.check_output(
                    f"sensuctl dump "
                    f"entities,events,assets,checks,filters,handlers,silenced "
                    f"--namespace {namespace} | sensuctl delete",
                    shell=True,
                )
                self.logger.info(f"Namespace {namespace} emptied")
                response = requests.delete(
                    f"{self.url}/api/core/v2/namespaces/{namespace}",
                    headers={"Authorization": f"Key {self.token}"},
                )

                if response.ok:
                    self.logger.info(f"Namespace {namespace} deleted")

                else:
                    msg = f"{response.status_code} {response.reason}"
                    try:
                        msg = f"{msg}: {response.json()['message']}"

                    except (ValueError, KeyError, TypeError):
                        pass

                    self.logger.error(f"Error deleting {namespace}: {msg}")

            except subprocess.CalledProcessError as err:
                self.logger.error(f"Error cleaning namespace {namespace}: {err.output}")

    def _get_checks(self, namespace):
        response = requests.get(
            f"{self.url}/api/core/v2/namespaces/{namespace}/checks",
            headers={"Authorization": f"Key {self.token}", "Content-Type": "application/json"},
        )

        if not response.ok:
            msg = f"{namespace}: Checks fetch error: {response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.error(msg)
            raise SensuException(msg)

        else:
            return response.json()

    def _get_events(self, namespace):
        response = requests.get(
            f"{self.url}/api/core/v2/namespaces/{namespace}/events",
            headers={"Authorization": f"Key {self.token}", "Content-Type": "application/json"},
        )
        return response

    def _get_event(self, entity, check, namespace):
        response = self._get_events(namespace=namespace)

        if not response.ok:
            msg = f"{namespace}: Events fetch error: {response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            raise SensuException(msg)

        else:
            try:
                return [
                    event
                    for event in response.json()
                    if event["entity"]["metadata"]["name"] == entity
                    and event["check"]["metadata"]["name"] == check
                ][0]

            except IndexError:
                raise SensuException(f"{namespace}: No event for entity {entity} and check {check}")

    def get_event_output(self, entity, check, namespace="default"):
        event = self._get_event(entity=entity, check=check, namespace=namespace)
        return event["check"]["output"]

    def _fetch_events(self, namespace):
        response = self._get_events(namespace=namespace)

        if not response.ok:
            msg = f"{namespace}: Events fetch error: {response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.warning(msg)
            raise SensuException(msg)

        else:
            return response.json()

    def _delete_check(self, check, namespace):
        response = requests.delete(
            f"{self.url}/api/core/v2/namespaces/{namespace}/checks/{check}",
            headers={"Authorization": f"Key {self.token}"},
        )

        if not response.ok:
            msg = (
                f"{namespace}: Check {check} not removed: {response.status_code} {response.reason}"
            )

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, TypeError, KeyError):
                pass

            raise SCGException(msg)

        else:
            self._delete_silenced_entry(check=check, namespace=namespace)

    def delete_check(self, check, namespace="default"):
        try:
            self._delete_check(check=check, namespace=namespace)

        except SCGWarnException:
            raise

        except SCGException as e:
            raise SensuException(str(e))

    def _delete_checks(self, checks, namespace):
        for check in checks:
            try:
                self._delete_check(check=check, namespace=namespace)

            except SCGWarnException as e:
                self.logger.info(f"{namespace}: Check {check} removed")
                self.logger.warning(f"{namespace}: {str(e)}")

            except SCGException as e:
                self.logger.warning(str(e))
                continue

            else:
                self.logger.info(f"{namespace}: Check {check} removed")

    def _delete_event(self, entity, check, namespace):
        response = requests.delete(
            f"{self.url}/api/core/v2/namespaces/{namespace}/events/{entity}/{check}",
            headers={"Authorization": f"Key {self.token}"},
        )

        if not response.ok:
            msg = (
                f"{namespace}: Event {entity}/{check} not removed: "
                f"{response.status_code} {response.reason}"
            )

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, TypeError, KeyError):
                pass

            raise SCGException(msg)

        else:
            self._delete_silenced_entry(entity=entity, check=check, namespace=namespace)

    def delete_event(self, entity, check, namespace="default"):
        try:
            self._delete_event(entity=entity, check=check, namespace=namespace)

        except SCGWarnException:
            raise

        except SCGException as e:
            raise SensuException(str(e))

    def _delete_events(self, events, namespace):
        for entity, checks in events.items():
            for check in checks:
                try:
                    self._delete_event(entity=entity, check=check, namespace=namespace)

                except SCGWarnException as e:
                    self.logger.info(f"{namespace}: Event {entity}/{check} removed")
                    self.logger.warning(f"{namespace}: {str(e)}")

                except SCGException as e:
                    self.logger.warning(str(e))

                else:
                    self.logger.info(f"{namespace}: Event {entity}/{check} removed")

    @staticmethod
    def _compare_checks(check1, check2):
        def proxy_equality(c1, c2):
            proxy_equal = False
            key1 = "proxy_requests"
            key2 = "entity_attributes"
            condition1 = key1 in c1 and key1 in c2
            condition2 = key1 not in c1 and key1 not in c2
            condition3 = False
            if condition1:
                condition3 = c1[key1][key2] == c2[key1][key2]
            if (condition1 and condition3) or condition2:
                proxy_equal = True

            return proxy_equal

        def interval_equality(c1, c2):
            interval_equal = False
            key1 = "cron"
            key2 = "interval"
            condition1 = key1 in c1 and key1 in c2
            condition2 = key1 not in c1 and key1 not in c2
            condition3 = key2 in c1 and key2 in c2
            condition4 = key2 not in c1 and key2 not in c2
            condition5 = False
            if condition1:
                condition5 = c1[key1] == c2[key1]

            if condition2 and condition3:
                condition5 = c1[key2] == c2[key2]

            if (condition1 and condition5) or (condition3 and condition5) or condition4:
                interval_equal = True

            return interval_equal

        def _equality_2lvl(c1, c2, key):
            _equal = False
            key1 = "metadata"
            key2 = key
            condition1 = key2 in c1[key1] and key2 in c2[key1]
            condition2 = key2 not in c1[key1] and key2 not in c2[key1]

            condition3 = False
            if condition1:
                condition3 = c1[key1][key2] == c2[key1][key2]

            if (condition1 and condition3) or condition2:
                _equal = True

            return _equal

        def annotations_equality(c1, c2):
            return _equality_2lvl(c1, c2, key="annotations")

        def labels_equality(c1, c2):
            return _equality_2lvl(c1, c2, key="labels")

        equal = False
        if (
            check1["command"] == check2["command"]
            and sorted(check1["subscriptions"]) == sorted(check2["subscriptions"])
            and sorted(check1["handlers"]) == sorted(check2["handlers"])
            and proxy_equality(check1, check2)
            and interval_equality(check1, check2)
            and check1["timeout"] == check2["timeout"]
            and check1["publish"] == check2["publish"]
            and check1["metadata"]["name"] == check2["metadata"]["name"]
            and check1["metadata"]["namespace"] == check2["metadata"]["namespace"]
            and check1["round_robin"] == check2["round_robin"]
            and check1["pipelines"] == check2["pipelines"]
            and annotations_equality(check1, check2)
        ) and labels_equality(check1, check2):
            equal = True

        return equal

    def _get_entities(self, namespace):
        response = requests.get(
            f"{self.url}/api/core/v2/namespaces/{namespace}/entities",
            headers={
                "Authorization": "Key {}".format(self.token),
                "Content-Type": "application/json",
            },
        )

        if not response.ok:
            msg = f"{response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            raise SensuException(msg)

        else:
            return response.json()

    def _get_proxy_entities(self, namespace):
        try:
            data = self._get_entities(namespace=namespace)

        except SensuException as e:
            msg = f"{namespace}: Error fetching proxy entities: {str(e).strip('Sensu error: ')}"
            self.logger.error(msg)
            raise SensuException(msg)

        return [entity for entity in data if entity["entity_class"] == "proxy"]

    def _get_agents(self, namespace):
        try:
            data = self._get_entities(namespace=namespace)

        except SensuException as e:
            msg = f"{namespace}: Error fetching agents: {str(e).strip('Sensu error: ')}"
            self.logger.error(msg)
            raise SensuException(msg)

        return [entity for entity in data if entity["entity_class"] == "agent"]

    def get_agents(self, namespace="default"):
        try:
            data = self._get_entities(namespace=namespace)

        except SensuException as e:
            msg = f"{namespace}: Error fetching agents: {str(e).strip('Sensu error: ')}"
            raise SensuException(msg)

        return [entity for entity in data if entity["entity_class"] == "agent"]

    def is_entity_agent(self, entity, namespace="default"):
        try:
            entity_configuration = [
                e
                for e in self._get_entities(namespace=namespace)
                if e["metadata"]["name"] == entity
            ][0]

        except IndexError:
            raise SensuException(f"No entity {entity} in namespace {namespace}")

        if entity_configuration["entity_class"] == "agent":
            return True

        else:
            return False

    def _delete_entities(self, entities, namespace):
        for entity in entities:
            response = requests.delete(
                f"{self.url}/api/core/v2/namespaces/{namespace}/entities/{entity}",
                headers={"Authorization": f"Key {self.token}"},
            )

            if not response.ok:
                msg = (
                    f"{namespace}: Entity {entity} not removed: "
                    f"{response.status_code} {response.reason}"
                )

                try:
                    msg = f"{msg}: {response.json()['message']}"

                except (ValueError, TypeError, KeyError):
                    pass

                self.logger.warning(msg)

            else:
                try:
                    self._delete_silenced_entry(entity=entity, namespace=namespace)

                except SCGWarnException as e:
                    self.logger.warning(f"{namespace}: {str(e)}")

                self.logger.info(f"{namespace}: Entity {entity} removed")

    @staticmethod
    def _compare_entities(entity1, entity2):
        equal = False

        try:
            entity2["metadata"]["labels"].pop("sensu.io/managed_by")

        except KeyError:
            pass

        if "subscriptions" not in entity1:
            entity1.update({"subscriptions": None})

        if "subscriptions" not in entity2:
            entity2.update({"subscriptions": None})

        if (
            entity1["metadata"]["name"] == entity2["metadata"]["name"]
            and entity1["metadata"]["namespace"] == entity2["metadata"]["namespace"]
            and entity1["metadata"]["labels"] == entity2["metadata"]["labels"]
            and entity1["subscriptions"] == entity2["subscriptions"]
        ):
            equal = True

        return equal

    def _put_check(self, check, namespace):
        response = requests.put(
            f"{self.url}/api/core/v2/namespaces/{namespace}/checks/{check['metadata']['name']}",
            headers={"Authorization": f"Key {self.token}", "Content-Type": "application/json"},
            data=json.dumps(check),
        )

        return response

    def put_check(self, check, namespace="default"):
        response = self._put_check(check=check, namespace=namespace)

        if not response.ok:
            msg = (
                f"{namespace}: "
                f"Check {check['metadata']['name']} not created: "
                f"{response.status_code} {response.reason}"
            )
            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, TypeError, KeyError):
                pass

            raise SensuException(msg)

    def handle_checks(self, checks, namespace="default"):
        existing_checks = self._get_checks(namespace=namespace)

        for check in checks:
            existing_check = [
                ec for ec in existing_checks if ec["metadata"]["name"] == check["metadata"]["name"]
            ]

            if len(existing_check) == 0:
                word = "created"

            else:
                word = "updated"

            if len(existing_check) == 0 or not self._compare_checks(check, existing_check[0]):
                response = self._put_check(check=check, namespace=namespace)

                if not response.ok:
                    msg = (
                        f"{namespace}: "
                        f"Check {check['metadata']['name']} not {word}: "
                        f"{response.status_code} {response.reason}"
                    )
                    try:
                        msg = f"{msg}: {response.json()['message']}"

                    except (ValueError, TypeError, KeyError):
                        pass

                    self.logger.warning(msg)

                else:
                    self.logger.info(f"{namespace}: Check {check['metadata']['name']} {word}")

        updated_existing_checks = self._get_checks(namespace=namespace)
        checks_tobedeleted = sorted(
            list(
                set([check["metadata"]["name"] for check in updated_existing_checks]).difference(
                    set([check["metadata"]["name"] for check in checks])
                )
            )
        )

        checks_tobedeleted = [
            item for item in checks_tobedeleted if item not in self.non_poem_checks
        ]

        if len(checks_tobedeleted) > 0:
            self._delete_checks(checks=checks_tobedeleted, namespace=namespace)

            after_delete_checks = [
                check["metadata"]["name"] for check in self._get_checks(namespace=namespace)
            ]
            try:
                existing_events = self._fetch_events(namespace=namespace)
                events_tobedeleted = dict()
                for event in existing_events:
                    check = event["check"]["metadata"]["name"]
                    if check not in after_delete_checks:
                        entity = event["entity"]["metadata"]["name"]
                        if entity not in events_tobedeleted.keys():
                            events_tobedeleted.update({entity: [check]})

                        else:
                            entity_checks = events_tobedeleted[entity]
                            entity_checks.append(check)
                            events_tobedeleted.update({entity: entity_checks})

                self._delete_events(events=events_tobedeleted, namespace=namespace)

            except SensuException:
                pass

    def handle_proxy_entities(self, entities, namespace="default"):
        existing_entities = self._get_proxy_entities(namespace=namespace)
        for entity in entities:
            existing_entity = [
                ent
                for ent in existing_entities
                if ent["metadata"]["name"] == entity["metadata"]["name"]
            ]

            if len(existing_entity) == 0:
                word = "created"

            else:
                word = "updated"

            if len(existing_entity) == 0 or not self._compare_entities(entity, existing_entity[0]):
                response = requests.put(
                    f"{self.url}/api/core/v2/namespaces/{namespace}/entities/"
                    f"{entity['metadata']['name']}",
                    data=json.dumps(entity),
                    headers={
                        "Authorization": f"Key {self.token}",
                        "Content-Type": "application/json",
                    },
                )

                if not response.ok:
                    msg = (
                        f"{namespace}: Proxy entity "
                        f"{entity['metadata']['name']} not {word}: "
                        f"{response.status_code} {response.reason}"
                    )

                    try:
                        msg = f"{msg}: {response.json()['message']}"

                    except (ValueError, TypeError, KeyError):
                        pass

                    self.logger.warning(msg)

                else:
                    self.logger.info(f"{namespace}: Entity {entity['metadata']['name']} {word}")

        entities_tobedeleted = list(
            set([entity["metadata"]["name"] for entity in existing_entities]).difference(
                set([entity["metadata"]["name"] for entity in entities])
            )
        )

        if len(entities_tobedeleted):
            self._delete_entities(entities=entities_tobedeleted, namespace=namespace)

    def handle_agents(
        self,
        metric_parameters_overrides=None,
        host_attributes_overrides=None,
        services="internals",
        namespace="default",
    ):
        if metric_parameters_overrides is None:
            metric_parameters_overrides = []

        if host_attributes_overrides is None:
            host_attributes_overrides = []

        def _get_labels(hostname):
            host_labels = {"hostname": hostname, "services": services}

            for item in metric_parameters_overrides:
                if item["hostname"] == hostname:
                    host_labels.update(
                        {
                            item["label"]: item["value"],
                        }
                    )

            for item in host_attributes_overrides:
                if item["hostname"] == hostname:
                    attr_val = create_attribute_env(item["value"])
                    if is_attribute_secret(item["attribute"]) and not attr_val.startswith("$"):
                        attr_val = f"${attr_val}"

                    host_labels.update({create_label(item["attribute"]): attr_val})

            return host_labels

        try:
            agents = self._get_agents(namespace=namespace)

            for agent in agents:
                send_data = dict()
                subs = [f"entity:{agent['metadata']['name']}"]

                if not set(subs) == set(agent["subscriptions"]):
                    send_data.update({"subscriptions": subs})

                labels = _get_labels(agent["metadata"]["name"])
                if (
                    "labels" in agent["metadata"] and labels != agent["metadata"]["labels"]
                ) or "labels" not in agent["metadata"]:
                    send_data.update({"metadata": {"labels": labels}})

                if send_data:
                    response = requests.patch(
                        f"{self.url}/api/core/v2/namespaces/"
                        f"{namespace}/entities/{agent['metadata']['name']}",
                        data=json.dumps(send_data),
                        headers={
                            "Authorization": f"Key {self.token}",
                            "Content-Type": "application/merge-patch+json",
                        },
                    )

                    if not response.ok:
                        msg = (
                            f"{namespace}: {agent['metadata']['name']} "
                            f"not updated: "
                            f"{response.status_code} {response.reason}"
                        )
                        try:
                            msg = f"{msg}: {response.json()['message']}"

                        except (ValueError, TypeError, KeyError):
                            pass

                        self.logger.error(msg)

                    else:
                        if "subscriptions" in send_data:
                            self.logger.info(
                                f"{namespace}: {agent['metadata']['name']} subscriptions updated"
                            )

                        if "metadata" in send_data:
                            self.logger.info(
                                f"{namespace}: {agent['metadata']['name']} labels updated"
                            )

        except SensuException:
            self.logger.warning(f"{namespace}: Agents not handled...")

    def _get_handlers(self, namespace):
        response = requests.get(
            f"{self.url}/api/core/v2/namespaces/{namespace}/handlers",
            headers={"Authorization": f"Key {self.token}", "Content-Type": "application/json"},
        )

        if not response.ok:
            msg = f"{namespace}: Handlers fetch error: {response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.error(msg)
            raise SensuException(msg)

        else:
            return response.json()

    def _handle_handler(self, name, data, namespace="default"):
        existing_handler = [
            handler
            for handler in self._get_handlers(namespace=namespace)
            if handler["metadata"]["name"] == name
        ]

        print_name = name if name.endswith("handler") else f"{name}-handler"
        if len(existing_handler) == 0:
            response = requests.post(
                f"{self.url}/api/core/v2/namespaces/{namespace}/handlers",
                headers={"Authorization": f"Key {self.token}", "Content-Type": "application/json"},
                data=json.dumps(data),
            )

            if not response.ok:
                msg = (
                    f"{namespace}: {print_name} create error: "
                    f"{response.status_code} {response.reason}"
                )

                try:
                    msg = f"{msg}: {response.json()['message']}"

                except (ValueError, KeyError, TypeError):
                    pass

                self.logger.error(msg)
                raise SensuException(msg)

            else:
                self.logger.info(f"{namespace}: {print_name} created")

        else:
            if existing_handler[0]["command"] != data["command"]:
                response = requests.patch(
                    f"{self.url}/api/core/v2/namespaces/{namespace}/handlers/{name}",
                    headers={
                        "Authorization": f"Key {self.token}",
                        "Content-Type": "application/merge-patch+json",
                    },
                    data=json.dumps({"command": data["command"]}),
                )

                if not response.ok:
                    msg = (
                        f"{namespace}: {print_name} not updated: "
                        f"{response.status_code} {response.reason}"
                    )

                    try:
                        msg = f"{msg}: {response.json()['message']}"

                    except (ValueError, KeyError, TypeError):
                        pass

                    self.logger.warning(msg)

                else:
                    self.logger.info(f"{namespace}: {print_name} updated")

    def handle_publisher_handler(self, namespace="default"):
        self._handle_handler(
            name="publisher-handler",
            data={
                "metadata": {"name": "publisher-handler", "namespace": namespace},
                "type": "pipe",
                "command": "/bin/sensu2publisher.py",
            },
            namespace=namespace,
        )

    def handle_slack_handler(self, secrets_file, namespace="default"):
        self._handle_handler(
            name="slack",
            data={
                "metadata": {"name": "slack", "namespace": namespace},
                "type": "pipe",
                "command": f"source {secrets_file} ; "
                f"export $(cut -d= -f1 {secrets_file}) ; "
                f"sensu-slack-handler --channel '#monitoring'",
                "runtime_assets": ["sensu-slack-handler"],
            },
            namespace=namespace,
        )

    def _get_filters(self, namespace):
        response = requests.get(
            f"{self.url}/api/core/v2/namespaces/{namespace}/filters",
            headers={"Authorization": f"Key {self.token}"},
        )

        if not response.ok:
            msg = f"{namespace}: Filters fetch error: {response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.error(msg)
            raise SensuException(msg)

        else:
            return response.json()

    def _add_filter(self, name, expressions, namespace="default"):
        filters = self._get_filters(namespace=namespace)
        filters_names = [f["metadata"]["name"] for f in filters]

        response = None
        added = False
        if name not in filters_names:
            added = True
            response = requests.post(
                f"{self.url}/api/core/v2/namespaces/{namespace}/filters",
                headers={"Authorization": f"Key {self.token}", "Content-Type": "application/json"},
                data=json.dumps(
                    {
                        "metadata": {"name": name, "namespace": namespace},
                        "action": "allow",
                        "expressions": expressions,
                    }
                ),
            )

        else:
            the_filter = [f for f in filters if f["metadata"]["name"] == name][0]
            if the_filter["expressions"] != expressions:
                response = requests.patch(
                    f"{self.url}/api/core/v2/namespaces/{namespace}/filters/{name}",
                    headers={
                        "Authorization": f"Key {self.token}",
                        "Content-Type": "application/merge-patch+json",
                    },
                    data=json.dumps({"expressions": expressions}),
                )

        if response:
            if not response.ok:
                if added:
                    intra_msg = f"{name} filter create error"

                else:
                    intra_msg = f"{name} filter not updated"

                msg = f"{namespace}: {intra_msg}: {response.status_code} {response.reason}"

                try:
                    msg = f"{msg}: {response.json()['message']}"

                except (ValueError, KeyError, TypeError):
                    pass

                if added:
                    self.logger.error(msg)
                    raise SensuException(msg)

                else:
                    self.logger.warning(msg)

            else:
                if added:
                    operation = "created"

                else:
                    operation = "updated"
                self.logger.info(f"{namespace}: {name} filter {operation}")

    def add_daily_filter(self, namespace="default"):
        expressions = [
            "((event.check.occurrences == 1 && event.check.status == 0 "
            "&& event.check.occurrences_watermark >= "
            "Number(event.check.annotations.attempts)) || "
            "(event.check.occurrences == "
            "Number(event.check.annotations.attempts) "
            "&& event.check.status != 0)) || "
            "event.check.occurrences % (86400 / event.check.interval) == 0"
        ]

        self._add_filter(name="daily", expressions=expressions, namespace=namespace)

    def add_hard_state_filter(self, namespace="default"):
        expressions = [
            "((event.check.status == 0) || (event.check.occurrences >= "
            "Number(event.check.annotations.attempts) "
            "&& event.check.status != 0))"
        ]

        self._add_filter(name="hard-state", expressions=expressions, namespace=namespace)

    def _get_pipelines(self, namespace):
        response = requests.get(
            f"{self.url}/api/core/v2/namespaces/{namespace}/pipelines",
            headers={"Authorization": f"Key {self.token}"},
        )

        if not response.ok:
            msg = f"{namespace}: Pipelines fetch error: {response.status_code} {response.reason}"

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            self.logger.error(msg)
            raise SensuException(msg)

        else:
            return response.json()

    def _add_pipeline(self, name, workflows, namespace="default"):
        pipelines = self._get_pipelines(namespace=namespace)
        pipelines_names = [p["metadata"]["name"] for p in pipelines]

        response = None
        added = False
        if name not in pipelines_names:
            added = True
            response = requests.post(
                f"{self.url}/api/core/v2/namespaces/{namespace}/pipelines",
                headers={"Authorization": f"Key {self.token}", "Content-Type": "application/json"},
                data=json.dumps(
                    {"metadata": {"name": name, "namespace": namespace}, "workflows": workflows}
                ),
            )

        else:
            the_pipeline = [p for p in pipelines if p["metadata"]["name"] == name][0]
            if the_pipeline["workflows"] != workflows:
                response = requests.patch(
                    f"{self.url}/api/core/v2/namespaces/{namespace}/pipelines/{name}",
                    headers={
                        "Authorization": f"Key {self.token}",
                        "Content-Type": "application/merge-patch+json",
                    },
                    data=json.dumps({"workflows": workflows}),
                )

        if response:
            if not response.ok:
                if added:
                    intra_msg = f"{name} pipeline create error"
                else:
                    intra_msg = f"{name} pipeline not updated"

                msg = f"{namespace}: {intra_msg}: {response.status_code} {response.reason}"

                try:
                    msg = f"{msg}: {response.json()['message']}"

                except (ValueError, KeyError, TypeError):
                    pass

                if added:
                    self.logger.error(msg)
                    raise SensuException(msg)

                else:
                    self.logger.warning(msg)

            else:
                if added:
                    operation = "created"
                else:
                    operation = "updated"

                self.logger.info(f"{namespace}: {name} pipeline {operation}")

    def add_reduce_alerts_pipeline(self, namespace="default"):
        workflows = [
            {
                "name": "slack_alerts",
                "filters": [
                    {"name": "is_incident", "type": "EventFilter", "api_version": "core/v2"},
                    {"name": "not_silenced", "type": "EventFilter", "api_version": "core/v2"},
                    {"name": "daily", "type": "EventFilter", "api_version": "core/v2"},
                ],
                "handler": {"name": "slack", "type": "Handler", "api_version": "core/v2"},
            }
        ]

        self._add_pipeline(name="reduce_alerts", workflows=workflows, namespace=namespace)

    def add_hard_state_pipeline(self, namespace="default"):
        workflows = [
            {
                "name": "mimic_hard_state",
                "filters": [
                    {"name": "hard-state", "type": "EventFilter", "api_version": "core/v2"}
                ],
                "handler": {
                    "name": "publisher-handler",
                    "type": "Handler",
                    "api_version": "core/v2",
                },
            }
        ]

        self._add_pipeline(name="hard_state", workflows=workflows, namespace=namespace)

    def _add_asset_check(self, name, namespace):
        checks = self._get_checks(namespace=namespace)
        checks_names = [check["metadata"]["name"] for check in checks]
        agents = [
            f"entity:{item['metadata']['name']}" for item in self.get_agents(namespace=namespace)
        ]

        assets = {"sensu.cpu.usage": "check-cpu-usage", "sensu.memory.usage": "check-memory-usage"}

        data = {
            "command": f"{assets[name]} -w 85 -c 90",
            "interval": 300,
            "publish": True,
            "runtime_assets": [assets[name]],
            "subscriptions": agents,
            "timeout": 900,
            "round_robin": False,
            "metadata": {"name": name, "namespace": namespace, "annotations": {"attempts": "3"}},
            "pipelines": [{"name": "reduce_alerts", "type": "Pipeline", "api_version": "core/v2"}],
        }

        response = None
        added = False
        if name not in checks_names:
            added = True
            response = requests.post(
                f"{self.url}/api/core/v2/namespaces/{namespace}/checks",
                data=json.dumps(data),
                headers={"Authorization": f"Key {self.token}", "Content-Type": "application/json"},
            )

        else:
            check = [check for check in checks if check["metadata"]["name"] == name][0]
            if (
                check["command"] != data["command"]
                or check["interval"] != data["interval"]
                or check["runtime_assets"] != data["runtime_assets"]
                or check["subscriptions"] != data["subscriptions"]
                or check["timeout"] != data["timeout"]
                or check["pipelines"] != data["pipelines"]
                or "annotations" not in check["metadata"]
                or check["metadata"]["annotations"] != data["metadata"]["annotations"]
            ):
                response = requests.put(
                    f"{self.url}/api/core/v2/namespaces/{namespace}/checks/{name}",
                    data=json.dumps(data),
                    headers={
                        "Authorization": f"Key {self.token}",
                        "Content-Type": "application/json",
                    },
                )

        if response:
            if added:
                operation = "created"
            else:
                operation = "updated"

            if response.ok:
                self.logger.info(f"{namespace}: Check {name} {operation}")

            else:
                msg = (
                    f"{namespace}: Check {name} not {operation}: "
                    f"{response.status_code} {response.reason}"
                )

                try:
                    msg = f"{msg}: {response.json()['message']}"

                except (ValueError, KeyError, TypeError):
                    pass

                self.logger.error(msg)
                raise SensuException(msg)

    def add_cpu_check(self, namespace="default"):
        self._add_asset_check(name="sensu.cpu.usage", namespace=namespace)

    def add_memory_check(self, namespace="default"):
        self._add_asset_check(name="sensu.memory.usage", namespace=namespace)

    def _get_check(self, check, namespace):
        try:
            return [
                c for c in self._get_checks(namespace=namespace) if c["metadata"]["name"] == check
            ][0]

        except IndexError:
            raise SensuException(f"No check {check} in namespace {namespace}")

    def get_check_run(self, entity, check, namespace="default"):
        check_configuration = self._get_check(check=check, namespace=namespace)

        try:
            entity_configuration = [
                e
                for e in self._get_entities(namespace=namespace)
                if e["metadata"]["name"] == entity
            ][0]

        except IndexError:
            raise SensuException(f"No entity {entity} in namespace {namespace}")

        is_check_run = (
            entity_configuration["entity_class"] == "agent"
            and len(
                set(check_configuration["subscriptions"]).intersection(
                    set(entity_configuration["subscriptions"])
                )
            )
            > 0
            and "proxy_requests" not in check_configuration
            or create_label(check) in entity_configuration["metadata"]["labels"]
        )

        if not is_check_run:
            raise SensuException(
                f"No event with entity {entity} and check {check} in namespace {namespace}"
            )

        list_command = []
        tmp = ""
        for c in check_configuration["command"]:
            if c == "{" or c == "}":
                list_command.append(tmp)
                tmp = ""

            else:
                tmp += c
        if tmp:
            list_command.append(tmp.strip())

        list_command = [element.strip() for element in list_command]

        while "" in list_command:
            list_command.remove("")

        command = []
        for element in list_command:
            if element.startswith(".labels"):
                key = element[8:]
                if "|" in key:
                    def_val = key.split("|")[1].split("default")[1].strip().replace('"', "")
                    key = key.split("|")[0].strip()
                    try:
                        value = entity_configuration["metadata"]["labels"][key]
                    except KeyError:
                        value = def_val
                else:
                    value = entity_configuration["metadata"]["labels"][key]
                command.append(value)

            else:
                command.append(element)

        output_command = " ".join(command)
        command_elements = output_command.split(" ")
        command_elements = [element.strip() for element in command_elements]
        try:
            timeout = int(command_elements[command_elements.index("-t") + 1])

        except ValueError:
            timeout = 900

        return output_command, timeout

    def get_check_subscriptions(self, check, namespace="default"):
        return self._get_check(check=check, namespace=namespace)["subscriptions"]

    def create_silencing_entry(self, check, entity, namespace="default"):
        try:
            self._get_event(entity=entity, check=check, namespace=namespace)

        except SensuException as err:
            raise SensuException(f"{str(err).lstrip('Sensu error: ')}: Silencing entry not created")

        else:
            response = requests.post(
                f"{self.url}/api/core/v2/namespaces/{namespace}/silenced",
                data=json.dumps(
                    {
                        "metadata": {"name": f"entity:{entity}:{check}", "namespace": namespace},
                        "expire_on_resolve": True,
                        "check": check,
                        "subscription": f"entity:{entity}",
                    }
                ),
                headers={"Authorization": f"Key {self.token}", "Content-Type": "application/json"},
            )

            if not response.ok:
                msg = (
                    f"{namespace}: Silencing entry {entity}/{check} create "
                    f"error: {response.status_code} {response.reason}"
                )

                try:
                    msg = f"{msg}: {response.json()['message']}"

                except (ValueError, KeyError, TypeError):
                    pass

                raise SensuException(msg)

    def _get_silenced_entries(self, namespace="default"):
        response = requests.get(
            f"{self.url}/api/core/v2/namespaces/{namespace}/silenced",
            headers={"Authorization": f"Key {self.token}"},
        )

        if not response.ok:
            msg = (
                f"{namespace}: Silenced entries fetch error: "
                f"{response.status_code} {response.reason}"
            )

            try:
                msg = f"{msg}: {response.json()['message']}"

            except (ValueError, KeyError, TypeError):
                pass

            raise SensuException(msg)

        else:
            return response.json()

    def _delete_silenced_entry(self, entity=None, check=None, namespace="default"):
        silenced_entries = self._get_silenced_entries(namespace=namespace)

        if entity:
            silenced_entries = [
                item
                for item in silenced_entries
                if item["metadata"]["name"].startswith(f"entity:{entity}:")
            ]

        if check:
            silenced_entries = [
                item for item in silenced_entries if item["metadata"]["name"].endswith(f":{check}")
            ]

        failed_delete = list()
        for entry in silenced_entries:
            response = requests.delete(
                f"{self.url}/api/core/v2/namespaces/{namespace}"
                f"/silenced/{entry['metadata']['name']}",
                headers={"Authorization": f"Key {self.token}"},
            )

            if not response.ok:
                msg = f"{response.status_code} {response.reason}"

                try:
                    msg = f"{msg}: {response.json()['message']}"

                except (ValueError, KeyError, TypeError):
                    pass

                failed_delete.append(f"{entry['metadata']['name']} ({msg})")

        if len(failed_delete) > 0:
            final_msg = "Silenced"
            if len(failed_delete) == 1:
                word = "entry"

            else:
                word = "entries"

            final_msg = f"{final_msg} {word} {', '.join(failed_delete)} not removed"

            raise SCGWarnException(final_msg)


class MetricOutput:
    def __init__(self, data):
        self.data = data

    def get_service(self):
        return self.data["entity"]["metadata"]["labels"]["service"]

    def get_hostname(self):
        return self.data["entity"]["metadata"]["name"][
            len(self.data["entity"]["metadata"]["labels"]["service"]) + 2 :
        ]

    def get_metric_name(self):
        return self.data["check"]["metadata"]["name"]

    def get_status(self):
        status_code = self.data["check"]["status"]
        if status_code == 0:
            status = "OK"

        elif status_code == 1:
            status = "WARNING"

        elif status_code == 2:
            status = "CRITICAL"

        else:
            status = "UNKNOWN"

        return status

    def _get_output(self):
        return self.data["check"]["output"].replace("\\n", "\n")

    def _get_output_lines(self):
        return self._get_output().split("\n")

    def _get_output_firstline(self):
        return self._get_output_lines()[0]

    def _get_output_firstline_split(self):
        return self._get_output_firstline().split("|")

    def get_message(self):
        output = ""

        all_lines = self._get_output_lines()

        if len(all_lines) > 1:
            other_lines = "\n".join(all_lines[1:]).split("|")
            other_lines = other_lines[0].strip()
            output = other_lines.strip()

        return output

    def get_summary(self):
        return self._get_output_firstline_split()[0].strip()

    def get_perfdata(self):
        firstline = self._get_output_firstline_split()
        perfdata = ""
        if len(firstline) > 1:
            perfdata = firstline[1].strip()

        all_lines = self._get_output_lines()

        if len(all_lines) > 1:
            other_lines = "\n".join(all_lines[1:])
            perfdata2 = other_lines.split("|")

            if len(perfdata2) > 1:
                perfdata2 = perfdata2[1].strip().replace("\n", " ")

                perfdata = f"{perfdata} {perfdata2}"

        return perfdata

    def get_site(self):
        return self.data["entity"]["metadata"]["labels"]["site"]

    def get_ngi(self):
        return self.data["entity"]["metadata"]["labels"]["ngi"]

    def get_tenants(self):
        check_tenants = set(
            [
                item.strip()
                for item in self.data["check"]["metadata"]["labels"]["tenants"].split(",")
            ]
        )
        entity_tenants = set(
            [
                item.strip()
                for item in self.data["entity"]["metadata"]["labels"]["tenants"].split(",")
            ]
        )

        return sorted(list(entity_tenants.intersection(check_tenants)))


class SensuCtl:
    def __init__(self, tenant, namespace):
        self.namespace = namespace
        self.tenant = tenant

    def _get_events(self):
        output = subprocess.check_output(
            ["sensuctl", "event", "list", "--format", "json", "--namespace", self.namespace]
        ).decode("utf-8")
        data = json.loads(output)

        return data

    @staticmethod
    def _format_events(data):
        output_list = list()
        entities = [item["entity"]["metadata"]["name"] for item in data]
        if len(entities) > 0:
            entities_len = len(max(entities, key=len)) + 2
            metrics = [item["check"]["metadata"]["name"] for item in data]
            metric_len = len(max(metrics, key=len)) + 2

        else:
            entities_len = 10
            metric_len = 10

        output_list.append(
            f"{'Entity'.ljust(entities_len)}{'Metric'.ljust(metric_len)}"
            f"{'Status'.ljust(10)}{'Executed'.ljust(21)}Output"
        )
        output_list.append("_" * (entities_len + metric_len + 40))

        for item in data:
            entity = item["entity"]["metadata"]["name"]
            metric = item["check"]["metadata"]["name"]
            status = item["check"]["status"]
            if status == 0:
                status = "OK"

            elif status == 1:
                status = "WARNING"

            elif status == 2:
                status = "CRITICAL"

            else:
                status = "UNKNOWN"

            executed = datetime.datetime.fromtimestamp(item["timestamp"], tz=datetime.timezone.utc)
            metric_output = item["check"]["output"].split("|")[0].strip()
            single_line_output = metric_output.split("\n")[0].split("\\n")[0].strip()

            output_list.append(
                f"{entity.ljust(entities_len)}{metric.ljust(metric_len)}"
                f"{status.ljust(10)}{executed.strftime('%Y-%m-%d %H:%M:%S')}  "
                f"{single_line_output}"
            )

        return output_list

    def get_events(self):
        data = self._get_events()
        tenant_data = [
            item
            for item in data
            if item["entity"]["entity_class"] == "agent"
            or (
                self.tenant
                in [t.strip() for t in item["check"]["metadata"]["labels"]["tenants"].split(",")]
                and self.tenant
                in [t.strip() for t in item["entity"]["metadata"]["labels"]["tenants"].split(",")]
            )
        ]
        return self._format_events(tenant_data)

    @staticmethod
    def _is_servicetype(item, servicetype):
        if item["entity"]["entity_class"] == "agent":
            services = item["entity"]["metadata"]["labels"]["services"].split(",")
            return servicetype in [service.strip() for service in services]

        else:
            try:
                return item["entity"]["metadata"]["labels"]["service"] == servicetype

            except KeyError:
                return False

    def filter_events(self, status=None, service_type=None, agent=False):
        events = self._get_events()

        if agent:
            events = [item for item in events if item["entity"]["entity_class"] == "agent"]

        if status is not None:
            if status == 3:
                events = [item for item in events if item["check"]["status"] >= 3]

            else:
                events = [item for item in events if item["check"]["status"] == status]

        if service_type:
            events = [
                item for item in events if self._is_servicetype(item=item, servicetype=service_type)
            ]

        return self._format_events(events)
