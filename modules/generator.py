import logging
import os
from urllib.parse import urlparse, urlsplit, urlunsplit

from argo_scg.exceptions import GeneratorException

hardcoded_attributes = {
    "NAGIOS_HOST_CERT": "/etc/sensu/certs/hostcert.pem",
    "NAGIOS_HOST_KEY": "/etc/sensu/certs/hostkey.pem",
    "KEYSTORE": "/etc/sensu/certs/keystore.jks",
    "TRUSTSTORE": "/etc/sensu/certs/truststore.ts"
}

HARD_STATE_PIPELINE = {
    "name": "hard_state",
    "type": "Pipeline",
    "api_version": "core/v2"
}


def create_attribute_env(item):
    return item.upper().replace(".", "_").replace("-", "_")


def create_label(item):
    return item.lower().replace(".", "_").replace("-", "_")


def is_attribute_secret(item):
    if item.endswith("_TOKEN") or item.endswith("_LOGIN") or \
            item.endswith("_SALT") or item.endswith("_ID") or \
            item.endswith("_PASSWORD") or item.endswith("_USER") or \
            item.endswith("_SECRET") or item.endswith("_USERNAME") or \
            item.endswith("_CREDENTIALS"):
        return True

    else:
        return False


def generate_adhoc_check(command, subscriptions, namespace="default"):
    return {
        "command": command,
        "subscriptions": subscriptions,
        "handlers": [],
        "interval": 86400,
        "timeout": 900,
        "publish": False,
        "metadata": {
            "name": "adhoc-check",
            "namespace": namespace
        },
        "round_robin": False
    }


class ConfigurationGenerator:
    def __init__(
            self, metrics, metric_profiles, topology, profiles, attributes,
            secrets_file, default_ports, tenant, default_agent,
            skipped_metrics=None, agents_config=None
    ):
        self.logger = logging.getLogger("argo-scg.generator")
        self.tenant = tenant
        self.metric_profiles = [
            p for p in metric_profiles if p["name"] in profiles
        ]
        metrics_in_profiles_set = set()
        for profile in self.metric_profiles:
            for service in profile["services"]:
                for metric in service["metrics"]:
                    metrics_in_profiles_set.add(metric)

        if not skipped_metrics:
            self.skipped_metrics = []

        else:
            self.skipped_metrics = skipped_metrics

        self.global_attributes = self._read_global_attributes(attributes)
        self.servicetypes = self._get_servicetypes()

        self.non_fallback_urls = ["ARGO_WEBDAV_OPS_URL", "ARGO_XROOTD_OPS_URL"]

        self.hostalias_var = "$HOSTALIAS$"
        self.servicesite_name_var = "$_SERVICESITE_NAME$"
        self.servicevo_fqan_var = "$_SERVICEVO_FQAN$"

        self.agents_config = agents_config
        sorted_agents = sorted(default_agent)

        if len(default_agent) > 1 and not agents_config:
            self.logger.warning(
                f"{tenant}: Multiple agents defined for tenant - using "
                f"{sorted_agents[0]} for checks' configuration"
            )

        self.subscriptions = [f"entity:{sorted_agents[0]}"]

        metrics_list = list()
        internal_metrics = list()
        metrics_with_endpoint_url = dict()
        list_metrics_with_endpoint_url = list()
        metrics_with_ports = list()
        metrics_with_path = list()
        metrics_with_ssl = list()
        metrics_with_url = dict()
        metrics_names_set = set()
        metrics_with_hostalias = list()
        metrics_with_servicesite_name = list()
        metrics_with_non_fallback_urls = dict()
        metrics_with_site_bdii = dict()
        for metric in metrics:
            for key, value in metric.items():
                metrics_names_set.add(key)
                if key in metrics_in_profiles_set:
                    metrics_list.append(metric)

                    if "PORT" in value["attribute"]:
                        metrics_with_ports.append({
                            "metric": key,
                            "attr_val": value["attribute"]["PORT"]
                        })

                    if "PATH" in value["attribute"]:
                        metrics_with_path.append({
                            "metric": key,
                            "attr_val": value["attribute"]["PATH"]
                        })

                    if "SSL" in value["attribute"]:
                        metrics_with_ssl.append(key)

                    if "internal" in value["tags"]:
                        internal_metrics.append(key)

                    for attribute, attr_val in value["attribute"].items():
                        if attribute == "URL":
                            list_metrics_with_endpoint_url.append(key)
                            metrics_with_endpoint_url.update({
                                key: {
                                    "attribute": attribute,
                                    "value": attr_val
                                }
                            })

                        if attribute == "SITE_BDII":
                            label = create_label(
                                attr_val.lstrip("-").lstrip("-")
                            )
                            metrics_with_site_bdii.update({
                                key: {
                                    "label": f"{label}__site_bdii",
                                    "value": attr_val
                                }
                            })

                        if attribute in self.non_fallback_urls:
                            metrics_with_non_fallback_urls.update({
                                key: {
                                    "attribute": attribute,
                                    "value": attr_val
                                }
                            })

                        elif attribute.endswith("_URL") and not (
                                attribute.endswith("GOCDB_SERVICE_URL")
                        ):
                            metrics_with_url.update({key: attribute})

                    for param, param_value in value["parameter"].items():
                        if self.hostalias_var in param_value:
                            metrics_with_hostalias.append({
                                "metric": key,
                                "parameter": param,
                                "label": self._create_metric_parameter_label(
                                    key, param
                                ),
                                "value": param_value
                            })

                        if self.servicesite_name_var in param_value:
                            metrics_with_servicesite_name.append({
                                "metric": key,
                                "parameter": param,
                                "label": self._create_metric_parameter_label(
                                    key, param
                                ),
                                "value": param_value
                            })

        self.metrics = metrics_list
        self.metrics_without_configuration = metrics_in_profiles_set.difference(
            metrics_names_set
        )
        self.metrics_with_hostalias = metrics_with_hostalias
        self.metrics_with_servicesite_name = metrics_with_servicesite_name
        self.metrics_with_endpoint_url = metrics_with_endpoint_url
        self.metrics_with_non_fallback_urls = metrics_with_non_fallback_urls
        self.metrics_with_site_bdii = metrics_with_site_bdii
        self.internal_metrics = internal_metrics
        self.topology = topology
        self.secrets = secrets_file
        self.default_ports = default_ports

        self.metric_parameter_overrides = self._read_metric_parameter_overrides(
            attributes
        )
        self.metrics_with_parameter_overrides = [
            metric["metric"] for metric in self.metric_parameter_overrides
        ]
        self.host_attribute_overrides = self._read_host_attribute_overrides(
            attributes
        )
        self.servicetypes4metrics = self._get_servicetypes4metrics()
        self.metrics4servicetypes = self._get_metrics4servicetypes()
        self.extensions = self._get_extensions()
        self.extensions4metrics = self._get_extensions4metrics()

        self.servicetypes_with_endpointURL = list()
        for metric in list_metrics_with_endpoint_url:
            self.servicetypes_with_endpointURL.extend(
                self.servicetypes4metrics[metric]
            )

        self.servicetypes_with_port = list()
        for metric in metrics_with_ports:
            sts = self.servicetypes4metrics[metric["metric"]]
            for st in sts:
                self.servicetypes_with_port.append({
                    "service": st,
                    "metric": metric["metric"],
                    "attr_val": metric["attr_val"]
                })

        self.servicetypes_with_path = list()
        for metric in metrics_with_path:
            sts = self.servicetypes4metrics[metric["metric"]]
            for st in sts:
                self.servicetypes_with_path.append({
                    "service": st,
                    "metric": metric["metric"],
                    "attr_val": metric["attr_val"]
                })

        self.servicetypes_with_SSL = list()
        for metric in metrics_with_ssl:
            self.servicetypes_with_SSL.extend(
                self.servicetypes4metrics[metric]
            )

        self.servicetypes_with_url = dict()
        for metric, attribute in metrics_with_url.items():
            sts = self.servicetypes4metrics[metric]
            for st in sts:
                if st in self.servicetypes_with_url:
                    att = self.servicetypes_with_url[st]
                    att.append(attribute)
                    self.servicetypes_with_url.update({st: list(set(att))})

                else:
                    self.servicetypes_with_url.update({st: [attribute]})

        self.servicetypes_with_site_bdii = list()
        for metric in self.metrics_with_site_bdii.keys():
            self.servicetypes_with_site_bdii.extend(
                self.servicetypes4metrics[metric]
            )

    @staticmethod
    def _read_global_attributes(input_attrs):
        attrs = dict()

        for file, keys in input_attrs.items():
            for item in keys["global_attributes"]:
                attrs.update({item["attribute"]: item["value"]})

        return attrs

    def _read_metric_parameter_overrides(self, input_attrs):
        metric_parameter_overrides = list()

        for file, keys in input_attrs.items():
            for item in keys["metric_parameters"]:
                metric_parameter_overrides.append({
                    "metric": item["metric"],
                    "hostname": item["hostname"],
                    "parameter": item["parameter"],
                    "label": self._create_metric_parameter_label(
                        item["metric"], item["parameter"]
                    ),
                    "value": item["value"]
                })

        return metric_parameter_overrides

    def _read_host_attribute_overrides(self, input_attrs):
        host_attribute_overrides = list()

        for files, keys in input_attrs.items():
            for item in keys["host_attributes"]:
                host_attribute_overrides.append({
                    "hostname": item["hostname"],
                    "attribute": item["attribute"],
                    "label": create_label(item["attribute"]),
                    "value": item["value"],
                    "metrics": self._get_metrics4attribute(item["attribute"])
                })

        return host_attribute_overrides

    def get_metric_parameter_overrides(self):
        return self.metric_parameter_overrides

    def get_host_attribute_overrides(self):
        return self.host_attribute_overrides

    def _get_single_endpoint_url(self, url):
        if "," in url:
            url = url.split(",")[0].strip()

        return self._handle_endpoint_url(url)

    def _get_metrics4attribute(self, attribute):
        metrics_with_attribute = list()
        for metric in self.metrics:
            for name, config in metric.items():
                if attribute in config["attribute"]:
                    metrics_with_attribute.append(name)

        return metrics_with_attribute

    @staticmethod
    def _create_metric_parameter_label(metric, parameter):
        return f"{create_label(metric)}_" \
               f"{parameter.strip('-').strip('-').replace('-', '_')}"

    def _is_extension_present_all_endpoints(self, services, extension):
        is_present = True
        endpoints = [
            endpoint for endpoint in self.topology
            if endpoint["service"] in services
        ]

        for endpoint in endpoints:
            if extension not in endpoint["tags"]:
                is_present = False
                break

        return is_present

    def _is_extension_present_any_endpoint(self, services, extension):
        is_present = False
        endpoints = [
            endpoint for endpoint in self.topology if
            endpoint["service"] in services
        ]

        for endpoint in endpoints:
            if extension in endpoint["tags"]:
                is_present = True
                break

        return is_present

    def _is_attribute_overridden_all_endpoints(self, attribute):
        hostnames4metric = self._get_hostnames4metrics()
        hostnames_with_overridden_attributes = set()
        hostnames_with_metrics = set()
        for item in self.host_attribute_overrides:
            if item["attribute"] == attribute:
                hostnames_with_overridden_attributes.add(item["hostname"])
                for metric in item["metrics"]:
                    hostnames_with_metrics.update(set(hostnames4metric[metric]))

        return len(set(hostnames_with_metrics).difference(
            set(hostnames_with_overridden_attributes)
        )) == 0

    def _is_parameter_default(self, metric_name, parameter):
        is_default = False

        for metric in self.metrics:
            for name, configuration in metric.items():
                if name == metric_name:
                    if parameter not in configuration["parameter"]:
                        is_default = True

                    break

        return is_default

    def _get_servicetypes4metrics(self):
        service_types = dict()
        for mp in self.metric_profiles:
            for service in mp["services"]:
                for metric in service["metrics"]:
                    if metric not in service_types:
                        service_types.update({metric: [service["service"]]})

                    else:
                        service_type = service_types[metric]
                        service_type.append(service["service"])
                        service_types.update({metric: service_type})

        return service_types

    def _get_metrics4servicetypes(self):
        metrics = dict()
        for mp in self.metric_profiles:
            for service in mp["services"]:
                servicetype = service["service"]
                if servicetype in metrics:
                    service_metrics = metrics[servicetype]
                    service_metrics += service["metrics"]

                else:
                    metrics.update({service["service"]: service["metrics"]})

        return metrics

    def _get_hostname(self, item):
        if "hostname" in item["tags"]:
            return item["tags"]["hostname"]

        else:
            return item["hostname"]

    def _get_hostnames4metrics(self):
        hostnames4metrics = dict()
        for metric, servicetypes in self.servicetypes4metrics.items():
            hostnames = list()
            for servicetype in servicetypes:
                hostnames.extend([
                    self._get_hostname(item) for item in self.topology
                    if item["service"] == servicetype
                ])

            hostnames = sorted(list(set(hostnames)))
            hostnames4metrics.update({metric: hostnames})

        return hostnames4metrics

    def _get_entities4metrics(self):
        entities4metrics = dict()
        for metric, servicetypes in self.servicetypes4metrics.items():
            entities = list()
            for servicetype in servicetypes:
                entities.extend([
                    f"{servicetype}__{item['hostname']}"
                    for item in self.topology if
                    item["service"] == servicetype
                ])

            entities = sorted(list(set(entities)))
            entities4metrics.update({metric: entities})

        return entities4metrics

    def _get_hostnames4servicetypes(self):
        hostnames4servicetypes = dict()

        for servicetype in self.servicetypes:
            hostnames = [
                self._get_hostname(item) for item in self.topology
                if item["service"] == servicetype
            ]

            hostnames4servicetypes.update({
                servicetype: sorted(list(set(hostnames)))
            })

        return hostnames4servicetypes

    def _get_entities4servicetypes(self):
        entities4servicetypes = dict()

        for servicetype in self.servicetypes:
            entities = [
                f"{servicetype}__{item['hostname']}" for item in self.topology
                if item["service"] == servicetype
            ]

            entities4servicetypes.update({
                servicetype: sorted(list(set(entities)))
            })

        return entities4servicetypes

    def _get_extensions(self):
        extensions = set()
        for item in self.topology:
            for tag, value in item["tags"].items():
                if tag.startswith("info_ext_"):
                    extensions.add(tag[9:])

        return list(extensions)

    def _get_extensions4metrics(self):
        ext_dict = dict()
        for metric in self.metrics:
            for name, configuration in metric.items():
                for attribute, value in configuration["attribute"].items():
                    if attribute in self.extensions:
                        if attribute not in ext_dict:
                            ext_dict.update({attribute: [name]})

                        else:
                            metrics = ext_dict[attribute]
                            metrics.append(name)
                            ext_dict.update({attribute: metrics})

        return ext_dict

    def _get_attributes4metrics(self):
        attributes = dict()
        for metric in self.metrics:
            for name, configuration in metric.items():
                for attribute, value in configuration["attribute"].items():
                    if attribute in [
                        o["attribute"] for o in self.host_attribute_overrides
                    ]:
                        if attribute not in attributes:
                            attributes.update({
                                attribute: [{
                                    "metric": name,
                                    "value": value
                                }]
                            })

                        else:
                            tmp = attributes[attribute]
                            tmp.append({
                                "metric": name,
                                "value": value
                            })
                            attributes.update({attribute: tmp})

        return attributes

    def _handle_attributes(self, metric, attrs):
        attributes = ""
        issecret = False
        overridden_attributes = [
            item["attribute"] for item in self.host_attribute_overrides
        ]
        overridden_parameters = [
            item["parameter"] for item in self.metric_parameter_overrides
            if item["metric"] == metric
        ]
        special_attributes = ["BDII_DN", "GLUE2_BDII_DN"]

        port_override = False
        path_override = False
        for key, value in attrs.items():
            if value not in overridden_parameters:
                if key == "NAGIOS_HOST_CERT":
                    if "ROBOT_CERT" in self.global_attributes:
                        key = self.global_attributes["ROBOT_CERT"]

                    else:
                        if key in self.global_attributes:
                            key = self.global_attributes[key]

                        else:
                            key = hardcoded_attributes[key]

                elif key == "NAGIOS_HOST_KEY":
                    if "ROBOT_KEY" in self.global_attributes:
                        key = self.global_attributes["ROBOT_KEY"]

                    else:
                        if key in self.global_attributes:
                            key = self.global_attributes[key]

                        else:
                            key = hardcoded_attributes[key]

                elif key == "NAGIOS_ACTUAL_HOST_CERT":
                    if "NAGIOS_HOST_CERT" in self.global_attributes:
                        key = self.global_attributes["NAGIOS_HOST_CERT"]

                    else:
                        key = hardcoded_attributes["NAGIOS_HOST_CERT"]

                elif key == "NAGIOS_ACTUAL_HOST_KEY":
                    if "NAGIOS_HOST_KEY" in self.global_attributes:
                        key = self.global_attributes["NAGIOS_HOST_KEY"]

                    else:
                        key = hardcoded_attributes["NAGIOS_HOST_KEY"]

                elif key in self.global_attributes:
                    if key in overridden_attributes:
                        key = "{{ .labels.%s | default \"%s\" }}" % (
                            create_label(key.lower()),
                            self.global_attributes[key]
                        )

                    else:
                        key = self.global_attributes[key]

                elif is_attribute_secret(key):
                    if key in overridden_attributes:
                        key = "{{ .labels.%s }}" % create_label(key)

                    else:
                        if "." in key:
                            key = key.upper().replace(".", "_")

                        key = f"${key}"

                    issecret = True

                else:
                    if key in ["KEYSTORE", "TRUSTSTORE"]:
                        key = hardcoded_attributes[key]

                    elif key == "TOP_BDII":
                        if "BDII_HOST" in self.global_attributes:
                            key = self.global_attributes["BDII_HOST"]
                        else:
                            key = ""

                    elif key == "SITE_BDII":
                        key = "{{ .labels.%s | default \"\" }}" % (
                            self.metrics_with_site_bdii[metric]["label"]
                        )
                        value = ""

                    elif key in self.default_ports:
                        if self._is_extension_present_any_endpoint(
                                services=self.servicetypes4metrics[metric],
                                extension=f"info_ext_{key}"
                        ) or self._is_extension_present_any_endpoint(
                            services=self.servicetypes4metrics[metric],
                            extension=f"info_bdii_{key}"
                        ) or key in overridden_attributes:
                            key = "{{ .labels.%s | default \"%s\" }}" % (
                                create_label(key.lower()),
                                self.default_ports[key]
                            )

                        else:
                            key = self.default_ports[key]

                    elif key == "SSL":
                        key = "{{ .labels.ssl | default \" \" }}"
                        value = ""

                    elif key == "PATH" and not path_override:
                        key = "{{ .labels.%s_path | default \" \" }}" % (
                            create_label(metric)
                        )
                        value = ""

                    elif key == "PORT" and not port_override:
                        key = "{{ .labels.%s_port | default \" \" }}" % (
                            create_label(metric)
                        )
                        value = ""

                    elif key.endswith("GOCDB_SERVICE_URL"):
                        key = "{{ .labels.info_url }}"

                    elif key == "URL":
                        key = "{{ .labels.endpoint_url }}"

                    elif key == "SITENAME":
                        key = "{{ .labels.site }}"

                    elif key == "HOSTDN":
                        key = "{{ .labels.info_hostdn }}"

                    elif key in self.extensions:
                        if self._is_extension_present_all_endpoints(
                            services=self.servicetypes4metrics[metric],
                            extension=f"info_ext_{key}"
                        ) or (
                                key.endswith("_URL") and
                                key not in self.non_fallback_urls
                        ):
                            if (key.endswith("PATH")) and not path_override:
                                path_override = True

                                key = "{{ .labels.%s_path | default \" \" }}" % (
                                create_label(metric)
                                )
                                value = ""
                            elif (key.endswith("PORT")):
                                port_override = True

                                key = "{{ .labels.%s_port | default \" \" }}" % (
                                create_label(metric)
                                )
                                value = ""
                            else:
                                key = "{{ .labels.%s }}" % create_label(key.lower())

                        else:
                            key = "{{ .labels.%s__%s | default \"\" }}" % (
                                create_label(value.lstrip("-").lstrip("-")),
                                create_label(key)
                            )
                            value = ""

                    elif key == "OS_KEYSTONE_PORT":
                        key = "{{ .labels.%s | default \"443\" }}" \
                              % create_label(key)

                    elif key in overridden_attributes:
                        if self._is_attribute_overridden_all_endpoints(
                                attribute=key
                        ):
                            key = "{{ .labels.%s }}" % create_label(key.lower())

                        else:
                            key = "{{ .labels.%s__%s | default \"\" }}" % (
                                create_label(value.lstrip("-").lstrip("-")),
                                create_label(key)
                            )
                            value = ""

                    elif (
                            key.startswith("OS_KEYSTONE_") or
                            key.endswith("_URL") or
                            key in overridden_attributes or
                            key in special_attributes
                    ):
                        key = "{{ .labels.%s }}" % create_label(key.lower())

                    else:
                        key = ""

                if key:
                    attr = f"{value} {key}".strip()

                else:
                    attr = ""

                attributes = f"{attributes} {attr}".strip()

        return attributes, issecret

    def _is_hostalias_present(self, value):
        return self.hostalias_var in value

    def _is_servicesite_name_present(self, value):
        return self.servicesite_name_var in value

    def _is_servicevo_fqan_present(self, value):
        return self.servicevo_fqan_var in value

    def _create_hostalias_value(self, value, hostname):
        return value.replace(self.hostalias_var, hostname)

    def _create_servicesite_name_value(self, value, site):
        return value.replace(self.servicesite_name_var, site)

    def _create_servicevo_fqan_value(self, value):
        if "VO_FQAN" in self.global_attributes:
            vo_fqan = self.global_attributes["VO_FQAN"]

        else:
            vo_fqan = self.global_attributes["VONAME"]

        return value.replace(self.servicevo_fqan_var, vo_fqan)

    @staticmethod
    def _is_passive(configuration):
        return "PASSIVE" in configuration["flags"]

    def _generate_active_check(
            self, name, configuration, publish, namespace="default"
    ):
        parameter_overrides = [
            item for item in self.metric_parameter_overrides
            if item["metric"] == name
        ]
        try:
            path = configuration["config"]["path"]
            if path.endswith("/"):
                path = path[:-1]

            executable = os.path.join(path, configuration["probe"])

            if "NOTIMEOUT" not in configuration["flags"]:
                parameters = "-t " + configuration["config"]["timeout"]

            else:
                parameters = ""

            if "NOHOSTNAME" not in configuration["flags"]:
                parameters = "-H {{ .labels.hostname }} " + parameters
                parameters = parameters.strip()

            for key, value in configuration["parameter"].items():
                if value == "$_SERVICEVO$":
                    if "VONAME" in self.global_attributes:
                        value = self.global_attributes["VONAME"]

                    else:
                        continue

                elif self._is_servicevo_fqan_present(value):
                    try:
                        value = self._create_servicevo_fqan_value(value)

                    except KeyError:
                        self.logger.warning(
                            f"{self.tenant}: Skipping check {name}: "
                            f"VONAME not defined"
                        )

                        return None

                elif (
                        self._is_hostalias_present(value) or
                        self._is_servicesite_name_present(value)
                ):
                    value = "{{ .labels.%s }}" % (
                        self._create_metric_parameter_label(name, key)
                    )

                else:
                    p = [
                        item for item in parameter_overrides
                        if item["parameter"] == key
                    ]
                    if len(p) > 0:
                        value = "{{ .labels.%s | default \"%s\" }}" % (
                            p[0]["label"], value
                        )

                param = f"{key} {value}".strip()
                parameters = f"{parameters} {param}".strip()

            used_default_params = list()
            if len(parameter_overrides) > 0:
                for o in parameter_overrides:
                    if (
                            self._is_parameter_default(
                                name, o["parameter"]
                            ) and o["label"] not in used_default_params
                    ):
                        param = "{{ .labels.%s }}" % o["label"]
                        used_default_params.append(o["label"])
                        parameters = f"{parameters} {param}"

            attributes, issecret = self._handle_attributes(
                metric=name,
                attrs=configuration["attribute"]
            )

            command = "{} {} {}".format(
                executable, parameters.strip(), attributes.lstrip()
            )

            if issecret:
                command = f"source {self.secrets} ; " \
                          f"export $(cut -d= -f1 {self.secrets}) ; " \
                          f"{command}"

            check = {
                "command": command.strip(),
                "subscriptions": self._get_subscription(name),
                "handlers": [],
                "interval": int(configuration["config"]["interval"]) * 60,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "annotations": {
                        "attempts": configuration["config"]["maxCheckAttempts"]
                    },
                    "labels": {
                        "tenants": self.tenant
                    }
                },
                "round_robin": False
            }

            if (
                    publish and "NOPUBLISH" not in configuration["flags"] and
                    "SILENCED" not in configuration["flags"]
            ):
                check.update({
                    "pipelines": [HARD_STATE_PIPELINE]
                })

            elif (
                    (not publish or "internal" in configuration["tags"]) and
                    "SILENCED" not in configuration["flags"]
            ):
                check.update({
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                })

            else:
                check.update({"pipelines": []})

            if namespace != "default" and \
                    "internal" not in configuration["tags"]:
                check.update({
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.{} == '{}'".format(
                                name.lower().replace(".", "_").replace(
                                    "-", "_"
                                ), name
                            )
                        ]
                    }
                })

            return check

        except KeyError as e:
            self.logger.warning(
                f"{self.tenant}: Skipping check {name}: "
                f"Missing key {str(e)}"
            )

            return None

    def _get_subscription(self, metric):
        subscription = self.subscriptions
        if self.agents_config:
            for agent, servicetypes in self.agents_config.items():
                if set(self.servicetypes4metrics[metric]).intersection(
                        set(servicetypes)
                ):
                    subscription = [f"entity:{agent}"]
                    break

        return subscription

    def generate_checks(self, publish, namespace="default"):
        checks = list()

        for metric in self.metrics:
            for name, configuration in metric.items():
                if name not in self.skipped_metrics:
                    if self._is_passive(configuration=configuration):
                        try:
                            attempts = [
                                item for item in self.metrics if
                                configuration["parent"] in item
                            ][0][configuration["parent"]]["config"][
                                "maxCheckAttempts"
                            ]
                            check = {
                                "command": "PASSIVE",
                                "subscriptions": self._get_subscription(metric),
                                "handlers": [],
                                "pipelines": [HARD_STATE_PIPELINE],
                                "cron": "CRON_TZ=Europe/Zagreb 0 0 31 2 *",
                                "timeout": 900,
                                "publish": False,
                                "metadata": {
                                    "name": name,
                                    "namespace": namespace,
                                    "annotations": {"attempts": attempts},
                                    "labels": {"tenants": self.tenant}
                                },
                                "round_robin": False
                            }

                        except IndexError:
                            self.logger.warning(
                                f"{self.tenant}: Skipping check generation for "
                                f"{name} - missing parent"
                            )
                            continue

                    else:
                        check = self._generate_active_check(
                            name=name, configuration=configuration,
                            publish=publish, namespace=namespace
                        )

                    if check:
                        checks.append(check)

        for metric in self.metrics_without_configuration:
            self.logger.warning(
                f"{self.tenant}: Missing metric configuration for {metric}... "
                f"Skipping check generation"
            )

        return checks

    def _get_servicetypes(self):
        service_types = set()
        for mp in self.metric_profiles:
            for service in mp["services"]:
                if len(
                        set(service["metrics"]).difference(self.skipped_metrics)
                ) > 0:
                    service_types.add(service["service"])

        return service_types

    @staticmethod
    def _handle_endpoint_url(url):
        if "&" in url:
            url = f"\"{url}\""
        
        return url
    
    @staticmethod
    def _are_any_url_ext_tags_defined(entity):
        return ("info_ext_SSL" in entity["tags"]
                or "info_ext_PORT" in entity["tags"]
                or "info_ext_PATH" in entity["tags"])

    @staticmethod
    def _get_url(entity, hostname):
        url = ""
        if "info_URL" in entity["tags"]:
            url = entity["tags"]["info_URL"]

            if ConfigurationGenerator._are_any_url_ext_tags_defined(entity):
                split_url = urlsplit(url)

                if "info_ext_SSL" in entity["tags"]:
                    try:
                        use_ssl = int(entity["tags"]["info_ext_SSL"])
                        new_scheme = "https" if use_ssl else "http"
                        split_url = split_url._replace(scheme=new_scheme)
                    except:
                        logging.warning(
                            "Unable to convert info_ext_SSL to int. \
                            Using default value in info_URL.")
                
                if "info_ext_PORT" in entity["tags"]:
                    try:
                        new_port = entity["tags"]["info_ext_PORT"]

                        netloc = split_url.netloc
                        if ":" in netloc and not netloc.count(":") > 1:
                            host = netloc.rsplit(":", 1)[0]
                        else:
                            host = netloc
                        
                        split_url = split_url._replace(netloc=f"{host}:{new_port}")
                    except:
                        logging.warning(
                            "Unable to parse info_ext_PORT. \
                            Using default value in info_URL.")
                    
                
                if "info_ext_PATH" in entity["tags"]:
                    try:
                        new_path = entity["tags"]["info_ext_PATH"]
                        if len(new_path) > 0 and new_path[0] == '/':
                            new_path = new_path[1:]
                        
                        split_url = split_url._replace(path=f"/{new_path}")
                    except:
                        logging.warning(
                            "Unable to parse info_ext_PATH. \
                            Using default value in info_URL.")
                
                url = urlunsplit(split_url)

        else:
            if ConfigurationGenerator._are_any_url_ext_tags_defined(entity):
                if "info_ext_SSL" in entity["tags"]:
                    use_ssl = entity["tags"]["info_ext_SSL"]
                    if use_ssl:
                        url += "https://"
                
                url += hostname

                if "info_ext_PORT" in entity["tags"]:
                    port = entity["tags"]["info_ext_PORT"]
                    url += f":{port}"
                
                if "info_ext_PATH" in entity["tags"]:
                    path = entity["tags"]["info_ext_PATH"]
                    if len(path) > 0 and path[0] == '/':
                        path = path[1:]
                    
                    url += f"/{path}"

        return url

    def generate_entities(self, namespace="default"):
        try:
            entities = list()
            topo_entities = [
                item for item in self.topology if
                item["service"] in self.servicetypes
            ]
            attributes4metrics = self._get_attributes4metrics()

            skipped_entities = list()
            for item in topo_entities:
                types = list()
                entity_name = f"{item['service']}__{item['hostname']}"

                if "hostname" in item["tags"]:
                    hostname = item["tags"]["hostname"]

                else:
                    hostname = item["hostname"]

                labels = {"hostname": hostname}

                if ("info_URL" in item["tags"]
                    or self._are_any_url_ext_tags_defined(item)):
                    url = self._get_url(item, hostname)

                    servicetypes_with_path = [
                        st for st in self.servicetypes_with_path if
                        item["service"] == st["service"]
                    ]
                    servicetypes_with_port = [
                        st for st in self.servicetypes_with_port if
                        item["service"] == st["service"]
                    ]
                    
                    if "info_URL" in item["tags"]:
                        labels.update({
                            "info_url": self._handle_endpoint_url(
                                url
                            )
                        })
                    
                    o = urlparse(url)
                    port = o.port

                    if item["service"] in self.servicetypes_with_SSL:                        
                        if (o.scheme == "https" 
                            or "info_ext_SSL" in item["tags"]
                        ):
                            labels.update({"ssl": "-S --sni"})
                    path = o.path
                    if path:
                        if o.query:
                            path = f"{path}?{o.query}"
                        for entry in servicetypes_with_path:
                            lbl = f"{create_label(entry['metric'])}_path"
                            val = f"{entry['attr_val']} {path}"
                            labels.update({lbl: val})
                    
                    if port:
                        for entry in servicetypes_with_port:
                            lbl = f"{create_label(entry['metric'])}_port"
                            val = f"{entry['attr_val']} {str(port)}"
                            labels.update({lbl: val})

                    if item["service"] in [
                        "org.openstack.nova", "org.openstack.swift"
                    ]:
                        if port:
                            labels.update({"os_keystone_port": str(port)})

                        labels.update({"os_keystone_host": o.hostname})
                        labels.update({
                            "os_keystone_url": self._handle_endpoint_url(
                                url
                            )
                        })

                missing_metrics_endpoint_url = list()
                if "info_service_endpoint_URL" in item["tags"]:
                    labels.update({
                        "endpoint_url":
                            self._get_single_endpoint_url(
                                item["tags"]["info_service_endpoint_URL"]
                            )
                    })

                else:
                    if item["service"] in self.servicetypes_with_endpointURL:
                        if ("info_URL" not in item["tags"]
                            and not self._are_any_url_ext_tags_defined(item)):
                            metrics_with_endpoint_url = \
                                self.metrics_with_endpoint_url.keys()
                            url_metrics = list(set(
                                self.metrics4servicetypes[item["service"]]
                            ).intersection(
                                set(metrics_with_endpoint_url)
                            ))

                            for metric in url_metrics:
                                parameter_overrides = [
                                    o["parameter"] for o in
                                    self.metric_parameter_overrides if
                                    o["metric"] == metric and
                                    o["hostname"] in [
                                        item["hostname"], entity_name
                                    ]
                                ]
                                attr_overrides = [
                                    o["attribute"] for o in
                                    self.host_attribute_overrides if
                                    o["hostname"] in [
                                        item["hostname"], entity_name
                                    ]
                                ]
                                if self.metrics_with_endpoint_url[metric][
                                    "value"
                                ] not in parameter_overrides and \
                                        "URL" not in attr_overrides:
                                    missing_metrics_endpoint_url.append(metric)

                            if len(missing_metrics_endpoint_url) > 0:
                                self.logger.warning(
                                    f"{self.tenant}: Entity {entity_name} "
                                    f"missing URL"
                                )

                        else:
                            labels.update({
                                "endpoint_url": self._handle_endpoint_url(
                                    self._get_url(item, hostname)
                                )
                            })

                if item["service"] in self.servicetypes_with_url:
                    for attr in self.servicetypes_with_url[item["service"]]:
                        if "info_service_endpoint_URL" in item["tags"]:
                            labels.update({
                                create_label(attr):
                                    self._get_single_endpoint_url(
                                        item["tags"][
                                            "info_service_endpoint_URL"
                                        ]
                                    )
                            })

                        elif ("info_URL" in item["tags"]
                            or self._are_any_url_ext_tags_defined(item)):
                            labels.update({
                                create_label(attr):
                                    self._handle_endpoint_url(
                                        self._get_url(item, hostname)
                                    )
                            })

                        else:
                            pass

                if item["service"] == "Top-BDII":
                    labels.update({"bdii_dn": "Mds-Vo-Name=local,O=Grid"})
                    labels.update({"bdii_type": "bdii_top"})
                    labels.update({
                        "glue2_bdii_dn":
                            "GLUE2DomainID=%s,o=glue" % item["group"]
                    })

                if item["service"] == "Site-BDII":
                    labels.update({
                        "bdii_dn": "Mds-Vo-Name=%s,O=Grid" % item["group"]
                    })
                    labels.update({"bdii_type": "bdii_site"})
                    labels.update({
                        "glue2_bdii_dn":
                            "GLUE2DomainID=%s,o=glue" % item["group"]
                    })

                if "info_HOSTDN" in item["tags"]:
                    labels.update({"info_hostdn": item["tags"]["info_HOSTDN"]})

                types.append(item["service"])

                metrics4servicetype = self.metrics4servicetypes[item["service"]]

                attribute_overrides = [
                    o for o in self.host_attribute_overrides
                    if len(
                        set(o["metrics"]).intersection(
                            set(metrics4servicetype)
                        )
                    ) > 0
                ]

                host_attribute_overrides = [
                    o for o in attribute_overrides
                    if o["hostname"] in [item["hostname"], entity_name]
                ]

                non_fallback_urls_created = list()
                for metric in metrics4servicetype:
                    metric_parameter_overrides = [
                        o for o in self.metric_parameter_overrides
                        if o["metric"] == metric
                    ]

                    hostaliases = [
                        ha for ha in self.metrics_with_hostalias
                        if ha["metric"] == metric
                    ]

                    servicesite_metrics = [
                        ss for ss in self.metrics_with_servicesite_name
                        if ss["metric"] == metric
                    ]

                    if metric in self.metrics_with_non_fallback_urls:
                        metric_attribute = \
                            self.metrics_with_non_fallback_urls[metric]
                        non_fallback_urls_created.append(
                            metric_attribute["attribute"]
                        )
                        key_prefix = create_label(
                            metric_attribute["value"].strip("-").strip("-")
                        )
                        key_suffix = create_label(
                            metric_attribute["attribute"]
                        )
                        value = ""
                        if (f"info_ext_{metric_attribute['attribute']}"
                                in item["tags"]):
                            ext_value = item["tags"][
                                f"info_ext_{metric_attribute['attribute']}"
                            ]
                            value = f"{metric_attribute['value']} {ext_value}"

                        overridden_attribute = [
                            a for a in host_attribute_overrides
                            if a["attribute"] == metric_attribute[
                                "attribute"
                            ]
                        ]

                        if len(overridden_attribute) > 0:
                            value = \
                                f"{metric_attribute['value']} "\
                                f"{overridden_attribute[-1]['value']}"

                        labels.update({f"{key_prefix}__{key_suffix}": value})

                    if metric not in self.internal_metrics:
                        key = create_label(metric)

                        if key not in labels and \
                                metric not in missing_metrics_endpoint_url and \
                                metric not in self.skipped_metrics:
                            labels.update({key: metric})

                    for o in metric_parameter_overrides:
                        if self._is_parameter_default(metric, o["parameter"]):
                            label = o["label"]
                            if o["hostname"] in [item["hostname"], entity_name]:
                                labels.update({
                                    label: "%s %s" % (
                                        o["parameter"], o["value"]
                                    )
                                })
                                break

                            else:
                                labels.update({label: ""})

                        else:
                            if o["hostname"] in [item["hostname"], entity_name]:
                                value = o["value"]
                                if self._is_hostalias_present(o["value"]):
                                    value = self._create_hostalias_value(
                                        o["value"], hostname
                                    )

                                if self._is_servicesite_name_present(
                                        o["value"]
                                ):
                                    value = (
                                        self._create_servicesite_name_value(
                                            o["value"], item["group"]
                                        ))

                                labels.update({o["label"]: value})

                    host_metric_parameter_overrides = [
                        o for o in metric_parameter_overrides if
                        o["hostname"] in [item["hostname"], entity_name]
                    ]

                    if len(host_metric_parameter_overrides) == 0:
                        for ha in hostaliases:
                            label = ha["label"]
                            value = self._create_hostalias_value(
                                ha["value"], hostname
                            )
                            labels.update({label: value})

                        for ss in servicesite_metrics:
                            label = ss["label"]
                            value = self._create_servicesite_name_value(
                                ss["value"], item["group"]
                            )
                            labels.update({label: value})

                if len(attribute_overrides) > 0:
                    overriding_attributes = set(
                        [o["attribute"] for o in attribute_overrides]
                    ).difference(set([
                            o["attribute"] for o in host_attribute_overrides
                    ]))

                    for o in host_attribute_overrides:
                        if o["label"] not in [
                            create_label(item) for item
                            in non_fallback_urls_created
                        ]:
                            if o["label"] == "url":
                                labels.update({"endpoint_url": o["value"]})

                            else:
                                if (self._is_attribute_overridden_all_endpoints(
                                    o["attribute"]
                                ) or o["attribute"] in self.global_attributes
                                        or o["attribute"] in self.default_ports
                                    or is_attribute_secret(o["attribute"])
                                ):
                                    labels.update({o["label"]: o["value"]})

                                else:
                                    params = attributes4metrics[o["attribute"]]
                                    for param in params:
                                        if param["metric"] in \
                                                metrics4servicetype:
                                            labels.update({
                                                "{}__{}".format(
                                                    param["value"].lstrip(
                                                        "-"
                                                    ).lstrip("-").replace(
                                                        "-", "_"
                                                    ), create_label(
                                                        o["attribute"]
                                                    )
                                                ): f"{param['value']} "
                                                   f"{o['value']}"
                                            })

                            # labels.update({
                            #     label: o["value"]
                            # })

                    for attr in overriding_attributes:
                        if attr not in self.global_attributes and \
                                is_attribute_secret(attr):
                            label = f"${create_attribute_env(attr)}"
                            labels.update({create_label(attr): label})

                for tag, value in item["tags"].items():
                    if (tag.startswith("info_bdii_") and
                            f"info_ext_{tag[10:]}" not in item["tags"]):
                        labels.update({
                            create_label(tag[10:]): value
                        })

                    if tag.startswith("info_ext_"):
                        present_in_all = \
                            self._is_extension_present_all_endpoints(
                                services=[item["service"]], extension=tag
                            )
                        if tag.lower() == "info_ext_port":
                            labels.update({"port": value})

                        else:
                            if tag[9:] in self.default_ports:
                                labels.update({
                                    create_label(tag[9:]): value
                                })

                            elif (tag[9:] in non_fallback_urls_created and
                                  not present_in_all):
                                continue
                            
                            elif tag.lower() == "info_ext_ssl":
                                continue
                            
                            elif present_in_all or tag.endswith("_URL"):
                                if value in ["0", "1"]:
                                    value = ""

                                labels.update({
                                    create_label(tag[9:]): value
                                })

                            else:
                                metrics = list()
                                for metric in self.metrics:
                                    for name, configuration in metric.items():
                                        if name in self.metrics4servicetypes[
                                            item["service"]
                                        ]:
                                            metrics.append(metric)

                                for metric in metrics:
                                    for name, configuration in metric.items():
                                        if tag[9:] in \
                                                configuration["attribute"]:
                                            if value in ["0", "1"]:
                                                value = ""

                                            labels.update({
                                                "{}__{}".format(
                                                    configuration["attribute"][
                                                        tag[9:]
                                                    ].lstrip("-").lstrip(
                                                        "-"
                                                    ).replace("-", "_"),
                                                    tag[9:].lower()
                                                ): "{} {}".format(
                                                    configuration["attribute"][
                                                        tag[9:]
                                                    ], value
                                                )
                                            })

                try:
                    ngi = item["ngi"]

                except KeyError:
                    ngi = ""

                labels.update({
                    "service": item["service"],
                    "site": item["group"],
                    "ngi": ngi,
                    "tenants": self.tenant
                })

                site_entries = [
                    i for i in self.topology if i["group"] == item["group"]
                ]
                site_bdii_entries = [
                    i for i in site_entries if i["service"] == "Site-BDII"
                ]

                if item["service"] in self.servicetypes_with_site_bdii:
                    if len(site_bdii_entries) > 0:
                        for metric, config in (
                                self.metrics_with_site_bdii.items()
                        ):
                            label = config["label"]
                            value = (f"{config['value']} "
                                     f"{site_bdii_entries[0]['hostname']}")
                            labels.update({label: value})

                existing_entities = [
                    ent for ent in entities if
                    ent["metadata"]["name"] == entity_name
                ]

                if len(existing_entities) > 0:
                    existing_entity = existing_entities[0]
                    old_labels = existing_entity["metadata"]["labels"].copy()
                    site = set([
                        e.strip() for e in
                        existing_entity["metadata"]["labels"]["site"].split(",")
                    ])
                    site.add(labels["site"])
                    if len(old_labels.keys()) >= len(labels.keys()):
                        new_labels = old_labels
                        for k, v in labels.items():
                            if k not in new_labels:
                                new_labels.update({k: v})

                            else:
                                if not new_labels[k]:
                                    new_labels[k] = v

                    else:
                        new_labels = labels.copy()
                        for k, v in old_labels.items():
                            if k not in new_labels:
                                new_labels.update({k: v})

                            else:
                                if not new_labels[k]:
                                    new_labels[k] = v

                    new_labels["site"] = ",".join(sorted(list(site)))

                    existing_entity["metadata"]["labels"] = new_labels

                else:
                    entities.append({
                        "entity_class": "proxy",
                        "metadata": {
                            "name": entity_name,
                            "namespace": namespace,
                            "labels": labels
                        }
                    })

            if len(skipped_entities) > 0:
                self.logger.info(
                    f"{self.tenant}: Skipped entities generation for entities: "
                    f"{', '.join(skipped_entities)}: invalid characters"
                )

            return entities

        except KeyError:
            self.logger.error(
                f"{self.tenant}: Skipping entities generation: faulty topology"
            )

            raise GeneratorException(
                f"{self.tenant}: Error generating entities: faulty topology"
            )

    def generate_internal_services(self):
        services = list()
        for metric in self.internal_metrics:
            services.extend(self.servicetypes4metrics[metric])

        return ",".join(sorted(list(set(services))))


class ConfigurationMerger:
    def __init__(
            self,
            checks,
            entities,
            internal_services,
            metricoverrides4agents=None,
            attributeoverrides4agents=None
    ):
        self.checks = checks
        self.entities = entities
        self.internal_services = internal_services
        self.metric_overrides = metricoverrides4agents
        self.attribute_overrides = attributeoverrides4agents
        self.logger = logging.getLogger("argo-scg.generator")

    def merge_checks(self):
        merged_checks = list()

        for tenant, checks in self.checks.items():
            checks_names = [item["metadata"]["name"] for item in merged_checks]
            for check in checks:
                if check["metadata"]["name"] not in checks_names:
                    merged_checks.append(check)

                else:
                    check_index = next(
                        (index for (index, d) in enumerate(merged_checks) if
                         d["metadata"]["name"] == check["metadata"]["name"]),
                        None
                    )

                    tenants = [
                        item.strip() for item in merged_checks[check_index][
                            "metadata"
                        ]["labels"]["tenants"].split(",")
                    ]

                    tenants.append(check["metadata"]["labels"]["tenants"])

                    merged_checks[check_index]["metadata"]["labels"][
                        "tenants"
                    ] = ",".join(sorted(tenants))

        return merged_checks

    def merge_entities(self):
        merged_entities = list()
        for tenant, entities in self.entities.items():
            entities_names = [
                item["metadata"]["name"] for item in merged_entities
            ]
            for entity in entities:
                if entity["metadata"]["name"] not in entities_names:
                    merged_entities.append(entity)

                else:
                    entity_index = next(
                        (index for (index, d) in enumerate(merged_entities) if
                         d["metadata"]["name"] == entity["metadata"]["name"]),
                        None
                    )

                    for key, value in entity["metadata"]["labels"].items():
                        if key not in merged_entities[entity_index]["metadata"][
                            "labels"
                        ]:
                            merged_entities[entity_index]["metadata"][
                                "labels"
                            ].update({key: value})

                    site = [
                        item.strip() for item in merged_entities[entity_index][
                            "metadata"
                        ]["labels"]["site"].split(",")
                    ]
                    tenants = [
                        item.strip() for item in merged_entities[entity_index][
                            "metadata"
                        ]["labels"]["tenants"].split(",")
                    ]
                    site.append(entity["metadata"]["labels"]["site"])
                    tenants.append(entity["metadata"]["labels"]["tenants"])

                    merged_entities[entity_index]["metadata"]["labels"][
                        "site"
                    ] = ",".join(sorted(site))
                    merged_entities[entity_index]["metadata"]["labels"][
                        "tenants"
                    ] = ",".join(sorted(tenants))

        return sorted(merged_entities, key=lambda e: e["metadata"]["name"])

    @staticmethod
    def _metric_parameter_override_exists(override, merged):
        return len([
            item for item in merged if (
                    item["metric"] == override["metric"] and
                    item["hostname"] == override["hostname"] and
                    item["parameter"] == override["parameter"]
            )
        ]) == 1

    @staticmethod
    def _metric_parameter_override_identical(override, merged):
        return len([
            item for item in merged if (
                    item["metric"] == override["metric"] and
                    item["hostname"] == override["hostname"] and
                    item["parameter"] == override["parameter"] and
                    item["value"] == override["value"]
            )
        ]) == 1

    def merge_metric_parameter_overrides(self):
        merged_overrides = list()
        if self.metric_overrides:
            for tenant, overrides in self.metric_overrides.items():
                for override in overrides:
                    if self._metric_parameter_override_exists(
                            override, merged_overrides
                    ):
                        if self._metric_parameter_override_identical(
                            override, merged_overrides
                        ):
                            continue

                        else:
                            self.logger.warning(
                                f"{tenant}: Discrepancy in "
                                f"{override['hostname']}/{override['metric']} "
                                f"metric parameter override"
                            )

                    else:
                        merged_overrides.append(override)

        return merged_overrides

    @staticmethod
    def _attribute_present(override, merged):
        return len([
            item for item in merged if (
                item["hostname"] == override["hostname"] and
                item["attribute"] == override["attribute"]
            )
        ]) == 1

    @staticmethod
    def _attribute_identical(override, merged):
        return len([
            item for item in merged if (
                    item["hostname"] == override["hostname"] and
                    item["attribute"] == override["attribute"] and
                    item["value"] == override["value"]
            )
        ]) == 1

    def merge_attribute_overrides(self):
        merged_attributes = list()
        if self.attribute_overrides:
            for tenant, overrides in self.attribute_overrides.items():
                for override in overrides:
                    if self._attribute_present(override, merged_attributes):
                        if self._attribute_identical(
                                override, merged_attributes
                        ):
                            merged_attribute = [
                                item for item in merged_attributes if (
                                        item["hostname"] == override["hostname"]
                                        and item["attribute"] == override[
                                            "attribute"
                                        ]
                                )
                            ][0]
                            metrics = merged_attribute["metrics"]
                            metrics.extend(override["metrics"])
                            merged_attributes[
                                merged_attributes.index(merged_attribute)
                            ]["metrics"] = sorted(metrics)

                        else:
                            self.logger.warning(
                                f"{tenant}: Discrepancy in "
                                f"{override['hostname']}/"
                                f"{override['attribute']} host attribute "
                                f"override"
                            )

                    else:
                        merged_attributes.append(override)

        return merged_attributes

    def merge_internal_services(self):
        internals = list()
        for tenant, services_str in self.internal_services.items():
            services = [item.strip() for item in services_str.split(",")]
            internals.extend(services)

        return ",".join(sorted(list(set(internals))))
