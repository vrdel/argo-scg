import copy
import logging
import unittest

from argo_scg.exceptions import GeneratorException
from argo_scg.generator import ConfigurationGenerator, generate_adhoc_check, \
    ConfigurationMerger

mock_metrics = [
    {
        "argo.AMSPublisher-Check": {
            "tags": [
                "ams",
                "ams publisher",
                "argo",
                "internal",
                "messaging"
            ],
            "probe": "ams-publisher-probe",
            "config": {
                "interval": "180",
                "maxCheckAttempts": "1",
                "path": "/usr/libexec/argo-monitoring/probes/argo",
                "retryInterval": "1",
                "timeout": "120"
            },
            "flags": {
                "NOHOSTNAME": "1",
                "NOTIMEOUT": "1",
                "NOPUBLISH": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {
                "-s": "/var/run/argo-nagios-ams-publisher/sock",
                "-q": "'w:metrics+g:published180' -c 4000 -q "
                      "'w:alarms+g:published180' -c 1 "
                      "-q 'w:metricsdevel+g:published180' -c 4000"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu/nagios-plugins-argo/blob/"
                      "master/README.md"
        }
    },
    {
        "argo.APEL-Pub": {
            "tags": [
                "accounting",
                "apel",
                "htc"
            ],
            "probe": "check_http_parser",
            "config": {
                "timeout": "120",
                "retryInterval": "15",
                "path": "/usr/libexec/argo/probes/http_parser",
                "maxCheckAttempts": "2",
                "interval": "720"
            },
            "flags": {
                "OBSESS": "1",
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {
                "-H": "goc-accounting.grid-support.ac.uk",
                "-u": "/rss/$_SERVICESITE_NAME$_Pub.html",
                "--warning-search": "WARN",
                "--critical-search": "ERROR",
                "--ok-search": "OK",
                "--case-sensitive": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu-Metrics/"
                      "argo-probe-http-parser/blob/main/README.md"
        }
    },
    {
        "argo.APEL-Sync": {
            "tags": [
                "accounting",
                "apel",
                "htc"
            ],
            "probe": "check_http_parser",
            "config": {
                "timeout": "120",
                "retryInterval": "15",
                "path": "/usr/libexec/argo/probes/http_parser",
                "maxCheckAttempts": "2",
                "interval": "720"
            },
            "flags": {
                "OBSESS": "1",
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {
                "-H": "goc-accounting.grid-support.ac.uk",
                "-u": "/rss/$_SERVICESITE_NAME$_Sync.html",
                "--warning-search": "WARN",
                "--critical-search": "ERROR",
                "--ok-search": "OK",
                "--case-sensitive": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu-Metrics/argo-probe-http-parser"
                      "/blob/main/README.md"
        }
    },
    {
        "argo.API-Check": {
            "tags": [
                "api",
                "argo",
                "monitoring"
            ],
            "probe": "web-api",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "120",
                "path": "/usr/libexec/argo-monitoring/probes/argo",
                "interval": "5",
                "retryInterval": "3"
            },
            "flags": {
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "argo.api_TOKEN": "--token"
            },
            "parameter": {
                "--tenant": "EGI",
                "--rtype": "ar",
                "--unused-reports": "Cloud Critical-Fedcloud Fedcloud "
                                    "NGIHRTest",
                "--day": "1"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu/nagios-plugins-argo/blob/"
                      "master/README.md"
        }
    },
    {
        "argo.cvmfs-stratum-1.status": {
            "tags": [
                "cvmfs",
                "htc",
                "http",
                "network"
            ],
            "probe": "check_http_parser",
            "config": {
                "timeout": "120",
                "retryInterval": "3",
                "path": "/usr/libexec/argo/probes/http_parser",
                "maxCheckAttempts": "3",
                "interval": "5"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "CVMFS-Stratum-1_PORT": "-p"
            },
            "parameter": {
                "-u": "\"/cvmfsmon/api/v1.0/all\"",
                "--unknown-message":
                    "\"Please check if cvmfs-servermon package is installed\""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl":
                "https://github.com/ARGOeu-Metrics/argo-probe-http-parser/blob/"
                "main/README.md"
        }
    },
    {
        "argo.nagios.freshness-simple-login": {
            "tags": [
                "argo",
                "authentication",
                "monitoring",
                "nagios"
            ],
            "probe": "check_nagios",
            "config": {
                "interval": "15",
                "maxCheckAttempts": "2",
                "path": "/usr/libexec/argo/probes/nagios",
                "retryInterval": "10",
                "timeout": "60"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "NAGIOS_FRESHNESS_USERNAME": "--username",
                "NAGIOS_FRESHNESS_PASSWORD": "--password"
            },
            "parameter": {
                "--nagios-service": "org.nagios.NagiosCmdFile"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu-Metrics/argo-probe-nagios/"
                      "blob/master/README.md"
        }
    },
    {
        "cern.webdav.status": {
            "tags": [
                "storage",
                "webdav"
            ],
            "probe": "check_webdav",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "2",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "15",
                "timeout": "600"
            },
            "flags": {
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "ARGO_WEBDAV_OPS_URL": "-u",
                "X509_USER_PROXY": "-E",
                "ARGO_WEBDAV_SKIP_DIR_TEST": "--skip-dir-test",
                "ARGO_WEBDAV_DYNAFED": "--dynafed"
            },
            "parameter": {
                "-v": "-v",
                "--no-crls": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl":
                "https://gitlab.cern.ch/lcgdm/nagios-plugins-webdav/blob/master"
                "/README.md"
        }
    },
    {
        "ch.cern.WebDAV": {
            "tags": [],
            "probe": "check_webdav",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "2",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "15",
                "timeout": "600"
            },
            "flags": {
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "webdav_URL": "-u",
                "X509_USER_PROXY": "-E"
            },
            "parameter": {
                "-v": "-v",
                "--no-crls": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://gitlab.cern.ch/lcgdm/nagios-plugins-webdav/"
                      "blob/master/README.md"
        }
    },
    {
        "ch.cern.WebDAV-dynafed": {
            "tags": [],
            "probe": "check_webdav",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "2",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "15",
                "timeout": "600"
            },
            "flags": {
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "URL": "-u",
                "X509_USER_PROXY": "-E"
            },
            "parameter": {
                "-v": "-v",
                "--no-crls": "",
                "--dynafed": "",
                "--fixed-content-length": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://gitlab.cern.ch/lcgdm/nagios-plugins-webdav/blob/"
                      "master/README.md"
        }
    },
    {
        "egi.xrootd.readonly": {
            "tags": [
                "htc",
                "storage",
                "xrootd"
            ],
            "probe": "xrootd_probe.py",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "300",
                "path": "/usr/lib64/nagios/plugins/xrootd",
                "interval": "60",
                "retryInterval": "15"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "ARGO_XROOTD_OPS_URL": "-E",
                "X509_USER_PROXY": "-X",
                "ARGO_XROOTD_SKIP_LS_DIR": "--skip-ls-dir"
            },
            "parameter": {
                "--read-only": "",
                "-p": "egi.xrootd.readonly"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl":
                "https://github.com/EGI-Federation/nagios-plugins-xrootd/blob/"
                "main/README.md"
        }
    },
    {
        "egi.xrootd.readwrite": {
            "tags": [
                "htc",
                "storage",
                "xrootd"
            ],
            "probe": "storage_probe.py",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "300",
                "path": "/usr/lib64/nagios/plugins/storage",
                "interval": "60",
                "retryInterval": "15"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "ARGO_XROOTD_OPS_URL": "-E",
                "X509_USER_PROXY": "-X",
                "ARGO_XROOTD_SKIP_LS_DIR": "--skip-ls-dir"
            },
            "parameter": {
                "-p": "egi.xrootd.readwrite"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/EGI-Federation/nagios-plugins-storage"
                      "/blob/main/README.md"
        }
    },
    {
        "eosc.test.api": {
            "tags": [],
            "probe": "check_api.py",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "30",
                "path": "/usr/libexec/argo/probes/test",
                "interval": "720",
                "retryInterval": "20"
            },
            "flags": {
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {
                "URL": "-u"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": ""
        }
    },
    {
        "eu.egi.AAI-OIDC-Login": {
            "tags": [
                "rciam"
            ],
            "probe": "checklogin",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "10",
                "path": " /usr/libexec/argo-monitoring/probes/rciam_probes",
                "interval": "15",
                "retryInterval": "2"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "EGISSO_USER": "-u",
                "EGISSO_PASSWORD": "-a"
            },
            "parameter": {
                "-i": "https://idp.admin.grnet.gr/idp/shibboleth,"
                      "https://www.egi.eu/idp/shibboleth",
                "-s": "https://snf-666522.vm.okeanos.grnet.gr/egi-rp/auth.php",
                "-C": "",
                "-e": "https://mon.rciam.grnet.gr/probes/results"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/rciam/rciam_probes/blob/master/"
                      "README.md"
        }
    },
    {
        "eu.egi.AAI-SAML-Login": {
            "tags": [
                "rciam"
            ],
            "probe": "checklogin",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "10",
                "path": "/usr/libexec/argo-monitoring/probes/rciam_probes",
                "interval": "15",
                "retryInterval": "2"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "EGISSO_USER": "-u",
                "EGISSO_PASSWORD": "-a"
            },
            "parameter": {
                "-i": "https://idp.admin.grnet.gr/idp/shibboleth,"
                      "https://www.egi.eu/idp/shibboleth",
                "-s": "https://snf-666522.vm.okeanos.grnet.gr/ssp/module.php/"
                      "core/authenticate.php?as=egi-sp",
                "-C": "",
                "-e": "https://mon.rciam.grnet.gr/probes/results"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/rciam/rciam_probes/blob/master/"
                      "README.md"
        }
    },
    {
        "eu.egi.cloud.DynDNS-Check": {
            "tags": [],
            "probe": "nagios-plugin-dynamic-dns.sh",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "120",
                "path": "/usr/libexec/argo-monitoring/probes/"
                        "nagios-plugin-dynamic-dns",
                "interval": "5",
                "retryInterval": "3"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "endpoint-name": "--endpoint-name"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/tdviet/DDNS-probe/blob/main/README.md"
        }
    },
    {
        "eu.egi.grycap.IM-Check": {
            "tags": [],
            "probe": "probeim.py",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "60",
                "path": "/usr/libexec/argo-monitoring/probes/es.upv.grycap.im",
                "interval": "60",
                "retryInterval": "3"
            },
            "flags": {
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {
                "es.upv.grycap.im_GOCDB_SERVICE_URL": "--url",
                "OIDC_TOKEN_FILE": "--token"
            },
            "parameter": {
                "-l": "NONE"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/grycap/im/blob/master/monitoring/"
                      "README.md"
        }
    },
    {
        "eu.egi.cloud.InfoProvider": {
            "tags": [],
            "probe": "cloudinfo.py",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "300",
                "path": "/usr/libexec/argo-monitoring/probes/fedcloud",
                "interval": "60",
                "retryInterval": "15"
            },
            "flags": {
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {
                "OS_KEYSTONE_URL": "--endpoint"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://wiki.egi.eu/wiki/Cloud_SAM_tests"
        }
    },
    {
        "eu.egi.cloud.OpenStack-Swift": {
            "tags": [],
            "probe": "swiftprobe.py",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "300",
                "path": "/usr/libexec/argo-monitoring/probes/fedcloud",
                "interval": "60",
                "retryInterval": "15"
            },
            "flags": {
                "NOHOSTNAME": "1",
                "OBSESS": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "0",
                "org.nagios.Keystone-TCP": "1"
            },
            "attribute": {
                "OS_KEYSTONE_URL": "--endpoint",
                "OIDC_ACCESS_TOKEN": "--access-token"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu/nagios-plugins-fedcloud/blob"
                      "/master/README.md"
        }
    },
    {
        "eu.egi.cloud.OpenStack-VM": {
            "tags": [],
            "probe": "novaprobe.py",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "300",
                "path": "/usr/libexec/argo-monitoring/probes/fedcloud",
                "interval": "60",
                "retryInterval": "15"
            },
            "flags": {
                "VO": "1",
                "NOHOSTNAME": "1",
                "OBSESS": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "0",
                "org.nagios.Keystone-TCP": "1"
            },
            "attribute": {
                "OIDC_ACCESS_TOKEN": "--access-token",
                "OS_APPDB_IMAGE": "--appdb-image",
                "OS_KEYSTONE_URL": "--endpoint",
                "X509_USER_PROXY": "--cert",
                "OS_REGION": "--region"
            },
            "parameter": {
                "-v": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://wiki.egi.eu/wiki/Cloud_SAM_tests"
        }
    },
    {
        "eu.egi.GRAM-CertValidity": {
            "tags": [],
            "probe": "check_ssl_cert",
            "config": {
                "timeout": "60",
                "retryInterval": "30",
                "path": "/usr/lib64/nagios/plugins",
                "maxCheckAttempts": "2",
                "interval": "240"
            },
            "flags": {
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "NAGIOS_HOST_CERT": "-C",
                "NAGIOS_HOST_KEY": "-K",
                "GRAM_PORT": "-p"
            },
            "parameter": {
                "-w": "30 -c 0 -N --altnames",
                "--rootcert-dir": "/etc/grid-security/certificates"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/matteocorti/check_ssl_cert/blob/"
                      "master/README.md"
        }
    },
    {
        "eu.egi.sec.ARCCE-Pakiti-Check": {
            "tags": [],
            "probe": "eu.egi.sec/probes/check_pakiti_vuln",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "30",
                "path": "/usr/libexec/grid-monitoring/probes",
                "interval": "60",
                "retryInterval": "5"
            },
            "flags": {
                "VO": "1",
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "VONAME": "--vo",
                "NAGIOS_HOST_CERT": "--cert",
                "NAGIOS_HOST_KEY": "--key",
                "SITENAME": "--site"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu/secmon-probes"
        }
    },
    {
        "eu.egi.SRM-All": {
            "tags": [],
            "probe": "srm_probe.py",
            "config": {
                "maxCheckAttempts": "4",
                "timeout": "300",
                "path": "/usr/lib64/nagios/plugins/srm",
                "interval": "60",
                "retryInterval": "15"
            },
            "flags": {
                "VO": "1"
            },
            "dependency": {},
            "attribute": {
                "VONAME": "--voname",
                "X509_USER_PROXY": "-X",
                "SITE_BDII": "--ldap-url",
                "SURL": "--endpoint"
            },
            "parameter": {
                "-d": "",
                "-p": "eu.egi.SRM",
                "-s": "$_SERVICEVO$",
                "--se-timeout": "260"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/EGI-Foundation/nagios-plugins-srm/"
                      "blob/master/README.md"
        }
    },
    {
        "eu.egi.SRM-VOGet": {
            "tags": [
                "htc",
                "nonharmonized",
                "srm",
                "storage"
            ],
            "probe": "",
            "config": {},
            "flags": {
                "PASSIVE": "1",
                "VO": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "eu.egi.SRM-All",
            "docurl": ""
        }
    },
    {
        "eu.egi.SRM-VOLsDir": {
            "tags": [
                "htc",
                "nonharmonized",
                "srm",
                "storage"
            ],
            "probe": "",
            "config": {},
            "flags": {
                "PASSIVE": "1",
                "VO": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "eu.egi.SRM-All",
            "docurl": ""
        }
    },
    {
        "eu.seadatanet.org.replicationmanager-check": {
            "tags": [],
            "probe": "check_http",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "30",
                "path": "/usr/lib64/nagios/plugins",
                "interval": "5",
                "retryInterval": "3"
            },
            "flags": {
                "PNP": "1",
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "rm_path": "-u"
            },
            "parameter": {
                "-f": "\"follow\""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http.html"
        }
    },
    {
        "eu.seadatanet.org.replicationmanager-check-status": {
            "tags": [],
            "probe": "replication_manager_check.py",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "30",
                "path": "/usr/libexec/argo-monitoring/probes/sdc-replication"
                        "-manager/",
                "interval": "5",
                "retryInterval": "3"
            },
            "flags": {
                "PNP": "1",
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "rm_path": "-r"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu/nagios-plugins-sdc-replication"
                      "-manager/blob/devel/README.md"
        }
    },
    {
        "eudat.b2access.unity.login-local": {
            "tags": [
                "aai",
                "auth",
                "harmonized",
                "login",
                "sso"
            ],
            "probe": "check_b2access_simple.py",
            "config": {
                "interval": "15",
                "maxCheckAttempts": "3",
                "path": "/usr/libexec/argo-monitoring/probes/eudat-b2access/",
                "retryInterval": "3",
                "timeout": "120"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1",
                "NOTIMEOUT": "1",
            },
            "dependency": {},
            "attribute": {
                "NAGIOS_B2ACCESS_LOGIN": "--username",
                "NAGIOS_B2ACCESS_PASSWORD": "--password"
            },
            "parameter": {
                "--url": "https://b2access.fz-juelich.de:8443"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/EUDAT-B2ACCESS/b2access-probe/"
                      "blob/master/README.md"
        }
    },
    {
        "eudat.b2handle.handle.api-crud": {
            "tags": [
                "api",
                "pids"
            ],
            "probe": "check_handle_api.py",
            "config": {
                "interval": "15",
                "maxCheckAttempts": "3",
                "path": "/usr/libexec/argo/probes/eudat-b2handle/",
                "retryInterval": "3",
                "timeout": "15"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1",
                "NOTIMEOUT": "1",
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {
                "B2HANDLE_PREFIX": "--prefix"
            },
            "parameter": {
                "-f": "/etc/nagios/plugins/eudat-b2handle/$HOSTALIAS$/"
                      "credentials.json"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl":
                "https://github.com/ARGOeu-Metrics/argo-probe-eudat-b2handle"
        }
    },
    {
        "eudat.b2handle.handle.api-healthcheck-resolve": {
            "tags": [
                "api",
                "harmonized",
                "pids",
                "resolution"
            ],
            "probe": "check_handle_resolution.pl",
            "config": {
                "interval": "10",
                "maxCheckAttempts": "3",
                "path": "/usr/libexec/argo/probes/eudat-b2handle/",
                "retryInterval": "3",
                "timeout": "10"
            },
            "flags": {
                "OBSESS": "1",
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {
                "B2HANDLE_PREFIX": "--prefix"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl":
                "https://github.com/ARGOeu-Metrics/argo-probe-eudat-b2handle"
        }
    },
    {
        "eudat.gitlab.liveness": {
            "tags": [
                "CI/CD",
                "collaboration",
                "development",
                "harmonized"
            ],
            "probe": "check_gitlab_liveness.sh",
            "config": {
                "timeout": "10",
                "retryInterval": "3",
                "path": "/usr/libexec/argo/probes/eudat-gitlab/",
                "maxCheckAttempts": "3",
                "interval": "60"
            },
            "flags": {
                "PNP": "1",
                "OBSESS": "1",
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {
                "URL": "--url"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl":
                "https://github.com/ARGOeu-Metrics/argo-probe-eudat-gitlab/"
        }
    },
    {
        "generic.certificate.validity": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_ssl_cert",
            "config": {
                "timeout": "60",
                "retryInterval": "30",
                "path": "/usr/lib64/nagios/plugins",
                "maxCheckAttempts": "2",
                "interval": "240"
            },
            "flags": {
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "NAGIOS_HOST_CERT": "-C",
                "NAGIOS_HOST_KEY": "-K"
            },
            "parameter": {
                "-w": "30 -c 0 -N --altnames",
                "--rootcert-dir": "/etc/grid-security/certificates",
                "--rootcert-file": "/etc/pki/tls/certs/ca-bundle.crt"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/matteocorti/check_ssl_cert/"
                      "blob/master/README.md"
        }
    },
    {
        "generic.certificate.validity-srm": {
            "tags": [
                "certificate",
                "htc",
                "srm",
                "storage"
            ],
            "probe": "check_ssl_cert",
            "config": {
                "timeout": "60",
                "retryInterval": "30",
                "path": "/usr/lib64/nagios/plugins",
                "maxCheckAttempts": "2",
                "interval": "240"
            },
            "flags": {
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "NAGIOS_HOST_CERT": "-C",
                "NAGIOS_HOST_KEY": "-K",
                "SRM2_PORT": "-p"
            },
            "parameter": {
                "-w": "30 -c 0 -N --altnames",
                "--rootcert-dir": "/etc/grid-security/certificates"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/matteocorti/check_ssl_cert/blob/"
                      "master/README.md"
        }
    },
    {
        "generic.http.ar-argoui-ni4os": {
            "tags": [
                "argo.webui",
                "harmonized"
            ],
            "probe": "check_http",
            "config": {
                "timeout": "30",
                "retryInterval": "3",
                "path": "/usr/lib64/nagios/plugins",
                "maxCheckAttempts": "3",
                "interval": "5"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {
                "-r": "argo.eu",
                "-u": "/ni4os/report-ar/Critical/NGI?accept=csv",
                "--ssl": "",
                "--onredirect": "follow"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http."
                      "html"
        }
    },
    {
        "generic.http.connect": {
            "tags": [
                "harmonized",
                "http",
                "network"
            ],
            "probe": "check_http",
            "config": {
                "interval": "5",
                "maxCheckAttempts": "3",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "3",
                "timeout": "60"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "SSL": "-S --sni",
                "PORT": "-p",
                "PATH": "-u"
            },
            "parameter": {
                "--link": "",
                "--onredirect": "follow"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http.html"
        }
    },
    {
        "generic.http.json": {
            "tags": [
                "http",
                "json"
            ],
            "probe": "check_http_json.py",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "30",
                "path": "/usr/lib64/nagios/plugins",
                "interval": "30",
                "retryInterval": "5"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "PATH": "-p"
            },
            "parameter": {
                "-s": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu-Metrics/nagios-http-json"
        }
    },
    {
        "generic.json.connect": {
            "tags": [
                "http",
                "json"
            ],
            "probe": "check_json",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "30",
                "path": "/usr/libexec/argo/probes/json",
                "interval": "15",
                "retryInterval": "5"
            },
            "flags": {
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {
                "URL": "-u",
                "ARGO_JSON_KEY": "-k",
                "ARGO_JSON_CRITICAL": "-c"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu-Metrics/argo-probe-json/blob/"
                      "master/README.md"
        }
    },
    {
        "generic.oai-pmh.validity": {
            "tags": [
                "OAI-PMH",
                "http"
            ],
            "probe": "check_oai_pmh",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "60",
                "path": "/usr/libexec/argo/probes/oai_pmh",
                "interval": "60",
                "retryInterval": "5"
            },
            "flags": {
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {
                "URL": "-u"
            },
            "parameter": {
                "-v": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu-Metrics/argo-probe-oai-pmh/"
                      "blob/master/README.md"
        }
    },
    {
        "generic.ssh.test": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_ssh",
            "config": {
                "interval": "15",
                "maxCheckAttempts": "4",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "5",
                "timeout": "60"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "PORT": "-p"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/index.html"
        }
    },
    {
        "generic.ssh.connect": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_ssh",
            "config": {
                "interval": "15",
                "maxCheckAttempts": "4",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "5",
                "timeout": "60"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "SSH_PORT": "-p"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/index.html"
        }
    },
    {
        "generic.tcp.connect": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_tcp",
            "config": {
                "interval": "5",
                "maxCheckAttempts": "3",
                "path": "/usr/lib64/nagios/plugins/",
                "retryInterval": "3",
                "timeout": "120"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {
                "-p": "443"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_tcp.html"
        }
    },
    {
        "grnet.agora.healthcheck": {
            "tags": [
                "catalogue",
                "harmonized",
                "profiles"
            ],
            "probe": "checkhealth",
            "config": {
                "timeout": "100",
                "retryInterval": "3",
                "path": "/usr/libexec/argo/probes/grnet-agora/",
                "maxCheckAttempts": "3",
                "interval": "15"
            },
            "flags": {
                "PNP": "1",
                "OBSESS": "1",
                "NOTIMEOUT": "1"
            },
            "dependency": {},
            "attribute": {
                "AGORA_USERNAME": "-u",
                "AGORA_PASSWORD": "-p"
            },
            "parameter": {
                "-v": "",
                "-i": ""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu-Metrics/argo-probe-grnet-agora"
                      "/blob/master/README.md"
        }
    },
    {
        "grnet.rciam.oidc-login-edugain-ni4os": {
            "tags": [
                "aai",
                "harmonized",
                "rciam"
            ],
            "probe": "checklogin",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "10",
                "path": "/usr/libexec/argo-monitoring/probes/rciam_probes",
                "interval": "15",
                "retryInterval": "2"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "EDUGAIN_USER": "-u",
                "EDUGAIN_PASSWORD": "-a"
            },
            "parameter": {
                "-i": "https://idp.admin.grnet.gr/idp/shibboleth",
                "-s": "https://snf-666522.vm.okeanos.grnet.gr/ni4os-rp/auth."
                      "php",
                "-C": "",
                "-e": "https://mon-dev.rciam.grnet.gr/probes/results"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/rciam/rciam_probes/blob/master/"
                      "README.md"
        }
    },
    {
        "grnet.rciam.oidc-login-edugain": {
            "tags": [
                "aai",
                "harmonized",
                "rciam"
            ],
            "probe": "checklogin",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "10",
                "path": "/usr/libexec/argo-monitoring/probes/rciam_probes",
                "interval": "15",
                "retryInterval": "2"
            },
            "flags": {},
            "dependency": {},
            "attribute": {
                "EDUGAIN_USER": "-u",
                "EDUGAIN_PASSWORD": "-a",
                "ARGO_OIDC_SP_URL": "-s"
            },
            "parameter": {
                "-i": "https://idp.admin.grnet.gr/idp/shibboleth",
                "-C": "",
                "-e": "https://mon-dev.rciam.grnet.gr/probes/results"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/rciam/rciam_probes/blob/master/"
                      "README.md"
        }
    },
    {
        "org.apel.APEL-Pub": {
            "tags": [
                "apel"
            ],
            "probe": "",
            "config": {},
            "flags": {
                "OBSESS": "1",
                "PASSIVE": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": ""
        }
    },
    {
        "org.bdii.Entries": {
            "tags": [],
            "probe": "check_bdii_entries",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "4",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "15",
                "timeout": "60"
            },
            "flags": {
                "NRPE": "1",
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {
                "org.nagios.BDII-Check": "1"
            },
            "attribute": {
                "BDII_DN": "-b",
                "BDII_PORT": "-p"
            },
            "parameter": {
                "-c": "40:1",
                "-w": "20:1"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://gridinfo-documentation.readthedocs.io/en/latest/"
                      "developers/tests.html"
        }
    },
    {
        "org.nagios.GLUE2-Check": {
            "tags": [],
            "probe": "midmon/check_bdii_entries_num",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "60",
                "path": "/usr/libexec/argo-monitoring/probes",
                "interval": "60",
                "retryInterval": "5"
            },
            "flags": {
                "PNP": "1",
                "OBSESS": "1"
            },
            "dependency": {},
            "attribute": {
                "GLUE2_BDII_DN": "-b",
                "BDII_PORT": "-p"
            },
            "parameter": {
                "-c": "1:1",
                "-f": "\"(&(objectClass=GLUE2Domain)"
                      "(GLUE2DomainID=$_SERVICESITE_NAME$))\""
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://wiki.egi.eu/wiki/MW_Nagios_tests"
        }
    },
    {
        "org.nagios.GridFTP-Check": {
            "tags": [],
            "probe": "check_ftp",
            "config": {
                "interval": "15",
                "maxCheckAttempts": "4",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "5",
                "timeout": "60"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {
                "org.nmap.Classic-SE": "1",
                "org.nmap.WMS": "1"
            },
            "attribute": {
                "GRIDFTP_PORT": "-p"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/index.html"
        }
    },
    {
        "org.nagios.Keystone-TCP": {
            "tags": [],
            "probe": "check_tcp",
            "config": {
                "interval": "15",
                "maxCheckAttempts": "3",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "3",
                "timeout": "120"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1",
                "NOHOSTNAME": "1"
            },
            "dependency": {},
            "attribute": {
                "OS_KEYSTONE_PORT": "-p",
                "OS_KEYSTONE_HOST": "-H"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_tcp.html"
        }
    },
    {
        "org.nordugrid.ARC-CE-SRM-submit": {
            "tags": [],
            "probe": "check_arcce_submit",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "2",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "15",
                "timeout": "600"
            },
            "flags": {
                "NOTIMEOUT": "1",
                "OBSESS": "1",
                "VO": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "0"
            },
            "attribute": {
                "ARC_GOOD_SES": "-O",
                "VONAME": "--voms",
                "VO_FQAN": "--fqan",
                "X509_USER_PROXY": "--user-proxy",
                "ARC_CE_MEMORY_LIMIT": "--memory-limit"
            },
            "parameter": {
                "--job-tag": "dist-stage-srm",
                "--termination-service": "org.nordugrid.ARC-CE-SRM-result-"
                                         "$_SERVICEVO_FQAN$",
                "--test": "dist-stage-srm",
                "-O": "service_suffix=-$_SERVICEVO_FQAN$",
                "--command-file": "/var/nagios/rw/nagios.cmd",
                "--how-invoked": "nagios"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://git.nbi.ku.dk/downloads/"
                      "NorduGridARCNagiosPlugins/index.html#"
        }
    },
    {
        "org.nordugrid.ARC-CE-submit": {
            "tags": [],
            "probe": "check_arcce_submit",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "2",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "15",
                "timeout": "600"
            },
            "flags": {
                "NOTIMEOUT": "1",
                "OBSESS": "1",
                "VO": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "0"
            },
            "attribute": {
                "VONAME": "--voms",
                "VO_FQAN": "--fqan",
                "X509_USER_PROXY": "--user-proxy",
                "ARC_CE_MEMORY_LIMIT": "--memory-limit"
            },
            "parameter": {
                "--termination-service": "org.nordugrid.ARC-CE-result-"
                                         "$_SERVICEVO_FQAN$",
                "--test": "dist-caversion --test dist-sw-csh "
                          "--test dist-sw-gcc --test dist-sw-python "
                          "--test dist-sw-perl",
                "-O": "service_suffix=-$_SERVICEVO_FQAN$",
                "--command-file": "/var/nagios/rw/nagios.cmd",
                "--how-invoked": "nagios"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://git.nbi.ku.dk/downloads/NorduGridARCNagiosPlugins"
                      "/index.html#"
        }
    },
    {
        "org.nordugrid.ARC-CE-clean": {
            "tags": [
                "arc",
                "compute",
                "htc",
                "internal",
                "nonharmonized"
            ],
            "probe": "check_arcce_clean",
            "config": {
                "interval": "20",
                "maxCheckAttempts": "2",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "60",
                "timeout": "600"
            },
            "flags": {
                "NOHOSTNAME": "1",
                "NOTIMEOUT": "1",
                "REQUIREMENT": "org.nordugrid.ARC-CE-submit",
                "VO": "1",
                "NOPUBLISH": "1",
                "SILENCED": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "0"
            },
            "attribute": {
                "VONAME": "--voms",
                "VO_FQAN": "--fqan",
                "X509_USER_PROXY": "--user-proxy"
            },
            "parameter": {
                "--timeout": "600",
                "--command-file": "/var/nagios/rw/nagios.cmd",
                "--how-invoked": "nagios"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://git.nbi.ku.dk/downloads/"
                      "NorduGridARCNagiosPlugins/index.html#"
        }
    },
    {
        "org.nordugrid.ARC-CE-monitor": {
            "tags": [
                "arc",
                "compute",
                "htc",
                "internal",
                "nonharmonized"
            ],
            "probe": "check_arcce_monitor",
            "config": {
                "interval": "20",
                "maxCheckAttempts": "2",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "20",
                "timeout": "900"
            },
            "flags": {
                "NOHOSTNAME": "1",
                "NOTIMEOUT": "1",
                "REQUIREMENT": "org.nordugrid.ARC-CE-submit",
                "VO": "1",
                "NOPUBLISH": "1",
                "SILENCED": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "0"
            },
            "attribute": {
                "VONAME": "--voms",
                "VO_FQAN": "--fqan",
                "X509_USER_PROXY": "--user-proxy"
            },
            "parameter": {
                "-O": "service_suffix=-$_SERVICEVO_FQAN$ -O lfc_host=dummy "
                      "-O se_host=dummy",
                "--timeout": "900",
                "--command-file": "/var/nagios/rw/nagios.cmd",
                "--how-invoked": "nagios"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://git.nbi.ku.dk/downloads/NorduGridARCNagiosPlugins"
                      "/index.html#"
        }
    },
    {
        "org.nordugrid.ARC-CE-test": {
            "tags": [
                "arc",
                "compute",
                "htc"
            ],
            "probe": "check_arcce_monitor",
            "config": {
                "interval": "20",
                "maxCheckAttempts": "2",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "20",
                "timeout": "900"
            },
            "flags": {
                "NOHOSTNAME": "1",
                "NOTIMEOUT": "1",
                "REQUIREMENT": "org.nordugrid.ARC-CE-submit",
                "VO": "1",
                "NOPUBLISH": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "0"
            },
            "attribute": {
                "X509_USER_PROXY": "--user-proxy"
            },
            "parameter": {
                "-O": "service_suffix=-$_SERVICEVO_FQAN$ -O lfc_host=dummy "
                      "-O se_host=dummy",
                "--timeout": "900",
                "--command-file": "/var/nagios/rw/nagios.cmd",
                "--how-invoked": "nagios"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://git.nbi.ku.dk/downloads/NorduGridARCNagiosPlugins"
                      "/index.html#"
        }
    },
    {
        "pl.plgrid.QCG-Broker": {
            "tags": [],
            "probe": "org.qoscosgrid/broker/qcg-broker-probe",
            "config": {
                "interval": "60",
                "maxCheckAttempts": "2",
                "path": "/usr/libexec/grid-monitoring/probes",
                "retryInterval": "15",
                "timeout": "600"
            },
            "flags": {
                "NRPE": "1",
                "OBSESS": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Valid": "1",
                "hr.srce.QCG-Broker-CertLifetime": "1"
            },
            "attribute": {
                "QCG-BROKER_PORT": "-p",
                "HOSTDN": "-n",
                "X509_USER_PROXY": "-x"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://www.qoscosgrid.org/trac/qcg-broker"
        }
    },
    {
        "srce.certificate.validity-moncert": {
            "tags": [
                "certificate",
                "htc",
                "internal"
            ],
            "probe": "CertLifetime-probe",
            "config": {
                "maxCheckAttempts": "2",
                "timeout": "60",
                "path": "/usr/libexec/argo/probes/cert",
                "interval": "240",
                "retryInterval": "30"
            },
            "flags": {
                "NOHOSTNAME": "1",
                "NOPUBLISH": "1"
            },
            "dependency": {},
            "attribute": {
                "NAGIOS_ACTUAL_HOST_CERT": "-f"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://wiki.egi.eu/wiki/ROC_SAM_Tests#hr.srce."
                      "CREAMCE-CertLifetime"
        }
    },
    {
        "srce.gridproxy.get": {
            "tags": [
                "argo",
                "authentication",
                "harmonized",
                "htc",
                "internal",
                "monitoring",
                "proxy certificate"
            ],
            "probe": "refresh_proxy",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "120",
                "path": "/usr/libexec/argo/probes/globus",
                "interval": "240",
                "retryInterval": "5"
            },
            "flags": {
                "NOHOSTNAME": "1",
                "VO": "1",
                "NOPUBLISH": "1"
            },
            "dependency": {},
            "attribute": {
                "VONAME": "--vo",
                "VO_FQAN": "--vo-fqan",
                "ROBOT_CERT": "--robot-cert",
                "PROXY_LIFETIME": "--lifetime",
                "MYPROXY_NAME": "--name",
                "MYPROXY_SERVER": "-H",
                "ROBOT_KEY": "--robot-key",
                "X509_USER_PROXY": "-x"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu-Metrics/argo-probe-globus/"
                      "blob/master/README.md"
        }
    },
    {
        "srce.gridproxy.validity": {
            "tags": [
                "argo",
                "authentication",
                "harmonized",
                "htc",
                "internal",
                "monitoring",
                "proxy certificate"
            ],
            "probe": "GridProxy-probe",
            "config": {
                "maxCheckAttempts": "3",
                "timeout": "30",
                "path": "/usr/libexec/argo/probes/globus",
                "interval": "15",
                "retryInterval": "3"
            },
            "flags": {
                "NOHOSTNAME": "1",
                "VO": "1",
                "NOPUBLISH": "1"
            },
            "dependency": {
                "hr.srce.GridProxy-Get": "0"
            },
            "attribute": {
                "VONAME": "--vo",
                "X509_USER_PROXY": "-x"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "https://github.com/ARGOeu-Metrics/argo-probe-globus/"
                      "blob/master/README.md"
        }
    }
]

faulty_metrics = [
    {
        "generic.http.ar-argoui-ni4os": {
            "tags": [
                "argo.webui",
                "harmonized"
            ],
            "probe": "check_http",
            "config": {
                "retryInterval": "3",
                "path": "/usr/lib64/nagios/plugins",
                "maxCheckAttempts": "3",
                "interval": "5"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {
                "-r": "argo.eu",
                "-u": "/ni4os/report-ar/Critical/NGI?accept=csv",
                "--ssl": "",
                "--onredirect": "follow"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_http."
                      "html"
        }
    },
    {
        "generic.ssh.test": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_ssh",
            "config": {
                "interval": "15",
                "maxCheckAttempts": "4",
                "path": "/usr/lib64/nagios/plugins",
                "retryInterval": "5",
                "timeout": "60"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {
                "PORT": "-p"
            },
            "parameter": {},
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/index.html"
        }
    },
    {
        "generic.tcp.connect": {
            "tags": [
                "harmonized"
            ],
            "probe": "check_tcp",
            "config": {
                "interval": "5",
                "maxCheckAttempts": "3",
                "path": "/usr/lib64/nagios/plugins/",
                "retryInterval": "3",
                "timeout": "120"
            },
            "flags": {
                "OBSESS": "1",
                "PNP": "1"
            },
            "dependency": {},
            "attribute": {},
            "parameter": {
                "-p": "443"
            },
            "file_parameter": {},
            "file_attribute": {},
            "parent": "",
            "docurl": "http://nagios-plugins.org/doc/man/check_tcp.html"
        }
    }
]

mock_topology = [
    {
        "date": "2022-02-16",
        "group": "GRNET",
        "type": "SITES",
        "service": "argo.webui",
        "hostname": "argo.ni4os.eu",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxxx",
            "info_URL": "https://argo.ni4os.eu",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-02-16",
        "group": "GRNET",
        "type": "SITES",
        "service": "argo.test",
        "hostname": "argo.ni4os.eu",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxxx",
            "info_URL": "https://argo.ni4os.eu",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-02-16",
        "group": "UKIM",
        "type": "SITES",
        "service": "eu.ni4os.ops.gocdb",
        "hostname": "gocdb.ni4os.eu",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxxx",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-02-16",
        "group": "GRNET",
        "type": "SITES",
        "service": "argo.mon",
        "hostname": "argo-mon2.ni4os.eu",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxxx",
            "info_URL": "https://argo-mon2.ni4os.eu",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-02-16",
        "group": "GRNET",
        "type": "SITES",
        "service": "argo.webui",
        "hostname": "argo-devel.ni4os.eu",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxxx",
            "info_URL": "http://argo-devel.ni4os.eu",
            "monitored": "1",
            "production": "1",
            "scope": "argo.eu"
        }
    },
    {
        "date": "2022-03-14",
        "group": "OPENSTACK",
        "type": "SITES",
        "service": "test.openstack.nova",
        "hostname": "cloud.cloudhost.com",
        "ngi": "FEDCLOUD",
        "tags": {
            "info_HOSTDN": "/CN=cloud.cloudhost.com",
            "info_ID": "xxxxxxx",
            "info_URL": "https://cloud.cloudhost.com:5000/v3/",
            "monitored": "1",
            "production": "1",
            "scope": "scope1, scope2"
        }
    },
    {
        "date": "2022-03-14",
        "group": "WEBDAV-test",
        "type": "SITES",
        "service": "mock.webdav",
        "hostname": "dpm.bla.meh.com",
        "ngi": "MEH",
        "tags": {
            "info_HOSTDN": "/CN=host/dpm.bla.meh.com",
            "info_ID": "xxxxxxx",
            "info_URL": "https://dpm.bla.meh.com/dpm/ops/",
            "info_service_endpoint_URL": "https://mock.url.com/dpm/ops, "
                                         "https://mock2.url.com/dpm/ops",
            "monitored": "1",
            "production": "1",
            "scope": "scope1"
        }
    },
    {
        "date": "2022-03-15",
        "group": "GRIDOPS-CheckIn",
        "type": "SITES",
        "service": "egi.aai.saml",
        "hostname": "aai.eosc-portal.eu",
        "ngi": "EGI.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://aai.eosc-portal.eu/proxy",
            "info_service_endpoint_URL":
                "https://aai.eosc-portal.eu/proxy/saml2/idp/metadata.php, "
                "https://aai.eosc-portal.eu/proxy/module.php/saml/sp/"
                "metadata.php/sso, "
                "https://aai.eosc-portal.eu/proxy/module.php/core/"
                "authenticate.php?as=sso",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-15",
        "group": "GRIDOPS-CheckIn",
        "type": "SITES",
        "service": "egi.aai.oidc",
        "hostname": "aai.eosc-portal.eu",
        "ngi": "EGI.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://aai.eosc-portal.eu/oidc",
            "info_service_endpoint_URL":
                "https://aai.eosc-portal.eu/oidc/.well-known/"
                "openid-configuration, "
                "https://aai.eosc-portal.eu/oidc/authorize",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-15",
        "group": "BDII",
        "type": "SITES",
        "service": "Top-BDII",
        "hostname": "bdii1.test.com",
        "ngi": "TEST",
        "tags": {
            "info_ID": "xxxxxxx",
            "monitored": "1",
            "production": "1",
            "scope": "scope3"
        }
    },
    {
        "date": "2022-03-15",
        "group": "SBDII",
        "type": "SITES",
        "service": "Site-BDII",
        "hostname": "sbdii.test.com",
        "ngi": "TEST",
        "tags": {
            "info_ID": "xxxxxxx",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-18",
        "group": "IPB",
        "type": "SITES",
        "service": "eu.ni4os.app.web",
        "hostname": "catalogue.ni4os.eu",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxx",
            "info_URL": "https://catalogue.ni4os.eu/",
            "monitored": "1",
            "production": "1",
            "scope": "NI4OS-Europe"
        }
    },
    {
        "date": "2022-03-18",
        "group": "SRCE",
        "type": "SITES",
        "service": "eu.ni4os.hpc.ui",
        "hostname": "teran.srce.hr",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxx",
            "monitored": "1",
            "production": "1",
            "scope": "NI4OS-Europe"
        }
    },
    {
        "date": "2022-03-18",
        "group": "IPB",
        "type": "SITES",
        "service": "eu.ni4os.hpc.ui",
        "hostname": "hpc.resource.ni4os.eu",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxxx",
            "info_ext_PORT": "1022",
            "info_ext_SSH_PORT": "1022",
            "monitored": "1",
            "production": "1",
            "scope": "NI4OS-Europe"
        }
    },
    {
        "date": "2022-03-18",
        "group": "EGI-DDNS",
        "type": "SITES",
        "service": "eu.egi.cloud.dyndns",
        "hostname": "dns1.cloud.test.eu",
        "ngi": "EGI.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://dns1.cloud.test.eu/",
            "info_ext_endpoint-name": "nsupdate",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-18",
        "group": "EGI-DDNS",
        "type": "SITES",
        "service": "eu.egi.cloud.dyndns",
        "hostname": "dns2.cloud.test.eu",
        "ngi": "EGI.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_ext_endpoint-name": "secondary",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-18",
        "group": "EGI-DDNS",
        "type": "SITES",
        "service": "eu.egi.cloud.dyndns",
        "hostname": "dns3.cloud.test.eu",
        "ngi": "EGI.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_ext_endpoint-name": "primary",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-23",
        "group": "INFN-CLOUD-CNAF",
        "type": "SITES",
        "service": "org.openstack.nova",
        "hostname": "cloud-api-pub.cr.cnaf.infn.it",
        "ngi": "NGI_IT",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://cloud-api-pub.cr.cnaf.infn.it:5000/v3",
            "info_ext_OS_REGION": "sdds",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, FedCloud"
        }
    },
    {
        "date": "2022-03-23",
        "group": "INFN-PADOVA-STACK",
        "type": "SITES",
        "service": "org.openstack.nova",
        "hostname": "egi-cloud.pd.infn.it",
        "ngi": "NGI_IT",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://egi-cloud.pd.infn.it:443/v3",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, FedCloud"
        }
    },
    {
        "date": "2022-03-23",
        "group": "CESNET-MCC",
        "type": "SITES",
        "service": "org.openstack.swift",
        "hostname": "identity.cloud.muni.cz",
        "ngi": "NGI_CZ",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://identity.cloud.muni.cz/v3",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, FedCloud"
        }
    },
    {
        "date": "2022-03-25",
        "group": "JUELICH",
        "type": "SITES",
        "service": "b2access.unity",
        "hostname": "b2access.eudat.eu",
        "ngi": "EUDAT",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://b2access.eudat.eu/home/",
            "info_ext_servicetype_id": "xx",
            "info_ext_state": "production",
            "monitored": "1",
            "production": "0",
            "scope": "EUDAT"
        }
    },
    {
        "date": "2022-03-25",
        "group": "CA-UVic-Cloud",
        "type": "SITES",
        "service": "ch.cern.dynafed",
        "hostname": "dynafed.hostname.ca",
        "ngi": "ROC_Canada",
        "tags": {
            "info_HOSTDN": "/C=CA/O=Grid/CN=dynafed.hostname.ca",
            "info_ID": "xxxxxxx",
            "info_URL": "https://dynafed.hostname.ca:443/dynafed/ops",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-25",
        "group": "CERN-PROD",
        "type": "SITES",
        "service": "webdav",
        "hostname": "hostname.cern.ch",
        "ngi": "CERN",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://hostname.cern.ch/atlas/opstest",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-25",
        "group": "UPV-GRyCAP",
        "type": "SITES",
        "service": "es.upv.grycap.im",
        "hostname": "grycap.upv.es",
        "ngi": "NGI_IBERGRID",
        "tags": {
            "info_ID": "xxxxxx",
            "info_URL": "https://grycap.upv.es:31443/im/",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, FedCloud"
        }
    },
    {
        "date": "2022-03-25",
        "group": "CING",
        "type": "SITES",
        "service": "web.check",
        "hostname": "bioinformatics.cing.ac.cy",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxxx",
            "info_URL":
                "https://bioinformatics.cing.ac.cy/MelGene?bla=oai%3meh",
            "monitored": "1",
            "production": "1",
            "scope": "NI4OS-Europe"
        }
    },
    {
        "date": "2022-03-25",
        "group": "CYI",
        "type": "SITES",
        "service": "web.check",
        "hostname": "eewrc-las.cyi.ac.cy",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxx",
            "info_URL": "http://eewrc-las.cyi.ac.cy/las/getUI.do",
            "monitored": "1",
            "production": "1",
            "scope": "NI4OS-Europe"
        }
    },
    {
        "date": "2022-03-25",
        "group": "SAMPA",
        "type": "SITES",
        "service": "web.check",
        "hostname": "sampaeos.if.usp.br",
        "ngi": "ROC_LA",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://sampaeos.if.usp.br:9000//eos/ops/opstest/",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, tier2, alice"
        }
    },
    {
        "date": "2022-03-28",
        "group": "AUVERGRID",
        "type": "SITES",
        "service": "ARC-CE",
        "hostname": "gridarcce01.mesocentre.uca.fr",
        "ngi": "NGI_FRANCE",
        "tags": {
            "info_ID": "xxxxxxx",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, atlas, lhcb"
        }
    },
    {
        "date": "2022-03-28",
        "group": "ARNES",
        "type": "SITES",
        "service": "Site-BDII",
        "hostname": "kser.arnes.si",
        "ngi": "NGI_SI",
        "tags": {
            "info_HOSTDN": "/C=SI/O=SiGNET/O=Arnes/CN=kser.arnes.si",
            "info_ID": "1691G0",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, atlas"
        }
    },
    {
        "date": "2022-03-28",
        "group": "ARNES",
        "type": "SITES",
        "service": "ngi.ARGUS",
        "hostname": "argus.sling.si",
        "ngi": "NGI_SI",
        "tags": {
            "info_HOSTDN": "/C=SI/O=SiGNET/O=SLING/CN=argus.sling.si",
            "info_ID": "5024G0",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, atlas"
        }
    },
    {
        "date": "2022-03-28",
        "group": "ARNES",
        "type": "SITES",
        "service": "SRM",
        "hostname": "dcache.arnes.si",
        "ngi": "NGI_SI",
        "tags": {
            "info_HOSTDN": "/C=SI/O=SiGNET/O=Arnes/CN=dcache.arnes.si",
            "info_ID": "5869G0",
            "info_bdii_SRM2_PORT": "8443",
            "monitored": "1",
            "production": "1",
            "scope": "EGI",
            "vo_cipkebip_attr_SE_PATH": "/data/arnes.si/cipkebip",
            "vo_gen.vo.sling_attr_SE_PATH": "/data/arnes.si/gen.vo.sling.si",
            "vo_ops_attr_SE_PATH": "/data/arnes.si/ops"
        }
    },
    {
        "date": "2022-03-28",
        "group": "RO-13-ISS",
        "type": "SITES",
        "service": "ARC-CE",
        "hostname": "alien.spacescience.ro",
        "ngi": "NGI_RO",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_ext_ARC_CE_MEMORY_LIMIT": "268435456",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, tier2, alice"
        }
    },
    {
        "date": "2022-03-28",
        "group": "NGI_PL_SERVICES",
        "type": "SITES",
        "service": "QCG.Broker",
        "hostname": "qcg-broker.man.poznan.pl",
        "ngi": "NGI_PL",
        "tags": {
            "info_HOSTDN": "/C=PL/CN=qcg-broker.man.poznan.pl",
            "info_ID": "xxxxxx",
            "info_URL": "https://qcg-broker.man.poznan.pl:8443/qcg/services/",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-03-29",
        "group": "DESY-HH",
        "type": "SITES",
        "service": "SRM",
        "hostname": "dcache-se-cms.desy.de",
        "ngi": "NGI_DE",
        "tags": {
            "info_ID": "3080G0",
            "info_bdii_SRM2_PORT": "8443",
            "info_ext_SURL": "srm://dcache-se-cms.desy.de:8443/srm/"
                             "managerv2?SFN=/pnfs/desy.de/ops",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, tier2, atlas, cms, lhcb",
            "vo_cms_attr_SE_PATH": "/pnfs/desy.de/cms/generated",
            "vo_desy_attr_SE_PATH": "/pnfs/desy.de/desy",
            "vo_dgops_attr_SE_PATH": "/pnfs/desy.de/dgops",
            "vo_dteam_attr_SE_PATH": "/pnfs/desy.de/dteam",
            "vo_ops_attr_SE_PATH": "/pnfs/desy.de/ops"
        }
    },
    {
        "date": "2022-03-29",
        "group": "DESY-HH",
        "type": "SITES",
        "service": "Site-BDII",
        "hostname": "grid-giis1.desy.de",
        "ngi": "NGI_DE",
        "tags": {
            "info_ID": "1729G0",
            "info_URL": "ldap://grid-giis1.desy.de:2170/mds-vo-name=DESY-HH,"
                        "o=grid",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, tier2, atlas, cms, lhcb"
        }
    },
    {
        "date": "2022-03-29",
        "group": "GAMMA",
        "type": "SITES",
        "service": "eu.seadatanet.org.replicationmanager",
        "hostname": "185.229.108.85",
        "ngi": "",
        "tags": {
            "info_ID": "xxxxx",
            "info_URL": "http://185.229.108.85:8080/",
            "monitored": "1",
            "production": "1",
            "scope": "SDC"
        }
    },
    {
        "date": "2022-03-29",
        "group": "HNODC",
        "type": "SITES",
        "service": "eu.seadatanet.org.replicationmanager",
        "hostname": "hnodc-dm.ath.hcmr.gr",
        "ngi": "",
        "tags": {
            "info_ID": "xxxxx",
            "info_URL": "http://hnodc-dm.ath.hcmr.gr/",
            "info_ext_rm_path": "/ReplicationManager/",
            "monitored": "1",
            "production": "1",
            "scope": "SDC"
        },
    },
    {
        "date": "2022-04-20",
        "group": "GRIDOPS",
        "type": "SITES",
        "service": "eu.eudat.itsm.spmt",
        "hostname": "eosc.agora.grnet.gr",
        "ngi": "EGI.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://eosc.agora.grnet.gr/",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-04-20",
        "group": "ARGO",
        "type": "SITES",
        "service": "argo.api",
        "hostname": "api.devel.argo.grnet.gr",
        "ngi": "EGI.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://api.devel.argo.grnet.gr/",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-04-20",
        "group": "ARGO",
        "type": "SITES",
        "service": "argo.api",
        "hostname": "api.argo.grnet.gr",
        "ngi": "EGI.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://api.argo.grnet.gr/",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-12-13",
        "group": "ARGO",
        "type": "SITES",
        "service": "argo.json",
        "hostname": "test-json.argo.grnet.gr",
        "ngi": "EGI.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://test-json.argo.grnet.gr/some/path",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-12-13",
        "group": "ARGO",
        "type": "SITES",
        "service": "probe.test",
        "hostname": "test.argo.grnet.gr",
        "ngi": "EGI.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://test.argo.grnet.gr/some/extra/path",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2022-12-13",
        "group": "ARGO",
        "type": "SITES",
        "service": "probe.test",
        "hostname": "test2.argo.grnet.gr",
        "ngi": "EGI.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://test2.argo.grnet.gr/some/extra2/path",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2023-04-13",
        "group": "ARGO",
        "type": "SITES",
        "service": "probe.test",
        "hostname": "test3.argo.grnet.gr",
        "ngi": "EGI.eu",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://test3.argo.grnet.gr/some/extra3/path",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2023-05-24",
        "group": "B2HANDLE",
        "type": "SITES",
        "service": "b2handle",
        "hostname": "b2handle.test.example.com",
        "ngi": "EUDAT",
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://b2handle.test.example.com",
            "monitored": "1",
            "production": "1",
            "scope": ""
        }
    },
    {
        "date": "2023-06-09",
        "group": "ARCHIVE-B2HANDLE",
        "type": "SERVICEGROUPS",
        "service": "b2handle.handle.api",
        "hostname": "b2handle3.test.com",
        "ngi": "EUDAT",
        "tags": {
            "info_ID": "xxxx",
            "monitored": "1",
            "production": "0",
            "scope": ""
        }
    },
    {
        "date": "2023-06-09",
        "group": "B2HANDLE TEST",
        "type": "SERVICEGROUPS",
        "service": "b2handle.handle.api",
        "hostname": "b2handle3.test.com",
        "ngi": "EUDAT",
        "tags": {
            "info_ID": "xxx",
            "monitored": "1",
            "production": "0",
            "scope": ""
        }
    },
    {
        "date": "2023-06-23",
        "group": "B2HANDLE-TEST",
        "type": "SERVICEGROUPS",
        "service": "b2handle.test",
        "hostname": "b2handle3.test.com",
        "ngi": "EUDAT",
        "tags": {
            "info_ID": "xxx",
            "monitored": "1",
            "production": "0",
            "scope": ""
        }
    },
    {
        "date": "2023-06-23",
        "group": "ARCHIVE-B2HANDLE",
        "type": "SERVICEGROUPS",
        "service": "b2handle.handle.test",
        "hostname": "b2handle3.test.com",
        "ngi": "EUDAT",
        "tags": {
            "info_ID": "xxxx",
            "monitored": "1",
            "production": "0",
            "scope": ""
        }
    },
    {
        "date": "2023-06-23",
        "group": "B2HANDLE-TEST",
        "type": "SERVICEGROUPS",
        "service": "b2handle.handle.test",
        "hostname": "b2handle.test.com",
        "ngi": "EUDAT",
        "tags": {
            "info_ID": "xxx",
            "monitored": "1",
            "production": "0",
            "scope": ""
        }
    },
    {
        "date": "2023-06-23",
        "group": "GITLAB-TEST",
        "type": "SERVICEGROUPS",
        "service": "gitlab",
        "hostname": "gitlab.test.com",
        "ngi": "TEST",
        "tags": {
            "info_ID": "xxx",
            "monitored": "1",
            "production": "0",
            "scope": ""
        }
    },
    {
        "date": "2023-06-23",
        "group": "GITLAB-TEST",
        "type": "SERVICEGROUPS",
        "service": "gitlab",
        "hostname": "gitlab2.test.com",
        "ngi": "TEST",
        "tags": {
            "info_ID": "xxx",
            "info_URL": "https://gitlab2.test.com/",
            "monitored": "1",
            "production": "0",
            "scope": ""
        }
    },
    {
        "date": "2023-06-26",
        "group": "GITLAB-TEST2",
        "type": "SERVICEGROUPS",
        "service": "gitlab2",
        "hostname": "gitlab2.test.com",
        "ngi": "TEST",
        "tags": {
            "info_ID": "xxx",
            "monitored": "1",
            "production": "0",
            "scope": ""
        }
    },
    {
        "date": "2023-06-26",
        "group": "GITLAB-TEST2",
        "type": "SERVICEGROUPS",
        "service": "gitlab2",
        "hostname": "gitlab.test.com",
        "ngi": "TEST",
        "tags": {
            "info_ID": "xxx",
            "monitored": "1",
            "production": "0",
            "scope": ""
        }
    },
    {
        "date": "2022-03-18",
        "group": "SRCE",
        "type": "SITES",
        "service": "eu.ni4os.hpc.ui2",
        "hostname": "teran.srce.hr",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxx",
            "monitored": "1",
            "production": "1",
            "scope": "NI4OS-Europe"
        }
    },
    {
        "date": "2022-03-18",
        "group": "IPB",
        "type": "SITES",
        "service": "eu.ni4os.hpc.ui2",
        "hostname": "hpc.resource.ni4os.eu",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxxx",
            "info_ext_PORT": "1022",
            "monitored": "1",
            "production": "1",
            "scope": "NI4OS-Europe"
        }
    },
    {
        "group": "argo-public-production",
        "service": "argo.grafana",
        "hostname": "www.srce.hr",
        "tags": {
            "info_URL": "http://www.srce.hr:6789/url_path",
            "info_ext_PORT": "45554",
            "info_ext_SSL": "1",
            "info_ext_PATH": "/path"
        }
    },

    {
        "date": "2023-10-03",
        "group": "SRCE",
        "type": "SITES",
        "service": "gridproxy",
        "hostname": "some.host.name",
        "ngi": "NI4OS",
        "tags": {
            "info_ID": "xxxx",
            "monitored": "1",
            "production": "1"
        }
    },
    {
        "date": "2023-10-03",
        "group": "APEL-Site1",
        "type": "SITES",
        "service": "APEL",
        "hostname": "apel.grid1.example.com",
        "ngi": "TEST",
        "notifications": {
            "enabled": True
        },
        "tags": {
            "info_ID": "xxxxxxx",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2023-10-03",
        "group": "APEL-Site2",
        "type": "SITES",
        "service": "APEL",
        "hostname": "apel.grid2.example.com",
        "ngi": "TEST",
        "notifications": {},
        "tags": {
            "info_ID": "xxxxxxx",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2023-09-12",
        "group": "APPDB",
        "type": "SITES",
        "service": "egi.AppDB",
        "hostname": "appdb.egi.eu",
        "ngi": "EGI.eu",
        "notifications": {},
        "tags": {
            "info_ID": "xxxxxx",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2023-10-06",
        "group": "IN2P3-CC",
        "type": "SITES",
        "service": "ch.cern.cvmfs.stratum.1",
        "hostname": "cclssts1.in2p3.fr",
        "ngi": "NGI_FRANCE",
        "notifications": {
            "enabled": True
        },
        "tags": {
            "info_ID": "xxxxxx",
            "info_ext_CVMFS-Stratum-1_PORT": "80",
            "monitored": "1",
            "production": "1",
            "scope": "Local, EGI, wlcg, tier1"
        }
    },
    {
        "date": "2023-10-06",
        "group": "JP-KEK-CRC-02",
        "type": "SITES",
        "service": "ch.cern.cvmfs.stratum.1",
        "hostname": "cvmfs-stratum-one.cc.kek.jp",
        "ngi": "AsiaPacific",
        "notifications": {},
        "tags": {
            "info_ID": "xxxxxxx",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2023-11-23",
        "group": "BEgrid-ULB-VUB",
        "type": "SITES",
        "service": "SRM",
        "hostname": "dcache6-shadow.iihe.ac.be",
        "ngi": "NGI_NL",
        "notifications": {
            "enabled": True
        },
        "tags": {
            "info_ID": "xxxxx",
            "monitored": "1",
            "production": "0",
            "scope": "EGI, wlcg, tier2, cms"
        }
    },
    {
        "date": "2023-11-23",
        "group": "BEgrid-ULB-VUB",
        "type": "SITES",
        "service": "Site-BDII",
        "hostname": "sitebdii.iihe.ac.be",
        "ngi": "NGI_NL",
        "notifications": {},
        "tags": {
            "info_ID": "xxxxx",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, tier2, cms"
        }
    },
    {
        "date": "2023-12-01",
        "group": "lida.lida_survey_data",
        "type": "SERVICEGROUPS",
        "service": "eu.eosc.generic.oai-pmh",
        "hostname": "lida.dataverse.lt",
        "ngi": "TEST",
        "tags": {
            "hostname": "lida.dataverse.lt",
            "info_URL": "https://lida.dataverse.lt/oai?verb="
                        "ListRecords&metadataPrefix=oai_datacite&set="
                        "lida_survey_data"
        }
    },
    {
        "date": "2023-12-18",
        "group": "XROOTD-SITE1",
        "type": "SITES",
        "service": "XRootD",
        "hostname": "atlas.dcache.example.eu",
        "ngi": "TEST",
        "notifications": {},
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "root://atlas.dcache.example.eu:1094/",
            "info_ext_ARGO_XROOTD_OPS_URL":
                "root://atlas.dcache.example.eu:1094/data/ops/",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2023-12-18",
        "group": "XROOTD-SITE2",
        "type": "SITES",
        "service": "XRootD",
        "hostname": "xrootd.example.eu",
        "ngi": "TEST",
        "notifications": {},
        "tags": {
            "info_ID": "xxxxx",
            "info_URL": "root://xrootd.example.eu:1094",
            "info_ext_ARGO_XROOTD_OPS_URL":
                "root://xrootd.example.eu:1094/ops/",
            "info_ext_ARGO_XROOTD_SKIP_LS_DIR": "0",
            "info_service_endpoint_URL": "root://xrootd.example.eu:1094",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2023-12-19",
        "group": "CERN-PROD",
        "type": "SITES",
        "service": "webdav",
        "hostname": "eosatlas.cern.ch",
        "ngi": "CERN",
        "notifications": {},
        "tags": {
            "info_ID": "xxxxx",
            "info_URL": "https://eosatlas.cern.ch//eos/atlas/opstest",
            "info_ext_ARGO_WEBDAV_OPS_URL":
                "https://eosatlas.cern.ch//eos/atlas/opstest/egi/",
            "info_ext_ARGO_WEBDAV_SKIP_DIR_TEST": "0",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, atlas"
        }
    },
    {
        "date": "2023-12-19",
        "group": "CERN-PROD",
        "type": "SITES",
        "service": "XRootD",
        "hostname": "castorpublic.cern.ch",
        "ngi": "CERN",
        "notifications": {},
        "tags": {
            "info_ID": "xxxxx",
            "monitored": "1",
            "production": "1",
            "scope": "EGI"
        }
    },
    {
        "date": "2024-01-15",
        "group": "XROOTD-READONLY",
        "type": "SITES",
        "service": "eu.egi.readonly.xrootd",
        "hostname": "xrootd01.readonly.eu",
        "ngi": "TEST",
        "notifications": {},
        "tags": {
            "info_ID": "xxxxx",
            "info_ext_ARGO_XROOTD_OPS_URL":
                "root://xrootd01.readonly.eu:1094/ops/xrootd_tests",
            "info_service_endpoint_URL":
                "root://xrootd01.readonly.eu:1094/ops/xrootd_tests",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, tier2, atlas, cms, lhcb"
        }
    },
    {
        "date": "2025-03-12",
        "group": "TEST_API",
        "type": "SERVICEGROUPS",
        "service": "argo.test.json.api",
        "hostname": "test.argo.eu",
        "tags": {
            "hostname": "test.argo.eu",
            "info_ID": "ARGO6",
            "info_URL": "https://test.argo.eu/api/DataSets/v2/search?q=house&metadataLanguage=en",
            "monitored": "1"
        }
    },
    {
        "date": "2025-03-12",
        "group": "TEST_API",
        "type": "SERVICEGROUPS",
        "service": "argo.test.json.api",
        "hostname": "test2.argo.eu",
        "tags": {
            "hostname": "test2.argo.eu",
            "info_ID": "ARGO7",
            "info_URL": "https://test2.argo.eu/v2/vocabularies-published",
            "monitored": "1"
        }
    },
    {
        "date": "2025-10-09",
        "group": "CSC",
        "type": "SITES",
        "service": "eudat.cms.confluence",
        "hostname": "wiki.eduuni.fi",
        "tags": {
            "info_ID": "ARGO8",
            "info_URL": "https://wiki.eduuni.fi/display/EUDATCDI/",
            "info_ext_state": "production",
            "monitored": "1",
            "production": "0",
            "scope": ""
        }
    },
]

mock_metric_profiles = [
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-11-24",
        "name": "ARGO_TEST1",
        "description": "Profile for monitoring",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "generic.http.ar-argoui-ni4os",
                    "generic.tcp.connect"
                ]
            },
            {
                "service": "argo.test",
                "metrics": [
                    "generic.http.ar-argoui-ni4os"
                ]
            }
        ]
    },
    {
        "id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
        "date": "2021-12-01",
        "name": "ARGO_TEST2",
        "description": "Profile for testing hard-coded attributes",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "generic.certificate.validity",
                    "eu.egi.GRAM-CertValidity",
                    "srce.certificate.validity-moncert"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST3",
        "description": "Another profile for testing hard-coded attributes",
        "services": [
            {
                "service": "argo.test",
                "metrics": [
                    "org.nagios.GridFTP-Check"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-11-24",
        "name": "ARGO_TEST4",
        "description": "Profile for testing metrics with attributes in file",
        "services": [
            {
                "service": "b2access.unity",
                "metrics": [
                    "eudat.b2access.unity.login-local",
                ]
            },
            {
                "service": "aai.oidc.login",
                "metrics": [
                    "grnet.rciam.oidc-login-edugain-ni4os"
                ]
            },
            {
                "service": "argo.test",
                "metrics": [
                    "eudat.b2access.unity.login-local"
                ]
            }
        ]
    },
    {
        "id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
        "date": "2021-12-01",
        "name": "ARGO_TEST5",
        "description": "Just another metric profile",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "generic.http.ar-argoui-ni4os",
                    "generic.tcp.connect",
                    "generic.certificate.validity"
                ]
            }
        ]
    },
    {
        "id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
        "date": "2021-12-01",
        "name": "ARGO_TEST6",
        "description": "Profile for fetching PATH and PORT",
        "services": [
            {
                "service": "web.check",
                "metrics": [
                    "generic.http.connect"
                ]
            },
            {
                "service": "eu.ni4os.hpc.ui",
                "metrics": [
                    "generic.ssh.test"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST7",
        "description": "Profile for SSL",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "generic.http.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST8",
        "description": "Profile for URLs",
        "services": [
            {
                "service": "webdav",
                "metrics": [
                    "ch.cern.WebDAV"
                ]
            },
            {
                "service": "ch.cern.dynafed",
                "metrics": [
                    "ch.cern.WebDAV-dynafed"
                ]
            },
            {
                "service": "es.upv.grycap.im",
                "metrics": [
                    "eu.egi.grycap.IM-Check"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST9",
        "description": "Profile for URLs",
        "services": [
            {
                "service": "mock.webdav",
                "metrics": [
                    "ch.cern.WebDAV"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST10",
        "description": "Profile for BDII",
        "services": [
            {
                "service": "Site-BDII",
                "metrics": [
                    "org.bdii.Entries",
                    "org.nagios.GLUE2-Check"
                ]
            },
            {
                "service": "Top-BDII",
                "metrics": [
                    "org.bdii.Entries"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST11",
        "description": "Profile for port testing",
        "services": [
            {
                "service": "eu.ni4os.hpc.ui",
                "metrics": [
                    "generic.ssh.test"
                ]
            },
            {
                "service": "eu.ni4os.app.web",
                "metrics": [
                    "generic.http.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST12",
        "description": "Profile for testing extensions",
        "services": [
            {
                "service": "eu.egi.cloud.dyndns",
                "metrics": [
                    "eu.egi.cloud.DynDNS-Check"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST13",
        "description": "Profile for testing openstack",
        "services": [
            {
                "service": "org.openstack.nova",
                "metrics": [
                    "eu.egi.cloud.InfoProvider",
                    "eu.egi.cloud.OpenStack-VM",
                    "org.nagios.Keystone-TCP"
                ]
            },
            {
                "service": "org.openstack.swift",
                "metrics": [
                    "eu.egi.cloud.OpenStack-Swift"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST14",
        "description": "Profile for testing openstack",
        "services": [
            {
                "service": "egi.aai.saml",
                "metrics": [
                    "eu.egi.AAI-SAML-Login"
                ]
            },
            {
                "service": "egi.aai.oidc",
                "metrics": [
                    "eu.egi.AAI-OIDC-Login"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST15",
        "description": "Profile for testing Pakiti probes",
        "services": [
            {
                "service": "ARC-CE",
                "metrics": [
                    "eu.egi.sec.ARCCE-Pakiti-Check"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST16",
        "description": "Profile for testing SITE-BDII attribute",
        "services": [
            {
                "service": "SRM",
                "metrics": [
                    "eu.egi.SRM-All"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST17",
        "description": "Profile for testing ARC_GOOD_SES attribute",
        "services": [
            {
                "service": "ARC-CE",
                "metrics": [
                    "org.nordugrid.ARC-CE-SRM-submit"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST18",
        "description": "Profile for testing HOSTDN attribute",
        "services": [
            {
                "service": "QCG.Broker",
                "metrics": [
                    "pl.plgrid.QCG-Broker"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST19",
        "description": "Profile for testing optional extensions",
        "services": [
            {
                "service": "ARC-CE",
                "metrics": [
                    "org.nordugrid.ARC-CE-SRM-submit",
                    "org.nordugrid.ARC-CE-submit"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST20",
        "description": "Profile for testing same extension values, different "
                       "parameters",
        "services": [
            {
                "service": "eu.seadatanet.org.replicationmanager",
                "metrics": [
                    "eu.seadatanet.org.replicationmanager-check",
                    "eu.seadatanet.org.replicationmanager-check-status"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST21",
        "description": "Profile for testing topology from file",
        "services": [
            {
                "service": "argo.mon",
                "metrics": [
                    "generic.certificate.validity"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST22",
        "description": "Profile for testing secret attributes",
        "services": [
            {
                "service": "eu.eudat.itsm.spmt",
                "metrics": [
                    "grnet.agora.healthcheck"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST23",
        "description": "Profile for testing secret attributes with dots",
        "services": [
            {
                "service": "argo.api",
                "metrics": [
                    "argo.API-Check"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST24",
        "description": "Profile for testing NOPUBLISH",
        "services": [
            {
                "service": "argo.test",
                "metrics": [
                    "org.nordugrid.ARC-CE-test",
                    "generic.tcp.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST25",
        "description": "Profile for testing metric parameter override",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "generic.tcp.connect"
                ]
            },
            {
                "service": "argo.test",
                "metrics": [
                    "generic.ssh.test",
                    "argo.APEL-Pub"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST26",
        "description": "Profile for testing host attribute override",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "argo.nagios.freshness-simple-login"
                ]
            },
            {
                "service": "argo.test",
                "metrics": [
                    "generic.tcp.connect"
                ]
            },
            {
                "service": "b2handle.test",
                "metrics": [
                    "eudat.b2handle.handle.api-healthcheck-resolve"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2021-12-01",
        "name": "ARGO_TEST27",
        "description": "Profile for testing internal metric",
        "services": [
            {
                "service": "argo.test",
                "metrics": [
                    "argo.AMSPublisher-Check",
                    "generic.tcp.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2022-09-13",
        "name": "ARGO_TEST28",
        "description": "Profile with metrics with attributes ending in _URL",
        "services": [
            {
                "service": "argo.oidc.login",
                "metrics": [
                    "grnet.rciam.oidc-login-edugain"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2022-09-13",
        "name": "ARGO_TEST29",
        "description": "Profile with metrics with attributes ending in _URL "
                       "in extensions",
        "services": [
            {
                "service": "webdav",
                "metrics": [
                    "ch.cern.WebDAV"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2022-09-22",
        "name": "ARGO_TEST30",
        "description": "Profile for topology that has hostname in tags",
        "services": [
            {
                "service": "eu.eosc.portal.services.url",
                "metrics": [
                    "generic.http.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2022-10-26",
        "name": "ARGO_TEST31",
        "description": "Profile for missing metrics",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "generic.tcp.connect"
                ]
            },
            {
                "service": "argo.test",
                "metrics": [
                    "mock.generic.check"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2022-12-13",
        "name": "ARGO_TEST32",
        "description": "Profile for metrics with PATH attribute",
        "services": [
            {
                "service": "argo.json",
                "metrics": [
                    "generic.http.json"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2022-12-13",
        "name": "ARGO_TEST33",
        "description": "Profile for metrics which override default parameters",
        "services": [
            {
                "service": "probe.test",
                "metrics": [
                    "eosc.test.api"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-05-24",
        "name": "ARGO_TEST34",
        "description": "Profile for metrics with HOSTALIAS",
        "services": [
            {
                "service": "b2handle",
                "metrics": [
                    "eudat.b2handle.handle.api-crud"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-06-09",
        "name": "ARGO_TEST35",
        "description": "Profile endpoints with duplicate sites",
        "services": [
            {
                "service": "b2handle.handle.api",
                "metrics": [
                    "eudat.b2handle.handle.api-crud"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-06-23",
        "name": "ARGO_TEST36",
        "description":
            "Profile endpoints with attributes with overrides and default "
            "value",
        "services": [
            {
                "service": "b2handle.handle.test",
                "metrics": [
                    "eudat.b2handle.handle.api-crud"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-06-23",
        "name": "ARGO_TEST37",
        "description": "Profile with endpoints using metrics which require "
                       "URL, but there's no URL in the topology",
        "services": [
            {
                "service": "gitlab",
                "metrics": [
                    "eudat.gitlab.liveness",
                    "generic.tcp.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-06-26",
        "name": "ARGO_TEST38",
        "description": "Profile with endpoints using metrics which require "
                       "URL, but there's no URL in the topology (here "
                       "with overrides)",
        "services": [
            {
                "service": "gitlab2",
                "metrics": [
                    "eudat.gitlab.liveness",
                    "generic.tcp.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-06-30",
        "name": "ARGO_TEST39",
        "description": "Profile for testing default port overrides using "
                       "extensions - some endpoints have overrides",
        "services": [
            {
                "service": "eu.ni4os.hpc.ui",
                "metrics": [
                    "generic.ssh.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-06-30",
        "name": "ARGO_TEST40",
        "description": "Profile for testing default port overrides using "
                       "extensions - no overrides",
        "services": [
            {
                "service": "eu.ni4os.hpc.ui2",
                "metrics": [
                    "generic.ssh.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-10-03",
        "name": "ARGO_TEST41",
        "description": "Profile for metrics with attributes not defined "
                       "anywhere",
        "services": [
            {
                "service": "gridproxy",
                "metrics": [
                    "srce.gridproxy.get",
                    "srce.gridproxy.validity"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-10-03",
        "name": "ARGO_TEST42",
        "description": "Profile for APEL metrics",
        "services": [
            {
                "service": "APEL",
                "metrics": [
                    "argo.APEL-Pub",
                    "argo.APEL-Sync"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-10-04",
        "name": "ARGO_TEST43",
        "description": "Profile for endpoints running generic.http.connect "
                       "without defined URL",
        "services": [
            {
                "service": "egi.AppDB",
                "metrics": [
                    "generic.http.connect",
                    "generic.certificate.validity"
                ]
            },
            {
                "service": "web.check",
                "metrics": [
                    "generic.http.connect",
                    "generic.certificate.validity"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-10-06",
        "name": "ARGO_TEST44",
        "description": "Profile for metrics with dashes in attribute names",
        "services": [
            {
                "service": "ch.cern.cvmfs.stratum.1",
                "metrics": [
                    "argo.cvmfs-stratum-1.status"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-10-26",
        "name": "ARGO_TEST45",
        "description": "Profile with passive metrics",
        "services": [
            {
                "service": "SRM",
                "metrics": [
                    "eu.egi.SRM-All",
                    "eu.egi.SRM-VOGet",
                    "eu.egi.SRM-VOLsDir"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-11-23",
        "name": "ARGO_TEST46",
        "description": "Profile with metrics with info in info_bdii_* tag",
        "services": [
            {
                "service": "SRM",
                "metrics": [
                    "generic.certificate.validity-srm"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-12-01",
        "name": "ARGO_TEST47",
        "description": "Profile with endpoint with & in URL",
        "services": [
            {
                "service": "eu.eosc.generic.oai-pmh",
                "metrics": [
                    "generic.oai-pmh.validity"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-12-18",
        "name": "ARGO_TEST48",
        "description": "Profile with XRootD tests",
        "services": [
            {
                "service": "XRootD",
                "metrics": [
                    "egi.xrootd.readwrite"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-12-19",
        "name": "ARGO_TEST49",
        "description": "Profile with XRootD and webdav tests",
        "services": [
            {
                "service": "webdav",
                "metrics": [
                    "cern.webdav.status"
                ]
            },
            {
                "service": "XRootD",
                "metrics": [
                    "egi.xrootd.readwrite"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2023-12-20",
        "name": "ARGO_TEST50",
        "description": "Profile for testing duplicate entries in the topology",
        "services": [
            {
                "service": "webdav",
                "metrics": [
                    "cern.webdav.status"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2024-01-03",
        "name": "ARGO_TEST51",
        "description": "Profile for testing subscription generation",
        "services": [
            {
                "service": "argo.webui",
                "metrics": [
                    "generic.http.ar-argoui-ni4os",
                    "generic.tcp.connect"
                ]
            },
            {
                "service": "argo.test",
                "metrics": [
                    "generic.certificate.validity"
                ]
            },
            {
                "service": "SRM",
                "metrics": [
                    "eu.egi.SRM-All"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2024-01-03",
        "name": "ARGO_TEST52",
        "description":
            "Profile for testing subscription generation with hostname ids",
        "services": [
            {
                "service": "eu.eosc.generic.oai-pmh",
                "metrics": [
                    "generic.oai-pmh.validity"
                ]
            },
            {
                "service": "eu.eosc.portal.services.url",
                "metrics": [
                    "generic.http.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2024-01-15",
        "name": "ARGO_TEST53",
        "description": "Profile for testing non-fallback attributes defined in "
                       "all endpoints",
        "services": [
            {
                "service": "eu.egi.readonly.xrootd",
                "metrics": [
                    "egi.xrootd.readonly"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2024-01-16",
        "name": "ARGO_TEST54",
        "description":
            "Profile for testing situations with _SERVICEVO_FQAN variable",
        "services": [
            {
                "service": "ARC-CE",
                "metrics": [
                    "org.nordugrid.ARC-CE-SRM-submit"
                ]
            },
            {
                "service": "argo.test",
                "metrics": [
                    "generic.tcp.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2024-02-19",
        "name": "ARGO_TEST55",
        "description": "Profile for testing generation of passive metrics with "
                       "missing parent",
        "services": [
            {
                "service": "APEL",
                "metrics": [
                    "argo.APEL-Pub",
                    "argo.APEL-Sync",
                    "org.apel.APEL-Pub"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2024-07-09",
        "name": "ARGO_TEST56",
        "description": "Profile with metrics with SILENCED flag",
        "services": [
            {
                "service": "argo.mon",
                "metrics": [
                    "argo.AMSPublisher-Check",
                    "org.nordugrid.ARC-CE-clean",
                    "org.nordugrid.ARC-CE-monitor"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2025-03-12",
        "name": "ARGO_TEST57",
        "description": "Profile for testing optional attributes",
        "services": [
            {
                "service": "argo.test.json.api",
                "metrics": [
                    "generic.json.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2025-10-09",
        "name": "ARGO_TEST58",
        "description": "Profile with repeating service types 1",
        "services": [
            {
                "service": "eudat.cms.confluence",
                "metrics": [
                    "generic.http.connect",
                    "generic.tcp.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2025-10-09",
        "name": "ARGO_TEST59",
        "description": "Profile with repeating service types 2",
        "services": [
            {
                "service": "eudat.cms.confluence",
                "metrics": [
                    "generic.http.connect"
                ]
            }
        ]
    },
    {
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "date": "2026-09-22",
        "name": "ARGO_TEST60",
        "description": "Profile for testing setting PATH, PORT, SSL \
                        via info_ext attribs",
        "services": [
            {
                "service": "argo.grafana",
                "metrics": [
                    "generic.http.connect"
                ]
            }
        ]
    }
]

mock_local_topology = [
    {
        "group": "SRCE",
        "service": "argo.mon",
        "hostname": "argo-mon-devel.egi.eu",
        "tags": {}
    },
    {
        "group": "SRCE",
        "service": "argo.mon",
        "hostname": "argo-mon-devel.ni4os.eu",
        "tags": {}
    },
    {
        "group": "argo-public-production",
        "service": "argo.api",
        "hostname": "api.argo.grnet.gr",
        "tags": {}
    }
]

faulty_local_topology = [
    {
        "group": "SRCE",
        "hostname": "argo-mon-devel.egi.eu",
        "tags": {}
    },
    {
        "group": "SRCE",
        "service": "argo.mon",
        "hostname": "argo-mon-devel.ni4os.eu",
        "tags": {}
    },
    {
        "group": "argo-public-production",
        "service": "argo.api",
        "hostname": "api.argo.grnet.gr",
        "tags": {}
    }
]

mock_topology_with_hostname_in_tag = [
    {
        "date": "2022-09-22",
        "group": "test1",
        "type": "SERVICEGROUPS",
        "service": "eu.eosc.portal.services.url",
        "hostname": "hostname1.argo.com_hostname1_id",
        "ngi": "TEST",
        "tags": {
            "hostname": "hostname1.argo.com",
            "info_ID": "hostname1_id",
            "info_URL": "https://hostname1.argo.com/path",
            "service_tags": "applications, batch systems"
        }
    },
    {
        "date": "2022-09-22",
        "group": "test2.test",
        "type": "SERVICEGROUPS",
        "service": "eu.eosc.portal.services.url",
        "hostname": "hostname2.argo.eu_second.id",
        "ngi": "TEST",
        "tags": {
            "hostname": "hostname2.argo.eu",
            "info_ID": "second.id",
            "info_URL": "https://hostname2.argo.eu",
            "service_tags": "FAIR, bioinformatics, bash, HPC, kubernetes, "
                            "docker, workflows, workflow-management-system"
        }
    },
    {
        "date": "2022-09-22",
        "group": "group3",
        "type": "SERVICEGROUPS",
        "service": "eu.eosc.portal.services.url",
        "hostname": "hostname3.argo.eu_test.id",
        "ngi": "TEST",
        "tags": {
            "hostname": "hostname3.argo.eu",
            "info_ID": "test.id",
            "info_URL": "http://hostname3.argo.eu/"
        }
    },
    {
        "date": "2024-01-03",
        "group": "srce",
        "type": "SERVICEGROUPS",
        "service": "eu.eosc.generic.oai-pmh",
        "hostname": "dabar.srce.hr_dabar_id",
        "ngi": "TEST",
        "tags": {
            "hostname": "dabar.srce.hr",
            "info_ID": "dabar_id",
            "info_URL": "https://dabar.srce.hr/oai?verb=Identify"
        }
    },
    {
        "date": "2024-01-03",
        "group": "srce",
        "type": "SERVICEGROUPS",
        "service": "eu.eosc.generic.oai-pmh",
        "hostname": "hrcak.srce.hr_hrcak.id",
        "ngi": "TEST",
        "tags": {
            "hostname": "hrcak.srce.hr",
            "info_ID": "hrcak.id",
            "info_URL": "https://hrcak.srce.hr/oai?verb=Identify"
        }
    }
]

mock_topology_with_hostname_wrong_chars = [
    {
        "date": "2023-01-26",
        "group": "test1",
        "type": "SERVICEGROUPS",
        "service": "eu.eosc.portal.services.url",
        "hostname": "hostname1.argo.com_hostname1 id",
        "ngi": "TEST",
        "tags": {
            "hostname": "hostname1.argo.com",
            "info_ID": "hostname1 id",
            "info_URL": "https://hostname1.argo.com/path",
            "service_tags": "applications, batch systems"
        }
    },
    {
        "date": "2022-09-22",
        "group": "test2.test",
        "type": "SERVICEGROUPS",
        "service": "eu.eosc.portal.services.url",
        "hostname": "hostname2.argo.eu_second/id",
        "ngi": "TEST",
        "tags": {
            "hostname": "hostname2.argo.eu",
            "info_ID": "second/id",
            "info_URL": "https://hostname2.argo.eu",
            "service_tags": "FAIR, bioinformatics, bash, HPC, kubernetes, "
                            "docker, workflows, workflow-management-system"
        }
    },
    {
        "date": "2022-09-22",
        "group": "group3",
        "type": "SERVICEGROUPS",
        "service": "eu.eosc.portal.services.url",
        "hostname": "hostname3.argo.eu_test.id",
        "ngi": "TEST",
        "tags": {
            "hostname": "hostname3.argo.eu",
            "info_ID": "test.id",
            "info_URL": "http://hostname3.argo.eu/"
        }
    }
]

mock_topology_with_duplicate_entries = [
    {
        "date": "2023-12-20",
        "group": "UNI-EXAMPLE",
        "type": "SITES",
        "service": "webdav",
        "hostname": "xrootd.example.de",
        "ngi": "TEST",
        "notifications": {
            "enabled": True
        },
        "tags": {
            "info_ID": "xxxxxxx",
            "info_URL": "https://xrootd.example.de:1094/cephfs/grid/ops",
            "info_ext_ARGO_WEBDAV_OPS_URL":
                "https://xrootd.example.de:1094//cephfs/grid/ops",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, atlas"
        }
    },
    {
        "date": "2023-12-20",
        "group": "UNI-TEST",
        "type": "SITES",
        "service": "webdav",
        "hostname": "webdav.test.de",
        "ngi": "TEST",
        "notifications": {
            "enabled": True
        },
        "tags": {
            "info_ID": "xxxxxx",
            "info_URL": "davs://webdav.test.de:2880",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, tier2, atlas"
        }
    },
    {
        "date": "2023-12-20",
        "group": "UNI-TEST",
        "type": "SITES",
        "service": "webdav",
        "hostname": "webdav.test.de",
        "ngi": "TEST",
        "notifications": {},
        "tags": {
            "info_ID": "xxxxx",
            "info_URL": "https://webdav.test.de:2881/ops/",
            "info_ext_ARGO_WEBDAV_OPS_URL": "https://webdav.test.de:2881/ops/",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, wlcg, tier2"
        }
    },
    {
        "date": "2023-12-20",
        "group": "CERN-PROD",
        "type": "SITES",
        "service": "webdav",
        "hostname": "eosatlas.cern.ch",
        "ngi": "CERN",
        "notifications": {},
        "tags": {
            "info_ID": "xxxxx",
            "info_URL": "https://eosatlas.cern.ch//eos/atlas/opstest",
            "info_ext_ARGO_WEBDAV_OPS_URL":
                "https://eosatlas.cern.ch//eos/atlas/opstest/egi/",
            "info_ext_ARGO_WEBDAV_SKIP_DIR_TEST": "0",
            "monitored": "1",
            "production": "1",
            "scope": "EGI, atlas"
        }
    },
]

mock_attributes = {
    "local": {
        "global_attributes": [
            {
                "attribute": "OIDC_TOKEN_FILE",
                "value": "/etc/sensu/certs/oidc"
            },
            {
                "attribute": "OIDC_ACCESS_TOKEN",
                "value": "/etc/sensu/certs/oidc"
            },
            {
                "attribute": "OS_APPDB_IMAGE",
                "value": "xxxx"
            },
            {
                "attribute": "X509_USER_PROXY",
                "value": "/etc/sensu/certs/userproxy.pem"
            },
            {
                "attribute": "VONAME",
                "value": "test"
            },
            {
                "attribute": "ARC_GOOD_SES",
                "value": "good_ses_file=/var/lib/gridprobes/ops/GoodSEs"
            },
            {
                "attribute": "B2HANDLE_PREFIX",
                "value": "234.234"
            }
        ],
        "host_attributes": [],
        "metric_parameters": []
    }
}

mock_attributes_with_robot = {
    "robot": {
        "global_attributes": [
            {
                "attribute": "ROBOT_CERT",
                "value": "/etc/nagios/robot/robot.pem"
            },
            {
                "attribute": "ROBOT_KEY",
                "value": "/etc/nagios/robot/robot.key"
            }
        ],
        "host_attributes": [],
        "metric_parameters": []
    },
    "local": {
        "global_attributes": [
            {
                "attribute": "NAGIOS_HOST_CERT",
                "value": "/etc/nagios/certs/hostcert.pem"
            },
            {
                "attribute": "NAGIOS_HOST_KEY",
                "value": "/etc/nagios/certs/hostcert.key"
            }
        ],
        "host_attributes": [],
        "metric_parameters": []
    }
}

mock_default_ports = {
    "SITE_BDII_PORT": "2170",
    "BDII_PORT": "2170",
    "MDS_PORT": "2135",
    "GRIDFTP_PORT": "2811",
    "GRAM_PORT": "2119",
    "RB_PORT": "7772",
    "WMS_PORT": "7772",
    "MYPROXY_PORT": "7512",
    "RGMA_PORT": "8443",
    "TOMCAT_PORT": "8443",
    "LL_PORT": "9002",
    "LB_PORT": "9000",
    "WMPROXY_PORT": "7443",
    "SRM1_PORT": "8443",
    "SRM2_PORT": "8443",
    "GSISSH_PORT": "1975",
    "FTS_PORT": "8446",
    "VOMS_PORT": "8443",
    "GRIDICE_PORT": "2136",
    "CREAM_PORT": "8443",
    "QCG-COMPUTING_PORT": "19000",
    "QCG-NOTIFICATION_PORT": "19001",
    "QCG-BROKER_PORT": "8443",
    "SSH_PORT": "22",
    "STOMP_PORT": "6163",
    "STOMP_SSL_PORT": "6162",
    "OPENWIRE_PORT": "6166",
    "OPENWIRE_SSL_PORT": "6167",
    "HTCondorCE_PORT": "9619",
    "CVMFS-Stratum-1_PORT": "8000"
}

LOGNAME = "argo-scg.generator"
DUMMY_LOGGER = logging.getLogger(LOGNAME)
DUMMY_LOG = [f"INFO:{LOGNAME}:dummy"]


def _log_dummy():
    DUMMY_LOGGER.info("dummy")


class CheckConfigurationTests(unittest.TestCase):
    def test_generate_checks_configuration(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST1"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent=["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 30 "
                               "-r argo.eu "
                               "-u /ni4os/report-ar/Critical/"
                               "NGI?accept=csv "
                               "--ssl --onredirect follow",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_http_ar_argoui_ni4os == "
                            "'generic.http.ar-argoui-ni4os'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.http.ar-argoui-ni4os",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_checks_configuration_if_multiple_agents_with_warning(
            self
    ):
        with self.assertLogs(LOGNAME) as log:
            generator = ConfigurationGenerator(
                metrics=mock_metrics,
                profiles=["ARGO_TEST1"],
                metric_profiles=mock_metric_profiles,
                topology=mock_topology,
                attributes=mock_attributes,
                secrets_file="",
                default_ports=mock_default_ports,
                tenant="MOCK_TENANT",
                default_agent=[
                    "sensu-agent-mock_tenant.example.com",
                    "sensu-agent-mock_tenant2.example.com"
                ]
            )
        checks = generator.generate_checks(
            publish=True, namespace="mockspace"
        )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 30 "
                               "-r argo.eu "
                               "-u /ni4os/report-ar/Critical/"
                               "NGI?accept=csv "
                               "--ssl --onredirect follow",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_http_ar_argoui_ni4os == "
                            "'generic.http.ar-argoui-ni4os'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.http.ar-argoui-ni4os",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(
            log.output, [
                f"WARNING:{LOGNAME}:MOCK_TENANT: Multiple agents defined for "
                f"tenant - using sensu-agent-mock_tenant.example.com for "
                f"checks' configuration"
            ]
        )

    def test_generate_checks_configuration_if_agents_configuration(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST1"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent=[
                "sensu-agent-mock_tenant.example.com",
                "sensu-agent-mock_tenant2.example.com"
            ],
            agents_config={
                "sensu-agent-mock_tenant2.example.com": ["argo.test"]
            }
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 30 "
                               "-r argo.eu "
                               "-u /ni4os/report-ar/Critical/"
                               "NGI?accept=csv "
                               "--ssl --onredirect follow",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant2.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_http_ar_argoui_ni4os == "
                            "'generic.http.ar-argoui-ni4os'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.http.ar-argoui-ni4os",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_checks_configuration_with_faulty_metrics(self):
        generator = ConfigurationGenerator(
            metrics=faulty_metrics,
            profiles=["ARGO_TEST1"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent=["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(
            log.output, [
                f"WARNING:{LOGNAME}:MOCK_TENANT: Skipping check "
                f"generic.http.ar-argoui-ni4os: Missing key 'timeout'"
            ]
        )

    def test_generate_checks_configuration_for_default_tenant(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST1"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="default",
            default_agent=["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=False, namespace="default"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 30 "
                               "-r argo.eu "
                               "-u /ni4os/report-ar/Critical/"
                               "NGI?accept=csv "
                               "--ssl --onredirect follow",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.http.ar-argoui-ni4os",
                        "namespace": "default",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "default"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "default",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "default"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_checks_configuration_without_publish(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST1"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=False, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 30 "
                               "-r argo.eu "
                               "-u /ni4os/report-ar/Critical/"
                               "NGI?accept=csv "
                               "--ssl --onredirect follow",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_http_ar_argoui_ni4os == "
                            "'generic.http.ar-argoui-ni4os'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.http.ar-argoui-ni4os",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_hardcoded_attributes(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST2", "ARGO_TEST3"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                               "-H {{ .labels.hostname }} -t 60 "
                               "-w 30 -c 0 -N --altnames --rootcert-dir "
                               "/etc/grid-security/certificates "
                               "-C /etc/sensu/certs/hostcert.pem "
                               "-K /etc/sensu/certs/hostkey.pem -p 2119",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_gram_certvalidity == "
                            "'eu.egi.GRAM-CertValidity'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.GRAM-CertValidity",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                               "-H {{ .labels.hostname }} -t 60 -w 30 -c 0 "
                               "-N --altnames --rootcert-dir "
                               "/etc/grid-security/certificates "
                               "--rootcert-file "
                               "/etc/pki/tls/certs/ca-bundle.crt "
                               "-C /etc/sensu/certs/hostcert.pem "
                               "-K /etc/sensu/certs/hostkey.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_certificate_validity == "
                            "'generic.certificate.validity'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.certificate.validity",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_ftp "
                               "-H {{ .labels.hostname }} -t 60 -p 2811",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nagios_gridftp_check == "
                            "'org.nagios.GridFTP-Check'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nagios.GridFTP-Check",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                },
                {
                    "command": "/usr/libexec/argo/probes/cert/"
                               "CertLifetime-probe -t 60 "
                               "-f /etc/sensu/certs/hostcert.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "srce.certificate.validity-moncert",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_robot_cert_key(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST2"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes_with_robot,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=False, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                               "-H {{ .labels.hostname }} -t 60 "
                               "-w 30 -c 0 -N --altnames --rootcert-dir "
                               "/etc/grid-security/certificates "
                               "-C /etc/nagios/robot/robot.pem "
                               "-K /etc/nagios/robot/robot.key -p 2119",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_gram_certvalidity == "
                            "'eu.egi.GRAM-CertValidity'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.GRAM-CertValidity",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                               "-H {{ .labels.hostname }} -t 60 -w 30 -c 0 "
                               "-N --altnames --rootcert-dir "
                               "/etc/grid-security/certificates "
                               "--rootcert-file "
                               "/etc/pki/tls/certs/ca-bundle.crt "
                               "-C /etc/nagios/robot/robot.pem "
                               "-K /etc/nagios/robot/robot.key",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_certificate_validity == "
                            "'generic.certificate.validity'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.certificate.validity",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                },
                {
                    "command": "/usr/libexec/argo/probes/cert/"
                               "CertLifetime-probe -t 60 "
                               "-f /etc/nagios/certs/hostcert.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "srce.certificate.validity-moncert",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_SSL(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST7"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 60 --link "
                               "--onredirect follow "
                               "{{ .labels.ssl | default \" \" }} "
                               "{{ .labels.generic_http_connect_port | "
                               "default \" \" }} "
                               "{{ .labels.generic_http_connect_path | "
                               "default \" \" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_http_connect == "
                            "'generic.http.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.http.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_various_URLs(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST8"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_webdav "
                               "-H {{ .labels.hostname }} -t 600 -v -v "
                               "--no-crls "
                               "-u {{ .labels.webdav_url }} "
                               "-E /etc/sensu/certs/userproxy.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.ch_cern_webdav == "
                            "'ch.cern.WebDAV'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "ch.cern.WebDAV",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_webdav "
                               "-H {{ .labels.hostname }} -t 600 -v -v "
                               "--no-crls --dynafed --fixed-content-length "
                               "-u {{ .labels.endpoint_url }} "
                               "-E /etc/sensu/certs/userproxy.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.ch_cern_webdav_dynafed == "
                            "'ch.cern.WebDAV-dynafed'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "ch.cern.WebDAV-dynafed",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/"
                               "es.upv.grycap.im/probeim.py -t 60 -l NONE "
                               "--url {{ .labels.info_url }} "
                               "--token /etc/sensu/certs/oidc",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_grycap_im_check == "
                            "'eu.egi.grycap.IM-Check'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.grycap.IM-Check",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_BDII(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST10"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_bdii_entries "
                               "-H {{ .labels.hostname }} -t 60 -c 40:1 "
                               "-w 20:1 -b {{ .labels.bdii_dn }} "
                               "-p 2170",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_bdii_entries == "
                            "'org.bdii.Entries'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.bdii.Entries",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/midmon/"
                               "check_bdii_entries_num "
                               "-H {{ .labels.hostname }} -t 60 -c 1:1 "
                               "-f {{ .labels.org_nagios_glue2_check_f }} "
                               "-b {{ .labels.glue2_bdii_dn }} -p 2170",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nagios_glue2_check == "
                            "'org.nagios.GLUE2-Check'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nagios.GLUE2-Check",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_mandatory_extensions(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST12"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/libexec/argo-monitoring/probes/"
                               "nagios-plugin-dynamic-dns/"
                               "nagios-plugin-dynamic-dns.sh "
                               "-H {{ .labels.hostname }} -t 120 "
                               "--endpoint-name {{ .labels.endpoint_name }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_dyndns_check == "
                            "'eu.egi.cloud.DynDNS-Check'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.DynDNS-Check",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_optional_extensions(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST19"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_arcce_submit "
                               "-H {{ .labels.hostname }} "
                               "--job-tag dist-stage-srm --termination-service "
                               "org.nordugrid.ARC-CE-SRM-result-test"
                               " --test dist-stage-srm "
                               "-O service_suffix=-test "
                               "--command-file /var/nagios/rw/nagios.cmd "
                               "--how-invoked nagios -O good_ses_file="
                               "/var/lib/gridprobes/ops/GoodSEs --voms test "
                               "--user-proxy /etc/sensu/certs/userproxy.pem "
                               "{{ .labels.memory_limit__arc_ce_memory_limit "
                               "| default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nordugrid_arc_ce_srm_submit == "
                            "'org.nordugrid.ARC-CE-SRM-submit'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nordugrid.ARC-CE-SRM-submit",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_arcce_submit "
                               "-H {{ .labels.hostname }} "
                               "--termination-service "
                               "org.nordugrid.ARC-CE-result-test"
                               " --test dist-caversion --test "
                               "dist-sw-csh --test dist-sw-gcc "
                               "--test dist-sw-python --test dist-sw-perl "
                               "-O service_suffix=-test "
                               "--command-file /var/nagios/rw/nagios.cmd "
                               "--how-invoked nagios --voms test "
                               "--user-proxy /etc/sensu/certs/userproxy.pem "
                               "{{ .labels.memory_limit__arc_ce_memory_limit "
                               "| default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nordugrid_arc_ce_submit == "
                            "'org.nordugrid.ARC-CE-submit'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nordugrid.ARC-CE-submit",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_different_parameter_exts(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST20"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 30 -f \"follow\" "
                               "{{ .labels.u__rm_path | default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels."
                            "eu_seadatanet_org_replicationmanager_check == "
                            "'eu.seadatanet.org.replicationmanager-check'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.seadatanet.org.replicationmanager-check",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/"
                               "sdc-replication-manager/"
                               "replication_manager_check.py "
                               "-H {{ .labels.hostname }} -t 30 "
                               "{{ .labels.r__rm_path | default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels."
                            "eu_seadatanet_org_replicationmanager_check_"
                            "status == "
                            "'eu.seadatanet.org.replicationmanager-check-"
                            "status'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.seadatanet.org.replicationmanager-check-"
                                "status",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_openstack_check_configuration(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST13"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo-monitoring/probes/fedcloud/"
                               "cloudinfo.py -t 300 "
                               "--endpoint {{ .labels.os_keystone_url }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_infoprovider == "
                            "'eu.egi.cloud.InfoProvider'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.InfoProvider",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/fedcloud/"
                               "swiftprobe.py -t 300 "
                               "--endpoint {{ .labels.os_keystone_url }} "
                               "--access-token /etc/sensu/certs/oidc",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_openstack_swift == "
                            "'eu.egi.cloud.OpenStack-Swift'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.OpenStack-Swift",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/fedcloud/"
                               "novaprobe.py -t 300 -v "
                               "--access-token /etc/sensu/certs/oidc "
                               "--appdb-image xxxx "
                               "--endpoint {{ .labels.os_keystone_url }} "
                               "--cert /etc/sensu/certs/userproxy.pem "
                               "{{ .labels.region__os_region | default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_openstack_vm == "
                            "'eu.egi.cloud.OpenStack-VM'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.OpenStack-VM",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-t 120 -p {{ .labels.os_keystone_port | "
                               "default \"443\" }} "
                               "-H {{ .labels.os_keystone_host }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nagios_keystone_tcp == "
                            "'org.nagios.Keystone-TCP'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nagios.Keystone-TCP",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_pakiti_check_configuration(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST15"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/grid-monitoring/probes/eu.egi.sec/"
                               "probes/check_pakiti_vuln "
                               "-H {{ .labels.hostname }} -t 30 --vo test "
                               "--cert /etc/sensu/certs/hostcert.pem "
                               "--key /etc/sensu/certs/hostkey.pem "
                               "--site {{ .labels.site }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_sec_arcce_pakiti_check == "
                            "'eu.egi.sec.ARCCE-Pakiti-Check'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.sec.ARCCE-Pakiti-Check",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_SITE_BDII(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST16"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/lib64/nagios/plugins/srm/srm_probe.py "
                               "-H {{ .labels.hostname }} -t 300 -d "
                               "-p eu.egi.SRM -s test --se-timeout 260 "
                               "--voname test "
                               "-X /etc/sensu/certs/userproxy.pem "
                               "{{ .labels.ldap_url__site_bdii | "
                               "default \"\" }} "
                               "{{ .labels.endpoint__surl | default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_srm_all == "
                            "'eu.egi.SRM-All'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.SRM-All",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_servicevo_without_voname(self):
        attributes = {
            "local": {
                "global_attributes": [
                    {
                        "attribute": "X509_USER_PROXY",
                        "value": "/etc/sensu/certs/userproxy.pem"
                    }
                ],
                "host_attributes": [],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST16"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/lib64/nagios/plugins/srm/srm_probe.py "
                               "-H {{ .labels.hostname }} -t 300 -d "
                               "-p eu.egi.SRM --se-timeout 260 "
                               "-X /etc/sensu/certs/userproxy.pem "
                               "{{ .labels.ldap_url__site_bdii | "
                               "default \"\" }} "
                               "{{ .labels.endpoint__surl | default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_srm_all == "
                            "'eu.egi.SRM-All'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.SRM-All",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_ARC_GOOD_SES(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST17"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_arcce_submit "
                               "-H {{ .labels.hostname }} "
                               "--job-tag dist-stage-srm --termination-service "
                               "org.nordugrid.ARC-CE-SRM-result-test"
                               " --test dist-stage-srm "
                               "-O service_suffix=-test "
                               "--command-file /var/nagios/rw/nagios.cmd "
                               "--how-invoked nagios "
                               "-O good_ses_file=/var/lib/gridprobes/ops/"
                               "GoodSEs --voms test "
                               "--user-proxy /etc/sensu/certs/userproxy.pem "
                               "{{ .labels.memory_limit__arc_ce_memory_limit "
                               "| default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nordugrid_arc_ce_srm_submit == "
                            "'org.nordugrid.ARC-CE-SRM-submit'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nordugrid.ARC-CE-SRM-submit",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_HOSTDN(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST18"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/libexec/grid-monitoring/probes/"
                               "org.qoscosgrid/broker/qcg-broker-probe "
                               "-H {{ .labels.hostname }} -t 600 -p 8443 "
                               "-n {{ .labels.info_hostdn }} "
                               "-x /etc/sensu/certs/userproxy.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.pl_plgrid_qcg_broker == "
                            "'pl.plgrid.QCG-Broker'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "pl.plgrid.QCG-Broker",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_local_topology(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST21"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                               "-H {{ .labels.hostname }} -t 60 "
                               "-w 30 -c 0 -N --altnames --rootcert-dir "
                               "/etc/grid-security/certificates --rootcert-file"
                               " /etc/pki/tls/certs/ca-bundle.crt "
                               "-C /etc/sensu/certs/hostcert.pem "
                               "-K /etc/sensu/certs/hostkey.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_certificate_validity == "
                            "'generic.certificate.validity'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.certificate.validity",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_secrets(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST22"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="/path/to/secrets",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "source /path/to/secrets ; "
                               "export $(cut -d= -f1 /path/to/secrets) ; "
                               "/usr/libexec/argo/probes/grnet-agora/"
                               "checkhealth -H {{ .labels.hostname }} -v -i "
                               "-u $AGORA_USERNAME -p $AGORA_PASSWORD",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.grnet_agora_healthcheck == "
                            "'grnet.agora.healthcheck'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "grnet.agora.healthcheck",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_secrets_with_dots(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST23"],
            metric_profiles=mock_metric_profiles,
            topology=mock_local_topology,
            attributes=mock_attributes,
            secrets_file="/path/to/secrets",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "source /path/to/secrets ; "
                               "export $(cut -d= -f1 /path/to/secrets) ; "
                               "/usr/libexec/argo-monitoring/probes/argo/"
                               "web-api -H {{ .labels.hostname }} -t 120 "
                               "--tenant EGI --rtype ar --unused-reports "
                               "Cloud Critical-Fedcloud Fedcloud NGIHRTest "
                               "--day 1 --token $ARGO_API_TOKEN",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_api_check == "
                            "'argo.API-Check'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.API-Check",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_if_NOPUBLISH(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST24"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_arcce_monitor "
                               "-O service_suffix=-test -O "
                               "lfc_host=dummy -O se_host=dummy --timeout 900 "
                               "--command-file /var/nagios/rw/nagios.cmd "
                               "--how-invoked nagios --user-proxy "
                               "/etc/sensu/certs/userproxy.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.org_nordugrid_arc_ce_test == "
                            "'org.nordugrid.ARC-CE-test'"
                        ]
                    },
                    "interval": 1200,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nordugrid.ARC-CE-test",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": []
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_metric_parameter_override(self):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [],
                "metric_parameters": [
                    {
                        "hostname": "argo.ni4os.eu",
                        "metric": "generic.tcp.connect",
                        "parameter": "-p",
                        "value": "80"
                    },
                    {
                        "hostname": "argo-devel.ni4os.eu",
                        "metric": "generic.tcp.connect",
                        "parameter": "-p",
                        "value": "90"
                    },
                    {
                        "hostname": "argo.ni4os.eu",
                        "metric": "argo.APEL-Pub",
                        "parameter": "--ok-search",
                        "value": "yes"
                    }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST25"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo/probes/http_parser/"
                               "check_http_parser -t 120 "
                               "-H goc-accounting.grid-support.ac.uk "
                               "-u {{ .labels.argo_apel_pub_u }} "
                               "--warning-search WARN --critical-search ERROR "
                               "--ok-search {{ .labels.argo_apel_pub_ok_search "
                               "| default \"OK\" }} --case-sensitive",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_apel_pub == 'argo.APEL-Pub'"
                        ]
                    },
                    "interval": 43200,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.APEL-Pub",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssh "
                               "-H {{ .labels.hostname }} -t 60 "
                               "{{ .labels.generic_ssh_test_port | "
                               "default \" \" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_ssh_test == "
                            "'generic.ssh.test'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.ssh.test",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 "
                               "-p {{ .labels.generic_tcp_connect_p | "
                               "default \"443\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_host_attribute_override(self):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [{
                    "hostname": "argo.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_USERNAME",
                    "value": "$NI4OS_NAGIOS_FRESHNESS_USERNAME"
                }, {
                    "hostname": "argo.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_PASSWORD",
                    "value": "$NI4OS_NAGIOS_FRESHNESS_PASSWORD"
                }, {
                    "hostname": "argo-devel.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_PASSWORD",
                    "value": "$NI4OS_DEVEL_NAGIOS_FRESHNESS_PASSWORD"
                }, {
                    "hostname": "b2handle3.test.com",
                    "attribute": "B2HANDLE_PREFIX",
                    "value": "123456"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST26"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "source  ; export $(cut -d= -f1 ) ; "
                               "/usr/libexec/argo/probes/nagios/check_nagios "
                               "-H {{ .labels.hostname }} -t 60 "
                               "--nagios-service org.nagios.NagiosCmdFile "
                               "--username "
                               "{{ .labels.nagios_freshness_username }} "
                               "--password "
                               "{{ .labels.nagios_freshness_password }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_nagios_freshness_simple_login "
                            "== 'argo.nagios.freshness-simple-login'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.nagios.freshness-simple-login",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo/probes/eudat-b2handle/"
                               "check_handle_resolution.pl -t 10 "
                               "--prefix {{ .labels.b2handle_prefix }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels."
                            "eudat_b2handle_handle_api_healthcheck_resolve "
                            "== 'eudat.b2handle.handle.api-healthcheck-resolve'"
                        ]
                    },
                    "interval": 600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eudat.b2handle.handle.api-healthcheck-resolve",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_host_attribute_override_global(
            self
    ):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [{
                    "hostname": "argo.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_USERNAME",
                    "value": "$NI4OS_NAGIOS_FRESHNESS_USERNAME"
                }, {
                    "hostname": "argo.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_PASSWORD",
                    "value": "$NI4OS_NAGIOS_FRESHNESS_PASSWORD"
                }, {
                    "hostname": "argo-devel.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_PASSWORD",
                    "value": "$NI4OS_DEVEL_NAGIOS_FRESHNESS_PASSWORD"
                }, {
                    "hostname": "b2handle3.test.com",
                    "attribute": "B2HANDLE_PREFIX",
                    "value": "123456"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST26"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "source  ; export $(cut -d= -f1 ) ; "
                               "/usr/libexec/argo/probes/nagios/check_nagios "
                               "-H {{ .labels.hostname }} -t 60 "
                               "--nagios-service org.nagios.NagiosCmdFile "
                               "--username "
                               "{{ .labels.nagios_freshness_username }} "
                               "--password "
                               "{{ .labels.nagios_freshness_password }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_nagios_freshness_simple_login "
                            "== 'argo.nagios.freshness-simple-login'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.nagios.freshness-simple-login",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo/probes/eudat-b2handle/"
                               "check_handle_resolution.pl -t 10 "
                               "--prefix {{ .labels.b2handle_prefix | "
                               "default \"234.234\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels."
                            "eudat_b2handle_handle_api_healthcheck_resolve "
                            "== 'eudat.b2handle.handle.api-healthcheck-resolve'"
                        ]
                    },
                    "interval": 600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eudat.b2handle.handle.api-healthcheck-resolve",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_overridden_secrets_with_dots(
            self
    ):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [{
                    "hostname": "api.argo.grnet.gr",
                    "attribute": "argo.api_TOKEN",
                    "value": "PROD_API_TOKEN"
                }, {
                    "hostname": "argo.devel.api.grnet.gr",
                    "attribute": "argo.api_TOKEN",
                    "value": "DEVEL_API_TOKEN"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST23"],
            metric_profiles=mock_metric_profiles,
            topology=mock_local_topology,
            attributes=attributes,
            secrets_file="/path/to/secrets",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "source /path/to/secrets ; "
                               "export $(cut -d= -f1 /path/to/secrets) ; "
                               "/usr/libexec/argo-monitoring/probes/argo/"
                               "web-api -H {{ .labels.hostname }} -t 120 "
                               "--tenant EGI --rtype ar --unused-reports "
                               "Cloud Critical-Fedcloud Fedcloud NGIHRTest "
                               "--day 1 --token {{ .labels.argo_api_token }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_api_check == "
                            "'argo.API-Check'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.API-Check",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_if_internal_metric(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST27"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo-monitoring/probes/argo/"
                               "ams-publisher-probe "
                               "-s /var/run/argo-nagios-ams-publisher/sock "
                               "-q 'w:metrics+g:published180' -c 4000 -q "
                               "'w:alarms+g:published180' -c 1 -q "
                               "'w:metricsdevel+g:published180' -c 4000",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "interval": 10800,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.AMSPublisher-Check",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "1"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_if_attribute_ending_in_url_not_servicetype_url(
            self
    ):
        attributes = {
            "local": {
                "global_attributes": [
                    {
                        "attribute": "ARGO_OIDC_SP_URL",
                        "value":
                            "https://snf-666522.vm.okeanos.grnet.gr/ni4os-rp/"
                            "auth.php"
                    }
                ],
                "host_attributes": [],
                "metric_parameters": []
            }
        }
        topology = [
            {
                "group": "ARGO",
                "service": "argo.oidc.login",
                "hostname": "aai.argo.eu",
                "tags": {}
            }
        ]
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST28"],
            metric_profiles=mock_metric_profiles,
            topology=topology,
            attributes=attributes,
            secrets_file="/path/to/secrets",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks, [{
                "command":
                    "source /path/to/secrets ; "
                    "export $(cut -d= -f1 /path/to/secrets) ; "
                    "/usr/libexec/argo-monitoring/probes/rciam_probes/"
                    "checklogin -H {{ .labels.hostname }} -t 10 "
                    "-i https://idp.admin.grnet.gr/idp/shibboleth -C "
                    "-e https://mon-dev.rciam.grnet.gr/probes/results "
                    "-u $EDUGAIN_USER -a $EDUGAIN_PASSWORD -s "
                    "https://snf-666522.vm.okeanos.grnet.gr/ni4os-rp/auth.php",
                "subscriptions": [
                    "entity:sensu-agent-mock_tenant.example.com"
                ],
                "handlers": [],
                "interval": 900,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "grnet.rciam.oidc-login-edugain",
                    "namespace": "mockspace",
                    "annotations": {
                        "attempts": "2"
                    },
                    "labels": {
                        "tenants": "MOCK_TENANT"
                    }
                },
                "round_robin": False,
                "pipelines": [
                    {
                        "name": "hard_state",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.grnet_rciam_oidc_login_edugain == "
                        "'grnet.rciam.oidc-login-edugain'"
                    ]
                },
            }]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_if_attribute_ending_in_url_in_extension(self):
        topology = [
            {
                "date": "2022-03-25",
                "group": "CERN-PROD",
                "type": "SITES",
                "service": "webdav",
                "hostname": "hostname.cern.ch",
                "tags": {
                    "info_ID": "xxxxxxx",
                    "info_URL": "https://hostname.cern.ch/atlas/opstest",
                    "monitored": "1",
                    "production": "1",
                    "scope": "EGI"
                }
            },
            {
                "date": "2022-03-25",
                "group": "CERN-PROD",
                "type": "SITES",
                "service": "webdav",
                "hostname": "hostname2.cern.ch",
                "tags": {
                    "info_ID": "xxxxxxx",
                    "info_URL": "https://hostname.cern.ch/atlas/opstest",
                    "info_ext_webdav_URL": "https://meh.cern.ch/atlas/opstest",
                    "monitored": "1",
                    "production": "1",
                    "scope": "EGI"
                }
            }
        ]
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST29"],
            metric_profiles=mock_metric_profiles,
            topology=topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks, [{
                "command":
                    "/usr/lib64/nagios/plugins/check_webdav "
                    "-H {{ .labels.hostname }} -t 600 -v -v --no-crls "
                    "-u {{ .labels.webdav_url }} "
                    "-E /etc/sensu/certs/userproxy.pem",
                "subscriptions": [
                    "entity:sensu-agent-mock_tenant.example.com"
                ],
                "handlers": [],
                "interval": 3600,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "ch.cern.WebDAV",
                    "namespace": "mockspace",
                    "annotations": {
                        "attempts": "2"
                    },
                    "labels": {
                        "tenants": "MOCK_TENANT"
                    }
                },
                "round_robin": False,
                "pipelines": [
                    {
                        "name": "hard_state",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.ch_cern_webdav == 'ch.cern.WebDAV'"
                    ]
                },
            }]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_if_hostname_in_tags(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST30"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology_with_hostname_in_tag,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks, [{
                "command":
                    "/usr/lib64/nagios/plugins/check_http "
                    "-H {{ .labels.hostname }} -t 60 --link "
                    "--onredirect follow {{ .labels.ssl | default \" \" }} "
                    "{{ .labels.generic_http_connect_port | default \" \" }} "
                    "{{ .labels.generic_http_connect_path | default \" \" }}",
                "subscriptions": [
                    "entity:sensu-agent-mock_tenant.example.com"
                ],
                "handlers": [],
                "interval": 300,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "generic.http.connect",
                    "namespace": "mockspace",
                    "annotations": {
                        "attempts": "3"
                    },
                    "labels": {
                        "tenants": "MOCK_TENANT"
                    }
                },
                "round_robin": False,
                "pipelines": [
                    {
                        "name": "hard_state",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.generic_http_connect == "
                        "'generic.http.connect'"
                    ]
                },
            }]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_warning_if_metric_is_missing(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST31"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(
            log.output, [
                f"WARNING:{LOGNAME}:MOCK_TENANT: Missing metric configuration "
                f"for mock.generic.check... Skipping check generation"
            ]
        )

    def test_generate_check_configuration_with_override_default_param(self):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [],
                "metric_parameters": [
                    {
                        "hostname": "test.argo.grnet.gr",
                        "metric": "eosc.test.api",
                        "parameter": "-l",
                        "value": "/var/log/sensu/test.log"
                    }, {
                        "hostname": "test3.argo.grnet.gr",
                        "metric": "eosc.test.api",
                        "parameter": "-l",
                        "value": "/var/log/meh/test.log"
                    }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST33"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/libexec/argo/probes/test/check_api.py "
                               "-t 30 "
                               "{{ .labels.eosc_test_api_l }} "
                               "-u {{ .labels.endpoint_url }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eosc_test_api == 'eosc.test.api'"
                        ]
                    },
                    "interval": 43200,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eosc.test.api",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_hostalias(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST34"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/libexec/argo/probes/eudat-b2handle/"
                               "check_handle_api.py "
                               "-f {{ .labels.eudat_b2handle_handle_api_crud_f "
                               "}} --prefix 234.234",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eudat_b2handle_handle_api_crud == "
                            "'eudat.b2handle.handle.api-crud'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eudat.b2handle.handle.api-crud",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_hostalias_overridden_param(self):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [],
                "metric_parameters": [
                    {
                        "hostname": "b2handle.test.example.com",
                        "metric": "eudat.b2handle.handle.api-crud",
                        "parameter": "-f",
                        "value":
                            "/etc/sensu/b2handle/$HOSTALIAS$/credentials.json"
                    }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST34"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/libexec/argo/probes/eudat-b2handle/"
                               "check_handle_api.py "
                               "-f {{ .labels.eudat_b2handle_handle_api_crud_f "
                               "}} --prefix 234.234",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eudat_b2handle_handle_api_crud == "
                            "'eudat.b2handle.handle.api-crud'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eudat.b2handle.handle.api-crud",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_host_attr_override_default_some(
            self
    ):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [{
                    "hostname": "b2handle3.test.com",
                    "attribute": "B2HANDLE_PREFIX",
                    "value": "123456"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST36"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks,
            [
                {
                    "command": "/usr/libexec/argo/probes/eudat-b2handle/"
                               "check_handle_api.py -f "
                               "{{ .labels.eudat_b2handle_handle_api_crud_f }}"
                               " --prefix {{ .labels.b2handle_prefix | "
                               "default \"234.234\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eudat_b2handle_handle_api_crud "
                            "== 'eudat.b2handle.handle.api-crud'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eudat.b2handle.handle.api-crud",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_url_no_url(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST37"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo/probes/eudat-gitlab/"
                               "check_gitlab_liveness.sh -t 10 "
                               "--url {{ .labels.endpoint_url }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eudat_gitlab_liveness "
                            "== 'eudat.gitlab.liveness'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eudat.gitlab.liveness",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect "
                            "== 'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_url_url_param_overrides_all(
            self
    ):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [],
                "metric_parameters": [
                    {
                        "hostname": "gitlab.test.com",
                        "metric": "eudat.gitlab.liveness",
                        "parameter": "--url",
                        "value": "https://gitlab.test.com"
                    },
                    {
                        "hostname": "gitlab2.test.com",
                        "metric": "eudat.gitlab.liveness",
                        "parameter": "--url",
                        "value": "https://gitlab2.test.com/"
                    }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST38"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo/probes/eudat-gitlab/"
                               "check_gitlab_liveness.sh -t 10 "
                               "{{ .labels.eudat_gitlab_liveness_url }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eudat_gitlab_liveness "
                            "== 'eudat.gitlab.liveness'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eudat.gitlab.liveness",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect "
                            "== 'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_url_url_param_overrides_some(
            self
    ):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [],
                "metric_parameters": [
                    {
                        "hostname": "gitlab.test.com",
                        "metric": "eudat.gitlab.liveness",
                        "parameter": "--url",
                        "value": "https://gitlab.test.com"
                    }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST38"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo/probes/eudat-gitlab/"
                               "check_gitlab_liveness.sh -t 10 "
                               "{{ .labels.eudat_gitlab_liveness_url }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eudat_gitlab_liveness "
                            "== 'eudat.gitlab.liveness'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eudat.gitlab.liveness",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect "
                            "== 'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_url_url_attr_overrides_all(
            self
    ):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [{
                    "hostname": "gitlab.test.com",
                    "attribute": "URL",
                    "value": "https://gitlab.test.com"
                }, {
                    "hostname": "gitlab2.test.com",
                    "attribute": "URL",
                    "value": "https://gitlab2.test.com"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST38"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo/probes/eudat-gitlab/"
                               "check_gitlab_liveness.sh -t 10 "
                               "--url {{ .labels.endpoint_url }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eudat_gitlab_liveness "
                            "== 'eudat.gitlab.liveness'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eudat.gitlab.liveness",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect "
                            "== 'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_url_url_attr_overrides_some(
            self
    ):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [{
                    "hostname": "gitlab.test.com",
                    "attribute": "URL",
                    "value": "https://gitlab.test.com"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST38"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo/probes/eudat-gitlab/"
                               "check_gitlab_liveness.sh -t 10 "
                               "--url {{ .labels.endpoint_url }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eudat_gitlab_liveness "
                            "== 'eudat.gitlab.liveness'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eudat.gitlab.liveness",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect "
                            "== 'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_default_port_override_by_ext_some(
            self
    ):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST39"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks, [
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssh "
                               "-H {{ .labels.hostname }} -t 60 "
                               "-p {{ .labels.ssh_port | default \"22\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_ssh_connect == "
                            "'generic.ssh.connect'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.ssh.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_default_port_override_by_ext_none(
            self
    ):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST40"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks, [
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssh "
                               "-H {{ .labels.hostname }} -t 60 -p 22",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_ssh_connect == "
                            "'generic.ssh.connect'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.ssh.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_default_port_override_by_global_attr(
            self
    ):
        attributes = {
            "local": {
                "global_attributes": [{
                    "attribute": "SSH_PORT",
                    "value": "1022"
                }],
                "host_attributes": [],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST40"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks, [
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssh "
                               "-H {{ .labels.hostname }} -t 60 -p 1022",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_ssh_connect == "
                            "'generic.ssh.connect'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.ssh.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_default_port_override_by_host_attr(
            self
    ):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [{
                    "hostname": "hpc.resource.ni4os.eu",
                    "attribute": "SSH_PORT",
                    "value": "1022"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST40"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks, [
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssh "
                               "-H {{ .labels.hostname }} -t 60 "
                               "-p {{ .labels.ssh_port | default \"22\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_ssh_connect == "
                            "'generic.ssh.connect'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.ssh.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_attributes_not_defined_anywhere(
            self
    ):
        attributes = {
            "local": {
                "global_attributes": [
                    {
                        "attribute": "OIDC_TOKEN_FILE",
                        "value": "/etc/sensu/certs/oidc"
                    },
                    {
                        "attribute": "OIDC_ACCESS_TOKEN",
                        "value": "/etc/sensu/certs/oidc"
                    },
                    {
                        "attribute": "X509_USER_PROXY",
                        "value": "/etc/sensu/certs/userproxy.pem"
                    },
                    {
                        "attribute": "VONAME",
                        "value": "test"
                    },
                    {
                        "attribute": "ROBOT_CERT",
                        "value": "/etc/nagios/robot/robot.pem"
                    },
                    {
                        "attribute": "ROBOT_KEY",
                        "value": "/etc/nagios/robot/robot.key"
                    }
                ],
                "host_attributes": [],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST41"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [
                {
                    "command": "/usr/libexec/argo/probes/globus/refresh_proxy "
                               "-t 120 --vo test "
                               "--robot-cert /etc/nagios/robot/robot.pem "
                               "--robot-key /etc/nagios/robot/robot.key "
                               "-x /etc/sensu/certs/userproxy.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "srce.gridproxy.get",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo/probes/globus/"
                               "GridProxy-probe -t 30 --vo test "
                               "-x /etc/sensu/certs/userproxy.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "srce.gridproxy.validity",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_servicesite_name(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST42"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [
                {
                    "command": "/usr/libexec/argo/probes/http_parser/"
                               "check_http_parser -t 120 "
                               "-H goc-accounting.grid-support.ac.uk "
                               "-u {{ .labels.argo_apel_pub_u }} "
                               "--warning-search WARN --critical-search ERROR "
                               "--ok-search OK --case-sensitive",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_apel_pub == 'argo.APEL-Pub'"
                        ]
                    },
                    "interval": 43200,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.APEL-Pub",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo/probes/http_parser/"
                               "check_http_parser -t 120 "
                               "-H goc-accounting.grid-support.ac.uk "
                               "-u {{ .labels.argo_apel_sync_u }} "
                               "--warning-search WARN --critical-search ERROR "
                               "--ok-search OK --case-sensitive",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_apel_sync == 'argo.APEL-Sync'"
                        ]
                    },
                    "interval": 43200,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.APEL-Sync",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_servicesite_name_with_override(
            self
    ):
        attributes = {
            "apel": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [],
                "metric_parameters": [
                    {
                        "hostname": "apel.grid1.example.com",
                        "metric": "argo.APEL-Pub",
                        "parameter": "-u",
                        "value": "/test/$_SERVICESITE_NAME$_Pub.html",
                    }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST42"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [
                {
                    "command": "/usr/libexec/argo/probes/http_parser/"
                               "check_http_parser -t 120 "
                               "-H goc-accounting.grid-support.ac.uk "
                               "-u {{ .labels.argo_apel_pub_u }} "
                               "--warning-search WARN --critical-search ERROR "
                               "--ok-search OK --case-sensitive",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_apel_pub == 'argo.APEL-Pub'"
                        ]
                    },
                    "interval": 43200,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.APEL-Pub",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo/probes/http_parser/"
                               "check_http_parser -t 120 "
                               "-H goc-accounting.grid-support.ac.uk "
                               "-u {{ .labels.argo_apel_sync_u }} "
                               "--warning-search WARN --critical-search ERROR "
                               "--ok-search OK --case-sensitive",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_apel_sync == 'argo.APEL-Sync'"
                        ]
                    },
                    "interval": 43200,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.APEL-Sync",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_http_check_configuration_if_no_URL(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST43"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                               "-H {{ .labels.hostname }} -t 60 -w 30 -c 0 "
                               "-N --altnames --rootcert-dir "
                               "/etc/grid-security/certificates "
                               "--rootcert-file "
                               "/etc/pki/tls/certs/ca-bundle.crt "
                               "-C /etc/sensu/certs/hostcert.pem "
                               "-K /etc/sensu/certs/hostkey.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_certificate_validity == "
                            "'generic.certificate.validity'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.certificate.validity",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command":
                        "/usr/lib64/nagios/plugins/check_http "
                        "-H {{ .labels.hostname }} -t 60 --link "
                        "--onredirect follow "
                        "{{ .labels.ssl | default \" \" }} "
                        "{{ .labels.generic_http_connect_port | "
                        "default \" \" }} "
                        "{{ .labels.generic_http_connect_path | "
                        "default \" \" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_http_connect == "
                            "'generic.http.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.http.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_if_attribute_with_dashes(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST44"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks, [
                {
                    "command": "/usr/libexec/argo/probes/http_parser/"
                               "check_http_parser -H {{ .labels.hostname }} "
                               "-t 120 -u \"/cvmfsmon/api/v1.0/all\" "
                               "--unknown-message "
                               "\"Please check if cvmfs-servermon package is "
                               "installed\" -p "
                               "{{ .labels.cvmfs_stratum_1_port | "
                               "default \"8000\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_cvmfs_stratum_1_status == "
                            "'argo.cvmfs-stratum-1.status'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.cvmfs-stratum-1.status",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_passive_check_configuration(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST45"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [
                {
                    "command": "/usr/lib64/nagios/plugins/srm/srm_probe.py "
                               "-H {{ .labels.hostname }} -t 300 -d "
                               "-p eu.egi.SRM -s test --se-timeout 260 "
                               "--voname test "
                               "-X /etc/sensu/certs/userproxy.pem "
                               "{{ .labels.ldap_url__site_bdii | "
                               "default \"\" }} "
                               "{{ .labels.endpoint__surl | default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_srm_all == "
                            "'eu.egi.SRM-All'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.SRM-All",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "PASSIVE",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "cron": "CRON_TZ=Europe/Zagreb 0 0 31 2 *",
                    "timeout": 900,
                    "publish": False,
                    "metadata": {
                        "name": "eu.egi.SRM-VOGet",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "PASSIVE",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "cron": "CRON_TZ=Europe/Zagreb 0 0 31 2 *",
                    "timeout": 900,
                    "publish": False,
                    "metadata": {
                        "name": "eu.egi.SRM-VOLsDir",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_passive_check_configuration_if_parent_missing(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST55"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [
                {
                    "command": "/usr/libexec/argo/probes/http_parser/"
                               "check_http_parser -t 120 "
                               "-H goc-accounting.grid-support.ac.uk "
                               "-u {{ .labels.argo_apel_pub_u }} "
                               "--warning-search WARN --critical-search ERROR "
                               "--ok-search OK --case-sensitive",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_apel_pub == 'argo.APEL-Pub'"
                        ]
                    },
                    "interval": 43200,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.APEL-Pub",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo/probes/http_parser/"
                               "check_http_parser -t 120 "
                               "-H goc-accounting.grid-support.ac.uk "
                               "-u {{ .labels.argo_apel_sync_u }} "
                               "--warning-search WARN --critical-search ERROR "
                               "--ok-search OK --case-sensitive",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.argo_apel_sync == 'argo.APEL-Sync'"
                        ]
                    },
                    "interval": 43200,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.APEL-Sync",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, [
            f"WARNING:{LOGNAME}:MOCK_TENANT: Skipping check generation for "
            f"org.apel.APEL-Pub - missing parent"
        ])

    def test_generate_check_configuration_if_info_bdii_tag(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST46"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks, [
                {
                    "command":
                        "/usr/lib64/nagios/plugins/check_ssl_cert "
                        "-H {{ .labels.hostname }} -t 60 -w 30 -c 0 -N "
                        "--altnames "
                        "--rootcert-dir /etc/grid-security/certificates "
                        "-C /etc/sensu/certs/hostcert.pem "
                        "-K /etc/sensu/certs/hostkey.pem "
                        "-p {{ .labels.srm2_port | default \"8443\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_certificate_validity_srm == "
                            "'generic.certificate.validity-srm'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.certificate.validity-srm",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_if_info_bdii_and_info_ext_tag(self):
        topology = copy.deepcopy(mock_topology)
        topology[33]["tags"].update({"info_ext_SRM2_PORT": "8444"})
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST46"],
            metric_profiles=mock_metric_profiles,
            topology=topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks, [
                {
                    "command":
                        "/usr/lib64/nagios/plugins/check_ssl_cert "
                        "-H {{ .labels.hostname }} -t 60 -w 30 -c 0 -N "
                        "--altnames "
                        "--rootcert-dir /etc/grid-security/certificates "
                        "-C /etc/sensu/certs/hostcert.pem "
                        "-K /etc/sensu/certs/hostkey.pem "
                        "-p {{ .labels.srm2_port | default \"8443\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_certificate_validity_srm == "
                            "'generic.certificate.validity-srm'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.certificate.validity-srm",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_with_integer_attributes(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST48"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks, [
                {
                    "command":
                        "/usr/lib64/nagios/plugins/storage/storage_probe.py "
                        "-H {{ .labels.hostname }} -t 300 "
                        "-p egi.xrootd.readwrite "
                        "{{ .labels.e__argo_xrootd_ops_url | default \"\" }} "
                        "-X /etc/sensu/certs/userproxy.pem "
                        "{{ .labels.skip_ls_dir__argo_xrootd_skip_ls_dir | "
                        "default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.egi_xrootd_readwrite == "
                            "'egi.xrootd.readwrite'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "egi.xrootd.readwrite",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_with_xrootd_webdav_extension(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST49"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [
                {
                    "command":
                        "/usr/lib64/nagios/plugins/check_webdav "
                        "-H {{ .labels.hostname }} -t 600 -v -v --no-crls "
                        "{{ .labels.u__argo_webdav_ops_url | default \"\" }} "
                        "-E /etc/sensu/certs/userproxy.pem "
                        "{{ .labels.skip_dir_test__argo_webdav_skip_dir_test "
                        "| default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.cern_webdav_status == "
                            "'cern.webdav.status'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "cern.webdav.status",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command":
                        "/usr/lib64/nagios/plugins/storage/storage_probe.py "
                        "-H {{ .labels.hostname }} -t 300 "
                        "-p egi.xrootd.readwrite "
                        "{{ .labels.e__argo_xrootd_ops_url | default \"\" }} "
                        "-X /etc/sensu/certs/userproxy.pem "
                        "{{ .labels.skip_ls_dir__argo_xrootd_skip_ls_dir | "
                        "default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.egi_xrootd_readwrite == "
                            "'egi.xrootd.readwrite'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "egi.xrootd.readwrite",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_with_xrootd_webdav_extension_with_override(self):
        attributes = {
            "local": {
                "global_attributes": [
                    {
                        "attribute": "X509_USER_PROXY",
                        "value": "/etc/sensu/certs/userproxy.pem"
                    }
                ],
                "host_attributes": [{
                    "hostname": "castorpublic.cern.ch",
                    "attribute": "ARGO_XROOTD_OPS_URL",
                    "value": "root://castorpublic.cern.ch/data/ops/"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST49"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [
                {
                    "command":
                        "/usr/lib64/nagios/plugins/check_webdav "
                        "-H {{ .labels.hostname }} -t 600 -v -v --no-crls "
                        "{{ .labels.u__argo_webdav_ops_url | default \"\" }} "
                        "-E /etc/sensu/certs/userproxy.pem "
                        "{{ .labels.skip_dir_test__argo_webdav_skip_dir_test "
                        "| default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.cern_webdav_status == "
                            "'cern.webdav.status'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "cern.webdav.status",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command":
                        "/usr/lib64/nagios/plugins/storage/storage_probe.py "
                        "-H {{ .labels.hostname }} -t 300 "
                        "-p egi.xrootd.readwrite "
                        "{{ .labels.e__argo_xrootd_ops_url | default \"\" }} "
                        "-X /etc/sensu/certs/userproxy.pem "
                        "{{ .labels.skip_ls_dir__argo_xrootd_skip_ls_dir | "
                        "default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.egi_xrootd_readwrite == "
                            "'egi.xrootd.readwrite'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "egi.xrootd.readwrite",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_with_duplicates_in_topology(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST50"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology_with_duplicate_entries,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [
                {
                    "command":
                        "/usr/lib64/nagios/plugins/check_webdav "
                        "-H {{ .labels.hostname }} -t 600 -v -v --no-crls "
                        "{{ .labels.u__argo_webdav_ops_url | default \"\" }} "
                        "-E /etc/sensu/certs/userproxy.pem "
                        "{{ .labels.skip_dir_test__argo_webdav_skip_dir_test "
                        "| default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.cern_webdav_status == "
                            "'cern.webdav.status'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "cern.webdav.status",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_with_non_fallback_attribute_in_every_endpoint(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST53"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            checks, [{
                "command":
                    "/usr/lib64/nagios/plugins/xrootd/xrootd_probe.py "
                    "-H {{ .labels.hostname }} -t 300 --read-only "
                    "-p egi.xrootd.readonly "
                    "-E {{ .labels.argo_xrootd_ops_url }} "
                    "-X /etc/sensu/certs/userproxy.pem "
                    "{{ .labels.skip_ls_dir__argo_xrootd_skip_ls_dir | "
                    "default \"\" }}",
                "subscriptions": [
                    "entity:sensu-agent-mock_tenant.example.com"
                ],
                "handlers": [],
                "interval": 3600,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "egi.xrootd.readonly",
                    "namespace": "mockspace",
                    "annotations": {
                        "attempts": "3"
                    },
                    "labels": {
                        "tenants": "MOCK_TENANT"
                    }
                },
                "round_robin": False,
                "pipelines": [
                    {
                        "name": "hard_state",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.egi_xrootd_readonly == "
                        "'egi.xrootd.readonly'"
                    ]
                }
            }]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_ARC_CE_check_with_set_VO_FQAN(self):
        attributes = {
            "local": {
                "global_attributes": [
                    {
                        "attribute": "X509_USER_PROXY",
                        "value": "/etc/sensu/certs/userproxy.pem"
                    },
                    {
                        "attribute": "VONAME",
                        "value": "test"
                    },
                    {
                        "attribute": "ARC_GOOD_SES",
                        "value": "good_ses_file=/var/lib/gridprobes/ops/GoodSEs"
                    },
                    {
                        "attribute": "VO_FQAN",
                        "value": "ops"
                    }
                ],
                "host_attributes": [],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST54"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [{
                "command":
                    "/usr/lib64/nagios/plugins/check_tcp "
                    "-H {{ .labels.hostname }} -t 120 -p 443",
                "subscriptions": [
                    "entity:sensu-agent-mock_tenant.example.com"
                ],
                "handlers": [],
                "interval": 300,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "generic.tcp.connect",
                    "namespace": "mockspace",
                    "annotations": {
                        "attempts": "3"
                    },
                    "labels": {
                        "tenants": "MOCK_TENANT"
                    }
                },
                "round_robin": False,
                "pipelines": [
                    {
                        "name": "hard_state",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.generic_tcp_connect == "
                        "'generic.tcp.connect'"
                    ]
                }}, {
                "command":
                    "/usr/lib64/nagios/plugins/check_arcce_submit "
                    "-H {{ .labels.hostname }} --job-tag dist-stage-srm "
                    "--termination-service org.nordugrid.ARC-CE-SRM-result-ops"
                    " --test dist-stage-srm -O service_suffix=-ops "
                    "--command-file /var/nagios/rw/nagios.cmd "
                    "--how-invoked nagios "
                    "-O good_ses_file=/var/lib/gridprobes/ops/GoodSEs "
                    "--voms test --fqan ops "
                    "--user-proxy /etc/sensu/certs/userproxy.pem "
                    "{{ .labels.memory_limit__arc_ce_memory_limit "
                    "| default \"\" }}",
                "subscriptions": [
                    "entity:sensu-agent-mock_tenant.example.com"
                ],
                "handlers": [],
                "interval": 3600,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "org.nordugrid.ARC-CE-SRM-submit",
                    "namespace": "mockspace",
                    "annotations": {
                        "attempts": "2"
                    },
                    "labels": {
                        "tenants": "MOCK_TENANT"
                    }
                },
                "round_robin": False,
                "pipelines": [
                    {
                        "name": "hard_state",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.org_nordugrid_arc_ce_srm_submit == "
                        "'org.nordugrid.ARC-CE-SRM-submit'"
                    ]
                }
            }]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_ARC_CE_check_without_VONAME(self):
        attributes = {
            "local": {
                "global_attributes": [
                    {
                        "attribute": "X509_USER_PROXY",
                        "value": "/etc/sensu/certs/userproxy.pem"
                    }
                ],
                "host_attributes": [],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST54"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [{
                "command":
                    "/usr/lib64/nagios/plugins/check_tcp "
                    "-H {{ .labels.hostname }} -t 120 -p 443",
                "subscriptions": [
                    "entity:sensu-agent-mock_tenant.example.com"
                ],
                "handlers": [],
                "interval": 300,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "generic.tcp.connect",
                    "namespace": "mockspace",
                    "annotations": {
                        "attempts": "3"
                    },
                    "labels": {
                        "tenants": "MOCK_TENANT"
                    }
                },
                "round_robin": False,
                "pipelines": [
                    {
                        "name": "hard_state",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.generic_tcp_connect == "
                        "'generic.tcp.connect'"
                    ]
                }
            }]
        )
        self.assertEqual(log.output, [
            f"WARNING:{LOGNAME}:MOCK_TENANT: Skipping check "
            f"org.nordugrid.ARC-CE-SRM-submit: VONAME not defined"
        ])

    def test_generate_check_configuration_if_skipped_metrics(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST13"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            skipped_metrics=[
                "org.nagios.Keystone-TCP", "eu.egi.cloud.OpenStack-Swift"
            ],
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo-monitoring/probes/fedcloud/"
                               "cloudinfo.py -t 300 "
                               "--endpoint {{ .labels.os_keystone_url }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_infoprovider == "
                            "'eu.egi.cloud.InfoProvider'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.InfoProvider",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/fedcloud/"
                               "novaprobe.py -t 300 -v "
                               "--access-token /etc/sensu/certs/oidc "
                               "--appdb-image xxxx "
                               "--endpoint {{ .labels.os_keystone_url }} "
                               "--cert /etc/sensu/certs/userproxy.pem "
                               "{{ .labels.region__os_region | default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_openstack_vm == "
                            "'eu.egi.cloud.OpenStack-VM'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.OpenStack-VM",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_if_skipped_metric_missing(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST13"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            skipped_metrics=["org.nagios.Keystone-TCP", "argo.mock.metric"],
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo-monitoring/probes/fedcloud/"
                               "cloudinfo.py -t 300 "
                               "--endpoint {{ .labels.os_keystone_url }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_infoprovider == "
                            "'eu.egi.cloud.InfoProvider'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.InfoProvider",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/fedcloud/"
                               "swiftprobe.py -t 300 "
                               "--endpoint {{ .labels.os_keystone_url }} "
                               "--access-token /etc/sensu/certs/oidc",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_openstack_swift == "
                            "'eu.egi.cloud.OpenStack-Swift'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.OpenStack-Swift",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo-monitoring/probes/fedcloud/"
                               "novaprobe.py -t 300 -v "
                               "--access-token /etc/sensu/certs/oidc "
                               "--appdb-image xxxx "
                               "--endpoint {{ .labels.os_keystone_url }} "
                               "--cert /etc/sensu/certs/userproxy.pem "
                               "{{ .labels.region__os_region | default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.eu_egi_cloud_openstack_vm == "
                            "'eu.egi.cloud.OpenStack-VM'"
                        ]
                    },
                    "interval": 3600,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "eu.egi.cloud.OpenStack-VM",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_if_SILENCED_flag(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST56"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "command": "/usr/libexec/argo-monitoring/probes/argo/"
                               "ams-publisher-probe "
                               "-s /var/run/argo-nagios-ams-publisher/sock "
                               "-q 'w:metrics+g:published180' -c 4000 -q "
                               "'w:alarms+g:published180' -c 1 -q "
                               "'w:metricsdevel+g:published180' -c 4000",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "interval": 10800,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.AMSPublisher-Check",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "1"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_arcce_clean "
                               "--timeout 600 "
                               "--command-file /var/nagios/rw/nagios.cmd "
                               "--how-invoked nagios --voms test "
                               "--user-proxy /etc/sensu/certs/userproxy.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "interval": 1200,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nordugrid.ARC-CE-clean",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": []
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_arcce_monitor "
                               "-O service_suffix=-test -O "
                               "lfc_host=dummy -O se_host=dummy --timeout 900 "
                               "--command-file /var/nagios/rw/nagios.cmd "
                               "--how-invoked nagios --voms test "
                               "--user-proxy /etc/sensu/certs/userproxy.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "interval": 1200,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "org.nordugrid.ARC-CE-monitor",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": []
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_optional_attributes(self):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [{
                    "hostname": "test.argo.eu",
                    "attribute": "ARGO_JSON_KEY",
                    "value": "key1.key2"
                }, {
                    "hostname": "test.argo.eu",
                    "attribute": "ARGO_JSON_CRITICAL",
                    "value": ":0"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST57"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [
                {
                    "command": "/usr/libexec/argo/probes/json/check_json -t 30 "
                               "-u {{ .labels.endpoint_url }} "
                               "{{ .labels.k__argo_json_key | default \"\" }} "
                               "{{ .labels.c__argo_json_critical | "
                               "default \"\" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_json_connect == "
                            "'generic.json.connect'"
                        ]
                    },
                    "interval": 900,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.json.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_check_configuration_with_repeating_servicetypes(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST58", "ARGO_TEST59"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            checks = generator.generate_checks(
                publish=True, namespace="mockspace"
            )
        self.assertEqual(
            sorted(checks, key=lambda k: k["metadata"]["name"]), [
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 60 --link "
                               "--onredirect follow "
                               "{{ .labels.ssl | default \" \" }} "
                               "{{ .labels.generic_http_connect_port | "
                               "default \" \" }} "
                               "{{ .labels.generic_http_connect_path | "
                               "default \" \" }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_http_connect == "
                            "'generic.http.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.http.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False,
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ]
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_tcp "
                               "-H {{ .labels.hostname }} -t 120 -p 443",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_tcp_connect == "
                            "'generic.tcp.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.tcp.connect",
                        "namespace": "mockspace",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "MOCK_TENANT"
                        }
                    },
                    "round_robin": False
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)


class EntityConfigurationTests(unittest.TestCase):
    def test_generate_entity_configuration(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST5"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_ar_argoui_ni4os":
                                "generic.http.ar-argoui-ni4os",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "hostname": "argo-devel.ni4os.eu",
                            "info_url": "http://argo-devel.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_ar_argoui_ni4os":
                                "generic.http.ar-argoui-ni4os",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_port_and_path(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST6"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui__hpc.resource.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_test": "generic.ssh.test",
                            "hostname": "hpc.resource.ni4os.eu",
                            "port": "1022",
                            "ssh_port": "1022",
                            "service": "eu.ni4os.hpc.ui",
                            "site": "IPB",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui__teran.srce.hr",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_test": "generic.ssh.test",
                            "hostname": "teran.srce.hr",
                            "service": "eu.ni4os.hpc.ui",
                            "site": "SRCE",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "web.check__bioinformatics.cing.ac.cy",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "bioinformatics.cing.ac.cy",
                            "generic_http_connect_path":
                                "-u /MelGene?bla=oai%3meh",
                            "ssl": "-S --sni",
                            "info_url":
                                "https://bioinformatics.cing.ac.cy/MelGene?"
                                "bla=oai%3meh",
                            "service": "web.check",
                            "site": "CING",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "web.check__eewrc-las.cyi.ac.cy",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "eewrc-las.cyi.ac.cy",
                            "generic_http_connect_path": "-u /las/getUI.do",
                            "info_url":
                                "http://eewrc-las.cyi.ac.cy/las/getUI.do",
                            "service": "web.check",
                            "site": "CYI",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "web.check__sampaeos.if.usp.br",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "sampaeos.if.usp.br",
                            "generic_http_connect_port": "-p 9000",
                            "generic_http_connect_path":
                                "-u //eos/ops/opstest/",
                            "ssl": "-S --sni",
                            "info_url":
                                "https://sampaeos.if.usp.br:9000//eos/ops/"
                                "opstest/",
                            "service": "web.check",
                            "site": "SAMPA",
                            "ngi": "ROC_LA",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)
    
    def test_generate_entities_with_ext_PORT_PATH_attribs(self) -> None:
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST60"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            self.maxDiff = None
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "generic_http_connect_path": "-u /path",
                            "generic_http_connect_port": "-p 45554",
                            "hostname": "www.srce.hr",
                            "info_url": "https://www.srce.hr:45554/path",
                            "ngi": "",
                            "path": "/path",
                            "port": "45554",
                            "service": "argo.grafana",
                            "site": "argo-public-production",
                            "ssl": "-S --sni",
                            "tenants": "MOCK_TENANT"
                        },
                    "name": "argo.grafana__www.srce.hr",
                    "namespace": "default"
               }
            }]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_SSL(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST7"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "argo-devel.ni4os.eu",
                            "info_url": "http://argo-devel.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "argo.ni4os.eu",
                            "ssl": "-S --sni",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_URLs(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST8"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "ch.cern.dynafed__dynafed.hostname.ca",
                        "namespace": "default",
                        "labels": {
                            "ch_cern_webdav_dynafed": "ch.cern.WebDAV-dynafed",
                            "hostname": "dynafed.hostname.ca",
                            "info_url":
                                "https://dynafed.hostname.ca:443/dynafed/ops",
                            "endpoint_url":
                                "https://dynafed.hostname.ca:443/dynafed/ops",
                            "service": "ch.cern.dynafed",
                            "site": "CA-UVic-Cloud",
                            "ngi": "ROC_Canada",
                            "tenants": "MOCK_TENANT",
                            "info_hostdn": "/C=CA/O=Grid/CN=dynafed.hostname.ca"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "es.upv.grycap.im__grycap.upv.es",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_grycap_im_check": "eu.egi.grycap.IM-Check",
                            "hostname": "grycap.upv.es",
                            "info_url": "https://grycap.upv.es:31443/im/",
                            "service": "es.upv.grycap.im",
                            "site": "UPV-GRyCAP",
                            "ngi": "NGI_IBERGRID",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "webdav__eosatlas.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "ch_cern_webdav": "ch.cern.WebDAV",
                            "hostname": "eosatlas.cern.ch",
                            "info_url":
                                "https://eosatlas.cern.ch//eos/atlas/opstest",
                            "webdav_url":
                                "https://eosatlas.cern.ch//eos/atlas/opstest",
                            "argo_webdav_ops_url":
                                "https://eosatlas.cern.ch//eos/atlas/opstest/"
                                "egi/",
                            "service": "webdav",
                            "site": "CERN-PROD",
                            "ngi": "CERN",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "webdav__hostname.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "ch_cern_webdav": "ch.cern.WebDAV",
                            "hostname": "hostname.cern.ch",
                            "info_url":
                                "https://hostname.cern.ch/atlas/opstest",
                            "webdav_url":
                                "https://hostname.cern.ch/atlas/opstest",
                            "service": "webdav",
                            "site": "CERN-PROD",
                            "ngi": "CERN",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_multiple_endpoint_URLs(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST9"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "mock.webdav__dpm.bla.meh.com",
                        "namespace": "default",
                        "labels": {
                            "ch_cern_webdav": "ch.cern.WebDAV",
                            "hostname": "dpm.bla.meh.com",
                            "info_url": "https://dpm.bla.meh.com/dpm/ops/",
                            "endpoint_url":
                                "https://mock.url.com/dpm/ops",
                            "webdav_url":
                                "https://mock.url.com/dpm/ops",
                            "service": "mock.webdav",
                            "site": "WEBDAV-test",
                            "ngi": "MEH",
                            "info_hostdn": "/CN=host/dpm.bla.meh.com",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_BDII(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST10"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "Site-BDII__grid-giis1.desy.de",
                        "namespace": "default",
                        "labels": {
                            "org_bdii_entries": "org.bdii.Entries",
                            "org_nagios_glue2_check":
                                "org.nagios.GLUE2-Check",
                            "org_nagios_glue2_check_f":
                                "\"(&(objectClass=GLUE2Domain)"
                                "(GLUE2DomainID=DESY-HH))\"",
                            "hostname": "grid-giis1.desy.de",
                            "bdii_dn": "Mds-Vo-Name=DESY-HH,O=Grid",
                            "bdii_type": "bdii_site",
                            "glue2_bdii_dn": "GLUE2DomainID=DESY-HH,o=glue",
                            "service": "Site-BDII",
                            "site": "DESY-HH",
                            "ngi": "NGI_DE",
                            "info_url": "ldap://grid-giis1.desy.de:2170/"
                                        "mds-vo-name=DESY-HH,o=grid",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "Site-BDII__kser.arnes.si",
                        "namespace": "default",
                        "labels": {
                            "org_bdii_entries": "org.bdii.Entries",
                            "org_nagios_glue2_check":
                                "org.nagios.GLUE2-Check",
                            "org_nagios_glue2_check_f":
                                "\"(&(objectClass=GLUE2Domain)"
                                "(GLUE2DomainID=ARNES))\"",
                            "hostname": "kser.arnes.si",
                            "bdii_dn": "Mds-Vo-Name=ARNES,O=Grid",
                            "bdii_type": "bdii_site",
                            "glue2_bdii_dn": "GLUE2DomainID=ARNES,o=glue",
                            "service": "Site-BDII",
                            "site": "ARNES",
                            "ngi": "NGI_SI",
                            "info_hostdn": "/C=SI/O=SiGNET/O=Arnes/"
                                           "CN=kser.arnes.si",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "Site-BDII__sbdii.test.com",
                        "namespace": "default",
                        "labels": {
                            "org_bdii_entries": "org.bdii.Entries",
                            "org_nagios_glue2_check":
                                "org.nagios.GLUE2-Check",
                            "org_nagios_glue2_check_f":
                                "\"(&(objectClass=GLUE2Domain)"
                                "(GLUE2DomainID=SBDII))\"",
                            "hostname": "sbdii.test.com",
                            "bdii_dn": "Mds-Vo-Name=SBDII,O=Grid",
                            "bdii_type": "bdii_site",
                            "glue2_bdii_dn": "GLUE2DomainID=SBDII,o=glue",
                            "service": "Site-BDII",
                            "site": "SBDII",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "Site-BDII__sitebdii.iihe.ac.be",
                        "namespace": "default",
                        "labels": {
                            "org_bdii_entries": "org.bdii.Entries",
                            "org_nagios_glue2_check":
                                "org.nagios.GLUE2-Check",
                            "org_nagios_glue2_check_f":
                                "\"(&(objectClass=GLUE2Domain)"
                                "(GLUE2DomainID=BEgrid-ULB-VUB))\"",
                            "hostname": "sitebdii.iihe.ac.be",
                            "bdii_dn": "Mds-Vo-Name=BEgrid-ULB-VUB,O=Grid",
                            "bdii_type": "bdii_site",
                            "glue2_bdii_dn":
                                "GLUE2DomainID=BEgrid-ULB-VUB,o=glue",
                            "service": "Site-BDII",
                            "site": "BEgrid-ULB-VUB",
                            "ngi": "NGI_NL",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "Top-BDII__bdii1.test.com",
                        "namespace": "default",
                        "labels": {
                            "org_bdii_entries": "org.bdii.Entries",
                            "hostname": "bdii1.test.com",
                            "bdii_dn": "Mds-Vo-Name=local,O=Grid",
                            "bdii_type": "bdii_top",
                            "glue2_bdii_dn": "GLUE2DomainID=BDII,o=glue",
                            "service": "Top-BDII",
                            "site": "BDII",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_different_PORTs(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST11"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.app.web__catalogue.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "catalogue.ni4os.eu",
                            "info_url": "https://catalogue.ni4os.eu/",
                            "ssl": "-S --sni",
                            "generic_http_connect_path": "-u /",
                            "service": "eu.ni4os.app.web",
                            "site": "IPB",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui__hpc.resource.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_test": "generic.ssh.test",
                            "hostname": "hpc.resource.ni4os.eu",
                            "port": "1022",
                            "ssh_port": "1022",
                            "service": "eu.ni4os.hpc.ui",
                            "site": "IPB",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui__teran.srce.hr",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_test": "generic.ssh.test",
                            "hostname": "teran.srce.hr",
                            "service": "eu.ni4os.hpc.ui",
                            "site": "SRCE",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_mandatory_extensions(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST12"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.egi.cloud.dyndns__dns1.cloud.test.eu",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_dyndns_check":
                                "eu.egi.cloud.DynDNS-Check",
                            "hostname": "dns1.cloud.test.eu",
                            "info_url": "https://dns1.cloud.test.eu/",
                            "endpoint_name": "nsupdate",
                            "service": "eu.egi.cloud.dyndns",
                            "site": "EGI-DDNS",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.egi.cloud.dyndns__dns2.cloud.test.eu",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_dyndns_check":
                                "eu.egi.cloud.DynDNS-Check",
                            "hostname": "dns2.cloud.test.eu",
                            "endpoint_name": "secondary",
                            "service": "eu.egi.cloud.dyndns",
                            "site": "EGI-DDNS",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.egi.cloud.dyndns__dns3.cloud.test.eu",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_dyndns_check":
                                "eu.egi.cloud.DynDNS-Check",
                            "hostname": "dns3.cloud.test.eu",
                            "endpoint_name": "primary",
                            "service": "eu.egi.cloud.dyndns",
                            "site": "EGI-DDNS",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_optional_extensions(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST20"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.seadatanet.org.replicationmanager__"
                                "185.229.108.85",
                        "namespace": "default",
                        "labels": {
                            "eu_seadatanet_org_replicationmanager_check":
                                "eu.seadatanet.org.replicationmanager-check",
                            "eu_seadatanet_org_replicationmanager_check_status":
                                "eu.seadatanet.org.replicationmanager-check-"
                                "status",
                            "info_url": "http://185.229.108.85:8080/",
                            "hostname": "185.229.108.85",
                            "service": "eu.seadatanet.org.replicationmanager",
                            "site": "GAMMA",
                            "ngi": "",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.seadatanet.org.replicationmanager__"
                                "hnodc-dm.ath.hcmr.gr",
                        "namespace": "default",
                        "labels": {
                            "eu_seadatanet_org_replicationmanager_check":
                                "eu.seadatanet.org.replicationmanager-check",
                            "eu_seadatanet_org_replicationmanager_check_status":
                                "eu.seadatanet.org.replicationmanager-check-"
                                "status",
                            "info_url": "http://hnodc-dm.ath.hcmr.gr/",
                            "u__rm_path": "-u /ReplicationManager/",
                            "r__rm_path": "-r /ReplicationManager/",
                            "hostname": "hnodc-dm.ath.hcmr.gr",
                            "service": "eu.seadatanet.org.replicationmanager",
                            "site": "HNODC",
                            "ngi": "",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_openstack_entities(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST13"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "org.openstack.nova__"
                                "cloud-api-pub.cr.cnaf.infn.it",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_infoprovider":
                                "eu.egi.cloud.InfoProvider",
                            "eu_egi_cloud_openstack_vm":
                                "eu.egi.cloud.OpenStack-VM",
                            "org_nagios_keystone_tcp":
                                "org.nagios.Keystone-TCP",
                            "info_url":
                                "https://cloud-api-pub.cr.cnaf.infn.it:5000/v3",
                            "os_keystone_url":
                                "https://cloud-api-pub.cr.cnaf.infn.it:5000/v3",
                            "os_keystone_port": "5000",
                            "os_keystone_host": "cloud-api-pub.cr.cnaf.infn.it",
                            "hostname": "cloud-api-pub.cr.cnaf.infn.it",
                            "region__os_region": "--region sdds",
                            "service": "org.openstack.nova",
                            "site": "INFN-CLOUD-CNAF",
                            "ngi": "NGI_IT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "org.openstack.nova__egi-cloud.pd.infn.it",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_infoprovider":
                                "eu.egi.cloud.InfoProvider",
                            "eu_egi_cloud_openstack_vm":
                                "eu.egi.cloud.OpenStack-VM",
                            "org_nagios_keystone_tcp":
                                "org.nagios.Keystone-TCP",
                            "info_url": "https://egi-cloud.pd.infn.it:443/v3",
                            "os_keystone_url":
                                "https://egi-cloud.pd.infn.it:443/v3",
                            "os_keystone_port": "443",
                            "os_keystone_host": "egi-cloud.pd.infn.it",
                            "hostname": "egi-cloud.pd.infn.it",
                            "service": "org.openstack.nova",
                            "site": "INFN-PADOVA-STACK",
                            "ngi": "NGI_IT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "org.openstack.swift__identity.cloud.muni.cz",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_openstack_swift":
                                "eu.egi.cloud.OpenStack-Swift",
                            "info_url": "https://identity.cloud.muni.cz/v3",
                            "os_keystone_url":
                                "https://identity.cloud.muni.cz/v3",
                            "os_keystone_host": "identity.cloud.muni.cz",
                            "hostname": "identity.cloud.muni.cz",
                            "service": "org.openstack.swift",
                            "site": "CESNET-MCC",
                            "ngi": "NGI_CZ",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_multiple_same_host_entities(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST14"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "egi.aai.oidc__aai.eosc-portal.eu",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_aai_oidc_login": "eu.egi.AAI-OIDC-Login",
                            "info_url": "https://aai.eosc-portal.eu/oidc",
                            "endpoint_url":
                                "https://aai.eosc-portal.eu/oidc/.well-known/"
                                "openid-configuration",
                            "hostname": "aai.eosc-portal.eu",
                            "service": "egi.aai.oidc",
                            "site": "GRIDOPS-CheckIn",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "egi.aai.saml__aai.eosc-portal.eu",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_aai_saml_login": "eu.egi.AAI-SAML-Login",
                            "info_url": "https://aai.eosc-portal.eu/proxy",
                            "endpoint_url":
                                "https://aai.eosc-portal.eu/proxy/saml2/idp/"
                                "metadata.php",
                            "hostname": "aai.eosc-portal.eu",
                            "service": "egi.aai.saml",
                            "site": "GRIDOPS-CheckIn",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_SITE_BDII(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST16"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "SRM__dcache-se-cms.desy.de",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_srm_all": "eu.egi.SRM-All",
                            "hostname": "dcache-se-cms.desy.de",
                            "ldap_url__site_bdii":
                                "--ldap-url grid-giis1.desy.de",
                            "service": "SRM",
                            "srm2_port": "8443",
                            "endpoint__surl":
                                "--endpoint srm://dcache-se-cms.desy.de:8443"
                                "/srm/managerv2?SFN=/pnfs/desy.de/ops",
                            "site": "DESY-HH",
                            "ngi": "NGI_DE",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "SRM__dcache.arnes.si",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_srm_all": "eu.egi.SRM-All",
                            "hostname": "dcache.arnes.si",
                            "ldap_url__site_bdii": "--ldap-url kser.arnes.si",
                            "service": "SRM",
                            "site": "ARNES",
                            "ngi": "NGI_SI",
                            "info_hostdn": "/C=SI/O=SiGNET/O=Arnes/"
                                           "CN=dcache.arnes.si",
                            "srm2_port": "8443",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "SRM__dcache6-shadow.iihe.ac.be",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_srm_all": "eu.egi.SRM-All",
                            "hostname": "dcache6-shadow.iihe.ac.be",
                            "ldap_url__site_bdii":
                                "--ldap-url sitebdii.iihe.ac.be",
                            "service": "SRM",
                            "site": "BEgrid-ULB-VUB",
                            "ngi": "NGI_NL",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_ARC_CE_MEMORY_LIMIT(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST17"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            entities,
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "ARC-CE__gridarcce01.mesocentre.uca.fr",
                        "namespace": "default",
                        "labels": {
                            "org_nordugrid_arc_ce_srm_submit":
                                "org.nordugrid.ARC-CE-SRM-submit",
                            "hostname": "gridarcce01.mesocentre.uca.fr",
                            "service": "ARC-CE",
                            "site": "AUVERGRID",
                            "ngi": "NGI_FRANCE",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "ARC-CE__alien.spacescience.ro",
                        "namespace": "default",
                        "labels": {
                            "org_nordugrid_arc_ce_srm_submit":
                                "org.nordugrid.ARC-CE-SRM-submit",
                            "hostname": "alien.spacescience.ro",
                            "service": "ARC-CE",
                            "site": "RO-13-ISS",
                            "ngi": "NGI_RO",
                            "memory_limit__arc_ce_memory_limit":
                                "--memory-limit 268435456",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_local_topology(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST21"],
            metric_profiles=mock_metric_profiles,
            topology=mock_local_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.mon__argo-mon-devel.egi.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "hostname": "argo-mon-devel.egi.eu",
                            "service": "argo.mon",
                            "site": "SRCE",
                            "ngi": "",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.mon__argo-mon-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "hostname": "argo-mon-devel.ni4os.eu",
                            "service": "argo.mon",
                            "site": "SRCE",
                            "ngi": "",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_faulty_topology(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST21"],
            metric_profiles=mock_metric_profiles,
            topology=faulty_local_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertRaises(GeneratorException) as context:
            with self.assertLogs(LOGNAME) as log:
                generator.generate_entities()

        self.assertEqual(
            context.exception.__str__(),
            "MOCK_TENANT: Error generating entities: faulty topology"
        )
        self.assertEqual(
            log.output, [
                f"ERROR:{LOGNAME}:MOCK_TENANT: Skipping entities generation: "
                f"faulty topology"
            ]
        )

    def test_generate_entities_with_metric_parameter_overrides(self):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [],
                "metric_parameters": [{
                    "hostname": "argo.ni4os.eu",
                    "metric": "generic.tcp.connect",
                    "parameter": "-p",
                    "value": "80"
                }, {
                    "hostname": "argo-devel.ni4os.eu",
                    "metric": "generic.tcp.connect",
                    "parameter": "-p",
                    "value": "90"
                }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST25"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.test__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_test": "generic.ssh.test",
                            "argo_apel_pub": "argo.APEL-Pub",
                            "argo_apel_pub_u": "/rss/GRNET_Pub.html",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.test",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_tcp_connect": "generic.tcp.connect",
                            "generic_tcp_connect_p": "90",
                            "hostname": "argo-devel.ni4os.eu",
                            "info_url": "http://argo-devel.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_tcp_connect": "generic.tcp.connect",
                            "generic_tcp_connect_p": "80",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_metric_parameter_overrides_entity_name(
            self
    ):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [],
                "metric_parameters": [{
                    "hostname": "argo.ni4os.eu",
                    "metric": "generic.tcp.connect",
                    "parameter": "-p",
                    "value": "80"
                }, {
                    "hostname": "argo.webui__argo-devel.ni4os.eu",
                    "metric": "generic.tcp.connect",
                    "parameter": "-p",
                    "value": "90"
                }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST25"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.test__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_test": "generic.ssh.test",
                            "argo_apel_pub": "argo.APEL-Pub",
                            "argo_apel_pub_u": "/rss/GRNET_Pub.html",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.test",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_tcp_connect": "generic.tcp.connect",
                            "generic_tcp_connect_p": "90",
                            "hostname": "argo-devel.ni4os.eu",
                            "info_url": "http://argo-devel.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_tcp_connect": "generic.tcp.connect",
                            "generic_tcp_connect_p": "80",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_host_attribute_overrides(self):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [{
                    "hostname": "argo.webui__argo.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_USERNAME",
                    "value": "$NI4OS_NAGIOS_FRESHNESS_USERNAME"
                }, {
                    "hostname": "argo.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_PASSWORD",
                    "value": "$NI4OS_NAGIOS_FRESHNESS_PASSWORD"
                }, {
                    "hostname": "argo-devel.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_PASSWORD",
                    "value": "$NI4OS_DEVEL_NAGIOS_FRESHNESS_PASSWORD"
                }, {
                    "hostname": "b2handle3.test.com",
                    "attribute": "B2HANDLE_PREFIX",
                    "value": "123456"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST26"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.test__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_tcp_connect": "generic.tcp.connect",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.test",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "argo_nagios_freshness_simple_login":
                                "argo.nagios.freshness-simple-login",
                            "nagios_freshness_username":
                                "$NAGIOS_FRESHNESS_USERNAME",
                            "nagios_freshness_password":
                                "$NI4OS_DEVEL_NAGIOS_FRESHNESS_PASSWORD",
                            "hostname": "argo-devel.ni4os.eu",
                            "info_url": "http://argo-devel.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "argo_nagios_freshness_simple_login":
                                "argo.nagios.freshness-simple-login",
                            "nagios_freshness_username":
                                "$NI4OS_NAGIOS_FRESHNESS_USERNAME",
                            "nagios_freshness_password":
                                "$NI4OS_NAGIOS_FRESHNESS_PASSWORD",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "b2handle.test__b2handle3.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_b2handle_handle_api_healthcheck_resolve":
                                "eudat.b2handle.handle.api-healthcheck-resolve",
                            "b2handle_prefix": "123456",
                            "hostname": "b2handle3.test.com",
                            "service": "b2handle.test",
                            "site": "B2HANDLE-TEST",
                            "ngi": "EUDAT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_host_attribute_overrides_if_global(self):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [{
                    "hostname": "argo.webui__argo.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_USERNAME",
                    "value": "$NI4OS_NAGIOS_FRESHNESS_USERNAME"
                }, {
                    "hostname": "argo.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_PASSWORD",
                    "value": "$NI4OS_NAGIOS_FRESHNESS_PASSWORD"
                }, {
                    "hostname": "argo-devel.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_PASSWORD",
                    "value": "$NI4OS_DEVEL_NAGIOS_FRESHNESS_PASSWORD"
                }, {
                    "hostname": "b2handle3.test.com",
                    "attribute": "B2HANDLE_PREFIX",
                    "value": "123456"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST26"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.test__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_tcp_connect": "generic.tcp.connect",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.test",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "argo_nagios_freshness_simple_login":
                                "argo.nagios.freshness-simple-login",
                            "nagios_freshness_username":
                                "$NAGIOS_FRESHNESS_USERNAME",
                            "nagios_freshness_password":
                                "$NI4OS_DEVEL_NAGIOS_FRESHNESS_PASSWORD",
                            "hostname": "argo-devel.ni4os.eu",
                            "info_url": "http://argo-devel.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "argo_nagios_freshness_simple_login":
                                "argo.nagios.freshness-simple-login",
                            "nagios_freshness_username":
                                "$NI4OS_NAGIOS_FRESHNESS_USERNAME",
                            "nagios_freshness_password":
                                "$NI4OS_NAGIOS_FRESHNESS_PASSWORD",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "b2handle.test__b2handle3.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_b2handle_handle_api_healthcheck_resolve":
                                "eudat.b2handle.handle.api-healthcheck-resolve",
                            "b2handle_prefix": "123456",
                            "hostname": "b2handle3.test.com",
                            "service": "b2handle.test",
                            "site": "B2HANDLE-TEST",
                            "ngi": "EUDAT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_overridden_secrets_with_dots(self):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [{
                    "hostname": "api.devel.argo.grnet.gr",
                    "attribute": "argo.api_TOKEN",
                    "value": "$DEVEL_API_TOKEN"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST23"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="/path/to/secrets",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.api__api.argo.grnet.gr",
                        "namespace": "default",
                        "labels": {
                            "argo_api_check": "argo.API-Check",
                            "argo_api_token": "$ARGO_API_TOKEN",
                            "hostname": "api.argo.grnet.gr",
                            "info_url": "https://api.argo.grnet.gr/",
                            "service": "argo.api",
                            "site": "ARGO",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.api__api.devel.argo.grnet.gr",
                        "namespace": "default",
                        "labels": {
                            "argo_api_check": "argo.API-Check",
                            "argo_api_token": "$DEVEL_API_TOKEN",
                            "hostname": "api.devel.argo.grnet.gr",
                            "info_url": "https://api.devel.argo.grnet.gr/",
                            "service": "argo.api",
                            "site": "ARGO",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_configuration_with_internal_metrics(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST27"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            entities,
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.test__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_tcp_connect": "generic.tcp.connect",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.test",
                            "site": "GRNET",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_with_attribute_ending_in_url_not_servicetype_url(
            self
    ):
        attributes = {
            "local": {
                "global_attributes": [
                    {
                        "attribute": "ARGO_OIDC_SP_URL",
                        "value":
                            "https://snf-666522.vm.okeanos.grnet.gr/ni4os-rp/"
                            "auth.php"
                    }
                ],
                "host_attributes": [],
                "metric_parameters": []
            }
        }
        topology = [
            {
                "group": "ARGO",
                "service": "argo.oidc.login",
                "hostname": "aai.argo.eu",
                "tags": {}
            }
        ]
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST28"],
            metric_profiles=mock_metric_profiles,
            topology=topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            entities, [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.oidc.login__aai.argo.eu",
                        "namespace": "default",
                        "labels": {
                            "grnet_rciam_oidc_login_edugain":
                                "grnet.rciam.oidc-login-edugain",
                            "hostname": "aai.argo.eu",
                            "service": "argo.oidc.login",
                            "site": "ARGO",
                            "ngi": "",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_with_attribute_ending_in_url_in_extensions(self):
        topology = [
            {
                "date": "2022-03-25",
                "group": "CERN-PROD",
                "type": "SITES",
                "service": "webdav",
                "hostname": "hostname.cern.ch",
                "ngi": "CERN",
                "tags": {
                    "info_ID": "xxxxxxx",
                    "info_URL": "https://hostname.cern.ch/atlas/opstest",
                    "monitored": "1",
                    "production": "1",
                    "scope": "EGI"
                }
            },
            {
                "date": "2022-03-25",
                "group": "CERN-PROD",
                "type": "SITES",
                "service": "webdav",
                "hostname": "hostname2.cern.ch",
                "ngi": "CERN",
                "tags": {
                    "info_ID": "xxxxxxx",
                    "info_URL": "https://hostname2.cern.ch/atlas/opstest",
                    "info_ext_webdav_URL": "https://meh.cern.ch/atlas/opstest",
                    "monitored": "1",
                    "production": "1",
                    "scope": "EGI"
                }
            }
        ]
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST29"],
            metric_profiles=mock_metric_profiles,
            topology=topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "webdav__hostname.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "ch_cern_webdav": "ch.cern.WebDAV",
                            "info_url":
                                "https://hostname.cern.ch/atlas/opstest",
                            "webdav_url":
                                "https://hostname.cern.ch/atlas/opstest",
                            "hostname": "hostname.cern.ch",
                            "service": "webdav",
                            "site": "CERN-PROD",
                            "ngi": "CERN",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "webdav__hostname2.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "ch_cern_webdav": "ch.cern.WebDAV",
                            "info_url":
                                "https://hostname2.cern.ch/atlas/opstest",
                            "webdav_url": "https://meh.cern.ch/atlas/opstest",
                            "hostname": "hostname2.cern.ch",
                            "service": "webdav",
                            "site": "CERN-PROD",
                            "ngi": "CERN",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_with_hostname_in_tags(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST30"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology_with_hostname_in_tag,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.eosc.portal.services.url__"
                                "hostname1.argo.com_hostname1_id",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "generic_http_connect_path": "-u /path",
                            "ssl": "-S --sni",
                            "info_url":
                                "https://hostname1.argo.com/path",
                            "hostname": "hostname1.argo.com",
                            "service": "eu.eosc.portal.services.url",
                            "site": "test1",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.eosc.portal.services.url__"
                                "hostname2.argo.eu_second.id",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "info_url": "https://hostname2.argo.eu",
                            "hostname": "hostname2.argo.eu",
                            "ssl": "-S --sni",
                            "service": "eu.eosc.portal.services.url",
                            "site": "test2.test",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.eosc.portal.services.url__"
                                "hostname3.argo.eu_test.id",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "info_url": "http://hostname3.argo.eu/",
                            "generic_http_connect_path": "-u /",
                            "hostname": "hostname3.argo.eu",
                            "service": "eu.eosc.portal.services.url",
                            "site": "group3",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_for_check_with_path_attribute(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST32"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            entities, [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.json__test-json.argo.grnet.gr",
                        "namespace": "default",
                        "labels": {
                            "generic_http_json": "generic.http.json",
                            "generic_http_json_path": "-p /some/path",
                            "info_url":
                                "https://test-json.argo.grnet.gr/some/path",
                            "hostname": "test-json.argo.grnet.gr",
                            "service": "argo.json",
                            "site": "ARGO",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_for_check_with_overridden_default_param(self):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [],
                "metric_parameters": [{
                    "hostname": "test.argo.grnet.gr",
                    "metric": "eosc.test.api",
                    "parameter": "-l",
                    "value": "/var/log/sensu/test.log"
                }, {
                    "hostname": "test3.argo.grnet.gr",
                    "metric": "eosc.test.api",
                    "parameter": "-l",
                    "value": "/var/log/meh/test.log"
                }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST33"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "probe.test__test.argo.grnet.gr",
                        "namespace": "default",
                        "labels": {
                            "eosc_test_api": "eosc.test.api",
                            "eosc_test_api_l": "-l /var/log/sensu/test.log",
                            "info_url":
                                "https://test.argo.grnet.gr/some/extra/path",
                            "endpoint_url":
                                "https://test.argo.grnet.gr/some/extra/path",
                            "hostname": "test.argo.grnet.gr",
                            "service": "probe.test",
                            "site": "ARGO",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "probe.test__test2.argo.grnet.gr",
                        "namespace": "default",
                        "labels": {
                            "eosc_test_api": "eosc.test.api",
                            "eosc_test_api_l": "",
                            "info_url":
                                "https://test2.argo.grnet.gr/some/extra2/path",
                            "endpoint_url":
                                "https://test2.argo.grnet.gr/some/extra2/path",
                            "hostname": "test2.argo.grnet.gr",
                            "service": "probe.test",
                            "site": "ARGO",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "probe.test__test3.argo.grnet.gr",
                        "namespace": "default",
                        "labels": {
                            "eosc_test_api": "eosc.test.api",
                            "eosc_test_api_l": "-l /var/log/meh/test.log",
                            "info_url":
                                "https://test3.argo.grnet.gr/some/extra3/path",
                            "endpoint_url":
                                "https://test3.argo.grnet.gr/some/extra3/path",
                            "hostname": "test3.argo.grnet.gr",
                            "service": "probe.test",
                            "site": "ARGO",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_for_check_with_overridden_deflt_param_entity_name(
            self
    ):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [],
                "metric_parameters": [{
                    "hostname": "probe.test__test.argo.grnet.gr",
                    "metric": "eosc.test.api",
                    "parameter": "-l",
                    "value": "/var/log/sensu/test.log"
                }, {
                    "hostname": "probe.test__test3.argo.grnet.gr",
                    "metric": "eosc.test.api",
                    "parameter": "-l",
                    "value": "/var/log/meh/test.log"
                }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST33"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "probe.test__test.argo.grnet.gr",
                        "namespace": "default",
                        "labels": {
                            "eosc_test_api": "eosc.test.api",
                            "eosc_test_api_l": "-l /var/log/sensu/test.log",
                            "info_url":
                                "https://test.argo.grnet.gr/some/extra/path",
                            "endpoint_url":
                                "https://test.argo.grnet.gr/some/extra/path",
                            "hostname": "test.argo.grnet.gr",
                            "service": "probe.test",
                            "site": "ARGO",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "probe.test__test2.argo.grnet.gr",
                        "namespace": "default",
                        "labels": {
                            "eosc_test_api": "eosc.test.api",
                            "eosc_test_api_l": "",
                            "info_url":
                                "https://test2.argo.grnet.gr/some/extra2/path",
                            "endpoint_url":
                                "https://test2.argo.grnet.gr/some/extra2/path",
                            "hostname": "test2.argo.grnet.gr",
                            "service": "probe.test",
                            "site": "ARGO",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "probe.test__test3.argo.grnet.gr",
                        "namespace": "default",
                        "labels": {
                            "eosc_test_api": "eosc.test.api",
                            "eosc_test_api_l": "-l /var/log/meh/test.log",
                            "info_url":
                                "https://test3.argo.grnet.gr/some/extra3/path",
                            "endpoint_url":
                                "https://test3.argo.grnet.gr/some/extra3/path",
                            "hostname": "test3.argo.grnet.gr",
                            "service": "probe.test",
                            "site": "ARGO",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_with_hostalias(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST34"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            entities,
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "b2handle__b2handle.test.example.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_b2handle_handle_api_crud":
                                "eudat.b2handle.handle.api-crud",
                            "eudat_b2handle_handle_api_crud_f":
                                "/etc/nagios/plugins/eudat-b2handle/"
                                "b2handle.test.example.com/credentials.json",
                            "info_url": "https://b2handle.test.example.com",
                            "hostname": "b2handle.test.example.com",
                            "service": "b2handle",
                            "site": "B2HANDLE",
                            "ngi": "EUDAT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_with_hostalias_with_override(self):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [],
                "metric_parameters": [
                    {
                        "hostname": "b2handle.test.example.com",
                        "metric": "eudat.b2handle.handle.api-crud",
                        "parameter": "-f",
                        "value":
                            "/etc/sensu/b2handle/$HOSTALIAS$/credentials.json"
                    }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST34"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            entities,
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "b2handle__b2handle.test.example.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_b2handle_handle_api_crud":
                                "eudat.b2handle.handle.api-crud",
                            "eudat_b2handle_handle_api_crud_f":
                                "/etc/sensu/b2handle/b2handle.test.example.com/"
                                "credentials.json",
                            "info_url": "https://b2handle.test.example.com",
                            "hostname": "b2handle.test.example.com",
                            "service": "b2handle",
                            "site": "B2HANDLE",
                            "ngi": "EUDAT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_with_duplicate_sites(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST35"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            entities,
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "b2handle.handle.api__b2handle3.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_b2handle_handle_api_crud":
                                "eudat.b2handle.handle.api-crud",
                            "eudat_b2handle_handle_api_crud_f":
                                "/etc/nagios/plugins/eudat-b2handle/"
                                "b2handle3.test.com/credentials.json",
                            "hostname": "b2handle3.test.com",
                            "service": "b2handle.handle.api",
                            "site": "ARCHIVE-B2HANDLE,B2HANDLE TEST",
                            "ngi": "EUDAT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_host_override_with_default_for_some(self):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [{
                    "hostname": "b2handle3.test.com",
                    "attribute": "B2HANDLE_PREFIX",
                    "value": "123456"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST36"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "b2handle.handle.test__b2handle.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_b2handle_handle_api_crud":
                                "eudat.b2handle.handle.api-crud",
                            "eudat_b2handle_handle_api_crud_f":
                                "/etc/nagios/plugins/eudat-b2handle/"
                                "b2handle.test.com/credentials.json",
                            "hostname": "b2handle.test.com",
                            "service": "b2handle.handle.test",
                            "site": "B2HANDLE-TEST",
                            "ngi": "EUDAT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "b2handle.handle.test__b2handle3.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_b2handle_handle_api_crud":
                                "eudat.b2handle.handle.api-crud",
                            "eudat_b2handle_handle_api_crud_f":
                                "/etc/nagios/plugins/eudat-b2handle/"
                                "b2handle3.test.com/credentials.json",
                            "b2handle_prefix": "123456",
                            "hostname": "b2handle3.test.com",
                            "service": "b2handle.handle.test",
                            "site": "ARCHIVE-B2HANDLE",
                            "ngi": "EUDAT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_host_override_with_hostalias_param_override(
            self
    ):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [{
                    "hostname": "b2handle3.test.com",
                    "attribute": "B2HANDLE_PREFIX",
                    "value": "123456"
                }],
                "metric_parameters": [{
                    "hostname": "b2handle3.test.com",
                    "metric": "eudat.b2handle.handle.api-crud",
                    "parameter": "-f",
                    "value": "/etc/nagios/plugins/eudat-b2handle/test/"
                             "credentials.json"
                }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST36"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "b2handle.handle.test__b2handle.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_b2handle_handle_api_crud":
                                "eudat.b2handle.handle.api-crud",
                            "eudat_b2handle_handle_api_crud_f":
                                "/etc/nagios/plugins/eudat-b2handle/"
                                "b2handle.test.com/credentials.json",
                            "hostname": "b2handle.test.com",
                            "service": "b2handle.handle.test",
                            "site": "B2HANDLE-TEST",
                            "ngi": "EUDAT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "b2handle.handle.test__b2handle3.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_b2handle_handle_api_crud":
                                "eudat.b2handle.handle.api-crud",
                            "eudat_b2handle_handle_api_crud_f":
                                "/etc/nagios/plugins/eudat-b2handle/"
                                "test/credentials.json",
                            "b2handle_prefix": "123456",
                            "hostname": "b2handle3.test.com",
                            "service": "b2handle.handle.test",
                            "site": "ARCHIVE-B2HANDLE",
                            "ngi": "EUDAT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_host_attr_override_if_value_with_dots(
            self
    ):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [{
                    "hostname": "b2handle3.test.com",
                    "attribute": "B2HANDLE_PREFIX",
                    "value": "123.456"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST36"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "b2handle.handle.test__b2handle.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_b2handle_handle_api_crud":
                                "eudat.b2handle.handle.api-crud",
                            "eudat_b2handle_handle_api_crud_f":
                                "/etc/nagios/plugins/eudat-b2handle/"
                                "b2handle.test.com/credentials.json",
                            "hostname": "b2handle.test.com",
                            "service": "b2handle.handle.test",
                            "site": "B2HANDLE-TEST",
                            "ngi": "EUDAT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "b2handle.handle.test__b2handle3.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_b2handle_handle_api_crud":
                                "eudat.b2handle.handle.api-crud",
                            "eudat_b2handle_handle_api_crud_f":
                                "/etc/nagios/plugins/eudat-b2handle/"
                                "b2handle3.test.com/credentials.json",
                            "b2handle_prefix": "123.456",
                            "hostname": "b2handle3.test.com",
                            "service": "b2handle.handle.test",
                            "site": "ARCHIVE-B2HANDLE",
                            "ngi": "EUDAT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_if_no_url(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST37"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "gitlab__gitlab.test.com",
                        "namespace": "default",
                        "labels": {
                            "generic_tcp_connect": "generic.tcp.connect",
                            "hostname": "gitlab.test.com",
                            "service": "gitlab",
                            "site": "GITLAB-TEST",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "gitlab__gitlab2.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_gitlab_liveness": "eudat.gitlab.liveness",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "info_url": "https://gitlab2.test.com/",
                            "endpoint_url": "https://gitlab2.test.com/",
                            "hostname": "gitlab2.test.com",
                            "service": "gitlab",
                            "site": "GITLAB-TEST",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, [
            f"WARNING:{LOGNAME}:MOCK_TENANT: Entity gitlab__gitlab.test.com "
            f"missing URL"
        ])

    def test_generate_entity_if_no_url_param_override_all(self):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [],
                "metric_parameters": [
                    {
                        "hostname": "gitlab.test.com",
                        "metric": "eudat.gitlab.liveness",
                        "parameter": "--url",
                        "value": "https://gitlab.test.com"
                    },
                    {
                        "hostname": "gitlab2.test.com",
                        "metric": "eudat.gitlab.liveness",
                        "parameter": "--url",
                        "value": "https://gitlab2.test.com/"
                    }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST38"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "gitlab2__gitlab.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_gitlab_liveness": "eudat.gitlab.liveness",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "eudat_gitlab_liveness_url":
                                "--url https://gitlab.test.com",
                            "hostname": "gitlab.test.com",
                            "service": "gitlab2",
                            "site": "GITLAB-TEST2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "gitlab2__gitlab2.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_gitlab_liveness": "eudat.gitlab.liveness",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "eudat_gitlab_liveness_url":
                                "--url https://gitlab2.test.com/",
                            "hostname": "gitlab2.test.com",
                            "service": "gitlab2",
                            "site": "GITLAB-TEST2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_if_no_url_param_override_some(self):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [],
                "metric_parameters": [
                    {
                        "hostname": "gitlab.test.com",
                        "metric": "eudat.gitlab.liveness",
                        "parameter": "--url",
                        "value": "https://gitlab.test.com"
                    }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST38"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "gitlab2__gitlab.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_gitlab_liveness": "eudat.gitlab.liveness",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "eudat_gitlab_liveness_url":
                                "--url https://gitlab.test.com",
                            "hostname": "gitlab.test.com",
                            "service": "gitlab2",
                            "site": "GITLAB-TEST2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "gitlab2__gitlab2.test.com",
                        "namespace": "default",
                        "labels": {
                            "generic_tcp_connect": "generic.tcp.connect",
                            "eudat_gitlab_liveness_url": "",
                            "hostname": "gitlab2.test.com",
                            "service": "gitlab2",
                            "site": "GITLAB-TEST2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, [
            f"WARNING:{LOGNAME}:MOCK_TENANT: Entity gitlab2__gitlab2.test.com "
            f"missing URL"
        ])

    def test_generate_entity_if_no_url_attr_override_all(self):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [{
                    "hostname": "gitlab.test.com",
                    "attribute": "URL",
                    "value": "https://gitlab.test.com"
                }, {
                    "hostname": "gitlab2.test.com",
                    "attribute": "URL",
                    "value": "https://gitlab2.test.com"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST38"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "gitlab2__gitlab.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_gitlab_liveness": "eudat.gitlab.liveness",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "endpoint_url": "https://gitlab.test.com",
                            "hostname": "gitlab.test.com",
                            "service": "gitlab2",
                            "site": "GITLAB-TEST2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "gitlab2__gitlab2.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_gitlab_liveness": "eudat.gitlab.liveness",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "endpoint_url": "https://gitlab2.test.com",
                            "hostname": "gitlab2.test.com",
                            "service": "gitlab2",
                            "site": "GITLAB-TEST2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_if_no_url_attr_override_some(self):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [{
                    "hostname": "gitlab.test.com",
                    "attribute": "URL",
                    "value": "https://gitlab.test.com"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST38"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "gitlab2__gitlab.test.com",
                        "namespace": "default",
                        "labels": {
                            "eudat_gitlab_liveness": "eudat.gitlab.liveness",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "endpoint_url": "https://gitlab.test.com",
                            "hostname": "gitlab.test.com",
                            "service": "gitlab2",
                            "site": "GITLAB-TEST2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "gitlab2__gitlab2.test.com",
                        "namespace": "default",
                        "labels": {
                            "generic_tcp_connect": "generic.tcp.connect",
                            "hostname": "gitlab2.test.com",
                            "service": "gitlab2",
                            "site": "GITLAB-TEST2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, [
            f"WARNING:{LOGNAME}:MOCK_TENANT: Entity gitlab2__gitlab2.test.com "
            f"missing URL"
        ])

    def test_generate_entity_default_port_override_by_extension_some(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST39"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui__hpc.resource.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_connect": "generic.ssh.connect",
                            "port": "1022",
                            "ssh_port": "1022",
                            "hostname": "hpc.resource.ni4os.eu",
                            "service": "eu.ni4os.hpc.ui",
                            "site": "IPB",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui__teran.srce.hr",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_connect": "generic.ssh.connect",
                            "hostname": "teran.srce.hr",
                            "service": "eu.ni4os.hpc.ui",
                            "site": "SRCE",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_default_port_override_by_extension_none(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST40"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui2__hpc.resource.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_connect": "generic.ssh.connect",
                            "port": "1022",
                            "hostname": "hpc.resource.ni4os.eu",
                            "service": "eu.ni4os.hpc.ui2",
                            "site": "IPB",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui2__teran.srce.hr",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_connect": "generic.ssh.connect",
                            "hostname": "teran.srce.hr",
                            "service": "eu.ni4os.hpc.ui2",
                            "site": "SRCE",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_default_port_override_by_global_attribute(self):
        attributes = {
            "local": {
                "global_attributes": [{
                    "attribute": "SSH_PORT",
                    "value": "1022"
                }],
                "host_attributes": [],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST40"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui2__hpc.resource.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_connect": "generic.ssh.connect",
                            "port": "1022",
                            "hostname": "hpc.resource.ni4os.eu",
                            "service": "eu.ni4os.hpc.ui2",
                            "site": "IPB",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui2__teran.srce.hr",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_connect": "generic.ssh.connect",
                            "hostname": "teran.srce.hr",
                            "service": "eu.ni4os.hpc.ui2",
                            "site": "SRCE",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_default_port_override_by_host_attribute(self):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [{
                    "hostname": "hpc.resource.ni4os.eu",
                    "attribute": "SSH_PORT",
                    "value": "1022"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST40"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui2__hpc.resource.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_connect": "generic.ssh.connect",
                            "port": "1022",
                            "ssh_port": "1022",
                            "hostname": "hpc.resource.ni4os.eu",
                            "service": "eu.ni4os.hpc.ui2",
                            "site": "IPB",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.ni4os.hpc.ui2__teran.srce.hr",
                        "namespace": "default",
                        "labels": {
                            "generic_ssh_connect": "generic.ssh.connect",
                            "hostname": "teran.srce.hr",
                            "service": "eu.ni4os.hpc.ui2",
                            "site": "SRCE",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_with_servicesite_name(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST42"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "APEL__apel.grid1.example.com",
                        "namespace": "default",
                        "labels": {
                            "argo_apel_pub": "argo.APEL-Pub",
                            "argo_apel_sync": "argo.APEL-Sync",
                            "argo_apel_pub_u": "/rss/APEL-Site1_Pub.html",
                            "argo_apel_sync_u": "/rss/APEL-Site1_Sync.html",
                            "hostname": "apel.grid1.example.com",
                            "service": "APEL",
                            "site": "APEL-Site1",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "APEL__apel.grid2.example.com",
                        "namespace": "default",
                        "labels": {
                            "argo_apel_pub": "argo.APEL-Pub",
                            "argo_apel_sync": "argo.APEL-Sync",
                            "argo_apel_pub_u": "/rss/APEL-Site2_Pub.html",
                            "argo_apel_sync_u": "/rss/APEL-Site2_Sync.html",
                            "hostname": "apel.grid2.example.com",
                            "service": "APEL",
                            "site": "APEL-Site2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_with_servicesite_name_with_override(self):
        attributes = {
            "apel": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [],
                "metric_parameters": [
                    {
                        "hostname": "apel.grid1.example.com",
                        "metric": "argo.APEL-Pub",
                        "parameter": "-u",
                        "value": "/test/$_SERVICESITE_NAME$_Pub.html",
                    }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST42"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "APEL__apel.grid1.example.com",
                        "namespace": "default",
                        "labels": {
                            "argo_apel_pub": "argo.APEL-Pub",
                            "argo_apel_sync": "argo.APEL-Sync",
                            "argo_apel_pub_u": "/test/APEL-Site1_Pub.html",
                            "argo_apel_sync_u": "/rss/APEL-Site1_Sync.html",
                            "hostname": "apel.grid1.example.com",
                            "service": "APEL",
                            "site": "APEL-Site1",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "APEL__apel.grid2.example.com",
                        "namespace": "default",
                        "labels": {
                            "argo_apel_pub": "argo.APEL-Pub",
                            "argo_apel_sync": "argo.APEL-Sync",
                            "argo_apel_pub_u": "/rss/APEL-Site2_Pub.html",
                            "argo_apel_sync_u": "/rss/APEL-Site2_Sync.html",
                            "hostname": "apel.grid2.example.com",
                            "service": "APEL",
                            "site": "APEL-Site2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_for_http_check_if_no_URL(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST43"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "egi.AppDB__appdb.egi.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "hostname": "appdb.egi.eu",
                            "service": "egi.AppDB",
                            "site": "APPDB",
                            "ngi": "EGI.eu",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "web.check__bioinformatics.cing.ac.cy",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "info_url":
                                "https://bioinformatics.cing.ac.cy/"
                                "MelGene?bla=oai%3meh",
                            "ssl": "-S --sni",
                            "generic_http_connect_path":
                                "-u /MelGene?bla=oai%3meh",
                            "hostname": "bioinformatics.cing.ac.cy",
                            "service": "web.check",
                            "site": "CING",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "web.check__eewrc-las.cyi.ac.cy",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "info_url":
                                "http://eewrc-las.cyi.ac.cy/las/getUI.do",
                            "generic_http_connect_path": "-u /las/getUI.do",
                            "hostname": "eewrc-las.cyi.ac.cy",
                            "service": "web.check",
                            "site": "CYI",
                            "ngi": "NI4OS",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "web.check__sampaeos.if.usp.br",
                        "namespace": "default",
                        "labels": {
                            "generic_http_connect": "generic.http.connect",
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "info_url":
                                "https://sampaeos.if.usp.br:9000//eos/ops/"
                                "opstest/",
                            "ssl": "-S --sni",
                            "generic_http_connect_port": "-p 9000",
                            "generic_http_connect_path":
                                "-u //eos/ops/opstest/",
                            "hostname": "sampaeos.if.usp.br",
                            "service": "web.check",
                            "site": "SAMPA",
                            "ngi": "ROC_LA",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_if_attribute_with_dash(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST44"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "ch.cern.cvmfs.stratum.1__cclssts1.in2p3.fr",
                        "namespace": "default",
                        "labels": {
                            "argo_cvmfs_stratum_1_status":
                                "argo.cvmfs-stratum-1.status",
                            "cvmfs_stratum_1_port": "80",
                            "hostname": "cclssts1.in2p3.fr",
                            "service": "ch.cern.cvmfs.stratum.1",
                            "site": "IN2P3-CC",
                            "ngi": "NGI_FRANCE",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name":
                            "ch.cern.cvmfs.stratum.1__cvmfs-stratum-one.cc.kek."
                            "jp",
                        "namespace": "default",
                        "labels": {
                            "argo_cvmfs_stratum_1_status":
                                "argo.cvmfs-stratum-1.status",
                            "hostname": "cvmfs-stratum-one.cc.kek.jp",
                            "service": "ch.cern.cvmfs.stratum.1",
                            "site": "JP-KEK-CRC-02",
                            "ngi": "AsiaPacific",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_if_info_bdii_tag(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST46"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "SRM__dcache-se-cms.desy.de",
                        "namespace": "default",
                        "labels": {
                            "generic_certificate_validity_srm":
                                "generic.certificate.validity-srm",
                            "srm2_port": "8443",
                            "hostname": "dcache-se-cms.desy.de",
                            "service": "SRM",
                            "site": "DESY-HH",
                            "ngi": "NGI_DE",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "SRM__dcache.arnes.si",
                        "namespace": "default",
                        "labels": {
                            "generic_certificate_validity_srm":
                                "generic.certificate.validity-srm",
                            "srm2_port": "8443",
                            "hostname": "dcache.arnes.si",
                            "service": "SRM",
                            "site": "ARNES",
                            "ngi": "NGI_SI",
                            "info_hostdn":
                                "/C=SI/O=SiGNET/O=Arnes/CN=dcache.arnes.si",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "SRM__dcache6-shadow.iihe.ac.be",
                        "namespace": "default",
                        "labels": {
                            "generic_certificate_validity_srm":
                                "generic.certificate.validity-srm",
                            "hostname": "dcache6-shadow.iihe.ac.be",
                            "service": "SRM",
                            "site": "BEgrid-ULB-VUB",
                            "ngi": "NGI_NL",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_if_ampersand_in_URL(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST47"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            entities,
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.eosc.generic.oai-pmh__lida.dataverse.lt",
                        "namespace": "default",
                        "labels": {
                            "generic_oai_pmh_validity":
                                "generic.oai-pmh.validity",
                            "endpoint_url":
                                "\"https://lida.dataverse.lt/oai?verb="
                                "ListRecords&metadataPrefix=oai_datacite&set="
                                "lida_survey_data\"",
                            "info_url":
                                "\"https://lida.dataverse.lt/oai?verb="
                                "ListRecords&metadataPrefix=oai_datacite&set="
                                "lida_survey_data\"",
                            "hostname": "lida.dataverse.lt",
                            "service": "eu.eosc.generic.oai-pmh",
                            "site": "lida.lida_survey_data",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_with_integer_attributes(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST48"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "XRootD__atlas.dcache.example.eu",
                        "namespace": "default",
                        "labels": {
                            "egi_xrootd_readwrite": "egi.xrootd.readwrite",
                            "e__argo_xrootd_ops_url":
                                "-E "
                                "root://atlas.dcache.example.eu:1094/data/ops/",
                            "info_url": "root://atlas.dcache.example.eu:1094/",
                            "hostname": "atlas.dcache.example.eu",
                            "service": "XRootD",
                            "site": "XROOTD-SITE1",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "XRootD__castorpublic.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "egi_xrootd_readwrite": "egi.xrootd.readwrite",
                            "e__argo_xrootd_ops_url": "",
                            "hostname": "castorpublic.cern.ch",
                            "service": "XRootD",
                            "site": "CERN-PROD",
                            "ngi": "CERN",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "XRootD__xrootd.example.eu",
                        "namespace": "default",
                        "labels": {
                            "egi_xrootd_readwrite": "egi.xrootd.readwrite",
                            "info_url": "root://xrootd.example.eu:1094",
                            "e__argo_xrootd_ops_url":
                                "-E root://xrootd.example.eu:1094/ops/",
                            "skip_ls_dir__argo_xrootd_skip_ls_dir":
                                "--skip-ls-dir ",
                            "endpoint_url": "root://xrootd.example.eu:1094",
                            "hostname": "xrootd.example.eu",
                            "service": "XRootD",
                            "site": "XROOTD-SITE2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_with_xrootd_webdav_extension(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST49"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "XRootD__atlas.dcache.example.eu",
                        "namespace": "default",
                        "labels": {
                            "egi_xrootd_readwrite": "egi.xrootd.readwrite",
                            "e__argo_xrootd_ops_url":
                                "-E "
                                "root://atlas.dcache.example.eu:1094/data/ops/",
                            "info_url": "root://atlas.dcache.example.eu:1094/",
                            "hostname": "atlas.dcache.example.eu",
                            "service": "XRootD",
                            "site": "XROOTD-SITE1",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "XRootD__castorpublic.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "egi_xrootd_readwrite": "egi.xrootd.readwrite",
                            "e__argo_xrootd_ops_url": "",
                            "hostname": "castorpublic.cern.ch",
                            "service": "XRootD",
                            "site": "CERN-PROD",
                            "ngi": "CERN",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "XRootD__xrootd.example.eu",
                        "namespace": "default",
                        "labels": {
                            "egi_xrootd_readwrite": "egi.xrootd.readwrite",
                            "info_url": "root://xrootd.example.eu:1094",
                            "e__argo_xrootd_ops_url":
                                "-E root://xrootd.example.eu:1094/ops/",
                            "skip_ls_dir__argo_xrootd_skip_ls_dir":
                                "--skip-ls-dir ",
                            "endpoint_url": "root://xrootd.example.eu:1094",
                            "hostname": "xrootd.example.eu",
                            "service": "XRootD",
                            "site": "XROOTD-SITE2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "webdav__eosatlas.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "cern_webdav_status": "cern.webdav.status",
                            "u__argo_webdav_ops_url":
                                "-u https://eosatlas.cern.ch//eos/atlas/"
                                "opstest/egi/",
                            "skip_dir_test__argo_webdav_skip_dir_test":
                                "--skip-dir-test ",
                            "info_url":
                                "https://eosatlas.cern.ch//eos/atlas/opstest",
                            "hostname": "eosatlas.cern.ch",
                            "service": "webdav",
                            "site": "CERN-PROD",
                            "ngi": "CERN",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "webdav__hostname.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "cern_webdav_status": "cern.webdav.status",
                            "u__argo_webdav_ops_url": "",
                            "info_url":
                                "https://hostname.cern.ch/atlas/opstest",
                            "hostname": "hostname.cern.ch",
                            "service": "webdav",
                            "site": "CERN-PROD",
                            "ngi": "CERN",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_with_xrootd_webdav_extension_with_override(self):
        attributes = {
            "local": {
                "global_attributes": [
                    {
                        "attribute": "X509_USER_PROXY",
                        "value": "/etc/sensu/certs/userproxy.pem"
                    }
                ],
                "host_attributes": [{
                    "hostname": "castorpublic.cern.ch",
                    "attribute": "ARGO_XROOTD_OPS_URL",
                    "value": "root://castorpublic.cern.ch/data/ops/"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST49"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "XRootD__atlas.dcache.example.eu",
                        "namespace": "default",
                        "labels": {
                            "egi_xrootd_readwrite": "egi.xrootd.readwrite",
                            "e__argo_xrootd_ops_url":
                                "-E "
                                "root://atlas.dcache.example.eu:1094/data/ops/",
                            "info_url": "root://atlas.dcache.example.eu:1094/",
                            "hostname": "atlas.dcache.example.eu",
                            "service": "XRootD",
                            "site": "XROOTD-SITE1",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "XRootD__castorpublic.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "egi_xrootd_readwrite": "egi.xrootd.readwrite",
                            "e__argo_xrootd_ops_url":
                                "-E root://castorpublic.cern.ch/data/ops/",
                            "hostname": "castorpublic.cern.ch",
                            "service": "XRootD",
                            "site": "CERN-PROD",
                            "ngi": "CERN",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "XRootD__xrootd.example.eu",
                        "namespace": "default",
                        "labels": {
                            "egi_xrootd_readwrite": "egi.xrootd.readwrite",
                            "info_url": "root://xrootd.example.eu:1094",
                            "e__argo_xrootd_ops_url":
                                "-E root://xrootd.example.eu:1094/ops/",
                            "skip_ls_dir__argo_xrootd_skip_ls_dir":
                                "--skip-ls-dir ",
                            "endpoint_url": "root://xrootd.example.eu:1094",
                            "hostname": "xrootd.example.eu",
                            "service": "XRootD",
                            "site": "XROOTD-SITE2",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "webdav__eosatlas.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "cern_webdav_status": "cern.webdav.status",
                            "u__argo_webdav_ops_url":
                                "-u https://eosatlas.cern.ch//eos/atlas/"
                                "opstest/egi/",
                            "skip_dir_test__argo_webdav_skip_dir_test":
                                "--skip-dir-test ",
                            "info_url":
                                "https://eosatlas.cern.ch//eos/atlas/opstest",
                            "hostname": "eosatlas.cern.ch",
                            "service": "webdav",
                            "site": "CERN-PROD",
                            "ngi": "CERN",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "webdav__hostname.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "cern_webdav_status": "cern.webdav.status",
                            "u__argo_webdav_ops_url": "",
                            "info_url":
                                "https://hostname.cern.ch/atlas/opstest",
                            "hostname": "hostname.cern.ch",
                            "service": "webdav",
                            "site": "CERN-PROD",
                            "ngi": "CERN",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_with_duplicates_in_topology(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST50"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology_with_duplicate_entries,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "webdav__eosatlas.cern.ch",
                        "namespace": "default",
                        "labels": {
                            "cern_webdav_status": "cern.webdav.status",
                            "u__argo_webdav_ops_url":
                                "-u https://eosatlas.cern.ch//eos/atlas/"
                                "opstest/egi/",
                            "skip_dir_test__argo_webdav_skip_dir_test":
                                "--skip-dir-test ",
                            "info_url":
                                "https://eosatlas.cern.ch//eos/atlas/opstest",
                            "hostname": "eosatlas.cern.ch",
                            "service": "webdav",
                            "site": "CERN-PROD",
                            "ngi": "CERN",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "webdav__webdav.test.de",
                        "namespace": "default",
                        "labels": {
                            "cern_webdav_status": "cern.webdav.status",
                            "u__argo_webdav_ops_url":
                                "-u https://webdav.test.de:2881/ops/",
                            "info_url": "davs://webdav.test.de:2880",
                            "hostname": "webdav.test.de",
                            "service": "webdav",
                            "site": "UNI-TEST",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "webdav__xrootd.example.de",
                        "namespace": "default",
                        "labels": {
                            "cern_webdav_status": "cern.webdav.status",
                            "u__argo_webdav_ops_url":
                                "-u https://xrootd.example.de:1094//cephfs/"
                                "grid/ops",
                            "info_url":
                                "https://xrootd.example.de:1094/cephfs/grid/"
                                "ops",
                            "hostname": "xrootd.example.de",
                            "service": "webdav",
                            "site": "UNI-EXAMPLE",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entity_if_non_fallback_attribute_in_every_endpoint(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST53"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            entities,
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eu.egi.readonly.xrootd__xrootd01.readonly.eu",
                        "namespace": "default",
                        "labels": {
                            "egi_xrootd_readonly": "egi.xrootd.readonly",
                            "argo_xrootd_ops_url":
                                "root://xrootd01.readonly.eu:1094/ops/"
                                "xrootd_tests",
                            "e__argo_xrootd_ops_url":
                                "-E root://xrootd01.readonly.eu:1094/ops/"
                                "xrootd_tests",
                            "endpoint_url":
                                "root://xrootd01.readonly.eu:1094/ops/"
                                "xrootd_tests",
                            "hostname": "xrootd01.readonly.eu",
                            "service": "eu.egi.readonly.xrootd",
                            "site": "XROOTD-READONLY",
                            "ngi": "TEST",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_skipped_metrics(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST13"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            skipped_metrics=[
                "org.nagios.Keystone-TCP", "eu.egi.cloud.OpenStack-Swift"
            ],
            tenant="MOCK_TENANT",
            default_agent=["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "org.openstack.nova__"
                                "cloud-api-pub.cr.cnaf.infn.it",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_infoprovider":
                                "eu.egi.cloud.InfoProvider",
                            "eu_egi_cloud_openstack_vm":
                                "eu.egi.cloud.OpenStack-VM",
                            "info_url":
                                "https://cloud-api-pub.cr.cnaf.infn.it:5000/v3",
                            "os_keystone_url":
                                "https://cloud-api-pub.cr.cnaf.infn.it:5000/v3",
                            "os_keystone_port": "5000",
                            "os_keystone_host": "cloud-api-pub.cr.cnaf.infn.it",
                            "hostname": "cloud-api-pub.cr.cnaf.infn.it",
                            "region__os_region": "--region sdds",
                            "service": "org.openstack.nova",
                            "site": "INFN-CLOUD-CNAF",
                            "ngi": "NGI_IT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "org.openstack.nova__egi-cloud.pd.infn.it",
                        "namespace": "default",
                        "labels": {
                            "eu_egi_cloud_infoprovider":
                                "eu.egi.cloud.InfoProvider",
                            "eu_egi_cloud_openstack_vm":
                                "eu.egi.cloud.OpenStack-VM",
                            "info_url": "https://egi-cloud.pd.infn.it:443/v3",
                            "os_keystone_url":
                                "https://egi-cloud.pd.infn.it:443/v3",
                            "os_keystone_port": "443",
                            "os_keystone_host": "egi-cloud.pd.infn.it",
                            "hostname": "egi-cloud.pd.infn.it",
                            "service": "org.openstack.nova",
                            "site": "INFN-PADOVA-STACK",
                            "ngi": "NGI_IT",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_optional_attributes(self):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [{
                    "hostname": "test.argo.eu",
                    "attribute": "ARGO_JSON_KEY",
                    "value": "key1.key2"
                }, {
                    "hostname": "test.argo.eu",
                    "attribute": "ARGO_JSON_CRITICAL",
                    "value": ":0"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST57"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent=["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.test.json.api__test.argo.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_json_connect": "generic.json.connect",
                            "endpoint_url":
                                '"https://test.argo.eu/api/DataSets/v2/search'
                                '?q=house&metadataLanguage=en"',
                            "k__argo_json_key": "-k key1.key2",
                            "c__argo_json_critical": "-c :0",
                            "info_url":
                                '"https://test.argo.eu/api/DataSets/v2/search?'
                                'q=house&metadataLanguage=en"',
                            "hostname": "test.argo.eu",
                            "service": "argo.test.json.api",
                            "site": "TEST_API",
                            "ngi": "",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.test.json.api__test2.argo.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_json_connect": "generic.json.connect",
                            "endpoint_url":
                                "https://test2.argo.eu/v2/"
                                "vocabularies-published",
                            "info_url":
                                "https://test2.argo.eu/v2/vocabularies-"
                                "published",
                            "hostname": "test2.argo.eu",
                            "service": "argo.test.json.api",
                            "site": "TEST_API",
                            "ngi": "",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_entities_with_repeating_servicetypes(self):
        self.maxDiff = None
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST58", "ARGO_TEST59"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent=["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            entities = generator.generate_entities()
        self.assertEqual(
            sorted(entities, key=lambda k: k["metadata"]["name"]),
            [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "eudat.cms.confluence__wiki.eduuni.fi",
                        "namespace": "default",
                        "labels": {
                            "generic_tcp_connect": "generic.tcp.connect",
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "wiki.eduuni.fi",
                            "ssl": "-S --sni",
                            "generic_http_connect_path":
                                "-u /display/EUDATCDI/",
                            "info_url":
                                "https://wiki.eduuni.fi/display/EUDATCDI/",
                            "service": "eudat.cms.confluence",
                            "site": "CSC",
                            "ngi": "",
                            "state": "production",
                            "tenants": "MOCK_TENANT"
                        }
                    }
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_generate_internal_services(self):
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST1", "ARGO_TEST2", "ARGO_TEST27"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=mock_attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent=["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            services = generator.generate_internal_services()
        self.assertEqual(services, "argo.test,argo.webui")
        self.assertEqual(log.output, DUMMY_LOG)


class OverridesTests(unittest.TestCase):
    def test_get_metric_parameter_overrides(self):
        attributes = {
            "local": {
                "global_attributes": [],
                "host_attributes": [],
                "metric_parameters": [{
                    "hostname": "argo.ni4os.eu",
                    "metric": "generic.tcp.connect",
                    "parameter": "-p",
                    "value": "80"
                }, {
                    "hostname": "argo-devel.ni4os.eu",
                    "metric": "generic.tcp.connect",
                    "parameter": "-p",
                    "value": "90"
                }]
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST25"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            overrides = generator.get_metric_parameter_overrides()

        self.assertEqual(
            overrides, [{
                "metric": "generic.tcp.connect",
                "hostname": "argo.ni4os.eu",
                "parameter": "-p",
                "label": "generic_tcp_connect_p",
                "value": "80"
            }, {
                "metric": "generic.tcp.connect",
                "hostname": "argo-devel.ni4os.eu",
                "parameter": "-p",
                "label": "generic_tcp_connect_p",
                "value": "90"
            }]
        )
        self.assertEqual(log.output, DUMMY_LOG)

    def test_get_host_attribute_overrides(self):
        attributes = {
            "local": {
                "global_attributes":
                    mock_attributes["local"]["global_attributes"],
                "host_attributes": [{
                    "hostname": "argo.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_USERNAME",
                    "value": "$NI4OS_NAGIOS_FRESHNESS_USERNAME"
                }, {
                    "hostname": "argo.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_PASSWORD",
                    "value": "NI4OS_NAGIOS_FRESHNESS_PASSWORD"
                }],
                "metric_parameters": []
            }
        }
        generator = ConfigurationGenerator(
            metrics=mock_metrics,
            profiles=["ARGO_TEST26"],
            metric_profiles=mock_metric_profiles,
            topology=mock_topology,
            attributes=attributes,
            secrets_file="",
            default_ports=mock_default_ports,
            tenant="MOCK_TENANT",
            default_agent = ["sensu-agent-mock_tenant.example.com"]
        )
        with self.assertLogs(LOGNAME) as log:
            _log_dummy()
            overrides = generator.get_host_attribute_overrides()

        self.assertEqual(
            sorted(overrides, key=lambda m: m["attribute"]),
            [
                {
                    "hostname": "argo.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_PASSWORD",
                    "label": "nagios_freshness_password",
                    "value": "NI4OS_NAGIOS_FRESHNESS_PASSWORD",
                    "metrics": ["argo.nagios.freshness-simple-login"]
                },
                {
                    "hostname": "argo.ni4os.eu",
                    "attribute": "NAGIOS_FRESHNESS_USERNAME",
                    "label": "nagios_freshness_username",
                    "value": "$NI4OS_NAGIOS_FRESHNESS_USERNAME",
                    "metrics": ["argo.nagios.freshness-simple-login"]
                }
            ]
        )
        self.assertEqual(log.output, DUMMY_LOG)


class AdHocCheckTests(unittest.TestCase):
    def test_generate_adhoc_check(self):
        command = \
            "/usr/lib64/nagios/plugins/check_tcp -H argo.ni4os.eu -t 120 -p 443"

        check = generate_adhoc_check(
            command=command, subscriptions=["internals"], namespace="TENANT1"
        )

        self.assertEqual(
            check, {
                "command": "/usr/lib64/nagios/plugins/check_tcp -H "
                           "argo.ni4os.eu -t 120 -p 443",
                "subscriptions": ["internals"],
                "handlers": [],
                "interval": 86400,
                "timeout": 900,
                "publish": False,
                "metadata": {
                    "name": "adhoc-check",
                    "namespace": "TENANT1"
                },
                "round_robin": False
            }
        )


class ConfigurationMergerTests(unittest.TestCase):
    def setUp(self):
        self.checks1 = [
            {
                "command": "/usr/lib64/nagios/plugins/check_http "
                           "-H {{ .labels.hostname }} -t 60 --link "
                           "--onredirect follow {{ .labels.ssl | "
                           "default " " }} {{ .labels."
                           "generic_http_connect_port | default " " }} "
                           "{{ .labels.generic_http_connect_path | "
                           "default " " }}",
                "subscriptions": [
                    "entity:sensu-agent-mock_tenant.example.com"
                ],
                "handlers": [],
                "pipelines": [
                    {
                        "name": "hard_state",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.generic_http_connect == "
                        "'generic.http.connect'"
                    ]
                },
                "interval": 300,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "generic.http.connect",
                    "namespace": "test",
                    "annotations": {
                        "attempts": "3"
                    },
                    "labels": {
                        "tenants": "TENANT1"
                    }
                },
                "round_robin": False
            },
            {
                "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                           "-H {{ .labels.hostname }} -t 60 -w 14 -c 0 "
                           "-N --altnames --rootcert-dir "
                           "/etc/grid-security/certificates "
                           "--rootcert-file /etc/pki/tls/certs/"
                           "ca-bundle.crt "
                           "-C /etc/sensu/certs/hostcert.pem "
                           "-K /etc/sensu/certs/hostkey.pem",
                "subscriptions": [
                    "entity:sensu-agent-mock_tenant.example.com"
                ],
                "handlers": [],
                "pipelines": [
                    {
                        "name": "hard_state",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.generic_certificate_validity == "
                        "'generic.certificate.validity'"
                    ]
                },
                "interval": 14400,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "generic.certificate.validity",
                    "namespace": "test",
                    "annotations": {
                        "attempts": "2"
                    },
                    "labels": {
                        "tenants": "TENANT1"
                    }
                },
                "round_robin": False
            },
            {
                "command": "/usr/libexec/argo/probes/argo_tools/"
                           "check_log -t 120 --file /var/log/"
                           "argo-poem-tools/argo-poem-tools.log "
                           "--age 2 --app argo-poem-packages",
                "subscriptions": [
                    "entity:sensu-agent-mock_tenant.example.com"
                ],
                "handlers": [],
                "pipelines": [
                    {
                        "name": "reduce_alerts",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ],
                "interval": 7200,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "argo.poem-tools.check",
                    "namespace": "test",
                    "annotations": {
                        "attempts": "4"
                    },
                    "labels": {
                        "tenants": "TENANT1"
                    }
                },
                "round_robin": False
            }
        ]
        self.checks2 = [
            {
                "command": "/usr/libexec/argo/probes/xml/check_xml "
                           "-t 30 -u {{ .labels.endpoint_url}} "
                           "-x /aris/partition/state_up --ok up",
                "subscriptions": [
                    "entity:sensu-agent-mock_tenant.example.com"
                ],
                "handlers": [],
                "pipelines": [
                    {
                        "name": "hard_state",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ],
                "proxy_requests": {
                    "entity_attributes": [
                        "entity.entity_class == 'proxy'",
                        "entity.labels.generic_xml_check == "
                        "'generic.xml.check'"
                    ]
                },
                "interval": 1800,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "generic.xml.check",
                    "namespace": "test",
                    "annotations": {
                        "attempts": "3"
                    },
                    "labels": {
                        "tenants": "TENANT2"
                    }
                },
                "round_robin": False
            },
            {
                "command": "/usr/libexec/argo/probes/argo_tools/"
                           "check_log -t 120 --file /var/log/"
                           "argo-poem-tools/argo-poem-tools.log "
                           "--age 2 --app argo-poem-packages",
                "subscriptions": [
                    "entity:sensu-agent-mock_tenant.example.com"
                ],
                "handlers": [],
                "pipelines": [
                    {
                        "name": "reduce_alerts",
                        "type": "Pipeline",
                        "api_version": "core/v2"
                    }
                ],
                "interval": 7200,
                "timeout": 900,
                "publish": True,
                "metadata": {
                    "name": "argo.poem-tools.check",
                    "namespace": "test",
                    "annotations": {
                        "attempts": "4"
                    },
                    "labels": {
                        "tenants": "TENANT2"
                    }
                },
                "round_robin": False
            }
        ]
        self.entities1 = [
            {
                "entity_class": "proxy",
                "metadata": {
                    "name": "argo.test__argo.ni4os.eu",
                    "namespace": "default",
                    "labels": {
                        "generic_http_ar_argoui_ni4os":
                            "generic.http.ar-argoui-ni4os",
                        "hostname": "argo.ni4os.eu",
                        "info_url": "https://argo.ni4os.eu",
                        "service": "argo.test",
                        "site": "GRNET",
                        "ngi": "EGI.eu",
                        "tenants": "TENANT1"
                    }
                }
            },
            {
                "entity_class": "proxy",
                "metadata": {
                    "name": "argo.webui__argo-devel.ni4os.eu",
                    "namespace": "default",
                    "labels": {
                        "generic_http_ar_argoui_ni4os":
                            "generic.http.ar-argoui-ni4os",
                        "generic_tcp_connect": "generic.tcp.connect",
                        "hostname": "argo-devel.ni4os.eu",
                        "info_url": "http://argo-devel.ni4os.eu",
                        "service": "argo.webui",
                        "site": "GRNET",
                        "ngi": "EGI.eu",
                        "tenants": "TENANT1"
                    }
                }
            },
            {
                "entity_class": "proxy",
                "metadata": {
                    "name": "argo.webui__argo.ni4os.eu",
                    "namespace": "default",
                    "labels": {
                        "generic_http_ar_argoui_ni4os":
                            "generic.http.ar-argoui-ni4os",
                        "generic_tcp_connect": "generic.tcp.connect",
                        "hostname": "argo.ni4os.eu",
                        "info_url": "https://argo.ni4os.eu",
                        "service": "argo.webui",
                        "site": "GRNET",
                        "ngi": "EGI.eu",
                        "tenants": "TENANT1"
                    }
                }
            }
        ]
        self.entities2 = [
            {
                "entity_class": "proxy",
                "metadata": {
                    "name": "argo.mon__argo-mon-devel.egi.eu",
                    "namespace": "default",
                    "labels": {
                        "generic_certificate_validity":
                            "generic.certificate.validity",
                        "hostname": "argo-mon-devel.egi.eu",
                        "service": "argo.mon",
                        "site": "SRCE",
                        "ngi": "EGI.eu",
                        "tenants": "TENANT2"
                    }
                }
            },
            {
                "entity_class": "proxy",
                "metadata": {
                    "name": "argo.mon__argo-mon-devel.ni4os.eu",
                    "namespace": "default",
                    "labels": {
                        "generic_certificate_validity":
                            "generic.certificate.validity",
                        "hostname": "argo-mon-devel.ni4os.eu",
                        "service": "argo.mon",
                        "site": "SRCE",
                        "ngi": "EGI.eu",
                        "tenants": "TENANT2"
                    }
                }
            }
        ]
        self.metric_overrides1 = [{
            "metric": "argo.poem-tools.check",
            "hostname": "agent1",
            "parameter": "--age",
            "value": "3"
        }]
        self.metric_overrides2 = [{
            "metric": "argo.poem-tools.check",
            "hostname": "agent1",
            "parameter": "--age",
            "value": "3"
        }, {
            "metric": "generic.certificate.validity-robot",
            "hostname": "agent1",
            "parameter": "-f",
            "value": "/some/custom/path/to/robotcert.pem"
        }]
        self.attribute_overrides1 = [{
            "hostname": "agent1",
            "attribute": "ROBOT_CERT",
            "label": "robot_cert",
            "value": "/etc/sensu/certs/robotcert.pem",
            "metrics": ["generic.certificate.validity-robot"]
        }]
        self.attribute_overrides2 = [{
            "hostname": "agent1",
            "attribute": "ROBOT_CERT",
            "label": "robot_cert",
            "value": "/etc/sensu/certs/robotcert.pem",
            "metrics": ["srce.gridproxy.get"]
        }, {
            "hostname": "agent1",
            "attribute": "ROBOT_KEY",
            "label": "robot_key",
            "value": "/etc/sensu/certs/robotkey.pem",
            "metrics": ["srce.gridproxy.get"]
        }]

    def test_merge_checks(self):
        merger = ConfigurationMerger(
            checks={
                "TENANT1": self.checks1,
                "TENANT2": self.checks2
            },
            entities={
                "TENANT1": self.entities1,
                "TENANT2": self.entities2
            },
            internal_services={
                "TENANT1": "service1,service2,service3",
                "TENANT2": "service2,service3,service4"
            }
        )
        checks = merger.merge_checks()
        self.assertEqual(
            sorted(checks, key=lambda c: c["metadata"]["name"]), [
                {
                    "command": "/usr/libexec/argo/probes/argo_tools/"
                               "check_log -t 120 --file /var/log/"
                               "argo-poem-tools/argo-poem-tools.log "
                               "--age 2 --app argo-poem-packages",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "reduce_alerts",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "interval": 7200,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "argo.poem-tools.check",
                        "namespace": "test",
                        "annotations": {
                            "attempts": "4"
                        },
                        "labels": {
                            "tenants": "TENANT1,TENANT2"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_ssl_cert "
                               "-H {{ .labels.hostname }} -t 60 -w 14 -c 0 "
                               "-N --altnames --rootcert-dir "
                               "/etc/grid-security/certificates "
                               "--rootcert-file /etc/pki/tls/certs/"
                               "ca-bundle.crt "
                               "-C /etc/sensu/certs/hostcert.pem "
                               "-K /etc/sensu/certs/hostkey.pem",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_certificate_validity == "
                            "'generic.certificate.validity'"
                        ]
                    },
                    "interval": 14400,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.certificate.validity",
                        "namespace": "test",
                        "annotations": {
                            "attempts": "2"
                        },
                        "labels": {
                            "tenants": "TENANT1"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/lib64/nagios/plugins/check_http "
                               "-H {{ .labels.hostname }} -t 60 --link "
                               "--onredirect follow {{ .labels.ssl | "
                               "default " " }} {{ .labels."
                               "generic_http_connect_port | default " " }} "
                               "{{ .labels.generic_http_connect_path | "
                               "default " " }}",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_http_connect == "
                            "'generic.http.connect'"
                        ]
                    },
                    "interval": 300,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.http.connect",
                        "namespace": "test",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "TENANT1"
                        }
                    },
                    "round_robin": False
                },
                {
                    "command": "/usr/libexec/argo/probes/xml/check_xml "
                               "-t 30 -u {{ .labels.endpoint_url}} "
                               "-x /aris/partition/state_up --ok up",
                    "subscriptions": [
                        "entity:sensu-agent-mock_tenant.example.com"
                    ],
                    "handlers": [],
                    "pipelines": [
                        {
                            "name": "hard_state",
                            "type": "Pipeline",
                            "api_version": "core/v2"
                        }
                    ],
                    "proxy_requests": {
                        "entity_attributes": [
                            "entity.entity_class == 'proxy'",
                            "entity.labels.generic_xml_check == "
                            "'generic.xml.check'"
                        ]
                    },
                    "interval": 1800,
                    "timeout": 900,
                    "publish": True,
                    "metadata": {
                        "name": "generic.xml.check",
                        "namespace": "test",
                        "annotations": {
                            "attempts": "3"
                        },
                        "labels": {
                            "tenants": "TENANT2"
                        }
                    },
                    "round_robin": False
                }
            ]
        )

    def test_merge_entities(self):
        merger = ConfigurationMerger(
            checks={
                "TENANT1": self.checks1,
                "TENANT2": self.checks2
            },
            entities={
                "TENANT1": self.entities1,
                "TENANT2": self.entities2
            },
            internal_services={
                "TENANT1": "service1,service2,service3",
                "TENANT2": "service2,service3,service4"
            }
        )
        entities = merger.merge_entities()
        self.assertEqual(
            sorted(entities, key=lambda e: e["metadata"]["name"]), [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.mon__argo-mon-devel.egi.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "hostname": "argo-mon-devel.egi.eu",
                            "service": "argo.mon",
                            "site": "SRCE",
                            "ngi": "EGI.eu",
                            "tenants": "TENANT2"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.mon__argo-mon-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "hostname": "argo-mon-devel.ni4os.eu",
                            "service": "argo.mon",
                            "site": "SRCE",
                            "ngi": "EGI.eu",
                            "tenants": "TENANT2"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.test__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_ar_argoui_ni4os":
                                "generic.http.ar-argoui-ni4os",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.test",
                            "site": "GRNET",
                            "ngi": "EGI.eu",
                            "tenants": "TENANT1"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_ar_argoui_ni4os":
                                "generic.http.ar-argoui-ni4os",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "hostname": "argo-devel.ni4os.eu",
                            "info_url": "http://argo-devel.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "EGI.eu",
                            "tenants": "TENANT1"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.webui__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_ar_argoui_ni4os":
                                "generic.http.ar-argoui-ni4os",
                            "generic_tcp_connect": "generic.tcp.connect",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.webui",
                            "site": "GRNET",
                            "ngi": "EGI.eu",
                            "tenants": "TENANT1"
                        }
                    }
                }
            ]
        )

    def test_merge_entities_if_duplicates(self):
        merger = ConfigurationMerger(
            checks={
                "TENANT1": self.checks1,
                "TENANT2": self.checks2
            },
            entities={
                "TENANT1": [
                    {
                        "entity_class": "proxy",
                        "metadata": {
                            "name": "argo.test__argo.ni4os.eu",
                            "namespace": "default",
                            "labels": {
                                "generic_http_ar_argoui_ni4os":
                                    "generic.http.ar-argoui-ni4os",
                                "hostname": "argo.ni4os.eu",
                                "info_url": "https://argo.ni4os.eu",
                                "service": "argo.test",
                                "site": "GRNET",
                                "ngi": "EGI.eu",
                                "tenants": "TENANT1"
                            }
                        }
                    },
                    {
                        "entity_class": "proxy",
                        "metadata": {
                            "name": "argo.mon__argo-mon-devel.ni4os.eu",
                            "namespace": "default",
                            "labels": {
                                "generic_http_connect": "generic.http.connect",
                                "hostname": "argo-mon-devel.ni4os.eu",
                                "service": "argo.mon",
                                "site": "GRNET",
                                "ngi": "EGI.eu",
                                "tenants": "TENANT1"
                            }
                        }
                    }
                ],
                "TENANT2": self.entities2
            },
            internal_services={
                "TENANT1": "service1,service2,service3",
                "TENANT2": "service2,service3,service4"
            }
        )
        entities = merger.merge_entities()
        self.assertEqual(
            sorted(entities, key=lambda e: e["metadata"]["name"]), [
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.mon__argo-mon-devel.egi.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "hostname": "argo-mon-devel.egi.eu",
                            "service": "argo.mon",
                            "site": "SRCE",
                            "ngi": "EGI.eu",
                            "tenants": "TENANT2"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.mon__argo-mon-devel.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_certificate_validity":
                                "generic.certificate.validity",
                            "generic_http_connect": "generic.http.connect",
                            "hostname": "argo-mon-devel.ni4os.eu",
                            "service": "argo.mon",
                            "site": "GRNET,SRCE",
                            "ngi": "EGI.eu",
                            "tenants": "TENANT1,TENANT2"
                        }
                    }
                },
                {
                    "entity_class": "proxy",
                    "metadata": {
                        "name": "argo.test__argo.ni4os.eu",
                        "namespace": "default",
                        "labels": {
                            "generic_http_ar_argoui_ni4os":
                                "generic.http.ar-argoui-ni4os",
                            "hostname": "argo.ni4os.eu",
                            "info_url": "https://argo.ni4os.eu",
                            "service": "argo.test",
                            "site": "GRNET",
                            "ngi": "EGI.eu",
                            "tenants": "TENANT1"
                        }
                    }
                }
            ]
        )

    def test_merge_metric_parameter_overrides(self):
        merger = ConfigurationMerger(
            checks={
                "TENANT1": self.checks1,
                "TENANT2": self.checks2
            },
            entities={
                "TENANT1": self.entities1,
                "TENANT2": self.entities2
            },
            internal_services={
                "TENANT1": "service1,service2,service3",
                "TENANT2": "service2,service3,service4"
            },
            metricoverrides4agents={
                "TENANT1": self.metric_overrides1,
                "TENANT2": self.metric_overrides2
            }
        )
        override = merger.merge_metric_parameter_overrides()
        self.assertEqual(override, self.metric_overrides2)

    def test_merge_metric_parameter_overrides_if_diff(self):
        merger = ConfigurationMerger(
            checks={
                "TENANT1": self.checks1,
                "TENANT2": self.checks2
            },
            entities={
                "TENANT1": self.entities1,
                "TENANT2": self.entities2
            },
            internal_services={
                "TENANT1": "service1,service2,service3",
                "TENANT2": "service2,service3,service4"
            },
            metricoverrides4agents={
                "TENANT1": [{
                    "metric": "argo.poem-tools.check",
                    "hostname": "agent1",
                    "parameter": "--age",
                    "value": "4"
                }],
                "TENANT2": self.metric_overrides2
            }
        )
        with self.assertLogs(LOGNAME) as log:
            override = merger.merge_metric_parameter_overrides()
        self.assertEqual(
            override, [{
                "metric": "argo.poem-tools.check",
                "hostname": "agent1",
                "parameter": "--age",
                "value": "4"
            }, {
                "metric": "generic.certificate.validity-robot",
                "hostname": "agent1",
                "parameter": "-f",
                "value": "/some/custom/path/to/robotcert.pem"
            }]
        )
        self.assertEqual(
            log.output, [
                f"WARNING:{LOGNAME}:TENANT2: Discrepancy in "
                f"agent1/argo.poem-tools.check metric parameter override"
            ]
        )

    def test_merge_metric_parameter_overrides_if_same_metric_different_param(
            self
    ):
        merger = ConfigurationMerger(
            checks={
                "TENANT1": self.checks1,
                "TENANT2": self.checks2
            },
            entities={
                "TENANT1": self.entities1,
                "TENANT2": self.entities2
            },
            internal_services={
                "TENANT1": "service1,service2,service3",
                "TENANT2": "service2,service3,service4"
            },
            metricoverrides4agents={
                "TENANT1": [{
                    "metric": "argo.poem-tools.check",
                    "hostname": "agent1",
                    "parameter": "--file",
                    "value": "/path/to/file"
                }],
                "TENANT2": self.metric_overrides2
            }
        )
        override = merger.merge_metric_parameter_overrides()
        self.assertEqual(
            override, [{
                "metric": "argo.poem-tools.check",
                "hostname": "agent1",
                "parameter": "--file",
                "value": "/path/to/file"
            }, {
                "metric": "argo.poem-tools.check",
                "hostname": "agent1",
                "parameter": "--age",
                "value": "3"
            }, {
                "metric": "generic.certificate.validity-robot",
                "hostname": "agent1",
                "parameter": "-f",
                "value": "/some/custom/path/to/robotcert.pem"
            }]
        )

    def test_merge_attribute_overrides(self):
        merger = ConfigurationMerger(
            checks={
                "TENANT1": self.checks1,
                "TENANT2": self.checks2
            },
            entities={
                "TENANT1": self.entities1,
                "TENANT2": self.entities2
            },
            internal_services={
                "TENANT1": "service1,service2,service3",
                "TENANT2": "service2,service3,service4"
            },
            attributeoverrides4agents={
                "TENANT1": self.attribute_overrides1,
                "TENANT2": self.attribute_overrides2
            }
        )
        override = merger.merge_attribute_overrides()
        self.assertEqual(
            override, [{
                "hostname": "agent1",
                "attribute": "ROBOT_CERT",
                "label": "robot_cert",
                "value": "/etc/sensu/certs/robotcert.pem",
                "metrics": [
                    "generic.certificate.validity-robot",
                    "srce.gridproxy.get"
                ]
            }, {
                "hostname": "agent1",
                "attribute": "ROBOT_KEY",
                "label": "robot_key",
                "value": "/etc/sensu/certs/robotkey.pem",
                "metrics": ["srce.gridproxy.get"]
            }]
        )

    def test_merge_attribute_overrides_if_diff(self):
        merger = ConfigurationMerger(
            checks={
                "TENANT1": self.checks1,
                "TENANT2": self.checks2
            },
            entities={
                "TENANT1": self.entities1,
                "TENANT2": self.entities2
            },
            internal_services={
                "TENANT1": "service1,service2,service3",
                "TENANT2": "service2,service3,service4"
            },
            attributeoverrides4agents={
                "TENANT1": [{
                    "hostname": "agent1",
                    "attribute": "ROBOT_CERT",
                    "label": "robot_cert",
                    "value": "/etc/sensu/certs/robot.cert",
                    "metrics": ["generic.certificate.validity-robot"]
                }],
                "TENANT2": self.attribute_overrides2
            }
        )
        with self.assertLogs(LOGNAME) as log:
            override = merger.merge_attribute_overrides()
        self.assertEqual(
            override, [{
                "hostname": "agent1",
                "attribute": "ROBOT_CERT",
                "label": "robot_cert",
                "value": "/etc/sensu/certs/robot.cert",
                "metrics": ["generic.certificate.validity-robot"]
            }, {
                "hostname": "agent1",
                "attribute": "ROBOT_KEY",
                "label": "robot_key",
                "value": "/etc/sensu/certs/robotkey.pem",
                "metrics": ["srce.gridproxy.get"]
            }]
        )
        self.assertEqual(
            log.output, [
                f"WARNING:{LOGNAME}:TENANT2: Discrepancy in "
                f"agent1/ROBOT_CERT host attribute override"
            ]
        )

    def test_merge_internal_services(self):
        merger = ConfigurationMerger(
            checks={
                "TENANT1": self.checks1,
                "TENANT2": self.checks2
            },
            entities={
                "TENANT1": self.entities1,
                "TENANT2": self.entities2
            },
            internal_services={
                "TENANT1": "service1,service2,service3",
                "TENANT2": "service2,service3,service4"
            }
        )
        internals = merger.merge_internal_services()
        self.assertEqual(internals, "service1,service2,service3,service4")
