#!/usr/bin/env python3
"""
Cluster Connection Module

Handles authentication and API access to the OpenShift cluster
via kubeconfig or service account token.
"""

from kubernetes import client, config
from kubernetes.client.rest import ApiException


class ClusterConnection:
    """Manages connection to an OpenShift/Kubernetes cluster."""

    def __init__(self, context=None, kubeconfig=None):
        self.context = context
        self.kubeconfig = kubeconfig
        self.core_v1 = None
        self.apps_v1 = None
        self.networking_v1 = None
        self.rbac_v1 = None
        self.storage_v1 = None
        self.custom_api = None
        self.policy_v1 = None
        self._api_client = None

    def connect(self) -> bool:
        """Connect to cluster using kubeconfig or in-cluster config."""
        try:
            if self.kubeconfig:
                config.load_kube_config(
                    config_file=self.kubeconfig,
                    context=self.context
                )
            else:
                try:
                    config.load_kube_config(context=self.context)
                except config.ConfigException:
                    config.load_incluster_config()

            self._api_client = client.ApiClient()
            self.core_v1 = client.CoreV1Api(self._api_client)
            self.apps_v1 = client.AppsV1Api(self._api_client)
            self.networking_v1 = client.NetworkingV1Api(self._api_client)
            self.rbac_v1 = client.RbacAuthorizationV1Api(self._api_client)
            self.storage_v1 = client.StorageV1Api(self._api_client)
            self.custom_api = client.CustomObjectsApi(self._api_client)
            self.policy_v1 = client.PolicyV1Api(self._api_client)

            # Test connection
            self.core_v1.list_namespace(limit=1)
            return True

        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def get_cluster_info(self) -> dict:
        """Get basic cluster info."""
        info = {"server": "unknown", "version": "unknown", "user": "unknown"}

        try:
            version = client.VersionApi(self._api_client).get_code()
            info["version"] = f"{version.major}.{version.minor}"
        except Exception:
            pass

        try:
            _, active_context = config.list_kube_config_contexts()
            info["server"] = active_context.get("cluster", {}).get("server", "unknown")
            info["user"] = active_context.get("user", {}).get("name", "unknown")
            info["context"] = active_context.get("name", "unknown")
        except Exception:
            pass

        # Detect OpenShift vs vanilla k8s
        info["is_openshift"] = self._detect_openshift()

        return info

    def _detect_openshift(self) -> bool:
        """Check if cluster is OpenShift by looking for route.openshift.io API."""
        try:
            self.custom_api.list_cluster_custom_object(
                group="route.openshift.io",
                version="v1",
                plural="routes",
                limit=1
            )
            return True
        except ApiException:
            return False
        except Exception:
            return False

    def get_routes(self, namespace=None):
        """Get OpenShift routes (returns empty list on vanilla k8s)."""
        try:
            if namespace:
                result = self.custom_api.list_namespaced_custom_object(
                    group="route.openshift.io",
                    version="v1",
                    namespace=namespace,
                    plural="routes"
                )
            else:
                result = self.custom_api.list_cluster_custom_object(
                    group="route.openshift.io",
                    version="v1",
                    plural="routes"
                )
            return result.get("items", [])
        except Exception:
            return []

    def get_security_context_constraints(self):
        """Get OpenShift SCCs."""
        try:
            result = self.custom_api.list_cluster_custom_object(
                group="security.openshift.io",
                version="v1",
                plural="securitycontextconstraints"
            )
            return result.get("items", [])
        except Exception:
            return []
