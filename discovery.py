#!/usr/bin/env python3
"""
Cluster Discovery Module

Collects a full inventory of cluster resources for audit.
"""

import fnmatch
from datetime import datetime, timezone


class ClusterDiscovery:
    """Discovers and inventories all cluster resources."""

    def __init__(self, conn, config, target_namespace=None):
        self.conn = conn
        self.config = config
        self.target_namespace = target_namespace
        self.excluded_ns = config.get("security", {}).get("excluded_namespaces", [])

    def _is_excluded(self, namespace):
        """Check if namespace matches exclusion patterns."""
        for pattern in self.excluded_ns:
            if fnmatch.fnmatch(namespace, pattern):
                return True
        return False

    def _get_namespaces(self):
        """Get all non-excluded namespaces."""
        if self.target_namespace:
            return [self.target_namespace]

        ns_list = self.conn.core_v1.list_namespace()
        return [
            ns.metadata.name for ns in ns_list.items
            if not self._is_excluded(ns.metadata.name)
        ]

    def collect(self) -> dict:
        """Collect full cluster inventory."""
        namespaces = self._get_namespaces()

        # Collect resources across namespaces
        pods = []
        deployments = []
        services = []
        pvcs = []
        secrets = []
        configmaps = []
        service_accounts = []
        network_policies = []
        resource_quotas = []
        limit_ranges = []
        pdbs = []
        namespace_objects = []

        for ns in namespaces:
            try:
                ns_obj = self.conn.core_v1.read_namespace(ns)
                namespace_objects.append(ns_obj)
            except Exception:
                pass

            try:
                pod_list = self.conn.core_v1.list_namespaced_pod(ns)
                pods.extend(pod_list.items)
            except Exception:
                pass

            try:
                dep_list = self.conn.apps_v1.list_namespaced_deployment(ns)
                deployments.extend(dep_list.items)
            except Exception:
                pass

            try:
                svc_list = self.conn.core_v1.list_namespaced_service(ns)
                services.extend(svc_list.items)
            except Exception:
                pass

            try:
                pvc_list = self.conn.core_v1.list_namespaced_persistent_volume_claim(ns)
                pvcs.extend(pvc_list.items)
            except Exception:
                pass

            try:
                secret_list = self.conn.core_v1.list_namespaced_secret(ns)
                secrets.extend(secret_list.items)
            except Exception:
                pass

            try:
                cm_list = self.conn.core_v1.list_namespaced_config_map(ns)
                configmaps.extend(cm_list.items)
            except Exception:
                pass

            try:
                sa_list = self.conn.core_v1.list_namespaced_service_account(ns)
                service_accounts.extend(sa_list.items)
            except Exception:
                pass

            try:
                np_list = self.conn.networking_v1.list_namespaced_network_policy(ns)
                network_policies.extend(np_list.items)
            except Exception:
                pass

            try:
                rq_list = self.conn.core_v1.list_namespaced_resource_quota(ns)
                resource_quotas.extend(rq_list.items)
            except Exception:
                pass

            try:
                lr_list = self.conn.core_v1.list_namespaced_limit_range(ns)
                limit_ranges.extend(lr_list.items)
            except Exception:
                pass

            try:
                pdb_list = self.conn.policy_v1.list_namespaced_pod_disruption_budget(ns)
                pdbs.extend(pdb_list.items)
            except Exception:
                pass

        # Cluster-scoped resources
        nodes = []
        pvs = []
        storage_classes = []
        cluster_roles = []
        cluster_role_bindings = []
        routes = []
        sccs = []

        try:
            node_list = self.conn.core_v1.list_node()
            nodes = node_list.items
        except Exception:
            pass

        try:
            pv_list = self.conn.core_v1.list_persistent_volume()
            pvs = pv_list.items
        except Exception:
            pass

        try:
            sc_list = self.conn.storage_v1.list_storage_class()
            storage_classes = sc_list.items
        except Exception:
            pass

        try:
            cr_list = self.conn.rbac_v1.list_cluster_role()
            cluster_roles = cr_list.items
        except Exception:
            pass

        try:
            crb_list = self.conn.rbac_v1.list_cluster_role_binding()
            cluster_role_bindings = crb_list.items
        except Exception:
            pass

        # OpenShift-specific
        for ns in namespaces:
            routes.extend(self.conn.get_routes(namespace=ns))

        sccs = self.conn.get_security_context_constraints()

        return {
            "namespaces": namespaces,
            "namespace_objects": namespace_objects,
            "pods": pods,
            "deployments": deployments,
            "services": services,
            "pvcs": pvcs,
            "pvs": pvs,
            "secrets": secrets,
            "configmaps": configmaps,
            "service_accounts": service_accounts,
            "network_policies": network_policies,
            "resource_quotas": resource_quotas,
            "limit_ranges": limit_ranges,
            "pdbs": pdbs,
            "nodes": nodes,
            "storage_classes": storage_classes,
            "cluster_roles": cluster_roles,
            "cluster_role_bindings": cluster_role_bindings,
            "routes": routes,
            "sccs": sccs,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "counts": {
                "namespaces": len(namespaces),
                "pods": len(pods),
                "deployments": len(deployments),
                "services": len(services),
                "pvcs": len(pvcs),
                "pvs": len(pvs),
                "nodes": len(nodes),
                "routes": len(routes),
                "secrets": len(secrets),
                "network_policies": len(network_policies),
                "sccs": len(sccs),
            }
        }
