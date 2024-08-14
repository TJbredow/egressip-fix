import threading
import os
import time
from datetime import datetime
from pprint import pprint
from kubernetes import client, config, watch


class NNCPApi(client.CustomObjectsApi):
    group = "nmstate.io"
    plural = "nodenetworkconfigurationpolicies"
    version = "v1"

    # K8's python client should really make a class factory for this
    # It already programatically generates this, they could create a method that returns
    # An object with methods specific to that resource.
    def get_nncp(self, nncp_name: str):
        nncp_name = nncp_name[0:63]
        return self.get_cluster_custom_object(
            group = self.group,
            version = self.version,
            plural = self.plural,
            name = nncp_name
        )

    def replace_nncp(self, nncp_name: str, body: dict):
        nncp_name = nncp_name[0:63]
        self.delete_nncp(nncp_name)
        return self.create_nncp(body)

    def create_nncp(self, body: dict):
        return self.create_cluster_custom_object(
            group = self.group,
            version = self.version,
            plural = self.plural,
            body = body
        )

    def list_nncp(self):
        return self.list_cluster_custom_object(
            group = self.group,
            version = self.version,
            plural = self.plural
        )

    def delete_nncp(self, nncp_name):
        nncp_name = nncp_name[0:63]
        return self.delete_cluster_custom_object(
            group = self.group,
            version = self.version,
            plural = self.plural,
            name = nncp_name
        )

class EgressIPFix:
    kube_env = os.getenv("KUBE_ENV", "local")
    # The z is just so it appears after the rest of them in the webGUI :)
    nncp_prefix = "z-eip-fix"
    tmp_prefix = "z-tmp"

    if kube_env == "local":
        # For easy dev
        config.load_kube_config()
    else:
        config.load_incluster_config()

    def __init__(self, ns: str, route_table: str, node_selector: dict, priority=5000):
        """
        Just a simple class to house the common elements
        Args:
        ns: The namespace to watch
        route_table: The kernel routing table to set
        priority: (Default: 5000) The priority of the rule. Lower number has higher priority,
        this is supposed to beat the 6000 that OpenShift is currently using.
        """
        self.ns = ns
        self.route_table = route_table
        self.priority = priority
        self.node_selector = node_selector
        # Check for a clean set of rules on initialization
        self.check_initial_state()

    def check_initial_state(self):
        """
        Deletes any unnessesary NNCP's that may have persisted from
        a previous version of this as part of the initialization.
        Omits adding, as generally the stream does that.
        """
        v1 = client.CoreV1Api()
        napi = NNCPApi()
        pods = v1.list_namespaced_pod(self.ns)
        pods_names = map(lambda x: x.metadata.name, pods.items)
        nncps = napi.list_nncp()
        for nncp in nncps['items']:
            #assuming the name of the pod is after the name of the namespace
            nncp_name = nncp['metadata']['name']
            if self.ns in nncp_name:
                nncp_pod_name = nncp_name.split(f"{self.ns}-")[-1]
                if not nncp_pod_name in pods_names:
                    self.delete_pod_nncp(nncp_pod_name)

    def nncp_tmp_template(self, resource_name: str, ip: str) -> dict:
        """Returns the temporary resource to apply"""
        resource_name = resource_name[0:63]
        return {
            "apiVersion": "nmstate.io/v1",
            "kind": "NodeNetworkConfigurationPolicy",
            "metadata": {"name": f"{resource_name}"},
            "spec": {
                "nodeSelector": self.node_selector,
                "desiredState": {
                    "route-rules": {
                        "config": [
                            {
                                "ip-from": f"{ip}/32",
                                "priority": self.priority,
                                "route-table": self.route_table,
                                "state" : "absent"
                            }
                        ]
                    }
                },
            },
        }

    def nncp_template(self, pod_name: str, ip: str) -> dict:
        """Returns the resource to apply"""
        name = f"{self.nncp_prefix}-{self.ns}-{pod_name}"
        if len(name) > 63:
            name = name[0:63]
        return {
            "apiVersion": "nmstate.io/v1",
            "kind": "NodeNetworkConfigurationPolicy",
            "metadata": {"name": name},
            "spec": {
                "nodeSelector": self.node_selector,
                "desiredState": {
                    "route-rules": {
                        "config": [
                            {
                                "ip-from": f"{ip}/32",
                                "priority": self.priority,
                                "route-table": self.route_table,
                            }
                        ]
                    }
                },
            },
        }

    @staticmethod
    def _delete_stale_nncp(nncp_name: str):
        """Should only be called from cleanup_stale_rules."""
        napi = NNCPApi()
        for i in range(25):
            # retry 25 times to await Successful Deployment
            time.sleep(2)
            r = napi.get_nncp(nncp_name)
            if r["status"].get("conditions"):
                reason = r["status"]["conditions"][0]["reason"]
                status = r["status"]["conditions"][0]["status"]
                if status == "True" and reason == "SuccessfullyConfigured":
                    r = napi.delete_nncp(nncp_name)
                    return

    def cleanup_stale_rules(self, ip: str):
        """
        Makes a random named resource, sets it as 'absent', then deletes it.
        This ensures the IP can be correctly reused by Kubernetes
        NMState should handle this, but doesn't currently it seems.
        """
        # We can safely assume this will be a unique resource
        napi = NNCPApi()
        ts = hex(int(datetime.now().timestamp() * 1000))
        tmpname = f"{self.tmp_prefix}-{ts}"
        body = self.nncp_tmp_template(tmpname, ip)
        r = napi.create_nncp(body)
        t = threading.Thread(target=self._delete_stale_nncp, args=(tmpname,))
        t.start()

    def delete_pod_nncp(self, pod_name: str, pod_ip = ""):
        """
        Deletes the resources, and does the same cleanup process to delete stale entries as
        the stale rules.
        """
        napi = NNCPApi()
        try:
            if not pod_ip:
                nncp = napi.get_nncp(
                    f"{self.nncp_prefix}-{self.ns}-{pod_name}",
                )
                pod_ip = nncp["spec"]["desiredState"]["route-rules"]["config"][0]["ip-from"].replace("/32", "")
            napi.delete_nncp(
                f"{self.nncp_prefix}-{self.ns}-{pod_name}",
            )
        except client.exceptions.ApiException as e:
            # Perhaps it's already deleted. We won't do cleanup.
            if e.status == 404:
                return
            else:
                raise
        self.cleanup_stale_rules(pod_ip)

    def create_update_nncp(self, pod_name: str, pod_ip: str):
        """
        Does some basic checks to ensure a rule doesn't already exist for the pod, and updates accordingly.
        Only allows for one rule per resource to avoid race conditions and conflicting ip assignments.
        Due to the fact that NMState doesn't really like to clean up after itself, we have to make some
        basic tasks before replacing fields to remove stale entries on the ip rule table.
        Args:
        pod_name: The name of the Pod (duh)
        pod_ip: The current IP of the Pod
        """
        napi = NNCPApi()
        try:
            # if it's there, update and cleanup
            nncp = napi.get_nncp(
                f"{self.nncp_prefix}-{self.ns}-{pod_name}",
            )
            #What's PEP 8?
            cur_ip = nncp["spec"]["desiredState"]["route-rules"]["config"][0]["ip-from"].replace("/32", "")
            if pod_ip == cur_ip:
                print("Already made")
                return
            cur_name = f"{self.nncp_prefix}-{self.ns}-{pod_name}"
            r = napi.replace_nncp(
                cur_name,
                self.nncp_template(pod_name, pod_ip),
            )
            self.cleanup_stale_rules(cur_ip)
        except client.exceptions.ApiException as e:
            # If the NNCP doesn't exist, this is ideal and expected.
            if e.status == 404:
                body = self.nncp_template(pod_name, pod_ip)
                r = napi.create_nncp(body)
                print(r)
                return
            else:
                # Something is wrong if it's not 404
                raise

    def watch_pods(self):
        """
        Watches for new pods in the specific namespace, then applies the appropriate
        route-rules for that pod.
        """
        while True:
            # After some time, the watcher expires, returning a 410.
            # Just refresh it after that.
            v1 = client.CoreV1Api()
            w = watch.Watch()
            try:
                for event in w.stream(v1.list_namespaced_pod, namespace=self.ns):
                    # Check for changes/additions and ensure it already has been assigned an IP
                    print(
                        "Event:",
                        event["type"],
                        event["object"].metadata.name,
                        event["object"].status.pod_ip,
                    )
                    if event["type"] in ("ADDED", "MODIFIED") and event["object"].status.pod_ip:
                        self.create_update_nncp(
                            event["object"].metadata.name, event["object"].status.pod_ip
                        )
                    elif event["type"] == "DELETED":
                        self.delete_pod_nncp(
                            event["object"].metadata.name, event["object"].status.pod_ip
                            )
            except client.exceptions.ApiException as e:
                if e.status == 410:
                    pass
                else: 
                    raise

if __name__ == "__main__":
    route_table = int(os.getenv("ROUTE_TABLE"))
    namespace = os.getenv("TARGET_NAMESPACE")
    efix = EgressIPFix(namespace, route_table, {"node-role.kubernetes.io/worker": ""})
    efix.watch_pods()
