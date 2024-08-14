# Egress IP Fix

This is was created to apply to a namespace that has an EgressIP applied to it on a separate nic than the OVN Kubernetes assigned interface. 
This shouldn't be needed anymore with newer versions of OVN-Kubernetes that derive a default route from the correct tables. However, it still may yield some benefit.

It is **highly recommended** that you use a readinessProbe on any pods that route rules will change on. Since the pod is provisioned, the IP address is assigned, and THEN this takes affect, there may be a slight delay
and it is better that the pod readiness is well defined rather than left to default settings.


## What it does

This leverages NMState operator to update ip route rules and table rules in order to appropriately assign routes to pods with egressIPs that require routing out of a different interface than the default OVN interface.
Due to IPTables/netfilter's process, the forwarding process happens before postrouting SNAT, so we have to use the pod's IP as a part of the rule.

There are some cleanup actions since NMState operator sometimes leaves stale records and doesn't clean up after itself, and there is consideration that the max size of the NNCP name is 64 chars.

## Deployment
There are two required options:

- ROUTE_TABLE
- TARGET_NAMESPACE


These are configured as environment variables within the pod. You can use the podspec.yml as reference.

In addition, you will need a role, serviceaccount, and binding in order to push NNCP configurations and listen to pods in the targeted namespace. This is how we derive the IP.
