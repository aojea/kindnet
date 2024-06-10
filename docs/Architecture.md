# Architecture

kindnet = controller manager + worker agents

The configuration based on the CRD configurations.kindnet.io.
There can only one CR with name `kindnet`on the `kube-system` namespace.
If the CR exist, that configuration is used, if it does not exist the first
controller creates the CR from its flags.
The agents on the node reconcile its state to the existing CR.

### Install

The user installs a deployment with the controller manager, one of them will take
the lease and be the leader.

If the CRD does not exist during the first 30 seconds (new clusters the CRD can be created
but not available) it will be created.
If the CRD exists and is compatible (TODO check if we need this, we can recorrd breaking changes
on the APIs and refuse to start if the controller detects the incompatibility)

Check the CR with the configuration exist, if it exists deploy the daemonset.


### Upgrades

(TODO check if we need to implement more complicated logic here)

The controller handles the agents Daemonset, this is to have more control on the
agents upgrades as is a high risk operation. 