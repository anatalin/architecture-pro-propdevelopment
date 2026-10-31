#!/usr/bin/env bash
# Связывает группы пользователей с ролями из 02-create-roles.sh.
#
# Права выдаются на группы: пользователь получает их через поле O своего сертификата
# (см. 01-create-users.sh). Роли кластера привязываются через ClusterRoleBinding,
# доменные роли через RoleBinding, поэтому действуют только в своём пространстве имён.
#
# Использование: KUBE_CONTEXT=minikube ./03-bind-roles.sh
set -euo pipefail

KUBE_CONTEXT="${KUBE_CONTEXT:-minikube}"
kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }

bind_cluster_role() {
  local role="$1" group="$2"
  kc apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: $role-binding
  labels:
    app.kubernetes.io/part-of: propdev-rbac
subjects:
  - kind: Group
    name: $group
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: $role
  apiGroup: rbac.authorization.k8s.io
EOF
}

bind_domain_role() {
  local domain="$1" role="$2" group="propdev-$1-$3"
  kc apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: $group
  namespace: propdev-$domain
  labels:
    app.kubernetes.io/part-of: propdev-rbac
subjects:
  - kind: Group
    name: $group
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: $role
  apiGroup: rbac.authorization.k8s.io
EOF
}

bind_cluster_role propdev-cluster-viewer propdev-cluster-viewers
bind_cluster_role propdev-cluster-operator propdev-cluster-operators
bind_cluster_role propdev-security-auditor propdev-security-auditors
bind_cluster_role propdev-cluster-admin propdev-cluster-admins

for domain in sales housing smart-home finance data; do
  bind_domain_role "$domain" propdev-domain-viewer viewers
  bind_domain_role "$domain" propdev-domain-developer developers
  bind_domain_role "$domain" propdev-domain-devops devops
done

echo
echo "Связи созданы:"
kc get clusterrolebindings -l app.kubernetes.io/part-of=propdev-rbac
kc get rolebindings -A -l app.kubernetes.io/part-of=propdev-rbac
