#!/usr/bin/env bash
# Создаёт пространства имён доменов компании и роли из таблицы roles.md.
#
# Все роли объявлены как ClusterRole. Доменные роли действуют только в своём
# пространстве имён: их ограничивает RoleBinding (см. 03-bind-roles.sh).
#
# Использование: KUBE_CONTEXT=minikube ./02-create-roles.sh
set -euo pipefail

KUBE_CONTEXT="${KUBE_CONTEXT:-minikube}"
kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }

# Пространства имён повторяют домены компании. Сервисы «Умный дом» (Task3) отделены от остальных
# сервисов ЖКУ: у них собственные секреты для обмена с партнёром и команды открытия дверей.
for domain in sales housing smart-home finance data; do
  kc apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: propdev-$domain
  labels:
    app.kubernetes.io/part-of: propdev-rbac
    propdev.ru/domain: $domain
    # Запрещает привилегированные поды, через которые можно обойти RBAC
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/warn: restricted
EOF
done

kc apply -f - <<'EOF'
# ---------- Роли уровня кластера ----------

# Просмотр ресурсов всего кластера. Secrets и журналы подов намеренно не перечислены: в них могут быть ПДн.
# Встроенная роль view не подходит, потому что не показывает узлы и другие кластерные ресурсы.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: propdev-cluster-viewer
  labels:
    app.kubernetes.io/part-of: propdev-rbac
rules:
  - apiGroups: [""]
    resources:
      - configmaps
      - endpoints
      - events
      - limitranges
      - namespaces
      - nodes
      - persistentvolumeclaims
      - persistentvolumes
      - pods
      - replicationcontrollers
      - resourcequotas
      - serviceaccounts
      - services
    verbs: [get, list, watch]
  - apiGroups: [apps]
    resources: [controllerrevisions, daemonsets, deployments, replicasets, statefulsets]
    verbs: [get, list, watch]
  - apiGroups: [autoscaling]
    resources: [horizontalpodautoscalers]
    verbs: [get, list, watch]
  - apiGroups: [batch]
    resources: [cronjobs, jobs]
    verbs: [get, list, watch]
  - apiGroups: [discovery.k8s.io]
    resources: [endpointslices]
    verbs: [get, list, watch]
  - apiGroups: [networking.k8s.io]
    resources: [ingressclasses, ingresses, networkpolicies]
    verbs: [get, list, watch]
  - apiGroups: [policy]
    resources: [poddisruptionbudgets]
    verbs: [get, list, watch]
  - apiGroups: [storage.k8s.io]
    resources: [csidrivers, csinodes, storageclasses, volumeattachments]
    verbs: [get, list, watch]
  - apiGroups: [apiextensions.k8s.io]
    resources: [customresourcedefinitions]
    verbs: [get, list, watch]
---
# Настройка кластера без чтения секретов и без изменения RBAC: иначе инженер смог бы выдать себе любые права.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: propdev-cluster-operator
  labels:
    app.kubernetes.io/part-of: propdev-rbac
rules:
  - apiGroups: [""]
    resources: [limitranges, namespaces, nodes, persistentvolumes, resourcequotas]
    verbs: [get, list, watch, create, update, patch, delete]
  # Обзор нагрузки без журналов и exec, вытеснение подов при обслуживании узлов
  - apiGroups: [""]
    resources: [events, pods, services]
    verbs: [get, list, watch]
  - apiGroups: [""]
    resources: [pods/eviction]
    verbs: [create]
  - apiGroups: [apps]
    resources: [daemonsets, deployments, replicasets, statefulsets]
    verbs: [get, list, watch]
  - apiGroups: [networking.k8s.io]
    resources: [ingressclasses, ingresses, networkpolicies]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [storage.k8s.io]
    resources: [csidrivers, csinodes, storageclasses, volumeattachments]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [scheduling.k8s.io]
    resources: [priorityclasses]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [apiextensions.k8s.io]
    resources: [customresourcedefinitions]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [admissionregistration.k8s.io]
    resources: [mutatingwebhookconfigurations, validatingwebhookconfigurations]
    verbs: [get, list, watch]
---
# Привилегированная роль ИБ: чтение всех ресурсов, включая Secrets и RBAC, без права что-либо менять.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: propdev-security-auditor
  labels:
    app.kubernetes.io/part-of: propdev-rbac
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: [get, list, watch]
  - nonResourceURLs: ["/healthz", "/healthz/*", "/livez", "/livez/*", "/readyz", "/readyz/*", "/version", "/version/*", "/metrics"]
    verbs: [get]
---
# Полный доступ на случай аварии и для управления RBAC. Участников группы должно быть минимум.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: propdev-cluster-admin
  labels:
    app.kubernetes.io/part-of: propdev-rbac
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
  - nonResourceURLs: ["*"]
    verbs: ["*"]
---
# ---------- Роли домена: привязываются только к пространству имён домена ----------

# Просмотр ресурсов домена без Secrets. Для владельцев продукта, аналитиков и менеджеров.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: propdev-domain-viewer
  labels:
    app.kubernetes.io/part-of: propdev-rbac
rules:
  - apiGroups: [""]
    resources: [configmaps, endpoints, events, limitranges, persistentvolumeclaims, pods, pods/log, resourcequotas, serviceaccounts, services]
    verbs: [get, list, watch]
  - apiGroups: [apps]
    resources: [daemonsets, deployments, replicasets, statefulsets]
    verbs: [get, list, watch]
  - apiGroups: [autoscaling]
    resources: [horizontalpodautoscalers]
    verbs: [get, list, watch]
  - apiGroups: [batch]
    resources: [cronjobs, jobs]
    verbs: [get, list, watch]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses, networkpolicies]
    verbs: [get, list, watch]
---
# Развёртывание приложений домена. Нет Secrets и pods/exec: через exec можно прочитать смонтированные секреты.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: propdev-domain-developer
  labels:
    app.kubernetes.io/part-of: propdev-rbac
rules:
  - apiGroups: [""]
    resources: [endpoints, events, limitranges, resourcequotas, serviceaccounts]
    verbs: [get, list, watch]
  - apiGroups: [""]
    resources: [configmaps, persistentvolumeclaims, services]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [""]
    resources: [pods/log]
    verbs: [get, list, watch]
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list, watch, delete]
  - apiGroups: [apps]
    resources: [deployments, deployments/scale, replicasets, statefulsets, statefulsets/scale]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [apps]
    resources: [daemonsets]
    verbs: [get, list, watch]
  - apiGroups: [autoscaling]
    resources: [horizontalpodautoscalers]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [batch]
    resources: [cronjobs, jobs]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses, networkpolicies]
    verbs: [get, list, watch]
---
# Привилегированная роль домена: Secrets, exec и настройка сети только в своём пространстве имён.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: propdev-domain-devops
  labels:
    app.kubernetes.io/part-of: propdev-rbac
rules:
  - apiGroups: [""]
    resources: [configmaps, persistentvolumeclaims, pods, secrets, serviceaccounts, services]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [""]
    resources: [endpoints, events, limitranges, pods/log, resourcequotas]
    verbs: [get, list, watch]
  - apiGroups: [""]
    resources: [pods/exec, pods/portforward]
    verbs: [create, get]
  - apiGroups: [apps]
    resources: [daemonsets, deployments, deployments/scale, replicasets, statefulsets, statefulsets/scale]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [autoscaling]
    resources: [horizontalpodautoscalers]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [batch]
    resources: [cronjobs, jobs]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses, networkpolicies]
    verbs: [get, list, watch, create, update, patch, delete]
EOF

echo
echo "Роли созданы:"
kc get clusterroles -l app.kubernetes.io/part-of=propdev-rbac
