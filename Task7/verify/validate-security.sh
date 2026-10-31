#!/usr/bin/env bash
# Проверяет состояние кластера: включён ли PodSecurity, работает ли Gatekeeper,
# запущены ли безопасные поды и соблюдаются ли ограничения в работающем контейнере.
# Запуск после применения всех манифестов: bash verify/validate-security.sh
set -u

KUBE_CONTEXT="${KUBE_CONTEXT:-minikube}"
NS=audit-zone
kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }

pass=0
fail=0

check() { # название, фактическое значение, ожидаемое значение
  if [[ "$2" == "$3" ]]; then
    pass=$((pass + 1))
    echo "PASS $1"
  else
    fail=$((fail + 1))
    echo "FAIL $1: получено '$2', ожидалось '$3'"
  fi
}

echo "=== PodSecurity"
for mode in enforce audit warn; do
  check "метка $mode" "$(kc get ns "$NS" -o jsonpath="{.metadata.labels.pod-security\.kubernetes\.io/$mode}")" restricted
done

echo "=== Gatekeeper"
ready="$(kc -n gatekeeper-system get deploy gatekeeper-controller-manager -o jsonpath='{.status.readyReplicas}')"
check "контроллер запущен" "$([[ "${ready:-0}" -ge 1 ]] && echo yes)" yes
check "аудит запущен" "$(kc -n gatekeeper-system get deploy gatekeeper-audit -o jsonpath='{.status.readyReplicas}')" 1
check "webhook зарегистрирован" \
  "$(kc get validatingwebhookconfiguration gatekeeper-validating-webhook-configuration -o name)" \
  "validatingwebhookconfiguration.admissionregistration.k8s.io/gatekeeper-validating-webhook-configuration"

for template in k8sdenyprivileged k8sdenyhostpath k8srequirerunasnonroot k8srequirereadonlyrootfs; do
  check "шаблон $template создан" "$(kc get constrainttemplate "$template" -o jsonpath='{.status.created}')" true
done

while read -r kind name; do
  check "ограничение $name в режиме deny" "$(kc get "$kind" "$name" -o jsonpath='{.spec.enforcementAction}')" deny
done <<LIST
k8sdenyprivileged deny-privileged
k8sdenyhostpath deny-hostpath
k8srequirerunasnonroot require-run-as-non-root
k8srequirereadonlyrootfs require-read-only-root-fs
LIST

echo "=== Безопасные поды"
for pod in pod-secure-01 pod-secure-02 pod-secure-03; do
  kc -n "$NS" wait --for=condition=Ready "pod/$pod" --timeout=180s >/dev/null 2>&1
  check "$pod готов" "$(kc -n "$NS" get pod "$pod" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')" True
  check "$pod работает не от root" "$(kc -n "$NS" exec "$pod" -- id -u 2>/dev/null)" 101
  check "$pod: корневая ФС только для чтения" \
    "$(kc -n "$NS" exec "$pod" -- sh -c 'touch /check 2>/dev/null && echo writable || echo read-only' 2>/dev/null)" read-only
  check "$pod: nginx отвечает" \
    "$(kc -n "$NS" exec "$pod" -- sh -c 'wget -qO /dev/null http://127.0.0.1:8080 && echo up' 2>/dev/null)" up
done

echo "=== Небезопасные поды отсутствуют"
for pod in pod-privileged pod-hostpath pod-root-user; do
  check "$pod не создан" "$(kc -n "$NS" get pod "$pod" -o name 2>/dev/null)" ""
done

echo
echo "Итог: успешно $pass, ошибок $fail"
[[ "$fail" -eq 0 ]]
