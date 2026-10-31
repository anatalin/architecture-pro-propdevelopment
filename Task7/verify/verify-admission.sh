#!/usr/bin/env bash
# Проверяет, что PodSecurity и Gatekeeper отклоняют небезопасные поды и пропускают безопасные.
# Запуск: bash verify/verify-admission.sh
set -u

KUBE_CONTEXT="${KUBE_CONTEXT:-minikube}"
TEST_NS=gatekeeper-test
kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }

cd "$(dirname "$0")/.."
pass=0
fail=0

ok() { pass=$((pass + 1)); echo "PASS $1"; }
bad() {
  fail=$((fail + 1))
  echo "FAIL $1"
  if [[ -n "${2:-}" ]]; then echo "     $2"; fi
}

# Манифест читается из stdin. Отказ должен прийти от ожидаемого механизма.
expect_denied() {
  local title="$1" pattern="$2" output
  if output="$(kc apply --dry-run=server -f - 2>&1)"; then
    bad "$title: запрос принят, ожидался отказ" "$output"
  elif grep -qE "$pattern" <<<"$output"; then
    ok "$title"
  else
    bad "$title: отказ не от ожидаемого механизма ($pattern)" "$output"
  fi
}

expect_allowed() {
  local title="$1" output
  if output="$(kc apply --dry-run=server -f - 2>&1)"; then
    ok "$title"
  else
    bad "$title: запрос отклонён" "$output"
  fi
}

# Под, который соответствует всем правилам Gatekeeper. Аргументы меняют отдельные настройки.
test_pod() {
  local extra="${1:-}" non_root="${2:-true}" read_only="${3:-true}" volume="${4:-emptyDir: {\}}"
  cat <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: gatekeeper-check
  namespace: $TEST_NS
spec:
  containers:
    - name: c
      image: nginxinc/nginx-unprivileged:1.31-alpine
      securityContext:
        runAsNonRoot: $non_root
        readOnlyRootFilesystem: $read_only
        $extra
      volumeMounts:
        - {name: v, mountPath: /tmp}
  volumes:
    - name: v
      $volume
YAML
}

echo "=== 1. PodSecurity: небезопасные манифесты в audit-zone"
for manifest in insecure-manifests/*.yaml; do
  expect_denied "$manifest" 'violates PodSecurity "restricted' <"$manifest"
done

echo "=== 2. Безопасные манифесты в audit-zone"
for manifest in secure-manifests/*.yaml; do
  expect_allowed "$manifest" <"$manifest"
done

echo "=== 3. Gatekeeper: пространство имён без PodSecurity"
# В audit-zone PodSecurity срабатывает раньше, поэтому Gatekeeper проверяется отдельно
kc create namespace "$TEST_NS" --dry-run=client -o yaml | kc apply -f - >/dev/null
trap 'kc delete namespace "$TEST_NS" --ignore-not-found >/dev/null' EXIT

# Подстановка вместо конвейера: иначе счётчики изменятся в подоболочке и ошибки не будут учтены
expect_allowed "под, соответствующий всем правилам" < <(test_pod)
expect_denied "privileged: true" 'deny-privileged' < <(test_pod "privileged: true")
expect_denied "hostPath" 'deny-hostpath' < <(test_pod "" true true "hostPath: {path: /}")
expect_denied "runAsNonRoot: false" 'require-run-as-non-root' < <(test_pod "" false)
expect_denied "runAsUser: 0" 'require-run-as-non-root' < <(test_pod "runAsUser: 0")
expect_denied "readOnlyRootFilesystem: false" 'require-read-only-root-fs' < <(test_pod "" true false)

echo "=== 4. Настоящая запись (без dry-run)"
for manifest in insecure-manifests/*.yaml; do
  if kc apply -f "$manifest" >/dev/null 2>&1; then
    bad "$manifest создан"
    kc delete -f "$manifest" --ignore-not-found >/dev/null
  else
    ok "$manifest не создан"
  fi
done

echo
echo "Итог: успешно $pass, ошибок $fail"
[[ "$fail" -eq 0 ]]
