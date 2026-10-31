#!/usr/bin/env bash
# Создаёт пользователей Kubernetes: выпускает клиентские сертификаты через CSR API
# и готовит отдельный kubeconfig для каждого пользователя.
#
# Группы пользователя записываются в сертификат (поле O), поэтому права выдаются
# на группы, а не на отдельных людей (см. 03-bind-roles.sh).
#
# Использование:
#   ./01-create-users.sh
#   KUBE_CONTEXT=minikube USERS_DIR=/secure/path CERT_TTL_SECONDS=2592000 ./01-create-users.sh
#
# Ключи и kubeconfig содержат секреты, поэтому по умолчанию лежат вне репозитория.
set -euo pipefail

KUBE_CONTEXT="${KUBE_CONTEXT:-minikube}"
USERS_DIR="${USERS_DIR:-$HOME/.propdev-k8s-users}"
CERT_TTL_SECONDS="${CERT_TTL_SECONDS:-2592000}" # 30 дней: отозвать сертификат нельзя, поэтому срок короткий

# Для запуска из Git Bash: не превращать "/CN=..." в путь Windows
export MSYS_NO_PATHCONV=1

kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }

# Без доступа к кластеру прекращаем работу, пока не созданы ключи
kc get --raw /version >/dev/null

# Пользователи: "имя:группа[,группа]". Группа system:masters запрещена, она обходит RBAC.
USERS=(
  "platform-admin:propdev-cluster-admins"
  "security-officer:propdev-security-auditors"
  "platform-engineer:propdev-cluster-operators"
  "it-auditor:propdev-cluster-viewers"
  "sales-devops:propdev-sales-devops"
  "sales-developer:propdev-sales-developers"
  "housing-developer:propdev-housing-developers"
  "housing-analyst:propdev-housing-viewers"
  "smart-home-devops:propdev-smart-home-devops"
  "finance-devops:propdev-finance-devops"
  "data-developer:propdev-data-developers"
)

create_user() {
  local user="$1" groups="$2"
  local dir="$USERS_DIR/$user" subject="/CN=$user" group csr_name="propdev-user-$user"

  IFS=',' read -ra group_list <<<"$groups"
  for group in "${group_list[@]}"; do
    if [[ "$group" == "system:masters" ]]; then
      echo "Ошибка: группа system:masters запрещена ($user)" >&2
      exit 1
    fi
    subject+="/O=$group"
  done

  mkdir -p "$dir"
  chmod 700 "$dir"

  # Ключ не перевыпускается при повторном запуске, сертификат обновляется
  if [[ ! -f "$dir/$user.key" ]]; then
    openssl genrsa -out "$dir/$user.key" 2048 2>/dev/null
    chmod 600 "$dir/$user.key"
  fi
  openssl req -new -key "$dir/$user.key" -subj "$subject" -out "$dir/$user.csr"

  # Заявка неизменяема, поэтому старая удаляется
  kc delete csr "$csr_name" --ignore-not-found >/dev/null

  kc apply -f - >/dev/null <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: $csr_name
  labels:
    app.kubernetes.io/part-of: propdev-rbac
spec:
  request: $(base64 <"$dir/$user.csr" | tr -d '\r\n')
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: $CERT_TTL_SECONDS
  usages:
    - client auth
EOF

  kc certificate approve "$csr_name" >/dev/null

  local cert="" attempt
  for attempt in {1..30}; do
    cert="$(kc get csr "$csr_name" -o jsonpath='{.status.certificate}')"
    [[ -n "$cert" ]] && break
    sleep 1
  done
  if [[ -z "$cert" ]]; then
    echo "Ошибка: сертификат для $user не выпущен за 30 секунд" >&2
    exit 1
  fi

  printf '%s' "$cert" | base64 --decode >"$dir/$user.crt"
  rm -f "$dir/$user.csr"

  # Отдельный kubeconfig: адрес и CA кластера берутся из текущего контекста
  local cluster server ca_file ca_data kubeconfig="$dir/kubeconfig"
  cluster="$(kc config view --minify --raw -o jsonpath='{.clusters[0].name}')"
  server="$(kc config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')"
  ca_file="$(kc config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority}')"
  ca_data="$(kc config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"

  rm -f "$kubeconfig"
  if [[ -n "$ca_data" ]]; then
    printf '%s' "$ca_data" | base64 --decode >"$dir/ca.crt"
  else
    cp "$ca_file" "$dir/ca.crt"
  fi
  kubectl config --kubeconfig="$kubeconfig" set-cluster "$cluster" --server="$server" \
    --certificate-authority="$dir/ca.crt" --embed-certs=true >/dev/null
  kubectl config --kubeconfig="$kubeconfig" set-credentials "$user" \
    --client-certificate="$dir/$user.crt" --client-key="$dir/$user.key" --embed-certs=true >/dev/null
  kubectl config --kubeconfig="$kubeconfig" set-context "$user@$cluster" \
    --cluster="$cluster" --user="$user" >/dev/null
  kubectl config --kubeconfig="$kubeconfig" use-context "$user@$cluster" >/dev/null
  chmod 600 "$kubeconfig"

  echo "Создан: $user (группы: $groups), kubeconfig: $kubeconfig"
}

for entry in "${USERS[@]}"; do
  create_user "${entry%%:*}" "${entry#*:}"
done

echo
echo "Пользователи созданы, но прав пока нет: выполните 02-create-roles.sh и 03-bind-roles.sh."
echo "Пример проверки: kubectl --kubeconfig \"$USERS_DIR/it-auditor/kubeconfig\" get pods -A"
