# Task7: аудит и блокировка небезопасных подов

Небезопасные поды отклоняются двумя независимыми механизмами: PodSecurity Admission в `audit-zone` и Gatekeeper во всех пространствах имён, кроме `kube-system` и `gatekeeper-system`. Безопасные поды запускаются и работают. Решение проверено на Minikube, Kubernetes v1.35.1 и Gatekeeper v3.23.1.

## Результаты проверки

| Что проверено | Результат |
| --- | --- |
| Три небезопасных манифеста в `audit-zone` | Отклонены PodSecurity, в том числе при настоящей записи |
| Три безопасных манифеста в `audit-zone` | Приняты, поды запущены |
| Четыре правила Gatekeeper, каждое отдельным нарушением | Отклонены именно нужным ограничением, соответствующий правилам под принят |
| `verify/verify-admission.sh` | 15 успешно, 0 ошибок |
| `verify/validate-security.sh` | 29 успешно, 0 ошибок |
| Безопасные поды внутри контейнера | UID 101, запись в корневую ФС невозможна, nginx отвечает на порту 8080 |
| Аудит Gatekeeper | Под, созданный до появления ограничений, найден и показан в `status.violations` |
| Аудит API-сервера | Отказы записаны с кодом 403 и причиной от PodSecurity |
| Сбой проверки | После удаления `deny-hostpath` скрипт вернул ошибку, после восстановления снова прошёл |

Краевые случаи тоже проверены разово, в сдачу эти тесты не входят: настройка контейнера важнее настройки пода, `initContainers`, `runAsUser: 0` на уровне пода и неиспользуемый том `hostPath`.

## Как запустить

Команды выполняются из каталога `Task7` в Linux или WSL.

1. Подготовить политику аудита и запустить кластер. Файл подключается снаружи, потому что Minikube перезаписывает манифест API-сервера.

   ```bash
   mkdir -p ~/propdev-audit-task7/config
   cp audit-policy.yaml ~/propdev-audit-task7/config/

   minikube start --driver=docker --kubernetes-version=v1.35.1 --memory=4096 --cpus=2 \
     --mount --mount-string="$HOME/propdev-audit-task7/config:/etc/ssl/certs/audit" \
     --extra-config=apiserver.audit-policy-file=/etc/ssl/certs/audit/audit-policy.yaml \
     --extra-config=apiserver.audit-log-path=/var/log/audit.log
   ```

2. Создать пространство имён и убедиться, что PodSecurity работает. Все три команды должны завершиться отказом.

   ```bash
   kubectl apply -f 01-create-namespace.yaml
   kubectl apply -f insecure-manifests/01-privileged-pod.yaml
   kubectl apply -f insecure-manifests/02-hostpath-pod.yaml
   kubectl apply -f insecure-manifests/03-root-user-pod.yaml
   ```

3. Установить Gatekeeper и применить правила. Шаблоны должны быть созданы раньше ограничений.

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.23.1/deploy/gatekeeper.yaml
   kubectl -n gatekeeper-system rollout status deploy/gatekeeper-controller-manager
   kubectl -n gatekeeper-system rollout status deploy/gatekeeper-audit

   kubectl apply -f gatekeeper/constraint-templates/
   kubectl wait --for=jsonpath='{.status.created}'=true constrainttemplate --all --timeout=120s
   kubectl apply -f gatekeeper/constraints/
   ```

4. Подождать около 15 секунд, пока ограничения вступят в силу, затем развернуть безопасные поды и запустить проверки.

   ```bash
   kubectl apply -f secure-manifests/
   bash verify/verify-admission.sh
   bash verify/validate-security.sh
   ```

Скрипты используют контекст `minikube`, другой задаётся через `KUBE_CONTEXT`. При наличии ошибок они возвращают ненулевой код.

## Правила Gatekeeper

| Правило | Шаблон | Ограничение | Файл |
| --- | --- | --- | --- |
| Нельзя использовать `privileged: true` | `K8sDenyPrivileged` | `deny-privileged` | `privileged.yaml` |
| `hostPath` запрещён | `K8sDenyHostPath` | `deny-hostpath` | `hostpath.yaml` |
| Только `runAsNonRoot: true`, UID 0 запрещён | `K8sRequireRunAsNonRoot` | `require-run-as-non-root` | `runasnonroot.yaml` |
| `readOnlyRootFilesystem: true` обязательно | `K8sRequireReadOnlyRootFs` | `require-read-only-root-fs` | `runasnonroot.yaml` |

## Решения, на которые стоит обратить внимание

- **Четвёртое правило лежит в `runasnonroot.yaml`.** В заданной структуре три файла на четыре правила, поэтому этот файл содержит два шаблона и два ограничения. Правила остаются отдельными и дают разные сообщения.
- **Gatekeeper проверяется вне `audit-zone`.** В `audit-zone` PodSecurity срабатывает первым, и до Gatekeeper запрос с такими нарушениями не доходит. Поэтому `verify-admission.sh` создаёт временное пространство имён `gatekeeper-test` без PodSecurity.
- **Заменён образ в безопасных подах.** Образ `nginx` запускается от root и пишет в корневую ФС, поэтому использован `nginxinc/nginx-unprivileged:1.31-alpine`. Для временных файлов nginx подключён `emptyDir` в `/tmp`.
- **Требования `restricted` шире, чем правила Gatekeeper.** Безопасным манифестам также нужны `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]` и `seccompProfile: RuntimeDefault`.
- **Журнал аудита API-сервера находится внутри контейнера.** Minikube не даёт подключить в API-сервер папку с правом записи, поэтому `/var/log/audit.log` выгружается отдельно:

  ```bash
  ID=$(docker exec minikube docker ps -q --filter name=k8s_kube-apiserver)
  docker exec minikube docker cp "$ID:/var/log/audit.log" - | tar -xO > audit.log
  ```

## Как посмотреть аудит

Нарушения, которые Gatekeeper нашёл среди уже работающих подов. Сейчас их нет: проверочный под удалён.

```bash
kubectl get k8sdenyprivileged deny-privileged -o jsonpath='{.status.totalViolations}{"\n"}'
kubectl get k8sdenyprivileged deny-privileged -o jsonpath='{.status.violations}{"\n"}'
```

Отказы в журнале API-сервера:

```bash
jq -c 'select(.stage=="ResponseComplete" and .responseStatus.code==403 and .objectRef.resource=="pods")
  | [.stageTimestamp, .user.username, .objectRef.namespace, .objectRef.name]' audit.log
```

Значения секретов записываются только на уровне `Metadata`, поэтому в журнал не попадают.

## Известные ограничения

- **Gatekeeper не блокирует при своём отказе.** У webhook `validation.gatekeeper.sh` стоит `failurePolicy: Ignore` (настройка по умолчанию): если Gatekeeper недоступен, поды проходят без его проверки. В `audit-zone` останется PodSecurity, а в других пространствах имён защиты не будет. Для production нужно оценить `Fail` и настроить оповещение о доступности.
- **Системные пространства имён исключены.** `kube-system` и `gatekeeper-system` не проверяются: там работают компоненты, которым нужны расширенные права, например `kube-proxy`. Доступ к этим пространствам нужно ограничивать через RBAC.
- **Правила применяются только к подам.** Deployment с нарушением будет создан, но его поды отклонятся позже, и ошибку будет видно только в событиях ReplicaSet.
