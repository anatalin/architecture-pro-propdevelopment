# Ролевая модель доступа к Kubernetes

В кластере семь ролей. Четыре действуют на весь кластер, три ограничены пространством имён домена. Права выдаются только группам, а пользователь получает группу через поле `O` своего сертификата.

## Роли, полномочия и группы

| Роль | Права роли | Группы пользователей | Кто входит |
| --- | --- | --- | --- |
| `propdev-cluster-admin` (привилегированная) | Все действия над всеми ресурсами кластера, включая управление RBAC. Только для аварий и изменения самой ролевой модели | `propdev-cluster-admins` | Назначенный администратор платформы, минимум людей |
| `propdev-security-auditor` (привилегированная) | Чтение всех ресурсов кластера, включая Secrets, журналы и RBAC. Изменять ничего нельзя | `propdev-security-auditors` | Специалист по ИБ |
| `propdev-cluster-operator` (настройка кластера) | Управление пространствами имён, узлами, квотами, лимитами, сетевыми политиками, Ingress, хранилищем, PriorityClass и CRD; вытеснение подов. Нет Secrets, журналов, exec и изменения RBAC | `propdev-cluster-operators` | Инженеры по эксплуатации платформы |
| `propdev-cluster-viewer` (только просмотр) | Чтение основных ресурсов кластера и узлов. Нет Secrets, журналов подов и RBAC | `propdev-cluster-viewers` | IT-аудиторы, руководители IT-команд |
| `propdev-domain-devops` (привилегированная в домене) | Полное управление приложениями, Secrets, сервисными учётными записями, сетевыми политиками и Ingress, exec и port-forward. Только в своём пространстве имён | `propdev-<домен>-devops` | DevOps-инженеры и инженеры по эксплуатации продуктовых команд |
| `propdev-domain-developer` (разработка в домене) | Управление Deployment, StatefulSet, Job, Service, ConfigMap, PVC, HPA, просмотр и удаление подов, журналы. Нет Secrets и exec. Только в своём пространстве имён | `propdev-<домен>-developers` | Разработчики продуктовых команд |
| `propdev-domain-viewer` (просмотр в домене) | Чтение приложений и журналов, без Secrets. Только в своём пространстве имён | `propdev-<домен>-viewers` | Владельцы продуктов, бизнес-аналитики, менеджеры операционных команд |

## Разграничение по оргструктуре

Для каждого домена созданы своё пространство имён и три группы.

| Домен | Пространство имён | Группы | Сервисы (C4) |
| --- | --- | --- | --- |
| Продажи | `propdev-sales` | `propdev-sales-viewers`, `propdev-sales-developers`, `propdev-sales-devops` | Витрина продаж, `client-mart-app`, `client-tour-app`, `client-crm-app`, `client-mart-estate-app` |
| ЖКУ | `propdev-housing` | `propdev-housing-viewers`, `propdev-housing-developers`, `propdev-housing-devops` | `tenant-core-app`, CRM |
| ЖКУ, «Умный дом» | `propdev-smart-home` | `propdev-smart-home-viewers`, `propdev-smart-home-developers`, `propdev-smart-home-devops` | `smart-access-service`, `integration-gateway` |
| Финансы | `propdev-finance` | `propdev-finance-viewers`, `propdev-finance-developers`, `propdev-finance-devops` | `accountant-service-1` |
| Дата | `propdev-data` | `propdev-data-viewers`, `propdev-data-developers`, `propdev-data-devops` | Хранилище, BI, отчётность |

## Пользователи

Пользователи создаются скриптом `01-create-users.sh` и показывают по одному примеру на каждый тип доступа.

| Пользователь | Группа | Что получает |
| --- | --- | --- |
| `platform-admin` | `propdev-cluster-admins` | Полный доступ |
| `security-officer` | `propdev-security-auditors` | Чтение всего, включая Secrets |
| `platform-engineer` | `propdev-cluster-operators` | Настройка кластера |
| `it-auditor` | `propdev-cluster-viewers` | Только просмотр |
| `sales-devops` | `propdev-sales-devops` | Привилегированный доступ в продажах |
| `sales-developer` | `propdev-sales-developers` | Разработка в продажах |
| `housing-developer` | `propdev-housing-developers` | Разработка в ЖКУ |
| `housing-analyst` | `propdev-housing-viewers` | Просмотр в ЖКУ |
| `smart-home-devops` | `propdev-smart-home-devops` | Привилегированный доступ в «Умном доме» |
| `finance-devops` | `propdev-finance-devops` | Привилегированный доступ в финансах |
| `data-developer` | `propdev-data-developers` | Разработка в домене данных |

## Запуск

Скрипты рассчитаны на Linux или WSL и работают с контекстом `minikube`. Другой контекст задаётся переменной `KUBE_CONTEXT`.

```bash
minikube start
bash 01-create-users.sh
bash 02-create-roles.sh
bash 03-bind-roles.sh
kubectl --kubeconfig ~/.propdev-k8s-users/it-auditor/kubeconfig get nodes
```

Сертификаты и kubeconfig пользователей сохраняются в `~/.propdev-k8s-users`, вне репозитория. Скрипты можно запускать повторно.

## Почему модель устроена именно так

- **Секреты читают только назначенные группы.** Кластерный администратор и ИБ видят все, DevOps домена только свои. Так выполняется требование о привилегированных действиях.
- **Настройка отделена от доступа к данным.** Инженер платформы настраивает кластер, но не читает Secrets и журналы, в которых могут быть ПДн (Task1), и не может выдать себе новые права.
- **ИБ только читает.** Специалист по ИБ может проверить всё, но не вносит изменений, поэтому надзор отделён от эксплуатации. Роль также закрывает находку из Task2: ИБ видит изменения в кластере сам, а не ждёт передачи от команд.
- **Домены не видят друг друга.** Разработчик продаж не имеет доступа к финансам и хранилищу. Это отвечает на проблему отсутствия ограничений доступа из кейса.
- **«Умный дом» вынесен в отдельное пространство имён.** В нём лежат ключи обмена с партнёром и команды открытия дверей (Task3), поэтому остальная команда ЖКУ доступа к ним не получает.

## Ограничения

- **Косвенное чтение секретов.** Разработчик не может прочитать Secret через API, но может создать Deployment, который его смонтирует. Полностью закрыть это RBAC не может. В production нужно добавить проверку манифестов при развёртывании (например, Kyverno или OPA Gatekeeper) и выкатку только через CI/CD. Для самых чувствительных сервисов секреты лучше хранить во внешнем менеджере.
- **Отзыв сертификатов.** Kubernetes не умеет отзывать клиентские сертификаты, поэтому срок их действия ограничен 30 днями, а группа зашита в сертификат. Чтобы срочно закрыть доступ, придётся удалить связь всей группы с ролью, и доступ потеряют все её участники. Для production нужен вход через OIDC (Keycloak и AD уже есть в компании), тогда пользователя можно будет отключить отдельно.
- **Администратор кластера Minikube.** Стандартный пользователь `minikube` из kubeconfig входит в `system:masters` и обходит RBAC. Его нельзя выдавать людям.
- **Журнал действий.** RBAC не показывает, кто и что сделал. В production нужно включить audit log API-сервера и передавать его в мониторинг ИБ.
