#!/usr/bin/env python3
"""Отбирает из audit.log Kubernetes подозрительные события и сохраняет их в JSON.

Использование:
    python3 filter_audit.py audit.log -o audit-extract.json
    python3 filter_audit.py audit.log --since 2026-10-31T18:16:21.2 -o audit-extract.json

Параметр --since отсекает установку кластера: kubeadm и minikube действуют от имени администратора,
поэтому их события нельзя отделить только по имени пользователя.

Значения секретов маскируются: политика RequestResponse записывает их в журнал открытым текстом.
"""
import argparse
import json
import os
import sys
from collections import Counter

READ_VERBS = {"get", "list", "watch"}
WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
EXEC_SUBRESOURCES = {"exec", "attach", "portforward"}
BINDING_RESOURCES = {"rolebindings", "clusterrolebindings"}
SYSTEM_USER_PREFIXES = ("system:node:", "system:kube-", "system:apiserver", "system:serviceaccount:kube-system:")
SYSTEM_USERS = {"system:apiserver", "system:kube-controller-manager", "system:kube-scheduler", "system:kube-proxy"}
SECRET_FIELDS = {"data", "stringData"}
HOST_POD_FIELDS = ("hostPID", "hostIPC", "hostNetwork")


def is_system_user(event):
    """Компоненты кластера постоянно обращаются к этим ресурсам и создают шум."""
    name = event.get("user", {}).get("username", "")
    # Учётную запись default используют обычные поды, а не контроллеры: её действия скрывать нельзя
    if name == "system:serviceaccount:kube-system:default":
        return False
    return name in SYSTEM_USERS or name.startswith(SYSTEM_USER_PREFIXES)


def is_impersonated(event):
    return bool(event.get("impersonatedUser"))


def is_privileged_pod(event):
    spec = (event.get("requestObject") or {}).get("spec") or {}
    if any(spec.get(field) for field in HOST_POD_FIELDS):
        return True
    containers = spec.get("containers", []) + spec.get("initContainers", []) + spec.get("ephemeralContainers", [])
    return any((c.get("securityContext") or {}).get("privileged") is True for c in containers)


def categorize(event):
    """Возвращает список категорий, под которые подходит завершённый запрос."""
    ref = event.get("objectRef") or {}
    resource = ref.get("resource")
    subresource = ref.get("subresource")
    verb = event.get("verb")
    categories = []

    if resource == "secrets" and verb in READ_VERBS and (not is_system_user(event) or is_impersonated(event)):
        categories.append("secret-access")
    if resource == "selfsubjectaccessreviews" and is_impersonated(event):
        categories.append("impersonated-permission-check")
    # Статические поды control plane создаёт сам kubelet, это штатное поведение
    if resource == "pods" and subresource is None and verb == "create" and is_privileged_pod(event) and not is_system_user(event):
        categories.append("privileged-pod")
    # Новые версии kubectl открывают exec через WebSocket, поэтому в журнале бывает и get, и create
    if resource == "pods" and subresource in EXEC_SUBRESOURCES and not is_system_user(event):
        categories.append("pod-exec")
    if resource in BINDING_RESOURCES and verb in WRITE_VERBS and not is_system_user(event):
        categories.append("rolebinding-change")
    if resource in ("pods", "serviceaccounts") and subresource is None and verb == "create" and not is_system_user(event):
        categories.append("workload-or-identity-create")
    if "audit-policy" in json.dumps(event, ensure_ascii=False) and not is_system_user(event):
        categories.append("audit-policy")
    if event.get("responseStatus", {}).get("code") == 403 and (is_impersonated(event) or not is_system_user(event)):
        categories.append("forbidden")
    return categories


def redact(node):
    """Заменяет значения секретов, рекурсивно обходя объект."""
    if isinstance(node, dict):
        is_secret = node.get("kind") == "Secret"
        result = {}
        for key, value in node.items():
            if is_secret and key in SECRET_FIELDS and isinstance(value, dict):
                result[key] = {name: "***REDACTED***" for name in value}
            elif key == "kubectl.kubernetes.io/last-applied-configuration":
                result[key] = "***REDACTED***"
            else:
                result[key] = redact(value)
        return result
    if isinstance(node, list):
        return [redact(item) for item in node]
    return node


def trim_list_response(event):
    """Ответ на list может быть огромным, поэтому от элементов остаются имена."""
    response = event.get("responseObject")
    if isinstance(response, dict) and isinstance(response.get("items"), list):
        names = [(item.get("metadata") or {}).get("name") for item in response["items"]]
        response["items"] = names
    return event


def read_events(path):
    with open(path, encoding="utf-8") as log:
        for number, line in enumerate(log, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                print(f"Пропущена повреждённая строка {number}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", help="путь к audit.log")
    parser.add_argument("--since", default="", help="не учитывать события раньше этого времени (RFC 3339, UTC)")
    parser.add_argument("-o", "--output", default="audit-extract.json", help="файл результата")
    args = parser.parse_args()

    if not os.path.isfile(args.log):
        sys.exit(f"Файл журнала не найден: {args.log}")

    total = 0
    extract = []
    stats = Counter()
    for event in read_events(args.log):
        total += 1
        if event.get("stage") != "ResponseComplete" or event.get("stageTimestamp", "") < args.since:
            continue
        categories = categorize(event)
        if categories:
            stats.update(categories)
            extract.append({"categories": categories, **trim_list_response(redact(event))})

    with open(args.output, "w", encoding="utf-8") as out:
        json.dump(extract, out, ensure_ascii=False, indent=2)
        out.write("\n")

    print(f"Событий в журнале: {total}, отобрано: {len(extract)}, файл: {args.output}")
    for category, count in sorted(stats.items()):
        print(f"  {category}: {count}")
    print()
    for event in extract:
        ref = event.get("objectRef") or {}
        target = "/".join(filter(None, (ref.get("namespace"), ref.get("resource"), ref.get("name"), ref.get("subresource"))))
        actor = event.get("user", {}).get("username")
        impersonated = (event.get("impersonatedUser") or {}).get("username")
        if impersonated:
            actor = f"{actor} as {impersonated}"
        code = event.get("responseStatus", {}).get("code")
        print(f"{event.get('stageTimestamp')} {','.join(event['categories'])} {actor} {event.get('verb')} {target} -> {code}")


if __name__ == "__main__":
    main()
