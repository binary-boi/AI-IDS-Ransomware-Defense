import json

def load_rules(path="rules/detection_rules.json"):
    with open(path, "r") as f:
        return json.load(f)

def evaluate_rule(packet_info, rule):
    field = rule["feature"]
    operator = rule["operator"]
    value = rule["value"]

    if field not in packet_info:
        return False

    try:
        if operator == "==":
            return packet_info[field] == value
        elif operator == ">":
            return packet_info[field] > value
        elif operator == "<":
            return packet_info[field] < value
        elif operator == "in":
            return packet_info[field] in value
        else:
            return False
    except Exception as e:
        print(f"Error evaluating rule {rule['id']}: {e}")
        return False

def apply_rules(packet_info, rules):
    alerts = []
    for rule in rules:
        if evaluate_rule(packet_info, rule):
            alerts.append({
                "rule_id": rule["id"],
                "description": rule["description"]
            })
    return alerts
