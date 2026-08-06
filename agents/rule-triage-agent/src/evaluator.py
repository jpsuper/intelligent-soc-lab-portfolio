def evaluate_condition(condition: dict, values: dict) -> bool:
    feature_name = condition.get("feature")
    expected = condition.get("equals")

    if feature_name is None:
        return False

    actual = values.get(feature_name, False)
    return actual == expected


def evaluate_when(when: dict, values: dict) -> bool:
    if not when:
        return False

    if "all" in when:
        conditions = when.get("all", [])
        return all(evaluate_condition(cond, values) for cond in conditions)

    if "any" in when:
        conditions = when.get("any", [])
        return any(evaluate_condition(cond, values) for cond in conditions)

    return False


def apply_derived_feature_rules(
    rules: list[dict], behavior_features: dict
) -> tuple[dict, list[str]]:
    derived_features: dict[str, bool] = {
        "download_and_execute_chain": False,
        "high_risk_execution_flow": False,
        "external_payload_source": False,
    }
    derived_features_extra: list[str] = []

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        when = rule.get("when", {})
        if not evaluate_when(when, behavior_features):
            continue

        produce = rule.get("produce", {})

        for key, value in produce.get("derived_features", {}).items():
            if isinstance(value, bool):
                derived_features[key] = value

        for item in produce.get("derived_features_extra", []):
            if item not in derived_features_extra:
                derived_features_extra.append(item)

    return derived_features, sorted(derived_features_extra)


def apply_assessment_rules(rules: list[dict], derived_features: dict) -> dict:
    for rule in rules:
        if not rule.get("enabled", True):
            continue

        when = rule.get("when", {})
        if not evaluate_when(when, derived_features):
            continue

        assessment = rule.get("produce", {}).get("assessment", {})
        if assessment:
            return assessment

    return {
        "verdict": "benign",
        "confidence": "low",
        "priority": "P3",
        "risk_score": 10,
    }
