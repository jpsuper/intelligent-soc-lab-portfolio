def validate_rules(rules: list[dict]) -> None:
    if not isinstance(rules, list):
        raise ValueError("rules must be a list")

    seen_ids: set[str] = set()

    for i, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            raise ValueError(f"rule[{i}] must be an object")

        rule_id = rule.get("id")
        name = rule.get("name")
        enabled = rule.get("enabled")
        when = rule.get("when")
        produce = rule.get("produce")

        if not isinstance(rule_id, str) or not rule_id:
            raise ValueError(f"rule[{i}] missing valid 'id'")

        if rule_id in seen_ids:
            raise ValueError(f"duplicate rule id: {rule_id}")
        seen_ids.add(rule_id)

        if not isinstance(name, str) or not name:
            raise ValueError(f"rule[{rule_id}] missing valid 'name'")

        if enabled is not None and not isinstance(enabled, bool):
            raise ValueError(f"rule[{rule_id}] 'enabled' must be boolean")

        if not isinstance(when, dict):
            raise ValueError(f"rule[{rule_id}] missing valid 'when' object")

        has_all = "all" in when
        has_any = "any" in when
        if not (has_all or has_any):
            raise ValueError(f"rule[{rule_id}] 'when' must contain 'all' or 'any'")

        if has_all and has_any:
            raise ValueError(f"rule[{rule_id}] 'when' must not contain both 'all' and 'any'")

        conditions = when.get("all") if has_all else when.get("any")
        if not isinstance(conditions, list) or not conditions:
            raise ValueError(f"rule[{rule_id}] conditions must be a non-empty list")

        for j, cond in enumerate(conditions, start=1):
            if not isinstance(cond, dict):
                raise ValueError(f"rule[{rule_id}] condition[{j}] must be an object")

            feature = cond.get("feature")
            if not isinstance(feature, str) or not feature:
                raise ValueError(f"rule[{rule_id}] condition[{j}] missing valid 'feature'")

            if "equals" not in cond:
                raise ValueError(f"rule[{rule_id}] condition[{j}] missing 'equals'")

            if not isinstance(cond["equals"], bool):
                raise ValueError(f"rule[{rule_id}] condition[{j}] 'equals' must be boolean")

        if not isinstance(produce, dict):
            raise ValueError(f"rule[{rule_id}] missing valid 'produce' object")

        has_df = "derived_features" in produce
        has_extra = "derived_features_extra" in produce
        has_assessment = "assessment" in produce

        if not (has_df or has_extra or has_assessment):
            raise ValueError(
                f"rule[{rule_id}] 'produce' must contain "
                "'derived_features', 'derived_features_extra', or 'assessment'"
            )

        if has_df:
            df = produce["derived_features"]
            if not isinstance(df, dict) or not df:
                raise ValueError(f"rule[{rule_id}] 'derived_features' must be a non-empty object")
            for key, value in df.items():
                if not isinstance(key, str) or not key:
                    raise ValueError(f"rule[{rule_id}] derived_features contains invalid key")
                if not isinstance(value, bool):
                    raise ValueError(f"rule[{rule_id}] derived_features['{key}'] must be boolean")

        if has_extra:
            extra = produce["derived_features_extra"]
            if not isinstance(extra, list) or not extra:
                raise ValueError(
                    f"rule[{rule_id}] 'derived_features_extra' must be a non-empty list"
                )
            for item in extra:
                if not isinstance(item, str) or not item:
                    raise ValueError(f"rule[{rule_id}] derived_features_extra must contain strings")

        if has_assessment:
            assessment = produce["assessment"]
            if not isinstance(assessment, dict) or not assessment:
                raise ValueError(f"rule[{rule_id}] 'assessment' must be a non-empty object")

            required_keys = {"verdict", "confidence", "priority", "risk_score"}
            missing = required_keys - set(assessment.keys())
            if missing:
                raise ValueError(f"rule[{rule_id}] assessment missing keys: {sorted(missing)}")

            if assessment["verdict"] not in {"malicious", "suspicious", "benign"}:
                raise ValueError(f"rule[{rule_id}] assessment.verdict has invalid value")

            if assessment["confidence"] not in {"low", "medium", "high"}:
                raise ValueError(f"rule[{rule_id}] assessment.confidence has invalid value")

            if assessment["priority"] not in {"P1", "P2", "P3"}:
                raise ValueError(f"rule[{rule_id}] assessment.priority has invalid value")

            if not isinstance(assessment["risk_score"], int):
                raise ValueError(f"rule[{rule_id}] assessment.risk_score must be an integer")
