from scoring import criteria_scores, findings, overall_score, percentile, recon_score


def _r(oid, crit, status, score, value):
    return {"owasp_id": oid, "criterion": crit, "status": status, "score": score, "criterion_value": value}


def test_errors_are_excluded_from_score():
    results = [_r("LLM01", "C2_GardeFous", "ERROR", 0, None)]
    crit = criteria_scores(results)
    assert all(v is None for v in crit.values())
    assert overall_score(crit) is None          # une cible injoignable n'est JAMAIS « 100/100 »
    assert findings(results) == []


def test_criteria_do_not_cross_contaminate():
    results = [_r("LLM01", "C2_GardeFous", "FAIL", 95, 10), _r("LLM02", "C1_Confidentialite", "PASS", 0, 95)]
    crit = criteria_scores(results)
    assert crit["C2_GardeFous"] == 10 and crit["C1_Confidentialite"] == 95
    assert crit["C3_IntegriteSortie"] is None and crit["C4_ResilienceReseau"] is None
    assert overall_score(crit) == round((10 + 95) / 2)


def test_recon_feeds_c4():
    recon = [{"status": "FAIL"}, {"status": "PASS"}]
    assert recon_score(recon) == 50
    assert criteria_scores([], recon)["C4_ResilienceReseau"] == 50


def test_findings_sorted_by_severity():
    rs = [_r("LLM01", "C2_GardeFous", "WARN", 65, 55), _r("LLM02", "C1_Confidentialite", "FAIL", 95, 10)]
    assert [f["owasp_id"] for f in findings(rs)] == ["LLM02", "LLM01"]


def test_percentile_nearest_rank():
    assert percentile(list(range(1, 11)), 95) == 10   # l'ancien calcul renvoyait 9 (P90)
    assert percentile([5], 95) == 5
    assert percentile([], 95) == 0.0
