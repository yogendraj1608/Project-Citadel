def map_severity(score, off_hours, country_changed, t_med=0.70, t_high=0.85, t_crit=0.95):
    if score >= t_crit or (score >= 0.90 and (off_hours or country_changed)):
        return "critical"
    if score >= t_high: return "high"
    if score >= t_med: return "medium"
    return "low"

def explain_row(r):
    reasons = []
    try:
        if r.get("off_hours"): reasons.append("off-hours")
        if r.get("country_changed"): reasons.append("country-changed")
        if r.get("asn_changed"): reasons.append("asn-changed")
        if float(r.get("ip_rarity", 0)) > 0.9: reasons.append("rare-ip")
        if float(r.get("distance_km", 0)) > 2000: reasons.append("long-distance")
        if float(r.get("fail_ratio_7d", 0)) > 0.5: reasons.append("high-fail-ratio")
    except Exception:
        pass
    return ", ".join(reasons) or "score-only"
