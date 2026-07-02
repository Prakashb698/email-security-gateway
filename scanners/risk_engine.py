def calculate_verdict(score, infected=False):
    if infected:
        return "malicious"

    if score >= 70:
        return "high_risk"

    if score >= 40:
        return "medium_risk"

    if score >= 20:
        return "low_risk"

    return "clean"
