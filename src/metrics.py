"""Primary coverage and byte counts plus explicitly dimensioned secondary ratios."""
def calculate(capture, selected_count, selected_size, evaluation):
    retention = selected_size / capture.size
    coverage = evaluation["coverage"]
    return {"original_bytes": capture.size, "selected_bytes": selected_size,
            "actual_retention_percent": 100 * retention,
            "packet_retention_percent": 100 * selected_count / len(capture.packets) if capture.packets else 0,
            "storage_reduction_percent": 100 * (1 - retention),
            "coverage": coverage, "answered": evaluation["answered"],
            "normalized_efficiency": coverage / retention,
            "questions_per_mib": evaluation["answered"] * 1048576 / selected_size}
