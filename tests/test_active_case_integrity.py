from infra.check_active_case_integrity import validate_active_cases


def test_active_case_layout_and_canary_integrity():
    assert validate_active_cases() == []
