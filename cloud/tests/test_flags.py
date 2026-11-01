import pytest

from cloud import flags


def test_default_is_off():
    assert flags.is_enabled({}) is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", " yes ", "On"])
def test_affirmative_values_enable(value):
    assert flags.is_enabled({flags.ENV_VAR: value}) is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "enabled", "tru", "2", "null", "  "])
def test_anything_else_stays_off(value):
    assert flags.is_enabled({flags.ENV_VAR: value}) is False


def test_reads_process_environment_by_default(monkeypatch):
    monkeypatch.delenv(flags.ENV_VAR, raising=False)
    assert flags.is_enabled() is False
    monkeypatch.setenv(flags.ENV_VAR, "true")
    assert flags.is_enabled() is True
