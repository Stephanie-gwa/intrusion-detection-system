import pytest

from nids.live_capture import (
    ConfirmationRequiredError,
    LiveCaptureConfig,
    LiveCaptureUnavailable,
    capture_live,
)


def test_capture_live_requires_confirmation():
    config = LiveCaptureConfig(interface="eth0", duration_seconds=5)
    with pytest.raises(ConfirmationRequiredError):
        capture_live(config, confirm=False)


def test_capture_live_without_scapy_reports_cleanly_even_when_confirmed():
    """Whether or not scapy happens to be installed in the environment
    running this test, capture_live must never crash with an ImportError
    traceback — it should raise our own informative exception type."""
    config = LiveCaptureConfig(interface="definitely-not-a-real-interface-xyz", duration_seconds=1)
    try:
        capture_live(config, confirm=True)
    except LiveCaptureUnavailable:
        pass  # expected: either scapy is missing, or the interface doesn't exist
    except Exception as exc:  # pragma: no cover - defensive
        pytest.fail(f"capture_live raised an unexpected exception type: {exc!r}")


def test_config_requires_a_stop_condition():
    with pytest.raises(ValueError):
        LiveCaptureConfig(interface="eth0", duration_seconds=None, packet_count=None)


def test_config_accepts_packet_count_without_duration():
    config = LiveCaptureConfig(interface="eth0", duration_seconds=None, packet_count=100)
    assert config.packet_count == 100
