import pytest

from speculos.client import SpeculosClient


def test_dashboard(comm: SpeculosClient, is_speculos: bool, app_version: str, model: str):
    # Tests that the text shown in the dashboard screens are the expected ones

    if not is_speculos:
        pytest.skip("Requires speculos")

    if model in ["stax", "flex", "apex_p"]:
        pytest.skip("No dashboard test for stax, flex and apex_p")

    comm.press_and_release("right")
    comm.wait_for_text_event("App settings")

    comm.press_and_release("right")
    comm.wait_for_text_event("App info")

    comm.press_and_release("right")
    comm.wait_for_text_event("Quit app")

    comm.press_and_release("left")
    comm.press_and_release("left")
    comm.press_and_release("left")
    comm.wait_for_text_event("Bitcoin")
    comm.wait_for_text_event("is ready")
