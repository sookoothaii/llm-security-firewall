import pathlib, json
from kids_policy.tools.cultural_validator import main

def test_cultural_matrix_smoke(tmp_path, monkeypatch):
    """Run validator over the full matrix. Assume repo has canonicals and SoT answers present."""
    reports = tmp_path / "reports"
    argv = [
        "--canon_root", "kids_policy/canonicals",
        "--answers", "kids_policy/answers/answers_cultural_6_8_v1_0_0.json",
        "--report_json", str(reports/"audit.json"),
        "--csi_json", str(reports/"csi.json"),
        "--compose_on_missing"  # compose for 9-12, 13-15 until SoT is complete
    ]
    rc = main(argv)
    assert rc in (0,2)  # allow failure before answers are complete; smoke ensures CLI works

