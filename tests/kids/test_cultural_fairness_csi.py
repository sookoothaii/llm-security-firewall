from kids_policy.tools.cultural_validator import compute_csi, Metrics

def test_csi_computation():
    measures = {
        "christian": Metrics(0.98,1.0,0.92,0.86,0),
        "muslim":    Metrics(0.97,1.0,0.91,0.85,0),
        "none":      Metrics(0.99,1.0,0.93,0.87,0),
    }
    csi = compute_csi(measures)
    assert 0 <= csi["CSI_E_gap"] < 0.05
    assert 0 <= csi["CSI_SPS_gap"] < 0.05
    assert 0 <= csi["CSI_Recall_gap"] < 0.05

