"""Metric oracles for the Jev trust report: calibration and pair agreement."""

import math

import pytest

from ctrl_ai.evaluation import metrics as M

P = [0.10, 0.40, 0.80, 0.90]
Y = [0, 1, 1, 1]
Q = [0.10, 0.80, 0.20, 0.90]
TOL = 1e-9


def test_four_case_fixture():
    assert M.log_loss(P, Y)["value"] == pytest.approx(0.3375388286260043, abs=TOL)
    assert M.brier(P, Y)["value"] == pytest.approx(0.105, abs=TOL)
    rel = M.reliability(P, Y)
    assert rel["ece"] == pytest.approx(0.25, abs=TOL)
    assert rel["ece_pp"] == pytest.approx(25.0, abs=1e-7)
    c = M.confusion(P, Y)
    assert c["cells"] == {"tp": 2, "fn": 1, "fp": 0, "tn": 1}
    assert c["recall"]["value"] == pytest.approx(2 / 3)
    assert c["fnr"]["value"] == pytest.approx(1 / 3)
    assert c["fpr"]["value"] == 0


def test_endpoints_clipped_only_for_loss_and_invalid_rejected():
    out = M.log_loss([0.0, 1.0], [1, 0])
    assert out["clipped"] == 2
    assert out["value"] == pytest.approx(-math.log(1e-6))
    assert M.reliability([0.0, 1.0], [1, 0])["bins"][4]["predicted_mean"] == 1.0
    for bad in (float("nan"), float("inf"), -0.1, 1.1, True, "0.5"):
        with pytest.raises(M.InvalidScore):
            M.log_loss([bad], [1])


def test_bin_edges():
    assert [M.bin_index(x) for x in (0.0, 0.2, 0.4, 0.6, 0.8, 1.0, 0.1999)] == [0, 1, 2, 3, 4, 4, 0]
    bins = M.reliability([0.1], [0])["bins"]
    assert bins[2]["predicted_mean"] is None and bins[2]["observed_rate"] is None


def test_null_denominators():
    c = M.confusion([0.1, 0.2], [0, 0])
    assert c["fnr"]["value"] is None and c["fnr"]["reason"] == "no_positive_labels"
    assert c["precision"]["value"] is None
    c = M.confusion([0.9], [1])
    assert c["fpr"]["value"] is None and c["fpr"]["reason"] == "no_negative_labels"


def test_labels_must_be_binary():
    with pytest.raises(M.InvalidScore):
        M.brier([0.5], [None])


def test_jsd_values():
    assert M.jsd_bits(0.3, 0.3) == pytest.approx(0, abs=TOL)
    assert M.jsd_bits(0.0, 1.0) == pytest.approx(1.0, abs=TOL)
    assert M.jsd_bits(0.1, 0.9) == pytest.approx(0.5310044064107189, abs=TOL)


def test_four_cell_fixture():
    a = [int(p >= 0.5) for p in P]
    b = [int(q >= 0.5) for q in Q]
    ag = M.agreement(a, b)
    assert ag["agreement"]["value"] == 0.5
    assert ag["cells"] == {"n00": 1, "n01": 1, "n10": 1, "n11": 1}
    assert ag["positive_agreement"]["value"] == 0.5
    nd = M.numeric_divergence(P, Q)
    assert nd["mean_jsd_bits"] == pytest.approx(0.10064578872407272, abs=TOL)
    assert nd["mean_abs_gap"] == pytest.approx(0.25, abs=TOL)
    assert nd["per_case"][1] == pytest.approx(0.12451124978365319, abs=TOL)


def test_empty_inputs_are_null_not_zero():
    assert M.log_loss([], [])["value"] is None
    assert M.agreement([], [])["agreement"]["value"] is None
    assert M.numeric_divergence([], [])["mean_jsd_bits"] is None
    assert M.wilson(0, 0)["lo"] is None


def test_weighted_means_and_effective_n():
    # Inverse-inclusion weights change the mean; effective N is reported separately.
    assert M.brier([1.0, 0.0], [1, 1], weights=[1, 3])["value"] == pytest.approx(0.75)
    assert M.effective_n([1, 3]) == pytest.approx(16 / 10)
    with pytest.raises(M.InvalidScore):
        M.brier([0.5], [1], weights=[0])
