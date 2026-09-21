"""Per-asset assessment: inputs, provenance, persistence and scenario previews.

Two classes of bug this suite exists to prevent.

**Stale arithmetic.** ``score_finding`` used ``setdefault`` for its mosca and
factor records, so a rescored finding displayed a new risk score beside the
previous assessment's arithmetic — an audit trail that contradicted the number
it was supposed to explain. Several tests here rescore and assert the
explanation moved with the score.

**Silent overwrites.** An operator who sets a twenty-five-year lifetime by
hand must not have it replaced by an estate-wide default the next time
somebody drags the Q-Day slider.
"""

from __future__ import annotations

import math
import os
from pathlib import Path

import pytest

from app import assessment as A
from app.assessment import AssetOverride, InvalidOverride
from app.engine import risk
from app.knowledge import purposes as P

from conftest import make_finding


@pytest.fixture
def fresh_store(tmp_path, monkeypatch):
    """A database of its own, so persistence tests cannot see each other."""
    import importlib
    monkeypatch.setenv("CD_DB", str(tmp_path / "assess.sqlite3"))
    from app import config, store
    importlib.reload(config)
    importlib.reload(store)
    store.init()
    yield store
    importlib.reload(config)
    importlib.reload(store)


# ==========================================================================
# Q-Day mathematics and terminology
# ==========================================================================

def test_likely_is_the_mode_and_the_median_is_computed_separately():
    """The defect: 'likely' was used as a median and documented as one.

    For a triangular distribution the mode is the peak and the median is the
    even-odds point, and they coincide only when the mode sits at the
    midpoint. Under the shipped defaults they differ by about 1.6 years,
    always in the direction that understates exposure.
    """
    q = risk.QDayModel(earliest=2030, likely=2034, latest=2044)
    assert q.mode_year == 2034.0

    a, b, c = 2030.0, 2044.0, 2034.0
    expected = b - math.sqrt((b - a) * (b - c) / 2)     # mode below midpoint
    assert q.median_year == pytest.approx(expected, abs=1e-9)
    assert q.median_year > q.mode_year
    assert q.to_dict()["median_year"] == pytest.approx(2035.63, abs=0.01)


def test_the_computed_median_matches_the_sampled_distribution():
    """The closed form must agree with what `sample` actually produces."""
    import random
    import statistics

    q = risk.QDayModel(earliest=2030, likely=2034, latest=2044)
    rng = random.Random(7)
    empirical = statistics.median(q.sample(rng) for _ in range(120_000))
    assert empirical == pytest.approx(q.median_year, abs=0.05)


def test_the_median_basis_is_selectable_and_changes_z():
    mode = risk.QDayModel(basis="mode").years_from(2026)
    median = risk.QDayModel(basis="median").years_from(2026)
    assert median > mode


def test_the_scenario_never_presents_itself_as_a_forecast():
    payload = risk.QDayModel().to_dict()
    assert payload["is_forecast"] is False
    assert "not a forecast" in payload["caveat"].lower()
    assert "mode" in payload["caveat"]


def test_an_incoherent_scenario_is_rejected():
    with pytest.raises(ValueError, match="earliest <= likely <= latest"):
        risk.QDayModel(earliest=2040, likely=2030, latest=2044)


def test_probabilities_are_labelled_conditional_on_the_scenario():
    result = risk.mosca(10, 2, risk.QDayModel(), now_year=2026)
    assert "conditional on the Q-Day scenario" in result.conditional_on
    assert "Not a forecast" in result.conditional_on


def test_the_assessment_year_is_recorded_and_overridable(monkeypatch):
    """It was a literal 2026 in three default arguments."""
    monkeypatch.setenv("CD_ASSESSMENT_DATE", "2031-07-01")
    assert risk.assessment_date().isoformat() == "2031-07-01"

    f = make_finding("rsa-2048")
    risk.score_finding(f, risk.QDayModel())
    assert f.extra["assessment"]["assessed_on"] == "2031-07-01"
    # Q-Day 2034 is now five years out, not eight.
    assert f.extra["mosca"]["years_to_qday"] == pytest.approx(2.5, abs=0.6)


def test_a_malformed_assessment_date_falls_back_to_today(monkeypatch):
    import datetime as dt
    monkeypatch.setenv("CD_ASSESSMENT_DATE", "not-a-date")
    assert risk.assessment_date() == dt.date.today()


# ==========================================================================
# Purpose-specific exposure models
# ==========================================================================

@pytest.mark.parametrize("purpose,model,retroactive", [
    (P.KEY_ESTABLISHMENT, risk.MODEL_HNDL, True),
    (P.ENCRYPTION, risk.MODEL_HNDL, True),
    (P.SIGNATURE, risk.MODEL_FORGERY, False),
    (P.AUTHENTICATION, risk.MODEL_FORGERY, False),
    (P.HASHING, risk.MODEL_GROVER, True),
    (P.UNKNOWN, risk.MODEL_UNRESOLVED, True),
])
def test_each_purpose_gets_its_own_exposure_model(purpose, model, retroactive):
    resolved = risk.exposure_model_for(purpose)
    assert resolved.key == model
    assert resolved.retroactive is retroactive


def test_a_signature_is_not_described_as_a_confidentiality_problem():
    """X means something different for a signature, and the tool must say so."""
    signing = risk.exposure_model_for(P.SIGNATURE)
    transport = risk.exposure_model_for(P.KEY_ESTABLISHMENT)

    assert "unforgeable" in signing.x_label
    assert "confidential" in transport.x_label
    assert signing.retroactive is False
    assert "cannot retract" in signing.assumptions
    assert "recording" in transport.assumptions


def test_a_symmetric_algorithm_uses_the_grover_model_whatever_its_purpose():
    resolved = risk.exposure_model_for(P.ENCRYPTION, "aes-128")
    assert resolved.key == risk.MODEL_GROVER
    assert "no arrival cliff" in resolved.assumptions


def test_the_exposure_model_travels_with_the_finding():
    f = make_finding("rsa-2048", purpose=P.SIGNATURE)
    risk.score_finding(f, risk.QDayModel())
    assert f.extra["exposure_model"]["key"] == risk.MODEL_FORGERY
    assert f.extra["mosca"]["model"] == risk.MODEL_FORGERY
    assert f.extra["factors"]["exposure_model"] == risk.MODEL_FORGERY


# ==========================================================================
# Stale factors
# ==========================================================================

def test_rescoring_replaces_the_arithmetic_rather_than_keeping_it():
    """The defect, inverted. `setdefault` left the explanation behind."""
    f = make_finding("rsa-2048")
    risk.score_finding(f, risk.QDayModel(), now_year=2026)
    first_score = f.risk_score
    first_z = f.extra["mosca"]["years_to_qday"]
    first_x = f.extra["factors"]["shelf_life_years"]

    f.sensitivity = "restricted"
    risk.score_finding(f, risk.QDayModel(earliest=2027, likely=2028, latest=2030),
                       now_year=2026)

    assert f.risk_score != first_score
    assert f.extra["mosca"]["years_to_qday"] != first_z
    assert f.extra["factors"]["shelf_life_years"] != first_x
    assert f.extra["factors"]["shelf_life_years"] == 25.0


def test_every_rescore_is_computed_from_the_inputs_given_now():
    f = make_finding("rsa-2048")
    scores = []
    for likely in (2030, 2035, 2040, 2030):
        risk.score_finding(f, risk.QDayModel(earliest=2029, likely=likely,
                                             latest=2045), now_year=2026)
        scores.append((f.risk_score, f.extra["mosca"]["years_to_qday"]))
    # Returning to the first scenario must return the first answer exactly.
    assert scores[0] == scores[3]
    assert scores[0] != scores[2]


def test_rescoring_preserves_detection_and_container_metadata():
    """Assessment must not trample the facts it is assessing."""
    f = make_finding("rsa-2048")
    f.extra["container"] = {"image": "app:1", "layer_index": 2, "effective": True,
                            "path": "usr/lib/x.so", "state": "effective"}
    f.extra["correlation"] = {"asset_id": "asset-1", "basis": ["component:openssl"]}
    risk.score_finding(f, risk.QDayModel())
    risk.score_finding(f, risk.QDayModel(earliest=2028, likely=2029, latest=2031))

    assert f.extra["container"]["image"] == "app:1"
    assert f.extra["correlation"]["asset_id"] == "asset-1"


# ==========================================================================
# Per-asset inputs and provenance
# ==========================================================================

def test_different_assets_can_carry_different_x_y_and_criticality():
    payments = make_finding("rsa-2048", location="svc/payments/keys.py")
    cache = make_finding("rsa-2048", location="svc/cache/keys.py")

    overrides = {
        A.asset_key(payments): AssetOverride(
            asset_key=A.asset_key(payments), shelf_life_years=25.0,
            migration_years=4.0, criticality=1.8),
        A.asset_key(cache): AssetOverride(
            asset_key=A.asset_key(cache), shelf_life_years=1.0,
            migration_years=0.5, criticality=0.3),
    }
    risk.score_all([payments, cache], risk.QDayModel(), now_year=2026,
                   overrides=overrides)

    assert payments.extra["factors"]["shelf_life_years"] == 25.0
    assert cache.extra["factors"]["shelf_life_years"] == 1.0
    assert payments.risk_score > cache.risk_score


def test_an_override_does_not_leak_to_another_asset_with_the_same_algorithm():
    """The trap: keying on the algorithm would make these one asset."""
    a = make_finding("aes-128", location="svc/a/crypto.py")
    b = make_finding("aes-128", location="svc/b/crypto.py")
    assert A.asset_key(a) != A.asset_key(b)

    overrides = {A.asset_key(a): AssetOverride(asset_key=A.asset_key(a),
                                               criticality=2.0)}
    risk.score_all([a, b], risk.QDayModel(), now_year=2026, overrides=overrides)
    assert a.extra["factors"]["business_criticality"] == 2.0
    assert b.extra["factors"]["business_criticality"] != 2.0


def test_an_override_survives_a_line_number_change():
    """A rescan renumbers lines; an override must not be lost to an edit."""
    before = make_finding("rsa-2048", location="src/keys.py", line=10)
    after = make_finding("rsa-2048", location="src/keys.py", line=204)
    assert A.asset_key(before) == A.asset_key(after)


def test_a_moved_file_is_a_different_asset():
    """Documented and deliberate: that is a different migration."""
    before = make_finding("rsa-2048", location="src/keys.py")
    after = make_finding("rsa-2048", location="lib/keys.py")
    assert A.asset_key(before) != A.asset_key(after)


def test_a_resolved_purpose_makes_it_a_different_asset():
    unresolved = make_finding("rsa-2048", purpose=P.UNKNOWN)
    resolved = make_finding("rsa-2048", purpose=P.SIGNATURE)
    assert A.asset_key(unresolved) != A.asset_key(resolved)


@pytest.mark.parametrize("field,expected", [
    ("shelf_life_years", A.DEFAULT),
    ("migration_years", A.DERIVED),
    ("criticality", A.DERIVED),
])
def test_unset_inputs_declare_where_they_came_from(field, expected):
    f = make_finding("rsa-2048")
    risk.score_finding(f, risk.QDayModel())
    assert f.extra["risk_inputs"][field]["provenance"] == expected
    assert f.extra["risk_inputs"][field]["source"]


def test_operator_inputs_are_marked_as_theirs():
    f = make_finding("rsa-2048")
    key = A.asset_key(f)
    risk.score_finding(f, risk.QDayModel(),
                       override=AssetOverride(asset_key=key, shelf_life_years=25.0))
    assert f.extra["risk_inputs"]["shelf_life_years"]["provenance"] == A.OPERATOR
    assert f.extra["assessment"]["operator_inputs"] == ["shelf_life_years"]
    assert f.extra["assessment"]["override_applied"] is True


def test_increasing_confidentiality_lifetime_increases_exposure():
    scores = []
    for years in (1.0, 10.0, 25.0):
        f = make_finding("rsa-2048")
        risk.score_finding(f, risk.QDayModel(), now_year=2026,
                           override=AssetOverride(asset_key="k",
                                                  shelf_life_years=years))
        scores.append((f.exposure_years, f.risk_score))
    assert scores[0][0] < scores[1][0] < scores[2][0]
    assert scores[0][1] < scores[2][1]


def test_increasing_migration_time_increases_exposure():
    lo = make_finding("rsa-2048")
    hi = make_finding("rsa-2048")
    risk.score_finding(lo, risk.QDayModel(), now_year=2026,
                       override=AssetOverride(asset_key="k", migration_years=0.5))
    risk.score_finding(hi, risk.QDayModel(), now_year=2026,
                       override=AssetOverride(asset_key="k", migration_years=8.0))
    assert hi.exposure_years > lo.exposure_years


def test_an_earlier_qday_scenario_never_reduces_exposure():
    late = make_finding("rsa-2048")
    early = make_finding("rsa-2048")
    risk.score_finding(late, risk.QDayModel(earliest=2040, likely=2045,
                                            latest=2055), now_year=2026)
    risk.score_finding(early, risk.QDayModel(earliest=2027, likely=2028,
                                             latest=2032), now_year=2026)
    assert early.exposure_years > late.exposure_years
    assert early.risk_score > late.risk_score


# ==========================================================================
# Validation
# ==========================================================================

@pytest.mark.parametrize("payload,fragment", [
    ({"shelf_life_years": 900}, "between 0.0 and 100.0"),
    ({"shelf_life_years": -1}, "between"),
    ({"migration_years": 400}, "between 0.0 and 30.0"),
    ({"criticality": 99}, "between"),
    ({"shelf_life_years": "soon"}, "must be a number"),
    ({"shelf_life_years": float("inf")}, "finite"),
    ({"sensitivity": "cosmic-top-secret"}, "sensitivity must be one of"),
    ({"constraints": ["teleportation"]}, "unknown constraint"),
    ({"constraints": "fips-required"}, "must be a list"),
    ({"nonsense": 1}, "unknown override field"),
])
def test_invalid_overrides_are_rejected_with_a_reason(payload, fragment):
    with pytest.raises(InvalidOverride, match=fragment):
        AssetOverride.parse("key", payload)


def test_a_valid_override_is_accepted_whole():
    o = AssetOverride.parse("key", {
        "shelf_life_years": 25, "migration_years": 4, "criticality": 1.5,
        "sensitivity": "restricted", "constraints": ["fips-required", "third-party"],
        "note": "payments signing key, HSM-backed",
    })
    assert o.shelf_life_years == 25.0
    assert o.constraints == ["fips-required", "third-party"]
    assert o.is_empty is False


def test_an_empty_override_is_recognised_as_empty():
    assert AssetOverride.parse("key", {}).is_empty is True


# ==========================================================================
# Persistence
# ==========================================================================

def test_an_override_survives_being_written_and_read_back(fresh_store):
    o = AssetOverride(asset_key="asset-1", shelf_life_years=25.0,
                      criticality=1.8, note="payments")
    fresh_store.save_override(o)
    loaded = fresh_store.get_override("asset-1")
    assert loaded.shelf_life_years == 25.0
    assert loaded.criticality == 1.8
    assert loaded.note == "payments"
    assert loaded.updated_at > 0


def test_overrides_survive_a_restart(fresh_store, tmp_path, monkeypatch):
    """A fresh process, the same file on disk."""
    import importlib
    fresh_store.save_override(
        AssetOverride(asset_key="asset-2", migration_years=6.0))

    from app import config, store
    importlib.reload(config)
    importlib.reload(store)

    assert store.get_override("asset-2").migration_years == 6.0


def test_resetting_an_override_removes_the_row(fresh_store):
    fresh_store.save_override(AssetOverride(asset_key="asset-3", criticality=1.4))
    fresh_store.delete_override("asset-3")
    assert fresh_store.get_override("asset-3") is None


def test_saving_an_empty_override_clears_rather_than_storing_nothing(fresh_store):
    fresh_store.save_override(AssetOverride(asset_key="asset-4", criticality=1.4))
    fresh_store.save_override(AssetOverride(asset_key="asset-4"))
    assert fresh_store.get_override("asset-4") is None


def test_overrides_are_not_deleted_when_a_scan_is(fresh_store):
    """They outlive the scan lifecycle by design: a person typed them."""
    from app.models import ScanResult, ScanTarget

    fresh_store.save_override(AssetOverride(asset_key="asset-5", criticality=1.9))
    result = ScanResult(target=ScanTarget(kind="repository", value="/tmp/x"))
    fresh_store.save_scan(result, {})
    fresh_store.delete_scan(result.id)

    assert fresh_store.get_override("asset-5").criticality == 1.9


# ==========================================================================
# Container deployment state
# ==========================================================================

def _with_state(effective):
    f = make_finding("rsa-2048", scanner="container/certificate")
    f.extra["container"] = {"image": "app:1", "path": "etc/ssl/k.key",
                            "layer_index": 0, "effective": effective,
                            "state": "effective" if effective else "historical",
                            "superseded_by_layer": None if effective else 1}
    return f


def test_a_historical_artefact_is_damped_but_not_dropped():
    """Not running, but still extractable from the archive. Neither zero nor full."""
    live = _with_state(True)
    gone = _with_state(False)
    risk.score_all([live, gone], risk.QDayModel(), now_year=2026)

    assert gone.risk_score > 0, "a recoverable key is not zero risk"
    assert gone.risk_score < live.risk_score
    assert gone.extra["factors"]["deployment_state_term"] < 1.0
    assert "extractable" in gone.extra["factors"]["deployment_state_note"]
    assert gone.extra["assessment"]["deployment_state"] == "historical"


def test_an_unknown_effective_state_is_treated_as_possibly_live():
    unknown = _with_state(None)
    risk.score_finding(unknown, risk.QDayModel())
    assert unknown.extra["assessment"]["deployment_state"] == "unknown"
    assert unknown.extra["factors"]["deployment_state_term"] > 0.55


def test_a_non_container_finding_is_unaffected_by_deployment_state():
    f = make_finding("rsa-2048")
    risk.score_finding(f, risk.QDayModel())
    assert f.extra["factors"]["deployment_state_term"] == 1.0
    assert f.extra["assessment"]["deployment_state"] == "not-a-container-asset"


# ==========================================================================
# Recommendation grounding
# ==========================================================================

def test_latency_and_cost_are_never_invented():
    """The most quotable fields in the report, and the least defensible."""
    from app.engine import recommend

    f = make_finding("rsa-2048", purpose=P.SIGNATURE)
    risk.score_all([f], risk.QDayModel())
    recommend.recommend_all([f])
    rec = f.recommendation

    assert rec["latency"]["status"] == "not-measured"
    assert rec["latency"]["value"] is None
    assert rec["cost"]["status"] == "not-estimated"
    assert rec["cost"]["value"] is None
    assert rec["cost"]["effort_band"] in ("low", "medium", "high")
    assert any("Latency and cost" in u for u in rec["unknowns"])


def test_a_recommendation_explains_the_exposure_in_its_own_model():
    from app.engine import recommend

    f = make_finding("rsa-2048", purpose=P.SIGNATURE)
    risk.score_all([f], risk.QDayModel())
    recommend.recommend_all([f])
    text = f.recommendation["exposure_explanation"]
    assert "Shor" in text
    assert "unforgeable" in text or "forg" in text


def test_size_impact_is_drawn_from_the_registry_not_prose():
    from app.engine import recommend
    from app.knowledge import algorithms as K

    f = make_finding("rsa-2048", purpose=P.SIGNATURE)
    risk.score_all([f], risk.QDayModel())
    recommend.recommend_all([f])
    text = " ".join(f.recommendation["compatibility"])
    assert f"{K.get('ml-dsa-65').signature_bytes:,}" in text


def test_operator_constraints_produce_warnings_not_silent_targets():
    from app.engine import recommend

    f = make_finding("rsa-2048", purpose=P.SIGNATURE)
    risk.score_all([f], risk.QDayModel())
    key = f.extra["asset_key"]
    recommend.recommend_all([f], overrides={
        key: AssetOverride(asset_key=key, constraints=["constrained-link"])})

    warnings = f.recommendation["constraint_warnings"]
    assert warnings
    assert "MTU" in warnings[0]
    assert f.recommendation["constraints_applied"] == ["constrained-link"]


def test_rsa_purpose_correctness_survives_the_new_recommender():
    """The M2 guarantee, restated against M4's enrichment."""
    from app.engine import recommend
    from app.knowledge import algorithms as K

    signing = make_finding("rsa-2048", purpose=P.SIGNATURE)
    transport = make_finding("rsa-2048", purpose=P.KEY_ESTABLISHMENT,
                             location="b.py")
    unknown = make_finding("rsa-2048", location="c.py")
    risk.score_all([signing, transport, unknown], risk.QDayModel())
    recommend.recommend_all([signing, transport, unknown])

    assert K.get(signing.recommendation["target"]).primitive == K.PRIM_SIGNATURE
    assert K.get(transport.recommendation["target"]).primitive in (
        K.PRIM_KEM, K.PRIM_KEY_AGREE)
    assert unknown.recommendation["unresolved"] is True
    assert unknown.recommendation["target"] == ""


def test_unreviewed_defaults_are_named_as_unknowns():
    from app.engine import recommend

    f = make_finding("rsa-2048", purpose=P.SIGNATURE)
    risk.score_all([f], risk.QDayModel())
    recommend.recommend_all([f])
    assert any("defaults" in u for u in f.recommendation["unknowns"])


def test_no_recommendation_proposes_an_unattended_rewrite():
    from app.engine import recommend

    f = make_finding("rsa-2048", purpose=P.SIGNATURE)
    risk.score_all([f], risk.QDayModel())
    recommend.recommend_all([f])
    steps = " ".join(f.recommendation["validation_steps"])
    assert "does not rewrite cryptographic code" in steps


# ==========================================================================
# The HTTP surface: preview must never write
# ==========================================================================

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CD_DB", str(tmp_path / "api.sqlite3"))
    monkeypatch.delenv("CD_TOKEN", raising=False)
    monkeypatch.setenv("CD_ASSESSMENT_DATE", "2026-06-15")
    import importlib
    from app import config, store
    importlib.reload(config)
    importlib.reload(store)
    from fastapi.testclient import TestClient
    from app.api import app as fastapi_app
    with TestClient(fastapi_app) as c:
        yield c
    importlib.reload(config)
    importlib.reload(store)


@pytest.fixture
def scanned(client, tmp_path):
    """A real scan the assessment endpoints can act on."""
    import time as _time
    tree = tmp_path / "estate"
    tree.mkdir()
    (tree / "keys.py").write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import padding\n"
        "hashlib.md5(b'x')\n"
        "padding.PSS(mgf=None, salt_length=32)\n")
    scan_id = client.post("/api/scan", json={"path": str(tree)}).json()["scan_id"]
    for _ in range(400):
        if client.get(f"/api/scan/{scan_id}/status").json()["state"] in (
                "done", "error", "refused"):
            break
        _time.sleep(0.02)
    payload = client.get(f"/api/scan/{scan_id}").json()
    assert payload["findings"], "the fixture scan produced nothing to assess"
    return scan_id, payload


def test_the_inputs_endpoint_describes_what_may_be_edited(client):
    body = client.get("/api/assessment/inputs").json()
    assert set(body["limits"]) == {"shelf_life_years", "migration_years",
                                   "criticality"}
    assert body["assessment_date"] == "2026-06-15"
    assert "fips-required" in body["constraints"]
    for state in ("observed", "derived", "operator", "default"):
        assert body["provenance"][state]["description"]


def test_a_preview_changes_the_score_without_writing_anything(client, scanned):
    scan_id, payload = scanned
    finding = payload["findings"][0]
    key = finding["extra"]["asset_key"]

    before = client.get(f"/api/scan/{scan_id}").json()["findings"]
    preview = client.post("/api/assessment/preview", json={
        "scan_id": scan_id, "asset_key": key,
        "override": {"shelf_life_years": 40.0, "criticality": 2.0},
    }).json()

    assert preview["state"] == "preview"
    assert preview["persisted"] is False
    assert preview["after"]["risk_score"] != preview["before"]["risk_score"]
    assert preview["saved_override"] is None

    # Nothing on disk moved.
    after = client.get(f"/api/scan/{scan_id}").json()["findings"]
    assert [f["risk_score"] for f in before] == [f["risk_score"] for f in after]
    assert client.get("/api/assessment/overrides").json()["overrides"] == {}


def test_saving_is_explicit_and_then_applies_on_rescore(client, scanned):
    scan_id, payload = scanned
    finding = payload["findings"][0]
    key = finding["extra"]["asset_key"]

    saved = client.put(f"/api/assessment/override/{key}",
                       json={"shelf_life_years": 40.0, "criticality": 2.0}).json()
    assert saved["state"] == "saved"
    assert saved["persisted"] is True

    recomputed = client.post("/api/qday", json={"scan_id": scan_id}).json()
    delta = next(d for d in recomputed["deltas"] if d["asset_key"] == key)
    assert delta["factors"]["shelf_life_years"] == 40.0
    assert delta["factors"]["business_criticality"] == 2.0
    assert delta["risk_inputs"]["shelf_life_years"]["provenance"] == "operator"
    assert recomputed["overrides_applied"] == 1


def test_a_qday_recompute_reports_whether_it_saved(client, scanned):
    scan_id, _ = scanned
    preview = client.post("/api/qday", json={"scan_id": scan_id}).json()
    assert preview["state"] == "preview" and preview["persisted"] is False

    saved = client.post("/api/qday", json={"scan_id": scan_id,
                                           "persist": True}).json()
    assert saved["state"] == "saved" and saved["persisted"] is True
    assert saved["assessment_date"] == "2026-06-15"


def test_the_estate_sensitivity_does_not_overwrite_an_operator_value(client, scanned):
    """Dragging the slider must not discard what a person typed."""
    scan_id, payload = scanned
    key = payload["findings"][0]["extra"]["asset_key"]
    client.put(f"/api/assessment/override/{key}",
               json={"sensitivity": "restricted", "shelf_life_years": 30.0})

    recomputed = client.post("/api/qday", json={
        "scan_id": scan_id, "sensitivity": "public"}).json()
    delta = next(d for d in recomputed["deltas"] if d["asset_key"] == key)

    assert delta["factors"]["shelf_life_years"] == 30.0
    assert delta["risk_inputs"]["sensitivity"]["value"] == "restricted"


def test_resetting_an_override_returns_the_asset_to_derived_inputs(client, scanned):
    scan_id, payload = scanned
    key = payload["findings"][0]["extra"]["asset_key"]
    client.put(f"/api/assessment/override/{key}", json={"criticality": 2.0})
    client.delete(f"/api/assessment/override/{key}")

    recomputed = client.post("/api/qday", json={"scan_id": scan_id}).json()
    delta = next(d for d in recomputed["deltas"] if d["asset_key"] == key)
    assert delta["risk_inputs"]["criticality"]["provenance"] == "derived"
    assert recomputed["overrides_applied"] == 0


def test_an_invalid_override_is_rejected_by_the_api(client, scanned):
    _, payload = scanned
    key = payload["findings"][0]["extra"]["asset_key"]
    response = client.put(f"/api/assessment/override/{key}",
                          json={"shelf_life_years": 900})
    assert response.status_code == 400
    assert "between" in response.json()["detail"]


def test_an_incoherent_qday_scenario_is_rejected_by_the_api(client, scanned):
    scan_id, _ = scanned
    response = client.post("/api/qday", json={
        "scan_id": scan_id, "earliest": 2044, "likely": 2030, "latest": 2032})
    assert response.status_code == 400


def test_previewing_an_unknown_asset_is_a_404(client, scanned):
    scan_id, _ = scanned
    response = client.post("/api/assessment/preview",
                           json={"scan_id": scan_id, "asset_key": "nosuchasset"})
    assert response.status_code == 404


def test_the_saved_assessment_reaches_the_report_and_the_cbom(client, scanned):
    scan_id, payload = scanned
    key = payload["findings"][0]["extra"]["asset_key"]
    client.put(f"/api/assessment/override/{key}", json={"shelf_life_years": 40.0})
    client.post("/api/qday", json={"scan_id": scan_id, "persist": True})

    doc = client.get(f"/api/scan/{scan_id}/cbom").json()
    metadata = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert metadata["assessment:date"] == "2026-06-15"
    # The document's own summary must agree with its components.
    assert metadata["assessment:overridesApplied"] == "1"
    assert metadata["assessment:qdayIsForecast"] == "false"
    assert metadata["assessment:qdayMostLikelyMode"] == "2034"
    assert float(metadata["assessment:qdayMedian"]) > 2034

    assert client.get(f"/api/scan/{scan_id}/cbom/validate").json()["valid"] is True

    assessed = [c for c in doc["components"]
                if any(p["name"] == "assessment:operatorSuppliedInputs"
                       for p in c["properties"])]
    assert assessed, "the operator's input must appear on its component"

    report_html = client.get(f"/api/scan/{scan_id}/report").text
    assert "Assumptions this assessment rests on" in report_html
    assert "not its median" in report_html
    assert "2026-06-15" in report_html


def test_detection_facts_and_operator_assumptions_stay_in_separate_namespaces(
        client, scanned):
    scan_id, payload = scanned
    key = payload["findings"][0]["extra"]["asset_key"]
    client.put(f"/api/assessment/override/{key}", json={"criticality": 1.9})
    client.post("/api/qday", json={"scan_id": scan_id, "persist": True})

    doc = client.get(f"/api/scan/{scan_id}/cbom").json()
    for component in doc["components"]:
        names = [p["name"] for p in component["properties"]]
        # Facts the tool observed.
        assert any(n.startswith("detection:") for n in names)
        # Assumptions a person or a default supplied, never mixed in with them.
        assert not any(n.startswith("detection:") and "input" in n for n in names)
