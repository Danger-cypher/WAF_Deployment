try:
    import pytest
except ImportError:
    class MockPytest:
        class mark:
            @staticmethod
            def asyncio(fn):
                return fn
        @staticmethod
        def raises(expected_exception):
            class Context:
                def __enter__(self):
                    return self
                def __exit__(self, exc_type, exc_val, exc_tb):
                    if exc_type is None:
                        raise AssertionError(f"Expected {expected_exception} but no exception was raised")
                    self.value = exc_val
                    return issubclass(exc_type, expected_exception)
            return Context()
    pytest = MockPytest()

from app.routes.ml import MLTuningModel, MLSimulateRequest, update_ml_tuning, simulate_ml_tuning, get_ml_tuning
from app.services.auth import TokenData
from fastapi import HTTPException


def test_ml_tuning_model_validates_threshold_ordering():
    # Valid model
    m = MLTuningModel(
        block_threshold=0.85,
        rate_limit_threshold=0.70,
        log_threshold=0.40,
        crs_block_threshold=4.0,
        crs_weight=0.50,
        xgb_weight=0.30,
        iso_weight=0.20,
    )
    assert m.block_threshold == 0.85

    # Out of order thresholds
    with pytest.raises(Exception):
        # pydantic ge/le constraint check or route logic
        MLTuningModel(block_threshold=0.20)  # ge=0.40


@pytest.mark.asyncio
async def test_update_ml_tuning_rejects_inverted_thresholds():
    payload = MLTuningModel(
        block_threshold=0.50,
        rate_limit_threshold=0.60,  # inverted: rate_limit > block
        log_threshold=0.40,
    )
    admin_user = TokenData(username="admin", role="admin")
    with pytest.raises(HTTPException) as exc:
        await update_ml_tuning(payload, admin_user)
    assert exc.value.status_code == 400
    assert "log_threshold < rate_limit_threshold < block_threshold" in exc.value.detail


@pytest.mark.asyncio
async def test_simulate_ml_tuning_returns_expected_decision():
    user = TokenData(username="analyst", role="analyst")
    sim_req = MLSimulateRequest(
        crs_score=2.0,
        xgb_prob=0.90,
        iso_score=-0.40,
        redis_rep=0.0,
        abuse_score=0.0,
        tuning=MLTuningModel(
            block_threshold=0.75,
            rate_limit_threshold=0.60,
            log_threshold=0.30,
            crs_weight=0.20,
            xgb_weight=0.60,
            iso_weight=0.20,
        ),
    )
    res = await simulate_ml_tuning(sim_req, user)
    assert res["decision"] == "rate_limit"
    assert res["threat_score"]["total"] == 0.72
    assert "reputation" in res["threat_score"]
    assert "reason" in res

    # Now simulate with block threshold 0.70 -> should be block
    sim_req.tuning.block_threshold = 0.70
    res_block = await simulate_ml_tuning(sim_req, user)
    assert res_block["decision"] == "block"
