import numpy as np
import feature_pipeline

def test_feature_pipeline_shape():
    """Verify that build_features constructs a vector of exactly shape (1, 30)."""
    data = {
        "crs_score": 5.0,
        "matched_vars": "ARGS:id,ARGS:name",
        "uri": "/index.php",
        "args": "id=1&name=test",
        "method": "GET",
        "body_len": 0,
        "ct": "text/html",
        "ua": "Mozilla/5.0",
        "redis_rpm": 12.0,
        "redis_rep": 0.0
    }
    features = feature_pipeline.build_features(data)
    assert isinstance(features, np.ndarray), "Result must be a numpy array"
    assert features.shape == (1, 30), f"Expected shape (1, 30), got {features.shape}"
    print("Test vector shape: PASS")

def test_feature_pipeline_missing_keys():
    """Verify that empty payloads fall back to defaults safely without raising KeyErrors."""
    data = {}
    try:
        features = feature_pipeline.build_features(data)
        assert isinstance(features, np.ndarray), "Result must be a numpy array"
        assert features.shape == (1, 30), f"Expected shape (1, 30), got {features.shape}"
        print("Test missing keys robust defaults: PASS")
    except KeyError as e:
        print(f"Test missing keys: FAIL (KeyError raised: {e})")
        raise

def test_feature_pipeline_entropy():
    """Verify character Shannon entropy calculation behaves correctly."""
    # Monotonous string should have zero entropy
    ent_low = feature_pipeline.entropy("aaaaa")
    # Dispersed string should have positive entropy
    ent_high = feature_pipeline.entropy("abcdefg")
    
    assert ent_low == 0.0, f"Expected 0.0 entropy for 'aaaaa', got {ent_low}"
    assert ent_high > 1.0, f"Expected positive entropy for diverse string, got {ent_high}"
    print("Test entropy math: PASS")

if __name__ == "__main__":
    print("Running feature pipeline unit tests...")
    test_feature_pipeline_shape()
    test_feature_pipeline_missing_keys()
    test_feature_pipeline_entropy()
    print("All unit tests passed successfully!")
