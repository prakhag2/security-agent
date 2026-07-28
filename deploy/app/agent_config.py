"""Shared configuration for Phase 1 and Phase 2 agents."""

import os

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", BENCH_DIR)
DJANGO_ROOT = os.environ.get("DJANGO_ROOT", os.path.join(DATA_DIR, "django"))
TESTS_DIR = os.path.join(DJANGO_ROOT, "tests")
RESULTS_DIR = os.path.join(DATA_DIR, "results")

MODEL_ID = os.environ.get("MODEL_ID", "us.anthropic.claude-opus-4-6-v1")
MODEL_REGION = os.environ.get("AWS_REGION", "us-east-1")


def create_model(cache=False):
    from strands.models import BedrockModel
    kwargs = dict(
        model_id=MODEL_ID,
        streaming=True,
        region_name=MODEL_REGION,
        max_tokens=16384,
    )
    if cache:
        from strands.models.bedrock import CacheConfig
        kwargs["cache_config"] = CacheConfig(strategy="auto")
    return BedrockModel(**kwargs)


def streaming_callback(**kwargs):
    data = kwargs.get("data", "")
    if data:
        print(data, end="", flush=True)
