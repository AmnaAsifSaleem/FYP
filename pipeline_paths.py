"""
Shared path constants for the offline CVE-processing/training pipeline
(Data_Processing/*.py, Model_Training/model_trainer.py, and the
update_cve_data.py orchestrator that calls them all in-process).

Previously each of those scripts hardcoded its own copy of
DATASET_FOLDER = r"D:\Downloads\CAVE-OT Datasets" — fine when each was run
standalone by hand, but update_cve_data.py imports and calls them directly,
so their path logic has to actually agree. One shared source instead of
five independent copies.
"""

import os

REPO_ROOT      = os.path.dirname(os.path.abspath(__file__))
DATASET_FOLDER = os.path.join(REPO_ROOT, "Datasets")
MODEL_FOLDER   = os.path.join(REPO_ROOT, "model")
