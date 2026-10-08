r"""
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

RUNTIME_FOLDER = os.environ.get("CAVE_OT_RUNTIME_DIR", os.path.join(REPO_ROOT,"docker","shared"))
ENGINE_FOLDER = os.environ.get("CAVE_OT_ENGINE_DIR", REPO_ROOT if os.name!="nt" else RUNTIME_FOLDER)
DB_CONFIG = {"host":os.environ.get("CAVE_OT_DB_HOST","localhost"),"port":int(os.environ.get("CAVE_OT_DB_PORT","5432")),"dbname":os.environ.get("CAVE_OT_DB_NAME","cave_ot"),"user":os.environ.get("CAVE_OT_DB_USER","postgres"),"password":os.environ.get("CAVE_OT_DB_PASSWORD",""),"connect_timeout":5}
DB_SCHEMA = os.environ.get('CAVE_OT_DB_SCHEMA')
if DB_SCHEMA:
    import re
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}',DB_SCHEMA):raise ValueError('Invalid database schema')
    DB_CONFIG['options']='-c search_path='+DB_SCHEMA
