"""
config.py - Centralized configuration and filesystem boundary manager.
Ensures seamless execution across:
1. Local Linux / Dev workstation (persists to ./data and ./generated_runbooks)
2. Cloud Serverless / Vercel (routes to writable /tmp/data and /tmp/generated_runbooks)
"""

import os
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IS_VERCEL = bool(os.environ.get("VERCEL") == "1" or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

if IS_VERCEL:
    DATA_DIR = "/tmp/data"
    STORAGE_VAULT_DIR = "/tmp/storage_vault"
    RUNBOOKS_DIR = "/tmp/generated_runbooks"
    SAMPLE_DOCS_DIR = os.path.join(BASE_DIR, "sample_docs")

    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(STORAGE_VAULT_DIR, exist_ok=True)
    os.makedirs(RUNBOOKS_DIR, exist_ok=True)

    # Sync bundled files to /tmp on cold start
    bundled_db = os.path.join(BASE_DIR, "data", "argus_knowledge_base.db")
    tmp_db = os.path.join(DATA_DIR, "argus_knowledge_base.db")
    if os.path.exists(bundled_db) and not os.path.exists(tmp_db):
        try:
            shutil.copy2(bundled_db, tmp_db)
        except Exception as e:
            print(f"[config] Warning copying db to tmp: {e}")

    bundled_cache = os.path.join(BASE_DIR, "data", "vector_cache.json")
    tmp_cache = os.path.join(DATA_DIR, "vector_cache.json")
    if os.path.exists(bundled_cache) and not os.path.exists(tmp_cache):
        try:
            shutil.copy2(bundled_cache, tmp_cache)
        except Exception as e:
            print(f"[config] Warning copying vector cache to tmp: {e}")

    bundled_enc = os.path.join(BASE_DIR, "data", "team_rules_enclave.enc")
    tmp_enc = os.path.join(DATA_DIR, "team_rules_enclave.enc")
    if os.path.exists(bundled_enc) and not os.path.exists(tmp_enc):
        try:
            shutil.copy2(bundled_enc, tmp_enc)
        except Exception as e:
            print(f"[config] Warning copying enclave rules to tmp: {e}")

    bundled_runbooks = os.path.join(BASE_DIR, "generated_runbooks")
    if os.path.exists(bundled_runbooks):
        for fname in os.listdir(bundled_runbooks):
            src_f = os.path.join(bundled_runbooks, fname)
            dst_f = os.path.join(RUNBOOKS_DIR, fname)
            if os.path.isfile(src_f) and not os.path.exists(dst_f):
                try:
                    shutil.copy2(src_f, dst_f)
                except Exception as e:
                    print(f"[config] Warning copying runbook {fname} to tmp: {e}")
else:
    DATA_DIR = os.path.join(BASE_DIR, "data")
    STORAGE_VAULT_DIR = os.path.join(BASE_DIR, "storage_vault")
    RUNBOOKS_DIR = os.path.join(BASE_DIR, "generated_runbooks")
    SAMPLE_DOCS_DIR = os.path.join(BASE_DIR, "sample_docs")
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(STORAGE_VAULT_DIR, exist_ok=True)
    os.makedirs(RUNBOOKS_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "argus_knowledge_base.db")
CHROMA_PERSIST_DIR = os.path.join(DATA_DIR, "chroma_db")
VECTOR_CACHE_PATH = os.path.join(DATA_DIR, "vector_cache.json")
ENCLAVE_RULEBOOK_PATH = os.path.join(DATA_DIR, "team_rules_enclave.enc")
