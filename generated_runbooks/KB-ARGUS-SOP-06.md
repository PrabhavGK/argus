---
id: KB-ARGUS-SOP-06
team: PaymentLedger
title: "PCI DSS Compliance Tokenization Key Rotation"
created_at: "2026-10-25 08:15:00"
content_hash: 9c48a92a5aa2
storage_tier: "Local SQLite + ChromaDB (all-MiniLM-L6-v2)"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "Synchronized from SQLite & ChromaDB"
---

# Runbook: PCI PAN Secret Rotation
Severity: Critical | Author: Priya Sharma

## Procedure:
1. Unseal Hardware Security Module utilizing <VAULT_ROOT_TOKEN_1>.
2. Rekey all payment transit data masking <CREDIT_CARD_PAN_1> across database <DB_CONNECTION_STRING_1>.
3. Verify zero unmasked transactions leaked to <INTERNAL_IP_2>.
