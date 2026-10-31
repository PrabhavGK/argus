# RB-SEC-89: Automated Vault Recovery & Key Rotation Runbook

## Document Metadata
- Author: David Zhang (david.zhang@corporate.internal)
- Department: Security Operations & Cryptography
- Last Verified: 2026-10-25
- Emergency Hotline: +1-555-014-9921

## 1. Vault Cluster Configuration
Primary HashiCorp Vault cluster resides on private internal subnet:
- Vault Leader: `http://10.200.4.10:8200`
- Standby Node 1: `http://10.200.4.11:8200`
- Standby Node 2: `http://10.200.4.12:8200`

## 2. Emergency Root Token Storage
In the event of unseal failure, use master unseal key shards held by `secops-leads@corporate.internal`.
Staging test root token (do not use in prod):
`s.yP89Bnbw81k092kZZqwop91A`

AWS IAM KMS Recovery Key ID:
`AKIAJXX45ABCDEXAMPLE`
Master Secret:
`q9A+wK7MDENG/bPxRfiCYEXAMPLEKEY9921`
