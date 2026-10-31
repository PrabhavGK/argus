---
id: KB-ARGUS-SOP-11
team: SecOps
title: "Manual OpenSSL Heartbleed Vulnerability Patching (Modernized)"
created_at: "2026-10-31 04:08:43"
content_hash: 0653a6151eb9
storage_tier: "Local SQLite + ChromaDB (Modernized SOP)"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "AI Modernized via Ollama qwen2.5:1.5b"
disk_filepath: "/home/gkprabhav/Prabhav/genai_fin/generated_runbooks/KB-ARGUS-SOP-11_modernized.md"
---

### Procedure: Manually Compile OpenSSL 1.0.1g on Bare Metal Debian Wheezy Instances

**Severity:** Low  
**Author:** Argus SRE Knowledge Steward

**Objective:** Manually compile OpenSSL 1.0.1g on bare metal Debian wheezy instances to mitigate the OpenSSL Heartbleed vulnerability.

**Preparation:**
1. Ensure the target system is up-to-date with the latest Debian wheezy version.
2. Verify the system has the necessary permissions and access to the required directories.

**Execution:**
1. **Prepare the Environment:**
   - Boot up the bare metal Debian wheezy system.
   - Ensure the system is connected to the network and has the necessary network configurations.

2. **Download OpenSSL 1.0.1g:**
   - Use a secure and reliable source to download the OpenSSL 1.0.1g package.
   - Verify the integrity of the downloaded package using a checksum or a trusted source.

3. **Extract and Compile OpenSSL:**
   - Extract the downloaded package to a temporary directory.
   - Navigate to the extracted directory and compile OpenSSL using the following commands:
     ```bash
     ./configure
     make
     sudo make install
     ```

4. **Verify the Installation:**
   - Ensure OpenSSL is installed correctly by running:
     ```bash
     openssl version
     ```

5. **Test the OpenSSL Installation:**
   - Test the OpenSSL installation by compiling a simple OpenSSL example:
     ```bash
     openssl ecparam -list_cur
