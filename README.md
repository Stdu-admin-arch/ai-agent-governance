# Zero-Trust AI Agent Governance & Workload Attestation Artifact

This repository contains the evaluation framework, policy engine, and containerized Kubernetes manifests designed to enforce zero-trust security and policy governance for autonomous AI agents. Developed as part of a dissertation artifact, this project demonstrates real-time access control, cryptographic workload attestation, and comprehensive performance benchmarking.

---

## Architecture Overview

The system architecture implements a defense-in-depth model for autonomous agents:
1. **Open Policy Agent (OPA) Engine:** Enforces dynamic, context-aware authorization policies on tool invocation (e.g., separating standard read operations from high-privilege database or communication actions).
2. **Kubernetes Multi-Container Pods (`agent-governance-pod`):** Implements a secure sidecar pattern where the core AI agent container is isolated from direct access credentials.
3. **SPIFFE/SPIRE Workload Attestation Simulation:** Dynamically provisions cryptographic SVID tokens (`/spire/svid.crt`) to ensure workloads can securely authenticate their identity before execution.

---

## Repository Structure

```text
├── agent-pod-manifest.yaml       # Multi-container Kubernetes pod specification with SPIRE simulation
├── mock_agent.py                 # Evaluation script (handles OPA server lifecycle, functional tests, & concurrency load testing)
├── policy.rego                   # Rego-based zero-trust authorization policies
├── audit_trail_export.json       # Structured audit logs generated during evaluation runs
├── comprehensive_results.log     # Terminal execution logs containing performance metrics and KPIs
└── artifact_results.log          # Baseline functional test outputs
Prerequisites & DependenciesKali Linux / Linux Environment (or compatible WSL2 instance)Python 3.11+ with standard libraries and requestsOpen Policy Agent (OPA) CLI binaryKubernetes & Minikube (for local container orchestration and sidecar validation)Getting Started & Execution1. Run the Evaluation ScriptExecute the Python test runner to spin up the local OPA server, load the Rego policy, execute functional test suites, and run a 50-thread concurrent load test:Bashpython3 mock_agent.py | tee comprehensive_results.log
2. Deploy to Kubernetes & Verify SPIRE AttestationStart your local Kubernetes cluster, apply the pod manifest, and verify that the workload successfully acquires its SPIFFE ID:Bashminikube start --driver=docker
kubectl apply -f agent-pod-manifest.yaml

# Check pod status (should show 2/2 Running)
kubectl get pods

# View container bootstrap logs
kubectl logs agent-governance-pod -c ai-agent-container

##Evaluation Results & KPIs
Functional Test Accuracy: 100% (Exceeding the >90 dissertation target)
Base Policy Latency: ~1.8ms to 2.5ms (Well below the <100ms KPI requirement)
Concurrency Load Handling: Maintained a stable average latency of ~12ms–15ms under a 50-parallel request stress test.
Auditability: Automatically exports structured JSON audit trails (audit_trail_export.json) for downstream compliance and reporting.
