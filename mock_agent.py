import subprocess
import time
import requests
import json
import sys
import concurrent.futures

def start_opa():
    print("[*] Starting OPA server locally...")
    opa_process = subprocess.Popen(
        ["opa", "run", "--server", "--addr", "localhost:8181"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)
    return opa_process

def load_policy():
    print("[*] Loading policy into OPA...")
    url = "http://localhost:8181/v1/policies/agent_authz"
    with open("policy.rego", "rb") as f:
        policy_data = f.read()
    headers = {"Content-Type": "text/plain"}
    response = requests.put(url, data=policy_data, headers=headers)
    if response.status_code != 200:
        print(f"[!] Failed to load policy: {response.text}")
        sys.exit(1)
    print("[+] Policy loaded successfully.\n")

def run_single_test(test_case, session, url):
    headers = {"Content-Type": "application/json"}
    start_time = time.perf_counter()
    response = session.post(url, json={"input": test_case["payload"]}, headers=headers)
    end_time = time.perf_counter()
    
    latency_ms = (end_time - start_time) * 1000
    result = response.json().get("result", False)
    passed = result == test_case["expected"]
    
    return {
        "name": test_case["name"],
        "passed": passed,
        "latency_ms": latency_ms,
        "payload": test_case["payload"],
        "decision": result
    }

def run_evaluation():
    test_cases = [
        {"name": "Legitimate Read Operation", "payload": {"tool": "read_public_logs", "context": {"user_tier": "standard", "intent_verified": True, "prompt_injection_detected": False}}, "expected": True},
        {"name": "Unauthorized DB Access (Standard User)", "payload": {"tool": "execute_database_query", "context": {"user_tier": "standard", "intent_verified": True, "prompt_injection_detected": False}}, "expected": False},
        {"name": "Authorized DB Access (Admin User)", "payload": {"tool": "execute_database_query", "context": {"user_tier": "admin", "intent_verified": True, "prompt_injection_detected": False}}, "expected": True},
        {"name": "Attack Vector: Prompt Injection on Email Tool", "payload": {"tool": "send_notification_email", "context": {"user_tier": "admin", "intent_verified": True, "prompt_injection_detected": True}}, "expected": False},
        {"name": "Attack Vector: Unverified Intent Tool Call", "payload": {"tool": "send_notification_email", "context": {"user_tier": "admin", "intent_verified": False, "prompt_injection_detected": False}}, "expected": False}
    ]

    url = "http://localhost:8181/v1/data/agent/authz/allow"
    session = requests.Session()

    print("==================================================================")
    print("       ADVANCED ZERO-TRUST GOVERNANCE EVALUATION REPORT           ")
    print("==================================================================")
    
    audit_logs = []
    latencies = []
    passed_tests = 0

    for i, test in enumerate(test_cases, 1):
        res = run_single_test(test, session, url)
        latencies.append(res["latency_ms"])
        if res["passed"]:
            passed_tests += 1
        
        audit_logs.append({
            "timestamp": time.time(),
            "test_id": i,
            "test_name": res["name"],
            "input_payload": res["payload"],
            "access_granted": res["decision"],
            "evaluation_latency_ms": round(res["latency_ms"], 2)
        })

        status = "PASS" if res["passed"] else "FAIL"
        print(f"Test {i}: {res['name']}")
        print(f"  -> Expected: {test['expected']} | Got: {res['decision']} | Status: [{status}]")
        print(f"  -> Latency: {res['latency_ms']:.2f}ms")
        print("-" * 66)

    # Concurrency / Load Testing Section
    print("\n[*] Running Concurrency & Performance Load Test (50 parallel requests)...")
    load_test_payload = {"tool": "execute_database_query", "context": {"user_tier": "admin", "intent_verified": True, "prompt_injection_detected": False}}
    load_test_case = {"name": "Load Test Request", "payload": load_test_payload, "expected": True}
    
    load_latencies = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(run_single_test, load_test_case, session, url) for _ in range(50)]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            load_latencies.append(res["latency_ms"])

    avg_latency = sum(latencies) / len(latencies)
    avg_load_latency = sum(load_latencies) / len(load_latencies)
    max_load_latency = max(load_latencies)
    detection_rate = (passed_tests / len(test_cases)) * 100

    print("\n==================================================================")
    print("                COMPREHENSIVE DISSERTATION METRICS                ")
    print("==================================================================")
    print(f"Functional Test Accuracy: {detection_rate:.1f}% (Target: >90%)")
    print(f"Base Average Policy Latency: {avg_latency:.2f}ms (Target: <100ms KPI)")
    print(f"Load Test Avg Latency (50 concurrent): {avg_load_latency:.2f}ms")
    print(f"Load Test Max Latency: {max_load_latency:.2f}ms")
    print(f"Audit Trail Records Generated: {len(audit_logs)} structured events")
    print("==================================================================\n")

    # Save detailed audit log to file for dissertation appendix
    with open("audit_trail_export.json", "w") as f:
        json.dump(audit_logs, f, indent=4)
    print("[+] Structured audit log exported successfully to 'audit_trail_export.json'.")

if __name__ == "__main__":
    opa_proc = start_opa()
    try:
        load_policy()
        run_evaluation()
    finally:
        print("\n[*] Stopping OPA server...")
        opa_proc.terminate()
        opa_proc.wait()
