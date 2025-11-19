
import time
import uuid
import threading
import statistics
from concurrent.futures import ThreadPoolExecutor
import sys
import os

# Adjust path to import from src
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from llm_firewall.storage import StorageManager
    from llm_firewall.agents.memory import HierarchicalMemory
    from llm_firewall.detectors.tool_killchain import ToolEvent
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you run this from standalone_packages/llm-security-firewall/")
    sys.exit(1)

def run_performance_test(num_sessions=100, events_per_session=50, concurrency=10):
    print(f"======================================================================")
    print(f"PERFORMANCE TEST: Persistence Layer")
    print(f"Sessions: {num_sessions} | Events/Session: {events_per_session} | Concurrency: {concurrency}")
    print(f"Database: SQLite (hakgal_firewall.db)")
    print(f"======================================================================")

    storage = StorageManager() # Uses default SQLite
    
    # Create sessions first
    sessions = []
    for _ in range(num_sessions):
        sid = f"perf-test-{uuid.uuid4().hex[:8]}"
        mem = HierarchicalMemory(session_id=sid)
        sessions.append((sid, mem))
        
    # Measure Write Performance (Create Sessions)
    start_time = time.time()
    
    def worker_save_session(session_data):
        sid, mem = session_data
        storage.save_session(sid, mem)
        
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        list(executor.map(worker_save_session, sessions))
        
    end_time = time.time()
    duration = end_time - start_time
    ops_per_sec = num_sessions / duration
    print(f"\n[CREATE] Created {num_sessions} sessions in {duration:.4f}s")
    print(f"[CREATE] Throughput: {ops_per_sec:.2f} sessions/sec")

    # Measure Update Performance (Add Events)
    # Simulating adding events which triggers a save_session call
    print(f"\n[UPDATE] Simulating {events_per_session} updates per session...")
    
    latencies = []
    
    def worker_add_events(session_data):
        sid, mem = session_data
        local_latencies = []
        for i in range(events_per_session):
            # Simulate logic
            event = ToolEvent(
                tool="chat", 
                category="test", 
                target=None, 
                timestamp=time.time(), 
                success=True, 
                metadata={"iter": i}
            )
            mem.tactical_buffer.append(event)
            
            # Simulate the persistence call happening in proxy_server
            t0 = time.time()
            storage.save_session(sid, mem)
            t1 = time.time()
            local_latencies.append(t1 - t0)
        return local_latencies

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        results = list(executor.map(worker_add_events, sessions))
        
    end_time = time.time()
    duration = end_time - start_time
    total_updates = num_sessions * events_per_session
    ops_per_sec = total_updates / duration
    
    # Flatten latencies
    for res in results:
        latencies.extend(res)
        
    avg_latency = statistics.mean(latencies) * 1000
    p95_latency = statistics.quantiles(latencies, n=20)[18] * 1000 # 95th percentile
    p99_latency = statistics.quantiles(latencies, n=100)[98] * 1000 # 99th percentile

    print(f"[UPDATE] Performed {total_updates} updates in {duration:.4f}s")
    print(f"[UPDATE] Throughput: {ops_per_sec:.2f} updates/sec")
    print(f"[UPDATE] Latency Avg: {avg_latency:.2f} ms")
    print(f"[UPDATE] Latency P95: {p95_latency:.2f} ms")
    print(f"[UPDATE] Latency P99: {p99_latency:.2f} ms")

    # Cleanup
    print(f"\n[CLEANUP] Deleting test sessions...")
    for sid, _ in sessions:
        storage.delete_session(sid)
        
    print("\nTest Complete.")

if __name__ == "__main__":
    # Run a moderate load test
    # SQLite handles concurrent READS well, but only one WRITE at a time.
    # We expect throughput to bottleneck on disk I/O and SQLite locking.
    run_performance_test(num_sessions=20, events_per_session=20, concurrency=5)

