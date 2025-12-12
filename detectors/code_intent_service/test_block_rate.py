"""Quick test to check block rate calculation."""
import requests
import json

r = requests.get('http://localhost:8000/api/v1/feedback/stats')
data = r.json()

print("=" * 60)
print("BLOCK RATE ANALYSIS")
print("=" * 60)
print(f"\nCombined Stats:")
print(f"  Total Samples: {data['total_samples']}")
print(f"  Blocked Samples: {data['blocked_samples']}")
print(f"  Block Rate: {data['block_rate']:.2%}")

print(f"\nRepository Stats:")
if 'repositories' in data:
    redis = data['repositories'].get('redis', {})
    postgres = data['repositories'].get('postgres', {})
    
    if redis:
        print(f"  Redis:")
        print(f"    Samples: {redis.get('total_samples', 0)}")
        print(f"    Blocked: {redis.get('blocked_samples', 0)}")
        print(f"    Block Rate: {redis.get('block_rate', 0.0):.2%}")
    
    if postgres:
        print(f"  PostgreSQL:")
        print(f"    Samples: {postgres.get('total_samples', 0)}")
        print(f"    Blocked: {postgres.get('blocked_samples', 0)}")
        print(f"    Block Rate: {postgres.get('block_rate', 0.0):.2%}")

print("\n" + "=" * 60)

