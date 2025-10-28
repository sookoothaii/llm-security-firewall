"""
Influence Budget Repository (PostgreSQL-backed)
==============================================

Online Z-Score tracking with EWMA for Slow-Roll-Poison detection.
Uses psycopg3 for atomic writes to influence_budget_rollup table.
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

try:
    import psycopg
    HAS_PSYCOPG3 = True
except ImportError:
    HAS_PSYCOPG3 = False
    psycopg = None


@dataclass(frozen=True)
class InfluenceConfig:
    """Configuration for Influence Budget tracking."""
    dsn: str
    bucket_minutes: int = 60
    alpha: float = 0.2
    alert_z: float = 4.0


class InfluenceBudgetRepo:
    """
    Repository for Influence Budget tracking.
    
    Uses PostgreSQL stored procedure sp_update_influence_budget
    for atomic EWMA updates and Z-score computation.
    """
    
    def __init__(self, cfg: InfluenceConfig):
        """
        Args:
            cfg: Influence configuration
        """
        if not HAS_PSYCOPG3:
            raise ImportError("psycopg3 required for InfluenceBudgetRepo")
        
        self.cfg = cfg
    
    def _bucket_start(self, t: datetime) -> datetime:
        """
        Compute bucket start time for given timestamp.
        
        Args:
            t: Timestamp
            
        Returns:
            Bucket start time (rounded down to bucket_minutes)
        """
        t = t.replace(second=0, microsecond=0)
        m = (t.minute // self.cfg.bucket_minutes) * self.cfg.bucket_minutes
        return t.replace(minute=m)
    
    def record(
        self, 
        domain: str, 
        influence: float, 
        when: Optional[datetime] = None
    ) -> float:
        """
        Record influence and get current Z-score.
        
        Args:
            domain: Domain (SCIENCE, MEDICINE, etc.)
            influence: Influence score
            when: Timestamp (default: now UTC)
            
        Returns:
            Current Z-score for this bucket
        """
        if when is None:
            when = datetime.utcnow()
        
        bucket = self._bucket_start(when)
        
        with psycopg.connect(self.cfg.dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                # Call stored procedure for atomic EWMA update
                cur.execute(
                    "SELECT sp_update_influence_budget(%s, %s, %s, %s);",
                    (domain.lower(), bucket, float(influence), float(self.cfg.alpha))
                )
                
                # Fetch current Z-score
                cur.execute(
                    "SELECT z_score FROM influence_budget_rollup "
                    "WHERE domain=%s AND bucket_start=%s;",
                    (domain.lower(), bucket)
                )
                
                row = cur.fetchone()
                if row is None:
                    return 0.0
                
                return float(row[0])
    
    def is_alert(self, z: float) -> bool:
        """
        Check if Z-score triggers alert.
        
        Args:
            z: Z-score
            
        Returns:
            True if alert threshold exceeded
        """
        return abs(z) >= self.cfg.alert_z
    
    def get_rollup(
        self, 
        domain: str, 
        start: datetime, 
        end: Optional[datetime] = None
    ) -> List[Dict]:
        """
        Get rollup data for domain in time range.
        
        Args:
            domain: Domain
            start: Start time
            end: End time (default: now)
            
        Returns:
            List of rollup records
        """
        if end is None:
            end = datetime.utcnow()
        
        with psycopg.connect(self.cfg.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT domain, bucket_start, ib_sum, ewma_mean, 
                           ewma_var, z_score, samples
                    FROM influence_budget_rollup
                    WHERE domain = %s 
                      AND bucket_start >= %s 
                      AND bucket_start <= %s
                    ORDER BY bucket_start
                    """,
                    (domain.lower(), start, end)
                )
                
                rows = cur.fetchall()
                
                return [
                    {
                        'domain': row[0],
                        'bucket_start': row[1],
                        'ib_sum': row[2],
                        'ewma_mean': row[3],
                        'ewma_var': row[4],
                        'z_score': row[5],
                        'samples': row[6]
                    }
                    for row in rows
                ]
    
    def get_alerts(
        self, 
        domain: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        Get alerts (high Z-scores).
        
        Args:
            domain: Optional domain filter
            since: Optional time filter
            limit: Max results
            
        Returns:
            List of alert records
        """
        if since is None:
            since = datetime.utcnow() - timedelta(days=7)
        
        with psycopg.connect(self.cfg.dsn) as conn:
            with conn.cursor() as cur:
                if domain is not None:
                    cur.execute(
                        """
                        SELECT domain, bucket_start, ib_sum, ewma_mean, 
                               ewma_var, z_score, samples
                        FROM influence_budget_rollup
                        WHERE domain = %s 
                          AND bucket_start >= %s
                          AND ABS(z_score) >= %s
                        ORDER BY ABS(z_score) DESC
                        LIMIT %s
                        """,
                        (domain.lower(), since, self.cfg.alert_z, limit)
                    )
                else:
                    cur.execute(
                        """
                        SELECT domain, bucket_start, ib_sum, ewma_mean, 
                               ewma_var, z_score, samples
                        FROM influence_budget_rollup
                        WHERE bucket_start >= %s
                          AND ABS(z_score) >= %s
                        ORDER BY ABS(z_score) DESC
                        LIMIT %s
                        """,
                        (since, self.cfg.alert_z, limit)
                    )
                
                rows = cur.fetchall()
                
                return [
                    {
                        'domain': row[0],
                        'bucket_start': row[1],
                        'ib_sum': row[2],
                        'ewma_mean': row[3],
                        'ewma_var': row[4],
                        'z_score': row[5],
                        'samples': row[6],
                        'is_alert': abs(row[5]) >= self.cfg.alert_z
                    }
                    for row in rows
                ]


# Example usage
if __name__ == "__main__":
    import os
    
    # Get DSN from environment or use default
    dsn = os.getenv("DATABASE_URL", "postgresql://hakgal:password@localhost:5172/hakgal")
    
    cfg = InfluenceConfig(
        dsn=dsn,
        bucket_minutes=60,
        alpha=0.2,
        alert_z=4.0
    )
    
    repo = InfluenceBudgetRepo(cfg)
    
    # Simulate normal influence
    print("Recording normal influences...")
    for i in range(10):
        z = repo.record("SCIENCE", 0.1 + i * 0.01)
        print(f"  Sample {i+1}: influence=0.{10+i}, z={z:.3f}")
    
    # Simulate spike
    print("\nRecording spike...")
    z_spike = repo.record("SCIENCE", 5.0)
    print(f"  Spike: influence=5.0, z={z_spike:.3f}")
    print(f"  Is alert: {repo.is_alert(z_spike)}")
    
    # Get alerts
    alerts = repo.get_alerts(domain="SCIENCE", limit=5)
    print(f"\nAlerts: {len(alerts)}")
    for alert in alerts:
        print(f"  {alert['bucket_start']}: z={alert['z_score']:.2f}")

