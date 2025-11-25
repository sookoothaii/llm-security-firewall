-- 020_influence_budget.sql
-- Online Z-Score/EWMA tracking for Slow-Roll-Poison detection
-- Persona-free, purely epistemic tracking

BEGIN;

CREATE TABLE IF NOT EXISTS influence_budget_rollup (
  domain TEXT NOT NULL,
  bucket_start TIMESTAMPTZ NOT NULL,
  ib_sum DOUBLE PRECISION NOT NULL,
  ewma_mean DOUBLE PRECISION NOT NULL,
  ewma_var  DOUBLE PRECISION NOT NULL,
  z_score   DOUBLE PRECISION NOT NULL,
  samples   BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (domain, bucket_start)
);

CREATE INDEX IF NOT EXISTS idx_ib_domain_bucket ON influence_budget_rollup(domain, bucket_start);

CREATE OR REPLACE FUNCTION sp_update_influence_budget(
  p_domain TEXT,
  p_bucket TIMESTAMPTZ,
  p_influence DOUBLE PRECISION,
  p_alpha DOUBLE PRECISION DEFAULT 0.2
) RETURNS VOID
LANGUAGE plpgsql AS $$
DECLARE
  v_mean DOUBLE PRECISION;
  v_var  DOUBLE PRECISION;
  v_sum  DOUBLE PRECISION;
  v_samp BIGINT;
  a DOUBLE PRECISION;
  delta DOUBLE PRECISION;
  new_mean DOUBLE PRECISION;
  new_var  DOUBLE PRECISION;
BEGIN
  -- Try to fetch existing record
  SELECT ib_sum, ewma_mean, ewma_var, samples
    INTO v_sum, v_mean, v_var, v_samp
    FROM influence_budget_rollup
   WHERE domain = p_domain AND bucket_start = p_bucket
   FOR UPDATE;

  IF NOT FOUND THEN
    -- First sample for this bucket
    v_sum := p_influence;
    v_mean := p_influence;
    v_var  := 0.0;
    v_samp := 1;
    INSERT INTO influence_budget_rollup(domain, bucket_start, ib_sum, ewma_mean, ewma_var, z_score, samples)
    VALUES (lower(p_domain), p_bucket, v_sum, v_mean, v_var, 0.0, v_samp);
    RETURN;
  END IF;

  -- EWMA updates (West et al. approximation)
  a := p_alpha;
  delta := p_influence - v_mean;
  new_mean := (1-a)*v_mean + a*p_influence;
  new_var  := (1-a)*(v_var + a*(delta*delta));

  v_sum := v_sum + p_influence;
  v_mean := new_mean;
  v_var  := new_var;
  v_samp := v_samp + 1;

  -- Update with new Z-score
  UPDATE influence_budget_rollup
     SET ib_sum = v_sum,
         ewma_mean = v_mean,
         ewma_var  = v_var,
         z_score   = CASE
                       WHEN v_var <= 1e-12 THEN 0.0
                       ELSE (p_influence - v_mean)/sqrt(v_var)
                     END,
         samples   = v_samp
   WHERE domain = p_domain AND bucket_start = p_bucket;
END;
$$;

COMMIT;
