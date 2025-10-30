-- Migration 005: Spatial CAPTCHA Challenges
-- ==========================================
-- 
-- Stores spatial reasoning challenges for human/bot differentiation.
--
-- Creator: Joerg Bollwahn
-- Date: 2025-10-30
-- License: MIT

-- Table: spatial_challenges
CREATE TABLE IF NOT EXISTS spatial_challenges (
    -- Primary key
    challenge_id UUID PRIMARY KEY,
    
    -- User
    user_id TEXT NOT NULL,
    session_id TEXT,
    
    -- Challenge parameters
    seed BIGINT NOT NULL,
    difficulty TEXT NOT NULL CHECK (difficulty IN ('easy', 'medium', 'hard')),
    question_type TEXT NOT NULL,
    rotation_angle FLOAT NOT NULL,
    occlusion_enabled BOOLEAN NOT NULL,
    
    -- Challenge content (JSONB for flexibility)
    objects JSONB NOT NULL,
    question_text TEXT NOT NULL,
    options JSONB NOT NULL,
    correct_answer TEXT NOT NULL,
    
    -- Presentation
    presented_at TIMESTAMP NOT NULL DEFAULT NOW(),
    png_path TEXT,
    
    -- Response
    user_answer TEXT,
    response_time_ms INTEGER,
    is_correct BOOLEAN,
    is_suspicious BOOLEAN,
    
    -- Device context
    device_info JSONB,
    
    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    responded_at TIMESTAMP,
    
    -- Indexes
    CONSTRAINT valid_response_time CHECK (response_time_ms IS NULL OR response_time_ms >= 0)
);

-- Index for user lookups
CREATE INDEX IF NOT EXISTS idx_spatial_challenges_user_id 
ON spatial_challenges(user_id);

-- Index for session tracking
CREATE INDEX IF NOT EXISTS idx_spatial_challenges_session_id 
ON spatial_challenges(session_id);

-- Index for time-based queries
CREATE INDEX IF NOT EXISTS idx_spatial_challenges_presented_at 
ON spatial_challenges(presented_at);

-- Index for difficulty-based analysis
CREATE INDEX IF NOT EXISTS idx_spatial_challenges_difficulty 
ON spatial_challenges(difficulty);


-- Table: spatial_user_profiles
-- Tracks user performance for adaptive difficulty
CREATE TABLE IF NOT EXISTS spatial_user_profiles (
    user_id TEXT PRIMARY KEY,
    
    -- Aggregate stats
    challenges_completed INTEGER NOT NULL DEFAULT 0,
    challenges_passed INTEGER NOT NULL DEFAULT 0,
    average_response_time_ms FLOAT NOT NULL DEFAULT 0.0,
    
    -- Difficulty-specific accuracy
    easy_accuracy FLOAT NOT NULL DEFAULT 0.0,
    medium_accuracy FLOAT NOT NULL DEFAULT 0.0,
    hard_accuracy FLOAT NOT NULL DEFAULT 0.0,
    
    -- Metadata
    last_updated TIMESTAMP NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT valid_accuracy_easy CHECK (easy_accuracy >= 0.0 AND easy_accuracy <= 1.0),
    CONSTRAINT valid_accuracy_medium CHECK (medium_accuracy >= 0.0 AND medium_accuracy <= 1.0),
    CONSTRAINT valid_accuracy_hard CHECK (hard_accuracy >= 0.0 AND hard_accuracy <= 1.0)
);

-- Index for profile lookups
CREATE INDEX IF NOT EXISTS idx_spatial_user_profiles_user_id 
ON spatial_user_profiles(user_id);


-- View: spatial_challenge_stats
-- Aggregated statistics for monitoring
CREATE OR REPLACE VIEW spatial_challenge_stats AS
SELECT
    difficulty,
    COUNT(*) as total_challenges,
    COUNT(*) FILTER (WHERE is_correct = true) as passed,
    COUNT(*) FILTER (WHERE is_correct = false) as failed,
    COUNT(*) FILTER (WHERE is_suspicious = true) as suspicious,
    AVG(response_time_ms) FILTER (WHERE response_time_ms IS NOT NULL) as avg_response_time_ms,
    STDDEV(response_time_ms) FILTER (WHERE response_time_ms IS NOT NULL) as stddev_response_time_ms,
    COUNT(DISTINCT user_id) as unique_users
FROM spatial_challenges
WHERE user_answer IS NOT NULL
GROUP BY difficulty;


-- View: spatial_user_performance
-- Per-user performance summary
CREATE OR REPLACE VIEW spatial_user_performance AS
SELECT
    user_id,
    COUNT(*) as total_attempts,
    COUNT(*) FILTER (WHERE is_correct = true) as passed,
    ROUND(COUNT(*) FILTER (WHERE is_correct = true)::numeric / NULLIF(COUNT(*), 0), 3) as pass_rate,
    AVG(response_time_ms) as avg_response_time_ms,
    COUNT(*) FILTER (WHERE is_suspicious = true) as suspicious_count,
    MAX(presented_at) as last_attempt_at
FROM spatial_challenges
WHERE user_answer IS NOT NULL
GROUP BY user_id;


-- Function: update_spatial_profile_trigger
-- Automatically updates user profile when challenge completed
CREATE OR REPLACE FUNCTION update_spatial_profile_trigger()
RETURNS TRIGGER AS $$
BEGIN
    -- Only trigger on response (not on challenge creation)
    IF NEW.user_answer IS NOT NULL AND OLD.user_answer IS NULL THEN
        -- Upsert profile
        INSERT INTO spatial_user_profiles (user_id, challenges_completed, challenges_passed)
        VALUES (NEW.user_id, 1, CASE WHEN NEW.is_correct THEN 1 ELSE 0 END)
        ON CONFLICT (user_id) DO UPDATE SET
            challenges_completed = spatial_user_profiles.challenges_completed + 1,
            challenges_passed = spatial_user_profiles.challenges_passed + CASE WHEN NEW.is_correct THEN 1 ELSE 0 END,
            last_updated = NOW();
        
        -- Update difficulty-specific accuracy
        IF NEW.difficulty = 'easy' THEN
            UPDATE spatial_user_profiles
            SET easy_accuracy = (
                SELECT AVG(CASE WHEN is_correct THEN 1.0 ELSE 0.0 END)
                FROM spatial_challenges
                WHERE user_id = NEW.user_id AND difficulty = 'easy' AND is_correct IS NOT NULL
            )
            WHERE user_id = NEW.user_id;
        ELSIF NEW.difficulty = 'medium' THEN
            UPDATE spatial_user_profiles
            SET medium_accuracy = (
                SELECT AVG(CASE WHEN is_correct THEN 1.0 ELSE 0.0 END)
                FROM spatial_challenges
                WHERE user_id = NEW.user_id AND difficulty = 'medium' AND is_correct IS NOT NULL
            )
            WHERE user_id = NEW.user_id;
        ELSIF NEW.difficulty = 'hard' THEN
            UPDATE spatial_user_profiles
            SET hard_accuracy = (
                SELECT AVG(CASE WHEN is_correct THEN 1.0 ELSE 0.0 END)
                FROM spatial_challenges
                WHERE user_id = NEW.user_id AND difficulty = 'hard' AND is_correct IS NOT NULL
            )
            WHERE user_id = NEW.user_id;
        END IF;
        
        -- Update average response time
        UPDATE spatial_user_profiles
        SET average_response_time_ms = (
            SELECT AVG(response_time_ms)
            FROM spatial_challenges
            WHERE user_id = NEW.user_id AND response_time_ms IS NOT NULL
        )
        WHERE user_id = NEW.user_id;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger: auto_update_spatial_profile
CREATE TRIGGER auto_update_spatial_profile
AFTER UPDATE ON spatial_challenges
FOR EACH ROW
EXECUTE FUNCTION update_spatial_profile_trigger();


-- Comments
COMMENT ON TABLE spatial_challenges IS 'Spatial reasoning challenges for human/bot differentiation (Spatial CAPTCHA)';
COMMENT ON TABLE spatial_user_profiles IS 'User performance profiles for adaptive difficulty';
COMMENT ON VIEW spatial_challenge_stats IS 'Aggregated challenge statistics by difficulty';
COMMENT ON VIEW spatial_user_performance IS 'Per-user performance summary';

