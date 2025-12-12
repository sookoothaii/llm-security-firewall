@echo off
REM Windows CMD Befehle für Quantum-Inspired CNN Training
REM ======================================================

REM 1. Erweiterte Trainingsdaten generieren
python scripts\generate_augmented_training_data.py --input data\train\quantum_cnn_training.jsonl --output data\train\quantum_cnn_training_augmented.jsonl --context_wrapper 300 --obfuscation 600 --eval_patterns 150 --sql_destructive 100

REM 2. Training mit erweiterten Daten
python training\train_quantum_cnn.py --train data\train\quantum_cnn_training_augmented.jsonl --val data\train\quantum_cnn_training_val.jsonl --learning_rate 5e-5 --gradient_clip 0.5 --batch_size 8 --weighted_sampler

REM 3. Test-Set Evaluation
python scripts\evaluate_final_model.py --model models\quantum_cnn_trained\best_model.pt --test data\train\quantum_cnn_training_test.jsonl

REM 4. Adversarial Tests
python scripts\adversarial_tests.py --model models\quantum_cnn_trained\best_model.pt

REM 5. Weakness Analysis
python scripts\analyze_model_weaknesses.py --test_results models\quantum_cnn_trained\test_evaluation_results.json --adversarial_results models\quantum_cnn_trained\adversarial_test_results.json

REM 6. Training (Standard - ohne Augmentation)
python training\train_quantum_cnn.py --learning_rate 5e-5 --gradient_clip 0.5 --batch_size 8 --weighted_sampler
