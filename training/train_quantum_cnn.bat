@echo off
python training/train_quantum_cnn.py --learning_rate 5e-5 --gradient_clip 0.5 --batch_size 8 --dropout 0.3 --weight_decay 1e-4 --early_stopping_patience 2 --warmup_epochs 3 --weighted_sampler --epochs 20
