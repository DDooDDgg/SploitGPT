"""
SploitGPT Training Module

Handles:
- Install-time fine-tuning with LoRA
- Session data collection for continuous learning
- Model export and optimization
"""

from .collector import SessionCollector
from .finetune import check_gpu_available, run_finetuning

__all__ = ["run_finetuning", "check_gpu_available", "SessionCollector"]
