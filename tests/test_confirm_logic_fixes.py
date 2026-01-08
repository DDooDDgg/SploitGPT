#!/usr/bin/env python3
"""Test confirm-before-execute logic fixes."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sploitgpt.agent.agent import Agent, SYSTEM_PROMPT
from sploitgpt.core.boot import BootContext
from sploitgpt.core.config import get_settings


def test_system_prompt_workflow():
    """Test that SYSTEM_PROMPT explains the correct workflow."""
    print("Testing SYSTEM_PROMPT workflow...")
    
    # Check for the numbered workflow
    assert "1. Explain what you'll do" in SYSTEM_PROMPT
    assert "2. Ask for confirmation explicitly" in SYSTEM_PROMPT
    assert "3. Wait for user to respond" in SYSTEM_PROMPT
    assert "4. Then make the tool_call" in SYSTEM_PROMPT
    assert "Do not call tools until after the user confirms" in SYSTEM_PROMPT
    
    # Check for example phrases
    assert "Proceed?" in SYSTEM_PROMPT
    assert "Confirm?" in SYSTEM_PROMPT
    assert "Okay to run?" in SYSTEM_PROMPT
    
    print("✓ SYSTEM_PROMPT has correct workflow explanation")


def test_confirmation_triggers():
    """Test that _infer_confirmation_question has expanded triggers."""
    print("\nTesting confirmation trigger phrases...")
    
    settings = get_settings()
    context = BootContext(
        msf_connected=False,
        ollama_connected=False,
        model_loaded=False,
    )
    agent = Agent(context)
    
    # Test new trigger phrases
    test_cases = [
        ("Confirm?", True),
        ("Proceed?", True),
        ("Okay to run this command?", True),
        ("Shall I execute this?", True),
        ("Ready to execute?", True),
        ("Ready to run?", True),
        # Original triggers still work
        ("Would you like me to execute?", True),
        ("Should I run this?", True),
        # Non-triggers
        ("Here's what I found", False),
        ("The scan completed", False),
    ]
    
    for text, should_match in test_cases:
        result = agent._infer_confirmation_question(text)
        if should_match:
            assert result is not None, f"Expected trigger to match: {text}"
            print(f"  ✓ Matched: {text} -> {result}")
        else:
            assert result is None, f"Expected no match: {text}"
            print(f"  ✓ No match: {text}")
    
    print("✓ All confirmation triggers working correctly")


def test_confirmation_gate_scope():
    """Test that confirmation gating applies to all tools except ask_user/finish."""
    print("\nTesting confirmation gate scope...")

    agent_file = Path(__file__).resolve().parents[1] / "sploitgpt" / "agent" / "agent.py"
    content = agent_file.read_text()

    assert 'confirm_exempt = {"ask_user", "finish"}' in content, \
        "confirm_exempt should include ask_user and finish"
    assert "if name not in confirm_exempt" in content, \
        "confirmation gate should apply to non-exempt tools"

    print("✓ confirmation gate applies to all tools except ask_user/finish")


if __name__ == "__main__":
    print("Testing confirm-before-execute logic fixes")
    print("=" * 60)
    
    try:
        test_system_prompt_workflow()
        test_confirmation_triggers()
        test_confirmation_gate_scope()
        
        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        sys.exit(0)
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
