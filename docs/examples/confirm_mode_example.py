#!/usr/bin/env python3
"""Example: Using confirmation mode in SploitGPT agent."""

import asyncio
from sploitgpt.core.boot import boot_sequence
from sploitgpt.agent import Agent


async def example_with_confirmation():
    """Example showing confirmation workflow."""
    print("=== Example: Agent with Confirmation Mode ===\n")
    
    # Boot the system
    context = await boot_sequence(quiet=True)
    
    # Create agent with confirmation enabled
    agent = Agent(context)
    agent.confirm_actions = True  # Require confirmation (default)
    agent.autonomous = False       # Not autonomous
    
    print(f"Confirmation mode: {agent.confirm_actions}")
    print(f"Autonomous mode: {agent.autonomous}\n")
    
    # Example task
    task = "Scan 10.0.0.1 for open ports"
    print(f"User: {task}\n")
    
    # Process the task
    async for response in agent.process(task):
        if response.type == "message":
            print(f"Agent: {response.content}\n")
        
        elif response.type == "choice":
            # Agent is asking for confirmation
            print(f"Confirmation Required:")
            print(f"  Question: {response.question}")
            print(f"  Options: {response.options}\n")
            
            # Simulate user confirming
            user_choice = "yes"
            print(f"User: {user_choice}\n")
            
            # Submit the choice and continue
            async for result in agent.submit_choice(user_choice):
                if result.type == "message":
                    print(f"Agent: {result.content}\n")
                elif result.type == "tool_result":
                    print(f"Tool Result: {result.content[:200]}...\n")
        
        elif response.type == "tool_result":
            print(f"Tool Result: {response.content[:200]}...\n")


async def example_without_confirmation():
    """Example showing autonomous mode (no confirmation)."""
    print("\n=== Example: Agent in Autonomous Mode ===\n")
    
    # Boot the system
    context = await boot_sequence(quiet=True)
    
    # Create agent in autonomous mode
    agent = Agent(context)
    agent.confirm_actions = False  # Disable confirmation
    agent.autonomous = True        # Fully autonomous
    
    print(f"Confirmation mode: {agent.confirm_actions}")
    print(f"Autonomous mode: {agent.autonomous}\n")
    
    # Example task
    task = "Quick scan of 192.168.1.1"
    print(f"User: {task}\n")
    
    # Process the task - no confirmation needed
    async for response in agent.process(task):
        if response.type == "message":
            print(f"Agent: {response.content}\n")
        elif response.type == "tool_result":
            print(f"Tool Result: {response.content[:200]}...\n")


async def main():
    """Run examples."""
    print("SploitGPT Confirmation Mode Examples")
    print("=" * 60)
    
    # Example 1: With confirmation
    await example_with_confirmation()
    
    # Example 2: Without confirmation (autonomous)
    await example_without_confirmation()
    
    print("\n" + "=" * 60)
    print("Examples completed!")


if __name__ == "__main__":
    asyncio.run(main())
