#!/usr/bin/python3

import argparse
import sys
from typing import Dict, Tuple, List


def parse_input(filename: str) -> Dict[str, int]:
    """Parse input file and return a dictionary of object class name to count."""
    data = {}
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) != 2:
                    print(f"Error: File '{filename}' line {line_num} does not contain exactly 2 columns", file=sys.stderr)
                    sys.exit(1)
                class_name, count = parts
                try:
                    data[class_name] = int(count)
                except ValueError:
                    print(f"Error: File '{filename}' line {line_num} has invalid count value: {count}", file=sys.stderr)
                    sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filename}': {e}", file=sys.stderr)
        sys.exit(1)
    return data


def calculate_changes(snapshot1: Dict[str, int], snapshot2: Dict[str, int]) -> List[Tuple[str, int, int, float]]:
    """Calculate changes between two heap snapshots.

    Returns a list of tuples: (class_name, before, after, change, percentage)
    """
    results = []

    # Find all objects present in either snapshots
    objects = set(snapshot1.keys()) | set(snapshot2.keys())

    for class_name in objects:
        before = snapshot1.get(class_name, 0)
        after = snapshot2.get(class_name, 0)
        change = after - before

        # Calculate percentage of change
        if before == 0:
            # New object appeared in second file
            if change > 0:
                percentage = float('inf')
            else:
                continue
        else:
            percentage = (change / before) * 100

        # Only include classes that have changed
        if change > 0:
            results.append((class_name, before, after, change, percentage))

    return results


def main():
    parser = argparse.ArgumentParser(
        description='Compare two heap snapshots to detect memory leak'
    )
    parser.add_argument('snapshot1', help='First heap snapshot')
    parser.add_argument('snapshot2', help='Second heao snapshot')

    args = parser.parse_args()

    # Parse both params
    snapshot1 = parse_input(args.snapshot1)
    snapshot2 = parse_input(args.snapshot2)

    if not snapshot1:
        print("Error: First heap snapshot is empty or invalid", file=sys.stderr)
        sys.exit(1)

    if not snapshot2:
        print("Error: Second heap snapshot is empty or invalid", file=sys.stderr)
        sys.exit(1)

    # Calculate changes
    results = calculate_changes(snapshot1, snapshot2)

    if not results:
        print("No heap changes")
        return

    # Sort by percentage (descending)
    results.sort(key=lambda x: (x[4] != float('inf'), x[4]), reverse=True)

    # Display results
    print(f"{'Class Name':<60} {'Before':>8} {'After':>8} {'Change':>8} {'Percentage':>11}")
    print("=" * 100)

    for i, (class_name, before, after, change, percentage) in enumerate(results):
        if percentage == float('inf'):
            percentage_str = "NEW"
        else:
            percentage_str = f"{percentage:+.0f}%"

        # Truncate long class names
        display_name = class_name[:60] if len(class_name) <= 60 else class_name[:57] + "..."

        print(f"{display_name:<60} {before:>8} {after:>8} {change:>+8} {percentage_str:>11}")


if __name__ == '__main__':
    main()
