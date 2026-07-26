#!/usr/bin/python3

import argparse
import sys
from typing import Dict, Tuple, List


def parse_snapshot(filename: str) -> Dict[str, int]:
    """Parse a heap snapshot file and return a dictionary of class name to instance count."""
    snapshot = {}
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    # Last part is the count, everything else is the class name
                    count = parts[-1]
                    class_name = ' '.join(parts[:-1])
                    try:
                        snapshot[class_name] = int(count)
                    except ValueError:
                        # Skip lines where the last column isn't a number
                        continue
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filename}': {e}", file=sys.stderr)
        sys.exit(1)
    return snapshot


def calculate_growth(snapshot1: Dict[str, int], snapshot2: Dict[str, int]) -> List[Tuple[str, int, int, float]]:
    """Calculate the growth between two snapshots.

    Returns a list of tuples: (class_name, count1, count2, growth_percentage)
    """
    growth_data = []

    # Find all classes present in either snapshot
    all_classes = set(snapshot1.keys()) | set(snapshot2.keys())

    for class_name in all_classes:
        count1 = snapshot1.get(class_name, 0)
        count2 = snapshot2.get(class_name, 0)

        # Calculate percentage growth
        if count1 == 0:
            # New class appeared in snapshot2
            if count2 > 0:
                growth_pct = float('inf')
            else:
                continue
        else:
            growth_pct = ((count2 - count1) / count1) * 100

        # Only include classes that have grown
        if count2 > count1:
            growth_data.append((class_name, count1, count2, growth_pct))

    return growth_data


def main():
    parser = argparse.ArgumentParser(
        description='Compare Java heap snapshots to identify potential memory leaks'
    )
    parser.add_argument('snapshot1', help='First heap snapshot file')
    parser.add_argument('snapshot2', help='Second heap snapshot file')
    parser.add_argument('-n', '--top', type=int, default=10,
                       help='Number of top growing classes to display (default: 10)')

    args = parser.parse_args()

    print(f"Comparing heap snapshots:")
    print(f"  Snapshot 1: {args.snapshot1}")
    print(f"  Snapshot 2: {args.snapshot2}")
    print()

    # Parse both snapshots
    snapshot1 = parse_snapshot(args.snapshot1)
    snapshot2 = parse_snapshot(args.snapshot2)

    if not snapshot1:
        print("Error: First snapshot is empty or invalid", file=sys.stderr)
        sys.exit(1)
    if not snapshot2:
        print("Error: Second snapshot is empty or invalid", file=sys.stderr)
        sys.exit(1)

    print(f"Classes in snapshot 1: {len(snapshot1)}")
    print(f"Classes in snapshot 2: {len(snapshot2)}")
    print()

    # Calculate growth
    growth_data = calculate_growth(snapshot1, snapshot2)

    if not growth_data:
        print("No classes with increased instance counts found")
        return

    # Sort by growth percentage (descending)
    growth_data.sort(key=lambda x: (x[3] != float('inf'), x[3]), reverse=True)

    # Display top N classes
    print(f"Top {args.top} classes with highest growth:")
    print()
    print(f"{'Class Name':<60} {'Count 1':>12} {'Count 2':>12} {'Growth':>12}")
    print("=" * 100)

    for i, (class_name, count1, count2, growth_pct) in enumerate(growth_data[:args.top]):
        if growth_pct == float('inf'):
            growth_str = "NEW"
        else:
            growth_str = f"{growth_pct:+.1f}%"

        # Truncate long class names
        display_name = class_name[:60] if len(class_name) <= 60 else class_name[:57] + "..."

        print(f"{display_name:<60} {count1:>12,} {count2:>12,} {growth_str:>12}")


if __name__ == '__main__':
    main()
