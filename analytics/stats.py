import csv

ALERT_FILE = "alerts/alerts.csv"

critical = 0
high = 0
medium = 0

with open(ALERT_FILE, "r") as file:

    reader = csv.DictReader(file)

    for row in reader:

        severity = row["Severity"]

        if severity == "Critical":
            critical += 1

        elif severity == "High":
            high += 1

        elif severity == "Medium":
            medium += 1

total = critical + high + medium

print("\nThreat Statistics")
print("=" * 30)

print(f"Total Alerts    : {total}")
print(f"Critical Alerts : {critical}")
print(f"High Alerts     : {high}")
print(f"Medium Alerts   : {medium}")