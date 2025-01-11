import csv

reader = csv.DictReader(open('Chrome Passwords.csv'))

passwords_dict = {}

for row in reader:
    passwords_dict[row['name']] = row['password']

print(passwords_dict)