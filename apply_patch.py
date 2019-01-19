from subprocess import call

import sys


patch = sys.argv[1]
parts = patch.split('/')
start = int(parts[0][-1])
print(start)

if parts[1] == 'complete':
    start += 1
    patch_file = parts[2]
    skip = False
else:
    patch_file = parts[1]
    skip = True

to_patch = patch_file.split('.')[0] + '.py'

for week in range(start, 9):
    if skip:
        skip = False
    else:
        filename = 'week{}/{}'.format(week, to_patch)
#        call('git checkout {}'.format(filename), shell=True)
        call('patch -p1 {} < {}'.format(filename, patch), shell=True)
    filename = 'week{}/complete/{}'.format(week, to_patch)
#    call('git checkout {}'.format(filename), shell=True)
    call('patch -p1 {} < {}'.format(filename, patch), shell=True)
