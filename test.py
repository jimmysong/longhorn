from os import chdir
from subprocess import call


for week in range(2):
    if week == 0:
        path = 'practice'
    else:
        path = 'week{}'.format(week)
    chdir(path)
    call('nosetests --with-doctest *.py', shell=True)
    chdir('complete')
    call('nosetests --with-doctest *.py', shell=True)
    chdir('../..')
