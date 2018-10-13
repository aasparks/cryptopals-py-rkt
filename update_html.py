import re

def update_stylesheets():
    direc = 'docs/py/html/'
    files = ['index', 'genindex', 'modules', 'py-modindex',
             'search', 'set1', 'set2', 'set3', 'set4', 'set5']
    ext = '.html'

    # no regexp needed
    style = "=\"_static/"
    newstyle = "=\"cryptopals-py-rkt/docs/py/html/_static/"

    for file in files:
        f = open(direc + file + ext, 'r')
        data = f.read().replace(style, newstyle)
        f.close()
        f = open(direc + file + ext, 'w')
        f.write(data)
        f.close()

if __name__ == "__main__":
    update_stylesheets()