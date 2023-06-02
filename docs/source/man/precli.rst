======
precli
======

SYNOPSIS
========

precli [-h] [-d] [-r] [--json] [--plain] [--no-color] [--version] [targets ...]

DESCRIPTION
===========

``precli`` is a tool designed to find common security issues in code. It 
processes each file, builds an AST from it, and runs appropriate
rules against the AST nodes.

OPTIONS
=======

  -h, --help       show this help message and exit
  -d, --debug      turn on debug mode
  -r, --recursive  find and process files in subdirectories
  --json           display output as formatted JSON
  --plain          display output in plain, tabular text
  --no-color       do not display color in output
  --version        show program's version number and exit

EXAMPLES
========

Example usage across a code tree::

    precli -r ~/your-repos/project

Precli supports passing lines of code to scan using standard input. To
run Precli with standard input::

    cat examples/imports.py | precli -

SEE ALSO
========

pylint(1)
