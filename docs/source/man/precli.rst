======
precli
======

SYNOPSIS
========

precli [-h] [-d] [-r] [--enable ENABLE] [--disable DISABLE] [--json] [--plain] 
              [--no-color]
              [--version]
              [targets ...]


DESCRIPTION
===========

``precli`` is a tool designed to find security issues in code. It finds issues
such as injection, weak hashes, cleartext transmission of data, timing
attacks, weak encryption, deserialization of untrusted data, improper
certificate validation, and more.

OPTIONS
=======

  -h, --help         show this help message and exit
  -d, --debug        turn on debug mode
  -r, --recursive    find and process files in subdirectories
  --enable ENABLE    comma-separated list of rule IDs or names to enable
  --disable DISABLE  comma-separated list of rule IDs or names to disable
  --json             display output as formatted JSON
  --plain            display output in plain, tabular text
  --no-color         do not display color in output
  --version          show program's version number and exit

FILES
=====

.preignore
  file that specifies which files and directories can be ignored

EXAMPLES
========

Example usage across a code tree::

    precli -r ~/your-repos/project

Precli supports passing lines of code to scan using standard input. To
run Precli with standard input::

    cat examples/imports.py | precli -

REPORTING BUGS
==============

Report issues at the following link: https://github.com/securesauce/precli/issues

SEE ALSO
========

pylint(1)
