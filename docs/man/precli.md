# **PRECLI**

## **SYNOPSIS**

```
precli [-h] [-d] [-c CONFIG] [--custom-rules CUSTOM_RULES] [-r] [--enable ENABLE |
       --disable DISABLE] [--json | --plain | --markdown] [--gist] [-o OUTPUT] [--no-color]
       [-q] [--version]
       [targets ...]
```

## **COPYRIGHT**

Copyright 2025 Secure Sauce LLC

## **DESCRIPTION**

**Precli** is a tool designed to find security issues in code. It finds issues
such as injection, weak hashes, cleartext transmission of data, timing
attacks, weak encryption, deserialization of untrusted data, improper
certificate validation, and more.

## **OPTIONS**

```
  -h, --help            show this help message and exit
  -d, --debug           turn on debug mode
  -c, --config CONFIG   configuration file
  --custom-rules CUSTOM_RULES
                        path to directory containing custom rules
  -r, --recursive       find and process files in subdirectories
  --enable ENABLE       comma-separated list of rule IDs or names to enable
  --disable DISABLE     comma-separated list of rule IDs or names to disable
  --json                render the output as formatted JSON
  --plain               render the output in plain, tabular text
  --markdown            render the output in markdown format
  --gist                output the results to Gist
  -o,--output OUTPUT    output the results to a file
  --no-color            do not display color in output
  -q, --quiet           quiet mode, display less output
  --version             show program's version number and exit
```

## **FILES**

<ins>.preignore</ins>

&nbsp;&nbsp;&nbsp;&nbsp;file that specifies which files and directories can be ignored

<ins>.precli.toml</ins> or <ins>precli.toml</ins>
  
&nbsp;&nbsp;&nbsp;&nbsp;file that specifies custom configuration

<ins>pyproject.toml</ins>
  
&nbsp;&nbsp;&nbsp;&nbsp;standard Python configuration file where precli can read configuration

## **ENVIRONMENT**

DEBUG

  Set to any value to enabling debug logging.

GITHUB_TOKEN

  Set to your GitHub token. This is required to use the `--gist` argument.

## **EXIT STATUS**

The **precli** tool exits with one of the following values:

0&nbsp;&nbsp;&nbsp;&nbsp;No errors or results found  
1&nbsp;&nbsp;&nbsp;&nbsp;One or more results found  
2&nbsp;&nbsp;&nbsp;&nbsp;Incorrect command usage  

## **EXAMPLES**

Recursively analyze an entire project code tree:

    precli -r ~/your-repos/project

Analyze code passed as standard input:

    cat examples/imports.py | precli -

## **REPORTING BUGS**

Report issues at the following link: [https://github.com/securesauce/precli/issues](https://github.com/securesauce/precli/issues)

## **SEE ALSO**

<ins>pylint(1)</ins>
