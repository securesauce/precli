# precli

## SYNOPSIS

```
precli [-h] [-d] [-r] [--enable ENABLE | --disable DISABLE] [--json | --plain | --markdown]
       [--gist] [-o OUTPUT] [--no-color] [-q] [--version]
       [targets ...]
```

## DESCRIPTION

`precli` is a tool designed to find security issues in code. It finds issues
such as injection, weak hashes, cleartext transmission of data, timing
attacks, weak encryption, deserialization of untrusted data, improper
certificate validation, and more.

## OPTIONS

```
  -h, --help            show this help message and exit
  -d, --debug           turn on debug mode
  -r, --recursive       find and process files in subdirectories
  --enable ENABLE       comma-separated list of rule IDs or names to enable
  --disable DISABLE     comma-separated list of rule IDs or names to disable
  --json                render the output as formatted JSON
  --plain               render the output in plain, tabular text
  --markdown            render the output in markdown format
  --gist                output the results to Gist
  -o OUTPUT, --output OUTPUT
                        output the results to a file
  --no-color            do not display color in output
  -q, --quiet           quiet mode, display less output
  --version             show program's version number and exit
```

## FILES

.preignore
  file that specifies which files and directories can be ignored

## ENVIRONMENT VARIABLES

DEBUG

  Set to any value to enabling debug logging.

GITHUB_TOKEN

  Set to your GitHub token. This is required to use the `--gist` argument.

## EXAMPLES

Example usage across a code tree::

    precli -r ~/your-repos/project

Precli supports passing lines of code to scan using standard input. To
run Precli with standard input::

    cat examples/imports.py | precli -

## REPORTING BUGS

Report issues at the following link: [https://github.com/securesauce/precli/issues](https://github.com/securesauce/precli/issues)

## SEE ALSO

`pylint(1)`
