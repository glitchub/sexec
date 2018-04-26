Secure exec, start a program with various security measures in place. Usage:

    sexec [-r directory] [-c cap ...] [-e name=value ...] [-u username] -- /path/to/program [args ...]

Where:

    -r directory    Run program in specified chroot directory. Note the program
                    path must be within and relative to the chroot.

    -c cap          Grant root capability to the exec'd program. By default the
                    program will have no capabilties. Capability names are
                    listed in 'man capabilties', the leading 'CAP_'is optional
                    and case is irrelevant. Can be used multiple times.

    -e name=value   Add entry to program's environment. By default the
                    program's environment is empty. Can be used up to 63 times.

    -u username     Exec the program as specified user.

In the event an error exit status is 125. Otherwise the exit status is that of
the exec'd program (which could also be 125).
