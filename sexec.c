// Secure exec, with capabilities and chroot
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <linux/capability.h>
#include <sys/capability.h>
#include <inttypes.h>
#include <sys/types.h>
#include <pwd.h>

#define die(...) fprintf(stderr, __VA_ARGS__), exit(125)

char *usage="\
Secure exec - start a program with various security measures in place.\n\
Usage:\n\
\n\
    sexec [-r directory] [-c cap ...] [-e name=value ...] [-u username] [-s] -- /path/to/program [args ...]\n\
\n\
Where:\n\
\n\
    -r directory    Run program in specified chroot directory. Note the program\n\
                    path must be within and relative to the chroot.\n\
\n\
    -c cap          Grant root capability to the exec'd program. By default the\n\
                    program will have no capabilties. Capability names are\n\
                    listed in 'man capabilties', the leading 'CAP_'is optional\n\
                    and case is irrelevant. Can be used multiple times.\n\
\n\
    -e name[=value] Add entry to program's environment, which by default is\n\
                    empty. If the value is not provided then copy the value\n\
                    from the parent environment. Can be used up to 63 times.\n\
\n\
    -u username     Exec the program as specified user.\n\
\n\
    -s              Don't exec the program as session leader.\n\
\n\
In the event an error exit status is 125. Otherwise the exit status is that of\n\
the exec'd program (which could also be 125).\n\
";

#define NENV 64

int main(int argc, char *argv[])
{
    cap_t caps;
    char *root=NULL, *env[NENV];
    int nenv=0, uid=-1, gid=-1;
    int nolead=0;

    memset(env, 0, sizeof env);

    // get current caps, and clear inheritable
    if (!(caps=cap_get_proc())) die("cap_get_proc failed: %s\n", strerror(errno));
    if (cap_clear_flag(caps, CAP_INHERITABLE)) die("cap_clear failed\n");

    while(1) switch (getopt(argc, argv, ":r:c:e:u:s"))
    {
        case 'r':
        {
            struct stat st;
            root=optarg;
            if (stat(root, &st)) die("Unable to stat %s: %s\n", root, strerror(errno));
            if (!S_ISDIR(st.st_mode)) die("%s is not a directory\n", root);
            break;
        }

        case 'c':
        {
            cap_value_t n;
            if (cap_from_name(optarg, &n))
            {
                char *s;
                if (asprintf(&s, "CAP_%s", optarg) <=0) die("asprintf failed!\n");
                if (cap_from_name(s, &n)) die("%s is not a valid capability\n", optarg);
                free(s);
            }
            if (cap_set_flag(caps, CAP_INHERITABLE, 1, &n, CAP_SET)) die("cap_set_flag %d failed: %s\n", n, strerror(errno));
            break;
        }

        case 'e':
        {
            int n;
            if (nenv == NENV) die("Exceeded max %d env vars\n",NENV-1);
            // Must start with letter, then zero or more
            // letter/number/underscores
            n=0, sscanf(optarg, "%*[A-Za-z]%n",&n);
            if (optarg[n]) n=0, sscanf(optarg, "%*1[A-Za-z]%*[0-9A-Z0-9_]%n",&n);
            if (optarg[n]) 
            {
                // Possibly followed by '=' and arbitrary printable ascii
                n=0, sscanf(optarg, "%*[A-Za-z]=%*[ -~]%n",&n);
                if (optarg[n]) n=0, sscanf(optarg, "%*1[A-Za-z]%*[0-9A-Z0-9_]=%*[ -~]%n",&n);
                if (optarg[n]) die("Invalid env var '%s'\n", optarg);
                env[nenv++]=optarg;
            } else
            {
                // fetch existing value for optarg
                char *o=getenv(optarg);
                if (!o) die("No such env var '%s'\n", optarg);
                if (asprintf(&env[nenv++], "%s=%s", optarg, o) <= 0) die("asprintf failed!\n");
            }
            break;
        }

        case 'u':
        {
            struct passwd *p = getpwnam(optarg);
            if (!p) die("Unable to lookup up user %s: %s\n", optarg, strerror(errno));
            uid=p->pw_uid;
            gid=p->pw_gid;
            break;
        }

        case 's':
        {
            nolead=1;
            break;
        }

        default: die("Invalid option.\n");

        case ':': break;            // don't care about missing options
        case '?': die("%s", usage); // croak on illegal options
        case -1: goto optx;         // no more options
    } optx:

    if (optind >= argc) die("%s", usage);

    // Updated inherited caps
    if (cap_set_proc(caps)) die("cap_set_proc failed: %s\n", strerror(errno));

    // Now drop bounds for each uninheritable cap
    for (cap_value_t v=0; v <= CAP_LAST_CAP; v++)
    {
        cap_flag_value_t f;
        if (cap_get_flag(caps, v, CAP_INHERITABLE, &f)) f=0; // assume unsupported flags are not set
        if (!f && cap_drop_bound(v)) die("cap_drop bound %d failed: %s\n", v, strerror(errno));
    }
    cap_free(caps);

    // maybe become session leader
    if (!nolead) setsid(); // failure ok 

    // maybe chroot
    if (root && chroot(root)) die("chroot %s failed: %s\n", root, strerror(errno));

    // maybe su, note the uid should be set last
    if (gid >= 0 && setgid(gid)) die("can't set gid %d: %s\n", gid, strerror(errno));
    if (uid >= 0 && setuid(uid)) die("can't set uid %d: %s\n", uid, strerror(errno));

    // finally exec
    execve(argv[optind], &argv[optind], env);
    die("execve %s failed: %s\n", argv[optind], strerror(errno));
}
