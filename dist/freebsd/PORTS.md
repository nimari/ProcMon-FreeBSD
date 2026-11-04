# FreeBSD ports preparation

The native application currently builds as version 2.2.2.1. The `port/` directory
is an **unfinished recipe**, not a submission-ready port. Its `MASTER_SITES` is
intentionally empty, and its distinfo describes an earlier local development
archive that is not a public release of this curated branch.

The maintained project is ProcMon-FreeBSD under GitHub account `nimari`. The
planned first public source release is 2.2.2.2. Until that release and packaging
validation are complete, build the application using
[the native instructions](../../docs/freebsd/APPLICATION.md).

## Requirements before submission

- Publish a fixed source archive from the reviewed FreeBSD branch as a GitHub
  Release asset. The archive must include its required licenses and notices.
- Set the recipe's public source/project URLs and maintainer to
  Abdulrahman Al-Nimari <alnimari@gmail.com>; regenerate distinfo from the exact
  downloaded release bytes with `make makesum`.
- Use ports-provided dependencies, honor build/staging/prefix settings and expose
  unprivileged unit tests and optional documentation through the framework.
- Restrict the initial support claim to FreeBSD 15.1 amd64. Check package/name
  conflicts, installed licenses, packing list, manual and dependency declarations.
- Run style checks, stage QA, packing-list checks and clean-jail poudriere tests
  with documentation enabled and disabled, including a custom-prefix build.
- Install through ports on the host and verify live capture, replay, terminal
  controls, permissions, package integrity and deinstallation.
- Produce a ports-tree patch including category registration, test logs and a
  Bugzilla submission description. FreeBSD maintainers decide acceptance.

Microsoft's original Linux archive does not include this community port and must
not be used as the FreeBSD distfile. The standalone `package.sh` script is for
the current bundled-library build; it does not replace framework package creation
or validation of a system-library build.

Current baseline results and limits are in
[VALIDATION.md](../../docs/freebsd/VALIDATION.md).

References: [Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/),
[port testing](https://docs.freebsd.org/en/books/porters-handbook/testing/),
and [new-port submission](https://docs.freebsd.org/en/books/porters-handbook/quick-porting/#porting-submitting).
