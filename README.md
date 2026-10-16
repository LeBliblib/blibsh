BlibShell (BlibSH / BSH) is the final project for a course I took : "Rust Programming". It is a simplified SSH, built in Rust and relying on TLS.

After an authentication phase, BSH opens a bash process and manages its stdin, stdout and stderr. This way, the user can use a bash process remotely.

The current implementation works out correctly with simple commands (ls, cat, cd, ...) but will not work with interactive programs (e.g. vim).

BSH manages its own users and roles that are mapped on the os (Linux) users.
