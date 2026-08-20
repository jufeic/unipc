# unipc

\[un\]share \[ipc\] namespace - a tool to execute programs in an isolated, per-user IPC namespace

## Installation

Build the executable:
```bash
make
```

Install to `/usr/local/bin`:
```bash
sudo make install
```

Install to custom location e.g. `$HOME/.local/bin`:
```bash
make install PREFIX=$HOME/.local
```

## Usage

All programs started with the unipc wrapper are running in the same isolated IPC namespace:
```bash
unipc <program> [args...]
```
Create a shell process to execute commands directly in the unipc namespaces:
```bash
unipc bash
```

## Overview
unipc allows to execute programs in a separate IPC namespace. To be exact, the
tool creates two new namespaces, a user and IPC namespace, called unipc namespaces.
The user namespace is needed to enable unprivileged users to create an IPC namespace.
The unipc namespaces are completely isolated from other users on the system.
This allows processes running in unipc namespaces to have an isolated view on the
System V IPC resources shared memory, message queues and semaphores and on
POSIX message queues.

Processes running in unipc namespaces still share the resources governed by the other 6
namespaces in Linux. By default, namespaces are destroyed when the last process
inside terminates. To prevent that, unipc runs a daemon process inside of the unipc namespaces
to keep them alive. unipc processes join the user and IPC namespace of the daemon and
then execute the specified program.

