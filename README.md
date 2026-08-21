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

## Limitation
There is a limitation of the current implementation when the daemon process is killed.
In such case there is a potential risk that processes started inside a unipc-wrapped shell
continue to run in the old unipc namespaces but a new daemon creates new unipc
namespaces. This is only a problem for long-running processes like servers or daemons.
For such processes, avoid starting them without the unipc wrapper:
```bash
unipc bash
$ server
```
That is because unipc internally tracks all processes started with unipc but
it is not possible for unipc to track processes that were not started with the unipc wrapper.
unipc processes are not affected and a new daemon will join the unipc namespaces of any
surviving unipc process.
