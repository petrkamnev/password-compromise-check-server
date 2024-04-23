#!/bin/bash

# First argument is the command (import-values or run-server)
COMMAND=$1
shift

if [ "$COMMAND" = "import-values" ]; then
    /app/bazel-bin/cmd/pccserver/pccserver $COMMAND "$@"
elif [ "$COMMAND" = "run-server" ]; then
    /app/bazel-bin/cmd/pccserver/pccserver $COMMAND "$@"
else
    echo "Unknown command: $COMMAND"
    echo "Expected 'import-storage' or 'run-server'"
    exit 1
fi
