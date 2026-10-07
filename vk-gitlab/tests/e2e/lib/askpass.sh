#!/bin/sh
# GIT_ASKPASS for gl_push: the user is in the URL, the password is root's token in $GL_PAT_FILE.
exec cat "$GL_PAT_FILE"
