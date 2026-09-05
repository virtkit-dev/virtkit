# Extract one version's CHANGELOG section for the GitHub release body, from
# `## [<version>]` to the next section or the trailing link definitions for the
# oldest version. Pass -v v=X.Y.Z.
index($0, "## [" v "]") == 1 { on = 1; next }
on && (/^## \[/ || /^\[[^]]*\]: /) { exit }
on { print }
