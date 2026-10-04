# A fleet node's guest: `vk` is shared in from the build under test, so this holds only what
# a test does to the node besides — nftables, to cut it off from the hub.
FROM docker.io/library/alpine:3.21
RUN apk add --no-cache nftables
