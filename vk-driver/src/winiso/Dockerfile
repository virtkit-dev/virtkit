# The tools vk builds a Windows install medium with (winiso.rs): 7z reads the UDF ISO, wimlib
# splits install.wim and edits boot.wim, sgdisk/mtools lay out the FAT32 disk without root.
FROM debian:trixie
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      wimtools mtools gdisk p7zip-full msitools \
 && rm -rf /var/lib/apt/lists/*
