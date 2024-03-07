Target 1 for the NASA combined challenge problem is a testbed developed at NASA GSFC that simulates the relay behavior of a lunar comm sat, with its primary compute powered by a TWR-P1025 QorIQ P1 MPU Tower System Module (https://www.nxp.com/docs/en/user-guide/TWR-P1025HUG.pdf).

The P1 provides a Linux Board Support Package (BSP) and runs the NASA core Flight System (cFS) flight software on top of a stripped-down Linux environment optimized for flight systems. The P1 hosts a dual-core PowerPC e500 CPU operating up to 533 MHz, with 512MB DDR3 RAM and 64MB NAND Flash memory.

The flight system leverages uBoot as the bootloader, which starts a Linux Kernel containing an embedded rootfs CPIO archive that contains the OS and main cFS Flight Software binary 32-bit ELF executable (core-cpu1). Note that binaries for this architecture show up as a shared object due to the PowerPC compiler inherently making segments within the binary relocatable within RAM.

The primary application is cpu1/core-cpu1, which is the main cFS application. cFS then loads a series of modules based on the cpu1/cf/cfe_es_startup.scr table, which are considered "apps" and each run in their own thread.

The "app" that requires patching is the Rover Relay app, or "rr.so." The entry point when the module is loaded is RR_Main(), which initializes the data structures and sets up interfaces to the main Flight Software via RR_Init(). State data is stored as a single instantiation of a global struct that is local to this module/thread.

The function that receives data from the JPL Lunar Rover is RR_ReadTlm_Input() (it is called by the event loop in RR_Main() and either receives between 0 and 10 UDP datagrams containing Space Packet Protocol packets of data (if queued up), or no data and exits.

The 6-byte CCSDS Primary Header (which follows this format, and is always going to be the first 6 bytes in the UDP packet payload after the UDP header):
2-Byte Big-Endian Bitfield:
  version (3 bits)
  type (1 bit)
  secondary header flag (1 bit)
  application identifier--AppID (11 bits)
2-Byte Big-Endian Bitfield:
  grouping (2 bits)
  sequence counter (14 bits)
2-Byte Big-Endian Short Unsigned Integer:
  length (16 bits)

The Length is computed by taking the total payload of the UDP packet (6-byte CCSDS header + any payload bytes) and subtracting the CCSDS header, and subtracting an additional 1. This allows for a maximum packet data payload of 65536 by setting the length=0xFFFF.

Because the application inherently trusts the data coming from the rover, it is not ensuring that the length field in the CCSDS packet is correct, and the Rover seems to have a bug in it where it is not always calculating the length field correctly. Unfortunately packets with an invalid length are causing the relay application to crash.

One fix might be to just throw away a packet if the length field doesn't equal the UDP payload length - 6 - 1. Unfortunately this will result in rover packets that are malformed being dropped. This migth be okay? Ask JPL :-)

Alternatively, you could re-write the length field by taking the UDP packet length, subtracting 7 and then jamming that as a big-endian unsigned integer into byte offsets 4 and 5 in the packet (starting from 0).

An example valid (but empty) packet with ApplicationID=0x400 or 1024 (which is the AppID the rover telemetry will be using) can be generated via:
echo -n "0400 0000 0011 00" | xxd -p -r | socat - udp:localhost:4000
Note that CCSDS requires every packet to have at least 1 byte of packet payload (hence length=0 is 1 byte of payload + 6 bytes of header).

Good luck!!

cFS Binary information:
core-cpu1: ELF 32-bit MSB executable, PowerPC or cisco 4500, version 1 (SYSV), dynamically linked, interpreter /lib/ld.so.1, for GNU/Linux 2.6.32, BuildID[sha1]=282a0123f17248eb054f1583b226ea29d31ccea8, with debug_info, not stripped
cf/rr.so: ELF 32-bit MSB shared object, PowerPC or cisco 4500, version 1 (SYSV), dynamically linked, BuildID[sha1]=20f328782ab207c2706a2c122da0619644d39816, with debug_info, not stripped

