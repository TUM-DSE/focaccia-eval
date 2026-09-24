{ focaccia, lib }:

let
  triggers = {
    "364" = {
      id = "364";
      guestIsa = "aarch64";
      instruction = "LDSMAXB";
      category = "computation";
      source = ../triggers/364;
      sources = [ "main.c" ];
      cflags = [ "-march=armv8.1-a+lse" ];
      freestanding = false;
      expected = "The old byte value and memory remain 3 for signed max(-1, 3).";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/364";
    };
    "508" = {
      id = "508";
      guestIsa = "x86_64";
      instruction = "CMPXCHG";
      category = "computation";
      source = ../triggers/508;
      sources = [ "main.c" ];
      cflags = [ ];
      freestanding = false;
      expected = "Successful 32-bit CMPXCHG preserves the high 32 bits of RAX.";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/508";
    };
    "508-box64" = {
      id = "508-box64";
      guestIsa = "x86_64";
      instruction = "CMPXCHG";
      category = "computation";
      source = ../triggers/508-box64;
      sources = [ "main.c" ];
      cflags = [ ];
      freestanding = false;
      expected = "Successful register CMPXCHG preserves the high 32 bits of RAX.";
      provenance = "https://github.com/ptitSeb/box64/commit/70ab16a6d6c54c83a6f9f678c5bbe1c104c6a672";
    };
    "1370" = {
      id = "1370";
      guestIsa = "x86_64";
      instruction = "BLSI/BLSR";
      category = "flags";
      source = ../triggers/1370;
      sources = [ "main.c" ];
      cflags = [ "-mbmi" ];
      freestanding = false;
      expected = "BLSI(1) sets CF; BLSR(1) clears CF.";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/1370";
    };
    "1371" = {
      id = "1371";
      guestIsa = "x86_64";
      instruction = "BLSMSK";
      category = "flags";
      source = ../triggers/1371;
      sources = [ "main.c" ];
      cflags = [ "-mbmi" ];
      freestanding = false;
      expected = "BLSMSK with a nonzero source clears CF.";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/1371";
    };
    "1372" = {
      id = "1372";
      guestIsa = "x86_64";
      instruction = "BEXTR";
      category = "computation";
      source = ../triggers/1372;
      sources = [ "main.c" ];
      cflags = [ "-mbmi" ];
      freestanding = false;
      expected = "The extracted 32-bit value is 0x5a.";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/1372";
    };
    "1374" = {
      id = "1374";
      guestIsa = "x86_64";
      instruction = "BZHI";
      category = "computation";
      source = ../triggers/1374;
      sources = [ "main.c" ];
      cflags = [ "-mbmi2" ];
      freestanding = false;
      expected = "An out-of-range index preserves 0x80000000ffffffff and sets SF.";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/1374";
    };
    "1375" = {
      id = "1375";
      guestIsa = "x86_64";
      instruction = "ADDSUBPS";
      category = "vector";
      source = ../triggers/1375;
      sources = [ "main.c" ];
      cflags = [ "-msse3" ];
      freestanding = false;
      expected = "NaN propagation preserves the expected 0xffffffff lane.";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/1375";
    };
    "1828867" = {
      id = "1828867";
      guestIsa = "x86_64";
      instruction = "REX.LAHF";
      category = "computation";
      source = ../triggers/1828867;
      sources = [ "main.S" ];
      cflags = [ ];
      freestanding = true;
      expected = "A redundant REX prefix does not redirect the AH write to SPL.";
      provenance = "https://bugs.launchpad.net/qemu/+bug/1828867";
    };
    "2175" = {
      id = "2175";
      guestIsa = "x86_64";
      expectedNativeStatus = 3;
      instruction = "BLSI";
      category = "flags";
      source = ../triggers/2175;
      sources = [ "main.c" "main.S" ];
      cflags = [ "-mbmi" ];
      freestanding = false;
      expected = "The low RFLAGS byte after BLSI is 3, not 2.";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/2175";
    };
    "2495" = {
      id = "2495";
      guestIsa = "x86_64";
      instruction = "REX.MOVQ MMX";
      category = "vector";
      source = ../triggers/2495;
      sources = [ "main.c" ];
      cflags = [ "-mmmx" ];
      freestanding = false;
      expected = "MOVQ with redundant REX bits copies all-ones MM0 into R8.";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/2495";
    };
    "1861404" = {
      id = "1861404";
      guestIsa = "x86_64";
      instruction = "VMOVDQU YMM";
      category = "vector";
      source = ../triggers/1861404;
      sources = [ "main.c" ];
      cflags = [ "-mavx" ];
      freestanding = false;
      nativeCaptureTransport = "gdbserver";
      expected = "A 32-byte YMM round trip preserves all bytes.";
      provenance = "https://bugs.launchpad.net/qemu/+bug/1861404";
    };
    "1376" = {
      id = "1376";
      guestIsa = "x86_64";
      expectedNativeStatus = 0;
      instruction = "LSL";
      category = "crash";
      source = ../triggers/1376;
      sources = [ "main.c" "main.S" ];
      cflags = [ ];
      freestanding = false;
      expected = "An inaccessible segment descriptor clears ZF without a SIGSEGV.";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/1376";
    };
    "1377" = {
      id = "1377";
      guestIsa = "x86_64";
      instruction = "CVTPS2PD";
      category = "crash";
      source = ../triggers/1377;
      sources = [ "main.c" ];
      cflags = [ "-msse2" ];
      freestanding = false;
      expected = "CVTPS2PD reads only eight source bytes at a page boundary.";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/1377";
    };
    "1832422" = {
      id = "1832422";
      guestIsa = "x86_64";
      instruction = "CMPPD";
      category = "crash";
      source = ../triggers/1832422;
      sources = [ "main.c" "main.S" ];
      cflags = [ "-msse2" ];
      freestanding = false;
      expected = "CMPPD masks unused immediate bits instead of raising SIGILL.";
      provenance = "https://bugs.launchpad.net/qemu/+bug/1832422";
    };
    "2248" = {
      id = "2248";
      guestIsa = "aarch64";
      instruction = "LSR optimization sequence";
      category = "optimization";
      source = ../triggers/2248;
      sources = [
        "main.c"
        "callme.S"
      ];
      cflags = [ "-march=armv8-a" ];
      freestanding = false;
      expected = "The complete basic block returns -1.";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/2248";
    };
    "2419" = {
      id = "2419";
      guestIsa = "aarch64";
      instruction = "LDAPUR";
      category = "memory";
      source = ../triggers/2419;
      sources = [ "main.c" ];
      cflags = [ "-march=armv8.4-a" ];
      freestanding = false;
      expected = "The signed -8 immediate loads the preceding 64-bit value.";
      provenance = "https://gitlab.com/qemu-project/qemu/-/issues/2419";
    };
  };

  emulatorVariants = {
    "qemu-4-0-0" = {
      emulator = "qemu";
      version = "4.0.0";
      upstreamRevision = "131b9a05705636086699df15d4a6d328bb2585e8";
      nixpkgsRevision = "80bda4933272f7e244dc9702f39d18433988cdd0";
      input = "nixpkgs-qemu-4-0-0";
    };
    "qemu-4-2-0" = {
      emulator = "qemu";
      version = "4.2.0";
      upstreamRevision = "b0ca999a43a22b38158a222233d3f5881648bb4f";
      nixpkgsRevision = "2738ca86bd623934d816bef90f1867002c119950";
      input = "nixpkgs-qemu-4-2-0";
    };
    "qemu-5-2-0" = {
      emulator = "qemu";
      version = "5.2.0";
      upstreamRevision = "553032db17440f8de011390e5a1cfddd13751b0b";
      nixpkgsRevision = "a78ed5cbdd5427c30ca02a47ce6cccc9b7d17de4";
      input = "nixpkgs-qemu-5-2-0";
    };
    "qemu-6-1-0" = {
      emulator = "qemu";
      version = "6.1.0";
      upstreamRevision = "f9baca549e44791be0dd98de15add3d8452a8af0";
      nixpkgsRevision = "f76bef61369be38a10c7a1aa718782a60340d9ff";
      input = "nixpkgs-qemu-6-1-0";
    };
    "qemu-7-2-0" = {
      emulator = "qemu";
      version = "7.2.0";
      upstreamRevision = "b67b00e6b4c7831a3f5bc684bc0df7a9bfd1bd56";
      nixpkgsRevision = "1b7a6a6e57661d7d4e0775658930059b77ce94a4";
      input = "nixpkgs-qemu-7-2-0";
    };
    "qemu-8-0-0" = {
      emulator = "qemu";
      version = "8.0.0";
      upstreamRevision = "c1eb2ddf0f8075faddc5f7c3d39feae3e8e9d6b4";
      nixpkgsRevision = "a64b73e07d4aa65cfcbda29ecf78eaf9e72e44bd";
      input = "nixpkgs-qemu-8-0-0";
    };
    "qemu-8-1-3" = {
      emulator = "qemu";
      version = "8.1.3";
      upstreamRevision = "179cc58e00eab7497ce0ac3a1897ec4878588a15";
      nixpkgsRevision = "4db6d0ab3a62ea7149386a40eb23d1bd4f508e6e";
      input = "nixpkgs-qemu-8-1-3";
    };
    "qemu-8-2-0" = {
      emulator = "qemu";
      version = "8.2.0";
      upstreamRevision = "1600b9f46b1bd08b00fe86c46ef6dbb48cbe10d6";
      nixpkgsRevision = "7a339d87931bba829f68e94621536cad9132971a";
      input = "nixpkgs-qemu-8-2-0";
    };
    "qemu-8-2-1" = {
      emulator = "qemu";
      version = "8.2.1";
      upstreamRevision = "f48c205fb42be48e2e47b7e1cd9a2802e5ca17b0";
      nixpkgsRevision = "336eda0d07dc5e2be1f923990ad9fdb6bc8e28e3";
      input = "nixpkgs-qemu-8-2-1";
    };
    "qemu-9-0-0" = {
      emulator = "qemu";
      version = "9.0.0";
      upstreamRevision = "c25df57ae8f9fe1c72eee2dab37d76d904ac382e";
      nixpkgsRevision = "3f878c71e15b53d8f817bb7aa95b5dce1b1071e1";
      input = "nixpkgs-qemu-9-0-0";
    };
    "box64-0-3-8" = {
      emulator = "box64";
      version = "0.3.8";
      upstreamRevision = "81c56d7155cdd7a4c49173a2fe4d7bdd87698683";
      fixedByRevision = "70ab16a6d6c54c83a6f9f678c5bbe1c104c6a672";
      regressionPatch = ../emulators/patches/box64-cmpxchg-zero-extension.patch;
      nixpkgsRevision = "9fea8b5c5dbd756dd84c2c4c22430c896fd9a8a4";
      input = "nixpkgs-box64-0-3-8";
    };
    "box64-0-3-8-reference" = {
      emulator = "box64";
      version = "0.3.8";
      upstreamRevision = "81c56d7155cdd7a4c49173a2fe4d7bdd87698683";
      nixpkgsRevision = "9fea8b5c5dbd756dd84c2c4c22430c896fd9a8a4";
      input = "nixpkgs-box64-0-3-8";
    };
  };

  paperTriggers = {
    "qemu-364" = {
      trigger = "364";
      emulator = "qemu-5-2-0";
      expectedMismatchSourceSymbol = "focaccia_trace_start";
      expectedMismatchSourceOffset = 0;
      expectedMismatchLength = 4;
      expectedMismatchCode = "memory-content-mismatch";
    };
    "qemu-508" = {
      trigger = "508";
      emulator = "qemu-6-1-0";
      expectedMismatchSourceSymbol = "focaccia_trace_start";
      expectedMismatchSourceOffset = 0;
      expectedMismatchLength = 5;
      expectedMismatchCode = "register-content-mismatch";
      expectedMismatchSubject = "RAX";
    };
    "box64-508" = {
      trigger = "508-box64";
      emulator = "box64-0-3-8";
    };
    "qemu-1372" = {
      trigger = "1372";
      emulator = "qemu-7-2-0";
      expectedMismatchSourceSymbol = "focaccia_trace_start";
      expectedMismatchSourceOffset = 30;
      expectedMismatchLength = 5;
      expectedMismatchCode = "register-content-mismatch";
      expectedMismatchSubject = "RAX";
    };
    "qemu-1374" = {
      trigger = "1374";
      emulator = "qemu-7-2-0";
      expectedMismatchSourceSymbol = "focaccia_trace_start";
      expectedMismatchSourceOffset = 0;
      expectedMismatchLength = 5;
      expectedMismatchCode = "register-content-mismatch";
      expectedMismatchSubject = "RAX";
    };
    "qemu-1828867" = {
      trigger = "1828867";
      emulator = "qemu-4-0-0";
      expectedMismatchSourceSymbol = "focaccia_trace_start";
      expectedMismatchSourceOffset = 0;
      expectedMismatchLength = 2;
      expectedMismatchCode = "register-content-mismatch";
      expectedMismatchSubject = "RAX";
    };
    "qemu-1370" = {
      trigger = "1370";
      emulator = "qemu-7-2-0";
      expectedMismatchSourceSymbol = "focaccia_trace_start";
      expectedMismatchSourceOffset = 0;
      expectedMismatchLength = 5;
      expectedMismatchCode = "register-content-mismatch";
      expectedMismatchSubject = "CF";
    };
    "qemu-1371" = {
      trigger = "1371";
      emulator = "qemu-7-2-0";
      expectedMismatchSourceSymbol = "focaccia_trace_start";
      expectedMismatchSourceOffset = 23;
      expectedMismatchLength = 5;
      expectedMismatchCode = "register-content-mismatch";
      expectedMismatchSubject = "CF";
    };
    "qemu-2175" = {
      trigger = "2175";
      emulator = "qemu-8-2-0";
      expectedMismatchSourceSymbol = "focaccia_trace_start";
      expectedMismatchSourceOffset = 0;
      expectedMismatchLength = 5;
      expectedMismatchCode = "register-content-mismatch";
      expectedMismatchSubject = "CF";
    };
    "qemu-1375" = {
      trigger = "1375";
      emulator = "qemu-7-2-0";
      expectedMismatchSourceSymbol = "focaccia_trace_start";
      expectedMismatchSourceOffset = 0;
      expectedMismatchLength = 4;
      expectedMismatchCode = "register-content-mismatch";
      expectedMismatchSubject = "XMM1";
    };
    "qemu-2495" = {
      trigger = "2495";
      emulator = "qemu-9-0-0";
      expectedMismatchSourceSymbol = "focaccia_trace_start";
      expectedMismatchSourceOffset = 0;
      expectedMismatchLength = 4;
      expectedMismatchCode = "register-content-mismatch";
      expectedMismatchSubject = "R8";
    };
    "qemu-1861404" = {
      trigger = "1861404";
      emulator = "qemu-4-2-0";
      validationCutpoint = "stop";
      expectedMismatchSourceSymbol = "focaccia_trace_start";
      expectedMismatchSourceOffset = 0;
      # The cutpoint composes the YMM load/store witness into one transition.
      expectedMismatchLength = 8;
      expectedMismatchCode = "memory-content-mismatch";
    };
    "qemu-1376" = {
      trigger = "1376";
      emulator = "qemu-7-2-0";
      expectedTerminalSignal = "SIGSEGV";
      expectedFaultSymbol = "focaccia_trace_start";
    };
    "qemu-1377" = {
      trigger = "1377";
      emulator = "qemu-8-0-0";
      expectedTerminalSignal = "SIGSEGV";
      expectedFaultSymbol = "focaccia_trace_start";
    };
    "qemu-1832422" = {
      trigger = "1832422";
      emulator = "qemu-4-0-0";
      expectedTerminalSignal = "SIGILL";
      expectedFaultSymbol = "focaccia_trace_start";
    };
    "qemu-2248" = {
      trigger = "2248";
      emulator = "qemu-8-2-1-plugin";
      expectedMismatchSourceSymbol = "focaccia_expected_mismatch";
      expectedMismatchSubject = "X0";
    };
    "qemu-2419" = {
      trigger = "2419";
      emulator = "qemu-8-1-3";
      expectedMismatchSourceSymbol = "focaccia_trace_start";
      expectedMismatchSourceOffset = 0;
      expectedMismatchLength = 4;
      expectedMismatchCode = "register-content-mismatch";
      expectedMismatchSubject = "X0";
      qemuCpuModel = "neoverse-v1";
    };
  };

  publicTriggers = lib.mapAttrs (_: trigger: builtins.removeAttrs trigger [ "source" ]) triggers;
  publicEmulators = lib.mapAttrs (
    _: emulator:
    builtins.removeAttrs emulator [
      "input"
      "regressionPatch"
    ]
  ) emulatorVariants;
  catalog = {
    schema = "focaccia-trigger-catalog-v1";
    authority = "Veritas paper Table 2";
    focaccia = {
      upstream = "https://github.com/TUM-DSE/focaccia";
      branch = "main";
      revision = focaccia.rev or null;
    };
    triggers = publicTriggers;
    emulators = publicEmulators;
    paperTriggers = paperTriggers;
    supportStatus = "packages-only; paper validation checks pending";
  };

in
{
  inherit
    catalog
    emulatorVariants
    paperTriggers
    publicEmulators
    publicTriggers
    triggers
    ;
}
