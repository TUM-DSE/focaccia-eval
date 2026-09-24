{ pkgs, triggerPackages, triggers, paperTriggers }:
let
  python = pkgs.python3.withPackages (p: [ p.pyelftools ]);
  objdump = "${pkgs.pkgsCross.musl64.stdenv.cc.bintools}/bin/${pkgs.pkgsCross.musl64.stdenv.cc.targetPrefix}objdump";
  cases = pkgs.writeText "libc-trigger-contracts.json" (builtins.toJSON (
    builtins.map (id: {
      inherit id;
      binary = "${triggerPackages.${id}}/bin/reproducer-${id}";
      trigger = removeAttrs triggers.${id} [ "source" ];
      localization = paperTriggers."qemu-${id}";
    }) [ "2175" "1376" "1832422" ]
  ));
in
# Static ELF inspection only: no native target, debugger, RR or emulator required.
pkgs.runCommand "paper-trigger-libc-entry-context" { } ''
  ${python}/bin/python - ${cases} <<'PY'
  import json
  import subprocess
  import sys
  from elftools.elf.elffile import ELFFile

  def require(condition, message):
      if not condition:
          raise ValueError(message)

  for case in json.load(open(sys.argv[1])):
      name = case['id']
      with open(case['binary'], 'rb') as stream:
          elf = ELFFile(stream)
          symbols = {s.name: s for s in elf.get_section_by_name('.symtab').iter_symbols()}
          def address(name):
              return symbols[name]['st_value']
          def data(start, size):
              for segment in elf.iter_segments():
                  base = segment['p_vaddr']
                  if base <= start and start + size <= base + segment['p_filesz']:
                      return segment.data()[start-base:start-base+size]
              raise ValueError('Unmapped code range')
          start, stop = address('focaccia_trace_start'), address('focaccia_trace_stop')
          entry = address('focaccia_trigger')
          size = symbols['focaccia_trigger']['st_size']
          require(elf.header['e_entry'] == address('_start'), name + ': libc ELF entry')
          for symbol in ['_start_c', '__libc_start_main', '__init_libc', 'main']:
              require(address(symbol) != entry, name + ': missing distinct libc/main entry')
          require(not any(s['p_type'] == 'PT_INTERP' for s in elf.iter_segments()), 'not static')
          if name == '2175':
              require(stop - start == 5, name + ': exact witness range')
              # R8=1, R9D=0xedbf530a, PUSH 1/POPFQ; BLSI then capture low flags.
              prefix = bytes.fromhex('49c7c00100000041b90a53bfed6a019d')
              witness = bytes.fromhex('c4c238f3d9')
              suffix = bytes.fromhex('9c5825ff000000c3')
              require(case['trigger']['expectedNativeStatus'] == 3, 'BLSI status')
              loc = case['localization']
              require((loc['expectedMismatchSourceSymbol'], loc['expectedMismatchSourceOffset'],
                       loc['expectedMismatchLength'], loc['expectedMismatchSubject'],
                       loc['expectedMismatchCode']) ==
                      ('focaccia_trace_start', 0, 5, 'CF', 'register-content-mismatch'), 'BLSI localization')
          elif name == '1376':
              require(stop - start == 4, name + ': exact witness range')
              # Preserve RBX around the original register inputs and LSL witness.
              prefix = bytes.fromhex('5348b86a5a1f748e692ea048bbef0a7add9d952000')
              witness = bytes.fromhex('660f03c3')
              suffix = bytes.fromhex('31c05bc3')  # Return zero through libc.
              require(case['trigger']['expectedNativeStatus'] == 0, 'LSL status')
              loc = case['localization']
              require((loc['expectedFaultSymbol'], loc['expectedTerminalSignal']) ==
                      ('focaccia_trace_start', 'SIGSEGV'), 'LSL localization')
          else:
              require(stop - start == 5, name + ': exact witness range')
              prefix = bytes.fromhex('660fefc0')  # PXOR XMM0,XMM0
              witness = bytes.fromhex('660fc2c0d1')  # Preserve unused immediate bits.
              suffix = bytes.fromhex('31c0c3')  # Return zero through libc.
              require(case['trigger'].get('expectedNativeStatus', 0) == 0, 'CMPPD status')
              loc = case['localization']
              require((loc['expectedFaultSymbol'], loc['expectedTerminalSignal']) ==
                      ('focaccia_trace_start', 'SIGILL'), 'CMPPD localization')
          # Exact complete body also proves balanced stack and no callee-saved clobbers.
          require(start == entry + len(prefix), name + ': context offset')
          require(size == len(prefix + witness + suffix), name + ': function size')
          require(data(entry, size) == prefix + witness + suffix, name + ': context/body bytes')
          require(case['trigger']['freestanding'] is False, 'freestanding catalog drift')
          require(case['trigger']['sources'] == ['main.c', 'main.S'], 'source identity drift')
          disassembly = subprocess.check_output([
              '${objdump}', '-d', '--disassemble=main', case['binary']
          ], text=True)
          require('<focaccia_trigger>' in disassembly, name + ': main does not invoke witness')
          startup = subprocess.check_output([
              '${objdump}', '-d', '--disassemble=_start_c', case['binary']
          ], text=True)
          require('<__libc_start_main>' in startup, name + ': entry bypasses libc')
          require(hex(address('main'))[2:] in startup, name + ': startup does not supply main')
          libc_start = subprocess.check_output([
              '${objdump}', '-d', '--disassemble=__libc_start_main', case['binary']
          ], text=True)
          require('<__init_libc>' in libc_start, name + ': libc initialization bypassed')
          print(name, 'libc entry/main, exact context, ABI-safe return and localization verified')
  PY
  touch "$out"
''
