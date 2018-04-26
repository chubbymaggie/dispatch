import dispatch

import logging, sys

if len(sys.argv) != 3:
    print "Usage: {} input_binary output_binary".format(sys.argv[0])
    sys.exit(1)


logging.basicConfig(level=logging.DEBUG)

# Load in the executable with read_executable (pass filename)
executable = dispatch.read_executable(sys.argv[1])

# Invoke the analyzer to find functions
executable.analyze()

# Prepare the executable for code injection
executable.prepare_for_injection()

instrumentation = '\xcc\xc3' # Sample x86 instrumentation - INT 3 (SIGTRAP), RET
instrumentation_vaddr = executable.inject(instrumentation)
logging.debug('Injected instrumentation asm at {}'.format(hex(instrumentation_vaddr)))

for function in executable.iter_functions():
    replaced_instruction = None
    for instruction in function.instructions:
        if instruction.size >= 5 \
                and not instruction.redirects_flow() \
                and not instruction.references_sp() \
                and not instruction.references_ip():
            logging.debug('In {} - Found candidate replacement instruction at {}: {} {}'
                          .format(function, hex(instruction.address), instruction.mnemonic, instruction.op_str()))

            replaced_instruction = instruction
            break

    if not replaced_instruction:
        logging.warning('Could not find instruction to replace in {}'.format(function))
    else:
        # Given a candidate instruction, replace it with a call to a new "function" that contains just that one
        # instruction and a jmp to the instrumentation code.

        hook_addr = executable.hook(replaced_instruction.address, 'jmp {}'.format(instrumentation_vaddr))
        logging.info('Replaced instruction at address {} to call hook at {}'.format(hex(replaced_instruction.address),
                                                                                    hex(hook_addr)))

executable.save(sys.argv[2])
