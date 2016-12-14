import os
from dispatch import *

# Read in our executable
exe = read_executable('thing')
# ... and analyze it
exe.analyze()

# Find the main function (main for linux, _main for OS X)
main = exe.function_named('main') or exe.function_named('_main')

for i in main.instructions:
    # Find the first jne which happens to be the "winner" check
    if i.mnemonic == 'jne':
        ins = i
        exe.replace_at(i.address, '') # NOP it out
        exe.save('patched') # Save
        os.system("chmod +x patched") # and make the patched binary executable

        break
