MAX_STEPS = 10000

def get_file_name():
    where_str = gdb.execute("frame 0", from_tty=False, to_string=True)
    file_line = where_str.splitlines()[0].split()[-1]
    filename, _, line = file_line.rpartition(":")
    #int(line)
    return filename

def step_until_file(target):
    orig_file_name = get_file_name()
    current_file_name = orig_file_name
    counter = 0
    for x in range(MAX_STEPS):
        gdb.execute("step", from_tty=True, to_string=True)
        counter += 1
        current_file_name = get_file_name()
        if current_file_name != orig_file_name:
            #print("%s: %30s, %s: %s %s" % ("new", current_file_name, "steps", counter, target))
            orig_file_name = current_file_name
        if current_file_name.split('/')[-1] == target:
            break

class UntilFile(gdb.Command):
    """step until a line in a named file is reached"""

    def __init__(self):
        gdb.Command.__init__(self, "ufile", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        #gdb.execute("set logging redirect on", from_tty=False, to_string=True)
        #gdb.execute("set logging file /dev/null", from_tty=False, to_string=True)
        step_until_file(arg)
        #gdb.execute("set logging off", from_tty=False, to_string=True)

class NextFile(gdb.Command):
    """step until a new line in the current file is reached"""

    def __init__(self):
        gdb.Command.__init__(self, "nfile", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        if arg:
            count = int(arg)
        else:
            count = 1
        current_file_name = get_file_name()
        for i in range(count):
            for x in range(MAX_STEPS):
                gdb.execute("next", from_tty=False, to_string=True)
                if (get_file_name() == current_file_name):
                    break

class StepFile(gdb.Command):
    """step until a new line in the current file is reached"""

    def __init__(self):
        gdb.Command.__init__(self, "sfile", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        if arg:
            count = int(arg)
        else:
            count = 1
        current_file_name = get_file_name()
        for i in range(count):
            for x in range(MAX_STEPS):
                gdb.execute("step", from_tty=False, to_string=True)
                if (get_file_name() == current_file_name):
                    break

UntilFile()
NextFile()
StepFile()
