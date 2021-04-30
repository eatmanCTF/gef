class Hexdump32Command(HexdumpCommand):
    """Display SIZE lines of hexdump from the memory location pointed by ADDRESS."""

    _cmdline_ = "Hexdump32Command is only prefix"

    def _hexdump(self, start_addr, length, arrange_as, offset=0):
        endianness = endian_str()

        base_address_color = get_gef_setting("theme.dereference_base_address")
        show_ascii = get_gef_setting("hexdump.always_show_ascii")

        formats = {
            "qword": ("Q", 8),
            "dword": ("I", 4),
            "word": ("H", 2),
        }

        r, l = formats[arrange_as]
        vals_per_line = current_arch.ptrsize * 2 // l
        line_count = length // vals_per_line
        fmt_str = "{{base}}{v}+{{offset:#06x}}   {{sym}}{{val}}   {{text}}".format(
            v=VERTICAL_LINE)
        fmt_pack = endianness + r
        lines = []

        i = 0
        while i < line_count:
            round_offset = (i * vals_per_line + offset) * l
            round_addr = start_addr + round_offset
            val_str = ""
            text = ""
            text_str = []
            if show_ascii:
                text += "|"
            for j in range(vals_per_line):
                cur_addr = start_addr + (i * vals_per_line + j + offset) * l
                mem = read_memory(cur_addr, l)
                if show_ascii:
                    text_str.append("".join(
                        [chr(b) if 0x20 <= b < 0x7F else "." for b in mem]))
                val = struct.unpack(fmt_pack, mem)[0]
                val_str += "{{val:#0{prec}x}} ".format(prec=l * 2 +
                                                       2).format(val=val)
            sym = gdb_get_location_from_symbol(round_addr)
            sym = "<{:s}+{:04x}> ".format(*sym) if sym else ""
            if show_ascii:
                text += " ".join(text_str)
                text += "|"
            lines.append(
                fmt_str.format(base=Color.colorify(format_address(round_addr),
                                                   base_address_color),
                               offset=round_offset,
                               sym=sym,
                               val=val_str,
                               text=text))
            i += 1
        return lines


class Hexdump32RVACommand(Hexdump32Command):
    _cmdline_ = "Hexdump32RVACommand is only prefix"

    @only_if_gdb_running
    def do_invoke(self, argv):
        if not self.format:
            err("Incomplete command")
            return

        fmt = self.format
        target = ""
        valid_formats = ["byte", "word", "dword", "qword"]
        read_len = None
        reverse = False
        base_filepath = ""

        opts, args = getopt.getopt(argv, "f:")
        for o, a in opts:
            if o == "-f": base_filepath = a
        for arg in args:
            arg_lower = arg.lower()
            if "reverse".startswith(arg_lower):
                reverse = True
                continue
            if arg_lower.startswith("l") or target:
                if arg_lower.startswith("l"):
                    arg_lower = arg_lower[1:]
                if read_len:
                    self.usage()
                    return
                read_len = int(arg_lower, 0)
                continue
            target = arg

        if not target:
            target = "$sp"

        start_addr = to_unsigned_long(gdb.parse_and_eval(
            target)) + RVACommand.base_address(base_filepath)
        read_from = align_address(start_addr)
        if not read_len:
            read_len = 0x40 if fmt == "byte" else 0x10

        if fmt == "byte":
            read_from += self.repeat_count * read_len
            mem = read_memory(read_from, read_len)
            lines = hexdump(mem, base=read_from).splitlines()
        else:
            lines = self._hexdump(read_from, read_len, fmt,
                                  self.repeat_count * read_len)

        if reverse:
            lines.reverse()

        gef_print("\n".join(lines))
        return


class DumpQwordCommand(Hexdump32Command):
    """Display SIZE lines of hexdump as QWORD from the memory location pointed by ADDRESS."""

    _cmdline_ = "dq"
    _syntax_ = "{:s} [ADDRESS] [[L][SIZE]] [REVERSE]".format(_cmdline_)
    _example_ = "{:s} $rsp L16 REVERSE".format(_cmdline_)

    def __init__(self):
        super(HexdumpCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)  #pylint: disable=bad-super-call
        self.format = "qword"
        return


class DumpDwordCommand(Hexdump32Command):
    """Display SIZE lines of hexdump as DWORD from the memory location pointed by ADDRESS."""

    _cmdline_ = "dd"
    _syntax_ = "{:s} [ADDRESS] [[L][SIZE]] [REVERSE]".format(_cmdline_)
    _example_ = "{:s} $rsp L16 REVERSE".format(_cmdline_)

    def __init__(self):
        super(HexdumpCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)  #pylint: disable=bad-super-call
        self.format = "dword"
        return


class DumpWordCommand(Hexdump32Command):
    """Display SIZE lines of hexdump as WORD from the memory location pointed by ADDRESS."""

    _cmdline_ = "dw"
    _syntax_ = "{:s} [ADDRESS] [[L][SIZE]] [REVERSE]".format(_cmdline_)
    _example_ = "{:s} $rsp L16 REVERSE".format(_cmdline_)

    def __init__(self):
        super(HexdumpCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)  #pylint: disable=bad-super-call
        self.format = "word"
        return


class DumpByteCommand(Hexdump32Command):
    """Display SIZE lines of hexdump as BYTE from the memory location pointed by ADDRESS."""

    _cmdline_ = "db"
    _syntax_ = "{:s} [ADDRESS] [[L][SIZE]] [REVERSE]".format(_cmdline_)
    _example_ = "{:s} $rsp L16 REVERSE".format(_cmdline_)

    def __init__(self):
        super(HexdumpCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)  #pylint: disable=bad-super-call
        self.format = "byte"
        return


class RVACommand(GenericCommand):
    """Calculate the relative offset of the address."""
    _cmdline_ = "rva"
    _syntax_ = "{:s} [ADDRESS] [FILENAME]".format(_cmdline_)

    def __init__(self):
        super(RVACommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting(
            "base_filepath", "",
            "The file corresponding to the base address used to calculate the RVA."
        )

    @staticmethod
    def base_address(path=""):
        cfg_base_filepath = get_gef_setting("rva.base_filepath")
        if not cfg_base_filepath:
            set_gef_setting("rva.base_filepath", get_filepath())
        cfg_base_filepath = get_gef_setting("rva.base_filepath")
        base_filepath = path if path else get_gef_setting("rva.base_filepath")
        match = None
        first_match = None
        first_match_path = ""
        for x in get_process_maps():
            if x.path == base_filepath:
                match = x.page_start
                break
            elif base_filepath in x.path and first_match is None:
                first_match = x.page_start
                first_match_path = x.path
        if match is not None:
            return match
        if first_match is not None:
            ok("Found first match module {:s}".format(first_match_path))
            return first_match
        elif not path:
            warn("Not a valid module name")
            return 0
        else:
            warn("Not a valid module name, using {:s}".format(
                get_gef_setting("rva.base_filepath")))
            return RVACommand.base_address("")

    @staticmethod
    def base_address_autofind(addr):
        module_path = ""
        for x in get_process_maps():
            if x.path != module_path and x.path:
                module_path = x.path
            if addr >= x.page_start and addr <= x.page_end:
                if x.path:
                    module_path = x.path
                break
        base_address = [
            x.page_start for x in get_process_maps() if x.path == module_path
        ][0]
        ok("Found match module {:s} (base: {:#x})".format(
            module_path, base_address))
        return base_address

    def do_invoke(self, argv):
        if len(argv) < 1:
            self.usage()
            return
        addr = int(gdb.parse_and_eval(argv[0]))
        if len(argv) > 1:
            base_address = RVACommand.base_address(argv[1])
        else:
            base_address = RVACommand.base_address_autofind(addr)
        gef_print("{:#x}".format(addr - base_address))


class VACommand(GenericCommand):
    """Get address by relative offset."""
    _cmdline_ = "va"
    _syntax_ = "{:s} [RVA] [FILENAME]".format(_cmdline_)

    def do_invoke(self, argv):
        if len(argv) < 1:
            self.usage()
            return
        offset = int(gdb.parse_and_eval(argv[0]))
        base_address = RVACommand.base_address(
            argv[1] if len(argv) > 1 else "")
        gef_print("{:#x}".format(offset + base_address))


class BreakRVACommand(PieBreakpointCommand):
    """Set a PIE breakpoint."""

    _cmdline_ = "brva"
    _syntax_ = "{:s} BREAKPOINT [FILENAME] [CONDITION]".format(_cmdline_)

    def __init__(self):
        super(BreakRVACommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.format = None
        return

    def do_invoke(self, argv):
        global __pie_counter__, __pie_breakpoints__
        if len(argv) < 1:
            self.usage()
            return
        bp_expr = argv[0]
        base_filepath = argv[1] if len(argv) > 1 else ""
        if bp_expr[0] == "*":
            addr = int(gdb.parse_and_eval(bp_expr[1:]))
        elif bp_expr[0] == "0" and bp_expr[1] == "x":
            addr = int(gdb.parse_and_eval(bp_expr))
        else:
            addr = int(gdb.parse_and_eval("&{}".format(
                bp_expr)))  # get address of symbol or function name
        condition = ""
        if len(argv) > 2:
            condition = ' '.join(argv[2:])
        self.set_pie_breakpoint(lambda base: "b *{} {}".format(base + addr, condition), addr)

        # When the process is already on, set real breakpoints immediately
        if is_alive():
            base_address = RVACommand.base_address(base_filepath)
            for bp_ins in __pie_breakpoints__.values():
                gef_print(bp_ins.instantiate(base_address))


class DeleteRVACommand(PieDeleteCommand):
    """Delete a PIE breakpoint."""
    _cmdline_ = "drva"


class DumpQwordRVACommand(Hexdump32RVACommand):
    """Display SIZE lines of hexdump as QWORD from the memory location pointed by RVA."""
    _cmdline_ = "dqva"
    _syntax_ = "{:s} [-f file_path] [RVA] [[L][SIZE]] [REVERSE]".format(
        _cmdline_)
    _example_ = "{:s} -f libc $rsp L16 REVERSE".format(_cmdline_)

    def __init__(self):
        super(Hexdump32RVACommand, self).__init__()  #pylint: disable=bad-super-call
        self.format = "qword"
        return


class DumpDwordRVACommand(Hexdump32RVACommand):
    """Display SIZE lines of hexdump as DWORD from the memory location pointed by RVA."""
    _cmdline_ = "ddva"
    _syntax_ = "{:s} [-f file_path] [RVA] [[L][SIZE]] [REVERSE]".format(
        _cmdline_)
    _example_ = "{:s} -f libc $rsp L16 REVERSE".format(_cmdline_)

    def __init__(self):
        super(Hexdump32RVACommand, self).__init__()  #pylint: disable=bad-super-call
        self.format = "dword"
        return


class DumpWordRVACommand(Hexdump32RVACommand):
    """Display SIZE lines of hexdump as WORD from the memory location pointed by RVA."""
    _cmdline_ = "dwva"
    _syntax_ = "{:s} [-f file_path] [RVA] [[L][SIZE]] [REVERSE]".format(
        _cmdline_)
    _example_ = "{:s} -f libc $rsp L16 REVERSE".format(_cmdline_)

    def __init__(self):
        super(Hexdump32RVACommand, self).__init__()  #pylint: disable=bad-super-call
        self.format = "word"
        return


class DumpByteRVACommand(Hexdump32RVACommand):
    """Display SIZE lines of hexdump as BYTE from the memory location pointed by RVA."""
    _cmdline_ = "dbva"
    _syntax_ = "{:s} [-f file_path] [RVA] [[L][SIZE]] [REVERSE]".format(
        _cmdline_)
    _example_ = "{:s} -f libc $rsp L16 REVERSE".format(_cmdline_)

    def __init__(self):
        super(Hexdump32RVACommand, self).__init__()  #pylint: disable=bad-super-call
        self.format = "byte"
        return


class DumpInsRVACommand(GenericCommand):
    """Display SIZE instructions from the memory location pointed by RVA."""
    _cmdline_ = "xiva"
    _syntax_ = "{:s} [-f file_path] [RVA] [[L][SIZE]]".format(_cmdline_)
    _aliases_ = [
        "diva",
    ]

    def do_invoke(self, argv):
        target = ""
        read_len = None
        base_filepath = ""

        opts, args = getopt.getopt(argv, "f:")
        for o, a in opts:
            if o == "-f": base_filepath = a
        for arg in args:
            arg_lower = arg.lower()
            if "reverse".startswith(arg_lower):
                reverse = True
                continue
            if arg_lower.startswith("l") or target:
                if arg_lower.startswith("l"):
                    arg_lower = arg_lower[1:]
                if read_len:
                    self.usage()
                    return
                read_len = int(arg_lower, 0)
                continue
            target = arg

        if not target:
            target = "$pc"

        start_addr = to_unsigned_long(gdb.parse_and_eval(
            target)) + RVACommand.base_address(base_filepath)
        read_from = align_address(start_addr)

        if not read_len:
            read_len = 20

        gdb.execute("x/{}xi {}".format(read_len, read_from))


register_external_command(DumpQwordCommand())
register_external_command(DumpDwordCommand())
register_external_command(DumpWordCommand())
register_external_command(DumpByteCommand())
register_external_command(RVACommand())
register_external_command(VACommand())
register_external_command(BreakRVACommand())
register_external_command(DeleteRVACommand())
register_external_command(DumpQwordRVACommand())
register_external_command(DumpDwordRVACommand())
register_external_command(DumpWordRVACommand())
register_external_command(DumpByteRVACommand())
register_external_command(DumpInsRVACommand())
