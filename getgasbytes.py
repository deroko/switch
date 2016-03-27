from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def     get_gas(buff):
        if not buff: return buff;

        cnt = 12;
        ret = "";
        for x in range(0, len(buff), cnt):
                data = buff[x:];
                if len(data) >= cnt:
                        data = data[:cnt];
                cstr = ".byte                   ";
		lst = [];
                for b in data:
                        lst.append("0x%.02x" % ord(b));
		ret += cstr + ", ".join(lst) + "\n";
        ret = ret[:-1];
        return ret;

f = open("./test64", "rb");
elffile = ELFFile(f);
symtab = elffile.get_section_by_name('.symtab')
testarm64     = symtab.get_symbol_by_name("testarm64")[0].entry.st_value;
testarm64_end = symtab.get_symbol_by_name("testarm64_end")[0].entry.st_value;

buff = open("./test64", "rb").read();
buff = buff[testarm64:testarm64_end];
buff = get_gas(buff); 

prefix = """
.syntax	unified

.global                 export_kill
export_kill:            
                        mov     r1, kill_end - kill
                        str     r1, [r0]
                        adr     r0, kill
                        bx      lr

.global	kill
kill:
			push    {r1-r12, lr}   
			mov	r12, r7
			mov	r7, 0x25
			svc	0
//if all went fine we are now aarch64
"""

suffix = """
pop	{r1-r12, pc}
kill_end:
""";

with open("./switchasm.S", "wb") as f:
	f.write(prefix);
	f.write(buff);
	f.write(suffix);
	f.flush();


