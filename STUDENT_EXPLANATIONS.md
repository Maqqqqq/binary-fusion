1. **Explain binary file formats and why they matter.**  
Binary file formats define how compiled programs are stored on disk. They matter because the OS loader, debuggers, and security tools rely on that structure to run and inspect programs safely.

2. **Explain your choice of executable format.**  
I chose ELF because this project targets Linux, and ELF is the standard executable format on Linux. It is also well documented and easy to inspect with libraries like LIEF.

3. **Explain your choice of tools.**  
I used Python for fast development, LIEF for parsing ELF headers and sections, GCC for building the fused launcher, and zlib for optional compression. These tools are simple, available on Linux, and fit the project requirements.

4. **Ask the student to identify and explain the key fields in the main header of their chosen executable format.**  
Key ELF header fields are `e_ident` for magic bytes and class, `e_type` for file kind, `e_machine` for architecture, and `e_entry` for the entry point.

5. **Ask the student to explain how their tool differentiates between executable, shared object, and relocatable files in the chosen format. Provide specific fields or markers used for identification.**  
The tool checks the ELF header field `e_type` through `header.file_type.name`. `EXEC` means executable, `DYN` means shared object or PIE executable, and `REL` means relocatable object file.

6. **Ask the student to explain the process of modifying the entry point in their chosen format. How does their tool ensure correct execution flow?**  
The fused binary uses its own `_start` stub instead of the original program entry point. That stub calls `fused_main`, and `fused_main` runs program 1 first and program 2 after that, so the execution order is controlled.

7. **Ask the student to describe the validation steps their tool performs to ensure the fused binary is structurally valid and executable.**  
The tool checks that both inputs are valid ELF files, have the same ELF class, have the same architecture, and have a supported type (`EXEC` or `DYN`). It also verifies payload integrity with CRC32 before execution.

8. **Ask the student to describe their testing methodology for verifying correct sequential execution of both programs in the fused binary.**  
I fused small test programs, ran the fused output, and checked that the first program output appears before the second one. I repeated this with normal and static binaries.

9. **Ask the student to demonstrate fusing incompatible executables.**  
One simple demo is trying to fuse a relocatable `.o` file with an executable. The tool detects `REL` in the ELF header, prints an unsupported-type error, and stops.

10. **Ask the student to demonstrate fusing files with non-standard section names.**  
I can compile a test program with custom section names and fuse it with another ELF file. The tool still works because it reads section flags and contents, not hardcoded section names.

11. **Ask the student to describe the optimization techniques used to minimize padding and improve efficiency in the fused binary. How do these techniques impact performance?**  
The tool groups sections by permissions and packs them with alignment-aware ordering to reduce padding. This keeps the fused binary smaller and avoids wasting space.

12. **Ask the student to explain the compression algorithm they chose and why. How does their implementation handle the decompression at runtime?**  
I used zlib because it is simple and already available on Linux systems. The input binaries are compressed when building, and the fused launcher decompresses them in memory before executing them.

13. **Ask the student to describe how their implementation manages file descriptors and output streams to achieve this redirection. How does it ensure that each program's output is correctly separated?**  
The launcher saves the current `stdout` and `stderr`, redirects them to the selected files with `open` and `dup2`, runs one program, then restores the original file descriptors before running the next program. This keeps each program's output separate.

14. **Ask the student to demonstrate and explain any bonus features they've implemented.**  
Bonus features include optional compression, CRC32 integrity checks, separate output redirection for each program, and support for static executables. These features make the fused binary more flexible and safer to test.
