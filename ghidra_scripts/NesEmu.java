//PCode emulation script that outputs trace logs of NES programs
//@author flib
//@category
//@keybinding
//@menupath
//@toolbar

import java.util.Arrays;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import db.Transaction;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.Emulator;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.emulator.MemoryAccessFilter;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.framework.store.LockException;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.util.exception.NotFoundException;

public class NesEmu extends GhidraScript {
	/**
	 * Protocol used for sending and receiving commands, which coordinate
	 * CPU execution and memory accesses between the server (Ghidra) and the client (smolnes).
	 */
	enum EMUSRV_PROTO {
		RUN(0x01),
		INT(0x02),
		RAM_R(0x10),
		RES_R(0x11),
		RAM_W(0x12),
		RES_W(0x13),
		CLT_RAM_R(0x20),
		CLT_RES_R(0x21),
		INPUTS_W(0x30),
		ERR(0xff);

		private int v;
	    EMUSRV_PROTO(int v) {
	    	this.v = v;
	    }
	    public static EMUSRV_PROTO of(int x) {
	        return Arrays.stream(values()).filter(v -> v.v == x).findFirst().orElse(ERR);
	    }
	}

	/**
	 * Types of page crossings to consider for extra instruction cycles.
	 */
	enum EMUSRV_ADD {
		NONE,
		ABSOLUTE_CROSS,
		BRANCH_CROSS,
		INDIRECT_CROSS;
	}
	private record Cycles (int cycles, EMUSRV_ADD add) {}
	
	/**
	 * Map of fixed + conditional number of cycles that each instruction should take, keyed by opcode.
	 */
	private static final Map<Integer, Cycles> INSTRUCTION_CYCLES = Map.ofEntries(
			Map.entry(0x09, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x0A, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x18, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x29, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x2A, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x38, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x49, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x4A, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x58, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x69, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x6A, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x78, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x88, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x8A, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x98, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x9A, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xA0, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xA2, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xA8, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xA9, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xAA, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xB8, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xBA, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xC0, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xC8, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xC9, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xCA, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xD8, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xE0, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xE8, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xE9, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xEA, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0xF8, new Cycles(2, EMUSRV_ADD.NONE)),
			Map.entry(0x10, new Cycles(2, EMUSRV_ADD.BRANCH_CROSS)),
			Map.entry(0x30, new Cycles(2, EMUSRV_ADD.BRANCH_CROSS)),
			Map.entry(0x50, new Cycles(2, EMUSRV_ADD.BRANCH_CROSS)),
			Map.entry(0x70, new Cycles(2, EMUSRV_ADD.BRANCH_CROSS)),
			Map.entry(0x90, new Cycles(2, EMUSRV_ADD.BRANCH_CROSS)),
			Map.entry(0xB0, new Cycles(2, EMUSRV_ADD.BRANCH_CROSS)),
			Map.entry(0xD0, new Cycles(2, EMUSRV_ADD.BRANCH_CROSS)),
			Map.entry(0xF0, new Cycles(2, EMUSRV_ADD.BRANCH_CROSS)),
			Map.entry(0x05, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0x08, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0x24, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0x25, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0x45, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0x48, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0x4C, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0x65, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0x84, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0x85, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0x86, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0xA4, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0xA5, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0xA6, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0xC4, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0xC5, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0xE4, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0xE5, new Cycles(3, EMUSRV_ADD.NONE)),
			Map.entry(0x0D, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x15, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x28, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x2C, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x2D, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x35, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x4D, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x55, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x68, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x6D, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x75, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x8C, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x8D, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x8E, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x94, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x95, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x96, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0xAC, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0xAD, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0xAE, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0xB4, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0xB5, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0xB6, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0xCC, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0xCD, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0xD5, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0xEC, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0xED, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0xF5, new Cycles(4, EMUSRV_ADD.NONE)),
			Map.entry(0x19, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0x1D, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0x39, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0x3D, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0x59, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0x5D, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0x79, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0x7D, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0xB9, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0xBC, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0xBD, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0xBE, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0xD9, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0xDD, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0xF9, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0xFD, new Cycles(4, EMUSRV_ADD.ABSOLUTE_CROSS)),
			Map.entry(0x06, new Cycles(5, EMUSRV_ADD.NONE)),
			Map.entry(0x26, new Cycles(5, EMUSRV_ADD.NONE)),
			Map.entry(0x46, new Cycles(5, EMUSRV_ADD.NONE)),
			Map.entry(0x66, new Cycles(5, EMUSRV_ADD.NONE)),
			Map.entry(0x6C, new Cycles(5, EMUSRV_ADD.NONE)),
			Map.entry(0x99, new Cycles(5, EMUSRV_ADD.NONE)),
			Map.entry(0x9D, new Cycles(5, EMUSRV_ADD.NONE)),
			Map.entry(0xC6, new Cycles(5, EMUSRV_ADD.NONE)),
			Map.entry(0xE6, new Cycles(5, EMUSRV_ADD.NONE)),
			Map.entry(0x11, new Cycles(5, EMUSRV_ADD.INDIRECT_CROSS)),
			Map.entry(0x31, new Cycles(5, EMUSRV_ADD.INDIRECT_CROSS)),
			Map.entry(0x51, new Cycles(5, EMUSRV_ADD.INDIRECT_CROSS)),
			Map.entry(0x71, new Cycles(5, EMUSRV_ADD.INDIRECT_CROSS)),
			Map.entry(0xB1, new Cycles(5, EMUSRV_ADD.INDIRECT_CROSS)),
			Map.entry(0xD1, new Cycles(5, EMUSRV_ADD.INDIRECT_CROSS)),
			Map.entry(0xF1, new Cycles(5, EMUSRV_ADD.INDIRECT_CROSS)),
			Map.entry(0x01, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x0E, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x16, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x20, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x21, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x2E, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x36, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x40, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x41, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x4E, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x56, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x60, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x61, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x6E, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x76, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x81, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x91, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0xA1, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0xC1, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0xCE, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0xD6, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0xE1, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0xEE, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0xF6, new Cycles(6, EMUSRV_ADD.NONE)),
			Map.entry(0x00, new Cycles(7, EMUSRV_ADD.NONE)),
			Map.entry(0x1E, new Cycles(7, EMUSRV_ADD.NONE)),
			Map.entry(0x3E, new Cycles(7, EMUSRV_ADD.NONE)),
			Map.entry(0x5E, new Cycles(7, EMUSRV_ADD.NONE)),
			Map.entry(0x7E, new Cycles(7, EMUSRV_ADD.NONE)),
			Map.entry(0xDE, new Cycles(7, EMUSRV_ADD.NONE)),
			Map.entry(0xFE, new Cycles(7, EMUSRV_ADD.NONE))
	);
	
	private byte buf[];
	private InputStream input;
	private OutputStream output;
	
	/**
	 * Hooks for hardware registers, so that these can be delegated to the client.
	 * Reference: https://github.com/NationalSecurityAgency/ghidra/blob/7cc135eb6bfabd166cbc23f7951dae09a7e03c39/Ghidra/Features/Base/src/main/java/ghidra/test/processors/support/EmulatorTestRunner.java#L582
	 */
	private class MyMemoryAccessFilter extends MemoryAccessFilter {

		@Override
		protected void processWrite(AddressSpace spc, long off, int size, byte[] values) {
			if (spc.getName().toLowerCase().startsWith("ram") 
					&& (((off & 0xf000) == 0x2000) || ((off & 0xf000) == 0x4000))) {
				//println(String.format("hook w@%04x=%02x size=%d", off, values[0], size));
				
				try {
					buf[0] = (byte) EMUSRV_PROTO.RAM_W.v;
					buf[1] = (byte) ((off & 0xff00) >> 8);
					buf[2] = (byte) ((off & 0xff));
					buf[3] = values[0];
					output.write(buf, 0, 4);
					output.flush();
					
					while (!monitor.isCancelled()) {
						int reqType = clientRead();
						switch (EMUSRV_PROTO.of(reqType)) {
						case CLT_RAM_R:
							int n = clientRead() << 8;
							n |= clientRead();
							int a = clientRead() << 8;
							a |= clientRead();
							byte[] code = new byte[n];
							emu.getMemState().getChunk(code, addr(a).getAddressSpace(), a, n, false);
							buf[0] = (byte) EMUSRV_PROTO.CLT_RES_R.v;
							output.write(buf, 0, 1);
							output.write(code);
							output.flush();
							break;
						case RES_W:
							return;
						default:
							println(String.format("Unknown type=%02x", reqType));
							return;
						}
					}
				} catch (Exception e) {
					printerr(e.getMessage());
				}
			}
		}

		@Override
		protected void processRead(AddressSpace spc, long off, int size, byte[] values) {
			if (spc.getName().toLowerCase().startsWith("ram") 
					&& (((off & 0xf000) == 0x2000) || ((off & 0xf000) == 0x4000))
					&& emu.getEmulateExecutionState() != EmulateExecutionState.INSTRUCTION_DECODE) {
				//println(String.format("hook r@%04x size=%d", off, size));
				
				try {
					buf[0] = (byte) EMUSRV_PROTO.RAM_R.v;
					buf[1] = (byte) ((off & 0xff00) >> 8);
					buf[2] = (byte) ((off & 0xff));
					output.write(buf, 0, 3);
					output.flush();
					
					int resType = input.read();
					switch (EMUSRV_PROTO.of(resType)) {
					case RES_R:
						int resVal = input.read();
						values[0] = (byte) resVal;
						break;
					default:
						println(String.format("Unknown type=%02x", resType));
					}
				} catch (IOException e) {
					printerr(e.getMessage());
				}
			}
		}
	}
	
	@Override
	protected void run() throws Exception {
		EmulatorHelper cpu = new EmulatorHelper(currentProgram);
		Map<Long, Integer> inputs = new HashMap<>();
		setup(cpu, inputs);
		long line_i = 0;
		long prevPC = cpu.readRegister("PC").longValue();
		
		println("Starting server...");
		ServerSocket server = new ServerSocket(6502);
		Socket socket_r = server.accept();
		socket_r.setTcpNoDelay(true);
		Socket socket_w = server.accept();
		socket_w.setTcpNoDelay(true);
		input = socket_w.getInputStream();
		output = new DataOutputStream(new BufferedOutputStream(socket_r.getOutputStream()));
		buf = new byte[0x10];

		println("Emulating...");
		try {
			while (!monitor.isCancelled()) {
				int reqType = clientRead();
				switch (EMUSRV_PROTO.of(reqType)) {
				case RUN:
					// If we have recorded inputs at this instruction line, send them 
					// to the client, overriding what it reads from the keyboard.
					if (inputs.containsKey(line_i)) {
						buf[0] = (byte) EMUSRV_PROTO.INPUTS_W.v;
						buf[1] = inputs.get(line_i).byteValue();
						output.write(buf, 0, 2);
						output.flush();
					}
					
					prevPC = cpu.readRegister("PC").longValue();
					boolean ok = cpu.step(monitor);
					if (!ok) {
						printerr(cpu.getLastError());
						println(dump(cpu));
						dumpMem(cpu);
						break;
					}
					
					// Tell client to proceed (will execute PPU logic before requesting the next CPU step).
					buf[0] = (byte) EMUSRV_PROTO.RUN.v;
					buf[1] = (byte) ((cpu.readRegister("PC").intValue() & 0xff00) >> 8);
					buf[2] = (byte) ((cpu.readRegister("PC").intValue() & 0xff));
					buf[3] = cpu.readRegister("A").byteValue();
					buf[4] = cpu.readRegister("X").byteValue();
					buf[5] = cpu.readRegister("Y").byteValue();
					buf[6] = cpu.readRegister("S").byteValue();
					buf[7] = (byte) flags(cpu);
					buf[8] = (byte) cycles(cpu, prevPC);
					output.write(buf, 0, 9);
					output.flush();
					
					line_i++;
					if (line_i % 1000000 == 0) {
						println(String.format("Passed line=%d", line_i));
					}
					break;
				case INT:
					handleHardwareInt(cpu);

					buf[0] = (byte) ((cpu.readRegister("PC").intValue() & 0xff00) >> 8);
					buf[1] = (byte) ((cpu.readRegister("PC").intValue() & 0xff));
					buf[2] = cpu.readRegister("A").byteValue();
					buf[3] = cpu.readRegister("X").byteValue();
					buf[4] = cpu.readRegister("Y").byteValue();
					buf[5] = cpu.readRegister("S").byteValue();
					buf[6] = (byte) flags(cpu);
					buf[7] = (byte) 7;
					output.write(buf, 0, 8);
					output.flush();
					break;
				default:
					println(String.format("Unknown type=%02x", reqType));
					return;
				}
			}
		} finally {
			socket_r.close();
			socket_w.close();
			server.close();
			println("Stopped server.");
			
			cpu.dispose();
		}
	}

	private void dumpMem(EmulatorHelper cpu) throws Exception {
		long pc = cpu.readRegister("PC").longValue();
		Path outFile = Paths.get(String.format("/tmp/0x%08x.ghidra.mem", pc));
		Files.write(outFile , new byte[0], StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
		
		byte[] code = new byte[0x800];
		cpu.getEmulator().getMemState().getChunk(code, addr(0).getAddressSpace(), 0, 0x800, false);
		Files.write(outFile, code);
	}

	/**
	 * @return Total number of cycles the instruction at PC should take.
	 */
	private int cycles(EmulatorHelper emu, long prevPC) throws MemoryAccessException {
		Instruction ins = explore(emu, addr(prevPC));
		Cycles cyclesRef = INSTRUCTION_CYCLES.get(Byte.toUnsignedInt(ins.getByte(0)));
		int cycles = cyclesRef.cycles;
		
		long op1 = 0, op2 = 0;
		switch(cyclesRef.add) {
		case ABSOLUTE_CROSS:
			// Fallthrough
		case INDIRECT_CROSS:
			if (ins.getNumOperands() == 1) {
				for (Object obj : ins.getDefaultOperandRepresentationList(0)) {
					if (obj instanceof Scalar) {
						Scalar s = (Scalar) obj;
						op1 = s.getUnsignedValue();
					} else if (obj instanceof Register) {
						Register reg = (Register) obj;
						op2 = emu.getEmulator().getMemState().getValue(reg);
					}
				}
			} else {
				throw new RuntimeException(String.format("Unhandled num_operands=%d", ins.getNumOperands()));
			}
			if (cyclesRef.add == EMUSRV_ADD.INDIRECT_CROSS) {
				op1 = load16(emu, op1);
			}
			if ((op1 & 0xff) + op2 > 0xff) {
				cycles++;
			}
			break;
		case BRANCH_CROSS:
			byte rel = ins.getByte(1);
			long pc = emu.readRegister("PC").longValue();
			boolean isBranchTaken = prevPC + ins.getLength() + rel == pc;
			if (isBranchTaken) {
				cycles++;
				
				// Check if branch occurs to different page
				if (((prevPC + ins.getLength()) & 0xff00) != (pc & 0xff00)) {
					cycles++;
				}
			}
			break;
		default:
			// Nothing to add
		}
		
		return cycles;
	}

	private int clientRead() throws Exception {
		int res = input.read();
		if (res == -1) {
			throw new RuntimeException("Client closed connection?");
		}
		return res;
	}
	
	private void setup(EmulatorHelper cpu, Map<Long, Integer> inputs) throws Exception {
		for (MemoryBlock mb : currentProgram.getMemory().getBlocks()) {
			if (!mb.getName().contains("MIRROR") && !mb.isInitialized()) {
				currentProgram.getMemory().convertToInitialized(mb, (byte) '\0');
			}
		}
		
		cpu.writeRegister("I", 1);
		cpu.writeRegister("SP", 0x1FD);
		
		MemoryState memState = cpu.getEmulator().getMemState();
		AddressSpace addressSpace = addr(0xFFFCL).getAddressSpace();
		cpu.writeRegister("PC", memState.getValue(addressSpace, 0xFFFCL, 2));
		
		MyMemoryAccessFilter memoryFilter = new MyMemoryAccessFilter();
		cpu.getEmulator().addMemoryAccessFilter(memoryFilter);
		
		parseRecordedInputs(inputs);
	}

	private void handleHardwareInt(EmulatorHelper emu) {
		final long sp = emu.readRegister("SP").longValue();
		final long pc = emu.readRegister("PC").longValue();
		final long p = flags(emu) | 0x20; // I=1
		emu.writeMemoryValue(addr(sp - 1), 2, pc);
		emu.writeMemoryValue(addr(sp - 2), 1, p);
		
		final long irqRef = load16(emu, 0xFFFAL);
		emu.writeRegister("SP", sp - 3);
		emu.writeRegister("PC", irqRef);
	}
	
	private int flags(EmulatorHelper emu) {
		return emu.readRegister("N").intValue() << 7
				| emu.readRegister("V").intValue() << 6
				| emu.readRegister("B").intValue() << 4
				| emu.readRegister("D").intValue() << 3
				| emu.readRegister("I").intValue() << 2
				| emu.readRegister("Z").intValue() << 1
				| emu.readRegister("C").intValue();
	}

	private void parseRecordedInputs(Map<Long, Integer> state) throws IOException {
		Path path = Paths.get("/tmp/smb.inputs");
		if (!Files.exists(path)) {
			printerr(String.format("Recorded inputs will be ignored, state file does not exist: %s", path));
			return;
		}

		try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
			String line;
			while ((line = reader.readLine()) != null) {
				String[] vars = line.split(",");
				state.put(Long.parseUnsignedLong(vars[0].strip(), 16), 
						Integer.parseUnsignedInt(vars[1].strip(), 16));
			}
		}
	}
	
	/**
	 * Retrieves an instruction at the given address, considering cases where
	 * it may not have been previously explored during auto-analysis.
	 */
	private Instruction explore(EmulatorHelper emu, Address addr) {
		DisassembleCommand cmd;
		Instruction ins = currentProgram.getListing().getInstructionAt(addr);
		if (ins == null) {
			/*
			 * Workaround for overlapping instructions, e.g.
			 * 
			 * 8046  jsr $8220    A:06 X:ff Y:ff S:ff nv--dIzC
			 * 8220  ldy #$00     A:06 X:ff Y:ff S:fd nv--dIzC
			 * 8222  bit $04a0    A:06 X:ff Y:00 S:fd nv--dIZC
			 * 8225  lda #$f8     A:06 X:ff Y:00 S:fd nv--dIZC
			 *
			 * 814a  jsr $8223    A:00 X:07 Y:00 S:fc nv--dIZc
			 * 8223  ldy #$04     A:00 X:07 Y:00 S:fa nv--dIZc
			 * 8225  lda #$f8     A:00 X:07 Y:04 S:fa nv--dIzc
			 */
			long off = addr.getUnsignedOffset();
			Instruction prevIns = currentProgram.getListing().getInstructionAt(addr(off - 1));
			Instruction nextIns = currentProgram.getListing().getInstructionAt(addr(off + 1));
			if (prevIns != null || nextIns != null) {
				currentProgram.getListing().clearCodeUnits(addr(off - 1), addr(off + 1), false);
				cmd = new DisassembleCommand(addr, null, true);
				if (!cmd.applyTo(emu.getProgram()) || cmd.getDisassembledAddressSet().isEmpty()) {
					throw new RuntimeException(String.format("Null instruction off-by-1 @ 0x%08x", addr.getUnsignedOffset()));	
				}
				ins = currentProgram.getListing().getInstructionAt(addr);
				if (ins == null) {
					throw new RuntimeException(String.format("Null instruction off-by-1 after disasm @ 0x%08x", addr.getUnsignedOffset()));
				}
			// Valid but unexplored code
			} else {
				cmd = new DisassembleCommand(addr, null, true);
				if (!cmd.applyTo(emu.getProgram()) || cmd.getDisassembledAddressSet().isEmpty()) {
					// Workaround for data auto-analysis creating false positive references
					// in the middle of unexplored code, or switch case data that was auto-analyzed,
					// but overlaps with subroutines that can be jumped into (unusual but used in e.g. nestest).
					int i = 1;
					while (i < 20) {
						Address nextAddr = addr(addr.getUnsignedOffset() + i);
						currentProgram.getListing().clearCodeUnits(addr, nextAddr, false);
						i++;
					}

					cmd = new DisassembleCommand(addr, null, true);
					if (!cmd.applyTo(emu.getProgram()) || cmd.getDisassembledAddressSet().isEmpty()) {
						throw new RuntimeException(String.format("Null instruction @ 0x%08x", addr.getUnsignedOffset()));	
					}
				}
				ins = currentProgram.getListing().getInstructionAt(addr);
				if (ins == null) {
					throw new RuntimeException(String.format("Null instruction after disasm @ 0x%08x", addr.getUnsignedOffset()));
				}
			}
		}

		return ins;
	}

	private long load16(EmulatorHelper emu, long ref) {
		MemoryState memState = emu.getEmulator().getMemState();
		AddressSpace addressSpace = addr(ref).getAddressSpace();

		return memState.getValue(addressSpace, ref, 2);
	}
	
	private Address addr(long offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}
	
	private String dump(EmulatorHelper emu) {
		long pc = emu.readRegister("PC").longValue();
		CodeUnit cu = currentProgram.getListing().getCodeUnitAt(addr(pc));
		StringBuilder sb = new StringBuilder();
		sb.append(String.format("%04x %-16s", pc, cu));
		sb.append(String.format("A:%02x ", emu.readRegister("A").longValue()));
		sb.append(String.format("X:%02x ", emu.readRegister("X").longValue()));
		sb.append(String.format("Y:%02x ", emu.readRegister("Y").longValue()));
		sb.append(String.format("S:%02x ", emu.readRegister("S").longValue()));

		sb.append(emu.readRegister("N").longValue() != 0 ? "N" : "n");
		sb.append(emu.readRegister("V").longValue() != 0 ? "V" : "v");
		sb.append("-");
		sb.append("-"); // B?
		sb.append(emu.readRegister("D").longValue() != 0 ? "D" : "d");
		sb.append(emu.readRegister("I").longValue() != 0 ? "I" : "i");
		sb.append(emu.readRegister("Z").longValue() != 0 ? "Z" : "z");
		sb.append(emu.readRegister("C").longValue() != 0 ? "C" : "c");

		return sb.toString();
	}
}
