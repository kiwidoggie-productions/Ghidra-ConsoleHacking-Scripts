// This script is for opening a kernel dump or decrypted kernel
// and labeling all of the syscalls
//
// This was written for Ghidra 9.2 DEV but should work with other versions
// If something broke contact @kd_tech_ on twitter
//
// @author kd_tech (@kd_tech_)
// @category PlayStation4
// @keybinding 
// @menupath 
// @toolbar 

import java.math.BigInteger;
import java.util.ArrayList;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.script.AskDialog;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfProgramHeader;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;

public class OrbisKernelSyscalls extends GhidraScript 
{
	// Custom data structure types
	private StructureDataType m_sysvecStruct;
	private StructureDataType m_sysentStruct;
	
	// HACK: Allow addresses to be shifted by 0x800000 because the kernel was not loaded properly
	private boolean m_addressShifted = false;
	
	private final long c_AddressHackOffset = 0x800000;
	
	/**
	 * Creates and initializes the structures we apply
	 */
	private void initializeStructures()
	{
		CategoryPath categoryPath = new CategoryPath("/freebsd");
		
		// Create the sysent_t data type
		m_sysentStruct = new StructureDataType(categoryPath, "sysent_t", 0);
		m_sysentStruct.add(new UnsignedIntegerDataType(), "sy_narg", "number of arguments");									// 0
		m_sysentStruct.add(new Undefined4DataType(), "", "");																	// 4
		m_sysentStruct.add(new Pointer64DataType(), "sy_call", "implementing function");									// 8
		m_sysentStruct.add(new UnsignedShortDataType(), "sy_auevent", "audit event associated with syscall");					// 16
		m_sysentStruct.add(new Undefined6DataType(), "", "");																	// 18
		m_sysentStruct.add(new Pointer64DataType(), "sy_systrace_args_func", "optional argument conversion function");	// 24
		m_sysentStruct.add(new UnsignedIntegerDataType(), "sy_entry", "DTrace entry ID for systrace");							// 32
		m_sysentStruct.add(new UnsignedIntegerDataType(), "sy_return", "DTrace return ID for systrace");						// 36
		m_sysentStruct.add(new UnsignedIntegerDataType(), "sy_flags", "General flags for system calls");						// 40
		m_sysentStruct.add(new UnsignedIntegerDataType(), "sy_thrcnt", "");														// 44
		
		currentProgram.getDataTypeManager().addDataType(m_sysentStruct, DataTypeConflictHandler.KEEP_HANDLER);
		
		// Create the sysvec data type
		m_sysvecStruct = new StructureDataType(categoryPath, "sysentvec", 0);
		m_sysvecStruct.add(new IntegerDataType(), "sv_size", "number of entries");						// 0
		m_sysvecStruct.add(new Undefined4DataType(), "", "");											// 4
		m_sysvecStruct.add(new Pointer64DataType(), "sv_table", "pointer to sysent");					// 8
		m_sysvecStruct.add(new UnsignedIntegerDataType(), "sv_mask", "optional mask to index");			// 16
		m_sysvecStruct.add(new IntegerDataType(), "sv_sigsize", "size of signal translation table");	// 20
		m_sysvecStruct.add(new Pointer64DataType(), "sv_sigtbl", "signal translation table");			// 24
		m_sysvecStruct.add(new IntegerDataType(), "sv_errsize", "size of errno translation table");		// 32
		m_sysvecStruct.add(new Undefined4DataType(), "", "");											// 36
		m_sysvecStruct.add(new Pointer64DataType(), "sv_errtbl", "errno translation table");			// 40
		m_sysvecStruct.add(new Pointer64DataType(), "sv_transtrap", "translate trap-to-signal mapping");// 48
		m_sysvecStruct.add(new Pointer64DataType(), "sv_fixup", "stack fixup function");				// 56
		m_sysvecStruct.add(new Pointer64DataType(), "sv_sendsig", "send signal");						// 64
		m_sysvecStruct.add(new Pointer64DataType(), "sv_sigcode", "start of sigtramp code");			// 72
		m_sysvecStruct.add(new Pointer64DataType(), "sv_szsigcode", "size of sigtramap code");			// 80
		m_sysvecStruct.add(new Pointer64DataType(), "sv_prepsyscall", "");								// 88
		m_sysvecStruct.add(new Pointer64DataType(), "sv_name", "name of binary type");					// 96
		m_sysvecStruct.add(new Pointer64DataType(), "sv_coredump", "function to dump core, or NULL");	// 104
		m_sysvecStruct.add(new Pointer64DataType(), "sv_imgact_try", "");								// 112
		m_sysvecStruct.add(new IntegerDataType(), "sv_minsigstksz", "minimum signal stack size");		// 120
		m_sysvecStruct.add(new IntegerDataType(), "sv_pagesize", "pagesize");							// 124
		m_sysvecStruct.add(new UnsignedLongLongDataType(), "sv_minuser", "VM_MIN_ADDRESS");				// 128
		m_sysvecStruct.add(new UnsignedLongLongDataType(), "sv_maxuser", "VM_MAXUSER_ADDRESS");			// 136
				
		// Handle fields that were removed in later firmwares
		boolean is170OrLower = askYesNo("Firmware Version", "is this firmware < 1.70?");
		if (is170OrLower)
		{
			m_sysvecStruct.add(new UnsignedLongLongDataType(), "sv_usrstack", "USRSTACK");				// 144
			m_sysvecStruct.add(new UnsignedLongLongDataType(), "sv_psstrings", "PS_STRINGS");			// 152
		}
		
		m_sysvecStruct.add(new IntegerDataType(), "sv_stackprot", "vm protection for stack");			// 160
		m_sysvecStruct.add(new Undefined4DataType(), "", "");											// 164
		m_sysvecStruct.add(new Pointer64DataType(), "sv_copyout_strings", "");							// 168
		m_sysvecStruct.add(new Pointer64DataType(), "sv_setregs", "");									// 176
		m_sysvecStruct.add(new Pointer64DataType(), "sv_fixlimit", "");									// 184
		m_sysvecStruct.add(new Pointer64DataType(), "sv_maxssiz", "");									// 192
		m_sysvecStruct.add(new UnsignedIntegerDataType(), "sv_flags", "");								// 200
		m_sysvecStruct.add(new Undefined4DataType(), "", "");											// 204
		m_sysvecStruct.add(new Pointer64DataType(), "sv_set_syscall_retval", "");						// 208
		m_sysvecStruct.add(new Pointer64DataType(), "sv_fetch_syscall_args", "");						// 216
		m_sysvecStruct.add(new Pointer64DataType(), "sv_syscallnames", "");								// 224
		m_sysvecStruct.add(new UnsignedLongLongDataType(), "sv_shared_page_base", "");					// 232
		m_sysvecStruct.add(new UnsignedLongLongDataType(), "sv_shared_page_len", "");					// 240
		m_sysvecStruct.add(new UnsignedLongLongDataType(), "sv_sigcode_base", "");						// 248
		m_sysvecStruct.add(new Pointer64DataType(), "sv_shared_page_obj", "");							// 256
		m_sysvecStruct.add(new Pointer64DataType(), "sv_schedtail", "");								// 264
		
		currentProgram.getDataTypeManager().addDataType(m_sysvecStruct, DataTypeConflictHandler.KEEP_HANDLER);
	}
	
	/**
	 * Gets the offset of a field in a StructureDataType
	 * @param InDataType Input StructureDataType
	 * @param FieldName Field name string
	 * @return -1 on error, value otherwise
	 */
	private long getFieldOffset(StructureDataType InDataType, String FieldName)
	{
		long offset = -1;
		
		DataTypeComponent[] components = InDataType.getDefinedComponents();
		for (int i = 0; i < components.length; ++i)
		{
			DataTypeComponent component = components[i];
			if (component.getFieldName() != FieldName)
				continue;
			
			offset = component.getOffset();
			break;
		}
		
		return offset;
	}
	
	/**
	 * Reads a null-terminated string at the specified address
	 * @param Api Program opened with the FlatProgramAPI
	 * @param ReadAddress Address to read from
	 * @return Empty String on error, String otherwise
	 * @throws Exception Read exception information
	 */
	private String readNullTerminatedString(FlatProgramAPI Api, Address ReadAddress) throws Exception
	{
		if (ReadAddress == null)
			return "";
		
		byte tempByte = 0;
		Address curAddress = ReadAddress;
		String tempString = "";
		
		while ((tempByte = Api.getByte(curAddress)) != 0)
		{
			tempString += (char)tempByte;
			curAddress = curAddress.add(1);
		}
		
		return tempString;
	}
	
	/**
	 * Helper function to determine if a provided address is within the current addressSpace or not
	 * @param Address Address offset to check
	 * @param Length Length to check
	 * @return True if address is available, false otherwise
	 */
	private boolean isAddressAvailable(long Address, int Length)
	{
		// Sanity check the address against null to prevent crash
		if (Address == 0)
			return false;
		
		// Get the default address space
		AddressSpace addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
		
		// Check the address space
		if (!addressSpace.isValidRange(Address, Length))
			return false;
		
		// Check to see if this address has already been mapped or not
		if (!currentProgram.getMemory().contains(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Address)))
			return false;
		
		return true;
	}
	
	/**
	 * Really bad hack in order to determine if a kernel dump was loaded properly
	 * @param Sysvec Address to sysvec structure
	 * @return True if kernel was not loaded properly and addresses are shifted, false otherwise
	 * @throws MemoryAccessException There was an invalid memory reference
	 */
	private boolean isKernelShifted(Address Sysvec) throws MemoryAccessException
	{
		boolean isDecrypted = askYesNo("Question", "Is this a decrypted (NOT DUMPED) kernel?");
		if (isDecrypted)
			return false;
		
		// Get the default address space
		AddressSpace addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
		
		// Get the offset of sv_syscall names within sysvec structure
		long syscallNamesStructOffset = getFieldOffset(m_sysvecStruct, "sv_syscallnames");
		if (syscallNamesStructOffset == 0)
			return false;
		
		// Read out the syscall names offset
		long syscallNamesOffset = getLong(Sysvec.add(syscallNamesStructOffset));
		if (!isAddressAvailable(syscallNamesOffset, 8))
		{
			printerr("syscall names offset: " + syscallNamesOffset + " address invalid.");
			return false;
		}
		
		// We only need to test the first syscall to see if the kernel isn't loaded properly
		Address syscallNamePosition = addressSpace.getAddress(syscallNamesOffset);
		
		long syscallNameOffset = getLong(syscallNamePosition);
		if (!isAddressAvailable(syscallNameOffset, 1))
		{
			// We have gotten a shit address, verify that shifting actually fixes the issue
			long fixedSyscallNamesOffset = syscallNamesOffset + c_AddressHackOffset;
			if (!isAddressAvailable(fixedSyscallNamesOffset, 1))
				return false;
		}
		
		// TODO: Walk the syscall address table determining if something is shifted
		
		return true;
	}
	
	/**
	 * Parses and gathers a list of syscall names from a dump
	 * @param Sysvec Address of Sysvec
	 * @param SyscallCount Total number of syscalls to parse
	 * @return ArrayList<String> full of syscall names, or empty or partial list on error
	 * @throws Exception Something broke
	 */
	private ArrayList<String> getSyscallNames(Address Sysvec, long SyscallCount) throws Exception
	{
		// Get the address space
		AddressSpace addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
		
		ArrayList<String> list = new ArrayList<String>();
		
		// Get the offset of sv_syscallnames from within the sysvec structure
		long syscallNamesStructOffset = getFieldOffset(m_sysvecStruct, "sv_syscallnames");
		if (syscallNamesStructOffset == 0)
			return list;
		
		// FIX: This fixes people's fucked up ass dumps
		long syscallNamesOffset = getLong(Sysvec.add(syscallNamesStructOffset));
		if (!isAddressAvailable(syscallNamesOffset, 8))
		{
			printerr("syscall names offset: " + syscallNamesOffset + " address invalid.");
			return list;
		}
		
		// Iterate through all of the syscalls
		for (int i = 0; i < SyscallCount; ++i)
		{
			// Check to see if the hack is already enabled, and adjust the value accordingly
			long recalculatedSyscallNamesOffset = m_addressShifted ? syscallNamesOffset + c_AddressHackOffset : syscallNamesOffset;
			
			// Use the recalculated syscall names offset (syscall names table)
			Address syscallPosition = addressSpace.getAddress(recalculatedSyscallNamesOffset + (0x8 * i));
			
			// HACK: Some kernel dumps aren't dumped correctly,
			// if we are not using a loader (this is a script) then we can't modify the headers/memory
			long nameOffset = getLong(syscallPosition);
			if (!isAddressAvailable(nameOffset, 1))
				return list;
			
			Address nameAddress = addressSpace.getAddress(nameOffset);
			String name;
			if (nameAddress.getUnsignedOffset() == 0)
				name = String.format("nosys_%d", i);
			else
			{
				
				name = readNullTerminatedString(this, nameAddress);
			
				if (nameAddress.getUnsignedOffset() == 0 || name.contains("#") || name.contains("obs_{"))
					name = String.format("nosys_%d", i);
			}
			
			list.add(name);
		}
		
		return list;
	}
	
	/**
	 * Clears all data within a specified address and length
	 * @param StartAddress Address to start clearing
	 * @param Length Length to clear
	 */
	private void clearDataRange(Address StartAddress, int Length)
	{
		for (int i = 0; i < Length; ++i)
		{
			try 
			{
				removeDataAt(StartAddress.add(i));
			} 
			catch (Exception e) 
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
				break;
			}
		}
	}
	
	/**
	 * Entrypoint for GhidraScript
	 */
    public void run() throws Exception 
    {
    	// Initialize the structures
    	initializeStructures();
    	
    	// Get the currently loaded ghidra program
    	if (currentProgram == null)
    	{
    		printerr("no program currently loaded");
    		return;
    	}
    	
    	// Get the address space
    	AddressSpace addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
    	
    	// Check the elf headers to make sure that it's proper
    	MemoryByteProvider memoryByteProvider = new MemoryByteProvider(currentProgram.getMemory(), currentProgram.getImageBase());
    	
    	// Get the elf header
    	ElfHeader elfHeader = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, memoryByteProvider);
    	ElfProgramHeader[] programHeaders = elfHeader.getProgramHeaders();
    	
    	// Check that all program headers filesz and memsz are the same
    	boolean areAllSegmentSizesEqual = true;
    	for (int i = 0; i < programHeaders.length; ++i)
    	{
    		// Get the program header
    		ElfProgramHeader programHeader = programHeaders[i];
    		
    		long fileSize = programHeader.getFileSize();
    		long memSize = programHeader.getMemorySize();
    		
    		if (fileSize != memSize)
    			areAllSegmentSizesEqual = false;
    	}
    	
    	// Handle if not all segment sizes are equal
    	// This WILL be the case for Decrypted Kernels
    	// This SHOULD NOT be the case for Dumped Kernels (unless you didn't fix the headers like a nincompoop)
    	if (!areAllSegmentSizesEqual)
    	{
        	boolean askResult = askYesNo("Continue analysis?", "Non-matching segment sizes for a kernel dump.\nIs this a kernel dump  (not decrypted)?");
        	if (askResult)
        	{
        		printerr("not proceeding with analysis of kernel, segment headers need to be fixed.");
        		printerr("this can be done by dumping a full 40MB kernel dump, iterating all headers and setting the program header filesz to memsz (as it's been dumped from memory)");
        		return;
        	}
    	}
    	
    	// Find the 'ORBIS kernel SELF' magic
    	Address orbisKernelSelfMagicAddress = find("ORBIS kernel SELF");
    	if (orbisKernelSelfMagicAddress == null)
    	{
    		printerr("err: could not find 'ORBIS kernel SELF' magic.");
    		return;
    	}
    	
    	// Get all references to the orbis kernel self magic
    	Reference[] orbisKernelSelfMagicReferences = getReferencesTo(orbisKernelSelfMagicAddress);
    	Address sysvecAddress = null;
    	
    	// Validate that we have any references
    	if (orbisKernelSelfMagicReferences == null || orbisKernelSelfMagicReferences.length < 1)
    	{
    		// Give user some update
    		printerr("could not find any references to the 'ORBIS kernel SELF' magic, falling back to manual search.");
    		
    		// We did not find any references, manually try and byte scan
    		long magicOffset = orbisKernelSelfMagicAddress.getOffset();
    		
    		// Create the hex string to search for
    		String magicSearchPattern = String.format("\\x%02X\\x%02X\\x%02X\\x%02X\\x%02X\\x%02X\\x%02X\\x%02X", 
    				(magicOffset & 0xFF), 
    				((magicOffset >> 0x8) & 0xFF), 
    				((magicOffset >> 0x10) & 0xFF), 
    				((magicOffset >> 0x18) & 0xFF),
    				((magicOffset >> 0x20) & 0xFF),
    				((magicOffset >> 0x28) & 0xFF),
    				((magicOffset >> 0x30) & 0xFF),
    				((magicOffset >> 0x38) & 0xFF));
    		
    		// Find references to the hex pattern
    		Address[] referenceAddresses = findBytes(currentProgram.getImageBase(), magicSearchPattern, 1, 8);
    		if (referenceAddresses == null || referenceAddresses.length < 1)
    		{
    			printerr("could not get any reference addresses");
    			return;
    		}
    		
    		Address referenceAddress = referenceAddresses[0];
    		if (referenceAddress == null)
    		{
    			printerr("unable to find reference address for: " + magicSearchPattern);
    			return;
    		}
    		
    		// Subtract the address to get the start of the self_orbis_sysvec
    		sysvecAddress = referenceAddress.subtract(0x60);
    		
    		// Label the sysvec
    		println("self_orbis_sysvec: " + sysvecAddress.toString());
    		createLabel(sysvecAddress, "self_orbis_sysvec", true);
    		
    		// Clear out all of the data where sysvec would be
    		clearDataRange(sysvecAddress, m_sysvecStruct.getLength());
    		
    		// Create the new sysvec structure
    		createData(sysvecAddress, m_sysvecStruct);
    	}
    	else
    	{    		
    		// Iterate through each of the refrences
    		for (int i = 0; i < orbisKernelSelfMagicReferences.length; ++i)
    		{
    			// Validate through the references
    			Reference reference = orbisKernelSelfMagicReferences[i];
    			if (reference == null)
    				continue;
    			
    			// Attempt to test this sysvec adresss
    			Address testSysvecAddress = reference.getFromAddress().subtract(0x60);
    			
    			// This is a ghetto hack in order to make sure the syscall count is in-bounds
    			int syscallCount = getInt(testSysvecAddress);
    			if (syscallCount <= 0 || syscallCount > 700)
    				continue;
    			
    			sysvecAddress = testSysvecAddress;
    		}
    		
    		if (sysvecAddress == null)
    		{
    			printerr("could not get the sysvec address out of all references.");
    			return;
    		}
    		
    		println("self_orbis_sysvec: " + sysvecAddress.toString());
    		createLabel(sysvecAddress,"self_orbis_sysvec", true);
    		
    		// Clear out all of the data where sysvec would be
    		clearDataRange(sysvecAddress, m_sysvecStruct.getLength());
    		
    		// Create the new sysvec structure
    		createData(sysvecAddress, m_sysvecStruct);
    	}
    	
    	// Determine if this kernel dump is bad or not
    	m_addressShifted = isKernelShifted(sysvecAddress);
    	if (m_addressShifted)
    		println("warning: kernel was not dumped and fixed properly, addresses are shifted.");
    	
    	// Parse the syscall string table
    	
    	// Get the number of syscalls
    	long svCountOffset = getFieldOffset(m_sysvecStruct, "sv_size");
    	if (svCountOffset == -1)
    	{
    		printerr("could not get the sv_size structure offset.");
    		return;
    	}
    	
    	// Read out the syscall count
    	long syscallCount = getLong(sysvecAddress.add(svCountOffset));
    	
    	// Read out the sysent offset
    	long sysentOffset = getFieldOffset(m_sysvecStruct, "sv_table");
    	if (sysentOffset == -1)
    	{
    		printerr("could not get the sv_table structure offset.");
    		return;
    	}
    	
    	// Read out the sysent address
    	long sysent = getLong(sysvecAddress.add(sysentOffset)) + (m_addressShifted ? c_AddressHackOffset : 0);
    	if (sysent == 0)
    	{
    		printerr("could not finnd sysent");
    		return;
    	}
    	Address sysentAddress = addressSpace.getAddress(sysent);
    	
    	// Label sysent
    	createLabel(sysentAddress, "sysent", true);
    	println(String.format("sysent: " + sysentAddress.toString()));
    	
    	// Get the syscall name array
    	ArrayList<String> syscallNames = getSyscallNames(sysvecAddress, syscallCount);
    	println("got " + syscallNames.size() + " syscall names.");
    	
    	// Validate that we have some syscall names at all (thx aerosoul)
    	if (syscallNames.size() < syscallCount)
    	{
    		printerr("cannot label syscalls.");
    		return;
    	}
    	
    	// Label all of the syscalls
    	println("labeling " + syscallCount + " syscalls.");
    	int sysentLength = m_sysentStruct.getLength();
    	for (int syscallIndex = 0; syscallIndex < syscallCount; ++syscallIndex)
    	{
    		String syscallName = syscallNames.get(syscallIndex);
    		
    		Address syscallSysentAddress = sysentAddress.add( syscallIndex * sysentLength); // sizeof(sysent_t)
    		
    		// Clear out all of the data where sysvec would be
    		clearDataRange(syscallSysentAddress, sysentLength);
    		
    		// Create a new structure at the start
    		createData(syscallSysentAddress, m_sysentStruct);
    		
    		// Write a comment with some useful information	
    		setPlateComment(syscallSysentAddress, String.format("%d %s", syscallIndex, syscallName));
    		
    		// Read out the sysent offset
        	long syCallOffset = getFieldOffset(m_sysentStruct, "sy_call");
        	if (syCallOffset == -1)
        		continue;
        	
        	// Read out the sysent address
        	long sy_call = getLong(syscallSysentAddress.add(syCallOffset));
        	if (sy_call == 0)
        		continue;
        	
        	// Get the sy_call address
        	Address sy_callAddress = addressSpace.getAddress(sy_call);
        	
        	Function sy_callFunction = getFunctionAt(sy_callAddress);
    		// Create a new function if it does not exist at the sy_call address
    		if (sy_callFunction == null)
    		{
    			sy_callFunction = createFunction(sy_callAddress, syscallName);
    			println(String.format("created %s %x", syscallName, sy_call));
    		}
    		else
    		{
    			// Set the name of the function if it already exists
    			sy_callFunction.setName(syscallName, SourceType.USER_DEFINED);
    			println(String.format("labeled %s %x", syscallName, sy_call));
    		}
    	}
    	
    	println("finished labeling all syscalls!");
    }
}
