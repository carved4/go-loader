
// TAKEN FROM https://github.com/timwhitez/Doge-Gabh/tree/main/pkg/Gabh
//based on https://golang.org/src/runtime/sys_windows_amd64.s
#define maxargs 18
//func Syscall(callid uint16, argh ...uintptr) (uint32, error)
TEXT ·hgSyscall(SB), $0-56
	XORQ AX,AX
	MOVW callid+0(FP), AX
	PUSHQ CX
	//put variadic size into CX
	MOVQ argh_len+16(FP),CX
	//put variadic pointer into SI
	MOVQ argh_base+8(FP),SI
	// SetLastError(0).
	MOVQ	0x30(GS), DI
	MOVL	$0, 0x68(DI)
	SUBQ	$(maxargs*8), SP	// room for args
	//no parameters, special case
	CMPL CX, $0
	JLE callz
	// Fast version, do not store args on the stack.
	CMPL	CX, $4
	JLE	loadregs
	// Check we have enough room for args.
	CMPL	CX, $maxargs
	JLE	2(PC)
	INT	$3			// not enough room -> crash
	// Copy args to the stack.
	MOVQ	SP, DI
	CLD
	REP; MOVSQ
	MOVQ	SP, SI
loadregs:
	//move the stack pointer????? why????
	SUBQ	$8, SP
	// Load first 4 args into correspondent registers.
	//交换位置免杀
	MOVQ	8(SI), DX
	MOVQ	24(SI), R9
	MOVQ	0(SI), CX
	MOVQ	16(SI), R8
	// Floating point arguments are passed in the XMM
	// registers. Set them here in case any of the arguments
	// are floating point values. For details see
	//	https://msdn.microsoft.com/en-us/library/zthk2dkh.aspx
	MOVQ	CX, X0
	MOVQ	DX, X1
	MOVQ	R8, X2
	MOVQ	R9, X3
	//MOVW callid+0(FP), AX
	MOVQ CX, R10
	SYSCALL
	ADDQ	$((maxargs+1)*8), SP
	// Return result.
	POPQ	CX
	MOVL	AX, errcode+32(FP)
	RET
	PUSHQ CX
callz:
	MOVQ CX, R10
	SYSCALL
	ADDQ	$((maxargs)*8), SP
	// Return result.
	POPQ	CX
	MOVL	AX, errcode+32(FP)
	RET

//func getModuleLoadedOrder(i int) (start uintptr, size uintptr)
TEXT ·getMLO(SB), $0-32
	//All operations push values into AX
	//PEB
	MOVQ 0x60(GS), AX
	//PEB->LDR
	MOVQ 0x18(AX),AX
	//LDR->InMemoryOrderModuleList
	MOVQ 0x20(AX),AX
	//loop things
	XORQ R10,R10
startloop:
	CMPQ R10,i+0(FP)
	JE endloop
	//Flink (get next element)
	MOVQ (AX),AX
	INCQ R10
	JMP startloop
endloop:
	//Flink - 0x10 -> _LDR_DATA_TABLE_ENTRY
	//_LDR_DATA_TABLE_ENTRY->DllBase (offset 0x30)
	MOVQ 0x30(AX),CX
	MOVQ CX, size+16(FP)
	MOVQ 0x20(AX),CX
    MOVQ CX, start+8(FP)
	MOVQ AX,CX
	ADDQ $0x38,CX
	MOVQ CX, modulepath+24(FP)
	//SYSCALL
	RET
