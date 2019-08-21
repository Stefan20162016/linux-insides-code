; Minimal Linux Bootloader
; ========================
; @ annotated version (added comments and the bootloader now prints the kernel version string which is in the kernel image file) Feb 2018, Stefan20162016

; @ author:	Sebastian Plotz
; @ version:	1.0
; @ date:	24.07.2012

; Copyright (C) 2012 Sebastian Plotz

; Minimal Linux Bootloader is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.

; Minimal Linux Bootloader is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
; GNU General Public License for more details.

; You should have received a copy of the GNU General Public License
; along with Minimal Linux Bootloader. If not, see <http://www.gnu.org/licenses/>.

; ubuntu kernel 4.13.13, qemu 2.8.0

;- load first 512 bytes of kernel to 0x10000 using int 0x13/ah=0x42
;- at 0x1f1 (497) size of kernel setup in 512 byte units, load it after first 512 bytes
;- check for boot protocol version in loaded kernel setup
;- set own kernel setup header fields: type of loader, can_use_heap, heap_end_ptr, cmd_line_ptr
;- move cmd_line to memory
;- read_protected_mode_kernel size according to syssize field in kernel_setup
;- use int 0x13/ah=0x42 to load 127*512=65024 byte chunks to temporary address 0x20000
;- use int 0x15/ah=0x87 to copy it to extended memory using GDT global descriptor table: destination 0x100000 = 1 Mbyte

; Memory layout
; =============

; 0x07c00 - 0x07dff	Minimal Linux Bootloader max 446 bytes, 
; 		;first bootloader code than rest zeros til partition table
;		;	+ partition table = 4*16 bytes: 4 entries a 16 byte
;		;	+ MBR signature	  = 2 bytes for 0xaa55
;							for a total of 512 bytes
;
; 0x10000 - 0x17fff	Real mode kernel		; size: 32Kb
; 0x18000 - 0x1dfff	Stack and heap			; size: 24Kb
; 0x1e000 - 0x1ffff	Kernel command line		; size: 8Kb
									; total of 64Kb
; 0x20000 - 0x2fdff	temporal space to load	; size: 63.5Kb is the max. size interrupt 15 in "do_move:" below can load at once: 127*512 bytes
;			protected-mode kernel			; 

; base_ptr = 0x10000							; 64Kb; X in diagram in linux-insides linux-bootstrap-1.html respectively boot.txt in kerneldoc
; heap_end = 0x e000							; 56Kb = sizeof(realmodekernel) + sizeof(stack and heap)
; heap_end_ptr = heap_end - 0x200 = 0xde00		; minus sizeof(kernel boot sector)
	; quote from kernel "boot.txt": "Set this field to the offset (from the beginning of the real-mode
    ; code) of the end of the setup stack/heap, minus 0x0200."
; cmd_line_ptr = base_ptr + heap_end = 0x1e000	; 

; a few comments
; use "objdump --adjust-vma 0x7c00 -z -bbinary -mi386 -D -Mintel,addr16,data16 MBR" to disassemble the MBR (-M are disassembler options)
; or use ndisasm -b16 -o7c00h -a -s7c4eh mbr (maybe change sync address or dont use the -s flag at all)
; double check size with: hexdump -C MBR (no bytes after 446) or else partition table will be corrupted
; I used a ubuntu 17.10 fresh install using VirtualBox for testing: compile kernel so it loads without initrd (check by deleting everything in the grub line except vmlinuz4.xx root=/dev/sda1) I just added config_sata_ahci=y to those options and config_pata_acpi 
; qemu-img convert -O raw ubuntu1710.vdi ubu.raw
; check if it boots without initrd and get the lba# of the kernel with hdparm --fibmap <kernel> to set "current_lba" at the bottom of the code; make sure hdparm gives you just one entry. If the kernel file is split over more lbas it wont work. Delete the file or copy it and check again.
; "dd if=mbr of=ubu.raw bs=1 count=446 conv=notrunc" don't forget the notrunc option or else the file ubu.raw will just be the mbr
; qemu-system-x86_64 -m 1024 -machine type=pc,accel=kvm -drive format=raw,file=ubu.raw

; qemu tipps: use ctrl+alt+f2 for the monitor console: 
; e.g.   "pmemsave addr size file"	e.g. pmemsave 0 10485676 first1Mbyte
; you can check your current boot_params in /sys/kernel/boot_params/data (with hex editor)
; qemu option "-serial mon:stdio": if you compile the kernel with builtin-command-line-option: CONFIG_CMDLINE="console=ttyS0" you
; get all the output in your terminal instead of the seperate qemu window and of course the early-print kernel output with 
; CONFIG_X86_VERBOSE_BOOTUP=y
; qemu-system-x86_64 -machine type=pc,accel=kvm -kernel arch/x86/boot/bzImage -initrd ~/code/kernel/rootfs.cpio.gz -serial mon:stdio  -s -append "earlyprintk=ttyS0,keep,debug"

; qemu option "-snapshot" means changes to the file system won't be written

; get assembler/hardware documentation: "intel 64 and ia-32 architectures software developer's manual (combined volumes)" and http://ref.x86asm.net tables for quick reference and see http://www.ctyme.com/intr/int.htm for interrupts
; "This OS is a Boot Sector” by Shikhin Sethi" in "PoC || GTFO" series https://www.alchemistowl.org/pocorgtfo/pocorgtfo04.pdf or https://github.com/tylert/pocorgtfo/blob/gh-pages/pocorgtfo04.pdf 

org	0x7c00	; 31Kb sets relative address because BIOS loads the bootloader at this address


; not enough bytes left for a proper boot-message-string, use kernel version string below
;	mov	si, boot_msg
;bootmsg_loop:
;	lodsb
;	and	al, al
;	jz	done
;	mov	ah, 0xe
;	mov	bx, 7
;	int	0x10
;	jmp	short bootmsg_loop
;done:

; just one char 'X' to see if we got loaded see below we print the kernel version string from insides the kernel image
;	mov al,'X'
;	mov ah,0xe
;	mov bx,7
;	int 0x10		; print X

;    xor ax,ax
; int 0x16 		; press ENTER to boot
	 
	cli
	xor	ax, ax
	mov	ds, ax
	mov	ss, ax
	mov	sp, 0x7c00			; setup stack 
	mov	ax, 0x1000
	mov	es, ax
	sti

read_kernel_bootsector:

	mov	eax, 0x0001			; register ax gets count: load one sector == 512 bytes
	xor	bx, bx				; BX gets offset: no offset
	mov	cx, 0x1000			; CX destination segment(0x1000 shifted left 4bits): load Kernel boot sector at 0x10000, cx*16 segment=0x10000
	call	read_from_hdd
						; first 512 bytes are now in memory at 0x10000 which is the kernel boot sector
read_kernel_setup:

	xor	eax, eax
	mov	al, [es:0x1f1]		; no. of sectors to load; value is in 512 byte / 1 sector units; [es:0x1f1] also selects segment 0x10000 with offset 0x1f1 = 497 which are the bytes previously loaded (kernel boot sector) from the kernel file
	cmp	ax, 0				; if setup_sects == 0 set to 4. It's here for compatibility reasons
	jne	read_kernel_setup.next
	mov	ax, 4
.next:
	mov	bx, 512				; 512 byte offset, start after kernel boot sector
	mov	cx, 0x1000			; so same segment but we dont overwrite first 512 bytes
	call	read_from_hdd	; next setup_sects * 512 bytes now after 0x10200

; print kernel version
	push ds					; because we change it below
	mov	esi, [es:0x20e]		; there is the pointer to the nul-terminated kernel version string
	add esi, 0x200			; but minus 512 for kernel boot sector. See "header.S" in kernel source line ~ 310.
	mov ax, 0x1000			; setup segment DS for lodsb below, see the (good) intel 64 and ia-32 architectures software developer's manual Chapter 3.2 and http://ref.x86asm.net tables for quick reference; LODSB loads from DS:(E)SI to AL
	mov ds, ax
bootmsg_loop:
	lodsb
	and	al, al
	jz	doneB
	mov	ah, 0xe
	mov	bx, 7
	int	0x10
	jmp	short bootmsg_loop
doneB:
	pop ds					; restore DS segment register

xor ax,ax
int 0x16 		; press <ENTER> to boot

;check_version: ; skip those checks to have some bytes to print the kernel version string, a contemporary kernel has those flags set

;	cmp	word [es:0x206], 0x204		; we need protocol version >= 2.04	; es also selects segment 0x10000
;	jb	error
;	test	byte [es:0x211], 1		; check for LOADED_HIGH==1 test computes logical AND 
;	jz	error						; jump if result 0

set_header_fields:

	mov	byte [es:0x210], 0xe1		; set type_of_loader
	or	byte [es:0x211], 0x80		; set CAN_USE_HEAP
	mov	word [es:0x224], 0xde00		; set heap_end_ptr
	;mov	byte [es:0x226], 0x00		; set ext_loader_ver
	mov	byte [es:0x227], 0x01		; set ext_loader_type (bootloader id: 0x11)
	mov	dword [es:0x228], 0x1e000	; set cmd_line_ptr
	cld					; copy cmd_line
	mov	si, cmd_line	; source DS:SI (intel manual vol2b chapter 4.3 MOVSB)
	mov	di, 0xe000		; destination ES:DI; so 0x1000:0xe000 == 0x1e000
	mov	cx, cmd_length
	rep	movsb

read_protected_mode_kernel:

	mov	edx, [es:0x1f4]			; edx stores the number of bytes to load; 0x1f4 syssize in 16byte unit
	shl	edx, 4					; so shift left; now edx is in bytes 
.loop:
	cmp	edx, 0
	je	run_kernel
	cmp	edx, 0xfe00			; less than 127*512 bytes remaining?
	jb	read_protected_mode_kernel_2
	mov	eax, 0x7f			; load 127 sectors (maximum)
	xor	bx, bx				; no offset
	mov	cx, 0x2000			; load temporary to 0x20000
	call	read_from_hdd
	mov	cx, 0x7f00			; move 65024 bytes (127*512 byte); the int15/ah=87h expects words (2 byte) in CX
	call	do_move			; copy to extended memory/above 1Mbyte; see ralf browns Int table int15/ah-87h
							; see GDTable below for source/destination address it loads from temporary 0x20000
							; to mem starting at 0x100000=1Mbyte
	sub	edx, 0xfe00			; update the number of bytes to load
	add	word [gdt.dest], 0xfe00 ; add how much got loaded to "destination segment address": 0xfe00 = 127*512 = 65024 bytes so next loop will start there
	adc	byte [gdt.dest+2], 0 ; add carry flag to dest+2
	jmp	short read_protected_mode_kernel.loop

read_protected_mode_kernel_2:

	mov	eax, edx	 ; edx in bytes
	shr	eax, 9		 ; eax in 512 byte sectors (divided by 2^9=512)
	test	edx, 511 ; low 9bits == zero?
	jz	read_protected_mode_kernel_2.next
	inc	eax			 ; so add 1 one because SHR lost them
.next:
	xor	bx, bx		; offset 0
	mov	cx, 0x2000  ; this segment is the temp space
	call	read_from_hdd
	mov	ecx, edx
	shr	ecx, 1		; the int 0x15 ah=87 expects words (2 byte) in CX
	call	do_move

run_kernel:

	cli
	mov	ax, 0x1000
	mov	ds, ax			; kernel will use that
	mov	es, ax
	mov	fs, ax
	mov	gs, ax
	mov	ss, ax
	mov	sp, 0xe000
;xor ax,ax		; (to stop before running kernelcode)
;int 0x16 		; press <ENTER> to boot
	jmp	0x1020:0; 0x10200: first kernel real-mode code (kernel setup) in 0x10000 + 512 byte = 0x10200 after kenel boot sector
				; jump will set codesegment to 0x1020, CS can only be changed by another jump/ret in kernelcode
				; see "retf" in header.S

read_from_hdd:	; fill dap: disk address paket; set ax,bx,cx before calling

	push	edx
	mov	[dap.count], ax			; count
	mov	[dap.offset], bx		; destination low part
	mov	[dap.segment], cx		; destination high part
	mov	edx, [current_lba]
	mov	[dap.lba], edx			; source
	add	[current_lba], eax		; update current_lba
	mov	ah, 0x42
	mov	si, dap
	mov	dl, 0x80			; first hard disk
	int	0x13
	jc	error
	pop	edx
	ret

do_move:		; see http://www.ctyme.com/intr/rb-1527.htm

	push	edx
	push	es
	xor	ax, ax
	mov	es, ax
	mov	ah, 0x87	;	SYSTEM - COPY EXTENDED MEMORY
	mov	si, gdt
	int	0x15
	jc	error
	pop	es
	pop	edx
	ret

error:

	mov	si, error_msg

msg_loop:

	lodsb
	and	al, al
	jz	reboot
	mov	ah, 0xe
	mov	bx, 7
	int	0x10
	jmp	short msg_loop

reboot:

	xor	ax, ax
	int	0x16
	int	0x19
	jmp	0xf000:0xfff0			; BIOS reset code

; Global Descriptor Table	http://www.ctyme.com/intr/rb-1527.htm

gdt:

	times	16	db	0
	dw	0xffff				; segment limit
.src:
	dw	0					; first 2 bytes of source
	db	2					; 3rd/last byte of source address, so 0x20000 = 128 KiB
	db	0x93				; data access rights
	dw	0
	dw	0xffff				; segment limit
.dest:
	dw	0
	db	0x10				; load protected-mode kernel to 0x100 000 ; 0x10 is the highest byte of 3 see int15/ah=87 
	db	0x93				; data access rights
	dw	0
	times	16	db	0
	; 16 + 6*2 + 4 + 16  =  48

; Disk Address Packet; that's what the BIOS int 13 expects

dap:

	db	0x10			; size of DAP
	db	0				; unused
.count:
	dw	0				; number of sectors
.offset:
	dw	0				; destination: offset
.segment:
	dw	0				; destination: segment
.lba:
	dd	0				; low bytes of LBA address
	dd	0				; high bytes of LBA address

;current_lba	dd	39716864 ; initialize to first LBA address: hdparm --fibmap <bzImage-to-load>
;current_lba	dd	43239424
current_lba	dd	69445632
cmd_line	db	'root=/dev/sda1 S', 0	; S for single-mode runlevel/console, X11 works but takes longer to load with qemu
cmd_length	equ	$ - cmd_line
error_msg	db	'err', 0xd,0xa,0		; /* FIXME: newline */ ; "fixed"?
;boot_msg	db 'Booting via minimal bootloader...', 0	; not much space for a boot message use kernel version string instead
times	510-($-$$)	db	0	; fill file with 0 until 510 
dw	0xaa55 	; we dont necessarily need/write that just to test without partition table with qemu et.al.
			; size of bootloader code has to end at 0x1BE or 446 bytes followed by the partition table than the two bytes for signature 0xaa55





