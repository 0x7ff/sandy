#include <fcntl.h>
#include <inttypes.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define KMOD_MAX_NAME (64)
#define POLICY_OPS_OFF (0x20)
#define HOOK_POLICY_INIT_OFF (0x398)
#define HOOK_POLICY_SYSCALL_OFF (0x3a8)
#define CASE_SYSCALL_CHECK_SANDBOX_BULK_OFF (21 * sizeof(int32_t))
#define IS_IN_RANGE(a, b, c) ((a) >= (b) && (a) <= (c))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define STRLEN(a) (sizeof(a) - 1)
#define UNTAG_PTR(a) ((a) | 0xffff000000000000ull)
#define IS_MOV_X(a) (((a) & 0xff800000u) == 0xd2800000u)
#define IS_MOV_W(a) (((a) & 0xff800000u) == 0x52800000u)
#define MOV_W_IMM(a) extract32(a, 5, 16)
#define MOV_SHIFT(a) (extract32(a, 21, 2) << 4u)
#define IS_MOVK_W(a) (((a) & 0xff800000u) == 0x72800000u)
#define IS_ADD_X(a) (((a) & 0xffc00000u) == 0x91000000u)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define IS_ADR(a) (((a) & 0x1f000000u) == 0x10000000u)
#define IS_ADR_PAGE(a) extract32(a, 31, 1)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2u) | extract32(a, 29, 2))
#define IS_ADRP(a) (IS_ADR(a) && IS_ADR_PAGE(a))
#define ADRP_IMM(a) (ADR_IMM(a) << 12u)
#define ADRP_RD(a) extract32(a, 0, 5)
#define ADRP_ADDR(a) ((a) & ~0xfffull)
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xffc00000u) == 0xf9400000u)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3u)
#define IS_NOP(a) ((a) == 0xd503201fu)
#define IS_B(a) (((a) & 0xfc000000u) == 0x14000000u)
#define B_IMM(a) (sextract64(a, 0, 26) << 2u)
#define IS_CMP(a) (((a) & 0xffc00000u) == 0xf1000000u)
#define CMP_IMM(a) extract32(a, 10, 12)

#pragma pack(4)
typedef struct {
	uint64_t next_addr;
	int32_t  info_version;
	uint32_t id;
	char     name[KMOD_MAX_NAME];
	char     version[KMOD_MAX_NAME];
	int32_t  reference_count;
	uint64_t reference_list_addr;
	uint64_t address;
	uint64_t size;
	uint64_t hdr_size;
	uint64_t start_addr;
	uint64_t stop_addr;
} kmod_info_64_t;
#pragma pack()

static inline uint32_t
extract32(uint32_t value, unsigned start, unsigned length) {
	return (value >> start) & (~0u >> (32u - length));
}

static inline uint64_t
sextract64(uint64_t value, unsigned start, unsigned length) {
	return (uint64_t)((int64_t)(value << (64u - length - start)) >> (64u - length));
}

static const struct segment_command_64 *
find_segment(const struct mach_header_64 *mhp, const char *seg_name) {
	const struct segment_command_64 *sgp = (const struct segment_command_64 *)((uintptr_t)mhp + sizeof(*mhp));
	uint32_t i;
	
	for(i = 0; i < mhp->ncmds; ++i) {
		if(sgp->cmd == LC_SEGMENT_64 && !strncmp(sgp->segname, seg_name, sizeof(sgp->segname))) {
			return sgp;
		}
		sgp = (const struct segment_command_64 *)((uintptr_t)sgp + sgp->cmdsize);
	}
	return NULL;
}

static const struct section_64 *
find_section(const struct segment_command_64 *sgp, const char *sect_name) {
	const struct section_64 *sp = (const struct section_64 *)((uintptr_t)sgp + sizeof(*sgp));
	uint32_t i;
	
	for(i = 0; i < sgp->nsects; ++i) {
		if(!strncmp(sp->segname, sgp->segname, sizeof(sp->segname)) && !strncmp(sp->sectname, sect_name, sizeof(sp->sectname))) {
			return sp;
		}
		++sp;
	}
	return NULL;
}

static const struct mach_header_64 *
sandy_old(const struct mach_header_64 *mhp, const struct segment_command_64 *seg_prelink_info, uint64_t *slide, uint64_t *kext_slide, uint64_t *start_addr) {
	const struct segment_command_64 *seg_prelink_text;
	const struct section_64 *info;
	const kmod_info_64_t *kmod;
	const char *s;
	uint64_t kext_addr, kmod_addr;
	
	if((seg_prelink_text = find_segment(mhp, "__PRELINK_TEXT")) &&
	   ((info = find_section(seg_prelink_info, "__info")))) {
		if((s = strstr((const char *)((uintptr_t)mhp + info->offset), "CFBundleName</key><string>Seatbelt sandbox policy</string>")) &&
		   (s = strstr(s + STRLEN("CFBundleName</key><string>Seatbelt sandbox policy</string>"), "_PrelinkExecutableLoadAddr</key><integer")) &&
		   (s = strchr(s + STRLEN("_PrelinkExecutableLoadAddr</key><integer"), '>')))
		{
			kext_addr = strtoull(s + 1, NULL, 16);
			if((s = strstr(s, "_PrelinkKmodInfo</key><integer")) &&
			   (s = strchr(s + STRLEN("_PrelinkKmodInfo</key><integer"), '>')))
			{
				kmod_addr = strtoull(s + 1, NULL, 16);
				*slide = seg_prelink_text->vmaddr - seg_prelink_text->fileoff;
				*kext_slide = info->addr - info->offset;
				kmod = (const kmod_info_64_t *)((uintptr_t)mhp + (kmod_addr - *kext_slide));
				*start_addr = kmod->start_addr;
				return (const struct mach_header_64 *)((uintptr_t)mhp + (kext_addr - *slide));
			}
		}
	}
	return NULL;
}

static const struct mach_header_64 *
sandy_new(const struct mach_header_64 *mhp, const struct segment_command_64 *seg_prelink_info, uint64_t *slide, uint64_t *kext_slide, uint64_t *start_addr) {
	const struct segment_command_64 *seg_text;
	const struct section_64 *sec_kmod_info, *sec_kmod_start;
	const uint64_t *kext_table, *info_table;
	const kmod_info_64_t *kmod;
	uint64_t i;
	
	if((sec_kmod_start = find_section(seg_prelink_info, "__kmod_start")) &&
	   (sec_kmod_info = find_section(seg_prelink_info, "__kmod_info")) &&
	   (seg_text = find_segment(mhp, "__TEXT")))
	{
		kext_table = (const uint64_t *)((uintptr_t)mhp + sec_kmod_start->offset);
		info_table = (const uint64_t *)((uintptr_t)mhp + sec_kmod_info->offset);
		for(i = 0; i < MIN(sec_kmod_info->size, sec_kmod_start->size) / sizeof(uint64_t); ++i) {
			kmod = (const kmod_info_64_t *)((uintptr_t)mhp + (UNTAG_PTR(info_table[i]) - seg_text->vmaddr));
			if(!strcmp(kmod->name, "com.apple.security.sandbox")) {
				*kext_slide = *slide = seg_text->vmaddr;
				*start_addr = UNTAG_PTR(kmod->start_addr);
				return (const struct mach_header_64 *)((uintptr_t)mhp + (UNTAG_PTR(kext_table[i]) - *slide));
			}
		}
	}
	return NULL;
}

static void
do_profiles(const struct mach_header_64 *mhp, uint64_t len, uint64_t slide, uint64_t kext_sec_text_start, uint64_t kext_sec_text_end, uint64_t policy_ops, const char *profile_filename) {
	const uint32_t *insn;
	uint64_t i, off, hook_policy_init_ptr, collection_data_ptr = 0;
	uint32_t movk_shift, collection_data_sz = 0;
	int fd;
	
	off = (policy_ops + HOOK_POLICY_INIT_OFF) - slide;
	if((off + sizeof(uint64_t)) > len) {
		return;
	}
	
	hook_policy_init_ptr = UNTAG_PTR(*(const uint64_t *)((uintptr_t)mhp + off));
	if(!IS_IN_RANGE(hook_policy_init_ptr, kext_sec_text_start, kext_sec_text_end)) {
		return;
	}
	
	insn = (const uint32_t *)((uintptr_t)mhp + (hook_policy_init_ptr - slide));
	for(i = 0; i < (kext_sec_text_end - hook_policy_init_ptr) / (4 * sizeof(*insn)); ++i) {
		if(IS_ADRP(insn[i]) && IS_ADD_X(insn[i + 1]) && IS_MOV_W(insn[i + 2]) && IS_MOVK_W(insn[i + 3])) {
			collection_data_ptr = ADRP_ADDR(hook_policy_init_ptr + (i * sizeof(*insn))) + ADRP_IMM(insn[i]) + ADD_X_IMM(insn[i + 1]);
			movk_shift = MOV_SHIFT(insn[i + 3]);
			collection_data_sz = ((MOV_W_IMM(insn[i + 2]) << MOV_SHIFT(insn[i + 2])) & ~(0xffffu << movk_shift)) | (MOV_W_IMM(insn[i + 3]) << movk_shift);
			break;
		}
	}
	
	off = collection_data_ptr - slide;
	if((off + collection_data_sz) > len) {
		return;
	}
	
	if((fd = open(profile_filename, O_TRUNC | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) != -1) {
		if(write(fd, (const void *)((uintptr_t)mhp + off), collection_data_sz) != -1) {
			printf("Wrote sandbox collection (addr: 0x%016" PRIx64 ", size: 0x%x) to file %s\n", collection_data_ptr, collection_data_sz, profile_filename);
		}
		close(fd);
	}
}

static void
do_operation_names(const struct mach_header_64 *mhp, uint64_t len, uint64_t slide, uint64_t kext_sec_text_start, uint64_t kext_sec_text_end, uint64_t policy_ops, const char *operation_filename) {
	const uint64_t *operation_names;
	const uint32_t *insn;
	uint64_t i, off, hook_policy_syscall_ptr, jump_table_ptr = 0, case_syscall_check_sandbox_bulk, syscall_check_sandbox_bulk_ptr = 0, operation_names_ptr = 0;
	uint32_t operation_names_sz = 0;
	int fd;
	
	off = (policy_ops + HOOK_POLICY_SYSCALL_OFF) - slide;
	if((off + sizeof(uint64_t)) > len) {
		return;
	}
	
	hook_policy_syscall_ptr = UNTAG_PTR(*(const uint64_t *)((uintptr_t)mhp + off));
	if(!IS_IN_RANGE(hook_policy_syscall_ptr, kext_sec_text_start, kext_sec_text_end)) {
		return;
	}
	
	insn = (const uint32_t *)((uintptr_t)mhp + (hook_policy_syscall_ptr - slide));
	for(i = 0; i < (kext_sec_text_end - hook_policy_syscall_ptr) / (2 * sizeof(*insn)); ++i) {
		if(IS_ADR(insn[i])) {
			jump_table_ptr = hook_policy_syscall_ptr + (i * sizeof(*insn));
			if(IS_ADR_PAGE(insn[i])) {
				jump_table_ptr = ADRP_ADDR(jump_table_ptr) + ADRP_IMM(insn[i]);
				if(IS_ADD_X(insn[i + 1])) {
					jump_table_ptr += ADD_X_IMM(insn[i + 1]);
					break;
				}
			} else {
				if(IS_NOP(insn[i + 1])) {
					jump_table_ptr += ADR_IMM(insn[i]);
					break;
				}
				return;
			}
		}
	}
	
	off = (jump_table_ptr + CASE_SYSCALL_CHECK_SANDBOX_BULK_OFF) - slide;
	if((off + sizeof(int32_t)) > len) {
		return;
	}
	
	case_syscall_check_sandbox_bulk = jump_table_ptr + (uint64_t)*(const int32_t *)((uintptr_t)mhp + off);
	if(!IS_IN_RANGE(case_syscall_check_sandbox_bulk, kext_sec_text_start, kext_sec_text_end)) {
		return;
	}
	
	insn = (const uint32_t *)((uintptr_t)mhp + (case_syscall_check_sandbox_bulk - slide));
	for(i = 0; i < (kext_sec_text_end - case_syscall_check_sandbox_bulk) / sizeof(*insn); ++i) {
		if(IS_B(insn[i])) {
			syscall_check_sandbox_bulk_ptr = case_syscall_check_sandbox_bulk + (i * sizeof(*insn)) + B_IMM(insn[i]);
			break;
		}
	}
	
	insn = (const uint32_t *)((uintptr_t)mhp + (syscall_check_sandbox_bulk_ptr - slide));
	for(i = 0; i < (kext_sec_text_end - hook_policy_syscall_ptr) / (3 * sizeof(*insn)); ++i) {
		if(IS_MOV_X(insn[i]) && IS_ADRP(insn[i + 1]) && IS_ADD_X(insn[i + 2])) {
			operation_names_ptr = ADRP_ADDR(syscall_check_sandbox_bulk_ptr + (i * sizeof(*insn))) + ADRP_IMM(insn[i + 1]) + ADD_X_IMM(insn[i + 2]);
		} else if(operation_names_ptr && IS_CMP(insn[i])) {
			operation_names_sz = CMP_IMM(insn[i]) + 1u;
			break;
		}
	}
	
	off = operation_names_ptr - slide;
	if((off + (operation_names_sz * sizeof(uint64_t))) > len) {
		return;
	}
	
	if((fd = open(operation_filename, O_TRUNC | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) != -1) {
		operation_names = (const uint64_t *)((uintptr_t)mhp + off);
		for(i = 0; i < operation_names_sz; ++i) {
			if(dprintf(fd, "%s\n", (const char *)((uintptr_t)mhp + (UNTAG_PTR(operation_names[i]) - slide))) == -1) {
				close(fd);
				return;
			}
		}
		close(fd);
		printf("Wrote sandbox operations (addr: 0x%016" PRIx64 ", size: 0x%x) to file %s\n", operation_names_ptr, operation_names_sz, operation_filename);
	}
}

static void
sandy(const struct mach_header_64 *mhp, uint64_t len, const char *profile_filename, const char *operation_filename) {
	const struct segment_command_64 *kext_seg_text_exec, *seg_prelink_info;
	const struct section_64 *kext_sec_text;
	const struct mach_header_64 *kext;
	const uint32_t *insn;
	uint64_t i, off, slide, kext_slide, start_addr, realmain, realmain_ptr = 0, policy_ops, policy_ops_ptr = 0, kext_sec_text_start, kext_sec_text_end;
	
	if((seg_prelink_info = find_segment(mhp, "__PRELINK_INFO")) &&
	   ((kext = sandy_new(mhp, seg_prelink_info, &slide, &kext_slide, &start_addr)) ||
		(kext = sandy_old(mhp, seg_prelink_info, &slide, &kext_slide, &start_addr))) &&
	   (kext_seg_text_exec = find_segment(kext, "__TEXT_EXEC")) &&
	   (kext_sec_text = find_section(kext_seg_text_exec, "__text")))
	{
		kext_sec_text_start = UNTAG_PTR(kext_sec_text->addr);
		kext_sec_text_end = kext_sec_text_start + kext_sec_text->size;
		
		insn = (const uint32_t *)((uintptr_t)mhp + (start_addr - slide));
		for(i = 0; i < (kext_sec_text_end - start_addr) / (3 * sizeof(*insn)); ++i) {
			if(IS_ADRP(insn[i]) && IS_LDR_X_UNSIGNED_IMM(insn[i + 2])) {
				realmain_ptr = ADRP_ADDR(start_addr + (i * sizeof(*insn))) + ADRP_IMM(insn[i]) + LDR_X_UNSIGNED_IMM(insn[i + 2]);
				if(IS_ADD_X(insn[i + 1])) {
					realmain_ptr += ADD_X_IMM(insn[i + 1]);
				} else if(!IS_NOP(insn[i + 1])) {
					return;
				}
				break;
			}
		}
		
		off = realmain_ptr - kext_slide;
		if((off + sizeof(uint64_t)) > len) {
			return;
		}
		
		realmain = UNTAG_PTR(*(const uint64_t *)((uintptr_t)mhp + off));
		if(!IS_IN_RANGE(realmain, kext_sec_text_start, kext_sec_text_end)) {
			return;
		}
		
		insn = (const uint32_t *)((uintptr_t)mhp + (realmain - slide));
		for(i = 0; i < (kext_sec_text_end - realmain) / (2 * sizeof(*insn)); ++i) {
			if(IS_ADRP(insn[i]) && ADRP_RD(insn[i]) == 0 && IS_ADD_X(insn[i + 1])) {
				policy_ops_ptr = ADRP_ADDR(realmain + (i * sizeof(*insn))) + ADRP_IMM(insn[i]) + ADD_X_IMM(insn[i + 1]) + POLICY_OPS_OFF;
				break;
			}
		}
		
		off = policy_ops_ptr - slide;
		if((off + sizeof(uint64_t)) > len) {
			return;
		}
		
		policy_ops = UNTAG_PTR(*(const uint64_t *)((uintptr_t)mhp + off));
		
		do_profiles(mhp, len, slide, kext_sec_text_start, kext_sec_text_end, policy_ops, profile_filename);
		do_operation_names(mhp, len, slide, kext_sec_text_start, kext_sec_text_end, policy_ops, operation_filename);
	}
}

int
main(int argc, char **argv) {
	if(argc != 4) {
		printf("Usage: %s kernel profiles_out operations_out\n", argv[0]);
	} else {
		int fd = open(argv[1], O_RDONLY);
		size_t len = (size_t)lseek(fd, 0, SEEK_END);
		struct mach_header_64 *mhp = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
		close(fd);
		if(mhp != MAP_FAILED) {
			if(mhp->magic == MH_MAGIC_64 && mhp->cputype == CPU_TYPE_ARM64) {
				sandy(mhp, len, argv[2], argv[3]);
			}
			munmap(mhp, len);
		}
	}
}
