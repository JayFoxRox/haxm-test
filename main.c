// Copyright 2018 Jannik Vogel
// Licensed under GPLv2 or any later version
// Refer to the included LICENSE.txt file.

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <hax-interface.h>

#ifdef WIN32

#include <windows.h>

typedef HANDLE hax_fd;
struct hax_state {
  hax_fd fd;
};
#include <hax-windows.h>

static char* hax_path() {
#define HAX_DEVFS "\\\\.\\HAX"
  return strdup(HAX_DEVFS);
}

static char* hax_vm_path(uint32_t vm_id) {
  //assert(vm_id <= MAX_VM_ID);
#define HAX_VM_DEVFS "\\\\.\\hax_vmxx"
  char* name = strdup(HAX_VM_DEVFS);
  snprintf(name, sizeof HAX_VM_DEVFS, "\\\\.\\hax_vm%02d", vm_id);
  return name;
}

static char* hax_vcpu_path(uint32_t vm_id, uint32_t vcpu_id) {
  //assert(vm_id <= MAX_VM_ID);
  //assert(vcpu_id <= MAX_VCPU_ID);
#define HAX_VCPU_DEVFS "\\\\.\\hax_vmxx_vcpuxx"
  char* name = strdup(HAX_VCPU_DEVFS);
  snprintf(name, sizeof HAX_VCPU_DEVFS, "\\\\.\\hax_vm%02d_vcpu%02d", vm_id, vcpu_id);
  return name;
}

static hax_fd hax_open(const char* path) {
  hax_fd fd = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (fd == INVALID_HANDLE_VALUE) {
    DWORD errNum = GetLastError();
    if (errno == ERROR_FILE_NOT_FOUND) {
      fprintf(stderr, "HAXM: Interface not found: '%s'\n", path);
    } else {
      fprintf(stderr, "HAXM: Error code %i while initilizing: '%s'\n", errno, path);
    }
    assert(false);
  }
  return fd;
}

static void hax_close(hax_fd fd) {
  CloseHandle(fd);
}

int hax_ioctl(hax_fd fildes, int request, void* in_data, size_t in_size, void* out_data, size_t out_size) {
  assert(((in_data == NULL) && (in_size == 0)) || ((out_data == NULL) && (out_size == 0)));
  DWORD dSize = 0;
  BOOL ret = DeviceIoControl(fildes, request, in_data, in_size, out_data, out_size, &dSize, (LPOVERLAPPED) NULL);
  assert(dSize == out_size);
  assert(ret != 0);
  return 0;
}

static void* hax_alloc(size_t size) {
  return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

#else

typedef int hax_fd;
struct hax_state {
  hax_fd fd;
};
#include <hax-darwin.h>

static hax_fd hax_open(const char* path) {
  hax_fd fd = open(path, O_RDWR);
  if (fd == -1) {
    fprintf(stderr, "HAXM: Failed to open the hax interface: '%s'\n", path);
  }
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  return fd;
}

static void hax_close(hax_fd fd) {
  close(fd);
}

int hax_ioctl(hax_fd fildes, int request, void* in_data, size_t in_size, void* out_data, size_t out_size) {

  // I've designed this API rather poorly, so we have to guess the users intention
  void* data;
  size_t size;
  if (in_data != NULL) {
    assert((out_data == NULL) && (out_size == 0));    
    data = in_data;
    size = in_size;
  } else (out_data != NULL) {
    assert((in_data == NULL) && (in_size == 0));
    data = out_data;
    size = out_size;
  } else {
    assert(false);
  }

  int ret = ioctl(fildes, request, data);
  return ret;
}

static void* hax_alloc(size_t size) {
  return memalign(0x100000, size);
}

#endif

typedef struct {
  hax_fd fd;
  hax_fd vm_fd;
  hax_fd vcpu_fd;
  struct hax_tunnel* haxm_tunnel;
  struct hax_tunnel_info haxm_tunnel_info;
} hax_context;

static void load_segment(struct segment_desc_t* desc, uint16_t selector, uint64_t base, uint32_t limit, uint16_t ar) {
  desc->selector = selector;
  desc->limit = limit;
  desc->base = base;
  desc->ar = ar;
  return;
}

int main(int argc, char* argv[]) {

  hax_context hax;

  hax.fd = HAX_INVALID_FD;
  hax.vm_fd = HAX_INVALID_FD;
  hax.vcpu_fd = HAX_INVALID_FD;
  hax.haxm_tunnel = NULL;

  hax.fd = hax_open(hax_path());

  struct hax_module_version haxm_version;
  hax_ioctl(hax.fd, HAX_IOCTL_VERSION, NULL, 0, &haxm_version, sizeof(haxm_version));
  printf("HAXM Versions: %i, %i\n", haxm_version.compat_version, haxm_version.cur_version);

  struct hax_capabilityinfo cap;
  hax_ioctl(hax.fd, HAX_IOCTL_CAPABILITY, NULL, 0, &cap, sizeof(cap));
  assert(cap.wstatus & HAX_CAP_STATUS_WORKING); //FIXME: Should copy qemu error message logic
  if (cap.wstatus & HAX_CAP_UG) {
    printf("Unrestricted guest!\n");
  } else {
    printf("Restricted guest!\n");
  }


  // Create a VM and retrieve VM ID from HAXM
  uint32_t vm_id = 0;
  hax_ioctl(hax.fd, HAX_IOCTL_CREATE_VM, NULL, 0, &vm_id, sizeof(vm_id));
  hax.vm_fd = hax_open(hax_vm_path(vm_id));

  // Expect version 4 of HAXM (same as QEMU at time of writing)
  struct hax_qemu_version qversion;
  qversion.min_version = 4;
  qversion.cur_version = 4;
  hax_ioctl(hax.vm_fd, HAX_VM_IOCTL_NOTIFY_QEMU_VERSION, &qversion, sizeof(qversion), NULL, 0);


  // Allocate 4MiB of data
  uint64_t ram_address = 0;
  uint32_t ram_size = 1024 * 1024 * 4;
  void* ram_ptr = hax_alloc(ram_size);

  // Create a cursor to write code
  uint8_t* c = ram_ptr;
  {
    // Write a handful of NOP
    for(int i = 0; i < 0x123; i++) {
      *c++ = 0x90;
    }
   
    // HLT
    *c++ = 0xF4;
  }

  struct hax_alloc_ram_info haxm_ram_info = {0};
  haxm_ram_info.va = (uintptr_t)ram_ptr;
  haxm_ram_info.size = ram_size;
  hax_ioctl(hax.vm_fd, HAX_VM_IOCTL_ALLOC_RAM, &haxm_ram_info, sizeof(haxm_ram_info), NULL, 0);

  struct hax_set_ram_info haxm_set_ram_info = {0};
  haxm_set_ram_info.pa_start = ram_address;
  haxm_set_ram_info.va = (uintptr_t)ram_ptr;
  haxm_set_ram_info.size = ram_size;
  haxm_set_ram_info.flags = 0; //FIXME: HAX_RAM_INFO_ROM is also possible
  hax_ioctl(hax.vm_fd, HAX_VM_IOCTL_SET_RAM, &haxm_set_ram_info, sizeof(haxm_set_ram_info), NULL, 0);



  // Create a VCPU, we choose the VCPU ID
  uint32_t vcpu_id = 0;
  hax_ioctl(hax.vm_fd, HAX_VM_IOCTL_VCPU_CREATE, &vcpu_id, sizeof(vcpu_id), NULL, 0);
  hax.vcpu_fd = hax_open(hax_vcpu_path(vm_id, vcpu_id));

  hax_ioctl(hax.vcpu_fd, HAX_VCPU_IOCTL_SETUP_TUNNEL, NULL, 0, &hax.haxm_tunnel_info, sizeof(hax.haxm_tunnel_info));
  assert(hax.haxm_tunnel_info.size == sizeof(struct hax_tunnel));
  hax.haxm_tunnel = (struct hax_tunnel*)hax.haxm_tunnel_info.va;



  // Prepare CPU State
  struct vcpu_state_t regs = { 0 };
  hax_ioctl(hax.vcpu_fd, HAX_VCPU_GET_REGS, NULL, 0, &regs, sizeof(regs));

  regs._rax = 0;
  regs._rbx = 0;
  regs._rcx = 0;
  regs._rdx = 0;
  regs._rsi = 0;
  regs._rdi = 0;
  regs._rsp = 0;
  regs._rbp = 0;
  // FIXME: regs.r8 - regs.r15 ?

  regs._cr0 |= 1; // Enable protected mode
  load_segment(&regs._gdt, 0x08, 0xFFFFF000, 0x18, 0x0000);
  load_segment(&regs._cs, 0x08, 0x00000000, 0xFFFFFFFF, 0xCF9B);
  load_segment(&regs._ds, 0x10, 0x00000000, 0xFFFFFFFF, 0xCF93);
  load_segment(&regs._es, 0x10, 0x00000000, 0xFFFFFFFF, 0xCF93);
  load_segment(&regs._ss, 0x10, 0x00000000, 0xFFFFFFFF, 0xCF93);

  regs._rflags = 2;
  regs._rip = 0;

  hax_ioctl(hax.vcpu_fd, HAX_VCPU_SET_REGS, &regs, sizeof(regs), NULL, 0);


  // Mainloop
  while(true) {
    hax_ioctl(hax.vcpu_fd, HAX_VCPU_IOCTL_RUN, NULL, 0, NULL, 0);

    struct vcpu_state_t regs = { 0 };
    hax_ioctl(hax.vcpu_fd, HAX_VCPU_GET_REGS, NULL, 0, &regs, sizeof(regs));

    switch(hax.haxm_tunnel->_exit_status) {
    case HAX_EXIT_HLT:
      printf("HLT at 0x%08X\n", regs._eip);
      break;
    case HAX_EXIT_IO:
      assert(false);
      break;
    case HAX_EXIT_MMIO:
      assert(false);
      break;
    case HAX_EXIT_REAL:
      assert(false);
      break;
    case HAX_EXIT_INTERRUPT:
      assert(false);
      break;
    case HAX_EXIT_UNKNOWN_VMEXIT:
      assert(false);
      break;
    case HAX_EXIT_STATECHANGE:
      printf("HAX_EXIT_STATECHANGE at 0x%08X\n", regs._eip);
      fflush(stdout);
      assert(false);
      break;
    case HAX_EXIT_PAUSED:
      assert(false);
      break;
    case HAX_EXIT_FAST_MMIO:
      assert(false);
      break;
    default:
      printf("unhandled exit status: %i\n", hax.haxm_tunnel->_exit_status);
      assert(false);
      break;
    }
  }

  //FIXME: Close the VM etc.
  assert(false);

  return 0;
}
