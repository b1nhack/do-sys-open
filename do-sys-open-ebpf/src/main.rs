#![no_std]
#![no_main]

use aya_bpf::bpf_printk;
use aya_bpf::helpers::bpf_probe_read_user_str_bytes;
use aya_bpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[kprobe(name = "do_sys_open")]
pub fn do_sys_open(ctx: ProbeContext) -> u32 {
    match try_do_sys_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_sys_open(ctx: ProbeContext) -> Result<u32, u32> {
    let mut buf = [0u8; 16];

    let filename = ctx.arg::<*const u8>(1).unwrap();
    let filename = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(filename, &mut buf).unwrap())
    }
    .as_ptr();

    unsafe {
        bpf_printk!(b"filename: %s", filename);
    }

    info!(&ctx, "function do_sys_open called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
