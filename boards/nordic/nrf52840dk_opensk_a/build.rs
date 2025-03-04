use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rerun-if-changed=../../kernel_layout.ld");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("locations.rs");
    fs::write(
        &dest_path,
        "
static mut STORAGE_LOCATIONS: [kernel::StorageLocation; 5] = [
    // We implement NUM_PAGES = 20 as 16 + 4 to satisfy the MPU.
    kernel::StorageLocation {
        address: 0xC0000,
        size: 0x10000, // 16 pages
        storage_type: kernel::StorageType::STORE,
    },
    kernel::StorageLocation {
        address: 0xD0000,
        size: 0x4000, // 4 pages
        storage_type: kernel::StorageType::STORE,
    },
    // Partitions can also be split to maximize MPU happiness.
    kernel::StorageLocation {
        address: 0x60000,
        size: 0x20000,
        storage_type: kernel::StorageType::PARTITION,
    },
    kernel::StorageLocation {
        address: 0x80000,
        size: 0x20000,
        storage_type: kernel::StorageType::PARTITION,
    },
    kernel::StorageLocation {
        address: 0x5000,
        size: 0x1000,
        storage_type: kernel::StorageType::METADATA,
    },
];
"
    ).unwrap();
}
