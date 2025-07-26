use serde::{Deserialize, Serialize};

/// Encoded page types for a launch update. See Table 58 of the SNP Firmware
/// specification for further details.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[repr(C)]
#[non_exhaustive]
pub enum PageType {
    /// A normal data page.
    Normal = 0x1,

    /// A VMSA page.
    Vmsa = 0x2,

    /// A page full of zeroes.
    Zero = 0x3,

    /// A page that is encrypted but not measured
    Unmeasured = 0x4,

    /// A page for the firmware to store secrets for the guest.
    Secrets = 0x5,

    /// A page for the hypervisor to provide CPUID function values.
    Cpuid = 0x6,
}
